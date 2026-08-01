//! NativeCipher — Cipher impl (ADR-428): 纯 Rust 解密, 无 electron/dll 外部依赖 (默认且唯一路径).
//!
//! 套 ADR-423 `Cipher` / `DbSession` trait:
//! `open_account` → 验 key 能解 entry_db 首页 (native-keyscan verify_passphrase) → `NativeDbSession`;
//! `query` → native-sqlcipher 解密 sub_db (内存 image + deserialize 只读) → rusqlite 跑 SQL → `CipherRow`。
//!
//! ## 性能 (alpha 简化)
//! - **单缓存当前 sub_db**: 同一 sub_db 多次 query (drain keyset 分页) 只解密一次; 换库即替换 (内存只留 1 库, 不累积).
//! - 同步阻塞: 解密 + rusqlite 在 async fn 内同步跑 (阻塞 worker); M3-d 再上 spawn_blocking + 多核.
//!
//! ## key 语义
//! open_account 收 `MasterKey` (= passphrase, 跟 sidecar 同语义); NativeDbSession 对各 sub_db 用
//! passphrase + 该库 salt 现场派生 (M3-b passphrase 路). enc_key 快路 (per-db 免派生) 是后续优化, 暂不接 trait.
//!
//! K-R4: passphrase `Zeroizing` 清零; CipherRow Debug 只露列名 (cipher/mod.rs); 错误经 map 出口 sha8.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use native_keyscan::{verify_passphrase, KeyMaterial, PAGE, SQLCIPHER_ROUNDS_V4};
use native_sqlcipher::{
    open_conn_vfs, open_decrypted, open_decrypted_with_wal, wal_sibling, DecryptedDb, SqlcipherError, WalRefreshHandle,
};
use rusqlite::types::ValueRef;
use zeroize::Zeroizing;

use crate::cipher::{Cipher, CipherError, CipherRow, DbSession};
use crate::key_provider::MasterKey;

/// NativeCipher — 纯 Rust 解密读库 (Cipher Path B). 无状态, 每 `open_account` 一个 session.
pub struct NativeCipher {
    /// KDF 轮数 (passphrase 派生; KI-F v4=256000 / v3=64000). 默认 v4.
    rounds: u32,
    /// live 模式 (件2): `open_account` 出 WAL 感知 + mtime 三档缓存的会话 (watch 用); 默认 false = ingest 现状.
    live_wal: bool,
}

impl NativeCipher {
    /// 默认 v4 轮数 (256000), 非 live (checkpoint 快照; ingest/导出用).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rounds: SQLCIPHER_ROUNDS_V4,
            live_wal: false,
        }
    }

    /// 指定 KDF 轮数 (按微信版本; KI-F), 非 live.
    #[must_use]
    pub fn with_rounds(rounds: u32) -> Self {
        Self {
            rounds,
            live_wal: false,
        }
    }

    /// live 模式 (watch): 会话合并 WAL 已提交增量 + mtime 三档缓存 (件2). v4 轮数.
    #[must_use]
    pub fn new_live() -> Self {
        Self {
            rounds: SQLCIPHER_ROUNDS_V4,
            live_wal: true,
        }
    }
}

impl Default for NativeCipher {
    fn default() -> Self {
        Self::new()
    }
}

/// 验 master passphrase 能否解 entry_db (只读首页 4096B 跑 HMAC, 不解整库; 复用 native-keyscan).
fn verify_key_on(entry_db: &Path, key: &MasterKey, rounds: u32) -> Result<(), CipherError> {
    use std::io::Read;
    let mut f = std::fs::File::open(entry_db)?; // io::Error → CipherError::Io (只留 kind)
    let mut page = vec![0u8; PAGE];
    f.read_exact(&mut page)
        .map_err(|_| CipherError::decrypt_failed(b"", Some(entry_db)))?; // 不足一页 = 非法库
    if verify_passphrase(key.as_bytes(), &page, rounds) {
        Ok(())
    } else {
        Err(CipherError::HmacVerifyFail) // key 错 (MATRIX #5)
    }
}

/// 轻量验 key: **只读源库首页 4096B 跑 HMAC**（不解整库、**不读 `-wal`**）判该 key 能否解密此库。
///
/// 供 R21 成本门 Blocked 前廉价验 key —— round-15 codex P1: `open_decrypted_db_vfs` 内部 `open_conn_vfs` 会
/// `build_wal_overlay` **读整个 `-wal` 并解密已提交帧**, 不适合当门的廉价探针（shard 有大 WAL 时, 本该被廉价拒绝
/// 的 Blocked 请求会卡顿/爆内存, 尤其 HTTP 在信号量之前跑）。本函数只 stat+读首页, 有界廉价。
/// key 有效 → `true`; 错 key / 读不了 / 不足一页 → `false`。默认 SQLCipher4 轮数（同 [`open_decrypted_db_vfs`]）。
#[must_use]
pub fn verify_key_page1(enc_db: &Path, key: &MasterKey) -> bool {
    verify_key_on(enc_db, key, SQLCIPHER_ROUNDS_V4).is_ok()
}

#[async_trait]
impl Cipher for NativeCipher {
    async fn open_account(&self, account_entry_db: &Path, key: &MasterKey) -> Result<Box<dyn DbSession>, CipherError> {
        verify_key_on(account_entry_db, key, self.rounds)?;
        let sess = if self.live_wal {
            NativeDbSession::new_live(*key.as_bytes(), self.rounds)
        } else {
            NativeDbSession::new(*key.as_bytes(), self.rounds)
        };
        Ok(Box::new(sess))
    }

    async fn verify(&self, account_entry_db: &Path, key: &MasterKey) -> Result<(), CipherError> {
        verify_key_on(account_entry_db, key, self.rounds)
    }

    fn name(&self) -> &'static str {
        "native-sqlcipher"
    }
}

/// 非 live (ingest) 单缓存槽: 换库即替换的 checkpoint 快照 (整库 deserialize, 内存只留 1 库).
struct CheckpointSlot {
    path: PathBuf,
    db: DecryptedDb,
}

/// live (watch) 缓存的一个 **VFS 按需解密连接** (~32MB/库, 非整库 GB). 记打开时 mtime 供失效判定.
struct VfsConn {
    conn: rusqlite::Connection,
    /// WAL 就地刷新句柄: 只 WAL 变时刷新 overlay (不重开连接/不重读 schema).
    handle: WalRefreshHandle,
    /// 上次同步时主库 `.db` mtime (纳秒).
    db_mtime: u64,
    /// 上次同步时 `.db-wal` mtime (纳秒); 变 = 有新消息 → overlay 就地刷新.
    wal_mtime: u64,
}

/// 已开账号会话 (Path B) — 持 master passphrase + 已开库连接.
///
/// - **非 live (ingest)**: 单缓存当前 sub_db 的 checkpoint 快照 (整库 deserialize; 换库即替换, 旧连接 Drop,
///   内存只留 1 库). 同一 sub_db 多次 query (keyset 分页) 只解密一次. Connection `!Sync` → `Mutex` 串行.
/// - **live (watch, `live_wal`)**: 每 sub_db 一个 **VFS 按需解密连接** (~32MB/库, 非整库 GB), 多连接并存;
///   mtime 没变复用 (schema 已缓存, 查询 ~2ms) / WAL 或主库变了重开 (重建 WAL overlay 拿新消息 + 重读 schema).
///   合并 WAL 拿**实时前沿**. **替代件2 整库 pristine 缓存 —— 内存从 GB/库 砍到 ~32MB/库 (ADR-500 VFS).**
pub struct NativeDbSession {
    passphrase: Zeroizing<[u8; 32]>,
    rounds: u32,
    live_wal: bool,
    /// 非 live: checkpoint 单槽.
    checkpoint: Mutex<Option<CheckpointSlot>>,
    /// live: 每 sub_db 一个 VFS 连接 (低内存, 多连接并存; 访问集合有界 = 各子库, 不无限增长).
    live: Mutex<HashMap<PathBuf, VfsConn>>,
}

impl NativeDbSession {
    fn new(passphrase: [u8; 32], rounds: u32) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase),
            rounds,
            live_wal: false,
            checkpoint: Mutex::new(None),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// live 模式会话 (watch): VFS 按需解密 + 合并 WAL. 见 [`NativeDbSession`] `live_wal`.
    fn new_live(passphrase: [u8; 32], rounds: u32) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase),
            rounds,
            live_wal: true,
            checkpoint: Mutex::new(None),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// 非 live: 换库即重解 checkpoint 快照 (现状语义); 同库复用. 保证 slot 为该 sub_db.
    fn ensure_checkpoint(&self, slot: &mut Option<CheckpointSlot>, sub_db: &Path) -> Result<(), CipherError> {
        let need = slot.as_ref().is_none_or(|c| c.path != sub_db);
        if need {
            *slot = None; // 先 drop 旧库释放 image, 再解新库 → 峰值 1× (codex E/G).
            let key = KeyMaterial::passphrase(*self.passphrase);
            let db = open_decrypted(sub_db, &key, self.rounds).map_err(|e| map_sqlcipher_err(&e, sub_db))?;
            *slot = Some(CheckpointSlot {
                path: sub_db.to_path_buf(),
                db,
            });
        }
        Ok(())
    }

    /// live: 确保 map 里有该 sub_db 的**最新** VFS 连接. 三种情况:
    /// - 全没变 → 复用 (schema 缓存 + overlay 当前, 查询 ~2ms);
    /// - **只 WAL 变** (主库没变) → **overlay 就地刷新** (不重开连接/不重读 schema → 大账号省 ~3s);
    /// - 主库变 / 换库 / 首次 → 重开 (drop 旧连接 + 重建 overlay + 重读 schema).
    fn ensure_live_vfs(&self, map: &mut HashMap<PathBuf, VfsConn>, sub_db: &Path) -> Result<(), CipherError> {
        let db_mt = mtime_nanos(sub_db);
        let wal_mt = mtime_nanos(&wal_sibling(sub_db));
        if let Some(vc) = map.get_mut(sub_db) {
            if vc.db_mtime == db_mt && vc.wal_mtime == wal_mt {
                return Ok(()); // 全没变: 复用.
            }
            if vc.db_mtime == db_mt {
                // 只 WAL 变 (主库没变): overlay 就地刷新, 保连接 + schema.
                vc.handle.refresh().map_err(|e| map_sqlcipher_err(&e, sub_db))?;
                vc.wal_mtime = wal_mt;
                return Ok(());
            }
            // 主库变了: 落到下面重开 (get_mut 借用到此结束).
        }
        map.remove(sub_db); // 先 drop 旧连接 (关 VFS 文件释放 ~32MB), 再开新的.
        let km = KeyMaterial::passphrase(*self.passphrase);
        let (conn, handle) = open_conn_vfs(sub_db, &km, self.rounds).map_err(|e| map_sqlcipher_err(&e, sub_db))?;
        map.insert(
            sub_db.to_path_buf(),
            VfsConn {
                conn,
                handle,
                db_mtime: db_mt,
                wal_mtime: wal_mt,
            },
        );
        Ok(())
    }
}

#[async_trait]
impl DbSession for NativeDbSession {
    async fn query(&self, _kind: &str, sub_db: &Path, sql: &str) -> Result<Vec<CipherRow>, CipherError> {
        // 同步段 (无 await 跨锁): 按模式确保连接为该 sub_db 的最新, 再跑 SQL.
        let map_err = |e: &rusqlite::Error, sub_db: &Path| {
            tracing::debug!(sqlite_err = %classify_rusqlite(e), "NativeCipher run_query 失败");
            CipherError::decrypt_failed(b"", Some(sub_db))
        };
        if self.live_wal {
            let mut map = self
                .live
                .lock()
                .map_err(|_| CipherError::decrypt_failed(b"", Some(sub_db)))?;
            self.ensure_live_vfs(&mut map, sub_db)?;
            let vc = map.get(sub_db).expect("ensure_live_vfs 已置");
            run_query(&vc.conn, sql).map_err(|e| map_err(&e, sub_db))
        } else {
            let mut slot = self
                .checkpoint
                .lock()
                .map_err(|_| CipherError::decrypt_failed(b"", Some(sub_db)))?;
            self.ensure_checkpoint(&mut slot, sub_db)?;
            let conn = slot.as_ref().expect("ensure_checkpoint 已置").db.conn();
            run_query(conn, sql).map_err(|e| map_err(&e, sub_db))
        }
    }
}

/// 文件 mtime → 纳秒 (取不到 = 0, 触发重解, 安全兜底). 件2 三档缓存判据 (抄 wx-cli daemon/cache.rs).
fn mtime_nanos(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64)
        .unwrap_or(0)
}

/// 跑只读 SQL → `CipherRow` — 列值统一成 `Option<String>` (对齐 sidecar dll "全 string" 行为).
///
/// 整数/浮点 → to_string; 文本 → string; NULL → None; blob → hex (sql 一般已 `hex(col)`, 兜底 hex()).
fn run_query(conn: &rusqlite::Connection, sql: &str) -> Result<Vec<CipherRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(sql)?;
    let col_count = stmt.column_count();
    let col_names: Vec<String> = (0..col_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_owned())
        .collect();
    let rows = stmt.query_map([], |row| {
        let mut cols: Vec<(String, Option<String>)> = Vec::with_capacity(col_count);
        for (i, name) in col_names.iter().enumerate() {
            let v = match row.get_ref(i)? {
                ValueRef::Null => None,
                ValueRef::Integer(n) => Some(n.to_string()),
                ValueRef::Real(fl) => Some(fl.to_string()),
                ValueRef::Text(t) => Some(String::from_utf8_lossy(t).into_owned()),
                ValueRef::Blob(b) => Some(hex::encode(b)),
            };
            cols.push((name.clone(), v));
        }
        Ok(CipherRow::new(cols))
    })?;
    rows.collect()
}

/// SqlcipherError → CipherError (钉死 7 变体): 首页 HMAC 不过 = key 错 → HmacVerifyFail;
/// 其余 (坏页 / AES / 读文件 / 非法库) → DecryptFailed (cipher 层无 wxid, db_file 出口 sha8).
fn map_sqlcipher_err(e: &SqlcipherError, ctx: &Path) -> CipherError {
    match e {
        SqlcipherError::PageHmacMismatch { page_num: 1 } => CipherError::HmacVerifyFail,
        _ => CipherError::decrypt_failed(b"", Some(ctx)),
    }
}

/// 便捷: 用账号 master key **就地解密一个微信子库** → 只读查询句柄 (全程内存, 不落明文文件).
///
/// 供 cli 各导出/解密命令直读**加密**微信库 (不必先手动解密成明文文件): passphrase 路
/// (v4 [`SQLCIPHER_ROUNDS_V4`] 派生 + 逐页 HMAC 校验), 复用 [`map_sqlcipher_err`] 脱敏 —
/// 错误不含明文 / wxid / 全路径 (K-R4). 产出 = **主库 checkpoint 快照** (不含活跃 WAL 最新行,
/// 见 native-sqlcipher crate 文档); 峰值内存 ≈ 1× 库大小 (NOCOPY deserialize). 只读, 不写源库.
///
/// 与 [`NativeCipher`] 同解密内核, 但走**同步一次性**接口 (无 async / 无 DbSession 分页缓存) —
/// 适合"解一个具体库整表扫出来导媒体"的 cli 场景 (ingest 分页取数才用 `Cipher` trait).
///
/// # Errors
/// [`CipherError::HmacVerifyFail`] key 不对 (首页 HMAC 不过); [`CipherError::DecryptFailed`]
/// 坏页 / 读文件失败 / 非法库 / 非加密文件.
pub fn open_decrypted_db(enc_db: &Path, key: &MasterKey) -> Result<DecryptedDb, CipherError> {
    let km = KeyMaterial::passphrase(*key.as_bytes());
    open_decrypted(enc_db, &km, SQLCIPHER_ROUNDS_V4).map_err(|e| map_sqlcipher_err(&e, enc_db))
}

/// 便捷: 同 [`open_decrypted_db`] 但**合并 `<db>-wal` 里已提交的增量帧** → 读出**实时前沿**行 (全程内存, 不落盘).
///
/// 微信/WCDB 频繁 checkpoint, 最新几笔常还压在加密 WAL 里未刷盘; 本函数在主库 checkpoint 快照上再叠加
/// WAL 已提交事务的最新页 (见 native-sqlcipher `wal` 模块). 供实时监听 (`--watch`): 每次轮询到库/WAL
/// 变化就重开一把拿最新消息. WAL 缺失/空/无提交时**等价** [`open_decrypted_db`] (退回快照).
///
/// # Errors
/// 同 [`open_decrypted_db`] ([`CipherError::HmacVerifyFail`] key 错 / [`CipherError::DecryptFailed`]
/// 坏页·读文件·非法库), 外加 WAL 合并失败 (映射同一出口, 脱敏).
pub fn open_decrypted_db_with_wal(enc_db: &Path, key: &MasterKey) -> Result<DecryptedDb, CipherError> {
    let km = KeyMaterial::passphrase(*key.as_bytes());
    open_decrypted_with_wal(enc_db, &km, SQLCIPHER_ROUNDS_V4).map_err(|e| map_sqlcipher_err(&e, enc_db))
}

/// 便捷: 用**按需解密 VFS** 打开加密库 → 只读 [`rusqlite::Connection`] (**低内存, 不整库解密, 不落盘**).
///
/// SQLite 顺 b-tree 只解查询碰到的页 (峰值内存 = 页缓存, 几十 MB, 非整库 GB); DLL 同款低内存实时读的
/// 纯 Rust 实现 (见 native-sqlcipher `vfs`). 供实时监听大账号 (整库 deserialize 吃 GB 内存的替代).
///
/// # Errors
/// 同 [`open_decrypted_db`] (key 错 / 坏页 / 读文件 / sqlite 打开失败; 映射同一出口, 脱敏).
pub fn open_decrypted_db_vfs(enc_db: &Path, key: &MasterKey) -> Result<rusqlite::Connection, CipherError> {
    let km = KeyMaterial::passphrase(*key.as_bytes());
    // 一次性读丢弃 refresh 句柄 (watch 走 NativeDbSession 直接用 open_conn_vfs 保留句柄).
    let (conn, _handle) = open_conn_vfs(enc_db, &km, SQLCIPHER_ROUNDS_V4).map_err(|e| map_sqlcipher_err(&e, enc_db))?;
    Ok(conn)
}

/// 同 [`open_decrypted_db_vfs`] 但返回 **WAL 就地刷新句柄** —— 该库 WAL 变了调 `refresh()` 只重建 overlay
/// (不重开连接/不重读 schema)。供实时监听保持连接跟进新消息。
///
/// # Errors
/// 同 [`open_decrypted_db_vfs`].
pub fn open_decrypted_db_vfs_live(
    enc_db: &Path,
    key: &MasterKey,
) -> Result<(rusqlite::Connection, WalRefreshHandle), CipherError> {
    let km = KeyMaterial::passphrase(*key.as_bytes());
    open_conn_vfs(enc_db, &km, SQLCIPHER_ROUNDS_V4).map_err(|e| map_sqlcipher_err(&e, enc_db))
}

/// rusqlite 错误类别 (codex H 排障线索) — 只取 sqlite code / 变体名, **不含 SQL 文本 / 明文行 / msg**.
fn classify_rusqlite(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqliteFailure(f, _) => format!("sqlite_code_{}", f.extended_code),
        rusqlite::Error::QueryReturnedNoRows => "no_rows".to_owned(),
        rusqlite::Error::InvalidColumnType(..) => "invalid_col_type".to_owned(),
        rusqlite::Error::InvalidColumnName(_) => "invalid_col_name".to_owned(),
        _ => "other".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    /// run_query: rusqlite 行 → CipherRow, 列值统一 string (int→"47279" / text / NULL→None / blob→hex).
    #[test]
    fn run_query_produces_string_cipher_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t(n INTEGER, s TEXT, nil TEXT, b BLOB);
             INSERT INTO t VALUES (47279, 'hi', NULL, x'4142');",
        )
        .unwrap();
        let rows = run_query(&conn, "SELECT n, s, nil, hex(b) AS bh FROM t").unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.get_str("n"), Some("47279"), "整数应转 string (对齐 sidecar)");
        assert_eq!(r.get_i64("n"), Some(47279));
        assert_eq!(r.get_str("s"), Some("hi"));
        assert_eq!(r.get_str("nil"), None, "NULL → None");
        assert_eq!(r.get_blob_hex("bh"), Some(vec![0x41, 0x42]), "hex(blob) 列还原");
    }

    /// 映射: 首页 HMAC 不过 = key 错 → HmacVerifyFail; 其余 → DecryptFailed.
    #[test]
    fn map_first_page_hmac_is_key_error() {
        let p = Path::new("/wx/contact.db");
        assert!(matches!(
            map_sqlcipher_err(&SqlcipherError::PageHmacMismatch { page_num: 1 }, p),
            CipherError::HmacVerifyFail
        ));
        assert!(matches!(
            map_sqlcipher_err(&SqlcipherError::PageHmacMismatch { page_num: 9 }, p),
            CipherError::DecryptFailed { .. }
        ));
        assert!(matches!(
            map_sqlcipher_err(&SqlcipherError::TooSmall(4096), p),
            CipherError::DecryptFailed { .. }
        ));
    }

    /// K-R4: 映射出的 DecryptFailed 不泄含 wxid 的 db 路径.
    #[test]
    fn mapped_error_masks_path() {
        let secret = Path::new("F:/x/wxid_secret_abfe/db_storage/contact.db");
        let err = map_sqlcipher_err(&SqlcipherError::Decrypt { page_num: 2 }, secret);
        let shown = format!("{err}");
        assert!(!shown.contains("wxid_secret"), "泄 wxid: {shown}");
        assert!(!shown.contains("F:/x"), "泄路径: {shown}");
    }

    /// NativeCipher 是合法 Cipher trait object (chain/config 切换 impl 必须 object-safe).
    #[test]
    fn native_cipher_is_trait_object() {
        let c: Box<dyn Cipher> = Box::new(NativeCipher::new());
        assert_eq!(c.name(), "native-sqlcipher");
        let c2: Box<dyn Cipher> = Box::new(NativeCipher::with_rounds(64_000));
        assert_eq!(c2.name(), "native-sqlcipher");
    }
}
