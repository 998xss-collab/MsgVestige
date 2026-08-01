//! cipher — 解密读库层 (ADR-423: open_account + exec_query 取数模型, 取代 ADR-405 §3.1 旧 decrypt 模型).
//!
//! 本 mod 提供 `Cipher` trait (开账号→`DbSession`)、`DbSession` (exec_query 查询会话)、
//! `CipherRow` (一行) 与 `CipherError`. impl: `NativeCipher` (native.rs, 纯 Rust SQLCipher 解密, 默认).
//!
//! ## 模型 (ADR-423 §3)
//! `open_account(entry_db,key)→DbSession`, `query(kind,sub_db,sql)→行` (列值全 string; blob 列走
//! SQL `hex()`)。**不落明文 db 文件** — NativeCipher 全页解密到内存 image + deserialize 只读 (ADR-428)。
//!
//! ## 红线 (cipher-加密.md §2 + ADR-423 §4)
//! - page-by-page: drain keyset 分页 (`WHERE pk>cursor LIMIT n`, 禁 OFFSET), 不全表入内存 (50GB 副号)
//! - trait 抽象: impl 可替换不动 trait (ADR-423 §3.3)
//! - 解密失败必 propagate (不吞错)
//! - 不缓存明文 (query 结果用完即弃)
//!
//! K-R4: master key hex 只在进程内派生/解密 (不入 log); CipherError 出口 sha8.

pub mod error;
pub mod native;

use std::path::Path;

use async_trait::async_trait;
pub use error::CipherError;
pub use native::{
    open_decrypted_db, open_decrypted_db_vfs, open_decrypted_db_vfs_live, open_decrypted_db_with_wal, verify_key_page1,
    NativeCipher, NativeDbSession,
};
// cli 导出命令的统一库句柄要能命名解密句柄 (SourceDb::Decrypted(DecryptedDb)); 从底层 crate 透出.
pub use native_sqlcipher::DecryptedDb;
pub use native_sqlcipher::WalRefreshHandle;

use crate::key_provider::MasterKey;

/// 解密读库器 (ADR-423 §3.3 trait 2/7) — 开账号返查询会话.
///
/// trait 抽象: impl 可替换不动 trait (当前 impl = NativeCipher 纯 Rust 解密).
#[async_trait]
pub trait Cipher: Send + Sync {
    /// 开账号 (内存解密) → 查询会话句柄. 1 账号 1 session.
    ///
    /// `account_entry_db` = 账号入口 db (e.g. `session/session.db`); `key` = master key.
    /// 复用/缓存策略由 impl 决定; 失败 (key 错 / 文件缺 / 解密异常) 返 `CipherError`.
    async fn open_account(&self, account_entry_db: &Path, key: &MasterKey) -> Result<Box<dyn DbSession>, CipherError>;

    /// 验 key 能否开账号 — `Ok(())` = 可开 (内部 open 后随即 close 验证 handle, 不泄);
    /// `Err` = 开不了 (rc 分档见 ADR-423 KI-E, alpha 不强判 false).
    async fn verify(&self, account_entry_db: &Path, key: &MasterKey) -> Result<(), CipherError>;

    /// 实现名 ("native-sqlcipher") — 写 log / etl_state.
    fn name(&self) -> &'static str;
}

/// 已开账号的查询会话 (ADR-423 §3.3) — 对账号下子库跑只读 SQL.
#[async_trait]
pub trait DbSession: Send + Sync {
    /// 对账号下某子库跑只读 SQL → 行.
    ///
    /// `kind` 子库类别 ("message"/"contact"/...); `sub_db` 子库绝对路径; `sql` 只读模板.
    /// 并发: impl 内部对句柄串行化 (ADR-423 §3.3).
    /// blob 列须在 sql 里 `hex()` 包 (ADR-423 §3.5), 用 [`CipherRow::get_blob_hex`] 还原.
    /// ⚠️ 内存 (代码双审 P1): 本层把整页结果**全量进内存**(无字节上限) — `sql` **必须带 LIMIT**
    /// 控制单页行数 (page-by-page 红线靠 SQL 保证, ADR-423 §4/KI-C; 防 50GB 副号一次拉爆)。
    async fn query(&self, kind: &str, sub_db: &Path, sql: &str) -> Result<Vec<CipherRow>, CipherError>;

    /// 显式关账号 (eager 释放句柄). 默认 no-op (native: 连接随 Drop 关).
    async fn close(&self) -> Result<(), CipherError> {
        Ok(())
    }
}

/// exec_query 一行 — 列名→值. 列值全 `Option<String>` (查询结果统一字符串化;
/// SQL NULL = None; poc-0-4 实证整数也是字符串 "47279")。
///
/// accessor 全**按列名查**, 不依赖列序 (实际列序 = `serde_json::Map` key 序, 非 SELECT 序)。
///
/// K-R4 (代码双审 P0): 列值含消息正文等 PII → 手写 Debug **只露列名 + 列数, 不露值** (出口侧 robust,
/// 不靠调用方不 `tracing::debug!(?row)`)。
#[derive(Clone, PartialEq, Eq)]
pub struct CipherRow {
    columns: Vec<(String, Option<String>)>,
}

impl std::fmt::Debug for CipherRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只露列名 (SQL 列名, 安全) + 列数; 列值 (可能含消息正文) 不露.
        let cols: Vec<&str> = self.columns.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("CipherRow")
            .field("columns", &cols)
            .field("len", &self.columns.len())
            .finish()
    }
}

impl CipherRow {
    /// 直接构造 (native cipher `run_query` 组装每行 + 测试用).
    #[must_use]
    pub fn new(columns: Vec<(String, Option<String>)>) -> Self {
        Self { columns }
    }

    /// 取列字符串值 (列不存在 / SQL NULL → None).
    #[must_use]
    pub fn get_str(&self, col: &str) -> Option<&str> {
        self.columns
            .iter()
            .find(|(k, _)| k == col)
            .and_then(|(_, v)| v.as_deref())
    }

    /// 取列整数 (parse string; 列缺 / NULL / 非数 → None). dll 整数列也是字符串.
    #[must_use]
    pub fn get_i64(&self, col: &str) -> Option<i64> {
        self.get_str(col).and_then(|s| s.parse().ok())
    }

    /// 取 blob 列 → 裸字节 (列须 `SELECT hex(col)`; `hex::decode` 还原; 列缺 / 坏 hex → None).
    /// ADR-423 §3.5: SQL 侧 hex() 绕开 dll blob 序列化歧义.
    #[must_use]
    pub fn get_blob_hex(&self, col: &str) -> Option<Vec<u8>> {
        self.get_str(col).and_then(|s| hex::decode(s).ok())
    }

    /// 列数.
    #[must_use]
    pub fn len(&self) -> usize {
        self.columns.len()
    }

    /// 是否空行 (无列).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn cipher_row_accessors() {
        let row = CipherRow::new(vec![
            ("cnt".into(), Some("47279".into())),
            ("name".into(), Some("hi".into())),
            ("payload_hex".into(), Some("4142".into())), // hex of [0x41,0x42]
            ("nil".into(), None),
        ]);
        assert_eq!(row.get_str("name"), Some("hi"));
        assert_eq!(row.get_i64("cnt"), Some(47279)); // string→i64
        assert_eq!(row.get_blob_hex("payload_hex"), Some(vec![0x41, 0x42]));
        assert_eq!(row.get_str("nil"), None); // SQL NULL
        assert_eq!(row.get_str("missing"), None); // 列不存在
        assert_eq!(row.get_i64("name"), None); // 非数 parse 失败
        assert_eq!(row.len(), 4);
        assert!(!row.is_empty());
    }

    #[test]
    fn cipher_row_bad_hex_is_none() {
        let row = CipherRow::new(vec![("h".into(), Some("zznothex".into()))]);
        assert_eq!(row.get_blob_hex("h"), None);
    }

    /// K-R4 (代码双审 P0): CipherRow Debug 只露列名, **不露值** (防 `tracing::debug!(?row)` 打消息正文).
    #[test]
    fn cipher_row_debug_redacts_values() {
        let row = CipherRow::new(vec![
            ("message_content".into(), Some("机密正文 secret-msg".into())),
            ("sender".into(), Some("wxid_peer_secret".into())),
        ]);
        let dbg = format!("{row:?}");
        assert!(!dbg.contains("机密正文"), "Debug 泄值: {dbg}");
        assert!(!dbg.contains("secret-msg"), "Debug 泄值: {dbg}");
        assert!(!dbg.contains("wxid_peer_secret"), "Debug 泄 wxid 值: {dbg}");
        assert!(
            dbg.contains("message_content") && dbg.contains("sender"),
            "应露列名: {dbg}"
        );
    }

    /// Cipher + DbSession trait 对象安全 (dyn) — chain/config 切换 impl 必须 object-safe.
    #[tokio::test]
    async fn cipher_and_session_trait_object_safe() {
        struct MockSession;
        #[async_trait]
        impl DbSession for MockSession {
            async fn query(&self, _kind: &str, _sub_db: &Path, _sql: &str) -> Result<Vec<CipherRow>, CipherError> {
                Ok(vec![CipherRow::new(vec![("cnt".into(), Some("47279".into()))])])
            }
        }
        struct MockCipher;
        #[async_trait]
        impl Cipher for MockCipher {
            async fn open_account(&self, _db: &Path, _key: &MasterKey) -> Result<Box<dyn DbSession>, CipherError> {
                Ok(Box::new(MockSession))
            }
            async fn verify(&self, _db: &Path, _key: &MasterKey) -> Result<(), CipherError> {
                Ok(())
            }
            fn name(&self) -> &'static str {
                "mock"
            }
        }

        let c: Box<dyn Cipher> = Box::new(MockCipher);
        assert_eq!(c.name(), "mock");
        let key = MasterKey::from_hex(&"a".repeat(64)).unwrap();
        c.verify(&PathBuf::from("/s.db"), &key).await.unwrap();
        let sess = c.open_account(&PathBuf::from("/s.db"), &key).await.unwrap();
        let rows = sess
            .query("message", Path::new("/m.db"), "SELECT cnt FROM x")
            .await
            .unwrap();
        assert_eq!(rows[0].get_i64("cnt"), Some(47279));
        sess.close().await.unwrap(); // 默认 no-op 可调
    }
}
