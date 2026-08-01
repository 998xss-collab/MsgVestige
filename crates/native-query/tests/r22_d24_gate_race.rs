//! R22 / ADR-508 **D24 会话级懒式落库** 对抗审 —— 并发 / 崩溃 / 新鲜度闸的**真跑**用例。
//!
//! 这些用例分两类:
//!
//! 1. **纯 SQLite** (默认跑): 写租约在**同一个 L1 文件 + 多线程**下的行为。产品自带的单测全在一条
//!    `Connection::open_in_memory()` 上跑, 证不了"两个进程/线程抢同一张表"这件事。
//! 2. **合成加密源库** (`#[ignore]`, 要真账号已缓存的 key): 端到端驱动 `ensure_chat_fresh`,
//!    把新鲜度闸的时序摆出来。key 只用于给测试自造的夹具**加密**, 不落盘明文、不打印。
//!
//! ```text
//! cargo test -p native-query --test r22_d24_gate_race
//! cargo test -p native-query --release --test r22_d24_gate_race -- --ignored --nocapture
//! ```
//!
//! 环境变量: `R22_WXID` (默认 `wxid_abcd1234efgh567`)。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use rusqlite::Connection;

// ═══════════════════════════════════════════════════════════════════════════
// 一、纯 SQLite: 写租约在真文件 + 真并发下的行为
// ═══════════════════════════════════════════════════════════════════════════

fn l1_file(dir: &Path) -> PathBuf {
    let p = dir.join("lease.db");
    let c = native_core::storage::open(&p).unwrap();
    native_core::write_lease::init_write_lease(&c).unwrap();
    p
}

/// **N 个线程同时抢同一片** —— 每个线程一条独立连接 (= 独立进程的等价物)。
/// 不变量: 恰好一个 `Claimed`, 其余全 `HeldByOther`; 账本里 epoch 恰好为 1 (只认领成功过一次)。
#[test]
fn d24_concurrent_claim_exactly_one_winner() {
    let tmp = tempfile::tempdir().unwrap();
    let path = l1_file(tmp.path());
    let n = 16;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let mut hs = Vec::new();
    for i in 0..n {
        let path = path.clone();
        let barrier = barrier.clone();
        hs.push(std::thread::spawn(move || {
            let c = native_core::storage::open(&path).unwrap();
            barrier.wait();
            native_core::write_lease::claim_write_lease(&c, "conv:acct:X", &format!("run-{i}"), 1000).unwrap()
        }));
    }
    let outs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let won = outs
        .iter()
        .filter(|o| matches!(o, native_core::write_lease::LeaseClaim::Claimed(_)))
        .count();
    let held = outs
        .iter()
        .filter(|o| matches!(o, native_core::write_lease::LeaseClaim::HeldByOther { .. }))
        .count();
    let c = native_core::storage::open(&path).unwrap();
    let epoch: i64 = c
        .query_row("SELECT epoch FROM write_lease WHERE lease_key='conv:acct:X'", [], |r| {
            r.get(0)
        })
        .unwrap();
    println!("[并发认领] 线程={n} 赢家={won} 被挡={held} 账本 epoch={epoch}");
    assert_eq!(won, 1, "同一片同一时刻只能有一个写者");
    assert_eq!(held, n - 1);
    assert_eq!(epoch, 1, "只认领成功过一次 → epoch 不应被并发抬高");
}

/// **同一 run_id 并发 = 互相 bump epoch → 双写**。
///
/// 这正是 `ensure_chat_fresh` 用 `q-<pid>` 当 run_id 时, 同一个 HTTP/MCP 进程里两个并发请求会撞上的形状:
/// `claim` 的闸含 `OR owner=run` → 两边都 `Claimed`, 谁都不被挡。修法 = run_id 每次调用唯一。
#[test]
fn d24_same_run_id_defeats_the_lease() {
    let tmp = tempfile::tempdir().unwrap();
    let path = l1_file(tmp.path());
    let a = native_core::storage::open(&path).unwrap();
    let b = native_core::storage::open(&path).unwrap();
    let ca = native_core::write_lease::claim_write_lease(&a, "conv:acct:X", "q-1234", 1000).unwrap();
    let cb = native_core::write_lease::claim_write_lease(&b, "conv:acct:X", "q-1234", 1000).unwrap();
    println!("[同 run_id] A={ca:?}\n           B={cb:?}");
    assert!(matches!(ca, native_core::write_lease::LeaseClaim::Claimed(_)));
    assert!(
        matches!(cb, native_core::write_lease::LeaseClaim::Claimed(_)),
        "同 run_id 第二次认领也成功 = 租约挡不住同进程并发 —— 所以 run_id 必须每次调用唯一"
    );
}

/// **崩溃 = 租约留到 TTL 到期**。领了不 release (= 进程被杀), 别的写者在 TTL 内一律被挡。
/// 这是 D24 现状最贵的一格: 一次 Ctrl-C 会让那个会话的懒式落库停摆 `WRITE_LEASE_TTL_SECS`。
#[test]
fn d24_crashed_writer_blocks_slice_for_full_ttl() {
    let tmp = tempfile::tempdir().unwrap();
    let path = l1_file(tmp.path());
    let dead = native_core::storage::open(&path).unwrap();
    let _lease = native_core::write_lease::claim_write_lease(&dead, "conv:acct:X", "q-dead", 1000).unwrap();
    drop(dead); // 进程没了, 没 release

    let ttl = native_core::write_lease::WRITE_LEASE_TTL_SECS;
    let next = native_core::storage::open(&path).unwrap();
    for t in [1001, 1000 + ttl - 1, 1000 + ttl] {
        let r = native_core::write_lease::claim_write_lease(&next, "conv:acct:X", "q-live", t).unwrap();
        let ok = matches!(r, native_core::write_lease::LeaseClaim::Claimed(_));
        println!("[崩溃残租] t={t} (TTL={ttl}) → {}", if ok { "可接手" } else { "被挡" });
        assert_eq!(ok, t >= 1000 + ttl, "只有跨过 TTL 才接得上");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 二、合成 SQLCipher4 源库 (要真账号已缓存 key)
//    格式 = native-sqlcipher `decrypt.rs` 的反向 (抄自被删的 r22_partial_adversarial round-10)。
// ═══════════════════════════════════════════════════════════════════════════

const PAGE: usize = 4096;
const RESERVE: usize = 80;
const ROUNDS: u32 = 256_000;
const MAC_SALT_XOR: u8 = 0x3a;
/// 全夹具共用一个 salt → PBKDF2-256000 每进程只派生一次。
const SALT: [u8; 16] = [0x5a; 16];

type Enc = cbc::Encryptor<aes::Aes256>;

fn wxid_str() -> String {
    std::env::var("R22_WXID").unwrap_or_else(|_| "wxid_abcd1234efgh567".to_string())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// 取真账号的 master key **字节** —— 只用来加密测试自造的夹具; 不打印、不落盘。
fn master_bytes() -> [u8; 32] {
    let wxid = native_core::key_provider::Wxid::try_new(wxid_str()).unwrap();
    let hex = rt()
        .block_on(native_query::cache_key(&wxid))
        .expect("取不到 key: 先跑 msgvestige auth")
        .to_hex();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn derived() -> &'static ([u8; 32], [u8; 32]) {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;
    static KEYS: std::sync::OnceLock<([u8; 32], [u8; 32])> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let master = master_bytes();
        let t = std::time::Instant::now();
        let mut enc = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&master, &SALT, ROUNDS, &mut enc);
        let mac_salt: Vec<u8> = SALT.iter().map(|b| b ^ MAC_SALT_XOR).collect();
        let mut mac = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&enc, &mac_salt, 2, &mut mac);
        println!("[夹具] PBKDF2-{ROUNDS} 派生一次, 用时 {:?}", t.elapsed());
        (enc, mac)
    })
}

/// 明文 sqlite image → SQLCipher4 加密文件。
fn encrypt(plain: &[u8]) -> Vec<u8> {
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit as _};
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let (enc_key, mac_key) = derived();
    assert_eq!(plain.len() % PAGE, 0, "明文库须页对齐");
    assert_eq!(usize::from(plain[20]), RESERVE, "明文库 reserve 须为 80");
    let mut out = Vec::with_capacity(plain.len());
    for idx in 0..plain.len() / PAGE {
        let page = &plain[idx * PAGE..(idx + 1) * PAGE];
        let is_first = idx == 0;
        let page_num = u32::try_from(idx + 1).unwrap();
        let body_start = usize::from(is_first) * 16;
        let body = &page[body_start..PAGE - RESERVE];
        let iv = [0xA5u8.wrapping_add(u8::try_from(idx % 251).unwrap()); 16];
        let mut buf = body.to_vec();
        let ct = Enc::new(enc_key.into(), (&iv).into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, body.len())
            .unwrap();
        let mut p = vec![0u8; PAGE];
        if is_first {
            p[..16].copy_from_slice(&SALT);
        }
        p[body_start..PAGE - RESERVE].copy_from_slice(ct);
        p[PAGE - RESERVE..PAGE - RESERVE + 16].copy_from_slice(&iv);
        let mut m = <Hmac<Sha512>>::new_from_slice(mac_key).unwrap();
        m.update(&p[body_start..PAGE - RESERVE + 16]);
        m.update(&page_num.to_le_bytes());
        p[PAGE - RESERVE + 16..].copy_from_slice(&m.finalize().into_bytes());
        out.extend_from_slice(&p);
    }
    out
}

/// 开一个 reserve=80 页布局的明文 sqlite (SQLCipher4 明文 image 每页只有前 4016B 可用)。
#[allow(unsafe_code)]
fn open_plain(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "page_size", 4096i64).unwrap();
    let mut want: std::os::raw::c_int = std::os::raw::c_int::try_from(RESERVE).unwrap();
    let rc = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            conn.handle(),
            std::ptr::null::<std::os::raw::c_char>(),
            rusqlite::ffi::SQLITE_FCNTL_RESERVE_BYTES,
            std::ptr::from_mut(&mut want).cast::<std::os::raw::c_void>(),
        )
    };
    assert_eq!(rc, rusqlite::ffi::SQLITE_OK);
    conn
}

fn msg_table(conv: &str) -> String {
    native_core::decoder::anchor::msg_anchor(conv, 0)
        .split(':')
        .next()
        .unwrap()
        .to_string()
}

/// 夹具建表 DDL —— **贴着真库来**(独立复审 P3 / codex round-6 P2)。
///
/// 关键是 `AUTOINCREMENT`: 真库 `message_0.db` 有 3386 条 `sqlite_sequence` 记录, 说明每张 `Msg_`
/// 表都带它 —— 删掉尾部的行之后**新行拿更大的号, 不会重用**。夹具漏掉它就会凭空造出一个生产上
/// 不存在的机制("删了再插会占回旧号"), 拿它去证护栏等于没证。
///
/// (`message_content` 真库声明是 TEXT; SQLite 动态类型下存什么类型就是什么类型 ——
/// `r22x_fingerprint_agrees_across_sides_for_cjk_text_content` 专门绑 String 打 TEXT 那条路。)
fn msg_table_ddl(t: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS \"{t}\" (local_id INTEGER PRIMARY KEY AUTOINCREMENT,
           server_id INTEGER, server_seq INTEGER, origin_source INTEGER, upload_status INTEGER,
           download_status INTEGER, local_type INTEGER, sort_seq INTEGER, create_time INTEGER,
           status INTEGER, real_sender_id INTEGER, message_content TEXT, source BLOB);"
    )
}

/// 合成账号目录: `<tmp>/<wxid>_d24/db_storage/{message,session}`。
struct Env {
    _tmp: tempfile::TempDir,
    data_dir: PathBuf,
    msg_dir: PathBuf,
    l1: PathBuf,
    wxid: native_core::key_provider::Wxid,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let w = wxid_str();
        let data_dir = tmp.path().join("data");
        let storage = data_dir.join(format!("{w}_d24")).join("db_storage");
        let msg_dir = storage.join("message");
        std::fs::create_dir_all(&msg_dir).unwrap();
        std::fs::create_dir_all(storage.join("session")).unwrap();
        // 账号入口库: 只要能过 verify_passphrase (首页 HMAC)。
        let plain = tmp.path().join("plain_session");
        {
            let c = open_plain(&plain);
            c.execute_batch("CREATE TABLE SessionTable (username TEXT);").unwrap();
        }
        std::fs::write(
            storage.join("session").join("session.db"),
            encrypt(&std::fs::read(&plain).unwrap()),
        )
        .unwrap();
        Self {
            data_dir,
            msg_dir,
            l1: tmp.path().join("l1.db"),
            wxid: native_core::key_provider::Wxid::try_new(w).unwrap(),
            _tmp: tmp,
        }
    }

    /// 造/更新一个分片: `convs` 里每个会话建 `Msg_<md5>` 表, 并写入 `1..=n` 条消息。
    fn write_shard(&self, rel: &str, convs: &[(&str, i64)]) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            c.execute_batch("CREATE TABLE IF NOT EXISTS Name2Id (user_name TEXT);")
                .unwrap();
            for (conv, n) in convs {
                let t = msg_table(conv);
                c.execute("INSERT INTO Name2Id (user_name) VALUES (?1)", rusqlite::params![conv])
                    .unwrap();
                c.execute_batch(&msg_table_ddl(&t)).unwrap();
                for i in 1..=*n {
                    c.execute(
                        &format!(
                            "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                               upload_status, download_status, local_type, sort_seq, create_time, status,
                               real_sender_id, message_content, source)
                             VALUES (?1, ?1, 0, 0, 0, 0, 1, ?2, ?3, 2, 1, ?4, x'')"
                        ),
                        rusqlite::params![
                            i,
                            1_700_000_000_000i64 + i * 1000,
                            1_700_000_000i64 + i,
                            format!("m{i}").as_bytes()
                        ],
                    )
                    .unwrap();
                }
            }
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// 造/改写 `<rel>-wal` (只动 WAL 伴生文件, 主库一个字节不碰)。
    /// 重写文件即刷新 mtime —— 这正是"新消息落进 WAL"在文件层留下的唯一痕迹。
    fn touch_wal(&self, rel: &str, bytes: usize) {
        std::fs::write(self.msg_dir.join(format!("{rel}-wal")), vec![0x77u8; bytes]).unwrap();
    }

    fn fresh(&self, conv: &str) -> native_query::ChatFreshness {
        rt().block_on(native_query::ensure_chat_fresh(
            &self.l1,
            &self.wxid,
            conv,
            Some(self.data_dir.to_str().unwrap()),
        ))
        .expect("ensure_chat_fresh")
    }

    fn state(&self, conv: &str) -> Option<(String, String)> {
        let c = native_core::storage::open(&self.l1).ok()?;
        c.query_row(
            "SELECT shards, src_sig FROM chat_refresh_state WHERE account_id_sha=?1 AND chat_id_sha=?2",
            rusqlite::params![
                native_core::sha256_hex(self.wxid.as_str()),
                native_core::sha256_hex(conv)
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
    }

    /// 就地改某一行的 `server_id` —— 模拟"自己发出去的消息拿到服务端回执": 写入时是 0,
    /// 回执到了就地填上真值。**其它字段一个不动**。
    fn set_row_server_id(&self, rel: &str, conv: &str, local_id: i64, sid: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            let n = c
                .execute(
                    &format!("UPDATE \"{t}\" SET server_id = ?1 WHERE local_id = ?2"),
                    rusqlite::params![sid, local_id],
                )
                .unwrap();
            assert_eq!(n, 1, "该改到 1 行");
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// 该会话在 `etl_state` 里的水位原文 —— 用来看"四样信号有没有真落盘"。
    fn watermark(&self, conv: &str) -> Option<String> {
        let c = native_core::storage::open(&self.l1).unwrap();
        c.query_row(
            "SELECT watermark_value FROM etl_state
             WHERE account_id_sha=?1 AND kind='message' AND source LIKE ?2",
            rusqlite::params![
                native_core::sha256_hex(self.wxid.as_str()),
                format!("%{}", msg_table(conv))
            ],
            |r| r.get(0),
        )
        .ok()
    }

    /// 造一个正文按 **TEXT 存储的中文** 的分片 —— 专打"两侧长度口径不一致"那一格。
    ///
    /// SQLite 是动态类型: 绑 `&str` 就存成 TEXT, 这时 `length(x)` 数的是**字符**;
    /// 而 drain 侧拿到的是字节数组。`你好` 一边 2 一边 6 —— 两侧算不出同一个指纹,
    /// **每一轮都会误判成"表被重建"→ 把整个会话重扫重发**。默认夹具全是 ASCII, 守不住这一格。
    fn reset_shard_text_cjk(&self, rel: &str, conv: &str, n: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(self.msg_dir.join(rel));
        {
            let c = open_plain(&plain);
            c.execute_batch("CREATE TABLE IF NOT EXISTS Name2Id (user_name TEXT);")
                .unwrap();
            let t = msg_table(conv);
            c.execute("INSERT INTO Name2Id (user_name) VALUES (?1)", rusqlite::params![conv])
                .unwrap();
            c.execute_batch(&msg_table_ddl(&t)).unwrap();
            for i in 1..=n {
                c.execute(
                    &format!(
                        "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                           upload_status, download_status, local_type, sort_seq, create_time, status,
                           real_sender_id, message_content, source)
                         VALUES (?1, ?1, 0, 0, 0, 0, 1, ?2, ?3, 2, 1, ?4, x'')"
                    ),
                    // 第四个参数绑 **String** → SQLite 存成 TEXT。
                    rusqlite::params![
                        i,
                        1_700_000_000_000i64 + i * 1000,
                        1_700_000_000i64 + i,
                        format!("第{i}条中文消息你好啊")
                    ],
                )
                .unwrap();
            }
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// **带"代次"重造分片** —— 同一个 `local_id` 在不同 `gen` 下 `server_id` / `create_time` / 正文全不同。
    ///
    /// 为什么必须有它: 默认 `write_shard` 的每一行都只由 `i` 决定, 所以"重建表"造出来的行跟旧的**一模一样** ——
    /// 指纹当然对得上, 新护栏根本不会响。**原来那条重建用例就是这么假绿的**(它只数 anchor 总数,
    /// 而新旧同 anchor 同内容, 看不出漏)。要真的打穿, 重建后的内容必须不一样。
    fn reset_shard_gen(&self, rel: &str, conv: &str, n: i64, gen: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(self.msg_dir.join(rel));
        {
            let c = open_plain(&plain);
            c.execute_batch("CREATE TABLE IF NOT EXISTS Name2Id (user_name TEXT);")
                .unwrap();
            let t = msg_table(conv);
            c.execute("INSERT INTO Name2Id (user_name) VALUES (?1)", rusqlite::params![conv])
                .unwrap();
            c.execute_batch(&msg_table_ddl(&t)).unwrap();
            for i in 1..=n {
                c.execute(
                    &format!(
                        "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                           upload_status, download_status, local_type, sort_seq, create_time, status,
                           real_sender_id, message_content, source)
                         VALUES (?1, ?2, 0, 0, 0, 0, 1, ?3, ?4, 2, 1, ?5, x'')"
                    ),
                    rusqlite::params![
                        i,
                        gen * 1000 + i, // server_id 带代次
                        1_700_000_000_000i64 + i * 1000,
                        1_700_000_000i64 + gen * 100_000 + i, // create_time 带代次
                        format!("g{gen}m{i}").as_bytes()      // 正文带代次
                    ],
                )
                .unwrap();
            }
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// L1 里属于第 `gen` 代的行数 —— 用来分辨"补进来的是哪一代的内容"。
    ///
    /// 用 `create_time` 区间认代次(夹具给每代都错开 100000 秒)。正文那列是 `text_content_sha`
    /// (哈希, 不是明文), LIKE 不上; 而 create_time 是逐行真值, 分辨力一样够。
    /// L1 存的是**毫秒**(源库的秒 ×1000)。
    fn l1_rows_of_gen(&self, conv: &str, gen: i64) -> i64 {
        let c = native_core::storage::open(&self.l1).unwrap();
        let lo = (1_700_000_000i64 + gen * 100_000 + 1) * 1000;
        let hi = (1_700_000_000i64 + gen * 100_000 + 1000) * 1000;
        c.query_row(
            "SELECT count(*) FROM message WHERE conv_id_sha=?1 AND create_time BETWEEN ?2 AND ?3",
            rusqlite::params![native_core::sha256_hex(conv), lo, hi],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    fn l1_rows(&self, conv: &str) -> i64 {
        let c = native_core::storage::open(&self.l1).unwrap();
        c.query_row(
            "SELECT count(*) FROM message WHERE conv_id_sha=?1",
            rusqlite::params![native_core::sha256_hex(conv)],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }
}

const CONV: &str = "d24probe@chatroom";

/// **P1 候选**: `ensure_chat_fresh` 用**非 live** cipher (`NativeCipher::new()` = checkpoint 快照,
/// 明确"不合并 WAL"), 但新鲜度签名里**算上了 `-wal` 的 mtime**。
///
/// 于是"新消息只落在 WAL、主库还没 checkpoint"这一格 (native-sqlcipher crate 文档自述这是**常态**:
/// 「微信/WCDB 频繁 checkpoint, 最新几笔常还压在加密 WAL 里未刷盘」) 会走成:
/// 闸因 WAL mtime 变了而**打开** → 读的却是不含 WAL 的快照 → 一条没读到 → 却把**含新 WAL mtime 的签名
/// 记成"已采"** → 下一次查询直接 `AlreadyFresh` 短路。
///
/// 本用例证明后半截 (签名被推进 + 下次短路); 前半截 (WAL 里真有读不到的行) 由
/// `r22_d24_wal_frontier.rs` 在真库上证。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn d24_wal_only_change_is_stamped_as_consumed() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    e.touch_wal("message_0.db", 16);

    let r1 = e.fresh(CONV);
    println!("[闸/WAL] 首采: {r1:?} → L1 {} 行", e.l1_rows(CONV));
    assert!(matches!(r1, native_query::ChatFreshness::Ingested { .. }));
    let (sh1, sig1) = e.state(CONV).expect("首采后必记状态");
    println!("[闸/WAL] shards={sh1} sig1={sig1}");

    // 「新消息落进 WAL, 主库没动」—— 只改 -wal, message_0.db 一个字节不碰。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.touch_wal("message_0.db", 32);

    let r2 = e.fresh(CONV);
    let (_, sig2) = e.state(CONV).expect("状态");
    let rows2 = e.l1_rows(CONV);
    println!("[闸/WAL] WAL 变化后: {r2:?} → L1 {rows2} 行\n          sig2={sig2}");
    assert_ne!(sig1, sig2, "WAL mtime 进了签名 → 闸认为源库变了 (确实开了库)");
    assert_eq!(rows2, 3, "非 live cipher 读不到 WAL 里的东西 → 一条没多");

    let r3 = e.fresh(CONV);
    println!("[闸/WAL] 再查一次: {r3:?}  ← 这一格就是 P1: WAL 的变化被**记成已消费**, 闸关上了");
    assert!(
        matches!(r3, native_query::ChatFreshness::AlreadyFresh),
        "签名已经把没读过的 WAL 变化算成已采 → 后续查询直接短路"
    );
}

/// 新鲜度闸只盯**上次命中的分片**。若该会话的表出现在一个**已存在但没被命中过**的分片里,
/// 目录名单没变 + 老分片没动 → 闸判"没变过"→ 永久漏。
///
/// v1 的自辩是「真机上微信轮转时**新建**分片文件, 目录名单会变, 被名单那段兜住」。**对沉寂会话不成立**:
/// 分片是几个月前建的(名单那时就更新过了), 群今天才醒过来, 消息写进的是**已存在**的活跃分片。
/// (真库实测 message_4.db 建于 2025-11-21、message_5.db 建于 2026-03-29 —— 一个 2026-07 才说话的
/// 沉寂群, 消息进的就是早已存在的 message_5。)
///
/// 而且这一格有**两个洞**, 缺一不可修:
/// 1. **闸**: 签名只覆盖 known → 判"没变过", 连库都不开。
/// 2. **扫描集**: 就算闸开了, `ingest_one_chat` 的 `only_shards` 也只有 known → 照样扫不到。
///
/// v2 修法: 签名存**整份分片快照** + 扫描集 = `known ∪ 变化过的分片`。
/// 本用例是这条修复的回归守卫 —— **它以前断言的是"漏"**, 现在断言"补齐"。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn d24_gate_catches_table_appearing_in_existing_shard() {
    let e = Env::new();
    // 两个分片一开始就都在; 会话只在 message_0 里。
    e.write_shard("message_0.db", &[(CONV, 3)]);
    e.write_shard("message_1.db", &[("someone_else", 2)]);

    let r1 = e.fresh(CONV);
    let (sh, _) = e.state(CONV).unwrap();
    println!("[闸/迁移] 首采 {r1:?}; 记下的 shards = {sh}");
    assert_eq!(sh, "message_0.db", "只命中 message_0");

    // 会话"搬"进已存在的 message_1.db (目录名单不变, message_0.db 不动)。
    e.write_shard("message_1.db", &[(CONV, 5)]);

    let r2 = e.fresh(CONV);
    let rows = e.l1_rows(CONV);
    println!("[闸/迁移] 搬到 message_1.db 后: {r2:?} → L1 {rows} 行 (源库共 3+5=8 条)");
    assert!(
        matches!(r2, native_query::ChatFreshness::Ingested { .. }),
        "message_1.db 动过 → 全快照签名必变 → 闸必须开 (v1 这里返 AlreadyFresh)"
    );
    assert_eq!(
        rows, 8,
        "扫描集含变化过的 message_1.db → 那 5 条必须补进来 (v1 这里停在 3)"
    );

    // 分片集合要**并上**新命中的, 不能把老分片丢了。
    let (sh2, _) = e.state(CONV).unwrap();
    println!("[闸/迁移] 现在记下的 shards = {sh2}");
    assert!(
        sh2.contains("message_0.db") && sh2.contains("message_1.db"),
        "两个分片都要记住: {sh2}"
    );

    // 补齐之后再查一次: 源库一个字节没动 → 快照没变 → 回到零开库的快闸。
    let r3 = e.fresh(CONV);
    println!("[闸/迁移] 补齐后再查: {r3:?}");
    assert!(
        matches!(r3, native_query::ChatFreshness::AlreadyFresh),
        "源库没动 → 必须短路, 否则每次冷查都白开库"
    );
}

/// **并发打开同一个还不存在的 L1 → 有一路直接 `database is locked` 硬失败**。
///
/// `storage::open` 的 `apply_pragmas` 把 `PRAGMA busy_timeout=30000` 排在**最后一条**, 而
/// `PRAGMA page_size` / `journal_mode=WAL` 在它前面 —— 这两条要写库头, 此时 busy_timeout 还是默认 0,
/// 撞上就是即刻 `SQLITE_BUSY`。D24 让每次冷查都自己 `open + init_l1_schema`, 于是"首次建库时来了两个
/// 并发请求"这一格会有一路直接报错 (CLI 命令失败 / HTTP 400 / MCP tool_err)。
#[test]
fn d24_concurrent_open_of_fresh_l1_can_hard_fail() {
    let run = |pre_init: bool| {
        let mut failures = 0;
        for _ in 0..20 {
            let tmp = tempfile::tempdir().unwrap();
            let p = tmp.path().join("fresh.db");
            if pre_init {
                let c = native_core::storage::open(&p).unwrap();
                native_core::storage::init_l1_schema(&c).unwrap();
            }
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
            let mut hs = Vec::new();
            for _ in 0..4 {
                let (p, barrier) = (p.clone(), barrier.clone());
                hs.push(std::thread::spawn(move || {
                    barrier.wait();
                    native_core::storage::open(&p)
                        .map(|c| native_core::storage::init_l1_schema(&c))
                        .map_err(|e| e.to_string())
                }));
            }
            for h in hs {
                if let Err(e) = h.join().unwrap() {
                    failures += 1;
                    if failures == 1 {
                        println!("[建库并发] pre_init={pre_init} 首个错误: {e}");
                    }
                }
            }
        }
        failures
    };
    let fresh = run(false);
    let existing = run(true);
    println!("[建库并发] 20 轮 × 4 并发 · 新建库 → 硬失败 {fresh}/80 次");
    println!("[建库并发] 20 轮 × 4 并发 · 已有库 → 硬失败 {existing}/80 次");
    assert_eq!(
        fresh + existing,
        0,
        "并发开 L1 不该有人被直接拒 (journal_mode=WAL 不走 busy handler, 必须自己重试)"
    );
}

/// 两个**并发**的 `ensure_chat_fresh` 打同一个会话 + 同一个 L1: 不许双写。
/// (同进程两线程 = 同 pid; 用来验 run_id 是否真的每次调用唯一。)
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn d24_two_concurrent_refresh_do_not_double_write() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 200)]);
    // 先把 L1 建好 —— 否则撞的是"并发首建库"那条独立的问题 (见 d24_concurrent_open_of_fresh_l1_can_hard_fail)。
    {
        let c = native_core::storage::open(&e.l1).unwrap();
        native_core::storage::init_l1_schema(&c).unwrap();
        native_core::write_lease::init_write_lease(&c).unwrap();
    }
    let l1 = e.l1.clone();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let wxid = e.wxid.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut hs = Vec::new();
    for _ in 0..2 {
        let (l1, dd, wxid, barrier) = (l1.clone(), dd.clone(), wxid.clone(), barrier.clone());
        hs.push(std::thread::spawn(move || {
            barrier.wait();
            rt().block_on(native_query::ensure_chat_fresh(&l1, &wxid, CONV, Some(&dd)))
        }));
    }
    let outs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    for (i, o) in outs.iter().enumerate() {
        println!("[并发采集] #{i} → {o:?}");
    }
    let c = native_core::storage::open(&e.l1).unwrap();
    let (n, d): (i64, i64) = c
        .query_row(
            "SELECT count(*), count(DISTINCT source||'#'||source_native_id) FROM message",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    println!("[并发采集] message 行数={n} 去重后={d}");
    assert_eq!(n, d, "并发采集不得产生重复行");
    assert_eq!(n, 200, "两个写者合起来必须正好把 200 条采齐");
    let skipped = outs
        .iter()
        .filter(|o| matches!(o, Ok(native_query::ChatFreshness::SkippedHeld { .. })))
        .count();
    assert_eq!(skipped, 1, "恰好一个被租约挡住 (否则 run_id 不唯一 / 租约失效)");
}

/// **取不到 key / 够不着源库 → 报错, 不静默降级**。
#[test]
fn d24_fail_closed_when_source_dir_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let wxid = native_core::key_provider::Wxid::try_new("wxid_nosuchaccount".to_string()).unwrap();
    let r = rt().block_on(native_query::ensure_chat_fresh(
        &tmp.path().join("l1.db"),
        &wxid,
        CONV,
        Some(tmp.path().to_str().unwrap()),
    ));
    println!("[fail-closed] {r:?}");
    // ⚠️ 本条的期望在 D24 审之后**改了**: 原来"够不着源库 → 报错"打断了"冷库拷到别的机器上自足查"
    // 的契约(审查方自己报的 P1: HTTP 传了 ?mode=cold 反而被要求给账号)。现在改成**降级**读 L1 现有的,
    // 但必须如实标出来 —— 关键不变量是"**不许静默装作补过了**"。
    let out = r.expect("够不着源库不该硬失败(冷库自足查的契约)");
    assert!(
        matches!(out, native_query::ChatFreshness::SourceUnavailable { .. }),
        "够不着源库必须报 SourceUnavailable, 实际 {out:?}"
    );
    assert_eq!(
        out.skip_reason(),
        Some("source_unavailable"),
        "原因要进信封的 refresh_skipped, 否则调用方以为读到的是最新的"
    );
    // 而且**不许**留下 chat_refresh_state (留了 = 下次闸命中 = 错误滚下去)。
    assert!(
        !tmp.path().join("l1.db").exists() || {
            let c = native_core::storage::open(&tmp.path().join("l1.db")).unwrap();
            c.query_row("SELECT count(*) FROM chat_refresh_state", [], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
                == 0
        }
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 三、对抗审 d563b2c (v2 全快照签名) —— 新增用例
// ═══════════════════════════════════════════════════════════════════════════

/// **实测探针: 一个"还开着"的 SQLite WAL 连接写入时, `-wal` 的 mtime / len 到底动不动?**
///
/// 为什么要问: v2 签名的三元组是 `(主库 mtime, 主库 len, -wal 的 mtime)` —— **WAL 的长度不在签名里**。
/// WAL 模式下主库在 checkpoint 之前一个字节都不变, 所以"源库有新消息"这件事**全靠 `-wal` 的 mtime 一个信号**。
/// 若 NTFS 在句柄未关闭时不刷新 LastWriteTime, 这个信号就是哑的 → 闸永远短路 → 与被修的 bug 同类。
#[test]
fn r22x_probe_wal_stat_signal_while_handle_open() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("probe.db");
    let wal = tmp.path().join("probe.db-wal");
    let stat = |p: &Path| -> (u64, u64) {
        std::fs::metadata(p)
            .map(|m| {
                (
                    u64::try_from(
                        m.modified()
                            .unwrap()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos(),
                    )
                    .unwrap(),
                    m.len(),
                )
            })
            .unwrap_or((0, 0))
    };

    let c = Connection::open(&db).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    c.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB);")
        .unwrap();
    // 让 WAL 先存在且有内容。
    for i in 0..50 {
        c.execute("INSERT INTO t VALUES (?1, ?2)", rusqlite::params![i, vec![7u8; 200]])
            .unwrap();
    }
    let (m0, l0) = stat(&wal);
    let (dm0, dl0) = stat(&db);
    println!("[WAL 探针] 基线  wal=(mtime={m0}, len={l0})  db=(mtime={dm0}, len={dl0})");

    // 关键: **连接一直开着**, 继续写。
    let mut obs = Vec::new();
    for round in 0..4 {
        std::thread::sleep(std::time::Duration::from_millis(120));
        for i in 0..50 {
            c.execute(
                "INSERT INTO t VALUES (?1, ?2)",
                rusqlite::params![1000 * (round + 1) + i, vec![7u8; 200]],
            )
            .unwrap();
        }
        let (m, l) = stat(&wal);
        let (dm, dl) = stat(&db);
        println!(
            "[WAL 探针] 第{round}轮 wal=(mtime={m}, len={l})  Δmtime={}  Δlen={}  | db mtime 变={} len 变={}",
            m != m0,
            l != l0,
            dm != dm0,
            dl != dl0
        );
        obs.push((m != m0, l != l0));
    }
    drop(c);
    let (m_after, l_after) = stat(&wal);
    println!(
        "[WAL 探针] 连接关闭后 wal=(mtime变={}, len变={})",
        m_after != m0,
        l_after != l0
    );

    let mtime_moved = obs.iter().any(|(m, _)| *m);
    let len_moved = obs.iter().any(|(_, l)| *l);
    println!("[WAL 探针] 结论: 句柄未关时 mtime 会动={mtime_moved} / len 会动={len_moved}");
    assert!(mtime_moved || len_moved, "两个信号都不动 = 新鲜度闸对 WAL 写入完全瞎");
}

impl Env {
    /// 直接改写 `chat_refresh_state.src_sig` —— 造"上次留下的是 v1 / 残缺签名"这几格。
    fn force_sig(&self, conv: &str, sig: &str) {
        let c = native_core::storage::open(&self.l1).unwrap();
        let n = c
            .execute(
                "UPDATE chat_refresh_state SET src_sig=?3 WHERE account_id_sha=?1 AND chat_id_sha=?2",
                rusqlite::params![
                    native_core::sha256_hex(self.wxid.as_str()),
                    native_core::sha256_hex(conv),
                    sig
                ],
            )
            .unwrap();
        assert_eq!(n, 1, "得先有状态行才谈得上改签名");
    }

    /// 丢一个**打不开**的 `message_<n>.db` 进消息目录 (WeChat 轮转出新分片的那一瞬 / 备份工具留下的残件)。
    fn drop_junk_shard(&self, rel: &str, bytes: usize) {
        std::fs::write(self.msg_dir.join(rel), vec![0xABu8; bytes]).unwrap();
    }

    /// 把某个分片**从头重造** (丢掉之前累积的表) —— `write_shard` 是往同一个明文库上累加的。
    fn reset_shard(&self, rel: &str, convs: &[(&str, i64)]) {
        let _ = std::fs::remove_file(self.msg_dir.parent().unwrap().join(format!("plain_{rel}")));
        let _ = std::fs::remove_file(self.msg_dir.join(rel));
        self.write_shard(rel, convs);
    }

    /// **就地改最新那一行** —— 模拟微信自己在干的事: 图片/视频上传完把 CDN 字段回写进
    /// `message_content`、撤回改写正文并改 `local_type`, 顺带动那几个可变列。
    /// **表没被重建**, `local_id` 一个没变。
    fn mutate_newest_row(&self, rel: &str, conv: &str) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            let n = c
                .execute(
                    &format!(
                        "UPDATE \"{t}\" SET message_content = ?1, local_type = 3, upload_status = 2,
                           server_seq = 998877, status = 4
                         WHERE local_id = (SELECT max(local_id) FROM \"{t}\")"
                    ),
                    // 长度也变了 —— 只改内容不改长度的话, 老那版"长度当指纹"还能蒙混过关。
                    rusqlite::params![
                        &b"<msg><img cdnthumburl=\"http://cdn.example/AAAA\" length=\"40961\"/></msg>"[..]
                    ],
                )
                .unwrap();
            assert_eq!(n, 1, "该就地改到 1 行");
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// **把源库换成另一份副本** —— 前 `same_upto` 行跟第 0 代**逐字节一样**, 之后到 `total` 行
    /// 是**别的消息**(第 `new_gen` 代)。整表重造, 但**最老那一行原封不动**。
    ///
    /// 这是这道护栏真实的触发路径: 从备份恢复、部分迁移、回滚数据目录。真库随机 400 张 `Msg_` 表
    /// `MIN(local_id)` 全是 1, 所以任何旧副本的最老那行都跟现在逐字节相同 → **身份指纹必然对得上**,
    /// 只能靠 `max_id` / 游标那行的 `create_time`+`server_id` 认出来。
    ///
    /// ⚠️ 别写成"删掉近期消息让 SQLite 重用 rowid"(我第一版就是这么写的, codex 与独立复审都点了):
    /// 真库是 `local_id INTEGER PRIMARY KEY AUTOINCREMENT`, **不重用**号 —— 那种夹具只有把
    /// `AUTOINCREMENT` 去掉才造得出来, 等于拿一个生产上不存在的机制去证护栏。
    fn swap_in_other_copy(
        &self,
        rel: &str,
        conv: &str,
        same_upto: i64,
        total: i64,
        new_gen: i64,
        keep_ct_at: Option<i64>,
    ) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        let _ = std::fs::remove_file(&plain);
        let _ = std::fs::remove_file(self.msg_dir.join(rel));
        {
            let c = open_plain(&plain);
            c.execute_batch("CREATE TABLE IF NOT EXISTS Name2Id (user_name TEXT);")
                .unwrap();
            let t = msg_table(conv);
            c.execute("INSERT INTO Name2Id (user_name) VALUES (?1)", rusqlite::params![conv])
                .unwrap();
            c.execute_batch(&msg_table_ddl(&t)).unwrap();
            for i in 1..=total {
                // ≤ same_upto 的行用第 0 代的参数 → 跟上一份副本逐字节一样。
                let gen = if i <= same_upto { 0 } else { new_gen };
                c.execute(
                    &format!(
                        "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                           upload_status, download_status, local_type, sort_seq, create_time, status,
                           real_sender_id, message_content, source)
                         VALUES (?1, ?2, 0, 0, 0, 0, 1, ?3, ?4, 2, 1, ?5, x'')"
                    ),
                    rusqlite::params![
                        i,
                        gen * 1000 + i,
                        1_700_000_000_000i64 + i * 1000,
                        // `keep_ct_at` 指定的那一行**保留第 0 代的 create_time** —— 专门造
                        // "游标那一格换了人、可秒数正好一样"这一格, 用来打 `server_id` 那道判据。
                        if keep_ct_at == Some(i) {
                            1_700_000_000i64 + i
                        } else {
                            1_700_000_000i64 + gen * 100_000 + i
                        },
                        format!("g{gen}m{i}").as_bytes()
                    ],
                )
                .unwrap();
            }
            println!(
                "[换副本] 1..{same_upto} 原样 + {}..{total} 换成第 {new_gen} 代",
                same_upto + 1
            );
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// **挖个洞再补回来** —— 造"一份有洞、另一份没有"那个形态: 先删掉 `hole_at` 那一行(模拟
    /// 用户删过一条消息), 采完之后再把它**原样插回去**(模拟恢复了删除前的副本)。
    ///
    /// 关键在**首尾两行都没动**: 最老那行原样, 最新那行原样, `max_id` 也原样 ——
    /// 前四个信号一个都不响。只有"已读那一段的行数"变了(少一条 → 又多回来)。
    fn punch_hole(&self, rel: &str, conv: &str, hole_at: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            let n = c
                .execute(
                    &format!("DELETE FROM \"{t}\" WHERE local_id = ?1"),
                    rusqlite::params![hole_at],
                )
                .unwrap();
            assert_eq!(n, 1, "该删掉 1 行");
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// 把 `punch_hole` 挖掉的那一行按第 `gen` 代原样插回去(显式给 local_id, 所以号还是原来那个)。
    fn refill_hole(&self, rel: &str, conv: &str, hole_at: i64, gen: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            c.execute(
                &format!(
                    "INSERT INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                       upload_status, download_status, local_type, sort_seq, create_time, status,
                       real_sender_id, message_content, source)
                     VALUES (?1, ?2, 0, 0, 0, 0, 1, ?3, ?4, 2, 1, ?5, x'')"
                ),
                rusqlite::params![
                    hole_at,
                    gen * 1000 + hole_at,
                    1_700_000_000_000i64 + hole_at * 1000,
                    1_700_000_000i64 + gen * 100_000 + hole_at,
                    format!("g{gen}m{hole_at}").as_bytes()
                ],
            )
            .unwrap();
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    fn fresh_raw(&self, conv: &str) -> anyhow::Result<native_query::ChatFreshness> {
        rt().block_on(native_query::ensure_chat_fresh(
            &self.l1,
            &self.wxid,
            conv,
            Some(self.data_dir.to_str().unwrap()),
        ))
    }

    fn timed(&self, conv: &str) -> (native_query::ChatFreshness, std::time::Duration) {
        let t = std::time::Instant::now();
        let r = self.fresh(conv);
        (r, t.elapsed())
    }
}

/// **状态格 (1)**: `known` 非空 + 上次是 **v1 旧签名** → 必须强制全扫, 把"会话搬进已存在分片"这一格也接住。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_grid_v1_sig_forces_full_rescan() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    e.write_shard("message_1.db", &[("someone_else", 2)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));

    // 造成"这个库是 v2 之前采过的": 把签名换成 v1 的真实格式。
    e.force_sig(CONV, "message_0.db,message_1.db|message_0.db:1:2:3");
    // 同时会话搬进已存在的 message_1.db。
    e.write_shard("message_1.db", &[(CONV, 5)]);

    let r = e.fresh(CONV);
    let rows = e.l1_rows(CONV);
    let (sh, sig) = e.state(CONV).unwrap();
    println!("[格/v1签名] {r:?} → L1 {rows} 行; shards={sh}; sig={sig}");
    assert!(matches!(r, native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(rows, 8, "v1 签名解析不出来 → 必须当全变过全扫一遍");
    assert!(sig.starts_with("v3|"), "扫完要写成当前版本: {sig}");
}

/// **状态格 (2)**: `known` 非空 + 签名**残缺 / 被截断 / 版本对不上** (库被别的工具改过 / 写了一半 /
/// 老版本二进制写的 / 将来版本写的) → 同样必须全扫。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_grid_corrupt_sig_forces_full_rescan() {
    for bad in [
        "v3|message_0.db:1:2",       // 少一项
        "v3|message_0.db:1:2:3:4:5", // 多一项
        "v3|message_0.db:x:2:3:4",   // 非数字
        "v2|message_0.db:1:2:3",     // 上一版格式 (三元组, 没 WAL 大小)
        "v9|message_0.db:1:2:3:4",   // 将来的版本
    ] {
        let e = Env::new();
        e.write_shard("message_0.db", &[(CONV, 3)]);
        e.write_shard("message_1.db", &[("someone_else", 2)]);
        assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
        e.force_sig(CONV, bad);
        e.write_shard("message_1.db", &[(CONV, 5)]);
        let r = e.fresh(CONV);
        let rows = e.l1_rows(CONV);
        println!("[格/坏签名] sig={bad:<28} → {r:?} L1 {rows} 行");
        assert_eq!(rows, 8, "坏签名必须当'全变过', 否则又是一次静默漏: {bad}");
    }
}

/// **状态格 (3)**: `known` 非空 + 签名是**合法但空**的快照 (`"v3"`, 目录当时一个分片都没有) → 也要全扫。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_grid_empty_snapshot_sig_forces_full_rescan() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    e.write_shard("message_1.db", &[("someone_else", 2)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    e.force_sig(CONV, "v3"); // parse_sig 认它是合法的空快照
    e.write_shard("message_1.db", &[(CONV, 5)]);
    let r = e.fresh(CONV);
    println!("[格/空快照] {r:?} → L1 {} 行", e.l1_rows(CONV));
    assert_eq!(e.l1_rows(CONV), 8, "空快照 = 每个分片都算新出现 → 全扫");
}

/// **对抗审逮到的 P1 回归 (已修)**: 首采成功之后, 消息目录里**新出现一个打不开的 `message_<n>.db`**
/// (微信轮转出新分片的那一瞬 / 残件 / 备份工具留下的同名文件 / 磁盘错)。
///
/// - v1: 扫描集 = `known`, 那个新文件**连开都不开** → 查询照常返回(但那是巧合, 不是设计)。
/// - v2 初版: 它进了 `changed` → 进扫描集 → 被打开 → 解密/HMAC 失败 → **整条冷查硬失败**,
///   而且不自愈(出错不写状态 → 每次都重撞)。**一个坏文件放倒所有会话的所有冷查。**
/// - v2 定版: 源库侧(`PipelineError::Source`)失败 → **退回只开已知分片重试** + 按"够不着源库"降级。
///   查询照常返回数据, 但 `refresh_skipped = source_unavailable` 如实说明"这次没补全", 不谎报新鲜。
///
/// 本用例钉死三件事: 不硬失败 / 不谎报新鲜 / 坏文件消失后自愈。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_new_unreadable_shard_degrades_instead_of_breaking() {
    for (label, bytes) in [("零长度", 0usize), ("垃圾内容 8K", 8192)] {
        let e = Env::new();
        e.write_shard("message_0.db", &[(CONV, 3)]);
        assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
        assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::AlreadyFresh));

        // 首采之后才出现的新分片 —— known 里没有它。
        e.drop_junk_shard("message_9.db", bytes);
        let r = e.fresh_raw(CONV);
        match &r {
            Ok(v) => println!("[新坏分片/{label}] 降级返回: {v:?} (skip={:?})", v.skip_reason()),
            Err(err) => println!("[新坏分片/{label}] 查询**硬失败**: {err}"),
        }
        let v = r.unwrap_or_else(|err| panic!("[{label}] 一个坏文件不该放倒整条冷查: {err}"));
        assert_eq!(
            v.skip_reason(),
            Some("source_degraded"),
            "[{label}] 必须如实标记'这次没补全' —— 报成新鲜就退回原来那个静默漏的病"
        );
        // 好分片的数据仍在(退回 known 重试的那一步)。
        assert_eq!(e.l1_rows(CONV), 3, "[{label}] 坏分片不该连累已经采到的行");

        // 不写状态 → 下次还会再试(而不是被签名挡住)。
        let again = e.fresh_raw(CONV).expect("第二次也不该硬失败");
        assert_eq!(
            again.skip_reason(),
            Some("source_degraded"),
            "[{label}] 坏文件还在 → 仍如实标记"
        );

        // 坏文件消失 → 下一次就该恢复正常(自愈, 不需要人工清状态)。
        std::fs::remove_file(e.msg_dir.join("message_9.db")).unwrap();
        let healed = e.fresh_raw(CONV).expect("自愈路径不该失败");
        println!("[新坏分片/{label}] 删掉坏文件后: {healed:?}");
        assert_eq!(healed.skip_reason(), None, "[{label}] 坏文件没了就该恢复正常");
    }
}

/// **`matched` 覆写语义**: `shards` 列是用这一轮的 `matched` **整列覆盖**写的。
/// 若某个老分片这一轮不再含该会话的表, 它就被从名单里**丢掉**。丢掉之后还接得回来吗?
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_matched_replace_shrinks_shards_column() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    e.write_shard("message_1.db", &[(CONV, 5)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    let (sh1, _) = e.state(CONV).unwrap();
    println!("[覆写] 首采 shards={sh1} / L1 {} 行", e.l1_rows(CONV));
    assert_eq!(sh1, "message_0.db,message_1.db");

    // message_1 被重造 (会话的表没了 —— 迁移 / 清空聊天记录 / 轮转会这样)。
    e.reset_shard("message_1.db", &[("someone_else", 2)]);
    let r2 = e.fresh(CONV);
    let (sh2, _) = e.state(CONV).unwrap();
    println!("[覆写] message_1 里表没了 → {r2:?}; shards={sh2}");
    assert_eq!(
        sh2, "message_0.db",
        "名单被这一轮的 matched 整列覆盖 → message_1 被丢掉"
    );

    // 丢掉之后, 会话又回到 message_1 —— 靠"变化过的分片"应当能接回来。
    e.write_shard("message_1.db", &[(CONV, 9)]);
    let r3 = e.fresh(CONV);
    let (sh3, _) = e.state(CONV).unwrap();
    println!(
        "[覆写] 会话回到 message_1 → {r3:?}; shards={sh3}; L1 {} 行",
        e.l1_rows(CONV)
    );
    assert!(sh3.contains("message_1.db"), "丢掉的分片必须能靠 changed 接回来: {sh3}");
    // 12 = message_0 的 3 + message_1 的 9 个 local_id 都进了 L1。
    // ⚠️ 但注意 stats 只解码了 **4** 条: message_1 被重造后 etl_state 游标还停在 5, 而新表 max_id=9 > 5,
    // "游标倒退护栏"只在 `max_id < cursor` 时才重扫 → 新表 local_id 1..5 这一段**被跳过**。
    // 本夹具里它们与旧表同 anchor 同内容, 所以看不出差别; 真实重建 (迁移/清空聊天记录) 下那一段是**新消息**。
    // 这条是 D24 游标模型的**既有**问题, 不是 d563b2c 引入的 —— 记在这里备查。
    assert_eq!(e.l1_rows(CONV), 12, "回来之后 12 个 anchor 都要在");
}

/// **性能回归的结构量**: `scan_shards = known ∪ changed` —— `known` 里**这一轮根本没动过**的分片
/// 也每次都被重新打开。用 `stats.subsources` 精确计数 (单会话快路下 = 打开且含该会话表的分片数)。
///
/// 为什么非开不可: `shards` 列是用 `matched` **整列覆盖**写的, 不重扫 `known` 就会把它们从名单里丢掉。
/// 于是"覆写语义"直接把每次查询的开库数顶到 `|known| + |变化的分片|`。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_perf_unchanged_known_shards_reopened_every_query() {
    let e = Env::new();
    // 6 个分片, 会话在**全部 6 个**里都有表 (长期活跃的群跨分片就是这样)。
    for i in 0..6 {
        e.write_shard(&format!("message_{i}.db"), &[(CONV, 20)]);
    }
    let (r0, d0) = e.timed(CONV);
    println!("[性能] 首采 {d0:?} -> {r0:?}");
    let (sh, _) = e.state(CONV).unwrap();
    assert_eq!(sh.split(',').count(), 6, "6 个分片都记住了: {sh}");

    let (r1, d1) = e.timed(CONV);
    println!("[性能] 源库没动 -> {r1:?} 用时 {d1:?}");
    assert!(matches!(r1, native_query::ChatFreshness::AlreadyFresh));

    // 只有 message_5 一直在写 (活跃分片), 别的 5 个是冻结的老分片。
    let mut opened = Vec::new();
    let mut times = Vec::new();
    for round in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        e.touch_wal("message_5.db", 16 + round);
        let (r, d) = e.timed(CONV);
        times.push(d);
        let n = match &r {
            native_query::ChatFreshness::Ingested { stats, .. } => stats.subsources,
            other => panic!("活跃分片动了闸必须开, 实得 {other:?}"),
        };
        opened.push(n);
        println!("[性能] 第{round}轮 只有 message_5 的 WAL 动过 -> 实际打开含该会话的分片数 = {n}, 用时 {d:?}");
    }
    println!(
        "[性能] 快闸命中 {d1:?} vs 闸开一次 {:?} (合成夹具每库仅 ~20KB; 真库单库 0.2-0.7s)",
        times.iter().max().unwrap()
    );
    assert!(
        opened.iter().all(|n| *n == 6),
        "只有 1 个分片有新数据, 却每次都开了 6 个: {opened:?}"
    );
}

/// **`NotCovered` / `SkippedHeld` / 出错路径都不写状态 → 签名被冻住 → `changed` 只增不减。**
///
/// 后果: 这类会话 (被 `capture` 白名单排除的 / 已被用户删掉的 / 公众号会话) 从此**每次查询**都要
/// 打开"自冻结那一刻以来变过的所有分片" —— 在活账号上很快就是**全部分片**, 而且永远回不去。
/// v1 这一格只开 `known` 那几个。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_not_covered_freezes_sig_and_scan_set_only_grows() {
    let e = Env::new();
    for i in 0..6 {
        e.write_shard(&format!("message_{i}.db"), &[(&format!("other_{i}@chatroom"), 5)]);
    }
    e.write_shard("message_0.db", &[(CONV, 3)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    let (sh, sig_frozen) = e.state(CONV).unwrap();
    println!("[冻结] 首采 shards={sh}");
    assert_eq!(sh, "message_0.db");

    // 会话从源库里消失 (用户删了聊天 / 被 capture 白名单排除) -> NotCovered, **不写状态**。
    e.reset_shard("message_0.db", &[("other_0@chatroom", 5)]);
    let r = e.fresh(CONV);
    println!("[冻结] 会话在源库里没了 -> {r:?} (skip_reason={:?})", r.skip_reason());
    assert!(matches!(r, native_query::ChatFreshness::NotCovered));
    let (_, sig_now) = e.state(CONV).unwrap();
    assert_eq!(sig_now, sig_frozen, "NotCovered 不写状态 -> 签名冻在首采那一刻");

    // 此后活跃账号继续写别的分片 —— 每一个都永久留在 changed 里。
    for i in 1..6 {
        e.touch_wal(&format!("message_{i}.db"), 16 + i);
    }
    // 把该会话的表塞回**每一个**分片, 用 subsources 数出这一轮到底开了几个。
    for i in 0..6 {
        e.write_shard(&format!("message_{i}.db"), &[(CONV, 2)]);
    }
    let r2 = e.fresh(CONV);
    let n = match &r2 {
        native_query::ChatFreshness::Ingested { stats, .. } => stats.subsources,
        other => panic!("实得 {other:?}"),
    };
    println!("[冻结] 一次 NotCovered 之后, 这一轮打开的分片数 = {n} (known 只有 1 个)");
    assert_eq!(n, 6, "签名冻住 -> changed 累积到全部分片 -> 每次查询开满 6 个");
}

/// **闸开得勤 = 每次冷查都要抢 R17 那把单写者 OS 锁**。
/// 有 `watch` / `ingest` 在跑时, 以前"分片没动过"的会话走快闸直接 `AlreadyFresh`;
/// 现在活跃分片一直在动 -> 闸必开 -> 抢锁失败 -> **每次冷查都报 `refresh_skipped=held`**,
/// 哪怕 L1 里这个会话本来就是最新的。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_watch_lock_turns_fresh_queries_into_held() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    e.write_shard("message_5.db", &[("busy_group@chatroom", 3)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert!(
        matches!(e.fresh(CONV), native_query::ChatFreshness::AlreadyFresh),
        "先确认: 源库不动时确实走快闸"
    );

    // 别的写者 (watch / ingest / live-index) 占着 L1 的单写者锁。
    let _watch = native_core::storage::acquire_watch_lock(&e.l1).expect("拿 watch 锁");

    // 快闸还在 -> 不碰锁, 照样 AlreadyFresh。
    let r_fast = e.fresh(CONV);
    println!("[持锁] 源库没动 -> {r_fast:?} (skip_reason={:?})", r_fast.skip_reason());
    assert!(matches!(r_fast, native_query::ChatFreshness::AlreadyFresh));

    // 只有**别的会话**在收消息 (message_5 的 WAL 动) —— CONV 自己一个字节没变。
    e.touch_wal("message_5.db", 64);
    let r_held = e.fresh(CONV);
    println!(
        "[持锁] 只有别的会话在收消息 -> {r_held:?} (skip_reason={:?})  <- v1 这里是 AlreadyFresh",
        r_held.skip_reason()
    );
    assert!(
        matches!(r_held, native_query::ChatFreshness::SkippedHeld { .. }),
        "全目录签名把闸打开 -> 撞上 watch 的锁 -> 本来最新的会话被报成 held"
    );
    assert_eq!(r_held.skip_reason(), Some("held"), "信封会挂上'这次没补成'的标");
}

/// **多个会话并发冷查**: 闸开得勤之后, 单写者 OS 锁 (每个 L1 文件一把, 不分会话) 成了全局串行点。
/// N 路并发 -> 只有 1 路能真刷, 其余全被报成 `held`。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_concurrent_queries_on_different_chats_mostly_held() {
    let e = Env::new();
    let convs: Vec<String> = (0..4).map(|i| format!("chat_{i}@chatroom")).collect();
    for (i, c) in convs.iter().enumerate() {
        e.write_shard(&format!("message_{i}.db"), &[(c.as_str(), 5)]);
    }
    e.write_shard("message_5.db", &[("busy_group@chatroom", 3)]);
    for c in &convs {
        assert!(matches!(e.fresh(c), native_query::ChatFreshness::Ingested { .. }));
    }
    for c in &convs {
        assert!(
            matches!(e.fresh(c), native_query::ChatFreshness::AlreadyFresh),
            "先都稳态"
        );
    }

    // 活跃分片收了一条消息 —— 与这 4 个会话全都无关。
    e.touch_wal("message_5.db", 128);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(convs.len()));
    let mut hs = Vec::new();
    for c in convs.clone() {
        let (l1, dd, wxid, b) = (
            e.l1.clone(),
            e.data_dir.to_str().unwrap().to_string(),
            e.wxid.clone(),
            barrier.clone(),
        );
        hs.push(std::thread::spawn(move || {
            b.wait();
            rt().block_on(native_query::ensure_chat_fresh(&l1, &wxid, &c, Some(&dd)))
        }));
    }
    let outs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let held = outs
        .iter()
        .filter(|o| matches!(o, Ok(native_query::ChatFreshness::SkippedHeld { .. })))
        .count();
    for (i, o) in outs.iter().enumerate() {
        println!("[并发/不同会话] #{i} -> {o:?}");
    }
    println!("[并发/不同会话] {} 路并发中被报 held 的 = {held}", convs.len());
    assert!(
        held > 0,
        "v1 这一格 4 路全是 AlreadyFresh (0 held); v2 因为闸开了才撞上串行锁"
    );
}

/// **角度 3 (采集窗口)**: 快照是在采集**之前**拍的。采集**期间**才写进源库的消息, 会不会被这次写下去的
/// 签名盖住? 用另一个线程在 `fresh()` 跑到一半时改写分片来实测。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_writes_during_ingest_are_not_stamped_as_consumed() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));

    // 触发一次真采集 (改 message_0), 同时另起线程在采集途中再追加一批。
    e.write_shard("message_0.db", &[(CONV, 6)]);
    let dir = e.msg_dir.clone();
    let parent = e.msg_dir.parent().unwrap().to_path_buf();
    let writer = std::thread::spawn(move || {
        // 采集开始后 ~40ms 再写 —— 落在 stat_shards 之后。
        std::thread::sleep(std::time::Duration::from_millis(40));
        let plain = parent.join("plain_message_0.db");
        {
            let c = open_plain(&plain);
            let t = msg_table(CONV);
            for i in 7..=11 {
                c.execute(
                    &format!(
                        "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                           upload_status, download_status, local_type, sort_seq, create_time, status,
                           real_sender_id, message_content, source)
                         VALUES (?1, ?1, 0, 0, 0, 0, 1, ?2, ?3, 2, 1, ?4, x'')"
                    ),
                    rusqlite::params![
                        i,
                        1_700_000_000_000i64 + i * 1000,
                        1_700_000_000i64 + i,
                        format!("m{i}").as_bytes()
                    ],
                )
                .unwrap();
            }
        }
        std::fs::write(dir.join("message_0.db"), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    });
    let r = e.fresh(CONV);
    writer.join().unwrap();
    println!("[采集窗口] 这一轮 {r:?} -> L1 {} 行", e.l1_rows(CONV));

    // 关键: 下一次查询**必须**还认为源库变过 (签名是采集前拍的, 盖不住采集期间的写入)。
    let r2 = e.fresh(CONV);
    println!(
        "[采集窗口] 紧接着再查 -> {r2:?} -> L1 {} 行 (源库共 11 条)",
        e.l1_rows(CONV)
    );
    assert_eq!(e.l1_rows(CONV), 11, "采集期间写进来的消息被签名盖住了 -> 永久漏");
}

/// **量一下边际开库成本**: 同一个进程内 (PBKDF2 派生已被 `native-sqlcipher::keycache` 缓存),
/// 扫描集 = 2 个分片 vs 6 个分片 vs 走快闸, 各自耗时。
///
/// v1 在"只有别的会话在收消息"这一格是**快闸**(0 开库); v2 是 `known ∪ changed`。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_perf_marginal_cost_of_widened_scan_set() {
    let e = Env::new();
    for i in 0..6 {
        e.write_shard(&format!("message_{i}.db"), &[(&format!("other_{i}@chatroom"), 30)]);
    }
    // 被查的会话只住在 message_0。
    e.write_shard("message_0.db", &[(CONV, 30)]);
    let (_, warm) = e.timed(CONV); // 首采 = 全扫 6 个 (顺带把 key 派生烘热)
    println!("[边际] 首采(全扫 6) {warm:?}");

    let mut fast = Vec::new();
    let mut two = Vec::new();
    let mut six = Vec::new();
    for round in 0..3u64 {
        // ① 源库一个字节没动 —— v1 与 v2 都走快闸。
        let (r, d) = e.timed(CONV);
        assert!(matches!(r, native_query::ChatFreshness::AlreadyFresh));
        fast.push(d);

        // ② 只有活跃分片 message_5 收了消息 (与被查会话无关) —— v1=快闸, v2=开 {0,5}。
        e.touch_wal("message_5.db", 100 + usize::try_from(round).unwrap());
        let (r, d) = e.timed(CONV);
        assert!(matches!(r, native_query::ChatFreshness::Ingested { .. }));
        two.push(d);

        // ③ 5 个分片都动过 (多会话活跃账号的常态) —— v2 开满 6 个。
        for i in 1..6 {
            e.touch_wal(
                &format!("message_{i}.db"),
                200 + usize::try_from(round).unwrap() * 10 + i,
            );
        }
        let (r, d) = e.timed(CONV);
        assert!(matches!(r, native_query::ChatFreshness::Ingested { .. }));
        six.push(d);
    }
    let avg = |v: &[std::time::Duration]| v.iter().sum::<std::time::Duration>() / u32::try_from(v.len()).unwrap();
    println!(
        "[边际] 快闸(0 开库) {:?} | 开 2 个分片 {:?} | 开 6 个分片 {:?}",
        avg(&fast),
        avg(&two),
        avg(&six)
    );
    println!(
        "[边际] 每多开 1 个合成分片 ≈ {:?} (夹具库仅 ~30KB; 真库 0.4-2.1GB, 提交自述单库 0.2-0.7s)",
        (avg(&six).saturating_sub(avg(&two))) / 4
    );
    assert!(avg(&two) > avg(&fast), "闸开一次总比快闸贵");
}

/// **拆一下"闸开一次 ~3s"的固定成本花在哪** —— 与分片数无关, 说明不是解密数据量。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_probe_where_the_gate_open_cost_goes() {
    let wxid = native_core::key_provider::Wxid::try_new(wxid_str()).unwrap();
    for i in 0..3 {
        let t = std::time::Instant::now();
        let _ = rt().block_on(native_query::cache_key(&wxid)).unwrap();
        println!("[成本] cache_key 第{i}次: {:?}", t.elapsed());
    }
    // 再量"开一个合成加密库并读一次 sqlite_master"的成本 (同 salt, keycache 应当命中)。
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 5)]);
    let (_, d1) = e.timed(CONV);
    let (_, d2) = e.timed(CONV); // 快闸
    e.touch_wal("message_0.db", 32);
    let (_, d3) = e.timed(CONV);
    e.touch_wal("message_0.db", 64);
    let (_, d4) = e.timed(CONV);
    println!("[成本] 首采={d1:?} 快闸={d2:?} 再开一次={d3:?} 又开一次={d4:?}");
}

// ── 第二轮: 打 f938feb 那条"坏分片降级"补丁本身 ───────────────────────────────

/// **降级补丁 (1)**: 坏分片在场时, `known` 分片里的**新消息**还进得来吗? 进得来的话,
/// 为什么还报 `source_unavailable`?
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_fallback_ingests_good_shard_but_still_reports_unavailable() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    let (_, sig0) = e.state(CONV).unwrap();

    // 坏分片出现 + 已知分片里真的来了 5 条新消息。
    e.drop_junk_shard("message_9.db", 0);
    e.write_shard("message_0.db", &[(CONV, 8)]);

    let r = e.fresh(CONV);
    let rows = e.l1_rows(CONV);
    let (_, sig1) = e.state(CONV).unwrap();
    println!("[降级] {r:?} (skip={:?}) → L1 {rows} 行", r.skip_reason());
    assert_eq!(rows, 8, "退回只开 known 之后, 好分片的新消息应当照样补进来");
    assert!(
        matches!(r, native_query::ChatFreshness::SourceDegraded { .. }),
        "够得着但有片读不开 = SourceDegraded, 跟'够不着'分开"
    );
    assert_eq!(sig1, sig0, "降级路径**不写状态** → 签名冻住");

    // 于是坏文件在一天, 这个会话就一天回不到快闸 —— 每次查询都要"宽扫失败 + 窄扫重试"两趟。
    let (r2, d2) = e.timed(CONV);
    println!("[降级] 源库此后一个字节没动, 再查: {r2:?} 用时 {d2:?}  ← 期望本该是 AlreadyFresh");
    assert!(
        !matches!(r2, native_query::ChatFreshness::AlreadyFresh),
        "签名冻住 → 快闸永远命不中 (这是降级路径的持续代价)"
    );

    // 坏文件消失 → 自愈。
    std::fs::remove_file(e.msg_dir.join("message_9.db")).unwrap();
    let r3 = e.fresh(CONV);
    println!("[降级] 删掉坏文件: {r3:?} → L1 {} 行", e.l1_rows(CONV));
    assert!(matches!(r3, native_query::ChatFreshness::Ingested { .. }));
    assert!(
        matches!(e.fresh(CONV), native_query::ChatFreshness::AlreadyFresh),
        "之后回到快闸"
    );
}

/// **两侧指纹必须同源的回归守卫**(codex round-2 P1): 正文是 **TEXT 存储的中文** 时,
/// 探测侧 `length(x)` 数字符、drain 侧数字节 —— 两边算不出同一个值 → 每轮误判"表被重建" → 全量重扫重发。
///
/// 判据: 源库**没有新行**、只是文件动了一下(闸会开)→ 这一轮必须 `messages_decoded == 0`。
/// 若两侧不同源, 这里会变成把 4 条全部重扫一遍。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_fingerprint_agrees_across_sides_for_cjk_text_content() {
    let e = Env::new();
    e.reset_shard_text_cjk("message_0.db", CONV, 4);
    let r1 = e.fresh(CONV);
    println!("[同源] 首采 {r1:?} → L1 {} 行", e.l1_rows(CONV));
    assert_eq!(e.l1_rows(CONV), 4);

    // 只动文件(WAL), 一行没加 → 闸会开, 但 drain 该一条不解。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.touch_wal("message_0.db", 16);

    let r2 = e.fresh(CONV);
    println!("[同源] 只动文件后: {r2:?}");
    let decoded = match &r2 {
        native_query::ChatFreshness::Ingested { stats, .. } => stats.messages_decoded,
        other => panic!("这一轮该是 Ingested(闸开了但没新行), 实际 {other:?}"),
    };
    assert_eq!(
        decoded, 0,
        "两侧指纹必须算出同一个值。这里非 0 = 游标被判成失效 → 整个会话被重扫重发          (中文正文按 TEXT 存时 length() 数字符、drain 侧数字节, 就会这样)"
    );
}

/// **老裸数字水位那一支的回归守卫** —— 第三轮对抗审逮到、已修。
///
/// 带指纹的水位格式从没发布过 → **现存每一个 L1 的每一个子源水位都是裸数字**
/// (审查方真库实测 `msgcol-l1.db`: 176 条 message 水位, 带指纹的 **0** 条), 所以每个会话都要
/// 恰好走这一支一次。原来那一支"只补种指纹不重扫": 一旦升级前正好赶上重建(迁移 / 清空聊天记录 /
/// 换设备), 这一轮就漏掉游标以下的行, **而且下一轮指纹已按新一代种好, 护栏永远不会再响 = 永久漏**
/// (实测过: 新表 9 条只补进 4 条, 再采一轮还是 4 条; L1 里 1..5 还挂着源库已经没有的旧内容)。
///
/// 上一版 `{"id","sid","ct"}` 我已判"强制重扫一次是安全动作" —— 裸数字的暴露面**完全相同**,
/// 处置就该一致。代价: 升级后每个会话第一轮全量重扫一次(采集三种写全幂等), 慢但只发生一次;
/// 静默把数据缺口水泥封住则没法补救。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_legacy_bare_watermark_forces_one_rescan() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(e.l1_rows(CONV), 5, "首采 5 条");

    // 把水位改回**裸数字** = 升级前的样子(现存所有 L1 都是这个形状)。
    {
        let c = native_core::storage::open(&e.l1).unwrap();
        let n = c
            .execute(
                "UPDATE etl_state SET watermark_value = CAST(json_extract(watermark_value,'$.id') AS TEXT)
                 WHERE watermark_value LIKE '{%'",
                [],
            )
            .unwrap();
        println!("[老水位] 改成裸数字的行数 = {n}");
        assert!(n >= 1, "得先有带指纹的水位才谈得上改回裸数字");
    }

    // 表被重建: id 从 1 重来、9 条、内容全是新一代。新表最大 id 9 > 旧水位 5。
    e.reset_shard_gen("message_0.db", CONV, 9, 1);

    let r = e.fresh(CONV);
    let g0 = e.l1_rows_of_gen(CONV, 0);
    let g1 = e.l1_rows_of_gen(CONV, 1);
    println!("[老水位] 重建后 {r:?} → 第0代 {g0} 行 / 第1代 {g1} 行");
    assert_eq!(
        g1, 9,
        "裸数字水位必须触发一次全量重扫 → 新表 9 条全进来。         修之前这里是 4(只补种指纹不重扫), 而且下一轮指纹已按新一代种好 → 永久漏"
    );
    assert_eq!(g0, 0, "旧一代内容必须被顶掉, 别留源库已经没有的行");
    match &r {
        native_query::ChatFreshness::Ingested { stats, .. } => {
            assert_eq!(stats.rescanned_subsources, 1, "老水位触发的重扫也得记一笔");
        }
        other => panic!("该是 Ingested, 实际 {other:?}"),
    }
}

/// **"老格式重扫没被计数"的回归守卫 (codex round-9 P2)**。
///
/// 老格式里有几种是在 `from_watermark_value` **解析阶段**就被打回 0 的
/// (`{"id","sid","ct"}` / 有 `fp` 没 `ct` / 有 `ct` 没 `sid` 键), 它们**压根走不到**
/// `cursor.local_id > 0` 那个护栏块 —— 而计数原来只加在护栏块里。
///
/// 于是最该被数到的场景反倒数不到: **升级后第一轮每个会话都走这条路**。
/// 那一轮 `messages_decoded` 会很大, 调用方却看到 `rescanned_subsources = 0`,
/// 只能理解成"真来了这么多新消息"。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_legacy_object_watermark_rescan_is_counted() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    let w1 = e.watermark(CONV).expect("首采后该有水位");
    assert!(w1.contains(r#""sid""#), "首采该写现行四元格式, 实际 {w1}");

    // 把水位改成**有 fp、没 ct/sid 键**的老形状 —— 解析阶段就会被判"重扫一次"。
    {
        let c = native_core::storage::open(&e.l1).unwrap();
        let n = c
            .execute(
                "UPDATE etl_state
                 SET watermark_value = json_object('id', json_extract(watermark_value,'$.id'),
                                                   'fp', json_extract(watermark_value,'$.fp'))
                 WHERE watermark_value LIKE '{%'",
                [],
            )
            .unwrap();
        assert!(n >= 1, "得先有现行格式的水位才谈得上改成老形状");
    }
    let w2 = e.watermark(CONV).unwrap();
    println!("[老格式计数] 改成 {w2}");
    assert!(!w2.contains(r#""ct""#) && !w2.contains(r#""sid""#));

    // 源库一条没变, 只是文件动一下让闸开。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.touch_wal("message_0.db", 16);

    let r = e.fresh(CONV);
    match &r {
        native_query::ChatFreshness::Ingested { stats, .. } => {
            println!(
                "[老格式计数] 解出 {} 条, rescanned = {}",
                stats.messages_decoded, stats.rescanned_subsources
            );
            assert_eq!(stats.messages_decoded, 5, "老格式水位 → 该会话从 0 全量重扫");
            assert_eq!(
                stats.rescanned_subsources, 1,
                "**解析阶段**打回 0 的重扫也必须计数 —— 这正是升级后第一轮每个会话都走的那条路"
            );
        }
        other => panic!("该是 Ingested, 实际 {other:?}"),
    }
}

/// **外部复审 P1 的回归守卫**: 微信把 `Msg_` 表**重建**且**新表长过旧水位** —— 旧护栏彻底失效那一格。
///
/// 旧水位 5、新表 1..9 时 `max_id(9) > cursor(5)`, "游标比最大 id 还大"那条不响, 而
/// `WHERE local_id > 5` 只读 6..9 → **新的 1..5 永久漏掉**, 且各路信号全是干净的。
///
/// ⚠️ **这一格以前测不出来**: 默认夹具的每行只由 `i` 决定, 重建出来的行跟旧的一模一样,
/// 所以"漏了 1..5"和"1..5 本来就在"在数据上不可分 —— 老用例只数 anchor 总数, 于是一直是绿的。
/// 这里用 `reset_shard_gen` 让重建后的**内容真的不同**(正文 `g1m*`、`server_id`、`create_time` 全变),
/// 断言就落在"**L1 里 1..9 全是新一代的内容**"上。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_table_rebuilt_larger_than_cursor_is_rescanned() {
    let e = Env::new();
    // 第一代: 5 条。
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let r1 = e.fresh(CONV);
    println!(
        "[重建] 首采 {r1:?} → L1 {} 行 (第0代 {} 行)",
        e.l1_rows(CONV),
        e.l1_rows_of_gen(CONV, 0)
    );
    assert_eq!(e.l1_rows(CONV), 5, "首采 5 条");
    assert_eq!(e.l1_rows_of_gen(CONV, 0), 5);

    // 微信重建这张表: id 从 1 重来、共 9 条, **内容全是新一代**。新表最大 id 9 > 旧水位 5。
    e.reset_shard_gen("message_0.db", CONV, 9, 1);

    let r2 = e.fresh(CONV);
    let total = e.l1_rows(CONV);
    let g0 = e.l1_rows_of_gen(CONV, 0);
    let g1 = e.l1_rows_of_gen(CONV, 1);
    println!("[重建] 重建后 {r2:?} → L1 共 {total} 行 (第0代 {g0} / 第1代 {g1})");
    assert!(matches!(r2, native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(
        g1, 9,
        "**新表 9 条必须全部进来**。修之前这里是 4(只读到 6..9), 而 1..5 还留着第0代的旧内容 ——          那就是复审逮到的静默漏。"
    );
    assert_eq!(
        g0, 0,
        "1..5 的旧内容必须被新内容顶掉(message 主表 INSERT OR REPLACE 同 anchor)"
    );
    assert_eq!(total, 9, "同 anchor 覆盖, 不该出现 9+5 双份");
}

/// **锚点搬家的反例 (第三轮对抗审 P2)**: 微信**就地改最新那一行**(图片上传完回写 CDN 字段 /
/// 撤回改写正文), 表根本没被重建 —— 不许触发重扫。
///
/// 原来锚点是"**游标那一行**", 而游标永远指向最新一条, 恰恰是最容易被就地改的那一行:
/// 每发一张图 → 指纹变 → 判成"表被重建" → 整个会话从 0 重扫 + 重发一遍事件。
/// 真库佐证: 8 张 `Msg_` 表最新两行的 `upload_status` **全是 0**(含 `local_type=3` 图片),
/// 说明"上传完回写"确实就发生在游标那一格上。
///
/// 搬到"**最老那一行**"两头都占: 重建 ⟹ 新表从 1 开始, 最老那行的 `local_id` 和内容都变 → 逮到
/// (`r22x_table_rebuilt_larger_than_cursor_is_rescanned` 守着); 就地改最新那条 ⟹ 最老那行没动 → 不误判。
///
/// ⚠️ **残留(如实记账)**: 被就地改掉的那一行, L1 里留的还是改之前的内容 —— keyset 游标天生
/// 看不见"已经扫过的行又被改了"。这不是本次改动引入的: 老锚点也只是"恰好"盖住**最新那一条**,
/// 且代价是每次上传都全量重扫重发。要真解得另开一件(补扫尾部 N 行), 事件会重发, 得单独设计。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_inplace_update_of_newest_row_is_not_a_rebuild() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let r1 = e.fresh(CONV);
    println!("[就地改] 首采 {r1:?} → L1 {} 行", e.l1_rows(CONV));
    assert_eq!(e.l1_rows(CONV), 5, "首采 5 条");

    // 文件签名要真的变(闸得开), 才谈得上"闸开了之后会不会误判重建"。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.mutate_newest_row("message_0.db", CONV);

    let r2 = e.fresh(CONV);
    let decoded = match &r2 {
        native_query::ChatFreshness::Ingested { stats, .. } => stats.messages_decoded,
        other => panic!("闸该开(文件变了) → Ingested, 实际 {other:?}"),
    };
    println!("[就地改] 改最新一行后 {r2:?} → 本轮解出 {decoded} 条");
    assert_eq!(
        decoded, 0,
        "就地改最新一行**不是**表被重建, 一条都不该重扫。         锚点搬到最老那行之前这里是 5(整个会话重扫重发一遍)"
    );
    assert_eq!(e.l1_rows(CONV), 5, "更不该冒出重复行");
}

/// **搬锚点新开的洞之一 (第五轮 codex + 独立复审各自逮到的 P1)**: 源库被换成一份**更短**的副本。
///
/// 老锚点(游标那一行)顺带管着这一格 —— 那一行没了就重扫。换成最老那行以后, 最老那行**逐字节
/// 一样**(真库随机 400 张 `Msg_` 表 `MIN(local_id)` 全是 1), 身份指纹必然对得上, 而游标停在旧的
/// 高位 → `WHERE local_id > 100` 一条也读不到, 之后新来的消息也全躲在游标底下。
///
/// 触发路径是**从备份恢复 / 部分迁移 / 回滚数据目录**, 不是"删了消息让 rowid 重用" ——
/// 真库 `AUTOINCREMENT` 不重用号(见 `msg_table_ddl`)。这一格靠 `max_id < 游标` 认出来。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_shorter_copy_keeping_oldest_row_is_rescanned() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 100, 0);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(e.l1_rows(CONV), 100, "首采 100 条, 游标停在 100");

    // 换成一份 80 行的副本: 1..60 逐字节一样, 61..80 是别的消息。max_id(80) < 游标(100)。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.swap_in_other_copy("message_0.db", CONV, 60, 80, 1, None);

    let r = e.fresh(CONV);
    let g1 = e.l1_rows_of_gen(CONV, 1);
    println!("[换短副本] {r:?} → 第1代 {g1} 行 / L1 共 {} 行", e.l1_rows(CONV));
    assert_eq!(
        g1, 20,
        "61..80 这 20 条必须进来。搬锚点之后没补这道判据时这里是 0 —— 静默漏, 而且源库不再长过 100 就永远不自愈"
    );
    // **护栏响了要数得出来**(独立复审 P2): 不然调用方拿到的 `messages_decoded` 里,
    // "真来了这么多新消息"和"护栏误响把老消息重扫了一遍"完全分不开。
    match &r {
        native_query::ChatFreshness::Ingested { stats, .. } => {
            assert_eq!(stats.rescanned_subsources, 1, "护栏把这个会话从 0 重扫了, 就该记 1 笔");
        }
        other => panic!("该是 Ingested, 实际 {other:?}"),
    }
}

/// **搬锚点新开的洞之二 (第五轮延伸)**: 换上的副本**比旧游标还长**, `max_id` 那条不响。
///
/// 旧游标 100; 新副本 1..60 原样 + 61..110 是别的消息 → `max_id(110) > 100`, 上一条判据**不响**,
/// 而 `WHERE local_id > 100` 只读到 101..110 —— 61..100 那 40 条**永久漏**。
///
/// 只能靠"**游标那一行还是不是原来那条消息**"认: 比 `create_time`(写入时定死, 上传回写和撤回
/// 都不改它, 所以不会像比正文那样误判)+ `server_id`(给秒级时间加基数)。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_longer_copy_replacing_cursor_slot_is_rescanned() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 100, 0);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(e.l1_rows(CONV), 100, "首采 100 条, 游标停在 100");

    // 换成一份 110 行的副本: 1..60 逐字节一样, 61..110 是别的消息。max_id 反超游标。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.swap_in_other_copy("message_0.db", CONV, 60, 110, 1, None);

    let r = e.fresh(CONV);
    let g1 = e.l1_rows_of_gen(CONV, 1);
    println!("[换长副本] {r:?} → 第1代 {g1} 行 / L1 共 {} 行", e.l1_rows(CONV));
    assert_eq!(
        g1, 50,
        "61..110 这 50 条必须全进来。只判 max_id 时这里是 10(只读到 101..110), 61..100 那 40 条永久漏"
    );
}

/// **`server_id` 那道判据的反例 (codex round-6 P1)**: 换上的副本在游标那一格摆了**另一条消息**,
/// 可它的 `create_time` **跟原来那条同一秒**。
///
/// `create_time` 只到秒 —— 真库 4.5 万行里就有 32 行跟别人同秒, 群聊连发时更容易撞。撞上了
/// `cursor_ct` 就认不出来, 而 `max_id(110) > 游标(100)` 那条也不响 → 61..100 永久漏。
/// `server_id` 基数高得多, 靠它兜 —— 但它**不是唯一**的(真库全量扫出过非零重复: 同一条消息
/// re-sync 双写, `server_id` 和 `create_time` 两样都一样), 所以是**加基数不是判定性身份**。
///
/// (夹具让 `local_id = 100` 那一行保留第 0 代的 `create_time`, 其余 61..110 换新一代 ——
/// 所以期望的第 1 代行数是 **49** 不是 50。)
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_same_second_cursor_row_is_caught_by_server_id() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 100, 0);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(e.l1_rows(CONV), 100, "首采 100 条, 游标停在 100");

    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.swap_in_other_copy("message_0.db", CONV, 60, 110, 1, Some(100));

    let r = e.fresh(CONV);
    let g1 = e.l1_rows_of_gen(CONV, 1);
    println!("[同秒换人] {r:?} → 第1代 {g1} 行 / L1 共 {} 行", e.l1_rows(CONV));
    assert_eq!(
        g1, 49,
        "游标那一行秒数没变但换了人, 只比 create_time 认不出来 → 那时这里是 10(只读到 101..110)"
    );
}

/// **`server_id` 回填必须落盘 (codex round-7 P1)**: 游标停在一条**还没拿到服务端回执**的消息上时,
/// 水位里存的 `sid` 是 0(= 这一项没意见)。回执到了以后源库那行就地填上真值 ——
/// 可这个会话要是**不再来新消息**, 空批**不写水位**, 那个 0 就永远换不掉 →
/// `sid` 那道判据对它**永远不生效**, 只剩秒级的 `ct` 兜着。
///
/// 所以护栏判定时顺手把探到的真值补种进游标, 并且**即使本轮零新行也要写一次水位**。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_cursor_server_id_is_backfilled_even_with_no_new_rows() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    // 游标那一行(最新的第 5 条)还没回执 → server_id = 0。
    e.set_row_server_id("message_0.db", CONV, 5, 0);

    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    let w1 = e.watermark(CONV).expect("首采后该有水位");
    println!("[回填] 首采后水位 = {w1}");
    assert!(w1.contains(r#""sid":0"#), "还没回执 → 水位里 sid 该是 0, 实际 {w1}");

    // 回执到了: 就地填上真值。**一条新消息都没有。**
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.set_row_server_id("message_0.db", CONV, 5, 987_654);

    let r = e.fresh(CONV);
    let decoded = match &r {
        native_query::ChatFreshness::Ingested { stats, .. } => stats.messages_decoded,
        other => panic!("闸该开(文件变了) → Ingested, 实际 {other:?}"),
    };
    let w2 = e.watermark(CONV).expect("该还有水位");
    println!("[回填] 回执后 本轮解出 {decoded} 条, 水位 = {w2}");
    assert_eq!(decoded, 0, "只是就地填了个 server_id, 不该重扫");
    // 这一条同时护着 `sid_conflict` 里"**任一侧为 0 就不比**"那半条规则(独立复审用变异测试指出
    // 它零覆盖 —— 那是在这条用例落地之前)。把规则简化成 `a != b`, 探到的真值就会跟存着的 0 判冲突
    // → 这里变成 5。而线上表现是**每发一条自己的消息就把整个会话重扫重发一遍**。
    match &r {
        native_query::ChatFreshness::Ingested { stats, .. } => {
            assert_eq!(stats.rescanned_subsources, 0, "没重扫, 计数也该是 0");
        }
        other => panic!("该是 Ingested, 实际 {other:?}"),
    }
    assert!(
        w2.contains(r#""sid":987654"#),
        "真值必须补种进水位并**落盘**。不落盘的话这个会话的 sid 判据永远停在 0 = 永久失效。实际 {w2}"
    );
}

/// **第五个信号"已读段行数"的反例**(用户 2026-07-30 拍板加这一项): 唯一够得着的那个形态 ——
/// **一份有洞、另一份没有**。
///
/// 前四个信号只看三个点(第一行 / 游标行 / 最大 id), 中间那段没人管:
/// 1. 源库里第 3 行**先被删掉**(用户删过一条消息), 我们**在删之后**才首次采到这一段 →
///    L1 里从来没有过第 3 行;
/// 2. 之后**恢复了删除前的副本**(第 3 行回来了), 而首尾两行、`max_id` 全都原样 ——
///    `oldest_fp` / `max_id` / `cursor_ct` / `cursor_sid` **一个都不响**;
/// 3. `WHERE local_id > 5` 返空 → **第 3 行永久缺失**。
///
/// "已读那一段的行数"从 4 变回 5, 正好逮住。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_hole_refilled_under_cursor_is_caught_by_prefix_rows() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    // 先挖洞, 再首采 —— 所以 L1 里从来没有过第 3 行, 水位记的是"已读段 4 行"。
    e.punch_hole("message_0.db", CONV, 3);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(e.l1_rows(CONV), 4, "源库当时只有 4 行(第 3 行被删了)");
    let w1 = e.watermark(CONV).expect("该有水位");
    println!("[补洞] 首采后水位 = {w1}");
    assert!(w1.contains(r#""n":4"#), "已读段行数该记成 4, 实际 {w1}");

    // 恢复删除前的副本: 第 3 行回来了。首尾两行、max_id 全没变。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.refill_hole("message_0.db", CONV, 3, 0);

    let r = e.fresh(CONV);
    println!("[补洞] 恢复后 {r:?} → L1 {} 行", e.l1_rows(CONV));
    assert_eq!(
        e.l1_rows(CONV),
        5,
        "第 3 行必须补进来。没有第五个信号时这里是 4 —— 前四项一个都不响, 而且**永远不会自愈**"
    );
    match &r {
        native_query::ChatFreshness::Ingested { stats, .. } => {
            assert_eq!(stats.rescanned_subsources, 1, "护栏响了就该记一笔");
        }
        other => panic!("该是 Ingested, 实际 {other:?}"),
    }
}

/// **回归守卫 (codex round-6 P2)**: 会话被采集白名单**一直**排除在外 —— 这是选择性采集的
/// **正常路径**, 必须报 `not_covered`, 不能报成 `source_degraded`("采集范围中途变了")。
///
/// 那一版判据只看 `skipped_subsources > 0` 就断言"范围变了", 而这条常规路径正好也满足它
/// (跳过 > 0 且 `matched` 为空)。判据得是「**跳过与命中同时出现**」才算残缺。
/// 教训: 我上一版注释里写着"既然下面 matched 非空", 判据里却没写这个条件 —— 拿注释当验证使了。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_stable_whitelist_exclusion_is_not_covered_not_degraded() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    // 先正常采一轮, 把 L1 和状态建起来。
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));

    // 只圈**别的**会话 → 本会话从此被白名单一直排除在外。
    {
        let c = native_core::storage::open(&e.l1).unwrap();
        native_core::capture::init_capture_targets(&c).unwrap();
        native_core::capture::add_capture_target(
            &c,
            &native_core::sha256_hex(e.wxid.as_str()),
            "someone_else",
            None,
            1,
        )
        .unwrap();
    }
    // 让签名变一下, 好让闸开(否则会短路)。
    e.write_shard("message_0.db", &[(CONV, 5)]);

    let r = e.fresh(CONV);
    println!("[白名单/稳定排除] {r:?} (skip={:?})", r.skip_reason());
    assert_eq!(
        r.skip_reason(),
        Some("not_covered"),
        "白名单一直排除 = 选择性采集的正常路径, 必须报 not_covered;          报 source_degraded 等于对用户谎称'采集范围刚被改过'"
    );
}

/// **降级补丁 (2) —— 关键一格**: 坏分片在场时, 退回的扫描集是 `known`, **不含变化过的分片**。
/// 于是"沉寂会话醒来搬进已存在的活跃分片"这个**被修的原 bug**, 在坏分片在场期间**又回来了**。
///
/// 要不要真漏取决于**分片扫描顺序** (按文件名排序): 坏分片排在会话新家**后面**时, 宽扫在失败前
/// 已经把新家扫过了 (数据照样进来); 排在**前面**时, 宽扫一条没扫到就炸, 退回 `known` 又不含新家
/// → 那批消息补不进来。这里造的就是后一种: 坏分片 = `message_1.db`, known = `message_2.db`,
/// 会话新家 = `message_3.db`。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_fallback_reopens_the_original_miss_while_a_bad_shard_exists() {
    let e = Env::new();
    e.write_shard("message_2.db", &[(CONV, 3)]);
    e.write_shard("message_3.db", &[("someone_else", 2)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(e.state(CONV).unwrap().0, "message_2.db");

    // 坏分片排在最前 + 会话搬进已存在的 message_3.db。
    e.drop_junk_shard("message_1.db", 0);
    e.write_shard("message_3.db", &[(CONV, 5)]);

    let r = e.fresh(CONV);
    let rows = e.l1_rows(CONV);
    println!(
        "[降级/漏] {r:?} (skip={:?}) -> L1 {rows} 行 (源库 3+5=8)  <- 逐分片采: 坏的只损失它自己",
        r.skip_reason()
    );
    assert_eq!(r.skip_reason(), Some("source_degraded"), "至少不是静默的");
    assert_eq!(
        rows, 8,
        "**这一格原来是 3** —— 上一版'退回只开 known'把被修的原 bug 放了回来(坏分片排在会话新家前面时,             宽扫没扫到新家就炸)。改成逐个分片采之后, message_1 坏了只损失它自己, message_3 照采。"
    );

    // 坏文件消失 -> 变化集重新生效 -> 补齐。
    std::fs::remove_file(e.msg_dir.join("message_1.db")).unwrap();
    let r2 = e.fresh(CONV);
    println!("[降级/漏] 删掉坏文件后: {r2:?} -> L1 {} 行", e.l1_rows(CONV));
    assert_eq!(e.l1_rows(CONV), 8, "坏文件一走必须补齐");
}

/// **降级补丁 (3)**: 坏的是 `known` 里的分片本身 (老分片损坏 / 微信正在重写它) —— 没有更小的安全子集
/// 可退, 必须仍然降级而不是硬失败。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_fallback_when_the_known_shard_itself_is_corrupt() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 3)]);
    e.write_shard("message_1.db", &[("someone_else", 2)]);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));

    // known 里的那个分片被写坏。
    e.drop_junk_shard("message_0.db", 8192);
    let r = e.fresh_raw(CONV);
    match &r {
        Ok(v) => println!("[降级/known坏] {v:?} (skip={:?})", v.skip_reason()),
        Err(err) => println!("[降级/known坏] 硬失败: {err}"),
    }
    let v = r.expect("known 分片坏掉也不该把冷查打死");
    assert!(matches!(v, native_query::ChatFreshness::SourceDegraded { .. }));
    assert_eq!(e.l1_rows(CONV), 3, "L1 里已有的数据不受影响");
}

/// **降级补丁 (4)**: **首采**时就有坏分片 —— `known` 为空, 没有可退的子集。
/// 好分片里的数据这一趟一条也进不来吗?
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r22x_fallback_on_first_ever_ingest_with_a_bad_shard() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 6)]);
    e.drop_junk_shard("message_9.db", 0);

    let r = e.fresh_raw(CONV).expect("首采撞坏分片也不该硬失败");
    let rows = e.l1_rows(CONV);
    println!(
        "[降级/首采] {r:?} (skip={:?}) → L1 {rows} 行 (源库 6 条)",
        r.skip_reason()
    );
    assert!(matches!(r, native_query::ChatFreshness::SourceDegraded { .. }));
    assert!(e.state(CONV).is_none(), "不记状态 → 坏文件一走就能重来");
    println!("[降级/首采] 注意: message_0.db 排在 message_9.db 前面, 所以失败前它已经被扫过 → L1 里有 {rows} 条");

    std::fs::remove_file(e.msg_dir.join("message_9.db")).unwrap();
    let r2 = e.fresh(CONV);
    println!("[降级/首采] 删掉坏文件后: {r2:?} → L1 {} 行", e.l1_rows(CONV));
    assert_eq!(e.l1_rows(CONV), 6, "坏文件一走必须补齐");
}

// ═══════════════════════════════════════════════════════════════════════════
// 独立复审(2026-07-30)对 `dbe3221` / `6dde41e` 写的反例 —— **原样收进来当常驻守卫**。
//
// 它们逮到的是 2 P1 + 1 P2: ①四信号老水位永远建立不起第五个信号 ②本轮没扫到的会话表被误判成
// "被换过"→ 下一轮整表历史当新消息重报 ③用户删一条老消息就重报整段历史。
// 前两条都是"**修了被点名的那一个, 旁边同结构的没修**"——
// `sid` 补种修过、`prefix_rows` 漏了; 写值那一半护住了、判定那一半没护。
// ═══════════════════════════════════════════════════════════════════════════

const CONV2: &str = "d24probe2@chatroom";

impl Env {
    /// 把水位串原样写回 `etl_state` —— 造"上一代格式的水位"。
    /// 扫描器计 `dropped_rows`(游标还活着, 只丢这一行)。这是"永久性的不完整"最便宜的造法:
    /// 这一行每一轮都读不出来, 于是 `partial` 恒为真。
    fn add_bad_typed_row(&self, rel: &str, conv: &str, local_id: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            c.execute_batch("CREATE TABLE IF NOT EXISTS Name2Id (user_name TEXT);")
                .unwrap();
            c.execute("INSERT INTO Name2Id (user_name) VALUES (?1)", rusqlite::params![conv])
                .unwrap();
            c.execute_batch(&msg_table_ddl(&t)).unwrap();
            c.execute(
                &format!(
                    "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                       upload_status, download_status, local_type, sort_seq, create_time, status,
                       real_sender_id, message_content, source)
                     VALUES (?1, ?1, 0, 0, 0, 0, 'x', 0, 1700000099, 2, 1, ?2, x'')"
                ),
                rusqlite::params![local_id, b"bad".to_vec()],
            )
            .unwrap();
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// 把某一行的 `local_type` 改成 **TEXT**(读不出来 → `read_raw_msg` 失败 → `dropped_rows`, 游标活着)
    /// 或改回整数(读得出来了)。模拟"这一行我们路过它的时候读不出来, 后来又读得出来了"。
    fn flip_row_readable(&self, rel: &str, conv: &str, local_id: i64, readable: bool) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            let n = if readable {
                c.execute(
                    &format!("UPDATE \"{t}\" SET local_type = 1 WHERE local_id = ?1"),
                    rusqlite::params![local_id],
                )
                .unwrap()
            } else {
                c.execute(
                    &format!("UPDATE \"{t}\" SET local_type = 'x' WHERE local_id = ?1"),
                    rusqlite::params![local_id],
                )
                .unwrap()
            };
            assert_eq!(n, 1, "该改到 1 行");
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// 往某个会话表尾部**追加**若干行(接着现有最大 local_id 往后排)。
    fn append_rows(&self, rel: &str, conv: &str, from: i64, to: i64, gen: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            for i in from..=to {
                c.execute(
                    &format!(
                        "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                           upload_status, download_status, local_type, sort_seq, create_time, status,
                           real_sender_id, message_content, source)
                         VALUES (?1, ?2, 0, 0, 0, 0, 1, ?3, ?4, 2, 1, ?5, x'')"
                    ),
                    rusqlite::params![
                        i,
                        gen * 1000 + i,
                        1_700_000_000_000i64 + i * 1000,
                        1_700_000_000i64 + gen * 100_000 + i,
                        format!("g{gen}m{i}").as_bytes()
                    ],
                )
                .unwrap();
            }
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    /// 插一行**类型全对、但正文解不开**的行(zstd 魔数开头 + 垃圾字节)。
    ///
    /// 这是**第二条**丢行的路: 扫描器读得出这一行(所以不计 `dropped_rows`), 但 `hot_new` 自己
    /// 按"冷查丢损坏行 → 热查也须跳"的口径把它丢掉。后果跟第一条一样 —— 位置越过去就永久看不见。
    fn add_bad_content_row(&self, rel: &str, conv: &str, local_id: i64) {
        let plain = self.msg_dir.parent().unwrap().join(format!("plain_{rel}"));
        {
            let c = open_plain(&plain);
            let t = msg_table(conv);
            // 0x28 B5 2F FD = zstd 魔数 → 解码器认它是 zstd, 后面是垃圾 → 解不开。
            let mut bad = vec![0x28u8, 0xB5, 0x2F, 0xFD];
            bad.extend_from_slice(b"not really zstd, just garbage bytes");
            c.execute(
                &format!(
                    "INSERT OR REPLACE INTO \"{t}\" (local_id, server_id, server_seq, origin_source,
                       upload_status, download_status, local_type, sort_seq, create_time, status,
                       real_sender_id, message_content, source)
                     VALUES (?1, ?1, 0, 0, 0, 0, 1, ?2, ?3, 2, 1, ?4, x'')"
                ),
                rusqlite::params![
                    local_id,
                    1_700_000_000_000i64 + local_id * 1000,
                    1_700_000_000i64 + local_id,
                    bad
                ],
            )
            .unwrap();
        }
        std::fs::write(self.msg_dir.join(rel), encrypt(&std::fs::read(&plain).unwrap())).unwrap();
    }

    fn set_watermark_raw(&self, conv: &str, v: &str) {
        let c = native_core::storage::open(&self.l1).unwrap();
        let n = c
            .execute(
                "UPDATE etl_state SET watermark_value=?3
                 WHERE account_id_sha=?1 AND kind='message' AND source LIKE ?2",
                rusqlite::params![
                    native_core::sha256_hex(self.wxid.as_str()),
                    format!("%{}", msg_table(conv)),
                    v
                ],
            )
            .unwrap();
        assert_eq!(n, 1, "该改到 1 行水位");
    }
}

/// 从水位串里把 `,"n":<数>` 摘掉 —— 得到上一代(四信号)格式。
fn strip_n(w: &str) -> String {
    let i = w.find(r#","n":"#).expect("该有 n");
    let mut s = w[..i].to_string();
    s.push('}');
    s
}

/// 【审计 B】**四信号老水位升级后, 第五个信号 `n` 永远建立不起来**。
///
/// `from_watermark_value` 故意不因缺 `n` 判迁移(对的, 否则 watch/懒式刷新互相打架), 而 drain 侧是
/// `since.prefix_rows.map(|n| n + 本批行数)` —— `None.map(..)` 恒 `None`。护栏命中"全对得上"那一支时
/// 只补种 `cursor_sid`, **没补 `prefix_rows`**。于是任何一个用上一版(带 fp/ct/sid、不带 n)建起来的
/// 水位, 这一项**永远是 None → 永远不比 → 形态②那个洞照旧敞着**。
///
/// 提交正文说"升级第一轮每个子源都会走一次[从 0 重扫], 于是全体白建" —— 只对**再上一代**(裸数字 /
/// 缺 ct/sid)成立; 四信号格式不重扫, 所以不成立。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_prefix_rows_never_backfilled_for_4signal_watermark() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    e.punch_hole("message_0.db", CONV, 3);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    assert_eq!(e.l1_rows(CONV), 4, "源库当时只有 4 行");
    let w1 = e.watermark(CONV).expect("该有水位");
    println!("[审计B] 首采后水位 = {w1}");
    assert!(w1.contains(r#""n":4"#));

    // ── 把水位降级成"上一代四信号格式" = 现存任何一个用 202a4c4..6dde41e 之间的版本建的 L1 ──
    let old = strip_n(&w1);
    e.set_watermark_raw(CONV, &old);
    println!("[审计B] 降级成四信号水位 = {old}");

    // 恢复删除前的副本: 第 3 行回来了, 首尾两行 + max_id 全没变。
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.refill_hole("message_0.db", CONV, 3, 0);

    let r = e.fresh(CONV); // 懒式刷新 = Deep, 库里真值必然是 5
    let w2 = e.watermark(CONV).expect("该还有水位");
    let rows = e.l1_rows(CONV);
    println!("[审计B] 恢复后 {r:?} → L1 {rows} 行 · 水位 = {w2}");
    assert!(
        w2.contains(r#""n":"#),
        "Deep 探到了真值(5)却不补种 → 水位里永远没有 n, 第五个信号对这条子源永久失效。实际 {w2}"
    );
    assert_eq!(rows, 5, "第 3 行必须补进来");
}

/// 【审计 A】`new --mode hot`: **本轮没扫到的会话表被误判成"被换过"** → 水位复位 → 下一轮把那张表
/// 的全部历史当新消息重报一遍。
///
/// `hot.rs` 尾部那个 `match was` 的**第一支** `Some(prev) if prev != now` 先手命中: 表没扫到时
/// `now` 取不到 → `unwrap_or(0)`, 跟记着的 `prev` 必不等 → 复位。
/// 第二支 `_` 里那句"**只对本轮真扫到的表**……没扫到的 now 是 0, 那不是'行数变 0'而是'没数'"
/// 只护住了写值那一半, **没护住判定那一半**。
///
/// 触发条件是产品自己文档里写着会发生的那几种: `degraded_tables`(分片打不开 / prepare 失败 /
/// query 失败, 且**一个坏分片会带走它引用的全部表**)、`build_degraded_shards`、
/// `truncated_tables`(游标中断在水位那一格之前)。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_hot_new_unscanned_table_is_misjudged_as_replaced() {
    use std::collections::HashMap;
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 5)]);
    e.write_shard("message_1.db", &[(CONV2, 5)]);
    let loc = e.data_dir.join("audit_locator.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();

    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    // ① 第一轮: 全收 → 两张表各建立 {id:5, n:5}
    let r1 = run(None);
    let wm1 = wm_of(&r1);
    println!("[审计A] ①全收 → {} 条新的; 水位 = {wm1:?}", r1.data.len());
    assert_eq!(r1.data.len(), 10);
    assert_eq!(wm1.len(), 2, "两张会话表各一格");

    // ② 第二轮: 什么都没动 → 稳态。护栏不该响, 也不该报出新消息。
    let r2 = run(Some(wm1.clone()));
    println!(
        "[审计A] ②稳态 → {} 条新的, guard_reset_tables={}; summary={}",
        r2.data.len(),
        guard_of(&r2),
        serde_json::to_string(r2.meta.summary.as_ref().unwrap()).unwrap()
    );
    assert_eq!(r2.data.len(), 0, "没有新消息");
    assert_eq!(guard_of(&r2), 0, "稳态下护栏必须恒 0");
    let wm2 = wm_of(&r2);

    // ③ message_1.db 打不开(被写坏 / 正被独占 / 备份工具留下的残件)。
    //    这一轮**只该**标 partial —— 那张表没数, 不是"数出来变了"。
    e.drop_junk_shard("message_1.db", 4096 * 3);
    let r3 = run(Some(wm2.clone()));
    let wm3 = wm_of(&r3);
    println!(
        "[审计A] ③坏分片 → {} 条新的, guard_reset_tables={}; summary={}",
        r3.data.len(),
        guard_of(&r3),
        serde_json::to_string(r3.meta.summary.as_ref().unwrap()).unwrap()
    );
    println!("[审计A] ③之后水位 = {wm3:?}");

    // ④ 分片修好了(备份还原 / 独占解除)。若上一轮把水位复位了, 这里就会把 5 条老消息重报一遍。
    e.write_shard("message_1.db", &[(CONV2, 5)]);
    let r4 = run(Some(wm3.clone()));
    println!(
        "[审计A] ④分片恢复 → {} 条新的 (期望 0); 明细 = {}",
        r4.data.len(),
        serde_json::to_string(&r4.data).unwrap()
    );

    assert_eq!(
        guard_of(&r3),
        0,
        "分片打不开 = 那张表**没数**, 不是'已读段行数变了'。判成'被换过'会把水位清零"
    );
    assert_eq!(r4.data.len(), 0, "分片恢复后不该把老消息当新消息重报");
}

/// 【审计 C】`new --mode hot`: **用户删掉一条老消息**(微信里最日常的操作)也会让护栏复位那张表的水位
/// → 下一轮把整段历史当新消息重报。
///
/// 判据是"已读段行数变没变", 不分方向。行数**变少**说明的是"已读过的行没了" —— 那些行早报过了,
/// 不可能因此漏报; 真正会漏的是行数**变多**(游标底下多出没报过的行)。现在两个方向一视同仁。
/// 冷路(L1)误判一次只是重扫一遍(幂等、用户看不见), 热 `new` 误判一次是**用户屏幕上多出几万条老消息**。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_hot_new_user_deleting_one_message_replays_whole_history() {
    use std::collections::HashMap;
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 5)]);
    let loc = e.data_dir.join("audit_locator_c.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    let r1 = run(None);
    let wm1 = wm_of(&r1);
    println!("[审计C] ①全收 → {} 条; 水位 {wm1:?}", r1.data.len());

    // 用户在微信里删了一条老消息 (local_id=2, 早就报过了)。
    e.punch_hole("message_0.db", CONV, 2);
    let r2 = run(Some(wm1));
    let wm2 = wm_of(&r2);
    println!(
        "[审计C] ②删掉一条老消息 → 本轮 {} 条, guard_reset_tables={}; 水位 {wm2:?}",
        r2.data.len(),
        guard_of(&r2)
    );

    let r3 = run(Some(wm2));
    println!("[审计C] ③下一轮 → {} 条新的 (期望 0)", r3.data.len());
    assert_eq!(guard_of(&r2), 0, "删一条早报过的老消息不该触发复位");
    assert_eq!(r3.data.len(), 0, "不该把整段历史当新消息重报");
}

/// 【审计 D】穷举 `n` 跟 `id` 的配对: BottomN 截断(每表只保前缀 / 后面的表一条都保不到)+ 多轮推进。
/// 两张会话表各 5 条, `limit=3` → 每轮都被截断, 且第一轮起就有表 0 保留。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_hot_new_mark_pairs_under_bottomn_truncation() {
    use std::collections::HashMap;
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 5)]);
    e.write_shard("message_1.db", &[(CONV2, 5)]);
    let loc = e.data_dir.join("audit_locator_d.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            3,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    let mut wm: Option<HashMap<String, native_query::NewHotMark>> = None;
    let mut seen_total = 0usize;
    for round in 1..=6 {
        let r = run(wm.clone());
        let next = wm_of(&r);
        seen_total += r.data.len();
        let mut ks: Vec<_> = next.iter().collect();
        ks.sort_by_key(|(k, _)| (*k).clone());
        println!(
            "[审计D] 第{round}轮 本轮 {} 条 · guard={} · 水位 {:?}",
            r.data.len(),
            guard_of(&r),
            ks
        );
        assert_eq!(guard_of(&r), 0, "第{round}轮不该有复位 —— 表没被换过, 只是没取完");
        wm = Some(next);
    }
    assert_eq!(seen_total, 10, "10 条各报一次, 不重不漏");
    // 每张表最终该是 {id:5, n:5}
    for (k, m) in wm.unwrap() {
        assert_eq!((m.id, m.n), (5, Some(5)), "{k} 的 id/n 该配平");
    }
}

/// 这里用"一行 `local_type` 存成 TEXT 的坏行"造同样的常态(每轮都读不出来 → `dropped_rows` 恒 > 0),
/// 然后跑一遍这个件的核心攻击: 已读段里补回一条没采过的消息。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_persistent_partial_disables_hot_guard_forever() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    e.punch_hole("message_0.db", CONV, 3); // 首采时第 3 行不存在 → 它从没被报过
    e.add_bad_typed_row("message_0.db", CONV2, 1); // 一行永远读不出来的坏行(另一张表)

    let loc = e.data_dir.join("audit_locator_e.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let sum = |r: &native_query::QueryResult| serde_json::to_string(r.meta.summary.as_ref().unwrap()).unwrap();

    let r1 = run(None);
    let wm1 = wm_of(&r1);
    println!("[审计E] ①全收 → {} 条; summary={}", r1.data.len(), sum(&r1));
    println!("[审计E] ①水位 = {wm1:?}");

    // 恢复删除前的副本: 第 3 行回来了。它 <= 水位(5), 永远不会被当成"新" —— 除非护栏认出这张表变了。
    e.refill_hole("message_0.db", CONV, 3, 0);
    let r2 = run(Some(wm1));
    let wm2 = wm_of(&r2);
    println!("[审计E] ②补回第3行 → {} 条; summary={}", r2.data.len(), sum(&r2));
    println!("[审计E] ②水位 = {wm2:?}");

    let r3 = run(Some(wm2));
    let texts: Vec<&str> = r3.data.iter().filter_map(|d| d["text_content"].as_str()).collect();
    println!("[审计E] ③下一轮 → {} 条: {texts:?}", r3.data.len());

    let mark = wm_of(&r1);
    let k = format!("message_0.db\u{1f}{CONV}");
    assert!(
        mark.get(&k).and_then(|m| m.n).is_some(),
        "全库有一行坏行 → 整个账号的 `n` 一格都建立不起来, 护栏等于没装。实际 {:?}",
        mark.get(&k)
    );
    // (字面量按夹具来: `refill_hole(.., 3, 0)` 写进去的正文是 `g0m3` —— 审查方原稿写的 "m3",
    //  那是笔误, 它自己的日志行里印的就是 `["g0m1", …, "g0m3", …]`。行为本身是对的。)
    assert!(
        texts.contains(&"g0m3"),
        "补回来的第 3 行必须被认出来并补报 —— 这正是这一串十三轮要修的那个洞。实际 {texts:?}"
    );
}

/// 推的是: 重扫 → drain 从 0 把 `n` 算出来 → 落盘 → 下一轮不再进这支。
/// 这里把闸强行打开两次, 数两轮各重扫了几次。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_missing_n_migration_rescans_exactly_once() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    assert!(matches!(e.fresh(CONV), native_query::ChatFreshness::Ingested { .. }));
    let w0 = e.watermark(CONV).expect("该有水位");
    e.set_watermark_raw(CONV, &strip_n(&w0));
    println!("[审计F] 降级成四信号 = {}", strip_n(&w0));

    let mut rescans = Vec::new();
    for round in 1..=3 {
        e.force_sig(CONV, &format!("forced-{round}")); // 强行打开新鲜度闸, 不动源库
        let r = e.fresh(CONV);
        let (resc, dec) = match &r {
            native_query::ChatFreshness::Ingested { stats, .. } => (stats.rescanned_subsources, stats.messages_decoded),
            other => panic!("闸该开 → Ingested, 实际 {other:?}"),
        };
        let w = e.watermark(CONV).expect("该有水位");
        println!("[审计F] 第{round}轮 rescanned={resc} decoded={dec} 水位={w}");
        rescans.push(resc);
    }
    assert_eq!(rescans[0], 1, "第一轮该按迁移重扫一次");
    assert_eq!(rescans[1], 0, "第二轮不该再重扫 —— 否则就是每轮全量重扫");
    assert_eq!(rescans[2], 0, "第三轮同上");
}

/// 【审计 G】新加的 `ct` 跟 `id` 配不配 —— BottomN 截断 / 本轮一条没保住 / 新表第一次出现 三格。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_hot_new_ct_pairs_with_id() {
    use std::collections::HashMap;
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 5)]);
    e.write_shard("message_1.db", &[(CONV2, 5)]);
    let loc = e.data_dir.join("audit_locator_g.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            3,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    let mut wm: Option<HashMap<String, native_query::NewHotMark>> = None;
    for round in 1..=6 {
        let r = run(wm.clone());
        let next = wm_of(&r);
        let mut ks: Vec<_> = next.iter().collect();
        ks.sort_by_key(|(k, _)| (*k).clone());
        println!(
            "[审计G] 第{round}轮 {} 条 guard={} 水位 {:?}",
            r.data.len(),
            guard_of(&r),
            ks
        );
        assert_eq!(guard_of(&r), 0, "第{round}轮不该复位");
        wm = Some(next);
    }
    // 两张表都推到了 id=5; 夹具 create_time = 1_700_000_000 + i (秒) → 热查解出来是毫秒。
    for (k, m) in wm.clone().unwrap() {
        println!("[审计G] 终态 {k} → {m:?}");
        assert_eq!(m.id, 5);
        assert_eq!(m.n, Some(5), "{k} 的 n");
        assert_eq!(m.ct, Some(1_700_000_005_000), "{k} 的 ct 必须是 id=5 那一行的时间");
    }
    // 稳态再跑两轮: ct/n 都不该动, 也不该复位。
    for round in 7..=8 {
        let r = run(wm.clone());
        let next = wm_of(&r);
        assert_eq!(guard_of(&r), 0, "第{round}轮稳态不该复位");
        assert_eq!(r.data.len(), 0, "第{round}轮不该有新消息");
        assert_eq!(next, wm.clone().unwrap(), "第{round}轮水位不该变");
        wm = Some(next);
    }
}

/// (SQL 那半截: `live_query.rs:2747` 是 `SELECT … FROM "<表>" ORDER BY local_id`,
///  `hot_new` 传 `base_types=None` 所以没有 WHERE; `local_id` 是 INTEGER PRIMARY KEY = rowid。)
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_scan_order_is_ascending_per_table() {
    let e = Env::new();
    e.write_shard("message_0.db", &[(CONV, 40)]);
    e.write_shard("message_1.db", &[(CONV2, 40)]);
    let loc = e.data_dir.join("audit_locator_m.json");
    let key = native_query::cache_key(&e.wxid);
    let key = rt().block_on(key).expect("key");
    let mut sq = native_core::live_query::SourceQuery::open(e.msg_dir.clone(), key, loc, e.wxid.as_str().to_string());
    sq.build().expect("build");
    let mut per_table: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
    sq.scan_all_messages(false, None, |m, _s, src| {
        per_table
            .entry(format!("{src}\u{1f}{}", m.conv_id))
            .or_default()
            .push(m.local_id);
        true
    })
    .expect("scan");
    assert_eq!(per_table.len(), 2, "两张会话表");
    for (k, ids) in &per_table {
        println!("[审计M] {k} → {} 行, 前 5 个 {:?}", ids.len(), &ids[..5.min(ids.len())]);
        assert!(
            ids.windows(2).all(|w| w[0] < w[1]),
            "{k} 的回调行序必须严格升序: {ids:?}"
        );
        assert_eq!(ids.len(), 40);
    }
}

/// (图片/视频上传完把 CDN 字段写回 `message_content`、撤回改写正文并改 `local_type`)——
/// 路过时正文是半截的 / 类型是坏的, 回写完就正常了。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_mid_prefix_skipped_row_becoming_readable_replays_history() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    e.flip_row_readable("message_0.db", CONV, 2, false); // 路过第 2 行时它读不出来

    let loc = e.data_dir.join("audit_locator_l.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    let r1 = run(None);
    let wm1 = wm_of(&r1);
    println!("[审计L] ①首轮 → {} 条; 水位 {wm1:?}", r1.data.len());

    // 微信把那一行就地回写好了 —— 现在读得出来。**一条新消息都没有。**
    e.flip_row_readable("message_0.db", CONV, 2, true);
    let r2 = run(Some(wm1));
    let wm2 = wm_of(&r2);
    println!(
        "[审计L] ②那行又读得出来 → {} 条, guard_reset_tables={}; 水位 {wm2:?}",
        r2.data.len(),
        guard_of(&r2)
    );

    let r3 = run(Some(wm2));
    let texts: Vec<&str> = r3.data.iter().filter_map(|d| d["text_content"].as_str()).collect();
    println!("[审计L] ③下一轮 → {} 条: {texts:?}", r3.data.len());

    assert_eq!(
        guard_of(&r2),
        0,
        "前缀中间跳了一行又补上, 不是'表被换过' —— 判成换过就把整段历史重报"
    );
    assert_eq!(r3.data.len(), 0, "不该重报老消息");
}

/// ⚠️ 关键在于**展示是在护栏之前算的**: 那几行这一轮已经进了 `data` 给用户看了, 水位却被退回去 ——
/// 所以不是"下一轮再报", 是"每一轮都报, 没有尽头"。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_one_unreadable_row_freezes_the_table_forever() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);

    let loc = e.data_dir.join("audit_locator_n.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };

    let r1 = run(None);
    let mut wm = wm_of(&r1);
    println!("[审计N] ①首轮 → {} 条; 水位 {wm:?}", r1.data.len());

    // 来了 5 条新消息, 其中第 6 条那一行**读不出来**(列映射失败 —— 行数据本身的属性, 每轮都失败)。
    e.append_rows("message_0.db", CONV, 7, 11, 0);
    e.add_bad_typed_row("message_0.db", CONV, 6);

    let mut shown = Vec::new();
    for round in 2..=5 {
        let r = run(Some(wm.clone()));
        let texts: Vec<String> = r
            .data
            .iter()
            .filter_map(|d| d["text_content"].as_str().map(str::to_string))
            .collect();
        wm = wm_of(&r);
        println!("[审计N] 第{round}轮 → {} 条 {texts:?}; 水位 {wm:?}", r.data.len());
        shown.push(texts);
    }
    assert_eq!(shown[0].len(), 5, "第2轮该报出 7..11 这 5 条");
    assert!(
        shown[1].is_empty(),
        "第3轮不该再报一遍 —— 报了就是每一轮都报, 没有尽头。实际 {:?}",
        shown[1]
    );
}

// ─────────── [独立审查追加] --per-conv 多轮端到端 ───────────

/// **[独立复审写的, 原样收进来]** `--per-conv` 开着一直跑到收敛: 每条消息**恰好报一次**, 护栏一次都不许复位,
/// 且每一轮各会话拿到的必须是它的**前缀**(水位靠这条)。
///
/// create_time = 1_700_000_000_000 + local_id*1000 → 反推得出 local_id, 于是能直接核前缀。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_perconv_multi_round_no_loss_no_replay() {
    use std::collections::{HashMap, HashSet};
    const A: &str = "aaa_busy@chatroom";
    const M: &str = "mmm_mid@chatroom";
    const Z: &str = "zzz_quiet@chatroom";
    for (limit, per_conv) in [(4usize, 2usize), (4, 1), (2, 3), (5, 0), (1, 1), (7, 2), (3, 5)] {
        let e = Env::new();
        e.write_shard("message_0.db", &[(A, 6), (M, 6), (Z, 6)]);
        let loc = e.data_dir.join(format!("audit_loc_mr_{limit}_{per_conv}.json"));
        let loc_s = loc.to_str().unwrap().to_string();
        let dd = e.data_dir.to_str().unwrap().to_string();
        let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
            rt().block_on(native_query::hot_new(
                &e.wxid,
                Some(dd.as_str()),
                Some(loc_s.as_str()),
                wm,
                limit,
                per_conv,
                None,
            ))
            .expect("hot_new")
        };
        let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
            serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
        };
        let lid_of = |ct: i64| (ct - 1_700_000_000_000) / 1000;

        let mut wm: Option<HashMap<String, native_query::NewHotMark>> = None;
        let mut seen: HashSet<(String, i64)> = HashSet::new();
        let mut per_conv_seen: HashMap<String, Vec<i64>> = HashMap::new();
        for round in 1..=40 {
            let r = run(wm.clone());
            let s = r.meta.summary.as_ref().unwrap();
            let guard = s["guard_reset_tables"].as_u64().unwrap();
            let lost = s["tables_with_lost_rows"].as_u64().unwrap();
            assert_eq!(guard, 0, "[{limit}/{per_conv}] 第{round}轮护栏复位了 —— 会重报整段历史");
            assert_eq!(lost, 0, "[{limit}/{per_conv}] 第{round}轮报了丢行");
            let rows: Vec<(String, i64)> = r
                .data
                .iter()
                .map(|d| {
                    (
                        d["conv_id"].as_str().unwrap().to_string(),
                        lid_of(d["create_time"].as_i64().unwrap()),
                    )
                })
                .collect();
            assert!(
                rows.len() <= limit,
                "[{limit}/{per_conv}] 第{round}轮超名额: {}",
                rows.len()
            );
            for k in &rows {
                assert!(
                    seen.insert(k.clone()),
                    "[{limit}/{per_conv}] 第{round}轮重报了 {k:?} —— 用户屏幕上会看见重复"
                );
                per_conv_seen.entry(k.0.clone()).or_default().push(k.1);
            }
            let next = wm_of(&r);
            // 前缀不变量: 每个会话累计报出来的必须是 1..=k 连续
            for (c, ids) in &per_conv_seen {
                let mut v = ids.clone();
                v.sort_unstable();
                let want: Vec<i64> = (1..=v.len() as i64).collect();
                assert_eq!(
                    v, want,
                    "[{limit}/{per_conv}] 第{round}轮后会话 {c} 报出来的不是前缀 —— 中间那几条永久看不见了"
                );
                // 水位不许越过没报的行
                let wk = format!("message_0.db\u{1f}{c}");
                if let Some(mk) = next.get(&wk) {
                    assert!(
                        mk.id <= v.len() as i64,
                        "[{limit}/{per_conv}] 第{round}轮 {c} 水位推到 {} 却只报了 {} 条 = 永久漏",
                        mk.id,
                        v.len()
                    );
                }
            }
            wm = Some(next);
            if rows.is_empty() {
                break;
            }
        }
        assert_eq!(
            seen.len(),
            18,
            "[{limit}/{per_conv}] 收敛后该 18 条一条不少, 实得 {} 条",
            seen.len()
        );
        // ⚠️ **拿终局水位再问一遍**(codex 审 ff12d69 的 P2): 循环一见空结果就退出, 从没用过
        // 那次返回的水位。要是"没新消息"那一支保住了每张表的位置、却把护栏那几样写坏了,
        // 上面每条断言照样过 —— 而下一次真查就会判成"这张表被换过"→ 复位 → 重报整段历史。
        let settled = wm.clone().expect("收敛后必有水位");
        let again = run(Some(settled.clone()));
        let s2 = again.meta.summary.as_ref().unwrap();
        assert!(
            again.data.is_empty(),
            "[{limit}/{per_conv}] 拿终局水位再问一遍不该再出行, 实得 {} 条",
            again.data.len()
        );
        assert_eq!(
            s2["guard_reset_tables"].as_u64().unwrap(),
            0,
            "[{limit}/{per_conv}] 拿终局水位再问一遍触发了护栏复位 = 下一次真查会重报整段历史"
        );
        let after: HashMap<String, native_query::NewHotMark> =
            serde_json::from_value(s2["next_watermark"].clone()).unwrap();
        let norm = |m: &HashMap<String, native_query::NewHotMark>| {
            let mut v: Vec<_> = m.iter().map(|(k, x)| (k.clone(), format!("{x:?}"))).collect();
            v.sort();
            v
        };
        assert_eq!(
            norm(&after),
            norm(&settled),
            "[{limit}/{per_conv}] 没新消息时水位不该有任何变化(含护栏那几样)"
        );

        // ⚠️ 这儿原先挂着一句"开着保底时第一轮就该有多个会话露面" —— 底下跟的是 println 没有断言,
        // **而且那句话在它自己的矩阵里就不成立**((5,0)、(2,3)、(1,1) 三档第一轮都只有一个会话)。
        // 注释说得比代码强, 正是这一串一直在治的毛病, 删掉(独立复审的 P3)。
        println!("[审计 per-conv 多轮] limit={limit} per_conv={per_conv} → 收敛, 18 条齐");
    }
}

/// **[独立复审写的, 原样收进来]** 同一个会话横跨两个分片 + `--per-conv` 开着, 多轮跑到收敛不许漏/不许重。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_perconv_cross_shard_multi_round() {
    use std::collections::{HashMap, HashSet};
    const A: &str = "aaa_spread@chatroom";
    const Z: &str = "zzz_single@chatroom";
    for (limit, per_conv) in [(3usize, 1usize), (4, 2), (2, 2), (6, 3)] {
        let e = Env::new();
        // ⚠️ **两个分片的行必须分得清**(codex 审 ff12d69 的 P2): 原先两边都写 1..=4, 于是
        // (会话, 时间) 完全重号 —— 结果里"重复报了 0 号分片的行、漏了 1 号分片的行"这种错法,
        // 条数照样对得上, 这条测试照样绿。而它自称守的正是"不漏不重"。
        // 错开行号 → `create_time` 跟着错开 → 12 条各有各的身份, 可以逐条核。
        e.write_shard("message_0.db", &[(A, 4), (Z, 4)]);
        e.write_shard("message_1.db", &[(A, 0)]); // 同一个会话, 另一个分片: 建表不写行
        e.append_rows("message_1.db", A, 5, 8, 0); // 行号错开, 跟 0 号分片区分得开
        let loc = e.data_dir.join(format!("audit_loc_cs_{limit}_{per_conv}.json"));
        let loc_s = loc.to_str().unwrap().to_string();
        let dd = e.data_dir.to_str().unwrap().to_string();
        let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
            rt().block_on(native_query::hot_new(
                &e.wxid,
                Some(dd.as_str()),
                Some(loc_s.as_str()),
                wm,
                limit,
                per_conv,
                None,
            ))
            .expect("hot_new")
        };
        let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
            serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
        };
        let mut wm: Option<HashMap<String, native_query::NewHotMark>> = None;
        // (conv, create_time) 在两个分片里会重号 —— 这里只核总条数 + 不重复报同一 (conv, ct, 轮次内)。
        // 分片维度靠水位表的键区分。
        let mut total = 0usize;
        // 逐条记身份 = (会话, 消息时间)。A 在两个分片各 4 条(行号 1..4 / 5..8)、Z 4 条 → 12 个各不相同。
        let mut ids: HashSet<(String, i64)> = HashSet::new();
        let mut wm_hist: Vec<HashMap<String, native_query::NewHotMark>> = Vec::new();
        let mut seen_rounds: HashSet<String> = HashSet::new();
        for round in 1..=40 {
            let r = run(wm.clone());
            let s = r.meta.summary.as_ref().unwrap();
            assert_eq!(
                s["guard_reset_tables"].as_u64().unwrap(),
                0,
                "[{limit}/{per_conv}] 第{round}轮护栏复位"
            );
            assert_eq!(s["tables_with_lost_rows"].as_u64().unwrap(), 0);
            total += r.data.len();
            for d in &r.data {
                let id = (
                    d["conv_id"].as_str().unwrap_or_default().to_string(),
                    d["create_time"].as_i64().unwrap_or_default(),
                );
                assert!(
                    ids.insert(id.clone()),
                    "[{limit}/{per_conv}] 第{round}轮重复报了 {id:?} (同一条报了两次)"
                );
            }
            let next = wm_of(&r);
            // 水位单调不减
            if let Some(prev) = wm_hist.last() {
                for (k, v) in prev {
                    let now = next.get(k).map_or(-1, |m| m.id);
                    assert!(
                        now >= v.id,
                        "[{limit}/{per_conv}] 第{round}轮水位 {k} 回退了 {} → {now}",
                        v.id
                    );
                }
            }
            wm_hist.push(next.clone());
            seen_rounds.insert(format!("{next:?}"));
            wm = Some(next);
            if r.data.is_empty() {
                break;
            }
        }
        assert_eq!(
            total, 12,
            "[{limit}/{per_conv}] 跨分片收敛后该 12 条一条不少一条不多, 实得 {total}"
        );
        // 光数条数不够(codex 的 P2): 逐条核身份, 12 个一个不少、一个不多。
        let want: HashSet<(String, i64)> = (1..=8)
            .map(|i| (A.to_string(), 1_700_000_000_000i64 + i * 1000))
            .chain((1..=4).map(|i| (Z.to_string(), 1_700_000_000_000i64 + i * 1000)))
            .collect();
        assert_eq!(ids, want, "[{limit}/{per_conv}] 报出来的 12 条身份对不上");
        // 每张表的水位必须落到它自己的最后一行(0 号分片 A/Z 是 4, 1 号分片 A 错开到 8)。
        for (k, m) in wm_hist.last().unwrap() {
            let want = if k.starts_with("message_1.db") { 8 } else { 4 };
            assert_eq!(m.id, want, "[{limit}/{per_conv}] 表 {k} 水位停在 {}, 该是 {want}", m.id);
        }
        // ⚠️ **拿终局水位再问一遍**(codex 审 ff12d69 的 P2): 上面的循环一见空结果就退出,
        // 从没用过那一次返回的水位。要是"没新消息"那一支把护栏那几样(已读段行数 / 游标那行的时间 /
        // 锚点)写坏了, 上面每条断言照样过 —— 而下一次真查就会判成"这张表被换过"→ 复位 → 重报整段历史。
        //
        // ⚠️ **这条咬得住"漂", 咬不住"稳定地写错"**(我埋反例量过, 如实记):
        // 把"没新消息"那一支的行数改成每问一次加一 → 红; 改成恒定地多加一 → **不红**
        // (两次问出来一样, 比不出差别; 而且那样只会让护栏变瞎, 不会触发复位)。
        // 要咬后一种得断言实际数值, 那就得把护栏的内部口径抄进测试, 一抄就会漂 —— 不划算。
        let settled = wm_hist.last().unwrap().clone();
        let again = run(Some(settled.clone()));
        let s2 = again.meta.summary.as_ref().unwrap();
        assert!(
            again.data.is_empty(),
            "[{limit}/{per_conv}] 拿终局水位再问一遍不该再出行, 实得 {} 条",
            again.data.len()
        );
        assert_eq!(
            s2["guard_reset_tables"].as_u64().unwrap(),
            0,
            "[{limit}/{per_conv}] 拿终局水位再问一遍触发了护栏复位 = 下一次真查会重报整段历史"
        );
        let after: std::collections::HashMap<String, native_query::NewHotMark> =
            serde_json::from_value(s2["next_watermark"].clone()).unwrap();
        assert_eq!(
            format!("{:?}", {
                let mut v: Vec<_> = after.iter().collect();
                v.sort_by_key(|(k, _)| (*k).clone());
                v
            }),
            format!("{:?}", {
                let mut v: Vec<_> = settled.iter().collect();
                v.sort_by_key(|(k, _)| (*k).clone());
                v
            }),
            "[{limit}/{per_conv}] 没新消息时水位不该有任何变化(含护栏那几样)"
        );
        println!("[审计 per-conv 跨分片] limit={limit} per_conv={per_conv} → 12 条齐");
    }
}

/// **保底名额按逻辑会话记, 不是按 (分片, 会话表) 记**(codex 审 80b3e74 的 P2)。
///
/// 同一个会话可以同时存在于多个分片 —— 真库实测 700 张同名 `Msg_` 表同时在 `message_0.db`
/// 和 `message_5.db`。按表记名额的话, 一个横跨两个分片的会话会拿到**两份**保底, 把别的会话挤出去,
/// 正是这个功能要治的毛病。
///
/// 夹具: 会话 A 在两个分片里各有新消息, 会话 Z 只在一个分片。名额 2 条、保底 1 条。
/// - 按会话记(对): A 占 1 个, Z 占 1 个 → 两个会话都露面。
/// - 按表记(错): A 的两张表各占 1 个 → Z 一条都没有。
///
/// 这条盖的是**调用点传哪个键**那一行 —— `offer_floor` 本身的单测传的就是 conv_id, 咬不到它。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_per_conv_quota_counts_the_conversation_not_the_shard_table() {
    use std::collections::HashMap;
    const A: &str = "aaa_spread@chatroom";
    const Z: &str = "zzz_single@chatroom";
    let e = Env::new();
    // ⚠️ **Z 必须排在更靠后的分片**: 按表记名额的错误实现里, 名额得先被 A 的两张表填满,
    // Z 才轮到 —— 这时它已经进不来了。要是 Z 跟 A 同在头一个分片, 错误实现也能让两个都露面
    // (我头一版夹具就是那样, 埋了反例零条红)。
    e.write_shard("message_0.db", &[(A, 2)]);
    e.write_shard("message_1.db", &[(A, 2)]); // 同一个会话, 另一个分片
    e.write_shard("message_2.db", &[(Z, 2)]);
    let loc = e.data_dir.join("audit_locator_perconv_shards.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();

    let r = rt()
        .block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            None::<HashMap<String, native_query::NewHotMark>>,
            2,
            1,
            None,
        ))
        .expect("hot_new");
    let convs: Vec<&str> = r.data.iter().filter_map(|d| d["conv_id"].as_str()).collect();
    println!("[per-conv 跨分片] → {convs:?}");
    assert!(
        convs.contains(&Z),
        "横跨两个分片的会话只该占一份保底名额 —— Z 被挤掉说明名额是按 (分片, 会话表) 记的: {convs:?}"
    );
}

/// **`--per-conv` 真的接到查询内核了** —— 用可控夹具做 A/B, 两边只差这一个参数。
///
/// 为什么非要夹具: 活的微信库上做不出来。我拿真账号跑过两次 A/B, 两次都不成立 ——
/// 一次是 `--reset` 第二遍没生效(两边看的不是同一批数据), 一次是两次跑隔了十几分钟、
/// 中间真有新消息进来。源是活的, 控制不住"有几个会话有新消息"这个前提。
///
/// 夹具里两张会话表各 3 条新的, 名额只给 2 条:
/// - 关(0): 2 条全来自排在前面那张表 —— 这就是被报的那个症状。
/// - 开(1): 每张表各 1 条。
///
/// 这条盖住的正是 `hot_new` 里那行"把 per_conv 传给分配函数" —— 纯函数那头有单测,
/// 而这根线只有这条能咬(把参数换成 0, 这条立刻红)。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_per_conv_floor_is_wired_into_hot_new() {
    use std::collections::HashMap;
    const A: &str = "aaa_busy@chatroom";
    const B: &str = "zzz_quiet@chatroom";
    let e = Env::new();
    e.write_shard("message_0.db", &[(A, 3), (B, 3)]);
    let loc = e.data_dir.join("audit_locator_perconv.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |per_conv: usize| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            None::<HashMap<String, native_query::NewHotMark>>, // 每次都从头看, 两边输入一模一样
            2,
            per_conv,
            None,
        ))
        .expect("hot_new")
    };
    let convs_of = |r: &native_query::QueryResult| -> Vec<String> {
        r.data
            .iter()
            .filter_map(|d| d["conv_id"].as_str())
            .map(str::to_string)
            .collect()
    };

    let off = convs_of(&run(0));
    println!("[per-conv] 关 → {off:?}");
    assert_eq!(off.len(), 2, "名额就 2 条");
    assert!(
        off.iter().all(|c| c == A),
        "不开的时候 2 条该全来自排在前面那张表(这正是被报的症状): {off:?}"
    );

    let on = convs_of(&run(1));
    println!("[per-conv] 开 → {on:?}");
    assert_eq!(on.len(), 2, "名额还是 2 条");
    assert!(
        on.iter().any(|c| c == A) && on.iter().any(|c| c == B),
        "开了之后两张表各该露一条 —— 只有一张说明 per_conv 没传到内核: {on:?}"
    );
}

/// BottomN 按 `(src, conv_id, local_id)` 取全局最小的 `limit` 条。卡住的那张表每轮都把同样一批
/// "新"行重新塞进来, 排在前面就把名额占满 —— 排在它后面的会话表**永远轮不到**。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_frozen_table_starves_the_others() {
    use std::collections::HashMap;
    // BottomN 按 (src, conv_id, local_id) 取全局最小 limit 条 —— 让**卡住的那张**排在前面。
    const FROZEN: &str = "aaa_frozen@chatroom";
    const CLEAN: &str = "zzz_clean@chatroom";
    let e = Env::new();
    e.write_shard("message_0.db", &[(FROZEN, 3), (CLEAN, 3)]);
    let loc = e.data_dir.join("audit_locator_o.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            3,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };

    let mut wm: Option<HashMap<String, native_query::NewHotMark>> = None;
    for round in 1..=2 {
        let r = run(wm.clone());
        wm = Some(wm_of(&r));
        println!("[审计O] 预热第{round}轮 → {} 条", r.data.len());
    }
    // CONV 收到 3 条新的, 其中一行读不出来 → CONV 永远进不了 complete_tables;
    // CONV2 也收到 3 条新的, 它自己是干净的。
    e.append_rows("message_0.db", FROZEN, 5, 7, 0);
    e.add_bad_typed_row("message_0.db", FROZEN, 4);
    e.append_rows("message_0.db", CLEAN, 4, 6, 0);

    let mut seen_conv2 = 0;
    for round in 3..=6 {
        let r = run(wm.clone());
        wm = Some(wm_of(&r));
        let convs: Vec<&str> = r.data.iter().filter_map(|d| d["conv_id"].as_str()).collect();
        let texts: Vec<&str> = r.data.iter().filter_map(|d| d["text_content"].as_str()).collect();
        seen_conv2 += convs.iter().filter(|c| **c == CLEAN).count();
        println!("[审计O] 第{round}轮 → {texts:?} (来自 {convs:?})");
    }
    assert!(
        seen_conv2 > 0,
        "干净的那张表的新消息一条都没露出来 —— 被卡住的表把 limit 名额占死了"
    );
}

/// 之后"游标底下多出一条没报过的消息"要多出**两条**才响 —— 删得越多, 护栏越瞎。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_n_never_ratchets_down_after_a_delete() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_p.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    let r1 = run(None);
    let mut wm = wm_of(&r1);
    println!("[审计P] ①首轮 → {} 条; 水位 {wm:?}", r1.data.len());

    // ② 用户删掉一条老消息(第 3 行)。已读段从 5 行变 4 行 —— 方向是"变少", 不该复位(对)。
    e.punch_hole("message_0.db", CONV, 3);
    let r2 = run(Some(wm.clone()));
    wm = wm_of(&r2);
    println!("[审计P] ②删一条老消息 → guard={}; 水位 {wm:?}", guard_of(&r2));
    assert_eq!(guard_of(&r2), 0, "变少不该复位");

    // ③ 第 3 号位置**换上另一条消息**(第 1 代)。它 <= 水位, 永远不会被当"新"——
    //    除非护栏认出"已读段多出了行"。已读段又回到 5 行。
    e.refill_hole("message_0.db", CONV, 3, 1);
    let r3 = run(Some(wm.clone()));
    wm = wm_of(&r3);
    println!("[审计P] ③补回一条别的消息 → guard={}; 水位 {wm:?}", guard_of(&r3));

    let r4 = run(Some(wm.clone()));
    let texts: Vec<&str> = r4.data.iter().filter_map(|d| d["text_content"].as_str()).collect();
    println!("[审计P] ④下一轮 → {} 条 {texts:?}", r4.data.len());

    assert_eq!(
        guard_of(&r3),
        1,
        "已读段从 4 行回到 5 行 = 游标底下多出一条没报过的消息, 护栏该响 —— \
         `n` 在第 ② 轮没跟着量到的 4 往下刷, 门槛就永久停在 5, 这一格从此瞎"
    );
    assert!(texts.contains(&"g1m3"), "补回来的那条必须补报");
}

/// **老水位没有护栏锚点 + 那一轮没扫全却推进了位置**(codex round-16 P1)。
///
/// 升级前的水位是 `{id, n, ct}`, 没有 `gid` —— 读的时候当作等于 `id`。
/// 要是**升级后第一轮**正好这张表没扫全(有一行永远读不出来)却又有新消息:
/// `id` 推进了, 而 `n`/`ct` 描述的还是**旧**那一格, `gid` 仍然缺席
/// → 下一轮 `unwrap_or(id)` 拿到的是**推进后**的 id
/// → 拿"≤ 新 id 的行数"去比"≤ 旧 id 的行数" → **假复位 → 整段历史重报**。
///
/// 修法: 没扫全却推进位置时, 把**推进前**那一格显式钉进 `gid`, 让它跟 `n`/`ct` 对齐。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_legacy_mark_without_gid_survives_a_partial_advance() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_q.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    let r1 = run(None);
    let mut wm = wm_of(&r1);
    // 把水位**降级成升级前的样子**: 去掉 `gid`。
    for m in wm.values_mut() {
        m.gid = None;
    }
    println!("[审计Q] ①降级成老水位 {wm:?}");

    // ② 来了新消息, 同时有一行**一时**读不出来 → 这一轮没扫全, 但位置要推进。
    //    ⚠️ 坏行必须是**一时的**: 它要是一直坏, 后面每轮都"没扫全"、比较根本不会发生,
    //    这条用例就打不到要验的那条路(第一版就是这么写的, 变体不红才发现)。
    e.append_rows("message_0.db", CONV, 6, 8, 0);
    e.add_bad_typed_row("message_0.db", CONV, 9);
    let r2 = run(Some(wm.clone()));
    wm = wm_of(&r2);
    println!("[审计Q] ②没扫全却推进 → {} 条; 水位 {wm:?}", r2.data.len());

    // ③ 坏行修好 → 这一轮**扫全了**, 比较真的会发生。
    //    锚点要是没钉住, 这里就拿"≤ 新 id 的行数"去比老的 n → 假复位 → 重报全部历史。
    e.flip_row_readable("message_0.db", CONV, 9, true);
    let r3 = run(Some(wm.clone()));
    println!("[审计Q] ③下一轮 → guard={}; {} 条", guard_of(&r3), r3.data.len());
    assert_eq!(
        guard_of(&r3),
        0,
        "源库一行没换, 只是升级后第一轮没扫全 —— 不该假复位。         复位了就是把这张表的整段历史当新消息重报一遍"
    );
}

/// "没扫全 + 有新行", 每轮都看一眼 `gid`。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_legacy_gid_pinned_once_not_creeping() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_r.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let guard_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_reset_tables"].as_u64().unwrap()
    };

    let r1 = run(None);
    let mut wm = wm_of(&r1);
    // 降级成"升级前的水位": 没有 gid。
    let k = format!("message_0.db\u{1f}{CONV}");
    let m0 = wm[&k].clone();
    wm.insert(
        k.clone(),
        native_query::NewHotMark {
            lost: false,
            lost_ids: vec![],
            id: m0.id,
            gid: None,
            n: m0.n,
            ct: m0.ct,
        },
    );
    println!("[审计R] 降级成无 gid 的老水位 = {:?}", wm[&k]);

    // 造一行**永久**读不出来的(第 9 行), 让之后每一轮都"没扫全"。
    e.append_rows("message_0.db", CONV, 6, 8, 0);
    e.add_bad_typed_row("message_0.db", CONV, 9);
    for (round, (from, to)) in [(10, 12), (13, 15), (16, 18)].into_iter().enumerate() {
        if round > 0 {
            e.append_rows("message_0.db", CONV, from, to, 0);
        }
        let r = run(Some(wm.clone()));
        wm = wm_of(&r);
        println!(
            "[审计R] 第{}轮 → {} 条, guard={}; 水位 {:?}",
            round + 2,
            r.data.len(),
            guard_of(&r),
            wm[&k]
        );
        assert_eq!(guard_of(&r), 0, "第{}轮不该复位", round + 2);
        assert_eq!(wm[&k].gid, Some(5), "锚点必须一次钉死在推进前那一格(5), 不许往后爬");
    }
}

/// **锚点追得上来**(codex round-17 P3 的正面): 一次**一时**的"没扫全 + 位置照推"之后,
/// 等这张表恢复正常, 护栏锚点要能追到汇报位置, 把 `(gid, id]` 那一段收进覆盖面。
///
/// 不追的话 `gid < id` 会**永久粘住** —— 一个"恒 0 才正常"的信号变成永久非 0,
/// 下次真出事就没人看了。参见 [`audit_legacy_gid_pinned_once_not_creeping`]:
/// 那条管的是**坏行还在**时不许往后爬, 这条管的是**坏行没了**之后必须追上来。
///
/// ⚠️ 追的时候用的是**专门量的"≤ 汇报位置的行数"**, 不能拿"这张表一共吐了几行"顶:
/// 展示名额会淘汰行, "这一轮没展示"不等于"没有更靠后的行"。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_lagging_guard_catches_up_after_recovery() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_s.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lag_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["guard_lagging_tables"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    let r1 = run(None);
    let mut wm = wm_of(&r1);
    assert_eq!(lag_of(&r1), 0, "干净首轮不该有落后");

    // ② 来了新消息, 同时有一行**一时**读不出来 → 没扫全但位置照推 → 锚点落后。
    e.append_rows("message_0.db", CONV, 6, 8, 0);
    e.add_bad_typed_row("message_0.db", CONV, 9);
    let r2 = run(Some(wm.clone()));
    wm = wm_of(&r2);
    println!("[审计S] ②没扫全却推进 → 落后={}; 水位 {:?}", lag_of(&r2), wm[&k]);
    assert_eq!(lag_of(&r2), 1, "这时该报落后");
    assert!(wm[&k].gid.is_some_and(|g| g < wm[&k].id), "锚点该落在汇报位置之前");

    // ③ 坏行**没了**(比如那条消息被撤回删掉了) → 这一轮扫全了, 而且没有比汇报位置更靠后的行。
    // ⚠️ 这里不能用"把坏行修好": 修好等于**多一行新的**, 走的是正常推进那条路,
    //    追赶那段代码压根不执行 —— 第一版夹具就是这么写的, 反例埋下去照样绿。
    e.punch_hole("message_0.db", CONV, 9);
    let r3 = run(Some(wm.clone()));
    let wm3 = wm_of(&r3);
    println!("[审计S] ③恢复后 → 落后={}; 水位 {:?}", lag_of(&r3), wm3[&k]);
    assert_eq!(
        lag_of(&r3),
        0,
        "表恢复正常了, 锚点必须追到汇报位置 —— 不追就永久粘着非 0, 这个信号从此没人看"
    );
    assert_eq!(wm3[&k].gid, Some(wm3[&k].id), "锚点该跟汇报位置对齐");

    // ④ 再跑一轮, 什么都没变 → 必须**风平浪静**。
    // ⚠️ 这一轮是第十八轮 codex 审出来的: 追赶时锚点搬了、时间戳却还是**旧锚点**那一格的,
    //    两者不一致 ⟹ 下一轮护栏必然误判成"这张表被换过" ⟹ 复位 ⟹ 整段历史重报一遍。
    //    只跑到 ③ 看不见 —— 测试少跑一轮, 这条 P1 就漏过去了。
    let r4 = run(Some(wm3.clone()));
    let wm4 = wm_of(&r4);
    let reset4 = r4.meta.summary.as_ref().unwrap()["guard_reset_tables"]
        .as_u64()
        .unwrap();
    println!(
        "[审计S] ④静置一轮 → 复位={reset4}, 报了 {} 条; 水位 {:?}",
        r4.data.len(),
        wm4[&k]
    );
    assert_eq!(
        reset4, 0,
        "锚点搬了就得把时间戳一起搬 —— 不然下一轮自己把自己判成'表被换过'"
    );
    assert!(r4.data.is_empty(), "什么都没变, 不该凭空重报");
    assert_eq!(wm4[&k].id, wm3[&k].id, "位置不该倒退");
}

/// **"压根没护栏"也算落后**(codex round-17 P2 的正面): 老水位没带基准行数, 又赶上这一轮没扫全 ——
/// 基准建不起来, 这张表这一轮**一点护栏都没有**。这种最该被看见的情况, 恰恰不满足"锚点落在位置之前",
/// 所以那个信号必须**两半都在**: 锚点落后 **或** 压根没基准。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_lagging_counts_tables_with_no_guard_at_all() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_t.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");
    // 老水位: 只有位置, 没有基准行数、没有锚点。
    let mut wm: HashMap<String, native_query::NewHotMark> = HashMap::new();
    wm.insert(
        k.clone(),
        native_query::NewHotMark {
            lost: false,
            lost_ids: vec![],
            id: 5,
            gid: None,
            n: None,
            ct: None,
        },
    );

    // 让这一轮**没扫全** → 基准建不起来 → 这张表全程裸奔。
    // ⚠️ 坏行必须在**水位下面**: 放上面的话位置会照推、锚点跟着落后, 第一半就兜住了,
    //    这条测的就不是"没基准"那一半了 —— 第一版夹具正是这么写的, 反例埋下去照样绿。
    e.flip_row_readable("message_0.db", CONV, 3, false);
    let r = rt()
        .block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            Some(wm),
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new");
    let sum = r.meta.summary.as_ref().unwrap();
    let out: HashMap<String, native_query::NewHotMark> = serde_json::from_value(sum["next_watermark"].clone()).unwrap();
    println!(
        "[审计T] 裸奔轮 → 落后={}; 水位 {:?}",
        sum["guard_lagging_tables"], out[&k]
    );
    assert!(out[&k].n.is_none(), "夹具得真的建不起基准, 否则这条测的不是它想测的");
    assert_eq!(
        sum["guard_lagging_tables"].as_u64().unwrap(),
        1,
        "压根没基准的表最该被看见 —— 它不满足'锚点落在位置之前', 只靠那一半会把它漏掉"
    );
}

/// **汇报位置那一行被删掉了, 锚点照样追得上来**(独立复审第十八轮 P2, 真跑复现过的死锁)。
///
/// 上一版要求"汇报位置那一行的行数和时间戳两样都拿到才敢搬"。那一行**被删掉**时(撤回/清理)
/// 时间戳就取不到 → 永不追赶 → 对**不会再来新消息的会话**(群解散、单向好友)这个告警**永远灭不掉**。
///
/// 改成锚到"**≤ 汇报位置的最后一行**": 那是一行真实存在的行, 行号/行数/时间三样永远配得齐,
/// 而它上面那一段本来就没有行, 护栏一点没少盖。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_catchup_works_when_the_cursor_row_itself_was_deleted() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_u.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let sum_u64 =
        |r: &native_query::QueryResult, k: &str| -> u64 { r.meta.summary.as_ref().unwrap()[k].as_u64().unwrap() };
    let k = format!("message_0.db\u{1f}{CONV}");

    let mut wm = wm_of(&run(None));
    // ② 有新消息 + 一行读不出来 → 没扫全却推进 → 锚点落后。
    e.append_rows("message_0.db", CONV, 6, 8, 0);
    e.add_bad_typed_row("message_0.db", CONV, 9);
    let r2 = run(Some(wm.clone()));
    wm = wm_of(&r2);
    println!(
        "[审计U] ②没扫全却推进 → 落后={}; 水位 {:?}",
        sum_u64(&r2, "guard_lagging_tables"),
        wm[&k]
    );
    assert_eq!(sum_u64(&r2, "guard_lagging_tables"), 1);
    assert_eq!(wm[&k].id, 8, "汇报位置该推到 8");

    // ③ 坏行没了, **而且汇报位置那一行(8号)自己也被删了** —— 这一轮扫全了。
    e.punch_hole("message_0.db", CONV, 9);
    e.punch_hole("message_0.db", CONV, 8);
    let r3 = run(Some(wm.clone()));
    let wm3 = wm_of(&r3);
    println!(
        "[审计U] ③8号也删了 → 落后={}; 水位 {:?}",
        sum_u64(&r3, "guard_lagging_tables"),
        wm3[&k]
    );
    assert_eq!(
        sum_u64(&r3, "guard_lagging_tables"),
        0,
        "扫全了就该核得了 —— 锚点得能搬到还在的那一行(7号), 不能因为 8 号没了就永远卡着"
    );
    assert_eq!(
        wm3[&k].gid,
        Some(7),
        "锚点该落在'≤ 汇报位置的最后一行'(7号), 而不是已经不存在的 8 号"
    );

    // ④ 静置一轮: 锚点/行数/时间三样必须配得齐, 不然又会自己判自己"表被换过"。
    let r4 = run(Some(wm3.clone()));
    println!(
        "[审计U] ④静置 → 复位={}, 报了 {} 条",
        sum_u64(&r4, "guard_reset_tables"),
        r4.data.len()
    );
    assert_eq!(sum_u64(&r4, "guard_reset_tables"), 0, "三样得配得齐");
    assert!(r4.data.is_empty(), "什么都没变, 不该凭空重报");
}

/// **真丢了一条消息的表, 得一直看得见**(独立复审第十八轮 P1-②, 用户 2026-07-30 拍板"乙+")。
///
/// 一行读不出来被跳过、而同表更靠后的行进了本批 ⟹ 汇报位置越过了它 ⟹ 它此后恒 `<= 位置`,
/// 哪怕后来又读得出来也永远不算新。**那条消息永久看不见了。**
///
/// 丢是有意的取舍(停在坏行那儿不动的话, 永久坏行会把整张表卡死、还占满名额饿死别的会话),
/// 但**静默不行** —— 独立复审真跑抓到的就是: 那一行重新读得出来的那一轮(= 这条消息变成
/// 永久报不出来的那一刻), 护栏覆盖的告警恰好被"锚点追赶"清成 0, 一点痕迹都不剩。
///
/// 所以另立一个**永不自动清除**的标记。这条守卫钉三件事: 立得起来 / 灭不掉 / 没丢的表不许乱立。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_a_table_that_really_lost_a_message_stays_visible() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_v.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");
    // 按**正文**记(行里没有 local_id 这一列), 夹具每行正文里带着自己的行号。
    let mut seen: Vec<String> = vec![];
    let mut note = |r: &native_query::QueryResult| {
        for row in &r.data {
            seen.push(row["text_content"].as_str().unwrap_or("?").to_string());
        }
    };

    let r1 = run(None);
    note(&r1);
    let mut wm = wm_of(&r1);
    assert_eq!(lost_of(&r1), 0, "干净首轮不该有丢");

    // ② 6/7/8 三条新消息, 其中 **7 号读不出来**; 8 号照报 ⟹ 位置越过 7 号。
    e.append_rows("message_0.db", CONV, 6, 6, 0);
    e.add_bad_typed_row("message_0.db", CONV, 7);
    e.append_rows("message_0.db", CONV, 8, 8, 0);
    let r2 = run(Some(wm.clone()));
    note(&r2);
    wm = wm_of(&r2);
    println!("[审计V] ②越过7号 → 丢={}; 水位 {:?}", lost_of(&r2), wm[&k]);
    assert!(wm[&k].id >= 7, "位置得真的越过 7 号, 否则这条测的不是它想测的");
    assert_eq!(lost_of(&r2), 1, "越过去了就得立起来");
    assert!(wm[&k].lost, "标记该落在水位里");

    // ③ 7 号重新读得出来 —— **这正是那条消息变成永久报不出来的那一刻**, 标记绝不能跟着灭。
    e.flip_row_readable("message_0.db", CONV, 7, true);
    for round in 3..=5 {
        let r = run(Some(wm.clone()));
        note(&r);
        wm = wm_of(&r);
        println!("[审计V] 第{round}轮 → 报了 {} 条, 丢={}", r.data.len(), lost_of(&r));
        assert_eq!(lost_of(&r), 1, "第{round}轮: 丢的那条没回来, 提示就不许灭");
    }

    seen.sort();
    println!("[审计V] 五轮一共报出来过: {seen:?}");
    let has = |n: i64| seen.iter().any(|t| t.contains(&format!("{n}")));
    assert!(has(8), "8 号得报过, 否则位置压根没越过 7 号");
    assert!(!has(7), "7 号确实一次都没报出来过 —— 夹具得真的丢了它");
}

/// 反面: 跳过的行在**汇报位置上面**时不许立标记 —— 那一行下一轮还会重新读, 没丢。
/// 乱立就是狼来了, 而狼来了报久了, 真丢那一次也没人看。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_skipped_row_above_the_cursor_is_not_a_loss() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_w.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 5);
    // 6 号读不出来, **它上面什么都没有** ⟹ 位置停在 5, 没越过去 ⟹ 不算丢。
    e.add_bad_typed_row("message_0.db", CONV, 6);
    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    println!("[审计W] 坏行在位置上面 → 丢={}; 水位 {:?}", lost_of(&r2), wm2[&k]);
    assert_eq!(wm2[&k].id, 5, "位置不该动");
    assert_eq!(lost_of(&r2), 0, "没越过去就不算丢 —— 乱报就是狼来了");
    assert!(!wm2[&k].lost);

    // 6 号恢复 → 照常报出来, 全程没丢。
    e.flip_row_readable("message_0.db", CONV, 6, true);
    let r3 = run(Some(wm2.clone()));
    println!("[审计W] 恢复后 → 报了 {} 条, 丢={}", r3.data.len(), lost_of(&r3));
    assert_eq!(r3.data.len(), 1, "6 号该在恢复后照常报出来");
    assert_eq!(lost_of(&r3), 0);
}

/// **第二条丢行的路也得算丢**(codex 第十九轮 P1)。
///
/// 头一版只认扫描器报的"整行读不出来"。可 `hot_new` 自己还会丢一类行: **行读得出来、但正文解不开**
/// (截断的 zstd)。后果一模一样 —— 这一行被丢掉、同表更靠后的行照报, 位置就越过了它;
/// 正文哪天补全了它也已经不算新, 永久看不见。**又是"修了被点名的、旁边同结构的没修"。**
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_content_decode_drop_counts_as_a_loss_too() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_x.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 5);
    // 6 号正文解不开(类型全对, 扫描器读得出来), 7 号正常 ⟹ 位置越过 6 号。
    e.add_bad_content_row("message_0.db", CONV, 6);
    e.append_rows("message_0.db", CONV, 7, 7, 0);
    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    let texts: Vec<&str> = r2
        .data
        .iter()
        .map(|x| x["text_content"].as_str().unwrap_or("?"))
        .collect();
    println!(
        "[审计X] 越过解不开的6号 → 报了 {texts:?}, 丢={}; 水位 {:?}",
        lost_of(&r2),
        wm2[&k]
    );
    assert_eq!(wm2[&k].id, 7, "位置得越过 6 号, 否则这条测的不是它想测的");
    assert!(!texts.iter().any(|t| t.contains("m6")), "6 号确实没报出来");
    assert_eq!(
        lost_of(&r2),
        1,
        "正文解不开被丢掉、位置又越过去了 —— 这跟'整行读不出来'是同一种丢"
    );
    assert!(wm2[&k].lost);
}

/// **早就报过的行后来坏掉了, 不算丢**(codex 第十九轮 P2)。
///
/// 判据头一版写的是"位置底下有读不出来的行"。可第 1..5 行早报给用户了, 后来第 2 行被就地改写
/// 弄坏了 —— 位置纹丝不动, 那条消息**用户早看到了**。按旧判据 `2 <= 5` 照样立标记 ⟹ 永久假告警,
/// 而这个标记是**永不自动清除**的, 立错了就一辈子挂着。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_already_delivered_row_going_bad_is_not_a_loss() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_y.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    // ① 1..5 全报给用户了。
    let r1 = run(None);
    let wm = wm_of(&r1);
    assert_eq!(r1.data.len(), 5, "五条都该报出来");
    assert_eq!(wm[&k].id, 5);

    // ② 第 2 行后来坏了(就地改写/损坏)。位置纹丝不动 —— 那条消息用户早看到了, 没丢。
    e.flip_row_readable("message_0.db", CONV, 2, false);
    for round in 2..=4 {
        let r = run(Some(wm.clone()));
        let w = wm_of(&r);
        println!("[审计Y] 第{round}轮 → 丢={}; 水位 {:?}", lost_of(&r), w[&k]);
        assert_eq!(w[&k].id, 5, "位置不该动");
        assert_eq!(
            lost_of(&r),
            0,
            "第{round}轮: 那条消息早报给用户了 —— 立标记就是永久假告警, 而这个标记清不掉"
        );
        assert!(!w[&k].lost);
    }
}

/// **坏行多到超过上限时, 降级方向必须是"更保守"**(第二十一轮自查, 角度: 上限与哨兵的算术)。
///
/// 这条钉的是: 坏行多到把上限撑爆时, **不能从"报"翻回"不报"**。
/// 具体造法: 让**前 64 个**坏行落在旧位置底下, 而**第 65 个**坏行才是这一轮真被越过去的。
///
/// ⚠️ 第二十三轮重构之后, 这条测的东西变了(测试本身一个字没改, 但它现在守的是别的机制):
/// 底下那 64 个**压根不会被记下来**(记录点就按旧位置过滤了), 所以第 65 个稳稳落在名额里 ——
/// 从"靠溢出区间兜住"变成"根本不需要兜"。反例(去掉记录点的下限过滤)当场打红, 说明它没空转。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_more_bad_rows_than_the_cap_still_reports_the_loss() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 70, 0);
    let loc = e.data_dir.join("audit_locator_z.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            200,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    // ① 70 行全报给用户 → 位置 70。
    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 70, "七十行都该报出来");
    assert!(!wm[&k].lost);

    // ② 前 64 行(早报过的)统统坏掉 —— 它们**不算丢**, 但会把上限撑爆。
    for i in 1..=64 {
        e.flip_row_readable("message_0.db", CONV, i, false);
    }
    // ③ 再来两条新消息, 其中 71 号坏、72 号好 ⟹ 位置从 70 推到 72, **越过了 71 号**。
    e.add_bad_typed_row("message_0.db", CONV, 71);
    e.append_rows("message_0.db", CONV, 72, 72, 0);

    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    println!(
        "[审计Z] 64 个老坏行撑爆上限 + 71 号真丢 → 丢={}; 水位 {:?}",
        lost_of(&r2),
        wm2[&k]
    );
    assert_eq!(wm2[&k].id, 72, "位置得越过 71 号, 否则这条测的不是它想测的");
    assert_eq!(
        lost_of(&r2),
        1,
        "底下那 64 个按下限过滤掉了, 71 号该稳稳落在名额里 —— 撑爆上限不能让真丢翻回不报"
    );
    assert!(wm2[&k].lost);
}

/// **坏行多到撑爆上限, 但它们全在位置底下 → 一条都没丢, 不许报**
/// (独立复审第二十一轮 P2, 它真跑出来的 A/B: 64 个坏行报 0 对, 65 个报 1 错)。
///
/// 跟 [`audit_more_bad_rows_than_the_cap_still_reports_the_loss`] 是**同一个上限的两个方向**:
/// 那条管"撑爆了也不许漏报", 这条管"撑爆了也不许假报"。两个方向都得对 ——
/// 而这个标记不会因为那行恢复正常就自己灭, 假报一次就一直挂着, 比不报还糟。
///
/// ⚠️ 第二十三轮重构之后它守的是**记录点的下限过滤**(这些行全在旧位置底下, 压根记不进来),
/// 不再是"溢出区间的上界"。反例(去掉下限过滤)当场打红。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_cap_overflow_below_the_cursor_is_not_a_loss() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 70, 0);
    let loc = e.data_dir.join("audit_locator_aa.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            200,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    // ① 70 行全报给用户 → 位置 70。
    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 70);

    // ② 其中 65 行**事后**坏掉(就地改写/损坏) —— 全在位置底下, 用户一条都没少看。
    //    65 > 上限 64, 会撑爆。
    for i in 1..=65 {
        e.flip_row_readable("message_0.db", CONV, i, false);
    }
    // ③ 来一条新消息, 位置动一格 —— 哨兵那一版就是在这儿把假告警立起来的。
    e.append_rows("message_0.db", CONV, 71, 71, 0);

    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    println!(
        "[审计AB] 65 个老坏行撑爆上限 + 位置动一格 → 丢={}; 水位 {:?}",
        lost_of(&r2),
        wm2[&k]
    );
    assert_eq!(wm2[&k].id, 71, "位置该动一格, 否则这条测的不是它想测的");
    assert_eq!(
        lost_of(&r2),
        0,
        "那 65 行用户早都看过了, 一条没丢 —— 撑爆上限不能把'没丢'翻成永久假告警"
    );
    assert!(!wm2[&k].lost);
}

/// **老坏行和新坏行混在一起**(codex 第二十轮 P1 的回归守卫)。
///
/// 独立复审第二十一轮点出: 这条 P1 修完**一条测试都没守着** —— 把判据退回"取最小"那一版,
/// 21 条 `audit_*` 会全绿。这条就是补那一格。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_old_bad_row_must_not_mask_a_new_one() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_ac.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    // ① 1..5 全报出去, 位置 5。
    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 5);
    // ② 第 2 行事后坏掉(早报过, 不算丢) + 第 6 行坏(没报过) + 第 7 行好 ⟹ 位置 5→7 越过 6。
    e.flip_row_readable("message_0.db", CONV, 2, false);
    e.add_bad_typed_row("message_0.db", CONV, 6);
    e.append_rows("message_0.db", CONV, 7, 7, 0);

    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    println!("[审计AC] 老坏行2 + 新坏行6 → 丢={}; 水位 {:?}", lost_of(&r2), wm2[&k]);
    assert_eq!(wm2[&k].id, 7, "位置得越过 6 号");
    assert_eq!(
        lost_of(&r2),
        1,
        "老坏行 2 不能把新丢的 6 号盖住 —— 判据退回'取最小'就会拿 2 去比, 5<2 不成立, 真丢反而不报"
    );
}

/// **坏行撑爆上限、而且全在位置"上面" → 一条都没丢, 不许报**
/// (独立复审第二十二轮 P1, 真跑逮到; 跟上一轮那条是**同一个形状的另一半**)。
///
/// 夹具矩阵里空着的就是这一格 —— 之前四条守卫是这么分布的:
///
/// |            | 坏行在位置**底下** | 坏行在位置**上面** |
/// |------------|--------------------|--------------------|
/// | 没撑爆(≤64) | `audit_already_delivered_row_going_bad_is_not_a_loss` | `audit_skipped_row_above_the_cursor_is_not_a_loss`(1 个坏行) |
/// | 撑爆(≥65)   | `audit_cap_overflow_below_the_cursor_is_not_a_loss`  | **就是这条** |
///
/// 而"上面"这一半**更容易撞上**: 底下那种要求 65 个已经报过的行事后坏掉; 上面这种只要新到的
/// 65 行这一轮读不出来就成立 —— 真库上 message_5.db 就是这样(微信正在写它)。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_cap_overflow_above_the_cursor_is_not_a_loss() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 70, 0);
    let loc = e.data_dir.join("audit_locator_ad.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            200,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let lost_of = |r: &native_query::QueryResult| -> u64 {
        r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
            .as_u64()
            .unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    // ① 70 行全报出去, 位置 70。
    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 70);

    // ② 新到 71..135 共 **65** 行, 这一轮全都读不出来(微信正在写它们) ⟹ 撑爆上限,
    //    而且**全在位置上面** —— 位置压根推不动, 它们下一轮还会重新读, 一条都没丢。
    for i in 71..=135 {
        e.add_bad_typed_row("message_0.db", CONV, i);
    }
    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    println!(
        "[审计AD] 65 个坏行全在位置上面 → 丢={}; 水位 {:?}",
        lost_of(&r2),
        wm2[&k]
    );
    assert_eq!(wm2[&k].id, 70, "位置不该动 —— 上面全是读不出来的行");
    assert_eq!(
        lost_of(&r2),
        0,
        "那 65 行下一轮还会重新读, 一条都没丢 —— 撑爆上限不能因为'有溢出'就报"
    );
    assert!(!wm2[&k].lost);

    // ③ 它们恢复正常 → 照常全报出来, 全程没丢过。
    for i in 71..=135 {
        e.flip_row_readable("message_0.db", CONV, i, true);
    }
    let r3 = run(Some(wm2.clone()));
    println!("[审计AD] 恢复后 → 报了 {} 条, 丢={}", r3.data.len(), lost_of(&r3));
    assert_eq!(r3.data.len(), 65, "65 行该在恢复后照常报出来");
    assert_eq!(lost_of(&r3), 0);
}

/// **高于下限的坏行超过上限时, 最小的那个必须还在**(第二十三轮重构的等价性前提)。
///
/// 重构之后上限只是展示预算, 不再影响结论 —— 靠的是"记下来的是最小的那几个, 所以最小值一定在里头"。
/// 现有守卫压的都是"坏行在下限**底下**"(被过滤掉), 没有一条压过"高于下限的坏行**超过上限**"这一格。
///
/// 钉两件事: ① 照样报得出来; ② 告警里给的行号从**最小**那个起 —— 用户拿它去查才对得上。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_more_bad_rows_above_the_floor_than_the_cap_keeps_the_smallest() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 70, 0);
    let loc = e.data_dir.join("audit_locator_ae.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            200,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    // ① 70 行全报出去, 位置 70(= 下限)。
    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 70);

    // ② 71..90 共 20 行(远超上限 8)全读不出来, 而 91 是好行 ⟹ 位置推到 91, 把那 20 行全越过去了。
    //
    // ⚠️ **两条路各喂一半**(第二十五轮变异全扫点出来的): 头一版这里全用 `add_bad_typed_row`,
    // 也就是只喂扫描器那一路 —— 而那一路本来就升序, 排不排序都一样。于是真正会破坏
    // "留下的是最小的那几个"这条性质的变异(判据里 `truncate` 之前不排序)下, 这条守卫**照绿**,
    // 它并没有在测它自己宣称的东西。奇数走扫描器、偶数走正文, 才逼得出排序那一步。
    for i in 71..=90 {
        if i % 2 == 1 {
            e.add_bad_typed_row("message_0.db", CONV, i);
        } else {
            e.add_bad_content_row("message_0.db", CONV, i);
        }
    }
    e.append_rows("message_0.db", CONV, 91, 91, 0);

    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    let lost = r2.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
        .as_u64()
        .unwrap();
    println!("[审计AE] 高于下限的坏行 20 个(上限 8) → 丢={lost}; 水位 {:?}", wm2[&k]);
    assert_eq!(wm2[&k].id, 91, "位置该越过那 20 行");
    assert_eq!(lost, 1, "超过上限也得报得出来 —— 上限只是展示预算, 不该影响结论");
    assert_eq!(
        wm2[&k].lost_ids.first().copied(),
        Some(71),
        "给用户的行号得从**最小**那个起 —— 等价性证明靠的就是'最小值一定在记录里'"
    );
    assert!(wm2[&k].lost_ids.len() <= native_core::SKIPPED_IDS_CAP, "别超过展示预算");
}

/// **早报过的行、正文后来坏了 —— 不算丢**(独立复审第二十四轮 P1: 守卫矩阵里唯一的空格)。
///
/// 丢行有两条路(扫描器整行读不出来 / 本函数正文解不开), 每条路都要按"高于旧位置"过滤。
/// 而三条盯下限的守卫**全走扫描器那一路**(`add_bad_typed_row` / `flip_row_readable`),
/// 唯一走正文那一路的只测正方向(坏行在位置上面 → 该报)。于是这一格空着:
///
/// |            | 坏行在位置**底下** | 坏行在位置**上面** |
/// |------------|--------------------|--------------------|
/// | 扫描器那路 | ✅ ×3              | ✅                 |
/// | 正文那路   | **就是这条**       | ✅                 |
///
/// 独立复审逐条变异跑出来: 去掉正文那一路的下限过滤, **26 条守卫一条都不红**。
/// 而我的提交正文写着"去掉记录点下限过滤 → 两条红" —— 那句只对扫描器那一路成立。
///
/// 场景不是假想: 微信**就地回写**会把已经报过的行的正文改成一时解不开的
/// (图片视频上传完写 CDN 字段、撤回改写正文), 代码里另一处注释自己写着这事真会发生。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_delivered_row_whose_content_goes_bad_is_not_a_loss() {
    use std::collections::HashMap;
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_af.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let dd = e.data_dir.to_str().unwrap().to_string();
    let run = |wm: Option<HashMap<String, native_query::NewHotMark>>| {
        rt().block_on(native_query::hot_new(
            &e.wxid,
            Some(dd.as_str()),
            Some(loc_s.as_str()),
            wm,
            50,
            0, // per_conv: 默认关 —— 这些测试锁的是原有行为
            None,
        ))
        .expect("hot_new")
    };
    let wm_of = |r: &native_query::QueryResult| -> HashMap<String, native_query::NewHotMark> {
        serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
    };
    let k = format!("message_0.db\u{1f}{CONV}");

    // ① 1..5 全报给用户了。
    let wm = wm_of(&run(None));
    assert_eq!(wm[&k].id, 5);

    // ② 第 2 行的**正文**后来坏了(就地回写) —— 那条消息用户早看过了。同时第 6 行新到。
    e.add_bad_content_row("message_0.db", CONV, 2);
    e.append_rows("message_0.db", CONV, 6, 6, 0);

    let r2 = run(Some(wm.clone()));
    let wm2 = wm_of(&r2);
    let lost = r2.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
        .as_u64()
        .unwrap();
    println!(
        "[审计AF] 早报过的第2行正文坏了 + 第6行新到 → 丢={lost}; 水位 {:?}",
        wm2[&k]
    );
    assert_eq!(wm2[&k].id, 6, "位置该推到 6");
    assert_eq!(
        lost, 0,
        "第 2 行用户早看过了 —— 正文那一路也得按'高于旧位置'过滤, 不然就是第十九轮那条永久假告警原样复发"
    );
    assert!(wm2[&k].lost_ids.is_empty());
}

/// **下限是一次性的: 扫完一轮就得自己关掉**(独立复审第二十四轮 P2)。
///
/// 下限是调用方"我上次读到哪儿"的快照, 只对**这一次**扫描有意义。留在字段里的话,
/// 同一个扫描器被复用着扫第二遍时下限还停在上一轮 ⟹ 早报过的行重新进集合
/// ⟹ 第十九轮那个永久假告警原样复活。
///
/// 今天没人复用(每处都是新建的), 但那是**调用约定**, 没有任何东西守着它; 而瘦库/watch
/// 那条线正朝"保温一个扫描器连着查"的方向走。这条把不变量从约定钉回类型里。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_skip_floors_switch_is_off_after_one_scan() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("audit_locator_ag.json");
    let key = rt().block_on(native_query::cache_key(&e.wxid)).expect("key");
    let mut sq = native_core::SourceQuery::open(e.msg_dir.clone(), key, loc, e.wxid.to_string());
    sq.track_skipped_rows_above(std::collections::HashMap::from([(
        format!("message_0.db\u{1f}{CONV}"),
        3i64,
    )]));
    assert!(sq.is_tracking_skipped_rows(), "刚设完该是开着的");

    sq.scan_all_messages(false, None, |_m, _src, _s| true).expect("扫一遍");

    assert!(
        !sq.is_tracking_skipped_rows(),
        "扫完必须自己关掉 —— 不关的话复用这个扫描器再扫一遍, 下限就停在上一轮的位置, \
         早报过的行会重新进集合, 变成永久假告警"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 变异全扫附加: 存活变异的**后果**探针。不是守卫, 只为坐实"后果是真的 / 是等价变异"。
// 名字一律 probe_ 前缀, 不进 audit_ 过滤器。
// ═══════════════════════════════════════════════════════════════════════════

fn probe_run(
    e: &Env,
    loc_s: &str,
    wm: Option<std::collections::HashMap<String, native_query::NewHotMark>>,
) -> native_query::QueryResult {
    let dd = e.data_dir.to_str().unwrap().to_string();
    rt().block_on(native_query::hot_new(
        &e.wxid,
        Some(dd.as_str()),
        Some(loc_s),
        wm,
        200,
        0, // per_conv: 默认关 —— 这些测试锁的是原有行为
        None,
    ))
    .expect("hot_new")
}

fn probe_wm(r: &native_query::QueryResult) -> std::collections::HashMap<String, native_query::NewHotMark> {
    serde_json::from_value(r.meta.summary.as_ref().unwrap()["next_watermark"].clone()).unwrap()
}

fn probe_lost(r: &native_query::QueryResult) -> u64 {
    r.meta.summary.as_ref().unwrap()["tables_with_lost_rows"]
        .as_u64()
        .unwrap()
}

/// 【探针 P1 / 变异 M07】**游标那一行自己**被就地改写成读不出来(扫描器那一路)。
/// 位置纹丝不动、那条消息用户早看过 ⟹ 一条都没丢, 不许立标记。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_cursor_row_itself_goes_bad_scanner_path() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p1.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let wm = probe_wm(&probe_run(&e, &loc_s, None));
    assert_eq!(wm[&k].id, 5);

    // 游标那一行(第 5 行, 也是最新那条)被就地回写弄坏 —— 真库最常见: 图片/视频上传完写 CDN 字段、撤回改写正文。
    e.flip_row_readable("message_0.db", CONV, 5, false);
    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm2 = probe_wm(&r2);
    println!("[探针P1] 游标行自己坏了 → 丢={}; 水位 {:?}", probe_lost(&r2), wm2[&k]);
    assert_eq!(wm2[&k].id, 5, "位置不该动");
    assert_eq!(
        probe_lost(&r2),
        0,
        "第 5 行早报给用户了 —— 记录点的下限过滤是 `>` 不是 `>=`, 写成 `>=` 就是永久假告警"
    );
    assert!(!wm2[&k].lost);
}

/// 【探针 P2 / 变异 M16】同 P1, 但坏在**正文**(本函数那一路)。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_cursor_row_itself_content_goes_bad() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p2.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let wm = probe_wm(&probe_run(&e, &loc_s, None));
    assert_eq!(wm[&k].id, 5);

    e.add_bad_content_row("message_0.db", CONV, 5); // 就地把游标那一行的正文写成解不开的
    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm2 = probe_wm(&r2);
    println!("[探针P2] 游标行正文坏了 → 丢={}; 水位 {:?}", probe_lost(&r2), wm2[&k]);
    assert_eq!(wm2[&k].id, 5, "位置不该动");
    assert_eq!(
        probe_lost(&r2),
        0,
        "正文那一路的下限过滤也得是 `>` —— `>=` 同样是永久假告警"
    );
    assert!(!wm2[&k].lost);
}

/// 【探针 P3 / 变异 M08】**头一回见到**的会话表, 第一行就读不出来、第二行照报 ⟹ 位置越过它, 永久看不见。
/// 这张表压根不在水位里 ⟹ 下限走缺省。缺省要是不等于 0, 这一类丢就**完全静默**。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_brand_new_table_loses_its_first_row() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p3.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k2 = format!("message_1.db\u{1f}{CONV2}");

    let wm = probe_wm(&probe_run(&e, &loc_s, None)); // 只认识 CONV
    assert!(!wm.contains_key(&k2), "CONV2 这一轮还不存在");

    // 新分片里出现一张新会话表: 1 号读不出来, 2 号好。
    e.write_shard("message_1.db", &[(CONV2, 0)]);
    e.add_bad_typed_row("message_1.db", CONV2, 1);
    e.append_rows("message_1.db", CONV2, 2, 2, 0);

    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm2 = probe_wm(&r2);
    println!(
        "[探针P3] 新表第一行就丢 → 丢={}; 水位 {:?}",
        probe_lost(&r2),
        wm2.get(&k2)
    );
    assert_eq!(wm2[&k2].id, 2, "位置该推到 2 号 —— 否则这条测的不是它想测的");
    assert!(
        wm2[&k2].lost,
        "1 号从此恒 <= 位置, 永久报不出来 —— 没见过的表下限缺省必须是 0, 不然这一类丢全静默"
    );
    assert_eq!(wm2[&k2].lost_ids, vec![1]);
}

/// 【探针 P4 / 变异 M17】同 P3, 但坏在**正文**那一路。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_brand_new_table_first_row_content_bad() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p4.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k2 = format!("message_1.db\u{1f}{CONV2}");

    let wm = probe_wm(&probe_run(&e, &loc_s, None));
    assert!(!wm.contains_key(&k2));

    e.write_shard("message_1.db", &[(CONV2, 0)]);
    e.add_bad_content_row("message_1.db", CONV2, 1);
    e.append_rows("message_1.db", CONV2, 2, 2, 0);

    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm2 = probe_wm(&r2);
    println!(
        "[探针P4] 新表第一行正文坏 → 丢={}; 水位 {:?}",
        probe_lost(&r2),
        wm2.get(&k2)
    );
    assert_eq!(wm2[&k2].id, 2);
    assert!(wm2[&k2].lost, "正文那一路的缺省下限同样必须是 0");
    assert_eq!(wm2[&k2].lost_ids, vec![1]);
}

/// 【探针 P5 / 变异 M22 M23 M27】**同一张表同一轮两条路都丢**。
/// 现有守卫每条只压一条路; 两条同时发生时行号该合起来、按升序给。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_both_loss_paths_in_one_table_same_round() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p5.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let wm = probe_wm(&probe_run(&e, &loc_s, None));
    assert_eq!(wm[&k].id, 5);

    e.add_bad_typed_row("message_0.db", CONV, 6); // 扫描器那一路
    e.add_bad_content_row("message_0.db", CONV, 7); // 本函数那一路
    e.append_rows("message_0.db", CONV, 8, 8, 0);

    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm2 = probe_wm(&r2);
    println!("[探针P5] 两条路同轮 → 丢={}; 水位 {:?}", probe_lost(&r2), wm2[&k]);
    assert_eq!(wm2[&k].id, 8, "位置得越过 6 和 7");
    assert_eq!(probe_lost(&r2), 1);
    assert_eq!(wm2[&k].lost_ids, vec![6, 7], "两条路的行号得合起来、按升序");
}

/// 【探针 P6 / 变异 M37】**跨轮累积**: 先丢 7 号, 后来又丢 12 号 —— 7 号不许被顶掉。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_lost_ids_accumulate_across_rounds() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p6.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let mut wm = probe_wm(&probe_run(&e, &loc_s, None));
    e.add_bad_typed_row("message_0.db", CONV, 6);
    e.append_rows("message_0.db", CONV, 7, 7, 0);
    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    wm = probe_wm(&r2);
    assert_eq!(wm[&k].lost_ids, vec![6], "第一轮丢的是 6 号");

    e.add_bad_typed_row("message_0.db", CONV, 8);
    e.append_rows("message_0.db", CONV, 9, 9, 0);
    let r3 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm3 = probe_wm(&r3);
    println!("[探针P6] 第二轮又丢 8 号 → lost_ids={:?}", wm3[&k].lost_ids);
    assert_eq!(
        wm3[&k].lost_ids,
        vec![6, 8],
        "早先丢的行号不许被这一轮的顶掉 —— 顶掉了告警就只剩最后一次的"
    );
}

/// 【探针 P7 / 变异 M30】**行数一样的另一份副本**必须被护栏认出来(靠游标那一行的 `create_time`)。
/// 审计里所有 `guard_reset_tables` 断言都是 `== 0`(不许假复位), 没有一条压"真换了副本就得复位"。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_same_length_different_copy_is_reset() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p7.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let wm = probe_wm(&probe_run(&e, &loc_s, None));
    assert_eq!(wm[&k].id, 5);
    assert!(wm[&k].ct.is_some(), "首轮该把游标那一行的时间记下来");

    // 换成**另一代**同样 5 行(行数一模一样, 内容/时间全不同) —— 光比行数认不出来。
    e.reset_shard_gen("message_0.db", CONV, 5, 1);
    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    let reset = r2.meta.summary.as_ref().unwrap()["guard_reset_tables"]
        .as_u64()
        .unwrap();
    println!("[探针P7] 换了行数一样的另一份副本 → 复位={reset}");
    assert_eq!(
        reset, 1,
        "行数一样的副本只有 `ct` 认得出来 —— 认不出就是这一串最早那个洞: 那 5 条永远看不见"
    );
}

/// 【探针 P8 / 变异 M28】护栏复位**必须清掉** `lost` / `lost_ids`(三处文档都这么写)。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_guard_reset_clears_the_lost_mark() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p8.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let mut wm = probe_wm(&probe_run(&e, &loc_s, None));
    // ① 先真丢一条 → 标记立起来。
    e.add_bad_typed_row("message_0.db", CONV, 6);
    e.append_rows("message_0.db", CONV, 7, 7, 0);
    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    wm = probe_wm(&r2);
    assert!(wm[&k].lost, "先得真的立起来");

    // ② 源库换成另一份副本 → 护栏复位 → 旧那份丢的行跟这份没关系, 标记该跟着清。
    e.reset_shard_gen("message_0.db", CONV, 9, 1);
    let r3 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm3 = probe_wm(&r3);
    let reset = r3.meta.summary.as_ref().unwrap()["guard_reset_tables"]
        .as_u64()
        .unwrap();
    println!("[探针P8] 复位={reset}; 复位后水位 {:?}", wm3[&k]);
    assert_eq!(reset, 1, "换副本该复位");
    assert!(!wm3[&k].lost, "复位了就得把旧那份的丢标记清掉");
    assert!(wm3[&k].lost_ids.is_empty());
}

/// 【探针 P9 / 变异 M13】下限必须取**汇报位置 `id`**, 不能取护栏锚点 `gid`。
/// 锚点落后是真库常态(某张表长期扫不全), 这时 `(gid, id]` 里的行**早报给用户了** ——
/// 拿 `gid` 当下限就把它们重新算成"丢了", 而这个标记永不自动清除。
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_floor_must_be_the_reported_position_not_the_anchor() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 5, 0);
    let loc = e.data_dir.join("probe_locator_p9.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let mut wm = probe_wm(&probe_run(&e, &loc_s, None));
    assert_eq!(wm[&k].id, 5);

    // ② 新到 6/7, 外加一行**一直**读不出来的 8 号 ⟹ 这一轮没扫全, 但位置照推到 7。
    e.append_rows("message_0.db", CONV, 6, 7, 0);
    e.add_bad_typed_row("message_0.db", CONV, 8);
    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    wm = probe_wm(&r2);
    println!("[探针P9] ②没扫全却推进 → 水位 {:?}", wm[&k]);
    assert_eq!(wm[&k].id, 7, "位置该推到 7");
    assert!(
        wm[&k].gid.unwrap_or(wm[&k].id) < wm[&k].id,
        "锚点该落在位置后面, 否则这条测的不是它想测的。实际 {:?}",
        wm[&k]
    );
    let lost_before = probe_lost(&r2);

    // ③ 早就报过的第 6 行(落在 (gid, id] 那一段里)被就地改写弄坏。用户早看过它, 一条没丢。
    e.flip_row_readable("message_0.db", CONV, 6, false);
    let r3 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm3 = probe_wm(&r3);
    println!(
        "[探针P9] ③(gid,id] 里的老行坏掉 → 丢={} (之前 {lost_before}); 水位 {:?}",
        probe_lost(&r3),
        wm3[&k]
    );
    assert_eq!(
        probe_lost(&r3),
        0,
        "第 6 行早报过了 —— 下限拿 `gid` 就会把它算成丢, 而这个标记清不掉"
    );
    assert!(!wm3[&k].lost);
}

/// 【探针 P10 / 变异 M27】两条路的行号加起来超过上限时, 留下的必须是**全局最小的那几个**。
/// (不排序就截断的话, 留下的是"扫描器那一路的前 8 个", 正文那一路更小的行号被挤掉 ——
///  用户拿告警里的行号去查, 查到的不是最早丢的那几行。)
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn audit_lost_ids_are_the_globally_smallest_across_both_paths() {
    let e = Env::new();
    e.reset_shard_gen("message_0.db", CONV, 70, 0);
    let loc = e.data_dir.join("probe_locator_p10.json");
    let loc_s = loc.to_str().unwrap().to_string();
    let k = format!("message_0.db\u{1f}{CONV}");

    let wm = probe_wm(&probe_run(&e, &loc_s, None));
    assert_eq!(wm[&k].id, 70);

    // 奇数行走扫描器那一路, 偶数行走正文那一路 —— 交错, 各自都超过上限 8。
    for i in 0..8 {
        e.add_bad_typed_row("message_0.db", CONV, 71 + i * 2);
    }
    for i in 0..8 {
        e.add_bad_content_row("message_0.db", CONV, 72 + i * 2);
    }
    e.append_rows("message_0.db", CONV, 90, 90, 0);

    let r2 = probe_run(&e, &loc_s, Some(wm.clone()));
    let wm2 = probe_wm(&r2);
    println!("[探针P10] 两路交错各 8 个 → lost_ids={:?}", wm2[&k].lost_ids);
    assert_eq!(wm2[&k].id, 90, "位置该越过那 16 行");
    assert_eq!(
        wm2[&k].lost_ids,
        vec![71, 72, 73, 74, 75, 76, 77, 78],
        "得是**合起来最小的 8 个**, 不是某一路的前 8 个"
    );
}
