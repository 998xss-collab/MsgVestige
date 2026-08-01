//! **第四轮对抗审 (改写前后行为等价性) 的一次性证据脚本** —— 不是产品守卫, 只是把
//! "调 1 次给 N 片" vs "调 N 次每次 1 片" 的差异**量出来**。
//!
//! 跑法:
//! ```text
//! CARGO_TARGET_DIR=E:/tq4 cargo test -p native-query --test r22_r4_equivalence_audit \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 夹具代码抄自 `r22_d24_gate_race.rs`(同一套合成 SQLCipher4 库)。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use rusqlite::Connection;

const PAGE: usize = 4096;
const RESERVE: usize = 80;
const ROUNDS: u32 = 256_000;
const MAC_SALT_XOR: u8 = 0x3a;
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
        let mut enc = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&master, &SALT, ROUNDS, &mut enc);
        let mac_salt: Vec<u8> = SALT.iter().map(|b| b ^ MAC_SALT_XOR).collect();
        let mut mac = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&enc, &mac_salt, 2, &mut mac);
        (enc, mac)
    })
}

fn encrypt(plain: &[u8]) -> Vec<u8> {
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit as _};
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let (enc_key, mac_key) = derived();
    assert_eq!(plain.len() % PAGE, 0);
    assert_eq!(usize::from(plain[20]), RESERVE);
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

struct Env {
    _tmp: Option<tempfile::TempDir>,
    data_dir: PathBuf,
    msg_dir: PathBuf,
    l1: PathBuf,
    wxid: native_core::key_provider::Wxid,
}

impl Env {
    /// `at = None` → tempdir(自动清理); `Some(p)` → 落在 p 下并**留着**(供三皮真跑用)。
    fn new_at(at: Option<PathBuf>) -> Self {
        let (tmp, root) = match at {
            Some(p) => {
                let _ = std::fs::remove_dir_all(&p);
                std::fs::create_dir_all(&p).unwrap();
                (None, p)
            }
            None => {
                let t = tempfile::tempdir().unwrap();
                let p = t.path().to_path_buf();
                (Some(t), p)
            }
        };
        let w = wxid_str();
        let data_dir = root.join("data");
        let storage = data_dir.join(format!("{w}_d24")).join("db_storage");
        let msg_dir = storage.join("message");
        std::fs::create_dir_all(&msg_dir).unwrap();
        std::fs::create_dir_all(storage.join("session")).unwrap();
        let plain = root.join("plain_session");
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
            l1: root.join("l1.db"),
            wxid: native_core::key_provider::Wxid::try_new(w).unwrap(),
            _tmp: tmp,
        }
    }

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
                c.execute_batch(&format!(
                    "CREATE TABLE IF NOT EXISTS \"{t}\" (local_id INTEGER PRIMARY KEY, server_id INTEGER,
                       server_seq INTEGER, origin_source INTEGER, upload_status INTEGER, download_status INTEGER,
                       local_type INTEGER, sort_seq INTEGER, create_time INTEGER, status INTEGER,
                       real_sender_id INTEGER, message_content BLOB, source BLOB);"
                ))
                .unwrap();
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

    fn drop_junk_shard(&self, rel: &str, bytes: usize) {
        std::fs::write(self.msg_dir.join(rel), vec![0x5du8; bytes]).unwrap();
    }

    fn source(&self) -> native_core::source::AccountDbSource {
        let key = rt().block_on(native_query::cache_key(&self.wxid)).unwrap();
        let entry = self.msg_dir.parent().unwrap().join("session").join("session.db");
        let cipher: Box<dyn native_core::cipher::Cipher> = Box::new(native_core::cipher::NativeCipher::new_live());
        native_core::source::AccountDbSource::new(cipher, entry, key, self.wxid.clone(), self.msg_dir.clone())
    }
}

const CONV: &str = "r4probe@chatroom";

fn shard_names(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("message_{i}.db")).collect()
}

/// **A/B: 「调 1 次给 N 片」 vs 「调 N 次每次 1 片」**。
///
/// 两边用**完全一样**的夹具 (各自一份 L1 + 各自一个 `AccountDbSource`), 比:
/// - `PipelineStats` 每个字段
/// - `matched` 内容与**顺序**
/// - 墙钟耗时 (= 逐分片改造的真实代价)
#[test]
#[ignore = "要真账号已缓存 key (只用于加密测试夹具)"]
fn r4_batch_vs_per_shard_equivalence_and_cost() {
    // 两轮: 第一轮有一次性预热 (keycache / 页缓存), 第二轮才是可比的数。
    for round in 0..2 {
        println!("──────── 第 {round} 轮 ────────");
        ab_once();
    }
}

fn ab_once() {
    let shards = shard_names(6);
    // 会话住在 message_2 与 message_5 两片 (跨片存在是真库常态: 轮转后老表冻在旧片)。
    let build = |e: &Env| {
        for (i, s) in shards.iter().enumerate() {
            if i == 2 {
                e.write_shard(s, &[(CONV, 40), ("bystander_a", 5)]);
            } else if i == 5 {
                e.write_shard(s, &[(CONV, 25), ("bystander_b", 5)]);
            } else {
                e.write_shard(s, &[("bystander_x", 7)]);
            }
        }
    };

    // ── 老形态: 一次把 6 片全丢进去 ──
    let e1 = Env::new_at(None);
    build(&e1);
    let mut src1 = e1.source();
    let mut rw1 = native_core::storage::open(&e1.l1).unwrap();
    native_core::storage::init_l1_schema(&rw1).unwrap();
    let t1 = std::time::Instant::now();
    let (stats_batch, matched_batch) = rt()
        .block_on(native_core::pipeline::ingest_one_chat(
            &mut src1,
            &mut rw1,
            &e1.wxid,
            CONV,
            &shards,
            native_core::PrivacyMode::archive_canonical(),
            1000,
            1_700_000_000_000,
        ))
        .unwrap();
    let d1 = t1.elapsed();

    // ── 新形态: 逐片调 6 次, 自己累加 ──
    let e2 = Env::new_at(None);
    build(&e2);
    let mut src2 = e2.source();
    let mut rw2 = native_core::storage::open(&e2.l1).unwrap();
    native_core::storage::init_l1_schema(&rw2).unwrap();
    let t2 = std::time::Instant::now();
    let mut per_shard: Vec<native_core::pipeline::PipelineStats> = Vec::new();
    let mut matched_seq: Vec<String> = Vec::new();
    for s in &shards {
        let (st, m) = rt()
            .block_on(native_core::pipeline::ingest_one_chat(
                &mut src2,
                &mut rw2,
                &e2.wxid,
                CONV,
                std::slice::from_ref(s),
                native_core::PrivacyMode::archive_canonical(),
                1000,
                1_700_000_000_000,
            ))
            .unwrap();
        per_shard.push(st);
        for n in m {
            if !matched_seq.contains(&n) {
                matched_seq.push(n);
            }
        }
    }
    let d2 = t2.elapsed();

    // refresh.rs 的 merge_stats 口径 (dbs 取 max, 其余求和) —— 原样复刻一遍。
    //
    // ⚠️ **这份是抄本, 会漂**(独立复审 651ed5c 的 P3 逮到的): 它当时已经落了
    // `rescanned_subsources`, 而整条测试是 `#[ignore]`(要真账号 + 已缓存 key), 所以漂了没人知道。
    // 结尾那句是整个结构体比, 漏一个字段就永远比不平。refresh.rs 那边现在有一条
    // `merge_stats_carries_every_field` 拿结构体字面量钉住"每个字段都得动";
    // 这里没法调那个私有函数, 只能人肉跟着 —— 加字段时两处一起改。
    let mut merged = native_core::pipeline::PipelineStats::default();
    for one in &per_shard {
        merged.dbs = merged.dbs.max(one.dbs);
        merged.subsources += one.subsources;
        merged.batches += one.batches;
        merged.messages_decoded += one.messages_decoded;
        merged.decode_errors += one.decode_errors;
        merged.cursor_updates += one.cursor_updates;
        merged.stalled_subsources += one.stalled_subsources;
        merged.rescanned_subsources += one.rescanned_subsources;
        merged.skipped_subsources += one.skipped_subsources;
        merged.decode_windows += one.decode_windows;
        merged.members_added += one.members_added;
        merged.members_removed += one.members_removed;
        merged.invalid_chatrooms += one.invalid_chatrooms;
        merged.chatrooms_created += one.chatrooms_created;
    }

    println!("[A/B] 整批  stats = {stats_batch:?}\n      matched = {matched_batch:?}  用时 {d1:?}");
    println!("[A/B] 逐片  stats = {merged:?}\n      matched = {matched_seq:?}  用时 {d2:?}");
    for (i, s) in per_shard.iter().enumerate() {
        println!("[A/B]   第{i}片({}) = {s:?}", shards[i]);
    }
    let rows = |p: &Path| {
        native_core::storage::open(p)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM message WHERE conv_id_sha=?1",
                rusqlite::params![native_core::sha256_hex(CONV)],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(-1)
    };
    println!("[A/B] L1 行数: 整批={} 逐片={}", rows(&e1.l1), rows(&e2.l1));
    println!(
        "[A/B] 逐片额外开销 = {:?} ({:.1}%)",
        d2.saturating_sub(d1),
        (d2.as_secs_f64() / d1.as_secs_f64() - 1.0) * 100.0
    );

    assert_eq!(rows(&e1.l1), rows(&e2.l1), "落库行数必须一致");
    assert_eq!(matched_batch, matched_seq, "命中名单的内容与顺序都必须一致");
    assert_eq!(merged, stats_batch, "merge_stats 合并出来的统计必须与整批一致");
}

/// **B: 三皮真跑用的持久夹具** —— 造一个"好分片 + 坏分片"的账号目录并**留在磁盘上**,
/// 打印路径供 CLI / HTTP / MCP 各跑一遍对拍 `refresh_skipped`。
#[test]
#[ignore = "要真账号已缓存 key; 会在 R22_AUDIT_DIR 留下夹具不删"]
fn r4_make_persistent_degraded_fixture() {
    // 这条是**手工工具**不是断言: 没给落地目录就跳过, 别让 `--ignored` 全跑时红一条
    // (原来是 `.expect(...)` → 直接 panic, 看着像回归)。
    let Ok(at) = std::env::var("R22_AUDIT_DIR") else {
        println!("[夹具] 未设 R22_AUDIT_DIR → 跳过 (这条是造三皮对拍夹具的手工工具, 不是回归断言)");
        return;
    };
    let e = Env::new_at(Some(PathBuf::from(&at)));
    e.write_shard("message_0.db", &[(CONV, 4)]);
    // 先正常采一轮, 把 L1 建起来 (含 chat_refresh_state)。
    let r0 = rt()
        .block_on(native_query::ensure_chat_fresh(
            &e.l1,
            &e.wxid,
            CONV,
            Some(e.data_dir.to_str().unwrap()),
        ))
        .unwrap();
    println!("[夹具] 首采 = {r0:?} skip={:?}", r0.skip_reason());
    // 再放一个读不开的新分片 → 之后每次查询都会落进 SourceDegraded。
    e.drop_junk_shard("message_9.db", 0);
    let r1 = rt()
        .block_on(native_query::ensure_chat_fresh(
            &e.l1,
            &e.wxid,
            CONV,
            Some(e.data_dir.to_str().unwrap()),
        ))
        .unwrap();
    println!("[夹具] 坏分片就位 = skip={:?}", r1.skip_reason());
    assert_eq!(r1.skip_reason(), Some("source_degraded"));
    println!("R4_L1={}", e.l1.display());
    println!("R4_DATA_DIR={}", e.data_dir.display());
    println!("R4_WXID={}", e.wxid.as_str());
    println!("R4_CONV={CONV}");
}
