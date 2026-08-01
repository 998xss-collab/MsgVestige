//! R19 选择性采集 —— `capture_targets` 会话白名单（"圈定某些群/好友只增量存这些；没圈零成本"）。
//!
//! # 语义（组件 spec §4 D1）
//! `capture_targets` 是**账号维白名单**：一行 = 「account_sha 这个账号，要采 conv_id 这个会话」。
//! - **空**（某账号一条没圈）→ [`read_capture_targets`] 返 `None` → 该账号**全采**（零过滤成本，维持现状）。
//! - **非空** → 返 `Some(set)` → `run_message_body` 只采 `conv_id ∈ set` 的会话，其余 drain 前整表跳过。
//!
//! "没圈零成本"就是这条：没圈=空=全采；一旦 `capture add X` 就只采 X。删到空=回全采（想彻底停别跑 watch）。
//!
//! # 为什么按 `account_id_sha` 分（D3）
//! 对齐 `etl_state`/`raw_payload_archive` 的账号隔离：account A 的采集清单**不**误过滤 account B（同一 L1 多账号
//! 时 conv_id 可能撞）。过滤读、三皮 list 都 `WHERE account_id_sha = ?` scope 到账号。
//!
//! # conv_id 明文（D2）
//! 存/比明文 `conv_id`（单聊 wxid / 群 `xxx@chatroom`），对齐 ADR-427 全程明文（业务表都明文列）。用户直接
//! `capture add <wxid>`。K-R4 脱敏只管 Debug/log，不管存储。
//!
//! # 建表位置
//! `storage::init_l1_schema` 调 [`init_capture_targets`]（增量 `CREATE IF NOT EXISTS`，不 bump schema 版本；
//! 旧 L1 下次 init 自愈补建）。故 ingest/watch 正常路径表恒在；[`read_capture_targets`]/[`list_capture_targets`]
//! 仍显式容忍"表不存在"（旧库/裸库）→ 全采/空清单，不 fail。

use std::collections::HashSet;

use rusqlite::Connection;

/// 三皮 `list` 的一行（`conv_id` + 圈定时刻 + 备注）。
#[derive(Clone, PartialEq, Eq)]
pub struct CaptureTarget {
    /// 会话标识（单聊 wxid / 群 `xxx@chatroom`）；明文。
    pub conv_id: String,
    /// 圈定时刻（ingest_time 口径 ms）。
    pub added_at: i64,
    /// 可选备注（谁/为什么圈；可 NULL → `None`）。
    pub note: Option<String>,
}

// K-R4 (审 round-3 P1): conv_id 含明文 wxid/chatroom + note 任意文本 → **Debug/log 脱敏** (sha8 conv_id + 只出 note 长度,
// 同 `MessageSubsource`); 存储仍明文 (ADR-427)。`{:?}` 进 tracing/panic 诊断不泄会话标识/备注内容。
impl std::fmt::Debug for CaptureTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureTarget")
            .field("conv_id_sha8", &crate::key_provider::sha8(self.conv_id.as_bytes()))
            .field("added_at", &self.added_at)
            .field("note_len", &self.note.as_ref().map(String::len))
            .finish()
    }
}

/// 建 `capture_targets` 表（IF NOT EXISTS，幂等；组件 spec §3 L1）。
///
/// # Errors
/// rusqlite 建表失败。
pub fn init_capture_targets(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS capture_targets (
            account_id_sha  TEXT    NOT NULL,
            conv_id         TEXT    NOT NULL,
            added_at        INTEGER NOT NULL,
            note            TEXT,
            PRIMARY KEY (account_id_sha, conv_id)
        );",
    )
}

/// 表是否存在（旧库/裸库无此表 → 全采/空清单，不 fail）。查询错误传播（不吞成"不存在"，对齐 `get_l1_generation`）。
fn capture_targets_exists(conn: &Connection) -> rusqlite::Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='capture_targets'",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// 读某账号的白名单 `conv_id` 集合（供 `run_message_body` 过滤）。
///
/// **空（该账号一条没圈）或表不存在 → `Ok(None)`**（= 该账号全采，语义 D1）。非空 → `Ok(Some(set))`。
/// 每次调用读一次：watch **仅在 source 库 mtime 签名变了那次 poll 才调** `run_message_body`（非每 poll；run_watch_loop
/// mtime 门控，见 pipeline.rs:395 + 组件 spec §88）→ 那次重读 → 中途 `capture add` 在**下次 source 变化**的 poll 生效
/// （活跃会话有新消息时≈即时；源完全空闲需等新消息或重启 watch）。
///
/// # Errors
/// rusqlite 查询失败（表存在但读错 → 传播，不静默降级为全采）。
pub fn read_capture_targets(conn: &Connection, account_sha: &str) -> rusqlite::Result<Option<HashSet<String>>> {
    if !capture_targets_exists(conn)? {
        return Ok(None); // 旧库/裸库无表 → 全采（向后兼容）。
    }
    let mut stmt = conn.prepare("SELECT conv_id FROM capture_targets WHERE account_id_sha = ?1")?;
    let set: HashSet<String> = stmt
        .query_map([account_sha], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    // 空集 → None（全采），非空 → Some（只采）。account-scoped：A 有圈、B 没圈 → B 仍 None 全采（D3）。
    Ok(if set.is_empty() { None } else { Some(set) })
}

/// add（圈定）某账号的一个会话。重复 add 刷新 `note`/`added_at`（`ON CONFLICT DO UPDATE`，幂等不报错）。
///
/// # Errors
/// rusqlite 执行失败。
pub fn add_capture_target(
    conn: &Connection,
    account_sha: &str,
    conv_id: &str,
    note: Option<&str>,
    added_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO capture_targets (account_id_sha, conv_id, added_at, note)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(account_id_sha, conv_id) DO UPDATE SET
            added_at = excluded.added_at,
            note     = excluded.note",
        rusqlite::params![account_sha, conv_id, added_at, note],
    )?;
    Ok(())
}

/// rm（停采）某账号的一个会话。返回 `true`=删了一行 / `false`=本就不在（不报错）。
///
/// 注：删掉某会话后，它下次会被 drain 前整表跳过（不再采新消息）；已落库的历史**不删**（capture_targets 只管
/// "今后采不采"，不回溯清库）。
///
/// # Errors
/// rusqlite 执行失败。
pub fn remove_capture_target(conn: &Connection, account_sha: &str, conv_id: &str) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "DELETE FROM capture_targets WHERE account_id_sha = ?1 AND conv_id = ?2",
        rusqlite::params![account_sha, conv_id],
    )?;
    Ok(n == 1)
}

/// list 某账号的采集清单（按 `added_at` 升序，同刻按 `conv_id`）。表不存在 → 空 `Vec`。
///
/// # Errors
/// rusqlite 查询失败。
pub fn list_capture_targets(conn: &Connection, account_sha: &str) -> rusqlite::Result<Vec<CaptureTarget>> {
    if !capture_targets_exists(conn)? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT conv_id, added_at, note FROM capture_targets
         WHERE account_id_sha = ?1 ORDER BY added_at, conv_id",
    )?;
    let rows = stmt
        .query_map([account_sha], |r| {
            Ok(CaptureTarget {
                conv_id: r.get(0)?,
                added_at: r.get(1)?,
                note: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_capture_targets(&conn).unwrap();
        conn
    }

    const A: &str = "acct_sha_aaaa";
    const B: &str = "acct_sha_bbbb";

    #[test]
    fn empty_table_reads_none_全采() {
        let conn = mem();
        assert_eq!(read_capture_targets(&conn, A).unwrap(), None, "空表该 None（全采）");
    }

    #[test]
    fn missing_table_reads_none_向后兼容() {
        // 裸库无 capture_targets 表 → None（全采），不 fail。
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(read_capture_targets(&conn, A).unwrap(), None);
        assert_eq!(list_capture_targets(&conn, A).unwrap(), Vec::new());
    }

    #[test]
    fn add_then_read_returns_set() {
        let conn = mem();
        add_capture_target(&conn, A, "wxid_x", Some("重要客户"), 1000).unwrap();
        add_capture_target(&conn, A, "grp@chatroom", None, 1001).unwrap();
        let set = read_capture_targets(&conn, A).unwrap().unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains("wxid_x") && set.contains("grp@chatroom"));
    }

    #[test]
    fn add_idempotent_refreshes_note() {
        let conn = mem();
        add_capture_target(&conn, A, "wxid_x", Some("v1"), 1000).unwrap();
        add_capture_target(&conn, A, "wxid_x", Some("v2"), 2000).unwrap(); // 重复 add 不报错
        let list = list_capture_targets(&conn, A).unwrap();
        assert_eq!(list.len(), 1, "重复 add 不生新行");
        assert_eq!(list[0].note.as_deref(), Some("v2"), "刷新 note");
        assert_eq!(list[0].added_at, 2000, "刷新 added_at");
    }

    #[test]
    fn remove_returns_existed_flag() {
        let conn = mem();
        add_capture_target(&conn, A, "wxid_x", None, 1000).unwrap();
        assert!(remove_capture_target(&conn, A, "wxid_x").unwrap(), "删存在的 → true");
        assert!(
            !remove_capture_target(&conn, A, "wxid_x").unwrap(),
            "删不存在的 → false"
        );
        assert_eq!(read_capture_targets(&conn, A).unwrap(), None, "删空后回全采");
    }

    #[test]
    fn account_isolation_d3() {
        let conn = mem();
        add_capture_target(&conn, A, "wxid_x", None, 1000).unwrap();
        // A 有圈 → Some；B 没圈 → None（全采，不被 A 的清单误过滤）。
        assert_eq!(read_capture_targets(&conn, A).unwrap().unwrap().len(), 1);
        assert_eq!(read_capture_targets(&conn, B).unwrap(), None);
        // 同 conv_id 在 A/B 各存一行不撞（PK 含 account_id_sha）。
        add_capture_target(&conn, B, "wxid_x", None, 1000).unwrap();
        assert_eq!(list_capture_targets(&conn, A).unwrap().len(), 1);
        assert_eq!(list_capture_targets(&conn, B).unwrap().len(), 1);
    }

    #[test]
    fn list_ordered_by_added_at() {
        let conn = mem();
        add_capture_target(&conn, A, "c_late", None, 3000).unwrap();
        add_capture_target(&conn, A, "c_early", None, 1000).unwrap();
        add_capture_target(&conn, A, "c_mid", None, 2000).unwrap();
        let list = list_capture_targets(&conn, A).unwrap();
        let ids: Vec<&str> = list.iter().map(|t| t.conv_id.as_str()).collect();
        assert_eq!(ids, ["c_early", "c_mid", "c_late"], "按 added_at 升序");
    }

    #[test]
    fn init_idempotent() {
        let conn = mem();
        add_capture_target(&conn, A, "wxid_x", None, 1000).unwrap();
        init_capture_targets(&conn).unwrap(); // 再 init 不清数据（IF NOT EXISTS）
        assert_eq!(read_capture_targets(&conn, A).unwrap().unwrap().len(), 1);
    }

    /// K-R4 (审 round-3 P1): `CaptureTarget` 的 Debug 不泄 conv_id 明文 / note 内容 (sha8 + 长度)。
    #[test]
    fn debug_redacts_conv_id_and_note() {
        let t = CaptureTarget {
            conv_id: "wxid_secret_peer".into(),
            added_at: 123,
            note: Some("敏感备注内容".into()),
        };
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("wxid_secret_peer"), "Debug 不泄 conv_id 明文: {dbg}");
        assert!(!dbg.contains("敏感备注内容"), "Debug 不泄 note 内容: {dbg}");
        assert!(dbg.contains("conv_id_sha8"), "应出 conv_id_sha8 而非明文: {dbg}");
        assert!(dbg.contains("note_len"), "应出 note_len 而非内容: {dbg}");
    }
}
