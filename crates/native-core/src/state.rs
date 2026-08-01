//! state — 增量水位 (cursor) 管理 (native-core 子系统, ADR-416 §3.2.1).
//!
//! 本 mod = PR2-4-c: etl_state 表 (L1-schema §3.2.1) CRUD — 每 (account_id_sha, source, kind) 一条
//! cursor 水位. 对应 [`crate::event::system::SystemCursorUpdate`] 事件携带的 cursor 状态 (adapter
//! 推进读取位置时 upsert, 续传/重放时 get).
//!
//! ## 字段全非敏感
//! account_id_sha 已 sha; source (db 文件名) / kind (event_type) / watermark_key (元组描述) /
//! watermark_value 都是元数据, 无 wxid/正文 → [`Watermark`] derive Debug 安全.
//!
//! ⚠️ 这条论证的**前提在"表重建"那一串里换过**(独立复审 P3): `watermark_value` 现在是
//! `{"id","fp","ct","sid"}`, 其中 `fp` 是把**正文全部字节**混进去的 FNV-1a 哈希
//! (见 [`crate::source::row_fingerprint`])。结论仍成立 —— 单向哈希不是正文、也不可逆 ——
//! 但别再照"时间戳+seq+local_id 元组"那句去推, 那个格式已经没有了。
//! 往水位里再加字段时, **这条安全性论证要重走一遍**。

use rusqlite::{params, Connection, OptionalExtension};

/// 一条增量水位 (etl_state 行, L1-schema §3.2.1). PK = (account_id_sha, source, kind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watermark {
    /// 多账号隔离 = sha256(account_id).
    pub account_id_sha: String,
    /// 源 db 文件名 (e.g. "message_5.db") 或 "_global_" (全局水位).
    pub source: String,
    /// event_type (e.g. "message" / "contact_update").
    pub kind: String,
    /// 水位键描述 (e.g. "(create_time, sort_seq, local_id)").
    pub watermark_key: String,
    /// 水位值 JSON 元组 (e.g. "[1780000000, 1780000000000, 100]").
    pub watermark_value: String,
    /// 水位最后变化时间 (毫秒).
    pub last_update: i64,
}

/// 建 etl_state 表 (IF NOT EXISTS 幂等, L1-schema §3.2.1).
///
/// # Errors
/// rusqlite 建表失败.
pub fn init_etl_state_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS etl_state (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            kind              TEXT    NOT NULL,
            watermark_key     TEXT    NOT NULL,
            watermark_value   TEXT    NOT NULL,
            last_update       INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, source, kind)
        );",
    )
}

/// 读 (account_id_sha, source, kind) 的当前水位; 无则 `None` (首次未推进).
///
/// # Errors
/// rusqlite 查询失败.
pub fn get_watermark(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    kind: &str,
) -> rusqlite::Result<Option<Watermark>> {
    conn.query_row(
        "SELECT watermark_key, watermark_value, last_update FROM etl_state
         WHERE account_id_sha = ?1 AND source = ?2 AND kind = ?3",
        params![account_id_sha, source, kind],
        |row| {
            Ok(Watermark {
                account_id_sha: account_id_sha.to_string(),
                source: source.to_string(),
                kind: kind.to_string(),
                watermark_key: row.get(0)?,
                watermark_value: row.get(1)?,
                last_update: row.get(2)?,
            })
        },
    )
    .optional()
}

/// 推进 (upsert) 水位 — 撞 PK (account_id_sha, source, kind) 则更新 watermark/last_update (cursor 前进).
///
/// # Errors
/// rusqlite 执行失败.
pub fn upsert_watermark(conn: &Connection, wm: &Watermark) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO etl_state (account_id_sha, source, kind, watermark_key, watermark_value, last_update)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(account_id_sha, source, kind) DO UPDATE SET
            watermark_key   = excluded.watermark_key,
            watermark_value = excluded.watermark_value,
            last_update     = excluded.last_update",
        params![
            wm.account_id_sha,
            wm.source,
            wm.kind,
            wm.watermark_key,
            wm.watermark_value,
            wm.last_update,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn wm(source: &str, kind: &str, value: &str, last_update: i64) -> Watermark {
        Watermark {
            account_id_sha: "acct_sha".to_string(),
            source: source.to_string(),
            kind: kind.to_string(),
            watermark_key: "(create_time, sort_seq, local_id)".to_string(),
            watermark_value: value.to_string(),
            last_update,
        }
    }

    fn open_inited() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let conn = Connection::open(dir.path().join("l1.db")).unwrap();
        init_etl_state_table(&conn).unwrap();
        (dir, conn)
    }

    #[test]
    fn init_idempotent() {
        let (_d, conn) = open_inited();
        init_etl_state_table(&conn).unwrap(); // 再建不报错
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='etl_state'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn get_missing_is_none() {
        let (_d, conn) = open_inited();
        assert_eq!(
            get_watermark(&conn, "acct_sha", "message_5.db", "message").unwrap(),
            None
        );
    }

    #[test]
    fn upsert_then_get_roundtrip() {
        let (_d, conn) = open_inited();
        let w = wm("message_5.db", "message", "[1780000000, 100]", 1000);
        upsert_watermark(&conn, &w).unwrap();
        assert_eq!(
            get_watermark(&conn, "acct_sha", "message_5.db", "message").unwrap(),
            Some(w)
        );
    }

    /// 推进: 同 PK 再 upsert → 更新 watermark_value + last_update, 不增行.
    #[test]
    fn upsert_same_pk_advances_not_duplicates() {
        let (_d, conn) = open_inited();
        upsert_watermark(&conn, &wm("message_5.db", "message", "[1780000000, 100]", 1000)).unwrap();
        upsert_watermark(&conn, &wm("message_5.db", "message", "[1790000000, 200]", 2000)).unwrap();
        let got = get_watermark(&conn, "acct_sha", "message_5.db", "message")
            .unwrap()
            .unwrap();
        assert_eq!(got.watermark_value, "[1790000000, 200]", "cursor 前进到新值");
        assert_eq!(got.last_update, 2000);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM etl_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 PK upsert 不增行");
    }

    /// 不同 (source 或 kind) → 各自独立水位行.
    #[test]
    fn different_pk_separate_rows() {
        let (_d, conn) = open_inited();
        upsert_watermark(&conn, &wm("message_5.db", "message", "[1, 1]", 1)).unwrap();
        upsert_watermark(&conn, &wm("message_6.db", "message", "[2, 2]", 2)).unwrap(); // 不同 source
        upsert_watermark(&conn, &wm("message_5.db", "contact_update", "[3, 3]", 3)).unwrap(); // 不同 kind
        let count: i64 = conn
            .query_row("SELECT count(*) FROM etl_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3, "不同 (account,source,kind) 各一行");
        // 各自取回正确
        assert_eq!(
            get_watermark(&conn, "acct_sha", "message_6.db", "message")
                .unwrap()
                .unwrap()
                .watermark_value,
            "[2, 2]"
        );
        assert_eq!(
            get_watermark(&conn, "acct_sha", "message_5.db", "contact_update")
                .unwrap()
                .unwrap()
                .watermark_value,
            "[3, 3]"
        );
    }

    /// "_global_" 全局水位也是一条普通行 (source="_global_").
    #[test]
    fn global_watermark_row() {
        let (_d, conn) = open_inited();
        upsert_watermark(&conn, &wm("_global_", "message", "[9, 9]", 9)).unwrap();
        assert_eq!(
            get_watermark(&conn, "acct_sha", "_global_", "message")
                .unwrap()
                .unwrap()
                .watermark_value,
            "[9, 9]"
        );
    }
}
