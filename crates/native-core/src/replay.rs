//! replay — 从 raw_payload_archive 重放历史事件到 in-proc channel (recovery / 续传).
//!
//! [`replay_archive`] = [`storage::read_archive_since`](crate::storage::read_archive_since) (读 archive
//! 自游标) + 逐条 emit 到 [`InProcEmitter`]. 给下游 app 崩溃后从游标续读 24h 窗口错过的事件 (adapter §replay).
//! **不重构 DecodedEvent** — 重放原 [`RawPayloadRecord`](crate::emit::RawPayloadRecord) (溯源行).
//!
//! ## !Send 限制 (alpha KI)
//! 本 async fn 持 `&Connection` 跨 await (rusqlite `Connection` !Sync → `&Connection` !Send) → future !Send,
//! 只能在【单线程/当前任务】 `.await` (不能 `tokio::spawn` 到多线程 worker). alpha adapter replay 是单任务, 可接受;
//! 0.2.0+ 若需 spawn 到 worker, 改"先 read 收 Vec (sync) 再 emit (Send)" 两段式.

use rusqlite::Connection;

use crate::emit::in_proc::{EmitError, InProcEmitter};
use crate::storage::read_archive_since;

/// replay 错误.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// 读 archive 失败.
    #[error("archive read error: {0}")]
    Storage(#[from] rusqlite::Error),
    /// 重发到 channel 失败 (消费端关闭).
    #[error("emit error: {0}")]
    Emit(#[from] EmitError),
}

/// 重放 raw_payload_archive 中 `after_id` 之后的事件到 `emitter` (in-proc channel), 按 archive id 升序.
///
/// 返回【最后重放的 archive id】 作新游标 (无新事件 → 返 `after_id` 原值). 背压按 emitter 的 mode
/// (Block 等消费 / Drop 满则丢 + 计数). 消费端关闭 → 立即停 + [`ReplayError::Emit`].
///
/// **!Send** — 见模块文档; 只在单任务 `.await`.
///
/// # Errors
/// [`ReplayError::Storage`] (读 archive 失败) / [`ReplayError::Emit`] (消费端关闭).
pub async fn replay_archive(emitter: &InProcEmitter, conn: &Connection, after_id: i64) -> Result<i64, ReplayError> {
    let rows = read_archive_since(conn, after_id)?;
    let mut cursor = after_id;
    for (id, record) in rows {
        emitter.emit(record).await?;
        cursor = id;
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::in_proc::{new_in_proc, Backpressure};
    use crate::emit::RawPayloadRecord;
    use crate::storage::{init_archive_table, insert_record, open};

    fn rec(native: &str, seq: i64) -> RawPayloadRecord {
        RawPayloadRecord {
            account_id_sha: "acct".to_string(),
            source: "m.db".to_string(),
            source_native_id: native.to_string(),
            event_type: "message".to_string(),
            event_action: "create".to_string(),
            event_seq: seq,
            ingest_time: seq * 100,
            payload_json: "{}".to_string(),
        }
    }

    fn db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("l1.db")).unwrap();
        init_archive_table(&conn).unwrap();
        (dir, conn)
    }

    /// 空 archive → 游标不变, 无 emit.
    #[tokio::test]
    async fn replay_empty_returns_cursor() {
        let (_d, conn) = db();
        let (tx, _rx) = new_in_proc(4, Backpressure::Block);
        assert_eq!(replay_archive(&tx, &conn, 0).await.unwrap(), 0, "无事件游标不变");
    }

    /// 重放全部按 id 序到 channel, 返末 id 作新游标.
    #[tokio::test]
    async fn replay_emits_all_and_returns_cursor() {
        let (_d, conn) = db();
        insert_record(&conn, &rec("a", 10)).unwrap();
        insert_record(&conn, &rec("b", 20)).unwrap();
        insert_record(&conn, &rec("c", 30)).unwrap();
        let (tx, mut rx) = new_in_proc(8, Backpressure::Block); // cap 8 > 3 不阻塞
        let cursor = replay_archive(&tx, &conn, 0).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().source_native_id, "a");
        assert_eq!(rx.recv().await.unwrap().source_native_id, "b");
        assert_eq!(rx.recv().await.unwrap().source_native_id, "c");
        assert!(cursor > 0, "游标 = 末条 archive id");
    }

    /// 从游标续放: 只重放 id > 游标 的新事件.
    #[tokio::test]
    async fn replay_from_cursor_skips_consumed() {
        let (_d, conn) = db();
        insert_record(&conn, &rec("a", 10)).unwrap();
        insert_record(&conn, &rec("b", 20)).unwrap();
        let (tx, mut rx) = new_in_proc(8, Backpressure::Block);
        let cursor = replay_archive(&tx, &conn, 0).await.unwrap(); // 放 a,b
        assert_eq!(rx.recv().await.unwrap().source_native_id, "a");
        assert_eq!(rx.recv().await.unwrap().source_native_id, "b");
        // 新增 c, 从 cursor 续放 → 只 c
        insert_record(&conn, &rec("c", 30)).unwrap();
        let cursor2 = replay_archive(&tx, &conn, cursor).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().source_native_id, "c", "续放只新事件");
        assert!(cursor2 > cursor, "游标前进");
    }

    /// Drop 背压: cap=1 满则丢, replay 不阻塞且计数 (用户接受丢).
    #[tokio::test]
    async fn replay_drop_mode_counts_dropped() {
        let (_d, conn) = db();
        insert_record(&conn, &rec("a", 10)).unwrap();
        insert_record(&conn, &rec("b", 20)).unwrap();
        insert_record(&conn, &rec("c", 30)).unwrap();
        let (tx, mut rx) = new_in_proc(1, Backpressure::Drop); // cap 1, 后 2 条丢
        replay_archive(&tx, &conn, 0).await.unwrap();
        assert_eq!(tx.dropped_count(), 2, "cap 1 → 丢 2 条");
        assert_eq!(rx.recv().await.unwrap().source_native_id, "a", "仅首条留");
    }

    /// 消费端关闭 → ReplayError::Emit(ChannelClosed).
    #[tokio::test]
    async fn replay_to_closed_channel_errs() {
        let (_d, conn) = db();
        insert_record(&conn, &rec("a", 10)).unwrap();
        let (tx, rx) = new_in_proc(4, Backpressure::Block);
        drop(rx);
        let err = replay_archive(&tx, &conn, 0).await.unwrap_err();
        assert!(matches!(err, ReplayError::Emit(EmitError::ChannelClosed)));
    }
}
