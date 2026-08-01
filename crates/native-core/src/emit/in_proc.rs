//! emit::in_proc — alpha 同进程 EventEmitter (tokio mpsc bounded channel).
//!
//! adapter-适配器.md §: alpha 用同进程 in-proc Tokio mpsc channel 把 [`RawPayloadRecord`] 从采集端
//! (adapter) 送到消费端 (sink writer). 0.2.0+ JSONL 落盘 / 0.3.0+ MQ 是别的 EventEmitter 实现.
//!
//! ## 背压 (adapter §"背压不允许默认 drop")
//! channel 满时:
//! - [`Backpressure::Block`] (**默认**): `send().await` 阻塞等消费 — 上层慢就阻塞采集, 【不丢消息】.
//! - [`Backpressure::Drop`] (用户主动): 丢弃当前 + [`InProcEmitter::dropped_count`] 计数, 返 `Ok`.
//! - Spill (满 → JSONL 落盘) 推 0.2.0+ (KI), 本片不含.
//!
//! ## 调用顺序契约 (adapter §)
//! 【archive 必须先写, 然后才 emit】: `archive.write(payload)` → `emitter.emit(payload)`.
//! 本 channel 只管【传输】, 顺序由调用方 (adapter) 保证 — 这里不耦合 storage.
//!
//! ## 边界 (推后续)
//! `EventEmitter` trait (统一 in-proc/JSONL/MQ 多实现) + `replay()` (24h 重放, 需读 raw_payload_archive)
//! 推后续 (需 adapter 接入 + recovery 实现); 本片只落 alpha 唯一实现的【具体并发 channel】.
//!
//! ## K-R4
//! channel 只【过】 [`RawPayloadRecord`] (不存储), record 自身手写 Debug 已脱敏 payload_json;
//! [`InProcEmitter`] / [`InProcReceiver`] 的 Debug 只示句柄 (无 payload), 安全.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::emit::RawPayloadRecord;

/// 背压模式 (config `[observability] backpressure`; adapter §: 默认 block, drop 用户主动, spill 推 0.2.0+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backpressure {
    /// **默认**: channel 满 → 阻塞 (`send().await`) 等消费, 不丢消息 (上层慢就阻塞采集).
    #[default]
    Block,
    /// 用户主动: channel 满 → 丢弃当前 + 计数 (用户接受丢消息, 靠 [`InProcEmitter::dropped_count`] 感知).
    Drop,
}

/// emit 失败 (thiserror). 背压 drop【不是】错 (返 Ok + 计数); 仅消费端关闭算错.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// 消费端已关闭 (receiver drop) — channel 不可用, 上层应停止采集.
    #[error("event channel closed (consumer dropped)")]
    ChannelClosed,
}

/// 生产端: 把 [`RawPayloadRecord`] 送进 in-proc channel (背压按 [`Backpressure`]). 可 `Clone` 多生产者.
#[derive(Debug, Clone)]
pub struct InProcEmitter {
    tx: mpsc::Sender<RawPayloadRecord>,
    mode: Backpressure,
    dropped: Arc<AtomicU64>,
}

/// 消费端: 从 channel 收 [`RawPayloadRecord`] (sink writer 用). 单消费者 (mpsc).
#[derive(Debug)]
pub struct InProcReceiver {
    rx: mpsc::Receiver<RawPayloadRecord>,
}

/// 建一个 bounded in-proc channel (`capacity` 满后按 `mode` 背压). 返 (生产端, 消费端).
///
/// # Panics
/// `capacity == 0` (tokio `mpsc::channel` 要求 capacity ≥ 1).
#[must_use]
pub fn new_in_proc(capacity: usize, mode: Backpressure) -> (InProcEmitter, InProcReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    (
        InProcEmitter {
            tx,
            mode,
            dropped: Arc::new(AtomicU64::new(0)),
        },
        InProcReceiver { rx },
    )
}

impl InProcEmitter {
    /// 异步 emit 一条 record (背压按 mode):
    /// - [`Backpressure::Block`]: channel 满 → await 等消费 (不丢);
    /// - [`Backpressure::Drop`]: channel 满 → 丢弃 + `dropped` 计数, 返 `Ok` (调用方靠 [`Self::dropped_count`] 感知).
    ///
    /// # Errors
    /// [`EmitError::ChannelClosed`]: 消费端已 drop.
    pub async fn emit(&self, payload: RawPayloadRecord) -> Result<(), EmitError> {
        match self.mode {
            Backpressure::Block => self.tx.send(payload).await.map_err(|_| EmitError::ChannelClosed),
            Backpressure::Drop => match self.tx.try_send(payload) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Err(EmitError::ChannelClosed),
            },
        }
    }

    /// 背压累计丢弃数 (Drop 模式下满时 +1; Block 模式恒 0). 多生产者共享 (`Arc<AtomicU64>`).
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 当前背压模式.
    #[must_use]
    pub fn mode(&self) -> Backpressure {
        self.mode
    }
}

impl InProcReceiver {
    /// 收下一条 record. channel 空 → await; 所有生产端 drop 且排空 → `None` (优雅收尾).
    pub async fn recv(&mut self) -> Option<RawPayloadRecord> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一条最小 RawPayloadRecord (字段全 pub; native_id 区分).
    fn rec(native_id: &str) -> RawPayloadRecord {
        RawPayloadRecord {
            account_id_sha: "acct_sha".to_string(),
            source: "message_5.db".to_string(),
            source_native_id: native_id.to_string(),
            event_type: "message".to_string(),
            event_action: "create".to_string(),
            event_seq: 1,
            ingest_time: 1,
            payload_json: r#"{"event_type":"message"}"#.to_string(),
        }
    }

    /// Block 模式基本往返: emit → recv 拿回同 record.
    #[tokio::test]
    async fn block_emit_recv_roundtrip() {
        let (tx, mut rx) = new_in_proc(4, Backpressure::Block);
        tx.emit(rec("a")).await.unwrap();
        let got = rx.recv().await.unwrap();
        assert_eq!(got.source_native_id, "a");
        assert_eq!(tx.dropped_count(), 0, "Block 模式不丢");
    }

    /// Block 背压: channel 满 (cap=1) → 第二条 emit 阻塞, 直到 recv 腾位才完成 (不丢, FIFO).
    #[tokio::test]
    async fn block_backpressure_releases_on_recv() {
        let (tx, mut rx) = new_in_proc(1, Backpressure::Block);
        tx.emit(rec("a")).await.unwrap(); // 填满 cap=1
        let tx2 = tx.clone();
        let h = tokio::spawn(async move { tx2.emit(rec("b")).await }); // 满 → 阻塞
                                                                       // 让 spawned task 先被 poll: 撞满 channel → 挂起 (严格证"满时 await", 非立即完成)
        tokio::task::yield_now().await;
        assert!(!h.is_finished(), "channel 满时 b 的 emit 必须挂起 (Block 背压不丢)");
        // 收 a → 腾位 → b 的 emit 才完成
        assert_eq!(rx.recv().await.unwrap().source_native_id, "a");
        h.await.unwrap().unwrap();
        assert_eq!(rx.recv().await.unwrap().source_native_id, "b", "FIFO 不丢");
        assert_eq!(tx.dropped_count(), 0);
    }

    /// Drop 背压: channel 满 (cap=1) → 后续 emit 丢弃 + 计数, 返 Ok; 仅首条进 channel.
    #[tokio::test]
    async fn drop_backpressure_counts_and_keeps_first() {
        let (tx, mut rx) = new_in_proc(1, Backpressure::Drop);
        tx.emit(rec("a")).await.unwrap(); // 进 channel
        tx.emit(rec("b")).await.unwrap(); // 满 → 丢
        tx.emit(rec("c")).await.unwrap(); // 满 → 丢
        assert_eq!(tx.dropped_count(), 2, "丢 2 条");
        assert_eq!(rx.recv().await.unwrap().source_native_id, "a", "仅首条留存");
    }

    /// 消费端 drop → emit 返 ChannelClosed (上层据此停采集).
    #[tokio::test]
    async fn emit_to_closed_channel_errs() {
        let (tx, rx) = new_in_proc(4, Backpressure::Block);
        drop(rx);
        let err = tx.emit(rec("a")).await.unwrap_err();
        assert!(matches!(err, EmitError::ChannelClosed));
    }

    /// Drop 模式 + 消费端关闭: try_send 走 Closed 分支 (非 Full) → ChannelClosed.
    #[tokio::test]
    async fn drop_mode_closed_channel_errs() {
        let (tx, rx) = new_in_proc(1, Backpressure::Drop);
        drop(rx);
        let err = tx.emit(rec("a")).await.unwrap_err();
        assert!(
            matches!(err, EmitError::ChannelClosed),
            "Drop 模式 closed 也返 ChannelClosed (非计数丢弃)"
        );
        assert_eq!(tx.dropped_count(), 0, "closed 不算 drop");
    }

    /// 所有生产端 drop 且排空 → recv 返 None (优雅收尾, 非错).
    #[tokio::test]
    async fn recv_none_after_all_senders_dropped() {
        let (tx, mut rx) = new_in_proc(4, Backpressure::Block);
        tx.emit(rec("a")).await.unwrap();
        drop(tx);
        assert_eq!(rx.recv().await.unwrap().source_native_id, "a", "排空残留");
        assert!(rx.recv().await.is_none(), "生产端全 drop + 排空 → None");
    }

    /// 默认背压是 Block (adapter §"背压不允许默认 drop").
    #[test]
    fn default_backpressure_is_block() {
        assert_eq!(Backpressure::default(), Backpressure::Block);
    }
}
