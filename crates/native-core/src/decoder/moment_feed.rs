//! moment_feed row 组装 — 明文 `SnsTopItem_1` 行 → [`MomentFeedCreate`] 事件 (一条好友朋友圈动态索引)。
//!
//! [`assemble_moment_feed`] 把一条 `SnsTopItem_1` 行 (直接列, 无 proto/XML) 映射成 [`MomentFeedCreate`]。
//! event_seq 留 0。仿 [`super::friend_verify`] / [`super::finder`] (直接列专表 → alpha 事件; ADR-474)。
//!
//! ## 真实 schema (sns.db `SnsTopItem_1`, 消费列; 2026-07-06 inspect 加密原库坐实)
//! tid (动态 id = 锚点/身份) / username (发布者 wxid) / create_time (发布秒) / last_read_time (我读秒) /
//! is_read。**`summary` 列全空不取** (零价值)。表名 `SnsTopItem_1` (单分片, 真库核实无 _2/_3)。

use crate::event::moment_feed::MomentFeedCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `SnsTopItem_1` 行 (drain 原始行; 全直接列, assemble 直接映射)。
pub struct MomentFeedRow {
    /// SnsTopItem_1 rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 朋友圈动态 id (tid; 雪花可为负; 锚点 + 身份)。
    pub tid: i64,
    /// 发布者 wxid (username)。
    pub author: String,
    /// 发布时刻 (create_time; unix 秒)。
    pub create_time: i64,
    /// 我读到的时刻 (last_read_time; unix 秒)。
    pub last_read_time: i64,
    /// 是否已读 (is_read)。
    pub is_read: i64,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct MomentFeedContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"sns.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"MomentFeed_<tid>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`MomentFeedRow`] + [`MomentFeedContext`] → [`MomentFeedCreate`] (event_seq 留 0, 后置填)。
///
/// 全直接列映射, `rowid` 是游标不进事件。**infallible**。
#[must_use]
pub fn assemble_moment_feed(row: &MomentFeedRow, ctx: &MomentFeedContext) -> MomentFeedCreate {
    MomentFeedCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::MomentFeedUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        tid: row.tid,
        author: row.author.clone(),
        create_time: row.create_time,
        last_read_time: row.last_read_time,
        is_read: row.is_read,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> MomentFeedContext {
        MomentFeedContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "sns.db".to_string(),
            source_native_id: "MomentFeed_-3652952694686404033".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_maps_columns() {
        let row = MomentFeedRow {
            rowid: 5,
            tid: -3_652_952_694_686_404_033,
            author: "wxid_ijkl5678mnop901".to_string(),
            create_time: 1_763_557_360,
            last_read_time: 1_779_501_771,
            is_read: 1,
        };
        let mf = assemble_moment_feed(&row, &ctx());
        assert_eq!(mf.tid, -3_652_952_694_686_404_033);
        assert_eq!(mf.author, "wxid_ijkl5678mnop901");
        assert_eq!(mf.create_time, 1_763_557_360);
        assert_eq!(mf.last_read_time, 1_779_501_771);
        assert_eq!(mf.is_read, 1);
        assert_eq!(mf.provenance.event_type, EventType::MomentFeedUpdate);
        assert_eq!(mf.provenance.event_seq, 0);
    }
}
