//! sns_notify row 组装 — 明文 `SnsMessage_tmp3` 行 → [`SnsNotifyCreate`] 事件 (一条朋友圈互动通知)。
//!
//! [`assemble_sns_notify`] 把一条 `SnsMessage_tmp3` 行 (直接列, 无 proto/XML) 映射成 [`SnsNotifyCreate`]。
//! event_seq 留 0。仿 [`super::moment_feed`] (直接列专表 → alpha 事件; 结构完全同型)。
//!
//! ## 真实 schema (sns.db `SnsMessage_tmp3`, 消费列; inspect 加密原库坐实, 688 行)
//! comment_id (通知 id = 锚点/身份) / feed_id (哪条动态 tid) / type (1赞/2评论/4其它) /
//! from_username (谁互动我 wxid) / create_time (互动秒) / from_nickname / to_username (回复对象) /
//! to_nickname / content (评论文本) / is_unread / del_status / is_relative_me。表名 `SnsMessage_tmp3`。

use crate::event::provenance::Provenance;
use crate::event::sns_notify::SnsNotifyCreate;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `SnsMessage_tmp3` 行 (drain 原始行; 全直接列, assemble 直接映射)。
pub struct SnsNotifyRow {
    /// SnsMessage_tmp3 rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 通知稳定 id (comment_id; 锚点 + 身份)。
    pub comment_id: i64,
    /// 哪条动态 (feed_id = 动态 tid)。
    pub feed_id: i64,
    /// 通知类型 (type; 1赞/2评论/4其它)。
    pub notify_type: i64,
    /// 谁互动我 wxid (from_username)。
    pub from_user: String,
    /// 互动时刻 (create_time; unix 秒)。
    pub create_time: i64,
    /// 互动者缓存昵称 (from_nickname; nullable)。
    pub from_nickname: Option<String>,
    /// 回复对象 wxid (to_username; nullable)。
    pub to_user: Option<String>,
    /// 回复对象缓存昵称 (to_nickname; nullable)。
    pub to_nickname: Option<String>,
    /// 评论文本 (content; nullable; 空串→None)。
    pub content: Option<String>,
    /// 是否未读 (is_unread)。
    pub is_unread: i64,
    /// 删除状态 (del_status)。
    pub del_status: i64,
    /// 是否与我相关 (is_relative_me)。
    pub is_relative_me: i64,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct SnsNotifyContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"sns.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"SnsNotify_<local_id>"` = 行唯一 id, **非 comment_id**[不唯一]; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`SnsNotifyRow`] + [`SnsNotifyContext`] → [`SnsNotifyCreate`] (event_seq 留 0, 后置填)。
///
/// 全直接列映射, `rowid` 是游标不进事件。**infallible**。
#[must_use]
pub fn assemble_sns_notify(row: &SnsNotifyRow, ctx: &SnsNotifyContext) -> SnsNotifyCreate {
    SnsNotifyCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::SnsNotifyUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        comment_id: row.comment_id,
        feed_id: row.feed_id,
        notify_type: row.notify_type,
        from_user: row.from_user.clone(),
        create_time: row.create_time,
        from_nickname: row.from_nickname.clone(),
        to_user: row.to_user.clone(),
        to_nickname: row.to_nickname.clone(),
        content: row.content.clone(),
        is_unread: row.is_unread,
        del_status: row.del_status,
        is_relative_me: row.is_relative_me,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SnsNotifyContext {
        SnsNotifyContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "sns.db".to_string(),
            source_native_id: "SnsNotify_123456789".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_maps_columns() {
        let row = SnsNotifyRow {
            rowid: 5,
            comment_id: 123_456_789,
            feed_id: -3_652_952_694_686_404_033,
            notify_type: 2,
            from_user: "wxid_ijkl5678mnop901".to_string(),
            create_time: 1_763_557_360,
            from_nickname: Some("小明昵称".to_string()),
            to_user: Some("wxid_reply_target".to_string()),
            to_nickname: None,
            content: Some("评论正文".to_string()),
            is_unread: 0,
            del_status: 0,
            is_relative_me: 0,
        };
        let sn = assemble_sns_notify(&row, &ctx());
        assert_eq!(sn.comment_id, 123_456_789);
        assert_eq!(sn.feed_id, -3_652_952_694_686_404_033);
        assert_eq!(sn.notify_type, 2);
        assert_eq!(sn.from_user, "wxid_ijkl5678mnop901");
        assert_eq!(sn.create_time, 1_763_557_360);
        assert_eq!(sn.from_nickname.as_deref(), Some("小明昵称"));
        assert_eq!(sn.to_user.as_deref(), Some("wxid_reply_target"));
        assert_eq!(sn.content.as_deref(), Some("评论正文"));
        assert_eq!(sn.provenance.event_type, EventType::SnsNotifyUpdate);
        assert_eq!(sn.provenance.event_seq, 0);
    }
}
