//! chat_room row 组装 — 解密明文 chat_room 表行 → [`ChatroomCreate`] 事件 (ADR-412 §3.x.3).
//!
//! [`assemble_chatroom`] 把一条真实 chat_room 行 (+ contact join 预备的群名) 映射成 [`ChatroomCreate`].
//! **无 decode/无 sender 解析** — chat_room 字段都是明文列, chatroom_id 是 String (非 Wxid) → 本函数
//! **infallible** (无 Result). event_seq 留 0 (compute_event_seq 后置填). 跟 [`super::contact`] 同模式.
//!
//! ## 真实 schema (v4 `chat_room` 表 + `contact` join)
//! - chat_room: chatroom_id (主键 `xxx@chatroom`) / owner (群主 UserName, 可空串) / RoomData (proto, 群成员).
//! - 群名: chat_room 表本身**不存**显示名 → 调用方从 `contact.nick_name where username=chatroom_id` join 取
//!   (缺/无对应 contact 行 → 空串). 群公告 announcement 由调用方从对应来源预备 (可空).
//! - member_count: 调用方从 RoomData proto 解出的成员数 (或 0).

use crate::event::chatroom::ChatroomCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 解密明文 chat_room 表行 (调用方从 cipher 解密的 db SELECT + contact join 预备).
pub struct ChatroomRow {
    /// 群 id (chat_room.chatroom_id; `xxxxxxxx@chatroom`).
    pub chatroom_id: String,
    /// 群名 (调用方从 `contact.nick_name where username=chatroom_id` join; 缺 → 空串).
    pub chatroom_name: Option<String>,
    /// 群备注 (我给群的私人备注; 调用方从 `contact.remark where username=chatroom_id` join; 未设 → None).
    pub chatroom_remark: Option<String>,
    /// 群公告 (调用方预备; 可空).
    pub announcement: Option<String>,
    /// 群主 wxid (chat_room.owner; 空串 → None).
    pub owner_wxid: Option<String>,
    /// 群成员数 (调用方从 RoomData proto 解出, 或 0; 元数据, 不解释).
    pub member_count: i64,
    /// 群公告编辑者 wxid (批H; 调用方从 chat_room_info_detail.announcement_editor_ join; 空串 → None)。
    pub announcement_editor: Option<String>,
    /// 群公告发布时间秒 (批H; chat_room_info_detail.announcement_publish_time_; 无 → 0)。
    pub announcement_publish_time: i64,
    /// 富媒体群公告 XML (ADR-460 KI-A; chat_room_info_detail.xml_announcement_; 空串 → None)。
    pub xml_announcement: Option<String>,
    /// 群状态位 (ADR-460 KI-B; chat_room_info_detail.chat_room_status_; 语义待确认, 无 → 0)。
    pub chat_room_status: i64,
    /// 我是否仍在此群 (ADR-493; 派生: 账号 wxid 在不在该群 ext_buffer roster; pipeline 算好传入)。
    /// `true` = 在群 / 解析不确定 (保守); `false` = Complete roster 确认无自身 = 已退。**L2-only 不进 digest**。
    pub is_still_member: bool,
}

/// 装配上下文 — 调用方 (adapter) 按 db 预备.
pub struct ChatroomContext {
    /// 数据所属账号 UserName.
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"chat_room.db"`).
    pub source: String,
    /// 复合 md5 锚点 (调用方用 [`super::chatroom_anchor`] 预合成 `"Chatroom_<md5_hex(chatroom_id)>"`;
    /// → `provenance.source_native_id`).
    pub source_native_id: String,
    /// 摄取时刻 (毫秒).
    pub ingest_time: i64,
}

/// 组装一条 [`ChatroomRow`] + [`ChatroomContext`] → [`ChatroomCreate`] (event_seq 留 0, 后置填).
///
/// 纯字段映射 (无 decode/sender 解析). 空串 announcement/owner_wxid → `None` (= 未设); chatroom_name
/// 缺/空串 → 空串 (ChatroomCreate.chatroom_name 非 Option). member_count 直映. 不 log. **infallible**.
#[must_use]
pub fn assemble_chatroom(row: &ChatroomRow, ctx: &ChatroomContext) -> ChatroomCreate {
    // 空串 → None (= 未设公告/群主), 跟 ChatroomCreate 的 nullable 语义一致.
    ChatroomCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::ChatroomUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        chatroom_id: row.chatroom_id.clone(),
        chatroom_name: row.chatroom_name.clone().unwrap_or_default(),
        chatroom_remark: super::non_empty(&row.chatroom_remark),
        announcement: super::non_empty(&row.announcement),
        owner_wxid: super::non_empty(&row.owner_wxid),
        member_count: row.member_count,
        announcement_editor: super::non_empty(&row.announcement_editor),
        announcement_publish_time: row.announcement_publish_time,
        xml_announcement: super::non_empty(&row.xml_announcement),
        chat_room_status: row.chat_room_status,
        is_still_member: row.is_still_member,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ChatroomContext {
        ChatroomContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "chat_room.db".to_string(),
            source_native_id: "Chatroom_a1b2c3d4".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    fn row(chatroom_id: &str, name: Option<&str>, announcement: Option<&str>, owner: Option<&str>) -> ChatroomRow {
        ChatroomRow {
            chatroom_id: chatroom_id.to_string(),
            chatroom_name: name.map(str::to_string),
            is_still_member: true,
            chatroom_remark: None,
            announcement: announcement.map(str::to_string),
            owner_wxid: owner.map(str::to_string),
            member_count: 0,
            announcement_editor: None,
            announcement_publish_time: 0,
            xml_announcement: None,
            chat_room_status: 0,
        }
    }

    /// 全字段填: chatroom_id/name/announcement/owner 直映 + provenance 装配 + event_seq 占位.
    #[test]
    fn full_chatroom_maps_all() {
        let mut r = row(
            "12345678@chatroom",
            Some("技术交流群"),
            Some("禁止广告"),
            Some("wxid_owner_003"),
        );
        r.member_count = 88;
        r.chatroom_remark = Some("我的群备注".to_string());
        r.announcement_editor = Some("wxid_editor_x".to_string());
        r.announcement_publish_time = 1_700_000_000;
        r.xml_announcement = Some("<xml>富媒体公告</xml>".to_string());
        r.chat_room_status = 0x80000;
        let c = assemble_chatroom(&r, &ctx());
        assert_eq!(c.chatroom_id, "12345678@chatroom");
        assert_eq!(c.chatroom_name, "技术交流群");
        assert_eq!(c.chatroom_remark.as_deref(), Some("我的群备注"), "群备注映射");
        assert_eq!(c.announcement.as_deref(), Some("禁止广告"));
        assert_eq!(c.owner_wxid.as_deref(), Some("wxid_owner_003"));
        assert_eq!(c.member_count, 88);
        assert_eq!(
            c.announcement_editor.as_deref(),
            Some("wxid_editor_x"),
            "批H 编辑者映射"
        );
        assert_eq!(c.announcement_publish_time, 1_700_000_000, "批H 发布时间映射");
        assert_eq!(
            c.xml_announcement.as_deref(),
            Some("<xml>富媒体公告</xml>"),
            "KI-A 富媒体公告映射"
        );
        assert_eq!(c.chat_room_status, 0x80000, "KI-B 群状态位映射");
        assert_eq!(c.provenance.event_type, EventType::ChatroomUpdate);
        assert_eq!(c.provenance.event_action, EventAction::Create);
        assert_eq!(c.provenance.source, "chat_room.db");
        assert_eq!(c.provenance.source_native_id, "Chatroom_a1b2c3d4");
        assert_eq!(c.provenance.ingest_time, 1_700_000_000_000);
        assert_eq!(c.provenance.event_seq, 0, "event_seq 占位");
    }

    /// 自定义号群主 owner (无 wxid_, e.g. 自定义微信号) — owner_wxid 是 String 不卡格式.
    #[test]
    fn custom_id_owner_ok() {
        let c = assemble_chatroom(&row("99@chatroom", Some("群"), None, Some("custom_no_prefix")), &ctx());
        assert_eq!(c.owner_wxid.as_deref(), Some("custom_no_prefix"));
    }

    /// @chatroom 群 id owner 是另一个 @chatroom (理论值) — 仍原样直映 (decoder 不判语义).
    #[test]
    fn at_chatroom_owner_passthrough() {
        let c = assemble_chatroom(&row("99@chatroom", Some("群"), None, Some("888@chatroom")), &ctx());
        assert_eq!(c.owner_wxid.as_deref(), Some("888@chatroom"));
    }

    /// 空串 announcement/owner/xml_announcement → None (= 未设).
    #[test]
    fn empty_optionals_become_none() {
        let mut r = row("r@chatroom", Some("群"), Some(""), Some(""));
        r.xml_announcement = Some(String::new());
        let c = assemble_chatroom(&r, &ctx());
        assert_eq!(c.announcement, None, "空 announcement → None");
        assert_eq!(c.owner_wxid, None, "空 owner → None");
        assert_eq!(c.xml_announcement, None, "空 xml_announcement → None");
    }

    /// None announcement/owner → None.
    #[test]
    fn none_optionals_stay_none() {
        let c = assemble_chatroom(&row("r@chatroom", Some("群"), None, None), &ctx());
        assert_eq!(c.announcement, None);
        assert_eq!(c.owner_wxid, None);
    }

    /// 群名缺 (contact join 无对应行) → 空串 (chatroom_name 非 Option).
    #[test]
    fn missing_name_becomes_empty() {
        let c = assemble_chatroom(&row("r@chatroom", None, None, None), &ctx());
        assert_eq!(c.chatroom_name, "", "群名缺 → 空串 (非 Option)");
    }

    /// 群名空串 → 空串 (unwrap_or_default 兜底, 与缺等价).
    #[test]
    fn empty_name_becomes_empty() {
        let c = assemble_chatroom(&row("r@chatroom", Some(""), None, None), &ctx());
        assert_eq!(c.chatroom_name, "");
    }

    /// member_count 标量直映 (含 0 / 大值, 不解释).
    #[test]
    fn member_count_maps() {
        let mut r = row("r@chatroom", Some("群"), None, None);
        r.member_count = 500;
        assert_eq!(assemble_chatroom(&r, &ctx()).member_count, 500);

        r.member_count = 0;
        assert_eq!(assemble_chatroom(&r, &ctx()).member_count, 0);

        r.member_count = i64::MAX;
        assert_eq!(assemble_chatroom(&r, &ctx()).member_count, i64::MAX);
    }
}
