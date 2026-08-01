//! event::chatroom — chatroom_update 3 个 action 字段集 (ADR-412 §3.x.3/4/5).
//!
//! 本 mod = PR2-3-f: [`ChatroomCreate`] (create) / [`ChatroomMemberAdd`] (member_add) /
//! [`ChatroomMemberRemove`] (member_remove) — 同源 chatroom_update 三态, 共享 chatroom_id (id 类).
//! 照 [`super::message`] / [`super::contact`] 模板 (嵌 [`Provenance`] + to_payload_json + 手写 Debug + 不 derive Serialize).
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** 脱敏 chatroom_id / member_wxid / owner_wxid /
//!   chatroom_name / announcement / display_name (经 [`sha8`], Option 也脱敏).
//!
//! ## 新增渲染点
//! - owner_wxid 是 **nullable id 类** — 经 [`render_opt_field`] Id (None → `owner_wxid_sha`=null 无 _len).
//! - joined_at / left_at 是 **nullable 元数据 i64** — 直塞 `map_or(Null, ..)` (天然非敏感).
//! - member_add/remove 的 source_native_id = `md5_hex(chatroom_id_sha + ':member:' + member_wxid_sha)`
//!   (调用方用 **sha 值** 合成, 不用裸 wxid, plaintext 不变) — 仍走 Provenance 例外原样直塞.

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, render_opt_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// log 脱敏 — Option 敏感字段在手写 Debug 里转 sha8 (None 保持 None).
fn opt_sha8(o: Option<&str>) -> Option<String> {
    o.map(|s| sha8(s.as_bytes()))
}

/// (chatroom_update, create) 字段集 (ADR-412 §3.x.3) — 群信息.
///
/// 归桶: chatroom_id / owner_wxid = **id 类** (owner nullable); chatroom_name / announcement =
/// **display_name 类** (announcement nullable); member_count = **元数据类**. text_content 无.
pub struct ChatroomCreate {
    /// 共享溯源头 (source_native_id = `"Chatroom_<md5_hex(chatroom_id)>"`).
    pub provenance: Provenance,
    /// 群 id raw `xxxxxxxx@chatroom` (id 类: 默认 chatroom_id_sha).
    pub chatroom_id: String,
    /// 群名 (display_name 类: 默认 chatroom_name_sha + chatroom_name_len).
    pub chatroom_name: String,
    /// 群公告 (display_name 类, nullable).
    pub announcement: Option<String>,
    /// 群备注 我给群的私人备注 (display_name 类, nullable; contact.remark; **只进 L2 chatroom,
    /// 不进 payload/digest** — 私人可变标注, 同批G/H L2-only 先例, 不动冻结 ChatroomUpdate schema; Debug 只露长度)。
    pub chatroom_remark: Option<String>,
    /// 群主 wxid (id 类, nullable — 已解散群可能没).
    pub owner_wxid: Option<String>,
    /// 群成员数 (元数据).
    pub member_count: i64,
    /// 群公告编辑者 wxid (批H; id 类, nullable; chat_room_info_detail.announcement_editor_;
    /// **只进 L2 chatroom, 不进 payload/digest**; Debug sha8)。
    pub announcement_editor: Option<String>,
    /// 群公告发布时间秒 (批H; 元数据; chat_room_info_detail.announcement_publish_time_; 无公告 0;
    /// **只进 L2 chatroom, 不进 payload/digest**)。
    pub announcement_publish_time: i64,
    /// 富媒体群公告 XML (ADR-460 KI-A; content 类, nullable; chat_room_info_detail.xml_announcement_;
    /// **只进 L2 chatroom, 不进 payload/digest**; Debug 只露长度)。
    pub xml_announcement: Option<String>,
    /// 群状态位 (ADR-460 KI-B; 元数据; chat_room_info_detail.chat_room_status_; 语义待确认, 原值落库;
    /// **只进 L2 chatroom, 不进 payload/digest**; Debug 整数直露)。
    pub chat_room_status: i64,
    /// 我是否仍在此群 (ADR-493; 派生自 ext_buffer roster 是否含账号 wxid; 元数据 bool; **只进 L2, 不进
    /// payload/digest**; Debug 直露)。`true`=在群/解析不确定(保守), `false`=Complete roster 确认无自身=已退。
    pub is_still_member: bool,
}

impl ChatroomCreate {
    /// 渲染 chatroom_update.create payload_json (§3.x.3 + §3.y, 唯一出口).
    ///
    /// 批H: announcement_editor / announcement_publish_time **不进 payload** (L2-only, 同 role/invited_by)。
    /// ADR-460 KI-A/B: xml_announcement / chat_room_status 同为 L2-only, **不进 payload**。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        render_field(&mut out, "chatroom_id", &self.chatroom_id, FieldCategory::Id, mode);
        render_field(
            &mut out,
            "chatroom_name",
            &self.chatroom_name,
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "announcement",
            self.announcement.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "owner_wxid",
            self.owner_wxid.as_deref(),
            FieldCategory::Id,
            mode,
        );
        out.insert("member_count".to_string(), Value::from(self.member_count));
        Value::Object(out)
    }
}

impl fmt::Debug for ChatroomCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatroomCreate")
            .field("provenance", &self.provenance)
            .field("chatroom_id_sha8", &sha8(self.chatroom_id.as_bytes()))
            .field("chatroom_name_len", &self.chatroom_name.chars().count())
            // codex 批H P1: 群名/公告/备注是 display/content 类 → Debug 只露长度 (不 hash, 同 ChatroomRawRow/V3Chatroom
            // 的 _len 惯例; announcement/remark 填真实文本, hash 短内容可能被反推 → 保守只 len)。
            .field("announcement_len", &self.announcement.as_deref().map_or(0, |s| s.chars().count()))
            .field("chatroom_remark_len", &self.chatroom_remark.as_deref().map_or(0, |s| s.chars().count()))
            .field("owner_wxid_sha8", &opt_sha8(self.owner_wxid.as_deref()))
            .field("member_count", &self.member_count)
            .field("announcement_editor_sha8", &opt_sha8(self.announcement_editor.as_deref()))
            .field("announcement_publish_time", &self.announcement_publish_time)
            // ADR-460 KI-A: xml_announcement 是富媒体公告内容 → Debug 只露长度 (不 hash, 同 announcement/remark)。
            .field("xml_announcement_len", &self.xml_announcement.as_deref().map_or(0, |s| s.chars().count()))
            .field("chat_room_status", &self.chat_room_status)
            .field("is_still_member", &self.is_still_member)
            .finish()
    }
}

/// (chatroom_update, member_add) 字段集 (ADR-412 §3.x.4) — 群成员加入.
///
/// 归桶: chatroom_id / member_wxid = **id 类**; display_name (群内自定义昵称) = **display_name 类** (nullable);
/// joined_at = **元数据类** (nullable).
pub struct ChatroomMemberAdd {
    /// 共享溯源头 (source_native_id = `md5_hex(chatroom_id_sha + ':member:' + member_wxid_sha)`).
    pub provenance: Provenance,
    /// 群 id raw (id 类).
    pub chatroom_id: String,
    /// 成员 wxid raw (id 类).
    pub member_wxid: String,
    /// 群昵称 群内自定义 (display_name 类, nullable).
    pub display_name: Option<String>,
    /// 加入时间毫秒 (元数据, nullable — ext_buffer fallback).
    pub joined_at: Option<i64>,
    /// 成员角色 (第八批; `"owner"` / `"admin"` / `"member"`; **只进 L2 chatroom_member, 不进 payload/digest**)。
    /// owner = username==chat_room.owner; admin = ext_buffer field3 flags & 2048; 其余 member。
    pub role: String,
    /// 邀请人 wxid (第九批; id 类, nullable; 谁拉此成员进群; **只进 L2 chatroom_member, 不进 payload/digest**; Debug sha8)。
    pub invited_by: Option<String>,
}

impl ChatroomMemberAdd {
    /// 渲染 chatroom_update.member_add payload_json (§3.x.4 + §3.y, 唯一出口).
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        render_field(&mut out, "chatroom_id", &self.chatroom_id, FieldCategory::Id, mode);
        render_field(&mut out, "member_wxid", &self.member_wxid, FieldCategory::Id, mode);
        render_opt_field(
            &mut out,
            "display_name",
            self.display_name.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        out.insert("joined_at".to_string(), self.joined_at.map_or(Value::Null, Value::from));
        // 第八/九批 role / invited_by **不进 payload_json** (L2-only, 只入 chatroom_member; 同联系人第五/七批属性)。
        Value::Object(out)
    }
}

impl fmt::Debug for ChatroomMemberAdd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatroomMemberAdd")
            .field("provenance", &self.provenance)
            .field("chatroom_id_sha8", &sha8(self.chatroom_id.as_bytes()))
            .field("member_wxid_sha8", &sha8(self.member_wxid.as_bytes()))
            .field("display_name_sha8", &opt_sha8(self.display_name.as_deref()))
            .field("joined_at", &self.joined_at)
            .field("role", &self.role)
            .field("invited_by_sha8", &opt_sha8(self.invited_by.as_deref()))
            .finish()
    }
}

/// (chatroom_update, member_remove) 字段集 (ADR-412 §3.x.5) — 群成员移除.
///
/// 归桶: chatroom_id / member_wxid = **id 类**; left_at = **元数据类** (nullable).
/// (无 display_name 类 — 移除事件不带群昵称.)
pub struct ChatroomMemberRemove {
    /// 共享溯源头 (source_native_id = `md5_hex(chatroom_id_sha + ':member:' + member_wxid_sha)`).
    pub provenance: Provenance,
    /// 群 id raw (id 类).
    pub chatroom_id: String,
    /// 成员 wxid raw (id 类).
    pub member_wxid: String,
    /// 退出时间毫秒 (元数据, nullable — ext_buffer).
    pub left_at: Option<i64>,
}

impl ChatroomMemberRemove {
    /// 渲染 chatroom_update.member_remove payload_json (§3.x.5 + §3.y, 唯一出口).
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        render_field(&mut out, "chatroom_id", &self.chatroom_id, FieldCategory::Id, mode);
        render_field(&mut out, "member_wxid", &self.member_wxid, FieldCategory::Id, mode);
        out.insert("left_at".to_string(), self.left_at.map_or(Value::Null, Value::from));
        Value::Object(out)
    }
}

impl fmt::Debug for ChatroomMemberRemove {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatroomMemberRemove")
            .field("provenance", &self.provenance)
            .field("chatroom_id_sha8", &sha8(self.chatroom_id.as_bytes()))
            .field("member_wxid_sha8", &sha8(self.member_wxid.as_bytes()))
            .field("left_at", &self.left_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn prov(action: EventAction) -> Provenance {
        Provenance {
            account_id: Wxid::try_new("wxid_acct_001").unwrap(),
            source: "chatroom.db".to_string(),
            source_native_id: "Chatroom_a1b2c3d4".to_string(),
            event_type: EventType::ChatroomUpdate,
            event_action: action,
            event_seq: 9,
            ingest_time: 1_700_000_000_000,
        }
    }

    fn create_sample() -> ChatroomCreate {
        ChatroomCreate {
            is_still_member: true,
            provenance: prov(EventAction::Create),
            chatroom_id: "12345678@chatroom".to_string(),
            chatroom_name: "技术交流群".to_string(),
            chatroom_remark: Some("私密群备注".to_string()),
            announcement: Some("禁止广告".to_string()),
            owner_wxid: Some("wxid_owner_003".to_string()),
            member_count: 88,
            announcement_editor: Some("wxid_editor_003".to_string()),
            announcement_publish_time: 1_700_000_000,
            xml_announcement: Some("<xml>富媒体公告</xml>".to_string()),
            chat_room_status: 0x80000,
        }
    }

    /// create 默认: chatroom_id/owner_wxid id 类 _sha; name/announcement display _sha+_len; member_count 照原.
    #[test]
    fn create_default_redacts() {
        let o = create_sample().to_payload_json(PrivacyMode::default_sha());
        let o = o.as_object().unwrap();
        assert_eq!(o["chatroom_id_sha"], Value::from(sha256_hex("12345678@chatroom")));
        assert_eq!(o["chatroom_name_sha"], Value::from(sha256_hex("技术交流群")));
        assert_eq!(o["chatroom_name_len"], Value::from(5_i64));
        assert_eq!(o["announcement_sha"], Value::from(sha256_hex("禁止广告")));
        assert_eq!(o["announcement_len"], Value::from(4_i64));
        assert_eq!(o["owner_wxid_sha"], Value::from(sha256_hex("wxid_owner_003")));
        assert!(!o.contains_key("owner_wxid_len"), "id 类 owner_wxid 无 _len");
        assert_eq!(o["member_count"], Value::from(88));
        for k in ["chatroom_id", "chatroom_name", "owner_wxid", "announcement"] {
            assert!(!o.contains_key(k), "K-R4: 默认不准出裸 {k}");
        }
        // 批H: 公告编辑者/发布时间 L2-only, 不进 payload (任何形态)。
        // ADR-460 KI-A/B: 富媒体公告 xml_announcement / 群状态位 chat_room_status 同 L2-only, 不进 payload。
        for k in [
            "announcement_editor",
            "announcement_editor_sha",
            "announcement_publish_time",
            "xml_announcement",
            "xml_announcement_sha",
            "chat_room_status",
        ] {
            assert!(!o.contains_key(k), "L2-only: {k} 不进 payload");
        }
    }

    /// create owner_wxid None → owner_wxid_sha null 占位 (nullable id).
    #[test]
    fn create_null_owner_and_announcement() {
        let mut c = create_sample();
        c.owner_wxid = None;
        c.announcement = None;
        let o = c.to_payload_json(PrivacyMode::default_sha());
        let o = o.as_object().unwrap();
        assert_eq!(o["owner_wxid_sha"], Value::Null);
        assert_eq!(o["announcement_sha"], Value::Null);
        assert_eq!(o["announcement_len"], Value::Null);
    }

    /// create --enable-display-name 只开 display, chatroom_id/owner_wxid (id) 仍 sha (§3.y.5).
    #[test]
    fn create_display_switch_not_id() {
        let o = create_sample().to_payload_json(PrivacyMode {
            enable_display_name: true,
            ..Default::default()
        });
        let o = o.as_object().unwrap();
        assert_eq!(o["chatroom_name"], Value::from("技术交流群"));
        assert_eq!(o["announcement"], Value::from("禁止广告"));
        assert!(o.contains_key("chatroom_id_sha"), "id 不受 display 开关");
        assert!(o.contains_key("owner_wxid_sha"), "owner id 不受 display 开关");
    }

    /// member_add 默认: chatroom_id/member_wxid id 类; display_name display nullable; joined_at 直塞.
    #[test]
    fn member_add_default() {
        let m = ChatroomMemberAdd {
            provenance: prov(EventAction::MemberAdd),
            chatroom_id: "12345678@chatroom".to_string(),
            member_wxid: "wxid_member_004".to_string(),
            display_name: Some("阿强".to_string()),
            joined_at: Some(1_699_000_000_000),
            role: "admin".to_string(),
            invited_by: Some("wxid_inviter_x".to_string()),
        };
        let o = m.to_payload_json(PrivacyMode::default_sha());
        let o = o.as_object().unwrap();
        assert_eq!(o["chatroom_id_sha"], Value::from(sha256_hex("12345678@chatroom")));
        assert_eq!(o["member_wxid_sha"], Value::from(sha256_hex("wxid_member_004")));
        assert_eq!(o["display_name_sha"], Value::from(sha256_hex("阿强")));
        assert_eq!(o["display_name_len"], Value::from(2_i64));
        assert_eq!(o["joined_at"], Value::from(1_699_000_000_000_i64));
        assert!(!o.contains_key("member_wxid"));
        assert!(!o.contains_key("role"), "第八批 role 不进 payload (L2-only)");
        assert!(
            !o.contains_key("invited_by"),
            "第九批 invited_by 不进 payload (L2-only)"
        );
    }

    /// member_add display_name None + joined_at None → null.
    #[test]
    fn member_add_nulls() {
        let m = ChatroomMemberAdd {
            provenance: prov(EventAction::MemberAdd),
            chatroom_id: "12345678@chatroom".to_string(),
            member_wxid: "wxid_member_004".to_string(),
            display_name: None,
            joined_at: None,
            role: "member".to_string(),
            invited_by: None,
        };
        let o = m.to_payload_json(PrivacyMode::default_sha());
        let o = o.as_object().unwrap();
        assert_eq!(o["display_name_sha"], Value::Null);
        assert_eq!(o["display_name_len"], Value::Null);
        assert_eq!(o["joined_at"], Value::Null);
    }

    /// member_remove 默认: id 类脱敏; left_at None → null.
    #[test]
    fn member_remove_default_and_null() {
        let m = ChatroomMemberRemove {
            provenance: prov(EventAction::MemberRemove),
            chatroom_id: "12345678@chatroom".to_string(),
            member_wxid: "wxid_member_004".to_string(),
            left_at: None,
        };
        let o = m.to_payload_json(PrivacyMode::default_sha());
        let o = o.as_object().unwrap();
        assert_eq!(o["chatroom_id_sha"], Value::from(sha256_hex("12345678@chatroom")));
        assert_eq!(o["member_wxid_sha"], Value::from(sha256_hex("wxid_member_004")));
        assert_eq!(o["left_at"], Value::Null);
        assert!(!o.contains_key("member_wxid"));
    }

    /// K-R4: 三态 (create/member_add/member_remove) 默认模式 payload + 手写 Debug 都不泄裸敏感值.
    #[test]
    fn k_r4_no_leak_all_three() {
        let def = PrivacyMode::default_sha();
        let add = ChatroomMemberAdd {
            provenance: prov(EventAction::MemberAdd),
            chatroom_id: "12345678@chatroom".to_string(),
            member_wxid: "wxid_member_004".to_string(),
            display_name: Some("阿强".to_string()),
            joined_at: None,
            role: "owner".to_string(),
            invited_by: None,
        };
        let remove = ChatroomMemberRemove {
            provenance: prov(EventAction::MemberRemove),
            chatroom_id: "12345678@chatroom".to_string(),
            member_wxid: "wxid_member_004".to_string(),
            left_at: None,
        };
        // payload 裸值扫描 — 三态 (统一 .to_string() 风格).
        let dumped_create = create_sample().to_payload_json(def).to_string();
        let dumped_add = add.to_payload_json(def).to_string();
        let dumped_remove = remove.to_payload_json(def).to_string();
        for raw in ["12345678@chatroom", "技术交流群", "禁止广告", "wxid_owner_003"] {
            assert!(!dumped_create.contains(raw), "K-R4: create payload 泄 {raw}");
        }
        for raw in ["12345678@chatroom", "wxid_member_004", "阿强"] {
            assert!(!dumped_add.contains(raw), "K-R4: member_add payload 泄 {raw}");
        }
        for raw in ["12345678@chatroom", "wxid_member_004"] {
            assert!(!dumped_remove.contains(raw), "K-R4: member_remove payload 泄 {raw}");
        }
        // Debug 脱敏 — 三态.
        let dbg_create = format!("{:?}", create_sample());
        for raw in [
            "12345678@chatroom",
            "技术交流群",
            "禁止广告",
            "私密群备注",
            "富媒体公告",
            "wxid_owner_003",
            "wxid_acct_001",
        ] {
            assert!(!dbg_create.contains(raw), "Debug create 泄 {raw}");
        }
        assert!(!format!("{add:?}").contains("阿强"), "Debug add 泄 display_name");
        for raw in ["12345678@chatroom", "wxid_member_004"] {
            assert!(!format!("{remove:?}").contains(raw), "Debug remove 泄 {raw}");
        }
    }
}
