//! event::decoded — [`DecodedEvent`] 统一事件枚举 (15 个 alpha 事件的 sum type).
//!
//! 本 mod = PR2-3-i: 把各事件 struct 包成一个枚举, 作 decoder 输出 + emit 输入的
//! 统一类型. 变体跟 config-events §7.3 的 15 个 (event_type, event_action) 合法组合一一对应
//! (原 7 + session ADR-412 + favorite/favorite_tag ADR-454 + sns ADR-467 + transfer/red_envelope/group_pay ADR-468 + friend_verify ADR-469).
//!
//! ## K-R4
//! - `#[derive(Debug)]` 安全 — 委托各内层 struct 的脱敏 Debug (message/contact/chatroom/error 手写,
//!   cursor 全元数据); **不 derive `Serialize`** (各内层也无, 唯一出口 [`DecodedEvent::to_payload_json`]).

use serde_json::Value;

use super::avatar::AvatarImageCreate;
use super::bizchat::BizChatContactCreate;
use super::chatroom::{ChatroomCreate, ChatroomMemberAdd, ChatroomMemberRemove};
use super::contact::ContactUpdate;
use super::emoticon::CustomEmoticonCreate;
use super::favorite::FavoriteCreate;
use super::favorite_tag::FavoriteTagCreate;
use super::finder::FinderVisitCreate;
use super::friend_verify::FriendVerifyCreate;
use super::group_pay::GroupPayCreate;
use super::message::MessageCreate;
use super::moment_feed::MomentFeedCreate;
use super::privacy::PrivacyMode;
use super::provenance::Provenance;
use super::red_envelope::RedEnvelopeCreate;
use super::session::SessionUpdate;
use super::sns::SnsCreate;
use super::sns_notify::SnsNotifyCreate;
use super::system::{SystemCursorUpdate, SystemError};
use super::transfer::TransferCreate;
use super::{EventAction, EventType};

/// alpha 15 个事件的统一枚举 (跟 config-events §7.3 合法组合 1:1).
///
/// decoder 产出 `DecodedEvent`; emit 层调 [`to_payload_json`](Self::to_payload_json) 出 payload_json,
/// 调 [`event_type`](Self::event_type)/[`event_action`](Self::event_action) 走 alpha 合法组合校验.
// clippy::large_enum_variant: ContactUpdate 变体随字段扩充 (第五/七批 extra_buffer 解出性别/地区等) 偏大。
// alpha 事件**流式逐条处理** (drain→assemble→project→sink 一条一条, 生产无 Vec<DecodedEvent> 批量持有 —
// 唯一 Vec<DecodedEvent> 在测试 all_variants), 大变体不放大内存; box 会 ripple 全 match 臂 (canonical/sink/
// projection)。0.2.0 若改批量持有再评估 Box<ContactUpdate>。
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum DecodedEvent {
    /// (message, create).
    Message(MessageCreate),
    /// (contact_update, create).
    ContactUpdate(ContactUpdate),
    /// (chatroom_update, create).
    ChatroomCreate(ChatroomCreate),
    /// (chatroom_update, member_add).
    ChatroomMemberAdd(ChatroomMemberAdd),
    /// (chatroom_update, member_remove).
    ChatroomMemberRemove(ChatroomMemberRemove),
    /// (session_update, create).
    SessionUpdate(SessionUpdate),
    /// (favorite_update, create).
    FavoriteCreate(FavoriteCreate),
    /// (favorite_tag_update, create).
    FavoriteTagCreate(FavoriteTagCreate),
    /// (sns_event, create) — 朋友圈动态本体 (ADR-467 件1).
    SnsCreate(SnsCreate),
    /// (transfer_update, create) — 转账 (ADR-468).
    TransferCreate(TransferCreate),
    /// (red_envelope_update, create) — 红包 (ADR-468 件2).
    RedEnvelopeCreate(RedEnvelopeCreate),
    /// (group_pay_update, create) — 群收款 (ADR-468 件3).
    GroupPayCreate(GroupPayCreate),
    /// (friend_verify_update, create) — 好友验证/打招呼 (ADR-469).
    FriendVerifyCreate(FriendVerifyCreate),
    /// (finder_visit_update, create) — 视频号主页记录 (ADR-473).
    FinderVisitCreate(FinderVisitCreate),
    /// 朋友圈好友动态索引 (moment_feed_update, create) — sns.db SnsTopItem_1 (ADR-474)。
    MomentFeedCreate(MomentFeedCreate),
    /// 自定义表情 (custom_emoticon_update, create) — emoticon.db kNonStoreEmoticonTable (ADR-478)。
    CustomEmoticonCreate(CustomEmoticonCreate),
    /// 头像图 (avatar_image_update, create) — head_image.db head_image (ADR-481)。
    AvatarImageCreate(AvatarImageCreate),
    /// 朋友圈互动通知 (sns_notify_update, create) — sns.db SnsMessage_tmp3 (照 moment_feed ADR-474)。
    SnsNotifyCreate(SnsNotifyCreate),
    /// 企微品牌号联系人 (biz_chat_contact_update, create) — bizchat.db user_info (ADR-482)。
    BizChatContactCreate(BizChatContactCreate),
    /// (system_event, cursor_update).
    SystemCursorUpdate(SystemCursorUpdate),
    /// (system_event, error).
    SystemError(SystemError),
}

impl DecodedEvent {
    /// 渲染 payload_json (派发到内层 struct 的 `to_payload_json`, 经隐私脱敏关口).
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        match self {
            Self::Message(e) => e.to_payload_json(mode),
            Self::ContactUpdate(e) => e.to_payload_json(mode),
            Self::ChatroomCreate(e) => e.to_payload_json(mode),
            Self::ChatroomMemberAdd(e) => e.to_payload_json(mode),
            Self::ChatroomMemberRemove(e) => e.to_payload_json(mode),
            Self::SessionUpdate(e) => e.to_payload_json(mode),
            Self::FavoriteCreate(e) => e.to_payload_json(mode),
            Self::FavoriteTagCreate(e) => e.to_payload_json(mode),
            Self::SnsCreate(e) => e.to_payload_json(mode),
            Self::TransferCreate(e) => e.to_payload_json(mode),
            Self::RedEnvelopeCreate(e) => e.to_payload_json(mode),
            Self::GroupPayCreate(e) => e.to_payload_json(mode),
            Self::FriendVerifyCreate(e) => e.to_payload_json(mode),
            Self::FinderVisitCreate(e) => e.to_payload_json(mode),
            Self::MomentFeedCreate(e) => e.to_payload_json(mode),
            Self::CustomEmoticonCreate(e) => e.to_payload_json(mode),
            Self::AvatarImageCreate(e) => e.to_payload_json(mode),
            Self::SnsNotifyCreate(e) => e.to_payload_json(mode),
            Self::BizChatContactCreate(e) => e.to_payload_json(mode),
            Self::SystemCursorUpdate(e) => e.to_payload_json(mode),
            Self::SystemError(e) => e.to_payload_json(mode),
        }
    }

    /// 取共享溯源头 (每变体都嵌 [`Provenance`]).
    #[must_use]
    pub fn provenance(&self) -> &Provenance {
        match self {
            Self::Message(e) => &e.provenance,
            Self::ContactUpdate(e) => &e.provenance,
            Self::ChatroomCreate(e) => &e.provenance,
            Self::ChatroomMemberAdd(e) => &e.provenance,
            Self::ChatroomMemberRemove(e) => &e.provenance,
            Self::SessionUpdate(e) => &e.provenance,
            Self::FavoriteCreate(e) => &e.provenance,
            Self::FavoriteTagCreate(e) => &e.provenance,
            Self::SnsCreate(e) => &e.provenance,
            Self::TransferCreate(e) => &e.provenance,
            Self::RedEnvelopeCreate(e) => &e.provenance,
            Self::GroupPayCreate(e) => &e.provenance,
            Self::FriendVerifyCreate(e) => &e.provenance,
            Self::FinderVisitCreate(e) => &e.provenance,
            Self::MomentFeedCreate(e) => &e.provenance,
            Self::CustomEmoticonCreate(e) => &e.provenance,
            Self::AvatarImageCreate(e) => &e.provenance,
            Self::SnsNotifyCreate(e) => &e.provenance,
            Self::BizChatContactCreate(e) => &e.provenance,
            Self::SystemCursorUpdate(e) => &e.provenance,
            Self::SystemError(e) => &e.provenance,
        }
    }

    /// 事件类型 — **变体内在决定** (不依赖 provenance 字段, 防构造时填错).
    #[must_use]
    pub fn event_type(&self) -> EventType {
        match self {
            Self::Message(_) => EventType::Message,
            Self::ContactUpdate(_) => EventType::ContactUpdate,
            Self::ChatroomCreate(_) | Self::ChatroomMemberAdd(_) | Self::ChatroomMemberRemove(_) => {
                EventType::ChatroomUpdate
            }
            Self::SessionUpdate(_) => EventType::SessionUpdate,
            Self::FavoriteCreate(_) => EventType::FavoriteUpdate,
            Self::FavoriteTagCreate(_) => EventType::FavoriteTagUpdate,
            Self::SnsCreate(_) => EventType::SnsEvent,
            Self::TransferCreate(_) => EventType::TransferUpdate,
            Self::RedEnvelopeCreate(_) => EventType::RedEnvelopeUpdate,
            Self::GroupPayCreate(_) => EventType::GroupPayUpdate,
            Self::FriendVerifyCreate(_) => EventType::FriendVerifyUpdate,
            Self::FinderVisitCreate(_) => EventType::FinderVisitUpdate,
            Self::MomentFeedCreate(_) => EventType::MomentFeedUpdate,
            Self::CustomEmoticonCreate(_) => EventType::CustomEmoticonUpdate,
            Self::AvatarImageCreate(_) => EventType::AvatarImageUpdate,
            Self::SnsNotifyCreate(_) => EventType::SnsNotifyUpdate,
            Self::BizChatContactCreate(_) => EventType::BizChatContactUpdate,
            Self::SystemCursorUpdate(_) | Self::SystemError(_) => EventType::SystemEvent,
        }
    }

    /// 事件动作 — **变体内在决定** (不依赖 provenance 字段).
    #[must_use]
    pub fn event_action(&self) -> EventAction {
        match self {
            Self::Message(_)
            | Self::ContactUpdate(_)
            | Self::ChatroomCreate(_)
            | Self::SessionUpdate(_)
            | Self::FavoriteCreate(_)
            | Self::FavoriteTagCreate(_)
            | Self::SnsCreate(_)
            | Self::TransferCreate(_)
            | Self::RedEnvelopeCreate(_)
            | Self::GroupPayCreate(_)
            | Self::FriendVerifyCreate(_)
            | Self::FinderVisitCreate(_)
            | Self::MomentFeedCreate(_)
            | Self::CustomEmoticonCreate(_)
            | Self::AvatarImageCreate(_)
            | Self::SnsNotifyCreate(_)
            | Self::BizChatContactCreate(_) => EventAction::Create,
            Self::ChatroomMemberAdd(_) => EventAction::MemberAdd,
            Self::ChatroomMemberRemove(_) => EventAction::MemberRemove,
            Self::SystemCursorUpdate(_) => EventAction::CursorUpdate,
            Self::SystemError(_) => EventAction::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::provenance::Provenance;
    use super::super::{is_alpha_valid_combo, EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn prov(event_type: EventType, event_action: EventAction) -> Provenance {
        Provenance {
            account_id: Wxid::try_new("wxid_acct_001").unwrap(),
            source: "x.db".to_string(),
            source_native_id: "anchor_x".to_string(),
            event_type,
            event_action,
            event_seq: 1,
            ingest_time: 1_700_000_000_000,
        }
    }

    /// 15 个变体一套样本 (覆盖所有 alpha 事件).
    fn all_variants() -> Vec<DecodedEvent> {
        vec![
            DecodedEvent::Message(MessageCreate {
                provenance: prov(EventType::Message, EventAction::Create),
                server_id: "1".to_string(),
                server_seq: 0,
                origin_source: 0,
                upload_status: 0,
                download_status: 0,
                conv_id: "wxid_a".to_string(),
                sender_wxid: Wxid::try_new("wxid_b").unwrap(),
                create_time: 1,
                sort_seq: 1,
                msg_type: 1,
                msg_sub_type: None,
                msg_type_name: "TEXT".to_string(),
                msg_sub_type_name: None,
                status: 1,
                local_type_raw: 1,
                is_chatroom: false,
                raw_xml_present: false,
                decode_kind: "plain".to_string(),
                text_content: "hi".to_string(),
                msg_source: String::new(),
            }),
            DecodedEvent::ContactUpdate(ContactUpdate {
                provenance: prov(EventType::ContactUpdate, EventAction::Create),
                username: "wxid_c".to_string(),
                nick_name: "n".to_string(),
                remark: None,
                alias: None,
                local_type: 1,
                is_in_chat_room: false,
                quan_pin: None,
                pin_yin_initial: None,
                remark_quan_pin: None,
                remark_pin_yin_initial: None,
                verify_flag: 0,
                delete_flag: 0,
                big_head_url: None,
                small_head_url: None,
                head_img_md5: None,
                description: None,
                flag: 0,
                chat_room_notify: 0,
                chat_room_type: 0,
                sex: 0,
                country: None,
                province: None,
                city: None,
                friend_source: 0,
                signature: None,
                moments_cover_url: None,
                labels: None,
                friend_add_time: None,
                openim_company: None,
                openim_realname: None,
            }),
            DecodedEvent::ChatroomCreate(ChatroomCreate {
                is_still_member: true,
                provenance: prov(EventType::ChatroomUpdate, EventAction::Create),
                chatroom_id: "x@chatroom".to_string(),
                chatroom_name: "g".to_string(),
                chatroom_remark: None,
                announcement: None,
                owner_wxid: None,
                member_count: 1,
                announcement_editor: None,
                announcement_publish_time: 0,
                xml_announcement: None,
                chat_room_status: 0,
            }),
            DecodedEvent::ChatroomMemberAdd(ChatroomMemberAdd {
                provenance: prov(EventType::ChatroomUpdate, EventAction::MemberAdd),
                chatroom_id: "x@chatroom".to_string(),
                member_wxid: "wxid_d".to_string(),
                display_name: None,
                joined_at: None,
                role: "member".to_string(),
                invited_by: None,
            }),
            DecodedEvent::ChatroomMemberRemove(ChatroomMemberRemove {
                provenance: prov(EventType::ChatroomUpdate, EventAction::MemberRemove),
                chatroom_id: "x@chatroom".to_string(),
                member_wxid: "wxid_d".to_string(),
                left_at: None,
            }),
            DecodedEvent::SessionUpdate(super::super::session::SessionUpdate {
                provenance: prov(EventType::SessionUpdate, EventAction::Create),
                username: "wxid_sess".to_string(),
                summary: None,
                last_sender_display_name: None,
                unread_count: 0,
                last_msg_type: 1,
                last_msg_sub_type: 0,
                sort_timestamp: 1,
                session_type: 0,
                is_hidden: 0,
                status: 0,
                draft: None,
                last_msg_sender: None,
                last_timestamp: 0,
                last_clear_unread_timestamp: 0,
                last_msg_locald_id: 0,
                last_msg_ext_type: 0,
                unread_first_msg_srv_id: 0,
            }),
            DecodedEvent::FavoriteCreate(FavoriteCreate {
                provenance: prov(EventType::FavoriteUpdate, EventAction::Create),
                server_id: 1,
                local_id: 1,
                fav_type: 14,
                update_time: 1,
                from_user: "wxid_fav_src".to_string(),
                real_chat_name: None,
                source_id: None,
                content_len: 0,
                note_text: None,
                media: vec![],
            }),
            DecodedEvent::FavoriteTagCreate(FavoriteTagCreate {
                provenance: prov(EventType::FavoriteTagUpdate, EventAction::Create),
                tag_server_id: 1,
                tag_local_id: 1,
                tag_name: "标签".to_string(),
                seq: 1,
                fav_server_id: 1,
                fav_local_id: 1,
                op_code: 1,
            }),
            DecodedEvent::SnsCreate(SnsCreate {
                provenance: prov(EventType::SnsEvent, EventAction::Create),
                tid: -3_518_821_952_372_526_549,
                author: "wxid_sns_author".to_string(),
                create_time: 1_779_546_990,
                moment_type: 1,
                content_desc: "hi".to_string(),
                author_nickname: None,
                source_user: None,
                location_label: None,
                latitude: None,
                longitude: None,
                title: None,
                link_url: None,
                media_count: 0,
                like_count: 0,
                comment_count: 0,
                source_nickname: None,
                is_bidirectional_fan: 0,
                is_rich_text: 0,
                public_user_name: None,
                app_name: None,
                content_len: 0,
                raw_content: String::new(),
            }),
            DecodedEvent::TransferCreate(TransferCreate {
                provenance: prov(EventType::TransferUpdate, EventAction::Create),
                transfer_id: "1000050001202507100225413996557".to_string(),
                transcation_id: "53010001606113202507100928575102".to_string(),
                message_server_id: 6_379_941_610_914_610_151,
                second_message_server_id: 0,
                session_name: "wxid_peer".to_string(),
                pay_sub_type: 2,
                pay_payer: "wxid_peer".to_string(),
                pay_receiver: "wxid_me".to_string(),
                begin_transfer_time: 1_752_162_563,
                last_modified_time: 1_752_162_564,
                invalid_time: 1_752_248_963,
                last_update_time: 1_752_217_991,
                delay_confirm_flag: 0,
                bubble_clicked_flag: 0,
            }),
            DecodedEvent::RedEnvelopeCreate(RedEnvelopeCreate {
                provenance: prov(EventType::RedEnvelopeUpdate, EventAction::Create),
                send_id: "1000039801202604206261068705009".to_string(),
                message_server_id: 461_510_149_866_340,
                session_name: "grp@chatroom".to_string(),
                sender_user_name: "wxid_sender".to_string(),
                native_url: "wxpay://x?sendusername=wxid_sender".to_string(),
                scene_id: 1002,
                hb_status: 1,
                hb_type: 0,
                receive_status: 0,
            }),
            DecodedEvent::GroupPayCreate(GroupPayCreate {
                provenance: prov(EventType::GroupPayUpdate, EventAction::Create),
                bill_no: "694a900673c1395568318fac8f11e4e2".to_string(),
                session_name: "grp@chatroom".to_string(),
                message_local_id: 38,
                message_create_time: 1_767_141_814,
            }),
            DecodedEvent::FriendVerifyCreate(FriendVerifyCreate {
                provenance: prov(EventType::FriendVerifyUpdate, EventAction::Create),
                user_name: "wxid_friend".to_string(),
                friend_type: 37,
                timestamp: 1_752_217_142,
                is_sender: 0,
                scene: 14,
                content: "你好".to_string(),
            }),
            DecodedEvent::FinderVisitCreate(FinderVisitCreate {
                provenance: prov(EventType::FinderVisitUpdate, EventAction::Create),
                owner_username: "wxid_qrst2345uvwx678".to_string(),
                name: "小应5899".to_string(),
                visit_time: 1_752_221_077,
                profile_url: "https://channels.weixin.qq.com/x".to_string(),
            }),
            DecodedEvent::MomentFeedCreate(MomentFeedCreate {
                provenance: prov(EventType::MomentFeedUpdate, EventAction::Create),
                tid: -3_652_952_694_686_404_033,
                author: "wxid_ijkl5678mnop901".to_string(),
                create_time: 1_763_557_360,
                last_read_time: 1_779_501_771,
                is_read: 1,
            }),
            DecodedEvent::CustomEmoticonCreate(CustomEmoticonCreate {
                provenance: prov(EventType::CustomEmoticonUpdate, EventAction::Create),
                md5: "c0c5d9625338df85".to_string(),
                emoticon_type: 1,
                caption: "微笑".to_string(),
                product_id: "p".to_string(),
                aes_key: "k".to_string(),
                cdn_url: "http://x".to_string(),
                thumb_url: String::new(),
                tp_url: String::new(),
                extern_url: String::new(),
                extern_md5: "60bfd31a".to_string(),
                encrypt_url: String::new(),
            }),
            DecodedEvent::AvatarImageCreate(AvatarImageCreate {
                provenance: prov(EventType::AvatarImageUpdate, EventAction::Create),
                username: "wxid_friend_001".to_string(),
                md5: "a1b2c3d4e5f60718".to_string(),
                image_buffer: vec![0xFF, 0xD8, 0xFF, 0xE0],
                update_time: 1_752_000_000,
            }),
            DecodedEvent::SnsNotifyCreate(SnsNotifyCreate {
                provenance: prov(EventType::SnsNotifyUpdate, EventAction::Create),
                comment_id: 123_456_789,
                feed_id: -3_652_952_694_686_404_033,
                notify_type: 2,
                from_user: "wxid_notify_from".to_string(),
                create_time: 1_763_557_360,
                from_nickname: None,
                to_user: None,
                to_nickname: None,
                content: Some("评论正文".to_string()),
                is_unread: 0,
                del_status: 0,
                is_relative_me: 0,
            }),
            DecodedEvent::BizChatContactCreate(BizChatContactCreate {
                provenance: prov(EventType::BizChatContactUpdate, EventAction::Create),
                user_id: "ww16xxxxxxxxxxxxxxxxxxx".to_string(),
                brand_user_name: "gh_44bfefcbb4a5".to_string(),
                user_name: "白星".to_string(),
                head_img_url: "http://head/x".to_string(),
                profile_url: "https://work.weixin.qq.com/x".to_string(),
                bit_flag: 16,
            }),
            DecodedEvent::SystemCursorUpdate(SystemCursorUpdate {
                provenance: prov(EventType::SystemEvent, EventAction::CursorUpdate),
                kind: "message".to_string(),
                watermark_key: "k".to_string(),
                watermark_value: "[1]".to_string(),
                last_update: 1,
            }),
            DecodedEvent::SystemError(SystemError {
                provenance: prov(EventType::SystemEvent, EventAction::Error),
                error_code: "E".to_string(),
                error_message: "m".to_string(),
                context_json: None,
                occurred_at_canonical: "c".to_string(),
            }),
        ]
    }

    /// 不变量: 每变体内在 (event_type, event_action) 都是 alpha 合法组合 (config-events §7.3).
    #[test]
    fn every_variant_is_alpha_valid_combo() {
        let variants = all_variants();
        assert_eq!(variants.len(), 21, "应覆盖 21 个 alpha 事件 (含 session + favorite + favorite_tag + sns + transfer + red_envelope + group_pay + friend_verify + finder + moment_feed + custom_emoticon + avatar + sns_notify + bizchat)");
        for ev in &variants {
            assert!(
                is_alpha_valid_combo(ev.event_type(), ev.event_action()),
                "{:?}/{:?} 不是 alpha 合法组合",
                ev.event_type(),
                ev.event_action()
            );
        }
    }

    /// 内在 (event_type, event_action) 跟内层 provenance 字段一致 (样本构造正确性 + 派生正确性).
    #[test]
    fn intrinsic_matches_provenance() {
        for ev in &all_variants() {
            assert_eq!(ev.event_type(), ev.provenance().event_type);
            assert_eq!(ev.event_action(), ev.provenance().event_action);
        }
    }

    /// to_payload_json 派发到内层 — payload 带正确 event_type/event_action + provenance 字段.
    #[test]
    fn to_payload_dispatches_to_inner() {
        let ev = &all_variants()[0]; // Message
        let p = ev.to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["event_type"], Value::from("message"));
        assert_eq!(o["event_action"], Value::from("create"));
        assert!(o.contains_key("text_content_sha"), "派发到 MessageCreate payload");
    }

    /// K-R4: derive Debug 委托内层脱敏 Debug — 敏感变体不泄裸值.
    #[test]
    fn debug_delegates_to_inner_redaction() {
        let ev = &all_variants()[0]; // Message (text_content="hi", conv_id=wxid_a)
        let dbg = format!("{ev:?}");
        assert!(!dbg.contains("wxid_a"), "K-R4: DecodedEvent Debug 应委托内层脱敏");
        assert!(dbg.contains("Message"), "变体名可见");
    }
}
