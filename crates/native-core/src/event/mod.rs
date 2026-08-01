//! event — raw_payload 事件类型枚举 (跟 config-events §7 + raw-payload-输出格式.md §3 一致).
//!
//! 本 mod = event 数据模型:
//!   - PR2-3-a 地基: EventType + EventAction 枚举 + alpha 合法组合校验 (本文件)
//!   - PR2-3-b 隐私核: [`privacy`] 子模块 — 字段类别 4 桶 + 隐私 3 开关 + payload_json 脱敏渲染
//!
//! 各事件的业务字段集 struct (DecodedMessage / V3Message / RawPayload 等, ADR-412 §3.x 表 + session/favorite/favorite_tag 扩)
//! 推后续 PR (PR2-3-c+, 按 event_type 逐个落, 调 [`privacy::render_field`] 出 payload).
//!
//! 红线 (raw-payload-输出格式.md §4 + config-events §7):
//!   - EventType / EventAction 是【元数据类】枚举 — **永远明文** (无 sha / 无隐私模式切换),
//!     序列化 snake_case 字符串 (跟 provenance event_type / event_action 字段一致)
//!   - alpha 冻结 15 个 (event_type, event_action) 组合 (§7.3 原 7 + session ADR-412 + favorite/favorite_tag ADR-454 + sns ADR-467 + transfer/red_envelope/group_pay ADR-468 + friend_verify ADR-469); 0.2.0+ 解锁走 supersede ADR-414
//!   - 敏感字符串字段 (wxid / 昵称 / 正文) 出 payload 必经 [`privacy::render_field`] (K-R4)

pub mod assembly;
pub mod avatar;
pub mod bizchat;
pub mod canonical;
pub mod chatroom;
pub mod contact;
pub mod decoded;
pub mod emoticon;
pub mod favorite;
pub mod favorite_tag;
pub mod finder;
pub mod fingerprint;
pub mod friend_verify;
pub mod group_pay;
pub mod message;
pub mod moment_feed;
pub mod privacy;
pub mod provenance;
pub mod red_envelope;
pub mod session;
pub mod sns;
pub mod sns_notify;
pub mod system;
pub mod transfer;

use serde::{Deserialize, Serialize};

/// raw_payload 事件类型 (config-events §7.1 — 5 变体, alpha 激活 4 个).
///
/// 序列化 snake_case: Message→"message" / ContactUpdate→"contact_update" / ... (provenance event_type 字段).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// 一条聊天消息 (alpha 必有).
    Message,
    /// 联系人变化 (alpha 必有).
    ContactUpdate,
    /// 群信息 + 成员 (alpha 必有).
    ChatroomUpdate,
    /// 会话列表项 (聊天列表: 未读 / 最近消息预览 / 排序; alpha — ADR-412 扩, ADR-427 全程明文).
    SessionUpdate,
    /// 收藏项 (favorite.db fav_db_item: 类型/收藏时间/来源; alpha — ADR-454 扩, 照 SessionUpdate/ADR-412 先例).
    FavoriteUpdate,
    /// 收藏标签绑定 (favorite.db fav_bind_tag_db_item ⋈ fav_tag: 标签↔收藏 M:N; alpha — ADR-454 批 B-2).
    FavoriteTagUpdate,
    /// 朋友圈 (0.2.0+ 解锁, 走 supersede ADR-414).
    SnsEvent,
    /// 转账 (general.db transferTable: 双方/状态/时间/消息链接; alpha — ADR-468 扩, 照收藏 ADR-454 先例)。
    TransferUpdate,
    /// 红包 (general.db redEnvelopeTable: 发送者/状态/类型/领取URL; alpha — ADR-468 件2)。
    RedEnvelopeUpdate,
    /// 群收款 (general.db groupPayTable: 账单号/会话/消息/时刻; alpha — ADR-468 件3)。
    GroupPayUpdate,
    /// 好友验证/打招呼 (general.db FMessageTable: 好友/来源 scene/打招呼语/方向; alpha — ADR-469)。
    FriendVerifyUpdate,
    /// 视频号主页记录 (general.db wcfinderuserpage: 视频号 id/昵称/访问时刻/主页URL; alpha — ADR-473)。
    FinderVisitUpdate,
    /// 朋友圈好友动态索引 (sns.db SnsTopItem_1: 动态 tid/发布者/发布时刻/读状态; alpha — ADR-474)。
    MomentFeedUpdate,
    /// 自定义表情 (emoticon.db kNonStoreEmoticonTable: md5/描述/密钥/CDN; alpha — ADR-478)。
    CustomEmoticonUpdate,
    /// 头像图 (head_image.db head_image: username/md5/原始图bytes/更新时刻; alpha — ADR-481)。
    AvatarImageUpdate,
    /// 朋友圈互动通知 (sns.db SnsMessage_tmp3: 通知id/动态/类型/互动者/时刻/评论文本; alpha — 照 moment_feed ADR-474)。
    SnsNotifyUpdate,
    /// 企微品牌号联系人 (bizchat.db user_info: 企微 wxid/品牌 gh_id/显示名/头像/主页; alpha — ADR-494)。
    BizChatContactUpdate,
    /// raw_payload 内部状态事件 cursor_update / error (alpha 必有, 跟 §5.2 12 类无关).
    SystemEvent,
}

/// raw_payload 事件动作 (config-events §7.2 — 9 变体, alpha 激活 5 个).
///
/// 序列化 snake_case: Create→"create" / MemberAdd→"member_add" / ... (provenance event_action 字段).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    // ── alpha 冻结 (5 个唯一取值, 跟 ADR-414) ──
    /// message/contact_update/chatroom_update 的新建.
    Create,
    /// chatroom_update 群成员加入.
    MemberAdd,
    /// chatroom_update 群成员移除.
    MemberRemove,
    /// system_event cursor 位置更新 (重放锚点).
    CursorUpdate,
    /// system_event 内部错误事件.
    Error,

    // ── 0.2.0+ 解锁 (走 supersede ADR-414, alpha 不产出) ──
    /// 0.2.0+ message 撤回.
    Recall,
    /// 0.2.0+ message/contact_update/chatroom_update 更新.
    Update,
    /// 0.2.0+ message 编辑.
    Edit,
    /// 0.2.0+ contact_update 删除.
    Delete,
}

impl EventType {
    /// canonical snake_case 串 (provenance event_type 字段 / log).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::ContactUpdate => "contact_update",
            Self::ChatroomUpdate => "chatroom_update",
            Self::SessionUpdate => "session_update",
            Self::FavoriteUpdate => "favorite_update",
            Self::FavoriteTagUpdate => "favorite_tag_update",
            Self::SnsEvent => "sns_event",
            Self::TransferUpdate => "transfer_update",
            Self::RedEnvelopeUpdate => "red_envelope_update",
            Self::GroupPayUpdate => "group_pay_update",
            Self::FriendVerifyUpdate => "friend_verify_update",
            Self::FinderVisitUpdate => "finder_visit_update",
            Self::MomentFeedUpdate => "moment_feed_update",
            Self::CustomEmoticonUpdate => "custom_emoticon_update",
            Self::AvatarImageUpdate => "avatar_image_update",
            Self::SnsNotifyUpdate => "sns_notify_update",
            Self::BizChatContactUpdate => "biz_chat_contact_update",
            Self::SystemEvent => "system_event",
        }
    }

    /// alpha 是否激活 (全 8 事件类型均已进 alpha: SnsEvent 经 ADR-467 扩入, 收藏经 ADR-454; 目前无 0.2.0+ 类型).
    #[must_use]
    pub fn is_alpha_active(self) -> bool {
        // 全类型已激活 — 保留 self 参数 (API 稳定 + 未来若加 0.2.0+ 类型仍在此收窄)。
        matches!(
            self,
            Self::Message
                | Self::ContactUpdate
                | Self::ChatroomUpdate
                | Self::SessionUpdate
                | Self::FavoriteUpdate
                | Self::FavoriteTagUpdate
                | Self::SnsEvent
                | Self::TransferUpdate
                | Self::RedEnvelopeUpdate
                | Self::GroupPayUpdate
                | Self::FriendVerifyUpdate
                | Self::FinderVisitUpdate
                | Self::MomentFeedUpdate
                | Self::CustomEmoticonUpdate
                | Self::AvatarImageUpdate
                | Self::SnsNotifyUpdate
                | Self::BizChatContactUpdate
                | Self::SystemEvent
        )
    }
}

impl EventAction {
    /// canonical snake_case 串 (provenance event_action 字段 / log).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::MemberAdd => "member_add",
            Self::MemberRemove => "member_remove",
            Self::CursorUpdate => "cursor_update",
            Self::Error => "error",
            Self::Recall => "recall",
            Self::Update => "update",
            Self::Edit => "edit",
            Self::Delete => "delete",
        }
    }

    /// alpha 是否冻结激活 (前 5 个; Recall/Update/Edit/Delete 推 0.2.0+).
    #[must_use]
    pub fn is_alpha_active(self) -> bool {
        matches!(
            self,
            Self::Create | Self::MemberAdd | Self::MemberRemove | Self::CursorUpdate | Self::Error
        )
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for EventAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// alpha 冻结的 21 个 (event_type, event_action) 合法组合 (config-events §7.3 / raw-payload §6.x).
/// 数组逐行对应 §7.3 表 (单一真相, 改这里必同步改 §7.3 + ADR-414; session=ADR-412 / favorite+favorite_tag=ADR-454 /
/// sns=ADR-467 / transfer+red_envelope+group_pay=ADR-468 / friend_verify=ADR-469 / finder=ADR-473 /
/// moment_feed=ADR-474 / custom_emoticon=ADR-478 / avatar=ADR-481 / sns_notify=照 moment_feed ADR-474 / bizchat=ADR-494 扩 alpha).
pub const ALPHA_VALID_COMBOS: [(EventType, EventAction); 21] = [
    (EventType::Message, EventAction::Create),              // §7.3 #1
    (EventType::ContactUpdate, EventAction::Create),        // §7.3 #2
    (EventType::ChatroomUpdate, EventAction::Create),       // §7.3 #3
    (EventType::ChatroomUpdate, EventAction::MemberAdd),    // §7.3 #4
    (EventType::ChatroomUpdate, EventAction::MemberRemove), // §7.3 #5
    (EventType::SessionUpdate, EventAction::Create),        // session 会话列表更新 (ADR-412 扩 alpha)
    (EventType::FavoriteUpdate, EventAction::Create),       // 收藏项 (ADR-454 扩 alpha)
    (EventType::FavoriteTagUpdate, EventAction::Create),    // 收藏标签绑定 (ADR-454 批 B-2)
    (EventType::SnsEvent, EventAction::Create),             // 朋友圈动态 (ADR-467 扩 alpha)
    (EventType::TransferUpdate, EventAction::Create),       // 转账 (ADR-468 扩 alpha)
    (EventType::RedEnvelopeUpdate, EventAction::Create),    // 红包 (ADR-468 件2)
    (EventType::GroupPayUpdate, EventAction::Create),       // 群收款 (ADR-468 件3)
    (EventType::FriendVerifyUpdate, EventAction::Create),   // 好友验证 (ADR-469)
    (EventType::FinderVisitUpdate, EventAction::Create),    // 视频号主页记录 (ADR-473)
    (EventType::MomentFeedUpdate, EventAction::Create),     // 朋友圈好友动态索引 (ADR-474)
    (EventType::CustomEmoticonUpdate, EventAction::Create), // 自定义表情 (ADR-478)
    (EventType::AvatarImageUpdate, EventAction::Create),    // 头像图 (ADR-481)
    (EventType::SnsNotifyUpdate, EventAction::Create),      // 朋友圈互动通知 (照 moment_feed ADR-474)
    (EventType::BizChatContactUpdate, EventAction::Create), // 企微品牌号联系人 (ADR-494)
    (EventType::SystemEvent, EventAction::CursorUpdate),    // §7.3 #6
    (EventType::SystemEvent, EventAction::Error),           // §7.3 #7
];

/// emit 层校验: 只允许 alpha 冻结的 15 组合产出, 其它 (0.2.0+ action / Sns·Transfer·RedEnvelope·GroupPay·FriendVerify 非 Create) 拒绝.
/// 0.2.0+ 解锁走 supersede ADR-414 + 扩 `ALPHA_VALID_COMBOS`.
#[must_use]
pub fn is_alpha_valid_combo(event_type: EventType, event_action: EventAction) -> bool {
    ALPHA_VALID_COMBOS.contains(&(event_type, event_action))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventType::ContactUpdate).unwrap(),
            "\"contact_update\""
        );
        assert_eq!(serde_json::to_string(&EventType::SnsEvent).unwrap(), "\"sns_event\"");
        let t: EventType = serde_json::from_str("\"system_event\"").unwrap();
        assert_eq!(t, EventType::SystemEvent);
    }

    #[test]
    fn event_action_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventAction::MemberAdd).unwrap(),
            "\"member_add\""
        );
        assert_eq!(
            serde_json::to_string(&EventAction::CursorUpdate).unwrap(),
            "\"cursor_update\""
        );
        let a: EventAction = serde_json::from_str("\"member_remove\"").unwrap();
        assert_eq!(a, EventAction::MemberRemove);
    }

    #[test]
    fn as_str_matches_serde() {
        // as_str (provenance 字段 / log) 跟 serde 序列化值一致 — 单一真相防漂移
        for t in [
            EventType::Message,
            EventType::ContactUpdate,
            EventType::ChatroomUpdate,
            EventType::SessionUpdate,
            EventType::FavoriteUpdate,
            EventType::FavoriteTagUpdate,
            EventType::SnsEvent,
            EventType::TransferUpdate,
            EventType::RedEnvelopeUpdate,
            EventType::GroupPayUpdate,
            EventType::FriendVerifyUpdate,
            EventType::SnsNotifyUpdate,
            EventType::BizChatContactUpdate,
            EventType::SystemEvent,
        ] {
            let serde_str = serde_json::to_string(&t).unwrap();
            assert_eq!(
                format!("\"{}\"", t.as_str()),
                serde_str,
                "EventType {t:?} as_str vs serde 漂移"
            );
        }
        for a in [
            EventAction::Create,
            EventAction::MemberAdd,
            EventAction::MemberRemove,
            EventAction::CursorUpdate,
            EventAction::Error,
            EventAction::Recall,
            EventAction::Update,
            EventAction::Edit,
            EventAction::Delete,
        ] {
            let serde_str = serde_json::to_string(&a).unwrap();
            assert_eq!(
                format!("\"{}\"", a.as_str()),
                serde_str,
                "EventAction {a:?} as_str vs serde 漂移"
            );
        }
    }

    #[test]
    fn alpha_active_flags() {
        assert!(EventType::Message.is_alpha_active());
        assert!(EventType::SnsEvent.is_alpha_active(), "SnsEvent 已 ADR-467 扩进 alpha");
        assert!(EventAction::Create.is_alpha_active());
        assert!(!EventAction::Recall.is_alpha_active(), "Recall 推 0.2.0+");
        assert!(!EventAction::Delete.is_alpha_active());
    }

    /// config-events §7.3: 恰好 21 个 alpha 合法组合 (§7.3 原 7 + session ADR-412 + favorite/favorite_tag ADR-454 + sns ADR-467 + transfer/red_envelope/group_pay ADR-468 + friend_verify ADR-469 + finder ADR-473 + moment_feed ADR-474 + custom_emoticon ADR-478 + avatar ADR-481 + sns_notify + bizchat ADR-494).
    #[test]
    fn exactly_21_alpha_combos() {
        let all_types = [
            EventType::Message,
            EventType::ContactUpdate,
            EventType::ChatroomUpdate,
            EventType::SessionUpdate,
            EventType::FavoriteUpdate,
            EventType::FavoriteTagUpdate,
            EventType::SnsEvent,
            EventType::TransferUpdate,
            EventType::RedEnvelopeUpdate,
            EventType::GroupPayUpdate,
            EventType::FriendVerifyUpdate,
            EventType::FinderVisitUpdate,
            EventType::MomentFeedUpdate,
            EventType::CustomEmoticonUpdate,
            EventType::AvatarImageUpdate,
            EventType::SnsNotifyUpdate,
            EventType::BizChatContactUpdate,
            EventType::SystemEvent,
        ];
        let all_actions = [
            EventAction::Create,
            EventAction::MemberAdd,
            EventAction::MemberRemove,
            EventAction::CursorUpdate,
            EventAction::Error,
            EventAction::Recall,
            EventAction::Update,
            EventAction::Edit,
            EventAction::Delete,
        ];
        let count = all_types
            .iter()
            .flat_map(|t| all_actions.iter().map(move |a| (*t, *a)))
            .filter(|(t, a)| is_alpha_valid_combo(*t, *a))
            .count();
        assert_eq!(count, 21, "alpha 应恰好 21 个合法组合 (§7.3 + session + favorite/favorite_tag + sns + transfer/red_envelope/group_pay + friend_verify + finder + moment_feed + custom_emoticon ADR-478 + avatar ADR-481 + sns_notify + bizchat ADR-494)");
        assert_eq!(ALPHA_VALID_COMBOS.len(), 21, "常量数组也应 21 行");
    }

    /// r1 Claude P2: 未知枚举串 → Err 不 panic (锁防未来误加 #[serde(other)] 吞未知值).
    #[test]
    fn unknown_variant_deserialize_is_err() {
        assert!(serde_json::from_str::<EventType>("\"foobar\"").is_err());
        assert!(serde_json::from_str::<EventAction>("\"nope\"").is_err());
    }

    #[test]
    fn valid_combos_spot_check() {
        assert!(is_alpha_valid_combo(EventType::Message, EventAction::Create));
        assert!(is_alpha_valid_combo(EventType::ChatroomUpdate, EventAction::MemberAdd));
        assert!(is_alpha_valid_combo(EventType::SystemEvent, EventAction::Error));
        // 非法: message 不能 member_add
        assert!(!is_alpha_valid_combo(EventType::Message, EventAction::MemberAdd));
        // 合法: SnsEvent create (ADR-467 扩 alpha)
        assert!(is_alpha_valid_combo(EventType::SnsEvent, EventAction::Create));
        // 非法: SnsEvent 非 create action
        assert!(!is_alpha_valid_combo(EventType::SnsEvent, EventAction::Update));
        // 合法: TransferUpdate create (ADR-468 扩 alpha); 非法: 非 create
        assert!(is_alpha_valid_combo(EventType::TransferUpdate, EventAction::Create));
        assert!(!is_alpha_valid_combo(EventType::TransferUpdate, EventAction::Update));
        // 合法: RedEnvelopeUpdate create (ADR-468 件2)
        assert!(is_alpha_valid_combo(EventType::RedEnvelopeUpdate, EventAction::Create));
        // 合法: GroupPayUpdate create (ADR-468 件3)
        assert!(is_alpha_valid_combo(EventType::GroupPayUpdate, EventAction::Create));
        // 合法: FriendVerifyUpdate create (ADR-469)
        assert!(is_alpha_valid_combo(EventType::FriendVerifyUpdate, EventAction::Create));
        // 非法: 0.2.0+ action
        assert!(!is_alpha_valid_combo(EventType::Message, EventAction::Recall));
        // 非法: contact_update 不能 member_remove
        assert!(!is_alpha_valid_combo(
            EventType::ContactUpdate,
            EventAction::MemberRemove
        ));
    }
}
