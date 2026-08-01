//! event::session — (session_update, create) 事件字段集. 微信会话列表 (聊天列表) 一项.
//!
//! 照 [`super::contact::ContactUpdate`] 模板 (嵌 [`Provenance`] + to_payload_json + 手写 Debug + 不 derive Serialize)。
//! 数据源 = 微信 session.db `SessionTable`。可变状态 (unread/summary/sort 随消息变) → 全表重扫 +
//! content_digest 去重 + UPSERT (同 contact)。
//!
//! 字段归桶: `username` / `last_msg_sender` = id 类; `summary` / `draft` = text_content 类 (预览 / 没发的草稿, 最私密);
//! `last_sender_display_name` = display_name 类 (群里"谁发的"); `unread_count`/`last_msg_type`/`last_msg_sub_type`/
//! `sort_timestamp`/`session_type`/`is_hidden`/`status`/`last_timestamp`/`last_clear_unread_timestamp`/
//! `last_msg_locald_id`/`last_msg_ext_type`/`unread_first_msg_srv_id` = 元数据类 (第四/六批会话列进 L2 不进 digest)。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 username / summary / sender 裸值被误序列化。
//! - **手写 `Debug`** — username / summary / sender 经 [`sha8`] 脱敏; provenance.account_id 自遮。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, render_opt_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (session_update, create) 事件字段集 — 一个会话 (聊天列表项)。
///
/// `username` = 会话标识 (对方 wxid / 群 `@chatroom` / `gh_` 公众号);
/// `source_native_id` = `"Session_<md5_hex(username)>"`。
pub struct SessionUpdate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 会话标识 raw (id 类: 对方 wxid / 群 @chatroom / gh_ 等; 默认 username_sha)。
    pub username: String,
    /// 最近消息预览 (text_content 类, nullable: 默认 summary_sha + summary_len; SessionTable 约 94% 非空)。
    pub summary: Option<String>,
    /// 最近消息发送者显示名 (display_name 类, nullable: 群里"谁发的"; 单聊常空)。
    pub last_sender_display_name: Option<String>,
    /// 未读数 (元数据)。
    pub unread_count: i64,
    /// 最近消息类型 (元数据; 1=文本 / 3=图片 / 49=APP 等)。
    pub last_msg_type: i64,
    /// 最近消息子类型 (元数据; APP_XML 时有效)。
    pub last_msg_sub_type: i64,
    /// 排序时间戳 (元数据; 会话列表按此倒序)。
    pub sort_timestamp: i64,

    // ── 会话状态列 (进 L2 不进 content_digest — 当前态筛选; 折叠/免打扰历史价值低, 同头像批不 supersede)。
    /// 会话类型 (元数据; 1=单聊/2=群 等)。
    pub session_type: i64,
    /// 隐藏/折叠会话 (元数据; 0/1)。
    pub is_hidden: i64,
    /// 会话状态位 (元数据; 含免打扰等)。
    pub status: i64,
    /// 草稿 (text_content 类, nullable; 用户未发文本, 最私密 → 默认 draft_sha+draft_len 脱敏)。
    pub draft: Option<String>,

    // ── 第六批 (2026-07-02): session 补充列 (**只进 L2 session 表, 不进 payload_json/archive/content_digest** —
    //     同第四批状态列 L2-only; last_msg_sender 是 id 类 wxid → Debug sha8)。
    /// 最后消息发送者 wxid (id 类, nullable; 只进 L2, Debug sha8 脱敏)。
    pub last_msg_sender: Option<String>,
    /// 最后消息时间戳 (元数据)。
    pub last_timestamp: i64,
    /// 最后清未读时间戳 (元数据)。
    pub last_clear_unread_timestamp: i64,
    /// 最后消息本地 id (元数据; 微信自身列名拼写 locald)。
    pub last_msg_locald_id: i64,
    /// 最后消息扩展类型 (元数据)。
    pub last_msg_ext_type: i64,
    /// 首条未读消息 server id (元数据)。
    pub unread_first_msg_srv_id: i64,
}

impl SessionUpdate {
    /// 渲染整条 session_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // id 类.
        render_field(&mut out, "username", &self.username, FieldCategory::Id, mode);
        // text_content 类 (summary 可空).
        render_opt_field(
            &mut out,
            "summary",
            self.summary.as_deref(),
            FieldCategory::TextContent,
            mode,
        );
        // display_name 类 (sender 可空).
        render_opt_field(
            &mut out,
            "last_sender_display_name",
            self.last_sender_display_name.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        // 数字元数据 — 直塞.
        out.insert("unread_count".to_string(), Value::from(self.unread_count));
        out.insert("last_msg_type".to_string(), Value::from(self.last_msg_type));
        out.insert("last_msg_sub_type".to_string(), Value::from(self.last_msg_sub_type));
        out.insert("sort_timestamp".to_string(), Value::from(self.sort_timestamp));
        // 第四批会话状态列 (session_type/is_hidden/status/draft) **不进 payload_json** (workflow 跨批深审 P1 修:
        // 这 4 列 L2-only 独立不进 content_digest → 若进 payload, archive 按 event_seq(=content_digest 派生)去重,
        // 只改草稿/免打扰、无新消息时 content_digest 不变 → 撞键丢弃新 archive 行、payload 冻结旧值, 而 L2 被 UPSERT
        // 刷新 → archive 与 L2 永久分歧, 下游重放读陈旧值)。与第五/六/七批及头像列一致: 只走 project_session → L2。
        // 第六批 (last_msg_sender/last_timestamp/last_clear_unread_timestamp/last_msg_locald_id/
        // last_msg_ext_type/unread_first_msg_srv_id) 同理 **不进 payload_json** (L2-only)。

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): username / summary / sender 经 sha8 脱敏; provenance 自遮。
/// **不准 derive Debug** — 会泄会话标识 / 消息预览 / 发送者裸值。
impl fmt::Debug for SessionUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let opt_sha8 = |o: &Option<String>| o.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("SessionUpdate")
            .field("provenance", &self.provenance)
            .field("username_sha8", &sha8(self.username.as_bytes()))
            .field("summary_sha8", &opt_sha8(&self.summary))
            .field("last_sender_sha8", &opt_sha8(&self.last_sender_display_name))
            .field("unread_count", &self.unread_count)
            .field("last_msg_type", &self.last_msg_type)
            .field("last_msg_sub_type", &self.last_msg_sub_type)
            .field("sort_timestamp", &self.sort_timestamp)
            .field("session_type", &self.session_type)
            .field("is_hidden", &self.is_hidden)
            .field("status", &self.status)
            .field("draft_sha8", &opt_sha8(&self.draft))
            .field("last_msg_sender_sha8", &opt_sha8(&self.last_msg_sender))
            .field("last_timestamp", &self.last_timestamp)
            .field("last_clear_unread_timestamp", &self.last_clear_unread_timestamp)
            .field("last_msg_locald_id", &self.last_msg_locald_id)
            .field("last_msg_ext_type", &self.last_msg_ext_type)
            .field("unread_first_msg_srv_id", &self.unread_first_msg_srv_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> SessionUpdate {
        SessionUpdate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "session.db".to_string(),
                source_native_id: "Session_a1b2c3d4".to_string(),
                event_type: EventType::SessionUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            username: "wxid_friend_002".to_string(),
            summary: Some("晚上吃饭吗".to_string()),
            last_sender_display_name: Some("小明".to_string()),
            unread_count: 3,
            last_msg_type: 1,
            last_msg_sub_type: 0,
            sort_timestamp: 1_700_000_009_000,
            session_type: 1,
            is_hidden: 0,
            status: 0,
            draft: Some("没发出的草稿".to_string()),
            last_msg_sender: Some("wxid_sender_last".to_string()),
            last_timestamp: 1_700_000_010_000,
            last_clear_unread_timestamp: 1_700_000_005_000,
            last_msg_locald_id: 42,
            last_msg_ext_type: 0,
            unread_first_msg_srv_id: 9_876_543_210,
        }
    }

    /// 默认模式: username/summary/sender 脱敏 _sha (+ summary/sender _len); 数字元数据照原。
    #[test]
    fn payload_default_redacts_content_and_id() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["username_sha"], Value::from(sha256_hex("wxid_friend_002")));
        assert!(!o.contains_key("username"));
        assert_eq!(o["summary_sha"], Value::from(sha256_hex("晚上吃饭吗")));
        assert_eq!(o["summary_len"], Value::from(5_i64));
        assert!(!o.contains_key("summary"), "K-R4: 默认不出裸 summary");
        assert_eq!(o["last_sender_display_name_sha"], Value::from(sha256_hex("小明")));
        assert_eq!(o["unread_count"], Value::from(3));
        assert_eq!(o["last_msg_type"], Value::from(1));
        assert_eq!(o["sort_timestamp"], Value::from(1_700_000_009_000_i64));
    }

    /// plaintext: username + summary + sender 全明文 (全程明文方针 ADR-427 默认即此)。
    #[test]
    fn payload_plaintext_exposes_content() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["username"], Value::from("wxid_friend_002"));
        assert_eq!(o["summary"], Value::from("晚上吃饭吗"));
        assert_eq!(o["last_sender_display_name"], Value::from("小明"));
        assert!(!o.contains_key("summary_sha"));
    }

    /// K-R4: 默认模式 payload 不含任何裸敏感值。
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in [
            "wxid_friend_002",
            "晚上吃饭吗",
            "小明",
            "wxid_acct_001",
            "没发出的草稿",
            "wxid_sender_last",
        ] {
            assert!(!dumped.contains(raw), "K-R4: 默认 payload 泄裸值 {raw}");
        }
        // 第四批状态列 (session_type/is_hidden/status/draft) 改为 **L2-only 不进 payload** (workflow 深审 P1:
        // 避免 archive 按 content_digest 去重致 payload 陈旧, 同第五/六/七批)。draft 整列不进 payload (连 draft_sha 也不出)。
        let o = p.as_object().unwrap();
        assert!(!o.contains_key("draft"), "第四批 draft 不进 payload (L2-only)");
        assert!(!o.contains_key("draft_sha"), "draft 整列不进 payload (连脱敏也不出)");
        for k in ["session_type", "is_hidden", "status"] {
            assert!(!o.contains_key(k), "第四批状态列 {k} 不进 payload (L2-only)");
        }
    }

    /// 字段扩充第六批: session 补充列只进 L2 (不进 payload); last_msg_sender Debug sha8 脱敏。
    #[test]
    fn batch6_not_in_payload() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        for k in [
            "last_msg_sender",
            "last_msg_sender_sha",
            "last_timestamp",
            "last_clear_unread_timestamp",
            "last_msg_locald_id",
            "last_msg_ext_type",
            "unread_first_msg_srv_id",
        ] {
            assert!(!o.contains_key(k), "第六批列不进 payload: {k}");
        }
        // plaintext 模式也不进 payload。
        let pp = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        assert!(
            !pp.as_object().unwrap().contains_key("last_msg_sender"),
            "plaintext 也不出 last_msg_sender"
        );
    }

    /// K-R4: 手写 Debug 不泄 username / summary / sender / account_id 裸值。
    #[test]
    fn debug_redacts_sensitive() {
        let dbg = format!("{:?}", sample());
        for raw in [
            "wxid_friend_002",
            "晚上吃饭吗",
            "小明",
            "wxid_acct_001",
            "wxid_sender_last",
        ] {
            assert!(!dbg.contains(raw), "Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("summary_sha8"));
        assert!(
            dbg.contains("last_msg_sender_sha8"),
            "第六批 last_msg_sender Debug sha8 脱敏"
        );
    }
}
