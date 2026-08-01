//! event::friend_verify — (friend_verify_update, create) 事件字段集. 微信好友验证/打招呼消息
//! (general.db `FMessageTable`) 一条。
//!
//! 照 [`super::transfer::TransferCreate`] 模板但 content 走 text 类。扩 alpha 第 15 事件类型 (新域, 非支付; ADR-469)。
//! 真库 `user_name_` 100% 唯一 (一好友一行 = 最新一条验证)。**⭐ `scene` = 加好友来源** (14 群聊 / 3 搜索微信号 /
//! 17 名片 / 30 扫一扫), 顺带定 contact.friend_source 语义。
//!
//! **不取 (drain 层已排除, 低读值)**: `encrypt_user_name_` (与 user_name 冗余, 加密态) / `ticket_` (接受好友的
//! 写操作 token, 318 字符无读/分析价值) / `fmessage_detail_buf_` (不透明 proto, 均值 31 字节)。
//!
//! ## content_digest (canonical.rs friend_verify 臂)
//! user_name_sha / timestamp / is_sender / scene — 好友 (真库唯一) + 时刻 + 方向 + 来源 (4 元)。
//! friend_type (真库恒 37) / content (打招呼语, text 类) 只进 L2。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — user_name 经 [`sha8`]; content (打招呼语) **只露字符数**
//!   (text 类, 同 message text_content)。
//! - content 出 payload 走 [`FieldCategory::TextContent`] (默认 sha; plaintext/enable_text_content 才出原文)。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (friend_verify_update, create) 事件字段集 — 一条好友验证/打招呼 (general.db `FMessageTable`)。
///
/// `source_native_id` = `"FMessage_<md5_hex(user_name)>"` (user_name 是好友 wxid → 内部 md5, 不暴露明文)。
pub struct FriendVerifyCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 好友 (FMessageTable.user_name_; id 类 wxid; 真库 100% 唯一; 进 digest 用 sha; anchor 用 md5)。
    pub user_name: String,
    /// 消息类型 (FMessageTable.type_; 真库恒 37; 元数据; 只进 L2)。
    pub friend_type: i64,
    /// 验证时刻 (FMessageTable.timestamp_; unix 秒; 进 digest)。
    pub timestamp: i64,
    /// 方向 (FMessageTable.is_sender_; 0=收到/1=发出; 进 digest)。
    pub is_sender: i64,
    /// 加好友来源 (FMessageTable.scene_; 14 群聊 / 3 搜索微信号 / 17 名片 / 30 扫一扫; 进 digest)。
    pub scene: i64,
    /// 打招呼语 (FMessageTable.content_; text 类; 只进 L2, Debug 只露字符数; K-R4 默认 payload sha)。
    pub content: String,
}

impl FriendVerifyCreate {
    /// 渲染整条 friend_verify_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // id 类 (user_name — 默认 sha).
        render_field(&mut out, "user_name", &self.user_name, FieldCategory::Id, mode);
        // text 类 (content 打招呼语 — 默认 sha, plaintext/enable_text_content 出原文).
        render_field(&mut out, "content", &self.content, FieldCategory::TextContent, mode);
        // 数字元数据 — 直塞.
        out.insert("friend_type".to_string(), Value::from(self.friend_type));
        out.insert("timestamp".to_string(), Value::from(self.timestamp));
        out.insert("is_sender".to_string(), Value::from(self.is_sender));
        out.insert("scene".to_string(), Value::from(self.scene));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): user_name 经 sha8; content (打招呼语) **只露字符数**; provenance 自遮。**不准 derive Debug**。
impl fmt::Debug for FriendVerifyCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FriendVerifyCreate")
            .field("provenance", &self.provenance)
            .field("user_name_sha8", &sha8(self.user_name.as_bytes()))
            .field("friend_type", &self.friend_type)
            .field("timestamp", &self.timestamp)
            .field("is_sender", &self.is_sender)
            .field("scene", &self.scene)
            .field("content_len", &self.content.chars().count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> FriendVerifyCreate {
        FriendVerifyCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "general.db".to_string(),
                source_native_id: "FMessage_3949bf65".to_string(),
                event_type: EventType::FriendVerifyUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            user_name: "wxid_friend_002".to_string(),
            friend_type: 37,
            timestamp: 1_752_217_142,
            is_sender: 0,
            scene: 14,
            content: "你好我是隔壁老王".to_string(),
        }
    }

    /// 默认模式: user_name 脱敏 _sha; content 脱敏 _sha (打招呼语); 数字元数据照原。
    #[test]
    fn payload_default_redacts_id_and_content() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["user_name_sha"], Value::from(sha256_hex("wxid_friend_002")));
        assert_eq!(
            o["content_sha"],
            Value::from(sha256_hex("你好我是隔壁老王")),
            "打招呼语默认 sha"
        );
        assert!(!o.contains_key("user_name"), "K-R4: 默认不出裸 user_name");
        assert!(!o.contains_key("content"), "K-R4: 默认不出裸 content");
        assert_eq!(o["scene"], Value::from(14));
        assert_eq!(o["is_sender"], Value::from(0));
        assert_eq!(o["timestamp"], Value::from(1_752_217_142_i64));
        assert_eq!(o["friend_type"], Value::from(37));
    }

    /// plaintext: user_name + content 全明文 (ADR-427)。
    #[test]
    fn payload_plaintext_exposes_all() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["user_name"], Value::from("wxid_friend_002"));
        assert_eq!(o["content"], Value::from("你好我是隔壁老王"));
        assert!(!o.contains_key("content_sha"));
    }

    /// K-R4: 默认 payload 不含任何裸敏感值 (含打招呼语)。
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["wxid_friend_002", "wxid_acct_001", "隔壁老王"] {
            assert!(!dumped.contains(raw), "K-R4: 默认 payload 泄裸值 {raw}");
        }
    }

    /// K-R4: 手写 Debug 不泄 user_name / content 原文。
    #[test]
    fn debug_redacts_sensitive() {
        let dbg = format!("{:?}", sample());
        for raw in ["wxid_friend_002", "wxid_acct_001", "隔壁老王"] {
            assert!(!dbg.contains(raw), "Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("user_name_sha8"));
        assert!(dbg.contains("content_len"), "content 只露字符数");
        assert!(dbg.contains("scene"));
    }
}
