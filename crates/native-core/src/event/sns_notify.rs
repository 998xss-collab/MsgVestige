//! event::sns_notify — (sns_notify_update, create) 事件字段集. 朋友圈互动通知
//! (sns.db `SnsMessage_tmp3`) 一条 = 一条"谁赞/评论了我"的通知流记录 (谁 + 何时 + 哪条动态 + 评论文本)。
//!
//! 照 [`super::moment_feed::MomentFeedCreate`] 模板 (sns.db 独立表 → alpha 事件; 结构完全同型)。
//! **真库坐实** (inspect 加密 sns.db `SnsMessage_tmp3` 688 行): 通知流, 一行一条互动通知。
//! 列: comment_id (通知稳定 id = 锚点/身份) / feed_id (哪条动态 tid, 100% 非零, 79% 不在 SnsTimeLine=本表独有价值) /
//! type (1赞/2评论/4其它) / from_username (谁互动我, 100% 覆盖) / create_time (互动时刻) /
//! from_nickname (19%) / to_username (回复对象 22%) / to_nickname / content (评论文本 45%) /
//! is_unread (⚠️本账号真库全 0, 无区分度, 但列存着对别的账号有值; 同批G is_starred 本账号 0 先例) /
//! del_status / is_relative_me。
//!
//! ## content_digest (canonical.rs sns_notify 臂, 恰 5 元)
//! comment_id / feed_id / from_user_sha / notify_type / create_time — 通知的不可变身份。
//! is_unread/del_status/content/from_nickname/to_user/to_nickname/is_relative_me 只进 L2 不进 digest
//! (照 moment_feed 的 last_read_time/is_read 只进 L2)。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — from_user/to_user 经 [`sha8`]; from_nickname/to_nickname/content
//!   经 opt_sha8; 数字元数据明文。
//! - from_user 出 payload 走 [`FieldCategory::Id`] (默认 sha); to_user 走可空 Id。content 走 TextContent。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, render_opt_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (sns_notify_update, create) 事件字段集 — 一条朋友圈互动通知 (sns.db `SnsMessage_tmp3`)。
///
/// `source_native_id` = `"SnsNotify_<comment_id>"` (comment_id 是通知稳定 id, 非 PII 直用; 真库唯一定位一条通知)。
pub struct SnsNotifyCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 通知稳定 id (SnsMessage_tmp3.comment_id; anchor + digest 身份)。
    pub comment_id: i64,
    /// 哪条动态 (SnsMessage_tmp3.feed_id = 动态 tid; 元数据; 进 digest; 真库 100% 非零)。
    pub feed_id: i64,
    /// 通知类型 (SnsMessage_tmp3.type; 1赞/2评论/4其它; 元数据; 进 digest)。
    pub notify_type: i64,
    /// 谁互动我 (SnsMessage_tmp3.from_username; id 类; 进 digest 用 sha; 100% 覆盖)。
    pub from_user: String,
    /// 互动时刻 (SnsMessage_tmp3.create_time; unix 秒; 进 digest)。
    pub create_time: i64,

    // ── 只进 L2 (不进 digest) ──
    /// 互动者缓存昵称 (SnsMessage_tmp3.from_nickname; display 类, nullable; 19% 覆盖; L2 明文, Debug sha8)。
    pub from_nickname: Option<String>,
    /// 回复对象 wxid (SnsMessage_tmp3.to_username; id 类, nullable; 22% 覆盖; L2 明文, Debug sha8)。
    pub to_user: Option<String>,
    /// 回复对象缓存昵称 (SnsMessage_tmp3.to_nickname; display 类, nullable; L2 明文, Debug sha8)。
    pub to_nickname: Option<String>,
    /// 评论文本 (SnsMessage_tmp3.content; text 类, nullable; 45% 覆盖; 空串→None; L2 明文, Debug sha8)。
    pub content: Option<String>,
    /// 是否未读 (SnsMessage_tmp3.is_unread; ⚠️本账号真库全 0 无区分度, 但列存着; 元数据; 只进 L2)。
    pub is_unread: i64,
    /// 删除状态 (SnsMessage_tmp3.del_status; NULL→0; 元数据; 只进 L2)。
    pub del_status: i64,
    /// 是否与我相关 (SnsMessage_tmp3.is_relative_me; NULL→0; 元数据; 只进 L2)。
    pub is_relative_me: i64,
}

impl SnsNotifyCreate {
    /// 渲染整条 sns_notify_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // id 类 (from_user 必填 / to_user 可空 — 默认 sha).
        render_field(&mut out, "from_user", &self.from_user, FieldCategory::Id, mode);
        render_opt_field(&mut out, "to_user", self.to_user.as_deref(), FieldCategory::Id, mode);
        // display / text 类.
        render_opt_field(
            &mut out,
            "from_nickname",
            self.from_nickname.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "to_nickname",
            self.to_nickname.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "content",
            self.content.as_deref(),
            FieldCategory::TextContent,
            mode,
        );
        // 数字/元数据 — 直塞 (comment_id/feed_id 非 PII; 通知类型/时刻/状态元数据)。
        out.insert("comment_id".to_string(), Value::from(self.comment_id));
        out.insert("feed_id".to_string(), Value::from(self.feed_id));
        out.insert("notify_type".to_string(), Value::from(self.notify_type));
        out.insert("create_time".to_string(), Value::from(self.create_time));
        out.insert("is_unread".to_string(), Value::from(self.is_unread));
        out.insert("del_status".to_string(), Value::from(self.del_status));
        out.insert("is_relative_me".to_string(), Value::from(self.is_relative_me));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): from_user/to_user 经 sha8; from_nickname/to_nickname/content 经 opt_sha8;
/// comment_id/feed_id/时刻/类型/状态数字明文; provenance 自遮。**不准 derive Debug** — 会泄互动者 wxid / 评论正文裸值。
impl fmt::Debug for SnsNotifyCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("SnsNotifyCreate")
            .field("provenance", &self.provenance)
            .field("comment_id", &self.comment_id)
            .field("feed_id", &self.feed_id)
            .field("notify_type", &self.notify_type)
            .field("from_user_sha8", &sha8(self.from_user.as_bytes()))
            .field("create_time", &self.create_time)
            .field("from_nickname_sha8", &o(&self.from_nickname))
            .field("to_user_sha8", &o(&self.to_user))
            .field("to_nickname_sha8", &o(&self.to_nickname))
            .field("content_sha8", &o(&self.content))
            .field("is_unread", &self.is_unread)
            .field("del_status", &self.del_status)
            .field("is_relative_me", &self.is_relative_me)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> SnsNotifyCreate {
        SnsNotifyCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "sns.db".to_string(),
                source_native_id: "SnsNotify_123456789".to_string(),
                event_type: EventType::SnsNotifyUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
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
        }
    }

    /// 默认模式: from_user 脱敏 _sha; content/from_nickname 脱敏 _sha+_len; 数字元数据照原。
    #[test]
    fn payload_default_redacts() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["from_user_sha"], Value::from(sha256_hex("wxid_ijkl5678mnop901")));
        assert!(!o.contains_key("from_user"), "K-R4: 默认不出裸互动者 wxid");
        assert_eq!(o["to_user_sha"], Value::from(sha256_hex("wxid_reply_target")));
        assert_eq!(o["content_sha"], Value::from(sha256_hex("评论正文")));
        assert_eq!(o["content_len"], Value::from(4_i64), "评论正文 = 4 字符");
        assert_eq!(o["from_nickname_sha"], Value::from(sha256_hex("小明昵称")));
        // to_nickname None → null 占位 (display 类)。
        assert_eq!(o["to_nickname_sha"], Value::Null);
        // 元数据照原。
        assert_eq!(o["comment_id"], Value::from(123_456_789_i64));
        assert_eq!(o["feed_id"], Value::from(-3_652_952_694_686_404_033_i64));
        assert_eq!(o["notify_type"], Value::from(2));
        assert_eq!(o["create_time"], Value::from(1_763_557_360_i64));
        assert_eq!(o["is_unread"], Value::from(0));
    }

    /// plaintext: from_user 明文 (ADR-427)。
    #[test]
    fn payload_plaintext_exposes() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["from_user"], Value::from("wxid_ijkl5678mnop901"));
        assert_eq!(o["content"], Value::from("评论正文"));
    }

    /// K-R4: 默认 payload + Debug 不泄裸互动者 wxid / 评论正文。
    #[test]
    fn k_r4_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        let dbg = format!("{:?}", sample());
        for raw in [
            "wxid_ijkl5678mnop901",
            "wxid_reply_target",
            "wxid_acct_001",
            "评论正文",
            "小明昵称",
        ] {
            assert!(!dumped.contains(raw), "K-R4: payload 泄裸值 {raw}");
            assert!(!dbg.contains(raw), "K-R4: Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("from_user_sha8"));
    }
}
