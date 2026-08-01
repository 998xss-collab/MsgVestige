//! event::red_envelope — (red_envelope_update, create) 事件字段集. 微信红包 (general.db `redEnvelopeTable`) 一条。
//!
//! 照 [`super::transfer::TransferCreate`] 模板 (ADR-468 交易系列件2)。数据源 = general.db `redEnvelopeTable`。
//! 红包随领取状态变会 UPDATE (hb_status/receive_status) → 全表重扫 + content_digest 去重 (状态进 digest →
//! 状态变即产新 fingerprint = 领取流水) + UPSERT。扩 alpha 第 13 事件类型。
//!
//! **金额不在本表** (在消息 XML / native_url 领取详情, 系列后置件解); **无时间列** (红包时间靠 message_server_id
//! JOIN 原消息 create_time)。
//!
//! ## content_digest (canonical.rs red_envelope 臂)
//! send_id / sender_user_name_sha / hb_type / hb_status / receive_status — 唯一标识 (send_id 真库 100% 唯一) +
//! 发送者 + 类型 + 领取状态 (5 元)。message_server_id / session_name / native_url / scene_id 只进 L2。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 session_name / sender_user_name / native_url 裸值被误序列化。
//! - **手写 `Debug`** — session_name / sender_user_name 经 [`sha8`]; `native_url` **只露长度** (真库实测 484/496
//!   的 URL query 里嵌 `sendusername=wxid_...` → 绝不露原文)。send_id 是红包单号非 wxid, 原样。
//! - **`native_url` 出 payload 走 [`FieldCategory::Id`]** (默认 sha 不泄嵌入 wxid; plaintext 模式才出原 URL)。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (red_envelope_update, create) 事件字段集 — 一条红包 (general.db `redEnvelopeTable`)。
///
/// `source_native_id` = `"RedEnvelope_<send_id>"` (send_id 是红包单号, 非 PII)。
pub struct RedEnvelopeCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 红包单号 (redEnvelopeTable.send_id; TEXT, 真库 100% 唯一; 元数据非 wxid; 进 digest — 红包身份)。
    pub send_id: String,
    /// 红包消息 server_id (redEnvelopeTable.message_server_id; 元数据; 链回聊天消息取时间; 只进 L2)。
    pub message_server_id: i64,
    /// 会话 (redEnvelopeTable.session_name; id 类: wxid / @chatroom; 真库 413/496 群红包; 只进 L2, Debug sha8)。
    pub session_name: String,
    /// 发送者 (redEnvelopeTable.sender_user_name; id 类 wxid; 进 digest 用 sha)。
    pub sender_user_name: String,
    /// 领取 URL (redEnvelopeTable.native_url; wxpay://... 元数据; **query 嵌 sendusername=wxid** →
    /// Debug 只露长度 + payload 走 Id 类默认 sha; 只进 L2; 供后置件取红包详情/金额)。
    pub native_url: String,
    /// 场景 id (redEnvelopeTable.scene_id; 元数据; 只进 L2)。
    pub scene_id: i64,
    /// 红包状态 (redEnvelopeTable.hb_status; 进 digest — 状态变即新 fingerprint)。
    pub hb_status: i64,
    /// 红包类型 (redEnvelopeTable.hb_type; 0=普通/1=拼手气; 进 digest)。
    pub hb_type: i64,
    /// 领取状态 (redEnvelopeTable.receive_status; 进 digest — 领取变即新 fingerprint)。
    pub receive_status: i64,
}

impl RedEnvelopeCreate {
    /// 渲染整条 red_envelope_update.create 的 payload_json (唯一出口)。
    ///
    /// 红包 immutable per digest (hb_status/receive_status 变即产新 fingerprint→新 archive) → 全字段进 payload。
    /// `native_url` 走 [`FieldCategory::Id`] (K-R4: 默认 sha 不泄嵌入 wxid; plaintext 才出原 URL)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // id 类 (session_name / sender_user_name — 默认 sha, plaintext 明文).
        render_field(&mut out, "session_name", &self.session_name, FieldCategory::Id, mode);
        render_field(
            &mut out,
            "sender_user_name",
            &self.sender_user_name,
            FieldCategory::Id,
            mode,
        );
        // native_url 嵌 wxid → 按 id 类脱敏 (默认 native_url_sha; plaintext 出原 URL 供取详情).
        render_field(&mut out, "native_url", &self.native_url, FieldCategory::Id, mode);
        // 元数据 string (send_id — 红包单号非 wxid, 恒明文).
        render_field(&mut out, "send_id", &self.send_id, FieldCategory::Metadata, mode);
        // 数字元数据 — 直塞 (天然非敏感).
        out.insert("message_server_id".to_string(), Value::from(self.message_server_id));
        out.insert("scene_id".to_string(), Value::from(self.scene_id));
        out.insert("hb_status".to_string(), Value::from(self.hb_status));
        out.insert("hb_type".to_string(), Value::from(self.hb_type));
        out.insert("receive_status".to_string(), Value::from(self.receive_status));

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): session_name / sender_user_name 经 sha8; `native_url` **只露长度** (嵌 wxid, 绝不露原文);
/// provenance 自遮。send_id 是红包单号非 wxid, 原样。**不准 derive Debug**。
impl fmt::Debug for RedEnvelopeCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedEnvelopeCreate")
            .field("provenance", &self.provenance)
            .field("send_id", &self.send_id)
            .field("message_server_id", &self.message_server_id)
            .field("session_name_sha8", &sha8(self.session_name.as_bytes()))
            .field("sender_user_name_sha8", &sha8(self.sender_user_name.as_bytes()))
            .field("native_url_len", &self.native_url.len())
            .field("scene_id", &self.scene_id)
            .field("hb_status", &self.hb_status)
            .field("hb_type", &self.hb_type)
            .field("receive_status", &self.receive_status)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    const URL_WITH_WXID: &str =
        "wxpay://c2cbizmessagehandler/hongbao/receivehongbao?sendid=100003&sendusername=wxid_sender_002&ver=6";

    fn sample() -> RedEnvelopeCreate {
        RedEnvelopeCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "general.db".to_string(),
                source_native_id: "RedEnvelope_1000039801202604206261068705009".to_string(),
                event_type: EventType::RedEnvelopeUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            send_id: "1000039801202604206261068705009".to_string(),
            message_server_id: 461_510_149_866_340,
            session_name: "wxid_peer_002".to_string(),
            sender_user_name: "wxid_sender_002".to_string(),
            native_url: URL_WITH_WXID.to_string(),
            scene_id: 1002,
            hb_status: 1,
            hb_type: 0,
            receive_status: 0,
        }
    }

    /// 默认模式: id 类脱敏 _sha; native_url 也脱敏 (嵌 wxid); send_id/数字元数据照原。
    #[test]
    fn payload_default_redacts_id_and_url() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["sender_user_name_sha"], Value::from(sha256_hex("wxid_sender_002")));
        assert_eq!(o["session_name_sha"], Value::from(sha256_hex("wxid_peer_002")));
        assert_eq!(
            o["native_url_sha"],
            Value::from(sha256_hex(URL_WITH_WXID)),
            "native_url 默认 sha"
        );
        assert!(!o.contains_key("native_url"), "K-R4: 默认不出裸 native_url (嵌 wxid)");
        assert!(!o.contains_key("sender_user_name"), "K-R4: 默认不出裸 sender");
        // 元数据照原.
        assert_eq!(
            o["send_id"],
            Value::from("1000039801202604206261068705009"),
            "红包单号非 wxid 照原"
        );
        assert_eq!(o["hb_type"], Value::from(0));
        assert_eq!(o["hb_status"], Value::from(1));
        assert_eq!(o["receive_status"], Value::from(0));
        assert_eq!(o["message_server_id"], Value::from(461_510_149_866_340_i64));
    }

    /// plaintext: session_name + sender + native_url 全明文 (ADR-427; native_url 出原 URL 供取详情)。
    #[test]
    fn payload_plaintext_exposes_all() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["sender_user_name"], Value::from("wxid_sender_002"));
        assert_eq!(o["session_name"], Value::from("wxid_peer_002"));
        assert_eq!(o["native_url"], Value::from(URL_WITH_WXID));
        assert!(!o.contains_key("native_url_sha"));
    }

    /// K-R4: 默认 payload 不含任何裸敏感值 (含 native_url 里嵌的 sender wxid)。
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["wxid_sender_002", "wxid_peer_002", "wxid_acct_001"] {
            assert!(!dumped.contains(raw), "K-R4: 默认 payload 泄裸值 {raw}");
        }
        assert!(
            !dumped.contains("sendusername=wxid"),
            "K-R4: 默认 payload 泄 native_url 里的 wxid"
        );
    }

    /// K-R4: 手写 Debug 不泄 session_name / sender / native_url 原文 (含 URL 里的 wxid)。
    #[test]
    fn debug_redacts_sensitive() {
        let dbg = format!("{:?}", sample());
        for raw in ["wxid_sender_002", "wxid_peer_002", "wxid_acct_001", "sendusername"] {
            assert!(!dbg.contains(raw), "Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("sender_user_name_sha8"));
        assert!(dbg.contains("native_url_len"), "native_url 只露长度");
        assert!(
            dbg.contains("1000039801202604206261068705009"),
            "send_id 非 wxid 原样可见"
        );
    }
}
