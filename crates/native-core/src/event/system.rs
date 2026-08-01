//! event::system — system_event 2 个 action 字段集 (ADR-412 §3.x.6/7).
//!
//! 本 mod = PR2-3-g (7 事件字段集收官): [`SystemCursorUpdate`] (cursor_update) /
//! [`SystemError`] (error) — raw_payload 内部状态事件 (§5.2 真 12 类数据范围之外).
//!
//! ## K-R4 红线
//! - 两 struct 都 **不 derive `Serialize`** (唯一出口 to_payload_json).
//! - [`SystemCursorUpdate`] **无敏感业务字段** (kind/watermark 全元数据) → `#[derive(Debug)]` 安全
//!   (account_id 由 [`Provenance`] Debug 自遮); [`SystemError`] 有 error_message/context_json
//!   (text_content 类) → **手写 Debug** 脱敏.
//!
//! ## context_json 特判 (§3.x.7 nuance)
//! context_json 是 text_content 类【开关语义】 (--enable-text-content/plaintext 出明文), 但字段表
//! **只列 context_json_sha 无 context_json_len** (跟 error_message 有 _len 不同) — 故不走标准
//! [`render_field`] (它对 text_content 必加 _len), 用本 mod 的 [`render_context_json`] 特判.

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, sha256_hex, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (system_event, cursor_update) 字段集 (ADR-412 §3.x.6) — 重放水位锚点.
///
/// 业务字段全 **元数据类** (无 id/display/text 敏感字段 — account_id/source_native_id 在 provenance).
/// 故本 struct `#[derive(Debug)]` 安全.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemCursorUpdate {
    /// 共享溯源头 (source_native_id = `"cursor:<db>:<kind>:<md5_hex(...)>"`).
    pub provenance: Provenance,
    /// 水位类别 "message" / "contact_update" / "chatroom_update" (元数据).
    pub kind: String,
    /// 水位键描述 "(create_time, sort_seq, local_id)" (元数据).
    pub watermark_key: String,
    /// 水位值 JSON 元组 e.g. `"[1780000000, ...]"` (元数据).
    pub watermark_value: String,
    /// 水位最后变化时间毫秒 (元数据, 临时).
    pub last_update: i64,
}

impl SystemCursorUpdate {
    /// 渲染 system_event.cursor_update payload_json (§3.x.6 + §3.y, 唯一出口).
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // 业务字段全元数据 — 字符串走 render_field Metadata (原名明文), 数字直塞.
        render_field(&mut out, "kind", &self.kind, FieldCategory::Metadata, mode);
        render_field(
            &mut out,
            "watermark_key",
            &self.watermark_key,
            FieldCategory::Metadata,
            mode,
        );
        render_field(
            &mut out,
            "watermark_value",
            &self.watermark_value,
            FieldCategory::Metadata,
            mode,
        );
        out.insert("last_update".to_string(), Value::from(self.last_update));
        Value::Object(out)
    }
}

/// context_json 特判渲染 (§3.x.7): text_content 隐私【开关】语义 (--enable-text-content / plaintext
/// 出明文), 但**无 _len** (字段表只列 context_json_sha, 不同于 error_message 有 _len). nullable.
fn render_context_json(out: &mut Map<String, Value>, opt: Option<&str>, mode: PrivacyMode) {
    let plaintext = mode.is_plaintext(FieldCategory::TextContent);
    match (opt, plaintext) {
        (Some(cj), true) => {
            out.insert("context_json".to_string(), Value::from(cj));
        }
        (Some(cj), false) => {
            out.insert("context_json_sha".to_string(), Value::from(sha256_hex(cj)));
        }
        (None, true) => {
            out.insert("context_json".to_string(), Value::Null);
        }
        (None, false) => {
            out.insert("context_json_sha".to_string(), Value::Null);
        }
    }
}

/// (system_event, error) 字段集 (ADR-412 §3.x.7) — 内部错误事件.
///
/// 归桶: error_message / context_json = **text_content 类** (敏感); error_code /
/// occurred_at_canonical = **元数据类**. (无 id/display 业务字段 — account_id 在 provenance.)
pub struct SystemError {
    /// 共享溯源头 (source_native_id = `"error:<error_code>:<md5_hex(...)>"`).
    pub provenance: Provenance,
    /// 错误码枚举 (元数据, 跟 ADR-410 联动).
    pub error_code: String,
    /// 错误消息 raw (text_content 类: 默认 error_message_sha + error_message_len; 开关后明文).
    pub error_message: String,
    /// 错误上下文 JSON raw (text_content 类, nullable; **无 _len** — §3.x.7 特判, 见 [`render_context_json`]).
    pub context_json: Option<String>,
    /// 错误发生场景确定性派生值 (元数据 — cursor 位置 / 请求 id, 非 ingest_time).
    pub occurred_at_canonical: String,
}

impl SystemError {
    /// 渲染 system_event.error payload_json (§3.x.7 + §3.y, 唯一出口).
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // 元数据.
        render_field(&mut out, "error_code", &self.error_code, FieldCategory::Metadata, mode);
        render_field(
            &mut out,
            "occurred_at_canonical",
            &self.occurred_at_canonical,
            FieldCategory::Metadata,
            mode,
        );
        // text_content 类: error_message 标准 (_sha + _len); context_json 特判 (无 _len).
        render_field(
            &mut out,
            "error_message",
            &self.error_message,
            FieldCategory::TextContent,
            mode,
        );
        render_context_json(&mut out, self.context_json.as_deref(), mode);
        Value::Object(out)
    }
}

impl fmt::Debug for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemError")
            .field("provenance", &self.provenance)
            .field("error_code", &self.error_code)
            .field("error_message_sha8", &sha8(self.error_message.as_bytes()))
            .field(
                "context_json_sha8",
                &self.context_json.as_deref().map(|s| sha8(s.as_bytes())),
            )
            .field("occurred_at_canonical", &self.occurred_at_canonical)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn prov(action: EventAction) -> Provenance {
        Provenance {
            account_id: Wxid::try_new("wxid_acct_001").unwrap(),
            source: "message_5.db".to_string(),
            source_native_id: "cursor:message_5.db:message:ab12cd34".to_string(),
            event_type: EventType::SystemEvent,
            event_action: action,
            event_seq: 11,
            ingest_time: 1_700_000_000_000,
        }
    }

    fn cursor_sample() -> SystemCursorUpdate {
        SystemCursorUpdate {
            provenance: prov(EventAction::CursorUpdate),
            kind: "message".to_string(),
            watermark_key: "(create_time, sort_seq, local_id)".to_string(),
            watermark_value: "[1780000000, 5, 1009]".to_string(),
            last_update: 1_700_000_000_000,
        }
    }

    fn error_sample() -> SystemError {
        SystemError {
            provenance: prov(EventAction::Error),
            error_code: "DECODE_FAIL".to_string(),
            error_message: "解码失败: 第 3 页 CRC 不匹配".to_string(),
            context_json: Some(r#"{"page":3,"db":"message_5"}"#.to_string()),
            occurred_at_canonical: "cursor:message_5.db:message:ab12cd34".to_string(),
        }
    }

    /// cursor_update 默认: 业务字段全元数据明文; account_id 脱敏 (provenance).
    #[test]
    fn cursor_default_all_metadata_plaintext() {
        let o = cursor_sample().to_payload_json(PrivacyMode::default_sha());
        let o = o.as_object().unwrap();
        assert_eq!(o["kind"], Value::from("message"));
        assert_eq!(o["watermark_key"], Value::from("(create_time, sort_seq, local_id)"));
        assert_eq!(o["watermark_value"], Value::from("[1780000000, 5, 1009]"));
        assert_eq!(o["last_update"], Value::from(1_700_000_000_000_i64));
        // provenance: account_id 脱敏, source_native_id 锚点照原
        assert!(o.contains_key("account_id_sha"));
        assert_eq!(
            o["source_native_id"],
            Value::from("cursor:message_5.db:message:ab12cd34")
        );
    }

    /// cursor_update derive Debug 不泄 account_id (provenance 自遮), 业务字段全元数据可见.
    #[test]
    fn cursor_debug_redacts_account_via_provenance() {
        let dbg = format!("{:?}", cursor_sample());
        assert!(
            !dbg.contains("wxid_acct_001"),
            "K-R4: account_id 应由 provenance Debug 自遮"
        );
        assert!(dbg.contains("message"), "kind 元数据可见");
    }

    /// error 默认: error_message _sha + _len; context_json 只 _sha (无 _len, §3.x.7 特判); 元数据明文.
    #[test]
    fn error_default_text_redacted_context_no_len() {
        let o = error_sample().to_payload_json(PrivacyMode::default_sha());
        let o = o.as_object().unwrap();
        // error_message: text_content 标准 _sha + _len
        assert_eq!(
            o["error_message_sha"],
            Value::from(sha256_hex("解码失败: 第 3 页 CRC 不匹配"))
        );
        assert!(o.contains_key("error_message_len"), "error_message 有 _len");
        assert!(!o.contains_key("error_message"), "K-R4: 默认不出裸 error_message");
        // context_json: 特判 — 只 _sha, 【无 _len】
        assert_eq!(
            o["context_json_sha"],
            Value::from(sha256_hex(r#"{"page":3,"db":"message_5"}"#))
        );
        assert!(!o.contains_key("context_json_len"), "§3.x.7: context_json 无 _len");
        assert!(!o.contains_key("context_json"), "K-R4: 默认不出裸 context_json");
        // 元数据明文
        assert_eq!(o["error_code"], Value::from("DECODE_FAIL"));
        assert_eq!(
            o["occurred_at_canonical"],
            Value::from("cursor:message_5.db:message:ab12cd34")
        );
    }

    /// error --enable-text-content: error_message + context_json 明文, account_id (id) 仍 sha.
    #[test]
    fn error_text_switch_opens_text_not_id() {
        let o = error_sample().to_payload_json(PrivacyMode {
            enable_text_content: true,
            ..Default::default()
        });
        let o = o.as_object().unwrap();
        assert_eq!(o["error_message"], Value::from("解码失败: 第 3 页 CRC 不匹配"));
        assert_eq!(o["context_json"], Value::from(r#"{"page":3,"db":"message_5"}"#));
        assert!(!o.contains_key("context_json_sha"));
        assert!(o.contains_key("account_id_sha"), "id 类不受 text 开关影响");
    }

    /// error context_json None: 默认 → context_json_sha=null; plaintext → context_json=null.
    #[test]
    fn error_context_json_none() {
        let mut e = error_sample();
        e.context_json = None;
        let def = e.to_payload_json(PrivacyMode::default_sha());
        assert_eq!(def.as_object().unwrap()["context_json_sha"], Value::Null);
        let pt = e.to_payload_json(PrivacyMode {
            enable_text_content: true,
            ..Default::default()
        });
        assert_eq!(pt.as_object().unwrap()["context_json"], Value::Null);
    }

    /// K-R4: error 默认 payload + 手写 Debug 不泄 error_message / context_json / account_id 裸值.
    #[test]
    fn error_k_r4_no_leak() {
        let dumped = error_sample().to_payload_json(PrivacyMode::default_sha()).to_string();
        for raw in ["解码失败", "CRC 不匹配", r#"{"page":3"#] {
            assert!(!dumped.contains(raw), "K-R4: error payload 泄 {raw}");
        }
        let dbg = format!("{:?}", error_sample());
        for raw in ["解码失败", "CRC 不匹配", "wxid_acct_001", r#""page":3"#] {
            assert!(!dbg.contains(raw), "K-R4: error Debug 泄 {raw}");
        }
        assert!(dbg.contains("DECODE_FAIL"), "error_code 元数据可见");
    }
}
