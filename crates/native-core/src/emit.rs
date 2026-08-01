//! emit — DecodedEvent → raw_payload_archive 行装配 (native-core 子系统, ADR-416 §3.2.1).
//!
//! 本 mod = PR2-4-a: [`RawPayloadRecord`] (L1 raw_payload_archive 8 非 id 列, schema §3.1.2) +
//! [`emit`] 装配 (串 decoder-event 全管线: compute_event_seq + to_payload_json). 桥接 event → storage.
//!
//! ## 无失败路径
//! [`DecodedEvent`] 的 10 个变体【天生】都是 config-events §7.3 的 alpha 合法 (event_type, event_action)
//! 组合 (PR2-3-i `every_variant_is_alpha_valid_combo` 实证), 故 `is_alpha_valid_combo` 闸门在本层恒真,
//! emit 对 DecodedEvent 不会失败 — 纯装配, 返 `RawPayloadRecord` 非 `Result`.
//!
//! ## K-R4
//! - `account_id_sha` 已是 sha (安全); `payload_json` = 隐私过滤后输出 (ADR-426 §2.2: archive 默认明文
//!   canonical [`PrivacyMode::archive_canonical`]; 脱敏 [`PrivacyMode::default_sha`] 供出底座边界 §2.4).
//! - **手写 Debug** 把 `payload_json` 转 sha8+len — 防明文 payload 经 log 泄露 (出口红线, 不论模式).

use std::fmt;

use serde_json::Value;

use crate::event::decoded::DecodedEvent;
use crate::event::privacy::PrivacyMode;
use crate::key_provider::sha8;
use crate::sha256_hex;

// PR2-7-a: alpha EventEmitter = 同进程 tokio mpsc bounded channel (adapter-适配器.md §; 载 RawPayloadRecord).
pub mod in_proc;

/// 一条 raw_payload_archive 记录 (L1 schema §3.1.2 的 8 非 id 列; id 由 storage AUTOINCREMENT 赋).
///
/// 5 元组去重键 = (account_id_sha, source, source_native_id, event_action, event_seq) (schema UNIQUE).
pub struct RawPayloadRecord {
    /// 多账号隔离 = sha256(account_id) (永远 sha, 非裸 wxid).
    pub account_id_sha: String,
    /// 源 db 文件名 (e.g. "message_5.db").
    pub source: String,
    /// 源 db 实例锚点 (复合 md5, e.g. "Msg_<md5>:86680").
    pub source_native_id: String,
    /// 事件类型 snake_case ("message" / "contact_update" / ...).
    pub event_type: String,
    /// 事件动作 snake_case ("create" / "member_add" / ...).
    pub event_action: String,
    /// 确定性 fingerprint 生成的稳定序号 (ADR-413; 重放幂等去重锚点).
    pub event_seq: i64,
    /// adapter emit 时间毫秒 (**非**源消息时间; 不进 fingerprint).
    pub ingest_time: i64,
    /// 隐私过滤后的 payload JSON 串 (默认 sha 模式; plaintext 模式才含明文敏感字段).
    pub payload_json: String,
}

/// 把 [`DecodedEvent`] 装配成一条 [`RawPayloadRecord`] (ADR-416 emit 层; 无失败路径见 mod 文档).
///
/// - `src_create_time_ms`: 源 db 事件时间 (decoder 按 ADR-413 §4 矩阵取; system_event 内部强制 0).
/// - `ingest_time`: adapter emit 时间毫秒 (调用方给; 不进 fingerprint, 仅存储 + 24h 滚动删用).
/// - `mode`: 隐私模式 (默认全 sha; 控制 payload_json 明文范围).
#[must_use]
pub fn emit(event: &DecodedEvent, src_create_time_ms: u64, ingest_time: i64, mode: PrivacyMode) -> RawPayloadRecord {
    let prov = event.provenance();
    let fingerprint = crate::event::assembly::compute_event_seq(event, src_create_time_ms);
    let payload: Value = event.to_payload_json(mode);
    RawPayloadRecord {
        account_id_sha: sha256_hex(prov.account_id.as_str()),
        source: prov.source.clone(),
        source_native_id: prov.source_native_id.clone(),
        event_type: event.event_type().as_str().to_string(),
        event_action: event.event_action().as_str().to_string(),
        event_seq: fingerprint.event_seq,
        ingest_time,
        payload_json: serde_json::to_string(&payload).expect("payload_json Value 序列化不会失败"),
    }
}

/// 手写 Debug (K-R4): payload_json 转 sha8+len (防 plaintext 模式 payload 经 log 泄露); 其余字段已安全.
impl fmt::Debug for RawPayloadRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawPayloadRecord")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("event_type", &self.event_type)
            .field("event_action", &self.event_action)
            .field("event_seq", &self.event_seq)
            .field("ingest_time", &self.ingest_time)
            .field("payload_json_sha8", &sha8(self.payload_json.as_bytes()))
            .field("payload_json_len", &self.payload_json.chars().count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::message::MessageCreate;
    use crate::event::provenance::Provenance;
    use crate::event::system::SystemCursorUpdate;
    use crate::event::{EventAction, EventType};
    use crate::key_provider::Wxid;

    fn sample_message() -> DecodedEvent {
        DecodedEvent::Message(MessageCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "message_5.db".to_string(),
                source_native_id: "Msg_test:1".to_string(),
                event_type: EventType::Message,
                event_action: EventAction::Create,
                event_seq: 0,
                ingest_time: 0,
            },
            server_id: "555".to_string(),
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            conv_id: "wxid_conv_x".to_string(),
            sender_wxid: Wxid::try_new("wxid_send_y").unwrap(),
            create_time: 0,
            sort_seq: 0,
            msg_type: 1,
            msg_sub_type: Some(0),
            msg_type_name: "TEXT".to_string(),
            msg_sub_type_name: None,
            status: 0,
            local_type_raw: 0,
            is_chatroom: false,
            raw_xml_present: false,
            decode_kind: "plain".to_string(),
            text_content: "hi there".to_string(),
            msg_source: String::new(),
        })
    }

    /// emit 装配: 8 列正确 + event_seq 跟 compute_event_seq 一致 + 5 元组键齐.
    #[test]
    fn emit_message_record_fields() {
        let ev = sample_message();
        let rec = emit(&ev, 1_700_000_000_000, 1_800_000_000_000, PrivacyMode::default_sha());
        // account_id_sha = sha256(account_id) 非裸
        assert_eq!(rec.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_ne!(rec.account_id_sha, "wxid_acct_001");
        assert_eq!(rec.source, "message_5.db");
        assert_eq!(rec.source_native_id, "Msg_test:1");
        assert_eq!(rec.event_type, "message");
        assert_eq!(rec.event_action, "create");
        // event_seq 跟 compute_event_seq 端到端一致 (golden seq from PR2-3-k)
        assert_eq!(rec.event_seq, 4_458_717_095_428_399_102);
        assert_eq!(rec.ingest_time, 1_800_000_000_000);
        // payload_json 是合法 JSON 串
        let parsed: Value = serde_json::from_str(&rec.payload_json).unwrap();
        assert_eq!(parsed["event_type"], Value::from("message"));
        assert!(parsed.as_object().unwrap().contains_key("text_content_sha"));
    }

    /// K-R4: 脱敏模式 (default_sha, 出边界用) payload_json 不含裸敏感值 — 脱敏能力保留 (ADR-426 §2.4).
    #[test]
    fn emit_default_payload_no_raw_leak() {
        let rec = emit(&sample_message(), 1_700_000_000_000, 1, PrivacyMode::default_sha());
        for raw in ["wxid_conv_x", "wxid_send_y", "wxid_acct_001", "hi there"] {
            assert!(!rec.payload_json.contains(raw), "K-R4: payload_json 泄裸值 {raw}");
        }
    }

    /// plaintext 模式: payload_json 含明文 (用户显式开启) — 但 record 仍正确装配.
    #[test]
    fn emit_plaintext_payload_has_plaintext() {
        let rec = emit(
            &sample_message(),
            1_700_000_000_000,
            1,
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        );
        assert!(rec.payload_json.contains("hi there"), "plaintext 模式 payload 含明文");
        // event_seq 不受隐私模式影响 (content_digest 用原值)
        assert_eq!(rec.event_seq, 4_458_717_095_428_399_102);
    }

    /// ADR-426 §2.2: archive_canonical (底座 archive 写入【缺省】) → payload_json 含明文真值 (canonical storage).
    #[test]
    fn emit_archive_canonical_has_plaintext() {
        let rec = emit(
            &sample_message(),
            1_700_000_000_000,
            1,
            PrivacyMode::archive_canonical(),
        );
        assert!(
            rec.payload_json.contains("hi there"),
            "archive 默认明文: 正文真值入 payload"
        );
        assert!(
            rec.payload_json.contains("wxid_conv_x"),
            "archive 默认明文: 会话 id 真值入 payload"
        );
        // event_seq 不受隐私模式影响 (content_digest 用原值, fingerprint 隔离 §2.7.3)
        assert_eq!(rec.event_seq, 4_458_717_095_428_399_102);
    }

    /// ingest_time 不影响 event_seq (5 元组去重不含 ingest_time, 同事件不同 ingest 仍同 seq).
    #[test]
    fn ingest_time_does_not_affect_event_seq() {
        let a = emit(&sample_message(), 1_700_000_000_000, 111, PrivacyMode::default_sha());
        let b = emit(&sample_message(), 1_700_000_000_000, 999, PrivacyMode::default_sha());
        assert_eq!(a.event_seq, b.event_seq, "ingest_time 变 → event_seq 不变 (重放幂等)");
        assert_ne!(a.ingest_time, b.ingest_time);
    }

    /// system_event 装配 (cursor): event_seq 用强制 0 src_time 算.
    #[test]
    fn emit_system_cursor_record() {
        let ev = DecodedEvent::SystemCursorUpdate(SystemCursorUpdate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "message_5.db".to_string(),
                source_native_id: "cursor:m:msg:ab".to_string(),
                event_type: EventType::SystemEvent,
                event_action: EventAction::CursorUpdate,
                event_seq: 0,
                ingest_time: 0,
            },
            kind: "message".to_string(),
            watermark_key: "k".to_string(),
            watermark_value: "[1]".to_string(),
            last_update: 0,
        });
        let rec = emit(&ev, 0, 1, PrivacyMode::default_sha());
        assert_eq!(rec.event_type, "system_event");
        assert_eq!(rec.event_action, "cursor_update");
        assert!(rec.event_seq >= 0, "event_seq 是 i63 非负");
    }

    /// K-R4: 手写 Debug 不泄 payload_json 原文 (默认模式已 sha, 但 Debug 仍只出 sha8+len).
    #[test]
    fn debug_redacts_payload_json() {
        let rec = emit(
            &sample_message(),
            1_700_000_000_000,
            1,
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        );
        let dbg = format!("{rec:?}");
        assert!(
            !dbg.contains("hi there"),
            "K-R4: Debug 不准出 payload_json 原文 (即便 plaintext 模式)"
        );
        assert!(!dbg.contains("wxid_conv_x"));
        assert!(dbg.contains("payload_json_sha8"));
        assert!(dbg.contains("payload_json_len"));
        // account_id_sha (已 sha) 可见
        assert!(dbg.contains(&sha256_hex("wxid_acct_001")));
    }
}
