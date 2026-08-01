//! event::assembly — event → event_seq 装配 (ADR-413 §3 完整公式收口).
//!
//! 本 mod = PR2-3-k: [`compute_event_seq`] 串整条 fingerprint 管线:
//!   canonical_raw_values(event) → content_digest → EventFingerprint::compute(provenance + src_create_time + content_digest).
//!
//! 这是 decoder-event 纯逻辑管线的【收口】. 上游 decode 实现 (源 db 页 → DecodedEvent + 按 §4 fallback 矩阵
//! 取 src_create_time) 推 §11.5-9 adapter (需真实 db 页才可验证).

use super::canonical::canonical_raw_values;
use super::decoded::DecodedEvent;
use super::fingerprint::{content_digest, EventFingerprint};
use super::privacy::sha256_hex;

/// 算一个 [`DecodedEvent`] 的 event_seq fingerprint (ADR-413 §3 完整公式).
///
/// 串: `content_digest(canonical_raw_values(event))` → [`EventFingerprint::compute`] 外层 canonical_bytes
/// (account_id_sha = sha256(provenance.account_id) / source / source_native_id / event_action / src_create_time_ms / content_digest_hex).
///
/// `src_create_time_ms`: 调用方 (decoder/adapter) 按 ADR-413 §4 fallback 矩阵从源 db 取 (禁用 ingest/emit 时间).
/// **system_event (cursor_update / error) 强制 0** (§4 固定常量) — 本函数内部 override, 防调用方误传非 0.
///
/// 重放保证: 同源事件重放 → 同 DecodedEvent + 同 src_create_time → 同 fingerprint → 同 event_seq → 5 元组去重.
#[must_use]
pub fn compute_event_seq(event: &DecodedEvent, src_create_time_ms: u64) -> EventFingerprint {
    let prov = event.provenance();
    // §4: system_event src_create_time_ms 固定 0; 内部强制以防调用方误传.
    let effective_time = match event {
        DecodedEvent::SystemCursorUpdate(_) | DecodedEvent::SystemError(_) => 0,
        _ => src_create_time_ms,
    };
    let content_digest_hex = content_digest(&canonical_raw_values(event));
    EventFingerprint::compute(
        &sha256_hex(prov.account_id.as_str()),
        &prov.source,
        &prov.source_native_id,
        prov.event_action.as_str(),
        effective_time,
        &content_digest_hex,
    )
}

#[cfg(test)]
mod tests {
    use super::super::chatroom::ChatroomCreate;
    use super::super::message::MessageCreate;
    use super::super::provenance::Provenance;
    use super::super::system::SystemCursorUpdate;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn msg(account: &str, conv: &str, text: &str, src_native: &str) -> DecodedEvent {
        DecodedEvent::Message(MessageCreate {
            provenance: Provenance {
                account_id: Wxid::try_new(account).unwrap(),
                source: "message_5.db".to_string(),
                source_native_id: src_native.to_string(),
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
            conv_id: conv.to_string(),
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
            text_content: text.to_string(),
            msg_source: String::new(),
        })
    }

    /// 端到端 golden (Rust 对 Python 独立复算): message → event_seq 整条管线.
    #[test]
    fn message_end_to_end_golden() {
        let ev = msg("wxid_acct_001", "wxid_conv_x", "hi there", "Msg_test:1");
        let fp = compute_event_seq(&ev, 1_700_000_000_000);
        assert_eq!(
            fp.fingerprint_hex, "3de08b9332f89ffe6081b2975f28e09f52ab2f3c9fe4af6bb24d7db3e292c4a9",
            "message 端到端 fingerprint (Rust+Python 交叉验)"
        );
        assert_eq!(fp.event_seq, 4_458_717_095_428_399_102, "message 端到端 event_seq");
    }

    /// 重放幂等: 同事件 + 同 src_create_time → 同 fingerprint (契约核心).
    #[test]
    fn deterministic_replay() {
        let a = compute_event_seq(&msg("wxid_acct_001", "wxid_c", "hi", "Msg_1:1"), 100);
        let b = compute_event_seq(&msg("wxid_acct_001", "wxid_c", "hi", "Msg_1:1"), 100);
        assert_eq!(a, b, "同源事件重放必同 fingerprint");
    }

    /// system_event 强制 src_create_time=0 (§4): 传非 0 跟传 0 同 fingerprint.
    #[test]
    fn system_event_forces_zero_time() {
        let cursor = || {
            DecodedEvent::SystemCursorUpdate(SystemCursorUpdate {
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
            })
        };
        let with_time = compute_event_seq(&cursor(), 999_999);
        let with_zero = compute_event_seq(&cursor(), 0);
        assert_eq!(
            with_time, with_zero,
            "§4: system 事件 src_create_time 强制 0, 传啥都一样"
        );
    }

    /// 不同 src_create_time → 不同 fingerprint (群成员先退后加再退反例: 区分多实例).
    #[test]
    fn different_src_time_different_fingerprint() {
        let a = compute_event_seq(&msg("wxid_acct_001", "wxid_c", "hi", "Msg_1:1"), 100);
        let b = compute_event_seq(&msg("wxid_acct_001", "wxid_c", "hi", "Msg_1:1"), 200);
        assert_ne!(a.fingerprint_hex, b.fingerprint_hex, "不同源时间 → 不同 fingerprint");
    }

    /// 不同 content (正文) → 不同 content_digest → 不同 fingerprint.
    #[test]
    fn different_content_different_fingerprint() {
        let a = compute_event_seq(&msg("wxid_acct_001", "wxid_c", "hi", "Msg_1:1"), 100);
        let b = compute_event_seq(&msg("wxid_acct_001", "wxid_c", "bye", "Msg_1:1"), 100);
        assert_ne!(a.fingerprint_hex, b.fingerprint_hex, "不同正文 → 不同 fingerprint");
    }

    /// 不同 account_id (多账号隔离) → 不同 fingerprint (account_id_sha 进外层 canonical_bytes).
    #[test]
    fn different_account_different_fingerprint() {
        let a = compute_event_seq(&msg("wxid_acct_001", "wxid_c", "hi", "Msg_1:1"), 100);
        let b = compute_event_seq(&msg("wxid_acct_002", "wxid_c", "hi", "Msg_1:1"), 100);
        assert_ne!(a.fingerprint_hex, b.fingerprint_hex, "不同账号 → 不同 fingerprint");
    }

    /// 非 system 事件用传入的 src_create_time (chatroom create 不被强制 0).
    #[test]
    fn non_system_uses_passed_time() {
        let cr = || {
            DecodedEvent::ChatroomCreate(ChatroomCreate {
                is_still_member: true,
                provenance: Provenance {
                    account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                    source: "chatroom.db".to_string(),
                    source_native_id: "Chatroom_ab".to_string(),
                    event_type: EventType::ChatroomUpdate,
                    event_action: EventAction::Create,
                    event_seq: 0,
                    ingest_time: 0,
                },
                chatroom_id: "x@chatroom".to_string(),
                chatroom_name: "群".to_string(),
                chatroom_remark: None,
                announcement: None,
                owner_wxid: None,
                member_count: 8,
                announcement_editor: None,
                announcement_publish_time: 0,
                xml_announcement: None,
                chat_room_status: 0,
            })
        };
        let t1 = compute_event_seq(&cr(), 100);
        let t2 = compute_event_seq(&cr(), 200);
        assert_ne!(
            t1.fingerprint_hex, t2.fingerprint_hex,
            "chatroom create 用传入 time, 非强制 0"
        );
    }
}
