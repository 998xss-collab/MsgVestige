//! event::transfer — (transfer_update, create) 事件字段集. 微信转账 (general.db `transferTable`) 一条。
//!
//! 照 [`super::favorite::FavoriteCreate`] 模板 (嵌 [`Provenance`] + to_payload_json + 手写 Debug + 不 derive Serialize)。
//! 数据源 = general.db `transferTable`。一条转账随状态推进 (发起→收款/退还) 会 UPDATE (pay_sub_type/last_update_time
//! 变) → 全表重扫 + content_digest 去重 (pay_sub_type 进 digest → 状态变即产新 fingerprint = 状态流水) + UPSERT
//! (同 favorite update_time)。ADR-468 扩 alpha 第 12 事件类型 (照收藏 ADR-454 先例)。
//!
//! 字段归桶: `session_name` (会话 wxid/@chatroom) / `pay_payer` / `pay_receiver` = id 类; `transfer_id` /
//! `transcation_id` / `message_server_id` / 时间 / flag = 元数据类。**金额不在本表** (在转账消息 XML feedesc,
//! 系列后续件从消息解) → 本事件只搬账号/状态/时间 + 消息链接 (message_server_id 供 JOIN 回原消息取金额)。
//!
//! ## content_digest (canonical.rs transfer 臂)
//! transfer_id / payer_sha / receiver_sha / pay_sub_type / begin_transfer_time — 唯一标识 (transfer_id 真库 100%
//! 唯一) + 双方 + 状态 + 起始时刻。其余 (transcation_id / message_server_id / 其它时间 / flag / session_name) 只进 L2。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 session_name / pay_payer / pay_receiver 裸值被误序列化。
//! - **手写 `Debug`** — 三个 id 类字段经 [`sha8`] 脱敏; provenance.account_id 自遮。transfer_id/transcation_id
//!   是交易单号非 wxid, 原样。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (transfer_update, create) 事件字段集 — 一条转账 (general.db `transferTable`)。
///
/// `source_native_id` = `"Transfer_<transfer_id>"` (transfer_id 是交易单号, 非 PII)。
pub struct TransferCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 微信转账单号 (transferTable.transfer_id; TEXT 31 位, 真库 100% 唯一; 元数据非 wxid; 进 digest — 转账身份)。
    pub transfer_id: String,
    /// 交易流水号 (transferTable.transcation_id; TEXT 银行侧流水; 元数据; 只进 L2)。
    pub transcation_id: String,
    /// 转账消息 server_id (transferTable.message_server_id; 元数据; 链回聊天消息取金额; 只进 L2)。
    pub message_server_id: i64,
    /// 收款确认消息 server_id (transferTable.second_message_server_id; 0=无/未收; 元数据; 只进 L2)。
    pub second_message_server_id: i64,
    /// 会话 (transferTable.session_name; id 类: wxid / @chatroom; 真库 402/1867 是群转账; 只进 L2, Debug sha8)。
    pub session_name: String,
    /// 状态 (transferTable.pay_sub_type; 1/2/3/4 = 发起/收款/已收/退还 等; 进 digest — 状态变即新 fingerprint)。
    pub pay_sub_type: i64,
    /// 付款方 (transferTable.pay_payer; id 类 wxid; 进 digest 用 sha)。
    pub pay_payer: String,
    /// 收款方 (transferTable.pay_receiver; id 类 wxid; 进 digest 用 sha)。
    pub pay_receiver: String,
    /// 发起时刻 (transferTable.begin_transfer_time; unix 秒; 不可变; 进 digest)。
    pub begin_transfer_time: i64,
    /// 末次修改 (transferTable.last_modified_time; unix 秒; 只进 L2)。
    pub last_modified_time: i64,
    /// 失效时刻 (transferTable.invalid_time; unix 秒, 通常 begin+24h; 只进 L2)。
    pub invalid_time: i64,
    /// 末次更新 (transferTable.last_update_time; unix 秒; 只进 L2)。
    pub last_update_time: i64,
    /// 延迟确认标志 (transferTable.delay_confirm_flag; 0/1; 只进 L2)。
    pub delay_confirm_flag: i64,
    /// 气泡点击标志 (transferTable.bubble_clicked_flag; 真库有 NULL, drain 已 COALESCE→0; 只进 L2)。
    pub bubble_clicked_flag: i64,
}

impl TransferCreate {
    /// 渲染整条 transfer_update.create 的 payload_json (唯一出口)。
    ///
    /// 转账 immutable per digest (pay_sub_type/begin_transfer_time 变即产新 fingerprint→新 archive), 无 server_seq 式
    /// 陈旧风险 → 全字段进 payload (含 transcation_id/msg_server_id/其它时间/flag 元数据)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // id 类 (session_name / pay_payer / pay_receiver — 默认 sha, plaintext 明文).
        render_field(&mut out, "session_name", &self.session_name, FieldCategory::Id, mode);
        render_field(&mut out, "pay_payer", &self.pay_payer, FieldCategory::Id, mode);
        render_field(&mut out, "pay_receiver", &self.pay_receiver, FieldCategory::Id, mode);
        // 元数据 string (transfer_id / transcation_id — 交易单号非 wxid, 恒明文).
        render_field(
            &mut out,
            "transfer_id",
            &self.transfer_id,
            FieldCategory::Metadata,
            mode,
        );
        render_field(
            &mut out,
            "transcation_id",
            &self.transcation_id,
            FieldCategory::Metadata,
            mode,
        );
        // 数字元数据 — 直塞 (天然非敏感).
        out.insert("message_server_id".to_string(), Value::from(self.message_server_id));
        out.insert(
            "second_message_server_id".to_string(),
            Value::from(self.second_message_server_id),
        );
        out.insert("pay_sub_type".to_string(), Value::from(self.pay_sub_type));
        out.insert("begin_transfer_time".to_string(), Value::from(self.begin_transfer_time));
        out.insert("last_modified_time".to_string(), Value::from(self.last_modified_time));
        out.insert("invalid_time".to_string(), Value::from(self.invalid_time));
        out.insert("last_update_time".to_string(), Value::from(self.last_update_time));
        out.insert("delay_confirm_flag".to_string(), Value::from(self.delay_confirm_flag));
        out.insert("bubble_clicked_flag".to_string(), Value::from(self.bubble_clicked_flag));

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): session_name / pay_payer / pay_receiver 经 sha8 脱敏; provenance 自遮。
/// **不准 derive Debug** — 会泄会话 wxid / 双方 wxid 裸值。transfer_id/transcation_id 是交易单号非 wxid, 原样。
impl fmt::Debug for TransferCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferCreate")
            .field("provenance", &self.provenance)
            .field("transfer_id", &self.transfer_id)
            .field("transcation_id", &self.transcation_id)
            .field("message_server_id", &self.message_server_id)
            .field("second_message_server_id", &self.second_message_server_id)
            .field("session_name_sha8", &sha8(self.session_name.as_bytes()))
            .field("pay_sub_type", &self.pay_sub_type)
            .field("pay_payer_sha8", &sha8(self.pay_payer.as_bytes()))
            .field("pay_receiver_sha8", &sha8(self.pay_receiver.as_bytes()))
            .field("begin_transfer_time", &self.begin_transfer_time)
            .field("last_modified_time", &self.last_modified_time)
            .field("invalid_time", &self.invalid_time)
            .field("last_update_time", &self.last_update_time)
            .field("delay_confirm_flag", &self.delay_confirm_flag)
            .field("bubble_clicked_flag", &self.bubble_clicked_flag)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> TransferCreate {
        TransferCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "general.db".to_string(),
                source_native_id: "Transfer_1000050001202507100225413996557".to_string(),
                event_type: EventType::TransferUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            transfer_id: "1000050001202507100225413996557".to_string(),
            transcation_id: "53010001606113202507100928575102".to_string(),
            message_server_id: 6_379_941_610_914_610_151,
            second_message_server_id: 0,
            session_name: "wxid_peer_002".to_string(),
            pay_sub_type: 2,
            pay_payer: "wxid_peer_002".to_string(),
            pay_receiver: "wxid_self_me".to_string(),
            begin_transfer_time: 1_752_162_563,
            last_modified_time: 1_752_162_564,
            invalid_time: 1_752_248_963,
            last_update_time: 1_752_217_991,
            delay_confirm_flag: 0,
            bubble_clicked_flag: 0,
        }
    }

    /// 默认模式: 三个 id 类字段脱敏 _sha; transfer_id/transcation_id/数字元数据照原。
    #[test]
    fn payload_default_redacts_id() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["pay_payer_sha"], Value::from(sha256_hex("wxid_peer_002")));
        assert_eq!(o["pay_receiver_sha"], Value::from(sha256_hex("wxid_self_me")));
        assert_eq!(o["session_name_sha"], Value::from(sha256_hex("wxid_peer_002")));
        assert!(!o.contains_key("pay_payer"), "K-R4: 默认不出裸 pay_payer");
        assert!(!o.contains_key("pay_receiver"), "K-R4: 默认不出裸 pay_receiver");
        // 元数据照原.
        assert_eq!(
            o["transfer_id"],
            Value::from("1000050001202507100225413996557"),
            "交易单号非 wxid 照原"
        );
        assert_eq!(o["transcation_id"], Value::from("53010001606113202507100928575102"));
        assert_eq!(o["pay_sub_type"], Value::from(2));
        assert_eq!(o["message_server_id"], Value::from(6_379_941_610_914_610_151_i64));
        assert_eq!(o["begin_transfer_time"], Value::from(1_752_162_563_i64));
        assert_eq!(o["bubble_clicked_flag"], Value::from(0));
    }

    /// plaintext: session_name + pay_payer + pay_receiver 全明文 (ADR-427 默认即此)。
    #[test]
    fn payload_plaintext_exposes_id() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["pay_payer"], Value::from("wxid_peer_002"));
        assert_eq!(o["pay_receiver"], Value::from("wxid_self_me"));
        assert_eq!(o["session_name"], Value::from("wxid_peer_002"));
        assert!(!o.contains_key("pay_payer_sha"));
    }

    /// K-R4: 默认模式 payload 不含任何裸敏感值。
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["wxid_peer_002", "wxid_self_me", "wxid_acct_001"] {
            assert!(!dumped.contains(raw), "K-R4: 默认 payload 泄裸值 {raw}");
        }
    }

    /// K-R4: 手写 Debug 不泄 session_name / pay_payer / pay_receiver / account_id 裸值。
    #[test]
    fn debug_redacts_sensitive() {
        let dbg = format!("{:?}", sample());
        for raw in ["wxid_peer_002", "wxid_self_me", "wxid_acct_001"] {
            assert!(!dbg.contains(raw), "Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("pay_payer_sha8"));
        assert!(dbg.contains("pay_receiver_sha8"));
        assert!(dbg.contains("session_name_sha8"));
        // transfer_id 非 wxid, Debug 原样可见 (溯源).
        assert!(dbg.contains("1000050001202507100225413996557"));
    }
}
