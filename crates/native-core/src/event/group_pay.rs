//! event::group_pay — (group_pay_update, create) 事件字段集. 微信群收款/AA (general.db `groupPayTable`) 一条。
//!
//! 照 [`super::transfer::TransferCreate`] 模板 (ADR-468 交易系列件3)。数据源 = general.db `groupPayTable` (真库仅
//! 4 列: bill_no/session_name/message_local_id/message_create_time)。扩 alpha 第 14 事件类型。
//!
//! **金额/成员分摊不在本表** (在群收款消息 XML, 后置件); 本事件搬账单号 + 会话 + 消息链接 + 时刻。
//!
//! ## content_digest (canonical.rs group_pay 臂)
//! bill_no / session_name_sha / message_create_time — 唯一标识 (bill_no 真库 100% 唯一) + 会话 + 时刻 (3 元)。
//! message_local_id 只进 L2。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — session_name 经 [`sha8`]; bill_no 是账单号非 wxid, 原样。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (group_pay_update, create) 事件字段集 — 一条群收款 (general.db `groupPayTable`)。
///
/// `source_native_id` = `"GroupPay_<bill_no>"` (bill_no 是账单号, 非 PII)。
pub struct GroupPayCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 账单号 (groupPayTable.bill_no; TEXT 96hex, 真库 100% 唯一; 元数据非 wxid; 进 digest — 群收款身份)。
    pub bill_no: String,
    /// 会话 (groupPayTable.session_name; id 类: wxid / @chatroom; 进 digest 用 sha)。
    pub session_name: String,
    /// 关联消息本地 id (groupPayTable.message_local_id; 元数据; 链回聊天消息; 只进 L2)。
    pub message_local_id: i64,
    /// 群收款时刻 (groupPayTable.message_create_time; unix 秒; 不可变; 进 digest)。
    pub message_create_time: i64,
}

impl GroupPayCreate {
    /// 渲染整条 group_pay_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // id 类 (session_name — 默认 sha, plaintext 明文).
        render_field(&mut out, "session_name", &self.session_name, FieldCategory::Id, mode);
        // 元数据 string (bill_no — 账单号非 wxid, 恒明文).
        render_field(&mut out, "bill_no", &self.bill_no, FieldCategory::Metadata, mode);
        // 数字元数据 — 直塞.
        out.insert("message_local_id".to_string(), Value::from(self.message_local_id));
        out.insert("message_create_time".to_string(), Value::from(self.message_create_time));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): session_name 经 sha8; provenance 自遮。bill_no 是账单号非 wxid, 原样。**不准 derive Debug**。
impl fmt::Debug for GroupPayCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupPayCreate")
            .field("provenance", &self.provenance)
            .field("bill_no", &self.bill_no)
            .field("session_name_sha8", &sha8(self.session_name.as_bytes()))
            .field("message_local_id", &self.message_local_id)
            .field("message_create_time", &self.message_create_time)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> GroupPayCreate {
        GroupPayCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "general.db".to_string(),
                source_native_id: "GroupPay_694a900673c1".to_string(),
                event_type: EventType::GroupPayUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            bill_no: "694a900673c1395568318fac8f11e4e2".to_string(),
            session_name: "grp@chatroom".to_string(),
            message_local_id: 38,
            message_create_time: 1_767_141_814,
        }
    }

    #[test]
    fn payload_default_redacts_id() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["session_name_sha"], Value::from(sha256_hex("grp@chatroom")));
        assert!(!o.contains_key("session_name"), "K-R4: 默认不出裸 session_name");
        assert_eq!(
            o["bill_no"],
            Value::from("694a900673c1395568318fac8f11e4e2"),
            "账单号非 wxid 照原"
        );
        assert_eq!(o["message_create_time"], Value::from(1_767_141_814_i64));
        assert_eq!(o["message_local_id"], Value::from(38));
    }

    #[test]
    fn payload_plaintext_exposes_id() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["session_name"], Value::from("grp@chatroom"));
        assert!(!o.contains_key("session_name_sha"));
    }

    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["grp@chatroom", "wxid_acct_001"] {
            assert!(!dumped.contains(raw), "K-R4: 默认 payload 泄裸值 {raw}");
        }
    }

    #[test]
    fn debug_redacts_sensitive() {
        let dbg = format!("{:?}", sample());
        for raw in ["grp@chatroom", "wxid_acct_001"] {
            assert!(!dbg.contains(raw), "Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("session_name_sha8"));
        assert!(
            dbg.contains("694a900673c1395568318fac8f11e4e2"),
            "bill_no 非 wxid 原样可见"
        );
    }
}
