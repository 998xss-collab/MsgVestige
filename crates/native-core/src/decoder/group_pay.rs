//! group_pay row 组装 — 明文 `groupPayTable` 行 → [`GroupPayCreate`] 事件 (群收款一条)。
//!
//! [`assemble_group_pay`] 把一条 `groupPayTable` 行映射成 [`GroupPayCreate`]. **无 decode** → **infallible**。
//! event_seq 留 0。仿 [`super::transfer::assemble_transfer`] (ADR-468 件3)。**金额/分摊不在本表** (在群收款消息 XML)。
//!
//! ## 真实 schema (general.db `groupPayTable`, 全 4 列)
//! rowid (分页游标) / bill_no (TEXT 96hex = 锚点, 真库 100% 唯一) / session_name (会话 wxid/@chatroom) /
//! message_local_id (INTEGER 链消息) / message_create_time (INTEGER unix 秒)。

use crate::event::group_pay::GroupPayCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `groupPayTable` 行。`rowid` 是本轮分页游标 (无整型 PK 列); `bill_no` 是稳定身份 (锚点)。
pub struct GroupPayRow {
    /// groupPayTable rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 账单号 (bill_no; TEXT, 锚点 + 身份)。
    pub bill_no: String,
    /// 会话 (session_name; id 类 wxid/@chatroom)。
    pub session_name: String,
    /// 关联消息本地 id (message_local_id)。
    pub message_local_id: i64,
    /// 群收款时刻 (message_create_time; unix 秒)。
    pub message_create_time: i64,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct GroupPayContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"general.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"GroupPay_<bill_no>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`GroupPayRow`] + [`GroupPayContext`] → [`GroupPayCreate`] (event_seq 留 0, 后置填)。
///
/// 纯字段映射 (无 decode)。`rowid` 是分页游标不进事件。不 log。**infallible**。
#[must_use]
pub fn assemble_group_pay(row: &GroupPayRow, ctx: &GroupPayContext) -> GroupPayCreate {
    GroupPayCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::GroupPayUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        bill_no: row.bill_no.clone(),
        session_name: row.session_name.clone(),
        message_local_id: row.message_local_id,
        message_create_time: row.message_create_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_maps_fields() {
        let row = GroupPayRow {
            rowid: 7,
            bill_no: "694a900673c1395568318fac8f11e4e2".to_string(),
            session_name: "grp@chatroom".to_string(),
            message_local_id: 38,
            message_create_time: 1_767_141_814,
        };
        let ctx = GroupPayContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "general.db".to_string(),
            source_native_id: "GroupPay_694a900673c1".to_string(),
            ingest_time: 1_700_000_000_000,
        };
        let gp = assemble_group_pay(&row, &ctx);
        assert_eq!(gp.bill_no, "694a900673c1395568318fac8f11e4e2");
        assert_eq!(gp.session_name, "grp@chatroom");
        assert_eq!(gp.message_local_id, 38);
        assert_eq!(gp.message_create_time, 1_767_141_814);
        assert_eq!(gp.provenance.event_type, EventType::GroupPayUpdate);
        assert_eq!(gp.provenance.event_action, EventAction::Create);
        assert_eq!(gp.provenance.event_seq, 0);
    }
}
