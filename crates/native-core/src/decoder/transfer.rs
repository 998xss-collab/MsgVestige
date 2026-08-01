//! transfer row 组装 — 明文 `transferTable` 行 → [`TransferCreate`] 事件 (转账一条)。
//!
//! [`assemble_transfer`] 把一条 `transferTable` 行映射成 [`TransferCreate`]. **无 decode** — 转账字段都是直接列
//! → 本函数 **infallible**。event_seq 留 0 (compute 后置填)。仿 [`super::favorite::assemble_favorite`]。
//! **金额不在本表** (在转账消息 XML feedesc) → 本层不取金额, 只搬账号/状态/时间 + message_server_id (供 JOIN 回原消息)。
//!
//! ## 真实 schema (general.db `transferTable`, 消费列)
//! rowid (分页游标, 非业务 id) / transfer_id (TEXT 单号 = 锚点, 真库 100% 唯一) / transcation_id (TEXT 流水) /
//! message_server_id (INTEGER 链消息) / second_message_server_id (INTEGER 收款确认消息, 0=无) /
//! session_name (会话 wxid/@chatroom) / pay_sub_type (状态) / pay_payer / pay_receiver (双方 wxid) /
//! begin/last_modified/invalid/last_update_time (unix 秒) / delay_confirm_flag / bubble_clicked_flag (0/1; NULL→0 由 drain COALESCE)。

use crate::event::provenance::Provenance;
use crate::event::transfer::TransferCreate;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `transferTable` 行 (调用方从 cipher / 明文 general.db SELECT)。
///
/// `rowid` 是本轮分页游标 (transferTable 无整型 PK 列 → 用隐式 rowid); `transfer_id` 是稳定身份 (锚点)。
pub struct TransferRow {
    /// transferTable rowid (本轮分页游标; 非业务 id, 不进事件)。
    pub rowid: i64,
    /// 微信转账单号 (transfer_id; TEXT, 锚点 + 身份)。
    pub transfer_id: String,
    /// 交易流水号 (transcation_id; TEXT)。
    pub transcation_id: String,
    /// 转账消息 server_id (message_server_id)。
    pub message_server_id: i64,
    /// 收款确认消息 server_id (second_message_server_id; 0=无)。
    pub second_message_server_id: i64,
    /// 会话 (session_name; id 类 wxid/@chatroom)。
    pub session_name: String,
    /// 状态 (pay_sub_type)。
    pub pay_sub_type: i64,
    /// 付款方 (pay_payer; id 类 wxid)。
    pub pay_payer: String,
    /// 收款方 (pay_receiver; id 类 wxid)。
    pub pay_receiver: String,
    /// 发起时刻 (begin_transfer_time; unix 秒)。
    pub begin_transfer_time: i64,
    /// 末次修改 (last_modified_time; unix 秒)。
    pub last_modified_time: i64,
    /// 失效时刻 (invalid_time; unix 秒)。
    pub invalid_time: i64,
    /// 末次更新 (last_update_time; unix 秒)。
    pub last_update_time: i64,
    /// 延迟确认标志 (delay_confirm_flag; 0/1)。
    pub delay_confirm_flag: i64,
    /// 气泡点击标志 (bubble_clicked_flag; drain 已 COALESCE NULL→0)。
    pub bubble_clicked_flag: i64,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct TransferContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"general.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"Transfer_<transfer_id>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`TransferRow`] + [`TransferContext`] → [`TransferCreate`] (event_seq 留 0, 后置填)。
///
/// 纯字段映射 (无 decode)。`rowid` 是分页游标不进事件。不 log。**infallible**。
#[must_use]
pub fn assemble_transfer(row: &TransferRow, ctx: &TransferContext) -> TransferCreate {
    TransferCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::TransferUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        transfer_id: row.transfer_id.clone(),
        transcation_id: row.transcation_id.clone(),
        message_server_id: row.message_server_id,
        second_message_server_id: row.second_message_server_id,
        session_name: row.session_name.clone(),
        pay_sub_type: row.pay_sub_type,
        pay_payer: row.pay_payer.clone(),
        pay_receiver: row.pay_receiver.clone(),
        begin_transfer_time: row.begin_transfer_time,
        last_modified_time: row.last_modified_time,
        invalid_time: row.invalid_time,
        last_update_time: row.last_update_time,
        delay_confirm_flag: row.delay_confirm_flag,
        bubble_clicked_flag: row.bubble_clicked_flag,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> TransferContext {
        TransferContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "general.db".to_string(),
            source_native_id: "Transfer_1000050001202507100225413996557".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    fn row() -> TransferRow {
        TransferRow {
            rowid: 42,
            transfer_id: "1000050001202507100225413996557".to_string(),
            transcation_id: "53010001606113202507100928575102".to_string(),
            message_server_id: 6_379_941_610_914_610_151,
            second_message_server_id: 0,
            session_name: "wxid_peer_002".to_string(),
            pay_sub_type: 2,
            pay_payer: "wxid_peer_002".to_string(),
            pay_receiver: "wxid_self_acct".to_string(),
            begin_transfer_time: 1_752_162_563,
            last_modified_time: 1_752_162_564,
            invalid_time: 1_752_248_963,
            last_update_time: 1_752_217_991,
            delay_confirm_flag: 0,
            bubble_clicked_flag: 0,
        }
    }

    #[test]
    fn assemble_maps_fields() {
        let t = assemble_transfer(&row(), &ctx());
        assert_eq!(t.transfer_id, "1000050001202507100225413996557");
        assert_eq!(t.transcation_id, "53010001606113202507100928575102");
        assert_eq!(t.message_server_id, 6_379_941_610_914_610_151);
        assert_eq!(t.second_message_server_id, 0);
        assert_eq!(t.session_name, "wxid_peer_002");
        assert_eq!(t.pay_sub_type, 2);
        assert_eq!(t.pay_payer, "wxid_peer_002");
        assert_eq!(t.pay_receiver, "wxid_self_acct");
        assert_eq!(t.begin_transfer_time, 1_752_162_563);
        assert_eq!(t.bubble_clicked_flag, 0);
        assert_eq!(t.provenance.event_type, EventType::TransferUpdate);
        assert_eq!(t.provenance.event_action, EventAction::Create);
        assert_eq!(t.provenance.event_seq, 0);
        // rowid 是分页游标, 不进事件 (TransferCreate 无该字段)。
    }
}
