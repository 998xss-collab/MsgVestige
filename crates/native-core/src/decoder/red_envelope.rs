//! red_envelope row 组装 — 明文 `redEnvelopeTable` 行 → [`RedEnvelopeCreate`] 事件 (红包一条)。
//!
//! [`assemble_red_envelope`] 把一条 `redEnvelopeTable` 行映射成 [`RedEnvelopeCreate`]. **无 decode** — 直接列
//! → **infallible**。event_seq 留 0 (compute 后置填)。仿 [`super::transfer::assemble_transfer`] (ADR-468 件2)。
//! **金额不在本表** (在消息 XML / native_url 领取详情); native_url query 嵌 sendusername=wxid (K-R4 出口脱敏)。
//!
//! ## 真实 schema (general.db `redEnvelopeTable`, 消费列)
//! rowid (分页游标) / send_id (TEXT 单号 = 锚点, 真库 100% 唯一) / message_server_id (INTEGER 链消息) /
//! session_name (会话 wxid/@chatroom) / sender_user_name (发送者 wxid) / native_url (wxpay 领取 URL 嵌 wxid) /
//! scene_id / hb_status / hb_type / receive_status (INTEGER)。**无时间列**。

use crate::event::provenance::Provenance;
use crate::event::red_envelope::RedEnvelopeCreate;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `redEnvelopeTable` 行 (调用方从 cipher / 明文 general.db SELECT)。
///
/// `rowid` 是本轮分页游标 (redEnvelopeTable 无整型 PK 列 → 用隐式 rowid); `send_id` 是稳定身份 (锚点)。
pub struct RedEnvelopeRow {
    /// redEnvelopeTable rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 红包单号 (send_id; TEXT, 锚点 + 身份)。
    pub send_id: String,
    /// 红包消息 server_id (message_server_id)。
    pub message_server_id: i64,
    /// 会话 (session_name; id 类 wxid/@chatroom)。
    pub session_name: String,
    /// 发送者 (sender_user_name; id 类 wxid)。
    pub sender_user_name: String,
    /// 领取 URL (native_url; wxpay://... 嵌 wxid)。
    pub native_url: String,
    /// 场景 id (scene_id)。
    pub scene_id: i64,
    /// 红包状态 (hb_status)。
    pub hb_status: i64,
    /// 红包类型 (hb_type; 0 普通/1 拼手气)。
    pub hb_type: i64,
    /// 领取状态 (receive_status)。
    pub receive_status: i64,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct RedEnvelopeContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"general.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"RedEnvelope_<send_id>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`RedEnvelopeRow`] + [`RedEnvelopeContext`] → [`RedEnvelopeCreate`] (event_seq 留 0, 后置填)。
///
/// 纯字段映射 (无 decode)。`rowid` 是分页游标不进事件。不 log。**infallible**。
#[must_use]
pub fn assemble_red_envelope(row: &RedEnvelopeRow, ctx: &RedEnvelopeContext) -> RedEnvelopeCreate {
    RedEnvelopeCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::RedEnvelopeUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        send_id: row.send_id.clone(),
        message_server_id: row.message_server_id,
        session_name: row.session_name.clone(),
        sender_user_name: row.sender_user_name.clone(),
        native_url: row.native_url.clone(),
        scene_id: row.scene_id,
        hb_status: row.hb_status,
        hb_type: row.hb_type,
        receive_status: row.receive_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RedEnvelopeContext {
        RedEnvelopeContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "general.db".to_string(),
            source_native_id: "RedEnvelope_100003".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_maps_fields() {
        let row = RedEnvelopeRow {
            rowid: 42,
            send_id: "1000039801202604206261068705009".to_string(),
            message_server_id: 461_510_149_866_340,
            session_name: "grp@chatroom".to_string(),
            sender_user_name: "wxid_sender".to_string(),
            native_url: "wxpay://x?sendusername=wxid_sender".to_string(),
            scene_id: 1002,
            hb_status: 1,
            hb_type: 0,
            receive_status: 0,
        };
        let re = assemble_red_envelope(&row, &ctx());
        assert_eq!(re.send_id, "1000039801202604206261068705009");
        assert_eq!(re.message_server_id, 461_510_149_866_340);
        assert_eq!(re.session_name, "grp@chatroom");
        assert_eq!(re.sender_user_name, "wxid_sender");
        assert_eq!(re.hb_type, 0);
        assert_eq!(re.receive_status, 0);
        assert_eq!(re.provenance.event_type, EventType::RedEnvelopeUpdate);
        assert_eq!(re.provenance.event_action, EventAction::Create);
        assert_eq!(re.provenance.event_seq, 0);
        // rowid 是分页游标, 不进事件。
    }
}
