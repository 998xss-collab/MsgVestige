//! session row 组装 — 明文 `SessionTable` 行 → [`SessionUpdate`] 事件 (会话列表项)。
//!
//! [`assemble_session`] 把一条 `SessionTable` 行映射成 [`SessionUpdate`]. **无 decode/无 sender 解析** —
//! session 字段都是明文列 (summary/last_sender_display_name 直接是文本) → 本函数 **infallible**。
//! event_seq 留 0 (compute_event_seq 后置填)。仿 [`super::contact::assemble_contact`]。
//!
//! ## 真实 schema (v4 session.db `SessionTable`, 消费列)
//! username (会话标识: 对方 wxid / 群 `@chatroom`) / summary (最近消息预览, 可空) /
//! last_sender_display_name (最近消息发送者显示名, 可空) / unread_count / last_msg_type /
//! last_msg_sub_type / sort_timestamp (排序时间戳) / type·is_hidden·status·draft [第四批状态列] /
//! last_msg_sender·last_timestamp·last_clear_unread_timestamp·last_msg_locald_id·last_msg_ext_type·
//! unread_first_msg_srv_id [第六批]。

use crate::event::provenance::Provenance;
use crate::event::session::SessionUpdate;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `SessionTable` 行 (调用方从 cipher / 明文 session.db SELECT)。
pub struct SessionRow {
    /// 源 db 行 rowid (= 取数游标键; assemble 不用, 仅供 pipeline 推进/校验游标, 同 [`super::contact::ContactRow`])。
    pub rowid: i64,
    /// 会话标识 (SessionTable.username: 对方 wxid / 群 @chatroom / gh_)。
    pub username: String,
    /// 最近消息预览 (SessionTable.summary; 可空 → 空串)。
    pub summary: Option<String>,
    /// 最近消息发送者显示名 (SessionTable.last_sender_display_name; 可空)。
    pub last_sender_display_name: Option<String>,
    /// 未读数 (SessionTable.unread_count; 元数据)。
    pub unread_count: i64,
    /// 最近消息类型 (SessionTable.last_msg_type; 元数据)。
    pub last_msg_type: i64,
    /// 最近消息子类型 (SessionTable.last_msg_sub_type; 元数据)。
    pub last_msg_sub_type: i64,
    /// 排序时间戳 (SessionTable.sort_timestamp; 会话列表倒序键)。
    pub sort_timestamp: i64,
    /// 会话类型 (SessionTable.type; 元数据; 进 L2 不进 digest — 当前态筛选)。
    pub session_type: i64,
    /// 隐藏/折叠会话 (SessionTable.is_hidden; 0/1 元数据)。
    pub is_hidden: i64,
    /// 会话状态位 (SessionTable.status; 元数据, 含免打扰等)。
    pub status: i64,
    /// 草稿 (SessionTable.draft; 用户未发文本, text_content 类脱敏, 可空)。
    pub draft: Option<String>,
    // ── 第六批 (2026-07-02): session 补充列 (全进 L2 不进 content_digest — 同第四批状态列 L2-only)。
    /// 最后消息发送者 wxid (SessionTable.last_msg_sender; id 类, 可空; L2 明文, Debug sha8)。
    pub last_msg_sender: Option<String>,
    /// 最后消息时间戳 (SessionTable.last_timestamp; 元数据)。
    pub last_timestamp: i64,
    /// 最后清未读时间戳 (SessionTable.last_clear_unread_timestamp; 元数据)。
    pub last_clear_unread_timestamp: i64,
    /// 最后消息本地 id (SessionTable.last_msg_locald_id; 元数据; 注: 微信自身列名拼写 locald)。
    pub last_msg_locald_id: i64,
    /// 最后消息扩展类型 (SessionTable.last_msg_ext_type; 元数据)。
    pub last_msg_ext_type: i64,
    /// 首条未读消息 server id (SessionTable.unread_first_msg_srv_id; 元数据)。
    pub unread_first_msg_srv_id: i64,
}

/// 装配上下文 — 调用方 (adapter) 按 db 预备。
pub struct SessionContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"session.db"`)。
    pub source: String,
    /// 复合 md5 锚点 (调用方预合成 `"Session_<md5_hex(username)>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`SessionRow`] + [`SessionContext`] → [`SessionUpdate`] (event_seq 留 0, 后置填)。
///
/// 纯字段映射 (无 decode)。空串 summary/sender → `None` (= 未设)。不 log。**infallible**。
#[must_use]
pub fn assemble_session(row: &SessionRow, ctx: &SessionContext) -> SessionUpdate {
    // 空串 → None (= 未设), 跟 SessionUpdate 的 nullable 语义一致。
    let non_empty = |o: &Option<String>| o.as_ref().filter(|s| !s.is_empty()).cloned();
    SessionUpdate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::SessionUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        username: row.username.clone(),
        summary: non_empty(&row.summary),
        last_sender_display_name: non_empty(&row.last_sender_display_name),
        unread_count: row.unread_count,
        last_msg_type: row.last_msg_type,
        last_msg_sub_type: row.last_msg_sub_type,
        sort_timestamp: row.sort_timestamp,
        // 会话状态列 (元数据直传; draft 空串→None; 进 L2 不进 content_digest — 当前态筛选, 折叠/免打扰历史价值低)。
        session_type: row.session_type,
        is_hidden: row.is_hidden,
        status: row.status,
        draft: non_empty(&row.draft),
        // 第六批 (进 L2 不进 digest — 同第四批): last_msg_sender 空串→None; 5 时间/id/类型元数据直传。
        last_msg_sender: non_empty(&row.last_msg_sender),
        last_timestamp: row.last_timestamp,
        last_clear_unread_timestamp: row.last_clear_unread_timestamp,
        last_msg_locald_id: row.last_msg_locald_id,
        last_msg_ext_type: row.last_msg_ext_type,
        unread_first_msg_srv_id: row.unread_first_msg_srv_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SessionContext {
        SessionContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "session.db".to_string(),
            source_native_id: "Session_a1b2c3d4".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    fn row(username: &str, summary: Option<&str>, sender: Option<&str>) -> SessionRow {
        SessionRow {
            rowid: 1,
            username: username.to_string(),
            summary: summary.map(str::to_string),
            last_sender_display_name: sender.map(str::to_string),
            unread_count: 3,
            last_msg_type: 1,
            last_msg_sub_type: 0,
            sort_timestamp: 1_700_000_009_000,
            session_type: 1,
            is_hidden: 0,
            status: 0,
            draft: None,
            last_msg_sender: None,
            last_timestamp: 0,
            last_clear_unread_timestamp: 0,
            last_msg_locald_id: 0,
            last_msg_ext_type: 0,
            unread_first_msg_srv_id: 0,
        }
    }

    #[test]
    fn assemble_maps_fields() {
        let s = assemble_session(&row("wxid_peer", Some("晚上吃饭吗"), Some("小明")), &ctx());
        assert_eq!(s.username, "wxid_peer");
        assert_eq!(s.summary.as_deref(), Some("晚上吃饭吗"));
        assert_eq!(s.last_sender_display_name.as_deref(), Some("小明"));
        assert_eq!(s.unread_count, 3);
        assert_eq!(s.last_msg_type, 1);
        assert_eq!(s.sort_timestamp, 1_700_000_009_000);
        assert_eq!(s.provenance.event_type, EventType::SessionUpdate);
        assert_eq!(s.provenance.event_action, EventAction::Create);
        assert_eq!(s.provenance.event_seq, 0);
    }

    #[test]
    fn empty_summary_sender_to_none() {
        let s = assemble_session(&row("wxid_peer", Some(""), Some("")), &ctx());
        assert_eq!(s.summary, None, "空串 summary → None (未设)");
        assert_eq!(s.last_sender_display_name, None, "空串 sender → None");
    }

    /// 字段扩充第四批 (2026-07-02): 会话状态列映射 (type/is_hidden/status 直传 + draft 空串→None)。
    #[test]
    fn session_status_columns_map() {
        let mut r = row("wxid_peer", None, None);
        r.session_type = 2;
        r.is_hidden = 1;
        r.status = 5;
        r.draft = Some(String::new()); // 空串 → None
        let s = assemble_session(&r, &ctx());
        assert_eq!(s.session_type, 2);
        assert_eq!(s.is_hidden, 1);
        assert_eq!(s.status, 5);
        assert_eq!(s.draft, None, "空串 draft → None");
    }

    /// 字段扩充第六批 (2026-07-02): session 补充列映射 (last_msg_sender 空串→None; 5 元数据直传)。
    #[test]
    fn session_batch6_columns_map() {
        let mut r = row("wxid_peer", None, None);
        r.last_msg_sender = Some("wxid_sender".into());
        r.last_timestamp = 1_700_000_100_000;
        r.last_clear_unread_timestamp = 1_700_000_050_000;
        r.last_msg_locald_id = 42;
        r.last_msg_ext_type = 3;
        r.unread_first_msg_srv_id = 9_876_543_210;
        let s = assemble_session(&r, &ctx());
        assert_eq!(s.last_msg_sender.as_deref(), Some("wxid_sender"));
        assert_eq!(s.last_timestamp, 1_700_000_100_000);
        assert_eq!(s.last_clear_unread_timestamp, 1_700_000_050_000);
        assert_eq!(s.last_msg_locald_id, 42);
        assert_eq!(s.last_msg_ext_type, 3);
        assert_eq!(s.unread_first_msg_srv_id, 9_876_543_210);
        r.last_msg_sender = Some(String::new());
        assert_eq!(assemble_session(&r, &ctx()).last_msg_sender, None, "空串 → None");
    }
}
