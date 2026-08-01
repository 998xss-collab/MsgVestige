//! friend_verify row 组装 — 明文 `FMessageTable` 行 → [`FriendVerifyCreate`] 事件 (好友验证/打招呼一条)。
//!
//! [`assemble_friend_verify`] 把一条 `FMessageTable` 行映射成 [`FriendVerifyCreate`]. **无 decode** → **infallible**。
//! event_seq 留 0。仿 [`super::transfer::assemble_transfer`] (ADR-469, 好友验证新域)。
//!
//! ## 真实 schema (general.db `FMessageTable`, 消费列)
//! rowid (分页游标) / user_name_ (好友 wxid = 锚点, 真库 100% 唯一) / type_ (恒 37) / timestamp_ (unix 秒) /
//! is_sender_ (0/1) / scene_ (加好友来源) / content_ (打招呼语)。
//! **不取**: encrypt_user_name_ (冗余) / ticket_ (写操作 token) / fmessage_detail_buf_ (不透明 proto)。

use crate::event::friend_verify::FriendVerifyCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `FMessageTable` 行 (只取消费列; 见 mod 注释的"不取")。`rowid` 分页游标; `user_name` 稳定身份 (锚点)。
pub struct FMessageRow {
    /// FMessageTable rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 好友 (user_name_; wxid, 锚点 + 身份)。
    pub user_name: String,
    /// 消息类型 (type_; 恒 37)。
    pub friend_type: i64,
    /// 验证时刻 (timestamp_; unix 秒)。
    pub timestamp: i64,
    /// 方向 (is_sender_; 0=收到/1=发出)。
    pub is_sender: i64,
    /// 加好友来源 (scene_)。
    pub scene: i64,
    /// 打招呼语 (content_; 可空 → 空串)。
    pub content: String,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct FriendVerifyContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"general.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"FMessage_<md5_hex(user_name)>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`FMessageRow`] + [`FriendVerifyContext`] → [`FriendVerifyCreate`] (event_seq 留 0, 后置填)。
///
/// 纯字段映射 (无 decode)。`rowid` 是分页游标不进事件。不 log。**infallible**。
#[must_use]
pub fn assemble_friend_verify(row: &FMessageRow, ctx: &FriendVerifyContext) -> FriendVerifyCreate {
    FriendVerifyCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::FriendVerifyUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        user_name: row.user_name.clone(),
        friend_type: row.friend_type,
        timestamp: row.timestamp,
        is_sender: row.is_sender,
        scene: row.scene,
        content: row.content.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_maps_fields() {
        let row = FMessageRow {
            rowid: 5,
            user_name: "wxid_friend".to_string(),
            friend_type: 37,
            timestamp: 1_752_217_142,
            is_sender: 0,
            scene: 14,
            content: "你好".to_string(),
        };
        let ctx = FriendVerifyContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "general.db".to_string(),
            source_native_id: "FMessage_abcd1234".to_string(),
            ingest_time: 1_700_000_000_000,
        };
        let fv = assemble_friend_verify(&row, &ctx);
        assert_eq!(fv.user_name, "wxid_friend");
        assert_eq!(fv.friend_type, 37);
        assert_eq!(fv.timestamp, 1_752_217_142);
        assert_eq!(fv.is_sender, 0);
        assert_eq!(fv.scene, 14);
        assert_eq!(fv.content, "你好");
        assert_eq!(fv.provenance.event_type, EventType::FriendVerifyUpdate);
        assert_eq!(fv.provenance.event_action, EventAction::Create);
        assert_eq!(fv.provenance.event_seq, 0);
    }
}
