//! favorite_tag row 组装 — 明文 `fav_bind_tag_db_item ⋈ fav_tag_db_item` 行 → [`FavoriteTagCreate`]。
//!
//! [`assemble_favorite_tag`] 把一条 (绑定 JOIN 标签名) 行映射成 [`FavoriteTagCreate`]. **无 decode** →
//! 本函数 **infallible**。event_seq 留 0 (compute 后置填)。仿 [`super::favorite::assemble_favorite`]。
//! 一条绑定 = 一个事件 (标签名去规范化到每条绑定)。ADR-454 §3.1 批 B-2。
//!
//! ## 真实 schema (favorite.db, 消费列)
//! fav_bind_tag_db_item: rowid (游标) / tag_server_id / tag_local_id / fav_server_id / fav_local_id / op_code。
//! LEFT JOIN fav_tag_db_item ON server_id=tag_server_id: name (标签名, 缺→空串) / seq (排序)。

use crate::event::favorite_tag::FavoriteTagCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `fav_bind_tag_db_item ⋈ fav_tag_db_item` 行 (调用方从 cipher / 明文 favorite.db SELECT)。
pub struct FavoriteTagRow {
    /// 绑定表 rowid (= 取数游标键; 非 PII)。
    pub rowid: i64,
    /// 标签服务端 id (fav_bind_tag_db_item.tag_server_id)。
    pub tag_server_id: i64,
    /// 标签本地 id (fav_bind_tag_db_item.tag_local_id)。
    pub tag_local_id: i64,
    /// 标签名 (fav_tag_db_item.name; LEFT JOIN, 缺→空串)。
    pub tag_name: String,
    /// 标签顺序 (fav_tag_db_item.seq; LEFT JOIN)。
    pub seq: i64,
    /// 收藏服务端 id (fav_bind_tag_db_item.fav_server_id)。
    pub fav_server_id: i64,
    /// 收藏本地 id (fav_bind_tag_db_item.fav_local_id)。
    pub fav_local_id: i64,
    /// 绑定操作码 (fav_bind_tag_db_item.op_code; 1=add)。
    pub op_code: i64,
}

/// 装配上下文 — 调用方 (adapter) 按 db 预备。
pub struct FavoriteTagContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"favorite.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"FavoriteTag_<tag_local_id>_<fav_local_id>"`; R16-3 后用 **local id** —— 未同步 server_id=0
    /// 会塌锚, local 单库唯一, 见 [`crate::decoder::favorite_tag_anchor`])。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`FavoriteTagRow`] + [`FavoriteTagContext`] → [`FavoriteTagCreate`] (event_seq 留 0, 后置填)。
///
/// 纯字段映射 (无 decode)。不 log。**infallible**。
#[must_use]
pub fn assemble_favorite_tag(row: &FavoriteTagRow, ctx: &FavoriteTagContext) -> FavoriteTagCreate {
    FavoriteTagCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::FavoriteTagUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        tag_server_id: row.tag_server_id,
        tag_local_id: row.tag_local_id,
        tag_name: row.tag_name.clone(),
        seq: row.seq,
        fav_server_id: row.fav_server_id,
        fav_local_id: row.fav_local_id,
        op_code: row.op_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FavoriteTagContext {
        FavoriteTagContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "favorite.db".to_string(),
            source_native_id: "FavoriteTag_1_254".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_maps_fields() {
        let row = FavoriteTagRow {
            rowid: 1,
            tag_server_id: 1,
            tag_local_id: 1,
            tag_name: "押金".to_string(),
            seq: 824_874_138,
            fav_server_id: 254,
            fav_local_id: 92,
            op_code: 1,
        };
        let ft = assemble_favorite_tag(&row, &ctx());
        assert_eq!(ft.tag_server_id, 1);
        assert_eq!(ft.tag_name, "押金");
        assert_eq!(ft.seq, 824_874_138);
        assert_eq!(ft.fav_server_id, 254);
        assert_eq!(ft.op_code, 1);
        assert_eq!(ft.provenance.event_type, EventType::FavoriteTagUpdate);
        assert_eq!(ft.provenance.event_action, EventAction::Create);
        assert_eq!(ft.provenance.event_seq, 0);
    }
}
