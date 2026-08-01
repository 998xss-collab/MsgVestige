//! avatar row 组装 — 明文 `head_image` 行 → [`AvatarImageCreate`] 事件 (一个联系人/群的当前头像图)。
//!
//! [`assemble_avatar`] 把一条 `head_image.db::head_image` 行 (直接列, 无 proto/XML) 映射成 [`AvatarImageCreate`]。
//! event_seq 留 0。仿 [`super::emoticon`] (直接列专表 → alpha 事件; ADR-481)。
//!
//! ## 真实 schema (head_image.db `head_image`, 2026-07-07 inspect 坐实 4 列 / 17935 行)
//! username (联系人/群 id) / md5 (头像内容 md5, 身份/anchor) / image_buffer (BLOB, 原始图 bytes,
//! 100% 非空 avg 5KB / max 42KB) / update_time (更新时刻秒)。

use crate::event::avatar::AvatarImageCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `head_image` 行 (drain 原始行; 全直接列, assemble 直接映射)。
pub struct AvatarRow {
    /// head_image rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 联系人/群 id (`username`; wxid_/gh_/@chatroom)。
    pub username: String,
    /// 头像内容 md5 (`md5`; 身份/anchor)。
    pub md5: String,
    /// 原始头像图 bytes (`image_buffer` BLOB; JPEG/PNG)。
    pub image_buffer: Vec<u8>,
    /// 头像更新时刻秒 (`update_time`)。
    pub update_time: i64,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct AvatarContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"head_image.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"Avatar_<username_sha256>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`AvatarRow`] + [`AvatarContext`] → [`AvatarImageCreate`] (event_seq 留 0, 后置填)。
///
/// 全直接列映射, `rowid` 是游标不进事件。**infallible**。
#[must_use]
pub fn assemble_avatar(row: &AvatarRow, ctx: &AvatarContext) -> AvatarImageCreate {
    AvatarImageCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::AvatarImageUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        username: row.username.clone(),
        md5: row.md5.clone(),
        image_buffer: row.image_buffer.clone(),
        update_time: row.update_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> AvatarContext {
        AvatarContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "head_image.db".to_string(),
            source_native_id: "Avatar_9f2b".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_maps_columns() {
        let row = AvatarRow {
            rowid: 5,
            username: "wxid_friend_001".to_string(),
            md5: "a1b2c3d4e5f60718".to_string(),
            image_buffer: vec![0xFF, 0xD8, 0xFF, 0xE0],
            update_time: 1_752_000_000,
        };
        let a = assemble_avatar(&row, &ctx());
        assert_eq!(a.username, "wxid_friend_001");
        assert_eq!(a.md5, "a1b2c3d4e5f60718");
        assert_eq!(a.image_buffer, vec![0xFF, 0xD8, 0xFF, 0xE0]);
        assert_eq!(a.update_time, 1_752_000_000);
        assert_eq!(a.provenance.event_type, EventType::AvatarImageUpdate);
        assert_eq!(a.provenance.event_seq, 0);
    }
}
