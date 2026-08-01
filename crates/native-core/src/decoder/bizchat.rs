//! bizchat row 组装 — 明文 `user_info` 行 → [`BizChatContactCreate`] 事件 (一个企微品牌号用户)。
//!
//! [`assemble_bizchat`] 把一条 `user_info` 行 (直接列, 无 proto/XML) 映射成 [`BizChatContactCreate`]。
//! event_seq 留 0。仿 [`super::emoticon`] (直接列专表 → alpha 事件; ADR-482)。
//!
//! ## 真实 schema (bizchat.db `user_info`, 消费列; 2026-07-07 inspect 坐实 13 列)
//! user_id (企微 wxid `ww...` = 身份/anchor) / brand_user_name (`gh_` 品牌 id) / user_name (显示名) /
//! bit_flag / head_img_url / profile_url (version/add_member_url/reserved0..3 低读值不取)。

use crate::event::bizchat::BizChatContactCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `user_info` 行 (drain 原始行; 全直接列, assemble 直接映射)。
pub struct BizChatUserRow {
    /// user_info rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 企微品牌号用户 id (user_id = 企微 wxid `ww...`; 身份/anchor)。
    pub user_id: String,
    /// 品牌 gh_id (`brand_user_name`)。
    pub brand_user_name: String,
    /// 显示名 (`user_name`)。
    pub user_name: String,
    /// 标志位 (`bit_flag`)。
    pub bit_flag: i64,
    /// 头像 URL (`head_img_url`)。
    pub head_img_url: String,
    /// 主页 URL (`profile_url`)。
    pub profile_url: String,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct BizChatContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"bizchat.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"BizUser_<md5_hex(user_id)>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`BizChatUserRow`] + [`BizChatContext`] → [`BizChatContactCreate`] (event_seq 留 0, 后置填)。
///
/// 全直接列映射, `rowid` 是游标不进事件。**infallible**。
#[must_use]
pub fn assemble_bizchat(row: &BizChatUserRow, ctx: &BizChatContext) -> BizChatContactCreate {
    BizChatContactCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::BizChatContactUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        user_id: row.user_id.clone(),
        brand_user_name: row.brand_user_name.clone(),
        user_name: row.user_name.clone(),
        head_img_url: row.head_img_url.clone(),
        profile_url: row.profile_url.clone(),
        bit_flag: row.bit_flag,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> BizChatContext {
        BizChatContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "bizchat.db".to_string(),
            source_native_id: "BizUser_3949bf65".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_maps_columns() {
        let row = BizChatUserRow {
            rowid: 5,
            user_id: "ww16xxxxxxxxxxxxxxxxxxx".to_string(),
            brand_user_name: "gh_44bfefcbb4a5".to_string(),
            user_name: "白星".to_string(),
            bit_flag: 16,
            head_img_url: "http://head/x".to_string(),
            profile_url: "https://work.weixin.qq.com/x".to_string(),
        };
        let b = assemble_bizchat(&row, &ctx());
        assert_eq!(b.user_id, "ww16xxxxxxxxxxxxxxxxxxx");
        assert_eq!(b.brand_user_name, "gh_44bfefcbb4a5");
        assert_eq!(b.user_name, "白星");
        assert_eq!(b.bit_flag, 16);
        assert_eq!(b.head_img_url, "http://head/x");
        assert_eq!(b.provenance.event_type, EventType::BizChatContactUpdate);
        assert_eq!(b.provenance.event_seq, 0);
    }
}
