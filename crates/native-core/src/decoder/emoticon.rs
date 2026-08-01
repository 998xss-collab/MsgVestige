//! emoticon row 组装 — 明文 `kNonStoreEmoticonTable` 行 → [`CustomEmoticonCreate`] 事件 (一个自定义表情)。
//!
//! [`assemble_emoticon`] 把一条 `kNonStoreEmoticonTable` 行 (直接列, 无 proto/XML) 映射成 [`CustomEmoticonCreate`]。
//! event_seq 留 0。仿 [`super::friend_verify`] / [`super::finder`] (直接列专表 → alpha 事件; ADR-478)。
//!
//! ## 真实 schema (emoticon.db `kNonStoreEmoticonTable`, 消费列; 2026-07-06 inspect 坐实 12 列)
//! md5 (身份/anchor) / type / caption (中文描述) / product_id / aes_key / cdn_url / thumb_url / tp_url /
//! extern_url / extern_md5 / encrypt_url (`auth_key` 低读值不取)。照抄 echotrace 查表列。

use crate::event::emoticon::CustomEmoticonCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `kNonStoreEmoticonTable` 行 (drain 原始行; 全直接列, assemble 直接映射)。
pub struct EmoticonRow {
    /// kNonStoreEmoticonTable rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 表情内容 md5 (身份/anchor)。
    pub md5: String,
    /// 表情类型 (`type`)。
    pub emoticon_type: i64,
    /// 中文描述 (`caption`)。
    pub caption: String,
    /// 商品 id (`product_id`)。
    pub product_id: String,
    /// 解密密钥 (`aes_key`)。
    pub aes_key: String,
    /// 主 CDN 地址 (`cdn_url`)。
    pub cdn_url: String,
    /// 缩略图地址 (`thumb_url`)。
    pub thumb_url: String,
    /// tp 地址 (`tp_url`)。
    pub tp_url: String,
    /// 外部地址 (`extern_url`)。
    pub extern_url: String,
    /// 外部 md5 (`extern_md5`)。
    pub extern_md5: String,
    /// 加密地址 (`encrypt_url`)。
    pub encrypt_url: String,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct EmoticonContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"emoticon.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"Emoticon_<md5>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 组装一条 [`EmoticonRow`] + [`EmoticonContext`] → [`CustomEmoticonCreate`] (event_seq 留 0, 后置填)。
///
/// 全直接列映射, `rowid` 是游标不进事件。**infallible**。
#[must_use]
pub fn assemble_emoticon(row: &EmoticonRow, ctx: &EmoticonContext) -> CustomEmoticonCreate {
    CustomEmoticonCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::CustomEmoticonUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        md5: row.md5.clone(),
        emoticon_type: row.emoticon_type,
        caption: row.caption.clone(),
        product_id: row.product_id.clone(),
        aes_key: row.aes_key.clone(),
        cdn_url: row.cdn_url.clone(),
        thumb_url: row.thumb_url.clone(),
        tp_url: row.tp_url.clone(),
        extern_url: row.extern_url.clone(),
        extern_md5: row.extern_md5.clone(),
        encrypt_url: row.encrypt_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EmoticonContext {
        EmoticonContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "emoticon.db".to_string(),
            source_native_id: "Emoticon_c0c5d96".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_maps_columns() {
        let row = EmoticonRow {
            rowid: 5,
            md5: "c0c5d9625338df85".to_string(),
            emoticon_type: 1,
            caption: "微笑".to_string(),
            product_id: "prod_x".to_string(),
            aes_key: "key".to_string(),
            cdn_url: "http://cdn/x".to_string(),
            thumb_url: "http://thumb/x".to_string(),
            tp_url: String::new(),
            extern_url: String::new(),
            extern_md5: "60bfd31a".to_string(),
            encrypt_url: "http://enc/x".to_string(),
        };
        let e = assemble_emoticon(&row, &ctx());
        assert_eq!(e.md5, "c0c5d9625338df85");
        assert_eq!(e.caption, "微笑");
        assert_eq!(e.extern_md5, "60bfd31a");
        assert_eq!(e.provenance.event_type, EventType::CustomEmoticonUpdate);
        assert_eq!(e.provenance.event_seq, 0);
    }
}
