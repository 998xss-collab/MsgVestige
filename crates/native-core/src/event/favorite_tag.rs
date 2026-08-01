//! event::favorite_tag — (favorite_tag_update, create) 事件字段集. 一条"标签↔收藏"绑定 (M:N)。
//!
//! 照 [`super::favorite::FavoriteCreate`] 模板 (嵌 [`Provenance`] + to_payload_json + 手写 Debug + 不 derive Serialize)。
//! 数据源 = favorite.db `fav_bind_tag_db_item` (绑定) LEFT JOIN `fav_tag_db_item` (标签名)。
//! **一条绑定 = 一个事件** (标签名去规范化到每条绑定 → 一张 L2 favorite_tag 表即可查"某收藏的标签"/"某标签的收藏")。
//! ADR-454 §3.1 批 B-2 (收藏标签; alpha 第 10 组合)。绑定创建后基本不变 → 全表重扫 + content_digest 去重 + UPSERT。
//!
//! 字段归桶: `tag_name` = text_content 类 (用户创建标签, 可能敏感如"老板"→默认脱敏); `tag_server_id`/`fav_server_id`/
//! `op_code`/`seq`/`tag_local_id`/`fav_local_id` = 元数据类 (微信内部整数)。
//!
//! ## content_digest (canonical.rs favorite_tag 臂)
//! tag_server_id + fav_server_id + tag_name + op_code — 唯一标识 (哪个标签打在哪个收藏上 + add/remove 态 + 标签名)。
//! seq / tag_local_id / fav_local_id 只进 L2 (排序 / 本地 id)。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 tag_name 裸值被误序列化。
//! - **手写 `Debug`** — tag_name 经 [`sha8`] 脱敏; provenance.account_id 自遮。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (favorite_tag_update, create) 事件字段集 — 一条"标签↔收藏"绑定。
///
/// `source_native_id` = `"FavoriteTag_<tag_local_id>_<fav_local_id>"` (绑定身份, 两整数非 PII; R16-3 后用 **local id**
/// —— 未同步 server_id=0 会塌锚, local 单库唯一)。
pub struct FavoriteTagCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 标签服务端 id (fav_tag_db_item.server_id; 元数据; 进 digest)。
    pub tag_server_id: i64,
    /// 标签本地 id (fav_tag_db_item.local_id; 元数据; 只进 L2)。
    pub tag_local_id: i64,
    /// 标签名 (fav_tag_db_item.name; text_content 类, 用户创建标签; 进 digest raw; 默认 payload 脱敏)。
    pub tag_name: String,
    /// 标签顺序 (fav_tag_db_item.seq; 元数据; 只进 L2 — 排序)。
    pub seq: i64,
    /// 收藏服务端 id (fav_bind_tag_db_item.fav_server_id; 元数据; 进 digest — 打在哪个收藏)。
    pub fav_server_id: i64,
    /// 收藏本地 id (fav_bind_tag_db_item.fav_local_id; 元数据; 只进 L2)。
    pub fav_local_id: i64,
    /// 绑定操作码 (fav_bind_tag_db_item.op_code; 1=add; 元数据; 进 digest — add/remove 态)。
    pub op_code: i64,
}

impl FavoriteTagCreate {
    /// 渲染整条 favorite_tag_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // text_content 类 (tag_name 用户标签, 默认脱敏 _sha+_len).
        render_field(&mut out, "tag_name", &self.tag_name, FieldCategory::TextContent, mode);
        // 数字元数据 — 直塞.
        out.insert("tag_server_id".to_string(), Value::from(self.tag_server_id));
        out.insert("tag_local_id".to_string(), Value::from(self.tag_local_id));
        out.insert("seq".to_string(), Value::from(self.seq));
        out.insert("fav_server_id".to_string(), Value::from(self.fav_server_id));
        out.insert("fav_local_id".to_string(), Value::from(self.fav_local_id));
        out.insert("op_code".to_string(), Value::from(self.op_code));

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): tag_name 经 sha8 脱敏; provenance 自遮。
/// **不准 derive Debug** — 会泄用户标签裸值。
impl fmt::Debug for FavoriteTagCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FavoriteTagCreate")
            .field("provenance", &self.provenance)
            .field("tag_server_id", &self.tag_server_id)
            .field("tag_local_id", &self.tag_local_id)
            .field("tag_name_sha8", &sha8(self.tag_name.as_bytes()))
            .field("seq", &self.seq)
            .field("fav_server_id", &self.fav_server_id)
            .field("fav_local_id", &self.fav_local_id)
            .field("op_code", &self.op_code)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> FavoriteTagCreate {
        FavoriteTagCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "favorite.db".to_string(),
                source_native_id: "FavoriteTag_1_254".to_string(),
                event_type: EventType::FavoriteTagUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            tag_server_id: 1,
            tag_local_id: 1,
            tag_name: "押金".to_string(),
            seq: 824_874_138,
            fav_server_id: 254,
            fav_local_id: 92,
            op_code: 1,
        }
    }

    /// 默认模式: tag_name 脱敏 _sha+_len; 数字元数据照原。
    #[test]
    fn payload_default_redacts_tag_name() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["tag_name_sha"], Value::from(sha256_hex("押金")));
        assert_eq!(o["tag_name_len"], Value::from(2_i64));
        assert!(!o.contains_key("tag_name"), "K-R4: 默认不出裸 tag_name");
        assert_eq!(o["tag_server_id"], Value::from(1));
        assert_eq!(o["fav_server_id"], Value::from(254));
        assert_eq!(o["op_code"], Value::from(1));
    }

    /// plaintext: tag_name 明文 (ADR-427 默认即此)。
    #[test]
    fn payload_plaintext_exposes_tag_name() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["tag_name"], Value::from("押金"));
        assert!(!o.contains_key("tag_name_sha"));
    }

    /// K-R4: 默认 payload + Debug 都不泄 tag_name 裸值。
    #[test]
    fn k_r4_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        assert!(
            !serde_json::to_string(&p).unwrap().contains("押金"),
            "K-R4: payload 泄裸标签"
        );
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("押金"), "K-R4: Debug 泄裸标签");
        assert!(dbg.contains("tag_name_sha8"));
    }
}
