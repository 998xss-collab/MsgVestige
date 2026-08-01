//! event::emoticon — (custom_emoticon_update, create) 事件字段集. 微信自定义表情
//! (emoticon.db `kNonStoreEmoticonTable`) 一条 = 用户自加的一个自定义表情。
//!
//! 照 [`super::finder::FinderVisitCreate`] 模板 (emoticon.db 专表 → alpha 事件; ADR-478)。
//! **真库坐实** (2026-07-06 inspect kNonStoreEmoticonTable 15 行 12 列): md5 (表情内容 md5 = 身份) /
//! caption (中文描述) / type / product_id / aes_key (解密密钥) / cdn_url / thumb_url / tp_url / extern_url /
//! extern_md5 / encrypt_url。照抄竞品 echotrace (md5/extern_md5→urls 查表 7 列)。
//!
//! ## content_digest (canonical.rs emoticon 臂)
//! md5 (表情身份, 内容哈希非 PII) + caption (描述) + emoticon_type — 3 元。urls/aes_key/product_id 只进 L2。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — aes_key (解密密钥) sha8; urls 只露长度; md5/caption/type 直露 (非 PII)。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::PrivacyMode;
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (custom_emoticon_update, create) 事件字段集 — 一个自定义表情 (emoticon.db `kNonStoreEmoticonTable`)。
///
/// `source_native_id` = `"Emoticon_<md5>"` (md5 是表情内容哈希, 非 PII 直用; 真库唯一定位)。
pub struct CustomEmoticonCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 表情内容 md5 (kNonStoreEmoticonTable.md5; 身份 + anchor; 内容哈希非 PII)。
    pub md5: String,
    /// 表情类型 (`type`; 元数据; 进 digest)。
    pub emoticon_type: i64,
    /// 中文描述 (`caption`, 如 "微笑"; 进 digest)。
    pub caption: String,
    /// 商品 id (`product_id`; 表情包来源; 元数据; 只进 L2)。
    pub product_id: String,
    /// 解密密钥 (`aes_key`; 敏感; 只进 L2, Debug sha8)。
    pub aes_key: String,
    /// 主 CDN 下载地址 (`cdn_url`; 只进 L2)。
    pub cdn_url: String,
    /// 缩略图地址 (`thumb_url`; 只进 L2)。
    pub thumb_url: String,
    /// tp 地址 (`tp_url`; 只进 L2)。
    pub tp_url: String,
    /// 外部地址 (`extern_url`; 只进 L2)。
    pub extern_url: String,
    /// 外部 md5 (`extern_md5`; echotrace 查表键之一; 只进 L2)。
    pub extern_md5: String,
    /// 加密地址 (`encrypt_url`; 只进 L2)。
    pub encrypt_url: String,
}

impl CustomEmoticonCreate {
    /// 渲染整条 custom_emoticon_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // md5/caption/type/product_id 元数据 (非 PII) 直塞; urls/aes_key 只进 L2 不进 payload (含密钥/冗余)。
        out.insert("md5".to_string(), Value::from(self.md5.as_str()));
        out.insert("caption".to_string(), Value::from(self.caption.as_str()));
        out.insert("emoticon_type".to_string(), Value::from(self.emoticon_type));
        out.insert("product_id".to_string(), Value::from(self.product_id.as_str()));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): aes_key (密钥) sha8; urls 只露长度; md5/caption/type/product_id 直露 (非 PII); provenance 自遮。
impl fmt::Debug for CustomEmoticonCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ul = |s: &str| s.chars().count();
        f.debug_struct("CustomEmoticonCreate")
            .field("provenance", &self.provenance)
            .field("md5", &self.md5)
            .field("emoticon_type", &self.emoticon_type)
            .field("caption", &self.caption)
            .field("product_id", &self.product_id)
            .field("aes_key_sha8", &sha8(self.aes_key.as_bytes()))
            .field("cdn_url_len", &ul(&self.cdn_url))
            .field("thumb_url_len", &ul(&self.thumb_url))
            .field("extern_md5", &self.extern_md5)
            .field("encrypt_url_len", &ul(&self.encrypt_url))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> CustomEmoticonCreate {
        CustomEmoticonCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "emoticon.db".to_string(),
                source_native_id: "Emoticon_c0c5d9625338df85".to_string(),
                event_type: EventType::CustomEmoticonUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            md5: "c0c5d9625338df85".to_string(),
            emoticon_type: 1,
            caption: "微笑".to_string(),
            product_id: "prod_x".to_string(),
            aes_key: "secretaeskey123".to_string(),
            cdn_url: "http://wxapp.tc.qq.com/262/20304/stodown".to_string(),
            thumb_url: "http://thumb/x".to_string(),
            tp_url: String::new(),
            extern_url: String::new(),
            extern_md5: "60bfd31a".to_string(),
            encrypt_url: "http://wxapp.tc.qq.com/262/20304/stodown".to_string(),
        }
    }

    /// payload: md5/caption/type/product_id 出; urls/aes_key 不出 (只进 L2)。
    #[test]
    fn payload_metadata_only() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["md5"], Value::from("c0c5d9625338df85"));
        assert_eq!(o["caption"], Value::from("微笑"));
        assert_eq!(o["emoticon_type"], Value::from(1));
        assert!(!o.contains_key("aes_key"), "密钥不进 payload");
        assert!(!o.contains_key("cdn_url"), "url 只进 L2");
    }

    /// K-R4: Debug 不泄 aes_key 裸值; urls 只露长度。
    #[test]
    fn k_r4_debug_redacts() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("secretaeskey123"), "K-R4: aes_key 裸值泄露");
        assert!(dbg.contains("aes_key_sha8") && dbg.contains("cdn_url_len"));
        assert!(dbg.contains("微笑"), "caption 非 PII 直露");
    }
}
