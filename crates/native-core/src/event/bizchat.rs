//! event::bizchat — (biz_chat_contact_update, create) 事件字段集. 企业微信品牌号联系人
//! (bizchat.db `user_info`) 一条 = 一个企微品牌号用户 (你与之互通的企业微信号)。
//!
//! 照 [`super::emoticon::CustomEmoticonCreate`] 模板 (独立小库 → 新 alpha 事件 → 单 L2 表; ADR-482)。
//! 另参 [`super::finder::FinderVisitCreate`] (general.db 专表 → alpha 事件) 作平行参考。
//! **真库坐实** (2026-07-07 inspect user_info 21 行 13 列): user_id (企微 wxid `ww...` = 身份) /
//! brand_user_name (`gh_` 品牌 id) / user_name (显示名, 如 "白星") / version / bit_flag / head_img_url /
//! profile_url / add_member_url / reserved0..3 (低读值不取)。
//! (`chat_group` 表 1 行 = 品牌号群容器, **本件不做** — 单行容器无价值, 联系人才是价值; ADR-482 §跳过。)
//!
//! ## content_digest (canonical.rs bizchat 臂)
//! user_id_sha (企微 wxid, 身份) + brand_user_name (`gh_` 品牌 id) + user_name (显示名) — 3 元。
//! head_img_url/profile_url/bit_flag 只进 L2, 不进 digest。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — user_id / user_name (PII) 经 [`sha8`]; brand_user_name
//!   (`gh_` 半公开) 直露; urls 只露长度; bit_flag 直露。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (biz_chat_contact_update, create) 事件字段集 — 一个企微品牌号用户 (bizchat.db `user_info`)。
///
/// `source_native_id` = `"BizUser_<md5_hex(user_id)>"` (user_id 是企微 wxid=PII → 内部 md5, 不暴露明文;
/// 照 finder 的 `Finder_<md5_hex(owner_username)>`, user_id 为 PII 故必哈希非 emoticon md5 直用)。
pub struct BizChatContactCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 企微品牌号用户 id (user_info.user_id = 企微 wxid `ww...`; id 类; 进 digest 用 sha; anchor 用 md5)。
    pub user_id: String,
    /// 品牌 gh_id (`brand_user_name`, 如 `gh_44bfefcbb4a5`; `gh_` 半公开; 进 digest 直露)。
    pub brand_user_name: String,
    /// 显示名 (`user_name`, 如 "白星"; display_name 类; 进 digest)。
    pub user_name: String,
    /// 头像 URL (`head_img_url`; 元数据; 只进 L2, Debug 只露长度)。
    pub head_img_url: String,
    /// 主页 URL (`profile_url`; 元数据; 只进 L2, Debug 只露长度)。
    pub profile_url: String,
    /// 标志位 (`bit_flag`; 元数据; 只进 L2)。
    pub bit_flag: i64,
}

impl BizChatContactCreate {
    /// 渲染整条 biz_chat_contact_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // id 类 (user_id — 默认 sha)。
        render_field(&mut out, "user_id", &self.user_id, FieldCategory::Id, mode);
        // display 类 (user_name 显示名 — 默认 sha, plaintext 出原文)。
        render_field(&mut out, "user_name", &self.user_name, FieldCategory::DisplayName, mode);
        // 元数据 — 直塞 (brand_user_name `gh_` 半公开 / bit_flag; urls 只进 L2 不进 payload)。
        out.insert(
            "brand_user_name".to_string(),
            Value::from(self.brand_user_name.as_str()),
        );
        out.insert("bit_flag".to_string(), Value::from(self.bit_flag));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): user_id / user_name (PII) 经 sha8; brand_user_name (`gh_`) 直露; urls 只露字符数;
/// bit_flag 直露; provenance 自遮。
impl fmt::Debug for BizChatContactCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ul = |s: &str| s.chars().count();
        f.debug_struct("BizChatContactCreate")
            .field("provenance", &self.provenance)
            .field("user_id_sha8", &sha8(self.user_id.as_bytes()))
            .field("brand_user_name", &self.brand_user_name)
            .field("user_name_sha8", &sha8(self.user_name.as_bytes()))
            .field("head_img_url_len", &ul(&self.head_img_url))
            .field("profile_url_len", &ul(&self.profile_url))
            .field("bit_flag", &self.bit_flag)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> BizChatContactCreate {
        BizChatContactCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "bizchat.db".to_string(),
                source_native_id: "BizUser_3949bf65".to_string(),
                event_type: EventType::BizChatContactUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            // 真库样本: 企微 wxid → 品牌号 gh_44bfefcbb4a5 / 显示名 "白星" (2026-07-07 inspect)。
            user_id: "ww16xxxxxxxxxxxxxxxxxxx".to_string(),
            brand_user_name: "gh_44bfefcbb4a5".to_string(),
            user_name: "白星".to_string(),
            head_img_url: "http://wx.qlogo.cn/mmhead/x/0".to_string(),
            profile_url: "https://work.weixin.qq.com/ca/x".to_string(),
            bit_flag: 16,
        }
    }

    /// 默认模式: user_id 脱敏 _sha; user_name 脱敏 _sha; brand_user_name/bit_flag 照原; urls 不进 payload。
    #[test]
    fn payload_default_redacts() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["user_id_sha"], Value::from(sha256_hex("ww16xxxxxxxxxxxxxxxxxxx")));
        assert_eq!(o["user_name_sha"], Value::from(sha256_hex("白星")), "显示名默认 sha");
        assert!(!o.contains_key("user_id"), "K-R4: 默认不出裸 id");
        assert!(!o.contains_key("user_name"), "K-R4: 默认不出裸显示名");
        assert_eq!(o["brand_user_name"], Value::from("gh_44bfefcbb4a5"));
        assert_eq!(o["bit_flag"], Value::from(16));
        assert!(!o.contains_key("head_img_url"), "url 只进 L2 不进 payload");
        assert!(!o.contains_key("profile_url"), "url 只进 L2 不进 payload");
    }

    /// plaintext: user_id + user_name 全明文 (ADR-427)。
    #[test]
    fn payload_plaintext_exposes() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["user_id"], Value::from("ww16xxxxxxxxxxxxxxxxxxx"));
        assert_eq!(o["user_name"], Value::from("白星"));
    }

    /// K-R4: 默认 payload + Debug 不泄裸值 (id / 显示名); urls 只露长度。
    #[test]
    fn k_r4_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        let dbg = format!("{:?}", sample());
        for raw in ["ww16xxxxxxxxxxxxxxxxxxx", "白星", "wxid_acct_001"] {
            assert!(!dumped.contains(raw), "K-R4: payload 泄裸值 {raw}");
            assert!(!dbg.contains(raw), "K-R4: Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("user_id_sha8") && dbg.contains("user_name_sha8"));
        assert!(
            dbg.contains("head_img_url_len") && dbg.contains("profile_url_len"),
            "urls 只露长度"
        );
        assert!(dbg.contains("gh_44bfefcbb4a5"), "brand_user_name (gh_) 直露");
    }
}
