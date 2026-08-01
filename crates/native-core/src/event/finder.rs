//! event::finder — (finder_visit_update, create) 事件字段集. 微信视频号主页记录
//! (general.db `wcfinderuserpage`) 一条 = 一个视频号号主 (你访问过其主页 / 与你相关的视频号)。
//!
//! 照 [`super::friend_verify::FriendVerifyCreate`] 模板 (general.db 专表 → alpha 事件; ADR-473)。
//! **真库坐实** (2026-07-06 inspect wcfinderuserpage 928 行): `username` = **视频号号主的 wxid/微信号**
//! (839 wxid + 84 微信号 alias + 4 @stranger + 1 @openim; **不是**频道 id — 频道 id `v2_..@finder` 在
//! f6 URL 里)。`extra_buffer` proto: f2=视频号昵称 / f5=访问时刻秒 / f6=主页 URL (含频道 id)。
//! 仅 492/928 有访问时刻或昵称, 其余为空壳 (纯号主 id 无频道数据) → pipeline 跳过空壳 (见 run_finder_visit_pipeline)。
//!
//! ## content_digest (canonical.rs finder 臂)
//! owner_username_sha / name / visit_time — 号主 (身份) + 视频号昵称 + 访问时刻 (3 元)。profile_url 只进 L2
//! (含频道 id, 冗余)。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — owner_username / name 经 [`sha8`]; profile_url 含 id → 只露长度。
//! - name (视频号昵称) 出 payload 走 [`FieldCategory::DisplayName`]; owner_username 走 [`FieldCategory::Id`]。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (finder_visit_update, create) 事件字段集 — 一个视频号号主 (general.db `wcfinderuserpage`)。
///
/// `source_native_id` = `"Finder_<md5_hex(owner_username)>"` (号主 id → 内部 md5, 不暴露明文)。
pub struct FinderVisitCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 视频号号主 id (wcfinderuserpage.username = wxid/微信号; id 类; 进 digest 用 sha; anchor 用 md5)。
    pub owner_username: String,
    /// 视频号昵称 (extra_buffer proto f2; display_name 类; 进 digest)。
    pub name: String,
    /// 访问时刻 (extra_buffer proto f5; unix 秒; 进 digest)。
    pub visit_time: i64,
    /// 主页 URL (extra_buffer proto f6; 含频道 id; 元数据; 只进 L2, Debug 只露长度)。
    pub profile_url: String,
}

impl FinderVisitCreate {
    /// **空壳行判据** —— 纯号主 id, 既无频道数据也无访问时刻: 无溯源价值, ingest 不 archive 不落 L1。
    ///
    /// **ingest 与热查共用这一份** (R16-1)。`wcfinderuserpage` 的空壳行**只有解完 proto 才认得出**
    /// (判据落在 f2/f5/f6 上, SQL 过滤不了) —— ingest 落 L1 时跳掉的行, 热查直读源库时必须用**同一个
    /// 判据**跳掉, 否则冷热行集分叉(冷查少热查多)。判据写两遍必漂, 故收在这。
    ///
    /// 注意是**三者全空**才算空壳: 真库里 `name`/`profile_url` 空而 `visit_time` 非 0 的行是**正常数据**
    /// (723 行的真 L1 里头两条就是), 不能跳。
    #[must_use]
    pub fn is_empty_shell(&self) -> bool {
        self.name.is_empty() && self.visit_time == 0 && self.profile_url.is_empty()
    }

    /// 渲染整条 finder_visit_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // id 类 (owner_username — 默认 sha).
        render_field(
            &mut out,
            "owner_username",
            &self.owner_username,
            FieldCategory::Id,
            mode,
        );
        // display 类 (name 视频号昵称 — 默认 sha, plaintext 出原文).
        render_field(&mut out, "name", &self.name, FieldCategory::DisplayName, mode);
        // 数字/元数据 — 直塞 (profile_url 只进 L2, 不进 payload — 含频道 id 冗余)。
        out.insert("visit_time".to_string(), Value::from(self.visit_time));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): owner_username / name 经 sha8; profile_url (含 id) 只露字符数; provenance 自遮。
impl fmt::Debug for FinderVisitCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinderVisitCreate")
            .field("provenance", &self.provenance)
            .field("owner_username_sha8", &sha8(self.owner_username.as_bytes()))
            .field("name_sha8", &sha8(self.name.as_bytes()))
            .field("visit_time", &self.visit_time)
            .field("profile_url_len", &self.profile_url.chars().count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> FinderVisitCreate {
        FinderVisitCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "general.db".to_string(),
                source_native_id: "Finder_3949bf65".to_string(),
                event_type: EventType::FinderVisitUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            // 真库样本: 号主 wxid → 视频号"小应5899" (2026-07-06 inspect)。
            owner_username: "wxid_qrst2345uvwx678".to_string(),
            name: "小应5899".to_string(),
            visit_time: 1_752_221_077,
            profile_url: "https://channels.weixin.qq.com/web/pages/profile?username=v2_xyz".to_string(),
        }
    }

    /// 默认模式: owner_username 脱敏 _sha; name 脱敏 _sha; visit_time 照原; profile_url 不进 payload。
    #[test]
    fn payload_default_redacts() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["owner_username_sha"], Value::from(sha256_hex("wxid_qrst2345uvwx678")));
        assert_eq!(o["name_sha"], Value::from(sha256_hex("小应5899")), "视频号昵称默认 sha");
        assert!(!o.contains_key("owner_username"), "K-R4: 默认不出裸 id");
        assert!(!o.contains_key("name"), "K-R4: 默认不出裸昵称");
        assert_eq!(o["visit_time"], Value::from(1_752_221_077_i64));
        assert!(!o.contains_key("profile_url"), "profile_url 只进 L2 不进 payload");
    }

    /// plaintext: owner_username + name 全明文 (ADR-427)。
    #[test]
    fn payload_plaintext_exposes() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["owner_username"], Value::from("wxid_qrst2345uvwx678"));
        assert_eq!(o["name"], Value::from("小应5899"));
    }

    /// K-R4: 默认 payload + Debug 不泄裸值 (id / 昵称)。
    #[test]
    fn k_r4_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        let dbg = format!("{:?}", sample());
        for raw in ["wxid_qrst2345uvwx678", "小应5899", "wxid_acct_001"] {
            assert!(!dumped.contains(raw), "K-R4: payload 泄裸值 {raw}");
            assert!(!dbg.contains(raw), "K-R4: Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("owner_username_sha8") && dbg.contains("name_sha8"));
        assert!(dbg.contains("profile_url_len"), "profile_url 只露长度");
    }
}
