//! event::favorite — (favorite_update, create) 事件字段集. 微信收藏 (favorite.db `fav_db_item`) 一条。
//!
//! 照 [`super::session::SessionUpdate`] 模板 (嵌 [`Provenance`] + to_payload_json + 手写 Debug + 不 derive Serialize)。
//! 数据源 = favorite.db `fav_db_item`。收藏项创建后基本不变 (update_time 重打标签时才 bump) → 全表重扫 +
//! content_digest 去重 + UPSERT (同 session/contact)。ADR-454 扩 alpha 第 8 事件类型 (照会话 ADR-412 先例)。
//!
//! 字段归桶: `from_user` / `real_chat_name` = id 类 (来源 wxid/@chatroom / 群内真实发送者); `source_id` = 元数据
//! (来源消息 hash id, 非 wxid); `server_id`/`local_id`/`fav_type`/`update_time`/`content_len` = 元数据类。
//! **content 本身不落** (最大 288KB 的 XML/proto payload, 按 type 拆解是独立大件 → 只存 `content_len` 尺寸)。
//!
//! ## content_digest (canonical.rs favorite 臂)
//! server_id / fav_type / update_time / from_user_sha / source_id — 唯一标识 + 溯源一条收藏 (immutable per 收藏)。
//! local_id / real_chat_name / content_len 只进 L2 (本地 id / 群内发送者 / 尺寸, 非身份)。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 from_user / real_chat_name 裸值被误序列化。
//! - **手写 `Debug`** — from_user / real_chat_name 经 [`sha8`] 脱敏; provenance.account_id 自遮。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, render_opt_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// 笔记(收藏)一个媒体引用 (ADR-472; content dataitem 里带 `<fullmd5>` 的一项 → favorite_media 派生行)。
/// md5/尺寸/类型非 PII → 可 derive Debug。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FavoriteMediaRef {
    /// 媒体在笔记内顺序 (0-based; 派生表 PK 判别列)。
    pub seq: i64,
    /// dataitem datatype (2 图片 / 6 文件 / 8 HTML 等)。
    pub data_type: i64,
    /// 内容 md5 (fullmd5; = 本地缓存文件**解密后** md5, app 据此定位本地文件解密; 非空)。
    pub media_md5: String,
    /// 内容字节数 (fullsize; 无 → 0)。
    pub media_size: i64,
    /// 数据格式 (datafmt, 如 "jpg"/"htm"; 可空)。
    pub data_fmt: Option<String>,
}

/// (favorite_update, create) 事件字段集 — 一条收藏 (favorite.db `fav_db_item`)。
///
/// `source_native_id` = `"Favorite_<local_id>"` (local_id 是本地 PK, 非 PII)。
pub struct FavoriteCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 服务端主键 (fav_db_item.server_id; 元数据; 进 digest — 收藏身份)。
    pub server_id: i64,
    /// 本地 id (fav_db_item.local_id; 元数据; 只进 L2 — 本地 PK 非身份)。
    pub local_id: i64,
    /// 收藏类型 (fav_db_item.type; 元数据; 真库核实 1=文本/2=图片/4=视频/5=链接/6=位置/14=聊天记录/18=笔记 等; 进 digest)。
    pub fav_type: i64,
    /// 收藏时间 (fav_db_item.update_time; unix 秒; 进 digest — 何时收藏, 溯源价值)。
    pub update_time: i64,
    /// 来源用户 (fav_db_item.fromusr; id 类: wxid / @chatroom; 进 digest 用 sha)。
    pub from_user: String,
    /// 群内真实发送者 (fav_db_item.realchatname; id 类, nullable; 只进 L2, Debug sha8)。
    pub real_chat_name: Option<String>,
    /// 来源消息 id (fav_db_item.source_id; hash id 非 wxid, nullable; 进 digest — 溯源到原消息)。
    pub source_id: Option<String>,
    /// content 字节长度 (fav_db_item content; 元数据; 只进 L2 — content 本身不落, 按 type 拆解是大件)。
    pub content_len: i64,
    /// 笔记正文 (ADR-471; 仅 type 18 笔记, 从 content XML `<datadesc>` 解; text 类, nullable;
    /// **只进 L2 favorite, 不进 payload/digest** — 私人内容 + 冻结事件 L2-only 先例 (同群备注); Debug 只露长度)。
    pub note_text: Option<String>,
    /// 笔记媒体引用 (ADR-472; 仅 type 18; content dataitem 带 fullmd5 的项; **投影到 favorite_media 派生表**,
    /// 不进本事件 payload/digest — favorite 第二投影, 同 message_media/mention 先例)。
    pub media: Vec<FavoriteMediaRef>,
}

impl FavoriteCreate {
    /// 渲染整条 favorite_update.create 的 payload_json (唯一出口)。
    ///
    /// 收藏项 immutable per digest (update_time 变即产新 fingerprint→新 archive), 无 server_seq 式陈旧风险 →
    /// 全字段进 payload (含 local_id/real_chat_name/content_len 元数据)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // id 类 (from_user 必填 / real_chat_name / source_id).
        render_field(&mut out, "from_user", &self.from_user, FieldCategory::Id, mode);
        render_opt_field(
            &mut out,
            "real_chat_name",
            self.real_chat_name.as_deref(),
            FieldCategory::Id,
            mode,
        );
        render_opt_field(
            &mut out,
            "source_id",
            self.source_id.as_deref(),
            FieldCategory::Metadata,
            mode,
        );
        // 数字元数据 — 直塞 (天然非敏感).
        out.insert("server_id".to_string(), Value::from(self.server_id));
        out.insert("local_id".to_string(), Value::from(self.local_id));
        out.insert("fav_type".to_string(), Value::from(self.fav_type));
        out.insert("update_time".to_string(), Value::from(self.update_time));
        out.insert("content_len".to_string(), Value::from(self.content_len));
        // note_text (笔记正文) **不进 payload** (L2-only, 同群备注/公告编辑者; 私人内容不扩冻结事件 payload)。

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): from_user / real_chat_name 经 sha8 脱敏; provenance 自遮。
/// **不准 derive Debug** — 会泄来源 wxid / 群内发送者裸值。source_id 是 hash id 非 wxid, 原样。
impl fmt::Debug for FavoriteCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FavoriteCreate")
            .field("provenance", &self.provenance)
            .field("server_id", &self.server_id)
            .field("local_id", &self.local_id)
            .field("fav_type", &self.fav_type)
            .field("update_time", &self.update_time)
            .field("from_user_sha8", &sha8(self.from_user.as_bytes()))
            .field("real_chat_name_sha8", &self.real_chat_name.as_deref().map(|s| sha8(s.as_bytes())))
            .field("source_id", &self.source_id)
            .field("content_len", &self.content_len)
            // 笔记正文 text 类 → 只露字符数 (私人内容, 不 hash 不出裸值)。
            .field("note_text_len", &self.note_text.as_deref().map(|s| s.chars().count()))
            .field("media_count", &self.media.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> FavoriteCreate {
        FavoriteCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "favorite.db".to_string(),
                source_native_id: "Favorite_156".to_string(),
                event_type: EventType::FavoriteUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            server_id: 329,
            local_id: 156,
            fav_type: 14,
            update_time: 1_779_354_334,
            from_user: "wxid_source_002".to_string(),
            real_chat_name: Some("wxid_realsender".to_string()),
            source_id: Some("c681bd33e92af06ac334df0585dbf0".to_string()),
            content_len: 2048,
            note_text: Some("私密笔记正文".to_string()),
            media: vec![
                FavoriteMediaRef {
                    seq: 0,
                    data_type: 2,
                    media_md5: "a".repeat(32),
                    media_size: 12_345,
                    data_fmt: Some("jpg".into()),
                },
                FavoriteMediaRef {
                    seq: 1,
                    data_type: 8,
                    media_md5: "b".repeat(32),
                    media_size: 678,
                    data_fmt: Some("htm".into()),
                },
            ],
        }
    }

    /// 默认模式: from_user/real_chat_name 脱敏 _sha; source_id/数字元数据照原。
    #[test]
    fn payload_default_redacts_id() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["from_user_sha"], Value::from(sha256_hex("wxid_source_002")));
        assert!(!o.contains_key("from_user"), "K-R4: 默认不出裸 from_user");
        assert_eq!(o["real_chat_name_sha"], Value::from(sha256_hex("wxid_realsender")));
        // 元数据照原.
        assert_eq!(o["server_id"], Value::from(329));
        assert_eq!(o["fav_type"], Value::from(14));
        assert_eq!(o["update_time"], Value::from(1_779_354_334_i64));
        assert_eq!(o["content_len"], Value::from(2048));
        assert_eq!(
            o["source_id"],
            Value::from("c681bd33e92af06ac334df0585dbf0"),
            "source_id 非 wxid 照原"
        );
    }

    /// plaintext: from_user + real_chat_name 全明文 (ADR-427 默认即此)。
    #[test]
    fn payload_plaintext_exposes_id() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["from_user"], Value::from("wxid_source_002"));
        assert_eq!(o["real_chat_name"], Value::from("wxid_realsender"));
        assert!(!o.contains_key("from_user_sha"));
    }

    /// K-R4: 默认模式 payload 不含任何裸敏感值。
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["wxid_source_002", "wxid_realsender", "wxid_acct_001", "私密笔记正文"] {
            assert!(
                !dumped.contains(raw),
                "K-R4: 默认 payload 泄裸值 {raw} (note_text 应 L2-only 不进 payload)"
            );
        }
    }

    /// K-R4: 手写 Debug 不泄 from_user / real_chat_name / account_id 裸值。
    #[test]
    fn debug_redacts_sensitive() {
        let dbg = format!("{:?}", sample());
        for raw in ["wxid_source_002", "wxid_realsender", "wxid_acct_001", "私密笔记正文"] {
            assert!(!dbg.contains(raw), "Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("from_user_sha8"));
        assert!(dbg.contains("real_chat_name_sha8"));
        assert!(dbg.contains("note_text_len"), "笔记正文只露长度");
    }
}
