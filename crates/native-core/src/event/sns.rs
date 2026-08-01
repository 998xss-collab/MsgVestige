//! event::sns — (sns_event, create) 事件字段集. 朋友圈一条动态 (sns.db `SnsTimeLine`)。ADR-467 件1。
//!
//! 照 [`super::favorite::FavoriteCreate`] 模板 (嵌 [`Provenance`] + to_payload_json + 手写 Debug + 不 derive Serialize)。
//! 数据源 = sns.db `SnsTimeLine` 一行 (tid/user_name/content-XML)。动态本体 immutable (发出后正文/作者/时间/类型
//! 不变) → 全表重扫 + content_digest 去重 + UPSERT (同 favorite; 点赞变只刷 L2 计数不产新 archive)。
//!
//! 字段归桶: `author` / `source_user` = id 类 (发布者 wxid / 转发来源 wxid); `content_desc` = text 类 (正文);
//! `author_nickname` / `location_label` / `title` = display 类; tid/create_time/moment_type/各计数/坐标/content_len
//! = 元数据类。**原始 content XML 不落** (只存 content_len 尺寸, 同 favorite content 不落); 但 content_desc(正文)
//! 存明文 (朋友圈正文即动态主体, 同 message text_content)。
//!
//! ## content_digest (canonical.rs sns 臂, 恰 4 元)
//! tid / author_sha / create_time / moment_type — 唯一标识 + immutable 属性 (动态本体指纹)。点赞/评论计数 +
//! 正文/位置/媒体等只进 L2 **不进 digest** (点赞变不产新 fingerprint; 互动增长历史留件2 moment_interaction)。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 author / content_desc 裸值被误序列化。
//! - **手写 `Debug`** — author / source_user / author_nickname / content_desc / location_label / title 经
//!   [`sha8`] 脱敏; provenance.account_id 自遮。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, render_opt_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (sns_event, create) 事件字段集 — 一条朋友圈动态 (sns.db `SnsTimeLine`)。ADR-467 件1 动态本体。
///
/// `source_native_id` = `"Sns_<tid>"` (tid 是 SnsTimeLine PK / rowid 别名, 雪花 id 可为负, 非 wxid)。
pub struct SnsCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 动态 id (SnsTimeLine.tid = rowid 别名; 雪花 id 可为负; 元数据; 进 digest — 动态身份)。
    pub tid: i64,
    /// 发布者 wxid (SnsTimeLine.user_name = TimelineObject/username; id 类; 进 digest 用 sha)。
    pub author: String,
    /// 发布时间 (TimelineObject/createTime; unix 秒; 元数据; 进 digest — immutable)。
    pub create_time: i64,
    /// 动态类型 (ContentObject/type; 1图文/2文字/3公众号/7封面/15小视频/28视频号 等; 元数据; 进 digest)。
    pub moment_type: i64,

    // ── 只进 L2 (不进 digest) ──
    /// 正文 (TimelineObject/contentDesc; text 类; 空串=无正文; L2 明文 + _len, Debug sha8)。
    pub content_desc: String,
    /// 发布者缓存昵称 (LocalExtraInfo/nickname; display 类, nullable; L2 明文, Debug sha8)。
    pub author_nickname: Option<String>,
    /// 转发来源 wxid (TimelineObject/sourceUserName; id 类, nullable; L2 明文, Debug sha8)。
    pub source_user: Option<String>,
    /// 位置名 (location@poiName 属性; display 类, nullable; L2 明文, Debug len)。
    pub location_label: Option<String>,
    /// 纬度 (location@latitude 属性原值, 不换算; nullable; 元数据)。
    pub latitude: Option<f64>,
    /// 经度 (location@longitude 属性原值; nullable; 元数据)。
    pub longitude: Option<f64>,
    /// 卡片/视频标题 (ContentObject/title; display 类, nullable; L2 明文)。
    pub title: Option<String>,
    /// 链接/视频页 url (ContentObject/contentUrl; text 类, nullable; L2 明文)。
    pub link_url: Option<String>,
    /// 媒体数 (mediaList 内 media 计数; 元数据; 逐条 url/md5 留件2)。
    pub media_count: i64,
    /// 点赞数 (like_user_list 内 type=1 计数; 元数据; 逐条点赞人留件2)。
    pub like_count: i64,
    /// 评论数 (like_user_list 内 type=2 计数; 元数据; 逐条评论文本留件2)。
    pub comment_count: i64,
    // 补列 (ADR-491; content XML 边角字段, 真库核有数据; **L2-only 不进 content_digest**)。
    /// 转发来源昵称 (sourceNickName; display 类, nullable; 真库 3.7%)。
    pub source_nickname: Option<String>,
    /// 是否互相关注 (is_bidirectional_fan; 0 单向/1 互关; 真库 互关11550/单向520)。
    pub is_bidirectional_fan: i64,
    /// 是否富文本朋友圈 (is_rich_text; 0 普通/1 富文本; 真库 富文本2698)。
    pub is_rich_text: i64,
    /// 公众号动态 gh_id (publicUserName; id 类, nullable; 真库 2.8%)。
    pub public_user_name: Option<String>,
    /// 来源应用名 (appName; display 类, nullable; 真库 3.0%)。
    pub app_name: Option<String>,
    /// 原始 content XML 字节长度 (content 本身不落; 元数据)。
    pub content_len: i64,

    /// 原始 content XML **载体** (件2a): 供派生投影 (project_moment_media 等) 再解析逐条媒体/互动。
    /// **不落 moment 表 / 不进 content_digest / 不进 payload_json** (同 message text_content 是派生源, 但 SNS
    /// 正文≠全XML 故单独载); K-R4 Debug 只露长度 (全 XML 含 wxid/正文/媒体 url)。
    pub raw_content: String,
}

impl SnsCreate {
    /// 渲染整条 sns_event.create 的 payload_json (唯一出口)。
    ///
    /// 动态本体 immutable per digest (create/author/type 变即产新 fingerprint), 点赞计数只 L2 刷新 →
    /// 全字段进 payload (含计数/坐标/content_len 元数据)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // id 类 (author 必填 / source_user 可空).
        render_field(&mut out, "author", &self.author, FieldCategory::Id, mode);
        render_opt_field(
            &mut out,
            "source_user",
            self.source_user.as_deref(),
            FieldCategory::Id,
            mode,
        );
        // display / text 类.
        render_opt_field(
            &mut out,
            "author_nickname",
            self.author_nickname.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_field(
            &mut out,
            "content_desc",
            &self.content_desc,
            FieldCategory::TextContent,
            mode,
        );
        render_opt_field(
            &mut out,
            "location_label",
            self.location_label.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "title",
            self.title.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "link_url",
            self.link_url.as_deref(),
            FieldCategory::TextContent,
            mode,
        );
        // 数字元数据 — 直塞 (天然非敏感; 坐标是数值, 语义位置名走 location_label 脱敏).
        out.insert("tid".to_string(), Value::from(self.tid));
        out.insert("create_time".to_string(), Value::from(self.create_time));
        out.insert("moment_type".to_string(), Value::from(self.moment_type));
        out.insert("latitude".to_string(), self.latitude.map_or(Value::Null, Value::from));
        out.insert("longitude".to_string(), self.longitude.map_or(Value::Null, Value::from));
        out.insert("media_count".to_string(), Value::from(self.media_count));
        out.insert("like_count".to_string(), Value::from(self.like_count));
        out.insert("comment_count".to_string(), Value::from(self.comment_count));
        // 补列 (ADR-491): 转发来源昵称/公众号gh_id/应用名 走脱敏渲染; 关系/富文本标志直塞元数据。
        render_opt_field(
            &mut out,
            "source_nickname",
            self.source_nickname.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "public_user_name",
            self.public_user_name.as_deref(),
            FieldCategory::Id,
            mode,
        );
        render_opt_field(
            &mut out,
            "app_name",
            self.app_name.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        out.insert(
            "is_bidirectional_fan".to_string(),
            Value::from(self.is_bidirectional_fan),
        );
        out.insert("is_rich_text".to_string(), Value::from(self.is_rich_text));
        out.insert("content_len".to_string(), Value::from(self.content_len));

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): author / source_user / author_nickname / content_desc / title 经 sha8 脱敏;
/// location_label 露长度; provenance 自遮。**不准 derive Debug** — 会泄发布者 wxid / 正文裸值。
impl fmt::Debug for SnsCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("SnsCreate")
            .field("provenance", &self.provenance)
            .field("tid", &self.tid)
            .field("author_sha8", &sha8(self.author.as_bytes()))
            .field("create_time", &self.create_time)
            .field("moment_type", &self.moment_type)
            .field("content_desc_sha8", &sha8(self.content_desc.as_bytes()))
            .field("author_nickname_sha8", &o(&self.author_nickname))
            .field("source_user_sha8", &o(&self.source_user))
            .field("location_label_len", &self.location_label.as_ref().map(|s| s.chars().count()))
            .field("latitude", &self.latitude)
            .field("longitude", &self.longitude)
            .field("title_sha8", &o(&self.title))
            .field("link_url_sha8", &o(&self.link_url))
            .field("media_count", &self.media_count)
            .field("like_count", &self.like_count)
            .field("comment_count", &self.comment_count)
            // 补列 (ADR-491): 昵称/gh_id/应用名 sha8 脱敏; 关系/富文本标志直显。
            .field("source_nickname_sha8", &o(&self.source_nickname))
            .field("is_bidirectional_fan", &self.is_bidirectional_fan)
            .field("is_rich_text", &self.is_rich_text)
            .field("public_user_name_sha8", &o(&self.public_user_name))
            .field("app_name_sha8", &o(&self.app_name))
            .field("content_len", &self.content_len)
            // raw_content (全 XML 载体) 只露长度 (K-R4: 含 wxid/正文/媒体 url)。
            .field("raw_content_len", &self.raw_content.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> SnsCreate {
        SnsCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "sns.db".to_string(),
                source_native_id: "Sns_-3518821952372526549".to_string(),
                event_type: EventType::SnsEvent,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            tid: -3_518_821_952_372_526_549,
            author: "wxid_author_002".to_string(),
            create_time: 1_779_546_990,
            moment_type: 1,
            content_desc: "麻了".to_string(),
            author_nickname: Some("小明昵称".to_string()),
            source_user: None,
            location_label: Some("台州市 · 路桥十里长街".to_string()),
            latitude: Some(121.382_042),
            longitude: Some(28.576_089_9),
            title: None,
            link_url: None,
            media_count: 1,
            like_count: 3,
            comment_count: 0,
            source_nickname: None,
            is_bidirectional_fan: 0,
            is_rich_text: 0,
            public_user_name: None,
            app_name: None,
            content_len: 2170,
            raw_content: "<SnsDataItem><TimelineObject><contentDesc>麻了</contentDesc></TimelineObject></SnsDataItem>"
                .to_string(),
        }
    }

    /// 默认模式: author 脱敏 _sha; content_desc/author_nickname 脱敏 _sha+_len; 数字元数据照原。
    #[test]
    fn payload_default_redacts_sensitive() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["author_sha"], Value::from(sha256_hex("wxid_author_002")));
        assert!(!o.contains_key("author"), "K-R4: 默认不出裸 author");
        assert_eq!(o["content_desc_sha"], Value::from(sha256_hex("麻了")));
        assert_eq!(o["content_desc_len"], Value::from(2_i64), "麻了 = 2 字符");
        assert_eq!(o["author_nickname_sha"], Value::from(sha256_hex("小明昵称")));
        // source_user None → null 占位 (id 类)。
        assert_eq!(o["source_user_sha"], Value::Null);
        // 元数据照原。
        assert_eq!(o["tid"], Value::from(-3_518_821_952_372_526_549_i64));
        assert_eq!(o["create_time"], Value::from(1_779_546_990_i64));
        assert_eq!(o["moment_type"], Value::from(1));
        assert_eq!(o["media_count"], Value::from(1));
        assert_eq!(o["like_count"], Value::from(3));
        assert_eq!(o["latitude"], Value::from(121.382_042));
        // raw_content 载体不进 payload (件2a: 只作派生 projection 用, content 本身不落)。
        assert!(!o.contains_key("raw_content"), "raw_content 载体不进 payload");
    }

    /// plaintext: author + content_desc 全明文 (ADR-427 默认即此)。
    #[test]
    fn payload_plaintext_exposes_sensitive() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["author"], Value::from("wxid_author_002"));
        assert_eq!(o["content_desc"], Value::from("麻了"));
        assert_eq!(o["author_nickname"], Value::from("小明昵称"));
        assert!(!o.contains_key("author_sha"));
    }

    /// K-R4: 默认模式 payload 不含任何裸敏感值。
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["wxid_author_002", "麻了", "小明昵称", "wxid_acct_001"] {
            assert!(!dumped.contains(raw), "K-R4: 默认 payload 泄裸值 {raw}");
        }
    }

    /// K-R4: 手写 Debug 不泄 author / content_desc / author_nickname 裸值。
    #[test]
    fn debug_redacts_sensitive() {
        let dbg = format!("{:?}", sample());
        for raw in ["wxid_author_002", "麻了", "小明昵称", "wxid_acct_001"] {
            assert!(!dbg.contains(raw), "Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("author_sha8"));
        assert!(dbg.contains("content_desc_sha8"));
    }
}
