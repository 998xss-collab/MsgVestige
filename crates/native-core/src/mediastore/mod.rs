//! 媒体内容仓(CAS)+ 状态账本 —— R10(批4·最长杆)。
//!
//! 把现有批处理媒体导出(media/{image,video,voice}_export)换成: 媒体按**内容 sha256** 存一份(去重)+ 侧车账本
//! (`ledger.db`)记身份/来源/变体/校验/回收关系, 支持断点续跑、崩溃恢复、逐项状态、GC。
//!
//! 权威设计 = `docs-dev/20-讨论沉淀/媒体落库-CAS-设计规格-v3.md`(v3.2 · 五轮外审真bug归零 · 架构锁定)。
//! 分期(§11): ①**身份 + 账本 DDL(本模块)** → ②引擎重构 discover/materialize/commit → ③状态分实体+job → ④崩溃协议
//! (journal+fencing+root-quota+recovery) → ⑤空间 → ⑥导出编排 → ⑦变体择优 → ⑧头像历史 → ⑨manifest/doctor → ⑩by-chat
//! 缓存 → ⑪自动保存 → ⑫§5c 契约 fold + ADR。
//!
//! **身份三层**(§1): 对外 [`MediaRef`](typed, 契约稳定) → 内 [`AssetId`](=`sha256:<hex>`, 物理寻址 + 强完整性/ETag)
//! → [`logical_group`](一段逻辑媒体, 持所有变体×派生)。解析链 `MediaRef → group → variant×derivation → asset`。

pub mod ledger;
// R10 §11-②: 三层引擎(discover/materialize/commit)—— 路径布局 + 值类型 + 共用 commit。
pub mod engine;
// R10 §11-②: 语音竖切(首个源实现, 验通三层契约再照搬 video/image)。
pub mod voice;
// R10 §11-②: 视频竖切(照搬 voice 三层, commit 脊复用; md5→hardlink 定位明文 mp4)。
pub mod video;
// R10 §11-②: 图片竖切(复用 fetch_image_one 定位+解密+wxgf 管线, commit 脊复用)。
pub mod image;

// 复审 P2: 只对外暴露 open_ledger(它保证建 schema 前开 foreign_keys); init_ledger_schema 是 pub(crate), 不外泄以免裸连接 FK 关。
pub use engine::{
    commit_materialized, CommitOutcome, DiscoveredItem, MaterializeFailure, MaterializeOutcome, Materialized,
    StoreLayout,
};
pub use image::{image_discover, image_discover_each, image_materialize, run_image_ingest, ImageIngestStats};
pub use ledger::{open_ledger, LEDGER_SCHEMA_VERSION};
pub use video::{run_video_ingest, video_discover, video_discover_each, video_materialize, VideoIngestStats};
pub use voice::{
    run_voice_ingest, scan_voice_anchors_into, voice_discover, voice_discover_each, voice_materialize, VoiceAnchorMap,
    VoiceIngestStats,
};

/// 对内 **asset 标识** = `sha256:<hex>`(某段**最终物化字节**的哈希)。CAS 物理寻址 + 强完整性/ETag 靠它(不靠上游 md5)。
/// 账本存全串 `sha256:<hex>`; 物理路径只用 `hex`(去前缀, 见 [`AssetId::hex`] / §五 存储布局)。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetId(String);

impl AssetId {
    /// 从 32 字节 sha256 digest 构造(小写 hex)。
    #[must_use]
    pub fn from_digest(digest: &[u8; 32]) -> Self {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(64);
        for b in digest {
            let _ = write!(hex, "{b:02x}");
        }
        Self(format!("sha256:{hex}"))
    }

    /// 解析账本里存的 `sha256:<hex>`; 非法(前缀不对/长度不对/**非小写** hex)→ None。
    /// 复审 P1: 只认 **64 位小写** hex —— 大写会在 NTFS(大小写不敏感)与小写撞同一物理路径, canonical 形态必须唯一。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let hex = s.strip_prefix("sha256:")?;
        (hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then(|| Self(s.to_string()))
    }

    /// 全串 `sha256:<hex>`(账本键)。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 裸 hex(去 `sha256:` 前缀)—— 物理路径 + 索引用(§12-A: ext 不进权威路径)。
    #[must_use]
    pub fn hex(&self) -> &str {
        self.0.strip_prefix("sha256:").unwrap_or(&self.0)
    }
}

/// 媒体**种类**(§1: kind 开放可扩; 聊天文件/合并转发/收藏附件是下一批 kind, §十三-1)。`asset_role` 里存字符串,
/// 此枚举给已知种类稳定串; 未来新 kind 直接加变体或用 [`MediaKind::Other`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaKind {
    /// 聊天图片(缩略/HD)。
    ChatImage,
    /// 视频。
    Video,
    /// 语音(SILK → WAV/MP3 派生)。
    Voice,
    /// 头像(字节会变 → MediaRef 带 version; 历史各版独立 asset)。
    Avatar,
    /// 表情包(自定义 emoticon)。
    Emoticon,
    /// 朋友圈媒体。
    Sns,
    /// 开放扩展(聊天文件/合并转发附件/收藏附件/…)。
    Other(String),
}

impl MediaKind {
    /// 稳定串标识(账本 `asset_role.kind` / `asset_registry.ref_kind` 用)。
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ChatImage => "chat_image",
            Self::Video => "video",
            Self::Voice => "voice",
            Self::Avatar => "avatar",
            Self::Emoticon => "emoticon",
            Self::Sns => "sns",
            Self::Other(s) => s,
        }
    }

    /// 从稳定串还原 —— **已知串归一到 typed 变体**(复审 P1: 否则 `Other("avatar")` 与 [`Self::Avatar`] 序列化同串却在
    /// `match` 里走不同分支, kind 判定分叉)。未知串才落 [`Self::Other`]。账本读回/外部输入都走这里, 保证 round-trip canonical。
    /// (命名避开 `FromStr::from_str`: 本方法**不可失败**、未知串归 `Other`, 不是可失败解析。)
    #[must_use]
    pub fn from_stable_str(s: &str) -> Self {
        match s {
            "chat_image" => Self::ChatImage,
            "video" => Self::Video,
            "voice" => Self::Voice,
            "avatar" => Self::Avatar,
            "emoticon" => Self::Emoticon,
            "sns" => Self::Sns,
            other => Self::Other(other.to_string()),
        }
    }

    /// 构造扩展 kind —— **经 [`from_stable_str`](Self::from_stable_str) 归一**, 串撞上已知 kind 时返回对应 typed 变体而非
    /// `Other`, 从构造侧根除 `Other("avatar")` 撞车。真正未知的串才是 `Other`。
    #[must_use]
    pub fn other(s: impl AsRef<str>) -> Self {
        Self::from_stable_str(s.as_ref())
    }

    /// 是否 canonical(即 `Other(s)` 的 `s` 不是已知 kind 的别名)。复审2 P2→P3: `Other("avatar")` 会序列化成与 [`Self::Avatar`]
    /// 同串却在 `match` 里走 `Other` 分支(分叉)。这是开放枚举 `Other(String)` 的通病(http::Method 等同款), 数据完整性已由
    /// 存储层 CHECK 兜底(空 version avatar 入不了库), 故**不做 newtype 密封**(过度、且是公认模式); 改由本方法 + 构造器 debug_assert
    /// 在测试/debug 下把"直接构造 `Other(已知名)`"打响, 引导走 [`other`](Self::other)/[`from_stable_str`](Self::from_stable_str)。
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        Self::from_stable_str(self.as_str()) == *self
    }
}

/// 对外 **媒体引用**(§1: typed `{kind, key, version?}`)—— 契约面稳定引用, 架在 §5c `/media/{key}` + registry 之上。
/// 图/视频 key = 上游 `wechat_media_md5`(**不预设它是哪段字节的哈希**); 语音 = svr_id; 头像 = locator + **version**
/// (头像字节会变、非不可变 → 必带 version, 见 §1 头像特殊 + §九 avatar_capture)。
/// `version` 缺省空串(非头像类不需要)。存/查 `asset_registry`(键 = 对外 key, **区别于** message 键 / 源身份键)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRef {
    // 复审 P1: 字段**私有** —— 只能经校验构造器建, 外部拿不到 `MediaRef{kind:Avatar, version:""}` 这种绕过路径。
    // (存储层还有 asset_registry `CHECK(ref_kind<>'avatar' OR ref_version<>'')` 兜底, 双保险。)
    kind: MediaKind,
    key: String,
    version: String,
}

impl MediaRef {
    /// 非头像类的无版本引用。头像**不该**走这里(字节会变必带 version, §一)。
    /// 复审3 P2: 头像契约改 **release 硬断言**(`assert!`, 不再只 debug)—— 空 version 的 avatar 引用即便没落库、只在查询/路由/缓存
    /// 阶段也会违约(registry 查不到该头像 → 合法头像查询失败), 存储 CHECK 兜不到这一段, 故构造侧直接拒(误用=panic)。
    ///
    /// # Panics
    /// `kind` 为 [`MediaKind::Avatar`](头像必须走 [`with_version`](Self::with_version))。
    #[must_use]
    pub fn new(kind: MediaKind, key: impl Into<String>) -> Self {
        // 复审4 P2: 按**稳定串** as_str()=="avatar" 判, 不按变体 —— 否则 Other("avatar") 绕过(它 as_str 也是 "avatar")。
        assert!(
            kind.as_str() != "avatar",
            "头像必须用 MediaRef::with_version 带 version(§一)"
        );
        debug_assert!(
            kind.is_canonical(),
            "别直接构造 Other(已知kind名); 用 MediaKind::other()/from_stable_str 归一"
        );
        Self {
            kind,
            key: key.into(),
            version: String::new(),
        }
    }

    /// 带版本引用(头像用; §一 头像必带 version)。
    ///
    /// # Panics
    /// `kind` 为 [`MediaKind::Avatar`] 但 `version` 为空(复审3 P2: release 硬断言, 头像 version 不得为空)。
    #[must_use]
    pub fn with_version(kind: MediaKind, key: impl Into<String>, version: impl Into<String>) -> Self {
        let version = version.into();
        // 复审4 P2: 同上, 按 as_str()=="avatar" 判, 堵 Other("avatar") 空 version 绕过。
        assert!(
            !(kind.as_str() == "avatar" && version.is_empty()),
            "头像 version 不得为空(§一)"
        );
        debug_assert!(
            kind.is_canonical(),
            "别直接构造 Other(已知kind名); 用 MediaKind::other()/from_stable_str 归一"
        );
        Self {
            kind,
            key: key.into(),
            version,
        }
    }

    /// 媒体种类。
    #[must_use]
    pub fn kind(&self) -> &MediaKind {
        &self.kind
    }

    /// 上游稳定 key(md5/svr_id/locator)。
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// 版本(头像非空; 其余空串)。
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_id_roundtrip_and_hex() {
        let digest = [0xabu8; 32];
        let a = AssetId::from_digest(&digest);
        assert_eq!(a.as_str(), format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(a.hex(), "ab".repeat(32));
        assert_eq!(AssetId::parse(a.as_str()), Some(a));
    }

    #[test]
    fn asset_id_parse_rejects_bad() {
        assert!(AssetId::parse("md5:abc").is_none(), "错前缀");
        assert!(AssetId::parse("sha256:xyz").is_none(), "非 hex / 短");
        assert!(
            AssetId::parse(&format!("sha256:{}", "ab".repeat(31))).is_none(),
            "长度不对"
        );
        // 复审 P1: 大写 hex 必拒(NTFS 大小写不敏感 → 与小写撞同一路径)。
        assert!(
            AssetId::parse(&format!("sha256:{}", "AB".repeat(32))).is_none(),
            "大写 hex 必拒"
        );
    }

    #[test]
    fn media_kind_stable_strings() {
        assert_eq!(MediaKind::ChatImage.as_str(), "chat_image");
        assert_eq!(MediaKind::Voice.as_str(), "voice");
        assert_eq!(MediaKind::Other("chat_file".into()).as_str(), "chat_file");
    }

    #[test]
    fn media_kind_from_str_canonicalizes() {
        // 复审 P1: 已知串归 typed 变体, 不留 Other("avatar") 撞车。
        assert_eq!(MediaKind::from_stable_str("avatar"), MediaKind::Avatar);
        assert_eq!(MediaKind::other("avatar"), MediaKind::Avatar, "构造器也归一");
        assert_eq!(MediaKind::from_stable_str("chat_image"), MediaKind::ChatImage);
        // 真未知串才落 Other, 且 round-trip 稳定。
        assert_eq!(
            MediaKind::from_stable_str("chat_file"),
            MediaKind::Other("chat_file".into())
        );
        assert_eq!(MediaKind::from_stable_str(MediaKind::Video.as_str()), MediaKind::Video);
        // 复审2 P2→P3: is_canonical 识破伪装的 Other(已知名)。
        assert!(MediaKind::Avatar.is_canonical());
        assert!(
            MediaKind::Other("chat_file".into()).is_canonical(),
            "真未知串是 canonical"
        );
        assert!(
            !MediaKind::Other("avatar".into()).is_canonical(),
            "Other(已知名) 非 canonical"
        );
    }

    #[test]
    fn media_ref_accessors_and_version() {
        let img = MediaRef::new(MediaKind::ChatImage, "md5abc");
        assert_eq!(img.kind(), &MediaKind::ChatImage);
        assert_eq!(img.key(), "md5abc");
        assert_eq!(img.version(), "", "非头像 version 空");
        let av = MediaRef::with_version(MediaKind::Avatar, "loc1", "v7");
        assert_eq!(av.version(), "v7");
    }

    #[test]
    #[should_panic(expected = "头像")]
    fn media_ref_new_avatar_panics() {
        // 复审3 P2: 头像走 new()(无 version)release 下也 panic。
        let _ = MediaRef::new(MediaKind::Avatar, "loc");
    }

    #[test]
    #[should_panic(expected = "version")]
    fn media_ref_avatar_empty_version_panics() {
        // 复审3 P2: 头像 with_version 空串 release 下也 panic。
        let _ = MediaRef::with_version(MediaKind::Avatar, "loc", "");
    }

    #[test]
    #[should_panic(expected = "头像")]
    fn media_ref_disguised_avatar_other_panics() {
        // 复审4 P2: Other("avatar") 伪装头像走 new() 也按 as_str 拦下(不再只匹配 Avatar 变体)。
        let _ = MediaRef::new(MediaKind::Other("avatar".into()), "loc");
    }
}
