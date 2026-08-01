//! decoder::media — 从消息 `text_content` 的媒体 XML 抽 md5/aeskey/cdn/尺寸/时长 (图/视频/表情/语音)。
//!
//! 微信媒体消息的 content 是 `<msg><img .../></msg>` (type 3 图) / `<msg><videomsg .../></msg>` (type 43 视频) /
//! `<msg><emoji .../></msg>` (type 47 表情) / `<msg><voicemsg .../></msg>` (type 34 语音) XML (decoder 已把 zstd
//! 解压进 text_content)。本 mod 把媒体 tag 的**属性**抽成结构化字段 → 派生 L2 表 message_media (ADR-456/462)。
//! **纯字符串抽属性, infallible** (返 `Option`: 非媒体消息 / 无可用引用 → None)。
//!
//! ## 字段来源 (采同行 WDA `chat_export_service.py` 解法, 无需用户验证)
//! - 图 `<img md5= aeskey= cdnthumburl= cdnmidimgurl= length=>`;
//! - 视频 `<videomsg md5= newmd5= aeskey= cdnvideourl= cdnthumburl= length= playlength=>`;
//! - 表情 `<emoji md5= aeskey= cdnurl= productid= len=>`;
//! - 语音 `<voicemsg voicemd5= aeskey= voiceurl= length= voicelength= voiceformat=>` (ADR-462; 属性名带 voice 前缀)。
//!   md5=媒体内容哈希 (hardlink 索引键); cdn_url=CDN 下载地址; aes_key=CDN 解密密钥; play_length=视频秒/语音毫秒。
//!   **⚠️ 语音丢弃例外**: 语音只要有时长就落 (voicelength 100% 覆盖, url/md5 常缺 — 别丢时长这条内容)。
//!
//! ## K-R4
//! - md5/aes_key/cdn_url/thumb_url/extra_id 是媒体资源引用 (aes_key 更是解密密钥) → [`MediaCard`] 手写
//!   Debug 走 [`sha8`] 脱敏 (同 [`AppmsgCard`](super::appmsg::AppmsgCard))。
//! - 本 mod 派生自 text_content (已在 message content_digest); message_media 表 **L2-only 不进 digest/payload**。

use std::fmt;

use crate::key_provider::sha8;

/// 媒体类别 (message_media.media_kind 判别列)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MediaKind {
    /// 图片 (msg_type 3)。
    Image,
    /// 视频 (msg_type 43)。
    Video,
    /// 表情 (msg_type 47)。
    Emoji,
    /// 语音 (msg_type 34; `<voicemsg>` — 竞品差距 ADR-462)。
    Voice,
}

impl MediaKind {
    /// L2 落库判别串。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MediaKind::Image => "image",
            MediaKind::Video => "video",
            MediaKind::Emoji => "emoji",
            MediaKind::Voice => "voice",
        }
    }

    /// msg_type → MediaKind (非媒体类型返 None)。
    fn from_msg_type(msg_type: i32) -> Option<Self> {
        match msg_type {
            3 => Some(MediaKind::Image),
            43 => Some(MediaKind::Video),
            47 => Some(MediaKind::Emoji),
            34 => Some(MediaKind::Voice),
            _ => None,
        }
    }
}

/// 从媒体 XML 抽出的字段 (图/视频/表情通用)。
#[derive(Clone, PartialEq, Eq)]
pub struct MediaCard {
    /// 媒体类别 (图/视频/表情)。
    pub media_kind: MediaKind,
    /// 媒体内容 MD5 (32 hex; hardlink 索引键; 可空)。
    pub md5: Option<String>,
    /// CDN 解密密钥 (`aeskey`; 可空)。
    pub aes_key: Option<String>,
    /// 主 CDN 下载地址 (图 `cdnmidimgurl`/`cdnbigimgurl` / 视频 `cdnvideourl` / 表情 `cdnurl`; 可空)。
    pub cdn_url: Option<String>,
    /// 缩略图 CDN 地址 (`cdnthumburl`; 表情无; 可空)。
    pub thumb_url: Option<String>,
    /// 文件字节数 (`length`/`len`; 未知 0)。
    pub file_size: i64,
    /// 视频时长秒 (`playlength`; 非视频 0)。
    pub play_length: i64,
    /// 类型专属附加 id (图片 `hdmd5` / 视频 `newmd5` / 表情 `productid`; 可空)。
    pub extra_id: Option<String>,
}

/// 抽 `<tag`.. 开标签内的属性串 (自 `<tag` 到本开标签的 `>` 之间; 媒体 tag 是自闭 `<img .../>`)。
/// 扫开标签尾 `>` 时**跳过引号内的 `>`** (属性值含裸 `>` 不误截断; codex 批D P2)。无该 tag / 无闭合 → None。
/// `pub(crate)`: 位置(location) 等同类 XML-tag 抽取件复用 (媒体系列共享 XML helper)。
pub(crate) fn open_tag_body<'a>(haystack: &'a str, tag: &str) -> Option<&'a str> {
    let needle = format!("<{tag}");
    let mut from = 0;
    loop {
        let pos = haystack[from..].find(&needle)? + from;
        let after = pos + needle.len();
        // 边界: `<tag` 后须是空白 / '/' / '>' (防 `<image` 误配 `<img`)。
        match haystack[after..].chars().next() {
            Some('>') => return Some(""),
            Some(c) if c.is_whitespace() || c == '/' => {
                // 扫本开标签的 '>' — 引号内 (`"` / `'`) 的 '>' 跳过 (属性值含 '>' 不截断)。
                let body = &haystack[after..];
                let mut quote: Option<char> = None;
                for (i, ch) in body.char_indices() {
                    match quote {
                        Some(q) => {
                            if ch == q {
                                quote = None;
                            }
                        }
                        None => match ch {
                            '"' | '\'' => quote = Some(ch),
                            '>' => return Some(&body[..i]),
                            _ => {}
                        },
                    }
                }
                return None; // 无闭合 '>' = 畸形 tag, 不抽
            }
            _ => from = after,
        }
    }
}

/// 从属性串抽 `attr="value"` / `attr='value'` (attr 前须是 XML 属性分隔符 = 空白 / '/', 防 `md5` 误配
/// `cdnthumbmd5`/`newmd5`/`hdmd5`; codex 批D P2 收紧: 不把 `foo-md5=` 当边界)。空值 → None。
/// `pub(crate)`: 位置等同类抽取件复用。
pub(crate) fn extract_attr(attrs: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=");
    let mut from = 0;
    loop {
        let pos = attrs[from..].find(&needle)? + from;
        // 边界: attr 前一个字符须是空白 / '/' (XML 属性分隔) 或串首 — 否则是更长属性名/带连字符名的后缀。
        let boundary = pos == 0
            || attrs[..pos]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_whitespace() || c == '/');
        let after = pos + needle.len();
        if boundary {
            let rest = &attrs[after..];
            if let Some(quote) = rest.chars().next() {
                if quote == '"' || quote == '\'' {
                    let val_start = after + quote.len_utf8();
                    if let Some(rel_end) = attrs[val_start..].find(quote) {
                        let val = attrs[val_start..val_start + rel_end].trim();
                        return if val.is_empty() { None } else { Some(val.to_string()) };
                    }
                }
            }
        }
        from = after;
    }
}

/// 属性抽整数 (缺 / 非法 → 0)。`pub(crate)`: 位置等同类抽取件复用。
pub(crate) fn attr_i64(attrs: &str, attr: &str) -> i64 {
    extract_attr(attrs, attr).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// 从消息 text_content (媒体 XML) 抽媒体字段。非媒体 msg_type (3图/34语音/43视频/47表情) → None; 有类型但
/// md5 与 cdn_url 都缺 (损坏/占位) → None。**infallible**。
#[must_use]
pub fn parse_media(msg_type: i32, content: &str) -> Option<MediaCard> {
    let media_kind = MediaKind::from_msg_type(msg_type)?;
    // (tag, 主url attr, 尺寸 attr, md5 attr) — 语音的属性名跟图/视频不同 (voicemsg/voiceurl/voicemd5)。
    let (tag, url_attr, size_attr, md5_attr) = match media_kind {
        MediaKind::Image => ("img", "cdnmidimgurl", "length", "md5"),
        MediaKind::Video => ("videomsg", "cdnvideourl", "length", "md5"),
        MediaKind::Emoji => ("emoji", "cdnurl", "len", "md5"),
        MediaKind::Voice => ("voicemsg", "voiceurl", "length", "voicemd5"),
    };
    let attrs = open_tag_body(content, tag)?;

    // 主 cdn_url 优先取媒体主图 (中图/大图/视频/语音); 图无中图则退大图。
    let cdn_url = extract_attr(attrs, url_attr).or_else(|| {
        if media_kind == MediaKind::Image {
            extract_attr(attrs, "cdnbigimgurl")
        } else {
            None
        }
    });
    let extra_id = match media_kind {
        MediaKind::Video => extract_attr(attrs, "newmd5"),
        MediaKind::Emoji => extract_attr(attrs, "productid"),
        MediaKind::Image => extract_attr(attrs, "hdmd5"),
        MediaKind::Voice => extract_attr(attrs, "voiceformat"), // 编码 (4=SILK)
    };
    let card = MediaCard {
        media_kind,
        md5: extract_attr(attrs, md5_attr),
        aes_key: extract_attr(attrs, "aeskey"),
        cdn_url,
        thumb_url: extract_attr(attrs, "cdnthumburl"),
        file_size: attr_i64(attrs, size_attr),
        // play_length: 视频=秒 (playlength) / 语音=毫秒 (voicelength, 随 media_kind 语义) / 其它 0。
        play_length: match media_kind {
            MediaKind::Video => attr_i64(attrs, "playlength"),
            MediaKind::Voice => attr_i64(attrs, "voicelength"),
            _ => 0,
        },
        extra_id,
    };
    // 无 md5 且无 cdn_url = 无可用媒体引用 → 不落 (损坏/占位消息)。
    // **⚠️ 例外: 语音只要有时长就有价值** — 真库实测 voicelength 100% 覆盖但 voiceurl 仅 95% / voicemd5 仅 5%,
    // ~4% 语音无 url 无 md5 只有时长; 若按图/视频口径丢弃就**丢了这些语音条**(时长本身是有用内容, 别丢)。
    let voice_with_duration = card.media_kind == MediaKind::Voice && card.play_length > 0;
    if card.md5.is_none() && card.cdn_url.is_none() && !voice_with_duration {
        return None;
    }
    Some(card)
}

/// K-R4: md5/aes_key/cdn_url/thumb_url/extra_id 是媒体资源引用 (aes_key 是解密密钥) → sha8 脱敏;
/// media_kind/file_size/play_length 明文。
impl fmt::Debug for MediaCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("MediaCard")
            .field("media_kind", &self.media_kind)
            .field("md5_sha8", &o(&self.md5))
            .field("aes_key_sha8", &o(&self.aes_key))
            .field("cdn_url_sha8", &o(&self.cdn_url))
            .field("thumb_url_sha8", &o(&self.thumb_url))
            .field("file_size", &self.file_size)
            .field("play_length", &self.play_length)
            .field("extra_id_sha8", &o(&self.extra_id))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMG: &str = r#"<?xml version="1.0"?><msg><img aeskey="4f1b9f0264f40a3d2596521cf30997d1" encryver="1" cdnthumbaeskey="4f1b9f0264f40a3d2596521cf30997d1" cdnthumburl="3057020100thumb" cdnthumblength="730787" cdnmidimgurl="3057020100mid" length="730787" md5="8bbfc6c281f8aaaaaaaaaaaaaaaaaaaa" hdmd5="ffff0000ffff0000ffff0000ffff0000" /></msg>"#;

    const VIDEO: &str = r#"<?xml version="1.0"?><msg><videomsg aeskey="d1c637737484578e1806134d3233e2f2" cdnvideourl="3057020100vid" cdnthumburl="3057020100thumb" length="936153" playlength="5" cdnthumbmd5="cccccccccccccccccccccccccccccccc" md5="abe2d4b7c2648a9deaf2c177503d759c" newmd5="dddddddddddddddddddddddddddddddd" /></msg>"#;

    const EMOJI: &str = r#"<msg><emoji fromusername="a" tousername="b@chatroom" type="2" md5="13f91eb9c2068544ee81a1a88a8b5e79" len="817940" productid="com.tencent.xin.emoticon.person" cdnurl="http://wxapp.tc.qq.com/x?m=13f91&amp;hy=SZ" /></msg>"#;

    const VOICE: &str = r#"<msg><voicemsg endflag="1" cancelflag="0" voiceformat="4" voicelength="3000" length="6730" bufid="0" aeskey="62697871636968706b6663717a796277" voiceurl="3052020100vurl" voicemd5="4e9ecb5cf4fb25641451bbaaaaaaaaaa" /></msg>"#;

    #[test]
    fn parse_image() {
        let m = parse_media(3, IMG).unwrap();
        assert_eq!(m.media_kind, MediaKind::Image);
        assert_eq!(
            m.md5.as_deref(),
            Some("8bbfc6c281f8aaaaaaaaaaaaaaaaaaaa"),
            "md5 词边界不误配 cdnthumbmd5/hdmd5"
        );
        assert_eq!(m.aes_key.as_deref(), Some("4f1b9f0264f40a3d2596521cf30997d1"));
        assert_eq!(m.cdn_url.as_deref(), Some("3057020100mid"), "图主图 cdnmidimgurl");
        assert_eq!(m.thumb_url.as_deref(), Some("3057020100thumb"));
        assert_eq!(m.file_size, 730_787);
        assert_eq!(m.play_length, 0, "图无时长");
        assert_eq!(
            m.extra_id.as_deref(),
            Some("ffff0000ffff0000ffff0000ffff0000"),
            "图 extra=hdmd5"
        );
    }

    #[test]
    fn parse_video() {
        let m = parse_media(43, VIDEO).unwrap();
        assert_eq!(m.media_kind, MediaKind::Video);
        assert_eq!(
            m.md5.as_deref(),
            Some("abe2d4b7c2648a9deaf2c177503d759c"),
            "md5 不误配 cdnthumbmd5/newmd5"
        );
        assert_eq!(m.cdn_url.as_deref(), Some("3057020100vid"), "视频 cdnvideourl");
        assert_eq!(m.file_size, 936_153);
        assert_eq!(m.play_length, 5, "视频时长 5 秒");
        assert_eq!(
            m.extra_id.as_deref(),
            Some("dddddddddddddddddddddddddddddddd"),
            "视频 extra=newmd5"
        );
    }

    #[test]
    fn parse_voice() {
        // 语音 (ADR-462): voicemsg 属性名跟图/视频不同 (voicemd5/voiceurl/voicelength/voiceformat)。
        let m = parse_media(34, VOICE).unwrap();
        assert_eq!(m.media_kind, MediaKind::Voice);
        assert_eq!(
            m.md5.as_deref(),
            Some("4e9ecb5cf4fb25641451bbaaaaaaaaaa"),
            "md5=voicemd5"
        );
        assert_eq!(m.aes_key.as_deref(), Some("62697871636968706b6663717a796277"));
        assert_eq!(m.cdn_url.as_deref(), Some("3052020100vurl"), "cdn=voiceurl");
        assert_eq!(m.file_size, 6730, "字节数=length");
        assert_eq!(m.play_length, 3000, "语音时长=voicelength 毫秒");
        assert_eq!(m.extra_id.as_deref(), Some("4"), "extra=voiceformat (4=SILK)");
        assert!(m.thumb_url.is_none(), "语音无 cdnthumburl");
    }

    #[test]
    fn voice_with_only_duration_kept() {
        // ⚠️ 别丢内容: 语音只有时长 (无 voiceurl/voicemd5) 仍要落 — 时长本身有用 (真库 ~4% 语音如此)。
        let x = parse_media(
            34,
            r#"<msg><voicemsg voicelength="5000" length="9000" voiceformat="4" /></msg>"#,
        )
        .unwrap();
        assert_eq!(x.media_kind, MediaKind::Voice);
        assert!(x.md5.is_none() && x.cdn_url.is_none(), "无 md5 无 url");
        assert_eq!(x.play_length, 5000, "但有时长 → 保留 (不丢)");
    }

    #[test]
    fn voice_no_duration_no_ref_dropped() {
        // 语音连时长都没有 (真损坏/占位) → 丢 (跟图/视频口径一致, 不是有用内容)。
        assert!(parse_media(34, r#"<msg><voicemsg voiceformat="4" /></msg>"#).is_none());
    }

    #[test]
    fn parse_emoji() {
        let m = parse_media(47, EMOJI).unwrap();
        assert_eq!(m.media_kind, MediaKind::Emoji);
        assert_eq!(m.md5.as_deref(), Some("13f91eb9c2068544ee81a1a88a8b5e79"));
        assert_eq!(
            m.cdn_url.as_deref(),
            Some("http://wxapp.tc.qq.com/x?m=13f91&amp;hy=SZ"),
            "cdnurl 含 &amp; 原样存"
        );
        assert_eq!(m.file_size, 817_940, "表情 len");
        assert_eq!(
            m.extra_id.as_deref(),
            Some("com.tencent.xin.emoticon.person"),
            "表情 extra=productid"
        );
        assert!(m.thumb_url.is_none(), "表情无 cdnthumburl");
    }

    #[test]
    fn non_media_returns_none() {
        assert!(parse_media(1, "普通文本").is_none(), "文本 type 1 → None");
        assert!(
            parse_media(49, IMG).is_none(),
            "appmsg type 49 → None (即便正文含 <img>)"
        );
        assert!(parse_media(3, "<msg></msg>").is_none(), "type 3 但无 <img> → None");
    }

    #[test]
    fn no_md5_no_cdn_returns_none() {
        // 有 <img> 但 md5/cdn_url 都缺 (只剩尺寸) → 无可用引用, 不落。
        assert!(parse_media(3, r#"<msg><img length="100" /></msg>"#).is_none());
    }

    #[test]
    fn md5_word_boundary() {
        // 只有 cdnthumbmd5 (无独立 md5) → md5 None, 但 cdnthumburl 缺 → 靠 cdn_url 判 (这里都缺 → None)。
        let x = parse_media(
            3,
            r#"<msg><img cdnthumbmd5="cccccccccccccccccccccccccccccccc" cdnmidimgurl="u" /></msg>"#,
        )
        .unwrap();
        assert!(x.md5.is_none(), "md5 词边界: cdnthumbmd5 不当 md5");
        assert_eq!(x.cdn_url.as_deref(), Some("u"), "靠 cdn_url 落库");
    }

    /// codex 批D P2: 属性值内含裸 `>` 时 open_tag_body 不提前截断 (引号感知)。
    #[test]
    fn attr_value_with_gt_not_truncated() {
        // md5 在含 '>' 的 url 之后 — 引号感知扫描应完整拿到 md5。
        let xml = r#"<msg><img cdnmidimgurl="http://a/x?p=1>2" md5="8bbfc6c281f8aaaaaaaaaaaaaaaaaaaa" /></msg>"#;
        let m = parse_media(3, xml).unwrap();
        assert_eq!(m.cdn_url.as_deref(), Some("http://a/x?p=1>2"), "url 含 '>' 完整");
        assert_eq!(
            m.md5.as_deref(),
            Some("8bbfc6c281f8aaaaaaaaaaaaaaaaaaaa"),
            "'>' 后的 md5 不丢"
        );
    }

    #[test]
    fn k_r4_debug_redacts() {
        let dbg = format!("{:?}", parse_media(47, EMOJI).unwrap());
        for raw in [
            "13f91eb9c2068544ee81a1a88a8b5e79",
            "com.tencent.xin.emoticon.person",
            "wxapp.tc.qq.com",
        ] {
            assert!(!dbg.contains(raw), "K-R4: MediaCard Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("md5_sha8"));
        assert!(dbg.contains("media_kind: Emoji"), "media_kind 明文");
    }
}
