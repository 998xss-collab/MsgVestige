//! decoder::sns — sns.db `SnsTimeLine` 一行 (content XML) → [`SnsCreate`] 事件 (朋友圈动态本体)。ADR-467 件1。
//!
//! [`assemble_sns`] 把一条 `SnsTimeLine` 行 (tid/user_name/content) 映射成 [`SnsCreate`]。**纯字符串抽命名标签 +
//! 属性, infallible** (照 [`super::appmsg`] 先例; SNS content XML 自描述, 无需用户验字段义)。动态本体总存在
//! (一行一条) → 解析失败字段退默认 (create_time=0 / moment_type=0 / 正文空), 不丢整条。
//!
//! ## content XML 结构 (真库坐实 2026-07-05)
//! 根 `<SnsDataItem>` → `<TimelineObject>` (动态本体) + `<LocalExtraInfo>` (缓存昵称 + 点赞/评论)。
//! - TimelineObject: `<createTime>` 秒 / `<contentDesc>` 正文 / `<sourceUserName>` 转发来源 /
//!   `<location latitude= longitude= poiName= />` (**属性非子标签**) / `<ContentObject>`{`<type>` 动态类型 /
//!   `<title>` / `<contentUrl>` / `<mediaList><media>…`}。
//! - LocalExtraInfo: `<nickname>` 发布者昵称 (在 like_user_list 前) / `<like_user_list><user_comment>{`<type>`
//!   1=赞 2=评论}…`。
//!
//! ## K-R4
//! - `SnsRow` 持 user_name (wxid) + content (含 PII 的 XML) → **不 derive Debug** (同 FavoriteRow)。
//! - 脱敏在 [`SnsCreate`] 出口 (手写 Debug) + projection (sha)。本层只搬运/抽取。

use crate::event::provenance::Provenance;
use crate::event::sns::SnsCreate;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `SnsTimeLine` 行 (调用方从 cipher / 明文 sns.db SELECT)。
///
/// schema 仅 4 列 (tid/user_name/content/pack_info_buf); 件1 消费 tid/user_name/content (pack_info_buf 留后)。
pub struct SnsRow {
    /// 动态 id (SnsTimeLine.tid = `INTEGER PRIMARY KEY DESC` = rowid 别名; 雪花 id 可为负; = 取数游标键 + 锚点)。
    pub tid: i64,
    /// 发布者 wxid (SnsTimeLine.user_name; id 类; 真库实测 == TimelineObject/username)。
    pub user_name: String,
    /// 动态本体 XML (`<SnsDataItem>…`; 一切结构化字段从此抽)。
    pub content: String,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct SnsContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"sns.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"Sns_<tid>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 从 content XML 抽出的结构化字段 (件1 动态本体; 内部中转, 不出 crate)。
struct ParsedSns {
    create_time: i64,
    moment_type: i64,
    content_desc: String,
    author_nickname: Option<String>,
    source_user: Option<String>,
    location_label: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    title: Option<String>,
    link_url: Option<String>,
    media_count: i64,
    like_count: i64,
    comment_count: i64,
    // 补列 (ADR-491; content XML 边角字段, 真库核有数据; L2-only 不进 digest)。
    source_nickname: Option<String>,
    is_bidirectional_fan: i64,
    is_rich_text: i64,
    public_user_name: Option<String>,
    app_name: Option<String>,
}

/// 组装一条 [`SnsRow`] + [`SnsContext`] → [`SnsCreate`] (event_seq 留 0, 后置填)。**infallible**。
#[must_use]
pub fn assemble_sns(row: &SnsRow, ctx: &SnsContext) -> SnsCreate {
    let p = parse_sns_content(&row.content);
    SnsCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::SnsEvent,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        tid: row.tid,
        author: row.user_name.clone(),
        create_time: p.create_time,
        moment_type: p.moment_type,
        content_desc: p.content_desc,
        author_nickname: p.author_nickname,
        source_user: p.source_user,
        location_label: p.location_label,
        latitude: p.latitude,
        longitude: p.longitude,
        title: p.title,
        link_url: p.link_url,
        media_count: p.media_count,
        like_count: p.like_count,
        comment_count: p.comment_count,
        // 补列 (ADR-491): content XML 边角字段 (L2-only 不进 digest)。
        source_nickname: p.source_nickname,
        is_bidirectional_fan: p.is_bidirectional_fan,
        is_rich_text: p.is_rich_text,
        public_user_name: p.public_user_name,
        app_name: p.app_name,
        // content 本身不落 → 只记原 XML 字节长度 (UTF-8; 同 favorite content_len 尺寸先例)。
        content_len: i64::try_from(row.content.len()).unwrap_or(i64::MAX),
        // 件2a: 原 XML 载体 (供 project_moment_media 再解析逐条媒体; 不落 moment 表/digest/payload)。
        raw_content: row.content.clone(),
    }
}

/// **轻量** 只取动态发布时刻 `createTime` (秒), 不解正文/媒体/赞评 —— 供热查排序用(全扫时对每行只需
/// create_time 定序, 完整 [`assemble_sns`] 只对最终整页做, 省掉非本页行的 count_interactions/媒体解析开销)。
///
/// **与 [`parse_sns_content`] 的 `create_time` 走完全相同的代码路径**(同 `first_block("TimelineObject")` 作用域 +
/// 同 `tag_text("createTime")`)→ 排序键与完整解析出的 create_time 逐位一致, 不引入排序分叉。infallible, 缺 → 0。
#[must_use]
pub fn parse_sns_create_time(xml: &str) -> i64 {
    let to = first_block(xml, "TimelineObject").unwrap_or(xml);
    tag_text(to, "createTime").and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// 解 content XML 为结构化字段 (纯字符串扫描, infallible; 缺字段退默认)。
fn parse_sns_content(xml: &str) -> ParsedSns {
    // TimelineObject 作用域 (动态本体; LocalExtraInfo 的 create_time/nickname 不在此干扰)。缺则退整串。
    let to = first_block(xml, "TimelineObject").unwrap_or(xml);

    let create_time = tag_text(to, "createTime").and_then(|s| s.parse().ok()).unwrap_or(0);
    let content_desc = tag_text(to, "contentDesc").unwrap_or_default();
    let source_user = tag_text(to, "sourceUserName"); // 空 → None (tag_text 空串返 None)

    // location 是自闭合属性标签 `<location latitude= longitude= poiName= />` — 抽属性非子标签。
    let (location_label, latitude, longitude) = parse_location_attrs(to);

    // ContentObject: type (剥 mediaList 避开媒体 <type>) / title / contentUrl / media 计数。
    let (moment_type, title, link_url, media_count) = parse_content_object(to);

    // LocalExtraInfo: 发布者 nickname (剥 like_user_list + comment_user_list 避开点赞人/评论人 nickname) + 计数。
    // 发布者 nickname 在两个 wrapper 之前, 但剥掉两者最稳 (真库两 wrapper 内 user_comment 各有 nickname)。
    let lei = first_block(xml, "LocalExtraInfo").unwrap_or("");
    let lei_head = strip_block(&strip_block(lei, "like_user_list"), "comment_user_list");
    let author_nickname = tag_text(&lei_head, "nickname");
    let (like_count, comment_count) = count_interactions(lei);

    // 补列 (ADR-491): 从整串抽 (这几个标签不在 TimelineObject 内 / 唯一出现)。真库核: is_bidirectional_fan
    // 12070/12070(互关11550/单向520) · is_rich_text(富文本2698) · sourceNickName 442 · publicUserName 343 · appName 360。
    let source_nickname = tag_text(xml, "sourceNickName");
    let is_bidirectional_fan = tag_text(xml, "is_bidirectional_fan")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let is_rich_text = tag_text(xml, "is_rich_text").and_then(|s| s.parse().ok()).unwrap_or(0);
    let public_user_name = tag_text(xml, "publicUserName");
    let app_name = tag_text(xml, "appName");

    ParsedSns {
        create_time,
        moment_type,
        content_desc,
        author_nickname,
        source_user,
        location_label,
        latitude,
        longitude,
        title,
        link_url,
        media_count,
        like_count,
        comment_count,
        source_nickname,
        is_bidirectional_fan,
        is_rich_text,
        public_user_name,
        app_name,
    }
}

/// ContentObject 内: (moment_type, title, link_url, media_count)。type 从剥掉 mediaList 的头部取
/// (避开 `<media><type>` 干扰); media_count 从 mediaList 块数 `<media>`。
fn parse_content_object(to: &str) -> (i64, Option<String>, Option<String>, i64) {
    let Some(co) = first_block(to, "ContentObject") else {
        return (0, None, None, 0);
    };
    // media 计数 (mediaList 块; 空 `<mediaList/>` → None → 0)。
    let media_count = first_block(co, "mediaList").map_or(0, |ml| count_occ(ml, "<media>"));
    // 剥 mediaList 后取动态本体 type/title/contentUrl (媒体也有 <type>/<title>)。
    let head = strip_block(co, "mediaList");
    let moment_type = tag_text(&head, "type").and_then(|s| s.parse().ok()).unwrap_or(0);
    let title = tag_text(&head, "title");
    let link_url = tag_text(&head, "contentUrl");
    (moment_type, title, link_url, media_count)
}

/// 点赞/评论计数。**真库坐实 (WeLive 解密加密原库)**: 赞在 `<like_user_list>`、评论在**独立的**
/// `<comment_user_list>` (两个分开的 wrapper, 不是同一个 —— 早期只 inspect 到带赞的行、误以为都在 like_user_list,
/// 导致评论全 0 的 bug)。直接在整个 LocalExtraInfo 内按 user_comment 的 `<type>` 计数 (LocalExtraInfo 内
/// `<type>` 仅出现在 user_comment: 1=赞 / 2=评论 / 其它如 type4 忽略), 一网打尽两个 wrapper。
fn count_interactions(lei: &str) -> (i64, i64) {
    (count_occ(lei, "<type>1</type>"), count_occ(lei, "<type>2</type>"))
}

/// 抽 `<location …/>` 自闭合标签的属性: (poiName, latitude, longitude)。经纬度原值不换算;
/// 都为 0 → None (无位置)。poiName 空/缺 → None。
fn parse_location_attrs(to: &str) -> (Option<String>, Option<f64>, Option<f64>) {
    // 定位 `<location` 开头到本标签的 '>' (自闭合 `/>` 也在此 '>' 内)。
    let Some(start) = to.find("<location") else {
        return (None, None, None);
    };
    let rest = &to[start..];
    let end = rest.find('>').map_or(rest.len(), |e| e + 1);
    let tag = &rest[..end];

    let lat = attr(tag, "latitude").and_then(|s| s.parse::<f64>().ok());
    let lng = attr(tag, "longitude").and_then(|s| s.parse::<f64>().ok());
    // 经纬度都 0 (或缺) → 视为无位置。
    let (latitude, longitude) = match (lat, lng) {
        (Some(a), Some(b)) if a == 0.0 && b == 0.0 => (None, None),
        _ => (lat, lng),
    };
    let label = attr(tag, "poiName").filter(|s| !s.is_empty()).map(str::to_string);
    (label, latitude, longitude)
}

// ── 纯字符串扫描 helper (照 decoder::appmsg 风格; 本 mod 自包含) ──

/// 抽 `<name>…</name>` 内层 (第一处; 剥 CDATA + trim; 空 → None)。`name` 须精确匹配 (含 `>`, 防 `<contentDesc>`
/// 误配 `<contentDescShowType>`)。
fn tag_text(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    let raw = xml[s..e].trim();
    let val = raw
        .strip_prefix("<![CDATA[")
        .and_then(|x| x.strip_suffix("]]>"))
        .unwrap_or(raw)
        .trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// 抽 `<name>…</name>` 内层块 (给 ContentObject/LocalExtraInfo/mediaList/like_user_list 作用域; 无则 None)。
/// 本函数不剥 CDATA/不 trim (返内部原始块供进一步扫描)。
fn first_block<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(&xml[s..e])
}

/// 删掉 `<name>…</name>` 整块 (剥 mediaList / like_user_list 干扰)。无闭合则原样返 (畸形容错)。
fn strip_block(xml: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    if let Some(s) = xml.find(&open) {
        if let Some(e_rel) = xml[s..].find(&close) {
            let e = s + e_rel + close.len();
            let mut out = String::with_capacity(xml.len());
            out.push_str(&xml[..s]);
            out.push_str(&xml[e..]);
            return out;
        }
    }
    xml.to_string()
}

/// 抽自闭合标签的属性值 `name="…"` (第一处; 无则 None)。
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let s = tag.find(&needle)? + needle.len();
    let e = tag[s..].find('"')? + s;
    Some(&tag[s..e])
}

/// 非重叠计数子串出现次数。
fn count_occ(hay: &str, needle: &str) -> i64 {
    if needle.is_empty() {
        return 0;
    }
    let mut n = 0i64;
    let mut from = 0;
    while let Some(pos) = hay[from..].find(needle) {
        n += 1;
        from += pos + needle.len();
    }
    n
}

// ── 件2a: 逐条媒体抽取 (SNS <media> 结构 = 子标签 + 属性 + url 文本内容; 不同于 message 媒体的纯属性) ──

/// 从 content XML 抽逐条媒体 (project_moment_media 用; 一动态 N 图/视频 → N 条)。infallible; 无媒体 → 空 Vec。
///
/// SNS `<media>` 结构 (真库坐实): `<id>`/`<type>`(2图/6视频, 裸标签) + `<url type= md5= key= enc_idx= videomd5=>`
/// 全图 url 文本 + `<thumb ...>` 缩略图 url 文本 + `<size width= height= totalSize=/>` + `<videoDuration>` +
/// `<enc key=>`(视频加密 key)。url/thumb 是**带属性标签的文本内容** → 用 [`tag_text_attr`]; 属性用 media.rs 复用件。
#[must_use]
pub fn parse_sns_media(xml: &str) -> Vec<SnsMediaItem> {
    use super::media::{attr_i64, extract_attr, open_tag_body};
    let to = first_block(xml, "TimelineObject").unwrap_or(xml);
    let Some(co) = first_block(to, "ContentObject") else {
        return Vec::new();
    };
    let Some(ml) = first_block(co, "mediaList") else {
        return Vec::new(); // 空 <mediaList/> 或无 → 无媒体
    };
    let mut out = Vec::new();
    let mut seq = 0i64;
    let mut from = 0;
    // 逐个 <media>…</media> 块 (非贪婪; 无闭合停止, 畸形容错)。
    // 双审件2a P2-2: 缺 </media> 时 break (跳过残缺块及其后; 对残缺尾部保守)。真实 SNS XML well-formed 不触发;
    // 若某块缺闭合, 件1 media_count(数 <media>) 会比本函数产出多算 → 罕见畸形数据下对账余量, 取 break 保守。
    while let Some(rel) = ml[from..].find("<media>") {
        let start = from + rel + "<media>".len();
        let Some(end_rel) = ml[start..].find("</media>") else {
            break;
        };
        let media = &ml[start..start + end_rel];
        from = start + end_rel + "</media>".len();

        let url_attrs = open_tag_body(media, "url").unwrap_or("");
        let enc_attrs = open_tag_body(media, "enc").unwrap_or("");
        let size_attrs = open_tag_body(media, "size").unwrap_or("");
        out.push(SnsMediaItem {
            seq,
            media_type: tag_text(media, "type").and_then(|s| s.parse().ok()).unwrap_or(0),
            media_id: tag_text(media, "id"),
            // url/thumb 是带属性标签 <url ...>TEXT</url> → tag_text_attr 取文本; md5/key 等取 url 属性。
            url: tag_text_attr(media, "url"),
            thumb_url: tag_text_attr(media, "thumb"),
            md5: extract_attr(url_attrs, "md5"),
            video_md5: extract_attr(url_attrs, "videomd5"),
            url_key: extract_attr(url_attrs, "key"),
            enc_idx: extract_attr(url_attrs, "enc_idx"),
            token: extract_attr(url_attrs, "token"),
            enc_key: extract_attr(enc_attrs, "key"),
            width: attr_i64(size_attrs, "width"),
            height: attr_i64(size_attrs, "height"),
            total_size: attr_i64(size_attrs, "totalSize"),
            video_duration: tag_text(media, "videoDuration").and_then(|s| s.parse().ok()),
        });
        seq += 1;
    }
    out
}

/// 一条 SNS 媒体 (project_moment_media 中转; 不出 crate 落库前)。
pub struct SnsMediaItem {
    /// 在 mediaList 内的序号 (0-based; = moment_media PK 的区分位)。
    pub seq: i64,
    /// 媒体类型 (`<type>`; 2=图 / 6=视频 / 3=封面等)。
    pub media_type: i64,
    /// 媒体 id (`<id>`; 可空)。
    pub media_id: Option<String>,
    /// 全图/视频下载 url (`<url>` 文本; SNS CBC 加密, 配 url_key/enc_idx 解; 可空)。
    pub url: Option<String>,
    /// 缩略图 url (`<thumb>` 文本; 可空)。
    pub thumb_url: Option<String>,
    /// 内容 md5 (`<url md5=>`; hardlink/去重键; 可空)。
    pub md5: Option<String>,
    /// 视频源 md5 (`<url videomd5=>`; 仅视频; 可空)。
    pub video_md5: Option<String>,
    /// url 解密 key (`<url key=>`; SNS 媒体 CBC 密钥; 可空)。
    pub url_key: Option<String>,
    /// 加密索引 (`<url enc_idx=>`; 配 url_key 解密; 可空)。
    pub enc_idx: Option<String>,
    /// CDN 下载 token (`<url token=>`; 下载 url 必带 `?token=<token>&idx=<enc_idx>`; 件3 下载用; 可空)。
    pub token: Option<String>,
    /// 视频加密 key (`<enc key=>`; 仅视频; 可空)。
    pub enc_key: Option<String>,
    /// 宽 (`<size width=>`; 未知 0)。
    pub width: i64,
    /// 高 (`<size height=>`; 未知 0)。
    pub height: i64,
    /// 总字节 (`<size totalSize=>`; 未知 0)。
    pub total_size: i64,
    /// 视频时长秒 (`<videoDuration>`; 非视频 / 缺 → None)。
    pub video_duration: Option<f64>,
}

/// K-R4: url/thumb/md5/video_md5/url_key/enc_key/media_id 是媒体资源引用 (url_key/enc_key 是解密密钥) → sha8;
/// seq/type/宽高/尺寸/时长 明文。
impl std::fmt::Debug for SnsMediaItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes()));
        f.debug_struct("SnsMediaItem")
            .field("seq", &self.seq)
            .field("media_type", &self.media_type)
            .field("media_id_sha8", &o(&self.media_id))
            .field("url_sha8", &o(&self.url))
            .field("thumb_url_sha8", &o(&self.thumb_url))
            .field("md5_sha8", &o(&self.md5))
            .field("video_md5_sha8", &o(&self.video_md5))
            .field("url_key_sha8", &o(&self.url_key))
            .field("enc_idx", &self.enc_idx)
            .field("token_sha8", &o(&self.token))
            .field("enc_key_sha8", &o(&self.enc_key))
            .field("width", &self.width)
            .field("height", &self.height)
            .field("total_size", &self.total_size)
            .field("video_duration", &self.video_duration)
            .finish()
    }
}

/// 找 `<name` 开标签的 '>' 之后位置 (容忍属性; 边界防 `<nameX` 误配)。无该 tag / 无闭合 → None。
/// 扫开标签尾 '>' 时**跳过引号内的 '>'** (与姊妹件 media.rs `open_tag_body` 一致; 属性值含裸 '>' 不误截断 —
/// SNS url 属性实测无裸 '>', 但引号感知消除跨件行为分叉, 双审件2a P2-1)。
fn open_tag_end(xml: &str, name: &str) -> Option<usize> {
    let needle = format!("<{name}");
    let mut from = 0;
    loop {
        let pos = xml[from..].find(&needle)? + from;
        let after = pos + needle.len();
        match xml[after..].chars().next() {
            Some('>') => return Some(after + 1),
            // 有属性/自闭: 扫本开标签的 '>', 引号内 ('"' / '\'') 的 '>' 跳过。
            Some(c) if c.is_whitespace() || c == '/' => {
                let body = &xml[after..];
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
                            '>' => return Some(after + i + 1),
                            _ => {}
                        },
                    }
                }
                return None; // 无闭合 '>' = 畸形 tag
            }
            _ => from = after, // `<nameX` 误配 → 继续找
        }
    }
}

/// 抽**带属性**标签 `<name ...>TEXT</name>` 的文本内容 (剥 CDATA + trim; 空 → None)。给 SNS `<url>`/`<thumb>`。
fn tag_text_attr(xml: &str, name: &str) -> Option<String> {
    let start = open_tag_end(xml, name)?;
    let close = format!("</{name}>");
    let e = xml[start..].find(&close)? + start;
    let raw = xml[start..e].trim();
    let val = raw
        .strip_prefix("<![CDATA[")
        .and_then(|x| x.strip_suffix("]]>"))
        .unwrap_or(raw)
        .trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

// ── 件2b: 逐条互动抽取 (点赞 + 评论; 真库坐实两个独立 wrapper like_user_list / comment_user_list) ──

/// 从 content XML 抽逐条互动 (project_moment_interaction 用; 一动态 N 赞/评论 → N 条)。infallible; 无互动 → 空 Vec。
///
/// **真库坐实 (WeLive 解密加密原库)**: `<LocalExtraInfo>` 下 `<like_user_list>`(赞) + `<comment_user_list>`(评论)
/// 两个独立 wrapper, 各含若干 `<user_comment>`{comment_id/username/nickname/content(评论文本,赞无)/type/
/// create_time/ref_username(回复谁)/ref_comment_id}(全裸标签)。kind 由所在 wrapper 定 (like/comment)。
///
/// ⚠️ **对账口径 (双审件2b P2)**: 本函数 kind **按 wrapper** 分, 而 [`count_interactions`] (件1 计数) **按 `<type>`**
/// (type1=赞/type2=评论) 数整个 LocalExtraInfo。两者相等**依赖『type↔wrapper 一致』这一经验不变量** (真库实测
/// like_user_list 恒 type1 / comment_user_list 恒 type2, 对账双 PASS 4217/2656); 若数据违反 (type 与所在 wrapper
/// 不符), `count(kind='comment')` 会 ≠ 件1 comment_count。二者均 L2-only 不进 digest, 分叉不影响正确性/去重。
#[must_use]
pub fn parse_sns_interactions(xml: &str) -> Vec<SnsInteractionItem> {
    let lei = first_block(xml, "LocalExtraInfo").unwrap_or("");
    let mut out = Vec::new();
    let mut seq = 0i64;
    // 顺序: 先赞后评论 (seq 跨两 wrapper 连续)。
    for (wrapper, kind) in [("like_user_list", "like"), ("comment_user_list", "comment")] {
        if let Some(block) = first_block(lei, wrapper) {
            push_user_comments(block, kind, &mut seq, &mut out);
        }
    }
    out
}

/// 逐个 `<user_comment>…</user_comment>` 块抽字段 push 进 out (kind 由调用方按 wrapper 给)。
fn push_user_comments(block: &str, kind: &'static str, seq: &mut i64, out: &mut Vec<SnsInteractionItem>) {
    let mut from = 0;
    while let Some(rel) = block[from..].find("<user_comment>") {
        let start = from + rel + "<user_comment>".len();
        let Some(end_rel) = block[start..].find("</user_comment>") else {
            break; // 无闭合 = 畸形, 停止 (同 media 保守)
        };
        let uc = &block[start..start + end_rel];
        from = start + end_rel + "</user_comment>".len();
        out.push(SnsInteractionItem {
            seq: *seq,
            kind,
            // 全裸标签 (无属性) → tag_text。comment_id vs comment_64id / ref_comment_id vs ref_comment_64id
            //  精确匹配不误配 (tag_text 用 <name> 带 '>' 边界)。
            type_raw: tag_text(uc, "type").and_then(|s| s.parse().ok()).unwrap_or(0),
            from_user: tag_text(uc, "username"),
            from_nickname: tag_text(uc, "nickname"),
            content: tag_text(uc, "content"), // 评论文本; 赞无 → None
            comment_id: tag_text(uc, "comment_id"),
            ref_username: tag_text(uc, "ref_username"), // 回复谁 (comment reply); 无 → None
            ref_comment_id: tag_text(uc, "ref_comment_id"),
            create_time: tag_text(uc, "create_time").and_then(|s| s.parse().ok()).unwrap_or(0),
        });
        *seq += 1;
    }
}

/// 一条 SNS 互动 (点赞/评论; project_moment_interaction 中转)。
pub struct SnsInteractionItem {
    /// 序号 (0-based, 跨 like_user_list + comment_user_list 连续; = moment_interaction PK 区分位)。
    pub seq: i64,
    /// 类别 ("like" 来自 like_user_list / "comment" 来自 comment_user_list)。
    pub kind: &'static str,
    /// user_comment 的 `<type>` 原值 (1赞/2评论/4其它; kind 已由 wrapper 定, 此为原始值备查)。
    pub type_raw: i64,
    /// 互动者 wxid (`<username>`; id 类; 可空)。
    pub from_user: Option<String>,
    /// 互动者缓存昵称 (`<nickname>`; display 类; 可空)。
    pub from_nickname: Option<String>,
    /// 评论文本 (`<content>`; text 类; 赞 → None)。
    pub content: Option<String>,
    /// 评论 id (`<comment_id>`; 非 PII; 可空)。
    pub comment_id: Option<String>,
    /// 回复对象 wxid (`<ref_username>`; comment 回复评论时的被回复者; id 类; 可空)。
    pub ref_username: Option<String>,
    /// 被回复评论 id (`<ref_comment_id>`; 非 PII; 可空)。
    pub ref_comment_id: Option<String>,
    /// 互动时间 (`<create_time>`; unix 秒; 缺 → 0)。
    pub create_time: i64,
}

/// K-R4: from_user/from_nickname/content/ref_username 敏感 (wxid/昵称/评论文本) → sha8;
/// seq/kind/type_raw/comment_id/ref_comment_id/create_time 明文 (id 非 PII)。
impl std::fmt::Debug for SnsInteractionItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes()));
        f.debug_struct("SnsInteractionItem")
            .field("seq", &self.seq)
            .field("kind", &self.kind)
            .field("type_raw", &self.type_raw)
            .field("from_user_sha8", &o(&self.from_user))
            .field("from_nickname_sha8", &o(&self.from_nickname))
            .field("content_sha8", &o(&self.content))
            .field("comment_id", &self.comment_id)
            .field("ref_username_sha8", &o(&self.ref_username))
            .field("ref_comment_id", &self.ref_comment_id)
            .field("create_time", &self.create_time)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SnsContext {
        SnsContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "sns.db".to_string(),
            source_native_id: "Sns_-3518821952372526549".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    // 真库形态: 图文 (type 1, 单图, 有点赞), 无位置。
    const IMG: &str = r#"<SnsDataItem><TimelineObject><id>14927922121337025067</id><username>wxid_ghij3456klmn789</username><createTime>1779546990</createTime><contentDesc>麻了</contentDesc><contentDescShowType>0</contentDescShowType><sourceUserName></sourceUserName><location latitude="0" longitude="0" poiScale="0"/><ContentObject><type>1</type><contentSubStyle>0</contentSubStyle><mediaList><media><id>1</id><type>2</type><url md5="abc">http://x/0</url></media></mediaList></ContentObject></TimelineObject><LocalExtraInfo><tid>14927922121337025067</tid><nickname>小明的昵称</nickname><like_user_list><user_comment><username>wxid_liker</username><nickname>点赞人</nickname><type>1</type><create_time>1779546205</create_time></user_comment></like_user_list></LocalExtraInfo></SnsDataItem>"#;

    // 真库形态: 小视频 (type 15) + 真实位置 (poiName) + 无互动。
    const VIDEO_LOC: &str = r#"<SnsDataItem><TimelineObject><id>14927895509319094803</id><username>wxid_id3xb6lc7nh221</username><createTime>1779543818</createTime><contentDesc></contentDesc><sourceUserName></sourceUserName><location city="台州市" latitude="121.382042" longitude="28.5760899" poiName="台州市 · 路桥十里长街" country="中国"/><ContentObject><title>微信小视频</title><contentUrl>https://support.weixin.qq.com/x</contentUrl><type>15</type><contentSubStyle>0</contentSubStyle><mediaList><media><id>1</id><type>6</type></media></mediaList></ContentObject></TimelineObject><LocalExtraInfo><tid>1</tid><nickname>视频作者</nickname></LocalExtraInfo></SnsDataItem>"#;

    fn row(tid: i64, un: &str, content: &str) -> SnsRow {
        SnsRow {
            tid,
            user_name: un.to_string(),
            content: content.to_string(),
        }
    }

    #[test]
    fn parse_image_moment() {
        let p = parse_sns_content(IMG);
        assert_eq!(p.create_time, 1_779_546_990);
        assert_eq!(p.moment_type, 1, "图文 type 1 (非 media 的 type 2)");
        assert_eq!(p.content_desc, "麻了");
        assert_eq!(
            p.author_nickname.as_deref(),
            Some("小明的昵称"),
            "发布者昵称 (非点赞人昵称)"
        );
        assert_eq!(p.media_count, 1);
        assert_eq!(p.like_count, 1, "1 个 type=1 点赞");
        assert_eq!(p.comment_count, 0);
        assert_eq!(p.location_label, None, "经纬度全 0 → 无位置");
        assert_eq!(p.latitude, None);
        assert_eq!(p.source_user, None, "空 sourceUserName → None");
        assert_eq!(p.title, None, "图文无 ContentObject/title");
    }

    #[test]
    fn parse_video_with_location() {
        let p = parse_sns_content(VIDEO_LOC);
        assert_eq!(p.moment_type, 15, "小视频 type 15 (非 media 的 type 6)");
        assert_eq!(p.content_desc, "", "空 contentDesc → 空串");
        assert_eq!(
            p.location_label.as_deref(),
            Some("台州市 · 路桥十里长街"),
            "poiName 属性"
        );
        assert_eq!(p.latitude, Some(121.382_042), "latitude 属性原值");
        assert_eq!(p.longitude, Some(28.576_089_9));
        assert_eq!(p.title.as_deref(), Some("微信小视频"));
        assert_eq!(p.link_url.as_deref(), Some("https://support.weixin.qq.com/x"));
        assert_eq!(p.media_count, 1);
        assert_eq!(p.like_count, 0);
        assert_eq!(p.author_nickname.as_deref(), Some("视频作者"));
    }

    #[test]
    fn assemble_maps_row_and_parsed() {
        let sns = assemble_sns(&row(-3_518_821_952_372_526_549, "wxid_ghij3456klmn789", IMG), &ctx());
        assert_eq!(sns.tid, -3_518_821_952_372_526_549);
        assert_eq!(sns.author, "wxid_ghij3456klmn789", "author = 行 user_name");
        assert_eq!(sns.create_time, 1_779_546_990);
        assert_eq!(sns.moment_type, 1);
        assert_eq!(sns.content_desc, "麻了");
        assert_eq!(sns.like_count, 1);
        assert_eq!(
            sns.content_len,
            i64::try_from(IMG.len()).unwrap(),
            "content_len = XML 字节长度"
        );
        assert_eq!(sns.provenance.event_type, EventType::SnsEvent);
        assert_eq!(sns.provenance.event_action, EventAction::Create);
        assert_eq!(sns.provenance.event_seq, 0, "event_seq 占位 0");
        assert_eq!(sns.provenance.source_native_id, "Sns_-3518821952372526549");
    }

    #[test]
    fn empty_content_yields_defaults_not_panic() {
        // 空 / 畸形 content → 全默认, 不 panic (动态本体仍靠 row.tid/user_name 保留)。
        let sns = assemble_sns(&row(5, "wxid_x", ""), &ctx());
        assert_eq!(sns.tid, 5);
        assert_eq!(sns.author, "wxid_x");
        assert_eq!(sns.create_time, 0);
        assert_eq!(sns.moment_type, 0);
        assert_eq!(sns.content_desc, "");
        assert_eq!(sns.media_count, 0);
        assert_eq!(sns.author_nickname, None);
    }

    #[test]
    fn contentdesc_not_confused_with_showtype() {
        // <contentDesc> 精确匹配, 不误配 <contentDescShowType> (前缀撞)。
        let xml = "<TimelineObject><contentDescShowType>0</contentDescShowType><contentDesc>正文甲</contentDesc></TimelineObject>";
        assert_eq!(parse_sns_content(xml).content_desc, "正文甲");
    }

    #[test]
    fn like_and_comment_counted_separately() {
        // 真库结构 (WeLive 解密加密原库坐实): 赞在 <like_user_list>、评论在**独立的** <comment_user_list>。
        // 2 赞 (like_user_list/type1) + 1 评论 (comment_user_list/type2)。
        let xml = r"<SnsDataItem><TimelineObject><ContentObject><type>2</type><mediaList/></ContentObject></TimelineObject><LocalExtraInfo><nickname>作者</nickname><like_user_list><user_comment><nickname>赞人甲</nickname><type>1</type></user_comment><user_comment><nickname>赞人乙</nickname><type>1</type></user_comment></like_user_list><comment_user_list><user_comment><nickname>评论人</nickname><content>评论文本</content><type>2</type></user_comment></comment_user_list></LocalExtraInfo></SnsDataItem>";
        let p = parse_sns_content(xml);
        assert_eq!(p.like_count, 2, "2 个 type=1 赞 (like_user_list)");
        assert_eq!(
            p.comment_count, 1,
            "1 个 type=2 评论 (comment_user_list — 独立 wrapper, 修复前会漏)"
        );
        assert_eq!(p.moment_type, 2, "纯文字 type 2 (剥 mediaList 后取; 空 mediaList/)");
        assert_eq!(
            p.author_nickname.as_deref(),
            Some("作者"),
            "剥两 wrapper 后取发布者昵称 (非赞人/评论人)"
        );
    }

    /// 回归: 只有评论无点赞的动态 (真库形态: comment_user_list 存在但无 like_user_list) → comment_count 正确。
    /// 这正是修复前 comment 全 0 的 bug 场景 (件1 只读 like_user_list, 取不到 comment_user_list)。
    #[test]
    fn comment_only_moment_counted() {
        let xml = r"<SnsDataItem><TimelineObject><ContentObject><type>1</type><mediaList/></ContentObject></TimelineObject><LocalExtraInfo><nickname>作者</nickname><comment_user_list><user_comment><nickname>评论人甲</nickname><content>谢谢大家</content><type>2</type></user_comment><user_comment><nickname>评论人乙</nickname><content>今年</content><type>2</type></user_comment></comment_user_list></LocalExtraInfo></SnsDataItem>";
        let p = parse_sns_content(xml);
        assert_eq!(p.like_count, 0, "无 like_user_list → 0 赞");
        assert_eq!(p.comment_count, 2, "comment_user_list 内 2 评论 (修复前会是 0)");
        assert_eq!(p.author_nickname.as_deref(), Some("作者"), "发布者昵称非评论人");
    }

    #[test]
    fn count_occ_non_overlapping() {
        assert_eq!(count_occ("<media><media><media>", "<media>"), 3);
        assert_eq!(count_occ("aaaa", "aa"), 2, "非重叠");
        assert_eq!(count_occ("x", "<media>"), 0);
    }

    // ── 件2a: parse_sns_media ──

    const MEDIA2: &str = r#"<SnsDataItem><TimelineObject><ContentObject><type>1</type><mediaList><media><id>111</id><type>2</type><thumb type="1" key="K1" enc_idx="1" token="TK">http://thumb/150</thumb><url type="1" md5="MD5A" key="K1" enc_idx="1" token="TK2">http://full/0</url><size width="1920" height="2560" totalSize="491021"/><videoDuration>0</videoDuration><enc>0</enc></media><media><id>222</id><type>2</type><url type="1" md5="MD5B" key="K2" enc_idx="2">http://full2/0</url><size width="100" height="200" totalSize="333"/></media></mediaList></ContentObject></TimelineObject></SnsDataItem>"#;

    const VIDEO_MEDIA: &str = r#"<SnsDataItem><TimelineObject><ContentObject><type>15</type><mediaList><media><id>999</id><type>6</type><url type="1" md5="VMD5" key="0" enc_idx="0" videomd5="VVMD5">http://video/0</url><size width="288" height="512" totalSize="16919"/><videoDuration>6.916</videoDuration><enc key="996686273">1</enc></media></mediaList></ContentObject></TimelineObject></SnsDataItem>"#;

    #[test]
    fn parse_media_two_images() {
        let m = parse_sns_media(MEDIA2);
        assert_eq!(m.len(), 2, "2 图 → 2 条");
        assert_eq!(m[0].seq, 0);
        assert_eq!(m[0].media_type, 2, "图 type 2 (非 ContentObject 的 1)");
        assert_eq!(m[0].media_id.as_deref(), Some("111"));
        assert_eq!(m[0].url.as_deref(), Some("http://full/0"), "全图 url 文本 (带属性标签)");
        assert_eq!(m[0].thumb_url.as_deref(), Some("http://thumb/150"));
        assert_eq!(m[0].md5.as_deref(), Some("MD5A"), "url md5 属性");
        assert_eq!(m[0].url_key.as_deref(), Some("K1"), "SNS 解密 key");
        assert_eq!(m[0].enc_idx.as_deref(), Some("1"));
        assert_eq!(m[0].token.as_deref(), Some("TK2"), "CDN 下载 token (件3)");
        assert_eq!(m[0].width, 1920);
        assert_eq!(m[0].height, 2560);
        assert_eq!(m[0].total_size, 491_021);
        assert_eq!(m[0].enc_key, None, "图无 enc key (<enc>0</enc>)");
        assert_eq!(m[1].seq, 1);
        assert_eq!(m[1].media_id.as_deref(), Some("222"));
        assert_eq!(m[1].md5.as_deref(), Some("MD5B"));
        assert_eq!(m[1].thumb_url, None, "第2图无 thumb");
    }

    #[test]
    fn parse_media_video_fields() {
        let m = parse_sns_media(VIDEO_MEDIA);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].media_type, 6, "视频 type 6");
        assert_eq!(m[0].video_md5.as_deref(), Some("VVMD5"));
        assert_eq!(m[0].enc_key.as_deref(), Some("996686273"), "视频 enc key");
        assert_eq!(m[0].video_duration, Some(6.916));
        assert_eq!(m[0].url.as_deref(), Some("http://video/0"));
    }

    #[test]
    fn parse_media_empty_and_none() {
        // 空 <mediaList/> → 空 Vec。
        assert!(parse_sns_media("<SnsDataItem><TimelineObject><ContentObject><type>2</type><mediaList/></ContentObject></TimelineObject></SnsDataItem>").is_empty());
        // 无 ContentObject → 空。
        assert!(parse_sns_media("<SnsDataItem></SnsDataItem>").is_empty());
    }

    #[test]
    fn media_debug_redacts() {
        let m = parse_sns_media(VIDEO_MEDIA);
        let dbg = format!("{:?}", m[0]);
        for raw in ["VMD5", "VVMD5", "http://video/0", "996686273"] {
            assert!(!dbg.contains(raw), "K-R4: SnsMediaItem Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("md5_sha8") && dbg.contains("url_key_sha8"));
    }

    /// 双审件2a P2-1: url 开标签属性值含裸 '>' (引号内) 时 open_tag_end 引号感知不提前截断 → url 文本完整。
    #[test]
    fn media_url_attr_gt_not_truncated() {
        let xml = r#"<SnsDataItem><TimelineObject><ContentObject><type>1</type><mediaList><media><type>2</type><url md5="M>X" key="K">http://full/0</url></media></mediaList></ContentObject></TimelineObject></SnsDataItem>"#;
        let m = parse_sns_media(xml);
        assert_eq!(m.len(), 1);
        assert_eq!(
            m[0].url.as_deref(),
            Some("http://full/0"),
            "'>' 在属性值内不截断 url 文本"
        );
        assert_eq!(
            m[0].md5.as_deref(),
            Some("M>X"),
            "md5 属性含 '>' 完整 (open_tag_body 引号感知)"
        );
    }

    // ── 件2b: parse_sns_interactions ──

    // 真库形态 (WeLive 坐实): like_user_list(赞) + comment_user_list(评论) 两独立 wrapper; comment 带 content +
    //  ref_username + comment_64id/ref_comment_64id (验 tag_text 精确匹配不误配 64id 变体)。
    const INTERACTIONS: &str = r"<SnsDataItem><TimelineObject><ContentObject><type>1</type><mediaList/></ContentObject></TimelineObject><LocalExtraInfo><nickname>作者</nickname><like_user_list><user_comment><comment_id>10</comment_id><comment_64id>0</comment_64id><username>wxid_liker</username><nickname>点赞人</nickname><type>1</type><create_time>1700000001</create_time></user_comment></like_user_list><comment_user_list><user_comment><comment_id>20</comment_id><comment_64id>0</comment_64id><username>wxid_commenter</username><nickname>评论人</nickname><content>谢谢大家</content><type>2</type><create_time>1700000002</create_time><ref_username>wxid_replied</ref_username><ref_comment_id>19</ref_comment_id><ref_comment_64id>0</ref_comment_64id></user_comment></comment_user_list></LocalExtraInfo></SnsDataItem>";

    #[test]
    fn parse_interactions_like_and_comment() {
        let items = parse_sns_interactions(INTERACTIONS);
        assert_eq!(items.len(), 2, "1 赞 + 1 评论 → 2 条 (跨两 wrapper)");
        // seq 0 = 赞 (like_user_list)。
        assert_eq!(items[0].seq, 0);
        assert_eq!(items[0].kind, "like");
        assert_eq!(items[0].type_raw, 1);
        assert_eq!(items[0].from_user.as_deref(), Some("wxid_liker"));
        assert_eq!(items[0].from_nickname.as_deref(), Some("点赞人"));
        assert_eq!(items[0].content, None, "赞无评论文本");
        assert_eq!(
            items[0].comment_id.as_deref(),
            Some("10"),
            "comment_id 不误配 comment_64id"
        );
        // seq 1 = 评论 (comment_user_list)。
        assert_eq!(items[1].seq, 1);
        assert_eq!(items[1].kind, "comment");
        assert_eq!(items[1].type_raw, 2);
        assert_eq!(items[1].from_user.as_deref(), Some("wxid_commenter"));
        assert_eq!(items[1].content.as_deref(), Some("谢谢大家"), "评论文本");
        assert_eq!(items[1].comment_id.as_deref(), Some("20"));
        assert_eq!(items[1].ref_username.as_deref(), Some("wxid_replied"), "回复对象");
        assert_eq!(
            items[1].ref_comment_id.as_deref(),
            Some("19"),
            "ref_comment_id 不误配 ref_comment_64id"
        );
        assert_eq!(items[1].create_time, 1_700_000_002);
    }

    #[test]
    fn parse_interactions_none() {
        assert!(
            parse_sns_interactions(
                "<SnsDataItem><LocalExtraInfo><nickname>作者</nickname></LocalExtraInfo></SnsDataItem>"
            )
            .is_empty(),
            "无互动 wrapper → 空 Vec"
        );
    }

    #[test]
    fn interaction_debug_redacts() {
        let items = parse_sns_interactions(INTERACTIONS);
        let dbg = format!("{:?}", items[1]);
        for raw in ["wxid_commenter", "谢谢大家", "评论人", "wxid_replied"] {
            assert!(!dbg.contains(raw), "K-R4: SnsInteractionItem Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("from_user_sha8") && dbg.contains("content_sha8"));
    }
}
