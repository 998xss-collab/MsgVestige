//! decoder::forward — 从合并转发消息 (msg_type=49, appmsg type=19) 抽逐条子项 (照 chatlog RecordInfo/DataList)。
//!
//! 真库实测 (2026-07-06 message_0): 合并转发 content 的 `<recorditem>` 是 **HTML 实体编码** (`&lt;recordinfo&gt;`
//! 非 CDATA, 微信版本差异) → 先 [`decode_xml_entities`] 解实体, 再迭代 `<datalist>` 内 `<dataitem>`。
//! 每子项 (照 chatlog DataItem): datatype(attr) / sourcename(发送人) / sourcetime / datadesc(内容) / datatitle /
//! fullmd5(子媒体) / datasize。**一转发多子项 → 多行** (照 message_mention)。**纯字符串抽, infallible**。
//!
//! ## 套娃合并转发 (nested recordxml)
//! dataitem 可嵌 `<recordxml>` 再套 dataitem。[`dataitem_blocks`] **深度感知** 只取顶层 dataitem (嵌套的算在块内,
//! extract_tag 取顶层字段) → 不误把嵌套子项当顶层。极深/畸形有 200 项安全上限 (ADR-476 KI)。
//!
//! ## K-R4
//! sourcename (转发消息发送人) / datadesc (转发内容) / datatitle → 敏感 (含他人名/内容) → 明文落库 (ADR-427) +
//! [`ForwardItem`] Debug 脱敏 (name/title sha8 + desc 只露长度 + md5 sha8)。

use std::fmt;

use super::appmsg::{extract_tag, strip_blocks};
use super::favorite::decode_xml_entities;
use super::media::{extract_attr, open_tag_body};
use crate::key_provider::sha8;

/// 合并转发主类型 (msg_type=49 appmsg, 子类 type=19; 由 `<recorditem>` 存在判定)。
const MSG_TYPE_APP: i32 = 49;
/// 单条转发子项上限 (防畸形/超深套娃; ADR-476 KI-A)。
const MAX_ITEMS: usize = 200;

/// 合并转发里的一个子项 (照 chatlog DataItem)。
#[derive(Clone, PartialEq, Eq)]
pub struct ForwardItem {
    /// datalist 内 0 基序号 (PK 组成, 一转发多子项 → 多行)。
    pub seq: i64,
    /// 子项类型 (`datatype` attr: 1 文本 / 2 图片 / …)。
    pub data_type: String,
    /// 原发送人名 (`sourcename`; 可空)。
    pub source_name: Option<String>,
    /// 原发送时间串 (`sourcetime`, 如 "2025-7-10 09:49"; 可空)。
    pub source_time: Option<String>,
    /// 子项标题 (`datatitle`, 媒体/链接类有; 可空)。
    pub data_title: Option<String>,
    /// 子项内容/描述 (`datadesc`, 文本正文; 可空)。
    pub data_desc: Option<String>,
    /// 子媒体内容 md5 (`fullmd5`, 图/视频子项有; 可空)。
    pub media_md5: Option<String>,
    /// 子媒体字节数 (`datasize`; 未知 0)。
    pub data_size: i64,
}

/// 深度感知迭代 `<dataitem>…</dataitem>` **顶层块** (套娃嵌套的算块内不单列)。畸形无闭合 → 停。
fn dataitem_blocks(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = s[i..].find("<dataitem") {
        let start = i + rel;
        let mut depth = 0i32;
        let mut j = start;
        let block_end = loop {
            let next_open = s[j..].find("<dataitem").map(|x| j + x);
            let next_close = s[j..].find("</dataitem>").map(|x| j + x);
            match (next_open, next_close) {
                // 下一个开标签在闭标签前 → 嵌套, depth++。
                (Some(open_pos), close_pos) if close_pos.is_none_or(|c| open_pos < c) => {
                    depth += 1;
                    j = open_pos + "<dataitem".len();
                }
                // 闭标签 → depth--; 归 0 = 顶层块结束。
                (_, Some(close_pos)) => {
                    depth -= 1;
                    j = close_pos + "</dataitem>".len();
                    if depth == 0 {
                        break j;
                    }
                }
                // 无闭标签 = 畸形, 块到串尾。
                _ => break s.len(),
            }
        };
        out.push(&s[start..block_end]);
        i = block_end;
        if out.len() >= MAX_ITEMS {
            break;
        }
    }
    out
}

/// 从合并转发消息 content 抽逐条子项。非 appmsg(49) / 无 `<recorditem>` / 无 dataitem → 空 Vec。**infallible**。
#[must_use]
pub fn parse_forward(msg_type: i32, content: &str) -> Vec<ForwardItem> {
    if msg_type != MSG_TYPE_APP {
        return Vec::new();
    }
    // recorditem 是实体编码的 recordinfo XML (非 CDATA); 先解实体。无 recorditem = 非合并转发。
    let Some(rec_raw) = extract_tag(content, "recorditem") else {
        return Vec::new();
    };
    let recordinfo = decode_xml_entities(&rec_raw);
    // 文本字段值自身**双重编码** (recorditem 解一次得结构后, datadesc/sourcename 值里还带一层实体如 &apos;)
    // → 抽出后再解一次 (真库实测 "苹果饭&apos;场")。md5/size/datatype 非文本不必。
    let text = |block: &str, tag: &str| extract_tag(block, tag).map(|s| decode_xml_entities(&s));
    dataitem_blocks(&recordinfo)
        .into_iter()
        .enumerate()
        .map(|(seq, block)| {
            // datatype 在 <dataitem …> 开标签属性里 (在 recordxml 前, 用原 block 取)。
            let data_type = open_tag_body(block, "dataitem")
                .and_then(|attrs| extract_attr(attrs, "datatype"))
                .unwrap_or_default();
            // ⭐ADR-476 F1 (双审): 顶层字段**只从剥掉套娃 <recordxml> 的外壳抽** —— 防顶层项缺某字段时
            // extract_tag 首匹配误取内层子项的值 (字段串味, 真库不触发但封死; 同 appmsg strip_blocks)。
            let shell = strip_blocks(block, &["recordxml"]);
            ForwardItem {
                seq: i64::try_from(seq).unwrap_or(i64::MAX),
                data_type,
                source_name: text(&shell, "sourcename"),
                source_time: text(&shell, "sourcetime"),
                data_title: text(&shell, "datatitle"),
                data_desc: text(&shell, "datadesc"),
                media_md5: extract_tag(&shell, "fullmd5"),
                data_size: extract_tag(&shell, "datasize")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
            }
        })
        .collect()
}

/// K-R4: 转发子项含他人名/内容 → Debug 脱敏 (name/title sha8 + desc 只露长度 + md5 sha8)。
impl fmt::Debug for ForwardItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("ForwardItem")
            .field("seq", &self.seq)
            .field("data_type", &self.data_type)
            .field("source_name_sha8", &o(&self.source_name))
            .field("source_time", &self.source_time)
            .field("data_title_sha8", &o(&self.data_title))
            .field("data_desc_len", &self.data_desc.as_deref().map(|s| s.chars().count()))
            .field("media_md5_sha8", &o(&self.media_md5))
            .field("data_size", &self.data_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 真库样本 (2026-07-06 message_0): recorditem 实体编码, 2 子项 (文本)。
    const FWD: &str = r#"<msg><appmsg><title>群聊的聊天记录</title><type>19</type><recorditem>&lt;recordinfo&gt;&lt;info&gt;安小米: 绘本团&lt;/info&gt;&lt;isChatRoom&gt;1&lt;/isChatRoom&gt;&lt;datalist count="2"&gt;&lt;dataitem htmlid="a" datatype="1" dataid="a"&gt;&lt;sourcetime&gt;2025-7-10 09:49&lt;/sourcetime&gt;&lt;datadesc&gt;乐乐趣小虫虫绘本&lt;/datadesc&gt;&lt;sourcename&gt;安小米&lt;/sourcename&gt;&lt;/dataitem&gt;&lt;dataitem htmlid="b" datatype="2" dataid="b"&gt;&lt;sourcetime&gt;2025-7-10 09:50&lt;/sourcetime&gt;&lt;datatitle&gt;图片&lt;/datatitle&gt;&lt;fullmd5&gt;abc123def456&lt;/fullmd5&gt;&lt;datasize&gt;20480&lt;/datasize&gt;&lt;sourcename&gt;小红&lt;/sourcename&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;</recorditem></appmsg></msg>"#;

    #[test]
    fn parse_two_items() {
        let items = parse_forward(49, FWD);
        assert_eq!(items.len(), 2, "2 子项");
        assert_eq!(items[0].seq, 0);
        assert_eq!(items[0].data_type, "1", "文本");
        assert_eq!(items[0].source_name.as_deref(), Some("安小米"));
        assert_eq!(items[0].source_time.as_deref(), Some("2025-7-10 09:49"));
        assert_eq!(items[0].data_desc.as_deref(), Some("乐乐趣小虫虫绘本"));
        assert_eq!(items[1].seq, 1);
        assert_eq!(items[1].data_type, "2", "图片");
        assert_eq!(items[1].data_title.as_deref(), Some("图片"));
        assert_eq!(items[1].media_md5.as_deref(), Some("abc123def456"));
        assert_eq!(items[1].data_size, 20480);
        assert_eq!(items[1].source_name.as_deref(), Some("小红"));
    }

    #[test]
    fn double_encoded_text_decoded() {
        // 真库实测: 文本值双重编码 (&amp;apos; 解一次成 &apos;, 需再解一次成 ')。
        let x = r#"<msg><appmsg><type>19</type><recorditem>&lt;recordinfo&gt;&lt;datalist count="1"&gt;&lt;dataitem datatype="1"&gt;&lt;sourcename&gt;老王&lt;/sourcename&gt;&lt;datadesc&gt;苹果饭&amp;apos;场&amp;amp;店&lt;/datadesc&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;</recorditem></appmsg></msg>"#;
        let items = parse_forward(49, x);
        assert_eq!(
            items[0].data_desc.as_deref(),
            Some("苹果饭'场&店"),
            "文本字段二次解实体"
        );
    }

    #[test]
    fn non_forward_empty() {
        assert!(parse_forward(1, FWD).is_empty(), "非 appmsg → 空");
        assert!(
            parse_forward(49, "<msg><appmsg><type>1</type></appmsg></msg>").is_empty(),
            "无 recorditem → 空"
        );
    }

    #[test]
    fn nested_forward_top_level_only() {
        // 套娃: 顶层 1 项内嵌一个 recordxml 里的 dataitem → 深度感知只算 1 顶层项。
        let nested = r#"<msg><appmsg><type>19</type><recorditem>&lt;recordinfo&gt;&lt;datalist count="1"&gt;&lt;dataitem datatype="19"&gt;&lt;sourcename&gt;老王&lt;/sourcename&gt;&lt;datatitle&gt;转发的聊天记录&lt;/datatitle&gt;&lt;recordxml&gt;&lt;recordinfo&gt;&lt;datalist&gt;&lt;dataitem datatype="1"&gt;&lt;sourcename&gt;内层人&lt;/sourcename&gt;&lt;datadesc&gt;内层消息&lt;/datadesc&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;&lt;/recordxml&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;</recorditem></appmsg></msg>"#;
        let items = parse_forward(49, nested);
        assert_eq!(items.len(), 1, "深度感知: 套娃只算 1 顶层项 (不把内层当第2项)");
        assert_eq!(items[0].source_name.as_deref(), Some("老王"), "取顶层发送人");
        assert_eq!(items[0].data_type, "19", "顶层是套娃转发");
    }

    #[test]
    fn nested_no_field_bleed() {
        // ADR-476 F1: 顶层项**自身缺** datadesc, 内层子项**有** —— 剥 recordxml 后顶层 data_desc 应为 None (不串味取内层)。
        let x = r#"<msg><appmsg><type>19</type><recorditem>&lt;recordinfo&gt;&lt;datalist count="1"&gt;&lt;dataitem datatype="19"&gt;&lt;sourcename&gt;老王&lt;/sourcename&gt;&lt;recordxml&gt;&lt;recordinfo&gt;&lt;datalist&gt;&lt;dataitem datatype="1"&gt;&lt;sourcename&gt;内层人&lt;/sourcename&gt;&lt;datadesc&gt;内层消息不该冒充顶层&lt;/datadesc&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;&lt;/recordxml&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;</recorditem></appmsg></msg>"#;
        let items = parse_forward(49, x);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].source_name.as_deref(),
            Some("老王"),
            "顶层自有 sourcename 正常取"
        );
        assert_eq!(
            items[0].data_desc, None,
            "顶层无 datadesc → None (不串味取内层 '内层消息')"
        );
    }

    #[test]
    fn k_r4_debug_redacts() {
        let dbg = format!("{:?}", parse_forward(49, FWD)[0]);
        for raw in ["安小米", "乐乐趣小虫虫绘本"] {
            assert!(!dbg.contains(raw), "K-R4: ForwardItem Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("source_name_sha8") && dbg.contains("data_desc_len"));
    }
}
