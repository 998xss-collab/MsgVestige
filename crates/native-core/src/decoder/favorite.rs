//! favorite row 组装 — 明文 `fav_db_item` 行 → [`FavoriteCreate`] 事件 (收藏一条)。
//!
//! [`assemble_favorite`] 把一条 `fav_db_item` 行映射成 [`FavoriteCreate`]. **无 decode** — 收藏骨架字段
//! 都是直接列 (server_id/type/update_time/fromusr/...) → 本函数 **infallible**。event_seq 留 0 (compute 后置填)。
//! 仿 [`super::session::assemble_session`]。content 本身**不取**(大 blob, 按 type 拆是独立大件) → 只搬 content_len。
//!
//! ## 真实 schema (favorite.db `fav_db_item`, 消费列)
//! local_id (本地 PK = 游标/锚点) / server_id (服务端主键) / type (收藏类型) / update_time (收藏时间 unix 秒) /
//! fromusr (来源 wxid/@chatroom) / realchatname (群内真实发送者, 可空) / source_id (来源消息 hash id, 可空) /
//! LENGTH(content) (content 字节长度, content 本身不落)。

use crate::event::favorite::{FavoriteCreate, FavoriteMediaRef};
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `fav_db_item` 行 (调用方从 cipher / 明文 favorite.db SELECT)。
pub struct FavoriteRow {
    /// 本地 PK (fav_db_item.local_id; = 取数游标键 + 锚点; 非 PII 的本地 rowid)。
    pub local_id: i64,
    /// 服务端主键 (fav_db_item.server_id; 元数据)。
    pub server_id: i64,
    /// 收藏类型 (fav_db_item.type; 元数据)。
    pub fav_type: i64,
    /// 收藏时间 (fav_db_item.update_time; unix 秒)。
    pub update_time: i64,
    /// 来源用户 (fav_db_item.fromusr; id 类: wxid / @chatroom)。
    pub from_user: String,
    /// 群内真实发送者 (fav_db_item.realchatname; id 类, 可空 → 空串)。
    pub real_chat_name: Option<String>,
    /// 来源消息 id (fav_db_item.source_id; hash id 非 wxid, 可空)。
    pub source_id: Option<String>,
    /// content 字节长度 (SQL LENGTH(content); 元数据; content 本身不取)。
    pub content_len: i64,
    /// 笔记 (type 18) 的 content XML 原文 (drain 仅 type=18 取, 其它类型 None); assemble 解 `<datadesc>` 正文。
    pub note_content: Option<String>,
}

/// 装配上下文 — 调用方 (adapter) 按 db 预备。
pub struct FavoriteContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"favorite.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"Favorite_<local_id>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 解 XML/HTML 实体 (`&#x0A;` 换行 / `&#10;` / `&amp;` / `&lt;` / `&gt;` / `&quot;` / `&apos;`; 微信笔记 datadesc 用)。
/// 非法实体原样保留 `&`。纯字符串扫描, infallible。`pub(crate)`: decoder/forward.rs 解实体编码的 recorditem 复用。
pub(crate) fn decode_xml_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        // 实体名/码在 & 与 ; 之间; 限 ; 距离 ≤ 10 防把普通 & 后一大段当实体。
        // (10 = 最长合法实体 &#x10FFFF; 的名部 "#x10FFFF" 8 字符 + 余量; 别下调会截断最大码点。)
        if let Some(semi) = tail[1..].find(';').map(|p| p + 1).filter(|&p| p <= 10) {
            let ent = &tail[1..semi];
            let decoded = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
                }
                _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
                _ => None,
            };
            if let Some(c) = decoded {
                out.push(c);
                rest = &tail[semi + 1..];
                continue;
            }
        }
        out.push('&'); // 非实体: & 原样, 前进 1
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

/// 从笔记 (type 18) content XML 抽正文: 拼接所有 `<datadesc>…</datadesc>` 文本 (笔记正文分段) + 解 XML 实体。
/// 无 content / 无 datadesc / 全空 → None。**纯字符串扫描, infallible** (非真 XML parser, 锁常见形态)。
#[must_use]
pub fn parse_note_text(content: Option<&str>) -> Option<String> {
    let xml = content?;
    let mut parts = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find("<datadesc>") {
        let after = &rest[s + "<datadesc>".len()..];
        let Some(e) = after.find("</datadesc>") else { break };
        let seg = decode_xml_entities(&after[..e]);
        let seg = seg.trim();
        if !seg.is_empty() {
            parts.push(seg.to_string());
        }
        rest = &after[e + "</datadesc>".len()..];
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// 抽 `<tag>…</tag>` 内容 (第一个; 无则 None)。
fn tag_text<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&format!("</{tag}>"))? + start;
    Some(&s[start..end])
}
/// 抽开标签属性 `name="值"` (给 dataitem datatype)。
fn attr<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = s.find(&needle)? + needle.len();
    let end = s[start..].find('"')? + start;
    Some(&s[start..end])
}

/// 从笔记 (type 18) content XML 抽媒体引用: 每个带 `<fullmd5>` 的 `<dataitem>` → 一条 [`FavoriteMediaRef`]
/// (seq 0-based, datatype/fullsize/datafmt)。无 content / 无媒体 dataitem → 空 Vec。**纯字符串扫描, infallible**。
#[must_use]
pub fn parse_note_media(content: Option<&str>) -> Vec<FavoriteMediaRef> {
    let Some(xml) = content else { return Vec::new() };
    let mut out = Vec::new();
    let mut seq = 0i64;
    let mut rest = xml;
    while let Some(s) = rest.find("<dataitem") {
        let after = &rest[s..];
        let Some(e) = after.find("</dataitem>") else { break };
        let item = &after[..e]; // 开标签(含 datatype 属性) + body(fullmd5/fullsize/datafmt)
        rest = &after[e + "</dataitem>".len()..];
        // 只收带 fullmd5 的项 (图片/文件/HTML; 纯文本 datatype=1 无 fullmd5 → 跳, 正文在 note_text)。
        let Some(md5) = tag_text(item, "fullmd5").map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        let data_type = attr(item, "datatype").and_then(|v| v.parse().ok()).unwrap_or(0);
        let media_size = tag_text(item, "fullsize")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let data_fmt = tag_text(item, "datafmt")
            .map(|v| v.trim().trim_start_matches('.').to_string())
            .filter(|s| !s.is_empty());
        out.push(FavoriteMediaRef {
            seq,
            data_type,
            media_md5: md5.to_string(),
            media_size,
            data_fmt,
        });
        seq += 1;
    }
    out
}

/// 组装一条 [`FavoriteRow`] + [`FavoriteContext`] → [`FavoriteCreate`] (event_seq 留 0, 后置填)。
///
/// 纯字段映射 + 笔记正文/媒体引用解析。空串 real_chat_name/source_id → `None`。不 log。**infallible**。
#[must_use]
pub fn assemble_favorite(row: &FavoriteRow, ctx: &FavoriteContext) -> FavoriteCreate {
    // 空串 → None (= 未设), 跟 FavoriteCreate 的 nullable 语义一致。
    FavoriteCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::FavoriteUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        server_id: row.server_id,
        local_id: row.local_id,
        fav_type: row.fav_type,
        update_time: row.update_time,
        from_user: row.from_user.clone(),
        real_chat_name: super::non_empty(&row.real_chat_name),
        source_id: super::non_empty(&row.source_id),
        content_len: row.content_len,
        note_text: parse_note_text(row.note_content.as_deref()),
        media: parse_note_media(row.note_content.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FavoriteContext {
        FavoriteContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "favorite.db".to_string(),
            source_native_id: "Favorite_156".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    fn row(from_user: &str, real_chat: Option<&str>, src: Option<&str>) -> FavoriteRow {
        FavoriteRow {
            local_id: 156,
            server_id: 329,
            fav_type: 14,
            update_time: 1_779_354_334,
            from_user: from_user.to_string(),
            real_chat_name: real_chat.map(str::to_string),
            source_id: src.map(str::to_string),
            content_len: 2048,
            note_content: None,
        }
    }

    #[test]
    fn assemble_maps_fields() {
        let fav = assemble_favorite(&row("wxid_src", Some("wxid_rc"), Some("hash_abc")), &ctx());
        assert_eq!(fav.server_id, 329);
        assert_eq!(fav.local_id, 156);
        assert_eq!(fav.fav_type, 14);
        assert_eq!(fav.update_time, 1_779_354_334);
        assert_eq!(fav.from_user, "wxid_src");
        assert_eq!(fav.real_chat_name.as_deref(), Some("wxid_rc"));
        assert_eq!(fav.source_id.as_deref(), Some("hash_abc"));
        assert_eq!(fav.content_len, 2048);
        assert_eq!(fav.provenance.event_type, EventType::FavoriteUpdate);
        assert_eq!(fav.provenance.event_action, EventAction::Create);
        assert_eq!(fav.provenance.event_seq, 0);
    }

    #[test]
    fn empty_realchat_source_to_none() {
        let fav = assemble_favorite(&row("wxid_src", Some(""), Some("")), &ctx());
        assert_eq!(fav.real_chat_name, None, "空串 real_chat_name → None");
        assert_eq!(fav.source_id, None, "空串 source_id → None");
        assert_eq!(fav.note_text, None, "非笔记 note_content None → note_text None");
    }

    #[test]
    fn parse_note_text_extracts_datadesc() {
        // 笔记 (type 18) content: datalist 里 datatype=1 的 datadesc = 笔记正文分段; &#x0A; 换行。
        let xml = "<favitem type=\"18\"><datalist count=\"2\">\
            <dataitem datatype=\"8\" htmlid=\"WeNoteHtmlFile\"><cdn_datakey>x</cdn_datakey></dataitem>\
            <dataitem datatype=\"1\"><datadesc>TiAmo:&#x0A;#接龙&#x0A;今天&amp;明天</datadesc></dataitem>\
            </datalist></favitem>";
        let note = parse_note_text(Some(xml)).unwrap();
        assert_eq!(note, "TiAmo:\n#接龙\n今天&明天", "抽 datadesc + 解 &#x0A;/&amp;");
        // 多段 datadesc 拼接 (换行连)。
        let multi = "<x><datadesc>第一段</datadesc><y/><datadesc>第二段</datadesc></x>";
        assert_eq!(parse_note_text(Some(multi)).as_deref(), Some("第一段\n第二段"));
        // 无 datadesc / None / 空 → None。
        assert_eq!(parse_note_text(Some("<favitem type=\"18\"></favitem>")), None);
        assert_eq!(parse_note_text(None), None);
        assert_eq!(
            parse_note_text(Some("<x><datadesc>  </datadesc></x>")),
            None,
            "全空白 → None"
        );
    }

    #[test]
    fn assemble_note_type18_fills_note_text() {
        let mut r = row("wxid_src", None, None);
        r.fav_type = 18;
        r.note_content = Some("<favitem><datadesc>笔记正文&#x0A;第二行</datadesc></favitem>".to_string());
        let fav = assemble_favorite(&r, &ctx());
        assert_eq!(
            fav.note_text.as_deref(),
            Some("笔记正文\n第二行"),
            "type18 笔记正文落库"
        );
    }

    #[test]
    fn decode_entities_edge_cases() {
        assert_eq!(decode_xml_entities("a&amp;b&lt;c&gt;d"), "a&b<c>d");
        assert_eq!(decode_xml_entities("&#65;&#x42;&#x4e2d;"), "AB中"); // 十进/十六进/中文码点
        assert_eq!(decode_xml_entities("plain & text"), "plain & text", "非实体 & 原样");
        assert_eq!(decode_xml_entities("&notreal;x"), "&notreal;x", "未知实体原样");
    }

    #[test]
    fn parse_note_media_extracts_refs() {
        let xml = "<favitem type=\"18\"><datalist count=\"3\">\
            <dataitem datatype=\"8\" htmlid=\"WeNoteHtmlFile\"><datafmt>.htm</datafmt><fullmd5>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</fullmd5><fullsize>3470</fullsize></dataitem>\
            <dataitem datatype=\"1\"><datadesc>纯文本无md5</datadesc></dataitem>\
            <dataitem datatype=\"2\" dataid=\"x\"><fullmd5>bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</fullmd5><fullsize>345787</fullsize></dataitem>\
            </datalist></favitem>";
        let m = parse_note_media(Some(xml));
        assert_eq!(m.len(), 2, "只收带 fullmd5 的项 (datatype=1 纯文本跳过)");
        assert_eq!(m[0].seq, 0);
        assert_eq!(m[0].data_type, 8);
        assert_eq!(m[0].media_md5, "a".repeat(32));
        assert_eq!(m[0].media_size, 3470);
        assert_eq!(m[0].data_fmt.as_deref(), Some("htm"), "datafmt 去前导点");
        assert_eq!(m[1].seq, 1, "seq 只在收录项递增 (跳过项不占号)");
        assert_eq!(m[1].data_type, 2);
        assert_eq!(m[1].media_md5, "b".repeat(32));
        assert_eq!(m[1].media_size, 345_787);
        assert_eq!(m[1].data_fmt, None, "无 datafmt → None");
        assert!(parse_note_media(None).is_empty(), "无 content → 空");
        assert!(
            parse_note_media(Some(
                "<x><dataitem datatype=\"1\"><datadesc>t</datadesc></dataitem></x>"
            ))
            .is_empty(),
            "无媒体 → 空"
        );
    }
}
