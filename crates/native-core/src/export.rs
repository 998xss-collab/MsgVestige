//! export — 从 L1 db 直读业务表导出 JSONL (alpha 直读 L1 明文表, 不走 query-planner)。
//!
//! L1 表全程明文 (ADR-427), 导出即读业务列拼 JSON 行。用途: `msgvestige export` 让用户把已 ingest 的
//! 联系人/群/会话/收藏拿出来 (JSONL: 一行一 JSON 对象, 流式好接下游)。**只读**, 不改 L1。
//!
//! ## K-R4
//! 导出**本就是把明文数据交给用户** (ADR-427 L1 明文 + 用户自己的数据), 故导出明文列是预期行为;
//! 但**内部脱敏列** (`*_sha` / `account_id_sha` 等) 不导 (对用户无意义 + 避免混淆); source/rowid 内部键不导。

use std::io::Write;

use rusqlite::Connection;
use serde_json::{Map, Value};

/// 可导出的 L1 业务表 (curated 业务列, 不含内部 _sha/键)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExportTable {
    /// person → 联系人 (wxid/昵称/备注/微信号/类型 + 拼音/状态位/性别地区)。
    Contacts,
    /// chatroom → 群 (群 id/群名/群主/人数/公告 + 编辑者/发布时间)。
    Groups,
    /// session → 会话列表 (对话 id/未读/最后消息时间等)。
    Sessions,
    /// favorite → 收藏条目骨架。
    Favorites,
    /// message → 聊天消息 (可 --chat 过滤某会话; 类型走 msg_type_name 人话名)。
    Messages,
}

impl ExportTable {
    /// CLI `--table <name>` 解析。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "contacts" | "person" => Some(Self::Contacts),
            "groups" | "chatroom" | "chatrooms" => Some(Self::Groups),
            "sessions" | "session" => Some(Self::Sessions),
            "favorites" | "favorite" => Some(Self::Favorites),
            "messages" | "message" | "msg" => Some(Self::Messages),
            _ => None,
        }
    }

    /// 导出 SQL (只选**业务明文列**, 稳定顺序; 不含 account_id_sha/username_sha/source/rowid 等内部键)。
    fn sql(self) -> &'static str {
        match self {
            Self::Contacts => {
                "SELECT username, nick_name, remark, alias, local_type, is_in_chat_room, \
                 quan_pin, pin_yin_initial, sex, country, province, city, friend_source, \
                 is_starred, is_pinned, blocks_moments, hide_their_moments, chat_only, is_muted, description, \
                 signature, moments_cover_url \
                 FROM person ORDER BY username"
            }
            Self::Groups => {
                "SELECT chatroom_id, chatroom_name, owner_wxid, member_count, announcement, \
                 announcement_editor, announcement_publish_time \
                 FROM chatroom ORDER BY chatroom_id"
            }
            Self::Sessions => {
                "SELECT username, unread_count, last_msg_type, last_timestamp, last_msg_sender \
                 FROM session ORDER BY last_timestamp DESC"
            }
            Self::Favorites => {
                "SELECT server_id, fav_type, update_time, from_user, real_chat_name, source_id, content_len \
                 FROM favorite ORDER BY update_time DESC"
            }
            Self::Messages => {
                "SELECT conv_id, create_time, sender_wxid, msg_type, msg_type_name, msg_sub_type_name, \
                 sys_type, text_content FROM message ORDER BY conv_id, create_time"
            }
        }
    }
}

/// 把 L1 表导成 JSONL (一行一 JSON 对象, 列名→值; NULL 列略过)。返回导出行数。
///
/// # Errors
/// rusqlite 查询失败 (表缺列/库损坏) 或 writer IO 失败。
pub fn export_jsonl(conn: &Connection, table: ExportTable, out: &mut dyn Write) -> anyhow::Result<u64> {
    let mut stmt = conn.prepare(table.sql())?;
    let col_names: Vec<String> = stmt.column_names().into_iter().map(str::to_string).collect();
    let mut rows = stmt.query([])?;
    let mut n = 0u64;
    while let Some(row) = rows.next()? {
        let mut obj = Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let v = match row.get_ref(i)? {
                rusqlite::types::ValueRef::Null => continue, // NULL 列略过 (JSONL 更紧凑)
                rusqlite::types::ValueRef::Integer(n) => Value::from(n),
                rusqlite::types::ValueRef::Real(f) => Value::from(f),
                rusqlite::types::ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
                rusqlite::types::ValueRef::Blob(b) => Value::from(hex::encode(b)),
            };
            obj.insert(name.clone(), v);
        }
        // 导出层派生 (ADR-505; 不落库, 查表可算): 联系人 friend_source 码 → 中文 (未知码保留原值 + "其他")。
        if table == ExportTable::Contacts {
            if let Some(code) = obj.get("friend_source").and_then(Value::as_i64) {
                obj.insert(
                    "friend_source_text".to_string(),
                    Value::from(crate::labels::friend_source_display(code)),
                );
            }
        }
        serde_json::to_writer(&mut *out, &Value::Object(obj))?;
        out.write_all(b"\n")?;
        n += 1;
    }
    Ok(n)
}

/// 导出格式 (cli `--format`)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExportFormat {
    /// 一行一 JSON 对象 (机器 / 下游流式)。
    Jsonl,
    /// CSV (Excel 友好; 首行列名, 字段按 RFC4180 转义)。
    Csv,
    /// 单文件 HTML 表格 (浏览器直接看)。
    Html,
}

impl ExportFormat {
    /// cli `--format <name>` 解析。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "jsonl" | "json" => Some(Self::Jsonl),
            "csv" => Some(Self::Csv),
            "html" => Some(Self::Html),
            _ => None,
        }
    }
}

/// 一个 sqlite 值 → 文本 (NULL→空串; Blob→hex)。给 CSV / HTML 单元格用。
fn cell_text(row: &rusqlite::Row, i: usize) -> rusqlite::Result<String> {
    Ok(match row.get_ref(i)? {
        rusqlite::types::ValueRef::Null => String::new(),
        rusqlite::types::ValueRef::Integer(n) => n.to_string(),
        rusqlite::types::ValueRef::Real(f) => f.to_string(),
        rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        rusqlite::types::ValueRef::Blob(b) => hex::encode(b),
    })
}

/// 一行 CSV (RFC4180: 含 `,` / `"` / 换行的字段用 `"` 包, 内部 `"`→`""`; 行尾 CRLF)。
fn csv_row(cells: &[String]) -> String {
    let mut s = String::new();
    for (i, c) in cells.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        if c.contains([',', '"', '\n', '\r']) {
            s.push('"');
            s.push_str(&c.replace('"', "\"\""));
            s.push('"');
        } else {
            s.push_str(c);
        }
    }
    s.push_str("\r\n");
    s
}

/// HTML 转义 (`&` `<` `>` `"` → 实体; 防 text_content 里的标签 / 引号破坏页面)。
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// HTML 头 + 表头行 (单文件, 内联样式, UTF-8; 浏览器直接开)。
fn write_html_head(out: &mut dyn Write, cols: &[String]) -> std::io::Result<()> {
    out.write_all(
        b"<!doctype html>\n<html lang=\"zh\">\n<head>\n<meta charset=\"utf-8\">\n\
          <style>body{font-family:sans-serif;font-size:13px}table{border-collapse:collapse}\
          td,th{border:1px solid #ccc;padding:2px 6px;text-align:left;vertical-align:top;\
          max-width:600px;overflow-wrap:anywhere}th{background:#f0f0f0}</style>\n\
          </head>\n<body>\n<table>\n<tr>",
    )?;
    for c in cols {
        out.write_all(format!("<th>{}</th>", escape_html(c)).as_bytes())?;
    }
    out.write_all(b"</tr>\n")?;
    Ok(())
}

/// 写一行 JSONL (列名→值; NULL 略过; Contacts 派生 friend_source_text)。export() 的 jsonl 分支用。
fn write_jsonl_row(
    row: &rusqlite::Row,
    col_names: &[String],
    table: ExportTable,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let mut obj = Map::new();
    for (i, name) in col_names.iter().enumerate() {
        let v = match row.get_ref(i)? {
            rusqlite::types::ValueRef::Null => continue,
            rusqlite::types::ValueRef::Integer(n) => Value::from(n),
            rusqlite::types::ValueRef::Real(f) => Value::from(f),
            rusqlite::types::ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
            rusqlite::types::ValueRef::Blob(b) => Value::from(hex::encode(b)),
        };
        obj.insert(name.clone(), v);
    }
    if table == ExportTable::Contacts {
        if let Some(code) = obj.get("friend_source").and_then(Value::as_i64) {
            obj.insert(
                "friend_source_text".to_string(),
                Value::from(crate::labels::friend_source_display(code)),
            );
        }
    }
    serde_json::to_writer(&mut *out, &Value::Object(obj))?;
    out.write_all(b"\n")?;
    Ok(())
}

/// 导出 L1 表到指定格式 (jsonl / csv / html); `chat` 仅对 Messages 生效 (按 conv_id 过滤某会话)。
/// **只读**, 不改 L1。返回导出行数。
///
/// # Errors
/// rusqlite 查询失败 / writer IO 失败。
pub fn export(
    conn: &Connection,
    table: ExportTable,
    format: ExportFormat,
    chat: Option<&str>,
    out: &mut dyn Write,
) -> anyhow::Result<u64> {
    let use_chat = table == ExportTable::Messages && chat.is_some();
    // Messages + --chat: 按 conv_id 过滤 (其他表忽略 chat)。
    let filtered = "SELECT conv_id, create_time, sender_wxid, msg_type, msg_type_name, \
                    msg_sub_type_name, sys_type, text_content FROM message \
                    WHERE conv_id = ?1 ORDER BY create_time";
    let sql: &str = if use_chat { filtered } else { table.sql() };
    let mut stmt = conn.prepare(sql)?;
    let col_names: Vec<String> = stmt.column_names().into_iter().map(str::to_string).collect();

    match format {
        ExportFormat::Jsonl => {}
        ExportFormat::Csv => out.write_all(csv_row(&col_names).as_bytes())?,
        ExportFormat::Html => write_html_head(out, &col_names)?,
    }

    let mut rows = if use_chat {
        stmt.query([chat.expect("use_chat 时 chat 非空")])?
    } else {
        stmt.query([])?
    };
    let mut n = 0u64;
    while let Some(row) = rows.next()? {
        match format {
            ExportFormat::Jsonl => write_jsonl_row(row, &col_names, table, out)?,
            ExportFormat::Csv => {
                let cells = (0..col_names.len())
                    .map(|i| cell_text(row, i))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                out.write_all(csv_row(&cells).as_bytes())?;
            }
            ExportFormat::Html => {
                out.write_all(b"<tr>")?;
                for i in 0..col_names.len() {
                    out.write_all(format!("<td>{}</td>", escape_html(&cell_text(row, i)?)).as_bytes())?;
                }
                out.write_all(b"</tr>\n")?;
            }
        }
        n += 1;
    }
    if format == ExportFormat::Html {
        out.write_all(b"</table>\n</body>\n</html>\n")?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_l1() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::storage::init_l1_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn export_format_parse() {
        assert_eq!(ExportFormat::parse("csv"), Some(ExportFormat::Csv));
        assert_eq!(ExportFormat::parse("HTML"), Some(ExportFormat::Html));
        assert_eq!(ExportFormat::parse("jsonl"), Some(ExportFormat::Jsonl));
        assert_eq!(ExportFormat::parse("nope"), None);
    }

    #[test]
    fn export_messages_sql_all_formats_valid() {
        // 空 message 表: 三格式 + --chat 过滤 SQL 都跑通 (列名对 schema, 0 行不报错)。
        let conn = mem_l1();
        let mut buf = Vec::new();
        for fmt in [ExportFormat::Jsonl, ExportFormat::Csv, ExportFormat::Html] {
            buf.clear();
            let n = export(&conn, ExportTable::Messages, fmt, None, &mut buf).unwrap();
            assert_eq!(n, 0, "空 message 表导 0 行");
        }
        buf.clear();
        let n = export(
            &conn,
            ExportTable::Messages,
            ExportFormat::Jsonl,
            Some("x@chatroom"),
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 0, "--chat 过滤 SQL 也跑通");
    }

    #[test]
    fn export_csv_header_and_escape() {
        let conn = mem_l1();
        let mut p = sample_person();
        p.nick_name = "含,逗号\"引号".into(); // 触发 CSV 转义
        crate::storage::insert_person(&conn, &p).unwrap();
        let mut buf = Vec::new();
        let n = export(&conn, ExportTable::Contacts, ExportFormat::Csv, None, &mut buf).unwrap();
        assert_eq!(n, 1);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("username,nick_name"), "首行是列名");
        assert!(s.contains("\"含,逗号\"\"引号\""), "含逗号/引号的字段按 RFC4180 转义");
    }

    #[test]
    fn export_html_wraps_and_escapes() {
        let conn = mem_l1();
        let mut p = sample_person();
        p.nick_name = "<script>x".into(); // 触发 HTML 转义 (防注入)
        crate::storage::insert_person(&conn, &p).unwrap();
        let mut buf = Vec::new();
        let n = export(&conn, ExportTable::Contacts, ExportFormat::Html, None, &mut buf).unwrap();
        assert_eq!(n, 1);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("<table>") && s.contains("</table>"), "HTML 表格包裹");
        assert!(s.contains("&lt;script&gt;x"), "数据里的 <script> 被转义");
        assert!(!s.contains("<script>x"), "原始 <script> 不出现 (防页面注入)");
    }

    #[test]
    fn parse_table_aliases() {
        assert_eq!(ExportTable::parse("contacts"), Some(ExportTable::Contacts));
        assert_eq!(ExportTable::parse("person"), Some(ExportTable::Contacts));
        assert_eq!(ExportTable::parse("GROUPS"), Some(ExportTable::Groups));
        assert_eq!(ExportTable::parse("session"), Some(ExportTable::Sessions));
        assert_eq!(ExportTable::parse("nope"), None);
    }

    #[test]
    fn export_empty_table_zero_rows() {
        let conn = mem_l1();
        let mut buf = Vec::new();
        let n = export_jsonl(&conn, ExportTable::Contacts, &mut buf).unwrap();
        assert_eq!(n, 0);
        assert!(buf.is_empty(), "空表导出 0 行 0 字节");
    }

    /// codex P2: 4 表的 SELECT 都对 L1 schema 跑通 (空表 0 行不报错) — 挡 curated 列名 vs schema 漂移。
    #[test]
    fn all_export_tables_sql_valid_against_schema() {
        let conn = mem_l1();
        for table in [
            ExportTable::Contacts,
            ExportTable::Groups,
            ExportTable::Sessions,
            ExportTable::Favorites,
        ] {
            let mut buf = Vec::new();
            let n = export_jsonl(&conn, table, &mut buf)
                .unwrap_or_else(|e| panic!("{table:?} 导出 SQL 对 L1 schema 报错 (列名漂移?): {e}"));
            assert_eq!(n, 0, "{table:?} 空库导 0 行");
        }
    }

    /// 导出联系人时派生 friend_source_text 中文 (ADR-505): 已知码→中文, 未知码→"其他 (码 N)", 原码保留。
    #[test]
    fn contacts_export_adds_friend_source_text() {
        let conn = mem_l1();
        let mut p = sample_person();
        p.friend_source = 30; // 扫一扫
        crate::storage::insert_person(&conn, &p).unwrap();
        let mut buf = Vec::new();
        let n = export_jsonl(&conn, ExportTable::Contacts, &mut buf).unwrap();
        assert_eq!(n, 1);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"friend_source\":30"), "原始码保留 (事实源)");
        assert!(s.contains("通过扫一扫添加"), "派生 friend_source_text 中文");
    }

    #[test]
    fn export_contacts_jsonl_shape() {
        let conn = mem_l1();
        // 塞一条联系人 (走 insert_person)。
        let mut p = sample_person();
        p.is_starred = true;
        crate::storage::insert_person(&conn, &p).unwrap();
        let mut buf = Vec::new();
        let n = export_jsonl(&conn, ExportTable::Contacts, &mut buf).unwrap();
        assert_eq!(n, 1);
        let line = String::from_utf8(buf).unwrap();
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["username"], Value::from("wxid_export_test"), "业务明文列导出");
        assert_eq!(v["nick_name"], Value::from("导出昵称"));
        assert_eq!(v["is_starred"], Value::from(1), "flag 位解码列导出");
        // 内部键不导。
        assert!(v.get("account_id_sha").is_none(), "内部 _sha 键不导");
        assert!(v.get("username_sha").is_none());
    }

    /// 构造一条最小 V3Person (明文列填, 其余默认)。
    fn sample_person() -> crate::storage::V3Person {
        crate::storage::V3Person {
            account_id_sha: "acct_sha".into(),
            source: "contact.db".into(),
            source_native_id: "Contact_x".into(),
            username_sha: "u_sha".into(),
            account_id: "wxid_acct".into(),
            username: "wxid_export_test".into(),
            nick_name: "导出昵称".into(),
            remark: Some("备注".into()),
            alias: None,
            nick_name_len: 4,
            remark_len: 2,
            alias_len: 0,
            local_type: 1,
            is_in_chat_room: false,
            quan_pin: None,
            pin_yin_initial: None,
            remark_quan_pin: None,
            remark_pin_yin_initial: None,
            verify_flag: 0,
            delete_flag: 0,
            big_head_url: None,
            small_head_url: None,
            head_img_md5: None,
            description: None,
            flag: 0,
            chat_room_notify: 0,
            chat_room_type: 0,
            sex: 0,
            country: None,
            province: None,
            city: None,
            friend_source: 0,
            is_starred: false,
            is_collapsed: false,
            is_pinned: false,
            blocks_moments: false,
            hide_their_moments: false,
            chat_only: false,
            is_muted: false,
            signature: None,
            moments_cover_url: None,
            labels: None,
            friend_add_time: None,
            openim_company: None,
            openim_realname: None,
        }
    }
}
