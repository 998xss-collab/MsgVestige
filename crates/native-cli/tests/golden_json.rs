//! 命令级 JSON golden 测试 —— 锁住每个**冷查**查询命令的 `{data, meta}` 信封**形状**。
//!
//! 目的: 后续把查询逻辑从 `main.rs` 抽成共享内核时, 若改了 json 键 / 丢了 `meta.summary` /
//! 漂了 `meta` 字段集, 本测试会红。现有单测只验 `query_*` 的**渲染前返回值**, 锁不住 json 信封。
//!
//! 除 json 外, 每命令**再跑一遍 `--format table`** 锁 `tests/goldens/<name>.table.txt` (stdout 逐字节)。
//! 抽核 §6② 把 table 渲染搬进 `native-query::render_table` (改读 json Value 而非 rusqlite 行) 前, 本
//! table golden 先捕获现网基线 → 搬后逐字节相等 = `render_cell` 适配零漂移的硬证据 (json golden 锁不住
//! table 渲染路径)。表头 / 游标提示走 stderr, 不入 table golden。
//!
//! 机制:
//!   1. 用 `native_core::storage::init_l1_schema` 建全表, PRAGMA 驱动插**确定性**假数据 (固定值,
//!      无随机 / 无 wall-clock, 可复现)。
//!   2. 对每个冷查命令跑真二进制 (`env!("CARGO_BIN_EXE_msgvestige")`) `<cmd> … --l1-db <fixture>`
//!      两次 (`--format json` / `--format table`), 各捕 stdout。
//!   3. 跟 `tests/goldens/<name>.json` + `<name>.table.txt` 比对; `UPDATE_GOLDENS=1` 时写入, 否则断言相等。
//!
//! 生成: `UPDATE_GOLDENS=1 cargo test -p msgvestige --test golden_json`
//! 校验: `cargo test -p msgvestige --test golden_json`
//!
//! 易变字段规整: `meta.account` (= sha8(L1 路径), 路径相关) 与 `meta.next_cursor` (游标内嵌
//! account_sha8, 路径相关) 在比对/写入前替换为占位串。fixture 里所有时间戳 / id 都是固定整数,
//! 命令 JSON 出口用**原值** (Fmt::Time 也只 emit 整数), 故无本地时区 / wall-clock 漂移。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use rusqlite::types::Value;
use rusqlite::Connection;

// ---------- fixture 构造 ----------

/// 便捷构造 rusqlite 文本值。
fn t(s: &str) -> Value {
    Value::Text(s.to_string())
}
/// 便捷构造 rusqlite 整数值。
fn n(i: i64) -> Value {
    Value::Integer(i)
}

/// PRAGMA 驱动的通用插入: 读 `table_info` → 未 override 的 NOT NULL 无默认列填类型占位, override 覆盖。
///
/// 这样免去逐表转抄 schema (NOT NULL 列多), 又保持确定性 (占位值固定)。`overrides` 里给足查询要读的列
/// + JOIN 键三元组 (account_id_sha/source/source_native_id) 即可。
fn ins(conn: &Connection, table: &str, overrides: &[(&str, Value)]) {
    let over: BTreeMap<&str, &Value> = overrides.iter().map(|(k, v)| (*k, v)).collect();
    // (name, type, notnull, has_default, pk)
    let cols: Vec<(String, String, bool, bool, i64)> = {
        let mut st = conn.prepare(&format!("PRAGMA table_info(\"{table}\")")).unwrap();
        let rows = st
            .query_map([], |r| {
                let name: String = r.get(1)?;
                let ctype: String = r.get(2)?;
                let notnull: i64 = r.get(3)?;
                let dflt: Option<String> = r.get(4)?;
                let pk: i64 = r.get(5)?;
                Ok((name, ctype, notnull == 1, dflt.is_some(), pk))
            })
            .unwrap();
        rows.map(Result::unwrap).collect()
    };
    assert!(!cols.is_empty(), "表 {table} 无列 (PRAGMA 空) — 表名拼错?");
    // 单列整型主键 = rowid 别名 (可省, 自增); 复合主键的整型列不是别名, 必须给值。
    let pk_count = cols.iter().filter(|(.., pk)| *pk >= 1).count();

    let mut names: Vec<String> = Vec::new();
    let mut vals: Vec<Value> = Vec::new();
    for (name, ctype, notnull, has_default, pk) in &cols {
        if let Some(v) = over.get(name.as_str()) {
            names.push(name.clone());
            vals.push((*v).clone());
            continue;
        }
        let up = ctype.to_uppercase();
        let is_int = up.contains("INT");
        // 单列整型主键 = rowid 别名 → 跳过让其自增 (复合主键的整型列不跳, 需给值)。
        if *pk >= 1 && is_int && pk_count == 1 {
            continue;
        }
        // 只给 "NOT NULL 且无默认" 的列补占位; 可空 / 有默认的略过 (NULL / 默认值)。
        if *notnull && !has_default {
            let ph = if is_int {
                Value::Integer(0)
            } else if up.contains("REAL") || up.contains("FLOA") || up.contains("DOUB") {
                Value::Real(0.0)
            } else if up.contains("BLOB") {
                Value::Blob(Vec::new())
            } else {
                Value::Text("x".to_string())
            };
            names.push(name.clone());
            vals.push(ph);
        }
    }
    // override 里给了但表没有的列 = 写错列名, 早失败。
    for k in over.keys() {
        assert!(
            cols.iter().any(|(nm, ..)| nm == k),
            "表 {table} 无 override 列 {k} — 列名拼错或 schema 变了"
        );
    }

    let placeholders = std::iter::repeat("?").take(names.len()).collect::<Vec<_>>().join(",");
    let col_list = names.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(",");
    let sql = format!("INSERT INTO \"{table}\" ({col_list}) VALUES ({placeholders})");
    conn.execute(&sql, rusqlite::params_from_iter(vals.iter()))
        .unwrap_or_else(|e| panic!("插 {table} 失败: {e}\nSQL: {sql}"));
}

/// 插一条 message 行 (JOIN 基表 + 众多命令的数据源)。三元组固定 account_id_sha='a', source='msg'。
#[allow(clippy::too_many_arguments)]
fn msg(
    conn: &Connection,
    nid: &str,
    conv: &str,
    sender: &str,
    ct: i64,
    mtype: i64,
    mtype_name: &str,
    text: &str,
    is_chatroom: i64,
    sys_type: Option<&str>,
) {
    let mut ov: Vec<(&str, Value)> = vec![
        ("account_id_sha", t("a")),
        ("source", t("msg")),
        ("source_native_id", t(nid)),
        ("account_id", t("acc")),
        ("conv_id", t(conv)),
        ("sender_wxid", t(sender)),
        ("create_time", n(ct)),
        ("msg_type", n(mtype)),
        ("msg_type_name", t(mtype_name)),
        ("text_content", t(text)),
        ("is_chatroom", n(is_chatroom)),
    ];
    if let Some(st) = sys_type {
        ov.push(("sys_type", t(st)));
    }
    ins(conn, "message", &ov);
}

/// 插一条 message_app 行 (links/files/thread/biz/money 金额 JOIN 用); 三元组绑对应 message。
fn app(conn: &Connection, nid: &str, extra: &[(&str, Value)]) {
    let mut ov: Vec<(&str, Value)> = vec![
        ("account_id_sha", t("a")),
        ("source", t("msg")),
        ("source_native_id", t(nid)),
        ("account_id", t("acc")),
    ];
    ov.extend(extra.iter().cloned());
    ins(conn, "message_app", &ov);
}

/// 建合成 L1 fixture 到 `path` (确定性; 覆盖所有冷查命令要读的表)。
fn build_fixture(path: &Path) {
    let conn = Connection::open(path).unwrap();
    native_core::storage::init_l1_schema(&conn).unwrap();

    // ---- 基础 message 行 ----
    // convA: alice 先, 我(acc)后 → 末条是我 = 不算漏回。
    msg(
        &conn,
        "m1",
        "chatA",
        "wxid_alice",
        1000,
        1,
        "文本",
        "看 https://example.com/a 联系13800138000 身份证110101199003070011",
        0,
        None,
    );
    msg(&conn, "m2", "chatA", "acc", 2000, 1, "文本", "好的收到", 0, None);
    // convB: bob 末条 = 漏回 (followups 非空)。
    msg(&conn, "mb1", "chatB", "wxid_bob", 1500, 1, "文本", "在吗", 0, None);
    // gh_ 公众号会话 (biz); 毫秒时间。
    msg(
        &conn,
        "B1",
        "gh_news",
        "gh_news",
        1_700_000_000_000,
        1,
        "文本",
        "<xml appmsg>",
        0,
        None,
    );
    // 群系统事件 (events): type10000 + sys_type。
    msg(
        &conn,
        "E1",
        "g@chatroom",
        "sysmsg",
        3000,
        10000,
        "SYSTEM",
        "\"甲\"邀请\"乙\"加入了群聊",
        1,
        Some("member_join"),
    );

    // ---- JOIN message 的派生表锚点 message + 派生行 ----
    // locations
    msg(&conn, "loc1", "chatA", "wxid_alice", 1100, 1, "文本", "[位置]", 0, None);
    ins(
        &conn,
        "message_location",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("loc1")),
            ("account_id", t("acc")),
            ("latitude", Value::Real(31.23041)),
            ("longitude", Value::Real(121.47370)),
            ("poiname", t("人民广场")),
            ("label", t("上海市黄浦区")),
            ("cityname", t("上海")),
        ],
    );
    // cards
    msg(
        &conn,
        "card1",
        "chatA",
        "wxid_alice",
        1200,
        1,
        "文本",
        "[名片]",
        0,
        None,
    );
    ins(
        &conn,
        "message_card",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("card1")),
            ("account_id", t("acc")),
            ("card_nickname", t("张三")),
            ("card_alias", t("zhangsan")),
            ("card_username", t("wxid_zhangsan")),
            ("card_open_im_desc", t("某公司")),
        ],
    );
    // media
    msg(&conn, "med1", "chatA", "wxid_alice", 1300, 3, "图片", "[图片]", 0, None);
    ins(
        &conn,
        "message_media",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("med1")),
            ("account_id", t("acc")),
            ("media_kind", t("image")),
            ("md5", t("d41d8cd98f00b204e9800998ecf8427e")),
            ("file_size", n(102_400)),
            ("play_length", n(0)),
            ("cdn_url", t("http://cdn/x")),
        ],
    );
    // hongbao claim (money --claims)
    msg(
        &conn,
        "hb1",
        "g@chatroom",
        "wxid_alice",
        1400,
        1,
        "文本",
        "[红包领取]",
        1,
        None,
    );
    ins(
        &conn,
        "message_hongbao_claim",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("hb1")),
            ("account_id", t("acc")),
            ("send_id", t("HB_SEND_1")),
            ("is_own_envelope", n(0)),
            ("peer_name", t("wxid_bob")),
        ],
    );
    // calls
    msg(&conn, "call1", "chatB", "wxid_bob", 1600, 1, "文本", "", 0, None);
    ins(
        &conn,
        "message_call",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("call1")),
            ("account_id", t("acc")),
            ("invite_type", n(1)),
            ("room_type", n(0)),
            ("call_state", n(101)),
            ("duration", n(42)),
            ("display_content", t("通话时长 00:42")),
        ],
    );
    // mentions
    msg(
        &conn,
        "men1",
        "g@chatroom",
        "wxid_sender",
        1700,
        1,
        "文本",
        "@张三 在吗",
        1,
        None,
    );
    ins(
        &conn,
        "message_mention",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("men1")),
            ("account_id", t("acc")),
            ("mentioned_wxid", t("wxid_zhangsan")),
            ("is_at_all", n(0)),
        ],
    );
    // links (message_app 带 url)
    msg(&conn, "lnk1", "chatA", "wxid_alice", 1800, 1, "文本", "看链接", 0, None);
    app(
        &conn,
        "lnk1",
        &[
            ("app_type", n(5)),
            ("media_count", n(0)),
            ("title", t("好文章")),
            ("url", t("https://example.com/link")),
        ],
    );
    // files (message_app 带 file_ext)
    msg(&conn, "fil1", "chatA", "wxid_alice", 1900, 1, "文本", "文件", 0, None);
    app(
        &conn,
        "fil1",
        &[
            ("app_type", n(6)),
            ("media_count", n(0)),
            ("title", t("报表.xlsx")),
            ("file_ext", t("xlsx")),
            ("file_size", n(2_097_152)),
        ],
    );
    // thread (message_app 带 refer_svrid)
    msg(
        &conn,
        "thr1",
        "chatC",
        "wxid_replier",
        2100,
        1,
        "文本",
        "<xml appmsg>",
        0,
        None,
    );
    app(
        &conn,
        "thr1",
        &[
            ("app_type", n(57)),
            ("media_count", n(0)),
            ("title", t("回复正文")),
            ("refer_svrid", t("7283910293847")),
            ("refer_type", n(1)),
            ("refer_content", t("被引原文")),
        ],
    );
    // biz 的图文标题 (message_app 绑 gh_ 会话消息 B1)
    app(
        &conn,
        "B1",
        &[
            ("app_type", n(5)),
            ("media_count", n(0)),
            ("title", t("公众号文章标题")),
        ],
    );

    // ---- money: transfer / red_envelope / group_pay (+message_app 金额) ----
    app(
        &conn,
        "txapp",
        &[
            ("app_type", n(2000)),
            ("media_count", n(0)),
            ("transfer_fee", t("￥10.00")),
            ("transfer_txid", t("TXID-AAA")),
        ],
    );
    ins(
        &conn,
        "transfer",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("tr1")),
            ("account_id", t("acc")),
            ("transfer_id", t("TID")),
            ("transcation_id", t("TXID-AAA")),
            ("pay_sub_type", n(3)),
            ("begin_transfer_time", n(5000)),
            ("session_name", t("与 wxid_bob 的转账")),
            ("pay_payer", t("wxid_payer")),
            ("pay_receiver", t("wxid_receiver")),
        ],
    );
    ins(
        &conn,
        "red_envelope",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("re1")),
            ("account_id", t("acc")),
            ("send_id", t("SID")),
            ("scene_id", n(1)),
            ("hb_status", n(4)),
            ("hb_type", n(0)),
            ("receive_status", n(1)),
            ("native_url", t("url")),
            ("sender_user_name", t("wxid_sender")),
            ("session_name", t("群红包")),
        ],
    );
    app(
        &conn,
        "gpapp",
        &[
            ("app_type", n(2000)),
            ("media_count", n(0)),
            ("group_pay_amount", t("应付¥8.00")),
            ("group_pay_bill_no", t("BILL1")),
        ],
    );
    ins(
        &conn,
        "group_pay",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("gp1")),
            ("account_id", t("acc")),
            ("bill_no", t("BILL1")),
            ("message_local_id", n(1)),
            ("message_create_time", n(6000)),
            ("session_name", t("项目群")),
        ],
    );
    ins(
        &conn,
        "group_pay_member",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("gp1")),
            ("payer_wxid_sha", t("p1s")),
            ("account_id", t("acc")),
            ("payer_wxid", t("wxid_p1")),
            ("bill_no", t("BILL1")),
            ("amount", n(800)),
            ("pay_status", n(1)),
        ],
    );
    ins(
        &conn,
        "group_pay_member",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("gp1")),
            ("payer_wxid_sha", t("p2s")),
            ("account_id", t("acc")),
            ("payer_wxid", t("wxid_p2")),
            ("bill_no", t("BILL1")),
            ("amount", n(800)),
            ("pay_status", n(0)),
        ],
    );

    // ---- 独立表 (无 JOIN) ----
    // person (contacts / inspect contact / account)
    ins(
        &conn,
        "person",
        &[
            ("account_id_sha", t("a")),
            ("source", t("contact")),
            ("source_native_id", t("wxid_alice")),
            ("username_sha", t("sha_alice")),
            ("account_id", t("acc")),
            ("username", t("wxid_alice")),
            ("nick_name", t("小爱")),
            ("remark", t("同事阿爱")),
            ("alias", t("alice_wx")),
            ("local_type", n(1)),
        ],
    );
    ins(
        &conn,
        "person",
        &[
            ("account_id_sha", t("a")),
            ("source", t("contact")),
            ("source_native_id", t("wxid_bob")),
            ("username_sha", t("sha_bob")),
            ("account_id", t("acc")),
            ("username", t("wxid_bob")),
            ("nick_name", t("阿波")),
            ("remark", t("")),
            ("alias", t("")),
            ("local_type", n(1)),
        ],
    );
    // chatroom (chatrooms / inspect chatroom)
    ins(
        &conn,
        "chatroom",
        &[
            ("account_id_sha", t("a")),
            ("source", t("contact")),
            ("source_native_id", t("g@chatroom")),
            ("account_id", t("acc")),
            ("chatroom_id", t("g@chatroom")),
            ("chatroom_name", t("项目群")),
            ("owner_wxid", t("wxid_owner")),
            ("member_count", n(3)),
            ("announcement", t("群公告内容示例")),
        ],
    );
    // chatroom_member (members)
    for (nid, wxid, disp, role, ingrp) in [
        ("cm1", "wxid_owner", "群主", "owner", 1),
        ("cm2", "wxid_alice", "小爱", "member", 1),
        ("cm3", "wxid_left", "走了的", "member", 0),
    ] {
        ins(
            &conn,
            "chatroom_member",
            &[
                ("account_id_sha", t("a")),
                ("source", t("contact")),
                ("source_native_id", t(nid)),
                ("chatroom_id_sha", t("cs")),
                ("member_wxid_sha", t(&format!("{wxid}_sha"))),
                ("account_id", t("acc")),
                ("chatroom_id", t("g@chatroom")),
                ("member_wxid", t(wxid)),
                ("display_name", t(disp)),
                ("role", t(role)),
                ("is_in_group", n(ingrp)),
            ],
        );
    }
    // session (inspect session; sessions 命令是热查另做)
    ins(
        &conn,
        "session",
        &[
            ("account_id_sha", t("a")),
            ("source", t("session")),
            ("source_native_id", t("wxid_alice")),
            ("account_id", t("acc")),
            ("username", t("wxid_alice")),
        ],
    );
    // favorite / favorite_tag / favorite_media
    ins(
        &conn,
        "favorite",
        &[
            ("account_id_sha", t("a")),
            ("source", t("favorite")),
            ("source_native_id", t("fav1")),
            ("account_id", t("acc")),
            ("server_id", n(9001)),
            ("fav_type", n(1)),
            ("update_time", n(1_700_000_100)),
            ("from_user", t("wxid_alice")),
            ("real_chat_name", t("chatA")),
            ("content_len", n(12)),
        ],
    );
    ins(
        &conn,
        "favorite_tag",
        &[
            ("account_id_sha", t("a")),
            ("source", t("favorite")),
            ("source_native_id", t("ft1")),
            ("account_id", t("acc")),
            ("tag_server_id", n(5001)),
            ("fav_server_id", n(9001)),
            ("tag_name", t("工作")),
        ],
    );
    ins(
        &conn,
        "favorite_media",
        &[
            ("account_id_sha", t("a")),
            ("source", t("favorite")),
            ("source_native_id", t("fm1")),
            ("account_id", t("acc")),
            ("fav_server_id", n(9001)),
            ("seq", n(0)),
            ("data_type", n(2)),
            ("media_md5", t("md5abc")),
            ("media_size", n(4096)),
            ("data_fmt", t("jpg")),
        ],
    );
    // moment / moment_feed / moment_interaction / sns_notify
    ins(
        &conn,
        "moment",
        &[
            ("account_id_sha", t("a")),
            ("source", t("sns")),
            ("source_native_id", t("mo1")),
            ("account_id", t("acc")),
            ("tid", n(1)),
            ("author", t("wxid_alice")),
            ("author_nickname", t("小爱")),
            ("create_time", n(1_700_000_200)),
            ("moment_type", n(1)),
            ("content_desc", t("今天天气不错")),
            ("media_count", n(2)),
            ("like_count", n(5)),
            ("comment_count", n(3)),
        ],
    );
    ins(
        &conn,
        "moment_feed",
        &[
            ("account_id_sha", t("a")),
            ("source", t("sns")),
            ("source_native_id", t("mf1")),
            ("account_id", t("acc")),
            ("tid", n(2)),
            ("author", t("wxid_bob")),
            ("create_time", n(1_700_000_300)),
            ("is_read", n(1)),
        ],
    );
    ins(
        &conn,
        "moment_interaction",
        &[
            ("account_id_sha", t("a")),
            ("source", t("sns")),
            ("source_native_id", t("mi1")),
            ("account_id", t("acc")),
            ("create_time", n(1_700_000_400)),
            ("kind", t("comment")),
            ("from_nickname", t("阿波")),
            ("from_user", t("wxid_bob")),
            ("content", t("好看")),
        ],
    );
    ins(
        &conn,
        "sns_notify",
        &[
            ("account_id_sha", t("a")),
            ("source", t("sns")),
            ("source_native_id", t("sn1")),
            ("account_id", t("acc")),
            ("create_time", n(1_700_000_500)),
            ("notify_type", t("like")),
            ("from_user", t("wxid_bob")),
            ("from_nickname", t("阿波")),
            ("content", t("赞了你")),
        ],
    );
    // finder_visit
    ins(
        &conn,
        "finder_visit",
        &[
            ("account_id_sha", t("a")),
            ("source", t("general")),
            ("source_native_id", t("fv1")),
            ("account_id", t("acc")),
            ("owner_username", t("wxid_creator")),
            ("visit_time", n(1_700_000_600)),
            ("name", t("一造物社DIY")),
            ("profile_url", t("https://channels.weixin.qq.com/x")),
        ],
    );
    // friend_verify
    ins(
        &conn,
        "friend_verify",
        &[
            ("account_id_sha", t("a")),
            ("source", t("fmsg")),
            ("source_native_id", t("fr1")),
            ("account_id", t("acc")),
            ("user_name", t("wxid_newfriend")),
            ("friend_type", n(2)),
            ("timestamp", n(1_700_000_700)),
            ("is_sender", n(0)),
            ("scene", n(17)),
            ("content", t("你好加个好友")),
        ],
    );
    // custom_emoticon
    ins(
        &conn,
        "custom_emoticon",
        &[
            ("account_id_sha", t("a")),
            ("source", t("emoticon")),
            ("source_native_id", t("em1")),
            ("account_id", t("acc")),
            ("caption", t("笑哭")),
            ("md5", t("emomd5")),
            ("emoticon_type", n(1)),
            ("product_id", t("prod1")),
            ("cdn_url", t("http://cdn/emo")),
        ],
    );
    // bizchat_user
    ins(
        &conn,
        "bizchat_user",
        &[
            ("account_id_sha", t("a")),
            ("source", t("bizchat")),
            ("source_native_id", t("bz1")),
            ("account_id", t("acc")),
            ("user_name", t("brand_kefu")),
            ("user_id", t("uid_1")),
            ("brand_user_name", t("某品牌")),
        ],
    );
    // avatar_image
    ins(
        &conn,
        "avatar_image",
        &[
            ("account_id_sha", t("a")),
            ("source", t("contact")),
            ("source_native_id", t("av1")),
            ("account_id", t("acc")),
            ("username", t("wxid_alice")),
            ("md5", t("avmd5")),
            ("update_time", n(1_700_000_800)),
        ],
    );
    // chatroom_member_event (group-events)
    ins(
        &conn,
        "chatroom_member_event",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("cme1")),
            ("account_id", t("acc")),
            ("event_time", n(1_700_000_900)),
            ("conv_id", t("g@chatroom")),
            ("event_kind", t("join")),
            ("member_nickname", t("新人")),
            ("member_wxid", t("wxid_newbie")),
        ],
    );
    // message_forward_item (resolve)
    for (seq, dtype, title, desc) in [(0i64, "1", "标题A", "内容A"), (1, "2", "标题B", "图片B")] {
        ins(
            &conn,
            "message_forward_item",
            &[
                ("account_id_sha", t("a")),
                ("source", t("msg")),
                ("source_native_id", t("fwd1")),
                ("account_id", t("acc")),
                ("seq", n(seq)),
                ("data_type", t(dtype)),
                ("data_size", n(10)),
                ("source_name", t("张三")),
                ("data_title", t(title)),
                ("data_desc", t(desc)),
            ],
        );
    }
    // raw_payload_archive (msgraw)
    ins(
        &conn,
        "raw_payload_archive",
        &[
            ("account_id_sha", t("a")),
            ("source", t("msg")),
            ("source_native_id", t("Msg_1:1")),
            ("event_type", t("message")),
            ("event_action", t("create")),
            ("event_seq", n(0)),
            ("ingest_time", n(111)),
            ("payload_json", t(r#"{"conv_id":"chatA","msg_type":1}"#)),
        ],
    );
}

// ---------- golden 比对 ----------

/// 易变字段规整: `meta.account` / `meta.next_cursor` (皆路径相关) 换占位串, 令 golden 跨机可复现。
fn normalize(v: &mut serde_json::Value) {
    if let Some(meta) = v.get_mut("meta").and_then(|m| m.as_object_mut()) {
        if meta.contains_key("account") {
            meta.insert("account".to_string(), serde_json::json!("<ACCOUNT>"));
        }
        if meta.contains_key("next_cursor") {
            meta.insert("next_cursor".to_string(), serde_json::json!("<CURSOR>"));
        }
    }
    // ⚠️ 时间戳同 `normalize_table` 那条: 产品有意用 SQLite `localtime` 出时间, golden 会跟着
    // 生成机器的时区走。**json 这侧也得归一** —— 第一版我只改了 table 那个函数, 而
    // followups.json / new.json 里同样躺着 `1970-01-01 08:00:01` 这种本地时间, CI 照样红。
    // 又是"只改了被点名那处"。这里递归扫所有字符串值。
    normalize_ts_in_place(v);
}

/// 时区相关的日期时间形态 —— **两种都要盖**:
/// - `YYYY-MM-DD HH:MM:SS`(`datetime(...,'localtime')`)→ `<TS>`
/// - `YYYY-MM-DD`(`date(...,'localtime')`, 如 dormant 的 `last_message_day`)→ `<DATE>`
///
/// ⚠️ **只写第一种会漏**: 我第一版正则要求带时分秒, 跑反例(`TZ=UTC`)当场红 ——
/// `last_message_day` 东八区是 `2023-11-15`、UTC 是 `2023-11-14`, **跨时区差一天**,
/// 而它压根没有时分秒。判据又是"只写了我眼前那一种写法"。
/// 先换长的再换短的, 否则短的会把长的前半截先吃掉。
fn ts_regexes() -> (regex::Regex, regex::Regex) {
    (
        regex::Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").expect("常量正则"),
        regex::Regex::new(r"\d{4}-\d{2}-\d{2}").expect("常量正则"),
    )
}

/// 递归把 JSON 里所有字符串值中的日期时间换成占位。
fn normalize_ts_in_place(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            let (long, short) = ts_regexes();
            let t = long.replace_all(s, "<TS>").into_owned();
            let t = short.replace_all(&t, "<DATE>").into_owned();
            if &t != s {
                *s = t;
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(normalize_ts_in_place),
        serde_json::Value::Object(o) => o.values_mut().for_each(normalize_ts_in_place),
        _ => {}
    }
}

fn goldens_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("goldens")
}

/// 跑一条命令, 返 (规整后的 JSON, 原始 stdout)。非零退出直接 panic 带 stderr。
fn run_cmd(l1_db: &str, args: &[&str]) -> serde_json::Value {
    let mut full: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    full.push("--l1-db".to_string());
    full.push(l1_db.to_string());
    full.push("--format".to_string());
    full.push("json".to_string());
    let out = Command::new(env!("CARGO_BIN_EXE_msgvestige"))
        .args(&full)
        .output()
        .unwrap_or_else(|e| panic!("起子进程失败 ({args:?}): {e}"));
    assert!(
        out.status.success(),
        "命令 {args:?} 非零退出 ({}):\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout 非 UTF-8");
    let mut v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("命令 {args:?} stdout 非合法 JSON: {e}\n--- stdout ---\n{stdout}"));
    normalize(&mut v);
    v
}

/// table 文本易变字段规整: fixture L1 路径 (进程/纳秒后缀, 跨运行变) → 占位; CRLF → LF
/// (autocrlf=true 下 golden 若被签出成 CRLF, 逐字节比不受影响)。cursor/account 在 table 模式走
/// **stderr** (`eprintln!` 表头 / `下一页: --cursor`), stdout 只有数据行 → 无游标/账号泄漏。
///
/// ⚠️ **时间戳要归一, 否则这个 golden 跟着跑机的时区走**(首次上 GitHub、CI 第一次真跑逮到):
/// 产品**有意**用 SQLite 的 `localtime` 出时间(见 `live_query.rs` 那句"必须用 SQLite 算, 不能用
/// Rust" —— 给用户看本地时间是对的, 冷热两路也靠它对齐口径)。于是同一份 fixture 在东八区跑出
/// `[1970-01-01 08:00:01]`, 在 UTC 的 CI 上跑出 `[1970-01-01 00:00:01]` —— golden 是在我机器上
/// 生成的, CI 必红, 而本地永远发现不了。
///
/// **不改产品**(时区相关是它该有的行为), 改这里: 这个 golden 守的是**信封漂移**(有哪些列、
/// 顺序、格式), 不是时间戳数值。把 `YYYY-MM-DD HH:MM:SS` 整体换成占位 —— 日期时间的**形状**
/// 照样守得住(少一列、格式变了仍然会红), 只是不再钉死在某个时区。
///
/// 也考虑过在 CI 里设 `TZ=Asia/Shanghai`: 不行 —— Windows 上 SQLite 的 `localtime` 读的是
/// 操作系统时区, 不认 `TZ` 环境变量, 那样 Linux 绿了 Windows 照样红。
fn normalize_table(s: &str, l1_db: &str) -> String {
    let s = s.replace("\r\n", "\n").replace(l1_db, "<L1DB>");
    // 两种形态都要盖 (见 `ts_regexes` 上的说明: 只带日期的字段跨时区会差一天)。
    let (long, short) = ts_regexes();
    let t = long.replace_all(&s, "<TS>").into_owned();
    short.replace_all(&t, "<DATE>").into_owned()
}

/// 跑一条命令的 `--format table`, 返规整后的 **stdout** 文本 (数据行; 表头/游标提示在 stderr, 不入 golden)。
/// 非零退出直接 panic 带 stderr。Part A: 在抽核前锁住 table 基线 → 抽核后逐字节比 = 零漂移证据。
fn run_cmd_table(l1_db: &str, args: &[&str]) -> String {
    let mut full: Vec<String> = args.iter().map(|&s| s.to_string()).collect();
    full.push("--l1-db".to_string());
    full.push(l1_db.to_string());
    full.push("--format".to_string());
    full.push("table".to_string());
    let out = Command::new(env!("CARGO_BIN_EXE_msgvestige"))
        .args(&full)
        .output()
        .unwrap_or_else(|e| panic!("起子进程失败 ({args:?} --format table): {e}"));
    assert!(
        out.status.success(),
        "命令 {args:?} --format table 非零退出 ({}):\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("table stdout 非 UTF-8");
    normalize_table(&stdout, l1_db)
}

#[test]
fn golden_json_envelopes() {
    // 唯一 fixture 路径 (纳秒后缀; 路径不入 JSON 出口, 仅为避免 `new` 水位文件跨运行串味)。
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("native_cli_golden_{}_{stamp}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let l1 = dir.join("fixture_l1.db");
    build_fixture(&l1);
    let l1s = l1.to_str().unwrap();

    // (golden 名, 参数)。全部隐式追加 --l1-db <fixture> --format json。
    let cases: &[(&str, &[&str])] = &[
        ("contacts", &["contacts"]),
        ("members", &["members", "g@chatroom"]),
        ("favorites", &["favorites"]),
        ("favorites_tags", &["favorites", "--tags"]),
        ("favorites_media", &["favorites", "--media"]),
        ("moments", &["moments"]),
        ("moments_interactions", &["moments", "--interactions"]),
        ("moments_feed", &["moments", "--feed"]),
        ("moments_inbox", &["moments", "--inbox"]),
        ("account", &["account"]),
        ("calls", &["calls"]),
        ("locations", &["locations"]),
        ("cards", &["cards"]),
        ("media", &["media"]),
        ("group_events", &["group-events"]),
        ("emoticons", &["emoticons"]),
        ("avatars", &["avatars"]),
        ("biz_contacts", &["biz-contacts"]),
        ("chatrooms", &["chatrooms"]),
        ("friend_requests", &["friend-requests"]),
        ("mentions", &["mentions"]),
        ("money", &["money"]),
        ("money_claims", &["money", "--claims"]),
        ("money_payers", &["money", "--payers"]),
        ("stats", &["stats", "--by", "sender"]),
        ("dormant", &["dormant"]),
        ("inspect_contact", &["inspect", "contact", "wxid_alice"]),
        ("inspect_chatroom", &["inspect", "chatroom", "g@chatroom"]),
        ("inspect_session", &["inspect", "session", "wxid_alice"]),
        ("inspect_message", &["inspect", "message", "m1"]),
        ("links", &["links"]),
        ("files", &["files"]),
        ("pii_scan", &["pii-scan"]),
        ("thread", &["thread"]),
        ("finder", &["finder"]),
        ("biz", &["biz"]),
        ("msgraw", &["msgraw"]),
        ("events", &["events"]),
        (
            "exec",
            &[
                "exec",
                "SELECT conv_id, count(*) AS n FROM message GROUP BY conv_id ORDER BY conv_id",
            ],
        ),
        ("extract_url", &["extract", "--kind", "url"]),
        ("new", &["new", "--no-advance"]),
        ("followups", &["followups"]),
        ("resolve_list", &["resolve"]),
        ("resolve_expand", &["resolve", "--msg-id", "fwd1"]),
    ];

    let update = std::env::var("UPDATE_GOLDENS").is_ok();
    let gdir = goldens_dir();
    if update {
        std::fs::create_dir_all(&gdir).unwrap();
    }

    let mut failures: Vec<String> = Vec::new();

    // search 特例: 先建 FTS 索引, 再搜 (query 出口进 golden)。
    {
        let build = Command::new(env!("CARGO_BIN_EXE_msgvestige"))
            .args(["search", "--build", "--l1-db", l1s, "--format", "json"])
            .output()
            .expect("search --build 起子进程失败");
        assert!(
            build.status.success(),
            "search --build 失败:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );
    }
    let all_cases: Vec<(&str, Vec<&str>)> = cases
        .iter()
        .map(|(name, a)| (*name, a.to_vec()))
        .chain(std::iter::once(("search", vec!["search", "--query", "example"])))
        .collect();

    for (name, args) in &all_cases {
        // ---- ① JSON 信封 golden (`<name>.json`; 解析后逐值比, 忽略空白) ----
        let got = run_cmd(l1s, args);
        let golden_path = gdir.join(format!("{name}.json"));
        if update {
            let pretty = serde_json::to_string_pretty(&got).unwrap();
            std::fs::write(&golden_path, format!("{pretty}\n")).unwrap();
        } else {
            match std::fs::read_to_string(&golden_path) {
                Ok(raw) => {
                    let want: serde_json::Value =
                        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("golden {golden_path:?} 非法 JSON: {e}"));
                    if want != got {
                        failures.push(format!(
                            "[{name}] JSON 信封漂移:\n--- 期望 (golden) ---\n{}\n--- 实得 ---\n{}",
                            serde_json::to_string_pretty(&want).unwrap(),
                            serde_json::to_string_pretty(&got).unwrap()
                        ));
                    }
                }
                Err(_) => failures.push(format!(
                    "[{name}] golden 缺失 {golden_path:?} — 先 UPDATE_GOLDENS=1 生成"
                )),
            }
        }

        // ---- ② table 输出 golden (`<name>.table.txt`; stdout 逐字节比) ----
        // Part A: 抽核**前**捕获现网 table 输出当基线; §6② 把 table 渲染搬进 native-query::render_table
        // (改读 json Value) 后, 本 golden 逐字节相等 = render_cell 适配零漂移的硬证据。
        let got_table = run_cmd_table(l1s, args);
        let table_path = gdir.join(format!("{name}.table.txt"));
        if update {
            std::fs::write(&table_path, &got_table).unwrap();
        } else {
            match std::fs::read_to_string(&table_path) {
                Ok(raw) => {
                    let want = raw.replace("\r\n", "\n");
                    if want != got_table {
                        failures.push(format!(
                            "[{name}] table 输出漂移:\n--- 期望 (golden) ---\n{want}\n--- 实得 ---\n{got_table}"
                        ));
                    }
                }
                Err(_) => failures.push(format!(
                    "[{name}] table golden 缺失 {table_path:?} — 先 UPDATE_GOLDENS=1 生成"
                )),
            }
        }
    }

    // 清理 fixture (golden 已落盘, 不留临时库)。
    let _ = std::fs::remove_dir_all(&dir);

    if update {
        eprintln!("已写 {} 个命令 × (json + table) golden 到 {gdir:?}", all_cases.len());
    }
    assert!(
        failures.is_empty(),
        "{} 个命令信封漂移:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
