//! 手写查询命令 (查询内核抽取 §6③) —— 非 clean 单表引擎档 (§6② `engine`) 的命令: 各自
//! JOIN / 过滤 / 标签, 不进 `REGISTRY`。每个 `<cmd>_query` **返 `QueryResult{data, meta}`**
//! (json 行**预组好** + `Meta` **组装好**), 呈现 (table 表头/逐列渲染) 留 msgvestige 皮 (§3)。
//!
//! §6③ **首批 (6 个 vanilla 命令)**: `calls` / `friend-requests` / `links` / `files` / `thread` /
//! `finder` —— 共同形: 单 `query_*` 取数 + 真 `COUNT(*)` 全量 + `Meta::page(本页, 真全量)+source=cold`
//! (旧 `print_query_json(&data, total)` 逐字节同)。无多表合并 / 无游标 / 无 `meta.summary` / 无
//! `limit+1` 探测。
//!
//! §6③ **第二批 (7 个简单命令)**: `mentions`(opt `-q` 过滤) / `biz` / `events`(opt `--sys-type` 过滤) /
//! `msgraw`(opt `--native-id`; NOT_FOUND 判定留皮) / `members`(带 `<chatroom>` 参 + total=loaded-all) /
//! `favorites`(opt `-q` 过滤, total=loaded-all) / `followups`(total=loaded-all) —— 同"单查取数 + 真
//! `COUNT`(或 total=全量载入行数) + `Meta::page`"。可选过滤 (`-q`/`--sys-type`/`--native-id`) 穿进
//! `<cmd>_query(..., filter)`; NOT_FOUND (msgraw 定向查无) + 参数解析留 CLI 皮。`sys_type_label` (events)
//! 随 json 预组 `label` 迁入; `msgraw` json `payload` 存**解析后**对象, table 皮从 json 值重建原串
//! (ingest 存 `payload_json` 走 `serde_json::to_string(Value)` 排序紧凑, 往返逐字节一致)。
//!
//! §6③ **第三批 (3 个 `limit+1` 探测命令)**: `moments`(bare moment 表; 无 `--interactions/--feed/--inbox`
//! 标志的档 —— 带标志的子视图走引擎 `CMD_*`, 不在此) / `new`(水位后增量, 升序) / `dormant`(每会话末条时间
//! 升序排行) —— 共同形: **fetch `limit+1` 探 `has_more` + truncate 到 limit + `Meta::cold_page`(省略
//! total_count, 不拿页大小充数)**。`limit+1`/truncate/has_more 逻辑**移进核** (核返组装好的 Meta, 呈现留皮)。
//! `new` 的**水位文件 I/O** (temp 读 + `--no-advance` 决定写不写) 留 msgvestige 皮; 核 `new_query(conn,
//! watermark, limit)` 只收 watermark 值、返 `QueryResult`, 皮从 `data` 末条 (升序 → create_time 最大) 取新水位。
//!
//! §6③ **第四批 (3 个 summary 命令)**: `stats`(`--by` 维度聚合排行) / `extract`(`--kind`
//! url/email/amount/phone/idcard 正则/手写扫描) / `pii-scan`(手机号/身份证扫描 + 打码) —— 共同形:
//! `limit+1`(stats)/截断(extract·pii-scan) 精确探 `has_more` + `Meta::cold_page().with_summary(...)` 把
//! 命令特有汇总收进 `meta.summary`(HOLE-3, 别铺 meta 顶层)。**has_more 探测 + summary 域对象都在核**
//! `<cmd>_query` 内组好 (核返满配 Meta), 皮只读 summary 渲表头 / 百分比。低层取数/扫描 (`query_stats` /
//! `query_pii_scan` / `query_extract`) + 纯函数助手 (`scan_pii_in_text` / `mask_pii` / `is_cn_mobile` /
//! `id_checksum_ok` / `extract_regex` / `extract_matches`) 一并迁入 (直测锁 SQL/扫描)。**pii-scan 打码放核**:
//! `pii_scan_query(.., reveal, ..)` 按 `reveal` 决定 json `value` 打码/显全 → MCP/HTTP 与 CLI 隐私行为一致
//! (非只 CLI 皮打码)。`--by`/`--kind` 枚举 (`StatsBy`/`PiiKind`/`ExtractKind`) 随命令迁入 (皮 flatten 复用)。
//!
//! §6③ **第五批 (2 个结构最硬的命令)**: `money`(三表合并时间线) / `contacts`(keyset 游标)。
//! `money` 的**默认档** (无 `--claims/--payers`; 那两子视图走引擎 `CMD_HONGBAO`/`CMD_GROUP_PAY_MEMBERS` 不在此)
//! 合并 `query_transfers`+`query_red_envelopes`+`query_group_pays` 三查 (各带自己的真 `COUNT`), `--kind`
//! 选源, 按时间倒序截 limit; **total_count = 被选源真 COUNT 之和** (与旧 `cmd_money` 累加 `total` 逐字节同,
//! 走 `Meta::page`)。三子查 + `MoneyRow` + `MoneyKind` 枚举 (皮 flatten 复用) 一并迁入; 各子查的
//! `context`+`needs_ingest_err`(缺表提示) 随查迁核。呈现 baked 串 (`"{payer} → {receiver}"` /
//! `"已付{paid}/{payers}人"` / `"(金额见消息) 状态码{sub}"`) 在子查内产出 → json 携出、table 读回, 原样不动。
//! `contacts` 走 [`crate::paginate`] keyset (username 唯一键 Asc/Text) → `Meta::cursor_page`(next_cursor+limit,
//! 省 total_count); `q` 子串过滤 + `filter_hash`(命令+q) + `acct` 位 (= `sha8(L1 路径)`, ③b 前占位, 未接真
//! account_id_sha) + `cursor` 穿透。**`InvalidCursor` (CliError) 原样上抛不加 context** —— 否则 classify
//! downcast 不到 → 误归 INTERNAL/70; 该 map_err 判别 (携码错直传, 通用错补 hint) 随查迁核, 退出码 2 不变。
//!
//! §6③ **specials (4 个特殊命令)**: `exec`(原生只读 SQL, 动态列) / `inspect`(类型消歧单行) /
//! `resolve`(合并转发双模式) / `search`(FTS5)。共同点: 各带自己的形状 (动态列 / 单行 / 双模式 / FTS),
//! 不套 vanilla 模板。**动态列 (exec/inspect) 的 table 呈现读有序低层, 非排序 json** —— `serde_json::Map`
//! 按键名排序丢 SQL/schema 列序, 故 exec 的 `run_exec_query`(有序 cols/行) 与 `exec_query`(json 出口) 并存
//! (table 皮走前者、json 皮走后者); inspect 的 `fetch_row`(有序列 Vec) 供 table 皮逐列渲染、`inspect_query`
//! collect 成排序 Map 供 json 皮。**exec 只读守卫 `is_readonly_sql` 留皮 pre-check** (须在 `open_l1` 前拒写:
//! 坏路径/写 SQL 不打库即 BAD_REQUEST/2; 移核只为直测 + 三皮复用, cmd_exec 仍在开库前调它)。NOT_FOUND
//! (inspect 查无 / resolve 展开查无) → `CliError{NotFound}` **携码原样上抛** (classify downcast 命中 → 退出3
//! 不漂 INTERNAL/70)。resolve 固定 json 键 → table 皮读 `r.data` by key(`type_label` 已 baked); `search`
//! 只 SEARCH 路移核 (`--build` 建 FTS 索引是**写**, 留皮), fetch limit+1 探 has_more + `Meta::cold_page`
//! (FTS 命中总数不额外算, 省 total_count); table 皮计时(`{}ms`)/预览截断留皮。值渲染助手
//! (`sql_value_display`/`json_value_display`) 迁核 (exec/inspect table 皮共用)。
//!
//! 热查 (sessions/messages) 留后续批 (async SourceQuery, 直查加密源库, 不在冷查内核范围)。
//!
//! **标签助手** (`call_kind` / `friend_scene_label` / `app_type_label`) 在 json 阶段预组 label 字段
//! (如 calls 的 `kind`、links 的 `type_label`); table 皮**读 json 里的 label**、不重算 → 移进核。
//! 纯 table 装饰 (`human_size` / `preview_line` 截断) 留 CLI 皮 (不进 json)。

// 手写查询的行元组就是数据库列的形状, 起别名反而多一层间接。
#![allow(clippy::type_complexity)]

use anyhow::{Context, Result};

// R9 复审 R2#4: 坏行 warn 后丢, 非静默; R4: collect_ok 非 offset 分页计丢弃; R5: collect_page 探针批精确 has_more+页内丢弃。
use crate::engine::{collect_ok, collect_page, ok_or_warn};
use crate::envelope::{Meta, QueryResult, Source};

// ── 冷查 offset 翻页稳定性: 排序次键 (R16) ───────────────────────────────────
// 单键 `ORDER BY <时间/计数> DESC` + `LIMIT/OFFSET` 翻页, 对**并列**行 (同排序键值) SQLite
// 不保证跨页稳定顺序 → 翻页可能**重复/漏行**。8+ 冷查端点经 native-http `clamp_offset(p.offset)`
// 让 offset 用户可控 → 可达。真库(msgcol-l1 77.6万消息)实测并列真实: message.create_time
// 776333 行 / 714093 不同值 → 62240 行(8%)与他行同秒; events(type10000) 8678/6800; links
// (message_app⋈message) 24331 行并列 464; files 1099 并列 600。
//
// 修法: 补**唯一次键**令全序确定 (照 friend_verify/message/session 先例)。次键选取:
// - **message 家族** (calls/links/files/thread/mentions/biz/events/followups/extract): 次键 =
//   **PK 尾 `(source, source_native_id)`**。**非**单 `source_native_id` —— message 表**分片**
//   (source = `message_N.db`, 单账号内即多值), 单个 PK 成员本身不唯一 (friend_verify 注辨此假
//   不变量); account_id_sha 由遮蔽视图 (`open_l1_scoped` WHERE account_id_sha=?) 钉成常量, PK
//   尾两列即够唯一。message **无 create_time 索引** → 这些查询本就走全表 temp-b-tree 排序 (EXPLAIN
//   证), 加两列**零计划退化**。**mentions 再加 `mentioned_wxid`**: message_mention 对 message 是
//   **1:N** (一条@多人 → 多行同 source_native_id, 真库一消息@20人), (create_time,source_native_id)
//   仍并列 131 行, 必须带 mention 分量才 0 并列 (真库实测)。
// - **moment**: 同用 PK 尾 `(source, source_native_id)`。moment 与 message 同 PK 结构, 只是
//   moment **有** `idx_moment_create_time(account_id_sha, create_time DESC)` 索引 → 填数据后 EXPLAIN 实测
//   加 PK 尾仍**保住该索引**(SEARCH ... USING idx_moment_create_time + 仅 LAST-2-TERMS 局部排序, 非全表排),
//   代价可忽略。(注: 空表 EXPLAIN 会误报'弃索引全排' —— 无统计的假象, 填数据即消失。)
// - **dormant/stats** (GROUP BY): 次键 = 分组键本身 (conv_id / label) —— 每组一行, 分组键在结果集
//   内必唯一 → 全序确定。ORDER BY max(create_time)/count(*) 的并列组靠它定序。
//
// **诚实标注**: golden 夹具/小库多为"顺路数据"(排序键各不同), 大概率复现不出真实重/漏 (SQLite 计划
// 确定); 依据是**次键唯一 → 翻页确定**这条原则 + 上述真库并列实测, 非夹具复现。
// members(群内 member_wxid 真库唯一 67662=67662)/msgraw(id 是 PK/rowid)/finder/favorites(R16 已补)
// 无需在此改。
// **同类覆盖面** (双审逮出): (1) money(三表合并时间线, 单键 + offset 经 /money 可达) —— **R16-4 已修**:
//   三源 SQL 都补 PK 尾 `(source, source_native_id) DESC` (= PK 去遮蔽钉死的 account_id_sha, 按 PK 约束唯一;
//   红包**原 `ORDER BY r.rowid DESC` 一并改**用 PK 尾 —— rowid 在 scoped 遮蔽视图上是 no such column, 原查 scoped
//   下即炸, 顺修); 且**合并步**不止 SQL —— 三源在内存按时间归并, 而元组原不带 PK → `MoneyRow` 增 `MoneyKey`=
//   (source,source_native_id) 次键, `money_query` 按 (时间 DESC, 次键 DESC) 定全序再切片。snid 带类型前缀
//   (`Transfer_`/`GroupPay_`/`RedEnvelope_`) 跨源全局唯一 → 跨源同秒并列也全序确定 (红包 time=None 恒末尾)。
//   (2) engine.rs REGISTRY 的 CMD_* 经 run_query_with_deadline 统一拼 `ORDER BY {order_by} LIMIT/OFFSET` 亦不加
//   次键, ~15 条单键 offset 冷查同型 (尤 member_count DESC) —— **仍待专件** (超本文件 scope)。

// ── calls (message_call ⋈ message) ──

/// calls 查询行: (create_time, conv_id, invite_type, duration_sec, display_content)。
type CallRow = (i64, String, i64, i64, String);

/// invite_type → 人话 (-1 气泡通知 / 0 视频 / 1 语音; 其它原样兜底)。json 里预组进 `kind` 字段。
#[must_use]
pub fn call_kind(invite_type: i64) -> &'static str {
    match invite_type {
        -1 => "气泡",
        0 => "视频",
        1 => "语音",
        _ => "通话",
    }
}

/// 查 L1 通话记录 (message_call ⋈ message 借 message 的时间/会话; 按时间倒序取前 limit)。
/// 返 `QueryResult`(json 行 + `Meta::page`(本页, 真 `COUNT`) + source=cold)。真总数用独立 `COUNT`
/// (非截断后的 rows.len(): 显示"N 条 (取前 limit)"要诚实, 别拿 limit 当总数 —— 双审逮出)。
pub fn calls_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let map = |row: &rusqlite::Row| -> rusqlite::Result<CallRow> {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
    };
    let join = "FROM message_call mc JOIN message m \
                ON mc.account_id_sha = m.account_id_sha AND mc.source = m.source \
                   AND mc.source_native_id = m.source_native_id";
    let total: i64 = conn.query_row(&format!("SELECT count(*) {join}"), [], |r| r.get(0))?;
    let mut st = conn.prepare(&format!(
        "SELECT m.create_time, m.conv_id, mc.invite_type, mc.duration, mc.display_content \
         {join} ORDER BY m.create_time DESC, m.source DESC, m.source_native_id DESC LIMIT ?1 OFFSET ?2"
    ))?;
    let rows: Vec<CallRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], map)?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, cv, it, d, r)| {
            serde_json::json!({"create_time": ct, "conv_id": cv, "kind": call_kind(*it), "invite_type": it, "duration_sec": d, "result": r})
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── account (账号自述) ──

/// `account` — 当前账号信息 (读 L1 各表行数统计; 只读)。账号 id 是用户自己的, 合理出口。
/// data = **单汇总行** (§2 golden 要 data 是数组 → `[row]`); `Meta::page(1,1)` + source=cold。
/// 表不存在 (空库) → 该表计 0 (不报错); account_id 取不到 → json `null`。
pub fn account_query(conn: &rusqlite::Connection) -> Result<QueryResult> {
    let account_id: Option<String> = conn
        .query_row("SELECT account_id FROM person LIMIT 1", [], |r| r.get(0))
        .ok();
    let count = |t: &str| -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
            .unwrap_or(0)
    };
    let (persons, rooms, msgs, moments, favs) = (
        count("person"),
        count("chatroom"),
        count("message"),
        count("moment"),
        count("favorite"),
    );
    let row = serde_json::json!({
        "account_id": account_id,
        "persons": persons,
        "chatrooms": rooms,
        "messages": msgs,
        "moments": moments,
        "favorites": favs,
    });
    Ok(QueryResult {
        data: vec![row],
        meta: Meta::page(1, 1).with_source(Source::Cold),
    })
}

/// 列库里可命名的账号 wxid (`person.account_id` distinct, **无上限** —— 区别于 [`crate::account_candidates`] 的
/// `LIMIT 8` 歧义候选; `/accounts` 端点据此让消费者选 `?account=`)。**不 scoped** (要看全部账号)。sha-only 账号
/// (person 无明文行, 如纯消息库) 列不出 —— 同 candidates 的"可能不全", 消费者遇空回退用 sha8 或先 ingest 联系人。
pub fn accounts_query(conn: &rusqlite::Connection) -> Result<QueryResult> {
    let mut st = conn
        .prepare("SELECT DISTINCT account_id FROM person WHERE account_id IS NOT NULL ORDER BY account_id")
        .context("查账号列表失败 (库是 L1?)")?;
    // R4 复审R3#5: collect_ok 显式计丢弃行 (page(n,n) 无独立 COUNT, offset 算术测不出) → .with_dropped 进 meta。
    let (rows, dropped) = collect_ok(
        st.query_map([], |r| Ok(serde_json::json!({ "account_id": r.get::<_, String>(0)? })))
            .context("查账号列表失败")?,
    );
    let n = rows.len();
    Ok(QueryResult {
        data: rows,
        meta: Meta::page(n, n).with_source(Source::Cold).with_dropped(dropped),
    })
}

/// R19 选择性采集清单查询 (三皮 list 共享: HTTP `GET /capture` 走 envelope)。一站式**解析账号 + 读清单** →
/// `QueryResult` (conv_id/added_at/note, 按 added_at 升序; 复用 `native_core::capture::list_capture_targets`)。
///
/// - **空库无账号 → 空清单** (采集清单必空 = 全采, 语义 D1); 单账号库自动解析真实 sha; 多账号未指定 → `Err(AccountAmbiguous)`。
/// - 调用方 (HTTP) 只需 `capture_targets_query(l1, account).map(envelope)`, 不碰 Meta/Source/账号解析。
///
/// # Errors
/// 多账号未指定 (`AccountAmbiguous`) / L1 打不开 / 读 `capture_targets` 失败 (库非 L1 / 损坏)。
pub fn capture_targets_query(l1_db: &str, account: Option<String>) -> Result<QueryResult> {
    // 审 round-11/12 P2 (codex+Claude 收敛): **resolve 前无条件**坐实是 L1 —— 显式账号分支 resolve 对无关 sqlite 返
    // Some(sha) 短路, 若只在 None 分支查则**显式账号 Some 分支绕过** → 非 L1 误报"有效空 L1 全采" + 三皮不一致 (round-11 的
    // None-only 修不完整)。提到两分支之前, Some/None 全覆盖。共享助手 ensure_l1_marker (CLI capture list 同款)。真空
    // **已初始化** L1 (有 raw_payload_archive 无账号) 仍会走到下方 None 分支返空清单 (=全采), 只拦非 L1/无关 sqlite。
    let probe = crate::engine::open_l1(l1_db)?;
    crate::engine::ensure_l1_marker(&probe)?;
    drop(probe);
    let Some(sha) = crate::engine::resolve_capture_account_sha(l1_db, account)? else {
        return Ok(QueryResult {
            data: vec![],
            meta: Meta::page(0, 0).with_source(Source::Cold),
        });
    };
    let conn = crate::engine::open_l1(l1_db)?;
    let list = native_core::capture::list_capture_targets(&conn, &sha).context("读 capture_targets 失败 (库是 L1?)")?;
    let rows: Vec<serde_json::Value> = list
        .into_iter()
        .map(|t| serde_json::json!({ "conv_id": t.conv_id, "added_at": t.added_at, "note": t.note }))
        .collect();
    let n = rows.len();
    // 审 round-7 P2: 填 meta.account = sha8 —— 与 run_query (engine.rs `meta.account = Some(sha[..8])`) 及其它 scoped
    // 冷端点一致。空清单时客户端也能知道这是**哪个账号**的清单 (多账号库指定 account 后尤其需要; sha 已 64 hex, resolve
    // 出的账号必真实)。三皮 (CLI/MCP list + HTTP /capture) 输出对齐。
    let mut meta = Meta::page(n, n).with_source(Source::Cold);
    // sha 恒 64 hex (resolve_capture_account_sha 产), `.get(..8)` 防御式 (与 CLI capture list 同款, 免理论越界 panic)。
    meta.account = Some(sha.get(..8).unwrap_or(&sha).to_string());
    Ok(QueryResult { data: rows, meta })
}

// ── resolve-names (wxid → 显示名; 内核 §5b) ──

/// 批量 wxid → 显示名 (昵称/备注/alias)。给 LLM/前端把满屏 wxid 换成人能认的名字 (内核 §5b)。
/// 查 person 表 (username=wxid); 空输入 → 空结果。**账号隔离**由调用方 scoped conn 兜 (person 视图已过滤)。
pub fn resolve_names_query(conn: &rusqlite::Connection, wxids: &[&str]) -> Result<QueryResult> {
    if wxids.is_empty() {
        return Ok(QueryResult {
            data: vec![],
            meta: Meta::page(0, 0).with_source(Source::Cold),
        });
    }
    let placeholders = vec!["?"; wxids.len()].join(",");
    // Claude + codex R16-6 P3: 加 `ORDER BY username, source` —— 冷本无序(SQLite btree/rowid 序, VACUUM 会变), 与热
    // (username, _src) 序对不上且冷自身不稳。补 `source`(person PK 成员, NOT NULL)当次键破同 username 两行(contact+
    // stranger)的并列 —— 与热 `_src`(contact 前 stranger 后, contact.db < contact.db|stranger)同向, 冷热 data[] 逐行对齐 +
    // last-write-wins map 结果确定。
    let sql = format!(
        "SELECT username, nick_name, remark, alias FROM person WHERE username IN ({placeholders}) ORDER BY username, source"
    );
    let mut st = conn.prepare(&sql).context("查 person 名字失败 (库是 L1?)")?;
    // R4 复审R3#5: collect_ok 显式计丢弃 (page(n,n) 无独立 COUNT) → .with_dropped。
    let (rows, dropped) = collect_ok(
        st.query_map(rusqlite::params_from_iter(wxids.iter().copied()), |r| {
            Ok(serde_json::json!({
                "wxid": r.get::<_, String>(0)?,
                "nick_name": r.get::<_, Option<String>>(1)?,
                "remark": r.get::<_, Option<String>>(2)?,
                "alias": r.get::<_, Option<String>>(3)?,
            }))
        })
        .context("查 person 名字失败")?,
    );
    let n = rows.len();
    Ok(QueryResult {
        data: rows,
        meta: Meta::page(n, n).with_source(Source::Cold).with_dropped(dropped),
    })
}

// ── friend-requests (friend_verify) ──

/// friend-requests 查询行: (timestamp, user_name, friend_type, is_sender, scene, content)。
type FriendReqRow = (i64, String, i64, i64, i64, String);

/// scene(加好友来源场景码) → 人话; 仅映射确认过的 17=名片 (其余场景码语义未定, 原样报数, 不瞎标)。
/// json 里预组进 `scene_label` 字段。
#[must_use]
pub fn friend_scene_label(scene: i64) -> String {
    match scene {
        17 => "名片添加".to_string(),
        n => format!("场景{n}"),
    }
}

/// 查 L1 friend_verify 表 (好友验证/申请; 按时间倒序取前 limit)。返 `QueryResult`(json + `Meta::page`)。
pub fn friend_requests_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let map = |row: &rusqlite::Row| -> rusqlite::Result<FriendReqRow> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    };
    let total: i64 = conn.query_row("SELECT count(*) FROM friend_verify", [], |r| r.get(0))?;
    // 次键 user_name: timestamp 真库**有并列** —— 实测 7967 行 / 7961 个不同 timestamp → 6 行与他人
    // 并列, 最大并列组 3 行 (同秒多条申请)。单键 + OFFSET 翻页时 SQLite 对并列行不保证稳定顺序 → 可能
    // 重复/漏。
    //
    // **为什么是 user_name, 不是 source_native_id**(轮4 审纠了我两处):
    // - **P3-a**: 我原先写"次键 source_native_id(**PK 成员, 必唯一**)" —— 那是**假不变量**。PK 是复合的
    //   `(account_id_sha, source, source_native_id)`, **复合 PK 的单个成员本身不唯一**。这里侥幸成立只
    //   因为两个巧合: `source` 是硬编码字面量 "general.db", `account_id_sha` 被 open_l1_resolved 的
    //   fail-closed 收成常量。同一套 schema 里就有反例: `message` 表 PK 同形状, 而它的 source 是分片文件名
    //   → 那里 source_native_id **不唯一**。(我刚修完 P3-4 的假不变量, 转头又写一个。)
    // - **P3-c**: 冷用 source_native_id / 热用 rowid = **两边不是同一个键** → 并列行的顺序对不上。
    //   通用对拍脚本真库实测复现: 第 1166 行 热=(1767079812, wxid_8wny…) 冷=(1767079812, wxid_gytp…)。
    //   改用 user_name 后冷热同键(热查那边 `user_name_` 列直接就有) → 顺序一致。
    //
    // **唯一性不是这里的必需条件**: 次键只求"冷热同键 → 顺序确定且一致"。user_name 真库实测唯一
    // (7967 行 / 7967 个不同 user_name), 但即便将来同一人多次申请, 冷热仍按同一个键排、顺序仍一致。
    let mut st = conn.prepare(
        "SELECT timestamp, user_name, friend_type, is_sender, scene, content \
         FROM friend_verify ORDER BY timestamp DESC, user_name DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<FriendReqRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], map)?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ts, w, ft, is_s, sc, c)| {
            serde_json::json!({"timestamp": ts, "user_name": w, "friend_type": ft, "is_sender": is_s, "scene": sc, "scene_label": friend_scene_label(*sc), "greeting": c})
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── links (message_app 带 url ⋈ message) ──

/// links 一行: (create_time, conv_id, title, url, app_type)。
type LinkRow = (i64, String, Option<String>, String, i64);

/// message_app app_type 码 → 人话 (仅映射 schema 确认的 5/33/51, 其余原样报数)。json 里预组进 `type_label`。
#[must_use]
pub fn app_type_label(t: i64) -> String {
    match t {
        5 => "链接".to_string(),
        33 => "小程序".to_string(),
        51 => "视频号".to_string(),
        other => format!("类型{other}"),
    }
}

/// 查分享的链接/卡片 (message_app 带 url 的 ⋈ message 取时间/会话; 直接 PK JOIN)。返 `QueryResult`。
/// total 须与数据查询同 JOIN (契约审 #4: orphan 行否则多报 total_count)。
pub fn links_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM message_app a JOIN message m \
           ON a.account_id_sha = m.account_id_sha AND a.source = m.source \
              AND a.source_native_id = m.source_native_id \
         WHERE a.url IS NOT NULL AND a.url != ''",
        [],
        |r| r.get(0),
    )?;
    let mut st = conn.prepare(
        "SELECT m.create_time, m.conv_id, a.title, a.url, a.app_type \
         FROM message_app a JOIN message m \
           ON a.account_id_sha = m.account_id_sha AND a.source = m.source \
              AND a.source_native_id = m.source_native_id \
         WHERE a.url IS NOT NULL AND a.url != '' \
         ORDER BY m.create_time DESC, m.source DESC, m.source_native_id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<LinkRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, cv, ti, u, at)| {
            serde_json::json!({"create_time": ct, "conv_id": cv, "title": ti, "url": u, "app_type": at, "type_label": app_type_label(*at)})
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── files (message_app 带 file_ext ⋈ message) ──

/// files 一行: (create_time, conv_id, 文件名, 后缀, 字节数)。
type FileRow = (i64, String, Option<String>, Option<String>, i64);

/// 查文件消息 (message_app 有 file_ext 的 ⋈ message 取时间/会话; 直接 PK JOIN)。返 `QueryResult`。
/// total 须与数据查询同 JOIN (契约审 #4: 不 JOIN 则 message_app orphan 行让 total_count 多报)。
pub fn files_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM message_app a JOIN message m \
           ON a.account_id_sha = m.account_id_sha AND a.source = m.source \
              AND a.source_native_id = m.source_native_id \
         WHERE a.file_ext IS NOT NULL AND a.file_ext != ''",
        [],
        |r| r.get(0),
    )?;
    let mut st = conn.prepare(
        "SELECT m.create_time, m.conv_id, a.title, a.file_ext, a.file_size \
         FROM message_app a JOIN message m \
           ON a.account_id_sha = m.account_id_sha AND a.source = m.source \
              AND a.source_native_id = m.source_native_id \
         WHERE a.file_ext IS NOT NULL AND a.file_ext != '' \
         ORDER BY m.create_time DESC, m.source DESC, m.source_native_id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<FileRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, cv, n, e, s)| {
            serde_json::json!({"create_time": ct, "conv_id": cv, "file_name": n, "file_ext": e, "file_size": s})
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── thread (message_app 带 refer_svrid ⋈ message) ──

/// thread 一行: (reply 时间, conv_id, reply 发送人, reply 正文, 被引类型, 被引原文)。
type ThreadRow = (i64, String, Option<String>, Option<String>, i64, Option<String>);

/// 查引用回复 (message_app 带 refer_svrid 的 ⋈ message 取 reply 侧时间/会话/发送人; 直接 PK JOIN)。
/// reply 正文在 a.title (回复者写的), 被引原文在 a.refer_content (已内联)。返 `QueryResult`。
/// total 须与数据查询同 JOIN (契约审 #4: orphan 行否则多报 total_count)。
pub fn thread_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM message_app a JOIN message m \
           ON a.account_id_sha = m.account_id_sha AND a.source = m.source \
              AND a.source_native_id = m.source_native_id \
         WHERE a.refer_svrid IS NOT NULL AND a.refer_svrid != ''",
        [],
        |r| r.get(0),
    )?;
    let mut st = conn.prepare(
        "SELECT reply.create_time, reply.conv_id, reply.sender_wxid, a.title, a.refer_type, a.refer_content \
         FROM message_app a JOIN message reply \
           ON a.account_id_sha = reply.account_id_sha AND a.source = reply.source \
              AND a.source_native_id = reply.source_native_id \
         WHERE a.refer_svrid IS NOT NULL AND a.refer_svrid != '' \
         ORDER BY reply.create_time DESC, reply.source DESC, reply.source_native_id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<ThreadRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, cv, s, title, rtype, refer)| {
            serde_json::json!({
                "create_time": ct, "conv_id": cv, "sender_wxid": s,
                "reply_text": title, "refer_type": rtype, "quoted_text": refer
            })
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── R6: 冷查 messages / sessions (--mode=cold 用; 字段集对齐热查 hot.rs 的 msg_json / session_json) ──

/// **冷查会话消息** (R6 `--mode=cold`): 读 L1 `message` 表 (投影后明文列) 某会话 `chat` 的最近消息, 字段集与热查
/// [`crate::hot_messages`] 的 `msg_json` **对齐** (**22 键**, R16-0 加 conv_id) —— 让 `--mode` 切冷/热对消费者
/// 透明 (同会话冷热同形)。**键集一致由 `cold_messages_json_keys_match_hot` 双边对拍守卫**, 别只改一边。
/// `chat` 明文 (对方 wxid / 群 id) → `sha256_hex` 匹配 `conv_id_sha` 列 (吃 `idx_message_conv_time` 索引)。
/// **排序**: `create_time DESC, source_native_id DESC` —— L1 无热查用的 `local_id` 列, 主键只能用 `create_time`
/// (热查 `latest_messages` 是 `local_id` 倒序, 同一时刻多条时冷热组内序可能微差, 属 L1 固有信息缺失)；`source_native_id`
/// (PK 分量, 单 source L1 下每行唯一) 作**次键**保 `offset` 翻页**不重复/不漏**行 (create_time 真库有并列值, 单键会漏消息)。
/// `create_time` 已是**毫秒** (L1 ingest 存毫秒, 同热查 R6 归一)。**账号隔离**由调用方 scoped conn (遮蔽视图) 兜,
/// 本函数不加 account 谓词。`local_id` 从 `source_native_id` (`Msg_<md5>:<local_id>`) 反解 (L1 message 表无该列)。
///
/// # Errors
/// [`CliError`] — prepare / 查询失败 (库非 L1 / 表缺 / 损坏)。
pub fn cold_messages_query(
    conn: &rusqlite::Connection,
    chat: &str,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let conv_sha = native_core::sha256_hex(chat);

    // ── 把 account_id_sha 补进 WHERE, 否则索引一列都用不上 ──
    //
    // 本查询原本只写 `WHERE conv_id_sha = ?`。多账号库走 `open_l1_scoped` 时遮蔽视图会替它补上账号,
    // 索引 `idx_message_conv_time (account_id_sha, conv_id_sha, ...)` 因而用得上; 但**单账号库没有
    // 视图**(不需要过滤), WHERE 里就真的只剩会话 —— 以账号打头的索引一列都用不上, SQLite 只能
    // 整表 SCAN + 建临时 B 树排序。真库实测: 210 万条的群取最近 3 条要 4.2 秒。
    // (实测本机 14 个真实 L1 全是单账号 → 这条路径正是日常在走的那条。)
    //
    // 判据用**看得见几个账号**, 两种情况下都对:
    //   * 有遮蔽视图 → 视图本来就只露一个账号 → 恒为 1 → 补的谓词与视图一致, 冗余但无害;
    //   * 无视图的单账号库 → 1 → 补对了;
    //   * 无视图的多账号库(没给 --account)→ ≥2 → **不补**, 行为与从前完全一致, 不会静默只查一个号。
    // ⚠️ 排序次键必须带 `source`(= 分片文件名, 如 message_5.db): L1 主键尾是
    //    `(source, source_native_id)`, 只用 source_native_id **不唯一** —— 同一会话跨两个分片时
    //    两边 local_id 会重号, 同毫秒就撞成并列行, offset 翻页会重复/丢行。
    //    (仓库里已经栽过一次同款: `native_core::thin` 的 rowid 就是因此必须带 source。
    //     本函数旧 doc 拿"单 source L1 下每行唯一"当前提, 而真实 L1 不满足 —— 一个会话跨多分片是常态。)
    // 探「看得见几个账号」—— 这里的写法是**实测挑出来的**, 不是想当然:
    //   `SELECT DISTINCT account_id_sha .. LIMIT 2`     → 337 ms(SQLite 全扫 idx_message_type)
    //   `SELECT MIN(..), MAX(..)` **写在同一条里**      → 404 ms(两个聚合并存会让端点优化失效)
    //   MIN 与 MAX **各发一条**                          → 2.1 ms / 0.0 ms  ← 用这个
    // (都在 210 万行的真库上量的。我第一版把「MIN/MAX 是 O(1)」当成常识写进注释, 结果就是那条 404ms。)
    // ⚠️ 两条探测必须在**同一个读快照**里。分开发的话有条窄缝: 库里只有账号 B, `MIN` 读到 B 之后、
    //    `MAX` 之前并发插进来一个字典序更小的 A —— 两边都返 B, 于是误判成"只有一个账号", A 的消息
    //    被静默过滤掉。更麻烦的是 COUNT 也一起过滤, **总数和行数仍然自洽**, 从结果上看不出任何异常。
    //    包进一个 DEFERRED 读事务就没这个缝, 成本为零(SQLite 读事务不阻塞别人)。
    //    (独立审查指出的; 触发概率极低 —— 要「查询进行中恰好新增第二个账号」—— 但代价既然是零就该修。)
    //
    //    **实测坐实过, 但第一个探针是废的**: 我先造了"并发插入一个比现有值**小**的行", 开不开事务
    //    结果都一样 → 看着像"快照生效", 其实是 `MAX` 根本不看小值, 探针压根区分不了两种情形。
    //    改成**两侧都插**(一个更小一个更大)才有判别力: 不开事务时第二条读到了新插的大值,
    //    开了事务两条都只看到原值。⇒ **反例造不对, 和"修复是假的"看起来一模一样** ——
    //    验证之前先让探针自证能区分。
    //    **机理更正**(审查方 P3-2): 上面那段把危害说成"MIN/MAX 会读到不一致的值"—— 实测**不对**:
    //    只并发插一个字典序更小的 A 时, 开不开事务 MIN/MAX 都返 B。真正起作用的是**后面的 COUNT 和
    //    取行那两条也被拉进了同一个快照** —— 否则探测判定"单账号 B"之后, 并发插入的 A 的行会被
    //    过滤掉却又计入不了, 快照统一才谈得上一致。
    //    (实测: 不开事务时按 sole_account 过滤只数到 1 行而库里有 2 行 —— **静默丢 1 行**; 开了就是 0 丢失。)
    let read_snapshot = conn.unchecked_transaction();
    if let Err(e) = &read_snapshot {
        // 唯一会失败的情形是"调用方已经在事务里"—— 那种情形下本来就有快照, 反而安全。
        // 但别静默: 若哪天因为别的原因失败, 会退回没有快照的老行为, 而外部完全看不出来。
        tracing::debug!(error = %e, "开只读快照失败 → 退回逐条读(极窄的并发窗口下可能少算一个账号)");
    }
    let _read_snapshot = read_snapshot.ok();
    let sole_account: Option<String> = {
        let lo = conn
            .query_row("SELECT MIN(account_id_sha) FROM message", [], |r| {
                r.get::<_, Option<String>>(0)
            })
            .context("探账号下界失败 (库是 L1?)")?;
        let hi = conn
            .query_row("SELECT MAX(account_id_sha) FROM message", [], |r| {
                r.get::<_, Option<String>>(0)
            })
            .context("探账号上界失败 (库是 L1?)")?;
        match (lo, hi) {
            (Some(a), Some(b)) if a == b => Some(a), // 只有一个账号 → 补进 WHERE, 索引才 seek 得动
            _ => None,                               // 空库 or 多账号 → 不补, 行为与从前一致
        }
    };
    let acct_pred = if sole_account.is_some() {
        " AND account_id_sha = ?4"
    } else {
        ""
    };

    let total: i64 = match &sole_account {
        Some(a) => conn.query_row(
            "SELECT count(*) FROM message WHERE conv_id_sha = ?1 AND account_id_sha = ?2",
            rusqlite::params![&conv_sha, a],
            |r| r.get(0),
        ),
        None => conn.query_row(
            "SELECT count(*) FROM message WHERE conv_id_sha = ?1",
            [&conv_sha],
            |r| r.get(0),
        ),
    }
    .context("查会话消息数失败 (库是 L1?)")?;
    let mut st = conn
        .prepare(
            &format!(
            "SELECT source_native_id, server_id, server_seq, origin_source, upload_status, download_status, \
                    create_time, sort_seq, status, local_type_raw, msg_type, msg_type_name, msg_sub_type, \
                    msg_sub_type_name, decode_kind, sys_type, is_chatroom, raw_xml_present, sender_wxid, text_content \
             FROM message WHERE conv_id_sha = ?1{acct_pred}              ORDER BY create_time DESC, source_native_id DESC, source DESC LIMIT ?2 OFFSET ?3"
            ),
        )
        .context("查会话消息失败 (库是 L1?)")?;
    let data: Vec<serde_json::Value> = st
        .query_map(
            rusqlite::params_from_iter(
                [
                    rusqlite::types::Value::Text(conv_sha.clone()),
                    rusqlite::types::Value::Integer(limit as i64),
                    rusqlite::types::Value::Integer(offset as i64),
                ]
                .into_iter()
                .chain(sole_account.clone().map(rusqlite::types::Value::Text)),
            ),
            |r| {
                let snid: String = r.get(0)?;
                // local_id: 从 source_native_id "Msg_<md5>:<local_id>" 反解 (L1 无该列); 解不出 → 0。
                let local_id = snid
                    .rsplit_once(':')
                    .and_then(|(_, id)| id.parse::<i64>().ok())
                    .unwrap_or(0);
                Ok(serde_json::json!({
                    "source_native_id": snid,
                    // R16-0 (对抗审 P2-1): 冷查也必须出 conv_id。热查加了它(→22 键)而冷查没加时, `--mode`
                    // 切换对消费者**不再透明**(违背本函数 doc 的对齐契约); 更实际的是 HTTP 默认 mode=auto
                    // + 配了 --l1-db **就走冷查**, openapi 的"每行 22 键"会对这条最常见路径撒谎。
                    // 入参 `chat` 就是明文 conv_id (SQL 用它的 sha 匹配 conv_id_sha), 白拿。
                    "conv_id": chat,
                    "local_id": local_id,
                    "server_id": r.get::<_, i64>(1)?,
                    "server_seq": r.get::<_, i64>(2)?,
                    "origin_source": r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    "upload_status": r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    "download_status": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    "create_time": r.get::<_, i64>(6)?,
                    "sort_seq": r.get::<_, i64>(7)?,
                    "status": r.get::<_, i64>(8)?,
                    "local_type": r.get::<_, i64>(9)?,
                    "msg_type": r.get::<_, i64>(10)?,
                    "msg_type_name": r.get::<_, String>(11)?,
                    "msg_sub_type": r.get::<_, Option<i64>>(12)?,
                    "msg_sub_type_name": r.get::<_, Option<String>>(13)?,
                    "decode_kind": r.get::<_, String>(14)?,
                    "sys_type": r.get::<_, Option<String>>(15)?,
                    "is_chatroom": r.get::<_, i64>(16)? != 0,
                    "raw_xml_present": r.get::<_, i64>(17)? != 0,
                    "sender": r.get::<_, String>(18)?,
                    "text": r.get::<_, String>(19)?,
                }))
            },
        )
        .context("查会话消息失败")?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

/// **冷查会话列表** (R6 `--mode=cold`): 读 L1 `session` 表, 字段集与热查 [`crate::hot_sessions`] 的 `session_json`
/// **对齐** (20 键)。按 `sort_timestamp DESC, username DESC` **倒序** (同热查 `read_hot_sessions`: `username` 唯一
/// 次键保 `offset` 翻页**不重复/不漏** —— `sort_timestamp` 真库有并列值, 单键翻页会漏会话)。账号隔离由
/// 调用方 scoped conn 兜。`is_group` 由 `username` 派生 (L1 无此列); `conv_id` = `username` (消费方拿它当 conv)。
///
/// # Errors
/// [`CliError`] — prepare / 查询失败。
pub fn cold_sessions_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let total: i64 = conn
        .query_row("SELECT count(*) FROM session", [], |r| r.get(0))
        .context("查会话数失败 (库是 L1?)")?;
    let mut st = conn
        .prepare(
            "SELECT username, summary, summary_len, last_sender_display_name, unread_count, last_msg_type, \
                    last_msg_sub_type, sort_timestamp, session_type, is_hidden, status, draft, last_msg_sender, \
                    last_timestamp, last_clear_unread_timestamp, last_msg_locald_id, last_msg_ext_type, \
                    unread_first_msg_srv_id \
             FROM session ORDER BY sort_timestamp DESC, username DESC LIMIT ?1 OFFSET ?2",
        )
        .context("查会话列表失败 (库是 L1?)")?;
    let data: Vec<serde_json::Value> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            let username: String = r.get(0)?;
            let is_group = username.ends_with("@chatroom");
            Ok(serde_json::json!({
                "conv_id": username.clone(),
                "username": username,
                "is_group": is_group,
                "summary": r.get::<_, Option<String>>(1)?,
                "summary_len": r.get::<_, i64>(2)?,
                "last_sender_display_name": r.get::<_, Option<String>>(3)?,
                "unread_count": r.get::<_, i64>(4)?,
                "last_msg_type": r.get::<_, i64>(5)?,
                "last_msg_sub_type": r.get::<_, i64>(6)?,
                "sort_timestamp": r.get::<_, i64>(7)?,
                "session_type": r.get::<_, i64>(8)?,
                "is_hidden": r.get::<_, i64>(9)?,
                "status": r.get::<_, i64>(10)?,
                "draft": r.get::<_, Option<String>>(11)?,
                "last_msg_sender": r.get::<_, Option<String>>(12)?,
                "last_timestamp": r.get::<_, i64>(13)?,
                "last_clear_unread_timestamp": r.get::<_, i64>(14)?,
                "last_msg_locald_id": r.get::<_, i64>(15)?,
                "last_msg_ext_type": r.get::<_, i64>(16)?,
                "unread_first_msg_srv_id": r.get::<_, i64>(17)?,
            }))
        })
        .context("查会话列表失败")?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    // R6 冷热同形: 会话总数也放 `summary.total_sessions` (对齐热查 §14.1 读法 —— 消费者跨冷热同一处读总数;
    // 顶层 `total_count` 保留 = 冷查精确分页 bonus)。CLI table 头读 summary → 冷查也显 "会话 N 个"。
    let mut summary = serde_json::Map::new();
    summary.insert("total_sessions".into(), serde_json::json!(total));
    let meta = Meta::offset_page(offset, data.len(), total, limit)
        .with_source(Source::Cold)
        .with_summary(serde_json::Value::Object(summary));
    Ok(QueryResult { data, meta })
}

// ── finder (finder_visit) ──

/// finder 一行: (visit_time 秒, 访问日期, 视频号名, 号主 username, 主页 url)。
type FinderRow = (i64, String, String, String, String);

/// 查访问过的视频号 (finder_visit 全表, 按访问时刻倒序)。返 `QueryResult`。
/// 注: visit_time 是 unix **秒** (10 位, 非 message.create_time 的毫秒) → date 直接 unixepoch。
pub fn finder_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let total: i64 = conn.query_row("SELECT count(*) FROM finder_visit", [], |r| r.get(0))?;
    // 次键 owner_username: visit_time 单键排序对并列行不保证稳定 → OFFSET 翻页可能重复/漏。
    // R16 硬约束④: 接一条 = 该条**冷热两侧都得稳**(热稳冷不稳仍不叫对等)。
    //
    // **为什么用 owner_username 而不是 source_native_id**: ① 它就是 finder_visit 锚的来源
    // (`finder_anchor(owner_username)`), 排它 == 排锚, 但**热查那边算得出**(源库 `username` 列直接就是),
    // 于是冷热并列顺序也一致 —— friend_verify 那条冷用 source_native_id / 热用 rowid, 并列行顺序对不上
    // (轮4 审 P3-c); ② 不靠"复合 PK 的成员必唯一"这种假不变量(轮4 审 P3-a: PK 是
    // `(account_id_sha, source, source_native_id)`, 单个成员本身不唯一 —— message 表同形状而 source
    // 是分片名, 那里就不唯一)。
    // **唯一性不是这里的必需条件**: 次键只求**冷热同键 → 顺序确定且一致**。owner_username 真库实测唯一
    // (723 行 L1 = 723 个不同号主), 但即便将来不唯一, 冷热仍按同一个键排, 顺序仍一致。
    let mut st = conn.prepare(
        "SELECT visit_time, date(visit_time, 'unixepoch', 'localtime'), name, owner_username, profile_url \
         FROM finder_visit ORDER BY visit_time DESC, owner_username DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<FinderRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(vt, day, name, owner, url)| {
            serde_json::json!({
                "visit_time": vt, "visit_date": day, "name": name,
                "owner_username": owner, "profile_url": url
            })
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── members (chatroom_member) ──

/// members 查询行: (member_wxid, display_name, role, joined_at, invited_by)。
type MemberRow = (String, Option<String>, String, Option<i64>, Option<String>);

/// 查某群**在群**成员 (chatroom_member; `admins_only` 只看 owner/admin, 按 role/wxid 排序)。
/// 全量载入 (无 SQL-LIMIT) → `total` = 本页行数 (§6③ total=loaded-all)。返 `QueryResult`。
pub fn members_query(
    conn: &rusqlite::Connection,
    chatroom: &str,
    admins_only: bool,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let map = |row: &rusqlite::Row| -> rusqlite::Result<MemberRow> {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
    };
    // is_in_group=1 只看在群; admins_only 再滤 role!=member。**必须有 LIMIT** (审查 P1-6: 大群几千人无
    // 上限会击穿 MCP 48KB 封顶且无翻页逃生口); total 用同谓词 COUNT → 截断诚实 (total_count 报全量)。
    // limit 是计算整数 (非用户文本) 内联无注入; chatroom 仍参数化 ?1。
    let where_ = if admins_only {
        "WHERE chatroom_id = ?1 AND is_in_group = 1 AND role != 'member'"
    } else {
        "WHERE chatroom_id = ?1 AND is_in_group = 1"
    };
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) FROM chatroom_member {where_}"),
        [chatroom],
        |r| r.get(0),
    )?;
    let sql = format!(
        "SELECT member_wxid, display_name, role, joined_at, invited_by FROM chatroom_member \
         {where_} ORDER BY role, member_wxid LIMIT {limit} OFFSET {offset}"
    );
    let mut st = conn.prepare(&sql)?;
    let rows: Vec<MemberRow> = st.query_map([chatroom], map)?.filter_map(ok_or_warn).collect();
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(w, d, r, j, inv)| {
            serde_json::json!({"member_wxid": w, "display_name": d, "role": r, "joined_at": j, "invited_by": inv})
        })
        .collect();
    let meta =
        Meta::offset_page(offset, data.len(), usize::try_from(total).unwrap_or(0), limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── favorites (favorite) ──

/// favorites 查询行: (server_id, fav_type, update_time, from_user, real_chat_name, content_len)。
type FavRow = (i64, i64, i64, Option<String>, Option<String>, i64);

/// 查收藏 (favorite; 可选 `-q` 过滤 来源人/会话名; 全量按 update_time 倒序后截前 limit)。
/// `total` = 截断前全量行数 (§6③ total=loaded-all)。返 `QueryResult`。
pub fn favorites_query(
    conn: &rusqlite::Connection,
    q: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let map = |row: &rusqlite::Row| -> rusqlite::Result<FavRow> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    };
    let cols = "server_id, fav_type, update_time, from_user, real_chat_name, content_len";
    // SQL LIMIT/OFFSET + COUNT (原全量载入改真分页, ④ offset)。
    let (total, all): (i64, Vec<FavRow>) = if let Some(q) = q {
        let filt = "from_user LIKE '%'||?1||'%' OR real_chat_name LIKE '%'||?1||'%'";
        let total = conn.query_row(&format!("SELECT count(*) FROM favorite WHERE {filt}"), [q], |r| {
            r.get(0)
        })?;
        let sql = format!(
            "SELECT {cols} FROM favorite WHERE {filt} ORDER BY update_time DESC, local_id DESC LIMIT ?2 OFFSET ?3"
        );
        let mut st = conn.prepare(&sql)?;
        let v = st
            .query_map(rusqlite::params![q, limit as i64, offset as i64], map)?
            .filter_map(ok_or_warn)
            .collect();
        (total, v)
    } else {
        let total: i64 = conn.query_row("SELECT count(*) FROM favorite", [], |r| r.get(0))?;
        let sql = format!("SELECT {cols} FROM favorite ORDER BY update_time DESC, local_id DESC LIMIT ?1 OFFSET ?2");
        let mut st = conn.prepare(&sql)?;
        let v = st
            .query_map(rusqlite::params![limit as i64, offset as i64], map)?
            .filter_map(ok_or_warn)
            .collect();
        (total, v)
    };
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = all
        .iter()
        .map(|(s, ft, u, fu, c, cl)| {
            serde_json::json!({"server_id": s, "fav_type": ft, "update_time": u, "from_user": fu, "real_chat_name": c, "content_len": cl})
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── mentions (message_mention ⋈ message) ──

/// mentions 查询行: (create_time, conv_id, sender_wxid, mentioned_wxid, is_at_all, text_content)。
type MentionRow = (i64, String, String, String, i64, String);

/// 查 @提及 (message_mention ⋈ message; 可选按 mentioned_wxid 子串过滤; 时间倒序取前 limit)。
/// 真总数用独立 `COUNT`(respect 过滤); 截断诚实 (limit 截数据不截 total)。返 `QueryResult`。
pub fn mentions_query(
    conn: &rusqlite::Connection,
    who: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let map = |row: &rusqlite::Row| -> rusqlite::Result<MentionRow> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
        ))
    };
    let cols = "m.create_time, m.conv_id, m.sender_wxid, mn.mentioned_wxid, mn.is_at_all, m.text_content";
    let join = "FROM message_mention mn JOIN message m \
                ON mn.account_id_sha = m.account_id_sha AND mn.source = m.source \
                   AND mn.source_native_id = m.source_native_id";
    // **codex mentions P2 (过滤语义冷热对齐)**: who 走 `instr()` **字面子串**匹配, 非 `LIKE '%..%'`。LIKE 里 `%`/`_` 是
    // 通配符 → `who=%` 冷查匹配全部而热查(`.contains`)匹配空; wxid 常含 `_`(`wxid_...`)会在冷查被当"任意单字符"过配。
    // 热查 `hot_mentions` 用 `mention.wxid.contains(w)`(字面) → 冷查亦须字面, `instr(x, ?)>0` = 字节级子串, 与之等价。
    let (rows, total): (Vec<MentionRow>, i64) = if let Some(w) = who {
        let total: i64 = conn.query_row(
            &format!("SELECT count(*) {join} WHERE instr(mn.mentioned_wxid, ?1) > 0"),
            [w],
            |r| r.get(0),
        )?;
        let sql = format!(
            "SELECT {cols} {join} WHERE instr(mn.mentioned_wxid, ?1) > 0 \
             ORDER BY m.create_time DESC, m.source DESC, m.source_native_id DESC, mn.mentioned_wxid DESC LIMIT ?2 OFFSET ?3"
        );
        let mut st = conn.prepare(&sql)?;
        let v: Vec<MentionRow> = st
            .query_map(rusqlite::params![w, limit as i64, offset as i64], map)?
            .filter_map(ok_or_warn)
            .collect();
        (v, total)
    } else {
        let total: i64 = conn.query_row(&format!("SELECT count(*) {join}"), [], |r| r.get(0))?;
        let sql = format!("SELECT {cols} {join} ORDER BY m.create_time DESC, m.source DESC, m.source_native_id DESC, mn.mentioned_wxid DESC LIMIT ?1 OFFSET ?2");
        let mut st = conn.prepare(&sql)?;
        let v: Vec<MentionRow> = st
            .query_map(rusqlite::params![limit as i64, offset as i64], map)?
            .filter_map(ok_or_warn)
            .collect();
        (v, total)
    };
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, cv, s, mw, aa, t)| {
            serde_json::json!({"create_time": ct, "conv_id": cv, "sender_wxid": s, "mentioned_wxid": mw, "is_at_all": aa, "text_content": t})
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── biz (message gh_ 会话 ⋈ message_app) ──

/// biz 查询行: (create_time 毫秒, 推送日期, 公众号 gh_id, 文章标题, msg_type)。
type BizRow = (i64, String, String, Option<String>, i64);

/// 查公众号图文推送 (message gh_ 会话 ⋈ message_app 取标题; 毫秒 create_time, date /1000)。
/// gh_ 会话用 substr 精确匹配 (避 LIKE '_' 通配歧义)。真 `COUNT` 全量。返 `QueryResult`。
pub fn biz_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM message WHERE substr(conv_id,1,3) = 'gh_'",
        [],
        |r| r.get(0),
    )?;
    let mut st = conn.prepare(
        "SELECT m.create_time, date(m.create_time/1000, 'unixepoch', 'localtime'), m.conv_id, a.title, m.msg_type \
         FROM message m LEFT JOIN message_app a \
           ON a.account_id_sha = m.account_id_sha AND a.source = m.source \
              AND a.source_native_id = m.source_native_id \
         WHERE substr(m.conv_id,1,3) = 'gh_' \
         ORDER BY m.create_time DESC, m.source DESC, m.source_native_id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<BizRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, day, gh, title, mtype)| {
            serde_json::json!({"create_time": ct, "date": day, "gh_id": gh, "title": title, "msg_type": mtype})
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── msgraw (raw_payload_archive) ──

/// msgraw 查询行: (id, ingest_time, event_type, event_action, source, source_native_id, payload_json)。
type MsgrawRow = (i64, i64, String, String, String, String, String);

/// 查原始 payload 归档 (raw_payload_archive; `--native-id` 精确过滤, 否则全表; id 倒序取前 limit)。
/// json `payload` = **解析后**的对象 (非法 JSON 退化为字符串)。真 `COUNT` 全量 (respect 过滤)。
/// NOT_FOUND (定向查无) 判定留 CLI 皮 (读 `meta.total_count`)。返 `QueryResult`。
///
/// ⚠️ **`source` 必须出在结果里**(外部复审 P2): 这个命令干的就是溯源, 而 `source_native_id`
/// (形如 `Msg_<表名>:<行号>`)**不带分片**。同一账号下同名会话表可以同时存在于多个分片 ——
/// 真库实测 **700 张同名 `Msg_` 表同时在 `message_0.db` 和 `message_5.db`** —— 那样 `--native-id`
/// 会返回多条, 而结果里没有任何字段能告诉用户哪条来自哪个分片。给了 `source` 才认得出,
/// 再给 `--source` 就能直接钉死一条。(账号维度另有遮蔽视图管, 不在这条的范围里。)
pub fn msgraw_query(
    conn: &rusqlite::Connection,
    native_id: Option<&str>,
    source: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    const COLS: &str = "id, ingest_time, event_type, event_action, source, source_native_id, payload_json";
    // 两个过滤条件都可选, 各自独立 —— 拼一次 WHERE, 计数和取行共用, 免得两边写岔。
    let mut wheres: Vec<&str> = Vec::new();
    let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::new();
    if native_id.is_some() {
        wheres.push("source_native_id = ?");
        binds.push(&native_id);
    }
    //
    // 分片名里带下划线, 而 `_` 在 LIKE 里是通配符 —— `message_0.db|%` 会连 `messageX0.db|...`
    // 一起匹上。真实分片不叫那个名字, 但这是自找的松口子, 所以显式转义(配 `ESCAPE`)。
    let source_prefix = source.map(|s| {
        let escaped = s.replace('!', "!!").replace('_', "!_").replace('%', "!%");
        format!("{escaped}|%")
    });
    if source.is_some() {
        wheres.push("(source = ? OR source LIKE ? ESCAPE '!')");
        binds.push(&source);
        binds.push(&source_prefix);
    }
    let where_sql = if wheres.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", wheres.join(" AND "))
    };
    let total: i64 = conn.query_row(
        &format!("SELECT count(*) FROM raw_payload_archive{where_sql}"),
        rusqlite::params_from_iter(binds.iter().copied()),
        |r| r.get(0),
    )?;
    let sql = format!("SELECT {COLS} FROM raw_payload_archive{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?");
    let (lim, off) = (limit as i64, offset as i64);
    let mut page_binds = binds.clone();
    page_binds.push(&lim);
    page_binds.push(&off);
    let mut st = conn.prepare(&sql)?;
    let rows: Vec<MsgrawRow> = st
        .query_map(rusqlite::params_from_iter(page_binds.iter().copied()), |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .filter_map(ok_or_warn)
        .collect();
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(id, it, etype, action, src, nid, payload)| {
            // payload_json 内嵌为解析后的对象 (非法则退化为字符串)。
            let parsed = serde_json::from_str::<serde_json::Value>(payload)
                .unwrap_or_else(|_| serde_json::Value::String(payload.clone()));
            serde_json::json!({
                "id": id, "ingest_time": it, "event_type": etype, "event_action": action,
                "source": src, "source_native_id": nid, "payload": parsed
            })
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── events (message type10000 群系统事件) ──

/// sys_type 分类码 → 人话 (批F/ADR-458 分类; 未知原样)。json 阶段预组进 `label` 字段。
#[must_use]
pub fn sys_type_label(t: &str) -> &str {
    match t {
        "member_join" => "入群",
        "member_remove" => "退群",
        "revoke" => "撤回",
        "pat" => "拍一拍",
        "topmsg" => "置顶",
        "group_dissolve" => "群解散", // codex 66e76ec P2: classify_sysmsg 发此值, 原走 _ => t 出英文原值
        "hongbao" => "领红包",
        "transfer" => "转账",
        "other" => "其他",
        _ => t,
    }
}

/// events 查询行: (create_time 毫秒, 事件日期, conv_id, sys_type, text_content)。
type EventRow = (i64, String, String, Option<String>, Option<String>);

/// 查群系统事件 (message type10000; `--sys-type` 精确过滤, 否则全部; 时间倒序取前 limit)。
/// create_time 毫秒 → date /1000 转本地日历日 (SQL 内算)。真 `COUNT` 全量 (respect 过滤)。
/// json `label` = `sys_type_label` 预组 (sys_type 为空则 null; table 皮读此 label 不重算)。返 `QueryResult`。
pub fn events_query(
    conn: &rusqlite::Connection,
    sys_type: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    const COLS: &str = "create_time, date(create_time/1000,'unixepoch','localtime'), conv_id, sys_type, text_content";
    let (rows, total): (Vec<EventRow>, i64) = if let Some(st) = sys_type {
        let total: i64 = conn.query_row(
            "SELECT count(*) FROM message WHERE msg_type = 10000 AND sys_type = ?1",
            [st],
            |r| r.get(0),
        )?;
        let sql = format!(
            "SELECT {COLS} FROM message WHERE msg_type = 10000 AND sys_type = ?1 ORDER BY create_time DESC, source DESC, source_native_id DESC LIMIT ?2 OFFSET ?3"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params![st, limit as i64, offset as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .filter_map(ok_or_warn)
            .collect();
        (rows, total)
    } else {
        let total: i64 = conn.query_row("SELECT count(*) FROM message WHERE msg_type = 10000", [], |r| r.get(0))?;
        let sql =
            format!("SELECT {COLS} FROM message WHERE msg_type = 10000 ORDER BY create_time DESC, source DESC, source_native_id DESC LIMIT ?1 OFFSET ?2");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .filter_map(ok_or_warn)
            .collect();
        (rows, total)
    };
    let total = usize::try_from(total).unwrap_or(0);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, day, conv, st, text)| {
            serde_json::json!({
                "create_time": ct, "date": day, "conv_id": conv,
                "sys_type": st, "label": st.as_deref().map(sys_type_label),
                "text": text
            })
        })
        .collect();
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── followups (message 末条对方发的会话) ──

/// followups 查询行: (last create_time 毫秒, 日期时间, conv_id, sender_wxid, msg_type_name, text)。
type FollowupRow = (i64, String, String, Option<String>, Option<String>, Option<String>);

/// 查漏回会话: 每会话末条非系统消息若是对方发的 (sender != account_id 本人) = 我还没回。
/// CTE 取每会话 max(create_time) 再 JOIN 回原表; 排系统消息 (type10000); private_only 再排群聊。
/// 全量载入 → `total` = 截断前会话数 (§6③ total=loaded-all)。返 `QueryResult`。
pub fn followups_query(
    conn: &rusqlite::Connection,
    private_only: bool,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let private_filter = if private_only { "AND m.is_chatroom = 0" } else { "" };
    // R6 复审 P2: 改 **SQL LIMIT/OFFSET + 独立 COUNT + offset_page**, 与其它列表查询一致 —— 不再"内存全取分页"。原做法
    // dropped 是整集总数、只首页报, 与 `dropped_rows`="本页丢失行数"字段契约不符, 且大结果全载低效。COUNT 与 data **同谓词**
    // → offset_page 算术 dropped = min(limit,total-offset)-shown 精确到**本页**; total_count = SQL COUNT (数不可读行, 同口径)。
    // WITH 子句须在 SELECT 前 → 拆成 with_clause + from_where, COUNT/data 各自 `WITH ... SELECT ... FROM ...`。
    let with_clause =
        "WITH last AS (SELECT conv_id, max(create_time) AS mc FROM message WHERE msg_type != 10000 GROUP BY conv_id)";
    let from_where = format!(
        "FROM message m JOIN last ON m.conv_id = last.conv_id AND m.create_time = last.mc \
         WHERE m.msg_type != 10000 AND m.sender_wxid IS NOT NULL AND m.sender_wxid <> m.account_id {private_filter}"
    );
    // codex-R7 P2#5: COUNT 与 data 两条 SELECT 包进**一个只读事务** —— 否则 autocommit 下两语句各取快照, 并发 ingest 在
    // COUNT 后插入/改状态会让 data 见新集而 total 仍旧 → 可能凭空 dropped_rows / 错 has_more / total_count<data.len()。
    // 事务内 (WAL: 首条 SELECT 取快照, 持到 tx 结束) COUNT+data 同快照, 消除两语句竞态。只读 → drop 即 rollback 无害。
    let tx = conn.unchecked_transaction()?;
    let total: i64 = tx.query_row(&format!("{with_clause} SELECT count(*) {from_where}"), [], |r| r.get(0))?;
    let sql = format!(
        "{with_clause} SELECT m.create_time, datetime(m.create_time/1000,'unixepoch','localtime'), \
                m.conv_id, m.sender_wxid, m.msg_type_name, m.text_content \
         {from_where} ORDER BY m.create_time DESC, m.source DESC, m.source_native_id DESC LIMIT ?1 OFFSET ?2"
    );
    let mut st = tx.prepare(&sql)?;
    let data: Vec<serde_json::Value> = st
        .query_map(
            rusqlite::params![limit as i64, offset as i64],
            |r| -> rusqlite::Result<FollowupRow> {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            },
        )?
        .filter_map(ok_or_warn)
        .map(|(ct, dt, conv, sender, tname, text)| {
            serde_json::json!({
                "last_create_time": ct, "datetime": dt, "conv_id": conv,
                "last_sender_wxid": sender, "msg_type_name": tname, "text_content": text
            })
        })
        .collect();
    // offset_page: has_more=offset+shown<total; total_count=total(含不可读); **dropped_rows 由算术 per-page 出**(本页缺行)。
    let meta =
        Meta::offset_page(offset, data.len(), usize::try_from(total).unwrap_or(0), limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── moments (moment 表, 朋友圈动态 bare 视图) ──

/// moments (bare) 查询行: (author, author_nickname, create_time, content_desc, media_count, like_count, comment_count)。
type MomentRow = (String, Option<String>, i64, String, i64, i64, i64);

/// 查 L1 moment 表 (朋友圈动态, 按 create_time 倒序 offset 分页)。COUNT 廉价 → `Meta::offset_page`
/// (has_more/total_count/limit/offset, 与其余列表端点一致)。返 `QueryResult`。
/// (注: `--interactions/--feed/--inbox` 子视图走引擎 `CMD_*`, 不在此 —— 此为无标志的 bare moment 表档。)
pub fn moments_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    let map = |row: &rusqlite::Row| -> rusqlite::Result<MomentRow> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    };
    // ④ offset_page (与其余 9 端点 meta 一致: has_more/total_count/limit/offset); COUNT 廉价。
    let total: i64 = conn.query_row("SELECT count(*) FROM moment", [], |r| r.get(0))?;
    let mut st = conn.prepare(
        "SELECT author, author_nickname, create_time, content_desc, media_count, like_count, comment_count \
         FROM moment ORDER BY create_time DESC, source DESC, source_native_id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<MomentRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], map)?
        .filter_map(ok_or_warn)
        .collect();
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(a, n, ct, d, m, l, c)| {
            serde_json::json!({"author": a, "author_nickname": n, "create_time": ct, "content_desc": d, "media_count": m, "like_count": l, "comment_count": c})
        })
        .collect();
    let meta =
        Meta::offset_page(offset, data.len(), usize::try_from(total).unwrap_or(0), limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── new (message create_time > watermark 增量) ──

/// new 查询行: (create_time 毫秒, 日期时间, conv_id, sender_wxid, msg_type_name, text_content)。
type NewRow = (i64, String, String, Option<String>, Option<String>, Option<String>);

/// 查水位之后**新 ingest 的消息** (`rowid > wm_rowid`, rowid 升序=ingest 到达序; 全类型)。R11 三方复审 P2: fetch
/// **limit+1** 作探针 → `has_more = fetched>limit` 精确(原 fetched==limit 数据刚好取完也假 true); 探针行不处理不推进水位。
/// `Meta::cold_page` 省 total_count(message 无廉价"水位后全量")。返 `QueryResult`。水位文件读写+按账号分区留 msgvestige 皮;
/// 核只收 `wm_rowid`、出 `scanned_rowid`(只到第 limit 行, 不含探针)供皮推进。
///
/// codex-R8 P1: 游标用 **rowid**(隐式行号)而非 create_time —— **rowid 是唯一随 ingest 单调递增的键** (SQLite `INSERT` /
/// `INSERT OR REPLACE` 都取 `max(rowid)+1`)。create_time **不单调**, 用它做游标两种数据都**永久漏**: ①同毫秒多条 (真库
/// 单毫秒挤 282 条 > limit, 批边界跳剩余)、②乱序晚到 (历史同步把旧 create_time 消息晚 ingest, `create_time>wm` 永不命中)。
/// rowid 游标 `rowid > wm` 对①②都不漏 (新/重写行 rowid 恒 > 水位)。代价: `INSERT OR REPLACE`(已读回执/状态更新)换 rowid
/// → 该消息**重投一次** (at-least-once, 符合 cold_page "宁重复不漏" 契约; **零丢失**是硬要求)。注意 rowid **非稳定主键**
/// (message 声明 PK 是复合 TEXT (account_id_sha,source,source_native_id); rowid 是独立隐式行号) —— VACUUM 会重编号使水位
/// 失效, 但 VACUUM 非 live-index 常规操作 (append-only 归档不 VACUUM)。rowid 需**裸 conn** (遮蔽视图无 rowid) → 皮层 open_l1
/// + 显式 account_id_sha 谓词隔离 (照 search_query 范式)。
pub fn new_query(
    conn: &rusqlite::Connection,
    wm_rowid: i64,
    limit: usize,
    account_sha: Option<&str>,
) -> Result<QueryResult> {
    let mut sql = String::from(
        "SELECT create_time, datetime(create_time/1000,'unixepoch','localtime'), conv_id, sender_wxid, \
                msg_type_name, text_content, rowid FROM message WHERE ",
    );
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(sha) = account_sha {
        sql.push_str("account_id_sha = ? AND "); // 多账号库显式隔离 (裸 conn 无遮蔽视图, 照 search)。
        params.push(rusqlite::types::Value::Text(sha.to_string()));
    }
    sql.push_str("rowid > ? ORDER BY rowid ASC LIMIT ?");
    params.push(rusqlite::types::Value::Integer(wm_rowid));
    // R11 三方复审 P2: fetch **limit+1** 作探针精确判 has_more —— 原 `fetched==limit` 在数据刚好取完时也假报 true。
    // keyset(rowid ASC) 分页可安全 over-fetch 一条(不像 OFFSET 翻页会重复); 探针行不处理、不推进水位, 下轮 rowid>wm 重取到。
    params.push(rusqlite::types::Value::Integer(
        i64::try_from(limit).unwrap_or(i64::MAX).saturating_add(1),
    ));
    let mut st = conn.prepare(&sql)?;
    // R6 复审 P1: 手工迭代 + 记 scanned_rowid —— 每行先读 rowid (推进依据; 深损坏读不出 → fail-hard), ASC 序末行=最大;
    // 再读余下列, 后列坏 → 丢行但 rowid 已记。皮层据此推水位, **整批全坏** (data 空) 也能推过 → 下轮跳过本坏批, 不死循环。
    let mut cursor = st.query(rusqlite::params_from_iter(params))?;
    let mut good: Vec<NewRow> = Vec::new();
    let mut dropped = 0u64;
    let mut scanned_rowid: Option<i64> = None;
    let mut fetched = 0usize;
    while let Some(r) = cursor.next()? {
        fetched += 1;
        if fetched > limit {
            break; // 第 limit+1 行 = 探针: 只证明 has_more, **不读列/不处理/不推进水位**(下轮 rowid>wm 会重取到它)。
        }
        let rid: i64 = r.get(6)?; // rowid = 游标推进依据, 读不出 = 深度损坏 → fail-hard (整查失败强于水位卡死)。
        scanned_rowid = Some(rid); // ASC → 逐行覆盖到本批最大 rowid (只到第 limit 行, 不含探针)。
        let row: rusqlite::Result<NewRow> =
            (|| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))();
        match row {
            Ok(v) => good.push(v),
            Err(e) => {
                tracing::warn!("new: 丢一条读取失败的消息 (rowid={rid} 已记, 水位可推过): {e}");
                dropped += 1;
            }
        }
    }
    // R11 三方复审 P2: has_more = **探针命中** (fetched>limit) 精确判, 非 `fetched==limit`(数据刚好取完也假 true)。codex-R7 P2#6:
    // limit>0 才判 —— limit=0 时探针会取到 1 条使 fetched(1)>limit(0) 假 true 且水位不推, 分页消费者无限重复; limit=0=不取。
    let has_more = limit > 0 && fetched > limit;
    let data: Vec<serde_json::Value> = good
        .iter()
        .map(|(ct, dt, conv, sender, tname, text)| {
            serde_json::json!({
                "create_time": ct, "datetime": dt, "conv_id": conv,
                "sender_wxid": sender, "msg_type_name": tname, "text_content": text
            })
        })
        .collect();
    // scanned_rowid 进 summary → 皮层 cmd_new 据此推进水位 (即便 data 空/全坏也推过本批坏行, 不死循环)。
    let mut meta = Meta::cold_page(has_more)
        .with_source(Source::Cold)
        .with_dropped(dropped);
    if let Some(rid) = scanned_rowid {
        meta = meta.with_summary(serde_json::json!({ "scanned_rowid": rid }));
    }
    Ok(QueryResult { data, meta })
}

// ── dormant (message GROUP BY conv_id, 最久没说话排行) ──

/// dormant 查询行: (conv_id, 最近一条消息的本地日期, 该会话消息总数)。
type DormantRow = (String, String, i64);

/// 沉睡会话: 每会话取最后一条消息时间, 升序 (最久没说话在前)。create_time 毫秒 → /1000 转本地日历日。
/// COUNT(DISTINCT conv_id) 廉价 → `Meta::offset_page` (has_more/total_count/limit/offset; 与其余列表一致)。
/// 返 `QueryResult`。
pub fn dormant_query(conn: &rusqlite::Connection, limit: usize, offset: usize) -> Result<QueryResult> {
    // ④ offset_page 统一 meta; total = 会话数 (COUNT DISTINCT, 与 GROUP BY 同一扫)。
    let total: i64 = conn.query_row("SELECT count(DISTINCT conv_id) FROM message", [], |r| r.get(0))?;
    let mut st = conn.prepare(
        "SELECT conv_id, date(max(create_time)/1000, 'unixepoch', 'localtime'), count(*) \
         FROM message GROUP BY conv_id ORDER BY max(create_time) ASC, conv_id ASC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<DormantRow> = st
        .query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            let cid: String = r.get(0)?;
            let last_day: Option<String> = r.get(1)?;
            let n: i64 = r.get(2)?;
            Ok((cid, last_day.unwrap_or_default(), n))
        })?
        .filter_map(ok_or_warn)
        .collect();
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(c, last, n)| serde_json::json!({"conv_id": c, "last_message_day": last, "message_count": n}))
        .collect();
    let meta =
        Meta::offset_page(offset, data.len(), usize::try_from(total).unwrap_or(0), limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── stats (message GROUP BY 维度排行 · summary) ──

/// stats 聚合维度 (clap `--by`; CLI 皮 flatten 复用同一枚举, MCP/HTTP 皮直接构造)。
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StatsBy {
    /// 按消息类型 (msg_type_name: 文本/图片/…)。
    Type,
    /// 按会话 (conv_id: 哪个聊天最多消息)。
    Conv,
    /// 按发送人 (sender_wxid: 谁发得最多)。
    Sender,
    /// 按日期 (create_time 转本地日历日)。
    Day,
}

/// 聚合维度 → 人话 (进 `meta.summary.dimension` + table 表头; 皮读此不重算)。
#[must_use]
pub fn stats_dimension_label(by: StatsBy) -> &'static str {
    match by {
        StatsBy::Type => "消息类型",
        StatsBy::Conv => "会话",
        StatsBy::Sender => "发送人",
        StatsBy::Day => "日期",
    }
}

/// stats 一行: (维度取值, 条数)。
type StatRow = (String, i64);

/// 消息按某维度聚合排行 (GROUP BY + count DESC)。返 (消息总数, 排行行)。低层取数 (直测锁 SQL);
/// `has_more`/summary 组装由 [`stats_query`] 承担。
pub fn query_stats(
    conn: &rusqlite::Connection,
    by: StatsBy,
    limit: usize,
    offset: usize,
) -> Result<(i64, Vec<StatRow>, u64, bool)> {
    // 返 (消息总数, 排行组[≤limit], **本批丢弃组数**, **has_more** R5复审P2#3+R5b)。total 是消息数非组数; 排行组无廉价
    // 精确 COUNT → collect_page fetch-limit 判 has_more (fetched==limit 保守; **不 over-fetch**, 否则 OFFSET 翻页 offset+=limit 重复行)。
    let total: i64 = conn.query_row("SELECT count(*) FROM message", [], |r| r.get(0))?;
    // 维度表达式是**固定字面量** (ValueEnum 非用户自由文本) → 无注入。day: create_time 是毫秒 → /1000 转 unixepoch。
    let expr = match by {
        StatsBy::Type => "msg_type_name",
        StatsBy::Conv => "conv_id",
        StatsBy::Sender => "sender_wxid",
        StatsBy::Day => "date(create_time/1000, 'unixepoch', 'localtime')",
    };
    let sql =
        format!("SELECT {expr} AS label, count(*) AS n FROM message GROUP BY label ORDER BY n DESC, label ASC LIMIT ?1 OFFSET ?2");
    let mut st = conn.prepare(&sql)?;
    // LIMIT limit (不 over-fetch 探针); collect_page 收好组 + 判 has_more (fetched==limit)。OFFSET 数所有 SQL 行(含坏组),
    // 与 offset+=limit 精确对齐 → 翻页无重复 (codex R5b P2)。
    let (rows, dropped, has_more) = collect_page(
        st.query_map(rusqlite::params![limit as i64, offset as i64], |r| {
            let label: Option<String> = r.get(0)?;
            let n: i64 = r.get(1)?;
            Ok((label.unwrap_or_else(|| "(空)".to_string()), n))
        })?,
        limit,
    );
    Ok((total, rows, dropped, has_more))
}

/// 消息聚合统计 (读 L1 message)。**fetch `limit+1` 精确探 `has_more`** (排行组数无廉价精确 COUNT →
/// `Meta::cold_page`, 省略 total_count); 命令特有汇总 (`total_messages`/`dimension`/`groups_shown`) 收进
/// `meta.summary` (HOLE-3)。`total_messages` = 消息总数 (百分比分母, 真实值; table 皮读 summary 算百分比)。
pub fn stats_query(conn: &rusqlite::Connection, by: StatsBy, limit: usize, offset: usize) -> Result<QueryResult> {
    // R5 复审 P2#3: 传**实际 limit** (query_stats 内部 fetch limit+1 探针 + collect_page 精确算 has_more/页内丢弃);
    // 原本这里传 limit+1 再 `rows.len()>limit` 判 has_more, 会被探针批里的坏组骗成假 false 漏页。total = 消息总数。
    let (total, rows, dropped, has_more) = query_stats(conn, by, limit, offset)?;
    let dim = stats_dimension_label(by);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(l, n)| serde_json::json!({"label": l, "count": n}))
        .collect();
    // HOLE-3 收口: 标准字段走 Meta (has_more/source 每命令一致); 命令特有汇总收进 meta.summary, 不铺 meta 顶层。
    // R4 复审R3#5: 排行组读取失败丢弃数 → dropped_rows (机器可读不完整信号)。
    let meta = Meta::cold_page(has_more)
        .with_source(Source::Cold)
        .with_dropped(dropped)
        .with_summary(serde_json::json!({"total_messages": total, "dimension": dim, "groups_shown": rows.len()}));
    Ok(QueryResult { data, meta })
}

// ── pii-scan (message 文本扫号 · 打码 · summary) ──

/// pii-scan 扫描类别 (clap `--kind`; all=手机+身份证 默认)。
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PiiKind {
    /// 手机号 + 身份证号 (默认)。
    All,
    /// 只手机号。
    Phone,
    /// 只身份证号。
    Idcard,
}

/// GLOB 预筛: text_content 里有 ≥11 位连续数字 (手机 11 位 / 身份证 18 位都含 11 连号)。
/// 让 SQLite 先剪掉绝大多数无号码消息, 再在 Rust 里精扫; 避免全表逐条扫。
const PII_GLOB11: &str = "*[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*";

/// 手机号判定: 11 位纯数字, 1 开头, 第二位 3-9 (中国大陆号段)。入参已是极大数字串。
#[must_use]
pub fn is_cn_mobile(run: &str) -> bool {
    let b = run.as_bytes();
    b.len() == 11 && b[0] == b'1' && (b'3'..=b'9').contains(&b[1])
}

/// 身份证校验位 (GB 11643-1999 mod-11): 前 17 位加权和 mod 11 → 查表得末位。
/// 这是把"18 位数字形"精筛成真身份证的关键 (真库实测把 133 个候选降到 129 个真号)。
#[must_use]
pub fn id_checksum_ok(id18: &str) -> bool {
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const C: [u8; 11] = *b"10X98765432";
    let b = id18.as_bytes();
    if b.len() != 18 {
        return false;
    }
    let mut sum = 0u32;
    for (&d, &w) in b[..17].iter().zip(W.iter()) {
        if !d.is_ascii_digit() {
            return false;
        }
        sum += u32::from(d - b'0') * w;
    }
    C[(sum % 11) as usize] == b[17].to_ascii_uppercase()
}

/// 号码去重后加入命中 (同一消息里同号只报一次)。
fn push_unique_pii(hits: &mut Vec<(&'static str, String)>, item: (&'static str, String)) {
    if !hits.iter().any(|h| h.0 == item.0 && h.1 == item.1) {
        hits.push(item);
    }
}

/// 扫一条文本的所有"极大连续数字串", 分类出手机号 / 身份证号。
/// 用极大数字串边界: 长度恰好 11=手机 / 18=身份证 → 天然排除嵌在更长串里的号
/// (如图片 XML 的 aeskey), 也正确处理逗号/空格分隔的多号 (逐串独立)。
/// 身份证末位可为 X: 17 位数字串紧跟 X/x 时凑成 18 位再验校验位。
#[must_use]
pub fn scan_pii_in_text(text: &str, want_phone: bool, want_id: bool) -> Vec<(&'static str, String)> {
    let mut hits: Vec<(&'static str, String)> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let run = &text[start..i]; // 纯 ASCII 数字, 切片安全
        let run_len = i - start;
        if want_phone && run_len == 11 && is_cn_mobile(run) {
            push_unique_pii(&mut hits, ("手机号", run.to_string()));
        } else if want_id && run_len == 18 && id_checksum_ok(run) {
            push_unique_pii(&mut hits, ("身份证", run.to_string()));
        } else if want_id && run_len == 17 {
            // 末位 X 型: 17 位数字后若紧跟 X/x, 凑 18 位验校验位。
            if let Some(&nb) = bytes.get(i) {
                if nb == b'X' || nb == b'x' {
                    let mut id18 = run.to_string();
                    id18.push(char::from(nb));
                    if id_checksum_ok(&id18) {
                        push_unique_pii(&mut hits, ("身份证", id18));
                    }
                }
            }
        }
    }
    hits
}

/// 打码: 手机 138****8000 (留头 3 尾 4); 身份证 1101**********001X (留头 4 尾 4); 其余留头尾各 2。
#[must_use]
pub fn mask_pii(kind: &str, value: &str) -> String {
    let (head, tail) = match kind {
        "手机号" => (3usize, 4usize),
        "身份证" => (4usize, 4usize),
        _ => (2usize, 2usize),
    };
    // 按**字符**(非字节)计数与切片: 号码全 ASCII 时 char==byte, 打码结果与旧码逐字节同; 但兜底档
    // (kind 非手机/身份证) 的 value 可能是非 ASCII 正文 —— 旧 `&value[..head]` 会切进 UTF-8 序列中段
    // 直接 panic, 且 `str` 越界 panic 文案会带上 ≤256B 原文 → 擦不掉的 PII 泄漏面 (logging §4.5-B②)。
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    if n <= head + tail {
        return "*".repeat(n);
    }
    let head_s: String = chars[..head].iter().collect();
    let tail_s: String = chars[n - tail..].iter().collect();
    let stars = "*".repeat(n - head - tail);
    format!("{head_s}{stars}{tail_s}")
}

/// pii-scan 一行命中: (create_time, conv_id, sender_wxid, 类别, 号码值)。
type PiiRow = (i64, String, Option<String>, &'static str, String);

/// 扫文本消息里疑似手机号/身份证号。返 (含PII的消息数, 手机命中数, 身份证命中数, 前 limit 条命中行)。
/// 只扫 msg_type=1 文本 (图片/视频等媒体消息的 text_content 是 XML, 里面 aeskey 会假冒号码 —
/// 真库实测: 不限类型时身份证误报 26361, 限文本后降到 133, 再过校验位 → 129 真号)。低层取数/扫描 (直测锁);
/// 打码/summary 组装由 [`pii_scan_query`] 承担。
pub fn query_pii_scan(
    conn: &rusqlite::Connection,
    kind: PiiKind,
    limit: usize,
) -> Result<(usize, usize, usize, Vec<PiiRow>)> {
    let want_phone = matches!(kind, PiiKind::All | PiiKind::Phone);
    let want_id = matches!(kind, PiiKind::All | PiiKind::Idcard);
    let mut st = conn.prepare(
        // R16-4: 单键 create_time 补次键 (source, source_native_id = 消息 PK 尾) → 同秒多命中消息序稳定,
        // 与热查 hot_pii_scan 的 sort (create_time/source/source_native_id DESC + 消息内 scan 序) 逐字节同 →
        // top-N 截断确定、冷热保序子序列对拍不错位。source/source_native_id 只进 ORDER BY 不进 SELECT (行输出不含)。
        "SELECT create_time, conv_id, sender_wxid, text_content \
         FROM message \
         WHERE msg_type = 1 AND text_content GLOB ?1 \
         ORDER BY create_time DESC, source DESC, source_native_id DESC",
    )?;
    let mut msgs_flagged = 0usize;
    let mut phone_total = 0usize;
    let mut id_total = 0usize;
    let mut rows: Vec<PiiRow> = Vec::new();
    let mut cursor = st.query([PII_GLOB11])?;
    while let Some(r) = cursor.next()? {
        let text: String = match r.get::<_, Option<String>>(3)? {
            Some(t) => t,
            None => continue,
        };
        let hits = scan_pii_in_text(&text, want_phone, want_id);
        if hits.is_empty() {
            continue;
        }
        msgs_flagged += 1;
        let ctime: i64 = r.get(0)?;
        let conv_id: String = r.get(1)?;
        let sender: Option<String> = r.get(2)?;
        for (k, v) in hits {
            if k == "手机号" {
                phone_total += 1;
            } else {
                id_total += 1;
            }
            if rows.len() < limit {
                rows.push((ctime, conv_id.clone(), sender.clone(), k, v));
            }
        }
    }
    Ok((msgs_flagged, phone_total, id_total, rows))
}

/// `pii-scan` 域出口: 扫号 + **按 `reveal` 决定 json `value` 打码/显全** (打码放核 → MCP/HTTP 与 CLI 隐私
/// 行为一致, 非只 CLI 皮打码)。**截断精确探 `has_more`** (`rows` 上限 limit; 总命中 = phone+idcard);
/// 命令特有汇总 (messages_flagged/phone_total/idcard_total/shown/masked) 收进 `meta.summary` (HOLE-3)。
pub fn pii_scan_query(conn: &rusqlite::Connection, kind: PiiKind, reveal: bool, limit: usize) -> Result<QueryResult> {
    let (msgs, phone_total, id_total, rows) = query_pii_scan(conn, kind, limit)?;
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, cv, s, k, v)| {
            let value = if reveal { v.clone() } else { mask_pii(k, v) };
            serde_json::json!({
                "create_time": ct, "conv_id": cv, "sender_wxid": s,
                "kind": k, "value": value
            })
        })
        .collect();
    // has_more 精确 (修 HOLE-2 漏网): 截断 (rows 上限 limit) 却无 has_more → 消费者静默漏 PII。
    // 总命中 = phone_total + id_total (每命中必计一类)。
    let has_more = rows.len() < phone_total + id_total;
    let meta = Meta::cold_page(has_more)
        .with_source(Source::Cold)
        .with_summary(serde_json::json!({
            "messages_flagged": msgs,
            "phone_total": phone_total,
            "idcard_total": id_total,
            "shown": rows.len(),
            "masked": !reveal,
        }));
    Ok(QueryResult { data, meta })
}

// ── extract (message 文本抽 url/email/amount/phone/idcard · summary) ──

/// extract 抽取类别 (clap `--kind`; 一次一类)。
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExtractKind {
    /// http(s) 链接 (文本内联, 区别于 links 的卡片链接)。
    Url,
    /// 邮箱地址。
    Email,
    /// 金额 (¥数字 / 数字元/块)。
    Amount,
    /// 手机号 (11 位号段; 不打码, 打码看 pii-scan)。
    Phone,
    /// 身份证号 (18 位过校验位; 不打码)。
    Idcard,
}

/// 类别 → 人话 (进 json `kind` 字段 + table 表头; 皮读此不重算)。
#[must_use]
pub fn extract_kind_label(kind: ExtractKind) -> &'static str {
    match kind {
        ExtractKind::Url => "链接",
        ExtractKind::Email => "邮箱",
        ExtractKind::Amount => "金额",
        ExtractKind::Phone => "手机号",
        ExtractKind::Idcard => "身份证",
    }
}

/// 编译某类抽取的正则 (phone/idcard 走手写扫描, 返 None)。
pub fn extract_regex(kind: ExtractKind) -> Result<Option<regex::Regex>> {
    let pat = match kind {
        ExtractKind::Url => r#"https?://[^\s"'<>）】]+"#,
        ExtractKind::Email => r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        ExtractKind::Amount => r"[¥￥]\s?[0-9]+(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?\s?[元块]",
        ExtractKind::Phone | ExtractKind::Idcard => return Ok(None),
    };
    Ok(Some(regex::Regex::new(pat).context("抽取正则编译失败")?))
}

/// 从一条文本抽某类的所有值 (消息内去重)。phone/idcard 复用手写扫描, 其余走正则。
#[must_use]
pub fn extract_matches(text: &str, kind: ExtractKind, re: Option<&regex::Regex>) -> Vec<String> {
    match kind {
        ExtractKind::Phone => scan_pii_in_text(text, true, false)
            .into_iter()
            .map(|(_, v)| v)
            .collect(),
        ExtractKind::Idcard => scan_pii_in_text(text, false, true)
            .into_iter()
            .map(|(_, v)| v)
            .collect(),
        _ => {
            let mut out: Vec<String> = Vec::new();
            if let Some(re) = re {
                for m in re.find_iter(text) {
                    let v = m.as_str().to_string();
                    if !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
            out
        }
    }
}

/// extract 一行: (create_time 毫秒, 日期, conv_id, sender_wxid, 抽出的值)。
type ExtractRow = (i64, String, String, Option<String>, String);

/// 抽取某类结构化信息 (只扫 msg_type=1 文本, 避 XML 噪音)。返 (命中消息数, 命中总数, 前 limit 行)。低层取数
/// (直测锁 SQL); json 预组/summary 组装由 [`extract_query`] 承担。
pub fn query_extract(
    conn: &rusqlite::Connection,
    kind: ExtractKind,
    limit: usize,
    offset: usize,
) -> Result<(usize, usize, Vec<ExtractRow>)> {
    let re = extract_regex(kind)?;
    // 各类的 SQL 预筛 (剪掉明显无关消息; amount 无廉价预筛→全文本扫)。
    let where_extra = match kind {
        ExtractKind::Url => "AND text_content LIKE '%http%'".to_string(),
        ExtractKind::Email => "AND text_content LIKE '%@%'".to_string(),
        ExtractKind::Amount => String::new(),
        ExtractKind::Phone | ExtractKind::Idcard => {
            format!("AND text_content GLOB '{PII_GLOB11}'")
        }
    };
    let sql = format!(
        "SELECT create_time, date(create_time/1000,'unixepoch','localtime'), conv_id, sender_wxid, text_content \
         FROM message WHERE msg_type = 1 {where_extra} ORDER BY create_time DESC, source DESC, source_native_id DESC"
    );
    let mut st = conn.prepare(&sql)?;
    let mut cursor = st.query([])?;
    let mut msgs = 0usize;
    let mut total = 0usize;
    let mut skipped = 0usize;
    let mut rows: Vec<ExtractRow> = Vec::new();
    while let Some(r) = cursor.next()? {
        let text: String = match r.get::<_, Option<String>>(4)? {
            Some(t) => t,
            None => continue,
        };
        let hits = extract_matches(&text, kind, re.as_ref());
        if hits.is_empty() {
            continue;
        }
        msgs += 1;
        total += hits.len();
        let ct: i64 = r.get(0)?;
        let day: String = r.get(1)?;
        let conv_id: String = r.get(2)?;
        let sender: Option<String> = r.get(3)?;
        for v in hits {
            // offset: 跨消息全局跳过前 offset 个命中, 再收 limit 个 → [offset, offset+limit) 切片 (深翻可达)。
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if rows.len() < limit {
                rows.push((ct, day.clone(), conv_id.clone(), sender.clone(), v));
            }
        }
    }
    Ok((msgs, total, rows))
}

/// `extract` 域出口: 抽结构化信息 + json 预组 (`kind` = `extract_kind_label`)。**截断精确探 `has_more`**;
/// 命令特有汇总 (messages_matched/total_matches/shown) 收进 `meta.summary` (HOLE-3)。
pub fn extract_query(
    conn: &rusqlite::Connection,
    kind: ExtractKind,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let (msgs, total, rows) = query_extract(conn, kind, limit, offset)?;
    let label = extract_kind_label(kind);
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(ct, day, conv, sender, v)| {
            serde_json::json!({
                "create_time": ct, "date": day, "conv_id": conv,
                "sender_wxid": sender, "kind": label, "value": v
            })
        })
        .collect();
    // offset_page: has_more = offset+shown < total (精确, 修 HOLE-2 漏网) + 带 total_count 让深翻可达 (审查 B D3)。
    let meta = Meta::offset_page(offset, rows.len(), total, limit)
        .with_source(Source::Cold)
        .with_summary(serde_json::json!({"messages_matched": msgs, "total_matches": total, "shown": rows.len()}));
    Ok(QueryResult { data, meta })
}

// ── money (transfer + red_envelope + group_pay 三表合并时间线 · §6③ 第五批) ──

/// money 统一行: (类型标签, 时间 unix秒/None, 主体人或会话, 明细文本, **合并次键**)。三类交易归一成一条时间线。
/// 末位次键 [`MoneyKey`] (R16-4): 内存归并按 (时间 DESC, 次键 DESC) 定**全序**, 令 offset 翻页跨页不重不漏
/// (详见 [`money_query`] 排序处 + 文件顶部"翻页稳定性"注)。json 出口丢弃 (只出前 4 元)。
type MoneyRow = (&'static str, Option<i64>, String, String, MoneyKey);

/// money 合并次键 (R16-4): 三源**统一取 PK 尾 `(source, source_native_id)`** —— 即 PRIMARY KEY 去掉遮蔽视图钉死
/// 的 account_id_sha, **唯一性直接源于 PK 约束**。为何三源统一 (**含红包也用 PK 尾, 而非 rowid**):
/// 1. **视图可用**: money 经 `--account`/HTTP account 参会走 `open_l1_scoped` 建 TEMP VIEW 遮蔽账号 → **视图无
///    rowid 伪列** (`r.rowid` 报 "no such column", scoped 下红包整条查询炸), 而 source/source_native_id 是真实列,
///    视图上照取 —— 故不能拿 rowid 当键 (原 `ORDER BY r.rowid` 在 scoped 下本就 broken, 见 money_paging_tests 的
///    scoped 守卫测)。
/// 2. **跨源全局唯一**: source_native_id 带类型前缀 (`Transfer_…`/`GroupPay_…`/`RedEnvelope_…`, 真库实测三表两两
///    交集 0) → 跨源同 time 并列也靠它全序确定, **不赌插入序 + 稳定排序**。
/// 3. **与各源 SQL `ORDER BY` 尾逐列同向 (DESC)** → 归并全序与各源取数序吻合, 保住"合并 top-N ⊆ 各源 top-N"。
///
/// 红包无自带时间戳 → time=None **恒排末尾**; 原 `rowid DESC` 是"新→旧"近似, 改 source_native_id DESC 同为该近似
/// 且键更稳 (PK durable, rowid 随 VACUUM 变)。实测本类源自 general.db 专表 (非 message 分片, source 恒 'general.db',
/// transfer 2239 / red_envelope 601 / group_pay 11), source_native_id 本已够唯一; 取全 PK 尾对 source 基数零假设。
type MoneyKey = (String, String);

/// money 交易类型选择 (clap `--kind`; CLI 皮 flatten 复用同一枚举, MCP/HTTP 皮直接构造)。
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MoneyKind {
    /// 三类都列 (合并按时间倒序; 红包无本地时间戳→排末尾, 常被 -n 截断看不到, 单看红包用 --kind red-envelope)。
    All,
    /// 只转账。
    Transfer,
    /// 只红包。
    RedEnvelope,
    /// 只群收款。
    GroupPay,
}

/// 查转账 (金额靠 transfer.transcation_id == message_app.transfer_txid 关联; 无匹配消息则出状态码)。返 (行, 真总数)。
///
/// 键说明 (真库实测坐实): 交易号是同一个 32 位串 (`5301000X`+日期+流水), 两边都存 → 直接对; 早先误用
/// `message_server_id==message.server_id` 是错的 (两者不同 id 空间, 真库 2186 条只命中 10)。
/// baked 明细串 (`"{payer} → {receiver}"` / `"(金额见消息) 状态码{sub}"`) 在此产出 → json 携出、table 读回。
pub fn query_transfers(conn: &rusqlite::Connection, limit: usize) -> Result<(Vec<MoneyRow>, usize)> {
    let total: i64 = conn.query_row("SELECT count(*) FROM transfer", [], |r| r.get(0))?;
    let mut st = conn.prepare(
        "SELECT t.begin_transfer_time, t.pay_payer, t.pay_receiver, t.pay_sub_type, \
           (SELECT a.transfer_fee FROM message_app a \
            WHERE a.account_id_sha = t.account_id_sha AND a.transfer_txid = t.transcation_id \
              AND a.transfer_fee IS NOT NULL LIMIT 1), \
           t.source, t.source_native_id \
         FROM transfer t \
         ORDER BY t.begin_transfer_time DESC, t.source DESC, t.source_native_id DESC LIMIT ?1",
    )?;
    let rows: Vec<MoneyRow> = st
        .query_map([limit as i64], |r| {
            let time: i64 = r.get(0)?;
            let payer: String = r.get(1)?;
            let receiver: String = r.get(2)?;
            let sub: i64 = r.get(3)?;
            let fee: Option<String> = r.get(4)?;
            let source: String = r.get(5)?;
            let snid: String = r.get(6)?;
            let detail = fee.unwrap_or_else(|| format!("(金额见消息) 状态码{sub}"));
            Ok((
                "转账",
                Some(time),
                format!("{payer} → {receiver}"),
                detail,
                (source, snid),
            ))
        })?
        .filter_map(ok_or_warn)
        .collect();
    Ok((rows, usize::try_from(total).unwrap_or(0)))
}

/// 查红包 (金额微信本地不存=微信设计; 红包表无自带时间戳 + 关联消息的 server_id 键不可靠 → time=None,
/// 按 rowid 倒序≈落库新→旧; 出发送人/会话/类型码/状态码)。返 (行, 真总数)。
pub fn query_red_envelopes(conn: &rusqlite::Connection, limit: usize) -> Result<(Vec<MoneyRow>, usize)> {
    let total: i64 = conn.query_row("SELECT count(*) FROM red_envelope", [], |r| r.get(0))?;
    let mut st = conn.prepare(
        "SELECT r.sender_user_name, r.session_name, r.hb_type, r.receive_status, r.source, r.source_native_id \
         FROM red_envelope r ORDER BY r.source DESC, r.source_native_id DESC LIMIT ?1",
    )?;
    let rows: Vec<MoneyRow> = st
        .query_map([limit as i64], |r| {
            let sender: String = r.get(0)?;
            let session: String = r.get(1)?;
            let hb_type: i64 = r.get(2)?;
            let recv: i64 = r.get(3)?;
            let source: String = r.get(4)?;
            let snid: String = r.get(5)?;
            let detail = format!("类型码{hb_type}/状态码{recv} @{session} (金额本地不存)");
            // 次键 = PK 尾 (source, source_native_id); 红包 time=None 恒末尾, 只与红包互比。**不用 rowid**:
            // rowid 在 scoped 遮蔽视图上不存在 (原 `ORDER BY r.rowid` scoped 下即炸); source_native_id 是真实列
            // 视图可取且带 `RedEnvelope_` 前缀跨源唯一。source_native_id DESC ≈ 落库新→旧 (同原 rowid DESC 语义)。
            Ok(("红包", None, sender, detail, (source, snid)))
        })?
        .filter_map(ok_or_warn)
        .collect();
    Ok((rows, usize::try_from(total).unwrap_or(0)))
}

/// 查群收款 (金额 JOIN message_app.group_pay_amount via bill_no; 已付/总人数 = group_pay_member 计数)。返 (行, 真总数)。
pub fn query_group_pays(conn: &rusqlite::Connection, limit: usize) -> Result<(Vec<MoneyRow>, usize)> {
    let total: i64 = conn.query_row("SELECT count(*) FROM group_pay", [], |r| r.get(0))?;
    let mut st = conn.prepare(
        "SELECT g.message_create_time, g.session_name, \
           (SELECT a.group_pay_amount FROM message_app a \
            WHERE a.account_id_sha = g.account_id_sha AND a.group_pay_bill_no = g.bill_no \
              AND a.group_pay_amount IS NOT NULL LIMIT 1), \
           (SELECT count(*) FROM group_pay_member mm \
            WHERE mm.account_id_sha = g.account_id_sha AND mm.bill_no = g.bill_no AND mm.pay_status = 1), \
           (SELECT count(*) FROM group_pay_member mm \
            WHERE mm.account_id_sha = g.account_id_sha AND mm.bill_no = g.bill_no), \
           g.source, g.source_native_id \
         FROM group_pay g \
         ORDER BY g.message_create_time DESC, g.source DESC, g.source_native_id DESC LIMIT ?1",
    )?;
    let rows: Vec<MoneyRow> = st
        .query_map([limit as i64], |r| {
            let time: i64 = r.get(0)?;
            let session: String = r.get(1)?;
            let amount: Option<String> = r.get(2)?;
            let paid: i64 = r.get(3)?;
            let payers: i64 = r.get(4)?;
            let source: String = r.get(5)?;
            let snid: String = r.get(6)?;
            let detail = format!("{} 已付{paid}/{payers}人", amount.as_deref().unwrap_or("(金额?)"));
            Ok(("群收款", Some(time), session, detail, (source, snid)))
        })?
        .filter_map(ok_or_warn)
        .collect();
    Ok((rows, usize::try_from(total).unwrap_or(0)))
}

/// `money` 域出口: 三类交易 (转账/红包/群收款) 合并成一条时间线 (读 L1; 只读)。**默认档** —— `--claims`/`--payers`
/// 子视图走引擎 `CMD_HONGBAO`/`CMD_GROUP_PAY_MEMBERS`, 由皮层拦在调本函数之前 (不在此)。`kind` 选源 (all/单类);
/// 各源子查带**自己的真 `COUNT`**, **`total_count` = 被选源真 COUNT 之和** (走 `Meta::page`, 与旧 `cmd_money`
/// 累加逐字节同)。合并后按 (时间 DESC, [`MoneyKey`] 次键 DESC) 定**全序** (红包 None 甩末尾) 再 skip/take 分页 —— 稳定次键
/// (R16-4) 令 offset 跨页不重不漏。各子查缺表 → `needs_ingest_err` 补 ingest 提示 (随查迁核)。
pub fn money_query(conn: &rusqlite::Connection, kind: MoneyKind, limit: usize, offset: usize) -> Result<QueryResult> {
    let want = |k: MoneyKind| kind == MoneyKind::All || kind == k;
    // ④ offset: 各源须取到**合并后前 offset+limit** 才够 skip(offset).take(limit) —— 故每源 fetch limit+offset
    // (合并 top-N 必落在各源 top-N 之内)。total = 各选源真 COUNT 之和 (不变)。
    let fetch = limit.saturating_add(offset);
    let mut rows: Vec<MoneyRow> = Vec::new();
    let mut total = 0usize;
    if want(MoneyKind::Transfer) {
        let (r, t) = query_transfers(conn, fetch)
            .context("查 transfer 表失败")
            .map_err(|e| crate::needs_ingest_err(e, "先跑 `msgvestige ingest --transfers` 导入转账表"))?;
        rows.extend(r);
        total += t;
    }
    if want(MoneyKind::RedEnvelope) {
        let (r, t) = query_red_envelopes(conn, fetch)
            .context("查 red_envelope 表失败")
            .map_err(|e| crate::needs_ingest_err(e, "先跑 `msgvestige ingest --red-envelopes` 导入红包表"))?;
        rows.extend(r);
        total += t;
    }
    if want(MoneyKind::GroupPay) {
        let (r, t) = query_group_pays(conn, fetch)
            .context("查 group_pay 表失败")
            .map_err(|e| crate::needs_ingest_err(e, "先跑 `msgvestige ingest --group-pays` 导入群收款表"))?;
        rows.extend(r);
        total += t;
    }
    // 合并后定**全序**再切片 (R16-4)。主键: 时间 DESC (`b.1.cmp(&a.1)`: Option None<Some → Some 大者在前,
    // None=红包 沉末尾); 同时间破并列: 次键 [`MoneyKey`]=(source, source_native_id) DESC (`b.4.cmp(&a.4)`, 方向
    // 与各源 SQL `ORDER BY` 尾一致 → 保住"合并 top-N ⊆ 各源 top-N"; snid 带类型前缀跨源全局唯一 → 全序确定,
    // 令 offset 跨页不重不漏)。**非** `sort_by_key(Reverse(time))` 单键稳定排序 —— 那把跨页定序寄托于插入序 +
    // 稳定排序 (脆: 改 `sort_unstable` / 重排 `want` 分支即破), 显式唯一次键才自足。
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.4.cmp(&a.4)));
    let rows: Vec<MoneyRow> = rows.into_iter().skip(offset).take(limit).collect();
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|(k, t, w, d, _)| serde_json::json!({"kind": k, "time": t, "who": w, "detail": d}))
        .collect();
    // R9 复审R3#5 双审注记: 本命令是唯一"total=各源全量 COUNT(丢行前) + 分页在内存 skip(offset) 于 ok_or_warn 丢行之后"
    // 的 offset_page 点。**健康数据无假阳** (无丢行 → shown=min(limit,total-offset) 恒成立, dropped=0; 已双审逐例证)。
    // 坏数据下 (transfer/red_envelope/group_pay 真有坏行): dropped_rows **聚合数正确** (共丢几行), 但因内存归并后
    // 才切片, 缺口浮现在**末页**而非坏行物理页 —— 位置归属不精确 (SQL-LIMIT/OFFSET 的点无此: SQLite 先 OFFSET 再页内丢)。
    // 作"结果不完整"信号足够 (总量对); 位置精确非必需, 不值为坏数据边界加复杂度。
    let meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

// ── contacts (person keyset 游标分页 · §6③ 第五批) ──

/// contacts 查询行: (username, nick_name, remark, alias, local_type)。
type ContactRow = (String, Option<String>, Option<String>, Option<String>, i64);

/// `contacts` 域出口: 查 / 搜联系人 (读 L1 person 表; **keyset 游标分页**, 只读)。
///
/// 排序键 = `username` (person 主键, **唯一** → 自身即 tiebreaker; ASC)。`q` 在 昵称/备注/微信号/wxid
/// 子串过滤。游标绑 (库路径指纹 + 过滤指纹): 换库/换 `q` 的旧游标 decode 不过 → INVALID_CURSOR。
/// ④ 游标分页 → 信封走 [`Meta::cursor_page`] (next_cursor + limit, **省略 total_count**, §6)。
/// `l1_db_path` 只为算 `acct` 位: ③ 多账号前, 用 L1 库路径 `sha8` 当 account 位 (**③b 前占位**, 未接真
/// account_id_sha — 换真值是 ③b, 此处不动)。**`InvalidCursor` (CliError) 原样上抛不加 context** —— 否则
/// classify downcast 不到 CliError → 误归 INTERNAL/70 (退出码从 2 漂到 70); 仅给通用错补排查 hint。
pub fn contacts_query(
    conn: &rusqlite::Connection,
    l1_db_path: &str,
    account_sha: Option<&str>,
    q: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<QueryResult> {
    // q → 子串过滤 (?1 复用 4 次; 参数化避免注入)。
    let filter: Option<(&str, Vec<rusqlite::types::Value>)> = q.map(|s| {
        (
            "username LIKE '%'||?1||'%' OR nick_name LIKE '%'||?1||'%' \
             OR remark LIKE '%'||?1||'%' OR alias LIKE '%'||?1||'%'",
            vec![rusqlite::types::Value::Text(s.to_string())],
        )
    });
    // 游标绑定: 过滤指纹 (命令+q) + 账号位。③b: 有 --account → 用 account_id_sha 当账号位 (账号专属游标,
    // 跨账号 decode 不过, 与遮蔽视图的隔离对齐); 无 → L1 库路径指纹占位 (单账号, 同库游标互通)。
    let fh = crate::paginate::filter_hash(&["contacts", &format!("q={}", q.unwrap_or(""))]);
    let acct = account_sha.map_or_else(
        || common::redact::sha8(l1_db_path.as_bytes()),
        std::string::ToString::to_string,
    );
    // ③b tiebreaker 必须是 schema 唯一键 (审查 P1-4): person PK=(account_id_sha, source, username_sha),
    // **username 非唯一** —— 同 wxid 可跨 source 两行 (contact.db / contact.db|stranger, --strangers 已是
    // 发货路径)。单用 username 当 tiebreaker → 跨页边界严格 `>` 把并列 username 整片跳过 → 静默丢联系人
    // (复现 anchor 688→98)。scoped 下 account_id_sha 固定 → (username, source) 即唯一 → 用 source 作末列
    // tiebreaker (source 是 PK 成员, NOT NULL, 满足 keyset 非空约束)。
    let spec = crate::paginate::KeysetSpec::new(
        vec![crate::paginate::SortCol::text("username")],
        crate::paginate::SortCol::text("source"),
        crate::paginate::SortDir::Asc,
    );

    let page = crate::paginate::paginate(
        conn,
        &["username", "nick_name", "remark", "alias", "local_type"],
        "person",
        filter,
        &spec,
        limit,
        cursor,
        &acct,
        &fh,
        |r| Ok::<ContactRow, rusqlite::Error>((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    // 携码错 (CliError, 如 InvalidCursor→退出2) 原样上抛, **不加 context** —— 否则包一层 classify
    // downcast 不到 CliError → 误归 INTERNAL/70。仅给通用错 (打库/SQL) 补排查 hint。
    .map_err(|e| {
        if e.downcast_ref::<crate::CliError>().is_some() {
            e
        } else {
            e.context("查 person 表失败 (库是 ingest 产出的 L1?)")
        }
    })?;

    let data: Vec<serde_json::Value> = page
        .rows
        .iter()
        .map(|(u, n, r, a, lt)| {
            serde_json::json!({"username": u, "nick_name": n, "remark": r, "alias": a, "local_type": lt})
        })
        .collect();
    let mut meta = Meta::cursor_page(page.has_more, page.next_cursor, limit as u64).with_source(Source::Cold);
    if let Some(sha) = account_sha {
        meta.account = Some(sha[..8].to_string());
    }
    Ok(QueryResult { data, meta })
}

// ── §6③ specials: exec / inspect / resolve / search ──

// ---- exec (原生只读 SQL, 动态列) ----

/// 判用户 SQL 是否**只读安全** (SELECT/WITH/EXPLAIN 前缀 + 无分号分隔多语句)。exec 皮在 `open_l1` **前**
/// 调它拒写 (坏 SQL 不打库即 BAD_REQUEST/2)。移核只为直测 + 三皮复用; 守卫**仍在皮层 pre-check** (需在开库
/// 前拒, 与 "写 SQL → NOT_FOUND-before-open" 契约一致)。
#[must_use]
pub fn is_readonly_sql(sql: &str) -> bool {
    let t = sql.trim().trim_end_matches(';').trim();
    if t.contains(';') {
        return false; // 多语句 (防夹带写操作)。**保守**: 字符串字面量里的 ';' 也拒 —— 安全侧过拒, 用户避开即可 (审查 C EXEC-REJECT-WS 接受)。
    }
    let up = t.to_uppercase();
    // 首关键字须是**完整词** (后接空白/结束/非词字符如 * ( ) —— 原 `starts_with("SELECT ")` 要求空格,
    // 把 `SELECT\n` / `SELECT\t` / `SELECT*` 误判成写 → 400; 审查 C EXEC-REJECT-WS 修)。
    let first_kw = |kw: &str| {
        up.strip_prefix(kw)
            .is_some_and(|rest| rest.is_empty() || !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
    };
    first_kw("SELECT") || first_kw("WITH") || first_kw("EXPLAIN")
}

/// rusqlite Value → 展示串 (BLOB 只报字节数, 不倒原始字节)。exec/inspect table 皮逐格渲染用。
#[must_use]
pub fn sql_value_display(v: &rusqlite::types::Value) -> String {
    use rusqlite::types::Value;
    match v {
        Value::Null => "(null)".to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        Value::Text(s) => s.clone(),
        Value::Blob(b) => format!("<{} 字节 BLOB>", b.len()),
    }
}

/// rusqlite Value → serde_json Value (BLOB 报字节数)。exec json / inspect `fetch_row` 预组用。
#[must_use]
pub fn sql_value_json(v: &rusqlite::types::Value) -> serde_json::Value {
    use rusqlite::types::Value;
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Integer(i) => serde_json::json!(i),
        Value::Real(f) => serde_json::json!(f),
        Value::Text(s) => serde_json::json!(s),
        Value::Blob(b) => serde_json::json!(format!("<{} 字节 BLOB>", b.len())),
    }
}

/// 跑一条只读 SQL, 取回 (列名, 行 (每行是各列 Value), 是否被 max_rows 截断)。
/// 动态列 (编译期不知 schema); 调用方须先过 [`is_readonly_sql`] 校验。**有序** cols/行 → table 皮读它保 SQL 列序。
pub fn run_exec_query(
    conn: &rusqlite::Connection,
    sql: &str,
    max_rows: usize,
) -> Result<(Vec<String>, Vec<Vec<rusqlite::types::Value>>, bool)> {
    // 审查 C EXEC-DOS-MEM: 单值 + 累计字节界 (const 提到 fn 顶避 items-after-statements)。max_rows 只限**行数**,
    // 单行多列大 BLOB (randomblob(1e9)×N) 会先 materialize 撑爆内存 → 下面 get_ref 探字节数 (零拷贝) 超限即拒。
    const MAX_VALUE_BYTES: usize = 8 * 1024 * 1024; // 单格 ≤8MB
                                                    // 审查 C round4: 此界是 **raw ValueRef 字节** 预算 (值 + 列名 + 每格开销)。实际进程峰值再乘**有界常数**
                                                    // (from_utf8_lossy 非法UTF8 ≤3× / json 序列化转义 NUL/控制符 ≤6×; into_iter 已消 2× 共存)。降到 64MB, 叠
                                                    // post_exec 的**并发上限 4** → 全局 exec RAM 有界 (无界放大类 round1-3 已尽, 剩有界常数由并发闸兜)。
    const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024; // raw 字节预算 ≤64MB (进程峰值 = 此 × 有界常数 × 并发4)
                                                     // 审查 C round3 Finding A/B: 预算须含**列名** (exec_query 逐行 clone 列名, 别名可 ~2MB × 行数放大 OOM) +
                                                     // **每格固定结构开销** (Value enum + 槽; 宽整数结果集 2000列×1万行 全不计破承诺) —— 非只算 value text/blob 字节。
    const PER_CELL_OVERHEAD: usize = 64; // 每格 owned Value + Vec/Map 槽保守估
                                         // 用户自写 SQL 的语法/表名/列名错 = 用户输入错 → BAD_REQUEST/2 (与 write/multi 拒绝一致);
                                         // 且**先于**集中兜底 (否则 "no such table" 会被误判成 NEEDS_INGEST —— exec 是裸 SQL, 表不存在是用户写错)。
    let mut st = conn.prepare(sql).map_err(|e| {
        crate::cli_err(
            native_core::ErrorCode::BadRequest,
            format!("SQL 预编译失败 (检查语法 / 表名 / 列名 / 是否被只读策略拒): {e}"),
        )
    })?;
    let cols: Vec<String> = st.column_names().iter().map(|s| (*s).to_string()).collect();
    let ncol = cols.len();
    let colname_bytes: usize = cols.iter().map(String::len).sum(); // 下游 exec_query 逐行 clone → 计入预算。
                                                                   // 审查 R7-P1 (单行**宽度**内存放大): SQLite `step()` 在 OP_ResultRow 把一行**所有列**一次性物化进寄存器
                                                                   // (`SELECT randomblob(8MB)×2000` = 单行 ~16GB), **早于**下面逐格 get_ref 的累计界 —— 那是物化**后**的 Rust 侧
                                                                   // 检查, 拦不住 SQLite 自身的峰值分配。单值 8MB 界 (exec_hardened set_limit) 只封"一格", 封不住"列数"。故按列数把
                                                                   // 单值界收紧到 min(8MB, 64MB/ncol) —— 令一行总物化 ≤ MAX_TOTAL_BYTES 预算, 从 SQLite **源头** (step 前 set_limit)
                                                                   // 封宽行 (超即构造期 SQLITE_TOOBIG → map_user_sql_err → BadRequest); 窄查询 (ncol ≤ 8) 仍得满 8MB/值。set_limit
                                                                   // 在 prepare **后** (需 ncol) query **前** 调, 对随后 step 的 randomblob 构造生效; st 与 conn 皆共享借用, 共存合法。
                                                                   // checked_div: ncol=0 (无列, SELECT 不会出现) → 退满 8MB/值 (无列可限, 无害); 否则 min(8MB, 64MB/ncol)。
    let per_value_cap = i32::try_from(
        MAX_TOTAL_BYTES
            .checked_div(ncol)
            .map_or(MAX_VALUE_BYTES, |b| b.min(MAX_VALUE_BYTES)),
    )
    .unwrap_or(i32::MAX)
    .max(1);
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, per_value_cap);
    // 审查 C EXEC-ERRCODE-500: step 期错 (含 authorizer 执行期拒 / 禁用函数) 也是**用户 SQL 错** → BadRequest(4xx),
    // 非 raw rusqlite 错落 classify_error 的 Internal(500) (那会让第三方误判服务端故障 + 攻击者零成本刷 5xx 告警)。
    let mut cursor = st.query([]).map_err(map_user_sql_err)?;
    let mut out_rows: Vec<Vec<rusqlite::types::Value>> = Vec::new();
    let mut truncated = false;
    let mut total_bytes = 0usize;
    while let Some(row) = cursor.next().map_err(map_user_sql_err)? {
        if out_rows.len() >= max_rows {
            truncated = true;
            break;
        }
        // 本行内存预算: 列名 (下游逐行 clone) + 各格 (值字节 + 固定开销)。任一步超界即拒 (在 materialize 前/中拦)。
        total_bytes = total_bytes.saturating_add(colname_bytes);
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(crate::cli_err(
                native_core::ErrorCode::BadRequest,
                format!("结果过大 (>{MAX_TOTAL_BYTES} 字节); 缩小 max_rows / 减列 / 用 length()"),
            ));
        }
        let mut vals = Vec::with_capacity(ncol);
        for i in 0..ncol {
            let vref = row.get_ref(i).map_err(map_user_sql_err)?;
            let sz = match vref {
                rusqlite::types::ValueRef::Blob(b) => b.len(),
                rusqlite::types::ValueRef::Text(t) => t.len(),
                _ => 0,
            };
            if sz > MAX_VALUE_BYTES {
                return Err(crate::cli_err(
                    native_core::ErrorCode::BadRequest,
                    format!("单值过大 ({sz} 字节 > {MAX_VALUE_BYTES}); 用 length()/substr() 取摘要"),
                ));
            }
            total_bytes = total_bytes.saturating_add(sz.saturating_add(PER_CELL_OVERHEAD));
            if total_bytes > MAX_TOTAL_BYTES {
                return Err(crate::cli_err(
                    native_core::ErrorCode::BadRequest,
                    format!("结果过大 (>{MAX_TOTAL_BYTES} 字节); 缩小 max_rows / 减列 / 用 length()"),
                ));
            }
            vals.push(value_ref_to_owned(vref));
        }
        out_rows.push(vals);
    }
    Ok((cols, out_rows, truncated))
}

/// 用户 SQL 的 step 期 rusqlite 错 → `BadRequest` (客户端错; 审查 C EXEC-ERRCODE-500)。
/// (by-value: 作 `.map_err(map_user_sql_err)` 的 fn 指针须收 `Error` 值。)
#[allow(clippy::needless_pass_by_value)]
fn map_user_sql_err(e: rusqlite::Error) -> anyhow::Error {
    crate::cli_err(
        native_core::ErrorCode::BadRequest,
        format!("SQL 执行失败 (用户 SQL / 被只读策略拒): {e}"),
    )
}

/// `ValueRef` → owned `Value` (字节界检**之后**调, 巨值已拒)。显式 match 免依赖 From impl。
fn value_ref_to_owned(v: rusqlite::types::ValueRef<'_>) -> rusqlite::types::Value {
    use rusqlite::types::{Value, ValueRef};
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::Integer(i),
        ValueRef::Real(f) => Value::Real(f),
        ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::Blob(b.to_vec()),
    }
}

/// `exec` 域出口: 跑只读 SQL → `QueryResult` (json 皮用)。**动态列** → 每行 `serde_json::Map` (列名→值,
/// BLOB 报字节数; Map 按键名排序, 非 SQL 列序 —— 机器按键取值不违约)。**has_more = 命中 max_rows 截断**
/// (exec 已知真值), raw SQL 无廉价全量 → `Meta::cold_page` (省 total_count)。**只读守卫由调用方 pre-check**
/// ([`is_readonly_sql`], 见其文档) —— 本函数假定 SQL 已过校验 (与 [`run_exec_query`] 契约一致)。
/// **table 皮不走此** —— 走 [`run_exec_query`] 的有序 cols/行保 SQL 列序 (排序 Map 丢列序)。
pub fn exec_query(conn: &rusqlite::Connection, sql: &str, max_rows: usize) -> Result<QueryResult> {
    let (cols, out_rows, truncated) = run_exec_query(conn, sql, max_rows)?;
    // 审查 C round4: **消费** out_rows (into_iter) 而非借用 —— 边建 data 边释放 out_rows, 峰值 ~1× 非 2× 共存。
    let data: Vec<serde_json::Value> = out_rows
        .into_iter()
        .map(|r| {
            let mut obj = serde_json::Map::new();
            for (name, v) in cols.iter().zip(r.into_iter()) {
                obj.insert(name.clone(), sql_value_json(&v));
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    // HOLE-2: has_more = 命中 --max-rows 截断 (exec 已知的真值); raw SQL 无廉价全量 → 省略 total_count。
    let meta = Meta::cold_page(truncated).with_source(Source::Cold);
    Ok(QueryResult { data, meta })
}

/// **硬只读 exec 共享入口** (R7/⑪) —— HTTP `/exec` 与 MCP `wx_exec` **同一份**安全码 (复制两份=将来分叉:
/// 改一处漏另一处 → 安全洞)。顺序 = 硬只读三层 + DoS 界, 全在此**一处**收口:
/// 1. [`is_readonly_sql`] 字符串预检 (**开库前**拒明显写/多语句)。防御纵深 —— 皮层通常已 pre-check (需在开库前拒
///    以对齐 "写 SQL → 不打库即 BAD_REQUEST" 契约), 此处再兜一道保证共享入口**自足安全** (任何漏检的调用方也挡)。
/// 2. `SQLITE_OPEN_READ_ONLY` 连接 —— 挡一切写, 含 is_readonly_sql 字符串检漏过的 WITH-前缀写。
/// 3. authorizer 白名单 (拒 ATTACH[任意文件读逃逸]/PRAGMA/其余 readonly 挡不住的逃逸) + `set_limit`(单值 8MB,
///    从 SQLite 源头封 randomblob 类分配) + progress 15s 界 (掐笛卡尔积/递归 CTE 的无界算力), 再跑 [`exec_query`]。
///
/// **打 L1 全库 (非 scoped)** —— 裸 SQL 逃生口; 多账号库跨账号读由调用方/操作者自负 (镜像 HTTP `/exec` 契约)。
/// **CPU 隔离 (spawn_blocking) 由调用方负责** —— 本函数**同步阻塞** (含 progress 15s 前的算力), 皮层须放阻塞池跑
/// (serve 是 current_thread runtime / MCP 是 stdio 单进程 —— 同步 SQL 若在 async 线程跑会冻死整皮)。
pub fn exec_hardened(l1_path: &str, sql: &str, max_rows: usize) -> Result<QueryResult> {
    // 层2: 只读连接 (SQLITE_OPEN_READ_ONLY 挡一切写)。URI 标志与 HTTP 原实现一致 (允许 file: URI 形式路径)。
    let conn = rusqlite::Connection::open_with_flags(
        l1_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;
    // 层 1+3a+3b+3c 委托 exec_hardened_conn (与热 VFS exec 共用同一套硬只读+DoS界)。
    exec_hardened_conn(&conn, sql, max_rows)
}

/// exec 加固 (**层 1 + 3a + 3b + 3c**) on 一个**已开好**的连接 —— 冷 L1 只读连接 [`exec_hardened`] 与热 VFS 源库连接
/// [`exec_hardened_vfs`] **复用同一套硬只读 + DoS 界** (R16-6 exec 冷热双模, 一份安全码)。**不含层 2(开库)**: 调用方
/// 负责传入只读 / VFS 连接。CPU 隔离 (spawn_blocking) 同样由调用方负责 (本函数同步阻塞含 progress 15s 前的算力)。
pub fn exec_hardened_conn(conn: &rusqlite::Connection, sql: &str, max_rows: usize) -> Result<QueryResult> {
    // 层1: 字符串预检 (拒明显写/多语句)。防御纵深 —— 皮层 pre-check 若漏, 此处兜住; 消息与皮层一致。
    if !is_readonly_sql(sql) {
        return Err(crate::cli_err(
            native_core::ErrorCode::BadRequest,
            "只读 exec 仅允许单条 SELECT/WITH/EXPLAIN (无写操作, 无多语句 ';')",
        ));
    }
    // 层3a: authorizer 白名单 (拒 ATTACH[任意文件读逃逸]/PRAGMA/其余; readonly / VFS 连接都挡不住 ATTACH 读别的库)。
    conn.authorizer(Some(exec_authorizer));
    // 层3b (DoS-内存): SQLite **源头**限单值 8MB —— run_exec_query 的 get_ref 字节界只挡 Rust 侧拷贝, 但 SQLite
    // VDBE 在 step() 内 OP_ResultRow 就把 randomblob(1e9)×N 全量分配 (早于 get_ref) → 整进程 OOM; `SELECT
    // length(randomblob(1e9))` 更绕过 Rust 字节界 (结果只是小整数)。SQLITE_LIMIT_LENGTH 令超 8MB 在**构造期**即错。
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 8 * 1024 * 1024);
    // 层3c (DoS-算力): 每 ~1e5 VM 步回调, 超 15s 墙钟即中断 (SQLITE_INTERRUPT)。max_rows 只限**行数**; 笛卡尔积/
    // 聚合/递归 CTE 在产出首行前就把全量算完, 行数界失效 —— progress_handler 是唯一能掐无界算力的闸。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    conn.progress_handler(100_000, Some(move || std::time::Instant::now() > deadline));
    exec_query(conn, sql, max_rows)
}

/// 热 exec (**R16-6**): 开**已解密的 VFS 源库**连接后走 [`exec_hardened_conn`] —— 直接对原始加密库跑只读 SQL, 裸
/// schema (`Msg_<md5>` 哈希表名 / `Name2Id` / 裸 `contact` 表 等, 与 L1 投影 schema 完全不同; 专家向, 配原始表名对照)。
/// 源库经 SQLCipher VFS **按需解密** (页级, 不整库落地), 连接本身写会失败 + authorizer/is_readonly 双挡写。
///
/// **`source_db` 路径安全**: 调用方 (皮层) **必须**把它限制在该账号的 `db_storage/` 下 (校验无 `..` / 不逃逸), 否则
/// `open_decrypted_db_vfs` 会拿任意路径当库开 —— 本函数只负责"开+跑", 不做路径校验。
pub fn exec_hardened_vfs(
    source_db: &std::path::Path,
    key: &native_core::MasterKey,
    sql: &str,
    max_rows: usize,
) -> Result<QueryResult> {
    // 层2': VFS 开库 (按需解密源库)。开库失败 (key 不对 / 非 SQLCipher 库 / 路径不存在) → BadRequest。
    let conn = native_core::cipher::open_decrypted_db_vfs(source_db, key).map_err(|e| {
        crate::cli_err(
            native_core::ErrorCode::BadRequest,
            format!("打开源库失败 (key 不对 / 不是 SQLCipher 库 / 路径不对?): {e}"),
        )
    })?;
    exec_hardened_conn(&conn, sql, max_rows)
}

/// exec authorizer (硬只读第 3 层): 放行读 (Select / Read 列访问 / Function SQL 内建如 count/date/substr) +
/// **Recursive** (递归 CTE 是合法只读, 其算力已由 progress_handler 15s 界兜; 原漏放行会把 `WITH RECURSIVE`
/// 序列/层级遍历全误杀)。其余 (ATTACH / DETACH / PRAGMA / 写 / DDL / 事务 / …) 一律 Deny。**默认拒 + 白名单放行**。
fn exec_authorizer(ctx: rusqlite::hooks::AuthContext) -> rusqlite::hooks::Authorization {
    use rusqlite::hooks::{AuthAction, Authorization};
    match ctx.action {
        AuthAction::Select | AuthAction::Read { .. } | AuthAction::Function { .. } | AuthAction::Recursive => {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

// ---- inspect (类型消歧单行) ----

/// inspect 的实体类型 —— 决定查哪张表 + key 列 (解 person↔session 同 wxid 歧义)。
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum InspectType {
    /// 联系人 (person 表, key=username)。
    Contact,
    /// 群 (chatroom 表, key=chatroom_id)。
    Chatroom,
    /// 会话 (session 表, key=username; 与 contact 同 wxid 但不同表)。
    Session,
    /// 消息 (message 表, key=source_native_id)。
    Message,
}

impl InspectType {
    /// (表名, key 列) —— 均固定字面量, 非用户输入。
    #[must_use]
    pub fn table_key(self) -> (&'static str, &'static str) {
        match self {
            Self::Contact => ("person", "username"),
            Self::Chatroom => ("chatroom", "chatroom_id"),
            Self::Session => ("session", "username"),
            Self::Message => ("message", "source_native_id"),
        }
    }
}

/// serde_json Value → 表格展示串 (Null→(null), 字符串原样含 BLOB 的 "<N 字节>", 数值 to_string)。
/// inspect table 皮读 [`fetch_row`] 的有序列渲染用。
#[must_use]
pub fn json_value_display(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "(null)".to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// 取单行全列 → 有序 (列名, JSON 值) 对 (BLOB 报字节数); 无则 None。
/// table/key_col 固定字面量 (非用户输入), key_val 参数绑定防注入。**有序** Vec 保 schema 列序 (inspect table
/// 皮逐列渲染读它; json 皮 collect 成排序 Map)。
pub fn fetch_row(
    conn: &rusqlite::Connection,
    table: &str,
    key_col: &str,
    key_val: &str,
) -> Result<Option<Vec<(String, serde_json::Value)>>> {
    let sql = format!("SELECT * FROM {table} WHERE {key_col} = ?1 LIMIT 1");
    let mut st = conn.prepare(&sql)?;
    let cols: Vec<String> = st.column_names().iter().map(|s| (*s).to_string()).collect();
    let mut rows = st.query([key_val])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let mut out = Vec::with_capacity(cols.len());
    for (i, name) in cols.iter().enumerate() {
        let v: rusqlite::types::Value = row.get(i)?;
        out.push((name.clone(), sql_value_json(&v)));
    }
    Ok(Some(out))
}

/// `inspect <type> <id>` 域出口: 类型消歧单行查 → `QueryResult` (json 皮用)。type→(表,key) 定死映射
/// (解 person↔session 同 wxid 歧义)。查无 → **`CliError{NotFound}`** (退出3, 携码原样上抛 → classify
/// downcast 命中不漂 INTERNAL/70)。json data=[排序 Map]、`Meta::page(1,1)` (单行, total_count=1)。
/// **table 皮不走此** —— 走 [`fetch_row`] 保 schema 列序 (排序 Map 丢列序)。
pub fn inspect_query(conn: &rusqlite::Connection, entity: InspectType, id: &str) -> Result<QueryResult> {
    let (table, key_col) = entity.table_key();
    let Some(row) = fetch_row(conn, table, key_col, id)? else {
        // NOT_FOUND → 退出码 3 (E0 携码; 不是笼统 anyhow)。
        return Err(crate::cli_err(
            native_core::ErrorCode::NotFound,
            format!("没找到 {table} 记录 {key_col}={id} (id 对? 该库 ingest 了 {table}?)"),
        ));
    };
    // 单条包成 data:[row] 走统一信封。Map 按键名排序 (非 schema 序); §5a 只要求全列出、JSON object 本无序、
    // 机器按键取值 → 非违约。
    let obj: serde_json::Map<String, serde_json::Value> = row.into_iter().collect();
    let meta = Meta::page(1, 1).with_source(Source::Cold);
    Ok(QueryResult {
        data: vec![serde_json::Value::Object(obj)],
        meta,
    })
}

// ---- resolve (合并转发展开, 双模式) ----

/// 合并转发子项类型码 → 人话 (仅映射 schema 确认的 1/2/19, 其余原样报数不瞎标)。json 里预组进 `type_label`。
#[must_use]
pub fn forward_type_label(t: &str) -> String {
    match t {
        "1" => "文本".to_string(),
        "2" => "图片".to_string(),
        "19" => "套娃转发".to_string(),
        other => format!("类型{other}"),
    }
}

/// forward 子项行: (seq, data_type, source_name, data_title, data_desc)。
type ForwardItemRow = (i64, String, Option<String>, Option<String>, Option<String>);

/// 列合并转发消息 (按子项数倒序)。返 (转发总数, [(source, msg_id, 子项数)])。
/// **R16-2 修 (消息锚跨分片重号)**: source_native_id 锚 **半数消息重号**(`Msg_<md5(conv)>:<local_id>` 的 local_id
/// 是**每分片各自的行号**, 活跃群消息摊到多分片 → 同群不同分片的**不同消息**得同锚; 主表靠 PK `(account, source,
/// source_native_id)` 唯一不丢, 但纯锚 `GROUP BY source_native_id` 会把不同分片的**不同转发**误并一行、子项数相加)。
/// 故按 **(source, source_native_id)** 分组 —— 每条转发独立一行, 带 source(分片)供展开精确定位。次键
/// (n DESC, source_native_id ASC, **source ASC**) 全序确定(PK 保证 (source, source_native_id) 唯一)。
pub fn query_forward_list(
    conn: &rusqlite::Connection,
    limit: usize,
    offset: usize,
) -> Result<(usize, Vec<(String, String, i64)>)> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM (SELECT DISTINCT source, source_native_id FROM message_forward_item)",
        [],
        |r| r.get(0),
    )?;
    let mut st = conn.prepare(
        "SELECT source, source_native_id, count(*) AS n FROM message_forward_item \
         GROUP BY source, source_native_id ORDER BY n DESC, source_native_id ASC, source ASC LIMIT ?1 OFFSET ?2",
    )?;
    let rows: Vec<(String, String, i64)> = st
        .query_map([limit as i64, offset as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(ok_or_warn)
        .collect();
    Ok((usize::try_from(total).unwrap_or(0), rows))
}

/// 某条合并转发 (msg_id, 可选 source) 跨哪几个分片有(供 resolve 歧义检测)。**R16-2 修**: 锚重号下同 msg_id
/// 可能对应多分片的不同转发, 返回 DISTINCT source 让调用方判是否需 --source 精确定位。
pub fn forward_sources(conn: &rusqlite::Connection, msg_id: &str) -> Result<Vec<String>> {
    let mut st =
        conn.prepare("SELECT DISTINCT source FROM message_forward_item WHERE source_native_id = ?1 ORDER BY source")?;
    let v: Vec<String> = st.query_map([msg_id], |r| r.get(0))?.filter_map(ok_or_warn).collect();
    Ok(v)
}

/// 展开某条合并转发的逐子项 (按 seq 升序)。返 (子项总数, 行)。R16-2: 加 offset 翻页。
/// **R16-2 修 (锚重号)**: 加 `source`(分片)参数精确定位 —— 锚 source_native_id 跨分片重号(半数消息), 给了 source
/// 就 `WHERE source_native_id=? AND source=?` 只取那一条转发; source=None 时 `WHERE source_native_id=?`(调用方
/// resolve_query 已先用 [`forward_sources`] 挡了跨分片歧义, 到这里必唯一分片)。seq 在单条转发内唯一 → 已全序确定。
pub fn query_forward_items(
    conn: &rusqlite::Connection,
    msg_id: &str,
    source: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<(usize, Vec<ForwardItemRow>)> {
    let map_row = |r: &rusqlite::Row| -> rusqlite::Result<ForwardItemRow> {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    };
    let (total, rows): (i64, Vec<ForwardItemRow>) = if let Some(src) = source {
        let total: i64 = conn.query_row(
            "SELECT count(*) FROM message_forward_item WHERE source_native_id = ?1 AND source = ?2",
            rusqlite::params![msg_id, src],
            |r| r.get(0),
        )?;
        let mut st = conn.prepare(
            "SELECT seq, data_type, source_name, data_title, data_desc FROM message_forward_item \
             WHERE source_native_id = ?1 AND source = ?2 ORDER BY seq LIMIT ?3 OFFSET ?4",
        )?;
        let rows = st
            .query_map(rusqlite::params![msg_id, src, limit as i64, offset as i64], map_row)?
            .filter_map(ok_or_warn)
            .collect();
        (total, rows)
    } else {
        let total: i64 = conn.query_row(
            "SELECT count(*) FROM message_forward_item WHERE source_native_id = ?1",
            [msg_id],
            |r| r.get(0),
        )?;
        let mut st = conn.prepare(
            "SELECT seq, data_type, source_name, data_title, data_desc FROM message_forward_item \
             WHERE source_native_id = ?1 ORDER BY seq, source LIMIT ?2 OFFSET ?3",
        )?;
        let rows = st
            .query_map(rusqlite::params![msg_id, limit as i64, offset as i64], map_row)?
            .filter_map(ok_or_warn)
            .collect();
        (total, rows)
    };
    Ok((usize::try_from(total).unwrap_or(0), rows))
}

/// `resolve` 域出口: 合并转发展开 (读 L1 message_forward_item; 只读)。**双模式**: `msg_id=Some` 展开逐子项
/// (查无 → `CliError{NotFound}`/退出3, 对齐 inspect) / `msg_id=None` 列出所有合并转发消息 (供挑 msg_id)。
/// 展开 json 预组 `type_label` ([`forward_type_label`]); 两模式皆 `Meta::page(本页, 真总数)` (与旧
/// `print_query_json(&data, total)` 逐字节同)。table 皮读 `r.data` by key + `r.meta.total_count` 渲表头。
pub fn resolve_query(
    conn: &rusqlite::Connection,
    msg_id: Option<&str>,
    source: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    if let Some(msg_id) = msg_id {
        // 展开模式。**R16-2 修 (锚重号)**: 消息锚跨分片重号(半数消息), 同 msg_id 可能对应多分片的**不同转发**。
        // source=None 时先查该 msg_id 落在哪几个分片, 跨多分片(歧义)→ 要 --source 精确定位, 不武断合并不同消息。
        // codex P2: **钉住验证过的 source** —— source=None 时先 forward_sources 判歧义, 唯一则**把那个 source 传给取数**
        // (而非再用 None 裸查); 否则 forward_sources 与 query_forward_items 两次查之间若并发写(live-index)多出碰撞分片,
        // 裸查 `WHERE source_native_id=?` 会把新分片的**不同消息**也捞进来合并。钉 source 后取数恒限在验证过的那一片。
        let effective_source: Option<String> = if let Some(s) = source {
            Some(s.to_string())
        } else {
            let srcs = forward_sources(conn, msg_id).context("查转发所在分片失败")?;
            if srcs.len() > 1 {
                return Err(crate::cli_err(
                    native_core::ErrorCode::BadRequest,
                    format!(
                        "msg_id {msg_id} 在 {} 个分片各有一条不同的消息 ({}) —— 消息锚跨分片重号; 加 --source <分片> 精确定位(见 list 的 source 列)",
                        srcs.len(),
                        srcs.join(", ")
                    ),
                ));
            }
            srcs.into_iter().next() // 唯一分片钉住(空 → None → 下面取数 0 行 → NotFound)。
        };
        let (total, rows) = query_forward_items(conn, msg_id, effective_source.as_deref(), limit, offset)
            .context("查 message_forward_item 失败")?;
        if total == 0 {
            // 查无 → NOT_FOUND(退出3), 对齐 inspect。total 不随 offset 变, ==0 = 该 (msg_id[, source]) 无转发子项。
            return Err(crate::cli_err(
                native_core::ErrorCode::NotFound,
                format!("消息 {msg_id} 没有合并转发子项 (不是合并转发? id/source 不对?)"),
            ));
        }
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|(seq, dt, sn, ti, de)| {
                serde_json::json!({"seq": seq, "data_type": dt, "type_label": forward_type_label(dt), "source_name": sn, "data_title": ti, "data_desc": de})
            })
            .collect();
        let dropped = limit.min(total.saturating_sub(offset)).saturating_sub(data.len()) as u64;
        let meta = Meta::offset_page(offset, data.len(), total, limit)
            .with_source(Source::Cold)
            .with_dropped(dropped);
        Ok(QueryResult { data, meta })
    } else {
        // 列表模式 (供发现 msg_id)。**R16-2 修**: 输出 source(分片) —— 锚重号下同 msg_id 可能多分片各一条不同转发,
        // source 供展开时精确定位(--source)。
        let (total, rows) = query_forward_list(conn, limit, offset).context("查 message_forward_item 失败")?;
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|(src, id, n)| serde_json::json!({"source": src, "msg_id": id, "item_count": n}))
            .collect();
        let dropped = limit.min(total.saturating_sub(offset)).saturating_sub(data.len()) as u64;
        let meta = Meta::offset_page(offset, data.len(), total, limit)
            .with_source(Source::Cold)
            .with_dropped(dropped);
        Ok(QueryResult { data, meta })
    }
}

// ---- search (FTS5; 只 SEARCH 路移核, --build 建索引=写留皮) ----

/// `search` 域出口 (只 SEARCH 路; `--build` 建 FTS 索引是**写**, 留 msgvestige 皮): FTS5 搜正文 →
/// `QueryResult`。**fetch limit+1 精确探 has_more** (bm25 top-N 满 limit 时可能还有更多) + 截断到 limit;
/// FTS 命中总数不额外算 → `Meta::cold_page` (省 total_count; source=cold 冷 FTS 索引)。table 皮计时
/// (`{}ms`)/预览截断留皮。
pub fn search_query(
    conn: &rusqlite::Connection,
    query: &str,
    limit: i64,
    account_sha: Option<&str>,
) -> Result<QueryResult> {
    // R9 复审#8: 负数 limit clamp 到 0 —— 否则 limit.saturating_add(1) 仍为负 / SQLite `LIMIT <0` = **无限制** →
    // 大库全表扫 (再 truncate 到 0 返空, 但全扫已发生, 慢)。负 limit 是用户错误, 归 0 (取 0 行, 不触发无限扫)。
    let limit = limit.max(0);
    // fetch limit+1 精确探 has_more (搜索按 bm25 相关度取 top-N; 满 limit 时可能还有更多)。
    // ③b: account_sha (sha256 wxid) 存在 → search_messages 两路都加 `account_id_sha=?` 显式过滤
    // (FTS 靠 message.rowid 关联故走非 scoped conn + 显式谓词, 不用遮蔽视图)。
    let mut hits =
        native_core::storage::search_messages(conn, query, limit.saturating_add(1), account_sha).context("搜索失败")?;
    let has_more = i64::try_from(hits.len()).unwrap_or(i64::MAX) > limit;
    hits.truncate(usize::try_from(limit).unwrap_or(0));
    let data: Vec<serde_json::Value> = hits
        .iter()
        .map(|h| {
            serde_json::json!({
                "create_time": h.create_time,
                "conv_id": h.conv_id,
                "sender_wxid": h.sender_wxid,
                "text_content": h.text_content,
            })
        })
        .collect();
    let mut meta = Meta::cold_page(has_more).with_source(Source::Cold);
    if let Some(sha) = account_sha {
        meta.account = Some(sha[..8].to_string());
    }
    Ok(QueryResult { data, meta })
}

#[cfg(test)]
mod cold_query_tests {
    use super::{cold_messages_query, cold_sessions_query};

    /// **R16-2 (codex 66e76ec P2)**: `sys_type_label` 必须覆盖 `classify_sysmsg` 能发的**每一个**值 ——
    /// 否则该类事件(如 group_dissolve)的 `label` 走 `_ => t` 兜底出英文原 token, 三皮 events 输出不完整。
    /// 判据列表**同步自 native-core `classify_sysmsg`**(sysmsg.rs 的 9 个返回值); 它加新类型时这里必须跟。
    /// 用真 sysmsg 文本喂 `classify_sysmsg` → 再喂 `sys_type_label`, 锁"分类→标签"链两端一致, 断言标签
    /// **已翻译**(!= 原 token)。classify_sysmsg 加类型却漏配标签 → 此测红。
    #[test]
    fn sys_type_label_covers_all_classify_sysmsg_outputs() {
        use native_core::decoder::classify_sysmsg;
        // (代表性 content, 期望 sys_type) —— 覆盖 classify_sysmsg 全部 9 分支 (sysmsg.rs)。
        let fixtures: &[(&str, &str)] = &[
            ("你撤回了一条消息", "revoke"),
            (r#""A" 拍了拍 "B""#, "pat"),
            (
                r#"<img src="SystemMessages_HongbaoIcon.png"/> 领取了你的红包"#,
                "hongbao",
            ),
            (r#"<sysmsg type="paymsg"></sysmsg>"#, "transfer"),
            (r#"<sysmsg type="mmchatroomtopmsg"></sysmsg>"#, "topmsg"),
            ("你已解散该群聊", "group_dissolve"),
            (r#""张三"将"李四"移出了群聊"#, "member_remove"),
            (r#""小群"邀请"张三"加入了群聊"#, "member_join"),
            ("某种没见过的系统提示", "other"),
        ];
        for (content, expect_type) in fixtures {
            let t = classify_sysmsg(content);
            assert_eq!(t, *expect_type, "classify_sysmsg 分类漂移: {content}");
            let label = super::sys_type_label(t);
            assert_ne!(label, t, "sys_type '{t}' 缺中文标签 (走 _ => t 出英文原 token)");
        }
    }

    /// 内存 L1 库 (真 schema)。
    fn mem_l1() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        conn
    }

    /// 插一行 L1 message (填全 NOT NULL 列 + 关心字段; 省略的 nullable 列 → NULL)。
    fn insert_msg(conn: &rusqlite::Connection, chat: &str, snid: &str, create_time: i64, sender: &str, text: &str) {
        conn.execute(
            "INSERT INTO message \
             (account_id_sha, source, source_native_id, conv_id_sha, server_id, server_seq, create_time, \
              sort_seq, status, msg_type, msg_type_name, local_type_raw, sender_wxid_sha, is_chatroom, \
              text_content_sha, text_content_len, raw_xml_present, decode_kind, account_id, conv_id, \
              sender_wxid, text_content) \
             VALUES ('acc', 's', ?1, ?2, 100, 0, ?3, 0, 0, 1, 'TEXT', 1, '', 0, '', 0, 0, 'plain', 'wxid_me', \
                     ?4, ?5, ?6)",
            rusqlite::params![snid, native_core::sha256_hex(chat), create_time, chat, sender, text],
        )
        .unwrap();
    }

    /// 插一行 L1 session。
    fn insert_sess(conn: &rusqlite::Connection, username: &str, sort_ts: i64, summary: &str) {
        conn.execute(
            "INSERT INTO session \
             (account_id_sha, source, source_native_id, username_sha, account_id, username, unread_count, \
              last_msg_type, last_msg_sub_type, sort_timestamp, summary_len, summary, last_sender_len, \
              session_type, is_hidden, status, draft_len, last_timestamp, last_clear_unread_timestamp, \
              last_msg_locald_id, last_msg_ext_type, unread_first_msg_srv_id) \
             VALUES ('acc', 's', ?1, ?2, 'wxid_me', ?1, 0, 1, 0, ?3, ?4, ?5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)",
            rusqlite::params![
                username,
                native_core::sha256_hex(username),
                sort_ts,
                i64::try_from(summary.chars().count()).unwrap(),
                summary
            ],
        )
        .unwrap();
    }

    /// 冷查消息: 会话过滤 (别的 conv 不混) + create_time 倒序 + local_id 从 source_native_id 反解 + 21 键对齐热查。
    #[test]
    fn cold_messages_conv_filter_order_local_id_fields() {
        let conn = mem_l1();
        insert_msg(&conn, "wxid_a", "Msg_aaa:11", 100, "wxid_a", "早");
        insert_msg(&conn, "wxid_a", "Msg_aaa:33", 300, "wxid_a", "晚");
        insert_msg(&conn, "wxid_a", "Msg_aaa:22", 200, "wxid_a", "中");
        insert_msg(&conn, "wxid_b", "Msg_bbb:99", 999, "wxid_b", "别的会话");
        let r = cold_messages_query(&conn, "wxid_a", 10, 0).unwrap();
        assert_eq!(r.data.len(), 3, "只返 conv A 的 3 条 (B 不混)");
        assert_eq!(r.meta.total_count, Some(3), "total 精确 = conv A 条数");
        assert_eq!(r.data[0]["create_time"], 300);
        assert_eq!(r.data[1]["create_time"], 200);
        assert_eq!(r.data[2]["create_time"], 100);
        assert_eq!(r.data[0]["local_id"], 33, "从 Msg_aaa:33 反解 local_id");
        assert_eq!(r.data[0]["sender"], "wxid_a");
        assert_eq!(r.data[0]["text"], "晚");
        assert_eq!(r.data[0]["is_chatroom"], false, "INTEGER 0 → bool");
        let obj = r.data[0].as_object().unwrap();
        for k in [
            "source_native_id",
            "local_id",
            "server_id",
            "server_seq",
            "origin_source",
            "upload_status",
            "download_status",
            "create_time",
            "sort_seq",
            "status",
            "local_type",
            "msg_type",
            "msg_type_name",
            "msg_sub_type",
            "msg_sub_type_name",
            "decode_kind",
            "sys_type",
            "is_chatroom",
            "raw_xml_present",
            "sender",
            "text",
        ] {
            assert!(obj.contains_key(k), "冷查消息缺字段 {k}");
        }
        // R16-0 (对抗审 P2-1): **双边键集对拍**, 取代原先的单边硬编码 `assert_eq!(obj.len(), 21)`。
        // 那条是假守卫 —— 我给热查 msg_json 加 conv_id (→22 键) 时它**照绿**, 冷热同形就此被打破、
        // 而 openapi 已按 22 键写 → 对 HTTP 默认路径 (mode=auto + 有 L1 = 走冷查) 撒谎。
        // 现在: 任何一边加/删键, 另一边不跟就挂。
        let hot_keys: std::collections::BTreeSet<String> = {
            let qm = native_core::QueriedMsg {
                source_native_id: String::new(),
                conv_id: String::new(),
                local_id: 0,
                server_id: 0,
                server_seq: 0,
                origin_source: 0,
                upload_status: 0,
                download_status: 0,
                create_time: 0,
                sort_seq: 0,
                status: 0,
                local_type: 0,
                msg_type: 0,
                msg_type_name: String::new(),
                msg_sub_type: None,
                msg_sub_type_name: None,
                decode_kind: String::new(),
                content_ok: true, // R16-2 biz P2: 新字段(msg_json 不出, 此测比键集无关)。
                sys_type: None,
                is_chatroom: false,
                raw_xml_present: false,
                sender: None,
                text: String::new(),
            };
            crate::hot::msg_json(&qm)
                .as_object()
                .expect("msg_json 出 object")
                .keys()
                .cloned()
                .collect()
        };
        let cold_keys: std::collections::BTreeSet<String> = obj.keys().cloned().collect();
        assert_eq!(
            cold_keys, hot_keys,
            "冷/热 msg json **键集必须一致** (--mode 切冷/热对消费者透明); 改一边必须改另一边"
        );
    }

    /// 冷查会话: sort_timestamp 倒序 + is_group 派生 + conv_id=username + 21 键对齐热查。
    #[test]
    fn cold_sessions_order_is_group_fields() {
        let conn = mem_l1();
        insert_sess(&conn, "wxid_x", 100, "个人会话");
        insert_sess(&conn, "g1@chatroom", 300, "群会话");
        insert_sess(&conn, "wxid_y", 200, "另一个");
        let r = cold_sessions_query(&conn, 10, 0).unwrap();
        assert_eq!(r.data.len(), 3);
        assert_eq!(r.meta.total_count, Some(3));
        // R6 同形: 冷查 sessions 总数也在 summary.total_sessions (对齐热查 §14.1 读法, CLI table 头读它)。
        assert_eq!(
            r.meta.summary.as_ref().and_then(|s| s["total_sessions"].as_u64()),
            Some(3),
            "冷查 sessions summary.total_sessions 对齐热查读法"
        );
        assert_eq!(r.data[0]["sort_timestamp"], 300);
        assert_eq!(r.data[0]["conv_id"], "g1@chatroom");
        assert_eq!(r.data[0]["username"], "g1@chatroom");
        assert_eq!(r.data[0]["is_group"], true, "@chatroom → is_group");
        assert_eq!(r.data[1]["is_group"], false);
        assert_eq!(r.data[0]["summary"], "群会话");
        let obj = r.data[0].as_object().unwrap();
        for k in [
            "conv_id",
            "username",
            "is_group",
            "summary",
            "summary_len",
            "last_sender_display_name",
            "unread_count",
            "last_msg_type",
            "last_msg_sub_type",
            "sort_timestamp",
            "session_type",
            "is_hidden",
            "status",
            "draft",
            "last_msg_sender",
            "last_timestamp",
            "last_clear_unread_timestamp",
            "last_msg_locald_id",
            "last_msg_ext_type",
            "unread_first_msg_srv_id",
        ] {
            assert!(obj.contains_key(k), "冷查会话缺字段 {k}");
        }
        assert_eq!(obj.len(), 20, "恰 20 键 (与热查 session_json 对齐)");
    }

    /// 冷查 offset 分页诚实: total 精确, 末页 has_more=false。
    #[test]
    fn cold_offset_pagination_honest() {
        let conn = mem_l1();
        for i in 0..5 {
            insert_msg(&conn, "wxid_a", &format!("Msg_aaa:{i}"), i64::from(i), "wxid_a", "t");
        }
        let p0 = cold_messages_query(&conn, "wxid_a", 2, 0).unwrap();
        assert_eq!(p0.data.len(), 2);
        assert_eq!(p0.meta.total_count, Some(5));
        assert!(p0.meta.has_more, "5 条取 2 → 还有");
        let p_last = cold_messages_query(&conn, "wxid_a", 2, 4).unwrap();
        assert_eq!(p_last.data.len(), 1, "offset 4 → 剩 1 条");
        assert!(!p_last.meta.has_more, "末页 → 到底");
    }

    /// R6 修: 冷查消息**并列 create_time** 下 offset 翻页不重复/不漏 (次键 source_native_id 唯一定序)。
    /// 无次键时 SQLite 对并列行跨查询顺序不保证 → 页边界可能重复/漏消息 (=数据缺失)。
    #[test]
    fn cold_messages_tied_create_time_offset_no_dup_no_gap() {
        let conn = mem_l1();
        // 4 条同 create_time=500 (并列), 不同 source_native_id (local_id 11/22/33/44)。
        for id in ["Msg_aaa:11", "Msg_aaa:22", "Msg_aaa:33", "Msg_aaa:44"] {
            insert_msg(&conn, "wxid_a", id, 500, "wxid_a", "并列");
        }
        // limit=2 翻两页, 并集必须是 4 条全不同 (无重复 = dedup 后仍 4; 无漏 = 覆盖全 4)。
        let p1 = cold_messages_query(&conn, "wxid_a", 2, 0).unwrap();
        let p2 = cold_messages_query(&conn, "wxid_a", 2, 2).unwrap();
        assert_eq!(p1.data.len(), 2);
        assert_eq!(p2.data.len(), 2);
        let mut ids: Vec<String> = p1
            .data
            .iter()
            .chain(p2.data.iter())
            .map(|m| m["source_native_id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 4, "并列 create_time 下两页并集恰 4 条不同 (次键防重复/漏)");
    }

    /// R6 修: 冷查会话**并列 sort_timestamp** 下 offset 翻页不重复/不漏 (次键 username 唯一定序, 对齐热查)。
    #[test]
    fn cold_sessions_tied_sort_ts_offset_no_dup_no_gap() {
        let conn = mem_l1();
        for u in ["wxid_a", "wxid_b", "wxid_c", "wxid_d"] {
            insert_sess(&conn, u, 500, "并列");
        }
        let p1 = cold_sessions_query(&conn, 2, 0).unwrap();
        let p2 = cold_sessions_query(&conn, 2, 2).unwrap();
        assert_eq!(p1.data.len(), 2);
        assert_eq!(p2.data.len(), 2);
        let mut names: Vec<String> = p1
            .data
            .iter()
            .chain(p2.data.iter())
            .map(|s| s["username"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names.dedup();
        assert_eq!(
            names.len(),
            4,
            "并列 sort_timestamp 下两页并集恰 4 条不同 (次键 username 防重复/漏)"
        );
    }
}

// ── money offset 翻页稳定性 (R16-4): 合并次键 MoneyKey=(source, source_native_id) ────────────
// money 的修比 message 家族多一层: 除各源 SQL 补 PK 尾外, 三源在内存按时间归并, 元组原不带 PK → 加
// `MoneyKey` 令归并全序确定。三源**统一 PK 尾**含红包 —— rowid 在 scoped 遮蔽视图上无此伪列, 原红包
// `ORDER BY r.rowid` 在 scoped 下即炸, 一并修。下面测: (a) 跨源/源内同 time 由**显式次键 (source,snid) DESC
// 定序** (区分新旧: 旧靠插入序 + 稳定排序); (b) **scoped 遮蔽视图下三源不炸** (锁 rowid→PK 尾 回归);
// (c) 分页一致 + 红包尾。非只"翻页不重漏"(小内存库 SQLite 计划确定, 旧码于此也大概率不重漏 —— 见文件顶部
// 原则注; 跨页稳定性正据是"次键唯一"原则 + 真库并列, 非本夹具复现)。
// **真库核 (ym853 单账号, 交易表源自 general.db 单 source)**: transfer 2239 / red 601 / group_pay 11;
// 真实同秒并列**稀少但存在** (transfer 仅 1 个时间值有 2 行并列 @1782465309, group_pay 0, 跨源 0) —— 印证
// "ties 罕见故旧码多数时候恰好不错, 但边界一撞即重/漏", 修是 correct-by-construction 的边界守卫。真跑 offset
// 逐页 (limit=50) 拼接逐位 == 全量单查 (2851 行不重不漏, 并列点相邻稳定, 601 红包全甩末尾; scoped --account
// 三源均不炸)。EXPLAIN (生产 rusqlite, 填真库量): 裸开新旧同 (全表 temp-btree); scoped transfer 保 idx_begin_time
// + LAST-2-TERM 块排, group_pay 转 idx_session + 有界全排 (11 行, 可忽略) —— 均无全表扫回退。
#[cfg(test)]
mod money_paging_tests {
    use super::{money_query, MoneyKind};

    /// 内存 L1 库 (真 schema)。
    fn mem_l1() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        conn
    }

    /// 插一条 transfer (21 列全 NOT NULL, 非关心列填占位; source 恒 's', snid/时间/收付人可控)。
    fn insert_transfer(conn: &rusqlite::Connection, snid: &str, time: i64, payer: &str, receiver: &str) {
        conn.execute(
            "INSERT INTO transfer (account_id_sha, source, source_native_id, transfer_id, transcation_id, \
              message_server_id, second_message_server_id, pay_sub_type, session_name_sha, pay_payer_sha, \
              pay_receiver_sha, begin_transfer_time, last_modified_time, invalid_time, last_update_time, \
              delay_confirm_flag, bubble_clicked_flag, account_id, session_name, pay_payer, pay_receiver) \
             VALUES ('acc','s',?1,'TID','TX',0,0,3,'ss','ps','rs',?2,0,0,0,0,0,'acc','会话',?3,?4)",
            rusqlite::params![snid, time, payer, receiver],
        )
        .unwrap();
    }

    /// 插一条 group_pay (who = session_name)。
    fn insert_group_pay(conn: &rusqlite::Connection, snid: &str, time: i64, session: &str) {
        conn.execute(
            "INSERT INTO group_pay (account_id_sha, source, source_native_id, bill_no, message_local_id, \
              message_create_time, session_name_sha, account_id, session_name) \
             VALUES ('acc','s',?1,'BILL',1,?2,'ss','acc',?3)",
            rusqlite::params![snid, time, session],
        )
        .unwrap();
    }

    /// 插一条 red_envelope (time 恒 None; who = sender_user_name; 归并次键 = PK 尾 (source='s', source_native_id=snid))。
    fn insert_red(conn: &rusqlite::Connection, snid: &str, sender: &str) {
        conn.execute(
            "INSERT INTO red_envelope (account_id_sha, source, source_native_id, send_id, message_server_id, \
              sender_user_name_sha, session_name_sha, scene_id, hb_status, hb_type, receive_status, \
              native_url, account_id, sender_user_name, session_name) \
             VALUES ('acc','s',?1,'SID',1,'ss','sess',1,4,0,1,'url','acc',?2,'群红包')",
            rusqlite::params![snid, sender],
        )
        .unwrap();
    }

    /// **scoped 遮蔽视图回归守卫 (R16-4 核心)**: money 经 `--account`/HTTP account 参会走 `open_l1_scoped` 建
    /// TEMP VIEW 遮蔽账号 → 三源查询跑在**视图**上。视图**无 rowid 伪列**, 原红包 `ORDER BY r.rowid` 在此报
    /// "no such column: r.rowid" 整条炸; 改用 PK 尾 (source, source_native_id) 后视图可取。本测建视图复现该路径,
    /// 断言三源 money 不炸且返数据 —— **旧红包 SQL 会令此测 panic** (query_red_envelopes Err → money_query Err → unwrap)。
    #[test]
    fn money_on_scoped_masking_view_ok() {
        let conn = mem_l1();
        insert_transfer(&conn, "Transfer_1", 300, "P", "R");
        insert_group_pay(&conn, "GroupPay_1", 200, "群");
        insert_red(&conn, "RedEnvelope_1", "wxid_snd");
        // 复现 open_l1_scoped: 对**money 触及的所有含 account_id_sha 列的表**建遮蔽视图 (temp schema 优先 main,
        // 账号钉 'acc' 与 insert_* 一致) —— 含三源主表 + 关联子查询表 message_app(转账费/群收款额)/group_pay_member
        // (已付人数), 与真 scope_conn_to_account 逐表等同 (子查询亦跑在视图上, 非退回裸表)。
        conn.execute_batch(
            "CREATE TEMP VIEW \"transfer\" AS SELECT * FROM main.\"transfer\" WHERE account_id_sha='acc';\
             CREATE TEMP VIEW \"red_envelope\" AS SELECT * FROM main.\"red_envelope\" WHERE account_id_sha='acc';\
             CREATE TEMP VIEW \"group_pay\" AS SELECT * FROM main.\"group_pay\" WHERE account_id_sha='acc';\
             CREATE TEMP VIEW \"message_app\" AS SELECT * FROM main.\"message_app\" WHERE account_id_sha='acc';\
             CREATE TEMP VIEW \"group_pay_member\" AS SELECT * FROM main.\"group_pay_member\" WHERE account_id_sha='acc';",
        )
        .unwrap();
        // 三源合并 (kind=all) + 红包单查 (原 rowid bug 的直接触发点) 都在视图上跑通。
        let all = money_query(&conn, MoneyKind::All, 10, 0).unwrap();
        assert_eq!(
            all.data.len(),
            3,
            "scoped 视图下三源合并不炸 (原红包 r.rowid 视图上 no such column)"
        );
        let red = money_query(&conn, MoneyKind::RedEnvelope, 10, 0).unwrap();
        assert_eq!(red.data.len(), 1, "scoped 视图下红包单查不炸");
        assert_eq!(red.data[0]["kind"], "红包");
    }

    /// 跨源同 time (转账 + 群收款 皆 time=100) 的归并**由显式次键 (source,snid) DESC 破并列**, 非插入序。
    /// 同 source 's', snid "zzz"(群收款) > "aaa"(转账) → 群收款排前。**旧码** (transfer 先 extend + 稳定排序)
    /// 会把转账排前 → 本测据此区分新旧 (证显式次键生效)。
    #[test]
    fn money_merge_cross_source_tie_ordered_by_pk_tail() {
        let conn = mem_l1();
        insert_transfer(&conn, "aaa", 100, "PT", "R"); // 转账 who="PT → R"
        insert_group_pay(&conn, "zzz", 100, "GRP"); // 群收款 who="GRP"
        let r = money_query(&conn, MoneyKind::All, 10, 0).unwrap();
        assert_eq!(r.data.len(), 2);
        assert_eq!(
            r.data[0]["kind"], "群收款",
            "snid 'zzz'>'aaa' → 群收款排前 (显式次键 DESC, 非插入序)"
        );
        assert_eq!(r.data[0]["who"], "GRP");
        assert_eq!(r.data[1]["kind"], "转账");
        assert_eq!(r.data[1]["who"], "PT → R");
    }

    /// 分页一致性 + 红包尾。3 转账 (两条同 time=200 并列 + 一条 100) + 2 红包 (time=None, 恒末尾, snid DESC):
    /// 逐条 (limit=1) 翻到底并集**逐位等于**全量单查 (offset/merge 一致); 源内并列 + 红包内均按 (source,snid) DESC。
    /// **诚实注**: 小内存库计划确定 → "逐位相等"这条旧单键码于此也可能过 (=假守卫面), 故它只锁 offset/merge 机制 +
    /// 红包尾序回归; tie 跨页稳定性正据在 `money_merge_cross_source_tie_ordered_by_pk_tail` 测 + 文件顶部"次键唯一"原则。
    #[test]
    fn money_offset_paging_matches_full_and_red_tail() {
        let conn = mem_l1();
        insert_transfer(&conn, "t_hi_a", 200, "A", "R"); // time=200
        insert_transfer(&conn, "t_hi_b", 200, "B", "R"); // time=200 并列
        insert_transfer(&conn, "t_lo", 100, "C", "R"); // time=100
        insert_red(&conn, "re1", "wxid_S1"); // rowid 1
        insert_red(&conn, "re2", "wxid_S2"); // rowid 2
        let full = money_query(&conn, MoneyKind::All, 10, 0).unwrap();
        assert_eq!(full.data.len(), 5, "3 转账 + 2 红包");
        // 逐条翻页 (limit=1, offset 0..5) 并集逐位 == 全量单查序。
        let paged: Vec<serde_json::Value> = (0..5)
            .map(|off| {
                let p = money_query(&conn, MoneyKind::All, 1, off).unwrap();
                assert_eq!(p.data.len(), 1, "offset {off} 取 1 条");
                p.data[0].clone()
            })
            .collect();
        assert_eq!(
            paged, full.data,
            "逐条翻页序 == 全量单查序 (offset/merge 一致, 不重不漏)"
        );
        // 前 3 条 Some-time 倒序 (200,200,100); 源内并列 snid DESC → t_hi_b(B) 先于 t_hi_a(A)。
        assert_eq!(full.data[0]["time"], 200);
        assert_eq!(full.data[0]["who"], "B → R", "源内并列 snid 't_hi_b'>'t_hi_a' → B 先");
        assert_eq!(full.data[1]["time"], 200);
        assert_eq!(full.data[1]["who"], "A → R");
        assert_eq!(full.data[2]["time"], 100);
        // 红包 (time=None) 恒末尾两位; 内部 source_native_id DESC → "re2" > "re1" → re2 先。
        assert_eq!(full.data[3]["kind"], "红包");
        assert_eq!(full.data[3]["who"], "wxid_S2", "红包 snid DESC: 're2'>'re1' → re2 先");
        assert_eq!(full.data[4]["kind"], "红包");
        assert_eq!(full.data[4]["who"], "wxid_S1");
        assert!(full.data[3]["time"].is_null(), "红包 time=None");
    }
}

#[cfg(test)]
mod mask_pii_tests {
    use super::mask_pii;

    /// **logging §4.5-B② 看护项收口**: `mask_pii` 旧码按**字节** `&value[..head]` 切片, 中文正文 (每字符 3
    /// 字节) 会切进 UTF-8 序列中段 → `str` 切片 panic, 且越界 panic 文案会带上 ≤256B 原文 (擦不掉 = PII
    /// 泄漏面)。改 char 计数切片后: (1) 中文输入不再 panic; (2) 中段字符被打码, 原文不整串出现在返回值。
    /// 现有调用点 (`pii_scan_query` / `hot_pii_scan`) 只传 ASCII 号码 → 此路不可达, 但改前是潜伏雷。
    #[test]
    fn mask_pii_chinese_no_panic_no_leak() {
        // 兜底档 (kind 非手机/身份证 → 留头尾各 2)。value 全中文: byte_len(21) != char_len(7),
        // 旧码 `&value[..2]` 的字节索引 2 落在首字 '张' (bytes 0..3) 中段 → 旧码此处 **必 panic**。
        let value = "张三丰在少林寺";
        let masked = mask_pii("其它", value);
        // (1) 能走到这里即证不再 panic。(2) 头尾各留 2 字符, 中段 3 字符打码 → 原文中段不泄。
        assert_eq!(masked, "张三***林寺", "留头尾各 2 字符 + 中段按字符打码 (非按字节)");
        for masked_ch in ['丰', '在', '少'] {
            assert!(!masked.contains(masked_ch), "中段字符 {masked_ch} 不得出现在打码结果");
        }
        assert!(!masked.contains(value), "原文整串不得泄漏");
        // 短中文串 (n <= head+tail) 全打码, 星号数 = 字符数 (非字节数), 同样不 panic。
        assert_eq!(
            mask_pii("其它", "甲乙"),
            "**",
            "2 字符 <= 2+2 → 全 * (按字符计, 非 6 字节)"
        );
        assert_eq!(mask_pii("其它", "你好呀"), "***", "3 字符 <= 2+2 → 全 *");
        // ASCII 号码打码与旧码逐字节不变 (回归锁; 与 msgvestige `pii_helpers_checksum_mobile_mask` 同结论,
        // 本文件自足, 证 char 化未回归 ASCII 行为)。
        assert_eq!(mask_pii("手机号", "13800138000"), "138****8000");
        assert_eq!(mask_pii("身份证", "110101199003070011"), "1101**********0011");
    }
}
