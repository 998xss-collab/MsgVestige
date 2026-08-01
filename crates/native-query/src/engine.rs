//! 查询引擎 (查询内核抽取 §6②) —— clean 单表 LIMIT 档命令的通用引擎 + 登记表。
//!
//! §3 分工: `run_query` 只**取数 + 组结构化结果** (`QueryResult{data,meta}`), **不打印**; 呈现交皮层
//! (CLI 打 table/json、MCP/HTTP 转各自响应)。table 渲染 (`Fmt`/`render_cell`/`render_table`) 与
//! `REGISTRY`/`Col.fmt` 同源, 一并放此; MCP/HTTP 只调 `run_query` 不碰 `render_table` 即可。
//!
//! `run_query` 读 rusqlite 行 → `value_json` 组 `data` (json); `render_table` 反过来读 `data` (json)
//! → `render_cell` 按 `Fmt` 渲染。二者经 `data` 解耦, 皮层可只要 json、按需再渲 table。

// 查询分发里把 const/辅助 item 就近声明在用它的那段旁边, 比堆到文件顶部更好读。
#![allow(clippy::items_after_statements)]

use std::path::Path;

use anyhow::{Context, Result};

use crate::envelope::{Meta, QueryResult, Source};
use crate::error::cli_err;
use crate::target::QueryTarget;

// ── 打开 L1 / 缺表归类 (引擎共享助手; 手写命令也复用, 故 pub) ──

/// 只读打开 L1 db 并**坐实是真 sqlite** (强读一次 schema; open_readonly 惰性打开, 垃圾文件也"成功")。
/// 打不开 / 非数据库 → BAD_REQUEST。三皮查询入口统一经此拿连接。
pub fn open_l1(l1_db: &str) -> Result<rusqlite::Connection> {
    let conn = native_core::storage::open_readonly(Path::new(l1_db)).map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            format!("打不开 L1 db {l1_db} (路径不存在 / 打不开)"),
        )
    })?;
    // open_readonly **惰性**打开 (不读头) → 垃圾/非 sqlite 文件也"打开成功", 错误延到首次查表冒 "not a
    // database"。强制读一次 schema 表在此坐实是真 sqlite (契约审 #2: 否则 account 等吞错命令会拿假数据/漏 BAD_REQUEST)。
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map_err(|e| {
            // ⚠️ 别把所有错误都说成"不是数据库"。这一步失败有两类完全不同的原因:
            //   · 真不是 sqlite / 文件损坏 → 用户该换文件
            //   · **库正被别的进程占着**(微信自己在写、另一个 msgvestige 在跑、DB 工具开着)
            //     → 库好好的, 等一下或关掉那个程序就行
            // 原先一律报"非数据库 / 已损坏", 用户很可能真去把好库删了重建 —— 实测造独占锁复现。
            let busy = matches!(
                e,
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ffi::ErrorCode::DatabaseBusy | rusqlite::ffi::ErrorCode::DatabaseLocked,
                        ..
                    },
                    _
                )
            );
            let hint = if busy {
                format!(
                    "--l1-db {l1_db} 打不开: 库正被别的程序占用(另一个 msgvestige 在跑? \
                     数据库工具开着?)。库本身没问题, 等它结束或关掉那个程序再试"
                )
            } else {
                format!("--l1-db {l1_db} 不是有效 sqlite 库 (非数据库 / 已损坏)")
            };
            cli_err(native_core::ErrorCode::BadRequest, hint)
        })?;
    // **codex R16-3 P1: 读侧也校验 schema 版本** —— 写侧 init_l1_schema 的版本门禁只拦 ingest; 若旧版本库(如 R14
    // 消息锚 8→32 前 v1 / R16-3 favorite_tag server 锚 v2)升级后**直接冷查**(不再 ingest), 会绕过写侧 bump、
    // 返旧锚格式的陈旧/重复/塌陷行。此处对**有版本 meta** 的库强校 == SCHEMA_VERSION, 不符报 SchemaMismatch;
    // 无版本 meta(半成品/极旧/空库)不拦(无陈旧业务数据可返)。SSE/HTTP/MCP 冷查全经 open_l1* → 一处即覆盖。
    if let Ok(Some(v)) = native_core::storage::get_meta(&conn, native_core::storage::META_KEY_VERSION) {
        if v != native_core::storage::SCHEMA_VERSION {
            return Err(cli_err(
                native_core::ErrorCode::SchemaMismatch,
                format!(
                    "L1 库 schema 版本过旧 (库 {v}, 需 {}): 旧锚格式行会返陈旧/重复数据 (R14 消息锚 / R16-3 favorite_tag 锚)。\
                     请删掉此 L1、从加密源全量重建。",
                    native_core::storage::SCHEMA_VERSION
                ),
            ));
        }
    }
    Ok(conn)
}

/// 打开 L1, 并在指定 `account_sha` 时对**所有含 `account_id_sha` 列的真表**建**临时过滤视图遮蔽**
/// → 全查询透明按账号隔离 (③b 多账号)。
///
/// 机制: SQLite temp schema 优先 main → `CREATE TEMP VIEW person AS SELECT * FROM main.person WHERE
/// account_id_sha='<sha>'` 后, 查询里裸 `FROM person` 自动命中过滤视图。**零 per-query 改动 + 从 schema
/// 枚举账号表故不可能漏一张** (连 `exec`/`inspect` 逃生口也隔离); 要全量走 `main.<表>` 显式绕过。
/// FTS `search` 例外 (靠 `message.rowid` 关联, 不能遮蔽 message) → 走 `search_messages` 的显式谓词过滤。
///
/// `account_sha` = `sha256(wxid)` (64 hex)。视图定义**不许带 `?` 绑参** → sha 内联字面量, 故先严校 64 hex 防注入。
///
/// # Errors
/// 打不开 L1 / 非 sqlite → BAD_REQUEST; `account_sha` 非 64 hex / 建视图失败 → BAD_REQUEST/Internal。
pub fn open_l1_scoped(l1_db: &str, account_sha: Option<&str>) -> Result<rusqlite::Connection> {
    let conn = open_l1(l1_db)?;
    if let Some(sha) = account_sha {
        scope_conn_to_account(&conn, sha)?;
    }
    Ok(conn)
}

/// 对所有含 `account_id_sha` 列的真表建遮蔽过滤视图 (③b; 见 [`open_l1_scoped`])。
fn scope_conn_to_account(conn: &rusqlite::Connection, account_sha: &str) -> Result<()> {
    // sha 内联进视图 SQL (视图不能绑参) → 严校 64 位 hex 防 SQL 注入 (sha256_hex 产物恒 64 hex)。
    if account_sha.len() != 64 || !account_sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!(
                "--account 解析的 account_id_sha 非法 (须 64 hex, 实得 {} 位)",
                account_sha.len()
            ),
        ));
    }
    // 枚举真表 (排除 sqlite_ 内部表 + 虚表/视图), 挑出有 account_id_sha 列的建遮蔽视图。
    let mut st = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
    let names: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(ok_or_warn)
        .collect();
    for t in names.iter().filter(|t| table_has_account_col(conn, t)) {
        // t = sqlite_master 真表名 (非用户输入); sha 已验 64 hex。视图名 = 表名 → temp 遮蔽 main。
        conn.execute_batch(&format!(
            "CREATE TEMP VIEW \"{t}\" AS SELECT * FROM main.\"{t}\" WHERE account_id_sha = '{account_sha}';"
        ))
        .with_context(|| format!("建账号过滤视图失败: {t}"))?;
    }
    Ok(())
}

/// L1 里出现过的所有 `account_id_sha` (并集, 跨**所有含该列的真表** —— 与 [`open_l1_scoped`] 用同一套
/// 表枚举, 判据与隔离机制一致, 不可能只探到一张表)。多账号探测用: 结果 ≤1 = 单账号 (裸查安全);
/// >1 = 必须显式选账号 (否则静默并库泄漏)。
///
/// `account_id_sha` 是各账号域表 PK/索引的**前导列** (message/person/chatroom… 皆然) → `DISTINCT` 走
/// 索引, 廉价 (无须全表扫)。
///
/// # Errors
/// 枚举 schema / 逐表取 distinct 失败 → `Err` (调用方须 **fail-closed**: 判不出账号维度就别裸查合并 ——
/// 防仅存于 message 的二号账号被并库泄漏; 审查 P1-2/3)。
/// R9 复审 R2#4: 行迭代丢弃**读取失败**的行时不再静默 —— warn 后丢 (原 `filter_map(Result::ok)` 无声吞, 用户
/// 不知结果少了行)。替代 `.filter_map(ok_or_warn)`: 坏行记 warn (CLI stderr / 服务日志可见), 结果仍
/// 返回 (韧性: 一坏行不崩整查); 消费者从日志知"结果可能不完整"。total_count 仍是 SQL COUNT (含坏行), 与 data.len()
/// 差即丢弃数, warn 是其信号。
pub(crate) fn ok_or_warn<T, E: std::fmt::Display>(r: std::result::Result<T, E>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("冷查/枚举丢弃一条读取失败的行 (结果可能不完整): {e}");
            None
        }
    }
}

/// R4 复审R3#5 扩展: 收集行迭代, **同时数丢弃了几行** —— 替非 offset 分页 (`Meta::page`/`cursor_page`/`cold_page`,
/// 如 accounts/names/new/stats/forward) 的 `.filter_map(ok_or_warn).collect()`。这些点 `total`=`shown` (无独立 COUNT)
/// → `offset_page` 的算术法测不出丢行, 必须显式计数。返 `(行, 丢弃数)`; 调用方把丢弃数 `.with_dropped()` 进 meta
/// → 消费者拿到机器可读的"结果不完整"信号 (与 offset 分页的 `dropped_rows` 同字段同义)。坏行仍 warn (ok_or_warn 里)。
pub(crate) fn collect_ok<T, E: std::fmt::Display>(
    iter: impl Iterator<Item = std::result::Result<T, E>>,
) -> (Vec<T>, u64) {
    let mut out = Vec::new();
    let mut dropped = 0u64;
    for r in iter {
        match ok_or_warn(r) {
            Some(v) => out.push(v),
            None => dropped += 1,
        }
    }
    (out, dropped)
}

/// R5 复审 P2#3 (+ R5b codex P2 重做): 收 `LIMIT limit` 一批 (**不 over-fetch 探针**), 返 `(页行[≤limit], 页内丢弃数,
/// has_more)`。给 `new`/`stats` 这类无廉价精确 COUNT、靠 fetch 判 has_more 的 cold_page 查询用。
///
/// **`has_more = fetched == limit && page 非空`**:
/// - `fetched == limit` —— SQL `LIMIT limit` 读满了 limit 个行 → 后面**可能**还有 (保守: 恰好剩 limit 个时也报 true,
///   消费者多翻一次拿到空页, 但**绝不假 `false` 漏数据** —— 这正是 R5 要修的方向)。fetched < limit → 读到底了, false。
/// - `&& !page.is_empty()` —— 整批全坏 (page 空) → false, 兜死循环 (new 的 watermark 无好行可推进, 否则消费者拿同一
///   游标无限重查同批坏行; codex R5b P2)。
///
/// **为何 fetch-limit 而非 limit+1 探针** (codex R5b P2): 探针会多读 1 个 SQL 行, 令 **OFFSET 翻页** (HTTP stats) 的
/// `offset += limit` 与实际消耗 (limit+1 或含坏行) **错位 → 重复行**。fetch 恰 limit 个 → `offset += limit` 精确无重叠
/// (OFFSET 数所有 SQL 行, 含坏行), watermark 翻页 (new) 也推进到末条好行不漏不重。`dropped` = 本批**全部**坏行 (fetch==limit
/// 时坏行都在页窗内, 无探针区)。
///
/// 调用方给 `iter` = `SELECT ... LIMIT limit` 的 `query_map` 迭代器 + 真实 `limit`。
pub(crate) fn collect_page<T, E: std::fmt::Display>(
    iter: impl Iterator<Item = std::result::Result<T, E>>,
    limit: usize,
) -> (Vec<T>, u64, bool) {
    let mut page = Vec::with_capacity(limit);
    let mut dropped = 0u64;
    let mut fetched = 0usize;
    for r in iter {
        fetched += 1;
        match ok_or_warn(r) {
            Some(v) => page.push(v), // fetch ≤ limit → page ≤ limit, 无需再 < limit 判。
            None => dropped += 1,
        }
    }
    let has_more = fetched == limit && !page.is_empty(); // 先算 (下句 move page)。
    (page, dropped, has_more)
}

pub fn account_shas(conn: &rusqlite::Connection) -> Result<Vec<String>> {
    let mut st = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
    let names: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(ok_or_warn)
        .collect();
    // R19 (审 round-2 P2): 排除 capture_targets —— 它是**用户可写、账号不校验**的采集控制面表 (`capture add --account <任意合法
    // wxid>` 直接 sha256 写入, 不核该账号是否真在库)。若纳入账号枚举, 一个 typo 的 --account 就注入孤儿 sha → 整库无-account
    // 查询全误报 ACCOUNT_AMBIGUOUS (而 /accounts 仍只报真账号, 自相矛盾且不可诊断)。账号枚举应由 **ingest 写真实 sha 的数据表**
    // 驱动 (person/message/raw_payload_archive/etl_state…), 与 CLI 登记表测试把 capture_targets 归"采集控制面非数据投影"一致。
    const ACCOUNT_ENUM_EXCLUDE: &[&str] = &["capture_targets"];
    let mut shas: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for t in names
        .iter()
        .filter(|t| !ACCOUNT_ENUM_EXCLUDE.contains(&t.as_str()) && table_has_account_col(conn, t))
    {
        // t = sqlite_master 真表名 (非用户输入)。逐表取 distinct account_id_sha 并入集合。**成本**: account_id_sha 是 PK/索引
        // 前导列 → 走 covering-index **扫** (非 O(1) 点查): O(表行数) 遍历取 distinct, 大 L1 上百 ms 级 (实测 3M 行 ~570ms)。
        // 故所有走此账号解析的**服务端**冷端点 (HTTP get_capture 等) 必下沉 spawn_blocking + COLD 并发闸, 别钉死 async 线程。
        // 出错**上抛** (不吞): account 列已确认存在, 查询仍失败 = 库异常 → fail-closed 强于漏账号。
        let sql = format!("SELECT DISTINCT account_id_sha FROM \"{t}\" WHERE account_id_sha IS NOT NULL");
        let mut q = conn.prepare(&sql)?;
        let rows = q.query_map([], |r| r.get::<_, String>(0))?;
        for s in rows {
            shas.insert(s?);
        }
    }
    Ok(shas.into_iter().collect())
}

/// 账号解析结果 (三皮同核 fail-closed 决策; 皮层各自格式化成 tool_err / ApiError)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountResolution {
    /// 用这个账号: 显式指定 → `Some(wxid)`; 单账号库无显式 → `None` (不过滤 = 那唯一账号)。
    Use(Option<String>),
    /// 多账号库未指定 → 需显式选; `candidates` = 能命名的 wxid (仅存于 message 的账号无明文名, 可能不全)。
    Ambiguous { candidates: Vec<String> },
}

/// 解析要用哪个账号 (三皮同核, 审查 P1-2/3 的 fail-closed 逻辑收敛在此, 免 MCP/HTTP 各写一份漂移):
/// `explicit`(工具/query 参 > 服务器默认) 有 → `Use(Some)`; 无 → 探真实账号集 ([`account_shas`], 跨表并集):
/// 0/1 → `Use(None)` (裸查安全); >1 → `Ambiguous`。
///
/// # Errors
/// 打不开 L1 / 探测账号维度失败 → `Err` (调用方须 **fail-closed**: 判不出就要求显式 account, 别裸查合并)。
pub fn resolve_account(l1_db: &str, explicit: Option<String>) -> Result<AccountResolution> {
    if let Some(a) = explicit {
        return Ok(AccountResolution::Use(Some(a)));
    }
    let conn = open_l1(l1_db)?;
    let shas = account_shas(&conn)?;
    Ok(if shas.len() > 1 {
        AccountResolution::Ambiguous {
            candidates: account_candidates(&conn),
        }
    } else {
        AccountResolution::Use(None)
    })
}

/// R9 复审 R2#2: **CLI 冷查开 scoped conn, 走 [`resolve_account`] fail-closed** —— 对齐 HTTP/MCP 的多账号挡歧义。
/// 替代 CLI 各命令直接 `open_l1_scoped(target.account_sha())` (未给 --account 时 None → 裸开混账号): 显式 --account
/// → scoped; 单账号库 → 裸查安全 (None); 多账号未指定 → `Err(AccountAmbiguous)`。scoping 靠遮蔽视图, 故只需换 open。
///
/// # Errors
/// L1 打不开 / 探账号失败 / 多账号未指定 (`AccountAmbiguous`, 皮层渲染成 409/退出码 + candidates 提示)。
pub fn open_l1_resolved(target: &crate::QueryTarget) -> Result<rusqlite::Connection> {
    // R16-1: l1_db 自热冷通用后是 Option —— 走到本函数即"要冷查", 缺库给**可操作**报错
    // (提示改 --mode hot), 而非 unwrap panic 或静默转热。
    let l1_db = target.require_l1_db()?;
    let sha = match resolve_account(l1_db, target.account.clone())? {
        AccountResolution::Use(Some(_)) => target.account_sha(), // 显式 --account → 其 sha (scoped)
        AccountResolution::Use(None) => None,                    // 单账号库 → 裸查安全 (库里就一个账号)
        AccountResolution::Ambiguous { candidates } => {
            return Err(crate::error::cli_err(
                native_core::ErrorCode::AccountAmbiguous,
                format!(
                    "多账号库需指定 --account (候选: {}); 或用 `accounts` 命令看全部账号",
                    if candidates.is_empty() {
                        "无可命名候选".to_string()
                    } else {
                        candidates.join(", ")
                    }
                ),
            ));
        }
    };
    open_l1_scoped(l1_db, sha.as_deref())
}

/// R9 复审R3#1: 解析账号 → `account_sha` (皮层**非 QueryTarget** 路径用: CLI cold sessions/messages/search)。
/// 显式 wxid → 其 sha; 单账号库 → `None` (裸查安全); 多账号未指定 → `Err(AccountAmbiguous)` (fail-closed, 不裸查混)。
///
/// # Errors
/// L1 打不开 / 探账号失败 / 多账号未指定 (`AccountAmbiguous` + candidates)。
pub fn resolve_account_sha(l1_db: &str, explicit: Option<String>) -> Result<Option<String>> {
    match resolve_account(l1_db, explicit)? {
        AccountResolution::Use(w) => Ok(w.map(|x| native_core::sha256_hex(&x))),
        AccountResolution::Ambiguous { candidates } => Err(crate::error::cli_err(
            native_core::ErrorCode::AccountAmbiguous,
            format!(
                "多账号库需指定 --account (候选: {}); 或用 `accounts` 命令看全部账号",
                if candidates.is_empty() {
                    "无可命名候选".to_string()
                } else {
                    candidates.join(", ")
                }
            ),
        )),
    }
}

/// 坐实 `conn` 指向 ingest 产出的 L1 (查 `raw_payload_archive` 标记表)。非 L1/无关 sqlite → `BadRequest`。
/// **capture 读路径共享守卫** (`capture_targets_query` 三皮 HTTP/MCP + CLI `capture list`; 写侧 `capture_open_l1_write`
/// 有同款查); round-12 两审收敛: 别只在某分支查致显式账号/CLI 绕过、非 L1 误报"空清单=全采"。
///
/// # Errors
/// 库缺 `raw_payload_archive` (非 L1)。
pub fn ensure_l1_marker(conn: &rusqlite::Connection) -> Result<()> {
    let is_l1 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='raw_payload_archive'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);
    if is_l1 {
        Ok(())
    } else {
        Err(crate::error::cli_err(
            native_core::ErrorCode::BadRequest,
            "库不是有效 L1 (缺 raw_payload_archive; capture 需指向 ingest 产出的 L1)".to_string(),
        ))
    }
}

/// R19 选择性采集: 解析 `capture_targets` 的**具体** `account_id_sha` (三皮共享, 免漂移)。
///
/// 与 [`resolve_account_sha`] 的关键区别: **单账号库返其真实 sha (非 `None`)** —— `capture_targets` 按
/// `account_id_sha` 分行, 单账号也需具体 sha 才能读写对行 (查询侧 `None`="无需 scope 裸查"的语义在这里行不通)。
///
/// 显式 `wxid` → 其 sha (**populated L1 校验 ∈ 数据账号 ∪ capture_targets 账号, typo 拒; 空数据 L1 放行任意**, round-10/11);
/// 单账号数据库 → 唯一账号 sha; **无数据账号但 capture_targets 有单账号
/// → 该账号 sha** (预 ingest 圈定可见, 审 round-4 P2); 真空库 → `Ok(None)`; 多账号 (数据表或 capture_targets) 未指定 → `Err(AccountAmbiguous)`。
///
/// # Errors
/// L1 打不开 / 探账号失败 / 多账号未指定 (`AccountAmbiguous` + candidates)。
pub fn resolve_capture_account_sha(l1_db: &str, explicit: Option<String>) -> Result<Option<String>> {
    if let Some(w) = explicit {
        // 审 round-5 P2: 校验 wxid 格式 (与 CLI add/rm 一致; malformed --account (含空白/控制符/超长) → BAD_REQUEST,
        // 非静默哈希成不命中的空清单谎报"全采")。Wxid 不做归一 → sha256_hex(校验后串) == 原 sha256_hex(&w)。
        let wxid: native_core::Wxid = w.parse().map_err(|_| {
            crate::error::cli_err(
                native_core::ErrorCode::BadRequest,
                "account 非法 (须合法微信 wxid)".to_string(),
            )
        })?;
        let sha = native_core::sha256_hex(wxid.as_str());
        // 审 round-10 P1 + round-11 P2: L1 **有数据账号**时校验显式账号 —— populated L1 上 typo 的 --account (合法 wxid 但
        // 非本库账号) 会静默哈希成孤儿 sha 白名单: capture add 报成功, 但真账号 ingest 见不到该 targets 仍全采 (谎报"已圈定"
        // → 选择性采集静默失效)。**接受集 = 数据账号 ∪ 已预圈账号 (capture_targets)** (round-11 codex P2: 否则 populated L1
        // 上预圈的 B 因不在数据账号被拒、无法 list/rm)。typo 既不在数据也不在预圈 → 拒。仅 L1 **无数据账号** (预 ingest, 无从
        // 校验) 时放行任意 (round-4 预圈可见: 空数据 L1 仍允许圈定)。
        let conn = open_l1(l1_db)?;
        let data_accounts: std::collections::BTreeSet<String> = account_shas(&conn)?.into_iter().collect();
        if !data_accounts.is_empty()
            && !data_accounts.contains(&sha)
            && !capture_target_account_shas(&conn)?.contains(&sha)
        {
            let c = account_candidates(&conn);
            return Err(crate::error::cli_err(
                native_core::ErrorCode::BadRequest,
                format!(
                    "账号 {} 不在此 L1 的已知账号里 (防 typo 造孤儿白名单致真账号仍全采); 已有账号: {}。用 `accounts` 命令看全部",
                    wxid.as_str(),
                    if c.is_empty() { "无可命名候选".to_string() } else { c.join(", ") }
                ),
            ));
        }
        return Ok(Some(sha));
    }
    let conn = open_l1(l1_db)?;
    // 审 round-4/5 P2 (union): capture 目标账号 = **数据表账号 ∪ capture_targets 账号**。数据账号来自 [`account_shas`]
    // (排除 capture_targets 防孤儿毒化通用 stats/contacts, round-2); capture_targets 账号来自它自身 (预 ingest 圈定该可见)。
    // union 后 1 → 用; 0 → None (真空库); >1 → `AccountAmbiguous` —— 含"数据 A + 预圈 B(≠A)"的不一致 (逼用户 --account 选,
    // 不谎报 A 全采而 B 其实选择性)。
    let mut union: std::collections::BTreeSet<String> = account_shas(&conn)?.into_iter().collect();
    union.extend(capture_target_account_shas(&conn)?);
    match union.len() {
        0 => Ok(None),
        1 => Ok(union.into_iter().next()),
        _ => {
            let c = account_candidates(&conn);
            Err(crate::error::cli_err(
                native_core::ErrorCode::AccountAmbiguous,
                format!(
                    "多账号 (数据表或采集清单) 需指定 --account (数据表候选: {}); 或用 `accounts` 命令看全部",
                    if c.is_empty() {
                        "无可命名候选".to_string()
                    } else {
                        c.join(", ")
                    }
                ),
            ))
        }
    }
}

/// R19 (审 round-4 P2): 从 `capture_targets` 取 distinct `account_id_sha` (表不存在 → 空 `Vec`)。**仅** [`resolve_capture_account_sha`]
/// 在无数据表账号时兜底用 —— 让预 ingest 的采集清单在 `capture list` (无 --account) 可见; 不进通用 [`account_shas`] (防孤儿毒化)。
fn capture_target_account_shas(conn: &rusqlite::Connection) -> Result<Vec<String>> {
    let has: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='capture_targets'",
        [],
        |r| r.get(0),
    )?;
    if has == 0 {
        return Ok(Vec::new());
    }
    let mut st = conn.prepare("SELECT DISTINCT account_id_sha FROM capture_targets")?;
    let shas = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(shas)
}

/// 多账号时能命名的候选 wxid (person 里 distinct `account_id` 明文; 可能不全 → 皮层文案引导用列账号命令看全量)。
/// `pub`: 皮层 `/accounts` 列账号 + mentions_me 派生"自己"wxid 复用同一取数 (免漂移)。**注 `LIMIT 8`** ——
/// 用于歧义候选够, 但当"列全部账号"端点用时 >8 账号会静默截断 (真实多账号库罕见到 8; 皮层若做全量列账号须自行去限)。
pub fn account_candidates(conn: &rusqlite::Connection) -> Vec<String> {
    conn.prepare("SELECT DISTINCT account_id FROM person WHERE account_id IS NOT NULL LIMIT 8")
        .and_then(|mut st| {
            st.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()
        })
        .unwrap_or_default()
}

/// 表是否有 `account_id_sha` 列 (PRAGMA table_info; 第 1 列 = 列名)。
fn table_has_account_col(conn: &rusqlite::Connection, table: &str) -> bool {
    // table 来自 sqlite_master 真表名 (无注入); PRAGMA 不接绑参故内联。
    conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .and_then(|mut st| {
            st.query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<String>>>()
        })
        .is_ok_and(|cols| cols.iter().any(|c| c == "account_id_sha"))
}

/// 把"库里缺某派生表"(未 ingest)的查询错 → **NEEDS_INGEST(退出5)** 附 ingest 提示;其余错原样上抛。
/// 信封审 rank4: `no such table` 是"该操作只有冷查能做但未 ingest"的确切信号, 别归 INTERNAL/70。
/// `ingest_hint` 说清补哪个 ingest (如 "先跑 `msgvestige ingest --transfers")。
pub fn needs_ingest_err(e: anyhow::Error, ingest_hint: &str) -> anyhow::Error {
    if e.chain().any(|c| c.to_string().contains("no such table")) {
        cli_err(
            native_core::ErrorCode::NeedsIngest,
            format!("{ingest_hint} (该表未 ingest)"),
        )
    } else {
        e
    }
}

// ── 查询登记表 + 通用引擎 (查询内核 v1; 收 clean 单表 LIMIT 档命令样板; 设计见 20-讨论沉淀/CLI-查询登记表-引擎设计.md §8) ──

/// 表格显示格式。**json 永远原值**, `Fmt` 只管 table 渲染 (装饰只进渲染层, 不进 SQL → 保 json=原值 铁律)。
#[allow(dead_code)] // Trunc/Hidden 等变体是词汇一部分, 待后续命令逐批港上引擎时用 (§8 建序)。
pub enum Fmt {
    /// 原样。
    Raw,
    /// 毫秒时间戳 → `[ts]`。
    Time,
    /// 分 → `X.XX元`。
    Money,
    /// i64 码 → 人话 (如 1→已付)。
    EnumI64(&'static [(i64, &'static str)]),
    /// 字符串码 → 人话 (如 "join"→进群; 无匹配退原值)。
    EnumStr(&'static [(&'static str, &'static str)]),
    /// 浮点保留 n 位 (经纬度)。
    Float(usize),
    /// 字节数 → `NB`。
    Bytes,
    /// 截断长文本到 n 字符。
    Trunc(usize),
    /// 只进 json, 不上 table。
    Hidden,
}

/// 一列: SQL 片段 (表别名 `t`=登记项主表 / `m`=JOIN 的 message) + json 键 + 显示格式。
pub struct Col {
    pub sql: &'static str,
    pub key: &'static str,
    pub fmt: Fmt,
}

/// 一条查询命令登记项 (clean 单表 LIMIT 档)。复杂命令 (聚合/多表合并/游标/有状态) 不进本表, 保留手写 (§8)。
pub struct QueryCommand {
    /// 表头人话 (如 "位置分享")。
    pub label: &'static str,
    /// 主表名 (别名固定 `t`)。
    pub table: &'static str,
    /// true = JOIN message m ON PK 三元组 (取 m.create_time/m.conv_id)。
    pub join_message: bool,
    /// 固定基谓词 (files/links/thread/events 用; None = 无)。
    pub base_where: Option<&'static str>,
    /// 有序输出列。
    pub columns: &'static [Col],
    /// ORDER BY 子句 (如 "m.create_time DESC")。
    pub order_by: &'static str,
    /// 缺表时人话提示。
    pub needs_ingest_hint: &'static str,
    /// 跨列/条件装饰的整行渲染钩子 (mentions/cards 等); None = 逐列按 fmt join。
    /// §6② 起吃**已组好的 json 行对象** (非 rusqlite 位置元组) —— 与 `render_table` 读 `data` 一致。
    pub row_render: Option<fn(&serde_json::Value) -> String>,
}

/// serde_json Value → 显示串 (NULL → 空;整数/浮点走各自 Display)。
/// (BLOB 已在 [`value_json`] 阶段 → `Null` 不外泄字节 → 此处 → 空串; 引擎命令列均不选 BLOB 列, 无影响。)
fn value_display(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else if let Some(f) = n.as_f64() {
                f.to_string()
            } else {
                String::new()
            }
        }
        serde_json::Value::String(s) => s.clone(),
        // value_json 只产 Null/Number/String → Null 与其余非预期变体统一空串。
        _ => String::new(),
    }
}

/// rusqlite Value → serde_json (原值; BLOB → null 不外泄字节)。
fn value_json(v: &rusqlite::types::Value) -> serde_json::Value {
    use rusqlite::types::Value;
    match v {
        Value::Null | Value::Blob(_) => serde_json::Value::Null,
        Value::Integer(i) => (*i).into(),
        Value::Real(r) => (*r).into(),
        Value::Text(s) => s.clone().into(),
    }
}

/// 按 `Fmt` 渲染一格 (表格用; 读 **json** Value —— int/real 走 Number, text 走 String)。
/// 与旧 rusqlite 版逐值同构: `value_json` 忠实映射 (Integer→int / Real→f64 / Text→String), 故
/// `as_i64()`/`is_f64()`/`String` 匹配恰复刻原 `Value::Integer`/`Value::Real`/`Value::Text` 分支。
fn render_cell(v: &serde_json::Value, fmt: &Fmt) -> String {
    match fmt {
        Fmt::Hidden => String::new(),
        Fmt::Raw => value_display(v),
        Fmt::Time => match v.as_i64() {
            Some(t) => format!("[{t}]"),
            None => value_display(v),
        },
        Fmt::Money => match v.as_i64() {
            Some(f) => format!("{:.2}元", f as f64 / 100.0),
            None => value_display(v),
        },
        Fmt::EnumI64(m) => match v.as_i64() {
            Some(c) => m
                .iter()
                .find(|(k, _)| *k == c)
                .map_or_else(|| c.to_string(), |(_, s)| (*s).to_string()),
            None => value_display(v),
        },
        Fmt::EnumStr(m) => {
            if let serde_json::Value::String(s) = v {
                m.iter()
                    .find(|(k, _)| *k == s)
                    .map_or_else(|| s.clone(), |(_, val)| (*val).to_string())
            } else {
                value_display(v)
            }
        }
        Fmt::Float(p) => {
            // 只对**浮点** json Number 定小数位 (原码只 match Value::Real);整数/文本退 value_display。
            if v.is_f64() {
                let x = v.as_f64().unwrap();
                format!("{x:.*}", *p)
            } else {
                value_display(v)
            }
        }
        Fmt::Bytes => match v.as_i64() {
            Some(n) => format!("{n}B"),
            None => value_display(v),
        },
        Fmt::Trunc(n) => value_display(v).chars().take(*n).collect(),
    }
}

/// 查询引擎登记表 —— 所有走 `run_query` 的 clean 单表命令 (含折进父命令的子视图) 的唯一真相源。
/// 覆盖测试 (`every_l1_table_has_command_or_exempt`, msgvestige) 拿它核 "每张 L1 表要么有命令要么显式豁免";
/// P3 建 HTTP/MCP 时也照这张表镜像 → 三皮同核。新增登记项 → 加进这里 + 对应 `pub static CMD_*`。
pub static REGISTRY: &[&QueryCommand] = &[
    &CMD_LOCATIONS,
    &CMD_CARDS,
    &CMD_MEDIA,
    &CMD_GROUP_EVENTS,
    &CMD_EMOTICONS,
    &CMD_AVATARS,
    &CMD_HONGBAO,
    &CMD_MOMENT_FEED,
    &CMD_BIZ_CONTACTS,
    &CMD_INTERACTIONS,
    &CMD_SNS_NOTIFY,
    &CMD_FAV_TAGS,
    &CMD_FAV_MEDIA,
    &CMD_CHATROOMS,
    &CMD_GROUP_PAY_MEMBERS,
];

/// 通用查询引擎: 组 SQL → COUNT 真 total → LIMIT 取行 → 组 `QueryResult{data, meta}` **返回 (不打印)**。
/// `data` = json 行 (三皮通吃); `meta` = `Meta::page`(全量 total + 精确 has_more) + `source=cold`。
///
/// **③b 多账号**: `target.account` (wxid) 存在时, [`open_l1_scoped`] 对账号域表建遮蔽视图 → COUNT/SELECT
/// 里裸 `FROM t` 自动只见该账号行 (**引擎侧零 SQL 改动**, 全 CMD_* 白拿隔离); `meta.account` 填 sha8 标签。
pub fn run_query(cmd: &QueryCommand, target: &QueryTarget, limit: usize, offset: usize) -> Result<QueryResult> {
    run_query_with_deadline(cmd, target, limit, offset, None)
}

/// codex-R7 P2#2: 带可选 SQLite deadline 的 registry 冷查 —— HTTP `cold_cmd` 传 `Some(30)` 给算力界。run_query 内部
/// 自开 conn, 调用方挂不上 progress_handler; 且 `LIMIT/OFFSET` 只限**输出**不限扫描/skip (大 offset 仍全扫+跳过 N 行
/// 空跑) → 超时的 spawn_blocking SQL 空转吃 CPU + 占冷查闸。`None` = CLI 无界 (长导出不掐)。
pub fn run_query_with_deadline(
    cmd: &QueryCommand,
    target: &QueryTarget,
    limit: usize,
    offset: usize,
    deadline_secs: Option<u64>,
) -> Result<QueryResult> {
    // R9 复审R3#1: run_query 也走 resolve_account fail-closed —— registry CMD_* (locations/cards/media 等) 经此,
    // 原直接 open_l1_scoped(account_sha()) 未给 --account 时 None → 裸开混账号。open_l1_resolved: 多账号未指定 → 报错。
    let acct_sha = target.account_sha();
    let conn = open_l1_resolved(target)?;
    // codex-R9 P2: 用标志记录 progress_handler 是否真触发中断 —— fetch 的 `filter_map(ok_or_warn)` 会把行迭代阶段的
    // SQLITE_INTERRUPT 当坏行**吞掉** → 返回 Ok(部分数据)。查完据此标志补判(见 fetch 后), 否则超时静默返部分结果。
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Some(secs) = deadline_secs {
        // registry 冷查算力界 (照 cold()/search deadline 范式): 超时的后台查询自停 (SQLITE_INTERRUPT), 不空跑吃 CPU。
        let flag = interrupted.clone();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        conn.progress_handler(
            100_000,
            Some(move || {
                if std::time::Instant::now() > deadline {
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }),
        );
    }
    let sel = cmd.columns.iter().map(|c| c.sql).collect::<Vec<_>>().join(", ");
    let from = if cmd.join_message {
        format!(
            "FROM {} t JOIN message m ON t.account_id_sha=m.account_id_sha \
             AND t.source=m.source AND t.source_native_id=m.source_native_id",
            cmd.table
        )
    } else {
        format!("FROM {} t", cmd.table)
    };
    let where_ = cmd.base_where.map(|w| format!(" WHERE {w}")).unwrap_or_default();
    let ncol = cmd.columns.len();
    let fetch = || -> Result<(Vec<Vec<rusqlite::types::Value>>, usize)> {
        let total: i64 = conn.query_row(&format!("SELECT count(*) {from}{where_}"), [], |r| r.get(0))?;
        let mut st = conn.prepare(&format!(
            "SELECT {sel} {from}{where_} ORDER BY {} LIMIT ?1 OFFSET ?2",
            cmd.order_by
        ))?;
        let rows = st
            .query_map(rusqlite::params![limit as i64, offset as i64], |row| {
                (0..ncol)
                    .map(|i| row.get::<_, rusqlite::types::Value>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })?
            .filter_map(ok_or_warn)
            .collect::<Vec<_>>();
        Ok((rows, usize::try_from(total).unwrap_or(0)))
    };
    let (rows, total) = fetch()
        .with_context(|| format!("查 {} 表失败", cmd.table))
        .map_err(|e| needs_ingest_err(e, cmd.needs_ingest_hint))?;
    // codex-R9 P2: 中断被 fetch 的 filter_map(ok_or_warn) 吞成 Ok(部分) 时, 据标志抛真正的 SQLITE_INTERRUPT —— 皮层
    // is_query_interrupted 识别 → 408, 别把超时截断的部分结果当 200 完整返回。
    if interrupted.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),
            Some("registry 冷查超 deadline 被中断 (结果不完整)".to_string()),
        )
        .into());
    }
    // json data (含 Hidden 列: json 出全量, table 才滤 Hidden)。
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let obj: serde_json::Map<String, serde_json::Value> = cmd
                .columns
                .iter()
                .zip(row)
                .map(|(c, v)| (c.key.to_string(), value_json(v)))
                .collect();
            serde_json::Value::Object(obj)
        })
        .collect();
    // 冷查列表: Meta::page(本页, 真全量) → total_count + 精确 has_more; source=cold (与旧 print_query_json 同)。
    let mut meta = Meta::offset_page(offset, data.len(), total, limit).with_source(Source::Cold);
    // ③b: 指定账号时 meta.account = sha8 标签 (account_sha 已 64 hex, open_l1_scoped 验过)。
    if let Some(sha) = &acct_sha {
        meta.account = Some(sha[..8].to_string());
    }
    Ok(QueryResult { data, meta })
}

/// 把 `run_query` 产的 json `data` 按登记项 `Fmt` 渲成 table 文本 (每行末带 `\n`; 空 data → 空串)。
/// 呈现皮层调 (CLI); 逐字节等价于旧 `run_query` table 分支的逐行 `println!`。表头/条数由皮层另打 (stderr)。
pub fn render_table(cmd: &QueryCommand, data: &[serde_json::Value]) -> String {
    let mut out = String::new();
    for row in data {
        let line = cmd.row_render.map_or_else(
            || {
                cmd.columns
                    .iter()
                    .filter(|c| !matches!(c.fmt, Fmt::Hidden))
                    .map(|c| render_cell(row.get(c.key).unwrap_or(&serde_json::Value::Null), &c.fmt))
                    .collect::<Vec<_>>()
                    .join("  ")
            },
            |rr| rr(row),
        );
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// `locations` 登记项 (查询引擎首个 clean 单表命令; 验引擎)。
pub static CMD_LOCATIONS: QueryCommand = QueryCommand {
    label: "位置分享",
    table: "message_location",
    join_message: true,
    base_where: None,
    columns: &[
        Col {
            sql: "m.create_time",
            key: "create_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "m.conv_id",
            key: "conv_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.latitude",
            key: "latitude",
            fmt: Fmt::Float(5),
        },
        Col {
            sql: "t.longitude",
            key: "longitude",
            fmt: Fmt::Float(5),
        },
        Col {
            sql: "t.poiname",
            key: "poiname",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.label",
            key: "label",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.cityname",
            key: "cityname",
            fmt: Fmt::Raw,
        },
    ],
    // R16-2: 补唯一次键 (源 message.source + source_native_id) —— 原单键 create_time 同毫秒 tie 序非确定 (offset 翻页
    // 潜在重漏 + 冷热无法对齐)。message_location⋈message 是 1:1 PK JOIN, (m.source, m.source_native_id) 唯一定序。
    order_by: "m.create_time DESC, m.source DESC, m.source_native_id DESC",
    needs_ingest_hint: "先 ingest 消息 (位置是消息派生的 message_location 表)",
    row_render: None,
};

/// `cards` 登记项 (message_card ⋈ message; 独立实体, 直接港)。
pub static CMD_CARDS: QueryCommand = QueryCommand {
    label: "名片",
    table: "message_card",
    join_message: true,
    base_where: None,
    columns: &[
        Col {
            sql: "m.create_time",
            key: "create_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "m.conv_id",
            key: "conv_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.card_nickname",
            key: "card_nickname",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.card_alias",
            key: "card_alias",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.card_username",
            key: "card_username",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.card_open_im_desc",
            key: "company",
            fmt: Fmt::Raw,
        },
    ],
    // R16-2: 补唯一次键 (同 CMD_LOCATIONS): 原单键 create_time 同毫秒 tie 序非确定。message_card⋈message 1:1 PK JOIN。
    order_by: "m.create_time DESC, m.source DESC, m.source_native_id DESC",
    needs_ingest_hint: "先 ingest 消息 (名片是消息派生的 message_card 表)",
    row_render: None,
};

/// `media` 登记项 (message_media ⋈ message; 独立实体; cdn_url 只进 json 不上表格)。
pub static CMD_MEDIA: QueryCommand = QueryCommand {
    label: "媒体清单",
    table: "message_media",
    join_message: true,
    base_where: None,
    columns: &[
        Col {
            sql: "m.create_time",
            key: "create_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "m.conv_id",
            key: "conv_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.media_kind",
            key: "media_kind",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.md5",
            key: "md5",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.file_size",
            key: "file_size",
            fmt: Fmt::Bytes,
        },
        Col {
            sql: "t.play_length",
            key: "play_length",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.cdn_url",
            key: "cdn_url",
            fmt: Fmt::Hidden,
        },
    ],
    // R16-2: 补唯一次键 (同 CMD_LOCATIONS/CMD_CARDS, 5420d74 未覆盖 media): 原单键 create_time 同毫秒 tie 序非确定
    // (offset 翻页潜在重漏 + 冷热无法对齐)。message_media⋈message 是 1:1 PK JOIN, (m.source, m.source_native_id) 唯一定序。
    order_by: "m.create_time DESC, m.source DESC, m.source_native_id DESC",
    needs_ingest_hint: "先 ingest 消息 (媒体清单是消息派生的 message_media 表)",
    row_render: None,
};

/// `group-events` 登记项 (chatroom_member_event; 独立实体; event_kind 字符串码走 EnumStr)。
pub static CMD_GROUP_EVENTS: QueryCommand = QueryCommand {
    label: "群进出记录",
    table: "chatroom_member_event",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.event_time",
            key: "event_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "t.conv_id",
            key: "conv_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.event_kind",
            key: "event_kind",
            fmt: Fmt::EnumStr(&[("join", "进群"), ("remove", "退群")]),
        },
        Col {
            sql: "t.member_nickname",
            key: "member_nickname",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.member_wxid",
            key: "member_wxid",
            fmt: Fmt::Raw,
        },
    ],
    // R16-2: 原单键 `t.event_time DESC` —— 同秒多成员进出(一消息多行 / 多消息同秒)并列 → offset 翻页跨页重漏, 且与
    // 热查(有界 TopN 需确定序)对不上。补 (source, source_native_id) 次键 = 本表 PK 尾(source_native_id=anchor:seq
    // 逐成员唯一)→ 全序确定; 热查 hot_group_events 同这 3 键 DESC。硬约束⑥(单键 order_by 补次键)。
    order_by: "t.event_time DESC, t.source DESC, t.source_native_id DESC",
    needs_ingest_hint: "先 ingest 消息 (群进出是系统消息派生的 chatroom_member_event 表)",
    row_render: None,
};

/// `emoticons` 登记项 (custom_emoticon; 独立实体; cdn_url 只进 json)。
pub static CMD_EMOTICONS: QueryCommand = QueryCommand {
    label: "自定义表情",
    table: "custom_emoticon",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.caption",
            key: "caption",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.md5",
            key: "md5",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.emoticon_type",
            key: "emoticon_type",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.product_id",
            key: "product_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.cdn_url",
            key: "cdn_url",
            fmt: Fmt::Hidden,
        },
    ],
    // R16-1: 从 `rowid DESC` 改成 `t.md5 DESC` —— **冷热同键才对等**(硬约束④)。热查读源库,
    // 源库 rowid 跟 L1 rowid 是两套、对不上; 而 `md5` 两边都是现成列且唯一(它就是 source_native_id
    // 的来源: `Emoticon_<md5>`)。同 finder 用 owner_username / friend-requests 用 user_name 的手法。
    // 只此一处用 rowid DESC(核过, 不牵连别的引擎命令), 且无测试锁旧序。
    order_by: "t.md5 DESC",
    needs_ingest_hint: "先 ingest (自定义表情来自收藏表 custom_emoticon)",
    row_render: None,
};

/// `avatars` 登记项 (avatar_image; 独立实体; 不露 BLOB)。
pub static CMD_AVATARS: QueryCommand = QueryCommand {
    label: "头像",
    table: "avatar_image",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.username",
            key: "username",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.md5",
            key: "md5",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.update_time",
            key: "update_time",
            fmt: Fmt::Time,
        },
    ],
    // R16-1: 补次键 username, md5 —— update_time 单键并列很常见(同秒多头像更新), SQLite 翻页不稳;
    // 热查也用这三键(rowid 两库不能对齐, username+md5 两皮都可访问, 硬约束④)。
    order_by: "t.update_time DESC, t.username, t.md5",
    needs_ingest_hint: "先 ingest (头像来自 avatar_image 表)",
    row_render: None,
};

/// `hongbao` 登记项 (message_hongbao_claim ⋈ message; 乙: 后折 money claims; is_own_envelope 走 EnumI64)。
pub static CMD_HONGBAO: QueryCommand = QueryCommand {
    label: "红包领取明细",
    table: "message_hongbao_claim",
    join_message: true,
    base_where: None,
    columns: &[
        Col {
            sql: "m.create_time",
            key: "create_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "m.conv_id",
            key: "conv_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.send_id",
            key: "send_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.is_own_envelope",
            key: "is_own_envelope",
            fmt: Fmt::EnumI64(&[(0, "我领的"), (1, "我发的被领")]),
        },
        Col {
            sql: "t.peer_name",
            key: "peer_name",
            fmt: Fmt::Raw,
        },
    ],
    // R16-4: 单键 create_time 补次键 (source, source_native_id = 消息 PK 尾, 一消息一 claim 故唯一) → offset 跨页不重不漏,
    // 与热查 hot_hongbao_claims 的 TopN (create_time/source/source_native_id DESC) 逐字节同序。
    order_by: "m.create_time DESC, m.source DESC, m.source_native_id DESC",
    needs_ingest_hint: "先 ingest 消息 (红包领取是消息派生的 message_hongbao_claim 表)",
    row_render: None,
};

// (CMD_HONGBAO 登记项由 `money --claims` 分派复用; 已撤独立 hongbao 命令 — 乙折父子。)

/// `moment-feed` 登记项 (moment_feed; 乙: 后折 moments feed; is_read 走 EnumI64)。
pub static CMD_MOMENT_FEED: QueryCommand = QueryCommand {
    label: "好友朋友圈索引",
    table: "moment_feed",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.tid",
            key: "tid",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.author",
            key: "author",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.create_time",
            key: "create_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "t.is_read",
            key: "is_read",
            fmt: Fmt::EnumI64(&[(0, "未读"), (1, "已读")]),
        },
    ],
    order_by: "t.create_time DESC",
    needs_ingest_hint: "先 ingest 朋友圈 (moment_feed 是好友动态索引)",
    row_render: None,
};

// (CMD_MOMENT_FEED 登记项由 `moments --feed` 分派复用; 已撤独立 moment-feed 命令 — 乙折父子。)

/// `biz-contacts` 登记项 (bizchat_user; 独立实体; contacts 走游标故 biz 独立)。
pub static CMD_BIZ_CONTACTS: QueryCommand = QueryCommand {
    label: "企微联系人",
    table: "bizchat_user",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.user_name",
            key: "user_name",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.user_id",
            key: "user_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.brand_user_name",
            key: "brand_user_name",
            fmt: Fmt::Raw,
        },
    ],
    // R16-1: 补次键 user_id —— user_name 可重名不唯一, 单键翻页不稳; 热查也用这两键(user_id 是身份唯一,
    // 两皮都可访问, rowid 不能对齐, 硬约束④)。
    order_by: "t.user_name, t.user_id",
    needs_ingest_hint: "先 ingest (企微联系人来自 bizchat.db → bizchat_user 表)",
    row_render: None,
};

/// `interactions` 登记项 (moment_interaction; 乙: 后折 moments interactions; kind 走 EnumStr)。
pub static CMD_INTERACTIONS: QueryCommand = QueryCommand {
    label: "朋友圈点赞评论",
    table: "moment_interaction",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.create_time",
            key: "create_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "t.kind",
            key: "kind",
            fmt: Fmt::EnumStr(&[("like", "赞"), ("comment", "评论")]),
        },
        Col {
            sql: "t.from_nickname",
            key: "from_nickname",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.from_user",
            key: "from_user",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.content",
            key: "content",
            fmt: Fmt::Raw,
        },
    ],
    // R16-3: 原单键 `t.create_time DESC` —— 互动 create_time **赞常为 0**(大量并列)→ offset 翻页跨页重漏, 且与热查
    // (内存排序需确定序)对不上。补**全 PK 尾** (source, source_native_id, interaction_seq) 次键(codex sns_notify 审 P2:
    // 与 group-events 一族对齐、匹配 moment_interaction 唯一键 = account_id_sha+这三列)→ 全序确定。**source 对 sns 派生表恒
    // "sns.db"**(单文件, 非 message 分片式变值)→ 此列实为退化常量、加它只为 PK 完备+跨表一致, 不改实际序; 热查
    // hot_interactions 内存排序 (create_time, source_native_id, interaction_seq)——source 常量省, 与本 3 键 DESC 等价
    // (create_time/interaction_seq 数值序, source_native_id 字节序)。硬约束⑥。
    order_by: "t.create_time DESC, t.source DESC, t.source_native_id DESC, t.interaction_seq DESC",
    needs_ingest_hint: "先 ingest 朋友圈 (点赞评论是 moment 派生的 moment_interaction 表)",
    row_render: None,
};

// (CMD_INTERACTIONS 登记项由 `moments --interactions` 分派复用; 已撤独立 interactions 命令 — 乙折父子。)

/// `sns-notify` 登记项 (sns_notify; 乙: 后折 moments inbox)。
pub static CMD_SNS_NOTIFY: QueryCommand = QueryCommand {
    label: "朋友圈互动通知",
    table: "sns_notify",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.create_time",
            key: "create_time",
            fmt: Fmt::Time,
        },
        Col {
            sql: "t.notify_type",
            key: "notify_type",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.from_user",
            key: "from_user",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.from_nickname",
            key: "from_nickname",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.content",
            key: "content",
            fmt: Fmt::Raw,
        },
    ],
    // R16-3: 原单键 `t.create_time DESC` —— 同秒多通知并列 → offset 翻页跨页重漏, 且与热查(内存排序需确定序)对不上。
    // 补**全 PK 尾** (source, source_native_id) 次键(codex 审 P2: 与 group-events 一族对齐、匹配 sns_notify 唯一键)→
    // 全序确定。**source 对 sns 派生表恒 "sns.db"**(单文件退化常量)→ 加它只为 PK 完备+跨表一致, 不改实际序; 热查
    // hot_sns_notify 内存排序 (create_time, source_native_id)——source 常量省, 与本 2 键 DESC 等价(source_native_id=
    // "SnsNotify_<rowid>" 每通知唯一; create_time 数值序, source_native_id 字节序)。硬约束⑥。
    order_by: "t.create_time DESC, t.source DESC, t.source_native_id DESC",
    needs_ingest_hint: "先 ingest 朋友圈 (互动通知是 sns.db 派生的 sns_notify 表)",
    row_render: None,
};

// (CMD_SNS_NOTIFY 登记项由 `moments --inbox` 分派复用; 已撤独立 sns-notify 命令 — 乙折父子。)

/// `fav-tags` 登记项 (favorite_tag; 乙: 后折 favorites tags)。
pub static CMD_FAV_TAGS: QueryCommand = QueryCommand {
    label: "收藏标签",
    table: "favorite_tag",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.tag_server_id",
            key: "tag_server_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.fav_server_id",
            key: "fav_server_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.tag_name",
            key: "tag_name",
            fmt: Fmt::Raw,
        },
    ],
    // R16-3: 原单键 `t.tag_server_id DESC` **不成全序** —— 一标签贴多收藏 → 多行同 tag_server_id 并列 → offset 翻页
    // 跨页重漏。补 source_native_id 次键 = favorite_tag PK 尾(source_native_id="FavoriteTag_<tag_local>_<fav_local>"
    // **local id, R16-3 根治未同步退化**, 每 (标签,收藏) 对唯一)→ 全序确定; 热查 hot_favorite_tags 同
    // (tag_server_id DESC, source_native_id DESC)。硬约束⑥。
    order_by: "t.tag_server_id DESC, t.source_native_id DESC",
    needs_ingest_hint: "先 ingest 收藏 (标签来自 favorite_tag 表)",
    row_render: None,
};

// (CMD_FAV_TAGS 登记项由 `favorites --tags` 分派复用; 已撤独立 fav-tags 命令 — 乙折父子。)

/// `fav-media` 登记项 (favorite_media; 乙: 后折 favorites media; data_type EnumI64 / media_size Bytes)。
pub static CMD_FAV_MEDIA: QueryCommand = QueryCommand {
    label: "收藏媒体",
    table: "favorite_media",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.fav_server_id",
            key: "fav_server_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.seq",
            key: "seq",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.data_type",
            key: "data_type",
            fmt: Fmt::EnumI64(&[(2, "图"), (6, "文件"), (8, "HTML")]),
        },
        Col {
            sql: "t.media_md5",
            key: "media_md5",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.media_size",
            key: "media_size",
            fmt: Fmt::Bytes,
        },
        Col {
            sql: "t.data_fmt",
            key: "data_fmt",
            fmt: Fmt::Raw,
        },
    ],
    // R16-3: 原 (fav_server_id DESC, seq) **不成全序** —— **未同步收藏 server_id=0** 会并列(多收藏同 server_id=0、
    // 各自 seq 从 0 起 → (fav_server_id, seq) 撞)→ offset 翻页跨页重漏。补 source_native_id 次键 = favorite_media
    // PK 尾(source_native_id="Favorite_<local_id>" 所属收藏, 与 seq 合成唯一)→ 全序确定; 热查 hot_favorite_media
    // 同 (fav_server_id DESC, source_native_id DESC, seq ASC)(seq 无 DESC)。硬约束⑥。
    order_by: "t.fav_server_id DESC, t.source_native_id DESC, t.seq",
    needs_ingest_hint: "先 ingest 收藏 (媒体引用来自 favorite_media 表)",
    row_render: None,
};

// (CMD_FAV_MEDIA 登记项由 `favorites --media` 分派复用; 已撤独立 fav-media 命令 — 乙折父子。)

/// `chatrooms` 登记项 (chatroom; 独立实体; announcement 走 Trunc(20))。
pub static CMD_CHATROOMS: QueryCommand = QueryCommand {
    label: "群",
    table: "chatroom",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.chatroom_id",
            key: "chatroom_id",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.chatroom_name",
            key: "chatroom_name",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.owner_wxid",
            key: "owner_wxid",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.member_count",
            key: "member_count",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.announcement",
            key: "announcement",
            fmt: Fmt::Trunc(20),
        },
    ],
    // R16-1: 补次键 chatroom_id —— member_count 单键并列很多群(同人数)时 SQLite 翻页不稳(重复/漏行),
    // 且热查也用这两键(冷热都能访问 chatroom_id, 硬约束④)。chatroom_id 是 PK 唯一 → 全序。
    order_by: "t.member_count DESC, t.chatroom_id",
    needs_ingest_hint: "先 ingest 联系人/群 (chatroom 表)",
    row_render: None,
};

/// `group-pay-members` 登记项 (group_pay_member; 乙: 后折 money payers; amount Money / pay_status EnumI64)。
pub static CMD_GROUP_PAY_MEMBERS: QueryCommand = QueryCommand {
    label: "群收款付款人",
    table: "group_pay_member",
    join_message: false,
    base_where: None,
    columns: &[
        Col {
            sql: "t.bill_no",
            key: "bill_no",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.payer_wxid",
            key: "payer_wxid",
            fmt: Fmt::Raw,
        },
        Col {
            sql: "t.amount",
            key: "amount_fen",
            fmt: Fmt::Money,
        },
        Col {
            sql: "t.pay_status",
            key: "pay_status",
            fmt: Fmt::EnumI64(&[(0, "未付"), (1, "已付")]),
        },
    ],
    // R16-4: 单键 bill_no 补全 PK 尾次键 (source, source_native_id, payer_wxid) —— **一对多** (一群收款消息多付款人),
    // bill_no 非唯一; 补到 PK (account, source, source_native_id, payer_wxid_sha) 的可见列尾 → offset 跨页不重不漏,
    // 与热查 hot_group_pay_members 的全量 sort (bill_no/source/source_native_id/payer_wxid DESC) 逐字节同序。
    order_by: "t.bill_no DESC, t.source DESC, t.source_native_id DESC, t.payer_wxid DESC",
    needs_ingest_hint: "先 ingest 消息 (群收款付款人是消息派生的 group_pay_member 表)",
    row_render: None,
};

// (CMD_GROUP_PAY_MEMBERS 登记项由 `money --payers` 分派复用; 已撤独立 group-pay-members 命令 — 乙折父子。)

#[cfg(test)]
mod collect_ok_tests {
    use super::collect_ok;

    /// R4 复审R3#5: `collect_ok` 收 Ok 行 + 数 Err 丢弃行 (给非 offset 分页出 dropped_rows)。
    #[test]
    fn collect_ok_counts_dropped() {
        let items: Vec<Result<i32, String>> = vec![Ok(1), Err("坏行".into()), Ok(3), Err("又坏".into()), Ok(5)];
        let (good, dropped) = collect_ok(items.into_iter());
        assert_eq!(good, vec![1, 3, 5], "只收 Ok 行");
        assert_eq!(dropped, 2, "数出 2 个 Err 丢弃行");
        // 全 Ok → dropped 0。
        let all_ok: Vec<Result<i32, String>> = vec![Ok(1), Ok(2)];
        assert_eq!(collect_ok(all_ok.into_iter()), (vec![1, 2], 0));
    }

    /// R5 复审 P2#3 (+R5b codex P2 重做为 fetch-limit): `collect_page` has_more=fetched==limit&&非空; 不 over-fetch (免翻页重复)。
    #[test]
    fn collect_page_fetch_limit_has_more_and_dropped() {
        use super::collect_page;
        // 满页无坏 (fetch 恰 limit): fetched==limit → has_more true (保守: 可能还有, 多翻一次拿空页也不漏)。
        let full: Vec<Result<i32, String>> = vec![Ok(1), Ok(2)];
        let (page, dropped, has_more) = collect_page(full.into_iter(), 2);
        assert_eq!((page, dropped), (vec![1, 2], 0));
        assert!(has_more, "读满 limit → 可能还有 (保守 true, 不假 false 漏页)");
        // R5 repro: [正常, 坏] 是 [正常,坏,正常,正常] limit2 的第 1 页 (SQL LIMIT 2 只读前 2 个)。fetched=2==limit → has_more
        // true → 消费者翻页拿到后面正常行, **不漏** (原 bug 是丢坏后 rows.len()≤limit 假 false)。坏行 → dropped=1。
        let with_bad: Vec<Result<i32, String>> = vec![Ok(1), Err("坏".into())];
        let (page, dropped, has_more) = collect_page(with_bad.into_iter(), 2);
        assert_eq!((page, dropped), (vec![1], 1));
        assert!(has_more, "满 limit 个 SQL 行(含坏) → has_more true, 翻页可达后续数据");
        // 不满一页 (fetched<limit) → 读到底, has_more false。
        let short: Vec<Result<i32, String>> = vec![Ok(1), Ok(2)];
        let (page, dropped, has_more) = collect_page(short.into_iter(), 5);
        assert_eq!((page, dropped, has_more), (vec![1, 2], 0, false));
        // R5b codex P2: 整批全坏 [Err,Err] limit=2 → fetched==limit 但 page 空 → has_more **false** (兜死循环:
        // new 的 watermark 无好行可推进, 否则消费者拿同一游标无限重查同批坏行)。dropped=本批全部坏行。
        let all_bad: Vec<Result<i32, String>> = vec![Err("坏".into()), Err("坏".into())];
        let (page, dropped, has_more) = collect_page(all_bad.into_iter(), 2);
        assert_eq!(page, Vec::<i32>::new(), "全坏 → 空页");
        assert_eq!(dropped, 2, "本批 2 个坏行");
        assert!(!has_more, "空页 → has_more false (不死循环)");
    }
}

#[cfg(test)]
mod account_scope_tests {
    use super::{account_shas, open_l1, open_l1_scoped};

    /// ③b fail-open 防线 (审查 P1-2): 账号 B 只在 message 无 person 行时, `account_shas` 仍数出 2 个账号
    /// (跨表并集, **不是**只探 person) → 调用方据此要求显式选账号, 不静默并库。只探 person 会漏 B。
    #[test]
    fn account_shas_unions_across_tables_not_just_person() {
        let sha_a = "a".repeat(64);
        let sha_b = "b".repeat(64);
        let tmp = std::env::temp_dir().join("nq_acct_union.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            // person 只有 A; message 有 A + B (B 只导了消息, 未导通讯录 —— 分步 ingest 的现实态)。
            c.execute_batch(&format!(
                "CREATE TABLE person(account_id_sha TEXT, username TEXT);
                 CREATE TABLE message(account_id_sha TEXT, body TEXT);
                 CREATE TABLE lookup(id INTEGER);
                 INSERT INTO person VALUES('{sha_a}','a1');
                 INSERT INTO message VALUES('{sha_a}','ma'),('{sha_b}','mb');"
            ))
            .unwrap();
        }
        let path = tmp.to_str().unwrap();
        let conn = open_l1(path).unwrap();
        let shas = account_shas(&conn).unwrap();
        assert_eq!(
            shas.len(),
            2,
            "并集须含 message 里独有的账号 B (只探 person 会漏 → fail-open)"
        );
        assert!(shas.contains(&sha_a) && shas.contains(&sha_b), "A 和 B 都在");
        drop(conn);
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19 (审 round-2 P2): `account_shas` **排除 capture_targets 控制面表** —— `capture add --account <孤儿wxid>` 写入的
    /// 未校验 sha 不该毒化账号枚举 (否则一个 typo 就把整库无-account 查询全误报 ACCOUNT_AMBIGUOUS, 而 /accounts 仍报真账号)。
    #[test]
    fn account_shas_excludes_capture_targets_orphan() {
        let sha_real = "d".repeat(64);
        let sha_orphan = "e".repeat(64); // capture add --account <typo> 注入的孤儿 (格式合法但非真账号)
        let tmp = std::env::temp_dir().join("nq_acct_orphan.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            c.execute_batch(&format!(
                "CREATE TABLE person(account_id_sha TEXT, username TEXT);
                 CREATE TABLE capture_targets(account_id_sha TEXT, conv_id TEXT);
                 INSERT INTO person VALUES('{sha_real}','me');
                 INSERT INTO capture_targets VALUES('{sha_real}','conv_a'),('{sha_orphan}','conv_ghost');"
            ))
            .unwrap();
        }
        let path = tmp.to_str().unwrap();
        let conn = open_l1(path).unwrap();
        let shas = account_shas(&conn).unwrap();
        assert_eq!(
            shas.len(),
            1,
            "capture_targets 的孤儿账号不毒化枚举 (只算数据表 person)"
        );
        assert!(
            shas.contains(&sha_real) && !shas.contains(&sha_orphan),
            "只真账号, 无孤儿"
        );
        drop(conn);
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19 (审 round-4 P2): 无数据表账号但 capture_targets 有单账号 → `resolve_capture_account_sha` 返该账号
    /// (预 ingest 圈定在 `capture list` 无 --account 时可见), 而非 `None` 谎报"空/全采"。
    #[test]
    fn resolve_capture_account_from_targets_when_no_data() {
        let sha_x = "f".repeat(64);
        let tmp = std::env::temp_dir().join("nq_cap_preingest.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            // 数据表空 (person 无行), 仅 capture_targets 有账号 X 的圈定 (预 ingest 场景)。
            c.execute_batch(&format!(
                "CREATE TABLE person(account_id_sha TEXT, username TEXT);
                 CREATE TABLE capture_targets(account_id_sha TEXT, conv_id TEXT);
                 INSERT INTO capture_targets VALUES('{sha_x}','conv_a');"
            ))
            .unwrap();
        }
        let got = super::resolve_capture_account_sha(tmp.to_str().unwrap(), None).unwrap();
        assert_eq!(
            got,
            Some(sha_x),
            "无数据账号时从 capture_targets 解析出 X (非 None 谎报空全采)"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19 (审 round-5 P2): 数据表账号 A + capture_targets 预圈账号 B(≠A) → union {A,B} → Ambiguous
    /// (逼 --account 选, 不静默选 A 谎报"全采"而 B 其实选择性)。
    #[test]
    fn resolve_capture_union_data_and_target_ambiguous() {
        let sha_a = "a".repeat(64); // 数据账号
        let sha_b = "b".repeat(64); // 仅 capture_targets 圈定 (≠ A)
        let tmp = std::env::temp_dir().join("nq_cap_union.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            c.execute_batch(&format!(
                "CREATE TABLE person(account_id_sha TEXT, username TEXT);
                 CREATE TABLE capture_targets(account_id_sha TEXT, conv_id TEXT);
                 INSERT INTO person VALUES('{sha_a}','me');
                 INSERT INTO capture_targets VALUES('{sha_b}','conv_b');"
            ))
            .unwrap();
        }
        let got = super::resolve_capture_account_sha(tmp.to_str().unwrap(), None);
        assert!(got.is_err(), "数据A + 预圈B → union 2 → Ambiguous");
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19 (审 round-5 P2 + round-10 P1): 显式 --account 校验 —— (a) 非法格式 (含空白/控制符) → BAD_REQUEST (格式校验在开库前,
    /// 路径可不存在); (b) 空数据 L1 (预 ingest) → 合法 wxid 放行 (无从校验存在, round-4 预圈); (c) populated L1 → 显式账号
    /// 必须是**已知数据账号**, typo (合法 wxid 但非本库账号) → BAD_REQUEST (防孤儿 sha 白名单致真账号仍全采、谎报"已圈定")。
    #[test]
    fn resolve_capture_explicit_account_validated() {
        // (a) 格式校验在开库前 → 非法 --account (含空格) 报错, 路径可不存在。
        assert!(
            super::resolve_capture_account_sha("/no/such/l1.db", Some("bad account".to_string())).is_err(),
            "非法 --account (含空格) → 报错"
        );
        // (b) 空数据 L1 (person 表存在但无行 = 预 ingest) → 合法 wxid 放行 (无数据账号可校验)。
        let empty = std::env::temp_dir().join("nq_cap_expl_empty.db");
        let _ = std::fs::remove_file(&empty);
        {
            let c = rusqlite::Connection::open(&empty).unwrap();
            c.execute_batch("CREATE TABLE person(account_id_sha TEXT, username TEXT);")
                .unwrap();
        }
        let ok = super::resolve_capture_account_sha(empty.to_str().unwrap(), Some("wxid_ok".to_string())).unwrap();
        assert!(ok.is_some(), "空数据 L1 → 合法 wxid 放行 (预 ingest 圈定可见)");
        let _ = std::fs::remove_file(&empty);
        // (c) populated L1 (数据账号 = sha256(wxid_alice)) → 已知账号放行, typo 拒。
        let pop = std::env::temp_dir().join("nq_cap_expl_pop.db");
        let _ = std::fs::remove_file(&pop);
        let sha_a = native_core::sha256_hex("wxid_alice");
        {
            let c = rusqlite::Connection::open(&pop).unwrap();
            c.execute_batch(&format!(
                "CREATE TABLE person(account_id_sha TEXT, username TEXT);
                 CREATE TABLE message(account_id_sha TEXT, body TEXT);
                 INSERT INTO person VALUES('{sha_a}','alice');
                 INSERT INTO message VALUES('{sha_a}','m');"
            ))
            .unwrap();
        }
        let good = super::resolve_capture_account_sha(pop.to_str().unwrap(), Some("wxid_alice".to_string())).unwrap();
        assert_eq!(good.as_deref(), Some(sha_a.as_str()), "populated L1 + 已知账号 → 放行");
        assert!(
            super::resolve_capture_account_sha(pop.to_str().unwrap(), Some("wxid_typo".to_string())).is_err(),
            "populated L1 + 未知账号 (typo) → 拒 (防孤儿白名单致真账号仍全采)"
        );
        let _ = std::fs::remove_file(&pop);
    }

    /// 单账号库: `account_shas` 恰 1 个 → 调用方可裸查 (不误判成多账号逼用户选)。
    #[test]
    fn account_shas_single_account_returns_one() {
        let sha_a = "c".repeat(64);
        let tmp = std::env::temp_dir().join("nq_acct_single.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            c.execute_batch(&format!(
                "CREATE TABLE person(account_id_sha TEXT, username TEXT);
                 CREATE TABLE message(account_id_sha TEXT, body TEXT);
                 INSERT INTO person VALUES('{sha_a}','a1'),('{sha_a}','a2');
                 INSERT INTO message VALUES('{sha_a}','m1');"
            ))
            .unwrap();
        }
        let path = tmp.to_str().unwrap();
        let conn = open_l1(path).unwrap();
        assert_eq!(account_shas(&conn).unwrap().len(), 1, "单账号 → 1");
        drop(conn);
        let _ = std::fs::remove_file(&tmp);
    }

    /// ③b: `open_l1_scoped(_, Some(sha))` 对含 `account_id_sha` 列的表建遮蔽过滤视图 → 只见该账号行;
    /// 无该列的表 (lookup) 不遮蔽; `None` 不过滤; 非 64 hex sha 拒 (防注入)。
    #[test]
    fn scope_view_isolates_by_account() {
        let sha_a = "a".repeat(64);
        let sha_b = "b".repeat(64);
        let tmp = std::env::temp_dir().join("nq_scope_iso.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            c.execute_batch(&format!(
                "CREATE TABLE person(account_id_sha TEXT, username TEXT);
                 CREATE TABLE lookup(id INTEGER);
                 INSERT INTO person VALUES('{sha_a}','a1'),('{sha_a}','a2'),('{sha_b}','b1');
                 INSERT INTO lookup VALUES(1),(2);"
            ))
            .unwrap();
        }
        let path = tmp.to_str().unwrap();
        // scope 到 A → person 只见 A 的 2 行 (裸 FROM person 命中遮蔽视图)。
        let conn = open_l1_scoped(path, Some(&sha_a)).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM person", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "scope A → 只 A 的 2 行");
        // exec 逃生口同样受遮蔽 (raw SQL 也过滤)。
        let distinct: i64 = conn
            .query_row("SELECT count(DISTINCT account_id_sha) FROM person", [], |r| r.get(0))
            .unwrap();
        assert_eq!(distinct, 1, "视图内只剩一个账号");
        // 无 account_id_sha 列的 lookup 不被遮蔽 → 全见。
        let l: i64 = conn.query_row("SELECT count(*) FROM lookup", [], |r| r.get(0)).unwrap();
        assert_eq!(l, 2, "无 account 列的表不遮蔽");
        drop(conn);
        // 无 scope → person 全 3 行。
        let conn2 = open_l1_scoped(path, None).unwrap();
        let n2: i64 = conn2
            .query_row("SELECT count(*) FROM person", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n2, 3, "无 scope → 全 3 行");
        drop(conn2);
        // 非 64 hex sha → BadRequest (视图内联字面量前的注入防线)。
        assert!(open_l1_scoped(path, Some("not-a-sha")).is_err(), "非 64 hex → 拒");
        assert!(open_l1_scoped(path, Some(&"z".repeat(64))).is_err(), "64 位非 hex → 拒");
        let _ = std::fs::remove_file(&tmp);
    }
}
