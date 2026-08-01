//! 冷路 keyset 分页 (内核 §6) —— O(1) 续翻, 非 offset 深翻。
//!
//! **反 anchor-688→98 的命脉**: 排序键**末列必唯一** (tiebreaker) → 全序 → 相邻页边界不丢/不重。
//! 值经 [`crate::cursor`] 不透明串往返 (`base64(版本|account|filter指纹|排序键)`); 绑 account+filter。
//!
//! **类型正确性 (关键)**: 每列在 [`SortCol`] 声明 [`ColType`], [`keyset_where`] 据此**按声明类型绑值**
//! (Int→`i64`、Text→字符串) —— 让比较**由构造即数值/字典正确**, 不倚赖 SQLite 列亲和度的隐式强转。
//! (补审订正: INTEGER **亲和度列**上, 就算误按字符串绑, SQLite 也会把 `"900"` 强转回数值 → 不丢行;
//! 故端到端数值守恒测**逮不到** int-vs-text 绑错 —— 真正守这条的是白盒 `int_cursor_value_binds_as_integer_not_text`
//! [直接断言 `Value::Integer`]。误按字符串绑只会咬**无整数亲和度**的排序列 [TEXT 列存数字串], 届时才字典序错序。)
//!
//! **NULL 限制**: 排序列 (含 tiebreaker) **须 NOT NULL**。row-value 比较 `(cols) </> (?)` 遇 NULL 得 NULL
//! (非真) → 该行被 keyset **静默排除 = 丢行**。contacts 用 `(username, source)` 复合键, 两列均 person PK
//! 成员 (NOT NULL) 安全; 接**可空 Int 列** (calls/messages 某些列) 前须加 `IS NOT NULL` 守卫或 `COALESCE`
//! 兜底 (补审留意, ③/P1 前处理)。
//!
//! P0 只接 `contacts` (`(username, source)` 复合唯一键, Asc/Text)。`Desc`/`Int`/更多列 keyset 路径由下方
//! 并列夹具测 **完整覆盖**, 随更多命令 (calls/messages…) 接入在生产启用 —— 那之前部分 API 仅测试用。

// P0 只接 contacts (Asc/Text 单键); Desc/Int/多列路径测试全覆盖、待更多命令接线后在生产启用 → 移除此行。
#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use native_core::ErrorCode;
use rusqlite::types::Value;
use rusqlite::{Connection, Row};

use crate::{cursor, CliError};

/// 排序方向 (全键**同向**; 混向不支持 —— row-value `<`/`>` 元组比较要求同向)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortDir {
    Asc,
    Desc,
}
impl SortDir {
    fn keyword(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
    /// 续翻比较向: ASC 下一页 = 严格大于末行键; DESC = 严格小于末行键。
    fn cmp_op(self) -> &'static str {
        match self {
            Self::Asc => ">",
            Self::Desc => "<",
        }
    }
}

/// 排序列的存储类型 —— 决定游标值怎么绑 (`Int`→i64 数值比较 / `Text`→字符串比较)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ColType {
    Int,
    Text,
}

/// 一个排序列 (列名 + 类型)。列名是**代码内固定字面量** (非用户输入) → 拼进 SQL 无注入。
#[derive(Clone, Copy, Debug)]
pub struct SortCol {
    pub name: &'static str,
    pub ty: ColType,
}
impl SortCol {
    #[must_use]
    pub const fn int(name: &'static str) -> Self {
        Self { name, ty: ColType::Int }
    }
    #[must_use]
    pub const fn text(name: &'static str) -> Self {
        Self {
            name,
            ty: ColType::Text,
        }
    }
}

/// keyset 排序键 = 前置列 (可并列) + **唯一 tiebreaker (末列, 必填)**, 全列同向。
///
/// ④ **静态断言 (类型钉死)**: [`KeysetSpec::new`] 强制显式给 `tiebreaker` —— **无法构造"无 tiebreaker"
/// 的铸游标查询**, 故"每个铸游标查询排序键唯一/带 tiebreaker"由类型系统在**编译期**保证 (比运行时测更强)。
#[derive(Clone, Debug)]
pub struct KeysetSpec {
    lead: Vec<SortCol>,
    tiebreaker: SortCol,
    dir: SortDir,
}
impl KeysetSpec {
    /// `lead` 前置排序列 (可空、可有并列值); `tiebreaker` **唯一**末列 (拆开所有并列组); `dir` 同向。
    #[must_use]
    pub fn new(lead: Vec<SortCol>, tiebreaker: SortCol, dir: SortDir) -> Self {
        Self { lead, tiebreaker, dir }
    }
    /// 全部排序列 (前置 ++ tiebreaker) —— **末列恒为唯一 tiebreaker**。
    fn cols(&self) -> Vec<SortCol> {
        let mut v = self.lead.clone();
        v.push(self.tiebreaker);
        v
    }
    /// `ORDER BY c1 <dir>, c2 <dir>, …` (含 tiebreaker; 全同向)。
    fn order_by(&self) -> String {
        let kw = self.dir.keyword();
        let parts: Vec<String> = self.cols().iter().map(|c| format!("{} {kw}", c.name)).collect();
        format!("ORDER BY {}", parts.join(", "))
    }
}

/// keyset 续翻比较子句 `(c1,c2,…) <op> (?s,?s+1,…)` + 类型化绑值。
///
/// **低层**、接**任意** `cols`: 守恒反例测故意传"无 tiebreaker"的列表 → 复现丢行 (见测)。生产路只经
/// [`KeysetSpec::cols`] (末列恒 tiebreaker)。`start_param` = 首占位符编号 (接在过滤参数之后, `?N` 密集不撞)。
fn keyset_where(cols: &[SortCol], dir: SortDir, values: &[String], start_param: usize) -> Result<(String, Vec<Value>)> {
    if cols.len() != values.len() {
        bail!(
            "游标排序值个数 {} 与排序键列数 {} 不符 (INVALID_CURSOR)",
            values.len(),
            cols.len()
        );
    }
    let lhs = cols.iter().map(|c| c.name).collect::<Vec<_>>().join(", ");
    let ph = (0..cols.len())
        .map(|i| format!("?{}", start_param + i))
        .collect::<Vec<_>>()
        .join(", ");
    let mut params = Vec::with_capacity(cols.len());
    for (c, v) in cols.iter().zip(values) {
        params.push(match c.ty {
            // Int 列按 i64 绑 → 比较由构造即数值 (不倚赖列亲和度强转; 白盒测锁此绑值)。解析不了 = 游标坏。
            ColType::Int => Value::Integer(
                v.parse::<i64>()
                    .map_err(|_| anyhow!("游标排序值非整数 `{v}` (INVALID_CURSOR)"))?,
            ),
            ColType::Text => Value::Text(v.clone()),
        });
    }
    Ok((format!("({lhs}) {} ({ph})", dir.cmp_op()), params))
}

/// 一页 keyset 分页结果。
pub struct Page<T> {
    pub rows: Vec<T>,
    /// 还有下页给串, 到底 = `None` (信封省略 next_cursor)。
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// keyset 翻一页 (内核 §6)。
///
/// - `select_cols`: 调用方要的列 (`map_row` 读**前** `select_cols.len()` 列)。paginator 在其后
///   **追加排序键列**供 next_cursor 提值 (可与 select 重叠, 无妨)。
/// - `from`: 表名 (或 JOIN 片段), **不含** WHERE/ORDER/LIMIT。**代码内字面量**, 非用户输入。
/// - `filter`: `Some((过滤SQL, 去重参数))` 或 `None`。过滤 SQL **密集编号 `?1..?k`** (可复用同号);
///   `k` = 去重参数个数 (`Vec` 长度)。keyset 参数从 `?k+1` 续、绝不与过滤撞号。
/// - `page_size`: 本页条数 (内部 fetch `+1` 精确探 has_more)。
/// - `cursor`: 上一页 next_cursor (首页 `None`); 解码校验 account/filter/版本 (cursor.rs) 不符 → 报错。
/// - `map_row`: 从前 `select_cols.len()` 列建 `T`。
#[allow(clippy::too_many_arguments)]
pub fn paginate<T>(
    conn: &Connection,
    select_cols: &[&str],
    from: &str,
    filter: Option<(&str, Vec<Value>)>,
    spec: &KeysetSpec,
    page_size: usize,
    cursor: Option<&str>,
    account_sha8: &str,
    filter_hash: &str,
    map_row: impl Fn(&Row) -> rusqlite::Result<T>,
) -> Result<Page<T>> {
    // page_size=0 (`-n 0`) 是退化请求: 返空、到底、无游标 (契约审: 否则 fetch=1 命中 → has_more=true 但
    // truncate(0) 后无末行 → next_cursor=None, "还有下页却没游标" → cursor-walk 死循环重取首页)。
    if page_size == 0 {
        return Ok(Page {
            rows: Vec::new(),
            next_cursor: None,
            has_more: false,
        });
    }
    let sort_cols = spec.cols();
    let k = filter.as_ref().map_or(0, |(_, p)| p.len());

    // 游标 → keyset WHERE 片段 (首页 None)。解码即校验账号/过滤/版本 → 坏则 **CliError{InvalidCursor}**
    // (退出码 2, doc② §二.5; **不**降级成 anyhow → 否则 classify 归 INTERNAL/70, 真跑逮出过)。
    let keyset = match cursor {
        Some(c) => {
            let cur = cursor::decode(c, account_sha8, filter_hash).ok_or_else(|| CliError {
                code: ErrorCode::InvalidCursor,
                hint: "游标失效 (账号/过滤/版本不符或格式坏) —— 去掉 --cursor 从头翻".to_string(),
            })?;
            let kw = keyset_where(&sort_cols, spec.dir, &cur.sort_values, k + 1).map_err(|_| CliError {
                code: ErrorCode::InvalidCursor,
                hint: "游标排序值与排序键不符 (损坏) —— 去掉 --cursor 从头翻".to_string(),
            })?;
            Some(kw)
        }
        None => None,
    };

    // SELECT <caller cols>, <sort cols> FROM <from> [WHERE filter [AND keyset]] ORDER BY … LIMIT n+1。
    let sort_names = sort_cols.iter().map(|c| c.name).collect::<Vec<_>>().join(", ");
    let select_list = format!("{}, {sort_names}", select_cols.join(", "));

    let mut where_parts: Vec<String> = Vec::new();
    if let Some((f, _)) = &filter {
        where_parts.push(format!("({f})"));
    }
    if let Some((frag, _)) = &keyset {
        where_parts.push(frag.clone());
    }
    let where_sql = if where_parts.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_parts.join(" AND "))
    };

    // LIMIT 内联 (fetch 是我算的整数, 非用户文本 → 无注入); 免占位符编号纠缠。
    let fetch = page_size.saturating_add(1);
    let sql = format!(
        "SELECT {select_list} FROM {from}{where_sql} {} LIMIT {fetch}",
        spec.order_by()
    );

    // 绑参: 过滤去重参数 (?1..?k) ++ keyset (?k+1..)。密集编号 → params_from_iter 按位定位绑。
    let mut all: Vec<Value> = Vec::with_capacity(k + sort_cols.len());
    if let Some((_, p)) = filter {
        all.extend(p);
    }
    if let Some((_, p)) = keyset {
        all.extend(p);
    }

    let mut stmt = conn
        .prepare(&sql)
        .with_context(|| format!("准备分页 SQL 失败: {sql}"))?;
    let ncol_lead = select_cols.len();

    // 收 (映射行 + 排序键值字符串); 排序键在追加列 (从 ncol_lead 起), 按类型取回并转字符串 (与 encode 对称)。
    let mut fetched: Vec<(T, Vec<String>)> = Vec::with_capacity(fetch);
    let mut rows = stmt.query(rusqlite::params_from_iter(all.iter()))?;
    while let Some(row) = rows.next()? {
        let mapped = map_row(row)?;
        let mut key_vals = Vec::with_capacity(sort_cols.len());
        for (i, c) in sort_cols.iter().enumerate() {
            let idx = ncol_lead + i;
            let s = match c.ty {
                ColType::Int => row.get::<_, i64>(idx)?.to_string(),
                ColType::Text => row.get::<_, String>(idx)?,
            };
            key_vals.push(s);
        }
        fetched.push((mapped, key_vals));
    }

    // has_more 精确 (fetch 到第 n+1 条即还有); next_cursor 取**末条已发行**的键 (非第 n+1 条)。
    let has_more = fetched.len() > page_size;
    fetched.truncate(page_size);
    let next_cursor = if has_more {
        fetched
            .last()
            .map(|(_, kv)| cursor::encode(account_sha8, filter_hash, kv))
    } else {
        None
    };
    let out_rows = fetched.into_iter().map(|(t, _)| t).collect();
    Ok(Page {
        rows: out_rows,
        next_cursor,
        has_more,
    })
}

/// 过滤指纹 (绑游标; 内核 §6 "filter 指纹")。稳定 sha8 —— 同过滤同串、异过滤异串 → 换过滤的旧游标
/// decode 校验不过 → INVALID_CURSOR。`parts` = 定义本次过滤的所有判据 (命令名 + 各过滤取值)。
#[must_use]
pub fn filter_hash(parts: &[&str]) -> String {
    common::redact::sha8(parts.join("\u{1f}").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 夹具: `t(id 唯一, ts 有并列)`。ts 故意含跨页边界并列组:
    /// ts = [50,50,50, 40,40, 30,30,30, 20, 10] (并列组 50×3 / 40×2 / 30×3), id 1..=10 唯一。
    /// page_size 取 2/3 会把 50×3、30×3 **劈到跨页** → 无 tiebreaker 必丢行 (守恒反例的靶)。
    fn tie_db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute("CREATE TABLE t(id INTEGER, ts INTEGER)", []).unwrap();
        let rows = [
            (1, 50),
            (2, 50),
            (3, 50),
            (4, 40),
            (5, 40),
            (6, 30),
            (7, 30),
            (8, 30),
            (9, 20),
            (10, 10),
        ];
        for (id, ts) in rows {
            c.execute("INSERT INTO t VALUES(?1,?2)", [id, ts]).unwrap();
        }
        c
    }

    /// 独立全量 (ts DESC, id DESC; **无游标子句**) —— 守恒基线, 不与翻页共 keyset 循环 (免同 bug 污染两边)。
    fn full_desc(c: &Connection) -> Vec<i64> {
        c.prepare("SELECT id FROM t ORDER BY ts DESC, id DESC")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn spec_ts_id() -> KeysetSpec {
        KeysetSpec::new(vec![SortCol::int("ts")], SortCol::int("id"), SortDir::Desc)
    }

    /// 翻完所有页 (真 next_cursor 驱动); 返 (拼接 ids 保序, 页数)。断言每页/末页 has_more 自洽。
    fn drain_pages(c: &Connection, page_size: usize) -> (Vec<i64>, usize) {
        let mut ids = Vec::new();
        let mut cur: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = paginate(
                c,
                &["id"],
                "t",
                None,
                &spec_ts_id(),
                page_size,
                cur.as_deref(),
                "acc",
                "filt",
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
            pages += 1;
            ids.extend(page.rows.iter().copied());
            match page.next_cursor {
                Some(nc) => {
                    assert!(page.has_more, "给了 next_cursor 就该 has_more=true");
                    cur = Some(nc);
                }
                None => {
                    assert!(!page.has_more, "末页 has_more 必 false");
                    break;
                }
            }
            assert!(pages < 100, "翻页不收敛 (死循环保护)");
        }
        (ids, pages)
    }

    /// ④ 主断言 —— **守恒**: keyset 翻页 (page_size 劈开并列组) 的并集 == 独立全量, 一行不丢不重, 顺序单调。
    #[test]
    fn tie_fixture_pages_conserve_all_rows() {
        let c = tie_db();
        let full = full_desc(&c);
        assert_eq!(full.len(), 10);
        let (ids, pages) = drain_pages(&c, 2);
        assert!(pages >= 3, "page_size=2 / 10 行 → ≥3 页 (实 {pages})");
        // 守恒: **顺序完全一致** (不 sort 再比 —— 保住 oldest-first 顺序 bug 的证据, ④ 卡明令别先 sort)。
        assert_eq!(ids, full, "翻页并集须 == 独立全量 (顺序一致, 一行不丢不重)");
        // 相邻页无重叠: 去重后仍等长。
        let mut uniq = ids.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), ids.len(), "相邻页不得重叠 (无重复 id)");
    }

    /// 换个 page_size 再验守恒 (page_size=3 劈并列组的位置不同, 别只碰巧对一个)。
    #[test]
    fn conserves_at_page_size_3() {
        let c = tie_db();
        let full = full_desc(&c);
        let (ids, pages) = drain_pages(&c, 3);
        assert!(pages >= 3);
        assert_eq!(ids, full, "page_size=3 并集仍 == 独立全量");
    }

    /// ④ **守恒专属反例 (命脉)** —— 去掉 tiebreaker (keyset 只 `(ts) < ?`) → 跨页并列组丢行 → 报警。
    /// 复现 anchor 688→98: 非唯一键上严格 `<` 把边界并列组整片跳过。
    /// **注 (补审)**: 此反例**手搓循环**演示"去 tiebreaker 就丢行", **不走** `paginate()` (KeysetSpec 类型上
    /// 禁 lead-only, 无法经生产路造无 tiebreaker 键)。生产路的**主守卫**是上面的守恒测 —— 它们直接盖
    /// `paginate()`, 且 mutation(把真 `cols()` 的 tiebreaker 去掉)确认会 FAIL。此反例是**平行佐证**, 非主守卫。
    #[test]
    fn no_tiebreaker_loses_rows_negative_control() {
        let c = tie_db();
        let full = full_desc(&c);
        let ts_only = [SortCol::int("ts")]; // **故意无 id tiebreaker** (绕过 KeysetSpec 的类型守卫走低层)。
        let mut ids = Vec::new();
        let mut last_ts: Option<i64> = None;
        for _ in 0..100 {
            let (where_sql, params) = match last_ts {
                None => (String::new(), vec![]),
                Some(t) => {
                    let (frag, p) = keyset_where(&ts_only, SortDir::Desc, &[t.to_string()], 1).unwrap();
                    (format!(" WHERE {frag}"), p)
                }
            };
            let sql = format!("SELECT id, ts FROM t{where_sql} ORDER BY ts DESC, id DESC LIMIT 2");
            let mut st = c.prepare(&sql).unwrap();
            let page: Vec<(i64, i64)> = st
                .query_map(rusqlite::params_from_iter(params.iter()), |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            if page.is_empty() {
                break;
            }
            for (id, _) in &page {
                ids.push(*id);
            }
            last_ts = Some(page.last().unwrap().1);
            if page.len() < 2 {
                break;
            }
        }
        // 去 tiebreaker → `ts < last_ts` 把边界并列组整片跳过 → union **少行** (正是 688→98 塌陷)。
        // 精确钉丢了哪些 (防 §9 假响: 若查询报错到空, `0<10` 也会过 —— 那不是"打中并列丢行", 是全崩)。
        let missing: Vec<i64> = full.iter().copied().filter(|id| !ids.contains(id)).collect();
        assert!(!ids.is_empty(), "反例不该整崩到空 (那证明的是别的故障, 非并列丢行)");
        assert!(
            ids.len() < full.len(),
            "反例必须丢行 (守恒测才有牙): union={} < full={}",
            ids.len(),
            full.len()
        );
        // 丢的正是跨页边界的并列行: id1(ts=50 组尾, 被 page1 末 ts=50 的 `<50` 跳过) + id6(ts=30 组尾)。
        assert_eq!(
            missing,
            vec![1, 6],
            "丢的须是边界并列行 {{1,6}} (瞄准 688→98, 非泛泛少行)"
        );
    }

    /// **类型正确性锁 (防 688 的另一面)**: Int 列游标值按 `Value::Integer` 绑, **不按 `Value::Text`** ——
    /// 否则 `"900" > "1000"` 字典序丢行。此测直接盯绑值类型 (回归成字符串绑 → 立即 FAIL)。
    #[test]
    fn int_cursor_value_binds_as_integer_not_text() {
        let (frag, params) = keyset_where(
            &[SortCol::int("ts"), SortCol::int("id")],
            SortDir::Desc,
            &["900".into(), "5".into()],
            1,
        )
        .unwrap();
        assert_eq!(frag, "(ts, id) < (?1, ?2)");
        assert_eq!(
            params,
            vec![Value::Integer(900), Value::Integer(5)],
            "Int 列须按 i64 绑 (数值比较), 不得按字符串"
        );
        // Text 列对照: 按字符串绑。
        let (_, tp) = keyset_where(&[SortCol::text("wxid")], SortDir::Asc, &["wxid_x".into()], 1).unwrap();
        assert_eq!(tp, vec![Value::Text("wxid_x".into())]);
        // ASC → `>`; DESC → `<`。
        let (asc, _) = keyset_where(&[SortCol::text("u")], SortDir::Asc, &["a".into()], 3).unwrap();
        assert_eq!(asc, "(u) > (?3)", "ASC 续翻 = 大于末行; 占位符从 start_param 起");
    }

    /// 数值列跨数量级 (ts 含 900 与 1000) 端到端守恒。**注 (补审)**: 此测**不**守 int-vs-text 绑值 ——
    /// ts 是 INTEGER 亲和度列, SQLite 会把误绑的字符串强转回数值 → 就算绑错也不丢行。绑值由白盒
    /// `int_cursor_value_binds_as_integer_not_text` 守 (mutation 验过)。此测守的是"数值数据翻页守恒"本身。
    #[test]
    fn numeric_magnitude_boundary_conserves() {
        let c = Connection::open_in_memory().unwrap();
        c.execute("CREATE TABLE t(id INTEGER, ts INTEGER)", []).unwrap();
        for (id, ts) in [(1, 1000), (2, 1000), (3, 900), (4, 900), (5, 100), (6, 90)] {
            c.execute("INSERT INTO t VALUES(?1,?2)", [id, ts]).unwrap();
        }
        let full: Vec<i64> = c
            .prepare("SELECT id FROM t ORDER BY ts DESC, id DESC")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut ids: Vec<i64> = Vec::new();
        let mut cur: Option<String> = None;
        for _ in 0..100 {
            let p = paginate(
                &c,
                &["id"],
                "t",
                None,
                &spec_ts_id(),
                1,
                cur.as_deref(),
                "acc",
                "filt",
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
            ids.extend(&p.rows);
            match p.next_cursor {
                Some(nc) => cur = Some(nc),
                None => break,
            }
        }
        assert_eq!(ids, full, "数值边界 (900 vs 1000) 按 i64 比较 → 守恒 (字符串绑会错序)");
    }

    /// 带过滤: 过滤参数 `?1` + keyset `?2..` **不撞号**, 并集 == 独立过滤全量 (盯参数编号缝)。
    #[test]
    fn paginate_with_filter_numbers_params_and_conserves() {
        let c = tie_db();
        let full: Vec<i64> = c
            .prepare("SELECT id FROM t WHERE ts>=30 ORDER BY ts DESC, id DESC")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut ids: Vec<i64> = Vec::new();
        let mut cur: Option<String> = None;
        for _ in 0..100 {
            let f = Some(("ts >= ?1", vec![Value::Integer(30)]));
            let p = paginate(
                &c,
                &["id"],
                "t",
                f,
                &spec_ts_id(),
                3,
                cur.as_deref(),
                "acc",
                "filt",
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
            ids.extend(&p.rows);
            match p.next_cursor {
                Some(nc) => cur = Some(nc),
                None => break,
            }
        }
        assert_eq!(
            ids, full,
            "带过滤 keyset 并集 == 独立过滤全量 (?1 过滤 + ?2.. keyset 不撞号)"
        );
        assert_eq!(full.len(), 8, "ts>=30 应 8 行 (排除 ts=20,10)");
    }

    /// page_size=0 (`-n 0`) → 空、到底、无游标 (契约审: 防 has_more=true 却无 next_cursor 的 cursor-walk 死循环)。
    #[test]
    fn page_size_zero_returns_empty_done_no_cursor() {
        let c = tie_db();
        let p = paginate(&c, &["id"], "t", None, &spec_ts_id(), 0, None, "acc", "filt", |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        assert!(p.rows.is_empty(), "0 行请求 → 空");
        assert!(!p.has_more, "不能 has_more=true (否则消费者被告知还有下页却无游标可续)");
        assert!(p.next_cursor.is_none(), "无游标");
    }

    /// 一页装下 → 无 next_cursor、has_more=false。
    #[test]
    fn single_page_no_cursor_when_all_fit() {
        let c = tie_db();
        let p = paginate(&c, &["id"], "t", None, &spec_ts_id(), 50, None, "acc", "filt", |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        assert_eq!(p.rows.len(), 10);
        assert!(!p.has_more);
        assert!(p.next_cursor.is_none(), "一页装下 → 无 next_cursor");
    }

    /// 游标绑 account+filter: 换 account 或 filter_hash 的游标 → decode 不过 → paginate 报错 (INVALID_CURSOR)。
    #[test]
    fn tampered_cursor_errors_invalid() {
        let c = tie_db();
        let p1 = paginate(&c, &["id"], "t", None, &spec_ts_id(), 2, None, "acc", "filt", |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        let nc = p1.next_cursor.expect("有下页应给游标");
        assert!(
            paginate(
                &c,
                &["id"],
                "t",
                None,
                &spec_ts_id(),
                2,
                Some(&nc),
                "OTHER",
                "filt",
                |r| r.get::<_, i64>(0)
            )
            .is_err(),
            "换 account 的游标须被拒 (INVALID_CURSOR)"
        );
        assert!(
            paginate(
                &c,
                &["id"],
                "t",
                None,
                &spec_ts_id(),
                2,
                Some(&nc),
                "acc",
                "OTHERFILT",
                |r| r.get::<_, i64>(0)
            )
            .is_err(),
            "换 filter 的游标须被拒 (INVALID_CURSOR)"
        );
        // 同 account+filter → 正常续翻。
        assert!(paginate(
            &c,
            &["id"],
            "t",
            None,
            &spec_ts_id(),
            2,
            Some(&nc),
            "acc",
            "filt",
            |r| r.get::<_, i64>(0)
        )
        .is_ok());
    }

    /// 静态断言 (结构): 排序键末列恒为 tiebreaker; order_by 全同向。
    #[test]
    fn spec_always_ends_with_tiebreaker() {
        let s = KeysetSpec::new(vec![SortCol::int("ts")], SortCol::text("wxid"), SortDir::Desc);
        assert_eq!(
            s.cols().last().unwrap().name,
            "wxid",
            "排序键末列恒为 tiebreaker (new() 强制传)"
        );
        assert_eq!(s.order_by(), "ORDER BY ts DESC, wxid DESC");
        let single = KeysetSpec::new(vec![], SortCol::text("username"), SortDir::Asc);
        assert_eq!(single.cols().len(), 1, "无 lead 时 tiebreaker 即全键");
        assert_eq!(single.order_by(), "ORDER BY username ASC");
    }

    /// filter_hash 稳定且能区分 (同过滤同串 / 异过滤异串)。
    #[test]
    fn filter_hash_stable_and_discriminates() {
        assert_eq!(
            filter_hash(&["contacts", "q=foo"]),
            filter_hash(&["contacts", "q=foo"]),
            "同过滤同指纹"
        );
        assert_ne!(
            filter_hash(&["contacts", "q=foo"]),
            filter_hash(&["contacts", "q=bar"]),
            "异过滤异指纹"
        );
        assert_eq!(filter_hash(&["contacts", "q=foo"]).len(), 8, "sha8 = 8 hex");
    }

    /// 排序值个数与排序键列数不符 → 报错 (坏游标)。
    #[test]
    fn keyset_where_arity_mismatch_errors() {
        assert!(keyset_where(
            &[SortCol::int("ts"), SortCol::int("id")],
            SortDir::Desc,
            &["1".into()],
            1
        )
        .is_err());
    }
}
