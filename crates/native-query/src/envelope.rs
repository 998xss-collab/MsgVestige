//! `{data, meta}` 顶层信封 —— 三皮共享契约 (内核 §2) 的 CLI 落地 + golden 锁形状。
//!
//! meta 字段集**以内核 §2 为准**:
//! `has_more`(恒给) · `total_count`(可选) · `limit`(可选) · `offset`(offset 分页) ·
//! `next_cursor`(游标分页) · `account`(sha8) · `source`(hot|cold|live-index) · `freshness`。
//!
//! P0 各件填各自字段:**① 立结构 + emit + golden**, 只诚实填 `total_count` + `has_more`
//! (非分页 = false); `source`/`freshness` = ②;`account` = ③;`limit`/`offset`/`next_cursor`
//! = ④。可选字段 `None` 时不序列化 (契约: 大集省略 total_count / 非分页不出 offset 等)。

// 信封的 match 兜底分支是**故意**的: 将来加了新变体也要走到兜底, 而不是漏掉。
#![allow(clippy::match_wildcard_for_single_variants)]

use anyhow::{Context, Result};
use serde::Serialize;

/// 本次查询走哪个后端 (内核 §14 双模式)。**② 双模式打标填入**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")] // Hot→"hot" / Cold→"cold" / LiveIndex→"live-index"
pub enum Source {
    Hot,
    Cold,
    /// live-index 后端 (§14.2) —— 查询命中独立瘦索引 → `source=live-index`。
    /// R18 件2 落地: `search --thin-db <瘦库>` (无 --l1-db) 直搜 thin FTS 即构造本变体 (见 msgvestige
    /// `cmd_search_thin_standalone`)。full 档仍走 `cold` (读 L1 投影)。
    #[allow(dead_code)] // 仅 msgvestige 下游构造; 本 crate 内无构造点故留 allow。
    LiveIndex,
}

/// `meta.freshness` 新鲜度 (② R6, 内核 §14) —— 消费者判"这数据多新"。**untagged**: 序列化就是内层对象,
/// 无 variant 包裹 (契约值同内核 §14 / openapi)。只序列化不反序列化 (Meta 只 derive Serialize)。
/// - 热查(直读源库, 恒最新)→ `{"live":true}`。
/// - 冷查(读 L1 投影)→ `{"ingested_at":<unix秒>[,"stale":bool]}`。`ingested_at` = 该账号 L1 最后 ingest 水位
///   (etl_state MAX(last_update)/1000; 粗粒度, 非逐源 —— 见 `freshness.rs`)。
///
/// **R9 复审R3#4 —— `indexed_through` 字段已撤**: 原设计 (§14.5) 想出"各源水位 MIN"作全库鲜度 floor, 但现 infra
/// 下**无廉价且诚实的实现**: etl_state 只由**消息管道**逐子源写、且 `last_update` 是**墙钟 ingest 时刻**非数据时刻
/// (contact/sns/transfer 等小库管道无状态全扫、根本不写 etl_state) → `MIN(last_update)` 既漏非消息源、又被休眠分片
/// 拖成假旧, 是**谎报**。真数据时刻要 `MAX(message.create_time)`, 无专用索引 787ms/77万行 → per-query 不可接受。
/// 故 per-query 冷查**只出 `ingested_at`**; 数据时刻鲜度改由 `/live-index/status` 专用端点 (稀有调用, 可承受全表
/// 扫) 报 `indexed_through=MAX(create_time)`。§14.5 "各源 MIN floor" 待日后逐源数据时刻水位 (心跳/专用索引) 落地。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Freshness {
    /// 热查: 直读源库, `live=true`。
    Hot {
        /// 恒 true (热查即实时)。
        live: bool,
    },
    /// 冷查: L1 投影。
    Cold {
        /// L1 最后 ingest 时间 (unix 秒); 读不到(空库/无水位)→ `None` 省略。
        #[serde(skip_serializing_if = "Option::is_none")]
        ingested_at: Option<i64>,
        /// 源库是否比 L1 新。**非 full → `None` 省略**(无常驻同步机制, 无法诚实判是否落后源 —— 复审#2: 宁缺不谎)。
        /// **R9 复审R3#4 + codex P1 —— full 语境据真实线程存活填, 但只报坏消息不报好消息**:
        /// - full + 后台 watch 线程**已退出/崩溃** → `stale:true`(配了 full 却没维护者了, L1 冻结源库仍长 → 安全告警)。
        /// - full + 线程**存活** → `stale` **仍省略 `None`**(**存活 ≠ 同步健康**: watch 吞每轮 ingest 错误+永久重试,
        ///   持续失败时线程活着但 L1 不推进 → 报 `false` 会谎报新鲜)。线程死由 R3#3 `AtomicBool`+`AliveGuard` 确认。
        #[serde(skip_serializing_if = "Option::is_none")]
        stale: Option<bool>,
        /// R22 懒式落库 (ADR-508 D24): **这个会话**上次被补到什么时候 (unix 秒)。
        ///
        /// 比账号级的 `ingested_at` 精确得多 —— 后者是"整库最后一次 ingest 的墙钟时刻", 而懒式落库
        /// 是按会话推进的: 你查的这个会话可能刚补过, 别的会话还停在几个月前。
        ///
        /// 只有**按会话查**且该会话被补过时才给; 其余情形省略 (同本枚举一贯的"宁缺不谎")。
        #[serde(skip_serializing_if = "Option::is_none")]
        chat_refreshed_at: Option<i64>,
        /// R22: 这次**没能**把该会话补到最新的原因; 补成了(或压根没要求补)就省略。
        ///
        /// 封闭取值:
        /// - `"held"` —— 别的写者正在维护该会话。
        /// - `"not_covered"` —— 采集白名单排除 / 公众号会话。
        /// - `"source_unavailable"` —— **够不着**微信库: 没数据目录、没缓存 key、L1 是只读文件。
        ///   **良性稳态**(把冷库拷到别的机器上自足查就长这样), 不需要处理。
        /// - `"source_degraded"` —— 够得着, 但**这一轮没补全**: 已补进去的仍然生效, 剩下那部分没看成。
        ///   三种成因(看返回里的 `why`, 处置建议也在那): 有分片读不开(损坏 / 微信正在写 / 也可能是
        ///   key、session 库、目录这类账号级问题)· 采集范围中途变了 · 有子源卡住没采完。
        ///   **跟上一格必须分开**: 那一格良性、不用管, 这一格**需要人看一眼**;
        ///   混成同一个 token 的话监控只会把它当良性的忽略掉。
        ///
        /// **为什么必须进结构化输出**: 只写日志的话, 机器可读的回答会变成"这个会话有 0 条消息"
        /// (D24 审实测: 7077 条的群被租约挡住时就是这个结果), 调用方无从知道自己拿到的是半截。
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_skipped: Option<String>,
    },
}

impl Freshness {
    /// 给冷查结果补上"这次没补成"的原因(`None` = 补成了 / 没要求补, 不改)。
    #[must_use]
    pub fn with_refresh_skipped(self, why: Option<&str>) -> Self {
        match (self, why) {
            (
                Self::Cold {
                    ingested_at,
                    stale,
                    chat_refreshed_at,
                    ..
                },
                w,
            ) => Self::Cold {
                ingested_at,
                stale,
                chat_refreshed_at,
                refresh_skipped: w.map(std::string::ToString::to_string),
            },
            (other, _) => other,
        }
    }

    /// 给冷查结果补上"这个会话上次补到什么时候"。
    #[must_use]
    pub fn with_chat_refreshed_at(self, at: Option<i64>) -> Self {
        match self {
            Self::Cold {
                ingested_at,
                stale,
                refresh_skipped,
                ..
            } => Self::Cold {
                ingested_at,
                stale,
                chat_refreshed_at: at,
                refresh_skipped,
            },
            other => other,
        }
    }
}

/// `{data, meta}` 的 `meta` —— 字段集以内核 §2 为准。可选字段 `None` 时不序列化。
///
/// 顶层 schema 恒定 (`data`+`meta`), 消费者只依赖外层;字段集三皮不得各列一份。
#[derive(Debug, Clone, Default, Serialize)]
pub struct Meta {
    /// **恒给**: 还有下一页 = true, 到底 = false。④ 分页填;非分页 = false。
    pub has_more: bool,
    /// 仅"能廉价精确"时给 (小集 / offset 分页);大过滤集省略 (①/④)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,
    /// 本页请求条数 (④ 分页填)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// 仅 offset 分页出 (④)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// 游标分页: 还有下页给串, 到底为 null → 用 `None` 省略 (④)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// 当前账号 (sha8);多账号维度 (③ 填)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// 走哪个后端 (② 打标填)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// 新鲜度 (② R6 填;cold = `{ingested_at}` / hot = `{live:true}`;stale 待 R9)。typed [`Freshness`]。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<Freshness>,
    /// **命令特有汇总**的**唯一容身处** (可选)——如 stats 的 `total_messages`、pii-scan 的 `phone_total`。
    /// 这些是每命令不同的域字段, **不得**直接铺在 meta 顶层 (否则破 §2 "meta 字段集固定/三皮不得各列一份");
    /// 统一收进这个**定义好的**槽位, 标准字段 (has_more/source/…) 才对每个命令一致、可预期 (HOLE-3 收口)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<serde_json::Value>,
    /// **R9 复审R3#5 (+ R4 扩全)**: 本页因**读取失败被丢弃的行数** (>0 才出;0 省略)。行级 `ok_or_warn` 会 warn+丢坏行
    /// 保韧性, 但**只 log 不进响应** → 消费者 (前端/AI) 把不完整结果当完整。此字段是**机器可读的"结果不完整"信号**,
    /// 且与 `has_more`(分页语义) **正交解耦**: `has_more`=还有下一页, `dropped_rows`=本页内缺了几行 —— 消费者能区分
    /// "翻页取更多"与"这批数据有洞"。**两条来源** (R4 扩全后覆盖所有查询形):
    /// - `offset_page`: 内部算术 `min(limit,total-offset)-shown` (有 limit/offset/total 精确算期望本页行数)。
    /// - `page`/`cursor_page`/`cold_page` (accounts/names/new/stats/forward 等无独立 COUNT 的): 经 [`Meta::with_dropped`]
    ///   塞 [`crate::engine::collect_ok`] 的显式计数 (那些点 total=shown 或 total 非行数, 算术测不出)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_rows: Option<u64>,
}

impl Meta {
    /// 一页列表结果的 meta:`total_count` = 已知全量, **`has_more` = 本页行数 < 全量**
    /// (§2 恒精确 —— `shown < total` 即还有下一页;`-n`/`--limit` 截断时才为 true)。
    /// ① 用;②③④ 在此基础上填 `source`/`account`/游标。
    ///
    /// ⚠ 前提: `total` 须是**真实全量**。SQL-LIMIT 命令若传本页行数(=页大小)当 `total`,
    /// 则 `total_count` 少报、`has_more` 恒 false —— 那是 HOLE-2(留 ④ 分页按命令订正:
    /// 取真 count 或省略 total_count),非本构造器的锅。
    #[must_use]
    pub fn page(shown: usize, total: usize) -> Self {
        Self {
            has_more: shown < total,
            total_count: Some(total as u64),
            ..Self::default()
        }
    }

    /// ④ **offset 分页** (统一 offset, 全数据可达): `offset`=已跳过条数, `shown`=本页返回, `total`=过滤后
    /// 真实全量, `limit`=本页请求量。`has_more = offset+shown < total` (offset 感知, 非 `page()` 的 `shown<total`
    /// 那种只对首页对的); `total_count`+`limit` 让客户端算下一页 (`offset += limit` 直到 `has_more=false`)。
    ///
    /// **R9 复审R3#5 `dropped_rows`**: 本构造器的契约已是 `total`=被分页集的真实全量 → 数据查 `LIMIT/OFFSET` 在**丢行前**
    /// 应恰返 `min(limit, total-offset)` 行; `shown`(=`data.len()`, 丢行**后**) 少于此即**本页丢了行**。`dropped =
    /// min(limit,total-offset) - shown` (>0 才记)。与 `has_more` 正交: `has_more` 认领"翻页" gap, `dropped_rows` 认领
    /// "本页缺行" gap。**可靠性同 `has_more`**: 都建立在同一 `total` 契约上, 契约破则 `has_more/total_count` 本就已错 (非本项引入)。
    #[must_use]
    pub fn offset_page(offset: usize, shown: usize, total: usize, limit: usize) -> Self {
        let expect_this_page = limit.min(total.saturating_sub(offset)); // 丢行前本页应返行数 (契约)。
        let dropped = expect_this_page.saturating_sub(shown); // shown 少于期望 = 本页读取丢弃的行数。
        Self {
            // codex-R7 P2#4: has_more 用 **limit**(本页窗口大小)非 shown —— 有坏行被 drop 时 shown<期望, 用 shown 会
            // 误判"还有下页"(offset+shown<total 虚真, 但下页实际空)。offset 分页 has_more 恒 = 窗口 [offset,offset+limit)
            // 未达 total (与 drop 无关); 无 drop 时 shown==min(limit,total-offset) 两式同值, 有 drop 才纠偏。
            // codex-R8 P2: `limit>0` 才可能有下页 —— limit=0 时 offset+0<total 会假 true, 令客户端 offset+=0 死循环。
            has_more: limit > 0 && offset.saturating_add(limit) < total,
            total_count: Some(total as u64),
            limit: Some(limit as u64),
            offset: Some(offset as u64), // 审查 Group A: 原漏写 → meta.offset 恒缺 (契约要求 offset 分页出)。
            dropped_rows: (dropped > 0).then_some(dropped as u64), // R3#5: 机器可读"结果不完整"信号 (0 省略)。
            ..Self::default()
        }
    }

    /// 链式设 `source` (② 打标)。**设在与后端同处的 emit 点**(热=SourceQuery / 冷=open_readonly L1),
    /// 绑实际码路而非游离常量:改了后端却没改这里 → 标签跟着错、易被真跑逮。
    #[must_use]
    pub fn with_source(mut self, source: Source) -> Self {
        self.source = Some(source);
        self
    }

    /// 链式挂**命令特有汇总**到 [`Meta::summary`](该字段) 槽位 (HOLE-3: 域字段的唯一容身处, 别铺 meta 顶层)。
    #[must_use]
    pub fn with_summary(mut self, summary: serde_json::Value) -> Self {
        self.summary = Some(summary);
        self
    }

    /// R4 复审R3#5 扩展: 链式设 `dropped_rows`(本次读取失败被丢弃的行数, `>0` 才出)。给**非 offset 分页**查询
    /// (`page`/`cursor_page`/`cold_page` —— total=shown 无独立 COUNT, `offset_page` 的算术测不出) 塞显式计数
    /// (来自 [`crate::engine::collect_ok`])。`0` → 不设 (skip_serializing 省略), 与 `offset_page` 内算的 dropped 同字段同义。
    #[must_use]
    pub fn with_dropped(mut self, dropped: u64) -> Self {
        if dropped > 0 {
            self.dropped_rows = Some(dropped);
        }
        self
    }

    /// 链式设 `freshness` (② R6): 热=`Freshness::Hot{live:true}` / 冷=`Freshness::Cold{ingested_at}` (stale 待 R9)。
    /// 设在 emit 点(与 `source` 同处): 热查在 hot.rs, 冷查在皮层 choke(有 L1 conn 读 etl_state 水位)。
    #[must_use]
    pub fn with_freshness(mut self, freshness: Freshness) -> Self {
        self.freshness = Some(freshness);
        self
    }

    /// 热查一页 meta:只有 `has_more`,**省略 `total_count`**(§14.1 热查恒省略 —— 源库无廉价
    /// 精确计数,不发近似值)。② 用于 SourceQuery 命令 (sessions/messages);`has_more` 由命令自算
    /// (sessions = 本页 < 全量;messages = 满页启发 `shown == limit`)。`source` 由 `with_source(Hot)` 补。
    #[must_use]
    pub fn hot(has_more: bool) -> Self {
        Self {
            has_more,
            total_count: None,
            ..Self::default()
        }
    }

    /// **游标分页**一页 meta(④, 内核 §6):`has_more` 精确 + `next_cursor`(到底 = `None` → 省略)
    /// + `limit`(本页请求条数)。**省略 `total_count`**(§6:游标分页非 offset, 不带总数 —— 大集
    /// `COUNT(*)` 要全扫;消费者靠 `has_more`/`next_cursor` 续翻, 不做"第 X/Y 页")。`source` 由
    /// `with_source(Cold)` 补。next_cursor 的绑定/失效见 [`crate::cursor`] + [`crate::paginate`]。
    #[must_use]
    pub fn cursor_page(has_more: bool, next_cursor: Option<String>, limit: u64) -> Self {
        Self {
            has_more,
            next_cursor,
            limit: Some(limit),
            total_count: None,
            ..Self::default()
        }
    }

    /// **冷查·无廉价精确全量**一页 meta(修 **HOLE-2**):`has_more` 由调用方**精确探得**
    /// (fetch `limit+1` 看有没有多的 / raw exec 用已知的 `truncated` 标志),但源表**无廉价精确 COUNT**
    /// (top-N by time · `GROUP BY` 排行 · 原生 SQL 逃生口)→ **省略 `total_count`**(§6 大过滤集省略,
    /// 不发近似值、**更不拿页大小充当总数**)。区别于 [`Meta::page`](该构造器要真实全量、给 total_count)。
    /// `source` 由 `with_source(Cold)` 补。
    #[must_use]
    pub fn cold_page(has_more: bool) -> Self {
        Self {
            has_more,
            total_count: None,
            ..Self::default()
        }
    }
}

/// `{data, meta}` 顶层信封。
#[derive(Debug, Serialize)]
pub struct Envelope<'a> {
    pub data: &'a [serde_json::Value],
    pub meta: Meta,
}

/// 内核查询结果 (查询内核抽取 §3) —— `run_query` / (③ 后)手写 `query_*` 的返回;呈现交皮层。
///
/// `data` = **预组好的 json 行** (键值对象; 三皮通吃 —— CLI 打 table/json、MCP/HTTP 转各自响应);
/// `meta` = **完全组装好的**信封 meta (含 `has_more`/`total_count`/`summary`, 皮层不重推)。
/// 与 [`Envelope`] 的区别: `Envelope` 借 `data`(`&[..]`, 序列化用瞬时视图), `QueryResult` **拥有** `data`
/// (查询产出所有权, 皮层再借出去 emit)。
#[derive(Debug)]
pub struct QueryResult {
    pub data: Vec<serde_json::Value>,
    pub meta: Meta,
}

/// 序列化并打印 `{data, meta}` 到 stdout (pretty)。**替 `print_query_json`**。
pub fn emit_envelope(data: &[serde_json::Value], meta: Meta) -> Result<()> {
    let env = Envelope { data, meta };
    println!(
        "{}",
        serde_json::to_string_pretty(&env).context("序列化信封 JSON 失败")?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({ "id": "wxid_a", "name": "甲" }),
            serde_json::json!({ "id": "wxid_b", "name": "乙" }),
        ]
    }

    /// golden(形状锁): 顶层 = `{data, meta}`, `data` 是数组, ① 阶段 `meta` 键集恰
    /// `{has_more, total_count}`。**任何字段漂移** (②③④ 有意加字段 / 误加误删) 都改变键集 → FAIL,
    /// 逼有意更新 (对齐 v2 验收单:golden 降格锁"顶层键集 + data 是数组", 不做逐字节脆快照)。
    #[test]
    fn envelope_shape_locked() {
        let data = sample();
        // 走命令实际出口形状: 冷查 = page + source=cold (②)。
        let v = serde_json::to_value(Envelope {
            data: &data,
            meta: Meta::page(2, 2).with_source(Source::Cold),
        })
        .unwrap();

        // 顶层恰 {data, meta}
        let top: std::collections::BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            top,
            ["data", "meta"].into_iter().collect(),
            "顶层键集须恰 {{data, meta}}"
        );

        // data 是数组
        assert!(v["data"].is_array(), "data 须是数组");

        // ②后 meta 键集恰 {has_more, total_count, source}(account/分页由 ③④ 再加时更新此断言)
        let meta: std::collections::BTreeSet<&str> =
            v["meta"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            meta,
            ["has_more", "source", "total_count"].into_iter().collect(),
            "meta 键集漂移 (③④ 加 account/分页时有意更新此断言)"
        );
    }

    /// total_count(①): 非分页 = 全量, 须存在且 == data 行数;`has_more` = false;可选字段不出。
    /// (count>limit 的真属性测在 ④ 分页落地后补 —— ① 无分页, 故 == data.len() 是构造诚实值。)
    #[test]
    fn total_count_full_result() {
        let data = sample();
        let meta = Meta::page(data.len(), data.len());
        assert_eq!(meta.total_count, Some(2));
        assert!(!meta.has_more);

        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["total_count"], serde_json::json!(2));
        assert_eq!(v["has_more"], serde_json::json!(false));
        for omitted in ["limit", "offset", "next_cursor", "account", "source", "freshness"] {
            assert!(v.get(omitted).is_none(), "① 阶段 meta 不应出 `{omitted}`");
        }
    }

    /// has_more 恒精确 (§2, 修 HOLE-1): 本页行数 < 全量 → true (截断);== 全量 → false (到底)。
    #[test]
    fn has_more_reflects_truncation() {
        assert!(Meta::page(2, 3).has_more, "本页 2 < 全量 3 → 还有下一页");
        assert!(!Meta::page(3, 3).has_more, "本页 == 全量 → 到底");
        assert!(!Meta::page(0, 0).has_more, "空结果 → 到底");
        assert_eq!(Meta::page(2, 3).total_count, Some(3), "total_count = 真实全量");
    }

    /// R9 复审R3#5: `offset_page` 算 `dropped_rows` (本页缺行) + 与 `has_more` 正交解耦。
    #[test]
    fn offset_page_dropped_rows_orthogonal_to_has_more() {
        // 满页无丢: offset=0 limit=10 total=25 shown=10 → 期望 min(10,25)=10, 丢=0 省略; has_more (0+10<25) true。
        let m = Meta::offset_page(0, 10, 25, 10);
        assert_eq!(m.dropped_rows, None, "满页无丢 → dropped_rows 省略");
        assert!(m.has_more, "还有下一页");
        // 满页丢 2: shown=8 但期望 10 → dropped=2; has_more 仍 true (0+8<25) —— 两信号各表其义, 不冲突。
        let m = Meta::offset_page(0, 8, 25, 10);
        assert_eq!(m.dropped_rows, Some(2), "本页期望 10 实得 8 → 丢 2 行");
        assert!(m.has_more, "翻页 gap 与丢行 gap 正交: has_more 仍 true");
        // 末页无丢: offset=20 limit=10 total=25 → 期望 min(10,5)=5, shown=5 丢=0; has_more (20+5<25) false 到底。
        let m = Meta::offset_page(20, 5, 25, 10);
        assert_eq!(m.dropped_rows, None, "末页恰 5 行无丢");
        assert!(!m.has_more, "到底");
        // 末页丢 1: 期望 5 实得 4 → dropped=1; has_more 用 limit → 20+10<25 false (codex-R7 P2#4: 不再被丢行"骗"成还有页;
        // 下页 offset=30>total 实际空)。dropped 与 has_more 各表其义: dropped=本页缺行, has_more=窗口未达 total。
        let m = Meta::offset_page(20, 4, 25, 10);
        assert_eq!(m.dropped_rows, Some(1), "末页期望 5 实得 4 → 丢 1");
        assert!(
            !m.has_more,
            "codex-R7 P2#4: 末页有丢行也不虚报 has_more (窗口 20+10 已越 total 25)"
        );
        // 序列化: >0 出, 0 省略。
        let v = serde_json::to_value(Meta::offset_page(0, 8, 25, 10)).unwrap();
        assert_eq!(v["dropped_rows"], serde_json::json!(2));
        assert!(serde_json::to_value(Meta::offset_page(0, 10, 25, 10))
            .unwrap()
            .get("dropped_rows")
            .is_none());
        // R4 复审R3#5: with_dropped (非 offset 分页 page/cursor/cold_page 显式塞 collect_ok 计数) —— >0 设, 0 省略。
        assert_eq!(
            Meta::page(3, 3).with_dropped(2).dropped_rows,
            Some(2),
            "with_dropped(2) 设"
        );
        assert_eq!(
            Meta::page(3, 3).with_dropped(0).dropped_rows,
            None,
            "with_dropped(0) 不设"
        );
        assert_eq!(
            serde_json::to_value(Meta::cold_page(false).with_dropped(1)).unwrap()["dropped_rows"],
            serde_json::json!(1),
            "cold_page + with_dropped 序列化出 dropped_rows"
        );
    }

    /// R6: `Freshness` untagged 序列化 —— 热 `{live:true}` / 冷 `{ingested_at,stale}`; None 字段省略。
    #[test]
    fn freshness_serializes_untagged() {
        assert_eq!(
            serde_json::to_value(Freshness::Hot { live: true }).unwrap(),
            serde_json::json!({ "live": true })
        );
        // full + 线程死 → stale:true (真告警: 索引垮了 L1 变旧)。
        assert_eq!(
            serde_json::to_value(Freshness::Cold {
                ingested_at: Some(1_700_000_000),
                stale: Some(true),
                chat_refreshed_at: None,
                refresh_skipped: None
            })
            .unwrap(),
            serde_json::json!({ "ingested_at": 1_700_000_000, "stale": true })
        );
        // 非 full (stale 判不出) → stale 省略, 只留 ingested_at。
        assert_eq!(
            serde_json::to_value(Freshness::Cold {
                ingested_at: Some(5),
                stale: None,
                chat_refreshed_at: None,
                refresh_skipped: None
            })
            .unwrap(),
            serde_json::json!({ "ingested_at": 5 }),
            "stale None 省略, 不谎报"
        );
        // 序列化机制: stale:Some(false) 必出 `false` (不被 skip_serializing_if=None 误省) —— 校 bool false≠None。
        // (语义上 cold_freshness_full 现只产 None|Some(true), codex P1 后不再产 Some(false); 此处纯验 untagged 编码。)
        assert_eq!(
            serde_json::to_value(Freshness::Cold {
                ingested_at: Some(100),
                stale: Some(false),
                chat_refreshed_at: None,
                refresh_skipped: None
            })
            .unwrap(),
            serde_json::json!({ "ingested_at": 100, "stale": false }),
            "Some(false) 序列化出 false 不省略"
        );
        // meta.with_freshness → meta.freshness 出。
        let m = Meta::hot(false)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true });
        assert_eq!(
            serde_json::to_value(&m).unwrap()["freshness"],
            serde_json::json!({ "live": true })
        );
    }

    /// ② source 打标: `with_source` 把后端标进 meta (hot=SourceQuery / cold=open_readonly L1);不设则不出。
    #[test]
    fn meta_source_labeled() {
        let cold = serde_json::to_value(Meta::page(1, 1).with_source(Source::Cold)).unwrap();
        assert_eq!(cold["source"], serde_json::json!("cold"));
        let hot = serde_json::to_value(Meta::page(1, 1).with_source(Source::Hot)).unwrap();
        assert_eq!(hot["source"], serde_json::json!("hot"));
        assert!(
            serde_json::to_value(Meta::page(1, 1)).unwrap().get("source").is_none(),
            "不设 source 则不出"
        );
    }

    /// 热查信封形状锁 (§14.1): meta 恰 {has_more, source}, **无 total_count** —— 捕获"热查误发 total_count"。
    #[test]
    fn hot_shape_omits_total_count() {
        // R6: 镜像真实热查 emit (hot.rs 三出口 .with_source(Hot).with_freshness(Hot{live:true}); 真发见真跑)。
        let v = serde_json::to_value(
            Meta::hot(true)
                .with_source(Source::Hot)
                .with_freshness(Freshness::Hot { live: true }),
        )
        .unwrap();
        let keys: std::collections::BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["freshness", "has_more", "source"].into_iter().collect(),
            "热查 meta 恰 {{has_more, source, freshness}} (§14.1 恒省略 total_count; R6 带 {{live:true}})"
        );
        assert_eq!(v["source"], serde_json::json!("hot"));
        assert_eq!(v["freshness"], serde_json::json!({ "live": true }));
        assert!(v.get("total_count").is_none(), "§14.1 热查恒省略 total_count");
        assert!(!Meta::hot(false).has_more);
    }

    /// 冷查·无廉价全量信封形状锁 (修 HOLE-2): meta 恰 {has_more, source}, **无 total_count** ——
    /// 捕获"SQL-LIMIT 命令(sns-feed/dormant/new/exec/stats)拿页大小当 total_count 少报"。
    /// `has_more` 是调用方 fetch limit+1 精确探得的真值,不是 `shown<total` 的重言式。
    #[test]
    fn cold_page_omits_total_count() {
        let v = serde_json::to_value(Meta::cold_page(true).with_source(Source::Cold)).unwrap();
        let keys: std::collections::BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["has_more", "source"].into_iter().collect(),
            "冷查·无廉价全量 meta 恰 {{has_more, source}} (HOLE-2: 省略 total_count)"
        );
        assert_eq!(v["has_more"], serde_json::json!(true));
        assert_eq!(v["source"], serde_json::json!("cold"));
        assert!(
            v.get("total_count").is_none(),
            "HOLE-2: 无廉价全量 → 省略 total_count, 不拿页大小充数"
        );
        assert!(!Meta::cold_page(false).has_more, "到底 → has_more=false");
    }

    /// 游标分页信封形状锁 (④, §6): meta 恰 {has_more, limit, next_cursor, source}, **无 total_count/offset**。
    /// 到底 (next_cursor=None) 时省略 next_cursor → 恰 {has_more, limit, source}。
    #[test]
    fn cursor_page_shape_locked() {
        // 有下页: next_cursor 出。
        let mid =
            serde_json::to_value(Meta::cursor_page(true, Some("opaque".into()), 50).with_source(Source::Cold)).unwrap();
        let keys: std::collections::BTreeSet<&str> = mid.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["has_more", "limit", "next_cursor", "source"].into_iter().collect(),
            "游标分页(有下页) meta 恰 {{has_more, limit, next_cursor, source}}"
        );
        assert_eq!(mid["next_cursor"], serde_json::json!("opaque"));
        assert!(mid.get("total_count").is_none(), "游标分页省略 total_count (§6)");
        assert!(mid.get("offset").is_none(), "游标分页不出 offset");

        // 到底: next_cursor=None → 省略。
        let last = serde_json::to_value(Meta::cursor_page(false, None, 50).with_source(Source::Cold)).unwrap();
        let lkeys: std::collections::BTreeSet<&str> = last.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            lkeys,
            ["has_more", "limit", "source"].into_iter().collect(),
            "到底省略 next_cursor → 恰 {{has_more, limit, source}}"
        );
        assert!(!last["has_more"].as_bool().unwrap());
    }

    /// meta.summary (HOLE-3 收口): 命令特有域字段收进定义好的 summary 槽位, 标准字段不受污染; 不设则不出。
    #[test]
    fn meta_summary_holds_domain_fields() {
        // 不设 → 不序列化 (标准命令 meta 干净)。
        let plain = serde_json::to_value(Meta::cold_page(false).with_source(Source::Cold)).unwrap();
        assert!(plain.get("summary").is_none(), "不设 summary → 不出");
        // 设了 → 域字段全在 meta.summary 内, meta 顶层仍恰 {标准字段 + summary}。
        let v = serde_json::to_value(
            Meta::cold_page(true)
                .with_source(Source::Cold)
                .with_summary(serde_json::json!({"phone_total": 5, "shown": 3})),
        )
        .unwrap();
        let keys: std::collections::BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["has_more", "source", "summary"].into_iter().collect(),
            "meta 顶层恰 {{标准 + summary}}, 域字段不外泄到顶层"
        );
        assert!(v["summary"].is_object(), "summary 是嵌套对象");
        assert_eq!(v["summary"]["phone_total"], serde_json::json!(5));
    }

    /// Source 枚举序列化对齐契约字符串 (② 会用到)。
    #[test]
    fn source_serializes_kebab() {
        assert_eq!(serde_json::to_value(Source::Hot).unwrap(), serde_json::json!("hot"));
        assert_eq!(serde_json::to_value(Source::Cold).unwrap(), serde_json::json!("cold"));
        assert_eq!(
            serde_json::to_value(Source::LiveIndex).unwrap(),
            serde_json::json!("live-index")
        );
    }
}
