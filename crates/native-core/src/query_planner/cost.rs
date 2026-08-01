//! Cost model —— **ADR-407 §3.1 公式 1:1**（线性 + 常数项 + 跨 db LPT makespan）。
//!
//! `cost(plan) = Σ_非跨db_step (constant + rows·per_row) + cost_cross_db(plan)`
//! 其中 `cost_cross_db` = **LPT（最长处理时间优先）贪心排程的可达 makespan**（per_db 降序、逐个派当前最闲 worker、
//! 取最重负载，MAX_CONCURRENT=4）。r7 收敛（同一区 r3/r4/r7 挖穿，简单闭式做不到「单调 ∧ 不过估异构 ∧ 不低估同构」
//! 三头兼得，换 LPT 模拟）：旧 `⌈N/4⌉×avg` 非单调、`⌈N/4⌉×max` 过估异构、`max(单库, ⌈总和/4⌉)` 是乐观下界低估同构；
//! LPT 是**可达排程墙钟（非下界）**→ 成本门永不欠拦、≤4/3·最优 → 不过估、加空步不改 → 单调。详见 `estimate()` 体内注 + ADR-407 §3.1。
//! ⚠️ R21 门走 `cross_db:false`（下方顺序求和 = 保守上界、永不欠拦），本 LPT 分支对 R21 恒不触发，仅供 R22 并发执行器。
//!
//! 参数 alpha 硬编码 baseline（ADR-407 §3.2）：Tier1 0.5ms + 1ms/千行；Tier2 单 db 10ms + 100ms/千行。
//! 已知 ±50% 硬件偏差（反例 1），真机校准推 0.2.0+ self-learning（KI-A）。
//!
//! **对 ADR-407 §3.1 签名的两处简化（甲 MVP）**：
//! 1. `estimate` 取 `&[PlanStep]` 而非 `&Plan` —— 避开 `Plan { estimated_cost: Cost }` 的鸡蛋循环
//!    （调用方 `plan()`：`let cost = estimate(&steps); Plan { steps, estimated_cost: cost }`）。
//! 2. 不入 `profile: PerfProfile` 参 —— cost（ms）**与主/副号档无关**（都是估算耗时）；档只在
//!    **阈值比较**用（cli 侧 `profile.prompt_threshold_ms()` 对比 `cost.estimated_ms`），不在估算里。
//!    （ADR-407 §3.1 原签名带 profile 但公式体从不读它。）

use super::PlanStep;

/// Tier2 单 db 常数项（ms）。
const TIER2_CONST_MS: f64 = 10.0;
/// Tier2 每千行（ms）。
const TIER2_PER_1K_MS: f64 = 100.0;
/// 跨 db 并发上限（ADR-406 §3.5 TD5 / ADR-407 一致，硬编码）。
const MAX_CONCURRENT_DB_QUERIES: usize = 4;

/// 估算成本（ADR-407 §3.1；单一真相在本 crate）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cost {
    /// 总估算 ms（cross_db 走 LPT 可达 makespan；单 db 顺序求和上界）。
    pub estimated_ms: u64,
    /// 总估算行数。
    pub estimated_rows: usize,
    /// 各 step 拆分（cli 调试 / 反例自检）。
    pub breakdown: CostBreakdown,
}

/// cost 拆分（ADR-407 §3.1）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CostBreakdown {
    /// Tier1（L1 cache）总 ms。
    ///
    /// **现在恒 0** —— 成本门只 stat 源库估回源开销, 不存在产出 Tier1 step 的代码路径
    /// (R22 那套分层执行器随 ADR-508 D24 删了)。字段保留是因为它是对外 breakdown 的形状。
    pub tier1_ms: u64,
    /// Tier2 单 db 总 ms。
    pub tier2_single_ms: u64,
    /// Tier2 跨 db（LPT 可达 makespan）总 ms。
    pub tier2_cross_db_ms: u64,
    /// 0.2.0+ self-learning 留余地（alpha 恒 0）。
    pub concurrency_adjustment_ms: i64,
}

/// 按 ADR-407 §3.1 公式估算 `steps` 的成本。见模块文档对签名的两处简化说明。
#[must_use]
pub fn estimate(steps: &[PlanStep]) -> Cost {
    let mut breakdown = CostBreakdown::default();
    let mut tier2_cross_db_per_db: Vec<f64> = Vec::new();
    let mut total_rows: usize = 0;

    for step in steps {
        match step {
            PlanStep::QueryTier2 { .. } => {
                let rows = step.estimated_rows();
                total_rows += rows;
                let ms = TIER2_CONST_MS + (rows as f64 / 1000.0) * TIER2_PER_1K_MS;
                if step.is_cross_db() {
                    tier2_cross_db_per_db.push(ms);
                } else {
                    breakdown.tier2_single_ms += ms.ceil() as u64;
                }
            }
        }
    }

    // 跨 db 并发 makespan（ADR-407 §3.1）—— **LPT (最长处理时间优先) 贪心排程的可达 makespan**。
    // 同一区被三轮挖穿 = 简单闭式做不到「单调 ∧ 不过估异构 ∧ 不低估同构」三者兼得, 故换设计走 LPT 模拟:
    //   · round-3 codex: `⌈N/4⌉×avg` **非单调**(加空 step 降 avg → 降总估);
    //   · round-4 codex: `⌈N/4⌉×max` **过估异构**(1×6s + 8 空 → 18s, 实 4-worker ~6s → Hint 误翻 Blocked);
    //   · round-7 codex: `max(单库最大, ⌈总和/4⌉)` 是**乐观下界**, **低估同构**(9×5010 实需 3 波 = 15030,
    //     下界只给 11273 → Main 档 Blocked 误翻 Hint = **欠拦**, 对成本门是安全方向的错)。
    // LPT 一举全解: 降序把每分片派给当前**最闲** worker, 取最重 worker 负载 = 真实可达排程的墙钟。
    //   · 是**可达 makespan** 而非下界 → 对成本门**永不欠拦**(门需 ≥ 真实耗时); 且 ≤ 4/3·最优 → 不过估;
    //   · **单调**: 加分片派最闲 worker → 最重负载非减; 加空/0 步不改 makespan(免 round-3 缺陷);
    //   · 异构**不过估**(round-4 例: 6s 独占一 worker、空步并行填别处 → 6000, 非 18000);
    //   · 同构**不低估**(round-7 例: 9×5010 → ⌈9/4⌉=3 波 → 15030);
    //   · 对齐 R22 并发执行器(Semaphore=4 贪心派工)的实际墙钟。
    // ⚠️ R21 门本身走 `cross_db:false`(上方 tier2_single_ms 顺序求和 = 保守上界), 本分支对 R21 恒 0;
    // 改此仅令 R22 / 跨 db API 的估算由「乐观下界」升为「可达 makespan」, 不改 R21 门行为。
    if !tier2_cross_db_per_db.is_empty() {
        let w = MAX_CONCURRENT_DB_QUERIES.max(1);
        // LPT: 先派大任务 (降序), 贪心近最优 (total_cmp 稳定处理 f64, 值恒非 NaN)。
        tier2_cross_db_per_db.sort_unstable_by(|a, b| b.total_cmp(a));
        let mut loads = vec![0.0_f64; w];
        for d in &tier2_cross_db_per_db {
            let min_i = loads
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| a.total_cmp(b))
                .map(|(i, _)| i)
                .unwrap_or(0);
            loads[min_i] += *d;
        }
        let makespan = loads.iter().copied().fold(0.0_f64, f64::max);
        breakdown.tier2_cross_db_ms = makespan.ceil() as u64;
        breakdown.concurrency_adjustment_ms = 0; // alpha
    }

    let estimated_ms = breakdown.tier1_ms + breakdown.tier2_single_ms + breakdown.tier2_cross_db_ms;

    Cost {
        estimated_ms,
        estimated_rows: total_rows,
        breakdown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造 N 个跨 db Tier2 step，每个 `rows` 行。
    fn cross_db_steps(n: usize, rows: usize) -> Vec<PlanStep> {
        (0..n)
            .map(|i| PlanStep::QueryTier2 {
                step_id: i,
                rel_name: format!("message_{i}.db"),
                estimated_rows: rows,
                cross_db: true,
            })
            .collect()
    }

    /// **round-3/4/7 codex 迭代收敛**：cross_db 用 **LPT 贪心排程的可达 makespan**（非任何闭式下界）。
    /// 单 db per_db = 10 + 50000/1000*100 = 5010ms；N 个**等成本**分片 4 worker → makespan = ⌈N/4⌉×per_db
    /// （等成本时 LPT = 波数×单波）。round-7 修：N=5 由乐观下界 6263 → 可达 10020（5 任务 4 worker 必 2 波）。
    #[test]
    fn cross_db_makespan_lpt() {
        let rows = 50_000;
        let per_db = 5010u64;
        // (N, 期望 = ⌈N/4⌉×5010)。
        for (n, expect) in [
            (1, 5010u64),
            (4, 5010),
            (5, 10020),
            (8, 10020),
            (12, 15030),
            (30, 40080),
            (50, 65130),
        ] {
            let cost = estimate(&cross_db_steps(n, rows));
            assert_eq!(cost.estimated_ms, expect, "N={n}: ⌈{n}/4⌉×{per_db} 应 = {expect}");
            assert_eq!(cost.estimated_rows, n * rows, "N={n} 总行数");
        }
        // 阈值对齐：N=1→5010(主号5s提示线)、N=12→15030(主号15s强制线上)、
        // N=30→40080(超副号30s强制)、N=50→65130(~65s, 副号60s p95 线上)。
    }

    /// **round-4 codex 反例锁死**：LPT **不过估异构** —— 1 个重分片 (6000ms) + 8 个空分片 (const 10ms) 4 worker
    /// → makespan = 6000（重的独占一 worker、空的并行填其余）, **非** ⌈9/4⌉×6000 = 18000 的过估。
    #[test]
    fn cross_db_lpt_no_overestimate_heterogeneous() {
        // 重分片 rows=59900 → 10 + 59900/1000*100 = 6000ms; 8 个空分片 rows=0 → const 10ms。
        let mut steps = vec![PlanStep::QueryTier2 {
            step_id: 0,
            rel_name: "big.db".into(),
            estimated_rows: 59_900,
            cross_db: true,
        }];
        for i in 1..9 {
            steps.push(PlanStep::QueryTier2 {
                step_id: i,
                rel_name: format!("empty_{i}.db"),
                estimated_rows: 0,
                cross_db: true,
            });
        }
        let cost = estimate(&steps);
        assert_eq!(
            cost.estimated_ms, 6000,
            "LPT 异构不过估: 重分片独占一 worker = 6000, 非 18000"
        );
    }

    /// 单调递增（旧 0.7^N 大 N 衰减到 0 的反例已废）：N 越大 cost 不减。
    #[test]
    fn cost_is_monotonic_in_db_count() {
        let rows = 50_000;
        let mut last = 0u64;
        for n in [1usize, 4, 5, 8, 12, 30, 50, 100] {
            let c = estimate(&cross_db_steps(n, rows)).estimated_ms;
            assert!(c >= last, "N={n} cost={c} 应 ≥ 前一档 {last}（单调递增）");
            last = c;
        }
    }

    /// **round-3 codex P2 反例**：**异构**分片下也必须单调（旧 `avg` 会「加空 step 反降总估」——
    /// 4×100k+1空=16020ms → 再+1空 降到 13354ms，Main 档从 Blocked 翻 Hint）。改 `max` 后非减。
    #[test]
    fn cross_db_monotonic_with_heterogeneous_shards() {
        let mk = |rows: usize, i: usize| PlanStep::QueryTier2 {
            step_id: i,
            rel_name: format!("message_{i}.db"),
            estimated_rows: rows,
            cross_db: true,
        };
        // base = 4 个 100k 行 step；逐个追加空 step，断言总估**永不下降**（旧 avg 在第 5→6 个会降）。
        let mut steps: Vec<PlanStep> = (0..4).map(|i| mk(100_000, i)).collect();
        let mut last = estimate(&steps).estimated_ms;
        for i in 4..12 {
            steps.push(mk(0, i));
            let now = estimate(&steps).estimated_ms;
            assert!(now >= last, "加空 step({i}) 后 cost={now} 应 ≥ 前 {last}（max 单调）");
            last = now;
        }
        // 追加一个更大的 step → max 上升 → 总估必抬高。
        steps.push(mk(500_000, 99));
        assert!(estimate(&steps).estimated_ms > last, "加更大 step 应抬高总估");
    }

    /// Tier2 单 db（非跨 db）：10ms const + rows/千行 × 100ms。
    #[test]
    fn tier2_single_db_not_cross() {
        let steps = vec![PlanStep::QueryTier2 {
            step_id: 0,
            rel_name: "message_0.db".into(),
            estimated_rows: 1_000,
            cross_db: false,
        }];
        let cost = estimate(&steps);
        // 10 + 1000/1000*100 = 110
        assert_eq!(cost.breakdown.tier2_single_ms, 110);
        assert_eq!(cost.breakdown.tier2_cross_db_ms, 0);
        assert_eq!(cost.estimated_ms, 110);
    }

    /// 空 steps → 0 成本（不 panic）。
    #[test]
    fn empty_steps_zero_cost() {
        assert_eq!(estimate(&[]).estimated_ms, 0);
    }
}
