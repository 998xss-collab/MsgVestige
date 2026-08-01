//! 计划引擎 —— R21 成本预估（甲档）。
//!
//! **R21 甲档**（用户 2026-07-26 拍板）：cost 预估**直接 stat 源库文件**粗估（数 db 个数 + 加总大小 → 定
//! 主/副号档 + ADR-407 §3.1 cost model 估耗时），**不填休眠地图表**。符串联 §289「预估只查元数据（catalog 能
//! stat 就别落表）不碰大库」。行数/耗时粗估（ADR-407 容忍 50% 偏差）。
//!
//! **权威源**：cost 公式 / 参数 / 阈值 / 主副号判定 / 触发行为 → **ADR-407**（本模块 [`cost`] / [`profile`]
//! 跟它 1:1）。
//!
//! **native-core 保持纯**（无 fs）：stat 源库 + CLI 阈值门在 cli 侧。
//!
//! ---
//!
//! ## 这里曾经还有一套 partial-hit 计划（已删，2026-07-27）
//!
//! R22 原本要在本模块出**可执行计划**：按已缓存的时间区间集合把查询窗拆成 covered（走 L1）/ gap
//! （回源解密），执行器分两路取数再合并。为此有过 `Plan` / `TimeRange` / `Tier1Exec` / `Tier2Exec` /
//! `PlanError` / `SourceShard` / `OrderKey` / `DedupKey` 等一大套类型。
//!
//! 它们随 **ADR-508 D24** 整体作废：判据"某段时间是完整的"没有便宜的验证方式 —— 微信会把很老的消息
//! 事后补写进来（真库实测：最老一次回补 137 天，插在表 92% 处），那条消息落在早已标"已缓存"的区间里，
//! 程序再不会去那段取数 → **永久不可见且零信号**。改成"这张表已采到 `local_id` 几"
//! （`AUTOINCREMENT` 保证后补的行必拿更大的号 → 游标必扫到），实现在 `native_query::refresh`。
//!
//! 那些类型在删除前已是生产零引用的残留，文档里凡提到 "covered / gap / 区间集合差" 的都是历史语境。
//! 要考古看 ADR-508 与 commit `f136163` / `fea011e`。

pub mod cost;
pub mod profile;

pub use cost::{estimate, Cost, CostBreakdown};
pub use profile::PerfProfile;

/// 计划步骤。
///
/// 现在只剩 R21 成本门用的那一个形态：**成本骨架** —— 只 stat 源库文件，不做 chat 路由、不带区间，
/// 拿 `estimated_rows` + `cross_db` 喂 [`cost::estimate`]。
///
/// 保留 `enum` 而非拍平成结构体，是因为 ADR-407 的成本模型本身分 Tier1/Tier2 两类；将来若真要再加
/// 一档（例如常驻索引直答），加 variant 比改类型签名便宜。
#[derive(Debug, Clone)]
pub enum PlanStep {
    /// Tier 2 源 db 查询（单 db SQLCipher 解密 + SQL，~100ms/1000 rows）。
    QueryTier2 {
        /// step 序号（从 0 起）。
        step_id: usize,
        /// 目标 db 相对名（e.g. `"message_3.db"`），供 breakdown 调试。
        rel_name: String,
        /// 该 step 估算行数。
        estimated_rows: usize,
        /// 是否属跨 db 并发批（true → 走 ADR-407 §3.1 跨 db LPT makespan）。
        ///
        /// R21 成本门恒 `false`：顺序求和才是真实上界，标 true 会低估成本（ADR-508 D9）。
        cross_db: bool,
    },
}

impl PlanStep {
    /// 该 step 估算行数（ADR-407 `estimate()` 消费）。
    #[must_use]
    pub fn estimated_rows(&self) -> usize {
        match self {
            PlanStep::QueryTier2 { estimated_rows, .. } => *estimated_rows,
        }
    }

    /// 是否跨 db step（走 ADR-407 §3.1 跨 db LPT makespan）。
    #[must_use]
    pub fn is_cross_db(&self) -> bool {
        matches!(self, PlanStep::QueryTier2 { cross_db: true, .. })
    }

    /// step 序号。
    #[must_use]
    pub fn step_id(&self) -> usize {
        match self {
            PlanStep::QueryTier2 { step_id, .. } => *step_id,
        }
    }
}
