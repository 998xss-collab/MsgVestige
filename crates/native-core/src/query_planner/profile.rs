//! 性能档（主/副号）判定 + 阈值门 —— **ADR-407 §3.3 / §3.4 / §3.5 1:1**。
//!
//! **甲档 stat 口径**：[`PerfProfile::detect`] 取 `db_count` + `total_size_bytes`（cli 侧 stat 源库目录得来），
//! **不查 source_db_catalog 表**（ADR-407 §3.4 原文查表；甲按串联 §289「catalog 能 stat 就别落表」改 stat，
//! 判定的**输入语义完全一致**：db 个数 + 总 size）。

/// 性能档（ADR-407 §3.4）。判据：`db_count >= 30 || total_size_gb >= 30` → 副号，否则主号。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfProfile {
    /// 主号（< 30 db **且** < 30 GB）。
    Main,
    /// 副号（≥ 30 db **或** ≥ 30 GB）。
    Secondary,
}

/// 副号判定阈值：db 个数（ADR-407 §3.4）。
const SECONDARY_DB_COUNT: usize = 30;
/// 副号判定阈值：总 size（GB，ADR-407 §3.4）。
const SECONDARY_SIZE_GB: u64 = 30;
/// 1 GiB 字节数。
const BYTES_PER_GB: u64 = 1024 * 1024 * 1024;

impl PerfProfile {
    /// 从源库 db 个数 + 总字节数判定主/副号（ADR-407 §3.4）。
    ///
    /// 甲：`db_count` / `total_size_bytes` 由 cli stat 源库目录得来（不查 catalog 表；输入语义同 ADR-407）。
    #[must_use]
    pub fn detect(db_count: usize, total_size_bytes: u64) -> Self {
        let total_size_gb = total_size_bytes / BYTES_PER_GB;
        if db_count >= SECONDARY_DB_COUNT || total_size_gb >= SECONDARY_SIZE_GB {
            PerfProfile::Secondary
        } else {
            PerfProfile::Main
        }
    }

    /// 提示阈值 ms（ADR-407 §3.3）：主 5s / 副 10s。cost ≥ 此值 < 强制值 → stderr 建议 cache add。
    #[must_use]
    pub fn prompt_threshold_ms(&self) -> u64 {
        match self {
            PerfProfile::Main => 5_000,
            PerfProfile::Secondary => 10_000,
        }
    }

    /// 强制阈值 ms（ADR-407 §3.3）：主 15s / 副 30s。cost ≥ 此值且无 --confirm → exit 1。
    #[must_use]
    pub fn enforce_threshold_ms(&self) -> u64 {
        match self {
            PerfProfile::Main => 15_000,
            PerfProfile::Secondary => 30_000,
        }
    }

    /// 阈值门判定（ADR-407 §3.5 case 1-4）。**纯逻辑**（不碰 stderr/exit —— 那是 cli 行为）；
    /// cli 拿 [`GateOutcome`] 后落 stderr 文案 + 退出码（+ `--quiet` 免打扰把 [`GateOutcome::Hint`] 压成静默）。
    ///
    /// - `estimated_ms`：[`super::cost::estimate`] 出的 `cost.estimated_ms`。
    /// - `confirm`：用户是否传了 `--confirm`。
    #[must_use]
    pub fn gate(&self, estimated_ms: u64, confirm: bool) -> GateOutcome {
        let prompt = self.prompt_threshold_ms();
        let enforce = self.enforce_threshold_ms();
        if estimated_ms < prompt {
            GateOutcome::Silent // case 1
        } else if estimated_ms < enforce {
            GateOutcome::Hint { estimated_ms } // case 2
        } else if confirm {
            GateOutcome::ConfirmedProceed { estimated_ms } // case 4
        } else {
            GateOutcome::Blocked {
                estimated_ms,
                enforce_threshold_ms: enforce,
            } // case 3
        }
    }
}

/// 阈值门结果（ADR-407 §3.5 的 4 case）。cli 据此落行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// case 1: cost < 提示阈值 → 静默执行。
    Silent,
    /// case 2: 提示阈值 ≤ cost < 强制阈值 → stderr 建议 + 继续（`--quiet` 免打扰时 cli 压成静默）。
    Hint {
        /// 估算 ms（cli 文案用）。
        estimated_ms: u64,
    },
    /// case 3: cost ≥ 强制阈值且未 --confirm → stderr + **exit 1**（不执行）。
    Blocked {
        /// 估算 ms。
        estimated_ms: u64,
        /// 触发的强制阈值 ms。
        enforce_threshold_ms: u64,
    },
    /// case 4: cost ≥ 强制阈值且已 --confirm → 继续（cli 可 stderr 告知"已确认，执行中"）。
    ConfirmedProceed {
        /// 估算 ms。
        estimated_ms: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_main_vs_secondary_boundaries() {
        // 主号：< 30 db 且 < 30 GB
        assert_eq!(PerfProfile::detect(0, 0), PerfProfile::Main);
        assert_eq!(PerfProfile::detect(29, 29 * BYTES_PER_GB), PerfProfile::Main);
        // 副号：≥ 30 db（size 无关）
        assert_eq!(PerfProfile::detect(30, 0), PerfProfile::Secondary);
        assert_eq!(PerfProfile::detect(50, 0), PerfProfile::Secondary);
        // 副号：≥ 30 GB（db 数无关）
        assert_eq!(PerfProfile::detect(1, 30 * BYTES_PER_GB), PerfProfile::Secondary);
        assert_eq!(PerfProfile::detect(5, 50 * BYTES_PER_GB), PerfProfile::Secondary);
        // 边界：29 db + 29 GB 仍主号（ADR-407 §3.6 反例 3：临界不突变到强制档）
        assert_eq!(
            PerfProfile::detect(29, 29 * BYTES_PER_GB + (BYTES_PER_GB - 1)),
            PerfProfile::Main
        );
    }

    #[test]
    fn thresholds_match_adr407() {
        assert_eq!(PerfProfile::Main.prompt_threshold_ms(), 5_000);
        assert_eq!(PerfProfile::Main.enforce_threshold_ms(), 15_000);
        assert_eq!(PerfProfile::Secondary.prompt_threshold_ms(), 10_000);
        assert_eq!(PerfProfile::Secondary.enforce_threshold_ms(), 30_000);
    }

    #[test]
    fn gate_four_cases_main() {
        let p = PerfProfile::Main; // 5s 提示 / 15s 强制
                                   // case 1: < 5s 静默
        assert_eq!(p.gate(4_999, false), GateOutcome::Silent);
        // case 2: 5s ≤ cost < 15s 提示
        assert_eq!(p.gate(5_000, false), GateOutcome::Hint { estimated_ms: 5_000 });
        assert_eq!(p.gate(14_999, false), GateOutcome::Hint { estimated_ms: 14_999 });
        // case 3: ≥ 15s 无 confirm 阻断
        assert_eq!(
            p.gate(15_000, false),
            GateOutcome::Blocked {
                estimated_ms: 15_000,
                enforce_threshold_ms: 15_000
            }
        );
        // case 4: ≥ 15s 有 confirm 放行
        assert_eq!(
            p.gate(45_000, true),
            GateOutcome::ConfirmedProceed { estimated_ms: 45_000 }
        );
    }

    #[test]
    fn gate_secondary_higher_thresholds() {
        let p = PerfProfile::Secondary; // 10s 提示 / 30s 强制
        assert_eq!(p.gate(9_999, false), GateOutcome::Silent);
        assert_eq!(p.gate(10_000, false), GateOutcome::Hint { estimated_ms: 10_000 });
        assert_eq!(p.gate(29_999, false), GateOutcome::Hint { estimated_ms: 29_999 });
        assert_eq!(
            p.gate(30_000, false),
            GateOutcome::Blocked {
                estimated_ms: 30_000,
                enforce_threshold_ms: 30_000
            }
        );
        assert_eq!(
            p.gate(30_000, true),
            GateOutcome::ConfirmedProceed { estimated_ms: 30_000 }
        );
    }
}
