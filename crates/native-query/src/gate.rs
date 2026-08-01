//! R21 全扫成本门 —— **三皮共享决策核**（CLI / MCP / HTTP 共用）。
//!
//! 门只**决策**（估算 + 阈值 → [`GateOutcome`]），**不呈现**（stderr/exit·isError·envelope 留各皮）。慢查
//! （热查经 `SourceQuery::scan_all_messages` / `scan_conversations` 全扫 message 分片, 大账号 10 分钟级）执行前
//! 按 ADR-407 估耗时: 超强制阈值 → `Blocked`（皮侧要求 confirm）, 提示档 → `Hint`。皮据 [`GateReport`] 呈现。
//!
//! **预检优先于成本块**（审 round-3/5 codex P2）: 翻页越界（`check_hot_window`）、缺 key（`cache_key` 失败）都
//! 比"多分钟全扫"廉价且是真拦因 —— 先于成本块处理。缺 key **返 `Silent` 放行**, 让下游 hot_X 的 `cache_key`
//! 报精确 auth 错（别用成本块盖 auth）。
//!
//! **三皮 confirm/quiet 差异**: `confirm` 是**参数**（CLI 顶层全局 flag / MCP arg / HTTP `?confirm=`）; `quiet`
//! （免打扰压 `Hint`）是**纯呈现**取舍, 不进本核 —— CLI 皮把 Hint 印 stderr（`--quiet` 压掉）; MCP/HTTP 对 Hint
//! **直接放行、不额外呈现**（信封无警告字段, 非交互皮一致丢弃软提示是刻意设计; 两皮只硬拦 `Blocked`）。
//!
//! **成本 vs 门覆盖**: 本核估的是 message+biz_message 分片顺序全扫成本; 只覆盖会**全扫**的命令（皮侧在调对应
//! `hot_*` 前调本门）。chat 定向查（messages/messages_around）、`biz`（scan_conversations gh_ 子集, 全扫估算会
//! 过估误拦）、`inspect` 非 message 臂 由皮侧**不调**本门（同 CLI 侧排除口径）。
//!
//! **已知限制（round-16 codex P2 · 用户裁定接受为文档化近似, 2026-07-26）**: 估算只按 message+biz_message 分片
//! 字节, **不计命令特定的非消息源读**。最显著: `money` 命令先调 `read_hot_money_base` **全表读** general.db 的 3
//! 张交易表（transferTable/红包/群收款, 无 `LIMIT`、materialize 全行）。若某账号**交易多而消息分片小**, 门估算
//! 偏低 → 该 money 查询可能未经 `confirm` 就跑。但 general.db 读**有界于交易条数**（秒级, 非 message 全扫的分钟
//! 级/GB 级）、且该组合罕见 —— 按"门 = 拦多分钟 message 全扫"的职责, 这是**可接受的近似边界**, 非欠拦真慢查。
//! 精确的命令特定成本模型留 0.2.0+（同 ADR-407 KI-A self-learning）。

use anyhow::Result;
use native_core::query_planner::profile::{GateOutcome, PerfProfile};
use native_core::query_planner::{cost, PlanStep};
use native_core::Wxid;

use crate::hot::{cache_key, check_hot_window, db_shard_files, resolve_message_dir};

/// 门决策报告 —— 皮侧据此呈现（CLI stderr/exit+quiet · MCP isError/envelope · HTTP error-envelope/警告字段）。
#[derive(Debug, Clone, Copy)]
pub struct GateReport {
    /// 阈值门结果（Silent / Hint / Blocked / ConfirmedProceed）。
    pub outcome: GateOutcome,
    /// 估算耗时 ms（文案用；Silent 时为 0）。
    pub estimated_ms: u64,
    /// 主/副号档（文案用: "主号"/"副号"）。
    pub profile: PerfProfile,
    /// 估算跨的 message+biz 分片数（文案用: "跨 N 分片"）。
    pub shard_count: usize,
}

impl GateReport {
    /// 不拦（Silent, 0 估算, 主号, 0 分片）—— 缺 key / 定位不到源库 / 无分片时返此放行。
    fn silent() -> Self {
        Self {
            outcome: GateOutcome::Silent,
            estimated_ms: 0,
            profile: PerfProfile::Main,
            shard_count: 0,
        }
    }
    /// 估算 ms 向上取整到秒（文案 "估算 X 秒" 用）。
    #[must_use]
    pub fn estimated_secs(&self) -> u64 {
        self.estimated_ms.div_ceil(1000)
    }
    /// 档位中文标（文案用）。
    #[must_use]
    pub fn profile_label(&self) -> &'static str {
        match self.profile {
            PerfProfile::Main => "主号",
            PerfProfile::Secondary => "副号",
        }
    }
}

/// R21 全扫成本门决策（三皮共享）。`async`（`cache_key` 缺 key 预检需）。**只决策不呈现**。
///
/// 流程: 翻页窗口预检 → 缺 key 预检（放行）→ stat message+biz 分片（含 WAL）算 cost + stat 整账号 catalog
/// 定主/副号 → [`GateOutcome`]。
///
/// # Errors
/// `check_hot_window` 越界 → `BadRequest`（携码 anyhow 错, 皮侧 `classify_error` map）。其余异常（缺 key /
/// 定位不到 / 无分片）**不报错**, 返 `Silent` 放行（让下游命令自己报精确错）。
pub async fn full_scan_cost_gate(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    offset: usize,
    limit: usize,
    confirm: bool,
) -> Result<GateReport> {
    // 预检① 翻页窗口越界（廉价纯算术, 越界该先于慢查报; 与 hot_X 首行同守卫幂等）。**唯一会返 Err 的**。
    check_hot_window(offset, limit)?;
    // 预检② 缺 key / cache 损坏 → 不拦（返 Silent 放行）—— 让下游 hot_X 的 cache_key 报精确 auth 错
    //   （审 round-5 codex P2: 缺 key 时查根本跑不了, 用成本块盖 auth 错会误导用户 confirm 一个跑不了的查）。
    //   拿到的 key **留到下方"要 Blocked 时"验它对源库真有效**（round-12 codex P2, 见预检③）。
    let Ok(key) = cache_key(wxid).await else {
        return Ok(GateReport::silent());
    };
    // **定位源库 + 全部 fs stat 都下沉 spawn_blocking**: serve 是 current_thread tokio runtime（见 Cargo.toml
    //   头注 / hot.rs）, 任何同步 fs 留在 async 线程都卡整个 reactor（健康检查/其它请求/request-timeout 定时器都被
    //   拖）。round-8 codex P2 先搬了 stat; round-10 codex P2: `resolve_message_dir` 也 `read_dir` 找账号目录, 一并
    //   搬进闭包别留 reactor 上。闭包返 None = 定位不到源库 / 无 message 分片, 皆 → Silent 放行（下游 hot_* 自报）。
    let wxid_owned = wxid.clone();
    let dir_owned = wechat_data_dir.map(str::to_string);
    let Ok(stat) = tokio::task::spawn_blocking(move || {
        let msg_dir = resolve_message_dir(dir_owned.as_deref(), &wxid_owned).ok()?;
        stat_shards_and_catalog(&msg_dir)
    })
    .await
    else {
        return Ok(GateReport::silent()); // stat 任务 panic/cancel（实际不可达, 内部全 unwrap_or）→ 不拦, 下游报
    };
    let Some((sizes, profile_db_count, profile_total_size, probe_shards)) = stat else {
        return Ok(GateReport::silent()); // 定位不到源库 / 无 message 分片 → 不拦, 下游报
    };
    let shard_count = sizes.len();
    let (estimated_ms, profile, outcome) = gate_decision(&sizes, profile_db_count, profile_total_size, confirm);
    // 预检③ **仅在要硬拦 (Blocked) 时**验 key 对源库真有效（round-12 codex P2）: `cache_key` 只证"缓存里有 key",
    //   不证它对这批库能解密 —— 过期 key / `wechat_data_dir` 指向另一同 wxid 装机时, key 缓存有但解不开。这种查
    //   同样"根本跑不了"（同 round-5 缺 key 情形）, 用成本块盖 auth 错会误导用户 confirm 一个注定失败的慢查。
    //   `verify_key_page1` **只读源库首页 4096B 跑 HMAC**（不解整库、**不读 -wal**）—— round-15 codex P1: 旧
    //   `open_decrypted_db_vfs` 会 `build_wal_overlay` 读整个 WAL 并解密已提交帧, 大 WAL 会让本该廉价拒绝的
    //   Blocked 请求卡顿/爆内存（尤其 HTTP 在 HOT_SCAN_SEMAPHORE 之前跑）; 页1-only 探针有界廉价。
    //   **逐分片试到任一验过即算 key 有效**（round-13 codex P2）: `SourceQuery::build` 容忍单分片坏、继续扫其余,
    //   故"首分片坏但其余好"仍是能跑的慢查 —— 只验首分片会把它误 Silent 放行成多分钟裸扫。key 有效则任一好分片必
    //   验过（全账号同 master key）, `.any` 命中即停（常见首分片就中 = 1 次 HMAC）; 全部验不过 = key 真错 / 全分片
    //   都坏（扫也跑不了）→ Silent 让下游报精确错。
    if matches!(outcome, GateOutcome::Blocked { .. }) {
        let key_ok = tokio::task::spawn_blocking(move || {
            probe_shards
                .iter()
                .any(|s| native_core::cipher::verify_key_page1(s, &key))
        })
        .await
        .unwrap_or(false); // 验 key 任务 panic/cancel → 当无效 → Silent（保守: 不硬拦, 下游报）
        if !key_ok {
            return Ok(GateReport::silent()); // key 对源库全分片都无效 → 不硬拦, 让下游 hot_* 报精确 auth 错
        }
    }
    Ok(GateReport {
        outcome,
        estimated_ms,
        profile,
        shard_count,
    })
}

/// **同步 fs 工作**（枚举 message+biz 分片 + stat 大小含 WAL + 递归 stat 整账号 catalog）—— 由
/// [`full_scan_cost_gate`] 经 `spawn_blocking` 调用（round-8 codex P2: 别在 current_thread async runtime 跑阻塞
/// fs, 否则卡 reactor）。返 `None` = 无 message 分片（放行）; `Some((分片字节含WAL, 整账号 db 数, 整账号总字节,
/// probe 分片路径集))`。probe 分片集 = 全 message+biz 分片路径, 供 Blocked 前逐分片 VFS 验 key（round-13 codex P2:
/// 单分片 probe 会漏"首分片坏但其余好"的能跑慢查, 逐分片试到任一开成即 key 有效）。
fn stat_shards_and_catalog(msg_dir: &std::path::Path) -> Option<(Vec<u64>, usize, u64, Vec<std::path::PathBuf>)> {
    // cost 估算集 = scan_all_messages 实扫集 = message_<n>.db + biz_message_<n>.db（content_shards 全族; 含 -wal 页）。
    let mut shards = db_shard_files(msg_dir, "message");
    shards.extend(db_shard_files(msg_dir, "biz_message"));
    if shards.is_empty() {
        return None;
    }
    let sizes: Vec<u64> = shards
        .iter()
        .map(|p| {
            let main = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            let wal = std::fs::metadata(wal_sibling(p)).map(|m| m.len()).unwrap_or(0);
            main + wal
        })
        .collect();
    // profile 判定用**整账号 db_storage 全 *.db**（ADR-407 §3.4 catalog 口径）, 非只 message 分片。cost 仍只用 message 分片。
    let db_storage = msg_dir.parent().unwrap_or(msg_dir);
    let (db_count, total_size) = stat_account_db_catalog(db_storage);
    Some((sizes, db_count, total_size, shards)) // shards 全集供 Blocked 前逐分片验 key
}

/// `<db>` → 兄弟 `<db>-wal` 路径, **保留原始 OS 字节**（不经 `display()` 有损转换）。审 round-8 codex P3:
/// 非 Unicode 路径分量经 `display()` 会被替换成 U+FFFD → 构造出的 `-wal` 路径不存在 → 漏算 WAL 字节 → 低估 →
/// 欠拦。同 native-sqlcipher `wal_sibling` 口径（WeChat WAL 命名 = 文件名直接追加 `-wal`, 非替换扩展名）。
fn wal_sibling(p: &std::path::Path) -> std::path::PathBuf {
    let mut s = p.to_path_buf().into_os_string();
    s.push("-wal");
    std::path::PathBuf::from(s)
}

/// 门的**纯逻辑决策**（可单测）: message 分片字节数 + 整账号 `(db_count, total_size)` + `confirm`
/// → `(估算 ms, 主/副号档, 阈值门结果)`。
///
/// 甲: `rows ≈ 分片字节 / AVG_BYTES_PER_MSG`（ADR-407 典型 db 50MB≈50k rows → 1KB, 可校准 KI-B）；N 个 message
/// 分片各建一**顺序** Tier2 step（`cross_db:false`, 逐个求和 = 保守上界, R21 热查同步顺序扫、无并发, 永不欠拦）；
/// **主/副号判定用整账号 catalog 的两参**（round-3 codex P2）。ADR-407 §3.1/§3.4/§3.5。
fn gate_decision(
    shard_sizes: &[u64],
    profile_db_count: usize,
    profile_total_size: u64,
    confirm: bool,
) -> (u64, PerfProfile, GateOutcome) {
    /// 每条消息平均字节数（甲粗估; ADR-407 典型 db 50MB≈50k rows → 1KB; 可校准 KI-B）。
    /// 审 round-2 Claude P3: 此估**假设全部行解码**; 但 ~15 个命令传 base_types 只解码稀疏匹配类型（calls[50]/
    /// cards[42]/events[10000] 等匹配行常占极小比例）→ 对它们**偏保守过估**（方向安全: 只会过拦、绝不放过真慢查）。
    /// 精确选择性需开库 = R22 partial-hit; 甲 stat-only 固有局限, 故 ADR-407「±50%」严格只对 base_types=None 命令成立。
    const AVG_BYTES_PER_MSG: u64 = 1024;
    // 主/副号判定用整账号 catalog（round-3 codex P2）, **不**用 message 分片个数/总 size。
    let profile = PerfProfile::detect(profile_db_count, profile_total_size);
    // cross_db:false → 各分片成本逐个求和（tier2_single_ms）= 顺序全扫的保守上界（R21 同步扫, 永不欠拦; 并发
    //   makespan（LPT）留 R22 执行器, 见 cost.rs）。
    let steps: Vec<PlanStep> = shard_sizes
        .iter()
        .enumerate()
        .map(|(i, &sz)| PlanStep::QueryTier2 {
            step_id: i,
            rel_name: format!("message_{i}.db"),
            estimated_rows: (sz / AVG_BYTES_PER_MSG) as usize,
            cross_db: false,
        })
        .collect();
    let est = cost::estimate(&steps);
    let outcome = profile.gate(est.estimated_ms, confirm);
    (est.estimated_ms, profile, outcome)
}

/// stat 账号整个 `db_storage` 树下全部 `*.db` 源库 → `(db 个数, 总字节)`, 供主/副号判定（ADR-407 §3.4 catalog 口径;
/// 甲用 stat 代替查休眠 catalog 表）。递归走子目录（message/contact/session/media/general/…）; `extension()=="db"`
/// 天然排除 `-wal`/`-shm`/`-journal` 伴生。目录读失败 → 返已收集的部分（best-effort; 数少=偏判主号=偏保守拦更多, 安全向）。
fn stat_account_db_catalog(db_storage: &std::path::Path) -> (usize, u64) {
    fn walk(dir: &std::path::Path, count: &mut usize, total: &mut u64) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                walk(&p, count, total);
            } else if p.extension().and_then(|s| s.to_str()) == Some("db") {
                *count += 1;
                *total += std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    let (mut count, mut total) = (0usize, 0u64);
    walk(db_storage, &mut count, &mut total);
    (count, total)
}

#[cfg(test)]
mod tests {
    use native_core::query_planner::profile::{GateOutcome, PerfProfile};

    use super::gate_decision;

    const KB: u64 = 1024; // = AVG_BYTES_PER_MSG，故 rows = bytes/KB 整除、期望值干净
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;

    /// 1 message 分片 = 50_000 rows → Tier2 10+50000/1000*100 = 5010ms；catalog 小(1 库/50MB)=主号；≥ 主号 5s 提示 → Hint。
    #[test]
    fn one_big_shard_main_hint() {
        let (ms, profile, outcome) = gate_decision(&[50_000 * KB], 1, 50_000 * KB, false);
        assert_eq!(profile, PerfProfile::Main);
        assert_eq!(ms, 5010);
        assert!(
            matches!(outcome, GateOutcome::Hint { .. }),
            "5010ms ≥ 主号 5s 提示 → Hint"
        );
    }

    /// 小库主号静默：3 个 1MB 分片 + 小 catalog → 主号，cost 远 < 5s → Silent。
    #[test]
    fn small_main_silent() {
        let (ms, profile, outcome) = gate_decision(&[MB, MB, MB], 3, 3 * MB, false);
        assert_eq!(profile, PerfProfile::Main);
        assert!(ms < 5_000, "小库估算 {ms}ms 应 < 5s");
        assert_eq!(outcome, GateOutcome::Silent);
    }

    /// 副号（catalog db 个数 ≥30）大查询：40 个 50k-row 分片 → cost=40×5010=200400ms（顺序求和）≥ 副号 30s 强制 →
    /// 无 confirm 阻断 / 有 confirm 放行。
    #[test]
    fn secondary_blocked_then_confirmed() {
        let sizes = vec![50_000 * KB; 40];
        let (ms, profile, outcome) = gate_decision(&sizes, 40, 40 * 50_000 * KB, false);
        assert_eq!(profile, PerfProfile::Secondary);
        assert_eq!(ms, 40 * 5010); // 顺序求和 = 200400
        assert!(
            matches!(outcome, GateOutcome::Blocked { .. }),
            "200400ms ≥ 副号 30s + 无 confirm → Blocked"
        );
        let (_, _, outcome2) = gate_decision(&sizes, 40, 40 * 50_000 * KB, true);
        assert!(matches!(outcome2, GateOutcome::ConfirmedProceed { .. }));
    }

    /// 总 catalog size ≥ 30GB 也判副号（即使 db 个数少）。
    #[test]
    fn big_total_size_is_secondary() {
        let (_, profile, _) = gate_decision(&[30 * GB], 1, 30 * GB, false);
        assert_eq!(profile, PerfProfile::Secondary);
    }

    /// **round-3 codex P2**: 主/副号判定用整账号 catalog、独立于 message 分片数 —— 1 个 message 分片但账号有
    /// 35 个源库 → 判副号(≥30 库)、拿更松阈值; 证明 profile 与 shard 数解耦。
    #[test]
    fn secondary_by_catalog_not_shard_count() {
        let (ms, profile, outcome) = gate_decision(&[50_000 * KB], 35, 35 * MB, false);
        assert_eq!(
            profile,
            PerfProfile::Secondary,
            "35 库 ≥ 30 → 副号(不看 message 只 1 分片)"
        );
        assert_eq!(ms, 5010);
        assert_eq!(outcome, GateOutcome::Silent, "5010ms < 副号 10s 提示阈值 → Silent");
    }

    /// 空分片 → 0 估算、主号、静默（纯逻辑边界；full_scan_cost_gate 上游对空 shards 早返 Silent）。
    #[test]
    fn empty_shards_silent() {
        let (ms, _, outcome) = gate_decision(&[], 0, 0, false);
        assert_eq!(ms, 0);
        assert_eq!(outcome, GateOutcome::Silent);
    }
}
