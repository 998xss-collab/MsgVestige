//! R17 统一底座 · L3 多写者协调 —— **通用 per-slice 写租约（方案 B 的 primitive）**。
//!
//! > **⚠️ R17 实际状态（2026-07-25 用户拍板 A，round-2 双审 codex P3 修）**：本模块是**方案 B 的 primitive，但 R17
//! > 未激活、watch 未接线**。早前按方案 B 撤了 L1 OS 锁，双审逮出撤锁破了 watch 与 ingest/build/clear/serve 的互斥
//! > (P1) → **用户拍板 A：恢复 OS 锁 + 撤锁激活整体推迟 R22**。故 R17 落地 = **保留 `acquire_watch_lock` OS 锁 + 本模块
//! > primitive 保留但 dormant**（watch 三策略不领租约、`claim/renew/release/write_conv_slice_coordinated` 全仓仅测试调用）。
//! > 下面「为什么存在 / 协作多写者 / daemon-free 共存」描述的是**方案 B 设计意图，R22 激活时才成立**；R22 接线前
//! > [`write_conv_slice_coordinated`] 还需补业务写事务内 fencing（见其文档）。
//!
//! # 为什么存在（方案 B 设计意图，R22 激活）
//! 现有 L1 写协调只有一把**进程级排他锁**（[`crate::storage::acquire_watch_lock`]，OS 独占句柄）：一个 L1
//! 同时只允许一个维护者**进程**，别的进程一律 `INDEX_LOCKED`。这挡死了 R22「边查边攒」——查询进程想把刚读
//! 的那片写回 L1，却在常驻 watch/serve 持锁时被整个挡掉。
//!
//! 方案 B（用户 2026-07-25 拍板）：**撤 L1 硬排他锁，改协作多写者**——
//! - **正确性**靠 SQLite WAL 单写者 + `busy_timeout` 串行化 commit + 叶子 `(source, source_native_id)` 幂等
//!   upsert 去重（多写者**写不坏**，最坏是重复干活）；
//! - **协调**靠本模块的**轻量咨询租约**：一个写者动手前先领它要写那片（slice）的租约；别的写者见活跃租就
//!   本轮跳过（避免俩都去物化同一片），过期/自己的可抢占。这样 watch 与查询侧写**能共存**，且查询侧写
//!   **daemon-free**（一次性 CLI 查询自己领租约写、写完释放，不需要常驻写者进程）。
//!
//! # 与 R10 块3 `work_item` 租约的关系
//! 本模块**镜像** R10 块3 已过 5 轮双审的 fencing（单语句原子认领 + `owner`/`epoch` 栅栏 + `deadline` TTL；
//! 见 `mediastore::engine::open_work_item`），但**只留通用 fencing 核心**——去掉媒体专属的状态机
//! （`done`/`failed`/`verifying`/`retry_count`）、结构化媒体列、attempt provenance。故键是**任意 slice 字符串**
//! （R17 域级 `"message"`/`"contact"`… ；R22 会话级 `"conv:<id>"`），非 media work_id。
//!
//! `work_item` 是这套 fencing 的「带状态机的富变体」；两者长远可收敛到一层，但那需重构已 DONE 的 R10，**本件
//! 不动 R10**（留作后续 follow-up）。本模块与之**同一 fencing 不变量**：epoch 每次（重）认领单调 +1 → 过期被抢的
//! 旧持租者手里的 epoch 落后账本 → 其续租/释放的 CAS 命中 0 行被拒 → **旧写者永不能覆盖现任**。
//!
//! # slice 语义（**非** water-level）
//! 租约只护「**认领→写→释放**」这段 active 写窗口，回答「此刻谁在写这片」。它**不是**采集水位
//! （`etl_state` cursor，回答「这片采到哪了」）——两者正交：租约防并发写者打架，水位管增量续抽去重。

use rusqlite::{Connection, OptionalExtension as _};

/// 写租约存活时长（**秒**，与 [`LEASE_TTL_SECS`](crate::mediastore::engine::LEASE_TTL_SECS) 同口径）。
///
/// **单位 = 秒**：所有 `now` 与 `deadline` 都用 Unix 秒（调用方传 `SystemTime…as_secs()`）；混入毫秒会让租约
/// 变几十小时、崩溃/换手恢复被长期挡死（R10 块3 双审 codex P1 栽过的坑，这里同口径避开）。
///
/// **取值 600s（10 分钟）**：须**远大于**一片的最坏单次写耗时（一批增量 pipeline 秒级），以免**活着**的写者被
/// 误判死亡而被抢；又须**有界**以限崩溃恢复延迟（崩溃时该片留活租，新写者须等其 TTL 到期才接手）。长耗时写可
/// 中途 [`renew_write_lease`] 续租免被误抢。
pub const WRITE_LEASE_TTL_SECS: i64 = 10 * 60;

/// **fencing token**：[`claim_write_lease`] 认领得到，[`renew_write_lease`]/[`release_write_lease`] 时 CAS 校验
/// `(lease_key, owner, epoch)`。epoch 每次（重）认领单调 +1 → 旧持租者（epoch 落后）的续租/释放 CAS 被拒。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceLease {
    /// 目标片键（R17 域级 `"message"`… / R22 会话级 `"conv:<id>"`）。调用方自定，本模块只当不透明字符串。
    pub lease_key: String,
    /// 持有者 = run_id（每进程/每次运行唯一；崩溃重启换 run_id 才能抢过期租，同 run_id 恒可续）。
    pub owner: String,
    /// fencing epoch（每次认领 +1；续租/释放 CAS 的核心，单调不减）。
    pub epoch: i64,
}

/// [`claim_write_lease`] 结果：认领到（带 fencing 租约）/ 被别的活写者持租（本轮不抢）。
///
/// 无 R10 那个 `AlreadyDone`——写片没有「终态」，来新数据永远可再写；故只有「认领到」与「被活跃他租挡」两种。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseClaim {
    /// 认领成功，带 [`SliceLease`]——调用方写完**必须** [`release_write_lease`]（或崩溃后靠 TTL 到期自动释放）。
    Claimed(SliceLease),
    /// 被别的写者持**未过期**租——本轮跳过（不抢不双写）。`until` = 该租到期时刻（秒；`now >= until` 后可抢占）。
    HeldByOther {
        /// 目标片键。
        lease_key: String,
        /// **持租者**的 run_id。调用方据此判"这租是不是某个已经崩掉的进程留下的" ——
        /// 崩溃残留要等满 TTL, 期间每次查询都读到半截数据(D24 审 P2)。
        owner: String,
        /// 租约到期时刻（**秒**，与 `now`/[`WRITE_LEASE_TTL_SECS`] 同口径）；仅诊断日志用，不参与算术。
        until: i64,
    },
}

/// 建 `write_lease` 协调表（每 L1 一张；`IF NOT EXISTS` 幂等）。放 L1 库内 → 所有写该 L1 的进程经同一张表协调，
/// 认领本身是单语句写、由 SQLite WAL 串行化，原子安全。
///
/// # Errors
/// 建表失败（DB 只读 / 损坏）。
pub fn init_write_lease(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS write_lease(\
           lease_key   TEXT PRIMARY KEY,\
           owner       TEXT,\
           epoch       INTEGER NOT NULL DEFAULT 0,\
           deadline    INTEGER,\
           updated_at  INTEGER NOT NULL\
         ) WITHOUT ROWID;",
    )
}

/// 认领片 `lease_key` 的写租约（**单语句原子**，`RETURNING`，无 TOCTOU 窗口）。
///
/// - 新片 → 建行 `owner=run_id, epoch=1, deadline=now+TTL`。
/// - 已存在且（**租已过期 `deadline<=now` / 无 deadline / 租是自己的 `owner=run_id`**）→ **抢占/续认领**：owner=run_id,
///   epoch **+1**, deadline 刷新。epoch 递增即 fence 掉持旧 epoch 的僵尸写者（其后续续租/释放 CAS 会命中 0 行）。
/// - 被别的写者持**未过期**租（`deadline>now && owner!=run_id`）→ [`LeaseClaim::HeldByOther`]（不抢，本轮跳过）。
///
/// `ON CONFLICT DO UPDATE … WHERE (deadline IS NULL OR deadline<=now OR owner=run)` 是 **CAS 认领闸**：一条语句内
/// 完成「读条件 + 条件写 + epoch 递增」。闸不满足（活跃他租）→ 无行更新 → `RETURNING` 空 → 分类 `HeldByOther`。
///
/// **契约警示**：对**自己仍持有、未 release** 的片再次调本函数会 `epoch+1`（闸含 `OR owner=run`）——此时旧
/// [`SliceLease`] 后续 release 会**自我 fence 掉**。调用方勿对同一在飞片重复认领。
///
/// # Errors
/// 账本写失败。
pub fn claim_write_lease(conn: &Connection, lease_key: &str, run_id: &str, now: i64) -> rusqlite::Result<LeaseClaim> {
    let deadline = now + WRITE_LEASE_TTL_SECS;
    // 单语句原子认领：新建 epoch=1 或抢占 epoch+1；活跃他租 → 闸挡 → RETURNING 空。
    let claimed_epoch: Option<i64> = conn
        .query_row(
            "INSERT INTO write_lease(lease_key, owner, epoch, deadline, updated_at) \
             VALUES(?1, ?2, 1, ?3, ?4) \
             ON CONFLICT(lease_key) DO UPDATE SET \
               owner=?2, epoch=write_lease.epoch+1, deadline=?3, updated_at=?4 \
             WHERE (write_lease.deadline IS NULL OR write_lease.deadline<=?4 OR write_lease.owner=?2) \
             RETURNING epoch",
            rusqlite::params![lease_key, run_id, deadline, now],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(epoch) = claimed_epoch {
        return Ok(LeaseClaim::Claimed(SliceLease {
            lease_key: lease_key.to_string(),
            owner: run_id.to_string(),
            epoch,
        }));
    }
    // 认领闸未过：唯一可能 = 被活跃他租持有（写片无 'done' 终态；行必存在，否则会走 INSERT 分支）。取 deadline 供诊断。
    let row: Option<(Option<i64>, String)> = conn
        .query_row(
            "SELECT deadline, COALESCE(owner,'') FROM write_lease WHERE lease_key=?1",
            [lease_key],
            |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?;
    let (until, owner) = row.map_or((None, String::new()), |(d, o)| (d, o));
    Ok(LeaseClaim::HeldByOther {
        lease_key: lease_key.to_string(),
        owner,
        until: until.unwrap_or(now),
    })
}

/// 续租：延长 `deadline`，**CAS 校验 `(lease_key, owner, epoch)` 未变**（不 bump epoch —— 同一写者保租）。长耗时
/// 写中途调，免被误判死亡而抢占。返回 `false` = 租已被抢（epoch 变 / owner 换）→ 调用方应弃写。
///
/// # Errors
/// 账本写失败。
pub fn renew_write_lease(conn: &Connection, lease: &SliceLease, now: i64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE write_lease SET deadline=?2, updated_at=?3 WHERE lease_key=?1 AND owner=?4 AND epoch=?5",
        rusqlite::params![
            lease.lease_key,
            now + WRITE_LEASE_TTL_SECS,
            now,
            lease.owner,
            lease.epoch
        ],
    )?;
    Ok(n == 1)
}

/// 释放租约（写完调）：**fenced** CAS 校验 `(lease_key, owner, epoch)` —— 过期被抢的旧写者的释放**不得** clobber
/// 现任（否则旧写者能清掉现任活跃租 → 现任被误判空闲遭抢，违「旧写者永不覆盖现任」）。清 `owner`/`deadline`
/// （保留 `epoch` 单调）→ 下一个写者即时可 `deadline IS NULL` 认领，不必空等 TTL。返回 `false` = 已失租（僵尸释放，
/// **no-op** 不动账本）。崩溃（未 release）则租留到 TTL 到期才可被抢。
///
/// # Errors
/// 账本写失败。
pub fn release_write_lease(conn: &Connection, lease: &SliceLease, now: i64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE write_lease SET owner=NULL, deadline=NULL, updated_at=?2 \
         WHERE lease_key=?1 AND owner=?3 AND epoch=?4",
        rusqlite::params![lease.lease_key, now, lease.owner, lease.epoch],
    )?;
    Ok(n == 1)
}

/// [`write_conv_slice_coordinated`] 结果: 写了(带闭包返回值)/ 被别的写者持该片活跃租而跳过。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryWriteOutcome<T> {
    /// 领到租约并跑完写闭包, 带其返回值。
    Wrote(T),
    /// 跑完了, 但**释放时发现租约已被抢占**(自己超了 TTL, 期间可能有别的写者在做同一份活)。
    ///
    /// 对幂等写者(R22 的增量采集)只意味着"可能白干了一部分", 数据仍是对的; 对非幂等写者
    /// 则说明**结果可能已被覆盖**, 调用方必须自己判断要不要重来。不吞掉这个信号。
    WroteButLost(T),
    /// 该会话片正被别的写者(常驻 watch / 另一查询)维护 → 跳过(调用方读本地已有 / 稍后重试)。
    SkippedHeld {
        /// 持租到期时刻(秒)。
        until: i64,
    },
}

/// R17 统一底座 · L2 **查询侧写触发**(方案B; R22 懒式落库入口)。查询未命中 → 领该**会话片** `"conv:{conv_id}"`
/// 租约 → 跑 `write`(R22: materialize 查询结果 + 写 L1)→ 释放。与常驻 watch **协作**: watch 持 `"messages"` 片,
/// 本入口持 `"conv:X"` 片, 不同片 SQLite 串行写不打架; **daemon-free** —— 一次性 CLI 查询自己领租约写, 无需常驻写者进程。
///
/// `write` 闭包自负实际 L1 写(经调用方的 `l1_conn`; 与本函数 claim/release 共用同一 `&Connection` 安全 —— rusqlite
/// 方法取 `&self`, 多不可变借用无碍)。被别的写者持活跃租 → [`QueryWriteOutcome::SkippedHeld`](调用方读本地已有 / 稍后重试),
/// **不双写**。写失败也先释放租约再传播错(不占租)。
///
/// **R17 只提供协调入口**; 实际"未命中判定 + materialize + 写回 L1 + 水位续传去重" = R22 懒式落库件(填 `write` 闭包)。
///
/// ## 关于事务内 fencing(codex round-1 双审 P1 的处置, R22 接线时重判)
///
/// 那条告警担心的是: 旧持租者超 TTL 被抢占后, 它的 `write()` 仍能**覆盖**新写者的状态。
/// 它成立的前提是"闭包写的是**可被覆盖的状态**"(如 mediastore 那种 `INSERT OR REPLACE` 的物化记录)。
///
/// ⚠️ **我曾判定 R22 的采集闭包不满足那个前提, 这个判定是错的**(D24 审 codex 打穿, 记在这里防止
/// 有人照着旧结论走):
///
/// 我当时的依据是"三种写全幂等"。前两条确实成立 —— 但它们只对**内容完全相同的同一条消息**成立:
/// · archive 五元组去重: 同一事件重复写 = no-op ✅
/// · 派生表按消息 delete+insert: 同一输入产出同样的行 ✅
/// · 采集游标无条件 upsert, 回退只导致多扫 ✅
///
/// **漏掉的是"同一 `local_id` 的内容会变"**: 源库的 `status` / `upload_status` / `download_status`
/// 是**可变列**(消息发送中→已送达→已读都会改它), 而 L2 主行是 `INSERT OR REPLACE`, 且这些状态
/// **不进 archive 的内容指纹**。于是可构造:
///   慢写者 A 读到 status=0 → watch/B 稍后读到 status=1 并**先**提交 → A 超 TTL 后仍能提交,
///   把 L2 写回 status=0, 而 archive 因指纹相同连第二份记录都不留。
/// **旧数据覆盖新数据, 且无痕。**
///
/// 这与 R10 媒体 CAS 的不变量("旧 epoch 在业务提交事务内被拒, 旧写者永不能提交")不一致:
/// 当前只在写完后的 release 才发现失租, 那时旧数据已经落库。
///
/// ⇒ **待办(下一件)**: 让采集的批事务在 commit 前 CAS 校验 `(lease_key, owner, epoch)`, 失租即
/// 中止该批。签名已把 [`SliceLease`] 交给闭包就是为了这个; 但 pipeline 的批事务边界在
/// `run_message_body` 内部, 要把租约透进去。在那之前, **并发写同一会话可能让消息状态列退回旧值**。
///
/// ⚠️ **但换个闭包就未必**: 若将来有调用方在这里写"最后写的赢"的状态(物化结果、汇总、任何
/// `INSERT OR REPLACE` 的非幂等行), 那条告警**照旧成立**, 必须自己在业务事务内校验 `lease`
/// (签名已把 [`SliceLease`] 交给闭包, 就是为了让它做得到)。
///
/// 另: `release` 返 `false` = 跑完才发现租约已被抢占(可能有人并发做了同一份活)。本函数**如实**
/// 把它作为 [`QueryWriteOutcome::WroteButLost`] 报出来, 不再吞掉。
///
/// # Errors
/// 租约认领 / `write` 闭包写失败。
pub fn write_conv_slice_coordinated<F, T>(
    l1_conn: &Connection,
    conv_id: &str,
    run_id: &str,
    now_secs: i64,
    write: F,
) -> rusqlite::Result<QueryWriteOutcome<T>>
where
    F: FnOnce(&SliceLease) -> rusqlite::Result<T>,
{
    let lease_key = format!("conv:{conv_id}");
    match claim_write_lease(l1_conn, &lease_key, run_id, now_secs)? {
        LeaseClaim::HeldByOther { until, .. } => Ok(QueryWriteOutcome::SkippedHeld { until }),
        LeaseClaim::Claimed(lease) => {
            let r = write(&lease);
            // 释放(命中即清); 写失败也先释放再传播错(不占租)。
            let still_ours = release_write_lease(l1_conn, &lease, now_secs)?;
            r.map(|v| {
                if still_ours {
                    QueryWriteOutcome::Wrote(v)
                } else {
                    tracing::warn!(conv_slice = %lease_key, "跑完才发现租约已被抢占(自己超了 TTL)");
                    QueryWriteOutcome::WroteButLost(v)
                }
            })
        }
    }
}

#[cfg(test)]
// `other => panic!(...)` 的兜底分支被判 match_wildcard_for_single_variants(此刻只剩一个变体)。
// 测试里这么写是**故意的**: 断言"必须是某个变体", 将来加了新变体也照样炸 —— 正是想要的行为。
#[allow(clippy::match_wildcard_for_single_variants)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_write_lease(&c).unwrap();
        c
    }

    /// 新片认领 → epoch=1。
    #[test]
    fn claim_fresh_gets_epoch_1() {
        let c = mem();
        match claim_write_lease(&c, "message", "runA", 1000).unwrap() {
            LeaseClaim::Claimed(l) => {
                assert_eq!(l.lease_key, "message");
                assert_eq!(l.owner, "runA");
                assert_eq!(l.epoch, 1);
            }
            other => panic!("期望 Claimed, 得 {other:?}"),
        }
    }

    /// 活跃他租 → HeldByOther，且 until = 原 deadline（不被抢）。
    #[test]
    fn claim_held_by_other_active() {
        let c = mem();
        let _a = claim_write_lease(&c, "message", "runA", 1000).unwrap(); // deadline=1000+600
        match claim_write_lease(&c, "message", "runB", 1100).unwrap() {
            LeaseClaim::HeldByOther { lease_key, until, .. } => {
                assert_eq!(lease_key, "message");
                assert_eq!(until, 1000 + WRITE_LEASE_TTL_SECS, "until = 现任 deadline");
            }
            other => panic!("期望 HeldByOther, 得 {other:?}"),
        }
    }

    /// 租过期 → 别的写者抢占，epoch+1。
    #[test]
    fn claim_expired_preempts_bumps_epoch() {
        let c = mem();
        let a = claim_write_lease(&c, "message", "runA", 1000).unwrap();
        let LeaseClaim::Claimed(a) = a else { panic!() };
        assert_eq!(a.epoch, 1);
        // now 跨过 deadline(1000+600=1600)：runB 抢占。
        match claim_write_lease(&c, "message", "runB", 1601).unwrap() {
            LeaseClaim::Claimed(b) => {
                assert_eq!(b.owner, "runB");
                assert_eq!(b.epoch, 2, "抢占 epoch+1");
            }
            other => panic!("期望 Claimed(抢占), 得 {other:?}"),
        }
    }

    /// 同 owner 再认领 → 续认领，epoch+1（闸含 OR owner=run）。
    #[test]
    fn claim_same_owner_reclaims_bumps_epoch() {
        let c = mem();
        let _a1 = claim_write_lease(&c, "message", "runA", 1000).unwrap();
        match claim_write_lease(&c, "message", "runA", 1100).unwrap() {
            LeaseClaim::Claimed(a2) => assert_eq!(a2.epoch, 2, "同 owner 续认领 epoch+1"),
            other => panic!("期望 Claimed, 得 {other:?}"),
        }
    }

    /// 续租：本 owner+epoch 命中延长 deadline；之后他租仍被挡到新 deadline。
    #[test]
    fn renew_extends_and_cas() {
        let c = mem();
        let LeaseClaim::Claimed(a) = claim_write_lease(&c, "message", "runA", 1000).unwrap() else {
            panic!()
        };
        assert!(renew_write_lease(&c, &a, 1500).unwrap(), "本租续租命中");
        // 续租后 deadline=1500+600=2100；t=1601（原 deadline 已过但续到 2100）→ runB 仍被挡。
        match claim_write_lease(&c, "message", "runB", 1601).unwrap() {
            LeaseClaim::HeldByOther { until, .. } => assert_eq!(until, 1500 + WRITE_LEASE_TTL_SECS),
            other => panic!("续租后应仍 HeldByOther, 得 {other:?}"),
        }
    }

    /// **fencing 回归**：过期被抢后，旧写者的续租/释放 CAS 均**被拒**（不 clobber 现任）。
    #[test]
    fn stale_owner_renew_and_release_rejected() {
        let c = mem();
        let LeaseClaim::Claimed(a) = claim_write_lease(&c, "message", "runA", 1000).unwrap() else {
            panic!()
        };
        // runB 过期抢占 → epoch=2。
        let LeaseClaim::Claimed(b) = claim_write_lease(&c, "message", "runB", 1601).unwrap() else {
            panic!()
        };
        assert_eq!(b.epoch, 2);
        // 旧 a(epoch=1) 续租/释放都 CAS 失败（僵尸 no-op）。
        assert!(!renew_write_lease(&c, &a, 1602).unwrap(), "旧持租者续租被 fence");
        assert!(!release_write_lease(&c, &a, 1602).unwrap(), "旧持租者释放被 fence");
        // 现任 b 不受影响：仍可续租 + 释放。
        assert!(renew_write_lease(&c, &b, 1603).unwrap(), "现任续租命中");
        assert!(release_write_lease(&c, &b, 1604).unwrap(), "现任释放命中");
    }

    /// 释放后立即可被下一个写者认领（deadline IS NULL 分支），epoch 继续单调。
    #[test]
    fn release_frees_for_next_claim() {
        let c = mem();
        let LeaseClaim::Claimed(a) = claim_write_lease(&c, "message", "runA", 1000).unwrap() else {
            panic!()
        };
        assert!(release_write_lease(&c, &a, 1010).unwrap());
        // 释放后（deadline=NULL）runB 立即认领，无需等 TTL；epoch 从 1 继续 → 2。
        match claim_write_lease(&c, "message", "runB", 1011).unwrap() {
            LeaseClaim::Claimed(b) => {
                assert_eq!(b.owner, "runB");
                assert_eq!(b.epoch, 2, "epoch 单调，释放不重置");
            }
            other => panic!("释放后应可认领, 得 {other:?}"),
        }
    }

    /// 不同片互不影响（并发写不同域不打架）。
    #[test]
    fn different_slices_independent() {
        let c = mem();
        let _m = claim_write_lease(&c, "message", "runA", 1000).unwrap();
        // 另一片 contact：即便 runA 持 message 租，runB 仍能领 contact。
        match claim_write_lease(&c, "contact", "runB", 1000).unwrap() {
            LeaseClaim::Claimed(l) => assert_eq!(l.lease_key, "contact"),
            other => panic!("不同片应独立可领, 得 {other:?}"),
        }
    }

    /// L2 查询侧写: 领 conv 片 → 跑写闭包 → 释放; 释放后别的写者可即领。
    #[test]
    fn query_write_claims_runs_releases() {
        let c = mem();
        let mut wrote = false;
        let out = write_conv_slice_coordinated(&c, "chat123", "queryA", 1000, |lease| {
            assert_eq!(
                lease.lease_key, "conv:chat123",
                "闭包拿得到自己的租约(供非幂等写者做事务内 CAS)"
            );
            wrote = true;
            Ok(42)
        })
        .unwrap();
        assert_eq!(out, QueryWriteOutcome::Wrote(42));
        assert!(wrote, "领到租约 → 写闭包跑了");
        // 释放后 runB 可即领 conv:chat123 (deadline IS NULL 分支)。
        match claim_write_lease(&c, "conv:chat123", "queryB", 1001).unwrap() {
            LeaseClaim::Claimed(l) => assert_eq!(l.lease_key, "conv:chat123"),
            other => panic!("释放后应可领, 得 {other:?}"),
        }
    }

    /// 跑得太久、TTL 到期被别人抢走 → 释放时发现租约已不是自己的 → 如实报 `WroteButLost`, **不吞**。
    ///
    /// 对幂等写者(R22 的会话级增量采集)这只意味着"可能白干了一部分"; 对非幂等写者则说明结果可能已被
    /// 覆盖, 必须自己决定要不要重来 —— 吞掉它就等于把这个判断权也吞了。
    #[test]
    fn query_write_reports_when_lease_was_stolen_midway() {
        let c = mem();
        let out: QueryWriteOutcome<i32> = write_conv_slice_coordinated(&c, "chat9", "slowA", 1000, |_lease| {
            // 闭包跑的过程中, 另一个写者在 TTL 之后把这片抢走了。
            let stolen = claim_write_lease(&c, "conv:chat9", "fastB", 999_999).expect("抢占");
            assert!(matches!(stolen, LeaseClaim::Claimed(_)), "超 TTL 必须能抢到");
            Ok(7)
        })
        .unwrap();
        assert_eq!(out, QueryWriteOutcome::WroteButLost(7), "跑完才发现失租, 要如实报");
    }

    /// L2 查询侧写: 该会话片正被别的写者(常驻 watch)持活跃租 → 跳过, **闭包不跑, 不双写**。
    #[test]
    fn query_write_skips_when_conv_held() {
        let c = mem();
        // watchX 先持 conv:chat123 活跃租。
        let _held = claim_write_lease(&c, "conv:chat123", "watchX", 1000).unwrap();
        let mut wrote = false;
        let out: QueryWriteOutcome<i32> = write_conv_slice_coordinated(&c, "chat123", "queryA", 1050, |_lease| {
            wrote = true;
            Ok(0)
        })
        .unwrap();
        assert!(
            matches!(out, QueryWriteOutcome::SkippedHeld { .. }),
            "被持租 → SkippedHeld"
        );
        assert!(!wrote, "被持租 → 写闭包不跑, 不双写");
    }
}
