//! 媒体内容仓引擎(R10 §11-② · §三 三层接口 discover/materialize/commit 的地基:路径布局 + 值类型)。
//!
//! 现成 `media/{voice,video,image}_export.rs` 是**批处理**:一趟 扫→解码→写扁平目录→只吐聚合计数,
//! 外层填不了逐项状态/续跑/去重(§三)。本模块把它拆成三层, 落到已冻结的 [`super::ledger`] 账本:
//! - **discover** —— 只发现不解码, 流式 + 每源游标([`super::ledger`] `source_scan`); 吐 [`DiscoveredItem`]。
//! - **materialize** —— 逐项解码/转码 → 最终字节 → sha256([`AssetId`])→ stage 到 `.staging/`; 出结构化 [`MaterializeOutcome`]。
//! - **commit** —— 一事务原子入账(asset 去重 + role/ref/variant + journal)+ 暂存挪进 by-content(见 [`StoreLayout`])。
//!
//! 本文件先落**纯部分**(路径布局 + 值类型), voice 竖切的 source/commit 随后接上。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

use super::{AssetId, MediaKind};

// ── R10块2 崩溃验收: 测试专用崩溃注入点(方案甲) ─────────────────────────────────
// thread-local(每测试线程独立→并行安全); **仅 #[cfg(test)] 存在**, release 构建 `maybe_crash` 是空 inline(零开销、
// 不进产品路径)。测试设 `set_crash_point(Some("commit_after_publish"))` → 引擎在该点 panic 模拟进程崩溃
// (unwind 会 drop 未提交的 tx = SQLite 自动回滚; publish_atomic 已挪的字节留作 orphan)。
#[cfg(test)]
thread_local! {
    static CRASH_POINT: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}
/// 设当前线程的崩溃注入点(测试用)。`None` 清除。
#[cfg(test)]
pub(crate) fn set_crash_point(p: Option<&str>) {
    CRASH_POINT.with(|c| *c.borrow_mut() = p.map(String::from));
}
/// 崩溃点检查: 匹配则崩溃。非测试构建为空 inline(无开销)。**两种崩溃模式**:
/// - 默认(方案甲, in-process): `panic!` → unwind → 未提交 tx 的 Drop → SQLite **优雅回滚**。
/// - `R10_B2_ABORT` 环境置位(方案乙, **子进程**): `process::abort()` → SIGABRT, **不 unwind、tx 不 Drop**
///   → **无** graceful rollback, 只留 WAL 未提交帧 → 测真崩溃下 SQLite WAL 恢复路径(必须在子进程, 否则杀测试 harness)。
#[inline]
fn maybe_crash(point: &str) {
    // 非 test 构建下这个参数确实没人读 —— 但**不能**靠下划线前缀来表达, 因为 test 构建下它是被用的,
    // 那样写 clippy 会报 used_underscore_binding。显式 `let _ =` 把「这里就是要丢掉它」写清楚。
    #[cfg(not(test))]
    let _ = point;
    #[cfg(test)]
    CRASH_POINT.with(|c| {
        if c.borrow().as_deref() == Some(point) {
            if std::env::var_os("R10_B2_ABORT").is_some() {
                std::process::abort(); // 乙: 真崩不 unwind → tx 不 Drop → 无 graceful 清理(测真强杀原子性)
            }
            panic!("R10块2 崩溃注入: {point}"); // 甲: unwind → tx Drop → SQLite 回滚
        }
    });
}

/// 一段逻辑媒体的**确定性 group_id**(§12-A 重建下不变; §一 MediaRef→group)。
///
/// 复审: 由 **(kind, upstream_key)** 定, **不用每消息 coords** —— 否则同一上游媒体(同 md5)出现在两条消息会得到两个组, 而
/// `asset_registry` 键 = `(kind, upstream_key)` 只能映一个组 → `MediaRef(K)` 解析到错组(串组, video/image 照搬即中招)。
/// 同上游 = 同逻辑组(多 media_reference 指它 + 其 thumb/hd/派生作多 variant)。`kind` 是受控枚举(无 `:`)故 `kind:key` 单射
/// (前缀恒为已知 kind, 反解唯一), 不会 `("voice","a:b")` 与 `("voice:a","b")` 撞。
#[must_use]
pub fn logical_group_id(item: &DiscoveredItem) -> String {
    format!("{}:{}", item.kind.as_str(), item.upstream_key)
}

/// 确定性 **work_id**(§12-C work key = account + source_identity + media 判别段 + observed_generation 的 sha256)。同一
/// (媒体位×generation)重跑得同 work_id → `work_item` UNIQUE 自然键幂等、崩溃恢复能定位同一活。用 `\x1f`(单元分隔符, 段内绝不
/// 出现)分段拼接杜绝歧义(否则 "a"+"bc" 与 "ab"+"c" 撞键)。gen 现占位 0(generation 语义 §12-C 后续)。
#[must_use]
pub fn work_id_for(account_id_sha: &str, item: &DiscoveredItem, observed_generation: i64) -> String {
    let key = format!(
        "{account_id_sha}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{observed_generation}",
        item.source_identity, item.source, item.source_native_id, item.role, item.media_seq
    );
    crate::sha256_hex(&key)
}

/// lease 存活时长(**秒**, §12-B)。worker 认领 `work_item` 后租约有效至 `now + LEASE_TTL_SECS`; 超期未完活视为 worker
/// 已死, 其租约可被别的 worker 抢占(`lease_epoch` +1)。
///
/// **单位 = 秒**(块3双审 codex P1 修): 生产 `cmd_media_ingest`(msgvestige)传 `now = SystemTime…as_secs()` = Unix **秒**,
/// 故本常量必须也是秒(旧版误用毫秒常量加到秒 `now` → 租约 ≈33 小时, 崩溃件几十小时不可恢复)。所有 `now` 与 deadline 同用秒。
///
/// **取值 600s(10 分钟)权衡**: (1) 须 **远大于最坏单项物化耗时**(SILK 解码/图片解密 ms 级; 视频 = 一次 copy+hash, 数 GB
/// 大文件在慢盘也就分钟级 → 600s 稳盖)以免**活着**的 worker 被误抢 —— 三皮 ingest **每项串行**(claim→物化→commit→finish 一轮),
/// 租只需活过单项这一轮, 故无需在物化中途 [`renew_lease`](它留给未来"单次操作本身就超 TTL"的显式长 op, 如大文件网络下载)。
/// (2) 又须**有界**以限崩溃**恢复延迟**: 崩溃时至多**一项**(串行, 在飞仅一)留活租, 新 run_id 须等其到期才接手 → 单项延迟 ≤600s,
/// 用户重跑通常远晚于此。二者兼顾。
pub const LEASE_TTL_SECS: i64 = 10 * 60;

/// **fencing token**(§12-B): 认领 [`open_work_item`] 得到, 提交 [`commit_materialized`] / 续租 [`renew_lease`] 时
/// CAS 校验 `(work_id, owner, epoch)`。语义: 每次(重)认领 `lease_epoch` 单调 **+1** → 过期被抢占的旧 worker 手里的
/// epoch 落后于账本(抢占者已 +1)→ 其提交 / 续租的 CAS **命中 0 行被拒** → **旧 worker 永不能提交**(否则双提交 /
/// 重复扣配额 / 旧字节覆盖新, §12-B)。`owner` = run_id(每进程唯一; 崩溃重启换 owner 才能抢过期租, 同 owner 恒可续)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// 目标 `work_item` 的确定性 work_id。
    pub work_id: String,
    /// 租约持有者(= run_id; 每进程 / 每次运行唯一)。
    pub owner: String,
    /// fencing epoch(每次认领 +1; 提交 / 续租 CAS 的核心, 单调不减)。
    pub epoch: i64,
}

/// [`open_work_item`] 结果:认领到(带 fencing 租约)/ 已 `done`(跳过)/ 被别的活 worker 持租(本轮不抢)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkClaim {
    /// 认领成功, 带 [`Lease`] fencing token —— 调用方 materialize 后**必须**把它传给 [`commit_materialized`] 做 CAS。
    Claimed(Lease),
    /// 该工作项上一轮已 `done` —— 跳过, 不重物化(codex P1)。
    AlreadyDone,
    /// 被别的 worker 持有**未过期**租约 —— 本轮跳过, 不抢不双做(§12-B)。`until` = 该租到期时刻(过后可被抢占)。
    HeldByOther {
        /// 目标 work_id。
        work_id: String,
        /// 租约到期时刻(**秒**, 与 [`LEASE_TTL_SECS`] / `now` 同单位); `now >= until` 后可被抢占。仅诊断日志用, 不参与算术。
        until: i64,
    },
}

/// 建/认领 `work_item` + **lease fencing**(§12-B; 崩溃恢复 / 续跑 / 防双做单元)。确定性 work_id + UNIQUE 自然键 → 同项重跑幂等。
/// media 判别段(source/native_id/role/media_seq)作结构化列存 —— 崩溃恢复从 journal.work_id 反解「这活对应哪条消息哪个媒体位」。
///
/// **认领语义**(单语句原子, `RETURNING`):
/// - 新项 → 建行 `state=claimed, owner=run_id, epoch=1, deadline=now+TTL`。
/// - 已存在且(**无租 / 租已过期(`deadline<=now`)/ 租是自己的(`owner=run_id`)**)且非 `done` → **抢占/续认领**: owner=run_id,
///   epoch **+1**, deadline 刷新。epoch 递增即 fence 掉任何持旧 epoch 的僵尸(它们的提交 CAS 会失败)。
/// - 已 `done` → [`WorkClaim::AlreadyDone`](codex P1: discover 每轮全扫, 不把已完成的活重置回 `claimed` 重物化 / 倒退成 `failed`)。
/// - 被别的 worker 持**未过期**租(`deadline>now && owner!=run_id`)→ [`WorkClaim::HeldByOther`](不抢, 本轮跳过;
///   旧 run 若已崩则等其租 TTL 到期, 由后续轮 / 后续进程接手 —— 恢复非即时是 lease 的固有代价, 见 [`LEASE_TTL_SECS`])。
///
/// `ON CONFLICT DO UPDATE ... WHERE (state!='done' AND (deadline IS NULL OR deadline<=now OR owner=run))` 是 **CAS 认领闸**:
/// 一条语句内完成「读条件 + 条件写 + epoch 递增」, **无 SELECT/INSERT 之间的 TOCTOU 窗口**。`RETURNING lease_epoch` 拿回新 epoch;
/// 闸不满足(done / 活跃他租)→ 无行更新 → RETURNING 空 → 下方 SELECT 分类为 `AlreadyDone` / `HeldByOther`。
///
/// **契约警示(块3双审 P3)**: 对**仍持有、未 finish** 的项由**同一 owner** 再次调本函数会 `epoch+1`(闸含 `OR owner=run`)——
/// 此时该 owner 手里的旧 [`Lease`](epoch 落后)后续 commit 会**自我 fence 掉**。三皮 ingest 每项处理到底(commit/fail)才进下一项,
/// 不触发; 调用方勿对同一在飞 work_id 重复认领。
///
/// # Errors
/// 账本写失败。
// ⚠️ **这条 allow 是 rustc 1.96 的 ICE 绕行, 不是嫌 lint 烦。**
//
// `cargo clippy` 在给本函数出 pedantic 警告时会让 **rustc 自己崩溃**
// (`rustc_span/lib.rs:2439` 断言 `bpos >= mbc.pos + mbc.bytes`, 字节位置→字符位置换算),
// 崩在**渲染**阶段, 所以一条警告都打不出来 —— short / json 格式一样崩。
//
// 排查记录(全是实测):
//   · 1.83 完全不崩且零警告; 1.96 与 nightly 都崩 ⇒ 不是我们的代码, 是编译器 bug, 升版本躲不掉。
//   · `-A clippy::pedantic` 不崩 / `-A clippy::all` 仍崩 ⇒ 触发者在 pedantic 组里。
//   · 按模块二分 → mediastore → engine.rs → **本函数**。
//   · 逐条试过 20 条 pedantic 都不是它; `clippy-driver -Whelp` 列不全 pedantic, 枚举这条路走不通。
//   · 把本函数体的中文全换成 ASCII **照样崩** ⇒ 与本函数里有没有多字节字符无关。
//
// 所以只能定点关掉整组, 范围压到一个函数。rustc 修了这个 bug 之后应当撤掉本条重新检查。
#[allow(clippy::pedantic)]
pub fn open_work_item(
    conn: &Connection,
    run_id: &str,
    account_id_sha: &str,
    item: &DiscoveredItem,
    observed_generation: i64,
    now: i64,
) -> Result<WorkClaim> {
    let work_id = work_id_for(account_id_sha, item, observed_generation);
    let deadline = now + LEASE_TTL_SECS;
    // 单语句原子认领(见 doc): 新建 epoch=1 或抢占 epoch+1; done / 活跃他租 → 闸挡 → RETURNING 空。
    let claimed_epoch: Option<i64> = conn
        .query_row(
            "INSERT INTO work_item(work_id,account_id_sha,source_identity,source,source_native_id,role,media_seq,\
             state,lease_owner,lease_epoch,lease_deadline,observed_generation,updated_at) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,'claimed',?8,1,?9,?10,?11) \
             ON CONFLICT(work_id) DO UPDATE SET \
               state='claimed', lease_owner=?8, lease_epoch=work_item.lease_epoch+1, lease_deadline=?9, updated_at=?11 \
             WHERE work_item.state!='done' \
               AND (work_item.lease_deadline IS NULL OR work_item.lease_deadline<=?11 OR work_item.lease_owner=?8) \
             RETURNING lease_epoch",
            rusqlite::params![
                work_id,
                account_id_sha,
                item.source_identity,
                item.source,
                item.source_native_id,
                item.role,
                item.media_seq,
                run_id,
                deadline,
                observed_generation,
                now
            ],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(epoch) = claimed_epoch {
        return Ok(WorkClaim::Claimed(Lease {
            work_id,
            owner: run_id.to_string(),
            epoch,
        }));
    }
    // 认领闸未过: 分类 —— done(跳过) 还是 被活跃他租持有(本轮不抢)。
    let row: Option<(String, Option<i64>)> = conn
        .query_row(
            "SELECT state, lease_deadline FROM work_item WHERE work_id=?1",
            [&work_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    match row {
        Some((state, _)) if state == "done" => Ok(WorkClaim::AlreadyDone),
        Some((_, until)) => Ok(WorkClaim::HeldByOther {
            work_id,
            until: until.unwrap_or(now),
        }),
        None => Ok(WorkClaim::HeldByOther { work_id, until: now }), // 不可达: 认领失败必因行存在(done / 活跃租)
    }
}

/// 续租(§12-B): 延长 `lease_deadline`, **CAS 校验 `(work_id, owner, epoch)` 未变**(不 bump epoch —— 同一 worker 保租)。
/// 长耗时物化(大视频)中途调, 免被误判死亡而抢占。返回 `false` = 租已被抢(epoch 变 / owner 换)或项已 `done` → 调用方应弃活。
///
/// # Errors
/// 账本写失败。
pub fn renew_lease(conn: &Connection, lease: &Lease, now: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE work_item SET lease_deadline=?4, updated_at=?5 \
         WHERE work_id=?1 AND lease_owner=?2 AND lease_epoch=?3 AND state!='done'",
        rusqlite::params![lease.work_id, lease.owner, lease.epoch, now + LEASE_TTL_SECS, now],
    )?;
    Ok(n == 1)
}

/// 记一次物化**尝试** provenance(§12-A `attempt`; 补第三方审 F2 —— 之前失败只 `count++` 不留「哪条/为何/可否重试」)。成功记
/// `result_asset_id`、失败记 `error_code`(二者互斥)。attempt.work_id FK→work_item, 故调前必先 [`open_work_item`]。
///
/// # Errors
/// 账本写失败(含 work_id 不存在的 FK 违约)。
pub fn record_attempt(
    conn: &Connection,
    run_id: &str,
    work_id: &str,
    result_asset_id: Option<&str>,
    error_code: Option<&str>,
    now: i64,
) -> Result<()> {
    // F2 契约(codex P2): 成功记 result_asset_id / 失败记 error_code, 二者**恰好一个**(XOR) —— 否则 (Some,Some)/(None,None)
    // 会留下恢复/审计无法分类的歧义 provenance。DDL 亦有 CHECK 硬闸, 这里提前给可读报错。
    anyhow::ensure!(
        result_asset_id.is_some() != error_code.is_some(),
        "record_attempt 契约违约: result_asset_id({result_asset_id:?}) 与 error_code({error_code:?}) 必须恰好一个",
    );
    conn.execute(
        "INSERT INTO attempt(run_id,work_id,result_asset_id,error_code,attempted_at) VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![run_id, work_id, result_asset_id, error_code, now],
    )?;
    Ok(())
}

/// 收尾 work_item 状态(`done`/`failed`/`verifying`; failed 累加 `retry_count` 供 §12-D 重试调度)+ 释放租约。
///
/// **fenced**(§12-B, 块3双审 codex P1 / 两 Claude P2): CAS 校验 `(work_id, owner, epoch)` —— **过期被抢的旧 worker 的收尾/失败
/// 写不得 clobber 现任持租者**(否则旧 worker 虽 commit 被 fence 挡下, 却能把现任的 `done` 反转成 `failed` / 清掉现任活跃租 →
/// 现任 commit 反被误 fence, 违「旧 worker 永不能提交/覆盖」不变量)。返回 `true`=命中(本 worker 仍持租, 收尾生效),
/// `false`=已失租(僵尸调用, **no-op** 不动账本)。
///
/// **释放租约**: 命中即**清 `lease_owner`/`lease_deadline`**(保留 `lease_epoch` 单调)—— 租只护「认领→提交」active 窗口;
/// 收尾后(含 `verifying`/`failed` 非终态)租立即释放, 下一轮/别的 worker 可**即时**重认领升级/重试, 不必空等 TTL。崩溃(未调
/// finish)则租留到 TTL 到期才可被抢 —— 二者共同满足「lease 不永久占用」。**成功路径**: commit_materialized 同事务刚 CAS 过同一
/// lease, 紧跟的 finish 必命中(state 变 publishing 不影响 CAS 的 owner+epoch 匹配)。
///
/// # Errors
/// 账本写失败。
pub fn finish_work(conn: &Connection, lease: &Lease, state: &str, error_code: Option<&str>, now: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE work_item SET state=?2, error_code=?3, updated_at=?4, lease_owner=NULL, lease_deadline=NULL, \
         retry_count = retry_count + CASE WHEN ?2='failed' THEN 1 ELSE 0 END \
         WHERE work_id=?1 AND lease_owner=?5 AND lease_epoch=?6",
        rusqlite::params![lease.work_id, state, error_code, now, lease.owner, lease.epoch],
    )?;
    Ok(n == 1)
}

/// 失败收尾: work→`failed`(fenced)+ `attempt`(error_code) **原子**(一事务)。修 codex P2/Claude P3 —— 原三源失败路径两条独立
/// autocommit + `let _=` 吞错, 中途崩溃/DB 错会留下 `failed` 无 attempt 或 `claimed` 却已记失败, 破坏 F2 provenance 契约。
///
/// **块3双审修**: 先 fenced [`finish_work`](CAS owner+epoch); **仅当命中(本 worker 仍持租)才记 attempt** —— 过期僵尸的失败
/// 是 no-op(不反转现任 done / 不清现任租 / 不留矛盾 provenance)。
///
/// # Errors
/// 账本写失败(调用方通常 log-warn 后续跑, 但错误不再被静默吞)。
pub fn fail_work(conn: &Connection, run_id: &str, lease: &Lease, error_code: &str, now: i64) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let applied = finish_work(conn, lease, "failed", Some(error_code), now)?;
    if applied {
        record_attempt(conn, run_id, &lease.work_id, None, Some(error_code), now)?;
    }
    tx.commit()?;
    Ok(())
}

/// 盘上文件的 sha256 是否 == 期望 asset_id(复审 P1: dedup 收养前重验, 防收养坏/截断同名文件)。读不出=不匹配。
/// 复审(第三方审 F6): **流式**算 hash(64KB 分块), 不 `fs::read` 整文件进内存 —— 视频可几百 MB, 去重重验时整读会内存尖峰。
fn on_disk_matches(path: &Path, expect: &AssetId) -> bool {
    use std::io::Read as _;

    use sha2::Digest as _;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return false, // 读到一半 IO 错 → 当不匹配(不收养)
        }
    }
    let d: [u8; 32] = hasher.finalize().into();
    AssetId::from_digest(&d) == *expect
}

/// **原子入位** staged→dest。staging 与 by-content 同在 `account_root` 下 = 同卷 → `rename` 原子。跨卷极端情形先 copy 到
/// dest 的临时兄弟再原子 rename, 保证 dest **绝不出现半写文件**(复审 P1: 旧实现 copy 直写 dest, 断电留坏文件)。
fn publish_atomic(staged: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("建 by-content 桶目录 {} 失败", parent.display()))?;
    }
    if std::fs::rename(staged, dest).is_ok() {
        return Ok(());
    }
    // rename 失败(通常跨卷): copy 到临时兄弟 → 原子 rename 顶上 → 删源。dest 只会看到完整文件。
    let tmp = dest.with_extension("copytmp");
    std::fs::copy(staged, &tmp).with_context(|| format!("拷贝到临时 {} 失败", tmp.display()))?;
    std::fs::rename(&tmp, dest).with_context(|| format!("原子 rename {} → dest 失败", tmp.display()))?;
    let _ = std::fs::remove_file(staged);
    Ok(())
}

/// [`commit_materialized`] 的结果: 字节是新落盘还是命中已有(去重)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// 这段 sha256 字节此前不在盘 → 新入位 by-content。
    Stored,
    /// 已在盘(内容寻址命中)→ 只加引用, 不重写字节(§七 在途去重)。
    Deduped,
}

/// **把一个已物化产物入账**(§四 commit 层核心: 字节入位 by-content + 一致地写账本关系)。崩溃 journal / lease(§四完整协议)
/// 与生成代 GC 语义(§12-C)留 §11-④/后续步骤; 本函数落**幂等 + 去重**的核心入账。
///
/// 时序(§四 published→accounted): **先把字节挪进 by-content**(published), **再写账本行**(accounted)。若账本写失败回滚,
/// 盘上多一个孤儿字节(可按 hash 重扫收养), 不会出现"账本有引用但字节缺失"。调用方在**同一事务**内调本函数并负责 commit/rollback。
///
/// 幂等: asset/role/registry 用 `ON CONFLICT DO NOTHING`, presence/verification/reference 用 `ON CONFLICT DO UPDATE` —— 重跑同项不产坏行。
/// 全程 **`ON CONFLICT` 不用 `INSERT OR REPLACE`**(写入契约, 见 ledger.rs; REPLACE 隐式删会丢 SET NULL 子的 provenance)。
///
/// # Errors
/// 文件挪位 / 账本写 失败。
#[allow(clippy::too_many_arguments)]
pub fn commit_materialized(
    conn: &Connection,
    account_id_sha: &str,
    layout: &StoreLayout,
    item: &DiscoveredItem,
    m: &Materialized,
    verified: bool,
    lease: &Lease,
    now: i64,
) -> Result<CommitOutcome> {
    // 0) §12-B **fencing CAS**(块3): 在挪任何字节 / 写任何账本行**之前**, 原子校验本 worker 的租约(owner+epoch)仍是账本最新。
    //    过期被抢的旧 worker 其 epoch 落后(抢占者已 +1) → 本 UPDATE 命中 0 行 → 拒绝提交(返回 Err)。调用方在同一事务内,
    //    Err 即回滚 → **一字节不挪、一行账本不写、一个引用不留**(§12-B: 旧 worker 永不能提交, 防双提交 / 重复扣配额 / 旧覆盖新)。
    //    置 state='publishing' 兼作 §四 published 相位标记(同事务内 finish_work 随即 →done/verifying, 外部观察不到中间态;
    //    若本 commit 事务回滚 / 崩溃, 随之回退 → work 仍 claimed, 与块2 恢复不变量一致)。
    // `AND state!='done'` 双保险(块3双审 P3-b): 现靠 finish_work 收尾清 owner 让"对 done 项用旧 lease 再提交"的 CAS 落空
    // (owner=NULL≠run_id), 但那耦合脆(未来任何"设 done 却不清 owner"的新写路径会静默破掉去重保护)→ 显式再挡一层。
    let fenced = conn.execute(
        "UPDATE work_item SET state='publishing', updated_at=?4 \
         WHERE work_id=?1 AND lease_owner=?2 AND lease_epoch=?3 AND state!='done'",
        rusqlite::params![lease.work_id, lease.owner, lease.epoch, now],
    )?;
    anyhow::ensure!(
        fenced == 1,
        "fencing 拒绝提交: 租约失效(work_id={} owner={} epoch={}) —— 已被抢占 / 已收尾 / 工作项不存在",
        lease.work_id,
        lease.owner,
        lease.epoch,
    );
    // 1) 字节入位 by-content(published)。复审 P1(§七"目标已存在≠成功"): 已在盘要**重算 hash 核对**, 匹配才收养,
    // 不匹配 = 上次崩溃/坏文件占了名 → 隔离后用好字节顶上(否则会把截断同名文件当好的静默入账、丢掉好副本)。
    let dest = layout.by_content(&m.asset_id);
    let outcome = if dest.exists() {
        if on_disk_matches(&dest, &m.asset_id) {
            let _ = std::fs::remove_file(&m.staged_path); // 真去重: 字节确认一致, 暂存不再需要
            CommitOutcome::Deduped
        } else {
            // 盘上是坏/截断的同名文件 → 挪进隔离(不自动删, §七), 用好字节重新原子入位。
            let q = layout.quarantine(&format!("{}.corrupt", m.asset_id.hex()));
            if let Some(parent) = q.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::rename(&dest, &q);
            publish_atomic(&m.staged_path, &dest)?;
            CommitOutcome::Stored
        }
    } else {
        publish_atomic(&m.staged_path, &dest)?;
        CommitOutcome::Stored
    };

    // R10块2 崩溃验收 C 点(最险): 字节已 published(orphan 在 by-content), ledger 行尚未写。此刻崩 → 外层 tx 回滚
    // (无半条 ledger 行, I1)+ 字节留 orphan(重启由 on_disk_matches 收养, I2)。测试在此注入; release 空 inline。
    maybe_crash("commit_after_publish");

    // 2) 账本关系(accounted)。全 ON CONFLICT, 幂等。
    let kind = item.kind.as_str();
    let group = logical_group_id(item);
    // asset: 字节事实(去重: 已有则不动)。
    conn.execute(
        "INSERT INTO asset(asset_id,hex,size,ext,mime,lifecycle,created_at) VALUES(?1,?2,?3,?4,?5,'live',?6) \
         ON CONFLICT(asset_id) DO NOTHING",
        rusqlite::params![m.asset_id.as_str(), m.asset_id.hex(), m.size, m.ext, m.mime, now],
    )?;
    // R10块2 崩溃验收(codex 复审 P1): 注入点在**已写 ≥1 条 ledger 行(asset)之后、后续行 + commit 之前**。此刻崩 →
    // 若 commit_materialized 真事务, 外层 tx 回滚会连 asset 行一起撤(I1 核心: 部分 ledger 写回滚, 非仅 orphan)。
    maybe_crash("commit_after_asset_row");
    // 在盘存在性 ready。
    conn.execute(
        "INSERT INTO asset_presence(asset_id,state,checked_at) VALUES(?1,'ready',?2) \
         ON CONFLICT(asset_id) DO UPDATE SET state='ready', checked_at=excluded.checked_at",
        rusqlite::params![m.asset_id.as_str(), now],
    )?;
    // 校验: 完整解码=verified(method=decode); 不完整=unverified 待复验。
    // 复审 P2: **不降级** —— 已 verified 的 asset 被后来一条 partial(unverified)观察到时, 保持 verified, 别覆写回 unverified。
    conn.execute(
        "INSERT INTO verification(asset_id,state,method,verified_at) VALUES(?1,?2,'decode',?3) \
         ON CONFLICT(asset_id) DO UPDATE SET \
           state = CASE WHEN verification.state='verified' THEN 'verified' ELSE excluded.state END, \
           method='decode', verified_at=excluded.verified_at",
        rusqlite::params![
            m.asset_id.as_str(),
            if verified { "verified" } else { "unverified" },
            now
        ],
    )?;
    // 角色 / 来源(多对多)。
    conn.execute(
        "INSERT INTO asset_role(asset_id,kind) VALUES(?1,?2) ON CONFLICT(asset_id,kind) DO NOTHING",
        rusqlite::params![m.asset_id.as_str(), kind],
    )?;
    conn.execute(
        "INSERT INTO asset_source(asset_id,source_ref) VALUES(?1,?2) ON CONFLICT(asset_id,source_ref) DO NOTHING",
        rusqlite::params![m.asset_id.as_str(), item.source_identity],
    )?;
    // 逻辑组(先 preferred=NULL)+ 成员边 variant。
    conn.execute(
        "INSERT INTO logical_media(logical_group_id,preferred_asset_id,created_at) VALUES(?1,NULL,?2) \
         ON CONFLICT(logical_group_id) DO NOTHING",
        rusqlite::params![group, now],
    )?;
    conn.execute(
        "INSERT INTO variant(logical_group_id,asset_id,clarity,derivation,confidence,edge_state) VALUES(?1,?2,?3,?4,1.0,'active') \
         ON CONFLICT(logical_group_id,asset_id,clarity,derivation) DO NOTHING",
        rusqlite::params![group, m.asset_id.as_str(), m.clarity, m.derivation],
    )?;
    // 指 preferred: 每次入账后**重算** —— 该组所有 active variant 按 (verified 优先 → clarity 高优先 → asset_id 稳定) 排第一。
    // 一并处理: 视频截断→完整(verified 维度, 复审 F6-P1a)、图片缩略→原图(clarity 维度, 复审 F5a)。
    // clarity 序 original(3)>hd(2)>thumb(1)>其他(0); verification 缺行(LEFT JOIN NULL, 不该发生)排最后。触发器 trg_preferred_upd
    // 校验新 preferred 是本组 active 成员 —— 子查询只从 active variant 选, 天然满足; recursive_triggers=ON 但触发器只 RAISE 不写表不级联。
    // TODO(§12-E retirement, Claude 复审 P3): 未来 GC 退役边落地后, 若某组 active variant 全退役, 子查询空 → preferred 被设 NULL 破
    // serve。那时须加 `AND EXISTS(子查询)` 守卫。今 nothing retires(edge_state='retired' 仅测试出现), 子查询恒非空, 不可达故暂不加。
    conn.execute(
        "UPDATE logical_media SET preferred_asset_id = ( \
           SELECT v.asset_id FROM variant v \
           LEFT JOIN verification vf ON vf.asset_id = v.asset_id \
           WHERE v.logical_group_id = ?1 AND v.edge_state = 'active' \
           ORDER BY (vf.state = 'verified') DESC, \
                    CASE v.clarity WHEN 'original' THEN 3 WHEN 'hd' THEN 2 WHEN 'thumb' THEN 1 ELSE 0 END DESC, \
                    v.asset_id \
           LIMIT 1 \
         ) WHERE logical_group_id = ?1",
        rusqlite::params![group],
    )?;
    // 消息锚引用(GC 主根)。generation 用 now 占位(§12-C 完整生成代语义后续)。
    conn.execute(
        "INSERT INTO media_reference(account_id_sha,source,source_native_id,role,media_seq,logical_group_id,\
         reference_generation,last_seen_generation,ref_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?7,'active') \
         ON CONFLICT(account_id_sha,source,source_native_id,role,media_seq) \
         DO UPDATE SET logical_group_id=excluded.logical_group_id, last_seen_generation=excluded.last_seen_generation, ref_state='active'",
        rusqlite::params![account_id_sha, item.source, item.source_native_id, item.role, item.media_seq, group, now],
    )?;
    // 对外 MediaRef 注册(§5c serve: /media/{kind}:{key} → group)。
    conn.execute(
        "INSERT INTO asset_registry(ref_kind,ref_key,ref_version,logical_group_id) VALUES(?1,?2,'',?3) \
         ON CONFLICT(ref_kind,ref_key,ref_version) DO NOTHING",
        rusqlite::params![kind, item.upstream_key, group],
    )?;
    Ok(outcome)
}

/// 内容仓**存储布局**(§五 唯一路径公式)。每账号一仓 `<store-root>/<账号>/`。
///
/// 关键(外审逮): 权威 CAS 路径**只用裸 hex**(非 `sha256:<hex>` —— 冒号在 Windows 非法、且前 2 位全 `sh` 分桶失效),
/// 且**不带扩展名/kind**(检测会变/歧义, ext 存账本、by-chat 视图才带)。no-replace 入位 + 换机迁移靠此当纯内容确定性函数。
#[derive(Debug, Clone)]
pub struct StoreLayout {
    /// 账号仓根 = `<store-root>/<账号编号>`。
    account_root: PathBuf,
}

impl StoreLayout {
    /// 构造某账号的仓布局。`store_root` = 多账号共享根; `account` = 账号编号(目录名)。
    #[must_use]
    pub fn new(store_root: &Path, account: &str) -> Self {
        Self {
            account_root: store_root.join(account),
        }
    }

    /// 账号仓根。
    #[must_use]
    pub fn account_root(&self) -> &Path {
        &self.account_root
    }

    /// 侧车账本路径 `<账号仓>/ledger.db`。
    #[must_use]
    pub fn ledger(&self) -> PathBuf {
        self.account_root.join("ledger.db")
    }

    /// 权威 CAS 终位 `<账号仓>/by-content/<hex前2位>/<hex>`。**入参是 [`AssetId`]**(保证 canonical 64 位小写 hex),
    /// 杜绝拿 `sha256:` 前缀或大写去拼路径。
    #[must_use]
    pub fn by_content(&self, asset: &AssetId) -> PathBuf {
        let hex = asset.hex();
        self.account_root.join("by-content").join(&hex[..2]).join(hex)
    }

    /// 暂存区 `<账号仓>/.staging/<token>.part`(同卷, 供原子 rename 入位)。`token` 由调用方给唯一值(避免 Date/rand)。
    #[must_use]
    pub fn staging(&self, token: &str) -> PathBuf {
        self.account_root.join(".staging").join(format!("{token}.part"))
    }

    /// 隔离区 `<账号仓>/.quarantine/<name>`(坏/截断文件, 不自动删, §四/§七)。
    #[must_use]
    pub fn quarantine(&self, name: &str) -> PathBuf {
        self.account_root.join(".quarantine").join(name)
    }

    /// by-chat 视图目录 `<账号仓>/by-chat`(可重建缓存, 硬链指 by-content; §五/§12-E)。
    #[must_use]
    pub fn by_chat_root(&self) -> PathBuf {
        self.account_root.join("by-chat")
    }
}

/// **discover 吐出的一个待物化媒体槽**(未解码)。判别段对齐 [`super::ledger`] `media_reference` PK + work_item 自然键。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredItem {
    /// 媒体种类。
    pub kind: MediaKind,
    /// 源 DB 身份(provenance; work_item.source_identity, §12-C work key 一段)。
    pub source_identity: String,
    /// `media_reference.source`(哪个消息源表/子源)。
    pub source: String,
    /// `media_reference.source_native_id`(源内稳定 id, 如 svr_id)。
    pub source_native_id: String,
    /// media 判别(哪个媒体位)。
    pub role: String,
    /// 多媒体消息的位序(§12-A 载重字段; 单媒体恒 0)。
    pub media_seq: i64,
    /// 上游稳定 key(md5/svr_id/locator)—— 对外 [`super::MediaRef`] 的 key 段, 存 asset_registry。
    pub upstream_key: String,
    /// 源**声明**的字节长度(视频 videomsg `length`; 复审 F6: 落盘 size < 此 = 截断。实测 25/25 == 实际文件大小, 可靠)。
    /// 无此源信息(voice/image)→ None, 靠结构 box-walk / 解码判完整。
    pub declared_size: Option<i64>,
}

/// **materialize 的结局**(§三 结构化, 不把各种失败混一锅)。
#[derive(Debug)]
pub enum MaterializeOutcome {
    /// 完整产出最终字节(已算 sha256、已写 staging)。
    Ready(Materialized),
    /// 解出但**不完整**(截断/中途坏)—— 仍产字节供预览, 但标 partial, **不当归档成功**(承接现有 BUG-2 处置)。
    Partial(Materialized),
    /// 失败(结构化原因), 不产字节。
    Failed(MaterializeFailure),
}

/// 物化成功产物(字节已 stage、sha256 已算)。
#[derive(Debug, Clone)]
pub struct Materialized {
    /// 最终字节的 `sha256:<hex>`。
    pub asset_id: AssetId,
    /// 字节数(≥0)。
    pub size: i64,
    /// 检测扩展名(可空; 不进权威路径, 存账本)。
    pub ext: Option<String>,
    /// MIME(可空)。
    pub mime: Option<String>,
    /// 清晰度档(thumb/hd/original)。
    pub clarity: String,
    /// 派生 profile(none/wav/mp3/wxgf_jpg/…)。
    pub derivation: String,
    /// `.staging/` 里的临时文件路径(commit 时原子挪进 by-content)。
    pub staged_path: PathBuf,
}

/// 物化失败的**结构化原因**(§三/§九 边界状态 → 落 source_locator.source_state / work_item.error_code)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeFailure {
    /// 坏 key / 解密失败(§九 blocked_missing_image_key 一类)。
    BadKey,
    /// 格式不识别(非目标编码 / 空 / 坏字节)。
    Unrecognized,
    /// 联网失败(联网类媒体; 持久 retry 归 work_item)。
    NetFail,
    /// 源里没有(§九 source_absent / encrypted_no_plain_cache)。
    SourceAbsent,
    /// IO / 写盘失败。
    Io(String),
    /// 解码器报错(带简述)。
    Decode(String),
}

impl MaterializeFailure {
    /// 稳定串(work_item.error_code / source_state 用)。
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::BadKey => "bad_key",
            Self::Unrecognized => "unrecognized",
            Self::NetFail => "net_fail",
            Self::SourceAbsent => "source_absent",
            Self::Io(_) => "io",
            Self::Decode(_) => "decode",
        }
    }
}

// @@GUARD:PROD_END@@  生产段到此为止; ledger.rs 的 no_replace_in_cas_writes 关卡只扫此标记之前。
#[cfg(test)]
mod tests {
    use super::*;

    fn asset_a() -> AssetId {
        AssetId::from_digest(&[0xabu8; 32])
    }

    fn digest_of(bytes: &[u8]) -> AssetId {
        use sha2::Digest as _;
        let d: [u8; 32] = sha2::Sha256::digest(bytes).as_slice().try_into().unwrap();
        AssetId::from_digest(&d)
    }

    fn voice_item(svr: &str) -> DiscoveredItem {
        DiscoveredItem {
            kind: MediaKind::Voice,
            source_identity: "media_0".into(),
            source: "message_0.db".into(),
            source_native_id: format!("Msg_ab:{svr}"),
            role: "voice".into(),
            media_seq: 0,
            upstream_key: svr.into(),
            declared_size: None,
        }
    }

    // 崩溃大件块1 地基: work_id 确定性(同项重跑同 id → work_item 幂等)+ 判别段任一变则变 + \x1f 防拼接歧义。
    #[test]
    fn work_id_deterministic_and_discriminating() {
        let item = voice_item("999");
        let a = work_id_for("acct_sha", &item, 0);
        assert_eq!(a, work_id_for("acct_sha", &item, 0), "同输入确定性");
        assert_eq!(a.len(), 64, "sha256 hex 64 位");
        assert_ne!(work_id_for("other_sha", &item, 0), a, "账号变则变");
        let mut r = item.clone();
        r.role = "thumb".into();
        assert_ne!(work_id_for("acct_sha", &r, 0), a, "role 变则变");
        assert_ne!(work_id_for("acct_sha", &item, 1), a, "generation 变则变");
        // \x1f 分段防拼接歧义: (source_identity="a", native="bc") vs ("ab","c") 不撞。
        let mut x = voice_item("1");
        x.source_identity = "a".into();
        x.source_native_id = "bc".into();
        let mut y = voice_item("1");
        y.source_identity = "ab".into();
        y.source_native_id = "c".into();
        assert_ne!(work_id_for("s", &x, 0), work_id_for("s", &y, 0), "分隔符防拼接歧义");
    }

    // 块1: work_item 生命周期 + attempt provenance(F2) —— open→claimed, 成功 attempt 记 result_asset_id+done, 失败记 error_code+failed(retry++)。
    #[test]
    fn work_item_attempt_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctW");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctW_sha", 1000).unwrap();
        let item = voice_item("777");
        // 首次认领 epoch1。
        let WorkClaim::Claimed(lease1) = open_work_item(&conn, "run-w", "acctW_sha", &item, 0, 1000).unwrap() else {
            panic!("首次 open 应认领")
        };
        let wid = lease1.work_id.clone();
        assert_eq!(wid, work_id_for("acctW_sha", &item, 0));
        assert_eq!(
            (lease1.owner.as_str(), lease1.epoch),
            ("run-w", 1),
            "块3: 首认领 owner=run_id, epoch=1"
        );
        let st: String = conn
            .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "claimed", "open → claimed");
        // ── 失败一次: attempt(error) + fenced finish(failed, lease1) → retry++、释租(返 true=现任命中)──
        //   块3: finish/fail 现 fenced, "同一 work 多次收尾"须**重认领**(不能对已 finish 行复用旧 lease 再 finish=no-op)。
        record_attempt(&conn, "run-1", &wid, None, Some("Decode"), 1000).unwrap();
        assert!(
            finish_work(&conn, &lease1, "failed", Some("Decode"), 1000).unwrap(),
            "现任 finish 命中"
        );
        let (st1, rc1): (String, i64) = conn
            .query_row(
                "SELECT state,retry_count FROM work_item WHERE work_id=?1",
                [&wid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((st1.as_str(), rc1), ("failed", 1), "failed + retry++、释租");
        // ── 重认领(failed 释租后即时可认领, epoch→2)→ 成功: asset 行 + attempt(result) + fenced finish(done) ──
        let WorkClaim::Claimed(lease2) = open_work_item(&conn, "run-w2", "acctW_sha", &item, 0, 2000).unwrap() else {
            panic!("failed 项应可重认领")
        };
        assert_eq!(lease2.epoch, 2, "重认领 epoch 单调 +1");
        let asset = digest_of(b"wav-bytes");
        conn.execute(
            "INSERT INTO asset(asset_id,hex,size,lifecycle,created_at) VALUES(?1,?2,1,'live',2000)",
            rusqlite::params![asset.as_str(), asset.hex()],
        )
        .unwrap();
        record_attempt(&conn, "run-2", &wid, Some(asset.as_str()), None, 2000).unwrap();
        assert!(
            finish_work(&conn, &lease2, "done", None, 2000).unwrap(),
            "现任 finish 命中"
        );
        let (st2, rc2): (String, i64) = conn
            .query_row(
                "SELECT state,retry_count FROM work_item WHERE work_id=?1",
                [&wid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((st2.as_str(), rc2), ("done", 1), "done(retry 不再增, 保留 failed 累计)");
        // 两次尝试(失败 error + 成功 result)都留档。
        let n_att: i64 = conn
            .query_row("SELECT COUNT(1) FROM attempt WHERE work_id=?1", [&wid], |r| r.get(0))
            .unwrap();
        assert_eq!(n_att, 2, "两次尝试(失败+成功)都留档");
        let (ra, ec): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT result_asset_id,error_code FROM attempt WHERE result_asset_id IS NOT NULL AND work_id=?1",
                [&wid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (ra.as_deref(), ec.as_deref()),
            (Some(asset.as_str()), None),
            "成功 attempt 记 result_asset_id"
        );
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // R10块2 崩溃验收(方案甲, voice 竖切, 用户 2026-07-20 拍板): C 点(publish 后、ledger 行前)崩 →
    // I1 崩溃不产半条记录(+ 字节留完整 orphan)· I2 重启续跑(认领 claimed → on_disk_matches 收养 orphan Deduped → done)·
    // I3 不重复(第三趟 done 跳过 + 无重复 asset/variant)。跨"进程"用**新 ledger 连接**(同 db 文件)模拟重启。
    #[test]
    fn crash_at_commit_recovers_i1_i2_i3() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctC2");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger_path = layout.ledger();
        let item = voice_item("crash1");
        let wid = work_id_for("acctC2_sha", &item, 0);
        let bytes = b"voice-wav-bytes-for-R10-crash-test";
        let asset = digest_of(bytes);
        // 造已 stage 的 Materialized(模拟 materialize 产物写到 .staging/)。
        let mk_m = || {
            let sp = layout.staging(&format!("crash-{}", asset.hex()));
            std::fs::create_dir_all(sp.parent().unwrap()).unwrap();
            std::fs::write(&sp, bytes).unwrap();
            Materialized {
                asset_id: asset.clone(),
                size: bytes.len() as i64,
                ext: Some("wav".into()),
                mime: Some("audio/wav".into()),
                clarity: "original".into(),
                derivation: "wav".into(),
                staged_path: sp,
            }
        };

        // ── 崩溃前: open_work_item(claimed, 拿租) + tx{ commit_materialized 在 C 点 panic } ──
        {
            let conn = super::super::ledger::open_ledger(&ledger_path, "acctC2_sha", 1000).unwrap();
            let WorkClaim::Claimed(lease) =
                open_work_item(&conn, "run-c2-crash", "acctC2_sha", &item, 0, 1000).unwrap()
            else {
                panic!("首次应认领")
            };
            let m = mk_m();
            // codex 复审 P1: 注入在 **asset 行已写之后**(非 publish 前)→ I1 的 asset-count=0 断言真验"部分 ledger 写回滚"
            // (若 commit_materialized 变非事务/asset autocommit, asset 行会残留 → 断言挂逮到)。此点在 publish 之后, 故字节亦已 orphan。
            set_crash_point(Some("commit_after_asset_row"));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let tx = conn.unchecked_transaction().unwrap();
                let _ = commit_materialized(&conn, "acctC2_sha", &layout, &item, &m, true, &lease, 1000);
                tx.commit().unwrap(); // 不可达: commit_materialized 在 asset 行后 panic
            }));
            set_crash_point(None);
            assert!(r.is_err(), "C 点应 panic 模拟崩溃");
            // conn 在此 drop = "进程结束"; 未提交 tx 已随 unwind 回滚。
        }

        // ── I1: 崩后不产半条记录 + 字节留完整 orphan ──
        {
            let conn = super::super::ledger::open_ledger(&ledger_path, "acctC2_sha", 2000).unwrap();
            let n_asset: i64 = conn
                .query_row("SELECT COUNT(1) FROM asset WHERE asset_id=?1", [asset.as_str()], |r| {
                    r.get(0)
                })
                .unwrap();
            // 注入点在 asset 行**写入之后**: 此断言真验 tx 回滚(asset 行写了又随 tx 回滚被撤; 非事务实现会残留→挂)。
            assert_eq!(n_asset, 0, "I1: 部分 ledger 写(asset 行)随 tx 回滚 → 无半条");
            let n_var: i64 = conn
                .query_row("SELECT COUNT(1) FROM variant", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n_var, 0, "I1: 无 variant 半条");
            let st: String = conn
                .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid], |r| r.get(0))
                .unwrap();
            assert_eq!(st, "claimed", "I1/I2: work 仍 claimed(finish 未提交)");
            let dest = layout.by_content(&asset);
            assert!(
                dest.exists() && on_disk_matches(&dest, &asset),
                "I1: orphan 完整字节在 by-content(可收养)"
            );
        }

        // ── I2: 重启(新连接=新进程, 新 run_id)→ 旧租过 TTL → 抢占(epoch+1)→ 收养 orphan(Deduped)→ done ──
        //   块3: 恢复**非即时** —— 新进程须等崩溃进程的租约(deadline=1000+TTL)到期才可接手其半成品(诚实建模真重启; 见 LEASE_TTL_SECS)。
        {
            let recover_now = 1000 + LEASE_TTL_SECS + 2000;
            let conn = super::super::ledger::open_ledger(&ledger_path, "acctC2_sha", recover_now).unwrap();
            let WorkClaim::Claimed(lease2) =
                open_work_item(&conn, "run-c2-restart", "acctC2_sha", &item, 0, recover_now).unwrap()
            else {
                panic!("I2: 旧租过期后应被新进程抢占续跑")
            };
            assert_eq!(
                lease2.epoch, 2,
                "I2: 抢占过期租 → epoch 递增到 2(fence 掉崩溃进程的 epoch=1)"
            );
            let m = mk_m(); // 重启从头 materialize
            let tx = conn.unchecked_transaction().unwrap();
            let outcome =
                commit_materialized(&conn, "acctC2_sha", &layout, &item, &m, true, &lease2, recover_now).unwrap();
            record_attempt(&conn, "run-c2-restart", &wid, Some(asset.as_str()), None, recover_now).unwrap();
            finish_work(&conn, &lease2, "done", None, recover_now).unwrap();
            tx.commit().unwrap();
            assert_eq!(
                outcome,
                CommitOutcome::Deduped,
                "I2: 重启收养 orphan 字节(Deduped, 不重写)"
            );
            let n_asset: i64 = conn
                .query_row("SELECT COUNT(1) FROM asset WHERE asset_id=?1", [asset.as_str()], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(n_asset, 1, "I2: 续跑后 asset 行齐");
            let st: String = conn
                .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid], |r| r.get(0))
                .unwrap();
            assert_eq!(st, "done", "I2: 续跑收尾 done");
        }

        // ── I3: 第三趟 → done 跳过 + 无重复 asset/variant ──
        {
            let after = 1000 + LEASE_TTL_SECS + 5000;
            let conn = super::super::ledger::open_ledger(&ledger_path, "acctC2_sha", after).unwrap();
            assert_eq!(
                open_work_item(&conn, "run-c2-x", "acctC2_sha", &item, 0, after).unwrap(),
                WorkClaim::AlreadyDone,
                "I3: done 项重扫跳过"
            );
            let n_asset: i64 = conn
                .query_row("SELECT COUNT(1) FROM asset WHERE asset_id=?1", [asset.as_str()], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(n_asset, 1, "I3: 无重复 asset");
            let n_var: i64 = conn
                .query_row("SELECT COUNT(1) FROM variant", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n_var, 1, "I3: 无重复 variant");
        }
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    /// re-exec 子进程的测试全名(硬编码脆 → 抽 const; 若测试重命名而此处没同步, `--exact` 匹配 0 测 → 子进程
    /// exit 0 → 父 `!success()` 断言**响亮失败**(fail-safe 非假绿)。审 P3。
    #[cfg(test)]
    const R10_B2_TEST_PATH: &str = "mediastore::engine::tests::r10_b2_real_crash_abort_durability";

    /// R10块2**乙**: **真崩溃(强杀)原子性 durability**。甲(上)用 in-process panic → unwind → **tx Drop 优雅回滚**
    /// (依赖 Rust 析构跑); 乙测**连 Rust 清理都不跑**的真崩: **子进程** `process::abort()`(SIGABRT/__fastfail,
    /// **不 unwind、tx 不 Drop、无任何 graceful 清理**)在 commit_materialized 的 `commit_after_asset_row` 点崩 →
    /// 父进程重开 ledger(=重启)→ 验崩后 ledger **原子无半条**(I1)+ 崩前已 publish 的 orphan 存活可收养 + 重启
    /// 续跑(I2 Deduped done)+ 幂等重扫(I3 AlreadyDone 不重复)。**乙相对甲的价值 = 证明"进程被强杀、Rust 析构
    /// 全不跑"时仍原子无半条**(甲靠 tx Drop 这一 Rust 机制回滚, 乙把它拿掉)。
    /// **诚实边界(审 P2, 实测坐实)**: (1) open_ledger 用 SQLite **默认回滚日志(非 WAL)**; (2) 此小事务在崩点前
    /// 未强制 spill 到盘(脏页留 page cache), 故 asset=0 的物理成因是"**未提交行从未 durable 落盘**"(cache-loss),
    /// 与"hot-journal 主动回滚"落盘态一致——**本测试不区分二者, 只断言崩后原子无半条这个结果**, 不声称走了 SQLite
    /// WAL/hot-journal 恢复路径(那需真启 WAL 或 cache_size=1 强制 spill, 见 follow-up)。子进程 re-exec 本测试
    /// (env `R10_B2_CHILD`/`R10_B2_ABORT`/`R10_B2_STORE` 触发, abort 必在子进程否则杀测试 harness)。
    #[test]
    fn r10_b2_real_crash_abort_durability() {
        // ── 子进程模式: 用父传的 store 路径跑 commit + 真崩(abort)──
        if std::env::var_os("R10_B2_CHILD").is_some() {
            assert!(
                std::env::var_os("R10_B2_ABORT").is_some(),
                "子进程须继承 R10_B2_ABORT(真崩非 panic)"
            );
            let store_root = std::path::PathBuf::from(std::env::var_os("R10_B2_STORE").expect("R10_B2_STORE 未传"));
            let layout = StoreLayout::new(&store_root, "acctB2");
            let item = voice_item("crashB2");
            let bytes = b"voice-wav-bytes-for-R10-b2-real-crash";
            let asset = digest_of(bytes);
            let sp = layout.staging(&format!("b2-{}", asset.hex()));
            std::fs::create_dir_all(sp.parent().unwrap()).unwrap();
            std::fs::write(&sp, bytes).unwrap();
            let m = Materialized {
                asset_id: asset.clone(),
                size: bytes.len() as i64,
                ext: Some("wav".into()),
                mime: Some("audio/wav".into()),
                clarity: "original".into(),
                derivation: "wav".into(),
                staged_path: sp,
            };
            let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctB2_sha", 1000).unwrap();
            let WorkClaim::Claimed(lease) =
                open_work_item(&conn, "run-b2-crash", "acctB2_sha", &item, 0, 1000).unwrap()
            else {
                panic!("子进程首次应认领")
            };
            set_crash_point(Some("commit_after_asset_row"));
            let tx = conn.unchecked_transaction().unwrap();
            let _ = commit_materialized(&conn, "acctB2_sha", &layout, &item, &m, true, &lease, 1000); // ← 内部 abort
            tx.commit().unwrap(); // 不可达
            std::process::exit(2); // 不可达: 到这=没在注入点崩 → 父断言逮
        }

        // ── 父进程 ──
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path().join("store");
        let layout = StoreLayout::new(&store_root, "acctB2");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let item = voice_item("crashB2");
        let bytes = b"voice-wav-bytes-for-R10-b2-real-crash";
        let asset = digest_of(bytes);
        let wid = work_id_for("acctB2_sha", &item, 0);

        // 起子进程真崩(re-exec 本测试 + env)。
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", R10_B2_TEST_PATH, "--nocapture"])
            .env("R10_B2_CHILD", "1")
            .env("R10_B2_ABORT", "1")
            .env("R10_B2_STORE", &store_root)
            .status()
            .expect("起子进程失败");
        // **正向断言死于 abort**(审 P2-2: 堵假绿向量A —— 否则 abort 接线退化成 panic-unwind 会 Drop tx 优雅回滚
        // = 甲路径, 而 `!success()` 照样通过 → 静默退回甲测不到真崩)。abort 退出码平台专属:
        //   - Windows: Rust `process::abort()` 走 `__fastfail(7)` → 0xC0000409(STATUS_STACK_BUFFER_OVERRUN),
        //     ExitStatus.code() = 0xC0000409 as i32 = -1073740791; panic-unwind 则 code=101, 二者可区分。
        //   - unix: SIGABRT(signal 6); panic-unwind 无信号(正常退出 101)。
        assert_ne!(
            status.code(),
            Some(2),
            "子进程走到 exit(2) = commit_materialized 未在注入点崩 = 测试前提失效"
        );
        #[cfg(windows)]
        assert_eq!(
            status.code(),
            Some(0xC000_0409_u32 as i32),
            "Windows: 子进程须**死于 abort(__fastfail 0xC0000409)**非 panic(101)/正常退出, 实得 {status:?}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(6),
                "unix: 子进程须**死于 SIGABRT(signal 6)**非 panic-unwind, 实得 {status:?}"
            );
        }

        // ── I1: 真崩(**无 tx Drop、无任何 Rust 清理**)后重开 → ledger **原子无半条**(未提交 asset/variant 行不可见)
        //   + 崩前已 publish 的 orphan 字节存活。**成因诚实**(见 docstring): asset=0 因未提交小事务从未 durable
        //   落盘(非 hot-journal 主动回滚); 关键点是"连 Rust 析构都不跑的真强杀"下 ledger 仍原子无半条 ──
        {
            let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctB2_sha", 2000).unwrap();
            let n_asset: i64 = conn
                .query_row("SELECT COUNT(1) FROM asset WHERE asset_id=?1", [asset.as_str()], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(
                n_asset, 0,
                "I1: 真强杀(无 Rust 清理)后未提交 asset 行不可见 → 原子无半条"
            );
            let n_var: i64 = conn
                .query_row("SELECT COUNT(1) FROM variant", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n_var, 0, "I1: 无 variant 半条");
            let st: String = conn
                .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid], |r| r.get(0))
                .unwrap();
            assert_eq!(st, "claimed", "I1/I2: work 仍 claimed(finish 未提交)");
            let dest = layout.by_content(&asset);
            assert!(
                dest.exists() && on_disk_matches(&dest, &asset),
                "I1: abort 前已 publish 的 orphan 字节完整在 by-content(可收养)"
            );
        }
        // ── I2: 重启(新 run_id)→ 旧租过 TTL → 抢占(epoch+1)→ 收养 orphan(Deduped)→ done ──
        {
            let recover_now = 1000 + LEASE_TTL_SECS + 2000;
            let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctB2_sha", recover_now).unwrap();
            let WorkClaim::Claimed(lease2) =
                open_work_item(&conn, "run-b2-restart", "acctB2_sha", &item, 0, recover_now).unwrap()
            else {
                panic!("I2: 旧租过期后应被新进程抢占续跑")
            };
            assert_eq!(
                lease2.epoch, 2,
                "I2: 抢占过期租 → epoch 递增到 2(fence 掉崩溃子进程的 epoch=1)"
            );
            let sp = layout.staging(&format!("b2r-{}", asset.hex()));
            std::fs::create_dir_all(sp.parent().unwrap()).unwrap();
            std::fs::write(&sp, bytes).unwrap();
            let m = Materialized {
                asset_id: asset.clone(),
                size: bytes.len() as i64,
                ext: Some("wav".into()),
                mime: Some("audio/wav".into()),
                clarity: "original".into(),
                derivation: "wav".into(),
                staged_path: sp,
            };
            let tx = conn.unchecked_transaction().unwrap();
            let outcome =
                commit_materialized(&conn, "acctB2_sha", &layout, &item, &m, true, &lease2, recover_now).unwrap();
            record_attempt(&conn, "run-b2-restart", &wid, Some(asset.as_str()), None, recover_now).unwrap();
            finish_work(&conn, &lease2, "done", None, recover_now).unwrap();
            tx.commit().unwrap();
            assert_eq!(
                outcome,
                CommitOutcome::Deduped,
                "I2: 重启收养 orphan 字节(Deduped, 不重写)"
            );
            let n_asset: i64 = conn
                .query_row("SELECT COUNT(1) FROM asset WHERE asset_id=?1", [asset.as_str()], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(n_asset, 1, "I2: 续跑后 asset 行齐");
            // 审 P3: 补 variant=1(甲 I2 验了)—— 防"续跑只写 asset 提前返回、漏 variant 却标 done"的假绿。
            let n_var: i64 = conn
                .query_row("SELECT COUNT(1) FROM variant", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n_var, 1, "I2: 续跑后 variant 行齐(非只写 asset)");
        }
        // ── I3: 三趟 → AlreadyDone 跳过 + 无重复 ──
        {
            let after = 1000 + LEASE_TTL_SECS + 5000;
            let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctB2_sha", after).unwrap();
            assert_eq!(
                open_work_item(&conn, "run-b2-x", "acctB2_sha", &item, 0, after).unwrap(),
                WorkClaim::AlreadyDone,
                "I3: done 项重扫跳过"
            );
            let n_asset: i64 = conn
                .query_row("SELECT COUNT(1) FROM asset WHERE asset_id=?1", [asset.as_str()], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(n_asset, 1, "I3: 无重复 asset");
        }
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // R10块2 崩溃验收 A/B 点(materialize 前/中崩, 无字节 published): 崩后 work claimed + by-content 无字节(无 orphan)
    // → 重启从头 materialize + commit → **Stored**(新字节, 非 Deduped)→ done。与 C 点(有 orphan → Deduped)对照。
    #[test]
    fn crash_before_publish_recovers_stored() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctAB");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger_path = layout.ledger();
        let item = voice_item("crashAB");
        let wid = work_id_for("acctAB_sha", &item, 0);
        let bytes = b"another-voice-bytes-AB";
        let asset = digest_of(bytes);
        // 崩溃前: 只 open_work_item(claimed); materialize/commit 未跑(模拟 A/B 点崩)。
        {
            let conn = super::super::ledger::open_ledger(&ledger_path, "acctAB_sha", 1000).unwrap();
            let WorkClaim::Claimed(_) = open_work_item(&conn, "run-ab-crash", "acctAB_sha", &item, 0, 1000).unwrap()
            else {
                panic!("首次应认领")
            };
            // conn drop = 崩溃; 无字节 published、无 ledger 关系行。
        }
        // I1: 无 asset + by-content 无字节(无 orphan)+ work claimed。
        {
            let conn = super::super::ledger::open_ledger(&ledger_path, "acctAB_sha", 2000).unwrap();
            let n_asset: i64 = conn
                .query_row("SELECT COUNT(1) FROM asset WHERE asset_id=?1", [asset.as_str()], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(n_asset, 0, "I1: A/B 点崩无 asset");
            assert!(
                !layout.by_content(&asset).exists(),
                "A/B 点崩无字节 published(无 orphan)"
            );
            let st: String = conn
                .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid], |r| r.get(0))
                .unwrap();
            assert_eq!(st, "claimed", "I1/I2: work 仍 claimed");
        }
        // I2: 重启(新 run_id, 旧租过 TTL)→ 抢占 → materialize + commit → Stored(新字节, 无 orphan 可收养)→ done。
        {
            let recover_now = 1000 + LEASE_TTL_SECS + 2000;
            let conn = super::super::ledger::open_ledger(&ledger_path, "acctAB_sha", recover_now).unwrap();
            let WorkClaim::Claimed(lease2) =
                open_work_item(&conn, "run-ab-restart", "acctAB_sha", &item, 0, recover_now).unwrap()
            else {
                panic!("I2: 旧租过期后应被新进程抢占认领")
            };
            let sp = layout.staging(&format!("ab-{}", asset.hex()));
            std::fs::create_dir_all(sp.parent().unwrap()).unwrap();
            std::fs::write(&sp, bytes).unwrap();
            let m = Materialized {
                asset_id: asset.clone(),
                size: bytes.len() as i64,
                ext: Some("wav".into()),
                mime: None,
                clarity: "original".into(),
                derivation: "wav".into(),
                staged_path: sp,
            };
            let tx = conn.unchecked_transaction().unwrap();
            let outcome =
                commit_materialized(&conn, "acctAB_sha", &layout, &item, &m, true, &lease2, recover_now).unwrap();
            record_attempt(&conn, "run-ab-restart", &wid, Some(asset.as_str()), None, recover_now).unwrap();
            finish_work(&conn, &lease2, "done", None, recover_now).unwrap();
            tx.commit().unwrap();
            assert_eq!(
                outcome,
                CommitOutcome::Stored,
                "I2: A/B 点重启无 orphan → 新字节 Stored"
            );
            let st: String = conn
                .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid], |r| r.get(0))
                .unwrap();
            assert_eq!(st, "done", "I2: 续跑收尾 done");
        }
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // 块1 双审(codex P1): 已 `done` 的 work 重扫 → AlreadyDone(不重认领, 防重复物化 + 源暂缺时把成功倒退成 failed); `failed` 可重认领(重试)。
    #[test]
    fn open_work_item_skips_done_reclaims_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctD");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctD_sha", 1000).unwrap();
        // done 项: 重 open → AlreadyDone, state 仍 done。
        let done_item = voice_item("555");
        let WorkClaim::Claimed(lease) = open_work_item(&conn, "run-d", "acctD_sha", &done_item, 0, 1000).unwrap()
        else {
            panic!("首次应认领")
        };
        let wid = lease.work_id.clone();
        finish_work(&conn, &lease, "done", None, 1000).unwrap();
        assert_eq!(
            open_work_item(&conn, "run-d2", "acctD_sha", &done_item, 0, 2000).unwrap(),
            WorkClaim::AlreadyDone
        );
        let st: String = conn
            .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "done", "已 done 不被重认领重置(codex P1)");
        // failed 项: 重 open → Claimed(可重试), state 回 claimed。块3: finish(failed) 已清租, 故新 owner 在 TTL 内也能即时重认领。
        let fail_item = voice_item("556");
        let WorkClaim::Claimed(lease2) = open_work_item(&conn, "run-d", "acctD_sha", &fail_item, 0, 1000).unwrap()
        else {
            panic!("首次应认领")
        };
        let wid2 = lease2.work_id.clone();
        finish_work(&conn, &lease2, "failed", Some("x"), 1000).unwrap();
        let WorkClaim::Claimed(lease3) = open_work_item(&conn, "run-d3", "acctD_sha", &fail_item, 0, 3000).unwrap()
        else {
            panic!("failed 可重认领重试")
        };
        assert_eq!(lease3.epoch, 2, "块3: failed 清租后重认领 → epoch 递增到 2(单调)");
        let st2: String = conn
            .query_row("SELECT state FROM work_item WHERE work_id=?1", [&wid2], |r| r.get(0))
            .unwrap();
        assert_eq!(st2, "claimed", "failed 重认领 → claimed");
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // ── 块3(§12-B lease fencing) ────────────────────────────────────────────────────────────────
    // 核心性质: **过期被抢的旧 worker 永不能提交**。A 认领(epoch1)→ A 租过 TTL → B 抢占(epoch2)→ A 拿 epoch1 提交被
    // CAS 拒(Err, 一行账本/一字节都不落, 因 fencing 在挪字节前)→ B 拿 epoch2 提交成功。防双提交 / 重复扣配额 / 旧覆盖新。
    #[test]
    fn lease_fencing_stale_worker_cannot_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctFence");
        std::fs::create_dir_all(layout.account_root().join(".staging")).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctFence_sha", 1000).unwrap();
        let item = voice_item("fence1");
        let bytes = b"fence-wav-bytes-for-block3";
        let asset = digest_of(bytes);
        let mk_m = || {
            let sp = layout.staging(&format!("fence-{}", asset.hex()));
            std::fs::create_dir_all(sp.parent().unwrap()).unwrap();
            std::fs::write(&sp, bytes).unwrap();
            Materialized {
                asset_id: asset.clone(),
                size: bytes.len() as i64,
                ext: Some("wav".into()),
                mime: None,
                clarity: "original".into(),
                derivation: "wav".into(),
                staged_path: sp,
            }
        };
        // A 认领 epoch1。
        let WorkClaim::Claimed(lease_a) = open_work_item(&conn, "run-A", "acctFence_sha", &item, 0, 1000).unwrap()
        else {
            panic!("A 应认领")
        };
        assert_eq!((lease_a.owner.as_str(), lease_a.epoch), ("run-A", 1));
        // A 租过 TTL → B 抢占 epoch2。
        let steal_now = 1000 + LEASE_TTL_SECS + 1;
        let WorkClaim::Claimed(lease_b) = open_work_item(&conn, "run-B", "acctFence_sha", &item, 0, steal_now).unwrap()
        else {
            panic!("B 应抢占过期租")
        };
        assert_eq!(
            (lease_b.owner.as_str(), lease_b.epoch),
            ("run-B", 2),
            "抢占 → owner=B, epoch+1"
        );
        // A 拿 stale epoch1 提交 → fencing 拒(Err)。tx 未 commit → 回滚, 零行零字节。
        {
            let tx = conn.unchecked_transaction().unwrap();
            let a_res = commit_materialized(
                &conn,
                "acctFence_sha",
                &layout,
                &item,
                &mk_m(),
                true,
                &lease_a,
                steal_now + 1,
            );
            assert!(a_res.is_err(), "块3: 过期旧 worker A(epoch1)提交被 fencing 拒");
            drop(tx); // 未 commit → 回滚
        }
        let n_asset_after_a: i64 = conn.query_row("SELECT COUNT(1) FROM asset", [], |r| r.get(0)).unwrap();
        assert_eq!(n_asset_after_a, 0, "块3: A 被拒后账本零行(无半条)");
        assert!(
            !layout.by_content(&asset).exists(),
            "块3: fencing 在挪字节前 → A 一字节未落"
        );
        // B 拿 epoch2 提交成功。
        {
            let tx = conn.unchecked_transaction().unwrap();
            let b_out = commit_materialized(
                &conn,
                "acctFence_sha",
                &layout,
                &item,
                &mk_m(),
                true,
                &lease_b,
                steal_now + 2,
            )
            .unwrap();
            finish_work(&conn, &lease_b, "done", None, steal_now + 2).unwrap();
            tx.commit().unwrap();
            assert_eq!(b_out, CommitOutcome::Stored, "块3: 现任 worker B(epoch2)提交成功");
        }
        let n_asset: i64 = conn.query_row("SELECT COUNT(1) FROM asset", [], |r| r.get(0)).unwrap();
        assert_eq!(n_asset, 1, "块3: 仅 B 一次入账(无双提交)");
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // 块3: 活跃(未过期)租不可被别的 worker 抢 —— B 在 A 租到期前认领 → HeldByOther(until=A 的 deadline); 到期后 → 抢占成功。
    #[test]
    fn lease_live_not_stealable_until_expiry() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctLive");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctLive_sha", 1000).unwrap();
        let item = voice_item("live1");
        let WorkClaim::Claimed(lease_a) = open_work_item(&conn, "run-A", "acctLive_sha", &item, 0, 1000).unwrap()
        else {
            panic!("A 应认领")
        };
        // B 在 TTL 内认领 → HeldByOther(until = A 的 deadline)。
        let mid = 1000 + LEASE_TTL_SECS / 2;
        match open_work_item(&conn, "run-B", "acctLive_sha", &item, 0, mid).unwrap() {
            WorkClaim::HeldByOther { until, .. } => assert_eq!(until, 1000 + LEASE_TTL_SECS, "until = A 的租到期时刻"),
            other => panic!("活跃租应 HeldByOther, 实得 {other:?}"),
        }
        // B 的失败认领**未动** A 的租(owner/epoch 不变)。
        assert_eq!(lease_a.epoch, 1);
        let (owner, epoch): (Option<String>, i64) = conn
            .query_row(
                "SELECT lease_owner, lease_epoch FROM work_item WHERE work_id=?1",
                [&lease_a.work_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((owner.as_deref(), epoch), (Some("run-A"), 1), "B 的失败认领未动 A 的租");
        // 过期后 B 抢占成功(epoch2)。
        let after = 1000 + LEASE_TTL_SECS + 1;
        let WorkClaim::Claimed(lease_b) = open_work_item(&conn, "run-B", "acctLive_sha", &item, 0, after).unwrap()
        else {
            panic!("过期后 B 应抢占")
        };
        assert_eq!((lease_b.owner.as_str(), lease_b.epoch), ("run-B", 2));
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // 块3: renew_lease 延 deadline + CAS 保护 —— 同 owner+epoch 续租成功(护住不被抢); 被抢后旧 lease 续租返回 false。
    #[test]
    fn renew_lease_extends_and_fails_after_steal() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctRenew");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctRenew_sha", 1000).unwrap();
        let item = voice_item("renew1");
        let WorkClaim::Claimed(lease_a) = open_work_item(&conn, "run-A", "acctRenew_sha", &item, 0, 1000).unwrap()
        else {
            panic!("A 应认领")
        };
        // 快到期时续租 → deadline 推到 renew_now+TTL, 返回 true。
        let renew_now = 1000 + LEASE_TTL_SECS - 10;
        assert!(
            renew_lease(&conn, &lease_a, renew_now).unwrap(),
            "同 owner+epoch 续租成功"
        );
        let deadline: i64 = conn
            .query_row(
                "SELECT lease_deadline FROM work_item WHERE work_id=?1",
                [&lease_a.work_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            deadline,
            renew_now + LEASE_TTL_SECS,
            "续租把 deadline 推到 renew_now+TTL"
        );
        // 因续租, 原到期点后 B 仍抢不到(deadline 已推后)。
        let orig_expiry = 1000 + LEASE_TTL_SECS + 5;
        assert!(
            matches!(
                open_work_item(&conn, "run-B", "acctRenew_sha", &item, 0, orig_expiry).unwrap(),
                WorkClaim::HeldByOther { .. }
            ),
            "续租后原到期点 B 仍抢不到"
        );
        // 推进到**新**到期点后 B 抢占(epoch2)。
        let new_expiry = renew_now + LEASE_TTL_SECS + 1;
        let WorkClaim::Claimed(lease_b) =
            open_work_item(&conn, "run-B", "acctRenew_sha", &item, 0, new_expiry).unwrap()
        else {
            panic!("新到期后 B 应抢占")
        };
        assert_eq!(lease_b.epoch, 2);
        // A 被抢后再续租 → CAS 失败(epoch 已变)→ false。
        assert!(
            !renew_lease(&conn, &lease_a, new_expiry + 1).unwrap(),
            "块3: 被抢后旧 lease(epoch1)续租失败"
        );
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // 块3: finish_work 释放租 —— verifying(非终态)收尾即清租, 别的 worker 在 TTL 内也能**即时**重认领升级(不空等 TTL)。
    #[test]
    fn finish_releases_lease_for_immediate_reclaim() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctRel");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctRel_sha", 1000).unwrap();
        let item = voice_item("rel1");
        let WorkClaim::Claimed(lease_a) = open_work_item(&conn, "run-A", "acctRel_sha", &item, 0, 1000).unwrap() else {
            panic!("A 应认领")
        };
        // A 收尾 verifying(截断视频待升级场景)→ 清租。
        finish_work(&conn, &lease_a, "verifying", None, 1100).unwrap();
        let (owner, deadline): (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT lease_owner, lease_deadline FROM work_item WHERE work_id=?1",
                [&lease_a.work_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((owner, deadline), (None, None), "块3: finish 清 lease_owner/deadline");
        // B 在 TTL 内(1200 << 1000+TTL)即时重认领 → Claimed(非 HeldByOther), epoch 单调 +1。
        let WorkClaim::Claimed(lease_b) = open_work_item(&conn, "run-B", "acctRel_sha", &item, 0, 1200).unwrap() else {
            panic!("块3: 清租后应即时重认领(不空等 TTL)")
        };
        assert_eq!(
            (lease_b.owner.as_str(), lease_b.epoch),
            ("run-B", 2),
            "重认领 → owner=B, epoch 单调+1"
        );
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // ⭐块3双审回归(codex P1 / 两 Claude P2, 三路真跑坐实的两条破坏时间线守卫): fencing 的**对称性** —— 过期被抢的旧 worker
    // 的 fail_work/finish **不得** clobber 现任持租者(既不能踢掉现任 live 租, 也不能把现任 done 反转成 failed)。修前 finish/fail
    // 只 `WHERE work_id` 无 CAS, 僵尸能破坏; 修后 finish/fail CAS(owner+epoch), 失租僵尸 no-op。
    #[test]
    fn lease_stale_finish_fail_cannot_clobber_current_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctZombie");
        std::fs::create_dir_all(layout.account_root().join(".staging")).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctZombie_sha", 1000).unwrap();
        let item = voice_item("zombie1");
        let bytes = b"zombie-regression-wav-block3";
        let asset = digest_of(bytes);
        let mk_m = || {
            let sp = layout.staging(&format!("z-{}", asset.hex()));
            std::fs::create_dir_all(sp.parent().unwrap()).unwrap();
            std::fs::write(&sp, bytes).unwrap();
            Materialized {
                asset_id: asset.clone(),
                size: bytes.len() as i64,
                ext: Some("wav".into()),
                mime: None,
                clarity: "original".into(),
                derivation: "wav".into(),
                staged_path: sp,
            }
        };
        // A 认领 ep1 → A 租过 TTL → B 抢占 ep2(现任 live, claimed)。
        let WorkClaim::Claimed(lease_a) = open_work_item(&conn, "run-A", "acctZombie_sha", &item, 0, 1000).unwrap()
        else {
            panic!("A 应认领")
        };
        let steal = 1000 + LEASE_TTL_SECS + 1;
        let WorkClaim::Claimed(lease_b) = open_work_item(&conn, "run-B", "acctZombie_sha", &item, 0, steal).unwrap()
        else {
            panic!("B 应抢占过期租")
        };
        assert_eq!(lease_b.epoch, 2);
        // ── 时间线 Y(踢现任 live): A(僵尸 ep1)fail_work → **不得**清 B 的 live 租 / 不改 state ──
        fail_work(&conn, "run-A", &lease_a, "materialize_error", steal + 1).unwrap();
        let (owner, epoch, st): (Option<String>, i64, String) = conn
            .query_row(
                "SELECT lease_owner, lease_epoch, state FROM work_item WHERE work_id=?1",
                [&lease_b.work_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (owner.as_deref(), epoch, st.as_str()),
            (Some("run-B"), 2, "claimed"),
            "块3回归Y: 僵尸 fail 不动现任 B 的 live 租/state"
        );
        let n_att: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM attempt WHERE work_id=?1",
                [&lease_b.work_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_att, 0, "块3回归: 僵尸失败(finish 未命中)不留矛盾 provenance");
        // B(现任)仍能 commit + finish done(未被踢)。
        {
            let tx = conn.unchecked_transaction().unwrap();
            let o = commit_materialized(
                &conn,
                "acctZombie_sha",
                &layout,
                &item,
                &mk_m(),
                true,
                &lease_b,
                steal + 2,
            )
            .unwrap();
            assert!(
                finish_work(&conn, &lease_b, "done", None, steal + 2).unwrap(),
                "B 现任 finish 命中"
            );
            tx.commit().unwrap();
            assert_eq!(o, CommitOutcome::Stored, "块3回归Y: B 现任未被僵尸踢, commit 成功");
        }
        // ── 时间线 X(反转 done): 已 done 后 A(僵尸)再 fail_work → **不得**把 done 反转成 failed / 不加 retry ──
        fail_work(&conn, "run-A", &lease_a, "commit_error", steal + 3).unwrap();
        let (st2, rc2): (String, i64) = conn
            .query_row(
                "SELECT state, retry_count FROM work_item WHERE work_id=?1",
                [&lease_b.work_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (st2.as_str(), rc2),
            ("done", 0),
            "块3回归X: 僵尸 fail 不反转现任 done / 不加 retry"
        );
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // 块1 双审(codex P2): record_attempt 的 result_asset_id/error_code 必须**恰好一个**(XOR); (None,None)/(Some,Some) 被 ensure 拒、不落库。
    #[test]
    fn record_attempt_rejects_ambiguous_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctX");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctX_sha", 1000).unwrap();
        let item = voice_item("333");
        let WorkClaim::Claimed(lease) = open_work_item(&conn, "run-x", "acctX_sha", &item, 0, 1000).unwrap() else {
            panic!("应认领")
        };
        let wid = lease.work_id.clone();
        assert!(
            record_attempt(&conn, "r", &wid, None, None, 1000).is_err(),
            "(None,None) 应拒"
        );
        assert!(
            record_attempt(&conn, "r", &wid, Some("sha256:aa"), Some("e"), 1000).is_err(),
            "(Some,Some) 应拒"
        );
        let n: i64 = conn
            .query_row("SELECT COUNT(1) FROM attempt WHERE work_id=?1", [&wid], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "歧义 attempt 一条都不落库");
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // 块1 复审二轮(codex P1): attempt CHECK 只禁 (Some,Some), **容许 GC SET NULL 后的 (None,None)** —— 否则成功 attempt
    // 令被引用 asset 删不掉(硬 GC root, 违 attempt 非-root 契约)。写入侧严格 XOR 仍由 record_attempt 的 ensure 保证。
    #[test]
    fn attempt_check_allows_gc_setnull_blocks_double() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctC");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctC_sha", 1000).unwrap();
        let item = voice_item("111");
        let WorkClaim::Claimed(lease) = open_work_item(&conn, "run-c", "acctC_sha", &item, 0, 1000).unwrap() else {
            panic!("应认领")
        };
        let wid = lease.work_id.clone();
        let asset = digest_of(b"gc-bytes");
        conn.execute(
            "INSERT INTO asset(asset_id,hex,size,lifecycle,created_at) VALUES(?1,?2,1,'live',1000)",
            rusqlite::params![asset.as_str(), asset.hex()],
        )
        .unwrap();
        record_attempt(&conn, "r", &wid, Some(asset.as_str()), None, 1000).unwrap();
        // 模拟 GC 的 ON DELETE SET NULL: result_asset_id → NULL, 得 (None,None); 新 CHECK 应放行(旧严格 XOR 会拒)。
        conn.execute("UPDATE attempt SET result_asset_id=NULL WHERE work_id=?1", [&wid])
            .unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(1) FROM attempt WHERE work_id=?1 AND result_asset_id IS NULL AND error_code IS NULL",
                [&wid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "GC SET NULL 后 (None,None) 被 CHECK 放行(不挡回收)");
        // 直接 SQL 绕过 ensure 插 (Some,Some) —— 存储层 CHECK 仍拒。
        let bad = conn.execute(
            "INSERT INTO attempt(run_id,work_id,result_asset_id,error_code,attempted_at) VALUES('r',?1,?2,'e',1000)",
            rusqlite::params![&wid, asset.as_str()],
        );
        assert!(bad.is_err(), "(Some,Some) 仍被 CHECK 拒");
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    // 块1 双审(codex P2/Claude P3): fail_work 一事务原子 → attempt(error_code) + work failed + retry++, 不再两条独立 autocommit 吞错。
    #[test]
    fn fail_work_atomic_records_attempt_and_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctF");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctF_sha", 1000).unwrap();
        let item = voice_item("222");
        let WorkClaim::Claimed(lease) = open_work_item(&conn, "run-f0", "acctF_sha", &item, 0, 1000).unwrap() else {
            panic!("应认领")
        };
        let wid = lease.work_id.clone();
        fail_work(&conn, "run-f", &lease, "materialize_error", 1000).unwrap();
        let (st, rc): (String, i64) = conn
            .query_row(
                "SELECT state,retry_count FROM work_item WHERE work_id=?1",
                [&wid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((st.as_str(), rc), ("failed", 1), "fail_work → failed + retry++");
        let (ra, ec): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT result_asset_id,error_code FROM attempt WHERE work_id=?1",
                [&wid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (ra, ec.as_deref()),
            (None, Some("materialize_error")),
            "attempt 记 error_code、result 空"
        );
        let _ = std::fs::remove_dir_all(tmp.path());
    }

    #[test]
    fn commit_lands_rows_idempotent_and_dedup() {
        let dir = std::env::temp_dir().join(format!("ms_commit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = StoreLayout::new(&dir, "acctX");
        std::fs::create_dir_all(layout.account_root().join(".staging")).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctX_sha", 1000).unwrap();

        let bytes = b"hello-wav-bytes-cafe";
        let asset = digest_of(bytes);
        let item = DiscoveredItem {
            kind: MediaKind::Voice,
            source_identity: "media_0".into(),
            source: "voice".into(),
            source_native_id: "12345".into(),
            role: "voice".into(),
            media_seq: 0,
            upstream_key: "12345".into(),
            declared_size: None,
        };
        let mk_m = || {
            let staged = layout.staging("tok1");
            std::fs::write(&staged, bytes).unwrap();
            Materialized {
                asset_id: asset.clone(),
                size: bytes.len() as i64,
                ext: Some("wav".into()),
                mime: Some("audio/wav".into()),
                clarity: "original".into(),
                derivation: "wav".into(),
                staged_path: staged,
            }
        };

        // 块3: commit 现强制 fencing → 先认领拿租(隔离 commit 测同样走真实"认领→提交"路径; 两次 commit 复用同租, epoch 不变)。
        let WorkClaim::Claimed(lease) = open_work_item(&conn, "run-x", "acctX_sha", &item, 0, 1000).unwrap() else {
            panic!("应认领")
        };
        // 首次: Stored, 字节入位, 暂存挪走, 行齐, preferred 指向 asset。
        let out = commit_materialized(&conn, "acctX_sha", &layout, &item, &mk_m(), true, &lease, 1000).unwrap();
        assert_eq!(out, CommitOutcome::Stored);
        assert!(layout.by_content(&asset).exists(), "字节入位 by-content");
        assert!(!layout.staging("tok1").exists(), "暂存已挪走");
        let pref: Option<String> = conn
            .query_row(
                "SELECT preferred_asset_id FROM logical_media WHERE logical_group_id=?1",
                [logical_group_id(&item)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pref.as_deref(), Some(asset.as_str()), "preferred 指向 asset");
        let n_ref: i64 = conn
            .query_row("SELECT count(*) FROM media_reference", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n_ref, 1);
        let n_reg: i64 = conn
            .query_row(
                "SELECT count(*) FROM asset_registry WHERE ref_kind='voice' AND ref_key='12345'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_reg, 1, "asset_registry 有 voice:12345");

        // 幂等重跑: 字节已在盘 → Deduped, 不产重复 asset/variant(同租 CAS 仍匹配, state 已 publishing 幂等)。
        let out2 = commit_materialized(&conn, "acctX_sha", &layout, &item, &mk_m(), true, &lease, 2000).unwrap();
        assert_eq!(out2, CommitOutcome::Deduped, "字节已在盘 → 去重");
        let n_asset: i64 = conn.query_row("SELECT count(*) FROM asset", [], |r| r.get(0)).unwrap();
        let n_variant: i64 = conn
            .query_row("SELECT count(*) FROM variant", [], |r| r.get(0))
            .unwrap();
        assert_eq!((n_asset, n_variant), (1, 1), "asset/variant 不重复");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // 复审 F5a: 同组多变体, preferred 按 clarity 升级(缩略→原图)—— 图片无 key 先收缩略, 后拿 key 收原图必须顶替 preferred。
    #[test]
    fn preferred_upgrades_thumbnail_to_original_by_clarity() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("store");
        let layout = StoreLayout::new(&dir, "acctI");
        std::fs::create_dir_all(layout.account_root().join(".staging")).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctI_sha", 1000).unwrap();
        let item = DiscoveredItem {
            kind: MediaKind::ChatImage,
            source_identity: "message_0".into(),
            source: "message_0.db".into(),
            source_native_id: "Msg_abcd1234:7".into(),
            role: "image".into(),
            media_seq: 0,
            upstream_key: "talker99:7".into(),
            declared_size: None,
        };
        let group = logical_group_id(&item);
        // 块3: commit 现强制 fencing → 先认领拿租(同一 item 的三次变体 commit 复用同租, epoch 不变)。
        let WorkClaim::Claimed(lease) = open_work_item(&conn, "run-i", "acctI_sha", &item, 0, 1000).unwrap() else {
            panic!("应认领")
        };
        // 造某 clarity 的 Materialized(不同 clarity 用不同 bytes → 不同 asset)。
        let mk = |bytes: &'static [u8], clarity: &str| {
            let asset = digest_of(bytes);
            let staged = layout.staging(&format!("tok-{clarity}"));
            std::fs::write(&staged, bytes).unwrap();
            Materialized {
                asset_id: asset,
                size: bytes.len() as i64,
                ext: Some("jpg".into()),
                mime: None,
                clarity: clarity.into(),
                derivation: "none".into(),
                staged_path: staged,
            }
        };
        // 1) 缩略图先入 → preferred = 缩略(只有它)。
        let thumb = mk(b"thumb-bytes", "thumb");
        commit_materialized(&conn, "acctI_sha", &layout, &item, &thumb, true, &lease, 1000).unwrap();
        let pref1: String = conn
            .query_row(
                "SELECT preferred_asset_id FROM logical_media WHERE logical_group_id=?1",
                [&group],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pref1, thumb.asset_id.as_str(), "只有缩略图时 preferred=缩略");
        // 2) 原图后入(同组, verified)→ preferred 按 clarity 升级到原图。
        let full = mk(b"original-full-image-bytes", "original");
        commit_materialized(&conn, "acctI_sha", &layout, &item, &full, true, &lease, 2000).unwrap();
        let pref2: String = conn
            .query_row(
                "SELECT preferred_asset_id FROM logical_media WHERE logical_group_id=?1",
                [&group],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pref2, full.asset_id.as_str(), "原图后到 → preferred 升级到原图");
        // 3) 缩略图再入(乱序/去重)不该把 preferred 降回缩略。
        commit_materialized(&conn, "acctI_sha", &layout, &item, &thumb, true, &lease, 3000).unwrap();
        let pref3: String = conn
            .query_row(
                "SELECT preferred_asset_id FROM logical_media WHERE logical_group_id=?1",
                [&group],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pref3, full.asset_id.as_str(), "缩略图再入不降级 preferred");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_reverify_quarantines_corrupt_and_stores_good() {
        // 复审 P1(§七): dest 已存在但**内容不符**(上次崩溃留的坏/截断同名)→ 不当去重命中, 隔离坏文件、用好字节顶上。
        let dir = std::env::temp_dir().join(format!("ms_reverify_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = StoreLayout::new(&dir, "acctQ");
        std::fs::create_dir_all(layout.account_root().join(".staging")).unwrap();
        let conn = super::super::ledger::open_ledger(&layout.ledger(), "acctQ_sha", 1000).unwrap();

        let good = b"the-good-full-wav-bytes-deadbeef";
        let asset = digest_of(good);
        // 在 dest 预埋一个内容不符的坏文件(模拟上次崩溃留的截断同名)。
        let dest = layout.by_content(&asset);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"truncated-bad-bytes").unwrap();
        // 用好字节 commit。
        let staged = layout.staging(asset.hex());
        std::fs::write(&staged, good).unwrap();
        let m = Materialized {
            asset_id: asset.clone(),
            size: good.len() as i64,
            ext: None,
            mime: None,
            clarity: "original".into(),
            derivation: "wav".into(),
            staged_path: staged,
        };
        let item = DiscoveredItem {
            kind: MediaKind::Voice,
            source_identity: "s".into(),
            source: "voice".into(),
            source_native_id: "1".into(),
            role: "voice".into(),
            media_seq: 0,
            upstream_key: "1".into(),
            declared_size: None,
        };
        // 块3: commit 现强制 fencing → 先认领拿租。
        let WorkClaim::Claimed(lease) = open_work_item(&conn, "run-q", "acctQ_sha", &item, 0, 1000).unwrap() else {
            panic!("应认领")
        };
        let out = commit_materialized(&conn, "acctQ_sha", &layout, &item, &m, true, &lease, 1000).unwrap();
        assert_eq!(out, CommitOutcome::Stored, "内容不符不当去重命中, 而是重新入位");
        assert_eq!(std::fs::read(&dest).unwrap(), good, "dest 现在是好字节");
        let q = layout.quarantine(&format!("{}.corrupt", asset.hex()));
        assert!(
            q.exists() && std::fs::read(&q).unwrap() == b"truncated-bad-bytes",
            "坏文件挪进隔离(不自动删)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn by_content_uses_bare_hex_two_level_bucket() {
        let layout = StoreLayout::new(Path::new("/store"), "acct1");
        let a = asset_a();
        let p = layout.by_content(&a);
        // 前 2 位分桶 + 全 hex 文件名; 无 'sha256:' 前缀、无冒号(Windows 非法)、文件名即裸 hex 无扩展名。
        assert!(
            p.ends_with(Path::new("ab").join("ab".repeat(32))),
            "by-content 路径: {p:?}"
        );
        let s = p.to_string_lossy();
        assert!(!s.contains("sha256:"), "路径不含 sha256: 前缀");
        assert!(!s.contains(':'), "路径不含冒号(Windows 非法)");
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            "ab".repeat(32),
            "文件名=裸 hex 无扩展名"
        );
    }

    #[test]
    fn layout_paths_under_account_root() {
        let layout = StoreLayout::new(Path::new("/store"), "acct1");
        assert_eq!(layout.account_root(), Path::new("/store/acct1"));
        assert_eq!(layout.ledger(), Path::new("/store/acct1/ledger.db"));
        assert_eq!(layout.staging("tok"), Path::new("/store/acct1/.staging/tok.part"));
        assert_eq!(layout.quarantine("bad1"), Path::new("/store/acct1/.quarantine/bad1"));
        assert!(layout.by_chat_root().ends_with("by-chat"));
    }

    #[test]
    fn failure_codes_stable() {
        assert_eq!(MaterializeFailure::BadKey.code(), "bad_key");
        assert_eq!(MaterializeFailure::Io("x".into()).code(), "io");
        assert_eq!(MaterializeFailure::SourceAbsent.code(), "source_absent");
    }
}
