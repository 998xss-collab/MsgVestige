//! 语音竖切(R10 §11-② 首个 [`super::engine`] 源实现)。§三 三层:discover 枚举 `VoiceInfo%` → materialize 解微信变体 SILK→WAV
//! →sha256→stage → commit 入账(共用 [`super::engine::commit_materialized`])。**语音最简**:数据直接在 `media_0.db` 的
//! `VoiceInfo.voice_data` BLOB(无 md5/hardlink 定位), 用它把三层契约 + 账本落库端到端验通, 再照搬到 video/image。
//!
//! 复用现有解码 [`native_silk`] + `media/voice_export.rs` 的分表枚举经验(**必枚举 `VoiceInfo%` 全分表**, 只读单表漏数据)。

use std::collections::HashMap;
use std::ops::ControlFlow;

use anyhow::{Context, Result};
use native_silk::{decode_silk_report, pcm_to_wav, SAMPLE_RATE_HZ};
use rusqlite::{Connection, OptionalExtension};

use super::engine::{
    commit_materialized, fail_work, finish_work, open_work_item, record_attempt, CommitOutcome, DiscoveredItem,
    MaterializeFailure, MaterializeOutcome, Materialized, StoreLayout, WorkClaim,
};
use super::{AssetId, MediaKind};
use crate::decoder::msg_anchor_from_talker_hex;

/// 枚举 message db 的 `Msg_<32hex>` 表(**小写 hex**; 同 video/image 的 talker 分表过滤 —— 微信表名恒小写)。
fn msg_talker_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|t| {
            t.strip_prefix("Msg_").is_some_and(|talker| {
                talker.len() == 32 && talker.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
        })
        .collect();
    Ok(names)
}

/// svr_id → L1 消息锚**列表**(复审 F3: 语音之前只存 svr_id 不锚回消息, video/image 都锚)。值是 `Vec`: 同 svr_id 的消息可能在
/// 多个分片(同消息跨分片 source 不同, 源契约支持)→ 各发一个 reference, 对齐 video/image 遍历消息(复审 codex P1-1)。
pub type VoiceAnchorMap = HashMap<i64, Vec<(String, String)>>;

/// 扫**单个** message 分片的 Msg_ 表(语音消息 `local_type=34`, `server_id>0`; server_id==VoiceInfo.svr_id, 真库实测 100% 命中)
/// 把 svr_id→(分片文件名, `Msg_<32hex>:<local_id>` 消息锚)累积进 `map`。**逐分片调**(CLI 开一个扫一个 drop, 免多解密库同时驻留
/// 内存 —— 复审 codex P1-3)。`server_id>0` 排除 0/负 未同步哨兵(否则一堆 svr_id=0 撞同一锚, 复审 Claude P3)。同锚去重(重跑幂等)。
///
/// # Errors
/// rusqlite 查询失败。
pub fn scan_voice_anchors_into(conn: &Connection, db_source: &str, map: &mut VoiceAnchorMap) -> Result<()> {
    for table in msg_talker_tables(conn)? {
        let talker = table.strip_prefix("Msg_").unwrap_or(&table).to_string();
        let sql = format!("SELECT server_id, local_id FROM \"{table}\" WHERE local_type = 34 AND server_id > 0");
        let mut stmt = conn
            .prepare(&sql)
            .with_context(|| format!("准备扫 {table} 语音消息失败"))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (svr_id, local_id) in rows {
            let anchor = (db_source.to_string(), msg_anchor_from_talker_hex(&talker, local_id));
            let entry = map.entry(svr_id).or_default();
            if !entry.contains(&anchor) {
                entry.push(anchor);
            }
        }
    }
    Ok(())
}

/// 枚举 `media_0.db` 全部 `VoiceInfo%` 分表(按名排序; 大历史库会分表, 只读单表 = 丢数据)。
fn voice_info_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'VoiceInfo%' ORDER BY name")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names)
}

/// **discover(流式 primitive, 块4: 不无限占内存)**: 枚举全部 `VoiceInfo%` 分表里有 `voice_data` 的行, 每条 svr_id(×命中锚)
/// 吐一个 [`DiscoveredItem`] 给 `on_item` 回调 —— **不 collect 进 Vec**(用流式游标 `query`+`rows.next`), 峰值内存 O(1) 不随
/// 行数涨。`on_item` 返 [`ControlFlow::Break`] 提前停(如达 limit)。收集版见 [`voice_discover`]。
///
/// **borrow**: `conn` 被流式游标共享借用时, `on_item` 内可对**同一 conn** 再查(voice_materialize 读 media_conn)—— rusqlite
/// 允许同连接多 active 语句(纯读并发, 真跑验证通)。
///
/// # Errors
/// rusqlite 查询失败 / `on_item` 回调返错。
#[allow(clippy::implicit_hasher)] // 内部只喂 std HashMap(run_voice_ingest 建), 不必泛化 hasher
pub fn voice_discover_each(
    conn: &Connection,
    source_identity: &str,
    anchor: &VoiceAnchorMap,
    mut on_item: impl FnMut(DiscoveredItem) -> Result<ControlFlow<()>>,
) -> Result<()> {
    for table in voice_info_tables(conn)? {
        // 表名来自 sqlite_master 白名单(LIKE 'VoiceInfo%'), 非外部输入; svr_id 唯一 → 每条一 item。
        let mut stmt = conn
            .prepare(&format!(
                "SELECT svr_id FROM \"{table}\" WHERE voice_data IS NOT NULL ORDER BY svr_id"
            ))
            .with_context(|| format!("准备枚举 {table} 失败"))?;
        let mut rows = stmt.query([])?; // 块4: 流式游标, 不 `.collect::<Vec>`
        while let Some(row) = rows.next()? {
            let svr_id: i64 = row.get(0)?;
            // 复审 F3: **每个命中锚发一个 item**(同 svr_id 跨分片多消息 → 各发一 reference, 对齐 video/image); 无锚降级
            // voice/svr_id(有音频无消息锚)。upstream_key 恒 svr_id(所有 item 同, materialize 定位/dedup 靠它)。
            let refs: Vec<(String, String)> = match anchor.get(&svr_id) {
                Some(v) if !v.is_empty() => v.clone(),
                _ => vec![("voice".to_string(), svr_id.to_string())],
            };
            for (source, source_native_id) in refs {
                let item = DiscoveredItem {
                    kind: MediaKind::Voice,
                    source_identity: source_identity.to_string(),
                    source,
                    source_native_id,
                    role: "voice".to_string(),
                    media_seq: 0,
                    upstream_key: svr_id.to_string(), // serve 键 + materialize 定位键(与 source_native_id 解耦)
                    declared_size: None,              // 语音无源声明字节数, 截断靠 SILK 解码器 report 判(materialize)
                };
                if on_item(item)?.is_break() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

/// **discover(收集版)**: [`voice_discover_each`] 的 Vec 包装(测试等非流式调用方用; 生产 ingest 走 `_each` 流式)。
///
/// # Errors
/// rusqlite 查询失败。
#[allow(clippy::implicit_hasher)]
pub fn voice_discover(
    conn: &Connection,
    source_identity: &str,
    anchor: &VoiceAnchorMap,
) -> Result<Vec<DiscoveredItem>> {
    let mut items = Vec::new();
    voice_discover_each(conn, source_identity, anchor, |item| {
        items.push(item);
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(items)
}

/// **materialize**:取 item 的 `voice_data` BLOB → 解微信变体 SILK v3 → PCM → WAV → 算 sha256 → 写 `.staging/<hex>.part`。
/// best-effort:非 SILK/空/坏 → [`MaterializeFailure`]; 完整 → `Ready`, 截断/中途坏 → `Partial`(仍产字节但不当归档成功)。
/// 复审 P1: 暂存**按内容 hash 命名**(不是外部 token)—— 跨 run/并发不会互相 clobber(不同内容不同名, 同内容同名无害),
/// 杜绝"run A 算完 hash 后被 run B 覆写暂存字节 → A 把 B 的字节按 A 的 hash 入库"。
///
/// # Errors
/// rusqlite 查询失败 / 写暂存失败。
pub fn voice_materialize(conn: &Connection, item: &DiscoveredItem, layout: &StoreLayout) -> Result<MaterializeOutcome> {
    // 复审 F3: svr_id 从 **upstream_key** 拿(定位键恒 svr_id); source_native_id 现可能是消息锚(Msg_<32hex>:<lid>) 不再是 svr_id。
    let Ok(svr_id) = item.upstream_key.parse::<i64>() else {
        return Ok(MaterializeOutcome::Failed(MaterializeFailure::Decode(
            "svr_id(upstream_key) 非整数".into(),
        )));
    };
    // 取 BLOB(枚举全分表, svr_id 跨分表唯一 → 命中即定)。
    let mut blob: Option<Vec<u8>> = None;
    for table in voice_info_tables(conn)? {
        let got: Option<Vec<u8>> = conn
            .query_row(
                &format!("SELECT voice_data FROM \"{table}\" WHERE svr_id = ?1 AND voice_data IS NOT NULL"),
                [svr_id],
                |r| r.get(0),
            )
            .optional()?;
        if got.is_some() {
            blob = got;
            break;
        }
    }
    let Some(blob) = blob else {
        return Ok(MaterializeOutcome::Failed(MaterializeFailure::SourceAbsent));
    };
    // 解 SILK(best-effort): 非 SILK/空/坏 → 格式不认。
    let Ok((pcm, report)) = decode_silk_report(&blob) else {
        return Ok(MaterializeOutcome::Failed(MaterializeFailure::Unrecognized));
    };
    let wav = pcm_to_wav(&pcm, SAMPLE_RATE_HZ);
    let asset_id = {
        use sha2::Digest as _;
        let d: [u8; 32] = sha2::Sha256::digest(&wav).into();
        AssetId::from_digest(&d)
    };
    let staged = layout.staging(asset_id.hex()); // 复审 P1: 按内容 hash 命名, 跨 run 不撞
    if let Some(parent) = staged.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("建暂存目录 {} 失败", parent.display()))?;
    }
    std::fs::write(&staged, &wav).with_context(|| format!("写暂存 {} 失败", staged.display()))?;
    let m = Materialized {
        asset_id,
        size: i64::try_from(wav.len()).unwrap_or(i64::MAX),
        ext: Some("wav".into()),
        mime: Some("audio/wav".into()),
        clarity: "original".into(),
        derivation: "wav".into(),
        staged_path: staged,
    };
    Ok(if report.is_complete() {
        MaterializeOutcome::Ready(m)
    } else {
        MaterializeOutcome::Partial(m)
    })
}

/// 语音入库统计。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VoiceIngestStats {
    /// discover 到的语音槽数。
    pub discovered: usize,
    /// 新落盘 by-content 的字节数(完整)。
    pub stored: usize,
    /// 内容去重命中(字节已在盘, 只加引用)。
    pub deduped: usize,
    /// 不完整(截断/中途坏)入账数(标 unverified)。
    pub partial: usize,
    /// 物化失败(坏 key/格式不认/源缺)。
    pub failed: usize,
}

/// **驱动**:discover → 逐项 materialize → commit(一项一事务)→ 记 `source_scan` coverage=complete。
/// `limit` = 最多**入账**多少条(None 全部)。`now` = UTC epoch(调用方给, 别在库内取时钟)。
///
/// # Errors
/// discover / 事务提交 / source_scan 记录 失败(单项 materialize 失败只计数不中断)。
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub fn run_voice_ingest(
    media_conn: &Connection,
    anchor: &VoiceAnchorMap,
    ledger_conn: &Connection,
    account_id_sha: &str,
    run_id: &str,
    source_identity: &str,
    layout: &StoreLayout,
    limit: Option<usize>,
    now: i64,
) -> Result<VoiceIngestStats> {
    // 复审 codex P2: 锚映射由调用方**建一次**传入(CLI 在 media 循环外逐分片 open→scan→drop 建), 不再每 media 分片重建重扫。
    let mut stats = VoiceIngestStats::default();
    let mut truncated = false;
    let mut held = 0usize; // 块3: 被别的 worker 持活跃租而跳过的项数(>0 → 覆盖不完整 → coverage=partial)。
                           // 复审 codex P2: 同 svr_id 多锚(跨分片)时**物化一次复用**, 别重 SILK 解码/重 hash/重写 staging。值 = (svr_id, (产物, verified))。
                           // 块4双审 codex P1: **单条**缓存(非 HashMap 全量)—— discover 按 svr_id 升序发、同 svr_id 多锚**连续**, 故只需缓存当前
                           // svr_id 一条; svr_id 变即替换(驱逐上个)→ **O(1) 内存**(不随 distinct svr_id 涨), 复用不丢(连续多锚仍命中同键)。
    let mut cache: Option<(String, (Materialized, bool))> = None;
    // 块4: **流式 discover**(不建全量 Vec)—— 逐项回调处理, 峰值内存 O(1) 不随源行数涨。discovered 逐项计(与旧 Vec 版
    // discovered=items.len() 等价: 达 limit 后仍流完全部计 discovered, 只 skip 入账 → truncated, 不 break 流)。
    voice_discover_each(media_conn, source_identity, anchor, |item| -> Result<ControlFlow<()>> {
        stats.discovered += 1;
        if limit.is_some_and(|l| stats.stored + stats.deduped + stats.partial >= l) {
            truncated = true; // 达 limit: 继续流(计 discovered)但不入账 → scope 未全覆盖(下方 coverage 记 partial)
            return Ok(ControlFlow::Continue(()));
        }
        // 块1(F2)+块3(§12-B lease): 建/认领 work_item(claimed, 拿 fencing 租约)。已 done 跳过(codex P1);
        // 被别的 worker 持活跃租 → 本轮跳过 + coverage 记 partial(等其租 TTL 到期由后续轮接手)。
        let lease = match open_work_item(ledger_conn, run_id, account_id_sha, &item, 0, now)? {
            WorkClaim::Claimed(l) => l,
            WorkClaim::AlreadyDone => return Ok(ControlFlow::Continue(())), // 上轮已 done: 不重物化, 不计 limit。
            WorkClaim::HeldByOther { until, .. } => {
                tracing::info!(svr_id = %item.upstream_key, until, "voice: work 被别的 worker 持活跃租, 本轮跳过");
                held += 1;
                return Ok(ControlFlow::Continue(()));
            }
        };
        let work_id = lease.work_id.clone();
        // 复审 P3(韧性): 单项出错**只计 failed 续跑**, 不炸掉整轮。codex P2: 同 svr_id 已物化则复用(不重解码)。
        // 块4: 单条缓存命中判 = 键 == 当前 svr_id(连续多锚)。
        let cached = match &cache {
            Some((k, mv)) if *k == item.upstream_key => Some(mv.clone()),
            _ => None,
        };
        let (m, verified) = if let Some(mv) = cached {
            mv
        } else {
            let mv = match voice_materialize(media_conn, &item, layout) {
                Ok(MaterializeOutcome::Ready(m)) => (m, true),
                Ok(MaterializeOutcome::Partial(m)) => (m, false),
                Ok(MaterializeOutcome::Failed(f)) => {
                    // 块1(F2): 失败也留 attempt(error_code)+ work failed **原子**(fail_work), 不再只 count++/吞错。
                    if let Err(e) = fail_work(ledger_conn, run_id, &lease, f.code(), now) {
                        tracing::warn!(svr_id = %item.upstream_key, err = %e, "voice 记失败 provenance 出错");
                    }
                    stats.failed += 1;
                    return Ok(ControlFlow::Continue(()));
                }
                Err(e) => {
                    tracing::warn!(svr_id = %item.upstream_key, err = %e, "voice materialize 失败, 跳过");
                    if let Err(e2) = fail_work(ledger_conn, run_id, &lease, "materialize_error", now) {
                        tracing::warn!(svr_id = %item.upstream_key, err = %e2, "voice 记失败 provenance 出错");
                    }
                    stats.failed += 1;
                    return Ok(ControlFlow::Continue(()));
                }
            };
            cache = Some((item.upstream_key.clone(), mv.clone())); // 单条: 替换=驱逐上个 svr_id → O(1) 内存
            mv
        };
        // 一项一事务: 挪字节 + 账本行 + attempt + finish 原子。tx 失败回滚(字节已入位则留孤儿, journal/recovery 兜——块2)。
        let committed = (|| -> Result<CommitOutcome> {
            let tx = ledger_conn.unchecked_transaction()?;
            let o = commit_materialized(ledger_conn, account_id_sha, layout, &item, &m, verified, &lease, now)?;
            // 复审 codex P1-2/Claude E: 有锚 item 入账后清同 svr_id 残留的**降级**引用(上次无 --message-db 跑留的),
            // 免一个 voice 两条 media_reference —— 降级那条无消息锚, GC-按消息删 永远释放不了该 asset。
            if item.source != "voice" {
                ledger_conn.execute(
                    "DELETE FROM media_reference WHERE account_id_sha=?1 AND source='voice' AND source_native_id=?2 AND role='voice'",
                    rusqlite::params![account_id_sha, item.upstream_key],
                )?;
            }
            // 块1(F2): 成功入账 → attempt 记 result_asset_id + work 收尾(同事务, 崩溃恢复据此判已 accounted)。
            // verified=完整 → done(重扫跳过); partial(verified=false) → verifying —— 非终态, 允许完整版重入升级(codex P1)。
            record_attempt(ledger_conn, run_id, &work_id, Some(m.asset_id.as_str()), None, now)?;
            // 块3: fenced finish(&lease)。成功路径同事务刚 commit CAS 过同租, 必命中 → ensure(防未来 lease 失序退化成静默不收尾)。
            anyhow::ensure!(
                finish_work(
                    ledger_conn,
                    &lease,
                    if verified { "done" } else { "verifying" },
                    None,
                    now
                )?,
                "voice finish_work 未命中租约(不应发生: commit 同事务刚 CAS 过同一 lease)"
            );
            tx.commit()?;
            Ok(o)
        })();
        match committed {
            Ok(CommitOutcome::Stored) if verified => stats.stored += 1,
            Ok(CommitOutcome::Deduped) if verified => stats.deduped += 1,
            Ok(_) => stats.partial += 1, // partial(verified=false)
            Err(e) => {
                tracing::warn!(svr_id = %item.upstream_key, err = %e, "voice commit 失败, 跳过");
                if let Err(e2) = fail_work(ledger_conn, run_id, &lease, "commit_error", now) {
                    tracing::warn!(svr_id = %item.upstream_key, err = %e2, "voice 记失败 provenance 出错");
                }
                stats.failed += 1;
            }
        }
        Ok(ControlFlow::Continue(()))
    })?;
    // 复审 P1(§12-C 诚实性): **只有全扫完(未被 limit 截断)、零失败、无被他租跳过**才 coverage=complete; 否则 partial ——
    // 否则日后引用撤销 pass 会把本轮"失败/未及/被他租跳过"的项当"完整扫描未见"误 tombstone(删活资产)。真实全量跑必有 failed, 故非罕例。
    let coverage = if !truncated && stats.failed == 0 && held == 0 {
        "complete"
    } else {
        "partial"
    };
    ledger_conn
        .execute(
            "INSERT INTO source_scan(source_identity,discovery_epoch,coverage,scanned_at) VALUES(?1,?2,?3,?2) \
             ON CONFLICT(source_identity) DO UPDATE SET discovery_epoch=excluded.discovery_epoch, coverage=excluded.coverage, scanned_at=excluded.scanned_at",
            rusqlite::params![source_identity, now, coverage],
        )
        .context("记 source_scan 失败")?;
    Ok(stats)
}

// @@GUARD:PROD_END@@  生产段到此为止(本文件全 ON CONFLICT, 无 REPLACE)。
#[cfg(test)]
mod tests {
    use super::*;

    /// 造含 VoiceInfo 表的内存源库, 验 discover 枚举全分表 + F3 锚回消息/降级(SILK 解码走真跑坐实)。
    #[test]
    fn discover_enumerates_and_anchors() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE VoiceInfo(svr_id INTEGER PRIMARY KEY, voice_data BLOB);
             INSERT INTO VoiceInfo VALUES(100, x'01'), (200, NULL), (300, x'02');
             CREATE TABLE VoiceInfo1(svr_id INTEGER PRIMARY KEY, voice_data BLOB);
             INSERT INTO VoiceInfo1 VALUES(400, x'03');",
        )
        .unwrap();
        // 锚: svr_id 100 命中一条消息; 300/400 无锚 → 降级。
        let mut anchor: VoiceAnchorMap = HashMap::new();
        anchor.insert(100i64, vec![("message_0.db".to_string(), "Msg_deadbeef:7".to_string())]);
        let items = voice_discover(&conn, "media_0", &anchor).unwrap();
        // 有 voice_data 的: 100/300(VoiceInfo)+400(VoiceInfo1); 200 是 NULL 跳过 —— 分表必枚举。upstream_key 恒 svr_id。
        let ids: Vec<&str> = items.iter().map(|i| i.upstream_key.as_str()).collect();
        assert_eq!(ids, ["100", "300", "400"], "枚举全分表非 NULL 行");
        assert!(items.iter().all(|i| i.kind == MediaKind::Voice && i.role == "voice"));
        // F3: 命中锚 → source/native_id 锚回 L1 message; 未命中 → 降级 voice/svr_id。
        let hit = items.iter().find(|i| i.upstream_key == "100").unwrap();
        assert_eq!(
            (hit.source.as_str(), hit.source_native_id.as_str()),
            ("message_0.db", "Msg_deadbeef:7"),
            "命中锚回消息"
        );
        let miss = items.iter().find(|i| i.upstream_key == "300").unwrap();
        assert_eq!(
            (miss.source.as_str(), miss.source_native_id.as_str()),
            ("voice", "300"),
            "未命中降级 voice/svr_id"
        );
        // F3 复审 codex P1-1: 同 svr_id 跨分片多消息 → **各发一 item**(对齐 video/image 每消息一 reference)。
        anchor.insert(
            300i64,
            vec![
                ("message_0.db".to_string(), "Msg_aa:1".to_string()),
                ("message_1.db".to_string(), "Msg_bb:2".to_string()),
            ],
        );
        let items2 = voice_discover(&conn, "media_0", &anchor).unwrap();
        assert_eq!(
            items2.iter().filter(|i| i.upstream_key == "300").count(),
            2,
            "svr_id 300 两锚 → 两 item"
        );
    }

    /// 块4: `voice_discover_each` 流式逐项 + `ControlFlow::Break` 早停 —— 证不 collect 全量 Vec、回调逐项收、Break 提前停。
    #[test]
    fn voice_discover_each_streams_and_breaks() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE VoiceInfo(svr_id INTEGER PRIMARY KEY, voice_data BLOB);
             INSERT INTO VoiceInfo VALUES(1, x'01'),(2, x'02'),(3, x'03'),(4, x'04');",
        )
        .unwrap();
        let anchor: VoiceAnchorMap = HashMap::new();
        // 全 Continue → 流式逐项见全部 4(顺序 by svr_id), 与收集版 voice_discover 等价。
        let mut all = Vec::new();
        voice_discover_each(&conn, "media_0", &anchor, |it| {
            all.push(it.upstream_key.clone());
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();
        assert_eq!(
            all,
            ["1", "2", "3", "4"],
            "块4: 全 Continue → 流式逐项见全部, 顺序 by svr_id"
        );
        assert_eq!(
            voice_discover(&conn, "media_0", &anchor).unwrap().len(),
            4,
            "收集版 wrapper 与 _each 一致"
        );
        // 第 2 项 Break → 只处理 2(早停, 不枚举其余 → 流式非全 collect)。
        let mut seen = 0usize;
        voice_discover_each(&conn, "media_0", &anchor, |_it| {
            seen += 1;
            if seen >= 2 {
                Ok(ControlFlow::Break(()))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })
        .unwrap();
        assert_eq!(
            seen, 2,
            "块4: Break 早停 → 只处理 2 项(证流式逐项调回调、非先 collect 再遍历)"
        );
    }

    /// 块4双审 a47f40 P3-a: 锁死并发契约 —— `voice_discover_each` 流式游标活着时, 回调内对**同一 conn** query_row(voice/image
    /// 的 materialize 就是这么读源 conn 取 blob 的)不炸 / 不漏行 / 不脏读。标准 ingest 测试(limit=None + real_run ignore)没守这条。
    #[test]
    fn voice_discover_each_inner_query_same_conn() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE VoiceInfo(svr_id INTEGER PRIMARY KEY, voice_data BLOB);
             INSERT INTO VoiceInfo VALUES(11, x'aa'),(22, x'bb'),(33, x'cc');",
        )
        .unwrap();
        let anchor: VoiceAnchorMap = HashMap::new();
        let mut seen = Vec::new();
        voice_discover_each(&conn, "media_0", &anchor, |it| {
            // 流式游标(SELECT svr_id FROM VoiceInfo)**活着**时, 对同一 conn 再查同一张 VoiceInfo(mimick materialize 取 blob)。
            let svr: i64 = it.upstream_key.parse().unwrap();
            let hit: i64 = conn
                .query_row(
                    "SELECT COUNT(1) FROM VoiceInfo WHERE svr_id=?1 AND voice_data IS NOT NULL",
                    [svr],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(hit, 1, "回调内同 conn query_row 命中(游标活跃时并发只读安全)");
            seen.push(svr);
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![11, 22, 33],
            "块4: 流式游标活跃时同 conn 内层查不漏行/不炸(rusqlite 多 active 只读语句)"
        );
    }

    /// 真跑坐实: 对**解密** media_0.db 跑整条 discover→materialize(真 SILK 解码)→commit, 核字节入位 + 账本 + WAV 头。
    /// `cargo test -p native-core real_run_voice_ingest -- --ignored --nocapture`(需环境变量 `MEDIA0_DB` 指向解密库)。
    #[test]
    #[ignore = "真跑: 需 MEDIA0_DB 指向解密 media_0.db"]
    fn real_run_voice_ingest() {
        let Ok(db_path) = std::env::var("MEDIA0_DB") else {
            eprintln!("跳过 real_run_voice_ingest: 未设 MEDIA0_DB");
            return;
        };
        let media = Connection::open(&db_path).unwrap();
        let dir = std::env::temp_dir().join(format!("ms_realrun_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = StoreLayout::new(&dir, "realrun");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger = super::super::ledger::open_ledger(&layout.ledger(), "realrun_acct_sha", 1_700_000_000).unwrap();

        // 真跑锚回消息可选: 设 MSG_DB 指向解密 message_0.db 则扫建锚, 否则空(全降级)。CLI 真跑走 --message-db 验锚。
        let mut anchor = VoiceAnchorMap::new();
        if let Ok(p) = std::env::var("MSG_DB") {
            let msg = Connection::open(p).unwrap();
            scan_voice_anchors_into(&msg, "message_0.db", &mut anchor).unwrap();
        }
        let stats = run_voice_ingest(
            &media,
            &anchor,
            &ledger,
            "realrun_acct_sha",
            "realrun-1",
            "media_0",
            &layout,
            Some(200),
            1_700_000_000,
        )
        .unwrap();
        eprintln!("语音真跑 stats = {stats:?}");
        assert!(stats.discovered > 0, "应发现语音");
        assert!(stats.stored + stats.deduped + stats.partial > 0, "应入账至少一条");

        // 抽一个 by-content 文件读回, 验是 WAV(RIFF....WAVE)。
        let hex: String = ledger
            .query_row("SELECT hex FROM asset LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let p = layout.account_root().join("by-content").join(&hex[..2]).join(&hex);
        let head = std::fs::read(&p).unwrap();
        assert_eq!(&head[..4], b"RIFF", "by-content 文件是 WAV(RIFF 头)");
        assert_eq!(&head[8..12], b"WAVE", "WAVE 格式");

        // 账本一致: 入账条数 = media_reference 行 = asset_registry(voice) 行; 每 asset 有 ready presence。
        let ledgered = stats.stored + stats.deduped + stats.partial;
        let n_ref: i64 = ledger
            .query_row("SELECT count(*) FROM media_reference", [], |r| r.get(0))
            .unwrap();
        let n_ready: i64 = ledger
            .query_row("SELECT count(*) FROM asset_presence WHERE state='ready'", [], |r| {
                r.get(0)
            })
            .unwrap();
        // 复审 P1: limit=200 截断 → coverage 应是 **partial**(未全扫), 不是 complete(诚实性)。
        let coverage: String = ledger
            .query_row(
                "SELECT coverage FROM source_scan WHERE source_identity='media_0'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        eprintln!("账本: media_reference={n_ref} asset_presence(ready)={n_ready} source_scan.coverage={coverage}");
        assert_eq!(n_ref as usize, ledgered, "media_reference 行 = 入账条数");
        assert_eq!(coverage, "partial", "limit 截断 → coverage=partial(诚实性)");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
