//! R18 件2: thin 持久档 daemon 的 source→thin 增量核心 (L1-free)。
//!
//! 与 [`crate::pipeline::run_message_body`] 平行、但**不建 L1**: drain 加密源库消息 → [`assemble_message`]
//! 抽正文 → 灌独立瘦 FTS ([`storage::insert_thin_msg`]);每分片 `local_id` 游标 (JSON map) 存 `thin_meta`
//! watermark ([`storage::set_thin_watermark`]),**与 FTS 插入同一事务提交** → 崩溃一致 (要么正文进索引且游标
//! 前移、要么整批回滚),重启从 watermark 续抽,不回放不漏。
//!
//! thin 只索引正文 (msg_id + text),**不落 message / 联系人等表** —— 这是 thin「不建库秒搜」与 full「保持 L1
//! 全鲜」的本质区别。故坏消息 (assemble 失败) 直接跳过 (thin 无 SystemError 事件、只搜正文)。

use std::collections::BTreeMap;

use anyhow::Context;
use rusqlite::Connection;

use crate::decoder::anchor::msg_anchor;
use crate::decoder::message::{assemble_message, MessageContext};
use crate::key_provider::Wxid;
use crate::source::{DbSource, DrainCursor, ProbeDepth, ResumeProbe};
use crate::storage;

/// `(source 分片, native_id 消息锚)` → 稳定 i64 rowid (FNV-1a 64bit,右移 1 位保正)。**同 (source,msg_id) → 同
/// rowid** → thin FTS 按 rowid 去重幂等 ([`storage::insert_thin_msg`] 先 `DELETE WHERE rowid` 再插),tail 重试 /
/// 崩溃重抽同一消息只覆盖、不重复倒排 (spec §7)。
///
/// **必须含 source 分片**: `msg_anchor = Msg_<md5(conv_id)>:<local_id>` **不含分片 md5**, 而 L1 message PK =
/// `(account_id_sha, source, source_native_id)` —— 同一 `source_native_id` 可在**不同源分片** (message_0/1/…) 重复
/// (各分片 local_id 独立; 测 `resolve_collision_compound_key_splits_by_shard` 证实)。只按 msg_id 做键 → 跨分片两条
/// 相异消息撞同 rowid → 后插 DELETE 覆盖前者 → 丢消息 (codex 复审 P1)。故键 = FNV(source ‖ 0x1f ‖ msg_id)。
#[must_use]
pub fn thin_rowid(source: &str, msg_id: &str) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
                                            // source(分片)→ 0x1f 分隔符 → msg_id(锚): 0x1f 防 ("a","bc") 与 ("ab","c") 拼接歧义撞键。
    for b in source.bytes().chain(std::iter::once(0x1f)).chain(msg_id.bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    (h >> 1) as i64 // 右移 1 → 恒非负 (SQLite rowid 允许负值, 但正值避歧义)
}

/// thin daemon 一趟增量: 扫所有消息分片子源 → 抽新消息正文灌 thin FTS + 推进 watermark。返本趟灌入条数。
///
/// `thin` = 已 `init_thin_fts` + `init_thin_meta` 的独立瘦库连接 (`&mut` 供 `transaction()`)。
/// 游标 map 存 `thin_meta` watermark (JSON `{"<rel>|<table>": local_id}`),与 FTS 插入同事务 → 崩溃一致。
/// 空正文 / assemble 失败的消息不入索引。
///
/// # Errors
/// DbSource drain 失败 / rusqlite 写失败 / DbSource 失约 (`next_cursor` != 本批最大 `local_id` → 会漏区间)。
pub async fn run_thin_pipeline_incremental(
    source: &mut dyn DbSource,
    thin: &mut Connection,
    account: &Wxid,
    batch_limit: usize,
) -> anyhow::Result<u64> {
    anyhow::ensure!(batch_limit >= 1, "batch_limit 必须 ≥ 1 (page-by-page 禁全量)");

    // codex 复审 P1 迁移守卫: 维护前核对 rowkey 键方案版本 —— 旧方案 (pre-源分片键, v1) 的非空索引会与新方案 (v2,
    // 含 source) 行并存重复倒排, 故先清空重建 (同时抹水位 → 下方从头全抽)。空库/版本相符则不动。
    if storage::ensure_thin_rowkey_current(thin).context("thin rowkey 版本核对失败")? {
        tracing::info!(
            "[thin] 检测到旧 rowkey 方案 (v1 无分片) 索引 → 已清空, 本趟按当前方案 (含 source 分片) 从头全重建"
        );
    }

    // 读游标 map (缺 / 坏 JSON → 空 = 从头抽; rowid 幂等去重保证重抽不产生重复倒排)。
    //
    // ⚠️ **值从裸 `i64` 换成 `DrainCursor` 的水位串**(2026-07-30 用户拍板补护栏): 原来这里只存
    // "读到第几条", 跟 L1 那条路修之前一模一样 —— 源库被换成另一份副本 / 表被重建时,
    // `WHERE local_id > 旧游标` 会**静默漏一段**, 搜索结果就少了, 而且**一点信号都没有**。
    // 比修之前的 L1 还弱一格: 连老的"游标比最大 id 还大就重扫"都没有。
    //
    // 老格式(`{"<键>": 123}`)反序列化成 `BTreeMap<String, String>` 会**失败** → 空 map →
    // **本趟从头全重建一次**。这正是想要的迁移动作, 不用写迁移代码; 重建幂等(rowid 去重), 只发生一次。
    let raw_wm = storage::get_thin_watermark(thin).ok().flatten();
    let mut cursors: BTreeMap<String, String> = raw_wm
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    // **迁移要吭一声**(独立复审 P3): 真库 750 万条重抽一遍是几十分钟级的动作, 静默做太吓人;
    // 而且水位 JSON 万一因别的原因坏掉, 不出声就变成"每轮静默重建"。
    if cursors.is_empty() {
        if let Some(j) = &raw_wm {
            if !j.trim().is_empty() && j.trim() != "{}" {
                tracing::info!("[thin] 老格式水位(或坏 JSON)读不出来 → 本趟从 0 整体重建一次(rowid 幂等, 只发生一次)");
            }
        }
    }

    let mut inserted: u64 = 0;
    let snapshots = source.snapshot_dbs().await?;
    for snapshot in &snapshots {
        let subsources = source.list_message_subsources(snapshot).await?;
        for subsource in &subsources {
            let etl_source = format!("{}|{}", snapshot.rel_name, subsource.table);
            let mut cursor = cursors
                .get(&etl_source)
                .and_then(|w| DrainCursor::from_watermark_value(w))
                .unwrap_or_default();

            // **护栏**(同 `pipeline::run_message_body`): 探一次源表, 认"这还是不是同一张表 /
            // 我停的位置还算不算数"。对不上就把游标归零、整表重抽 —— 瘦库重抽是幂等的
            // (`insert_thin_msg` 按 rowid 覆盖), 只是多花一趟。
            //
            // 深度用 `Shallow`: 这是 daemon, **来一条消息就跑一轮**, 而 `Deep` 那一项要扫已读段
            // (真库 750 万行 ≈ 18 秒/轮), 付不起。`Shallow` 不影响"已读段行数"的准确性 ——
            // 它由 drain 侧算术推进(见 `source::ProbeDepth`), 只是这条路不拿库里的真值核对它。
            let mut meta_backfilled = false;
            if cursor.local_id > 0 {
                // **这条路只有四条判据, 第五条(已读段行数)不在**——如实写在这, 别再说"同一套五信号"。
                //
                // 我上一版想按表大小分(小表走 `Deep`), codex 一轮就指出**那个算不过来账**:
                // 这个 daemon **任一分片一变就把全部子源过一遍**, 而真库 2.1 万张表里绝大多数都是小表
                // —— "每张小表各自 Deep"加起来就是**每来一条消息就把 750 万行扫一遍**(约 18 秒/轮),
                // 正好把增量的意义抵消掉。按表分的阈值管不住**总量**。
                //
                // 所以这条路就是 `Shallow`: `oldest_fp` / `max_id` / `cursor_ct` / `cursor_sid` 四条,
                // 全是主键点查。**代价如实记**: "已读段被挖洞又补回"那一格(形态②)这条路盖不住 ——
                // 搜索索引会少那一条。消息采集和懒式刷新那两条路是盖得住的, 数据本身不丢。
                let probe = source
                    .rebuild_sentinel(snapshot, subsource, cursor.local_id, ProbeDepth::Shallow)
                    .await?;
                if thin_guard_says_rescan(&probe, &cursor) {
                    tracing::warn!(
                        etl_source = %etl_source,
                        "[thin] 源表换过了 / 游标位置不算数了 → 该会话从 0 重抽(瘦库幂等)"
                    );
                    cursor = DrainCursor::default();
                } else if let ResumeProbe::Found(p) = &probe {
                    // **补种**(独立复审 P2: 消息采集那条路 round-7 修过, 这条漏了) ——
                    // `server_id` 存的可能是 0("当时还没回执"), 已读段行数可能压根没建立过。
                    // 不补的话, 这个会话只要不再来新消息就**永远换不掉**(下面 `batch_max.is_some()`
                    // 才写水位), 那两道判据对它永久失效。
                    if cursor.cursor_sid.unwrap_or(0) == 0 && p.cursor_sid.unwrap_or(0) != 0 {
                        cursor.cursor_sid = p.cursor_sid;
                        meta_backfilled = true;
                    }
                    // (`prefix_rows` 不在这补: `Shallow` 探不到它, 补种条件恒不成立 —— codex 指出过
                    // 这是死代码。它由 drain 侧算术推进维护, 只是这条路不拿它做判据。)
                }
            }
            if meta_backfilled {
                // 本轮**未必有新行**, 而补种不落盘等于没补 → 单独写一次水位。
                let tx = thin.transaction().context("thin 事务开启失败")?;
                cursors.insert(etl_source.clone(), cursor.to_watermark_value());
                let j = serde_json::to_string(&cursors).unwrap_or_default();
                storage::set_thin_watermark(&tx, &j).context("写 thin 水位失败")?;
                tx.commit().context("thin 事务提交失败")?;
            }
            loop {
                let batch = source.drain_messages(snapshot, subsource, &cursor, batch_limit).await?;
                let has_more = batch.has_more;
                let next = batch.next_cursor;
                let batch_max = batch.rows.iter().map(|r| r.local_id).max();
                // 契约校验 (同 run_message_body): 非空批 next_cursor == 本批最大 local_id, 否则 advance 会跳过
                // (max, next] 区间的行 → 漏数据。失约即停 (不推进)。
                if let Some(m) = batch_max {
                    anyhow::ensure!(
                        next.local_id == m,
                        "DbSource 失约: 子源 {etl_source} next_cursor={} != 本批最大 local_id={m}",
                        next.local_id
                    );
                }
                let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

                // 一个事务: 本批正文全灌 + 游标 map 推进 → thin_meta。崩溃在 commit 前整批回滚 → 重启从旧
                // watermark 重抽 (rowid 幂等去重, 不重不漏)。
                {
                    let tx = thin.transaction().context("thin 事务开启失败")?;
                    for row in &batch.rows {
                        let native_id = msg_anchor(&subsource.conv_id, row.local_id);
                        let ctx = MessageContext {
                            account_id: account.clone(),
                            conv_id: subsource.conv_id.clone(),
                            source: snapshot.rel_name.clone(),
                            source_native_id: native_id.clone(),
                            ingest_time: 0, // thin 只索引正文, 不落 ingest_time。
                        };
                        // assemble 失败 (坏 BLOB) → 跳过 (thin 只搜正文, 无 SystemError 事件)。
                        if let Ok(mc) = assemble_message(row, &ctx) {
                            if !mc.text_content.is_empty() {
                                // rowid 键含 source 分片 (snapshot.rel_name) —— 与 build 侧 L1.message.source 同源,
                                // 防跨分片同锚撞键覆盖 (codex 复审 P1)。
                                storage::insert_thin_msg(
                                    &tx,
                                    thin_rowid(&snapshot.rel_name, &native_id),
                                    &snapshot.rel_name,
                                    &native_id,
                                    &mc.text_content,
                                )
                                .context("插 thin FTS 失败")?;
                                inserted += 1;
                            }
                        }
                    }
                    if batch_max.is_some() {
                        cursors.insert(etl_source.clone(), next.to_watermark_value());
                        let j = serde_json::to_string(&cursors).unwrap_or_default();
                        storage::set_thin_watermark(&tx, &j).context("写 thin 水位失败")?;
                    }
                    tx.commit().context("thin 事务提交失败")?;
                }

                if !has_more || !made_progress {
                    break;
                }
                cursor = next;
            }
        }
    }
    Ok(inserted)
}

/// 瘦库这条路的护栏判据 —— 跟 `pipeline::run_message_body` 里那套**同一个口径**, 只是简化了分支
/// (瘦库没有"计数/日志分类"的需要, 只要一个 yes/no)。
///
/// ⚠️ 两边判据必须一致, 不然会出现"L1 认为该重扫、瘦库认为不用"这种半边天。改这里先看那边。
fn thin_guard_says_rescan(probe: &ResumeProbe, cursor: &DrainCursor) -> bool {
    match probe {
        // 探不出来(非 Msg_ 表 / 测试假 source)→ 没意见, 别当成"被重建"。
        ResumeProbe::Unsupported => false,
        // 表空了而水位不为 0 → 聊天记录被清 / 换过表。
        ResumeProbe::Missing => true,
        ResumeProbe::Found(p) => match cursor.resume_fp {
            // 没有身份指纹 = 老水位(这条路上不该出现: map 格式一换就整体重建过了)→ 保守重抽。
            None => true,
            Some(was) => {
                p.oldest_fp != was                                   // 不是同一张表
                    || p.max_id < cursor.local_id                    // 表缩了
                    || p.cursor_ct != cursor.cursor_ct               // 游标那格换了人
                    || crate::pipeline::sid_conflict(p.cursor_sid, cursor.cursor_sid)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{thin_guard_says_rescan, thin_rowid};
    use crate::source::{DrainCursor, ResumeProbe, TableProbe};

    fn probe(oldest_fp: i64, max_id: i64, ct: i64, sid: i64, n: Option<i64>) -> ResumeProbe {
        ResumeProbe::Found(TableProbe {
            oldest_fp,
            max_id,
            cursor_ct: Some(ct),
            cursor_sid: Some(sid),
            prefix_rows: n,
        })
    }
    fn cur(local_id: i64, fp: i64, ct: i64, sid: i64, n: Option<i64>) -> DrainCursor {
        DrainCursor {
            local_id,
            resume_fp: Some(fp),
            cursor_ct: Some(ct),
            cursor_sid: Some(sid),
            prefix_rows: n,
        }
    }

    /// **瘦库护栏的判据表** —— 跟 `pipeline::run_message_body` 那套同口径。
    ///
    /// 这条路以前**一道护栏都没有**(比修之前的 L1 还弱: 连"游标比最大 id 还大"都没有),
    /// 源库被换成另一份副本时搜索结果会静默少一段。
    #[test]
    fn thin_guard_matches_the_pipeline_criteria() {
        let c = cur(10, 111, 700, 900, Some(10));
        // 全都对得上 → 不重抽。
        assert!(!thin_guard_says_rescan(&probe(111, 10, 700, 900, Some(10)), &c));
        // 表被重建(最老那行的指纹变了)。
        assert!(thin_guard_says_rescan(&probe(222, 10, 700, 900, Some(10)), &c));
        // 表缩了(换上更短的副本)。
        assert!(thin_guard_says_rescan(&probe(111, 8, 700, 900, Some(8)), &c));
        // 游标那一格换了人(时间不同)。
        assert!(thin_guard_says_rescan(&probe(111, 10, 701, 900, Some(10)), &c));
        // 游标那一格换了人(时间撞了, 靠 server_id 兜)。
        assert!(thin_guard_says_rescan(&probe(111, 10, 700, 901, Some(10)), &c));

        // ⚠️ **这条路没有第五条判据**(已读段行数): 深度写死 `Shallow`, 探回来恒 `None` ——
        // 所以"已读段被挖过洞"这一格**逮不着**, 搜索索引会少那一条。
        // 为什么不加: 这个 daemon 任一分片一变就把全部子源过一遍, 真库 2 万张表里绝大多数是小表,
        // "每张小表各自 Deep"加起来就是每来一条消息扫 750 万行(约 18 秒/轮), 按表分的阈值管不住总量。
        // 消息采集和懒式刷新那两条路盖得住这一格, **数据本身不丢**。
        assert!(!thin_guard_says_rescan(&probe(111, 10, 700, 900, Some(9)), &c));
        // 表空了而水位不为 0。
        assert!(thin_guard_says_rescan(&ResumeProbe::Missing, &c));
        // 探不出来 → 没意见, **不能**当成"被重建"(测试假 source / 非 Msg_ 表走这支)。
        assert!(!thin_guard_says_rescan(&ResumeProbe::Unsupported, &c));
        // 没有身份指纹 = 老水位 → 保守重抽。
        assert!(thin_guard_says_rescan(
            &probe(111, 10, 700, 900, Some(10)),
            &DrainCursor { resume_fp: None, ..c }
        ));
        // `server_id` 任一侧为 0 = "还不知道" → 不比这一项(不然自己发一条消息就全量重抽)。
        assert!(!thin_guard_says_rescan(&probe(111, 10, 700, 0, Some(10)), &c));
        // 已读段行数任一侧没有 → 不比这一项(Shallow 路径推的水位本来就可能没建立过)。
        assert!(!thin_guard_says_rescan(&probe(111, 10, 700, 900, None), &c));
    }

    /// **老水位 map 会被自动判成"整体重建一次"** —— 不用写迁移代码。
    ///
    /// 老格式的值是裸数字 `{"<键>": 123}`, 反序列化成 `BTreeMap<String, String>` 必失败 →
    /// 空 map → 本趟从 0 全重抽(rowid 幂等)。这正是想要的迁移动作。
    #[test]
    fn thin_old_watermark_map_forces_one_rebuild() {
        let old = r#"{"message_0.db|Msg_x":123,"message_1.db|Msg_y":45}"#;
        assert!(
            serde_json::from_str::<BTreeMap<String, String>>(old).is_err(),
            "老格式必须解析失败, 才会退成空 map = 整体重建一次"
        );
        let now = r#"{"message_0.db|Msg_x":"{\"id\":5,\"fp\":-42,\"ct\":7,\"sid\":9,\"n\":5}"}"#;
        let m: BTreeMap<String, String> = serde_json::from_str(now).expect("现行格式要解得开");
        let c = DrainCursor::from_watermark_value(&m["message_0.db|Msg_x"]).expect("水位串要解得开");
        assert_eq!((c.local_id, c.prefix_rows), (5, Some(5)));
    }

    #[test]
    fn thin_rowid_stable_positive_and_distinct() {
        let s0 = "message_0.db";
        let s1 = "message_1.db";
        let a = "Msg_0021db3ef9c0aa11bb22cc33dd44ee55:1";
        let b = "Msg_0021db3ef9c0aa11bb22cc33dd44ee55:2";
        // 稳定: 同 (source,msg_id) 恒同输出 (幂等去重的根据)。
        assert_eq!(
            thin_rowid(s0, a),
            thin_rowid(s0, a),
            "同 (source,msg_id) 必同 rowid (幂等去重依赖)"
        );
        // 恒非负 (右移 1 保正)。
        assert!(thin_rowid(s0, a) >= 0 && thin_rowid(s0, b) >= 0, "rowid 恒非负");
        // 不同 msg_id → 不同 rowid (仅差 local_id 尾也要区分, 否则同分片相邻消息互撞覆盖)。
        assert_ne!(thin_rowid(s0, a), thin_rowid(s0, b), "不同 msg_id 应不同 rowid");
        // **跨分片同锚必不同 rowid** (codex P1): 同一 source_native_id 在不同源分片是相异消息, 键含 source 才不撞。
        assert_ne!(
            thin_rowid(s0, a),
            thin_rowid(s1, a),
            "同 msg_id 不同 source(分片) 必不同 rowid"
        );
        // 0x1f 分隔防拼接歧义: ("message_0.db","x") 与 ("message_0.dbx","") 不得撞 (若无分隔符会撞)。
        assert_ne!(
            thin_rowid("message_0.db", "x"),
            thin_rowid("message_0.dbx", ""),
            "分隔符防拼接歧义撞键"
        );
        // 空串也稳定 (不 panic)。
        assert_eq!(thin_rowid("", ""), thin_rowid("", ""));
    }
}
