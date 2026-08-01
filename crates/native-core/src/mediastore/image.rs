//! 图片竖切(R10 §11-② 第三源, 照搬三层 · commit 脊复用)。图片最绕(message 分片 packed_info → md5 → .dat 候选 →
//! 解密/wxgf), 但整条**定位+解密**已在 [`fetch_image_one`](crate::media::image_export::fetch_image_one)(HTTP `/media/img`
//! 同款): materialize 直接调它拿 [`DecodedImage`], 再算 sha256 + stage。upstream_key = `talker:local_id`(对齐 serve
//! `img:{talker}:{local_id}` 键)—— 图片按**消息位**成组(同图多消息各自一组, 字节层去重合到一 asset)。

use std::ops::ControlFlow;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

use super::engine::{
    commit_materialized, fail_work, finish_work, open_work_item, record_attempt, CommitOutcome, DiscoveredItem,
    MaterializeFailure, MaterializeOutcome, Materialized, StoreLayout, WorkClaim,
};
use super::{AssetId, MediaKind};
use crate::decoder::{msg_anchor_from_talker_hex, parse_image_md5, DatFormat, ImageKey};
use crate::media::image_export::fetch_image_one_located;
use crate::media::ImageVariant;

/// 图片消息 `local_type`(微信 4.x)。
const LOCAL_TYPE_IMAGE: i64 = 3;

/// 枚举 message db 的 `Msg_<32hex>` 表(talker 分表)。文件级分片 message_0..N.db 由调用方 loop 多 conn。
fn msg_talker_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|t| {
            // 复审: 只认小写 32hex talker(与 L1 一致; 大写表 L1 无对应消息 = 孤立引用)。
            t.strip_prefix("Msg_").is_some_and(|talker| {
                talker.len() == 32 && talker.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
        })
        .collect();
    Ok(names)
}

/// **discover(流式 primitive, 块4)**: 遍历 `Msg_<talker>` 表图片消息, 每条能抽出定位 md5 的吐一个 [`DiscoveredItem`] 给
/// `on_item` —— **不 collect 进 Vec**(流式游标; 尤其 packed_info BLOB 不整表驻留)。峰值内存 O(1)。见收集版 [`image_discover`]。
///
/// # Errors
/// rusqlite 查询失败 / `on_item` 回调返错。
pub fn image_discover_each(
    msg_conn: &Connection,
    db_source: &str,
    mut on_item: impl FnMut(DiscoveredItem) -> Result<ControlFlow<()>>,
) -> Result<()> {
    for table in msg_talker_tables(msg_conn)? {
        let talker = table.strip_prefix("Msg_").unwrap_or(&table).to_string();
        let sql = format!(
            "SELECT local_id, packed_info_data FROM \"{table}\" WHERE local_type = {LOCAL_TYPE_IMAGE} AND packed_info_data IS NOT NULL"
        );
        let mut stmt = msg_conn.prepare(&sql).with_context(|| format!("准备扫 {table} 失败"))?;
        let mut rows = stmt.query([])?; // 块4: 流式游标, 不 `.collect::<Vec>`(packed BLOB 逐行处理不驻留)
        while let Some(row) = rows.next()? {
            let local_id: i64 = row.get(0)?;
            let packed: Vec<u8> = row.get(1)?;
            if parse_image_md5(&packed).is_none() {
                continue; // 非图片 packed_info / 畸形 → 跳
            }
            let item = DiscoveredItem {
                kind: MediaKind::ChatImage,
                // 复审 P1: source/source_native_id 对齐 L1 message(否则 media_reference 连不上消息)。
                // upstream_key 仍是**全 32hex talker:local_id**(serve 键 img:{talker}:{local_id}, 见 fetch_image_one 参数)。
                source_identity: db_source.to_string(),
                source: db_source.to_string(),
                source_native_id: msg_anchor_from_talker_hex(&talker, local_id),
                role: "image".into(),
                media_seq: 0,
                upstream_key: format!("{talker}:{local_id}"),
                declared_size: None, // 图片截断判定靠解码(fetch_image_one 只返解得开的真图), 无源声明字节数
            };
            if on_item(item)?.is_break() {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// **discover(收集版)**: [`image_discover_each`] 的 Vec 包装(测试等非流式调用方用; 生产 ingest 走 `_each` 流式)。
///
/// # Errors
/// rusqlite 查询失败。
pub fn image_discover(msg_conn: &Connection, db_source: &str) -> Result<Vec<DiscoveredItem>> {
    let mut items = Vec::new();
    image_discover_each(msg_conn, db_source, |item| {
        items.push(item);
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(items)
}

/// **materialize**:调 [`fetch_image_one`](完整 定位→解密→wxgf 管线, 取第一个解得开的真图)→ [`DecodedImage`] → sha256
/// → stage(按内容 hash 命名)。定位不到/全解不开/全缩略无 key → `Failed`。wxgf 容器按 derivation='wxgf' 存(转 GIF 是 §七 后续)。
///
/// `image_key` = 账号级 image key(件3 提取/手传; `None` 也能出 V0 缩略图, 见 fetch_image_one)。
///
/// # Errors
/// rusqlite / 写暂存失败。
pub fn image_materialize(
    item: &DiscoveredItem,
    msg_conn: &Connection,
    account_dir: &Path,
    image_key: Option<&ImageKey>,
    layout: &StoreLayout,
) -> Result<MaterializeOutcome> {
    // fetch_image_one 需 **talker(32hex) + local_id** 定位; 二者在 upstream_key="{talker}:{local_id}"(serve 键)里
    // ——不能用 source/source_native_id(那俩现是对齐 L1 的 message_N.db / Msg_<32hex>:<lid>, 不是定位用的 32hex talker)。
    let Some((talker, lid_str)) = item.upstream_key.rsplit_once(':') else {
        return Ok(MaterializeOutcome::Failed(MaterializeFailure::Decode(
            "upstream_key 格式错(缺 talker:local_id)".into(),
        )));
    };
    let Ok(local_id) = lid_str.parse::<i64>() else {
        return Ok(MaterializeOutcome::Failed(MaterializeFailure::Decode(
            "local_id 非整数".into(),
        )));
    };
    let Some((img, variant)) = fetch_image_one_located(msg_conn, account_dir, image_key, talker, local_id)? else {
        // 定位不到(微信已清理)/ 候选全解不开(错 key)/ 全 Unknown —— 无可收字节。
        return Ok(MaterializeOutcome::Failed(MaterializeFailure::SourceAbsent));
    };
    // fetch_image_one 已滤掉 Unknown, 故 format 必是真图格式。
    // 复审 F5a: clarity 按**命中的候选变体**记 —— 无 key 时命中的是 V0 缩略图(Thumb), 别硬标 original。
    // 完整/高清版后到时 preferred 按 clarity 升级(commit_materialized 重算逻辑), 实现缩略→原图切换。
    // clarity 取值须是账本 variant.clarity 的封闭枚举: 'original' / 'hd' / 'thumb'(CHECK 约束)。
    let clarity = match variant {
        ImageVariant::Full => "original",
        ImageVariant::High => "hd",
        ImageVariant::Thumb => "thumb",
    };
    let asset_id = {
        use sha2::Digest as _;
        let d: [u8; 32] = sha2::Sha256::digest(&img.bytes).into();
        AssetId::from_digest(&d)
    };
    let staged = layout.staging(asset_id.hex());
    if let Some(parent) = staged.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("建暂存目录 {} 失败", parent.display()))?;
    }
    std::fs::write(&staged, &img.bytes).with_context(|| format!("写暂存 {} 失败", staged.display()))?;
    let derivation = if img.format == DatFormat::Wxgf { "wxgf" } else { "none" };
    // 缩略图(V0 `_t.dat`)是**完整的低清文件**(非截断/坏数据), 故一律 Ready→done; clarity 已按命中变体记(thumb/hd/original)
    // 进 variant 表。完整图后到的**升级**由 §8 `--pending` 重探(按 clarity=thumb 扫)触发, **不靠 media-ingest 每轮重物化**
    // —— 复审二轮 codex P1-2 建议 thumb→verifying 可重入升级, 但多数图用户只有缩略图 → 会每轮重物化 + attempt 无界(P3-a
    // 放大), 故裁归 --pending 后续功能(升级机制未落地前, thumb 标 done 不丢数据、不空转)。
    Ok(MaterializeOutcome::Ready(Materialized {
        asset_id,
        size: i64::try_from(img.bytes.len()).unwrap_or(i64::MAX),
        ext: Some(img.format.ext().to_string()),
        mime: None,
        clarity: clarity.into(),
        derivation: derivation.into(),
        staged_path: staged,
    }))
}

/// 图片入库统计。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImageIngestStats {
    /// discover 到的图片消息数。
    pub discovered: usize,
    /// 新落盘 by-content。
    pub stored: usize,
    /// 内容去重命中。
    pub deduped: usize,
    /// 无可收(已清理/解不开)。
    pub failed: usize,
}

/// **驱动**:image_discover → 逐项 image_materialize → commit(一项一事务)→ 记 `source_scan`(coverage 诚实)。
/// 照搬 voice/video 韧性(单项错续跑)。`now` = UTC epoch。
///
/// # Errors
/// discover / source_scan 记录失败。
#[allow(clippy::too_many_arguments)]
pub fn run_image_ingest(
    msg_conn: &Connection,
    account_dir: &Path,
    image_key: Option<&ImageKey>,
    ledger_conn: &Connection,
    account_id_sha: &str,
    run_id: &str,
    db_source: &str,
    layout: &StoreLayout,
    limit: Option<usize>,
    now: i64,
) -> Result<ImageIngestStats> {
    let mut stats = ImageIngestStats::default();
    let mut truncated = false;
    let mut held = 0usize; // 块3: 被别的 worker 持活跃租而跳过的项数(>0 → coverage=partial)。
                           // 块4: **流式 discover**(不建全量 Vec + packed BLOB 不驻留)。discovered 逐项计(与旧 Vec 版 discovered=items.len() 等价:
                           // 达 limit 后仍流完全部计 discovered, 只 skip 入账 → truncated, 不 break 流)。
    image_discover_each(msg_conn, db_source, |item| -> Result<ControlFlow<()>> {
        stats.discovered += 1;
        if limit.is_some_and(|l| stats.stored + stats.deduped >= l) {
            truncated = true; // 达 limit: 继续流(计 discovered)但不入账 → coverage 记 partial
            return Ok(ControlFlow::Continue(()));
        }
        // 块1(F2)+块3(§12-B lease): 建/认领 work_item(拿 fencing 租约)+ 失败/成功记 attempt。已 done 跳过(codex P1);
        // 被别的 worker 持活跃租 → 本轮跳过 + coverage 记 partial(等其租 TTL 到期由后续轮接手)。
        let lease = match open_work_item(ledger_conn, run_id, account_id_sha, &item, 0, now)? {
            WorkClaim::Claimed(l) => l,
            WorkClaim::AlreadyDone => return Ok(ControlFlow::Continue(())), // 上轮已 done: 不重物化, 不计 limit。
            WorkClaim::HeldByOther { until, .. } => {
                tracing::info!(key = %item.upstream_key, until, "image: work 被别的 worker 持活跃租, 本轮跳过");
                held += 1;
                return Ok(ControlFlow::Continue(()));
            }
        };
        let work_id = lease.work_id.clone();
        let m = match image_materialize(&item, msg_conn, account_dir, image_key, layout) {
            Ok(MaterializeOutcome::Ready(m)) => m,
            // image_materialize 恒 Ready(缩略图是完整低清文件, 记 clarity=thumb 而非 partial)。防御(第三轮 Claude P3):
            // 万一将来给 image 加截断检测而产 Partial, 当异常**单项跳过**而非 unreachable! panic 炸整轮(守"单项错不炸整轮"韧性)。
            Ok(MaterializeOutcome::Partial(_)) => {
                tracing::warn!(key = %item.upstream_key, "image 意外产 Partial(当前不应发生), 计 failed 跳过");
                if let Err(e) = fail_work(ledger_conn, run_id, &lease, "unexpected_partial", now) {
                    tracing::warn!(key = %item.upstream_key, err = %e, "image 记失败 provenance 出错");
                }
                stats.failed += 1;
                return Ok(ControlFlow::Continue(()));
            }
            Ok(MaterializeOutcome::Failed(f)) => {
                if let Err(e) = fail_work(ledger_conn, run_id, &lease, f.code(), now) {
                    tracing::warn!(key = %item.upstream_key, err = %e, "image 记失败 provenance 出错");
                }
                stats.failed += 1;
                return Ok(ControlFlow::Continue(()));
            }
            Err(e) => {
                tracing::warn!(key = %item.upstream_key, err = %e, "image materialize 失败, 跳过");
                if let Err(e2) = fail_work(ledger_conn, run_id, &lease, "materialize_error", now) {
                    tracing::warn!(key = %item.upstream_key, err = %e2, "image 记失败 provenance 出错");
                }
                stats.failed += 1;
                return Ok(ControlFlow::Continue(()));
            }
        };
        let committed = (|| -> Result<CommitOutcome> {
            let tx = ledger_conn.unchecked_transaction()?;
            // image 恒 verified(缩略图是完整低清文件, 非坏数据); 升级归 §8 --pending(按 clarity 扫), 不靠此每轮重物化。
            let o = commit_materialized(ledger_conn, account_id_sha, layout, &item, &m, true, &lease, now)?;
            record_attempt(ledger_conn, run_id, &work_id, Some(m.asset_id.as_str()), None, now)?;
            // 块3: fenced finish(&lease)。成功路径同事务刚 commit CAS 过同租, 必命中 → ensure(防未来 lease 失序退化成静默不收尾)。
            anyhow::ensure!(
                finish_work(ledger_conn, &lease, "done", None, now)?,
                "image finish_work 未命中租约(不应发生: commit 同事务刚 CAS 过同一 lease)"
            );
            tx.commit()?;
            Ok(o)
        })();
        match committed {
            Ok(CommitOutcome::Stored) => stats.stored += 1,
            Ok(CommitOutcome::Deduped) => stats.deduped += 1,
            Err(e) => {
                tracing::warn!(key = %item.upstream_key, err = %e, "image commit 失败, 跳过");
                if let Err(e2) = fail_work(ledger_conn, run_id, &lease, "commit_error", now) {
                    tracing::warn!(key = %item.upstream_key, err = %e2, "image 记失败 provenance 出错");
                }
                stats.failed += 1;
            }
        }
        Ok(ControlFlow::Continue(()))
    })?;
    let coverage = if !truncated && stats.failed == 0 && held == 0 {
        "complete"
    } else {
        "partial"
    };
    // scope 用 kind 前缀(image 与 video 扫同一 message db, 裸 db_source 会互相覆盖覆盖度)。
    let scan_scope = format!("image:{db_source}");
    ledger_conn
        .execute(
            "INSERT INTO source_scan(source_identity,discovery_epoch,coverage,scanned_at) VALUES(?1,?2,?3,?2) \
             ON CONFLICT(source_identity) DO UPDATE SET discovery_epoch=excluded.discovery_epoch, coverage=excluded.coverage, scanned_at=excluded.scanned_at",
            rusqlite::params![scan_scope, now, coverage],
        )
        .context("记 source_scan 失败")?;
    Ok(stats)
}

// @@GUARD:PROD_END@@  生产段到此为止(本文件全 ON CONFLICT, 无 REPLACE)。
#[cfg(test)]
mod tests {
    use super::*;

    // 复用 image_export 测试里的定位夹具口径: packed_info(件2) + resolve_image + .dat 明文(V1 全局 key/明文段可无 key 解)。
    // 这里只验 discover 枚举正确(materialize 的真解密走 image_export 已有测试 + 真库跑); 造合法 packed_info 较重, 用真库坐实。
    const TALKER: &str = "b3010f26cfa89d420c8d8183bb3d5f5b";

    #[test]
    fn discover_filters_by_parseable_packed_info() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(&format!(
            "CREATE TABLE \"Msg_{TALKER}\" (local_id INTEGER, local_type INTEGER, packed_info_data BLOB);"
        ))
        .unwrap();
        // local_type=3 但 packed_info 畸形(parse_image_md5 抽不出)→ 不计; 非 3 → 不计。
        c.execute(
            &format!("INSERT INTO \"Msg_{TALKER}\" VALUES (1, 3, ?1), (2, 1, ?1)"),
            rusqlite::params![vec![0u8, 1, 2, 3]],
        )
        .unwrap();
        let items = image_discover(&c, "message_0").unwrap();
        assert!(
            items.is_empty(),
            "畸形 packed_info + 非图片消息都不计(parse_image_md5 None)"
        );
        assert!(items.iter().all(|i| i.kind == MediaKind::ChatImage));
    }

    /// 真跑坐实: 解密 message db + 真账号目录(msg/attach)→ discover→fetch_image_one(**key=None 走 V0 缩略图**, 不需 key)→
    /// commit。`cargo test -p native-core real_run_image_ingest -- --ignored --nocapture`(需 MSG_DB / ACCOUNT_DIR)。
    #[test]
    #[ignore = "真跑: 需 MSG_DB / ACCOUNT_DIR"]
    fn real_run_image_ingest() {
        let (Ok(msg), Ok(acct)) = (std::env::var("MSG_DB"), std::env::var("ACCOUNT_DIR")) else {
            eprintln!("跳过 real_run_image_ingest: 未设 MSG_DB/ACCOUNT_DIR");
            return;
        };
        let mc = Connection::open(&msg).unwrap();
        let dir = std::env::temp_dir().join(format!("ms_realrun_img_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = StoreLayout::new(&dir, "realrun");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger = super::super::ledger::open_ledger(&layout.ledger(), "rr_img_sha", 1_700_000_000).unwrap();
        // key=None: V0 缩略图不需 key(V2 完整图无 key 解不开会跳到 V0), 足以验通端到端。
        let stats = run_image_ingest(
            &mc,
            Path::new(&acct),
            None,
            &ledger,
            "rr_img_sha",
            "rr-run",
            "message_0",
            &layout,
            Some(30),
            1_700_000_000,
        )
        .unwrap();
        eprintln!("图片真跑(key=None) stats = {stats:?}");
        assert!(stats.discovered > 0, "应发现图片消息");
        let n_ref: i64 = ledger
            .query_row("SELECT count(*) FROM media_reference WHERE role='image'", [], |r| {
                r.get(0)
            })
            .unwrap();
        eprintln!(
            "图片 media_reference={n_ref}, stored={} deduped={} failed={}",
            stats.stored, stats.deduped, stats.failed
        );
        assert_eq!(n_ref as usize, stats.stored + stats.deduped, "media_reference = 入账数");
        if stats.stored > 0 {
            // 抽一个 asset, 核 by-content 文件在 + 有 asset_role='chat_image'。
            let hex: String = ledger
                .query_row("SELECT hex FROM asset LIMIT 1", [], |r| r.get(0))
                .unwrap();
            assert!(
                layout
                    .account_root()
                    .join("by-content")
                    .join(&hex[..2])
                    .join(&hex)
                    .exists(),
                "by-content 有图"
            );
            let roles: i64 = ledger
                .query_row("SELECT count(*) FROM asset_role WHERE kind='chat_image'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(roles > 0, "有 chat_image 角色");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
