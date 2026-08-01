//! 视频竖切(R10 §11-② 第二源, 照搬 [`super::voice`] 三层 —— 换 discover/materialize, **commit 脊复用**已审的
//! [`super::engine::commit_materialized`])。
//!
//! 与语音的关键区别(§三/项目记忆): ①视频**不解密不转码** —— 明文 .mp4 整文件按内容 hash 收进内容仓(加密的没账号级 key
//! → SourceAbsent 降级); ②定位靠**独立 hardlink 库**(md5 → 候选路径), 非 packed_info; ③md5 来自消息 content XML。
//! 复用现有 [`resolve_video`]/[`classify_video`]/[`decode_message_content`]/[`parse_media`](HTTP /media/vid 同款定位)。
//! 视频文件可能很大 → materialize **流式算 sha256 + fs::copy**(不整读进内存, 守 §三 低内存)。

use std::io::Read as _;
use std::ops::ControlFlow;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

use super::engine::{
    commit_materialized, fail_work, finish_work, open_work_item, record_attempt, CommitOutcome, DiscoveredItem,
    MaterializeFailure, MaterializeOutcome, Materialized, StoreLayout, WorkClaim,
};
use super::{AssetId, MediaKind};
use crate::decoder::{decode_message_content, msg_anchor_from_talker_hex, parse_media};
use crate::media::resolve::resolve_video;
use crate::media::video_detect::{classify_video, VideoKind, VIDEO_HEAD_LEN};

/// 视频消息 `local_type`(ADR-421; 微信 4.x)。
const LOCAL_TYPE_VIDEO: i64 = 43;

/// 枚举一个 message db 里的 `Msg_<32hex>` 表(talker 分表)。文件级分片 message_0..N.db 由调用方 loop 多 conn。
fn msg_talker_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|t| {
            // 复审: 只认**小写** 32hex talker —— 与 L1(account.rs 只接受小写)一致, 否则大写表进这边但 L1 没对应消息行 = 孤立引用。
            t.strip_prefix("Msg_").is_some_and(|talker| {
                talker.len() == 32 && talker.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
        })
        .collect();
    Ok(names)
}

/// **单遍** copy src→dst 同时算 sha256(复审 P1: 视频大不整读进内存; 且 hash 与落盘字节**同一次读**, 杜绝
/// "先 hash 后 copy" 两遍读到不同字节——微信仍在下载/替换文件时会让 staging 字节 ≠ asset_id, 污染内容仓)。返回 (digest, 字节数)。
fn copy_and_hash(src: &Path, dst: &Path) -> std::io::Result<([u8; 32], i64)> {
    use std::io::Write as _;

    use sha2::Digest as _;
    let mut fin = std::fs::File::open(src)?;
    let mut fout = std::fs::File::create(dst)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0i64;
    loop {
        let n = fin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        fout.write_all(&buf[..n])?;
        total += i64::try_from(n).unwrap_or(0);
    }
    fout.flush()?;
    Ok((hasher.finalize().into(), total))
}

/// 读文件头至多 `max` 字节(给 classify_video 判 ftyp)。不存在=Ok(None); 真 IO 错=Err。
fn read_head(path: &Path, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::File::open(path) {
        Ok(f) => {
            let mut buf = Vec::new();
            f.take(max as u64).read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// **discover(流式 primitive, 块4)**: 遍历 `Msg_<talker>` 表视频消息, 每条抽出小写 32hex md5 的吐一个 [`DiscoveredItem`]
/// 给 `on_item` —— **不 collect 进 Vec**(流式游标; message_content BLOB 逐行处理不驻留)。峰值内存 O(1)。见收集版 [`video_discover`]。
///
/// # Errors
/// rusqlite 查询失败 / `on_item` 回调返错。
pub fn video_discover_each(
    msg_conn: &Connection,
    db_source: &str,
    mut on_item: impl FnMut(DiscoveredItem) -> Result<ControlFlow<()>>,
) -> Result<()> {
    for table in msg_talker_tables(msg_conn)? {
        let talker = table.strip_prefix("Msg_").unwrap_or(&table).to_string();
        let sql = format!(
            "SELECT local_id, message_content FROM \"{table}\" WHERE local_type = {LOCAL_TYPE_VIDEO} AND message_content IS NOT NULL"
        );
        let mut stmt = msg_conn.prepare(&sql).with_context(|| format!("准备扫 {table} 失败"))?;
        let mut rows = stmt.query([])?; // 块4: 流式游标, 不 `.collect::<Vec>`(content BLOB 逐行处理不驻留)
        while let Some(row) = rows.next()? {
            let local_id: i64 = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let Ok(content) = decode_message_content(&blob) else {
                continue; // zstd 坏帧 → 跳
            };
            let Some(card) = parse_media(LOCAL_TYPE_VIDEO as i32, &content) else {
                continue; // 非 videomsg
            };
            let Some(md5) = card.md5.clone() else {
                continue; // 无 md5
            };
            // 复审 P1/P2: md5 必是**小写 32hex**, 三处一致用同一份原样 key(不转换)——
            //   ① 32hex → staging 文件名 + serve 键路径安全(挡 '/../' 穿越);
            //   ② md5 既是 hardlink 定位键(resolve_video `WHERE md5=?1` 是**大小写敏感** BINARY collation)又是 registry
            //      serve 键(vid:{md5}, serve 端小写化)—— **只认小写**(不用 is_ascii_hexdigit 收大写)让二者同源, 免「先
            //      to_lowercase 再撞大小写敏感 lookup」的 codex P2 回归 + raw-case 存进 registry 不可 serve 的 Claude P3。
            // WeChat md5 恒小写(真库 hardlink 200/message 30 全小写, 同 Msg_ 表名小写 = 同一 md5 计算); 大写非真数据且**必与
            // 小写 hardlink 失配无法定位** → 同大写 Msg_ 表一样一律 drop(非静默丢真数据, 是拒非-WeChat/损坏键)。
            if md5.len() != 32 || !md5.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                continue;
            }
            let item = DiscoveredItem {
                kind: MediaKind::Video,
                // 复审 P1: source/source_native_id 必须对齐 L1 message —— source=源库名(message_N.db), native_id=msg_anchor
                // (Msg_<完整talker>:<local_id>), 否则 media_reference 连不上 L1 消息(GC 撤销/"某消息的媒体"全对不上)。
                source_identity: db_source.to_string(),
                source: db_source.to_string(),
                source_native_id: msg_anchor_from_talker_hex(&talker, local_id),
                role: "video".into(),
                media_seq: 0,
                upstream_key: md5,                                             // serve 键 vid:{md5}
                declared_size: (card.file_size > 0).then_some(card.file_size), // F6: videomsg length = 截断判定基准
            };
            if on_item(item)?.is_break() {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// **discover(收集版)**: [`video_discover_each`] 的 Vec 包装(测试等非流式调用方用; 生产 ingest 走 `_each` 流式)。
///
/// # Errors
/// rusqlite 查询失败。
pub fn video_discover(msg_conn: &Connection, db_source: &str) -> Result<Vec<DiscoveredItem>> {
    let mut items = Vec::new();
    video_discover_each(msg_conn, db_source, |item| {
        items.push(item);
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(items)
}

/// RAII 卫士: `video_materialize` 的 pid-scoped tmp 暂存文件 —— 除非 `committed`(成功 rename 到最终 hash 名), 否则出
/// 作用域(含 copy/rename 失败早返 / panic)删掉 tmp。防 codex 复审 P2: 带 pid 的 tmp 出错不删会跨 run 累积视频大小的孤儿文件。
struct TmpCleanup<'a> {
    path: &'a Path,
    committed: bool,
}
impl Drop for TmpCleanup<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// mp4 顶层 box **结构**判定(复审 F6, 三态)。只读 box 头(seek 跳 box 体, 不整读几百 MB): 顶层 box 须**正好平铺到文件尾** +
/// `moov`+`mdat`。任一 box 超尾 / 头读不全 / 缺 moov|mdat / 读不动 = `Truncated`。**size-0 box**(延伸到 EOF, 必是末 box):
/// 只有 `mdat` 且 `moov` 已见(ftyp…moov…mdat-to-EOF 合法形)才 `Indeterminate`(截断判不了, 但可排在真截断之上、且**不当 verified**);
/// 缺 moov / 非 mdat 的 size-0 = `Truncated`。真库实测视频 **0/39** 用 size-0。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mp4Structure {
    Complete,
    Indeterminate,
    Truncated,
}

fn mp4_structure(path: &Path) -> Mp4Structure {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return Mp4Structure::Truncated;
    };
    let Ok(file_len) = f.metadata().map(|m| m.len()) else {
        return Mp4Structure::Truncated;
    };
    let mut off: u64 = 0;
    let (mut saw_moov, mut saw_mdat) = (false, false);
    while off < file_len {
        if off + 8 > file_len {
            return Mp4Structure::Truncated; // box 头都读不全 = 截断
        }
        if f.seek(SeekFrom::Start(off)).is_err() {
            return Mp4Structure::Truncated;
        }
        let mut hdr = [0u8; 8];
        if f.read_exact(&mut hdr).is_err() {
            return Mp4Structure::Truncated;
        }
        let size32 = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let btype = &hdr[4..8];
        let (box_size, header_len) = if size32 == 1 {
            // 64-bit largesize: 紧接 8 字节
            if off + 16 > file_len {
                return Mp4Structure::Truncated;
            }
            let mut ext = [0u8; 8];
            if f.read_exact(&mut ext).is_err() {
                return Mp4Structure::Truncated;
            }
            (u64::from_be_bytes(ext), 16u64)
        } else if size32 == 0 {
            // size=0 延伸到 EOF: 合法形(mdat + moov 已见)→ Indeterminate; 否则(缺 moov / 非 mdat)= 截断。
            return if btype == b"mdat" && saw_moov {
                Mp4Structure::Indeterminate
            } else {
                Mp4Structure::Truncated
            };
        } else {
            (u64::from(size32), 8u64)
        };
        if box_size < header_len {
            return Mp4Structure::Truncated; // 非法 box 长度(< 头本身)
        }
        if btype == b"moov" {
            saw_moov = true;
        } else if btype == b"mdat" {
            saw_mdat = true;
        }
        match off.checked_add(box_size) {
            Some(n) if n <= file_len => off = n,
            _ => return Mp4Structure::Truncated, // box 声明超出文件尾 = 截断
        }
    }
    if off == file_len && saw_moov && saw_mdat {
        Mp4Structure::Complete
    } else {
        Mp4Structure::Truncated // 平铺不到尾 / 缺 moov|mdat
    }
}

/// 落盘 size 是否满足源声明长度(无声明 → 不设限)。
fn declared_len_ok(size: i64, declared: Option<i64>) -> bool {
    match declared {
        Some(d) if d > 0 => size >= d,
        _ => true,
    }
}

/// 候选**择优排名**(F6 复审 codex: 有效 size-0 mp4 须能排在真截断之上, 别混同): Complete+达标=3 > Complete但比声明短=2 >
/// Indeterminate(size-0, 可 serve 但 unverifiable)=1 > Truncated=0。选最高分候选。
fn video_candidate_rank(path: &Path, size: i64, declared: Option<i64>) -> u8 {
    match mp4_structure(path) {
        Mp4Structure::Complete if declared_len_ok(size, declared) => 3,
        Mp4Structure::Complete => 2, // 结构完整但比声明短(别 rendition)
        Mp4Structure::Indeterminate => 1,
        Mp4Structure::Truncated => 0,
    }
}

/// 落盘视频是否**完整(可当 verified→Ready)**:**结构 Complete + declared-length 双闸**(codex+Claude 收敛, 缺一不可)。
/// 只有结构 `Complete`(平铺 + moov + mdat)**且** `size >= 声明`(有声明时)才算; `Indeterminate`(size-0)/ `Truncated` /
/// 比声明短 → 一律 **Partial**(不因 declared 达标放过; size-0 也不靠 declared 蒙混 —— 两审 6 轮收敛)。
///
/// `size` = 落盘字节数(materialize 用 copy 出来的权威值)。**err-safe**: 只会误判完整→Partial(inert), 绝不把截断/坏判 Ready。
fn video_is_complete(path: &Path, size: i64, declared: Option<i64>) -> bool {
    declared_len_ok(size, declared) && mp4_structure(path) == Mp4Structure::Complete
}

/// **materialize**:md5 → [`resolve_video`] 候选 → 逐候选探头 [`classify_video`], 取第一个**存在且明文**的 .mp4 → 流式 sha256
/// → copy 进 staging(按内容 hash 命名)。完整 mp4 → `Ready`; **截断/结构不完整 → `Partial`**(F6: 仍收字节但 verification
/// 不当已验证, 照 voice 截断 SILK 口径); 全加密/全不存在 → `Failed(SourceAbsent)`(§九 无明文缓存)。
///
/// `hardlink_conn` = 已解密视频 hardlink 库; `account_dir` = xwechat_files 账号目录(`msg/video/…` 所在)。
///
/// # Errors
/// rusqlite / IO(copy/hash)失败。
pub fn video_materialize(
    item: &DiscoveredItem,
    hardlink_conn: &Connection,
    account_dir: &Path,
    layout: &StoreLayout,
) -> Result<MaterializeOutcome> {
    let locs = resolve_video(hardlink_conn, &item.upstream_key)?;
    // F6(复审 P2): 候选**择优** —— 多个明文候选时优先取**完整**的(截断的非-raw 与完整的 dup 并存时别选到截断)。
    // 完整判优先 declared-length(源声明字节数, 25/25 实测 == 实际大小可靠), 无声明退 mp4 结构 box-walk。
    // F6(复审 codex): 候选**按 rank 择优** —— Complete+达标(3) > Complete但短(2) > Indeterminate size-0(1) > Truncated(0)。
    // 选最高分明文候选(有效 size-0 排在真截断之上, 别选到截断); rank==3 立即用(最优)。
    let mut best: Option<(u8, std::path::PathBuf)> = None;
    for loc in &locs {
        let p = account_dir.join(&loc.rel_path);
        if let Ok(Some(head)) = read_head(&p, VIDEO_HEAD_LEN) {
            if matches!(classify_video(&head), VideoKind::Plaintext) {
                let sz = std::fs::metadata(&p)
                    .map(|m| i64::try_from(m.len()).unwrap_or(i64::MAX))
                    .unwrap_or(0);
                let rank = video_candidate_rank(&p, sz, item.declared_size);
                let better = match &best {
                    Some((r, _)) => rank > *r,
                    None => true,
                };
                if better {
                    let top = rank == 3;
                    best = Some((rank, p));
                    if top {
                        break; // 最优完整候选, 停搜
                    }
                }
            }
        }
    }
    let Some((_, src)) = best else {
        // 有候选但全加密, 或全不存在 —— 都是"无明文可收"(视频不解密, 加密的没账号级 key)。
        return Ok(MaterializeOutcome::Failed(MaterializeFailure::SourceAbsent));
    };
    // 复审 P1: **单遍 copy+hash** —— 先 copy 到临时 staging, 一次读同时算 sha256(hash 与落盘字节必一致), 再按**内容 hash**
    // rename 到最终 staging 名(同卷原子)。tmp 名带 **进程 id**(md5 已在 discover 校验 32hex, 路径安全)—— 两个并发 ingest 进程
    // 用不同 pid, 不会互相 truncate 对方正在写的 tmp(否则 hasher 算的流 ≠ 最终 tmp 字节)。进程内串行, md5 足够区分。
    let tmp = layout.staging(&format!("vidtmp-{}-{}", std::process::id(), item.upstream_key));
    if let Some(parent) = tmp.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("建暂存目录 {} 失败", parent.display()))?;
    }
    // 复审 P2(codex): pid-scoped tmp 若出错不删会**跨 run 累积** —— 旧 `vidtmp-{md5}` 定名下轮覆盖=自限, 带 pid 后每 run/每次
    // 中断各留一份视频大小的文件, 无界增长。`TmpCleanup` RAII 卫士(模块级): 除非成功 rename 到最终名(committed), 否则出
    // 作用域(含 copy/rename 失败 `?` 早返)删掉 tmp。剩「进程被杀/断电」残留归 §11-④ 崩溃恢复兜(设计已排), 同任何 staging 固有残余。
    let mut cleanup = TmpCleanup {
        path: &tmp,
        committed: false,
    };
    let (digest, size) = copy_and_hash(&src, &tmp).with_context(|| format!("copy+hash 视频 {} 失败", src.display()))?;
    let asset_id = AssetId::from_digest(&digest);
    let staged = layout.staging(asset_id.hex());
    if tmp != staged {
        std::fs::rename(&tmp, &staged).with_context(|| format!("暂存按 hash 改名到 {} 失败", staged.display()))?;
    }
    cleanup.committed = true; // tmp 已 rename 走(或本就是 staged), 卫士不再删。
                              // F6(复审收敛): 完整性判在**落盘字节**上(staged 文件 + copy 出来的权威 `size`), 非另读 src —— 杜绝 TOCTOU。
                              // video_is_complete = **结构 box-walk + declared-length 双闸**: 结构截断一律 Partial(不被 declared 达标放过), size-0 靠 declared 兜。
    let complete = video_is_complete(&staged, size, item.declared_size);
    let m = Materialized {
        asset_id,
        size,
        ext: Some("mp4".into()),
        mime: Some("video/mp4".into()),
        clarity: "original".into(),
        derivation: "none".into(), // 明文原文件, 不转码
        staged_path: staged,
    };
    Ok(if complete {
        MaterializeOutcome::Ready(m)
    } else {
        MaterializeOutcome::Partial(m)
    })
}

/// 视频入库统计。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VideoIngestStats {
    /// discover 到的视频消息数。
    pub discovered: usize,
    /// 新落盘 by-content。
    pub stored: usize,
    /// 内容去重命中。
    pub deduped: usize,
    /// 截断/结构不完整 mp4(仍入仓但 verification 未验证; F6)。stored/deduped 的子集计数。
    pub partial: usize,
    /// 无明文可收(全加密/已清理)。
    pub failed: usize,
}

/// **驱动**:video_discover → 逐项 video_materialize → commit(一项一事务)→ 记 `source_scan`(§12-C: 只全成功才 complete)。
/// `limit` = 最多入账多少(None 全部)。`now` = UTC epoch。单项 materialize/commit 出错只计 failed 续跑(照搬 voice 韧性)。
///
/// # Errors
/// discover / source_scan 记录失败。
#[allow(clippy::too_many_arguments)]
pub fn run_video_ingest(
    msg_conn: &Connection,
    hardlink_conn: &Connection,
    account_dir: &Path,
    ledger_conn: &Connection,
    account_id_sha: &str,
    run_id: &str,
    db_source: &str,
    layout: &StoreLayout,
    limit: Option<usize>,
    now: i64,
) -> Result<VideoIngestStats> {
    let mut stats = VideoIngestStats::default();
    let mut truncated = false;
    let mut held = 0usize; // 块3: 被别的 worker 持活跃租而跳过的项数(>0 → coverage=partial)。
                           // 块4: **流式 discover**(不建全量 Vec + content BLOB 不驻留)。discovered 逐项计(与旧 Vec 版等价: 达 limit 仍流完计, 只 skip 入账)。
    video_discover_each(msg_conn, db_source, |item| -> Result<ControlFlow<()>> {
        stats.discovered += 1;
        if limit.is_some_and(|l| stats.stored + stats.deduped >= l) {
            truncated = true; // 达 limit: 继续流(计 discovered)但不入账 → coverage 记 partial
            return Ok(ControlFlow::Continue(()));
        }
        // 块1(F2)+块3(§12-B lease): 建/认领 work_item(拿 fencing 租约)+ 失败/成功都记 attempt。已 done 跳过(codex P1);
        // 被别的 worker 持活跃租 → 本轮跳过 + coverage 记 partial(等其租 TTL 到期由后续轮接手)。
        let lease = match open_work_item(ledger_conn, run_id, account_id_sha, &item, 0, now)? {
            WorkClaim::Claimed(l) => l,
            WorkClaim::AlreadyDone => return Ok(ControlFlow::Continue(())), // 上轮已 done: 不重物化, 不计 limit。
            WorkClaim::HeldByOther { until, .. } => {
                tracing::info!(md5 = %item.upstream_key, until, "video: work 被别的 worker 持活跃租, 本轮跳过");
                held += 1;
                return Ok(ControlFlow::Continue(()));
            }
        };
        let work_id = lease.work_id.clone();
        let (m, verified) = match video_materialize(&item, hardlink_conn, account_dir, layout) {
            Ok(MaterializeOutcome::Ready(m)) => (m, true),
            Ok(MaterializeOutcome::Partial(m)) => (m, false), // F6: 截断 mp4, 入仓但不当已验证
            Ok(MaterializeOutcome::Failed(f)) => {
                if let Err(e) = fail_work(ledger_conn, run_id, &lease, f.code(), now) {
                    tracing::warn!(md5 = %item.upstream_key, err = %e, "video 记失败 provenance 出错");
                }
                stats.failed += 1;
                return Ok(ControlFlow::Continue(()));
            }
            Err(e) => {
                tracing::warn!(md5 = %item.upstream_key, err = %e, "video materialize 失败, 跳过");
                if let Err(e2) = fail_work(ledger_conn, run_id, &lease, "materialize_error", now) {
                    tracing::warn!(md5 = %item.upstream_key, err = %e2, "video 记失败 provenance 出错");
                }
                stats.failed += 1;
                return Ok(ControlFlow::Continue(()));
            }
        };
        let committed = (|| -> Result<CommitOutcome> {
            let tx = ledger_conn.unchecked_transaction()?;
            let o = commit_materialized(ledger_conn, account_id_sha, layout, &item, &m, verified, &lease, now)?;
            record_attempt(ledger_conn, run_id, &work_id, Some(m.asset_id.as_str()), None, now)?;
            // verified=完整 → done(重扫跳过); partial(F6 截断, verified=false) → verifying —— 非终态, 允许完整版重入升级(codex P1)。
            // 块3: fenced finish(&lease)。成功路径同事务刚 commit CAS 过同租, 必命中 → ensure(防未来 lease 失序退化成静默不收尾)。
            anyhow::ensure!(
                finish_work(
                    ledger_conn,
                    &lease,
                    if verified { "done" } else { "verifying" },
                    None,
                    now
                )?,
                "video finish_work 未命中租约(不应发生: commit 同事务刚 CAS 过同一 lease)"
            );
            tx.commit()?;
            Ok(o)
        })();
        match committed {
            Ok(outcome) => {
                match outcome {
                    CommitOutcome::Stored => stats.stored += 1,
                    CommitOutcome::Deduped => stats.deduped += 1,
                }
                if !verified {
                    stats.partial += 1; // F6: 截断计数(stored/deduped 的子集)
                }
            }
            Err(e) => {
                tracing::warn!(md5 = %item.upstream_key, err = %e, "video commit 失败, 跳过");
                if let Err(e2) = fail_work(ledger_conn, run_id, &lease, "commit_error", now) {
                    tracing::warn!(md5 = %item.upstream_key, err = %e2, "video 记失败 provenance 出错");
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
    // source_scan 的 scope 用 **kind 前缀**("video:{db_source}") —— video 与 image 扫同一 message db, 若都用裸 db_source
    // 会互相覆盖对方的覆盖度(§12-C)。media_reference.source 才用裸 db_source(对齐 L1)。
    let scan_scope = format!("video:{db_source}");
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

    const TALKER: &str = "b3010f26cfa89d420c8d8183bb3d5f5b";
    const VMD5: &str = "41318a6159dd261d3f10a19d6bf72dd1";

    // 复审 P2 回归: TmpCleanup 卫士未 committed 出作用域必删 tmp(= video_materialize copy/rename 失败 `?` 早返的清理契约,
    // 防 pid-scoped tmp 跨 run 累积); committed 后保留(rename 成功已把它搬走)。直接测卫士逻辑, 不需重建全物化夹具。
    #[test]
    fn tmp_cleanup_removes_uncommitted_keeps_committed() {
        let dir = std::env::temp_dir().join(format!("mediastore_tmpguard_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let uncommitted = dir.join("uncommitted.part");
        std::fs::write(&uncommitted, b"partial-copy").unwrap();
        {
            let _g = TmpCleanup {
                path: &uncommitted,
                committed: false,
            };
        }
        assert!(
            !uncommitted.exists(),
            "未 committed 的 tmp 出作用域必删(copy/rename 失败清理)"
        );
        let committed = dir.join("committed.part");
        std::fs::write(&committed, b"kept").unwrap();
        {
            let _g = TmpCleanup {
                path: &committed,
                committed: true,
            };
        }
        assert!(committed.exists(), "committed 的 tmp 保留(rename 成功已搬走, 卫士不动)");
        std::fs::remove_dir_all(&dir).ok();
    }

    // 复审 F6 收敛回归: mp4_structure_complete + video_is_complete **结构+declared 双闸**(codex P1 + Claude P2)。
    #[test]
    fn mp4_structure_and_completeness() {
        fn box_bytes(size: u32, typ: [u8; 4], body_len: usize) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&size.to_be_bytes());
            v.extend_from_slice(&typ);
            v.extend(std::iter::repeat(0u8).take(body_len));
            v
        }
        let dir = std::env::temp_dir().join(format!("mediastore_mp4_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // 完整: ftyp(16)+moov(16)+mdat(16)=48。
        let mut complete = Vec::new();
        complete.extend(box_bytes(16, *b"ftyp", 8));
        complete.extend(box_bytes(16, *b"moov", 8));
        complete.extend(box_bytes(16, *b"mdat", 8));
        let p_ok = dir.join("ok.mp4");
        std::fs::write(&p_ok, &complete).unwrap();
        assert_eq!(mp4_structure(&p_ok), Mp4Structure::Complete);
        assert!(
            video_is_complete(&p_ok, 48, Some(48)),
            "结构完整 + declared 达标 → 完整"
        );
        assert!(
            !video_is_complete(&p_ok, 48, Some(100)),
            "结构完整但比声明短 → 不完整(缺声明字节)"
        );
        assert!(video_is_complete(&p_ok, 48, None), "无声明 → 只看结构");

        // 截断: 末 mdat 声明 16 但砍到只剩 12 → 超出文件尾。
        let p_trunc = dir.join("trunc.mp4");
        std::fs::write(&p_trunc, &complete[..44]).unwrap();
        assert_eq!(mp4_structure(&p_trunc), Mp4Structure::Truncated);
        // **Claude P2**: 结构截断 → 一律不完整, **即使 declared 达标**(truncated _raw 比压缩版 length 大的情形)。
        assert!(
            !video_is_complete(&p_trunc, 44, Some(10)),
            "结构截断不被 declared 达标放过"
        );

        // 同长度但结构坏(缺 moov): ftyp+mdat 平铺到尾但无元数据。
        let mut no_moov = Vec::new();
        no_moov.extend(box_bytes(16, *b"ftyp", 8));
        no_moov.extend(box_bytes(16, *b"mdat", 8));
        let p_nomoov = dir.join("nomoov.mp4");
        std::fs::write(&p_nomoov, &no_moov).unwrap();
        assert_eq!(mp4_structure(&p_nomoov), Mp4Structure::Truncated);
        // **codex P1**: 同长度(size==declared)但结构坏 → 不完整(不只按字节数)。
        assert!(
            !video_is_complete(&p_nomoov, 32, Some(32)),
            "同长度结构坏不被 declared 放过"
        );

        // size-0 mdat(有 moov): Indeterminate —— **不当 verified**(不靠 declared 放过), 但 **rank 高于真截断**(codex 第6轮)。
        let mut size0 = Vec::new();
        size0.extend(box_bytes(16, *b"ftyp", 8));
        size0.extend(box_bytes(16, *b"moov", 8));
        size0.extend(box_bytes(0, *b"mdat", 8)); // size=0 延伸到 EOF
        let p_size0 = dir.join("size0.mp4");
        std::fs::write(&p_size0, &size0).unwrap();
        assert_eq!(
            mp4_structure(&p_size0),
            Mp4Structure::Indeterminate,
            "size-0 mdat + moov = Indeterminate"
        );
        assert!(
            !video_is_complete(&p_size0, 40, Some(40)),
            "size-0 即使 declared 达标也不当 verified(Partial)"
        );
        assert!(!video_is_complete(&p_size0, 40, None), "size-0 无声明也 Partial");
        // **codex 第6轮**: 有效 size-0(Indeterminate)候选 rank 须**高于**真截断, 择优别选到截断。
        assert!(
            video_candidate_rank(&p_size0, 40, Some(40)) > video_candidate_rank(&p_trunc, 44, Some(10)),
            "有效 size-0 rank 高于真截断"
        );
        assert_eq!(video_candidate_rank(&p_ok, 48, Some(48)), 3, "完整+达标 rank 3");
        assert_eq!(video_candidate_rank(&p_ok, 48, Some(100)), 2, "完整但比声明短 rank 2");

        // ftyp + size-0 mdat **无 moov**(codex 明列): Truncated + 判不完整。
        let mut size0_nomoov = Vec::new();
        size0_nomoov.extend(box_bytes(16, *b"ftyp", 8));
        size0_nomoov.extend(box_bytes(0, *b"mdat", 8));
        let p_s0nm = dir.join("size0_nomoov.mp4");
        std::fs::write(&p_s0nm, &size0_nomoov).unwrap();
        assert_eq!(
            mp4_structure(&p_s0nm),
            Mp4Structure::Truncated,
            "size-0 缺 moov = Truncated"
        );
        assert!(
            !video_is_complete(&p_s0nm, 24, Some(24)),
            "ftyp+size-0-mdat 缺 moov → Partial"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // videomsg length **= plaintext_mp4() 的字节数(48)** —— F6 用 declared-length 判截断, 夹具的声明长度须与完整字节对齐,
    // 否则完整 mp4 会被判截断。truncated_mp4()(44)< 48 → 走 Partial。
    fn video_content() -> Vec<u8> {
        let xml = format!(
            r#"<msg><videomsg aeskey="d1c6" cdnvideourl="3057vid" length="48" playlength="5" md5="{VMD5}" newmd5="dddddddddddddddddddddddddddddddd" /></msg>"#
        );
        zstd::stream::encode_all(xml.as_bytes(), 0).unwrap()
    }
    fn msg_db(rows: &[(i64, Vec<u8>)]) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(&format!(
            "CREATE TABLE \"Msg_{TALKER}\" (local_id INTEGER, local_type INTEGER, message_content BLOB);"
        ))
        .unwrap();
        for (lid, content) in rows {
            c.execute(
                &format!("INSERT INTO \"Msg_{TALKER}\" (local_id, local_type, message_content) VALUES (?1, 43, ?2)"),
                rusqlite::params![lid, content],
            )
            .unwrap();
        }
        c
    }
    fn hardlink_db(file_name: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE dir2id (username TEXT);
             CREATE TABLE video_hardlink_info_v4 (md5 TEXT, file_name TEXT, dir1 INTEGER, dir2 INTEGER);",
        )
        .unwrap();
        c.execute("INSERT INTO dir2id (rowid, username) VALUES (1,'2024-09')", [])
            .unwrap();
        c.execute(
            "INSERT INTO video_hardlink_info_v4 (md5, file_name, dir1, dir2) VALUES (?1, ?2, 1, 0)",
            rusqlite::params![VMD5, file_name],
        )
        .unwrap();
        c
    }
    // 完整 mp4: ftyp + moov + mdat, box 平铺到 EOF —— 过 classify_video 的 ftyp 头判 **和** mp4_is_complete 的结构判(F6)。
    fn plaintext_mp4() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&16u32.to_be_bytes());
        v.extend_from_slice(b"ftyp");
        v.extend_from_slice(b"isom\0\0\x02\0");
        v.extend_from_slice(&16u32.to_be_bytes());
        v.extend_from_slice(b"moov");
        v.extend_from_slice(&[0u8; 8]);
        v.extend_from_slice(&16u32.to_be_bytes());
        v.extend_from_slice(b"mdat");
        v.extend_from_slice(&[0u8; 8]);
        v
    }

    // 截断 mp4: ftyp 头正常(过明文判)但末 mdat 声明超出文件尾 → mp4_is_complete=false → 物化为 Partial(F6)。
    fn truncated_mp4() -> Vec<u8> {
        let mut v = plaintext_mp4();
        v.truncate(v.len() - 4); // 砍掉 mdat 尾 4 字节
        v
    }

    #[test]
    fn discover_finds_video_md5() {
        let mc = msg_db(&[(7, video_content()), (9, video_content())]);
        let items = video_discover(&mc, "message_0.db").unwrap();
        assert_eq!(items.len(), 2);
        assert!(items
            .iter()
            .all(|i| i.kind == MediaKind::Video && i.upstream_key == VMD5 && i.role == "video"));
        // 复审 P1: source = 源库名(对齐 L1), source_native_id = msg_anchor(Msg_<完整talker>:<local_id>; R14 全 32 位)。
        assert_eq!(items[0].source, "message_0.db");
        assert_eq!(
            items[0].source_native_id,
            format!("Msg_{}:7", TALKER.to_ascii_lowercase())
        );
    }

    // 复审 P3(收尾): 锁死「大写 md5 一律 drop」—— 镜像 is_msg_table 的大写拒收测试, 防 validator 回退到 is_ascii_hexdigit
    // (大写 md5 非真 WeChat 数据、且必与小写 hardlink 失配无法定位; 收窄小写-only 是刻意决策, 非 bug)。
    #[test]
    fn discover_drops_uppercase_md5() {
        let xml = format!(
            r#"<msg><videomsg aeskey="d1c6" cdnvideourl="3057vid" length="936153" playlength="5" md5="{}" newmd5="dddddddddddddddddddddddddddddddd" /></msg>"#,
            VMD5.to_ascii_uppercase()
        );
        let content = zstd::stream::encode_all(xml.as_bytes(), 0).unwrap();
        let mc = msg_db(&[(1, content)]);
        let items = video_discover(&mc, "message_0.db").unwrap();
        assert!(items.is_empty(), "大写 md5 的视频消息必被 validator drop(小写-only)");
    }

    #[test]
    fn ingest_plaintext_video_stores_to_cas() {
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("clip.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let account_dir = tmp.path().join("acct");
        let vpath = account_dir.join("msg").join("video").join("2024-09").join("clip.mp4");
        std::fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        std::fs::write(&vpath, plaintext_mp4()).unwrap();

        let store = tmp.path().join("store");
        let layout = StoreLayout::new(&store, "acctV");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger = super::super::ledger::open_ledger(&layout.ledger(), "acctV_sha", 1000).unwrap();

        let stats = run_video_ingest(
            &mc,
            &hc,
            &account_dir,
            &ledger,
            "acctV_sha",
            "test-run",
            "message_0",
            &layout,
            None,
            1000,
        )
        .unwrap();
        assert_eq!(
            stats,
            VideoIngestStats {
                discovered: 1,
                stored: 1,
                deduped: 0,
                partial: 0,
                failed: 0
            }
        );
        // by-content 落了明文 mp4 字节。
        let hex: String = ledger
            .query_row("SELECT hex FROM asset LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let p = layout.account_root().join("by-content").join(&hex[..2]).join(&hex);
        assert_eq!(std::fs::read(&p).unwrap(), plaintext_mp4(), "by-content = 原 mp4 字节");
        // registry 是 video:{md5}, source_scan complete。
        let reg: i64 = ledger
            .query_row(
                "SELECT count(*) FROM asset_registry WHERE ref_kind='video' AND ref_key=?1",
                [VMD5],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reg, 1);
        let cov: String = ledger
            .query_row("SELECT coverage FROM source_scan", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cov, "complete", "全成功无截断 → complete");
    }

    /// 块4双审 a47f40 P3-a: `--limit` 截断语义 —— **三条**同 md5 视频, limit=None / Some(1), 核 stats 与旧 Vec-break 版逐字段
    /// 一致。**关键(用 3 条非 2 条)**: option-b「达 limit 仍流完全部计 discovered」vs option-a「break 早停」在 limit 命中项**之后
    /// 还有项**时才有别 —— 3 条 limit=1: option-b discovered=3(与旧 Vec items.len()=3 一致), option-a 会=2(break 后不计第3条)。
    #[test]
    fn ingest_video_limit_truncates_equivalently() {
        let plaintext = plaintext_mp4();
        // 建一套 fresh 夹具(每次 ingest 独立账本/账号目录)。
        let mk = |tmp: &std::path::Path| {
            let account_dir = tmp.join("acct");
            let vpath = account_dir.join("msg").join("video").join("2024-09").join("clip.mp4");
            std::fs::create_dir_all(vpath.parent().unwrap()).unwrap();
            std::fs::write(&vpath, &plaintext).unwrap();
            let layout = StoreLayout::new(&tmp.join("store"), "acctV");
            std::fs::create_dir_all(layout.account_root()).unwrap();
            let ledger = super::super::ledger::open_ledger(&layout.ledger(), "acctV_sha", 1000).unwrap();
            (account_dir, layout, ledger)
        };
        let hc = hardlink_db("clip.mp4");
        // limit=None: 三条同 md5 都处理 → item0 Stored, item1/item2 同 md5 Deduped。discovered=3。
        let t1 = tempfile::tempdir().unwrap();
        let mc1 = msg_db(&[(7, video_content()), (8, video_content()), (9, video_content())]);
        let (ad1, ly1, lg1) = mk(t1.path());
        let s_none = run_video_ingest(&mc1, &hc, &ad1, &lg1, "acctV_sha", "r", "message_0", &ly1, None, 1000).unwrap();
        assert_eq!(
            s_none,
            VideoIngestStats {
                discovered: 3,
                stored: 1,
                deduped: 2,
                partial: 0,
                failed: 0
            },
            "块4 limit=None: 3 条同 md5 → Stored + 2 Deduped, discovered=3"
        );
        // limit=Some(1): item0 Stored 后 stored>=1 → item1/item2 在 open_work_item/materialize **前**短路; option-b 仍流完
        // 计 discovered=3(与旧 Vec 版 items.len()=3 一致), stored=1, deduped=0, coverage=partial。
        let t2 = tempfile::tempdir().unwrap();
        let mc2 = msg_db(&[(7, video_content()), (8, video_content()), (9, video_content())]);
        let (ad2, ly2, lg2) = mk(t2.path());
        let s_lim = run_video_ingest(
            &mc2,
            &hc,
            &ad2,
            &lg2,
            "acctV_sha",
            "r",
            "message_0",
            &ly2,
            Some(1),
            1000,
        )
        .unwrap();
        assert_eq!(
            s_lim,
            VideoIngestStats {
                discovered: 3,
                stored: 1,
                deduped: 0,
                partial: 0,
                failed: 0
            },
            "块4 limit=1: discovered 计全部 3(option-b 流完, 非 break 后 =2)但只入账 1, 与旧 Vec items.len()=3 一致"
        );
        let cov: String = lg2
            .query_row("SELECT coverage FROM source_scan", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cov, "partial", "块4 limit 截断 → coverage=partial");
    }

    #[test]
    fn ingest_encrypted_video_counts_failed() {
        // hardlink 命中但盘上无文件 → 无明文可收 → failed, coverage=partial。
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("gone.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let account_dir = tmp.path().join("acct");
        std::fs::create_dir_all(&account_dir).unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctV");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger = super::super::ledger::open_ledger(&layout.ledger(), "acctV_sha", 1000).unwrap();
        let stats = run_video_ingest(
            &mc,
            &hc,
            &account_dir,
            &ledger,
            "acctV_sha",
            "test-run",
            "message_0",
            &layout,
            None,
            1000,
        )
        .unwrap();
        assert_eq!(
            stats,
            VideoIngestStats {
                discovered: 1,
                stored: 0,
                deduped: 0,
                partial: 0,
                failed: 1
            }
        );
        let cov: String = ledger
            .query_row("SELECT coverage FROM source_scan", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cov, "partial", "有失败 → partial(诚实)");
    }

    // 复审 F6 端到端: 截断的明文 mp4(过 classify 明文判但结构不完整)→ 入仓但计 partial + verification 不当已验证。
    #[test]
    fn ingest_truncated_video_marks_partial() {
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("clip.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let account_dir = tmp.path().join("acct");
        let vpath = account_dir.join("msg").join("video").join("2024-09").join("clip.mp4");
        std::fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        std::fs::write(&vpath, truncated_mp4()).unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctV");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger = super::super::ledger::open_ledger(&layout.ledger(), "acctV_sha", 1000).unwrap();
        let stats = run_video_ingest(
            &mc,
            &hc,
            &account_dir,
            &ledger,
            "acctV_sha",
            "test-run",
            "message_0",
            &layout,
            None,
            1000,
        )
        .unwrap();
        assert_eq!(
            stats,
            VideoIngestStats {
                discovered: 1,
                stored: 1,
                deduped: 0,
                partial: 1,
                failed: 0
            },
            "截断 mp4: 入仓但计 partial"
        );
        // verification 状态不是 verified(截断不当已验证)。
        let vstate: String = ledger
            .query_row("SELECT state FROM verification LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_ne!(vstate, "verified", "截断 mp4 verification 不当已验证");
    }

    // 复审 P1-a 端到端: 截断版先入库当上 preferred, 完整版后到必须**升级顶替** preferred —— 否则 MediaRef 永远指截断字节。
    #[test]
    fn complete_reingest_promotes_preferred_over_partial() {
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("clip.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let account_dir = tmp.path().join("acct");
        let vpath = account_dir.join("msg").join("video").join("2024-09").join("clip.mp4");
        std::fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        let layout = StoreLayout::new(&tmp.path().join("store"), "acctV");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger = super::super::ledger::open_ledger(&layout.ledger(), "acctV_sha", 1000).unwrap();
        let group = format!("video:{VMD5}");

        // 1) 截断版先入库 → partial, 先占 preferred(让组可 serve)。
        std::fs::write(&vpath, truncated_mp4()).unwrap();
        let s1 = run_video_ingest(
            &mc,
            &hc,
            &account_dir,
            &ledger,
            "acctV_sha",
            "test-run",
            "message_0",
            &layout,
            None,
            1000,
        )
        .unwrap();
        assert_eq!(s1.partial, 1, "截断版计 partial");
        let partial_pref: Option<String> = ledger
            .query_row(
                "SELECT preferred_asset_id FROM logical_media WHERE logical_group_id=?1",
                [&group],
                |r| r.get(0),
            )
            .unwrap();
        assert!(partial_pref.is_some(), "截断版先占 preferred");

        // 2) 完整版再入库(同 md5, 不同字节 → 不同 sha, verified)→ 顶替 preferred。
        std::fs::write(&vpath, plaintext_mp4()).unwrap();
        let s2 = run_video_ingest(
            &mc,
            &hc,
            &account_dir,
            &ledger,
            "acctV_sha",
            "test-run",
            "message_0",
            &layout,
            None,
            1000,
        )
        .unwrap();
        assert_eq!(s2.stored, 1, "完整版新字节入库");
        assert_eq!(s2.partial, 0, "完整版不计 partial");
        let complete_pref: Option<String> = ledger
            .query_row(
                "SELECT preferred_asset_id FROM logical_media WHERE logical_group_id=?1",
                [&group],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(complete_pref, partial_pref, "完整 verified 版顶替截断版当 preferred");
        // preferred 现指 verified 资产。
        let pref_state: String = ledger
            .query_row(
                "SELECT v.state FROM verification v JOIN logical_media lm ON v.asset_id=lm.preferred_asset_id \
                 WHERE lm.logical_group_id=?1",
                [&group],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pref_state, "verified", "preferred 现指完整 verified 资产");
    }

    /// 真跑坐实: 解密 message db + hardlink 库 + 真账号目录 → 整条 discover→定位→sha256→commit。
    /// `cargo test -p native-core real_run_video_ingest -- --ignored --nocapture`(需 MSG_DB / HARDLINK_DB / ACCOUNT_DIR)。
    #[test]
    #[ignore = "真跑: 需 MSG_DB / HARDLINK_DB / ACCOUNT_DIR"]
    fn real_run_video_ingest() {
        let (Ok(msg), Ok(hl), Ok(acct)) = (
            std::env::var("MSG_DB"),
            std::env::var("HARDLINK_DB"),
            std::env::var("ACCOUNT_DIR"),
        ) else {
            eprintln!("跳过 real_run_video_ingest: 未设 MSG_DB/HARDLINK_DB/ACCOUNT_DIR");
            return;
        };
        let mc = Connection::open(&msg).unwrap();
        let hc = Connection::open(&hl).unwrap();
        let dir = std::env::temp_dir().join(format!("ms_realrun_vid_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = StoreLayout::new(&dir, "realrun");
        std::fs::create_dir_all(layout.account_root()).unwrap();
        let ledger = super::super::ledger::open_ledger(&layout.ledger(), "rr_vid_sha", 1_700_000_000).unwrap();
        let stats = run_video_ingest(
            &mc,
            &hc,
            Path::new(&acct),
            &ledger,
            "rr_vid_sha",
            "rr-run",
            "message_0",
            &layout,
            Some(30),
            1_700_000_000,
        )
        .unwrap();
        eprintln!("视频真跑 stats = {stats:?}");
        assert!(stats.discovered > 0, "应发现视频消息");
        // 明文视频存了几个就核几个(加密的多, stored 可能 0 —— 但至少不 panic、账本一致)。
        let n_ref: i64 = ledger
            .query_row("SELECT count(*) FROM media_reference WHERE role='video'", [], |r| {
                r.get(0)
            })
            .unwrap();
        eprintln!(
            "视频 media_reference={n_ref}, stored={} failed={}",
            stats.stored, stats.failed
        );
        assert_eq!(n_ref as usize, stats.stored + stats.deduped, "media_reference = 入账数");
        if stats.stored > 0 {
            let hex: String = ledger
                .query_row("SELECT hex FROM asset LIMIT 1", [], |r| r.get(0))
                .unwrap();
            let p = layout.account_root().join("by-content").join(&hex[..2]).join(&hex);
            let head = std::fs::read(&p).unwrap();
            assert!(head.len() > 8 && &head[4..8] == b"ftyp", "by-content 是 mp4(ftyp)");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
