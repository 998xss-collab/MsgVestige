//! R22 懒式落库 (ADR-508 D24): **查询前把这一个会话的新消息补进 L1**, 然后纯冷查。
//!
//! 放在 `native-query` 而不是 `msgvestige-adapter`: 三皮 (CLI / HTTP / MCP) 都只依赖本 crate, 而这里需要的
//! 东西 (`AccountDbSource`、`pipeline::ingest_one_chat`、写租约) 全在 `native-core`, 拿得到。放 adapter
//! 会逼 HTTP/MCP 把整套 ingest 栈拉进来。
//!
//! ## 为什么判据是"插入序"不是"时间"
//!
//! "某段时间是完整的"没有便宜的验证方式 —— 后到但时间戳更早的消息 (换设备登录 / 迁移聊天记录 /
//! 微信重新同步会整批产生) 会落进已声称完整的区间, 永久查不出来且零信号。而"这张表已采到
//! `local_id` N"是精确可验证的: 后插入的 id 必然更大, 与时间戳无关。所以直接复用仓库里现成的
//! 增量通道 (`WHERE local_id > cursor`, 游标记在 `etl_state`, 落库走 archive + 全部派生表)。
//!
//! ## 两道闸
//!
//! 1. **文件签名 (v3, 2026-07-30 改)**: 消息目录里**一个分片都没动过** → 连库都不开。
//!    v1 只盯"该会话上次命中的那几个分片", 想省掉"别的会话在收消息"带来的开库 —— 但那样会
//!    **静默永久漏**: 沉寂会话醒来时消息写进的是**已存在的活跃分片**, 而那个分片不在它的名单里
//!    (见 `snapshot_sig` 的完整说明 + `d24_gate_catches_table_appearing_in_existing_shard`)。
//!    代价: 活账号上闸开得勤了。但开闸只是多开一两个库 —— 真库实测**单库 0.2–0.7s**
//!    (ADR-500 的 VFS 按需解密之后, 早年"整库解密十几秒"那个数已经不成立), 而漏消息是没有信号的。
//! 2. **会话片写租约**: 别人 (常驻 watch / 另一个查询) 正维护该会话 → 不双写, 直接读 L1 已有的。

// run_id 的进程内计数器就近声明在用它的地方, 挪到文件顶部反而看不出它服务于谁。
#![allow(clippy::items_after_statements)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use native_core::key_provider::Wxid;
use native_core::pipeline::PipelineStats;
use rusqlite::Connection;

use crate::error::cli_err;

/// [`ensure_chat_fresh`] 的结果。
#[derive(Debug)]
pub enum ChatFreshness {
    /// 该会话所在分片自上次采集以来**一点没动** → 没开库, L1 已经是最新的。
    AlreadyFresh,
    /// **没采到这个会话** —— 开了库但它一个分片都没命中。两种正常成因:
    /// 采集白名单(`capture add`)把它排除了; 或它是公众号会话(在 `biz_message_*.db` 里, 当前不采)。
    ///
    /// ⚠️ 这一格**不能报成"已补最新"**: 调用方读到的是 L1 里的旧行(可能几个月前), 却以为是刚刷的。
    /// 也**不记** `chat_refresh_state` —— 记了下次就被新鲜度闸挡住, 连开库都不开, 错误会一直滚下去。
    NotCovered,
    /// 采过了。`stats` 全 0 = 开了库但没有新消息。
    Ingested {
        /// 本次采集统计。
        stats: Box<PipelineStats>,
        /// 释放时租约是否还是自己的。`false` = 跑得太久被抢占, 可能与别人做了同一份活 (数据无碍:
        /// 采集三种写全幂等, 游标回退只导致多扫一遍)。
        lease_kept: bool,
    },
    /// 该会话正被别的写者维护 → 本次没采, 调用方读 L1 现有的。
    SkippedHeld {
        /// 对方持租到期时刻 (秒)。
        until: i64,
    },
    /// **够不着源库**(没微信数据目录 / 没缓存 key / L1 是只读文件)→ 没补, 读 L1 现有的。
    ///
    /// 这一格**不能报错**: "把冷库拷到别的机器上自足查"是本仓一直成立的契约, D24 之前冷查根本不碰
    /// 源库。硬失败会把这个契约打断(D24 审 P1)。但也不能装作补过了 —— 见 [`Self::skip_reason`]。
    SourceUnavailable {
        /// 够不着的原因 (给人看; 不含路径明文)。
        why: String,
    },
    /// **源库够得着, 但这一轮没补全** —— 已经补进去的仍然生效, 剩下那部分没看成。
    ///
    /// 三种成因(**看 `why`, 别硬猜**; 处置建议也在 `why` 里, 谁产生谁给):
    /// 1. 有分片读不开(损坏 / 微信正在写它 / 也可能是 key、session 库、目录这类账号级问题);
    /// 2. 采集范围(`capture add/rm`)在这次刷新中途变了 → 只覆盖了一部分分片;
    /// 3. 有子源卡住没采完(源报"还有"但游标不前进)。
    ///
    /// 跟 [`Self::SourceUnavailable`] **必须分开**(第二轮对抗审 P2): 那一格是良性稳态
    /// ("这台机器上没有微信 / 冷库拷走自足查"), **不需要处理**; 这一格**需要看一眼**。
    /// 混成一个 token 的话, 监控侧只会把这一格当那一格忽略掉。
    ///
    /// 同样**不记** `chat_refresh_state`: 记了下次就被闸挡住, 没看成的那部分再也不看 —— 又变成静默漏。
    SourceDegraded {
        /// 哪几片读不开 + 原因 (给人看; 只含分片文件名与错误, 不含路径明文)。
        why: String,
        /// 好分片这一轮**真补进去**的统计 —— 别丢掉, 否则用户不知道其实进了 N 条。
        stats: Box<PipelineStats>,
    },
}

impl ChatFreshness {
    /// 这次**没补成**的原因, 给信封的 `refresh_skipped` 用; 补成了返 `None`。
    ///
    /// 为什么必须进结构化输出: 只写 stderr / 日志的话, 机器可读的回答会变成"这个会话有 0 条消息"
    /// (D24 审实测: 7077 条的群被租约挡住时就是这个结果), 调用方无从知道自己拿到的是半截。
    #[must_use]
    pub fn skip_reason(&self) -> Option<&'static str> {
        match self {
            Self::AlreadyFresh | Self::Ingested { .. } => None,
            Self::SkippedHeld { .. } => Some("held"),
            Self::NotCovered => Some("not_covered"),
            Self::SourceUnavailable { .. } => Some("source_unavailable"),
            Self::SourceDegraded { .. } => Some("source_degraded"),
        }
    }
}

/// 把一次分片采集的统计并进总数 —— 逐个分片采时用(见 [`ensure_chat_fresh`] 里那段说明)。
///
/// `dbs` 取**最大值**不是求和: 它是"这一轮扫到几个 message 库"(每次调用都被设成目录里的总数),
/// 求和会变成 N×总数 这种没意义的数。其余都是真计数, 直接加。
fn merge_stats(into: &mut PipelineStats, one: &PipelineStats) {
    into.dbs = into.dbs.max(one.dbs);
    into.subsources += one.subsources;
    into.batches += one.batches;
    into.messages_decoded += one.messages_decoded;
    into.decode_errors += one.decode_errors;
    into.cursor_updates += one.cursor_updates;
    into.stalled_subsources += one.stalled_subsources;
    into.skipped_subsources += one.skipped_subsources;
    into.rescanned_subsources += one.rescanned_subsources;
    into.decode_windows += one.decode_windows;
    into.members_added += one.members_added;
    into.members_removed += one.members_removed;
    into.invalid_chatrooms += one.invalid_chatrooms;
    into.chatrooms_created += one.chatrooms_created;
}

/// 一个分片的 stat 四元组: `(主库 mtime, 主库大小, WAL mtime, WAL 大小)`。
///
/// **四个分量全记, 任一动就开闸** —— 只押 mtime 一个的话, 碰上"句柄没关时不刷新 LastWriteTime"
/// 的文件系统这个信号就是哑的 → 闸永远短路 → 跟被修的那个 bug 同类。
///
/// ⚠️ 原来这里写的理由是"WAL 模式下主库在 checkpoint 之前一个字节不变, 全靠 `-wal` 的信号" ——
/// **真库上不是这样**(独立复审 P3 实测): WCDB 的 `-wal` 是**预分配定长**的, 活跃分片持续写入
/// 9 分钟里 `message_5.db-wal` 恒为 4194304 字节, 而**主库长度在变**(1180823552 → 1180889088),
/// 两边 mtime 相差约 1 ms 同步走。也就是说 `wal_len` 这一项在这台机器上恒等、零信息量。
/// 留着无害(多一项恒等比较), 但**别按那个理由去动它** —— 真正扛事的是主库那两项。
/// (本机实测两个都会动, 见 `r22x_probe_wal_stat_signal_while_handle_open`; 但判据不该赌某个平台的行为。)
type ShardStat = (u64, u64, u64, u64);

/// 采集**开始之前**把消息目录里每个分片 stat 一遍。
///
/// 签名必须反映"**采集开始那一刻**的源库状态"。若采集**之后**再 stat, 采集期间进来的新消息会被
/// 这个签名盖住(下次比对说没变过 → 跳过 → 那些消息再也不采)。先拍快照、事后写入, 就没有这个洞。
fn stat_shards(message_dir: &Path) -> BTreeMap<String, ShardStat> {
    let mut m = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(message_dir) else {
        return m;
    };
    for e in rd.filter_map(std::result::Result::ok) {
        let p = e.path();
        let Some(n) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // 判据必须与 `source::account::content_shards` **同源**: 那边要求 `message_` 之后是**纯数字**
        // (`message_0.db`), 而这里原来只看前后缀 —— `message_fts.db` / `message_resource.db` 也会被算进
        // 分片名单(签名平白多变几次)。两处判据不同源本身就是隐患。
        let Some(num) = n.strip_prefix("message_").and_then(|r| r.strip_suffix(".db")) else {
            continue;
        };
        if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // 必须跟 `snapshot_dbs` 一样判 `is_file()`(第二轮对抗审 P3): 一个**名叫** `message_7.db` 的目录
        // 会进签名、进扫描集, 却永远进不了 snapshot 列表 → 白开一次闸。判据同源这条就写在上面。
        if !p.is_file() {
            continue;
        }
        let wal = wal_of(&p);
        m.insert(n.to_string(), (mtime_ns(&p), len_of(&p), mtime_ns(&wal), len_of(&wal)));
    }
    m
}

fn len_of(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn mtime_ns(p: &Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .map(|t| {
            u64::try_from(t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()).unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}

/// `<db>` → `<db>-wal` (新消息**先落 WAL**, 故 WAL 的 mtime 是主变化信号; 与 watch 的判据同源)。
fn wal_of(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push("-wal");
    PathBuf::from(s)
}

/// 签名 = 采集前**全部分片**的快照(不只上次命中的那几个)。
///
/// ## v1 为什么漏 (2026-07-30 修)
///
/// v1 只把"目录名单 + 上次命中的分片的 stat"算进签名。于是这一格永久漏:
/// **会话的表出现在一个已存在、但没被它命中过的分片里** —— 目录名单没变(那分片早就在)、
/// 命中过的分片也没动(老表冻结了) → 判"没变过" → 连库都不开。
///
/// v1 的自辩是「真机上微信轮转时**新建**分片文件, 目录名单会变, 被名单那段兜住」。**对沉寂会话不成立**:
/// 分片是几个月前建的(名单那时就更新过了), 群今天才醒过来, 消息写进的是**已存在**的活跃分片。
/// 实测复现: 源库 8 条, L1 只有 3 条, 照样返回 `AlreadyFresh`。
///
/// ## v2/v3 判据
///
/// 存**整份快照**: 任何分片的 mtime/大小/WAL 动过、任何分片新增或消失 → 签名必变 → 闸开。
///
/// **代价 (真库实测, 7.4GB / 6 分片 / 该会话 38528 条、横跨 message_0+4+5)**:
/// - 源库没动 → 短路。整条 CLI 命令 188–234ms, 而 `--no-refresh`(**完全不碰源库**)是 207–225ms
///   —— 两者**不可区分**, 也就是说这道闸本身的开销≈0, 那 0.2s 是进程启动 + 开 L1 + 查询。
/// - 源库动过 → 开 `known ∪ 变化过的` 那几片, **约 1.6s**(逐分片采之前测的; 逐分片后同量级)。
/// - 升级那一次: 老库里是认不出的旧签名 → 强制全扫一遍再按当前版本写回, **每会话一次性**(实测 2.7s)。
///
/// 换句话说闸**只在源库真的动过时才开**(不是"每次查询都开")—— 有新消息才付这 1.6s, 而那正是
/// 该付的时候。漏消息则是**静默且永久**的。正确性优先。
fn snapshot_sig(snap: &BTreeMap<String, ShardStat>) -> String {
    let mut parts = vec![SIG_VER.to_string()];
    for (name, (mt, len, wal_mt, wal_len)) in snap {
        parts.push(format!("{name}:{mt}:{len}:{wal_mt}:{wal_len}"));
    }
    parts.join("|")
}

/// 签名的版本前缀。**认不出的版本(v1 老格式 / 将来的新格式 / 损坏)一律当"全部分片都变过"**,
/// 强制全扫一次再按当前版本写回 —— 所以升级和降级都不需要迁移脚本, 代价是每会话多扫一次。
///
/// v2 → v3: 四元组补上 WAL 大小(见 [`ShardStat`])。
const SIG_VER: &str = "v3";

/// 把签名解析回快照。版本对不上 / 有一项残缺 → `None`(调用方当作"上次状态不可用")。
fn parse_sig(sig: &str) -> Option<BTreeMap<String, ShardStat>> {
    let mut it = sig.split('|');
    if it.next()? != SIG_VER {
        return None;
    }
    let mut m = BTreeMap::new();
    for part in it {
        // 分片名固定形如 `message_<数字>.db`, 不含 ':' —— 名字切一刀, 余下四个数。
        let (name, rest) = part.split_once(':')?;
        let mut nums = rest.split(':');
        let mt = nums.next()?.parse().ok()?;
        let len = nums.next()?.parse().ok()?;
        let wal_mt = nums.next()?.parse().ok()?;
        let wal_len = nums.next()?.parse().ok()?;
        if nums.next().is_some() {
            return None;
        }
        m.insert(name.to_string(), (mt, len, wal_mt, wal_len));
    }
    Some(m)
}

/// 与上次快照相比 **stat 变了 / 新出现** 的分片名。
///
/// `prev = None`(首次 or 旧格式签名)→ 返回当前**全部**分片 = 全扫。
/// 消失的分片不返回(已经不在磁盘上, 扫它没有意义; 闸那边已经因为签名不同而开了)。
fn changed_shards(prev: Option<&BTreeMap<String, ShardStat>>, now: &BTreeMap<String, ShardStat>) -> Vec<String> {
    now.iter()
        .filter(|(name, stat)| prev.is_none_or(|p| p.get(*name) != Some(*stat)))
        .map(|(name, _)| name.clone())
        .collect()
}

fn read_prev(conn: &Connection, account_sha: &str, chat_sha: &str) -> rusqlite::Result<Option<(String, String)>> {
    match conn.query_row(
        "SELECT shards, src_sig FROM chat_refresh_state WHERE account_id_sha = ?1 AND chat_id_sha = ?2",
        rusqlite::params![account_sha, chat_sha],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    ) {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        // 表还不存在 = 这个库从没被采过 → 等同"没有先前状态"。
        // (建表被挪到拿写锁之后了, 见 `ensure_chat_fresh` 里的说明; 这里必须容忍。)
        Err(e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::Unknown) => Ok(None),
        Err(e) => Err(e),
    }
}

/// 保证 `conv_id` 这一个会话在 L1 里是最新的 —— 三皮冷查前都该调它。
///
/// # Errors
/// 取不到 key / 定位不到账号目录 / 打不开 L1 / 采集失败。**不静默降级**: 静默跳过会让调用方以为
/// 读到的是最新的。
pub async fn ensure_chat_fresh(
    l1_db_path: &Path,
    wxid: &Wxid,
    conv_id: &str,
    wechat_data_dir: Option<&str>,
) -> anyhow::Result<ChatFreshness> {
    let err = |e: String| cli_err(native_core::ErrorCode::Internal, e);

    // 够不着源库(目录不在 / 只读 L1 文件 / 没缓存 key)一律**降级**成"没补, 读现有的"并如实标记 ——
    // 不硬失败(那会打断"冷库拷走自足查"的契约), 也不装作补过了(调用方靠 `skip_reason` 看得出来)。
    let message_dir = match crate::hot::resolve_message_dir(wechat_data_dir, wxid) {
        Ok(d) => d,
        Err(e) => {
            return Ok(ChatFreshness::SourceUnavailable {
                why: format!("定位不到微信消息目录: {e}"),
            })
        }
    };
    let conn = match native_core::storage::open(l1_db_path) {
        Ok(c) => c,
        Err(e) => {
            return Ok(ChatFreshness::SourceUnavailable {
                why: format!("L1 打不开(只读文件?): {e}"),
            })
        }
    };
    // ⚠️ `init_l1_schema` **故意不在这里调**(补审 P2): 它含 `CREATE INDEX IF NOT EXISTS`, 在老库上
    // 是一次真建索引 —— 实测 200 万行 5.5s/+373MB, 750 万条外推 ~20s/~1.4GB。放在这里会有两个后果:
    //   1. 落在下面那道"分片没动过就短路"的快闸**之前** → 连"本来就新鲜"的查询都要付这笔;
    //   2. 在拿到单写者 OS 锁**之前**扫大表 → 可能和正在跑的 watch/ingest 抢, 把写者堵住。
    // 所以挪到 `acquire_watch_lock` 之后(见下)。代价: `read_prev` 要容忍 `chat_refresh_state`
    // 还不存在 —— 已在那边处理。
    // ⚠️ 只读 L1 的**第二个**入口(codex 收敛轮 P2): 后面那次只读降级只在"租约表已存在"时接得住 ——
    // 一个**老的**只读 L1(建库时还没有 `write_lease` 表)会在这里的 `CREATE TABLE` 就撞 `ReadOnly`,
    // 报"租约表建失败"硬失败, 走不到后面。同一条规矩: 只读 = 补不进去, 降级读现有的, 不报 4xx。
    if let Err(e) = native_core::write_lease::init_write_lease(&conn) {
        if e.sqlite_error_code() == Some(rusqlite::ErrorCode::ReadOnly) {
            tracing::info!("L1 是只读的(连租约表都建不了) → 没补, 读它现有的");
            return Ok(ChatFreshness::SourceUnavailable {
                why: "L1 是只读文件, 补不进去 —— 读它现有的".to_string(),
            });
        }
        return Err(err(format!("租约表建失败: {e}")));
    }

    let account_sha = native_core::sha256_hex(wxid.as_str());
    let chat_sha = native_core::sha256_hex(conv_id);

    // ── 闸一: 该会话所在分片没动过 → 连库都不开 ──
    let prev = read_prev(&conn, &account_sha, &chat_sha).map_err(|e| err(format!("读采集状态失败: {e}")))?;
    let known: Vec<String> = prev
        .as_ref()
        .map(|(sh, _)| sh.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default();
    let snap_before = stat_shards(&message_dir);
    let prev_snap = prev.as_ref().and_then(|(_, sig)| parse_sig(sig));
    if !known.is_empty() && prev_snap.as_ref() == Some(&snap_before) {
        tracing::debug!("消息目录**一个分片都没动过** → 跳过采集, 直接读 L1");
        return Ok(ChatFreshness::AlreadyFresh);
    }

    // ── 这次要开哪几个分片 ──
    // `known`(上次命中的)**不够**: 会话可能刚把新消息写进一个它以前没待过的分片(沉寂群醒来 →
    // 消息进当前活跃分片)。只开 `known` 的话闸开了也照样扫不到 —— 这是同一个 bug 的另一半
    // (`ingest_one_chat` 的 `only_shards` 是硬过滤, 见 pipeline.rs `run_message_body`)。
    // 所以扫 `known ∪ 自上次以来变化过的分片`。**首次采集(`known` 空)= 目录里现有的全部分片。**
    //
    // ⚠️ 这里**列成显式名单**而不是留空让 `ingest_one_chat` 自己"全开" —— 因为下面要**逐个分片单独采**
    // (见那段的说明), 必须知道到底有哪几个。
    let scan_shards: Vec<String> = if known.is_empty() {
        snap_before.keys().cloned().collect()
    } else {
        let mut s: std::collections::BTreeSet<String> = known.iter().cloned().collect();
        s.extend(changed_shards(prev_snap.as_ref(), &snap_before));
        s.into_iter().collect()
    };
    tracing::debug!(?known, ?scan_shards, "分片有动静 → 开这几个采");

    // ── 闸二: 会话片写租约 ──
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(i64::MAX);
    let now_secs = now_ms / 1000;
    // ⚠️ run_id 必须**每次调用唯一**: 只用 pid 的话, 同一个 HTTP/MCP 进程里的并发请求会被当成同一个
    // owner —— 互相 bump epoch 之后**双写**(D24 审 P1)。加一个进程内单调计数。
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let run_id = format!(
        "q-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let lease_conn = native_core::storage::open(l1_db_path).map_err(|e| err(format!("打不开 L1(租约): {e}")))?;
    // ── R17 那把 OS 单写者锁 —— **必须排在租约前面** ──
    //
    // ⚠️ 顺序有讲究(独立复审 656477c 的 P3, 它真跑测出来的): 局部变量按声明**逆序**析构。
    // 锁在租约后面声明的话, 锁先放、租约的归还后发生 —— 而归还是一次写库 CAS, 那时另一个写者
    // 可能已经抢到锁开始独占写, 我们这条 UPDATE 就撞上连接三十秒的忙等: 要么阻塞 tokio worker,
    // 要么超时后被静默吞掉、租约照样挂满 600 秒 —— 正是这套 RAII 要消灭的那个症状。
    // 改之前每处释放都是显式调用、发生在还持着锁的时候; 换成 Drop 之后这个隐含前提断了。
    // 锁排在前面 → 它最后析构 → 归还租约时锁还在手上。
    // `ingest` / `watch` / `live-index build` / `search --build` 全在这把锁下假设自己是**唯一写者**
    // (`run_message_pipeline_jobs` 会 drop 索引+FTS 触发器再重建, 那段窗口里被并发写进来的行属于
    // 没人验过的组合)。D24 之前冷查从不写 L1 所以不需要它, 现在查询侧也写了 —— 必须参与, 否则
    // "唯一写者"这条假设就被从旁边绕过去了(D24 审实测组点名)。
    //
    // 拿不到就**当成"别人正在维护"退回读现有的** —— 与租约那格同一个处置(不双写, 也不谎报新鲜)。
    // 这把锁是 DELETE_ON_CLOSE, 进程一死就释放, 所以不会像咨询租约那样留残留。
    let _os_lock = match native_core::storage::acquire_watch_lock(l1_db_path) {
        Ok(g) => g,
        Err(e) => {
            tracing::info!(error = %e, "L1 正被别的写者(ingest/watch/live-index)独占 → 读 L1 现有的");
            return Ok(ChatFreshness::SkippedHeld { until: now_secs });
        }
    };

    // ⚠️ **只读 L1 必须降级不能硬失败**(末轮对抗审 P2, 审查方实测): `storage::open` 在只读文件上会
    // 退成只读打开(成功), `init_write_lease` 的 `CREATE TABLE IF NOT EXISTS` 在表已存在时也不写,
    // 于是**第一个真写操作**就是这里的 CAS → 报 `ReadOnly`。原来直接 `?` 出去 = HTTP 400 / MCP tool_err /
    // CLI 整条命令失败, 而 D24 定的规矩是"**没补成不报 4xx**"(把冷库拷到别处自足查是一等公民)。
    // 下面那格 `SourceUnavailable(L1 不可写)` 本来就是为这个成因写的, 只是排在领租约之后, 接不到。
    let claim = match native_core::write_lease::claim_write_lease(
        &lease_conn,
        // 键必须带**账号**维度: 多账号 L1 里同一个群/联系人在不同账号下是两份数据, 只按 conv_id
        // 会让它们错误互斥(D24 审 P1)。
        &format!("conv:{account_sha}:{conv_id}"),
        &run_id,
        now_secs,
    ) {
        Ok(c) => c,
        Err(e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::ReadOnly) => {
            tracing::info!("L1 是只读的 → 没补, 读它现有的");
            return Ok(ChatFreshness::SourceUnavailable {
                why: "L1 是只读文件, 补不进去 —— 读它现有的".to_string(),
            });
        }
        Err(e) => return Err(err(format!("领租约失败: {e}"))),
    };
    let lease = match claim {
        native_core::write_lease::LeaseClaim::HeldByOther { owner, until, .. } => {
            // ⚠️ **残租回收**(D24 审 P2): 一次性查询被 Ctrl-C / 杀掉就留下租约, 要等满 TTL(10 分钟)。
            // 期间每次查询都拿 SkippedHeld → 读到半截数据(实测少 46%)。R17 那把 OS 锁是
            // DELETE_ON_CLOSE 崩溃即释放, 这把咨询租约反而没有崩溃安全性。
            //
            // 判据: 我们的 run_id 形如 `q-<pid>-<seq>`, 持租者进程**已经不在**就说明那是残租, 直接抢。
            // (只对本入口自己发的 run_id 生效 —— watch 等别的写者格式不同, 一律尊重它们的租约。)
            if owner_process_gone(&owner) {
                tracing::warn!(owner = %owner, "持租进程已不在(崩溃残留?) → 抢占该会话租约");
                match native_core::write_lease::claim_write_lease(
                    &lease_conn,
                    &format!("conv:{account_sha}:{conv_id}"),
                    &run_id,
                    // 把 now 往后推过对方的 deadline, 让 CAS 闸判它已过期。
                    until.saturating_add(1),
                )
                .map_err(|e| err(format!("抢占残租失败: {e}")))?
                {
                    native_core::write_lease::LeaseClaim::Claimed(l) => l,
                    native_core::write_lease::LeaseClaim::HeldByOther { until, .. } => {
                        return Ok(ChatFreshness::SkippedHeld { until });
                    }
                }
            } else {
                tracing::info!(until, "该会话正被别的写者维护 → 读 L1 现有的");
                return Ok(ChatFreshness::SkippedHeld { until });
            }
        }
        native_core::write_lease::LeaseClaim::Claimed(l) => l,
    };
    // 包成 Drop 守卫: 下面所有出口(包括**请求被取消**这条手写覆盖不到的)都会还回去。
    let mut lease = LeaseGuard {
        conn: lease_conn, // 搬进来 —— 借用会让整个请求 future 不 Send, 见类型注释
        lease,
        released: false,
    };

    // ── 建表/建索引: **拿到写锁之后**才做(补审 P2)──
    // 老库上这是一次真建索引(200 万行实测 5.5s/+373MB)。放在这里保证:
    //   * 上面「分片没动过」的快闸已经先返回了 → 稳态查询一分钱不付;
    //   * 扫大表时我们**持着**单写者 OS 锁 → 不会和 watch/ingest 抢。
    if let Err(e) = native_core::storage::init_l1_schema(&conn) {
        return Ok(ChatFreshness::SourceUnavailable {
            why: format!("L1 不可写(只读文件?): {e}"),
        });
    }

    // ── 采集 ──
    let key = match crate::hot::cache_key(wxid).await {
        Ok(k) => k,
        Err(e) => {
            // 已经领了租约 —— 先还回去再降级返回, 别占着。
            return Ok(ChatFreshness::SourceUnavailable {
                why: format!("取不到 key(先跑 auth?): {e}"),
            });
        }
    };
    // 这两处早退**也要先还租约**(末轮对抗审 P3): 同函数别处都写着"先还回去再降级返回, 别占着",
    // 这里漏了 —— 常驻 HTTP/MCP 进程里漏掉的租约要撑满 600 秒 TTL, 而残租回收看的是 pid 还活着,
    // 正好救不了这一格 → 那个会话期间每次查询都报 held。
    let Some(parent) = message_dir.parent() else {
        return Err(err("消息目录没有父目录".to_string()));
    };
    let entry_db = parent.join("session").join("session.db");
    // ⚠️ **必须用 live cipher**: 非 live 的 `open_decrypted` 只解主库、**不合并 WAL**, 而微信/WCDB
    // 频繁 checkpoint, **最新几笔常还压在加密 WAL 里没刷盘**。用非 live 采集会读不到那几条 ——
    // 偏偏"查最近消息"最在意的就是它们。更坏的是新鲜度签名把 `-wal` 的 mtime 算进去了: 闸因为 WAL 动了
    // 而打开 → 读的是不含 WAL 的快照 → 一条没读到 → 却把含新 WAL mtime 的签名记成"已采" → 下次直接短路,
    // 到该分片被 checkpoint 之前那些消息一直看不见, 而信封说是刚刷新的。
    // (真库实测: live 读到 1254054 行, 非 live 只读到 1254052 行。msgvestige-adapter 里早写着这条警告,
    //  D24 这条新路径当初正好撞上去了 —— D24 审实测组逮到。)
    let cipher: Box<dyn native_core::cipher::Cipher> = Box::new(native_core::cipher::NativeCipher::new_live());
    let mut source =
        native_core::source::AccountDbSource::new(cipher, entry_db, key, wxid.clone(), message_dir.clone());
    let mut rw = match native_core::storage::open(l1_db_path) {
        Ok(c) => c,
        Err(e) => {
            return Err(err(format!("打不开 L1(写): {e}")));
        }
    };
    let mut stats = native_core::pipeline::PipelineStats::default();
    let mut matched: Vec<String> = Vec::new();
    let mut broken: Vec<String> = Vec::new();
    let mut broken_why: Option<String> = None;
    let mut fatal: Option<native_core::pipeline::PipelineError> = None;
    for shard in &scan_shards {
        match native_core::pipeline::ingest_one_chat(
            &mut source,
            &mut rw,
            wxid,
            conv_id,
            std::slice::from_ref(shard),
            native_core::PrivacyMode::archive_canonical(),
            1000,
            now_ms,
        )
        .await
        {
            Ok((s, m)) => {
                merge_stats(&mut stats, &s);
                for name in m {
                    if !matched.contains(&name) {
                        matched.push(name);
                    }
                }
            }
            // 源库侧读不开 = 这一片的问题, 记下来接着采别的。
            Err(e @ native_core::pipeline::PipelineError::Source(_)) => {
                tracing::warn!(shard = %shard, error = %e, "这个分片读不开 → 跳过它, 继续采其余分片");
                broken.push(shard.clone());
                if broken_why.is_none() {
                    broken_why = Some(e.to_string());
                }
            }
            // sink / state / 契约违反 = **我们自己的 bug**, 不能被"源库读不开"那顶帽子盖过去
            // (codex round-2 P2)。先跳出循环把租约还了, 再硬失败。
            Err(e) => {
                fatal = Some(e);
                break;
            }
        }
    }

    // 写失败也**先释放再传播**(不占租)。
    let still_ours = lease
        .release_now(now_secs)
        .map_err(|e| err(format!("释放租约失败: {e}")))?;

    if let Some(e) = fatal {
        return Err(err(format!("采集失败: {e}")));
    }

    // 有分片读不开 → 降级: 好分片的数据已经采进去了, 但**不记状态**(下次重试; 坏文件消失即自愈),
    // 并如实告诉调用方"这次没看全"—— 不能报成新鲜, 那就退回原来那个静默漏的病。
    if !broken.is_empty() {
        let why = broken_why.unwrap_or_default();
        // ⚠️ `PipelineError::Source` **不一定是这一片的问题**(codex round-4 P2): `ingest_one_chat` 在套
        // `only_shards` 之前先 `snapshot_dbs` —— 那一步会开 `session.db` 并扫整个目录。所以 key 不对、
        // session 库缺失/损坏、目录读不了, 会**每一片都失败**, 却被报成"这几片坏了, 删掉即可" —— 指错路。
        //
        // 曾经想用"全挂就算账号级、改报 `SourceUnavailable`"来分辨, **那个方向是错的**(第四轮对抗审 P3):
        // N 片完全可以各自因为本地原因同时坏(微信同时 checkpoint 多片 / 目录权限变了 / 备份工具锁了几个),
        // 那样就被讲成"良性稳态、不用管" —— 正是刚修掉的那格。**宁可永远报 degraded**(监控一定看得见),
        // 把两种可能都写进 `why` 让人去判。
        //
        // 处置建议也**写在 why 里**(第四轮对抗审 P2-F): `SourceDegraded` 现在装三种原因, 让 CLI 写死
        // 一句"去删那个坏文件"会把另外两种原因的用户支去翻微信目录。谁产生的原因谁给建议。
        let all_failed = broken.len() == scan_shards.len();
        tracing::warn!(
            broken = ?broken,
            all_failed,
            decoded = stats.messages_decoded,
            "有分片读不开 → 本次不记状态; 好分片已补入的仍然生效"
        );
        let hint = if all_failed {
            "这次要开的分片一个都没打开。两种可能: (a) 这几个文件都坏了 / 微信正在写它们;              (b) 账号级问题 —— key 不对、session 库缺失或损坏、消息目录读不了。先跑一次 doctor 排 (b), 再看具体文件"
        } else {
            "只有这几片打不开、别的都正常 —— 多半是微信正在写它们, 或那个文件坏了。等一会儿重试;              一直这样就去看那几个文件(删掉坏的即可, 下次查询会自动重扫)"
        };
        return Ok(ChatFreshness::SourceDegraded {
            why: format!("这些分片读不开: {} —— {hint}。底层报错: {why}", broken.join(",")),
            stats: Box::new(stats),
        });
    }

    // ── 这一轮的覆盖面不完整 → 不能写状态 ──
    //
    // `ingest_one_chat` **每次调用都重读** `capture_targets`, 而 `capture add/rm` 不拿这把 OS 锁。
    // 白名单若在循环中途变了: 前面的分片被跳过、后面的命中 → `matched` 非空 → 照常写状态 →
    // **被跳过的那几片从此藏在 `AlreadyFresh` 后面**, 又是一次静默漏。
    //
    // 曾用"循环前后各读一次、不一致就算残缺"来挡, **两处不对**(codex round-5):
    //   1. 挡不住 ABA —— 中途删了又加回来, 前后一样, 而中间那几片确实被跳过了;
    //   2. 动的是**别的**会话的名单时也会误报残缺, 白白丢掉一次完整刷新的状态。
    //
    // 改用 pipeline **自己数出来**的 `skipped_subsources`: 这条路径 `only_conv` 恒 Some, 而
    // `find_message_subsource` 只返回那一个会话 → "会话 id 不匹配"那一支不可能触发, 于是这个计数
    // **只可能来自白名单把本会话排除掉**。
    //
    // ⚠️ 判据必须是「**跳过与命中同时出现**」, 不能只看跳过(codex round-6 P2): 会话被白名单
    // **一直**排除在外是**选择性采集的正常路径** —— 那时 `skipped > 0` 而 `matched` 空, 该报
    // `NotCovered`(下面那格)。只看 `skipped > 0` 会把这条常规路径误报成"范围中途变了", 三皮全受影响。
    // (上一版注释里写着"既然下面 matched 非空", 而判据里**根本没写这个条件** —— 拿注释当验证使了。)
    if stats.skipped_subsources > 0 && !matched.is_empty() {
        tracing::warn!(
            skipped = stats.skipped_subsources,
            matched = matched.len(),
            "同一轮里本会话既被白名单跳过又被命中(采集范围中途变了) → 不记状态, 下次重来"
        );
        return Ok(ChatFreshness::SourceDegraded {
            why: "采集范围在这次刷新中途变了(capture add/rm), 这一轮只覆盖了一部分分片 —— 再查一次即可, 不用处理"
                .to_string(),
            stats: Box::new(stats),
        });
    }
    // ⚠️ **"一个分片都没命中"必须排在"租约被抢"之前**(codex round-7 P2): 反过来的话,
    // 白名单排除的会话若又恰好丢了租约(比如跑过了 10 分钟 TTL), 就会掉进下面那格返回 `Ingested`
    // —— 而 `Ingested::skip_reason()` 是 `None`, 三皮会把"一片都没采"讲成"刷新成功"。
    // 覆盖面的事实(没采到)比租约的事实(可能有人跟我做了同一份活)更该先讲。
    if matched.is_empty() {
        // 一个分片都没命中 = 这个会话根本没被采集覆盖(白名单排除 / 公众号会话)。**不记状态**:
        // 记了下次新鲜度闸就命中, 连库都不开, "报刚刷新、实际没刷新"会一直滚下去。
        tracing::warn!("该会话没有任何分片命中(采集白名单排除? 公众号会话?) → 不记状态, 如实报 NotCovered");
        if !still_ours {
            tracing::warn!("且租约已被抢占");
        }
        return Ok(ChatFreshness::NotCovered);
    }
    // ⚠️ **完整性判据必须全部排在"租约被抢"之前**(末轮对抗审 P2 —— 第七轮只挪了 `¬matched` 那半边,
    // `stalled` 这半边漏了): `T ∧ ¬U` 同时成立时会掉进下面那格返 `Ingested`, 而 `Ingested` 的
    // `skip_reason()` 是 `None` → "那批行没采完"被讲成"刷新成功"。
    //
    // 为什么顺序该这样: 整轮跑都持着 `acquire_watch_lock`(进程级独占), 抢到租约的那一方拿不到这把锁
    // 只会返 `SkippedHeld` → **`¬U` 在数据正确性上不承重**, 它该排在所有完整性判据之后。
    // ⚠️ **卡住的子源也不能记状态**(第二轮对抗审 P3-10): `stalled_subsources > 0` = source 报"还有"
    // 但游标不前进 → drain 循环提前 break, 那批行**没采完**。而该分片已经进了 `matched`, 照写状态的话
    // 签名就把它盖成"已消费" —— 之后若这个分片的 stat 不再变, 那批行以 `AlreadyFresh` 的名义永久看不见,
    // 跟被修的那个 bug 同类。健康 source 恒 0, 所以这条不影响正常路径。
    if stats.stalled_subsources > 0 {
        // 返 `Ingested` 是错的(codex round-4 P1): 那样 `skip_reason()` = `None`, 三皮会把这份
        // **没采完**的结果讲成"已补到最新"。既然故意不写状态, 对外就必须带一个 skip 信号。
        tracing::warn!(
            stalled = stats.stalled_subsources,
            "有子源卡住(没采完) → 不记状态, 且如实标记这次没补全"
        );
        let n = stats.stalled_subsources;
        return Ok(ChatFreshness::SourceDegraded {
            why: format!(
                "有 {n} 个子源卡住没采完(源报'还有'但游标不前进) —— 这一轮没补全。健康的源库不该出现这一格, 请报给开发"
            ),
            stats: Box::new(stats),
        });
    }
    // 丢了租约就**别写状态**(D24 审 P2): 慢写者的 `matched` 可能比抢占者的旧(比如会话已经搬进活分片,
    // 而它只扫到冻结分片), 盖回去会让签名从此盯着一个不再变的分片 → 之后永久 AlreadyFresh。
    if !still_ours {
        tracing::warn!("采完才发现租约已被抢占 → 不写采集状态(避免用旧的分片集合盖掉新的)");
        return Ok(ChatFreshness::Ingested {
            stats: Box::new(stats),
            lease_kept: false,
        });
    }

    // 采成功才记状态。签名用**采集前**那份快照算 (见 `stat_shards`)。
    conn.execute(
        "INSERT INTO chat_refresh_state (account_id_sha, chat_id_sha, shards, src_sig, refreshed_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(account_id_sha, chat_id_sha) DO UPDATE SET
            shards = excluded.shards, src_sig = excluded.src_sig, refreshed_at_ms = excluded.refreshed_at_ms",
        rusqlite::params![
            account_sha,
            chat_sha,
            matched.join(","),
            snapshot_sig(&snap_before),
            now_ms
        ],
    )
    .map_err(|e| err(format!("记采集状态失败: {e}")))?;

    if !still_ours {
        tracing::warn!("采完才发现租约已被抢占; 采集幂等故数据无碍, 但可能有人做了同一份活");
    }
    Ok(ChatFreshness::Ingested {
        stats: Box::new(stats),
        lease_kept: still_ours,
    })
}

/// 持租者的进程还在不在 —— 只认本入口自己发的 `q-<pid>-<seq>` 格式, 别的写者(watch 等)一律返 false
/// (= 尊重它们的租约, 不去猜它们的存活性)。
///
/// 崩溃残留的租约要等满 10 分钟 TTL, 期间每次查询都读到半截数据; 而一次性 CLI 查询被 Ctrl-C 很常见。
/// 领到的写租约 —— **靠 Drop 还回去**, 不靠调用方在每个出口手写一遍。
///
/// 为什么非得是 Drop(外部复审⑤ 顺出来的): 这个函数里有六处早退, 每处都手写一句"先还租约再返回",
/// 而**取消**这条路一处也覆盖不到 —— `ensure_chat_fresh` 是在 HTTP/MCP 的请求 future 里直接 await 的,
/// 客户端一断线, axum 把整个 future 丢掉, 手写的那六句一句都不会跑。
///
/// 后果正是复审说的那个症状, 只是触发方式不同: 那个会话的租约要撑满 600 秒 TTL, 而**同一个进程
/// 抢不回来** —— 残租回收看的是"持租进程还在不在", 而进程好好活着; `owner == run_id` 也对不上,
/// 因为 run_id 每次调用都换一个序号。期间每次查这个会话都报"别人正在维护", 读到的是旧数据。
///
/// (进程被杀那一格本来就有救: 残租回收判 pid 不在就直接抢。这里补的是进程还活着的那一格。)
///
/// ⚠️ **连接是搬进来的, 不是借的**: 借 `&Connection` 的话这个守卫就不是 `Send` 了
/// (`rusqlite::Connection` 是 `Send` 但**不是 `Sync`**, 所以它的引用不 `Send`), 而守卫要跨 await
/// 活着 —— 整个请求 future 跟着不 `Send`, axum 直接判 handler 不合法。加 `Drop` 之前编译器还能把
/// 借用提前判死, 加了 `Drop` 之后它必须活到作用域末尾, 这个区别当场把 native-http 编译搞挂了。
struct LeaseGuard {
    conn: rusqlite::Connection,
    lease: native_core::write_lease::SliceLease,
    released: bool,
}

impl LeaseGuard {
    /// 主动还, 并告诉调用方"还的时候是不是还归我们"。还过之后 Drop 不再动它。
    ///
    /// ⚠️ 盖不住的: 把这里的 `released = true` 去掉, 测试**不红** —— 释放是按
    /// (键, 持有者, epoch) 做 CAS 的, 还第二次只会拿到 false, 没有副作用。留着是为了少跑一次库,
    /// 不是为了正确性。别为了让变异表好看去硬凑守卫。
    fn release_now(&mut self, now_secs: i64) -> rusqlite::Result<bool> {
        self.released = true;
        native_core::write_lease::release_write_lease(&self.conn, &self.lease, now_secs)
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // Drop 里拿不到调用方那个 now, 现取一个 —— 释放只按 (key, owner, epoch) 做 CAS, 跟时间无关。
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        // best-effort: 还不回去也只能算了(库没了/只读), 顶多等它自己到期 —— **但要说出来**
        // (独立复审 656477c 的 P3): 一个专门用来"别让租约挂着"的机制, 失败时完全无声等于没有。
        if let Err(e) = native_core::write_lease::release_write_lease(&self.conn, &self.lease, now) {
            tracing::warn!(
                error = %e,
                key = %self.lease.lease_key,
                "租约没还回去 —— 这个会话要等满 TTL 才会被别人接手"
            );
        }
    }
}

fn owner_process_gone(owner: &str) -> bool {
    let Some(rest) = owner.strip_prefix("q-") else {
        return false;
    };
    let Some(pid_s) = rest.split('-').next() else {
        return false;
    };
    let Ok(pid) = pid_s.parse::<u32>() else { return false };
    if pid == std::process::id() {
        return false; // 自己(同进程另一次调用)—— 让正常的 owner==run 分支去处理
    }
    !process_alive(pid)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    // 用 tasklist 过滤(免引 winapi 依赖)。查不出来时**保守当活着**(宁可多等, 不误抢别人的租)。
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map_or(true, |o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
}

#[cfg(not(windows))]
fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// 读"这个会话上次被补到什么时候"(unix **秒**), 供信封的 `chat_refreshed_at` 用。
///
/// 表不存在 / 没记过 → `None`(省略该字段, 不谎报)。
#[must_use]
pub fn chat_refreshed_at(l1_db_path: &Path, wxid: &Wxid, conv_id: &str) -> Option<i64> {
    let conn = native_core::storage::open(l1_db_path).ok()?;
    let account_sha = native_core::sha256_hex(wxid.as_str());
    let chat_sha = native_core::sha256_hex(conv_id);
    conn.query_row(
        "SELECT refreshed_at_ms FROM chat_refresh_state WHERE account_id_sha = ?1 AND chat_id_sha = ?2",
        rusqlite::params![account_sha, chat_sha],
        |r| r.get::<_, i64>(0),
    )
    .ok()
    .map(|ms| ms / 1000)
}

#[cfg(test)]
mod tests {

    /// **这个手写的合并函数不许漏字段**(独立复审 651ed5c 的 P3: `decode_windows` 加上去之后, 这里
    /// 静默丢了它 —— 其余 13 个字段都在)。
    ///
    /// 漏字段是静默的: 编译器不管, 结果只是那个数恒 0。而 `decode_windows` 加进来的理由正是
    /// "让窗口按什么切从外面看得见", 懒式采集(MCP/HTTP/CLI 热查)偏偏是最需要看见的常驻路径。
    ///
    /// 判据写成"每个字段都得动", 不是"点名这几个" —— 以后再加字段, 这条自动就管上了。
    #[test]
    fn merge_stats_carries_every_field() {
        use native_core::pipeline::PipelineStats;
        // 每个字段都塞非零值。加了新字段而这里没跟上 → 编译不过(结构体字面量必须写全), 也是一种红。
        let one = PipelineStats {
            dbs: 1,
            subsources: 2,
            batches: 3,
            messages_decoded: 4,
            decode_errors: 5,
            cursor_updates: 6,
            stalled_subsources: 7,
            skipped_subsources: 8,
            rescanned_subsources: 9,
            decode_windows: 10,
            members_added: 11,
            members_removed: 12,
            invalid_chatrooms: 13,
            chatrooms_created: 14,
        };
        let mut into = PipelineStats::default();
        super::merge_stats(&mut into, &one);
        assert_eq!(into, one, "合并到空统计上必须逐字还原 —— 有字段没合并的话它会停在 0");

        // ⚠️ **只合一次分不出 `+=` 和 `=`**(独立复审 656477c 的 P3, 它埋了这个变异, 我这条是绿的)。
        // 而生产就是 `for shard in &scan_shards` 逐片合并 —— 写成 `=` 会静默丢掉除最后一片外的全部计数。
        // 合第二次: 求和项该翻倍, `dbs` 按 max 不变。
        super::merge_stats(&mut into, &one);
        assert_eq!(into.dbs, one.dbs, "dbs 是取 max, 合两次还是它");
        assert_eq!(
            into.subsources,
            one.subsources * 2,
            "求和项合两次该翻倍, 写成 `=` 就不翻"
        );
        assert_eq!(into.messages_decoded, one.messages_decoded * 2);
        assert_eq!(into.decode_windows, one.decode_windows * 2);
        assert_eq!(into.rescanned_subsources, one.rescanned_subsources * 2);
        assert_eq!(into.chatrooms_created, one.chatrooms_created * 2);
    }

    /// **请求被取消, 租约也得还回去**(外部复审⑤ 顺出来的那一格)。
    ///
    /// `ensure_chat_fresh` 是在 HTTP/MCP 的请求 future 里直接 await 的。客户端一断线, 整个 future
    /// 被丢掉 —— 函数里那六处手写的"先还租约再返回"**一句都不会跑**。而残租回收看的是"持租进程
    /// 还在不在", 进程好好活着, 救不了这一格; `owner == run_id` 也对不上(run_id 每次调用换序号)。
    /// 结果就是那个会话被锁满 600 秒, 期间每次查都读到旧数据。
    ///
    /// 这条用超时把 future 丢掉, 复现的就是断线那一刻; 断言另一个 owner **立刻**能领到。
    #[tokio::test]
    async fn lease_comes_back_even_when_the_request_is_cancelled() {
        use native_core::write_lease::{claim_write_lease, init_write_lease, LeaseClaim};
        let dir = tempfile::tempdir().unwrap();
        let conn = native_core::storage::open(&dir.path().join("lease.db")).unwrap();
        init_write_lease(&conn).unwrap();
        let now = 1_800_000_000i64;

        let LeaseClaim::Claimed(l) = claim_write_lease(&conn, "conv:x", "q-1-0", now).unwrap() else {
            panic!("头一次该领到");
        };
        // 守卫要自己那份连接(它把连接搬进去) —— 同一个库文件, 两个句柄。
        let guard_conn = native_core::storage::open(&dir.path().join("lease.db")).unwrap();

        // 领着租约的 future 卡在 await 上 —— 超时把它丢掉, 就是客户端断线那一刻。
        let held = async {
            let _guard = super::LeaseGuard {
                conn: guard_conn,
                lease: l,
                released: false,
            };
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        };
        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(20), held).await;
        assert!(timed_out.is_err(), "夹具前提: 这个 future 得真的被超时丢掉");

        // 换个 owner 立刻再领 —— 时间**一秒都没往前推**, 所以不可能是"等到期了"。
        let again = claim_write_lease(&conn, "conv:x", "q-2-0", now).unwrap();
        assert!(
            matches!(again, LeaseClaim::Claimed(_)),
            "取消之后租约必须已经还回去, 不该让下一个人干等 600 秒: {again:?}"
        );
    }

    /// **表还不存在时 `read_prev` 必须返回"没有先前状态"而不是报错。**
    ///
    /// 背景: `1de5e23` 把 `init_l1_schema`(含建 `chat_refresh_state`)挪到了拿写锁之后 ——
    /// 因为它在老库上是一次真建索引, 放在快闸之前会让"本来就新鲜"的查询白白付几秒。
    /// 代价就是 `read_prev` 会在**表还没建**的时候被调到(全新库的第一次查询)。
    ///
    /// 这条锁死两件事:
    /// 1. 全新库不会因为缺表而炸;
    /// 2. 我当时**假设**的 SQLite 错误码是对的 —— 这个假设没验证过就写进了代码, 假设错了
    ///    全新库第一次查询必崩, 而且只在真机上崩(单测都是先 init 好 schema 的库)。
    #[test]
    fn read_prev_tolerates_missing_table_on_a_brand_new_db() {
        let conn = rusqlite::Connection::open_in_memory().expect("内存库");
        // 故意**不**建任何表 —— 模拟"拿锁之前, init_l1_schema 还没跑"。
        assert!(
            conn.query_row("SELECT 1 FROM chat_refresh_state", [], |_| Ok(()))
                .is_err(),
            "前提: 这个库里确实没有 chat_refresh_state"
        );
        let got = read_prev(&conn, &"a".repeat(64), &"b".repeat(64));
        assert!(
            matches!(got, Ok(None)),
            "表不存在应等同「没有先前状态」, 实得 {got:?} —— 若这里红了, 说明我对 SQLite              错误码的假设是错的, 全新库的第一次查询会崩"
        );
        // 建好表之后仍要正常工作(别把容忍写成"永远返 None")。
        conn.execute_batch(
            "CREATE TABLE chat_refresh_state (account_id_sha TEXT, chat_id_sha TEXT, shards TEXT, src_sig TEXT);",
        )
        .expect("建表");
        assert!(
            matches!(read_prev(&conn, &"a".repeat(64), &"b".repeat(64)), Ok(None)),
            "空表也是 None"
        );
        conn.execute(
            "INSERT INTO chat_refresh_state VALUES (?1, ?2, 'message_0.db', 'sig')",
            rusqlite::params!["a".repeat(64), "b".repeat(64)],
        )
        .expect("插一行");
        let hit = read_prev(&conn, &"a".repeat(64), &"b".repeat(64)).expect("查");
        assert_eq!(
            hit,
            Some(("message_0.db".to_string(), "sig".to_string())),
            "有行时要真读出来"
        );
    }
    use super::*;

    /// **残租回收的判据必须两向都对**: 死进程的租要抢, 活着的 / 别人格式的租要尊重。
    ///
    /// 之前只用临时脚本验了"抢"那一向, "尊重"那一向没验成(造出来的 pid 到检查时已退出)——
    /// 这里做成确定性单测补上。
    #[test]
    fn stale_lease_reclaim_judges_both_directions() {
        // ① 死进程留下的租 → 该抢。pid 999999 在任何平台都不会是活进程。
        assert!(owner_process_gone("q-999999-0"), "死进程的残租必须能被识破");

        // ② **自己**这个进程 → 不算残租(交给 owner==run 的正常分支)。
        let me = format!("q-{}-0", std::process::id());
        assert!(!owner_process_gone(&me), "自己的进程不该被当成残租");

        // ③ **别的写者**(watch 等)格式不同 → 一律尊重, 不去猜它们的存活性。
        for other in ["watch-123", "messages", "ingest-7", "", "q-", "q-abc-0"] {
            assert!(
                !owner_process_gone(other),
                "不是本入口发的 run_id(`{other}`)就不该动它的租约"
            );
        }
    }

    fn snap_of(items: &[(&str, u64, u64, u64, u64)]) -> BTreeMap<String, ShardStat> {
        items
            .iter()
            .map(|(n, a, b, c, d)| ((*n).to_string(), (*a, *b, *c, *d)))
            .collect()
    }

    /// 签名覆盖**每一个**分片的**四个** stat 分量。
    ///
    /// ⚠️ 这条**取代**了 v1 的 `signature_first_segment_is_the_shard_listing` —— 那条断言的是
    /// 「没盯的分片变了签名不该变」, 而那正是 bug 本身: 沉寂会话醒来时消息进的就是那种"没盯的"
    /// 活跃分片, 签名不变 → 闸不开 → 静默永久漏 (见 `snapshot_sig` 文档)。
    #[test]
    fn signature_covers_every_shard_and_every_component() {
        let snap = snap_of(&[("message_0.db", 1, 2, 3, 4), ("message_1.db", 5, 6, 7, 8)]);
        let sig = snapshot_sig(&snap);
        assert!(sig.starts_with("v3|"), "要有版本前缀才能跟旧格式区分: {sig}");

        // 没命中过的分片变了 → 签名**必须**变 (v1 在这里是 assert_eq, 那是 bug)。
        let moved = snapshot_sig(&snap_of(&[("message_0.db", 1, 2, 3, 4), ("message_1.db", 9, 9, 9, 9)]));
        assert_ne!(sig, moved, "任何分片动过都必须开闸");

        // **四个分量各自**单独动都必须让签名变 —— 少认一个就是少一条新鲜度信号。
        for (i, one) in [
            ("message_0.db", 99, 2, 3, 4), // 主库 mtime
            ("message_0.db", 1, 99, 3, 4), // 主库大小
            ("message_0.db", 1, 2, 99, 4), // WAL mtime
            ("message_0.db", 1, 2, 3, 99), // WAL 大小 (codex round-2 P2 补的这一个)
        ]
        .into_iter()
        .enumerate()
        {
            let s = snapshot_sig(&snap_of(&[one, ("message_1.db", 5, 6, 7, 8)]));
            assert_ne!(sig, s, "第 {i} 个分量动了必须开闸");
        }

        // 新分片出现 / 分片消失 → 都必须变。
        let added = snapshot_sig(&snap_of(&[
            ("message_0.db", 1, 2, 3, 4),
            ("message_1.db", 5, 6, 7, 8),
            ("message_2.db", 9, 9, 9, 9),
        ]));
        assert_ne!(sig, added, "新分片出现必须开闸");
        let removed = snapshot_sig(&snap_of(&[("message_0.db", 1, 2, 3, 4)]));
        assert_ne!(sig, removed, "分片消失必须开闸");
    }

    /// 签名 → 快照能原样解析回来; 认不出的版本 / 残缺一律 `None`(调用方当"全变过"→ 全扫一遍)。
    #[test]
    fn sig_roundtrips_and_rejects_other_versions() {
        let snap = snap_of(&[("message_0.db", 1, 2, 3, 4), ("message_10.db", u64::MAX, 0, 5, 6)]);
        assert_eq!(parse_sig(&snapshot_sig(&snap)).as_ref(), Some(&snap), "必须原样回来");

        // v1 的真实格式(名单开头, 无版本前缀)—— 必须拒。
        assert!(
            parse_sig("message_0.db,message_1.db|message_0.db:1:2:3").is_none(),
            "v1 格式必须拒"
        );
        // v2 (三元组, 没有 WAL 大小) —— 也必须拒, 拒了才会强制全扫一次补上新分量。
        assert!(parse_sig("v2|message_0.db:1:2:3").is_none(), "v2 必须拒");
        // 将来的版本同理 —— 认不出就当全变过, 不猜。
        assert!(parse_sig("v9|message_0.db:1:2:3:4").is_none(), "认不出的版本必须拒");
        assert!(parse_sig("").is_none());
        assert!(parse_sig("v3|message_0.db:1:2:3").is_none(), "少一项必须拒");
        assert!(parse_sig("v3|message_0.db:1:2:3:4:5").is_none(), "多一项必须拒");
        assert!(parse_sig("v3|message_0.db:x:2:3:4").is_none(), "非数字必须拒");
        assert!(parse_sig("v3|no_colon").is_none());
        // 空快照(目录里一个分片都没有)是合法的, 不是错误。
        assert_eq!(parse_sig("v3").as_ref(), Some(&BTreeMap::new()));
    }

    /// 变化集 = stat 变了 + 新出现的; 没变的不进, 消失的不进(扫一个不在磁盘上的分片没意义)。
    #[test]
    fn changed_shards_picks_moved_and_new_only() {
        let prev = snap_of(&[("message_0.db", 1, 2, 3, 4), ("message_1.db", 5, 6, 7, 8)]);
        let now = snap_of(&[
            ("message_0.db", 1, 2, 3, 4),  // 没动
            ("message_1.db", 5, 6, 7, 99), // 只有 WAL 大小动了 (v2 会漏判这一格)
            ("message_2.db", 9, 9, 9, 9),  // 新出现
        ]);
        assert_eq!(
            changed_shards(Some(&prev), &now),
            vec!["message_1.db".to_string(), "message_2.db".to_string()]
        );
        // 消失的分片不进变化集 (message_1 在 prev 里、now 里没有)。
        assert_eq!(
            changed_shards(Some(&prev), &snap_of(&[("message_0.db", 1, 2, 3, 4)])),
            Vec::<String>::new()
        );
        // 没有上次状态(首次 / v1 旧签名)→ 全部都算变过 → 全扫。
        assert_eq!(
            changed_shards(None, &now),
            vec![
                "message_0.db".to_string(),
                "message_1.db".to_string(),
                "message_2.db".to_string()
            ]
        );
    }
}
