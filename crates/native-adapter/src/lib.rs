//! msgvestige-adapter (lib) — 端到端 message ingest 编排 (可测核心)。
//!
//! 把 native-core 的取数 + ETL 编排件接成「一条链」的可测部分:
//! - [`locate_account_dbs`]: 微信数据目录 + wxid → 账号 db 路径 (`db_storage/session/session.db` 入口 +
//!   `db_storage/message/` 扫盘根)。布局实测自 `X:\xwechat_files\<wxid>_<后缀>\db_storage`。
//! - [`run_message_ingest`]: 给定 [`DbSource`] + L1 库路径 → 开库 + 建 L1 schema + 跑 `run_message_pipeline`。
//!
//! 真实依赖构造 (KeyProvider 取 key / NativeCipher / AccountDbSource) 在
//! `main.rs` 薄壳 (环境耦合, 不在可测 lib)。
//!
//! K-R4: 错误信息不露明文 wxid (走 sha8) / 不露微信库绝对路径 (只露相对子路径 / io 类别)。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use native_core::emit::in_proc::{new_in_proc, Backpressure};
use native_core::{
    run_avatar_pipeline, run_bizchat_pipeline, run_chatroom_pipeline, run_contact_pipeline, run_emoticon_pipeline,
    run_favorite_pipeline, run_favorite_tag_pipeline, run_finder_visit_pipeline, run_friend_verify_pipeline,
    run_group_pay_pipeline, run_message_pipeline_incremental, run_moment_feed_pipeline, run_red_envelope_pipeline,
    run_session_pipeline, run_sns_notify_pipeline, run_sns_pipeline, run_transfer_pipeline, sha8, AccountDbSource,
    DbSource, PipelineError, PipelineStats, PrivacyMode, Wxid,
};

/// 账号 db 路径 (locate 产出) — 喂 `AccountDbSource::new`。
///
/// K-R4 (代码双审 P1): 3 个 path 都含明文 wxid (db_storage 在 `<wxid>_<后缀>` 目录下) → 手写 Debug 走
/// sha8, 不 derive Debug (防 `{paths:?}` 泄绝对路径)。
#[derive(Clone, PartialEq, Eq)]
pub struct AccountDbPaths {
    /// 账号入口 db (`open_account` 用): `<account_dir>/db_storage/session/session.db`。
    pub account_entry_db: PathBuf,
    /// 消息子库扫盘根 (`message_*.db` 所在): `<account_dir>/db_storage/message/`。
    pub message_dir: PathBuf,
    /// 联系人 db (`drain_contacts` 用): `<account_dir>/db_storage/contact/contact.db`。
    /// locate 只算路径不校验存在 (contact ingest 时按需用; 缺则 contact pipeline 报 cipher 错)。
    pub contact_db: PathBuf,
    /// 收藏 db (`drain_favorites` 用): `<account_dir>/db_storage/favorite/favorite.db` (ADR-454)。
    /// locate 只算路径不校验存在 (favorite ingest 时按需用; 缺则 favorite pipeline 报 cipher 错)。
    pub favorite_db: PathBuf,
    /// 朋友圈 db (`drain_moments` 用): `<account_dir>/db_storage/sns/sns.db` (ADR-467)。
    /// locate 只算路径不校验存在 (sns ingest 时按需用; 缺则 --sns 跳过, 同 favorite)。
    pub sns_db: PathBuf,
    /// 通用 db (`drain_transfers` 用, 转账在 `transferTable`): `<account_dir>/db_storage/general/general.db` (ADR-468)。
    /// locate 只算路径不校验存在 (transfer ingest 时按需用; 缺则 --transfers 跳过, 同 sns)。
    pub general_db: PathBuf,
    /// 表情 db (`drain_emoticons` 用): `<account_dir>/db_storage/emoticon/emoticon.db` (ADR-478)。
    /// locate 只算路径不校验存在 (emoticon ingest 时按需用; 缺则 --emoticons 跳过, 同 sns)。
    pub emoticon_db: PathBuf,
    /// 头像 db (`drain_avatars` 用): `<account_dir>/db_storage/head_image/head_image.db` (ADR-481)。
    /// locate 只算路径不校验存在 (avatar ingest 时按需用; 缺则 --avatars 跳过, 同 sns)。
    pub head_image_db: PathBuf,
    /// 企微 db (`drain_bizchat_users` 用): `<account_dir>/db_storage/bizchat/bizchat.db` (ADR-482)。
    /// locate 只算路径不校验存在 (bizchat ingest 时按需用; 缺则 --bizchat 跳过, 同 sns)。
    pub bizchat_db: PathBuf,
}

// K-R4: 各 path 都含 wxid → Debug 走 sha8, 不露绝对路径 (代码双审 P1)。
impl std::fmt::Debug for AccountDbPaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s8 = |p: &PathBuf| sha8(p.to_string_lossy().as_bytes());
        f.debug_struct("AccountDbPaths")
            .field("account_entry_db_sha8", &s8(&self.account_entry_db))
            .field("message_dir_sha8", &s8(&self.message_dir))
            .field("contact_db_sha8", &s8(&self.contact_db))
            .field("favorite_db_sha8", &s8(&self.favorite_db))
            .field("sns_db_sha8", &s8(&self.sns_db))
            .field("general_db_sha8", &s8(&self.general_db))
            .field("emoticon_db_sha8", &s8(&self.emoticon_db))
            .field("head_image_db_sha8", &s8(&self.head_image_db))
            .field("bizchat_db_sha8", &s8(&self.bizchat_db))
            .finish()
    }
}

/// ingest 错误 (K-R4: 不露明文 wxid / 微信库绝对路径)。
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// 账号 db 路径定位失败 (账号目录 / session.db / message 目录缺)。`what` 非敏感 (wxid 已 sha8, 路径只相对子路径)。
    #[error("账号 db 定位失败: {what}")]
    AccountNotFound { what: String },
    /// L1 库打开 / 建表失败 (L1 是本地输出库, 非微信源库)。
    #[error("L1 库 open/建表失败: {0}")]
    Storage(#[from] rusqlite::Error),
    /// pipeline 取数/落库/游标错 (各内层已脱敏)。
    #[error("ingest pipeline: {0}")]
    Pipeline(#[from] PipelineError),
}

/// 微信数据目录 + wxid → 账号 db 路径 (`db_storage/session/session.db` + `db_storage/message/`)。
///
/// 账号目录名 = `<wxid>` (裸) 或 `<wxid>_<设备后缀>` (实测如 `wxid_abcd1234efgh567_abfe`) — 跟
/// msgvestige `auth` 的 detect 反向。校验入口 db + message 目录存在。
///
/// # Errors
/// [`IngestError::AccountNotFound`] — 无匹配账号目录 / `session.db` 缺 / `message/` 缺。
pub fn locate_account_dbs(wechat_data_dir: &Path, wxid: &Wxid) -> Result<AccountDbPaths, IngestError> {
    let candidates = account_dir_candidates(wechat_data_dir, wxid)?;
    if candidates.is_empty() {
        return Err(IngestError::AccountNotFound {
            // K-R4: wxid 走 sha8, 不露数据目录绝对路径。
            what: format!(
                "数据目录下无匹配账号目录 <wxid>_<后缀> (wxid sha8={})",
                sha8(wxid.as_str().as_bytes())
            ),
        });
    }
    // 试每个候选 (exact 优先), 返第一个 db_storage 布局完整的 — 防同 wxid 多目录 (如旧备份/坏目录) 时
    // read_dir 先撞到坏候选就误报缺库 (代码双审 P1)。
    let mut last_reason = "匹配到账号目录但 db_storage 布局不全 (session.db / message/ 缺)".to_string();
    for dir in &candidates {
        let db_storage = dir.join("db_storage");
        let account_entry_db = db_storage.join("session").join("session.db");
        let message_dir = db_storage.join("message");
        if account_entry_db.is_file() && message_dir.is_dir() {
            let contact_db = db_storage.join("contact").join("contact.db");
            let favorite_db = db_storage.join("favorite").join("favorite.db");
            let sns_db = db_storage.join("sns").join("sns.db");
            let general_db = db_storage.join("general").join("general.db");
            let emoticon_db = db_storage.join("emoticon").join("emoticon.db");
            let head_image_db = db_storage.join("head_image").join("head_image.db");
            let bizchat_db = db_storage.join("bizchat").join("bizchat.db");
            return Ok(AccountDbPaths {
                account_entry_db,
                message_dir,
                contact_db,
                favorite_db,
                sns_db,
                general_db,
                emoticon_db,
                head_image_db,
                bizchat_db,
            });
        }
        last_reason = if account_entry_db.is_file() {
            "db_storage/message/ 目录缺失".to_string()
        } else {
            "db_storage/session/session.db 缺失".to_string()
        };
    }
    Err(IngestError::AccountNotFound { what: last_reason })
}

/// 扫数据目录, 收**所有** `<wxid>` / `<wxid>_<后缀>` 账号目录 (exact 优先, 再 suffixed)。
///
/// 后缀须以 `_` 起 (防 `<wxid>extra` 误配; wxid 自身含下划线时按整串匹配)。read_dir 失败 →
/// `AccountNotFound`(只带 io `ErrorKind`, 不带绝对路径; 代码双审 P2 不静默吞成"账号不存在")。
fn account_dir_candidates(wechat_data_dir: &Path, wxid: &Wxid) -> Result<Vec<PathBuf>, IngestError> {
    let target = wxid.as_str();
    let entries = std::fs::read_dir(wechat_data_dir).map_err(|e| IngestError::AccountNotFound {
        what: format!("微信数据目录不可读 ({:?})", e.kind()),
    })?;
    let mut exact = Vec::new();
    let mut suffixed = Vec::new();
    for ent in entries.flatten() {
        if !ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = ent.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == target {
            exact.push(ent.path());
        } else if name.strip_prefix(target).is_some_and(|s| s.starts_with('_')) {
            suffixed.push(ent.path());
        }
    }
    exact.extend(suffixed); // exact 优先, 再 suffixed
    Ok(exact)
}

/// 给定 [`DbSource`] + L1 库路径 → 开库 + 建 L1 schema + 跑 message ETL pipeline.
///
/// - `source`: 已构造的取数源 (真实为 `AccountDbSource`, 测试为 mock);
/// - `l1_db_path`: L1 输出库路径 (不存在则建);
/// - `account` / `mode` / `batch_limit` / `ingest_time_ms`: 透传 pipeline。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_message_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    // R15 并行度 (批内 decode); 1 = 串行。全量 ingest 主体 (百万级消息) 唯一受益者。
    workers: usize,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    // emit 推送 (InProcEmitter) 的 adapter 消费端接入推后续 (PR2-7); 当前 None = 只 archive 不推上层。
    let stats = native_core::run_message_pipeline_jobs(
        source,
        &mut conn,
        account,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
        workers,
    )
    .await?;
    Ok(stats)
}

/// 实时 message watch 选项 (件3, ADR-499)。
pub struct MessageWatchOpts {
    /// 新消息打印到 stdout (payload 明文)。
    pub print: bool,
    /// 写**真实 L1** (持久化, 库随消息更新); `false` = 临时库观察 (拷真库水位做 tail-f, **不动真库**)。
    pub to_l1: bool,
    /// 轮询间隔。
    pub poll: Duration,
    /// `0` = 永久 (直到 Ctrl-C); `>0` = 跑满秒数即停 (demo/测试限时)。
    pub max_secs: u64,
    /// 盯 mtime 的消息库文件 (`message_dir` 下 `*.db`); 任一 (或其 `-wal`) mtime 变 → 跑一遍增量。
    pub watch_dbs: Vec<PathBuf>,
    /// (serve `/events` 用) 优雅关停信号: `Some(rx)` 且收到 `true` → 跳出轮询干净收尾; sender drop 也停。
    /// CLI watch 传 `None` (无限循环靠 Ctrl-C)。
    pub cancel: Option<tokio::sync::watch::Receiver<bool>>,
    /// (serve `/events` 用) 落库进度通知: 每次增量 pipeline 成功后 send 递增计数 → 唤醒 SSE 连接去读档
    /// (best-effort, 只传信号不传消息)。CLI watch 传 `None`。
    pub progress: Option<tokio::sync::watch::Sender<u64>>,
}

/// R17 · message tail-f 策略 (原 [`run_message_watch`] 循环体, 挂 [`run_watch_loop`])。单元 = 单个 `"messages"`
/// (所有分片折一个复合签名, 任一分片 mtime 变则跑一遍增量 pipeline, 从 `etl_state` 水位 tail-f)。`scan_units` 内重扫
/// 消息目录拾运行期轮转新分片; `on_applied` 每 100 pass 合并 FTS 段 (仅 `to_l1`) + 发 progress。`conn`/`emitter`/
/// `progress`/`watch_dbs` 由 [`run_message_watch`] 建好 move 入; 收尾 drop 本策略即 drop conn+emitter → 消费端排空。
struct MessageTailStrategy<'a> {
    source: &'a mut dyn DbSource,
    conn: rusqlite::Connection,
    account: &'a Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    watch_dbs: Vec<PathBuf>,
    emitter: Option<native_core::emit::in_proc::InProcEmitter>,
    to_l1: bool,
    progress: Option<tokio::sync::watch::Sender<u64>>,
    progress_tick: u64,
}

impl WatchStrategy for MessageTailStrategy<'_> {
    fn scan_units(&mut self) -> Vec<(String, WatchSig)> {
        // R9 复审#2: 每 pass 重扫消息目录拾运行期新增分片 (微信轮转出 message_N.db); 固定列表会漏新分片 mtime → 漏同步。
        if let Some(dir) = self
            .watch_dbs
            .first()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                let mut fresh: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "db"))
                    .collect();
                fresh.sort();
                if !fresh.is_empty() && fresh != self.watch_dbs {
                    tracing::info!(
                        "[watch] 分片变化 {} -> {} 个消息库 (拾取轮转新分片)",
                        self.watch_dbs.len(),
                        fresh.len()
                    );
                    self.watch_dbs = fresh;
                }
            }
        }
        let sig: WatchSig = self
            .watch_dbs
            .iter()
            .map(|db| (mtime_ns(db), mtime_ns(&wal_sibling_of(db))))
            .collect();
        vec![("messages".to_string(), sig)]
    }
    async fn apply(&mut self, _unit: &str) -> anyhow::Result<ApplyOutcome> {
        // R17: 增量 tail-f 一遍。**方案B 撤锁 + watch 领 L1 片租约的激活推迟 R22**(见 native_core::write_lease 的
        // primitive + L2 入口; 现由 cmd_watch 的 OS 锁保单写者互斥, watch 不领 L1 片租约)。恒 Applied(单写者不会跳过)。
        let t0 = Instant::now();
        // 出错不推进 (driver 层): pipeline 水位 (etl_state cursor) 只在 sink ack 后推进, 失败=水位未动 → 重试
        // WHERE local_id > cursor 必再读到那些行 (WAL/主库都在), 至多重复一次打印, 不漏。
        let stats = run_message_pipeline_incremental(
            self.source,
            &mut self.conn,
            self.account,
            self.mode,
            self.batch_limit,
            now_millis_lib(),
            self.emitter.as_ref(),
        )
        .await?;
        tracing::info!("[watch] 增量 pass {:?} ({}ms)", stats, t0.elapsed().as_millis());
        Ok(ApplyOutcome::Applied)
    }
    fn on_applied(&mut self, _unit: &str) {
        // (serve /events) 落库成功 → 递增进度, 唤醒 SSE 连接去读档 (best-effort)。
        self.progress_tick += 1;
        // R9 件6: 每 100 pass 合并 FTS 段 (纯增量插碎片化 → 长跑 optimize 防膨胀)。仅 to_l1 且触发器在岗才做; best-effort。
        if self.to_l1
            && self.progress_tick.is_multiple_of(100)
            && native_core::storage::message_fts_triggers_exist(&self.conn)
        {
            if let Err(e) = native_core::storage::optimize_message_fts(&self.conn) {
                tracing::warn!("[watch] FTS optimize 失败 (不阻断): {e}");
            } else {
                tracing::debug!(pass = self.progress_tick, "[watch] FTS 段合并");
            }
        }
        if let Some(tx) = &self.progress {
            let _ = tx.send(self.progress_tick);
        }
    }
    fn label(&self) -> &'static str {
        "watch"
    }
}

/// 实时 message watch (件3, ADR-499): 轮询消息库 mtime → 变了就跑一遍**增量** message pipeline
/// → 写 L1 + 可选打印新消息。
///
/// `source` **须用 live cipher 构造** (`NativeCipher::new_live`), 否则会话读的是 checkpoint 快照、
/// 看不到 WAL 里未刷盘的最新消息 (件1/件2 地基)。**tail-f**: 从 L1 已有水位续抽 (只出新消息, 不回放
/// 历史); `to_l1=false` 时开临时库并拷真库 `etl_state` 水位 (真库全程不写)。轮询用 mtime (件2 决策:
/// 非 notify)。**messages 域** (v1; 其他域后续)。
///
/// # Errors
/// L1 open/建表 / pipeline 取数落库 / 临时库准备失败。
pub async fn run_message_watch(
    source: &mut dyn DbSource,
    real_l1_path: &Path,
    account: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    mut opts: MessageWatchOpts,
) -> anyhow::Result<()> {
    // clamp poll 下限 (审查 round2: --poll-ms 0 → sleep(0)/timeout(0) busy-spin 打满一核)。此处**一处覆盖**
    // cmd_serve /events 与独立 watch 命令两个调用点, 免夹逻辑漂移。
    opts.poll = opts.poll.max(Duration::from_millis(50));
    // 1. 选工作库: to_l1 → 真实 L1 (持久); 否则临时库 (观察, 真库不动)。
    let tmp_dir = if opts.to_l1 {
        None
    } else {
        Some(std::env::temp_dir().join(format!("wxwatch-{}", std::process::id())))
    };
    let work_l1 = match &tmp_dir {
        None => real_l1_path.to_path_buf(),
        Some(d) => {
            std::fs::create_dir_all(d)?;
            d.join("watch_tmp_l1.db")
        }
    };
    let conn = native_core::storage::open(&work_l1)?; // R17: move 入 MessageTailStrategy, run_message_watch 内只 &conn 不改。
    native_core::storage::init_l1_schema(&conn)?;
    // R19 选择性采集 · --print 临时观察库镜像真库 capture_targets → --print 也按配置过滤 (与 --to-l1 一致); 否则读空表=全采、
    // 静默无视用户 `capture add` 圈定 (codex round-1 P1)。
    // **无条件先清** (审 round-3 P3): 临时库路径按 PID 命名, 崩溃残留 + PID 复用会带旧 targets; 故进 --print 就先 `DELETE`
    //   清 capture_targets —— **即便真库不存在** (下面 if 跳过拷贝) 也清成空=全采, 而非按陈旧复用清单过滤观察。init_l1_schema 已建该表。
    // **INSERT (非 OR REPLACE)** (round-2 P2): DELETE 后空表上全拷 = 精确镜像 (真库无表/空 → 临时库保持空 = 全采), PK 唯一无重复键。
    // **查询错误传播** (round-2 P2): sqlite_master 恒在, 查询失败 = 真库 I/O/锁异常 → `?` fail-closed; 非 `unwrap_or(0)` 静默当
    //   "无表" → 空白名单全采 (选择性特性 fail-open 是错的默认)。
    // **启动快照语义**: 真库 mid-run 的 capture add/rm 不反映到临时库 (观察按启动时配置, 要看新圈定重启 watch)—— --to-l1 时
    //   work_l1=真库故是 live (下次 source 变化触发 body 时重读)。
    if tmp_dir.is_some() {
        conn.execute_batch("DELETE FROM capture_targets;")?;
    }
    // 临时库: 拷真库 etl_state 水位 → tail-f (只抽新, 真库不写)。真库缺则从头 (首跑会回放, demo 前应先 ingest)。
    if tmp_dir.is_some() && real_l1_path.exists() {
        let esc = real_l1_path.to_string_lossy().replace('\'', "''");
        conn.execute_batch(&format!("ATTACH DATABASE '{esc}' AS realdb;"))?;
        conn.execute_batch("INSERT OR REPLACE INTO etl_state SELECT * FROM realdb.etl_state;")?;
        let real_has_ct: i64 = conn.query_row(
            "SELECT count(*) FROM realdb.sqlite_master WHERE type='table' AND name='capture_targets'",
            [],
            |r| r.get(0),
        )?;
        if real_has_ct > 0 {
            conn.execute_batch("INSERT INTO capture_targets SELECT * FROM realdb.capture_targets;")?;
        }
        conn.execute_batch("DETACH DATABASE realdb;")?;
    }

    // 2. print 消费端 (spawn; current_thread 协作调度: pipeline emit().await 满时让出 → 此任务打印)。
    let (emitter, consumer) = if opts.print {
        // 小 cap: 每 emit 满即让出 → 消费端及时打印 (实时流, 非 1024 攒批). flush: stdout 重定向到文件时
        // 默认块缓冲, 不 flush 看不到实时输出.
        let (tx, mut rx) = new_in_proc(64, Backpressure::Block);
        let h = tokio::spawn(async move {
            use std::io::Write;
            let mut out = std::io::stdout();
            while let Some(rec) = rx.recv().await {
                let _ = writeln!(
                    out,
                    "[{}] {}/{} #{}  {}",
                    rec.source, rec.event_type, rec.event_action, rec.source_native_id, rec.payload_json
                );
                let _ = out.flush();
            }
        });
        (Some(tx), Some(h))
    } else {
        (None, None)
    };

    // 3. 轮询循环 (mtime 门控: 全没变则只 sleep, 零解密)。
    tracing::info!(
        "[watch] 监听 {} 个消息库 (poll {}ms · {} · 打印{})",
        opts.watch_dbs.len(),
        opts.poll.as_millis(),
        if opts.to_l1 {
            "写真实 L1"
        } else {
            "临时库观察·不动真库"
        },
        if opts.print { "开" } else { "关" }
    );
    // R17: 循环体 + 收尾收敛到 [`run_watch_loop`] + [`MessageTailStrategy`] —— 原 last_sig/mtime 门控/分片重扫/
    // FTS optimize/progress/cancel 脚手架全归共享驱动 + 策略。单元 = 单个 "messages"(所有分片一个复合签名, 任一变
    // 则跑一遍增量 pipeline), 行为等价。conn/emitter/watch_dbs/progress move 入策略, 收尾 drop 策略即 drop 二者。
    let mut strategy = MessageTailStrategy {
        source,
        conn,
        account,
        mode,
        batch_limit,
        watch_dbs: opts.watch_dbs,
        emitter,
        to_l1: opts.to_l1,
        progress: opts.progress,
        progress_tick: 0,
    };
    let r = run_watch_loop(&mut strategy, opts.poll, opts.max_secs, opts.cancel).await;

    // 收尾: drop strategy (含 conn + emitter) → 消费端排空后结束; 清临时库。
    drop(strategy);
    if let Some(h) = consumer {
        let _ = h.await;
    }
    if let Some(d) = tmp_dir {
        let _ = std::fs::remove_dir_all(d);
    }
    r
}

/// R18 件2: thin 持久档 daemon 参数 (MessageWatchOpts 的子集; thin 无 L1/emit/print/progress)。
pub struct ThinWatchOpts {
    /// 轮询间隔 (mtime 门控; clamp ≥50ms 防 busy-spin)。
    pub poll: Duration,
    /// `0` = 永久 (直到 Ctrl-C / 关停); `>0` = 跑满秒数即停 (测试限时)。
    pub max_secs: u64,
    /// 要监听的消息库分片 (运行期轮转出的新 `message_N.db` 自动拾取)。
    pub watch_dbs: Vec<PathBuf>,
    /// 优雅关停 (serve): `Some(rx)` 收到 `true` → 跳出; sender drop 也停 (同 [`MessageWatchOpts::cancel`])。
    pub cancel: Option<tokio::sync::watch::Receiver<bool>>,
}

/// R17 · thin 增量策略 (原 [`run_thin_watch`] 循环体, 挂 [`run_watch_loop`])。单元 = 单个 `"thin"`(所有分片折一
/// 复合签名, 任一变则灌一遍瘦 FTS)。`scan_units` 内重扫消息目录拾轮转新分片; 无 L1/print/progress/FTS-optimize。
struct ThinStrategy<'a> {
    source: &'a mut dyn DbSource,
    thin: rusqlite::Connection,
    account: &'a Wxid,
    batch_limit: usize,
    watch_dbs: Vec<PathBuf>,
}

impl WatchStrategy for ThinStrategy<'_> {
    fn scan_units(&mut self) -> Vec<(String, WatchSig)> {
        // 分片重扫 (拾运行期新增 message_N.db; 同 message R9 复审#2 —— 固定列表会漏新分片)。
        if let Some(dir) = self
            .watch_dbs
            .first()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                let mut fresh: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "db"))
                    .collect();
                fresh.sort();
                if !fresh.is_empty() && fresh != self.watch_dbs {
                    tracing::info!("[thin-watch] 分片变化 {} -> {} 个", self.watch_dbs.len(), fresh.len());
                    self.watch_dbs = fresh;
                }
            }
        }
        let sig: WatchSig = self
            .watch_dbs
            .iter()
            .map(|db| (mtime_ns(db), mtime_ns(&wal_sibling_of(db))))
            .collect();
        vec![("thin".to_string(), sig)]
    }
    async fn apply(&mut self, _unit: &str) -> anyhow::Result<ApplyOutcome> {
        // thin 不写 L1、不领租约(独立瘦库), 恒 Applied。
        let n = native_core::thin::run_thin_pipeline_incremental(
            self.source,
            &mut self.thin,
            self.account,
            self.batch_limit,
        )
        .await?;
        tracing::info!("[thin-watch] 增量灌 {n} 条正文入瘦库");
        Ok(ApplyOutcome::Applied)
    }
    fn label(&self) -> &'static str {
        "thin-watch"
    }
}

/// R18 件2: thin 持久档 daemon —— tail-f 加密源库消息、增量灌独立瘦 FTS (**不建 L1**)。复用 run_message_watch
/// 的 mtime 门控 + 分片重扫 + 取消收尾; 每轮调 [`native_core::thin::run_thin_pipeline_incremental`] (源→thin)。
/// thin 库自身水位持久化 (thin_meta) → 崩溃/重启从水位续抽; 出错**不退出**、下轮重试 (水位未推进不漏)。
///
/// # Errors
/// 打开 thin 库 / init FTS 失败 (致命, 返错); drain/写失败逐轮重试不退出 (同 run_message_watch)。
pub async fn run_thin_watch(
    source: &mut dyn DbSource,
    thin_db_path: &Path,
    account: &Wxid,
    batch_limit: usize,
    mut opts: ThinWatchOpts,
) -> anyhow::Result<()> {
    opts.poll = opts.poll.max(Duration::from_millis(50));
    let thin = native_core::storage::open(thin_db_path)?; // R17: move 入 ThinStrategy, run_thin_watch 内只 &thin 不改。
    native_core::storage::init_thin_fts(&thin)?;
    native_core::storage::init_thin_meta(&thin)?;
    // R18: 绑定账号 (build 有此语义; daemon 补上 → search 靠 get_thin_account 核对防跨账号搜)。已绑别账号 → 拒,
    // 不覆盖别账号的瘦库 (换账号请用新瘦库路径)。空瘦库首建 → 写绑定。
    let acct_sha = native_core::sha256_hex(account.as_str());
    match native_core::storage::get_thin_account(&thin)? {
        Some(bound) => anyhow::ensure!(bound == acct_sha, "瘦库已绑定别的账号 (换账号请用新的 --thin-db 路径)"),
        None => native_core::storage::set_thin_account(&thin, &acct_sha)?,
    }
    tracing::info!(
        "[thin-watch] 监听 {} 个消息库 (poll {}ms) → 独立瘦库 {}",
        opts.watch_dbs.len(),
        opts.poll.as_millis(),
        thin_db_path.file_name().and_then(|n| n.to_str()).unwrap_or("thin.db") // K-R4: 路径只记文件名(全路径可能含用户名)
    );
    // R17: 循环体收敛到 [`run_watch_loop`] + [`ThinStrategy`](单元 = 单个 "thin", 所有分片折一签名, 变了灌瘦库)。
    let mut strategy = ThinStrategy {
        source,
        thin,
        account,
        batch_limit,
        watch_dbs: opts.watch_dbs,
    };
    run_watch_loop(&mut strategy, opts.poll, opts.max_secs, opts.cancel).await
}

/// 文件 mtime → 纳秒 (取不到 = 0). watch mtime 门控用 (件3)。
fn mtime_ns(p: &Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .map(|t| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64)
        .unwrap_or(0)
}

/// `<db>` → `<db>-wal` (新消息先落 WAL, 故 WAL mtime 是主变化信号)。
fn wal_sibling_of(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push("-wal");
    PathBuf::from(s)
}

/// 当前 unix 毫秒 (ingest_time_ms 用)。
fn now_millis_lib() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ── R17 统一底座 · L1: 共享 watch 驱动 (抽 message/source/thin 三套同构循环) ──

/// R17: 监听单元签名 = 该单元所有相关文件的 `(mtime_ns, wal_mtime_ns)`。签名变 → 该单元需跑一遍。
/// 用 `Vec` 精确逐对比较 (非 hash 折叠) 避免碰撞漏更新。
pub type WatchSig = Vec<(u64, u64)>;

/// R17: [`WatchStrategy::apply`] 结果 —— **驱动 skip-契约**。`Applied` 才推进 `last_sig` 签名 + 调 `on_applied`;
/// `Skipped` **不推进签名**(下轮 poll 继续判该单元)+ 不调 `on_applied`。
///
/// **为何分两态(不复用 `Ok(())`)**: 若「跳过没处理」也推进签名, mtime 门控会关死本进程对该单元的重判 → 崩溃/接管恢复
/// 路径被架空(round1 对抗审逮到的 P1: 持租者硬崩+源库静默时数据静默丢)。分两态后跳过下轮必重判、接手不丢。
///
/// **现状(方案B 激活推迟 R22)**: R17 的 watch 三策略由 `cmd_watch` 的 OS 锁保单写者, **不领 L1 片租约、恒返 `Applied`**;
/// `Skipped` 是给 **R22 懒式(片被别写者持租→可重试延迟)** 预留的驱动契约, 现仅 mock/skip 测试触发。
///
/// **注(codex round-1 双审)**: R19 选择性采集"跳过未圈会话"是**另一语义**——有意不采 = 该签名已决、应**推进**签名不再重判;
/// 与本 `Skipped`(可重试延迟 = **不**推进签名)相反。R19 接线须走**推进签名**的路径(现有 `Applied` 或届时另加 outcome),
/// **别复用 `Skipped`**(否则每 poll 重复处理已决签名)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// 真处理了该单元(驱动推进签名 + 调 `on_applied`)。
    Applied,
    /// 本轮**可重试延迟**没处理(驱动**不推进**签名 + 不调 `on_applied`, 下轮 poll 再认领)。R22 租约阻塞用; watch 现不产生。
    Skipped,
}

/// R17 统一底座 · L1: **watch 策略挂载点**。共享驱动 [`run_watch_loop`] 持 poll/cancel/max_secs/重试骨架 +
/// `last_sig`; 策略声明"监听哪些单元、变了跑什么、跑完做什么"。三填法各一 impl (message tail-f / source 整表重扫 /
/// thin) —— 抽掉三处各写一遍的 `mtime_ns`/poll/cancel/重试脚手架。
///
/// **`async fn in trait`**: 仅静态分发 (驱动泛型 `S`), future `!Send` 无碍 (watch 跑在 current_thread runtime)。
#[allow(async_fn_in_trait)]
pub trait WatchStrategy {
    /// 重扫监听单元 (拾运行期新增分片/小库), 返回 `(单元id, 当前签名)`。签名与上轮不同 → 该单元需 `apply`。
    fn scan_units(&mut self) -> Vec<(String, WatchSig)>;
    /// (去抖, source 用) 该单元距上次成功跑仍在窗内 → 本轮跳过 (不推进签名, 下轮再判到期)。默认无去抖。
    fn debounced(&self, _unit: &str) -> bool {
        false
    }
    /// 跑变化的单元 (增量/整表)。返回 [`ApplyOutcome`]: `Applied`=真处理了(驱动推进签名 + 调 `on_applied`);
    /// `Skipped`=被别的写者持租跳过(驱动**不推进**签名, 下轮 poll 再认领)。`Err` → **不推进**签名 → 下轮重试(幂等安全)。
    async fn apply(&mut self, unit: &str) -> anyhow::Result<ApplyOutcome>;
    /// `apply` 成功后回调 (记去抖时刻 / progress tick / FTS optimize)。默认空。
    fn on_applied(&mut self, _unit: &str) {}
    /// 日志标签 (如 `"watch"` / `"source-watch"` / `"thin-watch"`)。
    fn label(&self) -> &str;
}

/// R17 统一底座 · L1: **共享 watch 驱动**。抽三套同构循环骨架 —— 重扫单元 → 算签名 → 变了 `apply` →
/// Ok 推进签名 / Err 不推进 (下轮重试) → `max_secs` 判断 → cancel 感知 poll。`poll` clamp ≥50ms 防 busy-spin
/// (同原三套)。cancel: `Some(rx)` 收 `true` / sender drop → 提前干净收尾 (serve 优雅关停); `None` 靠 Ctrl-C。
///
/// # Errors
/// 当前 `apply` 错只 warn 不上抛 (整体不退出, 同原 watch: 单库临时错不该崩整个监听); 保留 `Result` 供未来致命错上抛。
pub async fn run_watch_loop<S: WatchStrategy>(
    strategy: &mut S,
    poll: Duration,
    max_secs: u64,
    mut cancel: Option<tokio::sync::watch::Receiver<bool>>,
) -> anyhow::Result<()> {
    let poll = poll.max(Duration::from_millis(50));
    let start = Instant::now();
    let mut last_sig: std::collections::HashMap<String, WatchSig> = std::collections::HashMap::new();
    loop {
        for (unit, sig) in strategy.scan_units() {
            if last_sig.get(&unit) == Some(&sig) {
                continue; // mtime 门控: 未变 → 零解密跳过。
            }
            if strategy.debounced(&unit) {
                continue; // 去抖窗内 → 不推进 (下轮再判到期)。
            }
            match strategy.apply(&unit).await {
                Ok(ApplyOutcome::Applied) => {
                    last_sig.insert(unit.clone(), sig); // 真处理成功才推进 (失败/跳过留旧值 → 下轮 sig 仍 != → 再判)。
                    strategy.on_applied(&unit);
                }
                Ok(ApplyOutcome::Skipped) => {
                    // R17 P1 修(round1 对抗审): 被别的写者持租跳过 ≠ 处理成功 → **不推进 last_sig**(下轮 poll 继续认领;
                    // 持租者硬崩后 ≤TTL 租约过期即由本进程接手, 从持久 cursor 续 drain, 不丢)。也不调 on_applied(无进度)。
                    // 误推进 = mtime 门控关死本进程认领 → 崩溃恢复路径被架空 → 休眠账号静默丢数据。
                }
                Err(e) => {
                    tracing::warn!(
                        "[{}] 单元 {unit} 跑失败, 下轮重试 (签名未推进, 不漏): {e}",
                        strategy.label()
                    );
                }
            }
        }
        if max_secs > 0 && start.elapsed().as_secs() >= max_secs {
            break;
        }
        // 轮询间隔 (取消感知; 用 timeout 而非 select! 宏不依赖 tokio "macros" feature)。
        match &mut cancel {
            Some(rx) => match tokio::time::timeout(poll, rx.changed()).await {
                Ok(Ok(())) => {
                    if *rx.borrow() {
                        break; // 收到取消信号。
                    }
                }
                Ok(Err(_)) => break, // sender dropped → 停。
                Err(_) => {}         // 超时 = 正常, 继续轮询。
            },
            None => tokio::time::sleep(poll).await,
        }
    }
    Ok(())
}

#[cfg(test)]
mod watch_loop_tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use super::{run_watch_loop, ApplyOutcome, WatchSig, WatchStrategy};

    /// Mock 策略: 预设每轮 `scan_units` 返回值; 指定哪些 unit 的 `apply` 失败; 记录 apply 调用序。
    /// rounds 耗尽后 `scan_units` 发 cancel 让驱动干净收尾 (确定性, 不靠 max_secs 计时避免 flaky)。
    struct MockStrategy {
        rounds: Vec<Vec<(String, WatchSig)>>,
        round_idx: usize,
        fail_units: HashSet<String>,
        skip_units: HashSet<String>,   // apply 返 Skipped (模拟 HeldByOther) 的 unit。
        applied_ok: Vec<String>,       // apply 成功(Applied)的 unit 序。
        applied_attempts: Vec<String>, // 所有 apply 调用 (含失败/跳过)。
        cancel_tx: Option<tokio::sync::watch::Sender<bool>>,
    }

    impl WatchStrategy for MockStrategy {
        fn scan_units(&mut self) -> Vec<(String, WatchSig)> {
            if self.round_idx >= self.rounds.len() {
                if let Some(tx) = self.cancel_tx.take() {
                    let _ = tx.send(true); // rounds 耗尽 → 发 cancel, 下个 poll 收尾。
                }
                return vec![];
            }
            let r = self.rounds[self.round_idx].clone();
            self.round_idx += 1;
            r
        }
        async fn apply(&mut self, unit: &str) -> anyhow::Result<ApplyOutcome> {
            self.applied_attempts.push(unit.to_string());
            if self.fail_units.contains(unit) {
                anyhow::bail!("mock fail {unit}");
            }
            if self.skip_units.contains(unit) {
                return Ok(ApplyOutcome::Skipped); // 模拟 HeldByOther: 不推进签名。
            }
            self.applied_ok.push(unit.to_string());
            Ok(ApplyOutcome::Applied)
        }
        fn label(&self) -> &'static str {
            "mock"
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn sig(m: u64) -> WatchSig {
        vec![(m, 0)]
    }

    /// 变了才跑、未变跳过: A 轮1(1)跑→轮2(1)跳→轮3(2)跑; B 轮1(1)跑→轮2(2)跑→轮3(2)跳。
    #[test]
    fn applies_changed_skips_unchanged() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut s = MockStrategy {
            rounds: vec![
                vec![("A".into(), sig(1)), ("B".into(), sig(1))],
                vec![("A".into(), sig(1)), ("B".into(), sig(2))],
                vec![("A".into(), sig(2)), ("B".into(), sig(2))],
            ],
            round_idx: 0,
            fail_units: HashSet::new(),
            skip_units: HashSet::new(),
            applied_ok: vec![],
            applied_attempts: vec![],
            cancel_tx: Some(tx),
        };
        rt().block_on(run_watch_loop(&mut s, Duration::from_millis(10), 0, Some(rx)))
            .unwrap();
        // 轮1: A,B 都新 → 跑; 轮2: A 未变跳过、B 变→跑; 轮3: A 变→跑、B 未变跳过。
        assert_eq!(s.applied_ok, vec!["A", "B", "B", "A"]);
    }

    /// apply 失败不推进签名 → 下轮同签名仍判"变"→ 重试 (不漏)。A 每轮失败 → 每轮都重试。
    #[test]
    fn failed_unit_not_advanced_retried() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut s = MockStrategy {
            rounds: vec![
                vec![("A".into(), sig(1))],
                vec![("A".into(), sig(1))],
                vec![("A".into(), sig(1))],
            ],
            round_idx: 0,
            fail_units: HashSet::from(["A".to_string()]),
            skip_units: HashSet::new(),
            applied_ok: vec![],
            applied_attempts: vec![],
            cancel_tx: Some(tx),
        };
        rt().block_on(run_watch_loop(&mut s, Duration::from_millis(10), 0, Some(rx)))
            .unwrap();
        assert_eq!(s.applied_attempts, vec!["A", "A", "A"], "失败不推进 → 每轮重试");
        assert!(s.applied_ok.is_empty(), "全失败无成功");
    }

    /// **P1 回归(round1 对抗审逮到)**: apply 返 `Skipped`(模拟 HeldByOther)**不推进签名** → 下轮同签名仍再认领。
    /// 这是「持租者硬崩后本进程接手不丢」的地基。旧 bug(Skipped 也推进签名)下 A 只会 apply 一次、门控关死永不重试。
    #[test]
    fn skipped_unit_not_advanced_retried() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut s = MockStrategy {
            rounds: vec![
                vec![("A".into(), sig(1))],
                vec![("A".into(), sig(1))],
                vec![("A".into(), sig(1))],
            ],
            round_idx: 0,
            fail_units: HashSet::new(),
            skip_units: HashSet::from(["A".to_string()]),
            applied_ok: vec![],
            applied_attempts: vec![],
            cancel_tx: Some(tx),
        };
        rt().block_on(run_watch_loop(&mut s, Duration::from_millis(10), 0, Some(rx)))
            .unwrap();
        // Skipped 不推进 last_sig → 每轮同签名仍判"变"→ 再 apply。3 轮 = 3 次尝试(旧 bug 会只 1 次)。
        assert_eq!(
            s.applied_attempts,
            vec!["A", "A", "A"],
            "Skipped 不推进签名 → 每轮重认领(P1 修)"
        );
        assert!(s.applied_ok.is_empty(), "全 Skipped 无 Applied");
    }

    /// cancel 信号 → 干净收尾 (rounds 未耗尽也能被 cancel 打断)。
    #[test]
    fn cancel_breaks_loop() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let _ = tx.send(true); // 预置 cancel: 第一轮处理完 poll 即退。
        let mut s = MockStrategy {
            rounds: vec![vec![("A".into(), sig(1))]],
            round_idx: 0,
            fail_units: HashSet::new(),
            skip_units: HashSet::new(),
            applied_ok: vec![],
            applied_attempts: vec![],
            cancel_tx: None,
        };
        rt().block_on(run_watch_loop(&mut s, Duration::from_millis(10), 0, Some(rx)))
            .unwrap();
        assert_eq!(s.applied_ok, vec!["A"], "第一轮跑完即被 cancel 收尾");
    }
}

// ── R9 件5: full 全源库监听 (小库整表重跑, 与消息 tail-f 并行) ──

/// R9 件5: 源库监听参数 (full 小库整表重跑; 对标 [`MessageWatchOpts`] 但小库走整表非 tail-f)。
pub struct SourceWatchOpts {
    /// 轮询间隔 (mtime 门控)。
    pub poll: Duration,
    /// `0` = 永久 (直到 Ctrl-C / 关停); `>0` = 跑满秒数即停 (测试限时)。
    pub max_secs: u64,
    /// **去抖**: 每源库至多每 `debounce` 整表重跑一次 (session/contact 高频变防每 poll 窗重跑; spec §4 P1)。
    pub debounce: Duration,
    /// 优雅关停 (serve): `Some(rx)` 收到 `true` → 跳出; sender drop 也停 (同 [`MessageWatchOpts::cancel`])。
    pub cancel: Option<tokio::sync::watch::Receiver<bool>>,
}

/// R9 件5: 源库监听分组 —— 一个小库文件 + 它喂的 L1 域 `plan`。mtime 变 → 该组域整表重跑 (幂等 upsert)。
struct SourceGroup {
    db: PathBuf,
    label: &'static str,
    plan: IngestPlan,
}

/// R9 件5: 建源库监听分组 (存在的库才盯)。**消息 + biz_message 走 tail-f** ([`run_message_watch`]) **不在此**;
/// 小库 (更新型: 联系人/会话被改非纯追加 → tail-f 会漏改 → 整表重跑幂等收敛)。域→源库映射对齐 [`run_full_ingest`]。
fn build_source_groups(paths: &AccountDbPaths) -> Vec<SourceGroup> {
    let mk = |db: &Path, label, plan| SourceGroup {
        db: db.to_path_buf(),
        label,
        plan,
    };
    [
        mk(
            &paths.contact_db,
            "contact",
            IngestPlan {
                messages: false,
                contacts: true,
                chatrooms: true,
                strangers: true,
                ..Default::default()
            },
        ),
        mk(
            &paths.account_entry_db,
            "session",
            IngestPlan {
                messages: false,
                sessions: true,
                ..Default::default()
            },
        ),
        mk(
            &paths.favorite_db,
            "favorite",
            IngestPlan {
                messages: false,
                favorites: true,
                ..Default::default()
            },
        ),
        mk(
            &paths.sns_db,
            "sns",
            IngestPlan {
                messages: false,
                sns: true,
                moment_feeds: true,
                sns_notifies: true,
                ..Default::default()
            },
        ),
        mk(
            &paths.general_db,
            "general",
            IngestPlan {
                messages: false,
                transfers: true,
                red_envelopes: true,
                group_pays: true,
                friend_verifies: true,
                finder_visits: true,
                ..Default::default()
            },
        ),
        mk(
            &paths.emoticon_db,
            "emoticon",
            IngestPlan {
                messages: false,
                emoticons: true,
                ..Default::default()
            },
        ),
        mk(
            &paths.head_image_db,
            "avatar",
            IngestPlan {
                messages: false,
                avatars: true,
                ..Default::default()
            },
        ),
        mk(
            &paths.bizchat_db,
            "bizchat",
            IngestPlan {
                messages: false,
                bizchat: true,
                ..Default::default()
            },
        ),
    ]
    .into_iter()
    .filter(|g| g.db.is_file())
    .collect()
}

/// R17 · source 整表重扫策略 (原 [`run_source_watch`] 循环体, 挂 [`run_watch_loop`])。每单元 = 一个小库组 (label);
/// 小库 mtime 变 → 对应域 [`run_full_ingest`] 整表重跑 (幂等 upsert, workers=1); 去抖防 session/contact 高频变每 poll 窗重跑。
struct SourceRescanStrategy<'a> {
    source: &'a mut AccountDbSource,
    paths: &'a AccountDbPaths,
    l1_db: &'a Path,
    account: &'a Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    debounce: Duration,
    groups: Vec<SourceGroup>,
    last_run: std::collections::HashMap<String, Instant>,
    prev_group_count: usize,
}

impl WatchStrategy for SourceRescanStrategy<'_> {
    fn scan_units(&mut self) -> Vec<(String, WatchSig)> {
        // R9 复审 R2#3: 每 pass 重扫小库组 —— 启动时不存在、运行期才建的库 (contact/sns/favorite/avatar 等) 也纳入。
        self.groups = build_source_groups(self.paths);
        // R17(Claude round-1 建议): 钉死 label 唯一不变量 —— 本策略靠 label keying last_sig/last_run + apply 的 find(label);
        // 两组同 label 会静默丢数据(HashMap 覆盖 + find 只命中首个)。现 8 个静态 label 天然唯一, 此断言防未来加组撞车。
        debug_assert!(
            {
                let mut ls: Vec<&str> = self.groups.iter().map(|g| g.label).collect();
                ls.sort_unstable();
                ls.dedup();
                ls.len() == self.groups.len()
            },
            "source-watch: build_source_groups 的 label 必须唯一(SourceRescanStrategy 按 label keying)"
        );
        if self.groups.len() != self.prev_group_count {
            tracing::info!(
                "[source-watch] 小库组变化 {} → {} 个 (拾取运行期新建小库)",
                self.prev_group_count,
                self.groups.len()
            );
            self.prev_group_count = self.groups.len();
        }
        self.groups
            .iter()
            .map(|g| {
                (
                    g.label.to_string(),
                    vec![(mtime_ns(&g.db), mtime_ns(&wal_sibling_of(&g.db)))],
                )
            })
            .collect()
    }
    fn debounced(&self, unit: &str) -> bool {
        // 去抖: mtime 变了但该组距上次重跑 < debounce → 暂不跑 (不推进, 下轮再判到期)。
        self.last_run.get(unit).is_some_and(|lr| lr.elapsed() < self.debounce)
    }
    async fn apply(&mut self, unit: &str) -> anyhow::Result<ApplyOutcome> {
        let now = now_millis_lib();
        // 找该单元 (小库组) 的 plan (clone 以释放 self.groups 借用, 免与 &mut self.source 冲突)。
        let plan = self
            .groups
            .iter()
            .find(|g| g.label == unit)
            .map(|g| g.plan)
            .ok_or_else(|| anyhow::anyhow!("source-watch: 单元 {unit} 无对应组"))?;
        // source-watch: mtime 触发的小库组重跑 = 增量节奏, 串行 workers=1 (低延迟优先, 非吞吐)。
        // (方案B watch 领 L1 片租约激活推迟 R22; 现由 cmd_watch OS 锁保单写者互斥。恒 Applied。)
        let stats = run_full_ingest(
            self.source,
            self.paths,
            self.l1_db,
            self.account,
            self.mode,
            self.batch_limit,
            &plan,
            now,
            1,
        )
        .await?;
        tracing::info!("[source-watch] {unit} 整表重跑完 ({} 域)", stats.len());
        Ok(ApplyOutcome::Applied)
    }
    fn on_applied(&mut self, unit: &str) {
        self.last_run.insert(unit.to_string(), Instant::now());
    }
    fn label(&self) -> &'static str {
        "source-watch"
    }
}

/// R9 件5: **full 全源库监听** —— 小库 mtime 变 → 对应域整表重跑 (幂等 upsert), 让 L1 全表跟源库实时。
/// 与消息 tail-f ([`run_message_watch`]) 并行 (serve `--live-index full` 起两套)。
///
/// **为何小库整表重跑而非 tail-f**: 小库多更新型 (联系人/会话被改, 非纯追加) → tail-f-by-watermark 漏改;
/// 小库小 → 整表重跑绕过"追哪行改了", 幂等 upsert 天然收敛 (spec §4)。**去抖** (`opts.debounce`) 防
/// session/contact 高频变每 poll 窗重跑。**出错不退出** (记 warn 下轮重试; 同 `run_message_watch`: 单库临时错
/// 不该崩整个监听)。**删除不传播** (整表重跑是 upsert, 源头删的行不从 L1 消失; spec §4 P2 接受此限)。
///
/// # Errors
/// 目前循环内单库重跑失败只 warn 不返 (整体不退出); 保留 `Result` 供未来致命错 (如 source 会话失效) 上抛。
pub async fn run_source_watch(
    source: &mut AccountDbSource,
    paths: &AccountDbPaths,
    l1_db: &Path,
    account: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    mut opts: SourceWatchOpts,
) -> anyhow::Result<()> {
    opts.poll = opts.poll.max(Duration::from_millis(50)); // clamp: 防 busy-spin (同 run_message_watch)。
    let groups = build_source_groups(paths);
    tracing::info!(
        "[source-watch] 监听 {} 个小库整表重跑 (poll {}ms · 去抖 {}s)",
        groups.len(),
        opts.poll.as_millis(),
        opts.debounce.as_secs()
    );
    // R17: 循环体收敛到 [`run_watch_loop`] + [`SourceRescanStrategy`](原 last_sig/last_run/mtime 门控/去抖/cancel 脚手架
    // 全归共享驱动 + 策略)。行为等价: 每单元 = 小库组 label, 变了整表重跑 (workers=1)、去抖、Err 不推进重试。
    let mut strategy = SourceRescanStrategy {
        source,
        paths,
        l1_db,
        account,
        mode,
        batch_limit,
        debounce: opts.debounce,
        groups: Vec::new(),
        last_run: std::collections::HashMap::new(),
        prev_group_count: groups.len(),
    };
    run_watch_loop(&mut strategy, opts.poll, opts.max_secs, opts.cancel).await
}

/// 给定 [`DbSource`] + L1 库路径 + contact.db → 开库 + 建 L1 schema + 跑 contact ETL pipeline.
///
/// 跟 [`run_message_ingest`] 同型 (开库/建表共用 [`init_l1_schema`](native_core::storage::init_l1_schema))。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标; contact.db 缺则 cipher 错)。
pub async fn run_contact_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    contact_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    // emit 推送 (InProcEmitter) 的 adapter 消费端接入推后续 (PR2-7); 当前 None = 只 archive 不推上层。
    let stats = run_contact_pipeline(
        source,
        &mut conn,
        account,
        contact_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + contact.db (chat_room 表所在) → 开库 + 建 schema + 跑群成员 ETL.
///
/// 群成员 diff (退群闭环 ADR-426 §1.1) 在 native-core `run_chatroom_pipeline`; adapter 只接线
/// (同 [`run_contact_ingest`])。emit 推送消费端接入推后续 (PR2-7); 当前 None = 只 archive 不推上层。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_chatroom_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    contact_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_chatroom_pipeline(
        source,
        &mut conn,
        account,
        contact_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + session.db → 开库 + 建 schema + 跑 session 会话列表 ETL.
///
/// 会话状态可变 (unread/summary/sort) → native-core `run_session_pipeline` 全表重扫 + content_digest
/// 去重 (同 contact/chatroom); adapter 只接线。`session_db` = `db_storage/session/session.db`(即 locate
/// 产出的 `account_entry_db`, 与账号入口 db 同库 — memory 实测)。emit 推送消费端接入推后续 (PR2-7);
/// 当前 None = 只 archive 不推上层。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_session_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    session_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_session_pipeline(
        source,
        &mut conn,
        account,
        session_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + favorite.db → 开库 + 建 schema + 跑 favorite 收藏 ETL (ADR-454).
///
/// 收藏项创建后基本不变 → native-core `run_favorite_pipeline` 全表重扫 + content_digest 去重 (同 session);
/// adapter 只接线。`favorite_db` = `db_storage/favorite/favorite.db`。当前 emitter None = 只 archive 不推。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_favorite_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    favorite_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_favorite_pipeline(
        source,
        &mut conn,
        account,
        favorite_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + favorite.db → 跑 favorite_tag 收藏标签 ETL (ADR-454 批 B-2).
///
/// fav_bind_tag ⋈ fav_tag 全表重扫 + content_digest 去重; adapter 只接线。当前 emitter None = 只 archive。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_favorite_tag_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    favorite_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_favorite_tag_pipeline(
        source,
        &mut conn,
        account,
        favorite_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + sns.db → 开库 + 建 schema + 跑 sns 朋友圈 ETL (ADR-467 件1).
///
/// 动态本体 immutable (点赞变刷计数) → native-core `run_sns_pipeline` 全表重扫 + content_digest 去重 (同
/// favorite; tid 游标从 i64::MIN 起覆盖负 tid); adapter 只接线。`sns_db` = `db_storage/sns/sns.db`。
/// 当前 emitter None = 只 archive 不推。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_sns_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    sns_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_sns_pipeline(
        source,
        &mut conn,
        account,
        sns_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + general.db → 开库 + 建 schema + 跑 transfer 转账 ETL (ADR-468).
///
/// 转账随状态推进就地 UPDATE → native-core `run_transfer_pipeline` 全表重扫 + content_digest 去重 (同 favorite);
/// adapter 只接线。`general_db` = `db_storage/general/general.db` (transferTable 所在)。当前 emitter None = 只 archive。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_transfer_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    general_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_transfer_pipeline(
        source,
        &mut conn,
        account,
        general_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + general.db → 开库 + 建 schema + 跑 red_envelope 红包 ETL (ADR-468 件2).
///
/// 红包随领取状态推进就地 UPDATE → native-core `run_red_envelope_pipeline` 全表重扫 + content_digest 去重 (同
/// transfer); adapter 只接线。`general_db` = `db_storage/general/general.db` (redEnvelopeTable 所在)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_red_envelope_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    general_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_red_envelope_pipeline(
        source,
        &mut conn,
        account,
        general_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + general.db → 开库 + 建 schema + 跑 group_pay 群收款 ETL (ADR-468 件3).
///
/// native-core `run_group_pay_pipeline` 全表重扫 + content_digest 去重; adapter 只接线。`general_db` =
/// `db_storage/general/general.db` (groupPayTable 所在)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_group_pay_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    general_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_group_pay_pipeline(
        source,
        &mut conn,
        account,
        general_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + general.db → 开库 + 建 schema + 跑 friend_verify 好友验证 ETL (ADR-469).
///
/// native-core `run_friend_verify_pipeline` 全表重扫 + content_digest 去重; adapter 只接线。`general_db` =
/// `db_storage/general/general.db` (FMessageTable 所在)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_friend_verify_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    general_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_friend_verify_pipeline(
        source,
        &mut conn,
        account,
        general_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + general.db → 开库 + 建 schema + 跑 finder_visit 视频号主页 ETL (ADR-473).
///
/// native-core `run_finder_visit_pipeline` 全表重扫 + content_digest 去重 + 空壳行跳过; adapter 只接线。
/// `general_db` = `db_storage/general/general.db` (wcfinderuserpage 所在)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_finder_visit_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    general_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_finder_visit_pipeline(
        source,
        &mut conn,
        account,
        general_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + sns.db → 开库 + 建 schema + 跑 moment_feed 朋友圈动态索引 ETL (ADR-474).
///
/// native-core `run_moment_feed_pipeline` 全表重扫 + content_digest 去重 (源重复 tid 靠 anchor + upsert 收敛);
/// adapter 只接线。`sns_db` = `db_storage/sns/sns.db` (SnsTopItem_1 所在)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_moment_feed_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    sns_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_moment_feed_pipeline(
        source,
        &mut conn,
        account,
        sns_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + sns.db → 开库 + 建 schema + 跑 sns_notify 朋友圈互动通知 ETL (照 moment_feed ADR-474).
///
/// native-core `run_sns_notify_pipeline` 全表重扫 + content_digest 去重 (源重复靠 anchor + upsert 收敛);
/// adapter 只接线。`sns_db` = `db_storage/sns/sns.db` (SnsMessage_tmp3 所在, 与 moment_feed 同库)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_sns_notify_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    sns_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_sns_notify_pipeline(
        source,
        &mut conn,
        account,
        sns_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + emoticon.db → 开库 + 建 schema + 跑 custom_emoticon 自定义表情 ETL (ADR-478).
///
/// native-core `run_emoticon_pipeline` 全表重扫 + content_digest 去重 + 空 md5 跳过; adapter 只接线。
/// `emoticon_db` = `db_storage/emoticon/emoticon.db` (kNonStoreEmoticonTable 所在)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_emoticon_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    emoticon_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_emoticon_pipeline(
        source,
        &mut conn,
        account,
        emoticon_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 给定 [`DbSource`] + L1 库路径 + bizchat.db → 开库 + 建 schema + 跑 bizchat_user 企微品牌号联系人 ETL (ADR-482).
///
/// native-core `run_bizchat_pipeline` 全表重扫 + content_digest 去重 + 空 user_id 跳过; adapter 只接线。
/// `bizchat_db` = `db_storage/bizchat/bizchat.db` (user_info 所在)。emitter None。
///
/// # Errors
/// [`IngestError::Storage`] (开库/建表) / [`IngestError::Pipeline`] (取数/落库/游标)。
pub async fn run_bizchat_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    bizchat_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_bizchat_pipeline(
        source,
        &mut conn,
        account,
        bizchat_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 跑一遍 avatar_image 头像图 ETL (ADR-481)。开库 + 建 L1 schema + 跑 `run_avatar_pipeline`。
///
/// `head_image_db` = `db_storage/head_image/head_image.db` (head_image 表所在)。emitter None。
///
/// # Errors
/// 开库 / 建 schema / pipeline 失败。
pub async fn run_avatar_ingest(
    source: &mut dyn DbSource,
    l1_db_path: &Path,
    account: &Wxid,
    head_image_db: &Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<PipelineStats, IngestError> {
    let mut conn = native_core::storage::open(l1_db_path)?;
    native_core::storage::init_l1_schema(&conn)?;
    let stats = run_avatar_pipeline(
        source,
        &mut conn,
        account,
        head_image_db,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
    )
    .await?;
    Ok(stats)
}

/// 一次 full ingest 要跑哪些域 (18 flag)。msgvestige-adapter bin (CLI flag → plan) 与 msgvestige 共用
/// 同一编排引擎 [`run_full_ingest`]。字段名镜像 bin 的 `Args` flag (`messages` = `!args.no_messages`)。
///
/// [`Default`] = 无 flag 默认 (仅 `messages`, 对齐 bin `!--no-messages`);
/// [`all`](IngestPlan::all) = 18 域全开。
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // 18 域各 1 开关 bool, 编排 plan 惯例 (同 bin Args flag struct)
pub struct IngestPlan {
    /// message ETL (bin: `!--no-messages`)。
    pub messages: bool,
    /// contact ETL (bin: `--contacts`)。
    pub contacts: bool,
    /// chatroom 群成员 ETL (bin: `--chatrooms`)。
    pub chatrooms: bool,
    /// session 会话列表 ETL (bin: `--sessions`)。
    pub sessions: bool,
    /// favorite 收藏 + favorite_tag 标签 ETL (bin: `--favorites`)。
    pub favorites: bool,
    /// sns 朋友圈 ETL (bin: `--sns`)。
    pub sns: bool,
    /// transfer 转账 ETL (bin: `--transfers`)。
    pub transfers: bool,
    /// red_envelope 红包 ETL (bin: `--red-envelopes`)。
    pub red_envelopes: bool,
    /// group_pay 群收款 ETL (bin: `--group-pays`)。
    pub group_pays: bool,
    /// friend_verify 好友验证 ETL (bin: `--friend-verifies`)。
    pub friend_verifies: bool,
    /// finder_visit 视频号主页 ETL (bin: `--finder-visits`)。
    pub finder_visits: bool,
    /// moment_feed 朋友圈好友动态索引 ETL (bin: `--moment-feeds`)。
    pub moment_feeds: bool,
    /// sns_notify 朋友圈互动通知 ETL (bin: `--sns-notifies`)。
    pub sns_notifies: bool,
    /// custom_emoticon 自定义表情 ETL (bin: `--emoticons`)。
    pub emoticons: bool,
    /// avatar_image 头像图 ETL (bin: `--avatars`)。
    pub avatars: bool,
    /// bizchat_user 企微品牌号联系人 ETL (bin: `--bizchat`)。
    pub bizchat: bool,
    /// biz_message 公众号消息 ETL (bin: `--biz-messages`)。
    pub biz_messages: bool,
    /// stranger 陌生人 ETL (bin: `--strangers`)。
    pub strangers: bool,
}

impl Default for IngestPlan {
    /// 无 flag 默认: 只跑 message ingest (对齐 bin `!args.no_messages` 默认 true, 余 flag 默认 false)。
    fn default() -> Self {
        Self {
            messages: true,
            contacts: false,
            chatrooms: false,
            sessions: false,
            favorites: false,
            sns: false,
            transfers: false,
            red_envelopes: false,
            group_pays: false,
            friend_verifies: false,
            finder_visits: false,
            moment_feeds: false,
            sns_notifies: false,
            emoticons: false,
            avatars: false,
            bizchat: false,
            biz_messages: false,
            strangers: false,
        }
    }
}

impl IngestPlan {
    /// 18 域全开。
    #[must_use]
    pub fn all() -> Self {
        Self {
            messages: true,
            contacts: true,
            chatrooms: true,
            sessions: true,
            favorites: true,
            sns: true,
            transfers: true,
            red_envelopes: true,
            group_pays: true,
            friend_verifies: true,
            finder_visits: true,
            moment_feeds: true,
            sns_notifies: true,
            emoticons: true,
            avatars: true,
            bizchat: true,
            biz_messages: true,
            strangers: true,
        }
    }
}

/// 跑一遍**完整 ingest 编排** (18 域, 由 `plan` 选跑哪些): msgvestige-adapter bin 与 msgvestige 共用引擎。
///
/// 行为 = 原 bin `main.rs` 18 个 flag-gated ingest 块逐条搬来 — 顺序、`is_file()` 文件存在 guard、
/// `else { tracing::warn!(..) }` 分支、每域 label 全保持。返回**真正跑了的**域的 `(label, stats)`
/// (调用方自行 report; label 同原 `report_stats` 首参)。`favorites` 开时跑 favorite + favorite_tag
/// 两域 (两条 result); `biz_messages` 切 `set_biz_mode` 复用 message pipeline; `strangers` 切
/// `set_stranger_mode` 复用 contact pipeline (跑后即复位)。
///
/// `source` 须为 [`AccountDbSource`] (biz_message/stranger 域要调 `set_biz_mode`/`set_stranger_mode`);
/// `paths` 供各域 db 路径 (session 域用 `account_entry_db`); `l1_db`/`mode`/`batch_limit`/`now` 透传各 ingest
/// (全域共用同一 `now` 作 `ingest_time_ms`)。
///
/// # Errors
/// 任一域 ingest 失败 (开库/建表/pipeline; 各内层已脱敏) → 该域 `.context(..)` 包装的 [`anyhow::Error`]。
#[allow(clippy::too_many_arguments)] // 编排固有多参 (source+paths+l1+wxid+mode+batch+plan+now); 同 native-core pipeline
pub async fn run_full_ingest(
    source: &mut AccountDbSource,
    paths: &AccountDbPaths,
    l1_db: &std::path::Path,
    wxid: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    plan: &IngestPlan,
    now: i64,
    workers: usize,
) -> anyhow::Result<Vec<(String, PipelineStats)>> {
    ingest_then_prune(
        l1_db,
        now,
        run_ingest_domains(source, paths, l1_db, wxid, mode, batch_limit, plan, now, workers),
    )
    .await
}

/// 跑完导入**再清一次归档 —— 不管导入成没成**(codex 审这一笔的 P2)。
///
/// 原先清理写在编排体的末尾, 而每一域都是 `?` 直接抛: 任何一域失败, 清理整条被跳过。
/// 而"某一域一直失败"恰恰是最需要清理的场景 —— 反复重试反复往归档里塞, 一条都不清, 表只会一直涨。
/// 清理跟哪一域成没成没关系, 它只看时间戳。
///
/// **单拎成这么个小壳子是为了能测**: 真 `AccountDbSource` 造不出"某一域失败"的夹具(要真库+真 key),
/// 而要守的其实只是这里的先后顺序 —— 壳子在, 顺序就能拿一个必然失败的 body 直接咬。
async fn ingest_then_prune<T>(
    l1_db: &std::path::Path,
    now: i64,
    body: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let outcome = body.await;
    prune_archive_after_ingest(l1_db, now);
    outcome // 原样抛出去 —— 清理是顺带的, 不许把导入的失败吞了或改写
}

/// 清一次原始归档的滚动窗口 —— 保留多久**读 config**, 见 [`native_core::storage::prune_archive_now`]。
///
/// best-effort: 数据都已经落库了, 清理失败不该把一次成功的导入变成失败。但**不静默** —— warn 出来。
fn prune_archive_after_ingest(l1_db: &std::path::Path, now: i64) {
    // ⚠️ 窗口**读 config**, 别写死(codex 审这一笔点出来的): `adapter.archive_retention_hours` 这个
    // 配置项一直就有(默认 24、可配 1..=720、还带校验), 只是从来没人读它。写死 24 的话, 用户配了
    // 72 小时, 我会按 24 小时**不可逆地删掉**他要留的那 48 小时 —— 比不清更糟。
    // ⚠️ 读不懂就**别清**(codex 审出来的 P1): 原先用 `load_or_default`, 它在任何加载失败时都退回
    // 默认 24 小时。用户配的是 720, 而某次解析偶然失败(文件正被写了一半 / 手滑写错一个字段),
    // 这里就会按 24 小时**不可逆地删掉**他要留的那 696 小时。猜错删的数据回不来, 不清只是这轮没清。
    // 走不带路径那个 —— 它内部读的是"生产该读哪个 config", 测试可以用 `config_path_for_test`
    // 把它指走。**别在这儿写 `default_config_path()`**: 那样测试就只能测内层, 而生产走的是外层,
    // 中间那一行没人守 —— 独立复审 656477c 的 P2 就是这么把我上一版的守卫绕过去的。
    let Some(hours) = native_core::storage::configured_retention_hours() else {
        return;
    };
    match native_core::storage::open(l1_db).and_then(|c| native_core::storage::prune_archive_now(&c, now, hours)) {
        Ok(0) => {}
        Ok(n) => tracing::info!(pruned = n, retention_hours = hours, "原始归档: 清掉超出保留期的记录"),
        Err(e) => tracing::warn!(error = %e, "原始归档清理失败 (不影响本次导入, 下轮再试)"),
    }
}

#[allow(clippy::too_many_arguments)] // 同上
async fn run_ingest_domains(
    source: &mut AccountDbSource,
    paths: &AccountDbPaths,
    l1_db: &std::path::Path,
    wxid: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    plan: &IngestPlan,
    now: i64,
    // R15 --jobs: 消息主体批内 decode 并行度 (>1 = rayon 并行); 其它类型 (contact/session…, 万级) 仍串行。
    workers: usize,
) -> anyhow::Result<Vec<(String, PipelineStats)>> {
    let mut results = Vec::new();

    // 5. message ETL ingest (默认; --no-messages 跳过)。
    if plan.messages {
        // requested_workers = 用户请求值 (实际 effective 经 run_message_pipeline_jobs 钳到逻辑核数后, 由其
        // 进度日志打 workers=effective; 审 Round-A P3-1: 此处标 requested 免与 effective 混淆)。
        tracing::info!(requested_workers = workers, "开始 message ingest…");
        let stats = run_message_ingest(&mut *source, l1_db, wxid, mode, batch_limit, now, workers)
            .await
            .context("message ingest 失败")?;
        results.push(("message".to_string(), stats));
    }

    // 6. contact ETL ingest (--contacts 开启; contact.db 存在才跑; 复用同一已开会话)。
    if plan.contacts {
        if paths.contact_db.is_file() {
            tracing::info!("开始 contact ingest…");
            let stats = run_contact_ingest(&mut *source, l1_db, wxid, &paths.contact_db, mode, batch_limit, now)
                .await
                .context("contact ingest 失败")?;
            results.push(("contact".to_string(), stats));
        } else {
            tracing::warn!("contact.db 不存在, 跳过 contact ingest");
        }
    }

    // 7. chatroom 群成员 ETL ingest (--chatrooms 开启; contact.db 的 chat_room 表; 复用同会话)。
    if plan.chatrooms {
        if paths.contact_db.is_file() {
            tracing::info!("开始 chatroom ingest…");
            let stats = run_chatroom_ingest(&mut *source, l1_db, wxid, &paths.contact_db, mode, batch_limit, now)
                .await
                .context("chatroom ingest 失败")?;
            results.push(("chatroom".to_string(), stats));
        } else {
            tracing::warn!("contact.db 不存在, 跳过 chatroom ingest");
        }
    }

    // 8. session 会话列表 ETL ingest (--sessions 开启; session.db == 账号入口 db, locate 已校验存在; 复用同会话)。
    if plan.sessions {
        tracing::info!("开始 session ingest…");
        let stats = run_session_ingest(
            &mut *source,
            l1_db,
            wxid,
            &paths.account_entry_db,
            mode,
            batch_limit,
            now,
        )
        .await
        .context("session ingest 失败")?;
        results.push(("session".to_string(), stats));
    }

    // 9. favorite 收藏 ETL ingest (--favorites 开启; favorite.db 存在才跑; 复用同会话; ADR-454)。
    if plan.favorites {
        if paths.favorite_db.is_file() {
            tracing::info!("开始 favorite ingest…");
            let stats = run_favorite_ingest(&mut *source, l1_db, wxid, &paths.favorite_db, mode, batch_limit, now)
                .await
                .context("favorite ingest 失败")?;
            results.push(("favorite".to_string(), stats));
            // 批 B-2: 收藏标签绑定 (同 favorite.db, 复用同会话)。
            tracing::info!("开始 favorite_tag ingest…");
            let tag_stats =
                run_favorite_tag_ingest(&mut *source, l1_db, wxid, &paths.favorite_db, mode, batch_limit, now)
                    .await
                    .context("favorite_tag ingest 失败")?;
            results.push(("favorite_tag".to_string(), tag_stats));
        } else {
            tracing::warn!("favorite.db 不存在, 跳过 favorite + favorite_tag ingest");
        }
    }

    // 10. sns 朋友圈 ETL ingest (--sns 开启; sns.db 存在才跑; 复用同会话; ADR-467 件1)。
    if plan.sns {
        if paths.sns_db.is_file() {
            tracing::info!("开始 sns ingest…");
            let stats = run_sns_ingest(&mut *source, l1_db, wxid, &paths.sns_db, mode, batch_limit, now)
                .await
                .context("sns ingest 失败")?;
            results.push(("sns".to_string(), stats));
        } else {
            tracing::warn!("sns.db 不存在, 跳过 sns ingest");
        }
    }

    // 11. transfer 转账 ETL ingest (--transfers 开启; general.db 存在才跑; 复用同会话; ADR-468)。
    if plan.transfers {
        if paths.general_db.is_file() {
            tracing::info!("开始 transfer ingest…");
            let stats = run_transfer_ingest(&mut *source, l1_db, wxid, &paths.general_db, mode, batch_limit, now)
                .await
                .context("transfer ingest 失败")?;
            results.push(("transfer".to_string(), stats));
        } else {
            tracing::warn!("general.db 不存在, 跳过 transfer ingest");
        }
    }

    // 12. red_envelope 红包 ETL ingest (--red-envelopes 开启; general.db 存在才跑; 复用同会话; ADR-468 件2)。
    if plan.red_envelopes {
        if paths.general_db.is_file() {
            tracing::info!("开始 red_envelope ingest…");
            let stats = run_red_envelope_ingest(&mut *source, l1_db, wxid, &paths.general_db, mode, batch_limit, now)
                .await
                .context("red_envelope ingest 失败")?;
            results.push(("red_envelope".to_string(), stats));
        } else {
            tracing::warn!("general.db 不存在, 跳过 red_envelope ingest");
        }
    }

    // 13. group_pay 群收款 ETL ingest (--group-pays 开启; general.db 存在才跑; 复用同会话; ADR-468 件3)。
    if plan.group_pays {
        if paths.general_db.is_file() {
            tracing::info!("开始 group_pay ingest…");
            let stats = run_group_pay_ingest(&mut *source, l1_db, wxid, &paths.general_db, mode, batch_limit, now)
                .await
                .context("group_pay ingest 失败")?;
            results.push(("group_pay".to_string(), stats));
        } else {
            tracing::warn!("general.db 不存在, 跳过 group_pay ingest");
        }
    }

    // 14. friend_verify 好友验证 ETL ingest (--friend-verifies 开启; general.db 存在才跑; 复用同会话; ADR-469)。
    if plan.friend_verifies {
        if paths.general_db.is_file() {
            tracing::info!("开始 friend_verify ingest…");
            let stats = run_friend_verify_ingest(&mut *source, l1_db, wxid, &paths.general_db, mode, batch_limit, now)
                .await
                .context("friend_verify ingest 失败")?;
            results.push(("friend_verify".to_string(), stats));
        } else {
            tracing::warn!("general.db 不存在, 跳过 friend_verify ingest");
        }
    }

    // 15. finder_visit 视频号主页 ETL ingest (--finder-visits 开启; general.db 存在才跑; 复用同会话; ADR-473)。
    if plan.finder_visits {
        if paths.general_db.is_file() {
            tracing::info!("开始 finder_visit ingest…");
            let stats = run_finder_visit_ingest(&mut *source, l1_db, wxid, &paths.general_db, mode, batch_limit, now)
                .await
                .context("finder_visit ingest 失败")?;
            results.push(("finder_visit".to_string(), stats));
        } else {
            tracing::warn!("general.db 不存在, 跳过 finder_visit ingest");
        }
    }

    // 16. moment_feed 朋友圈好友动态索引 ETL ingest (--moment-feeds 开启; sns.db 存在才跑; 复用同会话; ADR-474)。
    if plan.moment_feeds {
        if paths.sns_db.is_file() {
            tracing::info!("开始 moment_feed ingest…");
            let stats = run_moment_feed_ingest(&mut *source, l1_db, wxid, &paths.sns_db, mode, batch_limit, now)
                .await
                .context("moment_feed ingest 失败")?;
            results.push(("moment_feed".to_string(), stats));
        } else {
            tracing::warn!("sns.db 不存在, 跳过 moment_feed ingest");
        }
    }

    // 16b. sns_notify 朋友圈互动通知 ETL ingest (--sns-notifies 开启; sns.db 存在才跑; 复用同会话; 照 moment_feed ADR-474)。
    if plan.sns_notifies {
        if paths.sns_db.is_file() {
            tracing::info!("开始 sns_notify ingest…");
            let stats = run_sns_notify_ingest(&mut *source, l1_db, wxid, &paths.sns_db, mode, batch_limit, now)
                .await
                .context("sns_notify ingest 失败")?;
            results.push(("sns_notify".to_string(), stats));
        } else {
            tracing::warn!("sns.db 不存在, 跳过 sns_notify ingest");
        }
    }

    // 17. custom_emoticon 自定义表情 ETL ingest (--emoticons 开启; emoticon.db 存在才跑; 复用同会话; ADR-478)。
    if plan.emoticons {
        if paths.emoticon_db.is_file() {
            tracing::info!("开始 custom_emoticon ingest…");
            let stats = run_emoticon_ingest(&mut *source, l1_db, wxid, &paths.emoticon_db, mode, batch_limit, now)
                .await
                .context("custom_emoticon ingest 失败")?;
            results.push(("custom_emoticon".to_string(), stats));
        } else {
            tracing::warn!("emoticon.db 不存在, 跳过 custom_emoticon ingest");
        }
    }

    // 17b. avatar_image 头像图 ETL ingest (--avatars 开启; head_image.db 存在才跑; 复用同会话; ADR-481)。
    if plan.avatars {
        if paths.head_image_db.is_file() {
            tracing::info!("开始 avatar_image ingest…");
            let stats = run_avatar_ingest(&mut *source, l1_db, wxid, &paths.head_image_db, mode, batch_limit, now)
                .await
                .context("avatar_image ingest 失败")?;
            results.push(("avatar_image".to_string(), stats));
        } else {
            tracing::warn!("head_image.db 不存在, 跳过 avatar_image ingest");
        }
    }

    // 17c. bizchat_user 企微品牌号联系人 ETL ingest (--bizchat 开启; bizchat.db 存在才跑; 复用同会话; ADR-482)。
    if plan.bizchat {
        if paths.bizchat_db.is_file() {
            tracing::info!("开始 bizchat_user ingest…");
            let stats = run_bizchat_ingest(&mut *source, l1_db, wxid, &paths.bizchat_db, mode, batch_limit, now)
                .await
                .context("bizchat_user ingest 失败")?;
            results.push(("bizchat_user".to_string(), stats));
        } else {
            tracing::warn!("bizchat.db 不存在, 跳过 bizchat_user ingest");
        }
    }

    // 18. biz_message 公众号消息 ETL ingest (--biz-messages 开启; 复用 message pipeline 切 biz_mode; ADR-480)。
    // biz_message_*.db 与 message_*.db schema 全同, 落 message 表 source 列 `biz_message_N.db|...` 区分。
    if plan.biz_messages {
        tracing::info!(requested_workers = workers, "开始 biz_message ingest…");
        source.set_biz_mode(true);
        // biz_message 同 message pipeline (公众号消息可大量) → 同享 workers 并行度。
        let stats = run_message_ingest(&mut *source, l1_db, wxid, mode, batch_limit, now, workers)
            .await
            .context("biz_message ingest 失败")?;
        source.set_biz_mode(false); // 复位, 防后续误用
        results.push(("biz_message".to_string(), stats));
    }

    // 19. stranger 陌生人 ETL ingest (--strangers 开启; 复用 contact pipeline 切 stranger_mode; echotrace 同源)。
    // contact.db 的 stranger 表与 contact 表 schema 全同, 落同一 person 表 source 列 `contact.db|stranger` 区分。
    if plan.strangers {
        if paths.contact_db.is_file() {
            tracing::info!("开始 stranger ingest…");
            source.set_stranger_mode(true);
            let stats = run_contact_ingest(&mut *source, l1_db, wxid, &paths.contact_db, mode, batch_limit, now)
                .await
                .context("stranger ingest 失败")?;
            source.set_stranger_mode(false); // 复位, 防后续误用
            results.push(("stranger".to_string(), stats));
        } else {
            tracing::warn!("contact.db 不存在, 跳过 stranger ingest");
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use native_core::{
        AvatarBatch, BizChatUserBatch, ChatroomBatch, ContactBatch, ContactRow, DbSnapshot, DbSourceError, DrainCursor,
        EmoticonBatch, FMessageBatch, FavoriteBatch, FavoriteTagBatch, FinderBatch, GroupPayBatch, MessageBatch,
        MessageRow, MessageSubsource, MomentBatch, MomentFeedBatch, RedEnvelopeBatch, SessionBatch, SnsNotifyBatch,
        TransferBatch,
    };

    use super::*;

    /// watch mtime 门控: `<db>` → `<db>-wal` (新消息先落 WAL, 故盯 -wal mtime)。
    #[test]
    fn wal_sibling_appends_suffix() {
        assert_eq!(
            wal_sibling_of(Path::new("F:/x/message_0.db")).to_str().unwrap(),
            "F:/x/message_0.db-wal"
        );
    }

    /// mtime_ns: 不存在文件 → 0 (触发重跑, 安全兜底)。
    #[test]
    fn mtime_ns_missing_is_zero() {
        assert_eq!(mtime_ns(Path::new("Z:/definitely/not/here.db")), 0);
    }

    /// R9 件5: `build_source_groups` 域→源库映射正确 + filter 不存在的库 + **不碰消息** (走 tail-f)。
    #[test]
    fn source_groups_map_domains_and_filter_missing() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let touch = |name: &str| {
            let p = d.join(name);
            std::fs::write(&p, b"x").unwrap();
            p
        };
        // 只建 contact + session + general, 其余 5 库不建 (测 filter is_file)。
        let contact = touch("contact.db");
        let session = touch("session.db");
        let general = touch("general.db");
        let paths = AccountDbPaths {
            account_entry_db: session,
            message_dir: d.join("message"),
            contact_db: contact,
            favorite_db: d.join("favorite.db"),
            sns_db: d.join("sns.db"),
            general_db: general,
            emoticon_db: d.join("emoticon.db"),
            head_image_db: d.join("head_image.db"),
            bizchat_db: d.join("bizchat.db"),
        };
        let groups = build_source_groups(&paths);
        let labels: Vec<_> = groups.iter().map(|g| g.label).collect();
        assert_eq!(
            groups.len(),
            3,
            "只存在的 3 库入组 (contact/session/general), 缺的 5 库 filter 掉"
        );
        assert!(labels.contains(&"contact") && labels.contains(&"session") && labels.contains(&"general"));
        // contact 组: contacts+chatrooms+strangers, 不碰消息。
        let cg = groups.iter().find(|g| g.label == "contact").unwrap();
        assert!(
            cg.plan.contacts && cg.plan.chatrooms && cg.plan.strangers,
            "contact→contacts+chatrooms+strangers"
        );
        assert!(!cg.plan.messages, "件5 不碰消息 (走 tail-f)");
        // general 组: 5 专表, 不越界到别的域。
        let gg = groups.iter().find(|g| g.label == "general").unwrap();
        assert!(
            gg.plan.transfers
                && gg.plan.red_envelopes
                && gg.plan.group_pays
                && gg.plan.friend_verifies
                && gg.plan.finder_visits,
            "general→5 专表"
        );
        assert!(!gg.plan.messages && !gg.plan.contacts, "general 只开专表, 不越界");
    }

    // ── locate_account_dbs ──

    fn make_account_layout(root: &Path, dir_name: &str, with_session: bool, with_message: bool) {
        let ds = root.join(dir_name).join("db_storage");
        if with_session {
            let ses = ds.join("session");
            std::fs::create_dir_all(&ses).unwrap();
            std::fs::write(ses.join("session.db"), b"x").unwrap();
        }
        if with_message {
            std::fs::create_dir_all(ds.join("message")).unwrap();
        }
        if !with_session && !with_message {
            std::fs::create_dir_all(&ds).unwrap();
        }
    }

    #[test]
    fn locate_resolves_account_with_device_suffix() {
        let dir = tempfile::tempdir().unwrap();
        make_account_layout(dir.path(), "wxid_abcd1234efgh567_abfe", true, true);
        let wxid = Wxid::try_new("wxid_abcd1234efgh567").unwrap();
        let paths = locate_account_dbs(dir.path(), &wxid).unwrap();
        assert!(paths.account_entry_db.ends_with("db_storage/session/session.db"));
        assert!(paths.message_dir.ends_with("db_storage/message"));
    }

    #[test]
    fn locate_resolves_bare_account_dir() {
        let dir = tempfile::tempdir().unwrap();
        make_account_layout(dir.path(), "wxid_bare22", true, true);
        let wxid = Wxid::try_new("wxid_bare22").unwrap();
        assert!(locate_account_dbs(dir.path(), &wxid).is_ok());
    }

    #[test]
    fn locate_missing_account_dir_errs() {
        let dir = tempfile::tempdir().unwrap();
        make_account_layout(dir.path(), "wxid_other_acct_xx", true, true);
        let wxid = Wxid::try_new("wxid_notthere").unwrap();
        assert!(matches!(
            locate_account_dbs(dir.path(), &wxid),
            Err(IngestError::AccountNotFound { .. })
        ));
    }

    #[test]
    fn locate_account_dir_but_no_session_db_errs() {
        let dir = tempfile::tempdir().unwrap();
        make_account_layout(dir.path(), "wxid_acct22_abfe", false, true); // 无 session.db
        let wxid = Wxid::try_new("wxid_acct22").unwrap();
        match locate_account_dbs(dir.path(), &wxid) {
            Err(IngestError::AccountNotFound { what }) => assert!(what.contains("session.db")),
            other => panic!("应 AccountNotFound(session.db): {other:?}"),
        }
    }

    #[test]
    fn locate_prefix_collision_not_matched() {
        // "wxid_acct22extra" 不该被 wxid="wxid_acct22" 匹配 (后缀非 '_' 起)。
        let dir = tempfile::tempdir().unwrap();
        make_account_layout(dir.path(), "wxid_acct22extra", true, true);
        let wxid = Wxid::try_new("wxid_acct22").unwrap();
        assert!(matches!(
            locate_account_dbs(dir.path(), &wxid),
            Err(IngestError::AccountNotFound { .. })
        ));
    }

    /// K-R4: AccountNotFound 不露明文 wxid (走 sha8)。
    #[test]
    fn locate_error_redacts_wxid() {
        let dir = tempfile::tempdir().unwrap();
        let wxid = Wxid::try_new("wxid_secret_acct").unwrap();
        let err = locate_account_dbs(dir.path(), &wxid).unwrap_err();
        let msg = format!("{err}");
        assert!(!msg.contains("wxid_secret_acct"), "泄明文 wxid: {msg}");
        assert!(msg.contains("sha8="), "应 sha8 脱敏: {msg}");
    }

    /// 代码双审 P1: 同 wxid 多候选目录 (坏 + 好) → 返 db_storage 布局完整的那个 (不被坏候选误报缺库)。
    #[test]
    fn locate_picks_valid_candidate_among_multiple() {
        let dir = tempfile::tempdir().unwrap();
        make_account_layout(dir.path(), "wxid_multi22_old", false, true); // 坏: 无 session.db
        make_account_layout(dir.path(), "wxid_multi22_abfe", true, true); // 好: 完整
        let wxid = Wxid::try_new("wxid_multi22").unwrap();
        let paths = locate_account_dbs(dir.path(), &wxid).unwrap();
        assert!(
            paths.account_entry_db.to_string_lossy().contains("wxid_multi22_abfe"),
            "应返完整候选, 实际 {:?}",
            paths.account_entry_db
        );
    }

    /// K-R4 (代码双审 P1): AccountDbPaths Debug 不泄 wxid / 绝对路径 (3 个 path 走 sha8)。
    #[test]
    fn account_db_paths_debug_redacts() {
        let p = AccountDbPaths {
            account_entry_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\session\session.db"),
            message_dir: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\message"),
            contact_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\contact\contact.db"),
            favorite_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\favorite\favorite.db"),
            sns_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\sns\sns.db"),
            general_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\general\general.db"),
            emoticon_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\emoticon\emoticon.db"),
            head_image_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\head_image\head_image.db"),
            bizchat_db: PathBuf::from(r"X:\xwechat_files\wxid_secret_abfe\db_storage\bizchat\bizchat.db"),
        };
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("wxid_secret"), "Debug 泄 wxid: {dbg}");
        assert!(!dbg.contains("xwechat_files"), "Debug 泄绝对路径: {dbg}");
        assert!(dbg.contains("contact_db_sha8"), "应 sha8: {dbg}");
        assert!(dbg.contains("bizchat_db_sha8"), "应 sha8: {dbg}");
    }

    // ── run_message_ingest (mock DbSource + 临时 L1) ──

    struct MockSource {
        rel_name: String,
        subsource: MessageSubsource,
        rows: Vec<(i64, Vec<u8>)>,    // (local_id, content)
        contacts: Vec<(i64, String)>, // (rowid, username)
    }
    #[async_trait]
    impl DbSource for MockSource {
        async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError> {
            Ok(vec![DbSnapshot {
                db_id: format!("s|{}", self.rel_name),
                wxid: Wxid::try_new("wxid_self").unwrap(),
                kind: "message".into(),
                sub_db_path: PathBuf::from("/wx/message_0.db"),
                rel_name: self.rel_name.clone(),
                mtime_ms: 0,
                size_bytes: 0,
            }])
        }
        async fn list_message_subsources(
            &mut self,
            _snapshot: &DbSnapshot,
        ) -> Result<Vec<MessageSubsource>, DbSourceError> {
            Ok(vec![self.subsource.clone()])
        }
        async fn drain_messages(
            &mut self,
            _snapshot: &DbSnapshot,
            _subsource: &MessageSubsource,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<MessageBatch, DbSourceError> {
            let mut hit: Vec<&(i64, Vec<u8>)> = self.rows.iter().filter(|(lid, _)| *lid > since.local_id).collect();
            hit.sort_by_key(|(lid, _)| *lid);
            let page: Vec<MessageRow> = hit
                .iter()
                .take(limit)
                .map(|(lid, content)| MessageRow {
                    local_id: *lid,
                    server_id: 9000 + *lid,
                    server_seq: 0,
                    origin_source: 0,
                    upload_status: 0,
                    download_status: 0,
                    local_type: 1,
                    sort_seq: 1_700_000_000_000 + *lid,
                    create_time: 1_700_000_000,
                    status: 4,
                    message_content: content.clone(),
                    msg_source: Vec::new(), // mock 不带 source 列 (@提及 atuserlist 路径不测)
                    sender_username: None,
                })
                .collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |m| m.local_id);
            Ok(MessageBatch {
                rows: page,
                next_cursor: DrainCursor {
                    local_id: next,
                    resume_fp: None,
                    cursor_ct: None,
                    cursor_sid: None,
                    prefix_rows: None,
                },
                has_more: limit > 0 && fetched == limit,
            })
        }
        async fn drain_contacts(
            &mut self,
            _contact_db: &Path,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<ContactBatch, DbSourceError> {
            let mut hit: Vec<&(i64, String)> = self.contacts.iter().filter(|(rid, _)| *rid > since.local_id).collect();
            hit.sort_by_key(|(rid, _)| *rid);
            let page: Vec<ContactRow> = hit
                .iter()
                .take(limit)
                .map(|(rid, un)| ContactRow {
                    rowid: *rid,
                    username: un.clone(),
                    local_type: 1,
                    nick_name: None,
                    remark: None,
                    alias: None,
                    is_in_chat_room: 0,
                    quan_pin: None,
                    pin_yin_initial: None,
                    remark_quan_pin: None,
                    remark_pin_yin_initial: None,
                    verify_flag: 0,
                    delete_flag: 0,
                    big_head_url: None,
                    small_head_url: None,
                    head_img_md5: None,
                    description: None,
                    flag: 0,
                    chat_room_notify: 0,
                    chat_room_type: 0,
                    extra_buffer: Vec::new(),
                    labels: None,
                })
                .collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |c| c.rowid);
            Ok(ContactBatch {
                rows: page,
                next_cursor: DrainCursor {
                    local_id: next,
                    resume_fp: None,
                    cursor_ct: None,
                    cursor_sid: None,
                    prefix_rows: None,
                },
                has_more: limit > 0 && fetched == limit,
            })
        }
        async fn drain_chatrooms(
            &mut self,
            _contact_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<ChatroomBatch, DbSourceError> {
            Ok(ChatroomBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_sessions(
            &mut self,
            _session_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<SessionBatch, DbSourceError> {
            Ok(SessionBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_favorites(
            &mut self,
            _favorite_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<FavoriteBatch, DbSourceError> {
            Ok(FavoriteBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_favorite_tags(
            &mut self,
            _favorite_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<FavoriteTagBatch, DbSourceError> {
            Ok(FavoriteTagBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_moments(
            &mut self,
            _sns_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<MomentBatch, DbSourceError> {
            Ok(MomentBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_transfers(
            &mut self,
            _general_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<TransferBatch, DbSourceError> {
            Ok(TransferBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_red_envelopes(
            &mut self,
            _general_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<RedEnvelopeBatch, DbSourceError> {
            Ok(RedEnvelopeBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_group_pays(
            &mut self,
            _general_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<GroupPayBatch, DbSourceError> {
            Ok(GroupPayBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_friend_verifies(
            &mut self,
            _general_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<FMessageBatch, DbSourceError> {
            Ok(FMessageBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_finder_visits(
            &mut self,
            _general_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<FinderBatch, DbSourceError> {
            Ok(FinderBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_moment_feeds(
            &mut self,
            _sns_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<MomentFeedBatch, DbSourceError> {
            Ok(MomentFeedBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_sns_notifies(
            &mut self,
            _sns_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<SnsNotifyBatch, DbSourceError> {
            Ok(SnsNotifyBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_emoticons(
            &mut self,
            _emoticon_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<EmoticonBatch, DbSourceError> {
            Ok(EmoticonBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_avatars(
            &mut self,
            _head_image_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<AvatarBatch, DbSourceError> {
            Ok(AvatarBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_bizchat_users(
            &mut self,
            _bizchat_db: &Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<BizChatUserBatch, DbSourceError> {
            Ok(BizChatUserBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
    }

    /// **config 读不懂时, 收尾这条不设上限的清理也得停手**(独立复审 651ed5c 的 P2)。
    ///
    /// storage 那边有一条同型守卫, 但这条路是**另一个函数**、而且**不设批数上限** ——
    /// 把它绕开写死 24 小时的话, 用户配了 720 小时的库会被一口气删掉 696 小时的记录, 而且删完就没了。
    /// 复审埋这个变异时全工作区一条不红: 上一条守卫只盖住了 storage 那一半。
    /// **同一种缺陷在两个函数里各长一次** —— 判据得写成"每条会删数据的路", 不是"点名那一条"。
    #[test]
    fn adapter_prune_skips_when_config_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("adapter_cfg.db");
        let now = 1_800_000_000_000i64;
        {
            let c = native_core::storage::open(&l1).unwrap();
            native_core::storage::init_archive_table(&c).unwrap();
            c.execute(
                "INSERT INTO raw_payload_archive
                 (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                 VALUES ('sha','src','老得该清了','message','insert',1,1000,'{}')",
                [],
            )
            .unwrap();
        }
        let count = || {
            let c = native_core::storage::open(&l1).unwrap();
            c.query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };

        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "这不是 toml [[[").unwrap();
        // ⚠️ 走**真正的生产入口** `prune_archive_after_ingest`(不带路径那个), config 路径靠测试钩子指走。
        // 头一版调的是 `*_from`, 而生产调的是外层 —— 审查方把外层换成写死 24, 全工作区一条不红。
        let hook = native_core::storage::config_path_for_test(&broken);
        super::prune_archive_after_ingest(&l1, now);
        assert_eq!(count(), 1, "config 读不懂就一条都不许删");

        let good = dir.path().join("good.toml");
        std::fs::write(
            &good,
            "[config_meta]
version = \"0.1.0\"

[adapter]
archive_retention_hours = 24
",
        )
        .unwrap();
        drop(hook);
        let _hook = native_core::storage::config_path_for_test(&good);
        super::prune_archive_after_ingest(&l1, now);
        assert_eq!(count(), 0, "config 好了就该清 —— 不然上面那条断言是空的");
    }

    /// **`run_full_ingest` 跑完真的清了归档** —— 独立复审埋的变异说明这条非有不可。
    ///
    /// 复审把生产路径里那句清理调用整个删掉, **全仓一条测试都不红**: 被修的缺陷类型
    /// (函数写好了却没人调)原样重现, 而唯一的守卫是直接调函数的单测 —— 它证明"函数算得对",
    /// 证明不了"有人调它"。两者的判定面完全不相交。
    ///
    /// 所以这条走**公开入口** `run_full_ingest`, 计划里一域都不开: 测的不是导入, 就是
    /// "跑完到底清没清"。计划字段是一个个写死的 —— 以后加了新域, 这里编译不过, 逼着人回来看一眼。
    #[tokio::test]
    async fn run_full_ingest_actually_prunes() {
        use native_core::cipher::{Cipher, CipherError, DbSession};
        use native_core::key_provider::MasterKey;

        // 一域都不跑, source 根本不会被碰 —— 给个永不被调用的壳就够了。
        struct NeverUsedCipher;
        #[async_trait]
        impl Cipher for NeverUsedCipher {
            async fn open_account(&self, _: &Path, _: &MasterKey) -> Result<Box<dyn DbSession>, CipherError> {
                unreachable!("空计划不该开库")
            }
            async fn verify(&self, _: &Path, _: &MasterKey) -> Result<(), CipherError> {
                unreachable!("空计划不该验 key")
            }
            fn name(&self) -> &'static str {
                "never-used"
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let l1 = d.join("l1.db");
        let now = 1_800_000_000_000i64;
        let hour = 60 * 60 * 1000i64;
        {
            let c = native_core::storage::open(&l1).unwrap();
            native_core::storage::init_archive_table(&c).unwrap();
            for (nid, t) in [("超窗", now - 25 * hour), ("窗内", now - hour)] {
                c.execute(
                    "INSERT INTO raw_payload_archive
                     (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                     VALUES ('sha', 'src', ?1, 'message', 'insert', 1, ?2, '{}')",
                    rusqlite::params![nid, t],
                )
                .unwrap();
            }
        }

        // ⚠️ 拿同一把测试锁: config 路径的钩子是**进程级**的, 别的测试把它指到坏文件时这条会红。
        // 指到不存在的路径 = 走默认 24 小时, 结果确定。
        let _cfg = native_core::storage::config_path_for_test(std::path::Path::new("不存在的-config.toml"));
        let wxid = Wxid::try_new("wxid_pruneguard0001").unwrap();
        let paths = AccountDbPaths {
            account_entry_db: d.join("session.db"),
            message_dir: d.join("message"),
            contact_db: d.join("contact.db"),
            favorite_db: d.join("favorite.db"),
            sns_db: d.join("sns.db"),
            general_db: d.join("general.db"),
            emoticon_db: d.join("emoticon.db"),
            head_image_db: d.join("head_image.db"),
            bizchat_db: d.join("bizchat.db"),
        };
        let mut source = AccountDbSource::new(
            Box::new(NeverUsedCipher),
            paths.account_entry_db.clone(),
            MasterKey::from_bytes([0u8; 32]),
            wxid.clone(),
            paths.message_dir.clone(),
        );
        let plan = IngestPlan {
            messages: false,
            contacts: false,
            chatrooms: false,
            sessions: false,
            favorites: false,
            sns: false,
            transfers: false,
            red_envelopes: false,
            group_pays: false,
            friend_verifies: false,
            finder_visits: false,
            moment_feeds: false,
            sns_notifies: false,
            emoticons: false,
            avatars: false,
            bizchat: false,
            biz_messages: false,
            strangers: false,
        };

        let results = run_full_ingest(
            &mut source,
            &paths,
            &l1,
            &wxid,
            PrivacyMode::default_sha(),
            100,
            &plan,
            now,
            1,
        )
        .await
        .expect("空计划不该失败");
        assert!(results.is_empty(), "一域都没开, 不该有结果");

        let c = native_core::storage::open(&l1).unwrap();
        let left: Vec<String> = c
            .prepare("SELECT source_native_id FROM raw_payload_archive ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            left,
            vec!["窗内".to_string()],
            "跑完必须清过一遍 —— 这条红了就说明生产路径上那句清理没了"
        );
    }

    /// **某一域炸了, 归档清理照样得跑**(codex 审这一笔的 P2)。
    ///
    /// 清理原先写在编排体末尾, 每一域都是 `?` 直抛 —— 一域失败, 清理整条跳过。
    /// 而"某一域一直失败"正是最需要清理的场景: 反复重试反复往归档塞, 表只涨不清。
    ///
    /// 两件一起咬: 超窗那条**真被删了**, 且 body 的错误**原样抛出去**(清理不许吞错、不许改写)。
    #[tokio::test]
    async fn prune_runs_even_when_ingest_fails() {
        // ⚠️ 拿同一把测试锁: config 路径的钩子是**进程级**的, 别的测试把它指到坏文件时这条会红。
        // 指到不存在的路径 = 走默认 24 小时, 结果确定。
        let _cfg = native_core::storage::config_path_for_test(std::path::Path::new("不存在的-config.toml"));
        // ⚠️ 用 tempdir 不用固定名字: `cargo test --workspace` 会并行跑各 crate 的测试二进制,
        // 固定路径在两次运行重叠时会互相踩(我头一版就是固定名, 撞出过一次假失败)。
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("adapter_prune_on_failure.db");
        let now = 1_800_000_000_000i64;
        let hour = 60 * 60 * 1000i64;
        {
            let c = rusqlite::Connection::open(&l1).unwrap();
            native_core::storage::init_archive_table(&c).unwrap();
            let put = |nid: &str, t: i64| {
                c.execute(
                    "INSERT INTO raw_payload_archive
                     (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                     VALUES ('sha', 'src', ?1, 'message', 'insert', 1, ?2, '{}')",
                    rusqlite::params![nid, t],
                )
                .unwrap();
            };
            put("超窗", now - 25 * hour);
            put("窗内", now - hour);
        }

        let r: anyhow::Result<()> =
            super::ingest_then_prune(&l1, now, async { anyhow::bail!("某一域 ingest 失败") }).await;
        assert!(r.is_err(), "导入的失败必须原样抛出去, 不许被顺带的清理吞掉");

        let c = rusqlite::Connection::open(&l1).unwrap();
        let left: Vec<String> = c
            .prepare("SELECT source_native_id FROM raw_payload_archive ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            left,
            vec!["窗内".to_string()],
            "导入失败也得清 —— 失败恰恰是最该清的时候"
        );
    }

    #[tokio::test]
    async fn ingest_runs_end_to_end_and_inits_schema() {
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("l1.db");
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_0123456789abcdef0123456789abcdef".into(),
                conv_id: "wxid_friend".into(),
            },
            rows: vec![(1, b"hi".to_vec()), (2, b"yo".to_vec())],
            contacts: vec![],
        };
        let acct = Wxid::try_new("wxid_self").unwrap();
        let stats = run_message_ingest(&mut src, &l1, &acct, PrivacyMode::default_sha(), 10, 1000, 1)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 2);
        assert_eq!(stats.cursor_updates, 1);

        // L1 schema 建齐 + 落库正确: 重新打开库验 7 张表都在 + message/archive/etl_state 有数据。
        let conn = native_core::storage::open(&l1).unwrap();
        for t in [
            "raw_payload_archive",
            "message",
            "person",
            "person_alias_by_account_min",
            "chatroom",
            "chatroom_member",
            "etl_state",
        ] {
            let n: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap_or_else(|e| panic!("表 {t} 应存在 (init_l1_schema): {e}"));
            let _ = n;
        }
        let msgs: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(msgs, 2, "2 条消息落 L2");
        let wm: i64 = conn
            .query_row("SELECT count(*) FROM etl_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(wm, 1, "1 条游标水位");
    }

    /// run_contact_ingest 端到端: 联系人落 person + archive (+ 游标)。
    #[tokio::test]
    async fn contact_ingest_runs_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("l1.db");
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_0123456789abcdef0123456789abcdef".into(),
                conv_id: "wxid_friend".into(),
            },
            rows: vec![],
            contacts: vec![(1, "wxid_alice".into()), (2, "wxid_bob".into())],
        };
        let acct = Wxid::try_new("wxid_self").unwrap();
        let stats = run_contact_ingest(
            &mut src,
            &l1,
            &acct,
            Path::new("/wx/contact.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 2, "2 联系人落库");
        let conn = native_core::storage::open(&l1).unwrap();
        let persons: i64 = conn.query_row("SELECT count(*) FROM person", [], |r| r.get(0)).unwrap();
        assert_eq!(persons, 2, "2 联系人 → person");
    }

    /// run_chatroom_ingest 端到端接线: 空 mock → pipeline 跑通 + L1 schema 建齐 + chatroom_member 表在。
    /// (群成员 diff 落库逻辑由 native-core run_chatroom_pipeline 7 测试覆盖; 此处只验 adapter→pipeline 接线。)
    #[tokio::test]
    async fn chatroom_ingest_runs_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("l1.db");
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_0123456789abcdef0123456789abcdef".into(),
                conv_id: "wxid_friend".into(),
            },
            rows: vec![],
            contacts: vec![],
        };
        let acct = Wxid::try_new("wxid_self").unwrap();
        let stats = run_chatroom_ingest(
            &mut src,
            &l1,
            &acct,
            Path::new("/wx/contact.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
        )
        .await
        .unwrap();
        assert_eq!(stats.members_added, 0, "空 mock 无群成员 (接线验证: pipeline 跑通)");
        let conn = native_core::storage::open(&l1).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM chatroom_member", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "chatroom_member 表建齐 (空 mock 0 行)");
    }

    /// run_session_ingest 端到端接线: 空 mock → pipeline 跑通 + L1 schema 建齐 + session 表在。
    /// (会话落库逻辑由 native-core run_session_pipeline 测试覆盖; 此处只验 adapter→pipeline 接线。)
    #[tokio::test]
    async fn session_ingest_runs_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("l1.db");
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_0123456789abcdef0123456789abcdef".into(),
                conv_id: "wxid_friend".into(),
            },
            rows: vec![],
            contacts: vec![],
        };
        let acct = Wxid::try_new("wxid_self").unwrap();
        let stats = run_session_ingest(
            &mut src,
            &l1,
            &acct,
            Path::new("/wx/session.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 0, "空 mock 无会话 (接线验证: pipeline 跑通)");
        let conn = native_core::storage::open(&l1).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM session", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "session 表建齐 (空 mock 0 行)");
    }
}
