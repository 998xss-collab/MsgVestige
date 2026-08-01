//! pipeline — message ETL 编排 (adapter-role 主 loop): DbSource.drain → decoder → sink → 游标推进.
//!
//! **归属**: 逻辑驻 native-core (编排的 source/decoder/sink/state 全在本 crate, 跟 sink.rs 同为 core 内
//! adapter-role 落库编排); `msgvestige-adapter` binary = 薄壳 (建 config/cipher/conn → 调本 fn)。
//!
//! [`run_message_pipeline`] 把已建好的依赖 (一个 [`DbSource`] + L1 `Connection` + 账号) 串成增量 ETL:
//! `snapshot_dbs` → `list_message_subsources` → 逐子源 keyset `drain_messages` → 逐行 `assemble_message`
//! → `write_decoded_event` (archive+L2 一事务) → **批末写 cursor_update 事件推进 etl_state 水位**。
//!
//! ## 游标推进契约 (drain 设计双审 v2)
//! 游标推进**在 batch 的 rows + decode-error 事件都 sink 持久化之后** (cursor_update 作批末事件 →
//! `upsert_watermark`)。crash 在推进前 → 重启从旧水位重 drain, 已 sink 行靠 raw_payload_archive 5 元组
//! UNIQUE 幂等去重 (sink §6.8 契约5)。DbSource 只保证「给 cursor 返 ≤limit 行 + 准 next_cursor」, 持久化
//! 顺序 + 推进归本层 (adapter 契约)。
//!
//! ## 单条标坏不阻塞 (decoder §2 红线)
//! `assemble_message` 失败 (zstd 坏 / sender 无解) → 不中断整库, 而是 emit 一个 `SystemError` 事件
//! (进 archive 溯源, 无 L2) + 计数, 继续下一行。
//!
//! ## etl_state 键 (per-subsource)
//! `(account_id_sha = sha256(wxid), source = "<rel_name>|<Msg_table>", kind = "message")` — 每子源
//! (db × 会话表) 各自水位; 跟 `project_watermark` (cursor 事件 → Watermark) 的键组装严格一致 (读写同键)。
//!
//! ## 并发 / 阻塞 (alpha in-proc)
//! 本 fn 是 async (await DbSource.drain) 但 sink 是同步 rusqlite (短暂阻塞 executor)。alpha 单线程
//! in-proc (tokio current_thread) 可接受; `Connection` 非 Send → 本 future 非 Send (单线程 task 跑)。

// R15 并行 decode: par_iter 等并行迭代器 trait (仅 run_message_body 用; par_iter 与 std iter 不冲突)。
use rayon::prelude::*;
use rusqlite::Connection;

use crate::decoder::roomdata::{parse_roomdata, RoomDataParse, RoomMember};
use crate::decoder::{
    assemble_avatar, assemble_bizchat, assemble_chatroom, assemble_contact, assemble_emoticon, assemble_favorite,
    assemble_favorite_tag, assemble_finder, assemble_friend_verify, assemble_group_pay, assemble_message,
    assemble_moment_feed, assemble_red_envelope, assemble_session, assemble_sns, assemble_sns_notify,
    assemble_transfer, avatar_anchor, bizchat_anchor, chatroom_anchor, contact_anchor, cursor_anchor, emoticon_anchor,
    error_anchor, favorite_anchor, favorite_tag_anchor, finder_anchor, friend_verify_anchor, group_pay_anchor,
    member_anchor, moment_feed_anchor, msg_anchor, red_envelope_anchor, session_anchor, sns_anchor, sns_notify_anchor,
    transfer_anchor, AvatarContext, BizChatContext, ChatroomContext, ChatroomRow, ContactContext, DecoderError,
    EmoticonContext, FavoriteContext, FavoriteTagContext, FinderContext, FriendVerifyContext, GroupPayContext,
    MessageContext, MessageRow, MomentFeedContext, RedEnvelopeContext, SessionContext, SnsContext, SnsNotifyContext,
    TransferContext,
};
use crate::emit::emit;
use crate::emit::in_proc::{EmitError, InProcEmitter};
use crate::event::chatroom::{ChatroomMemberAdd, ChatroomMemberRemove};
use crate::event::decoded::DecodedEvent;
use crate::event::privacy::PrivacyMode;
use crate::event::provenance::Provenance;
use crate::event::system::{SystemCursorUpdate, SystemError};
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;
use crate::sha256_hex;
use crate::sink::{write_decoded_event, write_decoded_event_in_tx, SinkError};
use crate::source::{ChatroomRawRow, DbSource, DrainCursor};
use crate::state::get_watermark;
use crate::storage::{create_ingest_indexes, drop_ingest_indexes};

/// message 事件 kind (etl_state kind + cursor 事件 kind; 固定值).
const MESSAGE_KIND: &str = "message";

/// R15 进度日志间隔: 每 ~5s 打一次 ingest 进度 (模块级 const, 避免 items_after_statements)。
const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// 游标那一行的 `server_id` 是不是**确实对不上** —— 只有两边都拿到真值(非 0)才算数。
///
/// `0` 表示"还不知道": 自己发出去的消息在服务端回执之前是 0, 回执后就地填上真值。
/// 把 `0 → 真值` 这一下当成"换了人"会让**每条自己发的消息**都触发一次全会话重扫重发
/// (round-4 就是栽在拿会变的字段当身份)。所以任一侧为 0 / 缺席就当"这一项没意见"。
pub(crate) fn sid_conflict(probed: Option<i64>, stored: Option<i64>) -> bool {
    matches!((probed, stored), (Some(a), Some(b)) if a != 0 && b != 0 && a != b)
}

/// R15 **并行 decode 窗口**: 并行分支一次并行解 ≤此行数, 收集保序后即写, 再下一窗 (run_message_body)。
/// **峰值内存 = O(窗口 **条**解压事件) —— 与 `batch_limit` 无关**(这是分窗相对"整批 collect O(batch_limit) 条"
/// **注(审 Round-D/F, 精确措辞)**: 峰值**字节**数 = 窗口条 × 单条解压大小。
///
/// ⚠️ **这里原先写着"单条上限一并保护串/并两路", 那句话是错的**(独立复审点出来的)。decoder 层的单条
/// 上限(16 MiB)确实堵住了串行路, 但并行路是**整窗解完再写**: 1024 × 16 MiB = 16 GiB, 只是把"无上限"
/// 换成了"一个没用的上限"。所以窗口现在**按字节预算切**, 见 [`PAR_DECODE_BYTE_BUDGET`] —— 1024 是
/// 行数上限, 字节预算是另一道闸, 谁先到算谁。
///
/// **真实威胁模型**: 数据源是用户自有可信微信库(非对抗), 真实消息偏小(KB 级) → 正常路径永远碰不到
/// 字节预算, 窗口照样是 1024 行; 只有构造/异常数据才会自动收窄。1024 平衡: 32 核每核 ≤32 行保持忙 +
/// 默认批 4000/1024≈4 窗调度开销可忽略。写入总量/顺序不变 → speedup 不减。
const PAR_DECODE_WINDOW: usize = 1024;

/// 一窗**在飞的解压结果**最多占多少字节 —— 跟 [`PAR_DECODE_WINDOW`] 是两道闸, 谁先到算谁。
///
/// 独立复审报的 P1: 单条 16 MiB 的上限对并行路等于没有 —— 整窗 collect 完才写, 峰值是
/// 1024 × 16 MiB = 16 GiB。真来一批构造数据, 导入进程照样爆, 而"爆一次整批就没了"正是加那个上限
/// 要防的事。
///
/// 256 MiB 怎么定的: 真库上单条正文最大 697 KB(独立复审在 42 GB 全量库上量的), 一窗 1024 条正常
/// 也就 MB 级 —— 预算是给异常数据兜底的, 正常路径碰不到。
const PAR_DECODE_BYTE_BUDGET: usize = 256 * 1024 * 1024;

/// 解压出来的字节数 → 最终留在内存里的 `String` 字节数, 最坏放大几倍。
///
/// `String::from_utf8_lossy` 把每个非法 UTF-8 字节换成一个 U+FFFD, 而 U+FFFD 的 UTF-8 编码是
/// **3 个字节** —— 全是非法字节的输入长度正好放大 3 倍(独立复审真跑量到的就是 3.00)。
///
/// 但**占的内存不止长度**(codex 审 656477c 的 P2): `from_utf8_lossy(..).into_owned()` 出来的
/// `String` 会带富余容量 —— 当前标准库上, N 字节全 `0xFF` 的输入长度是 3N、**容量约 4N**。
/// 预算管的是"这一窗会占多少内存", 所以按容量算, 取 4。
///
/// 合法 UTF-8 一个字节都不放大, 所以真实数据上这个系数只是让预算保守四倍, 窗口照样满
/// (真库 509 万行模拟分窗: 4975 个窗里 4974 个是满的 1024 行)。
const UTF8_LOSSY_WORST_CASE: usize = 4;

/// 从 `start` 起, 这一窗切到哪儿为止(返回**开区间右端**)。
///
/// 两道闸: 行数不超 `max_rows`, 解压后的字节数不超 `byte_budget`。**至少切一行** —— 单条就超预算
/// 也得让它自己成一窗, 不然一行都切不出来会死循环(它自己还有 decoder 那道 16 MiB 硬闸兜着)。
///
/// 字节数是**不解压看帧头**估的, 见 [`crate::decoder::content::decoded_size_upper_bound`]。
fn next_decode_window_end(rows: &[MessageRow], start: usize, max_rows: usize, byte_budget: usize) -> usize {
    let mut end = start;
    let mut used = 0usize;
    while end < rows.len() && end - start < max_rows {
        // ⚠️ **一行里被解压的不止正文**(独立复审 c4b5dbc 的 P1, 它真跑复现过): `assemble_message`
        // 对 `msg_source`(@提及名单那列)调的是**同一个** `decode_message_content`, 同样吃到 16 MiB,
        // 结果原样留在事件里跟着整窗 collect。只算正文的话, 一行"正文 2 字节 + source 解出 12 MiB"
        // 会被算成 2 字节 —— 一窗 1024 行, 预算算出 2 KB、实际在飞 12 GiB, 这道闸从旁边绕回去了。
        //
        // 真库上 `source` 总量是正文的 31%(独立复审在 21197 张表 509 万行上量的), 就算不构造,
        // 只算一列也系统性少算约三成。
        // ⚠️ **窗口里真正装的是 `String`, 不是解压出来的字节**(独立复审 651ed5c 的 P2, 真跑量到 3 倍):
        // 解压完还要过 `String::from_utf8_lossy` —— 每个非法 UTF-8 字节变成一个 3 字节的 U+FFFD。
        // 复审的探针: 1 MiB 全 0xFF 的内容, 帧头老老实实声明 1 MiB, 估值也是 1 MiB, 而出来的 String
        // 是 3 MiB; 按 256 MiB 预算算就是实际在飞 768 MiB。跟这一笔刚修的 `msg_source` 是同一种形状 ——
        // **估的东西和真正留在内存里的东西不是一回事**, 只是倍数从"无界"变成了"恒定 3 倍"。
        // 真实微信数据是 UTF-8 碰不到, 而能碰到的正是这道闸存在的理由(坏数据 / 构造数据)。
        let sz = crate::decoder::content::decoded_size_upper_bound(&rows[end].message_content)
            .saturating_add(crate::decoder::content::decoded_size_upper_bound(&rows[end].msg_source))
            .saturating_mul(UTF8_LOSSY_WORST_CASE);
        if end > start && used.saturating_add(sz) > byte_budget {
            break;
        }
        used = used.saturating_add(sz);
        end += 1;
    }
    end
}

/// chatroom 表所在源 db (chat_room 在 contact.db; chatroom_member PK 的 source 维, 固定单源).
const CHATROOM_SOURCE: &str = "contact.db";

/// 一次 pipeline run 的累计统计 (非敏感, 全计数).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PipelineStats {
    /// 扫到的子库数 (message_*.db).
    pub dbs: usize,
    /// 枚举到的子源数 (跨所有库的 Msg_ 表总数).
    pub subsources: usize,
    /// drain 批次数 (含末尾空批)。
    pub batches: u64,
    /// 成功解码并落库的消息数.
    pub messages_decoded: u64,
    /// 解码失败 (emit SystemError 事件) 的行数.
    pub decode_errors: u64,
    /// 写出的 cursor_update 事件数。
    ///
    /// **不完全等于"推进水位次数"**: 游标那行的 `server_id` 从 0 补种成真值时, 位置没动也会写一笔
    /// (不写就永远补不上, 见 `DrainCursor::cursor_sid`)。每个会话至多发生一次。
    pub cursor_updates: u64,
    /// 卡住的子源数 (source 报 has_more 但游标不前进 → 停该子源防死循环; 健康 source 恒 0, 见 [`run_message_pipeline`])。
    pub stalled_subsources: usize,
    /// R19 选择性采集: 因不在 capture_targets 白名单被 drain 前整表跳过的子源数 (无白名单/全采时恒 0)。
    pub skipped_subsources: usize,
    /// **护栏把游标打回 0、整表重扫的子源数**(独立复审 P2: 这套判据审了七轮, 上线后总得有人
    /// 回答得出"它到底响不响、响多少")。
    ///
    /// 没有这个数的话, `messages_decoded = 50000` 有两种截然不同的读法 ——
    /// "这个会话真来了 5 万条新消息" 和 "护栏误响, 把 5 万条老消息重扫重写重发了一遍"。
    /// 光看日志 warn 不行: 调用方拿到的是 `ChatFreshness::Ingested { stats }`, 日志在别处。
    ///
    /// 健康稳态恒 0。升级后第一轮**每个 (分片, 会话) 各 +1**(老水位强制重扫一次), 预期内的一次性成本。
    ///
    /// ⚠️ 是**按子源**不是按会话: 同一个会话可以同时存在于多个分片 —— 真库实测
    /// **700 张同名 `Msg_` 表同时在 `message_0.db` 和 `message_5.db`**, 这些会话那一轮会 +2。
    /// (夹具是单分片的, 测不出这一格, 所以写在这。)
    pub rescanned_subsources: usize,
    /// **并行解码切了几窗**(独立复审 c4b5dbc 的 P2: 那道字节预算闸没有任何守卫证明生产真在用它)。
    ///
    /// 加这个数是为了让"窗口按什么切"从外面**看得见** —— 不然唯一的守卫是直接调那个私有切窗函数,
    /// 它证明"函数算得对", 证明不了"有人调它"。同一笔里我刚拿这句话说过 prune, 转身自己又犯一遍。
    ///
    /// 串行路(`workers=1` / 单行批)恒 0 —— 那条路是边解边写, 根本没有"窗"这个概念。
    /// 并行路正常数据下 ≈ `ceil(批行数 / 1024)`; 明显多于这个数就说明字节预算在起作用
    /// (有超大行), 值得看一眼。
    pub decode_windows: u64,
    /// 群聊 diff 新增成员事件数 (member_add).
    pub members_added: u64,
    /// 群聊 diff 退群成员事件数 (member_remove; member_wxid 从 L2 明文列回读 — ADR-426 §1.1 闭环).
    pub members_removed: u64,
    /// ext_buffer 解析 Invalid 跳过的群数 (不 diff, 避免误判全退).
    pub invalid_chatrooms: usize,
    /// 发出的 ChatroomCreate 事件数 (每群一笔群本身: 群名/主/人数, 不管成员解析成败)。
    /// 注: 是"事件发送数"非"chatroom 表净增数" — archive 按 content_digest 去重 + chatroom 表 upsert,
    /// 全表重扫重跑此值仍累加 (codex P1: 命名别当真实新增)。
    pub chatrooms_created: u64,
}

/// R11: 消息 ingest run 结束汇总 (落 N 行 / 错 K 条 / stalled)。有失败 → warn!, 否则 info!。
/// 全部是非敏感计数; `account_sha` 已是 `sha256_hex(wxid)` = 指纹非明文, 取前 8 位 (== sha8) 作账号标识。
fn log_message_stats(account_sha: &str, stats: &PipelineStats) {
    let acct = account_sha.get(..8).unwrap_or(account_sha);
    if stats.decode_errors > 0 || stats.stalled_subsources > 0 {
        tracing::warn!(
            account = acct,
            dbs = stats.dbs,
            subsources = stats.subsources,
            batches = stats.batches,
            decoded = stats.messages_decoded,
            decode_errors = stats.decode_errors,
            stalled = stats.stalled_subsources,
            skipped = stats.skipped_subsources,
            rescanned = stats.rescanned_subsources,
            "消息 ingest 完成 (有失败, 见 decode_errors/stalled)"
        );
    } else {
        // R19 (审 round-1 P3): skipped = 因不在 capture_targets 白名单被 drain 前跳过的会话数 (选择性采集生效可见; 全采时 0)。
        tracing::info!(
            account = acct,
            dbs = stats.dbs,
            subsources = stats.subsources,
            batches = stats.batches,
            decoded = stats.messages_decoded,
            cursor_updates = stats.cursor_updates,
            skipped = stats.skipped_subsources,
            // rescanned = 护栏判定"源表被换过/位置不算数"→ 整表从 0 重扫的会话数。健康稳态恒 0;
            // 升级后第一轮**每个 (分片, 会话) 各 1**(老水位强制重扫一次; 跨分片同名表会计两笔,
            // 真库有 700 张这样的表)。**稳态持续非 0 = 护栏在误响**, 要查。
            rescanned = stats.rescanned_subsources,
            "消息 ingest 完成"
        );
    }
}

/// pipeline 错误 (透传下层; 各下层错型已 K-R4 脱敏).
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// DbSource 取数失败 (snapshot / list / drain).
    #[error("pipeline source: {0}")]
    Source(#[from] crate::source::DbSourceError),
    /// sink 落库失败 (archive / L2 / 事务).
    #[error("pipeline sink: {0}")]
    Sink(#[from] SinkError),
    /// 读 etl_state 水位失败.
    #[error("pipeline state: {0}")]
    State(#[from] rusqlite::Error),
    /// 前置/源契约违反 (batch_limit=0 / DbSource 返 next_cursor 跳过本批最大 local_id). `detail` 非敏感.
    #[error("pipeline 契约违反: {0}")]
    Invariant(String),
    /// emit 推送失败 (消费端 drop → channel closed; 上层应停止采集).
    #[error("pipeline emit: {0}")]
    Emit(#[from] EmitError),
}

/// archive 写入 + 若有 emitter 则把同一事件产 record 推上层。**archive 与推送都用传入的 `mode`**
/// (默认 archive_canonical 全明文)。
///
/// **全程明文 (默认) + 脱敏能力保留 (用户 2026-06-29 决定: 自用纯明文, 微信有啥给啥不藏)**: archive 与推送
/// 同一 `mode` 渲染; adapter/CLI 默认传明文 → 存、推、导出全真值。脱敏 (`default_sha`) 能力保留在
/// PrivacyMode/emit (默认不启用) —— 将来若需对外脱敏 (如导出给第三方), 调用方显式传 `default_sha` 即可
/// (本函数推送 mode 跟随 archive, 不再硬编码脱敏; 这是从早先 "出边界强制脱敏 ADR-426 §2.4" 的翻转)。
/// archive 先写 commit, 再 emit (in_proc 契约: `archive.write` → `emitter.emit`)。`emitter=None` → 只 archive。
/// fingerprint/event_seq 与 mode 无关 (content_digest 隐私无关 §2.7.3)。
async fn archive_and_push(
    conn: &mut Connection,
    event: &DecodedEvent,
    src_create_time_ms: u64,
    ingest_time_ms: i64,
    mode: PrivacyMode,
    emitter: Option<&InProcEmitter>,
) -> Result<(), PipelineError> {
    write_decoded_event(conn, event, src_create_time_ms, ingest_time_ms, mode)?;
    if let Some(em) = emitter {
        let push_record = emit(event, src_create_time_ms, ingest_time_ms, mode);
        em.emit(push_record).await?;
    }
    Ok(())
}

/// R15 `--jobs` 默认并行度: **逻辑线程数的 50% (min 1)**。**不硬编码** —— `available_parallelism` 读实际
/// 核数, 取半留 headroom 给单写者 IO / SQLite / 系统 (ingest = decode-CPU 并行段 + 单写者-IO 串行段混合,
/// 全占核对串行写无益且抢占系统); `available_parallelism` 不可用 (如容器无 cgroup 配额) → 保守回退 1 (串行)。
#[must_use]
pub fn default_ingest_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 2).max(1))
        .unwrap_or(1)
}

/// **便利入口 (串行 `workers=1`)**: 现有调用者 (测试 / adapter 旧路径) 不变 —— 保留单线程语义作 R15 对拍基线。
/// R15 并行全量 ingest 走 [`run_message_pipeline_jobs`] (CLI `--jobs`)。
///
/// # Errors
/// 同 [`run_message_pipeline_jobs`]。
pub async fn run_message_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    run_message_pipeline_jobs(source, conn, account, mode, batch_limit, ingest_time_ms, emitter, 1).await
}

/// R15 并行全量 ingest 入口: `workers` = 批内 decode 并行度 (>1 = rayon 并行, =1 = 串行, 等价
/// [`run_message_pipeline`])。写入永远单写者按 rowid 序 → **并行结果逐字 == 串行** (不丢/不重/不乱水位)。
///
/// # Errors
/// `batch_limit==0` 或任一子源错即返 Err (水位未推进, 下次续)。
#[allow(clippy::too_many_arguments)] // 与 run_message_pipeline 同参 + workers; ingest 入口固有多参。
pub async fn run_message_pipeline_jobs(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
    // R15 --jobs: 批内 decode 并行度 (>1 = rayon 并行, =1 = 串行)。CLI 默认逻辑线程 50% (min 1)。本函数内按此值
    // 建**专用** rayon ThreadPool (钳到逻辑核数; 非全局 build_global → 不污染 keyscan 等其它 rayon 用户)。
    workers: usize,
) -> Result<PipelineStats, PipelineError> {
    // 代码双审 P2: batch_limit=0 = 无意义 (drain 0 行/不前进却正常返回) → 入口 reject。
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let account_sha = sha256_hex(account.as_str());
    let mut stats = PipelineStats::default();

    // R15 并行度: workers 钳到逻辑核数 (decode CPU-bound, 超核无益; 防极大 workers 如 --jobs 100000 / 库调用者
    // → rayon 试建上百线程爆资源; available_parallelism 不可用则保守 16)。workers<=1 直接串行 (effective=1)。
    let effective_workers = if workers > 1 {
        let cap = std::thread::available_parallelism().map_or(16, std::num::NonZeroUsize::get);
        let eff = workers.min(cap);
        if workers > eff {
            tracing::warn!(
                requested = workers,
                cap,
                effective = eff,
                "workers 超逻辑核数, 钳制 (超核无益)"
            );
        }
        eff
    } else {
        1
    };
    // 注(审 Round-D): R15 并行 decode **分窗** (PAR_DECODE_WINDOW) → 峰值内存 O(窗口) 不随 batch_limit 涨, 故
    // **无需对 batch_limit 设 R15 专属上界**(前几轮的 MAX 上界已随分窗设计删除)。batch.rows 本身 O(batch_limit)
    // 与 `emitter=Some` 时 pending_emit O(batch_limit) 都是 **base 既有**行为 (非 R15 新增), 其上界属独立 chip。
    // 仅 **effective>1 且 batch_limit>1 (真会有多行批可并行)** 才建专用 rayon 池 (非全局 build_global; 不污染
    // keyscan → 审 P2-2)。单核钳后 effective==1 或 batch_limit==1 (每批至多 1 行永走串行分支) → None 串行
    // (审 Round-A/C P3: 不建永不使用的池)。build 失败 `?` 早返; 亦在 drop 索引之前 → 不留半态。
    let pool: Option<rayon::ThreadPool> = if effective_workers > 1 && batch_limit > 1 {
        Some(
            rayon::ThreadPoolBuilder::new()
                .num_threads(effective_workers)
                .thread_name(|i| format!("ingest-decode-{i}"))
                .build()
                .map_err(|e| {
                    PipelineError::Invariant(format!(
                        "rayon decode 池构建失败 (effective_workers={effective_workers}): {e}"
                    ))
                })?,
        )
    } else {
        None
    };

    // 延迟索引 (性能): 落库前删二级索引 (每条免维护 5 棵 B-tree), 主体跑完**无论成败**重建 (codex P1:
    // finally 式, 防主体任何 `?` 早返留下无索引状态)。去重靠 message PK / archive UNIQUE(5 元组) 表级约束。
    // R9 双审 P2: FTS 增量触发器同理 —— 批量 ingest (watch 停机后追赶 / 重灌) 触发器在岗 = 每条 trigram 分词逐条
    // 写 message_fts (与 drop B-tree 索引规避逐条维护矛盾, 且非"一次性 rebuild")。落库前 drop 触发器, 跑完一次性
    // rebuild 对齐 + 建回 (SQLite bulk-load 惯例; 纯小增量 tail-f 的逐条成本是设计接受的增量代价, 此优化仅惠批量路径)。
    let had_fts_triggers = crate::storage::message_fts_triggers_exist(conn);
    if had_fts_triggers {
        crate::storage::drop_message_fts_triggers(conn)?;
    }
    drop_ingest_indexes(conn)?;
    let body = run_message_body(
        source,
        conn,
        account,
        &account_sha,
        mode,
        batch_limit,
        ingest_time_ms,
        emitter,
        pool.as_ref(),
        None, // 全量 ingest 不限会话(按持久白名单)
        &[],
        None,
        // 全量 ingest: Deep —— 一次性几十秒, 而且它正是"第一次把已读段行数算出来"的时机。
        crate::source::ProbeDepth::Deep,
        &mut stats,
    )
    .await;
    let recreate = create_ingest_indexes(conn);
    // R9 双审 P2: FTS 触发器建回 (finally 式, 同 create_ingest_indexes): 之前在岗则一次性 rebuild 对齐本批 + 重建
    // 触发器。主体失败也建回 (message 可能部分写, rebuild 对齐已写的; 不留"索引在触发器没了"的半态)。
    //
    // **零写入时跳过 rebuild** (2026-07-29): 上面 drop 触发器→body→rebuild 这套是为**批量**设计的
    // (避开逐条 trigram 分词), 对真有大批新消息的场景是对的。但增量 ingest 常常一条新消息都没有,
    // 这时 rebuild 是纯浪费 —— `INSERT INTO message_fts(message_fts) VALUES('rebuild')` 是全量重建,
    // 代价随**库里已有消息数**走而不是本批增量: 实测零新增的一次 ingest 仍重建整个索引, 大库要几分钟。
    // 用户每次增量导入都白等这一段, 而且完全看不出为什么慢。
    //
    // 跳过的**前提是本轮确实一行没写**: `messages_decoded == 0` 且主体 `Ok`。两个条件缺一不可 ——
    //   · 主体 Err 时 stats 可能不完整、message 也可能部分写 ⇒ 保守照旧全量重建 (原 finally 语义不变)
    //   · 触发器**无论如何都要建回**, 否则留下"索引在、触发器没了"的半态: 之后 watch 增量写进来的
    //     消息不会进 FTS, 搜索静默漏数据 —— 比慢严重得多。所以 skip 只跳 rebuild 不跳 init。
    let wrote_nothing = body.is_ok() && stats.messages_decoded == 0;
    let refts: rusqlite::Result<()> = if had_fts_triggers {
        if wrote_nothing {
            tracing::debug!("本轮零新增消息 → 跳过 FTS 全量重建 (触发器仍建回)");
            crate::storage::init_message_fts_triggers(conn)
        } else {
            crate::storage::rebuild_message_fts(conn).and_then(|_| crate::storage::init_message_fts_triggers(conn))
        }
    } else {
        Ok(())
    };
    body?; // 主体错误优先 (recreate/refts 已尝试)
    recreate?; // 主体成功但重建索引失败才抛
    refts?; // 索引 + FTS 触发器都重建才算干净

    // P2 (codex): 索引重建后 checkpoint 收 WAL (批量大事务会让 WAL 膨胀); best-effort 不阻断。
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    log_message_stats(&account_sha, &stats); // R11: run 结束汇总
    Ok(stats)
}

/// R9 P1-fix (复审#1): **增量 watch 专用** ETL —— 同 [`run_message_pipeline`] 但**不 drop/重建索引 + FTS 触发器**。
///
/// 索引 + `message_fts` 触发器**全程在岗**, `run_message_body` 逐条 INSERT/REPLACE 时触发器自维护倒排 (件1 增量设计)。
/// **为何不复用 batch 路径**: batch 每次 drop 触发器 → body → `rebuild_message_fts` (全量重建整个 FTS) —— 对 watch
/// **每个 tail-f 批**都全量重建, 百万级库 O(N)/批 卡死 (复审#1: aefd37c 批量优化误伤 watch)。小增量批逐条成本 << 重建。
///
/// **前提**: L1 已 build 过 (`search --build` / 初次 `run_message_pipeline` 建好索引 + 触发器); watch 只增量刷。
/// 无 FTS 触发器 (从没 build) → body 照常插入、无 FTS 维护 (正确)。
///
/// # Errors
/// 同 [`run_message_pipeline`] (任一子源错即返 Err, 水位未推进下次续)。
pub async fn run_message_pipeline_incremental(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let account_sha = sha256_hex(account.as_str());
    let mut stats = PipelineStats::default();
    // 增量: 索引 + FTS 触发器全在岗, 逐条维护, 不 drop 不 rebuild (对齐件1 增量设计)。
    // pool=None (串行): watch 每批小增量, 并行调度开销 > 收益; R15 并行只惠全量 ingest (run_message_pipeline_jobs)。
    run_message_body(
        source,
        conn,
        account,
        &account_sha,
        mode,
        batch_limit,
        ingest_time_ms,
        emitter,
        None,
        None,
        &[],
        None,
        // watch 每轮全子源循环: Shallow —— 750 万行 ≈ 18 秒/轮, 付不起。
        // 不影响这个数的准确性: drain 侧按"旧值 + 本批行数"算术推进(见 `ProbeDepth` 文档)。
        crate::source::ProbeDepth::Shallow,
        &mut stats,
    )
    .await?;
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    log_message_stats(&account_sha, &stats);
    Ok(stats)
}

/// R22 (ADR-508 D24) **会话级增量采集**: 只把 `conv_id` 这一个会话的新行采进 L1, 然后调用方纯冷查。
///
/// 为什么是这个形态: "某段时间是完整的"没有便宜的验证方式(D24 记了整个演进), 而"这张表已采到 `local_id` N"
/// 是精确可验证的 —— 后插入的 id 必然更大, 与时间戳无关。于是回填 / 表重建 / 乱序 / 同秒并发全部自然消解。
///
/// 复用**现成**的增量通道: 与 R9 watch 同一条 `run_message_body`, 同一个 `WHERE local_id > cursor` keyset,
/// 同一个 `etl_state` 游标(键 = `"<分片>|<表>"`, 而 `Msg_<md5>` 表就是一个会话 → 粒度天然对上),
/// 同一条 sink(archive + 全部派生表)。R22 不再自造第二套元数据。
///
/// **不改用户的 capture 白名单**: 临时作用域与白名单取交集; 别的会话在 drain 前整表跳过, 游标一动不动。
///
/// # Errors
/// 源库不可读 / 落库失败 / DbSource 失约(见 `PipelineError`)。
// 8 个参数都是彼此独立的输入(源/库/账号/会话/分片提示/隐私档/批大小/时间戳), 塞进一个结构体只是把
// 参数表搬个地方, 调用点还得先构造它 —— 不如就这么摆着, 每个参数上都有注释说明。
#[allow(clippy::too_many_arguments)]
pub async fn ingest_one_chat(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    conv_id: &str,
    // 要开哪几个分片; 空 = 全开。**硬过滤 —— 不在名单里的连开都不开**。
    // 调用方必须给"上次命中的 ∪ 这一轮变化过的", 只给前者会漏掉会话刚搬进去的活跃分片
    // (见 `run_message_body` 的 `only_shards` 详注)。
    scan_shards: &[String],
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
) -> Result<(PipelineStats, Vec<String>), PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let account_sha = sha256_hex(account.as_str());
    let mut stats = PipelineStats::default();
    let mut matched: Vec<String> = Vec::new();
    run_message_body(
        source,
        conn,
        account,
        &account_sha,
        mode,
        batch_limit,
        ingest_time_ms,
        None,
        None,
        Some(conv_id),
        scan_shards,
        Some(&mut matched),
        // 懒式刷新: Deep —— 一次只碰一个会话, 最坏 0.42 秒, 而闸开本来就要约 1.6 秒。
        crate::source::ProbeDepth::Deep,
        &mut stats,
    )
    .await?;
    Ok((stats, matched))
}

/// R15 步2(无改动重构): **纯解码一行** → `(DecodedEvent, 源事件时间ms)`。**不碰 `Connection`** —— 是 R15 多核
/// worker 池并行的前提(`Connection` `!Send` 是当前单线程根因; worker 只处理 `Send` 数据, 单写者线程独占连接写)。
/// assemble 成功 → `Message` 事件 + `create_time`(秒)×1000ms(进 fingerprint, ADR-413 §4); assemble 失败 → `SystemError`
/// 事件(src_time=0, 唯一性靠 `error_anchor`; decoder §2 红线: 单条坏不阻塞)。**逐字等价**原 `run_message_body` 内联
/// 解码逻辑, 抽出后单线程(现)与多核(R15)共用: 现路径 decode 后立即 `write_decoded_event_in_tx`; R15 worker 只算此
/// 函数、按 rowid 排回序后交单写者调同一 write。纯函数 → 顺序无关、幂等确定性天然保住(§5)。
fn decode_row(
    row: &MessageRow,
    account: &Wxid,
    conv_id: &str,
    rel_name: &str,
    ingest_time_ms: i64,
) -> (DecodedEvent, u64) {
    let native_id = msg_anchor(conv_id, row.local_id);
    let ctx = MessageContext {
        account_id: account.clone(),
        conv_id: conv_id.to_string(),
        source: rel_name.to_string(),
        source_native_id: native_id.clone(),
        ingest_time: ingest_time_ms,
    };
    match assemble_message(row, &ctx) {
        Ok(mc) => {
            let src_create_time_ms = u64::try_from(row.create_time.saturating_mul(1000)).unwrap_or(0);
            (DecodedEvent::Message(mc), src_create_time_ms)
        }
        // 单条标坏 → SystemError 事件 (archive 溯源, 无 L2)。src_time=0(约定; 唯一性靠 source_native_id=error_anchor)。
        Err(e) => (
            build_decode_error_event(account, rel_name, &native_id, &e, ingest_time_ms),
            0,
        ),
    }
}

/// `run_message_pipeline`/`_jobs` 的主体 loop (扫 snapshots × 子源 → 批量落库)。提取供上层 drop/create
/// 索引 **finally 包裹** (codex P1: 任何 `?` 早返后仍重建索引)。`account_sha` 预算好传入; `stats` &mut 累计。
#[allow(clippy::too_many_arguments)] // 提取自 run_message_pipeline + R15 pool 参数; 入口固有多参
async fn run_message_body(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    account_sha: &str,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
    // R15 并行 ingest: `Some(池)` = 批内 decode_row 走该**专用** rayon 池并行 (纯函数, `install` 内 par_iter
    // 保序 collect); `None` = 串行边解边写 (逐字等价原路径, O(1) 内存)。写入永远单线程按 rowid 序 (水位不乱);
    // 并行只在纯 decode 段。**专用池 (非全局 build_global)**: 不污染 keyscan 等其它 rayon 用户 (审 P2-2)。
    pool: Option<&rayon::ThreadPool>,
    // R22 (ADR-508 D24) 会话级增量采集: `Some(conv_id)` = 本次**只采这一个会话**, 与持久 capture 白名单
    // 取**交集**(不改用户的名单, 也不因为临时采一次就把别的会话游标推走)。`None` = 老行为(全采/按白名单)。
    only_conv: Option<&str>,
    // 配合 `only_conv`: **只开这几个分片**。空 = 不限, 全开。
    //
    // ⚠️ 调用方给的名单**必须含"这一轮变化过的分片"**, 不能只给"上次命中的" —— 沉寂会话醒来时
    // 新消息进的是当前活跃分片, 它不在上次的名单里, 只按老名单开就**永远扫不到**
    // (2026-07-30 修; 见 `native-query::refresh::snapshot_sig` + `d24_gate_catches_table_appearing_in_existing_shard`)。
    // 这是硬过滤: 名单里没有的分片**连开都不开**, 所以少给一个 = 静默漏。
    //
    // (开库成本: 真库 6 分片 0.4–2.1GB, 实测**单库 0.2–0.7s** —— ADR-500 的 VFS 按需解密之后,
    //  早年"整库解密十几秒"那个数已不成立。仍值得只开需要的那几个, 但不必为省它冒漏数据的险。)
    only_shards: &[String],
    // 配合 `only_conv`: 把**真正含有该会话**的分片文件名回报出来 —— 调用方拿它当"下次至少要开哪几个"
    // 的下限(注意只是下限: 还得并上"变化过的分片", 理由同上)。
    matched_shards: Option<&mut Vec<String>>,
    // 护栏探多深 —— 只影响"已读段行数"那一项要不要扫行。全量 ingest 和懒式刷新给 `Deep`,
    // watch 每轮全子源循环给 `Shallow`(750 万行 ≈ 18 秒/轮, 付不起)。见 `source::ProbeDepth`。
    depth: crate::source::ProbeDepth,
    stats: &mut PipelineStats,
) -> Result<(), PipelineError> {
    // R19 选择性采集: 读该账号的会话白名单 (空表/无表 → None = 全采, 零过滤成本)。**每次 body 调用读一次**。
    // 所有采集路径 (全量 jobs / 便利入口 / watch incremental) 共穿本函数 → 一处过滤覆盖 ingest+watch (R17 统一底座红利)。
    // **watch 生效时机 (codex round-1 P2 校正)**: run_watch_loop 仅在 source 库 mtime 签名**变了**才调 body (非每 poll)。故
    // --to-l1 (work_l1=真库, 读 live capture_targets) 中途 `capture add` 在**下次任一 source 变化**触发 body 时生效 (新圈会话
    // 从 cursor 0 补历史); --print (读 adapter 拷入的启动快照) 新圈定需重启 watch。要立即生效可重跑 ingest/watch。
    let capture_whitelist = crate::capture::read_capture_targets(conn, account_sha)?;
    let mut matched_shards = matched_shards;

    let snapshots = source.snapshot_dbs().await?;
    stats.dbs = snapshots.len();

    // R15 进度日志: 全量 ingest 是小时级重活, 每 ~5s 打一次进度 (已处理条数 + 即时速率 + workers),
    // 避免多小时静默。纯诊断 (tracing::info, 脱敏无 payload); 不影响落库逻辑。
    // effective_workers = 专用池实际线程数 (无池=串行=1); 只作日志展示。
    let effective_workers = pool.map_or(1, rayon::ThreadPool::current_num_threads);
    let mut last_log = std::time::Instant::now();
    let mut rows_at_last_log: u64 = 0;

    for snapshot in &snapshots {
        // 已知会话在哪几个分片 → 别的分片连开都不开(开库=整库解密, 十几秒)。
        if !only_shards.is_empty() && !only_shards.iter().any(|s| s == &snapshot.rel_name) {
            continue;
        }
        // R22 D24: 只采一个会话时走**单会话快路**(正着算表名点一下 sqlite_master), 不读整张 Name2Id ——
        // 那一步在真库 6 分片 2.2 万会话上约 16 秒, 而"确保某会话最新"每次查询都要走一遍。
        let subsources = match only_conv {
            Some(c) => source
                .find_message_subsource(snapshot, c)
                .await?
                .into_iter()
                .collect::<Vec<_>>(),
            None => source.list_message_subsources(snapshot).await?,
        };
        stats.subsources += subsources.len();

        for subsource in &subsources {
            // R19 选择性采集: 不在白名单 → **drain 前整表跳过** (不 drain / 不解密 / 不推水位)。
            // 关键 (spec D5): 跳过的会话 etl_state cursor 保持不动 → 后来 `capture add` 它 → 下次从 cursor 0 重 drain
            // 补全历史一条不漏。**不能逐行过滤** (逐行仍推水位会把 cursor 推到最新, 打穿"以后补历史")。
            if let Some(wl) = &capture_whitelist {
                if !wl.contains(&subsource.conv_id) {
                    stats.skipped_subsources += 1;
                    continue;
                }
            }
            // R22 D24: 临时会话作用域 —— 与白名单**同款语义**(drain 前整表跳过, 不动它的 cursor),
            // 所以"临时只采会话 A"不会把会话 B 的水位推走, B 以后照常从自己的 cursor 补齐历史。
            if only_conv.is_some_and(|c| c != subsource.conv_id) {
                stats.skipped_subsources += 1;
                continue;
            }
            if only_conv.is_some() {
                if let Some(v) = matched_shards.as_deref_mut() {
                    if !v.iter().any(|s| s == &snapshot.rel_name) {
                        v.push(snapshot.rel_name.clone());
                    }
                }
            }
            // etl_state 键: source="<rel>|<table>" (跟 project_watermark 读写同键)。
            let etl_source = format!("{}|{}", snapshot.rel_name, subsource.table);

            // 起始游标 = 持久水位 (无 / 解析失败 → 0 全量 re-drain)。
            //
            // ⚠️ **解析阶段就被打回 0 的那几种也要计进 `rescanned_subsources`**(codex round-9 P2):
            // 老格式(`{"id","sid","ct"}` / 缺 `ct` 或缺 `sid` 键)在 `from_watermark_value` 里直接返
            // `default()`, **压根走不到下面那个 `cursor.local_id > 0` 的护栏块**。而这恰恰是
            // **升级后第一轮每个会话都会走一次**的路 —— 最该被数到的场景反倒数不到, 那这个指标在
            // 迁移期就是错的: 调用方会把重扫出来的老消息当成"真来了这么多新消息"。
            // 判据: **存过水位、且存的不是 0, 解析完却是 0** —— 不管是老格式被判重扫还是根本解析不了,
            // 都等于"带着水位却要从头再来一遍", 都算。
            let mut cursor = DrainCursor::default();
            if let Some(w) = get_watermark(conn, account_sha, &etl_source, MESSAGE_KIND)? {
                let stored = w.watermark_value.trim();
                let stored_was_nonzero = !stored.is_empty() && stored != "0";
                cursor = DrainCursor::from_watermark_value(stored).unwrap_or_default();
                if cursor.local_id == 0 && stored_was_nonzero {
                    tracing::warn!(
                        etl_source,
                        "水位是老格式 / 解析不了 → 从 0 重扫该会话一次(升级后每个 (分片, 会话) 各一次)"
                    );
                    stats.rescanned_subsources += 1;
                }
            }

            // ⚠️ **游标倒退护栏**(D24 审 P1): `local_id` 单调只在"表没被重建过"时成立。微信迁移 / 清空
            // 聊天记录 / 换设备会把 `Msg_<md5>` 表**重建**, id 从 1 重来 —— 这时旧 cursor(比如 10000)比表里
            // 现有的最大 id(比如 500)还大, `WHERE local_id > 10000` 恒空, 那 500 条**永久漏掉**, 直到源库
            // 的 id 重新涨过 10000。而各路信号全是干净的(采集"成功"、stats 全 0)。
            // 判据就是"cursor 不该超过表里现有的最大 id": 一旦超了, 说明不是同一张表了 → 从 0 重扫。
            // (重扫是幂等的: archive 五元组去重 + 派生表按消息 delete+insert。)
            //
            // ⚠️ **只比"表里最大 id"挡不住"重建后长过旧游标"那一格**(外部复审 P1): 旧水位 5、新表 1..9 时
            // `max_id(9) > cursor(5)`, 上面那条不响, 而 `WHERE local_id > 5` 只读 6..9 —— **新的 1..5 永久漏**。
            // 所以真正的判据是「**这还是不是原来那张表**」: 水位里一并记了**全表最老那一行**的指纹
            // (`local_id` + 建表时间 + 类型 + 正文全字节, 见 `DrainCursor::resume_fp`), 对不上就是换过表了
            // → 从 0 重扫。
            //
            // ⚠️ 身份锚点是**最老那行**而不是游标(=最新)那行(第四轮对抗审 P2): 最新一条最容易被**就地改**
            // —— 图片/视频上传完把 CDN 字段回写进 `message_content`、撤回改写正文并改 `local_type`, 表根本
            // 没被重建。拿最新一条当身份, 每发一张图就误判"重建"一次 → 整个会话重扫重发。
            // 最老那行反过来最稳: 早同步完了, 没人再动它。
            //
            // ⚠️ **但光有身份不够**(第五轮 codex 与独立复审各自逮到的 P1): 老锚点顺带管着"我停的位置
            // 还算不算数", 搬走以后那一路空了。真实触发路径是**源库被换成一份更老 / 更短的同一张表**
            // —— 从备份恢复、部分迁移、回滚数据目录。这时最老那行**逐字节一样**(真库随机 400 张
            // `Msg_` 表 `MIN(local_id)` 全是 1), 身份指纹必然对得上, 而游标停在旧的高位, 之后新来的
            // 消息拿的号全在游标底下 → **永久躲着**, 各路信号还全是干净的。
            //
            // ⚠️ 别把理由记成"rowid 会重用"(我第一版就写错了): 真库是
            // `local_id INTEGER PRIMARY KEY AUTOINCREMENT`, **不重用**号。这道护栏该留的理由是上面
            // 那条, 不是 rowid 语义 —— 按错理由判"AUTOINCREMENT 不重用所以这道多余"就会把它删掉。
            //
            // 所以同一次探测把 `max_id` + 游标那行的 `create_time` + `server_id` 一并带回,
            // 四个信号各判各的(见 `source::TableProbe`)。
            //
            // 补种了游标那行的 `server_id` / 已读段行数, 而本轮**未必有新行** → 标一下, 让空批也写一次水位。
            // (名字留着 `sid_` 是历史原因, 现在两样都用它。)
            let mut sid_backfilled = false;
            if cursor.local_id > 0 {
                let probe = source
                    .rebuild_sentinel(snapshot, subsource, cursor.local_id, depth)
                    .await?;
                match (probe, cursor.resume_fp) {
                    // 表**空了** → 聊天记录被清 / 换过表 → 重扫。
                    (crate::source::ResumeProbe::Missing, _) => {
                        tracing::warn!(
                            etl_source,
                            cursor = cursor.local_id,
                            "源表空了但水位不为 0(聊天记录被清 / 表被重建?) → 从 0 重扫该会话"
                        );
                        cursor = DrainCursor::default();
                        stats.rescanned_subsources += 1;
                    }
                    // 还在, 但**不是原来那张表** → 重建过 → 重扫。**这就是被复审逮到的那一格。**
                    // (用户手动删掉最老几条也会走这里: 误判一次、重扫一次、重新锚定 —— 保守方向, 可接受。)
                    (crate::source::ResumeProbe::Found(p), Some(was)) if p.oldest_fp != was => {
                        tracing::warn!(
                            etl_source,
                            cursor = cursor.local_id,
                            "最老那行的指纹变了(源表被重建, 且新表长过旧游标) → 从 0 重扫该会话"
                        );
                        cursor = DrainCursor::default();
                        stats.rescanned_subsources += 1;
                    }
                    // 表**缩了**: 游标比现在的最大 id 还大(换上了一份更短的旧副本)。老锚点(游标那
                    // 一行)顺带管着这一格 —— 那一行没了就重扫; 换成最老那行以后必须显式判。
                    (crate::source::ResumeProbe::Found(p), Some(_)) if p.max_id < cursor.local_id => {
                        tracing::warn!(
                            etl_source,
                            cursor = cursor.local_id,
                            max_id = p.max_id,
                            "游标比表里最大 local_id 还大(近期消息被删 / 表被重建?) → 从 0 重扫该会话"
                        );
                        cursor = DrainCursor::default();
                        stats.rescanned_subsources += 1;
                    }
                    // **水位里没有"已读段行数", 而这一轮探得到(= 走的是 Deep)→ 从 0 重扫一次把它建立起来。**
                    //
                    // 独立复审 P1: 这一项缺席的原因有两种 —— 上一版格式(带 fp/ct/sid 不带 n)、
                    // 或者这个会话一直只被 `Shallow` 那条路(watch)碰过。两种都**不能靠"拿探到的值填进去"
                    // 收场**: 那等于**把当前状态直接当成基准**, 万一缺口在填之前就已经存在(正是复审造的
                    // 那个反例: 先挖洞首采、后恢复副本), 就被永久抹平了。
                    //
                    // 所以按迁移处置 —— 跟 `fp`/`ct`/`sid` 缺席一个待遇。**只在 Deep 上做**:
                    // `Shallow`(watch)探不到这一项, 走不到这里, 于是两条路不会互相打架。
                    // 重扫一次之后 drain 侧从 0 把这个数算出来, 之后 `Shallow` 靠算术推进维护它。
                    (crate::source::ResumeProbe::Found(p), Some(_))
                        if cursor.prefix_rows.is_none() && p.prefix_rows.is_some() =>
                    {
                        tracing::warn!(
                            etl_source,
                            cursor = cursor.local_id,
                            "水位里没有已读段行数(上一版格式 / 一直只走快路径)→ 从 0 重扫该会话一次建立它"
                        );
                        cursor = DrainCursor::default();
                        stats.rescanned_subsources += 1;
                    }
                    // 表没缩, 但**游标那个位置换了人**: 换上的那份副本在游标那一格上是**另一条消息**,
                    // 而且它比旧游标还长(旧游标 9, 新副本 1..4 原样 + 5..12 是别的消息)—— `max_id(12)>9`,
                    // 上面那条不响, 而 `WHERE local_id > 9` 只读 10..12, **5..9 那 5 条永久漏**。
                    //
                    // 比两样: `create_time`(写入时定死, 上传回写和撤回都不改它)+ `server_id` 加基数
                    // (秒级时间在真库一张表上 4.5 万行里就有 32 行同秒, 光比它可能撞;
                    // `server_id` 基数高得多 —— 但**它也不是唯一的**, 真库全量扫出过非零重复
                    // (同一条消息 re-sync 双写), 见 `source::TableProbe::cursor_sid`。它是加基数, 不是身份。)
                    // **任一侧 `server_id` 是 0 就不比它** —— 自己发的消息在回执前是 0、之后就地填上,
                    // 硬比等于把 round-4 那个"发一条就全量重扫"的坑再挖一遍。
                    //
                    // 水位里必有 `ct`(没有的在 `from_watermark_value` 就被判成重扫一次了), 所以这里
                    // 不再判 `is_some`: 万一真是 `None`, `Some != None` 也走重扫, 保守方向。
                    (crate::source::ResumeProbe::Found(p), Some(_))
                        if p.cursor_ct != cursor.cursor_ct || sid_conflict(p.cursor_sid, cursor.cursor_sid) =>
                    {
                        tracing::warn!(
                            etl_source,
                            cursor = cursor.local_id,
                            "游标那一行换成别的消息了(源库被换成另一份副本?) → 从 0 重扫该会话"
                        );
                        cursor = DrainCursor::default();
                        stats.rescanned_subsources += 1;
                    }
                    // 老水位没记指纹(升级前写的)→ 只能退回旧护栏: 比最大 id。
                    // ⚠️ **这一格挡不住"升级之前就已经发生过的重建"** —— 那时旧指纹压根没存过, 无从比对。
                    // 本轮结束会把指纹补上, 从下一轮起受保护。要清掉历史遗留只能显式全量重扫。
                    // 老水位(升级前写的裸数字)没有指纹 → **强制全量重扫一次**。
                    //
                    // ⚠️ 曾想省这一次: "只把当前那一行的指纹补种进去, 不重扫"。**那是错的**(第三轮对抗审 P1):
                    // 带指纹的水位格式从没发布过 → **现存每一个 L1 的每一个子源水位都是裸数字** → 每个会话
                    // 都要恰好走这一支一次。一旦升级前正好赶上重建(迁移 / 清空聊天记录 / 换设备),
                    // 这一轮就漏掉游标以下的行, **而且下一轮指纹已按新一代种好, 护栏再也不会响 = 永久漏**。
                    // 实测: 新表 9 条只补进 4 条, 再采一轮还是 4 条。
                    //
                    // 上一版 `{"id","sid","ct"}` 格式我已经判"强制重扫一次是安全动作" —— 裸数字的暴露面
                    // **完全相同**, 处置就该一致。代价: 每个会话在升级后第一轮全量重扫一次
                    // (采集三种写全幂等: archive 五元组去重 + 派生表 delete+insert + message 主表 REPLACE),
                    // 慢但只发生一次; 而静默把数据缺口水泥封住是没法补救的。
                    (crate::source::ResumeProbe::Found(_), None) => {
                        tracing::warn!(
                            etl_source,
                            cursor = cursor.local_id,
                            "水位里没有行指纹(升级前写的)→ 认不出升级之前是否发生过表重建 → 从 0 重扫该会话一次"
                        );
                        cursor = DrainCursor::default();
                        stats.rescanned_subsources += 1;
                    }
                    // 探不出来(默认实现 / 非 Msg_ 表)—— **不能**当成"表被重建", 也没指纹可补。
                    (crate::source::ResumeProbe::Unsupported, _) => {
                        if let Some(max_id) = source.max_local_id(snapshot, subsource).await? {
                            if max_id < cursor.local_id {
                                tracing::warn!(
                                    etl_source,
                                    cursor = cursor.local_id,
                                    max_id,
                                    "游标比表里最大 local_id 还大(源表被重建?) → 从 0 重扫该会话"
                                );
                                cursor = DrainCursor::default();
                                stats.rescanned_subsources += 1;
                            }
                        }
                    }
                    // 身份和位置都对得上, 但**已读那一段的行数变了** = 中间被挖过洞 / 补过行。
                    // 前面四项只看三个点(第一行 / 游标行 / 最大 id), 中间那段没人管 —— 这一项专管它。
                    // **两边都有值才比**: 探回来 `None` = 这一轮走的是 Shallow(watch 那条路),
                    // 水位里 `None` = 这个数还没建立过(补种那一支会从 `Deep` 的探测结果里填上)。
                    //
                    // ⚠️ **这里两个方向都判, 是有意的**(独立复审 P2 指出这一点): 严格说只有行数**变多**
                    // 才可能藏住没读过的行, 变少 = 已读过的行没了(用户删消息), 不会漏。
                    // 但**这条路误判的代价只是重扫一遍**(幂等、用户看不见), 而热 `new` 那条路误判会
                    // **在用户屏幕上重报整段历史** —— 所以那边收窄成"只判变多", 这边保守全判。
                    // 代价如实记: 用户每删一条老消息, 这个会话就整表重扫一次(只多花时间, 不出错)。
                    (crate::source::ResumeProbe::Found(p), Some(_))
                        if matches!((p.prefix_rows, cursor.prefix_rows),
                                    (Some(now), Some(was)) if now != was) =>
                    {
                        tracing::warn!(
                            etl_source,
                            cursor = cursor.local_id,
                            now = p.prefix_rows,
                            was = cursor.prefix_rows,
                            "已读那一段的行数变了(中间被挖过洞 / 换了副本) → 从 0 重扫该会话"
                        );
                        cursor = DrainCursor::default();
                        stats.rescanned_subsources += 1;
                    }
                    // 身份和位置都对得上 = 同一张表同一格 → 正常增量。
                    //
                    // 顺手**把游标那行的 `server_id` 补种进来**(codex round-7 P1): 水位里存的可能是 0
                    // ("当时还没回执"), 而它现在已经填上真值了。不补的话, 这个会话只要不再来新消息,
                    // 水位就永远停在 0 → `sid` 那道判据对它**永远不生效**, 只剩秒级的 `ct` 兜着。
                    // 补完要落盘才算数, 所以标一下: 下面即使是空批也写一次水位。
                    (crate::source::ResumeProbe::Found(p), Some(_)) => {
                        if cursor.cursor_sid.unwrap_or(0) == 0 && p.cursor_sid.unwrap_or(0) != 0 {
                            cursor.cursor_sid = p.cursor_sid;
                            sid_backfilled = true;
                        }
                    }
                }
            }

            loop {
                let batch = source.drain_messages(snapshot, subsource, &cursor, batch_limit).await?;
                stats.batches += 1;
                let has_more = batch.has_more;
                let next_cursor = batch.next_cursor;
                // source 契约校验 (代码双审 P1): 非空批 next_cursor 必须 == 本批最大 local_id, 否则
                // advance 到 next_cursor 会跳过 (max, next_cursor] 区间的行 → 漏数据。失约即停 (不前进)。
                let batch_max = batch.rows.iter().map(|r| r.local_id).max();
                if let Some(m) = batch_max {
                    if next_cursor.local_id != m {
                        return Err(PipelineError::Invariant(format!(
                            "DbSource 失约: 子源 {etl_source} next_cursor={} != 本批最大 local_id={m}",
                            next_cursor.local_id
                        )));
                    }
                }
                // 推进条件: 游标真前进 (校验后非空批必满足; 防 buggy source 死循环)。
                let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

                // 批量落库 (性能): 整批 rows + 批末 cursor_update **一个事务**, 摊薄每条 begin/commit 开销
                // (原每条一事务 → 每批一次)。崩溃在 commit 前整批回滚 → 重启从旧水位重 drain, archive 5 元组
                // 幂等去重 (契约不变: 游标推进仍在批内 rows 全落之后, 且与 rows 同事务原子)。
                // emit 推送在 commit **之后**批量发 (archive-first 契约保留: 先落库再推; emitter=None 则不发)。
                let mut pending_emit: Vec<(DecodedEvent, u64)> = Vec::new();
                {
                    let tx = conn.transaction()?;
                    // 单写者写一条 (并行窗内 / 串行 两路共用): archive+L2 落库 + stats 分类 + pending_emit 累积。
                    // 逐字等价原逐行 write 路径 (Message=解码成功, 其它 SystemError=解码失败, 等价原 Ok/Err 分支计数)。
                    macro_rules! write_one {
                        ($ev:expr, $t:expr) => {{
                            let ev = $ev;
                            let src_time = $t;
                            write_decoded_event_in_tx(&tx, &ev, src_time, ingest_time_ms, mode)?;
                            if matches!(ev, DecodedEvent::Message(_)) {
                                stats.messages_decoded += 1;
                            } else {
                                stats.decode_errors += 1;
                            }
                            if emitter.is_some() {
                                pending_emit.push((ev, src_time));
                            }
                        }};
                    }
                    // R15 decode: decode_row 是纯函数 (不碰 tx/无共享可变态, 见其定义)。写入永远单线程按 rowid 序 →
                    // 不丢/不重/不乱水位 (cursor 仍批末推进)。两路:
                    //   `Some(池)` 且批>1: **分窗并行** —— 每窗 ≤PAR_DECODE_WINDOW 行在专用池 par_iter 并行 decode,
                    //     `collect::<Vec>()` 保输入序 (IndexedParallelIterator 契约), 立即按序写, 再下一窗。窗间保序 +
                    //     窗内保序 = 整体按 rowid 序。**峰值内存 O(窗口 **条**解压事件), 与 batch_limit 无关**(分窗
                    //     相对整批 collect O(batch_limit) 条的真收益)。**字节**峰值=窗口条×单条解压大小, 单条无上限属
                    //     decoder 层关切; **另有一道字节预算闸** PAR_DECODE_BYTE_BUDGET —— 光靠单条上限, 并行路峰值是 1024 倍。
                    //   `None`/单行批: 惰性边解边写 O(1) (逐字等价原逐行路径)。
                    match pool {
                        Some(decode_pool) if batch.rows.len() > 1 => {
                            let mut win_start = 0usize;
                            while win_start < batch.rows.len() {
                                let win_end = next_decode_window_end(
                                    &batch.rows,
                                    win_start,
                                    PAR_DECODE_WINDOW,
                                    PAR_DECODE_BYTE_BUDGET,
                                );
                                let window = &batch.rows[win_start..win_end];
                                win_start = win_end;
                                stats.decode_windows += 1;
                                // install: par_iter 跑在**专用池** (非全局, 不节流 keyscan); collect 保输入序。
                                let decoded: Vec<(DecodedEvent, u64)> = decode_pool.install(|| {
                                    window
                                        .par_iter()
                                        .map(|row| {
                                            decode_row(
                                                row,
                                                account,
                                                &subsource.conv_id,
                                                &snapshot.rel_name,
                                                ingest_time_ms,
                                            )
                                        })
                                        .collect()
                                });
                                for (ev, src_time) in decoded {
                                    write_one!(ev, src_time);
                                }
                            }
                        }
                        _ => {
                            for row in &batch.rows {
                                let (ev, src_time) =
                                    decode_row(row, account, &subsource.conv_id, &snapshot.rel_name, ingest_time_ms);
                                write_one!(ev, src_time);
                            }
                        }
                    }

                    // 批内全落库后才推进水位 (cursor_update 作批末事件 → upsert_watermark), 与 rows 同事务原子。
                    //
                    // `sid_backfilled`: 位置没动、但游标那行的 `server_id` 从 0 变成真值了 —— 也得落一次盘,
                    // 否则这个会话只要不再来新消息, 水位里那个 0 就永远不会被换掉(codex round-7 P1)。
                    // 写完就清标记, 免得每批都写。**只在 `made_progress` 时推进 `cursor`**, 补种那一支
                    // 位置不动(空批的 `next_cursor` 虽然等于入参, 但非空却没前进的批不能拿它顶上)。
                    if made_progress || sid_backfilled {
                        if made_progress {
                            cursor = next_cursor;
                        }
                        sid_backfilled = false;
                        let cev = build_cursor_update_event(account, &etl_source, MESSAGE_KIND, cursor, ingest_time_ms);
                        write_decoded_event_in_tx(&tx, &cev, 0, ingest_time_ms, mode)?;
                        stats.cursor_updates += 1;
                        if emitter.is_some() {
                            pending_emit.push((cev, 0));
                        }
                    }

                    tx.commit()?; // 整批一次提交
                }

                // commit 后批量 emit (archive-first: 落库已 commit 再推送; emitter=None 跳过)。
                // **best-effort** (codex P1): cursor 已随批 commit 推进, emit 失败不可重放 → 失败只 warn 不
                // 阻断 pipeline (落库是真相, emit 是通知; 将来若需可靠投递要 durable outbox 另设计)。
                if let Some(em) = emitter {
                    for (ev, t) in &pending_emit {
                        let push_record = emit(ev, *t, ingest_time_ms, mode);
                        if let Err(e) = em.emit(push_record).await {
                            tracing::warn!(err = %e, "emit 推送失败 (best-effort, 落库已 commit, 不阻断 pipeline)");
                        }
                    }
                }

                // **归档的滚动窗口: 顺手清一次**(独立复审报的 P1 —— 常驻路径只写不清)。
                //
                // 挂在这条 pipeline 上而不是各个命令里: 三条消息路径(全量导入 / `watch` 的 tail-f /
                // 查询侧懒采集)都汇到同一个提交点, 而 tail-f 和懒采集是**长期跑**的形态 ——
                // 只写不清的话归档无限涨(真库上量到 977 万行 / 11.5 GiB, 占整库四分之一)。
                // 一个个命令去补调用就是"按点名清单修", 漏一处又回到原样。
                //
                // ⚠️ **放在 emit 之后**(codex 审出来的 P2): 它是同步删除, 一次最多十万行, 每条 DELETE
                // 还可能撞上连接三十秒的忙等。搁在 emit 前面的话, 数据明明已经提交了, watch 的输出和
                // SSE 那头却要干等它删完 —— 维护活儿不该挡在送达前面。
                //
                // 自带节流(默认五分钟一次), 所以每批都路过也不心疼; 失败只 warn。
                //
                // ⚠️ **这个先后顺序没有守卫盖住, 我试过**: 把这句挪回 emit 前面, 全仓测试一条不红 ——
                // 两种顺序**最终状态完全一样**, 差别只在"数据送到手上要等多久"。要咬住只能靠计时,
                // 而计时测试是会飘的。留这行字给以后动它的人: 挪之前先想清楚为什么要挪。
                crate::storage::prune_archive_throttled(conn, ingest_time_ms);

                // R15 进度: 每 ~5s 打一次 (即时速率 = 区间新增条数 / 区间秒数)。放批末 (commit 后),
                // 故崩溃不影响; 末批不到间隔则由 run 结束的 log_message_stats 汇总兜底 (不重复打)。
                let elapsed = last_log.elapsed();
                if elapsed >= PROGRESS_INTERVAL {
                    let done = stats.messages_decoded + stats.decode_errors;
                    let delta = done.saturating_sub(rows_at_last_log);
                    #[allow(clippy::cast_precision_loss)]
                    let rate = (delta as f64 / elapsed.as_secs_f64()) as u64;
                    tracing::info!(
                        rows_done = done,
                        batches = stats.batches,
                        rate_per_s = rate,
                        workers = effective_workers,
                        "message ingest 进度"
                    );
                    last_log = std::time::Instant::now();
                    rows_at_last_log = done;
                }

                if !has_more {
                    break;
                }
                if !made_progress {
                    // has_more=true 但游标没前进 = source 失约 → 停该子源防死循环 + 计入 stalled (不静默)。
                    // 这里必须 break (每子源至多计一次 stalled); 勿改 continue, 否则 stalled 无限累加。
                    stats.stalled_subsources += 1;
                    tracing::warn!(
                        etl_source = %etl_source,
                        "drain has_more 但游标未前进, 停止该子源 (防死循环, 计入 stalled)"
                    );
                    break;
                }
            }
        }
    }

    Ok(())
}

/// 跑一遍 contact ETL: **全表快照重扫** `contact.db` 的 `contact` 表 → `assemble_contact` →
/// `ContactUpdate` 事件 → sink。`stats.messages_decoded` 复用为【落库的联系人数】。
///
/// ## 为何全表重扫而非增量游标 (代码双审 P0)
/// 联系人是**可变快照实体** (用户改备注/昵称/alias 是【就地改同 rowid 行】), `WHERE rowid > 水位` 的
/// append-only 增量只抓【新增】行, 抓不到【就地更新】→ 漏变更。故 contact **每轮从 rowid 0 重扫全表,
/// 不持久游标、不发 cursor_update 事件** (rowid keyset 仅作【本轮分页】, 不跨轮)。靠去重保证幂等 + 抓变更:
/// 未变联系人重 emit → archive 5 元组撞键 `INSERT OR IGNORE` 忽略; 变更 → content_digest 变 → 新 fingerprint
/// → 新 archive 行 (溯源留痕); L2 `person` 表 `INSERT OR REPLACE` UPSERT 反映当前态。
///
/// ## contact src_create_time = 0
/// ADR-413 §4 指定 contact_update 用源 db `modify_time`, 但该 ADR 标其「弱保证 待字段调研验证」; 全表重扫下
/// 变更由 content_digest 捕获 (不依赖 src_create_time 区分实例) → 用稳定 0 (偏离 §4, 决策记此供双审)。
///
/// # Errors
/// [`PipelineError`] — source/sink 错 (contact 无 etl_state 读, 故无 State 路径)。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (contact_db + emitter, 比 message 多一)
pub async fn run_contact_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    contact_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    // 每轮从 0 重扫全表 (不读 etl_state); rowid 游标仅作本轮分页, 不持久。
    let mut cursor = DrainCursor::default();
    // source 溯源值: 普通 `contact.db` 或陌生人子模式 `contact.db|stranger` (进 person PK 的 source 维,
    // 分行不覆盖)。循环前取一次 (静态 &str, 与后续 &mut source.drain_contacts 无借用冲突)。
    let contact_source = source.contact_source_label().to_string();

    loop {
        let batch = source.drain_contacts(contact_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验 (同 message): 非空批 next_cursor 必 == 本批最大 rowid (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: contact next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            let ctx = ContactContext {
                account_id: account.clone(),
                source: contact_source.clone(),
                source_native_id: contact_anchor(&row.username),
                ingest_time: ingest_time_ms,
            };
            let cu = assemble_contact(row, &ctx); // infallible
                                                  // src_create_time=0 (见 fn doc: 全表重扫 + content_digest 捕获变更, 不需 src_time 区分)。
            archive_and_push(conn, &DecodedEvent::ContactUpdate(cu), 0, ingest_time_ms, mode, emitter).await?;
            stats.messages_decoded += 1;
        }

        // 仅本轮分页前进 (不持久, 无 cursor_update 事件)。
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_contacts has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 session 会话列表 ETL: 全表重扫 SessionTable → 每会话 assemble_session → archive + L2 (session 表).
///
/// 会话状态可变 (unread/summary/sort 随消息变) → **全表重扫 + content_digest 去重** (同 contact;
/// rowid 游标仅本轮分页, 不持久 etl_state / 无 cursor_update 事件)。`session_db` = session.db 路径;
/// `emitter` 推上层 (None=只 archive)。**全程明文 (ADR-427)**: mode 默认 archive_canonical, archive 与推送同 mode。
///
/// # Errors
/// [`PipelineError`] — 任一会话的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (session_db + emitter, 比 message 多一)
pub async fn run_session_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    session_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    // 每轮从 0 重扫全表 (不读 etl_state); rowid 游标仅作本轮分页, 不持久。
    let mut cursor = DrainCursor::default();

    loop {
        let batch = source.drain_sessions(session_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验 (同 contact): 非空批 next_cursor 必 == 本批最大 rowid (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: session next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            let ctx = SessionContext {
                account_id: account.clone(),
                source: "session.db".to_string(),
                source_native_id: session_anchor(&row.username),
                ingest_time: ingest_time_ms,
            };
            let su = assemble_session(row, &ctx); // infallible
                                                  // src_create_time=0 (全表重扫 + content_digest 捕获变更, 不需 src_time 区分; sort_timestamp 进表不进 digest)。
            archive_and_push(conn, &DecodedEvent::SessionUpdate(su), 0, ingest_time_ms, mode, emitter).await?;
            stats.messages_decoded += 1;
        }

        // 仅本轮分页前进 (不持久, 无 cursor_update 事件)。
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_sessions has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 favorite 收藏 ETL: 全表重扫 fav_db_item → 每收藏 assemble_favorite → archive + L2 (favorite 表)。
///
/// 收藏项创建后基本不变 (重打标签 update_time bump) → **全表重扫 + content_digest 去重** (同 session;
/// local_id 游标仅本轮分页, 不持久 etl_state / 无 cursor_update 事件)。`favorite_db` = favorite.db 路径;
/// `emitter` 推上层 (None=只 archive)。**全程明文 (ADR-427)**: mode 默认 archive_canonical, archive 与推送同 mode。
///
/// # Errors
/// [`PipelineError`] — 任一收藏的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (favorite_db + emitter, 同 session)
pub async fn run_favorite_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    favorite_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    // 每轮从 0 重扫全表 (不读 etl_state); local_id 游标仅作本轮分页, 不持久。
    let mut cursor = DrainCursor::default();

    loop {
        let batch = source.drain_favorites(favorite_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验 (同 session): 非空批 next_cursor 必 == 本批最大 local_id (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.local_id).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: favorite next_cursor={} != 本批最大 local_id={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            let ctx = FavoriteContext {
                account_id: account.clone(),
                source: "favorite.db".to_string(),
                source_native_id: favorite_anchor(row.local_id),
                ingest_time: ingest_time_ms,
            };
            let fav = assemble_favorite(row, &ctx); // infallible
                                                    // src_create_time=0 (全表重扫 + content_digest 捕获变更, update_time 进 digest 已够)。
            archive_and_push(
                conn,
                &DecodedEvent::FavoriteCreate(fav),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }

        // 仅本轮分页前进 (不持久, 无 cursor_update 事件)。
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_favorites has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 transfer 转账 ETL: 全表重扫 transferTable → 每转账 assemble_transfer → archive + L2 (transfer 表)。
///
/// 转账随状态推进就地 UPDATE (pay_sub_type/last_update_time 变) → **全表重扫 + content_digest 去重** (同 favorite;
/// rowid 游标仅本轮分页, 不持久 etl_state / 无 cursor_update 事件)。`general_db` = general.db 路径; `emitter` 推
/// 上层 (None=只 archive)。**全程明文 (ADR-427)**: mode 默认 archive_canonical, archive 与推送同 mode。ADR-468。
///
/// # Errors
/// [`PipelineError`] — 任一转账的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (general_db + emitter, 同 favorite)
pub async fn run_transfer_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    general_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    // 每轮从 0 重扫全表 (不读 etl_state); rowid 游标仅作本轮分页, 不持久。transferTable rowid 正常正整数 (非 sns 负 tid)。
    let mut cursor = DrainCursor::default();

    loop {
        let batch = source.drain_transfers(general_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验 (同 favorite): 非空批 next_cursor 必 == 本批最大 rowid (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: transfer next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            let ctx = TransferContext {
                account_id: account.clone(),
                source: "general.db".to_string(),
                source_native_id: transfer_anchor(&row.transfer_id),
                ingest_time: ingest_time_ms,
            };
            let t = assemble_transfer(row, &ctx); // infallible
                                                  // src_create_time=0 (全表重扫 + content_digest 捕获变更, pay_sub_type/begin_transfer_time 进 digest 已够)。
            archive_and_push(conn, &DecodedEvent::TransferCreate(t), 0, ingest_time_ms, mode, emitter).await?;
            stats.messages_decoded += 1;
        }

        // 仅本轮分页前进 (不持久, 无 cursor_update 事件)。
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_transfers has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 red_envelope 红包 ETL: 全表重扫 redEnvelopeTable → 每红包 assemble_red_envelope → archive + L2 (red_envelope 表)。
///
/// 红包随领取状态变就地 UPDATE → **全表重扫 + content_digest 去重** (同 transfer; rowid 游标仅本轮分页, 不持久)。
/// `general_db` = general.db 路径; `emitter` 推上层 (None=只 archive)。**全程明文 (ADR-427)**。ADR-468 件2。
///
/// # Errors
/// [`PipelineError`] — 任一红包的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (general_db + emitter, 同 transfer)
pub async fn run_red_envelope_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    general_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    // 每轮从 0 重扫全表 (不读 etl_state); rowid 游标仅作本轮分页, 不持久 (redEnvelopeTable rowid 正整数)。
    let mut cursor = DrainCursor::default();

    loop {
        let batch = source.drain_red_envelopes(general_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验 (同 transfer): 非空批 next_cursor 必 == 本批最大 rowid (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: red_envelope next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            let ctx = RedEnvelopeContext {
                account_id: account.clone(),
                source: "general.db".to_string(),
                source_native_id: red_envelope_anchor(&row.send_id),
                ingest_time: ingest_time_ms,
            };
            let re = assemble_red_envelope(row, &ctx); // infallible
                                                       // src_create_time=0 (全表重扫 + content_digest 捕获变更, send_id/hb_* 进 digest 已够)。
            archive_and_push(
                conn,
                &DecodedEvent::RedEnvelopeCreate(re),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }

        // 仅本轮分页前进 (不持久, 无 cursor_update 事件)。
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_red_envelopes has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 group_pay 群收款 ETL: 全表重扫 groupPayTable → 每群收款 assemble_group_pay → archive + L2 (group_pay 表)。
///
/// 全表重扫 + content_digest 去重 (同 transfer; rowid 游标仅本轮分页, 不持久)。`general_db` = general.db 路径。ADR-468 件3。
///
/// # Errors
/// [`PipelineError`] — 任一群收款的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (general_db + emitter, 同 transfer)
pub async fn run_group_pay_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    general_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    loop {
        let batch = source.drain_group_pays(general_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: group_pay next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            let ctx = GroupPayContext {
                account_id: account.clone(),
                source: "general.db".to_string(),
                source_native_id: group_pay_anchor(&row.bill_no),
                ingest_time: ingest_time_ms,
            };
            let gp = assemble_group_pay(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::GroupPayCreate(gp),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_group_pays has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 friend_verify 好友验证 ETL: 全表重扫 FMessageTable → 每条 assemble_friend_verify → archive + L2 (friend_verify 表)。
///
/// 全表重扫 + content_digest 去重 (同 transfer; rowid 游标仅本轮分页, 不持久)。`general_db` = general.db 路径。ADR-469。
///
/// # Errors
/// [`PipelineError`] — 任一条的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (general_db + emitter, 同 transfer)
pub async fn run_friend_verify_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    general_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    loop {
        let batch = source.drain_friend_verifies(general_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: friend_verify next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            let ctx = FriendVerifyContext {
                account_id: account.clone(),
                source: "general.db".to_string(),
                source_native_id: friend_verify_anchor(&row.user_name),
                ingest_time: ingest_time_ms,
            };
            let fv = assemble_friend_verify(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::FriendVerifyCreate(fv),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_friend_verifies has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 finder_visit 视频号主页 ETL: 全表重扫 wcfinderuserpage → 每行 assemble_finder → archive + L2
/// (finder_visit 表)。ADR-473。
///
/// **空壳行跳过**: 真库 wcfinderuserpage 928 行中仅 ~492 有访问时刻或视频号昵称, 其余为纯号主 id 无频道数据
/// (extra_buffer proto 全空)。这类空壳行 (name 空 && visit_time==0 && profile_url 空) 无溯源价值 → 跳过 (既不
/// archive 也不落 L2), 计入 `skipped_empty` 日志。号主随其视频号信息就地 UPDATE → 全表重扫 (rowid 游标仅本轮分页,
/// 不落 etl_state; 同 friend_verify)。`general_db` = general.db 路径; `emitter` 推上层 (None=只 archive)。
///
/// # Errors
/// [`PipelineError`] — 任一行的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (general_db + emitter, 同 friend_verify)
pub async fn run_finder_visit_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    general_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    let mut skipped_empty: u64 = 0;
    loop {
        let batch = source.drain_finder_visits(general_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: finder_visit next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            let ctx = FinderContext {
                account_id: account.clone(),
                source: "general.db".to_string(),
                source_native_id: finder_anchor(&row.owner_username),
                ingest_time: ingest_time_ms,
            };
            let fv = assemble_finder(row, &ctx); // infallible
                                                 // 空壳行跳过 (纯号主 id 无频道数据 + 无访问时刻) — 无溯源价值, 不 archive 不落 L2。
                                                 // R16-1: 判据收进 `FinderVisitCreate::is_empty_shell()` —— **热查直读源库时用同一份**
                                                 // (它必须跳掉 ingest 跳过的同一批行, 否则冷热行集分叉)。原地写两遍必漂。
            if fv.is_empty_shell() {
                skipped_empty += 1;
                continue;
            }
            archive_and_push(
                conn,
                &DecodedEvent::FinderVisitCreate(fv),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_finder_visits has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    if skipped_empty > 0 {
        tracing::info!("finder_visit: 跳过 {skipped_empty} 空壳行 (纯号主 id 无频道数据/访问时刻)");
    }
    Ok(stats)
}

/// 跑一遍 moment_feed 朋友圈好友动态索引 ETL: 全表重扫 SnsTopItem_1 → 每行 assemble_moment_feed → archive + L2
/// (moment_feed 表)。ADR-474。
///
/// 好友动态就地更新读状态 → 全表重扫 (rowid 游标仅本轮分页, 不落 etl_state; 同 finder/friend_verify)。**源有重复
/// tid 行** (真库 385K 行 / 301K 去重 tid) → anchor `MomentFeed_<tid>` 相同 → archive 5 元组去重 + L2 upsert 收敛到
/// 一行 (无需 drain 去重)。`sns_db` = sns.db 路径; `emitter` 推上层 (None=只 archive)。
///
/// # Errors
/// [`PipelineError`] — 任一行的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (sns_db + emitter, 同 finder)
pub async fn run_moment_feed_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    sns_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    loop {
        let batch = source.drain_moment_feeds(sns_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: moment_feed next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            let ctx = MomentFeedContext {
                account_id: account.clone(),
                source: "sns.db".to_string(),
                source_native_id: moment_feed_anchor(row.tid),
                ingest_time: ingest_time_ms,
            };
            let mf = assemble_moment_feed(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::MomentFeedCreate(mf),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_moment_feeds has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 sns_notify 朋友圈互动通知 ETL: 全表重扫 SnsMessage_tmp3 → 每行 assemble_sns_notify → archive + L2
/// (sns_notify 表)。照 moment_feed ADR-474。
///
/// 互动通知就地更新读状态 → 全表重扫 (rowid 游标仅本轮分页, 不落 etl_state; 同 moment_feed)。**源可能重复** →
/// anchor `SnsNotify_<comment_id>` 相同 → archive 5 元组去重 + L2 upsert 收敛 (无需 drain 去重)。`sns_db` = sns.db
/// 路径 (与 moment_feed 同库); `emitter` 推上层 (None=只 archive)。
///
/// # Errors
/// [`PipelineError`] — 任一行的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (sns_db + emitter, 同 moment_feed)
pub async fn run_sns_notify_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    sns_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    loop {
        let batch = source.drain_sns_notifies(sns_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: sns_notify next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            let ctx = SnsNotifyContext {
                account_id: account.clone(),
                source: "sns.db".to_string(),
                source_native_id: sns_notify_anchor(row.rowid), // ⚠️ rowid(=local_id 唯一) 作锚点, 非 comment_id(不唯一, 一 id 多通知 → 会塌 688→98)
                ingest_time: ingest_time_ms,
            };
            let sn = assemble_sns_notify(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::SnsNotifyCreate(sn),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_sns_notifies has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 custom_emoticon 自定义表情 ETL: 全表重扫 kNonStoreEmoticonTable → 每行 assemble_emoticon → archive + L2
/// (custom_emoticon 表)。ADR-478。
///
/// 表情静态引用 → 全表重扫 (rowid 游标仅本轮分页, 不落 etl_state; 同 finder)。**空 md5 行跳过** (md5 是身份/anchor,
/// 空则无法定位)。`emoticon_db` = emoticon.db 路径; `emitter` 推上层 (None=只 archive)。
///
/// # Errors
/// [`PipelineError`] — 任一行的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (emoticon_db + emitter, 同 finder)
pub async fn run_emoticon_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    emoticon_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    let mut skipped_empty: u64 = 0;
    loop {
        let batch = source.drain_emoticons(emoticon_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: custom_emoticon next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            // 空 md5 跳过 (md5 是身份/anchor, 空则无法定位)。
            if row.md5.is_empty() {
                skipped_empty += 1;
                continue;
            }
            let ctx = EmoticonContext {
                account_id: account.clone(),
                source: "emoticon.db".to_string(),
                source_native_id: emoticon_anchor(&row.md5),
                ingest_time: ingest_time_ms,
            };
            let e = assemble_emoticon(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::CustomEmoticonCreate(e),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_emoticons has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    if skipped_empty > 0 {
        tracing::info!("custom_emoticon: 跳过 {skipped_empty} 空 md5 行");
    }
    Ok(stats)
}

/// 跑一遍 avatar_image 头像图 ETL: 全表重扫 head_image → 每行 assemble_avatar → archive + L2
/// (avatar_image 表)。ADR-481。
///
/// 全表重扫 (同 emoticon: rowid 游标仅本轮分页, 不落 etl_state)。空 username 跳过 (身份/anchor)。
/// `head_image_db` = head_image.db 路径; `emitter` 推上层 (None=只 archive)。
///
/// # Errors
/// batch_limit=0 / drain 失败 / DbSource 游标失约 / archive 写入失败。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (head_image_db + emitter, 同 emoticon)
pub async fn run_avatar_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    head_image_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    let mut skipped_empty: u64 = 0;
    loop {
        let batch = source.drain_avatars(head_image_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: avatar_image next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            // 空 username 跳过 (username 是身份/anchor, 空则无法定位)。
            if row.username.is_empty() {
                skipped_empty += 1;
                continue;
            }
            let ctx = AvatarContext {
                account_id: account.clone(),
                source: "head_image.db".to_string(),
                source_native_id: avatar_anchor(&row.username),
                ingest_time: ingest_time_ms,
            };
            let a = assemble_avatar(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::AvatarImageCreate(a),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_avatars has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    if skipped_empty > 0 {
        tracing::info!("avatar_image: 跳过 {skipped_empty} 空 username 行");
    }
    Ok(stats)
}

/// 跑一遍 bizchat_user 企微品牌号联系人 ETL: 全表重扫 user_info → 每行 assemble_bizchat → archive + L2
/// (bizchat_user 表)。ADR-482。
///
/// 企微联系人静态引用 → 全表重扫 (rowid 游标仅本轮分页, 不落 etl_state; 同 emoticon)。**空 user_id 行跳过**
/// (user_id 是身份/anchor, 空则无法定位)。`bizchat_db` = bizchat.db 路径; `emitter` 推上层 (None=只 archive)。
///
/// # Errors
/// [`PipelineError`] — 任一行的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (bizchat_db + emitter, 同 emoticon)
pub async fn run_bizchat_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    bizchat_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();
    let mut skipped_empty: u64 = 0;
    loop {
        let batch = source.drain_bizchat_users(bizchat_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: bizchat_user next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);
        for row in &batch.rows {
            // 空 user_id 跳过 (user_id 是身份/anchor, 空则无法定位)。
            if row.user_id.is_empty() {
                skipped_empty += 1;
                continue;
            }
            let ctx = BizChatContext {
                account_id: account.clone(),
                source: "bizchat.db".to_string(),
                source_native_id: bizchat_anchor(&row.user_id),
                ingest_time: ingest_time_ms,
            };
            let b = assemble_bizchat(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::BizChatContactCreate(b),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_bizchat_users has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    if skipped_empty > 0 {
        tracing::info!("bizchat_user: 跳过 {skipped_empty} 空 user_id 行");
    }
    Ok(stats)
}

/// 跑一遍 favorite_tag 收藏标签 ETL: 全表重扫 fav_bind_tag ⋈ fav_tag → 每绑定 assemble_favorite_tag →
/// archive + L2 (favorite_tag 表)。ADR-454 批 B-2。
///
/// 绑定创建后基本不变 → 全表重扫 + content_digest 去重 (同 favorite; rowid 游标仅本轮分页, 不持久)。
/// `favorite_db` = favorite.db 路径; `emitter` 推上层 (None=只 archive)。
///
/// # Errors
/// [`PipelineError`] — 任一绑定的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (favorite_db + emitter, 同 favorite)
pub async fn run_favorite_tag_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    favorite_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let mut cursor = DrainCursor::default();

    loop {
        let batch = source.drain_favorite_tags(favorite_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验: 非空批 next_cursor 必 == 本批最大 rowid (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: favorite_tag next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            let ctx = FavoriteTagContext {
                account_id: account.clone(),
                source: "favorite.db".to_string(),
                // R16-3 codex P1 根治: 锚用 **local id**(未同步 server_id=0 会塌; local 单库唯一, 同本体锚)。
                source_native_id: favorite_tag_anchor(row.tag_local_id, row.fav_local_id),
                ingest_time: ingest_time_ms,
            };
            let ft = assemble_favorite_tag(row, &ctx); // infallible
            archive_and_push(
                conn,
                &DecodedEvent::FavoriteTagCreate(ft),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.messages_decoded += 1;
        }

        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_favorite_tags has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 sns 朋友圈 ETL: 全表重扫 SnsTimeLine → 每动态 assemble_sns → archive + L2 (moment 表)。ADR-467 件1。
///
/// 动态本体创建后 immutable (点赞/评论计数变) → **全表重扫 + content_digest 去重** (同 favorite; tid 游标仅本轮
/// 分页, 不持久 etl_state / 无 cursor_update 事件)。⚠️ **tid = rowid 别名可为负** → 游标从 `i64::MIN` 起
/// (非 `DrainCursor::default()` 的 0, 否则 `tid > 0` 漏全部负 tid)。`sns_db` = sns.db 路径; `emitter` 推上层
/// (None=只 archive)。**全程明文 (ADR-427)**: mode 默认 archive_canonical。
///
/// # Errors
/// [`PipelineError`] — 任一动态的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (sns_db + emitter, 同 favorite)
pub async fn run_sns_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    sns_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    // ⚠️ 从 i64::MIN 起 (非 default 的 0): tid 是有符号 rowid 别名, 约半数为负; `tid > 0` 会漏全部负 tid。
    let mut cursor = DrainCursor {
        local_id: i64::MIN,
        resume_fp: None,
        cursor_ct: None,
        cursor_sid: None,
        prefix_rows: None,
    };

    loop {
        let batch = source.drain_moments(sns_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验 (同 favorite): 非空批 next_cursor 必 == 本批最大 tid (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.tid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: sns next_cursor={} != 本批最大 tid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            let ctx = SnsContext {
                account_id: account.clone(),
                source: "sns.db".to_string(),
                source_native_id: sns_anchor(row.tid),
                ingest_time: ingest_time_ms,
            };
            let sns = assemble_sns(row, &ctx); // infallible
                                               // src_create_time=0 (全表重扫 + content_digest 捕获变更, create_time 进 digest 已够)。
            archive_and_push(conn, &DecodedEvent::SnsCreate(sns), 0, ingest_time_ms, mode, emitter).await?;
            stats.messages_decoded += 1;
        }

        // 仅本轮分页前进 (不持久, 无 cursor_update 事件)。
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_moments has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 跑一遍 chatroom 群成员增量 ETL: 全表重扫 chat_room → 每群 ext_buffer 当前成员 vs L2 在群成员 diff
/// → 产 member_add (新成员) / member_remove (退群) → [`write_decoded_event`] (archive + L2 一事务)。
///
/// **退群闭环 (ADR-426 §1.1)**: 退群成员已离开 ext_buffer, 其明文 `member_wxid` 从 L2 chatroom_member
/// 明文列回读 (add 时存的) — 这正是给 chatroom_member 加明文列的根本目的 (解最初的退群死结)。
///
/// **解析三态保守处理**: `Complete` 才判退群; `Suspicious` 只加不退 (解析可能漏成员, 退群判定不可靠,
/// 漏判退群比误判全退安全); `Invalid` 跳过整群 (不 diff)。
///
/// **本轮范围**: 只 member diff (chatroom_member 表)。群信息表 (chatroom) 不产 —— chatroom_name
/// 缺数据源 (drain_chatrooms 没取群名), 待群名来源确定后单独处理。
///
/// 参数同 [`run_contact_pipeline`]: 全表重扫 (rowid 游标仅本轮分页, 不持久 / 无 cursor_update 事件);
/// `contact_db` = chat_room 表所在库; 退群/进群靠 content_digest + 5 元组幂等去重 (不重复落)。
///
/// **emit 推送语义 (vs message 的差异 — 接消费端前必读)**: `emitter=Some` 时每 add/remove 经
/// [`archive_and_push`] 先 archive commit 再推 record (mode 跟随 archive, 默认明文)。但 chatroom **全表重扫按 L2 状态
/// diff** (非水位重放): `write_decoded_event` commit 即改变 L2 在群状态, 使重跑 diff 跳过该成员 → 若 archive
/// commit 成功但 emit 失败中断, 重跑因 L2 已变不再产该成员事件 = **推送 at-most (该条丢失)**; 区别于 message
/// 的水位重放 (re-drain re-emit = at-least 重推)。故消费端断开/重连须**从 L1 全量补偿** chatroom 成员 (不能靠
/// 重跑补推)。当前 adapter 未接 emitter (恒 None), 风险未激活 (§11.5-7 接消费端时落实补偿)。
///
/// # Errors
/// [`PipelineError`] — 任一群的 source/sink/state 错即整体返 Err。
#[allow(clippy::too_many_arguments)] // pipeline 编排固有多参 (contact_db + emitter, 比 message 多一)
pub async fn run_chatroom_pipeline(
    source: &mut dyn DbSource,
    conn: &mut Connection,
    account: &Wxid,
    contact_db: &std::path::Path,
    mode: PrivacyMode,
    batch_limit: usize,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
) -> Result<PipelineStats, PipelineError> {
    if batch_limit == 0 {
        return Err(PipelineError::Invariant(
            "batch_limit 必须 ≥ 1 (page-by-page 禁全量)".to_string(),
        ));
    }
    let mut stats = PipelineStats::default();
    let account_id_sha = sha256_hex(account.as_str());
    // 每轮从 0 重扫全表 (不读 etl_state); rowid 游标仅作本轮分页, 不持久。
    let mut cursor = DrainCursor::default();

    loop {
        let batch = source.drain_chatrooms(contact_db, &cursor, batch_limit).await?;
        stats.batches += 1;
        let has_more = batch.has_more;
        let next_cursor = batch.next_cursor;
        // source 契约校验 (同 message/contact): 非空批 next_cursor 必 == 本批最大 rowid (防分页跳行漏)。
        let batch_max = batch.rows.iter().map(|r| r.rowid).max();
        if let Some(m) = batch_max {
            if next_cursor.local_id != m {
                return Err(PipelineError::Invariant(format!(
                    "DbSource 失约: chatroom next_cursor={} != 本批最大 rowid={m}",
                    next_cursor.local_id
                )));
            }
        }
        let made_progress = batch_max.is_some_and(|m| m > cursor.local_id);

        for row in &batch.rows {
            diff_one_chatroom(
                conn,
                account,
                &account_id_sha,
                row,
                mode,
                ingest_time_ms,
                emitter,
                &mut stats,
            )
            .await?;
        }

        // 仅本轮分页前进 (不持久, 无 cursor_update 事件)。
        if made_progress {
            cursor = next_cursor;
        }
        if !has_more {
            break;
        }
        if !made_progress {
            stats.stalled_subsources += 1;
            tracing::warn!("drain_chatrooms has_more 但游标未前进, 停止分页 (防死循环, 计入 stalled)");
            break;
        }
    }
    Ok(stats)
}

/// 一个群的成员 diff: ext_buffer 当前成员 vs L2 在群成员 → 产 add/remove 事件落库 (ADR-426 §1.1 闭环).
///
/// - **add**: 本轮 ext_buffer 有 / L2 无 → member_add (member_wxid = ext_buffer 明文 username);
/// - **remove**: L2 有 (is_in_group=1) / 本轮 ext_buffer 无 → member_remove (member_wxid 从 L2 明文回读,
///   source_native_id 复用 L2 行的以命中同 PK); 仅 `allow_remove` (Complete 解析) 时执行。
#[allow(clippy::too_many_arguments)] // conn/account/sha/row/mode/time/emitter/stats — 一群 diff 固有
async fn diff_one_chatroom(
    conn: &mut Connection,
    account: &Wxid,
    account_id_sha: &str,
    row: &ChatroomRawRow,
    mode: PrivacyMode,
    ingest_time_ms: i64,
    emitter: Option<&InProcEmitter>,
    stats: &mut PipelineStats,
) -> Result<(), PipelineError> {
    let parse = parse_roomdata(&row.ext_buffer);
    let member_count = match &parse {
        RoomDataParse::Complete(m) | RoomDataParse::Suspicious(m) => m.len() as i64,
        RoomDataParse::Invalid => 0,
    };
    // ADR-493: 我是否仍在此群 = 账号 wxid 在不在该群 roster。**只 Complete roster 敢判"已退"(false)**;
    // Suspicious/Invalid 可能漏成员 → 保守 true (同下方 member diff "漏判退群比误判全退安全")。
    let is_still_member = match &parse {
        RoomDataParse::Complete(m) => m.iter().any(|mem| mem.username == account.as_str()),
        RoomDataParse::Suspicious(_) | RoomDataParse::Invalid => true,
    };
    let chatroom_id_sha = sha256_hex(&row.chatroom_id);

    // ── 群本身 ChatroomCreate (所有群都落, 即使成员解析坏: 群名/主来自 chat_room 行 + contact join, 人数来自解析) ──
    // 批H: announcement/editor/publish_time 来自 chat_room_info_detail LEFT JOIN (drain 已取); member_count Invalid 时 0。
    let create = assemble_chatroom(
        &ChatroomRow {
            chatroom_id: row.chatroom_id.clone(),
            chatroom_name: row.chatroom_name.clone(),
            chatroom_remark: row.chatroom_remark.clone(),
            announcement: row.announcement.clone(),
            owner_wxid: row.owner.clone(),
            member_count,
            announcement_editor: row.announcement_editor.clone(),
            announcement_publish_time: row.announcement_publish_time,
            xml_announcement: row.xml_announcement.clone(),
            chat_room_status: row.chat_room_status,
            is_still_member,
        },
        &ChatroomContext {
            account_id: account.clone(),
            source: CHATROOM_SOURCE.to_string(),
            source_native_id: chatroom_anchor(&row.chatroom_id),
            ingest_time: ingest_time_ms,
        },
    );
    archive_and_push(
        conn,
        &DecodedEvent::ChatroomCreate(create),
        0,
        ingest_time_ms,
        mode,
        emitter,
    )
    .await?;
    stats.chatrooms_created += 1;

    // ext_buffer 坏 → 群已记, 成员不 diff (避免误判全退)。
    let (current, allow_remove) = match parse {
        RoomDataParse::Complete(m) => (m, true),
        RoomDataParse::Suspicious(m) => (m, false), // 解析可能漏成员 → 只加不退 (漏判退群比误判全退安全)
        RoomDataParse::Invalid => {
            stats.invalid_chatrooms += 1;
            // R11: ext_buffer 解析坏 → 整群跳过成员 diff。debug! 帮诊断"哪些群成员没更新"。群 id 走 sha8。
            tracing::debug!(
                chatroom = %crate::key_provider::sha8(row.chatroom_id.as_bytes()),
                "群 ext_buffer 解析 Invalid, 跳过成员 diff"
            );
            return Ok(()); // 整群跳过 (不 diff, 避免误判全退)
        }
    };
    // diff 用 wxid_sha 做集合键 (稳定, _sha 是 PK 列必有; 明文仅作 add/remove payload — codex r1 稳健性)。
    let current_with_sha: Vec<(&RoomMember, String)> = current.iter().map(|m| (m, sha256_hex(&m.username))).collect();
    let current_shas: std::collections::HashSet<&str> = current_with_sha.iter().map(|(_, sha)| sha.as_str()).collect();
    // L2 上一轮在群成员 (同 source 单库; member_wxid 明文 = 退群回读源)。
    let l2_members =
        crate::storage::query_chatroom_members_in_group(conn, account_id_sha, CHATROOM_SOURCE, &chatroom_id_sha)?;
    let l2_shas: std::collections::HashSet<&str> = l2_members.iter().map(|l2| l2.member_wxid_sha.as_str()).collect();

    // ── add: ext_buffer 有 / L2 无 (sha 键) → member_add (upsert 幂等, 已在群者跳过省一次写) ──
    for (m, member_wxid_sha) in &current_with_sha {
        if l2_shas.contains(member_wxid_sha.as_str()) {
            continue;
        }
        // 第八批 role: 群主(chat_room.owner 列)优先, 再 admin(成员 field3 flags & 2048), 其余 member。
        // (role 在此 add 时定, 同 display_name — pipeline 对已在群成员跳过重发, 不刷新已有 role; 升管理员待再入群或后续全刷。)
        let role = if row.owner.as_deref() == Some(m.username.as_str()) {
            "owner"
        } else if m.is_admin {
            "admin"
        } else {
            "member"
        };
        let add = ChatroomMemberAdd {
            provenance: Provenance {
                account_id: account.clone(),
                source: CHATROOM_SOURCE.to_string(),
                source_native_id: member_anchor(&chatroom_id_sha, member_wxid_sha),
                event_type: EventType::ChatroomUpdate,
                event_action: EventAction::MemberAdd,
                event_seq: 0, // emit 层 compute_event_seq 重算, 占位
                ingest_time: ingest_time_ms,
            },
            chatroom_id: row.chatroom_id.clone(),
            member_wxid: m.username.clone(),
            display_name: m.group_nick.clone(),
            joined_at: None, // RoomMember 无加入时间 (ext_buffer 不带)
            role: role.to_string(),
            invited_by: m.invited_by.clone(),
        };
        archive_and_push(
            conn,
            &DecodedEvent::ChatroomMemberAdd(add),
            0,
            ingest_time_ms,
            mode,
            emitter,
        )
        .await?;
        stats.members_added += 1;
    }

    // ── remove: L2 有 / ext_buffer 无 (sha 键) → member_remove (member_wxid L2 明文回读, 闭 §1.1 死结) ──
    if allow_remove {
        for l2 in &l2_members {
            if current_shas.contains(l2.member_wxid_sha.as_str()) {
                continue; // 仍在群
            }
            let remove = ChatroomMemberRemove {
                provenance: Provenance {
                    account_id: account.clone(),
                    source: CHATROOM_SOURCE.to_string(),
                    source_native_id: l2.source_native_id.clone(), // 复用 L2 行的 → mark_left 命中同 PK
                    event_type: EventType::ChatroomUpdate,
                    event_action: EventAction::MemberRemove,
                    event_seq: 0,
                    ingest_time: ingest_time_ms,
                },
                chatroom_id: row.chatroom_id.clone(),
                member_wxid: l2.member_wxid.clone(), // ← 明文回读 (退群成员已离 ext_buffer)
                left_at: Some(ingest_time_ms),       // 退群检测时刻 (ext_buffer 无真实退群时间)
            };
            archive_and_push(
                conn,
                &DecodedEvent::ChatroomMemberRemove(remove),
                0,
                ingest_time_ms,
                mode,
                emitter,
            )
            .await?;
            stats.members_removed += 1;
        }
    }

    Ok(())
}

/// 组 cursor_update 事件 (批末推进水位; provenance.source = etl_state 键, 跟 project_watermark 一致)。
fn build_cursor_update_event(
    account: &Wxid,
    etl_source: &str,
    kind: &str,
    cursor: DrainCursor,
    ingest_time_ms: i64,
) -> DecodedEvent {
    let watermark_value = cursor.to_watermark_value();
    let source_native_id = cursor_anchor(etl_source, kind, &watermark_value);
    DecodedEvent::SystemCursorUpdate(SystemCursorUpdate {
        provenance: Provenance {
            account_id: account.clone(),
            source: etl_source.to_string(),
            source_native_id,
            event_type: EventType::SystemEvent,
            event_action: EventAction::CursorUpdate,
            event_seq: 0, // emit 层 compute_event_seq 重算, 占位
            ingest_time: ingest_time_ms,
        },
        kind: kind.to_string(),
        watermark_key: DrainCursor::KEY_DESC.to_string(),
        watermark_value,
        last_update: ingest_time_ms,
    })
}

/// 组 decode 失败的 SystemError 事件 (archive 溯源; 错误信息走 DecoderError Display 已脱敏)。
fn build_decode_error_event(
    account: &Wxid,
    db_rel: &str,
    row_native_id: &str,
    err: &DecoderError,
    ingest_time_ms: i64,
) -> DecodedEvent {
    let error_code = decoder_error_code(err);
    let source_native_id = error_anchor(error_code, row_native_id);
    DecodedEvent::SystemError(SystemError {
        provenance: Provenance {
            account_id: account.clone(),
            source: db_rel.to_string(),
            source_native_id,
            event_type: EventType::SystemEvent,
            event_action: EventAction::Error,
            event_seq: 0,
            ingest_time: ingest_time_ms,
        },
        error_code: error_code.to_string(),
        // DecoderError Display 已脱敏 (ZstdFail 无值 / UnresolvedSender 仅 local_id / InvalidSender sha8)。
        error_message: err.to_string(),
        context_json: None,
        // 失败行锚点 (Msg_<md5_hex(conv)>:<local_id>; conv 已 md5, 非 PII) — 定位用。
        occurred_at_canonical: row_native_id.to_string(),
    })
}

/// DecoderError → 稳定错误码 (元数据; 进 source_native_id error_anchor + payload error_code)。
fn decoder_error_code(err: &DecoderError) -> &'static str {
    match err {
        DecoderError::ZstdFail => "ZSTD_FAIL",
        // ⚠️ historical arm — 2026-07-01 起 assemble_message 不再产 sender 类错误 (改占位保留 SENDER_UNKNOWN);
        // 保留 arm 供枚举穷尽 + 未来严格模式 (见 DecoderError 变体注释). 当前 message 路径走不到这两支。
        DecoderError::UnresolvedSender { .. } => "UNRESOLVED_SENDER",
        DecoderError::InvalidSender { .. } => "INVALID_SENDER",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use async_trait::async_trait;

    use super::*;
    use crate::decoder::{ContactRow, FavoriteRow, FavoriteTagRow, MessageRow, SessionRow, SnsRow, TransferRow};
    use crate::source::{
        AvatarBatch, BizChatUserBatch, ChatroomBatch, ContactBatch, DbSnapshot, DbSourceError, EmoticonBatch,
        FMessageBatch, FavoriteBatch, FavoriteTagBatch, FinderBatch, GroupPayBatch, MessageBatch, MessageSubsource,
        MomentBatch, MomentFeedBatch, RedEnvelopeBatch, SessionBatch, SnsNotifyBatch, TransferBatch,
    };

    // ── L1 库 + 全表 (照 sink.rs setup) ──
    fn setup_conn() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::storage::open(&dir.path().join("l1.db")).unwrap();
        crate::storage::init_archive_table(&conn).unwrap();
        crate::storage::init_message_table(&conn).unwrap();
        crate::storage::init_person_table(&conn).unwrap();
        crate::storage::init_person_alias_table(&conn).unwrap();
        crate::storage::init_chatroom_table(&conn).unwrap();
        crate::storage::init_chatroom_member_table(&conn).unwrap();
        crate::storage::init_session_table(&conn).unwrap();
        crate::storage::init_favorite_table(&conn).unwrap();
        crate::storage::init_favorite_media_table(&conn).unwrap();
        crate::storage::init_favorite_tag_table(&conn).unwrap();
        crate::storage::init_message_app_table(&conn).unwrap();
        crate::storage::init_message_media_table(&conn).unwrap();
        crate::storage::init_message_location_table(&conn).unwrap();
        crate::storage::init_message_call_table(&conn).unwrap();
        crate::storage::init_message_hongbao_claim_table(&conn).unwrap();
        crate::storage::init_message_card_table(&conn).unwrap();
        crate::storage::init_message_forward_item_table(&conn).unwrap();
        crate::storage::init_message_mention_table(&conn).unwrap();
        crate::storage::init_chatroom_member_event_table(&conn).unwrap();
        crate::storage::init_group_pay_member_table(&conn).unwrap();
        crate::storage::init_moment_table(&conn).unwrap();
        crate::storage::init_moment_media_table(&conn).unwrap();
        crate::storage::init_moment_interaction_table(&conn).unwrap();
        crate::storage::init_transfer_table(&conn).unwrap();
        crate::state::init_etl_state_table(&conn).unwrap();
        (dir, conn)
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    // ── mock DbSource (1 库 1 子源; rows 按 local_id keyset 分页, 复刻真 DbSource 语义) ──
    #[derive(Clone)]
    struct MockRow {
        local_id: i64,
        content: Vec<u8>,
        sender: Option<String>,
    }

    struct MockSource {
        rel_name: String,
        subsource: MessageSubsource,
        rows: Vec<MockRow>,
        /// 覆盖 next_cursor.local_id (测 P1 失约: source 跳大游标)。None = 正常算 (本批最大)。
        force_next_cursor: Option<i64>,
        /// 覆盖 has_more (测 stalled: 永远 has_more)。None = 正常算 (拿满 limit)。
        force_has_more: Option<bool>,
    }

    impl MockSource {
        fn snapshot(&self) -> DbSnapshot {
            DbSnapshot {
                db_id: format!("{}|{}", crate::key_provider::sha8(b"wxid_self"), self.rel_name),
                wxid: Wxid::try_new("wxid_self").unwrap(),
                kind: "message".into(),
                sub_db_path: PathBuf::from("/wx/message_0.db"),
                rel_name: self.rel_name.clone(),
                mtime_ms: 0,
                size_bytes: 0,
            }
        }
    }

    fn to_message_row(r: &MockRow) -> MessageRow {
        MessageRow {
            local_id: r.local_id,
            server_id: 9000 + r.local_id,
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            local_type: 1, // TEXT
            sort_seq: 1_700_000_000_000 + r.local_id,
            create_time: 1_700_000_000,
            status: 4, // 已接收
            message_content: r.content.clone(),
            msg_source: Vec::new(),
            sender_username: r.sender.clone(),
        }
    }

    #[async_trait]
    impl DbSource for MockSource {
        async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError> {
            Ok(vec![self.snapshot()])
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
            let mut hit: Vec<&MockRow> = self.rows.iter().filter(|r| r.local_id > since.local_id).collect();
            hit.sort_by_key(|r| r.local_id);
            let page: Vec<MessageRow> = hit.iter().take(limit).map(|r| to_message_row(r)).collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |m| m.local_id);
            // 复刻真 DbSource: has_more = 拿满 limit (不预知是否还有)。force_* 用于测异常 source。
            let has_more = self.force_has_more.unwrap_or(limit > 0 && fetched == limit);
            let next_local = self.force_next_cursor.unwrap_or(next);
            Ok(MessageBatch {
                rows: page,
                next_cursor: DrainCursor {
                    local_id: next_local,
                    resume_fp: None,
                    cursor_ct: None,
                    cursor_sid: None,
                    prefix_rows: None,
                },
                has_more,
            })
        }
        async fn drain_contacts(
            &mut self,
            _contact_db: &std::path::Path,
            since: &DrainCursor,
            _limit: usize,
        ) -> Result<ContactBatch, DbSourceError> {
            // 消息 mock 不产联系人 (contact pipeline 用独立 ContactMockSource)。
            Ok(ContactBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_chatrooms(
            &mut self,
            _contact_db: &std::path::Path,
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
            _session_db: &std::path::Path,
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
            _favorite_db: &std::path::Path,
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
            _favorite_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _emoticon_db: &std::path::Path,
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
            _head_image_db: &std::path::Path,
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
            _bizchat_db: &std::path::Path,
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

    fn single_chat_source(rows: Vec<MockRow>) -> MockSource {
        MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_0123456789abcdef0123456789abcdef".into(),
                conv_id: "wxid_friend".into(),
            },
            rows,
            force_next_cursor: None,
            force_has_more: None,
        }
    }

    fn acct() -> Wxid {
        Wxid::try_new("wxid_self").unwrap()
    }

    fn etl_value(conn: &Connection, source: &str) -> Option<String> {
        crate::state::get_watermark(conn, &sha256_hex("wxid_self"), source, MESSAGE_KIND)
            .unwrap()
            .map(|w| w.watermark_value)
    }

    // ── R19 选择性采集: run_message_body drain 前会话过滤 ──
    // 单会话 mock 足够测两分支: 白名单放"别的会话"→本会话跳过; 放本会话→命中。conv_id="wxid_friend"(single_chat_source)。

    const MSG_ETL_KEY: &str = "message_0.db|Msg_0123456789abcdef0123456789abcdef";

    /// R19: 会话不在 capture_targets 白名单 → drain 前整表跳过 (0 落库, skipped=1, **水位不动**)。
    #[tokio::test]
    async fn r19_skip_conv_not_in_whitelist() {
        let (_d, mut conn) = setup_conn();
        crate::capture::init_capture_targets(&conn).unwrap();
        // 只圈别的会话 → 本 source 的 "wxid_friend" 不在白名单。
        crate::capture::add_capture_target(&conn, &sha256_hex("wxid_self"), "wxid_other", None, 1000).unwrap();
        let mut src = single_chat_source(vec![
            MockRow {
                local_id: 1,
                content: b"a".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 2,
                content: b"b".to_vec(),
                sender: None,
            },
        ]);
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 0, "非命中会话不该落库");
        assert_eq!(stats.skipped_subsources, 1, "该子源被跳过");
        assert_eq!(count(&conn, "message"), 0, "message 表空");
        assert_eq!(etl_value(&conn, MSG_ETL_KEY), None, "跳过不推水位 (补历史前提)");
    }

    /// R19: 会话在白名单 → 正常采 (逐字等价无过滤路径)。
    #[tokio::test]
    async fn r19_capture_conv_in_whitelist() {
        let (_d, mut conn) = setup_conn();
        crate::capture::init_capture_targets(&conn).unwrap();
        crate::capture::add_capture_target(&conn, &sha256_hex("wxid_self"), "wxid_friend", None, 1000).unwrap();
        let mut src = single_chat_source(vec![
            MockRow {
                local_id: 1,
                content: b"a".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 2,
                content: b"b".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 3,
                content: b"c".to_vec(),
                sender: None,
            },
        ]);
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 3, "命中会话全采");
        assert_eq!(stats.skipped_subsources, 0);
        assert_eq!(
            etl_value(&conn, MSG_ETL_KEY).as_deref(),
            Some("3"),
            "命中正常推水位到 3"
        );
    }

    /// R19 D1: capture_targets 表存在但空 → 全采 (没圈零成本; 与无表同效)。
    #[tokio::test]
    async fn r19_empty_table_captures_all() {
        let (_d, mut conn) = setup_conn();
        crate::capture::init_capture_targets(&conn).unwrap(); // 表在但一条没圈
        let mut src = single_chat_source(vec![MockRow {
            local_id: 1,
            content: b"a".to_vec(),
            sender: None,
        }]);
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 1, "空白名单 = 全采");
        assert_eq!(stats.skipped_subsources, 0);
    }

    /// R19 D5: 先跳过 (水位不动) → 后加白名单 → 从 cursor 0 重 drain 补全历史一条不漏。
    #[tokio::test]
    async fn r19_backfill_history_after_add() {
        let (_d, mut conn) = setup_conn();
        crate::capture::init_capture_targets(&conn).unwrap();
        let sha = sha256_hex("wxid_self");
        crate::capture::add_capture_target(&conn, &sha, "wxid_other", None, 1000).unwrap(); // run1 只圈别的
        let mut src = single_chat_source(vec![
            MockRow {
                local_id: 1,
                content: b"a".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 2,
                content: b"b".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 3,
                content: b"c".to_vec(),
                sender: None,
            },
        ]);
        let s1 = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(s1.messages_decoded, 0);
        assert_eq!(s1.skipped_subsources, 1);
        // run2: 加圈 "wxid_friend" → 水位仍 0 (run1 没推) → 从头 drain 3 条全补。
        crate::capture::add_capture_target(&conn, &sha, "wxid_friend", None, 2000).unwrap();
        let s2 = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 2000, None)
            .await
            .unwrap();
        assert_eq!(s2.messages_decoded, 3, "补历史: 从 cursor 0 重 drain 全 3 条");
        assert_eq!(count(&conn, "message"), 3);
    }

    /// happy path: 3 行单聊 → 3 message + 1 cursor; etl_state 水位=3.
    #[tokio::test]
    async fn happy_path_drains_and_advances() {
        let (_d, mut conn) = setup_conn();
        let mut src = single_chat_source(vec![
            MockRow {
                local_id: 1,
                content: b"a".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 2,
                content: b"b".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 3,
                content: b"c".to_vec(),
                sender: None,
            },
        ]);
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 3);
        assert_eq!(stats.decode_errors, 0);
        assert_eq!(stats.cursor_updates, 1, "1 批 (3<limit10) → 1 次推进");
        assert_eq!(stats.dbs, 1);
        assert_eq!(stats.subsources, 1);
        assert_eq!(count(&conn, "message"), 3, "L2 message 3 行");
        assert_eq!(count(&conn, "raw_payload_archive"), 4, "3 msg + 1 cursor");
        assert_eq!(
            etl_value(&conn, "message_0.db|Msg_0123456789abcdef0123456789abcdef").as_deref(),
            Some("3")
        );
    }

    /// R15 digest: 哈希 `table` **每行每列** (覆盖全部 SQLite 存储类), 按 `order_by` 排序 → sha256。
    /// 冷热两跑同摘要 ⟺ 该表逐字相同。archive 按 `id`(插入序) 捕获**乱序** + 内容; message 按 PK 捕获**全列**
    /// (含 L2-only origin/upload/download_status 等) 内容差异 —— 审 codex: 不能只比 archive 4 列。
    fn table_digest(conn: &Connection, table: &str, order_by: &str) -> String {
        use rusqlite::types::ValueRef;
        use sha2::{Digest, Sha256};
        let sql = format!("SELECT * FROM {table} ORDER BY {order_by}");
        let mut stmt = conn.prepare(&sql).unwrap();
        let ncol = stmt.column_count();
        let mut hasher = Sha256::new();
        let mut rows = stmt.query([]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            for i in 0..ncol {
                // 每列: 类型标签 + 值 (分隔 \x1f 防跨列歧义)。全 5 类 SQLite 存储类穷举。
                match r.get_ref(i).unwrap() {
                    ValueRef::Null => hasher.update([0u8]),
                    ValueRef::Integer(v) => {
                        hasher.update([1u8]);
                        hasher.update(v.to_le_bytes());
                    }
                    ValueRef::Real(v) => {
                        hasher.update([2u8]);
                        hasher.update(v.to_le_bytes());
                    }
                    ValueRef::Text(v) => {
                        hasher.update([3u8]);
                        hasher.update(v);
                    }
                    ValueRef::Blob(v) => {
                        hasher.update([4u8]);
                        hasher.update(v);
                    }
                }
                hasher.update([0x1f]);
            }
            hasher.update([0x1e]); // 行分隔
        }
        hex::encode(hasher.finalize())
    }

    /// R15 **核心验收**: 并行 (`workers=8`) 全量 ingest 结果**逐字 == 串行** (`workers=1`) —— 不丢/不重/不乱水位。
    /// **2500 行 / batch_limit=1300** → 2 批 (1300+1200), **每批 >PAR_DECODE_WINDOW(1024) → 每批 2 分窗** →
    /// 同时覆盖: 跨批水位推进 + 每批多窗并行 decode + **跨窗保序** (窗1024|窗剩); 两跑独立库全表 digest 比对相等。
    #[tokio::test]
    async fn r15_parallel_ingest_equals_serial() {
        // 2500 行, content 各异 (payload 区分, 使 digest 对内容/序敏感)。>1024 使并行分窗真跑多窗。
        let rows: Vec<MockRow> = (1..=2500)
            .map(|i| MockRow {
                local_id: i,
                content: format!("msg-body-{i}-内容").into_bytes(),
                sender: None,
            })
            .collect();

        // 串行基线 (workers=1)。
        let (_d1, mut conn1) = setup_conn();
        let mut src1 = single_chat_source(rows.clone());
        let s1 = run_message_pipeline_jobs(
            &mut src1,
            &mut conn1,
            &acct(),
            PrivacyMode::default_sha(),
            1300,
            5000,
            None,
            1,
        )
        .await
        .unwrap();

        // 并行 (workers=8): 逻辑核≥2 时建 min(8,核) 线程专用池 = 真并发 (所有真实 CI 机 ≥2 核); 单核机 effective
        // 钳到 1 → 退串行 (无真并发)。**确定性不依赖线程数**: collect 保序契约在任意池大小成立, 单核只是不"暴露"
        // 竞态 (decode_row 纯 → 本无竞态)。真并发覆盖靠多核 CI + 真库对拍 (审 Round-A P3-3: 不再过 claim 单核多线程)。
        let (_d8, mut conn8) = setup_conn();
        let mut src8 = single_chat_source(rows.clone());
        let s8 = run_message_pipeline_jobs(
            &mut src8,
            &mut conn8,
            &acct(),
            PrivacyMode::default_sha(),
            1300,
            5000,
            None,
            8,
        )
        .await
        .unwrap();

        // 1) stats 逐字段相等 (解码数/错误数/批数/游标推进/水位 stalled)。
        assert_eq!(s1.messages_decoded, 2500);
        assert_eq!(s1.messages_decoded, s8.messages_decoded, "并行解码数 != 串行");
        assert_eq!(s1.decode_errors, s8.decode_errors, "并行错误数 != 串行");
        assert_eq!(
            s1.cursor_updates, s8.cursor_updates,
            "并行游标推进次数 != 串行 (水位乱)"
        );
        assert_eq!(s1.batches, s8.batches, "批数不一致");
        // 2) 行数相等 (不丢/不重)。
        assert_eq!(count(&conn1, "message"), 2500);
        assert_eq!(
            count(&conn1, "message"),
            count(&conn8, "message"),
            "message 行数并行 != 串行"
        );
        assert_eq!(
            count(&conn1, "raw_payload_archive"),
            count(&conn8, "raw_payload_archive"),
            "archive 行数并行 != 串行"
        );
        // 3) 水位值相等 (最终 cursor 一致)。
        let key = "message_0.db|Msg_0123456789abcdef0123456789abcdef";
        assert_eq!(etl_value(&conn1, key), etl_value(&conn8, key), "最终水位并行 != 串行");
        // 4) **全表逐字相等** (审 codex: 比 archive 插入序 + message 全列, 非只 archive 4 列)。
        //    archive 按 id(插入序) → 捕获乱序 + 内容; message 按 PK → 捕获全列内容 (含 L2-only
        //    origin_source/upload_status/download_status 等只在 L2 表的字段)。
        let arch1 = table_digest(&conn1, "raw_payload_archive", "id");
        let arch8 = table_digest(&conn8, "raw_payload_archive", "id");
        assert_eq!(arch1, arch8, "并行 archive 全列 digest != 串行 (乱序/丢/重/内容)");
        let msg1 = table_digest(&conn1, "message", "source, source_native_id");
        let msg8 = table_digest(&conn8, "message", "source, source_native_id");
        assert_eq!(msg1, msg8, "并行 message L2 表全列 digest != 串行 (含 L2-only 列)");

        // 5) **顺序敏感性自证** (§审查增强规则4 负向): 若 digest 忽略插入序则上面 archive assert 恒真 = 空转。
        //    id ASC 与 id DESC digest 必不同 (200 行内容各异) → 证 digest 真捕获插入序 → arch1==arch8 有意义。
        let arch1_desc = table_digest(&conn1, "raw_payload_archive", "id DESC");
        assert_ne!(
            arch1, arch1_desc,
            "archive digest 对插入序不敏感 = 空转守卫失败 (乱序检不出)"
        );
    }

    /// R15 (审 Round-A P3-4): workers **边界值** —— 0(库调用者误传)当串行不 panic; 极大值(如 10_000)钳到
    /// 逻辑核数不爆线程; 两者结果均 == 串行基线 (archive 全列 digest 相等)。
    #[tokio::test]
    async fn r15_workers_edge_equals_serial() {
        let rows: Vec<MockRow> = (1..=50)
            .map(|i| MockRow {
                local_id: i,
                content: format!("edge-{i}").into_bytes(),
                sender: None,
            })
            .collect();
        // digest 在 async block 内算 (conn + tempdir _d 仍活), 返 owned String。
        let run = |w: usize| {
            let rows = rows.clone();
            async move {
                let (_d, mut conn) = setup_conn();
                let mut src = single_chat_source(rows);
                run_message_pipeline_jobs(
                    &mut src,
                    &mut conn,
                    &acct(),
                    PrivacyMode::default_sha(),
                    8,
                    1000,
                    None,
                    w,
                )
                .await
                .unwrap();
                table_digest(&conn, "raw_payload_archive", "id")
            }
        };
        let base = run(1).await; // 串行基线
        let w0 = run(0).await; // workers=0 → effective 1 → 串行, 不 panic
        let wbig = run(10_000).await; // 极大 → 钳到核数 (或单核退串行), 不爆线程
        assert_eq!(base, w0, "workers=0 结果 != 串行 (应当串行不 panic)");
        assert_eq!(base, wbig, "workers=10000 (钳制后) 结果 != 串行");
    }

    /// R15 `--jobs` 默认: 恒 ≥ 1 (绝不 0 —— 0 会致 rayon panic / 串并闸失效), 且 ≤ 逻辑核数 (50% 上界)。
    #[test]
    fn r15_default_ingest_jobs_at_least_one() {
        let j = default_ingest_jobs();
        assert!(j >= 1, "默认并行度必 ≥ 1, 实际 {j}");
        if let Ok(n) = std::thread::available_parallelism() {
            assert!(j <= n.get(), "默认并行度 {j} 不应超逻辑核数 {}", n.get());
            // 50% 语义: 多核机上应 == n/2 (min 1); 单核 == 1。
            assert_eq!(j, (n.get() / 2).max(1), "默认应为逻辑核 50% (min 1)");
        }
    }

    /// keyset 分页: 3 行 limit=2 → 2 批, cursor 推进 2 次, 水位=3.
    #[tokio::test]
    async fn paginates_by_keyset() {
        let (_d, mut conn) = setup_conn();
        let mut src = single_chat_source(vec![
            MockRow {
                local_id: 1,
                content: b"a".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 2,
                content: b"b".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 3,
                content: b"c".to_vec(),
                sender: None,
            },
        ]);
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 2, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 3);
        // batch1: 1,2 (满 limit → has_more); batch2: 3 (不满 → 止); 各推进 1 次 = 2.
        assert_eq!(stats.cursor_updates, 2);
        assert!(stats.batches >= 2);
        assert_eq!(
            etl_value(&conn, "message_0.db|Msg_0123456789abcdef0123456789abcdef").as_deref(),
            Some("3")
        );
    }

    /// 单条标坏不阻塞: 群聊 2 行, 1 行正文 zstd 帧损坏 → SystemError 事件 + 计数, 另 1 行正常落 L2.
    /// (2026-07-01: sender 无解已改占位保留、不再算 error; 真正丢弃路径只剩 zstd 坏帧 → 本测改用坏帧触发.)
    #[tokio::test]
    async fn decode_error_emits_system_error_and_continues() {
        let (_d, mut conn) = setup_conn();
        // zstd 魔数 + 垃圾帧体 → decode_message_content ZstdFail (content.rs corrupt_zstd_frame 同款).
        let corrupt_zstd = {
            let mut b = vec![0x28u8, 0xB5, 0x2F, 0xFD];
            b.extend_from_slice(&[0xff, 0x00, 0x12, 0x34, 0x56]);
            b
        };
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                conv_id: "room123@chatroom".into(), // 群聊
            },
            rows: vec![
                // 好行: 群聊 + Name2Id sender 有解 → Ok.
                MockRow {
                    local_id: 1,
                    content: b"hi".to_vec(),
                    sender: Some("wxid_member".into()),
                },
                // 坏行: 正文 zstd 帧损坏 → ZstdFail (sender 有解, 排除占位路径, 纯测坏帧).
                MockRow {
                    local_id: 2,
                    content: corrupt_zstd,
                    sender: Some("wxid_member".into()),
                },
            ],
            force_next_cursor: None,
            force_has_more: None,
        };
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 1, "1 行好");
        assert_eq!(stats.decode_errors, 1, "1 行坏 (zstd) → SystemError");
        assert_eq!(count(&conn, "message"), 1, "L2 只好行");
        // archive: 1 msg + 1 error + 1 cursor = 3.
        assert_eq!(count(&conn, "raw_payload_archive"), 3);
        // 游标仍推进到 2 (坏行也算 drain 过, 不重扫)。
        assert_eq!(
            etl_value(&conn, "message_0.db|Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").as_deref(),
            Some("2")
        );
    }

    /// R9 复审#1 回归: **增量 watch (run_message_pipeline_incremental) 靠触发器逐条维护 FTS, 全程不 drop/重建**。
    /// batch 路径每 pass drop 触发器 + rebuild_message_fts (全量) → 对 watch 每批全量重建 = 百万级库卡死。此测跑两个
    /// 增量 pass, 断言: 每 pass 后触发器仍在岗 (batch 会 drop, 增量不碰) + 两批消息都经触发器进 message_fts。
    #[tokio::test]
    async fn incremental_watch_keeps_triggers_and_maintains_fts() {
        let (_d, mut conn) = setup_conn();
        crate::storage::build_message_fts_incremental(&mut conn).unwrap();
        assert!(crate::storage::message_fts_triggers_exist(&conn), "build 后触发器在岗");
        for lid in [1_i64, 2] {
            let mut src = single_chat_source(vec![MockRow {
                local_id: lid,
                content: format!("m{lid}").into_bytes(),
                sender: None,
            }]);
            run_message_pipeline_incremental(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
                .await
                .unwrap();
            assert!(
                crate::storage::message_fts_triggers_exist(&conn),
                "增量 pass {lid} 后触发器仍在岗 (未被 drop+rebuild)"
            );
        }
        assert_eq!(count(&conn, "message"), 2, "两批增量都落库");
        let fts_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts_rows, 2, "触发器逐条把两条增量消息进 FTS (非全量重建)");
    }

    /// **窗口里装的是 `String` 不是解压出来的字节 —— 非法 UTF-8 会翻三倍**(独立复审 651ed5c 的 P2)。
    ///
    /// 解压完还要过 `String::from_utf8_lossy`, 每个非法字节换成一个 3 字节的 U+FFFD。
    /// 估值只按解压字节算的话, 1 MiB 全 0xFF 的内容估成 1 MiB、实际在飞 3 MiB, 按 256 MiB 预算
    /// 就是 768 MiB。跟"漏算 msg_source"是同一种形状: **估的东西和真正留在内存里的不是一回事**。
    #[test]
    fn window_budget_accounts_for_utf8_lossy_inflation() {
        // 帧头老老实实声明 1 MiB, 内容全是非法 UTF-8 字节。
        let all_invalid = zstd::bulk::compress(&vec![0xFFu8; 1024 * 1024], 3).expect("压");
        let ub = crate::decoder::content::decoded_size_upper_bound(&all_invalid);
        assert_eq!(ub, 1024 * 1024, "夹具前提: 帧头声明 1 MiB");
        // 实际解出来的 String 长度是 3 倍 —— 这一条钉死"放大真的存在", 不是我拍脑袋乘的。
        let decoded = crate::decoder::content::decode_message_content(&all_invalid).expect("解");
        assert_eq!(
            decoded.len(),
            3 * 1024 * 1024,
            "全非法字节 → U+FFFD 每个 3 字节, 长度正好 3 倍"
        );
        // 而**占的内存不止长度**(codex 审 656477c 的 P2): `into_owned()` 出来的 String 带富余容量,
        // 当前标准库上约 4 倍。预算管的是内存, 所以系数必须盖得住实测容量。
        assert!(
            super::UTF8_LOSSY_WORST_CASE * 1024 * 1024 >= decoded.capacity(),
            "预算系数得盖住实际容量 {} (长度 {}), 现在系数是 {}",
            decoded.capacity(),
            decoded.len(),
            super::UTF8_LOSSY_WORST_CASE
        );

        let row = |content: Vec<u8>| MessageRow {
            local_id: 1,
            server_id: 1,
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            local_type: 1,
            sort_seq: 0,
            create_time: 0,
            status: 4,
            message_content: content,
            msg_source: Vec::new(),
            sender_username: None,
        };
        let rows: Vec<MessageRow> = (0..4).map(|_| row(all_invalid.clone())).collect();

        // 预算 = 2 行的实际占用。不乘放大系数的话, 同样的预算会以为装得下好几倍的行。
        let per_row = ub * super::UTF8_LOSSY_WORST_CASE;
        assert_eq!(
            super::next_decode_window_end(&rows, 0, 1024, per_row * 2 + 1),
            2,
            "预算要按实际在飞的 String 算 —— 按解压字节算会多塞好几倍的行进来"
        );
    }

    /// **一行里被解压的不止正文, 预算得两列一起算**(独立复审 c4b5dbc 的 P1, 它真跑复现过)。
    ///
    /// `assemble_message` 对 `msg_source`(@提及名单那列)调的是同一个解压函数, 同样吃到 16 MiB,
    /// 结果跟着整窗 collect。只算正文的话, 一行"正文 2 字节 + source 解出 12 MiB"被算成 2 字节 ——
    /// 一窗 1024 行, 预算算出 2 KB、实际在飞 12 GiB, 这道闸从旁边一条没人看的路原样绕回去了。
    #[test]
    fn window_budget_counts_msg_source_too() {
        // 流式压出来的帧不写解压后大小 → 估算按硬上限 16 MiB 算, 而实际内容才一个字节。
        let looks_huge = zstd::stream::encode_all(&b"x"[..], 3).expect("压");
        let cap = crate::decoder::content::MAX_DECOMPRESSED;
        let row = |content: Vec<u8>, source: Vec<u8>| MessageRow {
            local_id: 1,
            server_id: 1,
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            local_type: 1,
            sort_seq: 0,
            create_time: 0,
            status: 4,
            message_content: content,
            msg_source: source,
            sender_username: None,
        };
        // 正文都是几个字节的明文, 大头全在 msg_source 上。
        let rows: Vec<MessageRow> = (0..5).map(|_| row(b"hi".to_vec(), looks_huge.clone())).collect();

        // 预算只够两行。一行 = (正文 2 字节 + msg_source 估 16 MiB) × lossy 最坏 3 倍。
        // 只算正文的话这 5 行加起来才 30 字节, 一窗就全塞下了。
        let per_row = (cap + 2) * super::UTF8_LOSSY_WORST_CASE;
        assert_eq!(
            super::next_decode_window_end(&rows, 0, 1024, per_row * 2 + 100),
            2,
            "msg_source 得算进预算 —— 不算的话 5 行会被塞进同一窗"
        );
    }

    /// **生产路径真的在按字节预算切窗**(独立复审 c4b5dbc 的 P2)。
    ///
    /// 上面那条 `decode_window_is_capped_by_rows_and_bytes` 直接调私有的切窗函数 —— 它证明
    /// "函数算得对", 证明不了"有人调它"。复审把生产那句 `PAR_DECODE_BYTE_BUDGET` 换成 `usize::MAX`,
    /// **全仓一条不红**。同一笔里我刚拿这句话说过归档清理, 转身自己又犯一遍。
    ///
    /// 夹具怎么造出"估得大、其实很小"的行: **流式压出来的帧不写解压后大小**, 于是估算按硬上限
    /// 16 MiB 算, 而实际内容才几个字节。20 行 × 16 MiB = 320 MiB > 256 MiB 预算 → 必须切成两窗以上。
    /// 预算一旦被换成无穷大, 20 行就只切一窗, 这条立刻红。
    #[tokio::test]
    async fn production_decode_really_honors_the_byte_budget() {
        let (_d, mut conn) = setup_conn();
        let big_but_cheap = zstd::stream::encode_all(&b"x"[..], 3).expect("流式压(帧头不写大小)");
        assert_eq!(
            crate::decoder::content::decoded_size_upper_bound(&big_but_cheap),
            crate::decoder::content::MAX_DECOMPRESSED,
            "夹具前提: 帧头读不出大小 → 按硬上限估。这条不成立的话下面的算术就是空的"
        );
        let rows: Vec<MockRow> = (1..=20)
            .map(|lid| MockRow {
                local_id: lid,
                content: big_but_cheap.clone(),
                sender: None,
            })
            .collect();
        let mut src = single_chat_source(rows);

        let stats = run_message_pipeline_jobs(
            &mut src,
            &mut conn,
            &acct(),
            PrivacyMode::default_sha(),
            100,
            1_800_000_000_000,
            None,
            2, // >1 才走并行分窗那条路
        )
        .await
        .unwrap();

        assert_eq!(stats.messages_decoded, 20, "20 行都得落库, 切窗不许丢行");
        assert!(
            stats.decode_windows >= 2,
            "20 行 × 16 MiB 估值超 256 MiB 预算, 必须切开; 只切了 {} 窗 = 预算没在生产路径上生效",
            stats.decode_windows
        );
    }

    /// **分窗有两道闸: 行数和字节, 谁先到算谁**(独立复审报的 P1)。
    ///
    /// decoder 那道单条 16 MiB 的上限对并行路等于没有 —— 整窗解完才写, 1024 × 16 MiB = 16 GiB。
    /// 这条钉三件: 正常小行照样满窗(不能白白收窄, 那是 R15 的性能)、大行自动收窄、
    /// **单条就超预算也得让它自己成一窗**(否则一行都切不出来, 外面那个 while 直接死循环)。
    #[test]
    fn decode_window_is_capped_by_rows_and_bytes() {
        let row = |content: Vec<u8>| MessageRow {
            local_id: 1,
            server_id: 1,
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            local_type: 1,
            sort_seq: 0,
            create_time: 0,
            status: 4,
            message_content: content,
            msg_source: Vec::new(),
            sender_username: None,
        };
        // 未压缩的老格式: 上界 = 自己的长度, 好算。
        let small: Vec<MessageRow> = (0..50).map(|_| row(vec![b'x'; 100])).collect();
        assert_eq!(
            super::next_decode_window_end(&small, 0, 10, 1_000_000),
            10,
            "预算宽松时按行数上限切满 —— 收窄了就是白丢并行度"
        );
        assert_eq!(
            super::next_decode_window_end(&small, 45, 10, 1_000_000),
            50,
            "剩不够一窗就切到结尾"
        );

        // 预算只够 3 行 (每行 100 字节 × lossy 最坏 3 倍 = 300, 预算 1050)。
        assert_eq!(
            super::next_decode_window_end(&small, 0, 10, 100 * super::UTF8_LOSSY_WORST_CASE * 3 + 50),
            3,
            "字节预算先到就按字节切"
        );

        // 单条就超预算 —— 必须仍然切出这一行, 不然外面死循环。
        let huge = vec![row(vec![b'x'; 10_000])];
        assert_eq!(
            super::next_decode_window_end(&huge, 0, 10, 100),
            1,
            "单条超预算也得自己成一窗 (它还有 decoder 那道硬闸兜着)"
        );
    }

    /// **常驻路径(tail-f)写完也会清归档** —— 独立复审报的 P1 就是这条路只写不清。
    ///
    /// 写归档的入口远不止 `ingest`: `watch` 的消息 tail-f、`serve --live-index full`、查询侧懒采集
    /// 全都往这张表写, 而且全是长期跑的形态。真库上量到 977 万行 / 11.5 GiB, 占整库四分之一。
    ///
    /// 这条走的是**增量 pipeline 的公开入口**, 不是直接调清理函数 —— 上一轮的教训正是
    /// "函数算得对"和"有人调它"是两回事, 只测前者时把调用整个删掉都不红。
    #[tokio::test]
    async fn incremental_watch_prunes_the_archive() {
        // ⚠️ 拿同一把测试锁: config 路径的测试钩子是**进程级**的, 别的测试把它指到坏文件时,
        // 这条会因为"读不懂就不清"而红。指到一个不存在的路径 = 走默认 24 小时, 结果确定。
        let _cfg = crate::storage::config_path_for_test(std::path::Path::new("不存在的-config.toml"));
        let (_d, mut conn) = setup_conn();
        // 保留期走默认 24 小时(测试环境没有 config 文件)。夹具的时间**跟着传给 pipeline 的
        // `ingest_time_ms` 走** —— 清理和写入必须同一个钟, 拿墙上时间对是错的(见
        // `prune_archive_throttled` 的注)。
        let now = 1_800_000_000_000i64;
        let hour = 60 * 60 * 1000i64;
        for (nid, t) in [("超窗", now - 25 * hour), ("窗内", now - hour)] {
            conn.execute(
                "INSERT INTO raw_payload_archive
                 (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                 VALUES ('sha', 'src', ?1, 'message', 'insert', 1, ?2, '{}')",
                rusqlite::params![nid, t],
            )
            .unwrap();
        }

        let mut src = single_chat_source(vec![MockRow {
            local_id: 1,
            content: b"m1".to_vec(),
            sender: None,
        }]);
        run_message_pipeline_incremental(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, now, None)
            .await
            .unwrap();

        let left: Vec<String> = conn
            .prepare("SELECT source_native_id FROM raw_payload_archive WHERE source = 'src' ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            left,
            vec!["窗内".to_string()],
            "tail-f 写完得顺手清一次 —— 这条红了就说明常驻路径又回到只写不清"
        );
    }

    /// 2026-07-01: 群聊无解 sender → 占位 SENDER_UNKNOWN 落 L2 (不再 error 丢弃; 内容保留做分析).
    /// 全量真跑暴露 14.3 万条这种消息 (多为群系统消息), 内容有效仅发送者未知 → 占位保留而非整条扔.
    #[tokio::test]
    async fn unresolved_sender_falls_back_to_placeholder_in_l2() {
        let (_d, mut conn) = setup_conn();
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                conv_id: "room456@chatroom".into(), // 群聊
            },
            rows: vec![
                // 群聊 + 无 Name2Id + content 无前缀 → 旧: UnresolvedSender error; 新: 占位落库.
                MockRow {
                    local_id: 1,
                    content: b"no prefix".to_vec(),
                    sender: None,
                },
            ],
            force_next_cursor: None,
            force_has_more: None,
        };
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 1, "占位消息算成功解码 (不再丢弃)");
        assert_eq!(stats.decode_errors, 0, "无 sender 不再算 error");
        assert_eq!(count(&conn, "message"), 1, "占位消息落 L2 message 表");
        // codex P1-3: 断言占位值真落库 (不只看 count, 防 sender 走错分支).
        let sender_sha: String = conn
            .query_row("SELECT sender_wxid_sha FROM message LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            sender_sha,
            crate::sha256_hex(crate::decoder::SENDER_UNKNOWN),
            "占位 sender_wxid_sha == sha256(SENDER_UNKNOWN)"
        );
        // 无 error 事件: 1 msg + 1 cursor = 2.
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "1 msg + 1 cursor, 无 error");
    }

    /// 续传: 第 1 run drain 完 (水位=3); 同 source+conn 第 2 run 从水位 3 续 → drain 0, 不增 archive.
    #[tokio::test]
    async fn resume_from_persisted_watermark() {
        let (_d, mut conn) = setup_conn();
        let rows = vec![
            MockRow {
                local_id: 1,
                content: b"a".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 2,
                content: b"b".to_vec(),
                sender: None,
            },
            MockRow {
                local_id: 3,
                content: b"c".to_vec(),
                sender: None,
            },
        ];
        let mut src = single_chat_source(rows);
        let s1 = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(s1.messages_decoded, 3);
        let archive_after_1 = count(&conn, "raw_payload_archive");

        // 第 2 run: 读到水位 3 → drain 0 → 无新事件。
        let s2 = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 2000, None)
            .await
            .unwrap();
        assert_eq!(s2.messages_decoded, 0, "续传从水位 3, 无新行");
        assert_eq!(s2.cursor_updates, 0, "无推进");
        assert_eq!(
            count(&conn, "raw_payload_archive"),
            archive_after_1,
            "archive 不增 (无新事件)"
        );
    }

    /// 空源: 0 行 → 0 事件, 无水位行.
    #[tokio::test]
    async fn empty_source_no_events() {
        let (_d, mut conn) = setup_conn();
        let mut src = single_chat_source(vec![]);
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        assert_eq!(stats.messages_decoded, 0);
        assert_eq!(stats.cursor_updates, 0);
        assert_eq!(count(&conn, "raw_payload_archive"), 0);
        assert_eq!(count(&conn, "etl_state"), 0, "无行 → 无水位");
    }

    /// decoder_error_code 映射稳定 (进 source_native_id + payload error_code)。
    #[test]
    fn decoder_error_codes() {
        assert_eq!(decoder_error_code(&DecoderError::ZstdFail), "ZSTD_FAIL");
        assert_eq!(
            decoder_error_code(&DecoderError::UnresolvedSender { local_id: 1 }),
            "UNRESOLVED_SENDER"
        );
        assert_eq!(
            decoder_error_code(&DecoderError::InvalidSender {
                sender_sha8: "x".into()
            }),
            "INVALID_SENDER"
        );
    }

    /// cursor 事件: provenance.source = etl 键 (跟 project_watermark 读写同键, 防漂移)。
    #[test]
    fn cursor_event_source_is_etl_key() {
        let ev = build_cursor_update_event(
            &acct(),
            "message_0.db|Msg_x",
            MESSAGE_KIND,
            DrainCursor {
                local_id: 7,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            1000,
        );
        match ev {
            DecodedEvent::SystemCursorUpdate(c) => {
                assert_eq!(c.provenance.source, "message_0.db|Msg_x");
                assert_eq!(c.kind, "message");
                assert_eq!(c.watermark_value, "7");
                assert_eq!(c.watermark_key, "local_id");
            }
            _ => panic!("应为 SystemCursorUpdate"),
        }
    }

    /// 代码双审 P2: batch_limit=0 入口 reject (page-by-page 禁全量)。
    #[tokio::test]
    async fn batch_limit_zero_rejected() {
        let (_d, mut conn) = setup_conn();
        let mut src = single_chat_source(vec![MockRow {
            local_id: 1,
            content: b"a".to_vec(),
            sender: None,
        }]);
        let err = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 0, 1000, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PipelineError::Invariant(_)),
            "batch_limit=0 应 Invariant: {err:?}"
        );
    }

    /// 代码双审 P1: source 返 next_cursor 跳过本批最大 local_id → Invariant (防漏中间行, 不前进不落库)。
    #[tokio::test]
    async fn bad_next_cursor_is_invariant() {
        let (_d, mut conn) = setup_conn();
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_0123456789abcdef0123456789abcdef".into(),
                conv_id: "wxid_friend".into(),
            },
            rows: vec![
                MockRow {
                    local_id: 1,
                    content: b"a".to_vec(),
                    sender: None,
                },
                MockRow {
                    local_id: 2,
                    content: b"b".to_vec(),
                    sender: None,
                },
            ],
            force_next_cursor: Some(999), // 本批 max=2 却报 999 → 会跳过 3..999
            force_has_more: None,
        };
        let err = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap_err();
        assert!(matches!(err, PipelineError::Invariant(_)), "应 Invariant: {err:?}");
        // 失约: 校验在 sink 前 → 无落库无推进。
        assert_eq!(count(&conn, "raw_payload_archive"), 0, "失约不落库");
        assert_eq!(
            etl_value(&conn, "message_0.db|Msg_0123456789abcdef0123456789abcdef"),
            None,
            "未推进水位"
        );
    }

    /// 代码双审 P1: source 报 has_more 但游标不前进 → 停子源 + 计 stalled (不死循环, 不伪装成功)。
    #[tokio::test]
    async fn stalled_subsource_counted() {
        let (_d, mut conn) = setup_conn();
        let mut src = MockSource {
            rel_name: "message_0.db".into(),
            subsource: MessageSubsource {
                table: "Msg_0123456789abcdef0123456789abcdef".into(),
                conv_id: "wxid_friend".into(),
            },
            rows: vec![
                MockRow {
                    local_id: 1,
                    content: b"a".to_vec(),
                    sender: None,
                },
                MockRow {
                    local_id: 2,
                    content: b"b".to_vec(),
                    sender: None,
                },
            ],
            force_next_cursor: None,
            force_has_more: Some(true), // 永远 has_more (异常 source)
        };
        let stats = run_message_pipeline(&mut src, &mut conn, &acct(), PrivacyMode::default_sha(), 10, 1000, None)
            .await
            .unwrap();
        // batch1: drain 1,2 → advance 2; batch2: 空 + has_more → stalled, 停 (不死循环)。
        assert_eq!(stats.messages_decoded, 2);
        assert_eq!(stats.cursor_updates, 1);
        assert_eq!(stats.stalled_subsources, 1, "卡住子源计 1");
    }

    /// emit 推送跟随 mode (全程明文方针): 默认 archive_canonical → archive 与推送都明文 (微信有啥给啥);
    /// 脱敏能力保留 → 显式传 default_sha 时推送脱敏。证 "默认明文 + 脱敏可选 (默认关)"。
    #[tokio::test]
    async fn message_pipeline_push_follows_mode() {
        // ── 默认明文 (archive_canonical): archive + 推送都含裸 conv_id 真值 ──
        let (_d, mut conn) = setup_conn();
        let (tx, mut rx) = crate::emit::in_proc::new_in_proc(16, crate::emit::in_proc::Backpressure::Block);
        let mut src = single_chat_source(vec![MockRow {
            local_id: 1,
            content: b"hi".to_vec(),
            sender: None,
        }]);
        run_message_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            PrivacyMode::archive_canonical(),
            10,
            1000,
            Some(&tx),
        )
        .await
        .unwrap();
        drop(tx); // 关生产端 → rx 排空后 recv None
        let mut pushed = None;
        while let Some(rec) = rx.recv().await {
            if rec.event_type == "message" {
                pushed = Some(rec);
            }
        }
        let pm = pushed.expect("上层应收到 message 推送");
        assert!(
            pm.payload_json.contains("wxid_friend"),
            "默认明文: 推送含裸 conv_id 真值"
        );
        let archive_payload: String = conn
            .query_row(
                "SELECT payload_json FROM raw_payload_archive WHERE event_type='message'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            archive_payload.contains("wxid_friend"),
            "默认明文: archive 含裸 conv_id 真值"
        );

        // ── 脱敏能力保留 (default_sha): 显式传则推送脱敏 (将来对外脱敏用, 默认不启用) ──
        let (_d2, mut conn2) = setup_conn();
        let (tx2, mut rx2) = crate::emit::in_proc::new_in_proc(16, crate::emit::in_proc::Backpressure::Block);
        let mut src2 = single_chat_source(vec![MockRow {
            local_id: 1,
            content: b"hi".to_vec(),
            sender: None,
        }]);
        run_message_pipeline(
            &mut src2,
            &mut conn2,
            &acct(),
            PrivacyMode::default_sha(),
            10,
            1000,
            Some(&tx2),
        )
        .await
        .unwrap();
        drop(tx2);
        let mut pushed2 = None;
        while let Some(rec) = rx2.recv().await {
            if rec.event_type == "message" {
                pushed2 = Some(rec);
            }
        }
        let pm2 = pushed2.expect("上层应收到 message 推送");
        assert!(
            !pm2.payload_json.contains("wxid_friend"),
            "脱敏能力: default_sha 推送无裸 conv_id"
        );
        assert!(
            pm2.payload_json.contains("conv_id_sha"),
            "脱敏能力: default_sha 推送含 conv_id_sha"
        );
    }

    // ── contact pipeline ──

    /// 独立 contact mock: drain_contacts 返 canned 联系人 (rowid keyset); 消息方法空 stub。
    struct ContactMockSource {
        contacts: Vec<(i64, String)>, // (rowid, username)
        delete_flag: i64,             // codex P1-b: 模拟 delete_flag (0→1 删好友) 验进 digest 溯源
    }
    #[async_trait]
    impl DbSource for ContactMockSource {
        async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError> {
            Ok(vec![])
        }
        async fn list_message_subsources(&mut self, _s: &DbSnapshot) -> Result<Vec<MessageSubsource>, DbSourceError> {
            Ok(vec![])
        }
        async fn drain_messages(
            &mut self,
            _s: &DbSnapshot,
            _ss: &MessageSubsource,
            since: &DrainCursor,
            _l: usize,
        ) -> Result<MessageBatch, DbSourceError> {
            Ok(MessageBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_contacts(
            &mut self,
            _contact_db: &std::path::Path,
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
                    nick_name: Some("nick".into()),
                    remark: None,
                    alias: None,
                    is_in_chat_room: 0,
                    quan_pin: None,
                    pin_yin_initial: None,
                    remark_quan_pin: None,
                    remark_pin_yin_initial: None,
                    verify_flag: 0,
                    delete_flag: self.delete_flag,
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
            _contact_db: &std::path::Path,
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
            _session_db: &std::path::Path,
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
            _favorite_db: &std::path::Path,
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
            _favorite_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _emoticon_db: &std::path::Path,
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
            _head_image_db: &std::path::Path,
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
            _bizchat_db: &std::path::Path,
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

    /// contact pipeline: drain → assemble_contact → ContactUpdate 落 L1 (person + person_alias + archive) + 推进游标。
    #[tokio::test]
    async fn contact_pipeline_drains_and_advances() {
        let (_d, mut conn) = setup_conn();
        let mut src = ContactMockSource {
            contacts: vec![
                (1, "wxid_alice".into()),
                (2, "wxid_bob".into()),
                (3, "grp@chatroom".into()),
            ],
            delete_flag: 0,
        };
        let stats = run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/wx/contact.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 3, "3 联系人落库");
        assert_eq!(stats.cursor_updates, 0, "全表重扫不发 cursor 事件");
        // ContactUpdate → person + person_alias 两投 (sink §) + archive (无 cursor 事件)。
        assert_eq!(count(&conn, "person"), 3, "3 联系人 → person");
        assert_eq!(count(&conn, "person_alias_by_account_min"), 3);
        assert_eq!(count(&conn, "raw_payload_archive"), 3, "3 contact (无 cursor 事件)");
        assert_eq!(
            count(&conn, "etl_state"),
            0,
            "contact 全表重扫不持久游标 → 无 etl_state"
        );
    }

    /// 代码双审 P0 修法验证: 全表重扫幂等 — 同联系人重跑 → archive 5 元组撞键去重 (不增行); person UPSERT。
    #[tokio::test]
    async fn contact_pipeline_rerun_is_idempotent() {
        let (_d, mut conn) = setup_conn();
        let mut src = ContactMockSource {
            contacts: vec![(1, "wxid_alice".into()), (2, "wxid_bob".into())],
            delete_flag: 0,
        };
        run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/c.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 2);
        // 重跑 (同联系人) → archive 去重不增 (幂等)。
        run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/c.db"),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "重跑 archive 去重不增");
        assert_eq!(count(&conn, "person"), 2, "person UPSERT 仍 2");
    }

    /// codex P1-b (字段扩充第二批): verify/delete **进 content_digest** 的端到端证明 —
    /// 同一联系人 (同 rowid/username) delete_flag 0→1 (删好友) → content_digest 变 → 新 fingerprint →
    /// **新 archive 行** (旧+新并存溯源"何时删"); person.delete_flag UPSERT 刷新。再重跑不变 → 同 fingerprint 去重 (幂等)。
    #[tokio::test]
    async fn contact_flag_change_produces_new_archive_row() {
        let (_d, mut conn) = setup_conn();
        let mut src = ContactMockSource {
            contacts: vec![(1, "wxid_alice".into())],
            delete_flag: 0,
        };
        // 轮1: delete_flag=0。
        run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/c.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1, "轮1: 1 archive 行");
        let df0: i64 = conn
            .query_row(
                "SELECT delete_flag FROM person WHERE username = 'wxid_alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(df0, 0, "轮1: person.delete_flag=0");
        // 轮2: 同 rowid delete_flag=1 (删好友) → content_digest 变 → 新 fingerprint → 新 archive 行。
        src.delete_flag = 1;
        run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/c.db"),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            count(&conn, "raw_payload_archive"),
            2,
            "轮2: delete_flag 变 → 新 archive 行 (旧+新并存溯源)"
        );
        let df1: i64 = conn
            .query_row(
                "SELECT delete_flag FROM person WHERE username = 'wxid_alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(df1, 1, "轮2: person.delete_flag UPSERT 刷新为 1");
        assert_eq!(count(&conn, "person"), 1, "person 仍 1 行 (UPSERT 非新增)");
        // 轮3: 仍 delete_flag=1 (不变) → 同 content_digest → 同 fingerprint → archive 去重不增 (幂等)。
        run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/c.db"),
            PrivacyMode::default_sha(),
            10,
            3000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            count(&conn, "raw_payload_archive"),
            2,
            "轮3: 不变重跑 → archive 稳定 (幂等)"
        );
    }

    /// contact: batch_limit=0 入口 reject (同 message)。
    #[tokio::test]
    async fn contact_pipeline_batch_limit_zero_rejected() {
        let (_d, mut conn) = setup_conn();
        let mut src = ContactMockSource {
            contacts: vec![(1, "wxid_a".into())],
            delete_flag: 0,
        };
        let err = run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/c.db"),
            PrivacyMode::default_sha(),
            0,
            1000,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PipelineError::Invariant(_)));
    }

    /// emit 推送 (contact) 跟随 mode: 默认 archive_canonical → archive 与推送都明文 (含裸 username 真值)。
    #[tokio::test]
    async fn contact_pipeline_pushes_plaintext_by_default() {
        let (_d, mut conn) = setup_conn();
        let (tx, mut rx) = crate::emit::in_proc::new_in_proc(16, crate::emit::in_proc::Backpressure::Block);
        let mut src = ContactMockSource {
            contacts: vec![(1, "wxid_alice".into())],
            delete_flag: 0,
        };
        let stats = run_contact_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/c.db"),
            PrivacyMode::archive_canonical(),
            10,
            1000,
            Some(&tx),
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 1);
        drop(tx);

        // 默认明文: 上层推送含裸 username 真值 (微信有啥给啥, 不脱敏)。
        let mut pushed = None;
        while let Some(rec) = rx.recv().await {
            pushed = Some(rec);
        }
        let pm = pushed.expect("上层应收到 contact 推送");
        assert!(
            pm.payload_json.contains("wxid_alice"),
            "默认明文: 推送含裸 username 真值"
        );

        // archive 也含裸 username 真值 (底座内明文)。
        let archive_payload: String = conn
            .query_row("SELECT payload_json FROM raw_payload_archive LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(
            archive_payload.contains("wxid_alice"),
            "默认明文: archive 含裸 username 真值"
        );
    }

    // ── chatroom pipeline (退群闭环 ADR-426 §1.1) ──

    /// 独立 chatroom mock: drain_chatrooms 返 canned 群行 (rowid keyset); 其它方法空 stub。
    struct ChatroomMockSource {
        rooms: Vec<ChatroomRawRow>,
    }
    #[async_trait]
    impl DbSource for ChatroomMockSource {
        async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError> {
            Ok(vec![])
        }
        async fn list_message_subsources(&mut self, _s: &DbSnapshot) -> Result<Vec<MessageSubsource>, DbSourceError> {
            Ok(vec![])
        }
        async fn drain_messages(
            &mut self,
            _s: &DbSnapshot,
            _ss: &MessageSubsource,
            since: &DrainCursor,
            _l: usize,
        ) -> Result<MessageBatch, DbSourceError> {
            Ok(MessageBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_contacts(
            &mut self,
            _contact_db: &std::path::Path,
            since: &DrainCursor,
            _l: usize,
        ) -> Result<ContactBatch, DbSourceError> {
            Ok(ContactBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_chatrooms(
            &mut self,
            _contact_db: &std::path::Path,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<ChatroomBatch, DbSourceError> {
            let mut hit: Vec<&ChatroomRawRow> = self.rooms.iter().filter(|r| r.rowid > since.local_id).collect();
            hit.sort_by_key(|r| r.rowid);
            let page: Vec<ChatroomRawRow> = hit.iter().take(limit).map(|r| (*r).clone()).collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |r| r.rowid);
            Ok(ChatroomBatch {
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
        async fn drain_sessions(
            &mut self,
            _session_db: &std::path::Path,
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
            _favorite_db: &std::path::Path,
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
            _favorite_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _emoticon_db: &std::path::Path,
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
            _head_image_db: &std::path::Path,
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
            _bizchat_db: &std::path::Path,
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

    // ── protobuf ext_buffer 编码 helper (复刻 roomdata 测试: 成员 = top-level submessage field1=username [field2=nick]) ──
    fn pb_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
        out
    }
    fn pb_len_field(field_no: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = pb_varint((field_no << 3) | 2);
        out.extend(pb_varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }
    fn ext_of(members: &[(&str, Option<&str>)]) -> Vec<u8> {
        let mut ext = Vec::new();
        for (username, nick) in members {
            let mut inner = pb_len_field(1, username.as_bytes());
            if let Some(n) = nick {
                inner.extend(pb_len_field(2, n.as_bytes()));
            }
            ext.extend(pb_len_field(1, &inner)); // 每成员包成 top-level chunk
        }
        ext
    }
    fn room_row(rowid: i64, chatroom_id: &str, members: &[(&str, Option<&str>)]) -> ChatroomRawRow {
        ChatroomRawRow {
            rowid,
            chatroom_id: chatroom_id.to_string(),
            owner: Some("wxid_owner".into()),
            ext_buffer: ext_of(members),
            chatroom_name: Some(format!("{chatroom_id} 群名")),
            chatroom_remark: None,
            announcement: None,
            announcement_editor: None,
            announcement_publish_time: 0,
            xml_announcement: None,
            chat_room_status: 0,
        }
    }
    fn cdb() -> &'static std::path::Path {
        std::path::Path::new("/wx/contact.db")
    }

    /// 首次运行 (L2 空): ext_buffer 成员全 add, 无 remove; chatroom_member is_in_group=1.
    #[tokio::test]
    async fn chatroom_first_run_adds_all_members() {
        let (_d, mut conn) = setup_conn();
        let mut src = ChatroomMockSource {
            rooms: vec![room_row(
                1,
                "room1@chatroom",
                &[("wxid_alice", Some("甲")), ("wxid_bob", None)],
            )],
        };
        let stats = run_chatroom_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.members_added, 2, "alice + bob 全 add");
        assert_eq!(stats.members_removed, 0);
        assert_eq!(stats.chatrooms_created, 1, "群本身落 1 笔");
        assert_eq!(count(&conn, "chatroom_member"), 2);
        let in_group: i64 = conn
            .query_row("SELECT count(*) FROM chatroom_member WHERE is_in_group=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(in_group, 2);
        assert_eq!(
            count(&conn, "raw_payload_archive"),
            3,
            "1 ChatroomCreate + 2 member_add"
        );
        // 群本身落 chatroom 表 (群名 + 人数 = 成员数)。
        assert_eq!(count(&conn, "chatroom"), 1, "群本身落 chatroom 表 (修复前是 0)");
        let (name, mc): (String, i64) = conn
            .query_row("SELECT chatroom_name, member_count FROM chatroom", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert!(name.contains("群名"), "群名落库 (contact join): {name}");
        assert_eq!(mc, 2, "人数 = 解析出的成员数");
    }

    /// 全表重扫幂等: 同群同成员重跑 → add 跳过已在群 (l2 contains) + 无 remove → 无新行/事件。
    #[tokio::test]
    async fn chatroom_rerun_is_idempotent() {
        let (_d, mut conn) = setup_conn();
        let mut src1 = ChatroomMockSource {
            rooms: vec![room_row(
                1,
                "room1@chatroom",
                &[("wxid_alice", Some("甲")), ("wxid_bob", None)],
            )],
        };
        run_chatroom_pipeline(
            &mut src1,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "chatroom_member"), 2);
        let archive1 = count(&conn, "raw_payload_archive");

        // 重跑 (同群同成员) → add 全跳过 (已在群) + 无 remove → 无新行/事件。
        let mut src2 = ChatroomMockSource {
            rooms: vec![room_row(
                1,
                "room1@chatroom",
                &[("wxid_alice", Some("甲")), ("wxid_bob", None)],
            )],
        };
        let s2 = run_chatroom_pipeline(
            &mut src2,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(s2.members_added, 0, "已在群成员不重 add");
        assert_eq!(s2.members_removed, 0);
        assert_eq!(count(&conn, "chatroom_member"), 2, "行数不变");
        assert_eq!(count(&conn, "raw_payload_archive"), archive1, "archive 不增 (幂等)");
        // ChatroomCreate 每轮重发, 但 ingest_time 1000→2000 不同 → archive 仍不增,
        // 锁定 ChatroomCreate content_digest 不含 ingest_time + chatroom 表 upsert 幂等 (codex P1)。
        assert_eq!(
            count(&conn, "chatroom"),
            1,
            "群表重跑不增 (content_digest 不含时间 + upsert 幂等)"
        );
    }

    /// 退群闭环 (ADR-426 §1.1 核心): run1 加 alice+bob; run2 只剩 alice → bob 退群,
    /// member_wxid 从 L2 明文列回读 (bob 已离 ext_buffer, 这是加明文列的目的)。
    #[tokio::test]
    async fn chatroom_retire_reads_back_plaintext_member_wxid() {
        let (_d, mut conn) = setup_conn();
        // run1: alice + bob 在群
        let mut src1 = ChatroomMockSource {
            rooms: vec![room_row(
                1,
                "room1@chatroom",
                &[("wxid_alice", Some("甲")), ("wxid_bob", Some("乙"))],
            )],
        };
        let s1 = run_chatroom_pipeline(
            &mut src1,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(s1.members_added, 2);
        assert_eq!(count(&conn, "chatroom_member"), 2);

        // run2: 只剩 alice (bob 退群)
        let mut src2 = ChatroomMockSource {
            rooms: vec![room_row(1, "room1@chatroom", &[("wxid_alice", Some("甲"))])],
        };
        let s2 = run_chatroom_pipeline(
            &mut src2,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(s2.members_added, 0, "alice 已在群不重 add");
        assert_eq!(s2.members_removed, 1, "bob 退群");

        // bob 行 is_in_group=0 + left_at=2000; member_wxid 明文回读正确 (闭 §1.1 死结)
        let room_sha = sha256_hex("room1@chatroom");
        let bob_sha = sha256_hex("wxid_bob");
        let (in_group, left, member_plain): (bool, Option<i64>, String) = conn
            .query_row(
                "SELECT is_in_group, left_at, member_wxid FROM chatroom_member WHERE chatroom_id_sha=?1 AND member_wxid_sha=?2",
                rusqlite::params![room_sha, bob_sha],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(!in_group, "bob 退群 is_in_group=0");
        assert_eq!(left, Some(2000), "left_at = ingest 时刻");
        assert_eq!(member_plain, "wxid_bob", "退群闭环: member_wxid 明文回读 (§1.1 死结解)");
        assert_eq!(count(&conn, "chatroom_member"), 2, "退群不删行 (UPDATE), 仍 2");
        // alice 仍在群
        let alice_in: bool = conn
            .query_row(
                "SELECT is_in_group FROM chatroom_member WHERE chatroom_id_sha=?1 AND member_wxid_sha=?2",
                rusqlite::params![room_sha, sha256_hex("wxid_alice")],
                |r| r.get(0),
            )
            .unwrap();
        assert!(alice_in, "alice 仍在群");
    }

    /// 先退后进复活 (codex r1 P1 反驳): run1 加 bob → run2 bob 退 → run3 bob 回。
    /// run3 的 re-add 事件 archive fingerprint 与首次 add **相同** (业务字段同 + src_create_time=0 +
    /// ingest 不进 fingerprint) → archive 5 元组撞键去重; 但 write_decoded_event 的 projection
    /// **无条件执行** (archive 撞键仅忽略, upsert 仍跑) → bob 复活 is_in_group=1, 不被去重吞掉。
    #[tokio::test]
    async fn chatroom_leave_then_rejoin_revives() {
        let (_d, mut conn) = setup_conn();
        let bob_sha = sha256_hex("wxid_bob");
        let q_in_group = "SELECT is_in_group FROM chatroom_member WHERE member_wxid_sha=?1";

        // run1: alice + bob 在群
        let mut s1 = ChatroomMockSource {
            rooms: vec![room_row(
                1,
                "room1@chatroom",
                &[("wxid_alice", None), ("wxid_bob", None)],
            )],
        };
        run_chatroom_pipeline(
            &mut s1,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        let b1: bool = conn
            .query_row(q_in_group, rusqlite::params![bob_sha], |r| r.get(0))
            .unwrap();
        assert!(b1, "run1 后 bob 在群");

        // run2: bob 退群
        let mut s2 = ChatroomMockSource {
            rooms: vec![room_row(1, "room1@chatroom", &[("wxid_alice", None)])],
        };
        run_chatroom_pipeline(
            &mut s2,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        let b2: bool = conn
            .query_row(q_in_group, rusqlite::params![bob_sha], |r| r.get(0))
            .unwrap();
        assert!(!b2, "run2 后 bob 退群 is_in_group=0");

        // run3: bob 回 — re-add 即使 archive 去重也复活
        let mut s3 = ChatroomMockSource {
            rooms: vec![room_row(
                1,
                "room1@chatroom",
                &[("wxid_alice", None), ("wxid_bob", None)],
            )],
        };
        let st3 = run_chatroom_pipeline(
            &mut s3,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            3000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(st3.members_added, 1, "bob re-add (alice 仍在群跳过)");
        let (revived, left): (bool, Option<i64>) = conn
            .query_row(
                "SELECT is_in_group, left_at FROM chatroom_member WHERE member_wxid_sha=?1",
                rusqlite::params![bob_sha],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(
            revived,
            "run3 bob 复活 is_in_group=1 (archive 去重不阻 projection upsert)"
        );
        assert_eq!(left, None, "复活 left_at 清空");
        assert_eq!(count(&conn, "chatroom_member"), 2, "复活不增行, 仍 2");
    }

    /// Suspicious 解析 (ext_buffer 截断): 只 add 解出的成员, **不据此判退群** (名单可能不全, 怕误退)。
    #[tokio::test]
    async fn chatroom_suspicious_adds_but_never_retires() {
        let (_d, mut conn) = setup_conn();
        // run1: alice + bob 完整
        let mut src1 = ChatroomMockSource {
            rooms: vec![room_row(
                1,
                "room1@chatroom",
                &[("wxid_alice", None), ("wxid_bob", None)],
            )],
        };
        run_chatroom_pipeline(
            &mut src1,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "chatroom_member"), 2);

        // run2: ext_buffer 截断 (Suspicious) — 只解出 alice + 尾部坏字节
        let mut ext = ext_of(&[("wxid_alice", None)]);
        ext.push(0xff); // 未完成 varint → Suspicious
        let mut src2 = ChatroomMockSource {
            rooms: vec![ChatroomRawRow {
                rowid: 1,
                chatroom_id: "room1@chatroom".into(),
                owner: None,
                ext_buffer: ext,
                chatroom_name: None,
                chatroom_remark: None,
                announcement: None,
                announcement_editor: None,
                announcement_publish_time: 0,
                xml_announcement: None,
                chat_room_status: 0,
            }],
        };
        let s2 = run_chatroom_pipeline(
            &mut src2,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(s2.members_removed, 0, "Suspicious 不判退群 (bob 不被误退)");
        let bob_in: bool = conn
            .query_row(
                "SELECT is_in_group FROM chatroom_member WHERE member_wxid_sha=?1",
                rusqlite::params![sha256_hex("wxid_bob")],
                |r| r.get(0),
            )
            .unwrap();
        assert!(bob_in, "Suspicious 解析下 bob 不被误判退群");
    }

    /// Invalid 解析 (空 ext_buffer): 跳过整群, 不 diff, 计 invalid_chatrooms。
    #[tokio::test]
    async fn chatroom_invalid_skips_group() {
        let (_d, mut conn) = setup_conn();
        let mut src = ChatroomMockSource {
            rooms: vec![ChatroomRawRow {
                rowid: 1,
                chatroom_id: "room1@chatroom".into(),
                owner: None,
                ext_buffer: vec![],
                chatroom_name: None,
                chatroom_remark: None,
                announcement: None,
                announcement_editor: None,
                announcement_publish_time: 0,
                xml_announcement: None,
                chat_room_status: 0,
            }],
        };
        let stats = run_chatroom_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.invalid_chatrooms, 1);
        assert_eq!(stats.members_added, 0);
        assert_eq!(count(&conn, "chatroom_member"), 0, "Invalid 群不落任何成员");
    }

    /// chatroom: batch_limit=0 入口 reject (同 message/contact)。
    #[tokio::test]
    async fn chatroom_pipeline_batch_limit_zero_rejected() {
        let (_d, mut conn) = setup_conn();
        let mut src = ChatroomMockSource { rooms: vec![] };
        let err = run_chatroom_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::default_sha(),
            0,
            1000,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PipelineError::Invariant(_)));
    }

    /// emit 推送 (chatroom member_add) 跟随 mode: 默认 archive_canonical → archive 与推送都明文 (含裸 member_wxid)。
    #[tokio::test]
    async fn chatroom_pipeline_pushes_plaintext_by_default() {
        let (_d, mut conn) = setup_conn();
        let (tx, mut rx) = crate::emit::in_proc::new_in_proc(16, crate::emit::in_proc::Backpressure::Block);
        let mut src = ChatroomMockSource {
            rooms: vec![room_row(1, "room1@chatroom", &[("wxid_alice", Some("甲"))])],
        };
        let stats = run_chatroom_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            cdb(),
            PrivacyMode::archive_canonical(),
            10,
            1000,
            Some(&tx),
        )
        .await
        .unwrap();
        assert_eq!(stats.members_added, 1);
        drop(tx);

        // 默认明文: 上层推送含裸 member_wxid 真值。
        let mut pushed = None;
        while let Some(rec) = rx.recv().await {
            pushed = Some(rec);
        }
        let pm = pushed.expect("上层应收到 chatroom 推送");
        assert!(
            pm.payload_json.contains("wxid_alice"),
            "默认明文: 推送含裸 member_wxid 真值"
        );

        // archive 含裸 member_wxid 真值 (底座内明文)。现多了 ChatroomCreate 群本身行 →
        // 不取 LIMIT 1 (第一条可能是群本身), 验"存在含 alice 的 archive 行"。
        let with_alice: i64 = conn
            .query_row(
                "SELECT count(*) FROM raw_payload_archive WHERE payload_json LIKE '%wxid_alice%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(with_alice >= 1, "默认明文: 某条 archive 含裸 member_wxid 真值");
    }

    // ── session pipeline (会话列表 ② 取数) ──

    struct SessionMockSource {
        sessions: Vec<(i64, String)>,                  // (rowid, username)
        favorites: Vec<(i64, i64, String)>,            // (local_id, fav_type, from_user); ADR-454 favorite e2e
        favorite_tags: Vec<(i64, i64, String)>,        // (rowid, fav_server_id, tag_name); ADR-454 B-2 e2e
        moments: Vec<(i64, String, String)>,           // (tid, user_name, content-XML); ADR-467 sns e2e
        transfers: Vec<(i64, String, String, String)>, // (rowid, transfer_id, payer, receiver); ADR-468 e2e
    }
    #[async_trait]
    impl DbSource for SessionMockSource {
        async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError> {
            Ok(vec![])
        }
        async fn list_message_subsources(&mut self, _s: &DbSnapshot) -> Result<Vec<MessageSubsource>, DbSourceError> {
            Ok(vec![])
        }
        async fn drain_messages(
            &mut self,
            _s: &DbSnapshot,
            _ss: &MessageSubsource,
            since: &DrainCursor,
            _l: usize,
        ) -> Result<MessageBatch, DbSourceError> {
            Ok(MessageBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_contacts(
            &mut self,
            _db: &std::path::Path,
            since: &DrainCursor,
            _l: usize,
        ) -> Result<ContactBatch, DbSourceError> {
            Ok(ContactBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_chatrooms(
            &mut self,
            _db: &std::path::Path,
            since: &DrainCursor,
            _l: usize,
        ) -> Result<ChatroomBatch, DbSourceError> {
            Ok(ChatroomBatch {
                rows: vec![],
                next_cursor: *since,
                has_more: false,
            })
        }
        async fn drain_sessions(
            &mut self,
            _session_db: &std::path::Path,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<SessionBatch, DbSourceError> {
            let mut hit: Vec<&(i64, String)> = self.sessions.iter().filter(|(rid, _)| *rid > since.local_id).collect();
            hit.sort_by_key(|(rid, _)| *rid);
            let page: Vec<SessionRow> = hit
                .iter()
                .take(limit)
                .map(|(rid, un)| SessionRow {
                    rowid: *rid,
                    username: un.clone(),
                    summary: Some("最近消息".into()),
                    last_sender_display_name: None,
                    unread_count: 2,
                    last_msg_type: 1,
                    last_msg_sub_type: 0,
                    sort_timestamp: 1_700_000_000_000 + *rid,
                    session_type: 0,
                    is_hidden: 0,
                    status: 0,
                    draft: None,
                    last_msg_sender: None,
                    last_timestamp: 0,
                    last_clear_unread_timestamp: 0,
                    last_msg_locald_id: 0,
                    last_msg_ext_type: 0,
                    unread_first_msg_srv_id: 0,
                })
                .collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |s| s.rowid);
            Ok(SessionBatch {
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
        async fn drain_favorites(
            &mut self,
            _favorite_db: &std::path::Path,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<FavoriteBatch, DbSourceError> {
            let mut hit: Vec<&(i64, i64, String)> = self
                .favorites
                .iter()
                .filter(|(lid, _, _)| *lid > since.local_id)
                .collect();
            hit.sort_by_key(|(lid, _, _)| *lid);
            let page: Vec<FavoriteRow> = hit
                .iter()
                .take(limit)
                .map(|(lid, ftype, fu)| FavoriteRow {
                    local_id: *lid,
                    server_id: 300 + *lid,
                    fav_type: *ftype,
                    update_time: 1_779_000_000 + *lid,
                    from_user: fu.clone(),
                    real_chat_name: None,
                    source_id: None,
                    content_len: 100,
                    note_content: if *ftype == 18 {
                        Some("<x><datadesc>笔记mock</datadesc></x>".to_string())
                    } else {
                        None
                    },
                })
                .collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |f| f.local_id);
            Ok(FavoriteBatch {
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
        async fn drain_favorite_tags(
            &mut self,
            _favorite_db: &std::path::Path,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<FavoriteTagBatch, DbSourceError> {
            let mut hit: Vec<&(i64, i64, String)> = self
                .favorite_tags
                .iter()
                .filter(|(rid, _, _)| *rid > since.local_id)
                .collect();
            hit.sort_by_key(|(rid, _, _)| *rid);
            let page: Vec<FavoriteTagRow> = hit
                .iter()
                .take(limit)
                .map(|(rid, fav_sid, name)| FavoriteTagRow {
                    rowid: *rid,
                    tag_server_id: 1,
                    tag_local_id: 1,
                    tag_name: name.clone(),
                    seq: 100 + *rid,
                    fav_server_id: *fav_sid,
                    fav_local_id: *fav_sid,
                    op_code: 1,
                })
                .collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |t| t.rowid);
            Ok(FavoriteTagBatch {
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
        async fn drain_moments(
            &mut self,
            _sns_db: &std::path::Path,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<MomentBatch, DbSourceError> {
            // tid 可为负 → keyset `tid > since` (调用方从 i64::MIN 起); 升序分页。
            let mut hit: Vec<&(i64, String, String)> = self
                .moments
                .iter()
                .filter(|(tid, _, _)| *tid > since.local_id)
                .collect();
            hit.sort_by_key(|(tid, _, _)| *tid);
            let page: Vec<SnsRow> = hit
                .iter()
                .take(limit)
                .map(|(tid, un, content)| SnsRow {
                    tid: *tid,
                    user_name: un.clone(),
                    content: content.clone(),
                })
                .collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |s| s.tid);
            Ok(MomentBatch {
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
        async fn drain_transfers(
            &mut self,
            _general_db: &std::path::Path,
            since: &DrainCursor,
            limit: usize,
        ) -> Result<TransferBatch, DbSourceError> {
            // rowid keyset 升序分页 (全表重扫; ADR-468)。派生固定占位 (transcation/时间/状态) 够验落库。
            let mut hit: Vec<&(i64, String, String, String)> = self
                .transfers
                .iter()
                .filter(|(rid, _, _, _)| *rid > since.local_id)
                .collect();
            hit.sort_by_key(|(rid, _, _, _)| *rid);
            let page: Vec<TransferRow> = hit
                .iter()
                .take(limit)
                .map(|(rid, tid, payer, receiver)| TransferRow {
                    rowid: *rid,
                    transfer_id: tid.clone(),
                    transcation_id: format!("txn_{tid}"),
                    message_server_id: 100 + rid,
                    second_message_server_id: 0,
                    session_name: payer.clone(),
                    pay_sub_type: 2,
                    pay_payer: payer.clone(),
                    pay_receiver: receiver.clone(),
                    begin_transfer_time: 1_752_000_000 + rid,
                    last_modified_time: 1_752_000_001 + rid,
                    invalid_time: 1_752_086_400 + rid,
                    last_update_time: 1_752_000_002 + rid,
                    delay_confirm_flag: 0,
                    bubble_clicked_flag: 0,
                })
                .collect();
            let fetched = page.len();
            let next = page.last().map_or(since.local_id, |t| t.rowid);
            Ok(TransferBatch {
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
        async fn drain_red_envelopes(
            &mut self,
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _general_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _sns_db: &std::path::Path,
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
            _emoticon_db: &std::path::Path,
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
            _head_image_db: &std::path::Path,
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
            _bizchat_db: &std::path::Path,
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

    /// session pipeline: drain → assemble_session → SessionUpdate 落 L1 (session 表 + archive) + 推进游标。
    #[tokio::test]
    async fn session_pipeline_drains_and_advances() {
        let (_d, mut conn) = setup_conn();
        let mut src = SessionMockSource {
            sessions: vec![(1, "wxid_alice".into()), (2, "grp@chatroom".into())],
            favorites: vec![],
            favorite_tags: vec![],
            moments: vec![],
            transfers: vec![],
        };
        let stats = run_session_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/s.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 2, "2 会话落库");
        assert_eq!(count(&conn, "session"), 2, "2 会话 → session 表");
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "2 archive");
        assert_eq!(count(&conn, "etl_state"), 0, "session 全表重扫不持久游标");
    }

    /// 全表重扫幂等: 同会话重跑 → archive 撞键去重不增 + session upsert。
    #[tokio::test]
    async fn session_pipeline_rerun_idempotent() {
        let (_d, mut conn) = setup_conn();
        let mut src = SessionMockSource {
            sessions: vec![(1, "wxid_alice".into())],
            favorites: vec![],
            favorite_tags: vec![],
            moments: vec![],
            transfers: vec![],
        };
        run_session_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/s.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        run_session_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/s.db"),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            count(&conn, "raw_payload_archive"),
            1,
            "重跑 archive 去重不增 (content_digest 同)"
        );
        assert_eq!(count(&conn, "session"), 1, "session upsert 仍 1");
    }

    /// favorite pipeline (ADR-454): drain → assemble_favorite → FavoriteCreate 落 L1 (favorite 表 + archive) +
    /// 全表重扫幂等 (重跑 archive 去重不增 + favorite upsert)。
    #[tokio::test]
    async fn favorite_pipeline_drains_and_idempotent() {
        let (_d, mut conn) = setup_conn();
        let mut src = SessionMockSource {
            sessions: vec![],
            favorites: vec![(10, 14, "wxid_src_a".into()), (11, 1, "grp@chatroom".into())],
            favorite_tags: vec![],
            moments: vec![],
            transfers: vec![],
        };
        let stats = run_favorite_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/f.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 2, "2 收藏落库");
        assert_eq!(count(&conn, "favorite"), 2, "2 收藏 → favorite 表");
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "2 archive");
        assert_eq!(count(&conn, "etl_state"), 0, "favorite 全表重扫不持久游标");
        // 回查 fav_type/from_user 落库正确。
        let ftype: i64 = conn
            .query_row("SELECT fav_type FROM favorite WHERE local_id=10", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ftype, 14);
        // 重跑幂等: archive content_digest 同 → 去重不增; favorite upsert 仍 2。
        run_favorite_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/f.db"),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            count(&conn, "raw_payload_archive"),
            2,
            "重跑 archive 去重不增 (content_digest 同)"
        );
        assert_eq!(count(&conn, "favorite"), 2, "favorite upsert 仍 2");
    }

    /// favorite_tag pipeline (ADR-454 B-2): drain → assemble_favorite_tag → FavoriteTagCreate 落 L1
    /// (favorite_tag 表 + archive) + 全表重扫幂等 + 标签名去规范化落库。
    #[tokio::test]
    async fn favorite_tag_pipeline_drains_and_idempotent() {
        let (_d, mut conn) = setup_conn();
        let mut src = SessionMockSource {
            sessions: vec![],
            favorites: vec![],
            favorite_tags: vec![(1, 254, "押金".into()), (2, 190, "押金".into()), (3, 29, "托号".into())],
            moments: vec![],
            transfers: vec![],
        };
        let stats = run_favorite_tag_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/f.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 3, "3 绑定落库");
        assert_eq!(count(&conn, "favorite_tag"), 3, "3 绑定 → favorite_tag 表");
        assert_eq!(count(&conn, "raw_payload_archive"), 3, "3 archive");
        // 查"收藏 254 的标签" = 押金 (标签名去规范化落库)。
        let name: String = conn
            .query_row("SELECT tag_name FROM favorite_tag WHERE fav_server_id=254", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(name, "押金", "标签名去规范化落库 (ADR-427 明文)");
        // 查"标签 押金 的收藏数" = 2。
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM favorite_tag WHERE tag_name='押金'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 2, "押金 打在 2 个收藏上");
        // 重跑幂等。
        run_favorite_tag_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/f.db"),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 3, "重跑 archive 去重不增");
        assert_eq!(count(&conn, "favorite_tag"), 3, "favorite_tag upsert 仍 3");
    }

    /// sns pipeline (ADR-467 件1): drain → assemble_sns → SnsCreate 落 L1 (moment 表 + archive) +
    /// **负 tid 被 i64::MIN 起点游标覆盖** (不因 tid>0 漏) + 全表重扫幂等。
    #[tokio::test]
    async fn sns_pipeline_drains_negative_tid_and_idempotent() {
        let (_d, mut conn) = setup_conn();
        let content = |desc: &str| {
            format!(
                r#"<SnsDataItem><TimelineObject><createTime>1779546990</createTime><contentDesc>{desc}</contentDesc><ContentObject><type>1</type><mediaList><media><id>1</id><type>2</type><url md5="MD5X" key="KEYX" enc_idx="1">http://full/0</url><size width="800" height="600" totalSize="12345"/></media></mediaList></ContentObject></TimelineObject><LocalExtraInfo><nickname>作者</nickname><like_user_list><user_comment><username>wxid_liker</username><type>1</type></user_comment></like_user_list><comment_user_list><user_comment><comment_id>9</comment_id><username>wxid_commenter</username><nickname>评论人</nickname><content>好看</content><type>2</type><create_time>1779546999</create_time></user_comment></comment_user_list></LocalExtraInfo></SnsDataItem>"#
            )
        };
        let mut src = SessionMockSource {
            sessions: vec![],
            favorites: vec![],
            favorite_tags: vec![],
            moments: vec![
                (-3_518_821_952_372_526_549, "wxid_a".into(), content("负tid动态")), // 负 tid (雪花 id 有符号存储)
                (4_611_686_018_427_387_904, "wxid_b".into(), content("正tid动态")),  // 正 tid
            ],
            transfers: vec![],
        };
        let stats = run_sns_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/sns.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 2, "2 动态落库 (含负 tid — i64::MIN 起点覆盖)");
        assert_eq!(count(&conn, "moment"), 2, "2 动态 → moment 表");
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "2 archive");
        assert_eq!(count(&conn, "etl_state"), 0, "sns 全表重扫不持久游标");
        // 负 tid 落库 + XML 字段解出 (作者/正文/类型/点赞/评论)。
        let (author, desc, mtype, likes, comments): (String, String, i64, i64, i64) = conn
            .query_row(
                "SELECT author, content_desc, moment_type, like_count, comment_count FROM moment WHERE tid=-3518821952372526549",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(author, "wxid_a", "发布者明文 (ADR-427)");
        assert_eq!(desc, "负tid动态", "正文解出");
        assert_eq!(mtype, 1, "moment_type 解出");
        assert_eq!(likes, 1, "点赞数解出 (like_user_list)");
        assert_eq!(comments, 1, "评论数解出 (comment_user_list — 修复后不再漏)");
        // 件2a: 逐条媒体落 moment_media (2 动态各 1 媒体 → 2 行), url/md5/key 解出。
        assert_eq!(count(&conn, "moment_media"), 2, "2 动态各 1 媒体 → moment_media 2 行");
        let (mt, url, md5, key): (i64, String, String, String) = conn
            .query_row(
                "SELECT media_type, url, md5, url_key FROM moment_media WHERE source_native_id='Sns_-3518821952372526549' AND media_seq=0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(mt, 2, "媒体 type 2 (图)");
        assert_eq!(url, "http://full/0", "媒体 url 明文");
        assert_eq!(md5, "MD5X");
        assert_eq!(key, "KEYX", "SNS 解密 key");
        // 件2b: 逐条互动落 moment_interaction (2 动态各 1 赞+1 评论 → 4 行)。
        assert_eq!(count(&conn, "moment_interaction"), 4, "2 动态各 赞+评论 → 4 行");
        let (kind, fu, ct): (String, String, String) = conn
            .query_row(
                "SELECT kind, from_user, content FROM moment_interaction WHERE source_native_id='Sns_-3518821952372526549' AND kind='comment'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(kind, "comment");
        assert_eq!(fu, "wxid_commenter", "评论者明文");
        assert_eq!(ct, "好看", "评论文本明文");
        // 重跑幂等: content_digest 同 → archive 去重不增; moment upsert 仍 2; media/interaction replace 不累积。
        run_sns_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/sns.db"),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "moment"), 2, "moment upsert 仍 2");
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "archive 去重仍 2");
        assert_eq!(
            count(&conn, "moment_media"),
            2,
            "moment_media replace-projection 仍 2 (不累积)"
        );
        assert_eq!(
            count(&conn, "moment_interaction"),
            4,
            "moment_interaction replace-projection 仍 4 (不累积)"
        );
    }

    /// transfer pipeline: drain → assemble_transfer → TransferCreate 落 L1 (transfer 表 + archive) + 全表重扫幂等 (ADR-468)。
    #[tokio::test]
    async fn transfer_pipeline_drains_and_idempotent() {
        let (_d, mut conn) = setup_conn();
        let mut src = SessionMockSource {
            sessions: vec![],
            favorites: vec![],
            favorite_tags: vec![],
            moments: vec![],
            transfers: vec![
                (
                    1,
                    "1000050001202507100225413996557".into(),
                    "wxid_payer_a".into(),
                    "wxid_me".into(),
                ),
                (
                    2,
                    "1000050001202507110029026829168".into(),
                    "wxid_payer_b".into(),
                    "wxid_me".into(),
                ),
            ],
        };
        let stats = run_transfer_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/general.db"),
            PrivacyMode::default_sha(),
            10,
            1000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats.messages_decoded, 2, "2 条转账落库");
        assert_eq!(count(&conn, "transfer"), 2, "transfer 表 2 行");
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "archive 2 条");

        // 全表重扫幂等: 重跑 archive content_digest 去重不增 + transfer upsert 不增。
        run_transfer_pipeline(
            &mut src,
            &mut conn,
            &acct(),
            std::path::Path::new("/general.db"),
            PrivacyMode::default_sha(),
            10,
            2000,
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&conn, "transfer"), 2, "transfer upsert 仍 2");
        assert_eq!(count(&conn, "raw_payload_archive"), 2, "archive 去重仍 2");
    }
}
