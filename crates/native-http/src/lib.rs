//! HTTP API 皮 (接口设计-③http-api规格.md) —— axum 服务器, **镜像 native-query 共享内核**的 REST 端点。
//! 第三张皮 (CLI/MCP/HTTP 同一内核), 消费者 = 第三方 / 网页前端。
//!
//! **本增量**: §5 响应契约 (错误 `{code,message,hint,candidates}` + 每响应 `X-Request-Id`) + 账号 fail-closed
//! (多账号未指定 → 409 `ACCOUNT_AMBIGUOUS` + candidates, 与 MCP 同走内核 [`native_query::resolve_account`]) +
//! 一批只读端点 + **per-endpoint 参数结构 `deny_unknown_fields`** (端点不认的参数 → 400, 不静默吞返未过滤全量;
//! 审查红队 #1)。
//!
//! **B① (本增量)**: `/messages` 冷热分发器 —— 投影 (`kind=call/link/file/image/system/biz` · `mentions`/`mentions_me`
//! · `conv_type=official` · `quote`) 走冷查 L1 派生表, 无投影 + `conv` 走热查会话 (§6b); 模板端点 `/extract`
//! (枚举参数式) + `/moments/interactions` (registry-cmd 式) 立可复制模式给 build workflow 铺开机械端点。
//!
//! **未做 (逐步补)**: `/moments/{inbox,media}` · `/accounts` · `/names` GET/POST · pack (§6) · 媒体 Range (§8) ·
//! SSE 实时 (§10) · exec POST · OpenAPI (§11) · `/sensitive`+`/live-index/status` (需 token/live-index 设施) ·
//! `kind=forward` 展开 / `?mode=` 显式路由 · 加固 (就绪门/CORS 收紧/访问日志/优雅关停; §9)。
//!
//! **注**: 冷查在 async handler 里同步跑 sqlite (本地低并发只读可接受; 加固步再议 spawn_blocking)。
//! HTTP 是**全保真本地皮** (loopback, ADR-427 明文), 不做 MCP 那种给云 LLM 的折叠/脱敏。

// HTTP 处理函数的参数多是因为一次请求要带账号/库路径/过滤/分页等多个独立输入;
// 就近声明的辅助 item 比堆到文件顶部更好读。
#![allow(clippy::too_many_arguments, clippy::items_after_statements)]
// ApiError 携 §5 契约全字段 (code/message/hint/candidates/request_id) 故较大; ~20 handler 全 Result<_, ApiError>,
// 逐个 Box 只添噪不增益 (本地只读服务无热路径) → 整 crate 允 large-err。
#![allow(clippy::result_large_err)]

mod error;
mod openapi;

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use error::{is_query_interrupted, map_core_err, request_id_mw, ApiError, Jb, Qs, RequestId};
use serde::Deserialize;
use serde_json::{json, Value};

/// 服务器状态 (启动时构造; 各端点据此取数据源)。
#[derive(Clone, Default)]
pub struct AppState {
    /// 冷查 L1 库路径 (联系人/账号/朋友圈等读它)。
    pub l1_db: Option<String>,
    /// 热查 (会话/消息直读加密源库) 的微信数据目录。
    pub wechat_data_dir: Option<String>,
    /// (serve `--sns-wasm-dir`) 朋友圈媒体解密的 node keystream 脚本目录 (含 weflow_wasm_keystream.js +
    /// wasm_video_decode.wasm/.js)。`/media/moment:` 加密媒体需它 (WxIsaac64 keystream 只在微信 WASM 里对)。
    /// `None` → 退到 env `WECHAT_SNS_WASM_DIR` / exe 同目录 `vendor/weflow_wasm` (见 `resolve_sns_node_script`)。
    pub sns_wasm_dir: Option<String>,
    /// (serve `--ffmpeg`) ffmpeg 可执行路径 (wxgf 动图/静图 → GIF/PNG 当场转码)。`None` → 退到 env
    /// `WECHAT_FFMPEG` / exe 同目录 / PATH (见 `native_core::media::resolve_ffmpeg`)。缺则 wxgf 出 octet-stream (内容不丢)。
    pub ffmpeg: Option<String>,
    /// 默认账号 wxid (端点未给 account 时用)。
    pub default_account: Option<String>,
    /// (serve `--watch`) 后台 watch 落库进度接收端: 每次增量落库 send 递增计数 → 唤醒 `/events` 连接读档。
    /// `None` = 未开实时 (/events 返 503)。`watch::Receiver` 可 Clone (每连接一份订阅)。
    pub events_progress: Option<tokio::sync::watch::Receiver<u64>>,
    /// (serve 内部装) 关停广播: serve 收 Ctrl-C 时先 `send(true)` 通知 SSE 长连流立即收尾 → 连接 future
    /// resolve → 优雅关停得以完成 (解审查 shutdown-leak 的三方循环等待死锁)。`None` = 非 serve 路径 (如测试)。
    pub shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    /// (serve `--request-timeout-secs`) 可选**每请求总超时**: 非流式端点超此秒数 → 408 `REQUEST_TIMEOUT` (§5 错误体)。
    /// `None` = 不限 (默认; 合法慢查询不被误杀)。流式 `/events`(SSE) 与 `/media`(大流/联网) **恒不受此限**。
    pub request_timeout: Option<std::time::Duration>,
    /// (serve `--max-concurrent`) 可选**最大并发常规请求数** (超出排队等待/背压)。**只算非流式端点** —— `/events`
    /// (SSE) / `/media` 放行 (各有 EVENTS/MEDIA/EGRESS per-op 闸兜, 计入会饿死常规请求)。`None` = 不限 (默认)。
    pub max_concurrent: Option<usize>,
    /// (serve `--live-index full`) full 实时索引是否开着。冷查 freshness 据此出 `stale`(R9 复审R3#4: full+线程活
    /// → `stale:false`, full+线程死 → `stale:true` 告警)。`false` = 静态 cold (freshness 只 `ingested_at`, 见 §11 决策 2)。
    pub live_index_full: bool,
    /// R9 复审R3#3: 后台监听线程**实际存活**信号 (watch/full 时 `Some`; 线程退出/崩溃 → 置 `false`)。
    /// `/live-index/status` 的 `live` 据此**真实**报, 不再拿启动期静态 flag 假报"正常" (线程死了仍显 live:true)。
    pub live_index_alive: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

type Shared = Arc<AppState>;

/// R9 复审R3#3: 后台 watch 线程是否**实际存活** (从 `live_index_alive` `AtomicBool` 读)。无信号 (未起 full) → false。
/// 冷查 freshness 的 `stale` + `/live-index/status` 的 `live` 共用。
fn live_thread_alive(st: &AppState) -> bool {
    st.live_index_alive
        .as_ref()
        .is_some_and(|a| a.load(std::sync::atomic::Ordering::Relaxed))
}

/// R9 件6 + 复审R3#4: 冷查统一挂 freshness —— `full`(serve `--live-index full`)时据**后台线程存活** `live_alive`
/// 出 `stale`(活→false 同步在运行 / 死→true 索引垮了告警);否则静态 cold 只 `ingested_at`。判不出(空 L1)→ 不挂
/// (不出误导性空壳)。4 处冷查点共用。(`indexed_through` R3#4 已撤: 无廉价诚实实现, 数据时刻鲜度看 `/live-index/status`。)
fn attach_cold_freshness(
    r: &mut native_query::QueryResult,
    l1: &str,
    account_sha: Option<&str>,
    full: bool,
    live_alive: bool,
    // R22 (第二轮对抗审 P1): 这次**没把会话补到最新**的原因, 必须进信封 —— 否则 HTTP 调用方拿到
    // 200 + 一批消息, **没有任何字段**告诉它读到的可能是半截 (原来这里恒 None, 只有 MCP 皮填了)。
    refresh_skipped: Option<&str>,
) {
    let f = if full {
        native_query::cold_freshness_full(l1, account_sha, live_alive)
    } else {
        native_query::cold_freshness(l1, account_sha)
    };
    match (f, refresh_skipped) {
        // 直接赋 pub 字段 (helper 持 &mut, 不能 move-out 走 with_freshness builder)。
        (Some(f), skip) => r.meta.freshness = Some(f.with_refresh_skipped(skip)),
        // ⚠️ **没水位也得把 skip 说出来**(codex round-4 P1): `cold_freshness*` 在 `etl_state` 没水位时
        // (全新库 / 老库) 返 `None`, 原来这里 `if let` 一并把 skip 丢了 → `/messages` 又变成
        // "200 + 一批(可能是空的)数据, 没有任何字段说这次没补成"。宁缺(ingested_at)不谎(丢 skip)。
        (None, Some(why)) => {
            r.meta.freshness = Some(native_query::Freshness::Cold {
                ingested_at: None,
                stale: None,
                chat_refreshed_at: None,
                refresh_skipped: Some(why.to_string()),
            });
        }
        // 判不出鲜度又没什么可说的 → 不挂 (不出误导性空壳)。
        (None, None) => {}
    }
}

// ── per-endpoint 参数结构 (全 `deny_unknown_fields`: 该端点不认的参数 → Qs 拒 400, 不静默吞) ──

/// 只带 account (汇总 / 单条 inspect 详情)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountQ {
    account: Option<String>,
}

/// `get_account` 专属 query (**R16-6 双模**; 独立于共享 [`AccountQ`] —— 后者被多个 detail/pack 端点复用, 不能加 mode)。
/// `deny_unknown_fields`(§文件头惯例): 拼错的键(如 `?moed=hot`)显式 400, 不静默吞成默认 auto。
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountSummaryQ {
    account: Option<String>,
    /// hot 实时聚合源库计数(messages 全扫慢, 要 account) / cold(默认 auto 有 L1)读 L1 各表 count。
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// 4 个单条 inspect 详情端点专属 query (**R16-6 双模**; 独立于共享 [`AccountQ`] —— 同 [`AccountSummaryQ`] 理由, 不能给
/// 共享结构加 mode)。`deny_unknown_fields`(§文件头惯例, Claude R16-6 P3): 拼错的键(`?moed=hot`)显式 400, 不静默吞成默认
/// auto 让用户以为走了热查其实没有。
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectQ {
    account: Option<String>,
    /// hot 直读加密源库按 entity 路由实时查(message 全扫找锚慢, contact/chatroom 字段少于冷, 要 account) /
    /// cold(默认 auto 有 L1)读 L1 单行。
    mode: Option<native_query::QueryMode>,
}

/// R21: message-detail (`/messages/{id}`) 专用 —— 同 [`InspectQ`] 但多 `confirm` (只 message 实体全扫找锚)。
/// contact/chatroom/session-detail 不全扫不收 confirm, 故拆。
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectScanQ {
    account: Option<String>,
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行 message 详情的全扫找锚。
    confirm: Option<bool>,
}

/// account + limit (通用列表: friend-requests/moments/channels/dormant/sessions)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    /// R6 查询模式: `hot` 实时读微信库 (默认) / `cold` 读 L1 投影库 (快但可能旧, 需服务端 --l1-db) / `auto` 有 L1
    /// 走冷否则热。缺省 = hot (默认实时最稳; 见 [`native_query::QueryMode`])。
    mode: Option<native_query::QueryMode>,
}

/// contacts (keyset 游标 + 子串搜; **R16-1 起冷热双模**)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactsQ {
    account: Option<String>,
    limit: Option<usize>,
    /// **冷查专用** keyset 游标。给了它又要 `mode=hot` = 参数组合矛盾 → 显式拒 (热查用 offset)。
    cursor: Option<String>,
    /// **热查专用**翻页 (冷查用 cursor)。
    offset: Option<usize>,
    search: Option<String>,
    /// R16-1 查询模式。**缺省 auto 而非 hot** —— 本端点原本只有冷查, 缺省给 hot 会让现有调用方
    /// (不传 mode) 从冷查变热查 = 最大意外。auto: 服务端配了 `--l1-db` 就照旧走冷、零破坏。
    /// (`ListQ`/sessions 缺省 hot 是 R6 给它俩单独定的语义, **别照抄**。)
    mode: Option<native_query::QueryMode>,
}

/// **R16-1**: 已接热查、用 account+limit+offset 三件套的 offset-分页端点专用（friend-requests / channels /
/// moments / dormant 等）。缺省 `mode` **auto**（同 [`ContactsQ`] 的 mode: 原只有冷查, 缺省 hot 破坏现有调用方）。
/// R21 起需 `confirm` 的全扫端点另用 [`HotScanPageQ`]（多 confirm 一字段）。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HotPageQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    /// 缺省 **auto**(理由同 `ContactsQ::mode`: 原本只有冷查, 缺省 hot 会破坏现有调用方)。
    mode: Option<native_query::QueryMode>,
}

/// R21: 已接热查**且全扫 message 分片**的 offset-分页端点 (locations/group-events/cards/money-claims/money-payers/
/// dormant) 专用 —— 同 [`HotPageQ`] 但多 `confirm`。非全扫 HotPageQ 端点不收 confirm, 故拆 (drift 契约 + deny_unknown_fields)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HotScanPageQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查。
    confirm: Option<bool>,
}

/// favorites (内容子串过滤 + offset; **R16-1 起冷热双模**)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FavoritesQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    query: Option<String>,
    /// 缺省 **auto**(理由同 `ContactsQ::mode`)。
    mode: Option<native_query::QueryMode>,
}

/// search (关键词; 三皮统一名 keyword)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchQ {
    account: Option<String>,
    limit: Option<usize>,
    keyword: Option<String>,
    /// R16-6 🔴降级双模: hot 全库扫 text.contains 子串(无 FTS/无 bm25, 时间序, 要 account) / cold(默认 auto 有 L1)FTS5 bm25。
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// money (kind 分类)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MoneyQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    kind: Option<String>,
    /// R16-4: 默认档冷热双模 (缺省 auto, 同 HotPageQ)。
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// pii-scan (R16-5: kind/reveal + 冷热双模; 无 offset, top-N)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PiiScanQ {
    account: Option<String>,
    limit: Option<usize>,
    kind: Option<String>,
    /// 显全不打码 (默认 false 打码)。
    reveal: Option<bool>,
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// stats (by 维度)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatsQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    by: Option<String>,
    /// R16-5: 冷热双模 (缺省 auto)。
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// followups (private_only)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FollowupsQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    private_only: Option<bool>,
    /// R16-6 双模: hot 全扫源库聚合漏回会话(要 account) / cold(默认 auto 有 L1)读 L1 message JOIN。
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// msgraw (native_id / source)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MsgrawQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    native_id: Option<String>,
    /// 只看某个源库 (如 `message_0.db`)。同名会话表可能同时在多个分片里, 光给 native_id 会返回多条。
    source: Option<String>,
}

/// members (admins_only; **R16-1 起冷热双模, 降级件**)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MembersQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    admins_only: Option<bool>,
    /// 缺省 **auto**(理由同 `HotPageQ::mode`: 原本只有冷查, 缺省 hot 会破坏现有调用方)。
    mode: Option<native_query::QueryMode>,
}

/// messages 分发器 (§6b: 投影无独立端点, 走本端点参数)。**双模**:
/// - 有投影选择器 (`kind`/`mentions`/`mentions_me`/`conv_type=official`/`quote`) → **冷查** L1 派生表 (calls/links/
///   files/events/biz/mentions/thread/media);
/// - 无选择器 + `conv` → **热查** 按需解密该会话消息 (现有 [`get_messages`] 行为);
/// - 无选择器 + 无 `conv` → 400 (全局明文消息火管无专用内核函数, 不静默返空; 记档 backlog)。
///
/// **R6 完成**: `?mode=hot|cold|auto` (mode 作用于**会话消息**冷热; 投影 kind/mentions/... 恒冷, 显式 mode=hot → 400)。
/// **未做 (记档, 非本增量)**: `kind=forward` 合并转发展开 (走 `resolve_query` 需 msg_id, 另形, 后续
/// `/messages/{id}?expand=` 或独立端点); `from`/`since`/`until`/`keyword`/`detail`/`expand`
/// (冷查投影内核函数尚无这些过滤参, 加时逐个补)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessagesQ {
    account: Option<String>,
    limit: Option<usize>,
    /// 冷查投影分页偏移 (审查 B D3: 投影超 limit 的行经 offset 可达; 热查会话分支不适用, 见下)。
    offset: Option<usize>,
    /// 会话标识 (对方 wxid / 群 id); 热查必需, 冷查投影忽略。
    conv: Option<String>,
    /// `false` = 冷查前**不要**先把这个会话的新消息补进 L1 (读 L1 现有的, 快但可能不是最新)。
    ///
    /// 缺省 = 补。补的前提是够得着微信库 (服务器起了 `--wechat-data-dir` 且能拿到 key);
    /// 够不着时如实报错, **不静默降级** —— 静默跳过会让调用方以为读到的是最新的。
    refresh: Option<bool>,
    /// 投影类型 (封闭枚举 §9): call/link/file/image/system/biz。缺 = 无类型投影。
    kind: Option<String>,
    /// `kind=system` 时按群系统事件子类过滤 (member_join/revoke/...); 其余 kind 忽略。
    sys_type: Option<String>,
    /// @提及某人 (mentioned_wxid 子串); 与 `mentions_me` 互斥优先本参。
    mentions: Option<String>,
    /// @提及"我" (= 解析出的账号 wxid); 需可定位账号 (显式 account 或单账号库)。
    mentions_me: Option<bool>,
    /// 会话类型: `official` → 公众号图文 (旧 biz; 等价 `kind=biz`)。
    conv_type: Option<String>,
    /// 引用回复投影 (thread; message_app 引用链)。
    quote: Option<bool>,
    /// `kind=forward` 时展开某条合并转发的子项 (给 message 的 source_native_id); 省略 = 列所有合并转发。其余 kind 忽略。
    msg_id: Option<String>,
    /// `kind=forward` 展开时精确定位分片 (消息 id 跨分片会重号, 用 list 结果里的 source 值)。其余 kind 忽略。
    source: Option<String>,
    /// R6 查询模式 (仅作用于**会话消息** = 无投影选择器时): `hot` 实时(默认) / `cold` 读 L1 / `auto` 有 L1 走冷。
    /// 投影 (kind/mentions/conv_type/quote) 恒冷; 对投影显式 `mode=hot` → 400 (投影无实时版)。
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// extract (结构化抽取; kind 封闭枚举 + offset 深翻)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractQ {
    account: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    kind: Option<String>,
    /// R16-5: 冷热双模 (缺省 auto)。
    mode: Option<native_query::QueryMode>,
    /// R21 成本门: `?confirm=true` 强制执行超阈值的全扫慢查 (仅热全扫端点读; 冷查/定向查忽略)。
    confirm: Option<bool>,
}

/// names GET (小批量 wxid→名字; `ids` 逗号分隔, ≤100; 大批量走 POST)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamesQ {
    account: Option<String>,
    ids: Option<String>,
    /// R16-6 双模: hot 读源库 contact.db(名字实时, 要 account) / cold(默认 auto 有 L1)读 L1 person。
    mode: Option<native_query::QueryMode>,
}

/// names POST body (大批量 wxid→名字; `ids[]` 上限 200; §6b)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamesReq {
    account: Option<String>,
    ids: Vec<String>,
}

/// exec POST body (只读 SQL; §6)。`max_rows` 缺省 1000, 钳 [1,10000]。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecReq {
    sql: String,
    max_rows: Option<usize>,
    /// R16-6 双模: hot 直查加密源库原始裸 schema (要 source_db+account) / cold(默认 auto 有 L1)查 L1 投影库。
    mode: Option<native_query::QueryMode>,
    /// mode=hot 必填: 源库相对路径 (db_storage 下, 如 `contact/contact.db` / `message/message_0.db`)。
    source_db: Option<String>,
    /// mode=hot 定位账号 (多账号库必填, 或用服务器默认账号)。
    account: Option<String>,
}

/// 无参端点 (如 `/accounts`): 任何 query 参 → deny_unknown_fields 拒 400 (不静默忽略)。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

// ── 信封 + 通用助手 ──

#[derive(serde::Serialize)]
struct Env<'a> {
    data: &'a [Value],
    meta: &'a native_query::Meta,
}

/// 成功信封 `{data, meta}` (三皮同核, 与 CLI json 逐字节同形)。
fn envelope(r: &native_query::QueryResult) -> Response {
    Json(Env {
        data: &r.data,
        meta: &r.meta,
    })
    .into_response()
}

/// L1 路径 (未配置 → 400)。
fn require_l1(st: &AppState, rid: &RequestId) -> Result<String, ApiError> {
    st.l1_db
        .clone()
        .ok_or_else(|| ApiError::bad_request(rid, "服务器未配置 L1 库 (serve --l1-db)"))
}

/// limit 夹 `[1, hard]`, 缺省 `default`。
fn clamp_limit(v: Option<usize>, default: usize, hard: usize) -> usize {
    v.unwrap_or(default).clamp(1, hard)
}

/// offset 上限钳制 (审查 Group A P3): 防病态巨值 —— `offset as i64` 溢负 → SQLite 负 OFFSET 当 0 返首页;
/// 且 money `limit+offset` 深翻 O(offset) 内存。任何真实列表都到不了 1e7 深, 超则视同翻过尾 (返空)。
const MAX_OFFSET: usize = 10_000_000;
fn clamp_offset(v: Option<usize>) -> usize {
    v.unwrap_or(0).min(MAX_OFFSET)
}

/// 冷查账号解析 (query `?account=` > 服务器默认 → 内核 fail-closed 决策): 单账号 → `Ok(None)`; 多账号未指定
/// → 409 `ACCOUNT_AMBIGUOUS` + candidates; 判不出 → 409 (要求显式)。三皮同核 (审查 P1-2/3)。
fn resolve_cold_account(
    l1: &str,
    explicit: Option<String>,
    default: Option<&str>,
    rid: &RequestId,
) -> Result<Option<String>, ApiError> {
    // query ?account= > 服务器默认 (serve --wxid) > 内核 fail-closed (复审#3: 补默认回退, 兑现本函数注释承诺;
    // 原先只透 explicit → 多账号库 + serve --wxid + 未带 ?account 仍 409, 与热查 require_wxid / SSE 不一致)。
    let requested = explicit.or_else(|| default.map(str::to_string));
    match native_query::resolve_account(l1, requested) {
        Ok(native_query::AccountResolution::Use(a)) => Ok(a),
        Ok(native_query::AccountResolution::Ambiguous { candidates }) => {
            Err(
                ApiError::new(rid, StatusCode::CONFLICT, "ACCOUNT_AMBIGUOUS", "多账号库需指定账号")
                    .with_hint("传 ?account=<wxid> 选一个 (候选见 candidates)")
                    .with_candidates(json!(candidates)),
            )
        }
        Err(e) => Err(ApiError::new(
            rid,
            StatusCode::CONFLICT,
            "ACCOUNT_AMBIGUOUS",
            "无法确定库里的账号 (判不出账号维度)",
        )
        .with_hint(format!("显式传 ?account=<wxid>; 底层: {e}"))),
    }
}

/// 冷查端点通用: require_l1 → 账号 fail-closed → `open_l1_scoped` (遮蔽视图隔离) → `run(conn, l1, account_sha)`
/// → 信封。绝大多数 L1 端点走它 (薄壳只提供 `run` 闭包)。**R6**: 回填 `meta.freshness`(冷查 ingested_at+stale)。
async fn cold<F>(st: &AppState, rid: &RequestId, explicit: Option<String>, run: F) -> Result<Response, ApiError>
where
    F: FnOnce(&rusqlite::Connection, &str, Option<&str>) -> anyhow::Result<native_query::QueryResult> + Send + 'static,
{
    cold_with_skip(st, rid, explicit, None, run).await
}

/// 同 [`cold`], 但把"这次没把会话补到最新"的原因带进信封 (R22 懒式落库的 `/messages` 冷查分支用)。
///
/// 第二轮对抗审 P1: 原来 `/messages` 算出了 `skip_reason` 却只 `let _ =` 丢掉 (注释写着"下面 cold() 里
/// 填进信封", 而 `cold()` 走的 `cold_freshness()` 把这个字段硬写成 `None`), 于是 HTTP 调用方拿到
/// 200 + 一批消息, **没有任何字段**能告诉它读到的可能是半截 —— 而 openapi 对外承诺的正是"如实标出"。
async fn cold_with_skip<F>(
    st: &AppState,
    rid: &RequestId,
    explicit: Option<String>,
    skip: Option<&'static str>,
    run: F,
) -> Result<Response, ApiError>
where
    F: FnOnce(&rusqlite::Connection, &str, Option<&str>) -> anyhow::Result<native_query::QueryResult> + Send + 'static,
{
    let l1 = require_l1(st, rid)?;
    let default_account = st.default_account.clone(); // 复审#3: account 未给时冷查账号回退服务器默认 (serve --wxid)。
    let rid2 = rid.clone();
    let full = st.live_index_full; // R9 件6: full 时冷查 freshness 出 stale (bool Copy → 进闭包)。
    let live_alive = live_thread_alive(st); // R3#4: full 语境 stale 由线程真存活定 (bool Copy → 进闭包)。
                                            // R6 复审 P1: 并发闸 permit 在此取、**移进 spawn_blocking 持到查询真跑完** (超时/断连丢 handler future 时后台
                                            // SQLite 不被取消仍在跑; permit 留 async 作用域会提前释放 → 闸被打穿、连发重查堆满阻塞池)。同 exec/search。
    let permit = COLD_SEMAPHORE.acquire().await.expect("cold semaphore 不会关闭");
    // §9 (审 P2): 冷查同步 sqlite 下沉 spawn_blocking —— serve **current_thread** runtime 上内联会钉死唯一 async
    // 线程, 慢冷查 (stats GROUP BY / search FTS / biz COUNT 全表扫) 冻死全服务 (含 /health), 且 --request-timeout-secs
    // 的 timer 得不到 poll 无法 fire (只 /exec 因已 spawn_blocking 受保护)。放阻塞池: async 线程空出 → 超时可 fire +
    // 别的请求不冻。account 解析亦同步 sqlite, 一并进闭包。(照 exec/media 范式。)
    let joined = tokio::task::spawn_blocking(move || -> Result<native_query::QueryResult, ApiError> {
        let _permit = permit; // 持到本闭包(查询)结束 → 并发闸对"真在跑的查询"生效。
        let account = resolve_cold_account(&l1, explicit, default_account.as_deref(), &rid2)?;
        let account_sha = account.as_deref().map(native_core::sha256_hex);
        let conn = native_query::open_l1_scoped(&l1, account_sha.as_deref()).map_err(|e| map_core_err(&rid2, &e))?;
        // R6 复审 P1: 冷查 SQLite 算力界 (无界 GROUP BY / 无索引扫描 → progress_handler 到期 SQLITE_INTERRUPT 自停),
        // 免超时的后台查询空跑吃满 CPU。照 exec/search deadline 范式。
        // codex-R9 P2: 标志记录 progress_handler 是否真触发中断 —— 冷查 *_query (followups 等) 的 filter_map(ok_or_warn)
        // 会把行迭代阶段 SQLITE_INTERRUPT 当坏行**吞掉** → Ok(部分)。查完据标志补判 408, 别把截断部分结果当 200 完整返回。
        let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = interrupted.clone();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(COLD_QUERY_DEADLINE_SECS);
        conn.progress_handler(
            100_000,
            Some(move || {
                if std::time::Instant::now() > deadline {
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }),
        );
        let run_result = run(&conn, &l1, account_sha.as_deref());
        if interrupted.load(std::sync::atomic::Ordering::Relaxed) {
            // 中断已触发(可能被吞成 Ok 部分): 结果不完整不可信 → 408, 不返 200。
            return Err(ApiError::new(
                &rid2,
                StatusCode::REQUEST_TIMEOUT,
                "REQUEST_TIMEOUT",
                "冷查超 30s 上限被中断 (结果不完整; 无界 GROUP BY / 无索引全表扫); 缩小范围或加 limit/offset 分页",
            ));
        }
        let mut r = run_result.map_err(|e| {
            // codex-R7 P2#1 / codex-R8 P2: deadline 触发但**传播出来**的 SQLITE_INTERRUPT → 408 (按错误码精确判, 非 elapsed
            // 计时)。多数会被上面的标志先逮到; 此处兜住 `?`/collect 传播的那类 (如 search_query 直传)。
            if is_query_interrupted(&e) {
                ApiError::new(
                    &rid2,
                    StatusCode::REQUEST_TIMEOUT,
                    "REQUEST_TIMEOUT",
                    "冷查超 30s 上限被中断 (无界 GROUP BY / 无索引全表扫); 缩小范围或加 limit/offset 分页",
                )
            } else {
                map_core_err(&rid2, &e)
            }
        })?;
        // 审查 B D1/D2: scoped 时统一回显 sha8 (meta schema 不随 kind 漂移)。
        if let Some(sha) = &account_sha {
            r.meta.account = Some(sha[..8].to_string());
        }
        // R6/R9: 冷查新鲜度 (审 R6-P2: ingested_at 按查询账号 scoped)。full → 据线程存活加 stale (R3#4: 活 false/死 true);
        // 静态 cold 只 ingested_at (非 full 无常驻同步, 不谎报)。判不出 → 不挂 (不出空壳 {})。
        attach_cold_freshness(&mut r, &l1, account_sha.as_deref(), full, live_alive, skip);
        Ok(r)
    })
    .await;
    match joined {
        Ok(Ok(r)) => Ok(envelope(&r)),
        Ok(Err(e)) => Err(e),
        Err(je) => Err(ApiError::new(
            rid,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("查询任务失败: {je}"),
        )),
    }
}

/// registry 命令端点通用 (`run_query` 路径; moments 子视图 / media 等 `CMD_*` 走它)。是 [`cold`] 的兄弟, 但
/// `run_query` **自建连接 + 内部 sha 遮蔽视图** (吃 [`native_query::QueryTarget`]`{l1,wxid}`, 非现成 conn) → 不复用
/// `cold` 的闭包形。offset 分页 (审查 B D3: 超 limit 行经 offset 可达; run_query 已补 `LIMIT ?1 OFFSET ?2`)。
async fn cold_cmd(
    st: &AppState,
    rid: &RequestId,
    explicit: Option<String>,
    cmd: &'static native_query::QueryCommand,
    limit: usize,
    offset: usize,
) -> Result<Response, ApiError> {
    let l1 = require_l1(st, rid)?;
    let default_account = st.default_account.clone(); // 复审#3: account 未给时冷查账号回退服务器默认 (serve --wxid)。
    let rid2 = rid.clone();
    let full = st.live_index_full; // R9 件6: full → 冷查 freshness 加 stale。
    let live_alive = live_thread_alive(st); // R3#4: full 语境 stale 由线程真存活定 (bool Copy → 进闭包)。
                                            // R6 复审 P1: 并发闸 (同 cold; run_query 的 LIMIT/OFFSET 有界故不另设 deadline, 主要靠闸防堆积)。permit 移进闭包。
    let permit = COLD_SEMAPHORE.acquire().await.expect("cold semaphore 不会关闭");
    // §9 (审 P2): 同 cold —— 同步 run_query 下沉 spawn_blocking (含 account 解析), 别钉死 current_thread。cmd 是 &'static
    // CMD_* (调用方传 &native_query::CMD_*), 可安全进闭包。
    let joined = tokio::task::spawn_blocking(move || -> Result<native_query::QueryResult, ApiError> {
        let _permit = permit; // 持到查询结束 → 闸对真在跑的查询生效。
        let account = resolve_cold_account(&l1, explicit, default_account.as_deref(), &rid2)?; // run_query 内部 sha256 建遮蔽视图
                                                                                               // R16-1: 同 MCP —— QueryTarget 转热冷通用后字段变多; 本路径只服务冷查派发, 用 ::cold 构造器。
                                                                                               // freshness 稍后还要用 l1 路径, 而 ::cold 会 move 它 → 先留一份 (比从 Option 里再取回干净)。
        let l1_for_freshness = l1.clone();
        let target = native_query::QueryTarget::cold(l1, account);
        // codex-R7 P2#2: registry 冷查加 30s deadline (run_query_with_deadline) —— LIMIT/OFFSET 只限输出不限扫描, 大
        // offset registry 查 (moments/interactions/inbox/image) 仍全扫空跑占闸。P2#1/codex-R8 P2: 命中 deadline 的
        // SQLITE_INTERRUPT → 408 非 500, **按错误码精确判** (is_query_interrupted; 非 elapsed —— cold_cmd 的计时起点在
        // deadline 安装[run_query_with_deadline 内 open 之后]之前, 慢开库会把普通错误误报 408)。
        let mut r = native_query::run_query_with_deadline(cmd, &target, limit, offset, Some(COLD_QUERY_DEADLINE_SECS))
            .map_err(|e| {
                if is_query_interrupted(&e) {
                    ApiError::new(
                        &rid2,
                        StatusCode::REQUEST_TIMEOUT,
                        "REQUEST_TIMEOUT",
                        "冷查超 30s 上限被中断 (大 offset 全表扫); 缩小范围或减小 offset",
                    )
                } else {
                    map_core_err(&rid2, &e)
                }
            })?;
        // R6/R9: 冷查新鲜度 (审 R6-P2: ingested_at 按账号 scoped)。full → 据线程存活加 stale (R3#4)。
        let acc_sha = target.account.as_deref().map(native_core::sha256_hex);
        attach_cold_freshness(&mut r, &l1_for_freshness, acc_sha.as_deref(), full, live_alive, None);
        Ok(r)
    })
    .await;
    match joined {
        Ok(Ok(r)) => Ok(envelope(&r)),
        Ok(Err(e)) => Err(e),
        Err(je) => Err(ApiError::new(
            rid,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("查询任务失败: {je}"),
        )),
    }
}

/// mentions_me 用: 解析"我"的具体 wxid (mentions_query 要 `mentioned_wxid` 子串, 不能靠遮蔽视图隐式)。
/// `explicit` 由调用方叠好 (query `?account=` > 服务器默认 `--wxid`); 都无则退到单账号库唯一 `person.account_id`。
/// 多账号未指定 → 409 (同 fail-closed); 判不出 (**真库常态: account_id 为 NULL 即便单账号**) → 400 (要求显式)。
fn resolve_self_wxid(l1: &str, explicit: Option<String>, rid: &RequestId) -> Result<String, ApiError> {
    if let Some(a) = explicit {
        return Ok(a);
    }
    let conn = native_query::open_l1(l1).map_err(|e| map_core_err(rid, &e))?;
    let shas = native_query::account_shas(&conn).map_err(|e| map_core_err(rid, &e))?;
    let cands = native_query::account_candidates(&conn);
    if shas.len() > 1 {
        return Err(ApiError::new(
            rid,
            StatusCode::CONFLICT,
            "ACCOUNT_AMBIGUOUS",
            "多账号库需指定账号 (mentions_me 要定位'我'的 wxid)",
        )
        .with_hint("传 ?account=<wxid> (候选见 candidates)")
        .with_candidates(json!(cands)));
    }
    cands.into_iter().next().ok_or_else(|| {
        ApiError::bad_request(
            rid,
            "无法定位账号 wxid (person.account_id 为空); 显式传 ?account=<wxid>",
        )
    })
}

/// 热查账号 (query > 默认; 热查必需 wxid 定位账号库 + 取 key)。缺 → 400。
/// R22 懒式落库 (ADR-508 D24): 冷查前把**一个会话**的新消息补进 L1。
///
/// 够不着微信库 (没配 `--l1-db` / 拿不到账号或 key) → **400 明说**, 不静默跳过:
/// 静默跳过等于告诉调用方"这是最新的", 而它可能差着几个月的消息。要显式读旧的就传 `?refresh=false`。
/// R22 懒式落库: 冷查前把**一个会话**的新消息补进 L1。
///
/// 返 `Ok(Some(原因))` = 没补成但数据可读(照读 L1, 原因进信封的 `refresh_skipped`)。
/// **没补成不报 4xx**: "冷库拷到别的机器上自足查"是本仓一直成立的契约, 硬失败会打断它
/// (D24 审 P1: 之前这里复用了热查的 `require_wxid`, 于是 `?mode=cold` 反而被要求给账号,
///  错误文案自己打自己)。但也**不能装作补过了** —— 原因进结构化输出。
async fn refresh_chat_soft(
    st: &AppState,
    rid: &RequestId,
    account: Option<String>,
    conv: &str,
) -> Result<Option<&'static str>, ApiError> {
    let Some(l1) = st.l1_db.as_deref() else {
        return Err(ApiError::bad_request(rid, "冷查要 serve --l1-db"));
    };
    // 没账号 = 够不着源库 → 降级读现有的并标记(**不**走 require_wxid 的热查文案)。
    let Some(acc) = account.or_else(|| st.default_account.clone()) else {
        return Ok(Some("source_unavailable"));
    };
    let wxid = match native_core::Wxid::try_new(acc) {
        Ok(w) => w,
        Err(e) => return Err(ApiError::bad_request(rid, format!("wxid 不合法: {e}"))),
    };
    match native_query::ensure_chat_fresh(std::path::Path::new(l1), &wxid, conv, st.wechat_data_dir.as_deref()).await {
        Ok(r) => {
            if let Some(why) = r.skip_reason() {
                tracing::info!(rid = %rid.0, why, "本次没把该会话补到最新 → 读 L1 现有的");
            }
            Ok(r.skip_reason())
        }
        Err(e) => Err(ApiError::bad_request(
            rid,
            format!("补入新消息失败 (要显式读 L1 现有的请加 ?refresh=false): {e}"),
        )),
    }
}

fn require_wxid(st: &AppState, rid: &RequestId, explicit: Option<String>) -> Result<native_core::Wxid, ApiError> {
    let acc = explicit
        .or_else(|| st.default_account.clone())
        .ok_or_else(|| {
            ApiError::bad_request(
                rid,
                "该端点(热查)需要 account (wxid) 或服务器默认账号; 或加 ?mode=cold 走 L1 (需 serve --l1-db) —— 冷查免 key/账号",
            )
        })?;
    acc.parse::<native_core::Wxid>()
        .map_err(|_| ApiError::bad_request(rid, "account 非合法 wxid"))
}

// ── 探针 (就绪门外; §9 健康探针分层) ──

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn ping() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// `GET /api/v1/openapi.json` — 本 API 的 OpenAPI 3.0.3 规格 (§11; 无鉴权/无信封, 直吐文档供第三方生成客户端)。
async fn get_openapi() -> impl IntoResponse {
    Json(openapi::openapi_doc())
}

/// 未知路径 → §5 404 (非 axum 默认空 body; 审查 F1)。
async fn not_found(Extension(rid): Extension<RequestId>) -> ApiError {
    ApiError::new(&rid, StatusCode::NOT_FOUND, "NOT_FOUND", "没有这个路径 / 端点")
        .with_hint("只读端点见 ③规格 §6; 未列的路径不存在")
}

/// 路径存在但 HTTP 方法不对 (如对只读端点 POST) → §5 405 (非空 body; 审查 F1)。
async fn method_not_allowed(Extension(rid): Extension<RequestId>) -> ApiError {
    ApiError::new(
        &rid,
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
        "该端点不支持此 HTTP 方法",
    )
    .with_hint("查询一律用 GET (只读服务)")
}

// ⚠️ **无 panic 恢复层** (审查 Group A P1): workspace `panic="abort"` 是 K-R4 安全红线 (禁 unwind 析构泄
// master_key)。abort 下 `catch_unwind` **接不住** panic → `CatchPanicLayer` 是死代码, 且 `cargo test` 强制
// unwind 会给它假绿。故不装该层 —— 服务端 §9"单请求 panic 不打死服务"在 K-R4 下**不可达**。缓解 = handler
// **无可达 panic** (全 Result/map_err, inc1 收敛复审已核); 若内核深处 panic, 进程 abort (K-R4 认: 宁 abort
// 不泄 key)。要真 panic 恢复须把 serve 拆独立 unwind 二进制 (v1 不做)。

/// 精确判定 loopback host (无 scheme, 形如 `127.0.0.1:8420` / `localhost` / `[::1]:8420`): host 须**恰是**
/// localhost/127.0.0.1/[::1] (后接 `:port` 或结束), 防 `localhost.evil.com` 前缀绕过。Host 头 / Origin host 共用。
fn is_loopback_host(host: &[u8]) -> bool {
    for h in [b"localhost".as_slice(), b"127.0.0.1".as_slice(), b"[::1]".as_slice()] {
        if let Some(after) = host.strip_prefix(h) {
            // 恰是 loopback host: 到此结束, 或后接 ':' + 纯数字端口 (审查 round3 P3: 收紧 ':' 后为纯数字, 防
            // `127.0.0.1:8420@evil` 一类混淆; 浏览器本不可达此串, 属纵深防御)。
            match after {
                [] => return true,
                [b':', port @ ..] if !port.is_empty() && port.iter().all(u8::is_ascii_digit) => {
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

/// 精确判定 loopback 源 (审查 C EXEC-CORS-1 防 drive-by): `scheme://host[:port]` 的 host 须 loopback。
fn is_loopback_origin(o: &[u8]) -> bool {
    for scheme in [b"http://".as_slice(), b"https://".as_slice()] {
        if let Some(rest) = o.strip_prefix(scheme) {
            if is_loopback_host(rest) {
                return true;
            }
        }
    }
    false
}

/// §3 CORS (浏览器前端必备)。**审查 C EXEC-CORS-1 收紧**: 原 `allow_origin(Any)` → ACAO:* → 任意网站 JS 可
/// drive-by fetch 打 127.0.0.1 读回结果 (exec 尤甚: 裸 SQL 非 scoped 拖全库)。改为**仅放行 loopback 源** (本机前端
/// localhost:* / 127.0.0.1:* 合法; evil.com 源被拒 → 预检失败, 浏览器不发真请求也读不到响应)。非 loopback 白名单
/// (`--cors-origin`) 留后续。**必补 Expose-Headers** (前端读 X-Request-Id 等)。不设 Allow-Credentials (Bearer 非 cookie)。
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::{header, HeaderName, Method};
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _parts| {
            is_loopback_origin(origin.as_bytes())
        }))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("last-event-id"),
        ])
        .expose_headers([
            HeaderName::from_static("x-request-id"),
            header::ETAG,
            header::ACCEPT_RANGES,
            header::CONTENT_RANGE,
        ])
        .max_age(std::time::Duration::from_secs(600))
}

// ── 冷查列表 / 汇总端点 ──

async fn get_account(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<AccountSummaryQ>,
) -> Result<Response, ApiError> {
    // R16-6 双模: hot 聚合源库实时计数 (messages 全扫 → 取 HOT_SCAN_SEMAPHORE permit 限并发)。
    if matches!(
        p.mode
            .unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some()),
        native_query::EffectiveMode::Hot
    ) {
        let wxid = require_wxid(&st, &rid, p.account)?;
        http_cost_gate(&st, &rid, &wxid, 0, 0, p.confirm.unwrap_or(false)).await?;
        let permit = hot_scan_permit(&rid, 0, 0).await?;
        let r = native_query::hot_account(&wxid, st.wechat_data_dir.as_deref(), None, Some(permit))
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
        return Ok(envelope(&r));
    }
    cold(&st, &rid, p.account, move |c, _l1, _sha| native_query::account_query(c)).await
}

async fn get_contacts(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<ContactsQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500); // HTTP 机器消费, 上限比 MCP 宽。
    let offset = clamp_offset(p.offset);
    // R16-1: 缺省 auto (**不是** unwrap_or_default() —— QueryMode 的 Default 是 Hot, 那是 sessions 的语义;
    // 本端点原本只有冷查, 缺省 hot 会让现有调用方从冷查变热查)。
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            // 冷查是 keyset 游标 / 热查是 offset —— 给了 cursor 又要热查 = 矛盾, 显式拒不静默忽略。
            if p.cursor.is_some() {
                return Err(ApiError::bad_request(
                    &rid,
                    "cursor 是冷查的 keyset 游标; 实时查请用 offset 翻页 (或 ?mode=cold 走 L1)",
                ));
            }
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r =
                native_query::hot_contacts(&wxid, st.wechat_data_dir.as_deref(), p.search.as_deref(), limit, offset)
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            // codex 审 P2: 冷查是 **keyset 游标**, 压根不吃 offset —— 收下却不传给 `contacts_query`
            // 就是**静默吞**: 用户 `?mode=cold&offset=40000` 拿到的是**第一页**, 还带 HTTP 200。
            // 这条 CLI 侧修过一次(`cmd_contacts` 的 cold 分支拒 offset), 我接 HTTP/MCP 时**原样又犯**。
            // 判据是"**每一皮 × 每个分支**, 这参数被读了吗", 不是"CLI 那条修了就完了"。
            if p.offset.is_some_and(|o| o != 0) {
                return Err(ApiError::bad_request(
                    &rid,
                    "offset 是实时查(mode=hot)的翻页方式; 冷查请用 cursor 续翻 (把上一页 meta.next_cursor 原样回传)",
                ));
            }
            cold(&st, &rid, p.account, move |c, l1, sha| {
                native_query::contacts_query(c, l1, sha, p.search.as_deref(), limit, p.cursor.as_deref())
            })
            .await
        }
    }
}

async fn get_friend_requests(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_friend_requests(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::friend_requests_query(c, limit, offset)
            })
            .await
        }
    }
}

/// `GET /api/v1/moments` — 查朋友圈动态本体。**R16-1 起冷热双模**: mode=hot 直读加密 sns.db 的
/// SnsTimeLine(复用 assemble_sns 解 content XML); cold 读 L1 moment 表。7 键对齐。
async fn get_moments(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_moments(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::moments_query(c, limit, offset)
            })
            .await
        }
    }
}

async fn get_money(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<MoneyQ>,
) -> Result<Response, ApiError> {
    let kind = match p.kind.as_deref().unwrap_or("all") {
        "all" => native_query::MoneyKind::All,
        "transfer" => native_query::MoneyKind::Transfer,
        "redpacket" | "red-envelope" | "red_envelope" => native_query::MoneyKind::RedEnvelope,
        "grouppay" | "group-pay" | "group_pay" => native_query::MoneyKind::GroupPay,
        other => {
            return Err(ApiError::bad_request(
                &rid,
                format!("kind 无效: {other} (all/transfer/redpacket/grouppay)"),
            ))
        }
    };
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    // R16-4: 默认档冷热双模 (热走 hot_money 两源混合: general.db 专表 + 扫 msg49 补金额/人数)。
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r = native_query::hot_money(
                &wxid,
                st.wechat_data_dir.as_deref(),
                None,
                kind,
                limit,
                offset,
                Some(permit),
            )
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::money_query(c, kind, limit, offset)
            })
            .await
        }
    }
}

/// `GET /api/v1/money/claims` — 查红包领取明细 (**R16-4 money 子视图, 冷热双模, 从零建端点**; type10000 hongbao
/// 领取通知派生)。mode=hot scan_all_messages 全局扫 msg10000 + parse_hongbao_claim(全库扫下沉 spawn_blocking +
/// HOT_SCAN_SEMAPHORE 闸); cold 走引擎 CMD_HONGBAO 读 L1 message_hongbao_claim。5 键对齐
/// (create_time/conv_id/send_id/is_own_envelope/peer_name)。镜像 CLI `money --claims` / MCP `wx_hongbao_claims`。
async fn get_money_claims(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotScanPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r = native_query::hot_hongbao_claims(
                &wxid,
                st.wechat_data_dir.as_deref(),
                None,
                limit,
                offset,
                Some(permit),
            )
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_HONGBAO, limit, offset).await
        }
    }
}

/// `GET /api/v1/money/payers` — 查群收款逐付款人 (**R16-4 money 子视图, 冷热双模, 从零建端点, 一对多**; type49 群收款
/// payerlist 派生)。mode=hot scan_all_messages 全局扫 msg49 + parse_appmsg payerlist(全库扫下沉 spawn_blocking +
/// HOT_SCAN_SEMAPHORE 闸, 一群收款消息多付款人); cold 走引擎 CMD_GROUP_PAY_MEMBERS 读 L1 group_pay_member。4 键对齐
/// (bill_no/payer_wxid/amount_fen/pay_status)。镜像 CLI `money --payers` / MCP `wx_group_pay_members`。
async fn get_money_payers(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotScanPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r = native_query::hot_group_pay_members(
                &wxid,
                st.wechat_data_dir.as_deref(),
                None,
                limit,
                offset,
                Some(permit),
            )
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(
                &st,
                &rid,
                p.account,
                &native_query::CMD_GROUP_PAY_MEMBERS,
                limit,
                offset,
            )
            .await
        }
    }
}

/// `GET /api/v1/pii-scan` — 扫全库文本 PII (手机号/身份证; **R16-5 冷热双模, 从零建端点**; msg1 文本派生, top-N 无翻页)。
/// mode=hot scan_all_messages 全扫 msg1 + `scan_pii_in_text` 纯函数(全库扫下沉 spawn_blocking + HOT_SCAN_SEMAPHORE 闸);
/// cold 走 `pii_scan_query` 读 L1。默认打码 (reveal=true 显全)。镜像 CLI `pii-scan` / MCP `wx_pii_scan`。
async fn get_pii_scan(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<PiiScanQ>,
) -> Result<Response, ApiError> {
    let kind = match p.kind.as_deref().unwrap_or("all") {
        "all" => native_query::PiiKind::All,
        "phone" => native_query::PiiKind::Phone,
        "idcard" => native_query::PiiKind::Idcard,
        other => {
            return Err(ApiError::bad_request(
                &rid,
                format!("kind 无效: {other} (all/phone/idcard)"),
            ))
        }
    };
    let reveal = p.reveal.unwrap_or(false);
    let limit = clamp_limit(p.limit, 30, 200);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            http_cost_gate(&st, &rid, &wxid, 0, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, 0, limit).await?;
            let r = native_query::hot_pii_scan(
                &wxid,
                st.wechat_data_dir.as_deref(),
                None,
                kind,
                reveal,
                limit,
                Some(permit),
            )
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::pii_scan_query(c, kind, reveal, limit)
            })
            .await
        }
    }
}

async fn get_favorites(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<FavoritesQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r =
                native_query::hot_favorites(&wxid, st.wechat_data_dir.as_deref(), p.query.as_deref(), limit, offset)
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::favorites_query(c, p.query.as_deref(), limit, offset)
            })
            .await
        }
    }
}

/// `GET /api/v1/favorites/media` — 查收藏媒体 (**R16-3 冷热双模, 从零建端点, 一对多**; 收藏笔记 type18 content 派生)。
/// 热走 `hot_favorite_media`(读 favorite.db fav_db_item 笔记 content 逐收藏 parse_note_media, 读源库非全库扫故无
/// scan_permit); 冷走 `cold_cmd` + `CMD_FAV_MEDIA`(registry run_query)。6 键对齐
/// (fav_server_id/seq/data_type/media_md5/media_size/data_fmt)。
async fn get_favorites_media(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_favorite_media(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_FAV_MEDIA, limit, offset).await
        }
    }
}

/// `GET /api/v1/favorites/tags` — 查收藏标签 (**R16-3 冷热双模, 从零建端点**; 收藏笔记的标签绑定)。
/// 热走 `hot_favorite_tags`(读 favorite.db fav_bind_tag ⋈ fav_tag 按 anchor 去重, 读源库非全库扫故无
/// scan_permit); 冷走 `cold_cmd` + `CMD_FAV_TAGS`。3 键对齐(tag_server_id/fav_server_id/tag_name)。
async fn get_favorites_tags(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_favorite_tags(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_FAV_TAGS, limit, offset).await
        }
    }
}

async fn get_channels(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_finder_visits(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::finder_query(c, limit, offset)
            })
            .await
        }
    }
}

/// **R16-1**: 自定义表情 (引擎路径热查的第一条)。冷查走 `cold_cmd(&CMD_EMOTICONS)`, 热查走
/// `hot_emoticons`(直读加密 emoticon.db)。5 键对齐。
async fn get_emoticons(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_emoticons(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        // 冷查引擎: cold_cmd 挂 freshness + 并发闸 + 遮蔽视图 (同 /moments/interactions)。
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_EMOTICONS, limit, offset).await
        }
    }
}

/// `GET /api/v1/chatrooms` — 查群列表 (**R16-1 起冷热双模, 从零建列表端点**; 原只有 /chatrooms/:id 单群详情)。
/// mode=hot 直读加密 contact.db 的 chat_room(LEFT JOIN 群名/公告, proto 数成员); cold 走引擎读 L1 chatroom。
async fn get_chatrooms(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_chatrooms(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_CHATROOMS, limit, offset).await
        }
    }
}

/// `GET /api/v1/avatars` — 查头像清单 (**R16-1 起冷热双模, 从零建端点**; 不含图片 BLOB)。
/// mode=hot 直读加密 head_image.db 的 head_image 表(WHERE username!='' 对齐 pipeline); cold 走引擎读 L1。
async fn get_avatars(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_avatars(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_AVATARS, limit, offset).await
        }
    }
}

/// `GET /api/v1/locations` — 查位置分享 (**R16-2 起冷热双模, 从零建端点**; type48 位置消息)。
/// mode=hot scan_all_messages 全局扫 msg48 + parse_location(全库扫下沉 spawn_blocking + HOT_SCAN_SEMAPHORE 闸);
/// cold 走引擎 CMD_LOCATIONS 读 L1 message_location。7 键对齐(create_time/conv_id/latitude/longitude/poiname/label/cityname)。
async fn get_locations(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotScanPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            // codex 3a10c84 P1: 全库扫热查取 HOT_SCAN_SEMAPHORE permit 移进 hot_locations 的 spawn_blocking。
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r =
                native_query::hot_locations(&wxid, st.wechat_data_dir.as_deref(), None, limit, offset, Some(permit))
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_LOCATIONS, limit, offset).await
        }
    }
}

/// `GET /api/v1/group-events` — 查群成员进出记录 (**R16-2 冷热双模, 从零建端点, 一对多**; type10000 系统消息派生)。
/// mode=hot scan_all_messages 全局扫 msg10000 + parse_member_events 一成员一行(全库扫下沉 spawn_blocking +
/// HOT_SCAN_SEMAPHORE 闸); cold 走引擎 CMD_GROUP_EVENTS 读 L1 chatroom_member_event。5 键对齐
/// (event_time/conv_id/event_kind/member_nickname/member_wxid)。
async fn get_group_events(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotScanPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r =
                native_query::hot_group_events(&wxid, st.wechat_data_dir.as_deref(), None, limit, offset, Some(permit))
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_GROUP_EVENTS, limit, offset).await
        }
    }
}

/// `GET /api/v1/cards` — 查分享的名片 (**R16-2 冷热双模, 从零建端点**; type42 名片消息)。
/// mode=hot scan_all_messages 全局扫 msg42 + parse_card(全库扫下沉 spawn_blocking + HOT_SCAN_SEMAPHORE 闸);
/// cold 走引擎 CMD_CARDS 读 L1 message_card。6 键对齐(create_time/conv_id/card_nickname/card_alias/card_username/company)。
async fn get_cards(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotScanPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            // codex 3a10c84 P1: 全库扫热查取 HOT_SCAN_SEMAPHORE permit 移进 hot_cards 的 spawn_blocking。
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r = native_query::hot_cards(&wxid, st.wechat_data_dir.as_deref(), None, limit, offset, Some(permit))
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_CARDS, limit, offset).await
        }
    }
}

/// `GET /api/v1/biz-contacts` — 查企微联系人 (**R16-1 起冷热双模, 从零建端点**)。
/// mode=hot 直读加密 bizchat.db 的 user_info 表(WHERE user_id!='' 对齐 pipeline); cold 走引擎读 L1。
async fn get_biz_contacts(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_biz_contacts(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_BIZ_CONTACTS, limit, offset).await
        }
    }
}

async fn get_stats(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<StatsQ>,
) -> Result<Response, ApiError> {
    let by = match p.by.as_deref().unwrap_or("day") {
        "day" => native_query::StatsBy::Day,
        "sender" => native_query::StatsBy::Sender,
        "conv" => native_query::StatsBy::Conv,
        "type" => native_query::StatsBy::Type,
        other => {
            return Err(ApiError::bad_request(
                &rid,
                format!("by 无效: {other} (day/sender/conv/type)"),
            ))
        }
    };
    let limit = clamp_limit(p.limit, 30, 100);
    let offset = clamp_offset(p.offset);
    // R16-5: 冷热双模 (热走 hot_stats 全扫全类型 HashMap 累加)。
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r = native_query::hot_stats(
                &wxid,
                st.wechat_data_dir.as_deref(),
                None,
                by,
                limit,
                offset,
                Some(permit),
            )
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::stats_query(c, by, limit, offset)
            })
            .await
        }
    }
}

async fn get_dormant(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotScanPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    // R16-6 双模: hot 全扫源库聚合(取 permit 限并发); cold 读 L1 GROUP BY。
    if matches!(
        p.mode
            .unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some()),
        native_query::EffectiveMode::Hot
    ) {
        let wxid = require_wxid(&st, &rid, p.account)?;
        http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
        let permit = hot_scan_permit(&rid, offset, limit).await?;
        let r = native_query::hot_dormant(&wxid, st.wechat_data_dir.as_deref(), None, limit, offset, Some(permit))
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
        return Ok(envelope(&r));
    }
    cold(&st, &rid, p.account, move |c, _l1, _sha| {
        native_query::dormant_query(c, limit, offset)
    })
    .await
}

async fn get_followups(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<FollowupsQ>,
) -> Result<Response, ApiError> {
    let private_only = p.private_only.unwrap_or(false);
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    if matches!(
        p.mode
            .unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some()),
        native_query::EffectiveMode::Hot
    ) {
        let wxid = require_wxid(&st, &rid, p.account)?;
        http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
        let permit = hot_scan_permit(&rid, offset, limit).await?;
        let r = native_query::hot_followups(
            &wxid,
            st.wechat_data_dir.as_deref(),
            None,
            private_only,
            limit,
            offset,
            Some(permit),
        )
        .await
        .map_err(|e| map_core_err(&rid, &e))?;
        return Ok(envelope(&r));
    }
    cold(&st, &rid, p.account, move |c, _l1, _sha| {
        native_query::followups_query(c, private_only, limit, offset)
    })
    .await
}

async fn get_msgraw(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<MsgrawQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 20, 100);
    let offset = clamp_offset(p.offset);
    cold(&st, &rid, p.account, move |c, _l1, _sha| {
        native_query::msgraw_query(c, p.native_id.as_deref(), p.source.as_deref(), limit, offset)
    })
    .await
}

/// ⭐模板A (枚举参数式, 复用现有内核函数): `/extract` 结构化抽取。`kind` flatten 成内核枚举 → `extract_query`
/// (同 [`get_money`] 的 kind 模式)。build workflow 铺开同类端点照此: 参数结构 + 枚举 match + `cold` 闭包一行。
async fn get_extract(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<ExtractQ>,
) -> Result<Response, ApiError> {
    let kind = match p.kind.as_deref().unwrap_or("url") {
        "url" | "link" => native_query::ExtractKind::Url,
        "email" => native_query::ExtractKind::Email,
        "amount" => native_query::ExtractKind::Amount,
        "phone" => native_query::ExtractKind::Phone,
        "idcard" | "id" => native_query::ExtractKind::Idcard,
        other => {
            return Err(ApiError::bad_request(
                &rid,
                format!("kind 无效: {other} (url/email/amount/phone/idcard)"),
            ))
        }
    };
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    // R16-5: 冷热双模 (热走 hot_extract 全扫 msg1 + extract_matches)。
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
            let permit = hot_scan_permit(&rid, offset, limit).await?;
            let r = native_query::hot_extract(
                &wxid,
                st.wechat_data_dir.as_deref(),
                None,
                kind,
                limit,
                offset,
                Some(permit),
            )
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::extract_query(c, kind, limit, offset)
            })
            .await
        }
    }
}

/// `/moments/interactions` 朋友圈点赞评论 (**R16-3 起冷热双模**)。热走 `hot_interactions`(读 sns.db SnsTimeLine
/// 逐动态 parse_sns_interactions 抽赞/评, 同 get_moments 读源库非全库扫故无 scan_permit); 冷走 `cold_cmd` +
/// `CMD_INTERACTIONS`(registry run_query)。5 键对齐(create_time/kind/from_nickname/from_user/content)。
async fn get_moments_interactions(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_interactions(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_INTERACTIONS, limit, offset).await
        }
    }
}

/// `/moments/inbox` 朋友圈互动通知 (照模板B, 换 `CMD_SNS_NOTIFY`)。
async fn get_moments_inbox(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<HotPageQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    // R16-3 起冷热双模: 热走 hot_sns_notify (读 sns.db SnsMessage_tmp3, 读源库非全库扫故无 scan_permit);
    // 冷走 cold_cmd + CMD_SNS_NOTIFY (registry run_query)。5 键对齐。
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_sns_notify(&wxid, st.wechat_data_dir.as_deref(), limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold_cmd(&st, &rid, p.account, &native_query::CMD_SNS_NOTIFY, limit, offset).await
        }
    }
}

/// R9 复审 R2#7: `GET /api/v1/live-index/status` —— live-index 索引状态 (CLI `live-index status` 的 HTTP 对应)。
/// 报: `tier`(serve 起的档: full=实时监听 / off) · `live` · `message_fts_rows` · `incremental_triggers` ·
/// `message_total` · `indexed_through`(unix 秒 = L1 最新消息 `MAX(create_time)`; message-scoped 数据时刻, 非全源
/// floor —— R3#4)。**不 scoped**(索引是全库属性)。
async fn get_live_index_status(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(_): Qs<NoParams>,
) -> Result<Response, ApiError> {
    let l1 = require_l1(&st, &rid)?;
    let full = st.live_index_full;
    // R9 复审R3#3: live = 后台线程**真存活** (线程退出/崩溃 → alive=false); 不再拿启动期静态 full 假报。无信号 → false。
    let live = full
        && st
            .live_index_alive
            .as_ref()
            .is_some_and(|a| a.load(std::sync::atomic::Ordering::Relaxed));
    let rid2 = rid.clone();
    // R9 复审R3#3: DB 统计 (message count+MAX(create_time) 合一次全表扫 + FTS count) 下沉 spawn_blocking —— 别在 serve
    // current_thread async 线程内联跑, 大库会冻死唯一 async 线程 (连 /health 都不响应)。照 cold()/exec 范式。
    let joined = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, ApiError> {
        let conn = native_query::open_l1(&l1).map_err(|e| map_core_err(&rid2, &e))?;
        let triggers = native_core::storage::message_fts_triggers_exist(&conn);
        let fts_rows: i64 = conn
            .query_row("SELECT count(*) FROM message_fts", [], |r| r.get(0))
            .unwrap_or(-1);
        // R9 复审R3#4: indexed_through = L1 **最新消息数据时刻** MAX(create_time)/1000 (unix 秒; message-scoped, 非
        // 全源 floor)。旧版取 etl_state MIN(last_update) 是**墙钟** ingest 时刻非数据时刻、且只覆盖消息源 + 被休眠分片
        // 拖成假旧 → 谎报, 已撤。与 message_total 的 count **合一次全表扫** (SQLite 单次扫描同出 count + MAX, 不加扫)。
        // 此端点稀有 (显式健康检查) 可承受全表扫; per-query 冷查负担不起故只出 ingested_at (见 freshness.rs)。
        let (msg_total, ct_ms): (i64, Option<i64>) = conn
            .query_row("SELECT count(*), MAX(create_time) FROM message", [], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?))
            })
            .unwrap_or((-1, None));
        let indexed_through: Option<i64> = ct_ms.map(|ms| ms / 1000); // message.create_time 毫秒 (R6 归一 ×1000) → 秒。
        Ok(json!({
            "tier": if full { "full" } else { "off" },
            "live": live,
            "message_fts_rows": if fts_rows >= 0 { Some(fts_rows) } else { None },
            "incremental_triggers": triggers,
            "message_total": if msg_total >= 0 { Some(msg_total) } else { None },
            "indexed_through": indexed_through,
        }))
    })
    .await;
    match joined {
        Ok(Ok(v)) => {
            let r = native_query::QueryResult {
                data: vec![v],
                meta: native_query::Meta::page(1, 1).with_source(native_query::Source::Cold),
            };
            Ok(envelope(&r))
        }
        Ok(Err(e)) => Err(e),
        Err(je) => Err(ApiError::new(
            &rid,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("live-index status 任务失败: {je}"),
        )),
    }
}

/// `/accounts` 列库里可命名的账号 (§6; 消费者据此选 `?account=`)。**不 scoped** (要看全部账号) →
/// 直接 `open_l1` + `accounts_query`, 不走 `cold`/账号解析。无 offset (账号数少; accounts_query 无上限)。
async fn get_accounts(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(_): Qs<NoParams>,
) -> Result<Response, ApiError> {
    let l1 = require_l1(&st, &rid)?;
    let conn = native_query::open_l1(&l1).map_err(|e| map_core_err(&rid, &e))?;
    let mut r = native_query::accounts_query(&conn).map_err(|e| map_core_err(&rid, &e))?;
    // R6/R9 (审 R6-P2): /accounts 展**全部**账号 (非 scoped) → 全局 ingested_at (account_sha=None)。full → 据线程
    // 存活加全局 stale (R3#4)。判不出 (无 etl_state) → 不挂。
    attach_cold_freshness(&mut r, &l1, None, st.live_index_full, live_thread_alive(&st), None);
    Ok(envelope(&r))
}

/// `GET /api/v1/capture` (R19 选择性采集) — 看当前圈定采集哪些会话 (只读反映; 镜像 CLI `capture list` / MCP `wx_capture_list`)。
/// 空清单=全采。**只读服务不暴露写** —— 圈定/停采走 CLI `capture add/rm` (采集目标是本地配置; R20 config-CLI-only 先例)。
/// 账号: `?account=<wxid>` > 服务器默认; 单账号库自动解析; 多账号未指定 → 409 `AccountAmbiguous`。
async fn get_capture(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<AccountQ>,
) -> Result<Response, ApiError> {
    let l1 = require_l1(&st, &rid)?;
    let account = p.account.or_else(|| st.default_account.clone());
    let rid2 = rid.clone();
    // 审 round-9 codex P2: 冷查同步 sqlite **下沉 spawn_blocking + COLD 并发闸** —— capture_targets_query 内部
    // resolve_capture_account_sha → account_shas 对大 L1 做 DISTINCT 全表扫是阻塞 sqlite; serve 是 current_thread
    // runtime, 内联会钉死唯一 async 线程 (冻死所有 HTTP/SSE 处理 + --request-timeout-secs 的 timer 得不到 poll 无法
    // fire), 同其它冷端点 cold() 的 §9 加固。permit 移进闭包持到查完 (超时/断连丢 handler future 时后台 sqlite 不被
    // 取消仍在跑, 闸对真在跑的查询生效)。account 解析亦同步 sqlite, 一并进闭包。(capture_targets_query 自开 conn +
    // 自解析 union 账号, 不套 cold 的闭包形; scan 有界故不另加 progress_handler deadline。)
    let permit = COLD_SEMAPHORE.acquire().await.expect("cold semaphore 不会关闭");
    let joined = tokio::task::spawn_blocking(move || -> Result<native_query::QueryResult, ApiError> {
        let _permit = permit; // 持到本闭包(查询)结束 → 并发闸对"真在跑的查询"生效。
                              // 一站式解析账号 + 读清单 (空库无账号 → 空清单; 多账号未指定 → AccountAmbiguous→409)。
        native_query::capture_targets_query(&l1, account).map_err(|e| map_core_err(&rid2, &e))
    })
    .await;
    match joined {
        Ok(Ok(r)) => Ok(envelope(&r)),
        Ok(Err(e)) => Err(e),
        Err(je) => Err(ApiError::new(
            &rid,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("采集清单查询任务失败: {je}"),
        )),
    }
}

/// `/names` GET 小批量 wxid→显示名 (内核 §5b)。`ids` 逗号分隔 (≤100; 大批量走 POST, 后续 C 组随 exec POST 落
/// —— POST body 的 §5 错误契约与 exec 一起做)。空/超限 → 400。
async fn get_names(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<NamesQ>,
) -> Result<Response, ApiError> {
    let ids_raw = p.ids.unwrap_or_default();
    // §9: ids 取 owned (Vec<String>) —— cold 闭包下沉 spawn_blocking 需 'static, 借 ids_raw 的 &str 活不到。
    let ids: Vec<String> = ids_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if ids.is_empty() {
        return Err(ApiError::bad_request(
            &rid,
            "names 需要 ?ids=wxid1,wxid2 (逗号分隔, ≤100)",
        ));
    }
    if ids.len() > 100 {
        // 审查 C NAMES-JB-01/F2: POST /names 已上线 (C①) → 提示指向它 (原"后续版本提供"已陈旧)。
        return Err(ApiError::bad_request(
            &rid,
            format!(
                "ids 过多 ({}); GET 上限 100; 大批量用 POST /api/v1/names (body ids[], ≤200)",
                ids.len()
            ),
        ));
    }
    // R16-6 双模: hot 读源库 contact.db 名字 (无需 scan_permit —— read_hot_contacts 是 SQL 读非全消息扫)。
    if matches!(
        p.mode
            .unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some()),
        native_query::EffectiveMode::Hot
    ) {
        let wxid = require_wxid(&st, &rid, p.account)?;
        let r = native_query::hot_resolve_names(&wxid, st.wechat_data_dir.as_deref(), &ids)
            .await
            .map_err(|e| map_core_err(&rid, &e))?;
        return Ok(envelope(&r));
    }
    cold(&st, &rid, p.account, move |c, _l1, _sha| {
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        native_query::resolve_names_query(c, &refs)
    })
    .await
}

/// `/names` POST 大批量 wxid→显示名 (body `{account?, ids[]}` ≤200; §6b)。共用 resolve_names_query 核; body 用
/// `Jb` 提取 (§5: 错 Content-Type→415, 坏 JSON/未知字段→400)。Jb 是 body 提取器故须是 handler **最后**一参。
async fn post_names(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Jb(body): Jb<NamesReq>,
) -> Result<Response, ApiError> {
    // 审查 C NAMES-JB-02: trim 对齐 GET (get_names 也 trim), 免同一 wxid 带空白在 POST/GET 结果分叉。
    let ids: Vec<String> = body
        .ids
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if ids.is_empty() {
        return Err(ApiError::bad_request(&rid, "names 需要 ids[] (非空 wxid 数组)"));
    }
    if ids.len() > 200 {
        return Err(ApiError::bad_request(
            &rid,
            format!("ids 过多 ({}); POST 上限 200", ids.len()),
        ));
    }
    cold(&st, &rid, body.account, move |c, _l1, _sha| {
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        native_query::resolve_names_query(c, &refs)
    })
    .await
}

// exec 硬只读机制 (SQLITE_OPEN_READ_ONLY 只读连接 + authorizer 白名单拒 ATTACH/PRAGMA + set_limit 单值 8MB +
// progress 15s 算力界) 已抽进 **native_query::exec_hardened** (R7/⑪: HTTP `/exec` 与 MCP `wx_exec` 同一份安全码,
// 免分叉 —— 改一处漏另一处即安全洞)。本皮 `post_exec` 在 spawn_blocking 里调它; 第 1 层 is_readonly_sql
// pre-check **仍留 handler** (须在开库前拒, 对齐 "写 SQL 不打库即 BAD_REQUEST" 契约) + 下面 EXEC_SEMAPHORE 并发闸。

/// exec 并发上限 (审查 C round4): exec 单请求 RAM 有界 (~64MB raw × 有界常数), 但无并发闸时 N 并行 → 宿主 OOM。
/// 信号量限 4 并发 exec → 全局 exec RAM 有界; 第 5+ 请求 await 排队 (只占小请求态, 非结果内存)。
static EXEC_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// R5 复审 P1#2: search 并发上限。search 未建索引/query<3字 → message 全表 LIKE 扫 (大库慢); spawn_blocking offload
/// 后**请求超时只停等待、后台 SQL 扫描不被取消** → 连发多个短词搜索可堆积大量全表扫吃满 CPU/磁盘。限 4 并发 (permit
/// 移进 spawn_blocking 持到扫描真跑完, 同 exec) + 每查 30s progress deadline (让扫描自停) 双闸兜。
static SEARCH_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// R6 复审 P1: 通用冷查 (cold/cold_cmd; stats GROUP BY 全表扫 / followups WITH+JOIN / biz COUNT 等重查都走这) 的并发
/// 上限。原只 spawn_blocking 无独立许可 → 请求超时 (--request-timeout-secs) 只丢 handler future, 后台 SQLite **不被取消**
/// 仍在跑; 连发多个重查可堆积后台任务占满阻塞池 + CPU/IO。限 8 并发 (permit 移进 spawn_blocking 持到查询真跑完, 同
/// exec/search) + cold() 每查 30s progress deadline (掐无界扫描)。8 比 exec/search 的 4 宽 —— 冷查是主流量、多数快。
static COLD_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// R16-2 (codex 3a10c84 P1): **热查全库扫**并发闸。`mode=hot` 的 events/calls(及后续 message 分片派生)走
/// `scan_all_messages` 同步扫**所有消息分片**(大账号 16-48s + 每 `SourceQuery` 数百 MB 页缓存/sender 图)。
/// 请求超时/断连丢 handler future 时 spawn_blocking **不被取消**仍在跑 → 连发会堆积多个巨扫耗尽内存/阻塞池。
/// 限 **2** 并发(远比冷查 8 紧: 热扫内存重、量小、非主流量; permit 移进 hot_* 的 spawn_blocking 持到扫真跑完)。
/// ⚠️ 暂无 per-scan cooperative deadline(scan_all_messages 是多分片 Rust 循环非单 SQLite 查, progress_handler
/// 不直接适用)—— 靠此闸把并发巨扫封在 2 个内, 内存有界; deadline 早停留后续硬化(见 hot.rs 头注)。
static HOT_SCAN_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// 取热扫 permit 前先校验翻页窗口 (codex/Claude d416553): offset+limit 超窗则 400 **拒, 不占 permit** ——
/// 否则超窗坏请求会先占 permit(挤合法扫)+ 进 spawn_blocking 开库 build ~秒才拒。kernel 入口也 check_hot_window
/// 兜底(CLI/MCP 路径), 本处让 HTTP 在取稀缺 permit 前就拒。深翻页/全量走 --mode cold(L1 无内存上限)。
async fn hot_scan_permit(
    rid: &RequestId,
    offset: usize,
    limit: usize,
) -> Result<tokio::sync::SemaphorePermit<'static>, ApiError> {
    native_query::check_hot_window(offset, limit).map_err(|e| map_core_err(rid, &e))?;
    Ok(HOT_SCAN_SEMAPHORE.acquire().await.expect("hot-scan semaphore 不会关闭"))
}

/// R21 全扫成本门（HTTP 皮）—— 三皮共享核 [`native_query::full_scan_cost_gate`] 的 HTTP 呈现。**`Blocked`
/// （超强制阈值且无 `?confirm=true`）→ 400 BadRequest**; 窗口越界 → `map_core_err`; 其余（Silent/Hint/
/// ConfirmedProceed）→ `Ok(())` 放行。全扫端点在取 [`hot_scan_permit`] **前**调本门（别为跑不了的查占稀缺 permit）。
///
/// **MCP/HTTP 只硬拦 `Blocked`**（多分钟全扫）; 软 `Hint`（会跑完但慢）不打断 —— 非交互皮无 stderr, 硬门已达
/// R21 专防"盲发多分钟全扫"目的（三皮对等的是**硬门**）。`biz`（scan_conversations gh_ 子集）**不调**（同 CLI 排除）。
async fn http_cost_gate(
    st: &AppState,
    rid: &RequestId,
    wxid: &native_core::Wxid,
    offset: usize,
    limit: usize,
    confirm: bool,
) -> Result<(), ApiError> {
    use native_core::query_planner::profile::GateOutcome;
    let report = native_query::full_scan_cost_gate(wxid, st.wechat_data_dir.as_deref(), offset, limit, confirm)
        .await
        .map_err(|e| map_core_err(rid, &e))?; // check_hot_window 越界等
    if matches!(report.outcome, GateOutcome::Blocked { .. }) {
        return Err(ApiError::bad_request(
            rid,
            format!(
                "该查询要全扫 {} 个 message 分片、估算 {} 秒 ({}); 加 ?confirm=true 强制执行, 或先对该账号建 L1 库后用 mode=cold (走索引, ms 级)",
                report.shard_count,
                report.estimated_secs(),
                report.profile_label()
            ),
        ));
    }
    Ok(())
}

/// biz(公众号 gh_ 消息)冷热双模派发 —— **两入口共用**(`?kind=biz` + `?conv_type=official` 别名)。热走 hot_biz
/// (scan_conversations("gh_") 会话层前缀过滤), 冷走 biz_query。默认 Auto(有 L1 冷否则热)。
async fn biz_dispatch(
    st: &Shared,
    rid: &RequestId,
    account: Option<String>,
    mode: Option<native_query::QueryMode>,
    offset: usize,
    limit: usize,
) -> Result<Response, ApiError> {
    match mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(st, rid, account)?;
            let permit = hot_scan_permit(rid, offset, limit).await?;
            let r = native_query::hot_biz(&wxid, st.wechat_data_dir.as_deref(), None, limit, offset, Some(permit))
                .await
                .map_err(|e| map_core_err(rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(st, rid, account, move |c, _l1, _sha| {
                native_query::biz_query(c, limit, offset)
            })
            .await
        }
    }
}

/// thread(引用回复, appmsg type57 有 refer_svrid)冷热双模派发 —— `?quote=true` 选择器用。热走 hot_thread
/// (scan_all_messages base_types=[49] + parse_appmsg 取有 refer_svrid 的, sender 走路径A), 冷走 thread_query。
/// 默认 Auto(有 L1 冷否则热)。镜像 biz_dispatch。
async fn thread_dispatch(
    st: &Shared,
    rid: &RequestId,
    account: Option<String>,
    mode: Option<native_query::QueryMode>,
    offset: usize,
    limit: usize,
    confirm: bool,
) -> Result<Response, ApiError> {
    match mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(st, rid, account)?;
            http_cost_gate(st, rid, &wxid, offset, limit, confirm).await?;
            let permit = hot_scan_permit(rid, offset, limit).await?;
            let r = native_query::hot_thread(&wxid, st.wechat_data_dir.as_deref(), None, limit, offset, Some(permit))
                .await
                .map_err(|e| map_core_err(rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(st, rid, account, move |c, _l1, _sha| {
                native_query::thread_query(c, limit, offset)
            })
            .await
        }
    }
}

/// resolve(合并转发展开)冷热双模派发 —— `?kind=forward` 用。**双模式**: `msg_id=Some` 展开该条子项 /
/// `msg_id=None` 列所有转发。热走 hot_resolve(scan msg49 + parse_forward), 冷走 resolve_query。默认 Auto。
/// 展开模式查无子项 → NotFound(404, 冷热一致)。镜像 biz_dispatch/thread_dispatch。
async fn resolve_dispatch(
    st: &Shared,
    rid: &RequestId,
    account: Option<String>,
    msg_id: Option<String>,
    source: Option<String>,
    mode: Option<native_query::QueryMode>,
    offset: usize,
    limit: usize,
    confirm: bool,
) -> Result<Response, ApiError> {
    match mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(st, rid, account)?;
            http_cost_gate(st, rid, &wxid, offset, limit, confirm).await?;
            let permit = hot_scan_permit(rid, offset, limit).await?;
            let r = native_query::hot_resolve(
                &wxid,
                st.wechat_data_dir.as_deref(),
                None,
                msg_id.as_deref(),
                source.as_deref(),
                limit,
                offset,
                Some(permit),
            )
            .await
            .map_err(|e| map_core_err(rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(st, rid, account, move |c, _l1, _sha| {
                native_query::resolve_query(c, msg_id.as_deref(), source.as_deref(), limit, offset)
            })
            .await
        }
    }
}

/// R6 复审 P1: 冷查 SQLite 单查算力界 (照 exec 15s / search 30s 范式)。全表 GROUP BY / 无索引扫描无界 → progress_handler
/// 到期返 SQLITE_INTERRUPT。给 cold() 用 (cold_cmd 的 run_query 是 LIMIT/OFFSET 有界, 主要靠并发闸)。
const COLD_QUERY_DEADLINE_SECS: u64 = 30;

/// `/exec` POST 只读 SQL (§6): **硬只读三层** —— (1) `is_readonly_sql` 字符串预检 (SELECT/WITH/EXPLAIN + 无多语句,
/// 开库**前**拒), (2) `SQLITE_OPEN_READ_ONLY` 连接 (挡写), (3) authorizer 拒 ATTACH/PRAGMA (readonly 挡不住的逃逸)
/// + max_rows 界 (防无界)。打 serve 绑定的 L1 (非源库)。**非 scoped** (裸 SQL 逃生口; 多账号库跨账号操作者自负)。
async fn post_exec(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Jb(body): Jb<ExecReq>,
) -> Result<Response, ApiError> {
    let sql = body.sql.trim().to_string();
    if sql.is_empty() {
        return Err(ApiError::bad_request(&rid, "exec 需要 sql (只读 SELECT/WITH/EXPLAIN)"));
    }
    // 层1: 字符串预检 (开库前拒明显写/多语句)。
    if !native_query::is_readonly_sql(&sql) {
        return Err(ApiError::bad_request(
            &rid,
            "只读 exec 仅允许单条 SELECT/WITH/EXPLAIN (无写操作, 无多语句 ';')",
        ));
    }
    let max_rows = body.max_rows.unwrap_or(1000).clamp(1, 10_000);
    // R16-6 双模: 热查直查加密源库原始裸 schema (hot_exec → exec_hardened_vfs, source_db 选库); 冷查 L1 投影库。
    if matches!(
        body.mode
            .unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some()),
        native_query::EffectiveMode::Hot
    ) {
        let Some(source_db) = body.source_db.as_deref().filter(|s| !s.is_empty()) else {
            return Err(ApiError::bad_request(
                &rid,
                "热查 exec (mode=hot) 要 source_db (源库相对路径, 如 contact/contact.db / message/message_0.db)",
            ));
        };
        let wxid = require_wxid(&st, &rid, body.account.clone())?;
        // 并发闸 permit 传进 hot_exec 的 scan_permit (hot_exec 内 spawn_blocking 持到真跑完, 不随 future 取消提前释放)。
        let permit = EXEC_SEMAPHORE.acquire().await.expect("exec semaphore 不会关闭");
        let r = native_query::hot_exec(
            &wxid,
            st.wechat_data_dir.as_deref(),
            source_db,
            &sql,
            max_rows,
            Some(permit),
        )
        .await
        .map_err(|e| map_core_err(&rid, &e))?;
        return Ok(envelope(&r));
    }
    let l1 = require_l1(&st, &rid)?;
    // 审查 C round4 并发闸: exec 单请求 RAM 有界但 N 并行会 OOM 宿主 → 限 4 并发, 持 permit 到本函数结束 (含
    // spawn_blocking 期); 第 5+ 请求 await 排队 (只占小请求态非结果内存)。permit 在函数返回时随 _permit 释放。
    let permit = EXEC_SEMAPHORE.acquire().await.expect("exec semaphore 不会关闭");
    // 层2+3 + 隔离: 审查 C EXEC-DOS-CPU —— serve 是 current_thread runtime, 同步 sqlite 若无界会钉死唯一 async
    // 线程冻死全服务 (含 /health)。移到 spawn_blocking 阻塞池 (async 线程不被占) + open_l1_readonly 的 progress 15s 界。
    let joined = tokio::task::spawn_blocking(move || {
        // §9 审: permit 移进闭包持到真跑完 —— 超时(--request-timeout-secs)/断连丢 handler future 时, spawn_blocking
        // SQL **不被取消**仍在跑; 若 permit 在 async 作用域会提前释放 → 并发闸(4)被打穿 → 宿主 OOM。照 media 范式。
        let _permit = permit;
        // 硬只读三层 + DoS 界 (readonly-open / authorizer / set_limit 8MB / progress 15s) 全在 exec_hardened
        // (R7 抽共享)。观察行为与原 open_l1_readonly + exec_query 一致 —— exec_hardened 内多一道 is_readonly_sql
        // 预检, 但本 handler 上面 (require_l1 前) 已 pre-check 过, 对已过检的 sql 是恒真 no-op, 不改 HTTP 任何响应。
        native_query::exec_hardened(&l1, &sql, max_rows)
    })
    .await;
    let r = match joined {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(map_core_err(&rid, &e)),
        Err(join_e) => {
            return Err(ApiError::new(
                &rid,
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                format!("exec 任务失败: {join_e}"),
            ))
        }
    };
    Ok(envelope(&r))
}

// ─────────────────────────────────────────────────────────────────
// /media/{key} — 媒体即时取用 (§8): 类型键定位 → 解密/读盘 → 字节流 (Range/HEAD/?info)。
// 本增量先通**语音** (media_0.db 单库最简竖切, 按需 VFS 只解碰到的页); vid:/img: 识别但 501
// (下件补"分片原始行"内核口子); emoji:/moment: (联网 CDN) 随其件加入 parser。
// ─────────────────────────────────────────────────────────────────

/// `/media/{key}` 查询参数。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MediaQ {
    /// 账号 (多账号库需给; 单账号可省, 退服务器默认 `--wxid`)。
    account: Option<String>,
    /// `?info=1`: 返元数据 JSON (kind/content_type/length) 不返字节 (前端预取/探测); 任意非空值即启用。
    info: Option<String>,
}

/// 媒体键 (path `/media/{key}`): 类型前缀 + 定位参数。本增量 parser 认三类本地媒体; 联网类 (emoji/moment)
/// 随其件加入。`vid`/`img` 需内核"分片原始行"口子 (下件), 现 handler 先 501。
enum MediaKey {
    /// 语音: `voice:<svr_id>` (media_0.db/`VoiceInfo` 直查, svr_id 真库唯一)。
    Voice { svr_id: i64 },
    /// 视频: `vid:<md5>` (md5 = 冷投影 `message_media.md5` = hardlink 索引键; 只开 hardlink 定位磁盘明文 .mp4)。
    Video { md5: String },
    /// 图片: `img:<talker_md5>:<local_id>` (读 message 分片行取 packed_info md5 → resolve_image → .dat 解密)。
    Image { talker_md5: String, local_id: i64 },
    /// 表情包: `emoji:<md5>` (读 emoticon.db 取 aes_key+CDN url → **联网下载** → AES-CBC 解; 本地不存)。
    Emoji { md5: String },
    /// 朋友圈媒体: `moment:<source_native_id>:<media_seq>` (读 L1 moment_media 取 CDN url+key → **联网下载** →
    /// WxIsaac64 XOR 解 [enc_idx=1, 需 node]; 本地不存)。source_native_id=`Sns_<tid>`, media_seq=mediaList 序号。
    Moment { source_native_id: String, media_seq: i64 },
}

/// 解析媒体键 (前缀分发); malformed → 400。
fn parse_media_key(key: &str, rid: &RequestId) -> Result<MediaKey, ApiError> {
    if let Some(rest) = key.strip_prefix("voice:") {
        let svr_id = rest
            .parse::<i64>()
            .map_err(|_| ApiError::bad_request(rid, "voice 键须 voice:<svr_id> (svr_id 为整数)"))?;
        return Ok(MediaKey::Voice { svr_id });
    }
    if let Some(rest) = key.strip_prefix("vid:") {
        // md5 = 32-hex (防注入 + 是 hardlink 键); 规整小写 (WeChat md5 小写)。
        if rest.len() == 32 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(MediaKey::Video {
                md5: rest.to_ascii_lowercase(),
            });
        }
        return Err(ApiError::bad_request(
            rid,
            "vid 键须 vid:<md5> (32-hex 视频内容 md5; 见冷投影 message_media.md5)",
        ));
    }
    if let Some(rest) = key.strip_prefix("img:") {
        // img:<talker_md5>:<local_id>
        if let Some((md5, lid)) = rest.split_once(':') {
            if md5.len() == 32 && md5.bytes().all(|b| b.is_ascii_hexdigit()) {
                if let Ok(local_id) = lid.parse::<i64>() {
                    return Ok(MediaKey::Image {
                        talker_md5: md5.to_ascii_lowercase(),
                        local_id,
                    });
                }
            }
        }
        return Err(ApiError::bad_request(
            rid,
            "img 键须 img:<talker_md5>:<local_id> (talker 32-hex 会话 md5, local_id 整数)",
        ));
    }
    if let Some(rest) = key.strip_prefix("emoji:") {
        // emoji:<md5> (32-hex 表情内容 md5; 匹配 emoticon.db kNonStoreEmoticonTable.md5)。
        if rest.len() == 32 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(MediaKey::Emoji {
                md5: rest.to_ascii_lowercase(),
            });
        }
        return Err(ApiError::bad_request(rid, "emoji 键须 emoji:<md5> (32-hex 表情 md5)"));
    }
    if let Some(rest) = key.strip_prefix("moment:") {
        // moment:<source_native_id>:<media_seq> —— 末个 ':' 前是 moment PK (Sns_<tid>, 不含 ':'), 后是 seq 整数。
        if let Some((sid, seq)) = rest.rsplit_once(':') {
            if let (false, Ok(media_seq)) = (sid.is_empty(), seq.parse::<i64>()) {
                return Ok(MediaKey::Moment {
                    source_native_id: sid.to_string(),
                    media_seq,
                });
            }
        }
        return Err(ApiError::bad_request(
            rid,
            "moment 键须 moment:<source_native_id>:<media_seq> (source_native_id=Sns_<tid>, media_seq 整数)",
        ));
    }
    Err(ApiError::bad_request(
        rid,
        "media 键须 voice:<svr_id> / vid:<md5> / img:<talker_md5>:<local_id> / emoji:<md5> / moment:<sid>:<seq>",
    ))
}

/// 单区间 Range 解析结果。
enum RangeResult {
    /// 无 Range / 不解析 (多区间 / 非 bytes 单位 / 值溢出) → 200 全量。
    Full,
    /// 命中单闭区间 `[start, end]` (均 < total) → 206。
    Partial { start: usize, end: usize },
    /// 语法合法但不可满足 (start ≥ total / 空 body / suffix=0) → 416。
    Unsatisfiable,
}

/// 解析 HTTP Range (只支持单区间 `bytes=a-b` / `bytes=a-` / `bytes=-suffix`; 多区间/非法单位/溢出 → 全量)。
/// 全程 usize (值直接 parse 成 usize, 溢出即当非法 → Full), 无 `as` 截断转换。
fn parse_single_byte_range(spec: &str, total: usize) -> RangeResult {
    let Some(rest) = spec.trim().strip_prefix("bytes=") else {
        return RangeResult::Full;
    };
    if rest.contains(',') {
        return RangeResult::Full; // 多区间 (multipart/byteranges) 不支持 → 退全量
    }
    let Some((a, b)) = rest.split_once('-') else {
        return RangeResult::Full;
    };
    let (a, b) = (a.trim(), b.trim());
    if total == 0 {
        return RangeResult::Unsatisfiable; // 空 body 任何区间都不可满足
    }
    let (start, end) = if a.is_empty() {
        // `-suffix`: 末尾 suffix 字节。
        let Ok(suffix) = b.parse::<usize>() else {
            return RangeResult::Full;
        };
        if suffix == 0 {
            return RangeResult::Unsatisfiable;
        }
        (total.saturating_sub(suffix), total - 1)
    } else {
        let Ok(start) = a.parse::<usize>() else {
            return RangeResult::Full;
        };
        let end = if b.is_empty() {
            total - 1
        } else {
            match b.parse::<usize>() {
                Ok(e) => e.min(total - 1), // 末端超界夹到 total-1 (HTTP 语义)
                Err(_) => return RangeResult::Full,
            }
        };
        (start, end)
    };
    if start > end || start >= total {
        return RangeResult::Unsatisfiable;
    }
    RangeResult::Partial { start, end }
}

/// 内存字节媒体响应 (voice/image 已解出的字节; video 大文件走文件级流不经此)。Range 命中 → 206 +
/// `Content-Range`; 无/不解析 → 200 全量; 不可满足 → 416 + `Content-Range: bytes */total`。`Accept-Ranges: bytes`
/// 恒发。HEAD 由 axum 自动去 body。X-Request-Id 由中间件补。Content-Length 由 axum 从 body 长度自动计。
fn media_bytes_response(body: Vec<u8>, content_type: &str, range: Option<&HeaderValue>) -> Response {
    use axum::http::header;
    let total = body.len();
    let result = range
        .and_then(|h| h.to_str().ok())
        .map_or(RangeResult::Full, |s| parse_single_byte_range(s, total));
    // X-Content-Type-Options: nosniff —— 媒体字节来自 CDN (observed content) + wxgf 缺 ffmpeg 时退 octet-stream,
    // 防浏览器 MIME 嗅探把边界类型当可执行 (§8 critic 纵深防御)。
    match result {
        RangeResult::Full => (
            [
                (header::CONTENT_TYPE, content_type.to_string()),
                (header::ACCEPT_RANGES, "bytes".to_string()),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            ],
            body,
        )
            .into_response(),
        RangeResult::Partial { start, end } => {
            // Range 覆盖全体 (start=0 且 end=total-1, 如浏览器 <video> 恒发的 bytes=0-) → 直接 move body 不复制
            // (§8: 省一份 ≤100MB 朋友圈视频拷贝, 峰值不翻倍); 真子区间才切片。start/end 均 < total → get 恒 Some。
            let payload = if start == 0 && end + 1 == total {
                body
            } else {
                body.get(start..=end).map(<[u8]>::to_vec).unwrap_or_default()
            };
            (
                StatusCode::PARTIAL_CONTENT,
                [
                    (header::CONTENT_TYPE, content_type.to_string()),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                    (header::CONTENT_RANGE, format!("bytes {start}-{end}/{total}")),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                ],
                payload,
            )
                .into_response()
        }
        RangeResult::Unsatisfiable => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            [(header::CONTENT_RANGE, format!("bytes */{total}"))],
        )
            .into_response(),
    }
}

/// `/media` 并发解密闸 (仿 EXEC/EVENTS_SEMAPHORE): 每次开加密库 VFS 页缓存有界内存, N 并行受此闸约束;
/// 持 permit 到 spawn_blocking 结束。**值 > 浏览器 per-host≈6** (drive-by 单主机名打不满饿死正常用户; 见 /events 注)。
static MEDIA_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);

/// 联网出口闸 (§9): 表情/朋友圈从 CDN 下载的并发上限 —— **独立于 [`MEDIA_SEMAPHORE`]** (本地解密闸)。慢/失效
/// CDN 只占本闸, 不拖 voice/image/video 本地媒体请求 (egress head-of-line 修)。值小些 (联网并发不宜多; 8)。
static EGRESS_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// `/media/{key}` — 媒体即时取用 (§8)。类型键**分发** → 定位/解密/读盘 → 字节流 (Range/HEAD/?info)。
/// **语音** `voice:<svr_id>`(枚举 media_N.db 分片 × VoiceInfo% 表 VFS 解密, 命中即返)· **视频** `vid:<md5>`
/// (md5=冷投影 message_media.md5 → hardlink 定位磁盘**明文 .mp4** → 文件级 Range 流, 视频不解密)· **图片** `img:…` 501 建设中。
///
/// **本地闸**: 媒体天然被 `<img>`/`<audio>`/`<video>` (永远 no-cors) 消费 → **不能**像 /events 拒 no-cors。只上
/// **Host 须 loopback** 挡 DNS-rebinding; drive-by 受浏览器 per-host cap + MEDIA_SEMAPHORE 兜 (响应 opaque 读不到)。
async fn get_media(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Qs(p): Qs<MediaQ>,
) -> Result<Response, ApiError> {
    // Host 须 loopback (挡 DNS-rebinding drive-by; 不拒 no-cors —— 媒体天然 no-cors 消费)。
    if headers.get("host").is_some_and(|h| !is_loopback_host(h.as_bytes())) {
        return Err(ApiError::new(
            &rid,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "跨源/非本机请求被拒 (Host); /media 仅限本机",
        ));
    }
    match parse_media_key(&key, &rid)? {
        MediaKey::Voice { svr_id } => serve_voice(&st, &rid, svr_id, &p, &headers).await,
        MediaKey::Video { md5 } => serve_video(&st, &rid, &md5, &p, &headers).await,
        MediaKey::Image { talker_md5, local_id } => serve_image(&st, &rid, &talker_md5, local_id, &p, &headers).await,
        MediaKey::Emoji { md5 } => serve_emoji(&st, &rid, &md5, &p, &headers).await,
        MediaKey::Moment {
            source_native_id,
            media_seq,
        } => serve_moment(&st, &rid, &source_native_id, media_seq, &p, &headers).await,
    }
}

/// `DecodedImage.format` → HTTP Content-Type。wxgf 动图容器 (内层 HEVC) 由 `transcode_if_wxgf` 当场转 GIF/PNG,
/// 本函数不经手 wxgf 正常路 (仅在 ffmpeg 缺/转失败时作 octet-stream 兜底; 同 Unknown)。
fn image_content_type(fmt: native_core::decoder::DatFormat) -> &'static str {
    use native_core::decoder::DatFormat;
    match fmt {
        DatFormat::Jpg => "image/jpeg",
        DatFormat::Png => "image/png",
        DatFormat::Gif => "image/gif",
        DatFormat::Webp => "image/webp",
        DatFormat::Bmp => "image/bmp",
        DatFormat::Wxgf | DatFormat::Unknown => "application/octet-stream",
    }
}

/// `img:<talker_md5>:<local_id>` —— 枚举全部 message_N.db 分片 (按 [`db_shard_files`] 防漏) 逐库 VFS 开 →
/// `fetch_image_one`(读该行 packed_info → resolve_image → 探 .dat → decrypt_dat)取第一张解得开的 → 解码后字节
/// 出 `media_bytes_response`(支持 Range/HEAD)。**image key**: 从独立 `ImageKeyCache` 取该账号 aes —— 有则解 **V2
/// 完整图**, 无则 V2 候选解不开自然退到 **V0 缩略图**(单字节 XOR 自推, 不需 key; 真库多数图只留缩略图)。V1/明文也不需 key。
async fn serve_image(
    st: &AppState,
    rid: &RequestId,
    talker_md5: &str,
    local_id: i64,
    p: &MediaQ,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let wxid = require_wxid(st, rid, p.account.clone())?;
    let db_storage = native_query::resolve_db_storage_dir(st.wechat_data_dir.as_deref(), &wxid)
        .map_err(|e| map_core_err(rid, &e))?;
    // account_dir (msg/attach/… 所在) = db_storage 的父; message 分片 = db_storage/message/message_<N>.db。
    let account_dir = db_storage
        .parent()
        .map_or_else(|| db_storage.clone(), std::path::Path::to_path_buf);
    let shards = native_query::db_shard_files(&db_storage.join("message"), "message");
    if shards.is_empty() {
        return Err(ApiError::new(
            rid,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "该账号无 message_*.db 分片",
        ));
    }
    let db_key = native_query::cache_key(&wxid)
        .await
        .map_err(|e| map_core_err(rid, &e))?;
    let talker = talker_md5.to_string();
    let permit = MEDIA_SEMAPHORE.acquire().await.expect("media semaphore 不会关闭");
    let joined = tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<(Vec<u8>, native_core::decoder::DatFormat)>> {
            let _permit = permit; // §8 P3: 持 permit 到 spawn_blocking 真跑完 (断连不提前释放, 见 serve_voice 注)
                                  // image key (V2 完整图解密): 独立 image cache 取该账号 aes+xor; 无 → None (只出 V0 缩略图/V1/明文)。
                                  // §8 P3 (blocking-async-executor): cache 读文件 + DPAPI 解密是同步 IO, 放进 spawn_blocking 别在
                                  // serve 的 current_thread async 线程上跑 (否则慢盘/大 image_keys.enc 冻死唯一 async 线程含 /health)。
            let image_key = native_core::ImageKeyCache::new(None).resolve(&wxid).ok().flatten();
            // 逐 message 分片 VFS 开库 + 查该会话行 (跨分片全局唯一, 命中即返)。有 image key 解 V2 完整图否则退缩略图。
            for shard in &shards {
                let conn = native_core::cipher::open_decrypted_db_vfs(shard, &db_key)
                    .map_err(|e| anyhow::anyhow!("开 message 分片失败: {e}"))?;
                if let Some(img) =
                    native_core::media::fetch_image_one(&conn, &account_dir, image_key.as_ref(), &talker, local_id)?
                {
                    return Ok(Some((img.bytes, img.format)));
                }
            }
            Ok(None)
        },
    )
    .await;
    let (bytes, fmt) = match joined {
        Ok(Ok(Some(v))) => v,
        Ok(Ok(None)) => {
            return Err(ApiError::new(
                rid,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "图片不存在 / 无法解码 (已清理, 或 V2 完整图需 image key)",
            ))
        }
        Ok(Err(e)) => return Err(map_core_err(rid, &e)),
        Err(join_e) => {
            return Err(ApiError::new(
                rid,
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                format!("媒体任务失败: {join_e}"),
            ))
        }
    };
    // wxgf 动图/静图 → 当场转 GIF/PNG (需 ffmpeg; 缺则 octet-stream 不丢)。非 wxgf 原样出 image_content_type。
    let (out, ct) = transcode_if_wxgf(st, bytes, fmt).await;
    if p.info.is_some() {
        return Ok(Json(json!({ "kind": "image", "content_type": ct, "length": out.len() })).into_response());
    }
    Ok(media_bytes_response(out, ct, headers.get(axum::http::header::RANGE)))
}

/// `voice:<svr_id>` —— 枚举全部 media_N.db 分片 (文件级) × VoiceInfo% 表 (表级) 按需 VFS 解密取语音 WAV
/// (svr_id 跨分片全局唯一, 命中即返)。重活 (VFS 解密 + SILK) 下沉 spawn_blocking。`?info=1` 返元数据。
async fn serve_voice(
    st: &AppState,
    rid: &RequestId,
    svr_id: i64,
    p: &MediaQ,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    // 账号 → db_storage/message/ 下**全部** media_<N>.db (真库实证媒体库文件级分片; 只开 media_0.db 漏后续 = 丢数据)。
    let wxid = require_wxid(st, rid, p.account.clone())?;
    let msg_dir =
        native_query::resolve_message_dir(st.wechat_data_dir.as_deref(), &wxid).map_err(|e| map_core_err(rid, &e))?;
    let media_dbs = native_query::media_db_files(&msg_dir);
    if media_dbs.is_empty() {
        return Err(ApiError::new(
            rid,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "该账号无 media_*.db 语音库 (未产生过语音?)",
        ));
    }
    let db_key = native_query::cache_key(&wxid)
        .await
        .map_err(|e| map_core_err(rid, &e))?;
    let permit = MEDIA_SEMAPHORE.acquire().await.expect("media semaphore 不会关闭");
    let joined = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<u8>>> {
        // §8 P3: permit 移进闭包持到真跑完 —— 客户端断连丢弃 handler future 时 spawn_blocking 任务**不被取消**仍在跑,
        // permit 若留在 handler 作用域会随 future 提前释放 → 并发闸失效 (在跑解密任务数超 16)。移进闭包 = 闸真兜住在跑量。
        let _permit = permit;
        // 逐 media 分片 VFS 开库 (只解碰到的页, 非整库驻留) + 查 svr_id (命中即返)。都无 → None。快照口径。
        for media_db in &media_dbs {
            let conn = native_core::cipher::open_decrypted_db_vfs(media_db, &db_key)
                .map_err(|e| anyhow::anyhow!("开语音库失败: {e}"))?;
            if let Some(wav) = native_core::media::fetch_voice_wav(&conn, svr_id)? {
                return Ok(Some(wav));
            }
        }
        Ok(None)
    })
    .await;
    let wav = match joined {
        Ok(Ok(Some(wav))) => wav,
        Ok(Ok(None)) => {
            return Err(ApiError::new(
                rid,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                format!("语音不存在 / 无法解码 (voice:{svr_id})"),
            ))
        }
        Ok(Err(e)) => return Err(map_core_err(rid, &e)),
        Err(join_e) => {
            return Err(ApiError::new(
                rid,
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                format!("媒体任务失败: {join_e}"),
            ))
        }
    };
    if p.info.is_some() {
        return Ok(Json(
            json!({ "kind": "voice", "content_type": "audio/wav", "svr_id": svr_id, "length": wav.len() }),
        )
        .into_response());
    }
    Ok(media_bytes_response(
        wav,
        "audio/wav",
        headers.get(axum::http::header::RANGE),
    ))
}

/// `vid:<md5>` —— md5 (=冷投影 message_media.md5 = hardlink 键) → 开 hardlink 库 (真库单个不分片, VFS) →
/// `locate_video_by_md5` 定位磁盘**明文 .mp4** → **文件级 Range 流** (ServeFile, 大文件不整块进内存)。视频不解密:
/// 明文文件直接流, 加密 (`_raw` / 未在微信里播过) 或已清理的 → 404。md5-key: **不读 message 分片, 只开 hardlink 一个库**。
async fn serve_video(
    st: &AppState,
    rid: &RequestId,
    md5: &str,
    p: &MediaQ,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let wxid = require_wxid(st, rid, p.account.clone())?;
    let db_storage = native_query::resolve_db_storage_dir(st.wechat_data_dir.as_deref(), &wxid)
        .map_err(|e| map_core_err(rid, &e))?;
    // account_dir (msg/video/… 所在) = db_storage 的父; hardlink 库 = db_storage/hardlink/hardlink.db。
    let account_dir = db_storage
        .parent()
        .map_or_else(|| db_storage.clone(), std::path::Path::to_path_buf);
    let hardlink_db = db_storage.join("hardlink").join("hardlink.db");
    if !hardlink_db.is_file() {
        return Err(ApiError::new(
            rid,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "该账号无 hardlink 视频索引库",
        ));
    }
    let db_key = native_query::cache_key(&wxid)
        .await
        .map_err(|e| map_core_err(rid, &e))?;
    let md5_owned = md5.to_string();
    let permit = MEDIA_SEMAPHORE.acquire().await.expect("media semaphore 不会关闭");
    let located = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<std::path::PathBuf>> {
        let _permit = permit; // §8 P3: 持 permit 到 spawn_blocking 真跑完 (断连不提前释放, 见 serve_voice 注)
        let hconn = native_core::cipher::open_decrypted_db_vfs(&hardlink_db, &db_key)
            .map_err(|e| anyhow::anyhow!("开 hardlink 库失败: {e}"))?;
        Ok(native_core::media::locate_video_by_md5(
            &hconn,
            &account_dir,
            &md5_owned,
        )?)
    })
    .await;
    let path = match located {
        Ok(Ok(Some(path))) => path,
        Ok(Ok(None)) => {
            return Err(ApiError::new(
                rid,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "视频不存在 / 无明文文件 (加密未在微信里播放过, 或已被清理)",
            ))
        }
        Ok(Err(e)) => return Err(map_core_err(rid, &e)),
        Err(join_e) => {
            return Err(ApiError::new(
                rid,
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                format!("媒体任务失败: {join_e}"),
            ))
        }
    };
    if p.info.is_some() {
        let length = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        return Ok(
            Json(json!({ "kind": "video", "content_type": "video/mp4", "md5": md5, "length": length })).into_response(),
        );
    }
    // 文件级 Range 流 (permit 已随本函数返回释放; 流本身只读明文文件不占解密资源)。
    Ok(stream_file(&path, headers).await)
}

/// 文件级 Range 流 (ServeFile): 大 .mp4 seek+按需读, 不整块进内存; 自带 200/206/416/HEAD + Content-Type (按扩展名)。
/// 转发请求 Range 头给 ServeFile。ServeFile 恒 Infallible (IO 问题作 4xx/5xx 响应体, 非 Err)。
async fn stream_file(path: &std::path::Path, headers: &HeaderMap) -> Response {
    use tower::ServiceExt;
    use tower_http::services::ServeFile;
    let mut req = axum::http::Request::new(axum::body::Body::empty());
    if let Some(r) = headers.get(axum::http::header::RANGE) {
        req.headers_mut().insert(axum::http::header::RANGE, r.clone());
    }
    let resp = ServeFile::new(path).oneshot(req).await.unwrap_or_else(|e| match e {});
    resp.map(axum::body::Body::new)
}

// ── 联网媒体 (§8 SSRF 安全): 表情/朋友圈从微信 CDN 下载 · serve 首次网络出口 ──

/// URL 目标 IP 是否**公网可路由** (SSRF 闸)。**默认拒**: v4 挡私网/loopback/link-local/CGNAT/组播/保留/benchmark/
/// IETF 协议段; v6 **仅放行全局单播 2000::/3**, 且对内嵌 v4 的过渡地址 (v4-mapped/v4-compatible/6to4/NAT64) 提取内嵌
/// v4 递归判、Teredo 直接拒 —— 防经 NAT64/6to4/CLAT 把内嵌私网/环回 v4 路由进内网 (§8: 原 v6 分支是"默认放行"黑名单
/// 漏这些过渡形式)。防 DB 里畸形 CDN URL (observed content) 引 serve 去打本机/内网。
fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_public_v4(v4),
        std::net::IpAddr::V6(v6) => {
            // 显式拒: loopback(::1)/unspecified(::)/组播(ff00::/8)/ULA(fc00::/7)/link-local(fe80::/10)。
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let s = v6.segments();
            if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            // 内嵌 v4 的过渡地址 → 提取内嵌 v4 递归判 (防经 NAT64/6to4/CLAT 打内网)。
            if let Some(v4) = embedded_v4(v6) {
                return is_public_v4(v4);
            }
            // Teredo 2001:0::/32 (内嵌 v4 被混淆, 不解) → 直接拒。
            if s[0] == 0x2001 && s[1] == 0x0000 {
                return false;
            }
            // 默认拒: 仅全局单播 2000::/3 放行 (其余 discard/deprecated/未来段一律非公网)。
            (s[0] & 0xe000) == 0x2000
        }
    }
}

/// IPv4 是否公网可路由 (挡私网/loopback/link-local/CGNAT/组播/保留 + benchmark 198.18/15 + IETF 192.0.0/24 +
/// 6to4-relay-anycast 192.88.99/24)。
fn is_public_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    !(v4.is_private()            // 10/8 · 172.16/12 · 192.168/16
        || v4.is_loopback()      // 127/8
        || v4.is_link_local()    // 169.254/16
        || v4.is_unspecified()   // 0.0.0.0
        || v4.is_broadcast()     // 255.255.255.255
        || v4.is_documentation() // 192.0.2/24 · 198.51.100/24 · 203.0.113/24
        || o[0] == 0             // 0/8
        || (o[0] & 0xf0) == 0xe0 // 224-239 组播
        || o[0] >= 240           // 240+ 保留/未来
        || (o[0] == 100 && (o[1] & 0xc0) == 64)       // 100.64/10 CGNAT
        || (o[0] == 198 && (o[1] & 0xfe) == 18)       // 198.18/15 benchmark
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)    // 192.0.0/24 IETF 协议分配
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)) // 192.88.99/24 6to4 relay anycast
}

/// 从内嵌 IPv4 的 IPv6 过渡地址提取内嵌 v4: v4-mapped(::ffff:a.b.c.d) / 6to4(2002:AABB:CCDD::/48) /
/// NAT64 well-known(64:ff9b::/96) / v4-compatible(::a.b.c.d, 已废弃)。非过渡地址 → `None`。
fn embedded_v4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(m) = v6.to_ipv4_mapped() {
        return Some(m);
    }
    let s = v6.segments();
    // 6to4 2002::/16: v4 在 s[1..=2]。
    if s[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    // NAT64 well-known 64:ff9b::/96: v4 在低 32 位 (s[6..=7])。
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(std::net::Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    // v4-compatible ::/96 (高 96 位 0, 低 32 非零且非 ::/::1): 已废弃但防御性提取。
    if s[..6].iter().all(|&x| x == 0) && !(s[6] == 0 && s[7] <= 1) {
        return Some(std::net::Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    None
}

#[cfg(test)]
mod ip_gate_tests {
    use std::net::IpAddr;

    use super::is_public_ip;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_private_and_special_rejected() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "192.0.0.1",
            "192.88.99.1",
        ] {
            assert!(!is_public_ip(ip(s)), "{s} 应判非公网");
        }
    }

    #[test]
    fn v4_public_allowed() {
        for s in ["1.1.1.1", "8.8.8.8", "203.0.114.1", "114.114.114.114"] {
            assert!(is_public_ip(ip(s)), "{s} 应判公网");
        }
    }

    #[test]
    fn v6_special_rejected() {
        for s in ["::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1", "2001::1"] {
            assert!(!is_public_ip(ip(s)), "{s} 应判非公网");
        }
    }

    #[test]
    fn v6_embedded_v4_transition_rejected_when_private() {
        // §8 核心: 内嵌私网/环回 v4 的过渡地址必须被拆解拒绝 (原黑名单漏这些)。
        for s in [
            "::ffff:127.0.0.1", // v4-mapped loopback
            "::ffff:10.0.0.1",  // v4-mapped private
            "64:ff9b::7f00:1",  // NAT64 → 127.0.0.1
            "64:ff9b::c0a8:1",  // NAT64 → 192.168.0.1
            "2002:7f00:1::",    // 6to4 → 127.0.0.1
            "2002:c0a8:101::",  // 6to4 → 192.168.1.1
            "::7f00:1",         // v4-compatible → 127.0.0.1
        ] {
            assert!(!is_public_ip(ip(s)), "{s} 内嵌私网/环回 v4 应判非公网");
        }
    }

    #[test]
    fn v6_global_and_embedded_public_allowed() {
        for s in [
            "2606:4700:4700::1111", // Cloudflare 全局单播
            "2400:3200::1",         // 阿里 DNS v6 全局单播
            "::ffff:8.8.8.8",       // v4-mapped 公网
            "64:ff9b::808:808",     // NAT64 → 8.8.8.8 (公网内嵌)
        ] {
            assert!(is_public_ip(ip(s)), "{s} 应判公网");
        }
    }
}

/// 表情包下载内存上限 (同 CLI: 表情实际几 MB, 30MiB 足够; 防谎报 Content-Length 爆内存)。
const MAX_EMOJI_BYTES: usize = 30 * 1024 * 1024;

/// **SSRF 安全**的联网抓取 (表情/朋友圈从微信 CDN 下载用; CDN URL 来自 WeChat DB = observed content 故必须闸):
/// ① scheme 须 http/https; ② 自解析 host → IP, 全非公网 → 拒 (挡内网/loopback; is_public_ip 含 v6 过渡地址拆解);
/// ③ `.resolve()` **pin** 校验过的 IP 防 DNS-rebind (fetch 不重解析); ④ **禁跟转** (跟转到内网也是 SSRF);
/// ⑤ DNS 5s + connect 10s + 整体 20s 超时 (慢/黑洞 CDN 不久占信号量); ⑥ 边下边限 `max_bytes`。
/// `Err` = 拒/失败原因 (**K-R4: 不含 url 明文** —— reqwest 错误经 `without_url()` 剥掉内嵌带 token 的 url, §8)。
async fn guarded_fetch(raw_url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt as _;
    let url = reqwest::Url::parse(raw_url).map_err(|_| "url 非法".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("scheme 非 http/https".into());
    }
    let host = url.host_str().ok_or("url 无 host")?.to_string();
    let port = url.port_or_known_default().ok_or("url 无端口")?;
    // 自解析 (5s 超时防 OS 解析器慢查久占信号量) + 校验 IP: 全解析到非公网 → SSRF 拒 (挡 http://127.0.0.1 / 内网)。
    let resolved = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| "DNS 解析超时".to_string())?
    .map_err(|_| "DNS 解析失败".to_string())?;
    let addr = resolved
        .into_iter()
        .find(|a| is_public_ip(a.ip()))
        .ok_or("目标解析到非公网 IP (SSRF 拒)")?;
    // pin 校验过的 IP + 禁跟转 (防 DNS-rebind: fetch 走这个 IP 不重解析; 禁 3xx 防转内网) + connect 界。
    let client = reqwest::Client::builder()
        .resolve(&host, addr)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    // K-R4: reqwest 错误 Display 会带上含 token 的完整 url → without_url() 剥掉再格式化 (§8, 同下 stream 处)。
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("下载失败: {}", e.without_url()))?;
    if !resp.status().is_success() {
        return Err(format!("CDN 返 {}", resp.status()));
    }
    if resp.content_length().is_some_and(|n| n > max_bytes as u64) {
        return Err("响应超上限".into());
    }
    let mut bytes = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("读响应失败: {}", e.without_url()))?;
        if bytes.len() + chunk.len() > max_bytes {
            return Err("响应超上限 (流式截断)".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err("空响应 (URL 失效?)".into());
    }
    Ok(bytes)
}

/// wxgf (内层 HEVC 动图/静图) → GIF/PNG **当场转码** (需 ffmpeg); 非 wxgf 原样出 `image_content_type`。
/// 返 `(字节, content-type)`。ffmpeg 缺 / 转失败 → 原 wxgf 字节 + `application/octet-stream` (内容不丢, 客户端
/// 可自转; 同 CLI「留 .wxgf」哲学)。转码 = ffmpeg 子进程 + temp 文件 IO = 阻塞 → 下沉 spawn_blocking。
async fn transcode_if_wxgf(
    st: &AppState,
    bytes: Vec<u8>,
    fmt: native_core::decoder::DatFormat,
) -> (Vec<u8>, &'static str) {
    if fmt != native_core::decoder::DatFormat::Wxgf {
        return (bytes, image_content_type(fmt));
    }
    let ffmpeg_cfg = st.ffmpeg.clone();
    tokio::task::spawn_blocking(
        move || match native_core::media::resolve_ffmpeg(ffmpeg_cfg.as_deref()) {
            Some(ff) => {
                let ffprobe = native_core::media::resolve_ffprobe(&ff);
                match native_core::media::transcode_wxgf_bytes(&ff, ffprobe.as_deref(), &bytes) {
                    Some((out, ct)) => (out, ct),
                    None => (bytes, "application/octet-stream"), // 转失败 → 原 wxgf 不丢
                }
            }
            None => (bytes, "application/octet-stream"), // 无 ffmpeg → 原 wxgf 不丢
        },
    )
    .await
    .unwrap_or_else(|_| (Vec::new(), "application/octet-stream")) // spawn_blocking panic (极罕见)
}

/// `emoji:<md5>` —— 开加密 emoticon.db 取该 md5 的 aes_key + CDN url 候选 → **guarded_fetch 联网下** →
/// `decrypt_emoticon` (AES-128-CBC) → 认图 → 字节出 `media_bytes_response`。**表情本地不存** (WeChat 只留 CDN 引用),
/// 故必须联网; 逐 url 候选(encrypt_url→cdn_url→extern_url)试, 取第一个下得到且解得出图的。
async fn serve_emoji(
    st: &AppState,
    rid: &RequestId,
    md5: &str,
    p: &MediaQ,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let wxid = require_wxid(st, rid, p.account.clone())?;
    let db_storage = native_query::resolve_db_storage_dir(st.wechat_data_dir.as_deref(), &wxid)
        .map_err(|e| map_core_err(rid, &e))?;
    let emoticon_db = db_storage.join("emoticon").join("emoticon.db");
    if !emoticon_db.is_file() {
        return Err(ApiError::new(
            rid,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "该账号无 emoticon.db (无自定义表情?)",
        ));
    }
    let db_key = native_query::cache_key(&wxid)
        .await
        .map_err(|e| map_core_err(rid, &e))?;
    let md5_owned = md5.to_string();
    // 1. 开 emoticon.db (VFS 解密) + 读 → (aes_key + url 候选)。**MEDIA_SEMAPHORE** (本地解密闸; PBKDF 缓存后很快)。
    //    permit 移进闭包持到真跑完 (断连不提前释放, §8 P3)。
    let permit = MEDIA_SEMAPHORE.acquire().await.expect("media semaphore 不会关闭");
    let emo = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<native_core::media::EmoticonRef>> {
        let _permit = permit;
        let conn = native_core::cipher::open_decrypted_db_vfs(&emoticon_db, &db_key)
            .map_err(|e| anyhow::anyhow!("开 emoticon.db 失败: {e}"))?;
        // 单行查询 (不读全表解码; §8 critic: 减内存 + 缩 permit 持有)。
        Ok(native_core::media::read_emoticon_one(&conn, &md5_owned)?)
    })
    .await;
    let emo = match emo {
        Ok(Ok(Some(e))) => e,
        Ok(Ok(None)) => {
            return Err(ApiError::new(
                rid,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                format!("emoticon.db 无此表情 (emoji:{md5})"),
            ))
        }
        Ok(Err(e)) => return Err(map_core_err(rid, &e)),
        Err(je) => {
            return Err(ApiError::new(
                rid,
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                format!("媒体任务失败: {je}"),
            ))
        }
    };
    // 2. 逐 url 候选: SSRF 安全联网下 → AES-CBC 解 → 认图。**EGRESS_SEMAPHORE** (§9: 独立联网出口闸, 慢/失效 CDN
    //    不占本地解密闸, 不拖 voice/image/video 本地媒体)。取第一个成的。
    let _egress = EGRESS_SEMAPHORE.acquire().await.expect("egress semaphore 不会关闭");
    for url in &emo.urls {
        let Ok(enc) = guarded_fetch(url, MAX_EMOJI_BYTES).await else {
            continue;
        };
        let Some(img) = native_core::media::decrypt_emoticon(&enc, &emo.aes_key) else {
            continue;
        };
        let fmt = native_core::decoder::detect_format(&img);
        if fmt == native_core::decoder::DatFormat::Unknown {
            continue; // 解出不是已知图 (url/key 不对) → 试下一候选
        }
        // wxgf 动图贴纸 → 当场转 GIF/PNG (需 ffmpeg; 缺则 octet-stream 不丢)。
        let (out, ct) = transcode_if_wxgf(st, img, fmt).await;
        if p.info.is_some() {
            return Ok(
                Json(json!({ "kind": "emoji", "content_type": ct, "md5": md5, "length": out.len() })).into_response(),
            );
        }
        return Ok(media_bytes_response(out, ct, headers.get(axum::http::header::RANGE)));
    }
    Err(ApiError::new(
        rid,
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "表情下载/解密失败 (CDN URL 全失效或已下架)",
    ))
}

/// 朋友圈媒体下载内存上限 (视频可几十 MB, 同 CLI cmd_export_sns_media 的 100MiB)。
const MAX_MOMENT_BYTES: usize = 100 * 1024 * 1024;

/// 定位朋友圈 keystream node 脚本: `AppState.sns_wasm_dir` → env `WECHAT_SNS_WASM_DIR` → exe 同目录
/// `vendor/weflow_wasm`。返 `weflow_wasm_keystream.js` 路径 (须存在)。**仅加密媒体 (enc_idx=1) 需它** —— 缺则
/// 503 (未配置 node 脚本), 明文媒体不调本函数。
fn resolve_sns_node_script(st: &AppState, rid: &RequestId) -> Result<std::path::PathBuf, ApiError> {
    let dir = st
        .sns_wasm_dir
        .clone()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("WECHAT_SNS_WASM_DIR").ok().map(std::path::PathBuf::from))
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(|p| p.join("vendor").join("weflow_wasm")))
        });
    match dir.map(|d| d.join("weflow_wasm_keystream.js")) {
        Some(s) if s.is_file() => Ok(s),
        _ => Err(ApiError::new(
            rid,
            StatusCode::SERVICE_UNAVAILABLE,
            "SNS_WASM_MISSING",
            "朋友圈加密媒体需 WxIsaac64 keystream (node): serve 加 --sns-wasm-dir 指 weflow_wasm 目录 (或设 \
             WECHAT_SNS_WASM_DIR), 且系统装 node",
        )),
    }
}

/// `moment:<source_native_id>:<media_seq>` —— 读 L1 moment_media 取该媒体的 CDN url+token+key → **guarded_fetch
/// 联网下** → decrypt_sns_media (enc_idx=1 走 node WxIsaac64 XOR; 明文原样) → 认图/视频 → 字节。**朋友圈媒体本地
/// 不存** (WeChat 只留 CDN 引用), 故必须联网; 视频 (media_type=6) 出 video/mp4, 图走 detect_format。
async fn serve_moment(
    st: &AppState,
    rid: &RequestId,
    source_native_id: &str,
    media_seq: i64,
    p: &MediaQ,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    let l1 = require_l1(st, rid)?;
    let account = resolve_cold_account(&l1, p.account.clone(), st.default_account.as_deref(), rid)?;
    let account_sha = account.as_deref().map(native_core::sha256_hex);
    let sid = source_native_id.to_string();
    // 1. 读 L1 moment_media (明文, 无 PBKDF) 取单条 ref (遮蔽视图账号隔离, 同冷查)。**MEDIA_SEMAPHORE** (本地闸);
    //    permit 移进闭包持到真跑完 (断连不提前释放, §8 P3)。
    let permit = MEDIA_SEMAPHORE.acquire().await.expect("media semaphore 不会关闭");
    let emo = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<native_core::media::SnsMediaRef>> {
        let _permit = permit;
        let conn = native_query::open_l1_scoped(&l1, account_sha.as_deref())?;
        Ok(native_core::media::read_sns_media_ref_one(&conn, &sid, media_seq)?)
    })
    .await;
    let emo = match emo {
        Ok(Ok(Some(e))) => e,
        Ok(Ok(None)) => {
            return Err(ApiError::new(
                rid,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                format!("moment_media 无此媒体 (moment:{source_native_id}:{media_seq})"),
            ))
        }
        Ok(Err(e)) => return Err(map_core_err(rid, &e)), // 含表不存在 → NeedsIngest 409 (需先 adapter --sns)
        Err(je) => {
            return Err(ApiError::new(
                rid,
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                format!("媒体任务失败: {je}"),
            ))
        }
    };
    // 2. 加密媒体 (enc_idx=1) 才需 node 脚本; 缺 → 503 (明文媒体不受影响)。
    let node_script = if emo.enc_idx == "1" {
        Some(resolve_sns_node_script(st, rid)?)
    } else {
        None
    };
    // 3. SSRF 安全联网下 (拼 ?token=&idx=) + 解密。**EGRESS_SEMAPHORE** (§9: 独立联网出口闸, 慢/失效 CDN 不占
    //    本地解密闸, 不拖 voice/image/video 本地媒体)。
    let _egress = EGRESS_SEMAPHORE.acquire().await.expect("egress semaphore 不会关闭");
    let url = native_core::media::build_download_url(&emo.url, emo.token.as_deref(), &emo.enc_idx);
    let enc = guarded_fetch(&url, MAX_MOMENT_BYTES).await.map_err(|e| {
        ApiError::new(
            rid,
            StatusCode::BAD_GATEWAY,
            "CDN_FETCH_FAILED",
            format!("朋友圈媒体下载失败: {e}"),
        )
    })?;
    // 4. 解密 (enc_idx=1 走 node keystream XOR = 阻塞子进程, 下沉 spawn_blocking; 明文原样)。
    let media_type = emo.media_type;
    let dec = tokio::task::spawn_blocking(move || {
        let script = node_script.as_deref().unwrap_or_else(|| std::path::Path::new(""));
        native_core::media::decrypt_sns_media(enc, &emo, script)
    })
    .await
    .map_err(|je| {
        ApiError::new(
            rid,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("解密任务失败: {je}"),
        )
    })?
    .map_err(|e| {
        ApiError::new(
            rid,
            StatusCode::BAD_GATEWAY,
            "SNS_DECRYPT_FAILED",
            format!("朋友圈媒体解密失败: {e}"),
        )
    })?;
    // 5. 视频 (media_type=6) → mp4 原样; 图 → detect_format (Unknown = URL/key 不符 → 404) + wxgf 当场转。
    let (out, ct) = if media_type == 6 {
        (dec, "video/mp4")
    } else {
        let fmt = native_core::decoder::detect_format(&dec);
        if fmt == native_core::decoder::DatFormat::Unknown {
            return Err(ApiError::new(
                rid,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "朋友圈媒体解不出图 (URL 失效/key 不符)",
            ));
        }
        transcode_if_wxgf(st, dec, fmt).await
    };
    if p.info.is_some() {
        return Ok(Json(json!({
            "kind": "moment", "content_type": ct, "media_type": media_type,
            "source_native_id": source_native_id, "media_seq": media_seq, "length": out.len()
        }))
        .into_response());
    }
    Ok(media_bytes_response(out, ct, headers.get(axum::http::header::RANGE)))
}

// ─────────────────────────────────────────────────────────────────
// /events — SSE 实时事件流 (§10): 读档 tail + watch 进度信号即时唤醒 + 心跳 + Last-Event-ID 补发。
// ─────────────────────────────────────────────────────────────────

/// `/events` 查询参数。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsQ {
    /// 账号 (多账号库必给否则 409; 单账号可省)。
    account: Option<String>,
    /// 会话过滤 (payload_json 的 conv_id; 明文流下传明文 conv_id)。
    conv: Option<String>,
    /// 事件类型过滤 (raw_payload_archive.event_type, 如 message / contact_update)。
    #[serde(rename = "type")]
    event_type: Option<String>,
    /// 断线补发起点 (archive id); 也可走 `Last-Event-ID` 请求头 (header 优先)。
    last_event_id: Option<i64>,
}

/// SSE 单次读档上限 (单次查询的行数/内存界; 读满则本轮分批续读)。
const SSE_READ_LIMIT: i64 = 500;
/// SSE 单连接补发**总量**界 (审查 replay-abuse: 起点太旧/=0 会拉全 24h archive)。resume 点落后当前
/// max 超过此值 → 判 gap 太大, 从 (max - 此值) 起并发 resync, 不做全档重放。
const SSE_MAX_CATCHUP: i64 = 20_000;
/// `/events` 并发连接上限 (审查 conn-exhaust/backpressure: SSE 长连无上限 → 洪泛耗 fd/内存/阻塞池;
/// 仿 EXEC_SEMAPHORE)。连接持 permit 到流结束; 满 → 503。
/// ⚠️ **值必须显著 > 浏览器 per-(host,port) 并发上限 (HTTP/1.1 ≈6)** —— 否则浏览器 drive-by 单主机名即可打满
/// (审查 round2)。别下调到 ≤6, 也别在 serve 前架 HTTP/2 终结器 (H2 单连多路复用绕过 per-host cap); DoS 不再
/// 靠此裕度而靠 1a 的 Host/Sec-Fetch-Mode 服务端闸兜底。
static EVENTS_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);

/// SSE 一批读档结果: (读到的最后 archive id, 过滤后待发的 (id, event_type, payload_json) 列, 本批原始行数)。
type SseBatch = (i64, Vec<(i64, String, String)>, usize);
/// SSE 兜底轮询 (防 watch 进度信号漏发/积压; 正常走进度即时唤醒, 这只是安全网)。
const SSE_FALLBACK_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// 打开 L1 只读连接 (SSE tail: 读固定 raw_payload_archive, 不带 exec 的 authorizer/15s deadline)。
fn open_l1_readonly_simple(l1: &str) -> anyhow::Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    let conn =
        rusqlite::Connection::open_with_flags(l1, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)?;
    // codex R16-3 P1/P2: SSE/archive 读也校验 schema 版本 (同 native_query::open_l1) —— 旧版本库(R14 消息锚 / R16-3
    // favorite_tag 锚过时)的 archive 事件锚格式旧, 补发会串旧格式。有版本 meta 且不符 → 拒 (提示重建)。
    // **用 native_query::cli_err(SchemaMismatch) 而非 anyhow::bail!**(codex P2): 后者产无类型 anyhow → map_core_err
    // 的 classify_error downcast 不到 CliError → 归 Internal/HTTP500; cli_err 包 CliError → classify 提 SchemaMismatch
    // → 409 + 重建 hint, 与 open_l1 一致 (`serve --watch` 默认账号短路时旧库正落此支)。
    if let Ok(Some(v)) = native_core::storage::get_meta(&conn, native_core::storage::META_KEY_VERSION) {
        if v != native_core::storage::SCHEMA_VERSION {
            return Err(native_query::cli_err(
                native_core::ErrorCode::SchemaMismatch,
                format!(
                    "L1 库 schema 版本过旧 (库 {v}, 需 {}): 请删掉此 L1、从加密源全量重建",
                    native_core::storage::SCHEMA_VERSION
                ),
            ));
        }
    }
    Ok(conn)
}

/// 当前 archive 最大 id (SSE 新连接不带 Last-Event-ID 的起点: 只发此后)。空库 → 0。
fn archive_max_id(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COALESCE(MAX(id), 0) FROM raw_payload_archive", [], |r| r.get(0))
        .unwrap_or(0)
}

/// 断线补发的**起点判定**: 给"客户端上次收到第几条"和"表里现在还剩哪一段", 算出从哪儿续、要不要先喊 `resync`。
///
/// 单拎成纯函数是为了**能测** —— 原先这段逻辑长在 handler 里的 `spawn_blocking` 闭包中, 全仓一条守卫都没有,
/// 而它管的是"客户端会不会**以为自己没漏、其实漏了**"。
///
/// 判据只有一条: **证不出连续就得喊 resync**。三种证不出的情况:
/// - `id > max` —— 客户端的位置比表里最大的还大。归档表的 id 是 AUTOINCREMENT 单调发的, 正常只会越来越大;
///   位置反超只有一个解释: 这个库被重建过、或者整表被清空过。中间那段**找不回来了**。
///   ⚠️ **归档被清空是这一格的主戏**(codex 审 24 小时清理那一笔时点出来的): 清空后 `min`/`max` 全变 0,
///   老代码的 `min > 0 &&` 前提当场不成立, 于是**一声不吭**地按"没漏"续下去 —— 而恰恰是全清空这种情况漏得最多。
/// - `id < max - SSE_MAX_CATCHUP` —— 落后太多。补发有总量界, 不做全档倒扫, 从近窗起。
/// - `id < min - 1` —— 客户端要的下一条(`id+1`)比现存最老的还老, 中间那段已被滚动窗口清掉。
///   `id == min - 1` 不算漏: 下一条正好就是 `min`, 接得上。
///
/// 走到第三条时表一定非空: 前面 `id > max` 已经拦掉了 `max == 0`, 而 `id` 在入口就校验过 > 0,
/// 所以 `max >= id >= 1` → 表里有行 → `min >= 1`。
fn sse_resume_point(last_event_id: i64, min: i64, max: i64) -> (i64, bool) {
    if last_event_id > max {
        (max, true) // 库被重建 / 归档被清空 → 从头来, 且必须告诉客户端
    } else if last_event_id < max - SSE_MAX_CATCHUP {
        (max - SSE_MAX_CATCHUP, true) // 落后太多 → 有界近窗补发 + resync
    } else if last_event_id < min - 1 {
        (min - 1, true) // 补发点已被滚动窗口清掉 → resync
    } else {
        (last_event_id, false) // 接得上, 照常续
    }
}

/// 当前 archive 最小 id (resync 判定: 补发起点 < min-1 = 中间已被 24h prune 删)。空库 → 0。
fn archive_min_id(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COALESCE(MIN(id), 0) FROM raw_payload_archive", [], |r| r.get(0))
        .unwrap_or(0)
}

/// 从 payload_json 取 conv_id (SSE ?conv 过滤; conv 非 archive 顶层列)。解析失败/无字段 → None。
fn payload_conv_id(payload_json: &str) -> Option<String> {
    serde_json::from_str::<Value>(payload_json)
        .ok()
        .and_then(|v| v.get("conv_id").and_then(|c| c.as_str()).map(str::to_string))
}

/// `Last-Event-ID` 请求头 → archive id (EventSource 断线重连自动带此头)。非法/缺 → None。
fn last_event_id_header(headers: &HeaderMap) -> Option<i64> {
    headers.get("last-event-id")?.to_str().ok()?.trim().parse::<i64>().ok()
}

/// `/events` — SSE 实时事件流 (§10)。对外一套读档模型: 每条 `id=archive.id` / `event=event_type` /
/// `data=单行 payload_json`; 内部 watch 进度信号即时唤醒去读档 (低延迟) + 5s 兜底轮询 (防漏信号) + 15s 心跳。
/// `Last-Event-ID` (头 / `?last_event_id`) 断线补发走 read_archive_since; 补发点被 24h prune → 先发 `resync`。
/// `?account` fail-closed (多账号未指定 → 409) · `?conv` / `?type` 过滤。需 serve `--watch` 起后台监听 (否则 503)。
#[allow(clippy::similar_names)] // conn / conv / conv_c 领域命名相近, 非笔误
async fn get_events(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    headers: HeaderMap,
    Qs(p): Qs<EventsQ>,
) -> Result<Response, ApiError> {
    // 1a. 本地-only 请求闸 (审查 round2): SSE GET 无预检; 且**浏览器 no-cors 跨源 GET 不带 Origin 头** (Fetch 规范:
    //     Origin 仅 cors-mode 或非 GET/HEAD 才附), 故单 Origin 闸挡不住 drive-by。三重闸 (开库前拒):
    //     (i) **Host 须 loopback** —— 挡 DNS-rebinding 多池 (*.evil→127.0.0.1 时 Host 带攻击者域名), 这是耗尽
    //         EVENTS_SEMAPHORE 的关键路径 (直连 127.0.0.1 受浏览器 per-host≈6 cap 打不满 32, 必须靠多主机名);
    //     (ii) **Sec-Fetch-Mode=no-cors → 拒** —— no-cors fetch/<img>/<script> 的浏览器 drive-by (EventSource
    //          走 cors mode、本地 curl 不发此头 → 不误伤, 含合法本地跨端口前端);
    //     (iii) **Origin 非 loopback → 拒** —— cors-mode 跨源 (EventSource/fetch cors)。本地 curl (无这些头,
    //          Host=127.0.0.1) 全放行。
    let deny = |m: &str| {
        ApiError::new(
            &rid,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            format!("跨源/非本机请求被拒 ({m}); /events 仅限本机"),
        )
    };
    if headers.get("host").is_some_and(|h| !is_loopback_host(h.as_bytes())) {
        return Err(deny("Host"));
    }
    if headers
        .get("sec-fetch-mode")
        .is_some_and(|m| m.as_bytes() == b"no-cors")
    {
        return Err(deny("Sec-Fetch-Mode"));
    }
    if headers.get("origin").is_some_and(|o| !is_loopback_origin(o.as_bytes())) {
        return Err(deny("Origin"));
    }
    // 1b. 实时未启用 (serve 无 --watch) → 503。
    let mut progress = st.events_progress.clone().ok_or_else(|| {
        ApiError::new(
            &rid,
            StatusCode::SERVICE_UNAVAILABLE,
            "EVENTS_DISABLED",
            "实时事件未启用 (serve 需 --watch --wxid 开后台监听)",
        )
    })?;
    // 1c. 后台 watch 已死 (sender 全 drop) → 503 (审查 watch-liveness: 别让客户端连上又立即断 + 每 3s 重连打转)。
    if progress.has_changed().is_err() {
        return Err(ApiError::new(
            &rid,
            StatusCode::SERVICE_UNAVAILABLE,
            "EVENTS_DISABLED",
            "实时监听后台已停止",
        ));
    }
    let l1 = require_l1(&st, &rid)?;
    // 1d. 并发闸 (审查 conn-exhaust/backpressure): 满 → 503; permit 移进 stream 持到流结束。
    let permit = EVENTS_SEMAPHORE.try_acquire().map_err(|_| {
        ApiError::new(
            &rid,
            StatusCode::SERVICE_UNAVAILABLE,
            "EVENTS_BUSY",
            "并发 SSE 连接已达上限, 稍后重试",
        )
    })?;

    // 2. 账号 fail-closed + **pin 具体 sha** (审查 account-leak TOCTOU): 未指定 ?account 时退到 serve 的 --wxid
    //    默认 (由 resolve_cold_account 的 default 参统一兜, 复审#3), 令 account_sha 恒为具体值 —— 否则单账号库
    //    解析成 None=不过滤, 之后别账号 ingest 进同库会泄给此长连流。
    let account = resolve_cold_account(&l1, p.account.clone(), st.default_account.as_deref(), &rid)?;
    let account_sha = account.as_deref().map(native_core::sha256_hex);
    // 3. 起点: Last-Event-ID (头优先) > ?last_event_id > 无 (从最新)。<=0 非法 (防绕过 resync 全量倒扫)。
    let explicit_start = last_event_id_header(&headers).or(p.last_event_id);
    if matches!(explicit_start, Some(id) if id <= 0) {
        return Err(ApiError::bad_request(
            &rid,
            "last_event_id 须 > 0 (0/负非法; 不带则从最新开始)",
        ));
    }
    let conv = p.conv.clone();
    let event_type = p.event_type.clone();
    let mut shutdown = st.shutdown.clone();

    // 4. 起点游标 + resync 判定 (spawn_blocking: Connection !Send)。**补发有总量界**: gap 超 SSE_MAX_CATCHUP
    //    (或补发点已被 24h prune) → 从近窗起 + resync, 不做全档倒扫。
    let l1c = l1.clone();
    let (mut cursor, resync) = tokio::task::spawn_blocking(move || -> anyhow::Result<(i64, bool)> {
        let conn = open_l1_readonly_simple(&l1c)?;
        match explicit_start {
            None => Ok((archive_max_id(&conn), false)), // 新连接: 只发此后
            Some(id) => Ok(sse_resume_point(id, archive_min_id(&conn), archive_max_id(&conn))),
        }
    })
    .await
    .map_err(|e| {
        ApiError::new(
            &rid,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("events 起点解析失败: {e}"),
        )
    })?
    .map_err(|e| map_core_err(&rid, &e))?;

    // 5. SSE stream。permit 持到流结束; conv 过滤放进 spawn_blocking (审查 replay-abuse: 逐行 serde 别跑单 async worker)。
    let stream = async_stream::stream! {
        let _permit = permit; // 持并发 permit 到流结束
        yield Ok::<_, std::convert::Infallible>(
            Event::default().retry(std::time::Duration::from_secs(3)).comment("connected")
        );
        if resync {
            yield Ok(Event::default().event("resync").data(format!("{{\"reason\":\"gap\",\"resume_from\":{cursor}}}")));
        }
        loop {
            // 读档 + conv 过滤都在 spawn_blocking (不跨 await 持 Connection; conv serde 不跑单 async worker)。
            loop {
                let l1c = l1.clone();
                let acc = account_sha.clone();
                let et = event_type.clone();
                let conv_c = conv.clone();
                let cur = cursor;
                let read = tokio::task::spawn_blocking(
                    move || -> anyhow::Result<SseBatch> {
                        let conn = open_l1_readonly_simple(&l1c)?;
                        let rows = native_core::storage::read_archive_since_filtered(
                            &conn, cur, acc.as_deref(), et.as_deref(), SSE_READ_LIMIT,
                        )?;
                        let n = rows.len();
                        let mut last = cur;
                        let mut out = Vec::with_capacity(n);
                        for (id, rec) in rows {
                            last = id; // 游标按读到的最后一行推进 (即便被 conv 过滤掉, 也不重读)
                            if let Some(cv) = &conv_c {
                                if payload_conv_id(&rec.payload_json).as_deref() != Some(cv.as_str()) {
                                    continue;
                                }
                            }
                            out.push((id, rec.event_type, rec.payload_json));
                        }
                        Ok((last, out, n))
                    },
                )
                .await;
                let (last_id, matched, n) = match read {
                    Ok(Ok(v)) => v,
                    _ => break, // 读/join 失败: 本轮不推进游标, 等下次唤醒重试 (不漏)
                };
                if n == 0 {
                    break;
                }
                cursor = last_id;
                for (id, ev, pj) in matched {
                    yield Ok(Event::default().id(id.to_string()).event(ev).data(pj));
                }
                if (n as i64) < SSE_READ_LIMIT {
                    break; // 未读满 = 已到尾, 等唤醒
                }
                // 读满 = 可能还有积压, 内层继续读下一批
            }
            // 等 watch 唤醒 (低延迟) / 兜底轮询 / 关停 (审查 shutdown-leak: serve 关停 send → 立即结束流解死锁)。
            match &mut shutdown {
                Some(sd) => {
                    tokio::select! {
                        () = tokio::time::sleep(SSE_FALLBACK_POLL) => {}
                        r = progress.changed() => { if r.is_err() { break; } }
                        r = sd.changed() => { if r.is_err() || *sd.borrow() { break; } }
                    }
                }
                None => {
                    // watch sender 关 (serve 关停) → break; 进度更新 / 兜底超时 → 回去读下一批。
                    if let Ok(Err(_)) = tokio::time::timeout(SSE_FALLBACK_POLL, progress.changed()).await
                    {
                        break;
                    }
                }
            }
        }
    };

    let mut resp = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)).text("hb"))
        .into_response();
    // 禁反向代理缓冲 (SSE 需即时 flush)。
    resp.headers_mut()
        .insert("X-Accel-Buffering", HeaderValue::from_static("no"));
    Ok(resp)
}

/// pack 组合工具复用: 取某账号某会话近期消息 (热·尽力而为; 无账号/无 dir/失败 → 空数组, 不整体报错; 对标
/// MCP `pack_recent_messages` §9.2)。HTTP 全保真 → 直返 `r.data` (不 fold)。
async fn pack_recent(st: &AppState, account: Option<&str>, conv: &str, limit: usize) -> Vec<Value> {
    let Some(acc) = account else { return vec![] };
    let Ok(wxid) = acc.parse::<native_core::Wxid>() else {
        return vec![];
    };
    (native_query::hot_messages(&wxid, conv, st.wechat_data_dir.as_deref(), None, limit).await)
        .map(|r| r.data)
        .unwrap_or_default()
}

/// `/contacts/{wxid}/pack` 一键概览 (对标 MCP `contact_pack`): 联系人信息 (冷·scoped resolve_names) + 近期消息
/// (热·尽力而为)。组合形 `{contact, recent_messages}` (非 {data,meta} 信封 —— 聚合非查询, 同 MCP)。
async fn get_contact_pack(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(wxid): Path<String>,
    Qs(p): Qs<AccountQ>,
) -> Result<Response, ApiError> {
    let l1 = require_l1(&st, &rid)?;
    // 账号 fail-closed (多账号未指定 → 409, 但先退服务器默认 --wxid); 联系人是主载荷故走完整解析 (非尽力而为)。
    let account = resolve_cold_account(&l1, p.account.clone(), st.default_account.as_deref(), &rid)?;
    let account_sha = account.as_deref().map(native_core::sha256_hex);
    let conn = native_query::open_l1_scoped(&l1, account_sha.as_deref()).map_err(|e| map_core_err(&rid, &e))?;
    let contact = native_query::resolve_names_query(&conn, &[wxid.as_str()])
        .map(|r| r.data)
        .unwrap_or_default();
    // 近期消息 (热): account wxid 用解析出的 > 服务器默认; 缺则空 (尽力而为)。
    let me = account.or_else(|| st.default_account.clone());
    let recent = pack_recent(&st, me.as_deref(), &wxid, 5).await;
    Ok(Json(json!({ "contact": contact, "recent_messages": recent })).into_response())
}

/// `/sessions/{id}/pack` 一键概览 (对标 MCP `session_pack`): 会话近期消息 (热)。热查必需账号 (定位账号库+key)
/// → 缺 400 (与 sessions/messages 一致, 不静默空)。组合形 `{conv, is_group, recent_messages}`。
async fn get_session_pack(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(id): Path<String>,
    Qs(p): Qs<AccountQ>,
) -> Result<Response, ApiError> {
    let wxid = require_wxid(&st, &rid, p.account)?;
    let is_group = id.ends_with("@chatroom");
    // recent 尽力而为 (热查不可用 → 空; 审查 B D1 簇G **接受**: best-effort 对标 MCP §9.2, 冒错会丢 cold-only
    // serve 的优雅降级 —— 返 {conv,is_group,recent:[]} 仍有用; P3, 记档非修)。
    let recent = pack_recent(&st, Some(wxid.as_str()), &id, 10).await;
    Ok(Json(json!({ "conv": id, "is_group": is_group, "recent_messages": recent })).into_response())
}

/// search 特殊: FTS 靠 message.rowid 关联 → **非 scoped** conn + 显式账号谓词 (同 CLI/MCP 皮)。
async fn get_search(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<SearchQ>,
) -> Result<Response, ApiError> {
    let keyword = p
        .keyword
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::bad_request(&rid, "search 需要 ?keyword="))?;
    let limit_usize = clamp_limit(p.limit, 20, 100);
    // R16-6 🔴降级双模: 热 = 全库扫 text.contains 子串 (无 FTS/无 bm25 排名, 时间序)。冷 = FTS5 bm25(下方原逻辑)。
    if matches!(
        p.mode
            .unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some()),
        native_query::EffectiveMode::Hot
    ) {
        let wxid = require_wxid(&st, &rid, p.account)?;
        http_cost_gate(&st, &rid, &wxid, 0, limit_usize, p.confirm.unwrap_or(false)).await?;
        let permit = hot_scan_permit(&rid, 0, limit_usize).await?;
        let r = native_query::hot_search(
            &wxid,
            st.wechat_data_dir.as_deref(),
            None,
            &keyword,
            limit_usize,
            Some(permit),
        )
        .await
        .map_err(|e| map_core_err(&rid, &e))?;
        return Ok(envelope(&r));
    }
    // ── 冷 (FTS5 bm25) ──
    let l1 = require_l1(&st, &rid)?;
    let default_account = st.default_account.clone();
    let limit = limit_usize as i64;
    let (full, live_alive) = (st.live_index_full, live_thread_alive(&st));
    let explicit = p.account;
    let rid2 = rid.clone();
    // R5 复审 P1#2: 并发闸 —— permit 在此 await 取得, **移进 spawn_blocking 持到扫描真跑完** (超时/断连丢 handler future
    // 时后台 SQL 不被取消仍在跑; permit 若留在 async 作用域会提前释放 → 闸被打穿、连发短词搜索堆满全表扫)。同 exec/media 范式。
    let permit = SEARCH_SEMAPHORE.acquire().await.expect("search semaphore 不会关闭");
    // R4 复审 P1: search 的账号解析 + open_l1 + search_query (未建索引/query<3字 → message 全表 LIKE 扫描) 全**下沉
    // spawn_blocking** —— serve 是 current_thread runtime, 内联在 async 线程跑大库全扫会冻死唯一线程 (连 /health 都不
    // 响应)。照 cold()/exec 范式。account fail-closed 由 resolve_cold_account (多账号未指定 → 409 ACCOUNT_AMBIGUOUS)。
    let joined = tokio::task::spawn_blocking(move || -> Result<native_query::QueryResult, ApiError> {
        let _permit = permit; // 持到本闭包(扫描)结束才释放 → 并发闸对"真在跑的扫描"生效, 非只对 await。
        let account = resolve_cold_account(&l1, explicit, default_account.as_deref(), &rid2)?;
        let account_sha = account.as_deref().map(native_core::sha256_hex);
        let conn = native_query::open_l1(&l1).map_err(|e| map_core_err(&rid2, &e))?;
        // R5 复审 P1#2: 全表 LIKE 扫描无界算力 → progress_handler 30s deadline 掐 (照 exec 15s 范式)。请求超时只停等待、
        // spawn_blocking SQL **不被取消** → 靠这个 deadline 让扫描自停 (返 SQLITE_INTERRUPT), 别让超时的扫描空跑吃满 CPU。
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(30);
        conn.progress_handler(100_000, Some(move || std::time::Instant::now() > deadline));
        let mut r = native_query::search_query(&conn, &keyword, limit, account_sha.as_deref()).map_err(|e| {
            // R5b 复审 P2 / codex-R8 P2: 30s deadline 触发的 SQLITE_INTERRUPT → **408 REQUEST_TIMEOUT** (语义准: 查询超时被
            // 掐), 别当 500。**按错误码精确判** (is_query_interrupted), 非 elapsed 计时 (计时会把其它 30s 后失败误报 408)。
            if is_query_interrupted(&e) {
                ApiError::new(
                    &rid2,
                    StatusCode::REQUEST_TIMEOUT,
                    "REQUEST_TIMEOUT",
                    "搜索超 30s 上限被中断 (未建索引/短词 → message 全表扫); 先 `search --build` 建全文索引, 或用更长/更具体的关键词",
                )
            } else {
                map_core_err(&rid2, &e)
            }
        })?;
        // R6/R9 (审 R6-P2): search 走非 scoped conn 直返、不经 cold() choke, 故此处补冷查新鲜度 (与其它冷查端点一致)。
        attach_cold_freshness(&mut r, &l1, account_sha.as_deref(), full, live_alive, None);
        Ok(r)
    })
    .await;
    match joined {
        Ok(Ok(r)) => Ok(envelope(&r)),
        Ok(Err(e)) => Err(e),
        Err(je) => Err(ApiError::new(
            &rid,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("search 任务失败: {je}"),
        )),
    }
}

// ── 单条 inspect 详情 (§6: sessions/{id} · contacts/{wxid} · chatrooms/{id} · messages/{id}) ──

async fn inspect_one(
    st: &AppState,
    rid: &RequestId,
    account: Option<String>,
    mode: Option<native_query::QueryMode>,
    entity: native_query::InspectType,
    id: String,
    confirm: bool,
) -> Result<Response, ApiError> {
    // R16-6 双模: hot 直读加密源库按 entity 路由 (message 全扫找锚 → 取 permit 限并发); cold 读 L1 单行。
    if matches!(
        mode.unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some()),
        native_query::EffectiveMode::Hot
    ) {
        let wxid = require_wxid(st, rid, account)?;
        // R21 成本门只对 message 实体挂 —— 只 hot_inspect 的 Message 臂全扫找锚; contact/chatroom/session 直读各库。
        if matches!(entity, native_query::InspectType::Message) {
            http_cost_gate(st, rid, &wxid, 0, 0, confirm).await?;
        }
        let permit = hot_scan_permit(rid, 0, 0).await?;
        let r = native_query::hot_inspect(&wxid, st.wechat_data_dir.as_deref(), None, entity, &id, Some(permit))
            .await
            .map_err(|e| map_core_err(rid, &e))?;
        return Ok(envelope(&r));
    }
    cold(st, rid, account, move |c, _l1, _sha| {
        native_query::inspect_query(c, entity, &id)
    })
    .await
}

async fn get_contact_detail(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(wxid): Path<String>,
    Qs(p): Qs<InspectQ>,
) -> Result<Response, ApiError> {
    inspect_one(
        &st,
        &rid,
        p.account,
        p.mode,
        native_query::InspectType::Contact,
        wxid,
        false,
    )
    .await
}

async fn get_chatroom_detail(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(id): Path<String>,
    Qs(p): Qs<InspectQ>,
) -> Result<Response, ApiError> {
    inspect_one(
        &st,
        &rid,
        p.account,
        p.mode,
        native_query::InspectType::Chatroom,
        id,
        false,
    )
    .await
}

async fn get_session_detail(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(id): Path<String>,
    Qs(p): Qs<InspectQ>,
) -> Result<Response, ApiError> {
    inspect_one(
        &st,
        &rid,
        p.account,
        p.mode,
        native_query::InspectType::Session,
        id,
        false,
    )
    .await
}

async fn get_message_detail(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(id): Path<String>,
    Qs(p): Qs<InspectScanQ>,
) -> Result<Response, ApiError> {
    inspect_one(
        &st,
        &rid,
        p.account,
        p.mode,
        native_query::InspectType::Message,
        id,
        p.confirm.unwrap_or(false),
    )
    .await
}

/// `GET /api/v1/chatrooms/:id/members` — 查群成员。**R16-1 起冷热双模 (降级件)**: mode=hot 直读加密
/// `contact.db` 的 `chat_room` 行解 proto 展开当前在群名单; cold 读 L1 chatroom_member。
///
/// **热查明说降级** (决策②): `joined_at` 恒 null (源库 proto 无入群时刻); 已退群成员不返回 (仅当前在群快照);
/// summary 里 `partial:true`+`degraded` —— 调用方据此知道这份比冷查窄。
async fn get_members(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Path(id): Path<String>,
    Qs(p): Qs<MembersQ>,
) -> Result<Response, ApiError> {
    let admins_only = p.admins_only.unwrap_or(false);
    let limit = clamp_limit(p.limit, 100, 500);
    let offset = clamp_offset(p.offset);
    // codex 审 P1: 缺省必须 **Auto**(不是 unwrap_or_default —— QueryMode::default()=Hot)。/chatrooms/:id/members
    // 是 R16 前就有的端点, OpenAPI + MembersQ 都承诺"省略=auto"; 用 default(Hot)会让老调用方(有 --l1-db 服务器,
    // 期望冷查)被翻成热查 → 要 wxid/key 常 400, 或返降级快照。同 get_emoticons/get_chatrooms 用显式 Auto。
    match p
        .mode
        .unwrap_or(native_query::QueryMode::Auto)
        .effective(st.l1_db.is_some())
    {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_members(&wxid, st.wechat_data_dir.as_deref(), &id, admins_only, limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::members_query(c, &id, admins_only, limit, offset)
            })
            .await
        }
    }
}

// ── 热查 (直读加密源库; sessions/messages) ──

async fn get_sessions(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<ListQ>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(p.limit, 50, 500);
    let offset = clamp_offset(p.offset);
    // R6: mode 派发 (auto 按服务端有无 L1)。cold 走 cold() choke —— 自动 scoped + 挂 freshness + meta.account。
    match p.mode.unwrap_or_default().effective(st.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = require_wxid(&st, &rid, p.account)?;
            let r = native_query::hot_sessions(&wxid, st.wechat_data_dir.as_deref(), None, limit, offset)
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
            Ok(envelope(&r))
        }
        native_query::EffectiveMode::Cold => {
            cold(&st, &rid, p.account, move |c, _l1, _sha| {
                native_query::cold_sessions_query(c, limit, offset)
            })
            .await
        }
    }
}

/// `/messages` 分发器 (§6b 投影 + 会话热查双模)。见 [`MessagesQ`] 文档说明路由/延后项。
async fn get_messages(
    State(st): State<Shared>,
    Extension(rid): Extension<RequestId>,
    Qs(p): Qs<MessagesQ>,
) -> Result<Response, ApiError> {
    // 投影选择器 (§6b): 互斥, 有则冷查派生表, 无则热查会话。
    let has_kind = p.kind.as_deref().is_some_and(|s| !s.is_empty());
    let has_mentions = p.mentions.as_deref().is_some_and(|s| !s.is_empty()) || p.mentions_me == Some(true);
    let has_official = p.conv_type.as_deref() == Some("official");
    let has_quote = p.quote == Some(true);
    let selectors =
        usize::from(has_kind) + usize::from(has_mentions) + usize::from(has_official) + usize::from(has_quote);

    // ── 通用参数校验 (审查 B D3/D4/D8: 必须提到分支之前 —— 若落 selectors==0 早返之后, 热查会话分支的
    //    ?conv=X&sys_type=Y / ?kind=X&conv_type=bogus 会被静默吞, 与冷路同参 400 自相矛盾) ──
    // conv_type 只认 official; 非法值 → 400 (无论有无其它选择器)。
    if let Some(ct) = p.conv_type.as_deref() {
        if ct != "official" {
            return Err(ApiError::bad_request(
                &rid,
                format!("conv_type 无效: {ct} (仅 official)"),
            ));
        }
    }
    // sys_type 仅 kind=system 有效; 别处给 (含热查会话) → 400, 不静默吞。
    if p.sys_type.is_some() && p.kind.as_deref() != Some("system") {
        return Err(ApiError::bad_request(&rid, "sys_type 仅 kind=system 有效"));
    }
    // mentions 与 mentions_me 互斥 (字段 doc 明示互斥); 同给 → 400 (不静默优先 mentions 吞 mentions_me; round3
    // sweep: 与 offset/sys_type/conv_type "不适用即显式 400" 一致, 补齐"无字段被静默丢"不变量)。
    if p.mentions.as_deref().is_some_and(|s| !s.is_empty()) && p.mentions_me == Some(true) {
        return Err(ApiError::bad_request(&rid, "mentions 与 mentions_me 互斥 (只给一个)"));
    }

    // ── 无投影 → 会话消息 (R6: mode 派发冷热; 需 conv) ──
    if selectors == 0 {
        let Some(conv) = p.conv.clone().filter(|s| !s.is_empty()) else {
            return Err(ApiError::bad_request(
                &rid,
                "messages 需要 ?conv= (对方 wxid 或群 id), 或给投影参 (kind/mentions/mentions_me/conv_type=official/quote)",
            ));
        };
        let limit = clamp_limit(p.limit, 30, 200);
        return match p.mode.unwrap_or_default().effective(st.l1_db.is_some()) {
            native_query::EffectiveMode::Hot => {
                // offset 不支持热查会话 (round2 回归: hot_messages 返最近 N 无分页 → offset>0 显式拒, 不静默吞成恒最近页)。
                if p.offset.unwrap_or(0) > 0 {
                    return Err(ApiError::bad_request(
                        &rid,
                        "offset 不支持实时查会话消息 (返最近 N, 无分页); 深翻用 mode=cold, 或投影 kind=, 或去掉 offset",
                    ));
                }
                let wxid = require_wxid(&st, &rid, p.account)?;
                let r = native_query::hot_messages(&wxid, &conv, st.wechat_data_dir.as_deref(), None, limit)
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
                Ok(envelope(&r))
            }
            native_query::EffectiveMode::Cold => {
                let offset = clamp_offset(p.offset); // 冷查会话消息支持 offset 翻页 (与投影一致)。
                                                     // R22 懒式落库: 先把这个会话的新消息补进 L1, 于是冷查结果总是最新的。判据是插入序
                                                     // (`WHERE local_id > 游标`) 不是时间 —— 回填 / 表重建 / 乱序 / 同秒并发都不漏。
                let mut skip_reason: Option<&'static str> = None;
                if p.refresh != Some(false) {
                    skip_reason = refresh_chat_soft(&st, &rid, p.account.clone(), &conv).await?;
                }

                cold_with_skip(&st, &rid, p.account, skip_reason, move |c, _l1, _sha| {
                    native_query::cold_messages_query(c, &conv, limit, offset)
                })
                .await
            }
        };
    }

    if selectors > 1 {
        return Err(ApiError::bad_request(
            &rid,
            "投影选择器互斥 (kind / mentions(_me) / conv_type=official / quote 只能给一个)",
        ));
    }

    // R6: 投影恒冷查、无实时版 → 显式 mode=hot **报错不静默忽略** (审查维度1: 参数在某分支被无声吞是本库老毛病)。
    // **R16-2 起**部分投影有热查版 (kind=system→hot_events, kind=call→hot_calls, kind=image→hot_media, kind=biz→hot_biz,
    // …) → 从此拦截**豁免**, 由下方各分支按 effective 派发; 尚无热版的投影 (mentions/quote) 仍显式 mode=hot → 400
    // (逐条接热查时把该 kind 加进 HOT_PROJECTION_KINDS)。mode=cold/auto/缺省 → 冷投影 (auto 无 L1 由 cold() 报错)。
    // **conv_type=official = kind=biz 别名**(kind 为 None 但 has_official), 有热版 → 也豁免。
    const HOT_PROJECTION_KINDS: &[&str] = &["system", "call", "link", "file", "image", "biz", "forward"];
    if p.mode == Some(native_query::QueryMode::Hot)
        && !has_official
        && !has_quote
        && !has_mentions
        && !p.kind.as_deref().is_some_and(|k| HOT_PROJECTION_KINDS.contains(&k))
    {
        return Err(ApiError::bad_request(
            &rid,
            "该投影无实时版; mode=hot 只对会话消息 (无投影参) 或 kind=system/call/link/file/image/biz/forward / conv_type=official / quote / mentions(_me) 有效。去掉 mode=hot 或去掉投影参",
        ));
    }

    // ── 冷查投影 (以下均无 conv 过滤: 内核投影函数无 conv 参 → 有 conv 是矛盾请求, 拒之非静默忽略) ──
    if p.conv.as_deref().is_some_and(|s| !s.is_empty()) {
        return Err(ApiError::bad_request(
            &rid,
            "投影 (kind/mentions/conv_type/quote) 不支持 conv 过滤 (内核投影无 conv 参); 去掉 conv, 或无投影时用 conv 走热查会话",
        ));
    }

    let limit = clamp_limit(p.limit, 30, 200);
    let offset = clamp_offset(p.offset); // 审查 B D3: 投影超 limit 的行经 offset 可达。

    if has_quote {
        // quote=true = thread(引用回复, appmsg type57); R16-2 起冷热双模(镜像 kind=biz 的 biz_dispatch)。
        return thread_dispatch(&st, &rid, p.account, p.mode, offset, limit, p.confirm.unwrap_or(false)).await;
    }
    if has_official {
        // conv_type=official = kind=biz 别名; R16-2 起冷热双模(同 kind=biz 分支)。
        return biz_dispatch(&st, &rid, p.account, p.mode, offset, limit).await;
    }
    if has_mentions {
        // **R16-2 起冷热双模** (镜像 CLI mentions / MCP wx_mentions)。默认 Auto。
        return match p
            .mode
            .unwrap_or(native_query::QueryMode::Auto)
            .effective(st.l1_db.is_some())
        {
            native_query::EffectiveMode::Hot => {
                // 热: 账号 wxid = 定位 + "我"。mentions=X → who=X; mentions_me → who=账号自身 wxid(= me, 无需 L1)。
                let wxid = require_wxid(&st, &rid, p.account)?;
                let who = p
                    .mentions
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| wxid.as_str().to_string());
                http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
                let permit = hot_scan_permit(&rid, offset, limit).await?;
                let r = native_query::hot_mentions(
                    &wxid,
                    st.wechat_data_dir.as_deref(),
                    None,
                    Some(&who),
                    limit,
                    offset,
                    Some(permit),
                )
                .await
                .map_err(|e| map_core_err(&rid, &e))?;
                Ok(envelope(&r))
            }
            native_query::EffectiveMode::Cold => {
                // 冷: mentions=<X>: who=X, scope=p.account。mentions_me: who=scope=me(显式 account > --wxid 默认 > 单账号
                // person.account_id > 400) —— scope 与 who **对齐同一 wxid**(审查 B D4)。person.account_id 常空 → 先叠默认。
                let (who, scope) = if let Some(w) = p.mentions.clone().filter(|s| !s.is_empty()) {
                    (w, p.account.clone())
                } else {
                    let l1 = require_l1(&st, &rid)?;
                    let me = resolve_self_wxid(&l1, p.account.clone().or_else(|| st.default_account.clone()), &rid)?;
                    (me.clone(), Some(me))
                };
                cold(&st, &rid, scope, move |c, _l1, _sha| {
                    native_query::mentions_query(c, Some(&who), limit, offset)
                })
                .await
            }
        };
    }
    // has_kind (唯一剩余选择器)。
    match p.kind.as_deref().unwrap_or_default() {
        "call" => {
            // R16-2 起冷热双模 (镜像 CLI calls / MCP wx_calls)。默认 Auto (unwrap_or(Auto) 同 R16-1)。
            match p
                .mode
                .unwrap_or(native_query::QueryMode::Auto)
                .effective(st.l1_db.is_some())
            {
                native_query::EffectiveMode::Hot => {
                    let wxid = require_wxid(&st, &rid, p.account)?;
                    // codex 3a10c84 P1: 热扫并发闸 permit 移进 hot_calls 的 spawn_blocking 持到扫完(超时也不释放)。
                    http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
                    let permit = hot_scan_permit(&rid, offset, limit).await?;
                    let r = native_query::hot_calls(
                        &wxid,
                        st.wechat_data_dir.as_deref(),
                        None,
                        limit,
                        offset,
                        Some(permit),
                    )
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
                    Ok(envelope(&r))
                }
                native_query::EffectiveMode::Cold => {
                    cold(&st, &rid, p.account, move |c, _l1, _sha| {
                        native_query::calls_query(c, limit, offset)
                    })
                    .await
                }
            }
        }
        "link" => {
            // R16-2 起冷热双模 (镜像 CLI links / MCP wx_links)。默认 Auto。
            match p
                .mode
                .unwrap_or(native_query::QueryMode::Auto)
                .effective(st.l1_db.is_some())
            {
                native_query::EffectiveMode::Hot => {
                    let wxid = require_wxid(&st, &rid, p.account)?;
                    http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
                    let permit = hot_scan_permit(&rid, offset, limit).await?;
                    let r = native_query::hot_links(
                        &wxid,
                        st.wechat_data_dir.as_deref(),
                        None,
                        limit,
                        offset,
                        Some(permit),
                    )
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
                    Ok(envelope(&r))
                }
                native_query::EffectiveMode::Cold => {
                    cold(&st, &rid, p.account, move |c, _l1, _sha| {
                        native_query::links_query(c, limit, offset)
                    })
                    .await
                }
            }
        }
        "file" => {
            // R16-2 起冷热双模 (镜像 CLI files / MCP wx_files)。默认 Auto。
            match p
                .mode
                .unwrap_or(native_query::QueryMode::Auto)
                .effective(st.l1_db.is_some())
            {
                native_query::EffectiveMode::Hot => {
                    let wxid = require_wxid(&st, &rid, p.account)?;
                    http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
                    let permit = hot_scan_permit(&rid, offset, limit).await?;
                    let r = native_query::hot_files(
                        &wxid,
                        st.wechat_data_dir.as_deref(),
                        None,
                        limit,
                        offset,
                        Some(permit),
                    )
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
                    Ok(envelope(&r))
                }
                native_query::EffectiveMode::Cold => {
                    cold(&st, &rid, p.account, move |c, _l1, _sha| {
                        native_query::files_query(c, limit, offset)
                    })
                    .await
                }
            }
        }
        "biz" => biz_dispatch(&st, &rid, p.account, p.mode, offset, limit).await,
        "system" => {
            // R16-2 起冷热双模 (镜像 CLI events / MCP wx_events)。默认 Auto(同 R16-1 get_moments/get_favorites:
            // unwrap_or(Auto) 显式覆盖 QueryMode::default()=Hot, 有 L1 走冷否则热)。sys_type 两路都吃。
            // Claude 审 P3-1: 空串 sys_type 归 None(= 无过滤), 三皮统一(MCP filter(!is_empty) 同款), 否则
            // Some("") → WHERE sys_type='' 恒 0 行, 与 MCP "返全部" 分叉。
            let sys = p.sys_type.clone().filter(|s| !s.is_empty());
            match p
                .mode
                .unwrap_or(native_query::QueryMode::Auto)
                .effective(st.l1_db.is_some())
            {
                native_query::EffectiveMode::Hot => {
                    let wxid = require_wxid(&st, &rid, p.account)?;
                    // codex 3a10c84 P1: 热扫并发闸 permit 移进 hot_events 的 spawn_blocking 持到扫完(超时也不释放)。
                    http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
                    let permit = hot_scan_permit(&rid, offset, limit).await?;
                    let r = native_query::hot_events(
                        &wxid,
                        st.wechat_data_dir.as_deref(),
                        None,
                        sys.as_deref(),
                        limit,
                        offset,
                        Some(permit),
                    )
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
                    Ok(envelope(&r))
                }
                native_query::EffectiveMode::Cold => {
                    cold(&st, &rid, p.account, move |c, _l1, _sha| {
                        native_query::events_query(c, sys.as_deref(), limit, offset)
                    })
                    .await
                }
            }
        }
        "image" => {
            // R16-2 起冷热双模 (镜像 CLI media / MCP wx_get_media)。默认 Auto。kind=image 返**完整媒体清单**
            // (CMD_MEDIA/hot_media 含图/视频/语音/表情, 非仅图)。
            match p
                .mode
                .unwrap_or(native_query::QueryMode::Auto)
                .effective(st.l1_db.is_some())
            {
                native_query::EffectiveMode::Hot => {
                    let wxid = require_wxid(&st, &rid, p.account)?;
                    // codex 3a10c84 P1: 全库扫热查取 HOT_SCAN_SEMAPHORE permit 移进 hot_media 的 spawn_blocking。
                    http_cost_gate(&st, &rid, &wxid, offset, limit, p.confirm.unwrap_or(false)).await?;
                    let permit = hot_scan_permit(&rid, offset, limit).await?;
                    let r = native_query::hot_media(
                        &wxid,
                        st.wechat_data_dir.as_deref(),
                        None,
                        limit,
                        offset,
                        Some(permit),
                    )
                    .await
                    .map_err(|e| map_core_err(&rid, &e))?;
                    Ok(envelope(&r))
                }
                native_query::EffectiveMode::Cold => {
                    cold_cmd(&st, &rid, p.account, &native_query::CMD_MEDIA, limit, offset).await
                }
            }
        }
        // R16-2: kind=forward 挂上 (原"暂未挂 HTTP")。双模式: ?msg_id=X 展开该条子项 / 省略=列所有合并转发。冷热双模。
        // R16-2 修: ?source=<分片> 精确定位(锚跨分片重号)。Claude P3-2: 空串 msg_id/source 归 None(镜像 sys_type 归一,
        // 三皮统一) —— 否则 ?source= 空 → Some("") 跳过歧义检测 → WHERE source='' 0 行 → 误导性 404(该给 BadRequest 指引)。
        "forward" => {
            let fmsg = p.msg_id.clone().filter(|s| !s.is_empty());
            let fsrc = p.source.clone().filter(|s| !s.is_empty());
            resolve_dispatch(
                &st,
                &rid,
                p.account,
                fmsg,
                fsrc,
                p.mode,
                offset,
                limit,
                p.confirm.unwrap_or(false),
            )
            .await
        }
        other => Err(ApiError::bad_request(
            &rid,
            format!("kind 无效: {other} (call/link/file/image/system/biz/forward)"),
        )),
    }
}

// ── 路由 ──

/// 建路由 (端点 + request-id 中间件 + CORS)。**CORS 收紧 (§3 白名单/Expose-Headers)** 留加固步; 骨架
/// permissive (loopback 默认)。(`Router` 本身 `#[must_use]`, 不再重复标。)
/// §9 可选请求超时中间件 (serve `--request-timeout-secs`): 非流式端点处理超 `d` → 408 `REQUEST_TIMEOUT`
/// (§5 错误体)。**流式 `/events`(SSE 无限) / `/media`(大文件/联网) 不受此限** —— 它们本就长连, 加总超时会误切。
async fn timeout_mw(req: axum::extract::Request, next: axum::middleware::Next, d: std::time::Duration) -> Response {
    let path = req.uri().path();
    if path == "/api/v1/events" || path.starts_with("/api/v1/media/") {
        return next.run(req).await; // 流式端点: 不加总超时
    }
    let rid = req
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(|| RequestId("req-unknown".to_string()));
    match tokio::time::timeout(d, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => ApiError::new(
            &rid,
            StatusCode::REQUEST_TIMEOUT,
            "REQUEST_TIMEOUT",
            format!("请求处理超过 {}s 上限 (serve --request-timeout-secs 配)", d.as_secs()),
        )
        .into_response(),
    }
}

/// §9 可选并发上限中间件 (serve `--max-concurrent`): 只对**常规端点**计数, **放行流式 `/events`/`/media`**
/// —— 它们各有 EVENTS(32)/MEDIA(16)/EGRESS(8) 闸兜, 且 media handler 内联联网/解密会持 permit 跨网络, 计入全局
/// 会饿死常规请求 (§9 审 P3)。超上限的常规请求排队等待 (背压)。
async fn concurrency_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
    sem: std::sync::Arc<tokio::sync::Semaphore>,
) -> Response {
    let path = req.uri().path();
    if path == "/api/v1/events" || path.starts_with("/api/v1/media/") {
        return next.run(req).await; // 流式端点: 不占并发名额 (各有 per-op 闸)
    }
    let _permit = sem.acquire().await.expect("concurrency semaphore 不会关闭");
    next.run(req).await
}

/// 访问日志 path 脱敏 (K-R4): **按真实路由模板逐段匹配** —— 只有模板里该**位置**是静态词才原样留,
/// 路径参数位 (`*`) 一律 `<id>`; 任何路径匹配不到模板则 fail-closed 全脱 (仅留 api/v1 公开前缀)。
///
/// **为何位置感知** (codex d4b5921 P1): 旧做法"段值 ∈ 白名单就留"是**位置无关**的。微信 UserName 是宽松
/// 不透明 id (真库 ~10% 无固定标记的 legacy/自定义号如 `momo526005`), 一个 id 段可能**恰好等于**某路由词
/// —— 如 contact id = "status" / "locations", 位置无关白名单会把 `/api/v1/contacts/status` 原样记进日志 =
/// 明文账号标识泄漏破 K-R4。故按**位置**判: 模板 `["api","v1","contacts","*"]` 第 4 位是参数 → 无论段值
/// 是 "status" 还是 "wxid_x" 一律 `<id>`。
///
/// **为何模板全匹配** (§9 审查历史): 反黑名单 (按 `wxid_`/`gh_`/`@`/`:` 形状判) 会漏无标记的自定义号 +
/// percent-encoded 段。模板法**不看段内容**, 逢任何 id 形态天然安全。调用方传 `uri().path()` (不含 query)。
fn redact_log_path(path: &str) -> String {
    // 全部路由模板 (与 build_router 的 .route 同步; `*` = 路径参数占位)。改路由须同步这里 ——
    // redact_log_path_whitelist 测钉每条真实路由脱敏结果 + codex d4b5921 P1 位置冲突反例守回归。
    const TEMPLATES: &[&[&str]] = &[
        &["health"],
        &["api", "v1", "ping"],
        &["api", "v1", "openapi.json"],
        &["api", "v1", "live-index", "status"],
        &["api", "v1", "account"],
        &["api", "v1", "accounts"],
        &["api", "v1", "capture"], // R19 选择性采集清单 (codex round-1 P3: 漏注册则访问日志误分类为 /<id>)
        &["api", "v1", "names"],
        &["api", "v1", "exec"],
        &["api", "v1", "events"],
        &["api", "v1", "media", "*"],
        &["api", "v1", "contacts"],
        &["api", "v1", "contacts", "*"],
        &["api", "v1", "contacts", "*", "pack"],
        &["api", "v1", "sessions"],
        &["api", "v1", "sessions", "*"],
        &["api", "v1", "sessions", "*", "pack"],
        &["api", "v1", "messages"],
        &["api", "v1", "messages", "*"],
        &["api", "v1", "chatrooms"],
        &["api", "v1", "chatrooms", "*"],
        &["api", "v1", "chatrooms", "*", "members"],
        &["api", "v1", "avatars"],
        &["api", "v1", "locations"],
        &["api", "v1", "group-events"], // codex fav_media P2: R16-2 建端点时漏注册 → 访问日志曾误分类为 /<id>
        &["api", "v1", "cards"],
        &["api", "v1", "biz-contacts"],
        &["api", "v1", "friend-requests"],
        &["api", "v1", "moments"],
        &["api", "v1", "moments", "interactions"],
        &["api", "v1", "moments", "inbox"],
        &["api", "v1", "money"],
        &["api", "v1", "money", "claims"], // R16-4 红包领取子视图
        &["api", "v1", "money", "payers"], // R16-4 群收款付款人子视图
        &["api", "v1", "pii-scan"],        // R16-5 PII 扫描
        &["api", "v1", "favorites"],
        &["api", "v1", "favorites", "media"], // R16-3 收藏媒体子视图
        &["api", "v1", "favorites", "tags"],  // R16-3 收藏标签子视图
        &["api", "v1", "channels"],
        &["api", "v1", "emoticons"],
        &["api", "v1", "search"],
        &["api", "v1", "stats"],
        &["api", "v1", "dormant"],
        &["api", "v1", "followups"],
        &["api", "v1", "extract"],
        &["api", "v1", "msgraw"],
    ];
    // 按 '/' 切; **保留内部/尾部空段**(不 filter) —— 双斜杠 `//` / 尾斜杠产生的空段匹配不到任何模板静态词
    // → 落 fail-closed。与 Axum 对畸形路径 404 的语义一致: 不把 `/api/v1//locations` 归一成合法路由再原样记
    // (codex 23d888b P2#1)。仅去掉**前导 '/'** 的第一个空段(HTTP path 恒以 '/' 起)。
    let mut segs: Vec<&str> = path.split('/').collect();
    if segs.first() == Some(&"") {
        segs.remove(0);
    }
    for tmpl in TEMPLATES {
        if tmpl.len() == segs.len() && tmpl.iter().zip(&segs).all(|(t, s)| *t == "*" || t == s) {
            let joined = tmpl
                .iter()
                .zip(&segs)
                .map(|(t, s)| if *t == "*" { "<id>" } else { *s })
                .collect::<Vec<_>>()
                .join("/");
            return format!("/{joined}");
        }
    }
    // 无模板命中 (未知路径 / 404 探测 / 畸形): fail-closed 全脱。**仅当路径确以 `api/v1` 完整前缀开头**才留这
    // 两段 (公开常量, 便于识别 API 流量); 否则连 api/v1 也脱 —— 否则 `/lookup/v1/secret` 会留 "v1"、`/api/secret`
    // 留 "api", 而未知段是用户可控、可能恰好等于路由词的不透明 id (codex 23d888b P2#2)。
    let has_api_v1_prefix = segs.first() == Some(&"api") && segs.get(1) == Some(&"v1");
    let joined = segs
        .iter()
        .enumerate()
        .map(|(i, s)| if has_api_v1_prefix && i < 2 { *s } else { "<id>" })
        .collect::<Vec<_>>()
        .join("/");
    format!("/{joined}")
}

#[cfg(test)]
mod redact_tests {
    use super::redact_log_path;

    /// K-R4 模板位置感知脱敏: 真实路由静态段留、任何 id 段 (含 legacy 自定义号 / 中文 / 编码 / 媒体 key /
    /// **恰好等于某路由词的 id**) 全 `<id>`, 无明文泄漏。
    #[test]
    fn redact_log_path_whitelist() {
        // 各 id 形态都脱敏 (§9 审查 P1: legacy 无前缀号 momo526005 曾漏; P3: percent-encoded)。
        for (raw, want) in [
            ("/api/v1/contacts/wxid_abc", "/api/v1/contacts/<id>"),
            ("/api/v1/contacts/momo526005", "/api/v1/contacts/<id>"), // legacy 自定义号 (P1)
            ("/api/v1/contacts/wxid_x/pack", "/api/v1/contacts/<id>/pack"),
            ("/api/v1/sessions/wang19971216/pack", "/api/v1/sessions/<id>/pack"),
            (
                "/api/v1/chatrooms/123@chatroom/members",
                "/api/v1/chatrooms/<id>/members",
            ),
            ("/api/v1/media/emoji:abc", "/api/v1/media/<id>"),
            ("/api/v1/media/moment:Sns_1%3A0", "/api/v1/media/<id>"), // percent-encoded (P3)
            ("/api/v1/messages/9007", "/api/v1/messages/<id>"),
            ("/api/v1/moments/interactions", "/api/v1/moments/interactions"), // 全静态不动
            // codex 6ba1ba2 P2 + 全扫: R16 registry 路由静态段留、其后 id 段仍脱敏。
            ("/api/v1/locations", "/api/v1/locations"),
            ("/api/v1/group-events", "/api/v1/group-events"), // codex fav_media P2: R16-2 漏注册, 补
            ("/api/v1/favorites/media", "/api/v1/favorites/media"), // R16-3 收藏媒体子视图
            ("/api/v1/favorites/tags", "/api/v1/favorites/tags"), // R16-3 收藏标签子视图
            ("/api/v1/money/claims", "/api/v1/money/claims"), // R16-4 红包领取子视图
            ("/api/v1/money/payers", "/api/v1/money/payers"), // R16-4 群收款付款人子视图
            ("/api/v1/pii-scan", "/api/v1/pii-scan"),         // R16-5 PII 扫描
            ("/api/v1/avatars", "/api/v1/avatars"),
            ("/api/v1/biz-contacts", "/api/v1/biz-contacts"),
            ("/api/v1/emoticons", "/api/v1/emoticons"),
            ("/api/v1/live-index/status", "/api/v1/live-index/status"), // 两段全静态
            // codex d4b5921 P1: id 段**恰好等于**某路由词时, 位置无关白名单会原样记 = 泄漏。模板法按位置判,
            // 参数位一律 <id> (微信 UserName 是宽松不透明 id, "status"/"locations"/"pack" 都可能是真 id 值)。
            ("/api/v1/contacts/status", "/api/v1/contacts/<id>"),
            ("/api/v1/messages/locations", "/api/v1/messages/<id>"),
            ("/api/v1/media/emoticons", "/api/v1/media/<id>"),
            ("/api/v1/contacts/pack/pack", "/api/v1/contacts/<id>/pack"), // 参数位=pack 也脱
            ("/api/v1/chatrooms/members/members", "/api/v1/chatrooms/<id>/members"),
            // codex 23d888b P2: 畸形/未知路径必落 fail-closed, 不许保留用户可控段(哪怕它恰好等于 api/v1)。
            ("/api/v1//locations", "/api/v1/<id>/<id>"), // P2#1 中段双斜杠: 空段保留 → 不匹配 locations 模板
            ("/lookup/v1/secret", "/<id>/<id>/<id>"),    // P2#2 非 api 前缀: "v1" 也不许留
            ("/api/secret", "/<id>/<id>"),               // P2#2 仅 api 段: 不许留(需完整 api/v1 前缀)
            ("/api/v1/moments/inbox", "/api/v1/moments/inbox"), // Claude P3: 正例钉住 moments/inbox 模板
            ("/health", "/health"),
        ] {
            assert_eq!(redact_log_path(raw), want, "{raw}");
        }
        // 模板同步守卫: 每个 collection 根路由 /api/v1/<c> 必留静态段。漏一条模板 = 该 collection 被 fail-closed
        // 成 <id>, 这里逮到 (改 build_router 加/删路由须同步 TEMPLATES + 这张清单)。
        for c in [
            "ping",
            "openapi.json",
            "account",
            "accounts",
            "capture",
            "names",
            "exec",
            "events",
            "contacts",
            "sessions",
            "messages",
            "chatrooms",
            "avatars",
            "locations",
            "cards",
            "biz-contacts",
            "friend-requests",
            "moments",
            "money",
            "favorites",
            "channels",
            "emoticons",
            "search",
            "stats",
            "dormant",
            "followups",
            "extract",
            "msgraw",
        ] {
            let p = format!("/api/v1/{c}");
            assert_eq!(redact_log_path(&p), p, "collection 根 {c} 应保留静态段");
        }
        // 兜底: 任何非白名单段都成 <id>, 逐段确认无原值残留。
        for raw in ["/api/v1/contacts/纯中文昵称", "/api/v1/names/gh_official"] {
            let r = redact_log_path(raw);
            assert!(!r.contains("纯中文"), "{r}");
            assert!(!r.contains("gh_official"), "{r}");
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let request_timeout = state.request_timeout;
    let max_concurrent = state.max_concurrent;
    let mut router = Router::new()
        // 探针 (就绪门外)。
        .route("/health", get(health))
        .route("/api/v1/ping", get(ping))
        .route("/api/v1/openapi.json", get(get_openapi))
        // R9 复审 R2#7: live-index 索引状态 (设计要求的 HTTP status 端点)。
        .route("/api/v1/live-index/status", get(get_live_index_status))
        // 汇总 / 列表。
        .route("/api/v1/account", get(get_account))
        .route("/api/v1/accounts", get(get_accounts))
        .route("/api/v1/capture", get(get_capture)) // R19 选择性采集清单 (只读反映)
        .route("/api/v1/names", get(get_names).post(post_names))
        .route("/api/v1/exec", post(post_exec))
        .route("/api/v1/events", get(get_events))
        .route("/api/v1/media/:key", get(get_media))
        .route("/api/v1/contacts", get(get_contacts))
        .route("/api/v1/contacts/:wxid", get(get_contact_detail))
        .route("/api/v1/contacts/:wxid/pack", get(get_contact_pack))
        .route("/api/v1/sessions", get(get_sessions))
        .route("/api/v1/sessions/:id", get(get_session_detail))
        .route("/api/v1/sessions/:id/pack", get(get_session_pack))
        .route("/api/v1/messages", get(get_messages))
        .route("/api/v1/messages/:id", get(get_message_detail))
        .route("/api/v1/chatrooms", get(get_chatrooms))
        .route("/api/v1/chatrooms/:id", get(get_chatroom_detail))
        .route("/api/v1/chatrooms/:id/members", get(get_members))
        .route("/api/v1/avatars", get(get_avatars))
        .route("/api/v1/locations", get(get_locations))
        .route("/api/v1/group-events", get(get_group_events))
        .route("/api/v1/cards", get(get_cards))
        .route("/api/v1/biz-contacts", get(get_biz_contacts))
        .route("/api/v1/friend-requests", get(get_friend_requests))
        .route("/api/v1/moments", get(get_moments))
        .route("/api/v1/moments/interactions", get(get_moments_interactions))
        .route("/api/v1/moments/inbox", get(get_moments_inbox))
        .route("/api/v1/money", get(get_money))
        .route("/api/v1/money/claims", get(get_money_claims))
        .route("/api/v1/money/payers", get(get_money_payers))
        .route("/api/v1/pii-scan", get(get_pii_scan))
        .route("/api/v1/favorites", get(get_favorites))
        .route("/api/v1/favorites/media", get(get_favorites_media))
        .route("/api/v1/favorites/tags", get(get_favorites_tags))
        .route("/api/v1/channels", get(get_channels))
        .route("/api/v1/emoticons", get(get_emoticons))
        .route("/api/v1/search", get(get_search))
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/dormant", get(get_dormant))
        .route("/api/v1/followups", get(get_followups))
        .route("/api/v1/extract", get(get_extract))
        .route("/api/v1/msgraw", get(get_msgraw))
        // 未知路径 / 错方法 → §5 错误体 (非 axum 默认空 body; 审查 F1)。中间件在外层 → fallback 也带 X-Request-Id。
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed);
    // §9 可选加固 (默认关, 只 serve 传了旗标才生效; INNER of request-id → rid 已设可进 §5 错误体)。
    if let Some(d) = request_timeout {
        router = router.layer(axum::middleware::from_fn(move |req, next| timeout_mw(req, next, d)));
    }
    if let Some(n) = max_concurrent {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(n));
        router = router.layer(axum::middleware::from_fn(move |req, next| {
            concurrency_mw(req, next, sem.clone())
        }));
    }
    router
        // 层序 (由内到外): request-id → CORS → 访问日志。(无 catch-panic —— K-R4 panic=abort 下接不住, 见上注。)
        .layer(axum::middleware::from_fn(request_id_mw))
        .layer(cors_layer())
        // §9 访问日志: 每请求 INFO span (method + **脱敏 path**) + 响应 INFO (status/latency)。给开发/AI 可观测性。
        // **K-R4**: 默认 DefaultMakeSpan 记完整 uri (含 ?account=wxid / /contacts/wxid_x 路径段 → 明文 wxid 进日志,
        // 红线!)。改自定义: 只记 path (不含 query → ?account= 不进), path 段脱敏 (wxid_/gh_/@/媒体 key → <id>)。
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|req: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!("http", method = %req.method(), path = %redact_log_path(req.uri().path()))
                })
                .on_response(tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .with_state(Arc::new(state))
}

/// 起 HTTP 服务 (阻塞到关停)。msgvestige `serve` 子命令调它。
///
/// # Errors
/// 绑端口失败 / 服务出错 → `anyhow::Error`。
pub async fn serve(mut state: AppState, addr: std::net::SocketAddr) -> anyhow::Result<()> {
    // §9 优雅关停: 建关停广播注入 AppState → Ctrl-C 时先 send(true) 让 SSE 长连流立即收尾 (否则 SSE body
    //   永不结束 → 连接 future 不 resolve → axum graceful shutdown 永久挂起, 见审查 shutdown-leak)。
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    state.shutdown = Some(sd_rx);
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("HTTP API serve on http://{addr} (只读; loopback)");
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = sd_tx.send(true); // 先通知 SSE 流收尾, 再让 axum 排空在途连接
                                      // §9 硬超时兜底: 10s 内没排空 (卡死/慢读连接) 就强制退出, 别永久挂 (SSE 广播已让长连收尾, 这是双保险)。
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                tracing::warn!("优雅关停超时 10s, 强制退出");
                std::process::exit(0);
            });
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{HeaderValue, Request, StatusCode};
    use tower::ServiceExt;

    use super::{build_router, media_bytes_response, parse_single_byte_range, AppState, RangeResult}; // oneshot

    /// **断线补发起点: 证不出连续就得喊 resync**。
    ///
    /// 这套判定原先长在 handler 的闭包里, 零守卫, 而它管的是"客户端会不会以为自己没漏、其实漏了"。
    /// 归档清空那一格是 codex 审 24 小时清理时点出来的: 清空后 `min`/`max` 全变 0,
    /// 老代码 `min > 0 &&` 的前提当场不成立, 于是一声不吭按"没漏"续下去。
    #[test]
    fn resume_point_flags_every_gap_it_cannot_rule_out() {
        use super::{sse_resume_point, SSE_MAX_CATCHUP};

        // 接得上: 位置就在现存区间里, 或正好差一条(下一条就是最老那条)。
        assert_eq!(sse_resume_point(500, 100, 900), (500, false), "区间内, 照常续");
        assert_eq!(
            sse_resume_point(99, 100, 900),
            (99, false),
            "id == min-1: 下一条正好是 min, 接得上"
        );

        // 中间那段被滚动窗口清掉了。
        assert_eq!(
            sse_resume_point(50, 100, 900),
            (99, true),
            "50..99 已被清 → 必须 resync"
        );

        // **归档被清空**: 老代码在这儿返回 (id, false) —— 静默漏。
        assert_eq!(
            sse_resume_point(500, 0, 0),
            (0, true),
            "整表清空后客户端拿老位置回来, 必须 resync; 静默续下去等于告诉他没漏"
        );

        // 库被重建 → id 从头发, 客户端位置反超表里最大值。
        assert_eq!(
            sse_resume_point(1000, 1, 500),
            (500, true),
            "位置反超 max → 库重建过, 必须 resync"
        );

        // 落后太多: 有界近窗补发, 不做全档倒扫。
        let far = SSE_MAX_CATCHUP + 5000;
        assert_eq!(
            sse_resume_point(1, 1, far),
            (far - SSE_MAX_CATCHUP, true),
            "落后超 SSE_MAX_CATCHUP → 从近窗起 + resync"
        );
    }

    /// 写含 person + message 行的临时 L1 (每账号 `msgs` 条消息, 各账号数不同 → 隔离测能咬)。
    /// `accounts` = (wxid, 该账号消息数); **`account_id_sha` = `sha256_hex(wxid)`** —— 必须与端点
    /// `resolve_account` 算的 sha 一致, 否则遮蔽视图 `WHERE account_id_sha=sha256(wxid)` 匹配不到 (隔离测才真咬)。
    fn write_l1(name: &str, accounts: &[(&str, usize)]) -> std::path::PathBuf {
        let tmp = std::env::temp_dir().join(name);
        let _ = std::fs::remove_file(&tmp);
        let c = rusqlite::Connection::open(&tmp).unwrap();
        native_core::storage::init_l1_schema(&c).unwrap();
        for (acc, msgs) in accounts {
            let accsha = native_core::sha256_hex(acc);
            let accsha = accsha.as_str();
            c.execute(
                "INSERT INTO person \
                 (account_id_sha, source, source_native_id, username_sha, account_id, username, \
                  nick_name, nick_name_len, remark_len, alias_len, local_type, is_in_chat_room) \
                 VALUES (?1, 's', ?2, ?3, ?4, ?4, 'n', 0, 0, 0, 1, 0)",
                rusqlite::params![accsha, format!("nid-{acc}"), format!("ush-{acc}"), acc],
            )
            .unwrap();
            for k in 0..*msgs {
                c.execute(
                    "INSERT INTO message \
                     (account_id_sha, source, source_native_id, conv_id_sha, server_id, create_time, \
                      sort_seq, status, msg_type, msg_type_name, local_type_raw, sender_wxid_sha, \
                      is_chatroom, text_content_sha, text_content_len, raw_xml_present, decode_kind, \
                      account_id, conv_id, sender_wxid, text_content) \
                     VALUES (?1, 'message_0.db', ?2, 'cvs', ?3, ?4, ?4, 3, 1, 'TEXT', 1, 'sws', 0, \
                             'tcs', 5, 0, 'plain', ?5, 'conv_x', ?5, 'hello')",
                    rusqlite::params![
                        accsha,
                        format!("m-{acc}-{k}"),
                        1000i64 + k as i64,
                        1_700_000_000_000i64 + k as i64,
                        acc
                    ],
                )
                .unwrap();
            }
        }
        tmp
    }

    fn state(l1: &std::path::Path) -> AppState {
        AppState {
            l1_db: Some(l1.to_str().unwrap().to_string()),
            ..Default::default()
        }
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn get(app: &Router, uri: &str) -> axum::response::Response {
        app.clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    use axum::Router;

    /// /health 探针不碰 DB, 恒 200 + X-Request-Id。
    #[tokio::test]
    async fn health_ok_without_db() {
        let app = build_router(AppState::default());
        let resp = get(&app, "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("x-request-id"), "每响应带 X-Request-Id");
    }

    /// 单账号库 /api/v1/account → 200 + 信封。
    #[tokio::test]
    async fn account_single_ok() {
        let tmp = write_l1("http_one_acct.db", &[("wxid_solo", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/account").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert!(j.get("data").is_some() && j.get("meta").is_some(), "信封 {{data,meta}}");
        let _ = std::fs::remove_file(&tmp);
    }

    /// 多账号库未指定 account → 409 ACCOUNT_AMBIGUOUS + candidates + request_id (审查 P1-2 fail-closed, HTTP 侧)。
    #[tokio::test]
    async fn multi_account_ambiguous_409() {
        let tmp = write_l1("http_two_acct.db", &[("wxid_alice", 3), ("wxid_bob", 5)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/contacts").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "多账号未指定 → 409");
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], "ACCOUNT_AMBIGUOUS");
        assert!(j["error"]["candidates"].is_array(), "带候选账号");
        assert!(j["request_id"].is_string(), "错误体带 request_id");
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19: 单账号库无圈定 → /api/v1/capture 200 空信封 (与 CLI/MCP 一致, 非报错)。
    #[tokio::test]
    async fn capture_single_account_empty_ok() {
        let tmp = write_l1("http_cap_empty.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/capture").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert!(
            j["data"].as_array().is_some_and(std::vec::Vec::is_empty),
            "空清单 = 空 data 数组"
        );
        assert_eq!(j["meta"]["total_count"], 0);
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19: 单账号库圈了会话 → /api/v1/capture 返该行 (conv_id/added_at/note)。
    #[tokio::test]
    async fn capture_lists_targets() {
        let tmp = write_l1("http_cap_list.db", &[("wxid_solo", 2)]);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            let sha = native_core::sha256_hex("wxid_solo");
            native_core::capture::add_capture_target(&c, &sha, "grp@chatroom", Some("团队群"), 1234).unwrap();
        }
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/capture").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["meta"]["total_count"], 1);
        assert_eq!(j["data"][0]["conv_id"], "grp@chatroom");
        assert_eq!(j["data"][0]["note"], "团队群");
        // 审 round-8 codex P2: 解析出账号 → meta.account = sha8 (三皮一致; MCP 经 fold::envelope 同走此契约, CLI json 同填)。
        let full = native_core::sha256_hex("wxid_solo");
        assert_eq!(
            j["meta"]["account"].as_str(),
            Some(&full[..8]),
            "单账号解析 → meta.account = sha8"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19: 多账号库未指定 account → /api/v1/capture 409 ACCOUNT_AMBIGUOUS (与其他端点一致 fail-closed)。
    #[tokio::test]
    async fn capture_multi_account_409() {
        let tmp = write_l1("http_cap_multi.db", &[("wxid_alice", 2), ("wxid_bob", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/capture").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "多账号未指定 → 409");
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], "ACCOUNT_AMBIGUOUS");
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐隔离真咬 (审查红队 #3 补厚夹具): 2 账号各不同消息数, ?account=alice 的 stats 只见 alice 的消息数
    /// (遮蔽视图真过滤; 若隔离破 → 见两账号之和)。
    #[tokio::test]
    async fn scoped_stats_isolates_account_messages() {
        let tmp = write_l1("http_iso_stats.db", &[("wxid_alice", 3), ("wxid_bob", 5)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/stats?account=wxid_alice&by=type").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(
            j["meta"]["summary"]["total_messages"], 3,
            "?account=alice 只见 alice 的 3 条 (非 8; 隔离破会串味)"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐fail-open 参数已堵 (审查红队 #1): 端点不认的参数 (moments 不吃 kind) → 400, **不静默吞返全量**。
    #[tokio::test]
    async fn unknown_param_rejected_400() {
        let tmp = write_l1("http_param.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        // moments 只认 account/limit; 传 kind → deny_unknown_fields → Qs 拒 400 §5。
        let resp = get(&app, "/api/v1/moments?kind=call").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "未知参数 → 400 (不静默忽略)");
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], "BAD_REQUEST");
        assert!(j["request_id"].is_string());
        // 完全瞎编的参数也拒。
        assert_eq!(
            get(&app, "/api/v1/contacts?bogus=1").await.status(),
            StatusCode::BAD_REQUEST
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐审查 F1: 未知路径 → §5 404 体 (非 axum 空 body); 错方法 (POST 到只读端点) → §5 405 体。都带 X-Request-Id。
    #[tokio::test]
    async fn unknown_path_and_bad_method_get_v5_body() {
        let app = build_router(AppState::default());
        let resp = get(&app, "/api/v1/nope").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.headers().contains_key("x-request-id"), "404 也带 X-Request-Id");
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], "NOT_FOUND", "404 带 §5 code (非空 body)");
        assert!(j["request_id"].is_string());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/account")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], "METHOD_NOT_ALLOWED", "405 带 §5 code (非空 body)");
    }

    /// ⭐审查 F2: 内核错 (坏游标 → INVALID_CURSOR) → §5 `hint` 字段被填 (非只塞进 message)。
    #[tokio::test]
    async fn kernel_error_populates_hint() {
        let tmp = write_l1("http_hint.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/contacts?cursor=ZZZZ").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], "INVALID_CURSOR");
        assert!(j["error"]["hint"].is_string(), "F2: hint 字段被填 (非 absent)");
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐A组 §3: CORS 暴露 X-Request-Id 给前端 + OPTIONS 预检 200 + allow-methods。
    #[tokio::test]
    async fn cors_exposes_headers_and_preflight() {
        let app = build_router(AppState::default());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("origin", "http://localhost:3000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let expose = resp
            .headers()
            .get("access-control-expose-headers")
            .map(|v| v.to_str().unwrap().to_lowercase())
            .unwrap_or_default();
        assert!(expose.contains("x-request-id"), "CORS 暴露 X-Request-Id 给前端 JS");
        let pre = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/v1/account")
                    .header("origin", "http://localhost:3000")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pre.status(), StatusCode::OK, "预检 200");
        let allow = pre
            .headers()
            .get("access-control-allow-methods")
            .map(|v| v.to_str().unwrap().to_uppercase())
            .unwrap_or_default();
        assert!(allow.contains("GET"), "预检返 allow-methods 含 GET");
    }

    /// 未配置 L1 的冷查端点 → 400 (非 panic)。
    #[tokio::test]
    async fn cold_without_l1_is_400() {
        let app = build_router(AppState::default());
        let resp = get(&app, "/api/v1/moments").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let j = body_json(resp).await;
        assert_eq!(j["error"]["code"], "BAD_REQUEST");
    }

    // ── B① /messages 分发器 (投影路由 + 会话热查双模) ──

    /// kind=system → events_query 冷查投影 (读 message; 表在, 无 type10000 行 → 200 空集); meta.source=cold
    /// **证明走冷路**——若误走热查, 无 wechat_data_dir + 无 account 会 400/err, 不会是 cold 200。
    #[tokio::test]
    async fn messages_kind_system_routes_cold() {
        let tmp = write_l1("http_msg_system.db", &[("wxid_solo", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?kind=system").await;
        assert_eq!(resp.status(), StatusCode::OK, "kind=system 冷查投影 200");
        let j = body_json(resp).await;
        assert_eq!(j["meta"]["source"], "cold", "走冷路 (非热查)");
        assert!(j["data"].is_array());
        let _ = std::fs::remove_file(&tmp);
    }

    /// **R16-2**: kind=system/call/link/file/image/**biz** + **conv_type=official**(=biz 别名)起支持 `mode=hot`
    /// —— **不再**被"投影无实时版"400 拦。无 account 的测试环境走进热分支会因缺 wxid 400, 但错误**不是**投影拒绝那条
    /// → 证豁免生效。对照 `quote=true&mode=hot` 仍被投影拒绝 (尚未接热查)。逐条接热查时把该 kind 加进
    /// HOT_PROJECTION_KINDS + 更新此对照(别让新接的 kind 悄悄漏出豁免名单)。
    #[tokio::test]
    async fn messages_hot_projection_exemption_system_and_call() {
        let tmp = write_l1("http_msg_hotproj.db", &[("wxid_solo", 3)]);
        let app = build_router(state(&tmp));
        for kind in ["system", "call", "link", "file", "image", "biz"] {
            let resp = get(&app, &format!("/api/v1/messages?kind={kind}&mode=hot")).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{kind} 无 account 热查 → 400");
            let msg = body_json(resp).await["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(
                !msg.contains("无实时版"),
                "kind={kind} 不该被当'投影无实时版'拒 (进了热分支); msg={msg}"
            );
        }
        // conv_type=official = kind=biz 别名, 也豁免(进热分支, 缺 wxid 400 但非投影拒绝那条)。
        let respo = get(&app, "/api/v1/messages?conv_type=official&mode=hot").await;
        assert_eq!(
            respo.status(),
            StatusCode::BAD_REQUEST,
            "official 无 account 热查 → 400"
        );
        let msgo = body_json(respo).await["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            !msgo.contains("无实时版"),
            "conv_type=official 不该被投影拒 (进了热分支); msg={msgo}"
        );
        // quote=true (=thread 引用回复) R16-2 起有热版, 也豁免(进热分支, 缺 wxid 400 但非投影拒绝那条)。
        let respq = get(&app, "/api/v1/messages?quote=true&mode=hot").await;
        assert_eq!(respq.status(), StatusCode::BAD_REQUEST, "quote 无 account 热查 → 400");
        let msgq = body_json(respq).await["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            !msgq.contains("无实时版"),
            "quote 不该被投影拒 (进了热分支); msgq={msgq}"
        );
        // R16-2: mentions/mentions_me 也有热版 (hot_mentions), 也豁免 (进热分支, 缺 wxid 400 但非"无实时版")。
        // **R16-2 后所有投影都有热版** → "无实时版"错误已不可达 (留守卫防未来新投影漏接热)。
        for q in ["mentions=wxid_x", "mentions_me=true"] {
            let respm = get(&app, &format!("/api/v1/messages?{q}&mode=hot")).await;
            assert_eq!(respm.status(), StatusCode::BAD_REQUEST, "{q} 无 account 热查 → 400");
            let msgm = body_json(respm).await["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(!msgm.contains("无实时版"), "{q} 不该被投影拒 (进了热分支); msgm={msgm}");
        }
        let _ = std::fs::remove_file(&tmp);
    }

    /// 各 kind 都路由到冷查投影 (表都在 → 200)。call/link/file/biz = 手写冷函数 (断言 source=cold);
    /// image = registry 路径 (cold_cmd/CMD_MEDIA, 只断言 200 + 信封 —— run_query meta 另形)。
    #[tokio::test]
    async fn messages_kinds_route_cold() {
        let tmp = write_l1("http_msg_kinds.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        for k in ["call", "link", "file", "biz"] {
            let resp = get(&app, &format!("/api/v1/messages?kind={k}")).await;
            assert_eq!(resp.status(), StatusCode::OK, "kind={k} → 200 冷路");
            let j = body_json(resp).await;
            assert_eq!(j["meta"]["source"], "cold", "kind={k} meta.source=cold");
        }
        // image 走 registry (CMD_MEDIA); 只验 200 + data 数组。
        let resp = get(&app, "/api/v1/messages?kind=image").await;
        assert_eq!(resp.status(), StatusCode::OK, "kind=image (registry) → 200");
        assert!(body_json(resp).await["data"].is_array());
        let _ = std::fs::remove_file(&tmp);
    }

    /// conv_type=official → biz_query (kind=biz 别名) 冷路; quote=true → thread_query 冷路。
    #[tokio::test]
    async fn messages_official_and_quote_route_cold() {
        let tmp = write_l1("http_msg_offq.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        for uri in ["/api/v1/messages?conv_type=official", "/api/v1/messages?quote=true"] {
            let resp = get(&app, uri).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri} → 200");
            assert_eq!(body_json(resp).await["meta"]["source"], "cold", "{uri} cold");
        }
        let _ = std::fs::remove_file(&tmp);
    }

    /// mentions=<X> → mentions_query 冷路 (显式 who, 无需解析自身)。
    #[tokio::test]
    async fn messages_mentions_who_routes_cold() {
        let tmp = write_l1("http_msg_mention.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?mentions=wxid_target").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["meta"]["source"], "cold");
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐mentions_me=true 单账号 → resolve_self_wxid 从 person.account_id 派生"我", mentions_query 冷路 200
    /// (不 400; 证明 self 解析成功)。
    #[tokio::test]
    async fn messages_mentions_me_resolves_self_single_account() {
        let tmp = write_l1("http_msg_me.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?mentions_me=true").await;
        assert_eq!(resp.status(), StatusCode::OK, "单账号 mentions_me 解析自身 → 冷路 200");
        assert_eq!(body_json(resp).await["meta"]["source"], "cold");
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐真跑逮到的回归 (合成夹具假绿): 真 msgcol L1 是纯消息库, **person 表空** → account_candidates (读
    /// person.account_id) 返空 → mentions_me 派生不出"我" (原 [`write_l1`] 填了 person 行故测不到; account_id 又
    /// 有 NOT NULL 约束填不成 NULL)。修 = 回退链叠服务器默认 (--wxid)。本测建 **空 person 坏夹具** (纯消息库常态),
    /// 验: 无默认 → 400 (诚实要显式); 有 --wxid 默认 → 冷路 200。
    #[tokio::test]
    async fn messages_mentions_me_falls_back_to_default_when_self_unnamed() {
        let tmp = std::env::temp_dir().join("http_msg_me_emptyperson.db");
        let _ = std::fs::remove_file(&tmp);
        let c = rusqlite::Connection::open(&tmp).unwrap();
        native_core::storage::init_l1_schema(&c).unwrap();
        // 坏夹具: 只建 schema, 不插 person 行 (纯消息库常态) → candidates 空, 派生不出"我"。
        drop(c);

        // 无 default + 无 ?account → candidates 空 → 400 (诚实要显式, 非静默错查)。
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?mentions_me=true").await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "account_id NULL 且无 default → 400"
        );

        // 服务器带 --wxid 默认 → mentions_me 用默认当"我" → 冷路 200 (回退链生效, 不再 400)。
        let st = AppState {
            l1_db: Some(tmp.to_str().unwrap().to_string()),
            default_account: Some("wxid_me".to_string()),
            ..Default::default()
        };
        let resp2 = get(&build_router(st), "/api/v1/messages?mentions_me=true").await;
        assert_eq!(
            resp2.status(),
            StatusCode::OK,
            "有 --wxid 默认 → mentions_me 走冷路 200"
        );
        assert_eq!(body_json(resp2).await["meta"]["source"], "cold");
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐审查 shutdown-leak (P2): 活跃 /events SSE 流必须**响应关停信号立即结束** —— 否则 serve 优雅关停会被
    /// 永不结束的 SSE body 卡死 (三方循环等待死锁)。验: 建 shutdown 通道 → 开 /events 流 → send(true) → 流必须
    /// EOF (不永久挂)。(kill -INT 在 MSYS/CI 不触发 ctrl_c, 故用信号通道直接验 stream 层修复。)
    #[tokio::test]
    async fn events_stream_ends_on_shutdown_signal() {
        let tmp = std::env::temp_dir().join("http_sse_shutdown.db");
        let _ = std::fs::remove_file(&tmp);
        let c = rusqlite::Connection::open(&tmp).unwrap();
        native_core::storage::init_l1_schema(&c).unwrap();
        drop(c);

        let (prog_tx, prog_rx) = tokio::sync::watch::channel(0u64);
        let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let st = AppState {
            l1_db: Some(tmp.to_str().unwrap().to_string()),
            default_account: Some("wxid_me".to_string()),
            events_progress: Some(prog_rx),
            shutdown: Some(sd_rx),
            ..Default::default()
        };
        let app = build_router(st);
        let resp = get(&app, "/api/v1/events").await;
        assert_eq!(resp.status(), StatusCode::OK, "/events 建流 200");

        // 触发关停 (模拟 serve 收 Ctrl-C 后 send)。保持 prog_tx 活 → 单独验 shutdown 臂 (非 progress-drop 分支)。
        sd_tx.send(true).unwrap();
        let _keep_prog = prog_tx;

        // 读整个 SSE body: 收到关停后流必须 EOF; 若死锁未解则永久挂 → timeout 失败。
        let body = resp.into_body();
        let got = tokio::time::timeout(std::time::Duration::from_secs(8), axum::body::to_bytes(body, 1 << 20)).await;
        assert!(
            got.is_ok(),
            "SSE 流应在 shutdown 信号后结束 (EOF), 不能永久挂住 (死锁根因)"
        );
        let text = String::from_utf8_lossy(&got.unwrap().unwrap()).to_string();
        assert!(text.contains("connected"), "至少发了初始 connected 帧");
        let _ = std::fs::remove_file(&tmp);
    }

    /// mentions_me 多账号未指定 → 409 ACCOUNT_AMBIGUOUS (要显式选"我")。
    #[tokio::test]
    async fn messages_mentions_me_multi_account_409() {
        let tmp = write_l1("http_msg_me_multi.db", &[("wxid_alice", 2), ("wxid_bob", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?mentions_me=true").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT, "多账号 mentions_me → 409");
        assert_eq!(body_json(resp).await["error"]["code"], "ACCOUNT_AMBIGUOUS");
        let _ = std::fs::remove_file(&tmp);
    }

    /// 投影选择器互斥: kind + quote 同给 → 400。
    #[tokio::test]
    async fn messages_multiple_selectors_400() {
        let tmp = write_l1("http_msg_excl.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?kind=call&quote=true").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "两个投影选择器 → 400");
        assert_eq!(body_json(resp).await["error"]["code"], "BAD_REQUEST");
        let _ = std::fs::remove_file(&tmp);
    }

    /// 投影 + conv → 400 (投影内核无 conv 参; 不静默忽略 conv 返全局投影 = 误导消费者)。
    #[tokio::test]
    async fn messages_projection_with_conv_400() {
        let tmp = write_l1("http_msg_projconv.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?kind=call&conv=wxid_x").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&tmp);
    }

    /// sys_type 仅 kind=system 有效; kind=call&sys_type=revoke → 400 (非静默吞)。
    #[tokio::test]
    async fn messages_sys_type_wrong_kind_400() {
        let tmp = write_l1("http_msg_systype.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?kind=call&sys_type=revoke").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&tmp);
    }

    /// 无投影 + 无 conv → 400 (不默默返全局明文火管)。无投影 + 非法 conv_type 值 → 400。
    #[tokio::test]
    async fn messages_no_projection_no_conv_400() {
        let tmp = write_l1("http_msg_noconv.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        assert_eq!(get(&app, "/api/v1/messages").await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            get(&app, "/api/v1/messages?conv_type=bogus").await.status(),
            StatusCode::BAD_REQUEST,
            "conv_type 非 official → 400 (不静默当无过滤)"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// 无效 kind → 400; kind=forward (R16-2 挂上) → 200 冷路列表 / 展开无子项 → 404。
    #[tokio::test]
    async fn messages_invalid_kind_400_and_forward_wired() {
        let tmp = write_l1("http_msg_badkind.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        assert_eq!(
            get(&app, "/api/v1/messages?kind=bogus").await.status(),
            StatusCode::BAD_REQUEST
        );
        // R16-2: kind=forward 挂上 (原延后 400)。列表模式(无 msg_id): 空库 → 200 空列表 source=cold。
        let resp = get(&app, "/api/v1/messages?kind=forward").await;
        assert_eq!(resp.status(), StatusCode::OK, "kind=forward 列表模式 → 200");
        assert_eq!(body_json(resp).await["meta"]["source"], "cold", "kind=forward 冷路");
        // 展开模式给不存在的 msg_id → NotFound 404 (冷热一致, 对齐 resolve_query)。
        assert_eq!(
            get(&app, "/api/v1/messages?kind=forward&msg_id=nope").await.status(),
            StatusCode::NOT_FOUND,
            "kind=forward&msg_id=不存在 → 404"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// 投影仍走账号 fail-closed: 多账号 kind=call 未指定 account → 409 (与列表端点一致)。
    #[tokio::test]
    async fn messages_projection_multi_account_409() {
        let tmp = write_l1("http_msg_projmulti.db", &[("wxid_alice", 2), ("wxid_bob", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?kind=call").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(resp).await["error"]["code"], "ACCOUNT_AMBIGUOUS");
        let _ = std::fs::remove_file(&tmp);
    }

    /// 分发器端点仍守 deny_unknown_fields: /messages?bogus=1 → 400。
    #[tokio::test]
    async fn messages_unknown_param_400() {
        let tmp = write_l1("http_msg_unknown.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/messages?bogus=1").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── B① 模板端点 ──

    /// 模板A /extract 枚举参数: kind=url → extract_query 冷路 200 (fixture 文本 'hello' 无 url → 空 data + summary)。
    #[tokio::test]
    async fn extract_url_routes_cold() {
        let tmp = write_l1("http_extract.db", &[("wxid_solo", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/extract?kind=url").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["meta"]["source"], "cold");
        assert!(j["data"].is_array());
        let _ = std::fs::remove_file(&tmp);
    }

    /// /extract 无效 kind → 400。
    #[tokio::test]
    async fn extract_invalid_kind_400() {
        let tmp = write_l1("http_extract_bad.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/extract?kind=bogus").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let _ = std::fs::remove_file(&tmp);
    }

    /// 模板B /moments/interactions registry-cmd: cold_cmd + CMD_INTERACTIONS → 200 + 信封 (表存在空集)。
    #[tokio::test]
    async fn moments_interactions_routes_cold() {
        let tmp = write_l1("http_interactions.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/moments/interactions").await;
        assert_eq!(resp.status(), StatusCode::OK, "registry-cmd 端点 200");
        let j = body_json(resp).await;
        assert!(j.get("data").is_some() && j.get("meta").is_some(), "信封 {{data,meta}}");
        assert!(j["data"].is_array());
        let _ = std::fs::remove_file(&tmp);
    }

    /// registry-cmd 端点仍走账号 fail-closed: 多账号 /moments/interactions 未指定 → 409。
    #[tokio::test]
    async fn moments_interactions_multi_account_409() {
        let tmp = write_l1("http_interactions_multi.db", &[("wxid_alice", 2), ("wxid_bob", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/moments/interactions").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(resp).await["error"]["code"], "ACCOUNT_AMBIGUOUS");
        let _ = std::fs::remove_file(&tmp);
    }

    /// /moments/inbox (CMD_SNS_NOTIFY) → 200 + 信封。
    #[tokio::test]
    async fn moments_inbox_routes_cold() {
        let tmp = write_l1("http_inbox.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/moments/inbox").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_json(resp).await["data"].is_array());
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐/accounts 列**全部**账号 (不 scoped/不 409): 多账号库返两账号 (区别于会走 fail-closed 409 的 scoped 端点)。
    #[tokio::test]
    async fn accounts_lists_all_not_scoped() {
        let tmp = write_l1("http_accounts.db", &[("wxid_alice", 2), ("wxid_bob", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/accounts").await;
        assert_eq!(resp.status(), StatusCode::OK, "/accounts 列全部 → 200 (非 409)");
        let j = body_json(resp).await;
        let ids: Vec<String> = j["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["account_id"].as_str().map(str::to_string))
            .collect();
        assert!(
            ids.contains(&"wxid_alice".to_string()) && ids.contains(&"wxid_bob".to_string()),
            "列出两账号: {ids:?}"
        );
        // 无参端点仍拒未知参 (NoParams deny_unknown)。
        assert_eq!(
            get(&app, "/api/v1/accounts?bogus=1").await.status(),
            StatusCode::BAD_REQUEST
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// /names GET: ?ids= 解析名字 (person.username=wxid → 命中); 空 ids / >100 → 400。
    #[tokio::test]
    async fn names_get_resolves_and_guards() {
        let tmp = write_l1("http_names.db", &[("wxid_solo", 1)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/names?ids=wxid_solo").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["meta"]["source"], "cold");
        assert!(j["data"].is_array());
        // 空 ids → 400。
        assert_eq!(get(&app, "/api/v1/names").await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(get(&app, "/api/v1/names?ids=").await.status(), StatusCode::BAD_REQUEST);
        // >100 → 400 (拼 101 个)。
        let many = (0..101).map(|i| format!("w{i}")).collect::<Vec<_>>().join(",");
        assert_eq!(
            get(&app, &format!("/api/v1/names?ids={many}")).await.status(),
            StatusCode::BAD_REQUEST
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐C /names POST: JSON body {ids[]} → 200; §5 body 契约: 缺 Content-Type→415, 坏 JSON→400, 空/超200→400。
    #[tokio::test]
    async fn names_post_body_and_guards() {
        let tmp = write_l1("http_names_post.db", &[("wxid_solo", 1)]);
        let app = build_router(state(&tmp));
        let post = |ct: Option<&'static str>, body: &'static str| {
            let mut b = Request::builder().method("POST").uri("/api/v1/names");
            if let Some(ct) = ct {
                b = b.header("content-type", ct);
            }
            let app = app.clone();
            async move { app.oneshot(b.body(Body::from(body)).unwrap()).await.unwrap() }
        };
        // 正常 POST JSON → 200 + 信封。
        let resp = post(Some("application/json"), r#"{"ids":["wxid_solo"]}"#).await;
        assert_eq!(resp.status(), StatusCode::OK, "POST names JSON → 200");
        assert!(body_json(resp).await["data"].is_array());
        // 缺 Content-Type → 415 (§5 code)。
        let resp = post(None, r#"{"ids":["x"]}"#).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "缺 Content-Type → 415"
        );
        assert_eq!(body_json(resp).await["error"]["code"], "UNSUPPORTED_MEDIA_TYPE");
        // 坏 JSON → 400。
        assert_eq!(
            post(Some("application/json"), "{bad").await.status(),
            StatusCode::BAD_REQUEST,
            "坏 JSON → 400"
        );
        // 未知字段 (deny_unknown_fields) → 400。
        assert_eq!(
            post(Some("application/json"), r#"{"ids":["x"],"bogus":1}"#)
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "未知字段 → 400"
        );
        // 空 ids → 400; >200 → 400。
        assert_eq!(
            post(Some("application/json"), r#"{"ids":[]}"#).await.status(),
            StatusCode::BAD_REQUEST,
            "空 ids → 400"
        );
        let big = (0..201).map(|i| format!("\"w{i}\"")).collect::<Vec<_>>().join(",");
        assert_eq!(
            post(
                Some("application/json"),
                Box::leak(format!("{{\"ids\":[{big}]}}").into_boxed_str())
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST,
            ">200 → 400"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐C /exec POST 硬只读三层: SELECT 通; 写/DDL/pragma/attach/多语句拒 (层1 字符串); WITH-前缀写过层1 但被
    /// readonly 连接+authorizer 挡 (层2/3) → 非 200 且**真没写**。
    #[tokio::test]
    async fn exec_readonly_enforced() {
        let tmp = write_l1("http_exec.db", &[("wxid_solo", 3)]);
        let app = build_router(state(&tmp));
        let exec = |sql: &str| {
            let body = serde_json::json!({ "sql": sql }).to_string();
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/exec")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        // 正常 SELECT → 200 + 数据 (person 1 行)。
        let resp = exec("SELECT count(*) AS n FROM person").await;
        assert_eq!(resp.status(), StatusCode::OK, "SELECT → 200");
        assert_eq!(body_json(resp).await["data"][0]["n"], 1, "person 1 行");
        // 层1 (is_readonly_sql): 写/DDL/pragma/attach 非 SELECT 前缀 → 400 (开库前拒)。
        for sql in [
            "DELETE FROM person",
            "INSERT INTO person(account_id) VALUES('x')",
            "UPDATE person SET account_id='x'",
            "DROP TABLE person",
            "CREATE TABLE t(x)",
            "PRAGMA table_info(person)",
            "ATTACH DATABASE 'x.db' AS y",
        ] {
            assert_eq!(exec(sql).await.status(), StatusCode::BAD_REQUEST, "层1 拒: {sql}");
        }
        // 层1: 多语句 (夹带写) → 400。
        assert_eq!(
            exec("SELECT 1; DROP TABLE person").await.status(),
            StatusCode::BAD_REQUEST,
            "多语句拒"
        );
        // ⭐层2/3: WITH-前缀 DELETE 骗过 is_readonly_sql (WITH 前缀), 但 readonly 连接 + authorizer 挡 → 非 200。
        let resp = exec("WITH x AS (SELECT 1) DELETE FROM person").await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "WITH-前缀 DELETE 被 readonly/authorizer 挡 (非 200)"
        );
        // 坐实真没写: person 仍 1 行 (若 DELETE 生效会变 0)。
        let resp2 = exec("SELECT count(*) AS n FROM person").await;
        assert_eq!(
            body_json(resp2).await["data"][0]["n"],
            1,
            "WITH-DELETE 未生效, person 仍 1 行"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐C 审查修 exec 硬化: MEM 界(大BLOB→400) + 递归CTE放行 + 空白容错 + 执行期错→400(非500)。
    /// (CPU 界 progress_handler 15s 走真跑坐实, 单测不宜等 15s。)
    #[tokio::test]
    async fn exec_dos_and_correctness_hardening() {
        let tmp = write_l1("http_exec_hard.db", &[("wxid_solo", 3)]);
        let app = build_router(state(&tmp));
        let exec = |sql: &str| {
            let body = serde_json::json!({ "sql": sql }).to_string();
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/exec")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        // EXEC-DOS-MEM: 单值 >8MB → 400 (SQLITE_LIMIT_LENGTH 构造期封 + get_ref 字节界兜底)。
        assert_eq!(
            exec("SELECT randomblob(9000000)").await.status(),
            StatusCode::BAD_REQUEST,
            "9MB blob → 400"
        );
        // ⭐round2: length(randomblob(1e9)) 结果只是小整数 (绕过 Rust 侧 get_ref 字节界), 但 SQLITE_LIMIT_LENGTH
        // 令 randomblob 在**构造期**超 8MB 即错 → 400 (原 round1 修此例返 200 = SQLite 内部已分配 1GB 的漏)。
        assert_eq!(
            exec("SELECT length(randomblob(1000000000))").await.status(),
            StatusCode::BAD_REQUEST,
            "round2: length(randomblob(1e9)) 源头界 → 400 (曾绕过 OOM)"
        );
        // ⭐round3 Finding A: 列名不受 set_limit/值字节界约束 —— 大别名 × 多行 (递归 CTE 自造行) 经 exec_query 逐行
        // clone 列名 OOM。现列名字节计入 128MB 预算 → 400 (200KB 别名 × ~671 行即破)。
        let big_alias = "a".repeat(200_000);
        let sql_a =
            format!("WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r WHERE i<1000) SELECT i AS \"{big_alias}\" FROM r");
        assert_eq!(
            exec(&sql_a).await.status(),
            StatusCode::BAD_REQUEST,
            "round3 A: 大列名×行 → 400 (colname 预算)"
        );
        // EXEC-RECURSIVE-DENY 修: 合法递归 CTE 现放行 → 200 (progress 15s 界兜其 CPU)。
        let resp =
            exec("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<5) SELECT count(*) AS n FROM c")
                .await;
        assert_eq!(resp.status(), StatusCode::OK, "WITH RECURSIVE 只读 → 200");
        assert_eq!(body_json(resp).await["data"][0]["n"], 5);
        // EXEC-REJECT-WS 修: 关键字后换行不再误判为写 → 200。
        assert_eq!(
            exec("SELECT\n1 AS n").await.status(),
            StatusCode::OK,
            "SELECT+换行 → 200"
        );
        // EXEC-ERRCODE-500 修: 执行期被拒的用户 SQL (load_extension 禁用) → 400 (非 500 Internal)。
        assert_eq!(
            exec("SELECT load_extension('x')").await.status(),
            StatusCode::BAD_REQUEST,
            "执行期拒 → 400 (非 500)"
        );
        // ⭐R7-P1 (单行**宽度**内存放大): 单行 N 列 randomblob, 每格未超 8MB 单值界, 但 SQLite step() 一次性物化整行
        // → ~N×8MB 峰值 (早于逐格 Rust 界)。按列数收紧单值界 (min(8MB, 64MB/ncol)) → 宽行超预算即构造期 SQLITE_TOOBIG → 400。
        let wide_big = (0..100).map(|_| "randomblob(2000000)").collect::<Vec<_>>().join(",");
        assert_eq!(
            exec(&format!("SELECT {wide_big}")).await.status(),
            StatusCode::BAD_REQUEST,
            "R7-P1: 100列×2MB 单行 (ncol 界≈640KB) → 400 (源头封宽行, 曾 ~16GB OOM)"
        );
        // 反向: 宽但**小**值 (100 列小整数) 仍放行 → 200 (界只按宽度收单值上限, 不误杀合法宽查询/SELECT *)。
        let wide_small = (0..100).map(|i| format!("{i} AS c{i}")).collect::<Vec<_>>().join(",");
        assert_eq!(
            exec(&format!("SELECT {wide_small}")).await.status(),
            StatusCode::OK,
            "R7-P1 反向: 100列小值 → 200 (不误杀合法宽查询)"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐C 审查修 EXEC-CORS-1: CORS 仅放行 loopback 源 (防任意网站 drive-by 打 127.0.0.1)。
    #[tokio::test]
    async fn cors_only_loopback_origin() {
        let app = build_router(AppState::default());
        let acao = |origin: &'static str| {
            let app = app.clone();
            async move {
                let resp = app
                    .oneshot(
                        Request::builder()
                            .uri("/health")
                            .header("origin", origin)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                resp.headers().get("access-control-allow-origin").is_some()
            }
        };
        assert!(acao("http://localhost:3000").await, "loopback localhost:3000 放行");
        assert!(acao("http://127.0.0.1:9000").await, "loopback 127.0.0.1 放行");
        assert!(!acao("https://evil.com").await, "非 loopback evil.com 拒 (防 drive-by)");
        assert!(
            !acao("http://localhost.evil.com").await,
            "localhost.evil.com 前缀绕过被拒"
        );
    }

    // ── /media (§8 媒体即时取用: Range / 键校验 / Host 闸) ──

    /// Range 解析 (纯函数): 全量 / 单区间 / 后缀 / 末端夹取 / 不可满足 / 非法退全量。
    #[test]
    fn byte_range_parsing() {
        use RangeResult::{Full, Partial, Unsatisfiable};
        assert!(matches!(
            parse_single_byte_range("bytes=0-4", 10),
            Partial { start: 0, end: 4 }
        ));
        assert!(
            matches!(parse_single_byte_range("bytes=5-", 10), Partial { start: 5, end: 9 }),
            "开区间到尾"
        );
        assert!(
            matches!(parse_single_byte_range("bytes=-3", 10), Partial { start: 7, end: 9 }),
            "后缀 3 字节"
        );
        assert!(
            matches!(parse_single_byte_range("bytes=8-100", 10), Partial { start: 8, end: 9 }),
            "末端超界夹到 total-1"
        );
        assert!(
            matches!(parse_single_byte_range("bytes=10-20", 10), Unsatisfiable),
            "start ≥ total → 416"
        );
        assert!(
            matches!(parse_single_byte_range("bytes=-0", 10), Unsatisfiable),
            "suffix=0 → 416"
        );
        assert!(
            matches!(parse_single_byte_range("bytes=0-4", 0), Unsatisfiable),
            "空 body → 416"
        );
        assert!(
            matches!(parse_single_byte_range("items=0-4", 10), Full),
            "非 bytes 单位 → 全量"
        );
        assert!(
            matches!(parse_single_byte_range("bytes=0-4,6-8", 10), Full),
            "多区间不支持 → 全量"
        );
        assert!(
            matches!(parse_single_byte_range("bytes=abc", 10), Full),
            "无 '-' → 全量"
        );
    }

    /// `media_bytes_response`: 206 partial (切片 + Content-Range) / 416 (`bytes */total`) / 200 全量 (Accept-Ranges)。
    #[tokio::test]
    async fn media_bytes_response_range() {
        use axum::http::header;
        let body = b"0123456789".to_vec();
        // 206: bytes=2-5 → "2345"
        let rv = HeaderValue::from_static("bytes=2-5");
        let resp = media_bytes_response(body.clone(), "audio/wav", Some(&rv));
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.headers()[header::CONTENT_RANGE].to_str().unwrap(), "bytes 2-5/10");
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert_eq!(&bytes[..], b"2345", "切片正确");
        // 416: 越界
        let rv = HeaderValue::from_static("bytes=100-200");
        let resp = media_bytes_response(body.clone(), "audio/wav", Some(&rv));
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(resp.headers()[header::CONTENT_RANGE].to_str().unwrap(), "bytes */10");
        // 200 全量 (无 Range)
        let resp = media_bytes_response(body, "audio/wav", None);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::ACCEPT_RANGES].to_str().unwrap(), "bytes");
        assert_eq!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap(), "audio/wav");
    }

    /// /media 键校验 + 分发: 坏键/非法md5 → 400; 合法 voice/vid 但无 account → 400 (走到各分支非 501); img → 501。
    #[tokio::test]
    async fn media_key_validation_and_dispatch() {
        let app = build_router(AppState::default());
        assert_eq!(
            get(&app, "/api/v1/media/bogus").await.status(),
            StatusCode::BAD_REQUEST,
            "坏键 → 400"
        );
        // vid: 须 32-hex md5; 非法 → 400。
        assert_eq!(
            get(&app, "/api/v1/media/vid:abcd:1").await.status(),
            StatusCode::BAD_REQUEST,
            "vid 非 32hex md5 → 400"
        );
        // 合法 32-hex md5 但无 account/默认 → require_wxid 400 (证明分发到视频分支, 非 501)。
        assert_eq!(
            get(&app, "/api/v1/media/vid:0123456789abcdef0123456789abcdef")
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "vid 合法 md5 但无 account → 400 (require_wxid, 非 501)"
        );
        // img: 非法 talker (非 32hex) → 400; 合法 img 但无 account → 400 (分发到图片分支非 501)。
        assert_eq!(
            get(&app, "/api/v1/media/img:abcd:1").await.status(),
            StatusCode::BAD_REQUEST,
            "img talker 非 32hex → 400"
        );
        assert_eq!(
            get(&app, "/api/v1/media/img:0123456789abcdef0123456789abcdef:7")
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "img 合法键但无 account → 400 (require_wxid, 非 501)"
        );
        assert_eq!(
            get(&app, "/api/v1/media/voice:123").await.status(),
            StatusCode::BAD_REQUEST,
            "voice 合法键但无 account/默认 → 400"
        );
    }

    /// **`?source=` 从 HTTP 参数到内核那根线**(独立复审 656477c 的 P2)。
    ///
    /// 唯一那条 msgraw 的测试写在 msgvestige 里、直接调内核函数, **不经过 axum handler**。
    /// 审查方把 `p.source.as_deref()` 换成 `None`, 全工作区一条不红 —— 内核的过滤有守卫,
    /// 这根线没有。真回归的症状: 客户端给了分片想钉死一条, 静默拿回全部分片的行, `total_count`
    /// 跟着一起说谎。
    #[tokio::test]
    async fn msgraw_source_param_is_wired_through_the_handler() {
        let tmp = std::env::temp_dir().join("http_msgraw_source_wired.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            native_core::storage::init_l1_schema(&c).unwrap();
            for (src, nid) in [("message_0.db", "Msg_a:1"), ("message_5.db", "Msg_a:1")] {
                c.execute(
                    "INSERT INTO raw_payload_archive                      (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)                      VALUES ('a',?1,?2,'message','create',0,111,'{}')",
                    rusqlite::params![src, nid],
                )
                .unwrap();
            }
        }
        let app = build_router(AppState {
            l1_db: Some(tmp.to_str().unwrap().to_string()),
            ..Default::default()
        });
        let body = |uri: &str| {
            let app = app.clone();
            let uri = uri.to_string();
            async move {
                let resp = app
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };

        let all = body("/api/v1/msgraw").await;
        assert_eq!(all["data"].as_array().unwrap().len(), 2, "不给分片该拿到两条");

        let one = body("/api/v1/msgraw?source=message_5.db").await;
        assert_eq!(
            one["data"].as_array().unwrap().len(),
            1,
            "给了分片就只该剩一条 —— 拿到两条说明 ?source= 根本没传下去"
        );
        assert_eq!(one["data"][0]["source"], "message_5.db");
        assert_eq!(one["meta"]["total_count"], 1, "总数也得跟着过滤, 不然它在说谎");
        let _ = std::fs::remove_file(&tmp);
    }

    /// /media Host 闸 (挡 DNS-rebinding drive-by): Host 非 loopback → 403; loopback → 放行 (往下走 400 非 403)。
    #[tokio::test]
    async fn media_host_gate_blocks_non_loopback() {
        let app = build_router(AppState::default());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/media/voice:1")
                    .header("host", "evil.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "Host 非 loopback → 403");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/media/voice:1")
                    .header("host", "127.0.0.1:8420")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "loopback Host 放行 → require_wxid 400 (非 403)"
        );
    }

    // ── B pack (组合式, 对标 MCP) ──

    /// /contacts/{wxid}/pack: 联系人 (冷 resolve_names 命中) + recent_messages (无 wechat_data_dir → 尽力而为空)。
    /// 组合形 {contact, recent_messages} (非信封)。
    #[tokio::test]
    async fn contact_pack_composite_shape() {
        let tmp = write_l1("http_cpack.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/contacts/wxid_solo/pack").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert!(j["contact"].is_array(), "contact 段");
        assert!(j["recent_messages"].is_array(), "recent_messages 段 (无 dir → 空)");
        assert_eq!(j["contact"][0]["wxid"], "wxid_solo", "resolve_names 命中该联系人");
        let _ = std::fs::remove_file(&tmp);
    }

    /// contact_pack 多账号未指定 → 409 (联系人是主载荷, 走 fail-closed 非尽力而为)。
    #[tokio::test]
    async fn contact_pack_multi_account_409() {
        let tmp = write_l1("http_cpack_multi.db", &[("wxid_alice", 2), ("wxid_bob", 3)]);
        let app = build_router(state(&tmp));
        let resp = get(&app, "/api/v1/contacts/wxid_alice/pack").await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(resp).await["error"]["code"], "ACCOUNT_AMBIGUOUS");
        let _ = std::fs::remove_file(&tmp);
    }

    /// /sessions/{id}/pack: 需账号 (热) → 缺 400; 带 account → 200 组合形 {conv,is_group,recent_messages};
    /// @chatroom → is_group=true。
    #[tokio::test]
    async fn session_pack_requires_account_and_flags_group() {
        let tmp = write_l1("http_spack.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        // 无 account/默认 → 400。
        assert_eq!(
            get(&app, "/api/v1/sessions/wxid_x/pack").await.status(),
            StatusCode::BAD_REQUEST
        );
        // 带 account → 200 (recent 尽力而为空, 无 dir); is_group=false。
        let resp = get(&app, "/api/v1/sessions/wxid_x/pack?account=wxid_solo").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["conv"], "wxid_x");
        assert_eq!(j["is_group"], false, "非 @chatroom → is_group=false");
        assert!(j["recent_messages"].is_array());
        // @chatroom → is_group=true。
        let resp2 = get(&app, "/api/v1/sessions/room123@chatroom/pack?account=wxid_solo").await;
        let j2 = body_json(resp2).await;
        assert_eq!(j2["is_group"], true, "@chatroom → is_group=true");
        let _ = std::fs::remove_file(&tmp);
    }

    // ── B④ 审查修回归 ──

    /// ⭐簇CD (审查修 D3/D8/D4): sys_type/conv_type 校验提到分支前 —— 热查 ?conv=X&sys_type=Y 与投影 ?kind=call&
    /// conv_type=bogus 都 400 (曾落 selectors==0 早返之后被静默吞, 与冷路同参 400 自相矛盾)。
    #[tokio::test]
    async fn messages_param_guards_fire_before_branch() {
        let tmp = write_l1("http_msg_guards.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        // 热查分支 (conv, 无投影) + sys_type → 400 (曾静默吞; hot_messages 无 sys_type 参)。
        assert_eq!(
            get(&app, "/api/v1/messages?conv=wxid_x&sys_type=revoke&account=wxid_solo")
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "conv+sys_type → 400 (sys_type 仅 kind=system, 热路也拦)"
        );
        // 投影 + 非法 conv_type → 400 (曾静默吞: has_official=false→selectors=1→跳过校验)。
        assert_eq!(
            get(&app, "/api/v1/messages?kind=call&conv_type=bogus").await.status(),
            StatusCode::BAD_REQUEST,
            "kind=call+conv_type=bogus → 400 (非法 conv_type 不被选择器掩盖)"
        );
        // round3: mentions 与 mentions_me 互斥 → 400 (曾静默吞 mentions_me)。
        assert_eq!(
            get(&app, "/api/v1/messages?mentions=alice&mentions_me=true")
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "mentions + mentions_me 互斥 → 400 (不静默优先吞 mentions_me)"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐簇A (审查修 D3): 投影/extract/registry 接受 offset 参 (深翻可达; 曾无 offset 字段 → deny_unknown 400)。
    #[tokio::test]
    async fn messages_projection_accepts_offset() {
        let tmp = write_l1("http_msg_offset.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        assert_eq!(
            get(&app, "/api/v1/messages?kind=call&offset=5").await.status(),
            StatusCode::OK,
            "投影认 offset"
        );
        assert_eq!(
            get(&app, "/api/v1/messages?kind=system&offset=1").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            get(&app, "/api/v1/messages?kind=image&offset=2").await.status(),
            StatusCode::OK,
            "registry 认 offset"
        );
        assert_eq!(
            get(&app, "/api/v1/extract?kind=url&offset=3").await.status(),
            StatusCode::OK,
            "extract 认 offset"
        );
        assert_eq!(
            get(&app, "/api/v1/moments/interactions?offset=2").await.status(),
            StatusCode::OK
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐round2 回归修: 热查会话拒 offset>0 (round1 加 MessagesQ.offset 供**冷投影**, 但 hot_messages 无分页 →
    /// ?conv=X&offset=N 曾静默吞成恒最近页 = 与簇CD 同类)。现显式 400。
    #[tokio::test]
    async fn messages_hot_rejects_offset() {
        let tmp = write_l1("http_msg_hotoffset.db", &[("wxid_solo", 2)]);
        let app = build_router(state(&tmp));
        // 热查分支 (无投影 + conv) + offset>0 → 400 (offset guard 在 hot_messages 之前, 单测无 dir 也能咬)。
        let resp = get(&app, "/api/v1/messages?conv=wxid_x&offset=5&account=wxid_solo").await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "热查 offset>0 → 400 (非静默吞恒最近页)"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// ⭐簇B (审查修 D1/D2): meta.account 在 cold 投影路径也回显, 与 cold_cmd (image) 一致 —— 同 /messages 端点
    /// meta schema 不再随 kind 漂移 (曾 kind=image 有 account、kind=call 无)。
    #[tokio::test]
    async fn messages_projection_meta_account_consistent() {
        let tmp = write_l1("http_msg_metaacct.db", &[("wxid_alice", 2), ("wxid_bob", 3)]);
        let app = build_router(state(&tmp));
        let jc = body_json(get(&app, "/api/v1/messages?kind=call&account=wxid_alice").await).await;
        assert!(
            jc["meta"]["account"].is_string(),
            "簇B: cold 投影 meta.account 回显 (曾缺)"
        );
        let ji = body_json(get(&app, "/api/v1/messages?kind=image&account=wxid_alice").await).await;
        assert!(ji["meta"]["account"].is_string(), "cold_cmd 投影 meta.account 回显");
        assert_eq!(
            jc["meta"]["account"], ji["meta"]["account"],
            "两路 account sha8 一致 (不漂移)"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
