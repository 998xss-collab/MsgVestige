//! 共享查询内核 (查询内核抽取 §4/§6) —— 信封 / 游标 / keyset 分页 / 错误码。
//!
//! CLI / MCP / HTTP 三皮共用; 本 crate 只做"取数 + 结构化契约", **不含 stdout 呈现 / 退出码**
//! (那留各皮: `render_cli_error` + 退出码映射仍在 msgvestige)。
//!
//! §6① 首刀: 搬 `envelope` / `cursor` / `paginate` / `error` 四个最独立模块 (零查询逻辑改动)。
//! §6② (本步): 搬**引擎** —— `engine`(`run_query` 改返 `QueryResult` 不打印 + `render_table` +
//! `REGISTRY` + 15 `CMD_*` + `open_l1`/`needs_ingest_err`)+ `target`(`QueryTarget`)。手写 `query_*`
//! 是 §6③, 后续。呈现 (table 表头/游标提示/退出码) 仍留 msgvestige 皮。

pub mod cursor;
pub mod engine;
pub mod envelope;
pub mod error;
pub mod freshness;
// R21 计划引擎全扫成本门 —— 三皮共享决策核 (估算 + 阈值 → GateOutcome; 呈现留各皮)。
pub mod gate;
pub mod handwritten;
pub mod hot;
pub mod paginate;
// R22 懒式落库 (ADR-508 D24): 查询前把这一个会话的新消息补进 L1, 然后纯冷查。
pub mod refresh;
pub mod target;

// 常用项在 crate 根 re-export, 方便皮层 `use native_query::{...}` 一行引全。
// §6② 查询引擎: 通用 run_query (返 QueryResult) + table 渲染 + 登记表 + 15 CMD_* + 打库/缺表助手。
pub use engine::{
    account_candidates, account_shas, ensure_l1_marker, needs_ingest_err, open_l1, open_l1_resolved, open_l1_scoped,
    render_table, resolve_account, resolve_account_sha, resolve_capture_account_sha, run_query,
    run_query_with_deadline, AccountResolution, Col, Fmt, QueryCommand, CMD_AVATARS, CMD_BIZ_CONTACTS, CMD_CARDS,
    CMD_CHATROOMS, CMD_EMOTICONS, CMD_FAV_MEDIA, CMD_FAV_TAGS, CMD_GROUP_EVENTS, CMD_GROUP_PAY_MEMBERS, CMD_HONGBAO,
    CMD_INTERACTIONS, CMD_LOCATIONS, CMD_MEDIA, CMD_MOMENT_FEED, CMD_SNS_NOTIFY, REGISTRY,
};
pub use envelope::{emit_envelope, Envelope, Freshness, Meta, QueryResult, Source};
pub use error::{classify_error, cli_err, CliError};
pub use freshness::{cold_freshness, cold_freshness_full};
// R21 三皮共享成本门: 决策函数 + 报告 (皮据 GateReport 呈现)。
pub use gate::{full_scan_cost_gate, GateReport};
// §6③ 手写查询 (各返 QueryResult): 取数 + json 预组 + Meta 组装进核, 呈现留皮。
// 标签助手 (call_kind/friend_scene_label/app_type_label/…) 也 re-export —— json 里预组 label + 直测。
// 第四批 summary 命令 (stats/extract/pii-scan): 域出口 (`*_query` 返满配 Meta.summary) + 低层取数/扫描
// (`query_*`/`scan_pii_in_text`/`mask_pii`/…, 直测锁 SQL) + `--by`/`--kind` 枚举 (皮 flatten 复用)。
// 第五批 (结构最硬): money(三表合并时间线, `money_query` + 3 子查 `query_*` + `MoneyKind` 枚举皮 flatten 复用) /
// contacts(keyset 游标 `contacts_query` → cursor_page; InvalidCursor 携码原样上抛)。
// specials (4 特殊命令): exec(`is_readonly_sql` 守卫留皮 pre-check + `run_exec_query` 有序低层 + `exec_query`
// json 出口 + `sql_value_display`/`sql_value_json` 值渲染) / inspect(`InspectType`+`fetch_row` 有序列 +
// `inspect_query` + `json_value_display`; NOT_FOUND 携码) / resolve(`resolve_query` 双模式 + `query_forward_*`
// + `forward_type_label`) / search(`search_query`, 只 SEARCH 路; --build 建索引=写留皮)。
pub use handwritten::{
    account_query, accounts_query, app_type_label, biz_query, call_kind, calls_query, capture_targets_query,
    cold_messages_query, cold_sessions_query, contacts_query, dormant_query, events_query, exec_hardened,
    exec_hardened_vfs, exec_query, extract_kind_label, extract_matches, extract_query, extract_regex, favorites_query,
    fetch_row, files_query, finder_query, followups_query, forward_sources, forward_type_label, friend_requests_query,
    friend_scene_label, id_checksum_ok, inspect_query, is_cn_mobile, is_readonly_sql, json_value_display, links_query,
    mask_pii, members_query, mentions_query, moments_query, money_query, msgraw_query, new_query, pii_scan_query,
    query_extract, query_forward_items, query_forward_list, query_group_pays, query_pii_scan, query_red_envelopes,
    query_stats, query_transfers, resolve_names_query, resolve_query, run_exec_query, scan_pii_in_text, search_query,
    sql_value_display, sql_value_json, stats_dimension_label, stats_query, sys_type_label, thread_query, ExtractKind,
    InspectType, MoneyKind, PiiKind, StatsBy,
};
// 热查出口 (§6③ 收尾): sessions/messages 直查加密源库 (async, 仅取 key 需 async; SourceQuery 本体同步) +
// 账号定位 helper (MCP/HTTP 依赖本 crate 故上移; msgvestige auth/export/media 用到的从此回引)。
pub use hot::{
    cache_key, check_hot_window, db_shard_files, default_wechat_data_dir, hot_account, hot_avatars, hot_biz,
    hot_biz_contacts, hot_calls, hot_cards, hot_chatrooms, hot_contacts, hot_dormant, hot_emoticons, hot_events,
    hot_exec, hot_extract, hot_favorite_media, hot_favorite_tags, hot_favorites, hot_files, hot_finder_visits,
    hot_followups, hot_friend_requests, hot_group_events, hot_group_pay_members, hot_hongbao_claims, hot_inspect,
    hot_interactions, hot_links, hot_locations, hot_media, hot_members, hot_mentions, hot_messages,
    hot_messages_around, hot_moments, hot_money, hot_new, hot_pii_scan, hot_resolve, hot_resolve_names, hot_search,
    hot_sessions, hot_sns_notify, hot_stats, hot_thread, media_db_files, query_locator_path, resolve_db_storage_dir,
    resolve_message_dir, wxid_from_dir_name, NewHotMark,
};
pub use refresh::{chat_refreshed_at, ensure_chat_fresh, ChatFreshness};
pub use target::{EffectiveMode, QueryMode, QueryTarget};
