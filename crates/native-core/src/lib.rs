//! native-core — alpha 核心运行时 lib
//!
//! 模块组织 (跟 ADR-415 §3.2 + ADR-416 §3.2.1 一致):
//! - key_provider / cipher / decoder / storage / state / sink / emit / config / media
//!
//! PR2-1: key_provider 全栈 (trait + cache + ciphertalk + cli + chain).
//! PR2-2 / ADR-423: cipher — Cipher trait (open_account) + DbSession + CipherRow + CipherError;
//!   impl NativeCipher (纯 Rust 解密; open_account+exec_query 取数模型, 非 decrypt 成文件).
//! 其余 7 module 等 PR2-N.
//!
//! ## 架构红线 (K-R7 x64 only)
//! native-core 跟 vendor wx_key.dll / wcdb_api.dll FFI 直接耦合, 两 dll 仅 x86_64 提供.
//! 跨架构编译会在 PR2-1-b/c 真实 FFI 调用时静默失败 — 这里编译期直接拒绝.

// 不再 `#![allow(dead_code)]` —— 那个总开关正是 R22 那 ~700 行残留能悄悄堆起来还没人发现的原因。
// 确实需要留着不读的东西(如 RAII 守卫字段)请**定点** `#[allow(dead_code)]` 并写明为什么。

// K-R7 r2 P0 修: x64 only 钉死. ARM64 / x86 32-bit 拒绝编译.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("native-core requires x86_64 architecture (K-R7) — vendor wx_key.dll / wcdb_api.dll 仅 x64");

pub mod cipher;
pub mod event;
pub mod key_provider;
// PR2-12-a: cipher 解密的明文 row/blob → 结构化 Event 字段 (zstd 解压 / proto / xml / 图片 .dat).
pub mod config;
pub mod decoder;
pub mod emit;
pub mod state;
pub mod storage;
// 共享错误码枚举 (内核持有, 三皮同 code 值; 内核 §13 闭集 + doc② §二.5 退出码).
pub mod error_code;
// PR2-9-a: DecodedEvent → L2 业务表行 (V3*) 投影 (纯映射, decode 的下游, 不碰 db).
pub mod projection;
// PR2-10-a: DecodedEvent → L1 落库 (archive 写 + L2 投影 insert, 一事务原子). 整合 emit+projection+storage.
pub mod sink;
// PR2-11-b: 从 raw_payload_archive 重放历史事件到 in-proc channel (recovery/续传). read_archive_since + emit.
pub mod replay;
// PR2-13-a: 媒体导出 (CLI 侧, 非 raw_payload; ADR-421). 视频判定 (文件名 _raw 主判 + mdat NAL H.264/H.265).
pub mod media;

pub mod mediastore;
// R17 统一底座 · L3: 通用 per-slice 写租约 (方案 B 多写者协调; 镜像 mediastore 块3 fencing, 去状态机留通用核心).
pub mod write_lease;
// R19 选择性采集: capture_targets 会话白名单 (圈定某些群/好友只增量存这些; 没圈零成本). run_message_body drain 前过滤.
pub mod capture;
// ADR-405 §3.1 trait 3/7 / ADR-423 §3.4: DbSource 取数适配层 (cipher 会话 → decoder 输入行) 接口骨架.
pub mod source;
// adapter 主 loop: DbSource.drain → decoder → sink → 游标推进 (ADR-405 §3.1 / drain 设计双审 v2).
pub mod pipeline;
// R18 件2: thin 持久档 daemon 的 source→thin 增量核心 (L1-free; 平行 pipeline 但只灌瘦 FTS 不建 L1).
pub mod thin;
// L1-free 源库快查 (保温 VFS 连接 + 定位表; 存储紧张/小号免建 L1 直查加密源库).
pub mod live_query;
// export: 从 L1 db 直读业务表导出 JSONL (msgvestige export 用; alpha 直读明文 L1, 不走 query-planner).
pub mod export;
// R21 计划引擎 MVP (预估+提示): 慢查询执行前按 ADR-407 cost model 估耗时 + 超阈值弹提示 / --confirm.
// 甲档: cost 预估 stat 源库粗估、不填地图表 (留 R22). 纯逻辑 (无 fs); stat + cli 阈值门在 cli 侧.
pub mod labels;
pub mod query_planner;
// ADR-428 M3-d 收尾: 逐表内容对账 (native 解密的库 vs 竞品/WDA 解密的明文库, row count + 全表 SHA-256 digest).
pub mod reconcile;

pub use cipher::{Cipher, CipherError, CipherRow, DbSession};
pub use config::{ensure_config_paths, expand_env_vars, load_config, validate_auth_password, Config, ConfigError};
pub use decoder::{
    assemble_chatroom, assemble_contact, assemble_message, assemble_session, chatroom_anchor, contact_anchor,
    content_encoding, cursor_anchor, decode_local_type, decode_message_content, error_anchor, member_anchor,
    msg_anchor, session_anchor, split_chatroom_sender, ChatroomContext, ChatroomRow, ContactContext, ContactRow,
    DecoderError, LocalType, MessageContext, MessageRow, SessionContext, SessionRow,
};
pub use emit::in_proc::{new_in_proc, Backpressure, EmitError, InProcEmitter, InProcReceiver};
pub use emit::{emit, RawPayloadRecord};
pub use error_code::ErrorCode;
pub use event::assembly::compute_event_seq;
pub use event::canonical::{canonical_raw_values, CanonicalRawValues};
pub use event::chatroom::{ChatroomCreate, ChatroomMemberAdd, ChatroomMemberRemove};
pub use event::contact::ContactUpdate;
pub use event::decoded::DecodedEvent;
pub use event::fingerprint::{content_digest, EventFingerprint};
pub use event::message::MessageCreate;
pub use event::privacy::{render_field, render_opt_field, sha256_hex, FieldCategory, PrivacyMode};
pub use event::provenance::Provenance;
pub use event::session::SessionUpdate;
pub use event::system::{SystemCursorUpdate, SystemError};
pub use event::{is_alpha_valid_combo, EventAction, EventType};
pub use key_provider::{sha8, ImageKeyCache, KeyError, KeyProvider, KeyProviderCapabilities, MasterKey, Wxid};
pub use live_query::{
    read_hot_avatars, read_hot_biz_contacts, read_hot_chatrooms, read_hot_contacts, read_hot_emoticons,
    read_hot_favorite_media, read_hot_favorite_tags, read_hot_favorites, read_hot_finder_visits,
    read_hot_friend_requests, read_hot_members, read_hot_moment_interactions, read_hot_moments, read_hot_money_base,
    read_hot_sessions, read_hot_sns_notify, MoneyBase, MoneyGroupRow, MoneyRedRow, MoneyTransferRow, QueriedAvatar,
    QueriedBizContact, QueriedChatroom, QueriedContact, QueriedEmoticon, QueriedFavorite, QueriedFavoriteMedia,
    QueriedFavoriteTag, QueriedFinderVisit, QueriedFriendRequest, QueriedMember, QueriedMoment,
    QueriedMomentInteraction, QueriedMsg, QueriedSession, QueriedSnsNotify, ScanStats, SourceQuery, SKIPPED_IDS_CAP,
};
pub use pipeline::{
    default_ingest_jobs, run_avatar_pipeline, run_bizchat_pipeline, run_chatroom_pipeline, run_contact_pipeline,
    run_emoticon_pipeline, run_favorite_pipeline, run_favorite_tag_pipeline, run_finder_visit_pipeline,
    run_friend_verify_pipeline, run_group_pay_pipeline, run_message_pipeline, run_message_pipeline_incremental,
    run_message_pipeline_jobs, run_moment_feed_pipeline, run_red_envelope_pipeline, run_session_pipeline,
    run_sns_notify_pipeline, run_sns_pipeline, run_transfer_pipeline, PipelineError, PipelineStats,
};
pub use projection::{
    project_chatroom, project_chatroom_member_add, project_message, project_person, project_person_alias,
    project_watermark, ProjectionError,
};
pub use replay::{replay_archive, ReplayError};
pub use sink::{write_decoded_event, SinkError};
pub use source::{
    AccountDbSource, AvatarBatch, BizChatUserBatch, ChatroomBatch, ChatroomRawRow, ContactBatch, DbSnapshot, DbSource,
    DbSourceError, DrainCursor, EmoticonBatch, FMessageBatch, FavoriteBatch, FavoriteTagBatch, FinderBatch,
    GroupPayBatch, MessageBatch, MessageSubsource, MomentBatch, MomentFeedBatch, RedEnvelopeBatch, SessionBatch,
    SnsNotifyBatch, TransferBatch,
};
pub use storage::{
    V3BizchatUser, V3CapabilityBacklog, V3Chatroom, V3ChatroomMember, V3CustomEmoticon, V3Favorite, V3FavoriteMedia,
    V3FavoriteTag, V3FinderVisit, V3FriendVerify, V3GroupPay, V3Message, V3MessageApp, V3MessageCall, V3MessageCard,
    V3MessageForwardItem, V3MessageHongbaoClaim, V3Moment, V3MomentFeed, V3MomentInteraction, V3MomentMedia, V3Person,
    V3PersonAlias, V3RedEnvelope, V3Session, V3SnsNotify, V3SourceChatIndex, V3SourceChatToDb, V3SourceDbCatalog,
    V3SourceDbTimerange, V3SourceQueryPlan, V3Transfer,
};

/// Crate version marker — PR1 骨架, 业务逻辑分 PR2-N 逐步迁入.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
