//! key_provider — 微信 master key 取源 (跟 ADR-405 §3.1 + ADR-413 一致).
//!
//! 本 mod = PR2-1-a 骨架: trait + 类型 + error + capabilities.
//! 各 impl (cache / ciphertalk / cli) 等 PR2-1-b/c 拷.
//!
//! 红线 (K-R*, 跟 PoC-1 v3-key-source-spec.md §四 一致):
//!   - K-R1 一次性 hook, 用户手动触发 (ADR-028 R2)
//!   - K-R2 缓存优先 (ChainedKeyProvider 默认 [cache, ciphertalk, cli])
//!   - K-R3 默认永久 cache, 可选 stale_after_days 兜底
//!   - K-R4 明文 wxid / master_key 绝不入 log — 统一走 sha8
//!   - K-R5 DPAPI CURRENT_USER 范围
//!   - K-R6 Drop 必清 hook (防微信进程残留 shellcode)
//!   - K-R7 x64 only
//!   - K-R8 M2 自研路线已规划 (KI-028-A, alpha 阶段复用 vendor wx_key.dll)
//!   - K-R9 不依赖 WCDA / DbkeyHookCMD
//!   - K-R10 vendor dll 协议跟 ADR-419 一致 (wx_key.dll = CipherTalk MIT)
//!
//! 接口契约: ADR-405 §3.1 (KeyProvider trait) + ADR-410 MATRIX (KeyError ↔ #3/#9/#11/#13/#17).

pub mod cache;
pub mod capabilities;
pub mod chain;
/// 图片 image key (aes+xor) 按账号 DPAPI 缓存 —— 独立于 master `keys.enc` (serve `/media/img` V2 完整图解密用)。
pub mod image_cache;
// PR2-8-b: DPAPI 原语从 cache.rs 抽到共享模块 (cache 加密 master key 缓存 + config 解密 auth_password 复用).
pub(crate) mod dpapi;
// PR2-1-c r2 baseline:
//   - unused_variables: r2 P1 #3 修了 install detail, 但其它 PoC-1 KeySourceError 解构字段 (secs/last_status)
//     仍有残留. r3+ 逐处清理后收窄.
//   - unsafe_code: 12 unsafe FFI (libloading wrapper / Win32 process enum / DPAPI), 局部 escape workspace
//     `unsafe_code = "warn"`. r3 收窄到函数级 `#[allow(unsafe_code)]` (P2 #3).
//   - unused_variables: PoC-1 KeySourceError 解构字段 (secs/last_status) 残留, r3+ 逐处清理后收窄.
//   - PR2-1-e 已落: println! 抢 stdout → UserNotifier trait (默认 StdoutNotifier, adapter 可注入).
#[cfg(target_os = "windows")]
#[allow(unused_variables, unsafe_code)]
pub mod ciphertalk;
pub mod cli;
pub mod error;
pub mod provider;

pub use cache::{CacheKeyProvider, KeyCacheV1, KeyEntry, UpsertOutcome};
pub use capabilities::KeyProviderCapabilities;
pub use chain::ChainedKeyProvider;
// PR2-1-e: UserNotifier 注入点 (扫码指引 / 倒计时 / 超时诊断). ciphertalk windows-only → cfg 门.
#[cfg(target_os = "windows")]
pub use ciphertalk::{CipherTalkProvider, StdoutNotifier, UserNotifier};
pub use cli::CliKeyProvider;
pub use error::KeyError;
pub use image_cache::ImageKeyCache;
pub use provider::{sha8, KeyProvider, MasterKey, Wxid};
