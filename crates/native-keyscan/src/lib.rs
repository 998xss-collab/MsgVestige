//! native-keyscan — ADR-428 M3-a: 纯 Rust 扫微信进程内存提 SQLCipher4 key.
//!
//! 干一件事: 从运行中的微信进程私有内存里把解密 key 捞出来, 经首页 HMAC 校验后产出.
//! 不碰 wcdb_api.dll / electron / Python — 替代 vendor `wx_key.dll` 的自研路线 (K-R8 落地).
//!
//! ## 两套提取法 (ADR-428 §2.1, PoC `key-scan-poc` 实测)
//! - **enc_key 快路** (默认): WCDB 在内存为每个已加载库缓存 `x'<64hex enc_key><32hex salt>'`,
//!   enc_key 是**已派生完 (256000 轮) 的成品 AES key**. 正则扫 → enc_key → 2 轮 HMAC 校验.
//!   零 dll、零 256000 轮, ~0.7s. 局限: 只覆盖微信运行时加载过的库 (不含 migrate 等废库).
//! - **passphrase 完整路** (`--key-mode full`): raw_key (扫指针结构) XOR internal_db_key
//!   (goblin 从 Weixin.dll 代码段静态提常量) = master passphrase, + 各库 salt 跑
//!   PBKDF2-256000 现场派生. 能解任意库 (含未加载), 代价: 读 dll + 慢.
//!
//! ## 两种产出语义不可混用 (本 crate 设计核心)
//! [`KeyMaterial::EncKey`] 是成品 key (不可再派生, 只喂 NativeCipher 直用);
//! [`KeyMaterial::Passphrase`] 跟 sidecar 的 master_key 同语义 (需 PBKDF2-256000 派生).
//! 上层 (M3-c NativeCipher) 据 [`KeyKind`] 决定走派生还是直用.
//!
//! ## 红线
//! - **K-R4**: enc_key / passphrase / raw_key / internal_db_key 绝不入 log/stdout/panic;
//!   出口统一 [`sha8`]; [`KeyMaterial`] 手写 Debug 只露 kind + sha8, 且 `ZeroizeOnDrop`.
//! - **正则命中只是候选**: 必须经 [`verify_enc_key`] / [`verify_passphrase`] 首页 HMAC
//!   校验通过才认作 key (ADR-428 §2.1 codex P1 — 不把 regex 命中当 key).
//! - **K-R7**: 扫内存仅 Windows x64; 其余平台纯算法层 (校验/类型) 仍可编, 扫描入口缺省.
//!
//! ## 验证锚点
//! 校验需一个该账号下任一加密库的首页 (4096B) 作锚 — 通常 `account_entry_db`
//! (session/session.db 之类). enc_key 路逐库锚验, passphrase 路单锚即可 (master 通用).

mod error;
mod key_material;
mod sqlcipher;

// Windows 内存扫描层 (K-R7 x64). win.rs 集中所有 Win32 unsafe FFI; 其余模块走其安全封装.
#[cfg(all(windows, target_arch = "x86_64"))]
mod dll;
#[cfg(all(windows, target_arch = "x86_64"))]
mod enckey;
#[cfg(all(windows, target_arch = "x86_64"))]
mod image_key;
#[cfg(all(windows, target_arch = "x86_64"))]
mod passphrase;
#[cfg(all(windows, target_arch = "x86_64"))]
mod scan;
#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)] // 进程内存访问 FFI (OpenProcess/ReadProcessMemory/...); 限本 mod, 对外安全.
mod win;

pub use error::KeyScanError;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use image_key::scan_image_key;
pub use key_material::{sha8, KeyKind, KeyMaterial, KeyMode, KeyScanOutcome};
#[cfg(all(windows, target_arch = "x86_64"))]
pub use scan::{scan_key, ScanOptions};
pub use sqlcipher::{
    verify_enc_key, verify_passphrase, MAC_SALT_XOR, PAGE, RESERVE, SQLCIPHER_ROUNDS_V3, SQLCIPHER_ROUNDS_V4,
};
#[cfg(all(windows, target_arch = "x86_64"))]
pub use win::WeixinProcess;
