//! native-sqlcipher — ADR-428 M3-b: 纯 Rust SQLCipher4 全页解密 → 内存 image → 只读读出明文行.
//!
//! 把 M3-a 提到的 key 真正用起来: 全页 AES-256-CBC 解密 + 逐页 HMAC 校验, 拼成标准 sqlite
//! 明文 image, 经 `rusqlite` `deserialize` 只读挂载读出真实行 — **全程内存, 不落明文文件** (ADR-423 §7).
//!
//! ## 解密算法 (ADR-428 §2.2, 本地 chatlog/wechat-decrypt/WDA 实证对齐)
//! - 每页 4096B: 尾 80B reserve = IV(16) + HMAC-SHA512(64); 正文 [0..4016] (首页 [16..4016] 跳 salt).
//! - enc_key: EncKey 直用 / Passphrase + 库 salt 跑 PBKDF2-256000 现场派生.
//! - mac_key = PBKDF2-SHA512(enc_key, salt XOR 0x3a, 2); 逐页 HMAC 校验 (坏页/key 错即报).
//! - AES-256-CBC(enc_key, IV=页尾 reserve 前 16B) 解正文.
//! - 明文 image 每页: 首页 = `"SQLite format 3\0"`(16) + 解密正文 + reserve 区清零(80); 非首页 = 解密正文 + 清零.
//!
//! ## WAL 两条路 (checkpoint 快照 / 实时前沿)
//! - [`decrypt_db_to_image`] / [`open_decrypted`] — **只解主库, 不合并 WAL** = checkpoint 快照
//!   (不含活跃 WAL 的最新行). 静态导出/离线分析用这条; `deserialize` 走内存 image 天然避开
//!   "残留 -wal 让 sqlite 报 malformed".
//! - [`decrypt_db_to_image_with_wal`] / [`open_decrypted_with_wal`] — 主库快照 **+ 合并
//!   `<db>-wal` 里已提交的增量帧** (见 [`wal`] 模块) = **实时前沿**. 微信/WCDB 频繁 checkpoint,
//!   最新几笔常还压在加密 WAL 里未刷盘 (真库实测: media_1.db 主库 1 页空壳, 全部 18 页内容在 WAL);
//!   WAL 帧与主库同一套页加密, 直接复用页解密内核. 供实时监听 (`--watch`) 拿未 checkpoint 的最新消息.
//!
//! ## 红线
//! - **不落明文文件**: 解密 + 读全在内存 (`deserialize`), 不写明文 db 到盘.
//! - **K-R4**: 不打印 image / 明文行; enc_key/mac_key 派生后 `Zeroizing` 清零; 错误不含明文 / wxid 全路径.

mod decrypt;
mod error;
/// §9: PBKDF2 派生库级 key 进程内缓存 (同库重开跳过 ~3s)。
mod keycache;
#[allow(unsafe_code)] // sqlite3_malloc + deserialize FFI; 限本 mod, 对外安全.
mod reader;
#[allow(unsafe_code)] // 自定义 SQLite VFS C ABI 回调; 限本 mod, 只读、对外安全.
mod vfs;
mod wal;

use std::path::Path;

pub use decrypt::{decrypt_db_to_image, decrypt_db_to_image_with_wal, DecryptSession, DEFAULT_ROUNDS};
pub use error::SqlcipherError;
pub use keycache::clear_cache as clear_key_cache;
use native_keyscan::KeyMaterial;
pub use reader::{open_image, DecryptedDb};
pub use vfs::{open_conn_vfs, WalRefreshHandle};
pub use wal::{wal_sibling, WalApplyStats};

/// 便捷: 解密加密库 + 只读挂载, 一步到位读出明文行 (全程内存, 不落盘).
///
/// 产出 = 主库 checkpoint 快照 (不含活跃 WAL 最新行, 见 crate 文档); NOCOPY 挂载, 峰值内存 ≈ 1× 库大小
/// (见 [`open_image`]). 返回 [`DecryptedDb`] 持连接 + 底层内存, `.conn()` 取只读连接跑 query.
///
/// `key`: [`native_keyscan::KeyKind::EncKey`] 直用 (须是该库的 enc_key) /
/// [`native_keyscan::KeyKind::Passphrase`] + 库 salt 派生; `rounds` 一般传 [`DEFAULT_ROUNDS`].
///
/// # Errors
/// 见 [`SqlcipherError`] — 解密 (读文件 / key 错 / 坏页) 或 sqlite 挂载失败.
pub fn open_decrypted(enc_db_path: &Path, key: &KeyMaterial, rounds: u32) -> Result<DecryptedDb, SqlcipherError> {
    let image = decrypt_db_to_image(enc_db_path, key, rounds)?;
    open_image(image)
}

/// 便捷: 解密加密库 **并合并已提交的 WAL 增量** + 只读挂载 → 读出**实时前沿**行 (全程内存, 不落盘).
///
/// = [`open_decrypted`] 但底层走 [`decrypt_db_to_image_with_wal`] (含未 checkpoint 的最新页).
/// 供实时监听场景 (`--watch`): 每次轮询到库/WAL 变化就重开一把, 拿到最新消息. WAL 缺失/无提交
/// 时等价 [`open_decrypted`].
///
/// # Errors
/// 见 [`SqlcipherError`] — 解密 (读文件 / key 错 / 坏页) / WAL 合并 / sqlite 挂载失败.
pub fn open_decrypted_with_wal(
    enc_db_path: &Path,
    key: &KeyMaterial,
    rounds: u32,
) -> Result<DecryptedDb, SqlcipherError> {
    let image = decrypt_db_to_image_with_wal(enc_db_path, key, rounds)?;
    open_image(image)
}
