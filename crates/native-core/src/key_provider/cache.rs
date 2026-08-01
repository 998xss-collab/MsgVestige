//! CacheKeyProvider — Windows DPAPI 加密的多账号 key 缓存
//!
//! 详见 spec v3-key-source-spec.md §五
//!
//! 阶段 2 实装：DPAPI (CryptProtectData / CryptUnprotectData, CURRENT_USER 范围)
//!              + bincode 序列化 + **永久 cache（默认无 TTL）**
//!
//! 设计契约（用户决策：选项 1 — 默认永久 + 解密失败才清）：
//!   - 默认 `stale_after_days = None` → entry 永不陈旧
//!   - 用户配置 `Some(days)` → 兜底语义：超期 entry 视为陈旧，被新 key 覆盖
//!   - 上层（Phase 4 ETL）解密失败时显式调用 `invalidate(wxid)` 失效一条 entry
//!
//! 红线：
//!   - **K-R3** 默认永久 cache — 仅在 `stale_after_days` 配置时才周期清理
//!   - **K-R3'** 显式失效接口 `invalidate(wxid)` — 解密失败上层手动清
//!   - **K-R4** 明文 wxid / master_key 绝不入 log（一律走 `sha8`）
//!   - **K-R5** DPAPI CURRENT_USER 范围（CryptProtectData 默认行为）
//!
//! 文件路径：`%USERPROFILE%\.v3-wechat-base\keys.enc`
//!
//! 文件格式（外层 DPAPI 密文 → 内层 bincode）：
//!   - 整文件 = `CryptProtectData(bincode::serialize(KeyCacheV1))`
//!   - bincode 选 default config（小端 / 变长 int / 无大小上限）
//!
//! 兼容性降级：
//!   - DPAPI 解密失败 → 自动 `keys.enc.bak` 备份 + 返回空 cache（避免锁死）
//!   - `allow_plaintext=true`（CLI flag）→ 退化为 bincode 明文（仅调研期）

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// PR2-8-b: DPAPI 原语抽到 super::dpapi (共享给 config); call site 仍写 dpapi::dpapi_{en,de}crypt.
use super::dpapi;
use super::error::KeyError;
use super::{sha8, KeyProvider, KeyProviderCapabilities, MasterKey, Wxid};

// PR2-1-b: anyhow::Result → KeyError 本地 alias 简化 cache.rs 内部 ?-传播.
type Result<T> = std::result::Result<T, KeyError>;

// PR2-1-b r3 P1-5/6/7/8: tracing 路径脱敏 — Path::strip_prefix 替代 String prefix 匹配,
// 防 backslash / UTF-8 多字节边界 / 中文路径误判. 三层 fallback:
// LOCALAPPDATA → USERPROFILE/AppData/Local → USERPROFILE → ext-only.
// 兜底不显示 filename (防 filename 可能编码 wxid), 只显示扩展名.
fn sanitize_path(p: &Path) -> String {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let userprofile = std::env::var_os("USERPROFILE").map(PathBuf::from);

    if let Some(ref lp) = local {
        if let Ok(rest) = p.strip_prefix(lp) {
            return format!("{{LOCALAPPDATA}}/{}", rest.to_string_lossy());
        }
    }
    if let Some(ref up) = userprofile {
        let appdata_local = up.join("AppData").join("Local");
        if let Ok(rest) = p.strip_prefix(&appdata_local) {
            return format!("{{USERPROFILE}}/AppData/Local/{}", rest.to_string_lossy());
        }
        if let Ok(rest) = p.strip_prefix(up) {
            return format!("{{USERPROFILE}}/{}", rest.to_string_lossy());
        }
    }
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("<no-ext>");
    format!("<sanitized-path>.{ext}")
}

/// 缓存 schema v1 — PoC-1 期固定 schema_version=1，破坏性升级走 ADR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCacheV1 {
    pub schema_version: u32,
    pub entries: HashMap<Wxid, KeyEntry>,
}

impl Default for KeyCacheV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            entries: HashMap::new(),
        }
    }
}

/// 单个 key 缓存条目
///
/// R8 补审 P2: **不 derive(Debug)** —— `master_key_hex` 是内存明文, derive 会让 `debug!(?entry)`/`{:?}`
/// 把所有缓存账号明文 key 写进日志文件。手写 Debug 走 sha8(对齐 MasterKey/Wxid/image_cache 既有纪律)。
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub wxid: Wxid,
    /// 64 char hex master key (整体文件已 DPAPI 加密, 本字段在内存里仍为明文).
    ///
    /// PR2-1-b: 保 String 类型 (而非 MasterKey newtype) — bincode 字节流跟 PoC-1 keys.enc 兼容.
    /// 边界转换走 `MasterKey::from_hex(&master_key_hex)` (resolve 出口) /
    /// `master_key_hex = key.to_hex()` (store 入口).
    pub master_key_hex: String,
    /// unix seconds
    pub created_at: i64,
    /// 取源 ("ciphertalk" / "cli") — 追踪 provenance
    pub source: String,
    /// 取 key 时微信版本 (可选)
    pub wechat_version: Option<String>,
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // K-R4: master_key_hex 内存明文 → 只露 sha8 指纹, 绝不出明文 (防 debug!(?entry) 泄进日志)。
        f.debug_struct("KeyEntry")
            .field("wxid", &self.wxid)
            .field(
                "master_key_hex",
                &format_args!("sha8={}", sha8(self.master_key_hex.as_bytes())),
            )
            .field("created_at", &self.created_at)
            .field("source", &self.source)
            .field("wechat_version", &self.wechat_version)
            .finish()
    }
}

impl KeyEntry {
    /// 是否陈旧（按可选 `stale_after_days` 判定）
    ///
    /// - `stale_after_days == None` → 永久模式，永不陈旧
    /// - `stale_after_days == Some(d)` → age > d 天则陈旧
    pub fn is_stale(&self, now_secs: i64, stale_after_days: Option<u64>) -> bool {
        match stale_after_days {
            None => false,
            Some(days) => {
                let age = now_secs.saturating_sub(self.created_at);
                age > (days as i64) * 86_400
            }
        }
    }
}

// PR2-1-b r2 P1-4: master_key_hex String 字段 Drop 时清零, 跟 MasterKey ZeroizeOnDrop 对称.
// 防内存 dump 残留明文 hex 副本 (K-R4 红线).
// String::clear() 不一定 zero 出底层 buffer; 走 zeroize::Zeroize::zeroize() 兜底.
impl Drop for KeyEntry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.master_key_hex.zeroize();
    }
}

/// `CacheStore::upsert` 的写回结果 — 用于上层判断是否真的需要落盘
///
/// 红线 #3 cache immutability：未陈旧 entry 不允许被覆盖，
/// 防止 ciphertalk 反复 hook 把已有 key 替换成新 key（即便 key 值相同，
/// `created_at` 重置也会冲掉永久窗口的可追溯性）。
///
/// 默认永久模式下任何已有 entry 都不被覆盖；
/// 仅当用户配置了 `stale_after_days` 且 entry 已陈旧时才允许覆盖。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UpsertOutcome {
    /// 写入成功 — 新增 entry 或覆盖了已陈旧 entry
    Written,
    /// 跳过 — 现有 entry 仍有效（未陈旧），保留原值（红线 #3）
    SkippedExistingValid,
}

/// CacheKeyProvider — DPAPI 加密缓存 (K-R5).
///
/// r2: `allow_plaintext` 改 `pub(crate)` (Claude r1 P1-3 — 防外部生产代码意外开明文模式).
/// 测试用 `with_allow_plaintext()` builder 或直接构造 `CacheKeyProvider { allow_plaintext: true, .. }`
/// 在 mod 内 (cfg(test)).
pub struct CacheKeyProvider {
    pub path: PathBuf,
    /// 调研期允许明文降级 (DPAPI 不可用时) — 默认 false. r2: pub→pub(crate) 防外部误开.
    pub(crate) allow_plaintext: bool,
    /// 陈旧天数 — `None` 永久 (默认), `Some(d)` 超过 d 天视为陈旧.
    pub stale_after_days: Option<u64>,
}

impl CacheKeyProvider {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path: path.unwrap_or_else(Self::default_path),
            allow_plaintext: false,
            stale_after_days: None,
        }
    }

    /// 配置陈旧天数（`None` 永久，`Some(d)` d 天后视为陈旧）
    pub fn with_stale_after_days(mut self, days: Option<u64>) -> Self {
        self.stale_after_days = days;
        self
    }

    /// **仅调研期** 开启 bincode 明文降级 (DPAPI 不可用时). 生产严禁 (K-R5).
    ///
    /// r2: 提供显式 builder 方法替代 `pub allow_plaintext: bool` 字段, 防外部生产
    /// 代码意外构造 `CacheKeyProvider { allow_plaintext: true, .. }` (Claude r1 P1-3).
    /// r4 P1: 加 #[cfg(test)] 编译期门控 — 外部 release 编译时方法不存在, 调用即编译错误.
    /// 0.2.0+ 删除整个方法 (单测改用 mod 内直接 pub(crate) 字段构造).
    #[cfg(test)]
    #[deprecated(note = "allow_plaintext 仅 PoC 调研期可用. 0.2.0+ 删除整个方法.")]
    pub fn with_allow_plaintext(mut self, allow: bool) -> Self {
        self.allow_plaintext = allow;
        self
    }

    /// 默认路径: `%LOCALAPPDATA%\msgvestige\cache\keys.enc` (PR2-1-b 改, 跟 ADR-411 §3.1 一致).
    ///
    /// fallback 链: LOCALAPPDATA → USERPROFILE/AppData/Local → "."
    pub fn default_path() -> PathBuf {
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local")))
            .unwrap_or_else(|| PathBuf::from("."));
        local.join("msgvestige").join("cache").join("keys.enc")
    }

    fn now_secs() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// 显式失效一个 wxid 的 entry（上层解密失败时调用）
    ///
    /// 配套永久 cache 模式的主清理路径：当 ETL/sqlcipher 用旧 key 解密失败时
    /// 上层应调本方法清掉缓存，再触发 chain.resolve() 走 ciphertalk 重新取 key。
    ///
    /// 返回 `true` 表示真的有 entry 被移除；`false` 表示原本就没这条 wxid。
    pub fn invalidate(&self, wxid: &Wxid) -> Result<bool> {
        let wxid_sha = sha8(wxid.as_str().as_bytes());
        // 第5轮复审 P3 (Claude): invalidate 的读-删-存也走同一独占锁, 别跟并发 store 互相整份覆盖。
        let _lock = lock_cache(&self.path);
        if !self.path.exists() {
            tracing::debug!(
                wxid_sha = %wxid_sha,
                "CacheKeyProvider.invalidate: cache 文件不存在，no-op"
            );
            return Ok(false);
        }
        let mut cache = CacheStore::load(&self.path, self.allow_plaintext)?;
        let removed = cache.entries.remove(wxid).is_some();
        if removed {
            CacheStore::save(&self.path, &cache, self.allow_plaintext)?;
            tracing::info!(
                wxid_sha = %wxid_sha,
                "CacheKeyProvider.invalidate: cache 显式失效（解密失败兜底）"
            );
        } else {
            tracing::debug!(
                wxid_sha = %wxid_sha,
                "CacheKeyProvider.invalidate: wxid 不在 cache 中，no-op"
            );
        }
        Ok(removed)
    }

    /// 清理已陈旧的 entry 并落盘
    ///
    /// 仅在用户配置了 `stale_after_days` 时跑 — 默认永久模式下直接返 Ok(0)，
    /// 不读 / 不写盘。
    ///
    /// 设计：
    ///   - 永久模式 → 直接 Ok(0)
    ///   - 配置模式 → load → 过滤 → 若有变化则 save，无变化跳过 IO
    ///   - 文件不存在 / 空 cache 直接返回 Ok(0)
    ///   - 任一步失败 bubble；调用方决定是否致命（resolve 内当 best-effort）
    ///
    /// 返回值：被剔除的 entry 数
    pub fn cleanup_stale(&self) -> Result<usize> {
        let Some(_days) = self.stale_after_days else {
            // 永久模式 — 不清
            return Ok(0);
        };
        // 第5轮复审 P3 (Claude): cleanup_stale (仅配置模式走到这) 的读-滤-存也走同一独占锁, 别跟并发 store 互相覆盖。
        let _lock = lock_cache(&self.path);
        if !self.path.exists() {
            return Ok(0);
        }
        let mut cache = CacheStore::load(&self.path, self.allow_plaintext)?;
        let now = Self::now_secs();
        let before = cache.entries.len();
        cache
            .entries
            .retain(|_, entry| !entry.is_stale(now, self.stale_after_days));
        let removed = before - cache.entries.len();
        if removed > 0 {
            CacheStore::save(&self.path, &cache, self.allow_plaintext)?;
            tracing::info!(
                removed,
                remaining = cache.entries.len(),
                "CacheKeyProvider.cleanup_stale: 剔除陈旧 entry"
            );
        }
        Ok(removed)
    }
}

/// 复审(第5轮)#4 + 双审 P2: 取 cache 的独占文件锁, 序列化"读-改-存整份 cache" (`store`/`invalidate`/`cleanup_stale`
/// 共用) —— 否则并发写不同账号会各存回只含自己那条、后者整份覆盖前者丢 key。**先建 cache 目录** (首次运行目录
/// 尚未建则 lock 文件开不了 → 恰漏首次并发多账号 setup, codex/Claude 双审都逮到)。锁独立 `<cache>.lock` 文件
/// (不随 cache 的 temp+rename 换 inode); 阻塞独占, 返回的 `File` drop 时释放。best-effort: 开/锁失败 → warn + `None`
/// (退无锁, 只留给真不支持文件锁的 FS)。**调用方须全同步持锁 (无 `.await` 跨锁点)**。
fn lock_cache(cache_path: &Path) -> Option<std::fs::File> {
    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut lp = cache_path.as_os_str().to_os_string();
    lp.push(".lock");
    let lp = std::path::PathBuf::from(lp);
    let f = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lp)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "cache 锁文件打开失败, 退无锁 (并发写可能丢更新)");
            return None;
        }
    };
    match f.lock() {
        Ok(()) => Some(f),
        Err(e) => {
            tracing::warn!(error = %e, "cache 锁获取失败, 退无锁 (并发写可能丢更新)");
            None
        }
    }
}

#[async_trait]
impl KeyProvider for CacheKeyProvider {
    async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>> {
        let cache = CacheStore::load(&self.path, self.allow_plaintext)?;
        let now = Self::now_secs();
        let mut out = HashMap::new();
        for (wxid, entry) in cache.entries.into_iter() {
            if entry.is_stale(now, self.stale_after_days) {
                tracing::debug!(
                    wxid_sha = %sha8(wxid.as_str().as_bytes()),
                    age_secs = now - entry.created_at,
                    stale_after_days = ?self.stale_after_days,
                    "CacheKeyProvider.resolve_all: 跳过陈旧 entry"
                );
                continue;
            }
            // PR2-1-b: String hex → MasterKey newtype 边界转换
            let mk = MasterKey::from_hex(&entry.master_key_hex)?;
            out.insert(wxid, mk);
        }
        Ok(out)
    }

    async fn resolve(&self, wxid: &Wxid) -> Result<MasterKey> {
        let cache = CacheStore::load(&self.path, self.allow_plaintext)?;
        let wxid_sha = sha8(wxid.as_str().as_bytes());
        // PR2-1-b r2: 改回 .get().cloned() (Claude r1 P1-1 — remove() 破坏 cache 语义).
        // KeyEntry derive(Clone), master_key_hex 是 String, clone OK; MasterKey 边界 from_hex 即可.
        // cache 是临时 load 的 (next call 重新 load), 但语义清晰: read-only resolve 不该修改 cache.
        match cache.entries.get(wxid).cloned() {
            Some(entry) => {
                let now = Self::now_secs();
                if entry.is_stale(now, self.stale_after_days) {
                    if let Err(e) = self.cleanup_stale() {
                        tracing::warn!(
                            wxid_sha = %wxid_sha,
                            error_kind = ?e,
                            "CacheKeyProvider.resolve: cleanup_stale 失败 (非致命)"
                        );
                    }
                    // PR2-1-b: CacheStale → NotFound (alpha 8 变体收敛, ADR-405 §3.1)
                    Err(KeyError::NotFound { wxid: wxid.clone() })
                } else {
                    MasterKey::from_hex(&entry.master_key_hex)
                }
            }
            None => Err(KeyError::NotFound { wxid: wxid.clone() }),
        }
    }

    /// 写回单条 key（K-R2 cache-first 落地） — load → upsert → save
    ///
    /// `provenance` 写入 `KeyEntry.source`（"ciphertalk" / "cli"），追踪 key 起源。
    /// `created_at` 用当前 unix 秒。
    ///
    /// 沿用 `CacheStore` 既有的 DPAPI/明文降级路径（与 `save` 完全一致）。
    ///
    /// 红线 #3：未陈旧 entry 不覆盖 — 见 `CacheStore::upsert`
    /// （永久模式下任何已有 entry 都不被覆盖；上层需显式 `invalidate` 才能让新 key 落地）
    /// 命中 `SkippedExistingValid` 时直接返 Ok，不 `save`（避免无意义重写 DPAPI 密文）。
    async fn store(&self, wxid: &Wxid, key: &MasterKey, provenance: &str) -> Result<()> {
        let wxid_sha = sha8(wxid.as_str().as_bytes());
        // **复审(第5轮)#4 + 双审 P2**: 独占文件锁序列化整个"读-改-存整份 cache", 防并发存不同账号互相整份覆盖丢
        // key (`lock_cache` 内**先建目录**, 修首次运行锁失效)。`_lock` 持到函数末 drop 释放; store 内全同步无 `.await`。
        let _lock = lock_cache(&self.path);
        let mut cache = CacheStore::load(&self.path, self.allow_plaintext)?;
        let now = Self::now_secs();
        let entry = KeyEntry {
            wxid: wxid.clone(),
            // PR2-1-b: MasterKey → String hex 边界转换 (落盘走 String, 跟 PoC-1 bincode 字节兼容)
            master_key_hex: key.to_hex(),
            created_at: now,
            source: provenance.to_string(),
            wechat_version: None,
        };
        let outcome = CacheStore::upsert(&mut cache, entry, now, self.stale_after_days);
        match outcome {
            UpsertOutcome::Written => {
                CacheStore::save(&self.path, &cache, self.allow_plaintext)?;
                tracing::info!(
                    wxid_sha = %wxid_sha,
                    provenance = %provenance,
                    "CacheKeyProvider.store: write-back 完成（Written）"
                );
            }
            UpsertOutcome::SkippedExistingValid => {
                // 红线 #3：现有未陈旧 entry 保留，不 save
                tracing::info!(
                    wxid_sha = %wxid_sha,
                    provenance = %provenance,
                    "CacheKeyProvider.store: 跳过 — 现有未陈旧 entry（红线 #3）"
                );
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "cache"
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            can_resolve_all: true,
            needs_user_consent: false,
            persists_to_disk: true,
        }
    }
}

/// CacheStore — 内部读写工具
///
/// 设计：
///   - `load` 不存在 → 返空 cache (`KeyCacheV1::default()`)，不报错
///   - DPAPI 解密失败 → 自动备份 `.bak` + 返空 cache（避免锁死用户）
///   - schema_version != 1 → 同上
///   - `save` 写时先建父目录，DPAPI 加密后 `fs::write`（非原子，PoC 期可接受）
pub struct CacheStore;

impl CacheStore {
    pub fn load(path: &Path, allow_plaintext: bool) -> Result<KeyCacheV1> {
        if !path.exists() {
            return Ok(KeyCacheV1::default());
        }
        let bytes = std::fs::read(path).map_err(KeyError::from)?;

        // 尝试 DPAPI 解密；失败时根据 allow_plaintext 走兜底
        let plain_result = dpapi::dpapi_decrypt(&bytes);
        let plain = match plain_result {
            Ok(p) => p,
            Err(e) => {
                if allow_plaintext {
                    // 调研模式：DPAPI 解密失败 → 当做明文 bincode 直读
                    // 红线提示：明文降级仅 PoC-1 调研期可用，v3-beta 后严禁开启
                    tracing::warn!(
                        path_kind = %sanitize_path(path),
                        error_kind = ?e,
                        "CacheStore.load: DPAPI 解密失败，allow_plaintext=true 降级为明文 bincode（仅调研期）"
                    );
                    bytes.clone()
                } else {
                    // 备份损坏文件 → 返空 cache
                    let bak = path.with_extension("enc.bak");
                    let _ = std::fs::rename(path, &bak);
                    tracing::warn!(
                        path_kind = %sanitize_path(path),
                        bak_kind = %sanitize_path(&bak),
                        error_kind = ?e,
                        "CacheStore.load: DPAPI 解密失败，备份原文件并返空 cache"
                    );
                    return Ok(KeyCacheV1::default());
                }
            }
        };

        let cache: KeyCacheV1 = match bincode::deserialize(&plain) {
            Ok(c) => c,
            Err(e) => {
                let bak = path.with_extension("enc.bak");
                let _ = std::fs::rename(path, &bak);
                // r5: bincode::Error 不暴露 schema 字段名 — 取 to_string 前 8 char 兜底脱敏.
                // r5 字段名统一用 bincode_error_prefix 而非 error_label, 强调"截断 prefix 非完整 error".
                let err_prefix = e.to_string().chars().take(8).collect::<String>();
                tracing::warn!(
                    path_kind = %sanitize_path(path),
                    bak_kind = %sanitize_path(&bak),
                    bincode_error_prefix = %err_prefix,
                    "CacheStore.load: bincode 反序列化失败 (备份并返空 cache)"
                );
                return Ok(KeyCacheV1::default());
            }
        };

        if cache.schema_version != 1 {
            // schema 不匹配 → 跟 DPAPI / bincode 失败同样处理：备份 + 返空 cache
            // 不再 bubble Err 是因为 PoC 阶段允许跨版本破坏性升级，避免锁死调用方
            // （spec §五 5.4：与 DPAPI / bincode 失败一致 fallback）
            let bak = path.with_extension("enc.bak");
            let _ = std::fs::rename(path, &bak);
            tracing::warn!(
                path_kind = %sanitize_path(path),
                bak_kind = %sanitize_path(&bak),
                actual = cache.schema_version,
                expected = 1u32,
                "CacheStore.load: schema_version 不匹配，备份并返空 cache"
            );
            return Ok(KeyCacheV1::default());
        }
        Ok(cache)
    }

    pub fn save(path: &Path, cache: &KeyCacheV1, allow_plaintext: bool) -> Result<()> {
        // 原子写临时名用的进程内单调序号 (第4轮复审: 防同进程并发 save 撞同一 tmp)。放在**语句之前**声明 item
        // (clippy items_after_statements)。
        static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(KeyError::from)?;
        }
        // bincode 序列化失败 → 走 io_sanitized (类型不该泄字节细节)
        let plain = bincode::serialize(cache).map_err(|_| {
            KeyError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bincode serialize failed",
            ))
        })?;

        let cipher = if allow_plaintext {
            // 调研模式：直接落 bincode 明文（不推荐，仅 PoC-1 调研期可用）
            // 红线提示：v3-beta-tag 后严禁开启明文路径
            tracing::warn!(
                path_kind = %sanitize_path(path),
                "CacheStore.save: allow_plaintext=true，落 bincode 明文（仅调研期，生产严禁）"
            );
            plain
        } else {
            dpapi::dpapi_encrypt(&plain)?
        };

        // 复审#7: **原子写** (同目录临时文件 + rename), 别 `std::fs::write` 就地覆盖 —— 就地覆盖时进程崩溃/断电
        // 会留**半截损坏**的 cache, 下次 load 反序列化失败 → 备份并返空 = 丢掉**全部**已缓存 key (要重跑 auth
        // 重提所有账号)。rename 同卷原子 (Windows std::fs::rename 走 `MOVEFILE_REPLACE_EXISTING`, 目标已存在也替换);
        // rename 失败清理临时文件不留垃圾。
        // **第4轮复审**: 临时名 = pid + **进程内单调序号** (`TMP_SEQ`, 见函数首) —— 只带 pid 时**同进程并发 save**
        // 会撞同一临时文件 (一个的 write 覆盖另一个、或一个的 rename 抢走另一个的 tmp); 原子自增序号令每次 save 的
        // tmp 唯一。(注: 这只防**临时文件**撞; 多任务"读-改-存**整份** cache"的丢更新竞争另见 KI, 需文件级锁, 非本修范围。)
        let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_extension(format!("enc.tmp.{}.{seq}", std::process::id()));
        std::fs::write(&tmp, &cipher).map_err(KeyError::from)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(KeyError::from(e));
        }
        Ok(())
    }

    /// 红线 #3 cache immutability：未陈旧 entry 不覆盖
    ///
    /// 行为：
    ///   - wxid 已有未陈旧 entry → 拒绝覆盖，返回 `SkippedExistingValid`
    ///   - wxid 不存在 OR 现有 entry 已陈旧 → 写入新 entry，返回 `Written`
    ///
    /// 永久模式（`stale_after_days = None`）：任何已有 entry 都视为未陈旧
    ///   即便 ciphertalk hook 跑了一次拿到新 key，只要 cache 里有旧 key，
    ///   就坚持用旧 key — 上层需显式 `CacheKeyProvider::invalidate(wxid)` 才能让新 key 落地。
    ///
    /// `now_secs` / `stale_after_days` 由调用方传入，便于测试 mock 时钟。
    pub fn upsert(
        cache: &mut KeyCacheV1,
        entry: KeyEntry,
        now_secs: i64,
        stale_after_days: Option<u64>,
    ) -> UpsertOutcome {
        if let Some(existing) = cache.entries.get(&entry.wxid) {
            if !existing.is_stale(now_secs, stale_after_days) {
                tracing::warn!(
                    wxid_sha = %sha8(entry.wxid.as_str().as_bytes()),
                    incoming_source = %entry.source,
                    existing_source = %existing.source,
                    existing_age_secs = now_secs - existing.created_at,
                    stale_after_days = ?stale_after_days,
                    "CacheStore.upsert: 未陈旧 entry 已存在，拒绝覆盖（永久红线 #3 cache immutability）"
                );
                return UpsertOutcome::SkippedExistingValid;
            }
            // existing 已陈旧 → 允许覆盖（继续走到下面 insert）
            tracing::debug!(
                wxid_sha = %sha8(entry.wxid.as_str().as_bytes()),
                existing_age_secs = now_secs - existing.created_at,
                "CacheStore.upsert: 现有 entry 已陈旧，允许覆盖"
            );
        }
        cache.entries.insert(entry.wxid.clone(), entry);
        UpsertOutcome::Written
    }
}

// =====================================================================================
// 单元测试
// =====================================================================================
#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn sample_entry(wxid: &str, key: &str, created_at: i64) -> KeyEntry {
        KeyEntry {
            wxid: Wxid::new(wxid),
            master_key_hex: key.to_string(),
            created_at,
            source: "ciphertalk".into(),
            wechat_version: Some("4.0.3.39".into()),
        }
    }

    // PR2-1-b 测试 helper: 把 &str wxid 包成 Wxid 再调 resolve / invalidate.
    // PoC-1 单测全用 &str, alpha 改 newtype 后需要边界包装.
    fn w(s: &str) -> Wxid {
        Wxid::new(s)
    }

    /// 测试用 upsert 简写 — 默认 now=0、`stale_after_days=Some(0)`
    /// → 任何 created_at >= 0 的 entry 都视为"陈旧"，guard 不阻拦覆盖。
    /// 这维持了旧测试"无条件 insert"的语义，但通过 outcome 让新测试可断言行为。
    fn upsert_simple(cache: &mut KeyCacheV1, entry: KeyEntry) -> UpsertOutcome {
        // now=i64::MAX/2 + stale=Some(0) → 任何 created_at 都已陈旧 → guard 不阻拦覆盖
        CacheStore::upsert(cache, entry, i64::MAX / 2, Some(0))
    }

    // --- schema 基础测试（与平台无关）---------------------------------------

    // r4 P1: sanitize_path 单测覆盖 5 分支 (Claude r3 P1-2).
    // r5 P1: skip 改 #[cfg(target_os = "windows")] 显式 — non-Windows 自动 skip 编译, 不污染 test runner.
    #[cfg(target_os = "windows")]
    #[test]
    fn sanitize_path_strips_localappdata() {
        let local = match std::env::var_os("LOCALAPPDATA") {
            Some(v) => PathBuf::from(v),
            None => return,
        };
        let p = local.join("msgvestige").join("cache").join("keys.enc");
        let s = sanitize_path(&p);
        assert!(s.starts_with("{LOCALAPPDATA}"), "should strip LOCALAPPDATA: {s}");
        if let Ok(user) = std::env::var("USERNAME") {
            if !user.is_empty() {
                assert!(!s.contains(&user), "should not leak username: {s}");
            }
        }
    }

    // r6 P1: 全局 Mutex 防 parallel cargo test 竞争 env var 操作.
    #[cfg(target_os = "windows")]
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// r5 P1: USERPROFILE/AppData/Local 分支单测 (覆盖 LOCALAPPDATA 不可用时的中间路径).
    #[cfg(target_os = "windows")]
    #[test]
    fn sanitize_path_strips_userprofile_appdata_local() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = match std::env::var_os("USERPROFILE") {
            Some(v) => PathBuf::from(v),
            None => return,
        };
        let p = home.join("AppData").join("Local").join("some-app").join("data.bin");
        let saved = std::env::var_os("LOCALAPPDATA");
        std::env::remove_var("LOCALAPPDATA");
        let s = sanitize_path(&p);
        if let Some(v) = saved {
            std::env::set_var("LOCALAPPDATA", v);
        }
        assert!(s.contains("{USERPROFILE}/AppData/Local"), "second fallback: {s}");
        if let Ok(user) = std::env::var("USERNAME") {
            if !user.is_empty() {
                assert!(!s.contains(&user), "should not leak username: {s}");
            }
        }
    }

    /// r5 P1: USERPROFILE-only 分支单测 (LOCALAPPDATA 不可用 + 路径不在 AppData/Local 下).
    #[cfg(target_os = "windows")]
    #[test]
    fn sanitize_path_strips_userprofile_only() {
        let _g = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let home = match std::env::var_os("USERPROFILE") {
            Some(v) => PathBuf::from(v),
            None => return,
        };
        let p = home.join("Documents").join("secret.txt");
        let saved = std::env::var_os("LOCALAPPDATA");
        std::env::remove_var("LOCALAPPDATA");
        let s = sanitize_path(&p);
        if let Some(v) = saved {
            std::env::set_var("LOCALAPPDATA", v);
        }
        assert!(s.contains("{USERPROFILE}/"), "third fallback: {s}");
        assert!(!s.contains("{USERPROFILE}/AppData"), "should not match 2nd: {s}");
    }

    #[test]
    fn sanitize_path_ext_only_fallback_for_unknown_root() {
        let p = PathBuf::from("/some/unknown/secret/path/keys.enc");
        let s = sanitize_path(&p);
        // 不应含敏感目录段
        assert!(!s.contains("secret"), "should not leak path components: {s}");
        assert!(!s.contains("unknown"), "should not leak path: {s}");
        // 应只露扩展名
        assert!(
            std::path::Path::new(&s)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("enc")),
            "should expose .enc extension: {s}"
        );
    }

    #[test]
    fn sanitize_path_no_extension_fallback() {
        let p = PathBuf::from("/random/no_ext_file");
        let s = sanitize_path(&p);
        assert!(s.ends_with(".<no-ext>"), "no-ext fallback: {s}");
    }

    #[test]
    fn sanitize_path_does_not_panic_on_empty() {
        let p = PathBuf::from("");
        let _ = sanitize_path(&p); // should not panic
    }

    #[test]
    fn cache_v1_default_is_empty() {
        let c = KeyCacheV1::default();
        assert_eq!(c.schema_version, 1);
        assert!(c.entries.is_empty());
    }

    /// 永久模式（默认）：任何 entry 永不陈旧
    #[test]
    fn key_entry_never_stale_in_permanent_mode() {
        let e = sample_entry("wxid_abc", &"0".repeat(64), 1_700_000_000);
        // 100 天 / 1000 天 / 10000 天后都仍不陈旧
        assert!(!e.is_stale(1_700_000_000, None));
        assert!(!e.is_stale(1_700_000_000 + 100 * 86_400, None));
        assert!(!e.is_stale(1_700_000_000 + 10_000 * 86_400, None));
    }

    /// 配置模式：stale_after_days = Some(7) 超过 7 天视为陈旧
    #[test]
    fn key_entry_stale_after_days_configured() {
        let e = sample_entry("wxid_abc", &"0".repeat(64), 1_700_000_000);
        let days7 = Some(7u64);
        // 同时刻 / 6 天 / 7 天精确边界 — 均未陈旧（> 而非 >=）
        assert!(!e.is_stale(1_700_000_000, days7));
        assert!(!e.is_stale(1_700_000_000 + 6 * 86_400, days7));
        assert!(!e.is_stale(1_700_000_000 + 7 * 86_400, days7));
        // 7 天 + 1 秒 → 陈旧
        assert!(e.is_stale(1_700_000_000 + 7 * 86_400 + 1, days7));
        // 8 天后 → 陈旧
        assert!(e.is_stale(1_700_000_000 + 8 * 86_400, days7));
    }

    // --- 红线 #3 cache immutability：未陈旧 entry 不覆盖 -------------------
    //
    // 用户决策（选项 1 永久 cache）后，红线语义改成：
    //   - 永久模式：任何已有 entry 都不被覆盖
    //   - 配置 stale_after_days：仅未陈旧 entry 不被覆盖；陈旧可覆盖
    //
    //   - upsert_new_entry_writes               : 新 wxid → Written
    //   - upsert_existing_in_permanent_mode_skips : 永久 cache 已有 entry → 永远 Skipped
    //   - upsert_existing_unstale_skips         : 配置 + 未陈旧 → Skipped
    //   - upsert_existing_stale_overwrites      : 配置 + 已陈旧 → Written
    // ----------------------------------------------------------------------

    #[test]
    fn upsert_new_entry_writes() {
        let mut c = KeyCacheV1::default();
        let now = 1_700_000_000;
        let outcome = CacheStore::upsert(
            &mut c,
            sample_entry("wxid_w1", &"a".repeat(64), now),
            now,
            None, // 永久模式
        );
        assert_eq!(outcome, UpsertOutcome::Written);
        assert_eq!(c.entries.len(), 1);
        assert_eq!(c.entries[&w("wxid_w1")].master_key_hex, "a".repeat(64));
    }

    #[test]
    fn upsert_existing_in_permanent_mode_always_skips() {
        // 永久 cache 红线：即便 10000 天后再 upsert 同 wxid，仍拒绝覆盖
        let mut c = KeyCacheV1::default();
        let now = 1_700_000_000;
        // 第一次写入
        let r1 = CacheStore::upsert(&mut c, sample_entry("wxid_w1", &"a".repeat(64), now), now, None);
        assert_eq!(r1, UpsertOutcome::Written);

        // 一万天后尝试覆盖 — 永久模式仍拒绝（必须显式 invalidate 才能让新 key 落地）
        let far_future = now + 10_000 * 86_400;
        let new_entry = KeyEntry {
            wxid: Wxid::new("wxid_w1"),
            master_key_hex: "b".repeat(64),
            created_at: far_future,
            source: "cli".into(),
            wechat_version: None,
        };
        let r2 = CacheStore::upsert(&mut c, new_entry, far_future, None);
        assert_eq!(
            r2,
            UpsertOutcome::SkippedExistingValid,
            "永久模式下任何已有 entry 都不应被覆盖"
        );

        // 旧 entry 必须原封不动
        let kept = &c.entries[&w("wxid_w1")];
        assert_eq!(kept.master_key_hex, "a".repeat(64));
        assert_eq!(kept.source, "ciphertalk");
        assert_eq!(kept.created_at, now);
    }

    #[test]
    fn upsert_existing_unstale_skips_in_configured_mode() {
        // 配置 stale_after_days=Some(7)：未陈旧 → 拒绝覆盖
        let mut c = KeyCacheV1::default();
        let now = 1_700_000_000;
        let days7 = Some(7u64);
        let r1 = CacheStore::upsert(&mut c, sample_entry("wxid_w1", &"a".repeat(64), now), now, days7);
        assert_eq!(r1, UpsertOutcome::Written);

        // 1 天后 — 仍未陈旧
        let later = now + 86_400;
        let new_entry = KeyEntry {
            wxid: Wxid::new("wxid_w1"),
            master_key_hex: "b".repeat(64),
            created_at: later,
            source: "cli".into(),
            wechat_version: None,
        };
        let r2 = CacheStore::upsert(&mut c, new_entry, later, days7);
        assert_eq!(r2, UpsertOutcome::SkippedExistingValid);

        // 旧 entry 保留
        let kept = &c.entries[&w("wxid_w1")];
        assert_eq!(kept.master_key_hex, "a".repeat(64));
        assert_eq!(kept.source, "ciphertalk");
        assert_eq!(kept.created_at, now);
    }

    #[test]
    fn upsert_existing_stale_overwrites_in_configured_mode() {
        // 配置 + 已陈旧 → 可覆盖
        let mut c = KeyCacheV1::default();
        let old = 1_700_000_000;
        let days7 = Some(7u64);
        let r1 = CacheStore::upsert(&mut c, sample_entry("wxid_w1", &"a".repeat(64), old), old, days7);
        assert_eq!(r1, UpsertOutcome::Written);

        // 时钟跳到 10 天后 — 旧 entry 已陈旧（>7d）
        let now = old + 10 * 86_400;
        let new_entry = KeyEntry {
            wxid: Wxid::new("wxid_w1"),
            master_key_hex: "b".repeat(64),
            created_at: now,
            source: "cli".into(),
            wechat_version: None,
        };
        let r2 = CacheStore::upsert(&mut c, new_entry, now, days7);
        assert_eq!(r2, UpsertOutcome::Written, "陈旧 entry 应被覆盖（用户配置兜底）");
        let replaced = &c.entries[&w("wxid_w1")];
        assert_eq!(replaced.master_key_hex, "b".repeat(64));
        assert_eq!(replaced.source, "cli");
        assert_eq!(replaced.created_at, now);
    }

    #[test]
    fn default_path_contains_native_cli_dir() {
        let p = CacheKeyProvider::default_path();
        let s = p.to_string_lossy();
        assert!(
            s.contains("msgvestige") || s.contains("cache"),
            "default_path 应含 msgvestige/cache: {s}"
        );
    }

    #[test]
    fn capabilities_cache() {
        let cs = CacheKeyProvider::new(None);
        let cap = cs.capabilities();
        assert!(cap.can_resolve_all);
        assert!(!cap.needs_user_consent);
        assert!(cap.persists_to_disk);
        assert_eq!(cs.name(), "cache");
        // 默认永久模式
        assert!(cs.stale_after_days.is_none(), "默认应为永久 cache");
    }

    #[test]
    fn with_stale_after_days_builder() {
        let cs = CacheKeyProvider::new(None).with_stale_after_days(Some(30));
        assert_eq!(cs.stale_after_days, Some(30));
        let cs2 = CacheKeyProvider::new(None).with_stale_after_days(None);
        assert_eq!(cs2.stale_after_days, None);
    }

    // --- bincode roundtrip（平台无关）--------------------------------------

    #[test]
    fn bincode_roundtrip_preserves_entries() {
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_x", &"f".repeat(64), 1_700_000_000));
        upsert_simple(&mut c, sample_entry("wxid_y", &"e".repeat(64), 1_700_000_100));

        let bytes = bincode::serialize(&c).expect("serialize");
        let back: KeyCacheV1 = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(back.schema_version, 1);
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.entries[&w("wxid_x")].master_key_hex, "f".repeat(64));
        assert_eq!(back.entries[&w("wxid_y")].created_at, 1_700_000_100);
    }

    #[test]
    fn load_missing_file_returns_empty_cache() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nope").join("keys.enc");
        let c = CacheStore::load(&path, false).expect("load missing should be ok");
        assert_eq!(c.schema_version, 1);
        assert!(c.entries.is_empty());
    }

    #[test]
    fn allow_plaintext_save_load_roundtrip() {
        // 用 allow_plaintext 避免依赖 DPAPI，覆盖核心 save→load 逻辑
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_p", &"1".repeat(64), 1_700_000_000));
        CacheStore::save(&path, &c, true).expect("save plaintext");
        assert!(path.exists());

        let back = CacheStore::load(&path, true).expect("load plaintext");
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[&w("wxid_p")].master_key_hex, "1".repeat(64));
    }

    #[test]
    fn load_corrupted_file_backs_up_and_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");
        // 写垃圾数据：DPAPI 解密会失败，bincode 也会失败
        std::fs::write(&path, b"not a valid DPAPI blob").unwrap();

        let c = CacheStore::load(&path, false).expect("load corrupted should not panic");
        assert!(c.entries.is_empty());
        // 原文件应被重命名为 .bak
        let bak = path.with_extension("enc.bak");
        assert!(bak.exists() || !path.exists());
    }

    // --- resolve / resolve_all（用 allow_plaintext 做平台无关测试）---------

    #[tokio::test]
    async fn resolve_hits_entry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let now = CacheKeyProvider::now_secs();
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_hit", &"c".repeat(64), now));
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path));
        src.allow_plaintext = true;
        let key = src.resolve(&w("wxid_hit")).await.expect("should hit");
        assert_eq!(key.to_hex(), "c".repeat(64));
    }

    /// P0-1：CacheKeyProvider::store → resolve roundtrip
    /// 验证 write-back 写入的 key 下次能直接从 cache 读出（K-R2 cache-first 闭环）
    #[tokio::test]
    async fn store_then_resolve_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let mut src = CacheKeyProvider::new(Some(path));
        src.allow_plaintext = true;

        // 初始 miss
        let r = src.resolve(&w("wxid_rt")).await;
        assert!(r.is_err(), "尚未写入应 miss");

        // store
        src.store(
            &w("wxid_rt"),
            &MasterKey::from_hex(&"f".repeat(64)).unwrap(),
            "ciphertalk",
        )
        .await
        .expect("store should succeed");

        // 现在能 resolve 出来
        let key = src.resolve(&w("wxid_rt")).await.expect("应能命中刚写入的 entry");
        assert_eq!(key.to_hex(), "f".repeat(64));

        // provenance 落到 KeyEntry.source
        let cache = CacheStore::load(&src.path, true).unwrap();
        assert_eq!(cache.entries[&w("wxid_rt")].source, "ciphertalk");
    }

    #[tokio::test]
    async fn resolve_miss_returns_cache_miss_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");
        let c = KeyCacheV1::default();
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path));
        src.allow_plaintext = true;
        let err = src.resolve(&w("wxid_none")).await.unwrap_err();
        // anyhow::Error → downcast 检查 KeyError 变种
        let kse = err;
        match kse {
            KeyError::NotFound { wxid } => {
                // PR2-12-d-pre: 断言原样回传 (不假设 wxid_ 前缀 — UserName 是不透明键).
                assert_eq!(wxid.as_str(), "wxid_none");
            }
            other => panic!("期望 CacheMiss，实得 {:?}", other),
        }
    }

    /// 永久模式：resolve 1 年前的 entry 也不会陈旧 — 仍命中
    #[tokio::test]
    async fn resolve_permanent_mode_never_stale() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        // entry created_at = 365 天前
        let old = CacheKeyProvider::now_secs() - 365 * 24 * 3600;
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_old", &"d".repeat(64), old));
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path));
        src.allow_plaintext = true;
        // 默认永久模式（stale_after_days = None）→ 仍能命中
        let key = src.resolve(&w("wxid_old")).await.expect("永久模式应命中陈年 entry");
        assert_eq!(key.to_hex(), "d".repeat(64));
    }

    /// 配置模式：stale_after_days=Some(7) → 8 天前的 entry 视为陈旧
    #[tokio::test]
    async fn resolve_stale_returns_stale_error_when_configured() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let old = CacheKeyProvider::now_secs() - 8 * 24 * 3600;
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_old", &"d".repeat(64), old));
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path)).with_stale_after_days(Some(7));
        src.allow_plaintext = true;
        let err = src.resolve(&w("wxid_old")).await.unwrap_err();
        let kse = err;
        match kse {
            KeyError::NotFound { .. } => {}
            other => panic!("期望 CacheStale，实得 {:?}", other),
        }
    }

    #[tokio::test]
    async fn resolve_all_filters_stale_entries_when_configured() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let now = CacheKeyProvider::now_secs();
        let old = now - 100 * 24 * 3600;
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_fresh", &"a".repeat(64), now));
        upsert_simple(&mut c, sample_entry("wxid_stale", &"b".repeat(64), old));
        CacheStore::save(&path, &c, true).unwrap();

        // 配置 7 天 — stale 应被过滤
        let mut src = CacheKeyProvider::new(Some(path)).with_stale_after_days(Some(7));
        src.allow_plaintext = true;
        let all = src.resolve_all().await.expect("resolve_all");
        assert_eq!(all.len(), 1);
        assert!(all.contains_key(&w("wxid_fresh")));
        assert!(!all.contains_key(&w("wxid_stale")));
    }

    /// 永久模式：resolve_all 不会过滤任何 entry
    #[tokio::test]
    async fn resolve_all_permanent_mode_returns_all() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let now = CacheKeyProvider::now_secs();
        let old = now - 1000 * 24 * 3600;
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_fresh", &"a".repeat(64), now));
        upsert_simple(&mut c, sample_entry("wxid_very_old", &"b".repeat(64), old));
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path));
        src.allow_plaintext = true;
        let all = src.resolve_all().await.expect("resolve_all");
        assert_eq!(all.len(), 2, "永久模式应全部返回");
    }

    // --- invalidate(wxid) 接口测试 ----------------------------------------

    /// invalidate 命中存在的 wxid → 返 true + 真的删
    #[tokio::test]
    async fn invalidate_removes_existing_entry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let mut src = CacheKeyProvider::new(Some(path.clone()));
        src.allow_plaintext = true;
        src.store(
            &w("wxid_inv"),
            &MasterKey::from_hex(&"f".repeat(64)).unwrap(),
            "ciphertalk",
        )
        .await
        .unwrap();
        // 确认存在
        let _ = src.resolve(&w("wxid_inv")).await.expect("应命中");

        // invalidate
        let removed = src.invalidate(&w("wxid_inv")).expect("invalidate ok");
        assert!(removed, "应返回 true");

        // 再 resolve 应 miss
        let err = src.resolve(&w("wxid_inv")).await.unwrap_err();
        let kse = err;
        assert!(matches!(kse, KeyError::NotFound { .. }));
    }

    /// invalidate 不存在的 wxid → 返 false，不报错
    #[tokio::test]
    async fn invalidate_nonexistent_returns_false() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let mut src = CacheKeyProvider::new(Some(path));
        src.allow_plaintext = true;
        // 先写一条别的 wxid 让 cache 文件存在
        src.store(
            &w("wxid_other"),
            &MasterKey::from_hex(&"a".repeat(64)).unwrap(),
            "ciphertalk",
        )
        .await
        .unwrap();

        let removed = src.invalidate(&w("wxid_not_here")).expect("invalidate ok");
        assert!(!removed, "不存在的 wxid 应返 false");

        // 其它 entry 不受影响
        let kept = src.resolve(&w("wxid_other")).await.expect("其它 entry 仍在");
        assert_eq!(kept.to_hex(), "a".repeat(64));
    }

    /// invalidate cache 文件不存在 → no-op 返 false
    #[test]
    fn invalidate_no_cache_file_is_noop() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nope").join("keys.enc");
        let src = CacheKeyProvider::new(Some(path));
        let removed = src.invalidate(&w("wxid_x")).expect("no-op ok");
        assert!(!removed);
    }

    /// invalidate 后允许 store 新 key（覆盖永久红线的合法路径）
    #[tokio::test]
    async fn invalidate_then_store_writes_new_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let mut src = CacheKeyProvider::new(Some(path));
        src.allow_plaintext = true;
        src.store(
            &w("wxid_inv"),
            &MasterKey::from_hex(&"a".repeat(64)).unwrap(),
            "ciphertalk",
        )
        .await
        .unwrap();
        // 直接 store 新 key — 永久模式下应被红线拦截
        src.store(&w("wxid_inv"), &MasterKey::from_hex(&"b".repeat(64)).unwrap(), "cli")
            .await
            .unwrap();
        let still_old = src.resolve(&w("wxid_inv")).await.unwrap();
        assert_eq!(still_old.to_hex(), "a".repeat(64), "永久模式不应被覆盖");

        // 显式 invalidate 后再 store → 新 key 落地
        src.invalidate(&w("wxid_inv")).unwrap();
        src.store(&w("wxid_inv"), &MasterKey::from_hex(&"b".repeat(64)).unwrap(), "cli")
            .await
            .unwrap();
        let new_key = src.resolve(&w("wxid_inv")).await.unwrap();
        assert_eq!(new_key.to_hex(), "b".repeat(64));
    }

    // --- P1 修复回归测试 ---------------------------------------------------

    /// schema_version != 1 → 备份 + 返空 cache（不再 bubble Err）
    /// 回归：P1 修复后 schema 不匹配跟 DPAPI / bincode 失败同样处理，避免锁死
    #[test]
    fn load_schema_mismatch_backs_up_and_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        // 构造一个 schema_version = 999 的 cache，allow_plaintext 落盘
        let bad = KeyCacheV1 {
            schema_version: 999,
            entries: HashMap::new(),
        };
        let bytes = bincode::serialize(&bad).unwrap();
        std::fs::write(&path, bytes).unwrap();

        let c = CacheStore::load(&path, true).expect("schema mismatch 不该 bubble Err");
        assert_eq!(c.schema_version, 1);
        assert!(c.entries.is_empty(), "schema 不匹配 → 返空 cache");

        let bak = path.with_extension("enc.bak");
        assert!(bak.exists() || !path.exists(), "原文件应被重命名为 .bak");
    }

    /// 配置 stale_after_days：resolve 命中陈旧 entry 触发 cleanup_stale 并落盘
    #[tokio::test]
    async fn resolve_stale_triggers_cleanup_when_configured() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let now = CacheKeyProvider::now_secs();
        let old = now - 100 * 24 * 3600;
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_old", &"d".repeat(64), old));
        upsert_simple(&mut c, sample_entry("wxid_fresh", &"a".repeat(64), now));
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path.clone())).with_stale_after_days(Some(7));
        src.allow_plaintext = true;
        // 触发 resolve(陈旧 wxid) → Err(CacheStale) + 自动 cleanup
        let err = src.resolve(&w("wxid_old")).await.unwrap_err();
        let kse = err;
        assert!(matches!(kse, KeyError::NotFound { .. }));

        // 重新 load — 陈旧 entry 应已被剔除，fresh 仍在
        let back = CacheStore::load(&path, true).expect("reload");
        assert!(
            !back.entries.contains_key(&w("wxid_old")),
            "陈旧 entry 应被 cleanup_stale 剔除"
        );
        assert!(back.entries.contains_key(&w("wxid_fresh")), "未陈旧 entry 应保留");
    }

    /// cleanup_stale 在无 cache 文件时返 Ok(0)
    #[test]
    fn cleanup_stale_no_file_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nope").join("keys.enc");
        let src = CacheKeyProvider::new(Some(path)).with_stale_after_days(Some(7));
        let removed = src.cleanup_stale().expect("missing file 不该 bubble");
        assert_eq!(removed, 0);
    }

    /// cleanup_stale 在永久模式（None）下不做任何事 — 即便有陈年 entry
    #[test]
    fn cleanup_stale_permanent_mode_is_noop() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let now = CacheKeyProvider::now_secs();
        let very_old = now - 10_000 * 24 * 3600;
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_ancient", &"z".repeat(64), very_old));
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path.clone()));
        src.allow_plaintext = true;
        // 默认永久模式
        let removed = src.cleanup_stale().expect("noop ok");
        assert_eq!(removed, 0, "永久模式不该清任何 entry");

        // entry 仍在
        let back = CacheStore::load(&path, true).unwrap();
        assert!(back.entries.contains_key(&w("wxid_ancient")));
    }

    /// cleanup_stale 在配置模式下 + 无陈旧 entry 时不写盘 + 返 0
    #[test]
    fn cleanup_stale_configured_no_op_when_all_fresh() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let now = CacheKeyProvider::now_secs();
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_fresh", &"a".repeat(64), now));
        CacheStore::save(&path, &c, true).unwrap();

        let mut src = CacheKeyProvider::new(Some(path)).with_stale_after_days(Some(30));
        src.allow_plaintext = true;
        let removed = src.cleanup_stale().expect("cleanup ok");
        assert_eq!(removed, 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dpapi_save_load_roundtrip() {
        // 真 DPAPI 路径（allow_plaintext = false）
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let now = CacheKeyProvider::now_secs();
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_dpapi", &"7".repeat(64), now));
        CacheStore::save(&path, &c, false).expect("save with DPAPI");

        // 写出的字节不应包含 wxid 明文（已被 DPAPI 加密）
        let raw = std::fs::read(&path).unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("wxid_dpapi"), "DPAPI 密文不应可见明文 wxid");

        let back = CacheStore::load(&path, false).expect("load with DPAPI");
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[&w("wxid_dpapi")].master_key_hex, "7".repeat(64));
    }

    // --- 红线 #3 store 层回归 + 多账号 chain 回归 -------------------------
    //
    // 覆盖 CacheKeyProvider::store 与 ChainedKeySource.resolve(wxid_B) 在已有
    // 未陈旧 entry 时的行为契约（永久模式）。
    // ----------------------------------------------------------------------

    /// 红线 #3 store 层契约（永久模式）：同 wxid 第二次 store → no-op
    #[tokio::test]
    async fn store_in_permanent_mode_is_no_op() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let mut src = CacheKeyProvider::new(Some(path.clone()));
        src.allow_plaintext = true;

        // 第一次 store key1
        src.store(
            &w("wxid_A"),
            &MasterKey::from_hex(&"1".repeat(64)).unwrap(),
            "ciphertalk",
        )
        .await
        .expect("first store ok");
        let first = src.resolve(&w("wxid_A")).await.expect("hit after first store");
        assert_eq!(first.to_hex(), "1".repeat(64));

        // 文件字节快照（验证第二次 store 真的没 save）
        let bytes_before = std::fs::read(&path).expect("read after 1st store");

        // 第二次 store key2 — 永久模式应 no-op
        src.store(&w("wxid_A"), &MasterKey::from_hex(&"2".repeat(64)).unwrap(), "cli")
            .await
            .expect("second store returns Ok");

        // resolve 应仍拿到 key1
        let second = src.resolve(&w("wxid_A")).await.expect("still hit");
        assert_eq!(
            second.to_hex(),
            "1".repeat(64),
            "未陈旧 entry 不应被覆盖（永久红线 #3）"
        );

        // provenance 仍是 ciphertalk
        let cache = CacheStore::load(&path, true).expect("reload");
        assert_eq!(cache.entries[&w("wxid_A")].source, "ciphertalk");

        // 文件字节未变
        let bytes_after = std::fs::read(&path).expect("read after 2nd store");
        assert_eq!(
            bytes_before, bytes_after,
            "no-op 路径不应 save，cache 文件字节应完全相同"
        );
    }

    /// 红线 #3 边界（配置模式 + 已陈旧）：第二次 store 真的覆盖
    #[tokio::test]
    async fn store_stale_overwrites_when_configured() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        let mut src = CacheKeyProvider::new(Some(path)).with_stale_after_days(Some(0));
        src.allow_plaintext = true;

        // 第一次 store key1（stale_after_days=0 → 立即陈旧）
        src.store(
            &w("wxid_A"),
            &MasterKey::from_hex(&"1".repeat(64)).unwrap(),
            "ciphertalk",
        )
        .await
        .expect("first store ok");

        // 等 1 秒确保 created_at 时间戳前进
        std::thread::sleep(std::time::Duration::from_secs(1));

        // 第二次 store key2 — 旧 entry 已陈旧 → 应覆盖
        src.store(&w("wxid_A"), &MasterKey::from_hex(&"2".repeat(64)).unwrap(), "cli")
            .await
            .expect("second store ok");

        let cache = CacheStore::load(&src.path, true).expect("reload");
        let kept = &cache.entries[&w("wxid_A")];
        assert_eq!(kept.master_key_hex, "2".repeat(64), "陈旧 entry 应被新 key 覆盖");
        assert_eq!(kept.source, "cli", "provenance 应更新为新值");
    }

    // PR2-1-d r1: 启用 PR2-1-b 推迟的 ChainedKeyProvider 集成测试 — 其它 4 个 (resolve_full_miss
    // / store_writeback / consent_denied / terminal_error) 已在 chain.rs 内 mock 测覆盖, 此处只
    // 保留 multi-wxid 持久化断言 (cache 真盘 + ChainedKeyProvider 真链).
    /// P1 多账号回归: chain.resolve(wxid_B) 不应碰已有的 wxid_A entry.
    #[tokio::test]
    async fn chain_resolve_partial_cache_does_not_touch_other_wxid() {
        use crate::key_provider::ChainedKeyProvider;

        struct MockCipherTalk {
            key_for_b_hex: String,
        }
        #[async_trait]
        impl KeyProvider for MockCipherTalk {
            async fn resolve_all(&self) -> std::result::Result<HashMap<Wxid, MasterKey>, KeyError> {
                Ok(HashMap::new())
            }
            async fn resolve(&self, wxid: &Wxid) -> std::result::Result<MasterKey, KeyError> {
                if wxid.as_str() == "wxid_B" {
                    MasterKey::from_hex(&self.key_for_b_hex).map_err(|_| KeyError::algorithm_mismatch("mock_corrupt"))
                } else {
                    Err(KeyError::NotFound { wxid: wxid.clone() })
                }
            }
            fn name(&self) -> &'static str {
                "mock_ciphertalk"
            }
            fn capabilities(&self) -> KeyProviderCapabilities {
                KeyProviderCapabilities {
                    can_resolve_all: false,
                    needs_user_consent: true,
                    persists_to_disk: false,
                }
            }
        }

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("keys.enc");

        // 提前给 cache 灌一条 wxid_A 的 entry (永久模式, 不会陈旧).
        let now = CacheKeyProvider::now_secs();
        let mut c = KeyCacheV1::default();
        upsert_simple(&mut c, sample_entry("wxid_A", &"a".repeat(64), now));
        CacheStore::save(&path, &c, true).unwrap();

        let mut cache_src = CacheKeyProvider::new(Some(path.clone()));
        cache_src.allow_plaintext = true;

        let chain = ChainedKeyProvider::new(vec![
            Box::new(cache_src),
            Box::new(MockCipherTalk {
                key_for_b_hex: "b".repeat(64),
            }),
        ]);

        // resolve(wxid_B) → cache miss → ciphertalk hit → write-back.
        let key_b = chain.resolve(&w("wxid_B")).await.expect("命中 wxid_B");
        assert_eq!(key_b.to_hex(), "b".repeat(64));

        // 关键断言: wxid_A 必须原封不动.
        let cache = CacheStore::load(&path, true).expect("reload after chain.resolve");
        assert!(
            cache.entries.contains_key(&w("wxid_A")),
            "wxid_A 必须保留 — 多账号 cache 不能因 resolve(B) 被清空"
        );
        let kept_a = &cache.entries[&w("wxid_A")];
        assert_eq!(
            kept_a.master_key_hex,
            "a".repeat(64),
            "wxid_A 的 key 必须不变 (红线 #3)"
        );
        assert_eq!(kept_a.source, "ciphertalk", "wxid_A 的 source 必须不变");
        assert_eq!(kept_a.created_at, now, "wxid_A 的 created_at 必须不变");

        // wxid_B 应该被 write-back 写入.
        assert!(
            cache.entries.contains_key(&w("wxid_B")),
            "wxid_B 应已被 write-back 到 cache"
        );
        assert_eq!(cache.entries[&w("wxid_B")].master_key_hex, "b".repeat(64));
        assert_eq!(
            cache.entries[&w("wxid_B")].source,
            "mock_ciphertalk",
            "wxid_B 的 provenance 应记 mock_ciphertalk"
        );
    }
}
