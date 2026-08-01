//! config — config.toml 加载 + 校验 (native-core 子系统, ADR-416 §3.2.1).
//!
//! - PR2-4-d: [`Config`] (ADR-403 §3.1 7 大类 17 字段) + serde TOML 反序列化 + 每段 `#[serde(default)]`
//!   兜底 + `[custom_*]` flatten 容错.
//! - PR2-4-e: validator 校验 (ADR-403 §3.4 TD3 serde+validator) — range/enum/红线/wxid 格式 +
//!   [`ConfigError`] (§3.4 钉死 7 变体) + [`load_config`] 入口 (file→parse→validate).
//! - PR2-4-f: semver 版本兼容检查 (ADR-403 §3.3 TD2) — [`check_version_compat`] (同 major 兼容) 接入 load_config.
//!
//! **推后续片**: 路径 writable 校验 (IO, validate_path_writable — 推 startup 片) + semver 老 minor 启动
//! 自动写回版本号 + warn (§3.3 反例 2, 文件写) + migrate-config 子命令 + DPAPI auth_password 解密
//! (§3.5 → DpapiDecryptFailed) + vendor dll sha256 校验.
//!
//! ## K-R4
//! `[cli].default_account_wxid` (wxid) + `[cli].auth_password` (DPAPI) 敏感 → 手写 [`Cli`] Debug 脱敏.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use validator::{Validate, ValidationError, ValidationErrors, ValidationErrorsKind};

use crate::key_provider::sha8;

// ── alpha 默认值 (ADR-403 §3.1) ──
fn d_version() -> String {
    "0.1.0".to_string()
}
fn d_data_dir() -> String {
    r"%LOCALAPPDATA%\msgvestige\data".to_string()
}
fn d_cache_dir() -> String {
    r"%LOCALAPPDATA%\msgvestige\cache".to_string()
}
fn d_node_path() -> String {
    "<bundled>".to_string()
}
fn d_emit_mode() -> String {
    "channel".to_string()
}
fn d_backpressure() -> String {
    "block".to_string()
}
fn d_log_level() -> String {
    "info".to_string()
}
fn d_log_dir() -> String {
    r"%LOCALAPPDATA%\msgvestige\logs".to_string()
}

/// `[config_meta]` — config schema 版本 (semver, §5 升级用; 版本校验推 semver 片).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
#[serde(default)]
pub struct ConfigMeta {
    pub version: String,
}
impl Default for ConfigMeta {
    fn default() -> Self {
        Self { version: d_version() }
    }
}

/// `[storage]` — L1 db + cache 目录. (data_dir/cache_dir writable 校验推 startup 片.)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
#[serde(default)]
pub struct Storage {
    pub data_dir: String,
    pub cache_dir: String,
    #[validate(range(min = 1, max = 1024, message = "须 1..=1024 GB"))]
    pub max_cache_size_gb: u32,
}
impl Default for Storage {
    fn default() -> Self {
        Self {
            data_dir: d_data_dir(),
            cache_dir: d_cache_dir(),
            max_cache_size_gb: 10,
        }
    }
}

/// `[wechat]` — 微信 db 路径. (db_path_override 路径存在校验推 startup 片.)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default, Validate)]
#[serde(default)]
pub struct Wechat {
    /// 空 = 自动发现; 非空 = 手动指定 (默认 "").
    pub db_path_override: String,
}

/// `[sidecar]` — sidecar Node 进程.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
#[serde(default)]
pub struct Sidecar {
    pub node_path: String,
    pub auto_restart: bool,
    #[validate(range(min = 1, max = 10, message = "须 1..=10 次/小时"))]
    pub max_restart_per_hour: u8,
}
impl Default for Sidecar {
    fn default() -> Self {
        Self {
            node_path: d_node_path(),
            auto_restart: true,
            max_restart_per_hour: 3,
        }
    }
}

/// `[privacy]` — 隐私默认 (跟 PrivacyMode 联动).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
#[serde(default)]
pub struct Privacy {
    pub default_sha: bool,
    #[validate(range(min = 0, max = 60, message = "须 0..=60 分钟"))]
    pub log_plaintext_window_minutes: u32,
}
impl Default for Privacy {
    fn default() -> Self {
        Self {
            default_sha: true,
            log_plaintext_window_minutes: 0,
        }
    }
}

/// `[adapter]` — emit / 背压 / 归档保留.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
#[serde(default)]
pub struct Adapter {
    #[validate(custom(function = "validate_emit_mode"))]
    pub emit_mode: String,
    #[validate(custom(function = "validate_backpressure"))]
    pub backpressure: String,
    #[validate(range(min = 1, max = 720, message = "须 1..=720 小时 (30 天)"))]
    pub archive_retention_hours: u32,
}
impl Default for Adapter {
    fn default() -> Self {
        Self {
            emit_mode: d_emit_mode(),
            backpressure: d_backpressure(),
            archive_retention_hours: 24,
        }
    }
}

/// `[cli]` — 账号 + auth 密码缓存 (**敏感, 手写 Debug 脱敏**). 默认全空 (derive Default).
#[derive(Clone, PartialEq, Eq, Deserialize, Default, Validate)]
#[serde(default)]
pub struct Cli {
    /// 多账号默认 wxid (空 = 当前微信账号). **K-R4: Debug 脱敏**.
    #[validate(custom(function = "validate_account_wxid"))]
    pub default_account_wxid: String,
    /// cli auth 密码缓存 (DPAPI `dpapi:<base64>`, 空 = 每次问). **K-R4: Debug 脱敏**. (DPAPI 解密推 §3.5 片.)
    pub auth_password: String,
}
/// 手写 Debug (K-R4): wxid → sha8 / password → 只示存在, 绝不出原值.
impl fmt::Debug for Cli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wxid = if self.default_account_wxid.is_empty() {
            "<empty>".to_string()
        } else {
            sha8(self.default_account_wxid.as_bytes())
        };
        f.debug_struct("Cli")
            .field("default_account_wxid_sha8", &wxid)
            .field(
                "auth_password",
                &if self.auth_password.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .finish()
    }
}

/// `[live_index]` — R9 三档实时索引 (off/thin/full) 的**持久默认档** (spec §14.5 件3 配置面)。
/// `watch` / `serve` 未显式给 `--live-index` 时照此档维护。生效优先级: per-account 覆盖 > global default > off。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default, Validate)]
#[serde(default)]
pub struct LiveIndex {
    /// 全局默认档 (off/thin/full); 空/缺 = off。
    #[validate(custom(function = "validate_tier"))]
    pub default: String,
    /// per-account 覆盖: wxid → 档。带 `--account` 的 `config set live-index` 写这里。
    /// (map 值的 off/thin/full 校验在 `config set` 写入时把关; 读侧 [`LiveIndex::tier_for`] 对未知值容错归 off。)
    pub accounts: BTreeMap<String, String>,
}

impl LiveIndex {
    /// 解析某账号**生效档**: per-account 覆盖 > global default > `"off"`。空串 / 未知值归一为 `"off"`
    /// (读侧容错: 配置里手写了非法档不致命, 退到最保守的 off — 不建索引)。
    #[must_use]
    pub fn tier_for(&self, account_wxid: &str) -> String {
        let raw = self
            .accounts
            .get(account_wxid)
            .filter(|t| !t.is_empty())
            .unwrap_or(&self.default);
        match raw.as_str() {
            "thin" => "thin".to_string(),
            "cold" => "cold".to_string(), // R20 冷库: L1 静态冷查, 不 watch。
            "full" => "full".to_string(),
            _ => "off".to_string(), // 空 / "off" / 未知 → off
        }
    }
}

/// R20 四档友好名 → 规范档值。接受中文档名(裸跑/快搜/冷库/全速)+ 英文规范值(off/thin/cold/full)+ 常见别名。
/// `None` = 无法识别 (调用方拒)。四档语义(声明式, `config set tier` 只记档 + 打印手动指引, 不自动触发重活):
/// - 裸跑=`off`: 无索引库, 热查直读源库。
/// - 快搜=`thin`: R18 独立瘦搜 FTS (不建 L1)。
/// - 冷库=`cold`: L1 建一次(`ingest --all`), 静态冷查, **不 watch**。
/// - 全速=`full`: L1 + watch 实时。
#[must_use]
pub fn tier_canonical(name: &str) -> Option<&'static str> {
    match name.trim() {
        "off" | "裸跑" | "bare" => Some("off"),
        "thin" | "快搜" => Some("thin"),
        "cold" | "冷库" => Some("cold"),
        "full" | "全速" => Some("full"),
        _ => None,
    }
}

/// `[observability]` — 日志 + metrics (metrics_enabled 红线 must false).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Validate)]
#[serde(default)]
pub struct Observability {
    #[validate(custom(function = "validate_log_level"))]
    pub log_level: String,
    pub log_dir: String,
    #[validate(custom(function = "validate_metrics_disabled"))]
    pub metrics_enabled: bool,
}
impl Default for Observability {
    fn default() -> Self {
        Self {
            log_level: d_log_level(),
            log_dir: d_log_dir(),
            metrics_enabled: false,
        }
    }
}

// ── 自定义校验函数 (ADR-403 §3.1 校验列 + §3.6 反例 X 红线) ──

fn validate_emit_mode(v: &str) -> Result<(), ValidationError> {
    if matches!(v, "channel" | "jsonl" | "mq") {
        Ok(())
    } else {
        Err(ValidationError::new("emit_mode_invalid").with_message("须 ∈ {channel, jsonl, mq}".into()))
    }
}

fn validate_backpressure(v: &str) -> Result<(), ValidationError> {
    if matches!(v, "block" | "spill" | "drop") {
        Ok(())
    } else {
        Err(ValidationError::new("backpressure_invalid").with_message("须 ∈ {block, spill, drop}".into()))
    }
}

fn validate_log_level(v: &str) -> Result<(), ValidationError> {
    if matches!(v, "trace" | "debug" | "info" | "warn" | "error") {
        Ok(())
    } else {
        Err(ValidationError::new("log_level_invalid").with_message("须 ∈ {trace, debug, info, warn, error}".into()))
    }
}

/// R9 件3 + R20: live-index 默认档校验 (空 = off; 否则 ∈ {off, thin, cold, full})。`cold`(冷库)= R20 加 —— L1
/// 静态冷查、不 watch。
fn validate_tier(v: &str) -> Result<(), ValidationError> {
    if v.is_empty() || matches!(v, "off" | "thin" | "cold" | "full") {
        Ok(())
    } else {
        Err(ValidationError::new("live_index_tier_invalid").with_message("须 ∈ {off, thin, cold, full}".into()))
    }
}

/// §3.6 反例 X 红线: metrics_enabled 永远 false (不主动联网, 需求 §11.5-5).
// validator custom 函数签名强制 &T (宏生成 fn(&self.field)), 故 &bool 不能改 by-value.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn validate_metrics_disabled(value: &bool) -> Result<(), ValidationError> {
    if *value {
        Err(ValidationError::new("metrics_enabled_must_be_false")
            .with_message("红线: 须 false (不主动联网); 调试走 cli flag 不进 config".into()))
    } else {
        Ok(())
    }
}

/// 空 = 当前账号; 非空须合法微信 UserName — 跟 [`crate::key_provider::Wxid`] 同一套不透明校验
/// (接受 wxid_/自定义微信号/gh_/@chatroom/系统号; 只拒超长/含空白控制符). 单一真相: 委托 `Wxid::try_new`.
/// PR2-12-d-pre: 旧版写死 wxid_ 前缀会拒真实数据 ~9% 自定义号 own-account, 已放宽.
fn validate_account_wxid(v: &str) -> Result<(), ValidationError> {
    if v.is_empty() || crate::key_provider::Wxid::try_new(v).is_ok() {
        Ok(())
    } else {
        Err(ValidationError::new("account_wxid_invalid")
            .with_message("须空 (当前账号) 或合法微信 UserName (≤128, 无空白/控制符)".into()))
    }
}

/// 完整 config.toml (ADR-403 §3.1 7 大类 + `[custom_*]` 扩展). 缺段/缺字段全走 alpha 默认.
///
/// Config derive Debug 安全 — [`Cli`] 段手写 Debug 已脱敏 wxid/password.
#[derive(Debug, Clone, Deserialize, Default, Validate)]
#[serde(default)]
pub struct Config {
    pub config_meta: ConfigMeta,
    #[validate(nested)]
    pub storage: Storage,
    #[validate(nested)]
    pub wechat: Wechat,
    #[validate(nested)]
    pub sidecar: Sidecar,
    #[validate(nested)]
    pub privacy: Privacy,
    #[validate(nested)]
    pub adapter: Adapter,
    #[validate(nested)]
    pub cli: Cli,
    #[validate(nested)]
    pub observability: Observability,
    #[validate(nested)]
    pub live_index: LiveIndex,
    /// `[custom_*]` 扩展段 + 任何未知顶层段 (alpha 不强校验, 容错捕获不报错; FD1 用户拍 B 留口子).
    #[serde(flatten)]
    pub custom: BTreeMap<String, toml::Value>,
}

/// config 子系统错误 (ADR-403 §3.4 钉死完整 7 变体; 跟 ADR-405 ConfigError 子 enum 一致).
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    /// config 文件不存在.
    #[error("config file not found at {0}")]
    FileNotFound(PathBuf),

    /// 字段校验失败 (含友好修改建议).
    #[error("validation failed for field `{field}`: {reason}; suggested fix: {suggestion}")]
    ValidationFailed {
        field: String,
        reason: String,
        suggestion: String,
    },

    /// config 版本不兼容 (semver 片用).
    #[error(
        "version incompatible: config is {actual}, cli expects {expected}; run `msgvestige migrate-config` to upgrade"
    )]
    VersionIncompatible { actual: String, expected: String },

    /// DPAPI 解密失败 (DPAPI 片用).
    #[error("DPAPI decrypt failed for field `{field}`: {reason}; try re-running `msgvestige auth` to refresh the cached credential")]
    DpapiDecryptFailed { field: String, reason: String },

    /// vendor dll sha256 不匹配 (vendor 校验片用; ADR-410 STPA #18).
    #[error("vendor dll sha256 mismatch: expected {expected_sha256}, got {actual_sha256}; re-download release zip, see INSTALL.md §6 + ADR-419")]
    VendorDllMismatch {
        expected_sha256: String,
        actual_sha256: String,
    },

    /// IO 错 (文件读).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML 反序列化错.
    #[error("toml deserialize error: {0}")]
    TomlDe(#[from] toml::de::Error),
}

/// 取第一个校验失败叶子 → (字段路径, 原因), 跨 nested 递归.
fn first_failure(errs: &ValidationErrors) -> (String, String) {
    for (field, kind) in errs.errors() {
        match kind {
            ValidationErrorsKind::Field(ves) => {
                if let Some(ve) = ves.first() {
                    let reason = ve
                        .message
                        .as_ref()
                        .map_or_else(|| ve.code.to_string(), std::string::ToString::to_string);
                    return ((*field).to_string(), reason);
                }
            }
            ValidationErrorsKind::Struct(inner) => {
                let (f, r) = first_failure(inner);
                return (format!("{field}.{f}"), r);
            }
            ValidationErrorsKind::List(map) => {
                if let Some(inner) = map.values().next() {
                    let (f, r) = first_failure(inner);
                    return (format!("{field}.{f}"), r);
                }
            }
        }
    }
    ("<unknown>".to_string(), "validation failed".to_string())
}

/// 按字段给友好修改建议 (ADR-403 §3.4 "建议怎么修").
fn suggest_fix(field: &str) -> String {
    match field {
        f if f.ends_with("max_cache_size_gb") => "改到 1..=1024".to_string(),
        f if f.ends_with("max_restart_per_hour") => "改到 1..=10".to_string(),
        f if f.ends_with("log_plaintext_window_minutes") => "改到 0..=60".to_string(),
        f if f.ends_with("archive_retention_hours") => "改到 1..=720".to_string(),
        f if f.ends_with("emit_mode") => "改成 channel / jsonl / mq".to_string(),
        f if f.ends_with("backpressure") => "改成 block / spill / drop".to_string(),
        f if f.ends_with("log_level") => "改成 trace / debug / info / warn / error".to_string(),
        f if f.ends_with("metrics_enabled") => "改成 false (红线)".to_string(),
        f if f.ends_with("default_account_wxid") => {
            "留空 (当前账号) 或填合法微信 UserName (≤128, 无空白/控制符)".to_string()
        }
        _ => "见 ADR-403 §3.1 字段约束".to_string(),
    }
}

impl Config {
    /// 从 config.toml 内容串解析 (缺字段兜底 alpha 默认; 未知/custom_* 段容错). **不含校验** — 用 [`Config::validate_config`].
    ///
    /// # Errors
    /// `toml::de::Error` — TOML 语法错 / 已知字段类型不匹配.
    pub fn load_from_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// validator 校验 (ADR-403 §3.4) — 失败映射成友好 [`ConfigError::ValidationFailed`] (字段 + 原因 + 建议).
    ///
    /// # Errors
    /// `ConfigError::ValidationFailed` — 任一字段不合规 (range / enum / 红线 / wxid 格式).
    pub fn validate_config(&self) -> Result<(), ConfigError> {
        self.validate().map_err(|errs| {
            let (field, reason) = first_failure(&errs);
            let suggestion = suggest_fix(&field);
            ConfigError::ValidationFailed {
                field,
                reason,
                suggestion,
            }
        })
    }
}

/// alpha cli 期望的 config schema 版本 (跟 [`ConfigMeta`] 默认 + ADR-403 §3.3 起始版本一致).
pub const EXPECTED_CONFIG_VERSION: &str = "0.1.0";

/// 取 semver 版本的 major 号 (第一段); 无法解析返 `None`.
fn parse_major(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

/// 检查 config 版本兼容 (ADR-403 §3.3 TD2 semver): **同 major 兼容** (0.x 内 minor/patch 差异由
/// serde default 兜底); **major 不同 (或不可解析) → [`ConfigError::VersionIncompatible`]** (需 migrate-config).
///
/// **推后续片** (本片不做): 老 minor 版本启动自动写回新版本号 + warn (§3.3 反例 2, 文件写) /
/// `migrate-config` 子命令 (major 升级迁移工具).
///
/// # Errors
/// `ConfigError::VersionIncompatible` — config major != expected major, 或版本串不可解析.
pub fn check_version_compat(config_version: &str, expected: &str) -> Result<(), ConfigError> {
    match (parse_major(config_version), parse_major(expected)) {
        (Some(c), Some(e)) if c == e => Ok(()),
        _ => Err(ConfigError::VersionIncompatible {
            actual: config_version.to_string(),
            expected: expected.to_string(),
        }),
    }
}

/// 从文件路径加载 config (file→parse→version 兼容检查→validate, ADR-403 §3.4 load_config 入口).
///
/// 版本检查在 validate 之前 — major 不兼容的 config 直接拒, 不浪费校验 (其字段集可能已变).
///
/// **推后续片** (本片不做): 老 minor 自动写回版本号 + warn (§3.3 反例 2) / [custom_*] warn 提示 /
/// DPAPI auth_password 解密 (§3.5).
///
/// # Errors
/// - `ConfigError::FileNotFound` — 路径不存在.
/// - `ConfigError::Io` — 其它读文件错.
/// - `ConfigError::TomlDe` — TOML 解析错.
/// - `ConfigError::VersionIncompatible` — config major 跟 cli 不兼容.
/// - `ConfigError::ValidationFailed` — 字段校验失败.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::FileNotFound(path.to_path_buf()));
    }
    let raw = std::fs::read_to_string(path)?; // ConfigError::Io
    let config: Config = toml::from_str(&raw)?; // ConfigError::TomlDe
    check_version_compat(&config.config_meta.version, EXPECTED_CONFIG_VERSION)?; // VersionIncompatible
    config.validate_config()?; // ConfigError::ValidationFailed
                               // 推后续片: 老 minor 自动写回版本号 + warn / custom_* warn / DPAPI 解密 auth_password
    Ok(config)
}

/// 默认 config.toml 路径: `%LOCALAPPDATA%\msgvestige\config.toml` (DEPLOY 约定; fallback USERPROFILE/AppData/Local → ".")。
#[must_use]
pub fn default_config_path() -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local")))
        .unwrap_or_else(|| PathBuf::from("."));
    local.join("msgvestige").join("config.toml")
}

/// 尽力加载 config: 文件不存在 → 全默认 (正常 — 首次运行没配置文件); 解析/校验失败 → 默认 + eprintln 警告
/// (启动早期日志系统还没起, 只能 eprintln 兜底)。**绝不因配置问题让程序起不来**。
#[must_use]
pub fn load_or_default(path: &Path) -> Config {
    match load_config(path) {
        Ok(c) => c,
        Err(ConfigError::FileNotFound(_)) => Config::default(),
        Err(e) => {
            eprintln!("⚠️ config 加载失败, 本次用默认值兜底 (改 {} 修): {e}", path.display());
            Config::default()
        }
    }
}

/// R9 件3: **config set live-index 写回** —— 读现有 config.toml (`toml::Table`, 保留其它段/字段) → set
/// `live_index.default` (`account=None`) 或 `live_index.accounts.<wxid>` (`account=Some`) → 写回。文件不存在则
/// 新建 (只含 `[live_index]` 段, 其余项加载时走默认)。父目录缺则建。
///
/// `tier` 须 ∈ {off, thin, full} (调用方 CLI 先校验)。往返用 toml crate (**非格式保留** —— config.toml 是机器管理
/// 配置, 丢注释可接受; 但保留所有其它键值段)。
///
/// # Errors
/// - `ConfigError::Io` — 读 / 写 / 建目录失败。
/// - `ConfigError::TomlDe` — 现有 config.toml 语法损坏 (无法解析成 Table)。
/// - `ConfigError::ValidationFailed{field:"live_index"}` — 序列化回 TOML 失败 (极罕见)。
pub fn set_live_index_tier(path: &Path, tier: &str, account: Option<&str>) -> Result<(), ConfigError> {
    let mut doc: toml::Table = if path.exists() {
        toml::from_str(&std::fs::read_to_string(path)?)?
    } else {
        toml::Table::new()
    };
    // 取 / 建 [live_index] 段 (现有非 table → 重建这一段, 不动 doc 里其它段)。
    let mut li = match doc.remove("live_index") {
        Some(toml::Value::Table(t)) => t,
        _ => toml::Table::new(),
    };
    match account {
        None => {
            li.insert("default".to_string(), toml::Value::String(tier.to_string()));
        }
        Some(wxid) => {
            let mut accts = match li.remove("accounts") {
                Some(toml::Value::Table(t)) => t,
                _ => toml::Table::new(),
            };
            accts.insert(wxid.to_string(), toml::Value::String(tier.to_string()));
            li.insert("accounts".to_string(), toml::Value::Table(accts));
        }
    }
    doc.insert("live_index".to_string(), toml::Value::Table(li));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(&doc).map_err(|e| ConfigError::ValidationFailed {
        field: "live_index".to_string(),
        reason: format!("序列化 config.toml 失败: {e}"),
        suggestion: "检查现有 config.toml 是否损坏".to_string(),
    })?;
    std::fs::write(path, text)?;
    Ok(())
}

// ── startup 路径校验 + 准备 (ADR-403 §3.1 校验列; config 校验器 PR2-4-e 显式推后的 FS-touching 片) ──

/// 展开路径里的 Windows `%VAR%` 环境变量 (e.g. `%LOCALAPPDATA%\msgvestige\data` → 真实路径).
///
/// 未知 var 或无闭合 `%` → 原样保留 (不静默吞 — 让后续 existence 校验自然报错)。
#[must_use]
pub fn expand_env_vars(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(pos) = rest.find('%') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            if let Ok(val) = std::env::var(name) {
                out.push_str(&val);
            } else {
                // 未知 var: 原样保留 %NAME%
                out.push('%');
                out.push_str(name);
                out.push('%');
            }
            rest = &after[end + 1..];
        } else {
            // 落单的 % 无闭合: 原样保留
            out.push('%');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// 写探测序号 (保证同进程并发探测文件名唯一, 避免撞 create_new).
static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 目录【可写】探测 (ADR-403 §3.1 "可写"): 建唯一临时文件再删. 失败 → ValidationFailed{field}.
///
/// 唯一名 = pid + 原子序号 (防同进程并发撞名); 显式 `drop(file)` 再删 (Windows 不能删开着的文件).
fn probe_writable(dir: &str, field: &str) -> Result<(), ConfigError> {
    let seq = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let probe = Path::new(dir).join(format!(".native_cli_write_probe_{}_{seq}", std::process::id()));
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(file) => {
            drop(file); // 显式关闭后才能删 (Windows 文件占用)
            let _ = std::fs::remove_file(&probe); // 清理失败不致命 (探测已成)
            Ok(())
        }
        Err(e) => Err(ConfigError::ValidationFailed {
            field: field.to_string(),
            reason: format!("目录不可写 {dir}: {e}"),
            suggestion: "检查目录写权限 (startup 需写)".to_string(),
        }),
    }
}

/// startup 路径校验 + 准备 (ADR-403 §3.1 "校验"列; load_config 之后由启动序列调用 — 有 FS 副作用故不塞进纯 load_config).
///
/// 各路径字段【展开 %VAR%】后:
/// - `[storage].data_dir`: 必须【已存在且是目录】 (装机时建, 不在此自动建).
/// - `[storage].cache_dir` / `[observability].log_dir`: 【缺则建】 (`create_dir_all`).
/// - `[wechat].db_path_override`: 空跳过 (自动发现); 非空则必须【存在】.
/// - `[sidecar].node_path`: `<bundled>` / 空跳过 (bundle/PATH 解析推后续); 其它则必须【存在】.
///
/// **推后续片** (本片不做): `[cli].auth_password` DPAPI 解密校验 (§3.5, windows DPAPI) /
/// node_path `<bundled>` 实际定位 + PATH 查找.
///
/// # Errors
/// `ConfigError::ValidationFailed` — data_dir 不存在/非目录 / cache·log 创建失败 / override·node_path 非空但不存在
/// (均带 field + reason + 友好建议).
pub fn ensure_config_paths(config: &Config) -> Result<(), ConfigError> {
    // data_dir: 必须已存在且是目录 (装机时建)
    let data_dir = expand_env_vars(&config.storage.data_dir);
    if !Path::new(&data_dir).is_dir() {
        return Err(ConfigError::ValidationFailed {
            field: "storage.data_dir".to_string(),
            reason: format!("目录不存在或非目录: {data_dir}"),
            suggestion: "先建该目录 (装机流程) 或改 config 指向已存在目录".to_string(),
        });
    }
    probe_writable(&data_dir, "storage.data_dir")?; // §3.1 "可写"
                                                    // cache_dir / log_dir: 缺则建 (create_dir_all 幂等) + 可写探测
    for (field, raw) in [
        ("storage.cache_dir", &config.storage.cache_dir),
        ("observability.log_dir", &config.observability.log_dir),
    ] {
        let dir = expand_env_vars(raw);
        std::fs::create_dir_all(&dir).map_err(|e| ConfigError::ValidationFailed {
            field: field.to_string(),
            reason: format!("无法创建目录 {dir}: {e}"),
            suggestion: "检查父目录权限 / 磁盘空间".to_string(),
        })?;
        probe_writable(&dir, field)?; // §3.1 "可写"
    }
    // db_path_override: 空跳过 (自动发现); 非空则须存在
    if !config.wechat.db_path_override.is_empty() {
        let db = expand_env_vars(&config.wechat.db_path_override);
        if !Path::new(&db).exists() {
            return Err(ConfigError::ValidationFailed {
                field: "wechat.db_path_override".to_string(),
                reason: format!("指定的 db 路径不存在: {db}"),
                suggestion: "留空 = 自动发现, 或改成存在的 db 路径".to_string(),
            });
        }
    }
    // node_path: <bundled>/空 跳过 (解析推后续); 其它须存在
    let node = config.sidecar.node_path.trim();
    if !node.is_empty() && node != "<bundled>" {
        let np = expand_env_vars(node);
        if !Path::new(&np).exists() {
            return Err(ConfigError::ValidationFailed {
                field: "sidecar.node_path".to_string(),
                reason: format!("node 路径不存在: {np}"),
                suggestion: "留空找 PATH / 用 <bundled> / 改成存在的 node 路径".to_string(),
            });
        }
    }
    Ok(())
}

/// 校验 `[cli].auth_password` (ADR-403 §3.1 校验列 + §3.5 DPAPI): 空跳过 (每次问);
/// 非空须 `dpapi:` 前缀 + base64(DPAPI 密文) 且【解密成功】.
///
/// 跨机器迁移 (PC-A 加密的密文在 PC-B 解不开, DPAPI Per-User 作用域) → DpapiDecryptFailed (提示重跑 cli auth).
/// **K-R4**: 解密出的明文密码仅用于验解密性, 立即 zeroize 不留.
///
/// # Errors
/// - `ConfigError::ValidationFailed`: 非空但无 `dpapi:` 前缀 (格式错) / base64 解码失败.
/// - `ConfigError::DpapiDecryptFailed`: DPAPI 解密失败 (密文损坏 / 跨机器 → 重跑 cli auth).
pub fn validate_auth_password(config: &Config) -> Result<(), ConfigError> {
    use base64::Engine as _;
    use zeroize::Zeroize as _;

    let pw = config.cli.auth_password.trim();
    if pw.is_empty() {
        return Ok(()); // 空 = 每次都问, 合法
    }
    let Some(b64) = pw.strip_prefix("dpapi:") else {
        return Err(ConfigError::ValidationFailed {
            field: "cli.auth_password".to_string(),
            reason: "非空 auth_password 必须是 DPAPI 密文 (须 \"dpapi:\" 前缀, ADR-403 §3.5)".to_string(),
            suggestion: "留空 (每次问) 或跑 `msgvestige auth` 生成 DPAPI 密文".to_string(),
        });
    };
    let cipher = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| ConfigError::ValidationFailed {
            field: "cli.auth_password".to_string(),
            reason: format!("DPAPI 密文 base64 解码失败: {e}"),
            suggestion: "密文损坏 — 跑 `msgvestige auth` 重新生成".to_string(),
        })?;
    let mut plain =
        crate::key_provider::dpapi::dpapi_decrypt(&cipher).map_err(|e| ConfigError::DpapiDecryptFailed {
            field: "cli.auth_password".to_string(),
            reason: e.to_string(),
        })?;
    plain.zeroize(); // K-R4: 验完解密性立即清零明文密码
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── R9 件3: live-index 持久默认档 (tier_for 优先级 + set 写回) ──

    /// `LiveIndex::tier_for` 优先级: per-account 覆盖 > global default > off; 未知/空值容错归 off。
    #[test]
    fn live_index_tier_for_precedence() {
        let mut li = LiveIndex::default();
        assert_eq!(li.tier_for("wxid_a"), "off", "空 config → off");
        li.default = "full".to_string();
        assert_eq!(li.tier_for("wxid_a"), "full", "global default 生效");
        li.accounts.insert("wxid_a".to_string(), "thin".to_string());
        assert_eq!(li.tier_for("wxid_a"), "thin", "per-account 覆盖 global");
        assert_eq!(li.tier_for("wxid_b"), "full", "别账号仍走 global");
        li.default = "garbage".to_string();
        assert_eq!(li.tier_for("wxid_b"), "off", "未知 global 值容错归 off");
        li.accounts.insert("wxid_c".to_string(), "bogus".to_string());
        assert_eq!(li.tier_for("wxid_c"), "off", "未知 per-account 值容错归 off");
        // R20: cold(冷库)是第 4 合法档, tier_for 保留不归 off。
        li.default = "cold".to_string();
        assert_eq!(li.tier_for("wxid_z"), "cold", "R20 cold 档保留");
    }

    /// R20: 四档友好名 → 规范值映射 (中文档名 + 英文规范 + 别名; 未识别 → None)。
    #[test]
    fn r20_tier_canonical_maps_four_tiers() {
        assert_eq!(tier_canonical("裸跑"), Some("off"));
        assert_eq!(tier_canonical("快搜"), Some("thin"));
        assert_eq!(tier_canonical("冷库"), Some("cold"));
        assert_eq!(tier_canonical("全速"), Some("full"));
        // 英文规范值直通。
        assert_eq!(tier_canonical("off"), Some("off"));
        assert_eq!(tier_canonical("thin"), Some("thin"));
        assert_eq!(tier_canonical("cold"), Some("cold"));
        assert_eq!(tier_canonical("full"), Some("full"));
        // 别名 + 去空白。
        assert_eq!(tier_canonical(" bare "), Some("off"));
        // 未识别 → None (调用方拒)。
        assert_eq!(tier_canonical("garbage"), None);
        assert_eq!(tier_canonical(""), None);
        // 四档规范值都过 validate_tier (契约一致)。
        for t in ["off", "thin", "cold", "full"] {
            assert!(validate_tier(t).is_ok(), "规范值 {t} 应过 validate_tier");
        }
    }

    /// `set_live_index_tier` 写回: global default + per-account, **保留其它段**, 往返读回; 文件不存在则新建 (含父目录)。
    #[test]
    fn set_live_index_tier_writes_and_preserves_other_sections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[storage]\nmax_cache_size_gb = 42\n").unwrap(); // 预置其它段
                                                                               // set global full → 其它段须保留。
        set_live_index_tier(&path, "full", None).unwrap();
        let c = load_config(&path).unwrap();
        assert_eq!(c.live_index.default, "full", "global default 写入");
        assert_eq!(c.storage.max_cache_size_gb, 42, "其它段 (storage) 保留");
        // set per-account thin → global 仍在 + 其它段仍在。
        set_live_index_tier(&path, "thin", Some("wxid_x")).unwrap();
        let c = load_config(&path).unwrap();
        assert_eq!(c.live_index.default, "full", "global 仍在");
        assert_eq!(
            c.live_index.accounts.get("wxid_x").map(String::as_str),
            Some("thin"),
            "per-account 写入"
        );
        assert_eq!(c.storage.max_cache_size_gb, 42, "其它段仍保留");
        // 文件不存在 → 新建 (含父目录)。
        let path2 = dir.path().join("sub").join("new.toml");
        set_live_index_tier(&path2, "off", None).unwrap();
        assert!(path2.exists(), "父目录 + 文件新建");
        assert_eq!(load_config(&path2).unwrap().live_index.default, "off");
    }

    // ── PR2-8-a: startup 路径校验 (expand_env_vars + ensure_config_paths) ──

    #[test]
    fn expand_env_vars_cases() {
        assert_eq!(expand_env_vars(r"C:\plain\path"), r"C:\plain\path", "无 % 不变");
        assert_eq!(
            expand_env_vars(r"%NO_SUCH_VAR_NC_XZ%\x"),
            r"%NO_SUCH_VAR_NC_XZ%\x",
            "未知 var 原样保留"
        );
        assert_eq!(expand_env_vars(r"a%bc"), r"a%bc", "落单 % 无闭合原样");
        // cargo test 必设 CARGO_MANIFEST_DIR (跨平台, 无需 set_var)
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        assert_eq!(
            expand_env_vars(r"%CARGO_MANIFEST_DIR%\sub"),
            format!(r"{manifest}\sub"),
            "已知 var 展开"
        );
    }

    /// 把 config 路径字段指向具体绝对路径 (无 %VAR%); db_override 空 + node <bundled> (都跳过).
    fn config_with_dirs(data: &str, cache: &str, log: &str) -> Config {
        let mut c = Config::load_from_str("").unwrap();
        c.storage.data_dir = data.to_string();
        c.storage.cache_dir = cache.to_string();
        c.observability.log_dir = log.to_string();
        c.wechat.db_path_override = String::new();
        c.sidecar.node_path = "<bundled>".to_string();
        c
    }

    /// happy: data_dir 已存在 → 通过; cache_dir / log_dir 缺则建.
    #[test]
    fn ensure_paths_happy_creates_cache_and_log() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let cache = dir.path().join("cache");
        let log = dir.path().join("logs");
        let c = config_with_dirs(data.to_str().unwrap(), cache.to_str().unwrap(), log.to_str().unwrap());
        ensure_config_paths(&c).unwrap();
        assert!(cache.is_dir(), "cache_dir 缺则建");
        assert!(log.is_dir(), "log_dir 缺则建");
        // §3.1 可写探测后无残留 (data/cache/log 都不留 probe 文件)
        for d in [&data, &cache, &log] {
            let leftover = std::fs::read_dir(d)
                .unwrap()
                .filter_map(Result::ok)
                .any(|e| e.file_name().to_string_lossy().contains("write_probe"));
            assert!(!leftover, "写探测文件应已清理: {d:?}");
        }
    }

    /// data_dir 不存在 → ValidationFailed(storage.data_dir).
    #[test]
    fn ensure_paths_missing_data_dir_errs() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent");
        let c = config_with_dirs(
            missing.to_str().unwrap(),
            dir.path().join("c").to_str().unwrap(),
            dir.path().join("l").to_str().unwrap(),
        );
        match ensure_config_paths(&c) {
            Err(ConfigError::ValidationFailed { field, .. }) => assert_eq!(field, "storage.data_dir"),
            other => panic!("期望 data_dir ValidationFailed, 实际 {other:?}"),
        }
    }

    /// db_path_override 非空但不存在 → ValidationFailed(wechat.db_path_override).
    #[test]
    fn ensure_paths_db_override_missing_errs() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let mut c = config_with_dirs(
            data.to_str().unwrap(),
            dir.path().join("c").to_str().unwrap(),
            dir.path().join("l").to_str().unwrap(),
        );
        c.wechat.db_path_override = dir.path().join("nope.db").to_str().unwrap().to_string();
        match ensure_config_paths(&c) {
            Err(ConfigError::ValidationFailed { field, .. }) => assert_eq!(field, "wechat.db_path_override"),
            other => panic!("期望 db_override ValidationFailed, 实际 {other:?}"),
        }
    }

    /// node_path 非空非 <bundled> 但不存在 → ValidationFailed(sidecar.node_path).
    #[test]
    fn ensure_paths_node_path_missing_errs() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let mut c = config_with_dirs(
            data.to_str().unwrap(),
            dir.path().join("c").to_str().unwrap(),
            dir.path().join("l").to_str().unwrap(),
        );
        c.sidecar.node_path = dir.path().join("no_node.exe").to_str().unwrap().to_string();
        match ensure_config_paths(&c) {
            Err(ConfigError::ValidationFailed { field, .. }) => assert_eq!(field, "sidecar.node_path"),
            other => panic!("期望 node_path ValidationFailed, 实际 {other:?}"),
        }
    }

    // ── PR2-8-b: auth_password DPAPI 校验 ──

    /// 空 auth_password (默认) → Ok (每次问).
    #[test]
    fn auth_password_empty_ok() {
        let c = Config::load_from_str("").unwrap();
        validate_auth_password(&c).unwrap();
    }

    /// 非空但无 "dpapi:" 前缀 → ValidationFailed (该字段必须是 DPAPI 密文).
    #[test]
    fn auth_password_no_dpapi_prefix_errs() {
        let mut c = Config::load_from_str("").unwrap();
        c.cli.auth_password = "plaintextpw".to_string();
        match validate_auth_password(&c) {
            Err(ConfigError::ValidationFailed { field, .. }) => assert_eq!(field, "cli.auth_password"),
            other => panic!("期望 ValidationFailed (无前缀), 实际 {other:?}"),
        }
    }

    /// "dpapi:" + 非法 base64 → ValidationFailed.
    #[test]
    fn auth_password_bad_base64_errs() {
        let mut c = Config::load_from_str("").unwrap();
        c.cli.auth_password = "dpapi:!!!not-base64!!!".to_string();
        match validate_auth_password(&c) {
            Err(ConfigError::ValidationFailed { field, .. }) => assert_eq!(field, "cli.auth_password"),
            other => panic!("期望 ValidationFailed (base64), 实际 {other:?}"),
        }
    }

    /// windows: dpapi_encrypt → base64 → "dpapi:" 前缀 → 校验解密成功.
    #[cfg(target_os = "windows")]
    #[test]
    fn auth_password_dpapi_roundtrip_ok() {
        use base64::Engine as _;
        let cipher = crate::key_provider::dpapi::dpapi_encrypt(b"my-secret-pw").unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&cipher);
        let mut c = Config::load_from_str("").unwrap();
        c.cli.auth_password = format!("dpapi:{b64}");
        validate_auth_password(&c).unwrap();
    }

    /// windows: 合法 base64 但非 DPAPI 密文 → DpapiDecryptFailed (跨机器/损坏场景).
    #[cfg(target_os = "windows")]
    #[test]
    fn auth_password_corrupt_cipher_dpapi_fails() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"not-a-real-dpapi-blob");
        let mut c = Config::load_from_str("").unwrap();
        c.cli.auth_password = format!("dpapi:{b64}");
        match validate_auth_password(&c) {
            Err(ConfigError::DpapiDecryptFailed { field, .. }) => assert_eq!(field, "cli.auth_password"),
            other => panic!("期望 DpapiDecryptFailed, 实际 {other:?}"),
        }
    }

    // ── PR2-4-d: 解析 + 默认 + custom + 脱敏 ──

    #[test]
    fn empty_toml_all_defaults() {
        let c = Config::load_from_str("").unwrap();
        assert_eq!(c.config_meta.version, "0.1.0");
        assert_eq!(c.storage.max_cache_size_gb, 10);
        assert_eq!(c.storage.data_dir, r"%LOCALAPPDATA%\msgvestige\data");
        assert_eq!(c.sidecar.node_path, "<bundled>");
        assert!(c.sidecar.auto_restart);
        assert_eq!(c.sidecar.max_restart_per_hour, 3);
        assert!(c.privacy.default_sha);
        assert_eq!(c.adapter.emit_mode, "channel");
        assert_eq!(c.adapter.backpressure, "block");
        assert_eq!(c.adapter.archive_retention_hours, 24);
        assert_eq!(c.observability.log_level, "info");
        assert!(!c.observability.metrics_enabled);
        assert!(c.custom.is_empty());
    }

    #[test]
    fn partial_override_keeps_other_defaults() {
        let c = Config::load_from_str("[storage]\nmax_cache_size_gb = 20\n").unwrap();
        assert_eq!(c.storage.max_cache_size_gb, 20);
        assert_eq!(c.storage.data_dir, r"%LOCALAPPDATA%\msgvestige\data");
        assert!(c.sidecar.auto_restart);
    }

    #[test]
    fn custom_section_tolerated_and_captured() {
        let c = Config::load_from_str("[custom_lab]\nexperimental_x = true\nn = 42\n").unwrap();
        assert!(c.custom.contains_key("custom_lab"));
        assert_eq!(c.storage.max_cache_size_gb, 10);
    }

    #[test]
    fn unknown_field_in_known_section_ignored() {
        let c = Config::load_from_str("[storage]\nmax_cache_size_gb = 5\nfuture_field = \"x\"\n").unwrap();
        assert_eq!(c.storage.max_cache_size_gb, 5);
    }

    #[test]
    fn wrong_type_known_field_errors() {
        assert!(Config::load_from_str("[storage]\nmax_cache_size_gb = \"ten\"\n").is_err());
    }

    #[test]
    fn cli_debug_redacts_sensitive() {
        let c = Config::load_from_str(
            "[cli]\ndefault_account_wxid = \"wxid_secret_001\"\nauth_password = \"dpapi:c2VjcmV0\"\n",
        )
        .unwrap();
        let dbg = format!("{:?}", c.cli);
        assert!(!dbg.contains("wxid_secret_001"));
        assert!(!dbg.contains("dpapi:c2VjcmV0"));
        assert!(!dbg.contains("c2VjcmV0"));
        assert!(dbg.contains("default_account_wxid_sha8"));
        assert!(dbg.contains("<redacted>"));
        assert!(!format!("{c:?}").contains("wxid_secret_001"));
    }

    // ── PR2-4-e: validator 校验 ──

    /// 默认 config 校验通过 (alpha 默认值全合规).
    #[test]
    fn default_config_validates_ok() {
        assert!(Config::default().validate_config().is_ok());
        assert!(Config::load_from_str("").unwrap().validate_config().is_ok());
    }

    /// range 越界 → ValidationFailed + 字段名 + 建议.
    #[test]
    fn out_of_range_rejected() {
        let c = Config::load_from_str("[storage]\nmax_cache_size_gb = 2000\n").unwrap();
        let err = c.validate_config().unwrap_err();
        match err {
            ConfigError::ValidationFailed { field, suggestion, .. } => {
                assert!(
                    field.ends_with("max_cache_size_gb"),
                    "字段路径含 max_cache_size_gb: {field}"
                );
                assert!(suggestion.contains("1..=1024"), "建议: {suggestion}");
            }
            other => panic!("应是 ValidationFailed, 实际 {other:?}"),
        }
        // 其它 range
        assert!(Config::load_from_str("[sidecar]\nmax_restart_per_hour = 99\n")
            .unwrap()
            .validate_config()
            .is_err());
        assert!(Config::load_from_str("[privacy]\nlog_plaintext_window_minutes = 120\n")
            .unwrap()
            .validate_config()
            .is_err());
        assert!(Config::load_from_str("[adapter]\narchive_retention_hours = 9999\n")
            .unwrap()
            .validate_config()
            .is_err());
    }

    /// enum 非法值 → 拒绝 (emit_mode / backpressure / log_level).
    #[test]
    fn invalid_enum_rejected() {
        assert!(Config::load_from_str("[adapter]\nemit_mode = \"ftp\"\n")
            .unwrap()
            .validate_config()
            .is_err());
        assert!(Config::load_from_str("[adapter]\nbackpressure = \"explode\"\n")
            .unwrap()
            .validate_config()
            .is_err());
        assert!(Config::load_from_str("[observability]\nlog_level = \"verbose\"\n")
            .unwrap()
            .validate_config()
            .is_err());
        // 合法枚举值通过
        assert!(Config::load_from_str("[adapter]\nemit_mode = \"jsonl\"\n")
            .unwrap()
            .validate_config()
            .is_ok());
    }

    /// §3.6 反例 X 红线: metrics_enabled = true → 拒绝.
    #[test]
    fn metrics_enabled_true_rejected() {
        let c = Config::load_from_str("[observability]\nmetrics_enabled = true\n").unwrap();
        let err = c.validate_config().unwrap_err();
        match err {
            ConfigError::ValidationFailed { field, suggestion, .. } => {
                assert!(field.ends_with("metrics_enabled"));
                assert!(suggestion.contains("false"));
            }
            other => panic!("应 ValidationFailed, 实 {other:?}"),
        }
    }

    /// account_wxid 校验 (PR2-12-d-pre 放宽): 空 = 当前账号 / 合法微信 UserName (wxid_/自定义/gh_/
    /// @chatroom 均过, 跟 Wxid::try_new 一致) / 真垃圾 (空白/超长) 拒.
    #[test]
    fn account_wxid_format_validated() {
        let ok = |v: &str| {
            Config::load_from_str(&format!("[cli]\ndefault_account_wxid = \"{v}\"\n"))
                .unwrap()
                .validate_config()
                .is_ok()
        };
        assert!(ok(""), "空 = 当前账号");
        assert!(ok("wxid_abc"), "wxid_ 系统号");
        assert!(ok("custom_no_prefix"), "自定义号 (真实数据 ~9%, 旧版误拒)");
        assert!(ok("gh_official"), "公众号也是合法 UserName");
        assert!(ok("abc123@chatroom"), "@chatroom");
        // 真垃圾仍拒 (跟 Wxid::try_new 一致)
        assert!(!ok("has space"), "含空格拒");
        assert!(!ok(&"a".repeat(129)), "超长 >128 拒");
    }

    /// load_config: 不存在路径 → FileNotFound.
    #[test]
    fn load_config_missing_file() {
        let err = load_config(Path::new("Z:/nonexistent/msgvestige/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::FileNotFound(_)));
    }

    /// load_config: 真文件 file→parse→validate 全通.
    #[test]
    fn load_config_from_file_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[storage]\nmax_cache_size_gb = 50\n").unwrap();
        let c = load_config(&path).unwrap();
        assert_eq!(c.storage.max_cache_size_gb, 50);
    }

    /// load_config: 真文件但字段越界 → ValidationFailed (parse 过但 validate 拦).
    #[test]
    fn load_config_validation_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[observability]\nmetrics_enabled = true\n").unwrap();
        assert!(matches!(
            load_config(&path).unwrap_err(),
            ConfigError::ValidationFailed { .. }
        ));
    }

    // ── PR2-4-f: semver 版本兼容 ──

    /// 同 major 兼容 (0.x 内 minor/patch 差异 OK, §3.3).
    #[test]
    fn version_same_major_compatible() {
        assert!(check_version_compat("0.1.0", "0.1.0").is_ok());
        assert!(check_version_compat("0.2.0", "0.1.0").is_ok(), "minor 升级兼容");
        assert!(check_version_compat("0.1.5", "0.1.0").is_ok(), "patch 升级兼容");
        // 默认 config 版本跟 cli 期望一致
        assert!(check_version_compat(&ConfigMeta::default().version, EXPECTED_CONFIG_VERSION).is_ok());
    }

    /// 不同 major → VersionIncompatible (§3.3 major 升级不兼容).
    #[test]
    fn version_different_major_incompatible() {
        match check_version_compat("1.0.0", "0.1.0").unwrap_err() {
            ConfigError::VersionIncompatible { actual, expected } => {
                assert_eq!(actual, "1.0.0");
                assert_eq!(expected, "0.1.0");
            }
            other => panic!("应 VersionIncompatible, 实 {other:?}"),
        }
    }

    /// 不可解析版本 → VersionIncompatible (保守拒).
    #[test]
    fn version_unparseable_incompatible() {
        assert!(matches!(
            check_version_compat("abc", "0.1.0").unwrap_err(),
            ConfigError::VersionIncompatible { .. }
        ));
        assert!(matches!(
            check_version_compat("0.1.0", "xyz").unwrap_err(),
            ConfigError::VersionIncompatible { .. }
        ));
    }

    /// load_config: 文件 version major 不兼容 → VersionIncompatible (validate 之前拦).
    #[test]
    fn load_config_version_incompatible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[config_meta]\nversion = \"1.0.0\"\n").unwrap();
        assert!(matches!(
            load_config(&path).unwrap_err(),
            ConfigError::VersionIncompatible { .. }
        ));
    }

    /// load_config: 兼容 minor 版本 (0.2.0) 正常加载.
    #[test]
    fn load_config_compatible_minor_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[config_meta]\nversion = \"0.2.0\"\n[storage]\nmax_cache_size_gb = 7\n",
        )
        .unwrap();
        let c = load_config(&path).unwrap();
        assert_eq!(c.storage.max_cache_size_gb, 7);
    }
}
