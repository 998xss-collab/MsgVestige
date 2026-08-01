//! KeyError — KeyProvider 错误枚举 (ADR-405 §3.1 钉死 8 变体 + r3 加 HookTimeout = 9 变体).
//!
//! 跟 PoC-1 v3-key-source 的 KeySourceError 15 变体的差异:
//!   - alpha 收敛: 把 PoC-1 15 个 implementation-specific 错误合并成 8 个 contract-level 错误
//!   - From<KeySourceError> 的桥接 impl 等 PR2-1-b 拷 cache.rs / ciphertalk.rs 时再加
//!
//! 跟 ADR-410 MATRIX §2 行号链接 (r2 codex 拉真实表号校正):
//!   - NotFound             → #9   (多账号其一 key 失效, 含 NotFound + cipher DecryptFailed 合并行)
//!   - AlgorithmMismatch    → #11  (微信升级换 key 派生算法 4.0.x → 4.1.x)
//!   - WxidMismatch         → #13  (跨账号 key 串扰, 主号 key 错装到副号槽)
//!   - DpapiUnavailable     → #3   (DPAPI 拿不到 key, 换机器/重装系统/密钥被清除)
//!   - DpapiLocked          → #17  (DPAPI master key 锁定, Windows 账号密码改/域变更)
//!
//! 取消语义设计 (r4 整理 — 单一入口):
//!   - **alpha 决策**: 取消信号 (Ctrl-C / 用户主动退出) 不进 KeyError 表面.
//!     走 `tokio::signal::ctrl_c` + `tokio_util::sync::CancellationToken` (out-of-band).
//!   - **r4 KI-405-CANCEL** (推 ADR-405 r3 + PR2-1-c 实施):
//!     原 PoC-1 KeySourceError::UserCancelled 变体被 alpha 收敛掉, 改走 CancellationToken.
//!     ChainedKeyProvider 实施时 (PR2-1-c) trait 方法签名是否补 `&CancellationToken` 参数,
//!     由 ADR-405 r3 拍板. 当前 PR2-1-a 骨架不动 trait 签名.
//!   - **ConsentDenied ≠ 取消** (注释行边界): 本变体专指"hook 提示中用户点拒绝",
//!     不是按 Ctrl-C 退出. 防 PoC-1 NH-3 (chain 把 Err 全当 miss → cli 静悄悄盖 Ctrl-C) 复发,
//!     alpha 用 in-band Error + out-of-band Cancel 分离.

use thiserror::Error;

use crate::key_provider::{sha8, Wxid};

/// KeyProvider 错误 — ADR-405 §3.1 钉死 8 变体 + r3 加 HookTimeout (KI-405-NOTFOUND 闭) = 9 变体.
///
/// # r3+r4 K-R4 强制脱敏契约
/// 含 wxid / wechat_version / 任意可能含明文标识的 String 字段, **不允许直接 struct 构造**.
/// 必须走工厂方法 (`KeyError::wxid_mismatch` / `KeyError::dpapi_unavailable` /
/// `KeyError::algorithm_mismatch` / `KeyError::io_sanitized`) — 工厂内部强制 sha8 化 / 路径剥离.
/// 直接 struct 构造仍然能编译 (alpha pub field), 但属 contract violation, 双审 r3 抓出来即 P0.
/// 0.2.0+ 升级 ADR-405 r3 → 字段类型改 `Sha8` newtype, 编译期强制.
///
/// # r4 Debug 手写脱敏
/// `#[derive(Debug)]` 会递归 Debug 每个字段, 让 `{err:?}` 暴露 NotFound 的 Wxid 内部 String + Io 的
/// io::Error 全文案 (含路径含 wxid). r4 手写 `impl Debug` 对每个变体的敏感字段 sha8 化, 防泄.
///
/// # r4 Io 变体丢 source
/// `#[source] io::Error` 让 `err.source().to_string()` 仍能拿到 io::Error.to_string() (含路径含 wxid),
/// 绕开 Display 的脱敏. r4 把 Io 变体改成 `Io { kind }` 单字段, 丢弃原 io::Error 实例.
/// 代价: 丢失 errno / OS-level 细节. alpha K-R4 优先 > 调试细节.
#[derive(Error)]
pub enum KeyError {
    /// 链上无 source 能给该 wxid 的 key (chain miss).
    #[error("KeyProvider: 未找到 wxid 对应 key (wxid_sha8={})", sha8(wxid.as_str().as_bytes()))]
    NotFound { wxid: Wxid },

    /// 用户在 hook 提示中点"拒绝" (recoverable, chain 继续 cli 兜底).
    #[error("KeyProvider: 用户未同意 key 取源 (hook 提示被拒)")]
    ConsentDenied,

    /// ciphertalk hook 轮询超时 (等了 secs 秒微信仍未触发 setKey, 未捕获 key).
    ///
    /// ADR-405 r3 (KI-405-NOTFOUND): 原 PoC-1 HookTimeout 变体被 alpha 收敛掉, PR2-1-c
    /// 临时借 `dpapi_unavailable(b"hook_timeout")` 上报 — 语义错位 (不是 DPAPI 故障).
    /// r3 恢复专用变体 (8→9), 携带 secs + 微信最后状态供用户/上层诊断.
    ///
    /// **terminal** (is_recoverable_miss=false): 超时 = 真出问题, 不让 cli 静悄悄兜底盖掉 (NH-3).
    ///
    /// # K-R4: `last_status` 来自 dll 状态消息, 调用方 (ciphertalk drain_status_messages) 必须
    /// 已过 `mask_hex_in_log` 脱敏才传入 — 本字段非 wxid/key 但兜底防 dll 误吐 hex.
    #[error("KeyProvider: hook 超时 ({secs}s 未捕获 key, 微信最后状态={last_status:?})")]
    HookTimeout { secs: u64, last_status: Option<String> },

    /// 该 source 不支持该操作 (e.g. ciphertalk 不能 resolve_all).
    #[error("KeyProvider: {name} 不支持 {op}")]
    Unsupported { name: &'static str, op: &'static str },

    /// DPAPI 不可用 — cache 加密/解密失败或 wx_key.dll 加载失败.
    /// 调用方走 `KeyError::dpapi_unavailable(wxid)` 工厂构造, 内部 sha8 化.
    #[error("KeyProvider: DPAPI 不可用 (wxid sha8={wxid})")]
    DpapiUnavailable { wxid: String },

    /// wx 版本跟硬编码 KeyClass / cipher 算法不匹配.
    /// 调用方走 `KeyError::algorithm_mismatch(ver)` 工厂.
    #[error("KeyProvider: wx 版本 {wechat_version} 跟 KeyClass / cipher 算法不匹配")]
    AlgorithmMismatch { wechat_version: String },

    /// 用户输入的 wxid 跟实际进程的 wxid 不一致 (防跨账号串扰).
    /// 调用方走 `KeyError::wxid_mismatch(expected, actual)` 工厂, 内部 sha8 化.
    #[error("KeyProvider: wxid 不匹配 (期望 sha8={expected}, 实际 sha8={actual})")]
    WxidMismatch { expected: String, actual: String },

    /// DPAPI 调用被锁 (windows error code).
    #[error("KeyProvider: DPAPI 被锁 (error_code=0x{error_code:08x})")]
    DpapiLocked { error_code: u32 },

    /// 底层 IO 错误 — r4: 丢 io::Error 实例, 只留 ErrorKind 分类.
    /// 走 `KeyError::io_sanitized(io_err)` 工厂或 `From<io::Error>`.
    #[error("KeyProvider: IO 错误 (kind={kind:?})")]
    Io { kind: std::io::ErrorKind },
}

impl From<std::io::Error> for KeyError {
    fn from(e: std::io::Error) -> Self {
        // r4: 只取 kind, 丢 io::Error 实例本身防 source() / Debug 泄路径.
        Self::Io { kind: e.kind() }
    }
}

// r4 P0: 手写 Debug — 对所有敏感字段 sha8 化, 防 #[derive(Debug)] 自动暴露明文.
impl std::fmt::Debug for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { wxid } => f
                .debug_struct("KeyError::NotFound")
                .field("wxid_sha8", &sha8(wxid.as_str().as_bytes()))
                .finish(),
            Self::ConsentDenied => f.write_str("KeyError::ConsentDenied"),
            Self::HookTimeout { secs, last_status } => f
                .debug_struct("KeyError::HookTimeout")
                .field("secs", secs)
                .field("last_status", last_status)
                .finish(),
            Self::Unsupported { name, op } => f
                .debug_struct("KeyError::Unsupported")
                .field("name", name)
                .field("op", op)
                .finish(),
            Self::DpapiUnavailable { wxid } => f
                .debug_struct("KeyError::DpapiUnavailable")
                .field("wxid_sha8", &sha8(wxid.as_bytes()))
                .finish(),
            Self::AlgorithmMismatch { wechat_version } => f
                .debug_struct("KeyError::AlgorithmMismatch")
                .field("wechat_version", wechat_version)
                .finish(),
            Self::WxidMismatch { expected, actual } => f
                .debug_struct("KeyError::WxidMismatch")
                .field("expected_sha8", &sha8(expected.as_bytes()))
                .field("actual_sha8", &sha8(actual.as_bytes()))
                .finish(),
            Self::DpapiLocked { error_code } => f
                .debug_struct("KeyError::DpapiLocked")
                .field("error_code", &format_args!("{error_code:#x}"))
                .finish(),
            Self::Io { kind } => f.debug_struct("KeyError::Io").field("kind", kind).finish(),
        }
    }
}

// r3 工厂方法 — 强制 sha8 脱敏 (K-R4 入口侧).
impl KeyError {
    /// 构造 WxidMismatch — 内部 sha8 化两个字段, 防调用方传明文.
    #[must_use]
    pub fn wxid_mismatch(expected: impl AsRef<[u8]>, actual: impl AsRef<[u8]>) -> Self {
        Self::WxidMismatch {
            expected: sha8(expected.as_ref()),
            actual: sha8(actual.as_ref()),
        }
    }

    /// 构造 DpapiUnavailable — 内部 sha8 化 wxid 字段.
    #[must_use]
    pub fn dpapi_unavailable(wxid: impl AsRef<[u8]>) -> Self {
        Self::DpapiUnavailable {
            wxid: sha8(wxid.as_ref()),
        }
    }

    /// 构造 AlgorithmMismatch — 包裹版本字符串.
    ///
    /// # 输入约定 (r6 doc 加)
    /// `wechat_version` 设计约定为 ASCII 版本号 (如 "4.0.3.99"). truncate `chars().take(32)`
    /// 按字符截断: 纯 ASCII 时上限 32 bytes, UTF-8 多字节字符时可能 ≤ 96 bytes (3 byte / char).
    /// alpha 假设调用方传 ASCII; 0.2.0+ 改类型 `WechatVersion(ArrayString<32>)` 编译期强制.
    #[must_use]
    pub fn algorithm_mismatch(wechat_version: impl Into<String>) -> Self {
        let v = wechat_version.into();
        Self::AlgorithmMismatch {
            wechat_version: v.chars().take(32).collect(),
        }
    }

    /// 构造 Io — `From<io::Error>` 已经做, 这里是显式入口供测试 / 调用方主动构造.
    #[must_use]
    pub fn io_sanitized(io_err: std::io::Error) -> Self {
        Self::from(io_err)
    }
}

impl KeyError {
    /// 是否是"可恢复 miss" — chain 应继续尝试下一个 source.
    ///
    /// 跟 PoC-1 KeySourceError::is_recoverable_miss 同语义, 收敛后变体减少:
    ///   - NotFound       → true  (cache miss / cli 未提供, 应 fallthrough)
    ///   - Unsupported    → true  (该 source 不支持该 op, fallthrough)
    ///   - ConsentDenied  → true  (用户拒绝本 source / 命令行 key 仍可兜底, ADR-405 r3 FD2=继续)
    ///   - 其他 (HookTimeout / DpapiUnavailable / AlgorithmMismatch / WxidMismatch /
    ///           DpapiLocked / Io) → false (terminal, 中止 chain)
    ///
    /// ADR-405 r3: HookTimeout terminal — 超时不让 cli 静悄悄盖掉 (NH-3 红线).
    ///
    /// 设计动机 (postmortem NH-3): 早期 chain 把所有 Err 当 miss → cli 静悄悄盖掉
    /// 真正的故障, 用户看不到 root cause. terminal error 立刻 break.
    pub fn is_recoverable_miss(&self) -> bool {
        matches!(
            self,
            KeyError::NotFound { .. } | KeyError::Unsupported { .. } | KeyError::ConsentDenied
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recoverable_miss_classification() {
        assert!(KeyError::NotFound {
            wxid: Wxid::new("wxid_demo")
        }
        .is_recoverable_miss());
        assert!(KeyError::Unsupported {
            name: "ciphertalk",
            op: "resolve_all"
        }
        .is_recoverable_miss());
        assert!(KeyError::ConsentDenied.is_recoverable_miss());

        assert!(!KeyError::DpapiUnavailable { wxid: "abcd".into() }.is_recoverable_miss());
        assert!(!KeyError::AlgorithmMismatch {
            wechat_version: "4.0.3.x".into()
        }
        .is_recoverable_miss());
        assert!(!KeyError::wxid_mismatch(b"abcd", b"ef01").is_recoverable_miss());
        assert!(!KeyError::DpapiLocked {
            error_code: 0x8009_0005
        }
        .is_recoverable_miss());
    }

    #[test]
    fn display_no_plaintext_wxid_in_not_found() {
        // K-R4: NotFound 文案绝不暴露明文 wxid (用 sha8 脱敏)
        let err = KeyError::NotFound {
            wxid: Wxid::new("wxid_super_secret_abc"),
        };
        let msg = format!("{err}");
        assert!(!msg.contains("wxid_super_secret_abc"));
        assert!(msg.contains("wxid_sha8="));
    }

    /// PR2-1-a r2 P0 — 遍历全部变体的 Display 输出, 验证 K-R4 脱敏全覆盖.
    /// r1 漏测 7/8 变体, codex 抓 contract level, Claude 抓 K-R4 红线. ADR-405 r3: 加 HookTimeout (9 变体).
    #[test]
    fn display_all_9_variants_no_plaintext_leak() {
        let secret_wxid = "wxid_real_user_42";
        let secret_hex64 = "deadbeef".repeat(8); // 64 char hex 模拟 master key 字面
        let suspicious_substrings = [secret_wxid, &secret_hex64, "wxid_real_user"];

        let variants = [
            KeyError::NotFound {
                wxid: Wxid::new(secret_wxid),
            },
            KeyError::ConsentDenied,
            // ADR-405 r3: HookTimeout — last_status 是非敏感 dll 状态 (调用方已 mask), 验它不含 wxid/key
            KeyError::HookTimeout {
                secs: 180,
                last_status: Some("等待 setKey 调用".to_string()),
            },
            KeyError::Unsupported {
                name: "ciphertalk",
                op: "resolve_all",
            },
            // r3: 全部走工厂方法 — 即便传明文也保证脱敏
            KeyError::dpapi_unavailable(secret_wxid.as_bytes()),
            KeyError::algorithm_mismatch("4.0.3.99"),
            KeyError::wxid_mismatch(secret_wxid.as_bytes(), b"wxid_other_user"),
            KeyError::DpapiLocked {
                error_code: 0x8009_0005,
            },
            // r3+r4: Io 走 From, r4 只留 kind 字段防 source() 泄露路径
            KeyError::from(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("failed to open cache: /Users/x/.config/{secret_wxid}.db"),
            )),
        ];

        // r4: Debug 也要测 — Display 单测在上面循环里覆了, Debug 单独循环
        for (i, err) in variants.iter().enumerate() {
            let dbg = format!("{err:?}");
            for needle in &suspicious_substrings {
                assert!(!dbg.contains(needle), "variant #{i} Debug 泄露明文 {needle:?}: {dbg}");
            }
        }

        for (i, err) in variants.iter().enumerate() {
            let msg = format!("{err}");
            for needle in &suspicious_substrings {
                assert!(!msg.contains(needle), "variant #{i} Display 泄露明文 {needle:?}: {msg}");
            }
        }
    }

    /// r3 P0 修: 工厂方法强制 sha8 — 即便 caller 把明文 wxid 当字节传, Display 也不会泄露.
    #[test]
    fn wxid_mismatch_factory_forces_sha8() {
        let plaintext_a = "wxid_real_user_aaa";
        let plaintext_b = "wxid_real_user_bbb";
        let err = KeyError::wxid_mismatch(plaintext_a.as_bytes(), plaintext_b.as_bytes());
        let msg = format!("{err}");
        assert!(!msg.contains(plaintext_a));
        assert!(!msg.contains(plaintext_b));
        // 应该含 sha8 前缀, 8 char hex 标记
        assert!(msg.contains("sha8="));
    }

    /// r3 P0 修: DpapiUnavailable 工厂同上.
    #[test]
    fn dpapi_unavailable_factory_forces_sha8() {
        let plaintext = "wxid_real_dpapi_owner";
        let err = KeyError::dpapi_unavailable(plaintext.as_bytes());
        let msg = format!("{err}");
        assert!(!msg.contains(plaintext));
        assert!(msg.contains("sha8="));
    }

    /// r3 P0 修: From<io::Error> 不暴露 io::Error.to_string() (含路径含 wxid).
    #[test]
    fn io_from_does_not_expose_path_or_wxid() {
        let secret_path = "/Users/john/.config/wxid_secret_user/cache.db";
        let io_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("permission denied opening {secret_path}"),
        );
        let err = KeyError::from(io_err);
        let msg = format!("{err}");
        assert!(!msg.contains("wxid_secret_user"));
        assert!(!msg.contains("/Users/john"));
        assert!(!msg.contains(".config"));
        // 只露 ErrorKind
        assert!(msg.contains("PermissionDenied"));
    }

    /// r3 P0 修: ConsentDenied Display + doc 不再混"主动取消" 字眼.
    #[test]
    fn consent_denied_msg_excludes_cancel_wording() {
        let msg = format!("{}", KeyError::ConsentDenied);
        // 主动取消 / Ctrl-C / abort 都不该出现 (走 CancellationToken out-of-band)
        assert!(!msg.contains("主动取消"));
        assert!(!msg.contains("Ctrl"));
        assert!(!msg.contains("abort"));
        assert!(msg.contains("hook 提示被拒"));
    }

    /// r4 P0 修: source() trait 不再暴露 io::Error.to_string() — Io 变体只留 kind 字段.
    #[test]
    fn io_source_does_not_leak_path() {
        use std::error::Error as StdError;
        let secret_path = "/Users/john/.config/wxid_secret/cache.db";
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("denied {secret_path}"));
        let key_err = KeyError::from(io_err);
        // source() 必须返 None (r4 丢了 io::Error 实例)
        assert!(key_err.source().is_none(), "Io::source() 必须 None 防泄路径");
        // Debug 也不能含 path
        let dbg = format!("{key_err:?}");
        assert!(!dbg.contains("wxid_secret"));
        assert!(!dbg.contains("/Users"));
    }

    /// r4 P0 修: NotFound 的 Debug 输出经 sha8 化, 不暴露明文 wxid.
    #[test]
    fn debug_not_found_uses_sha8() {
        let secret = "wxid_real_secret_user_xyz";
        let err = KeyError::NotFound {
            wxid: Wxid::new(secret),
        };
        let dbg = format!("{err:?}");
        assert!(!dbg.contains(secret), "Debug 泄露明文 wxid: {dbg}");
        assert!(dbg.contains("wxid_sha8"), "Debug 应含 wxid_sha8 字段: {dbg}");
    }

    /// r5 P1 修: AlgorithmMismatch Debug 输出含 wechat_version, 验 truncate(32) 防长字串.
    /// wechat_version 设计上不含 wxid, 但 r5 加显式单测兜底.
    #[test]
    fn debug_algorithm_mismatch_truncates_long_strings() {
        // 故意传 100 char 长字串 (设计假设这不会发生, 但兜底)
        let long = "x".repeat(100);
        let err = KeyError::algorithm_mismatch(&long);
        let msg = format!("{err}");
        // 工厂方法 take(32) 截断 — 完整 100 个 x 不应该完整出现
        assert!(!msg.contains(&long), "AlgorithmMismatch 不截断长字串: {msg}");
        let dbg = format!("{err:?}");
        assert!(!dbg.contains(&long));
        assert!(dbg.contains("KeyError::AlgorithmMismatch"));
    }

    /// r6 P1 修: 一锅测全部变体 Debug 格式正确性 (类型名 + 字段标签).
    /// 跟 display_all_9_variants_no_plaintext_leak 互补 — 前者验泄露, 本测验格式. ADR-405 r3: +HookTimeout.
    #[test]
    fn debug_all_9_variants_format_correct() {
        let cases: Vec<(KeyError, &str, &str)> = vec![
            (
                KeyError::NotFound {
                    wxid: Wxid::new("wxid_x"),
                },
                "KeyError::NotFound",
                "wxid_sha8",
            ),
            (KeyError::ConsentDenied, "KeyError::ConsentDenied", ""),
            (
                KeyError::HookTimeout {
                    secs: 180,
                    last_status: None,
                },
                "KeyError::HookTimeout",
                "secs",
            ),
            (
                KeyError::Unsupported {
                    name: "ciphertalk",
                    op: "resolve_all",
                },
                "KeyError::Unsupported",
                "name",
            ),
            (
                KeyError::dpapi_unavailable(b"wxid_y"),
                "KeyError::DpapiUnavailable",
                "wxid_sha8",
            ),
            (
                KeyError::algorithm_mismatch("4.0.3.99"),
                "KeyError::AlgorithmMismatch",
                "wechat_version",
            ),
            (
                KeyError::wxid_mismatch(b"a", b"b"),
                "KeyError::WxidMismatch",
                "expected_sha8",
            ),
            (
                KeyError::DpapiLocked {
                    error_code: 0x8009_0005,
                },
                "KeyError::DpapiLocked",
                "error_code",
            ),
            (
                KeyError::from(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "x")),
                "KeyError::Io",
                "kind",
            ),
        ];
        for (i, (err, type_marker, field_marker)) in cases.iter().enumerate() {
            let dbg = format!("{err:?}");
            assert!(dbg.contains(type_marker), "case #{i}: {dbg} 不含类型标记 {type_marker}");
            if !field_marker.is_empty() {
                assert!(
                    dbg.contains(field_marker),
                    "case #{i}: {dbg} 不含字段标记 {field_marker}"
                );
            }
        }
    }

    /// r5 P1 修: DpapiLocked Debug 含 error_code (u32, 非敏感), 验格式正确.
    #[test]
    fn debug_dpapi_locked_shows_error_code_only() {
        let err = KeyError::DpapiLocked {
            error_code: 0x8009_0005,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("KeyError::DpapiLocked"));
        assert!(dbg.contains("0x"), "Debug 应含 hex 前缀: {dbg}");
        // 不应含任何 wxid 明文 (DpapiLocked 没 wxid 字段)
        assert!(!dbg.contains("wxid"));
    }
}
