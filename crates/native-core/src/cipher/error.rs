//! CipherError — Cipher trait 错误枚举 (跟 ADR-405 §3.3 + cipher-加密.md §3 + MATRIX §2 一致, 7 变体).
//!
//! 失败矩阵映射 (MATRIX-恢复矩阵.md §2):
//!   - SidecarStartFail   → #1  (sidecar 启动失败)
//!   - SidecarCrashed     → #2  (sidecar 中途崩溃, auto-restart ≤3)
//!   - SidecarTimeout     → #16 (sidecar 卡死不响应)
//!   - SidecarUnreachable → #1  (sidecar 进程挂了)
//!   - HmacVerifyFail     → #5  (db header / HMAC 校验失败 = key 错)
//!   - DecryptFailed      → #5/#9 (解密失败)
//!   - Io                 → 不进 MATRIX (cipher 内部 IO 兜底)
//!
//! # K-R4 强制脱敏契约 (r2 双审 P0: 出口侧脱敏, 比 KeyError factory-侧更 robust)
//! `DecryptFailed.wxid` / `db_file` 是敏感 (db_file 文件名可能含 wxid 如 message_<wxid>.db).
//! 脱敏在 **Display + 手写 Debug 出口侧** sha8 (in-formatter) — 即便外部安全 Rust 一行直接
//! struct 构造 `DecryptFailed { wxid: "明文", .. }` 绕过 `decrypt_failed` 工厂, 任何输出路径仍 sha8,
//! 不泄明文. 对齐 KeyError::NotFound (宏内 sha8) 的鲁棒出口脱敏; 强于 KeyError::DpapiUnavailable
//! (factory 预脱敏 + Display 裸字段, 直接构造可绕 — 推 0.2.0+ 跟本款统一或上 Sha8 newtype).
//! 工厂 `decrypt_failed` 仅负责 db_file 从 Path 剥 basename (去目录), 不再承担脱敏.

use thiserror::Error;

use crate::key_provider::sha8;

/// Cipher 错误 — ADR-405 §3.3 钉死 7 变体.
#[derive(Error)]
pub enum CipherError {
    /// sidecar 启动失败 (MATRIX §2 #1). `reason` 是 sidecar 进程级诊断 (非用户数据).
    #[error("Cipher: sidecar 启动失败 ({reason})")]
    SidecarStartFail { reason: String },

    /// sidecar 中途崩溃, auto-restart 计数 (MATRIX §2 #2).
    #[error("Cipher: sidecar 崩溃 (auto-restart {restart_count}/3)")]
    SidecarCrashed { restart_count: u32 },

    /// sidecar 卡死不响应超时 (MATRIX §2 #16).
    #[error("Cipher: sidecar 超时 ({0:?})")]
    SidecarTimeout(std::time::Duration),

    /// sidecar 进程不可达 (MATRIX §2 #1).
    #[error("Cipher: sidecar 不可达")]
    SidecarUnreachable,

    /// db header / HMAC 校验失败 = key 错 (MATRIX §2 #5).
    #[error("Cipher: HMAC 校验失败 (key 错或 db 损坏)")]
    HmacVerifyFail,

    /// 解密失败 (MATRIX §2 #5/#9).
    ///
    /// r2 (双审 P0): 脱敏在 **Display/Debug 出口侧** sha8 (in-formatter), 不靠工厂预脱敏 —
    /// 即便外部安全 Rust 直接 struct 构造 `DecryptFailed { wxid: "明文", .. }` 绕过工厂,
    /// 任何输出路径 (Display / Debug) 仍 sha8, 不泄明文 (对齐 KeyError::NotFound 出口脱敏).
    /// 字段存原始值; 工厂 `decrypt_failed` 仅负责 db_file 从 Path 剥 basename (去目录).
    #[error("Cipher: 解密失败 (wxid_sha8={}, db_file={:?})", sha8(wxid.as_bytes()), db_file.as_deref().map(|f| sha8(f.as_bytes())))]
    DecryptFailed { wxid: String, db_file: Option<String> },

    /// 底层 IO 错误 — 跟 KeyError::Io 同款只留 ErrorKind 防 source() / Debug 泄路径.
    #[error("Cipher: IO 错误 (kind={kind:?})")]
    Io { kind: std::io::ErrorKind },
}

impl From<std::io::Error> for CipherError {
    fn from(e: std::io::Error) -> Self {
        // 只取 kind, 丢 io::Error 实例防 source() / Debug 泄路径 (跟 KeyError::Io 同款).
        Self::Io { kind: e.kind() }
    }
}

// K-R4 手写 Debug — 对 wxid / db_file sha8 化, 防 #[derive(Debug)] 暴露明文.
impl std::fmt::Debug for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SidecarStartFail { reason } => f
                .debug_struct("CipherError::SidecarStartFail")
                .field("reason", reason)
                .finish(),
            Self::SidecarCrashed { restart_count } => f
                .debug_struct("CipherError::SidecarCrashed")
                .field("restart_count", restart_count)
                .finish(),
            Self::SidecarTimeout(d) => f.debug_tuple("CipherError::SidecarTimeout").field(d).finish(),
            Self::SidecarUnreachable => f.write_str("CipherError::SidecarUnreachable"),
            Self::HmacVerifyFail => f.write_str("CipherError::HmacVerifyFail"),
            Self::DecryptFailed { wxid, db_file } => f
                .debug_struct("CipherError::DecryptFailed")
                .field("wxid_sha8", &sha8(wxid.as_bytes()))
                // r2 P0: db_file 也 sha8 (原 .field(db_file) 裸传, 直接构造时泄含 wxid 文件名)
                .field("db_file_sha8", &db_file.as_deref().map(|f| sha8(f.as_bytes())))
                .finish(),
            Self::Io { kind } => f.debug_struct("CipherError::Io").field("kind", kind).finish(),
        }
    }
}

impl CipherError {
    /// 构造 DecryptFailed — 存原始值, 脱敏在 Display/Debug 出口侧 (sha8 in-formatter).
    ///
    /// r2 (双审 P0): 脱敏从工厂移到出口侧 → 即便外部直接 struct 构造绕过本工厂, Display/Debug
    /// 仍 sha8 不泄 (跟 KeyError::NotFound 同款 robust). 本工厂职责仅: db_file 从 Path 剥 basename
    /// (去目录防泄绝对路径); basename 可能含 wxid (message_<wxid>.db), 由 Display/Debug sha8 兜底.
    #[must_use]
    pub fn decrypt_failed(wxid: impl AsRef<[u8]>, db_file: Option<&std::path::Path>) -> Self {
        let db_file = db_file.map(|p| {
            p.file_name()
                .map_or_else(|| "<no-name>".to_string(), |n| n.to_string_lossy().into_owned())
        });
        Self::DecryptFailed {
            wxid: String::from_utf8_lossy(wxid.as_ref()).into_owned(),
            db_file,
        }
    }

    /// 构造 SidecarStartFail — reason 是 sidecar 进程诊断 (非用户数据, 不脱敏).
    #[must_use]
    pub fn sidecar_start_fail(reason: impl Into<String>) -> Self {
        Self::SidecarStartFail { reason: reason.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// K-R4: DecryptFailed 工厂 — 传明文 wxid + 含 wxid 的 db 路径, Display/Debug 不泄.
    #[test]
    fn decrypt_failed_factory_masks_wxid_and_path() {
        let secret_wxid = "wxid_real_user_42";
        let secret_path = std::path::Path::new("C:/Users/john/wx/message_wxid_real_user_42.db");
        let err = CipherError::decrypt_failed(secret_wxid.as_bytes(), Some(secret_path));

        let display = format!("{err}");
        let debug = format!("{err:?}");
        for s in [&display, &debug] {
            assert!(!s.contains(secret_wxid), "泄露明文 wxid: {s}");
            assert!(!s.contains("C:/Users/john"), "泄露绝对路径: {s}");
            assert!(!s.contains("message_wxid"), "泄露含 wxid 文件名: {s}");
        }
        assert!(display.contains("wxid_sha8="), "应含 wxid sha8: {display}");
    }

    /// r2 双审 P0: 直接 struct 构造绕过 decrypt_failed 工厂 — Display/Debug 出口侧 sha8 仍不泄.
    /// 这是 r1 漏网点 (原 Display 插裸字段, 直构泄明文).
    #[test]
    fn decrypt_failed_direct_construction_still_masked() {
        // 故意绕过工厂, 直接塞明文 wxid + 含 wxid 的文件名
        let err = CipherError::DecryptFailed {
            wxid: "wxid_bypass_factory".to_string(),
            db_file: Some("message_wxid_bypass_factory.db".to_string()),
        };
        let display = format!("{err}");
        let debug = format!("{err:?}");
        for s in [&display, &debug] {
            assert!(!s.contains("wxid_bypass_factory"), "直构绕工厂仍泄明文: {s}");
            assert!(!s.contains("message_wxid"), "直构泄含 wxid 文件名: {s}");
        }
        assert!(display.contains("wxid_sha8="), "Display 仍应 sha8: {display}");
    }

    /// DecryptFailed db_file=None 不 panic.
    #[test]
    fn decrypt_failed_no_db_file() {
        let err = CipherError::decrypt_failed(b"wxid_x", None);
        let s = format!("{err}");
        assert!(s.contains("None"));
    }

    /// Io 走 From — 只留 kind, 不泄路径 (跟 KeyError::Io 同款).
    #[test]
    fn io_from_does_not_leak_path() {
        use std::error::Error as _;
        let io_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied C:/Users/john/wx/message_wxid_secret.db",
        );
        let err = CipherError::from(io_err);
        let s = format!("{err}");
        let dbg = format!("{err:?}");
        assert!(!s.contains("wxid_secret") && !dbg.contains("wxid_secret"));
        assert!(!s.contains("C:/Users") && !dbg.contains("C:/Users"));
        assert!(err.source().is_none(), "Io::source() 必须 None 防泄路径");
        assert!(s.contains("PermissionDenied"));
    }

    /// 遍历 7 变体 Display/Debug — 验 K-R4 全覆盖 + 格式正确 (跟 KeyError all_9_variants 同款).
    #[test]
    fn all_7_variants_no_plaintext_leak_and_format() {
        let secret = "wxid_real_user_99";
        let variants: Vec<(CipherError, &str)> = vec![
            (CipherError::sidecar_start_fail("node not found"), "SidecarStartFail"),
            (CipherError::SidecarCrashed { restart_count: 2 }, "SidecarCrashed"),
            (
                CipherError::SidecarTimeout(std::time::Duration::from_secs(30)),
                "SidecarTimeout",
            ),
            (CipherError::SidecarUnreachable, "SidecarUnreachable"),
            (CipherError::HmacVerifyFail, "HmacVerifyFail"),
            (CipherError::decrypt_failed(secret.as_bytes(), None), "DecryptFailed"),
            (
                CipherError::from(std::io::Error::new(std::io::ErrorKind::NotFound, "x")),
                "Io",
            ),
        ];
        for (err, marker) in &variants {
            let display = format!("{err}");
            let debug = format!("{err:?}");
            assert!(!display.contains(secret), "Display 泄露 {secret}: {display}");
            assert!(!debug.contains(secret), "Debug 泄露 {secret}: {debug}");
            assert!(debug.contains(marker), "Debug 缺类型标记 {marker}: {debug}");
        }
    }
}
