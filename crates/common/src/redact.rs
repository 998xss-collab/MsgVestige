//! redact — 日志脱敏工具 (K-R4: 日志绝不露明文 wxid / key / 聊天内容; logging-日志.md 任务 3)。
//!
//! `sha8` 短指纹 = sha256 前 4 字节 hex (8 字符), 跟 `key_provider/ciphertalk` / native-core `sha8` 一致。
//! 敏感值 (wxid / 内容) 打日志前过一遍这里, 保证 grep 日志搜不到明文。

use sha2::{Digest, Sha256};

/// 敏感字节 → sha8 短指纹 (sha256 前 4 字节 = 8 hex)。日志脱敏用。
#[must_use]
pub fn sha8(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..4])
}

/// wxid → sha8 (日志里代替明文 wxid)。
#[must_use]
pub fn wxid(w: &str) -> String {
    sha8(w.as_bytes())
}

/// 敏感文本 → `"len=N sha=xxxx"` (日志里代替消息正文等; 留长度便于诊断, 不露内容)。
#[must_use]
pub fn text(s: &str) -> String {
    format!("len={} sha={}", s.len(), sha8(s.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{sha8, text, wxid};

    #[test]
    fn sha8_is_8_hex_stable() {
        let a = sha8(b"wxid_abcd1234efgh567");
        assert_eq!(a.len(), 8, "sha8 = 8 hex 字符");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, sha8(b"wxid_abcd1234efgh567"), "同输入稳定");
        assert_ne!(a, sha8(b"wxid_other"), "不同输入不同");
    }

    #[test]
    fn wxid_and_text_redact() {
        assert_eq!(wxid("wxid_abc").len(), 8);
        let t = text("hello 世界");
        assert!(t.starts_with("len="));
        assert!(t.contains("sha="));
        assert!(!t.contains("hello"), "不露正文");
    }
}
