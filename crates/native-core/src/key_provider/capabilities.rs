//! KeyProviderCapabilities — 描述某个 KeyProvider impl 的能力.
//!
//! 用于 ChainedKeyProvider 路由决策 (例如: 只能找 persists_to_disk=true 的做 write-back).

/// KeyProvider 能力描述.
///
/// 跟 PoC-1 KeySourceCapabilities 字段一致 (alpha 不动, M2 视需求扩):
///   - can_resolve_all: 是否可列举所有已知 wxid → key (cache 可, ciphertalk/cli 不可)
///   - needs_user_consent: 是否需要用户手动确认 (ciphertalk 要, 其他不要 — 跟 ADR-028 R2 一致)
///   - persists_to_disk: 是否会落盘 (cache 落盘, 其他不落 — 决定 write-back 目标)
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KeyProviderCapabilities {
    pub can_resolve_all: bool,
    pub needs_user_consent: bool,
    pub persists_to_disk: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_all_false() {
        let c = KeyProviderCapabilities::default();
        assert!(!c.can_resolve_all);
        assert!(!c.needs_user_consent);
        assert!(!c.persists_to_disk);
    }

    #[test]
    fn cache_like_caps() {
        let cache = KeyProviderCapabilities {
            can_resolve_all: true,
            persists_to_disk: true,
            ..Default::default()
        };
        assert!(cache.can_resolve_all);
        assert!(cache.persists_to_disk);
        assert!(!cache.needs_user_consent);
    }
}
