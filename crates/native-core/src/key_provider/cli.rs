//! CliKeyProvider — `--master-key-hex` 兜底
//!
//! PoC-1 v3-key-source/cli.rs (126 LoC) 适配 PR2-1-a/b/c 接口 (ADR-405 §3.1):
//!   - KeySource → KeyProvider trait
//!   - Wxid String → Wxid newtype (PR2-1-a)
//!   - MasterKey String → MasterKey([u8; 32]) (PR2-1-a)
//!   - anyhow::Result → Result<T, KeyError> 直接 (alpha 8 变体)
//!
//! 红线 (跟 PR2-1-c ciphertalk 共享):
//!   - K-R2 缓存优先 (本 provider 作为 chain 链尾兜底)
//!   - K-R4 master_key 绝不进 log (sha8 / Wxid Display)
//!   - capabilities: can_resolve_all=false, needs_user_consent=false, persists_to_disk=false

use std::collections::HashMap;

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::key_provider::{KeyError, KeyProvider, KeyProviderCapabilities, MasterKey, Wxid};

/// CliKeyProvider — 把 CLI flag `--master-key-hex` 包成 KeyProvider, 链尾兜底
pub struct CliKeyProvider {
    /// CLI 传入的 64 char hex master key 解码后的 MasterKey (可选).
    inline_key: Option<MasterKey>,
    /// 当前账号 wxid (可选).
    ///
    /// - `None`: 信任 CLI 调用方, `resolve(任意 wxid)` 都返该 key (适合单账号场景, 调用方已确认 wxid).
    /// - `Some(w)`: 严格匹配, `resolve(wxid != w)` 返 recoverable `KeyError::NotFound` —
    ///   chain 可 fallthrough 到其它 source (cli 是兜底, "不匹配" 应是 "本 source 没 key" 而非 "全链死").
    ///   r2 P0 #1: alpha 早期返 terminal WxidMismatch, Claude r1 review 发现破 chain 兜底语义 → 改回 NotFound.
    wxid: Option<Wxid>,
}

impl CliKeyProvider {
    /// r2 P1 #2: 拒荒谬组合 `Some(wxid) + None(key)` — wxid filter 设置但无 key, 永返 NotFound,
    /// filter 形同虚设. 调用方误传时早 fail (Result), 不静默吞错.
    ///
    /// 合法组合:
    /// - `(None, None)`: 无 CLI key (resolve 永返 NotFound recoverable)
    /// - `(Some(k), None)`: 无 wxid filter, 信任 CLI 调用方任意 wxid 返该 key
    /// - `(Some(k), Some(w))`: 严格匹配 wxid==w
    pub fn new(inline_key: Option<MasterKey>, wxid: Option<Wxid>) -> Result<Self, KeyError> {
        if inline_key.is_none() && wxid.is_some() {
            return Err(KeyError::Unsupported {
                name: "cli",
                op: "new(None, Some(wxid)) — wxid filter 无 key 永 miss",
            });
        }
        Ok(Self { inline_key, wxid })
    }
}

#[async_trait]
impl KeyProvider for CliKeyProvider {
    async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>, KeyError> {
        // PoC-1 NH: 跟 ciphertalk 不同, cli 在有 wxid 时可以返单 entry; 无 wxid 时返空 map.
        // 不返 Unsupported, 因为本 op 语义"该 source 不支持"在 chain.resolve_all 时会被 merge,
        // 返空 map 等价于"无可贡献".
        Ok(HashMap::new())
    }

    async fn resolve(&self, wxid: &Wxid) -> Result<MasterKey, KeyError> {
        let key = self
            .inline_key
            .as_ref()
            .ok_or_else(|| KeyError::NotFound { wxid: wxid.clone() })?;

        // r2 P0 #1 (Claude review): 若 self.wxid 设置且不匹配 → 返 recoverable NotFound 让 chain
        // fallthrough, 不再返 terminal WxidMismatch.
        //   理由: CLI 是链尾兜底, "不匹配" 应是 "该 source 没有这个 wxid 的 key", 不是 "全链死".
        //   K-R8 跨账号串扰防护应在 chain 上游 (caller wxid 一致性校验), 不在 cli source 内.
        //   PoC-1 同语义: 不匹配返 CacheMiss (recoverable miss).
        if let Some(w) = &self.wxid {
            if w != wxid {
                return Err(KeyError::NotFound { wxid: wxid.clone() });
            }
        }

        // r2 P0 #2 (codex/Claude review): MasterKey 不 Clone — 拿 hex 副本重构.
        //   hex 副本走 Zeroizing<String> 包裹防 K-R4 — String drop 时归零内部 buffer,
        //   防 chain 调用频率高时 RSS 残留明文 hex.
        //   alpha 已知 to_hex 返裸 String 但调用方有责任 zeroize — 见 provider.rs to_hex doc.
        let hex_copy: Zeroizing<String> = Zeroizing::new(key.to_hex());
        MasterKey::from_hex(&hex_copy).map_err(|_| KeyError::algorithm_mismatch("inline_key_corrupt"))
    }

    fn name(&self) -> &'static str {
        "cli"
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            can_resolve_all: false,
            needs_user_consent: false,
            persists_to_disk: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(c: u8) -> MasterKey {
        let hex_char = format!("{:x}", c & 0xf);
        MasterKey::from_hex(&hex_char.repeat(64)).expect("64 hex char")
    }

    #[tokio::test]
    async fn cli_resolve_returns_inline_key_when_no_wxid_filter() {
        let provider = CliKeyProvider::new(Some(make_key(0xa)), None).unwrap();
        let wxid = Wxid::new("wxid_demo");
        let k = provider.resolve(&wxid).await.unwrap();
        assert_eq!(k.to_hex().len(), 64);
    }

    #[tokio::test]
    async fn cli_resolve_matches_wxid_when_filter_set() {
        let provider = CliKeyProvider::new(Some(make_key(0xa)), Some(Wxid::new("wxid_demo"))).unwrap();
        let k = provider.resolve(&Wxid::new("wxid_demo")).await.unwrap();
        assert_eq!(k.to_hex().len(), 64);
        // r2 P0 #1: 不匹配返 recoverable NotFound (chain 可 fallthrough)
        let err = provider.resolve(&Wxid::new("wxid_other")).await.unwrap_err();
        assert!(matches!(err, KeyError::NotFound { .. }));
    }

    #[tokio::test]
    async fn cli_resolve_err_when_no_key() {
        let provider = CliKeyProvider::new(None, None).unwrap();
        let err = provider.resolve(&Wxid::new("wxid_demo")).await.unwrap_err();
        assert!(matches!(err, KeyError::NotFound { .. }));
    }

    #[tokio::test]
    async fn cli_resolve_all_always_empty() {
        // PoC-1 NH: 有 wxid+key 也返空 map (跟 PoC-1 不同, 简化 — chain.resolve_all 不依赖 cli).
        let provider = CliKeyProvider::new(Some(make_key(0xa)), Some(Wxid::new("wxid_demo"))).unwrap();
        let map = provider.resolve_all().await.unwrap();
        assert!(map.is_empty());

        let provider2 = CliKeyProvider::new(Some(make_key(0xa)), None).unwrap();
        let map2 = provider2.resolve_all().await.unwrap();
        assert!(map2.is_empty());
    }

    #[test]
    fn capabilities_cli() {
        let provider = CliKeyProvider::new(None, None).unwrap();
        let cap = provider.capabilities();
        assert!(!cap.can_resolve_all);
        assert!(!cap.needs_user_consent);
        assert!(!cap.persists_to_disk);
        assert_eq!(provider.name(), "cli");
    }

    /// r1 NotFound miss → chain 应 fallthrough (is_recoverable_miss=true).
    #[tokio::test]
    async fn cli_no_key_err_is_recoverable_miss() {
        let provider = CliKeyProvider::new(None, None).unwrap();
        let err = provider.resolve(&Wxid::new("wxid_demo")).await.unwrap_err();
        assert!(
            err.is_recoverable_miss(),
            "cli NotFound 应 recoverable, chain 可 fallthrough"
        );
    }

    /// r2 P1 #2: `new(None, Some(wxid))` 荒谬组合早 fail.
    #[test]
    fn cli_new_rejects_wxid_filter_without_key() {
        let r = CliKeyProvider::new(None, Some(Wxid::new("wxid_demo")));
        let err = match r {
            Ok(_) => panic!("new(None, Some(wxid)) 应 Err"),
            Err(e) => e,
        };
        assert!(matches!(err, KeyError::Unsupported { .. }));
    }

    /// r2 P0 #1: wxid 不匹配返 recoverable NotFound, chain 可 fallthrough (兜底语义).
    /// K-R8 跨账号串扰防护应在 chain 上游, 不在 cli source 内.
    #[tokio::test]
    async fn cli_wxid_mismatch_is_recoverable() {
        let provider = CliKeyProvider::new(Some(make_key(0xa)), Some(Wxid::new("wxid_demo"))).unwrap();
        let err = provider.resolve(&Wxid::new("wxid_other")).await.unwrap_err();
        assert!(err.is_recoverable_miss(), "wxid 不匹配应 recoverable, chain 可继续兜底");
    }
}
