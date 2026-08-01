//! ChainedKeyProvider — 按顺序尝试, 第一个成功的返
//!
//! PoC-1 v3-key-source/source.rs (ChainedKeySource) 适配 PR2-1-a/b/c 接口:
//!   - KeySource → KeyProvider
//!   - anyhow::Result + downcast → Result<T, KeyError> 直接 (alpha 8 变体)
//!   - is_recoverable_miss() 直接调 KeyError 方法, 不再 downcast
//!
//! 默认顺序: `[cache, ciphertalk, cli]` (ADR-028 R2 / K-R2 cache-first).
//!
//! 命中非 cache source 时, 自动 write-back 到链中第一个 `persists_to_disk` source —
//! 让 ciphertalk 命中后下次直接走 cache 不再 hook (K-R1 一次性).
//!
//! 红线:
//!   - K-R2 cache-first (write_back_idx)
//!   - K-R4 master_key 绝不进 log (走 sha8 / Wxid Display)
//!   - NH-3 区分 recoverable miss / terminal — terminal 立即中止 chain 防 cli 静悄悄盖 Ctrl-C / hook 超时

use std::collections::HashMap;

use async_trait::async_trait;

use crate::key_provider::{KeyError, KeyProvider, KeyProviderCapabilities, MasterKey, Wxid};

/// 链式 KeyProvider — 按顺序尝试, 第一个成功的返回.
pub struct ChainedKeyProvider {
    sources: Vec<Box<dyn KeyProvider>>,
    /// 写回目标在 sources 中的下标 — `None` 表示链上没有可写回的 cache.
    /// 在 `new()` 中扫描 `capabilities().persists_to_disk == true` 取首个, 避免每次 resolve 重扫.
    write_back_idx: Option<usize>,
}

impl ChainedKeyProvider {
    #[must_use]
    pub fn new(sources: Vec<Box<dyn KeyProvider>>) -> Self {
        let write_back_idx = sources.iter().position(|s| s.capabilities().persists_to_disk);
        Self {
            sources,
            write_back_idx,
        }
    }

    /// 获取链头的 cache source (若存在), 用于 write-back.
    /// 当前实现只识别 `capabilities().persists_to_disk == true` 的 source.
    #[must_use]
    pub fn first_persistent_source(&self) -> Option<&dyn KeyProvider> {
        self.write_back_idx
            .and_then(|i| self.sources.get(i))
            .map(std::convert::AsRef::as_ref)
    }
}

#[async_trait]
impl KeyProvider for ChainedKeyProvider {
    async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>, KeyError> {
        // 合并所有支持 resolve_all 的 source 结果, 按链顺序优先 (前者优先).
        let mut out: HashMap<Wxid, MasterKey> = HashMap::new();
        for s in &self.sources {
            if !s.capabilities().can_resolve_all {
                continue;
            }
            match s.resolve_all().await {
                Ok(map) => {
                    for (k, v) in map {
                        out.entry(k).or_insert(v);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        source = s.name(),
                        error = %e,
                        "ChainedKeyProvider.resolve_all: 该 source 失败, 继续下一个"
                    );
                }
            }
        }
        Ok(out)
    }

    async fn resolve(&self, wxid: &Wxid) -> Result<MasterKey, KeyError> {
        let mut last_err: Option<KeyError> = None;

        for (idx, s) in self.sources.iter().enumerate() {
            match s.resolve(wxid).await {
                Ok(k) => {
                    // r2 P2 #2 (Claude review): 高频 resolve 用 debug 防 log 噪音.
                    //   alpha 期排查方便临时用 info, 0.2.0+ 上线后必降 debug + 仅在 chain 决策点 (write-back / fallthrough) info.
                    tracing::debug!(
                        source = s.name(),
                        wxid = %wxid,
                        "ChainedKeyProvider.resolve: 命中"
                    );
                    // K-R2 write-back: 命中非 cache source 时, 回写到链上首个 cache.
                    // 让下次同 wxid 直接走 cache, 不再触发 ciphertalk hook (K-R1 一次性).
                    if let Some(wb_idx) = self.write_back_idx {
                        if idx != wb_idx {
                            // 仅当命中的不是写回目标本身时回写.
                            let provenance = s.name();
                            if let Some(target) = self.sources.get(wb_idx) {
                                match target.store(wxid, &k, provenance).await {
                                    Ok(()) => {
                                        tracing::info!(
                                            target_source = target.name(),
                                            from_source = provenance,
                                            wxid = %wxid,
                                            "ChainedKeyProvider.resolve: write-back 成功"
                                        );
                                    }
                                    Err(e) => {
                                        // K-R2 红线: write-back 失败不阻断 resolve, 仅 warn —
                                        // 保证 ciphertalk 命中后用户能拿到 key, 即便 cache 落盘失败
                                        // (DPAPI 故障等).
                                        tracing::warn!(
                                            target_source = target.name(),
                                            from_source = provenance,
                                            wxid = %wxid,
                                            error = %e,
                                            "ChainedKeyProvider.resolve: write-back 失败, 已忽略"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    return Ok(k);
                }
                Err(e) => {
                    // NH-3: 区分 recoverable miss vs terminal error.
                    //   - is_recoverable_miss() == true → tracing::debug, last_err = Some(e), 继续
                    //   - is_recoverable_miss() == false → tracing::warn, 立刻 break (terminal)
                    //
                    // alpha 收敛 vs PoC-1: 直接调 KeyError::is_recoverable_miss(), 不再走 anyhow
                    // downcast (PR2-1-a 删了 anyhow::Result 包装).
                    if e.is_recoverable_miss() {
                        tracing::debug!(
                            source = s.name(),
                            wxid = %wxid,
                            error = %e,
                            "ChainedKeyProvider.resolve: miss (recoverable), 尝试下一个"
                        );
                        last_err = Some(e);
                    } else {
                        tracing::warn!(
                            source = s.name(),
                            wxid = %wxid,
                            error = %e,
                            "ChainedKeyProvider.resolve: terminal error, 中止 chain"
                        );
                        return Err(e);
                    }
                }
            }
        }
        Err(last_err.unwrap_or(KeyError::NotFound { wxid: wxid.clone() }))
    }

    /// r2 P1 #1: 嵌套 ChainedKeyProvider 时 outer chain 调 inner chain store —
    /// 转发到内部首个 persists_to_disk source, 防 capabilities().persists_to_disk=true 撒谎.
    /// 不嵌套时 (本 chain 直接含 cache), `target` 就是本 chain 的 write_back_idx 指向的 source.
    async fn store(&self, wxid: &Wxid, key: &MasterKey, provenance: &str) -> Result<(), KeyError> {
        let Some(wb_idx) = self.write_back_idx else {
            return Err(KeyError::Unsupported {
                name: self.name(),
                op: "store (链上无 persists_to_disk source)",
            });
        };
        let target = self.sources.get(wb_idx).ok_or(KeyError::Unsupported {
            name: self.name(),
            op: "store (write_back_idx 越界, 不应出现)",
        })?;
        target.store(wxid, key, provenance).await
    }

    fn name(&self) -> &'static str {
        "chained"
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        // 取链上所有 source 的并集 (任一具备即认为整体具备).
        KeyProviderCapabilities {
            can_resolve_all: self.sources.iter().any(|s| s.capabilities().can_resolve_all),
            needs_user_consent: self.sources.iter().any(|s| s.capabilities().needs_user_consent),
            persists_to_disk: self.sources.iter().any(|s| s.capabilities().persists_to_disk),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[allow(dead_code)]
    fn make_key(c: u8) -> MasterKey {
        let hex_char = format!("{:x}", c & 0xf);
        MasterKey::from_hex(&hex_char.repeat(64)).expect("64 hex char")
    }

    /// 记录 store 调用的 mock cache source — 模拟 CacheKeyProvider, 不依赖 DPAPI / 文件 IO.
    struct MockCache {
        name_str: &'static str,
        /// 命中时返回的 MasterKey hex (内部存 hex, 每次 resolve 重新构造 MasterKey).
        resolve_hit_hex: Mutex<Option<String>>,
        /// 写回调用记录: (wxid_str, key_hex, provenance).
        store_calls: Arc<Mutex<Vec<(String, String, String)>>>,
        /// store 是否故意失败 (用于 write_back_failure 用例).
        store_fails: bool,
    }

    #[async_trait]
    impl KeyProvider for MockCache {
        async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>, KeyError> {
            Ok(HashMap::new())
        }
        async fn resolve(&self, wxid: &Wxid) -> Result<MasterKey, KeyError> {
            let lock = self.resolve_hit_hex.lock().unwrap();
            match lock.as_ref() {
                Some(hex) => MasterKey::from_hex(hex).map_err(|_| KeyError::algorithm_mismatch("mock_corrupt")),
                None => Err(KeyError::NotFound { wxid: wxid.clone() }),
            }
        }
        async fn store(&self, wxid: &Wxid, key: &MasterKey, provenance: &str) -> Result<(), KeyError> {
            self.store_calls
                .lock()
                .unwrap()
                .push((wxid.as_str().to_string(), key.to_hex(), provenance.to_string()));
            if self.store_fails {
                Err(KeyError::dpapi_unavailable(b"mock_store_fail"))
            } else {
                Ok(())
            }
        }
        fn name(&self) -> &'static str {
            self.name_str
        }
        fn capabilities(&self) -> KeyProviderCapabilities {
            KeyProviderCapabilities {
                can_resolve_all: true,
                needs_user_consent: false,
                persists_to_disk: true,
            }
        }
    }

    /// 模拟 CipherTalk / Cli: 命中后返 key, 不可写回.
    struct MockProvider {
        name_str: &'static str,
        key_hex: String,
    }

    #[async_trait]
    impl KeyProvider for MockProvider {
        async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>, KeyError> {
            Ok(HashMap::new())
        }
        async fn resolve(&self, _wxid: &Wxid) -> Result<MasterKey, KeyError> {
            MasterKey::from_hex(&self.key_hex).map_err(|_| KeyError::algorithm_mismatch("mock_corrupt"))
        }
        fn name(&self) -> &'static str {
            self.name_str
        }
        fn capabilities(&self) -> KeyProviderCapabilities {
            KeyProviderCapabilities {
                can_resolve_all: false,
                needs_user_consent: false,
                persists_to_disk: false,
            }
        }
    }

    /// 模拟 terminal error source — 用于 NH-3 测试.
    struct MockTerminalErrProvider {
        name_str: &'static str,
    }

    #[async_trait]
    impl KeyProvider for MockTerminalErrProvider {
        async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>, KeyError> {
            Ok(HashMap::new())
        }
        async fn resolve(&self, _wxid: &Wxid) -> Result<MasterKey, KeyError> {
            Err(KeyError::dpapi_unavailable(b"mock_terminal"))
        }
        fn name(&self) -> &'static str {
            self.name_str
        }
        fn capabilities(&self) -> KeyProviderCapabilities {
            KeyProviderCapabilities {
                can_resolve_all: false,
                needs_user_consent: false,
                persists_to_disk: false,
            }
        }
    }

    /// 模拟 recoverable miss source — 用于 NH-3 测试.
    struct MockRecoverableMissProvider {
        name_str: &'static str,
    }

    #[async_trait]
    impl KeyProvider for MockRecoverableMissProvider {
        async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>, KeyError> {
            Ok(HashMap::new())
        }
        async fn resolve(&self, wxid: &Wxid) -> Result<MasterKey, KeyError> {
            Err(KeyError::NotFound { wxid: wxid.clone() })
        }
        fn name(&self) -> &'static str {
            self.name_str
        }
        fn capabilities(&self) -> KeyProviderCapabilities {
            KeyProviderCapabilities {
                can_resolve_all: false,
                needs_user_consent: false,
                persists_to_disk: false,
            }
        }
    }

    // ====== write-back 用例 (K-R2 cache-first 落地) ======

    /// case 1: 链 = [Cache(miss), CipherTalk(hit)] → CipherTalk 命中后 write-back 到 Cache.
    #[tokio::test]
    async fn write_back_chains_to_cache() {
        let cache_calls = Arc::new(Mutex::new(Vec::new()));
        let cache = MockCache {
            name_str: "cache",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::clone(&cache_calls),
            store_fails: false,
        };
        let ciphertalk = MockProvider {
            name_str: "ciphertalk",
            key_hex: "a".repeat(64),
        };

        let chain = ChainedKeyProvider::new(vec![Box::new(cache), Box::new(ciphertalk)]);
        let key = chain.resolve(&Wxid::new("wxid_demo")).await.expect("命中 ciphertalk");
        assert_eq!(key.to_hex(), "a".repeat(64));

        let calls = cache_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "应触发 1 次 write-back");
        assert_eq!(calls[0].0, "wxid_demo");
        assert_eq!(calls[0].1, "a".repeat(64));
        assert_eq!(calls[0].2, "ciphertalk", "provenance 应记 ciphertalk");
    }

    /// case 2: 链 = [Cache1, Cache2, Cli] → Cli 命中只写回 Cache1 (首个 persists_to_disk).
    #[tokio::test]
    async fn write_back_to_first_cache_only() {
        let cache1_calls = Arc::new(Mutex::new(Vec::new()));
        let cache2_calls = Arc::new(Mutex::new(Vec::new()));
        let cache1 = MockCache {
            name_str: "cache_primary",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::clone(&cache1_calls),
            store_fails: false,
        };
        let cache2 = MockCache {
            name_str: "cache_secondary",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::clone(&cache2_calls),
            store_fails: false,
        };
        let cli = MockProvider {
            name_str: "cli",
            key_hex: "b".repeat(64),
        };

        let chain = ChainedKeyProvider::new(vec![Box::new(cache1), Box::new(cache2), Box::new(cli)]);
        let key = chain.resolve(&Wxid::new("wxid_z")).await.expect("命中 cli");
        assert_eq!(key.to_hex(), "b".repeat(64));

        assert_eq!(cache1_calls.lock().unwrap().len(), 1, "首个 cache 应收 1 次");
        assert_eq!(cache2_calls.lock().unwrap().len(), 0, "次级 cache 不应收到 store");
    }

    /// case 3: write-back 时 cache.store 失败 → resolve 仍返成功 (warn 不阻断).
    #[tokio::test]
    async fn write_back_failure_logs_warn_but_returns_key() {
        let cache_calls = Arc::new(Mutex::new(Vec::new()));
        let cache = MockCache {
            name_str: "cache",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::clone(&cache_calls),
            store_fails: true,
        };
        let ciphertalk = MockProvider {
            name_str: "ciphertalk",
            key_hex: "c".repeat(64),
        };

        let chain = ChainedKeyProvider::new(vec![Box::new(cache), Box::new(ciphertalk)]);
        let key = chain
            .resolve(&Wxid::new("wxid_fail"))
            .await
            .expect("即便 write-back 失败, resolve 也应返 ciphertalk 的 key");
        assert_eq!(key.to_hex(), "c".repeat(64));
        assert_eq!(cache_calls.lock().unwrap().len(), 1, "store 确实被尝试");
    }

    /// case 4: cache 命中时不应 write-back (避免自旋写).
    #[tokio::test]
    async fn cache_hit_does_not_trigger_write_back() {
        let cache_calls = Arc::new(Mutex::new(Vec::new()));
        let cache = MockCache {
            name_str: "cache",
            resolve_hit_hex: Mutex::new(Some("d".repeat(64))),
            store_calls: Arc::clone(&cache_calls),
            store_fails: false,
        };
        let ciphertalk = MockProvider {
            name_str: "ciphertalk",
            key_hex: "deadbeef".repeat(8),
        };

        let chain = ChainedKeyProvider::new(vec![Box::new(cache), Box::new(ciphertalk)]);
        let key = chain.resolve(&Wxid::new("wxid_cached")).await.unwrap();
        assert_eq!(key.to_hex(), "d".repeat(64));
        assert_eq!(cache_calls.lock().unwrap().len(), 0, "cache 自己命中不该再 write-back");
    }

    /// case 5: 链上无 cache 时不应 panic / 不报错.
    #[tokio::test]
    async fn no_cache_in_chain_resolve_still_works() {
        let ciphertalk = MockProvider {
            name_str: "ciphertalk",
            key_hex: "e".repeat(64),
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(ciphertalk)]);
        let key = chain.resolve(&Wxid::new("wxid_x")).await.unwrap();
        assert_eq!(key.to_hex(), "e".repeat(64));
    }

    // ====== NH-3 用例: recoverable miss vs terminal error ======

    /// recoverable miss 链上 fallthrough 到下个 source.
    #[tokio::test]
    async fn chain_recoverable_miss_falls_through() {
        let miss = MockRecoverableMissProvider { name_str: "cache" };
        let hit = MockProvider {
            name_str: "ciphertalk",
            key_hex: "f".repeat(64),
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(miss), Box::new(hit)]);
        let key = chain.resolve(&Wxid::new("wxid_y")).await.unwrap();
        assert_eq!(key.to_hex(), "f".repeat(64));
    }

    /// terminal error 中止 chain, 不再尝试后续 source (防 NH-3 NotFound 静悄悄盖).
    #[tokio::test]
    async fn chain_terminal_error_breaks_immediately() {
        let terminal = MockTerminalErrProvider { name_str: "ciphertalk" };
        let cli_fallback = MockProvider {
            name_str: "cli",
            key_hex: "deadbeef".repeat(8),
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(terminal), Box::new(cli_fallback)]);
        let err = chain.resolve(&Wxid::new("wxid_t")).await.unwrap_err();
        // 应是 terminal error, 不是 cli 的成功 (terminal break chain, 后续 source 不动)
        assert!(matches!(err, KeyError::DpapiUnavailable { .. }));
    }

    /// 全链 miss → 返末次 recoverable err.
    #[tokio::test]
    async fn chain_all_miss_returns_last_err() {
        let miss1 = MockRecoverableMissProvider { name_str: "cache" };
        let miss2 = MockRecoverableMissProvider { name_str: "ciphertalk" };
        let chain = ChainedKeyProvider::new(vec![Box::new(miss1), Box::new(miss2)]);
        let err = chain.resolve(&Wxid::new("wxid_nope")).await.unwrap_err();
        assert!(matches!(err, KeyError::NotFound { .. }));
    }

    // ====== capabilities 并集 ======

    #[tokio::test]
    async fn capabilities_union() {
        let cache = MockCache {
            name_str: "cache",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::new(Mutex::new(Vec::new())),
            store_fails: false,
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(cache)]);
        let cap = chain.capabilities();
        assert!(cap.can_resolve_all);
        assert!(!cap.needs_user_consent);
        assert!(cap.persists_to_disk);
        assert_eq!(chain.name(), "chained");
    }

    /// first_persistent_source 工具方法.
    #[tokio::test]
    async fn first_persistent_source_returns_cache() {
        let cache = MockCache {
            name_str: "cache",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::new(Mutex::new(Vec::new())),
            store_fails: false,
        };
        let cli = MockProvider {
            name_str: "cli",
            key_hex: "a".repeat(64),
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(cache), Box::new(cli)]);
        let p = chain.first_persistent_source().expect("有 cache");
        assert_eq!(p.name(), "cache");
    }

    /// 链上无 cache → first_persistent_source 返 None.
    #[tokio::test]
    async fn first_persistent_source_none_when_no_cache() {
        let cli = MockProvider {
            name_str: "cli",
            key_hex: "a".repeat(64),
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(cli)]);
        assert!(chain.first_persistent_source().is_none());
    }

    // ====== r3 P1: chain.store 直接调 + nested chain 回归 (codex/Claude r2 共识) ======

    /// r3 P1 #1 (codex): chain.store 直接调 → 转发到首个 persists_to_disk source.
    #[tokio::test]
    async fn chain_store_forwards_to_first_persistent_source() {
        let cache_calls = Arc::new(Mutex::new(Vec::new()));
        let cache = MockCache {
            name_str: "cache",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::clone(&cache_calls),
            store_fails: false,
        };
        let cli = MockProvider {
            name_str: "cli",
            key_hex: "1".repeat(64),
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(cache), Box::new(cli)]);

        let key = MasterKey::from_hex(&"2".repeat(64)).unwrap();
        chain
            .store(&Wxid::new("wxid_X"), &key, "external_caller")
            .await
            .expect("chain.store 应转发成功");

        let calls = cache_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "chain.store 必须转发一次到 cache");
        assert_eq!(calls[0].0, "wxid_X");
        assert_eq!(calls[0].1, "2".repeat(64));
        assert_eq!(calls[0].2, "external_caller", "provenance 原样转发");
    }

    /// r3 P1 #1 (codex): 链上无 cache → chain.store 返 Unsupported (不静默吞).
    #[tokio::test]
    async fn chain_store_returns_unsupported_when_no_cache() {
        let cli = MockProvider {
            name_str: "cli",
            key_hex: "1".repeat(64),
        };
        let chain = ChainedKeyProvider::new(vec![Box::new(cli)]);

        let key = MasterKey::from_hex(&"2".repeat(64)).unwrap();
        let err = chain
            .store(&Wxid::new("wxid_X"), &key, "external_caller")
            .await
            .expect_err("无 cache 链应返 Err");
        assert!(matches!(err, KeyError::Unsupported { .. }));
    }

    /// r3 P1 #2 (codex/Claude): nested chain — outer.resolve → inner_chain.store 转发到 inner cache.
    /// 关键: 锁住 "嵌套时 inner_chain 不递归自旋, 只落最内层 cache 一次".
    #[tokio::test]
    async fn nested_chain_resolve_write_back_lands_in_inner_cache() {
        let inner_cache_calls = Arc::new(Mutex::new(Vec::new()));
        let inner_cache = MockCache {
            name_str: "inner_cache",
            resolve_hit_hex: Mutex::new(None),
            store_calls: Arc::clone(&inner_cache_calls),
            store_fails: false,
        };
        let inner_cli = MockProvider {
            name_str: "inner_cli",
            key_hex: "3".repeat(64),
        };
        // inner chain = [inner_cache, inner_cli] — inner_cache 是 persists_to_disk.
        let inner_chain = ChainedKeyProvider::new(vec![Box::new(inner_cache), Box::new(inner_cli)]);

        let hit_source = MockProvider {
            name_str: "ciphertalk",
            key_hex: "4".repeat(64),
        };
        // outer chain = [inner_chain, ciphertalk] — outer.write_back_idx = 0 (inner_chain).
        let outer_chain = ChainedKeyProvider::new(vec![Box::new(inner_chain), Box::new(hit_source)]);

        // resolve: inner_chain.resolve(wxid) → inner_cache miss → inner_cli hit → inner_chain
        // 自己 write-back 到 inner_cache (调用 1). Inner 返 Ok(key="3"x64).
        // outer 拿到 inner_chain Ok → 不再 write-back (idx == wb_idx).
        let key = outer_chain.resolve(&Wxid::new("wxid_nested")).await.unwrap();
        assert_eq!(key.to_hex(), "3".repeat(64), "应命中 inner_cli");

        let calls = inner_cache_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "inner_cache 只应收 1 次 store (不递归自旋)");
        assert_eq!(calls[0].2, "inner_cli", "provenance 应记 inner_cli");
    }
}
