//! KeyProvider trait + Wxid newtype + MasterKey + sha8 工具.
//!
//! 设计 (跟 ADR-405 §3.1 + ADR-410 MATRIX 一致):
//!   - trait 5 方法 (async resolve_all / resolve / store + sync name / capabilities)
//!   - Wxid 用 newtype 防跨账号串扰 (ADR-410 MATRIX #13)
//!   - MasterKey 包成 newtype + zeroize 防内存 dump 残留, inner [u8; 32] 不暴露给外部 (K-R4)

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key_provider::{KeyError, KeyProviderCapabilities};

/// 微信 UserName newtype — 防 String 类型混淆 / 跨账号串扰 (ADR-410 MATRIX #13).
///
/// 装微信 **UserName** (不透明主键标识): `wxid_*` (系统自动分配) / 自定义微信号 (用户设的, 无 wxid_ 前缀) /
/// `gh_*` (公众号) / `*@chatroom` (群) / 系统号 (`filehelper`/`weixin` 等) 都合法.
/// **不是**标准化的"微信号/Alias" (后者才是 6-20 字母开头规则, 是另一个字段). PoC-1 沿用
/// `pub type Wxid = String`, alpha 收紧成 newtype 保类型安全.
///
/// PR2-12-d-pre: try_new 从"强制 `wxid_` 前缀"放宽成"只挡空/超长/含空白控制符" — 真实数据 (Name2Id
/// 9826 样本 15.7% 非 wxid_, 多为自定义微信号) + chatlog/wxdump/wx-cli 等工具全把 UserName 当不透明键不卡格式.
/// newtype 仍防 String 串扰, K-R4 Debug/Display 仍 sha8 自遮.
/// - `Wxid::try_new(s)` 校验返 `Result` (用户传入 / 反序列化场景)
/// - `Wxid::new(s)` 内部 debug_assert + alpha 期 fail-fast, release 不 panic (代码内已知构造用)
/// - 删除 `impl From<S>` / `FromStr Err=Infallible` 防隐式 String 转换
// r5: 删 derive(Debug) — 手写 sha8 化, 防外部 `dbg!(wxid)` / `format!("{wxid:?}")` 泄明文.
// PR2-1-b: 加 Serialize/Deserialize + serde(transparent) — bincode 字节流等价 String, 兼容
// PoC-1 keys.enc 落盘格式 (cache.rs schema_version=1 字节兼容).
// 反序列化不经 try_new 校验 — cache 文件已 DPAPI 加密 + 用户身份隔离, 信任级足够;
// 不信任 source 反序列化时调用方需自己 try_new 重校.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Wxid(String);

impl fmt::Debug for Wxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wxid(sha8={})", sha8(self.0.as_bytes()))
    }
}

/// 微信 UserName 合法性 — 只挡明显非标识 (空 / 超长 / 含空白或控制符), 不卡格式 (UserName 是
/// wxid_/自定义号/gh_/@chatroom/系统号 的联合体). 长度上限 128 给足余量 (真实 UserName 一般 ≤40).
fn is_valid_username(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl Wxid {
    /// 校验构造 — 微信 UserName (不透明主键) 用; 用户输入 / 反序列化场景.
    ///
    /// 微信 UserName 是联合体 (`wxid_*` / 自定义微信号 / `gh_*` / `*@chatroom` / 系统号) — **不卡格式**.
    /// 只挡明显非标识: 空 / 超长 (>128) / 含空白或控制符 (防腐坏数据 / 正文误判 / 日志注入).
    ///
    /// # Errors
    /// - `KeyError::WxidMismatch` 若 `s` 空 / 长度 >128 / 含空白或控制字符.
    pub fn try_new(s: impl Into<String>) -> Result<Self, KeyError> {
        let s = s.into();
        if !is_valid_username(&s) {
            return Err(KeyError::WxidMismatch {
                expected: "non-empty wechat UserName (len<=128, no whitespace/control)".into(),
                actual: sha8(s.as_bytes()),
            });
        }
        Ok(Self(s))
    }

    /// 内部已知合法 UserName 构造 — alpha debug build fail-fast, release 不 panic.
    /// 调用方负责 (来源: cache 表 / config 字段 / 已校验输入).
    pub fn new(s: impl Into<String>) -> Self {
        let s = s.into();
        // K-R4: 失败信息走 sha8, 不泄裸 UserName (旧版 {s:?} 会在 debug panic 时泄明文).
        debug_assert!(
            is_valid_username(&s),
            "Wxid::new 收到非法 UserName (空/超长/含空白控制符): sha8={}",
            sha8(s.as_bytes())
        );
        Self(s)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Display 走 sha8 防 K-R4 明文泄露 — `format!("{wxid}")` / `%wxid` / `tracing` 都安全.
/// 需要明文必须显式调 `.as_str()` 走非日志边界 (cache 序列化 / DPAPI input 等).
impl fmt::Display for Wxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wxid#{}", sha8(self.0.as_bytes()))
    }
}

impl FromStr for Wxid {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// 64 char hex master key 解码后的原始字节 (32 bytes).
///
/// PoC-1 沿用 `pub type MasterKey = String` (hex), alpha 转 newtype:
///   - 不暴露 inner [u8; 32] 防泄露 (K-R4)
///   - ZeroizeOnDrop: Drop 时清零, 防内存 dump 残留
///   - 不 derive Serialize/Deserialize — 落盘走 hex (cache.rs 自己 encode/decode)
///
/// r3: **删 derive(Clone)** — Clone 会让副本永驻直到副本独立 Drop, 破坏"Drop 即清零"语义.
/// ChainedKeyProvider write-back 改走 `to_hex()` 拿 hex 副本 → 立即 DPAPI 加密 → 不持 owned 副本.
/// 若极端场景需要明文副本, 调用方走 `to_hex()` + 自行 `Zeroizing<String>` 包裹.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 从 64 char hex 字符串解析 (大小写无关). 长度或字符不对返 AlgorithmMismatch.
    pub fn from_hex(s: &str) -> Result<Self, KeyError> {
        if s.len() != 64 {
            return Err(KeyError::AlgorithmMismatch {
                wechat_version: format!("hex len {} (期望 64)", s.len()),
            });
        }
        let mut buf = [0u8; 32];
        hex::decode_to_slice(s, &mut buf).map_err(|_| KeyError::AlgorithmMismatch {
            wechat_version: "hex decode 失败 (非 hex char)".into(),
        })?;
        Ok(Self(buf))
    }

    /// 解封 — 给 crate 内部 cipher 模块用.
    ///
    /// r2 P1: 改 `pub(crate)` 防 msgvestige / msgvestige-adapter 等其他 crate 直接拿明文 key bytes.
    /// 跨 crate 调用方必须走 KeyProvider trait (而非直接持 MasterKey).
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 解封 + 转 hex (cache 落盘用 — 落盘前自己负责 DPAPI 加密).
    ///
    /// # K-R4 红线 — 调用方约定
    /// 返回的 `String` 是 64-char hex master key 明文. 调用方必须:
    /// 1. 立即 DPAPI 加密 (跟 cache.rs 一致, 不长期持有)
    /// 2. 不写入 log / stderr / panic message
    /// 3. 用完后让 Drop 自然释放 (alpha 不强制 ZeroizeOnDrop on String, 0.2.0+ 改 SecretString)
    ///
    /// 违反这 3 条 = K-R4 红线漏, 双审 r1 P1 已警告.
    #[must_use = "to_hex returns plaintext master key — caller must DPAPI-encrypt immediately"]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // K-R4: 绝不 log 明文 hex, 只露 sha8.
        write!(f, "MasterKey(sha8={})", sha8(&self.0))
    }
}

/// 微信 master key 取源统一抽象.
///
/// alpha 计划 3 个 impl (PR2-1-b/c 拷过来):
///   - `CacheKeyProvider` — DPAPI 加密缓存 (默认永久, 可选 stale_after_days)
///   - `CipherTalkKeyProvider` — vendor wx_key.dll 一次性 hook
///   - `CliKeyProvider` — --master-key-hex 兜底
///
/// 红线 (跟 PoC-1 v3-key-source-spec.md §四 一致, 见 mod.rs 顶部):
///   - K-R4 明文 wxid / master_key 绝不入 log
///   - K-R5 DPAPI CURRENT_USER 范围
///   - K-R6 Drop 必清 hook (防微信进程残留 shellcode)
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// 拉所有已知 wxid 的 key (cache 实, 其他默认返 Unsupported).
    async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>, KeyError> {
        Err(KeyError::Unsupported {
            name: self.name(),
            op: "resolve_all",
        })
    }

    /// 拉指定 wxid 的 key.
    async fn resolve(&self, wxid: &Wxid) -> Result<MasterKey, KeyError>;

    /// 写回 key — 仅 cache 类 source 实装, 其他默认返 Unsupported.
    ///
    /// `provenance` 记录原始取源名 ("ciphertalk" / "cli"), 写入 cache entry.
    /// 调用方应只对 `capabilities().persists_to_disk == true` 的 source 调用.
    async fn store(&self, wxid: &Wxid, key: &MasterKey, provenance: &str) -> Result<(), KeyError> {
        let _ = (wxid, key, provenance);
        Err(KeyError::Unsupported {
            name: self.name(),
            op: "store",
        })
    }

    /// source 名称 (写入 log / etl_state).
    fn name(&self) -> &'static str;

    /// 能力描述 — ChainedKeyProvider 路由用.
    fn capabilities(&self) -> KeyProviderCapabilities;
}

/// 8 char hex sha256 前缀 — 通用脱敏工具 (K-R4).
///
/// 用于 log / error message / cache key 哈希化, 不暴露明文 wxid / master_key.
///
/// # `#[must_use]` 防 footgun
/// `sha8` 返回值必须用于脱敏 log; 不用即等同直接 log 明文 (K-R4 红线漏).
/// 例: ❌ `sha8(&key); tracing::info!("key={:?}", key);` (sha8 算了但没用, 后面继续 log 明文)
#[must_use = "sha8 返回值必须用于脱敏 log 输出; 丢弃返回值 = 等同直接 log 明文 (K-R4 红线漏)"]
pub fn sha8(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(&digest[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// r5 P1 修: Wxid 手写 Debug 脱敏 — 防外部 `dbg!(wxid)` / `{wxid:?}` 泄明文.
    #[test]
    fn wxid_debug_redacted() {
        let secret = "wxid_super_secret_user";
        let w = Wxid::new(secret);
        let dbg = format!("{w:?}");
        assert!(!dbg.contains(secret), "Wxid Debug 泄露明文: {dbg}");
        assert!(dbg.starts_with("Wxid(sha8="), "Wxid Debug 应含 sha8 前缀: {dbg}");
    }

    /// PR2-12-d-pre: 非 wxid_ UserName (自定义号/@chatroom) 的 Debug/Display 仍脱敏 (脱敏无格式分支).
    #[test]
    fn wxid_non_prefix_username_still_redacted() {
        for secret in ["custom_secret_id", "private_grp_8f3a@chatroom"] {
            let w = Wxid::new(secret);
            let dbg = format!("{w:?}");
            let disp = format!("{w}");
            assert!(!dbg.contains(secret), "非 wxid_ Debug 泄明文: {dbg}");
            assert!(!disp.contains(secret), "非 wxid_ Display 泄明文: {disp}");
            assert!(dbg.starts_with("Wxid(sha8="));
            assert!(disp.starts_with("wxid#"));
        }
    }

    /// r5 P1 修: Hash + PartialEq 在 HashMap 中一致性 — ChainedKeyProvider.resolve_all 合并依赖.
    #[test]
    fn wxid_hash_consistency_in_hashmap() {
        let mut map: HashMap<Wxid, u32> = HashMap::new();
        map.insert(Wxid::new("wxid_a"), 1);
        map.insert(Wxid::new("wxid_b"), 2);
        // 同样字面值的 Wxid 必须命中同一 bucket
        assert_eq!(map.get(&Wxid::new("wxid_a")), Some(&1));
        assert_eq!(map.get(&Wxid::new("wxid_b")), Some(&2));
        // 不同 wxid 命中不同 bucket
        assert_eq!(map.get(&Wxid::new("wxid_c")), None);
    }

    #[test]
    fn wxid_newtype_roundtrip() {
        let w = Wxid::new("wxid_demo_123");
        assert_eq!(w.as_str(), "wxid_demo_123");
        // r2 P0 #3: Display 走 sha8 防明文泄露 — to_string 不再等于明文.
        // 明文取 as_str() / into_inner.
        let displayed = w.to_string();
        assert!(displayed.starts_with("wxid#"));
        assert!(!displayed.contains("wxid_demo_123"), "Display 不应含明文: {displayed}");
        let parsed: Wxid = "wxid_xyz".parse().unwrap();
        assert_eq!(parsed.as_str(), "wxid_xyz");
        // try_new 成功路径
        let try_ok = Wxid::try_new("wxid_abc").unwrap();
        assert_eq!(try_ok.as_str(), "wxid_abc");
    }

    /// PR2-12-d-pre: try_new 接受所有真实微信 UserName 格式 (不卡格式, UserName 是联合体).
    /// 真实数据 Name2Id 9826 样本: wxid_ 84% / 自定义号(无 wxid_) 9% / @chatroom 7%.
    #[test]
    fn wxid_try_new_accepts_real_username_formats() {
        for ok in [
            "wxid_abc123",         // 系统自动
            "custom_id_no_prefix", // 自定义微信号 (无 wxid_, 占真实数据 ~9%)
            "zhang-san_88",        // 自定义号含减号
            "gh_official_acct",    // 公众号
            "abc123@chatroom",     // 群
            "filehelper",          // 系统号
            "12345678",            // 偶见纯数字
        ] {
            assert!(Wxid::try_new(ok).is_ok(), "应接受真实 UserName 格式: {ok}");
        }
    }

    /// PR2-12-d-pre: 只拒明显非标识 — 空 / 超长 (>128) / 含空白或控制符.
    #[test]
    fn wxid_try_new_rejects_garbage() {
        assert!(Wxid::try_new("").is_err(), "空");
        assert!(Wxid::try_new("a".repeat(129)).is_err(), "超长 >128");
        assert!(Wxid::try_new("has space").is_err(), "含空格");
        assert!(Wxid::try_new("line\nbreak").is_err(), "含换行");
        assert!(Wxid::try_new("tab\tchar").is_err(), "含 tab");
        assert!(Wxid::try_new("ctrl\u{0}null").is_err(), "含控制符");
        assert!(matches!(Wxid::try_new("").unwrap_err(), KeyError::WxidMismatch { .. }));
        // 边界: 恰 128 过, 129 拒
        assert!(Wxid::try_new("a".repeat(128)).is_ok(), "恰 128 应过");
    }

    /// FromStr 用 try_new: 自定义号 (无 wxid_) 该过, 含空白的非标识该拒.
    #[test]
    fn wxid_from_str_accepts_custom_rejects_garbage() {
        assert!("custom_no_prefix".parse::<Wxid>().is_ok(), "自定义号该过");
        let err: KeyError = "has space".parse::<Wxid>().unwrap_err();
        assert!(matches!(err, KeyError::WxidMismatch { .. }));
    }

    /// K-R4: try_new 的 actual 字段经 sha8 脱敏 — 不暴露原始非法 input.
    #[test]
    fn wxid_try_new_error_does_not_leak_input() {
        let err = Wxid::try_new("secret value with space").unwrap_err();
        let msg = format!("{err}");
        assert!(!msg.contains("secret"), "错误信息泄露 input: {msg}");
        assert!(!msg.contains("value"));
    }

    #[test]
    fn master_key_from_hex_valid() {
        let hex_str = "aa".repeat(32);
        let mk = MasterKey::from_hex(&hex_str).unwrap();
        assert_eq!(mk.as_bytes(), &[0xaau8; 32]);
        assert_eq!(mk.to_hex(), hex_str);
    }

    #[test]
    fn master_key_from_hex_wrong_length() {
        let err = MasterKey::from_hex(&"aa".repeat(31)).unwrap_err();
        assert!(matches!(err, KeyError::AlgorithmMismatch { .. }));
    }

    #[test]
    fn master_key_from_hex_non_hex_chars() {
        let s: String = std::iter::repeat('z').take(64).collect();
        let err = MasterKey::from_hex(&s).unwrap_err();
        assert!(matches!(err, KeyError::AlgorithmMismatch { .. }));
    }

    #[test]
    fn master_key_debug_redacted() {
        // K-R4: Debug 输出不暴露 hex 明文, 只露 sha8 prefix.
        let mk = MasterKey::from_bytes([0xab; 32]);
        let dbg = format!("{mk:?}");
        let hex_str = mk.to_hex();
        assert!(!dbg.contains(&hex_str));
        assert!(dbg.starts_with("MasterKey(sha8="));
    }

    #[test]
    fn sha8_is_8_hex_chars_deterministic() {
        let h1 = sha8(b"wxid_demo");
        let h2 = sha8(b"wxid_demo");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 8);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
        // 不同 input 不同 output
        assert_ne!(sha8(b"wxid_a"), sha8(b"wxid_b"));
    }

    /// 验 default impl: 没自定义 resolve_all 的 KeyProvider 返 Unsupported.
    struct OnlyResolve;

    #[async_trait]
    impl KeyProvider for OnlyResolve {
        async fn resolve(&self, _wxid: &Wxid) -> Result<MasterKey, KeyError> {
            Ok(MasterKey::from_bytes([0x11; 32]))
        }
        fn name(&self) -> &'static str {
            "only_resolve"
        }
        fn capabilities(&self) -> KeyProviderCapabilities {
            KeyProviderCapabilities::default()
        }
    }

    #[tokio::test]
    async fn default_resolve_all_returns_unsupported() {
        let p = OnlyResolve;
        let err = p.resolve_all().await.unwrap_err();
        assert!(matches!(
            err,
            KeyError::Unsupported {
                name: "only_resolve",
                op: "resolve_all"
            }
        ));
    }

    #[tokio::test]
    async fn default_store_returns_unsupported() {
        let p = OnlyResolve;
        let mk = MasterKey::from_bytes([0u8; 32]);
        let err = p.store(&Wxid::new("wxid_x"), &mk, "test").await.unwrap_err();
        assert!(matches!(
            err,
            KeyError::Unsupported {
                name: "only_resolve",
                op: "store"
            }
        ));
    }
}
