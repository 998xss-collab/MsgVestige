//! KeyMaterial — 扫出的 key (两种语义) + 产出包装 + K-R4 脱敏出口.
//!
//! 设计核心 (ADR-428 §2.1): 内存里有两种可用 key 形态, **语义不可混用**:
//!   - [`KeyMaterial::EncKey`]: enc_key 快路扫到的**成品 AES key** (已派生完 256000 轮),
//!     只能喂 NativeCipher 直用, **不可再派生** (再跑 PBKDF2 就错).
//!   - [`KeyMaterial::Passphrase`]: raw_key XOR internal_db_key 得的 master passphrase,
//!     跟 sidecar 的 master_key 同语义, **需 PBKDF2-256000 + 各库 salt 现场派生**.
//!
//! K-R4: 两者都 `ZeroizeOnDrop`, Debug 只露 kind + sha8, `to_hex` must_use 警告.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// 8 char hex sha256 前缀 — K-R4 脱敏出口 (key/wxid 哈希化, 不暴露明文).
///
/// 跟 native-core `key_provider::sha8` 同算法; 本 crate 自带一份避免反向依赖 native-core.
#[must_use = "sha8 返回值必须用于脱敏 log 输出; 丢弃 = 等同 log 明文 (K-R4 红线漏)"]
pub fn sha8(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    hex::encode(&digest[..4])
}

/// key 形态 — 决定上层走派生还是直用.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    /// 成品 AES key (enc_key 快路): 直用, 不可再派生.
    EncKey,
    /// master passphrase (完整路): 需 PBKDF2-256000 + salt 派生.
    Passphrase,
}

impl KeyKind {
    /// 写 log / etl_state 的稳定标识.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncKey => "enc_key",
            Self::Passphrase => "passphrase",
        }
    }
}

/// 提取模式 — 选两套法 (ADR-428 §3 `--key-mode fast|full`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyMode {
    /// 快路: 扫 enc_key, 零 dll/零 256000, 解活跃库 (默认).
    Fast,
    /// 完整路: raw_key XOR dll → 256000 派生, 解全库 (含未加载).
    Full,
}

impl KeyMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Full => "full",
        }
    }

    /// 覆盖范围说明 — fast 必须标注 "漏 migrate" 避免上层误当全库 (ADR-428 §4 codex P1).
    #[must_use]
    pub fn coverage_note(self) -> &'static str {
        match self {
            Self::Fast => "active-only: 仅微信运行时加载过的库 (不含 migrate 等未加载废库)",
            Self::Full => "全库: passphrase 现场派生, 含未加载库 (migrate)",
        }
    }
}

/// 扫出的 key 字节 (两种语义) — `ZeroizeOnDrop` 防内存 dump 残留 (K-R4).
///
/// **不 derive Clone**: Clone 会让副本永驻直到独立 Drop, 破坏"Drop 即清零"语义 (跟 `MasterKey` 一致).
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum KeyMaterial {
    /// enc_key 快路成品 key — 直用, 不可再派生.
    EncKey([u8; 32]),
    /// passphrase 完整路 — 需派生.
    Passphrase([u8; 32]),
}

impl KeyMaterial {
    /// 构造成品 enc_key.
    #[must_use]
    pub fn enc_key(bytes: [u8; 32]) -> Self {
        Self::EncKey(bytes)
    }

    /// 构造 master passphrase.
    #[must_use]
    pub fn passphrase(bytes: [u8; 32]) -> Self {
        Self::Passphrase(bytes)
    }

    /// 形态 — 上层据此决定派生还是直用.
    #[must_use]
    pub fn kind(&self) -> KeyKind {
        match self {
            Self::EncKey(_) => KeyKind::EncKey,
            Self::Passphrase(_) => KeyKind::Passphrase,
        }
    }

    fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::EncKey(b) | Self::Passphrase(b) => b,
        }
    }

    /// 脱敏标识 (K-R4 安全出口) — log / 诊断用.
    #[must_use]
    pub fn sha8(&self) -> String {
        sha8(self.bytes())
    }

    /// 解封字节 — 给上层 cipher 模块用 (NativeCipher 派生 / 直用).
    ///
    /// # K-R4 红线 — 调用方约定
    /// 返回明文 key 字节. 不得写入 log/stderr/panic; 用完让 Drop 清零.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.bytes()
    }

    /// 解封 + 转 64-char hex (落盘缓存前自己负责 DPAPI 加密).
    ///
    /// # K-R4 红线 — 调用方约定
    /// 返回明文 hex key. 必须立即加密落盘, 不写 log, 用完即弃.
    #[must_use = "to_hex 返回明文 key — 调用方须立即 DPAPI 加密, 不得入 log (K-R4)"]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes())
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // K-R4: 只露 kind + sha8, 绝不露 key 字节/hex.
        write!(f, "KeyMaterial({}, sha8={})", self.kind().as_str(), self.sha8())
    }
}

/// 一次扫描的产出 — key + 模式 + (fast) 锚点 scope.
///
/// 字段私有 + 只经 [`Self::from_enc_key`] / [`Self::from_passphrase`] 构造 (codex A 修):
/// 保证 material↔mode 一致, **不可构造 `EncKey+Full` 这类矛盾态**.
#[derive(Debug)]
pub struct KeyScanOutcome {
    material: KeyMaterial,
    mode: KeyMode,
    /// fast 路: 此 enc_key 对应的**锚点库 salt 的 sha8** — enc_key 是 per-db salt 派生,
    /// **只对该库有效** (codex F 修: 上层据此知 scope, 多库需逐库再扫, 留 M3-c);
    /// full 路: None (passphrase 是 master, 全库通用).
    anchor_salt_sha8: Option<String>,
}

impl KeyScanOutcome {
    /// fast 产出: 成品 enc_key + 锚点库 salt sha8 (标明此 key 仅对该 salt/库有效).
    #[must_use]
    pub fn from_enc_key(enc: [u8; 32], anchor_salt_sha8: String) -> Self {
        Self {
            material: KeyMaterial::enc_key(enc),
            mode: KeyMode::Fast,
            anchor_salt_sha8: Some(anchor_salt_sha8),
        }
    }

    /// full 产出: master passphrase (全库通用, 无 scope).
    #[must_use]
    pub fn from_passphrase(pass: [u8; 32]) -> Self {
        Self {
            material: KeyMaterial::passphrase(pass),
            mode: KeyMode::Full,
            anchor_salt_sha8: None,
        }
    }

    /// 扫出并校验通过的 key (语义见 [`KeyMaterial`], 形态靠 [`KeyMaterial::kind`]).
    #[must_use]
    pub fn material(&self) -> &KeyMaterial {
        &self.material
    }

    /// 走的提取模式 (与 material 形态绑定: Fast↔EncKey / Full↔Passphrase).
    #[must_use]
    pub fn mode(&self) -> KeyMode {
        self.mode
    }

    /// fast: `Some(锚点库 salt sha8)` — 此 enc_key **仅对该库有效**, 解别库需逐库再扫 (M3-c);
    /// full: `None` — master passphrase 全库通用.
    #[must_use]
    pub fn anchor_scope(&self) -> Option<&str> {
        self.anchor_salt_sha8.as_deref()
    }

    /// 覆盖范围说明 (fast 标注漏 migrate, 防上层误当全库).
    #[must_use]
    pub fn coverage_note(&self) -> &'static str {
        self.mode.coverage_note()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha8_deterministic_8hex() {
        let a = sha8(b"anchor");
        assert_eq!(a, sha8(b"anchor"));
        assert_eq!(a.len(), 8);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(sha8(b"a"), sha8(b"b"));
    }

    #[test]
    fn key_material_kind_and_hex_roundtrip() {
        let enc = KeyMaterial::enc_key([0xaa; 32]);
        assert_eq!(enc.kind(), KeyKind::EncKey);
        assert_eq!(enc.to_hex(), "aa".repeat(32));
        let pass = KeyMaterial::passphrase([0xbb; 32]);
        assert_eq!(pass.kind(), KeyKind::Passphrase);
        assert_eq!(pass.as_bytes(), &[0xbb; 32]);
    }

    /// K-R4: Debug 不露 key 明文 hex, 只露 kind + sha8.
    #[test]
    fn key_material_debug_redacted() {
        let km = KeyMaterial::enc_key([0xcd; 32]);
        let hex_str = km.to_hex();
        let dbg = format!("{km:?}");
        assert!(!dbg.contains(&hex_str), "Debug 泄 key hex: {dbg}");
        assert!(dbg.contains("enc_key"), "应露 kind: {dbg}");
        assert!(dbg.contains("sha8="), "应露 sha8: {dbg}");
        // passphrase variant 同样脱敏
        let pp = KeyMaterial::passphrase([0xcd; 32]);
        assert!(!format!("{pp:?}").contains(&pp.to_hex()));
    }

    /// 两 variant 同字节 → 同 sha8 (sha8 只看字节) 但 kind 不同 (语义靠 kind 区分).
    #[test]
    fn same_bytes_differ_by_kind_not_sha8() {
        let enc = KeyMaterial::enc_key([0x42; 32]);
        let pass = KeyMaterial::passphrase([0x42; 32]);
        assert_eq!(enc.sha8(), pass.sha8());
        assert_ne!(enc.kind(), pass.kind());
    }

    #[test]
    fn mode_coverage_note_marks_fast_active_only() {
        assert!(KeyMode::Fast.coverage_note().contains("active-only"));
        assert!(KeyMode::Fast.coverage_note().contains("migrate"));
        assert!(KeyMode::Full.coverage_note().contains("全库"));
    }

    /// 构造函数绑定 material↔mode + fast 带锚点 scope (codex A/F 修).
    #[test]
    fn outcome_binds_material_mode_and_scope() {
        let fast = KeyScanOutcome::from_enc_key([1; 32], "deadbeef".into());
        assert!(fast.coverage_note().contains("active-only"));
        assert_eq!(fast.mode(), KeyMode::Fast);
        assert_eq!(fast.material().kind(), KeyKind::EncKey);
        assert_eq!(fast.anchor_scope(), Some("deadbeef"), "fast 须带锚点库 salt scope");
        // full: master passphrase, 全库通用无 scope.
        let full = KeyScanOutcome::from_passphrase([2; 32]);
        assert_eq!(full.mode(), KeyMode::Full);
        assert_eq!(full.material().kind(), KeyKind::Passphrase);
        assert_eq!(full.anchor_scope(), None, "full master 无 scope");
    }
}
