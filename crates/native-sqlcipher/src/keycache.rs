//! §9 加固: PBKDF2-256000 派生库级 key **进程内缓存** —— 同 (master-key, salt, rounds) 重开跳过 ~3s 派生。
//!
//! 背景: 微信一个账号 ~24 个子库 (message 分片 / media / contact / …); serve 每请求新开加密库 (低内存 VFS
//! 不跨请求保温), 每次 3s 的 PBKDF2-256000 是 /media + 热查的主延迟, 也是 cpu-dos 面 (drive-by N×PBKDF)。
//! 缓存后同库重开 ~0, 一举兜掉延迟 + cpu-dos。VFS 路 (vfs.rs) 与整库路 (decrypt.rs) 共用本函数。
//!
//! ## 安全 (K-R4)
//! - 缓存**键** = master-key 的 sha256, **绝不存明文 key**。
//! - 缓存**值** = 派生的 enc_key / mac_key (`Zeroizing`, 内存, 进程存活期常驻) —— 与 master key 已被
//!   `CacheKeyProvider` 常驻内存**同风险面, 不新增暴露**; 从不进日志。
//! - PBKDF2 **确定性**: 同 (key, salt, rounds) 恒得同 key → 缓存命中永不返错 key。
//! - 上限 `MAX_ENTRIES` 防无界 (真实一账号库数 <100)。

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use native_keyscan::{KeyKind, KeyMaterial, MAC_SALT_XOR};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// (master-key sha256, salt[16], rounds) → (enc_key, mac_key)。
type CacheKey = ([u8; 32], [u8; 16], u32);
type Derived = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// 缓存上限 (真实一账号库数 <100; 多账号也 <1024)。满则不再插 (已缓存的常用库仍命中)。
const MAX_ENTRIES: usize = 1024;

static CACHE: LazyLock<Mutex<HashMap<CacheKey, Derived>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock() -> MutexGuard<'static, HashMap<CacheKey, Derived>> {
    // panic=abort 下无毒化; into_inner 兜任何异常路径不 panic。
    CACHE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 派生 (enc_key, mac_key), **缓存 PBKDF2-256000 结果** (同 master-key+salt+rounds 重开跳过 ~3s)。
/// EncKey 直用不缓存 (无 PBKDF); salt 不足 16 (不该发生) 退回不缓存派生。字节等价原 vfs.rs `derive_keys` /
/// decrypt.rs `resolve_enc_key`+`derive_mac_key`。
#[must_use]
pub fn derive_keys_cached(key: &KeyMaterial, salt: &[u8], rounds: u32) -> Derived {
    // EncKey 路: 直用, 无 PBKDF → 不缓存 (派生本身 ~0)。
    if matches!(key.kind(), KeyKind::EncKey) {
        return derive_uncached(key, salt, rounds);
    }
    // **只对标准 16B salt 缓存** (§9 审查 NONE 硬化): 缓存键取 salt 全长 → 派生 (PBKDF salt + mac_salt) 也用全长,
    // 二者一致。非 16 (不该发生; SQLCipher salt 恒 16B) → 不缓存直接派生, 杜绝"截断缓存键 vs 全长派生"不一致。
    let Ok(salt16) = <[u8; 16]>::try_from(salt) else {
        return derive_uncached(key, salt, rounds);
    };
    let key_hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        h.finalize().into()
    };
    let ck = (key_hash, salt16, rounds);
    if let Some(v) = lock().get(&ck) {
        return (v.0.clone(), v.1.clone());
    }
    let derived = derive_uncached(key, salt, rounds);
    let mut c = lock();
    if c.len() < MAX_ENTRIES {
        c.insert(ck, (derived.0.clone(), derived.1.clone()));
    }
    derived
}

/// 无缓存派生 (原逻辑, 字节等价): EncKey 直用 / Passphrase PBKDF2-256000 → enc_key; mac_key =
/// PBKDF2(enc_key, salt⊕MAC_SALT_XOR, 2)。
fn derive_uncached(key: &KeyMaterial, salt: &[u8], rounds: u32) -> Derived {
    let enc_key = match key.kind() {
        KeyKind::EncKey => Zeroizing::new(*key.as_bytes()),
        KeyKind::Passphrase => {
            let mut enc = Zeroizing::new([0u8; 32]);
            pbkdf2_hmac::<Sha512>(key.as_bytes(), salt, rounds, &mut *enc);
            enc
        }
    };
    let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ MAC_SALT_XOR).collect();
    let mut mac_key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha512>(&*enc_key, &mac_salt, 2, &mut *mac_key);
    (enc_key, mac_key)
}

/// 清空缓存 (master key 失效 / 换账号时可调; 平时进程存活期常驻)。
pub fn clear_cache() {
    lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn km() -> KeyMaterial {
        KeyMaterial::passphrase([7u8; 32])
    }

    #[test]
    fn cached_equals_uncached_and_hits() {
        clear_cache();
        let salt = [0x11u8; 16];
        let direct = derive_uncached(&km(), &salt, 4000);
        let c1 = derive_keys_cached(&km(), &salt, 4000); // miss → 派生 + 缓存
        let c2 = derive_keys_cached(&km(), &salt, 4000); // hit
        assert_eq!(*c1.0, *direct.0, "缓存派生 enc_key 与无缓存字节等价");
        assert_eq!(*c1.1, *direct.1, "mac_key 等价");
        assert_eq!(*c2.0, *direct.0, "命中返同 enc_key");
        assert_eq!(*c2.1, *direct.1, "命中返同 mac_key");
    }

    #[test]
    fn different_salt_different_key() {
        clear_cache();
        let a = derive_keys_cached(&km(), &[0x22u8; 16], 4000);
        let b = derive_keys_cached(&km(), &[0x33u8; 16], 4000);
        assert_ne!(*a.0, *b.0, "不同 salt → 不同 enc_key (缓存键含 salt, 不串)");
    }
}
