//! SQLCipher4 首页校验 — 确认一个候选 key 能否解某库 (ADR-428 §2.2).
//!
//! 微信 V4 db = 标准 SQLCipher4 + 一处特化 (mac_salt 异或 0x3A). 本模块只做**首页 HMAC 校验**
//! (判断 key 对不对), 不做全页解密 (那是 M3-b native-sqlcipher 的事).
//!
//! ```text
//! salt     = 首页前 16B
//! mac_salt = salt XOR 0x3A                                   (← 微信特化)
//! enc_key  = PBKDF2-HMAC-SHA512(passphrase, salt, rounds, 32B)   (passphrase 路; enc_key 路跳过)
//! mac_key  = PBKDF2-HMAC-SHA512(enc_key, mac_salt, 2, 32B)
//! reserve  = 80 (= align(IV16 + HMAC_SHA512_64, AES16))
//! 校验: HMAC-SHA512(mac_key, page[16 .. 4096-80+16] ++ u32_le(1)) == page[4032..4096]
//! ```

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

/// SQLCipher 页大小 (微信 V4 默认 4096; M3-b 全页解密时从首页探测, M3-a 校验固定 4096).
pub const PAGE: usize = 4096;
/// 每页尾部保留字节 = align(IV 16 + HMAC-SHA512 64, AES 16) = 80.
pub const RESERVE: usize = 80;
/// 微信特化: mac_salt = salt XOR 此常量 (标准 SQLCipher 用 0x3a, 微信沿用).
pub const MAC_SALT_XOR: u8 = 0x3a;
/// 微信 V4 KDF 轮数 (KI-F 版本矩阵, chatlog 实证). passphrase 路按版本传, 不写死.
pub const SQLCIPHER_ROUNDS_V4: u32 = 256_000;
/// 微信 V3 KDF 轮数 (KI-F 版本矩阵).
pub const SQLCIPHER_ROUNDS_V3: u32 = 64_000;

/// 首页 HMAC 校验核心 — 给定**派生后的 enc_key** (成品 AES key), 验首页 mac.
///
/// enc_key 路直接调 (内存拿的就是成品); passphrase 路先 PBKDF2 派生再调.
/// `enc_key` 须 32B, `first_page` 须 ≥ [`PAGE`], 否则返 false (不 panic).
fn mac_check(enc_key: &[u8; 32], first_page: &[u8]) -> bool {
    if first_page.len() < PAGE {
        return false;
    }
    let salt = &first_page[..16];
    let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ MAC_SALT_XOR).collect();

    let mut mac_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);

    // HMAC-SHA512 接受任意长度 key, new_from_slice 不会失败.
    let mut mac = <Hmac<Sha512>>::new_from_slice(&mac_key).expect("HMAC accepts any key length");
    mac.update(&first_page[16..PAGE - RESERVE + 16]);
    mac.update(&1u32.to_le_bytes()); // page number = 1
    let computed = mac.finalize().into_bytes();
    let stored = &first_page[PAGE - RESERVE + 16..PAGE - RESERVE + 16 + 64];
    computed.as_slice() == stored
}

/// enc_key 快路校验 — enc_key 是内存里拿的**成品 key**, 只 PBKDF2 2 轮算 mac_key,
/// **不跑 256000、不碰任何 dll** (ADR-428 §2.1a).
///
/// 返回 true = 该 enc_key 能解此库首页 (经 HMAC 验过才认作 key, codex P1).
#[must_use]
pub fn verify_enc_key(enc_key: &[u8], first_page: &[u8]) -> bool {
    if enc_key.len() != 32 {
        return false;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&enc_key[..32]);
    mac_check(&k, first_page)
}

/// passphrase 完整路校验 — passphrase + 库 salt 跑 `rounds` 轮派生 enc_key, 再首页 HMAC.
///
/// `rounds` 显式传 (KI-F: v4=256000 / v3=64000, 不写死). 返回 true = 该 passphrase 能解此库.
#[must_use]
pub fn verify_passphrase(passphrase: &[u8], first_page: &[u8], rounds: u32) -> bool {
    if first_page.len() < PAGE {
        return false;
    }
    let salt = &first_page[..16];
    let mut enc_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(passphrase, salt, rounds, &mut enc_key);
    mac_check(&enc_key, first_page)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合成一页: 任意 salt + 用已知 enc_key 算正确 mac 填尾部, 验自洽 (不涉真 key).
    fn synth_page_for_enc_key(enc_key: &[u8; 32], salt_seed: u8) -> Vec<u8> {
        let mut page = vec![0u8; PAGE];
        for (i, b) in page.iter_mut().enumerate().take(16) {
            *b = (i as u8).wrapping_mul(7).wrapping_add(salt_seed);
        }
        for (i, b) in page.iter_mut().enumerate().take(PAGE - RESERVE).skip(16) {
            *b = (i % 251) as u8;
        }
        let salt = &page[..16];
        let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ MAC_SALT_XOR).collect();
        let mut mac_key = [0u8; 32];
        pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);
        let mut mac = <Hmac<Sha512>>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[16..PAGE - RESERVE + 16]);
        mac.update(&1u32.to_le_bytes());
        let tag = mac.finalize().into_bytes();
        page[PAGE - RESERVE + 16..PAGE - RESERVE + 16 + 64].copy_from_slice(&tag);
        page
    }

    #[test]
    fn enc_key_verify_roundtrip_and_rejects_wrong() {
        let enc_key = [0x11u8; 32];
        let page = synth_page_for_enc_key(&enc_key, 0);
        assert!(verify_enc_key(&enc_key, &page), "正确 enc_key 应过");
        assert!(!verify_enc_key(&[0x22u8; 32], &page), "错 enc_key 应拒");
        // 篡改正文页 → mac 不符
        let mut tampered = page.clone();
        tampered[100] ^= 1;
        assert!(!verify_enc_key(&enc_key, &tampered), "篡改页应拒");
    }

    #[test]
    fn passphrase_verify_roundtrip_low_rounds() {
        // 测试用低轮数 (不跑 256000), 验派生→校验链路自洽.
        let pass = b"test-passphrase-not-a-real-key";
        let rounds = 64u32;
        let salt_seed = 0x5a;
        let mut page = vec![0u8; PAGE];
        for (i, b) in page.iter_mut().enumerate().take(16) {
            *b = (i as u8) ^ salt_seed;
        }
        for (i, b) in page.iter_mut().enumerate().take(PAGE - RESERVE).skip(16) {
            *b = (i % 241) as u8;
        }
        let salt = &page[..16];
        let mut enc = [0u8; 32];
        pbkdf2_hmac::<Sha512>(pass, salt, rounds, &mut enc);
        // 用派生出的 enc 填正确 mac
        let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ MAC_SALT_XOR).collect();
        let mut mac_key = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&enc, &mac_salt, 2, &mut mac_key);
        let mut mac = <Hmac<Sha512>>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[16..PAGE - RESERVE + 16]);
        mac.update(&1u32.to_le_bytes());
        page[PAGE - RESERVE + 16..PAGE - RESERVE + 16 + 64].copy_from_slice(&mac.finalize().into_bytes());

        assert!(verify_passphrase(pass, &page, rounds), "正确 pass+rounds 应过");
        assert!(!verify_passphrase(b"wrong-pass", &page, rounds), "错 pass 应拒");
        assert!(!verify_passphrase(pass, &page, rounds + 1), "轮数不符应拒");
    }

    #[test]
    fn verify_rejects_malformed_inputs() {
        let page = synth_page_for_enc_key(&[0x33; 32], 0);
        assert!(!verify_enc_key(&[0u8; 16], &page), "key 非 32B 应拒");
        assert!(!verify_enc_key(&[0x33; 32], &[0u8; 100]), "page 不足 4096 应拒");
        assert!(!verify_passphrase(b"x", &[0u8; 100], 64), "page 不足 4096 应拒");
    }

    /// 常量锚定 — 跟 ADR-428 §2.2 / PoC 一致, 防误改.
    #[test]
    fn constants_match_spec() {
        assert_eq!(PAGE, 4096);
        assert_eq!(RESERVE, 80);
        assert_eq!(MAC_SALT_XOR, 0x3a);
        assert_eq!(SQLCIPHER_ROUNDS_V4, 256_000);
        assert_eq!(SQLCIPHER_ROUNDS_V3, 64_000);
        // 校验区间: 正文 [16,4032) + 尾 mac [4032,4096) = 64B HMAC-SHA512.
        assert_eq!(PAGE - RESERVE + 16, 4032);
        assert_eq!(PAGE - (PAGE - RESERVE + 16), 64);
    }
}
