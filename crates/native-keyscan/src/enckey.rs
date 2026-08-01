//! enckey.rs — fast 路: 扫内存 `x'<hex>'` 拿 WCDB 缓存的成品 enc_key (ADR-428 §2.1a).
//!
//! 零 dll、零 256000 轮: 正则命中 → 取前 64hex 当 enc_key 候选 → 首页 HMAC 校验 (2 轮 mac).
//! 正则命中只是候选, 必须过 [`verify_enc_key`] 才认作 key (ADR-428 codex P1).

use std::ops::ControlFlow;

use regex::bytes::Regex;

use crate::sqlcipher::verify_enc_key;
use crate::win::WeixinProcess;

/// 扫私有内存找 `x'<64hex enc_key><32hex salt>'` → 验锚点首页 → 命中即返成品 enc_key.
///
/// `anchor_page` = 目标库首页 4096B. 扫完无命中返 None (内存无对应 enc_key — 库没加载 / 微信没解锁).
#[must_use]
pub fn scan_enc_key(proc: &WeixinProcess, anchor_page: &[u8]) -> Option<[u8; 32]> {
    // WCDB 为每个已加载库缓存 x'<enc_key 64hex><salt 32hex>'; 取前 64hex 作 enc_key 候选.
    // 用 for_each_readable_region (private/mapped/image 全扫) 而非 for_each_private_region:
    // enc_key 串跟 image key 一样可能待在**非 private 区** (mapped/image), private-only 会漏
    // (2026-07-11: 对拍 chatlog v4 windows scanner 逮到 — 它扫所有 RW 区; image key 扫描早已广扫, 主 key 之前没跟上).
    let re = Regex::new(r"x'([0-9a-fA-F]{64,192})'").expect("static regex valid");
    let mut found: Option<[u8; 32]> = None;
    proc.for_each_readable_region(|_base, mem| {
        for cap in re.captures_iter(mem) {
            let hx = &cap[1];
            if hx.len() < 64 {
                continue;
            }
            if let Some(enc) = decode_hex32(&hx[..64]) {
                if verify_enc_key(&enc, anchor_page) {
                    found = Some(enc);
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    });
    found
}

/// 64 个 hex ascii 字节 → 32 字节; 非 hex 返 None.
fn decode_hex32(hex_ascii: &[u8]) -> Option<[u8; 32]> {
    if hex_ascii.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex_ascii.chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex32_roundtrip() {
        let hex_ascii = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let bytes = decode_hex32(hex_ascii).unwrap();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x11);
        assert_eq!(bytes[31], 0xff);
    }

    #[test]
    fn decode_hex32_rejects_bad() {
        assert!(decode_hex32(b"too short").is_none());
        // 64 长度但含非 hex 字符 (G).
        let mut bad = vec![b'a'; 64];
        bad[10] = b'G';
        assert!(decode_hex32(&bad).is_none());
    }
}
