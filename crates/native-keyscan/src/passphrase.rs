//! passphrase.rs — full 路: raw_key (扫指针结构) XOR internal_db_key (dll 常量) → 256000 派生
//! (ADR-428 §2.1b). 能解任意库 (含微信未加载的), 代价: 读 dll + 每候选 256000 轮 (rayon 并行).

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::Path;

use rayon::prelude::*;

use crate::dll::extract_internal_keys;
use crate::error::KeyScanError;
use crate::sqlcipher::verify_passphrase;
use crate::win::WeixinProcess;

/// full 路提 master passphrase:
///   raw_key 候选 (扫指针结构 + 熵过滤) XOR internal_db_key (dll 常量) → `rounds` 轮派生验首页 (rayon 并行).
///
/// # Errors
/// - `VersionPatternMismatch` dll 提不到常量 (版本 pattern 不匹配);
/// - `NoCandidateVerified` 所有 raw × internal 组合无一过首页 HMAC.
pub fn scan_passphrase(
    proc: &WeixinProcess,
    dll_path: &Path,
    anchor_page: &[u8],
    rounds: u32,
) -> Result<[u8; 32], KeyScanError> {
    let internal_keys = extract_internal_keys(dll_path)?;
    if internal_keys.is_empty() {
        return Err(KeyScanError::VersionPatternMismatch);
    }
    let raw_candidates = scan_raw_key_candidates(proc);
    if raw_candidates.is_empty() {
        return Err(KeyScanError::NoCandidateVerified);
    }
    // rayon 并行: 每个 raw_key × 每个 internal_db_key XOR → 256000 派生验 (重活, 并行收益大).
    raw_candidates
        .par_iter()
        .find_map_any(|raw| {
            for ik in &internal_keys {
                let mut pass = [0u8; 32];
                for i in 0..32 {
                    pass[i] = raw[i] ^ ik[i];
                }
                // 正则/指针命中只是候选, 必须过首页 HMAC 才认作 key (ADR-428 codex P1).
                if verify_passphrase(&pass, anchor_page, rounds) {
                    return Some(pass);
                }
            }
            None
        })
        .ok_or(KeyScanError::NoCandidateVerified)
}

/// 扫指针结构 (PoC 实证): 32B 槽 = `[ptr 8B(高2字节0)][0×8][len=0x20][cap=0x2f]`
/// → 顺 ptr 读 32B 候选 → 熵过滤 → 去重.
fn scan_raw_key_candidates(proc: &WeixinProcess) -> Vec<[u8; 32]> {
    let len_marker = [0x20u8, 0, 0, 0, 0, 0, 0, 0];
    let cap_marker = [0x2fu8, 0, 0, 0, 0, 0, 0, 0];
    let mut cands: Vec<[u8; 32]> = Vec::new();
    let mut seen_ptr: HashSet<usize> = HashSet::new();
    let mut seen_key: HashSet<[u8; 32]> = HashSet::new();
    proc.for_each_private_region(|_base, mem| {
        if mem.len() >= 32 {
            let mut i = 0usize;
            while i + 32 <= mem.len() {
                if mem[i + 16..i + 24] == len_marker
                    && mem[i + 24..i + 32] == cap_marker
                    && mem[i + 6..i + 16].iter().all(|&b| b == 0)
                {
                    let ptr = u64::from_le_bytes(mem[i..i + 8].try_into().unwrap()) as usize;
                    if ptr != 0 && seen_ptr.insert(ptr) {
                        if let Some(k) = proc.read(ptr, 32) {
                            if k.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&k);
                                if is_potential_key(&arr) && seen_key.insert(arr) {
                                    cands.push(arr);
                                }
                            }
                        }
                    }
                }
                i += 1;
            }
        }
        ControlFlow::Continue(())
    });
    cands
}

/// 熵/字符过滤: 随机 32B key 相异字节多 (≥15) 且可打印 ASCII 少 (≤24) — 滤掉文本/结构噪音.
fn is_potential_key(key: &[u8; 32]) -> bool {
    let distinct: HashSet<u8> = key.iter().copied().collect();
    if distinct.len() < 15 {
        return false;
    }
    let printable = key.iter().filter(|&&b| (32..=126).contains(&b)).count();
    printable <= 24
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_potential_filters_text_and_low_entropy() {
        // 全可打印 ascii (文本) → 滤掉.
        let text = *b"abcdefghijklmnopqrstuvwxyz012345";
        assert!(!is_potential_key(&text), "全文本应滤掉");
        // 全 0 (低熵) → 滤掉.
        assert!(!is_potential_key(&[0u8; 32]), "低熵应滤掉");
        // 高熵随机字节 → 留.
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        assert!(is_potential_key(&k), "高熵候选应留");
    }
}
