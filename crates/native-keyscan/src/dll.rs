//! dll.rs — full 路: 从 Weixin.dll 代码段静态提 internal_db_key 常量 (ADR-428 §2.1b / ADR-419 版权).
//!
//! goblin 解 PE, **静态读文件不运行 dll**. 机器码 4×(mov rdx, imm64) = `48 BA <8B>` 拼 32 字节,
//! 末尾 `48 85 C0` (test rax,rax) 作锚 — PoC 在 4.1.6.14 验通 (提 2 候选, verify 过滤真的那个).

use std::collections::HashSet;
use std::path::Path;

use crate::error::KeyScanError;

/// 静态读 Weixin.dll 可执行段, 提 internal_db_key 候选 (可能多个, 上层 verify 过滤).
///
/// # Errors
/// - `DllRead` 读文件 / PE 解析失败.
///
/// 返回空 vec = pattern 不匹配 (上层转 `VersionPatternMismatch`).
pub fn extract_internal_keys(dll_path: &Path) -> Result<Vec<[u8; 32]>, KeyScanError> {
    let data = std::fs::read(dll_path).map_err(|e| KeyScanError::DllRead(format!("{}: {e}", dll_path.display())))?;
    let pe = goblin::pe::PE::parse(&data).map_err(|e| KeyScanError::DllRead(format!("PE 解析失败: {e}")))?;
    // 4 条 mov rdx,imm64 (48 BA <8B>), 间隔 3~8 字节, 末尾 test rax,rax (48 85 C0).
    let re = regex::bytes::Regex::new(
        r"(?s-u)\x48\xBA(.{8}).{3,8}?\x48\xBA(.{8}).{3,8}?\x48\xBA(.{8}).{3,8}?\x48\xBA(.{8}).{3,8}?\x48\x85\xC0",
    )
    .expect("static regex valid");

    let mut out: Vec<[u8; 32]> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for section in &pe.sections {
        // 仅可执行代码段 (IMAGE_SCN_MEM_EXECUTE = 0x20000000).
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = start.saturating_add(size).min(data.len());
        if start >= end {
            continue;
        }
        for cap in re.captures_iter(&data[start..end]) {
            let mut k = [0u8; 32];
            k[0..8].copy_from_slice(&cap[1]);
            k[8..16].copy_from_slice(&cap[2]);
            k[16..24].copy_from_slice(&cap[3]);
            k[24..32].copy_from_slice(&cap[4]);
            if seen.insert(k) {
                out.push(k);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn missing_dll_returns_dll_read_error() {
        let err = extract_internal_keys(&PathBuf::from("Z:/no/such/Weixin.dll")).unwrap_err();
        assert!(matches!(err, KeyScanError::DllRead(_)));
    }
}
