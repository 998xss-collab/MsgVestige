//! key_provider::dpapi — Windows DPAPI 原语 (CryptProtectData / CryptUnprotectData, CURRENT_USER 范围).
//!
//! **共享 crypto 原语** (K-R5 DPAPI CURRENT_USER): [`cache`](super::cache) 用它加密 master key 缓存;
//! config `[cli].auth_password` 校验用它解密 (ADR-403 §3.5). 非 windows 平台是 stub (CI/Linux 编译过).
//!
//! 原 PR2-1-b 埋在 cache.rs 私有 mod; PR2-8-b 抽到本共享模块 (config + cache 复用). 仅 windows 块有
//! unsafe (CryptProtect/Unprotect + LocalFree + ptr 拷), 不扩散模块外. 0.2.0+ 改 SafeDPAPI wrapper 后移除 escape.

use super::error::KeyError;

type Result<T> = std::result::Result<T, KeyError>;

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod win {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    use super::{KeyError, Result};

    fn map_dpapi_err() -> KeyError {
        // 取 GetLastError 分流 DpapiLocked (0x80070005 ACCESS_DENIED) vs DpapiUnavailable
        let code = unsafe { GetLastError() };
        if code == 0x8007_0005 {
            KeyError::DpapiLocked { error_code: code }
        } else {
            // wxid 这里没有, 用 "(dpapi)" 兜底脱敏字串
            KeyError::dpapi_unavailable(b"(dpapi)")
        }
    }

    /// DPAPI 加密（CURRENT_USER 范围）— K-R5
    ///
    /// # Safety
    /// - `plain` 切片必须有效（Rust 引用保证）
    /// - `CryptProtectData` 通过 `LocalAlloc` 分配出参缓冲，调用方必须 `LocalFree` —— 已处理
    pub fn dpapi_encrypt(plain: &[u8]) -> Result<Vec<u8>> {
        // 输入 blob: pbData 字段虽 `*mut u8`，但 CryptProtectData 不会修改入参
        // （Win32 API 历史包袱），这里临时 cast 是合法 idiom
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                std::ptr::null(),     // szDataDescr
                std::ptr::null_mut(), // pOptionalEntropy
                std::ptr::null_mut(), // pvReserved
                std::ptr::null_mut(), // pPromptStruct
                // K-R5: CURRENT_USER 范围（默认）+ CRYPTPROTECT_UI_FORBIDDEN
                // 禁止任何交互式 UI（如远端会话弹窗），守护 CLI/守护进程语义
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(map_dpapi_err());
        }
        // 拷出密文，再 LocalFree
        let cipher = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            LocalFree(output.pbData as _);
        }
        Ok(cipher)
    }

    /// DPAPI 解密（CURRENT_USER 范围）— 与 `dpapi_encrypt` 对称
    pub fn dpapi_decrypt(cipher: &[u8]) -> Result<Vec<u8>> {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: cipher.len() as u32,
            pbData: cipher.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(), // ppszDataDescr
                std::ptr::null_mut(), // pOptionalEntropy
                std::ptr::null_mut(), // pvReserved
                std::ptr::null_mut(), // pPromptStruct
                // K-R5: 与加密侧对齐，禁止交互式 UI
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(map_dpapi_err());
        }
        let plain = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            LocalFree(output.pbData as _);
        }
        Ok(plain)
    }
}

#[cfg(target_os = "windows")]
pub(crate) use win::{dpapi_decrypt, dpapi_encrypt};

/// 非 Windows 平台 stub — 仅用于编译通过 (CI/Linux 跑 schema 测试).
#[cfg(not(target_os = "windows"))]
pub(crate) fn dpapi_encrypt(_plain: &[u8]) -> Result<Vec<u8>> {
    Err(KeyError::dpapi_unavailable(b"(non-windows)"))
}

/// 非 Windows 平台 stub.
#[cfg(not(target_os = "windows"))]
pub(crate) fn dpapi_decrypt(_cipher: &[u8]) -> Result<Vec<u8>> {
    Err(KeyError::dpapi_unavailable(b"(non-windows)"))
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    /// CRYPTPROTECT_UI_FORBIDDEN 已加入 DPAPI 调用 (编译期+运行时双重验证).
    #[test]
    fn dpapi_uses_ui_forbidden_flag() {
        use windows_sys::Win32::Security::Cryptography::CRYPTPROTECT_UI_FORBIDDEN as FLAG;
        assert_ne!(FLAG, 0, "CRYPTPROTECT_UI_FORBIDDEN 应为非零标志");
        let plain = b"flag-test";
        let cipher = super::dpapi_encrypt(plain).expect("encrypt");
        let back = super::dpapi_decrypt(&cipher).expect("decrypt");
        assert_eq!(back, plain);
    }

    #[test]
    fn dpapi_roundtrip_preserves_bytes() {
        let plain = b"hello v3 cache, 64-char-hex placeholder \x00\x01\x02\xff";
        let cipher = super::dpapi_encrypt(plain).expect("encrypt");
        assert_ne!(cipher.as_slice(), plain, "密文不应等于明文");
        let back = super::dpapi_decrypt(&cipher).expect("decrypt");
        assert_eq!(back, plain);
    }

    #[test]
    fn dpapi_roundtrip_empty_bytes() {
        let plain: &[u8] = &[];
        let cipher = super::dpapi_encrypt(plain).expect("encrypt empty");
        let back = super::dpapi_decrypt(&cipher).expect("decrypt empty");
        assert_eq!(back, plain);
    }
}
