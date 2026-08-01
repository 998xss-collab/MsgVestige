//! `ImageKeyCache` — 图片 `.dat` V2 解密的 image key (aes+xor) 按账号 DPAPI 加密缓存。
//!
//! **独立于 master key 缓存** (`keys.enc`): 单独 `image_keys.enc` —— 往 master `KeyEntry` 加字段会让旧
//! `keys.enc` bincode 反序列化失败 = 用户已缓存 master key 全清空要重 auth, 故**分文件零迁移**。
//! 同 K-R4/K-R5: DPAPI CURRENT_USER 范围 + aes 不入 log (走 `sha8`) + Drop 清零。
//! 对标 WDA (每账号存 image_aes_key + image_xor_key, key_service 按 wxid 匹配, 扫到落盘)。
//!
//! image key = **V2 完整图专用** (V0 缩略图 / V1 / 明文不需 key); serve `/media/img` 有 cache key 才解 V2 完整图。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::error::KeyError;
use super::{dpapi, sha8, Wxid};
use crate::decoder::ImageKey;

type Result<T> = std::result::Result<T, KeyError>;

const SCHEMA_VERSION: u32 = 1;

/// image key 缓存 (schema v1; 外层 DPAPI 密文 → 内层 bincode, 同 master cache)。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImageKeyCacheV1 {
    schema_version: u32,
    entries: HashMap<Wxid, ImageKeyEntry>,
}

impl Default for ImageKeyCacheV1 {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            entries: HashMap::new(),
        }
    }
}

/// 单账号 image key 条目。
#[derive(Clone, Serialize, Deserialize)]
struct ImageKeyEntry {
    /// 32 hex = 16 字节账号级 AES-128 key (V2 `.dat` 解密; 整文件 DPAPI 加密, 本字段内存明文)。
    aes_hex: String,
    /// V2 尾段单字节 XOR key。
    xor: u8,
    /// unix seconds。
    created_at: i64,
    /// 取源 ("scan" 内存扫 / "manual" 手填)。
    source: String,
}

// K-R4 (§8 审查修): aes_hex 是明文 key 材料 → **手写脱敏 Debug 只露 sha8** (同 ImageKey/MasterKey/Wxid), 防将来
// 某句 `tracing::debug!(?entry)` / `dbg!` 把 32-hex AES key 明文写进日志。derive(Debug) 会全露 aes_hex, 故不 derive。
impl std::fmt::Debug for ImageKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageKeyEntry")
            .field("aes_sha8", &sha8(self.aes_hex.as_bytes()))
            .field("xor", &self.xor)
            .field("created_at", &self.created_at)
            .field("source", &self.source)
            .finish()
    }
}

// K-R4: aes_hex 敏感材料 → Drop 清零 (同 master `KeyEntry`)。
impl Drop for ImageKeyEntry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.aes_hex.zeroize();
    }
}

/// 图片 image key 缓存 (DPAPI 加密文件, **独立于** master `keys.enc`)。
pub struct ImageKeyCache {
    path: PathBuf,
}

impl ImageKeyCache {
    /// `path` 省 → 默认 [`Self::default_path`] (与 master keys.enc 同目录的 `image_keys.enc`)。
    #[must_use]
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path: path.unwrap_or_else(Self::default_path),
        }
    }

    /// 默认路径: `%LOCALAPPDATA%\msgvestige\cache\image_keys.enc` (与 master `keys.enc` 同目录, 不同名)。
    #[must_use]
    pub fn default_path() -> PathBuf {
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local")))
            .unwrap_or_else(|| PathBuf::from("."));
        local.join("msgvestige").join("cache").join("image_keys.enc")
    }

    fn now_secs() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    }

    /// 存一个账号的 image key (aes 16 字节 + xor)。已存则覆盖 —— image key 会随微信版本/换机变, 不做 master
    /// cache 那种"红线#3 不可变" (那是为 master key provenance; image key 刷新是正常的)。
    ///
    /// # Errors
    /// DPAPI 加密 / 写盘失败。
    pub fn store(&self, wxid: &Wxid, aes: &[u8; 16], xor: u8, source: &str) -> Result<()> {
        let mut cache = Self::load(&self.path)?;
        cache.entries.insert(
            wxid.clone(),
            ImageKeyEntry {
                aes_hex: hex_encode(aes),
                xor,
                created_at: Self::now_secs(),
                source: source.to_string(),
            },
        );
        Self::save(&self.path, &cache)?;
        tracing::info!(
            wxid_sha = %sha8(wxid.as_str().as_bytes()),
            source,
            "ImageKeyCache.store: 存账号 image key"
        );
        Ok(())
    }

    /// 取一个账号的 image key。无此账号 / cache 损坏 (备份后返空) / aes 非法 → `Ok(None)`。
    ///
    /// # Errors
    /// 读盘失败 (DPAPI/bincode 损坏在 load 内已备份+返空 → 不 Err)。
    pub fn resolve(&self, wxid: &Wxid) -> Result<Option<ImageKey>> {
        let cache = Self::load(&self.path)?;
        let Some(entry) = cache.entries.get(wxid) else {
            return Ok(None);
        };
        let Some(aes) = hex_decode16(&entry.aes_hex) else {
            return Ok(None);
        };
        Ok(Some(ImageKey { aes, xor: entry.xor }))
    }

    fn load(path: &Path) -> Result<ImageKeyCacheV1> {
        if !path.exists() {
            return Ok(ImageKeyCacheV1::default());
        }
        let bytes = std::fs::read(path).map_err(KeyError::from)?;
        // 损坏 (DPAPI 解密失败 / bincode 反序列化失败 / schema 不匹配) → 备份 + 返空 (同 master cache 兜底)。
        let Ok(plain) = dpapi::dpapi_decrypt(&bytes) else {
            let _ = std::fs::rename(path, path.with_extension("enc.bak"));
            return Ok(ImageKeyCacheV1::default());
        };
        match bincode::deserialize::<ImageKeyCacheV1>(&plain) {
            Ok(c) if c.schema_version == SCHEMA_VERSION => Ok(c),
            _ => {
                let _ = std::fs::rename(path, path.with_extension("enc.bak"));
                Ok(ImageKeyCacheV1::default())
            }
        }
    }

    fn save(path: &Path, cache: &ImageKeyCacheV1) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(KeyError::from)?;
        }
        let plain = bincode::serialize(cache).map_err(|_| {
            KeyError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bincode serialize failed",
            ))
        })?;
        let cipher = dpapi::dpapi_encrypt(&plain)?;
        std::fs::write(path, cipher).map_err(KeyError::from)?;
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn hex_decode16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// store → resolve 往返: 存的 aes/xor 能原样取回 (DPAPI + bincode 闭环)。
    #[test]
    fn store_then_resolve_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("nk_imgcache_{}.enc", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let cache = ImageKeyCache::new(Some(tmp.clone()));
        let wxid = Wxid::try_new("wxid_test").unwrap();
        let aes = *b"f55dbb3da8a161c6";
        cache.store(&wxid, &aes, 0xD3, "manual").unwrap();
        let got = cache.resolve(&wxid).unwrap().expect("命中");
        assert_eq!(got.aes, aes, "aes 原样取回");
        assert_eq!(got.xor, 0xD3, "xor 原样取回");
        // 别的账号 → None。
        assert!(
            cache.resolve(&Wxid::try_new("wxid_other").unwrap()).unwrap().is_none(),
            "无此账号 → None"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// 文件不存在 → resolve None (不 Err)。
    #[test]
    fn resolve_missing_file_is_none() {
        let tmp = std::env::temp_dir().join(format!("nk_imgcache_absent_{}.enc", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let cache = ImageKeyCache::new(Some(tmp));
        assert!(cache.resolve(&Wxid::try_new("wxid_x").unwrap()).unwrap().is_none());
    }

    #[test]
    fn hex_roundtrip() {
        let aes = *b"f55dbb3da8a161c6";
        assert_eq!(hex_decode16(&hex_encode(&aes)), Some(aes));
        assert_eq!(hex_decode16("short"), None);
        assert_eq!(hex_decode16(&"z".repeat(32)), None, "非 hex → None");
    }
}
