//! decoder::dat — 微信本地图片 `.dat` 解密 (V0 单字节 XOR / V1 固定 AES / V2 三段 AES+XOR)。
//!
//! 微信 PC 把聊天图片以私有 `.dat` 容器落盘, 四种编码 (05-图片解密方法.md §1), 判定靠文件头前 6 字节:
//! - **V0**(无头): 整文件单字节 XOR; key 从图头 magic 反推 (JPEG 0xFF / PNG 0x89 / GIF 0x47)。
//! - **V1**(`\x07\x08V1\x08\x07`): AES-128-ECB+PKCS7, key = 固定常量 `cfcd208495d565ef` (16 ASCII 字节)。
//! - **V2**(`\x07\x08V2\x08\x07`): **三段** — `[15:15+aes_aligned]` AES-128-ECB+PKCS7(账号级 image key)+
//!   `[..:len-xor_size]` raw 原样 + 尾 `xor_size` 字节单字节 XOR。
//! - WXGF(`wxgf` 头): 解出后是 HEVC 容器需再转码 — **本 mod 不做**(留后, 走 ffmpeg 路)。
//!
//! ## ⚠️ V2 对齐坑 (05-图片解密方法.md §5.2, 实战踩过)
//! `aes_aligned = (aes_size / 16 + 1) * 16` — aes_size 已是 16 倍数时**仍 +16**(PKCS7 总补一整块)。
//! 误用 `(aes_size + 15) / 16 * 16` 会让 aes_size 整除时从 `offset = aes_size` 起花 16 字节 (头尾合法但中间乱)。
//!
//! ## key 语义 (05-图片解密方法.md §5.3)
//! V2 AES key = **账号级 image key**(从微信进程内存扫/wx_key 取, 一装一把固定), **不是**消息 aeskey(那是
//! 表情包/CDN 用)。本 mod 收 [`ImageKey`] 作参数, key 提取在别处 (native-keyscan)。
//!
//! ## K-R4
//! 解出的是**用户自己的图片明文** — 本 mod 返 [`DecodedImage`] 字节, 不打印内容; ImageKey Debug 脱敏。

use std::fmt;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;

use crate::key_provider::sha8;

/// V1 固定 AES key (`md5("0")` 前 16 ASCII 字符, 直接当 key 不 hex-decode)。
const V1_FIXED_KEY: &[u8; 16] = b"cfcd208495d565ef";

/// 图片 .dat 解密 key (V2 用; V0/V1 不需要 aes)。
#[derive(Clone, Copy)]
pub struct ImageKey {
    /// 账号级 image AES-128 key (16 字节; wx_key/内存扫取)。
    pub aes: [u8; 16],
    /// V2 尾段单字节 XOR key (wx_key 给, 或 JPEG 尾反推)。
    pub xor: u8,
}

// K-R4: key 是敏感材料 → Debug 只露 sha8。
impl fmt::Debug for ImageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageKey")
            .field("aes_sha8", &sha8(&self.aes))
            .field("xor", &self.xor)
            .finish()
    }
}

/// .dat 编码代数。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DatVersion {
    /// 无头, 整文件单字节 XOR。
    V0,
    /// `\x07\x08V1\x08\x07`, 固定 AES key。
    V1,
    /// `\x07\x08V2\x08\x07`, 三段 AES+XOR。
    V2,
    /// 已是明文图片 (jpg/png/gif 头) — 不用解。
    Plain,
    /// WXGF 容器 (需再转码, 本 mod 不解)。
    Wxgf,
}

/// 从文件头判代数。
#[must_use]
pub fn detect_version(data: &[u8]) -> DatVersion {
    if data.len() >= 6 && &data[..6] == b"\x07\x08V1\x08\x07" {
        DatVersion::V1
    } else if data.len() >= 6 && &data[..6] == b"\x07\x08V2\x08\x07" {
        DatVersion::V2
    } else if data.len() >= 4 && &data[..4] == b"wxgf" {
        DatVersion::Wxgf
    } else if detect_format(data) != DatFormat::Unknown {
        DatVersion::Plain
    } else {
        DatVersion::V0
    }
}

/// 解出图片格式 (按首字节 magic)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DatFormat {
    Jpg,
    Png,
    Gif,
    Webp,
    Bmp,
    /// 微信动图/动态贴图容器 (`wxgf` magic, 内层 HEVC) — 直接可播不了, 需 ffmpeg 转码成 GIF (cli 层做)。
    Wxgf,
    Unknown,
}

impl DatFormat {
    /// 文件扩展名。
    #[must_use]
    pub fn ext(self) -> &'static str {
        match self {
            DatFormat::Jpg => "jpg",
            DatFormat::Png => "png",
            DatFormat::Gif => "gif",
            DatFormat::Webp => "webp",
            DatFormat::Bmp => "bmp",
            DatFormat::Wxgf => "wxgf",
            DatFormat::Unknown => "bin",
        }
    }
}

/// 按 magic 判图片格式。
#[must_use]
pub fn detect_format(b: &[u8]) -> DatFormat {
    if b.len() >= 3 && b[..3] == [0xFF, 0xD8, 0xFF] {
        DatFormat::Jpg
    } else if b.len() >= 8 && b[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        DatFormat::Png
    } else if b.len() >= 6 && (&b[..6] == b"GIF87a" || &b[..6] == b"GIF89a") {
        DatFormat::Gif
    } else if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        DatFormat::Webp
    } else if b.len() >= 4 && &b[..4] == b"wxgf" {
        // 微信动图容器 (V2 内层实测约占该账号完整图一半; ffmpeg 认它作 HEVC 可转 GIF)。
        DatFormat::Wxgf
    } else if b.len() >= 2 && &b[..2] == b"BM" {
        DatFormat::Bmp
    } else {
        DatFormat::Unknown
    }
}

/// 解密结果 (图字节 + 格式)。
#[derive(Clone, PartialEq, Eq)]
pub struct DecodedImage {
    pub bytes: Vec<u8>,
    pub format: DatFormat,
}

// K-R4: 内容不进 Debug (用户图片明文), 只露长度 + 格式。
impl fmt::Debug for DecodedImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedImage")
            .field("len", &self.bytes.len())
            .field("format", &self.format)
            .finish()
    }
}

/// .dat 解密错误。
#[derive(Debug, thiserror::Error)]
pub enum DatError {
    /// 空 / 太短。
    #[error("dat too short: {0} bytes")]
    TooShort(usize),
    /// V2 需 image key 但没给。
    #[error("V2 dat needs image key")]
    MissingKey,
    /// header 声明的段长越界 (畸形 / 截断)。
    #[error("V2 segment lengths out of bounds (aes_size={aes} xor_size={xor} len={len})")]
    BadSegments { aes: usize, xor: usize, len: usize },
    /// WXGF 容器需转码, 本 mod 不解。
    #[error("wxgf container needs transcode (not handled here)")]
    Wxgf,
    /// V0 无法从图头反推 XOR key。
    #[error("V0 xor key not derivable (no known image magic)")]
    V0KeyUnknown,
}

/// AES-128-ECB 逐块解密 (data 长须 16 倍数)。
fn aes128_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

/// 剥 PKCS7 padding (最后一字节 = pad 长 1..=16; 非法则原样返回, 宽松)。
fn pkcs7_unpad(mut data: Vec<u8>) -> Vec<u8> {
    let Some(&pad) = data.last() else { return data };
    let pad = pad as usize;
    if (1..=16).contains(&pad) && pad <= data.len() && data[data.len() - pad..].iter().all(|&b| b as usize == pad) {
        data.truncate(data.len() - pad);
    }
    data
}

/// V0 单字节 XOR: 从图头 magic 反推 key (WXGF/JPEG/PNG/GIF), 整文件异或。
///
/// **⚠️ WXGF 必须收 + 放最前, 且去掉弱 BMP (2026-07-04 真机逮到)**: 微信 wxgf 动图/HEVC 图除 V2 三段头存储外,
/// 还有**整文件单字节 XOR** 存储 (头如 `a4 ab b4 b5` = "wxgf" XOR 0xD3)。本账号实测 ~852 张这种被漏 (含唯一
/// 一张真动图), 因 export_full_images 早先只认 V2 头。修 = V0 加 wxgf magic 反推。**放最前**: wxgf 是 4 字节
/// 强 magic; 早先的弱 BMP (`"BM"` 2 字节) 会把 XOR-WXGF 误匹配成 BMP (a4^e6=B, ab^e6=M) 落垃圾图 → **去掉 BMP**
/// (微信 0 张 BMP, 是假匹配源; BMP 仍在 detect_format 供明文 passthrough)。
fn decrypt_v0(data: &[u8]) -> Result<DecodedImage, DatError> {
    if data.is_empty() {
        return Err(DatError::TooShort(0));
    }
    // 候选: (magic, magic 首字节). 用 cipher[0]^首字节 得 key, 再校验整段 magic + detect_format。全 ≥3 字节强 magic。
    let candidates: [(&[u8], u8); 4] = [
        (b"wxgf", 0x77),             // WXGF 容器 (整文件 XOR 式; 强 4 字节, 放最前防弱 magic 抢匹配)
        (&[0xFF, 0xD8, 0xFF], 0xFF), // JPEG
        (&[0x89, 0x50, 0x4E], 0x89), // PNG
        (b"GIF", 0x47),              // GIF
    ];
    for (magic, first) in candidates {
        // codex P1: 文件须 ≥ magic 长 (否则短文件缺字节被"跳过"误判命中)。
        if data.len() < magic.len() {
            continue;
        }
        let key = data[0] ^ first;
        if magic.iter().enumerate().all(|(i, &m)| (data[i] ^ key) == m) {
            let bytes: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            // codex P2: 解出后要 detect_format 确认是真图 (整头校验), 挡短 magic (BMP 2B) 误判。
            let format = detect_format(&bytes);
            if format != DatFormat::Unknown {
                return Ok(DecodedImage { bytes, format });
            }
        }
    }
    Err(DatError::V0KeyUnknown)
}

/// V1/V2 通用三段解密 (aes_key 由调用方定: V1 固定 / V2 image key)。
fn decrypt_segmented(data: &[u8], aes_key: &[u8; 16], xor_key: u8) -> Result<DecodedImage, DatError> {
    // header: [6 magic][4 aes_size LE][4 xor_size LE][1 pad] = 15 字节。
    if data.len() < 15 {
        return Err(DatError::TooShort(data.len()));
    }
    let aes_size = u32::from_le_bytes([data[6], data[7], data[8], data[9]]) as usize;
    let xor_size = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
    // ⚠️ 对齐: 总进到下一个 16 倍数 (PKCS7 总补一整块; 05-图片解密方法.md §5.2)。
    // codex P1: checked 算术 — 防 32-bit usize 下巨大 aes_size 溢出 panic (x64 不触发, 防御性)。
    let bad = || DatError::BadSegments {
        aes: aes_size,
        xor: xor_size,
        len: data.len(),
    };
    let aes_aligned = (aes_size / 16 + 1).checked_mul(16).ok_or_else(bad)?;
    let off = 15usize;
    let raw_start = off.checked_add(aes_aligned).ok_or_else(bad)?;
    let raw_end = data.len().checked_sub(xor_size).ok_or_else(bad)?;
    if raw_start > data.len() || raw_end < raw_start {
        return Err(bad());
    }
    // 段① AES-128-ECB + unpad。
    let aes_part = pkcs7_unpad(aes128_ecb_decrypt(aes_key, &data[off..raw_start]));
    // 段② raw 原样。
    let raw_middle = &data[raw_start..raw_end];
    // 段③ 单字节 XOR。
    let xor_part: Vec<u8> = data[raw_end..].iter().map(|&b| b ^ xor_key).collect();
    let mut bytes = Vec::with_capacity(aes_part.len() + raw_middle.len() + xor_part.len());
    bytes.extend_from_slice(&aes_part);
    bytes.extend_from_slice(raw_middle);
    bytes.extend_from_slice(&xor_part);
    let format = detect_format(&bytes);
    Ok(DecodedImage { bytes, format })
}

/// 解密一个 `.dat` 文件字节 → 图片。V2 需 [`ImageKey`](V0/V1 传 None 也行)。
///
/// # Errors
/// [`DatError`] — 太短 / V2 缺 key / 段越界 / WXGF 需转码 / V0 key 不可推。
pub fn decrypt_dat(data: &[u8], key: Option<&ImageKey>) -> Result<DecodedImage, DatError> {
    match detect_version(data) {
        DatVersion::Plain => Ok(DecodedImage {
            bytes: data.to_vec(),
            format: detect_format(data),
        }),
        // 原始 wxgf .dat (整文件即 wxgf 动图容器, 未加密) — 内容原样返回 (format=Wxgf), 交上层 ffmpeg 转码。
        // (常见情形是 V2 .dat 解密后内层才是 wxgf, 走 V2 分支 → detect_format 自动判 Wxgf。)
        DatVersion::Wxgf => Ok(DecodedImage {
            bytes: data.to_vec(),
            format: DatFormat::Wxgf,
        }),
        DatVersion::V0 => decrypt_v0(data),
        DatVersion::V1 => {
            // V1 固定 key; xor key 取 image key 给的或 0 (V1 通常无 xor 尾; xor_size=0 则段③空)。
            let xor = key.map_or(0, |k| k.xor);
            decrypt_segmented(data, V1_FIXED_KEY, xor)
        }
        DatVersion::V2 => {
            let k = key.ok_or(DatError::MissingKey)?;
            decrypt_segmented(data, &k.aes, k.xor)
        }
    }
}

/// 从一张 V2 sample 反推账号级 XOR key: 用已知 AES key 解出图格式 → 由**图尾 magic** 反推尾段单字节 XOR。
///
/// V2 尾段 (`xor_size` 字节) 是单字节 XOR, 其明文就是图片文件的**结尾**。JPEG 恒以 `FF D9` 结束、PNG 恒以
/// `IEND` chunk (`...AE 42 60 82`) 结束 → 尾字节明文已知 → `xor = 密文尾字节 ^ 已知明文尾字节`。反推后**全解一遍**
/// 确认解出的图字节确实以该 magic 结尾 (挡尾段跨界/格式误判)。
///
/// 返 `None`: 非 V2 / 无 xor 尾 (`xor_size==0`, 这张推不出) / 解出非 JPEG·PNG (尾 magic 未知) / 反推后尾 magic 对不上。
/// 调用方对多张 sample 逐张试, 取第一张成功的 (账号级 xor 对所有 V2 一致)。
#[must_use]
pub fn derive_v2_xor(sample: &[u8], aes: &[u8; 16]) -> Option<u8> {
    if detect_version(sample) != DatVersion::V2 || sample.len() < 15 {
        return None;
    }
    // 无 xor 尾 → 尾字节落在 raw 段 (未加密), 反推出的是伪 xor, 会污染其它有尾的图 → 拒 (换下一张)。
    let xor_size = u32::from_le_bytes([sample[10], sample[11], sample[12], sample[13]]) as usize;
    if xor_size == 0 {
        return None;
    }
    // 先用 xor=0 探格式: xor 只影响尾段, detect_format 看的是 AES 头 → 格式判定不受 xor 影响。
    let probe = decrypt_dat(sample, Some(&ImageKey { aes: *aes, xor: 0 })).ok()?;
    // 只认尾 magic 确定的格式 (JPEG `FF D9` / PNG `IEND`+CRC); GIF `3B`/WEBP 尾不稳, 不推 → 换下一张。
    let tail_magic: &[u8] = match probe.format {
        DatFormat::Jpg => &[0xFF, 0xD9],
        DatFormat::Png => &[0xAE, 0x42, 0x60, 0x82], // IEND chunk 尾 4 字节 (含 CRC32)
        _ => return None,
    };
    // 密文最末字节 ^ 明文最末字节 = xor key (最末字节必在 xor 尾段内, 因 xor_size>=1)。
    let xor = sample[sample.len() - 1] ^ tail_magic[tail_magic.len() - 1];
    // 全解验证: 用推出的 xor 完整解密, 图字节须以该格式尾 magic 结尾 (xor 错则尾巴乱 → 不 ends_with)。
    let full = decrypt_dat(sample, Some(&ImageKey { aes: *aes, xor })).ok()?;
    full.bytes.ends_with(tail_magic).then_some(xor)
}

/// 测试样本构造 (V2 .dat 反向封装 + fake JPEG)。`pub(crate)` 供本 mod 与 media::image_export 测试共用。
#[cfg(test)]
pub(crate) mod test_support {
    use aes::cipher::{BlockEncrypt, KeyInit};

    use super::{Aes128, GenericArray, ImageKey};

    /// AES-128-ECB 加密 (造 V2 测试样本用)。
    fn aes128_ecb_encrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut out = Vec::new();
        for chunk in data.chunks_exact(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
        }
        out
    }

    /// 造一个三段 .dat (V1/V2 通用): 给定 magic + aes_key + xor_key + 原图明文, 反向封装。
    pub(crate) fn make_segmented(
        magic: [u8; 6],
        aes_key: &[u8; 16],
        xor_key: u8,
        plain: &[u8],
        aes_size: usize,
        xor_size: usize,
    ) -> Vec<u8> {
        assert!(aes_size + xor_size <= plain.len());
        let aes_seg = &plain[..aes_size];
        let mid = &plain[aes_size..plain.len() - xor_size];
        let xor_seg = &plain[plain.len() - xor_size..];
        // 段① PKCS7 pad 到 (aes_size/16+1)*16 再 AES-ECB 加密。
        let aligned = (aes_size / 16 + 1) * 16;
        let mut padded = aes_seg.to_vec();
        let pad = aligned - aes_size;
        padded.extend(std::iter::repeat(pad as u8).take(pad));
        let enc = aes128_ecb_encrypt(aes_key, &padded);
        let xored: Vec<u8> = xor_seg.iter().map(|&b| b ^ xor_key).collect();
        let mut out = Vec::new();
        out.extend_from_slice(&magic);
        out.extend_from_slice(&(aes_size as u32).to_le_bytes());
        out.extend_from_slice(&(xor_size as u32).to_le_bytes());
        out.push(0); // pad byte
        out.extend_from_slice(&enc);
        out.extend_from_slice(mid);
        out.extend_from_slice(&xored);
        out
    }

    /// 造一张 V2 .dat (用给定 image key 三段封装 `plain`)。
    pub(crate) fn make_v2(plain: &[u8], key: &ImageKey, aes_size: usize, xor_size: usize) -> Vec<u8> {
        make_segmented(*b"\x07\x08V2\x08\x07", &key.aes, key.xor, plain, aes_size, xor_size)
    }

    /// FFD8FF 头 + 可复现内容 + FFD9 尾 = 合法 JPEG 结构 (非随机, 便于逐字节断言)。
    pub(crate) fn fake_jpeg(len: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
        for i in 4..len - 2 {
            v.push((i * 37 + 11) as u8);
        }
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{fake_jpeg, make_segmented, make_v2};
    use super::*;

    #[test]
    fn v2_roundtrip_aligned_and_unaligned() {
        let key = ImageKey {
            aes: *b"f55dbb3da8a161c6",
            xor: 0xD3,
        };
        // aes_size 恰整除 (1024) — 踩对齐坑的场景。
        let plain = fake_jpeg(5000);
        for aes_size in [1024usize, 1020, 16, 48] {
            let xor_size = 500;
            let dat = make_v2(&plain, &key, aes_size, xor_size);
            let out = decrypt_dat(&dat, Some(&key)).unwrap();
            assert_eq!(
                out.bytes, plain,
                "V2 roundtrip aes_size={aes_size} 应逐字节还原 (对齐坑防线)"
            );
            assert_eq!(out.format, DatFormat::Jpg);
        }
    }

    /// codex P2: V1 固定 key `cfcd208495d565ef` 三段结构 roundtrip (锁死 V1 走 decrypt_segmented 对)。
    #[test]
    fn v1_fixed_key_roundtrip() {
        let plain = fake_jpeg(4000);
        // V1 用固定 key 封装; xor_key 用 0 (V1 通常无 xor 尾, 这里给个非零验尾段也通)。
        let dat = make_segmented(*b"\x07\x08V1\x08\x07", V1_FIXED_KEY, 0x11, &plain, 1024, 300);
        // decrypt_dat 对 V1 从 ImageKey 取 xor (aes 用固定 key 忽略传入 aes)。
        let key = ImageKey {
            aes: [0; 16],
            xor: 0x11,
        };
        let out = decrypt_dat(&dat, Some(&key)).unwrap();
        assert_eq!(out.bytes, plain, "V1 固定 key 三段 roundtrip 逐字节还原");
        assert_eq!(out.format, DatFormat::Jpg);
    }

    #[test]
    fn v0_short_file_not_false_positive() {
        // codex P1: 短于 magic 的文件不该误判成 V0 图 (以前 i>=len 跳过会误命中)。
        assert!(matches!(
            decrypt_dat(&[0x00], None),
            Err(DatError::V0KeyUnknown | DatError::TooShort(_))
        ));
        assert!(matches!(decrypt_dat(&[0x00, 0x11], None), Err(DatError::V0KeyUnknown)));
    }

    #[test]
    fn v2_missing_key_errors() {
        let key = ImageKey {
            aes: *b"f55dbb3da8a161c6",
            xor: 0xD3,
        };
        let dat = make_v2(&fake_jpeg(3000), &key, 1024, 300);
        assert!(matches!(decrypt_dat(&dat, None), Err(DatError::MissingKey)));
    }

    #[test]
    fn v2_bad_segments_errors() {
        // header 声明 aes_size 巨大越界。
        let mut dat = vec![0x07, 0x08, b'V', b'2', 0x08, 0x07];
        dat.extend_from_slice(&999_999u32.to_le_bytes()); // aes_size 越界
        dat.extend_from_slice(&0u32.to_le_bytes());
        dat.push(0);
        dat.extend_from_slice(&[0u8; 32]);
        let key = ImageKey { aes: [0; 16], xor: 0 };
        assert!(matches!(
            decrypt_dat(&dat, Some(&key)),
            Err(DatError::BadSegments { .. })
        ));
    }

    #[test]
    fn derive_v2_xor_recovers_from_jpeg_tail() {
        // 账号 xor 从 JPEG 尾 (FF D9) 反推: 造已知 xor 的 V2, derive 应还原同一 xor。
        let key = ImageKey {
            aes: *b"f55dbb3da8a161c6",
            xor: 0xD3,
        };
        let plain = fake_jpeg(5000); // 结尾恒 FF D9
        let dat = make_v2(&plain, &key, 1024, 500); // xor 尾 500 字节含 FF D9
        assert_eq!(derive_v2_xor(&dat, &key.aes), Some(0xD3), "从 JPEG 尾反推账号 xor");

        // AES key 错 → 头解不出 JPEG (格式 Unknown) → 尾 magic 未知 → None (不瞎推)。
        assert_eq!(derive_v2_xor(&dat, b"0000000000000000"), None, "AES 错 → 头非图 → None");

        // 非图明文 (全 0, 无 FF D9 尾) → 格式 Unknown → None。
        let dat2 = make_v2(&vec![0u8; 5000], &key, 1024, 500);
        assert_eq!(derive_v2_xor(&dat2, &key.aes), None, "非图 → None");

        // xor_size==0 (无尾) → 尾字节落 raw 段, 反推的是伪值 → 拒 (None)。
        let dat3 = make_v2(&plain, &key, 1024, 0);
        assert_eq!(derive_v2_xor(&dat3, &key.aes), None, "无 xor 尾 → None");

        // 非 V2 (明文 JPEG) → None。
        assert_eq!(derive_v2_xor(&plain, &key.aes), None, "非 V2 → None");
    }

    #[test]
    fn v0_xor_roundtrip() {
        // 造 V0: 明文 jpeg ^ 0x5A。
        let plain = fake_jpeg(200);
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ 0x5A).collect();
        let out = decrypt_dat(&enc, None).unwrap();
        assert_eq!(out.bytes, plain, "V0 单字节 XOR 从图头反推 key 还原");
        assert_eq!(out.format, DatFormat::Jpg);
    }

    #[test]
    fn v0_xor_wxgf_decoded() {
        // 修 bug: 整文件单字节 XOR 的 wxgf (头 a4 ab b4 b5 = "wxgf" ^ 0xD3) → V0 magic 反推 → Wxgf。
        let mut plain = b"wxgf\x12\x00\x02\x07".to_vec(); // 0x12 = 动图
        plain.extend((0..300u32).map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8));
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ 0xD3).collect();
        assert_eq!(
            &enc[..4],
            &[0xa4, 0xab, 0xb4, 0xb5],
            "wxgf ^ 0xD3 = a4 ab b4 b5 (漏解 bug 的头特征)"
        );
        let out = decrypt_dat(&enc, None).unwrap();
        assert_eq!(out.format, DatFormat::Wxgf, "V0-XOR-wxgf → Wxgf (不再漏/不再误判 BMP)");
        assert_eq!(out.bytes, plain, "解出 = 原 wxgf 字节");
        // key-agnostic: 换个 XOR key 也能反推 (magic 反推自适应任意 key)。
        let enc2: Vec<u8> = plain.iter().map(|&b| b ^ 0x5A).collect();
        assert_eq!(
            decrypt_dat(&enc2, None).unwrap().format,
            DatFormat::Wxgf,
            "任意 XOR key 的 wxgf 都反推"
        );
    }

    #[test]
    fn detect_version_and_format() {
        assert_eq!(detect_version(b"\x07\x08V2\x08\x07ssssssss"), DatVersion::V2);
        assert_eq!(detect_version(b"\x07\x08V1\x08\x07ssssssss"), DatVersion::V1);
        assert_eq!(detect_version(b"wxgf1234"), DatVersion::Wxgf);
        assert_eq!(detect_version(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0]), DatVersion::Plain);
        assert_eq!(detect_format(&[0xFF, 0xD8, 0xFF]), DatFormat::Jpg);
        assert_eq!(detect_format(b"GIF89a-"), DatFormat::Gif);
        assert_eq!(DatFormat::Png.ext(), "png");
    }

    #[test]
    fn wxgf_returned_as_content_for_transcode() {
        // 原始 wxgf .dat: 不再报错, 内容原样返回 format=Wxgf (交上层 ffmpeg 转码)。
        let out = decrypt_dat(b"wxgf\x13\x00\x02\x07hevc-stream", None).unwrap();
        assert_eq!(out.format, DatFormat::Wxgf);
        assert_eq!(out.bytes, b"wxgf\x13\x00\x02\x07hevc-stream");
        assert_eq!(DatFormat::Wxgf.ext(), "wxgf");
        // V2 .dat 解密后内层是 wxgf → detect_format 自动判 Wxgf。
        assert_eq!(detect_format(b"wxgf\x13\x00\x02\x07"), DatFormat::Wxgf);
    }

    #[test]
    fn plain_image_passthrough() {
        let jpg = fake_jpeg(100);
        let out = decrypt_dat(&jpg, None).unwrap();
        assert_eq!(out.bytes, jpg, "已明文图片原样返回");
        assert_eq!(out.format, DatFormat::Jpg);
    }

    #[test]
    fn k_r4_debug_redacts_key_and_content() {
        let key = ImageKey {
            aes: *b"f55dbb3da8a161c6",
            xor: 0xD3,
        };
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("f55dbb3da8a161c6"), "K-R4: ImageKey Debug 泄裸 key");
        assert!(dbg.contains("aes_sha8"));
        let img = DecodedImage {
            bytes: fake_jpeg(500),
            format: DatFormat::Jpg,
        };
        let dbg = format!("{img:?}");
        assert!(
            dbg.contains("len") && dbg.contains("Jpg"),
            "DecodedImage Debug 只露 len+格式"
        );
    }
}
