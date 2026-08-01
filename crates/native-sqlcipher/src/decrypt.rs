//! decrypt.rs — SQLCipher4 全页解密 → 明文 sqlite image (ADR-428 §2.2 / §4-b).
//!
//! 逐页 HMAC 校验 (坏页 / key 不对该库即报) + AES-256-CBC 解密, 拼成标准 sqlite 明文 image (内存).

use std::path::Path;

use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use native_keyscan::{KeyMaterial, PAGE, RESERVE, SQLCIPHER_ROUNDS_V4};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::SqlcipherError;
use crate::reader::DecryptedDb;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// 解密后明文 image 首页前 16B 固定 magic (替换加密库的 salt).
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const IV_LEN: usize = 16;
const HMAC_LEN: usize = 64;

/// 微信 V4 默认 KDF 轮数 (passphrase 路派生用; 调用方按版本传, 见 [`decrypt_db_to_image`]).
pub const DEFAULT_ROUNDS: u32 = SQLCIPHER_ROUNDS_V4;

/// 解密整库 → 明文 sqlite image (内存, 不落盘). 逐页 HMAC 校验.
///
/// `key`:
/// - `KeyKind::EncKey` 直用 — **须是该库的 enc_key** (enc_key per-db salt 派生, 锚点错则首页 HMAC 报);
/// - `KeyKind::Passphrase` + 库 salt 现场跑 PBKDF2 `rounds` 轮派生该库 enc_key.
///
/// **WAL 不合并** — 只解主库 = checkpoint 快照 (不含活跃 WAL 最新行). 要实时前沿 (合并已提交 WAL 帧)
/// 用 [`decrypt_db_to_image_with_wal`]. image 可交 [`crate::open_image`] 只读读出行 (M3-b reader).
///
/// # Errors
/// 见 [`SqlcipherError`] — 读文件 / 太小 / 非页对齐 / 某页 HMAC 不过 (key 错) / AES 失败.
pub fn decrypt_db_to_image(enc_db_path: &Path, key: &KeyMaterial, rounds: u32) -> Result<Vec<u8>, SqlcipherError> {
    Ok(decrypt_main(enc_db_path, key, rounds)?.0)
}

/// 解密整库 **并合并 `<db>-wal` 里已提交的增量帧** → 明文 image (实时前沿).
///
/// = [`decrypt_db_to_image`] 的 checkpoint 快照 **+** WAL 中当前周期已提交事务的最新页 (见 [`crate::wal`]).
/// 主库解密派生的 enc_key/mac_key 直接复用于 WAL 帧 (同一套页加密), 不重复跑 PBKDF2. WAL 缺失/空/无提交
/// → 等价 [`decrypt_db_to_image`] (退回快照). 供实时监听 (`--watch`) 拿未 checkpoint 的最新消息.
///
/// # Errors
/// 同 [`decrypt_db_to_image`], 外加读已存在 WAL 失败 / WAL 帧解密失败 (见 [`SqlcipherError`]).
pub fn decrypt_db_to_image_with_wal(
    enc_db_path: &Path,
    key: &KeyMaterial,
    rounds: u32,
) -> Result<Vec<u8>, SqlcipherError> {
    let (mut image, keys) = decrypt_main(enc_db_path, key, rounds)?;
    let wal_path = crate::wal::wal_sibling(enc_db_path);
    crate::wal::apply_wal_to_image(&mut image, &wal_path, &keys.enc_key, &keys.mac_key)?;
    Ok(image)
}

/// 主库解密派生的两把库级 key (Zeroizing 用完清零) — 供 WAL 合并复用, 免二次 PBKDF2-256000.
struct DerivedKeys {
    enc_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
}

/// 主库全页解密 (共享内核): 返回 (明文 image, 派生 key). [`decrypt_db_to_image`] 丢弃 key;
/// [`decrypt_db_to_image_with_wal`] 拿 key 去合并 WAL.
fn decrypt_main(enc_db_path: &Path, key: &KeyMaterial, rounds: u32) -> Result<(Vec<u8>, DerivedKeys), SqlcipherError> {
    let data =
        std::fs::read(enc_db_path).map_err(|e| SqlcipherError::Io(format!("{}: {e}", file_name(enc_db_path))))?;
    if data.len() < PAGE {
        return Err(SqlcipherError::TooSmall(PAGE));
    }
    if data.len() % PAGE != 0 {
        return Err(SqlcipherError::NotPageAligned {
            size: data.len(),
            page: PAGE,
        });
    }

    let salt = &data[..16];
    // §9: 走进程内派生 key 缓存 (同 master-key+salt+rounds 重开跳过 PBKDF2-256000; VFS 路同用)。
    let (enc_key, mac_key) = crate::keycache::derive_keys_cached(key, salt, rounds);

    let n_pages = data.len() / PAGE;
    let mut image = vec![0u8; data.len()]; // 全 0: reserve 区无需再清
                                           // SQLite 在 offset 0x40000000 (1GB) 有 lock-byte page (PENDING_BYTE): sqlite 从不读写其内容
                                           // (只拿来做文件锁), SQLCipher 也不加密它 → 逐页解密到此页会 HMAC 失败. 原样保留 (< 1GB 的库无此页).
    let lock_byte_page = 0x4000_0000_usize / PAGE + 1; // 1-based (= 262145 @ 4096)
    for idx in 0..n_pages {
        let page = &data[idx * PAGE..(idx + 1) * PAGE];
        let page_num = (idx + 1) as u32;
        let (lo, hi) = (idx * PAGE, (idx + 1) * PAGE);
        if idx + 1 == lock_byte_page {
            // lock-byte page: 未加密, 原样保留 (sqlite 不读其内容, 只做文件锁).
            image[lo..hi].copy_from_slice(page);
            continue;
        }
        verify_page_hmac(&mac_key, page, page_num)?;
        decrypt_page_into(&enc_key, page, idx == 0, page_num, &mut image[lo..hi])?;
    }
    Ok((image, DerivedKeys { enc_key, mac_key }))
}

/// 解密会话 (件2 三档缓存地基): 持解密后的**主库 pristine image** + 派生 key, 支持在**不重解主库**的
/// 前提下反复"克隆 pristine + 叠加当前 WAL"产出最新只读快照 (Path-2)。
///
/// 供实时轮询: 一个库开一次 [`DecryptSession::open`] (跑一次 PBKDF2-256000 + 全页 AES 解出 pristine);
/// 之后每次 WAL 变化只调 [`DecryptSession::snapshot_with_wal`] = clone pristine + apply WAL 已提交增量
/// (大库 ~3s 全解 → ~0.5s clone)。主库文件本身变了 (checkpoint) 才需重新 `open`。
///
/// **全程内存不落盘** (持 pristine `Vec`)。K-R4: enc_key/mac_key `Zeroizing` 清零; Debug 不露 image/key。
pub struct DecryptSession {
    enc_db_path: std::path::PathBuf,
    /// 主库 checkpoint 快照 (解密后, **不含 WAL**); 每次 snapshot 从它 clone, 自身保持 pristine.
    pristine: Vec<u8>,
    /// 该库派生的 enc_key + mac_key (Zeroizing); WAL 帧复用同一套.
    keys: DerivedKeys,
}

impl DecryptSession {
    /// 解密主库 → 持有 pristine image + 派生 key (一次性 PBKDF2 + 全页解密)。
    ///
    /// # Errors
    /// 见 [`SqlcipherError`] — 读文件 / key 错 (首页 HMAC) / 坏页.
    pub fn open(enc_db_path: &Path, key: &KeyMaterial, rounds: u32) -> Result<Self, SqlcipherError> {
        let (pristine, keys) = decrypt_main(enc_db_path, key, rounds)?;
        Ok(Self {
            enc_db_path: enc_db_path.to_path_buf(),
            pristine,
            keys,
        })
    }

    /// 克隆 pristine + 叠加当前 `<db>-wal` 已提交增量 → 只读挂载 (**实时前沿**)。不重解主库。
    ///
    /// # Errors
    /// 见 [`SqlcipherError`] — 读 WAL / WAL 帧解密 / sqlite 挂载失败.
    pub fn snapshot_with_wal(&self) -> Result<DecryptedDb, SqlcipherError> {
        let mut image = self.pristine.clone();
        let wal_path = crate::wal::wal_sibling(&self.enc_db_path);
        crate::wal::apply_wal_to_image(&mut image, &wal_path, &self.keys.enc_key, &self.keys.mac_key)?;
        crate::reader::open_image(image)
    }

    /// 只挂 pristine 快照 (**不含 WAL**, = checkpoint 快照)。
    ///
    /// # Errors
    /// 见 [`SqlcipherError`] — sqlite 挂载失败.
    pub fn snapshot(&self) -> Result<DecryptedDb, SqlcipherError> {
        crate::reader::open_image(self.pristine.clone())
    }

    /// pristine 主库物理页数 (× 4096 = 常驻内存字节, 供上层判断内存占用)。
    #[must_use]
    pub fn pristine_pages(&self) -> usize {
        self.pristine.len() / PAGE
    }
}

// K-R4: 不 derive Debug (DerivedKeys 无 Debug 且不该露 image/key); 只示文件名 + pristine 页数.
#[allow(clippy::missing_fields_in_debug)] // 故意不露 pristine/keys (安全); 只示非敏感元数据.
impl std::fmt::Debug for DecryptSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptSession")
            .field("db", &file_name(&self.enc_db_path))
            .field("pristine_pages", &self.pristine_pages())
            .finish()
    }
}

// enc_key/mac_key 派生已下沉 keycache::derive_keys_cached (§9: 进程内缓存 PBKDF2-256000; 字节等价原
// resolve_enc_key + derive_mac_key)。VFS 路 (vfs.rs) 同用一份。

/// 逐页 HMAC: HMAC-SHA512(mac_key, page[off..4032] ++ page_num_le) == page[4032..4096].
/// 首页 off=16 (跳 salt), 非首页 off=0. `pub(crate)`: WAL 帧复用同一校验 (wal.rs).
pub(crate) fn verify_page_hmac(mac_key: &[u8; 32], page: &[u8], page_num: u32) -> Result<(), SqlcipherError> {
    let off = if page_num == 1 { 16 } else { 0 };
    let hmac_start = PAGE - RESERVE + IV_LEN; // 4032
    let mut mac = <Hmac<Sha512>>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&page[off..hmac_start]);
    mac.update(&page_num.to_le_bytes());
    let computed = mac.finalize().into_bytes();
    let stored = &page[hmac_start..hmac_start + HMAC_LEN];
    if computed.as_slice() == stored {
        Ok(())
    } else {
        Err(SqlcipherError::PageHmacMismatch { page_num })
    }
}

/// 解密一页写入 `out` (4096B, 调用方已全 0):
/// 首页 = magic(16) + AES 解密 [16..4016]; 非首页 = AES 解密 [0..4016]; 尾 80B reserve 保持 0.
/// `pub(crate)`: WAL 帧复用同一页解密 (wal.rs); WAL 首页帧带 salt 头, 传 `is_first=true` 同主库 page1.
pub(crate) fn decrypt_page_into(
    enc_key: &[u8; 32],
    page: &[u8],
    is_first: bool,
    page_num: u32,
    out: &mut [u8],
) -> Result<(), SqlcipherError> {
    let iv_start = PAGE - RESERVE; // 4016
    let iv: [u8; 16] = page[iv_start..iv_start + IV_LEN].try_into().unwrap();
    let data_start = if is_first { 16 } else { 0 };
    let cipher = &page[data_start..PAGE - RESERVE]; // 首页 [16..4016], 非首页 [0..4016]
    let mut buf = cipher.to_vec();
    let plain = Aes256CbcDec::new(enc_key.into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| SqlcipherError::Decrypt { page_num })?;
    if is_first {
        out[..16].copy_from_slice(SQLITE_HEADER);
        out[16..16 + plain.len()].copy_from_slice(plain);
    } else {
        out[..plain.len()].copy_from_slice(plain);
    }
    Ok(())
}

/// K-R4: error 只放文件名, 不放含 wxid 的全路径.
fn file_name(p: &Path) -> String {
    p.file_name().and_then(|s| s.to_str()).unwrap_or("<db>").to_string()
}

#[cfg(test)]
mod tests {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use native_keyscan::MAC_SALT_XOR;
    use pbkdf2::pbkdf2_hmac;

    use super::*;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    /// 造一个合成加密库 (salt + n 页, 已知 enc_key) + 期望明文 image. 不涉真 key/256000 (走 EncKey 直用).
    fn synth_encrypted_db(enc_key: &[u8; 32], salt: &[u8; 16], n_pages: usize) -> (Vec<u8>, Vec<u8>) {
        let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ MAC_SALT_XOR).collect();
        let mut mac_key = [0u8; 32];
        pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);

        let mut db = Vec::new();
        let mut expect = Vec::new();
        for idx in 0..n_pages {
            let page_num = (idx + 1) as u32;
            let is_first = idx == 0;
            let body_len = if is_first { PAGE - RESERVE - 16 } else { PAGE - RESERVE }; // 4000 / 4016
            let mut body = vec![0u8; body_len];
            for (i, b) in body.iter_mut().enumerate() {
                *b = ((i + idx * 7) % 251) as u8;
            }
            let iv = [0x11u8 ^ (idx as u8); 16];
            let mut enc_buf = body.clone();
            let cipher = Aes256CbcEnc::new(enc_key.into(), (&iv).into())
                .encrypt_padded_mut::<NoPadding>(&mut enc_buf, body_len)
                .unwrap();

            let mut page = vec![0u8; PAGE];
            let data_start = if is_first { 16 } else { 0 };
            if is_first {
                page[..16].copy_from_slice(salt);
            }
            page[data_start..PAGE - RESERVE].copy_from_slice(cipher);
            page[PAGE - RESERVE..PAGE - RESERVE + 16].copy_from_slice(&iv);
            let off = if is_first { 16 } else { 0 };
            let mut mac = <Hmac<Sha512>>::new_from_slice(&mac_key).unwrap();
            mac.update(&page[off..PAGE - RESERVE + 16]);
            mac.update(&page_num.to_le_bytes());
            page[PAGE - RESERVE + 16..PAGE].copy_from_slice(&mac.finalize().into_bytes());
            db.extend_from_slice(&page);

            let mut img = vec![0u8; PAGE];
            if is_first {
                img[..16].copy_from_slice(SQLITE_HEADER);
                img[16..16 + body_len].copy_from_slice(&body);
            } else {
                img[..body_len].copy_from_slice(&body);
            }
            expect.extend_from_slice(&img);
        }
        (db, expect)
    }

    #[test]
    fn decrypt_roundtrip_multi_page() {
        let enc_key = [0x42u8; 32];
        let salt = [0x7au8; 16];
        let (db, expect) = synth_encrypted_db(&enc_key, &salt, 3);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &db).unwrap();
        let image = decrypt_db_to_image(tmp.path(), &KeyMaterial::enc_key(enc_key), DEFAULT_ROUNDS).unwrap();
        assert_eq!(image.len(), expect.len());
        assert_eq!(&image[..16], SQLITE_HEADER, "首页 magic 替换");
        assert_eq!(&image[PAGE - RESERVE..PAGE], &[0u8; RESERVE], "首页 reserve 区清零");
        assert_eq!(image, expect, "全页解密应逐字节还原明文 image");
    }

    #[test]
    fn decrypt_wrong_key_first_page_hmac_fails() {
        let (db, _) = synth_encrypted_db(&[0x42; 32], &[0x7a; 16], 2);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &db).unwrap();
        let err = decrypt_db_to_image(tmp.path(), &KeyMaterial::enc_key([0x99; 32]), DEFAULT_ROUNDS).unwrap_err();
        assert!(
            matches!(err, SqlcipherError::PageHmacMismatch { page_num: 1 }),
            "错 key 应首页 HMAC 报错, 实际 {err:?}"
        );
    }

    #[test]
    fn rejects_non_page_aligned() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), vec![0u8; PAGE + 100]).unwrap();
        let err = decrypt_db_to_image(tmp.path(), &KeyMaterial::enc_key([0; 32]), DEFAULT_ROUNDS).unwrap_err();
        assert!(matches!(err, SqlcipherError::NotPageAligned { .. }));
    }

    #[test]
    fn rejects_too_small() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), vec![0u8; 100]).unwrap();
        let err = decrypt_db_to_image(tmp.path(), &KeyMaterial::enc_key([0; 32]), DEFAULT_ROUNDS).unwrap_err();
        assert!(matches!(err, SqlcipherError::TooSmall(_)));
    }

    /// lock-byte page 位置锚定 — SQLite PENDING_BYTE=0x40000000 (1GB) 处的保留页, 1-based 页号
    /// @ 4096 = 262145. 解密须跳过它 (不加密/不 HMAC, 原样保留). 防常量误改; 实际跨此页解密
    /// 由 message_0.db 1GB 真跑验证 (117 万条读通, 无此跳过则第 262145 页 HMAC 报错).
    #[test]
    fn lock_byte_page_position() {
        assert_eq!(0x4000_0000_usize / PAGE + 1, 262_145);
    }
}
