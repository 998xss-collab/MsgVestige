//! 表情包 (自定义 emoji/贴图) 解密 — 微信自定义表情**不在本地明文存**, 是从 CDN 下载加密字节再 AES-128-CBC
//! 解密 (竞品 WCDA `media_helpers.py:390` 同款: 本地文件与消息 md5 零匹配, WCDA 自己也是下载 encrypt_url 再解)。
//!
//! ## 模型 (真数据实测 2026-07-04, emoticon.db 6/6 通)
//! `emoticon.db` `kNonStoreEmoticonTable` 存每个表情的 `md5` + `aes_key`(32 hex=16 字节) + 若干 CDN URL
//! (`encrypt_url`/`cdn_url`/`extern_url`, 实测 **http** 非 https)。流程: 下载 URL 的加密字节 → **AES-128-CBC
//! (iv=key) + PKCS7 unpad** → GIF/PNG 真图。
//!
//! **本模块只做纯解密 + 读 db 拿 (md5, aes_key, urls)**; HTTP 下载在 cli 层 (native-core 不碰网络, 同 ffmpeg 子进程)。
//!
//! ## K-R4
//! `aes_key` 是解密密钥 → [`EmoticonRef`] Debug 里 sha8 脱敏; 解出的表情内容 (用户贴图) 本模块只返字节不打印。

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use rusqlite::Connection;

use crate::key_provider::sha8;

/// 一个待下载解密的表情引用 (从 emoticon.db 读出)。
#[derive(Clone)]
pub struct EmoticonRef {
    /// 表情 md5 (32 hex; 输出文件名主干, 非 PII)。
    pub md5: String,
    /// AES-128 key (32 hex 字符 = 16 字节; CBC 解密用, iv 也用它)。
    pub aes_key: String,
    /// CDN URL 候选 (encrypt_url → cdn_url → extern_url 优先序; cli 逐个试下载)。
    pub urls: Vec<String>,
}

// K-R4: aes_key 是密钥 → 只露 sha8; urls 是 CDN 路径 (弱敏感) 只露个数。
impl std::fmt::Debug for EmoticonRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmoticonRef")
            .field("md5", &self.md5)
            .field("aes_key_sha8", &sha8(self.aes_key.as_bytes()))
            .field("urls", &self.urls.len())
            .finish()
    }
}

/// AES-128-CBC 解密 (只用 aes crate, 不引 cbc): 逐块 ECB 解 → XOR 前一密文块 (首块 XOR iv)。data 长须 16 倍数。
fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        out.extend_from_slice(&block);
        prev.copy_from_slice(chunk); // 下一块的"前一密文块"= 本块密文
    }
    out
}

/// 剥 PKCS7 padding, **严格** (codex P2): pad ∈ 1..=16 且尾部 pad 字节全等, 非法 → `None`。表情包解密
/// 要严格 —— 错 key/URL 解出的垃圾 (padding 几乎必不合法) 被拒 → cli 换下一 URL 候选, 而非落垃圾图。
fn pkcs7_unpad_strict(mut data: Vec<u8>) -> Option<Vec<u8>> {
    let &pad = data.last()?;
    let pad = pad as usize;
    if !(1..=16).contains(&pad) || pad > data.len() {
        return None;
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return None;
    }
    data.truncate(data.len() - pad);
    Some(data)
}

/// 解密表情包 CDN 下载的加密字节: AES-128-CBC (iv=key) + PKCS7 unpad。
///
/// `aes_key_hex` = emoticon.db / 消息 `<emoji aeskey>` 的 32 hex 字符 (= 16 字节 key)。
/// 返 `None`: key 非法 (非 32 hex) / data 空或非 16 倍数 (CBC 前提)。**infallible** (解出不校验图头, 交调用方判)。
#[must_use]
pub fn decrypt_emoticon(data: &[u8], aes_key_hex: &str) -> Option<Vec<u8>> {
    let khex = aes_key_hex.trim();
    if khex.len() != 32 || !khex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let raw = hex::decode(khex).ok()?;
    let key: [u8; 16] = raw.try_into().ok()?;
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return None; // CBC 密文须整块
    }
    // 微信约定 iv = key; 严格 PKCS7 → 错 key 解出的垃圾被拒 (None), cli 据此换下一 URL。
    pkcs7_unpad_strict(aes128_cbc_decrypt(&key, &key, data))
}

/// 读 `emoticon.db` 的 `kNonStoreEmoticonTable` 得所有 (md5, aes_key, url 候选)。
/// 过滤掉无 aes_key 的行 (无 key 解不了)。URL 候选优先序 encrypt_url → cdn_url → extern_url (只收 http/https)。
pub fn read_emoticons(conn: &Connection) -> rusqlite::Result<Vec<EmoticonRef>> {
    let mut stmt = conn.prepare(
        "SELECT md5, aes_key, encrypt_url, cdn_url, extern_url FROM kNonStoreEmoticonTable \
         WHERE aes_key IS NOT NULL AND aes_key != ''",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (md5, aes_key, enc, cdn, ext) = row?;
        // md5 校验 32 hex (codex P2: 输出文件名安全 + 数据合法性; 非法行跳)。
        let md5 = md5.trim().to_ascii_lowercase();
        if md5.len() != 32 || !md5.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let aes_key = aes_key.trim().to_string();
        if aes_key.is_empty() {
            continue; // 纯空白 key (过了 SQL 的 != '' 但 trim 后空) → 跳
        }
        // URL 候选 trim 后再过滤 (codex P2: 带首尾空白的 http URL 别被误滤)。
        let urls: Vec<String> = [enc, cdn, ext]
            .into_iter()
            .flatten()
            .map(|u| u.trim().to_string())
            .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
            .collect();
        if urls.is_empty() {
            continue; // 无可下载 URL → 跳
        }
        out.push(EmoticonRef { md5, aes_key, urls });
    }
    Ok(out)
}

/// 读 `emoticon.db` 里指定 md5 的**单条**表情引用 (serve `/media/emoji:` 用: 每请求只取一条, 不必读全表解码 —— 同
/// [`super::read_sns_media_ref_one`] 的单行模式)。无该行 / 无 aes_key / 无 http url / md5 非 32-hex → `Ok(None)`。
/// 表不存在 → rusqlite 上抛 (交调用方)。md5 匹配大小写/首尾空白无关 (与 [`read_emoticons`] 清洗一致)。
///
/// # Errors
/// rusqlite 查询失败 (含表不存在)。
pub fn read_emoticon_one(conn: &Connection, md5: &str) -> rusqlite::Result<Option<EmoticonRef>> {
    use rusqlite::OptionalExtension as _;
    let want = md5.trim().to_ascii_lowercase();
    let row = conn
        .query_row(
            "SELECT md5, aes_key, encrypt_url, cdn_url, extern_url FROM kNonStoreEmoticonTable \
             WHERE lower(trim(md5)) = ?1 AND aes_key IS NOT NULL AND aes_key != ''",
            rusqlite::params![want],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((md5, aes_key, enc, cdn, ext)) = row else {
        return Ok(None);
    };
    // 与 read_emoticons 同款清洗 (md5 32-hex / aes_key trim 非空 / http url 候选)。
    let md5 = md5.trim().to_ascii_lowercase();
    if md5.len() != 32 || !md5.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let aes_key = aes_key.trim().to_string();
    if aes_key.is_empty() {
        return Ok(None);
    }
    let urls: Vec<String> = [enc, cdn, ext]
        .into_iter()
        .flatten()
        .map(|u| u.trim().to_string())
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
        .collect();
    if urls.is_empty() {
        return Ok(None);
    }
    Ok(Some(EmoticonRef { md5, aes_key, urls }))
}

#[cfg(test)]
mod tests {
    use aes::cipher::BlockEncrypt;

    use super::*;

    /// 用 aes crate 造 CBC 密文 (iv=key, PKCS7) — 验 decrypt_emoticon 能还原。
    fn cbc_encrypt(key: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        // PKCS7 pad 到 16 倍数。
        let pad = 16 - (plain.len() % 16);
        let mut padded = plain.to_vec();
        padded.extend(std::iter::repeat(pad as u8).take(pad));
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut out = Vec::new();
        let mut prev = *key; // iv = key
        for chunk in padded.chunks_exact(16) {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ prev[i];
            }
            let mut ga = GenericArray::clone_from_slice(&block);
            cipher.encrypt_block(&mut ga);
            out.extend_from_slice(&ga);
            prev.copy_from_slice(&ga);
        }
        out
    }

    #[test]
    fn cbc_roundtrip_recovers_plaintext() {
        let key = b"0123456789abcdef";
        let khex = "30313233343536373839616263646566"; // hex of the 16 ASCII bytes
        let plain = b"GIF89a\x01\x02 fake sticker bytes \xff\xff test payload!";
        let ct = cbc_encrypt(key, plain);
        let out = decrypt_emoticon(&ct, khex).unwrap();
        assert_eq!(out, plain, "CBC(iv=key)+PKCS7 还原");
    }

    #[test]
    fn rejects_bad_key_and_misaligned() {
        let ct = vec![0u8; 32];
        assert!(decrypt_emoticon(&ct, "short").is_none(), "非 32 hex key → None");
        assert!(
            decrypt_emoticon(&ct, "zz313233343536373839616263646566").is_none(),
            "非 hex → None"
        );
        assert!(
            decrypt_emoticon(&[0u8; 20], "30313233343536373839616263646566").is_none(),
            "非 16 倍数 → None"
        );
        assert!(
            decrypt_emoticon(&[], "30313233343536373839616263646566").is_none(),
            "空 → None"
        );
    }

    #[test]
    fn read_emoticons_filters_and_orders_urls() {
        let aa = "a".repeat(32); // 合法 32-hex md5
        let bb = "b".repeat(32);
        let cc = "c".repeat(32);
        let dd = "d".repeat(32);
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE kNonStoreEmoticonTable (md5 TEXT, aes_key TEXT, encrypt_url TEXT, cdn_url TEXT, extern_url TEXT);").unwrap();
        let ins = |md5: &str, key: &str, e: Option<&str>, cd: Option<&str>, x: Option<&str>| {
            c.execute(
                "INSERT INTO kNonStoreEmoticonTable VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![md5, key, e, cd, x],
            )
            .unwrap();
        };
        ins(&aa, "key1", Some("  http://enc/1 "), Some("http://cdn/1"), None); // 带空白 URL → trim 后留
        ins(&bb, "  ", Some("http://x"), None, None); // 纯空白 aes_key → 滤
        ins(&cc, "key3", None, None, None); // 无 URL → 滤
        ins(&dd, "key4", None, Some("ftp://bad"), Some("http://ext/4")); // ftp 滤, 留 http extern
        ins("nothex_zz", "key5", Some("http://y"), None, None); // 非 32-hex md5 → 滤 (codex P2)

        let refs = read_emoticons(&c).unwrap();
        assert_eq!(refs.len(), 2, "只留 32-hex md5 + 有 aes_key + 有 http URL (aa, dd)");
        let ra = refs.iter().find(|r| r.md5 == aa).unwrap();
        assert_eq!(
            ra.urls,
            vec!["http://enc/1", "http://cdn/1"],
            "URL trim + encrypt 优先 cdn"
        );
        let rd = refs.iter().find(|r| r.md5 == dd).unwrap();
        assert_eq!(rd.urls, vec!["http://ext/4"], "ftp 滤掉只留 http extern_url");
    }

    #[test]
    fn debug_redacts_aes_key() {
        let r = EmoticonRef {
            md5: "abc".into(),
            aes_key: "30313233343536373839616263646566".into(),
            urls: vec!["http://x".into()],
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("30313233"), "K-R4: aes_key 原值不进 Debug");
        assert!(dbg.contains("aes_key_sha8"));
    }
}
