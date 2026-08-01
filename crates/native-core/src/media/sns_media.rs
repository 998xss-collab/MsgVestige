//! SNS 朋友圈媒体解密 (ADR-467 件3) — CDN 下载的加密图/视频 XOR 解密 (微信 WxIsaac64 keystream)。
//!
//! **native-core 只做纯解密 + keystream (node 子进程, 同 ffmpeg) + 读 moment_media; HTTP 下载在 cli 层**
//! (同 [`super::emoticon`]: native-core 不碰网络)。
//!
//! ## 模型 (真库坐实 + 竞品 WeChatDataAnalysis sns_media.py / CipherTalk snsService)
//! moment_media 存 url/token/enc_idx/url_key/media_type。下载 url = `{url}?token={token}&idx={enc_idx}`
//! (真机实测: 缺 token 或缺 idx 都 HTTP 400)。**enc_idx=1 才加密**: 图 = WxIsaac64 keystream 全文 XOR;
//! 视频 = 只 XOR 前 128KB (竞品同款)。enc_idx=0 = 明文, 下载即用不解 (解了反而毁)。
//!
//! ## ⚠️ keystream = 微信 WxIsaac64 (可移植性代价)
//! 微信的 WxIsaac64 **不是标准 ISAAC64** (实测公开 python/TS 实现均对不上, 只在微信编译的 WASM 里对) →
//! 必须 spawn `node` 跑 vendor 的 `weflow_wasm_keystream.js` (加载 wasm_video_decode.wasm)。**运行期依赖 node**
//! (换机器需装 node; 用户 2026-07-05 拍板『全支持·环境不自带』)。无本地缓存图 (.dat) 那样的纯 Rust 路。
//!
//! ## K-R4
//! url/token/url_key 是资源引用/解密密钥 → [`SnsMediaRef`] Debug sha8; 解出的图字节本模块只返不打印。

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use base64::Engine;
use rusqlite::Connection;

use crate::key_provider::sha8;

/// 视频只加密前 128KB (竞品 sns_media.py `maybe_decrypt_sns_video_file`)。
const VIDEO_ENC_PREFIX: usize = 128 * 1024;
/// node keystream 子进程有界 deadline (media §8: 挂死不占死 serve 信号量) + stdout 上限 (keystream base64 ≤ ~4/3×size,
/// size≤100MB → ~133MB; 封顶 160MB 防无界缓冲)。
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_STDOUT_CAP: u64 = 160 * 1024 * 1024;

/// 一条待下载解密的 SNS 媒体引用 (从 moment_media 读出)。
#[derive(Clone)]
pub struct SnsMediaRef {
    /// 所属 moment PK (`Sns_<tid>`; 输出文件名/归属)。
    pub source_native_id: String,
    /// mediaList 内序号 (输出文件名区分)。
    pub media_seq: i64,
    /// 媒体类型 (2=图 / 6=视频; 决定全文 XOR vs 前 128KB)。
    pub media_type: i64,
    /// 内容 md5 (输出文件名主干, 非 PII; 可空)。
    pub md5: Option<String>,
    /// 全图/视频下载 url (`<url>` 文本; 必有才可下)。
    pub url: String,
    /// CDN 下载 token (拼 `?token=`; 可空 → 可能 400)。
    pub token: Option<String>,
    /// 加密索引 ("0"=明文不解 / "1"=加密需 XOR)。
    pub enc_idx: String,
    /// WxIsaac64 keystream key (`<url key=>`; 加密媒体必需; 可空/"0"=无 → 视为明文)。
    pub url_key: Option<String>,
}

// K-R4: url/token/url_key 资源引用/密钥 → sha8; md5 是文件名主干 (非 PII, 同 emoticon) 保留; seq/type 明文。
impl std::fmt::Debug for SnsMediaRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnsMediaRef")
            .field("source_native_id", &self.source_native_id)
            .field("media_seq", &self.media_seq)
            .field("media_type", &self.media_type)
            .field("md5", &self.md5)
            .field("url_sha8", &sha8(self.url.as_bytes()))
            .field("token_sha8", &self.token.as_deref().map(|t| sha8(t.as_bytes())))
            .field("enc_idx", &self.enc_idx)
            .field("url_key_sha8", &self.url_key.as_deref().map(|k| sha8(k.as_bytes())))
            .finish()
    }
}

/// SNS 媒体解密错误 (K-R4: 不露 url/key 明文)。
#[derive(Debug, thiserror::Error)]
pub enum SnsMediaError {
    /// node keystream 子进程失败 (spawn / 非零退出 / 无 node)。`what` 非敏感 (io kind / exit code)。
    #[error("WxIsaac64 keystream (node) 失败: {what}")]
    Node { what: String },
    /// node 输出的 base64 keystream 解码失败。
    #[error("keystream base64 解码失败")]
    Base64,
    /// 加密媒体缺 url_key (enc_idx=1 但无 key)。
    #[error("加密媒体缺 url_key")]
    MissingKey,
}

/// 拼 SNS 下载 url: `{url}?token={token}&idx={enc_idx}` (真机实测缺 token/idx 都 400)。
///
/// url 已含 `?` 则用 `&` 追加 (稳健)。token 缺则不拼 token 段 (可能 400, 交调用方判)。
#[must_use]
pub fn build_download_url(url: &str, token: Option<&str>, enc_idx: &str) -> String {
    let mut u = url.to_string();
    let mut sep = if url.contains('?') { '&' } else { '?' };
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        u.push(sep);
        u.push_str("token=");
        u.push_str(t);
        sep = '&';
    }
    u.push(sep);
    u.push_str("idx=");
    u.push_str(enc_idx);
    u
}

/// 决定用哪个 node: 优先**随包携带**的, 回退系统 PATH。
///
/// 候选顺序 (跟 ffmpeg 的 vendor-优先一个路子):
/// 1. 环境变量 `WECHAT_NODE` —— 显式指定, 最高优先。
/// 2. exe 同目录的 `vendor/node.exe` / `node.exe` —— 完整版发布包的布局。
/// 3. 裸 `node` —— 交给 PATH 解析 (系统装了 node 的情况)。
///
/// 返回 `PathBuf` 而非 `&str`: 候选 2 是绝对路径。找不到任何一个时返回裸 `node`, 让
/// spawn 失败后走 [`SnsMediaError::Node`] 的正常错误路径 —— 这里不提前报错, 因为
/// "有没有 node" 要等真去 spawn 才算数 (PATH 上可能有我们看不到的)。
fn resolve_node() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os("WECHAT_NODE") {
        return std::path::PathBuf::from(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for cand in [dir.join("vendor").join("node.exe"), dir.join("node.exe")] {
                if cand.is_file() {
                    return cand;
                }
            }
        }
    }
    std::path::PathBuf::from("node")
}

/// spawn `node <script> <key> <size>` 生成 WxIsaac64 keystream (size 字节; 脚本内已对齐+反转+截断)。
///
/// `node_script` = vendor 的 `weflow_wasm_keystream.js` (同目录须有 wasm_video_decode.wasm/.js)。
/// stdout = base64 keystream。
///
/// **node 从哪来**: 先找**跟 exe 同目录的 `vendor/node.exe`**(完整版发布包里带了一份), 找不到才
/// 回退系统 PATH 上的 `node`。原先只有后者 —— 于是完整版包里那个 87MB 的 node.exe 是**死的**:
/// 代码从不查它, 用户在没装 node 的机器上照样跑不了, 而包内清单还写着「完整版都带上了」。
/// (审查方实测: 清空 PATH 后从完整版包目录跑, `where node` 找不到, 功能不可用。)
///
/// # Errors
/// [`SnsMediaError::Node`] (spawn/退出失败) / [`SnsMediaError::Base64`] (输出非法 base64)。
pub fn sns_keystream(node_script: &Path, key: &str, size: usize) -> Result<Vec<u8>, SnsMediaError> {
    let mut cmd = Command::new(resolve_node());
    cmd.arg(node_script).arg(key).arg(size.to_string());
    // 有界 deadline + stdout 上限 (media §8: node 挂死/大输出不占死 serve 信号量)。超时/非零退出/spawn 失败 → Node。
    let stdout =
        super::subprocess::output_with_timeout(cmd, NODE_TIMEOUT, NODE_STDOUT_CAP).ok_or(SnsMediaError::Node {
            what: "超时 / 非零退出 / spawn 失败".into(),
        })?;
    base64::engine::general_purpose::STANDARD
        .decode(stdout.trim_ascii())
        .map_err(|_| SnsMediaError::Base64)
}

/// 用 keystream XOR 解密下载的加密字节 (纯函数, 无子进程/网络; 图全文 / 视频前 128KB)。
///
/// `media_type` 6=视频 (只 XOR 前 128KB) 其余=图 (全文 XOR)。keystream 须 ≥ XOR 长度 (由调用方按此长度取)。
#[must_use]
pub fn xor_decrypt(mut enc: Vec<u8>, keystream: &[u8], media_type: i64) -> Vec<u8> {
    let xor_len = xor_len_for(media_type, enc.len());
    for (b, k) in enc[..xor_len].iter_mut().zip(keystream.iter()) {
        *b ^= *k;
    }
    enc
}

/// XOR 长度: 视频 (type 6) 前 128KB, 其余全文。
#[must_use]
pub fn xor_len_for(media_type: i64, enc_len: usize) -> usize {
    if media_type == 6 {
        enc_len.min(VIDEO_ENC_PREFIX)
    } else {
        enc_len
    }
}

/// 解密下载的 SNS 媒体 (enc_idx≠"1" → 原样明文; 否则 node keystream + XOR)。
///
/// `enc` = 已下载的字节; `node_script` = vendor keystream 脚本。
///
/// # Errors
/// [`SnsMediaError::MissingKey`] (加密但无 key) / [`SnsMediaError::Node`] / [`SnsMediaError::Base64`]。
pub fn decrypt_sns_media(enc: Vec<u8>, media: &SnsMediaRef, node_script: &Path) -> Result<Vec<u8>, SnsMediaError> {
    // enc_idx 0 (或非 1) = 明文, 下载即用不解 (解了反而毁 — 竞品 sns_media.py 同 guard)。
    if media.enc_idx != "1" {
        return Ok(enc);
    }
    let key = media
        .url_key
        .as_deref()
        .filter(|k| !k.is_empty() && *k != "0")
        .ok_or(SnsMediaError::MissingKey)?;
    let xor_len = xor_len_for(media.media_type, enc.len());
    let ks = sns_keystream(node_script, key, xor_len)?;
    // 双审件3 P2-1: 校验 keystream 长度 (node 脚本异常返短 keystream 会让 xor_decrypt 的 zip 静默只解前段,
    //  产半明文坏图)。虽 cli 图头校验兜得住, 显式 fail 坐实契约。`what` 非敏感 (只长度)。
    if ks.len() < xor_len {
        return Err(SnsMediaError::Node {
            what: format!("keystream 短 ({} < {xor_len})", ks.len()),
        });
    }
    Ok(xor_decrypt(enc, &ks, media.media_type))
}

/// 读 moment_media 得所有有 url 的媒体引用 (cli 下载解密用; 按 moment PK + seq 稳定排序)。
///
/// # Errors
/// rusqlite 查询失败。
pub fn read_sns_media_refs(conn: &Connection) -> rusqlite::Result<Vec<SnsMediaRef>> {
    let mut stmt = conn.prepare(
        "SELECT source_native_id, media_seq, media_type, md5, url, token, enc_idx, url_key \
         FROM moment_media WHERE url IS NOT NULL AND url != '' \
         ORDER BY source_native_id, media_seq",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(SnsMediaRef {
            source_native_id: r.get(0)?,
            media_seq: r.get(1)?,
            media_type: r.get(2)?,
            md5: r.get(3)?,
            url: r.get(4)?,
            token: r.get(5)?,
            enc_idx: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            url_key: r.get(7)?,
        })
    })?;
    rows.collect()
}

/// 读 moment_media 里指定 `(source_native_id, media_seq)` 的**单条**媒体引用 (serve `/media/moment:` 用: 每请求
/// 只取一条, 不必读全表)。无该行 / url 空 → `Ok(None)`。moment_media 表不存在 (L1 未 `adapter --sns` 投影) →
/// rusqlite "no such table" 上抛 (交调用方映 NeedsIngest, 语义正确: 需先投影)。
///
/// # Errors
/// rusqlite 查询失败 (含表不存在)。
pub fn read_sns_media_ref_one(
    conn: &Connection,
    source_native_id: &str,
    media_seq: i64,
) -> rusqlite::Result<Option<SnsMediaRef>> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT source_native_id, media_seq, media_type, md5, url, token, enc_idx, url_key \
         FROM moment_media WHERE source_native_id = ?1 AND media_seq = ?2 \
         AND url IS NOT NULL AND url != ''",
        rusqlite::params![source_native_id, media_seq],
        |r| {
            Ok(SnsMediaRef {
                source_native_id: r.get(0)?,
                media_seq: r.get(1)?,
                media_type: r.get(2)?,
                md5: r.get(3)?,
                url: r.get(4)?,
                token: r.get(5)?,
                enc_idx: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                url_key: r.get(7)?,
            })
        },
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_token_and_idx() {
        assert_eq!(
            build_download_url("http://x/0", Some("TK"), "1"),
            "http://x/0?token=TK&idx=1"
        );
        // url 已含 ? → 用 &。
        assert_eq!(
            build_download_url("http://x/0?a=1", Some("TK"), "1"),
            "http://x/0?a=1&token=TK&idx=1"
        );
        // 无 token → 只拼 idx。
        assert_eq!(build_download_url("http://x/0", None, "0"), "http://x/0?idx=0");
    }

    #[test]
    fn xor_len_video_vs_image() {
        assert_eq!(xor_len_for(2, 50_000), 50_000, "图全文");
        assert_eq!(xor_len_for(6, 50_000), 50_000, "视频 <128KB 全文");
        assert_eq!(xor_len_for(6, 300_000), VIDEO_ENC_PREFIX, "视频 >128KB 只前 128KB");
    }

    #[test]
    fn xor_decrypt_image_full() {
        let enc = vec![0xAA; 100];
        let ks = vec![0xFF; 100];
        let dec = xor_decrypt(enc, &ks, 2);
        assert!(dec.iter().all(|&b| b == 0x55), "0xAA^0xFF=0x55 全文");
    }

    #[test]
    fn xor_decrypt_video_only_prefix() {
        // 视频: 前 128KB XOR, 之后原样。
        let mut enc = vec![0xAA; VIDEO_ENC_PREFIX + 100];
        for b in &mut enc[VIDEO_ENC_PREFIX..] {
            *b = 0x11; // 尾部标记
        }
        let ks = vec![0xFF; VIDEO_ENC_PREFIX];
        let dec = xor_decrypt(enc, &ks, 6);
        assert!(dec[..VIDEO_ENC_PREFIX].iter().all(|&b| b == 0x55), "前 128KB 解");
        assert!(dec[VIDEO_ENC_PREFIX..].iter().all(|&b| b == 0x11), "128KB 后原样不动");
    }

    #[test]
    fn decrypt_plaintext_passthrough() {
        // enc_idx=0 (明文) → 原样返回不解 (无需 node)。
        let m = SnsMediaRef {
            source_native_id: "Sns_1".into(),
            media_seq: 0,
            media_type: 2,
            md5: None,
            url: "http://x/0".into(),
            token: None,
            enc_idx: "0".into(),
            url_key: Some("0".into()),
        };
        let enc = vec![1, 2, 3];
        let out = decrypt_sns_media(enc.clone(), &m, Path::new("/nonexistent")).unwrap();
        assert_eq!(out, enc, "明文原样 (不 spawn node)");
    }

    #[test]
    fn decrypt_encrypted_missing_key_errs() {
        let m = SnsMediaRef {
            source_native_id: "Sns_1".into(),
            media_seq: 0,
            media_type: 2,
            md5: None,
            url: "http://x/0".into(),
            token: None,
            enc_idx: "1".into(),
            url_key: Some("0".into()), // "0" = 无有效 key
        };
        match decrypt_sns_media(vec![1, 2, 3], &m, Path::new("/x")) {
            Err(SnsMediaError::MissingKey) => {}
            other => panic!("加密无 key 应 MissingKey, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_url_token_key() {
        let m = SnsMediaRef {
            source_native_id: "Sns_1".into(),
            media_seq: 0,
            media_type: 2,
            md5: Some("abc123".into()),
            url: "http://secret.cdn/path".into(),
            token: Some("SECRETTOKEN".into()),
            enc_idx: "1".into(),
            url_key: Some("2437692427012835906".into()),
        };
        let dbg = format!("{m:?}");
        for raw in ["secret.cdn", "SECRETTOKEN", "2437692427012835906"] {
            assert!(!dbg.contains(raw), "K-R4: SnsMediaRef Debug 泄 {raw}");
        }
        assert!(dbg.contains("url_sha8") && dbg.contains("token_sha8") && dbg.contains("url_key_sha8"));
        assert!(dbg.contains("abc123"), "md5 是文件名主干保留");
    }

    #[test]
    fn read_refs_filters_no_url() {
        let c = Connection::open_in_memory().unwrap();
        crate::storage::init_moment_media_table(&c).unwrap();
        let mut m = crate::storage::V3MomentMedia {
            account_id_sha: "acct".into(),
            source: "sns.db".into(),
            source_native_id: "Sns_1".into(),
            media_seq: 0,
            media_type: 2,
            account_id: "wxid".into(),
            media_id: None,
            url: Some("http://x/0".into()),
            thumb_url: None,
            md5: Some("m".into()),
            video_md5: None,
            url_key: Some("K".into()),
            enc_idx: Some("1".into()),
            token: Some("TK".into()),
            enc_key: None,
            width: 0,
            height: 0,
            total_size: 0,
            video_duration: None,
        };
        crate::storage::insert_moment_media(&c, &m).unwrap();
        m.media_seq = 1;
        m.url = None; // 无 url → 不进 refs
        crate::storage::insert_moment_media(&c, &m).unwrap();
        let refs = read_sns_media_refs(&c).unwrap();
        assert_eq!(refs.len(), 1, "只留有 url 的");
        assert_eq!(refs[0].enc_idx, "1");
        assert_eq!(refs[0].url_key.as_deref(), Some("K"));
    }

    #[test]
    fn read_one_targets_single_row() {
        let c = Connection::open_in_memory().unwrap();
        crate::storage::init_moment_media_table(&c).unwrap();
        let mk = |seq: i64, ty: i64, url: Option<&str>| crate::storage::V3MomentMedia {
            account_id_sha: "acct".into(),
            source: "sns.db".into(),
            source_native_id: "Sns_7".into(),
            media_seq: seq,
            media_type: ty,
            account_id: "wxid".into(),
            media_id: None,
            url: url.map(Into::into),
            thumb_url: None,
            md5: Some("m".into()),
            video_md5: None,
            url_key: Some("K".into()),
            enc_idx: Some("1".into()),
            token: Some("TK".into()),
            enc_key: None,
            width: 0,
            height: 0,
            total_size: 0,
            video_duration: None,
        };
        crate::storage::insert_moment_media(&c, &mk(0, 2, Some("http://x/img"))).unwrap();
        crate::storage::insert_moment_media(&c, &mk(1, 6, Some("http://x/vid"))).unwrap();
        crate::storage::insert_moment_media(&c, &mk(2, 2, None)).unwrap(); // 无 url
                                                                           // 精准命中 seq=1 (视频): 只返这一条, 不受同 sid 别的 seq 干扰。
        let r = read_sns_media_ref_one(&c, "Sns_7", 1).unwrap().unwrap();
        assert_eq!((r.media_type, r.url.as_str()), (6, "http://x/vid"));
        assert!(
            read_sns_media_ref_one(&c, "Sns_7", 2).unwrap().is_none(),
            "无 url 行 → None"
        );
        assert!(
            read_sns_media_ref_one(&c, "Sns_7", 9).unwrap().is_none(),
            "无此 seq → None"
        );
        assert!(
            read_sns_media_ref_one(&c, "Sns_X", 0).unwrap().is_none(),
            "无此 sid → None"
        );
        // 表不存在 → Err 上抛 (serve 映 NeedsIngest, 语义=需先 adapter --sns 投影)。
        let empty = Connection::open_in_memory().unwrap();
        assert!(
            read_sns_media_ref_one(&empty, "Sns_7", 0).is_err(),
            "moment_media 表不存在 → Err"
        );
    }
}
