//! wal.rs — 把加密 `<db>-wal` 里**已提交**的增量帧应用到解密后的内存 image (实时读取地基).
//!
//! 微信/WCDB 频繁 checkpoint, 主库解密出的是"checkpoint 快照"(见 decrypt.rs); 最新几笔事务
//! 常还压在 WAL 里未刷盘. 读 WAL 才能拿到实时前沿 (真库实测: media_1.db 主库仅 1 页空壳, 全部
//! 18 页内容都在 WAL). SQLCipher4 的 WAL 帧与主库**同一套页加密** (同 enc_key/mac_key), 故本模块
//! 直接复用 decrypt.rs 的 [`crate::decrypt::verify_page_hmac`] + [`crate::decrypt::decrypt_page_into`],
//! **零新增 crypto**.
//!
//! ## WAL 帧格式 (SQLite 标准, big-endian)
//! - WAL header 32B: magic(4)+format(4)+**page_sz(4)@8**+ckpt_seq(4)+**salt1(4)@16**+**salt2(4)@20**+cksum(8).
//! - 每帧 = frame header 24B + page PAGE(4096)B:
//!   frame header = **pgno(4)@0** + **commit_pgcnt(4)@4** + **salt1(4)@8** + **salt2(4)@12** + cksum(8).
//!   - `commit_pgcnt != 0` ⇒ 该帧是某事务的**提交帧** (值 = 提交后 db 总页数); 否则 0.
//!   - 帧 salt == WAL 头 salt ⇒ 属**当前周期** (未被 checkpoint 覆盖的新帧); 不等 = 上一周期旧帧, 跳过.
//!
//! ## 只应用已提交、当前周期、HMAC 通过的帧 (一致性 + 抗撕裂)
//! 1. 一遍扫: 取最后一个"当前周期 + 提交帧" = 提交边界 `last_commit`; 其 commit_pgcnt = `final_pages`.
//!    无提交帧 ⇒ WAL 无已提交事务, no-op (不应用半截 in-progress 事务, 防 image malformed).
//! 2. image resize 到 `final_pages*PAGE` (WAL 可让 db 增长到超过主库物理长度 → 补零扩容; 收缩则截断).
//! 3. 二遍扫 `[0..=last_commit]`: 当前周期 + `pgno<=final_pages` 的帧, 复用 HMAC 校验 (失败=撕裂/损坏帧,
//!    跳过不报错, 下次轮询再拿) + 页解密 (pgno==1 走首页路径 —— **真库实测 WAL 首页帧带 salt 头**,
//!    与主库 page1 同布局), patch 到 image. 同 pgno 多帧后写覆盖先写 (last-writer-wins).
//!
//! ## 红线
//! K-R4: 不打印明文页 / 不泄 wxid; enc_key/mac_key 借用 (调用方 Zeroizing 持有, 见 decrypt.rs).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use native_keyscan::PAGE;

use crate::decrypt::{decrypt_page_into, verify_page_hmac};
use crate::error::SqlcipherError;

/// 已提交 WAL 页的稀疏 overlay: `pgno → 解密后的 4096B 页` (VFS 按需读命中此则返最新前沿).
pub(crate) type WalOverlay = HashMap<u32, [u8; PAGE]>;

/// WAL header 固定 32B.
const WAL_HDR: usize = 32;
/// 每帧的 frame header 固定 24B.
const WAL_FRAME_HDR: usize = 24;

/// WAL 应用统计 (可观测: 健康数据应 `skipped_hmac == 0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalApplyStats {
    /// 应用后 db 逻辑总页数 (= 最后提交帧的 commit_pgcnt; 无 WAL/无提交时 = 主库物理页数).
    pub final_pages: usize,
    /// 实际 patch 进 image 的帧数 (含同页多次覆盖).
    pub applied_frames: usize,
    /// HMAC 校验未过被跳过的帧数 (撕裂/损坏; 健康数据应为 0).
    pub skipped_hmac: usize,
    /// 是否找到"当前周期的提交帧" (false = WAL 缺失/无已提交事务, image 未改).
    pub had_commit: bool,
}

/// `<db>` → 兄弟 `<db>-wal` 路径 (WeChat WAL 命名 = 文件名直接追加 `-wal`, 非替换扩展名).
#[must_use]
pub fn wal_sibling(db_path: &Path) -> PathBuf {
    let mut s = db_path.to_path_buf().into_os_string();
    s.push("-wal");
    PathBuf::from(s)
}

#[inline]
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// 把 `wal_path` 里已提交的增量帧应用到 `image` (原地改; 见模块级文档的三步算法).
///
/// `enc_key` / `mac_key`: 由主库解密时派生 (decrypt.rs), 与 WAL 帧同一套. `image` 传 `&mut Vec`
/// 因 WAL 可让 db 增长需 resize.
///
/// # Errors
/// [`SqlcipherError::Io`] 读已存在的 WAL 失败; [`SqlcipherError::Decrypt`] 某帧 AES 解密失败
/// (HMAC 已过却解密失败 = 异常, 上报). WAL 缺失 / 太短 / page_sz 非 4096 / 无提交帧 → `Ok(no-op)`.
pub(crate) fn apply_wal_to_image(
    image: &mut Vec<u8>,
    wal_path: &Path,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<WalApplyStats, SqlcipherError> {
    let physical_pages = image.len() / PAGE;
    let noop = WalApplyStats {
        final_pages: physical_pages,
        applied_frames: 0,
        skipped_hmac: 0,
        had_commit: false,
    };

    if !wal_path.exists() {
        return Ok(noop);
    }
    let wal = std::fs::read(wal_path).map_err(|e| SqlcipherError::Io(format!("{}: {e}", file_name(wal_path))))?;
    if wal.len() <= WAL_HDR {
        return Ok(noop); // 只有头 / 空 WAL: 无帧.
    }
    // 只处理 page_sz==4096 (本项目全部微信库均是; 不等则不敢应用, 退回快照).
    if be32(&wal, 8) as usize != PAGE {
        return Ok(noop);
    }
    let hsalt = &wal[16..24]; // salt1|salt2 当 8B 整体比对.

    let frame_sz = WAL_FRAME_HDR + PAGE;
    let area = &wal[WAL_HDR..];
    let n_frames = area.len() / frame_sz;

    // ---- 一遍: 找提交边界 (最后一个 当前周期+提交帧) ----
    let mut last_commit: Option<usize> = None;
    let mut final_pages = physical_pages;
    for i in 0..n_frames {
        let fh = &area[i * frame_sz..i * frame_sz + WAL_FRAME_HDR];
        let commit = be32(fh, 4);
        let fresh = &fh[8..16] == hsalt;
        if fresh && commit != 0 {
            last_commit = Some(i);
            final_pages = commit as usize;
        }
    }
    let Some(last_commit) = last_commit else {
        return Ok(noop); // 无已提交事务: 不应用 in-progress 帧.
    };

    // 防御: 逻辑页数不可能超过 (主库物理页 + WAL 总帧数) —— 每个新页至少要一帧承载. 超出 =
    // commit_pgcnt 损坏/异常, 退回快照 (避免 resize 到天量内存 OOM). u32 commit 最大 ~16TB.
    if final_pages > physical_pages + n_frames {
        return Ok(noop);
    }

    // ---- resize image 到提交后逻辑大小 (WAL 可扩容超过主库物理页) ----
    image.resize(final_pages * PAGE, 0);

    // ---- 二遍: 应用 [0..=last_commit] 中 当前周期 + pgno<=final_pages 的帧 ----
    let mut applied_frames = 0usize;
    let mut skipped_hmac = 0usize;
    for i in 0..=last_commit {
        let base = i * frame_sz;
        let fh = &area[base..base + WAL_FRAME_HDR];
        let page = &area[base + WAL_FRAME_HDR..base + frame_sz];
        let pgno = be32(fh, 0);
        if &fh[8..16] != hsalt {
            continue; // 旧周期残帧 (提交边界前偶有; 跳过).
        }
        if pgno == 0 || pgno as usize > final_pages {
            continue; // 超出提交后大小 (曾增后缩的页); 忽略.
        }
        // HMAC 失败 = 撕裂/损坏帧 (并发写常见于末帧, 已被 last_commit 排除; 此处仍兜): 跳过不报错.
        if verify_page_hmac(mac_key, page, pgno).is_err() {
            skipped_hmac += 1;
            continue;
        }
        let lo = (pgno as usize - 1) * PAGE;
        decrypt_page_into(enc_key, page, pgno == 1, pgno, &mut image[lo..lo + PAGE])?;
        applied_frames += 1;
    }

    Ok(WalApplyStats {
        final_pages,
        applied_frames,
        skipped_hmac,
        had_commit: true,
    })
}

/// 扫 `<db>-wal` 构建**已提交 WAL 页的稀疏 overlay** (`pgno → 解密后的页`) + 逻辑总页数 (供 VFS 按需读).
///
/// 命中 overlay 的页返最新 (WAL 未刷盘前沿), 否则读主库。提交边界 / salt 周期 / HMAC / OOM 守卫逻辑与
/// [`apply_wal_to_image`] 一致, 只是产出稀疏 map 而非整库 image (**内存 = WAL 页数 × 4K, ~几 MB, 非整库**)。
///
/// 返回 `(overlay, logical_pages, skipped_hmac)`; WAL 缺失/太短/无提交 → 空 overlay + `logical_pages = physical_pages`。
///
/// # Errors
/// [`SqlcipherError::Io`] 读 WAL 失败; [`SqlcipherError::Decrypt`] 某帧解密失败 (HMAC 已过).
pub(crate) fn build_wal_overlay(
    wal_path: &Path,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    physical_pages: u64,
) -> Result<(WalOverlay, u64, usize), SqlcipherError> {
    let mut overlay: WalOverlay = HashMap::new();
    if !wal_path.exists() {
        return Ok((overlay, physical_pages, 0));
    }
    let wal = std::fs::read(wal_path).map_err(|e| SqlcipherError::Io(format!("{}: {e}", file_name(wal_path))))?;
    if wal.len() <= WAL_HDR || be32(&wal, 8) as usize != PAGE {
        return Ok((overlay, physical_pages, 0));
    }
    let hsalt = &wal[16..24];
    let frame_sz = WAL_FRAME_HDR + PAGE;
    let area = &wal[WAL_HDR..];
    let n_frames = area.len() / frame_sz;

    // pass 1: 提交边界 + 逻辑页数.
    let mut last_commit: Option<usize> = None;
    let mut final_pages = physical_pages;
    for i in 0..n_frames {
        let fh = &area[i * frame_sz..i * frame_sz + WAL_FRAME_HDR];
        if &fh[8..16] == hsalt && be32(fh, 4) != 0 {
            last_commit = Some(i);
            final_pages = u64::from(be32(fh, 4));
        }
    }
    let Some(last_commit) = last_commit else {
        return Ok((overlay, physical_pages, 0));
    };
    if final_pages > physical_pages + n_frames as u64 {
        return Ok((overlay, physical_pages, 0)); // commit_pgcnt 损坏 → 退回主库.
    }

    // pass 2: 收集 [0..=last_commit] 中 当前周期 + pgno<=final_pages + HMAC 通过 的页 (后写覆盖先写).
    let mut skipped = 0usize;
    for i in 0..=last_commit {
        let base = i * frame_sz;
        let fh = &area[base..base + WAL_FRAME_HDR];
        let page = &area[base + WAL_FRAME_HDR..base + frame_sz];
        let pgno = be32(fh, 0);
        if &fh[8..16] != hsalt || pgno == 0 || u64::from(pgno) > final_pages {
            continue;
        }
        if verify_page_hmac(mac_key, page, pgno).is_err() {
            skipped += 1;
            continue;
        }
        let mut out = [0u8; PAGE];
        decrypt_page_into(enc_key, page, pgno == 1, pgno, &mut out)?;
        overlay.insert(pgno, out);
    }
    Ok((overlay, final_pages, skipped))
}

/// K-R4: error 只放文件名, 不放含 wxid 的全路径.
fn file_name(p: &Path) -> String {
    p.file_name().and_then(|s| s.to_str()).unwrap_or("<wal>").to_string()
}

#[cfg(test)]
mod tests {
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use hmac::{Hmac, Mac};
    use native_keyscan::{MAC_SALT_XOR, RESERVE};
    use sha2::Sha512;

    use super::*;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

    fn mac_key_for(enc_key: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
        use pbkdf2::pbkdf2_hmac;
        let mac_salt: Vec<u8> = salt.iter().map(|b| b ^ MAC_SALT_XOR).collect();
        let mut mk = [0u8; 32];
        pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mk);
        mk
    }

    /// 造一个加密页 (页内明文 = `body_seed` 派生的固定字节), 布局同真库:
    /// 首页 = salt(16) + 密文[16..4016] + IV(16) + HMAC(64); 非首页 = 密文[0..4016] + IV + HMAC.
    /// 返回 (加密页 4096B, 期望解密后 image 页 4096B).
    fn synth_page(
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        salt: &[u8; 16],
        pgno: u32,
        body_seed: u8,
    ) -> (Vec<u8>, Vec<u8>) {
        let is_first = pgno == 1;
        let body_len = if is_first { PAGE - RESERVE - 16 } else { PAGE - RESERVE };
        let mut body = vec![0u8; body_len];
        for (i, b) in body.iter_mut().enumerate() {
            *b = ((i + body_seed as usize) % 251) as u8;
        }
        let iv = [0x11u8 ^ body_seed; 16];
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
        let mut mac = <Hmac<Sha512>>::new_from_slice(mac_key).unwrap();
        mac.update(&page[off..PAGE - RESERVE + 16]);
        mac.update(&pgno.to_le_bytes());
        page[PAGE - RESERVE + 16..PAGE].copy_from_slice(&mac.finalize().into_bytes());

        let mut img = vec![0u8; PAGE];
        if is_first {
            img[..16].copy_from_slice(SQLITE_HEADER);
            img[16..16 + body_len].copy_from_slice(&body);
        } else {
            img[..body_len].copy_from_slice(&body);
        }
        (page, img)
    }

    /// 组一个 WAL 文件: header(salt1,salt2) + 帧列表 (每帧: pgno, commit_pgcnt, 用给定 salt).
    /// `frame_salt` 与 header salt 不同者 = 旧周期帧.
    fn build_wal(
        hsalt1: u32,
        hsalt2: u32,
        frames: &[(u32, u32, u32, u32, Vec<u8>)], // (pgno, commit, fsalt1, fsalt2, encrypted_page)
    ) -> Vec<u8> {
        let mut w = vec![0u8; WAL_HDR];
        w[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes()); // magic (big-endian variant)
        w[8..12].copy_from_slice(&(PAGE as u32).to_be_bytes());
        w[16..20].copy_from_slice(&hsalt1.to_be_bytes());
        w[20..24].copy_from_slice(&hsalt2.to_be_bytes());
        for (pgno, commit, fs1, fs2, page) in frames {
            let mut fh = vec![0u8; WAL_FRAME_HDR];
            fh[0..4].copy_from_slice(&pgno.to_be_bytes());
            fh[4..8].copy_from_slice(&commit.to_be_bytes());
            fh[8..12].copy_from_slice(&fs1.to_be_bytes());
            fh[12..16].copy_from_slice(&fs2.to_be_bytes());
            w.extend_from_slice(&fh);
            w.extend_from_slice(page);
        }
        w
    }

    fn write_tmp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    /// 核心往返: 主库 2 页 image + WAL 增长到 4 页 (含首页覆写 + 新页), 应用后逐字节还原, 且末帧提交.
    #[test]
    fn apply_grows_and_patches() {
        let enc_key = [0x42u8; 32];
        let salt = [0x7au8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (hs1, hs2) = (0xAAAA_1111u32, 0xBBBB_2222u32);

        // 主库快照: 2 页 (page1 seed=10, page2 seed=20).
        let (_p1_old, img1_old) = synth_page(&enc_key, &mac_key, &salt, 1, 10);
        let (_p2_old, img2_old) = synth_page(&enc_key, &mac_key, &salt, 2, 20);
        let mut image = [img1_old, img2_old].concat();
        assert_eq!(image.len(), 2 * PAGE);

        // WAL: 覆写 page1(seed=11), 覆写 page2(seed=21), 新增 page3(seed=30), 新增 page4(seed=40, 提交=4页).
        let (e1, exp1) = synth_page(&enc_key, &mac_key, &salt, 1, 11);
        let (e2, exp2) = synth_page(&enc_key, &mac_key, &salt, 2, 21);
        let (e3, exp3) = synth_page(&enc_key, &mac_key, &salt, 3, 30);
        let (e4, exp4) = synth_page(&enc_key, &mac_key, &salt, 4, 40);
        let wal = build_wal(
            hs1,
            hs2,
            &[
                (1, 0, hs1, hs2, e1),
                (2, 0, hs1, hs2, e2),
                (3, 0, hs1, hs2, e3),
                (4, 4, hs1, hs2, e4), // 提交帧, 提交后 4 页.
            ],
        );
        let f = write_tmp(&wal);
        let stats = apply_wal_to_image(&mut image, f.path(), &enc_key, &mac_key).unwrap();

        assert!(stats.had_commit);
        assert_eq!(stats.final_pages, 4, "提交后 4 页");
        assert_eq!(stats.applied_frames, 4);
        assert_eq!(stats.skipped_hmac, 0);
        assert_eq!(image.len(), 4 * PAGE, "image 应扩容到 4 页");
        assert_eq!(&image[0..PAGE], &exp1[..], "page1 覆写 (首页含 magic)");
        assert_eq!(&image[0..16], SQLITE_HEADER, "首页 magic");
        assert_eq!(&image[PAGE..2 * PAGE], &exp2[..], "page2 覆写");
        assert_eq!(&image[2 * PAGE..3 * PAGE], &exp3[..], "page3 新增");
        assert_eq!(&image[3 * PAGE..4 * PAGE], &exp4[..], "page4 新增");
    }

    /// last-writer-wins: 同 pgno 多帧, 取提交边界内最后一帧.
    #[test]
    fn last_writer_wins() {
        let enc_key = [0x11u8; 32];
        let salt = [0x33u8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (hs1, hs2) = (1, 2);
        let (_o, img_old) = synth_page(&enc_key, &mac_key, &salt, 1, 1);
        let mut image = img_old;
        let (ea, _) = synth_page(&enc_key, &mac_key, &salt, 2, 50);
        let (eb, expb) = synth_page(&enc_key, &mac_key, &salt, 2, 60); // 后写胜
        let wal = build_wal(hs1, hs2, &[(2, 0, hs1, hs2, ea), (2, 2, hs1, hs2, eb)]);
        let f = write_tmp(&wal);
        let stats = apply_wal_to_image(&mut image, f.path(), &enc_key, &mac_key).unwrap();
        assert_eq!(stats.applied_frames, 2);
        assert_eq!(&image[PAGE..2 * PAGE], &expb[..], "page2 取后写帧");
    }

    /// 旧周期帧 (salt 不匹配) 跳过; 未提交尾帧 (提交边界之后) 不应用.
    #[test]
    fn skips_stale_and_uncommitted() {
        let enc_key = [0x22u8; 32];
        let salt = [0x44u8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (hs1, hs2) = (7, 8);
        let (_o, img_old) = synth_page(&enc_key, &mac_key, &salt, 1, 1);
        let mut image = img_old.clone();

        let (e2, exp2) = synth_page(&enc_key, &mac_key, &salt, 2, 70);
        let (e_stale, _) = synth_page(&enc_key, &mac_key, &salt, 2, 99); // 旧周期 salt
        let (e_uncommit, _) = synth_page(&enc_key, &mac_key, &salt, 3, 88); // 提交后追加, 无提交标记

        let wal = build_wal(
            hs1,
            hs2,
            &[
                (2, 0, 999, 999, e_stale),    // 旧周期: 跳过
                (2, 2, hs1, hs2, e2),         // 提交帧 (边界 = 此)
                (3, 0, hs1, hs2, e_uncommit), // 未提交尾帧: 不应用
            ],
        );
        let f = write_tmp(&wal);
        let stats = apply_wal_to_image(&mut image, f.path(), &enc_key, &mac_key).unwrap();
        assert_eq!(stats.final_pages, 2, "提交边界 = 2 页 (未提交的 page3 不算)");
        assert_eq!(image.len(), 2 * PAGE, "不因未提交尾帧扩容到 3 页");
        assert_eq!(stats.applied_frames, 1, "只应用提交边界内的 page2");
        assert_eq!(&image[PAGE..2 * PAGE], &exp2[..]);
    }

    /// 无提交帧 (全是 in-progress) → no-op, image 不变.
    #[test]
    fn no_commit_is_noop() {
        let enc_key = [0x55u8; 32];
        let salt = [0x66u8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (hs1, hs2) = (5, 6);
        let (_o, img_old) = synth_page(&enc_key, &mac_key, &salt, 1, 1);
        let mut image = img_old.clone();
        let before = image.clone();
        let (e2, _) = synth_page(&enc_key, &mac_key, &salt, 2, 70);
        let wal = build_wal(hs1, hs2, &[(2, 0, hs1, hs2, e2)]); // 无 commit!=0 帧
        let f = write_tmp(&wal);
        let stats = apply_wal_to_image(&mut image, f.path(), &enc_key, &mac_key).unwrap();
        assert!(!stats.had_commit);
        assert_eq!(stats.applied_frames, 0);
        assert_eq!(image, before, "无提交事务: image 原样");
    }

    /// commit_pgcnt 损坏 (远超 物理页+帧数) → no-op, 不 resize 到天量内存.
    #[test]
    fn corrupt_final_pages_is_noop() {
        let enc_key = [0xcdu8; 32];
        let salt = [0xefu8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (hs1, hs2) = (9, 10);
        let (_o, img_old) = synth_page(&enc_key, &mac_key, &salt, 1, 1);
        let mut image = img_old.clone();
        let before = image.clone();
        let (e2, _) = synth_page(&enc_key, &mac_key, &salt, 2, 70);
        // commit_pgcnt = 1_000_000 (远超 物理1页 + 1帧): 损坏.
        let wal = build_wal(hs1, hs2, &[(2, 1_000_000, hs1, hs2, e2)]);
        let f = write_tmp(&wal);
        let stats = apply_wal_to_image(&mut image, f.path(), &enc_key, &mac_key).unwrap();
        assert!(!stats.had_commit, "损坏 commit 退回 no-op");
        assert_eq!(image, before, "image 不变, 未 resize");
    }

    /// WAL 缺失 → no-op (final_pages = 主库物理页数).
    #[test]
    fn missing_wal_is_noop() {
        let enc_key = [0x77u8; 32];
        let salt = [0x88u8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (_o, img_old) = synth_page(&enc_key, &mac_key, &salt, 1, 1);
        let mut image = img_old.clone();
        let before = image.clone();
        let missing = std::path::Path::new("Z:/does/not/exist.db-wal");
        let stats = apply_wal_to_image(&mut image, missing, &enc_key, &mac_key).unwrap();
        assert!(!stats.had_commit);
        assert_eq!(stats.final_pages, 1);
        assert_eq!(image, before);
    }

    /// 撕裂帧 (HMAC 坏) 跳过并计数, 不污染 image, 不报错.
    #[test]
    fn torn_frame_skipped_by_hmac() {
        let enc_key = [0x99u8; 32];
        let salt = [0xabu8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (hs1, hs2) = (3, 4);
        let (_o, img_old) = synth_page(&enc_key, &mac_key, &salt, 1, 1);
        let mut image = img_old;

        let (mut e2_bad, _) = synth_page(&enc_key, &mac_key, &salt, 2, 70);
        e2_bad[100] ^= 0xff; // 破坏正文 → HMAC 不过
        let (e3, exp3) = synth_page(&enc_key, &mac_key, &salt, 3, 80);
        let wal = build_wal(hs1, hs2, &[(2, 0, hs1, hs2, e2_bad), (3, 3, hs1, hs2, e3)]);
        let f = write_tmp(&wal);
        let stats = apply_wal_to_image(&mut image, f.path(), &enc_key, &mac_key).unwrap();
        assert_eq!(stats.skipped_hmac, 1, "坏 page2 被 HMAC 拦下");
        assert_eq!(stats.applied_frames, 1, "只应用好的 page3");
        assert_eq!(stats.final_pages, 3);
        assert_eq!(&image[2 * PAGE..3 * PAGE], &exp3[..]);
        assert_eq!(&image[PAGE..2 * PAGE], &[0u8; PAGE], "坏 page2 未写入 (保持扩容零页)");
    }

    #[test]
    fn wal_sibling_appends_suffix() {
        let p = std::path::Path::new("F:/x/message_0.db");
        assert_eq!(wal_sibling(p).to_str().unwrap(), "F:/x/message_0.db-wal");
    }

    /// build_wal_overlay: 收集提交边界内的页 (稀疏 map), 逻辑页数正确, 未改的页不在 overlay (VFS 按需读用).
    #[test]
    fn build_overlay_collects_committed_pages() {
        let enc_key = [0x42u8; 32];
        let salt = [0x7au8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (hs1, hs2) = (0xAAAA_1111u32, 0xBBBB_2222u32);
        // 主库物理 2 页; WAL 覆写 page1 + 新增 page3, 提交后 3 页.
        let (e1, exp1) = synth_page(&enc_key, &mac_key, &salt, 1, 11);
        let (e3, exp3) = synth_page(&enc_key, &mac_key, &salt, 3, 30);
        let wal = build_wal(hs1, hs2, &[(1, 0, hs1, hs2, e1), (3, 3, hs1, hs2, e3)]);
        let f = write_tmp(&wal);
        let (overlay, logical, skipped) = build_wal_overlay(f.path(), &enc_key, &mac_key, 2).unwrap();
        assert_eq!(logical, 3, "提交后逻辑 3 页");
        assert_eq!(skipped, 0);
        assert_eq!(overlay.len(), 2, "page1 + page3 进 overlay");
        assert_eq!(
            &overlay.get(&1).unwrap()[..],
            &exp1[..],
            "page1 解密内容 (含 magic, 未做 rollback patch)"
        );
        assert_eq!(&overlay.get(&3).unwrap()[..], &exp3[..], "page3 新增页解密内容");
        assert!(!overlay.contains_key(&2), "page2 未在 WAL → 不在 overlay (VFS 读主库)");
    }

    /// 无提交帧 → 空 overlay + logical = physical (退回纯主库).
    #[test]
    fn build_overlay_no_commit_empty() {
        let enc_key = [0x55u8; 32];
        let salt = [0x66u8; 16];
        let mac_key = mac_key_for(&enc_key, &salt);
        let (e2, _) = synth_page(&enc_key, &mac_key, &salt, 2, 70);
        let wal = build_wal(5, 6, &[(2, 0, 5, 6, e2)]); // 无 commit!=0
        let f = write_tmp(&wal);
        let (overlay, logical, _) = build_wal_overlay(f.path(), &enc_key, &mac_key, 4).unwrap();
        assert!(overlay.is_empty());
        assert_eq!(logical, 4, "无提交 → logical = physical");
    }
}
