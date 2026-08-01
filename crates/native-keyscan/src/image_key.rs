//! image_key.rs — 扫微信进程内存提图片 `.dat` 的账号级 AES image key (ADR-461 件3).
//!
//! 抄 wx-cli `ImageKeyProvider` 但**强化**: 扫可读内存里 `[0-9A-Za-z]{16,}` alnum 候选 → **滑窗**取每个
//! 16 字节窗口当 AES-128 key → 用**多张 (≥2 互不相同) V2 sample .dat 交叉验证** (每张: 解 AES **全段**
//! → PKCS7 unpad 严格合法 → **强** magic 图头 JPEG/PNG/GIF/WEBP), 全过才认。复用
//! [`WeixinProcess::for_each_readable_region`](crate::win::WeixinProcess::for_each_readable_region)
//! (广覆盖 private/mapped/image 可读区), **被动 ReadProcessMemory, 无 dll 注入** (合规: 读微信内存=可, hook 注入=红线)。
//!
//! **⚠️ 4 个实测踩过的坑 (别退回)**: ①只验首块(2^-24)会撞假阳→全段 PKCS7+图头。②只取 [:16] 漏真 key
//! (嵌长串中段)→滑窗每个 16 窗口。③弱 magic (BMP"BM"/裸 RIFF) 撞假阳→只收强 magic + 多锚交叉验证。
//! ④image key **瞬态**驻留 (微信按需加载非常驻)→调用方需重试多轮直到某轮在 (见 ignored 测试)。
//!
//! ## 与 SQLCipher key 的区别
//! master/enc_key 解库用 (SQLCipher); 本 key 解图片 `.dat` (AES-128, 账号级一装一把)。二者都在微信进程
//! 内存里、扫法同源 (regex 候选 + 验证), 但验证锚不同: 库首页 HMAC vs 图 sample 首块解出图头。
//!
//! ## 为何需要它 (vs 解码器自推 XOR)
//! V0 缩略图整文件 XOR, key 从图头 magic 可反推 (解码器自己搞定, 不需本 mod)。但 **V2 完整图**的 AES 段
//! 需要这把账号级 AES key —— 内存里才有, 这就是本 mod 的活。
//!
//! ## K-R4
//! image key 是密钥 → 出口不露原值 (调用方拿 `[u8;16]` 自行处置; 本 mod 只在 sha8 后打印, 不打原值)。

use std::ops::ControlFlow;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use regex::bytes::Regex;

use crate::win::WeixinProcess;

/// 从微信进程私有内存扫出账号级 image AES-128 key (16 字节)。
///
/// `samples` = 该账号 **多张 (建议 ≥3)** V2 图片 `.dat` 的原始字节 (magic `\x07\x08V2\x08\x07`)。候选 key
/// 须能把**每一张** sample 的 AES 全段解成 PKCS7 合法 + 图头才认 (抄 wx-cli `_validate_image_key_for_raw`
/// 但**多锚交叉验证**)。命中即停。
///
/// **⚠️ 为何要多锚 + 滑窗 (两个实测踩过的坑)**:
/// 1. key 常嵌在更长 alnum 串中段 → 必须滑窗试**每个** 16 字节窗口, 只取 [:16] 找不到 (漏真 key)。
/// 2. 滑窗放出**海量**候选 (十亿级) → 单张 sample 的全段 PKCS7+图头验 (~2^-32) 也会撞假阳; 实测单锚
///    找到的 key sha8 跟真 key 不符 (是假阳)。**多张 sample 交叉验证**: 假阳只在它撞中的那张过,
///    换张就露馅; 真 key 张张都过 → 假阳率 ~(2^-32)^N → 0。
///
/// 返 `None`: samples 空/非 V2 / 内存扫不到 (微信没跑 / 没加载过图片 key)。
#[must_use]
pub fn scan_image_key(proc: &WeixinProcess, samples: &[&[u8]]) -> Option<[u8; 16]> {
    let segs = valid_anchor_segments(samples)?;
    // 第一张 sample 的首块作便宜预筛 (2^-24 挡掉绝大多数窗口); 过了再对**全部** sample 全段确认。
    let first: [u8; 16] = segs[0][..16].try_into().expect("seg 已保证 >=16");
    let re = Regex::new(r"[0-9A-Za-z]{16,}").expect("static regex valid");
    let mut found: Option<[u8; 16]> = None;
    // 用**广覆盖**读区 (含 mapped/image, 非仅 private): image key 常不在 private 区, private-only 扫不到。
    proc.for_each_readable_region(|_base, mem| {
        if let Some(k) = scan_bytes_for_key(&re, mem, &first, &segs) {
            found = Some(k);
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    });
    found
}

/// 在一段内存字节里滑窗找 image key (纯逻辑, 与进程解耦便于确定性单测)。命中即返。
/// 对每个 `[0-9A-Za-z]{16,}` 候选串滑窗取每个 16 字节窗口, cheap 预筛过再对全部锚全段交叉验证。
fn scan_bytes_for_key(re: &Regex, mem: &[u8], first: &[u8; 16], segs: &[Vec<u8>]) -> Option<[u8; 16]> {
    for m in re.find_iter(mem) {
        for w in m.as_bytes().windows(16) {
            let cand: [u8; 16] = w.try_into().expect("windows(16) 恒 16 字节");
            if head_block_ok(&cand, first) && segs.iter().all(|seg| full_segment_ok(&cand, seg)) {
                return Some(cand);
            }
        }
    }
    None
}

/// 校验并取多锚 AES 段: **所有** sample 都得是 V2 (不静默丢坏样本) 且 **≥2 张互不相同**, 否则 None
/// (codex P1: 拒单锚/坏锚/重复锚 —— 海量滑窗候选下单锚会撞假阳, 多锚交叉验证才把假阳压到 0)。
fn valid_anchor_segments(samples: &[&[u8]]) -> Option<Vec<Vec<u8>>> {
    let segs: Vec<Vec<u8>> = samples.iter().filter_map(|s| v2_aes_segment(s)).collect();
    // 每张都必须解析成功 (segs.len()==samples.len()) 且 ≥2 张。
    if segs.len() != samples.len() || segs.len() < 2 {
        return None;
    }
    // 拒重复锚 (同一张传两次 ≠ 真交叉验证)。
    for i in 1..segs.len() {
        if segs[..i].contains(&segs[i]) {
            return None;
        }
    }
    Some(segs)
}

/// V2 `.dat` 的 AES 全段密文 (`[15 : 15+aes_aligned]`, 16 倍数)。非 V2 / 越界 / 非对齐 → None。
fn v2_aes_segment(sample: &[u8]) -> Option<Vec<u8>> {
    if !sample.starts_with(b"\x07\x08V2\x08\x07") {
        return None;
    }
    let aes_size = u32::from_le_bytes(sample.get(6..10)?.try_into().ok()?) as usize;
    let aligned = (aes_size / 16 + 1).checked_mul(16)?; // PKCS7 总补一整块 (对齐坑, 同 decoder)
    let seg = sample.get(15..15usize.checked_add(aligned)?)?;
    if seg.len() < 16 || seg.len() % 16 != 0 {
        return None;
    }
    Some(seg.to_vec())
}

/// 便宜预筛: 候选 key 解首块 → 图头 (2^-24 过滤, 挡掉绝大多数候选)。
fn head_block_ok(key: &[u8; 16], first_block: &[u8; 16]) -> bool {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(first_block);
    cipher.decrypt_block(&mut block);
    is_image_head(&block)
}

/// 全段确认: 解 AES 全段 → PKCS7 unpad 合法 → 图头 (假阳要同时满足全段 PKCS7 + 图头, ~不可能)。
fn full_segment_ok(key: &[u8; 16], seg: &[u8]) -> bool {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(seg.len());
    for chunk in seg.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    // PKCS7 unpad 严格校验: pad ∈ 1..=16 且尾部 pad 字节全等于 pad。
    let Some(&pad) = out.last() else {
        return false;
    };
    let pad = pad as usize;
    if !(1..=16).contains(&pad) || pad > out.len() {
        return false;
    }
    if out[out.len() - pad..].iter().any(|&b| b as usize != pad) {
        return false;
    }
    is_image_head(&out[..out.len() - pad])
}

/// 解出的首字节是不是**强** magic 图头 (jpg/png/gif/webp/wxgf)。
///
/// **⚠️ 只收强 magic**: 早先收 BMP `"BM"` (2 字节=2^-16) + 裸 `"RIFF"` → 内存滑窗海量候选里撞假阳
/// (实测: 假 key `04f6760e...` 解出 `42 4d`="BM"+乱码, PKCS7 又碰巧过 → 假阳骗过验证)。去掉弱 magic,
/// 只认 JPEG(3B)/PNG(8B)/GIF(6B)/WEBP(RIFF+WEBP@8)/WXGF(4B), 配多锚交叉验证把假阳压到 0。
///
/// **⚠️ 必须收 WXGF (2026-07-04 真机逮到)**: V2 `.dat` 内层不只是静态图 —— 微信**动图/动态贴图**解密后是
/// `wxgf` 容器 (HEVC, 需转码)。实测某账号 4 张 V2 里 2 张解出 `77 78 67 66`="wxgf"。若不收, 内存扫的
/// **多锚交叉验证要求每张锚都过 is_image_head** → 真 key 解 WXGF 锚出 "wxgf" 头 → 被判非图 → **真 key 被拒**
/// (collect 随机挑锚必然混入 WXGF, 直接导致扫不到 key)。`wxgf` 是 4 字节强 magic (2^-32), 收它不引假阳。
fn is_image_head(b: &[u8]) -> bool {
    b.starts_with(&[0xFF, 0xD8, 0xFF]) // JPEG (SOI + marker)
        || b.starts_with(b"\x89PNG\r\n\x1a\n") // PNG 8 字节全签名
        || b.starts_with(b"GIF87a")
        || b.starts_with(b"GIF89a") // GIF 6 字节
        || (b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP") // WEBP
        || b.starts_with(b"wxgf") // WXGF (微信动图容器, V2 内层; 需转码但 magic 强)
}

#[cfg(test)]
mod tests {
    use aes::cipher::BlockEncrypt;

    use super::*;

    /// 造一张 V2 sample: header(15B) + ECB_encrypt(key, PKCS7(plain 到 aligned))。plain 须以图头开头。
    fn make_v2_sample(key: &[u8; 16], plain: &[u8], aes_size: usize) -> Vec<u8> {
        let aligned = (aes_size / 16 + 1) * 16;
        let pad = aligned - aes_size;
        let mut padded = plain[..aes_size].to_vec();
        padded.extend(std::iter::repeat(pad as u8).take(pad));
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut seg = Vec::new();
        for chunk in padded.chunks_exact(16) {
            let mut b = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut b);
            seg.extend_from_slice(&b);
        }
        let mut out = vec![0x07, 0x08, b'V', b'2', 0x08, 0x07];
        out.extend_from_slice(&(aes_size as u32).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // xor_size (占位)
        out.push(0); // pad byte → header 共 15B
        out.extend_from_slice(&seg);
        out
    }

    fn fake_jpeg(n: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
        v.extend((4..n).map(|i| (i * 31 + 7) as u8));
        v
    }

    #[test]
    fn v2_aes_segment_extracts_or_rejects() {
        let key = b"f55dbb3da8a161c6";
        let sample = make_v2_sample(key, &fake_jpeg(600), 512);
        let seg = v2_aes_segment(&sample).unwrap();
        assert_eq!(seg.len() % 16, 0, "全段 16 对齐");
        assert_eq!(seg.len(), (512 / 16 + 1) * 16, "aes_aligned = (aes_size/16+1)*16");
        assert!(
            v2_aes_segment(b"\x07\x08V1\x08\x07________________").is_none(),
            "V1 头 → None"
        );
        assert!(
            v2_aes_segment(b"\x07\x08V2\x08\x07\x00\x04\x00\x00").is_none(),
            "越界 → None"
        );
    }

    #[test]
    fn is_image_head_recognizes_strong_magics_only() {
        assert!(is_image_head(&[0xFF, 0xD8, 0xFF, 0xE0]));
        assert!(is_image_head(b"\x89PNG\r\n\x1a\n"));
        assert!(is_image_head(b"GIF89a"));
        assert!(is_image_head(b"GIF87a"));
        assert!(is_image_head(b"RIFF\x00\x00\x00\x00WEBP"));
        assert!(
            is_image_head(b"wxgf\x13\x00\x02\x04"),
            "WXGF 动图容器 (V2 内层) 必收, 否则真 key 撞 WXGF 锚被拒"
        );
        // 弱 magic 不收 (假阳源): BMP "BM" (2B) / 裸 RIFF (无 WEBP)。
        assert!(!is_image_head(b"BM\xc7\xc4random padding"), "BMP 2 字节太弱 → 拒");
        assert!(!is_image_head(b"RIFF\x00\x00\x00\x00AVI "), "裸 RIFF 非 WEBP → 拒");
        assert!(!is_image_head(&[0u8; 16]), "全 0 不是图头");
        assert!(!is_image_head(b"random garbage!!"), "乱码不是图头");
    }

    #[test]
    fn full_segment_ok_accepts_correct_rejects_wrong() {
        // 全段验证: 正确 key 解出 PKCS7 合法 + JPEG 头 → 认; 错 key → 不认。
        let key = b"f55dbb3da8a161c6";
        let sample = make_v2_sample(key, &fake_jpeg(600), 512);
        let seg = v2_aes_segment(&sample).unwrap();
        assert!(full_segment_ok(key, &seg), "正确 key 全段解出 JPEG → 认");
        assert!(
            !full_segment_ok(b"0000000000000000", &seg),
            "错 key → PKCS7/图头不过 → 不认"
        );
    }

    #[test]
    fn head_block_ok_is_cheap_prefilter() {
        // 首块预筛: 正确 key 首块解出图头 (但这只是预筛, 真验靠 full_segment_ok)。
        let key = b"f55dbb3da8a161c6";
        let sample = make_v2_sample(key, &fake_jpeg(600), 512);
        let seg = v2_aes_segment(&sample).unwrap();
        let first: [u8; 16] = seg[..16].try_into().unwrap();
        assert!(head_block_ok(key, &first));
        assert!(!head_block_ok(b"0000000000000000", &first));
    }

    #[test]
    fn non_v2_sample_rejected_early() {
        // sample 不是 V2 → v2_aes_segment None (不碰进程, 不会因没微信 panic)。
        assert!(v2_aes_segment(b"not a wechat dat at all").is_none());
    }

    #[test]
    fn valid_anchor_segments_enforces_multi_anchor() {
        // codex P1: 强制多锚 —— 全 V2 + ≥2 张互不相同, 否则 None (拒单锚/坏锚/重复锚)。
        let key = b"f55dbb3da8a161c6";
        let a = make_v2_sample(key, &fake_jpeg(600), 512);
        let b = make_v2_sample(key, &fake_jpeg(700), 400); // 不同 aes_size → 不同段
        assert_eq!(
            valid_anchor_segments(&[&a, &b]).map(|s| s.len()),
            Some(2),
            "2 张不同 V2 → 通过"
        );
        assert!(valid_anchor_segments(&[&a]).is_none(), "单锚 → 拒");
        assert!(valid_anchor_segments(&[]).is_none(), "空 → 拒");
        assert!(
            valid_anchor_segments(&[&a, &b, b"not v2"]).is_none(),
            "含非 V2 → 拒 (不静默丢)"
        );
        assert!(valid_anchor_segments(&[&a, &a]).is_none(), "重复锚 → 拒");
    }

    #[test]
    fn scan_bytes_finds_key_embedded_mid_run() {
        // 确定性验证扫描核心 (滑窗 + 多锚交叉验证): key 嵌在更长 alnum 串**中段**也能拎出。
        // (真机 live 测试受 key 瞬态影响会 flaky, 本测试把核心逻辑与进程解耦, 稳定复现。)
        let key = b"f55dbb3da8a161c6";
        let a = make_v2_sample(key, &fake_jpeg(600), 512);
        let b = make_v2_sample(key, &fake_jpeg(700), 400);
        let segs = valid_anchor_segments(&[&a, &b]).unwrap();
        let first: [u8; 16] = segs[0][..16].try_into().unwrap();
        let re = Regex::new(r"[0-9A-Za-z]{16,}").unwrap();

        // key 前后都接 alnum (同一 run 中段) + 首尾非 alnum 分隔 → 只有滑窗才能从中段取到 key。
        let mut mem = vec![0x00];
        mem.extend_from_slice(b"prefixAAAA"); // run 前缀 (非 key)
        mem.extend_from_slice(key);
        mem.extend_from_slice(b"BBBBsuffix");
        mem.push(0x00);
        assert_eq!(
            scan_bytes_for_key(&re, &mem, &first, &segs).as_ref(),
            Some(key),
            "从中段滑窗取到真 key"
        );

        // 不含 key 的 alnum 乱码 → None (多锚交叉验证不放假阳)。
        let noise = b"\x00zzz1234567890abcdefQWERTYuiop0000\x00";
        assert!(scan_bytes_for_key(&re, noise, &first, &segs).is_none(), "无 key → None");
    }

    /// 真机验证 (需微信在跑 + 环境变量 `IMG_V2_SAMPLES` = 逗号分隔的**多张** V2 .dat 路径, 建议 ≥3):
    /// `IMG_V2_SAMPLES=<p1,p2,p3> cargo test -p native-keyscan scan_finds_image_key_live -- --ignored --nocapture`
    #[test]
    #[ignore = "需微信在跑 + IMG_V2_SAMPLES 逗号分隔多张 V2 .dat"]
    fn scan_finds_image_key_live() {
        let env = std::env::var("IMG_V2_SAMPLES").expect("set IMG_V2_SAMPLES=<p1,p2,p3>");
        let datas: Vec<Vec<u8>> = env
            .split(',')
            .map(|p| std::fs::read(p.trim()).expect("读 sample 失败"))
            .collect();
        let refs: Vec<&[u8]> = datas.iter().map(Vec::as_slice).collect();
        assert!(refs.len() >= 2, "至少给 2 张 sample 做交叉验证 (建议 3)");
        for d in &refs {
            assert!(v2_aes_segment(d).is_some(), "某 sample 不是 V2 .dat");
        }
        let proc = WeixinProcess::open(None).expect("微信没跑? 打开进程失败");
        // image key **瞬态**驻留 (微信按需加载图片 key, 非常驻内存, 实测轮询多次才某轮在) → 重试多轮
        //  直到扫到 (同 wx-cli 提示"在微信里点开 2-3 张图后重试"). 实测第 4 轮命中真 key。
        let mut key = None;
        for round in 1..=8 {
            if let Some(k) = scan_image_key(&proc, &refs) {
                eprintln!("第 {round} 轮扫到");
                key = Some(k);
                break;
            }
        }
        let key = key.expect("8 轮都没扫到 (key 瞬态; 在微信里点开几张图触发加载再跑)");
        // 独立复核 (防回归): 找到的 key 能解**每一张** sample (交叉验证过 = 非假阳)。
        for d in &refs {
            assert!(
                full_segment_ok(&key, &v2_aes_segment(d).unwrap()),
                "key 解每张 sample 都过"
            );
        }
        // K-R4: 不打印 key 原值, 只 sha8。
        eprintln!(
            "✅ image key sha8 = {} (交叉验证 {} 张 sample)",
            crate::sha8(&key),
            refs.len()
        );
    }
}
