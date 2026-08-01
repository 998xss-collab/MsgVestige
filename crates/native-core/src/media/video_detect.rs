//! 视频导出判定 (ADR-421 §3.3; **2026-07-11 按竞品调研 + 真库全量复核重定**) — 判一个视频文件
//! 该【明文导出 / 降级】。
//!
//! **本地视频落盘即明文。** 真库全量复核 (此账号 `msg/video` 下 2754 个视频, 含 164 个 `_raw`, 用
//! ffmpeg 逐个真解码): **2754/2754 全能播 = 全明文, 0 加密**。旧判据两个前提均被推翻:
//! - `_raw` **不是加密标志** —— 是"原画版 vs 压缩解码缓存"命名 (164 个 `_raw` 全能解码; 竞品
//!   MemoTrace/WeChatMsg 亦如此用)。
//! - `mdat` 首 NAL 长度启发式 **误判约四成明文为加密** (如 mdat 首 4 字节是编码器 SEI `…Lavc58…`
//!   被当 NAL 长度→荒谬→误判加密), 且是循环论证 (旧"742 非raw 加密"其实是这套启发式自己的误报)。
//!
//! **竞品调研 (~35 个工具)**: 对本地视频做内容级"加密/明文"判定的 **一个都没有** —— 都是 md5→hardlink
//! 查到文件即当明文拷出/发出; 最"讲究"的 (WeChatDataAnalysis) 也只做一个轻量 **文件头 `ftyp` box
//! 健全检查**。本判定即采此行业通行法: 文件头是合法 mp4 (`ftyp` box) → 明文导出; 否则 (随机字节 /
//! 整体加密 / 损坏 / 非视频文件) → 降级不导, 避免把非视频字节当 `.mp4` 拷出。
//!
//! ⚠️ 局限 (**与全行业一致**): 若某视频"容器结构完好但 `mdat` 内容被加密", `ftyp` 检查会放行 —— 但
//! 真库全量复核无此类样本 (2754/2754 明文), 竞品对本地视频亦无人能判此情形。真碰到 (未播账号等)
//! 由下游"导一个查一个"兜底, 不在判定层硬猜。

/// `classify_video` 的 `head` 至少读这么多字节 —— 只需前 8 字节判 `ftyp` box (在字节 4..8), 读 16 留余量。
/// (旧值 65536 是为深扫 `mdat` NAL, 该启发式已废除, 见本模块头。)
pub const VIDEO_HEAD_LEN: usize = 16;

/// 视频导出判定 (ADR-421 §3.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoKind {
    /// 明文可播 (文件头是合法 mp4 `ftyp` box) — 拷贝 / HTML `<video>` 嵌入导出。
    Plaintext,
    /// 无法直接导出 (文件头非合法 mp4: 随机字节 / 整体加密 / 损坏 / 非视频) — 降级不导 (§3.3/KI-D)。
    Encrypted,
}

/// 判定视频文件导出方式 (ADR-421 §3.3; 竞品通行的轻量文件头检查)。
/// - `head`: 文件开头若干字节 (调用方按 [`VIDEO_HEAD_LEN`] 读)。
///
/// 头是合法 mp4 (`ftyp` box @ 字节 4..8) → [`VideoKind::Plaintext`]; 否则 → [`VideoKind::Encrypted`] 降级。
/// **不再看文件名 `_raw`、不再做 mdat-NAL 内容启发式** —— 两者前提均被真库全量复核推翻 (见本模块头)。
/// `_raw` 仍是候选**排序**信号 (原画优先, 见 `resolve.rs`::[`is_raw_name`]), 但不参与明文/加密判定。
#[must_use]
pub fn classify_video(head: &[u8]) -> VideoKind {
    if has_mp4_ftyp(head) {
        VideoKind::Plaintext
    } else {
        VideoKind::Encrypted
    }
}

/// 文件头是否合法 mp4: 顶层 box 类型 (字节 4..8, 紧跟 4 字节 box size) 是 `ftyp` (mp4 文件类型盒,
/// ISO BMFF 规范要求为首盒)。竞品 WeChatDataAnalysis 同款判据; 真库 2754/2754 视频首盒均 `ftyp`。
fn has_mp4_ftyp(head: &[u8]) -> bool {
    head.len() >= 8 && &head[4..8] == b"ftyp"
}

/// 文件名是否微信"原始/原画"视频 (`<md5>_raw.mp4`, 大小写不敏感)。
/// **非加密标志** —— `_raw`=原画版 / `<md5>.mp4`=压缩解码缓存, 两者皆明文 (真库 164 个 `_raw` 全能解码;
/// 竞品 MemoTrace 亦如此用)。`resolve.rs` 复用: 候选**排序** (非 `_raw` 优先) 用, 不参与明文/加密判定。
pub(crate) fn is_raw_name(file_name: &str) -> bool {
    file_name.to_ascii_lowercase().ends_with("_raw.mp4")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合法 mp4 文件头: 4 字节 box size + `ftyp` + brand。
    fn ftyp_head() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x20u32.to_be_bytes());
        v.extend_from_slice(b"ftyp");
        v.extend_from_slice(b"isom\0\0\x02\0");
        v
    }

    #[test]
    fn valid_ftyp_is_plaintext() {
        assert_eq!(classify_video(&ftyp_head()), VideoKind::Plaintext);
    }

    #[test]
    fn no_ftyp_is_encrypted() {
        // 无 ftyp 首盒 (随机字节 / 整体加密 / 非视频) → 降级。用真库加密 _raw 曾误当明文的字节模式。
        let rnd = [0x21u8, 0x11, 0x45, 0x00, 0x14, 0x50, 0x01, 0x46, 0xff, 0xf1];
        assert_eq!(classify_video(&rnd), VideoKind::Encrypted);
    }

    #[test]
    fn short_head_is_encrypted() {
        assert_eq!(classify_video(b""), VideoKind::Encrypted);
        assert_eq!(classify_video(b"ftyp"), VideoKind::Encrypted); // <8 字节, 判不了
    }

    #[test]
    fn ftyp_must_be_at_offset_4() {
        // `ftyp` 出现在别处 (如首字节) 不算 —— 必须是 box 类型位 (4..8), 防碰巧含子串。
        let mut v = b"ftypisom".to_vec();
        v.extend_from_slice(b"\0\0\x02\0");
        assert_eq!(classify_video(&v), VideoKind::Encrypted);
    }

    #[test]
    fn is_raw_name_case_insensitive() {
        // _raw 仅供 resolve 排序; 大小写不敏感, 须 _raw.mp4 后缀 (非子串)。
        assert!(is_raw_name("X_raw.mp4"));
        assert!(is_raw_name("X_RAW.MP4"));
        assert!(!is_raw_name("X.mp4"));
        assert!(!is_raw_name("xrawy.mp4"));
    }
}
