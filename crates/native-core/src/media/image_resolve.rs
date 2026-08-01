//! 图片 .dat 定位 (ADR-461, PR2-13) — 从消息 (talker_md5, create_time, image_md5) 直接构造 .dat 路径。
//!
//! 跟视频 [`resolve_video`](super::resolve::resolve_video) 不同: 视频靠 hardlink_db (md5 查表得文件名),
//! 图片**不需要 hardlink_db** —— packed_info md5 直接就是文件名, 路径可算。真库实测: 文件在盘时**路径
//! 100% 对** (单会话 300/300); 跨全部会话约 **70% 在盘**, 其余 30% 已被微信清理 (盘上任何目录都找不到,
//! 非路径 bug) —— 走 best-effort: resolve 只出路径, cli 探到就解、探不到就跳 (同 resolve_video 对历史已删)。
//!
//! 路径 = `msg/attach/<talker_md5>/<月份>/Img/<image_md5><后缀>` (相对 account 目录):
//! - `<talker_md5>` = Msg 表名 hash;
//! - `<月份>` = create_time 按**本地时区** `YYYY-MM` (微信按本地时间建目录);
//! - 后缀: `_W.dat` (完整, 实测 300/300) / `_h_W.dat` (高清, 罕见 3/300) / `_t_W.dat` (缩略, 300/300)。
//!   微信 4.x 一律带 `_W` (旧版 `.dat`/`_h.dat`/`_t.dat` 本账号 0 命中)。
//!
//! resolve 纯算路径不碰 FS —— **文件存在性由 cli 层逐候选探** (同 resolve_video 口径)。完整优先。

use chrono::{Local, LocalResult, TimeZone};

/// 图片 .dat 变体 (完整 / 高清 / 缩略)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageVariant {
    /// 完整图 `_W.dat` (导出首选)。
    Full,
    /// 高清图 `_h_W.dat` (罕见)。
    High,
    /// 缩略图 `_t_W.dat` (完整缺失时降级)。
    Thumb,
}

impl ImageVariant {
    /// 文件名后缀 (含 `.dat`)。
    fn suffix(self) -> &'static str {
        match self {
            ImageVariant::Full => "_W.dat",
            ImageVariant::High => "_h_W.dat",
            ImageVariant::Thumb => "_t_W.dat",
        }
    }
}

/// 图片文件定位结果 (路径相对 account 目录)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLocation {
    /// 变体 (完整 / 高清 / 缩略)。
    pub variant: ImageVariant,
    /// 相对 account 目录的路径 (`msg/attach/<talker>/<月>/Img/<md5><后缀>`)。
    pub rel_path: String,
}

/// 32 位小写/大写 hex 校验 (talker_md5 / image_md5 必须是 md5, 挡路径穿越: `/`、`..` 天然非 hex)。
fn is_md5_hex(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 用给定时区把秒级 ts 折成 `YYYY-MM` (超范围 → None)。抽 tz 参数 = 便于固定偏移锁跨月行为
/// (codex P2: 否则测试自算 expected, 实现被误改成 UTC 也发现不了)。
fn month_dir_in<Tz>(tz: &Tz, create_time_secs: i64) -> Option<String>
where
    Tz: TimeZone,
    Tz::Offset: std::fmt::Display,
{
    match tz.timestamp_opt(create_time_secs, 0) {
        // Single = 正常; Ambiguous = 夏令时折叠 (取较早那个 dt); 两者都能出月份。
        LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => Some(dt.format("%Y-%m").to_string()),
        LocalResult::None => None, // 超范围 ts
    }
}

/// create_time (秒级 Unix ts) → **本地时区** `YYYY-MM` (微信按本地时间建目录)。非法 ts → None。
fn month_dir_local(create_time_secs: i64) -> Option<String> {
    month_dir_in(&Local, create_time_secs)
}

/// 构造某月三变体候选 (完整→高清→缩略序)。纯路径, 不校验存在性。
fn build_candidates(talker_md5: &str, month_dir: &str, image_md5: &str) -> Vec<ImageLocation> {
    [ImageVariant::Full, ImageVariant::High, ImageVariant::Thumb]
        .into_iter()
        .map(|variant| ImageLocation {
            variant,
            rel_path: format!(
                "msg/attach/{talker_md5}/{month_dir}/Img/{image_md5}{}",
                variant.suffix()
            ),
        })
        .collect()
}

/// 从消息定位图片 .dat 候选 (完整→高清→缩略序)。cli 逐候选探 FS 取第一个存在的。
///
/// 空 Vec = talker_md5 / image_md5 非法 hex (挡穿越) 或 create_time 超范围。
/// `talker_md5` = Msg 表名; `create_time_secs` = 消息秒级 ts; `image_md5` = packed_info 抽出的文件名 md5。
#[must_use]
pub fn resolve_image(talker_md5: &str, create_time_secs: i64, image_md5: &str) -> Vec<ImageLocation> {
    // 校验 md5 hex: 既是数据健全性也是路径穿越防御 (含 `/`、`\`、`..` 的串天然非 hex → 空)。
    if !is_md5_hex(talker_md5) || !is_md5_hex(image_md5) {
        return Vec::new();
    }
    let Some(month_dir) = month_dir_local(create_time_secs) else {
        return Vec::new();
    };
    build_candidates(talker_md5, &month_dir, image_md5)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TALKER: &str = "b3010f26cfa89d420c8d8183bb3d5f5b";
    const MD5: &str = "e3e751d84c3d0e81189b27d6a3d4dcad";

    #[test]
    fn build_candidates_order_and_paths() {
        let locs = build_candidates(TALKER, "2025-07", MD5);
        assert_eq!(locs.len(), 3);
        assert_eq!(locs[0].variant, ImageVariant::Full);
        assert_eq!(
            locs[0].rel_path,
            "msg/attach/b3010f26cfa89d420c8d8183bb3d5f5b/2025-07/Img/e3e751d84c3d0e81189b27d6a3d4dcad_W.dat"
        );
        assert_eq!(locs[1].variant, ImageVariant::High);
        assert!(locs[1].rel_path.ends_with("_h_W.dat"));
        assert_eq!(locs[2].variant, ImageVariant::Thumb);
        assert!(locs[2].rel_path.ends_with("_t_W.dat"));
    }

    #[test]
    fn resolve_valid_matches_disk_shape() {
        // create_time 1752143852 真库落在 2025-07 (本地时区)。断言路径结构 + 月份跟本机 Local 一致。
        let locs = resolve_image(TALKER, 1_752_143_852, MD5);
        assert_eq!(locs.len(), 3);
        let expected_month = month_dir_local(1_752_143_852).unwrap();
        let expected = format!("msg/attach/{TALKER}/{expected_month}/Img/{MD5}_W.dat");
        assert_eq!(
            locs[0].rel_path, expected,
            "完整图路径 = msg/attach/<talker>/<月>/Img/<md5>_W.dat"
        );
    }

    #[test]
    fn invalid_talker_hex_empty() {
        assert!(
            resolve_image("../../etc", 1_752_143_852, MD5).is_empty(),
            "talker 非 hex (含穿越) → 空"
        );
        assert!(
            resolve_image("short", 1_752_143_852, MD5).is_empty(),
            "talker 长度非 32 → 空"
        );
    }

    #[test]
    fn invalid_md5_hex_empty() {
        assert!(
            resolve_image(TALKER, 1_752_143_852, "../../../secret").is_empty(),
            "md5 非 hex → 空"
        );
        assert!(
            resolve_image(TALKER, 1_752_143_852, "zzz1234567890abcdef1234567890abc").is_empty(),
            "md5 含非 hex 字符 → 空"
        );
    }

    #[test]
    fn no_path_traversal_in_output() {
        // 合法输入下路径不含穿越; 非法输入返空 (上一测已覆盖) → 双向保证 rel_path 无 `..`。
        for loc in resolve_image(TALKER, 1_752_143_852, MD5) {
            assert!(!loc.rel_path.contains(".."), "rel_path 无 ..");
            assert!(loc.rel_path.starts_with("msg/attach/"), "限定在 msg/attach 下");
        }
    }

    #[test]
    fn month_uses_offset_not_utc() {
        // codex P2 回归: 锁"用本地 offset 非 UTC"。2025-07-31 20:00:00 UTC = 2025-08-01 04:00 (+08:00) 跨月。
        use chrono::{FixedOffset, Utc};
        let secs = Utc.with_ymd_and_hms(2025, 7, 31, 20, 0, 0).unwrap().timestamp();
        let plus8 = FixedOffset::east_opt(8 * 3600).unwrap();
        assert_eq!(
            month_dir_in(&plus8, secs).as_deref(),
            Some("2025-08"),
            "UTC+8 跨到 8 月"
        );
        assert_eq!(
            month_dir_in(&Utc, secs).as_deref(),
            Some("2025-07"),
            "UTC 是 7 月 → 证明用的是 offset 非 UTC"
        );
    }

    #[test]
    fn month_dir_shape() {
        let m = month_dir_local(1_752_143_852).unwrap();
        assert_eq!(m.len(), 7);
        assert_eq!(&m[4..5], "-");
        assert!(m[..4].bytes().all(|b| b.is_ascii_digit()));
        assert!(m[5..].bytes().all(|b| b.is_ascii_digit()));
    }
}
