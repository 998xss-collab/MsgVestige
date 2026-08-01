//! wxgf 动图/静图 (内层 HEVC) → GIF/PNG 转码 (ffmpeg 子进程; 同 [`super::sns_media`] 的 node —— native-core
//! 托管媒体子进程工具, 不碰网络)。
//!
//! serve `/media` 即时转 + cli `decrypt-images` 批量转**共用**: 字节进字节出 (temp 文件中转, 复用证过的
//! `-f hevc` 强制 HEVC 解复用 + ffprobe 帧数判静图/动图)。ffmpeg/ffprobe 缺 → 调用方留原 wxgf (内容不丢)。
//!
//! ## wxgf 内层 HEVC (ffmpeg 自动检测不可靠, 实测 36 张只认 16 → 一律 `-f hevc` 强制) + 静图别转 GIF
//! 该账号 wxgf 多为**静图** (V2 内层实测约占完整图一半, 含唯一 1 张真动图) → 静图必走 PNG (无损), 只动图 GIF
//! (256 色)。帧数用 ffprobe `-count_frames` 真解码计数; 探不到 → 当动图 (保动画不丢, 静图掉质为次优兜底)。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// temp 文件唯一名计数 (配 process id 防并发/多进程撞名)。
static WXGF_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// ffmpeg 转码输出上限 (§8 critic: HEVC→GIF/PNG 可膨胀; 超此判异常不读回, 防解压炸弹爆内存)。贴纸/图正常几 MB。
const MAX_WXGF_OUT_BYTES: u64 = 64 * 1024 * 1024;
/// 子进程有界 deadline (media §8: 对病态媒体不挂死占死信号量)。ffmpeg 转码 30s / ffprobe 帧数 15s / `-version` 探活 5s。
const FFMPEG_TIMEOUT: Duration = Duration::from_secs(30);
const FFPROBE_TIMEOUT: Duration = Duration::from_secs(15);
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// 找 `ffmpeg` 可执行: 显式路径 → env `WECHAT_FFMPEG` → 当前 exe 同目录 (打包随产品) → PATH (`-version` 验)。
/// 都无 → `None` (调用方留 .wxgf / 出 octet-stream 不转)。
#[must_use]
pub fn resolve_ffmpeg(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Ok(p) = std::env::var("WECHAT_FFMPEG") {
        let pb = PathBuf::from(&p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // ⚠️ **`vendor/ffmpeg/…` 这两条原先漏了**, 而完整版发布包正是把 ffmpeg 放在
            //    `vendor/ffmpeg/ffmpeg.exe` (195MB) —— 包里带了它却永远找不到: 完整版用户
            //    doctor 照样报 ⚠️ 没找到、`export-voices --mp3` 照样退化成 wav, 而随包文档
            //    写着「要 mp3 就用完整版」。带了等于没带。
            //    这跟 sns_media.rs 里 node 的那个 bug **是同一个** —— 上一轮只修了被审查
            //    点名的 node, 没扫旁边同结构的 ffmpeg。判据是「凡完整包 vendor/ 下带的外部
            //    程序, 解析时都要查 vendor/」: 按判据全扫, 不按点名清单修。
            for cand in [
                "vendor/ffmpeg/ffmpeg.exe",
                "vendor/ffmpeg/ffmpeg",
                "ffmpeg.exe",
                "ffmpeg",
                "ffmpeg/ffmpeg.exe",
                "ffmpeg/ffmpeg",
            ] {
                let pb = dir.join(cand);
                if pb.is_file() {
                    return Some(pb);
                }
            }
        }
    }
    if exe_runnable(Path::new("ffmpeg")) {
        return Some(PathBuf::from("ffmpeg"));
    }
    None
}

/// 找 `ffprobe`: `ffmpeg` 同目录 (vendored 一起) → PATH。都无 → `None` (调用方当动图走 GIF 兜底)。
#[must_use]
pub fn resolve_ffprobe(ffmpeg: &Path) -> Option<PathBuf> {
    // ⚠️ **必须先排除空 parent**。`resolve_ffmpeg` 兜底到 PATH 时返回的是裸 `"ffmpeg"`,
    //    而 `Path::new("ffmpeg").parent()` 是 `Some("")` **不是 `None`** —— 于是
    //    `dir.join("ffprobe.exe")` 塌成相对路径 `"ffprobe.exe"`, 探的是**当前工作目录**,
    //    命中后直接进 `Command::new()` 执行。等于: 用户在哪个目录敲命令, 那个目录里的
    //    ffprobe.exe 就会被跑起来。实测坐实 (parent=Some("") → is_file 命中 cwd 下的文件)。
    if let Some(dir) = ffmpeg.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Some(p) = ["ffprobe.exe", "ffprobe"]
            .iter()
            .map(|n| dir.join(n))
            .find(|p| p.is_file())
        {
            return Some(p);
        }
    }
    // 随包 vendor 布局 —— **这条原先漏了**。ffprobe 跟 ffmpeg 一起发在
    // `vendor/ffmpeg/ffprobe.exe`, 但这里只靠"蹭 ffmpeg 的父目录"找它: 一旦 ffmpeg 来自
    // `--ffmpeg` / `WECHAT_FFMPEG` / PATH(精简包的包内清单正是叫用户这么配), 旁边那个
    // vendored ffprobe 就永远看不见 → `wxgf_frame_count` 返 None → 每张 wxgf 都被当动图
    // → 静图被写成 256 色 GIF 而不是无损 PNG。
    //
    // 判据是 wxgf.rs:44 那段写死的那条 (凡随包 vendor/ 下的外部件, **每条**查找路径都要覆盖
    // vendor/)。node(三轮)→ ffmpeg(四轮)→ ffprobe(五轮), 同一个判据连漏三轮 ——
    // 每次都只改了被点名的那一个。这次把 ffmpeg / ffprobe 两个 resolver 都补齐。
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for cand in [
                "vendor/ffmpeg/ffprobe.exe",
                "vendor/ffmpeg/ffprobe",
                "ffprobe.exe",
                "ffprobe",
            ] {
                let pb = dir.join(cand);
                if pb.is_file() {
                    return Some(pb);
                }
            }
        }
    }
    if exe_runnable(Path::new("ffprobe")) {
        return Some(PathBuf::from("ffprobe"));
    }
    None
}

/// `<exe> -version` 能成功跑 = 可用 (给 PATH 兜底判定)。有界超时 (探活正常秒回; 挂死 5s kill)。
fn exe_runnable(ff: &Path) -> bool {
    let mut cmd = Command::new(ff);
    cmd.arg("-version");
    super::subprocess::status_with_timeout(cmd, VERSION_TIMEOUT)
}

/// ffprobe 数 wxgf (HEVC) 的解码帧数: 1=静图 / >1=动图。取不到 → `None`。`-count_frames` 真解码计数 (静图秒回)。
/// 有界超时 (病态流不挂死); stdout 上限 64KB (帧数就一个整数)。
#[must_use]
pub fn wxgf_frame_count(ffprobe: &Path, wxgf: &Path) -> Option<u32> {
    let mut cmd = Command::new(ffprobe);
    cmd.args([
        "-v",
        "error",
        "-f",
        "hevc",
        "-select_streams",
        "v:0",
        "-count_frames",
        "-show_entries",
        "stream=nb_read_frames",
        "-of",
        "csv=p=0",
    ])
    .arg(wxgf);
    let out = super::subprocess::output_with_timeout(cmd, FFPROBE_TIMEOUT, 64 * 1024)?;
    String::from_utf8_lossy(&out).trim().parse().ok()
}

/// 内存 wxgf 字节 → `(图字节, content-type)`。**静图→PNG (无损) / 动图→GIF**; ffprobe 缺则当动图 (保动画)。
///
/// temp 文件中转 (唯一名 process-id + 计数, 用完删双清)。ffmpeg 出错 / 无输出 → `None` (调用方留原 wxgf, 内容不丢)。
///
/// 一律 `-f hevc` 强制 HEVC 解复用器 (ffmpeg 自动检测对部分 wxgf 不可靠)。
#[must_use]
pub fn transcode_wxgf_bytes(ffmpeg: &Path, ffprobe: Option<&Path>, wxgf: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    let seq = WXGF_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("native-wxgf-{}-{seq}", std::process::id()));
    let in_path = base.with_extension("wxgf");
    if std::fs::write(&in_path, wxgf).is_err() {
        return None;
    }
    // 帧数判静/动 (探不到 → 当动图, GIF 保动画不丢)。
    let animated = ffprobe
        .and_then(|pp| wxgf_frame_count(pp, &in_path))
        .is_none_or(|n| n > 1);
    let (ext, ct): (&str, &'static str) = if animated {
        ("gif", "image/gif")
    } else {
        ("png", "image/png")
    };
    let out_path = base.with_extension(ext);
    let mut cmd = Command::new(ffmpeg);
    cmd.args(["-y", "-loglevel", "error", "-f", "hevc", "-i"]).arg(&in_path);
    if !animated {
        cmd.args(["-frames:v", "1"]); // 静图只取首帧 → PNG
    }
    cmd.arg(&out_path);
    let ran = super::subprocess::status_with_timeout(cmd, FFMPEG_TIMEOUT);
    // 输出上限: 超 MAX_WXGF_OUT_BYTES 判异常不读回 (防 HEVC→GIF 膨胀爆内存, §8 critic)。
    let result = if ran && out_path.metadata().is_ok_and(|m| m.len() <= MAX_WXGF_OUT_BYTES) {
        std::fs::read(&out_path).ok().map(|b| (b, ct))
    } else {
        None
    };
    // 双清 temp (成功/失败都清; 不留半成品)。
    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&out_path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcode_bogus_ffmpeg_returns_none_and_cleans() {
        // 不存在的 ffmpeg → None (graceful), 且 temp 输入文件被清 (双清逻辑)。
        let before: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("native-wxgf-"))
            .collect();
        let out = transcode_wxgf_bytes(Path::new("definitely-not-a-real-ffmpeg-xyz"), None, b"wxgf\x13\x00fake");
        assert!(out.is_none(), "无 ffmpeg → None");
        let after: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("native-wxgf-"))
            .collect();
        assert_eq!(before.len(), after.len(), "temp .wxgf 已清 (无泄漏)");
    }

    #[test]
    fn resolve_ffmpeg_explicit_nonexistent_falls_through() {
        // 显式路径不存在 → 不 panic, 继续回退链 (最终 env/PATH 无则 None)。
        let _ = resolve_ffmpeg(Some("/no/such/ffmpeg"));
    }

    /// **回归**: `resolve_ffprobe` 不许把探测落到当前工作目录。
    ///
    /// `resolve_ffmpeg` 兜底到 PATH 时返回裸 `"ffmpeg"`, 而 `Path::new("ffmpeg").parent()`
    /// 是 `Some("")` **不是 `None`** —— 于是 `dir.join("ffprobe.exe")` 塌成相对路径, 探到的是
    /// **进程当前工作目录**, 命中后直接 `Command::new()` 跑起来。用户在哪个目录敲命令, 那个
    /// 目录里的 ffprobe.exe 就会被执行。(五轮审查逮到, 用一个 5 行程序坐实 parent=Some("")。)
    ///
    /// 这个测试**必须能打穿**: 去掉 `resolve_ffprobe` 里那个 `.filter(非空)` 就该红。
    #[test]
    fn ffprobe_never_probes_cwd() {
        let dir = std::env::temp_dir().join(format!("ffprobe_cwd_guard_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let planted = dir.join("ffprobe.exe");
        std::fs::write(&planted, b"not a real ffprobe").expect("写夹具");

        // 把 cwd 切到埋了假 ffprobe 的目录, 再用裸 "ffmpeg" (= PATH 兜底的返回值) 去解析。
        let saved = std::env::current_dir().expect("存 cwd");
        std::env::set_current_dir(&dir).expect("切 cwd");
        let got = resolve_ffprobe(Path::new("ffmpeg"));
        // **canonicalize 必须在还原 cwd 之前做** —— 相对路径是相对"当时的 cwd"解析的。
        // 我第一版把它放在还原之后, 于是带 bug 时返回的 "ffprobe.exe" 被按仓库根解析、
        // canonicalize 失败、退回相对路径, 跟绝对的 bad 一比不相等 → **测试照样绿**。
        // 注入 bug 复跑才发现这个假守卫 (assert 恒真的经典形状)。
        let hit = got
            .as_ref()
            .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()));
        std::env::set_current_dir(&saved).expect("还原 cwd");
        let _ = std::fs::remove_file(&planted);

        // 允许 None (机器上没 ffprobe), 也允许命中 PATH 上真正的 ffprobe;
        // **不允许**命中刚埋进 cwd 的那个。
        if let Some(hit) = hit {
            let bad = std::fs::canonicalize(&dir)
                .unwrap_or_else(|_| dir.clone())
                .join("ffprobe.exe");
            assert_ne!(
                hit,
                bad,
                "resolve_ffprobe 命中了当前工作目录里的 ffprobe: {}",
                hit.display()
            );
        }
    }
}
