//! log — 统一日志初始化 (cli / adapter 共用; logging-日志.md 任务 1)。
//!
//! 终端 (stderr) + 按天滚动文件双输出; 级别 `RUST_LOG` 覆盖 > config `log_level`。
//! K-R4: tracing 字段脱敏靠类型层 (`Wxid` Display=sha8 / `MasterKey` 无 Display) + [`crate::redact`] 工具;
//! 本模块只管"日志去哪 / 什么级别", 不改字段值。
//! metrics 红线: 不接任何 metrics / 遥测 (logging-日志.md §2)。

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// 初始化统一日志: 终端 (stderr) + 按天文件 (`<log_dir>/native.log.YYYY-MM-DD`)。
///
/// 级别: `RUST_LOG` 环境变量优先, 否则用 `log_level` (如 `"info"`)。
/// `log_dir` 支持 `%LOCALAPPDATA%` / `%USERPROFILE%` 占位展开。建目录失败则只走终端 (不阻塞运行)。
///
/// 用 **blocking appender (每条同步写盘)**: cli 短命令进程秒退, non-blocking 后台线程可能来不及
/// flush → 日志丢; 日志量不大, 同步写可接受。**只能调一次** (tracing 全局 subscriber 单例)。
pub fn init_logging(log_level: &str, log_dir: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    let dir = expand_env(log_dir);
    // Builder 路径 (非 daily() 快捷函数) 才有 max_log_files 清理 → 旧文件按 N 份上限自动删,
    // 防日志无限累积撑爆磁盘 (双审 P0; daily() 快捷函数无清理能力, 两条互斥)。
    let file_appender = if std::fs::create_dir_all(&dir).is_ok() {
        tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("native.log")
            .max_log_files(14) // 留最近 14 天, 更早的自动删
            .build(&dir)
            .ok()
    } else {
        None
    };
    if let Some(appender) = file_appender {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_writer(appender).with_ansi(false)) // 文件: 无颜色码
            .with(fmt::layer().with_writer(std::io::stderr)) // 终端
            .init();
        // 自证一条 (证明日志落文件 + 格式; log_dir 是路径非敏感)。
        tracing::info!(log_dir = %dir, "日志系统就绪 (终端 + 按天文件, 留 14 天)");
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
        tracing::warn!("日志文件不可用 (目录建不了 / appender 建失败), 只走终端");
    }
    // subscriber 就绪后装 panic 钩子 —— panic 桥接进 tracing (脱敏), abort 前落一条 (§4.5-B / 收尾③)。
    install_panic_hook();
}

/// 擦除文本里的明文 `wxid_` 形态 → `wxid_<sha8>` (panic 消息自由文本兜底脱敏; 无 regex 依赖)。
///
/// panic 消息是自由文本、逐值 `sha8` 够不到 → 对最常见的明文账号形态 (`wxid_` + 连续小写字母数字) 兜底。
/// 注: 无 `wxid_` 前缀的 legacy 号 (如 momo…) 检不出 —— 主保障是**别 `panic!` 带明文** (K-R4); 此仅兜底常见形态。
fn redact_panic_msg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find("wxid_") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 5..];
        let end = after
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
            .unwrap_or(after.len());
        if end > 0 {
            out.push_str("wxid_");
            out.push_str(&crate::redact::sha8(&rest.as_bytes()[pos..pos + 5 + end]));
        } else {
            out.push_str("wxid_"); // "wxid_" 后无字母数字 → 原样 (非账号)
        }
        rest = &rest[pos + 5 + end..];
    }
    out.push_str(rest);
    out
}

/// 装 panic 钩子: 把 panic 桥接进 `tracing::error!` (脱敏, K-R4; logging-日志.md §4.5-B / 任务1收尾③)。
///
/// `panic=abort` 下钩子在进程终止**前**跑 → 崩溃**位置 + (脱敏)原因**落进日志文件 (同步 appender 已 flush,
/// 不再"崩了就没痕迹")。`catch_unwind` 在 abort 下接不住是死代码 → 不做恢复、只做记录。
/// 位置 (file:line:col) 非敏感、是主诊断; 消息过 [`redact_panic_msg`] 兜底脱敏。
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map_or_else(
            || "unknown".to_string(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<非字符串 panic payload>".to_string());
        let redacted = redact_panic_msg(&msg);
        tracing::error!(location = %loc, "PANIC (进程即将 abort): {redacted}");
        // 旁路 EnvFilter 兜底 (审查 P3): RUST_LOG=off / 目标 =off 会把上面 error! 一并过滤 → 崩溃静默丢诊断。
        // 直接写 stderr 保证崩溃原因至少可见 (已脱敏, 与 error! 内容一致; panic 罕见终态, 重复一行 stderr 可接受)。
        eprintln!("[PANIC] at {loc}: {redacted}");
    }));
}

/// 展开 `%LOCALAPPDATA%` / `%USERPROFILE%` 环境占位 (Windows 风格路径)。占位对应环境变量缺失则原样留。
///
/// pub: `logs bundle` (R2/⑧) 复用它把 config 里的 `log_dir` 展开成真实路径去收日志。
pub fn expand_env(path: &str) -> String {
    let mut out = path.to_string();
    for (var, placeholder) in [("LOCALAPPDATA", "%LOCALAPPDATA%"), ("USERPROFILE", "%USERPROFILE%")] {
        if out.contains(placeholder) {
            if let Ok(v) = std::env::var(var) {
                out = out.replace(placeholder, &v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{expand_env, redact_panic_msg};

    #[test]
    fn redact_panic_msg_scrubs_plain_wxid() {
        let out = redact_panic_msg("boom for wxid_abcd1234efgh567 at step 3");
        assert!(!out.contains("ym853euf2gpg22"), "明文 wxid 被擦成指纹");
        assert!(out.contains("wxid_"), "保留 wxid_ 前缀 + sha8");
        assert!(out.contains("at step 3"), "非敏感文本保留");
    }

    #[test]
    fn redact_panic_msg_leaves_normal_message() {
        // 最常见的 panic (stdlib 消息) 非敏感 → 原样可读, 不无脑打码。
        let m = "index out of bounds: the len is 3 but the index is 5";
        assert_eq!(redact_panic_msg(m), m, "非敏感 panic 消息原样可读");
    }

    #[test]
    fn redact_panic_msg_handles_multiple_and_edge() {
        let out = redact_panic_msg("a wxid_abc123 b wxid_ c wxid_def456");
        assert!(!out.contains("abc123") && !out.contains("def456"), "多处 wxid 都擦");
        assert!(out.contains("wxid_ c"), "光 wxid_ 后无字母数字 → 原样(非账号)");
    }

    #[test]
    fn expand_env_replaces_known_placeholder() {
        std::env::set_var("LOCALAPPDATA", r"C:\Users\x\AppData\Local");
        let out = expand_env(r"%LOCALAPPDATA%\msgvestige\logs");
        assert!(out.starts_with(r"C:\Users\x\AppData\Local"), "占位被展开");
        assert!(!out.contains("%LOCALAPPDATA%"));
    }

    #[test]
    fn expand_env_leaves_plain_path() {
        assert_eq!(expand_env(r"C:\logs"), r"C:\logs");
    }
}
