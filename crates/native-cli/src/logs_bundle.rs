//! logs bundle — 把日志 + 配置 + 版本/OS 打成一个 zip, 给内测报 bug 用 (⑧ R2)。
//!
//! K-R4 (日志不出明文 wxid/master key):
//! - **只收**已脱敏的日志文件 (`native.log*`) + 调用侧生成的 info.txt + (存在则) config.toml;
//!   **绝不收** key 缓存 (`cache/keys.enc`) / 任何 `.db` / data 目录。
//! - config.toml 里的 `auth_password` (DPAPI 密文) 逐行打码 ([`redact_config`])。
//! - 日志本身在**写入时**已按 K-R4 脱敏 (Wxid Display=sha8 / MasterKey 无 Display), 本模块原样打包,
//!   不二次改动 hex (避免误伤合法 sha8/sha256 指纹); 但对**明文 wxid_ 形态**做一层兜底擦除
//!   ([`build_bundle`] 内 [`scrub_wxid`]) —— 正常日志不该有, 命中即打码 + 计数上报 (供 dev 回源头修)。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result};

/// 明文 wxid 形态 (`wxid_` + 12~20 位小写字母数字)。日志按 K-R4 不该出现明文 wxid; 命中=写入侧漏了。
/// 注意: 无 `wxid_` 前缀的 legacy 号 (如 momo526005) 检不出 —— 主保障是写入时类型层脱敏, 此仅兜底常见形态。
static WXID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"wxid_[0-9a-z]{12,20}").expect("wxid 正则合法"));

/// 打包结果 (给调用侧打印)。
pub struct BundleReport {
    /// 生成的 zip 路径。
    pub out_path: PathBuf,
    /// zip 内条目名 (info.txt / config.toml / logs/native.log.*)。
    pub entries: Vec<String>,
    /// 收进的日志文件数。
    pub log_file_count: usize,
    /// 未压缩总字节 (原始大小)。
    pub total_uncompressed: u64,
    /// 兜底擦除命中的明文 wxid 次数 (>0 说明某处日志写入漏了脱敏, 该回源头修)。
    pub wxid_scrubbed: usize,
    /// 收集过程中的告警 (如读不了的日志被跳过); 非空时也会作 warnings.txt 进包。
    pub warnings: Vec<String>,
}

/// 敏感键判定: 键的**末段**(去点路径) ∈ 显式名单, 或键名含通用秘密子串。
///
/// - 显式名单 = ADR-403 §3.1 `[cli]` 两个 designated 敏感字段 (native-core/src/config.rs:14 手写 Debug 脱敏);
/// - 子串兜底 = 未来 schema 新增秘密字段的保险 (呼应 §9 教训: 名单要能兜未知; 诊断包里过度打码无害)。
///
/// 用**末段**匹配 (`rsplit('.')`) 是为了让点键 `cli.default_account_wxid` 也命中 (审查 P1: 原精确整串匹配
/// 被点键/内联表书写绕过 → legacy 明文账号泄漏)。
fn is_sensitive_key(key: &str) -> bool {
    const SENSITIVE_KEYS: [&str; 2] = ["auth_password", "default_account_wxid"];
    const SECRET_SUBSTR: [&str; 9] = [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "wxid",
        "key",
        "apikey",
        "private",
    ];
    let last = key.rsplit('.').next().unwrap_or(key).trim();
    let lc = last.to_ascii_lowercase();
    SENSITIVE_KEYS.contains(&last) || SECRET_SUBSTR.iter().any(|s| lc.contains(s))
}

/// 递归对解析后的 TOML 表打码 (任意深度: 子表 / 表数组 / 内联表)。
fn redact_table(t: &mut toml::Table) {
    for (k, v) in t.iter_mut() {
        if is_sensitive_key(k) {
            *v = toml::Value::String("<REDACTED>".to_string());
        } else if let Some(inner) = v.as_table_mut() {
            redact_table(inner);
        } else if let Some(arr) = v.as_array_mut() {
            for item in arr.iter_mut() {
                if let Some(it) = item.as_table_mut() {
                    redact_table(it);
                }
            }
        }
    }
}

/// config.toml 敏感值打码。**先解析成 TOML 结构、再逐键递归打码, 免受书写形态影响** ——
/// 段式 `[cli]` / 点键 `cli.x` / 内联表 `cli = {x=..}` / 表数组 解析后都归一成嵌套表, 统一处理
/// (审查 P1: 原逐行文本匹配被点键/内联表绕过 → 明文账号泄漏; 解析式免疫书写形态)。
/// 解析失败 (坏 toml, 反正也 load 不了) → 回退逐行尽力打码。保留其余非敏感字段值供排 bug。
pub fn redact_config(text: &str) -> String {
    match text.parse::<toml::Table>() {
        Ok(mut table) => {
            redact_table(&mut table);
            toml::to_string(&table).unwrap_or_else(|_| "# (config 重序列化失败, 为防泄漏已省略内容)\n".to_string())
        }
        Err(_) => redact_lines(text),
    }
}

/// 逐行尽力打码 (仅**坏 toml 回退路**; 正常结构化路见 [`redact_table`])。保留缩进/注释/其余内容。
fn redact_lines(text: &str) -> String {
    text.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if !line.contains('=') || trimmed.starts_with('#') {
                return line.to_string(); // 段头 [x] / 注释 / 无值行 原样
            }
            let key = line
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            if is_sensitive_key(key) {
                let indent = &line[..line.len() - trimmed.len()];
                format!("{indent}{key} = \"<REDACTED>\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 兜底擦除明文 wxid, 返回 (擦除后文本, 命中次数)。
fn scrub_wxid(text: &str) -> (String, usize) {
    let count = WXID_RE.find_iter(text).count();
    if count == 0 {
        (text.to_string(), 0)
    } else {
        (WXID_RE.replace_all(text, "wxid_<REDACTED>").into_owned(), count)
    }
}

/// 收集 `log_dir` 下的日志文件 (`native.log*`), 按名 (=时间) 升序。
/// `days` 给了则只留最近 N 个 (日志按天滚动, 一天一文件; 见 common::log 留 14 天)。
pub fn collect_log_files(log_dir: &Path, days: Option<u32>) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(log_dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    // 绑死滚动命名 native.log / native.log.YYYY-MM-DD (审查 P3: 裸 starts_with 会误收
                    // native.logins.db 之类)。
                    .is_some_and(|n| n == "native.log" || n.starts_with("native.log."))
        })
        .collect();
    files.sort(); // native.log.YYYY-MM-DD → 字典序 == 时间序
    if let Some(d) = days {
        let d = d as usize;
        if files.len() > d {
            files = files.split_off(files.len() - d); // 留最后 (最近) N 个
        }
    }
    files
}

/// 建 bundle: info.txt + (存在则)脱敏 config.toml + 日志文件, 写 zip 到 `out_path`。
/// 所有文本内容过一遍 [`scrub_wxid`] 兜底 (计数上报)。日志非 UTF-8 时原样收 (不擦, 计 warn)。
pub fn build_bundle(
    info_txt: &str,
    log_files: &[PathBuf],
    config: Option<String>, // 已脱敏 (redact_config) 的 config.toml 文本
    out_path: &Path,
) -> Result<BundleReport> {
    use zip::write::SimpleFileOptions;

    let file = fs::File::create(out_path).with_context(|| format!("建 zip 失败: {}", out_path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut entries: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    let mut wxid_hits: usize = 0;
    let mut warnings: Vec<String> = Vec::new();

    // 小工具: 写一条文本条目 (过 scrub)。
    let mut write_text = |zip: &mut zip::ZipWriter<fs::File>, name: &str, text: &str| -> Result<()> {
        let (clean, hits) = scrub_wxid(text);
        wxid_hits += hits;
        zip.start_file(name, opts)?;
        zip.write_all(clean.as_bytes())?;
        total += clean.len() as u64;
        entries.push(name.to_string());
        Ok(())
    };

    write_text(&mut zip, "info.txt", info_txt)?;
    if let Some(cfg_text) = config {
        write_text(&mut zip, "config.toml", &cfg_text)?;
    }

    // 日志: UTF-8 就过 scrub, 非 UTF-8 原样收 (tracing 写 UTF-8, 罕见)。读不了的**跳过 + 记 warning**,
    // 不炸整包 (审查 P2: 单文件读失败会中断整包并留半截 zip; 诊断包恰在 serve/watch 滚删日志时最需要)。
    let mut log_count = 0usize;
    for p in log_files {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("native.log");
        let entry = format!("logs/{name}");
        let raw = match fs::read(p) {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!("跳过读不了的日志 {}: {e}", p.display()));
                continue;
            }
        };
        match std::str::from_utf8(&raw) {
            Ok(text) => {
                let (clean, hits) = scrub_wxid(text);
                wxid_hits += hits;
                zip.start_file(&entry, opts)?;
                zip.write_all(clean.as_bytes())?;
                total += clean.len() as u64;
            }
            Err(_) => {
                zip.start_file(&entry, opts)?;
                zip.write_all(&raw)?;
                total += raw.len() as u64;
            }
        }
        entries.push(entry);
        log_count += 1;
    }

    // 有跳过的文件 → 附一份 warnings.txt (让收件人知道哪些日志没进包)。
    if !warnings.is_empty() {
        zip.start_file("warnings.txt", opts)?;
        zip.write_all(warnings.join("\n").as_bytes())?;
        entries.push("warnings.txt".to_string());
    }

    zip.finish().context("zip 收尾失败")?;
    Ok(BundleReport {
        out_path: out_path.to_path_buf(),
        entries,
        log_file_count: log_count,
        total_uncompressed: total,
        wxid_scrubbed: wxid_hits,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn redact_config_masks_auth_password() {
        let src = "[cli]\nauth_password = \"AQAAANCM...base64ciphertext...\"\nother = 1\n";
        let out = redact_config(src);
        assert!(out.contains("auth_password = \"<REDACTED>\""), "auth_password 被打码");
        assert!(!out.contains("base64ciphertext"), "密文原文不留");
        assert!(out.contains("other = 1"), "其余行保留");
    }

    #[test]
    fn redact_config_keeps_nonsensitive_values() {
        // 解析式重序列化: 敏感值打码 + 非敏感字段值保留 (注释/精确格式会丢, 是换 K-R4 稳健性的可接受取舍)。
        let src = "# 注释\n  auth_password = 'x'\n[observability]\nlog_level = \"info\"";
        let out = redact_config(src);
        assert!(!out.contains("'x'") && !out.contains("\"x\""), "auth_password 值打码");
        assert!(out.contains("<REDACTED>"), "有打码标记");
        assert!(out.contains("log_level = \"info\""), "非敏感字段值保留");
    }

    #[test]
    fn redact_config_masks_default_account_wxid() {
        // 按字段名打码, 不靠 wxid_ 形态 → legacy 明文账号 (momo…, 无 wxid_ 前缀) 也兜住。
        let out = redact_config("[cli]\ndefault_account_wxid = \"momo526005\"\n");
        assert!(
            out.contains("default_account_wxid = \"<REDACTED>\""),
            "默认账号按字段名打码"
        );
        assert!(!out.contains("momo526005"), "legacy 明文账号也被打掉");
    }

    #[test]
    fn redact_config_masks_generic_secret_keys_but_keeps_paths() {
        let src =
            "[custom]\napi_token = \"abc123\"\nsome_password = \"p\"\nlog_level = \"info\"\ndata_dir = \"C:/x\"\n";
        let out = redact_config(src);
        assert!(out.contains("api_token = \"<REDACTED>\""), "含 token 的键兜底打码");
        assert!(
            out.contains("some_password = \"<REDACTED>\""),
            "含 password 的键兜底打码"
        );
        assert!(out.contains("log_level = \"info\""), "非敏感字段保留");
        assert!(out.contains("data_dir = \"C:/x\""), "路径字段不误伤 (key 不含秘密词)");
    }

    #[test]
    fn redact_config_masks_dotted_key() {
        // 点键写法 (审查 P1): cli.default_account_wxid / cli.auth_password 也必须打码。
        let out = redact_config("cli.default_account_wxid = \"momo526005\"\ncli.auth_password = \"dpapi:x\"\n");
        assert!(!out.contains("momo526005"), "点键 legacy 账号被打码");
        assert!(!out.contains("dpapi:x"), "点键 auth_password 被打码");
        assert!(out.contains("<REDACTED>"));
    }

    #[test]
    fn redact_config_masks_inline_table() {
        // 内联表写法 (审查 P1): cli = { default_account_wxid = "momo…", auth_password = "…" }。
        let out = redact_config("cli = { default_account_wxid = \"momo526005\", auth_password = \"dpapi:secret\" }\n");
        assert!(!out.contains("momo526005"), "内联表 legacy 账号被打码");
        assert!(!out.contains("dpapi:secret"), "内联表 auth_password 被打码");
    }

    #[test]
    fn redact_config_bad_toml_falls_back_to_line_redaction() {
        // 坏 toml (解析失败) → 逐行回退仍打掉 auth_password (不整体泄漏)。
        let out = redact_config("[[[ 坏 toml\nauth_password = \"secret\"\n");
        assert!(!out.contains("\"secret\""), "坏 toml 回退路仍打掉 auth_password");
    }

    #[test]
    fn scrub_wxid_replaces_plaintext() {
        let (out, n) = scrub_wxid("open account wxid_abcd1234efgh567 then done");
        assert_eq!(n, 1, "命中一次");
        assert!(out.contains("wxid_<REDACTED>"));
        assert!(!out.contains("ym853euf2gpg22"), "明文号不留");
    }

    #[test]
    fn scrub_wxid_leaves_sha_fingerprint() {
        // sha8 指纹 (合法, K-R4 允许) 不该被误擦。
        let src = "account sha8=f0e1d2c3 opened ok";
        let (out, n) = scrub_wxid(src);
        assert_eq!(n, 0, "指纹不算 wxid 形态");
        assert_eq!(out, src);
    }

    #[test]
    fn build_bundle_writes_zip_with_expected_entries() {
        let dir = tempfile::tempdir().unwrap();
        // 造两个假日志 (其中一个混入明文 wxid 测兜底擦除)。
        let log_dir = dir.path().join("logs");
        fs::create_dir_all(&log_dir).unwrap();
        fs::write(log_dir.join("native.log.2026-07-12"), "INFO 正常一行 sha8=abcd1234\n").unwrap();
        fs::write(
            log_dir.join("native.log.2026-07-13"),
            "INFO 漏脱敏 wxid_abcd1234efgh567 出现\n",
        )
        .unwrap();

        let logs = collect_log_files(&log_dir, None);
        assert_eq!(logs.len(), 2, "两个日志都收");

        let out = dir.path().join("bundle.zip");
        let cfg = redact_config("[cli]\nauth_password = \"secret\"\n");
        let report = build_bundle("info here", &logs, Some(cfg), &out).unwrap();

        assert!(out.exists(), "zip 生成");
        assert_eq!(report.log_file_count, 2);
        assert_eq!(report.wxid_scrubbed, 1, "混入的明文 wxid 被兜底擦除并计数");
        assert!(report.entries.contains(&"info.txt".to_string()));
        assert!(report.entries.contains(&"config.toml".to_string()));
        assert!(report.entries.contains(&"logs/native.log.2026-07-13".to_string()));

        // 读回 zip 坐实内容 + 无明文泄漏。
        let f = fs::File::open(&out).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        let mut cfg_txt = String::new();
        zip.by_name("config.toml")
            .unwrap()
            .read_to_string(&mut cfg_txt)
            .unwrap();
        assert!(cfg_txt.contains("<REDACTED>"), "zip 内 config 已脱敏");
        assert!(!cfg_txt.contains("secret"), "zip 内无 auth_password 原文");

        let mut log_txt = String::new();
        zip.by_name("logs/native.log.2026-07-13")
            .unwrap()
            .read_to_string(&mut log_txt)
            .unwrap();
        assert!(!log_txt.contains("ym853euf2gpg22"), "zip 内日志无明文 wxid");
        assert!(log_txt.contains("wxid_<REDACTED>"));
    }

    #[test]
    fn collect_log_files_days_limit_keeps_recent() {
        let dir = tempfile::tempdir().unwrap();
        for day in ["2026-07-10", "2026-07-11", "2026-07-12", "2026-07-13"] {
            fs::write(dir.path().join(format!("native.log.{day}")), "x").unwrap();
        }
        // 干扰文件不该被收。
        fs::write(dir.path().join("other.txt"), "x").unwrap();
        let all = collect_log_files(dir.path(), None);
        assert_eq!(all.len(), 4, "只收 native.log*");
        let recent2 = collect_log_files(dir.path(), Some(2));
        assert_eq!(recent2.len(), 2);
        assert!(recent2[1].to_string_lossy().contains("2026-07-13"), "留最近的");
        assert!(recent2[0].to_string_lossy().contains("2026-07-12"));
    }
}
