//! R13 · 日志防退化关卡(logging-日志.md §6 · 竞品全栽在"埋点随开发退化/脱敏被绕过")。
//!
//! **靠机器不靠人**:扫全工作区源码,禁止日志宏(`error!`/`warn!`/`info!`/`debug!`/`trace!`)整条语句里出现
//! K-R4 风险的**路径→字符串**写法或**明文 wxid**:
//! - 路径 `.display()` / `.to_string_lossy()` → 该 `file_name()`(全路径含 `xwechat_files/wxid_xxx` 会漏 wxid);
//! - 裸明文 `wxid_<10+位>` 字面量 → 该 `sha8()`。
//!
//! **跨行宏感知**(R13 补审 P1):日志宏常多行写(`warn!(` 一行、`%path.display()` 在续行),故从 `名!(` 累积到
//! 配平 `)` 整条语句一起查 —— 逐行扫会漏掉续行里的 `.display()`。
//!
//! **覆盖边界(别高估)**:这是**语法 tripwire 非污点分析**。它挡 `.display()`/`.to_string_lossy()`/字面 `wxid_`;
//! **挡不住** `%var`/`{var}` 里 var 恰是路径/conv_id/群名/正文/手机号、legacy 非 `wxid_` 账号(momo…/gh_/@chatroom)。
//! 那些靠**类型层**(`Wxid` Display=sha8 / `MasterKey` 无 Display / V3* 自定义 Debug)+ 埋点时手动 `sha8` 兜,
//! 见 `key_provider/provider.rs` 的 `*_debug_redacted` 单测。本守卫只封"路径裸打 + 字面 wxid"这两条最常见退化路。
//!
//! 已知安全的按**行内** `// log-safe: <原因>` 显式豁免(要写原因)。常驻 `#[test]` 进 `cargo test --workspace`。

use std::fs;
use std::path::{Path, PathBuf};

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            // 跳过 target / 隐藏目录 / workspace **exclude** 的 PoC 参考代码(wechat-poc-0/crates-placeholder,
            // 非产品成员, 见根 Cargo.toml exclude)。扫的是真 workspace 成员(crates/* + xtask)。
            let skip = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                matches!(n, "target" | "node_modules" | "wechat-poc-0" | "crates-placeholder") || n.starts_with('.')
            });
            if !skip {
                walk_rs(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// 行里日志宏调用起点(`名!(`,容忍 `tracing::` 前缀 + 宏名与 `(` 间空白)。返回宏名起始字节位。
fn log_macro_open(line: &str) -> Option<usize> {
    const MACROS: [&str; 5] = ["error!", "warn!", "info!", "debug!", "trace!"];
    let mut best: Option<usize> = None;
    for m in MACROS {
        let mut from = 0;
        while let Some(rel) = line[from..].find(m) {
            let pos = from + rel;
            if line[pos + m.len()..].trim_start().starts_with('(') {
                best = Some(best.map_or(pos, |b| b.min(pos)));
                break;
            }
            from = pos + m.len();
        }
    }
    best
}

/// 文本里是否有**明文 wxid**(`wxid_` 后 ≥10 位小写字母数字)。字段名 `wxid =`、`sha8(..)` 输出都不含此形态。
fn has_plaintext_wxid(text: &str) -> bool {
    let mut rest = text;
    while let Some(pos) = rest.find("wxid_") {
        let after = &rest[pos + 5..];
        let run = after
            .bytes()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            .count();
        if run >= 10 {
            return true;
        }
        rest = &after[run.max(1)..];
    }
    false
}

/// 一条(可能跨行的)日志宏语句里的 K-R4 风险模式。空 = 无。
fn risky_pattern(stmt: &str) -> Option<&'static str> {
    if stmt.contains(".display()") {
        Some("路径 .display() → 用 file_name()")
    } else if stmt.contains(".to_string_lossy()") {
        Some("路径 .to_string_lossy() → 用 file_name()")
    } else if has_plaintext_wxid(stmt) {
        Some("裸明文 wxid_ → 用 sha8()")
    } else {
        None
    }
}

/// 扫一个文件, 返回违规 (起始行1-based, 说明, 语句预览)。跨行宏感知 + 行内 `// log-safe` 整条豁免。
fn scan_file(src: &str) -> Vec<(usize, &'static str, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        if t.starts_with("//") {
            i += 1;
            continue;
        }
        let Some(open) = log_macro_open(lines[i]) else {
            i += 1;
            continue;
        };
        // 从宏起累积到配平 `)`(跨行)。
        let mut stmt = String::new();
        let mut depth: i32 = 0;
        let mut started = false;
        let mut j = i;
        'block: while j < lines.len() {
            let seg = if j == i { &lines[j][open..] } else { lines[j] };
            for ch in seg.chars() {
                stmt.push(ch);
                match ch {
                    '(' => {
                        depth += 1;
                        started = true;
                    }
                    ')' => {
                        depth -= 1;
                        if started && depth == 0 {
                            break 'block;
                        }
                    }
                    _ => {}
                }
            }
            stmt.push('\n');
            j += 1;
            if j - i > 40 {
                break; // 防跑飞(未配平)
            }
        }
        // 整条语句任一行标 log-safe → 豁免。
        let safe = (i..=j.min(lines.len().saturating_sub(1))).any(|k| lines[k].contains("// log-safe"));
        if !safe {
            if let Some(why) = risky_pattern(&stmt) {
                out.push((i + 1, why, lines[i].trim().to_string()));
            }
        }
        i = j + 1;
    }
    out
}

#[test]
fn log_macros_have_no_kr4_risk_patterns() {
    // CARGO_MANIFEST_DIR = <ws>/crates/common → parent.parent = <ws> 根(扫所有成员含 xtask, 补审 P3)。
    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace 根");
    let mut files = Vec::new();
    walk_rs(ws_root, &mut files);
    assert!(
        files.len() > 30,
        "扫到的 .rs 太少 ({}), 路径不对? {}",
        files.len(),
        ws_root.display()
    );

    let mut violations = Vec::new();
    for f in &files {
        if f.file_name().is_some_and(|n| n == "log_redaction_guard.rs") {
            continue; // 跳过本守卫自身(含 pattern 字面量)。
        }
        let Ok(src) = fs::read_to_string(f) else { continue };
        for (ln, why, preview) in scan_file(&src) {
            violations.push(format!("{}:{}  [{why}]  {preview}", f.display(), ln));
        }
    }

    assert!(
        violations.is_empty(),
        "\n日志宏出现 K-R4 风险写法({} 处)——路径用 `file_name()`、敏感值用 `sha8()`;\n\
         确认安全(如微信安装路径无 wxid)则在该(跨行宏的任一)行加 `// log-safe: <原因>`:\n\n{}\n",
        violations.len(),
        violations.join("\n")
    );
}

#[cfg(test)]
mod self_tests {
    use super::{has_plaintext_wxid, log_macro_open, scan_file};

    #[test]
    fn detects_log_macro_open() {
        assert!(log_macro_open(r#"tracing::warn!(x = 1, "boom");"#).is_some());
        assert!(log_macro_open(r#"    info! ("hi");"#).is_some());
        assert!(log_macro_open("let warning = 1;").is_none()); // warn! 才算
        assert!(log_macro_open("let e = my_error;").is_none()); // 无 ! 无 (
    }

    #[test]
    fn cross_line_display_is_caught() {
        // 关键(补审 P1): 多行宏, .display() 在续行 —— 逐行扫会漏, 跨行须逮到。
        let src = "fn f(p: &std::path::Path) {\n    tracing::warn!(\n        path = %p.display(),\n        \"boom\"\n    );\n}\n";
        let v = scan_file(src);
        assert_eq!(v.len(), 1, "多行 .display() 须逮到");
        assert!(v[0].1.contains("display"));
    }

    #[test]
    fn log_safe_marker_exempts_multiline() {
        let src = "    warn!(\n        path = %p.display(), // log-safe: 安装路径\n    );\n";
        assert!(scan_file(src).is_empty(), "块内任一行 log-safe → 豁免");
    }

    #[test]
    fn to_string_lossy_caught_wxid_forms() {
        assert_eq!(scan_file("info!(\"{}\", p.to_string_lossy());").len(), 1);
        assert!(has_plaintext_wxid(r#"warn!("bad wxid_abcd1234efgh567");"#));
        assert!(!has_plaintext_wxid(r"warn!(wxid = %sha8(w));")); // 字段名不算
        assert!(!has_plaintext_wxid("wxid_short")); // <10 不算
    }
}
