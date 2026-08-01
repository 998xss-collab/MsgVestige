//! 编 vendored Skype SILK SDK C 源码 → 静态库 `silk`, 手写 FFI 链接 (src/lib.rs)。
//!
//! **刻意不用 bindgen** (对比 crates.io 的 silk-v3-sys): bindgen 需编译期 libclang/LLVM,
//! 换机器最易缺; 手写 FFI (就 3 个 decode 函数 + 1 个 struct) 免这个依赖。可移植性严格更优。
//! 编译期只需 C 编译器 (Windows=MSVC, 项目编 rusqlite bundled SQLite 已在用; Linux/Mac=cc 自动选 gcc/clang)。

use std::path::Path;

fn main() {
    let mut files = Vec::new();
    collect_c(&mut files, "silk/interface");
    collect_c(&mut files, "silk/src");
    cc::Build::new()
        .includes(["silk/src", "silk/interface"])
        .files(&files)
        .warnings(false) // Skype SDK 是 2006-2012 老 C, 大量老式 warning, 静音 (非本仓代码)
        .compile("silk");
    println!("cargo:rerun-if-changed=silk");
}

/// 递归收集 dir 下所有 .c 文件路径。
fn collect_c(v: &mut Vec<String>, dir: &str) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("读 {dir} 失败: {e}")) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_c(v, path.to_str().expect("utf8 path"));
        } else if path.extension().is_some_and(|x| x == "c") {
            v.push(path.to_str().expect("utf8 path").to_string());
        }
    }
    let _ = Path::new(dir);
}
