//! 把**这个 exe 是从哪一笔提交建出来的**编进二进制。
//!
//! 为什么要这个: 打包出去的版本号一直是工作区里写死的 `0.1.0-alpha`, 包名分了 alpha.1/2/3,
//! 而 exe 自己报的永远是同一句话 —— 拿到包的人跑 `--version` **分不出手里是哪一版**,
//! 出了问题也没法确定跑的是哪一笔代码。内部试用阶段这个必须有。
//!
//! 拿不到 git(比如从 tar 包里构建、或者没装 git)就退成 `unknown`, 不让构建失败。

use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());

    // 工作区有没有没提交的**代码**改动 —— 内部试用时最容易搞混的就是"我本地改过的那版"。
    //
    // ⚠️ 只看 `crates/` —— 头一版看的是整个工作区, 结果被**别人未提交的文档改动**判成了 dirty
    // (这个仓库有并发的其他 fork 在编辑文档)。文档改了不会改变这个二进制, 标出来是假信号,
    // 而假信号多了这个标记就没人看了。打包时当场发现的。
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no", "--", "../../crates"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| !o.stdout.is_empty());

    println!(
        "cargo:rustc-env=BUILD_GIT_SHA={sha}{}",
        if dirty { "+改动未提交" } else { "" }
    );

    // 只在 HEAD 变了的时候重跑 —— 不然每次 `cargo build` 都要重编 msgvestige。
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}
