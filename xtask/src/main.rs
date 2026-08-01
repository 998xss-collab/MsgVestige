//! xtask — cargo xtask 工具 (codegen + docs check)
//!
//! 跟 ADR-417 §3 一致:
//! - cargo xtask docs   — codegen _generated.md
//! - cargo xtask check  — ADR YAML 校验 (frontmatter ↔ 正文契约)
//!
//! 当前 PR1 = 空壳, codegen 逻辑等 PR2-N 实现.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "build / docs / codegen 工具 (跟 ADR-417 §3 一致)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// codegen _generated.md (推 PR2-N)
    Docs,
    /// ADR YAML 校验 (推 PR2-N)
    Check,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Docs) => println!("xtask docs — codegen 推 PR2-N (详 ADR-417 §3)"),
        Some(Commands::Check) => println!("xtask check — ADR YAML 校验推 PR2-N"),
        None => println!("PR1 workspace 骨架. 子命令: docs / check (推 PR2-N)"),
    }
    Ok(())
}
