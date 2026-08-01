//! common — 共享 utilities (log / redact / safety)
//!
//! 跟 ADR-416 §3.2.4 一致 — 跨 crate 共享非业务 utilities.
//!
//! PR2-14 (logging-日志.md 任务 1+3): `log` (统一 tracing init) + `redact` (脱敏 sha8) 落地; `safety` 待 PR2-N.

pub mod log;
pub mod redact;
// PR2-N: pub mod safety;    // 进程安全 + 红线检查
