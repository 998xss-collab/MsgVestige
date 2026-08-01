//! MCP 皮 (接口设计-④mcp接口.md) —— **手写 JSON-RPC over stdio, 传输无关**。第三张皮, 消费者是 LLM。
//!
//! - [`protocol::handle_line`] 只吃/吐 `serde_json::Value` (stdio 收发在 msgvestige 皮 `mcp` 子命令) →
//!   同一核心将来可挂 HTTP/SSE 传输, 核心不改 (WDA 实证: 手写协议核心与传输解耦)。
//! - 各 `wx_` 工具 (见 [`tools`]) **直调 native-query 共享内核** (三皮同核, 不重写查询), 输出经 [`fold`]
//!   按 token 预算折叠。
//! - **只读 allowlist**: 无写/导出/wipe/auth。`wx_exec` (R7/⑪) 是**只读** SQL 逃生口 —— 镜像 HTTP `/exec`,
//!   调同一份 [`native_query::exec_hardened`] (硬只读三层 + DoS 界); ④文档 §3 原"exec 默认不放"已由用户批准放开
//!   (仍硬只读, 非放开写)。

pub mod error;
pub mod fold;
pub mod protocol;
pub mod tools;

pub use protocol::{handle_line, PROTOCOL_VERSION};

/// MCP 服务器上下文 —— 启动时从 `msgvestige mcp` 参数构造, 各工具据此取数据源。
///
/// 冷查 (联系人/账号/朋友圈…读 L1) 用 `l1_db`; 热查 (会话/消息直读加密源库) 用 `wechat_data_dir` +
/// 账号 (工具 `account` 参 > `default_account`)。字段 pub —— HTTP 皮将来同样直接构造。
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    /// 冷查 L1 库路径 (ingest 产出); `None` = 未配置冷查, 冷查工具返 isError 提示。
    pub l1_db: Option<String>,
    /// 热查 (sessions/messages) 的微信数据目录 (xwechat_files); `None` = 未配置热查。
    pub wechat_data_dir: Option<String>,
    /// 默认账号 wxid (工具未显式给 `account` 时用); 热查必需 (定位账号库 + 取缓存 key)。
    pub default_account: Option<String>,
}
