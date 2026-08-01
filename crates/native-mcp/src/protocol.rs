//! JSON-RPC 分派 (MCP 线协议; ④文档 §1) —— **传输无关**: 只吃/吐 `serde_json::Value`,
//! stdio 收发在 msgvestige 皮的 `mcp` 子命令。同一 `handle_line` 将来可挂 HTTP/SSE 传输 (核心不改)。
//!
//! 只读服务器要处理的方法很少: `initialize`(握手) · `notifications/initialized`(无回) · `ping` ·
//! `tools/list`(列工具+schema) · `tools/call`(调工具)。批量/resources/prompts v1 不做 (④文档 §4 砍)。

use serde_json::{json, Value};

use crate::error::{jsonrpc_error, jsonrpc_result, tool_err, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR};
use crate::{tools, Ctx};

/// 目标 MCP 协议版本 (spec 日期戳; 握手回给客户端)。
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// 解析一行 JSON → 分派 → 返回响应 `Value` (通知返 `None`, 不回)。**传输无关入口**。
pub async fn handle_line(line: &str, ctx: &Ctx) -> Option<Value> {
    match serde_json::from_str::<Value>(line) {
        Ok(payload) => handle_request(&payload, ctx).await,
        Err(_) => Some(jsonrpc_error(Value::Null, PARSE_ERROR, "Parse error")),
    }
}

/// 握手响应: 协议版本 + 能力 (只 tools) + serverInfo + **instructions** (服务器级给 LLM 的总提示)。
fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "msgvestige-mcp", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "查询本地微信数据 (只读)。模糊的人名/群名先用 wx_contacts 搜到 wxid 再传给消息类工具。\
            list 类工具 limit 保持小、按需靠 has_more 翻页, 别整库扫。不确定'今天/上周'先调 wx_current_time。\
            多账号库里未指定 account 且有歧义时工具会列候选让你选。"
    })
}

async fn handle_request(req: &Value, ctx: &Ctx) -> Option<Value> {
    let Some(obj) = req.as_object() else {
        return Some(jsonrpc_error(Value::Null, INVALID_REQUEST, "Invalid Request"));
    };
    let id = obj.get("id").cloned();
    let is_notification = !obj.contains_key("id");
    let method = obj.get("method").and_then(Value::as_str).unwrap_or("");

    // 通知 (无 id): 只吞 initialized, 其余通知静默忽略, 一律不回。
    if is_notification {
        return None;
    }
    let id = id.unwrap_or(Value::Null);

    match method {
        "initialize" => Some(jsonrpc_result(id, initialize_result())),
        "ping" => Some(jsonrpc_result(id, json!({}))),
        "tools/list" => Some(jsonrpc_result(id, json!({ "tools": tools::tool_defs() }))),
        "tools/call" => {
            let params = obj.get("params").and_then(Value::as_object);
            let name = params.and_then(|p| p.get("name")).and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                // 缺工具名 = 参数错; 但走 tool-result isError 让 LLM 看得到并自纠 (§7)。
                return Some(jsonrpc_result(
                    id,
                    tool_err("缺少工具名", "tools/call 的 params 要带 name"),
                ));
            }
            let empty = Value::Object(serde_json::Map::new());
            let args = params.and_then(|p| p.get("arguments")).unwrap_or(&empty);
            let result = tools::call_tool(name, args, ctx).await;
            Some(jsonrpc_result(id, result))
        }
        _ => Some(jsonrpc_error(id, METHOD_NOT_FOUND, "Method not found")),
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_line, METHOD_NOT_FOUND, PARSE_ERROR, PROTOCOL_VERSION};
    use crate::Ctx;

    /// initialize 回协议版本 + instructions (给 LLM 的服务器级总提示)。
    #[tokio::test]
    async fn initialize_returns_version_and_instructions() {
        let resp = handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#, &Ctx::default())
            .await
            .unwrap();
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["instructions"].is_string(), "带 instructions 总提示");
        assert_eq!(resp["id"], 1);
    }

    /// 通知 (无 id) 不回。
    #[tokio::test]
    async fn notification_gets_no_response() {
        let out = handle_line(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &Ctx::default(),
        )
        .await;
        assert!(out.is_none(), "通知不回响应");
    }

    /// 坏 JSON → PARSE_ERROR。
    #[tokio::test]
    async fn garbage_is_parse_error() {
        let resp = handle_line("not json at all", &Ctx::default()).await.unwrap();
        assert_eq!(resp["error"]["code"], PARSE_ERROR);
    }

    /// 未知方法 → METHOD_NOT_FOUND (请求有 id)。
    #[tokio::test]
    async fn unknown_method_errors() {
        let resp = handle_line(r#"{"jsonrpc":"2.0","id":9,"method":"no_such_method"}"#, &Ctx::default())
            .await
            .unwrap();
        assert_eq!(resp["error"]["code"], METHOD_NOT_FOUND);
    }

    /// tools/list 返回工具清单 (每个带 name + inputSchema)。
    #[tokio::test]
    async fn tools_list_returns_defs() {
        let resp = handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, &Ctx::default())
            .await
            .unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert!(tools.len() >= 4, "至少首批 4 个工具");
        assert!(tools
            .iter()
            .all(|t| t["name"].is_string() && t["inputSchema"].is_object()));
    }

    /// 冷查工具在未配置 L1 时返 isError (不 panic; §7 LLM 友好)。
    #[tokio::test]
    async fn cold_tool_without_l1_returns_is_error() {
        let resp = handle_line(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wx_account","arguments":{}}}"#,
            &Ctx::default(),
        )
        .await
        .unwrap();
        assert_eq!(resp["result"]["isError"], true, "无 L1 → 工具级 isError, 非协议崩");
    }
}
