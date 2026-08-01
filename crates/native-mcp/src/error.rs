//! JSON-RPC 协议级错误 + 工具级结果 (isError) 构造。
//!
//! **两层错误分清** (④文档 §7): 协议级错 (parse/method-not-found) 走 JSON-RPC `error` 字段 (宿主可能不喂模型);
//! 工具级错 (查询失败/参数错) 走 **tool-result 的 `isError:true`** —— 一定回灌给 LLM, 它才能自纠。

use serde_json::{json, Value};

// JSON-RPC 2.0 标准错误码。
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;

/// JSON-RPC `result` 响应。
#[must_use]
// ⚠️ rustc 1.96 的 ICE 绕行(不是嫌 lint 烦): clippy 给本函数出 pedantic 警告时 rustc 自己崩
// (rustc_span:2439 断言, 崩在渲染阶段 → 一条警告都打不出来)。1.83 不崩、1.96 与 nightly 都崩
// ⇒ 编译器 bug, 升降版本都躲不掉。逐层二分定位到本函数。
// 完整排查记录见 native-core::mediastore::engine::open_work_item 上的注释。
#[allow(clippy::pedantic)]
pub fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// JSON-RPC `error` 响应 (协议级; 工具错不走这, 走 [`tool_err`])。
#[must_use]
pub fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// 工具**成功**结果: `content[text=json]` + `isError:false`。**每条成功响应的统一预算出口** —— 过
/// [`crate::fold::enforce_budget`] 盖 `meta._budget` (本次预算/硬顶/是否截断/实际字节/建议档) 且**无条件保证**
/// 最终紧凑 JSON ≤ `budget` (折叠层已控数据路径; 这里是最后一道兜底闸, 令"所有返回路径受硬上限控制"构造成立)。
/// 只给 text (不给 structuredContent) —— 省 token (§2.2; 避免同数据两份撑爆上下文)。
/// **compact (非 pretty)**: 省字节/token, 且预算按 compact 量测 —— 这里必须同发 compact, 否则 pretty 缩进 ~1.4x
/// 会让近上限载荷实付溢出封顶 (审查 P2-8)。
#[must_use]
pub fn tool_ok(structured: &Value, budget: usize) -> Value {
    let final_struct = crate::fold::enforce_budget(structured.clone(), budget);
    let text = serde_json::to_string(&final_struct).unwrap_or_else(|_| "{}".to_string());
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}

/// 工具**错误**结果 (§7 LLM 友好): 自然语言 `{what, how_to_fix}`, `isError:true` 保证回灌给 LLM 自纠。
/// `candidates` 非空时附候选 (多账号未指定 / 名字撞多人时列出让 LLM 选, 不瞎猜)。
#[must_use]
pub fn tool_err(what: &str, how_to_fix: &str) -> Value {
    tool_err_with(what, how_to_fix, None)
}

/// 带候选的工具错误 (§7 歧义列候选)。
#[must_use]
pub fn tool_err_with(what: &str, how_to_fix: &str, candidates: Option<Value>) -> Value {
    let mut obj = json!({ "what": what, "how_to_fix": how_to_fix });
    if let Some(c) = candidates {
        obj["candidates"] = c;
    }
    let text = serde_json::to_string_pretty(&obj).unwrap_or_default();
    json!({ "content": [{ "type": "text", "text": text }], "isError": true })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::tool_ok;

    /// 审查 P2-8: tool_ok 交付 **compact** (无缩进/换行) —— 与 [`crate::fold::envelope`] 的 48KB 封顶
    /// (按 compact 量测) 一致, 免近上限载荷因 pretty 缩进 ~1.4x 实付溢出封顶。
    #[test]
    fn tool_ok_emits_compact_json() {
        let out = tool_ok(
            &json!({ "data": [1, 2, 3], "meta": { "source": "cold" } }),
            crate::fold::DEFAULT_MAX_BYTES,
        );
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains('\n'), "compact 无换行 (pretty 会带 \\n)");
        assert!(!text.contains("  "), "compact 无缩进 (pretty 会带两空格缩进)");
        assert_eq!(out["isError"], false);
    }
}
