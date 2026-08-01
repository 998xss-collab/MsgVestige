//! OpenAPI 3.0.3 规格 (③规格 §11) —— `GET /api/v1/openapi.json` 吐机器可读接口契约。
//!
//! **手写** (非 utoipa 派生): 响应 `data` 是 native-query 动态拼的 JSON 非 native-http 固定类型, 派生库看不见
//! 这些字段 → 手写换全控 (同手写 MCP 的理由)。**冻结契约** (§11): 信封 + 错误 schema + 全错误码 + 封闭枚举 +
//! nullable 约定, 第三方据它生成客户端。
//!
//! **不走偏**: 错误码从 [`native_core::ErrorCode`] 拉 (drift-free); 端点/字段级对齐由 `openapi_drift` 测试守
//! (路由↔规格双向 + 错误码枚举 == ErrorCode + 真库逐字段核) —— 后期加字段没同步规格 → 测试红并指名 (件 D5)。
//!
//! 用 **3.0.3** 非 3.1: 客户端生成器 (openapi-generator 等) 对 3.0 支持最广 (§11 目标=第三方生成客户端); nullable
//! 走 `nullable: true` (3.0 风格)。

use serde_json::{json, Value};

/// 规格自带版本 (对齐 workspace crate 版本; §11 "自带版本")。
const API_VERSION: &str = "0.1.0-alpha";

/// HTTP 皮层直接 mint、**不在** [`native_core::ErrorCode`] 闭集里的 code (serve 专有: Host 闸/媒体联网/SSE/POST body)。
/// 与内核 14 码合起来 = 契约暴露的全部错误码。**改动这里 = 契约变更**, 由 `openapi_drift` 测试扫源码 mint 点核对。
const HTTP_ONLY_CODES: &[&str] = &[
    "METHOD_NOT_ALLOWED",     // 405: 已知路径错方法
    "FORBIDDEN",              // 403: Host 非 loopback / CORS 拒
    "UNSUPPORTED_MEDIA_TYPE", // 415: POST body 非 application/json
    "PAYLOAD_TOO_LARGE",      // 413: POST body 超上限
    "CDN_FETCH_FAILED",       // 502: 朋友圈媒体 CDN 下载失败
    "SNS_DECRYPT_FAILED",     // 502: 朋友圈媒体解密失败
    "SNS_WASM_MISSING",       // 503: 朋友圈加密媒体缺 node keystream 脚本
    "EVENTS_DISABLED",        // 503: /events 未开 --watch
    "EVENTS_BUSY",            // 503: /events 并发闸满
    "REQUEST_TIMEOUT",        // 408: 非流式端点超 serve --request-timeout-secs (opt-in, 默认不限)
];

/// 契约暴露的**全部错误码** (内核 14 闭集 + HTTP 皮 mint)。内核部分从 [`native_core::ErrorCode`] 拉 → 增删码这里
/// 自动跟 (drift-free)。用于 `Error.code` 枚举 + 各响应错误码。
fn all_error_codes() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = native_core::ErrorCode::ALL.iter().map(|c| c.code()).collect();
    v.extend_from_slice(HTTP_ONLY_CODES);
    v
}

/// 完整 OpenAPI 3.0.3 文档 (serve `/api/v1/openapi.json` 序列化它; 测试也调它做结构/漂移核对)。
#[must_use]
pub fn openapi_doc() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "微信数据基座 · 只读 HTTP API",
            "version": API_VERSION,
            "description":
                "本机只读 REST API —— 解密并查询本机微信数据 (联系人/消息/会话/朋友圈/交易/媒体…)。\n\
                 三皮之一 (CLI / MCP / HTTP 同一查询内核)。**只读**: 无写操作。默认仅监听 loopback \
                 (127.0.0.1), 非公网方案 (无 TLS/限流/审计, 见 §13)。\n\
                 所有成功响应为统一信封 `{data, meta}` (见 Envelope schema); 错误为 `{error, request_id}` \
                 (见 Error schema, code 为稳定枚举)。每个响应带 `X-Request-Id` 头。",
            "license": { "name": "proprietary" }
        },
        "servers": [
            { "url": "http://127.0.0.1:8420", "description": "默认 loopback (serve --host/--port 可改)" }
        ],
        "tags": tags(),
        "paths": paths(),
        "components": {
            "schemas": schemas()
        }
    })
}

/// 端点分组标签 (Swagger UI 分节)。
fn tags() -> Value {
    json!([
        { "name": "meta", "description": "服务自身 (健康/规格/账号)" },
        { "name": "contacts", "description": "联系人 / 群 / 成员" },
        { "name": "messages", "description": "消息 / 会话 / 投影 (call/link/file/image/system/biz)" },
        { "name": "moments", "description": "朋友圈 (动态/互动/收件箱)" },
        { "name": "media", "description": "媒体即时取用 (语音/视频/图片/表情/朋友圈, Range/联网)" },
        { "name": "finance", "description": "交易 (转账/红包/群收款)" },
        { "name": "misc", "description": "收藏 / 视频号 / 好友申请 / 统计 / 搜索 / 原始 payload" },
        { "name": "realtime", "description": "实时事件流 (SSE)" },
        { "name": "advanced", "description": "只读 SQL 逃生口" }
    ])
}

// ── components/schemas ──────────────────────────────────────────────────

/// 复用 schema 集: 信封/meta/错误/枚举 + (件 D4) 各端点数据行。
fn schemas() -> Value {
    let mut s = json!({
        // 后端来源 (§14 双模式)。
        "Source": {
            "type": "string", "enum": ["hot", "cold", "live-index"],
            "description": "本次查询走哪个后端: hot=直读加密源库 / cold=读 L1 / live-index=实时索引"
        },
        // 信封 meta (内核 §2; 可选字段缺省不出现)。
        "Meta": {
            "type": "object",
            "required": ["has_more"],
            "properties": {
                "has_more": { "type": "boolean", "description": "还有下一页 (恒给; 非分页=false)" },
                "total_count": { "type": "integer", "format": "int64", "description": "过滤后真实全量 (仅小集/offset 分页给; 热查/大集省略)" },
                "limit": { "type": "integer", "format": "int64", "description": "本页请求条数 (分页时给)" },
                "offset": { "type": "integer", "format": "int64", "description": "已跳过条数 (offset 分页给)" },
                "next_cursor": { "type": "string", "description": "游标分页下页串 (到底省略)" },
                "account": { "type": "string", "description": "当前账号 sha8 (多账号维度给)" },
                "source": { "$ref": "#/components/schemas/Source" },
                "freshness": {
                    "type": "object", "description": "新鲜度 (cold={ingested_at[,stale]} / hot={live:true})。ingested_at=该账号最后 ingest unix 秒 (etl_state MAX(last_update)/1000; 粗粒度非逐源)。stale (R9 复审R3#4+codex P1): **只报坏消息不报好消息** —— 仅 serve --live-index full 且后台 watch 线程**已退出/崩溃**时 stale:true (没维护者了 L1 冻结源库仍长, 安全告警); 线程存活时 stale **省略** (存活≠同步健康: watch 吞 ingest 错误永久重试, 持续失败时线程活但 L1 不推进, 报 false 会谎报新鲜); 非 full 恒省略。数据时刻鲜度 (最新消息 create_time) 见 /live-index/status 的 indexed_through (per-query 冷查负担不起全表扫故不出; 原 §14.5 各源 MIN floor 因 infra 无廉价诚实实现已撤)。",
                    "additionalProperties": true
                },
                "summary": {
                    "type": "object", "description": "命令特有汇总 (如 stats 的 total_messages) 的唯一容身处",
                    "additionalProperties": true
                },
                "dropped_rows": { "type": "integer", "format": "int64", "description": "本页因读取失败被丢弃的行数 (R9 复审R3#5 + R4 扩全; >0 才出)。机器可读的'结果不完整'信号, 与 has_more(分页) 正交: has_more=还有下一页, dropped_rows=本页内缺了几行。R4 扩全后覆盖所有查询形 (offset 分页内部算术 + page/cursor/cold_page 经 collect_ok 显式计数, 如 accounts/names/new/stats/forward)。消费者据此知这批数据有洞、非仅未翻页。" }
            },
            "description": "信封 meta —— 字段集固定 (内核 §2), 三皮共享。可选字段 None 时不序列化。"
        },
        // 顶层成功信封。data 元素形随端点 (D4 各端点 override data.items)。
        "Envelope": {
            "type": "object",
            "required": ["data", "meta"],
            "properties": {
                "data": {
                    "type": "array",
                    "items": { "type": "object", "additionalProperties": true },
                    "description": "结果行数组 (元素字段随端点; 各端点响应会具体化 items)"
                },
                "meta": { "$ref": "#/components/schemas/Meta" }
            },
            "description": "统一成功信封 (内核 §2): 顶层恒 {data, meta}, 消费者只依赖外层。"
        },
        // 错误码枚举 (内核 14 + HTTP mint)。
        "ErrorCode": {
            "type": "string",
            "enum": all_error_codes(),
            "description": "稳定错误码 (第三方可 switch; 内核 §13 闭集 + HTTP 皮专有)。"
        },
        // §5 错误体。
        "Error": {
            "type": "object",
            "required": ["error", "request_id"],
            "properties": {
                "error": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": { "$ref": "#/components/schemas/ErrorCode" },
                        "message": { "type": "string", "description": "人话错因 (为什么)" },
                        "hint": { "type": "string", "description": "怎么修 (可选)" },
                        "candidates": {
                            "description": "歧义候选 (如多账号 ACCOUNT_AMBIGUOUS 的账号列表; 可选)",
                            "nullable": true
                        }
                    }
                },
                "request_id": { "type": "string", "description": "本请求 id (= X-Request-Id 头; 同机日志关联)" }
            },
            "description": "§5 错误体。所有 4xx/5xx 响应为此形。"
        }
    });
    // 件 D4: 各端点数据行 schema 合并进来 (person/message/session/moment/...)。
    if let (Some(obj), Some(rows)) = (s.as_object_mut(), row_schemas().as_object()) {
        for (k, v) in rows {
            obj.insert(k.clone(), v.clone());
        }
    }
    s
}

/// 各端点数据行 schema (**件 D4**: 逐字段真实类型)。字段从 native-core `storage.rs` 的 V3* 表结构 + native-query
/// 各查询的 SELECT 列抽出 (workflow 并行抽 23 形状 + 真库对拍), 落 `openapi_schemas.json` 编译期嵌入 + 解析。
/// 全字段 `additionalProperties:true` (前向兼容: 新加字段不破客户端) + `nullable` 逐字段标; `openapi_drift`
/// 字段级测试对真库响应核 (真实字段 ⊄ 规格 → 红并指名, "后期加字段方便"靠此)。加字段 = 编辑此 JSON (或重跑抽取)。
fn row_schemas() -> Value {
    serde_json::from_str(include_str!("openapi_schemas.json")).expect("openapi_schemas.json 须合法 JSON (件 D4 生成)")
}

// ── paths ───────────────────────────────────────────────────────────────

/// 标准错误响应引用 (按状态码挂 Error schema)。
fn err_resp(desc: &str) -> Value {
    json!({
        "description": desc,
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } }
    })
}

/// 标准成功信封响应 (200)。`data_schema` = 该端点 data 元素 schema 名 (None → 通用开放 object)。
fn ok_envelope(desc: &str, data_schema: Option<&str>) -> Value {
    let items = match data_schema {
        Some(name) => json!({ "$ref": format!("#/components/schemas/{name}") }),
        None => json!({ "type": "object", "additionalProperties": true }),
    };
    json!({
        "description": desc,
        "headers": {
            "X-Request-Id": { "schema": { "type": "string" }, "description": "本请求 id (每响应带)" }
        },
        "content": { "application/json": { "schema": {
            "allOf": [
                { "$ref": "#/components/schemas/Envelope" },
                { "type": "object", "properties": { "data": { "type": "array", "items": items } } }
            ]
        } } }
    })
}

/// **裸对象**成功响应 (200; pack 组合端点直接返 schema 对象, **不套** `{data,meta}` 信封 —— 与 handler 真实
/// 返回一致, 见 §D7 审查)。
fn bare_ok(desc: &str, schema: &str) -> Value {
    json!({
        "description": desc,
        "headers": { "X-Request-Id": { "schema": { "type": "string" }, "description": "本请求 id" } },
        "content": { "application/json": { "schema": { "$ref": format!("#/components/schemas/{schema}") } } }
    })
}

/// query 参数对象 (name/desc/schema)。
#[allow(clippy::needless_pass_by_value)] // schema 取所有权是 builder 惯例 (调用方传 json!(...) owned)
fn q_param(name: &str, desc: &str, schema: Value) -> Value {
    json!({ "name": name, "in": "query", "required": false, "description": desc, "schema": schema })
}

/// path 参数对象 (恒 required)。
fn path_param(name: &str, desc: &str) -> Value {
    json!({ "name": name, "in": "path", "required": true, "description": desc, "schema": { "type": "string" } })
}

/// 常用可选 `?account=` 参数 (多账号库指定账号)。
fn account_param() -> Value {
    q_param(
        "account",
        "账号 wxid (多账号库须指定; 单账号可省; 不指定又多账号 → 409 ACCOUNT_AMBIGUOUS)",
        json!({ "type": "string" }),
    )
}

/// `?limit=` 参数。
fn limit_param() -> Value {
    q_param(
        "limit",
        "本页条数 (端点各有默认/上限)",
        json!({ "type": "integer", "format": "int64", "minimum": 1 }),
    )
}

/// `?offset=` 参数 (offset 分页; 上限 1e7)。
fn offset_param() -> Value {
    q_param(
        "offset",
        "跳过条数 (offset 分页; offset+=limit 翻页至 has_more=false)",
        json!({ "type": "integer", "format": "int64", "minimum": 0 }),
    )
}

/// 标准列表端点错误响应集: 400 (参数无效) + 409 (多账号未指定)。
fn list_errors() -> Value {
    json!({
        "400": err_resp("参数无效 (BAD_REQUEST; 未知参数/值非法/互斥冲突)"),
        "409": err_resp("多账号未指定 (ACCOUNT_AMBIGUOUS, candidates 给候选) / 需先 ingest (NEEDS_INGEST)")
    })
}

/// 详情端点错误响应集: 400 + 404 (id 查无) + 409。
fn detail_errors() -> Value {
    json!({
        "400": err_resp("参数无效 (BAD_REQUEST)"),
        "404": err_resp("目标 id 不存在 (NOT_FOUND)"),
        "409": err_resp("多账号未指定 (ACCOUNT_AMBIGUOUS) / 需先 ingest (NEEDS_INGEST)"),
        // R16-6: mode=hot 热查扫描不完整(源库分片瞬态降级/超 10 万窗口)→ 没法确认记录是否存在, 可重试 (区别于 404 确认不存在)。
        "503": err_resp("热查扫描不完整, 没法确认 (DB_NOT_READY; 可重试或用 mode=cold)")
    })
}

/// 详情端点响应集: 200 信封 (data=schema[]) + detail_errors (400/404/409)。
fn detail_ok(desc: &str, data_schema: &str) -> Value {
    let mut r = detail_errors();
    r["200"] = ok_envelope(desc, Some(data_schema));
    r
}

/// 标准 GET 列表端点 operation (信封 data=data_schema[] + list_errors + 各参数)。
fn list_op(tag: &str, summary: &str, op_id: &str, data_schema: &str, mut params: Vec<Value>) -> Value {
    let mut responses = list_errors();
    responses["200"] = ok_envelope(summary, Some(data_schema));
    params.insert(0, account_param());
    json!({ "get": {
        "tags": [tag], "summary": summary, "operationId": op_id,
        "parameters": params, "responses": responses
    } })
}

/// `?confirm=` R21 成本门确认参 —— **仅热全扫端点**收它。凡运行时收 confirm 的端点 (独占全扫结构 +
/// HotScanPageQ/InspectScanQ 的) 规格里必须有它 (`every_runtime_query_param_is_documented` drift 契约)。
fn confirm_param() -> Value {
    q_param(
        "confirm",
        "R21 成本门: 估算超强制阈值 (主号 15s / 副号 30s) 的热全扫慢查默认 400 拒; 传 true 强制执行 (或改 mode=cold 走 L1 索引, ms 级)",
        json!({ "type": "boolean", "default": false }),
    )
}

/// `?mode=` 查询模式参数 (**R16-1**)。
///
/// **凡运行时收 `mode` 的端点, 规格里就必须有它** —— 否则拿 `/openapi.json` 生成的客户端**够不着热查**,
/// 且拿到一份不准的契约 (codex 审 P2 点名)。判据是"运行时收不收", 不是"哪个件加的":
/// `/sessions` 早就收 `mode`(R6 的 `ListQ.mode`), 规格里**一直没有** —— 那是既有的漏, 一并补。
///
/// `default` 由调用方给: R16-1 新接的那批是 **auto**(它们原本只有冷查, 缺省 hot 会破坏现有调用方);
/// `sessions`/`messages` 是 **hot**(R6 给它俩单独定的语义)。
fn mode_param(default: &str) -> Value {
    q_param(
        "mode",
        &format!(
            "查询模式 (默认 {default}): hot=直读微信库拿实时数据 (需 account + 已缓存 key) / \
             cold=读 L1 投影库 (快, 但可能旧, 响应带 ingested_at) / auto=有 L1 走 cold, 否则 hot"
        ),
        json!({ "type": "string", "enum": ["hot", "cold", "auto"], "default": default }),
    )
}

/// `/messages` 专用的 `?mode=` —— **故意不给 `default`**。
///
/// 该端点的缺省行为**随投影选择器变**, 不是一个固定值:
/// - **无**选择器 (只给 `?conv=`) → 缺省 **hot** (查会话最近消息)
/// - **有**选择器 → **R16-2 起投影都有热查版** (`kind=system/call/link/file/image/biz/forward` + `conv_type=official`
///   (=biz 别名) + `quote`(引用回复) + `mentions`/`mentions_me`(@提及); hot_events/calls/links/files/media/biz/thread/
///   resolve/mentions): 缺省 **auto** (有 L1 冷否则热), `mode=hot` 实时读微信库
///
/// 所以规格里**不能**声明 `default: "hot"`(codex 复审 P2): 客户端生成器会把 default **物化成真参数
/// 发出去** → `?kind=link&mode=hot` → 本来合法的投影请求变 **400**。宁可不写 default, 让生成器
/// 保持"不传", 由服务端按选择器决定。
fn mode_param_messages() -> Value {
    q_param(
        "mode",
        "查询模式 —— **缺省值取决于有没有投影选择器, 故本参数不声明 default; 别自动物化它**。\
         无选择器 (只给 ?conv=) 时: 缺省 hot (实时读微信库, 需 account + 已缓存 key), 可给 cold/auto。\
         投影选择器 R16-2 起**都有热查版** (kind=system/call/link/file/image/biz/forward + conv_type=official(=biz 别名) \
         + quote(引用回复) + mentions/mentions_me(@提及)): 缺省 auto (有 L1 冷否则热), 可给 hot/cold。",
        json!({ "type": "string", "enum": ["hot", "cold", "auto"] }),
    )
}

/// 全部 31 端点 path (件 D3)。用 `list_op` 收标准列表端点 + json! 定制特殊端点 (media/events/exec/names/detail)。
fn paths() -> Value {
    let mut m = serde_json::Map::new();
    let mut put = |k: &str, v: Value| {
        m.insert(k.to_string(), v);
    };

    // ── meta ──
    put(
        "/health",
        json!({ "get": {
        "tags": ["meta"], "summary": "健康检查 (就绪门外)", "operationId": "health",
        "responses": { "200": { "description": "服务存活 (非信封, 简单 JSON)",
            "content": { "application/json": { "schema": { "type": "object" } } } } }
    } }),
    );
    put(
        "/api/v1/ping",
        json!({ "get": {
        "tags": ["meta"], "summary": "连通性探测", "operationId": "ping",
        "responses": { "200": { "description": "pong (非信封, 简单对象 {status})",
            "content": { "application/json": { "schema": { "type": "object" } } } } }
    } }),
    );
    put(
        "/api/v1/openapi.json",
        json!({ "get": {
        "tags": ["meta"], "summary": "本 OpenAPI 3.0.3 规格 (供第三方生成客户端)", "operationId": "openapi",
        "responses": { "200": { "description": "OpenAPI 3.0.3 文档",
            "content": { "application/json": { "schema": { "type": "object" } } } } }
    } }),
    );
    put(
        "/api/v1/account",
        list_op(
            "meta",
            "当前账号信息 (各表行数统计; mode=hot 实时聚合源库计数, messages 全扫慢)",
            "getAccount",
            "AccountSummary",
            vec![mode_param("auto"), confirm_param()],
        ),
    );
    put(
        "/api/v1/accounts",
        json!({ "get": {
        "tags": ["meta"], "summary": "列全部账号 (无上限, 不需指定账号)", "operationId": "getAccounts",
        "responses": { "200": ok_envelope("账号列表信封", Some("AccountRef")),
            "400": err_resp("参数无效 (BAD_REQUEST; 未知参数等)") }
    } }),
    );
    // R19 选择性采集清单 (只读反映; 圈定/停采走 CLI `capture add/rm` —— 只读服务不暴露写)。
    put(
        "/api/v1/capture",
        json!({ "get": {
        "tags": ["meta"],
        "summary": "选择性采集清单 (R19; 每行 conv_id/added_at/note; 空=全采所有会话; 只读, 增删走 CLI capture add/rm)",
        "operationId": "getCapture",
        "parameters": [ account_param() ],
        "responses": { "200": ok_envelope("采集清单信封 (每行 conv_id/added_at/note)", None),
            "400": err_resp("参数无效 (BAD_REQUEST)"),
            "409": err_resp("多账号未指定 (ACCOUNT_AMBIGUOUS)") }
    } }),
    );
    // R9 复审 R2#7: live-index 索引状态端点。
    put(
        "/api/v1/live-index/status",
        json!({ "get": {
        "tags": ["meta"],
        "summary": "live-index 索引状态 (tier/live/message_fts_rows/incremental_triggers/message_total/indexed_through)",
        "operationId": "getLiveIndexStatus",
        "responses": { "200": ok_envelope("live-index 状态信封 (单行)", None),
            "400": err_resp("需服务端 --l1-db (BAD_REQUEST)") }
    } }),
    );

    // ── contacts / 群 ──
    put(
        "/api/v1/contacts",
        list_op(
            "contacts",
            "查/搜联系人 (cold=keyset 游标分页 / hot=offset 分页)",
            "getContacts",
            "Person",
            vec![
                mode_param("auto"),
                limit_param(),
                q_param(
                    "cursor",
                    "keyset 游标 (**仅 cold**; 上页 meta.next_cursor; 失效→INVALID_CURSOR)。给了它又 mode=hot → 400",
                    json!({ "type": "string" }),
                ),
                q_param(
                    "offset",
                    "跳过条数 (**仅 hot**; cold 请用 cursor —— cold 给 offset → 400)",
                    json!({ "type": "integer", "format": "int64", "minimum": 0 }),
                ),
                q_param("search", "昵称/备注/wxid 子串搜", json!({ "type": "string" })),
            ],
        ),
    );
    put(
        "/api/v1/contacts/{wxid}",
        json!({ "get": {
        "tags": ["contacts"], "summary": "单个联系人详情 (全字段)", "operationId": "getContactDetail",
        "description": "R16-6 冷热双模: cold 读 L1 person 全字段; mode=hot 直读加密 contact.db 实时查, 但字段少于冷 (热是列表集, 无冷派生的扩展列)。",
        "parameters": [ path_param("wxid", "联系人 wxid (或 sha)"), account_param(), mode_param("auto") ],
        "responses": detail_ok("联系人详情", "Person")
    } }),
    );
    put(
        "/api/v1/contacts/{wxid}/pack",
        json!({ "get": {
        "tags": ["contacts"], "summary": "联系人组合包 (名称解析 + 近期消息; 裸对象非信封)", "operationId": "getContactPack",
        "parameters": [ path_param("wxid", "联系人 wxid"), account_param() ],
        "responses": {
            "200": bare_ok("联系人组合包 {contact, recent_messages} (裸对象, 非 {data,meta})", "ContactPack"),
            "400": err_resp("参数无效 (BAD_REQUEST)"),
            "409": err_resp("多账号未指定 (ACCOUNT_AMBIGUOUS)")
        }
    } }),
    );
    put(
        "/api/v1/chatrooms",
        list_op(
            "contacts",
            "群列表 (群id/群名/群主/成员数/公告, 按成员数倒序; R16-1 冷热双模)",
            "getChatrooms",
            "Chatroom",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    ); // 审 P3: account_param 由 list_op 自动插, 别重复传
    put(
        "/api/v1/chatrooms/{id}",
        json!({ "get": {
        "tags": ["contacts"], "summary": "单个群详情 (群名/群主/人数/公告)", "operationId": "getChatroomDetail",
        "description": "R16-6 冷热双模: cold 读 L1 chatroom 全字段; mode=hot 直读加密 contact.db 实时查, 但字段少于冷 (热是列表集)。",
        "parameters": [ path_param("id", "群 id (@chatroom)"), account_param(), mode_param("auto") ],
        "responses": detail_ok("群详情", "Chatroom")
    } }),
    );
    put(
        "/api/v1/chatrooms/{id}/members",
        json!({ "get": {
        "tags": ["contacts"], "summary": "群成员列表",
        "description": "查群成员。R16-1 起冷热双模: mode=hot 直读微信库拿当前在群名单, 但降级 —— joined_at 恒 null (源库无入群时刻)、已退群成员不返回 (仅当前在群快照), summary 里 partial=true; cold 读 L1 (含入群时间和退群历史)。",
        "operationId": "getMembers",
        "parameters": [ path_param("id", "群 id"), mode_param("auto"), account_param(), limit_param(), offset_param(),
            q_param("admins_only", "只列管理员/群主", json!({ "type": "boolean" })) ],
        "responses": {
            "200": ok_envelope("群成员列表", Some("ChatroomMember")),
            "400": err_resp("参数无效 (BAD_REQUEST)"),
            "409": err_resp("多账号未指定 (ACCOUNT_AMBIGUOUS) / 需先 ingest (NEEDS_INGEST)")
        }
    } }),
    );

    // ── messages / 会话 ──
    put(
        "/api/v1/sessions",
        list_op(
            "messages",
            "会话列表 (最近会话, offset 分页)",
            "getSessions",
            "Session",
            vec![mode_param("hot"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/sessions/{id}",
        json!({ "get": {
        "tags": ["messages"], "summary": "单个会话详情", "operationId": "getSessionDetail",
        "description": "R16-6 冷热双模: cold 读 L1 session; mode=hot 直读加密 session.db 实时查 (字段与冷对等)。",
        "parameters": [ path_param("id", "会话 id (对方 wxid 或群 id)"), account_param(), mode_param("auto") ],
        "responses": detail_ok("会话详情", "Session")
    } }),
    );
    put(
        "/api/v1/sessions/{id}/pack",
        json!({ "get": {
        "tags": ["messages"], "summary": "会话组合包 (会话标识 + 近期消息; 裸对象非信封)", "operationId": "getSessionPack",
        "parameters": [ path_param("id", "会话 id"), account_param() ],
        "responses": {
            "200": bare_ok("会话组合包 {conv, is_group, recent_messages} (裸对象, 非 {data,meta})", "SessionPack"),
            "400": err_resp("无账号 (热查需定位账号库) / 参数无效 (BAD_REQUEST)")
        }
    } }),
    );
    put(
        "/api/v1/messages",
        json!({ "get": {
        "tags": ["messages"],
        "summary": "查消息 —— ?conv= 取某会话 (热查源库); 或给投影选择器 (多数冷查 L1 派生表, kind=system/call/link/file/image/biz/forward 冷热双模)",
        "description": "两模式二选一: (a) ?conv=<对方 wxid 或群 id> 取该会话最近消息 (热查); \
                        (b) 投影选择器 kind/mentions/mentions_me/conv_type=official/quote (互斥, 只能给一个)。\
                        多数投影走冷查派生表 (显式 mode=hot → 400 无实时版); **例外 kind=system/kind=call/kind=link/kind=file/kind=image/kind=biz (=conv_type=official) + quote (引用回复) + kind=forward (合并转发展开)** \
                        R16-2 起冷热双模: 缺省 auto (有 L1 冷否则热), 可 mode=hot 直读微信库。都不给 → 400。\
                        kind=forward 双模式: ?msg_id=X 展开该条子项 / 省略=列所有合并转发。data 元素形随选择器 (base/call/link/file/image/system/biz/thread/forward)。",
        "parameters": [
            account_param(), limit_param(), offset_param(), mode_param_messages(),
            q_param("conv", "会话 id (对方 wxid 或群 id; 热查该会话最近消息)", json!({ "type": "string" })),
            q_param("kind", "消息投影类型 (与其它选择器互斥; 多数冷查派生表, kind=system/call/link/file/image/biz/forward 冷热双模)",
                json!({ "type": "string", "enum": ["call", "link", "file", "image", "system", "biz", "forward"] })),
            q_param("sys_type", "系统消息子类过滤 (仅 kind=system): member_join/member_remove/revoke/pat/topmsg/group_dissolve/hongbao/transfer/other", json!({ "type": "string" })),
            q_param("msg_id", "合并转发展开 (仅 kind=forward): 给 message 的 source_native_id 展开该条子项; 省略=列所有合并转发消息供挑", json!({ "type": "string" })),
            q_param("source", "合并转发展开精确定位分片 (仅 kind=forward; 消息 id 跨分片会重号, 用 list 结果的 source 值; 省略且不重号时可不填)", json!({ "type": "string" })),
            q_param("mentions", "@提及某人 (填 wxid; R16-2 起冷热双模, mode=hot 直读微信库)", json!({ "type": "string" })),
            q_param("mentions_me", "只看 @我 的", json!({ "type": "boolean" })),
            q_param("conv_type", "会话类型 (仅 official=公众号; =kind=biz 别名, R16-2 起冷热双模)", json!({ "type": "string", "enum": ["official"] })),
            q_param("quote", "只看引用回复 (=thread; R16-2 起冷热双模, mode=hot 直读微信库取实时数据)", json!({ "type": "boolean" })),
            q_param(
                "refresh",
                "冷查前是否先把该会话的新消息补进 L1 (默认 true)。\
                 给 false = 只读 L1 现有的, 不碰微信库 —— 更快, 但可能看不到最新几条。\
                 无论补没补, 响应的 freshness 里都会如实标出 (chat_refreshed_at / refresh_skipped)。",
                json!({ "type": "boolean", "default": true }),
            ),
            confirm_param(),
        ],
        "responses": {
            "200": ok_envelope("消息列表 (热查省 total_count; 投影冷查带)", Some("Message")),
            "400": err_resp("缺 conv 且无投影选择器 / 选择器互斥冲突 / 值非法 (BAD_REQUEST)"),
            "409": err_resp("多账号未指定 (ACCOUNT_AMBIGUOUS) / 需先 ingest (NEEDS_INGEST)")
        }
    } }),
    );
    put(
        "/api/v1/messages/{id}",
        json!({ "get": {
        "tags": ["messages"], "summary": "单条消息详情 (全字段)", "operationId": "getMessageDetail",
        "description": "R16-6 冷热双模: cold 读 L1 message; mode=hot 全扫源库找 source_native_id 锚 (较慢; 字段与冷对等)。",
        "parameters": [ path_param("id", "消息 id (source_native_id)"), account_param(), mode_param("auto"), confirm_param() ],
        "responses": detail_ok("消息详情", "Message")
    } }),
    );

    // ── moments 朋友圈 ──
    put(
        "/api/v1/moments",
        list_op(
            "moments",
            "朋友圈动态 (作者/时间/正文/媒体数/赞评数; R16-1 冷热双模)",
            "getMoments",
            "Moment",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/moments/interactions",
        list_op(
            "moments",
            "朋友圈互动 (赞/评; R16-3 冷热双模)",
            "getMomentsInteractions",
            "MomentInteraction",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/moments/inbox",
        list_op(
            "moments",
            "朋友圈收件箱通知 (谁赞/评了我; R16-3 冷热双模)",
            "getMomentsInbox",
            "MomentInboxItem",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );

    // ── media 媒体 (二进制, 非信封) ──
    put(
        "/api/v1/media/{key}",
        json!({ "get": {
        "tags": ["media"],
        "summary": "媒体即时取用 (语音/视频/图片/表情/朋友圈; Range/HEAD; ?info 出元数据)",
        "description": "key 形: voice:<svr_id> · vid:<md5> · img:<talker_md5>:<local_id> · emoji:<md5> · \
                        moment:<source_native_id>:<media_seq>。即时解密/联网下载出字节。表情/朋友圈从 WeChat CDN \
                        联网取 (SSRF 闸)。**仅本机** (Host 须 loopback)。支持 Range (206) / HEAD。",
        "parameters": [
            path_param("key", "类型键 (voice:/vid:/img:/emoji:/moment:)"),
            account_param(),
            q_param("info", "出 JSON 元数据 (content_type/length…) 而非字节", json!({ "type": "string" })),
            { "name": "Range", "in": "header", "required": false,
              "description": "字节范围 (bytes=start-end) → 206 Partial", "schema": { "type": "string" } },
        ],
        "responses": {
            "200": { "description": "媒体字节 (Content-Type 随类型: image/* · audio/wav · video/mp4 · \
                     application/octet-stream) 或 ?info 的 JSON 元数据。带 Accept-Ranges: bytes。",
                "content": { "application/octet-stream": { "schema": { "type": "string", "format": "binary" } },
                             "application/json": { "schema": { "type": "object" } } } },
            "206": { "description": "Range 部分内容", "content": { "application/octet-stream": {
                "schema": { "type": "string", "format": "binary" } } } },
            "400": err_resp("媒体键格式非法 (BAD_REQUEST)"),
            "403": err_resp("非本机请求 (FORBIDDEN; Host 非 loopback)"),
            "404": err_resp("媒体不存在/取不到 (NOT_FOUND)"),
            "409": err_resp("多账号未指定 / 需先 ingest"),
            "416": { "description": "Range 不可满足" },
            "502": err_resp("朋友圈媒体 CDN 下载/解密失败 (CDN_FETCH_FAILED / SNS_DECRYPT_FAILED)"),
            "503": err_resp("朋友圈加密媒体缺 node keystream 脚本 (SNS_WASM_MISSING)")
        }
    } }),
    );

    // ── finance 交易 ──
    put(
        "/api/v1/money",
        json!({ "get": {
        "tags": ["finance"], "summary": "交易 (转账/红包/群收款 合并时间线; R16-4 冷热双模)", "operationId": "getMoney",
        "parameters": [ account_param(), mode_param("auto"), limit_param(), offset_param(),
            q_param("kind", "交易类型过滤 (省略/all = 全部)",
                json!({ "type": "string", "enum": ["all", "transfer", "red_envelope", "group_pay"] })), confirm_param() ],
        "responses": {
            "200": ok_envelope("交易时间线", Some("MoneyItem")),
            "400": err_resp("参数无效 (BAD_REQUEST)"),
            "409": err_resp("多账号未指定 / 需先 ingest")
        }
    } }),
    );
    put("/api/v1/money/claims", list_op("finance", "红包领取明细 (谁领了每个红包: 时间/会话/单号/我领的还是我发的被领/对方昵称; R16-4 冷热双模, type10000 系统消息派生)", "getMoneyClaims", "HongbaoClaim",
        vec![mode_param("auto"), limit_param(), offset_param(), confirm_param()]));
    put("/api/v1/money/payers", list_op("finance", "群收款逐付款人 (每笔群收款每人: 账单号/付款人wxid/金额分/已付未付; R16-4 冷热双模, type49 payerlist 派生, 一群收款多付款人)", "getMoneyPayers", "GroupPayMember",
        vec![mode_param("auto"), limit_param(), offset_param(), confirm_param()]));
    put(
        "/api/v1/pii-scan",
        list_op(
            "misc",
            "扫全库文本 PII (手机号/身份证; R16-5 冷热双模, msg1 派生, top-N 无翻页, 默认打码 reveal=true 显全)",
            "getPiiScan",
            "PiiHit",
            vec![
                mode_param("auto"),
                q_param(
                    "kind",
                    "PII 类型 (省略/all=全部)",
                    json!({ "type": "string", "enum": ["all", "phone", "idcard"] }),
                ),
                q_param("reveal", "显全不打码 (默认 false)", json!({ "type": "boolean" })),
                limit_param(),
                confirm_param(),
            ],
        ),
    );

    // ── misc ──
    put(
        "/api/v1/favorites",
        list_op(
            "misc",
            "收藏",
            "getFavorites",
            "Favorite",
            vec![
                mode_param("auto"),
                limit_param(),
                offset_param(),
                q_param("query", "标题/正文子串搜", json!({ "type": "string" })),
            ],
        ),
    );
    put(
        "/api/v1/favorites/media",
        list_op(
            "misc",
            "收藏媒体 (收藏笔记里的图/文件/HTML; R16-3 冷热双模)",
            "getFavoritesMedia",
            "FavMedia",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/favorites/tags",
        list_op(
            "misc",
            "收藏标签 (哪条收藏被贴了什么标签; R16-3 冷热双模)",
            "getFavoritesTags",
            "FavTag",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/channels",
        list_op(
            "misc",
            "访问过的视频号",
            "getChannels",
            "FinderVisit",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/avatars",
        list_op(
            "misc",
            "头像清单 (归属wxid/内容md5/更新时刻, 不含图片本体; R16-1 冷热双模)",
            "getAvatars",
            "Avatar",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    ); // 审 P3: account_param 由 list_op 自动插, 别重复传
    put(
        "/api/v1/locations",
        list_op(
            "messages",
            "位置分享 (经纬度/地点名/城市; R16-2 冷热双模, type48)",
            "getLocations",
            "Location",
            vec![mode_param("auto"), limit_param(), offset_param(), confirm_param()],
        ),
    );
    put(
        "/api/v1/group-events",
        list_op(
            "messages",
            "群成员进出记录 (谁进群/退群 昵称+wxid+时刻; R16-2 冷热双模, type10000 系统消息派生, 一消息可多成员)",
            "getGroupEvents",
            "GroupEvent",
            vec![mode_param("auto"), limit_param(), offset_param(), confirm_param()],
        ),
    );
    put(
        "/api/v1/cards",
        list_op(
            "messages",
            "分享名片 (被推荐人昵称/微信号/身份/企微公司名; R16-2 冷热双模, type42)",
            "getCards",
            "Card",
            vec![mode_param("auto"), limit_param(), offset_param(), confirm_param()],
        ),
    );
    put(
        "/api/v1/biz-contacts",
        list_op(
            "contacts",
            "企微联系人 (昵称/企微id/品牌号gh_; R16-1 冷热双模)",
            "getBizContacts",
            "BizContact",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/emoticons",
        list_op(
            "misc",
            "自定义表情目录",
            "getEmoticons",
            "Emoticon",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/search",
        list_op(
            "misc",
            "全文搜索消息正文 (默认 cold FTS5 trigram bm25; mode=hot 🔴降级全库扫子串无排名)",
            "getSearch",
            "SearchHit",
            vec![
                limit_param(),
                q_param("keyword", "搜索词 (必给才有结果)", json!({ "type": "string" })),
                mode_param("auto"),
                confirm_param(),
            ],
        ),
    );
    put(
        "/api/v1/stats",
        list_op(
            "misc",
            "统计聚合排行 (R16-5 冷热双模)",
            "getStats",
            "StatRow",
            vec![
                mode_param("auto"),
                limit_param(),
                offset_param(),
                q_param(
                    "by",
                    "聚合维度",
                    json!({ "type": "string", "enum": ["type", "conv", "sender", "day"] }),
                ),
                confirm_param(),
            ],
        ),
    );
    put(
        "/api/v1/dormant",
        list_op(
            "misc",
            "沉睡会话 (最久没说话排行; R16-6 冷热双模)",
            "getDormant",
            "DormantSession",
            vec![mode_param("auto"), limit_param(), offset_param(), confirm_param()],
        ),
    );
    put(
        "/api/v1/followups",
        list_op(
            "misc",
            "待回复会话 (每会话末条为对方所发、本账号还没回, 待跟进; R16-6 冷热双模)",
            "getFollowups",
            "Followup",
            vec![
                mode_param("auto"),
                limit_param(),
                offset_param(),
                q_param("private_only", "只看私聊", json!({ "type": "boolean" })),
                confirm_param(),
            ],
        ),
    );
    put(
        "/api/v1/extract",
        list_op(
            "misc",
            "模板抽取 (枚举式子集; R16-5 冷热双模)",
            "getExtract",
            "ExtractRow",
            vec![
                mode_param("auto"),
                limit_param(),
                offset_param(),
                q_param(
                    "kind",
                    "抽取模板类型 (省略默认 url)",
                    json!({ "type": "string", "enum": ["url", "email", "amount", "phone", "idcard"] }),
                ),
                confirm_param(),
            ],
        ),
    );
    put(
        "/api/v1/msgraw",
        list_op(
            "misc",
            "原始 payload dump (溯源)",
            "getMsgraw",
            "RawPayload",
            vec![
                limit_param(),
                offset_param(),
                q_param(
                    "native_id",
                    "某条 source_native_id (转出整条原始事件)",
                    json!({ "type": "string" }),
                ),
                q_param(
                    "source",
                    "只看某个源库 (如 message_0.db; 同名会话表可能同时在多个分片里)。按整个分片算: 消息那类 source 就是库名本身, 水位那类是 \"库名|表名\", 两种都算在内",
                    json!({ "type": "string" }),
                ),
            ],
        ),
    );
    put(
        "/api/v1/friend-requests",
        list_op(
            "misc",
            "好友申请/验证 (加好友来源场景+打招呼语)",
            "getFriendRequests",
            "FriendVerify",
            vec![mode_param("auto"), limit_param(), offset_param()],
        ),
    );
    put(
        "/api/v1/names",
        json!({
            "get": {
                "tags": ["misc"], "summary": "id→名称 批量解析 (GET; ids 上限 100; mode=hot 读源库 contact.db)", "operationId": "getNames",
                "parameters": [ account_param(),
                    q_param("ids", "逗号分隔 id 列表 (wxid/群id; ≤100, 更多用 POST)", json!({ "type": "string" })), mode_param("auto") ],
                "responses": { "200": ok_envelope("id→名称 映射", Some("NameEntry")),
                    "400": err_resp("ids 过多/格式错 (BAD_REQUEST)"), "409": err_resp("多账号未指定") }
            },
            "post": {
                "tags": ["misc"], "summary": "id→名称 批量解析 (POST; ids ≤200)", "operationId": "postNames",
                "requestBody": { "required": true, "content": { "application/json": { "schema": {
                    "type": "object", "required": ["ids"], "properties": {
                        "account": { "type": "string", "description": "账号 wxid (可选)" },
                        "ids": { "type": "array", "items": { "type": "string" }, "description": "id 列表 (≤200)" }
                    } } } } },
                "responses": { "200": ok_envelope("id→名称 映射", Some("NameEntry")),
                    "400": err_resp("body 无效/ids 过多 (BAD_REQUEST)"),
                    "413": err_resp("body 超上限 (PAYLOAD_TOO_LARGE)"),
                    "415": err_resp("Content-Type 非 application/json (UNSUPPORTED_MEDIA_TYPE)"),
                    "409": err_resp("多账号未指定") }
            }
        }),
    );

    // ── realtime SSE ──
    put(
        "/api/v1/events",
        json!({ "get": {
        "tags": ["realtime"],
        "summary": "实时事件流 (SSE; 读档 tail + watch 唤醒 + 心跳 + Last-Event-ID 补发)",
        "description": "text/event-stream 长连。serve 须 --watch 开启否则 503。每事件: id=archive.id · event=类型 · \
                        data=单行 JSON payload。断线用 Last-Event-ID 头 (或 ?last_event_id=) 补发。**仅本机**。",
        "parameters": [ account_param(),
            q_param("conv", "只推某会话 (对方 wxid 或群 id)", json!({ "type": "string" })),
            q_param("type", "只推某事件类型 (wire 名是 type, 非 event_type)", json!({ "type": "string" })),
            q_param("last_event_id", "从此 archive id 之后补发 (>0)", json!({ "type": "integer", "format": "int64" })),
            { "name": "Last-Event-ID", "in": "header", "required": false,
              "description": "SSE 重连补发点 (等价 ?last_event_id=)", "schema": { "type": "string" } } ],
        "responses": {
            "200": { "description": "SSE 事件流", "content": { "text/event-stream": {
                "schema": { "type": "string" } } } },
            "400": err_resp("last_event_id ≤ 0 等参数无效 (BAD_REQUEST)"),
            "403": err_resp("跨源/非本机 (FORBIDDEN; Host/Origin/Sec-Fetch-Mode)"),
            "503": err_resp("未开 --watch (EVENTS_DISABLED) / 并发满 (EVENTS_BUSY)")
        }
    } }),
    );

    // ── advanced 只读 SQL 逃生口 ──
    put(
        "/api/v1/exec",
        json!({ "post": {
        "tags": ["advanced"],
        "summary": "只读 SQL 逃生口 (cold 查 L1 / hot 直查加密源库原始 schema; 拒写/多语句)",
        "description": "高级用法: 跑 SELECT。硬只读 (authorizer 拒写/ATTACH/pragma); 内存/CPU 有界 \
                        (8MB set_limit + 15s deadline + 并发闸)。data 元素 = 查询结果行 (随 SQL, 开放对象)。\
                        R16-6 双模: 缺省 auto(有 L1 走 cold 查投影库); mode=hot 直查**加密源库原始裸 schema** \
                        (要 source_db 选库 + account), 表名 Msg_<md5>/Name2Id/裸 contact 等, 与 L1 完全不同, 专家向。",
        "requestBody": { "required": true, "content": { "application/json": { "schema": {
            "type": "object", "required": ["sql"], "properties": {
                "sql": { "type": "string", "description": "单条 SELECT (拒写操作/多语句)" },
                "max_rows": { "type": "integer", "format": "int64", "description": "结果行上限 (可选)" },
                "mode": { "type": "string", "enum": ["hot", "cold", "auto"], "description": "查询模式: auto(默认)/hot 直查源库原始 schema(要 source_db+account)/cold 查 L1" },
                "source_db": { "type": "string", "description": "mode=hot 必填: 源库相对路径 (db_storage 下, 如 contact/contact.db / message/message_0.db)" },
                "account": { "type": "string", "description": "mode=hot 定位账号 wxid (多账号库必填, 或用服务器默认账号)" }
            } } } } },
        "responses": {
            "200": ok_envelope("SQL 结果行", Some("ExecRow")),
            "400": err_resp("非 SELECT / 多语句 / SQL 错 / body 无效 / mode=hot 缺 source_db 或 account (BAD_REQUEST)"),
            "413": err_resp("body 超上限 (PAYLOAD_TOO_LARGE)"),
            "415": err_resp("Content-Type 非 application/json (UNSUPPORTED_MEDIA_TYPE)")
        }
    } }),
    );

    Value::Object(m)
}

#[cfg(test)]
mod openapi_drift {
    use std::collections::BTreeSet;

    use super::*;

    /// 编译期嵌 lib.rs 源 → 从 `.route("…")` 抽真实路由路径 (:x→{x} 归一) = 路由权威源。
    const LIB_SRC: &str = include_str!("lib.rs");

    fn normalize_path(p: &str) -> String {
        p.split('/')
            .map(|seg| {
                seg.strip_prefix(':')
                    .map_or_else(|| seg.to_string(), |name| format!("{{{name}}}"))
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// build_router 里全部 `.route("PATH", …)` 的 PATH (归一后)。
    fn router_paths() -> BTreeSet<String> {
        LIB_SRC
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix(".route(\"")?;
                let path = rest.split('"').next()?;
                Some(normalize_path(path))
            })
            .collect()
    }

    fn spec_paths() -> BTreeSet<String> {
        openapi_doc()["paths"].as_object().unwrap().keys().cloned().collect()
    }

    /// **R16-1 审 P3**: 每个端点的 parameters **(name, in) 必须唯一**(OpenAPI 3.0.3 硬约束)。
    /// chatrooms/avatars 曾在 list_op 的 vec 里多传一个 `account_param`(list_op 自身还会插一个)→ account
    /// 出现两次, 客户端 codegen 会报错/冲突。此测试扫全端点每方法的参数, 逮重复。
    #[test]
    fn no_duplicate_parameters_per_operation() {
        let doc = openapi_doc();
        let paths = doc["paths"].as_object().unwrap();
        let mut dups: Vec<String> = Vec::new();
        for (path, item) in paths {
            for (method, op) in item.as_object().unwrap() {
                let Some(params) = op.get("parameters").and_then(|p| p.as_array()) else {
                    continue;
                };
                let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
                for p in params {
                    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let loc = p.get("in").and_then(|v| v.as_str()).unwrap_or("");
                    if !seen.insert((name.to_string(), loc.to_string())) {
                        dups.push(format!("{method} {path}: 参数 ({name}, in={loc}) 重复"));
                    }
                }
            }
        }
        assert!(
            dups.is_empty(),
            "OpenAPI 参数 (name,in) 必须唯一, 逮到重复:\n{}",
            dups.join("\n")
        );
    }

    /// **路由↔规格双向严格相等** (真实源自动对): build_router 加/删端点没同步规格 → 此测试红并指名差集。
    #[test]
    fn every_route_documented_and_vice_versa() {
        let (routes, spec) = (router_paths(), spec_paths());
        let missing_in_spec: Vec<_> = routes.difference(&spec).collect();
        let missing_in_router: Vec<_> = spec.difference(&routes).collect();
        assert!(
            missing_in_spec.is_empty(),
            "路由有、规格缺: {missing_in_spec:?} (openapi.rs paths() 补上)"
        );
        assert!(
            missing_in_router.is_empty(),
            "规格有、路由无: {missing_in_router:?} (规格写了不存在的端点)"
        );
    }

    /// `.route("PATH", get(handler))` → (PATH, handler 名)。
    fn route_handlers() -> Vec<(String, String)> {
        LIB_SRC
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                let rest = t.strip_prefix(".route(\"")?;
                let mut it = rest.split('"');
                let path = it.next()?;
                // …", get(get_contacts))  /  …", get(x).post(y))
                let tail = it.next()?;
                let h = tail.split("get(").nth(1)?.split(')').next()?.split('.').next()?;
                Some((normalize_path(path), h.trim().to_string()))
            })
            .collect()
    }

    /// `async fn <handler>(… Qs(p): Qs<XxxQ>…)` → (handler 名, Q struct 名)。
    fn handler_query_structs() -> std::collections::BTreeMap<String, String> {
        let mut out = std::collections::BTreeMap::new();
        let mut cur: Option<String> = None;
        for l in LIB_SRC.lines() {
            let t = l.trim();
            if let Some(rest) = t.strip_prefix("async fn ") {
                cur = rest.split('(').next().map(|s| s.trim().to_string());
            } else if let Some(rest) = t.strip_prefix("Qs(p): Qs<") {
                if let (Some(h), Some(q)) = (cur.clone(), rest.split('>').next()) {
                    out.insert(h, q.to_string());
                }
            }
        }
        out
    }

    /// `struct XxxQ { … }` 的 **query 参数名**(= serde 的 wire 名, **认 `#[serde(rename = "…")]`**)。
    ///
    /// 必须认 rename: `EventsQ.event_type` 的 wire 名是 `type`(`#[serde(rename = "type")]`) —— 只抽
    /// struct 字段名的话会误报"规格没写 event_type", 而规格写的 `type` 才是对的。**验证器自己误报,
    /// 会逼人去改本来正确的代码。**
    fn q_struct_fields(name: &str) -> BTreeSet<String> {
        let head = format!("struct {name} {{");
        let Some(start) = LIB_SRC.find(&head) else {
            return BTreeSet::new();
        };
        let body = &LIB_SRC[start + head.len()..];
        let end = body.find("\n}").unwrap_or(body.len());
        let mut out = BTreeSet::new();
        let mut rename: Option<String> = None;
        for l in body[..end].lines() {
            let t = l.trim();
            // #[serde(rename = "type")] → 下一个字段的 wire 名
            if let Some(r) = t.strip_prefix("#[serde(rename = \"") {
                rename = r.split('"').next().map(str::to_string);
                continue;
            }
            if t.starts_with("//") || t.starts_with('#') {
                continue;
            }
            let Some((fname, _)) = t.split_once(':') else { continue };
            let fname = fname.trim();
            if fname.chars().all(|c| c.is_ascii_lowercase() || c == '_') && !fname.is_empty() {
                out.insert(rename.take().unwrap_or_else(|| fname.to_string()));
            }
        }
        out
    }

    /// 规格里某端点 GET 声明的 query 参数名。
    fn spec_query_params(path: &str) -> BTreeSet<String> {
        openapi_doc()["paths"][path]["get"]["parameters"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .filter(|p| p["in"] == "query")
                    .filter_map(|p| p["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// **运行时收的每个 query 参数, 规格里都得有** (codex 审 P2 逮到的那类, 根治)。
    ///
    /// 为什么非要机器扫: 上面那个 `every_route_documented_and_vice_versa` 只对**路由**, **不看参数** ——
    /// 于是 R16-1 给 contacts/favorites/friend-requests/channels 的运行时加了 `mode`(+contacts 的 hot
    /// `offset`)、规格却只字未提, **4 个漂移测试全绿**。拿 `/openapi.json` 生成的客户端够不着热查,
    /// 而且拿到一份不准的契约。顺带查出 `/sessions` 的 `mode`(R6 就有)**一直没进规格** —— 早就漂了。
    ///
    /// 全自动、零手抄: 路由表 → handler → `Qs<XxxQ>` → struct 字段, 三跳全从 lib.rs 源码抽。
    /// 加字段忘了写规格 → 此测试红并指名端点 + 缺的参数名。
    #[test]
    fn every_runtime_query_param_is_documented() {
        let structs = handler_query_structs();
        let mut bad: Vec<String> = Vec::new();
        let mut checked = 0usize;
        for (path, handler) in route_handlers() {
            let Some(q) = structs.get(&handler) else { continue }; // 该 handler 不吃 query struct
            let runtime = q_struct_fields(q);
            if runtime.is_empty() {
                continue; // struct 不在 lib.rs (如共用类型) → 本测试够不着, 不误报
            }
            let documented = spec_query_params(&path);
            let missing: Vec<_> = runtime.difference(&documented).cloned().collect();
            if !missing.is_empty() {
                bad.push(format!(
                    "  {path} (handler {handler}, {q}): 运行时收但规格没写 → {missing:?}"
                ));
            }
            checked += 1;
        }
        assert!(
            checked >= 8,
            "只核到 {checked} 个端点 —— 源码解析多半失效了, 别让这测试变成假绿"
        );
        assert!(
            bad.is_empty(),
            "以下端点的 query 参数运行时收、规格没写 (拿 /openapi.json 生成的客户端够不着):\n{}",
            bad.join("\n")
        );
    }

    /// 错误码枚举 == `native_core::ErrorCode::ALL` + HTTP 皮专有码 (增删内核码自动跟, drift-free)。
    #[test]
    fn error_code_enum_matches_source() {
        let spec_codes: Vec<String> = openapi_doc()["components"]["schemas"]["ErrorCode"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            spec_codes,
            all_error_codes(),
            "ErrorCode 枚举须 == 内核 ALL + HTTP 专有 (源变自动跟)"
        );
        for c in native_core::ErrorCode::ALL {
            assert!(spec_codes.iter().any(|s| s == c.code()), "内核码 {} 未进规格", c.code());
        }
    }

    /// 每个 `$ref: #/components/schemas/X` 的 X 都在 components.schemas 里 (无悬空引用)。
    #[test]
    fn all_refs_resolve() {
        let doc = openapi_doc();
        let schemas: BTreeSet<String> = doc["components"]["schemas"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut refs = Vec::new();
        collect_refs(&doc, &mut refs);
        for r in &refs {
            if let Some(name) = r.strip_prefix("#/components/schemas/") {
                assert!(schemas.contains(name), "悬空 $ref: {r} (schemas 无 {name})");
            }
        }
        assert!(refs.len() > 30, "应有可观 $ref 数, 实 {}", refs.len());
    }

    fn collect_refs(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, vv) in m {
                    if k == "$ref" {
                        if let Some(s) = vv.as_str() {
                            out.push(s.to_string());
                        }
                    } else {
                        collect_refs(vv, out);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
            _ => {}
        }
    }

    /// 顶层结构合规 (openapi 版本 / info.version / 每端点有 operation+responses)。
    #[test]
    fn doc_structure_valid() {
        let doc = openapi_doc();
        assert_eq!(doc["openapi"], "3.0.3");
        assert!(doc["info"]["version"].is_string());
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.len() >= 30, "端点数 {}", paths.len());
        for (path, ops) in paths {
            let ops = ops.as_object().unwrap();
            assert!(!ops.is_empty(), "{path} 无 operation");
            for (method, op) in ops {
                assert!(
                    op["responses"]["200"].is_object() || op["responses"]["206"].is_object(),
                    "{path} {method} 无 200/206 响应"
                );
            }
        }
    }

    /// **字段级防走偏** (D5b, 需真 L1 夹具故 #[ignore]): 对每个数据端点跑真实请求, 断言响应 data[0] 的每个字段
    /// 都在对应 schema 的 properties 里 —— **加了库列/查询字段没同步规格 → 此测试红并指名缺哪个** (这就是
    /// "后期加字段方便"靠的东西)。空表端点自动跳过。跑法: `WECHAT_TEST_L1=<某 L1.db> cargo test -p native-http
    /// openapi_field_drift -- --ignored --nocapture` (夹具字段越全覆盖越广)。
    #[tokio::test]
    #[ignore = "需真 L1 夹具: 设 WECHAT_TEST_L1=<l1.db> 再 --ignored 跑"]
    async fn openapi_field_drift() {
        use tower::ServiceExt as _;
        let Ok(l1) = std::env::var("WECHAT_TEST_L1") else {
            eprintln!("跳过 openapi_field_drift: 未设 WECHAT_TEST_L1");
            return;
        };
        let app = crate::build_router(crate::AppState {
            l1_db: Some(l1),
            ..Default::default()
        });
        let doc = openapi_doc();
        // (url, schema 名): 数据端点。真实 data[0] 字段须 ⊆ schema.properties (投影按 kind 各跑)。
        let cases: &[(&str, &str)] = &[
            ("/api/v1/contacts?limit=1", "Person"),
            ("/api/v1/account", "AccountSummary"),
            ("/api/v1/accounts", "AccountRef"),
            ("/api/v1/sessions?limit=1", "Session"),
            ("/api/v1/messages?kind=call&limit=1", "Message"),
            ("/api/v1/messages?kind=link&limit=1", "Message"),
            ("/api/v1/messages?kind=file&limit=1", "Message"),
            ("/api/v1/messages?kind=image&limit=1", "Message"),
            ("/api/v1/messages?kind=system&limit=1", "Message"),
            ("/api/v1/messages?kind=biz&limit=1", "Message"),
            ("/api/v1/moments?limit=1", "Moment"),
            ("/api/v1/moments/interactions?limit=1", "MomentInteraction"),
            ("/api/v1/moments/inbox?limit=1", "MomentInboxItem"),
            ("/api/v1/money?limit=1", "MoneyItem"),
            ("/api/v1/favorites?limit=1", "Favorite"),
            ("/api/v1/channels?limit=1", "FinderVisit"),
            ("/api/v1/emoticons?limit=1", "Emoticon"),
            ("/api/v1/search?keyword=%E7%9A%84&limit=1", "SearchHit"),
            ("/api/v1/stats?by=type&limit=1", "StatRow"),
            ("/api/v1/dormant?limit=1", "DormantSession"),
            ("/api/v1/followups?limit=1", "Followup"),
            ("/api/v1/extract?limit=1", "ExtractRow"),
            ("/api/v1/msgraw?limit=1", "RawPayload"),
            ("/api/v1/friend-requests?limit=1", "FriendVerify"),
        ];
        let mut problems = Vec::new();
        let mut checked = 0;
        for (url, sn) in cases {
            let req = axum::http::Request::builder()
                .uri(*url)
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let Ok(j) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            let Some(row) = j["data"].as_array().and_then(|a| a.first()).and_then(Value::as_object) else {
                continue; // 空表 → 跳
            };
            checked += 1;
            let empty = serde_json::Map::new();
            let props = doc["components"]["schemas"][*sn]["properties"]
                .as_object()
                .unwrap_or(&empty);
            let missing: Vec<_> = row.keys().filter(|k| !props.contains_key(*k)).cloned().collect();
            if !missing.is_empty() {
                problems.push(format!("{url} ({sn}) 规格缺字段: {missing:?}"));
            }
        }
        eprintln!("openapi_field_drift: 核了 {checked} 个有数据端点");
        assert!(
            problems.is_empty(),
            "字段漂移 (加字段没同步规格):\n{}",
            problems.join("\n")
        );
    }
}
