//! HTTP 响应契约 (③ §5) —— 错误体 `{error:{code,message,hint,candidates}, request_id}` + **每响应带
//! `X-Request-Id`** (成功也带; §5/§48)。错误码与内核 [`native_core::ErrorCode`] 共享, 每码都映射到 HTTP 状态
//! (§5 "别留缺口")。
//!
//! `request_id` 进程内单调计数生成 (无 uuid 依赖) —— v1 同机日志关联足够 (公网/0.0.0.0 OUT OF SCOPE, §2)。

use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{FromRequest, FromRequestParts, Query, Request};
use axum::http::header::HeaderName;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// 每请求唯一 id (中间件塞进 extensions, handler 经 `Extension<RequestId>` 取)。
#[derive(Clone)]
pub struct RequestId(pub String);

static REQ_SEQ: AtomicU64 = AtomicU64::new(1);

// ⚠️ rustc 1.96 的 ICE 绕行(不是嫌 lint 烦): clippy 给本函数出 pedantic 警告时 rustc 自己崩
// (rustc_span:2439 断言, 崩在渲染阶段 → 一条警告都打不出来)。1.83 不崩、1.96 与 nightly 都崩
// ⇒ 编译器 bug, 升降版本都躲不掉。逐层二分定位到本函数。
// 完整排查记录见 native-core::mediastore::engine::open_work_item 上的注释。
#[allow(clippy::pedantic)]
fn gen_id() -> String {
    format!("req-{:08x}", REQ_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// 中间件: 生成 request id 塞进 extensions (供 handler 读进错误体) + 给**每个响应**(成功/错误)加
/// `X-Request-Id` 头。§5: 每响应带, casing 统一 `X-Request-Id`。
pub async fn request_id_mw(mut req: Request, next: Next) -> Response {
    let id = gen_id();
    req.extensions_mut().insert(RequestId(id.clone()));
    let mut resp = next.run(req).await;
    if let Ok(hv) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(HeaderName::from_static("x-request-id"), hv);
    }
    resp
}

/// §5 错误: 机器码 `code` (稳定枚举, 第三方可 switch) + 人话 `message` + `hint` + 歧义 `candidates`。
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub candidates: Option<Value>,
    pub request_id: String,
}

impl ApiError {
    pub fn new(rid: &RequestId, status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            hint: None,
            candidates: None,
            request_id: rid.0.clone(),
        }
    }

    /// 参数错 (400 BAD_REQUEST) 快捷。
    pub fn bad_request(rid: &RequestId, message: impl Into<String>) -> Self {
        Self::new(rid, StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    #[must_use]
    pub fn with_candidates(mut self, candidates: Value) -> Self {
        self.candidates = Some(candidates);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut err = json!({ "code": self.code, "message": self.message });
        if let Some(h) = self.hint {
            err["hint"] = json!(h);
        }
        if let Some(c) = self.candidates {
            err["candidates"] = c;
        }
        let body = json!({ "error": err, "request_id": self.request_id });
        (self.status, Json(body)).into_response()
    }
}

/// 查询参数提取器 —— 解析失败 (未知参数 / 值非法) → **§5 400 错误体** (非 axum 默认空 body)。
/// 各端点配 per-endpoint 参数结构 (`#[serde(deny_unknown_fields)]`) → 该端点不认的参数被**拒 400**,
/// **不静默吞** (审查红队 #1: 共享参数结构 + handler 只读自己那几个 → 筛选参数被无声忽略, 返未过滤全量)。
pub struct Qs<T>(pub T);

#[axum::async_trait]
impl<T, S> FromRequestParts<S> for Qs<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let rid = parts
            .extensions
            .get::<RequestId>()
            .cloned()
            .unwrap_or_else(|| RequestId("req-unknown".to_string()));
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(v)) => Ok(Self(v)),
            Err(rej) => Err(ApiError::bad_request(&rid, format!("查询参数无效: {rej}"))
                .with_hint("检查参数名与取值 (端点不认的参数会被拒绝, 而非静默忽略)")),
        }
    }
}

/// JSON body 提取器 (POST 端点 names/exec 用) —— 解析失败映射 §5: 错/缺 `Content-Type: application/json` → **415
/// UNSUPPORTED_MEDIA_TYPE**, 坏 JSON / 缺字段 / 未知字段 (body 结构 `#[serde(deny_unknown_fields)]`) → **400**;
/// 非 axum 默认纯文本体。镜像 [`Qs`] 的"拒非静默"契约到请求体。
pub struct Jb<T>(pub T);

#[axum::async_trait]
impl<T, S> FromRequest<S> for Jb<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // rid 由中间件塞进 extensions; body 提取消费 req 前先克隆出来。
        let rid = req
            .extensions()
            .get::<RequestId>()
            .cloned()
            .unwrap_or_else(|| RequestId("req-unknown".to_string()));
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(rej) => {
                use axum::extract::rejection::JsonRejection;
                let (status, code) = match &rej {
                    JsonRejection::MissingJsonContentType(_) => {
                        (StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE")
                    }
                    // 审查 C NAMES-JB-03: body 超 axum 默认 2MB → BytesRejection(LengthLimitError) → 413 (非 400)。
                    JsonRejection::BytesRejection(_) => (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE"),
                    _ => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
                };
                Err(ApiError::new(&rid, status, code, format!("请求体无效: {rej}"))
                    .with_hint("POST body 须为 JSON (Content-Type: application/json); 字段见 ③规格 §6"))
            }
        }
    }
}

/// per-code 通用修复提示 (§5 `hint`='怎么修'; `message` 仍保内核具体信息)。审查 F2: 否则 hint 对内核错恒空。
fn code_hint(code: native_core::ErrorCode) -> Option<&'static str> {
    use native_core::ErrorCode as C;
    match code {
        C::InvalidCursor => Some("游标失效 —— 去掉 ?cursor= 从头翻"),
        // AccountAmbiguous 不在此列: 真歧义路 (resolve_cold_account) 自建 hint + candidates; 若从 map_core_err
        // 走会给"候选见 candidates"却无 candidates 字段 (复审逮的自相矛盾) → 留 None。
        C::AccountNotFound => Some("确认 account (wxid) 存在; 见 GET /api/v1/account"),
        C::NotFound => Some("确认 id 正确, 且该表已 ingest"),
        C::NeedsIngest => Some("该操作需先 ingest 产出 L1"),
        C::SchemaMismatch => Some("L1 库 schema 旧, 需重建 / 迁移"),
        C::DbNotReady | C::DbDecrypting => Some("库未就绪 / 解密中, 稍后重试"),
        _ => None,
    }
}

/// 内核 anyhow 错 → `ApiError` (classify_error 取码 → §5 HTTP 状态映射; **每码都有**, 别留缺口)。
/// `message` = 内核具体错; `hint` = per-code 修复提示 (§5 拆分 message=为什么 / hint=怎么修; 审查 F2)。
pub fn map_core_err(rid: &RequestId, e: &anyhow::Error) -> ApiError {
    use native_core::ErrorCode as C;
    let code = native_query::classify_error(e);
    let status = match code {
        C::BadRequest | C::InvalidCursor => StatusCode::BAD_REQUEST,
        C::Unauthorized => StatusCode::UNAUTHORIZED,
        C::NotFound | C::AccountNotFound => StatusCode::NOT_FOUND,
        C::AccountAmbiguous | C::SchemaMismatch | C::NeedsIngest | C::IndexLocked => StatusCode::CONFLICT,
        C::DbNotReady | C::DbDecrypting | C::IndexBuilding => StatusCode::SERVICE_UNAVAILABLE,
        C::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        C::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let err = ApiError::new(rid, status, code.code(), e.to_string());
    match code_hint(code) {
        Some(h) => err.with_hint(h),
        None => err,
    }
}

/// codex-R8 P2: 该 anyhow 错是否为 SQLite **查询被中断** (progress_handler deadline 到期 → `SQLITE_INTERRUPT`)。
/// 冷查/搜索据此**精确**判 408 REQUEST_TIMEOUT —— 按错误码判, 非按 `elapsed>=30s` 计时 (计时会把慢开库 / 其它 30s
/// 后失败的非中断错误误报 408, 且 cold_cmd 的计时起点早于 deadline 安装点)。遍历 anyhow source 链找
/// `rusqlite::Error::SqliteFailure{code: OperationInterrupted}` (中断错常被 `.context()` 包裹; needs_ingest_err 对非
/// "no such table" 原样透传, 故 rusqlite 错保留在链上可被 downcast 命中)。
pub fn is_query_interrupted(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(ffi, _)) if ffi.code == rusqlite::ErrorCode::OperationInterrupted
        )
    })
}
