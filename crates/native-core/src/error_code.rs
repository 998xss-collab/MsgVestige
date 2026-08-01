//! 共享错误码枚举 —— 内核持有, CLI/HTTP/MCP 三皮同 `code` 字符串值 (内核 §13 闭集)。
//!
//! 契约来源:
//! - **闭集 14 码**: `接口设计-①数据模型内核 §13`。
//! - **CLI 退出码**: `接口设计-②cli命令行 §二.5`(错误码→固定整数, 脚本可 `case $?`)。
//! - **HTTP 状态映射**: `接口设计-③http-api`。serve 是 **P3** —— [`ErrorCode::http_status`]
//!   于 P3 落地时按 doc③ 冻结表补 (`SCHEMA_MISMATCH` 等尚未在 doc 明确, 不在此臆测);
//!   P0 只需 CLI 用到的 [`ErrorCode::code`] / [`ErrorCode::exit_code`]。
//!
//! 三皮错误信封形态不同 (CLI `{_error,_hint}` / HTTP `{error:{code,…}}` / MCP isError
//! `{what,how_to_fix}`), 但 `code` 字符串值共享、退出码在此定义一次。

use std::fmt;

/// 内核 §13 共享错误码闭集 (14 个)。
///
/// **穷尽 `match` (无 `_` 兜底)**: 增删码会让 [`ErrorCode::code`] / [`ErrorCode::exit_code`]
/// 编译不过, 逼同步契约。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// 请求参数不合法 (缺参 / 值非法 / 互斥选项冲突)。
    BadRequest,
    /// 未鉴权 (HTTP-only; CLI loopback 不触发)。
    Unauthorized,
    /// 目标不存在 (会话 / 联系人 / 消息 id 查无)。
    NotFound,
    /// 游标失效 (版本 / account / filter 不符; 客户端从头翻)。
    InvalidCursor,
    /// L1 schema 版本与工具期望不符 (旧库未迁移 / 版本戳不认)。
    SchemaMismatch,
    /// 数据库尚未就绪。
    DbNotReady,
    /// 数据库解密中 (稍后重试)。
    DbDecrypting,
    /// live-index 索引异步在建, 且无可接受回退。
    IndexBuilding,
    /// live-index 单写者锁被另一维护者持有 / 已在跑。
    IndexLocked,
    /// 未指定账号且存在多账号 (返候选让调用方选)。
    AccountAmbiguous,
    /// 指定的账号不存在 / 未缓存 key。
    AccountNotFound,
    /// 限流 (HTTP-only; CLI 不触发)。
    RateLimited,
    /// 内部错误 (未分类的兜底)。
    Internal,
    /// 该操作只有冷查能做但未 ingest (附"先 ingest"提示)。
    NeedsIngest,
}

impl ErrorCode {
    /// SCREAMING_SNAKE `code` 字符串值 (三皮共享; 对齐内核 §13 / doc③ 枚举)。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "BAD_REQUEST",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::NotFound => "NOT_FOUND",
            Self::InvalidCursor => "INVALID_CURSOR",
            Self::SchemaMismatch => "SCHEMA_MISMATCH",
            Self::DbNotReady => "DB_NOT_READY",
            Self::DbDecrypting => "DB_DECRYPTING",
            Self::IndexBuilding => "INDEX_BUILDING",
            Self::IndexLocked => "INDEX_LOCKED",
            Self::AccountAmbiguous => "ACCOUNT_AMBIGUOUS",
            Self::AccountNotFound => "ACCOUNT_NOT_FOUND",
            Self::RateLimited => "RATE_LIMITED",
            Self::Internal => "INTERNAL",
            Self::NeedsIngest => "NEEDS_INGEST",
        }
    }

    /// CLI 稳定退出码 (doc② §二.5; 脚本可 `case $?`)。`0`=成功不在此 (非错误)。
    ///
    /// `UNAUTHORIZED` / `RATE_LIMITED` 是 **HTTP-only**、CLI 不触发 —— 兜底给 `70`(不应到达)。
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::BadRequest | Self::InvalidCursor => 2,
            Self::NotFound => 3,
            Self::AccountAmbiguous | Self::AccountNotFound => 4,
            Self::NeedsIngest => 5,
            Self::SchemaMismatch => 6,
            Self::DbNotReady | Self::DbDecrypting | Self::IndexBuilding | Self::IndexLocked => 7,
            Self::Internal | Self::Unauthorized | Self::RateLimited => 70,
        }
    }

    /// 全部错误码 (契约遍历用: OpenAPI `ErrorCode` 枚举从此拉 → drift-free)。增删码须同步 —— 下方
    /// `error_code_contract_frozen` 断言 `ALL` == §13 冻结 14 码表 (同码同序), 漏/错即 FAIL。
    pub const ALL: [ErrorCode; 14] = [
        Self::BadRequest,
        Self::Unauthorized,
        Self::NotFound,
        Self::InvalidCursor,
        Self::SchemaMismatch,
        Self::DbNotReady,
        Self::DbDecrypting,
        Self::IndexBuilding,
        Self::IndexLocked,
        Self::AccountAmbiguous,
        Self::AccountNotFound,
        Self::RateLimited,
        Self::Internal,
        Self::NeedsIngest,
    ];
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 锁死 §13 闭集 (14 码) + doc② §二.5 退出码映射 —— 改动即触发, 逼对齐契约 (mini golden)。
    /// 左表 = 冻结期望, 右 = impl; 增删码 / 改退出码 → 断言 FAIL。
    #[test]
    fn error_code_contract_frozen() {
        let table = [
            (ErrorCode::BadRequest, "BAD_REQUEST", 2),
            (ErrorCode::Unauthorized, "UNAUTHORIZED", 70),
            (ErrorCode::NotFound, "NOT_FOUND", 3),
            (ErrorCode::InvalidCursor, "INVALID_CURSOR", 2),
            (ErrorCode::SchemaMismatch, "SCHEMA_MISMATCH", 6),
            (ErrorCode::DbNotReady, "DB_NOT_READY", 7),
            (ErrorCode::DbDecrypting, "DB_DECRYPTING", 7),
            (ErrorCode::IndexBuilding, "INDEX_BUILDING", 7),
            (ErrorCode::IndexLocked, "INDEX_LOCKED", 7),
            (ErrorCode::AccountAmbiguous, "ACCOUNT_AMBIGUOUS", 4),
            (ErrorCode::AccountNotFound, "ACCOUNT_NOT_FOUND", 4),
            (ErrorCode::RateLimited, "RATE_LIMITED", 70),
            (ErrorCode::Internal, "INTERNAL", 70),
            (ErrorCode::NeedsIngest, "NEEDS_INGEST", 5),
        ];
        assert_eq!(table.len(), 14, "§13 闭集恰 14 码 (增删须同步本表 + enum)");
        // ErrorCode::ALL 须与冻结表同码同序 (OpenAPI 从 ALL 拉全错误码 → ALL 漏码=规格漏码)。
        assert_eq!(
            ErrorCode::ALL.to_vec(),
            table.iter().map(|(ec, _, _)| *ec).collect::<Vec<_>>(),
            "ErrorCode::ALL 须与 §13 冻结 14 码表同码同序 (增删码同步 ALL)"
        );
        for (ec, code, exit) in table {
            assert_eq!(ec.code(), code, "{ec:?} 的 code 串");
            assert_eq!(ec.exit_code(), exit, "{ec:?} 的退出码");
            assert_eq!(ec.to_string(), code, "{ec:?} Display == code");
        }
    }
}
