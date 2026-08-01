//! CLI 业务错误码 (查询内核抽取 §6①: 移自 msgvestige `main.rs`)。
//!
//! `CliError` 携 [`native_core::ErrorCode`] + hint;[`cli_err`] 构造携码错;[`classify_error`] 顶层错 → 码。
//! **呈现留皮**: `render_cli_error` + `main()` 退出码映射仍在 msgvestige (CLI stdout/exit 呈现, 非核), 不进本 crate。

/// CLI 业务错误 (带错误码) —— msgvestige `main` 据此渲染 `{_error,_hint}` + 设退出码。
/// ②③④ 用它携码 (如 `CliError{code: ErrorCode::AccountAmbiguous, hint}`);未携码的 anyhow 错 → `INTERNAL`。
///
/// 字段 **`pub`**(§6① 跨 crate 后必需): `paginate`(本 crate 兄弟模块)构造字面量 + msgvestige
/// `render_cli_error` 读 `hint`(跨 crate)+ cmd_inspect/单测构造字面量(跨 crate)。
#[derive(Debug)]
pub struct CliError {
    pub code: native_core::ErrorCode,
    pub hint: String,
}
impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hint)
    }
}
impl std::error::Error for CliError {}

/// 构造**携码** CLI 错误 —— `main` 据码设退出码 (doc② §二.5)。**用户可预期的错**
/// (参数非法/查无/账号歧义…) 走这个, 别用无码的 `bail!`/`anyhow!`/`.context` (那会 classify 成 INTERNAL/70)。
pub fn cli_err(code: native_core::ErrorCode, hint: impl Into<String>) -> anyhow::Error {
    CliError {
        code,
        hint: hint.into(),
    }
    .into()
}

/// 顶层错误 → 错误码。携码 [`CliError`] 取其码;否则按**底层错误特征**归类 —— **集中兜底**, 免逐命令
/// 包裹漏网 (契约审 rank1/2: `open_readonly` 惰性打开, 非 sqlite/损坏文件到查表才冒 "not a database";
/// 缺派生表冒 "no such table"。SQLite 这两句消息稳定, 集中匹配一次覆盖所有走 `.context` 的冷查路径)。
/// **exec 的用户 SQL 表/列错在其站点已构造 `CliError{BadRequest}` 短路**, 不会被误判成 NEEDS_INGEST。
pub fn classify_error(e: &anyhow::Error) -> native_core::ErrorCode {
    if let Some(c) = e.downcast_ref::<CliError>() {
        return c.code;
    }
    let chain = e
        .chain()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" | ");
    if chain.contains("not a database") {
        native_core::ErrorCode::BadRequest // 非 sqlite / 损坏 / 空文件指给 --l1-db = 用户给错输入
    } else if chain.contains("no such table") {
        native_core::ErrorCode::NeedsIngest // 库能开但缺某派生表 = 未 ingest
    } else if chain.contains("no such column") {
        native_core::ErrorCode::SchemaMismatch // 列漂移 = 旧/未迁移 schema (契约审 #8)
    } else {
        native_core::ErrorCode::Internal
    }
}
