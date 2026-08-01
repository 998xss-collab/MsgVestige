//! KeyScanError — 扫内存提 key 的错误分类 (ADR-428 §4 M3-a: 微信没跑 / 权限 / 版本 pattern 不匹配).
//!
//! 分类目的: 上层 (NativeCipher / cli) 据此决定**回退 sidecar** (KI-F/G/I 统一退路) 还是报用户处理.
//! K-R4: 任何字段不含明文 key; pid 不是秘密但仍只用于诊断.

/// 扫内存提 key 的失败原因. 每个变体对应一种处置 (回退 sidecar / 提示用户 / 换模式).
#[derive(Debug, thiserror::Error)]
pub enum KeyScanError {
    /// 找不到微信主进程 (Weixin.exe 未运行). 内存提 key 需微信在跑 (KI-G).
    /// 处置: 提示用户先登录微信, 或回退 sidecar 缓存 key.
    #[error("微信进程未运行 (找不到 Weixin.exe) — 内存提 key 需微信在跑")]
    WeixinNotRunning,

    /// 打开微信进程失败 (OpenProcess 返回 NULL) — 权限不足 / 被安全软件拦 (KI-I).
    /// 处置: 换管理员重试, 或回退 sidecar.
    #[error("打开微信进程失败 (pid={pid}) — 权限不足或被安全软件拦; 可换管理员或回退 sidecar")]
    AccessDenied {
        /// 目标进程 pid (诊断用, 非秘密).
        pid: u32,
    },

    /// 读 Weixin.dll 失败 (full 路) — 路径不对 / 文件缺.
    #[error("读 Weixin.dll 失败: {0}")]
    DllRead(String),

    /// dll 机器码 pattern 不匹配, 提不到 internal_db_key (full 路, KI-F 版本适配).
    /// 处置: 换 fast 路 (enc_key 跨版本最稳), 或回退 sidecar.
    #[error("Weixin.dll 版本 pattern 不匹配 (提不到 internal_db_key) — 微信版本可能不支持, 换 fast 或回退 sidecar")]
    VersionPatternMismatch,

    /// 验证锚点 db 首页读取失败 (文件缺 / 不足 4096B).
    #[error("验证锚点 db 读取失败: {0}")]
    AnchorDbRead(String),

    /// 扫完内存没验出 key:
    /// - fast 路: 内存里没有匹配锚点的 enc_key (微信没加载该库 / 未解锁登录);
    /// - full 路: 所有 raw_key 候选 × internal_db_key 无一过首页 HMAC (版本不符 / 账号未登录).
    ///
    /// 处置: full 路可兜 fast 漏的库; 都失败则回退 sidecar.
    #[error("扫完内存没验出 key (fast: 内存无对应 enc_key / full: 候选无一过 HMAC) — 微信可能未解锁登录, 或版本不符")]
    NoCandidateVerified,

    /// 非 Windows 平台调用扫描入口 (K-R7: 扫内存仅 Windows x64).
    #[error("不支持的平台 (内存扫描仅 Windows x64)")]
    UnsupportedPlatform,
}
