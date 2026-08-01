//! scan.rs — 顶层编排: 找进程 → 选路 → 扫 → 验 → 产出 (ADR-428 §4 M3-a 主入口).
//!
//! K-R4: 产出 [`KeyScanOutcome`] 出口只露 sha8 (KeyMaterial Debug 已脱敏); 本层不打印任何 key.

use std::path::{Path, PathBuf};

use crate::enckey::scan_enc_key;
use crate::error::KeyScanError;
use crate::key_material::{sha8, KeyMode, KeyScanOutcome};
use crate::passphrase::scan_passphrase;
use crate::sqlcipher::{PAGE, SQLCIPHER_ROUNDS_V4};
use crate::win::WeixinProcess;

/// 扫描参数. 最简: `ScanOptions::new(anchor_db)` = fast 模式 + 自动找进程 + v4 轮数.
pub struct ScanOptions {
    /// 提取模式: fast (扫 enc_key, 默认) / full (raw_key XOR dll → 派生).
    pub mode: KeyMode,
    /// 验证锚点 db — 该账号下任一加密库 (通常 account_entry_db), 取首页 4096B 验 key.
    pub anchor_db: PathBuf,
    /// 指定微信进程 pid; None = 自动枚举 Weixin.exe 取主进程 (内存最大).
    pub pid: Option<u32>,
    /// full 路 Weixin.dll 路径; None = 从进程已加载模块自动定位.
    pub dll_path: Option<PathBuf>,
    /// passphrase 派生轮数 (KI-F: v4=256000 / v3=64000); 默认 v4. 仅 full 路用.
    pub rounds: u32,
}

impl ScanOptions {
    /// 默认 fast 模式 + 自动找进程 + v4 轮数; 只需给锚点 db.
    #[must_use]
    pub fn new(anchor_db: impl Into<PathBuf>) -> Self {
        Self {
            mode: KeyMode::Fast,
            anchor_db: anchor_db.into(),
            pid: None,
            dll_path: None,
            rounds: SQLCIPHER_ROUNDS_V4,
        }
    }

    #[must_use]
    pub fn with_mode(mut self, mode: KeyMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub fn with_pid(mut self, pid: Option<u32>) -> Self {
        self.pid = pid;
        self
    }

    #[must_use]
    pub fn with_dll_path(mut self, dll_path: Option<PathBuf>) -> Self {
        self.dll_path = dll_path;
        self
    }

    #[must_use]
    pub fn with_rounds(mut self, rounds: u32) -> Self {
        self.rounds = rounds;
        self
    }
}

/// 主入口: 按 opts 扫内存提 key, 经首页 HMAC 校验后产出.
///
/// # Errors
/// 见 [`KeyScanError`] — 微信没跑 / 权限 / 版本 pattern 不匹配 / 没验出 / 锚点读取失败.
/// 任一失败上层据此回退 sidecar (KI-F/G/I 统一退路).
pub fn scan_key(opts: &ScanOptions) -> Result<KeyScanOutcome, KeyScanError> {
    let anchor_page = read_first_page(&opts.anchor_db)?;
    let proc = WeixinProcess::open(opts.pid)?;
    match opts.mode {
        KeyMode::Fast => {
            let enc = scan_enc_key(&proc, &anchor_page).ok_or(KeyScanError::NoCandidateVerified)?;
            // enc_key 是 per-db salt 派生 → 标注锚点库 salt 的 sha8 作有效 scope (codex F).
            let anchor_salt_sha8 = sha8(&anchor_page[..16]);
            Ok(KeyScanOutcome::from_enc_key(enc, anchor_salt_sha8))
        }
        KeyMode::Full => {
            let dll = resolve_dll_path(&proc, opts.dll_path.as_deref())?;
            let pass = scan_passphrase(&proc, &dll, &anchor_page, opts.rounds)?;
            Ok(KeyScanOutcome::from_passphrase(pass))
        }
    }
}

/// 读锚点 db 首页 4096B (只读首页, 不读整库).
///
/// K-R4: error 只放文件名 (如 message_0.db), **不放完整路径** — 锚点路径含 wxid 目录
/// (`...\wxid_xxx_abfe\...`), 全路径入 error 若被上层 log 即泄 wxid 明文.
fn read_first_page(db: &Path) -> Result<Vec<u8>, KeyScanError> {
    use std::io::Read;
    let name = db.file_name().and_then(|s| s.to_str()).unwrap_or("<anchor_db>");
    let mut f = std::fs::File::open(db).map_err(|e| KeyScanError::AnchorDbRead(format!("{name}: {e}")))?;
    let mut buf = vec![0u8; PAGE];
    f.read_exact(&mut buf)
        .map_err(|e| KeyScanError::AnchorDbRead(format!("{name} 不足 {PAGE}B: {e}")))?;
    Ok(buf)
}

/// full 路定位 Weixin.dll: opts 传了用传的, 否则从进程已加载模块找.
fn resolve_dll_path(proc: &WeixinProcess, given: Option<&Path>) -> Result<PathBuf, KeyScanError> {
    if let Some(p) = given {
        return Ok(p.to_path_buf());
    }
    proc.module_path("weixin.dll")
        .ok_or_else(|| KeyScanError::DllRead("进程未加载 Weixin.dll 且未传 dll_path".into()))
}
