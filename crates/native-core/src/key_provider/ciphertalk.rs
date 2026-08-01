//! ★★★ 测试安全性 ★★★
//! · kill_wechat_processes / launch_wechat 是 DESTRUCTIVE 操作
//! · 真调它们会动用户系统 (杀微信进程 / 启动微信)
//! · 凡涉及它们的单测必须 #[ignore], 仅 CI 干净环境或显式 --ignored 时跑
//! · 普通 cargo test 必须跳过这些测试
//!
//! CipherTalkProvider — vendor wx_key.dll FFI hook
//!
//! 详见 spec v3-key-source-spec.md §六
//!
//! 阶段 2：libloading + sysinfo + 60s 轮询完整实装
//!
//! 红线：
//!   - **K-R1** 一次性 hook，用户手动触发（ADR-028 R2）
//!   - **K-R6** Drop 必调 CleanupHook（防微信进程残留 shellcode）
//!   - **K-R7** x64 only

use super::error::KeyError;
use super::{sha8, KeyProvider, KeyProviderCapabilities, MasterKey, Wxid};

type Result<T> = std::result::Result<T, KeyError>;
use std::collections::HashMap;
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use libloading::{Library, Symbol};
use tokio::sync::Mutex as AsyncMutex;

// =====================================================================================
// HOOK_GUARD — 全局单例 Mutex（spec §6.4 红线：并发 resolve 不能同时进 hook）
//
// P1-C 修复：
//   - 之前 resolve() 没有任何全局保护，并发调用可同时进入 InitializeHook
//     → 同一进程双 hook，wx_key.dll 内部状态被踩乱（甚至残留 shellcode）。
//   - 现在用 tokio::sync::Mutex 串行化整个 hook session：
//       1) lock 必须跨 spawn_blocking 边界，因此用 tokio::sync::Mutex（不能用 std::sync::Mutex）
//       2) guard 持有期间覆盖：find_pid → confirm_callback → install → poll → CleanupHook
//       3) HookSession::Drop 会调 CleanupHook，所以 guard drop（_guard 出 resolve 作用域）
//          时 cleanup 已经跑完 —— 下一个并发 resolve 才能拿锁
//   - OnceLock 用 stdlib 自带（Rust 1.70+），不引入新依赖
// =====================================================================================
static HOOK_GUARD: OnceLock<AsyncMutex<()>> = OnceLock::new();

fn hook_guard() -> &'static AsyncMutex<()> {
    HOOK_GUARD.get_or_init(|| AsyncMutex::new(()))
}

// =====================================================================================
// SHUTDOWN_FLAG — 全局取消信号（postmortem P0-1：Ctrl-C 能优雅退 + 跑 cleanup）
//
// 设计动机：
//   - HookSession::poll_key 跑在 spawn_blocking 内是同步阻塞循环（每 100ms 一次 PollKeyData）。
//   - 如果用户按 Ctrl-C, 默认 tokio 行为是直接 kill 进程, dll 里 InitializeHook 安装的远线程 / patch
//     就残留在微信进程里 — 下次再 hook 同进程会拿到一个“脏”状态, 必失败。
//   - 解决：注册 Ctrl-C handler → `request_shutdown()` 翻 AtomicBool。轮询循环每次 tick 检查这个 flag,
//     翻了就立即 Err(ConsentDenied) 退出循环 (ADR-405 r3: alpha 收敛 UserCancelled→ConsentDenied,
//     KI-405-CANCEL out-of-band CancellationToken 推 0.2.0+)；HookSession::Drop 照常跑 CleanupHook 清 dll。
//
// 选 AtomicBool 而不是 tokio::sync::Notify 的原因：
//   - poll loop 在 spawn_blocking 同步线程上跑, 没法 await Notify; AtomicBool relaxed-load 廉价
//     (单条 mov), 100ms tick 一次根本不算开销。
//   - request_shutdown 从 tokio 异步 ctx 翻 flag → spawn_blocking 同步线程读 — 经典的跨线程信号
//     模式, AtomicBool 就是为这场景设计的。
//
// reset_shutdown() 仅供测试用 — 生产路径上 process lifetime 内 flag 只翻一次 (Ctrl-C 就准备退出),
// 不需要 reset; 但单元测试需要在 case 之间 reset, 否则一旦某 case 翻了 flag, 后续所有 case 都
// 看到 cancelled 状态污染。
// =====================================================================================
static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

/// 触发全局 shutdown — 由 v3-adapter Ctrl-C handler 调用
///
/// 调用后, 所有正在 poll_key 的循环会在下一次 tick (≤ poll_interval) 内退出, 返 ConsentDenied
/// (ADR-405 r3 收敛), HookSession::Drop 跟着跑 CleanupHook 把 dll 内部状态清干净。
///
/// 幂等：多次调用安全（Relaxed store 是无锁原子写）。
pub fn request_shutdown() {
    SHUTDOWN_FLAG.store(true, Ordering::Relaxed);
}

/// 当前是否已请求 shutdown — poll loop 用
fn shutdown_requested() -> bool {
    SHUTDOWN_FLAG.load(Ordering::Relaxed)
}

/// 仅测试用 — reset 全局 flag, 避免 case 间状态污染
#[cfg(test)]
fn reset_shutdown_for_test() {
    SHUTDOWN_FLAG.store(false, Ordering::Relaxed);
}

// =====================================================================================
// FFI 类型签名（来自 dllReport / hook_controller.h）
//
// 注意：底层 `bool` 通过 C ABI 视为 1 字节 `u8`（非零为 true）。
// 直接用 `bool` 在 Rust 端 *理论* 合法，但跨 dll 时 1-byte bool 的 ABI 隐含约束很微妙，
// 这里统一用 `u8` 包一层，由 Rust 侧判 `!= 0`，更稳。
// =====================================================================================

/// `bool InitializeHook(DWORD target_pid)`
pub type FnInitializeHook = unsafe extern "C" fn(target_pid: u32) -> u8;

/// `bool PollKeyData(char* key_buffer, int buffer_size)` — buf ≥ 65 字节，写入 64 hex + '\0'
pub type FnPollKeyData = unsafe extern "C" fn(key_buffer: *mut u8, buffer_size: i32) -> u8;

/// `bool GetStatusMessage(char* status_buffer, int buffer_size, int* out_level)`
/// out_level: 0=Info, 1=Success, 2=Error
pub type FnGetStatusMessage = unsafe extern "C" fn(status_buffer: *mut u8, buffer_size: i32, out_level: *mut i32) -> u8;

/// `bool CleanupHook()` — **退出前必调**（K-R6）
pub type FnCleanupHook = unsafe extern "C" fn() -> u8;

/// `const char* GetLastErrorMsg()` — DLL 内部静态字符串指针
pub type FnGetLastErrorMsg = unsafe extern "C" fn() -> *const i8;

/// 默认 dll 相对路径（vendor/wx_key/wx_key.dll）
pub const DEFAULT_DLL_PATH: &str = "vendor/wx_key/wx_key.dll";

/// 微信进程名（K-401.5 实证 4.x 是 Weixin.exe）
pub const DEFAULT_PROCESS_NAME: &str = "Weixin.exe";

/// 默认超时 60s（对齐 WCDA key_service.py）—
/// 仅保留给文档参考；运行时实际超时由 `CipherTalkProvider.hook_timeout_seconds` 决定
/// （默认 180s — 给用户更多时间触发微信操作，详见 `DEFAULT_HOOK_TIMEOUT_SECONDS`）。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// 默认 hook 超时秒数（demo 用户友好）—
/// 原 60s 太短 → 120s 仍然有用户来不及做注销重登 / 切账号操作就超时；
/// postmortem NH-1：实测发现注销 + 扫码登录平均要 90s+, 加上找手机扫码等开小差 = 120s 边缘超时高发。
/// 现在提到 180s 给充裕窗口。CLI 上 `--hook-timeout-seconds` 可覆盖。
pub const DEFAULT_HOOK_TIMEOUT_SECONDS: u64 = 180;

/// poll loop 内 heartbeat 间隔 — 每 N 毫秒打一次 "等待中..." 提示, 避免长时间静默
/// 让用户误以为程序卡死。postmortem NH-2 引入。
const HEARTBEAT_INTERVAL_MS: u128 = 10_000;

/// 默认轮询间隔 100ms
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// PollKeyData 的 buffer 大小（spec §六：buf ≥ 65 字节；多给点保险）
const POLL_BUF_SIZE: usize = 128;

/// GetStatusMessage 的 buffer 大小（够装一行日志）
const STATUS_BUF_SIZE: usize = 1024;

/// 用户确认 callback 类型 — 调用方注入, `resolve()` hook 前调用一次.
///
/// 入参 (按模式区分, r3 P1 #2 K-R1 enforcement):
/// - **模式 A** (`restart_wechat=false`): callback 在 `find_wechat_pid` 之后 / hook 前调用一次,
///   入参 `Some(pid)` 是真实发现的微信 PID; 找不到时 callback 不被调用 — 已先 terminal err 返出.
/// - **模式 B** (`restart_wechat=true`, 默认): callback 在 `kill_wechat` 之前调用一次, 入参 `None`
///   (还没 PID, 即将杀+启动微信); callback 返 false → `ConsentDenied` 早退不动微信.
///   拿到新 PID 后**不再**第二次 prompt (一次同意全程).
///
/// 返回: `true` 同意 hook, `false` → `KeyError::ConsentDenied`.
///
/// 红线 K-R1 / ADR-028 R2: cache miss 才能触发, cache hit 时永不该走到 callback.
/// 红线 K-R1 enforcement (r3): 模式 B 必须显式注入 callback (`is_some()`), 否则 `resolve()` 直接
/// 早退 `ConsentDenied` — 防 adapter 忘传 callback 静默杀用户微信.
pub type ConfirmCallback = dyn Fn(Option<u32>) -> bool + Send + Sync;

/// 用户提示通道 — 把 ciphertalk hook 流程的用户可见提示 (扫码登录指引 / 倒计时 / 超时诊断)
/// 从硬编码 `println!` 解耦, 让上层注入去向.
///
/// PR2-1-e (PR2-1-c r1 review P1 #5): lib crate 直接 `println!` 抢 stdout, 上层 CLI / HTTP /
/// adapter 都吃这个 channel → 库不该擅自占用. 改为:
///   - 默认 `StdoutNotifier` 保留 CLI 现状 (println + flush), 不破坏现有命令行体验
///   - adapter 走 `with_notifier` 注入 (HTTP → SSE / GUI → 弹窗 / 测试 → buffer)
///
/// alpha ciphertalk-local; 0.2.0+ 若 cli/其它 provider 也要 prompt, 提到共享模块 + ADR-405 §3.1.
pub trait UserNotifier: Send + Sync {
    /// 输出一段用户可见提示 (可含多行 `\n`). 实现决定去向 + 是否 flush.
    ///
    /// ⚠️ 契约 (PR2-1-e r1 Claude review P2): impl **不应 panic** — 倒计时心跳在
    /// `spawn_blocking` 内调用本方法, workspace `panic = "abort"` (防 K-R4 解栈泄 master_key)
    /// 下 panic 会**整进程退出**, 不是局部错误. adapter 实现应内部吞掉 IO 错误 (如 SSE 断连)
    /// 而非 panic/unwrap.
    fn notify(&self, msg: &str);
}

/// 默认 `UserNotifier` — `println!` 到 stdout + flush (保留 CLI 现状).
pub struct StdoutNotifier;

impl UserNotifier for StdoutNotifier {
    fn notify(&self, msg: &str) {
        println!("{msg}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

/// CipherTalkProvider — 一次性 hook，用户手动触发（K-R1）
pub struct CipherTalkProvider {
    pub dll_path: PathBuf,
    pub process_name: String,
    /// hook 超时秒数（默认 `DEFAULT_HOOK_TIMEOUT_SECONDS` = 120s）—
    /// 用户在该时间窗内必须做一次微信操作（开聊天 / 发消息 / 切会话）
    /// 触发 SQLCipher 解密让 wx_key.dll 能捕到 master key。
    /// 通过 `with_hook_timeout(secs)` 覆盖。
    pub hook_timeout_seconds: u64,
    pub poll_interval: Duration,
    /// 用户确认 callback — `resolve()` hook 前先调一次, 返 false → `KeyError::ConsentDenied`.
    ///
    /// r3 P1 #2 (K-R1 enforcement) 分支语义按模式区分:
    /// - **模式 A** (`restart_wechat == false`):
    ///   - `None`: 不 prompt (adapter 自己提前 prompt 兼容老链路) — 直接 hook 已在跑的微信.
    ///   - `Some`: `resolve()` 拿到 PID 后 / hook 前调 callback(Some(pid)); false → ConsentDenied.
    /// - **模式 B** (`restart_wechat == true`, 默认):
    ///   - `None`: **直接 `ConsentDenied` 早退** — K-R1 不允许静默 kill 用户微信进程,
    ///     adapter 必须显式注入 callback. (r3 改 PoC-1 "兼容" 假设, 改硬约束).
    ///   - `Some`: kill 前调 callback(None); false → ConsentDenied 不动微信. 拿到新 PID 后**不再**
    ///     第二次 prompt (一次同意全程).
    ///
    /// 设计目的 (P0-2b): prompt 从"构 chain 时"推迟到"真要 hook 时", cache-first 语义 (cache hit
    /// 时绝不打扰用户).
    ///
    /// `Arc` 包是为了 `tokio::spawn_blocking` 闭包内 clone 走 (callback 可能阻塞读 stdin).
    pub confirm_callback: Option<Arc<ConfirmCallback>>,
    /// 用户通过 CLI `--wechat-pid` 强制指定的微信主进程 PID。
    ///
    /// `None`（默认）：走 `find_wechat_pid` sysinfo 自动发现（多进程时按 memory 最大）。
    /// `Some(pid)`：跳过自动发现，直接拿这个 PID hook —— 用于 memory 启发式选错时的兜底。
    ///
    /// 详见 `find_or_use_wechat_pid`。
    pub wechat_pid_override: Option<u32>,

    /// `--restart-wechat` 模式开关。
    ///
    /// `true`（**默认**）：模式 B — 在 `resolve()` 入口先杀掉所有 Weixin.exe / WeChat.exe，
    ///        再启动 Weixin.exe，新进程冷启动一定会 setKey，hook 命中率 100%。用户只需扫码登录。
    /// `false`：模式 A — hook 当前已在跑的 Weixin.exe，靠用户手动注销/重登触发 SQLCipher 解密。
    ///        仅作为“用户坚持不动微信”的可选 fallback。
    ///
    /// 决策（2026-06）：实测发现 wx_key.dll 必须微信【重新 open db】才能 hook 到 key。
    /// 模式 A（手动重登）和模式 B（自动杀+启）本质都是“重新登录”，B 用户体验更好（程序代劳，
    /// 用户只管扫码），所以改为默认。
    ///
    /// 配套字段：`wechat_exe_path`（默认走 `detect_wechat_exe` 自动探测）。
    pub restart_wechat: bool,

    /// `--restart-wechat` 模式下用的 Weixin.exe 路径（绝对路径）。
    ///
    /// `None`（默认）：`resolve()` 内部走 `detect_wechat_exe()` 自动探测候选目录。
    /// `Some(path)`：用户显式钉死路径（用于安装位置非标准时的兜底）。
    ///
    /// 仅当 `restart_wechat == true` 时被读取；模式 A 完全忽略此字段。
    pub wechat_exe_path: Option<PathBuf>,

    /// PR2-1-e: 用户提示通道 (扫码指引 / 倒计时 / 超时诊断). 默认 `StdoutNotifier` (CLI 现状),
    /// adapter 走 `with_notifier` 注入. `Arc<dyn>` 为了 clone 进 `spawn_blocking` 跨线程.
    notifier: Arc<dyn UserNotifier>,
}

// r3 P0 #3: 删 impl Drop for CipherTalkProvider
//   - r2 加的 Drop 写 SHUTDOWN_FLAG=true 是进程级污染:
//     14+ 单测 `let s = CipherTalkProvider::default()` 函数返回时 Drop → 设 flag → 后续测的
//     shutdown_flag_round_trip / reset_shutdown_for_test 被污染, cargo test 多线程并行 flaky.
//     生产侧 chained provider drop 后让其他在跑的 hook session 收到误取消信号.
//   - K-R6 真正的 owner 一直是 `HookSession::Drop` (resolve() 局部 var, RAII guard);
//     codex r1 P0 #2 抓到 "Provider 自身无 Drop" 是脆弱信号, 但 r2 修法引入更大坏处 — 退回 noop.
//   - 若 K-R6 防御深度真需要 Provider 层 cleanup, 等 PR2-1-d 改 instance-level Arc<AtomicBool>
//     + 把 WxKeyLib 提升到 Provider 字段 + impl Drop 真调 vendor CleanupHook (codex r1 P0 #2
//     第二种修法), 不动全局 flag.

impl CipherTalkProvider {
    pub fn new(dll_path: Option<PathBuf>) -> Self {
        Self {
            dll_path: dll_path.unwrap_or_else(|| PathBuf::from(DEFAULT_DLL_PATH)),
            process_name: DEFAULT_PROCESS_NAME.to_string(),
            hook_timeout_seconds: DEFAULT_HOOK_TIMEOUT_SECONDS,
            poll_interval: DEFAULT_POLL_INTERVAL,
            confirm_callback: None,
            wechat_pid_override: None,
            // 2026-06 决策：默认 B 模式（自动杀+启微信）。实测发现 wx_key.dll 必须微信
            // 【重新 open db】才能 hook 到 key — A 模式让用户手动“注销重登”、B 模式程序代劳
            // 杀+启，本质都是“重新登录”，B 用户只需扫码 → 体验更好，应当默认。
            // A 模式仅作为“用户坚持不动微信”的可选 fallback（CLI 上 --hook-mode hold）。
            restart_wechat: true,
            wechat_exe_path: None,
            // PR2-1-e: 默认 stdout (CLI 现状). adapter 走 with_notifier 注入.
            notifier: Arc::new(StdoutNotifier),
        }
    }

    /// builder: 注入用户提示通道 (PR2-1-e). 默认 `StdoutNotifier` (println);
    /// adapter 传自定义实现把扫码指引 / 倒计时 / 超时诊断路由到 HTTP SSE / GUI / 测试 buffer.
    #[must_use]
    pub fn with_notifier(mut self, notifier: Arc<dyn UserNotifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// builder：覆盖 hook 超时秒数（默认 120s）
    ///
    /// demo 场景常见诉求：用户来不及触发微信操作就超时 — 调大这个值给更充裕窗口。
    /// CLI 上对应 `--hook-timeout-seconds <N>`。
    pub fn with_hook_timeout(mut self, secs: u64) -> Self {
        self.hook_timeout_seconds = secs;
        self
    }

    /// builder：注入 CLI `--wechat-pid` override
    ///
    /// 当 memory 启发式选错主进程时（极端用例），允许用户手动钉死 PID。
    /// `None` 等价于不设 — 走自动发现。
    pub fn with_wechat_pid_override(mut self, pid: Option<u32>) -> Self {
        self.wechat_pid_override = pid;
        self
    }

    /// builder: 注入用户确认 callback ([ADR-028 R2] / P0-2b / K-R1 enforcement).
    ///
    /// 调用时机按模式区分 (详见 `ConfirmCallback` 类型 doc):
    /// - 模式 A: `find_wechat_pid()` 之后 / `InitializeHook` 之前 一次, 入参 Some(pid).
    /// - 模式 B: `kill_wechat()` 之前 一次, 入参 None (kill 前 consent-first 红线).
    ///
    /// r3 P1 #2: 模式 B 不传 callback 等价于 ConsentDenied 早退 — 必须显式注入.
    pub fn with_confirm_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(Option<u32>) -> bool + Send + Sync + 'static,
    {
        self.confirm_callback = Some(Arc::new(callback));
        self
    }

    /// builder：开启 / 关闭 `--restart-wechat` 模式（杀微信 + 重新启动）
    ///
    /// **默认 `true`（模式 B）**：`resolve()` 会先杀掉所有 Weixin.exe / WeChat.exe 再启动
    /// 新的 Weixin.exe — 新进程冷启动一定会 setKey，hook 100% 命中。用户只需扫码登录。
    ///
    /// 显式传 `false`（模式 A）：保留用户当前微信窗口，等用户手动注销重登触发 setKey。
    /// 仅作为“坚持不动微信”的可选 fallback。
    pub fn with_restart_wechat(mut self, restart: bool) -> Self {
        self.restart_wechat = restart;
        self
    }

    /// builder：钉死 Weixin.exe 路径（仅 `restart_wechat == true` 时被使用）
    ///
    /// `None`：走 `detect_wechat_exe()` 自动探测（覆盖 Program Files / Program Files (x86)）。
    /// `Some(path)`：用户显式钉死路径，绕过探测 — 用于非标准安装目录。
    pub fn with_wechat_exe(mut self, exe: Option<PathBuf>) -> Self {
        self.wechat_exe_path = exe;
        self
    }
}

impl Default for CipherTalkProvider {
    fn default() -> Self {
        Self::new(None)
    }
}

#[async_trait]
impl KeyProvider for CipherTalkProvider {
    async fn resolve_all(&self) -> Result<HashMap<Wxid, MasterKey>> {
        // ciphertalk 只能取当前登录账号 — 不支持枚举
        Err(KeyError::Unsupported {
            name: "ciphertalk",
            op: "resolve_all",
        }
        .into())
    }

    async fn resolve(&self, wxid: &Wxid) -> Result<MasterKey> {
        // P0-2b：先找 PID（不 hook 也不 prompt） → 再调 callback 让用户确认 → 才 hook
        //   这样 cache hit 时永不会走到这里，cache miss 才弹 prompt（cache-first 不破）。
        //
        // P1-C：全程持有 HOOK_GUARD（tokio AsyncMutex），保证 spec §6.4 单例红线 —
        //   并发 resolve() 会串行化进入下面 find_pid → confirm → install → poll → cleanup。
        //   _guard 在函数返回时 drop，此时 HookSession::Drop 已跑完 CleanupHook，
        //   下一个等锁的 resolve 才会拿到 guard。
        let _guard = hook_guard().lock().await;

        let dll_path = self.dll_path.clone();
        let process_name = self.process_name.clone();
        let hook_timeout_seconds = self.hook_timeout_seconds;
        let timeout = Duration::from_secs(hook_timeout_seconds);
        let poll_interval = self.poll_interval;
        let pid_override = self.wechat_pid_override;
        let wxid_sha = sha8(wxid.as_str().as_bytes());

        // 1) 找 / 重启 微信 PID
        //    模式 A（默认）：sysinfo 找已在跑的 Weixin.exe（多进程时 memory 最大者）；--wechat-pid 可 override。
        //    模式 B（--restart-wechat）：先杀全部 Weixin.exe/WeChat.exe，再启动新的 — 冷启动 100% 触发 setKey。
        //
        // r2 P0 #1 (consent-first / ADR-028 R2 / K-R1) — 模式 B 必须先拿 consent 再动手:
        //   PoC-1 原流程: kill_wechat → launch_wechat → confirm_callback
        //   r2 修订流程:   confirm_callback(None) → kill_wechat → launch_wechat → (跳过模式 A 二次 callback)
        //   理由: kill/launch 是破坏性动作 (杀用户进程 = 影响用户工作); callback 拒绝必须在动手前.
        //   callback 拿 None 表示 "还没找到 PID, 即将走模式 B kill+launch, 是否同意".
        let pre_kill_consent_given = if self.restart_wechat {
            // r3 P1 #2: 模式 B 强制要求 confirm_callback (K-R1 不可漏)
            //   PoC-1 注释假设 "adapter 自己保证 prompt", 但运行时无 enforcement → adapter
            //   忘传 callback 直接 kill 用户微信. r3 改硬约束: 无 callback → 早退 ConsentDenied.
            let Some(cb) = &self.confirm_callback else {
                tracing::warn!(
                    wxid_sha = %wxid_sha,
                    mode = "B-pre-kill",
                    "ciphertalk: restart_wechat=true 但无 confirm_callback — K-R1 不允许静默杀进程"
                );
                return Err(KeyError::ConsentDenied.into());
            };
            let cb_cloned = Arc::clone(cb);
            let ok = tokio::task::spawn_blocking(move || cb_cloned(None))
                .await
                .map_err(|e| {
                    tracing::warn!(stage = "pre_kill_consent", error = %e, "spawn_blocking join 失败");
                    KeyError::dpapi_unavailable(b"join_err")
                })?;
            if !ok {
                tracing::info!(
                    wxid_sha = %wxid_sha,
                    mode = "B-pre-kill",
                    "ciphertalk: 用户在 kill 前 confirm_callback 拒绝, 不动微信"
                );
                return Err(KeyError::ConsentDenied.into());
            }
            true
        } else {
            false
        };

        let pid = if self.restart_wechat {
            // 模式 B —— 杀 + 启动 (consent 已拿)
            let exe = match self.wechat_exe_path.clone() {
                Some(p) => p,
                None => {
                    let detected = tokio::task::spawn_blocking(detect_wechat_exe).await.map_err(|e| {
                        tracing::warn!(stage = "detect_wechat_exe", error = %e, "spawn_blocking join 失败");
                        KeyError::dpapi_unavailable(b"join_err")
                    })?;
                    detected?
                }
            };

            // PR2-1-e: 走 notifier (原硬编码 println! 抢 stdout)
            self.notifier.notify(&format!(
                "\n✋ --restart-wechat 模式: 杀微信进程 + 重新启动\n✋ Weixin.exe 路径: {}",
                exe.display()
            ));

            let killed = tokio::task::spawn_blocking(kill_wechat_processes).await.map_err(|e| {
                tracing::warn!(stage = "kill_wechat", error = %e, "spawn_blocking join 失败");
                KeyError::dpapi_unavailable(b"join_err")
            })??;
            tracing::info!(killed_count = killed, "killed wechat processes");

            let exe_for_launch = exe.clone();
            let new_pid = tokio::task::spawn_blocking(move || launch_wechat(&exe_for_launch))
                .await
                .map_err(|e| {
                    tracing::warn!(stage = "launch_wechat", error = %e, "spawn_blocking join 失败");
                    KeyError::dpapi_unavailable(b"join_err")
                })??;
            tracing::info!(new_pid = new_pid, "wechat relaunched");

            // PR2-1-e: 走 notifier
            self.notifier.notify(&format!(
                "\n✋ 微信已重启 (PID {new_pid}), 等待 {hook_timeout_seconds} 秒\n\
                 ✋ 请在新弹出的微信窗口扫码登录, 系统会自动捕获 key\n"
            ));

            new_pid
        } else {
            // 模式 A —— 找已在跑的（现有逻辑）
            let process_name = process_name.clone();
            tokio::task::spawn_blocking(move || find_or_use_wechat_pid(&process_name, pid_override))
                .await
                .map_err(|e| {
                    tracing::warn!(stage = "find_wechat_pid", error = %e, "spawn_blocking join 失败");
                    KeyError::dpapi_unavailable(b"join_err")
                })??
        };

        // 2) 用户确认（[ADR-028 R2] / K-R1）— callback 没设就直接放行（兼容旧链路）
        //
        // r2 P0 #1: 模式 B 已经在 step 1 之前 (kill 之前) 拿到 consent_given=true, 跳过二次问.
        //           模式 A 没破坏性动作, 此处保持原 PoC-1 流程 (拿到 PID 之后 / hook 之前 confirm).
        if !pre_kill_consent_given {
            if let Some(cb) = &self.confirm_callback {
                // callback 自身可能阻塞读 stdin，丢到 spawn_blocking；Arc clone 廉价
                let cb_cloned = Arc::clone(cb);
                let ok = tokio::task::spawn_blocking(move || cb_cloned(Some(pid)))
                    .await
                    .map_err(|e| {
                        tracing::warn!(stage = "confirm_callback", error = %e, "spawn_blocking join 失败");
                        KeyError::dpapi_unavailable(b"join_err")
                    })?;
                if !ok {
                    tracing::info!(
                        wxid_sha = %wxid_sha,
                        pid = pid,
                        "ciphertalk: 用户在 confirm_callback 中拒绝 hook"
                    );
                    return Err(KeyError::ConsentDenied.into());
                }
            }
        }

        // 3) 用户提示：hook 已确认，即将安装并等候用户触发微信【重新打开 db】
        //
        //    P0-3 / restart-wechat 文案修订：
        //      早期文案让用户“打开聊天 / 发消息 / 切会话” —— 实证错的：
        //      微信启动后 db 已经 open，SQLCipher setKey 只在 *第一次* open 时被调用，
        //      之后无论怎么浏览 / 收发都不会再触发。所以用户照旧操作必然超时。
        //
        //      正确触发路径只有 “重新 open db” —— 即让微信走完整 cold-open 流程：
        //        ✓ 注销当前账号 → 重新扫码登录（100% 触发，最简单）
        //        ✓ 切到另一个账号（如有多账号；新账号 open 自己的 db）
        //        ✓ 重启微信（100% 触发，但要手动启）
        //
        //      接受“杀+启”的用户可以走 --restart-wechat 模式 B，全自动。
        //    PR2-1-e: 用户提示走 self.notifier (默认 stdout, adapter 可注入), 不依赖 RUST_LOG.
        let real_pid = pid;
        tracing::info!(
            wxid_sha = %wxid_sha,
            pid = real_pid,
            timeout_seconds = hook_timeout_seconds,
            "Hook 已确认 / 即将安装. 请在 {} 秒内触发微信【重新打开 db】(注销重登 / 切换账号 / 重启微信)",
            hook_timeout_seconds
        );
        // postmortem P0-4 + 2026-06 重构：按当前模式分场景显示提示。
        //   - 模式 B（restart_wechat=true，默认）：微信已被本程序杀+启，用户只管扫码 → 简洁提示。
        //   - 模式 A（restart_wechat=false）：保留原“必须重新 open db”教育文案 + ❌ 无效操作对比。
        // PR2-1-e: 整块 banner 走 notifier (原逐行 println! 抢 stdout). 中段按模式分支.
        let mid = if self.restart_wechat {
            // 模式 B：杀+启已完成，新窗口就是要用户扫码登录的那个
            "✋\n\
             ✋ 🚀 模式 B (默认): 微信已被自动杀+重启\n\
             ✋ ✅ 请在新弹出的微信窗口扫码登录, 系统会自动捕获 key\n\
             ✋\n\
             ✋ 💡 如果要保留当前微信不杀, 重跑加 --hook-mode hold\n\
             ✋ 💡 中途按 Ctrl-C 可安全退出 (会自动 cleanup hook)"
        } else {
            // 模式 A：保留原教育文案（用户必须手动让微信 reopen db）
            "✋\n\
             ✋ 🚨 必须让微信【重新打开数据库】才能取到 key:\n\
             ✋\n\
             ✋   ✅ 注销当前微信账号 → 重新扫码登录\n\
             ✋     · 点微信【我】→【设置】→【退出登录】→ 扫码重登\n\
             ✋     · 100% 触发, 最稳\n\
             ✋\n\
             ✋   ✅ 或: 切换微信账号 (多账号时)\n\
             ✋   ✅ 或: 完全重启微信 (杀掉再启动)\n\
             ✋\n\
             ✋ ❌ 以下操作【无效】(微信不会 reopen db):\n\
             ✋   · 浏览聊天 / 发消息 / 切聊天会话\n\
             ✋   · 切换通讯录 / 朋友圈\n\
             ✋   · 微信开着不动\n\
             ✋\n\
             ✋ 💡 如果接受杀微信自动重启, 重跑不加 --hook-mode hold (默认 B 模式)\n\
             ✋ 💡 中途按 Ctrl-C 可安全退出 (会自动 cleanup hook)"
        };
        self.notifier.notify(&format!(
            "\n✋ ===================================================\n\
             ✋ Hook 已安装到微信进程 (PID {real_pid})\n\
             ✋ ⏱️  等待时间: {hook_timeout_seconds} 秒, 倒计时启动\n\
             {mid}\n\
             ✋ ===================================================\n"
        ));

        // 4) 走完整 hook 流程
        //
        // r3 P0 #1: 用 hook_start 时间 + elapsed 判超时, 不再依赖 KeyError 变体区分
        //           (r2 P0 #4 把 NotFound 假占位 → DpapiUnavailable terminal 后, wxid 字段被 sha8
        //           不可逆识别 — 改成 elapsed 判超时更准更直接).
        let hook_start = std::time::Instant::now();
        // PR2-1-e: clone notifier Arc move 进 spawn_blocking — poll_key 倒计时心跳走它.
        let notifier_for_hook = Arc::clone(&self.notifier);
        let key_hex = tokio::task::spawn_blocking(move || -> Result<MasterKey> {
            run_hook_session_with_pid(&dll_path, pid, timeout, poll_interval, &*notifier_for_hook)
        })
        .await
        .map_err(|e| {
            tracing::warn!(stage = "run_hook_session", error = %e, "spawn_blocking join 失败");
            KeyError::dpapi_unavailable(b"join_err")
        })?;
        let hook_elapsed = hook_start.elapsed();

        // 5) hook 超时 / 用户取消分支：给出更友好的诊断信息
        let key_hex = match key_hex {
            Ok(k) => k,
            Err(e) => {
                // r3 P0 #1: elapsed >= 90% timeout 视为 hook 超时 (留 10% 余量给上下文切换).
                // ConsentDenied 优先识别 (Ctrl-C 路径).
                if matches!(&e, KeyError::ConsentDenied) {
                    tracing::info!(
                        wxid_sha = %wxid_sha,
                        pid = real_pid,
                        "ciphertalk: 用户 Ctrl-C 取消, hook 已 cleanup"
                    );
                } else if hook_elapsed.as_secs_f64() >= 0.9 * (timeout.as_secs_f64()) {
                    // hook 超时 — 打用户诊断 (恢复 r1 review 关键 UX)
                    print_hook_timeout_diagnostic(&*self.notifier, self.restart_wechat);
                }
                return Err(e);
            }
        };

        // K-R4：log 只打 wxid_sha 和 key 长度，永不打明文 key
        tracing::info!(
            wxid_sha = %wxid_sha,
            key_len = 64u32,
            "ciphertalk: master key resolved"
        );
        Ok(key_hex)
    }

    fn name(&self) -> &'static str {
        "ciphertalk"
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            can_resolve_all: false,
            needs_user_consent: true, // K-R1
            persists_to_disk: false,
        }
    }
}

// =====================================================================================
// 同步 hook 流程（在 spawn_blocking 里跑）
// =====================================================================================

/// 执行一次完整的 hook 流程（PID 由调用方先发现）：
/// 加载 dll → InitializeHook(pid) → 轮询 → CleanupHook
///
/// 全程同步，由调用方 wrap 进 spawn_blocking。
///
/// P0-2b：从 `run_hook_session` 抽出 — PID 发现移到 `resolve()` 顶部，
/// 这样 confirm_callback 可以拿到真实 PID 给用户看（而不是“PID 12345”假占位）。
/// r3 P0 #1: 救回 r1 review 关键 UX — hook 超时诊断, 由 resolve() 用 elapsed 判断后调用.
/// 不依赖 KeyError 区分变体 (r2 P0 #4 改 NotFound→DpapiUnavailable 后 wxid 字段 sha8 不可逆).
// PR2-1-e: 走 notifier (原硬编码 println!). &dyn 借用即可 (resolve() 内同步调, 不跨线程).
fn print_hook_timeout_diagnostic(notifier: &dyn UserNotifier, restart_wechat: bool) {
    let body = if restart_wechat {
        "可能原因 (模式 B 默认, 自动杀+启):\n\
         \x20 1. 微信被杀+启后, 你没在新窗口完成扫码登录\n\
         \x20    ★ 必须扫码登录才会触发 setKey ★\n\
         \x20 2. 微信启动后窗口还没出现就到了超时\n\
         \x20    → 重跑加 --hook-timeout-seconds <N> 拉长等待 (默认 180s)\n\
         \x20 3. 微信 exe 路径不对 → 重跑加 --wechat-exe-path <path>\n\
         \x20 4. 多 Weixin.exe 子进程时选错 → 重跑加 --wechat-pid <PID>"
    } else {
        "可能原因 (模式 A, 用户手动重登):\n\
         \x20 1. 你没让微信【重新打开 db】(注销重登 / 切账号 / 重启微信)\n\
         \x20    ★ 仅“开聊天 / 发消息”不会触发 ★\n\
         \x20 2. 重跑时务必走【注销 → 重登】这条 100% 路径\n\
         \x20 3. 或者重跑去掉 --hook-mode hold, 让程序自动杀+启 (默认 B 模式)\n\
         \x20 4. 还可 --wechat-pid <PID> 手动指定 + --hook-timeout-seconds <N> 加时间"
    };
    notifier.notify(&format!("\n⏱️  hook 超时: 未捕获到 key\n\n{body}\n"));
}

fn run_hook_session_with_pid(
    dll_path: &Path,
    pid: u32,
    timeout: Duration,
    poll_interval: Duration,
    notifier: &dyn UserNotifier,
) -> Result<MasterKey> {
    // 1. 加载 dll（先按配置路径，失败回退到当前目录、可执行同目录）
    let lib = WxKeyLib::load(dll_path)?;
    tracing::debug!(pid, "ciphertalk: 开始 hook 微信进程");

    // 2. 安装 hook（带 1 次重试 — 见 install_with_retry 兜底 cleanup 语义）
    let mut session = install_with_retry(&lib, pid)?;

    // 3. 轮询 key（带 timeout + Ctrl-C 取消, PR2-1-e: 倒计时心跳走 notifier）
    let key_hex = session.poll_key(timeout, poll_interval, notifier)?;

    // 4. session drop → CleanupHook 自动调用（K-R6）
    drop(session);

    // 5. 把 hex 字符串 normalize（小写 + 校验 64 char hex）
    validate_master_key_hex(&key_hex)?;
    MasterKey::from_hex(&key_hex)
}

/// 带 retry + 失败兜底 cleanup 的 install 包装（postmortem P0-2）
///
/// 老实现只在“第一次失败 → cleanup → 重试”这条路径上调 cleanup; 但如果【第二次
/// 也失败】, dll 内部仍可能残留脏状态 (脏内存 patch / 远线程没回收), 接下来同进程
/// 再 install 必碎; 本进程退出时 OS 也只清自己的内存, 微信进程里那份 shellcode 仍
/// 在跑。
///
/// 修复：任何一次 install 失败前后都先调一次 cleanup_hook() 兜底, 把 dll 内部
/// 状态强制清零；retry 仍然只一次, 但 cleanup 路径不漏掉第二次。
fn install_with_retry(lib: &WxKeyLib, pid: u32) -> Result<HookSession<'_>> {
    match HookSession::install(lib, pid) {
        Ok(s) => Ok(s),
        Err(first_err) => {
            tracing::warn!(
                error = %first_err,
                "ciphertalk: hook 安装失败 (第一次), 兜底 cleanup 后重试"
            );
            // 第一次失败 → 先 cleanup 把 dll 内部脏状态清掉
            let _ = lib.cleanup_hook();

            match HookSession::install(lib, pid) {
                Ok(s) => Ok(s),
                Err(second_err) => {
                    // 第二次仍失败 → 再 cleanup 一次再 bubble; 不能让脏 hook 残留
                    tracing::error!(
                        first_err = %first_err,
                        second_err = %second_err,
                        "ciphertalk: hook 安装失败 (第二次, 已尽力 cleanup), 放弃"
                    );
                    let _ = lib.cleanup_hook();
                    Err(second_err)
                }
            }
        }
    }
}

/// 老接口：完整流程（找 PID + hook）— 保留给 integration test 和直接用 dll 的调用方
#[allow(dead_code)]
fn run_hook_session(
    dll_path: &Path,
    process_name: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<MasterKey> {
    let pid = find_wechat_pid(process_name)?;
    tracing::debug!(pid, process = %process_name, "ciphertalk: 找到微信进程");
    // PR2-1-e: 死代码老接口 (integration test 留), 用默认 StdoutNotifier 保持编译.
    run_hook_session_with_pid(dll_path, pid, timeout, poll_interval, &StdoutNotifier)
}

/// 校验 64 char hex（lower/upper 都收，但要全 hex digit）
fn validate_master_key_hex(s: &str) -> Result<()> {
    // r2 P1 #4: 走工厂方法 algorithm_mismatch (take(32) 截断 + alpha contract 强制)
    if s.len() != 64 {
        return Err(KeyError::algorithm_mismatch(format!(
            "master_key len {} (expected 64)",
            s.len()
        )));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeyError::algorithm_mismatch("master_key non-hex"));
    }
    Ok(())
}

// =====================================================================================
// WxKeyLib — libloading::Library wrapper，加载即抽出 5 个符号指针
// =====================================================================================

/// 持有 dll handle + 5 个导出函数符号
///
/// 注意：符号本质是函数指针，生命周期绑在 lib 上。这里把 `Symbol<'_>` deref
/// 出 `unsafe extern "C" fn(...)` 函数指针存进结构体，函数指针自身没有生命周期
/// 但只在 dll 加载期间有效；通过把 `Library` 放结构体最后一个字段、依赖 Rust
/// 字段按声明倒序 drop 的规则，保证函数指针使用期间 dll 始终在内存里。
pub struct WxKeyLib {
    initialize_hook: unsafe extern "C" fn(u32) -> u8,
    poll_key_data: unsafe extern "C" fn(*mut u8, i32) -> u8,
    get_status_message: unsafe extern "C" fn(*mut u8, i32, *mut i32) -> u8,
    cleanup_hook: unsafe extern "C" fn() -> u8,
    get_last_error_msg: unsafe extern "C" fn() -> *const i8,
    // lib 必须放最后 — Rust 字段是按声明顺序 drop，最后释放 lib 保证前面的函数指针有效
    _lib: Library,
}

impl WxKeyLib {
    /// 加载 dll：先按用户传入路径，失败时按 vendor/wx_key/wx_key.dll、
    /// ./wx_key.dll、可执行同目录 wx_key.dll 这一串候选回退。
    pub fn load(path: &Path) -> Result<Self> {
        let candidates = build_candidate_paths(path);
        let mut last_err: Option<libloading::Error> = None;

        for candidate in &candidates {
            match unsafe { Library::new(candidate) } {
                Ok(lib) => {
                    tracing::debug!(path = %candidate.display(), "ciphertalk: wx_key.dll 加载成功"); // log-safe: DLL 安装路径, 无 wxid/用户数据
                    return Self::resolve_symbols(lib).map_err(|_e| KeyError::dpapi_unavailable(b"dll_load"));
                }
                Err(e) => {
                    tracing::trace!(
                        path = %candidate.display(), // log-safe: candidate DLL 路径, 无 wxid/聊天数据
                        error = %e,
                        "ciphertalk: candidate 加载失败，尝试下一个"
                    );
                    last_err = Some(e);
                }
            }
        }

        let _ = last_err;
        Err(KeyError::dpapi_unavailable(b"dll_load"))
    }

    fn resolve_symbols(lib: Library) -> std::result::Result<Self, libloading::Error> {
        // SAFETY: 5 个符号的 ABI 已 dllReport 核对（cdecl），lib 在结构体里活到最后
        unsafe {
            let initialize_hook: Symbol<FnInitializeHook> = lib.get(b"InitializeHook\0")?;
            let poll_key_data: Symbol<FnPollKeyData> = lib.get(b"PollKeyData\0")?;
            let get_status_message: Symbol<FnGetStatusMessage> = lib.get(b"GetStatusMessage\0")?;
            let cleanup_hook: Symbol<FnCleanupHook> = lib.get(b"CleanupHook\0")?;
            let get_last_error_msg: Symbol<FnGetLastErrorMsg> = lib.get(b"GetLastErrorMsg\0")?;

            Ok(WxKeyLib {
                initialize_hook: *initialize_hook,
                poll_key_data: *poll_key_data,
                get_status_message: *get_status_message,
                cleanup_hook: *cleanup_hook,
                get_last_error_msg: *get_last_error_msg,
                _lib: lib,
            })
        }
    }

    /// 安装 hook（同步阻塞）
    pub fn initialize_hook(&self, pid: u32) -> bool {
        // SAFETY: 函数指针来自加载的 dll，签名与 dllReport 一致
        unsafe { (self.initialize_hook)(pid) != 0 }
    }

    /// 非阻塞轮询 key：返回 `Some(64 char hex String)` 表示有 key；`None` 表示还没好
    pub fn poll_key_data(&self) -> Result<Option<String>> {
        let mut buf = [0u8; POLL_BUF_SIZE];
        // SAFETY: buf 是栈上数组，POLL_BUF_SIZE 远大于 spec 要求的 65
        let got = unsafe { (self.poll_key_data)(buf.as_mut_ptr(), POLL_BUF_SIZE as i32) };
        if got == 0 {
            return Ok(None);
        }
        // dll 写入的是 NUL-terminated C 字符串
        let key_str = bytes_to_string_until_nul(&buf)?;
        Ok(Some(key_str))
    }

    /// 取一条状态消息（非阻塞）；返回 `Some((msg, level))` 或 `None`
    pub fn get_status_message(&self) -> Option<(String, i32)> {
        let mut buf = [0u8; STATUS_BUF_SIZE];
        let mut level: i32 = 0;
        // SAFETY: buf/level 都是栈上变量
        let got =
            unsafe { (self.get_status_message)(buf.as_mut_ptr(), STATUS_BUF_SIZE as i32, &mut level as *mut i32) };
        if got == 0 {
            return None;
        }
        bytes_to_string_until_nul(&buf).ok().map(|s| (s, level))
    }

    /// 显式 cleanup（HookSession::drop 会兜底调）
    pub fn cleanup_hook(&self) -> bool {
        // SAFETY: 函数指针来自加载的 dll
        unsafe { (self.cleanup_hook)() != 0 }
    }

    /// 取最后一次错误描述（用户可读字符串）
    pub fn get_last_error(&self) -> String {
        // SAFETY: dll 内部静态字符串，不需要释放；NUL-terminated
        unsafe {
            let p = (self.get_last_error_msg)();
            if p.is_null() {
                return "(no error info)".to_string();
            }
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

/// 构造 dll 加载候选路径
fn build_candidate_paths(primary: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    out.push(primary.to_path_buf());

    // 如果 primary 是相对路径，再叠 ./ + 可执行同目录
    if primary.is_relative() {
        // 当前工作目录下的相对路径已由 primary 提供，这里加一些通用回退
        // 取裸文件名 fallback
        if let Some(fname) = primary.file_name() {
            out.push(PathBuf::from(fname));
            // 可执行同目录
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    out.push(parent.join(fname));
                    // build.rs 把 wx_key.dll 拷到了 target/{debug,release}/，
                    // 而 cargo test/cargo run 的 cwd 是 workspace root，所以这里覆盖到
                    // target/debug/wx_key.dll 之类
                    //
                    // ⚠️ `vendor/wx_key/` 这条原先漏了, 而 **doctor 的 check_wx_key_dll 恰恰
                    //    按这个位置找** (msgvestige/src/main.rs)。两处不一致的后果:
                    //    用户照 doctor 的提示把 dll 放进 `vendor/wx_key/`, doctor 报 ✅ 找到,
                    //    真去 auth 时加载器却看不见 —— 「体检说有、用的时候没有」比两边都说
                    //    没有更坑。
                    //    同一类问题这一轮修了三处 (ffmpeg / node / 这里): 凡"随包带的外部件",
                    //    **找它的每条路径都要覆盖 vendor/ 布局** —— 按判据全扫, 不按点名清单修。
                    out.push(parent.join("vendor").join("wx_key").join(fname));
                }
            }
        }
    }
    out
}

/// 64-hex 脱敏 — 把字符串里任何 ≥ 64 char 的 ASCII-hex 连续段替换成
/// `<hex64:sha8={hash}>`（hash = sha8(全段)）。
///
/// P1-G 修复：
///   - master key 的全 hex 形态是 *exactly* 64 char，但调试字符串可能把它包在
///     更长的串里（如 256 bit hex / 拼前缀），所以这里取 ≥64 而非 ==64。
///   - sha8 留 8 char 短指纹，足够在日志里关联“同一 key 出现多次”但泄不出明文。
///   - 实现走纯线性扫描（不引入 regex 依赖），按 char 边界切分；ASCII-only
///     hex 字符天然单字节，索引安全。
fn mask_hex_in_log(msg: &str) -> String {
    let bytes = msg.as_bytes();
    let mut out = String::with_capacity(msg.len());
    let mut i = 0;
    while i < bytes.len() {
        // 扫一段连续的 ASCII hex
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let run_len = i - start;
        if run_len >= 64 {
            // SAFETY: ASCII hex 都是单字节 ASCII，切片必落在 char 边界
            let run = &msg[start..i];
            out.push_str("<hex64:sha8=");
            out.push_str(&sha8(run.as_bytes()));
            out.push('>');
        } else if run_len > 0 {
            // SAFETY: 同上，ASCII 边界安全
            out.push_str(&msg[start..i]);
        }
        // 非 hex 字符原样保留（可能是 UTF-8 多字节，按 char 推进）
        if i < bytes.len() {
            // 找到当前 byte 所在 char 的范围
            let ch = msg[i..].chars().next().expect("i < len 必有 char");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// 把 NUL-terminated 字节数组取到第一个 0 之前作为 UTF-8 字符串
fn bytes_to_string_until_nul(buf: &[u8]) -> Result<String> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    // r2 P1 #4: 走工厂方法 algorithm_mismatch (alpha contract 强制)
    let s = std::str::from_utf8(&buf[..end]).map_err(|_e| KeyError::algorithm_mismatch("ffi-utf8-decode-fail"))?;
    Ok(s.to_string())
}

// =====================================================================================
// HookSession — RAII guard：Drop 自动 CleanupHook（K-R6）
// =====================================================================================

/// `HookSession` — RAII guard，drop 时无条件调 `CleanupHook`（K-R6）
///
/// 生命周期绑定到 `WxKeyLib`：保证 cleanup 调用时 dll 一定还活着。
///
/// postmortem P0-3 引入 `last_status` 字段：每次 drain_status_messages 时记录最后
/// 一条 (msg, level) — 超时分支用它做诊断, 让用户看到 dll 走到哪一步死掉的
/// (e.g. "找到 WeChatWin.dll" vs "等待 setKey 调用" 完全不同的故障语义)。
pub struct HookSession<'a> {
    lib: &'a WxKeyLib,
    cleanup_called: bool,
    /// dll 最后一次产出的 status message (已过 mask_hex_in_log 脱敏)。
    /// HookTimeout 时塞进 `KeyError::HookTimeout.last_status`, 用户可见。
    last_status: Option<String>,
}

impl<'a> HookSession<'a> {
    /// 安装 hook；失败时不创建 session（不需要 cleanup）
    pub fn install(lib: &'a WxKeyLib, pid: u32) -> Result<Self> {
        if !lib.initialize_hook(pid) {
            // r2 P1 #3: 之前 detail 被 #[allow(unused_variables)] 静默丢弃 — 用户拿不到 dll 内部 reason.
            // detail 走 mask_hex_in_log 防 hex 串泄露 (理论上 wx_key.dll 错误描述不含 hex master_key,
            // 但 mask_hex_in_log 是入口侧 K-R4 兜底).
            let detail = lib.get_last_error();
            let masked = mask_hex_in_log(&detail);
            tracing::warn!(stage = "hook_install", pid = pid, detail = %masked, "InitializeHook 返 false");
            return Err(KeyError::dpapi_unavailable(b"hook_install").into());
        }
        Ok(Self {
            lib,
            cleanup_called: false,
            last_status: None,
        })
    }

    /// 轮询 key，超时返 `HookTimeout`
    ///
    /// 改动 (postmortem)：
    ///   - P0-1：每次循环检查全局 SHUTDOWN_FLAG, true 则立刻返 ConsentDenied (ADR-405 r3 收敛)
    ///     (Drop 仍会跑 CleanupHook 把 dll 内部状态清干净)
    ///   - P0-3：超时分支带 secs + last_status, 用户能看到 dll 最后状态
    ///   - NH-2：每 10s 打一次 heartbeat println, 避免长时间静默让用户以为程序卡死
    pub fn poll_key(
        &mut self,
        timeout: Duration,
        poll_interval: Duration,
        notifier: &dyn UserNotifier,
    ) -> Result<String> {
        let start = Instant::now();
        let mut next_heartbeat_at: u128 = HEARTBEAT_INTERVAL_MS;
        loop {
            // P0-1：取消优先 — 即便 dll 此刻把 key 给我们了, 用户既然按了 Ctrl-C
            // 就应直接退出, 不再写 cache (cache hit 会让下次跳过 prompt, 但用户的
            // 明确退出意图比这更重要)
            if shutdown_requested() {
                self.drain_status_messages();
                return Err(KeyError::ConsentDenied.into());
            }

            if let Some(key) = self.lib.poll_key_data()? {
                self.drain_status_messages();
                return Ok(key);
            }
            self.drain_status_messages();

            let elapsed = start.elapsed();
            if elapsed > timeout {
                // ADR-405 r3 (KI-405-NOTFOUND 闭): 专用 HookTimeout 变体 (terminal), 替代 PR2-1-c
                // 临时借用的 dpapi_unavailable(b"hook_timeout") (语义错位). last_status 已过
                // drain_status_messages 的 mask_hex_in_log 脱敏 (K-R4).
                let secs = timeout.as_secs();
                tracing::warn!(reason = "hook_timeout", secs, "CipherTalk hook 轮询超时, 返 terminal");
                return Err(KeyError::HookTimeout {
                    secs,
                    last_status: self.last_status.clone(),
                }
                .into());
            }

            // NH-2：heartbeat — 每 HEARTBEAT_INTERVAL_MS 打一次剩余秒数提示
            // 用 elapsed.as_millis() 做边界判断, 用 next_heartbeat_at 推进避免重复打
            //
            // 注：HookSession 不持有 restart_wechat 字段 (这层只管 poll), 所以 heartbeat
            // 文案用通用版本——既适配 B 模式 "扫码登录" 也适配 A 模式 "注销重登"。
            let elapsed_ms = elapsed.as_millis();
            if elapsed_ms >= next_heartbeat_at {
                let remaining = timeout.as_secs().saturating_sub(elapsed.as_secs());
                // PR2-1-e: 倒计时心跳走 notifier (原硬编码 println!)
                notifier.notify(&format!(
                    "⏱️ 等待中... 已 {}s, 剩余约 {}s; 请完成微信扫码登录 (B 模式) 或注销重登/切账号 (A 模式) 触发 reopen db",
                    elapsed.as_secs(),
                    remaining,
                ));
                next_heartbeat_at += HEARTBEAT_INTERVAL_MS;
            }

            std::thread::sleep(poll_interval);
        }
    }

    /// 把 dll 内部缓冲的所有状态消息抽到 tracing log + 记录最后一条
    ///
    /// K-R4 / P1-G：dll 自己的 status message 实证基本不含 master key 明文，
    /// 但 GetStatusMessage 行为依赖 dll 版本（CipherTalk 更新 / 不同分支）—
    /// 万一 dll 把 64-hex key 片段拼进调试字符串，tracing 就成了泄密通道。
    /// 所以这里**统一**走 `mask_hex_in_log` 兜底，把任何 ≥64 char 的 hex 连
    /// 续段替换成 `<hex64:sha8={hash}>`（既能在日志里看到“同一 key”关联，又
    /// 不会泄漏明文）。
    ///
    /// postmortem P0-3：drain 时记录最后一条 masked message 到 `self.last_status`,
    /// 供 HookTimeout 时回填给用户。
    fn drain_status_messages(&mut self) {
        // r2 P1 #6: spec 未钉死 dll 必返 None — 加 MAX_DRAIN 上限兜底防 vendor 返"无限新 msg"卡死.
        // 实际正常 dll 每 poll 顶多产 1-3 条新 msg, 200 是十倍的余量.
        const MAX_DRAIN: usize = 200;
        for _ in 0..MAX_DRAIN {
            let Some((msg, level)) = self.lib.get_status_message() else {
                break;
            };
            let masked = mask_hex_in_log(&msg);
            // 记录最后一条 — 已脱敏, 安全
            self.last_status = Some(masked.clone());
            match level {
                0 => tracing::debug!(target: "ciphertalk::dll", level = "info",    "{}", masked),
                1 => tracing::info!( target: "ciphertalk::dll", level = "success", "{}", masked),
                2 => tracing::warn!( target: "ciphertalk::dll", level = "error",   "{}", masked),
                _ => tracing::debug!(target: "ciphertalk::dll", level,             "{}", masked),
            }
        }
    }

    /// 显式 cleanup（幂等，drop 会兜底）
    pub fn cleanup(&mut self) -> bool {
        if self.cleanup_called {
            return true;
        }
        let ok = self.lib.cleanup_hook();
        self.cleanup_called = true;
        ok
    }
}

impl Drop for HookSession<'_> {
    fn drop(&mut self) {
        if !self.cleanup_called {
            // K-R6：兜底 cleanup，错误不传播（drop 不能 panic）
            let ok = self.lib.cleanup_hook();
            self.cleanup_called = true;
            if !ok {
                tracing::warn!("HookSession::drop: CleanupHook 返回 false");
            }
        }
    }
}

// =====================================================================================
// find_wechat_pid — sysinfo crate 找 Weixin.exe（多进程择优）
//
// Bug 背景（K-401.6）：
//   微信 4.x 一次启动会拉起多个 Weixin.exe（主进程 + 1~N worker / utility 子进程）。
//   实测 4 进程场景：
//     PID 8252  (850 MB, 主窗口=微信, 151 modules) ← 真主，wx_key.dll 必须 hook 这个
//     PID 8636 / 28856 / 29160 (< 200 MB worker)
//   老实现遍历到 sysinfo 给的第一个匹配就返，常拿到 worker（如 29160），
//   随后 wx_key.dll GetWeChatVersion 因为目标进程没加载 WeChatWin.dll 直接失败。
//
// 修复策略（按优先级）：
//   1. ★ 主策略 ★ memory 最大 — 主进程加载完整 WeChatWin.dll + 资源，> 500MB；worker < 200MB
//   2. 备选：EnumProcessModules 找加载了 WeChatWin.dll 的 PID（PoC 阶段先不做）
//   3. 备选：MainWindowHandle != 0（PoC 阶段先不做）
//   4. 终极兜底：CLI --wechat-pid 用户手动指定 → 见 find_or_use_wechat_pid
// =====================================================================================

/// 在多 Weixin.exe 子进程环境下取主进程 PID
///
/// 启发式：按 process.memory() 最大 — 主进程加载完整 dll 与资源，memory 量级 >> worker。
/// 4.x（Weixin.exe）找不到时回退 3.x（WeChat.exe），回退侧也按 memory 最大。
pub fn find_wechat_pid(process_name: &str) -> Result<u32> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};

    // 刷 process list 时只要 memory 指标 — 不开 cpu / disk / user 等省 syscall
    let mut sys =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new().with_memory()));
    sys.refresh_processes_specifics(ProcessRefreshKind::new().with_memory());

    let target = std::ffi::OsStr::new(process_name);
    let mut candidates: Vec<(u32, u64)> = sys
        .processes()
        .iter()
        .filter(|(_, p)| p.name() == target)
        .map(|(pid, p)| (pid.as_u32(), p.memory()))
        .collect();

    // 4.x → 3.x 回退（仅当默认 Weixin.exe 一个都没找到时）
    if candidates.is_empty() && process_name == DEFAULT_PROCESS_NAME {
        let fallback = std::ffi::OsStr::new("WeChat.exe");
        candidates = sys
            .processes()
            .iter()
            .filter(|(_, p)| p.name() == fallback)
            .map(|(pid, p)| (pid.as_u32(), p.memory()))
            .collect();
        if !candidates.is_empty() {
            tracing::info!(
                "find_wechat_pid: 未找到 Weixin.exe，回退到 WeChat.exe（3.x 微信），候选数={}",
                candidates.len()
            );
        }
    }

    if candidates.is_empty() {
        // r2 P0 #4: 同 hook_timeout — wx_not_running terminal, 不走 cli 兜底.
        tracing::warn!(reason = "wx_not_running", "CipherTalk: 找不到 Weixin/WeChat 进程");
        return Err(KeyError::dpapi_unavailable(b"wx_not_running").into());
    }

    // 按 memory 降序，取最大（主进程）
    let (best_pid, best_mem) = candidates
        .iter()
        .max_by_key(|(_, mem)| *mem)
        .copied()
        .expect("candidates 非空已上面 early return");

    let total_count = candidates.len();
    if total_count == 1 {
        tracing::debug!(
            process_name = %process_name,
            selected_pid = best_pid,
            memory_mb = best_mem / 1024 / 1024,
            "find_wechat_pid: 单进程直接返"
        );
    } else {
        tracing::info!(
            process_name = %process_name,
            total_candidates = total_count,
            selected_pid = best_pid,
            memory_mb = best_mem / 1024 / 1024,
            "find_wechat_pid: 多进程择优（按 memory 最大）"
        );
        // 列其他候选（debug 看是不是真选对了）
        for (pid, mem) in &candidates {
            if *pid != best_pid {
                tracing::debug!(pid = pid, memory_mb = mem / 1024 / 1024, "find_wechat_pid: 跳过子进程");
            }
        }
    }

    Ok(best_pid)
}

/// 用户手动指定 PID 时直接返回，不做 sysinfo 发现
///
/// 这是给 CLI `--wechat-pid` 兜底用：当 memory 启发式选错（极端用例：用户
/// 关了主窗口只留 worker、或者多账号实例 memory 差不大）时，调用方可以
/// 用 `Some(pid)` 强制指定。`None` 走自动发现。
///
/// 调用方（v3-adapter）建议日志里同时打 "override" / "discovered" 来源标签。
pub fn find_or_use_wechat_pid(process_name: &str, override_pid: Option<u32>) -> Result<u32> {
    if let Some(pid) = override_pid {
        tracing::info!(pid = pid, "find_wechat_pid: 使用 CLI --wechat-pid override");
        return Ok(pid);
    }
    find_wechat_pid(process_name)
}

// =====================================================================================
// --restart-wechat 模式辅助：杀微信 / 启动微信 / 自动定位 Weixin.exe
//
// 设计动机（B-Task）：
//   模式 A（默认 hook 已在跑的 Weixin.exe）要求用户手动注销重登，触发 setKey；
//   模式 B 在 resolve() 入口先杀掉所有 Weixin.exe / WeChat.exe，再拉起新进程，
//   冷启动 100% 会调一次 SQLCipher setKey —— 用户只需重新扫码登录。
// =====================================================================================

/// 杀所有 Weixin.exe / WeChat.exe 进程（不区分大小写匹配进程名）
///
/// 返回成功杀掉的进程数。kill 失败的进程不计入返回值，但会在 trace log 留痕。
/// 杀完之后 sleep 1s 让 OS 完成资源释放（端口、文件句柄），避免紧接着 spawn
/// 新进程时撞到“资源还没清完”的状态。
fn kill_wechat_processes() -> Result<usize> {
    use sysinfo::{ProcessRefreshKind, System};
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    // sysinfo 0.30 在 Windows 下 Process::name() 返 &str（已 UTF-8）；
    // 直接字符串比较，无需 OsStr 包装。
    let mut killed = 0usize;

    for (pid, proc) in sys.processes() {
        let name = proc.name();
        if name == "Weixin.exe" || name == "WeChat.exe" {
            if proc.kill() {
                killed += 1;
                tracing::info!(
                    pid = %pid.as_u32(),
                    name = %name,
                    "killed wechat process"
                );
            } else {
                tracing::warn!(
                    pid = %pid.as_u32(),
                    name = %name,
                    "kill_wechat_processes: kill 返回 false（可能已退出 / 权限不足）"
                );
            }
        }
    }

    if killed > 0 {
        // 等 OS 把资源（文件句柄 / 网络端口 / DPAPI session 等）清干净再启动新进程
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(killed)
}

/// 启动微信并返回主进程 PID
///
/// 注意：Weixin.exe 启动后会拉起一组子进程（主窗口 + worker / utility），
/// 这里 spawn 拿到的 child PID 不一定是“真主”—— 必须再走 sysinfo 按 memory
/// 最大启发式（find_wechat_pid）选一次。
///
/// 等待 2s 留给微信完成 process group 创建 + 加载主 dll。实测 1s 偶有择优拿到
/// worker（worker 比主进程先把 memory 撑大）；2s 比较稳。
fn launch_wechat(exe_path: &Path) -> Result<u32> {
    use std::process::Command;
    let _child = Command::new(exe_path)
        .spawn()
        .map_err(|_e| KeyError::dpapi_unavailable(b"dll_load"))?;

    // 给微信启动 + 加载完时间
    std::thread::sleep(std::time::Duration::from_secs(2));

    // 重新枚举找主 PID (memory 最大). PR2-1-c 改: find_wechat_pid 已返 Result<u32>,
    // 不再 anyhow downcast — 任何 Err 都映射成 wechat_launch 失败.
    find_wechat_pid("Weixin.exe").map_err(|_e| KeyError::dpapi_unavailable(b"dll_load"))
}

/// 自动定位 Weixin.exe 路径（B-2 真修：4 层 fallback）
///
/// 候选策略（按概率排序）：
///   1. `C:\Program Files\Tencent\Weixin\Weixin.exe`（4.x 默认 64 位安装）
///   2. `C:\Program Files (x86)\Tencent\Weixin\Weixin.exe`（兼容 32 位）
///   3. ★ B-2 新增 ★ 注册表 `HKLM\Software\Tencent\Weixin` (或 HKCU) 的 InstallPath
///      — 微信安装器写到注册表的安装路径, 即使用户装在非标准盘也覆盖
///   4. ★ B-2 重写 ★ 用 `windows-sys QueryFullProcessImageNameW` 直接从运行中的
///      Weixin.exe / WeChat.exe 进程拿绝对路径 —— 不依赖 sysinfo, 因为 sysinfo 0.30
///      起 `Process.exe()` 默认 `UpdateKind::Never`, 实测在普通 `System::new()` +
///      `refresh_processes_specifics(ProcessRefreshKind::new())` 下返 None / 空路径。
///      Win32 API 直接读 PEB 100% 稳。
///
/// r2 P0 #4: 没有命中时返 terminal `DpapiUnavailable(reason="exe_not_found")` —
/// 不再走 cli fallback (NH-3 防 chain 把 Err 全当 miss 静悄悄掩盖故障).
/// 用户可用 `--wechat-exe-path <PATH>` 显式指定兜底.
///
/// 调用时机重要（B-2 验收）：
///   `resolve_via_restart` 流程必须先 `detect_wechat_exe` 再 `kill_wechat_processes` —
///   否则进程已死, 路径 4 拿不到任何运行中进程。
///   `CipherTalkProvider::resolve` 当前已是先 detect 再 kill 顺序, 满足该约束。
fn detect_wechat_exe() -> Result<PathBuf> {
    // 1) Program Files 标准位置
    let candidates = vec![
        PathBuf::from(r"C:\Program Files\Tencent\Weixin\Weixin.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Tencent\Weixin\Weixin.exe"),
    ];
    for path in &candidates {
        if path.exists() {
            tracing::debug!(path = %path.display(), "detect_wechat_exe: 命中标准路径"); // log-safe: 微信 exe 安装路径, 无 wxid
            return Ok(path.clone());
        }
    }

    // 2) ★ B-2 新增 ★ 注册表 HKLM/HKCU\Software\Tencent\Weixin InstallPath
    #[cfg(windows)]
    {
        if let Some(p) = read_wechat_install_path_from_registry() {
            if p.exists() {
                tracing::info!(path = %p.display(), "detect_wechat_exe: 从注册表获取"); // log-safe: 微信 exe 安装路径, 无 wxid
                return Ok(p);
            } else {
                tracing::debug!(
                    path = %p.display(), // log-safe: 微信 exe 安装路径, 无 wxid/聊天数据
                    "detect_wechat_exe: 注册表给的路径不存在, 继续 fallback"
                );
            }
        }
    }

    // 3) ★ B-2 重写 ★ 用 Win32 QueryFullProcessImageNameW 从运行进程拿路径
    //    sysinfo 0.30+ 的 Process.exe() 默认 UpdateKind::Never, 不可靠;
    //    直接 EnumProcesses + OpenProcess + QueryFullProcessImageNameW 100% 稳。
    #[cfg(windows)]
    {
        if let Some(exe) = find_wechat_exe_from_running_process() {
            tracing::info!(path = %exe.display(), "detect_wechat_exe: 从运行进程获取 (windows-sys QueryFullProcessImageNameW)"); // log-safe: 微信 exe 路径, 无 wxid
            return Ok(exe);
        }
    }

    // r2 P0 #4: 同 hook_timeout — exe_not_found terminal, 不走 cli 兜底.
    tracing::warn!(
        reason = "exe_not_found",
        "CipherTalk: detect_wechat_exe 三 path 全 miss"
    );
    Err(KeyError::dpapi_unavailable(b"exe_not_found"))
}

/// B-2 path 3: 注册表 HKLM/HKCU\Software\Tencent\Weixin 取 InstallPath
///
/// 微信安装器在 64 位安装时写 HKLM\Software\Tencent\Weixin\InstallPath；
/// 一些场景可能落在 HKCU 下。这里按概率顺序探两个 hive。
///
/// 实现选 `reg query` 命令而不是直接 RegOpenKeyExW + RegQueryValueExW 的理由：
///   - PoC 阶段一行 Command 就完事, 不引入 winreg 依赖
///   - WOW64 reflection 已由 `reg` 自动处理, 不用手算 KEY_WOW64_64KEY
///   - 不在热路径上 — detect_wechat_exe 全程只调一次
///
/// 返 `Some(完整 Weixin.exe 绝对路径)` 或 `None`（注册表项不存在 / parse 失败）。
/// 调用方负责检查文件 `.exists()` —— 注册表里的路径可能是历史残留（卸载后没清）。
#[cfg(windows)]
fn read_wechat_install_path_from_registry() -> Option<PathBuf> {
    use std::process::Command;

    // 注：64-bit 安装时 reg query 会自动走 64-bit hive; 32-bit 安装时会 reflect 到
    // SOFTWARE\WOW6432Node\Tencent\Weixin —— 我们两条路径都试一遍, 反正都很廉价。
    const HIVES: &[&str] = &[
        r"HKLM\Software\Tencent\Weixin",
        r"HKCU\Software\Tencent\Weixin",
        r"HKLM\Software\WOW6432Node\Tencent\Weixin",
    ];
    // InstallPath / Install Path 两种字段名都见过, 都试
    const VALUES: &[&str] = &["InstallPath", "Install Path"];

    for hive in HIVES {
        for value in VALUES {
            let output = match Command::new("reg").args(["query", hive, "/v", value]).output() {
                Ok(o) => o,
                Err(_) => continue,
            };
            if !output.status.success() {
                continue;
            }
            // stdout 是 OEM 代码页 (默认 CP936/UTF-8 都可能)；
            // InstallPath 一定是 ASCII 路径 (Program Files / 盘符), 用 lossy 不会丢信息。
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if !line.contains(value) || !line.contains("REG_SZ") {
                    continue;
                }
                // 行格式: "    InstallPath    REG_SZ    C:\Program Files\Tencent\Weixin"
                if let Some(idx) = line.find("REG_SZ") {
                    let raw = line[idx + "REG_SZ".len()..].trim();
                    if raw.is_empty() {
                        continue;
                    }
                    let dir = PathBuf::from(raw);
                    let exe = dir.join("Weixin.exe");
                    tracing::debug!(
                        hive = %hive,
                        value = %value,
                        candidate = %exe.display(), // log-safe: 注册表候选 exe 路径, 无 wxid/聊天数据
                        "read_wechat_install_path_from_registry: 候选"
                    );
                    return Some(exe);
                }
            }
        }
    }
    None
}

/// B-2 path 4: 直接调 Win32 API `QueryFullProcessImageNameW` 从运行中的
/// Weixin.exe / WeChat.exe 进程拿绝对路径
///
/// 为什么不用 sysinfo `Process.exe()`：
///   sysinfo 0.30 起 `ProcessRefreshKind::default()` 里 `exe = UpdateKind::Never`,
///   即使 `System::new_all()` 走 `RefreshKind::everything()` 也只是当前快照, 之后
///   `refresh_processes_specifics(ProcessRefreshKind::new())` 会清空 exe 字段。
///   实测 `proc.exe()` 频繁返 None 或空路径 — 不可靠。
///
/// 自己调 EnumProcesses + OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) +
/// QueryFullProcessImageNameW 同 sysinfo 内部用法, 但确保每次调用都【真去拿】, 不
/// 依赖 sysinfo 内部缓存策略。
///
/// 返 `Some(exe_path)` —— 第一个 Weixin.exe 或 WeChat.exe 进程的绝对路径；
/// 多 worker 子进程时哪个先扫到就用哪个（路径都一样）。
#[cfg(windows)]
fn find_wechat_exe_from_running_process() -> Option<PathBuf> {
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::ProcessStatus::EnumProcesses;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // 4096 个 PID 上限够覆盖大多数 Windows 桌面 (典型 < 500 进程); 缓冲不够时
    // bytes_returned == buf 容量, 我们 trace 一下但不展开 — PoC 不为极端容量优化。
    let mut pids = vec![0u32; 4096];
    let mut bytes_returned: u32 = 0;
    let buf_bytes = (pids.len() * std::mem::size_of::<u32>()) as u32;

    // SAFETY: pids 是栈/堆上有效缓冲, bytes_returned 是栈变量, 都按 API 契约对齐
    let ok = unsafe { EnumProcesses(pids.as_mut_ptr(), buf_bytes, &mut bytes_returned as *mut u32) };
    if ok == 0 {
        tracing::debug!("find_wechat_exe_from_running_process: EnumProcesses 失败");
        return None;
    }
    let count = bytes_returned as usize / std::mem::size_of::<u32>();
    if count == 0 {
        return None;
    }

    for &pid in &pids[..count] {
        if pid == 0 {
            continue;
        }

        // SAFETY: pid 是 u32, OpenProcess 自身负责检查; 失败返 NULL HANDLE。
        let handle: HANDLE = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            // 大多数权限失败的进程 (System / 受保护进程) 都会到这, debug 级别即可
            continue;
        }

        let mut buf = [0u16; 1024]; // MAX_PATH * 2, 富余很多
        let mut size: u32 = buf.len() as u32;

        // SAFETY: handle 非空 (上面已查), buf/size 是栈变量
        let q_ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size as *mut u32) };

        // 关闭 handle 之前先拿到结果（CloseHandle 不影响已 copy 出来的 buf 内容）
        // SAFETY: handle 非空
        unsafe {
            CloseHandle(handle);
        }
        // 防 unused_assignments lint —— 后续不再用 handle
        let _ = ptr::null::<()>();

        if q_ok == 0 || size == 0 {
            continue;
        }
        // size 是 wide-char 计数 (不含 NUL), 见 MSDN
        let path_str = String::from_utf16_lossy(&buf[..size as usize]);
        let path = PathBuf::from(&path_str);
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.eq_ignore_ascii_case("Weixin.exe") || name.eq_ignore_ascii_case("WeChat.exe") {
                tracing::info!(
                    pid = pid,
                    path = %path.display(), // log-safe: 运行进程 exe 路径, 无 wxid/聊天; per-user 安装可能含 Windows 用户名(检测诊断, 随 R2 包发开发者, 可接受)
                    "find_wechat_exe_from_running_process: 命中"
                );
                return Some(path);
            }
        }
    }
    None
}

/// 非 Windows 平台占位 —— 真正实现仅在 Windows 下被引用 (调用点都套了 cfg(windows))。
/// 留这个空函数让 cfg(test) 单测可以无脑 link, 不必再 cfg 包测试。
#[cfg(not(windows))]
#[allow(dead_code)]
fn read_wechat_install_path_from_registry() -> Option<PathBuf> {
    None
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn find_wechat_exe_from_running_process() -> Option<PathBuf> {
    None
}

// =====================================================================================
// 单元测试 — 只测能纯 Rust 跑的接口契约，FFI 真调走 integration test
// =====================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // PR2-1-e: 测试用 notifier — 收集 notify() 调用到 buffer, 验证注入生效 + 内容路由.
    struct BufferNotifier {
        lines: std::sync::Mutex<Vec<String>>,
    }
    impl BufferNotifier {
        fn new() -> Self {
            Self {
                lines: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn joined(&self) -> String {
            self.lines.lock().unwrap().join("\n")
        }
    }
    impl UserNotifier for BufferNotifier {
        fn notify(&self, msg: &str) {
            self.lines.lock().unwrap().push(msg.to_string());
        }
    }

    /// PR2-1-e: print_hook_timeout_diagnostic 走 notifier (非 stdout), 模式 B 文案.
    #[test]
    fn hook_timeout_diagnostic_routes_to_notifier_mode_b() {
        let buf = BufferNotifier::new();
        print_hook_timeout_diagnostic(&buf, true);
        let out = buf.joined();
        assert!(out.contains("hook 超时"), "应含超时标题: {out}");
        assert!(out.contains("模式 B"), "模式 B 应走 B 分支文案: {out}");
        assert!(out.contains("扫码登录"));
        assert!(!out.contains("模式 A, 用户手动重登"), "B 模式不应混 A 文案");
    }

    /// PR2-1-e: 模式 A 文案分支.
    #[test]
    fn hook_timeout_diagnostic_routes_to_notifier_mode_a() {
        let buf = BufferNotifier::new();
        print_hook_timeout_diagnostic(&buf, false);
        let out = buf.joined();
        assert!(out.contains("模式 A"), "模式 A 应走 A 分支: {out}");
        assert!(out.contains("重新打开 db") || out.contains("注销重登"));
    }

    /// PR2-1-e: with_notifier 覆盖默认; 默认是 StdoutNotifier (不 panic 即可, 行为=println).
    #[test]
    fn with_notifier_overrides_default() {
        let buf = Arc::new(BufferNotifier::new());
        let provider = CipherTalkProvider::new(None).with_notifier(buf.clone());
        // 直接调注入的 notifier 验证是同一个 (Arc 指向 buf)
        provider.notifier.notify("test-line");
        assert_eq!(buf.joined(), "test-line", "with_notifier 应替换默认 notifier");
    }

    #[test]
    fn default_dll_path_is_vendor() {
        let s = CipherTalkProvider::default();
        assert_eq!(s.dll_path.to_string_lossy(), DEFAULT_DLL_PATH);
        assert_eq!(s.process_name, DEFAULT_PROCESS_NAME);
        assert_eq!(s.hook_timeout_seconds, DEFAULT_HOOK_TIMEOUT_SECONDS);
        // postmortem NH-1：120s 实测仍偏紧 (注销+扫码登录 90s+, 加上找手机 / 开小差),
        // 提到 180s 给充裕窗口。
        assert_eq!(s.hook_timeout_seconds, 180, "默认应为 180s (demo UX, NH-1)");
        assert_eq!(s.poll_interval, DEFAULT_POLL_INTERVAL);
        assert!(s.confirm_callback.is_none());
        assert!(s.wechat_pid_override.is_none());
        // 2026-06：restart_wechat 默认 true (B 模式)，wechat_exe_path 默认 None
        // 决策：实测发现 wx_key.dll 必须微信【重新 open db】才能 hook, B 模式程序代劳
        // 杀+启用户只管扫码 → 体验更好, 应当默认。
        assert!(s.restart_wechat, "restart_wechat 默认应为 true (B 模式, 2026-06 决策)");
        assert!(s.wechat_exe_path.is_none(), "wechat_exe_path 默认应为 None");
    }

    #[test]
    fn with_wechat_pid_override_sets_field() {
        let s = CipherTalkProvider::default().with_wechat_pid_override(Some(12345));
        assert_eq!(s.wechat_pid_override, Some(12345));
        let s2 = CipherTalkProvider::default().with_wechat_pid_override(None);
        assert!(s2.wechat_pid_override.is_none());
    }

    #[test]
    fn with_hook_timeout_sets_field() {
        let s = CipherTalkProvider::default().with_hook_timeout(300);
        assert_eq!(s.hook_timeout_seconds, 300);
        // builder 可链式覆盖
        let s2 = CipherTalkProvider::default()
            .with_hook_timeout(45)
            .with_wechat_pid_override(Some(7777));
        assert_eq!(s2.hook_timeout_seconds, 45);
        assert_eq!(s2.wechat_pid_override, Some(7777));
    }

    #[test]
    fn with_confirm_callback_sets_field() {
        let s = CipherTalkProvider::default().with_confirm_callback(|_pid| true);
        assert!(s.confirm_callback.is_some());
    }

    #[test]
    fn capabilities_ciphertalk() {
        let s = CipherTalkProvider::default();
        let cap = s.capabilities();
        assert!(!cap.can_resolve_all); // ciphertalk 不能枚举
        assert!(cap.needs_user_consent); // K-R1
        assert!(!cap.persists_to_disk);
        assert_eq!(s.name(), "ciphertalk");
    }

    #[tokio::test]
    async fn resolve_all_returns_unsupported() {
        let s = CipherTalkProvider::default();
        let r = s.resolve_all().await;
        let err = r.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("不支持") || msg.contains("Unsupported"));
    }

    #[test]
    fn find_wechat_pid_returns_wechat_not_running_when_absent() {
        // r2 P0 #4: 改返 terminal DpapiUnavailable (reason="wx_not_running") — 不污染 NotFound 语义
        // 用一个肯定不存在的进程名探边界
        let r = find_wechat_pid("__definitely_not_a_real_process_xx12.exe");
        let err = r.unwrap_err();
        let downcast = Some(&err);
        assert!(matches!(downcast, Some(KeyError::DpapiUnavailable { .. })));
    }

    #[test]
    fn find_or_use_wechat_pid_returns_override_without_discovery() {
        // override 给定时，即使 process_name 完全是垃圾也应直接返 override —
        // 这是 CLI --wechat-pid 兜底语义：用户钉死 PID，sysinfo 一律绕开。
        let r = find_or_use_wechat_pid("__definitely_not_a_real_process_xx12.exe", Some(99999));
        assert_eq!(r.unwrap(), 99999);
    }

    #[test]
    fn find_or_use_wechat_pid_falls_through_to_discovery_when_none() {
        // override = None 时，等价于直接调 find_wechat_pid —
        // r2 P0 #4: 改返 terminal DpapiUnavailable (reason="wx_not_running").
        let r = find_or_use_wechat_pid("__definitely_not_a_real_process_xx12.exe", None);
        let err = r.unwrap_err();
        let downcast = Some(&err);
        assert!(matches!(downcast, Some(KeyError::DpapiUnavailable { .. })));
    }

    // 多 Weixin.exe 多进程时选 memory 最大的 PID 的真测得在装了 4.x 微信的机器上
    // 跑 integration test 才能验 — 单元测里只能描述意图：
    //
    //   给定 4 个候选 (pid=8252, mem=850MB), (pid=8636, mem=180MB),
    //   (pid=28856, mem=120MB), (pid=29160, mem=77MB)
    //   期望 find_wechat_pid 返 8252 而不是 sysinfo 第一个返的 29160。
    //
    // sysinfo::System 没暴露注入 fake process 的 hook，所以这里只能靠在真机
    // 跑的 E2E 验证（K-401.6 用例）。如果将来要 mock 这层，需要把
    // “枚举 + memory” 抽成 trait —— 当前 PoC 阶段不值。

    #[test]
    fn bytes_to_string_until_nul_stops_at_nul() {
        let buf = b"abcdef\0garbage_after_nul";
        let s = bytes_to_string_until_nul(buf).unwrap();
        assert_eq!(s, "abcdef");
    }

    #[test]
    fn bytes_to_string_until_nul_no_nul_uses_full_len() {
        let buf = b"abcdef";
        let s = bytes_to_string_until_nul(buf).unwrap();
        assert_eq!(s, "abcdef");
    }

    #[test]
    fn bytes_to_string_until_nul_rejects_invalid_utf8() {
        let buf = &[0xffu8, 0xfe, 0xfd, 0x00];
        let r = bytes_to_string_until_nul(buf);
        assert!(r.is_err());
    }

    #[test]
    fn validate_master_key_hex_ok_for_64_lower_hex() {
        assert!(validate_master_key_hex(&"a".repeat(64)).is_ok());
        assert!(validate_master_key_hex(&"0123456789abcdef".repeat(4)).is_ok());
    }

    #[test]
    fn validate_master_key_hex_rejects_wrong_len() {
        let r = validate_master_key_hex(&"a".repeat(63));
        assert!(r.is_err());
        let r = validate_master_key_hex(&"a".repeat(65));
        assert!(r.is_err());
    }

    #[test]
    fn validate_master_key_hex_rejects_non_hex() {
        let mut s = "a".repeat(63);
        s.push('z');
        let r = validate_master_key_hex(&s);
        assert!(r.is_err());
    }

    #[test]
    fn build_candidate_paths_includes_primary_and_filename_fallback() {
        let primary = PathBuf::from("vendor/wx_key/wx_key.dll");
        let cands = build_candidate_paths(&primary);
        assert!(cands.contains(&PathBuf::from("vendor/wx_key/wx_key.dll")));
        // 相对路径会带裸 filename fallback
        assert!(cands.iter().any(|p| p
            .file_name()
            .map(|f| f == std::ffi::OsStr::new("wx_key.dll"))
            .unwrap_or(false)));
    }

    // ---- P1-G mask_hex_in_log 测试 -----------------------------------------

    #[test]
    fn mask_hex_in_log_masks_64_hex_run() {
        let key = "a".repeat(64);
        let msg = format!("got key={key} done");
        let masked = mask_hex_in_log(&msg);
        // 原 key 不该出现在 mask 后字符串里
        assert!(!masked.contains(&key), "mask 后仍出现明文 key：{masked}");
        // 应当包含 <hex64:sha8=...> 标记
        assert!(
            masked.contains("<hex64:sha8="),
            "mask 后没有 <hex64:sha8=> 标记：{masked}"
        );
        // 边界文字保留
        assert!(masked.starts_with("got key="), "前缀丢了：{masked}");
        assert!(masked.ends_with(" done"), "后缀丢了：{masked}");
        // sha8 应能匹配 key 自身的 sha8
        let expected_sha = sha8(key.as_bytes());
        assert!(masked.contains(&expected_sha), "缺指纹 {expected_sha}：{masked}");
    }

    #[test]
    fn mask_hex_in_log_passes_through_short_hex() {
        // 63 个 hex 不该被脱敏（不到 64 char 阈值）
        let short_hex = "a".repeat(63);
        let msg = format!("nonce={short_hex}");
        let masked = mask_hex_in_log(&msg);
        assert_eq!(masked, msg, "63-hex 误伤被脱敏：{masked}");
    }

    #[test]
    fn mask_hex_in_log_masks_long_hex_over_64() {
        // 100 char hex 也应被脱敏（≥64 都视为可疑）
        let long_hex = "9".repeat(100);
        let masked = mask_hex_in_log(&long_hex);
        assert!(!masked.contains(&long_hex), "长 hex 没被脱敏：{masked}");
        assert!(masked.contains("<hex64:sha8="), "长 hex 没拿到 mask 标记：{masked}");
    }

    #[test]
    fn mask_hex_in_log_preserves_non_hex_and_utf8() {
        // 中文 + 非 hex + 短 hex 都该原样保留
        let msg = "微信进程 PID=12345 状态=ok deadbeef";
        let masked = mask_hex_in_log(msg);
        assert_eq!(masked, msg, "非 hex / UTF-8 被误改：{masked}");
    }

    #[test]
    fn mask_hex_in_log_handles_empty_string() {
        assert_eq!(mask_hex_in_log(""), "");
    }

    /// 不直接 FFI；构造一个错误的 dll 路径走 WxKeyLib::load → 必拿 DllLoadFailed
    #[test]
    fn wx_key_lib_load_failed_yields_dll_load_failed() {
        let bogus = PathBuf::from("__no_such_dir__/__no_such_dll__.dll");
        // WxKeyLib 没实现 Debug，不能直接 unwrap_err；改用 match
        let err = match WxKeyLib::load(&bogus) {
            Ok(_) => panic!("加载不存在的 dll 居然成功了"),
            Err(e) => e,
        };
        let downcast = Some(&err);
        assert!(matches!(downcast, Some(KeyError::DpapiUnavailable { .. })));
    }

    // ---- --restart-wechat 模式 builders / 辅助函数 ------------------------------

    #[test]
    fn with_restart_wechat_sets_field() {
        let s = CipherTalkProvider::default().with_restart_wechat(true);
        assert!(s.restart_wechat);
        let s2 = CipherTalkProvider::default().with_restart_wechat(false);
        assert!(!s2.restart_wechat);
    }

    #[test]
    fn with_wechat_exe_sets_field() {
        let path = PathBuf::from(r"C:\custom\Weixin.exe");
        let s = CipherTalkProvider::default().with_wechat_exe(Some(path.clone()));
        assert_eq!(s.wechat_exe_path.as_deref(), Some(path.as_path()));
        // None 应清回缺省
        let s2 = CipherTalkProvider::default().with_wechat_exe(None);
        assert!(s2.wechat_exe_path.is_none());
    }

    #[test]
    fn restart_wechat_builder_chains_with_others() {
        // builder 链可叠加：覆盖超时 + 开启 restart + 指定 exe
        let path = PathBuf::from(r"C:\Program Files\Tencent\Weixin\Weixin.exe");
        let s = CipherTalkProvider::default()
            .with_hook_timeout(45)
            .with_restart_wechat(true)
            .with_wechat_exe(Some(path.clone()));
        assert_eq!(s.hook_timeout_seconds, 45);
        assert!(s.restart_wechat);
        assert_eq!(s.wechat_exe_path.as_deref(), Some(path.as_path()));
    }

    // ---- postmortem P0-1 / P0-3 / NH 单元测试 ---------------------------------

    /// P0-1：request_shutdown 翻 flag, shutdown_requested 真读到
    #[test]
    fn shutdown_flag_round_trip() {
        // 用 reset_shutdown_for_test 隔离 — 串行调度避免和其他 case 冲突
        reset_shutdown_for_test();
        assert!(!shutdown_requested(), "初始应为 false");
        request_shutdown();
        assert!(shutdown_requested(), "request_shutdown 后应为 true");
        // 收尾 reset, 避免污染其他 test (注意：cargo 默认多线程跑 test, 但本 case
        // 只在 setup/teardown 时翻 flag, 其他 case 真要避免污染应自己 reset)
        reset_shutdown_for_test();
    }

    /// P0-1：request_shutdown 幂等 — 多次调用安全
    #[test]
    fn request_shutdown_is_idempotent() {
        reset_shutdown_for_test();
        request_shutdown();
        request_shutdown();
        request_shutdown();
        assert!(shutdown_requested());
        reset_shutdown_for_test();
    }

    /// ADR-405 r3: HookTimeout Display 含 secs 与 last_status (启用自 PR2-1-c 的 #[ignore])
    #[test]
    fn hook_timeout_display_shows_secs_and_status() {
        let err = KeyError::HookTimeout {
            secs: 180,
            last_status: Some("等待 setKey 调用".to_string()),
        };
        let s = format!("{err}");
        assert!(s.contains("180"), "应含 secs: {s}");
        assert!(s.contains("等待 setKey 调用"), "应含 last_status: {s}");
    }

    /// ADR-405 r3: HookTimeout last_status=None 时 Display 不 panic (启用自 #[ignore])
    #[test]
    fn hook_timeout_display_handles_no_status() {
        let err = KeyError::HookTimeout {
            secs: 60,
            last_status: None,
        };
        let s = format!("{err}");
        assert!(s.contains("60"));
        assert!(s.contains("None"), "None 应可 Debug 出来: {s}");
    }

    /// ADR-405 r3: HookTimeout 是 terminal — 不允许 cli 兜底盖掉超时事实 (NH-3, 启用自 #[ignore])
    #[test]
    fn hook_timeout_is_terminal_not_recoverable_miss() {
        assert!(
            !KeyError::HookTimeout {
                secs: 180,
                last_status: None
            }
            .is_recoverable_miss(),
            "HookTimeout 必须 terminal"
        );
    }

    /// ADR-405 r3 r1 codex P2: 端到端 K-R4 — dll status 含 64-hex master key →
    /// mask_hex_in_log 脱敏 → 进 HookTimeout.last_status → Display 不泄明文 hex.
    /// 钉死"last_status 入口侧脱敏 → Display 逐字显示安全"这条契约 (无 sha8 工厂兜底).
    #[test]
    fn hook_timeout_last_status_masked_no_hex_leak() {
        let fake_key = "deadbeef".repeat(8); // 64 char hex 模拟 dll 误吐 master key
        let raw_status = format!("dll 状态: key={fake_key} 已捕获");
        // ciphertalk 生产路径: drain_status_messages 存 last_status 前过 mask_hex_in_log
        let masked = mask_hex_in_log(&raw_status);
        let err = KeyError::HookTimeout {
            secs: 180,
            last_status: Some(masked),
        };
        let shown = format!("{err}");
        assert!(
            !shown.contains(&fake_key),
            "64-hex master key 不应出现在 Display: {shown}"
        );
        assert!(shown.contains("sha8="), "应是脱敏后的 sha8 摘要: {shown}");
    }

    // ADR-405 r3 FD2=继续: 删 user_cancelled_is_terminal_not_recoverable_miss —
    //   该测断言 ConsentDenied terminal (PoC-1 NH-3 旧观念). r3 决策: 用户拒绝 hook 后
    //   命令行 --master-key-hex 仍应兜底 → ConsentDenied 保持 recoverable (见 error.rs
    //   is_recoverable_miss). "彻底中止" 语义改由 HookTimeout (terminal) + 真 Ctrl-C
    //   out-of-band CancellationToken (KI-405-CANCEL, 推 0.2.0+) 承载.

    #[test]
    #[ignore = "DESTRUCTIVE: 会真杀机器上跑着的微信进程, 仅显式 --ignored 时跑 (例如 CI 干净环境)"]
    fn kill_wechat_processes_returns_zero_when_no_wechat_running() {
        // 仅在确认机器上没有微信进程时手动跑
        // cargo test -- --ignored kill_wechat
        let killed = kill_wechat_processes().expect("kill_wechat_processes 应可调用");
        assert_eq!(killed, 0, "无微信进程时应返 0");
    }

    #[test]
    fn detect_wechat_exe_returns_not_found_when_no_candidate_exists() {
        // 测试机 (Linux CI / 没装微信的 Windows) 两个标准路径都不存在
        //   且无运行中的微信进程 → 应返 WeChatExeNotFound。
        //   开发机上若真装了微信 / 微信在跑，detect 会成功 — 我们只在 "都没有" 分支断言。
        let std_paths_exist = PathBuf::from(r"C:\Program Files\Tencent\Weixin\Weixin.exe").exists()
            || PathBuf::from(r"C:\Program Files (x86)\Tencent\Weixin\Weixin.exe").exists();
        let running_exe = find_wechat_exe_from_running_process();
        let registry_exe = read_wechat_install_path_from_registry().filter(|p| p.exists());

        if std_paths_exist || running_exe.is_some() || registry_exe.is_some() {
            // 装了 / 在跑 / 注册表有 — detect 必成功
            let r = detect_wechat_exe();
            assert!(r.is_ok(), "已装/在跑微信但 detect 失败：{r:?}");
            return;
        }
        // r3 P0 #2: r2 P0 #4 把 detect_wechat_exe miss 改成 terminal DpapiUnavailable, 测试断言同步
        let err = detect_wechat_exe().unwrap_err();
        assert!(
            matches!(err, KeyError::DpapiUnavailable { .. }),
            "期望 DpapiUnavailable (exe_not_found terminal), 实际：{err:?}"
        );
    }

    /// B-2 path 4: 仅契约测 — find_wechat_exe_from_running_process 总能不 panic 调,
    /// 返 Some 时路径非空且 file_name 命中 Weixin.exe / WeChat.exe (大小写不敏感),
    /// Some/None 都允许（取决于机器是否在跑微信）。
    ///
    /// 真"非标准路径命中" (例如 F:\weixin4.0\Weixin\Weixin.exe) 的回归只能在真机
    /// 跑 destructive integration test 验, 单测层只能保证函数本身可调 + 返值合法。
    #[test]
    fn find_wechat_exe_from_running_process_smoke() {
        let r = find_wechat_exe_from_running_process();
        if let Some(exe) = r {
            assert!(!exe.as_os_str().is_empty(), "Some 分支返空路径");
            // 命中的话, file_name 应当是 Weixin.exe / WeChat.exe (大小写不敏感) —
            // QueryFullProcessImageNameW 拿的是完整磁盘路径, file_name 一定有值
            let name = exe
                .file_name()
                .and_then(|n| n.to_str())
                .expect("命中时 file_name 必须有");
            assert!(
                name.eq_ignore_ascii_case("Weixin.exe") || name.eq_ignore_ascii_case("WeChat.exe"),
                "命中的 file_name 应为 Weixin.exe / WeChat.exe, 实际：{name}"
            );
        } else {
            // None — 测试机没跑微信, 符合 CI 干净环境预期
            tracing::debug!("find_wechat_exe_from_running_process: 无微信进程 (CI 环境)");
        }
    }

    /// B-2 path 3: 注册表读取契约测 — 不 panic, Some 返带 Weixin.exe 后缀的 PathBuf
    ///
    /// 大多数测试机不会装微信 → 这条多半返 None; 装了 4.x 微信的开发机会返 Some。
    /// 注意: registry path 可能是历史残留 (卸载后未清), 所以 detect_wechat_exe 会
    /// 再做一次 `.exists()` 检查 — 这里我们只测 Some 时 file_name 是 Weixin.exe。
    #[test]
    fn read_wechat_install_path_from_registry_smoke() {
        let r = read_wechat_install_path_from_registry();
        if let Some(p) = r {
            assert!(!p.as_os_str().is_empty());
            let name = p.file_name().and_then(|n| n.to_str()).expect("Some 必有 file_name");
            assert_eq!(name, "Weixin.exe", "注册表 fallback 应拼出 Weixin.exe");
        } else {
            // None — 注册表没写 (没装微信 / 微信卸载干净 / 32 位 hive 也没有)
            tracing::debug!("read_wechat_install_path_from_registry: 无注册表项");
        }
    }

    /// B-2 4 层 fallback 整体逻辑测 — 用现有环境断言一致性:
    /// 任何一层命中 → detect_wechat_exe 必成功; 全都 miss → 必返 terminal DpapiUnavailable
    /// (r2 P0 #4 改, reason="exe_not_found", 见 detect_wechat_exe 末尾分支).
    ///
    /// 这条相当于 detect_wechat_exe_returns_not_found_when_no_candidate_exists 的
    /// 对偶 — 那条只测 "全 miss" 分支, 这条同时覆盖 "至少一层命中" 分支。
    #[test]
    fn detect_wechat_exe_4_layer_fallback_consistency() {
        let layer1_2 = PathBuf::from(r"C:\Program Files\Tencent\Weixin\Weixin.exe").exists()
            || PathBuf::from(r"C:\Program Files (x86)\Tencent\Weixin\Weixin.exe").exists();
        let layer3 = read_wechat_install_path_from_registry()
            .map(|p| p.exists())
            .unwrap_or(false);
        let layer4 = find_wechat_exe_from_running_process().is_some();
        let any_layer_hit = layer1_2 || layer3 || layer4;

        let r = detect_wechat_exe();
        if any_layer_hit {
            assert!(
                r.is_ok(),
                "至少一层 (1/2={layer1_2}, 3={layer3}, 4={layer4}) 命中, 但 detect 失败: {r:?}"
            );
        } else {
            // r4 P0: r2 P0 #4 把 detect_wechat_exe miss 改成 terminal DpapiUnavailable, 兄弟测同步
            assert!(
                matches!(r, Err(KeyError::DpapiUnavailable { .. })),
                "全层 miss, 应返 DpapiUnavailable (exe_not_found terminal), 实际: {r:?}"
            );
        }
    }

    /// B-2 destructive integration test (默认 ignore):
    /// 当机器上有微信【在跑】但【标准路径 1/2 都不存在】时 (非标准安装位置),
    /// detect_wechat_exe 应当走 fallback 路径 3/4 拿到运行进程的 exe 路径,
    /// 而不是返 terminal DpapiUnavailable(reason="exe_not_found") (r2 P0 #4).
    ///
    /// 只能手动 (或在配好这种环境的 CI 上) 跑:
    ///   cargo test -- --ignored b2_fallback_finds_nonstandard_path
    #[test]
    #[ignore = "B-2 destructive: 要求机器上微信在跑且装在非标准位置 (F:\\weixin4.0\\ 之类), 普通 CI 跑不了"]
    fn b2_fallback_finds_nonstandard_path() {
        let std_paths_exist = PathBuf::from(r"C:\Program Files\Tencent\Weixin\Weixin.exe").exists()
            || PathBuf::from(r"C:\Program Files (x86)\Tencent\Weixin\Weixin.exe").exists();
        let running = find_wechat_exe_from_running_process();

        if std_paths_exist {
            eprintln!("跳过: 标准路径存在, 走不到 fallback 分支");
            return;
        }
        let Some(running_exe) = running else {
            eprintln!("跳过: 微信不在跑, 没法验 fallback");
            return;
        };

        let detected = detect_wechat_exe().expect("fallback 应成功");
        // 接受 registry / running 任一: detect 内部先 registry 后 running, 两者
        // 通常指向同一安装目录 (Weixin.exe 路径相同), 但路径大小写 / 末段名可能略
        // 不同 (注册表存 InstallPath 目录, 进程返完整 exe 路径)。这里比 file_name。
        assert!(detected.exists(), "fallback 拿到的路径不存在: {}", detected.display());
        let detected_name = detected.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let running_name = running_exe.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert_eq!(
            detected_name.to_ascii_lowercase(),
            running_name.to_ascii_lowercase(),
            "detect_wechat_exe fallback file_name 应匹配运行进程"
        );
    }
}
