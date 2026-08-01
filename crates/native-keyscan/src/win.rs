//! win.rs — Windows 进程内存访问 (K-R7 x64). 所有 Win32 unsafe FFI 集中本文件,
//! 对外只暴露安全封装 (open / read / for_each_private_region / module_path).
//!
//! 枚举 Weixin.exe 取主进程 (内存最大者, 跟 ciphertalk find_wechat_pid 同策略) — 不写死 pid.

use std::ffi::c_void;
use std::ops::ControlFlow;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetProcessMemoryInfo, LIST_MODULES_ALL, PROCESS_MEMORY_COUNTERS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::error::KeyScanError;

/// 单次 ReadProcessMemory 上限 (512MB) — 跳过异常大区域防 OOM (跟 PoC 一致).
const MAX_READ: usize = 512 * 1024 * 1024;

/// 宽字符数组 (NUL 结尾) → String.
fn wstr_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// 枚举所有 Weixin.exe 的 pid (ToolHelp 进程快照).
fn enum_weixin_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    // SAFETY: 失败返 INVALID_HANDLE_VALUE, 下面即校验; 成功的 snap 用完 CloseHandle.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE || snap.is_null() {
        return pids;
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: snap 有效, entry.dwSize 已设 (Process32FirstW 契约要求).
    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        loop {
            if wstr_to_string(&entry.szExeFile).eq_ignore_ascii_case("Weixin.exe") {
                pids.push(entry.th32ProcessID);
            }
            // SAFETY: snap 有效; entry 上次调用已填.
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }
    // SAFETY: snap 由 CreateToolhelp32Snapshot 得, 仅此关一次.
    unsafe { CloseHandle(snap) };
    pids
}

/// 取某 pid 的 WorkingSetSize (选主进程: 微信主进程加载完整资源, 内存最大).
fn working_set(pid: u32) -> Option<usize> {
    // SAFETY: pid 是普通整数, OpenProcess 自检; 失败返 NULL.
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: h 有效, pmc 已初始化 cb.
    let ok = unsafe { GetProcessMemoryInfo(h, &mut pmc, pmc.cb) };
    // SAFETY: h 仅此关一次.
    unsafe { CloseHandle(h) };
    (ok != 0).then_some(pmc.WorkingSetSize)
}

/// 已打开的微信进程句柄 — RAII (Drop 关 handle).
pub struct WeixinProcess {
    handle: HANDLE,
}

impl WeixinProcess {
    /// 打开微信主进程. `pid=None` 自动枚举 Weixin.exe 取内存最大者 (主进程).
    ///
    /// # Errors
    /// - `WeixinNotRunning` 找不到 Weixin.exe;
    /// - `AccessDenied` OpenProcess 失败 (权限 / 安全软件拦, KI-I).
    pub fn open(pid: Option<u32>) -> Result<Self, KeyScanError> {
        let pid = match pid {
            Some(p) => p,
            None => {
                let pids = enum_weixin_pids();
                if pids.is_empty() {
                    return Err(KeyScanError::WeixinNotRunning); // 真没 Weixin.exe (KI-G)
                }
                // 找到进程了; 选内存最大者. 若全 OpenProcess 失败 = 权限/安全软件拦 (KI-I),
                // 不是"没跑" — 报 AccessDenied 才让上层走对的退路 (codex E 修).
                pids.iter()
                    .filter_map(|&p| working_set(p).map(|ws| (p, ws)))
                    .max_by_key(|&(_, ws)| ws)
                    .map(|(p, _)| p)
                    .ok_or(KeyScanError::AccessDenied { pid: pids[0] })?
            }
        };
        // SAFETY: pid 普通整数; 失败返 NULL → AccessDenied.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return Err(KeyScanError::AccessDenied { pid });
        }
        Ok(Self { handle })
    }

    /// 读进程内存 `[addr, addr+size)`; 失败 / 越界 / 超 512MB 返 None.
    #[must_use]
    pub fn read(&self, addr: usize, size: usize) -> Option<Vec<u8>> {
        if size == 0 || size > MAX_READ {
            return None;
        }
        let mut buf = vec![0u8; size];
        let mut read: usize = 0;
        // SAFETY: handle 有效; buf 容量 size; read 接收实读字节数.
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const c_void,
                buf.as_mut_ptr().cast(),
                size,
                &mut read,
            )
        };
        if ok == 0 || read == 0 {
            return None;
        }
        buf.truncate(read);
        Some(buf)
    }

    /// 遍历所有已提交私有内存区 (MEM_COMMIT & MEM_PRIVATE), 逐区把读出的字节交回调.
    /// 回调返 `ControlFlow::Break` 提前停 (fast 路命中即停).
    pub fn for_each_private_region<F>(&self, mut f: F)
    where
        F: FnMut(usize, &[u8]) -> ControlFlow<()>,
    {
        let mut addr: usize = 0;
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: handle 有效; mbi 接收查询结果; 第四参为结构体大小.
            let r = unsafe {
                VirtualQueryEx(
                    self.handle,
                    addr as *const c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if r == 0 {
                break;
            }
            let base = mbi.BaseAddress as usize;
            let region = mbi.RegionSize;
            if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE {
                if let Some(mem) = self.read(base, region) {
                    if f(base, &mem).is_break() {
                        break;
                    }
                }
            }
            let next = base.wrapping_add(region);
            if next <= addr {
                break; // 地址回绕 / 不前进 → 停 (防死循环).
            }
            addr = next;
        }
    }

    /// 遍历所有已提交且**可读**的内存区 (private/mapped/image 都算, 不限 MEM_PRIVATE) — 比
    /// [`for_each_private_region`](Self::for_each_private_region) 覆盖更广。image key 常在**非 private**
    /// 区 (mapped/image), private-only 扫不到 (跟 wx-cli `_iter_windows_process_image_keys` 同覆盖)。
    /// 跳过 GUARD / NOACCESS 页。**大区分块读** (64MB + 15B overlap) 不整跳, 避免超 512MB 区静默漏扫
    /// (codex 件3 P2); 16 字节候选跨块边界靠 overlap 兜。回调 `Break` 提前停。
    pub fn for_each_readable_region<F>(&self, mut f: F)
    where
        F: FnMut(usize, &[u8]) -> ControlFlow<()>,
    {
        const PAGE_GUARD: u32 = 0x100;
        // 分块: 64MB (< read 的 512MB cap, 不会被跳); overlap 15B = 16 字节窗口跨界仍完整。
        const CHUNK: usize = 64 * 1024 * 1024;
        const OVERLAP: usize = 15;
        // 可读保护位 (Protect 低字节): READONLY/READWRITE/WRITECOPY/EXECUTE(_READ/_READWRITE/_WRITECOPY)。
        let is_readable = |protect: u32| {
            matches!(protect & 0xFF, 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80) && (protect & PAGE_GUARD) == 0
        };
        let mut addr: usize = 0;
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: handle 有效; mbi 接收查询结果; 第四参为结构体大小.
            let r = unsafe {
                VirtualQueryEx(
                    self.handle,
                    addr as *const c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if r == 0 {
                break;
            }
            let base = mbi.BaseAddress as usize;
            let region = mbi.RegionSize;
            if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
                let mut off = 0;
                let mut stop = false;
                while off < region {
                    let want = (region - off).min(CHUNK + OVERLAP);
                    if let Some(mem) = self.read(base.wrapping_add(off), want) {
                        if f(base.wrapping_add(off), &mem).is_break() {
                            stop = true;
                            break;
                        }
                    }
                    off += CHUNK; // 步进 CHUNK; 上面多读 OVERLAP → 相邻块重叠 15B
                }
                if stop {
                    break;
                }
            }
            let next = base.wrapping_add(region);
            if next <= addr {
                break; // 地址回绕 / 不前进 → 停.
            }
            addr = next;
        }
    }

    /// 找进程已加载的某 dll 绝对路径 (文件名后缀匹配, 大小写不敏感). full 路定位 Weixin.dll —
    /// 直接拿进程加载的那份 (含版本目录), 不靠猜路径.
    #[must_use]
    pub fn module_path(&self, file_name_lc: &str) -> Option<PathBuf> {
        let mut mods: Vec<HMODULE> = vec![std::ptr::null_mut(); 2048];
        let cb = (mods.len() * std::mem::size_of::<HMODULE>()) as u32;
        let mut needed: u32 = 0;
        // SAFETY: mods 容量 cb 字节; needed 接收所需字节数; handle 有效.
        let ok = unsafe { EnumProcessModulesEx(self.handle, mods.as_mut_ptr(), cb, &mut needed, LIST_MODULES_ALL) };
        if ok == 0 {
            return None;
        }
        let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(mods.len());
        for &hmod in &mods[..count] {
            let mut buf = [0u16; 520];
            // SAFETY: handle + hmod 有效; buf 容量 buf.len().
            let len = unsafe { GetModuleFileNameExW(self.handle, hmod, buf.as_mut_ptr(), buf.len() as u32) };
            if len == 0 {
                continue;
            }
            let path = wstr_to_string(&buf[..len as usize]);
            if path.to_lowercase().ends_with(file_name_lc) {
                return Some(PathBuf::from(path));
            }
        }
        None
    }
}

impl Drop for WeixinProcess {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle 由 OpenProcess 得, 仅此处关一次.
            unsafe { CloseHandle(self.handle) };
        }
    }
}
