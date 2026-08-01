//! vfs.rs — 自定义 SQLite VFS: **按需逐页解密** (on-demand), 低内存 (只解查询碰到的页, 非整库).
//!
//! DLL 同款思路的纯 Rust 实现: SQLite 顺着 b-tree 只读它需要的页, 我们的 VFS 在 `xRead` 里**当场解密那一页**
//! 再交给 SQLite. 峰值内存 ≈ SQLite 页缓存 (+ 步骤2 的 WAL 叠加) = 几十 MB, 非整库 GB. 复用 decrypt.rs 的
//! [`crate::decrypt::verify_page_hmac`] + [`crate::decrypt::decrypt_page_into`], **零新增 crypto**.
//!
//! ## 设计 (只读, 不包装默认 VFS)
//! - 自己开 [`std::fs::File`] 做 I/O; `xRead` 逐页解密; 其余 io 回调 = 只读 noop/常量; OS 工具类
//!   (`xRandomness`/`xSleep`/`xCurrentTime`) 委托默认 VFS.
//! - `xAccess` 对 `-wal`/`-shm`/`-journal` 返 false → SQLite 走 **rollback 模式**, 只经我们 `xRead` 读主库
//!   (WAL 我们自己在解密后的 page 里叠加, 见步骤2; 避开 SQLite 原生 WAL 对密文帧校验和不匹配的问题).
//! - page1: 解密写入 `SQLite format 3\0` magic + **改 header 为 rollback (byte18/19=1)** 让 SQLite 不找 `-wal`.
//!
//! ## 红线
//! - **只读**: `xWrite`/`xTruncate` 返 `SQLITE_READONLY`; 绝不写微信库.
//! - **不落盘**: 解密只在 `xRead` 的 buffer 里 (SQLite 页缓存内存); 不写明文文件.
//! - K-R4: key 存 CipherData (进程内存, 不打印); 错误不含明文. (`unsafe_code` allow 在 lib.rs `mod vfs` 处.)

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs::File;
// 定位读(不动文件指针)在两个平台上叫法不同: Windows 是 `seek_read`, Unix 是 `read_at`。
// 两者语义一致(都可能短读, 由下面的 read_exact_at 循环补齐)。
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Mutex, Once};

use native_keyscan::{KeyMaterial, PAGE};
use rusqlite::ffi;
use zeroize::Zeroizing;

use crate::decrypt::{decrypt_page_into, verify_page_hmac};
use crate::error::SqlcipherError;
use crate::wal::{build_wal_overlay, wal_sibling, WalOverlay};

/// 注册用的 VFS 名 (rusqlite `open_with_flags_and_vfs` 按此名开库).
const VFS_NAME: &[u8] = b"wxcipher\0";
/// lock-byte page (1GB / PAGE + 1, 1-based): SQLite 不读其内容 (只做锁), SQLCipher 不加密它 → 原样返回.
const LOCK_BYTE_PAGE: u64 = 0x4000_0000 / PAGE as u64 + 1;

/// WAL 前沿的**可刷新**状态 (Arc<Mutex> 共享给 xRead 读 + [`WalRefreshHandle`] 写).
///
/// overlay 就地刷新的意义: WAL 变了只重建这一小块 (不重开连接、不重读 schema)。`refresh_gen` 每刷新 +1,
/// xRead 把它叠到 page1 的 change-counter (offset 24) 上 → SQLite 下次查询发现变更 → 丢页缓存重读拿新数据;
/// **schema cookie (offset 40) 不变 → SQLite 保留已解析的表结构 (省掉大账号 ~3s schema 重解)**。
struct WalState {
    /// 已提交 WAL 页 (pgno → 解密后的页); xRead 命中则返最新前沿。
    overlay: WalOverlay,
    /// 逻辑总页数 = max(物理, WAL 提交后页数); 供 xFileSize + 越界判断。
    logical_pages: u64,
    /// 刷新代数: 每次 refresh +1, 叠到 page1 change-counter 强制 SQLite 重读 (即便 WeChat change-counter 未变).
    refresh_gen: u32,
}

/// 每个打开的加密库文件的解密上下文 (Rust 堆; C 侧 CipherFile 只持指针).
struct CipherData {
    file: File,
    enc_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
    /// 主库物理页数 (文件大小 / PAGE).
    physical_pages: u64,
    /// WAL 前沿状态 (可就地刷新; 与 [`WalRefreshHandle`] 共享).
    state: Arc<Mutex<WalState>>,
}

/// **WAL 就地刷新句柄** —— watch 用: 检测到某库 WAL 变了, 调 [`WalRefreshHandle::refresh`] 只重建 overlay,
/// 不重开连接 (省 schema 重解)。持 rebuild 所需输入 + 与 [`CipherData`] 共享的 [`WalState`]。
pub struct WalRefreshHandle {
    state: Arc<Mutex<WalState>>,
    wal_path: PathBuf,
    enc_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
    physical_pages: u64,
}

impl WalRefreshHandle {
    /// 重扫 `<db>-wal` 重建 overlay + 逻辑页数, 并 bump `refresh_gen` (强制 SQLite 下次查询重读页).
    /// 不重开连接、不重读 schema → 大账号省 ~3s。
    ///
    /// # Errors
    /// [`SqlcipherError`] — 读/解密 WAL 失败.
    pub fn refresh(&self) -> Result<(), SqlcipherError> {
        let (overlay, logical, _skipped) =
            build_wal_overlay(&self.wal_path, &self.enc_key, &self.mac_key, self.physical_pages)?;
        let mut st = lock_state(&self.state);
        st.overlay = overlay;
        st.logical_pages = logical;
        st.refresh_gen = st.refresh_gen.wrapping_add(1);
        Ok(())
    }
}

/// 锁 WalState (poison 恢复: xRead 不该 panic, 但即便有也不崩, 取内部值).
fn lock_state(state: &Mutex<WalState>) -> std::sync::MutexGuard<'_, WalState> {
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// C 侧文件对象: 首字段必须是 `sqlite3_file` (SQLite 把本结构指针当 `sqlite3_file*`), 尾随我们的数据指针.
#[repr(C)]
struct CipherFile {
    base: ffi::sqlite3_file,
    data: *mut CipherData,
}

// 打开加密库前, 把派生好的 key 放线程本地; xOpen (同线程同步调用) 取走. 避免 key 进 URI/日志.
thread_local! {
    static PENDING: RefCell<Option<CipherData>> = const { RefCell::new(None) };
}

// ---- 派生 key (与 decrypt.rs 同: EncKey 直用 / Passphrase + salt PBKDF2) ----

fn derive_keys(salt: &[u8; 16], key: &KeyMaterial, rounds: u32) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    // §9: 走进程内派生 key 缓存 —— 同 (master-key, salt, rounds) 重开跳过 PBKDF2-256000 (~3s)。字节等价原派生。
    crate::keycache::derive_keys_cached(key, salt, rounds)
}

// ---- VFS / io_methods 单例 (注册一次) ----

static REGISTER: Once = Once::new();

/// 确保 "wxcipher" VFS 已注册 (幂等). 返回是否可用.
fn ensure_registered() -> Result<(), SqlcipherError> {
    REGISTER.call_once(|| {
        // Box::leak 让 vfs 结构永久存活 (SQLite 持其指针).
        let vfs = Box::leak(Box::new(ffi::sqlite3_vfs {
            iVersion: 1,
            szOsFile: std::mem::size_of::<CipherFile>() as c_int,
            mxPathname: 1024,
            pNext: ptr::null_mut(),
            zName: VFS_NAME.as_ptr().cast::<c_char>(),
            pAppData: ptr::null_mut(),
            xOpen: Some(x_open),
            xDelete: Some(x_delete),
            xAccess: Some(x_access),
            xFullPathname: Some(x_full_pathname),
            xDlOpen: None,
            xDlError: None,
            xDlSym: None,
            xDlClose: None,
            xRandomness: Some(x_randomness),
            xSleep: Some(x_sleep),
            xCurrentTime: Some(x_current_time),
            xGetLastError: Some(x_get_last_error),
            xCurrentTimeInt64: None,
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        }));
        unsafe {
            ffi::sqlite3_vfs_register(vfs as *mut ffi::sqlite3_vfs, 0);
        }
    });
    Ok(())
}

/// 默认 VFS (委托 xRandomness/xSleep/xCurrentTime; 这些不碰文件).
unsafe fn default_vfs() -> *mut ffi::sqlite3_vfs {
    ffi::sqlite3_vfs_find(ptr::null())
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(io_close),
    xRead: Some(io_read),
    xWrite: Some(io_write),
    xTruncate: Some(io_truncate),
    xSync: Some(io_sync),
    xFileSize: Some(io_file_size),
    xLock: Some(io_lock_noop),
    xUnlock: Some(io_lock_noop),
    xCheckReservedLock: Some(io_check_reserved_lock),
    xFileControl: Some(io_file_control),
    xSectorSize: Some(io_sector_size),
    xDeviceCharacteristics: Some(io_device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

// ---- io_methods 回调 ----

unsafe extern "C" fn io_close(file: *mut ffi::sqlite3_file) -> c_int {
    let cf = file.cast::<CipherFile>();
    if !(*cf).data.is_null() {
        drop(Box::from_raw((*cf).data)); // 关文件 + 清 key (Zeroizing).
        (*cf).data = ptr::null_mut();
    }
    ffi::SQLITE_OK
}

/// 核心: 逐页解密. SQLite 读 `[iOfst, iOfst+iAmt)`, 可能跨页 / 页内偏移 (如首 100B header).
#[allow(non_snake_case)] // C ABI 参数名沿用 SQLite 约定.
unsafe extern "C" fn io_read(
    file: *mut ffi::sqlite3_file,
    buf: *mut c_void,
    iAmt: c_int,
    iOfst: ffi::sqlite3_int64,
) -> c_int {
    let cf = file.cast::<CipherFile>();
    let data = &*(*cf).data;
    let amt = usize::try_from(iAmt).unwrap_or(0);
    let ofst = u64::try_from(iOfst).unwrap_or(0);
    let out = std::slice::from_raw_parts_mut(buf.cast::<u8>(), amt);

    let page_sz = PAGE as u64;
    let first_page = ofst / page_sz; // 0-based
    let last_page = (ofst + amt as u64 - 1) / page_sz;
    let mut short = false;

    let st = lock_state(&data.state); // 锁一次 WAL 前沿状态 (overlay + refresh_gen), 遍历本次读的页.
    for p0 in first_page..=last_page {
        let pgno = (p0 + 1) as u32; // 1-based
        let mut plain = [0u8; PAGE];
        match read_decrypt_page(data, &st, pgno, &mut plain) {
            Ok(true) => {}
            Ok(false) => short = true, // 越界: plain 保持 0 (SQLite short read 语义).
            Err(_) => return ffi::SQLITE_IOERR_READ, // 坏页 (key 错 / 撕裂): 让 SQLite 报错, 上层重试.
        }
        // 拷本页与请求区间的交集到 out.
        let page_start = p0 * page_sz;
        let copy_lo = ofst.max(page_start);
        let copy_hi = (ofst + amt as u64).min(page_start + page_sz);
        if copy_lo < copy_hi {
            let dst_off = (copy_lo - ofst) as usize;
            let src_off = (copy_lo - page_start) as usize;
            let n = (copy_hi - copy_lo) as usize;
            out[dst_off..dst_off + n].copy_from_slice(&plain[src_off..src_off + n]);
        }
    }
    if short {
        // 越界部分已是 0; SQLite 约定短读返回 SHORT_READ.
        ffi::SQLITE_IOERR_SHORT_READ
    } else {
        ffi::SQLITE_OK
    }
}

/// 读加密页 pgno 并解密进 `out` (4096B). 返回 Ok(true)=成功, Ok(false)=越界(全0), Err=坏页.
/// `st`: 当前 WAL 前沿 (overlay 命中返最新前沿页; page1 叠 `refresh_gen` 到 change-counter).
fn read_decrypt_page(
    data: &CipherData,
    st: &WalState,
    pgno: u32,
    out: &mut [u8; PAGE],
) -> Result<bool, SqlcipherError> {
    // WAL overlay 命中 → 返最新前沿页 (已解密, 未 checkpoint 的最新数据).
    if let Some(pg) = st.overlay.get(&pgno) {
        out.copy_from_slice(pg);
    } else {
        let idx = u64::from(pgno) - 1;
        if idx >= data.physical_pages {
            return Ok(false); // 不在主库物理范围又不在 overlay: 越界 (全 0).
        }
        let mut enc = [0u8; PAGE];
        read_exact_at(&data.file, &mut enc, idx * PAGE as u64)?;
        if u64::from(pgno) == LOCK_BYTE_PAGE {
            out.copy_from_slice(&enc); // lock-byte: 未加密原样 (无 header patch).
            return Ok(true);
        }
        verify_page_hmac(&data.mac_key, &enc, pgno)?;
        decrypt_page_into(&data.enc_key, &enc, pgno == 1, pgno, out)?;
    }
    if pgno == 1 {
        // page1: 改 header 为 rollback → SQLite 不找 -wal (我们自己叠加 WAL).
        out[18] = 1;
        out[19] = 1;
        // 把 refresh_gen 叠到 file change-counter (offset 24, big-endian) → 每次 refresh 后 SQLite 发现 page1
        // 变了 → 丢页缓存重读拿新 overlay 数据; schema cookie (offset 40) 不变 → 保留已解析 schema (省重解).
        let orig = u32::from_be_bytes([out[24], out[25], out[26], out[27]]);
        out[24..28].copy_from_slice(&orig.wrapping_add(st.refresh_gen).to_be_bytes());
    }
    Ok(true)
}

/// 按偏移读满 `buf` (Windows `seek_read` / Unix `read_at`; 都可能短读, 这里循环补齐)。
///
/// ⚠️ 两个平台**并不完全等价**: Windows 的 `seek_read` **会**把文件指针移到读完的位置, Unix 的
/// `read_at` 不会。本模块不依赖那个指针(整个 vfs 里这个 `File` 只被本函数用), 所以无害 —— 但别把
/// 「不改文件指针」当成契约写进注释(旧注释就是这么写的, 是错的)。
fn read_exact_at(file: &File, buf: &mut [u8], mut offset: u64) -> Result<(), SqlcipherError> {
    // 被信号打断的重试次数上限。std 自己的 `read_exact_at` 是**无限**重试的 —— 那对应用代码没问题,
    // 但本函数跑在**服务里的解密读**路径上: 万一中断持续出现(病态的信号风暴), 无限重试就是整个
    // 请求线程卡死, 而卡死比报错难查得多。给个上限, 超了就当成真错误报上去。
    // 1024 远大于任何正常场景(EINTR 是瞬时的, 通常一两次就过), 到不了这个数说明真出事了。
    const MAX_INTERRUPTED_RETRIES: u32 = 1024;
    let mut filled = 0;
    let mut interrupted = 0u32;
    while filled < buf.len() {
        #[cfg(windows)]
        let r = file.seek_read(&mut buf[filled..], offset);
        #[cfg(unix)]
        let r = file.read_at(&mut buf[filled..], offset);
        match r {
            Ok(0) => break, // EOF (末页不足一页: 余下保持 0).
            Ok(n) => {
                filled += n;
                offset += n as u64;
                interrupted = 0; // 成功读一次就复位 —— 上限说的是「**连续**被打断」, 不是整次调用累计
            }
            // 被信号打断要**重试**, 不是报错 —— std 自己的 read_exact_at 就是这么处理的。
            // Unix 上 `read_at` 会返回 Interrupted; 不重试的话一次普通信号就能让解密读失败。
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                interrupted += 1;
                if interrupted > MAX_INTERRUPTED_RETRIES {
                    return Err(SqlcipherError::Io(format!(
                        "vfs read: 被信号连续打断超过 {MAX_INTERRUPTED_RETRIES} 次, 判定为真错误(否则会无限重试卡死)"
                    )));
                }
                // 不推进 filled/offset, 下一轮重读同一段。
            }
            Err(e) => return Err(SqlcipherError::Io(format!("vfs read: {e}"))),
        }
    }
    Ok(())
}

#[allow(non_snake_case)] // C ABI 参数名沿用 SQLite 约定.
unsafe extern "C" fn io_write(
    _file: *mut ffi::sqlite3_file,
    _buf: *const c_void,
    _iAmt: c_int,
    _iOfst: ffi::sqlite3_int64,
) -> c_int {
    ffi::SQLITE_READONLY // 只读: 绝不写微信库.
}

unsafe extern "C" fn io_truncate(_file: *mut ffi::sqlite3_file, _size: ffi::sqlite3_int64) -> c_int {
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn io_sync(_file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    ffi::SQLITE_OK // 只读无需 sync.
}

unsafe extern "C" fn io_file_size(file: *mut ffi::sqlite3_file, p_size: *mut ffi::sqlite3_int64) -> c_int {
    let cf = file.cast::<CipherFile>();
    let data = &*(*cf).data;
    // 逻辑大小 = max(物理, WAL 提交后页数) —— WAL 可让库增长超过主库物理长度 (随 refresh 变).
    let logical = lock_state(&data.state).logical_pages;
    *p_size = i64::try_from(logical * PAGE as u64).unwrap_or(i64::MAX);
    ffi::SQLITE_OK
}

// 只读单连接: 无需真锁 (SQLite 会调 xLock/xUnlock, noop 即可).
unsafe extern "C" fn io_lock_noop(_file: *mut ffi::sqlite3_file, _lock: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_check_reserved_lock(_file: *mut ffi::sqlite3_file, p_res: *mut c_int) -> c_int {
    *p_res = 0; // 无保留锁.
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_file_control(_file: *mut ffi::sqlite3_file, _op: c_int, _arg: *mut c_void) -> c_int {
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn io_sector_size(_file: *mut ffi::sqlite3_file) -> c_int {
    PAGE as c_int
}

unsafe extern "C" fn io_device_characteristics(_file: *mut ffi::sqlite3_file) -> c_int {
    // 只读, 无特殊特性.
    0
}

// ---- vfs 回调 ----

unsafe extern "C" fn x_open(
    _vfs: *mut ffi::sqlite3_vfs,
    _z_name: *const c_char,
    file: *mut ffi::sqlite3_file,
    _flags: c_int,
    p_out_flags: *mut c_int,
) -> c_int {
    // 取线程本地 PENDING (open_decrypted_vfs 已放好该库的 key+file).
    let data = PENDING.with(|p| p.borrow_mut().take());
    let Some(data) = data else {
        return ffi::SQLITE_CANTOPEN; // 无 pending: 非预期 (只该主库经此).
    };
    let cf = file.cast::<CipherFile>();
    (*cf).base.pMethods = &IO_METHODS as *const ffi::sqlite3_io_methods;
    (*cf).data = Box::into_raw(Box::new(data));
    if !p_out_flags.is_null() {
        *p_out_flags = ffi::SQLITE_OPEN_READONLY;
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn x_delete(_vfs: *mut ffi::sqlite3_vfs, _z_name: *const c_char, _sync_dir: c_int) -> c_int {
    ffi::SQLITE_READONLY // 只读 VFS 不删.
}

/// `-wal`/`-shm`/`-journal` 返 false → SQLite 走 rollback 只读主库; 主库 EXISTS 返 true.
unsafe extern "C" fn x_access(
    _vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    _flags: c_int,
    p_res_out: *mut c_int,
) -> c_int {
    let name = CStr::from_ptr(z_name).to_string_lossy();
    let n = name.as_ref();
    if n.ends_with("-wal") || n.ends_with("-shm") || n.ends_with("-journal") {
        *p_res_out = 0;
    } else {
        *p_res_out = i32::from(Path::new(n).exists());
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn x_full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    n_out: c_int,
    z_out: *mut c_char,
) -> c_int {
    // 已是绝对路径 (调用方给绝对路径); 原样拷贝.
    let src = CStr::from_ptr(z_name).to_bytes_with_nul();
    let cap = usize::try_from(n_out).unwrap_or(0);
    if src.len() > cap {
        return ffi::SQLITE_CANTOPEN;
    }
    ptr::copy_nonoverlapping(src.as_ptr().cast::<c_char>(), z_out, src.len());
    ffi::SQLITE_OK
}

unsafe extern "C" fn x_randomness(_vfs: *mut ffi::sqlite3_vfs, n_byte: c_int, z_out: *mut c_char) -> c_int {
    let d = default_vfs();
    ((*d).xRandomness.unwrap())(d, n_byte, z_out)
}

unsafe extern "C" fn x_sleep(_vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    let d = default_vfs();
    ((*d).xSleep.unwrap())(d, microseconds)
}

unsafe extern "C" fn x_current_time(_vfs: *mut ffi::sqlite3_vfs, p_time: *mut f64) -> c_int {
    let d = default_vfs();
    ((*d).xCurrentTime.unwrap())(d, p_time)
}

unsafe extern "C" fn x_get_last_error(_vfs: *mut ffi::sqlite3_vfs, _n: c_int, _z: *mut c_char) -> c_int {
    0
}

// ---- 公开入口 ----

/// 用 **按需解密 VFS** 打开加密库 → `(只读 Connection, WAL 就地刷新句柄)` (**低内存, 不整库解密, 不落盘**).
///
/// 每次查询只解 SQLite 碰到的页 (峰值内存 = 页缓存, 几十 MB), 含 WAL 前沿 overlay。返回的
/// [`WalRefreshHandle`] 供实时监听: 该库 WAL 变了调 [`WalRefreshHandle::refresh`] 只重建 overlay
/// (**不重开连接、不重读 schema** → 大账号省 ~3s)。
///
/// # Errors
/// [`SqlcipherError`] — 读文件 / 太小 / 首页 HMAC (key 错) / sqlite 打开失败.
pub fn open_conn_vfs(
    enc_db_path: &Path,
    key: &KeyMaterial,
    rounds: u32,
) -> Result<(rusqlite::Connection, WalRefreshHandle), SqlcipherError> {
    ensure_registered()?;

    let file = File::open(enc_db_path).map_err(|e| SqlcipherError::Io(format!("{}: {e}", file_name(enc_db_path))))?;
    let len = file
        .metadata()
        .map_err(|e| SqlcipherError::Io(format!("{}: {e}", file_name(enc_db_path))))?
        .len();
    if len < PAGE as u64 {
        return Err(SqlcipherError::TooSmall(PAGE));
    }

    // 读 salt (前 16B) 派生 key.
    let mut salt = [0u8; 16];
    read_exact_at(&file, &mut salt, 0)?;
    let (enc_key, mac_key) = derive_keys(&salt, key, rounds);
    let physical_pages = len / PAGE as u64;

    // 首页 HMAC 预检 (key 错早报, 语义同 open_decrypted 的首页校验).
    {
        let mut p1 = [0u8; PAGE];
        read_exact_at(&file, &mut p1, 0)?;
        verify_page_hmac(&mac_key, &p1, 1).map_err(|_| SqlcipherError::PageHmacMismatch { page_num: 1 })?;
    }

    // 构建 WAL overlay (已提交前沿页 + 逻辑大小); WAL 缺失/无提交 → 空 overlay + logical=physical.
    let wal_path = wal_sibling(enc_db_path);
    let (overlay, logical_pages, _skipped) = build_wal_overlay(&wal_path, &enc_key, &mac_key, physical_pages)?;

    // 共享 WAL 前沿状态 (xRead 读 / refresh 写); refresh 句柄持 rebuild 输入 + 同一 Arc.
    let state = Arc::new(Mutex::new(WalState {
        overlay,
        logical_pages,
        refresh_gen: 0,
    }));
    let handle = WalRefreshHandle {
        state: Arc::clone(&state),
        wal_path,
        enc_key: enc_key.clone(),
        mac_key: mac_key.clone(),
        physical_pages,
    };

    PENDING.with(|p| {
        *p.borrow_mut() = Some(CipherData {
            file,
            enc_key,
            mac_key,
            physical_pages,
            state,
        });
    });

    // 只读 + 我们的 VFS 打开. NO_MUTEX 无所谓 (只读单线程用).
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY;
    let vfs = std::str::from_utf8(&VFS_NAME[..VFS_NAME.len() - 1]).unwrap();
    let conn = rusqlite::Connection::open_with_flags_and_vfs(enc_db_path, flags, vfs).map_err(|e| {
        // 清掉可能残留的 PENDING (open 失败时 xOpen 可能没取走).
        PENDING.with(|p| *p.borrow_mut() = None);
        SqlcipherError::Sqlite(format!("open_with_vfs: {e}"))
    })?;
    conn.execute_batch("PRAGMA query_only = ON; PRAGMA temp_store = MEMORY;")
        .map_err(|e| SqlcipherError::Sqlite(format!("pragma: {e}")))?;
    Ok((conn, handle))
}

fn file_name(p: &Path) -> String {
    p.file_name().and_then(|s| s.to_str()).unwrap_or("<db>").to_string()
}
