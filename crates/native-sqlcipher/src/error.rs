//! SqlcipherError — 解密 / 读取的错误分类 (ADR-428 §4-b).
//!
//! K-R4: 任何字段不含明文 key / db 内容 / wxid 全路径; page_num 是页号 (非秘密).

/// SQLCipher4 解密 + 内存读取的失败原因.
#[derive(Debug, thiserror::Error)]
pub enum SqlcipherError {
    /// 读加密库文件失败 (只放文件名, 不放含 wxid 的全路径).
    #[error("读加密库失败: {0}")]
    Io(String),

    /// 加密库太小 (不足一页).
    #[error("加密库太小 (不足一页 {0}B)")]
    TooSmall(usize),

    /// 加密库大小非页对齐 (不是 4096 整数倍) — 文件损坏 / 非 SQLCipher 库.
    #[error("加密库大小非页对齐 ({size}B 不是 {page}B 整数倍)")]
    NotPageAligned {
        /// 实际文件字节数.
        size: usize,
        /// 页大小 (4096).
        page: usize,
    },

    /// 某页 HMAC 校验失败 — key 不对该库 / 页损坏. 首页(page_num=1)失败通常是 key 错.
    #[error("第 {page_num} 页 HMAC 校验失败 — key 不对该库 / 页损坏")]
    PageHmacMismatch {
        /// 1-based 页号.
        page_num: u32,
    },

    /// 某页 AES 解密失败 (正文长度非 16 倍数等).
    #[error("第 {page_num} 页 AES 解密失败")]
    Decrypt {
        /// 1-based 页号.
        page_num: u32,
    },

    /// sqlite3_malloc 分配 image 失败 (内存不足).
    #[error("sqlite3_malloc 分配 {0}B 失败")]
    Alloc(usize),

    /// sqlite 读取 / deserialize 失败 (rusqlite 错误转此).
    #[error("sqlite 读取失败: {0}")]
    Sqlite(String),
}

impl From<rusqlite::Error> for SqlcipherError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e.to_string())
    }
}
