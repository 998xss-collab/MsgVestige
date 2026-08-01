//! reader.rs — 解密后明文 image → 内存 sqlite (只读), 读出真实行. **不落盘** (ADR-423 §7).
//!
//! NOCOPY 挂载: 直接把解密出的 image (Rust `Vec<u8>`) 交给 sqlite 读, **不再 sqlite3_malloc 拷一份** —
//! 省掉 2× 内存, 且绕开 sqlite ~2GB 单次分配上限 (>2GB 库 malloc 会失败). image `Vec` 由 [`DecryptedDb`]
//! 持有、与 `conn` 同生命周期 (conn 先 Drop 停读、image 后 Drop 释放), sqlite 只读不写不 free.

use rusqlite::{ffi, Connection};

use crate::error::SqlcipherError;

/// 解密后挂载好的只读库 — 持 `conn` (查询用) + 底层 image `Vec` (sqlite 直接读它, 必须同活).
///
/// **字段顺序 = Drop 顺序**: `conn` 先 Drop (关 sqlite、停止读 image), `_image` 后 Drop (释放内存) —
/// 保证 sqlite 读期间 image 一直在, 无 use-after-free.
pub struct DecryptedDb {
    conn: Connection,
    /// sqlite (conn) 经 NOCOPY deserialize 直接读这块; 不能提前释放. 移动 `DecryptedDb` 安全
    /// (Vec 移动只搬 ptr/len/cap, 堆数据地址不变, sqlite 持的指针仍有效).
    _image: Vec<u8>,
}

impl DecryptedDb {
    /// 取只读连接跑 query.
    #[must_use]
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

/// 把解密后的明文 image 只读挂载进内存 sqlite (NOCOPY, 不拷贝), 返回 [`DecryptedDb`].
///
/// image 被 move 进返回值持有, sqlite 直接读它 (不 sqlite3_malloc、不撞 2GB 上限). 峰值内存 ≈ 1× image.
///
/// # Errors
/// [`SqlcipherError::Sqlite`] — deserialize / 打开 / PRAGMA 失败, 或 image 超 i64.
pub fn open_image(mut image: Vec<u8>) -> Result<DecryptedDb, SqlcipherError> {
    // WAL 模式 db (header[18]/[19] = write/read version = 2) 内存挂载会 CannotOpen (内存 db 开不了
    // WAL、也没 -wal 文件); image 是 owned, 直接改回 rollback(1). 我们只读, journal 标志对读无影响.
    if image.len() >= 20 {
        image[18] = 1;
        image[19] = 1;
    }
    let sz = i64::try_from(image.len()).map_err(|_| SqlcipherError::Sqlite("image 超 i64 上限".into()))?;
    let conn = Connection::open_in_memory()?;
    // NOCOPY: sqlite 直接读 image 这块 (不 copy、不 sqlite3_malloc → 绕开 sqlite ~2GB 单次分配上限);
    // READONLY 只读、无 FREEONCLOSE → sqlite 不写不 free, image Vec 自己管生命周期.
    // SAFETY: conn.handle() 是有效 sqlite3*; image.as_ptr() 指向的堆活到 conn Drop 之后 (DecryptedDb
    //   字段序 conn 先 Drop、_image 后 Drop); READONLY 保证不写 image; szDb==szBuf==sz、无 RESIZEABLE
    //   → sqlite 不 realloc image.
    let rc = unsafe {
        ffi::sqlite3_deserialize(
            conn.handle(),
            c"main".as_ptr(),
            image.as_ptr() as *mut u8,
            sz,
            sz,
            ffi::SQLITE_DESERIALIZE_READONLY,
        )
    };
    if rc != ffi::SQLITE_OK {
        return Err(SqlcipherError::Sqlite(format!("sqlite3_deserialize rc={rc}")));
    }
    // 严格不落盘: 临时数据进内存 (防 ORDER BY / 大结果集落临时明文文件) + query_only 双保险只读.
    conn.execute_batch("PRAGMA temp_store = MEMORY; PRAGMA query_only = ON;")?;
    Ok(DecryptedDb { conn, _image: image })
}

#[cfg(test)]
mod tests {
    use rusqlite::DatabaseName;

    use super::*;

    /// deserialize 往返: rusqlite 造明文 db image → open_image (NOCOPY) 读回行.
    #[test]
    fn open_image_reads_rows() {
        let src = Connection::open_in_memory().unwrap();
        src.execute_batch("CREATE TABLE t(a INTEGER, b TEXT); INSERT INTO t VALUES (1,'hi'),(2,'yo');")
            .unwrap();
        let image: Vec<u8> = src.serialize(DatabaseName::Main).unwrap().to_vec();

        let db = open_image(image).unwrap();
        let n: i64 = db.conn().query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
        let b: String = db
            .conn()
            .query_row("SELECT b FROM t WHERE a=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(b, "hi");
    }

    /// 只读: NOCOPY READONLY + query_only 后写应失败.
    #[test]
    fn open_image_is_read_only() {
        let src = Connection::open_in_memory().unwrap();
        src.execute_batch("CREATE TABLE t(a); INSERT INTO t VALUES (1);")
            .unwrap();
        let image: Vec<u8> = src.serialize(DatabaseName::Main).unwrap().to_vec();
        let db = open_image(image).unwrap();
        let w = db.conn().execute("INSERT INTO t VALUES (2)", []);
        assert!(w.is_err(), "只读挂载应禁止写");
    }

    /// WAL 模式 header (write/read version=2) 的 image 必须能挂载 (真实微信库都是 WAL 模式). 防回归.
    #[test]
    fn open_image_handles_wal_mode_header() {
        let src = Connection::open_in_memory().unwrap();
        src.execute_batch("CREATE TABLE t(a); INSERT INTO t VALUES (7),(8),(9);")
            .unwrap();
        let mut image: Vec<u8> = src.serialize(DatabaseName::Main).unwrap().to_vec();
        image[18] = 2; // write version = WAL
        image[19] = 2; // read version = WAL
        let db = open_image(image).unwrap();
        let n: i64 = db.conn().query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 3, "WAL header image 应挂载并读出行");
    }
}
