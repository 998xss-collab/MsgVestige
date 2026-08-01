//! reconcile — 逐表内容对账 (ADR-428 M3-d 收尾: native 解密 vs 竞品解密结果逐表比).
//!
//! 输入两个**已打开的只读** `Connection` (一个是 native 解密的加密库, 一个是竞品/WDA 解密的明文库),
//! 逐张**共有表**比 row count + 全表内容 SHA-256 digest。用于确认 native 解密与竞品**逐字节一致**:
//! - **封存分片** (如 `message_0.db` 写满不再变·两份大小完全相同) → 期望**逐表全等**。
//! - **有时间增长的库** (如 `contact.db`) → 总数会差, 用子集语义 (竞品那份的行在 native 里都在且一致) 另论,
//!   本模块只给"逐表全量 digest 比"原语, 增长库的子集判断由调用方按业务定 (先做封存分片)。
//!
//! K-R4: digest 只吐十六进制哈希, 不吐明文行 / 列值。

use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// 一张表在两库里的对账结果。
#[derive(Debug, Clone)]
pub struct TableCompare {
    pub table: String,
    pub enc_rows: usize,
    pub plain_rows: usize,
    /// 全表内容 SHA-256 (十六进制)。
    pub enc_digest: String,
    pub plain_digest: String,
}

impl TableCompare {
    /// 逐字节一致 = 行数相同且内容 digest 相同。
    #[must_use]
    pub fn matches(&self) -> bool {
        self.enc_rows == self.plain_rows && self.enc_digest == self.plain_digest
    }
}

/// 库里所有**用户表** (排除 sqlite_ 内部表; fts 影子表按需另过滤, 这里保留)。
fn user_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    rows.collect()
}

/// 一张表的 `(row_count, content_digest)` — `SELECT * ORDER BY rowid`, digest 起手喂**列数**,
/// 再逐行逐列 **类型标签 + (Text/Blob 8 字节 LE 长度前缀) + 值** 喂 SHA-256。
/// 类型标签防 `int 12` 撞 `text "12"`; 长度前缀防 `"ab"+"c"` 撞 `"a"+"bc"`; 列数入 digest 封跨 schema 碰撞 (双审 P2)。
///
/// **前提** (双审): ① 表须有 `rowid` (`ORDER BY rowid`; 微信 Msg_/contact/session 均有);
///   `WITHOUT ROWID` 表会报 "no such column: rowid" **使该轮对账失败** (无回退, 需 `--only` 排除)。
/// ② 两库须是**同一物理封存文件**的两路解密 — rowid 持久在 B-tree, 同源必一致; 各自 `VACUUM`/`REINDEX`
///   过的副本 rowid 会重排 → 同内容不同序 → 假阳, 不可用。
///
/// # Errors
/// 表不存在 / `WITHOUT ROWID` (rowid 列不存在) / SQL 失败 / 列读取失败。
pub fn table_digest(conn: &Connection, table: &str) -> rusqlite::Result<(usize, String)> {
    // 表名来自 sqlite_master (可信来源), 仍用双引号包 + 转义内嵌引号防注入/特殊名。
    let sql = format!("SELECT * FROM \"{}\" ORDER BY rowid", table.replace('"', "\"\""));
    let mut stmt = conn.prepare(&sql)?;
    let ncol = stmt.column_count();
    let mut hasher = Sha256::new();
    // 列数入 digest: 封"两库同名表列数不同"的碰撞面 + 让 schema 列数差异体现在 digest (双审 P2)。
    hasher.update((ncol as u64).to_le_bytes());
    let mut count = 0usize;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        for i in 0..ncol {
            use rusqlite::types::ValueRef;
            match row.get_ref(i)? {
                ValueRef::Null => hasher.update(b"\x00N"),
                ValueRef::Integer(n) => {
                    hasher.update(b"\x00I");
                    hasher.update(n.to_le_bytes());
                }
                ValueRef::Real(f) => {
                    hasher.update(b"\x00R");
                    hasher.update(f.to_le_bytes());
                }
                ValueRef::Text(t) => {
                    hasher.update(b"\x00T");
                    hasher.update((t.len() as u64).to_le_bytes());
                    hasher.update(t);
                }
                ValueRef::Blob(b) => {
                    hasher.update(b"\x00B");
                    hasher.update((b.len() as u64).to_le_bytes());
                    hasher.update(b);
                }
            }
        }
        count += 1;
    }
    Ok((count, hex::encode(hasher.finalize())))
}

/// 对账报告 — 逐表比对 + 两库表集合**对称差** (双审 P1: 表集合差异不能静默假定相同)。
#[derive(Debug, Clone)]
pub struct ReconcileReport {
    /// 共有表 (或 `--only` 过滤后) 的逐表比对。
    pub compares: Vec<TableCompare>,
    /// 仅加密库有、明文库无的表 (native 当前 vs 旧快照 = 新增会话; 或真缺表)。
    pub enc_only: Vec<String>,
    /// 仅明文库有、加密库无的表。
    pub plain_only: Vec<String>,
}

impl ReconcileReport {
    /// 全等 = 每张比对表逐字节一致 **且** 两库表集合相同 (无对称差)。
    #[must_use]
    pub fn all_match(&self) -> bool {
        self.enc_only.is_empty() && self.plain_only.is_empty() && self.compares.iter().all(TableCompare::matches)
    }
}

/// 逐张**共有表**对账 + 记录表集合对称差。`only` 给定则 `compares` 只含这些表 (交集内);
/// 对称差 (`enc_only`/`plain_only`) 始终按**全表集合**算 (不受 `only` 影响, 反映真实表集合差异)。
///
/// # Errors
/// 枚举表 / 某表 digest 计算失败 (含 `WITHOUT ROWID` 表的 rowid 报错)。
pub fn reconcile_tables(
    enc: &Connection,
    plain: &Connection,
    only: Option<&[String]>,
) -> rusqlite::Result<ReconcileReport> {
    use std::collections::BTreeSet;
    let enc_tabs: BTreeSet<String> = user_tables(enc)?.into_iter().collect();
    let plain_tabs: BTreeSet<String> = user_tables(plain)?.into_iter().collect();
    let enc_only: Vec<String> = enc_tabs.difference(&plain_tabs).cloned().collect();
    let plain_only: Vec<String> = plain_tabs.difference(&enc_tabs).cloned().collect();
    let mut common: Vec<String> = enc_tabs.intersection(&plain_tabs).cloned().collect();
    if let Some(sel) = only {
        common.retain(|t| sel.iter().any(|s| s == t));
    }
    let mut compares = Vec::with_capacity(common.len());
    for t in common {
        let (er, ed) = table_digest(enc, &t)?;
        let (pr, pd) = table_digest(plain, &t)?;
        compares.push(TableCompare {
            table: t,
            enc_rows: er,
            plain_rows: pr,
            enc_digest: ed,
            plain_digest: pd,
        });
    }
    Ok(ReconcileReport {
        compares,
        enc_only,
        plain_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(sql: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(sql).unwrap();
        c
    }

    /// 相同内容 + 同表集合 → all_match()=true。
    #[test]
    fn identical_tables_match() {
        let a = mk("CREATE TABLE t(x INTEGER, s TEXT, b BLOB); INSERT INTO t VALUES (1,'hi',x'41'),(2,'yo',NULL);");
        let b = mk("CREATE TABLE t(x INTEGER, s TEXT, b BLOB); INSERT INTO t VALUES (1,'hi',x'41'),(2,'yo',NULL);");
        let r = reconcile_tables(&a, &b, None).unwrap();
        assert_eq!(r.compares.len(), 1);
        assert!(r.all_match(), "同内容 + 同表集合应全等");
        assert_eq!(r.compares[0].enc_rows, 2);
    }

    /// 一行内容不同 → digest 不同、matches()=false。
    #[test]
    fn one_diff_row_mismatch() {
        let a = mk("CREATE TABLE t(x, s); INSERT INTO t VALUES (1,'hi'),(2,'yo');");
        let b = mk("CREATE TABLE t(x, s); INSERT INTO t VALUES (1,'hi'),(2,'YO');");
        let r = reconcile_tables(&a, &b, None).unwrap();
        assert!(!r.compares[0].matches(), "内容不同应不一致");
        assert_eq!(r.compares[0].enc_rows, r.compares[0].plain_rows, "行数仍相同");
    }

    /// 类型区分: int 12 不撞 text '12'。
    #[test]
    fn int_not_equal_text() {
        let a = mk("CREATE TABLE t(v); INSERT INTO t VALUES (12);");
        let b = mk("CREATE TABLE t(v); INSERT INTO t VALUES ('12');");
        let r = reconcile_tables(&a, &b, None).unwrap();
        assert!(!r.compares[0].matches(), "int 12 不应等于 text '12'");
    }

    /// 长度前缀: ('ab','c') 不撞 ('a','bc')。
    #[test]
    fn length_prefix_no_concat_ambiguity() {
        let a = mk("CREATE TABLE t(p, q); INSERT INTO t VALUES ('ab','c');");
        let b = mk("CREATE TABLE t(p, q); INSERT INTO t VALUES ('a','bc');");
        let r = reconcile_tables(&a, &b, None).unwrap();
        assert!(!r.compares[0].matches(), "拼接歧义应被长度前缀挡住");
    }

    /// only 过滤: 只对指定表 (交集内)。
    #[test]
    fn only_filters_tables() {
        let a = mk("CREATE TABLE t1(x); INSERT INTO t1 VALUES(1); CREATE TABLE t2(y); INSERT INTO t2 VALUES(9);");
        let b = mk("CREATE TABLE t1(x); INSERT INTO t1 VALUES(1); CREATE TABLE t2(y); INSERT INTO t2 VALUES(8);");
        let only = vec!["t1".to_string()];
        let r = reconcile_tables(&a, &b, Some(&only)).unwrap();
        assert_eq!(r.compares.len(), 1);
        assert_eq!(r.compares[0].table, "t1");
        assert!(r.compares[0].matches());
    }

    /// 双审 P1: 表集合对称差 — 一边独有表要记录, all_match()=false (不静默假定表集合相同)。
    #[test]
    fn table_set_asymmetry_detected() {
        let a = mk("CREATE TABLE shared(x); INSERT INTO shared VALUES(1); CREATE TABLE enc_extra(z); INSERT INTO enc_extra VALUES(7);");
        let b = mk("CREATE TABLE shared(x); INSERT INTO shared VALUES(1); CREATE TABLE plain_extra(w); INSERT INTO plain_extra VALUES(8);");
        let r = reconcile_tables(&a, &b, None).unwrap();
        assert_eq!(r.compares.len(), 1, "只 shared 是共有表");
        assert!(r.compares[0].matches(), "shared 内容一致");
        assert_eq!(r.enc_only, vec!["enc_extra".to_string()], "加密库独有表被记录");
        assert_eq!(r.plain_only, vec!["plain_extra".to_string()], "明文库独有表被记录");
        assert!(!r.all_match(), "有对称差 → 不算全等 (双审 P1)");
    }

    /// 双审 P2: 列数入 digest — 同名表列数不同应体现为不一致。
    #[test]
    fn column_count_in_digest() {
        let a = mk("CREATE TABLE t(p); INSERT INTO t VALUES('ab');");
        let b = mk("CREATE TABLE t(p, q); INSERT INTO t VALUES('a','b');");
        let r = reconcile_tables(&a, &b, None).unwrap();
        assert!(!r.compares[0].matches(), "列数不同应体现在 digest → 不一致");
    }
}
