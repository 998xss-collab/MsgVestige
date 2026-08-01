//! `cold_messages_query` 的账号谓词与排序次键 —— 868499f + 次键补丁的常驻守卫。
//!
//! 补审指出这两条分支在仓内**零覆盖**(既有 6 个 cold_query 测试全是单账号裸连), 而它们恰好是
//! "既要快、又不能静默只查一个号"这条契约的全部依据。

use rusqlite::Connection;

/// 建一个最小可用的 L1(直接用生产的 `init_l1_schema`, 不手搓 schema —— 手搓就测不到真列/真索引)。
fn l1() -> Connection {
    let c = Connection::open_in_memory().expect("内存库");
    native_core::storage::init_l1_schema(&c).expect("init l1 schema");
    c
}

#[allow(clippy::too_many_arguments)]
fn put(c: &Connection, acct: &str, conv: &str, source: &str, native_id: &str, ct: i64, text: &str) {
    c.execute(
        "INSERT INTO message (account_id_sha, source, source_native_id, conv_id_sha, server_id,
             create_time, sort_seq, status, upload_status, download_status, server_seq, origin_source,
             local_type_raw, msg_type, msg_type_name, msg_sub_type, msg_sub_type_name, sys_type,
             sender_wxid_sha, is_chatroom, text_content_sha, text_content_len,
             raw_xml_present, decode_kind, account_id, conv_id, sender_wxid, text_content)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, 0, 0, 0, 0, 0, 1, 1, 'text', 0, '', '',
                 '', 0, '', 0, 0, 'text', 'me', 'conv', 'sender', ?6)",
        rusqlite::params![
            native_core::sha256_hex(acct),
            source,
            native_id,
            native_core::sha256_hex(conv),
            ct,
            text
        ],
    )
    .expect("插消息");
}

fn texts(c: &Connection, conv: &str, limit: usize, offset: usize) -> Vec<String> {
    native_query::handwritten::cold_messages_query(c, conv, limit, offset)
        .expect("查")
        .data
        .iter()
        .map(|v| v["text"].as_str().unwrap_or("<无 text 键>").to_string())
        .collect()
}

/// **多账号库不许静默只查一个号。**
///
/// 单账号库没有遮蔽视图 → WHERE 里只剩会话 → 索引用不上, 所以查询会在"看得见的账号只有一个"时
/// 把 `account_id_sha` 补进 WHERE。这条锁死反面: 看得见两个账号时**不补**, 两个号的消息都要出来。
/// (补错了的后果是静默丢掉另一个号的全部消息 —— 没有任何报错, 正是最难发现的那类。)
#[test]
fn multi_account_must_not_silently_filter_to_one() {
    let c = l1();
    put(&c, "acct_a", "g@chatroom", "message_0.db", "n1", 100, "A的消息");
    put(&c, "acct_b", "g@chatroom", "message_0.db", "n2", 101, "B的消息");

    let got = texts(&c, "g@chatroom", 10, 0);
    assert_eq!(got.len(), 2, "两个账号的消息都该出来, 实得 {got:?}");
    assert!(
        got.contains(&"A的消息".to_string()) && got.contains(&"B的消息".to_string()),
        "{got:?}"
    );

    let total = native_query::handwritten::cold_messages_query(&c, "g@chatroom", 10, 0)
        .expect("查")
        .meta
        .total_count;
    assert_eq!(total, Some(2), "total 也不能只数一个号的");
}

/// 单账号库照常出全量(补了谓词也不能少行)。
#[test]
fn single_account_still_returns_everything() {
    let c = l1();
    for i in 0..5 {
        put(
            &c,
            "acct_a",
            "g@chatroom",
            "message_0.db",
            &format!("n{i}"),
            100 + i,
            &format!("第{i}条"),
        );
    }
    assert_eq!(texts(&c, "g@chatroom", 10, 0).len(), 5);
    // 空库: MIN/MAX 都是 NULL → 不补谓词 → 0 行, 不炸。
    assert_eq!(texts(&l1(), "g@chatroom", 10, 0).len(), 0, "空库该返 0 行而不是报错");
}

// ⚠️ **这里本来有一条"并列行翻页不重不漏"的测试, 删了 —— 它是假守卫。**
//
// 我造了同会话跨两分片、native_id 与 create_time 全相同的并列行, 断言逐页拼接等于全量。
// 它绿。但**把 `source DESC` 从 ORDER BY 里撤掉之后它照样绿** —— 反向验证当场戳穿。
//
// 原因: 静态库上 SQLite 的查询计划是确定的, 同一条 SQL 每次都给出同一个顺序, 于是并列行在
// 页边界上并不会真的重复或丢失。这类测试只有在计划会变(数据量变化触发换索引、ANALYZE、
// 并发写)时才可能红 —— 而那正是它测不到的场景。
//
// 仓库里早有这条教训(offset 翻页次键 SOP): **按"次键唯一"的原则修, 不靠复现测**。
// `ORDER BY` 必须带满 L1 主键尾 `(source, source_native_id)`, 因为一个会话跨多分片是常态、
// 两边 local_id 会重号。真要验只能在真库上找并列行实测, 不是合成夹具能担保的。

/// **`total_count` 必须和实际返回的行数出自同一套过滤条件。**
///
/// 取行那条 SQL 和数总数那条 SQL 是**分开写**的 —— 一个补了账号条件另一个没补, 就会出现
/// "说共 210 万条、实际只返回其中一个账号的" 这种对不上, 而且**两条 SQL 各自看都没错**。
///
/// ⚠️ **说清楚这条能守什么、守不了什么** —— 我试着破坏它, 破坏不了, 所以别把它当强守卫:
///
/// 反向验时我把 COUNT 那一路的账号条件废掉, 三条测试仍全绿。查下来是两层原因:
/// 1. 本夹具是**两个账号**, 那时代码走的是"不补条件"那一支 —— 我破坏的"补条件"那一支根本没执行到;
/// 2. 更根本的: **单账号库里补不补账号条件, 结果完全一样**(所有行都属于那一个账号)。
///    所以"一路补了一路没补 → 总数和行数对不上"这种事, 在当前结构下根本发生不了 ——
///    两条 SQL 读的是同一个 `sole_account`, 要么都补要么都不补。
///
/// 那这条还留着干什么: 它钉住「**在 limit 够大、offset 为 0 时** total 等于实际行数」。
/// ⚠️ 注意这**不是这个函数的通用不变量** —— 翻页时 total 必然大于本页行数(审查方 P3-7 指出我上一版
/// 把它写成了"不变量", 会让下一个人以为翻页也该满足)。将来若有人改成「总数走另一套过滤」
/// (比如为了省时间跳过某些行), 这条会红。它守的是**结构别被改坏**, 不是"现在有 bug"。
///
/// 真正需要提防的那个洞不在这里, 而是探测 `sole_account` 的 MIN/MAX 是两条语句、两个读快照 ——
/// 并发插入第二个账号时可能误判成单账号, 那时**总数和行数会一起错**, 反而更难发现(见下面那条)。
#[test]
fn total_count_and_returned_rows_use_the_same_filter() {
    for (n_a, n_b) in [(3usize, 1usize), (1, 4)] {
        let c = l1();
        for i in 0..n_a {
            put(
                &c,
                "acct_a",
                "g@chatroom",
                "message_0.db",
                &format!("a{i}"),
                100 + i as i64,
                "A",
            );
        }
        for i in 0..n_b {
            put(
                &c,
                "acct_b",
                "g@chatroom",
                "message_0.db",
                &format!("b{i}"),
                200 + i as i64,
                "B",
            );
        }
        let r = native_query::handwritten::cold_messages_query(&c, "g@chatroom", 100, 0).expect("查");
        assert_eq!(
            r.meta.total_count,
            Some(r.data.len() as u64),
            "总数与实际行数对不上(A {n_a} 条 / B {n_b} 条): 两条 SQL 的过滤条件不一致 —— \
             一个补了账号条件另一个没补。实得 total={:?} rows={}",
            r.meta.total_count,
            r.data.len()
        );
        assert_eq!(r.data.len(), n_a + n_b, "多账号库该把两个号的都返回");
    }
}
