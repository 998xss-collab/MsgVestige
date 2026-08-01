//! R22 / ADR-508 **D24** 对抗审 —— 真库上证"懒式落库读的是 checkpoint 快照, 看不见 WAL 前沿"。
//!
//! ⚠️ **本文件的前提已经过时**(外部复审 P3, 2026-07-30): `ensure_chat_fresh` **早已改用
//! `NativeCipher::new_live()`**(合并 WAL) —— 就是这条用例当初逼出来的修复。所以它现在**不再守护
//! 当前实现**, 只是把"非 live 读法会看不见 WAL 前沿"这个事实钉在这儿备查(仍有价值: 谁要是把
//! 生产改回非 live, 这份说明就是证据)。**别拿它当"live 读法已验证"的凭据。**
//!
//! 以下是当初的描述, 保留原文:
//! `ensure_chat_fresh` 曾用 `NativeCipher::new()`(非 live), 而 native-sqlcipher 自己的文档写着:
//! `open_decrypted` = **只解主库、不合并 WAL** = checkpoint 快照; 微信/WCDB 频繁 checkpoint,
//! **最新几笔常还压在加密 WAL 里未刷盘**。常驻 watch 走的是 `NativeCipher::new_live()`(合并 WAL)。
//!
//! 本用例把同一时刻、同一张表、同一条 SQL 用两条 cipher 各读一遍, 看差多少条。差 > 0 就说明:
//! 懒式落库那一路**读不到最新消息**, 而它的新鲜度签名里**已经把 `-wal` 的 mtime 算成"已消费"**
//! (见 `r22_d24_gate_race.rs::d24_wal_only_change_is_stamped_as_consumed`)。
//!
//! ```text
//! cargo test -p native-query --release --test r22_d24_wal_frontier -- --ignored --nocapture
//! ```
//! 环境变量: `R22_WXID` / `R22_DATA_DIR` / `R22_CHAT` / `R22_POLL_SECS`(默认 120)。

// 测试夹具里的辅助 item 就近声明更好读。
#![allow(clippy::items_after_statements)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use native_core::cipher::{Cipher, DbSession, NativeCipher};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn msg_table(conv: &str) -> String {
    native_core::decoder::anchor::msg_anchor(conv, 0)
        .split(':')
        .next()
        .unwrap()
        .to_string()
}

fn shards(msg_dir: &Path) -> Vec<PathBuf> {
    native_query::db_shard_files(msg_dir, "message")
}

/// `SELECT <expr> FROM <table>` 的单值读; 表不存在 / 查失败 → None。
async fn scalar(sess: &dyn DbSession, db: &Path, table: &str, expr: &str) -> Option<i64> {
    let sql = format!("SELECT {expr} AS v FROM \"{table}\"");
    sess.query("message", db, &sql)
        .await
        .ok()?
        .first()
        .and_then(|r| r.get_i64("v"))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "要真加密库 + 已缓存 key; 手动 --ignored 跑"]
async fn d24_checkpoint_reader_is_blind_to_wal_frontier() {
    let wxid_s = env_or("R22_WXID", "wxid_abcd1234efgh567");
    let data_dir = env_or("R22_DATA_DIR", r"X:\xwechat_files");
    let chat = env_or("R22_CHAT", "3907****959@chatroom");
    let poll_secs: u64 = env_or("R22_POLL_SECS", "120").parse().unwrap();

    let wxid = native_core::key_provider::Wxid::try_new(wxid_s.clone()).expect("wxid");
    let msg_dir = native_query::resolve_message_dir(Some(&data_dir), &wxid).expect("message 目录");
    let entry = msg_dir.parent().unwrap().join("session").join("session.db");
    let table = msg_table(&chat);
    println!("会话 {chat} → 源库表 {table}");

    let key_ck = native_query::cache_key(&wxid).await.expect("key");
    let key_lv = native_query::cache_key(&wxid).await.expect("key");
    let _ck = NativeCipher::new()
        .open_account(&entry, &key_ck)
        .await
        .expect("非 live 会话");
    let lv = NativeCipher::new_live()
        .open_account(&entry, &key_lv)
        .await
        .expect("live 会话");

    // 先用**便宜的** live 连接找出该会话的"活分片"(最新一条消息所在)。
    let all = shards(&msg_dir);
    let mut active: Option<(PathBuf, i64)> = None;
    for p in &all {
        if let Some(mx) = scalar(lv.as_ref(), p, &table, "MAX(create_time)").await {
            println!(
                "  {} → 最新消息 create_time={mx}",
                p.file_name().unwrap().to_string_lossy()
            );
            if active.as_ref().is_none_or(|(_, m)| mx > *m) {
                active = Some((p.clone(), mx));
            }
        }
    }
    let (shard, _) = active.expect("该会话在任何分片里都找不到 — 换 R22_CHAT");
    let name = shard.file_name().unwrap().to_string_lossy().to_string();
    println!("活分片 = {name}");

    // 单会话灵敏度太低 (它得**恰好**在窗口里来消息)。改成盯**整个活分片的总行数**:
    // 该分片里任何一个会话来了消息, 两条 cipher 的读数就会岔开。
    let tables: Vec<String> = lv
        .query(
            "message",
            &shard,
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'",
        )
        .await
        .expect("列表")
        .iter()
        .filter_map(|r| r.get_str("name").map(str::to_string))
        .filter(|n| n.len() == 36)
        .collect();
    println!("活分片里有 {} 张会话表 —— 盯它们的总行数", tables.len());
    // 分块拼 `(SELECT COUNT(*) FROM "T") + ...`, 一次 query 拿全分片总行数。
    let chunks: Vec<String> = tables
        .chunks(50)
        .map(|c| {
            let sum = c
                .iter()
                .map(|t| format!("(SELECT COUNT(*) FROM \"{t}\")"))
                .collect::<Vec<_>>()
                .join("+");
            format!("SELECT {sum} AS v")
        })
        .collect();
    async fn total(sess: &dyn DbSession, db: &Path, chunks: &[String]) -> Option<i64> {
        let mut n = 0i64;
        for sql in chunks {
            n += sess
                .query("message", db, sql)
                .await
                .ok()?
                .first()
                .and_then(|r| r.get_i64("v"))?;
        }
        Some(n)
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(poll_secs);
    let mut caught = None;
    let mut samples = 0u32;
    while std::time::Instant::now() < deadline {
        let wal_mt = std::fs::metadata(PathBuf::from(format!("{}-wal", shard.display())))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis())
            .unwrap_or(0);
        // **每轮重开非 live 会话**: 它的 checkpoint 槽只按路径缓存、不按 mtime 失效, 复用会一直返回首次的快照。
        let key = native_query::cache_key(&wxid).await.expect("key");
        let ck_now = NativeCipher::new()
            .open_account(&entry, &key)
            .await
            .expect("非 live 会话");
        let lvn = total(lv.as_ref(), &shard, &chunks).await;
        let ckn = total(ck_now.as_ref(), &shard, &chunks).await;
        samples += 1;
        println!("[{samples:>2}] wal_mtime={wal_mt}  live 总行数={lvn:?}   checkpoint 总行数={ckn:?}");
        if let (Some(l), Some(c)) = (lvn, ckn) {
            if l != c {
                caught = Some((l, c));
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    match caught {
        Some((l, c)) => {
            println!(
                "\n★ 抓到 WAL 前沿: 活分片 {name} 里 live 读到 {l} 行, checkpoint 只读到 {c} 行 → 差 {} 行。\n\
                 懒式落库 (ensure_chat_fresh → NativeCipher::new()) 走的正是 checkpoint 这一路, 读不到这些行;\n\
                 而它的新鲜度签名已经把这次 -wal 变化记成「已采」(见 r22_d24_gate_race)。",
                l - c
            );
        }
        None => {
            println!(
                "\n本次 {poll_secs}s 内没抓到 (采样时活分片刚好都 checkpoint 过了)。\n\
                 这**不构成**「不会发生」的证据 —— native-sqlcipher crate 文档自述这是常态。拉长 R22_POLL_SECS 再试。"
            );
        }
    }
}
