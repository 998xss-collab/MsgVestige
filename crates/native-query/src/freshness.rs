//! freshness.rs — 冷查新鲜度计算 (R6, 内核 §14): `ingested_at`(L1 最后 ingest 水位) + `stale`(full 语境)。
//!
//! **自开只读 conn 读 etl_state**(不复用查询 conn)→ 皮层无论走哪条冷查路(现成 conn 的 `cold` / run_query
//! 自建 conn 的 `cold_cmd`)都能统一只凭 **L1 路径** 调它。
//!
//! **`stale` 语义 (R9 复审R3#4 + codex P1 定型)**:
//! - **非 full**(off): 无常驻同步机制, 静态查无法诚实判 L1 是否落后源 → `stale = None` 省略(复审#2: 宁缺不谎)。
//! - **full + 后台 watch 线程已退出/崩溃**: 配了 full 却没维护者了, L1 冻结而源库仍在长 → `stale = Some(true)`
//!   (安全告警方向, 不谎报新鲜)。线程死由 R3#3 的 `AtomicBool` 信号 + `AliveGuard` 确认(覆盖正常/Err/panic/早退)。
//! - **full + 线程存活**: `stale = None`(**诚实未知, 不报 false**)。**线程存活 ≠ 同步健康**(codex 复审 P1): 两个
//!   watch 循环都吞每轮 ingest 错误、只记日志并永久重试、线程不退出 → 持续解密/读取失败时 L1 不推进但线程仍活。
//!   报 `stale:false` 会谎报新鲜; 静态查分辨不了"健康同步/空闲无新数据/持续失败"三态 → 宁 `None` 不谎报。
//!
//! **`indexed_through` 为何 R3#4 撤掉**: 原设计 (§14.5) 想出"各源水位 MIN"作全库鲜度 floor, 但现 infra 无廉价且
//! 诚实的实现 —— etl_state 只由**消息管道**逐子源写、`last_update` 是**墙钟 ingest 时刻**非数据时刻(小库管道无
//! 状态全扫、不写 etl_state)→ `MIN(last_update)` 既漏非消息源又被休眠分片拖成假旧, 是谎报; 真数据时刻要
//! `MAX(message.create_time)`, 无专用索引 787ms/77万行 → per-query 不可接受。故 per-query 冷查**只出
//! `ingested_at`(+full 时 `stale`)**; 数据时刻鲜度改由 `/live-index/status` 专用端点(稀有、可承受全表扫)报。

use crate::Freshness;

/// 算冷查 [`Freshness::Cold`](非 full 语境):
/// - `ingested_at`(unix 秒)= L1 `etl_state` 该账号各源水位 `MAX(last_update)`(毫秒)/1000;空库/无水位/查错 → `None`。
/// - `stale` = **`None`**(非 full 无常驻同步, 静态查不谎报;理由见模块文档)。
///
/// **`ingested_at` 语义(要点, 别误读)**:"该账号**任一源库**最近一次 ingest 的时间", **非逐源** —— 早 ingest 的
/// 源(如 contact)可能比这个时间旧。作"这份 L1 大概多久没更新过"的粗提示即可, 别当成"所有源都新到此刻"的保证。
///
/// **返 `Option`**:`ingested_at` 判不出(L1 无 etl_state 水位 / 查错)→ `None`, 皮层据此**不挂** freshness ——
/// 别序列化成误导性的空壳 `{}`(`meta.source=cold` 已够表"这是冷查")。
#[must_use]
pub fn cold_freshness(l1_path: &str, account_sha: Option<&str>) -> Option<Freshness> {
    let ingested_at = l1_ingested_at_secs(l1_path, account_sha)?;
    // 静态 cold: stale 恒 None (非 full 无常驻同步机制, 不谎报;复审#2)。
    Some(Freshness::Cold {
        ingested_at: Some(ingested_at),
        stale: None,
        chat_refreshed_at: None,
        refresh_skipped: None,
    })
}

/// R9 件6 + 复审R3#4(codex P1 订正): **full 冷查 freshness** —— serve `--live-index full` 运行时的冷查, 除
/// `ingested_at` 外据**后台 watch 线程真实存活** (`live_alive`, 皮层从 `AppState.live_index_alive` 读) 填 `stale`:
/// - `live_alive == false`(线程退出/崩溃/runtime 建失败)→ `stale = Some(true)`: 配了 full 却没维护者了, L1 冻结而
///   源库仍在长 → **告警**(安全方向: 不谎报新鲜)。
/// - `live_alive == true`(线程活)→ `stale = None`(**诚实未知, 不报 false**): **线程存活 ≠ 同步健康** —— 两个 watch
///   循环都**吞每轮 ingest 错误、只记日志并永久重试、线程不退出**(见 `msgvestige-adapter` watch: 解密/读取持续失败时
///   L1 不再推进但线程仍活)。故 alive 只能说明"轮询在转", 不能证明"L1 跟上了" → 报 `stale:false` 会**谎报新鲜**
///   (codex 复审 P1)。静态冷查无法分辨"健康同步 / 空闲无新数据 / 持续失败"三态, 宁 `None` 不谎报(与 R6 反谎报一致)。
///
/// **与静态 `cold_freshness` 的差异**: full 语境**线程死**是可诚实确认的坏消息(→ `stale:true` 告警); 静态版无常驻
/// 同步、`stale` 恒 `None`。alive 时两者都 `None`(都不谎报新鲜)。`indexed_through` 字段 R3#4 已撤(见模块文档)。
///
/// **返 `Option`**: 线程**活**且 `ingested_at` 读不到(空 L1 无 etl_state 水位)→ `None`, 皮层不挂 freshness(同
/// `cold_freshness`)。线程**死**则**恒返 `Some`(`stale:true`)**, 即使没水位 —— 见下 R4 复审。
#[must_use]
pub fn cold_freshness_full(l1_path: &str, account_sha: Option<&str>, live_alive: bool) -> Option<Freshness> {
    let ingested_at = l1_ingested_at_secs(l1_path, account_sha);
    if !live_alive {
        // R4 复审 P2: 线程**死** → 无论有没有 etl_state 水位都报 `stale:true`。**首同步就崩**的场景 (配了 full 但后台
        // 线程还没成功 ingest 过一次就死了 → etl_state 空 → 原先 `?` 早返 None → 查询完全不带 freshness、消费者看不到
        // 任何告警) 恰是最该告警的 —— 索引压根没起来。`ingested_at` 有则带上 (None 时 serde 省略)。
        return Some(Freshness::Cold {
            ingested_at,
            stale: Some(true),
            chat_refreshed_at: None,
            refresh_skipped: None,
        });
    }
    // 线程活: ingested_at 读不到 (空 L1 / 尚未首同步) → None 不挂 (同 cold_freshness, 线程在跑不谎报); 有 → stale None
    // (存活≠同步健康, 不谎报 false; codex 复审 P1)。
    let ingested_at = ingested_at?;
    Some(Freshness::Cold {
        ingested_at: Some(ingested_at),
        stale: None,
        chat_refreshed_at: None,
        refresh_skipped: None,
    })
}

/// L1 最后 ingest 时间(unix 秒)= `etl_state` `MAX(last_update)`[ms] / 1000。打**只读** L1 单查;任何失败 → `None`。
///
/// **审 R6-P2 账号 scoped**: `account_sha` 给了就 `WHERE account_id_sha=?`(否则多账号库 global `MAX` 会取到
/// **别账号**更新时间 → 误报本账号新鲜度)。`None`(单账号/未过滤)→ global `MAX`(库里就一个账号, 即该账号)。
fn l1_ingested_at_secs(l1_path: &str, account_sha: Option<&str>) -> Option<i64> {
    use rusqlite::OpenFlags;
    let conn =
        rusqlite::Connection::open_with_flags(l1_path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)
            .ok()?;
    let max_ms: Option<i64> = match account_sha {
        Some(sha) => conn
            .query_row(
                "SELECT MAX(last_update) FROM etl_state WHERE account_id_sha = ?1",
                [sha],
                |r| r.get::<_, Option<i64>>(0),
            )
            .ok()
            .flatten(),
        None => conn
            .query_row("SELECT MAX(last_update) FROM etl_state", [], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .ok()
            .flatten(),
    };
    max_ms.map(|ms| ms / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R9 件6 + 复审R3#4: `cold_freshness`(非 full, stale None) vs `cold_freshness_full`(据线程存活填 stale) +
    /// `ingested_at` account scoped + 毫秒/1000→秒 归一。
    ///
    /// **回归钉死**: `ingested_at` = `etl_state.last_update`(毫秒 13 位)/1000 = 秒(10 位); account scoped 不把
    /// 别账号(accB)更新算进本账号(accA)。full 的 `stale` 由 `live_alive` 决定, 不再读已撤的 `indexed_through`。
    #[test]
    fn freshness_stale_by_liveness_and_account_scoped() {
        let tmp = std::env::temp_dir().join("nq_r9_freshness.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            c.execute_batch(
                "CREATE TABLE etl_state(account_id_sha TEXT, source TEXT, kind TEXT, last_update INTEGER);
                 INSERT INTO etl_state VALUES('accA','message','m', 1783539216353);
                 INSERT INTO etl_state VALUES('accA','contact','c', 1700000000000);
                 INSERT INTO etl_state VALUES('accB','message','m', 1799999999000);",
            )
            .unwrap();
        }
        let path = tmp.to_str().unwrap();

        // 静态 cold (accA scoped): ingested_at = MAX(accA last_update 1783539216) / 1000; stale None; 不算 accB。
        assert_eq!(
            cold_freshness(path, Some("accA")).expect("accA 有 etl_state → Some"),
            Freshness::Cold {
                ingested_at: Some(1_783_539_216),
                stale: None,
                chat_refreshed_at: None,
                refresh_skipped: None
            },
            "静态 cold: ingested_at=MAX(accA)·stale None·account scoped 排除 accB"
        );

        // full + 线程活: stale None (codex P1: 存活≠同步健康, watch 吞错永久重试可能活着但 L1 不推进 → 不谎报 false)。
        assert_eq!(
            cold_freshness_full(path, Some("accA"), true).expect("Some"),
            Freshness::Cold {
                ingested_at: Some(1_783_539_216),
                stale: None,
                chat_refreshed_at: None,
                refresh_skipped: None
            },
            "full 线程活: stale None (不谎报新鲜; 存活≠同步健康)"
        );

        // full + 线程死: stale:true (没维护者了, L1 冻结源库仍长 → 安全告警方向)。
        assert_eq!(
            cold_freshness_full(path, Some("accA"), false).expect("Some"),
            Freshness::Cold {
                ingested_at: Some(1_783_539_216),
                stale: Some(true),
                chat_refreshed_at: None,
                refresh_skipped: None
            },
            "full 线程死: stale:true 告警"
        );

        // 空 L1 (无 etl_state 行) → None (皮层不挂 freshness)。
        let empty = std::env::temp_dir().join("nq_r9_freshness_empty.db");
        let _ = std::fs::remove_file(&empty);
        {
            let c = rusqlite::Connection::open(&empty).unwrap();
            c.execute_batch(
                "CREATE TABLE etl_state(account_id_sha TEXT, source TEXT, kind TEXT, last_update INTEGER);",
            )
            .unwrap();
        }
        let ep = empty.to_str().unwrap();
        assert_eq!(cold_freshness(ep, None), None, "空 etl_state → None");
        assert_eq!(
            cold_freshness_full(ep, None, true),
            None,
            "空 etl_state + 线程活 → None (在跑不谎报)"
        );
        // R4 复审 P2: 空 etl_state (首同步就崩) + 线程**死** → stale:true (即使无 ingested_at 水位, 也要告警索引没起来)。
        assert_eq!(
            cold_freshness_full(ep, None, false).expect("死线程恒 Some 告警"),
            Freshness::Cold {
                ingested_at: None,
                stale: Some(true),
                chat_refreshed_at: None,
                refresh_skipped: None
            },
            "空 etl_state + 线程死: stale:true 且无 ingested_at (首同步崩的告警)"
        );

        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&empty);
    }
}
