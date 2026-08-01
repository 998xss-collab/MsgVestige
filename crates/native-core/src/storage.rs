//! storage — L1 sqlite 持久化 (native-core 子系统, ADR-416 §3.2.1).
//!
//! 本 mod = PR2-4-b: raw_payload_archive 存储 — open + §3.4 PRAGMA + 建表 + INSERT OR IGNORE
//! 5 元组去重 + 24h 滚动删. 消费 [`crate::emit::RawPayloadRecord`] (emit 装配的行).
//!
//! ## L1 不加密 (alpha)
//! L1 库 alpha 阶段【不加密】 (L1-schema §3.4 line 466 / ADR-029 R5; 靠 Windows ACL / DPAPI 保护).
//! rusqlite 用 **bundled** (普通 sqlite, 无 sqlcipher/openssl) — 不开 key; sqlcipher 推到真做 L1 加密时 (ADR-416 §3.1).
//!
//! ## 重放去重 (契约核心)
//! [`insert_record`] 用 `INSERT OR IGNORE` 撞 5 元组 UNIQUE (account_id_sha, source, source_native_id,
//! event_action, event_seq) → 同源事件重放 (WAL 重读 / cursor 重置) 给同 event_seq → 撞键被忽略 → 去重.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::emit::RawPayloadRecord;

/// 打开/创建 L1 库 + 应用 §3.4 PRAGMA (alpha 不加密).
///
/// # Errors
/// rusqlite 打开失败 / PRAGMA 应用失败 (e.g. 路径不可写 / 文件损坏).
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// **只读**打开已存在的 L1 库 (export/查询用; 文件不存在则报错**不创建空库**, 不写 pragma/WAL)。
///
/// # Errors
/// 文件不存在 / 打开失败 (rusqlite `SQLITE_OPEN_READ_ONLY` 不建文件)。
pub fn open_readonly(path: &Path) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
}

/// 建消息 ETL 落库所需的全部 L1 表 (幂等) — [`crate::sink::write_decoded_event`] 会写到的表:
/// `raw_payload_archive` (L1 溯源) + `message` / `person` / `person_alias` / `chatroom` /
/// `chatroom_member` (L2) + `etl_state` (游标水位)。adapter/cli 启动时一次建齐。
///
/// 不含 rebuild-map / source 目录 / schema_meta / capability_backlog 等其它子系统表 (各自按需建)。
///
/// # Errors
/// 任一表建失败 (rusqlite).
pub fn init_l1_schema(conn: &Connection) -> rusqlite::Result<()> {
    // R14 迁移门禁(codex P1): 旧 8hex 锚库必须删库重建, 否则新 32hex 锚与旧行混用 —— message/chatroom/session 等 PK 含
    // source_native_id, 旧 8hex 行不被新 32hex 覆盖而是**插重复行**; media discovery 生成的 32hex 引用**连不上**旧 8hex 消息。
    // schema_meta.version: 当前版本→放行(续 ingest); 真空首建→建表+播种; 无版本+已有 message 表(旧库)/版本过时→拒、删库重建。
    init_schema_meta_table(conn)?;
    let stored = get_meta(conn, META_KEY_VERSION)?;
    let has_msg_table: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='message'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    let is_fresh = stored.is_none() && !has_msg_table;
    if stored.as_deref() != Some(SCHEMA_VERSION) && !is_fresh {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
            Some(format!(
                "L1 库 schema 版本不符(需 {SCHEMA_VERSION}, 实际 {stored:?}): R14 消息锚 8hex→32hex + R16-3 favorite_tag \
                 锚 server_id→local_id, 旧库锚格式过时。请删掉此 L1 库、从加密源全量重建 —— 勿在旧库上增量(新旧锚混用会插\
                 重复行、媒体连不上消息、favorite_tag 残留塌陷孤儿行)。"
            )),
        ));
    }
    // R14(Claude P3-1 砖化修): 真空首建**立即**播种版本(建表之前) —— 若后续建表中途失败(如磁盘满), 下次 init 见 version=当前 →
    // 放行、CREATE IF NOT EXISTS 补建自愈; 否则半成品库(有 message 表无 version)会被门禁误当旧库拒、要求手动删库。
    if is_fresh {
        set_meta(conn, META_KEY_VERSION, SCHEMA_VERSION, 0)?;
    }
    init_archive_table(conn)?;
    init_message_table(conn)?;
    init_person_table(conn)?;
    init_person_alias_table(conn)?;
    init_chatroom_table(conn)?;
    init_chatroom_member_table(conn)?;
    init_session_table(conn)?;
    init_favorite_table(conn)?;
    init_favorite_media_table(conn)?;
    init_favorite_tag_table(conn)?;
    init_message_app_table(conn)?;
    init_message_media_table(conn)?;
    init_message_location_table(conn)?;
    init_message_call_table(conn)?;
    init_message_hongbao_claim_table(conn)?;
    init_message_card_table(conn)?;
    init_message_mention_table(conn)?;
    init_chatroom_member_event_table(conn)?;
    init_group_pay_member_table(conn)?;
    init_message_forward_item_table(conn)?;
    init_moment_table(conn)?;
    init_moment_media_table(conn)?;
    init_moment_interaction_table(conn)?;
    init_transfer_table(conn)?;
    init_red_envelope_table(conn)?;
    init_group_pay_table(conn)?;
    init_friend_verify_table(conn)?;
    init_finder_visit_table(conn)?;
    init_custom_emoticon_table(conn)?;
    init_avatar_image_table(conn)?;
    init_moment_feed_table(conn)?;
    init_sns_notify_table(conn)?;
    init_bizchat_user_table(conn)?;
    crate::state::init_etl_state_table(conn)?;
    // R22 (ADR-508 D24) 查询触发的会话级增量采集: 记"某会话上次采集时, 整个消息目录长什么样"。
    // 一个分片都没动过才跳过开库。**签名必须覆盖全部分片** —— 只盯"该会话所在的那几个"会静默漏:
    // 沉寂会话醒来时消息进的是当前活跃分片, 而那个分片不在它的名单里
    // (2026-07-30 修; 见 `native_query::refresh::snapshot_sig` 与 `native_query::ensure_chat_fresh`)。
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS chat_refresh_state (
            account_id_sha  TEXT    NOT NULL,
            chat_id_sha     TEXT    NOT NULL,
            shards          TEXT    NOT NULL,   -- 该会话命中过的分片, 逗号分隔 (下次至少要开哪几个的下限)
            src_sig         TEXT    NOT NULL,   -- 采集**开始那一刻**的**全部分片**快照 (v2|名:mtime:大小:WAL|…)
            refreshed_at_ms INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, chat_id_sha)
        );",
    )?;
    init_l1_generation(conn)?;
    // R17 统一底座 · L3: 每 L1 建 write_lease 协调表(方案B primitive; 纯增量 CREATE IF NOT EXISTS, 不改锚格式/现有表,
    // 无需 schema 版本 bump —— 旧 L1 下次 init 自愈补建)。**R17 dormant**: watch 未接租约、由 cmd_watch 的 OS 锁保单写者;
    // 表建好留给 R22 撤锁激活时用(那时新写者据此领片租约与常驻 watch 协调)。
    crate::write_lease::init_write_lease(conn)?;
    // R19 选择性采集 · capture_targets 会话白名单(增量 CREATE IF NOT EXISTS, 不改锚格式/现有表, 无需 schema 版本 bump;
    // 旧 L1 下次 init 自愈补建)。空表 = 全采(维持现状), 非空 = run_message_body drain 前只采圈定会话。
    crate::capture::init_capture_targets(conn)?;
    // R22 懒式落库 · query_cache_coverage 已缓存区间表(ADR-508 D1; 增量 CREATE IF NOT EXISTS, 不改锚格式/现有表,
    // 无需 schema 版本 bump —— 旧 L1 下次 init 自愈补建, 读侧另容忍表不存在 → 空覆盖 = 全 gap)。**独立于 etl_state**:
    // 它是查询缓存水位, 混进 etl_state 会让 watch 把它当采集 cursor 解析(跳消息)+ freshness 伪装成刚同步。
    Ok(())
}

/// R9 codex-R10: L1 **实例代号** —— `new` 增量命令的水位(rowid)只在当前表实例内单调, 同路径**重建/恢复/re-ingest**
/// 后 rowid 重排, 旧水位 `rowid>N` 会静默跳过消息。给每个 L1 文件盖一个建库时的随机代号: `new` 水位绑它, 代号变了
/// (=文件被重建)就自动从头重扫, 彻底防跨重建丢消息。**INSERT OR IGNORE**: 首次建库(表刚建)写一次, 后续 ingest / 同
/// L1 再调都 ignore → 代号在 L1 文件生命周期内稳定; 删文件重建 → 表重建 → 新代号。用 SQLite `randomblob` 免 rand 依赖。
///
/// **已知限制(七方复审收敛)**: 代号标的是**文件谱系**(建库一次)非**当前状态**。"删文件重建/re-ingest"零漏(新代号);
/// 恢复**带同代号的旧备份/克隆到原路径**时代号不变 —— `new` 侧 **max(rowid) 护栏**兜住其中"库变小"那类(恢复较小备份 → max
/// 掉到水位下 → 从头)。**但 VACUUM/dump-reload 会把 rowid 重编号成连续 1..N 而 max=N 可能仍 ≥ 水位**(水位下有 REPLACE
/// 空洞时), 护栏抓不到 → 未见行被压到 ≤水位 rowid 静默漏。彻底需每 ingest 递增的写代计数(收益/复杂度不划算)。
/// **缓解(须做): 从备份/克隆恢复、或对 L1 跑 VACUUM/dump-reload 之后, 都跑一次 `new --reset`**(append-only 归档本不应 VACUUM)。
pub fn init_l1_generation(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS l1_generation (id INTEGER PRIMARY KEY CHECK (id = 1), gen TEXT NOT NULL)",
        [],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO l1_generation (id, gen) VALUES (1, lower(hex(randomblob(16))))",
        [],
    )?;
    Ok(())
}

/// 读 L1 实例代号 (见 [`init_l1_generation`]); 旧 L1 无此表 → `None` (皮层退化到 rowid + max(rowid) 护栏, 下次 ingest 会补建代号)。
pub fn get_l1_generation(conn: &Connection) -> rusqlite::Result<Option<String>> {
    // R11 三方复审 P2: sqlite_master 查询错误**传播**(原 `unwrap_or(0)` 会把读错吞成"表不存在"→ 上层 fail-closed 被绕过)。
    let has: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='l1_generation'",
        [],
        |r| r.get(0),
    )?;
    if has == 0 {
        return Ok(None); // 表不存在 = 旧库, 合法向后兼容 (上层靠身份 backstop)。
    }
    // 表存在 → 代号行必存在 (init 建表即 INSERT)。缺行(QueryReturnedNoRows)或读错 → 传播为 Err, 让上层 fail-closed 从头重扫,
    // 不当"无代号"静默降级。故用 query_row(缺行=Err) 而非 optional()(缺行=Ok(None))。
    conn.query_row("SELECT gen FROM l1_generation WHERE id = 1", [], |r| {
        r.get::<_, String>(0)
    })
    .map(Some)
}

/// 应用 L1-schema §3.4 PRAGMA — **page_size 必须在任何 CREATE TABLE 之前** (顺序敏感, line 449).
fn apply_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    // `busy_timeout` 必须**先设**, 后面几条要写库头。
    conn.execute_batch("PRAGMA busy_timeout=30000; PRAGMA page_size=4096;")?;
    set_wal_with_retry(conn)?;
    conn.execute_batch(
        "PRAGMA synchronous=NORMAL;         PRAGMA foreign_keys=ON;         PRAGMA temp_store=MEMORY;         PRAGMA cache_size=-262144;         PRAGMA mmap_size=268435456;         PRAGMA recursive_triggers=ON;",
    )
    // R9 双审 P2 (recursive_triggers): external-content message_fts 增量触发器 (件1) 依赖它 —— SQLite 默认 OFF 时,
    // `INSERT OR REPLACE INTO message` 撞 PK 的**隐式 DELETE 不触发 message_fts_ad** → 旧 rowid 倒排项悬空/膨胀。
    // 置 ON 后 REPLACE 的删行 fire _ad 准确删旧项 (finder 实测坐实)。connection-level pragma, 每连接经此设。
}

/// 把库切成 WAL —— **必须自己重试**, 因为 `busy_timeout` 对这条 pragma 无效。
///
/// SQLite 切 journal mode 要独占锁, 而**切换路径不调用 busy handler**: 拿不到锁就当场返回
/// `database is locked`, 设多大的 `busy_timeout` 都拦不住。R22 懒式落库让查询侧也会建 L1,
/// 于是多个进程/线程首次同时开同一个新库时, 抢输的那些直接开库失败。
///
/// 实测(`r22_d24_gate_race::d24_concurrent_open_of_fresh_l1_can_hard_fail`, 20 轮 × 4 并发):
/// 只把 `busy_timeout` 排到最前 → 新建库仍 **33/80** 硬失败; 加上这里的重试 → 0/80。
/// 库已存在时一直是 0/80, 因为那时它已经是 WAL, 这条 pragma 是空操作 —— 这也正是当初
/// 误判"顺序问题"的原因: 失败只在**首建**出现, 看着像库头写入竞争。
fn set_wal_with_retry(conn: &Connection) -> rusqlite::Result<()> {
    let mut waited = std::time::Duration::ZERO;
    let budget = std::time::Duration::from_secs(10);
    let mut delay = std::time::Duration::from_millis(2);
    loop {
        let r = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0));
        match r {
            // 切成了就走。
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => return Ok(()),
            // 没报错但也没切成(别人正持锁时会这样): 当作可重试。
            Ok(_) => {}
            Err(e) => {
                let busy = matches!(
                    e.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                );
                // 不是锁冲突(权限/磁盘/损坏)就别耗着, 直接报上去。
                if !busy || waited >= budget {
                    return Err(e);
                }
            }
        }
        if waited >= budget {
            // 预算耗尽仍不是 WAL。**别硬失败** —— 补审指出两件事:
            //   1. 归因不能只写"别人占着锁": 更常见的是这个文件系统**根本不支持 WAL**
            //      (网络盘 / 不支持共享内存的挂载点), 那种情况下再等多久都切不过去;
            //   2. 这条路径之前是静默降级继续跑的, 改成硬失败等于把"能用但慢"变成"用不了"。
            // 所以: 降级放行 + **出声**(非 WAL 会让读写互相阻塞, 用户该知道为什么变慢)。
            let mode = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap_or_else(|_| "未知".to_string());
            tracing::warn!(
                journal_mode = %mode,
                waited_ms = waited.as_millis(),
                "切不到 WAL 模式, 降级继续 —— 读写会互相阻塞, 查询和后台索引同时跑时会明显变慢。两种可能: 这个文件系统不支持 WAL(网络盘/不支持共享内存的挂载点), 或者一直有别的进程占着独占锁。"
            );
            return Ok(());
        }
        std::thread::sleep(delay);
        waited += delay;
        delay = (delay * 2).min(std::time::Duration::from_millis(250));
    }
}

/// 建 raw_payload_archive 表 + 2 索引 (IF NOT EXISTS, 幂等; L1-schema §3.1.2).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_archive_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS raw_payload_archive (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            event_type        TEXT    NOT NULL,
            event_action      TEXT    NOT NULL,
            event_seq         INTEGER NOT NULL,
            ingest_time       INTEGER NOT NULL,
            payload_json      TEXT    NOT NULL,
            UNIQUE (account_id_sha, source, source_native_id, event_action, event_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_archive_account_ingest
            ON raw_payload_archive (account_id_sha, ingest_time DESC);
        CREATE INDEX IF NOT EXISTS idx_archive_event_type
            ON raw_payload_archive (event_type, event_action);",
    )?;
    // 同 message 侧: 定义漂了要就地修回来, 别让 CREATE IF NOT EXISTS 静默跳过。
    for (name, sql) in ARCHIVE_REBUILT_INDEXES {
        reconcile_index(conn, name, sql)?;
    }
    Ok(())
}

/// 插入一条 (INSERT OR IGNORE 5 元组去重). 返回 `true`=新插入 / `false`=撞键被忽略 (重放去重).
///
/// 撞键判定靠 schema 的 UNIQUE (account_id_sha, source, source_native_id, event_action, event_seq);
/// **注意去重键不含 ingest_time / payload_json** — 同源事件重放 (ingest_time 变) 仍撞键去重.
///
/// # Errors
/// rusqlite 执行失败 (非撞键的 DB 错误; 撞键不是错误, 返 `false`).
pub fn insert_record(conn: &Connection, rec: &RawPayloadRecord) -> rusqlite::Result<bool> {
    let changed = conn
        .prepare_cached(
            "INSERT OR IGNORE INTO raw_payload_archive
            (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?
        .execute(params![
            rec.account_id_sha,
            rec.source,
            rec.source_native_id,
            rec.event_type,
            rec.event_action,
            rec.event_seq,
            rec.ingest_time,
            rec.payload_json,
        ])?;
    Ok(changed == 1)
}

/// 一次 DELETE 最多删几行 —— **分批不是优化, 是别把一次删爆**。
///
/// 独立复审在全量真跑的 L1(42 GB)上量过: `raw_payload_archive` **977 万行 / payload_json 共 11.5 GiB**,
/// 占整库四分之一强, 而且时间戳全是同一次导入打的 —— 也就是说**头一次清理会一口气删掉全部 977 万行**。
/// 单条不分批的 DELETE 会把这些全塞进一个隐式事务, 三个索引跟着维护, WAL 涨到 GB 级, 而这段跑在
/// pipeline 那句 `wal_checkpoint(TRUNCATE)` **之后**, 后面没人再收。中途盘满还要长时间回滚。
///
/// 分批之后每一批是自己的事务: WAL 到阈值就自动 checkpoint, 中途失败前面几批**已经落地**,
/// 下一轮接着删(删除本来就是幂等的、可续的)。
const ARCHIVE_PRUNE_BATCH: usize = 10_000;

/// 删 `ingest_time < cutoff_ingest_time_ms` 的记录, 返回删除行数。**分批删**, 见 [`ARCHIVE_PRUNE_BATCH`]。
///
/// ⚠️ **全量 ingest 期间这张表是没有索引的**(独立复审 c4b5dbc 的 P3): `run_message_pipeline_jobs`
/// 开头会把 `idx_archive_account_ingest` / `idx_archive_event_type` 一起 drop 掉, 跑完才建回 ——
/// 那段时间里下面那句"带 LIMIT 每批扫到够数就停"不成立, 是裸表扫。
/// 影响有界: 全量导入全程 `ingest_time` 是同一个数, 第一批记下节流时间之后后面全被挡,
/// 所以这条路上最多裸扫一次、删十批; 真正干活的是收尾那条不设上限的清理, 那时索引已经建回来了。
///
/// ⚠️ 谓词只有 `ingest_time`, 而索引是 `(account_id_sha, ingest_time DESC)` —— 缺前导列只能扫索引、
/// 不能 seek(独立复审 `EXPLAIN QUERY PLAN` 实测: `SCAN ... USING COVERING INDEX`)。带 `LIMIT` 之后
/// 每批扫到够数就停, 不至于每批全表。没有为此单加一条 `ingest_time` 索引: 977 万行的库上那是几百 MB
/// 的常驻代价, 换一个一天跑一次的清理, 不划算。
///
/// ⚠️ **`event_action = 'error'` 那类记录永不清**(2026-07-31 用户拍板)。
/// 一条消息正文解不出来时, 它不进 message 表, 只 emit 一条 `SystemError` —— 而 `SystemError`
/// 没有 L2 表, **这张表里那一行就是"这儿丢过一条"的唯一持久记录**。滚动窗口一清, 消息没了、
/// 记录也没了, 而水位早过去了, 重跑也不会再读到它。这跟已经定死的"丢可以、静默不行"直接冲突。
/// 这类行数量极少(一次全量导入通常个位数到几十条), 永远留着不占什么地方,
/// 用户随时能用 `msgraw` 查到哪条丢了、丢在哪张表哪一行。
///
/// ⚠️ 删掉的空间**不会还给文件系统** —— SQLite 不 VACUUM 就不缩文件, 只是把页标成可复用。
/// 42 GB 的库清完还是 42 GB, 但后续写入会填回这些页, 不会继续涨。VACUUM 要锁整库且要等量临时空间,
/// 不适合塞在导入收尾里。
///
/// # Errors
/// rusqlite 执行失败.
pub fn prune_older_than(conn: &Connection, cutoff_ingest_time_ms: i64) -> rusqlite::Result<usize> {
    prune_older_than_capped(conn, cutoff_ingest_time_ms, usize::MAX)
}

/// 同 [`prune_older_than`], 但**最多删 `max_batches` 批就收手**(剩下的下一轮再说)。
///
/// 给常驻路径用: 那些地方一次调用不能长时间占着线程, 而删除本来就是可续的 —— 这一轮删不完,
/// 下一轮接着删, 中间不会丢也不会重。
///
/// # Errors
/// rusqlite 执行失败.
pub fn prune_older_than_capped(
    conn: &Connection,
    cutoff_ingest_time_ms: i64,
    max_batches: usize,
) -> rusqlite::Result<usize> {
    let mut total = 0usize;
    for _ in 0..max_batches {
        // 子查询挑 id 再按 id 删: `DELETE ... LIMIT` 要 SQLITE_ENABLE_UPDATE_DELETE_LIMIT 编译开关,
        // 不能假定打开; 挑 id 这条到处都能跑。
        let n = conn.execute(
            "DELETE FROM raw_payload_archive WHERE id IN (
                 SELECT id FROM raw_payload_archive
                 WHERE ingest_time < ?1 AND event_action <> 'error'
                 LIMIT ?2
             )",
            params![cutoff_ingest_time_ms, ARCHIVE_PRUNE_BATCH],
        )?;
        total += n;
        if n < ARCHIVE_PRUNE_BATCH {
            break; // 这一批没装满 = 没有更老的了
        }
    }
    Ok(total)
}

/// 原始归档默认保留多久 —— **24 小时**。
///
/// 这张表是给下游 app 的**重放窗口**(见 [`read_archive_since`]): 错过事件的消费方拿游标续读。
/// 超出窗口的记录没有用处, 只占地方。
///
/// ⚠️ 这只是**兜底默认值**, 真正生效的是 config 里的 `adapter.archive_retention_hours`
/// (1..=720 小时, 有校验)。写死会让用户配了也不算数 —— codex 审这一笔时点出来的:
/// 用户配 72 小时, 而我按 24 小时**不可逆地删掉**他要留的那 48 小时。
pub const ARCHIVE_RETENTION_HOURS_DEFAULT: u32 = 24;

/// 按给定的保留小时数清一次原始归档, 返回删了几条。
///
/// **为什么单独包一层**(外部复审报的 P1): `prune_older_than` 写好了却**从来没接进生产路径** ——
/// 全仓唯一调用点是它自己的单元测试。真库上量过后果: 13.4 万条、41 MB 正文, 时间戳全在同一次导入
/// 的 43 秒内, 一条都没被清过。
///
/// ⚠️ **接在哪儿栽过两次**: 头一版接在**消息 pipeline** 收尾, 真跑才发现 —— adapter 里有
/// **十几条** `run_*_ingest`(联系人 / 群 / 会话 / 收藏 / 朋友圈 / 转账 / 红包…), 各自开库跑各自的,
/// 消息那条只是其中之一。第二版接在 CLI 收尾, 自查发现 `msgvestige-adapter` 自己那个二进制也能跑导入,
/// 走不到 CLI。最终落在 `run_full_ingest` 收尾 —— 两个入口共用的那一条, 一次导入清一次。
///
/// ⚠️ **窗口长度是参数, 不是常量**(codex 审这一笔点出来的): config 里 `adapter.archive_retention_hours`
/// 早就有(默认 24、可配 1..=720、还带校验), 只是从来没人读。写死 24 的话用户配 72,
/// 我会按 24 小时**不可逆地删掉**他要留的那 48 小时 —— 比不清更糟。
///
/// # Errors
/// rusqlite 执行失败.
pub fn prune_archive_now(conn: &Connection, now_ms: i64, retention_hours: u32) -> rusqlite::Result<usize> {
    let window_ms = i64::from(retention_hours) * 60 * 60 * 1000;
    prune_older_than(conn, now_ms - window_ms)
}

/// 常驻路径上"顺手清一次"的最小间隔。
///
/// 常驻形态(`watch` tail-f、`serve --live-index full`、查询侧懒采集)每写一批就会经过清理点,
/// 但真删只按这个节奏来 —— 不然每批一次 DELETE, 白白折腾索引。
const ARCHIVE_PRUNE_THROTTLE_MS: i64 = 5 * 60 * 1000;

/// 保留期读不出来时, 隔多久重试一次。
///
/// 比正常节流短得多(不然全量导入一整轮都不会清), 又不是每批都试(不然 config 坏着的时候
/// 每批重读一遍坏文件 + 每批一行警告)。两条审各按住一头, 见 `prune_archive_throttled_with`。
const ARCHIVE_PRUNE_RETRY_MS: i64 = 30 * 1000;

/// 常驻路径一次最多删几批 —— 见 [`prune_older_than_capped`]。
///
/// 这些地方一次调用不能长时间占着线程。常驻形态新写进来的是**涓流**, 十批(十万行)远够用;
/// 真要是攒了大堆(独立复审在 42 GB 真库上量到 977 万行), 那是历史欠账, 由 `ingest` 那条
/// 不设上限的路去还。
const ARCHIVE_PRUNE_THROTTLED_BATCHES: usize = 10;

/// 每个库上次真删是什么时候 —— 按**库文件路径**分开记, 一个进程里开两个 L1 不会互相顶掉节流。
static LAST_PRUNE_MS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, i64>>> =
    std::sync::OnceLock::new();

/// **常驻路径上顺手清一次归档** —— 自带节流, 挂在写入点上, 调多勤都不怕。
///
/// 为什么挂在写入点而不是各个命令里(独立复审报的 P1): 写归档的入口远不止 `ingest` 一条 ——
/// `watch` 的消息 tail-f、`serve --live-index full`、查询侧的懒采集, 全都往这张表里写, 而且全是
/// **长期跑**的形态。一个个去补调用就是"按点名清单修", 漏一处就又回到只写不清。
/// 三条消息路径(全量导入 / tail-f / 懒采集)都汇到 `run_message_body` 那一个提交点, 挂在那儿
/// 才是按判据覆盖整类。
///
/// ⚠️ **`now_ms` 要跟写入用的是同一个钟** —— 传进来的必须是这批行落库时打的 `ingest_time`,
/// 不能自己去读墙上时间。头一版我在函数里 `SystemTime::now()`, 结果一跑就删掉了刚写进去的行:
/// 行上盖的时间戳是调用方给的, 两个钟对不上, 窗口就算在了错的基准上。
/// 生产里这俩差不多, 但**一次跑几个小时的全量导入**里差得就不是一点 —— 收尾那批的 `ingest_time`
/// 还是开跑时那个数, 拿墙上时间去卡, 等于把自己刚写的当过期的删了。native-core 的四条 pipeline
/// 测试当场红给我看的。
///
/// best-effort: 清理失败绝不能影响写入 —— 只 warn, 不往上抛。
pub fn prune_archive_throttled(conn: &Connection, now_ms: i64) {
    prune_archive_throttled_from(conn, now_ms, &production_config_path());
}

/// 测试期间临时改用哪个 config 文件 —— **只为了让守卫能从真正的生产入口进去**。
///
/// 独立复审 656477c 的 P2: 我上一笔加的两条守卫调的是 `*_from`(带路径参数那个内层函数),
/// 而生产调的是不带参数的外层。审查方把**外层那一行**换成"绕开 config 写死 24", 全工作区
/// 一条不红 —— 我的 commit message 却写着这两个反例已经打红了。我埋的是内层, 他埋的是外层,
/// 两句话都对, 但没人守着的正是外层那一行。
///
/// 又是"它证明函数算得对, 证明不了有人调它" —— 这回判据只往外挪了一层, 仍然是"点名那一条"。
static TEST_CONFIG_PATH: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// 测试之间互斥用 —— 上面那个是进程级的, 两条测试同时改会互相踩。
static TEST_CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 生产真正读哪个 config 文件。测试可以临时改(见 [`TEST_CONFIG_PATH`]), 生产恒为默认路径。
fn production_config_path() -> std::path::PathBuf {
    // ⚠️ **不用 `#[cfg(test)]` 门**: adapter 的测试链接的是**非 test 编译**的 native-core,
    // cfg(test) 的东西它根本看不见 —— 而 adapter 那条清理路正是要从生产入口测的那一条。
    // 代价只是每次真清之前多读一次 Mutex(至多五分钟一次), 可以忽略。
    let over = TEST_CONFIG_PATH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(p) = over {
        return p;
    }
    crate::config::default_config_path()
}

/// 测试期间把 config 路径指到别处, 出作用域自动还原; 同时对别的用它的测试互斥。
#[doc(hidden)] // 仅供测试从**真正的生产入口**进去, 不是对外 API
#[must_use]
pub fn config_path_for_test(path: &std::path::Path) -> TestConfigPathGuard {
    let lock = TEST_CONFIG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *TEST_CONFIG_PATH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(path.to_path_buf());
    TestConfigPathGuard(lock)
}

#[doc(hidden)]
pub struct TestConfigPathGuard(
    /// 只为持到作用域末尾 —— 它在的时候别的测试改不了这个路径。
    #[allow(dead_code)]
    std::sync::MutexGuard<'static, ()>,
);

impl Drop for TestConfigPathGuard {
    fn drop(&mut self) {
        *TEST_CONFIG_PATH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// 同上, 但 config 路径由调用方给 —— **拆出来是为了能测"读不懂就别删"那一支**。
///
/// 独立复审 651ed5c 的 P2: "config 读不懂就别清"这条本来是 codex 报的 P1, 修完之后**删的那一头
/// 一条守卫都没有** —— 把它改成"读不懂就按默认 24 删"、或者让生产路径绕开 config 写死 24,
/// 全工作区一条不红。唯一相关的那条测试只调"读的那一头", 证明不了删的那一头听不听。
/// 又是那句"它证明函数算得对, 证明不了有人调它", 这回落在同一个函数的另一半上。
///
/// 默认路径吃 `%LOCALAPPDATA%` 环境变量, 而环境变量是整个进程共享的, 测试并行跑会互相踩 ——
/// 所以是**传路径**而不是设环境变量。
pub fn prune_archive_throttled_from(conn: &Connection, now_ms: i64, config_path: &std::path::Path) {
    // ⚠️ **保留期是等节流放行之后才去读的**(独立复审 c4b5dbc 的 P2)。原先第一句就读 config 文件,
    // 而这个函数挂在 drain 循环里, 是"每分片 × 每会话 × 每批"调一次 —— 被节流挡掉的那些也照付。
    // 实测一次读盘 161.6 µs(有配置文件), 按真库 2.2 万会话算, watch 一轮白花约 3.5 秒。
    // 配置写坏时更难看: 每批还要多打一行警告。
    let retention = || configured_retention_hours_at(config_path);
    match prune_archive_throttled_with(conn, now_ms, ARCHIVE_PRUNE_THROTTLE_MS, retention) {
        Ok(Some(n)) if n > 0 => tracing::info!(pruned = n, "原始归档: 常驻路径顺手清了一次"),
        Ok(_) => {} // 被节流跳过 / config 读不懂 / 没什么可删
        Err(e) => tracing::warn!(error = %e, "原始归档顺手清失败 (不影响写入, 下次再说)"),
    }
}

/// 取配置的保留小时数; **读不懂就返回 `None`, 意思是"这轮别清"**。
///
/// codex 审出来的 P1: 原先用的是 `load_or_default` —— 它在**任何**加载失败时都退回默认 24 小时。
/// 用户配的是 720 小时, 而某次读文件/解析/校验偶然失败(文件正被编辑器写了一半、磁盘打嗝、
/// 手滑写错一个字段), 这条删除路径就会立刻按 24 小时**不可逆地删掉**他要留的那 696 小时。
/// 猜错的代价是删掉的数据回不来, 而不清的代价只是这一轮没清 —— 两边不对等, 所以宁可不清。
///
/// 只有一种"失败"是可以照默认走的: **文件根本不存在**。那不是读不懂, 那是没配置。
///
/// `pub` 是给 adapter 那条不设上限的清理路复用的 —— 两条路必须用同一套判断, 不然又是"按点名清单修"。
pub fn configured_retention_hours() -> Option<u32> {
    configured_retention_hours_at(&production_config_path())
}

/// [`configured_retention_hours`] 的可测内核: config 路径由调用方给。
///
/// 拆出来是因为默认路径吃 `%LOCALAPPDATA%` 环境变量, 而环境变量是整个进程共享的 ——
/// 测试并行跑起来会互相踩。
#[must_use]
pub fn configured_retention_hours_at(path: &std::path::Path) -> Option<u32> {
    match crate::config::load_config(path) {
        Ok(c) => Some(c.adapter.archive_retention_hours),
        Err(crate::config::ConfigError::FileNotFound(_)) => Some(ARCHIVE_RETENTION_HOURS_DEFAULT),
        Err(e) => {
            tracing::warn!(error = %e, "config 读不出保留期, 这轮不清归档 (宁可不清, 也不按猜的值删)");
            None
        }
    }
}

/// [`prune_archive_throttled`] 的可测内核: 时间和窗口都由调用方给。
///
/// 返回 `None` = 这次被节流跳过了(没查库也没删); `Some(n)` = 真删了 n 条。
///
/// # Errors
/// rusqlite 执行失败.
pub fn prune_archive_throttled_at(
    conn: &Connection,
    now_ms: i64,
    min_interval_ms: i64,
    retention_hours: u32,
) -> rusqlite::Result<Option<usize>> {
    prune_archive_throttled_with(conn, now_ms, min_interval_ms, || Some(retention_hours))
}

/// 同上, 但保留期是**等节流放行之后才去取**的 —— 取它要读盘, 别让被挡掉的那些也付这份钱。
///
/// `retention` 返回 `None` = 取不到(config 读不懂), 这轮不清。
///
/// # Errors
/// rusqlite 执行失败.
pub fn prune_archive_throttled_with(
    conn: &Connection,
    now_ms: i64,
    min_interval_ms: i64,
    retention: impl FnOnce() -> Option<u32>,
) -> rusqlite::Result<Option<usize>> {
    // 节流键 = 库文件路径。两个边角(独立复审 c4b5dbc 的 P3):
    // - **大小写归一, 但只在 Windows 上**: Windows 上 `k.db` 和 `K.DB` 是同一个文件, 不归一就是
    //   两个节流槽; 而 Linux 上它们是**两个不同的库**, 一律小写反而会把两个库并成一个槽 ——
    //   两个库在节流间隔内先后跑, 后一个的清理就被前一个顶掉, 调用顺序稳定的话可以一直清不了
    //   (codex 审 651ed5c 的 P2)。所以按平台分, 不搞"一刀切归一"。
    // - **内存库**: `conn.path()` 返回的是 `Some("")` 不是 `None`, 所以 `unwrap_or` 那条是死代码;
    //   而且一个进程里所有内存库会共用空串这一个槽。显式认出来, 免得以后写测试互相串。
    let raw = conn.path().unwrap_or_default();
    let key = if raw.is_empty() {
        ":memory:".to_string()
    } else if cfg!(windows) {
        raw.to_lowercase()
    } else {
        raw.to_string()
    };
    {
        let mut map = LAST_PRUNE_MS
            .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&last) = map.get(&key) {
            if now_ms - last < min_interval_ms {
                return Ok(None);
            }
        }
        // **先记时间再删**: 删的过程中别的线程进来直接被节流挡掉, 不会两个人同时删。
        // (没清成的话由 `back_off_throttle` 把它拨回退避点 —— 那边按"是不是我自己那一格"判, 见其注。)
        map.insert(key.clone(), now_ms);
    }
    let Some(hours) = retention() else {
        // 保留期取不到 —— 这轮不清(见 configured_retention_hours 的注), 而且**把节流槽往回拨**,
        // 让它过一小段就能重试, 而不是占满整个正常间隔。
        //
        // 两头都不能走极端, 两条审各按住一头:
        // - 占满五分钟不行(独立复审 651ed5c 的 P3): 全量导入里 `now_ms` 是整轮不变的常量,
        //   头一批恰好读不懂就意味着这一整轮(几个小时)一次都不会清。
        // - 完全清掉也不行(codex 审 656477c 的 P2): config 一直坏着的话, 每一批都重读一遍同一个
        //   坏文件、每一批打一行警告 —— 节流形同虚设, 换来的是 IO 和日志风暴。
        // 所以退避到 `ARCHIVE_PRUNE_RETRY_MS`: 坏着的时候按这个节奏重试, 不是每批, 也不是五分钟。
        back_off_throttle(&key, now_ms, min_interval_ms);
        return Ok(None);
    };
    let window_ms = i64::from(hours) * 60 * 60 * 1000;
    let out = prune_older_than_capped(conn, now_ms - window_ms, ARCHIVE_PRUNE_THROTTLED_BATCHES);
    if out.is_err() {
        // ⚠️ **删失败也算"这轮没清成"**(独立复审 656477c 的 P3): 上面只给"取不到保留期"那条
        // 加了退避, 而库忙(SQLITE_BUSY)/表还没建也会让这一轮白跑, 那时槽照样被占满整个间隔。
        // 判据是"**任何一轮**没清成都不该占满槽", 不是"取不到保留期那一轮"。
        back_off_throttle(&key, now_ms, min_interval_ms);
    }
    out.map(Some)
}

/// 把节流槽往回拨到"过 [`ARCHIVE_PRUNE_RETRY_MS`] 就能重试"。
///
/// 两头都不能走极端: 占满整个间隔 → 全量导入一整轮都不清; 完全清掉 → 每批重试一次, IO 和日志风暴。
fn back_off_throttle(key: &str, now_ms: i64, min_interval_ms: i64) {
    let mut map = LAST_PRUNE_MS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // 往回拨 = 假装上次是在"能重试的那一刻"跑的, 于是 now + RETRY 之后才放行。
    let backoff_marker = now_ms - min_interval_ms + ARCHIVE_PRUNE_RETRY_MS;
    // ⚠️ "别抹掉别人刚写的新标记"这件事, 判据是**跟我自己那一格比**, 不是跟退避点比,
    // 也不是跟进函数时捕获的旧值比(独立复审 656477c 的 P3, 它真跑复现过):
    // - 进函数时我已经把 `now_ms` 写进去了, 所以 map 里**严格晚于 `now_ms`** 的只能是别人写的 → 不动。
    // - 等于或早于 `now_ms` 的就是我自己那一格(或更老的) → 换成退避点。
    // 拿"退避点"当判据的话, 我自己刚写的 `now_ms` 永远大于退避点 → 一路保留 → 等于占满整个间隔,
    // 退避形同虚设(我头一版就是这么写的, 改完当场把自己的守卫打红了)。
    let keep = match map.get(key).copied() {
        Some(t) if t > now_ms => t,
        _ => backoff_marker,
    };
    map.insert(key.to_string(), keep);
}

/// 读 raw_payload_archive 中 `id > after_id` 的记录 (replay 数据访问原语), 按 id ASC 返 `(id, record)`.
///
/// 给 24h 重放窗口 (adapter §): 下游 app 从 `after_id` 游标续读错过的事件; 每条带 archive `id`
/// (AUTOINCREMENT 单调插入序) 作下一次游标. `after_id=0` 读全部 (id 从 1 起). 24h 外的已被 prune 删.
///
/// **不重构 DecodedEvent** — 只取回原 [`RawPayloadRecord`] (溯源行); 重建 L2 / 反投影是上层的活.
///
/// # Errors
/// rusqlite 查询失败.
pub fn read_archive_since(conn: &Connection, after_id: i64) -> rusqlite::Result<Vec<(i64, RawPayloadRecord)>> {
    let mut stmt = conn.prepare(
        "SELECT id, account_id_sha, source, source_native_id, event_type, event_action,
                event_seq, ingest_time, payload_json
         FROM raw_payload_archive WHERE id > ?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(params![after_id], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            RawPayloadRecord {
                account_id_sha: r.get(1)?,
                source: r.get(2)?,
                source_native_id: r.get(3)?,
                event_type: r.get(4)?,
                event_action: r.get(5)?,
                event_seq: r.get(6)?,
                ingest_time: r.get(7)?,
                payload_json: r.get(8)?,
            },
        ))
    })?;
    rows.collect()
}

/// 读 raw_payload_archive `id > after_id` 的记录, 带**账号/类型过滤 + 单次上限** (SSE `/events` tail 用)。
///
/// [`read_archive_since`] 的过滤变体: `account_id_sha` / `event_type` 传 `None` = 不筛该维 (SQL
/// `?N IS NULL OR col = ?N` 固定 4 参数, 免动态拼串); `limit` 封单次读回行数 —— SSE 分批 tail (一次最多
/// `limit` 行, cursor 推进后下轮续), 防超大 `Last-Event-ID` / `after_id=0` 触发全量 24h 巨量单读。
/// 会话 (conv) 过滤不在此 (conv 不是顶层列, 在 payload_json 里, 由上层解析筛)。按 id ASC。
///
/// # Errors
/// rusqlite 查询失败。
pub fn read_archive_since_filtered(
    conn: &Connection,
    after_id: i64,
    account_id_sha: Option<&str>,
    event_type: Option<&str>,
    limit: i64,
) -> rusqlite::Result<Vec<(i64, RawPayloadRecord)>> {
    let mut stmt = conn.prepare(
        "SELECT id, account_id_sha, source, source_native_id, event_type, event_action,
                event_seq, ingest_time, payload_json
         FROM raw_payload_archive
         WHERE id > ?1
           AND (?2 IS NULL OR account_id_sha = ?2)
           AND (?3 IS NULL OR event_type = ?3)
         ORDER BY id ASC LIMIT ?4",
    )?;
    let rows = stmt.query_map(params![after_id, account_id_sha, event_type, limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            RawPayloadRecord {
                account_id_sha: r.get(1)?,
                source: r.get(2)?,
                source_native_id: r.get(3)?,
                event_type: r.get(4)?,
                event_action: r.get(5)?,
                event_seq: r.get(6)?,
                ingest_time: r.get(7)?,
                payload_json: r.get(8)?,
            },
        ))
    })?;
    rows.collect()
}

// ── L2 message 业务表 (L1-schema §3.1.3) ──

/// 一条 message 业务行 (L1-schema §3.1.3 的 19 列). PK = (account_id_sha, source, source_native_id).
///
/// **全 sha/派生值无裸文本** (conv_id_sha / sender_wxid_sha / text_content_sha — 隐私模型默认 sha 模式;
/// 业务表只存 sha + len, 明文只在 raw_payload_archive.payload_json 的 plaintext 模式) → `#[derive(Debug)]` K-R4 安全.
///
/// 投影来源 (decode 事件 → V3Message, 把 conv_id/sender_wxid/text_content 算成 _sha) 推后续 (需 decode).
// 持明文列 (ADR-426 §2.1 第一类) → **不 derive Debug**, 手写出口脱敏 (ADR-426 §2.5 日志红线)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3Message {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub conv_id_sha: String,
    pub server_id: i64,
    pub server_seq: i64,
    pub origin_source: i64,
    pub upload_status: i64,
    pub download_status: i64,
    pub create_time: i64,
    pub sort_seq: i64,
    pub status: i64,
    pub msg_type: i64,
    pub msg_type_name: String,
    pub msg_sub_type: Option<i64>,
    pub msg_sub_type_name: Option<String>,
    pub local_type_raw: i64,
    pub sender_wxid_sha: String,
    pub is_chatroom: bool,
    pub text_content_sha: String,
    pub text_content_len: i64,
    pub raw_xml_present: bool,
    pub decode_kind: String,
    /// 系统消息 (msg_type 10000) 粗分类 revoke/pat/hongbao/transfer/topmsg/member_join/member_remove/other
    /// (decoder/sysmsg.rs::classify_sysmsg; 非系统消息 None; 批F, L2-only 不进 digest/payload)。
    pub sys_type: Option<String>,
    // 明文列 (第一类真实数据; 与对应 _sha 同源, 由 project_message 统一构造 — ADR-426 §2.7.1)。
    pub account_id: String,
    pub conv_id: String,
    pub sender_wxid: String,
    pub text_content: String,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha/元数据原样; 明文 id 列 → sha8; 正文 → 只 len (省略)。
impl std::fmt::Debug for V3Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Message")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("conv_id_sha", &self.conv_id_sha)
            .field("server_id", &self.server_id)
            .field("server_seq", &self.server_seq)
            .field("origin_source", &self.origin_source)
            .field("upload_status", &self.upload_status)
            .field("download_status", &self.download_status)
            .field("create_time", &self.create_time)
            .field("sort_seq", &self.sort_seq)
            .field("status", &self.status)
            .field("msg_type", &self.msg_type)
            .field("msg_type_name", &self.msg_type_name)
            .field("msg_sub_type", &self.msg_sub_type)
            .field("msg_sub_type_name", &self.msg_sub_type_name)
            .field("local_type_raw", &self.local_type_raw)
            .field("sender_wxid_sha", &self.sender_wxid_sha)
            .field("is_chatroom", &self.is_chatroom)
            .field("text_content_sha", &self.text_content_sha)
            .field("text_content_len", &self.text_content_len)
            .field("raw_xml_present", &self.raw_xml_present)
            .field("decode_kind", &self.decode_kind)
            .field("sys_type", &self.sys_type)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("conv_id_sha8", &crate::key_provider::sha8(self.conv_id.as_bytes()))
            .field("sender_wxid_sha8", &crate::key_provider::sha8(self.sender_wxid.as_bytes()))
            // text_content 明文有意省略 (上面 text_content_len 已表长度) → non_exhaustive (K-R4)。
            .finish_non_exhaustive()
    }
}

/// 建 message 表 + 4 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.3).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            conv_id_sha       TEXT    NOT NULL,
            server_id         INTEGER NOT NULL,
            server_seq        INTEGER NOT NULL DEFAULT 0,
            origin_source     INTEGER NOT NULL DEFAULT 0,  -- 消息来源分类 (Msg_ 现成列; L2-only)
            upload_status     INTEGER NOT NULL DEFAULT 0,  -- 媒体上传状态 (Msg_ 现成列; L2-only)
            download_status   INTEGER NOT NULL DEFAULT 0,  -- 媒体下载状态 (Msg_ 现成列; L2-only)
            create_time       INTEGER NOT NULL,
            sort_seq          INTEGER NOT NULL,
            status            INTEGER NOT NULL,
            msg_type          INTEGER NOT NULL,
            msg_type_name     TEXT    NOT NULL,
            msg_sub_type      INTEGER,
            msg_sub_type_name TEXT,
            local_type_raw    INTEGER NOT NULL,
            sender_wxid_sha   TEXT    NOT NULL,
            is_chatroom       INTEGER NOT NULL,
            text_content_sha  TEXT    NOT NULL,
            text_content_len  INTEGER NOT NULL,
            raw_xml_present   INTEGER NOT NULL,
            decode_kind       TEXT    NOT NULL,
            sys_type          TEXT,                 -- 系统消息 (type 10000) 分类 revoke/pat/… (批F; 非系统 NULL)
            -- 明文列 (ADR-426 §2.1 第一类真实数据; 与对应 _sha 同源, project_message 统一构造)。
            account_id        TEXT    NOT NULL,
            conv_id           TEXT    NOT NULL,
            sender_wxid       TEXT    NOT NULL,
            text_content      TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_conv_time
            ON message (account_id_sha, conv_id_sha, create_time DESC);
        -- 「按会话取最近 N 条」的排序键是 (create_time DESC, source_native_id DESC) —— 索引必须**两键都带**,
        -- 否则 SQLite 只能靠临时 B 树补最后一键的排序。account 打头保证多账号库也 seek 得动。
        -- 配套: handwritten::cold_messages_query 会在**看得见的账号只有一个**时把 account_id_sha 补进 WHERE
        -- (单账号库没有遮蔽视图, 不补的话这条索引一列都用不上 —— 真库实测 210 万条的群取 3 条要 4.2 秒)。
        --
        -- ⚠️ **老库拿不到这条索引的那些路径**(aa75d67 撤索引时说这条 P2 随之消失, 868499f 又把它带回来了,
        --    而那笔 commit 没提 —— 补审点名, 在此补记): 只有**可写**连接跑到 init_l1_schema 才会建,
        --    即 ingest 各入口 + refresh.rs 里拿到写锁之后那一处。所以 `--no-refresh` / 没给 --wxid /
        --    HTTP refresh=false / 拷到别的机器的冷库 / 只读文件 / 「分片没动过」的快闸, **永远拿不到**。
        --    好消息(补审实测): 查询侧那一半**不需要迁移就已见效** —— 120 万条的群 910ms → 222ms,
        --    计划从 SCAN + 整个 TEMP B-TREE 变成 SEARCH + 只剩最后一键要排。老库也拿得到大部分收益。
        --    代价(补审实测 200 万行, 我原先写的数字低估约 40%): 本索引建 5.5s / +373MB;
        --    750 万行外推约 20s / 约 1.4GB。
        -- ⚠️ 与老索引 idx_message_conv_time **不是纯冗余**: 老的更窄, 对每次调用都发的那条 COUNT
        --    明显更快(120 万行会话实测 269ms vs 339ms, 两条都在时 SQLite 主动挑窄的 288ms)。
        --    删老的不会坏(它是新的严格列前缀), 但会让 total_count 变慢 —— 这是「COUNT 快 25%」换空间的取舍。
        -- 历史: 2026-07-27 曾试过 conv 打头的 idx_message_convsha_time, 因为**对多账号库是回归**
        -- (SQLite 选它满足排序却按账号定位不了)已撤 aa75d67, 换成这里 account 打头的加宽版。
        CREATE INDEX IF NOT EXISTS idx_message_conv_time_full
            ON message (account_id_sha, conv_id_sha, create_time DESC, source_native_id DESC, source DESC);
        CREATE INDEX IF NOT EXISTS idx_message_server_id
            ON message (account_id_sha, server_id);
        CREATE INDEX IF NOT EXISTS idx_message_type
            ON message (account_id_sha, msg_type);",
    )?;
    // ⚠️ **改了索引定义但没改名字 = 在已存在的库上彻底空操作** —— `CREATE INDEX IF NOT EXISTS`
    //    只看名字, 同名就跳过, 定义变了它一声不吭。2026-07-27 把 idx_message_conv_time_full 从 4 列
    //    加宽到 5 列时就栽在这: 全新库拿到 5 列版, 而**所有已存在的库仍是 4 列**, 文档里写的
    //    "走纯 SEARCH" 在那些库上根本不成立 —— 独立审查逐库实测才发现。
    //    所以每次 init 都核对一遍定义, 不一致就重建。DROP 很便宜, 重建只在真的漂了时发生。
    // ⚠️ 只核对 **message** 那几条 —— 第一版把整批(含 2 条 archive 索引)塞在这里, 于是
    //    `init_message_table` 悄悄多了个「raw_payload_archive 必须先存在」的前置条件, 而它是 pub、
    //    doc 里也没写。仓内 13 个调用点碰巧都先建了 archive 表所以今天不炸, 典型的下一个人踩空。
    //    (审查方实测: 无 archive 表时报 `no such table`, 而且已经建了 4 条 message 索引才炸 = 半成功。)
    for (name, sql) in MESSAGE_REBUILT_INDEXES {
        reconcile_index(conn, name, sql)?;
    }
    // 旧 message 表 (无 server_seq) 补列 (批A 扫尾; 同 person/session/chatroom_member ensure)。
    ensure_message_columns(conn)
}

/// 让某个索引的**定义**跟目标一致 —— 不一致就 DROP 重建。
///
/// 存在的理由见调用点: `CREATE INDEX IF NOT EXISTS` 只认名字, 定义改了它静默跳过, 于是老库永远
/// 停在旧定义上, 而代码、文档、性能声明全按新定义写 —— 三方都对不上, 还没有任何东西报警。
///
/// 比对前把两边都归一化(小写 + 压缩空白), 免得纯排版差异触发无谓的重建。
///
/// **两条路径都在真库上量过**(1GB / 5286 条消息的 L1):
/// - 定义一致(常态): `rootpage` 不变, 首次 init 35ms、之后 2ms —— **不会每次启动都重建**;
/// - 定义漂了: 31ms 完成 DROP+CREATE, 4 列被修回 5 列。
///   (7.5M 行的大库上重建约 20s —— 所以上面那条 `tracing::info!` 要出声, 让用户知道卡在哪。)
///
/// 返回**有没有真的重建**。这个返回值不是装饰: 光比对 `sqlite_master.sql` 判断不了「这次跑有没有
/// 重建」—— 重建写回去的正是同一条定义, 两种情况那个值**完全一样**。守卫要验幂等只能靠它。
/// (第一版守卫就是拿归一化后的 sql 比的, 独立审查实测: 把 reconcile 改成「每次都 DROP+CREATE」,
///  守卫照样全绿 —— 而那正是这个修复引入的唯一新风险。`rootpage` 也当不了探针: DROP 释放的页会被
///  CREATE 复用, 实测重建前后同值。)
///
/// # Errors
/// 读 `sqlite_master` / DROP / CREATE 失败。
/// 只给测试用的薄壳 —— 让守卫能直接触发错误路径(正常代码只喂常量, 走不到 CREATE 失败那支)。
#[doc(hidden)]
pub fn reconcile_index_for_test(conn: &Connection, name: &str, sql: &str) -> rusqlite::Result<bool> {
    reconcile_index(conn, name, sql)
}

fn reconcile_index(conn: &Connection, name: &str, create_sql: &str) -> rusqlite::Result<bool> {
    fn norm(s: &str) -> String {
        s.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
    }
    // 两条都是 `format!` 拼 SQL 的前提, 当前只喂常量所以恒成立 —— 但下一个人未必:
    //   · 含分号 → 会被 execute_batch 拆成多语句, 混进 SAVEPOINT 里;
    //   · name 与 create_sql 里的索引名不一致 → DROP 一个建另一个, 下次调用必报 already exists。
    debug_assert!(!create_sql.contains(';'), "create_sql 不该自带分号: {create_sql}");
    // ⚠️ 不能用裸 `contains(name)` —— 索引名互为前缀时假通过, 而本仓恰好有这么一对
    //    (`idx_message_conv_time` 是 `idx_message_conv_time_full` 的前缀), 审查方实测断言形同虚设。
    //    带上后面那个空格才是"这条语句建的就是这个索引"。
    debug_assert!(
        create_sql.contains(&format!("INDEX {name} ")),
        "create_sql 里建的索引名得和 name 一致(别靠子串, 名字会互为前缀): {name} / {create_sql}"
    );
    // `sql` 列对**自动生成的索引**(UNIQUE 约束产生的 `sqlite_autoindex_*`)是 NULL, 直接
    // `get::<String>` 会抛 InvalidColumnType。取 Option 再判, NULL 就放过。
    // ⚠️ 更正一句我原先写错的理由: 我说过"raw_payload_archive 有 UNIQUE 约束所以会打挂"——
    //    **不对**。自动索引一律叫 `sqlite_autoindex_*`, 而 SQLite **拒绝**用户建 `sqlite_` 开头的索引,
    //    所以"拿普通索引名调本函数、库里恰好有个同名自动索引"这个场景造不出来, 这个分支实际不可达。
    //    留着是防御性的(将来若有人主动传自动索引名), 但别拿一个不成立的理由当依据。
    let existing: Option<Option<String>> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
            [name],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?;
    let existing: Option<String> = match existing {
        Some(None) => return Ok(false), // 自动生成的索引(sql 为 NULL), 不动它
        Some(Some(sql)) => Some(sql),
        None => None,
    };
    match existing {
        // 定义一致 → 什么都不做(绝大多数情况走这条)。
        Some(sql) if norm(&sql) == norm(create_sql) => Ok(false),
        // 定义漂了 → 重建。出声, 因为大库上重建要几十秒, 用户该知道为什么卡。
        Some(sql) => {
            tracing::info!(
                index = name,
                "索引定义与当前代码不一致 → 重建(旧库升级的正常一步; 大库上可能要几十秒)"
            );
            tracing::debug!(index = name, old = %sql, "旧定义");
            // 原子化: DROP 完、CREATE 前崩掉的话库里会**没有这条索引** —— 下次可写 init 能自愈, 但只查
            // 不 ingest 的用户会长期少一条且不知道。
            //
            // ⚠️ **必须用 SAVEPOINT 不能用 BEGIN**: `init_l1_schema` 可能被调用方包在外层事务里调,
            //    那时嵌套 `BEGIN` 直接报 "cannot start a transaction within a transaction", 把整个
            //    init 打挂, 而且连接**卡在事务态**。我上一版就是写的 BEGIN, 实测确实炸
            //    —— 为了修一个「崩溃留下没索引的库」的低概率问题, 换来一个**确定会炸**的场景。
            //    SAVEPOINT 可以嵌套: 没有外层事务时它自己开一个, 有外层时它就是个嵌套点。
            //    ⚠️ 还得**自己收拾错误路径**: `execute_batch` 在 CREATE 失败时直接返回, `RELEASE` 不会执行
            //       —— 连接就卡在 savepoint 里(写锁不放), 而索引已经被 DROP 掉了。实测过: 无外层事务时
            //       `is_autocommit` 变 false、索引没了; 有外层事务时那个「只删没建」还会被外层 COMMIT
            //       **永久提交**。改动前是两次独立 autocommit, 失败后连接是干净的 —— 所以这一步不做的话,
            //       崩溃路径修好了, 错误路径(磁盘满 / BUSY / 中断)反而更糟。
            conn.execute_batch(&format!(
                "SAVEPOINT reconcile_idx; DROP INDEX IF EXISTS {name}; {create_sql}; RELEASE reconcile_idx;"
            ))
            .inspect_err(|_| {
                // 回滚到 savepoint 再释放: 索引回到 DROP 之前的样子, 连接也不再卡在事务里。
                // 这里的失败无从处理(原错误更重要), 但要出声 —— 静默的话下一个人只会看到「连接怪怪的」。
                if let Err(e2) = conn.execute_batch("ROLLBACK TO reconcile_idx; RELEASE reconcile_idx;") {
                    // ⚠️ 文案别写成「连接可能仍在事务中」—— 审查方用 progress_handler 强制中断实测 18 组,
                    //    ROLLBACK 失败的典型原因恰恰是 **SQLite 自己已经把整个事务回滚掉了**
                    //    (没有 savepoint 可回), 此时 autocommit=true、索引也还在。
                    //    有外层事务时调用方的 COMMIT 会拿到 "cannot commit - no transaction is active"。
                    //    按原文案排查会走反方向。
                    tracing::warn!(
                        index = name,
                        error = %e2,
                        "回滚索引重建失败(常见原因: SQLite 已自行回滚整个事务, savepoint 不存在了) ——                          若调用方有外层事务, 它的 COMMIT 可能会报 no transaction is active"
                    );
                }
            })?;
            Ok(true)
        }
        // 还没有 → 建(上面那批 CREATE IF NOT EXISTS 本该建好, 走到这说明批里漏了它)。
        None => {
            conn.execute_batch(&format!("{create_sql};"))?;
            Ok(true)
        }
    }
}

/// R11: 旧库迁移记 info! —— **真加了 ≥1 列才记** (老库已全有 = no-op, 每次启动打会刷屏)。
/// `table`/列名是 schema, 非 PII, 可带。各 `ensure_*_columns` 算出 `added`(缺的目标列数)后调它。
fn note_migration(table: &str, added: usize) {
    if added > 0 {
        tracing::info!(table, added, "旧库迁移: 补列");
    }
}

/// R11: 表当前列数 (PRAGMA table_info 行数)。ensure_* 用「迁移前后差」算真加的列数,
/// 免列出目标列 / 免与 ALTER 列表脱节。表名是 schema (非 PII)。
fn count_columns(conn: &Connection, table: &str) -> rusqlite::Result<usize> {
    Ok(conn
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))?
        .query_map([], |_| Ok(()))?
        .count())
}

/// 旧 message 表补列 (server_seq / origin_source / upload_status / download_status INTEGER NOT NULL DEFAULT 0;
/// ALTER ADD NOT NULL 必带 DEFAULT + sys_type nullable TEXT)。旧 schema 迁移。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_message_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(message)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数 (与其余 ensure_* 一致, 用前后差实测)
    if !existing.contains("server_seq") {
        conn.execute_batch("ALTER TABLE message ADD COLUMN server_seq INTEGER NOT NULL DEFAULT 0")?;
    }
    // Msg_ 现成整数列 (来源/上传/下载状态), L2-only。ALTER ADD NOT NULL 必带 DEFAULT 0。
    if !existing.contains("origin_source") {
        conn.execute_batch("ALTER TABLE message ADD COLUMN origin_source INTEGER NOT NULL DEFAULT 0")?;
    }
    if !existing.contains("upload_status") {
        conn.execute_batch("ALTER TABLE message ADD COLUMN upload_status INTEGER NOT NULL DEFAULT 0")?;
    }
    if !existing.contains("download_status") {
        conn.execute_batch("ALTER TABLE message ADD COLUMN download_status INTEGER NOT NULL DEFAULT 0")?;
    }
    if !existing.contains("sys_type") {
        // nullable TEXT (非系统消息 NULL) → ALTER ADD 无需 DEFAULT (批F)。
        conn.execute_batch("ALTER TABLE message ADD COLUMN sys_type TEXT")?;
    }
    note_migration("message", count_columns(conn, "message")?.saturating_sub(before));
    Ok(())
}

/// 落库前删掉 message/archive 的**二级索引** (批量全量落库时, 每条都维护 5 棵索引 B-tree 很费;
/// 落完再一次性重建, 比逐条维护快得多)。
///
/// **只删二级索引** (`CREATE INDEX` 建的那 5 个); message 的 PRIMARY KEY 与 archive 的 UNIQUE(5 元组)
/// 是**表级约束索引**, 不受此影响 → INSERT OR REPLACE / OR IGNORE 的**去重语义不变**。
/// 增量场景也会 drop+重建 (全量优先; 增量少量重建索引的取舍留后优化)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn drop_ingest_indexes(conn: &Connection) -> rusqlite::Result<()> {
    // 走同一份清单 —— 硬编码第三份副本的话, 漂开的后果**不对称**: 清单里加了而这里漏 = 只是慢;
    // **这里加了而清单漏 = 索引被删掉后永远建不回来, 而且静默**。
    // 不是纸上谈兵: 真库 msgcol-l1.db(77 万条消息)现在这 6 条一条都没有, 而别的 idx_message_* 都在
    // —— 说明 drop 跑过、create 没跑完, 「少一条索引且不知道」已经发生过。
    let sql: String = INGEST_REBUILT_INDEXES
        .iter()
        .map(|(name, _)| format!("DROP INDEX IF EXISTS {name};"))
        .collect::<Vec<_>>()
        .join("\n         ");
    conn.execute_batch(&sql)
}

/// **落库前后会 drop/重建的那批索引 —— 唯一权威定义。**
///
/// 收成一份的理由: 同一条索引的定义原先散在三处(建表批 / reconcile 的目标 / 落库收尾的重建批),
/// 只要有一处漂开, 每次 ingest 结尾就把定义写成旧的 → 下次 init 又重建 → 再被 drop, 来回折腾,
/// 而库里长期停在错误定义上, 还没有任何守卫看得见(文档守卫只比名字)。独立审查点名的 P2。
/// message 那 4 条(供 `init_message_table` —— 它不该依赖 archive 表存在)。
const MESSAGE_REBUILT_INDEXES: &[(&str, &str)] = &[
    (
        "idx_message_conv_time_full",
        "CREATE INDEX idx_message_conv_time_full ON message          (account_id_sha, conv_id_sha, create_time DESC, source_native_id DESC, source DESC)",
    ),
    (
        "idx_message_conv_time",
        "CREATE INDEX idx_message_conv_time ON message (account_id_sha, conv_id_sha, create_time DESC)",
    ),
    ("idx_message_server_id", "CREATE INDEX idx_message_server_id ON message (account_id_sha, server_id)"),
    ("idx_message_type", "CREATE INDEX idx_message_type ON message (account_id_sha, msg_type)"),
];

/// archive 那 2 条(供 `init_archive_table`)。
const ARCHIVE_REBUILT_INDEXES: &[(&str, &str)] = &[
    (
        "idx_archive_account_ingest",
        "CREATE INDEX idx_archive_account_ingest ON raw_payload_archive (account_id_sha, ingest_time DESC)",
    ),
    (
        "idx_archive_event_type",
        "CREATE INDEX idx_archive_event_type ON raw_payload_archive (event_type, event_action)",
    ),
];

const INGEST_REBUILT_INDEXES: &[(&str, &str)] = &[
    (
        "idx_message_conv_time_full",
        "CREATE INDEX idx_message_conv_time_full ON message          (account_id_sha, conv_id_sha, create_time DESC, source_native_id DESC, source DESC)",
    ),
    (
        "idx_message_conv_time",
        "CREATE INDEX idx_message_conv_time ON message (account_id_sha, conv_id_sha, create_time DESC)",
    ),
    ("idx_message_server_id", "CREATE INDEX idx_message_server_id ON message (account_id_sha, server_id)"),
    ("idx_message_type", "CREATE INDEX idx_message_type ON message (account_id_sha, msg_type)"),
    (
        "idx_archive_account_ingest",
        "CREATE INDEX idx_archive_account_ingest ON raw_payload_archive (account_id_sha, ingest_time DESC)",
    ),
    (
        "idx_archive_event_type",
        "CREATE INDEX idx_archive_event_type ON raw_payload_archive (event_type, event_action)",
    ),
];

/// 落库后重建 message/archive 二级索引 (定义跟 [`init_message_table`] / [`init_archive_table`] 一致;
/// IF NOT EXISTS 幂等)。配 [`drop_ingest_indexes`] 用 (落库前 drop, 落完 create)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn create_ingest_indexes(conn: &Connection) -> rusqlite::Result<()> {
    // 走 reconcile 而不是裸 CREATE IF NOT EXISTS: 后者只认名字, 定义漂了一声不吭 ——
    // 而这里是每次全量 ingest 的**收尾**, 用旧定义建回去的话库会长期停在错的索引上。
    for (name, sql) in INGEST_REBUILT_INDEXES {
        reconcile_index(conn, name, sql)?;
    }
    Ok(())
}

// ── 全文搜索 (FTS5; ADR-502) ──

/// 建全文搜索虚表 `message_fts` (FTS5 external-content over `message.text_content`; trigram 分词)。
///
/// - **external-content** (`content='message'`, `content_rowid='rowid'`): FTS 只存倒排索引, 正文仍在
///   message 表本身 (message 无 `WITHOUT ROWID` → 有隐式整数 rowid 可关联), **不复制一份正文**, 省存储。
/// - **trigram** 分词: 不需要中文词典, 按 3-字符滑窗建索引, 支持任意 ≥3 字的**子串**匹配 (含中文)。
///   bundled sqlite (≥3.34) 内建; 竞品 chatlog 走 FTS5+bm25, 中文场景 trigram 是最稳的选择。
///
/// # Errors
/// rusqlite 执行失败 (若 sqlite 未编译 FTS5 会在此报错; bundled 默认带)。
pub fn init_message_fts(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
            text_content,
            content='message',
            content_rowid='rowid',
            tokenize='trigram'
        );",
    )
}

/// 从 message 表重建整个 FTS 索引 (external-content `'rebuild'` 命令; 幂等, 覆盖旧内容)。返回索引行数。
///
/// 落库 / 增量 ingest 后调一次即可让搜索跟上最新 message (external-content 无触发器, 靠显式 rebuild)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn rebuild_message_fts(conn: &Connection) -> rusqlite::Result<i64> {
    init_message_fts(conn)?;
    conn.execute_batch("INSERT INTO message_fts(message_fts) VALUES('rebuild');")?;
    let rows: i64 = conn.query_row("SELECT count(*) FROM message_fts", [], |r| r.get(0))?;
    tracing::info!(rows, "FTS 全文索引重建");
    Ok(rows)
}

/// 建 `message_fts` **增量维护触发器** (R9 件1; external-content FTS5 官方增量法): message 表
/// INSERT/UPDATE/DELETE 自动同步 FTS 倒排, 不再靠手动全量 [`rebuild_message_fts`]。
///
/// **`INSERT OR REPLACE` 换 rowid 自动正确**: message 是复合 PK + 隐式 rowid, REPLACE 撞键 = SQLite 内部
/// **DELETE 旧行 (触发 `_ad` 用**旧正文**准确删旧 FTS 项) + INSERT 新行 (触发 `_ai` 插新 FTS)** → 无悬空倒排;
/// 与 message 写入**同事务原子**, 崩溃回滚一致。这正是 external-content FTS "external-content 无自动触发器"
/// 现状 (仅显式 `'rebuild'`) 的补齐。
///
/// **用法 (SQLite bulk-load 标准)**: build / 全量 ingest 前先 [`drop_message_fts_triggers`] + 跑完再
/// [`rebuild_message_fts`] 一次性重建 (避开逐条 trigram 分词开销), **之后**建触发器走增量; 增量 (watch tail-f
/// 少量新消息) 触发器逐条维护开销小。
///
/// # Errors
/// rusqlite 执行失败 (FTS5 未编译则 `init_message_fts` 先报)。
pub fn init_message_fts_triggers(conn: &Connection) -> rusqlite::Result<()> {
    init_message_fts(conn)?; // 触发器前提: FTS 虚表在。
    conn.execute_batch(
        "CREATE TRIGGER IF NOT EXISTS message_fts_ai AFTER INSERT ON message BEGIN
            INSERT INTO message_fts(rowid, text_content) VALUES (new.rowid, new.text_content);
        END;
        CREATE TRIGGER IF NOT EXISTS message_fts_ad AFTER DELETE ON message BEGIN
            INSERT INTO message_fts(message_fts, rowid, text_content) VALUES('delete', old.rowid, old.text_content);
        END;
        CREATE TRIGGER IF NOT EXISTS message_fts_au AFTER UPDATE ON message BEGIN
            INSERT INTO message_fts(message_fts, rowid, text_content) VALUES('delete', old.rowid, old.text_content);
            INSERT INTO message_fts(rowid, text_content) VALUES (new.rowid, new.text_content);
        END;",
    )
}

/// 删 `message_fts` 增量维护触发器 (build / 全量 ingest 前调, 避开逐条 FTS 维护开销; 之后
/// [`rebuild_message_fts`] 一次性重建 + [`init_message_fts_triggers`] 重建触发器)。幂等 (`IF EXISTS`)。
///
/// # Errors
/// rusqlite 执行失败。
pub fn drop_message_fts_triggers(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS message_fts_ai;
         DROP TRIGGER IF EXISTS message_fts_ad;
         DROP TRIGGER IF EXISTS message_fts_au;",
    )
}

/// `message_fts` 增量维护触发器是否已建 (三个都在才算; 供 `live-index status` / 测试查)。
#[must_use]
pub fn message_fts_triggers_exist(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='trigger' \
         AND name IN ('message_fts_ai', 'message_fts_ad', 'message_fts_au')",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n == 3)
    .unwrap_or(false)
}

/// R9 件1: **一步建/重建 FTS 索引 + 增量触发器** —— `search --build` / `live-index build` 的入口。
/// 全量 [`rebuild_message_fts`] 对齐当前 message → 建触发器 [`init_message_fts_triggers`] (之后 message
/// 写入自动增量维护, **不再需 ingest 后手动 rebuild**)。返索引行数。
///
/// 取代裸 `rebuild_message_fts`: build 后触发器在岗, 后续 ingest/watch 新消息自动进 FTS —— 修掉
/// "external-content 无触发器, ingest 后要手动重建"的冷 FTS 重建式缺陷 (spec §10 决策4: 件1 提前 P1,
/// 冷查自身受益、不依赖 live-index)。**全量 rebuild 先跑** (对齐历史) **再建触发器** (顺序要紧: 触发器只管
/// 建后的增量, 建前的历史靠这次 rebuild 一次性灌)。
///
/// # Errors
/// rusqlite 执行失败。
pub fn build_message_fts_incremental(conn: &Connection) -> rusqlite::Result<i64> {
    let n = rebuild_message_fts(conn)?; // 全量重建对齐当前 message (建触发器前的历史一次性灌)。
    init_message_fts_triggers(conn)?; // 建触发器 → 后续增量自动维护。
    Ok(n)
}

// ── R9 件2: thin 独立瘦 FTS 库 (自存 content, 不挂 L1; 只搜索) ──

/// R9 件2: 建 **thin 独立瘦 FTS** schema —— **自存 content** FTS5 (存 `msg_id` + `text`, 非 external-content →
/// 不需 base 表在同库, 能自成一库)。`msg_id` `UNINDEXED` (可取回、不进匹配 → 按 msg_id 回连 L1/热查取整条);
/// `text` trigram (与冷查 `message_fts` 一致 → 同词冷/热搜结果一致)。每账号一个独立 `.db`
/// (`<cache>/live-index/<account_sha8>.thin-fts.db`, 按账号隔离)。
///
/// # Errors
/// rusqlite 执行失败 (FTS5 未编译则在此报)。
pub fn init_thin_fts(conn: &Connection) -> rusqlite::Result<()> {
    // 列: msg_id(锚) + source(分片, 如 message_0.db) + text(唯一被索引列)。source 参与结果身份 ——
    // 跨分片同锚是相异消息 (codex 复审 P2), 单 msg_id 不足以唯一定位, 须连 source 才能 rejoin L1 (PK 含 source)。
    conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS thin_fts USING fts5(
            msg_id UNINDEXED,
            source UNINDEXED,
            text,
            tokenize='trigram'
        );",
    )
}

/// R5 复审 P1#1: thin 库**账号绑定**表 —— thin build 按账号过滤正文后, 把该账号 `account_id_sha` 存这里; search 时
/// 核对请求账号是否与之相符, 防"账号 A 的 thin 库被 `--account B` 搜出 A 的数据"(thin_fts 无账号列、搜索无从自证)。
/// 单行, key 固定 `account_sha`。
///
/// # Errors
/// rusqlite 执行失败。
pub fn init_thin_meta(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS thin_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);")
}

/// 写 thin 库绑定的账号 `account_id_sha`。build 收尾调 (与灌数据同事务); 幂等 upsert。
///
/// # Errors
/// rusqlite 执行失败。
pub fn set_thin_account(conn: &Connection, account_sha: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO thin_meta(key, value) VALUES ('account_sha', ?1) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![account_sha],
    )?;
    Ok(())
}

/// 读 thin 库绑定的账号 `account_id_sha`。`Ok(None)` = 库没绑 (旧库无 `thin_meta` 表, 向后兼容不报错); `Ok(Some(sha))` = 绑了。
///
/// # Errors
/// rusqlite 执行失败 (非"表不存在")。
pub fn get_thin_account(conn: &Connection) -> rusqlite::Result<Option<String>> {
    let has: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='thin_meta'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has == 0 {
        return Ok(None); // 旧 thin 库无绑定表 → 视为未绑 (向后兼容)。
    }
    conn.query_row("SELECT value FROM thin_meta WHERE key = 'account_sha'", [], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .map(|o| o.filter(|s| !s.is_empty()))
}

/// R18 件2: 写 thin 库的**增量续抽水位** —— source tail-f 的续点 (daemon 定义格式的不透明串, 如各分片 local_id
/// 游标 JSON)。**与 FTS 插入同事务提交** → 崩溃一致 (要么正文进索引且水位前移, 要么都不动), 重启从此续抽, 不回放不漏。
/// 幂等 upsert (键 `watermark`)。
///
/// # Errors
/// rusqlite 执行失败。
pub fn set_thin_watermark(conn: &Connection, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO thin_meta(key, value) VALUES ('watermark', ?1) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![value],
    )?;
    Ok(())
}

/// R18 件2: 读 thin 库续抽水位。`Ok(None)` = 没写过 (首建 / 旧 thin 库无 `thin_meta` 表, 向后兼容 → daemon 从头抽);
/// `Ok(Some(v))` = 有续点。空串亦视为无 (与 [`get_thin_account`] 同口径)。
///
/// # Errors
/// rusqlite 执行失败 (非"表不存在")。
pub fn get_thin_watermark(conn: &Connection) -> rusqlite::Result<Option<String>> {
    let has: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='thin_meta'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has == 0 {
        return Ok(None); // 旧 thin 库无 meta 表 → 视为无水位 (向后兼容)。
    }
    conn.query_row("SELECT value FROM thin_meta WHERE key = 'watermark'", [], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .map(|o| o.filter(|s| !s.is_empty()))
}

/// thin FTS 的 **rowid 去重键方案版本**。`v1` = `thin_rowid(msg_id)` 单锚键; `v2` = `thin_rowid(source, msg_id)`
/// 含分片键 (codex 复审 P1: 修跨分片同锚撞覆盖)。键方案变更时递增 —— [`ensure_thin_rowkey_current`] 据此决定
/// 是否清空旧索引重建 (防旧方案行与新方案行并存重复倒排)。
pub const THIN_ROWKEY_VERSION: &str = "2";

/// 写 thin 库的 rowkey 键方案版本 (幂等 upsert, 键 `rowkey_version`)。
///
/// # Errors
/// rusqlite 执行失败。
pub fn set_thin_rowkey_version(conn: &Connection, version: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO thin_meta(key, value) VALUES ('rowkey_version', ?1) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![version],
    )?;
    Ok(())
}

/// 读 thin 库 rowkey 键方案版本。`None` = 没写过 (旧库 / v1 无版本标记)。
///
/// # Errors
/// rusqlite 执行失败 (非"表不存在")。
pub fn get_thin_rowkey_version(conn: &Connection) -> rusqlite::Result<Option<String>> {
    let has: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='thin_meta'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has == 0 {
        return Ok(None);
    }
    conn.query_row("SELECT value FROM thin_meta WHERE key = 'rowkey_version'", [], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .map(|o| o.filter(|s| !s.is_empty()))
}

/// 开库**维护前**核对 rowkey 键方案版本 (codex/Claude 复审 P1 迁移守卫)。版本 != 当前 ([`THIN_ROWKEY_VERSION`],
/// 含"无版本标记"=旧库) 时按**两facet取并**迁移: ① thin_fts 缺 `source` 列 (旧 schema) → DROP+重建新 schema;
/// ② schema 已新但非空 (旧 hash 方案的残留行) → 清行。两者都抹水位 (下次从头按当前方案全重建), 标当前版本, 返 `true`。
/// 空库+新 schema (fresh) / 版本相符 → 仅补标当前版本, 返 `false`。**须在 `init_thin_fts` + `init_thin_meta` 之后调**。
///
/// # Errors
/// rusqlite 执行失败。
pub fn ensure_thin_rowkey_current(conn: &Connection) -> rusqlite::Result<bool> {
    // 版本已是当前 → 直接返 (最常路径, 免检)。
    if get_thin_rowkey_version(conn)?.as_deref() == Some(THIN_ROWKEY_VERSION) {
        return Ok(false);
    }
    // 版本不符 (None = 旧库无标记 / 新库 init 后未标; 或旧版本号)。**两种独立变更取并处理** (Claude 末轮附加洞):
    //  ① schema 变 (列变, 如 v1→v2 加 source): thin_fts 无 source 列 → 必 **DROP + 重建**新 schema ——
    //     `CREATE VIRTUAL TABLE IF NOT EXISTS` 对已存在旧表 no-op、加不了列 → 只清行的话 daemon 带 source 的
    //     INSERT / search 的 SELECT source 全 "no such column: source", 旧库彻底不可用 (codex 末轮 P1)。
    //  ② rowkey 哈希方案变但 schema 不变 (未来 v2→v3 只改 hash 不改列): schema OK 但残留旧 hash 行 → 必**清行**重灌,
    //     否则旧 hash 行与新 hash 行并存 → 重复倒排 (正是最初 R18 要修的 bug)。**只按 schema 判会漏 ②** → 判据取并。
    let schema_old = !thin_fts_has_source(conn)?;
    // **一个事务原子** (unchecked_transaction 用于 &Connection; thin 有单写者锁无并发): DROP/清 fts + 抹水位 +
    // 标版本 要么全成要么全滚。**关键**: 若不原子, 崩在"清了 fts 但没抹 watermark"之间 → 重启读残留旧游标从
    // 中途续抽 → 漏掉游标之前的早期消息。原子后崩则整体回滚, 重启重做, 不漏。
    let tx = conn.unchecked_transaction()?;
    let migrated = if schema_old {
        // ① 旧 schema → DROP 旧虚表 + 重建当前 schema (msg_id, source, text) + 抹水位 (顺带清所有旧行)。DDL 事务内。
        // 无条件 DROP → 不需 count (损坏 FTS 也一并重建修复), 故此分支不查 count。
        tx.execute_batch(
            "DROP TABLE IF EXISTS thin_fts; \
             CREATE VIRTUAL TABLE thin_fts USING fts5(msg_id UNINDEXED, source UNINDEXED, text, tokenize='trigram');",
        )?;
        tx.execute("DELETE FROM thin_meta WHERE key = 'watermark'", [])?;
        true
    } else {
        // ② schema 已新: 需**准确** count 判有无旧 hash 残留行 → count 失败必**传播** (codex 末轮 P2: 别 unwrap_or(0)
        // 把损坏 FTS 影子表当空 → 漏清 + 标版本 → 后续跳过迁移永不修复)。非空 → 清行 + 抹水位重灌; 空 (fresh) → 仅标版本。
        let n: i64 = tx.query_row("SELECT count(*) FROM thin_fts", [], |r| r.get(0))?;
        if n > 0 {
            tx.execute("DELETE FROM thin_fts", [])?;
            tx.execute("DELETE FROM thin_meta WHERE key = 'watermark'", [])?;
            true
        } else {
            false
        }
    };
    tx.execute(
        "INSERT INTO thin_meta(key, value) VALUES ('rowkey_version', ?1) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![THIN_ROWKEY_VERSION],
    )?;
    tx.commit()?;
    Ok(migrated)
}

/// R9 件2: 插一条到 thin FTS (自存 msg_id + text)。批量灌 (build) / watch 增量刷共用。
/// **去重按 rowid** (调用方以 msg_id 派生稳定整数当 rowid 传入 → `DELETE WHERE rowid=?` O(log N) 幂等; 见
/// spec §7)。`rowid` 显式给 → tail 重试重复 msg 时覆盖不重复倒排 (自存 content FTS 支持 rowid upsert 语义:
/// 先按 rowid delete 旧再插, 由调用方保证同 msg_id → 同 rowid)。
///
/// # Errors
/// rusqlite 执行失败。
pub fn insert_thin_msg(conn: &Connection, rowid: i64, source: &str, msg_id: &str, text: &str) -> rusqlite::Result<()> {
    // 幂等: 同 rowid 先删旧 (自存 content FTS 无 external 'delete' 语义, 直接按 rowid DELETE 再插)。
    conn.execute("DELETE FROM thin_fts WHERE rowid = ?1", rusqlite::params![rowid])?;
    conn.execute(
        "INSERT INTO thin_fts(rowid, msg_id, source, text) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![rowid, msg_id, source, text],
    )?;
    Ok(())
}

/// R9 件2: 搜 thin FTS (MATCH + `snippet()` 高亮)。返 `(msg_id, source, snippet)` 列表 —— `(msg_id, source)` 供
/// **唯一**回连 L1/热查取整条 (跨分片同锚须连 source 才唯一, codex 复审 P2; text 是列 2)。
/// `query` <3 字 trigram 建不了索引 → 空结果 (thin 只搜索, 无 LIKE 兜底; 短词回退让消费者走冷/热 LIKE)。
///
/// # Errors
/// rusqlite 查询失败 (MATCH 语法错等)。
/// thin_fts 是否已是**当前 schema**(有 `source` 列)。旧库 (pre-source-列) 无此列 → 只读搜索路径据此给清晰
/// "请重建"提示, 而非裸 "no such column: source" SQL 错 (codex 末轮 P1: 旧库搜索也 fail)。`Ok(false)` = 无 source
/// 列 (旧 schema) 或表不存在。
///
/// # Errors
/// rusqlite 执行失败。
pub fn thin_fts_has_source(conn: &Connection) -> rusqlite::Result<bool> {
    let has: i64 = conn
        .query_row(
            "SELECT count(*) FROM pragma_table_info('thin_fts') WHERE name = 'source'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(has > 0)
}

pub fn search_thin(conn: &Connection, query: &str, limit: usize) -> rusqlite::Result<Vec<(String, String, String)>> {
    if query.chars().count() < 3 {
        return Ok(Vec::new()); // trigram 需 ≥3 字。
    }
    let mut st = conn.prepare(
        "SELECT msg_id, source, snippet(thin_fts, 2, '[', ']', '…', 12) \
         FROM thin_fts WHERE thin_fts MATCH ?1 ORDER BY rank LIMIT ?2",
    )?;
    let rows = st
        .query_map(rusqlite::params![query, limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .filter_map(std::result::Result::ok)
        .collect();
    Ok(rows)
}

/// R9 件6: **FTS 段合并** (external-content `'optimize'`) —— 纯增量插会碎片化 (每次插一个新段) → 定期合并
/// 防长期膨胀/变慢 (spec §2 P1)。**调用点**: `run_message_watch` 长跑每 100 轮 pass 调 message_fts optimize
/// (双审 P3 已接, msgvestige-adapter); thin build 后调 [`optimize_thin_fts`]。共用逻辑, 只换目标表名。
///
/// # Errors
/// rusqlite 执行失败 (表不存在等)。
pub fn optimize_message_fts(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("INSERT INTO message_fts(message_fts) VALUES('optimize');")
}

/// R9 件6: thin FTS 段合并 (同 [`optimize_message_fts`], 目标 thin_fts)。
///
/// # Errors
/// rusqlite 执行失败。
pub fn optimize_thin_fts(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("INSERT INTO thin_fts(thin_fts) VALUES('optimize');")
}

/// R9 件6 + 复审R3#2: **单写者锁 guard** —— windows 持 OS 独占句柄 (句柄关=OS 释放锁 + DELETE_ON_CLOSE 删文件,
/// 含崩溃/强杀, 无残锁无 TOCTOU); 非 windows 持 lock 文件路径 drop 删 (兜底)。
pub struct WatchLockGuard {
    // **故意不读**: 这是 RAII 守卫, 持有句柄本身就是目的 —— 句柄活着 = 锁held, drop 掉 = OS 释放。
    // 没有任何代码"用"它是对的; 定点豁免而不是靠 crate 级 allow(dead_code) 盖住(那个已摘)。
    #[cfg(windows)]
    #[allow(dead_code)]
    handle: WindowsLockHandle,
    #[cfg(not(windows))]
    path: std::path::PathBuf,
}
#[cfg(not(windows))]
impl Drop for WatchLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// windows 独占锁句柄 (drop 时 CloseHandle → OS 释放独占 + FILE_FLAG_DELETE_ON_CLOSE 删锁文件)。
#[cfg(windows)]
struct WindowsLockHandle(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Drop for WindowsLockHandle {
    fn drop(&mut self) {
        // SAFETY: handle 来自 CreateFileW 成功返回, guard 独占持有仅此处 close 一次。DELETE_ON_CLOSE → OS 删锁文件。
        #[allow(unsafe_code)]
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
// HANDLE 是裸指针; guard 在 async serve (Send future) 里持有 → 标 Send/Sync (本进程独占, 无跨线程别名冲突)。
#[cfg(windows)]
#[allow(unsafe_code)] // HANDLE 独占持有, 无跨线程别名 (见上)
unsafe impl Send for WindowsLockHandle {}
#[cfg(windows)]
#[allow(unsafe_code)]
unsafe impl Sync for WindowsLockHandle {}

/// R9 件6 + 复审R3#2: **取单写者锁 (OS 独占, 崩溃安全, 无 TOCTOU)** —— 一账号 L1 同时只允许一个索引维护者
/// (watch / serve --live-index full) 写。
///
/// **windows**: `CreateFileW(dwShareMode=0)` 独占打开锁文件 `<l1>.live-index.lock` + `FILE_FLAG_DELETE_ON_CLOSE`。
/// 别进程再 open → `ERROR_SHARING_VIOLATION` = `INDEX_LOCKED`。句柄关 (正常退/panic/崩溃/强杀 —— OS 都关) → OS 释放
/// 独占 + 删文件。**无残锁、无 PID 检测、无 remove+create 抢锁竞态** (复审R3#2 根治 R2#5 的 TOCTOU)。
///
/// **非 windows** (兜底, 本工具主 win32): `create_new(O_EXCL)` 存在性锁 + drop 删 (崩溃留残锁, 保守报占用)。
///
/// # Errors
/// 锁被独占 (`INDEX_LOCKED` 语义, 皮层 cli_err 映射) / 建锁文件 IO 失败。
pub fn acquire_watch_lock(l1_path: &Path) -> Result<WatchLockGuard, String> {
    // P2-A: 按规范化路径去重 (同物理文件不同拼写各拿锁会击穿单写者)。
    let lock_base = match (l1_path.parent(), l1_path.file_name()) {
        (Some(parent), Some(fname)) => std::fs::canonicalize(parent)
            .map(|cp| cp.join(fname))
            .unwrap_or_else(|_| l1_path.to_path_buf()),
        _ => l1_path.to_path_buf(),
    };
    let mut lock = lock_base.into_os_string();
    lock.push(".live-index.lock");
    let path = std::path::PathBuf::from(lock);

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        use windows_sys::Win32::Foundation::{GetLastError, ERROR_SHARING_VIOLATION, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_DELETE_ON_CLOSE, FILE_GENERIC_WRITE, OPEN_ALWAYS,
        };
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: CreateFileW 标准 Win32 调用; wide 是 nul 结尾 UTF-16 路径, 其余参数为合法常量/空指针。
        #[allow(unsafe_code)]
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_ALWAYS,
                FILE_FLAG_DELETE_ON_CLOSE,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: 紧接失败调用取错误码, 无副作用。
            #[allow(unsafe_code)]
            let err = unsafe { GetLastError() };
            return if err == ERROR_SHARING_VIOLATION {
                Err(format!(
                    "另一索引维护者正独占此 L1 (锁 {}); 同时只允许一个 watch/serve full 写。等它退出或换库",
                    path.display()
                ))
            } else {
                Err(format!("取索引锁失败 (CreateFileW 错误码 {err}): {}", path.display()))
            };
        }
        Ok(WatchLockGuard {
            handle: WindowsLockHandle(handle),
        })
    }
    #[cfg(not(windows))]
    {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                use std::io::Write as _;
                let _ = write!(f, "pid={}", std::process::id());
                Ok(WatchLockGuard { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
                "另一索引维护者在写此 L1 (锁 {}); 若确无其它 watch/serve 在跑 (崩溃残留), 删该文件再试",
                path.display()
            )),
            Err(e) => Err(format!("取索引锁失败: {e}")),
        }
    }
}

/// 一条全文搜索命中 (正文 + 定位; conv_id/sender_wxid 明文, 调用方出口自负 K-R4 脱敏)。
#[derive(Debug, Clone)]
pub struct MessageSearchHit {
    pub create_time: i64,
    pub conv_id: String,
    pub sender_wxid: String,
    pub text_content: String,
}

/// `message_fts` 索引是否已建 (没建也能搜 — 退化成 LIKE 全表扫描, 慢但零索引存储)。
fn message_fts_exists(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='message_fts'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// 全文搜索 message 正文, 按 bm25 相关度取前 `limit` 条。
///
/// **走哪条**: query ≥3 字 **且**已建 `message_fts` 索引 → trigram FTS (ms 级); 否则 (索引没建 / query <3 字)
/// → message 全表 `LIKE` 扫描 (慢但正确、零索引)。**搜索不强依赖索引** —— 小库不建也能直接搜, 大库建了才快
/// (索引对 170 万条约 3GB, 存储紧张可不建)。query 内的 FTS/LIKE 元字符已转义, 防注入/误解析。
///
/// # Errors
/// rusqlite 执行失败.
/// `account_sha` (③b 多账号): `Some(account_id_sha)` → 只搜该账号消息 (两路都加 `account_id_sha=?` 谓词)。
/// 走**显式谓词**而非查询侧的 scope 视图 —— FTS 路靠 `message.rowid` 关联 `message_fts`, message 若被
/// temp view 遮蔽则 rowid 断; 故 search 用**非 scoped** conn + 此处显式过滤 (绑参, 无注入)。
pub fn search_messages(
    conn: &Connection,
    query: &str,
    limit: i64,
    account_sha: Option<&str>,
) -> rusqlite::Result<Vec<MessageSearchHit>> {
    use rusqlite::types::Value;
    let map = |r: &rusqlite::Row<'_>| {
        Ok(MessageSearchHit {
            create_time: r.get(0)?,
            conv_id: r.get(1)?,
            sender_wxid: r.get(2)?,
            text_content: r.get(3)?,
        })
    };
    if query.chars().count() >= 3 && message_fts_exists(conn) {
        // trigram: query 包成 FTS5 短语 (双引号裹 + 内部双引号转义), 避免被当查询语法 (AND/OR/*/:)。
        let phrase = format!("\"{}\"", query.replace('"', "\"\""));
        let acct = if account_sha.is_some() {
            " AND m.account_id_sha = ?3"
        } else {
            ""
        };
        let sql = format!(
            "SELECT m.create_time, m.conv_id, m.sender_wxid, m.text_content \
               FROM message_fts f JOIN message m ON m.rowid = f.rowid \
              WHERE message_fts MATCH ?1{acct} ORDER BY bm25(message_fts) LIMIT ?2"
        );
        let mut ps: Vec<Value> = vec![Value::Text(phrase), Value::Integer(limit)];
        if let Some(s) = account_sha {
            ps.push(Value::Text(s.to_string()));
        }
        conn.prepare(&sql)?
            .query_map(rusqlite::params_from_iter(ps), map)?
            .collect()
    } else {
        // <3 字: LIKE 兜底 (转义 % _ \ 防通配); 按时间倒序取最近。
        let esc = query.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        let like = format!("%{esc}%");
        let acct = if account_sha.is_some() {
            " AND account_id_sha = ?3"
        } else {
            ""
        };
        let sql = format!(
            "SELECT create_time, conv_id, sender_wxid, text_content \
               FROM message WHERE text_content LIKE ?1 ESCAPE '\\'{acct} \
              ORDER BY create_time DESC LIMIT ?2"
        );
        let mut ps: Vec<Value> = vec![Value::Text(like), Value::Integer(limit)];
        if let Some(s) = account_sha {
            ps.push(Value::Text(s.to_string()));
        }
        conn.prepare(&sql)?
            .query_map(rusqlite::params_from_iter(ps), map)?
            .collect()
    }
}

/// 写一条 message (INSERT OR REPLACE upsert on PK — 重解码同源消息刷新行, e.g. status 更新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message(conn: &Connection, m: &V3Message) -> rusqlite::Result<()> {
    conn.prepare_cached(
        "INSERT OR REPLACE INTO message
            (account_id_sha, source, source_native_id, conv_id_sha, server_id, create_time, sort_seq,
             status, msg_type, msg_type_name, msg_sub_type, msg_sub_type_name, local_type_raw,
             sender_wxid_sha, is_chatroom, text_content_sha, text_content_len, raw_xml_present, decode_kind,
             account_id, conv_id, sender_wxid, text_content, server_seq, sys_type,
             origin_source, upload_status, download_status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28)",
    )?
    .execute(params![
        m.account_id_sha, m.source, m.source_native_id, m.conv_id_sha, m.server_id, m.create_time,
        m.sort_seq, m.status, m.msg_type, m.msg_type_name, m.msg_sub_type, m.msg_sub_type_name,
        m.local_type_raw, m.sender_wxid_sha, m.is_chatroom, m.text_content_sha, m.text_content_len,
        m.raw_xml_present, m.decode_kind,
        m.account_id, m.conv_id, m.sender_wxid, m.text_content, m.server_seq, m.sys_type,
        m.origin_source, m.upload_status, m.download_status,
    ])?;
    Ok(())
}

// ── L2 person 业务表 (L1-schema §3.1.4) ──

/// 一条 person 联系人主行 (L1-schema §3.1.4 的 32 列; 4 sha/编号 + 5 明文 + 3 _len + local_type/is_in_chat_room +
/// 4 拼音 + verify_flag/delete_flag + 3 头像 + description/flag/chat_room_notify/chat_room_type [第五批] +
/// sex/country/province/city/friend_source [第七批 extra_buffer 解出]).
/// PK = (account_id_sha, source, username_sha).
///
/// **全 sha/派生值无裸文本**: `username_sha` 是联系人 wxid 的 sha; nick_name/remark/alias 只存
/// 【长度】 (`_len`, 不含明文也不含 sha — 这三者的 sha 在 §3.1.5 person_alias_by_account_min 别名表供 JOIN);
/// local_type / is_in_chat_room 是 metadata → `#[derive(Debug)]` K-R4 安全.
///
/// 投影来源 (decode contact_update 事件 → V3Person, 把 username 算 sha + 量三个名字长度) 推后续 (需 decode).
// 持明文列 (ADR-426 §2.1 第一类真实数据) → **不 derive Debug**, 手写出口脱敏 (ADR-426 §2.5 日志红线:
// struct 持明文, Debug/日志出口仍只出 _sha/sha8/len, 永不露裸 wxid/名字)。
#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // is_in_chat_room + 批G flag 位解码 4 bool = L2 业务列, 非配置 flag 惯例
pub struct V3Person {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub username_sha: String,
    // 明文列 (第一类真实数据; 与对应 _sha 同源, 由 project_person 统一构造保证一致 — ADR-426 §2.7.1)。
    pub account_id: String,
    pub username: String,
    pub nick_name: String,
    pub remark: Option<String>,
    pub alias: Option<String>,
    // _len 保留 (元数据, ADR-426 §2.1 KI-4)。
    pub nick_name_len: i64,
    pub remark_len: i64,
    pub alias_len: i64,
    pub local_type: i64,
    pub is_in_chat_room: bool,
    // 拼音搜索列 (明文, nullable; 搜索用, 不进 content_digest — ADR-412 §3.x.2 digest 字段集不变)。
    pub quan_pin: Option<String>,
    pub pin_yin_initial: Option<String>,
    pub remark_quan_pin: Option<String>,
    pub remark_pin_yin_initial: Option<String>,
    // 状态标志 (元数据; 进 content_digest — 第二批独立状态溯源, ADR-412 §3.x.2 字段集 8)。
    pub verify_flag: i64,
    pub delete_flag: i64,
    // 头像列 (资源明文, nullable; 进 L2 不进 content_digest — 第三批, ADR-450 §3)。
    pub big_head_url: Option<String>,
    pub small_head_url: Option<String>,
    pub head_img_md5: Option<String>,
    // 第五批补充列 (进 L2 不进 content_digest — ADR-450 §3): description 文本明文 nullable; flag/notify/type 元数据。
    pub description: Option<String>,
    pub flag: i64,
    pub chat_room_notify: i64,
    pub chat_room_type: i64,
    // 第七批补充列 (extra_buffer 解出; 进 L2 不进 content_digest — ADR-450 §3): sex/friend_source 元数据; 地区明文 nullable。
    pub sex: i64,
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub friend_source: i64,
    // 批G: flag 位解码 (元数据 bool; 进 L2 不进 digest — ADR-450 §3)。位定义 2026-07-08 用户真机 ground-truth 坐实
    // (改设置 diff flag, ADR-503): bit6 星标 / bit8 不让她看我(屏蔽) / bit11 置顶 / bit16 不看她 / bit23 仅聊天 / bit28 折叠。
    pub is_starred: bool,
    pub is_pinned: bool,
    /// 不让她看我的朋友圈 (屏蔽朋友圈, 她看不到我; flag bit8) — 真机测坐实, 早先误用 bit16 (纠正 ADR-459)。
    pub blocks_moments: bool,
    /// 不看她的朋友圈 (我把她的朋友圈隐藏; flag bit16) — 与 blocks_moments 是两个不同设置 (ADR-503)。
    pub hide_their_moments: bool,
    pub chat_only: bool,
    /// 折叠的群聊 (flag bit28=0x10000000; 三档小补丁 ADR-479; CipherTalk sessionList.ts:170)。
    pub is_collapsed: bool,
    // 免打扰 (派生自 local_type+chat_room_notify; 进 L2 不进 digest — 用户 2026-07-04 真人核对确认方向)。
    // 群(local_type=2) chat_room_notify=0 → 免打扰; 个人好友该字段无区分度(几乎全0) → 一律 false。
    pub is_muted: bool,
    // 批 I 补充列 (extra_buffer 再解; 进 L2 不进 content_digest — ADR-450 §3): 个性签名 / 朋友圈封面 URL (明文 nullable)。
    pub signature: Option<String>,
    pub moments_cover_url: Option<String>,
    // 标签件补充列 (extra_buffer f30 + contact_label map 解出; 进 L2 不进 content_digest — ADR-450 §3):
    // 联系人标签名逗号分隔 (明文 nullable; 标签名用户自设可能敏感 → Debug 省略, 出口脱敏)。
    pub labels: Option<String>,
    // 添加时间件补充列 (extra_buffer f41 varint; 进 L2 不进 content_digest — ADR-486): 好友添加时间 unix 秒
    // (nullable; 老版本/未回填 → NULL; 时间戳元数据非 PII → Debug 直显)。
    pub friend_add_time: Option<i64>,
    // 企微件补充列 (extra_buffer f4 内层 custom_info 解出; 进 L2 不进 content_digest — ADR-450 §3):
    // 企微 (@openim) 公司名 / 实名 (明文 nullable; 公司名/真实姓名 = PII → Debug 省略, 出口脱敏)。
    pub openim_company: Option<String>,
    pub openim_realname: Option<String>,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; 明文 id 列 → sha8; 名字列 → 只 len。
impl std::fmt::Debug for V3Person {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Person")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("username_sha", &self.username_sha)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("username_sha8", &crate::key_provider::sha8(self.username.as_bytes()))
            .field("nick_name_len", &self.nick_name_len)
            .field("remark_len", &self.remark_len)
            .field("alias_len", &self.alias_len)
            .field("local_type", &self.local_type)
            .field("is_in_chat_room", &self.is_in_chat_room)
            .field("verify_flag", &self.verify_flag)
            .field("delete_flag", &self.delete_flag)
            .field("flag", &self.flag)
            .field("chat_room_notify", &self.chat_room_notify)
            .field("chat_room_type", &self.chat_room_type)
            .field("sex", &self.sex)
            .field("friend_source", &self.friend_source)
            .field("is_starred", &self.is_starred)
            .field("is_collapsed", &self.is_collapsed)
            .field("is_pinned", &self.is_pinned)
            .field("blocks_moments", &self.blocks_moments)
            .field("hide_their_moments", &self.hide_their_moments)
            .field("chat_only", &self.chat_only)
            .field("is_muted", &self.is_muted)
            .field("friend_add_time", &self.friend_add_time) // 时间戳元数据, 非 PII → 直显
            // 明文列 (account_id/username/nick_name/remark/alias/description/country/province/city/signature/moments_cover_url/labels/openim_company/openim_realname) 有意省略 → non_exhaustive (K-R4 出口脱敏)。
            .finish_non_exhaustive()
    }
}

/// 建 person 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.4).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_person_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS person (
            account_id_sha   TEXT    NOT NULL,
            source           TEXT    NOT NULL,
            source_native_id TEXT    NOT NULL,
            username_sha     TEXT    NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类真实数据; 与对应 _sha 同源, project_person 统一构造)。
            account_id       TEXT    NOT NULL,
            username         TEXT    NOT NULL,
            nick_name        TEXT    NOT NULL,
            remark           TEXT,
            alias            TEXT,
            nick_name_len    INTEGER NOT NULL,
            remark_len       INTEGER NOT NULL,
            alias_len        INTEGER NOT NULL,
            local_type       INTEGER NOT NULL,
            is_in_chat_room  INTEGER NOT NULL,
            -- 拼音搜索列 (明文, nullable; 搜索用, 不进 content_digest — L1-schema §3.1.4)。
            quan_pin               TEXT,
            pin_yin_initial        TEXT,
            remark_quan_pin        TEXT,
            remark_pin_yin_initial TEXT,
            -- 状态标志 (元数据; 进 content_digest — 第二批独立状态溯源, L1-schema §3.1.4)。
            verify_flag INTEGER NOT NULL DEFAULT 0,
            delete_flag INTEGER NOT NULL DEFAULT 0,
            -- 头像列 (资源明文, nullable; 进 L2 不进 content_digest — 第三批, L1-schema §3.1.4)。
            big_head_url           TEXT,
            small_head_url         TEXT,
            head_img_md5           TEXT,
            -- 第五批补充列 (进 L2 不进 content_digest — ADR-450 §3): description 明文 nullable; flag/notify/type 元数据。
            description            TEXT,
            flag                   INTEGER NOT NULL DEFAULT 0,
            chat_room_notify       INTEGER NOT NULL DEFAULT 0,
            chat_room_type         INTEGER NOT NULL DEFAULT 0,
            -- 第七批补充列 (extra_buffer 解出; 进 L2 不进 content_digest — ADR-450 §3): sex/friend_source 元数据; 地区明文。
            sex                    INTEGER NOT NULL DEFAULT 0,
            country                TEXT,
            province               TEXT,
            city                   TEXT,
            friend_source          INTEGER NOT NULL DEFAULT 0,
            -- 批G: flag 位解码 (进 L2 不进 digest; 采 WDA 位定义)。星标/置顶/屏蔽朋友圈/仅聊天。
            is_starred             INTEGER NOT NULL DEFAULT 0,
            is_collapsed           INTEGER NOT NULL DEFAULT 0,
            is_pinned              INTEGER NOT NULL DEFAULT 0,
            blocks_moments         INTEGER NOT NULL DEFAULT 0,  -- bit8 不让她看我(屏蔽朋友圈); 真机坐实 ADR-503
            hide_their_moments     INTEGER NOT NULL DEFAULT 0,  -- bit16 不看她(我不看她朋友圈)
            chat_only              INTEGER NOT NULL DEFAULT 0,
            -- 免打扰 (派生 local_type+chat_room_notify; 进 L2 不进 digest — 用户 2026-07-04 确认)。群 notify=0=免打扰。
            is_muted               INTEGER NOT NULL DEFAULT 0,
            -- 批 I 补充列 (extra_buffer 再解; 进 L2 不进 digest — ADR-450 §3): 个性签名 / 朋友圈封面 URL (明文 nullable)。
            signature              TEXT,
            moments_cover_url      TEXT,
            -- 标签件补充列 (extra_buffer f30 + contact_label map 解出; 进 L2 不进 digest — ADR-450 §3): 标签名逗号分隔 (明文 nullable)。
            labels                 TEXT,
            -- 添加时间件补充列 (extra_buffer f41 varint; 进 L2 不进 digest — ADR-486): 好友添加时间 unix 秒 (nullable=老版本/未回填)。
            friend_add_time        INTEGER,
            -- 企微件补充列 (extra_buffer f4 内层 custom_info; 进 L2 不进 digest — ADR-450 §3): 企微公司名 / 实名 (明文 nullable)。
            openim_company         TEXT,
            openim_realname        TEXT,
            -- 身份键用 username_sha (全长 sha256, 不撞) 而非 source_native_id
            -- (= Contact_<md5 前8位>, 不同 username 前8位可能相同 → 撞键 → 后写覆盖丢人).
            -- 跟 §3.1.5 person_alias_by_account_min 身份键 (account_id_sha, username_sha) 一致;
            -- source_native_id 仍留列 (溯源 / archive 投影用), 只是不再当主键.
            -- ⚠ IF NOT EXISTS 不迁移既存表 PK: 旧 PK 库需重建或走 L1-schema §9 迁移 (新表+COPY+DROP+RENAME).
            PRIMARY KEY (account_id_sha, source, username_sha)
        );
        CREATE INDEX IF NOT EXISTS idx_person_username
            ON person (account_id_sha, username_sha);",
    )?;
    // codex P1: `CREATE TABLE IF NOT EXISTS` 不给**旧表**加列 → 旧 L1 上 insert 缺列会报
    // "no column named ..."。补: PRAGMA 检查缺列并 ALTER ADD (幂等; 新建表已含则全跳过)。
    ensure_person_extra_columns(conn)
}

/// 旧 person 表补字段扩充列 — 拼音/头像/description/第七批地区(country/province/city) (TEXT nullable) +
/// verify_flag/delete_flag/flag/chat_room_notify/chat_room_type/第七批 sex/friend_source
/// (INTEGER NOT NULL DEFAULT 0; ALTER ADD NOT NULL 列 SQLite 要求必带 DEFAULT)。旧 schema 迁移 (codex P1)。
/// `PRAGMA table_info` 取现有列, 缺则 `ALTER TABLE ADD COLUMN`; 幂等 (已有全跳过)。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_person_extra_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(person)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数
                                 // 拼音列 (第一批) + 头像列 (第三批): nullable TEXT — ALTER ADD 无需 DEFAULT。
    for col in [
        "quan_pin",
        "pin_yin_initial",
        "remark_quan_pin",
        "remark_pin_yin_initial",
        "big_head_url",
        "small_head_url",
        "head_img_md5",
        "description",
        "country",
        "province",
        "city",
        "signature",
        "moments_cover_url",
        "labels",
        // 企微件 (extra_buffer f4 custom_info): 公司名 / 实名 (明文 nullable TEXT — ALTER ADD 无需 DEFAULT)。
        "openim_company",
        "openim_realname",
    ] {
        if !existing.contains(col) {
            conn.execute_batch(&format!("ALTER TABLE person ADD COLUMN {col} TEXT"))?;
        }
    }
    // 状态标志 (第二批) + 第五批 flag/chat_room_notify/chat_room_type + 第七批 sex/friend_source + 批G flag 位解码
    // (is_starred/is_pinned/blocks_moments/chat_only): INTEGER NOT NULL — ALTER ADD NOT NULL 列必须带 DEFAULT (SQLite 约束)。
    for col in [
        "verify_flag",
        "delete_flag",
        "flag",
        "chat_room_notify",
        "chat_room_type",
        "sex",
        "friend_source",
        "is_starred",
        "is_collapsed",
        "is_pinned",
        "blocks_moments",
        "hide_their_moments",
        "chat_only",
        "is_muted",
    ] {
        if !existing.contains(col) {
            conn.execute_batch(&format!(
                "ALTER TABLE person ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"
            ))?;
        }
    }
    // 添加时间件 (ADR-486): friend_add_time = nullable INTEGER (NULL=老版本/未回填, 区别于 0=1970 哨兵) →
    // 单独 ALTER, 不带 NOT NULL DEFAULT (旧行补列即为 NULL, 语义正确)。
    if !existing.contains("friend_add_time") {
        conn.execute_batch("ALTER TABLE person ADD COLUMN friend_add_time INTEGER")?;
    }
    note_migration("person", count_columns(conn, "person")?.saturating_sub(before));
    Ok(())
}

/// 写一条 person (INSERT OR REPLACE upsert on PK — 重解码同源联系人刷新行, e.g. 改备注 / 进退群).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_person(conn: &Connection, p: &V3Person) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO person
            (account_id_sha, source, source_native_id, username_sha,
             account_id, username, nick_name, remark, alias,
             nick_name_len, remark_len, alias_len, local_type, is_in_chat_room,
             quan_pin, pin_yin_initial, remark_quan_pin, remark_pin_yin_initial,
             verify_flag, delete_flag,
             big_head_url, small_head_url, head_img_md5,
             description, flag, chat_room_notify, chat_room_type,
             sex, country, province, city, friend_source,
             is_starred, is_collapsed, is_pinned, blocks_moments, hide_their_moments, chat_only, is_muted,
             signature, moments_cover_url, labels, friend_add_time,
             openim_company, openim_realname)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45)",
        params![
            p.account_id_sha, p.source, p.source_native_id, p.username_sha,
            p.account_id, p.username, p.nick_name, p.remark, p.alias,
            p.nick_name_len, p.remark_len, p.alias_len, p.local_type, p.is_in_chat_room,
            p.quan_pin, p.pin_yin_initial, p.remark_quan_pin, p.remark_pin_yin_initial,
            p.verify_flag, p.delete_flag,
            p.big_head_url, p.small_head_url, p.head_img_md5,
            p.description, p.flag, p.chat_room_notify, p.chat_room_type,
            p.sex, p.country, p.province, p.city, p.friend_source,
            p.is_starred, p.is_collapsed, p.is_pinned, p.blocks_moments, p.hide_their_moments, p.chat_only, p.is_muted,
            p.signature, p.moments_cover_url, p.labels, p.friend_add_time,
            p.openim_company, p.openim_realname,
        ],
    )?;
    Ok(())
}

// ── L2 chatroom 业务表 (L1-schema §3.1.6) ──

/// 一条 chatroom 群信息行 (L1-schema §3.1.6). PK = (account_id_sha, source, source_native_id).
///
/// **持明文 (第一类) + 保留 _sha/_len (第二类)** — ADR-426 §2.1: `chatroom_id`/`owner_wxid` 裸 id +
/// `chatroom_name`/`announcement` 正文存明文列; 对应 `chatroom_id_sha`/`owner_wxid_sha` (PK/JOIN 键) +
/// `chatroom_name_len`/`announcement_len` 保留; member_count 是 metadata。明文与 _sha 同源 (project_chatroom)。
/// Debug 出口脱敏 (§2.5 K-R4): id→sha8, 正文→len。
#[derive(Clone, PartialEq, Eq)]
pub struct V3Chatroom {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub chatroom_id_sha: String,
    // 明文列 (第一类真实数据; 与对应 _sha 同源, project_chatroom 统一构造)。
    pub account_id: String,
    pub chatroom_id: String,
    pub owner_wxid: Option<String>,
    pub chatroom_name: String,
    pub announcement: Option<String>,
    // _len/metadata 保留 (第二类/元数据)。
    pub chatroom_name_len: i64,
    pub announcement_len: i64,
    pub member_count: i64,
    pub owner_wxid_sha: Option<String>,
    // 批H: 群公告编辑者 + 发布时间 (L2-only 不进 digest/payload)。
    pub announcement_editor: Option<String>,
    pub announcement_publish_time: i64,
    // ADR-460 KI-A/B: 富媒体群公告 XML + 群状态位 (L2-only 不进 digest/payload; status 未知→0)。
    pub xml_announcement: Option<String>,
    pub chat_room_status: i64,
    // 群备注 我给群的私人备注 (contact.remark; L2-only 明文 + _len; 不进 digest/payload)。
    pub chatroom_remark: Option<String>,
    pub chatroom_remark_len: i64,
    // ADR-493: 我是否仍在此群 (派生自 ext_buffer roster 含账号 wxid; L2-only 元数据 bool; 不进 digest/payload)。
    pub is_still_member: bool,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; 明文 id 列 → sha8; 正文列 → 只 len。
impl std::fmt::Debug for V3Chatroom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Chatroom")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("chatroom_id_sha", &self.chatroom_id_sha)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("chatroom_id_sha8", &crate::key_provider::sha8(self.chatroom_id.as_bytes()))
            .field("owner_wxid_sha8", &self.owner_wxid.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())))
            .field("chatroom_name_len", &self.chatroom_name_len)
            .field("announcement_len", &self.announcement_len)
            .field("member_count", &self.member_count)
            .field("owner_wxid_sha", &self.owner_wxid_sha)
            .field("announcement_editor_sha8", &self.announcement_editor.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())))
            .field("announcement_publish_time", &self.announcement_publish_time)
            // KI-A: xml_announcement 是富媒体公告内容 → Debug 只露长度 (不露内容, 同 announcement)。
            .field("xml_announcement_len", &self.xml_announcement.as_deref().map_or(0, |s| s.chars().count()))
            .field("chat_room_status", &self.chat_room_status)
            .field("chatroom_remark_len", &self.chatroom_remark_len)
            .field("is_still_member", &self.is_still_member)
            // 明文/内容列 (account_id/chatroom_id/owner_wxid/chatroom_name/announcement/xml_announcement/chatroom_remark) 有意省略。
            .finish_non_exhaustive()
    }
}

/// 建 chatroom 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.6).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_chatroom_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS chatroom (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            chatroom_id_sha   TEXT    NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; 与对应 _sha 同源, project_chatroom 统一构造)。
            account_id        TEXT    NOT NULL,
            chatroom_id       TEXT    NOT NULL,
            owner_wxid        TEXT,
            chatroom_name     TEXT    NOT NULL,
            announcement      TEXT,
            chatroom_name_len INTEGER NOT NULL,
            announcement_len  INTEGER NOT NULL,
            member_count      INTEGER NOT NULL,
            owner_wxid_sha    TEXT,
            announcement_editor        TEXT,               -- 批H: 群公告编辑者 wxid (nullable)
            announcement_publish_time  INTEGER NOT NULL DEFAULT 0, -- 批H: 群公告发布时间秒
            xml_announcement           TEXT,               -- KI-A: 富媒体群公告 XML (nullable)
            chat_room_status           INTEGER NOT NULL DEFAULT 0, -- KI-B: 群状态位 (语义待确认, 原值)
            chatroom_remark            TEXT,               -- 群备注 我给群的私人备注 (contact.remark; nullable)
            chatroom_remark_len        INTEGER NOT NULL DEFAULT 0, -- 群备注字符数
            is_still_member            INTEGER NOT NULL DEFAULT 1, -- ADR-493: 我是否仍在此群 (1在群/0已退; 默认1保守)
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_chatroom_id
            ON chatroom (account_id_sha, chatroom_id_sha);",
    )?;
    // 旧 chatroom 表 (无批H公告编辑者/发布时间) 补列 (同 message/person ensure 迁移)。
    ensure_chatroom_columns(conn)
}

/// 旧 chatroom 表补 L2-only 列 (announcement_editor TEXT / announcement_publish_time INTEGER NOT NULL
/// DEFAULT 0 = 批H; xml_announcement TEXT / chat_room_status INTEGER NOT NULL DEFAULT 0 = KI-A/B;
/// chatroom_remark TEXT / chatroom_remark_len INTEGER NOT NULL DEFAULT 0 = 群备注)。旧 schema 迁移
/// (IF NOT EXISTS 不给旧表加列; INTEGER NOT NULL 必带 DEFAULT 0, TEXT nullable 不用)。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_chatroom_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(chatroom)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数
    if !existing.contains("announcement_editor") {
        conn.execute_batch("ALTER TABLE chatroom ADD COLUMN announcement_editor TEXT")?;
    }
    if !existing.contains("announcement_publish_time") {
        conn.execute_batch("ALTER TABLE chatroom ADD COLUMN announcement_publish_time INTEGER NOT NULL DEFAULT 0")?;
    }
    // KI-A/B: 富媒体公告 XML (nullable) + 群状态位 (INTEGER NOT NULL DEFAULT 0)。
    if !existing.contains("xml_announcement") {
        conn.execute_batch("ALTER TABLE chatroom ADD COLUMN xml_announcement TEXT")?;
    }
    if !existing.contains("chat_room_status") {
        conn.execute_batch("ALTER TABLE chatroom ADD COLUMN chat_room_status INTEGER NOT NULL DEFAULT 0")?;
    }
    // 群备注 (contact.remark; 末尾追加, 列序与 fresh CREATE 一致)。
    if !existing.contains("chatroom_remark") {
        conn.execute_batch("ALTER TABLE chatroom ADD COLUMN chatroom_remark TEXT")?;
    }
    if !existing.contains("chatroom_remark_len") {
        conn.execute_batch("ALTER TABLE chatroom ADD COLUMN chatroom_remark_len INTEGER NOT NULL DEFAULT 0")?;
    }
    // ADR-493: 我是否仍在此群 (末尾追加, 列序与 fresh CREATE 一致; 默认 1 = 在群保守)。
    if !existing.contains("is_still_member") {
        conn.execute_batch("ALTER TABLE chatroom ADD COLUMN is_still_member INTEGER NOT NULL DEFAULT 1")?;
    }
    note_migration("chatroom", count_columns(conn, "chatroom")?.saturating_sub(before));
    Ok(())
}

/// 写一条 chatroom (INSERT OR REPLACE upsert on PK — 重解码同源群刷新行, e.g. member_count / 公告变).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_chatroom(conn: &Connection, c: &V3Chatroom) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO chatroom
            (account_id_sha, source, source_native_id, chatroom_id_sha,
             account_id, chatroom_id, owner_wxid, chatroom_name, announcement,
             chatroom_name_len, announcement_len, member_count, owner_wxid_sha,
             announcement_editor, announcement_publish_time,
             xml_announcement, chat_room_status,
             chatroom_remark, chatroom_remark_len, is_still_member)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            c.account_id_sha,
            c.source,
            c.source_native_id,
            c.chatroom_id_sha,
            c.account_id,
            c.chatroom_id,
            c.owner_wxid,
            c.chatroom_name,
            c.announcement,
            c.chatroom_name_len,
            c.announcement_len,
            c.member_count,
            c.owner_wxid_sha,
            c.announcement_editor,
            c.announcement_publish_time,
            c.xml_announcement,
            c.chat_room_status,
            c.chatroom_remark,
            c.chatroom_remark_len,
            c.is_still_member,
        ],
    )?;
    Ok(())
}

// ── L2 session 业务表 (L1-schema §3.1.8) ──

/// 一条 session 会话行 (聊天列表, L1-schema §3.1.8). PK = (account_id_sha, source, source_native_id).
///
/// **持明文 (第一类) + 保留 _sha (第二类)** — ADR-426 §2.1: `username` (会话对方 wxid 单聊 / 群 id 群聊,
/// = ADR 表 conv_id; 本表历史列名 username_sha) 存明文列, 对应 `username_sha` (JOIN 键) 保留;
/// unread_count/last_msg_type/last_msg_sub_type/sort_timestamp 是 metadata。Debug 出口脱敏 (§2.5 K-R4): id→sha8。
///
/// 投影来源: project_session (SessionUpdate → V3Session, 同源填明文列 + _len; 会话状态 4 列第四批进 L2)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3Session {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub username_sha: String,
    // 明文列 (第一类; 投影就绪后由 project_session 同源填)。
    pub account_id: String,
    pub username: String,
    pub unread_count: i64,
    pub last_msg_type: i64,
    pub last_msg_sub_type: i64,
    pub sort_timestamp: i64,
    // 会话列表展示列 (ADR-427 全程明文; summary=text_content / last_sender=display_name 类, 仿 person: _len + 明文)。
    pub summary_len: i64,
    pub summary: Option<String>,
    pub last_sender_len: i64,
    pub last_sender_display_name: Option<String>,
    // 会话状态列 (进 L2 不进 content_digest — 第四批; session_type/is_hidden/status 元数据, draft 同 summary)。
    pub session_type: i64,
    pub is_hidden: i64,
    pub status: i64,
    pub draft_len: i64,
    pub draft: Option<String>,
    // 第六批 session 补充列 (进 L2 不进 content_digest — ADR-451; last_msg_sender id 类明文 nullable, 5 元数据)。
    pub last_msg_sender: Option<String>,
    pub last_timestamp: i64,
    pub last_clear_unread_timestamp: i64,
    pub last_msg_locald_id: i64,
    pub last_msg_ext_type: i64,
    pub unread_first_msg_srv_id: i64,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; 明文 id 列 → sha8。
impl std::fmt::Debug for V3Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Session")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("username_sha", &self.username_sha)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("username_sha8", &crate::key_provider::sha8(self.username.as_bytes()))
            .field("unread_count", &self.unread_count)
            .field("last_msg_type", &self.last_msg_type)
            .field("last_msg_sub_type", &self.last_msg_sub_type)
            .field("sort_timestamp", &self.sort_timestamp)
            .field("summary_len", &self.summary_len)
            .field("summary_sha8", &self.summary.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())))
            .field("last_sender_len", &self.last_sender_len)
            .field(
                "last_sender_sha8",
                &self.last_sender_display_name.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())),
            )
            .field("session_type", &self.session_type)
            .field("is_hidden", &self.is_hidden)
            .field("status", &self.status)
            .field("draft_len", &self.draft_len)
            .field("draft_sha8", &self.draft.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())))
            .field("last_msg_sender_sha8", &self.last_msg_sender.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())))
            .field("last_timestamp", &self.last_timestamp)
            .field("last_clear_unread_timestamp", &self.last_clear_unread_timestamp)
            .field("last_msg_locald_id", &self.last_msg_locald_id)
            .field("last_msg_ext_type", &self.last_msg_ext_type)
            .field("unread_first_msg_srv_id", &self.unread_first_msg_srv_id)
            // 明文列 (account_id/username/summary/last_sender/draft/last_msg_sender) 有意省略 (敏感的上面有 sha8)。
            .finish_non_exhaustive()
    }
}

/// 建 session 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.8).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_session_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS session (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            username_sha      TEXT    NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; = ADR conv_id, 投影就绪后 project_session 同源填)。
            account_id        TEXT    NOT NULL,
            username          TEXT    NOT NULL,
            unread_count      INTEGER NOT NULL,
            last_msg_type     INTEGER NOT NULL,
            last_msg_sub_type INTEGER NOT NULL,
            sort_timestamp    INTEGER NOT NULL,
            summary_len       INTEGER NOT NULL,
            summary           TEXT,
            last_sender_len   INTEGER NOT NULL,
            last_sender_display_name TEXT,
            -- 会话状态列 (第四批; 进 L2 不进 content_digest — 当前态筛选, 折叠/免打扰/草稿)。
            session_type      INTEGER NOT NULL DEFAULT 0,
            is_hidden         INTEGER NOT NULL DEFAULT 0,
            status            INTEGER NOT NULL DEFAULT 0,
            draft_len         INTEGER NOT NULL DEFAULT 0,
            draft             TEXT,
            -- 第六批 session 补充列 (进 L2 不进 content_digest — ADR-451; last_msg_sender id 类明文, 5 元数据)。
            last_msg_sender              TEXT,
            last_timestamp               INTEGER NOT NULL DEFAULT 0,
            last_clear_unread_timestamp  INTEGER NOT NULL DEFAULT 0,
            last_msg_locald_id           INTEGER NOT NULL DEFAULT 0,
            last_msg_ext_type            INTEGER NOT NULL DEFAULT 0,
            unread_first_msg_srv_id      INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_session_username
            ON session (account_id_sha, username_sha);
        CREATE INDEX IF NOT EXISTS idx_session_sort
            ON session (account_id_sha, sort_timestamp DESC);",
    )?;
    // 旧 session 表 (无状态列) 补列 (同 person 的 ensure; ALTER ADD NOT NULL 必带 DEFAULT)。
    ensure_session_columns(conn)
}

/// 旧 session 表补字段扩充列 — 第四批 session_type/is_hidden/status/draft_len + 第六批 last_timestamp/
/// last_clear_unread_timestamp/last_msg_locald_id/last_msg_ext_type/unread_first_msg_srv_id (INTEGER NOT NULL
/// DEFAULT 0) + draft/last_msg_sender (TEXT nullable) + 明文列。旧 schema 迁移 (同 `ensure_person_extra_columns`)。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_session_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(session)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数
                                 // codex P1: 补齐**所有**缺列 (不只状态列) — 旧 9 列库缺明文(ADR-426)/展示列时也能迁到 19 列, 否则 insert 报 no column。
                                 // TEXT NOT NULL 明文列 ALTER 带 DEFAULT '' (SQLite 约束); INTEGER NOT NULL 带 DEFAULT 0; nullable TEXT 无需 DEFAULT。
    for col in ["account_id", "username"] {
        if !existing.contains(col) {
            conn.execute_batch(&format!(
                "ALTER TABLE session ADD COLUMN {col} TEXT NOT NULL DEFAULT ''"
            ))?;
        }
    }
    for col in [
        "summary_len",
        "last_sender_len",
        "session_type",
        "is_hidden",
        "status",
        "draft_len",
        "last_timestamp",
        "last_clear_unread_timestamp",
        "last_msg_locald_id",
        "last_msg_ext_type",
        "unread_first_msg_srv_id",
    ] {
        if !existing.contains(col) {
            conn.execute_batch(&format!(
                "ALTER TABLE session ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"
            ))?;
        }
    }
    for col in ["summary", "last_sender_display_name", "draft", "last_msg_sender"] {
        if !existing.contains(col) {
            conn.execute_batch(&format!("ALTER TABLE session ADD COLUMN {col} TEXT"))?;
        }
    }
    note_migration("session", count_columns(conn, "session")?.saturating_sub(before));
    Ok(())
}

/// 写一条 session (INSERT OR REPLACE upsert on PK — 重解码同源会话刷新行, e.g. unread/sort_timestamp 变).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_session(conn: &Connection, s: &V3Session) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO session
            (account_id_sha, source, source_native_id, username_sha,
             account_id, username,
             unread_count, last_msg_type, last_msg_sub_type, sort_timestamp,
             summary_len, summary, last_sender_len, last_sender_display_name,
             session_type, is_hidden, status, draft_len, draft,
             last_msg_sender, last_timestamp, last_clear_unread_timestamp,
             last_msg_locald_id, last_msg_ext_type, unread_first_msg_srv_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)",
        params![
            s.account_id_sha, s.source, s.source_native_id, s.username_sha,
            s.account_id, s.username,
            s.unread_count, s.last_msg_type, s.last_msg_sub_type, s.sort_timestamp,
            s.summary_len, s.summary, s.last_sender_len, s.last_sender_display_name,
            s.session_type, s.is_hidden, s.status, s.draft_len, s.draft,
            s.last_msg_sender, s.last_timestamp, s.last_clear_unread_timestamp,
            s.last_msg_locald_id, s.last_msg_ext_type, s.unread_first_msg_srv_id,
        ],
    )?;
    Ok(())
}

// ── L2 favorite 收藏表 (ADR-454; favorite.db fav_db_item 骨架) ──

/// 一条收藏 L2 行 (favorite.db `fav_db_item` 骨架列)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_favorite (FavoriteCreate → V3Favorite, 同源填明文列)。**持明文 (ADR-427) + 保留 _sha**:
/// `from_user` (来源 wxid/@chatroom, id 类) 存明文 + from_user_sha (JOIN 键); `real_chat_name` (群内发送者,
/// id 类) 明文 nullable, Debug sha8; `source_id` (来源消息 hash id, 非 wxid) 明文。content 本身不落 (只 content_len)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3Favorite {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub server_id: i64,
    pub local_id: i64,
    pub fav_type: i64,
    pub update_time: i64,
    pub from_user_sha: String,
    // 明文列 (ADR-426 §2.1 第一类; 与 _sha 同源, project_favorite 统一构造)。
    pub account_id: String,
    pub from_user: String,
    pub real_chat_name: Option<String>,
    pub source_id: Option<String>,
    pub content_len: i64,
    // 笔记正文 (ADR-471; 仅 type 18; 从 content <datadesc> 解; L2-only 明文; 非笔记 None)。
    pub note_text: Option<String>,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; 明文 id 列 (account_id/from_user/real_chat_name) → sha8。
impl std::fmt::Debug for V3Favorite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Favorite")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("server_id", &self.server_id)
            .field("local_id", &self.local_id)
            .field("fav_type", &self.fav_type)
            .field("update_time", &self.update_time)
            .field("from_user_sha", &self.from_user_sha)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("from_user_sha8", &crate::key_provider::sha8(self.from_user.as_bytes()))
            .field("real_chat_name_sha8", &self.real_chat_name.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())))
            .field("source_id", &self.source_id)
            .field("content_len", &self.content_len)
            .field("note_text_len", &self.note_text.as_deref().map(|s| s.chars().count()))
            // 明文列 (account_id/from_user/real_chat_name/note_text) 有意省略 (上面有 sha8/len)。
            .finish_non_exhaustive()
    }
}

/// 建 favorite 表 + 3 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.10 / ADR-454).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_favorite_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS favorite (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            server_id         INTEGER NOT NULL,
            local_id          INTEGER NOT NULL,
            fav_type          INTEGER NOT NULL,
            update_time       INTEGER NOT NULL,
            from_user_sha     TEXT    NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; 投影就绪后 project_favorite 同源填)。
            account_id        TEXT    NOT NULL,
            from_user         TEXT    NOT NULL,
            real_chat_name    TEXT,
            source_id         TEXT,
            content_len       INTEGER NOT NULL,
            note_text         TEXT,                 -- ADR-471: 笔记正文 (仅 type 18; content <datadesc> 解; L2-only)
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_favorite_type
            ON favorite (account_id_sha, fav_type);
        CREATE INDEX IF NOT EXISTS idx_favorite_update_time
            ON favorite (account_id_sha, update_time DESC);
        CREATE INDEX IF NOT EXISTS idx_favorite_from_user
            ON favorite (account_id_sha, from_user_sha);",
    )?;
    ensure_favorite_columns(conn)
}

/// 旧 favorite 表 (ADR-454, 无 note_text) 补 ADR-471 笔记正文列; 缺则 ALTER ADD; 幂等。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_favorite_columns(conn: &Connection) -> rusqlite::Result<()> {
    let has_note: bool = conn
        .prepare("PRAGMA table_info(favorite)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<String>>>()?
        .iter()
        .any(|c| c == "note_text");
    if !has_note {
        conn.execute_batch("ALTER TABLE favorite ADD COLUMN note_text TEXT")?;
    }
    note_migration("favorite", usize::from(!has_note)); // R11: 真加了 note_text 才记
    Ok(())
}

/// 写一条 favorite (INSERT OR REPLACE upsert on PK — 重解码同源收藏刷新行, e.g. 重打标签 update_time 变).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_favorite(conn: &Connection, fav: &V3Favorite) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO favorite
            (account_id_sha, source, source_native_id, server_id, local_id, fav_type, update_time,
             from_user_sha, account_id, from_user, real_chat_name, source_id, content_len, note_text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            fav.account_id_sha,
            fav.source,
            fav.source_native_id,
            fav.server_id,
            fav.local_id,
            fav.fav_type,
            fav.update_time,
            fav.from_user_sha,
            fav.account_id,
            fav.from_user,
            fav.real_chat_name,
            fav.source_id,
            fav.content_len,
            fav.note_text,
        ],
    )?;
    Ok(())
}

// ── L2 favorite_media 收藏媒体引用表 (ADR-472; 笔记图片/文件 md5 元数据, 派生自 favorite content) ──

/// 一条收藏媒体引用 L2 行 (笔记 content 里带 fullmd5 的一个 dataitem)。PK = (account_id_sha, source,
/// source_native_id, seq) = **favorite PK + 媒体序号** (一笔记多媒体 → 多行, 同 message_mention)。
/// **派生自 favorite content** → L2-only 不进 digest/payload。`media_md5` = 内容 md5 (= 本地缓存文件解密后
/// md5, app 据此定位本地文件解密); md5/尺寸/类型非 PII → Debug 只遮 account_id。
#[derive(Clone, PartialEq, Eq)]
pub struct V3FavoriteMedia {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub seq: i64,
    pub fav_server_id: i64,
    pub account_id: String,
    pub data_type: i64,
    pub media_md5: String,
    pub media_size: i64,
    pub data_fmt: Option<String>,
}

// K-R4: account_id → sha8; md5/尺寸/类型/格式非 PII 原样。
impl std::fmt::Debug for V3FavoriteMedia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3FavoriteMedia")
            .field("account_id_sha", &self.account_id_sha)
            .field("source_native_id", &self.source_native_id)
            .field("seq", &self.seq)
            .field("fav_server_id", &self.fav_server_id)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("data_type", &self.data_type)
            .field("media_md5", &self.media_md5)
            .field("media_size", &self.media_size)
            .field("data_fmt", &self.data_fmt)
            // 明文 account_id + source/source(favorite.db) 有意省略。
            .finish_non_exhaustive()
    }
}

/// 建 favorite_media 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.11b / ADR-472).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_favorite_media_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS favorite_media (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,     -- 所属 favorite 的 PK (一收藏多媒体 → 多行)
            seq               INTEGER NOT NULL,     -- 媒体在笔记内顺序 (0-based)
            fav_server_id     INTEGER NOT NULL,     -- 所属收藏 server_id (查询便利)
            account_id        TEXT    NOT NULL,
            data_type         INTEGER NOT NULL,     -- dataitem datatype (2图/6文件/8HTML)
            media_md5         TEXT    NOT NULL,     -- fullmd5 = 内容md5 = 本地缓存解密后md5 (app 定位键)
            media_size        INTEGER NOT NULL,     -- fullsize 字节数
            data_fmt          TEXT,                 -- datafmt (jpg/htm; nullable)
            PRIMARY KEY (account_id_sha, source, source_native_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_favorite_media_md5
            ON favorite_media (account_id_sha, media_md5);",
    )
}

/// 写一条 favorite_media (INSERT OR REPLACE upsert on PK).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_favorite_media(conn: &Connection, m: &V3FavoriteMedia) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO favorite_media
            (account_id_sha, source, source_native_id, seq, fav_server_id, account_id,
             data_type, media_md5, media_size, data_fmt)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.seq,
            m.fav_server_id,
            m.account_id,
            m.data_type,
            m.media_md5,
            m.media_size,
            m.data_fmt,
        ],
    )?;
    Ok(())
}

/// 按 favorite PK 删该收藏的**所有** media 行 (replace-projection: sink 重投前先删; 一收藏多行删整组; 无则 0 行).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_favorite_media(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM favorite_media WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 favorite_tag 收藏标签表 (ADR-454 批 B-2; fav_bind_tag ⋈ fav_tag M:N) ──

/// 一条"标签↔收藏"绑定 L2 行 (标签名去规范化)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_favorite_tag (FavoriteTagCreate → V3FavoriteTag)。查"某收藏的标签" = WHERE fav_server_id=X;
/// 查"某标签的收藏" = WHERE tag_server_id=Y。`tag_name` (用户标签, text_content 类) 明文 (ADR-427) + Debug sha8。
#[derive(Clone, PartialEq, Eq)]
pub struct V3FavoriteTag {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub tag_server_id: i64,
    pub tag_local_id: i64,
    pub seq: i64,
    pub fav_server_id: i64,
    pub fav_local_id: i64,
    pub op_code: i64,
    pub tag_name_len: i64,
    // 明文列 (ADR-426 §2.1)。
    pub account_id: String,
    pub tag_name: String,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — tag_name (用户标签) / account_id → sha8。
impl std::fmt::Debug for V3FavoriteTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3FavoriteTag")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("tag_server_id", &self.tag_server_id)
            .field("tag_local_id", &self.tag_local_id)
            .field("seq", &self.seq)
            .field("fav_server_id", &self.fav_server_id)
            .field("fav_local_id", &self.fav_local_id)
            .field("op_code", &self.op_code)
            .field("tag_name_len", &self.tag_name_len)
            .field(
                "account_id_sha8",
                &crate::key_provider::sha8(self.account_id.as_bytes()),
            )
            .field("tag_name_sha8", &crate::key_provider::sha8(self.tag_name.as_bytes()))
            .finish_non_exhaustive()
    }
}

/// 建 favorite_tag 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.11 / ADR-454 批 B-2).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_favorite_tag_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS favorite_tag (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            tag_server_id     INTEGER NOT NULL,
            tag_local_id      INTEGER NOT NULL,
            seq               INTEGER NOT NULL,
            fav_server_id     INTEGER NOT NULL,
            fav_local_id      INTEGER NOT NULL,
            op_code           INTEGER NOT NULL,
            tag_name_len      INTEGER NOT NULL,
            account_id        TEXT    NOT NULL,
            tag_name          TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_favorite_tag_fav
            ON favorite_tag (account_id_sha, fav_server_id);
        CREATE INDEX IF NOT EXISTS idx_favorite_tag_tag
            ON favorite_tag (account_id_sha, tag_server_id);",
    )
}

/// 写一条 favorite_tag 绑定 (INSERT OR REPLACE upsert on PK — 重解码同源绑定刷新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_favorite_tag(conn: &Connection, t: &V3FavoriteTag) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO favorite_tag
            (account_id_sha, source, source_native_id, tag_server_id, tag_local_id, seq,
             fav_server_id, fav_local_id, op_code, tag_name_len, account_id, tag_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            t.account_id_sha,
            t.source,
            t.source_native_id,
            t.tag_server_id,
            t.tag_local_id,
            t.seq,
            t.fav_server_id,
            t.fav_local_id,
            t.op_code,
            t.tag_name_len,
            t.account_id,
            t.tag_name,
        ],
    )?;
    Ok(())
}

// ── L2 transfer 转账表 (ADR-468; general.db transferTable) ──

/// 一条转账 L2 行 (general.db `transferTable`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_transfer (TransferCreate → V3Transfer, 同源填明文列)。**持明文 (ADR-427) + 保留 _sha**:
/// `session_name`/`pay_payer`/`pay_receiver` (id 类) 存明文 + _sha (JOIN/digest 键)。transfer_id/transcation_id
/// 是交易单号 (非 wxid) 明文。**金额不在本表** (在转账消息 XML feedesc, 系列后续件解; message_server_id 供 JOIN)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3Transfer {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub transfer_id: String,
    pub transcation_id: String,
    pub message_server_id: i64,
    pub second_message_server_id: i64,
    pub pay_sub_type: i64,
    pub session_name_sha: String,
    pub pay_payer_sha: String,
    pub pay_receiver_sha: String,
    pub begin_transfer_time: i64,
    pub last_modified_time: i64,
    pub invalid_time: i64,
    pub last_update_time: i64,
    pub delay_confirm_flag: i64,
    pub bubble_clicked_flag: i64,
    // 明文列 (ADR-426 §2.1 第一类; 与 _sha 同源, project_transfer 统一构造)。
    pub account_id: String,
    pub session_name: String,
    pub pay_payer: String,
    pub pay_receiver: String,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; account_id 明文 → sha8; session_name/payer/receiver
// 明文有意省略 (上面有各自 _sha 全值)。transfer_id/transcation_id 是交易单号非 wxid, 原样。
impl std::fmt::Debug for V3Transfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Transfer")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("transfer_id", &self.transfer_id)
            .field("transcation_id", &self.transcation_id)
            .field("message_server_id", &self.message_server_id)
            .field("second_message_server_id", &self.second_message_server_id)
            .field("pay_sub_type", &self.pay_sub_type)
            .field("session_name_sha", &self.session_name_sha)
            .field("pay_payer_sha", &self.pay_payer_sha)
            .field("pay_receiver_sha", &self.pay_receiver_sha)
            .field("begin_transfer_time", &self.begin_transfer_time)
            .field("last_modified_time", &self.last_modified_time)
            .field("invalid_time", &self.invalid_time)
            .field("last_update_time", &self.last_update_time)
            .field("delay_confirm_flag", &self.delay_confirm_flag)
            .field("bubble_clicked_flag", &self.bubble_clicked_flag)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            // 明文列 (session_name/pay_payer/pay_receiver) 有意省略 (上面有各自 _sha)。
            .finish_non_exhaustive()
    }
}

/// 建 transfer 表 + 3 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.12 / ADR-468).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_transfer_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS transfer (
            account_id_sha           TEXT    NOT NULL,
            source                   TEXT    NOT NULL,
            source_native_id         TEXT    NOT NULL,
            transfer_id              TEXT    NOT NULL,
            transcation_id           TEXT    NOT NULL,
            message_server_id        INTEGER NOT NULL,
            second_message_server_id INTEGER NOT NULL,
            pay_sub_type             INTEGER NOT NULL,
            session_name_sha         TEXT    NOT NULL,
            pay_payer_sha            TEXT    NOT NULL,
            pay_receiver_sha         TEXT    NOT NULL,
            begin_transfer_time      INTEGER NOT NULL,
            last_modified_time       INTEGER NOT NULL,
            invalid_time             INTEGER NOT NULL,
            last_update_time         INTEGER NOT NULL,
            delay_confirm_flag       INTEGER NOT NULL,
            bubble_clicked_flag      INTEGER NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; 投影就绪后 project_transfer 同源填)。
            account_id               TEXT    NOT NULL,
            session_name             TEXT    NOT NULL,
            pay_payer                TEXT    NOT NULL,
            pay_receiver             TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_transfer_payer
            ON transfer (account_id_sha, pay_payer_sha);
        CREATE INDEX IF NOT EXISTS idx_transfer_receiver
            ON transfer (account_id_sha, pay_receiver_sha);
        CREATE INDEX IF NOT EXISTS idx_transfer_begin_time
            ON transfer (account_id_sha, begin_transfer_time DESC);",
    )
}

/// 写一条 transfer (INSERT OR REPLACE upsert on PK — 重解码同源转账刷新行, e.g. 状态推进 pay_sub_type 变)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_transfer(conn: &Connection, t: &V3Transfer) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO transfer
            (account_id_sha, source, source_native_id, transfer_id, transcation_id, message_server_id,
             second_message_server_id, pay_sub_type, session_name_sha, pay_payer_sha, pay_receiver_sha,
             begin_transfer_time, last_modified_time, invalid_time, last_update_time, delay_confirm_flag,
             bubble_clicked_flag, account_id, session_name, pay_payer, pay_receiver)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            t.account_id_sha,
            t.source,
            t.source_native_id,
            t.transfer_id,
            t.transcation_id,
            t.message_server_id,
            t.second_message_server_id,
            t.pay_sub_type,
            t.session_name_sha,
            t.pay_payer_sha,
            t.pay_receiver_sha,
            t.begin_transfer_time,
            t.last_modified_time,
            t.invalid_time,
            t.last_update_time,
            t.delay_confirm_flag,
            t.bubble_clicked_flag,
            t.account_id,
            t.session_name,
            t.pay_payer,
            t.pay_receiver,
        ],
    )?;
    Ok(())
}

// ── L2 red_envelope 红包表 (ADR-468 件2; general.db redEnvelopeTable) ──

/// 一条红包 L2 行 (general.db `redEnvelopeTable`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_red_envelope (RedEnvelopeCreate → V3RedEnvelope)。**持明文 (ADR-427) + 保留 _sha**:
/// `session_name`/`sender_user_name` (id 类) 存明文 + _sha。send_id 红包单号 (非 wxid) 明文。`native_url` (wxpay
/// 领取 URL, query 嵌 wxid) 存明文供后置件取详情/金额 — Debug 只露长度。**金额不在本表**; **无时间列** (靠消息 JOIN)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3RedEnvelope {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub send_id: String,
    pub message_server_id: i64,
    pub sender_user_name_sha: String,
    pub session_name_sha: String,
    pub scene_id: i64,
    pub hb_status: i64,
    pub hb_type: i64,
    pub receive_status: i64,
    // 明文列 (ADR-426 §2.1 第一类; 与 _sha 同源, project_red_envelope 统一构造)。
    pub native_url: String,
    pub account_id: String,
    pub sender_user_name: String,
    pub session_name: String,
}

// K-R4 (ADR-426 §2.5): _sha 列原样; account_id 明文 → sha8; native_url 嵌 wxid → 只露长度; sender/session 明文省略。
impl std::fmt::Debug for V3RedEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3RedEnvelope")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("send_id", &self.send_id)
            .field("message_server_id", &self.message_server_id)
            .field("sender_user_name_sha", &self.sender_user_name_sha)
            .field("session_name_sha", &self.session_name_sha)
            .field("scene_id", &self.scene_id)
            .field("hb_status", &self.hb_status)
            .field("hb_type", &self.hb_type)
            .field("receive_status", &self.receive_status)
            .field("native_url_len", &self.native_url.len())
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            // 明文列 (sender_user_name/session_name) 有意省略 (上面有各自 _sha); native_url 只露长度 (嵌 wxid)。
            .finish_non_exhaustive()
    }
}

/// 建 red_envelope 表 + 3 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.13 / ADR-468 件2).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_red_envelope_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS red_envelope (
            account_id_sha       TEXT    NOT NULL,
            source               TEXT    NOT NULL,
            source_native_id     TEXT    NOT NULL,
            send_id              TEXT    NOT NULL,
            message_server_id    INTEGER NOT NULL,
            sender_user_name_sha TEXT    NOT NULL,
            session_name_sha     TEXT    NOT NULL,
            scene_id             INTEGER NOT NULL,
            hb_status            INTEGER NOT NULL,
            hb_type              INTEGER NOT NULL,
            receive_status       INTEGER NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; 投影就绪后 project_red_envelope 同源填)。
            native_url           TEXT    NOT NULL,
            account_id           TEXT    NOT NULL,
            sender_user_name     TEXT    NOT NULL,
            session_name         TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_red_envelope_sender
            ON red_envelope (account_id_sha, sender_user_name_sha);
        CREATE INDEX IF NOT EXISTS idx_red_envelope_session
            ON red_envelope (account_id_sha, session_name_sha);
        CREATE INDEX IF NOT EXISTS idx_red_envelope_type
            ON red_envelope (account_id_sha, hb_type);",
    )
}

/// 写一条 red_envelope (INSERT OR REPLACE upsert on PK — 重解码同源红包刷新行, e.g. 领取状态变)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_red_envelope(conn: &Connection, r: &V3RedEnvelope) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO red_envelope
            (account_id_sha, source, source_native_id, send_id, message_server_id, sender_user_name_sha,
             session_name_sha, scene_id, hb_status, hb_type, receive_status, native_url, account_id,
             sender_user_name, session_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            r.account_id_sha,
            r.source,
            r.source_native_id,
            r.send_id,
            r.message_server_id,
            r.sender_user_name_sha,
            r.session_name_sha,
            r.scene_id,
            r.hb_status,
            r.hb_type,
            r.receive_status,
            r.native_url,
            r.account_id,
            r.sender_user_name,
            r.session_name,
        ],
    )?;
    Ok(())
}

// ── L2 group_pay 群收款表 (ADR-468 件3; general.db groupPayTable) ──

/// 一条群收款 L2 行 (general.db `groupPayTable`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_group_pay (GroupPayCreate → V3GroupPay)。**持明文 (ADR-427) + 保留 _sha**: `session_name`
/// (id 类) 存明文 + _sha。bill_no 是账单号 (非 wxid) 明文。**金额/分摊不在本表** (在群收款消息 XML; message_local_id 供 JOIN)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3GroupPay {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub bill_no: String,
    pub message_local_id: i64,
    pub message_create_time: i64,
    pub session_name_sha: String,
    // 明文列 (ADR-426 §2.1 第一类; 与 _sha 同源, project_group_pay 统一构造)。
    pub account_id: String,
    pub session_name: String,
}

// K-R4: _sha 列原样; account_id/session_name 明文 → sha8。bill_no 是账单号非 wxid, 原样。
impl std::fmt::Debug for V3GroupPay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3GroupPay")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("bill_no", &self.bill_no)
            .field("message_local_id", &self.message_local_id)
            .field("message_create_time", &self.message_create_time)
            .field("session_name_sha", &self.session_name_sha)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            // 明文列 (session_name) 有意省略 (上面有 _sha)。
            .finish_non_exhaustive()
    }
}

/// 建 group_pay 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.14 / ADR-468 件3).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_group_pay_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS group_pay (
            account_id_sha      TEXT    NOT NULL,
            source              TEXT    NOT NULL,
            source_native_id    TEXT    NOT NULL,
            bill_no             TEXT    NOT NULL,
            message_local_id    INTEGER NOT NULL,
            message_create_time INTEGER NOT NULL,
            session_name_sha    TEXT    NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; 投影就绪后 project_group_pay 同源填)。
            account_id          TEXT    NOT NULL,
            session_name        TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_group_pay_session
            ON group_pay (account_id_sha, session_name_sha);
        CREATE INDEX IF NOT EXISTS idx_group_pay_time
            ON group_pay (account_id_sha, message_create_time DESC);",
    )
}

/// 写一条 group_pay (INSERT OR REPLACE upsert on PK)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_group_pay(conn: &Connection, g: &V3GroupPay) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO group_pay
            (account_id_sha, source, source_native_id, bill_no, message_local_id, message_create_time,
             session_name_sha, account_id, session_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            g.account_id_sha,
            g.source,
            g.source_native_id,
            g.bill_no,
            g.message_local_id,
            g.message_create_time,
            g.session_name_sha,
            g.account_id,
            g.session_name,
        ],
    )?;
    Ok(())
}

// ── L2 friend_verify 好友验证表 (ADR-469; general.db FMessageTable) ──

/// 一条好友验证/打招呼 L2 行 (general.db `FMessageTable`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_friend_verify (FriendVerifyCreate → V3FriendVerify)。**持明文 (ADR-427) + 保留 _sha**:
/// `user_name` (好友 wxid, id 类) 存明文 + _sha。`content` (打招呼语, text 类) 存明文 + content_len (字符数)。
/// **不存** encrypt_user_name / ticket / fmessage_detail_buf (低读值, drain 未取)。`scene` = 加好友来源。
#[derive(Clone, PartialEq, Eq)]
pub struct V3FriendVerify {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub user_name_sha: String,
    pub friend_type: i64,
    pub timestamp: i64,
    pub is_sender: i64,
    pub scene: i64,
    pub content_len: i64,
    // 明文列 (ADR-426 §2.1 第一类; user_name 与 _sha 同源; content 打招呼语)。
    pub account_id: String,
    pub user_name: String,
    pub content: String,
}

// K-R4: _sha 列原样; account_id/user_name 明文 → sha8; content (打招呼语) 只露长度 (content_len 已在)。
impl std::fmt::Debug for V3FriendVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3FriendVerify")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("user_name_sha", &self.user_name_sha)
            .field("friend_type", &self.friend_type)
            .field("timestamp", &self.timestamp)
            .field("is_sender", &self.is_sender)
            .field("scene", &self.scene)
            .field("content_len", &self.content_len)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            // 明文列 (user_name / content 打招呼语) 有意省略 (user_name 有 _sha; content 有 content_len)。
            .finish_non_exhaustive()
    }
}

/// 建 friend_verify 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.15 / ADR-469).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_friend_verify_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS friend_verify (
            account_id_sha   TEXT    NOT NULL,
            source           TEXT    NOT NULL,
            source_native_id TEXT    NOT NULL,
            user_name_sha    TEXT    NOT NULL,
            friend_type      INTEGER NOT NULL,
            timestamp        INTEGER NOT NULL,
            is_sender        INTEGER NOT NULL,
            scene            INTEGER NOT NULL,
            content_len      INTEGER NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; 投影就绪后 project_friend_verify 同源填)。
            account_id       TEXT    NOT NULL,
            user_name        TEXT    NOT NULL,
            content          TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_friend_verify_scene
            ON friend_verify (account_id_sha, scene);
        CREATE INDEX IF NOT EXISTS idx_friend_verify_time
            ON friend_verify (account_id_sha, timestamp DESC);",
    )
}

/// 写一条 friend_verify (INSERT OR REPLACE upsert on PK)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_friend_verify(conn: &Connection, v: &V3FriendVerify) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO friend_verify
            (account_id_sha, source, source_native_id, user_name_sha, friend_type, timestamp,
             is_sender, scene, content_len, account_id, user_name, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            v.account_id_sha,
            v.source,
            v.source_native_id,
            v.user_name_sha,
            v.friend_type,
            v.timestamp,
            v.is_sender,
            v.scene,
            v.content_len,
            v.account_id,
            v.user_name,
            v.content,
        ],
    )?;
    Ok(())
}

// ── L2 finder_visit 视频号主页访问表 (ADR-473; general.db wcfinderuserpage) ──

/// 一条视频号号主记录 L2 行 (general.db `wcfinderuserpage`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_finder_visit (FinderVisitCreate → V3FinderVisit)。**持明文 (ADR-427) + 保留 _sha**:
/// `owner_username` (视频号号主 wxid/微信号, id 类) 存明文 + _sha。`name` (视频号昵称, display 类) 存明文。
/// `profile_url` (主页 URL 含频道 id, 元数据 L2-only) 存明文, 不进 digest。`visit_time` = 访问时刻秒。
#[derive(Clone, PartialEq, Eq)]
pub struct V3FinderVisit {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub owner_username_sha: String,
    pub visit_time: i64,
    // 明文列 (ADR-426 §2.1 第一类; owner_username 与 _sha 同源; name 昵称; profile_url 主页)。
    pub account_id: String,
    pub owner_username: String,
    pub name: String,
    pub profile_url: String,
}

// K-R4: _sha 列原样; account_id/owner_username 明文 → sha8; name (昵称) → sha8; profile_url → 长度。
impl std::fmt::Debug for V3FinderVisit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        f.debug_struct("V3FinderVisit")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("owner_username_sha", &self.owner_username_sha)
            .field("visit_time", &self.visit_time)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("name_sha8", &sha8(self.name.as_bytes()))
            .field("profile_url_len", &self.profile_url.chars().count())
            // 明文列 (owner_username 有 _sha; name 有 name_sha8; profile_url 有 _len) 有意省略。
            .finish_non_exhaustive()
    }
}

/// 建 finder_visit 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.16 / ADR-473).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_finder_visit_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS finder_visit (
            account_id_sha      TEXT    NOT NULL,
            source              TEXT    NOT NULL,
            source_native_id    TEXT    NOT NULL,
            owner_username_sha  TEXT    NOT NULL,
            visit_time          INTEGER NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; project_finder_visit 同源填)。
            account_id          TEXT    NOT NULL,
            owner_username      TEXT    NOT NULL,
            name                TEXT    NOT NULL,
            profile_url         TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_finder_visit_time
            ON finder_visit (account_id_sha, visit_time DESC);",
    )
}

/// 写一条 finder_visit (INSERT OR REPLACE upsert on PK)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_finder_visit(conn: &Connection, v: &V3FinderVisit) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO finder_visit
            (account_id_sha, source, source_native_id, owner_username_sha, visit_time,
             account_id, owner_username, name, profile_url)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            v.account_id_sha,
            v.source,
            v.source_native_id,
            v.owner_username_sha,
            v.visit_time,
            v.account_id,
            v.owner_username,
            v.name,
            v.profile_url,
        ],
    )?;
    Ok(())
}

// ── L2 custom_emoticon 自定义表情表 (ADR-478; emoticon.db kNonStoreEmoticonTable) ──

/// 一条自定义表情 L2 行 (emoticon.db `kNonStoreEmoticonTable`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_custom_emoticon (CustomEmoticonCreate → V3CustomEmoticon)。**持明文 (ADR-427)**:
/// `md5` (表情内容哈希, 身份) / `caption` (中文描述) / `emoticon_type` 进 digest; `aes_key` (密钥, Debug sha8) /
/// cdn_url/thumb_url/tp_url/extern_url/extern_md5/encrypt_url/product_id 只进 L2。
#[derive(Clone, PartialEq, Eq)]
pub struct V3CustomEmoticon {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub md5: String,
    pub emoticon_type: i64,
    pub caption: String,
    // L2-only 明文列 (ADR-426 §2.1)。
    pub account_id: String,
    pub product_id: String,
    pub aes_key: String,
    pub cdn_url: String,
    pub thumb_url: String,
    pub tp_url: String,
    pub extern_url: String,
    pub extern_md5: String,
    pub encrypt_url: String,
}

// K-R4: aes_key (密钥) → sha8; urls → 长度; md5/caption/type/product_id/extern_md5 直露 (非 PII); account_id → sha8。
impl std::fmt::Debug for V3CustomEmoticon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let ul = |s: &str| s.chars().count();
        f.debug_struct("V3CustomEmoticon")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("md5", &self.md5)
            .field("emoticon_type", &self.emoticon_type)
            .field("caption", &self.caption)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("product_id", &self.product_id)
            .field("aes_key_sha8", &sha8(self.aes_key.as_bytes()))
            .field("cdn_url_len", &ul(&self.cdn_url))
            .field("thumb_url_len", &ul(&self.thumb_url))
            .field("extern_md5", &self.extern_md5)
            .field("encrypt_url_len", &ul(&self.encrypt_url))
            .finish_non_exhaustive()
    }
}

/// 建 custom_emoticon 表 + 1 索引 (IF NOT EXISTS 幂等, ADR-478).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_custom_emoticon_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS custom_emoticon (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            md5               TEXT    NOT NULL,     -- 表情内容 md5 (身份)
            emoticon_type     INTEGER NOT NULL,
            caption           TEXT    NOT NULL,     -- 中文描述
            account_id        TEXT    NOT NULL,
            product_id        TEXT    NOT NULL,
            aes_key           TEXT    NOT NULL,     -- 解密密钥
            cdn_url           TEXT    NOT NULL,
            thumb_url         TEXT    NOT NULL,
            tp_url            TEXT    NOT NULL,
            extern_url        TEXT    NOT NULL,
            extern_md5        TEXT    NOT NULL,     -- echotrace 查表键之一
            encrypt_url       TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_custom_emoticon_md5
            ON custom_emoticon (account_id_sha, md5);",
    )
}

/// 写一条 custom_emoticon (INSERT OR REPLACE upsert on PK)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_custom_emoticon(conn: &Connection, e: &V3CustomEmoticon) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO custom_emoticon
            (account_id_sha, source, source_native_id, md5, emoticon_type, caption, account_id,
             product_id, aes_key, cdn_url, thumb_url, tp_url, extern_url, extern_md5, encrypt_url)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            e.account_id_sha,
            e.source,
            e.source_native_id,
            e.md5,
            e.emoticon_type,
            e.caption,
            e.account_id,
            e.product_id,
            e.aes_key,
            e.cdn_url,
            e.thumb_url,
            e.tp_url,
            e.extern_url,
            e.extern_md5,
            e.encrypt_url,
        ],
    )?;
    Ok(())
}

// ── L2 bizchat_user 企微品牌号联系人表 (ADR-482; bizchat.db user_info) ──

/// 一条企微品牌号联系人 L2 行 (bizchat.db `user_info`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_bizchat_user (BizChatContactCreate → V3BizchatUser)。**持明文 (ADR-427)**:
/// `user_id` (企微 wxid, 身份, id 类) 明文 + `user_id_sha` (JOIN/digest 键); `brand_user_name` (`gh_` 品牌 id) /
/// `user_name` (显示名) 进 digest; `head_img_url`/`profile_url`/`bit_flag` 只进 L2。
#[derive(Clone, PartialEq, Eq)]
pub struct V3BizchatUser {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub user_id_sha: String,
    pub brand_user_name: String,
    pub user_name: String,
    // L2-only 明文/元数据列 (ADR-426 §2.1)。
    pub account_id: String,
    pub user_id: String,
    pub head_img_url: String,
    pub profile_url: String,
    pub bit_flag: i64,
}

// K-R4: user_id (企微 wxid) / user_name (显示名) → sha8; urls → 字符长度; brand_user_name (`gh_`) / bit_flag 直露;
// account_id → sha8。
impl std::fmt::Debug for V3BizchatUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let ul = |s: &str| s.chars().count();
        f.debug_struct("V3BizchatUser")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("user_id_sha", &self.user_id_sha)
            .field("brand_user_name", &self.brand_user_name)
            .field("user_name_sha8", &sha8(self.user_name.as_bytes()))
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("user_id_sha8", &sha8(self.user_id.as_bytes()))
            .field("head_img_url_len", &ul(&self.head_img_url))
            .field("profile_url_len", &ul(&self.profile_url))
            .field("bit_flag", &self.bit_flag)
            .finish_non_exhaustive()
    }
}

/// 建 bizchat_user 表 + 1 索引 (IF NOT EXISTS 幂等, ADR-482).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_bizchat_user_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS bizchat_user (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            user_id_sha       TEXT    NOT NULL,     -- 企微 wxid sha (JOIN/digest 键)
            brand_user_name   TEXT    NOT NULL,     -- gh_ 品牌 id
            user_name         TEXT    NOT NULL,     -- 显示名
            account_id        TEXT    NOT NULL,
            user_id           TEXT    NOT NULL,     -- 企微 wxid 明文 (身份)
            head_img_url      TEXT    NOT NULL,
            profile_url       TEXT    NOT NULL,
            bit_flag          INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_bizchat_user_brand
            ON bizchat_user (account_id_sha, brand_user_name);",
    )
}

/// 写一条 bizchat_user (INSERT OR REPLACE upsert on PK)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_bizchat_user(conn: &Connection, e: &V3BizchatUser) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO bizchat_user
            (account_id_sha, source, source_native_id, user_id_sha, brand_user_name, user_name,
             account_id, user_id, head_img_url, profile_url, bit_flag)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            e.account_id_sha,
            e.source,
            e.source_native_id,
            e.user_id_sha,
            e.brand_user_name,
            e.user_name,
            e.account_id,
            e.user_id,
            e.head_img_url,
            e.profile_url,
            e.bit_flag,
        ],
    )?;
    Ok(())
}

// ── L2 avatar_image 头像图表 (ADR-481; head_image.db head_image) ──

/// 一条头像图 L2 行 (head_image.db `head_image`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_avatar (AvatarImageCreate → V3AvatarImage)。`username` (联系人/群 id) 明文 (ADR-427)
/// 外加 `username_sha` (JOIN/digest 键); `md5` (头像内容哈希, 进 digest); `image_buffer` (原始图 bytes, BLOB,
/// 只进 L2), `update_time` (更新秒, 只进 L2)。
pub struct V3AvatarImage {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub username_sha: String,
    pub md5: String,
    // L2-only 明文/资源列 (ADR-426 §2.1)。
    pub account_id: String,
    pub username: String,
    /// 原始头像图 bytes (JPEG/PNG; BLOB)。
    pub image_buffer: Vec<u8>,
    pub update_time: i64,
}

// K-R4: username (联系人 wxid) → sha8; image_buffer → 字节长度; md5 直露 (内容哈希非 PII); account_id → sha8。
impl std::fmt::Debug for V3AvatarImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        f.debug_struct("V3AvatarImage")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("username_sha", &self.username_sha)
            .field("md5", &self.md5)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("username_sha8", &sha8(self.username.as_bytes()))
            .field("image_buffer_len", &self.image_buffer.len())
            .field("update_time", &self.update_time)
            .finish_non_exhaustive()
    }
}

/// 建 avatar_image 表 + 1 索引 (IF NOT EXISTS 幂等, ADR-481).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_avatar_image_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS avatar_image (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            username_sha      TEXT    NOT NULL,     -- 联系人 id sha (JOIN/digest 键)
            md5               TEXT    NOT NULL,     -- 头像内容 md5 (身份)
            account_id        TEXT    NOT NULL,
            username          TEXT    NOT NULL,     -- 明文联系人 id (L2)
            image_buffer      BLOB,                 -- 原始图 bytes (JPEG/PNG; L2)
            update_time       INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_avatar_image_username
            ON avatar_image (account_id_sha, username_sha);",
    )
}

/// 写一条 avatar_image (INSERT OR REPLACE upsert on PK — 同联系人换头像刷新)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_avatar_image(conn: &Connection, a: &V3AvatarImage) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO avatar_image
            (account_id_sha, source, source_native_id, username_sha, md5, account_id, username,
             image_buffer, update_time)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            a.account_id_sha,
            a.source,
            a.source_native_id,
            a.username_sha,
            a.md5,
            a.account_id,
            a.username,
            a.image_buffer,
            a.update_time,
        ],
    )?;
    Ok(())
}

// ── L2 moment_feed 朋友圈好友动态索引表 (ADR-474; sns.db SnsTopItem_1) ──

/// 一条朋友圈好友动态索引 L2 行 (sns.db `SnsTopItem_1`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_moment_feed (MomentFeedCreate → V3MomentFeed)。**持明文 (ADR-427) + 保留 _sha**:
/// `author` (发布者 wxid, id 类) 存明文 + _sha。`tid` (动态 id, 雪花可为负) / `create_time` (发布秒) 进 digest;
/// `last_read_time` (我读秒) / `is_read` (真库 99.5% 恒 1 噪音) 只进 L2。`summary` 全空**不落**。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MomentFeed {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub tid: i64,
    pub author_sha: String,
    pub create_time: i64,
    pub last_read_time: i64,
    pub is_read: i64,
    // 明文列 (ADR-426 §2.1 第一类; author 与 _sha 同源)。
    pub account_id: String,
    pub author: String,
}

// K-R4: _sha 列原样; account_id/author 明文 → sha8; tid/时刻/读状态数字明文 (非 PII)。
impl std::fmt::Debug for V3MomentFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        f.debug_struct("V3MomentFeed")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("tid", &self.tid)
            .field("author_sha", &self.author_sha)
            .field("create_time", &self.create_time)
            .field("last_read_time", &self.last_read_time)
            .field("is_read", &self.is_read)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            // 明文列 (author 有 _sha) 有意省略。
            .finish_non_exhaustive()
    }
}

/// 建 moment_feed 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.17 / ADR-474).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_moment_feed_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS moment_feed (
            account_id_sha   TEXT    NOT NULL,
            source           TEXT    NOT NULL,
            source_native_id TEXT    NOT NULL,
            tid              INTEGER NOT NULL,
            author_sha       TEXT    NOT NULL,
            create_time      INTEGER NOT NULL,
            last_read_time   INTEGER NOT NULL,
            is_read          INTEGER NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; project_moment_feed 同源填)。
            account_id       TEXT    NOT NULL,
            author           TEXT    NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_moment_feed_author_time
            ON moment_feed (account_id_sha, author_sha, create_time DESC);",
    )
}

/// 写一条 moment_feed (INSERT OR REPLACE upsert on PK; 源 tid 重复行去重到一行)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_moment_feed(conn: &Connection, v: &V3MomentFeed) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO moment_feed
            (account_id_sha, source, source_native_id, tid, author_sha, create_time,
             last_read_time, is_read, account_id, author)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            v.account_id_sha,
            v.source,
            v.source_native_id,
            v.tid,
            v.author_sha,
            v.create_time,
            v.last_read_time,
            v.is_read,
            v.account_id,
            v.author,
        ],
    )?;
    Ok(())
}

// ── L2 sns_notify 朋友圈互动通知表 (照 moment_feed ADR-474; sns.db SnsMessage_tmp3) ──

/// 一条朋友圈互动通知 L2 行 (sns.db `SnsMessage_tmp3`)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_sns_notify (SnsNotifyCreate → V3SnsNotify)。**持明文 (ADR-427) + 保留 _sha**:
/// `from_user` (互动者 wxid, id 类) / `to_user` (回复对象 wxid, nullable) 存明文 + _sha。
/// `comment_id` (通知 id) / `feed_id` (动态 tid) / `notify_type` / `create_time` 进 digest;
/// `from_nickname` / `to_nickname` / `content` (评论文本) / `is_unread` (真库本账号全 0) / `del_status` /
/// `is_relative_me` 只进 L2。
#[derive(Clone, PartialEq, Eq)]
pub struct V3SnsNotify {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub comment_id: i64,
    pub feed_id: i64,
    pub notify_type: i64,
    pub from_user_sha: String,
    pub create_time: i64,
    pub to_user_sha: Option<String>,
    pub is_unread: i64,
    pub del_status: i64,
    pub is_relative_me: i64,
    // 明文列 (ADR-426 §2.1 第一类; from_user/to_user 与 _sha 同源; 昵称/评论文本 display/text 类)。
    pub account_id: String,
    pub from_user: String,
    pub to_user: Option<String>,
    pub from_nickname: Option<String>,
    pub to_nickname: Option<String>,
    pub content: Option<String>,
}

// K-R4: _sha 列原样; account_id/from_user/to_user/昵称/content 明文 → sha8/opt_sha8; 数字明文 (非 PII)。
impl std::fmt::Debug for V3SnsNotify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("V3SnsNotify")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("comment_id", &self.comment_id)
            .field("feed_id", &self.feed_id)
            .field("notify_type", &self.notify_type)
            .field("from_user_sha", &self.from_user_sha)
            .field("create_time", &self.create_time)
            .field("to_user_sha", &self.to_user_sha)
            .field("is_unread", &self.is_unread)
            .field("del_status", &self.del_status)
            .field("is_relative_me", &self.is_relative_me)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            // 明文列 (from_user/to_user 有 _sha; 昵称/content 敏感) 走 sha8/省略。
            .field("from_nickname_sha8", &o(&self.from_nickname))
            .field("to_nickname_sha8", &o(&self.to_nickname))
            .field("content_sha8", &o(&self.content))
            .finish_non_exhaustive()
    }
}

/// 建 sns_notify 表 + 1 索引 (IF NOT EXISTS 幂等, 照 moment_feed L1-schema §3.1.17).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_sns_notify_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sns_notify (
            account_id_sha   TEXT    NOT NULL,
            source           TEXT    NOT NULL,
            source_native_id TEXT    NOT NULL,
            comment_id       INTEGER NOT NULL,
            feed_id          INTEGER NOT NULL,
            notify_type      INTEGER NOT NULL,
            from_user_sha    TEXT    NOT NULL,
            create_time      INTEGER NOT NULL,
            to_user_sha      TEXT,
            is_unread        INTEGER NOT NULL,
            del_status       INTEGER NOT NULL,
            is_relative_me   INTEGER NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; project_sns_notify 同源填)。
            account_id       TEXT    NOT NULL,
            from_user        TEXT    NOT NULL,
            to_user          TEXT,
            from_nickname    TEXT,
            to_nickname      TEXT,
            content          TEXT,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sns_notify_feed_time
            ON sns_notify (account_id_sha, feed_id, create_time DESC);",
    )
}

/// 写一条 sns_notify (INSERT OR REPLACE upsert on PK)。
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_sns_notify(conn: &Connection, v: &V3SnsNotify) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sns_notify
            (account_id_sha, source, source_native_id, comment_id, feed_id, notify_type,
             from_user_sha, create_time, to_user_sha, is_unread, del_status, is_relative_me,
             account_id, from_user, to_user, from_nickname, to_nickname, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![
            v.account_id_sha,
            v.source,
            v.source_native_id,
            v.comment_id,
            v.feed_id,
            v.notify_type,
            v.from_user_sha,
            v.create_time,
            v.to_user_sha,
            v.is_unread,
            v.del_status,
            v.is_relative_me,
            v.account_id,
            v.from_user,
            v.to_user,
            v.from_nickname,
            v.to_nickname,
            v.content,
        ],
    )?;
    Ok(())
}

// ── L2 moment 朋友圈动态表 (ADR-467 件1; sns.db SnsTimeLine 动态本体) ──

/// 一条朋友圈动态 L2 行 (sns.db `SnsTimeLine` 动态本体)。PK = (account_id_sha, source, source_native_id)。
///
/// 投影来源: project_moment (SnsCreate → V3Moment, 同源填明文列)。**持明文 (ADR-427) + 保留 _sha**:
/// `author` (发布者 wxid, id 类) 存明文 + author_sha (JOIN/digest 键); `content_desc` (正文, text 类) 明文 +
/// _len (同 message text_content); `author_nickname`/`source_user`/`location_label`/`title` 明文 nullable, Debug
/// sha8/len。**原始 content XML 不落** (只 content_len 尺寸)。经纬度原值不换算 (nullable REAL)。
#[derive(Clone, PartialEq)]
pub struct V3Moment {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub tid: i64,
    pub author_sha: String,
    pub create_time: i64,
    pub moment_type: i64,
    // 明文列 (ADR-426 §2.1 第一类; 与 _sha 同源, project_moment 统一构造)。
    pub account_id: String,
    pub author: String,
    pub author_nickname: Option<String>,
    pub content_desc: String,
    pub content_desc_len: i64,
    pub source_user: Option<String>,
    pub location_label: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub title: Option<String>,
    pub link_url: Option<String>,
    pub media_count: i64,
    pub like_count: i64,
    pub comment_count: i64,
    // 补列 (ADR-491; content XML 边角字段; 进 L2 不进 content_digest — 同批I L2-only)。
    pub source_nickname: Option<String>,
    pub is_bidirectional_fan: i64,
    pub is_rich_text: i64,
    pub public_user_name: Option<String>,
    pub app_name: Option<String>,
    pub content_len: i64,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; 明文 id/正文/昵称 → sha8; 位置名 → 长度。
impl std::fmt::Debug for V3Moment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let o8 = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("V3Moment")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("tid", &self.tid)
            .field("author_sha", &self.author_sha)
            .field("create_time", &self.create_time)
            .field("moment_type", &self.moment_type)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("author_sha8", &sha8(self.author.as_bytes()))
            .field("author_nickname_sha8", &o8(&self.author_nickname))
            .field("content_desc_sha8", &sha8(self.content_desc.as_bytes()))
            .field("content_desc_len", &self.content_desc_len)
            .field("source_user_sha8", &o8(&self.source_user))
            .field("location_label_len", &self.location_label.as_ref().map(|s| s.chars().count()))
            .field("latitude", &self.latitude)
            .field("longitude", &self.longitude)
            .field("title_sha8", &o8(&self.title))
            .field("link_url_sha8", &o8(&self.link_url))
            .field("media_count", &self.media_count)
            .field("like_count", &self.like_count)
            .field("comment_count", &self.comment_count)
            // 补列 (ADR-491): 昵称/gh_id/应用名 sha8; 关系/富文本标志直显。
            .field("source_nickname_sha8", &o8(&self.source_nickname))
            .field("is_bidirectional_fan", &self.is_bidirectional_fan)
            .field("is_rich_text", &self.is_rich_text)
            .field("public_user_name_sha8", &o8(&self.public_user_name))
            .field("app_name_sha8", &o8(&self.app_name))
            .field("content_len", &self.content_len)
            // 明文列 (account_id/author/content_desc/…) 有意省略 (上面有 sha8/len)。
            .finish_non_exhaustive()
    }
}

/// 建 moment 表 + 3 索引 (IF NOT EXISTS 幂等, ADR-467 件1).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_moment_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS moment (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            tid               INTEGER NOT NULL,
            author_sha        TEXT    NOT NULL,
            create_time       INTEGER NOT NULL,
            moment_type       INTEGER NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; project_moment 同源填)。
            account_id        TEXT    NOT NULL,
            author            TEXT    NOT NULL,
            author_nickname   TEXT,
            content_desc      TEXT    NOT NULL,
            content_desc_len  INTEGER NOT NULL,
            source_user       TEXT,
            location_label    TEXT,
            latitude          REAL,
            longitude         REAL,
            title             TEXT,
            link_url          TEXT,
            media_count       INTEGER NOT NULL,
            like_count        INTEGER NOT NULL,
            comment_count     INTEGER NOT NULL,
            -- 补列 (ADR-491; content XML 边角; 进 L2 不进 digest): 转发来源昵称/公众号gh_id/应用名(明文) + 互关/富文本标志。
            source_nickname      TEXT,
            is_bidirectional_fan INTEGER NOT NULL DEFAULT 0,
            is_rich_text         INTEGER NOT NULL DEFAULT 0,
            public_user_name     TEXT,
            app_name             TEXT,
            content_len       INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_moment_author
            ON moment (account_id_sha, author_sha);
        CREATE INDEX IF NOT EXISTS idx_moment_create_time
            ON moment (account_id_sha, create_time DESC);
        CREATE INDEX IF NOT EXISTS idx_moment_type
            ON moment (account_id_sha, moment_type);",
    )?;
    ensure_moment_columns(conn)
}

/// 旧 moment 表 (22 列) 补 ADR-491 5 列 (CREATE IF NOT EXISTS 不给旧表加列 → 旧 L1 上 insert 27 列会崩;
/// 通用模式 派生表 GROW 列必配 ensure_*_columns, 同 message_location 教训 6d1f6da)。幂等。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_moment_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(moment)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数
    for col in ["source_nickname", "public_user_name", "app_name"] {
        if !existing.contains(col) {
            conn.execute_batch(&format!("ALTER TABLE moment ADD COLUMN {col} TEXT"))?;
        }
    }
    for col in ["is_bidirectional_fan", "is_rich_text"] {
        if !existing.contains(col) {
            conn.execute_batch(&format!(
                "ALTER TABLE moment ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"
            ))?;
        }
    }
    note_migration("moment", count_columns(conn, "moment")?.saturating_sub(before));
    Ok(())
}

/// 写一条 moment (INSERT OR REPLACE upsert on PK — 重扫同源动态刷新行, e.g. 点赞数变刷 like_count).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_moment(conn: &Connection, m: &V3Moment) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO moment
            (account_id_sha, source, source_native_id, tid, author_sha, create_time, moment_type,
             account_id, author, author_nickname, content_desc, content_desc_len, source_user,
             location_label, latitude, longitude, title, link_url, media_count, like_count,
             comment_count, source_nickname, is_bidirectional_fan, is_rich_text, public_user_name,
             app_name, content_len)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
             ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.tid,
            m.author_sha,
            m.create_time,
            m.moment_type,
            m.account_id,
            m.author,
            m.author_nickname,
            m.content_desc,
            m.content_desc_len,
            m.source_user,
            m.location_label,
            m.latitude,
            m.longitude,
            m.title,
            m.link_url,
            m.media_count,
            m.like_count,
            m.comment_count,
            m.source_nickname,
            m.is_bidirectional_fan,
            m.is_rich_text,
            m.public_user_name,
            m.app_name,
            m.content_len,
        ],
    )?;
    Ok(())
}

// ── L2 moment_media 朋友圈媒体表 (ADR-467 件2a; 派生自 sns content, 一动态多媒体多行) ──

/// 一条朋友圈媒体 L2 行 (SnsTimeLine content 的一个 `<media>`)。PK = (account_id_sha, source, source_native_id,
/// media_seq) = **moment PK + 媒体序号** (一动态多图/视频 → 多行, 同 message_mention 一消息多@多行)。
/// **派生自 content XML** (content 不落但结构化媒体引用落) → L2-only 不进 digest/payload。
///
/// 投影来源: project_moment_media (SnsCreate → Vec<V3MomentMedia>, 无媒体空 Vec)。url/thumb/md5/key (媒体资源
/// 引用, url_key/enc_key 是解密密钥) L2 明文 (ADR-427) + Debug sha8。
#[derive(Clone, PartialEq)]
pub struct V3MomentMedia {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub media_seq: i64,
    pub media_type: i64,
    // 明文列 (ADR-426/427; 媒体资源引用 + 解密密钥, Debug sha8)。
    pub account_id: String,
    pub media_id: Option<String>,
    pub url: Option<String>,
    pub thumb_url: Option<String>,
    pub md5: Option<String>,
    pub video_md5: Option<String>,
    pub url_key: Option<String>,
    pub enc_idx: Option<String>,
    pub token: Option<String>,
    pub enc_key: Option<String>,
    pub width: i64,
    pub height: i64,
    pub total_size: i64,
    pub video_duration: Option<f64>,
}

// K-R4 (ADR-426 §2.5): url/thumb/md5/key/token/media_id/account_id → sha8; seq/type/宽高/尺寸/时长/enc_idx 明文。
impl std::fmt::Debug for V3MomentMedia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let o8 = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("V3MomentMedia")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("media_seq", &self.media_seq)
            .field("media_type", &self.media_type)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("media_id_sha8", &o8(&self.media_id))
            .field("url_sha8", &o8(&self.url))
            .field("thumb_url_sha8", &o8(&self.thumb_url))
            .field("md5_sha8", &o8(&self.md5))
            .field("video_md5_sha8", &o8(&self.video_md5))
            .field("url_key_sha8", &o8(&self.url_key))
            .field("enc_idx", &self.enc_idx)
            .field("token_sha8", &o8(&self.token))
            .field("enc_key_sha8", &o8(&self.enc_key))
            .field("width", &self.width)
            .field("height", &self.height)
            .field("total_size", &self.total_size)
            .field("video_duration", &self.video_duration)
            .finish_non_exhaustive()
    }
}

/// 建 moment_media 表 + 2 索引 (IF NOT EXISTS 幂等, ADR-467 件2a).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_moment_media_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS moment_media (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,     -- 所属 moment 的 PK (一动态多媒体 → 多行)
            media_seq         INTEGER NOT NULL,     -- mediaList 内序号 (0-based)
            media_type        INTEGER NOT NULL,     -- 2图/6视频/3封面
            account_id        TEXT    NOT NULL,
            media_id          TEXT,
            url               TEXT,
            thumb_url         TEXT,
            md5               TEXT,
            video_md5         TEXT,
            url_key           TEXT,                 -- SNS 媒体 CBC 解密 key
            enc_idx           TEXT,
            token             TEXT,                 -- CDN 下载 token (件3 下载用)
            enc_key           TEXT,                 -- 视频加密 key
            width             INTEGER NOT NULL,
            height            INTEGER NOT NULL,
            total_size        INTEGER NOT NULL,
            video_duration    REAL,
            PRIMARY KEY (account_id_sha, source, source_native_id, media_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_moment_media_moment
            ON moment_media (account_id_sha, source, source_native_id);
        CREATE INDEX IF NOT EXISTS idx_moment_media_md5
            ON moment_media (account_id_sha, md5);",
    )
}

/// 写一条 moment_media (INSERT OR REPLACE upsert on PK).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_moment_media(conn: &Connection, m: &V3MomentMedia) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO moment_media
            (account_id_sha, source, source_native_id, media_seq, media_type, account_id, media_id,
             url, thumb_url, md5, video_md5, url_key, enc_idx, token, enc_key, width, height,
             total_size, video_duration)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.media_seq,
            m.media_type,
            m.account_id,
            m.media_id,
            m.url,
            m.thumb_url,
            m.md5,
            m.video_md5,
            m.url_key,
            m.enc_idx,
            m.token,
            m.enc_key,
            m.width,
            m.height,
            m.total_size,
            m.video_duration,
        ],
    )?;
    Ok(())
}

/// 按 moment PK 删该动态的**所有** media 行 (replace-projection: sink 重投前先删, 保媒体变化不残留;
/// 一动态多行整组删; 不存在则 0 行, 无害).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_moment_media(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM moment_media WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 moment_interaction 朋友圈互动表 (ADR-467 件2b; 点赞+评论, 派生自 sns content, 一动态多互动多行) ──

/// 一条朋友圈互动 L2 行 (SnsTimeLine content 的一个点赞/评论)。PK = (account_id_sha, source, source_native_id,
/// interaction_seq) = **moment PK + 互动序号** (一动态多赞/评论 → 多行, 同 moment_media)。
/// **派生自 content XML 的 like_user_list/comment_user_list** → L2-only 不进 digest/payload。
///
/// 投影来源: project_moment_interaction (SnsCreate → Vec<V3MomentInteraction>, 无互动空 Vec)。from_user (id 类)
/// 明文 + from_user_sha (JOIN 键); from_nickname (display) / content (评论文本) / ref_username (id) 明文, Debug sha8。
#[derive(Clone, PartialEq, Eq)] // 全字段 String/i64/Option<String> 无浮点 → 可 Eq (同 V3Message/V3Person; 双审件2b P2)
pub struct V3MomentInteraction {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub interaction_seq: i64,
    pub kind: String,
    pub type_raw: i64,
    pub from_user_sha: String,
    // 明文列 (ADR-426/427)。
    pub account_id: String,
    pub from_user: Option<String>,
    pub from_nickname: Option<String>,
    pub content: Option<String>,
    pub comment_id: Option<String>,
    pub ref_username: Option<String>,
    pub ref_comment_id: Option<String>,
    pub create_time: i64,
}

// K-R4 (ADR-426 §2.5): from_user/from_nickname/content/ref_username/account_id → sha8; seq/kind/type/id/时间 明文。
impl std::fmt::Debug for V3MomentInteraction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let o8 = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("V3MomentInteraction")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("interaction_seq", &self.interaction_seq)
            .field("kind", &self.kind)
            .field("type_raw", &self.type_raw)
            .field("from_user_sha", &self.from_user_sha)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("from_user_sha8", &o8(&self.from_user))
            .field("from_nickname_sha8", &o8(&self.from_nickname))
            .field("content_sha8", &o8(&self.content))
            .field("comment_id", &self.comment_id)
            .field("ref_username_sha8", &o8(&self.ref_username))
            .field("ref_comment_id", &self.ref_comment_id)
            .field("create_time", &self.create_time)
            .finish_non_exhaustive()
    }
}

/// 建 moment_interaction 表 + 2 索引 (IF NOT EXISTS 幂等, ADR-467 件2b).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_moment_interaction_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS moment_interaction (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,     -- 所属 moment 的 PK (一动态多互动 → 多行)
            interaction_seq   INTEGER NOT NULL,     -- 跨 like/comment 连续序号 (0-based)
            kind              TEXT    NOT NULL,      -- 'like' / 'comment'
            type_raw          INTEGER NOT NULL,      -- user_comment <type> 原值 (1赞/2评论/4其它)
            from_user_sha     TEXT    NOT NULL,
            account_id        TEXT    NOT NULL,
            from_user         TEXT,                  -- 互动者 wxid 明文
            from_nickname     TEXT,
            content           TEXT,                  -- 评论文本 (赞 NULL)
            comment_id        TEXT,
            ref_username      TEXT,                  -- 回复对象 wxid (comment reply)
            ref_comment_id    TEXT,
            create_time       INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, source, source_native_id, interaction_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_moment_interaction_moment
            ON moment_interaction (account_id_sha, source, source_native_id);
        CREATE INDEX IF NOT EXISTS idx_moment_interaction_from
            ON moment_interaction (account_id_sha, from_user_sha);",
    )
}

/// 写一条 moment_interaction (INSERT OR REPLACE upsert on PK).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_moment_interaction(conn: &Connection, m: &V3MomentInteraction) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO moment_interaction
            (account_id_sha, source, source_native_id, interaction_seq, kind, type_raw, from_user_sha,
             account_id, from_user, from_nickname, content, comment_id, ref_username, ref_comment_id,
             create_time)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.interaction_seq,
            m.kind,
            m.type_raw,
            m.from_user_sha,
            m.account_id,
            m.from_user,
            m.from_nickname,
            m.content,
            m.comment_id,
            m.ref_username,
            m.ref_comment_id,
            m.create_time,
        ],
    )?;
    Ok(())
}

/// 按 moment PK 删该动态的**所有** interaction 行 (replace-projection: sink 重投前先删).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_moment_interactions(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM moment_interaction WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_app 消息卡片表 (ADR-455; 视频号/小程序/链接, 派生自 message text_content) ──

/// 一条消息卡片 L2 行 (appmsg XML 抽出的视频号/小程序/链接字段)。PK = (account_id_sha, source, source_native_id)
/// = 所属 message 的 PK (一条 appmsg 消息一行)。**派生自 text_content** (已在 message digest) → L2-only 不进 digest。
///
/// 投影来源: project_message_app (MessageCreate → Option<V3MessageApp>, 非 appmsg 返 None)。title/nickname/source
/// (内容/展示类) L2 明文 (ADR-427) + Debug sha8。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MessageApp {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub app_type: i64,
    pub media_count: i64,
    // 明文列 (ADR-426/427; 派生自 text_content, project_message_app 抽)。
    pub account_id: String,
    pub title: Option<String>,
    pub source_name: Option<String>,
    pub url: Option<String>,
    pub app_username: Option<String>,
    pub app_nickname: Option<String>,
    pub app_pagepath: Option<String>,
    // ── 类型专属细节 (ADR-462; 文件/转账/引用/合并转发; 非对应类型 0/None) ──
    pub file_size: i64,
    pub file_ext: Option<String>,
    pub file_md5: Option<String>,
    pub transfer_fee: Option<String>,
    pub transfer_direction: i64,
    pub transfer_txid: Option<String>,
    pub refer_svrid: Option<String>,
    pub refer_type: i64,
    pub refer_content: Option<String>,
    pub forward_item_count: i64,
    pub red_envelope_wish: Option<String>,
    pub red_envelope_count: i64,
    // ── 群收款金额 (ADR-487; type 2001 带 newaa; senderdes ¥金额 + newaa/billno 单号; 非群收款 None) ──
    pub group_pay_amount: Option<String>,
    pub group_pay_bill_no: Option<String>,
    // ── 音乐/礼物/直播 (ADR-462 扩; type 92/115/63; 非对应类型 0/None) ──
    pub music_desc: Option<String>,
    pub gift_wish: Option<String>,
    pub gift_sku: Option<String>,
    pub live_status: i64,
    pub live_desc: Option<String>,
    // 支付场景类别名 (ADR-495; type 2000/2001 scenetext, 系统低基数枚举; 与结构分类冗余, 图齐全而存)。
    pub pay_scene_text: Option<String>,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — title/source/url/username/nickname/pagepath + account_id → sha8。
impl std::fmt::Debug for V3MessageApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes()));
        f.debug_struct("V3MessageApp")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("app_type", &self.app_type)
            .field("media_count", &self.media_count)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("title_sha8", &o(&self.title))
            .field("source_name_sha8", &o(&self.source_name))
            .field("url_sha8", &o(&self.url))
            .field("app_username_sha8", &o(&self.app_username))
            .field("app_nickname_sha8", &o(&self.app_nickname))
            .field("app_pagepath_sha8", &o(&self.app_pagepath))
            // 类型专属脱敏: md5/交易号/引用原文 高熵→sha8; **金额低熵→只露有无 (codex P1: sha8 金额可枚举反推)**。
            .field("file_size", &self.file_size)
            .field("file_ext", &self.file_ext)
            .field("file_md5_sha8", &o(&self.file_md5))
            .field("transfer_fee", &self.transfer_fee.as_ref().map(|_| "[redacted]"))
            .field("transfer_direction", &self.transfer_direction)
            .field("transfer_txid_sha8", &o(&self.transfer_txid))
            .field("refer_svrid", &self.refer_svrid)
            .field("refer_type", &self.refer_type)
            .field("refer_content_sha8", &o(&self.refer_content))
            .field("forward_item_count", &self.forward_item_count)
            // 红包祝福语=内容/展示类→sha8; 个数明文。
            .field("red_envelope_wish_sha8", &o(&self.red_envelope_wish))
            .field("red_envelope_count", &self.red_envelope_count)
            // 群收款金额=财务低熵→只露有无; 单号=交易 id 高熵→sha8。
            .field("group_pay_amount", &self.group_pay_amount.as_ref().map(|_| "[redacted]"))
            .field("group_pay_bill_no_sha8", &o(&self.group_pay_bill_no))
            // 音乐描述/礼物祝福语·名/直播标题=内容展示类→sha8; 直播状态码明文。
            .field("music_desc_sha8", &o(&self.music_desc))
            .field("gift_wish_sha8", &o(&self.gift_wish))
            .field("gift_sku_sha8", &o(&self.gift_sku))
            .field("live_status", &self.live_status)
            .field("live_desc_sha8", &o(&self.live_desc))
            // 场景类别名=系统低基数枚举(微信红包/群收款), 非 PII → 直露。
            .field("pay_scene_text", &self.pay_scene_text)
            .finish_non_exhaustive()
    }
}

/// 建 message_app 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.12 / ADR-455/462).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_app_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_app (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            app_type          INTEGER NOT NULL,     -- appmsg 子类 (5链接/33小程序/51视频号 等)
            media_count       INTEGER NOT NULL,     -- 视频号媒体数 (非视频号 0)
            account_id        TEXT    NOT NULL,
            title             TEXT,                 -- 卡片标题 (明文)
            source_name       TEXT,                 -- 来源显示名 (小程序来源)
            url               TEXT,                 -- 主链接
            app_username      TEXT,                 -- 视频号 id (v2_) / 小程序 gh id
            app_nickname      TEXT,                 -- 视频号作者
            app_pagepath      TEXT,                 -- 小程序页面路径
            file_size         INTEGER NOT NULL DEFAULT 0,  -- 文件字节数 (type 6)
            file_ext          TEXT,                 -- 文件后缀 (type 6)
            file_md5          TEXT,                 -- 文件 md5 (type 6)
            transfer_fee      TEXT,                 -- 转账金额串 (type 2000, 如 ￥10.00)
            transfer_direction INTEGER NOT NULL DEFAULT 0, -- 转账方向 (type 2000)
            transfer_txid     TEXT,                 -- 转账交易号 (type 2000)
            refer_svrid       TEXT,                 -- 被引消息 id (type 57)
            refer_type        INTEGER NOT NULL DEFAULT 0,  -- 被引消息类型 (type 57)
            refer_content     TEXT,                 -- 被引消息原文 (type 57)
            forward_item_count INTEGER NOT NULL DEFAULT 0, -- 合并转发条数 (type 19)
            red_envelope_wish  TEXT,                 -- 红包祝福语/留言 (type 2001 sendertitle)
            red_envelope_count INTEGER NOT NULL DEFAULT 0, -- 红包个数 (type 2001 nativeurl total_num)
            group_pay_amount   TEXT,                 -- 群收款金额串 (type 2001 带 newaa, senderdes ¥金额; ADR-487)
            group_pay_bill_no  TEXT,                 -- 群收款单号 (type 2001 newaa/billno; JOIN groupPayTable)
            music_desc         TEXT,                 -- 音乐描述/歌手 (type 92 des)
            gift_wish          TEXT,                 -- 礼物祝福语 (type 115 wishmessage)
            gift_sku           TEXT,                 -- 礼物名 (type 115 skutitle)
            live_status        INTEGER NOT NULL DEFAULT 0, -- 视频号直播状态 (type 63 liveStatus)
            live_desc          TEXT,                 -- 视频号直播标题 (type 63 finderLive desc)
            pay_scene_text     TEXT,                 -- 支付场景类别名 (type 2000/2001 scenetext, 微信红包/群收款; ADR-495)
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_app_type
            ON message_app (account_id_sha, app_type);
        CREATE INDEX IF NOT EXISTS idx_message_app_username
            ON message_app (account_id_sha, app_username);",
    )?;
    ensure_message_app_columns(conn)
}

/// 旧 message_app 表 (批C 12 列) 补类型专属列 (ADR-462 文件/转账/引用/合并转发); 缺则 ALTER ADD; 幂等。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_message_app_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(message_app)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数
                                 // **按 CREATE schema 声明顺序追加** (codex P2: 分组加会让 migrated 库列序 ≠ fresh 库, SELECT */导出踩坑);
                                 // INTEGER NOT NULL 须带 DEFAULT (SQLite ALTER ADD 约束)。
    for (col, coltype) in [
        ("file_size", "INTEGER NOT NULL DEFAULT 0"),
        ("file_ext", "TEXT"),
        ("file_md5", "TEXT"),
        ("transfer_fee", "TEXT"),
        ("transfer_direction", "INTEGER NOT NULL DEFAULT 0"),
        ("transfer_txid", "TEXT"),
        ("refer_svrid", "TEXT"),
        ("refer_type", "INTEGER NOT NULL DEFAULT 0"),
        ("refer_content", "TEXT"),
        ("forward_item_count", "INTEGER NOT NULL DEFAULT 0"),
        ("red_envelope_wish", "TEXT"),
        ("red_envelope_count", "INTEGER NOT NULL DEFAULT 0"),
        ("group_pay_amount", "TEXT"),
        ("group_pay_bill_no", "TEXT"),
        ("music_desc", "TEXT"),
        ("gift_wish", "TEXT"),
        ("gift_sku", "TEXT"),
        ("live_status", "INTEGER NOT NULL DEFAULT 0"),
        ("live_desc", "TEXT"),
        ("pay_scene_text", "TEXT"),
    ] {
        if !existing.contains(col) {
            conn.execute_batch(&format!("ALTER TABLE message_app ADD COLUMN {col} {coltype}"))?;
        }
    }
    note_migration(
        "message_app",
        count_columns(conn, "message_app")?.saturating_sub(before),
    );
    Ok(())
}

/// 写一条 message_app 卡片 (INSERT OR REPLACE upsert on PK — 同消息重解码刷新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_app(conn: &Connection, a: &V3MessageApp) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_app
            (account_id_sha, source, source_native_id, app_type, media_count, account_id,
             title, source_name, url, app_username, app_nickname, app_pagepath,
             file_size, file_ext, file_md5, transfer_fee, transfer_direction, transfer_txid,
             refer_svrid, refer_type, refer_content, forward_item_count,
             red_envelope_wish, red_envelope_count,
             group_pay_amount, group_pay_bill_no,
             music_desc, gift_wish, gift_sku, live_status, live_desc, pay_scene_text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                 ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32)",
        params![
            a.account_id_sha,
            a.source,
            a.source_native_id,
            a.app_type,
            a.media_count,
            a.account_id,
            a.title,
            a.source_name,
            a.url,
            a.app_username,
            a.app_nickname,
            a.app_pagepath,
            a.file_size,
            a.file_ext,
            a.file_md5,
            a.transfer_fee,
            a.transfer_direction,
            a.transfer_txid,
            a.refer_svrid,
            a.refer_type,
            a.refer_content,
            a.forward_item_count,
            a.red_envelope_wish,
            a.red_envelope_count,
            a.group_pay_amount,
            a.group_pay_bill_no,
            a.music_desc,
            a.gift_wish,
            a.gift_sku,
            a.live_status,
            a.live_desc,
            a.pay_scene_text,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删 message_app 行 (replace-projection: sink 重投前先删, 保 message 从 appmsg→非 appmsg 时
/// 不残留旧派生行; codex 批C P1)。不存在则 0 行, 无害。
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_app(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_app WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_media 媒体元数据表 (ADR-456; 图/视频/表情/语音, 派生自 message text_content) ──

/// 一条媒体元数据 L2 行 (图/视频/表情 XML 抽出的 md5/aeskey/cdn/尺寸/时长)。PK = (account_id_sha, source,
/// source_native_id) = 所属 message 的 PK (一条媒体消息一行)。**派生自 text_content** (已在 message digest)
/// → L2-only 不进 digest。
///
/// 投影来源: project_message_media (MessageCreate → Option<V3MessageMedia>, 非媒体/无引用返 None)。
/// md5/aes_key/cdn_url/thumb_url/extra_id (媒体资源引用, aes_key 是解密密钥) → L2 明文 (ADR-427) + Debug sha8。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MessageMedia {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    /// 判别列 "image"/"video"/"emoji"/"voice" (MediaKind::as_str; voice 真库实证入表, 见 L1-schema §3.1.13)。
    pub media_kind: String,
    pub file_size: i64,
    pub play_length: i64,
    // 明文列 (ADR-426/427; 派生自 text_content, project_message_media 抽)。
    pub account_id: String,
    pub md5: Option<String>,
    pub aes_key: Option<String>,
    pub cdn_url: Option<String>,
    pub thumb_url: Option<String>,
    pub extra_id: Option<String>,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — md5/aes_key/cdn_url/thumb_url/extra_id + account_id → sha8。
impl std::fmt::Debug for V3MessageMedia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes()));
        f.debug_struct("V3MessageMedia")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("media_kind", &self.media_kind)
            .field("file_size", &self.file_size)
            .field("play_length", &self.play_length)
            .field(
                "account_id_sha8",
                &crate::key_provider::sha8(self.account_id.as_bytes()),
            )
            .field("md5_sha8", &o(&self.md5))
            .field("aes_key_sha8", &o(&self.aes_key))
            .field("cdn_url_sha8", &o(&self.cdn_url))
            .field("thumb_url_sha8", &o(&self.thumb_url))
            .field("extra_id_sha8", &o(&self.extra_id))
            .finish_non_exhaustive()
    }
}

/// 建 message_media 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.13 / ADR-456).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_media_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_media (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            media_kind        TEXT    NOT NULL,     -- image/video/emoji/voice (无 CHECK; voice 真库实证入表)
            file_size         INTEGER NOT NULL,     -- 文件字节数 (未知 0)
            play_length       INTEGER NOT NULL,     -- 视频时长秒 (非视频 0)
            account_id        TEXT    NOT NULL,
            md5               TEXT,                 -- 媒体内容 MD5 (hardlink 索引键)
            aes_key           TEXT,                 -- CDN 解密密钥
            cdn_url           TEXT,                 -- 主 CDN 下载地址
            thumb_url         TEXT,                 -- 缩略图 CDN 地址
            extra_id          TEXT,                 -- 图片 hdmd5 / 视频 newmd5 / 表情 productid
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_media_kind
            ON message_media (account_id_sha, media_kind);
        CREATE INDEX IF NOT EXISTS idx_message_media_md5
            ON message_media (account_id_sha, md5);",
    )
}

/// 写一条 message_media (INSERT OR REPLACE upsert on PK — 同消息重解码刷新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_media(conn: &Connection, m: &V3MessageMedia) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_media
            (account_id_sha, source, source_native_id, media_kind, file_size, play_length,
             account_id, md5, aes_key, cdn_url, thumb_url, extra_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.media_kind,
            m.file_size,
            m.play_length,
            m.account_id,
            m.md5,
            m.aes_key,
            m.cdn_url,
            m.thumb_url,
            m.extra_id,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删 message_media 行 (replace-projection: sink 重投前先删, 保 message 从 媒体→非媒体 时
/// 不残留旧派生行; 同 message_app 批C P1)。不存在则 0 行, 无害。
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_media(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_media WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_location 位置元数据表 (ADR-462; 位置消息 local_type=48, 派生自 message text_content) ──

/// 一条位置 L2 行 (位置消息 `<location>` 抽出的经纬度/地点)。PK = message PK (一条位置消息一行)。
/// **派生自 text_content** (已在 message digest) → L2-only 不进 digest。
///
/// 投影来源: project_message_location (MessageCreate → Option<V3MessageLocation>, 非位置返 None)。
/// K-R4: lat/lng/poiname/label/poiid 精确定位 → 明文落库 (ADR-427) + Debug 脱敏 (坐标粗化 + 串 sha8)。
#[derive(Clone, PartialEq)]
pub struct V3MessageLocation {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    /// 地图缩放级别 (未知 0)。
    pub scale: i64,
    // 明文列 (ADR-426/427; 派生自 text_content, project_message_location 抽)。
    pub account_id: String,
    /// 纬度 (北纬正)。
    pub latitude: f64,
    /// 经度 (东经正)。
    pub longitude: f64,
    pub label: Option<String>,
    pub poiname: Option<String>,
    pub poiid: Option<String>,
    /// 地图类型 (未知 0; 三档小补丁 ADR-479)。
    pub maptype: i64,
    /// 行政区划码 (6 位; nullable)。
    pub adcode: Option<String>,
    /// 城市名 (nullable)。
    pub cityname: Option<String>,
}

// K-R4: 位置敏感 → Debug 脱敏 (poiname/label/poiid + account_id → sha8; lat/lng 只留两位小数粗化)。
impl std::fmt::Debug for V3MessageLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes()));
        f.debug_struct("V3MessageLocation")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("scale", &self.scale)
            .field(
                "account_id_sha8",
                &crate::key_provider::sha8(self.account_id.as_bytes()),
            )
            .field("lat~", &format!("{:.2}", self.latitude))
            .field("lng~", &format!("{:.2}", self.longitude))
            .field("label_sha8", &o(&self.label))
            .field("poiname_sha8", &o(&self.poiname))
            .field("poiid_sha8", &o(&self.poiid))
            .field("maptype", &self.maptype)
            .field("adcode", &self.adcode)
            .field("cityname", &self.cityname)
            .finish_non_exhaustive()
    }
}

/// 建 message_location 表 + 1 索引 (IF NOT EXISTS 幂等, ADR-462).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_location_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_location (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            scale             INTEGER NOT NULL,     -- 地图缩放级别
            account_id        TEXT    NOT NULL,
            latitude          REAL    NOT NULL,     -- 纬度 (北纬正)
            longitude         REAL    NOT NULL,     -- 经度 (东经正)
            label             TEXT,                 -- 地址串
            poiname           TEXT,                 -- 地点名
            poiid             TEXT,                 -- 腾讯地图 POI id
            maptype           INTEGER NOT NULL DEFAULT 0, -- 地图类型 (ADR-479)
            adcode            TEXT,                 -- 行政区划码
            cityname          TEXT,                 -- 城市名
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_location_acct
            ON message_location (account_id_sha);",
    )?;
    ensure_message_location_columns(conn)
}

/// 旧 10 列 message_location (ADR-462) → 补 maptype/adcode/cityname 3 列 = 13 (ADR-479 迁移, 幂等).
/// `CREATE TABLE IF NOT EXISTS` 对已存在旧表是空操作, 不会补列 → 旧 L1 须 ALTER 追加, 否则 insert 13 列失败。
/// 按 CREATE schema 声明顺序追加 (同 `ensure_message_app_columns`: 保 migrated 库列序 == fresh 库)。
fn ensure_message_location_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(message_location)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数
                                 // INTEGER NOT NULL 须带 DEFAULT (SQLite ALTER ADD 约束)。
    for (col, coltype) in [
        ("maptype", "INTEGER NOT NULL DEFAULT 0"),
        ("adcode", "TEXT"),
        ("cityname", "TEXT"),
    ] {
        if !existing.contains(col) {
            conn.execute_batch(&format!("ALTER TABLE message_location ADD COLUMN {col} {coltype}"))?;
        }
    }
    note_migration(
        "message_location",
        count_columns(conn, "message_location")?.saturating_sub(before),
    );
    Ok(())
}

/// 写一条 message_location (INSERT OR REPLACE upsert on PK — 同消息重解码刷新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_location(conn: &Connection, m: &V3MessageLocation) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_location
            (account_id_sha, source, source_native_id, scale, account_id, latitude, longitude,
             label, poiname, poiid, maptype, adcode, cityname)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.scale,
            m.account_id,
            m.latitude,
            m.longitude,
            m.label,
            m.poiname,
            m.poiid,
            m.maptype,
            m.adcode,
            m.cityname,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删 message_location 行 (replace-projection: sink 重投前先删, 保 message 从 位置→非位置
/// 时不残留旧派生行; 同 message_media)。不存在则 0 行, 无害。
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_location(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_location WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_call 通话记录表 (ADR-475; type50 通话消息 <voipmsg> 派生, 照 WeChatMsg parser_voip) ──

/// 一条通话 L2 行 (通话消息 `<voipmsg>` 抽出的类型/时长/结果)。PK = message PK (一条通话消息一行)。
/// **派生自 text_content** (已在 message digest) → L2-only 不进 digest。
///
/// 投影来源: project_message_call (MessageCreate → Option<V3MessageCall>, 非通话返 None)。
/// display_content 是系统生成的通话结果文本 ("通话时长 00:25" / "对方已取消", 非 PII) → 明文落库 + Debug 直露。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MessageCall {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    /// 邀请类型 (-1 气泡摘要 / 0 视频 / 1 语音)。
    pub invite_type: i64,
    /// 通话房间类型。
    pub room_type: i64,
    /// 通话状态码 (voip msg_type: 100 正常 / 101 已在其它设备接听)。
    pub call_state: i64,
    /// 时长秒 (气泡形式 0, 实际时长在 display_content 文本里)。
    pub duration: i64,
    // 明文列 (ADR-426/427; 派生自 text_content, project_message_call 抽)。
    pub account_id: String,
    /// 通话结果显示文本 (系统生成, 非 PII)。
    pub display_content: String,
}

// K-R4: 通话字段全系统生成 (状态码/时长/结果文本非 PII); account_id 明文 → sha8。
impl std::fmt::Debug for V3MessageCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3MessageCall")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("invite_type", &self.invite_type)
            .field("room_type", &self.room_type)
            .field("call_state", &self.call_state)
            .field("duration", &self.duration)
            .field(
                "account_id_sha8",
                &crate::key_provider::sha8(self.account_id.as_bytes()),
            )
            .field("display_content", &self.display_content)
            .finish()
    }
}

/// 建 message_call 表 + 1 索引 (IF NOT EXISTS 幂等, ADR-475).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_call_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_call (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            invite_type       INTEGER NOT NULL,     -- -1 气泡 / 0 视频 / 1 语音
            room_type         INTEGER NOT NULL,
            call_state        INTEGER NOT NULL,     -- voip msg_type 100/101
            duration          INTEGER NOT NULL,     -- 时长秒
            account_id        TEXT    NOT NULL,
            display_content   TEXT    NOT NULL,     -- 通话结果文本
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_call_acct
            ON message_call (account_id_sha);",
    )
}

/// 写一条 message_call (INSERT OR REPLACE upsert on PK — 同消息重解码刷新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_call(conn: &Connection, m: &V3MessageCall) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_call
            (account_id_sha, source, source_native_id, invite_type, room_type, call_state,
             duration, account_id, display_content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.invite_type,
            m.room_type,
            m.call_state,
            m.duration,
            m.account_id,
            m.display_content,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删 message_call 行 (replace-projection: sink 重投前先删, 保 message 从 通话→非通话 时不残留;
/// 同 message_location)。不存在则 0 行, 无害。
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_call(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_call WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_hongbao_claim 红包领取明细表 (ADR-504; sys_type=hongbao 领取通知派生; 竞品无一解此) ──

/// 一条红包领取 L2 行 ("谁领了红包": 领取人显示名 + 红包单号 + 方向)。PK = message PK (一条领取通知一行)。
/// **派生自 text_content** (已在 message digest) → L2-only 不进 digest/payload。**金额不含** (微信不写进消息)。
///
/// 投影来源: project_message_hongbao_claim (MessageCreate → Option, 非领取通知返 None)。
/// "我发的红包谁领了" = 查 is_own_envelope=1 → 按 send_id GROUP BY 聚领取人; send_id 关联 red_envelope.send_id。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MessageHongbaoClaim {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    /// 红包单号 (关联 red_envelope.send_id; 同群红包多领取人共享)。
    pub send_id: String,
    /// true = 我发的红包被领 / false = 我领别人的。
    pub is_own_envelope: bool,
    // 明文列 (ADR-426/427; 派生自 text_content)。
    pub account_id: String,
    /// 对方显示名 (领取人 或 发红包人)。
    pub peer_name: String,
}

// K-R4: send_id 红包单号 (非 wxid) 明文; account_id / peer_name (显示名 PII) → Debug 只露 sha8。
impl std::fmt::Debug for V3MessageHongbaoClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3MessageHongbaoClaim")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("send_id", &self.send_id)
            .field("is_own_envelope", &self.is_own_envelope)
            .field(
                "account_id_sha8",
                &crate::key_provider::sha8(self.account_id.as_bytes()),
            )
            .field("peer_name_sha8", &crate::key_provider::sha8(self.peer_name.as_bytes()))
            .finish()
    }
}

/// 建 message_hongbao_claim 表 + 1 索引 (按 send_id 聚领取人; IF NOT EXISTS 幂等, ADR-504)。
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_hongbao_claim_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_hongbao_claim (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            send_id           TEXT    NOT NULL,     -- 红包单号 (关联 red_envelope.send_id)
            is_own_envelope   INTEGER NOT NULL,     -- 1 我发的被领 / 0 我领别人的
            account_id        TEXT    NOT NULL,
            peer_name         TEXT    NOT NULL,     -- 领取人 或 发红包人 显示名
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_hongbao_claim_send
            ON message_hongbao_claim (account_id_sha, send_id);",
    )
}

/// 写一条 message_hongbao_claim (INSERT OR REPLACE upsert on PK — 同消息重解码刷新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_hongbao_claim(conn: &Connection, m: &V3MessageHongbaoClaim) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_hongbao_claim
            (account_id_sha, source, source_native_id, send_id, is_own_envelope, account_id, peer_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.send_id,
            m.is_own_envelope,
            m.account_id,
            m.peer_name,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删 message_hongbao_claim 行 (replace-projection: sink 重投前先删)。不存在 0 行, 无害。
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_hongbao_claim(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_hongbao_claim WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_card 名片表 (ADR-477; type42 名片消息 <msg> 属性派生, 照 WeChatMsg parser_business) ──

/// 一条名片 L2 行 (名片消息 `<msg>` 属性抽出的被推荐人信息)。PK = message PK (一条名片消息一行)。
/// **派生自 text_content** (已在 message digest) → L2-only 不进 digest。
///
/// 投影来源: project_message_card (MessageCreate → Option<V3MessageCard>, 非名片返 None)。
/// K-R4: card_username/nickname/alias/sign 是他人身份 → 明文落 (ADR-427) + Debug 脱敏 (sha8 + url 只露长度)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MessageCard {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    /// 被推荐人性别 (0 未知 / 1 男 / 2 女)。
    pub card_sex: i64,
    // 明文列 (ADR-426/427; 派生自 text_content)。
    pub account_id: String,
    /// 被推荐人身份 (username; v3_ 名片 token 或 wxid)。
    pub card_username: String,
    pub card_nickname: Option<String>,
    pub card_alias: Option<String>,
    pub card_province: Option<String>,
    pub card_city: Option<String>,
    pub card_sign: Option<String>,
    pub card_open_im_desc: Option<String>,
    pub big_head_url: Option<String>,
    pub small_head_url: Option<String>,
}

// K-R4: 名片是他人身份 → Debug 脱敏 (username/nickname/alias/sign sha8; head url 只露长度; province/city/sex 直露)。
impl std::fmt::Debug for V3MessageCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        let l = |v: &Option<String>| v.as_deref().map(|s| s.chars().count());
        f.debug_struct("V3MessageCard")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("card_sex", &self.card_sex)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("card_username_sha8", &sha8(self.card_username.as_bytes()))
            .field("card_nickname_sha8", &o(&self.card_nickname))
            .field("card_alias_sha8", &o(&self.card_alias))
            .field("card_province", &self.card_province)
            .field("card_city", &self.card_city)
            .field("card_sign_sha8", &o(&self.card_sign))
            .field("card_open_im_desc_sha8", &o(&self.card_open_im_desc))
            .field("big_head_url_len", &l(&self.big_head_url))
            .field("small_head_url_len", &l(&self.small_head_url))
            .finish()
    }
}

/// 建 message_card 表 + 1 索引 (IF NOT EXISTS 幂等, ADR-477).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_card_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_card (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,
            card_sex          INTEGER NOT NULL,
            account_id        TEXT    NOT NULL,
            card_username     TEXT    NOT NULL,     -- 被推荐人身份 (v3_ token 或 wxid)
            card_nickname     TEXT,
            card_alias        TEXT,                 -- 微信号
            card_province     TEXT,
            card_city         TEXT,
            card_sign         TEXT,
            card_open_im_desc TEXT,                 -- 企微公司名
            big_head_url      TEXT,
            small_head_url    TEXT,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_message_card_acct
            ON message_card (account_id_sha);",
    )
}

/// 写一条 message_card (INSERT OR REPLACE upsert on PK).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_card(conn: &Connection, m: &V3MessageCard) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_card
            (account_id_sha, source, source_native_id, card_sex, account_id, card_username,
             card_nickname, card_alias, card_province, card_city, card_sign, card_open_im_desc,
             big_head_url, small_head_url)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.card_sex,
            m.account_id,
            m.card_username,
            m.card_nickname,
            m.card_alias,
            m.card_province,
            m.card_city,
            m.card_sign,
            m.card_open_im_desc,
            m.big_head_url,
            m.small_head_url,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删 message_card 行 (replace-projection: sink 重投前先删; 不存在 0 行无害).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_card(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_card WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_mention @提及表 (ADR-457; 群消息 @谁, 派生自 message source 列) ──

/// 一条 @提及 L2 行 (群消息 atuserlist 里的一个被 @ 对象)。PK = (account_id_sha, source, source_native_id,
/// mentioned_wxid_sha) = **message PK + 被@wxid** (一消息多@ → 多行, 区别 message_app/media 一消息一行)。
/// **派生自 message source 列** → L2-only (source 非 message 身份字段, 不进 digest)。
///
/// 投影来源: project_message_mention (MessageCreate → Vec<V3MessageMention>, 无 @ 空 Vec)。
/// mentioned_wxid (id 类) → L2 明文 (ADR-427) + Debug sha8。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MessageMention {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub mentioned_wxid_sha: String,
    /// 是否 @所有人 (notify@all)。
    pub is_at_all: bool,
    // 明文列 (ADR-426/427)。
    pub account_id: String,
    pub mentioned_wxid: String,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — mentioned_wxid + account_id → sha8。
impl std::fmt::Debug for V3MessageMention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3MessageMention")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("mentioned_wxid_sha", &self.mentioned_wxid_sha)
            .field("is_at_all", &self.is_at_all)
            .field(
                "account_id_sha8",
                &crate::key_provider::sha8(self.account_id.as_bytes()),
            )
            .field(
                "mentioned_wxid_sha8",
                &crate::key_provider::sha8(self.mentioned_wxid.as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

/// 建 message_mention 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.14 / ADR-457).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_mention_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_mention (
            account_id_sha     TEXT    NOT NULL,
            source             TEXT    NOT NULL,
            source_native_id   TEXT    NOT NULL,     -- 所属 message 的 PK (一消息多@ → 多行)
            mentioned_wxid_sha TEXT    NOT NULL,     -- 被 @ 的 wxid sha (或 notify@all 的 sha)
            is_at_all          INTEGER NOT NULL,     -- 1 = @所有人 (notify@all)
            account_id         TEXT    NOT NULL,
            mentioned_wxid     TEXT    NOT NULL,     -- 明文 wxid (或 notify@all)
            PRIMARY KEY (account_id_sha, source, source_native_id, mentioned_wxid_sha)
        );
        CREATE INDEX IF NOT EXISTS idx_message_mention_wxid
            ON message_mention (account_id_sha, mentioned_wxid_sha);",
    )
}

/// 写一条 @提及 (INSERT OR REPLACE upsert on PK — 同消息同被@人幂等).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_mention(conn: &Connection, m: &V3MessageMention) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_mention
            (account_id_sha, source, source_native_id, mentioned_wxid_sha, is_at_all,
             account_id, mentioned_wxid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.mentioned_wxid_sha,
            m.is_at_all,
            m.account_id,
            m.mentioned_wxid,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删该消息的**所有** @提及行 (replace-projection: sink 重投前先删, 保 @名单变化不残留;
/// 一消息多行, 删整组; 不存在则 0 行, 无害).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_mentions(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_mention WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 chatroom_member_event 群成员进出事件表 (群成员系统消息 msg_type=10000, 派生自 message text_content) ──

/// 一条群成员进出事件 L2 行 (谁在哪个群何时入/退群)。一条系统消息可产出多行 (一次邀请多人)。
/// PK = (account_id_sha, source, source_native_id); **source_native_id = message anchor + `:` + seq**
/// (一消息多成员 → 逐行唯一序号, 保 PK 不塌陷; 区别 message_mention 用 mentioned_wxid_sha ——
/// 本表 remove 无 wxid, 靠 seq 保唯一)。`msg_native_id` 列 = 裸 message anchor, 供 replace-projection 删整组。
/// **派生自 message text_content** (系统消息文本, 已在 message digest) → chatroom_member_event 表
/// **L2-only 不进 digest**。
///
/// 投影来源: project_chatroom_member_events (MessageCreate → Vec, 非进出事件空 Vec)。
/// K-R4: member_wxid / inviter_wxid / conv_id (id 类) → 明文列 + `_sha` + Debug sha8;
/// member_nickname (display) → Debug 只露 sha8; event_kind / event_time 直露。
#[derive(Clone, PartialEq, Eq)]
pub struct V3ChatroomMemberEvent {
    pub account_id_sha: String,
    pub source: String,
    /// message anchor + `:` + seq (逐行唯一; 一消息多成员多行)。
    pub source_native_id: String,
    /// 裸 message anchor (供 replace-projection 按所属消息删整组)。
    pub msg_native_id: String,
    pub conv_id_sha: String,
    /// 进/出成员 wxid sha (纯文本无 wxid → None)。
    pub member_wxid_sha: Option<String>,
    /// 事件类别: "join" | "remove"。
    pub event_kind: String,
    /// 邀请人 wxid sha (仅入群结构化 XML; 否则 None)。
    pub inviter_wxid_sha: Option<String>,
    /// 事件时间 (= MessageCreate.create_time)。
    pub event_time: i64,
    // 明文列 (ADR-426/427)。
    pub account_id: String,
    pub conv_id: String,
    /// 明文成员 wxid (纯文本无 → None)。
    pub member_wxid: Option<String>,
    /// 明文成员昵称 (display; 纯文本/结构化一般都有)。
    pub member_nickname: Option<String>,
    /// 明文邀请人 wxid (仅入群结构化 XML; 否则 None)。
    pub inviter_wxid: Option<String>,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — conv_id/member_wxid/inviter_wxid/account_id → sha8;
// member_nickname (display) → sha8; event_kind/event_time 元数据直显。
impl std::fmt::Debug for V3ChatroomMemberEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("V3ChatroomMemberEvent")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("msg_native_id", &self.msg_native_id)
            .field("conv_id_sha", &self.conv_id_sha)
            .field("member_wxid_sha", &self.member_wxid_sha)
            .field("event_kind", &self.event_kind)
            .field("inviter_wxid_sha", &self.inviter_wxid_sha)
            .field("event_time", &self.event_time)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("conv_id_sha8", &sha8(self.conv_id.as_bytes()))
            .field("member_wxid_sha8", &o(&self.member_wxid))
            .field("member_nickname_sha8", &o(&self.member_nickname))
            .field("inviter_wxid_sha8", &o(&self.inviter_wxid))
            .finish()
    }
}

/// 建 chatroom_member_event 表 + 2 索引 (IF NOT EXISTS 幂等; 新建表全列一次 CREATE, 无 ensure 迁移).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_chatroom_member_event_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS chatroom_member_event (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,     -- message anchor + ':' + seq (一消息多成员 → 逐行唯一)
            msg_native_id     TEXT    NOT NULL,     -- 裸 message anchor (replace-projection 删整组用)
            conv_id_sha       TEXT    NOT NULL,     -- 群 id sha
            member_wxid_sha   TEXT,                 -- 进/出成员 wxid sha (纯文本无 → NULL)
            event_kind        TEXT    NOT NULL,     -- 'join' | 'remove'
            inviter_wxid_sha  TEXT,                 -- 邀请人 wxid sha (仅入群结构化 → 否则 NULL)
            event_time        INTEGER NOT NULL,     -- = message create_time
            account_id        TEXT    NOT NULL,
            conv_id           TEXT    NOT NULL,     -- 明文群 id
            member_wxid       TEXT,                 -- 明文成员 wxid (纯文本无 → NULL)
            member_nickname   TEXT,                 -- 明文成员昵称 (display)
            inviter_wxid      TEXT,                 -- 明文邀请人 wxid
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_chatroom_member_event_conv
            ON chatroom_member_event (account_id_sha, conv_id_sha);
        CREATE INDEX IF NOT EXISTS idx_chatroom_member_event_member
            ON chatroom_member_event (account_id_sha, member_wxid_sha);",
    )
}

/// 写一条群成员进出事件 (INSERT OR REPLACE upsert on PK).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_chatroom_member_event(conn: &Connection, e: &V3ChatroomMemberEvent) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO chatroom_member_event
            (account_id_sha, source, source_native_id, msg_native_id, conv_id_sha,
             member_wxid_sha, event_kind, inviter_wxid_sha, event_time,
             account_id, conv_id, member_wxid, member_nickname, inviter_wxid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            e.account_id_sha,
            e.source,
            e.source_native_id,
            e.msg_native_id,
            e.conv_id_sha,
            e.member_wxid_sha,
            e.event_kind,
            e.inviter_wxid_sha,
            e.event_time,
            e.account_id,
            e.conv_id,
            e.member_wxid,
            e.member_nickname,
            e.inviter_wxid,
        ],
    )?;
    Ok(())
}

/// 按所属 message anchor 删该消息的**所有**成员进出事件行 (replace-projection: sink 重投前先删整组;
/// 一消息多行, 删整组; 不存在则 0 行, 无害). 按 `msg_native_id` (裸 anchor) 删 (source_native_id 含 seq 不便前缀匹配).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_chatroom_member_events(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    msg_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM chatroom_member_event WHERE account_id_sha=?1 AND source=?2 AND msg_native_id=?3",
        params![account_id_sha, source, msg_native_id],
    )?;
    Ok(())
}

// ── L2 group_pay_member 群收款逐付款人表 (ADR-488; type2001 newaa payerlist, 派生自 message content) ──

/// 一条群收款付款人 L2 行 (`<newaa><payerlist>` 里的一个 `wxid,金额,状态`)。PK = message PK + 付款人 wxid
/// (一群收款消息多付款人 → 多行, 同 message_mention)。**已付人数 = COUNT(*) GROUP BY bill_no**。
/// **派生自 text_content** (已在 message digest) → L2-only 不进 digest/payload。
///
/// 投影来源: project_group_pay_members (MessageCreate → Vec, 非群收款空 Vec)。payer_wxid (id) → 明文 + Debug sha8。
#[derive(Clone, PartialEq, Eq)]
pub struct V3GroupPayMember {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub payer_wxid_sha: String,
    /// 群收款单号 (JOIN general.db groupPayTable.bill_no; 明文非 wxid)。
    pub bill_no: String,
    /// 该付款人金额 (分; AA 均摊每人同额)。
    pub amount: i64,
    /// 付款状态 (payerlist 末位; 真库样本恒 1 = 已付; 0 = 未付/边缘)。
    pub pay_status: i64,
    // 明文列 (ADR-426/427)。
    pub account_id: String,
    pub payer_wxid: String,
}

// K-R4 (ADR-426 §2.5): payer_wxid + account_id → sha8; bill_no 交易号 → sha8; 金额/状态元数据直显。
impl std::fmt::Debug for V3GroupPayMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3GroupPayMember")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("payer_wxid_sha", &self.payer_wxid_sha)
            .field("bill_no_sha8", &crate::key_provider::sha8(self.bill_no.as_bytes()))
            .field("amount", &self.amount)
            .field("pay_status", &self.pay_status)
            .field(
                "account_id_sha8",
                &crate::key_provider::sha8(self.account_id.as_bytes()),
            )
            .field(
                "payer_wxid_sha8",
                &crate::key_provider::sha8(self.payer_wxid.as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

/// 建 group_pay_member 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema / ADR-488).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_group_pay_member_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS group_pay_member (
            account_id_sha   TEXT    NOT NULL,
            source           TEXT    NOT NULL,
            source_native_id TEXT    NOT NULL,     -- 所属群收款 message 的 PK (一消息多付款人 → 多行)
            payer_wxid_sha   TEXT    NOT NULL,     -- 付款人 wxid sha
            bill_no          TEXT    NOT NULL,     -- 单号 (JOIN groupPayTable; 明文)
            amount           INTEGER NOT NULL,     -- 该付款人金额 (分)
            pay_status       INTEGER NOT NULL,     -- 付款状态 (1=已付)
            account_id       TEXT    NOT NULL,
            payer_wxid       TEXT    NOT NULL,     -- 明文 wxid
            PRIMARY KEY (account_id_sha, source, source_native_id, payer_wxid_sha)
        );
        CREATE INDEX IF NOT EXISTS idx_group_pay_member_bill
            ON group_pay_member (account_id_sha, bill_no);",
    )
}

/// 写一条群收款付款人 (INSERT OR REPLACE upsert on PK — 同消息同付款人幂等).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_group_pay_member(conn: &Connection, m: &V3GroupPayMember) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO group_pay_member
            (account_id_sha, source, source_native_id, payer_wxid_sha, bill_no, amount, pay_status,
             account_id, payer_wxid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.payer_wxid_sha,
            m.bill_no,
            m.amount,
            m.pay_status,
            m.account_id,
            m.payer_wxid,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删该群收款消息的**所有**付款人行 (replace-projection: 重投前先删, 保付款人变化不残留;
/// 一消息多行删整组; 不存在则 0 行, 无害).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_group_pay_members(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM group_pay_member WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 message_forward_item 合并转发逐条子项表 (ADR-476; type49 子类19, 派生自 message content) ──

/// 一条合并转发子项 L2 行 (`<datalist>` 里的一个 `<dataitem>`)。PK = message PK + seq (一转发多子项 → 多行)。
/// **派生自 text_content** (已在 message digest) → L2-only 不进 digest。
///
/// 投影来源: project_message_forward (MessageCreate → Vec<V3MessageForwardItem>, 非转发空 Vec)。
/// K-R4: source_name (原发送人) / data_desc (转发内容) / data_title / media_md5 敏感 → 明文落 (ADR-427) + Debug 脱敏。
#[derive(Clone, PartialEq, Eq)]
pub struct V3MessageForwardItem {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    /// datalist 内 0 基序号 (PK 组成)。
    pub seq: i64,
    /// 子项类型 (datatype: 1 文本 / 2 图片 / 19 套娃转发 / …)。
    pub data_type: String,
    pub data_size: i64,
    // 明文列 (ADR-426/427; 派生自 text_content)。
    pub account_id: String,
    pub source_name: Option<String>,
    pub source_time: Option<String>,
    pub data_title: Option<String>,
    pub data_desc: Option<String>,
    pub media_md5: Option<String>,
}

// K-R4: 转发子项含他人名/内容 → Debug 脱敏 (name/title/md5 sha8 + desc 只露长度)。
impl std::fmt::Debug for V3MessageForwardItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::key_provider::sha8;
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("V3MessageForwardItem")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("seq", &self.seq)
            .field("data_type", &self.data_type)
            .field("data_size", &self.data_size)
            .field("account_id_sha8", &sha8(self.account_id.as_bytes()))
            .field("source_name_sha8", &o(&self.source_name))
            .field("source_time", &self.source_time)
            .field("data_title_sha8", &o(&self.data_title))
            .field("data_desc_len", &self.data_desc.as_deref().map(|s| s.chars().count()))
            .field("media_md5_sha8", &o(&self.media_md5))
            .finish()
    }
}

/// 建 message_forward_item 表 + 1 索引 (IF NOT EXISTS 幂等, ADR-476).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_message_forward_item_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_forward_item (
            account_id_sha    TEXT    NOT NULL,
            source            TEXT    NOT NULL,
            source_native_id  TEXT    NOT NULL,     -- 所属 message 的 PK (一转发多子项 → 多行)
            seq               INTEGER NOT NULL,     -- datalist 内 0 基序号
            data_type         TEXT    NOT NULL,     -- datatype (1 文本 / 2 图片 / 19 套娃 / …)
            data_size         INTEGER NOT NULL,
            account_id        TEXT    NOT NULL,
            source_name       TEXT,                 -- 原发送人
            source_time       TEXT,                 -- 原发送时间串
            data_title        TEXT,                 -- 子项标题
            data_desc         TEXT,                 -- 子项内容
            media_md5         TEXT,                 -- 子媒体 fullmd5
            PRIMARY KEY (account_id_sha, source, source_native_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_message_forward_item_acct
            ON message_forward_item (account_id_sha, source, source_native_id);",
    )
}

/// 写一条合并转发子项 (INSERT OR REPLACE upsert on PK).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_message_forward_item(conn: &Connection, m: &V3MessageForwardItem) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_forward_item
            (account_id_sha, source, source_native_id, seq, data_type, data_size,
             account_id, source_name, source_time, data_title, data_desc, media_md5)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.seq,
            m.data_type,
            m.data_size,
            m.account_id,
            m.source_name,
            m.source_time,
            m.data_title,
            m.data_desc,
            m.media_md5,
        ],
    )?;
    Ok(())
}

/// 按 message PK 删该消息的**所有**转发子项行 (replace-projection: sink 重投前先删整组; 不存在 0 行无害).
///
/// # Errors
/// rusqlite 执行失败.
pub fn delete_message_forward_items(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM message_forward_item WHERE account_id_sha=?1 AND source=?2 AND source_native_id=?3",
        params![account_id_sha, source, source_native_id],
    )?;
    Ok(())
}

// ── L2 person_alias_by_account_min 别名表 (L1-schema §3.1.5) ──

/// 一条联系人简化别名行 (L1-schema §3.1.5 的 4 列). PK = (account_id_sha, username_sha).
///
/// **表结构特殊** (跟其它 L2 业务表【不同】): PK 是【2 元组】(account_id_sha, username_sha),
/// 【无】 source / source_native_id 列, 【无】 索引 (PK 即查询键). 用途: message → 发送者快速 JOIN
/// 拿 remark/nick_name 的 sha (不是 plaintext 关联; 明文关联由上层订阅 contact_update 事件维护).
///
/// **持明文 (第一类) + 保留 _sha (第二类)** — ADR-426 §2.1: `username` + `remark`/`nick_name` 存明文列
/// (与 person 表同数据, 本表是发送者 JOIN 辅助表 → 上层 JOIN 本表即得明文, 不必再回 person);
/// 对应 username_sha/remark_sha/nick_name_sha (JOIN 键) 保留; 明文与 _sha 同源 (project_person_alias)。
/// Debug 出口脱敏 (§2.5 K-R4): id→sha8, remark/nick_name 明文省略 (上面有 _sha 占位)。
#[derive(Clone, PartialEq, Eq)]
pub struct V3PersonAlias {
    pub account_id_sha: String,
    pub username_sha: String,
    pub remark_sha: Option<String>,
    pub nick_name_sha: Option<String>,
    // 明文列 (第一类; 与对应 _sha 同源, project_person_alias 统一构造)。nick_name 必填 → 恒 Some。
    pub account_id: String,
    pub username: String,
    pub remark: Option<String>,
    pub nick_name: Option<String>,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; 明文 id 列 → sha8; remark/nick_name 省略 (有 _sha 占位)。
impl std::fmt::Debug for V3PersonAlias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3PersonAlias")
            .field("account_id_sha", &self.account_id_sha)
            .field("username_sha", &self.username_sha)
            .field("remark_sha", &self.remark_sha)
            .field("nick_name_sha", &self.nick_name_sha)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("username_sha8", &crate::key_provider::sha8(self.username.as_bytes()))
            // 明文列 (account_id/username/remark/nick_name) 有意省略 (id 有 sha8, remark/nick_name 有 _sha)。
            .finish_non_exhaustive()
    }
}

/// 建 person_alias_by_account_min 表 (IF NOT EXISTS 幂等, L1-schema §3.1.5). 无索引 (PK 即查询键).
///
/// # Errors
/// rusqlite 建表失败.
pub fn init_person_alias_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS person_alias_by_account_min (
            account_id_sha TEXT NOT NULL,
            username_sha   TEXT NOT NULL,
            remark_sha     TEXT,
            nick_name_sha  TEXT,
            -- 明文列 (ADR-426 §2.1 第一类; 与对应 _sha 同源, project_person_alias 统一构造)。
            account_id     TEXT NOT NULL,
            username       TEXT NOT NULL,
            remark         TEXT,
            nick_name      TEXT,
            PRIMARY KEY (account_id_sha, username_sha)
        );",
    )
}

/// 写一条别名 (INSERT OR REPLACE upsert on PK — contact_update 刷新 remark/nick_name sha).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_person_alias(conn: &Connection, a: &V3PersonAlias) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO person_alias_by_account_min
            (account_id_sha, username_sha, remark_sha, nick_name_sha,
             account_id, username, remark, nick_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            a.account_id_sha,
            a.username_sha,
            a.remark_sha,
            a.nick_name_sha,
            a.account_id,
            a.username,
            a.remark,
            a.nick_name,
        ],
    )?;
    Ok(())
}

// ── L2 chatroom_member 群成员表 (L1-schema §3.1.7) ──

/// 一条群成员行 (L1-schema §3.1.7 的 9 列). PK = (account_id_sha, source, source_native_id).
/// `source_native_id` 是复合 id, e.g. "<chatroom>:member:<wxid>".
///
/// **不是多版本历史表** — 同 PK 保留【当前状态一行】, 完整事件历史在 raw_payload_archive 重放
/// (§6.8 契约3c). 入退群【不能用 INSERT OR REPLACE】 (REPLACE 丢 joined_at, 也产不出"0 条"),
/// 用 [`upsert_chatroom_member_add`] (member_add) + [`mark_chatroom_member_left`] (member_remove) 两原语.
///
/// **持明文 (第一类) + 保留 _sha/_len (第二类)** — ADR-426 §2.1: `chatroom_id`/`member_wxid` 裸 id +
/// `display_name` 正文存明文列; 对应 _sha (PK/JOIN 键) + display_name_len 保留; joined_at/left_at/is_in_group
/// 是 metadata。**member_wxid 明文是退群闭环关键** (§1.1: add 时存, remove 按 member_wxid_sha 回读明文)。
/// 明文与 _sha 同源 (project_chatroom_member_add)。Debug 出口脱敏 (§2.5 K-R4): id→sha8, 正文→len。
#[derive(Clone, PartialEq, Eq)]
pub struct V3ChatroomMember {
    pub account_id_sha: String,
    pub source: String,
    pub source_native_id: String,
    pub chatroom_id_sha: String,
    pub member_wxid_sha: String,
    // 明文列 (第一类; 与对应 _sha 同源, project_chatroom_member_add 统一构造)。
    pub account_id: String,
    pub chatroom_id: String,
    pub member_wxid: String,
    pub display_name: Option<String>,
    // _len/metadata 保留。
    pub display_name_len: i64,
    pub joined_at: Option<i64>,
    pub left_at: Option<i64>,
    pub is_in_group: bool,
    /// 成员角色 (第八批; "owner"/"admin"/"member"; L2-only 不进 digest)。owner=chat_room.owner; admin=field3 flags&2048。
    pub role: String,
    /// 邀请人 wxid (第九批; id 类明文 nullable; 谁拉此成员进群; L2-only; Debug sha8)。
    pub invited_by: Option<String>,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — _sha 列原样; 明文 id 列 → sha8; 正文列 → 只 len。
impl std::fmt::Debug for V3ChatroomMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3ChatroomMember")
            .field("account_id_sha", &self.account_id_sha)
            .field("source", &self.source)
            .field("source_native_id", &self.source_native_id)
            .field("chatroom_id_sha", &self.chatroom_id_sha)
            .field("member_wxid_sha", &self.member_wxid_sha)
            .field("account_id_sha8", &crate::key_provider::sha8(self.account_id.as_bytes()))
            .field("chatroom_id_sha8", &crate::key_provider::sha8(self.chatroom_id.as_bytes()))
            .field("member_wxid_sha8", &crate::key_provider::sha8(self.member_wxid.as_bytes()))
            .field("display_name_len", &self.display_name_len)
            .field("joined_at", &self.joined_at)
            .field("left_at", &self.left_at)
            .field("is_in_group", &self.is_in_group)
            .field("role", &self.role)
            .field("invited_by_sha8", &self.invited_by.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes())))
            // 明文列 (account_id/chatroom_id/member_wxid/display_name/invited_by) 有意省略 (invited_by 上面有 sha8)。
            .finish_non_exhaustive()
    }
}

/// 建 chatroom_member 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.7).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_chatroom_member_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS chatroom_member (
            account_id_sha   TEXT    NOT NULL,
            source           TEXT    NOT NULL,
            source_native_id TEXT    NOT NULL,
            chatroom_id_sha  TEXT    NOT NULL,
            member_wxid_sha  TEXT    NOT NULL,
            -- 明文列 (ADR-426 §2.1 第一类; member_wxid 明文供退群闭环回读, project_chatroom_member_add 同源)。
            account_id       TEXT    NOT NULL,
            chatroom_id      TEXT    NOT NULL,
            member_wxid      TEXT    NOT NULL,
            display_name     TEXT,
            display_name_len INTEGER NOT NULL,
            joined_at        INTEGER,
            left_at          INTEGER,
            is_in_group      INTEGER NOT NULL DEFAULT 1,
            -- 成员角色 (第八批; owner/admin/member; L2-only 不进 digest; owner=chat_room.owner, admin=成员 field3 flags&2048)。
            role             TEXT    NOT NULL DEFAULT 'member',
            -- 邀请人 wxid (第九批; id 类明文 nullable; 谁拉此成员进群; L2-only — ADR-452; 成员 ext_buffer field4)。
            invited_by       TEXT,
            PRIMARY KEY (account_id_sha, source, source_native_id)
        );
        CREATE INDEX IF NOT EXISTS idx_chatroom_member_chatroom
            ON chatroom_member (account_id_sha, chatroom_id_sha, is_in_group);
        CREATE INDEX IF NOT EXISTS idx_chatroom_member_wxid
            ON chatroom_member (account_id_sha, member_wxid_sha);",
    )?;
    // 旧 chatroom_member 表 (无 role) 补列 (同 person/session ensure; ALTER ADD NOT NULL 带 DEFAULT)。
    ensure_chatroom_member_columns(conn)
}

/// 旧 chatroom_member 表补第八批 role (TEXT NOT NULL DEFAULT 'member') + 第九批 invited_by (TEXT nullable)。
/// 旧 schema 迁移 (同 `ensure_person_extra_columns`)。
///
/// # Errors
/// rusqlite 执行失败.
fn ensure_chatroom_member_columns(conn: &Connection) -> rusqlite::Result<()> {
    let existing: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(chatroom_member)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    let before = existing.len(); // R11: 迁移前列数
    if !existing.contains("role") {
        conn.execute_batch("ALTER TABLE chatroom_member ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")?;
    }
    if !existing.contains("invited_by") {
        conn.execute_batch("ALTER TABLE chatroom_member ADD COLUMN invited_by TEXT")?;
    }
    note_migration(
        "chatroom_member",
        count_columns(conn, "chatroom_member")?.saturating_sub(before),
    );
    Ok(())
}

/// member_add: INSERT 新成员 / 同 PK 复活 (UPDATE is_in_group=1, left_at=NULL, joined_at 重置).
///
/// 调用方在 `m` 里给定 `is_in_group=true` / `left_at=None` / `joined_at=Some(now)`. 同 PK 冲突时
/// UPDATE 所有非 PK 列 (含 joined_at 重置为本次值 — §6.8 契约3c 再加群刷新加入时间).
///
/// # Errors
/// rusqlite 执行失败.
pub fn upsert_chatroom_member_add(conn: &Connection, m: &V3ChatroomMember) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO chatroom_member
            (account_id_sha, source, source_native_id, chatroom_id_sha, member_wxid_sha,
             account_id, chatroom_id, member_wxid, display_name,
             display_name_len, joined_at, left_at, is_in_group, role, invited_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
         ON CONFLICT(account_id_sha, source, source_native_id) DO UPDATE SET
            chatroom_id_sha  = excluded.chatroom_id_sha,
            member_wxid_sha  = excluded.member_wxid_sha,
            account_id       = excluded.account_id,
            chatroom_id      = excluded.chatroom_id,
            member_wxid      = excluded.member_wxid,
            display_name     = excluded.display_name,
            display_name_len = excluded.display_name_len,
            joined_at        = excluded.joined_at,
            left_at          = excluded.left_at,
            is_in_group      = excluded.is_in_group,
            role             = excluded.role,
            invited_by       = excluded.invited_by",
        params![
            m.account_id_sha,
            m.source,
            m.source_native_id,
            m.chatroom_id_sha,
            m.member_wxid_sha,
            m.account_id,
            m.chatroom_id,
            m.member_wxid,
            m.display_name,
            m.display_name_len,
            m.joined_at,
            m.left_at,
            m.is_in_group,
            m.role,
            m.invited_by,
        ],
    )?;
    Ok(())
}

/// member_remove: UPDATE is_in_group=0 + left_at WHERE PK. **保留 joined_at 不动**.
///
/// 返回受影响行数: `0` = PK 不在业务表 → 调用方【仅业务表跳过】 + 写一条 error system_event;
/// (archive 不依赖 PK 是否在业务表里, 仍必先写 — §6.8 契约3c / §2 红线). `1` = 正常退群标记.
///
/// # Errors
/// rusqlite 执行失败.
pub fn mark_chatroom_member_left(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
    left_at: i64,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE chatroom_member SET is_in_group = 0, left_at = ?4
         WHERE account_id_sha = ?1 AND source = ?2 AND source_native_id = ?3",
        params![account_id_sha, source, source_native_id, left_at],
    )
}

// ── L2 chatroom_member 退群 diff 回读 (ADR-426 §1.1 闭环) ──

/// 某群【当前在群】一个成员的回读视图 — `member_wxid` 明文是退群 diff 产 member_remove 事件的源
/// (退群成员已离开 ext_buffer, 只能从这里拿回明文; 这正是 ADR-426 给 chatroom_member 加明文列的目的)。
#[derive(Clone, PartialEq, Eq)]
pub struct ChatroomMemberRef {
    /// 成员 wxid 的 sha (diff 比对键之一 / member_anchor 输入)。
    pub member_wxid_sha: String,
    /// 成员 wxid 明文 (退群事件 member_wxid 回读源 — 第一类真实数据)。
    pub member_wxid: String,
    /// 该成员行的 source_native_id (= member_anchor; remove 事件复用以命中同 PK)。
    pub source_native_id: String,
}

// K-R4 (ADR-426 §2.5): 持明文但 Debug 出口脱敏 — member_wxid 明文 → sha8。
impl std::fmt::Debug for ChatroomMemberRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatroomMemberRef")
            .field("member_wxid_sha", &self.member_wxid_sha)
            .field("source_native_id", &self.source_native_id)
            .field("member_wxid_sha8", &crate::key_provider::sha8(self.member_wxid.as_bytes()))
            // member_wxid 明文有意省略 (上面有 sha8)。
            .finish_non_exhaustive()
    }
}

/// 查某群【当前在群】成员 (is_in_group=1) — 退群 diff 用: 上一轮在群集跟本轮 ext_buffer 成员比,
/// L2 有 / ext_buffer 无 的判退群 (member_wxid 明文回读填 member_remove 事件, 闭 §1.1 死结)。
/// 按 (account_id_sha, source, chatroom_id_sha) 过滤 — source 维封住单源不变量 (codex r1 P1)。
///
/// # Errors
/// rusqlite 查询失败.
pub fn query_chatroom_members_in_group(
    conn: &Connection,
    account_id_sha: &str,
    source: &str,
    chatroom_id_sha: &str,
) -> rusqlite::Result<Vec<ChatroomMemberRef>> {
    let mut stmt = conn.prepare(
        "SELECT member_wxid_sha, member_wxid, source_native_id FROM chatroom_member
         WHERE account_id_sha = ?1 AND source = ?2 AND chatroom_id_sha = ?3 AND is_in_group = 1",
    )?;
    let rows = stmt.query_map(params![account_id_sha, source, chatroom_id_sha], |r| {
        Ok(ChatroomMemberRef {
            member_wxid_sha: r.get(0)?,
            member_wxid: r.get(1)?,
            source_native_id: r.get(2)?,
        })
    })?;
    rows.collect()
}

// ── schema_meta 登记表 (L1-schema §3.1.1) ──

/// L1 schema 版本 (value 存字符串; v1 自身不算 migration)。**R14: 1→2**(消息锚 8hex→32hex 全扩 —— `source_native_id`
/// 语义变, 旧库 8hex 锚与新 32hex 混用会让 message/chatroom/session 等 PK 插重复行、media 连不上旧消息;
/// [`init_l1_schema`] 版本门禁拒旧库、要求删库从加密源全量重建)。
/// **R16-3: 2→3**(favorite_tag 锚 `FavoriteTag_<server>_<server>`→`FavoriteTag_<local>_<local>` —— 未同步 server_id=0
/// 会塌锚, 改 local id 根治; 同 R14 是 `source_native_id` 格式变 → 旧库新旧锚混用会插重复 favorite_tag 行 + archive
/// 重复身份 → 版本门禁拒旧库、要求重建)。
pub const SCHEMA_VERSION: &str = "3";
/// well-known key: L1 schema 版本号.
pub const META_KEY_VERSION: &str = "version";
/// well-known key: 库创建 unix 时间.
pub const META_KEY_CREATED_AT: &str = "created_at";
/// well-known key: 写库 app 版本 (e.g. "0.1.0-alpha").
pub const META_KEY_APP_VERSION: &str = "app_version";
/// well-known key: migration 历史 JSON 数组 (初始 "[]", v1→v2 起追加).
pub const META_KEY_MIGRATION_HISTORY: &str = "migration_history";
/// well-known key: 本文件归属 wxid sha (业务表写入校验 account_id_sha = 本行 value).
pub const META_KEY_ACCOUNT_ID_SHA: &str = "account_id_sha";

/// 建 schema_meta 表 (IF NOT EXISTS 幂等, L1-schema §3.1.1). 无索引 (PK key 即查询键).
///
/// **登记表性质**: 本表【无 account_id_sha 列】 — 自身存 `('account_id_sha', '<wxid_sha>')` 行锁文件归属.
///
/// # Errors
/// rusqlite 建表失败.
pub fn init_schema_meta_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (
            key        TEXT    NOT NULL,
            value      TEXT    NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (key)
        );",
    )
}

/// 写一条 meta (INSERT OR REPLACE upsert on key — 刷新 value + updated_at).
///
/// # Errors
/// rusqlite 执行失败.
pub fn set_meta(conn: &Connection, key: &str, value: &str, updated_at: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta (key, value, updated_at) VALUES (?1, ?2, ?3)",
        params![key, value, updated_at],
    )?;
    Ok(())
}

/// 读一条 meta 的 value (key 不存在 → None).
///
/// # Errors
/// rusqlite 查询失败 (NoRows 不算错, 返 None).
pub fn get_meta(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM schema_meta WHERE key = ?1", params![key], |r| {
        r.get(0)
    })
    .optional()
}

/// 初始化播种 5 个 well-known key (L1-schema §3.1.1 初始化插入). version="1" / migration_history="[]";
/// account_id_sha / created_at / app_version 由调用方给 (account_id_sha 是 wxid sha 锁文件归属).
/// 所有行 updated_at = `now`.
///
/// # Errors
/// rusqlite 执行失败.
pub fn seed_schema_meta(
    conn: &Connection,
    account_id_sha: &str,
    app_version: &str,
    created_at: i64,
    now: i64,
) -> rusqlite::Result<()> {
    set_meta(conn, META_KEY_VERSION, SCHEMA_VERSION, now)?;
    set_meta(conn, META_KEY_CREATED_AT, &created_at.to_string(), now)?;
    set_meta(conn, META_KEY_APP_VERSION, app_version, now)?;
    set_meta(conn, META_KEY_MIGRATION_HISTORY, "[]", now)?;
    set_meta(conn, META_KEY_ACCOUNT_ID_SHA, account_id_sha, now)?;
    Ok(())
}

// ── capability_backlog 28 缺口字段跟踪登记表 (L1-schema §3.1.9) ──

/// 一条能力缺口跟踪行 (L1-schema §3.1.9 的 9 列). PK = (field_category, field_name).
///
/// **登记表性质** (跟 schema_meta 类似): 本表【无 account_id_sha 列】, 每个 L1 文件内同构副本,
/// 行内容通过版本化 seed + migration 事务收敛 (软一致). PK 是【2 元组】(field_category, field_name).
///
/// **非用户数据无 K-R4 风险**: 全是能力设计元数据 (字段名 / 源 db 表列名 / 里程碑 / 状态 / 备注),
/// 不含 wxid / 消息正文 / 联系人信息 → `#[derive(Debug)]` 安全.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3CapabilityBacklog {
    pub field_category: String,
    pub field_name: String,
    pub src_table: Option<String>,
    pub src_column: Option<String>,
    pub reference_project: Option<String>,
    pub target_milestone: String,
    pub status: String,
    pub notes: Option<String>,
    pub updated_at: i64,
}

/// 建 capability_backlog 表 + 2 索引 (IF NOT EXISTS 幂等, L1-schema §3.1.9).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_capability_backlog_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS capability_backlog (
            field_category    TEXT    NOT NULL,
            field_name        TEXT    NOT NULL,
            src_table         TEXT,
            src_column        TEXT,
            reference_project TEXT,
            target_milestone  TEXT    NOT NULL,
            status            TEXT    NOT NULL,
            notes             TEXT,
            updated_at        INTEGER NOT NULL,
            PRIMARY KEY (field_category, field_name)
        );
        CREATE INDEX IF NOT EXISTS idx_backlog_status
            ON capability_backlog (status);
        CREATE INDEX IF NOT EXISTS idx_backlog_milestone
            ON capability_backlog (target_milestone);",
    )
}

/// 写一条 backlog (INSERT OR REPLACE upsert on PK — status 推进 / 字段调研结果刷新).
/// 注: seed 内容 / status 变化按 §3.1.9 须走 schema/backlog migration 收敛, 本函数是底层 upsert 原语.
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_capability_backlog(conn: &Connection, b: &V3CapabilityBacklog) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO capability_backlog
            (field_category, field_name, src_table, src_column, reference_project,
             target_milestone, status, notes, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            b.field_category,
            b.field_name,
            b.src_table,
            b.src_column,
            b.reference_project,
            b.target_milestone,
            b.status,
            b.notes,
            b.updated_at,
        ],
    )?;
    Ok(())
}

// ════ §3.2 alpha 元数据 / 地图表 (查询规划用, 表结构钉此, 用法在 §11.5-4) ════

// ── source_db_catalog 已发现源 db 清单 (L1-schema §3.2.2) ──

/// 一条已发现源 db 行 (L1-schema §3.2.2 的 7 列). PK = (account_id_sha, db_path_sha).
///
/// **K-R4 关注**: `db_path` 是【明文文件路径】 (可能含 wxid, e.g. "...\\WeChat Files\\wxid_xxx\\..."),
/// 默认 NULL 仅 plaintext 模式填; `db_path_sha` 是其 sha. 故【手写 Debug 脱敏 db_path】 (不 derive),
/// 只示存在性 + db_path_sha (已脱敏). 其余 db_size/mtime/kind/last_scanned 是 metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct V3SourceDbCatalog {
    pub account_id_sha: String,
    pub db_path_sha: String,
    pub db_path: Option<String>,
    pub db_size_bytes: i64,
    pub db_mtime: i64,
    pub db_kind: String,
    pub last_scanned_at: i64,
}

// K-R4: db_path 明文路径 (可能含 wxid) 绝不入 Debug — 只示 Some("<redacted>")/None; db_path_sha 已脱敏可见.
impl std::fmt::Debug for V3SourceDbCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3SourceDbCatalog")
            .field("account_id_sha", &self.account_id_sha)
            .field("db_path_sha", &self.db_path_sha)
            .field("db_path", &self.db_path.as_ref().map(|_| "<redacted>"))
            .field("db_size_bytes", &self.db_size_bytes)
            .field("db_mtime", &self.db_mtime)
            .field("db_kind", &self.db_kind)
            .field("last_scanned_at", &self.last_scanned_at)
            .finish()
    }
}

/// 建 source_db_catalog 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.2.2).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_source_db_catalog_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS source_db_catalog (
            account_id_sha  TEXT    NOT NULL,
            db_path_sha     TEXT    NOT NULL,
            db_path         TEXT,
            db_size_bytes   INTEGER NOT NULL,
            db_mtime        INTEGER NOT NULL,
            db_kind         TEXT    NOT NULL,
            last_scanned_at INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, db_path_sha)
        );
        CREATE INDEX IF NOT EXISTS idx_db_catalog_kind
            ON source_db_catalog (account_id_sha, db_kind);",
    )
}

/// 写一条源 db 清单 (INSERT OR REPLACE upsert on PK — 重扫刷新 size/mtime/last_scanned).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_source_db_catalog(conn: &Connection, c: &V3SourceDbCatalog) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO source_db_catalog
            (account_id_sha, db_path_sha, db_path, db_size_bytes, db_mtime, db_kind, last_scanned_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            c.account_id_sha,
            c.db_path_sha,
            c.db_path,
            c.db_size_bytes,
            c.db_mtime,
            c.db_kind,
            c.last_scanned_at,
        ],
    )?;
    Ok(())
}

// ── source_chat_index chat→源 db 明细映射 (L1-schema §3.2.3) ──

/// 一条 chat→db 明细映射行 (L1-schema §3.2.3 的 5 列). PK = (account_id_sha, chat_id_sha, db_path_sha).
/// 全 sha/metadata (chat_id_sha 跟 message.conv_id_sha 对齐) 无裸文本 → `#[derive(Debug)]` 安全.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3SourceChatIndex {
    pub account_id_sha: String,
    pub chat_id_sha: String,
    pub db_path_sha: String,
    pub message_count: Option<i64>,
    pub last_msg_time: Option<i64>,
}

/// 建 source_chat_index 表 + 1 索引 (IF NOT EXISTS 幂等, L1-schema §3.2.3).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_source_chat_index_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS source_chat_index (
            account_id_sha TEXT    NOT NULL,
            chat_id_sha    TEXT    NOT NULL,
            db_path_sha    TEXT    NOT NULL,
            message_count  INTEGER,
            last_msg_time  INTEGER,
            PRIMARY KEY (account_id_sha, chat_id_sha, db_path_sha)
        );
        CREATE INDEX IF NOT EXISTS idx_chat_index_db
            ON source_chat_index (account_id_sha, db_path_sha);",
    )
}

/// 写一条 chat→db 映射 (INSERT OR REPLACE upsert on PK — 重扫刷新 count/last_msg_time).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_source_chat_index(conn: &Connection, c: &V3SourceChatIndex) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO source_chat_index
            (account_id_sha, chat_id_sha, db_path_sha, message_count, last_msg_time)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            c.account_id_sha,
            c.chat_id_sha,
            c.db_path_sha,
            c.message_count,
            c.last_msg_time
        ],
    )?;
    Ok(())
}

// ── source_chat_to_db chat 跨 db 分布【物化聚合表】 (L1-schema §3.2.4) ──

/// 一条 chat 跨 db 分布行 (L1-schema §3.2.4 的 6 列). PK = (account_id_sha, chat_id_sha).
///
/// **物化聚合表** (真表非 VIEW): 从 source_chat_index 派生 (每 chat 一行, 供 cost model 快查).
/// 刷新责任方/触发条件推 §11.5-4 query planner. 全 sha/metadata → `#[derive(Debug)]` 安全.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3SourceChatToDb {
    pub account_id_sha: String,
    pub chat_id_sha: String,
    pub total_message_count: i64,
    pub db_count: i64,
    pub first_msg_time: Option<i64>,
    pub last_msg_time: Option<i64>,
}

/// 建 source_chat_to_db 表 (IF NOT EXISTS 幂等, L1-schema §3.2.4). 无索引 (PK 即查询键).
///
/// # Errors
/// rusqlite 建表失败.
pub fn init_source_chat_to_db_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS source_chat_to_db (
            account_id_sha      TEXT    NOT NULL,
            chat_id_sha         TEXT    NOT NULL,
            total_message_count INTEGER NOT NULL,
            db_count            INTEGER NOT NULL,
            first_msg_time      INTEGER,
            last_msg_time       INTEGER,
            PRIMARY KEY (account_id_sha, chat_id_sha)
        );",
    )
}

/// 写一条 chat 分布聚合 (INSERT OR REPLACE upsert on PK — 重算聚合刷新).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_source_chat_to_db(conn: &Connection, c: &V3SourceChatToDb) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO source_chat_to_db
            (account_id_sha, chat_id_sha, total_message_count, db_count, first_msg_time, last_msg_time)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            c.account_id_sha,
            c.chat_id_sha,
            c.total_message_count,
            c.db_count,
            c.first_msg_time,
            c.last_msg_time,
        ],
    )?;
    Ok(())
}

// ── source_db_timerange 每 db 时间窗 (L1-schema §3.2.5) ──

/// 一条 db 时间窗行 (L1-schema §3.2.5 的 4 列). PK = (account_id_sha, db_path_sha).
/// min/max_msg_time nullable (空 db / 未扫). 全 sha/metadata → `#[derive(Debug)]` 安全.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3SourceDbTimerange {
    pub account_id_sha: String,
    pub db_path_sha: String,
    pub min_msg_time: Option<i64>,
    pub max_msg_time: Option<i64>,
}

/// 建 source_db_timerange 表 (IF NOT EXISTS 幂等, L1-schema §3.2.5). 无索引 (PK 即查询键).
///
/// # Errors
/// rusqlite 建表失败.
pub fn init_source_db_timerange_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS source_db_timerange (
            account_id_sha TEXT    NOT NULL,
            db_path_sha    TEXT    NOT NULL,
            min_msg_time   INTEGER,
            max_msg_time   INTEGER,
            PRIMARY KEY (account_id_sha, db_path_sha)
        );",
    )
}

/// 写一条 db 时间窗 (INSERT OR REPLACE upsert on PK).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_source_db_timerange(conn: &Connection, t: &V3SourceDbTimerange) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO source_db_timerange
            (account_id_sha, db_path_sha, min_msg_time, max_msg_time)
         VALUES (?1, ?2, ?3, ?4)",
        params![t.account_id_sha, t.db_path_sha, t.min_msg_time, t.max_msg_time],
    )?;
    Ok(())
}

// ── source_query_plans 查询计划缓存 (L1-schema §3.2.6) ──

/// 一条查询计划缓存行 (L1-schema §3.2.6 的 6 列). PK = (account_id_sha, query_signature_sha).
///
/// query_signature_sha 是查询参数 sha (chat_id+时间窗+关键词等); plan_json 是计划 (走 sha 标识符, 非用户数据);
/// LRU 淘汰 (按 last_used_at) 推 §11.5-4 query planner. 全 sha/metadata → `#[derive(Debug)]` 安全.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3SourceQueryPlan {
    pub account_id_sha: String,
    pub query_signature_sha: String,
    pub plan_json: String,
    pub estimated_cost: Option<i64>,
    pub last_used_at: i64,
    pub hit_count: i64,
}

/// 建 source_query_plans 表 + 1 LRU 索引 (IF NOT EXISTS 幂等, L1-schema §3.2.6).
///
/// # Errors
/// rusqlite 建表 / 建索引失败.
pub fn init_source_query_plans_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS source_query_plans (
            account_id_sha      TEXT    NOT NULL,
            query_signature_sha TEXT    NOT NULL,
            plan_json           TEXT    NOT NULL,
            estimated_cost      INTEGER,
            last_used_at        INTEGER NOT NULL,
            hit_count           INTEGER NOT NULL,
            PRIMARY KEY (account_id_sha, query_signature_sha)
        );
        CREATE INDEX IF NOT EXISTS idx_query_plans_lru
            ON source_query_plans (account_id_sha, last_used_at DESC);",
    )
}

/// 写一条查询计划 (INSERT OR REPLACE upsert on PK — 复用刷新 last_used_at/hit_count).
///
/// # Errors
/// rusqlite 执行失败.
pub fn insert_source_query_plan(conn: &Connection, p: &V3SourceQueryPlan) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO source_query_plans
            (account_id_sha, query_signature_sha, plan_json, estimated_cost, last_used_at, hit_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            p.account_id_sha,
            p.query_signature_sha,
            p.plan_json,
            p.estimated_cost,
            p.last_used_at,
            p.hit_count,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    /// R9 复审R3#2: 单写者锁 **OS 独占** —— 持锁时二次取失败 (INDEX_LOCKED), drop 释放后可再取 (无残锁)。
    /// (windows OS 句柄独占; 验证 TOCTOU 根治: 无 remove+create 竞态, 释放即净。)
    #[cfg(windows)]
    #[test]
    fn watch_lock_exclusive_and_released_on_drop() {
        let dir = tempdir().unwrap();
        let l1 = dir.path().join("locktest.db");
        std::fs::write(&l1, b"x").unwrap(); // L1 存在 (canonicalize 父目录用)
        let g1 = acquire_watch_lock(&l1).expect("首次取锁成功");
        assert!(acquire_watch_lock(&l1).is_err(), "已被独占 → 二次取锁 INDEX_LOCKED");
        drop(g1); // OS 关句柄 → 释放独占 + DELETE_ON_CLOSE 删锁文件
        let g2 = acquire_watch_lock(&l1).expect("释放后可再取 (无残锁)");
        drop(g2);
    }

    fn rec(native_id: &str, event_seq: i64, ingest_time: i64) -> RawPayloadRecord {
        RawPayloadRecord {
            account_id_sha: "acct_sha".to_string(),
            source: "message_5.db".to_string(),
            source_native_id: native_id.to_string(),
            event_type: "message".to_string(),
            event_action: "create".to_string(),
            event_seq,
            ingest_time,
            payload_json: r#"{"event_type":"message"}"#.to_string(),
        }
    }

    /// 真文件库 (WAL 要文件) — open + init + 基本插入回查.
    fn open_inited() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let conn = open(&dir.path().join("l1.db")).unwrap();
        init_archive_table(&conn).unwrap();
        (dir, conn)
    }

    #[test]
    fn open_applies_wal_pragma() {
        let (_d, conn) = open_inited();
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        assert_eq!(mode.to_lowercase(), "wal", "§3.4 journal_mode=WAL (真文件库)");
        let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        assert_eq!(page, 4096, "§3.4 page_size=4096");
    }

    #[test]
    fn init_is_idempotent() {
        let (_d, conn) = open_inited();
        // 再建一次不报错 (IF NOT EXISTS)
        init_archive_table(&conn).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='raw_payload_archive'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn insert_then_query_back() {
        let (_d, conn) = open_inited();
        assert!(
            insert_record(&conn, &rec("Msg_a:1", 100, 1000)).unwrap(),
            "新插入返 true"
        );
        let (et, seq, payload): (String, i64, String) = conn
            .query_row(
                "SELECT event_type, event_seq, payload_json FROM raw_payload_archive WHERE source_native_id='Msg_a:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(et, "message");
        assert_eq!(seq, 100);
        assert_eq!(payload, r#"{"event_type":"message"}"#);
    }

    /// 重放去重: 同 5 元组 (即便 ingest_time / payload 不同) → INSERT OR IGNORE 撞键 → 返 false, 不增行.
    #[test]
    fn replay_same_5tuple_deduped() {
        let (_d, conn) = open_inited();
        assert!(insert_record(&conn, &rec("Msg_a:1", 100, 1000)).unwrap());
        // 同 (account/source/native_id/action/seq), 不同 ingest_time + 不同 payload
        let mut dup = rec("Msg_a:1", 100, 9999);
        dup.payload_json = r#"{"event_type":"message","x":1}"#.to_string();
        assert!(!insert_record(&conn, &dup).unwrap(), "撞 5 元组 → 去重返 false");
        let count: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "重放不增行");
        // 且保留的是第一条 (ingest_time=1000)
        let kept: i64 = conn
            .query_row("SELECT ingest_time FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(kept, 1000);
    }

    /// SSE tail 过滤变体: account_id_sha / event_type / limit / after_id 各维生效.
    #[test]
    fn read_archive_since_filtered_by_account_type_limit() {
        let (_d, conn) = open_inited();
        // A 账号 2 条 message + B 账号 1 条 message + A 账号 1 条 contact_update.
        let mut r = rec("Msg_a:1", 1, 1000);
        r.account_id_sha = "A".into();
        insert_record(&conn, &r).unwrap();
        let mut r = rec("Msg_a:2", 2, 1001);
        r.account_id_sha = "A".into();
        insert_record(&conn, &r).unwrap();
        let mut r = rec("Msg_b:1", 3, 1002);
        r.account_id_sha = "B".into();
        insert_record(&conn, &r).unwrap();
        let mut r = rec("Ct_a:1", 4, 1003);
        r.account_id_sha = "A".into();
        r.event_type = "contact_update".into();
        insert_record(&conn, &r).unwrap();

        // 无过滤 → 全 4 条, id ASC.
        let all = read_archive_since_filtered(&conn, 0, None, None, 100).unwrap();
        assert_eq!(all.len(), 4);
        assert!(all.windows(2).all(|w| w[0].0 < w[1].0), "id ASC");

        // 账号 A → 3 条.
        let a = read_archive_since_filtered(&conn, 0, Some("A"), None, 100).unwrap();
        assert_eq!(a.len(), 3);
        assert!(a.iter().all(|(_, r)| r.account_id_sha == "A"));

        // 账号 A + 类型 message → 2 条.
        let am = read_archive_since_filtered(&conn, 0, Some("A"), Some("message"), 100).unwrap();
        assert_eq!(am.len(), 2);
        assert!(am
            .iter()
            .all(|(_, r)| r.account_id_sha == "A" && r.event_type == "message"));

        // 类型 contact_update → 1 条.
        let c = read_archive_since_filtered(&conn, 0, None, Some("contact_update"), 100).unwrap();
        assert_eq!(c.len(), 1);

        // limit 2 → 只前 2 条 (id 最小).
        let lim = read_archive_since_filtered(&conn, 0, None, None, 2).unwrap();
        assert_eq!(lim.len(), 2);
        assert_eq!(lim[0].1.source_native_id, "Msg_a:1");
        assert_eq!(lim[1].1.source_native_id, "Msg_a:2");

        // after_id 游标 (第 2 条之后) → 剩 2 条.
        let after = read_archive_since_filtered(&conn, all[1].0, None, None, 100).unwrap();
        assert_eq!(after.len(), 2);
    }

    /// 不同 event_seq (新实例) → 不同 5 元组 → 都插入 (不去重).
    #[test]
    fn different_seq_not_deduped() {
        let (_d, conn) = open_inited();
        assert!(insert_record(&conn, &rec("Msg_a:1", 100, 1000)).unwrap());
        assert!(
            insert_record(&conn, &rec("Msg_a:1", 200, 1000)).unwrap(),
            "不同 seq → 新行"
        );
        let count: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    /// 滚动删: 删 ingest_time < cutoff, 保留 >=.
    /// **超窗的删、窗内的一条不许碰**(外部复审报的 P1)。
    ///
    /// 底下那条 `prune_deletes_old_keeps_recent` 测的是**原始函数**(调用方自己算 cutoff);
    /// 这条测的是**生产真正调的那个入口** —— 它自己按保留小时数算窗口, 调用方只给"现在几点"
    /// 和"留几小时"。窗口算错(符号写反、单位搞错秒/毫秒、小时当分钟)只有这条逮得到。
    #[test]
    fn prune_archive_now_uses_the_given_window() {
        let conn = Connection::open_in_memory().unwrap();
        init_archive_table(&conn).unwrap();
        let now = 1_800_000_000_000i64;
        let put = |t: i64, nid: &str| insert_record(&conn, &rec(nid, 0, t)).unwrap();
        // ⚠️ **时间点写死, 不拿常量算** —— 头一版用的是 `now - ARCHIVE_RETENTION_MS - 1` 这种,
        // 结果常量单位从毫秒改成秒(少 1000 倍)时**照样绿**: 夹具跟着常量一起缩, 相对关系没变。
        // 那样测的是"删的是不是比 cutoff 老", 不是"窗口到底多长"。埋反例才发现的。
        let hour: i64 = 60 * 60 * 1000;
        put(now - 25 * hour, "25 小时前(超窗)");
        put(now - 23 * hour, "23 小时前(窗内)");
        put(now - 1000, "一秒前");
        put(now, "此刻");

        let deleted = prune_archive_now(&conn, now, ARCHIVE_RETENTION_HOURS_DEFAULT).unwrap();
        assert_eq!(deleted, 1, "默认 24 小时: 只该删 25 小时前那一条, 不是别的数");

        let left: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 3, "23 小时前的和更近的都得留着 —— 它们是下游 app 的重放窗口");
    }

    /// **配的小时数得真算数**(codex 审这一笔的 P2)。
    ///
    /// 窗口写死 24 的话, 用户配 72 小时, 我会把 24..72 小时那段**不可逆地删掉** —— 他要留的正是那段。
    /// 反过来配 1 小时, 该清的多留 23 小时。两边都错, 而且删掉的找不回来。
    ///
    /// 这条挑的时间点是 **48 小时前**: 它在默认 24 小时窗外、在配的 72 小时窗内。
    /// 谁要是把窗口改回写死 24(不管是常量还是把参数丢掉), 这一条立刻红。
    #[test]
    fn prune_archive_now_honors_a_non_default_window() {
        let conn = Connection::open_in_memory().unwrap();
        init_archive_table(&conn).unwrap();
        let now = 1_800_000_000_000i64;
        let hour: i64 = 60 * 60 * 1000;
        insert_record(&conn, &rec("48 小时前", 0, now - 48 * hour)).unwrap();
        insert_record(&conn, &rec("此刻", 0, now)).unwrap();

        let deleted = prune_archive_now(&conn, now, 72).unwrap();
        assert_eq!(deleted, 0, "配了 72 小时, 48 小时前那条还在窗内 —— 一条都不许删");

        let deleted = prune_archive_now(&conn, now, 1).unwrap();
        assert_eq!(deleted, 1, "配 1 小时: 48 小时前那条该走, 此刻那条得留");
    }

    /// **正好落在 cutoff 上的那条得留着**(独立复审埋变异逮到的空白)。
    ///
    /// 同文件 `prune_older_than` 的注释白纸黑字写着"删 `ingest_time < cutoff`, **保留 >=**"。
    /// 把 SQL 的 `<` 改成 `<=`, 代码跟这句注释直接矛盾 —— 而全仓 1075 条测试**一条不红**:
    /// 上面那几条挑的时间点是 25 小时前 / 23 小时前 / 一秒前 / 此刻, 没有一个落在 cutoff 上。
    #[test]
    fn row_exactly_at_the_cutoff_survives() {
        let conn = Connection::open_in_memory().unwrap();
        init_archive_table(&conn).unwrap();
        let now = 1_800_000_000_000i64;
        let hour: i64 = 60 * 60 * 1000;
        insert_record(&conn, &rec("正好 24 小时整", 0, now - 24 * hour)).unwrap();
        insert_record(&conn, &rec("再老一毫秒", 0, now - 24 * hour - 1)).unwrap();

        let deleted = prune_archive_now(&conn, now, ARCHIVE_RETENTION_HOURS_DEFAULT).unwrap();
        assert_eq!(deleted, 1, "只该删老一毫秒那条");

        let left: String = conn
            .query_row("SELECT source_native_id FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, "正好 24 小时整", "正好卡在窗口边上的算窗内, 得留着");
    }

    /// **超过一批的量要全删完, 不能只删头一批**。
    ///
    /// 分批是为了别把 977 万行塞进一个事务(独立复审在 42 GB 真库上量的量), 但分批引进一个新的
    /// 失败方式: 循环退化成只跑一趟, 就变成**一次只删一批** —— 表永远清不完, 而返回值看着还挺正常。
    /// 这条塞 `一批 + 5` 条老记录, 一次调用必须全删干净(埋"只删一批"这个变异, 实测打红)。
    ///
    /// ⚠️ 盖不住也不该盖的: 退出条件从 `n < 批` 改成 `n == 0` 这条测**不红**, 我埋过。
    /// 那不是 bug —— 它照样删干净, 只是末尾多跑一次空查询。别为了让变异表好看去硬凑守卫。
    #[test]
    fn prune_clears_everything_past_one_batch() {
        let conn = Connection::open_in_memory().unwrap();
        init_archive_table(&conn).unwrap();
        let n_old = super::ARCHIVE_PRUNE_BATCH + 5;
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..n_old {
            conn.execute(
                "INSERT INTO raw_payload_archive
                 (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                 VALUES ('sha', 'src', ?1, 'message', 'insert', 1, 1000, '{}')",
                params![i.to_string()],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
        insert_record(&conn, &rec("窗内", 0, 9_000)).unwrap();

        let deleted = prune_older_than(&conn, 5_000).unwrap();
        assert_eq!(deleted, n_old, "一次调用要把超窗的全删完, 不是只删头一批");
        let left: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "只剩窗内那一条");
    }

    /// **节流真的在节流, 而且到点会再删**。
    ///
    /// 常驻路径每写一批都路过清理点, 靠节流才不会每批一次 DELETE。节流写坏有两种方向, 各守一边:
    /// 挡过头(到点也不删 → 归档还是无限涨)、挡不住(每批都删 → 白折腾索引)。
    ///
    /// 一次最多删几批也在这条里钉住: 塞 `十批 + 1` 条老记录, 一次调用只该删掉十批那么多。
    #[test]
    fn throttled_prune_waits_then_fires_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("throttle.db");
        let conn = open(&path).unwrap();
        init_archive_table(&conn).unwrap();
        let now = 1_800_000_000_000i64;
        let hour: i64 = 60 * 60 * 1000;
        let put = |nid: &str, t: i64| {
            conn.execute(
                "INSERT INTO raw_payload_archive
                 (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                 VALUES ('sha', 'src', ?1, 'message', 'insert', 1, ?2, '{}')",
                params![nid, t],
            )
            .unwrap();
        };

        put("第一条超窗", now - 25 * hour);
        let first = prune_archive_throttled_at(&conn, now, 5 * 60 * 1000, 24).unwrap();
        assert_eq!(first, Some(1), "头一次没有前科, 该删就删");

        // 又来一条超窗的, 但离上次不到间隔 —— 这次必须原地跳过, 连库都不该查。
        put("间隔内又来一条", now - 26 * hour);
        let second = prune_archive_throttled_at(&conn, now + 60_000, 5 * 60 * 1000, 24).unwrap();
        assert_eq!(second, None, "没到间隔就得跳过, 不然等于每批都删");
        let left: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "跳过就是真没删");

        // 过了间隔 —— 必须再删一次, 不能"挡过头"。
        let third = prune_archive_throttled_at(&conn, now + 6 * 60 * 1000, 5 * 60 * 1000, 24).unwrap();
        assert_eq!(third, Some(1), "到点了就得再删, 否则归档只涨不清");
    }

    /// 常驻路径一次调用**最多删十批** —— 别长时间占着线程。
    #[test]
    fn throttled_prune_stops_at_the_batch_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cap.db");
        let conn = open(&path).unwrap();
        init_archive_table(&conn).unwrap();
        let n_old = super::ARCHIVE_PRUNE_BATCH * super::ARCHIVE_PRUNE_THROTTLED_BATCHES + 1;
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..n_old {
            conn.execute(
                "INSERT INTO raw_payload_archive
                 (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                 VALUES ('sha', 'src', ?1, 'message', 'insert', 1, 1000, '{}')",
                params![i.to_string()],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();

        let deleted = prune_archive_throttled_at(&conn, 1_800_000_000_000, 0, 24).unwrap();
        assert_eq!(
            deleted,
            Some(super::ARCHIVE_PRUNE_BATCH * super::ARCHIVE_PRUNE_THROTTLED_BATCHES),
            "到上限就收手, 剩的下一轮再删 (删除本来可续)"
        );
        let left: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "剩下那条还在, 下一轮会被带走");
    }

    /// **"这条消息没解出来"的记录永不清**(2026-07-31 用户拍板)。
    ///
    /// 正文解不出来的消息不进 message 表, 只 emit 一条 `SystemError`; 而 `SystemError` 没有 L2 表,
    /// 归档里那一行就是"这儿丢过一条"的**唯一持久记录**。滚动窗口一清, 消息没了、记录也没了,
    /// 而水位早过去了, 重跑不会再读到它 —— 跟已经定死的"丢可以、静默不行"直接冲突。
    #[test]
    fn error_records_are_never_pruned() {
        let conn = Connection::open_in_memory().unwrap();
        init_archive_table(&conn).unwrap();
        let put = |nid: &str, action: &str, t: i64| {
            conn.execute(
                "INSERT INTO raw_payload_archive
                 (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)
                 VALUES ('sha', 'src', ?1, 'system_event', ?2, 0, ?3, '{}')",
                params![nid, action, t],
            )
            .unwrap();
        };
        put("解不出来那条", "error", 1_000); // 老得不能再老
        put("水位记录", "cursor_update", 1_000);
        put("普通消息", "create", 1_000);

        let deleted = prune_older_than(&conn, 5_000).unwrap();
        assert_eq!(deleted, 2, "水位和普通消息该清, 丢失记录不该");

        let left: Vec<String> = conn
            .prepare("SELECT source_native_id FROM raw_payload_archive")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            left,
            vec!["解不出来那条".to_string()],
            "丢失记录不许被清 —— 清了就等于丢得悄无声息"
        );
    }

    /// **保留期是节流放行之后才去取的** —— 被挡掉的那些不许付读盘的钱(独立复审 c4b5dbc 的 P2)。
    ///
    /// 这个清理挂在 drain 循环里, 是"每分片 × 每会话 × 每批"调一次。原先第一句就读 config 文件,
    /// 实测一次 161.6 µs, 按真库 2.2 万会话算 watch 一轮白花约 3.5 秒 —— 而其中绝大多数都会被
    /// 节流当场挡掉, 那份钱纯属白花。
    #[test]
    fn retention_is_fetched_only_after_the_throttle_lets_it_through() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("lazy.db")).unwrap();
        init_archive_table(&conn).unwrap();
        let now = 1_800_000_000_000i64;
        let fetches = AtomicUsize::new(0);
        let retention = || {
            fetches.fetch_add(1, Ordering::SeqCst);
            Some(24u32)
        };

        prune_archive_throttled_with(&conn, now, 5 * 60 * 1000, retention).unwrap();
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "放行那次要取一遍");

        for i in 1..=50 {
            prune_archive_throttled_with(&conn, now + i * 1000, 5 * 60 * 1000, retention).unwrap();
        }
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "被节流挡掉的 50 次一次都不该去取 —— 取一次要读盘"
        );
    }

    /// **节流键归一**(独立复审 c4b5dbc 的 P3): 同一个库不该占两个槽。
    #[test]
    fn throttle_key_is_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let lower = dir.path().join("case.db");
        let conn = open(&lower).unwrap();
        init_archive_table(&conn).unwrap();
        let now = 1_800_000_000_000i64;

        assert!(
            prune_archive_throttled_at(&conn, now, 5 * 60 * 1000, 24)
                .unwrap()
                .is_some(),
            "头一次放行"
        );
        // 大小写归一**只在 Windows 上**成立 —— 那儿 `k.db` / `K.DB` 是同一个文件。
        // Linux 上它们是两个不同的库, 并成一个槽反而会让其中一个永远清不了(codex 审 651ed5c 的 P2)。
        if cfg!(windows) {
            let upper: std::path::PathBuf = lower.to_string_lossy().to_uppercase().into();
            // ⚠️ 原先写的是 `if let Ok(conn2) = open(..)` —— 打不开整条断言就**无声消失**
            // (独立复审 651ed5c 的 P3)。Windows 上大小写不同指的就是同一个已存在的文件,
            // 打不开是环境不对, 该当场炸出来, 不是悄悄跳过。
            let conn2 = open(&upper).expect("Windows 上大小写变体指向同一个已存在的文件, 该打得开");
            assert_eq!(
                prune_archive_throttled_at(&conn2, now + 1000, 5 * 60 * 1000, 24).unwrap(),
                None,
                "Windows 上大小写不同是同一个库, 必须共用同一个节流槽"
            );
        }

        // 内存库: `conn.path()` 给的是空串不是 None, 要显式认出来。
        let mem = Connection::open_in_memory().unwrap();
        init_archive_table(&mem).unwrap();
        assert!(
            prune_archive_throttled_at(&mem, now, 5 * 60 * 1000, 24)
                .unwrap()
                .is_some(),
            "内存库也要能走通(键退成固定串), 不能因为空串跟别人串在一起"
        );
    }

    /// **删的那一头也得听"读不懂就别清"**(独立复审 651ed5c 的 P2)。
    ///
    /// 底下那条 `unreadable_config_means_do_not_prune` 只调"读的那一头", 它证明读出来是 `None`,
    /// 证明不了删的那一头听不听、也证明不了生产真去读了。复审埋了三个变异 ——
    /// 把 `None` 改成退回默认 24 / 生产路径绕开 config 写死 24 / adapter 那条也写死 24 ——
    /// **全工作区一条不红**。又是那句"它证明函数算得对, 证明不了有人调它", 这回落在同一个函数的另一半。
    ///
    /// ⚠️ **头一版这条走的不是生产入口**(独立复审 656477c 的 P2): 我调的是 `*_from`(带路径参数
    /// 那个内层函数), 而生产调的是不带参数的外层。审查方把**外层那一行**换成"绕开 config 写死 24",
    /// 全工作区一条不红 —— 而我的 commit message 写着这个反例已经打红了。我埋的是内层、他埋的是
    /// 外层, 两句都对, 但没人守着的正是外层。现在走真正的 `prune_archive_throttled`,
    /// config 路径靠测试钩子指到临时文件。
    #[test]
    fn production_prune_skips_when_config_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("skip.db");
        let conn = open(&db).unwrap();
        init_archive_table(&conn).unwrap();
        insert_record(&conn, &rec("老得该清了", 0, 1_000)).unwrap();
        let now = 1_800_000_000_000i64;

        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "这不是 toml [[[").unwrap();
        let hook = config_path_for_test(&broken);
        prune_archive_throttled(&conn, now);
        let left: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            left, 1,
            "config 读不懂就一条都不许删 —— 退回默认 24 会删掉配了长保留期的人的数据"
        );

        // 换成能读懂的 config, 同一条立刻该走 —— 证明上面那次不是因为别的原因没删。
        let good = dir.path().join("good.toml");
        std::fs::write(
            &good,
            "[config_meta]
version = \"0.1.0\"

[adapter]
archive_retention_hours = 24
",
        )
        .unwrap();
        drop(hook);
        let _hook = config_path_for_test(&good);
        prune_archive_throttled(&conn, now + 10 * 60 * 1000);
        let left: i64 = conn
            .query_row("SELECT count(*) FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0, "config 好了就该清 —— 不然上面那条断言是空的");
    }

    /// **读不懂的那一轮退避重试 —— 既不占满五分钟, 也不是每批都试**。
    ///
    /// 两条审各按住一头, 这条把两头一起钉死:
    /// - 占满五分钟不行(独立复审 651ed5c 的 P3): 全量导入里传进来的时刻是整轮不变的常量,
    ///   头一批恰好读不懂就意味着这一整轮(几个小时)一次都不会清。
    /// - 完全清掉也不行(codex 审 656477c 的 P2): config 一直坏着的话每批都重读一遍坏文件 +
    ///   每批一行警告, 节流形同虚设, 换来 IO 和日志风暴。
    #[test]
    fn a_failed_retention_lookup_backs_off_instead_of_burning_or_hogging_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("slot.db")).unwrap();
        init_archive_table(&conn).unwrap();
        insert_record(&conn, &rec("老得该清了", 0, 1_000)).unwrap();
        let now = 1_800_000_000_000i64;

        assert_eq!(
            prune_archive_throttled_with(&conn, now, 5 * 60 * 1000, || None).unwrap(),
            None,
            "取不到保留期 → 这轮不清"
        );
        // 紧接着的下一批: **还不能**放行 —— 不然 config 一直坏着的话每批都要重读一遍坏文件
        // 加一行警告(codex 审 656477c 的 P2)。
        assert_eq!(
            prune_archive_throttled_with(&conn, now + 1, 5 * 60 * 1000, || Some(24)).unwrap(),
            None,
            "刚失败就立刻重试 = 节流形同虚设, config 坏着时会 IO + 日志风暴"
        );
        // 过了退避那一小段就要能重试 —— 而且**远早于**正常的五分钟间隔。
        let retry = super::ARCHIVE_PRUNE_RETRY_MS;
        assert!(retry * 4 < 5 * 60 * 1000, "退避得明显短于正常间隔, 否则等于占满槽");
        assert_eq!(
            prune_archive_throttled_with(&conn, now + retry + 1, 5 * 60 * 1000, || Some(24)).unwrap(),
            Some(1),
            "退避到期就得重试 —— 占满五分钟的话, 全量导入一整轮都不会清"
        );
    }

    /// **删本身失败那一轮也要退避**(独立复审 656477c 的 P3)。
    ///
    /// 上一版只给"取不到保留期"那条加了退避, 而**库忙 / 表还没建**也会让这一轮白跑 ——
    /// 那时槽照样被占满整个间隔。判据是"**任何一轮**没清成都不该占满槽", 不是"取不到保留期那一轮"。
    ///
    /// 夹具用一个**没有归档表**的库让删除真失败(不是模拟), 然后建好表, 断言退避到期能重试。
    #[test]
    fn a_failed_delete_also_backs_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("failed-delete.db");
        let conn = open(&path).unwrap();
        let now = 1_800_000_000_000i64;
        let retry = super::ARCHIVE_PRUNE_RETRY_MS;

        // 表还没建 → 删除真报错。
        assert!(
            prune_archive_throttled_with(&conn, now, 5 * 60 * 1000, || Some(24)).is_err(),
            "夹具前提: 没有归档表时删除该报错"
        );

        init_archive_table(&conn).unwrap();
        insert_record(&conn, &rec("老得该清了", 0, 1_000)).unwrap();

        // 紧接着不放行(不然坏状态下每批都试)。
        assert_eq!(
            prune_archive_throttled_with(&conn, now + 1, 5 * 60 * 1000, || Some(24)).unwrap(),
            None,
            "刚失败就立刻重试 = 节流形同虚设"
        );
        // 退避到期就该重试 —— 而不是等满整个间隔。
        assert_eq!(
            prune_archive_throttled_with(&conn, now + retry + 1, 5 * 60 * 1000, || Some(24)).unwrap(),
            Some(1),
            "删失败那一轮不该占满整个间隔, 退避到期就得再试"
        );
    }

    /// **config 读不懂就别清**(codex 审 c4b5dbc 的 P1)。
    ///
    /// 原先用 `load_or_default`: 任何加载失败都退回默认 24 小时。用户配 720 小时, 某次解析偶然失败
    /// (文件正被写了一半 / 手滑写错一个字段), 就会按 24 小时**不可逆地删掉**他要留的那 696 小时。
    /// 猜错删掉的数据回不来, 不清只是这轮没清 —— 两边代价不对等。
    ///
    /// 只有"文件不存在"可以照默认走: 那不是读不懂, 那是没配置。
    #[test]
    fn unreadable_config_means_do_not_prune() {
        let dir = tempfile::tempdir().unwrap();

        let missing = dir.path().join("没有这个文件.toml");
        assert_eq!(
            configured_retention_hours_at(&missing),
            Some(ARCHIVE_RETENTION_HOURS_DEFAULT),
            "没配置文件 = 没配置, 走默认"
        );

        let good = dir.path().join("good.toml");
        std::fs::write(
            &good,
            "[config_meta]
version = \"0.1.0\"

[adapter]
archive_retention_hours = 720
",
        )
        .unwrap();
        assert_eq!(configured_retention_hours_at(&good), Some(720), "配了就听配的");

        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "这不是 toml [[[").unwrap();
        assert_eq!(
            configured_retention_hours_at(&broken),
            None,
            "读不懂就返回 None = 这轮别清; 退回默认 24 会把配了 720 的人的数据删掉"
        );

        let out_of_range = dir.path().join("range.toml");
        std::fs::write(
            &out_of_range,
            "[config_meta]
version = \"0.1.0\"

[adapter]
archive_retention_hours = 99999
",
        )
        .unwrap();
        assert_eq!(
            configured_retention_hours_at(&out_of_range),
            None,
            "校验不过也算读不懂, 同样别清"
        );
    }

    #[test]
    fn prune_deletes_old_keeps_recent() {
        let (_d, conn) = open_inited();
        insert_record(&conn, &rec("Msg_old:1", 1, 1_000)).unwrap();
        insert_record(&conn, &rec("Msg_new:1", 2, 9_000)).unwrap();
        let deleted = prune_older_than(&conn, 5_000).unwrap();
        assert_eq!(deleted, 1, "删 1 条旧的");
        let remaining: String = conn
            .query_row("SELECT source_native_id FROM raw_payload_archive", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, "Msg_new:1", "保留新的");
    }

    // ── read_archive_since (replay 数据访问原语) ──

    /// 空 archive → 空.
    #[test]
    fn read_archive_since_empty() {
        let (_d, conn) = open_inited();
        assert!(read_archive_since(&conn, 0).unwrap().is_empty());
    }

    /// after_id=0: 读全部, 按 id ASC, 重构 RawPayloadRecord 字段对.
    #[test]
    fn read_archive_since_zero_reads_all_in_order() {
        let (_d, conn) = open_inited();
        insert_record(&conn, &rec("Msg_a:1", 10, 1000)).unwrap();
        insert_record(&conn, &rec("Msg_b:1", 20, 2000)).unwrap();
        insert_record(&conn, &rec("Msg_c:1", 30, 3000)).unwrap();
        let rows = read_archive_since(&conn, 0).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].0 < rows[1].0 && rows[1].0 < rows[2].0, "按 id ASC 单调");
        // 重构字段对 (第一条)
        let (_id, r0) = &rows[0];
        assert_eq!(r0.source_native_id, "Msg_a:1");
        assert_eq!(r0.event_seq, 10);
        assert_eq!(r0.ingest_time, 1000);
        assert_eq!(r0.event_type, "message");
        assert_eq!(r0.event_action, "create");
        assert_eq!(r0.payload_json, r#"{"event_type":"message"}"#);
    }

    /// after_id=游标: 只读 id > 游标 (续传跳过已消费).
    #[test]
    fn read_archive_since_cursor_skips_consumed() {
        let (_d, conn) = open_inited();
        insert_record(&conn, &rec("Msg_a:1", 10, 1000)).unwrap();
        insert_record(&conn, &rec("Msg_b:1", 20, 2000)).unwrap();
        insert_record(&conn, &rec("Msg_c:1", 30, 3000)).unwrap();
        let first_id = read_archive_since(&conn, 0).unwrap()[0].0;
        let rest = read_archive_since(&conn, first_id).unwrap();
        assert_eq!(rest.len(), 2, "id > 第一条游标 → 跳过已消费");
        assert_eq!(rest[0].1.source_native_id, "Msg_b:1", "续读从第二条起");
        // 末条游标 → 空 (全消费)
        let last_id = rest[1].0;
        assert!(
            read_archive_since(&conn, last_id).unwrap().is_empty(),
            "末游标后无新事件"
        );
    }

    // ── L2 message 表 ──

    fn sample_msg(native_id: &str, status: i64) -> V3Message {
        V3Message {
            account_id_sha: "acct_sha".to_string(),
            source: "message_5.db".to_string(),
            source_native_id: native_id.to_string(),
            conv_id_sha: "conv_sha".to_string(),
            server_id: 9_876_543_210,
            server_seq: 100,
            origin_source: 2,
            upload_status: 0,
            download_status: 0,
            create_time: 1_700_000_000_000,
            sort_seq: 555,
            status,
            msg_type: 1,
            msg_type_name: "TEXT".to_string(),
            msg_sub_type: Some(0),
            msg_sub_type_name: None,
            local_type_raw: 1,
            sender_wxid_sha: "sender_sha".to_string(),
            is_chatroom: false,
            text_content_sha: "text_sha".to_string(),
            text_content_len: 12,
            raw_xml_present: false,
            decode_kind: "plain".to_string(),
            sys_type: None,
            account_id: "wxid_acct".to_string(),
            conv_id: "wxid_conv".to_string(),
            sender_wxid: "wxid_sender".to_string(),
            text_content: "你好啊在吗".to_string(),
        }
    }

    /// FTS5 全文搜索 (ADR-502): 中文子串命中 + trigram(≥3字) 与 LIKE 兜底(<3字) 两条路 + 无命中.
    #[test]
    fn fts_search_chinese_substring() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        let mk = |id: &str, text: &str| V3Message {
            text_content: text.to_string(),
            ..sample_msg(id, 1)
        };
        insert_message(&conn, &mk("Msg_a:1", "今天天气很欧美，出去玩")).unwrap();
        insert_message(&conn, &mk("Msg_a:2", "晚上一起吃火锅吗")).unwrap();
        insert_message(&conn, &mk("Msg_a:3", "欧美风格的照片挺好看")).unwrap();

        let n = rebuild_message_fts(&conn).unwrap();
        assert_eq!(n, 3, "FTS 索引 3 行");

        // "欧美" 2 字 → LIKE 兜底; 命中 m1(很欧美) + m3(欧美风格)。
        assert_eq!(
            search_messages(&conn, "欧美", 10, None).unwrap().len(),
            2,
            "'欧美' 两条"
        );
        // "很欧美" 3 字 → trigram FTS; 只 m1。
        let h = search_messages(&conn, "很欧美", 10, None).unwrap();
        assert_eq!(h.len(), 1, "'很欧美' 一条");
        assert!(h[0].text_content.contains("很欧美"));
        // "吃火锅" 3 字 → trigram; 只 m2。
        assert_eq!(
            search_messages(&conn, "吃火锅", 10, None).unwrap().len(),
            1,
            "'吃火锅' 一条"
        );
        // 无命中。
        assert!(
            search_messages(&conn, "不存在的词", 10, None).unwrap().is_empty(),
            "无命中空"
        );
        // rebuild 幂等 (再来一遍仍 3 行, 不翻倍)。
        assert_eq!(rebuild_message_fts(&conn).unwrap(), 3, "rebuild 幂等");
    }

    /// 无索引也能搜 (ADR-502 §4): 不建 message_fts, ≥3 字 query 自动退化 LIKE 全表扫描仍命中。
    #[test]
    fn fts_search_without_index_falls_back_to_like() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        insert_message(
            &conn,
            &V3Message {
                text_content: "今天很欧美啊".to_string(),
                ..sample_msg("Msg_a:1", 1)
            },
        )
        .unwrap();
        // 没跑 rebuild_message_fts → message_fts 不存在 → 即便 3 字也走 LIKE。
        let hits = search_messages(&conn, "很欧美", 10, None).unwrap();
        assert_eq!(hits.len(), 1, "无索引靠 LIKE 兜底仍命中");
    }

    /// R9 件1: `message_fts` 增量触发器 —— INSERT 自动可搜 + **INSERT OR REPLACE 换 rowid 后 FTS 无悬空**
    /// (旧正文项自动删、新正文项自动插) + DELETE 自动删 + FTS 行数与 message 恒一致。
    #[test]
    fn fts_triggers_incremental_maintain_over_replace() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        init_message_fts_triggers(&conn).unwrap(); // 建触发器 → 增量维护 (不用手动 rebuild)。
        let mk = |id: &str, text: &str| V3Message {
            text_content: text.to_string(),
            ..sample_msg(id, 1)
        };

        // (1) INSERT 自动进 FTS (触发器, 无手动 rebuild)。
        insert_message(&conn, &mk("Msg_a:1", "今天吃火锅很开心")).unwrap();
        assert_eq!(
            search_messages(&conn, "吃火锅", 10, None).unwrap().len(),
            1,
            "触发器: 新插自动可搜"
        );

        // (2) ⭐INSERT OR REPLACE 同 PK → 换 rowid → 触发器 (AFTER DELETE 用旧正文删旧项 + AFTER INSERT 插新项)。
        let old_rowid: i64 = conn
            .query_row("SELECT rowid FROM message WHERE source_native_id='Msg_a:1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        insert_message(&conn, &mk("Msg_a:1", "改吃烧烤味道也不错")).unwrap();
        let new_rowid: i64 = conn
            .query_row("SELECT rowid FROM message WHERE source_native_id='Msg_a:1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_ne!(old_rowid, new_rowid, "INSERT OR REPLACE 确实换 rowid (坐实前提)");
        assert!(
            search_messages(&conn, "吃火锅", 10, None).unwrap().is_empty(),
            "旧正文项随旧 rowid 被触发器删 —— 无悬空"
        );
        // 双审 P2 真验证无悬空: **直接查 FTS raw rowid** —— search_messages 的 `JOIN message m ON m.rowid=f.rowid`
        // 会掩盖死 rowid (recursive_triggers=OFF 时旧倒排残留却因 JOIN 过滤看不出, 原单测正是这样假过)。绕过 JOIN
        // 直查原始倒排: recursive_triggers=ON 让 REPLACE 隐式删触发 _ad 删旧项 → 旧词无残留。
        let raw_old: Vec<i64> = conn
            .prepare("SELECT rowid FROM message_fts WHERE message_fts MATCH '吃火锅'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert!(
            raw_old.is_empty(),
            "recursive_triggers=ON: 旧词原始倒排无残留 rowid (真无悬空, 非 JOIN 掩盖)"
        );
        assert_eq!(
            search_messages(&conn, "吃烧烤", 10, None).unwrap().len(),
            1,
            "新正文按新 rowid 可搜, 恰 1 条 (不重复)"
        );

        // (3) DELETE → 触发器删 FTS 项。
        conn.execute("DELETE FROM message WHERE source_native_id='Msg_a:1'", [])
            .unwrap();
        assert!(
            search_messages(&conn, "吃烧烤", 10, None).unwrap().is_empty(),
            "删消息 → FTS 项随 AFTER DELETE 触发器删"
        );

        // (4) 无悬空不变量: FTS 索引行数 == message 行数。
        insert_message(&conn, &mk("Msg_a:2", "另一条测试消息内容")).unwrap();
        insert_message(&conn, &mk("Msg_a:3", "第三条消息随便写点")).unwrap();
        let msg_n: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        let fts_n: i64 = conn
            .query_row("SELECT count(*) FROM message_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(msg_n, fts_n, "FTS 行数 == message 行数 (触发器维护无悬空/无漏)");
    }

    /// R9 件1: drop 触发器后停止自动维护 (build/全量 ingest 前禁触发器 → 一次性 rebuild 的前提)。
    #[test]
    fn fts_triggers_drop_stops_maintenance() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        init_message_fts_triggers(&conn).unwrap();
        assert!(message_fts_triggers_exist(&conn), "建后三触发器都在");
        drop_message_fts_triggers(&conn).unwrap();
        assert!(!message_fts_triggers_exist(&conn), "drop 后不在");
        // drop 后新插不进 FTS (需手动 rebuild 才有)。
        let mk = |id: &str, text: &str| V3Message {
            text_content: text.to_string(),
            ..sample_msg(id, 1)
        };
        insert_message(&conn, &mk("Msg_a:9", "禁触发器后插入的消息")).unwrap();
        assert!(
            search_messages(&conn, "禁触发器", 10, None).unwrap().is_empty(),
            "drop 触发器后新插未进 FTS (走 FTS 路但该行未索引)"
        );
    }

    /// R9 件2: thin 独立瘦 FTS —— 插 + 搜 (MATCH + snippet 回连 msg_id) + 同 rowid 幂等 (重插覆盖不重复)。
    #[test]
    fn thin_fts_insert_search_idempotent() {
        let (_d, conn) = open_inited();
        init_thin_fts(&conn).unwrap();
        let src = "message_0.db";
        insert_thin_msg(&conn, 1, src, "Msg_a:1", "今天一起吃火锅很开心").unwrap();
        insert_thin_msg(&conn, 2, src, "Msg_a:2", "明天去爬山看风景").unwrap();
        // 搜 "吃火锅" (3 字 trigram) → 命中 msg 1 + (msg_id, source, snippet) 回连。
        let hits = search_thin(&conn, "吃火锅", 10).unwrap();
        assert_eq!(hits.len(), 1, "'吃火锅' 命中 1 条");
        assert_eq!(hits[0].0, "Msg_a:1", "回连 msg_id");
        assert_eq!(hits[0].1, src, "回连 source 分片");
        assert!(
            hits[0].2.contains("吃火锅") || hits[0].2.contains('['),
            "snippet(列2) 含正文/高亮标记"
        );
        // <3 字 → 空 (trigram 需 ≥3 字; thin 无 LIKE 兜底)。
        assert!(search_thin(&conn, "吃", 10).unwrap().is_empty(), "<3 字空");
        // 同 rowid 重插 (改正文) → 幂等: 旧正文没了, 新正文有, 不重复。
        insert_thin_msg(&conn, 1, src, "Msg_a:1", "改成去逛街买东西").unwrap();
        assert!(
            search_thin(&conn, "吃火锅", 10).unwrap().is_empty(),
            "同 rowid 重插 → 旧正文搜不到"
        );
        assert_eq!(search_thin(&conn, "去逛街", 10).unwrap().len(), 1, "新正文搜到, 不重复");
        let n: i64 = conn
            .query_row("SELECT count(*) FROM thin_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2, "同 rowid 覆盖不增行 (msg1 覆盖 + msg2)");
    }

    /// R18 白盒 P2-1 回归: build 与 daemon **必须用同一 rowid 键** `thin_rowid(锚)` —— 否则先 build 再 daemon
    /// 维护同一瘦库会**整库重复索引** (每条消息两行, 搜每命中出现两次)。此测钉死"同锚→同 rowid→去重",
    /// 并反向证明"键不一致→双行" (若 build 回退用 message.rowid 之类小整数键, 此不变量即被打破 → 测挂)。
    #[test]
    fn thin_build_daemon_same_rowid_key_dedups() {
        use crate::thin::thin_rowid;
        let (_d, conn) = open_inited();
        init_thin_fts(&conn).unwrap();
        let (s0, s1) = ("message_0.db", "message_1.db");
        let anchor = "Msg_0021db3ef9c0aa11bb22cc33dd44ee55:42";
        // build 侧 (main.rs: rowid = thin_rowid(source, source_native_id), source 列亦存 s0)。
        insert_thin_msg(&conn, thin_rowid(s0, anchor), s0, anchor, "一起去公园散步聊天").unwrap();
        // daemon 侧 (thin.rs: rowid = thin_rowid(snapshot.rel_name, msg_anchor) = 同 (source,锚) 同值) 重抽同一消息 → 覆盖不新增。
        insert_thin_msg(&conn, thin_rowid(s0, anchor), s0, anchor, "一起去公园散步聊天").unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM thin_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 1,
            "build+daemon 同 (source,锚) 同 rowid → 去重, 整库不重复索引 (P2-1)"
        );
        assert_eq!(
            search_thin(&conn, "去公园", 10).unwrap().len(),
            1,
            "搜每命中恰一次, 不双行"
        );
        // **codex 复审 P1 回归**: 同一 source_native_id 在不同源分片 (message_0 vs message_1) 是**相异消息**
        // (各分片 local_id 独立; L1 PK 含 source)。键含 source → 不同 rowid → 两条都进索引都可搜。
        // 若键漏 source(退回只按锚), 后插 DELETE 覆盖前者 → 丢消息, n2 会是 1 且分片0消息搜不到 → 此测挂。
        insert_thin_msg(&conn, thin_rowid(s1, anchor), s1, anchor, "另一分片同锚的不同消息内容").unwrap();
        let n2: i64 = conn
            .query_row("SELECT count(*) FROM thin_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n2, 2,
            "跨分片同锚 → 不同 rowid → 两条都在 (codex P1: 键必含 source 分片)"
        );
        assert_eq!(
            search_thin(&conn, "去公园", 10).unwrap().len(),
            1,
            "分片0消息仍在, 未被分片1覆盖"
        );
        assert_eq!(
            search_thin(&conn, "另一分片", 10).unwrap().len(),
            1,
            "分片1消息也在, 两条独立可搜"
        );
        // codex P2: 结果带 source → 跨分片同锚两条可按 source 区分。搜共有词, 两条都命中且 source 不同。
        let both = search_thin(&conn, "散步聊天", 10).unwrap();
        let s1_hit = search_thin(&conn, "不同消息", 10).unwrap();
        assert_eq!(both.len(), 1, "分片0 独有词命中1条");
        assert_eq!(both[0].1, s0, "命中回连 source=分片0");
        assert_eq!(s1_hit.len(), 1, "分片1 独有词命中1条");
        assert_eq!(s1_hit[0].1, s1, "命中回连 source=分片1 (同锚两条靠 source 区分)");
    }

    /// codex 复审 P1 回归: rowkey 版本守卫 —— 旧 schema (v1: msg_id+text 无 source 列) 的瘦库, 开库维护前
    /// **DROP+重建**新 schema (带 source) + 抹水位 + 标版本。**只清行不够**: `CREATE IF NOT EXISTS` 加不了 source
    /// 列 → 清行后带 source 的 insert/search 全 "no such column"。fresh 新 schema 库不误 drop。
    #[test]
    fn thin_rowkey_version_guard_clears_stale_index() {
        use crate::thin::thin_rowid;
        let (_d, conn) = open_inited();
        init_thin_meta(&conn).unwrap();
        // 造"旧 v1 库": thin_fts 是**旧 schema (msg_id, text, 无 source)** + 有行 + 有水位 + 无版本标记。
        conn.execute_batch("CREATE VIRTUAL TABLE thin_fts USING fts5(msg_id UNINDEXED, text, tokenize='trigram');")
            .unwrap();
        conn.execute(
            "INSERT INTO thin_fts(rowid, msg_id, text) VALUES (1, 'Msg_a:1', '旧方案索引内容')",
            [],
        )
        .unwrap();
        set_thin_watermark(&conn, r#"{"message_0.db|MSG":5}"#).unwrap();
        assert!(get_thin_rowkey_version(&conn).unwrap().is_none(), "旧库无版本标记");
        // 守卫: 旧 schema (无 source 列) → DROP+重建新 schema + 抹水位 + 标版本, 返 true。
        assert!(
            ensure_thin_rowkey_current(&conn).unwrap(),
            "旧 schema 库应被 DROP 重建 (返 true)"
        );
        // 重建后 thin_fts 有 source 列 → 带 source 的 insert 成功 (旧 schema 会 "no such column: source" 挂)。
        insert_thin_msg(
            &conn,
            thin_rowid("message_0.db", "Msg_b:2"),
            "message_0.db",
            "Msg_b:2",
            "新方案内容",
        )
        .unwrap();
        assert_eq!(
            search_thin(&conn, "新方案", 10).unwrap().len(),
            1,
            "重建后新 schema 可插可搜, 回连 source"
        );
        assert!(search_thin(&conn, "旧方案", 10).unwrap().is_empty(), "旧行随 DROP 清掉");
        assert!(get_thin_watermark(&conn).unwrap().is_none(), "水位已抹 → 从头全抽");
        assert_eq!(
            get_thin_rowkey_version(&conn).unwrap().as_deref(),
            Some(THIN_ROWKEY_VERSION),
            "已标当前版本"
        );
        // 再 ensure (版本已当前) → 不动, 返 false (幂等); 已灌行不被误清。
        assert!(
            !ensure_thin_rowkey_current(&conn).unwrap(),
            "版本已当前 → 不重建 (返 false)"
        );
        assert_eq!(search_thin(&conn, "新方案", 10).unwrap().len(), 1, "当前版本库不被误清");

        // fresh 新 schema 库 (init 就带 source, 仅无版本标记) → **不 drop** (schema 已新), 仅补标版本, 返 false。
        let (_d2, c2) = open_inited();
        init_thin_fts(&c2).unwrap(); // 新 schema (带 source)。
        init_thin_meta(&c2).unwrap();
        assert!(
            !ensure_thin_rowkey_current(&c2).unwrap(),
            "fresh 新 schema 库不重建 (已带 source)"
        );
        assert_eq!(
            get_thin_rowkey_version(&c2).unwrap().as_deref(),
            Some(THIN_ROWKEY_VERSION),
            "fresh 库也标版本"
        );

        // **② facet (Claude 末轮附加洞) 回归**: 同 schema 但 rowkey 版本升级 (未来 v2→v3 只改 hash 不改列)。
        // schema 有 source (不旧) 但版本标成旧 + 有行 → 必**清行**重灌, 否则旧 hash 行与新 hash 行并存重复倒排。
        // (若判据只看 schema, 此路会漏清 → 测挂。)
        let (_d3, c3) = open_inited();
        init_thin_fts(&c3).unwrap(); // 新 schema (带 source)。
        init_thin_meta(&c3).unwrap();
        insert_thin_msg(
            &c3,
            thin_rowid("message_0.db", "Msg_x:1"),
            "message_0.db",
            "Msg_x:1",
            "旧hash方案残留行",
        )
        .unwrap();
        set_thin_rowkey_version(&c3, "1").unwrap(); // 标成旧版本号 (模拟同 schema 的版本升级前)。
        set_thin_watermark(&c3, r#"{"message_0.db|MSG":9}"#).unwrap();
        assert!(
            ensure_thin_rowkey_current(&c3).unwrap(),
            "schema新但版本旧+有行 → 清行 (返 true, 别漏)"
        );
        assert!(
            search_thin(&c3, "旧hash", 10).unwrap().is_empty(),
            "旧 hash 行已清 (防同 schema 版本升级重复倒排)"
        );
        assert!(
            get_thin_watermark(&c3).unwrap().is_none(),
            "水位已抹 → 从头按当前 hash 全重灌"
        );
        assert_eq!(
            get_thin_rowkey_version(&c3).unwrap().as_deref(),
            Some(THIN_ROWKEY_VERSION),
            "标当前版本"
        );
    }

    /// R9 件6: FTS 段合并 optimize (message_fts + thin_fts) 不崩 + 索引仍可搜。
    #[test]
    fn fts_optimize_no_crash_still_searchable() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        init_message_fts_triggers(&conn).unwrap();
        let mk = |id: &str, text: &str| V3Message {
            text_content: text.to_string(),
            ..sample_msg(id, 1)
        };
        for i in 0..5 {
            insert_message(&conn, &mk(&format!("Msg_a:{i}"), "今天吃火锅很开心")).unwrap();
        }
        optimize_message_fts(&conn).unwrap(); // 段合并不崩。
        assert_eq!(
            search_messages(&conn, "吃火锅", 10, None).unwrap().len(),
            5,
            "message_fts optimize 后仍可搜"
        );
        // thin optimize。
        init_thin_fts(&conn).unwrap();
        insert_thin_msg(&conn, 1, "message_0.db", "Msg_a:1", "另一条测试消息内容").unwrap();
        optimize_thin_fts(&conn).unwrap();
        assert_eq!(
            search_thin(&conn, "测试消息", 10).unwrap().len(),
            1,
            "thin_fts optimize 后仍可搜"
        );
    }

    /// message 建表 + 插入回查关键字段.
    #[test]
    fn message_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        insert_message(&conn, &sample_msg("Msg_a:1", 2)).unwrap();
        let (conv_sha, mtype, len, sub, sseq): (String, i64, i64, Option<i64>, i64) = conn
            .query_row(
                "SELECT conv_id_sha, msg_type, text_content_len, msg_sub_type, server_seq FROM message WHERE source_native_id='Msg_a:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(conv_sha, "conv_sha");
        assert_eq!(mtype, 1);
        assert_eq!(len, 12);
        assert_eq!(sub, Some(0));
        assert_eq!(sseq, 100, "server_seq 落库回查 (sample_msg 填 100)");
    }

    /// upsert: 同 PK (account,source,native_id) 重写 → 不增行 + status 刷新.
    #[test]
    fn message_upsert_same_pk_refreshes() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        insert_message(&conn, &sample_msg("Msg_a:1", 1)).unwrap();
        insert_message(&conn, &sample_msg("Msg_a:1", 9)).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 PK upsert 不增行");
        let status: i64 = conn.query_row("SELECT status FROM message", [], |r| r.get(0)).unwrap();
        assert_eq!(status, 9, "status 刷新到新值");
    }

    /// nullable msg_sub_type/name None → NULL 回查 None.
    #[test]
    fn message_nullable_fields() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        let mut m = sample_msg("Msg_b:1", 1);
        m.msg_sub_type = None;
        m.msg_sub_type_name = None;
        insert_message(&conn, &m).unwrap();
        let (sub, subname): (Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT msg_sub_type, msg_sub_type_name FROM message WHERE source_native_id='Msg_b:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sub, None);
        assert_eq!(subname, None);
    }

    /// bool 列 (is_chatroom / raw_xml_present) true→1→true round-trip (codex r1 P2).
    #[test]
    fn message_bool_columns_round_trip() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        let mut m = sample_msg("Msg_c:1", 1);
        m.is_chatroom = true;
        m.raw_xml_present = true;
        insert_message(&conn, &m).unwrap();
        let (is_chatroom, raw_xml): (bool, bool) = conn
            .query_row(
                "SELECT is_chatroom, raw_xml_present FROM message WHERE source_native_id='Msg_c:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(is_chatroom, "true→1→true");
        assert!(raw_xml);
        // 28 列 (原 19 + ADR-426 明文列 4 + server_seq 批A + sys_type 批F + origin_source/upload_status/download_status)
        let col_count: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('message')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            col_count, 28,
            "message 表 28 列 (含 server_seq 批A + sys_type 批F + origin/upload/download_status)"
        );
    }

    /// 批A/F codex P2 + 本批: 旧 23 列 message 表 (无 server_seq/sys_type/origin_source/upload_status/
    /// download_status) → init_message_table 自动 ALTER 补 5 列 = 28; 旧行 server_seq/origin/upload/download
    /// 默认 0 / sys_type NULL; 新 insert 成功回查正确。锁死 ensure_message_columns 迁移。
    #[test]
    fn old_23col_message_migrates_server_seq() {
        let (_d, conn) = open_inited();
        // 旧 schema = 当前 24 列去掉 server_seq (19 原始 + ADR-426 明文 4)。
        conn.execute_batch(
            "CREATE TABLE message (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                conv_id_sha TEXT NOT NULL, server_id INTEGER NOT NULL, create_time INTEGER NOT NULL,
                sort_seq INTEGER NOT NULL, status INTEGER NOT NULL, msg_type INTEGER NOT NULL,
                msg_type_name TEXT NOT NULL, msg_sub_type INTEGER, msg_sub_type_name TEXT,
                local_type_raw INTEGER NOT NULL, sender_wxid_sha TEXT NOT NULL, is_chatroom INTEGER NOT NULL,
                text_content_sha TEXT NOT NULL, text_content_len INTEGER NOT NULL, raw_xml_present INTEGER NOT NULL,
                decode_kind TEXT NOT NULL, account_id TEXT NOT NULL, conv_id TEXT NOT NULL,
                sender_wxid TEXT NOT NULL, text_content TEXT NOT NULL,
                PRIMARY KEY (account_id_sha, source, source_native_id))",
        )
        .unwrap();
        // 旧库先塞一行 (23 列, 无 server_seq)。
        conn.execute(
            "INSERT INTO message (account_id_sha, source, source_native_id, conv_id_sha, server_id,
                create_time, sort_seq, status, msg_type, msg_type_name, local_type_raw, sender_wxid_sha,
                is_chatroom, text_content_sha, text_content_len, raw_xml_present, decode_kind,
                account_id, conv_id, sender_wxid, text_content)
             VALUES ('acct','m.db','Msg_old:1','conv',111,1,1,1,1,'TEXT',1,'snd',0,'tc',3,0,'plain','a','c','s','hi')",
            [],
        )
        .unwrap();
        init_message_table(&conn).unwrap(); // 应 ALTER 补 server_seq + sys_type + origin/upload/download_status
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('message')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            cols, 28,
            "旧 23 列 → ALTER 补 5 列 (server_seq/sys_type/origin/upload/download) = 28"
        );
        // 旧行 server_seq/origin/upload/download 默认 0 (ALTER ADD ... DEFAULT 0 回填); sys_type NULL (nullable, 无 default)。
        let (old_seq, old_sys, old_origin, old_up, old_down): (i64, Option<String>, i64, i64, i64) = conn
            .query_row(
                "SELECT server_seq, sys_type, origin_source, upload_status, download_status \
                 FROM message WHERE source_native_id='Msg_old:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(old_seq, 0, "旧行 server_seq DEFAULT 0 回填");
        assert_eq!(old_sys, None, "旧行 sys_type NULL");
        assert_eq!(
            (old_origin, old_up, old_down),
            (0, 0, 0),
            "旧行 origin/upload/download_status DEFAULT 0 回填"
        );
        // 新 insert (28 列, server_seq=826 + origin/upload/download=11/22/33) 成功且回查正确。
        let mut m = sample_msg("Msg_new:1", 1);
        m.server_seq = 826;
        m.origin_source = 11;
        m.upload_status = 22;
        m.download_status = 33;
        insert_message(&conn, &m).unwrap();
        let (new_seq, new_origin, new_up, new_down): (i64, i64, i64, i64) = conn
            .query_row(
                "SELECT server_seq, origin_source, upload_status, download_status \
                 FROM message WHERE source_native_id='Msg_new:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(new_seq, 826, "旧库补列后新 insert server_seq 落库正确");
        assert_eq!(
            (new_origin, new_up, new_down),
            (11, 22, 33),
            "旧库补列后新 insert origin/upload/download 落库正确"
        );
    }

    /// ADR-426 明文列 DB roundtrip — insert → 查回明文列, 卡死 DDL/insert/列顺序错配 (codex r1 P2)。
    #[test]
    fn message_plaintext_columns_round_trip() {
        let (_d, conn) = open_inited();
        init_message_table(&conn).unwrap();
        let mut m = sample_msg("Msg_p:1", 1);
        m.account_id = "wxid_real_acct".to_string();
        m.conv_id = "wxid_real_conv".to_string();
        m.sender_wxid = "wxid_real_sender".to_string();
        m.text_content = "真实正文内容".to_string();
        insert_message(&conn, &m).unwrap();
        let (r_acct, r_conv, r_sender, r_text): (String, String, String, String) = conn
            .query_row(
                "SELECT account_id, conv_id, sender_wxid, text_content FROM message WHERE source_native_id='Msg_p:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(r_acct, "wxid_real_acct");
        assert_eq!(r_conv, "wxid_real_conv");
        assert_eq!(r_sender, "wxid_real_sender");
        assert_eq!(r_text, "真实正文内容", "聊天正文明文列查回一致");
    }

    // ── L2 person 表 ──

    fn sample_person(native_id: &str, remark_len: i64) -> V3Person {
        V3Person {
            account_id_sha: "acct_sha".to_string(),
            source: "contact.db".to_string(),
            source_native_id: native_id.to_string(),
            username_sha: "user_sha".to_string(),
            account_id: "wxid_acct".to_string(),
            username: "wxid_user".to_string(),
            nick_name: "小明".to_string(),
            remark: Some("备注甲".to_string()),
            alias: None,
            nick_name_len: 6,
            remark_len,
            alias_len: 3,
            local_type: 1,
            is_in_chat_room: false,
            quan_pin: None,
            pin_yin_initial: None,
            remark_quan_pin: None,
            remark_pin_yin_initial: None,
            verify_flag: 0,
            delete_flag: 0,
            big_head_url: None,
            small_head_url: None,
            head_img_md5: None,
            description: None,
            flag: 0,
            chat_room_notify: 0,
            chat_room_type: 0,
            sex: 0,
            country: None,
            province: None,
            city: None,
            friend_source: 0,
            is_starred: false,
            is_collapsed: false,
            is_pinned: false,
            blocks_moments: false,
            hide_their_moments: false,
            chat_only: false,
            is_muted: false,
            signature: None,
            moments_cover_url: None,
            labels: None,
            friend_add_time: None,
            openim_company: None,
            openim_realname: None,
        }
    }

    /// person 建表 + 插入回查关键字段.
    #[test]
    fn person_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        insert_person(&conn, &sample_person("wxid_a", 4)).unwrap();
        let (user_sha, nick_len, ltype): (String, i64, i64) = conn
            .query_row(
                "SELECT username_sha, nick_name_len, local_type FROM person WHERE source_native_id='wxid_a'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(user_sha, "user_sha");
        assert_eq!(nick_len, 6);
        assert_eq!(ltype, 1);
    }

    /// 同 PK upsert (INSERT OR REPLACE): 不增行 + remark_len 刷新 (改备注重解码).
    #[test]
    fn person_upsert_same_pk_refreshes() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        insert_person(&conn, &sample_person("wxid_a", 4)).unwrap();
        insert_person(&conn, &sample_person("wxid_a", 9)).unwrap();
        let count: i64 = conn.query_row("SELECT count(*) FROM person", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "同 PK upsert 不增行");
        let remark: i64 = conn
            .query_row(
                "SELECT remark_len FROM person WHERE source_native_id='wxid_a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remark, 9, "remark_len 刷新 4→9");
    }

    /// is_in_chat_room bool true→1→true round-trip + person 表恰 42 列.
    #[test]
    fn person_bool_and_column_count() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_b", 2);
        p.is_in_chat_room = true;
        insert_person(&conn, &p).unwrap();
        let in_room: bool = conn
            .query_row(
                "SELECT is_in_chat_room FROM person WHERE source_native_id='wxid_b'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(in_room, "true→1→true");
        let col_count: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('person')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(col_count, 45, "person 表 45 列 (14 + 4 拼音 + 2 状态标志 + 3 头像 + 4 第五批 + 5 第七批 + 5 批G flag 位解码(含不看她 hide_their_moments ADR-503) + 1 免打扰 + 2 批 I + 1 is_collapsed ADR-479 + 1 标签件 labels + 1 添加时间 ADR-486 + 2 企微件 openim_company/realname)");
    }

    /// 字段扩充第一批 (codex P2-1 回查 + P1-2 验证): 拼音落库回查 + 重投 REPLACE 刷新。
    /// **P1-2 回应**: person 是无条件 `INSERT OR REPLACE` (sink 里 archive 去重与 L2 投影解耦) →
    /// contact 全表重扫每轮都 REPLACE 带最新拼音, 即使 nick 未变/archive digest 重复也不陈旧。
    #[test]
    fn person_pinyin_roundtrip_and_replace() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_pinyin", 2);
        p.quan_pin = Some("xiaoming".to_string());
        p.pin_yin_initial = Some("XM".to_string());
        insert_person(&conn, &p).unwrap();
        let (qp, py): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT quan_pin, pin_yin_initial FROM person WHERE source_native_id='wxid_pinyin'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(qp.as_deref(), Some("xiaoming"), "拼音落库回查");
        assert_eq!(py.as_deref(), Some("XM"));
        // 重投带新拼音 (模拟 nick 未变但拼音源字段变) → REPLACE 无条件刷新, 不陈旧。
        p.quan_pin = Some("xiaomingming".to_string());
        insert_person(&conn, &p).unwrap();
        let qp2: Option<String> = conn
            .query_row(
                "SELECT quan_pin FROM person WHERE source_native_id='wxid_pinyin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            qp2.as_deref(),
            Some("xiaomingming"),
            "重投 REPLACE 刷新拼音 (P1-2: 不陈旧)"
        );
    }

    /// 字段扩充第二批 (2026-07-01): verify_flag/delete_flag 落库回查 (INTEGER 元数据 round-trip)。
    #[test]
    fn person_verify_delete_flag_roundtrip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_flag", 2);
        p.verify_flag = 2;
        p.delete_flag = 1;
        insert_person(&conn, &p).unwrap();
        let (vf, df): (i64, i64) = conn
            .query_row(
                "SELECT verify_flag, delete_flag FROM person WHERE source_native_id='wxid_flag'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(vf, 2, "verify_flag 落库回查");
        assert_eq!(df, 1, "delete_flag 落库回查");
    }

    /// 字段扩充第三批 (2026-07-02): 头像 3 列落库回查 (TEXT nullable)。
    #[test]
    fn person_head_columns_roundtrip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_head", 2);
        p.big_head_url = Some("https://wx.qlogo.cn/x/0".to_string());
        p.small_head_url = None;
        p.head_img_md5 = Some("abc123".to_string());
        insert_person(&conn, &p).unwrap();
        let (big, small, md5): (Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT big_head_url, small_head_url, head_img_md5 FROM person WHERE source_native_id='wxid_head'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(big.as_deref(), Some("https://wx.qlogo.cn/x/0"), "big_head_url 落库回查");
        assert_eq!(small, None, "small_head_url None → NULL");
        assert_eq!(md5.as_deref(), Some("abc123"), "head_img_md5 落库回查");
    }

    /// 字段扩充第五批 (2026-07-02): description/flag/chat_room_notify/chat_room_type 落库回查。
    #[test]
    fn person_batch5_columns_roundtrip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_b5", 2);
        p.description = Some("个性签名".to_string());
        p.flag = 5;
        p.chat_room_notify = 1;
        p.chat_room_type = 2;
        insert_person(&conn, &p).unwrap();
        let (desc, flag, notify, rtype): (Option<String>, i64, i64, i64) = conn
            .query_row(
                "SELECT description, flag, chat_room_notify, chat_room_type FROM person WHERE source_native_id='wxid_b5'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(desc.as_deref(), Some("个性签名"), "description 落库回查");
        assert_eq!(flag, 5, "flag 落库回查");
        assert_eq!(notify, 1);
        assert_eq!(rtype, 2);
    }

    /// 字段扩充第七批 (2026-07-02): sex/country/province/city/friend_source 落库回查。
    #[test]
    fn person_batch7_columns_roundtrip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_b7", 2);
        p.sex = 2;
        p.country = Some("CN".to_string());
        p.province = Some("Zhejiang".to_string());
        p.city = Some("Hangzhou".to_string());
        p.friend_source = 3;
        insert_person(&conn, &p).unwrap();
        let (sex, country, province, city, src): (i64, Option<String>, Option<String>, Option<String>, i64) = conn
            .query_row(
                "SELECT sex, country, province, city, friend_source FROM person WHERE source_native_id='wxid_b7'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(sex, 2, "sex 落库回查");
        assert_eq!(country.as_deref(), Some("CN"));
        assert_eq!(province.as_deref(), Some("Zhejiang"));
        assert_eq!(city.as_deref(), Some("Hangzhou"));
        assert_eq!(src, 3, "friend_source 落库回查");
    }

    /// 字段扩充批 I (2026-07-04): signature/moments_cover_url 落库回查 (TEXT nullable)。
    #[test]
    fn person_batch_i_columns_roundtrip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_b8", 2);
        p.signature = Some("做自己 不太好也没关系".to_string());
        p.moments_cover_url = Some("http://shmmsns.qpic.cn/mmsns/xxx/0".to_string());
        insert_person(&conn, &p).unwrap();
        let (sig, cover): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT signature, moments_cover_url FROM person WHERE source_native_id='wxid_b8'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sig.as_deref(), Some("做自己 不太好也没关系"), "signature 落库回查");
        assert_eq!(
            cover.as_deref(),
            Some("http://shmmsns.qpic.cn/mmsns/xxx/0"),
            "moments_cover_url 落库回查"
        );
    }

    /// 标签件: labels 落库回查 (TEXT nullable)。
    #[test]
    fn person_labels_column_roundtrip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_lbl", 2);
        p.labels = Some("老板,客户".to_string());
        insert_person(&conn, &p).unwrap();
        let labels: Option<String> = conn
            .query_row("SELECT labels FROM person WHERE source_native_id='wxid_lbl'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(labels.as_deref(), Some("老板,客户"), "labels 落库回查");
    }

    /// 添加时间件 (ADR-486): friend_add_time 真值 + NULL 双向往返落库回查。
    #[test]
    fn person_friend_add_time_roundtrip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        // 真值 (小胡7 1698674704 = 2023-10-30)。
        let mut p = sample_person("wxid_at", 2);
        p.friend_add_time = Some(1_698_674_704);
        insert_person(&conn, &p).unwrap();
        let at: Option<i64> = conn
            .query_row(
                "SELECT friend_add_time FROM person WHERE source_native_id='wxid_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(at, Some(1_698_674_704), "friend_add_time 真值落库回查");
        // NULL (老版本/未回填) — sample_person 默认 None。
        insert_person(&conn, &sample_person("wxid_none", 2)).unwrap();
        let none_at: Option<i64> = conn
            .query_row(
                "SELECT friend_add_time FROM person WHERE source_native_id='wxid_none'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(none_at, None, "无 f41 → NULL (非 0 哨兵)");
    }

    /// codex P1-1/P2-2: 旧 14 列 person 表, init_person_table 自动 ALTER 补 4 拼音 + 3 头像 + 2 状态标志列, 再 insert 23 列成功。
    #[test]
    fn old_person_schema_migrates_pinyin_columns() {
        let (_d, conn) = open_inited();
        conn.execute_batch(
            "CREATE TABLE person (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                username_sha TEXT NOT NULL, account_id TEXT NOT NULL, username TEXT NOT NULL,
                nick_name TEXT NOT NULL, remark TEXT, alias TEXT, nick_name_len INTEGER NOT NULL,
                remark_len INTEGER NOT NULL, alias_len INTEGER NOT NULL, local_type INTEGER NOT NULL,
                is_in_chat_room INTEGER NOT NULL,
                PRIMARY KEY (account_id_sha, source, username_sha))",
        )
        .unwrap();
        init_person_table(&conn).unwrap(); // 应 ALTER 补 4 列
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('person')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 45, "旧 14 列 → ALTER 补 4 拼音 + 3 头像 + 2 状态标志 + 4 第五批 + 5 第七批 + 5 批G(含不看她) + 1 免打扰 + 2 批 I + is_collapsed(ADR-479) + 1 labels + 1 添加时间(ADR-486) + 2 企微件 = 45");
        let mut p = sample_person("wxid_mig", 2);
        p.quan_pin = Some("migrated".to_string());
        insert_person(&conn, &p).unwrap(); // 不报 no column
        let qp: Option<String> = conn
            .query_row(
                "SELECT quan_pin FROM person WHERE source_native_id='wxid_mig'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(qp.as_deref(), Some("migrated"), "旧库补列后 insert 拼音成功");
    }

    /// codex P2 (第三批): 旧 20 列库 (第二批 14+4拼音+2flag) → ensure 补 3 头像 = 23; insert 头像成功。
    #[test]
    fn old_20col_person_migrates_head_columns() {
        let (_d, conn) = open_inited();
        conn.execute_batch(
            "CREATE TABLE person (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                username_sha TEXT NOT NULL, account_id TEXT NOT NULL, username TEXT NOT NULL,
                nick_name TEXT NOT NULL, remark TEXT, alias TEXT, nick_name_len INTEGER NOT NULL,
                remark_len INTEGER NOT NULL, alias_len INTEGER NOT NULL, local_type INTEGER NOT NULL,
                is_in_chat_room INTEGER NOT NULL,
                quan_pin TEXT, pin_yin_initial TEXT, remark_quan_pin TEXT, remark_pin_yin_initial TEXT,
                verify_flag INTEGER NOT NULL DEFAULT 0, delete_flag INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (account_id_sha, source, username_sha))",
        )
        .unwrap();
        init_person_table(&conn).unwrap(); // 应 ALTER 补 3 头像列
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('person')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 45, "旧 20 列 → ALTER 补 3 头像 + 4 第五批 + 5 第七批 + 5 批G(含不看她) + 1 免打扰 + 2 批 I + is_collapsed(ADR-479) + 1 labels + 1 添加时间(ADR-486) + 2 企微件 = 45");
        let mut p = sample_person("wxid_mig2", 2);
        p.big_head_url = Some("https://wx.qlogo.cn/x/0".to_string());
        insert_person(&conn, &p).unwrap(); // 不报 no column
        let big: Option<String> = conn
            .query_row(
                "SELECT big_head_url FROM person WHERE source_native_id='wxid_mig2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            big.as_deref(),
            Some("https://wx.qlogo.cn/x/0"),
            "旧 20 列库补头像后 insert 成功"
        );
    }

    /// 第五批: 旧 23 列库 (14+4拼音+2flag+3头像) → ensure 补 4 第五批列 = 27; insert 成功。
    #[test]
    fn old_23col_person_migrates_batch5_columns() {
        let (_d, conn) = open_inited();
        conn.execute_batch(
            "CREATE TABLE person (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                username_sha TEXT NOT NULL, account_id TEXT NOT NULL, username TEXT NOT NULL,
                nick_name TEXT NOT NULL, remark TEXT, alias TEXT, nick_name_len INTEGER NOT NULL,
                remark_len INTEGER NOT NULL, alias_len INTEGER NOT NULL, local_type INTEGER NOT NULL,
                is_in_chat_room INTEGER NOT NULL,
                quan_pin TEXT, pin_yin_initial TEXT, remark_quan_pin TEXT, remark_pin_yin_initial TEXT,
                verify_flag INTEGER NOT NULL DEFAULT 0, delete_flag INTEGER NOT NULL DEFAULT 0,
                big_head_url TEXT, small_head_url TEXT, head_img_md5 TEXT,
                PRIMARY KEY (account_id_sha, source, username_sha))",
        )
        .unwrap();
        init_person_table(&conn).unwrap(); // 应 ALTER 补 4 第五批列
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('person')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 45, "旧 23 列 → ALTER 补 4 第五批 + 5 第七批 + 5 批G(含不看她) + 1 免打扰 + 2 批 I + is_collapsed(ADR-479) + 1 labels + 1 添加时间(ADR-486) + 2 企微件 = 45");
        let mut p = sample_person("wxid_mig5", 2);
        p.description = Some("签名".to_string());
        p.flag = 7;
        insert_person(&conn, &p).unwrap(); // 不报 no column
        let (desc, flag): (Option<String>, i64) = conn
            .query_row(
                "SELECT description, flag FROM person WHERE source_native_id='wxid_mig5'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(desc.as_deref(), Some("签名"), "旧 23 列库补第五批后 insert 成功");
        assert_eq!(flag, 7);
    }

    /// 第七批: 旧 27 列库 (第五批版) → ensure 补 5 第七批列 = 32; insert 成功。
    #[test]
    fn old_27col_person_migrates_batch7_columns() {
        let (_d, conn) = open_inited();
        conn.execute_batch(
            "CREATE TABLE person (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                username_sha TEXT NOT NULL, account_id TEXT NOT NULL, username TEXT NOT NULL,
                nick_name TEXT NOT NULL, remark TEXT, alias TEXT, nick_name_len INTEGER NOT NULL,
                remark_len INTEGER NOT NULL, alias_len INTEGER NOT NULL, local_type INTEGER NOT NULL,
                is_in_chat_room INTEGER NOT NULL,
                quan_pin TEXT, pin_yin_initial TEXT, remark_quan_pin TEXT, remark_pin_yin_initial TEXT,
                verify_flag INTEGER NOT NULL DEFAULT 0, delete_flag INTEGER NOT NULL DEFAULT 0,
                big_head_url TEXT, small_head_url TEXT, head_img_md5 TEXT,
                description TEXT, flag INTEGER NOT NULL DEFAULT 0,
                chat_room_notify INTEGER NOT NULL DEFAULT 0, chat_room_type INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (account_id_sha, source, username_sha))",
        )
        .unwrap();
        init_person_table(&conn).unwrap(); // 应 ALTER 补 5 第七批列
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('person')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 45, "旧 27 列 → ALTER 补 5 第七批 + 5 批G(含不看她) + 1 免打扰 + 2 批 I + 1 is_collapsed(ADR-479) + 1 labels + 1 添加时间(ADR-486) + 2 企微件 = 45");
        let mut p = sample_person("wxid_mig7", 2);
        p.sex = 2;
        p.province = Some("Zhejiang".to_string());
        insert_person(&conn, &p).unwrap(); // 不报 no column
        let (sex, prov): (i64, Option<String>) = conn
            .query_row(
                "SELECT sex, province FROM person WHERE source_native_id='wxid_mig7'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sex, 2, "旧 27 列库补第七批后 insert 成功");
        assert_eq!(prov.as_deref(), Some("Zhejiang"));
    }

    /// 8hex 锚点撞车: 两个不同联系人 md5 前 8 位恰好相同 → source_native_id 相同,
    /// 但 username_sha 不同 (全长 sha 不撞). PK 用 username_sha 后两行并存, 不再互相覆盖丢人.
    /// (此测试在旧 PK=source_native_id 下会 FAIL: b 覆盖 a, count=1.)
    #[test]
    fn person_anchor_collision_keeps_both() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut a = sample_person("Contact_dead", 4);
        a.username_sha = "user_a_sha".to_string();
        let mut b = sample_person("Contact_dead", 7); // 同 source_native_id (8hex 撞)
        b.username_sha = "user_b_sha".to_string(); // 不同 username_sha
        insert_person(&conn, &a).unwrap();
        insert_person(&conn, &b).unwrap();
        let count: i64 = conn.query_row("SELECT count(*) FROM person", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 2, "锚点撞车两个联系人都保留 (PK=username_sha 不撞)");
    }

    /// ADR-426 明文列 DB roundtrip — insert → 查回明文列, 卡死 DDL/insert/列顺序错配 (codex r1 P2)。
    #[test]
    fn person_plaintext_columns_round_trip() {
        let (_d, conn) = open_inited();
        init_person_table(&conn).unwrap();
        let mut p = sample_person("wxid_a", 4);
        p.account_id = "wxid_real_acct".to_string();
        p.username = "wxid_real_user".to_string();
        p.nick_name = "真实昵称".to_string();
        p.remark = Some("真实备注".to_string());
        insert_person(&conn, &p).unwrap();
        let (acc, user, nick, remark): (String, String, String, Option<String>) = conn
            .query_row(
                "SELECT account_id, username, nick_name, remark FROM person WHERE username_sha='user_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(acc, "wxid_real_acct");
        assert_eq!(user, "wxid_real_user");
        assert_eq!(nick, "真实昵称");
        assert_eq!(remark.as_deref(), Some("真实备注"));
    }

    // ── L2 favorite 收藏表 (ADR-454) ──

    fn sample_favorite(native_id: &str, server_id: i64, fav_type: i64) -> V3Favorite {
        V3Favorite {
            account_id_sha: "acct_sha".to_string(),
            source: "favorite.db".to_string(),
            source_native_id: native_id.to_string(),
            server_id,
            local_id: 156,
            fav_type,
            update_time: 1_779_354_334,
            from_user_sha: "fromusr_sha".to_string(),
            account_id: "wxid_acct".to_string(),
            from_user: "wxid_source".to_string(),
            real_chat_name: Some("wxid_realsender".to_string()),
            source_id: Some("hash_abc".to_string()),
            content_len: 2048,
            note_text: if fav_type == 18 {
                Some("笔记正文示例".to_string())
            } else {
                None
            },
        }
    }

    /// favorite 建表 + 插入回查骨架字段 (ADR-454)。
    #[test]
    fn favorite_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_favorite_table(&conn).unwrap();
        insert_favorite(&conn, &sample_favorite("Favorite_156", 329, 14)).unwrap();
        let (sid, ftype, ut, fromusr, realchat, srcid, clen): (
            i64,
            i64,
            i64,
            String,
            Option<String>,
            Option<String>,
            i64,
        ) = conn
            .query_row(
                "SELECT server_id, fav_type, update_time, from_user, real_chat_name, source_id, content_len \
                 FROM favorite WHERE source_native_id='Favorite_156'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(sid, 329);
        assert_eq!(ftype, 14);
        assert_eq!(ut, 1_779_354_334);
        assert_eq!(fromusr, "wxid_source", "明文 from_user 落库 (ADR-427)");
        assert_eq!(realchat.as_deref(), Some("wxid_realsender"));
        assert_eq!(srcid.as_deref(), Some("hash_abc"));
        assert_eq!(clen, 2048);
    }

    /// favorite upsert: 同 PK 重写 → 不增行 + update_time 刷新 (重打标签). 列数基线 13。
    #[test]
    fn favorite_upsert_and_column_count() {
        let (_d, conn) = open_inited();
        init_favorite_table(&conn).unwrap();
        insert_favorite(&conn, &sample_favorite("Favorite_1", 1, 14)).unwrap();
        let mut f2 = sample_favorite("Favorite_1", 1, 14);
        f2.update_time = 9_999;
        insert_favorite(&conn, &f2).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM favorite", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "同 PK upsert 不增行");
        let ut: i64 = conn
            .query_row(
                "SELECT update_time FROM favorite WHERE source_native_id='Favorite_1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ut, 9_999, "update_time 刷新");
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('favorite')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 14, "favorite 表 14 列 (ADR-454 骨架 13 + ADR-471 note_text)");
    }

    /// K-R4: V3Favorite 持明文但 Debug 脱敏 — 不含裸 from_user/real_chat_name。
    #[test]
    fn favorite_debug_no_raw_leak() {
        let dbg = format!("{:?}", sample_favorite("Favorite_1", 1, 14));
        for raw in ["wxid_source", "wxid_realsender", "wxid_acct"] {
            assert!(!dbg.contains(raw), "K-R4: V3Favorite Debug 含裸值 {raw}");
        }
        assert!(dbg.contains("from_user_sha8"));
    }

    // ── L2 favorite_media 收藏媒体引用表 (ADR-472) ──

    fn sample_fav_media(native_id: &str, seq: i64, md5: &str, dt: i64) -> V3FavoriteMedia {
        V3FavoriteMedia {
            account_id_sha: "acct_sha".to_string(),
            source: "favorite.db".to_string(),
            source_native_id: native_id.to_string(),
            seq,
            fav_server_id: 329,
            account_id: "wxid_acct".to_string(),
            data_type: dt,
            media_md5: md5.to_string(),
            media_size: 12_345,
            data_fmt: Some("jpg".to_string()),
        }
    }

    /// favorite_media 多行(一收藏多媒体)插入回查 + delete 整组 + 列数基线 10 + Debug 不泄 account_id。
    #[test]
    fn favorite_media_multi_row_roundtrip_and_delete() {
        let (_d, conn) = open_inited();
        init_favorite_media_table(&conn).unwrap();
        insert_favorite_media(&conn, &sample_fav_media("Favorite_9", 0, &"a".repeat(32), 2)).unwrap();
        insert_favorite_media(&conn, &sample_fav_media("Favorite_9", 1, &"b".repeat(32), 8)).unwrap();
        insert_favorite_media(&conn, &sample_fav_media("Favorite_7", 0, &"c".repeat(32), 2)).unwrap();
        let n9: i64 = conn
            .query_row(
                "SELECT count(*) FROM favorite_media WHERE source_native_id='Favorite_9'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n9, 2, "一收藏两媒体 → 2 行");
        let (md5, dt): (String, i64) = conn
            .query_row(
                "SELECT media_md5, data_type FROM favorite_media WHERE source_native_id='Favorite_9' AND seq=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(md5, "b".repeat(32));
        assert_eq!(dt, 8);
        // delete 整组 (replace-projection): 只删 Favorite_9, 不动 Favorite_7。
        delete_favorite_media(&conn, "acct_sha", "favorite.db", "Favorite_9").unwrap();
        let after9: i64 = conn
            .query_row(
                "SELECT count(*) FROM favorite_media WHERE source_native_id='Favorite_9'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let after7: i64 = conn
            .query_row(
                "SELECT count(*) FROM favorite_media WHERE source_native_id='Favorite_7'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(after9, 0, "删整组");
        assert_eq!(after7, 1, "别的收藏不受影响");
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('favorite_media')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cols, 10, "favorite_media 表 10 列");
        let dbg = format!("{:?}", sample_fav_media("Favorite_9", 0, &"a".repeat(32), 2));
        assert!(!dbg.contains("wxid_acct"), "K-R4: Debug 不泄 account_id");
        assert!(dbg.contains("media_md5"), "md5 非 PII 原样");
    }

    // ── L2 favorite_tag 收藏标签表 (ADR-454 B-2) ──

    fn sample_favorite_tag(native_id: &str, fav_server_id: i64, name: &str) -> V3FavoriteTag {
        V3FavoriteTag {
            account_id_sha: "acct_sha".to_string(),
            source: "favorite.db".to_string(),
            source_native_id: native_id.to_string(),
            tag_server_id: 1,
            tag_local_id: 1,
            seq: 824_874_138,
            fav_server_id,
            fav_local_id: 92,
            op_code: 1,
            tag_name_len: i64::try_from(name.chars().count()).unwrap(),
            account_id: "wxid_acct".to_string(),
            tag_name: name.to_string(),
        }
    }

    /// favorite_tag 建表 + 插入回查 + 列数基线 12 (ADR-454 B-2)。
    #[test]
    fn favorite_tag_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_favorite_tag_table(&conn).unwrap();
        insert_favorite_tag(&conn, &sample_favorite_tag("FavoriteTag_1_254", 254, "押金")).unwrap();
        let (tag_sid, fav_sid, name, op): (i64, i64, String, i64) = conn
            .query_row(
                "SELECT tag_server_id, fav_server_id, tag_name, op_code FROM favorite_tag WHERE source_native_id='FavoriteTag_1_254'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(tag_sid, 1);
        assert_eq!(fav_sid, 254);
        assert_eq!(name, "押金", "标签名明文落库 (ADR-427)");
        assert_eq!(op, 1);
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('favorite_tag')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cols, 12, "favorite_tag 表 12 列");
    }

    /// K-R4: V3FavoriteTag Debug 脱敏 — 不含裸 tag_name。
    #[test]
    fn favorite_tag_debug_no_raw_leak() {
        let dbg = format!("{:?}", sample_favorite_tag("FavoriteTag_1_254", 254, "押金"));
        assert!(!dbg.contains("押金"), "K-R4: V3FavoriteTag Debug 含裸标签");
        assert!(!dbg.contains("wxid_acct"), "K-R4: Debug 含裸 account");
        assert!(dbg.contains("tag_name_sha8"));
    }

    // ── L2 moment 朋友圈动态表 (ADR-467 件1) ──

    fn sample_moment(native_id: &str, tid: i64, mtype: i64) -> V3Moment {
        V3Moment {
            account_id_sha: "acct_sha".to_string(),
            source: "sns.db".to_string(),
            source_native_id: native_id.to_string(),
            tid,
            author_sha: "author_sha".to_string(),
            create_time: 1_779_546_990,
            moment_type: mtype,
            account_id: "wxid_acct".to_string(),
            author: "wxid_author".to_string(),
            author_nickname: Some("发布者昵称".to_string()),
            content_desc: "动态正文".to_string(),
            content_desc_len: 4,
            source_user: None,
            location_label: Some("台州市".to_string()),
            latitude: Some(121.382_042),
            longitude: Some(28.576_089_9),
            title: None,
            link_url: None,
            media_count: 1,
            like_count: 3,
            comment_count: 0,
            source_nickname: None,
            is_bidirectional_fan: 0,
            is_rich_text: 0,
            public_user_name: None,
            app_name: None,
            content_len: 2170,
        }
    }

    /// moment 建表 + 插入回查骨架字段 + 列数基线 22 (ADR-467)。
    #[test]
    fn moment_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_moment_table(&conn).unwrap();
        insert_moment(
            &conn,
            &sample_moment("Sns_-3518821952372526549", -3_518_821_952_372_526_549, 1),
        )
        .unwrap();
        let (tid, mtype, author, desc, lat): (i64, i64, String, String, f64) = conn
            .query_row(
                "SELECT tid, moment_type, author, content_desc, latitude FROM moment WHERE source_native_id='Sns_-3518821952372526549'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(tid, -3_518_821_952_372_526_549, "负 tid 落库原样");
        assert_eq!(mtype, 1);
        assert_eq!(author, "wxid_author", "发布者明文落库 (ADR-427)");
        assert_eq!(desc, "动态正文");
        assert!((lat - 121.382_042).abs() < 1e-6, "经纬度 REAL 落库");
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('moment')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 27, "moment 表 27 列 (ADR-467 件1 的 22 + ADR-491 补 5)");
    }

    /// moment upsert: 同 PK 重写 → 不增行 + like_count 刷新 (点赞数变)。
    #[test]
    fn moment_upsert_refreshes_like_count() {
        let (_d, conn) = open_inited();
        init_moment_table(&conn).unwrap();
        insert_moment(&conn, &sample_moment("Sns_1", 1, 1)).unwrap();
        let mut m2 = sample_moment("Sns_1", 1, 1);
        m2.like_count = 99; // 点赞数变
        insert_moment(&conn, &m2).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM moment", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "同 PK upsert 不增行");
        let likes: i64 = conn
            .query_row(
                "SELECT like_count FROM moment WHERE source_native_id='Sns_1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(likes, 99, "like_count 刷新");
    }

    /// null 位置/标题 → NULL 落库 (nullable 列)。
    #[test]
    fn moment_null_location_ok() {
        let (_d, conn) = open_inited();
        init_moment_table(&conn).unwrap();
        let mut m = sample_moment("Sns_2", 2, 2);
        m.location_label = None;
        m.latitude = None;
        m.longitude = None;
        insert_moment(&conn, &m).unwrap();
        let lat: Option<f64> = conn
            .query_row("SELECT latitude FROM moment WHERE source_native_id='Sns_2'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(lat, None, "无位置 → NULL");
    }

    /// K-R4: V3Moment 持明文但 Debug 脱敏 — 不含裸 author/content_desc/nickname。
    #[test]
    fn moment_debug_no_raw_leak() {
        let dbg = format!("{:?}", sample_moment("Sns_1", 1, 1));
        for raw in ["wxid_author", "动态正文", "发布者昵称", "wxid_acct"] {
            assert!(!dbg.contains(raw), "K-R4: V3Moment Debug 含裸值 {raw}");
        }
        assert!(dbg.contains("author_sha8") && dbg.contains("content_desc_sha8"));
    }

    // ── L2 moment_media 朋友圈媒体表 (ADR-467 件2a) ──

    fn sample_moment_media(native_id: &str, seq: i64) -> V3MomentMedia {
        V3MomentMedia {
            account_id_sha: "acct_sha".to_string(),
            source: "sns.db".to_string(),
            source_native_id: native_id.to_string(),
            media_seq: seq,
            media_type: 2,
            account_id: "wxid_acct".to_string(),
            media_id: Some("111".to_string()),
            url: Some("http://full/0".to_string()),
            thumb_url: Some("http://thumb/150".to_string()),
            md5: Some("MD5A".to_string()),
            video_md5: None,
            url_key: Some("K1".to_string()),
            enc_idx: Some("1".to_string()),
            token: Some("TK1".to_string()),
            enc_key: None,
            width: 1920,
            height: 2560,
            total_size: 491_021,
            video_duration: None,
        }
    }

    /// moment_media 建表 + 插入回查 + 列数基线 19 (ADR-467 件2a + 件3 token)。
    #[test]
    fn moment_media_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_moment_media_table(&conn).unwrap();
        insert_moment_media(&conn, &sample_moment_media("Sns_1", 0)).unwrap();
        let (mtype, url, md5, key, w): (i64, String, String, String, i64) = conn
            .query_row(
                "SELECT media_type, url, md5, url_key, width FROM moment_media WHERE source_native_id='Sns_1' AND media_seq=0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(mtype, 2);
        assert_eq!(url, "http://full/0", "url 明文落库");
        assert_eq!(md5, "MD5A");
        assert_eq!(key, "K1", "解密 key 明文落库 (ADR-427)");
        assert_eq!(w, 1920);
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('moment_media')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cols, 19, "moment_media 表 19 列 (ADR-467 件2a + 件3 token)");
    }

    /// delete_moment_media 删该 moment PK 的所有媒体行 (一动态多媒体整组删; replace-projection)。
    #[test]
    fn delete_moment_media_removes_all_rows() {
        let (_d, conn) = open_inited();
        init_moment_media_table(&conn).unwrap();
        for seq in 0..3 {
            insert_moment_media(&conn, &sample_moment_media("Sns_1", seq)).unwrap();
        }
        insert_moment_media(&conn, &sample_moment_media("Sns_2", 0)).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM moment_media", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            4
        );
        delete_moment_media(&conn, "acct_sha", "sns.db", "Sns_1").unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM moment_media", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1,
            "Sns_1 的 3 行删光, Sns_2 保留"
        );
    }

    /// K-R4: V3MomentMedia Debug 脱敏 — 不含裸 url/md5/key。
    #[test]
    fn moment_media_debug_no_raw_leak() {
        let dbg = format!("{:?}", sample_moment_media("Sns_1", 0));
        for raw in ["http://full/0", "http://thumb/150", "MD5A", "K1", "wxid_acct"] {
            assert!(!dbg.contains(raw), "K-R4: V3MomentMedia Debug 含裸值 {raw}");
        }
        assert!(dbg.contains("url_sha8") && dbg.contains("url_key_sha8"));
    }

    // ── L2 moment_interaction 朋友圈互动表 (ADR-467 件2b) ──

    fn sample_interaction(native_id: &str, seq: i64, kind: &str, is_comment: bool) -> V3MomentInteraction {
        V3MomentInteraction {
            account_id_sha: "acct_sha".to_string(),
            source: "sns.db".to_string(),
            source_native_id: native_id.to_string(),
            interaction_seq: seq,
            kind: kind.to_string(),
            type_raw: if is_comment { 2 } else { 1 },
            from_user_sha: "from_sha".to_string(),
            account_id: "wxid_acct".to_string(),
            from_user: Some("wxid_from".to_string()),
            from_nickname: Some("互动人昵称".to_string()),
            content: if is_comment {
                Some("谢谢大家".to_string())
            } else {
                None
            },
            comment_id: Some("20".to_string()),
            ref_username: if is_comment {
                Some("wxid_replied".to_string())
            } else {
                None
            },
            ref_comment_id: Some("0".to_string()),
            create_time: 1_700_000_002,
        }
    }

    /// moment_interaction 建表 + 插入回查 + 列数基线 15 (ADR-467 件2b)。
    #[test]
    fn moment_interaction_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_moment_interaction_table(&conn).unwrap();
        insert_moment_interaction(&conn, &sample_interaction("Sns_1", 0, "comment", true)).unwrap();
        let (kind, fu, content, refu): (String, String, String, String) = conn
            .query_row(
                "SELECT kind, from_user, content, ref_username FROM moment_interaction WHERE source_native_id='Sns_1' AND interaction_seq=0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(kind, "comment");
        assert_eq!(fu, "wxid_from", "互动者明文 (ADR-427)");
        assert_eq!(content, "谢谢大家", "评论文本明文");
        assert_eq!(refu, "wxid_replied", "回复对象");
        let cols: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('moment_interaction')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cols, 15, "moment_interaction 表 15 列 (ADR-467 件2b)");
    }

    /// 赞 content NULL (赞无评论文本)。
    #[test]
    fn moment_interaction_like_content_null() {
        let (_d, conn) = open_inited();
        init_moment_interaction_table(&conn).unwrap();
        insert_moment_interaction(&conn, &sample_interaction("Sns_1", 0, "like", false)).unwrap();
        let content: Option<String> = conn
            .query_row(
                "SELECT content FROM moment_interaction WHERE source_native_id='Sns_1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(content, None, "赞 content NULL");
    }

    /// delete_moment_interactions 删该 moment PK 的所有互动行 (replace-projection)。
    #[test]
    fn delete_moment_interactions_removes_all() {
        let (_d, conn) = open_inited();
        init_moment_interaction_table(&conn).unwrap();
        for seq in 0..3 {
            insert_moment_interaction(&conn, &sample_interaction("Sns_1", seq, "like", false)).unwrap();
        }
        insert_moment_interaction(&conn, &sample_interaction("Sns_2", 0, "like", false)).unwrap();
        delete_moment_interactions(&conn, "acct_sha", "sns.db", "Sns_1").unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM moment_interaction", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1,
            "Sns_1 3 行删光, Sns_2 留"
        );
    }

    /// K-R4: V3MomentInteraction Debug 脱敏 — 不含裸 from_user/content/昵称。
    #[test]
    fn moment_interaction_debug_no_raw_leak() {
        let dbg = format!("{:?}", sample_interaction("Sns_1", 0, "comment", true));
        for raw in ["wxid_from", "谢谢大家", "互动人昵称", "wxid_replied", "wxid_acct"] {
            assert!(!dbg.contains(raw), "K-R4: V3MomentInteraction Debug 含裸值 {raw}");
        }
        assert!(dbg.contains("from_user_sha8") && dbg.contains("content_sha8"));
    }

    // ── L2 message_app 消息卡片表 (ADR-455) ──

    /// message_app 建表 + 插入回查 + 列数基线 12。
    #[test]
    fn message_app_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_message_app_table(&conn).unwrap();
        let app = V3MessageApp {
            account_id_sha: "acct_sha".to_string(),
            source: "message_0.db".to_string(),
            source_native_id: "Msg_a:1".to_string(),
            app_type: 51,
            media_count: 7,
            account_id: "wxid_acct".to_string(),
            title: None,
            source_name: None,
            url: Some("http://v.qq/x".to_string()),
            app_username: Some("v2_abc".to_string()),
            app_nickname: Some("视频号作者".to_string()),
            app_pagepath: None,
            // 类型专属细节 (ADR-462) — 这条视频号无, 都 0/None; 另插一条转账验专属列。
            file_size: 0,
            file_ext: None,
            file_md5: None,
            transfer_fee: None,
            transfer_direction: 0,
            transfer_txid: None,
            refer_svrid: None,
            refer_type: 0,
            refer_content: None,
            forward_item_count: 0,
            red_envelope_wish: None,
            red_envelope_count: 0,
            group_pay_amount: None,
            group_pay_bill_no: None,
            music_desc: None,
            gift_wish: None,
            gift_sku: None,
            live_status: 0,
            live_desc: None,
            pay_scene_text: None,
        };
        insert_message_app(&conn, &app).unwrap();
        // 第二条: 转账 (type 2000) — 验类型专属列落库。
        let xfer = V3MessageApp {
            app_type: 2000,
            source_native_id: "Msg_a:2".to_string(),
            transfer_fee: Some("￥10.00".to_string()),
            transfer_direction: 3,
            transfer_txid: Some("100050001".to_string()),
            ..app.clone()
        };
        insert_message_app(&conn, &xfer).unwrap();
        // 第三条: 红包 (type 2001) — 验祝福语+个数落库 (ADR-468 §7.3)。
        let hb = V3MessageApp {
            app_type: 2001,
            source_native_id: "Msg_a:3".to_string(),
            red_envelope_wish: Some("恭喜发财大吉大利".to_string()),
            red_envelope_count: 16,
            pay_scene_text: Some("微信红包".to_string()), // ADR-495: 场景类别名往返
            ..app.clone()
        };
        insert_message_app(&conn, &hb).unwrap();
        // 第四条: 群收款 (type 2001 带 newaa) — 验金额+单号落库 (ADR-487)。
        let gp = V3MessageApp {
            app_type: 2001,
            source_native_id: "Msg_a:4".to_string(),
            group_pay_amount: Some("应付¥8.00".to_string()),
            group_pay_bill_no: Some("100600001aabbcc".to_string()),
            ..app.clone()
        };
        insert_message_app(&conn, &gp).unwrap();
        let (at, mc, nick, uname): (i64, i64, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT app_type, media_count, app_nickname, app_username FROM message_app WHERE source_native_id='Msg_a:1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(at, 51);
        assert_eq!(mc, 7);
        assert_eq!(nick.as_deref(), Some("视频号作者"), "视频号作者明文落库 (ADR-427)");
        assert_eq!(uname.as_deref(), Some("v2_abc"));
        let (fee, dir): (Option<String>, i64) = conn
            .query_row(
                "SELECT transfer_fee, transfer_direction FROM message_app WHERE source_native_id='Msg_a:2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fee.as_deref(), Some("￥10.00"), "转账金额明文落库 (ADR-427)");
        assert_eq!(dir, 3, "转账方向落库");
        let (wish, num, scene): (Option<String>, i64, Option<String>) = conn
            .query_row(
                "SELECT red_envelope_wish, red_envelope_count, pay_scene_text FROM message_app WHERE source_native_id='Msg_a:3'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            wish.as_deref(),
            Some("恭喜发财大吉大利"),
            "红包祝福语明文落库 (ADR-427)"
        );
        assert_eq!(num, 16, "红包个数落库");
        assert_eq!(scene.as_deref(), Some("微信红包"), "支付场景类别名落库 (ADR-495)");
        let (amt, bill): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT group_pay_amount, group_pay_bill_no FROM message_app WHERE source_native_id='Msg_a:4'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(amt.as_deref(), Some("应付¥8.00"), "群收款金额明文落库 (ADR-487)");
        assert_eq!(bill.as_deref(), Some("100600001aabbcc"), "群收款单号落库");
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('message_app')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            cols, 32,
            "message_app 表 32 列 (12 + 10 类型专属 + 2 红包 + 2 群收款 + 5 音乐/礼物/直播 + 1 场景 ADR-495)"
        );
    }

    /// 旧 12 列 message_app (批C) → ensure_message_app_columns 补 17 类型专属列 = 29, 幂等 (ADR-462/468/462扩 迁移)。
    #[test]
    fn message_app_migrate_old_12col_table() {
        let (_d, conn) = open_inited();
        // 手建旧 12 列表 (批C schema, 无类型专属列) 覆盖 init 建的。
        conn.execute_batch(
            "DROP TABLE IF EXISTS message_app;
             CREATE TABLE message_app (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                app_type INTEGER NOT NULL, media_count INTEGER NOT NULL, account_id TEXT NOT NULL,
                title TEXT, source_name TEXT, url TEXT, app_username TEXT, app_nickname TEXT, app_pagepath TEXT,
                PRIMARY KEY (account_id_sha, source, source_native_id));",
        )
        .unwrap();
        let names = |c: &Connection| -> Vec<String> {
            c.prepare("PRAGMA table_info(message_app)")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        // codex P2: fresh 库 (init CREATE) 31 列 vs migrated 库 (ensure ALTER) 列名**且顺序**必须一致,
        //  否则 SELECT */导出踩坑。这里造一个 fresh 库取其列序作基准。
        let (_d2, fresh) = open_inited();
        init_message_app_table(&fresh).unwrap(); // fresh 走 CREATE 32 列路
        let fresh_names = names(&fresh);
        assert_eq!(fresh_names.len(), 32, "fresh CREATE 32 列");
        assert_eq!(names(&conn).len(), 12, "旧表 12 列");
        ensure_message_app_columns(&conn).unwrap();
        assert_eq!(names(&conn), fresh_names, "migrated 列名+序 == fresh CREATE");
        ensure_message_app_columns(&conn).unwrap(); // 幂等: 再跑不重复加
        assert_eq!(names(&conn), fresh_names, "再 ensure 仍一致 (幂等)");
    }

    // ── L2 message_media 媒体元数据表 (ADR-456) ──

    /// message_media 建表 + 插入回查 + 列数基线 12。
    #[test]
    fn message_media_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_message_media_table(&conn).unwrap();
        let m = V3MessageMedia {
            account_id_sha: "acct_sha".to_string(),
            source: "message_0.db".to_string(),
            source_native_id: "Msg_v:9".to_string(),
            media_kind: "video".to_string(),
            file_size: 936_153,
            play_length: 5,
            account_id: "wxid_acct".to_string(),
            md5: Some("abe2d4b7c2648a9deaf2c177503d759c".to_string()),
            aes_key: Some("d1c637737484578e1806134d3233e2f2".to_string()),
            cdn_url: Some("3057020100vid".to_string()),
            thumb_url: Some("3057020100thumb".to_string()),
            extra_id: Some("newmd5val".to_string()),
        };
        insert_message_media(&conn, &m).unwrap();
        let (kind, sz, pl, md5): (String, i64, i64, Option<String>) = conn
            .query_row(
                "SELECT media_kind, file_size, play_length, md5 FROM message_media WHERE source_native_id='Msg_v:9'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(kind, "video");
        assert_eq!(sz, 936_153);
        assert_eq!(pl, 5, "视频时长落库");
        assert_eq!(
            md5.as_deref(),
            Some("abe2d4b7c2648a9deaf2c177503d759c"),
            "md5 明文落库 (ADR-427)"
        );
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('message_media')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cols, 12, "message_media 表 12 列");
    }

    /// message_location 建表 + 插入回查 + 列数基线 10。
    #[test]
    fn message_location_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_message_location_table(&conn).unwrap();
        let m = V3MessageLocation {
            account_id_sha: "acct_sha".to_string(),
            source: "message_0.db".to_string(),
            source_native_id: "Msg_loc:7".to_string(),
            scale: 15,
            account_id: "wxid_acct".to_string(),
            latitude: 28.386_938,
            longitude: 121.395_126,
            label: Some("浙江省台州市".to_string()),
            poiname: Some("台州万达广场".to_string()),
            poiid: Some("qqmap_123".to_string()),
            maptype: 0,
            adcode: Some("331000".to_string()),
            cityname: Some("台州市".to_string()),
        };
        insert_message_location(&conn, &m).unwrap();
        let (lat, lng, poi): (f64, f64, Option<String>) = conn
            .query_row(
                "SELECT latitude, longitude, poiname FROM message_location WHERE source_native_id='Msg_loc:7'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!((lat - 28.386_938).abs() < 1e-6, "纬度落库");
        assert!((lng - 121.395_126).abs() < 1e-6, "经度落库");
        assert_eq!(poi.as_deref(), Some("台州万达广场"), "地点名明文落库 (ADR-427)");
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('message_location')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            cols, 13,
            "message_location 表 13 列 (ADR-479 补 maptype/adcode/cityname)"
        );
    }

    /// 旧 10 列 message_location (ADR-462) → ensure_message_location_columns 补 maptype/adcode/cityname = 13, 幂等。
    /// 防旧 L1 (CREATE IF NOT EXISTS 不补列) insert 13 列失败 (ADR-479 迁移)。
    #[test]
    fn message_location_migrate_old_10col_table() {
        let (_d, conn) = open_inited();
        // 手建旧 10 列表 (ADR-462 schema, 无 maptype/adcode/cityname) 覆盖 init 建的。
        conn.execute_batch(
            "DROP TABLE IF EXISTS message_location;
             CREATE TABLE message_location (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                scale INTEGER NOT NULL, account_id TEXT NOT NULL, latitude REAL NOT NULL,
                longitude REAL NOT NULL, label TEXT, poiname TEXT, poiid TEXT,
                PRIMARY KEY (account_id_sha, source, source_native_id));",
        )
        .unwrap();
        let names = |c: &Connection| -> Vec<String> {
            c.prepare("PRAGMA table_info(message_location)")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        // fresh 库 (init CREATE 13 列) 作列序基准 — migrated 列名+序须一致 (同 message_app 迁移)。
        let (_d2, fresh) = open_inited();
        init_message_location_table(&fresh).unwrap();
        let fresh_names = names(&fresh);
        assert_eq!(fresh_names.len(), 13, "fresh CREATE 13 列");
        assert_eq!(names(&conn).len(), 10, "旧表 10 列");
        ensure_message_location_columns(&conn).unwrap();
        assert_eq!(names(&conn), fresh_names, "migrated 列名+序 == fresh CREATE");
        ensure_message_location_columns(&conn).unwrap(); // 幂等: 再跑不重复加
        assert_eq!(names(&conn), fresh_names, "再 ensure 仍一致 (幂等)");
        // 迁移后可插 13 列行 (旧 L1 不再 insert 失败)。
        insert_message_location(
            &conn,
            &V3MessageLocation {
                account_id_sha: "a".to_string(),
                source: "m.db".to_string(),
                source_native_id: "Msg:1".to_string(),
                scale: 15,
                account_id: "wxid".to_string(),
                latitude: 1.0,
                longitude: 2.0,
                label: None,
                poiname: None,
                poiid: None,
                maptype: 0,
                adcode: Some("330100".to_string()),
                cityname: Some("杭州市".to_string()),
            },
        )
        .unwrap();
    }

    /// K-R4: V3MessageLocation Debug 脱敏 — 不含裸 poiname/label/精确坐标。
    #[test]
    fn message_location_debug_no_raw_leak() {
        let m = V3MessageLocation {
            account_id_sha: "acct_sha".to_string(),
            source: "m.db".to_string(),
            source_native_id: "Msg:1".to_string(),
            scale: 15,
            account_id: "wxid_acct".to_string(),
            latitude: 28.386_938,
            longitude: 121.395_126,
            label: Some("浙江省台州市黄岩区".to_string()),
            poiname: Some("台州万达广场".to_string()),
            poiid: Some("qqmap_123".to_string()),
            maptype: 0,
            adcode: None,
            cityname: None,
        };
        let dbg = format!("{m:?}");
        for raw in ["台州万达广场", "浙江省台州市黄岩区", "28.386938", "121.395126"] {
            assert!(!dbg.contains(raw), "K-R4: V3MessageLocation Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("poiname_sha8") && dbg.contains("28.39"), "sha8 + 坐标粗化");
    }

    /// K-R4: V3MessageMedia Debug 脱敏 — 不含裸 md5/aes_key/cdn_url。
    #[test]
    fn message_media_debug_no_raw_leak() {
        let m = V3MessageMedia {
            account_id_sha: "acct_sha".to_string(),
            source: "m.db".to_string(),
            source_native_id: "Msg:1".to_string(),
            media_kind: "emoji".to_string(),
            file_size: 100,
            play_length: 0,
            account_id: "wxid_acct".to_string(),
            md5: Some("13f91eb9c2068544ee81a1a88a8b5e79".to_string()),
            aes_key: Some("secretaeskey00000000000000000000".to_string()),
            cdn_url: Some("http://wxapp.tc.qq.com/x".to_string()),
            thumb_url: None,
            extra_id: None,
        };
        let dbg = format!("{m:?}");
        for raw in [
            "13f91eb9c2068544ee81a1a88a8b5e79",
            "secretaeskey",
            "wxapp.tc.qq.com",
            "wxid_acct",
        ] {
            assert!(!dbg.contains(raw), "K-R4: V3MessageMedia Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("md5_sha8"));
        assert!(dbg.contains("media_kind: \"emoji\""), "media_kind 明文");
    }

    // ── L2 message_mention @提及表 (ADR-457) ──

    /// message_mention 建表 + 插入回查 + 列数基线 7 + Debug 脱敏。
    #[test]
    fn message_mention_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_message_mention_table(&conn).unwrap();
        let m = V3MessageMention {
            account_id_sha: "acct_sha".to_string(),
            source: "message_0.db".to_string(),
            source_native_id: "Msg_a:5".to_string(),
            mentioned_wxid_sha: "wxid_at_sha".to_string(),
            is_at_all: false,
            account_id: "wxid_acct".to_string(),
            mentioned_wxid: "wxid_at_target".to_string(),
        };
        insert_message_mention(&conn, &m).unwrap();
        let (wx, at): (String, bool) = conn
            .query_row(
                "SELECT mentioned_wxid, is_at_all FROM message_mention WHERE source_native_id='Msg_a:5'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(wx, "wxid_at_target", "被@wxid 明文落库 (ADR-427)");
        assert!(!at);
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('message_mention')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cols, 7, "message_mention 表 7 列");
        // K-R4 Debug 脱敏。
        let dbg = format!("{m:?}");
        assert!(!dbg.contains("wxid_at_target"), "K-R4: Debug 泄裸被@wxid");
        assert!(!dbg.contains("wxid_acct"), "K-R4: Debug 泄裸 account");
        assert!(dbg.contains("mentioned_wxid_sha8"));
    }

    /// delete_message_mentions 删该 message PK 的所有 @行 (一消息多行整组删)。
    #[test]
    fn delete_message_mentions_removes_all_rows() {
        let (_d, conn) = open_inited();
        init_message_mention_table(&conn).unwrap();
        for w in ["a", "b", "c"] {
            insert_message_mention(
                &conn,
                &V3MessageMention {
                    account_id_sha: "acct_sha".to_string(),
                    source: "m.db".to_string(),
                    source_native_id: "Msg:1".to_string(),
                    mentioned_wxid_sha: format!("sha_{w}"),
                    is_at_all: false,
                    account_id: "wxid_acct".to_string(),
                    mentioned_wxid: format!("wxid_{w}"),
                },
            )
            .unwrap();
        }
        assert_eq!(
            conn.query_row("SELECT count(*) FROM message_mention", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3
        );
        delete_message_mentions(&conn, "acct_sha", "m.db", "Msg:1").unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM message_mention", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0,
            "整组 @行删净"
        );
    }

    // ── L2 chatroom_member_event 群成员进出事件表 ──

    fn sample_member_event(seq: i64, wxid: Option<&str>, kind: &str) -> V3ChatroomMemberEvent {
        V3ChatroomMemberEvent {
            account_id_sha: "acct_sha".to_string(),
            source: "message_0.db".to_string(),
            source_native_id: format!("Msg_a:5:{seq}"),
            msg_native_id: "Msg_a:5".to_string(),
            conv_id_sha: "conv_sha".to_string(),
            member_wxid_sha: wxid.map(|_| "mem_sha".to_string()),
            event_kind: kind.to_string(),
            inviter_wxid_sha: Some("inv_sha".to_string()),
            event_time: 1_699_000,
            account_id: "wxid_acct".to_string(),
            conv_id: "12345@chatroom".to_string(),
            member_wxid: wxid.map(str::to_string),
            member_nickname: Some("春风".to_string()),
            inviter_wxid: Some("wxid_inviter".to_string()),
        }
    }

    /// chatroom_member_event 建表 + 插入回查 + 列数基线 14 + Debug 脱敏 (含 nickname)。
    #[test]
    fn chatroom_member_event_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_chatroom_member_event_table(&conn).unwrap();
        let e = sample_member_event(0, Some("wxid_member_x"), "join");
        insert_chatroom_member_event(&conn, &e).unwrap();
        let (wx, kind, t): (String, String, i64) = conn
            .query_row(
                "SELECT member_wxid, event_kind, event_time FROM chatroom_member_event WHERE source_native_id='Msg_a:5:0'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(wx, "wxid_member_x", "成员 wxid 明文落库 (ADR-427)");
        assert_eq!(kind, "join");
        assert_eq!(t, 1_699_000, "event_time = create_time");
        let cols: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('chatroom_member_event')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cols, 14, "chatroom_member_event 表 14 列");
        // K-R4 Debug 脱敏: wxid/nickname/conv_id/account 都不露裸值。
        let dbg = format!("{e:?}");
        for raw in ["wxid_member_x", "wxid_inviter", "wxid_acct", "12345@chatroom", "春风"] {
            assert!(!dbg.contains(raw), "K-R4: Debug 泄裸值 {raw}");
        }
        assert!(
            dbg.contains("member_wxid_sha8")
                && dbg.contains("member_nickname_sha8")
                && dbg.contains("inviter_wxid_sha8")
        );
    }

    /// remove 事件 member_wxid=None (纯文本无 wxid) 落库 NULL, 不硬造。
    #[test]
    fn chatroom_member_event_null_wxid_for_plaintext_remove() {
        let (_d, conn) = open_inited();
        init_chatroom_member_event_table(&conn).unwrap();
        let mut e = sample_member_event(0, None, "remove");
        e.member_wxid = None;
        e.member_wxid_sha = None;
        e.inviter_wxid = None;
        e.inviter_wxid_sha = None;
        insert_chatroom_member_event(&conn, &e).unwrap();
        let wx: Option<String> = conn
            .query_row(
                "SELECT member_wxid FROM chatroom_member_event WHERE source_native_id='Msg_a:5:0'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(wx.is_none(), "纯文本 remove: member_wxid 落 NULL (不硬造 wxid)");
    }

    /// delete_chatroom_member_events 按 msg_native_id 删该消息所有行 (一消息多成员整组删)。
    #[test]
    fn delete_chatroom_member_events_removes_all_rows() {
        let (_d, conn) = open_inited();
        init_chatroom_member_event_table(&conn).unwrap();
        for seq in 0..3 {
            insert_chatroom_member_event(&conn, &sample_member_event(seq, Some("wxid_m"), "join")).unwrap();
        }
        assert_eq!(
            conn.query_row("SELECT count(*) FROM chatroom_member_event", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            3,
            "3 行 source_native_id 各异 (Msg_a:5:0/1/2)"
        );
        delete_chatroom_member_events(&conn, "acct_sha", "message_0.db", "Msg_a:5").unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM chatroom_member_event", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0,
            "按 msg_native_id 整组删净"
        );
    }

    // ── L2 group_pay_member 群收款付款人表 (ADR-488) ──

    /// group_pay_member 建表 + 逐付款人插 + 已付人数=COUNT + 列数 9 + Debug 脱敏 + 整组删。
    #[test]
    fn group_pay_member_count_and_delete() {
        let (_d, conn) = open_inited();
        init_group_pay_member_table(&conn).unwrap();
        for (w, st) in [("p1", 1), ("p2", 1), ("p3", 0)] {
            insert_group_pay_member(
                &conn,
                &V3GroupPayMember {
                    account_id_sha: "acct_sha".to_string(),
                    source: "message_0.db".to_string(),
                    source_native_id: "Msg_gp:1".to_string(),
                    payer_wxid_sha: format!("sha_{w}"),
                    bill_no: "bill_x".to_string(),
                    amount: 2000,
                    pay_status: st,
                    account_id: "wxid_acct".to_string(),
                    payer_wxid: format!("wxid_{w}"),
                },
            )
            .unwrap();
        }
        // 已付人数 = COUNT GROUP BY bill_no。
        let total: i64 = conn
            .query_row(
                "SELECT count(*) FROM group_pay_member WHERE bill_no='bill_x'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, 3, "3 付款人 (已付人数派生自行数)");
        let paid: i64 = conn
            .query_row(
                "SELECT count(*) FROM group_pay_member WHERE bill_no='bill_x' AND pay_status=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(paid, 2, "status=1 已付 2 人");
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('group_pay_member')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cols, 9, "group_pay_member 表 9 列");
        // K-R4 Debug: payer_wxid/bill_no sha8, 金额/状态直显。
        let m = V3GroupPayMember {
            account_id_sha: "s".into(),
            source: "m".into(),
            source_native_id: "Msg_gp:1".into(),
            payer_wxid_sha: "psha".into(),
            bill_no: "bill_secret".into(),
            amount: 2000,
            pay_status: 1,
            account_id: "wxid_acct".into(),
            payer_wxid: "wxid_payer_secret".into(),
        };
        let dbg = format!("{m:?}");
        assert!(
            !dbg.contains("wxid_payer_secret") && !dbg.contains("bill_secret"),
            "K-R4: payer_wxid/bill_no 脱敏"
        );
        assert!(dbg.contains("payer_wxid_sha8") && dbg.contains("amount: 2000"));
        // replace-projection: 整组删净。
        delete_group_pay_members(&conn, "acct_sha", "message_0.db", "Msg_gp:1").unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM group_pay_member", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0,
            "整组付款人删净"
        );
    }

    // ── L2 chatroom 表 ──

    fn sample_chatroom(native_id: &str, member_count: i64, owner: Option<&str>) -> V3Chatroom {
        V3Chatroom {
            is_still_member: true,
            account_id_sha: "acct_sha".to_string(),
            source: "chatroom.db".to_string(),
            source_native_id: native_id.to_string(),
            chatroom_id_sha: "room_sha".to_string(),
            account_id: "wxid_acct".to_string(),
            chatroom_id: "room@chatroom".to_string(),
            owner_wxid: owner.map(|_| "wxid_owner".to_string()),
            chatroom_name: "群名".to_string(),
            announcement: Some("公告".to_string()),
            chatroom_name_len: 8,
            announcement_len: 20,
            member_count,
            owner_wxid_sha: owner.map(str::to_string),
            announcement_editor: Some("wxid_ann_editor".to_string()),
            announcement_publish_time: 1_700_000_000,
            xml_announcement: Some("<xml>富媒体公告</xml>".to_string()),
            chat_room_status: 0x80000,
            chatroom_remark: Some("我的群备注".to_string()),
            chatroom_remark_len: 5,
        }
    }

    /// chatroom 建表 + 插入回查关键字段 (含非空 owner).
    #[test]
    fn chatroom_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_chatroom_table(&conn).unwrap();
        insert_chatroom(&conn, &sample_chatroom("room_a@chatroom", 5, Some("owner_sha"))).unwrap();
        let (room_sha, count, owner): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT chatroom_id_sha, member_count, owner_wxid_sha FROM chatroom WHERE source_native_id='room_a@chatroom'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(room_sha, "room_sha");
        assert_eq!(count, 5);
        assert_eq!(owner, Some("owner_sha".to_string()));
    }

    /// 同 PK upsert (INSERT OR REPLACE): 不增行 + member_count 刷新 (进退群重解码).
    #[test]
    fn chatroom_upsert_same_pk_refreshes() {
        let (_d, conn) = open_inited();
        init_chatroom_table(&conn).unwrap();
        insert_chatroom(&conn, &sample_chatroom("room_a@chatroom", 5, Some("owner_sha"))).unwrap();
        insert_chatroom(&conn, &sample_chatroom("room_a@chatroom", 7, Some("owner_sha"))).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM chatroom", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 PK upsert 不增行");
        let members: i64 = conn
            .query_row(
                "SELECT member_count FROM chatroom WHERE source_native_id='room_a@chatroom'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(members, 7, "member_count 刷新 5→7");
    }

    /// nullable owner_wxid_sha: 已解散群 None → NULL round-trip + chatroom 表恰 20 列.
    #[test]
    fn chatroom_nullable_owner_and_column_count() {
        let (_d, conn) = open_inited();
        init_chatroom_table(&conn).unwrap();
        insert_chatroom(&conn, &sample_chatroom("room_dissolved@chatroom", 0, None)).unwrap();
        let owner: Option<String> = conn
            .query_row(
                "SELECT owner_wxid_sha FROM chatroom WHERE source_native_id='room_dissolved@chatroom'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(owner, None, "已解散群 owner NULL");
        let col_count: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('chatroom')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(col_count, 20, "chatroom 表恰 20 列 (8 + 5 明文 + 2 批H公告编辑者/发布时间 + 2 KI-A/B富媒体公告/群状态位 + 2 群备注 + 1 ADR-493 退群标记)");
    }

    // ── L2 session 表 ──

    fn sample_session(native_id: &str, unread: i64, sort_ts: i64) -> V3Session {
        V3Session {
            account_id_sha: "acct_sha".to_string(),
            source: "session.db".to_string(),
            source_native_id: native_id.to_string(),
            username_sha: "peer_sha".to_string(),
            account_id: "wxid_acct".to_string(),
            username: "wxid_peer".to_string(),
            unread_count: unread,
            last_msg_type: 1,
            last_msg_sub_type: 0,
            sort_timestamp: sort_ts,
            summary_len: 4,
            summary: Some("最近消息".to_string()),
            last_sender_len: 2,
            last_sender_display_name: Some("张三".to_string()),
            session_type: 1,
            is_hidden: 0,
            status: 0,
            draft_len: 0,
            draft: None,
            last_msg_sender: None,
            last_timestamp: 0,
            last_clear_unread_timestamp: 0,
            last_msg_locald_id: 0,
            last_msg_ext_type: 0,
            unread_first_msg_srv_id: 0,
        }
    }

    /// session 建表 + 插入回查关键字段.
    #[test]
    fn session_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_session_table(&conn).unwrap();
        insert_session(&conn, &sample_session("sess_a", 3, 1_700_000_000)).unwrap();
        let (peer, unread, sort_ts): (String, i64, i64) = conn
            .query_row(
                "SELECT username_sha, unread_count, sort_timestamp FROM session WHERE source_native_id='sess_a'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(peer, "peer_sha");
        assert_eq!(unread, 3);
        assert_eq!(sort_ts, 1_700_000_000);
    }

    /// 字段扩充第四批 (2026-07-02): 会话状态 4 列落库回查 (INTEGER + draft TEXT nullable)。
    #[test]
    fn session_status_columns_roundtrip() {
        let (_d, conn) = open_inited();
        init_session_table(&conn).unwrap();
        let mut s = sample_session("sess_st", 3, 1_700_000_000);
        s.session_type = 2;
        s.is_hidden = 1;
        s.status = 5;
        s.draft = Some("没发的草稿".to_string());
        insert_session(&conn, &s).unwrap();
        let (t, hid, st, draft): (i64, i64, i64, Option<String>) = conn
            .query_row(
                "SELECT session_type, is_hidden, status, draft FROM session WHERE source_native_id='sess_st'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(t, 2, "session_type 回查");
        assert_eq!(hid, 1, "is_hidden 回查");
        assert_eq!(st, 5, "status 回查");
        assert_eq!(draft.as_deref(), Some("没发的草稿"), "draft 回查");
    }

    /// 字段扩充第六批 (2026-07-02): session 补充列落库回查 (last_msg_sender TEXT + 5 INTEGER)。
    #[test]
    fn session_batch6_columns_roundtrip() {
        let (_d, conn) = open_inited();
        init_session_table(&conn).unwrap();
        let mut s = sample_session("sess_b6", 3, 1_700_000_000);
        s.last_msg_sender = Some("wxid_sender".to_string());
        s.last_timestamp = 1_700_000_100_000;
        s.last_clear_unread_timestamp = 1_700_000_050_000;
        s.last_msg_locald_id = 42;
        s.last_msg_ext_type = 3;
        s.unread_first_msg_srv_id = 9_876_543_210;
        insert_session(&conn, &s).unwrap();
        let (sender, lts, lcut, llid, lext, ufsi): (Option<String>, i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT last_msg_sender, last_timestamp, last_clear_unread_timestamp, last_msg_locald_id, last_msg_ext_type, unread_first_msg_srv_id FROM session WHERE source_native_id='sess_b6'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(sender.as_deref(), Some("wxid_sender"), "last_msg_sender 回查");
        assert_eq!(lts, 1_700_000_100_000);
        assert_eq!(lcut, 1_700_000_050_000);
        assert_eq!(llid, 42);
        assert_eq!(lext, 3);
        assert_eq!(ufsi, 9_876_543_210);
    }

    /// codex P1 (第四批): 旧 8 列 session 表 (缺 ADR-426 明文列 + 展示列 + 状态列 + 第六批列) → ensure 补齐 = 25,
    /// insert 不报 no column (ensure 只补缺的)。
    #[test]
    fn old_session_schema_migrates_all_columns() {
        let (_d, conn) = open_inited();
        conn.execute_batch(
            "CREATE TABLE session (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                username_sha TEXT NOT NULL, unread_count INTEGER NOT NULL, last_msg_type INTEGER NOT NULL,
                last_msg_sub_type INTEGER NOT NULL, sort_timestamp INTEGER NOT NULL,
                PRIMARY KEY (account_id_sha, source, source_native_id))",
        )
        .unwrap();
        init_session_table(&conn).unwrap(); // ensure 补 明文2 + 展示4 + 状态5 + 第六批6 = 17 列 → 25
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('session')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 25, "旧 8 列 → ensure 补明文/展示/状态/第六批 = 25");
        // insert 25 列不报 no column (旧库缺的明文/展示/状态/第六批列都补齐了)。
        insert_session(&conn, &sample_session("sess_mig", 3, 1)).unwrap();
        let (t, draft): (i64, Option<String>) = conn
            .query_row(
                "SELECT session_type, draft FROM session WHERE source_native_id='sess_mig'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(t, 1, "session_type 回查");
        assert_eq!(draft, None, "sample_session draft None");
    }

    /// 第六批: 旧 19 列 session 表 (第四批版, 14+5状态) → ensure 补 6 第六批列 = 25; insert 成功。
    #[test]
    fn old_19col_session_migrates_batch6_columns() {
        let (_d, conn) = open_inited();
        conn.execute_batch(
            "CREATE TABLE session (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                username_sha TEXT NOT NULL, account_id TEXT NOT NULL, username TEXT NOT NULL,
                unread_count INTEGER NOT NULL, last_msg_type INTEGER NOT NULL,
                last_msg_sub_type INTEGER NOT NULL, sort_timestamp INTEGER NOT NULL,
                summary_len INTEGER NOT NULL, summary TEXT, last_sender_len INTEGER NOT NULL,
                last_sender_display_name TEXT,
                session_type INTEGER NOT NULL DEFAULT 0, is_hidden INTEGER NOT NULL DEFAULT 0,
                status INTEGER NOT NULL DEFAULT 0, draft_len INTEGER NOT NULL DEFAULT 0, draft TEXT,
                PRIMARY KEY (account_id_sha, source, source_native_id))",
        )
        .unwrap();
        init_session_table(&conn).unwrap(); // 应 ALTER 补 6 第六批列
        let cols: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('session')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(cols, 25, "旧 19 列 → ALTER 补 6 第六批 = 25");
        let mut s = sample_session("sess_mig6", 3, 1);
        s.last_msg_sender = Some("wxid_x".to_string());
        s.last_timestamp = 999;
        insert_session(&conn, &s).unwrap(); // 不报 no column
        let (sender, lts): (Option<String>, i64) = conn
            .query_row(
                "SELECT last_msg_sender, last_timestamp FROM session WHERE source_native_id='sess_mig6'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sender.as_deref(), Some("wxid_x"), "旧 19 列库补第六批后 insert 成功");
        assert_eq!(lts, 999);
    }

    /// 同 PK upsert (INSERT OR REPLACE): 不增行 + unread/sort_timestamp 刷新 (读消息 / 新消息重排).
    #[test]
    fn session_upsert_same_pk_refreshes() {
        let (_d, conn) = open_inited();
        init_session_table(&conn).unwrap();
        insert_session(&conn, &sample_session("sess_a", 3, 1_700_000_000)).unwrap();
        insert_session(&conn, &sample_session("sess_a", 0, 1_700_000_999)).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM session", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 PK upsert 不增行");
        let (unread, sort_ts): (i64, i64) = conn
            .query_row(
                "SELECT unread_count, sort_timestamp FROM session WHERE source_native_id='sess_a'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(unread, 0, "unread 刷新 3→0 (已读)");
        assert_eq!(sort_ts, 1_700_000_999, "sort_timestamp 刷新");
    }

    /// session 表恰 25 列 (第四批 19 + 第六批 6) + 2 索引 (idx_session_username / idx_session_sort) 均建.
    #[test]
    fn session_indexes_and_column_count() {
        let (_d, conn) = open_inited();
        init_session_table(&conn).unwrap();
        let col_count: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('session')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(col_count, 25, "session 表恰 25 列 (14 + 5 会话状态 + 6 第六批: last_msg_sender/last_timestamp/last_clear_unread_timestamp/last_msg_locald_id/last_msg_ext_type/unread_first_msg_srv_id)");
        // init_l1_schema 一键建表也含 session (adapter run_session_ingest 用; 防漏建回归)。
        let d2 = tempfile::tempdir().unwrap();
        let conn2 = crate::storage::open(&d2.path().join("l1b.db")).unwrap();
        crate::storage::init_l1_schema(&conn2).unwrap();
        let n: i64 = conn2
            .query_row("SELECT count(*) FROM session", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 0,
            "init_l1_schema 建了 session 表 (空表 count=0, 不报 no such table)"
        );
        let idx_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='session' AND name IN ('idx_session_username','idx_session_sort')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 2, "session 2 索引均建");
    }

    // ── L2 person_alias_by_account_min 别名表 ──

    fn sample_alias(username: &str, remark: Option<&str>, nick: Option<&str>) -> V3PersonAlias {
        V3PersonAlias {
            account_id_sha: "acct_sha".to_string(),
            username_sha: username.to_string(),
            remark_sha: remark.map(str::to_string),
            nick_name_sha: nick.map(str::to_string),
            account_id: "wxid_acct".to_string(),
            username: "wxid_user".to_string(),
            remark: remark.map(|_| "备注".to_string()),
            nick_name: nick.map(|_| "昵称".to_string()),
        }
    }

    /// person_alias 建表 + 插入回查 (双 sha 非空).
    #[test]
    fn person_alias_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_person_alias_table(&conn).unwrap();
        insert_person_alias(
            &conn,
            &sample_alias("user_a_sha", Some("remark_a_sha"), Some("nick_a_sha")),
        )
        .unwrap();
        let (remark, nick): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT remark_sha, nick_name_sha FROM person_alias_by_account_min WHERE username_sha='user_a_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(remark, Some("remark_a_sha".to_string()));
        assert_eq!(nick, Some("nick_a_sha".to_string()));
    }

    /// 2 元组 PK (account_id_sha, username_sha): 同 PK upsert 刷新 remark; 不同 username 新行.
    #[test]
    fn person_alias_pk_is_account_username() {
        let (_d, conn) = open_inited();
        init_person_alias_table(&conn).unwrap();
        insert_person_alias(&conn, &sample_alias("user_a_sha", Some("remark_v1"), None)).unwrap();
        // 同 (account, username) → upsert 刷新, 不增行
        insert_person_alias(&conn, &sample_alias("user_a_sha", Some("remark_v2"), None)).unwrap();
        // 不同 username → 新行
        insert_person_alias(&conn, &sample_alias("user_b_sha", Some("remark_b"), None)).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM person_alias_by_account_min", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "同 PK upsert 不增行; 不同 username 新行 → 共 2");
        let remark: String = conn
            .query_row(
                "SELECT remark_sha FROM person_alias_by_account_min WHERE username_sha='user_a_sha'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remark, "remark_v2", "同 PK remark 刷新 v1→v2");
    }

    /// nullable remark_sha / nick_name_sha: 都 None → NULL round-trip + 表恰 4 列.
    #[test]
    fn person_alias_nullable_shas_and_column_count() {
        let (_d, conn) = open_inited();
        init_person_alias_table(&conn).unwrap();
        insert_person_alias(&conn, &sample_alias("user_c_sha", None, None)).unwrap();
        let (remark, nick): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT remark_sha, nick_name_sha FROM person_alias_by_account_min WHERE username_sha='user_c_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(remark, None);
        assert_eq!(nick, None);
        let col_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('person_alias_by_account_min')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(col_count, 8, "person_alias 表恰 8 列 (4 + 4 明文)");
    }

    // ── L2 chatroom_member 群成员表 ──

    /// 一个"新加群"成员 (is_in_group=true, left_at=None, joined_at 给定).
    fn sample_member(native_id: &str, joined_at: i64) -> V3ChatroomMember {
        V3ChatroomMember {
            account_id_sha: "acct_sha".to_string(),
            source: "chatroom.db".to_string(),
            source_native_id: native_id.to_string(),
            chatroom_id_sha: "room_sha".to_string(),
            member_wxid_sha: "member_sha".to_string(),
            account_id: "wxid_acct".to_string(),
            chatroom_id: "room@chatroom".to_string(),
            member_wxid: "wxid_member".to_string(),
            display_name: Some("群昵称".to_string()),
            display_name_len: 5,
            joined_at: Some(joined_at),
            left_at: None,
            is_in_group: true,
            role: "member".to_string(),
            invited_by: None,
        }
    }

    /// member_add 新 PK → INSERT 一行, is_in_group=1, joined_at 写入, left_at NULL.
    #[test]
    fn chatroom_member_add_inserts_new() {
        let (_d, conn) = open_inited();
        init_chatroom_member_table(&conn).unwrap();
        upsert_chatroom_member_add(&conn, &sample_member("room:member:wx_a", 1000)).unwrap();
        let (in_group, joined, left): (bool, Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT is_in_group, joined_at, left_at FROM chatroom_member WHERE source_native_id='room:member:wx_a'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(in_group);
        assert_eq!(joined, Some(1000));
        assert_eq!(left, None);
    }

    /// §6.8 契约3c 先退后加再退: 同 PK 始终 1 行; 退保留 joined_at + 翻 is_in_group=0/left_at;
    /// 再加重置 joined_at + 复活; 再退再翻. 完整历史在 archive 重放, 业务表只留当前状态行.
    #[test]
    fn chatroom_member_leave_rejoin_leave() {
        let (_d, conn) = open_inited();
        init_chatroom_member_table(&conn).unwrap();
        let q = "SELECT is_in_group, joined_at, left_at FROM chatroom_member WHERE source_native_id='room:member:wx_a'";

        // 加 (joined_at=1000)
        upsert_chatroom_member_add(&conn, &sample_member("room:member:wx_a", 1000)).unwrap();

        // 退 (left_at=2000) — joined_at 保留 1000
        assert_eq!(
            mark_chatroom_member_left(&conn, "acct_sha", "chatroom.db", "room:member:wx_a", 2000).unwrap(),
            1
        );
        let (g, j, l): (bool, Option<i64>, Option<i64>) = conn
            .query_row(q, [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert!(!g, "退群 is_in_group=0");
        assert_eq!(j, Some(1000), "退群保留 joined_at 不动");
        assert_eq!(l, Some(2000));

        // 再加 (joined_at=3000 重置) — 复活
        upsert_chatroom_member_add(&conn, &sample_member("room:member:wx_a", 3000)).unwrap();
        let (g, j, l): (bool, Option<i64>, Option<i64>) = conn
            .query_row(q, [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert!(g, "再加复活 is_in_group=1");
        assert_eq!(j, Some(3000), "再加重置 joined_at 1000→3000");
        assert_eq!(l, None, "再加 left_at 清空");

        // 再退 (left_at=4000)
        mark_chatroom_member_left(&conn, "acct_sha", "chatroom.db", "room:member:wx_a", 4000).unwrap();
        let (g, j): (bool, Option<i64>) = conn
            .query_row(
                "SELECT is_in_group, joined_at FROM chatroom_member WHERE source_native_id='room:member:wx_a'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(!g);
        assert_eq!(j, Some(3000), "再退保留再加时的 joined_at 3000");

        // 全程同 PK → 1 行 (REPLACE 会丢历史/产 0 行, 这里用 UPDATE 留当前状态)
        let count: i64 = conn
            .query_row("SELECT count(*) FROM chatroom_member", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "先退后加再退全程 1 行");
    }

    /// member_remove on 不在业务表的 PK → 0 行 (调用方据此写 error 事件; archive 仍先写).
    #[test]
    fn chatroom_member_remove_missing_pk_returns_zero() {
        let (_d, conn) = open_inited();
        init_chatroom_member_table(&conn).unwrap();
        let affected = mark_chatroom_member_left(&conn, "acct_sha", "chatroom.db", "room:member:ghost", 5000).unwrap();
        assert_eq!(affected, 0, "PK 不在表 → 0 行 (非报错, 交调用方决策)");
    }

    /// 查询当前在群 WHERE is_in_group=1 排除已退群; 不加该条件查曾在群.
    #[test]
    fn chatroom_member_query_current_excludes_left() {
        let (_d, conn) = open_inited();
        init_chatroom_member_table(&conn).unwrap();
        upsert_chatroom_member_add(&conn, &sample_member("room:member:wx_a", 1000)).unwrap();
        upsert_chatroom_member_add(&conn, &sample_member("room:member:wx_b", 1000)).unwrap();
        mark_chatroom_member_left(&conn, "acct_sha", "chatroom.db", "room:member:wx_b", 2000).unwrap();
        let current: i64 = conn
            .query_row("SELECT count(*) FROM chatroom_member WHERE is_in_group=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(current, 1, "当前在群仅 wx_a");
        let ever: i64 = conn
            .query_row("SELECT count(*) FROM chatroom_member", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ever, 2, "曾在群 (含退群 wx_b) 共 2");
    }

    /// chatroom_member 表恰 9 列 + 2 索引均建.
    #[test]
    fn chatroom_member_table_shape() {
        let (_d, conn) = open_inited();
        init_chatroom_member_table(&conn).unwrap();
        let col_count: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('chatroom_member')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            col_count, 15,
            "chatroom_member 表恰 15 列 (9 + 4 明文 + role 第八批 + invited_by 第九批)"
        );
        let idx_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='chatroom_member' AND name IN ('idx_chatroom_member_chatroom','idx_chatroom_member_wxid')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 2, "chatroom_member 2 索引均建");
    }

    /// 字段扩充第八批 (2026-07-02): role 落库回查 + 旧 13 列表 ensure ALTER 补 role。
    #[test]
    fn chatroom_member_role_roundtrip_and_migrate() {
        let (_d, conn) = open_inited();
        init_chatroom_member_table(&conn).unwrap();
        let mut m = sample_member("room:member:admin", 1000);
        m.role = "admin".to_string();
        m.invited_by = Some("wxid_inviter_a".to_string());
        upsert_chatroom_member_add(&conn, &m).unwrap();
        let (role, inv): (String, Option<String>) = conn
            .query_row(
                "SELECT role, invited_by FROM chatroom_member WHERE source_native_id='room:member:admin'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(role, "admin", "role 落库回查");
        assert_eq!(inv.as_deref(), Some("wxid_inviter_a"), "invited_by 落库回查 (第九批)");

        // 旧 13 列表 (无 role) → init 的 ensure ALTER 补 role DEFAULT 'member'; insert 不报 no column。
        let (_d2, conn2) = open_inited();
        conn2
            .execute_batch(
                "CREATE TABLE chatroom_member (
                    account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                    chatroom_id_sha TEXT NOT NULL, member_wxid_sha TEXT NOT NULL,
                    account_id TEXT NOT NULL, chatroom_id TEXT NOT NULL, member_wxid TEXT NOT NULL,
                    display_name TEXT, display_name_len INTEGER NOT NULL,
                    joined_at INTEGER, left_at INTEGER, is_in_group INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (account_id_sha, source, source_native_id))",
            )
            .unwrap();
        // codex P2: 旧表**已有行** (13 列无 role) → ALTER ADD role DEFAULT 'member' 应回填此行。
        conn2
            .execute(
                "INSERT INTO chatroom_member (account_id_sha, source, source_native_id, chatroom_id_sha, member_wxid_sha, \
                 account_id, chatroom_id, member_wxid, display_name, display_name_len, joined_at, left_at, is_in_group) \
                 VALUES ('a','chatroom.db','room:member:old','rs','ms','wxid_acct','room@chatroom','wxid_old',NULL,0,NULL,NULL,1)",
                [],
            )
            .unwrap();
        init_chatroom_member_table(&conn2).unwrap(); // ensure ALTER 补 role, 旧行回填 DEFAULT 'member'
        let cols: i64 = conn2
            .query_row("SELECT count(*) FROM pragma_table_info('chatroom_member')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(cols, 15, "旧 13 列 → ALTER 补 role + invited_by = 15");
        let old_role: String = conn2
            .query_row(
                "SELECT role FROM chatroom_member WHERE source_native_id='room:member:old'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old_role, "member", "旧行被 ALTER ADD ... DEFAULT 'member' 回填");
        upsert_chatroom_member_add(&conn2, &sample_member("room:member:mig", 1)).unwrap(); // 不报 no column
        let role2: String = conn2
            .query_row(
                "SELECT role FROM chatroom_member WHERE source_native_id='room:member:mig'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(role2, "member", "旧表补 role 后 insert 成功 (DEFAULT member)");
    }

    // ── ADR-426 明文列 round-trip (insert → 查回明文列断言原值, 卡死 DDL/insert 列↔params 错配) ──

    /// chatroom 5 明文列 insert→查回断言原值.
    #[test]
    fn chatroom_plaintext_columns_round_trip() {
        let (_d, conn) = open_inited();
        init_chatroom_table(&conn).unwrap();
        let mut c = sample_chatroom("room_p@chatroom", 3, Some("owner_sha"));
        c.account_id = "wxid_acct_real".into();
        c.chatroom_id = "room_real@chatroom".into();
        c.owner_wxid = Some("wxid_owner_real".into());
        c.chatroom_name = "真实群名".into();
        c.announcement = Some("真实公告".into());
        insert_chatroom(&conn, &c).unwrap();
        let (acct, room, owner, name, ann): (String, String, Option<String>, String, Option<String>) = conn
            .query_row(
                "SELECT account_id, chatroom_id, owner_wxid, chatroom_name, announcement FROM chatroom WHERE source_native_id='room_p@chatroom'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(acct, "wxid_acct_real");
        assert_eq!(room, "room_real@chatroom");
        assert_eq!(owner.as_deref(), Some("wxid_owner_real"));
        assert_eq!(name, "真实群名");
        assert_eq!(ann.as_deref(), Some("真实公告"));
    }

    /// session 2 明文列 insert→查回断言原值 (无投影, 仅 storage 双轨防回归).
    #[test]
    fn session_plaintext_columns_round_trip() {
        let (_d, conn) = open_inited();
        init_session_table(&conn).unwrap();
        let mut s = sample_session("sess_p", 1, 1_700_000_000);
        s.account_id = "wxid_acct_real".into();
        s.username = "wxid_peer_real".into();
        insert_session(&conn, &s).unwrap();
        let (acct, user): (String, String) = conn
            .query_row(
                "SELECT account_id, username FROM session WHERE source_native_id='sess_p'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(acct, "wxid_acct_real");
        assert_eq!(user, "wxid_peer_real");
    }

    /// session 手写 Debug 脱敏: struct 含明文 account_id/username 但 Debug 输出不露裸值
    /// (session 无投影 → 无 projection 层 no_raw_leak, 故在此单测 K-R4 出口).
    #[test]
    fn session_debug_redacts_plaintext() {
        let mut s = sample_session("sess_d", 0, 1);
        s.account_id = "wxid_acct_secret".into();
        s.username = "wxid_peer_secret".into();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("wxid_acct_secret"), "account_id 明文不入 Debug");
        assert!(!dbg.contains("wxid_peer_secret"), "username 明文不入 Debug");
    }

    /// person_alias 4 明文列 insert→查回断言原值.
    #[test]
    fn person_alias_plaintext_columns_round_trip() {
        let (_d, conn) = open_inited();
        init_person_alias_table(&conn).unwrap();
        let mut a = sample_alias("user_p_sha", Some("remark_sha"), Some("nick_sha"));
        a.account_id = "wxid_acct_real".into();
        a.username = "wxid_user_real".into();
        a.remark = Some("真实备注".into());
        a.nick_name = Some("真实昵称".into());
        insert_person_alias(&conn, &a).unwrap();
        let (acct, user, remark, nick): (String, String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT account_id, username, remark, nick_name FROM person_alias_by_account_min WHERE username_sha='user_p_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(acct, "wxid_acct_real");
        assert_eq!(user, "wxid_user_real");
        assert_eq!(remark.as_deref(), Some("真实备注"));
        assert_eq!(nick.as_deref(), Some("真实昵称"));
    }

    /// chatroom_member 4 明文列 insert→查回断言原值 (member_wxid 明文是退群闭环回读源).
    #[test]
    fn chatroom_member_plaintext_columns_round_trip() {
        let (_d, conn) = open_inited();
        init_chatroom_member_table(&conn).unwrap();
        let mut m = sample_member("room:member:wx_p", 1000);
        m.account_id = "wxid_acct_real".into();
        m.chatroom_id = "room_real@chatroom".into();
        m.member_wxid = "wxid_member_real".into();
        m.display_name = Some("群昵称真实".into());
        upsert_chatroom_member_add(&conn, &m).unwrap();
        let (acct, room, member, disp): (String, String, String, Option<String>) = conn
            .query_row(
                "SELECT account_id, chatroom_id, member_wxid, display_name FROM chatroom_member WHERE source_native_id='room:member:wx_p'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(acct, "wxid_acct_real");
        assert_eq!(room, "room_real@chatroom");
        assert_eq!(member, "wxid_member_real", "member_wxid 明文回读 (退群闭环源)");
        assert_eq!(disp.as_deref(), Some("群昵称真实"));
    }

    // ── schema_meta 登记表 ──

    /// set_meta 写入回读; 缺 key → None.
    #[test]
    fn schema_meta_set_get_and_missing() {
        let (_d, conn) = open_inited();
        init_schema_meta_table(&conn).unwrap();
        set_meta(&conn, META_KEY_VERSION, "1", 1000).unwrap();
        assert_eq!(get_meta(&conn, META_KEY_VERSION).unwrap(), Some("1".to_string()));
        assert_eq!(
            get_meta(&conn, "nonexistent_key").unwrap(),
            None,
            "缺 key → None 不报错"
        );
    }

    /// R9 codex-R10: L1 实例代号 —— 建库写一次(随机)、同库幂等不变、异库不同、无表 → None。`new` 水位跨重建检测的地基。
    #[test]
    fn l1_generation_stable_idempotent_and_unique() {
        let conn = Connection::open_in_memory().unwrap();
        init_l1_generation(&conn).unwrap();
        let g1 = get_l1_generation(&conn).unwrap();
        assert!(
            g1.as_deref().is_some_and(|g| g.len() == 32),
            "建库后有 32 hex 代号, 实得 {g1:?}"
        );
        init_l1_generation(&conn).unwrap(); // INSERT OR IGNORE: 同库再调不变
        assert_eq!(get_l1_generation(&conn).unwrap(), g1, "同 L1 再 init 代号稳定不变");
        let conn2 = Connection::open_in_memory().unwrap(); // 无表 → None (旧库)
        assert_eq!(get_l1_generation(&conn2).unwrap(), None, "无 l1_generation 表 → None");
        init_l1_generation(&conn2).unwrap();
        assert_ne!(
            get_l1_generation(&conn2).unwrap(),
            g1,
            "另一 L1 随机代号不同 (重建=新代号)"
        );
    }

    /// 同 key INSERT OR REPLACE: 不增行 + value/updated_at 刷新.
    #[test]
    fn schema_meta_set_overwrites_same_key() {
        let (_d, conn) = open_inited();
        init_schema_meta_table(&conn).unwrap();
        set_meta(&conn, META_KEY_APP_VERSION, "0.1.0-alpha", 1000).unwrap();
        set_meta(&conn, META_KEY_APP_VERSION, "0.2.0", 2000).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM schema_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 key upsert 不增行");
        let (val, ts): (String, i64) = conn
            .query_row(
                "SELECT value, updated_at FROM schema_meta WHERE key='app_version'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(val, "0.2.0", "value 刷新");
        assert_eq!(ts, 2000, "updated_at 刷新");
    }

    /// seed_schema_meta 播种 5 个 well-known key + 表恰 3 列.
    #[test]
    fn schema_meta_seed_writes_5_keys() {
        let (_d, conn) = open_inited();
        init_schema_meta_table(&conn).unwrap();
        seed_schema_meta(&conn, "acct_wxid_sha", "0.1.0-alpha", 1_700_000_000, 1_700_000_500).unwrap();
        assert_eq!(
            get_meta(&conn, META_KEY_VERSION).unwrap(),
            Some(SCHEMA_VERSION.to_string()),
            "version=当前 SCHEMA_VERSION(R14 起 2)"
        );
        assert_eq!(
            get_meta(&conn, META_KEY_ACCOUNT_ID_SHA).unwrap(),
            Some("acct_wxid_sha".to_string()),
            "锁文件归属"
        );
        assert_eq!(
            get_meta(&conn, META_KEY_MIGRATION_HISTORY).unwrap(),
            Some("[]".to_string()),
            "初始空数组"
        );
        assert_eq!(
            get_meta(&conn, META_KEY_APP_VERSION).unwrap(),
            Some("0.1.0-alpha".to_string())
        );
        assert_eq!(
            get_meta(&conn, META_KEY_CREATED_AT).unwrap(),
            Some("1700000000".to_string()),
            "i64→字符串"
        );
        let count: i64 = conn
            .query_row("SELECT count(*) FROM schema_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 5, "恰 5 个 well-known key");
        let col_count: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('schema_meta')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(col_count, 3, "schema_meta 表恰 3 列");
    }

    /// R14 迁移门禁: init_l1_schema 真空首建放行 + 播种当前版本; 同库重开放行; 旧库(有 message 表但无 version = R14 前 8hex 锚库)被拒。
    #[test]
    fn init_l1_schema_gates_stale_anchor_db() {
        // 真空首建 → 放行 + 播种当前 SCHEMA_VERSION。
        let conn = Connection::open_in_memory().unwrap();
        init_l1_schema(&conn).unwrap();
        assert_eq!(
            get_meta(&conn, META_KEY_VERSION).unwrap(),
            Some(SCHEMA_VERSION.to_string()),
            "首建播种当前版本"
        );
        // 同库(version=当前)重开 → 放行(幂等续 ingest)。
        init_l1_schema(&conn).unwrap();
        // 模拟旧库: 抹掉 version 行(留 message 表) = R14 前的 8hex 锚库(有数据无版本) → 门禁拒。
        conn.execute("DELETE FROM schema_meta WHERE key=?1", [META_KEY_VERSION])
            .unwrap();
        let err = init_l1_schema(&conn).unwrap_err();
        assert!(
            matches!(&err, rusqlite::Error::SqliteFailure(f, _) if f.extended_code == rusqlite::ffi::SQLITE_MISMATCH),
            "旧库(有表无版本)抛 SQLITE_MISMATCH(供 CLI 分类 SchemaMismatch/退出6): {err}"
        );
        assert!(err.to_string().contains("锚格式过时"), "带删库重建提示: {err}");
        // 旧版本库(有 version 但过时, 如将来 v2→v3 迁移前): stored=Some("1") → 同样拒(Claude P3-6 补分支)。
        conn.execute(
            "INSERT INTO schema_meta(key,value,updated_at) VALUES(?1,'1',0)",
            [META_KEY_VERSION],
        )
        .unwrap();
        let err_old = init_l1_schema(&conn).unwrap_err();
        assert!(
            matches!(&err_old, rusqlite::Error::SqliteFailure(f, _) if f.extended_code == rusqlite::ffi::SQLITE_MISMATCH),
            "旧版本库(version=1 过时)被拒: {err_old}"
        );
    }

    // ── capability_backlog 登记表 ──

    fn sample_backlog(category: &str, name: &str, status: &str) -> V3CapabilityBacklog {
        V3CapabilityBacklog {
            field_category: category.to_string(),
            field_name: name.to_string(),
            src_table: Some("WCDB_Contact.sqlite".to_string()),
            src_column: Some("amount".to_string()),
            reference_project: Some("wx-cli".to_string()),
            target_milestone: "0.2.0".to_string(),
            status: status.to_string(),
            notes: Some("调研中".to_string()),
            updated_at: 1000,
        }
    }

    /// backlog 建表 + 插入回查关键字段.
    #[test]
    fn capability_backlog_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_capability_backlog_table(&conn).unwrap();
        insert_capability_backlog(&conn, &sample_backlog("wallet", "wallet_amount", "unimplemented")).unwrap();
        let (milestone, status, refp): (String, String, Option<String>) = conn
            .query_row(
                "SELECT target_milestone, status, reference_project FROM capability_backlog WHERE field_category='wallet' AND field_name='wallet_amount'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(milestone, "0.2.0");
        assert_eq!(status, "unimplemented");
        assert_eq!(refp, Some("wx-cli".to_string()));
    }

    /// 同 PK (field_category, field_name) upsert: status 推进 unimplemented→shipped, 不增行.
    #[test]
    fn capability_backlog_upsert_status_change() {
        let (_d, conn) = open_inited();
        init_capability_backlog_table(&conn).unwrap();
        insert_capability_backlog(&conn, &sample_backlog("wallet", "wallet_amount", "unimplemented")).unwrap();
        insert_capability_backlog(&conn, &sample_backlog("wallet", "wallet_amount", "shipped")).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM capability_backlog", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 PK upsert 不增行");
        let status: String = conn
            .query_row(
                "SELECT status FROM capability_backlog WHERE field_name='wallet_amount'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "shipped", "status 推进 unimplemented→shipped");
    }

    /// nullable src_table/src_column/reference_project/notes 都 None → NULL + 表恰 9 列 + 2 索引.
    #[test]
    fn capability_backlog_nullable_and_shape() {
        let (_d, conn) = open_inited();
        init_capability_backlog_table(&conn).unwrap();
        let b = V3CapabilityBacklog {
            field_category: "miniprogram".to_string(),
            field_name: "mp_usage".to_string(),
            src_table: None,
            src_column: None,
            reference_project: None,
            target_milestone: "1.0.0+".to_string(),
            status: "researching".to_string(),
            notes: None,
            updated_at: 2000,
        };
        insert_capability_backlog(&conn, &b).unwrap();
        let (st, sc, rp, nt): (Option<String>, Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT src_table, src_column, reference_project, notes FROM capability_backlog WHERE field_name='mp_usage'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (st, sc, rp, nt),
            (None, None, None, None),
            "4 nullable 字段调研中可空 → NULL"
        );
        let col_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('capability_backlog')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(col_count, 9, "capability_backlog 表恰 9 列");
        let idx_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='capability_backlog' AND name IN ('idx_backlog_status','idx_backlog_milestone')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 2, "capability_backlog 2 索引均建");
    }

    // ── §3.2 source_db_catalog 表 ──

    fn sample_db_catalog(path_sha: &str, size: i64, scanned: i64) -> V3SourceDbCatalog {
        V3SourceDbCatalog {
            account_id_sha: "acct_sha".to_string(),
            db_path_sha: path_sha.to_string(),
            db_path: None,
            db_size_bytes: size,
            db_mtime: 1_700_000_000,
            db_kind: "message".to_string(),
            last_scanned_at: scanned,
        }
    }

    /// source_db_catalog 建表 + 插入回查 (db_path 默认 NULL = sha 模式).
    #[test]
    fn source_db_catalog_insert_then_query_back() {
        let (_d, conn) = open_inited();
        init_source_db_catalog_table(&conn).unwrap();
        insert_source_db_catalog(&conn, &sample_db_catalog("path_a_sha", 4096, 100)).unwrap();
        let (kind, size, path): (String, i64, Option<String>) = conn
            .query_row(
                "SELECT db_kind, db_size_bytes, db_path FROM source_db_catalog WHERE db_path_sha='path_a_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(kind, "message");
        assert_eq!(size, 4096);
        assert_eq!(path, None, "默认 sha 模式 db_path NULL");
    }

    /// 同 PK upsert (重扫): 不增行 + db_size_bytes/last_scanned 刷新.
    #[test]
    fn source_db_catalog_upsert_refresh() {
        let (_d, conn) = open_inited();
        init_source_db_catalog_table(&conn).unwrap();
        insert_source_db_catalog(&conn, &sample_db_catalog("path_a_sha", 4096, 100)).unwrap();
        insert_source_db_catalog(&conn, &sample_db_catalog("path_a_sha", 8192, 200)).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM source_db_catalog", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 PK 重扫不增行");
        let (size, scanned): (i64, i64) = conn
            .query_row(
                "SELECT db_size_bytes, last_scanned_at FROM source_db_catalog WHERE db_path_sha='path_a_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(size, 8192, "db_size 刷新 4096→8192");
        assert_eq!(scanned, 200, "last_scanned 刷新");
    }

    /// K-R4: db_path 明文 (含 wxid) 绝不入 Debug — 手写 Debug 只示 redacted + db_path_sha.
    #[test]
    fn source_db_catalog_debug_redacts_path() {
        let c = V3SourceDbCatalog {
            account_id_sha: "acct_sha".to_string(),
            db_path_sha: "path_sha_visible".to_string(),
            db_path: Some(r"C:\WeChat Files\wxid_secret123\Msg\message_5.db".to_string()),
            db_size_bytes: 100,
            db_mtime: 1,
            db_kind: "message".to_string(),
            last_scanned_at: 2,
        };
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("wxid_secret123"), "K-R4: 明文路径含 wxid 绝不入 Debug");
        assert!(!dbg.contains("WeChat Files"), "K-R4: 明文路径绝不入 Debug");
        assert!(dbg.contains("redacted"), "db_path 示 <redacted>");
        assert!(dbg.contains("path_sha_visible"), "db_path_sha (已脱敏) 可见");
    }

    /// source_db_catalog 表恰 7 列 + 1 索引 idx_db_catalog_kind.
    #[test]
    fn source_db_catalog_shape() {
        let (_d, conn) = open_inited();
        init_source_db_catalog_table(&conn).unwrap();
        let col_count: i64 = conn
            .query_row("SELECT count(*) FROM pragma_table_info('source_db_catalog')", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(col_count, 7, "source_db_catalog 表恰 7 列");
        let idx: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_db_catalog_kind'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx, 1, "idx_db_catalog_kind 建");
    }

    // ── §3.2 source_chat_index / chat_to_db / db_timerange / query_plans ──

    fn tbl_cols(conn: &Connection, tbl: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM pragma_table_info('{tbl}')"), [], |r| {
            r.get(0)
        })
        .unwrap()
    }
    fn idx_exists(conn: &Connection, name: &str) -> i64 {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?1",
            params![name],
            |r| r.get(0),
        )
        .unwrap()
    }
    /// 用户建的二级索引数 (排除 PK 的 sqlite_autoindex_%) — 证"无索引"表确实无.
    fn user_index_count(conn: &Connection, tbl: &str) -> i64 {
        conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name=?1 AND name NOT LIKE 'sqlite_autoindex_%'",
            params![tbl], |r| r.get(0),
        ).unwrap()
    }

    /// source_chat_index: 插入回查 (count/last_msg_time 未扫前 None) + 5 列 + idx_chat_index_db.
    #[test]
    fn source_chat_index_insert_query_shape() {
        let (_d, conn) = open_inited();
        init_source_chat_index_table(&conn).unwrap();
        let c = V3SourceChatIndex {
            account_id_sha: "acct".to_string(),
            chat_id_sha: "chat_sha".to_string(),
            db_path_sha: "db_sha".to_string(),
            message_count: None,
            last_msg_time: None,
        };
        insert_source_chat_index(&conn, &c).unwrap();
        let (mc, lmt): (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT message_count, last_msg_time FROM source_chat_index WHERE chat_id_sha='chat_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((mc, lmt), (None, None), "未扫前 nullable NULL");
        assert_eq!(tbl_cols(&conn, "source_chat_index"), 5, "5 列");
        assert_eq!(idx_exists(&conn, "idx_chat_index_db"), 1, "idx_chat_index_db 建");
    }

    /// source_chat_to_db 物化聚合: 插入回查 + 6 列.
    #[test]
    fn source_chat_to_db_insert_query_shape() {
        let (_d, conn) = open_inited();
        init_source_chat_to_db_table(&conn).unwrap();
        let c = V3SourceChatToDb {
            account_id_sha: "acct".to_string(),
            chat_id_sha: "chat_sha".to_string(),
            total_message_count: 500,
            db_count: 3,
            first_msg_time: Some(1000),
            last_msg_time: Some(2000),
        };
        insert_source_chat_to_db(&conn, &c).unwrap();
        let (total, dbc): (i64, i64) = conn
            .query_row(
                "SELECT total_message_count, db_count FROM source_chat_to_db WHERE chat_id_sha='chat_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((total, dbc), (500, 3), "chat 分布在 3 个 db 共 500 条");
        assert_eq!(tbl_cols(&conn, "source_chat_to_db"), 6, "6 列");
        assert_eq!(
            user_index_count(&conn, "source_chat_to_db"),
            0,
            "物化聚合表无二级索引 (PK 即查询键)"
        );
    }

    /// source_db_timerange: 插入 min/max None (空 db/未扫) → NULL round-trip + 4 列.
    #[test]
    fn source_db_timerange_nullable_shape() {
        let (_d, conn) = open_inited();
        init_source_db_timerange_table(&conn).unwrap();
        let t = V3SourceDbTimerange {
            account_id_sha: "acct".to_string(),
            db_path_sha: "db_sha".to_string(),
            min_msg_time: None,
            max_msg_time: None,
        };
        insert_source_db_timerange(&conn, &t).unwrap();
        let (mn, mx): (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT min_msg_time, max_msg_time FROM source_db_timerange WHERE db_path_sha='db_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((mn, mx), (None, None), "空 db/未扫 min/max NULL");
        assert_eq!(tbl_cols(&conn, "source_db_timerange"), 4, "4 列");
        assert_eq!(
            user_index_count(&conn, "source_db_timerange"),
            0,
            "无二级索引 (PK 即查询键)"
        );
    }

    /// source_query_plans: 插入 + 同 PK 复用刷新 hit_count/last_used_at 不增行 + 6 列 + LRU 索引.
    #[test]
    fn source_query_plans_insert_upsert_shape() {
        let (_d, conn) = open_inited();
        init_source_query_plans_table(&conn).unwrap();
        let mk = |hits: i64, used: i64| V3SourceQueryPlan {
            account_id_sha: "acct".to_string(),
            query_signature_sha: "sig_sha".to_string(),
            plan_json: r#"{"scan":["db_sha"]}"#.to_string(),
            estimated_cost: Some(42),
            last_used_at: used,
            hit_count: hits,
        };
        insert_source_query_plan(&conn, &mk(1, 100)).unwrap();
        insert_source_query_plan(&conn, &mk(2, 200)).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM source_query_plans", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "同 PK 复用不增行");
        let (hits, used): (i64, i64) = conn
            .query_row(
                "SELECT hit_count, last_used_at FROM source_query_plans WHERE query_signature_sha='sig_sha'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((hits, used), (2, 200), "hit_count/last_used_at 刷新");
        assert_eq!(tbl_cols(&conn, "source_query_plans"), 6, "6 列");
        assert_eq!(idx_exists(&conn, "idx_query_plans_lru"), 1, "idx_query_plans_lru 建");
        // LRU 索引方向: last_used_at 必须 DESC (淘汰策略依赖)
        let lru_desc: i64 = conn
            .query_row(
                "SELECT \"desc\" FROM pragma_index_xinfo('idx_query_plans_lru') WHERE name='last_used_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lru_desc, 1, "idx_query_plans_lru 的 last_used_at 是 DESC");
    }

    // ── 件⑤: schema 迁移守卫 (旧库物化) ──
    //
    // 守的 bug: 给某表 CREATE TABLE 加了列, 却忘了在该表 ensure_*_columns 迁移函数里也加 → fresh 库没事
    // (CREATE 直接建全列), 但**旧库** (加列之前建的) 永远拿不到新列 → 下次全列 INSERT 抛 "table X has no
    // column named Y" 崩 (真实事故 message_location 10→13, 修 6d1f6da)。
    //
    // ⚠ 反乏味: 拿 **fresh 库**反射列集比 CREATE 声明列集是**重言式** (fresh 库上 ensure_* 是死代码, CREATE
    // 已建全列 → 反射==声明与迁移函数对不对无关), 抓不到"某 GROW 表缺可用迁移"。bug 只在**旧库**发作。所以这里
    // **物化一个旧 (缺列) 库 → 跑真实 init/ensure 迁移路径 → 断言列补齐 + 全列 insert 不抛** (抄
    // `old_23col_message_migrates_server_seq` / `message_location_migrate_old_10col_table` 两个现成范式,
    // 泛化到每张 GROW 表)。**本文件不引入 fresh-vs-声明-const 比较** — 那正是上面警告的乏味写法, 真实覆盖靠下面
    // 的逐表旧库测。

    /// 一张 GROW 表 (有 `ensure_*_columns` 迁移函数) 的登记项。
    struct GrowTableSpec {
        /// 表名 (PRAGMA / SQL 用)。
        table: &'static str,
        /// 该表迁移函数的**函数名** (源码扫描守卫用; 须与真实 `ensure_*_columns` 定义名逐字一致)。
        ensure_fn: &'static str,
        /// 生产迁移入口 `init_*_table` (跑真实路径: CREATE IF NOT EXISTS 对旧表 no-op + ensure_* ALTER 补列)。
        init_fn: fn(&Connection) -> rusqlite::Result<()>,
        /// `ensure_*` 能 ALTER-ADD 的 GROW 列 (旧库缺列迁移的靶子; 逐字抄自对应 ensure 函数体)。
        grow_cols: &'static [&'static str],
    }

    /// GROW 表登记表 — 每张有 `ensure_*_columns` 的表在册。**新加一张 GROW 表却没登记 →
    /// `grow_table_registry_covers_every_ensure_fn` FAIL** (源码扫描比对, 逼后来人不能偷偷跳过迁移)。
    /// grow_cols 逐字抄自各 ensure 函数体 (若抄错/漏, `grow_tables_migrate_from_old_db` 会当场 FAIL)。
    const GROW_TABLES: &[GrowTableSpec] = &[
        GrowTableSpec {
            table: "message",
            ensure_fn: "ensure_message_columns",
            init_fn: init_message_table,
            grow_cols: &[
                "server_seq",
                "origin_source",
                "upload_status",
                "download_status",
                "sys_type",
            ],
        },
        GrowTableSpec {
            table: "person",
            ensure_fn: "ensure_person_extra_columns",
            init_fn: init_person_table,
            grow_cols: &[
                // ensure_person_extra_columns TEXT 组
                "quan_pin",
                "pin_yin_initial",
                "remark_quan_pin",
                "remark_pin_yin_initial",
                "big_head_url",
                "small_head_url",
                "head_img_md5",
                "description",
                "country",
                "province",
                "city",
                "signature",
                "moments_cover_url",
                "labels",
                "openim_company",
                "openim_realname",
                // ensure_person_extra_columns INTEGER NOT NULL DEFAULT 0 组
                "verify_flag",
                "delete_flag",
                "flag",
                "chat_room_notify",
                "chat_room_type",
                "sex",
                "friend_source",
                "is_starred",
                "is_collapsed",
                "is_pinned",
                "blocks_moments",
                "hide_their_moments",
                "chat_only",
                "is_muted",
                // ADR-486 nullable INTEGER
                "friend_add_time",
            ],
        },
        GrowTableSpec {
            table: "chatroom",
            ensure_fn: "ensure_chatroom_columns",
            init_fn: init_chatroom_table,
            grow_cols: &[
                "announcement_editor",
                "announcement_publish_time",
                "xml_announcement",
                "chat_room_status",
                "chatroom_remark",
                "chatroom_remark_len",
                "is_still_member",
            ],
        },
        GrowTableSpec {
            table: "session",
            ensure_fn: "ensure_session_columns",
            init_fn: init_session_table,
            grow_cols: &[
                // 明文列 (旧 9 列库缺 ADR-426 明文列时也迁)
                "account_id",
                "username",
                // 展示/状态/第六批 metadata
                "summary_len",
                "summary",
                "last_sender_len",
                "last_sender_display_name",
                "session_type",
                "is_hidden",
                "status",
                "draft_len",
                "draft",
                "last_msg_sender",
                "last_timestamp",
                "last_clear_unread_timestamp",
                "last_msg_locald_id",
                "last_msg_ext_type",
                "unread_first_msg_srv_id",
            ],
        },
        GrowTableSpec {
            table: "favorite",
            ensure_fn: "ensure_favorite_columns",
            init_fn: init_favorite_table,
            grow_cols: &["note_text"],
        },
        GrowTableSpec {
            table: "moment",
            ensure_fn: "ensure_moment_columns",
            init_fn: init_moment_table,
            grow_cols: &[
                "source_nickname",
                "public_user_name",
                "app_name",
                "is_bidirectional_fan",
                "is_rich_text",
            ],
        },
        GrowTableSpec {
            table: "message_app",
            ensure_fn: "ensure_message_app_columns",
            init_fn: init_message_app_table,
            grow_cols: &[
                "file_size",
                "file_ext",
                "file_md5",
                "transfer_fee",
                "transfer_direction",
                "transfer_txid",
                "refer_svrid",
                "refer_type",
                "refer_content",
                "forward_item_count",
                "red_envelope_wish",
                "red_envelope_count",
                "group_pay_amount",
                "group_pay_bill_no",
                "music_desc",
                "gift_wish",
                "gift_sku",
                "live_status",
                "live_desc",
                "pay_scene_text",
            ],
        },
        GrowTableSpec {
            table: "message_location",
            ensure_fn: "ensure_message_location_columns",
            init_fn: init_message_location_table,
            grow_cols: &["maptype", "adcode", "cityname"],
        },
        GrowTableSpec {
            table: "chatroom_member",
            ensure_fn: "ensure_chatroom_member_columns",
            init_fn: init_chatroom_member_table,
            grow_cols: &["role", "invited_by"],
        },
    ];

    /// `PRAGMA table_info(table)` → (name, type, notnull, dflt_value, pk-position)。
    fn column_defs(conn: &Connection, table: &str) -> Vec<(String, String, bool, Option<String>, i64)> {
        conn.prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,         // name
                    r.get::<_, String>(2)?,         // declared type
                    r.get::<_, i64>(3)? != 0,       // notnull
                    r.get::<_, Option<String>>(4)?, // dflt_value (NULL=无默认)
                    r.get::<_, i64>(5)?,            // pk position (0=非PK)
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// 某表当前列名**集合** (顺序无关 — 物理列序 fresh vs migrated 可不同, 如 person 分组追加; 但按列名
    /// INSERT 与序无关, "列集相等"才是要守的不变量)。
    fn col_name_set(conn: &Connection, table: &str) -> std::collections::BTreeSet<String> {
        column_defs(conn, table).into_iter().map(|d| d.0).collect()
    }

    /// 物化一张**旧 (缺 drop_cols) 库** — 照 fresh 库 PRAGMA 重建 CREATE, 去掉 drop_cols, 保留其余列的
    /// 类型 / NOT NULL / DEFAULT + 复合 PK = "加 GROW 列之前"的旧 schema。
    fn materialize_old_table(old: &Connection, fresh: &Connection, table: &str, drop_cols: &[&str]) {
        let defs = column_defs(fresh, table);
        let mut cols = Vec::new();
        let mut pk: Vec<(i64, String)> = Vec::new();
        for (name, ty, notnull, dflt, pkpos) in &defs {
            if drop_cols.contains(&name.as_str()) {
                continue;
            }
            let mut s = if ty.is_empty() {
                name.clone()
            } else {
                format!("{name} {ty}")
            };
            if *notnull {
                s.push_str(" NOT NULL");
            }
            if let Some(d) = dflt {
                // clippy format_push_string: d 是 &String, 直接 push_str 两段, 免中间 format! 分配。
                s.push_str(" DEFAULT ");
                s.push_str(d);
            }
            cols.push(s);
            if *pkpos > 0 {
                pk.push((*pkpos, name.clone()));
            }
        }
        pk.sort_by_key(|(p, _)| *p);
        let pk_clause = if pk.is_empty() {
            String::new()
        } else {
            format!(
                ", PRIMARY KEY ({})",
                pk.into_iter().map(|(_, n)| n).collect::<Vec<_>>().join(", ")
            )
        };
        old.execute_batch(&format!(
            "DROP TABLE IF EXISTS {table}; CREATE TABLE {table} ({}{pk_clause});",
            cols.join(", ")
        ))
        .unwrap();
    }

    /// 用**当前全列形状**造一条 INSERT (列清单 = fresh CREATE 全列, 同生产 `insert_*` 的列清单) 并执行。
    /// 合成值按声明类型给 (满足 NOT NULL); 单行无 PK 冲突 → **唯一可能的失败就是"迁移漏列 → no column named"**。
    fn insert_full_shape(
        conn: &Connection,
        table: &str,
        fresh_defs: &[(String, String, bool, Option<String>, i64)],
    ) -> rusqlite::Result<()> {
        let mut cols = Vec::new();
        let mut vals = Vec::new();
        for (name, ty, _, _, _) in fresh_defs {
            cols.push(name.clone());
            let up = ty.to_uppercase();
            let v = if up.contains("INT") {
                "0"
            } else if up.contains("REAL") || up.contains("FLOA") || up.contains("DOUB") {
                "0.0"
            } else if up.contains("CHAR") || up.contains("TEXT") || up.contains("CLOB") {
                "'x'"
            } else {
                "0" // BLOB / 无类型: 数值字面量 (BLOB affinity + NOT NULL 都能收)
            };
            vals.push(v.to_string());
        }
        conn.execute(
            &format!("INSERT INTO {table} ({}) VALUES ({})", cols.join(", "), vals.join(", ")),
            [],
        )?;
        Ok(())
    }

    /// 扫本文件源码找出所有 `ensure_*_columns` 迁移函数**定义名** (注册表守卫用 — 手写扫描, 不引 regex)。
    /// 只认 `fn ` 紧跟的 `ensure_...` 且以 `_columns` 收尾的标识符 (定义处才有 `fn ` 前缀; 调用处/字符串不算)。
    fn scan_ensure_fn_names(src: &str) -> std::collections::BTreeSet<String> {
        let mut set = std::collections::BTreeSet::new();
        for (i, _) in src.match_indices("fn ensure_") {
            let rest = &src[i + 3..]; // 跳过 "fn "
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            if name.ends_with("_columns") {
                set.insert(name);
            }
        }
        set
    }

    /// 从源码切出 `fn {name}` 的**完整函数源码** (签名 + 体), 用字符串感知的花括号配对定界:
    /// 从 `fn {name}` 后第一个 `{` 起, 跳过字符串字面量内的花括号 (format 串里的 `{col}`/`{coltype}`),
    /// 配到 depth 归零的 `}` 收尾。切片从 `fn` 起 → **不含前置 doc 注释**, 不会误吞相邻函数的注释文本。
    /// (字节级扫 ASCII 定界符; UTF-8 续字节 ≥0x80 不与 `"`/`{`/`}`/`\` 冲突, 中文注释安全。)
    fn slice_fn_source<'a>(src: &'a str, name: &str) -> &'a str {
        let needle = format!("fn {name}");
        let start = src
            .find(&needle)
            .unwrap_or_else(|| panic!("源码找不到 `{needle}` 定义"));
        let b = src.as_bytes();
        let mut i = start + needle.len();
        while i < b.len() && b[i] != b'{' {
            i += 1;
        }
        assert!(i < b.len(), "`{needle}` 后找不到函数体起始 `{{`");
        let (mut depth, mut in_str, mut esc) = (0i32, false, false);
        let mut j = i;
        while j < b.len() {
            let c = b[j];
            if in_str {
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
                if depth == 0 {
                    return &src[start..=j];
                }
            }
            j += 1;
        }
        panic!("`{needle}` 花括号未闭合 (切片失败)")
    }

    /// 字符串内容是否"列名" = 小写 snake_case 标识符 `^[a-z][a-z0-9_]*$`。这是本仓库列名的铁律
    /// (60+ 列全小写下划线); 而 ALTER 里的类型串 (`INTEGER`/`TEXT`… 大写)、`PRAGMA …` /
    /// `ALTER TABLE … ADD COLUMN {col} …` 模板 (含空格/大括号) 都不符 → 天然被排除。
    fn is_col_ident(s: &str) -> bool {
        let mut it = s.chars();
        matches!(it.next(), Some(c) if c.is_ascii_lowercase())
            && it.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    /// 扫某 ensure 函数源码, 得它能 `ALTER … ADD COLUMN` 的**列名集合** —— 从**双引号字符串字面量**
    /// (字符串感知, 处理 `\` 转义) 里挑出符合 `is_col_ident` 的内容。覆盖两种 ensure 写法:
    /// (a) 字面 `ADD COLUMN name` —— 列名同时出现在 `existing.contains("name")` 守卫串;
    /// (b) 插值 `ADD COLUMN {col}` —— 列名在 `for col in ["a", …]` / `for (col, ty) in [("a","T"), …]`
    ///     的数组字面量里。两种写法列名都是小写字符串字面量 → 一网打尽; 类型串大写被 is_col_ident 挡掉。
    /// **入参只有函数体源码文本, 不碰 grow_cols → 与被测常量非同源, 非循环论证。**
    ///
    /// ⚠ **假设 / 已知残留(补审 HOLE-1, LOW)**: 列名须以小写 snake **双引号字面量**出现。若将来某列名
    /// 用 `const` / 变量 / `format!` 拼(非字面量)`ADD COLUMN {X}` → 这里看不到、`literal_add_column_targets`
    /// 也看不到(`{X` 非 bareword)→ 若该列同时漏登记 grow_cols, 本守卫**假阴放过**(已实证 Mutation W)。
    /// **加非字面量列名时**: 把列名写成字面量, 或给该表在 migrate 测补一条运行时 schema-delta 断言。
    /// 当前 9 表全用字面量(guard 串 / `for col in ["…"]` 数组), 补审实证 100% 覆盖。
    fn ensure_add_column_cols(body: &str) -> std::collections::BTreeSet<String> {
        assert!(
            body.contains("ADD COLUMN"),
            "函数体无 `ADD COLUMN` (切错函数 / 非 GROW 迁移函数?)"
        );
        let b = body.as_bytes();
        let mut set = std::collections::BTreeSet::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'"' {
                let mut j = i + 1;
                let mut esc = false;
                while j < b.len() {
                    match b[j] {
                        _ if esc => esc = false,
                        b'\\' => esc = true,
                        b'"' => break,
                        _ => {}
                    }
                    j += 1;
                }
                let content = &body[i + 1..j.min(b.len())];
                if is_col_ident(content) {
                    set.insert(content.to_string());
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
        set
    }

    /// 从**字面** `ADD COLUMN <bareword>` 站点直接抽列名 (Pattern A: 非插值; 插值 `{col}` → 空 token 跳过;
    /// 顺带容忍 `IF NOT EXISTS` 前缀)。只用作正交佐证 (须 ⊆ `ensure_add_column_cols`), 坐实"解析集确实
    /// 覆盖了真实 ADD COLUMN 靶", 而非任意小写串。
    fn literal_add_column_targets(body: &str) -> std::collections::BTreeSet<String> {
        let mut set = std::collections::BTreeSet::new();
        for (p, _) in body.match_indices("ADD COLUMN ") {
            let rest = body[p + "ADD COLUMN ".len()..].trim_start();
            let rest = rest.strip_prefix("IF NOT EXISTS ").unwrap_or(rest);
            let tok: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !tok.is_empty() {
                set.insert(tok);
            }
        }
        set
    }

    /// ⑤-1 逐 GROW 表旧库迁移测: 物化缺列旧库 → 跑真实 init/ensure → 列补齐 + 全列 insert 不抛。
    #[test]
    fn grow_tables_migrate_from_old_db() {
        for spec in GROW_TABLES {
            let table = spec.table;
            assert!(
                !spec.grow_cols.is_empty(),
                "[{table}] grow_cols 不能为空 (否则旧库测空转)"
            );

            // fresh 预言器: init_fn 在干净库建**全列** (CREATE 完整, 与 ensure 是否漏无关) → 读 fresh 列集/列定义。
            let (_fd, fresh) = open_inited();
            (spec.init_fn)(&fresh).unwrap();
            let fresh_defs = column_defs(&fresh, table);
            let fresh_cols = col_name_set(&fresh, table);

            // registry 自洽: 每个登记的 grow col 必在 fresh CREATE 里 (抓 registry 拼写/漂移)。
            let grow_set: std::collections::BTreeSet<String> =
                spec.grow_cols.iter().map(|s| (*s).to_string()).collect();
            assert!(
                grow_set.is_subset(&fresh_cols),
                "[{table}] grow_cols 含 fresh CREATE 没有的列 (registry 写错): {:?}",
                grow_set.difference(&fresh_cols).collect::<Vec<_>>()
            );

            // 物化旧库 = fresh 去掉 grow_cols (在**另一条连接**上, 与 fresh 预言器隔离)。
            let (_od, old) = open_inited();
            materialize_old_table(&old, &fresh, table, spec.grow_cols);

            // 反乏味关键前置: 旧库列集须**恰等于** fresh 去掉 grow_cols → 证明 (i) grow 列真被拿掉了
            // (ii) 若下面 ensure 漏 ALTER 就真会缺列。materialize 若出错保留了 grow 列, 这里当场 FAIL (不空转)。
            let expected_old: std::collections::BTreeSet<String> = fresh_cols.difference(&grow_set).cloned().collect();
            let old_before = col_name_set(&old, table);
            assert_eq!(
                old_before, expected_old,
                "[{table}] 物化旧库列集须 == fresh 去掉 grow_cols"
            );
            assert!(
                old_before.len() < fresh_cols.len(),
                "[{table}] 旧库须比 fresh 少列 (证明真在测迁移路径)"
            );

            // 跑**真实生产迁移入口** (CREATE IF NOT EXISTS 对旧表 no-op + ensure_* ALTER 补列)。
            (spec.init_fn)(&old).unwrap();

            // (b) 用当前全列形状 INSERT (= 生产 insert_* 的列清单) 须成功 — 这是要守的 bug 的**真实失败面**:
            //     ensure 漏 ALTER → 旧库缺该列 → 这条 INSERT 抛 "no column named ..."。放最前当主牙 (反例演示的报错口)。
            insert_full_shape(&old, table, &fresh_defs)
                .unwrap_or_else(|e| panic!("[{table}] 旧库迁移后全列 INSERT 失败 (ensure_* 漏 ALTER?): {e}"));

            // (a) 迁移后列集 == fresh CREATE 列集 (顺序无关)。这里**只**保证"旧库迁移后补齐了每个 fresh 列"
            //     (无漏列); 抓不到"ensure ALTER 了 CREATE 没有的列"—— 因为 init_fn 对 fresh 也跑同一 ensure,
            //     fresh 自己也会拿到那列 → 两边都有 → 相等仍成立。列多/列漏的真正守卫是
            //     `grow_cols_pinned_to_ensure_add_column` (grow_cols ↔ 真实 ADD COLUMN 源码站点双向钉死)。
            let old_after = col_name_set(&old, table);
            assert_eq!(old_after, fresh_cols, "[{table}] 旧库迁移后列集须 == fresh CREATE 列集");

            // 幂等: 再跑一次 init/ensure 不炸, 列集不变 (同 message_location 现成范式)。
            (spec.init_fn)(&old).unwrap();
            assert_eq!(col_name_set(&old, table), fresh_cols, "[{table}] 二次 init/ensure 幂等");
        }
    }

    /// ⑤-2 注册表守卫: 每张有 `ensure_*_columns` 的 GROW 表都在 GROW_TABLES 在册。
    /// **新加一张 GROW 表 (新 `ensure_*_columns` 函数) 却没登记 → 这里 FAIL** (源码扫描比对, 逼登记 + 自动补旧库测)。
    #[test]
    fn grow_table_registry_covers_every_ensure_fn() {
        let found = scan_ensure_fn_names(include_str!("storage.rs"));
        let registered: std::collections::BTreeSet<String> =
            GROW_TABLES.iter().map(|g| g.ensure_fn.to_string()).collect();
        assert_eq!(
            found, registered,
            "GROW_TABLES 与源码里的 ensure_*_columns 函数对不上 (左=源码实有, 右=已登记): \
             新增 GROW 表须在 GROW_TABLES 登记, 自动获得逐表旧库迁移测"
        );
        // 冗余兜底: 当前 9 张 GROW 表; 增减须回看本守卫 (顺带确认扫描没吞/多认)。
        assert_eq!(registered.len(), 9, "当前 9 张 GROW 表; 增减须同步此断言 + GROW_TABLES");
    }

    /// R18 件2: thin 续抽水位 KV 往返 + 负向 (无表/未写/空串 → None, 别假报有水位) + key 隔离 (不串到 account 绑定)。
    #[test]
    fn thin_watermark_roundtrip_and_absent_is_none() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // 无 thin_meta 表 → None (向后兼容, 旧 thin 库无 meta 表)。
        assert_eq!(get_thin_watermark(&conn).unwrap(), None, "无 thin_meta 表应 None");
        init_thin_meta(&conn).unwrap();
        // 有表未写 → None (负向: 别把"没水位"报成空串/假值 → daemon 会误以为有续点跳过回补)。
        assert_eq!(get_thin_watermark(&conn).unwrap(), None, "有表未写水位应 None");
        // 往返。
        set_thin_watermark(&conn, "cursor-v1").unwrap();
        assert_eq!(get_thin_watermark(&conn).unwrap().as_deref(), Some("cursor-v1"));
        // upsert 覆盖 (幂等键 watermark)。
        set_thin_watermark(&conn, "cursor-v2").unwrap();
        assert_eq!(
            get_thin_watermark(&conn).unwrap().as_deref(),
            Some("cursor-v2"),
            "upsert 应覆盖旧值"
        );
        // 空串视为无 (与 get_thin_account 同口径, 防"写了空串"当有水位)。
        set_thin_watermark(&conn, "").unwrap();
        assert_eq!(get_thin_watermark(&conn).unwrap(), None, "空串视为无水位");
        // key 隔离: watermark 与 account 绑定各自独立, 互不覆盖。
        set_thin_account(&conn, "acct-sha").unwrap();
        set_thin_watermark(&conn, "cur").unwrap();
        assert_eq!(
            get_thin_account(&conn).unwrap().as_deref(),
            Some("acct-sha"),
            "watermark 不应串到 account"
        );
        assert_eq!(get_thin_watermark(&conn).unwrap().as_deref(), Some("cur"));
    }

    /// ⑤-3 **HOLE-1 守卫**: 把 `grow_cols` 钉死到各 ensure 函数**真实的 ADD COLUMN 列集**上 (双向相等)。
    ///
    /// 为什么需要: `grow_tables_migrate_from_old_db` 靠 `materialize_old_table(.., spec.grow_cols)` **只 drop
    /// grow_cols** 造旧库。若某 GROW 表新加列 Z (CREATE + ensure 都加了) 却**漏登记进 grow_cols** → 物化旧库
    /// 时 Z 不被 drop → 旧库从没缺过 Z → 迁移测永远绿, 而"日后有人删掉 Z 的 ALTER"这个正主 bug **反而漏抓**。
    /// 而 `grow_tables_migrate_from_old_db` 里 `grow_set.is_subset(fresh_cols)` 只挡"grow_cols 写了 fresh 没有
    /// 的列" (多列), **挡不住漏列** (方向反了)。这里从 ensure 函数体源码文本解析真实 ADD COLUMN 列集, 与
    /// grow_cols 常量**双向 assert_eq** → 漏列 / 多列都当场 FAIL。左 (解析) 源自函数体源码, 右 (grow_cols) 源自
    /// 常量数组 → **非同源, 非重言** (解析器签名 `fn(&str) -> …` 只吃源码文本, 结构上不可能循环)。
    #[test]
    fn grow_cols_pinned_to_ensure_add_column() {
        let src = include_str!("storage.rs");
        for spec in GROW_TABLES {
            let table = spec.table;
            let body = slice_fn_source(src, spec.ensure_fn);
            let mut parsed = ensure_add_column_cols(body);
            // R11: note_migration("<表>", …) / count_columns(conn, "<表>") 往函数体引入了**表名**字面量,
            // 它是 col-ident 形态会被 ensure_add_column_cols 当列抽出。表名非列 → 剔除后再比
            //（无任何表有与自身同名的列, 剔除不会掩盖真实列漏登记）。
            parsed.remove(spec.table);
            let grow_set: std::collections::BTreeSet<String> =
                spec.grow_cols.iter().map(|s| (*s).to_string()).collect();

            // 主牙: 真实 ADD COLUMN 列集 (源码) == grow_cols (常量), **双向**。
            assert_eq!(
                parsed,
                grow_set,
                "[{table}] ensure_fn=`{}` 的真实 ADD COLUMN 列集 与 grow_cols 对不上 \
                 (ensure 有但 grow_cols 漏登记={:?}; grow_cols 有但 ensure 无此 ALTER={:?})",
                spec.ensure_fn,
                parsed.difference(&grow_set).collect::<Vec<_>>(),
                grow_set.difference(&parsed).collect::<Vec<_>>(),
            );
            // 解析非空 (防解析失效退化成 {} == {} 的空转)。
            assert!(
                !parsed.is_empty(),
                "[{table}] 从 `{}` 解析出的 ADD COLUMN 列集为空 (切片/解析失效?)",
                spec.ensure_fn
            );
            // 正交佐证: 字面 ADD COLUMN 靶 ⊆ 解析集 → 坐实解析集确实覆盖真实 ADD COLUMN 靶 (非任意小写串)。
            let literal = literal_add_column_targets(body);
            assert!(
                literal.is_subset(&parsed),
                "[{table}] 字面 ADD COLUMN 靶 {:?} 不在解析集内 (解析逻辑漏了直写列?)",
                literal.difference(&parsed).collect::<Vec<_>>()
            );
        }
    }
}
#[cfg(test)]
mod sql_comment_quote_guard {
    /// **SQL 字符串字面量里的 `--` 注释不许出现 ASCII 双引号。**
    ///
    /// 本会话我在这上面栽了**三次**: 在 `execute_batch("… -- 说明 …")` 的注释里写了 `"某某"`,
    /// 那个引号直接把 Rust 字符串字面量截断, `cargo build` 当场不过。三次都发生在"只是改注释"的时候
    /// —— 正因为觉得改注释不用编译, 才一路提交上去(78d8371 / cf47a45 两个坏提交)。
    ///
    /// ⚠️ **说实话: 这条守卫并不比编译器强。** 反向验证时故意塞一个 ASCII 引号进去, 结果测试
    /// 根本没跑起来 —— rustc 先炸了。真正的闸一直是编译器, 失效的是**我的流程**(没编译就提交)。
    /// 留着它只为两点: 报错信息比 `expected one of ...` 直白; 以及把这段教训钉在代码里。
    /// 中文引号「」不受影响, 想强调就用它。
    #[test]
    fn sql_literal_comments_have_no_ascii_quotes() {
        let src = include_str!("storage.rs");
        let mut bad = Vec::new();
        for (n, line) in src.lines().enumerate() {
            let t = line.trim_start();
            // SQL 注释行(Rust 注释是 `//`, 不会误伤; `--` 开头且不是 `-->` 之类)
            if t.starts_with("--") && !t.starts_with("-->") && t.contains('"') {
                bad.push(format!("  第 {} 行: {}", n + 1, line.trim()));
            }
        }
        assert!(
            bad.is_empty(),
            "SQL 注释里有 ASCII 双引号 —— 它会截断外层 Rust 字符串字面量, 编译不过。\n\
             改用中文引号「」。出问题的行:\n{}",
            bad.join("\n")
        );
    }
}

#[cfg(test)]
mod schema_doc_sync_guard {
    use super::INGEST_REBUILT_INDEXES;

    /// **权威 schema 文档必须逐条列出代码里真建的 message 相关索引。**
    ///
    /// 背景: `docs-dev/00-当前生效/02-schemas/L1-schema-数据库设计.md` 是**权威规格** —— 下一个人
    /// 照它改。2026-07-27 加 `idx_message_conv_time_full` 时只改了代码没改文档, 文档列 12 条、
    /// 代码建 14 条, 补审才逮到。当时没有任何东西守着这个一致性, 所以它一直在漂。
    ///
    /// 这条不比对索引的**定义**(列顺序/DESC 那些), 只比对**名字有没有列全** —— 定义的措辞会有
    /// 合理差异, 但"文档里压根没提这条索引"是无可辩解的漏。
    #[test]
    fn schema_doc_lists_every_message_index() {
        let code = include_str!("storage.rs");
        // ⚠️ **必须先把 CRLF 归一成 LF**: 下面按「CREATE INDEX IF NOT EXISTS 名字 + 换行」定位文档块,
        //    CRLF 检出时名字后面是回车符, find 直接返回 None → continue → **6 条全部静默跳过**,
        //    守卫退化回「只比名字」。仓库 core.autocrlf=true 且**没有 .gitattributes** ⇒ 新克隆出来的
        //    .md 就是 CRLF, 而 CI 的 test job 有 windows-latest 那条腿 —— 那条腿上这守卫是死的。
        //    (审查方拿 git archive 快照做出了干净的 A/B: LF 下反例红、CRLF 下静默放过。他第一遍用
        //     Python 复现时 open() 的 universal-newlines 把 CRLF 悄悄归一, 得出「全 MATCH」的假清白
        //     —— 探针自身的归一化也会造假。)
        let doc_raw = include_str!("../../../docs-dev/00-当前生效/02-schemas/L1-schema-数据库设计.md");
        let doc_owned = doc_raw.replace("\r\n", "\n");
        let doc: &str = &doc_owned;

        // 代码里**真建**的(只认 CREATE INDEX 后面跟的名字, 注释里提到的不算)。
        let mut in_code: Vec<&str> = Vec::new();
        // ⚠️ 权威清单 `INGEST_REBUILT_INDEXES` 里的索引**不经** `CREATE INDEX IF NOT EXISTS` 建
        //    (它们走 reconcile), 光扫那个字面串会把它们整批漏掉 —— 而这一轮刚把 reconcile 立成
        //    新写法, 等于新推荐的路子自带盲区(审查方点名的 D)。
        for (name, _) in INGEST_REBUILT_INDEXES {
            if !in_code.contains(name) {
                in_code.push(name);
            }
        }
        for part in code.split("CREATE INDEX IF NOT EXISTS ").skip(1) {
            let name: &str = part
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("");
            if name.starts_with("idx_message") && !in_code.contains(&name) {
                in_code.push(name);
            }
        }
        // 门槛按"扫出来的"算, 不含上面预置的那 6 个 —— 否则预置白送底数, 抓取逻辑坏掉时报不出来。
        // 当前真实值 scanned = 10(审查方把门槛临时改成 99999 读出来的), 门槛 8 ⇒ **余量 2**。
        // (我之前写"余量 4"是错的。余量小就意味着正常删掉两三条 idx_message_* 会误报 ——
        //  真删的时候顺手把门槛跟着调, 别把它当成不能动的常数。)
        let scanned = in_code.len() - INGEST_REBUILT_INDEXES.len();
        assert!(
            scanned >= 8,
            "从 CREATE 语句扫出来的索引太少({scanned} 条), 抓取逻辑坏了"
        );

        // ⚠️ **不能用 `doc.contains(name)`** —— 索引名之间有前缀包含关系:
        //    `idx_message_conv_time` 是 `idx_message_conv_time_full` 的严格前缀。用子串匹配的话,
        //    把前者从文档里整块删掉, 后者的名字仍然"包含"前者 → 守卫照样绿。
        //    审查方实测拆穿了这个假阴性, 而且它**恰好在这次要守的那对索引上失灵**。
        //    改成先把文档里的索引名当**完整词**抽出来做集合比对。
        // 判据是「文档里**定义**了这条索引」, 不是「正文里提过这个名字」—— 只认 `CREATE INDEX` 后面
        // 跟的那个名字。第一版只要求名字在文档里出现过, 结果我自己在旁边注解里提了一句
        // `idx_message_conv_time`, 就足以让"整块定义被删掉"这个反例照样绿。
        let doc_names: std::collections::HashSet<String> = doc
            .split("CREATE INDEX IF NOT EXISTS ")
            .skip(1)
            .filter_map(|part| part.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next())
            .filter(|w| w.starts_with("idx_"))
            .map(str::to_string)
            .collect();
        assert!(
            doc_names.len() >= 10,
            "没从文档里抽到索引定义, 抽取逻辑坏了: {doc_names:?}"
        );
        let missing: Vec<&&str> = in_code.iter().filter(|n| !doc_names.contains(**n)).collect();
        assert!(
            missing.is_empty(),
            "这些索引代码里建了、权威 schema 文档里没有 —— 文档是下一个人改代码的依据, 漏了会让人踩空。
             补进 docs-dev/00-当前生效/02-schemas/L1-schema-数据库设计.md 的 message 段:
  {missing:?}"
        );

        // **列清单也要对上**, 不只是名字对上。审查方点名的反例 C: 文档把 `_full` 写回 4 列(名字没动),
        // 守卫照样绿 —— 而"定义漂了名字没漂"正是这一轮修 reconcile_index 要解决的那个 bug 类别,
        // 守卫却看不见它。这里对权威清单里那几条比对列清单(归一化后比, 允许排版差异)。
        let norm = |s: &str| -> String {
            s.to_lowercase()
                .replace(['\n', '\r'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        // 取**第一对**括号里的内容 —— 不能用 `rfind(')')`, 文档里 CREATE 语句后面紧跟的注释
        // 常常也带括号(比如「按类型过滤 (e.g. 只看图片)」), 那样会把注释一起算进列清单。
        // 按括号配对扫, 遇到深度归零就停。
        let cols_of = |sql: &str| -> Option<String> {
            let open = sql.find('(')?;
            let mut depth = 0i32;
            for (i, ch) in sql[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(norm(&sql[open + 1..open + i]));
                        }
                    }
                    _ => {}
                }
            }
            None
        };
        let mut col_drift: Vec<String> = Vec::new();
        for (name, code_sql) in INGEST_REBUILT_INDEXES {
            let want = cols_of(code_sql).unwrap_or_default();
            // 从文档里抠出这条索引的 CREATE 块(到下一个空行为止)。
            let Some(pos) = doc.find(&format!(
                "CREATE INDEX IF NOT EXISTS {name}
"
            )) else {
                continue; // 名字缺失上面那条断言已经报过了
            };
            let block = &doc[pos..];
            let block = &block[..block
                .find(
                    "

",
                )
                .unwrap_or(block.len())];
            let got = cols_of(block).unwrap_or_default();
            if got != want {
                col_drift.push(format!(
                    "  {name}
    代码: {want}
    文档: {got}"
                ));
            }
        }
        assert!(
            col_drift.is_empty(),
            "文档里这些索引的**列清单**与代码对不上 —— 名字对了不代表定义对了, 而「定义漂了名字没漂」
             正是最难发现的那类(SQLite 的 CREATE IF NOT EXISTS 只认名字):
{}",
            col_drift.join(
                "
"
            )
        );
    }
}

// ⚠️ 这里本来有一条 `old_anchor_db_is_rejected_not_silently_migrated`, **删了 —— 它是重复造的**。
//
// 我当时的 commit 写「门禁本身此前一个测试都没有」—— 那是**错的**: `storage::tests` 里的
// `init_l1_schema_gates_stale_anchor_db` 从门禁引入那笔(`6a72b6f`)就在, 覆盖同样三件事,
// 而且**更强**(它还断言 extended_code == SQLITE_MISMATCH, 我那条没有)。独立审查把门禁短路掉,
// 两条一起红 —— 证明我那条是真守卫, 但净新增覆盖约等于零, 还漏了错误码那条断言。
//
// 教训: **加守卫之前先查有没有现成的**。"此前没有测试"这种判断不能凭印象, 得 grep。

#[cfg(test)]
mod index_definition_drift_guard {
    use super::*;

    /// **索引定义漂了必须被修回来, 不能靠 `IF NOT EXISTS` 装作没事。**
    ///
    /// 这条守的是一个**静默**失效: `CREATE INDEX IF NOT EXISTS` 只认名字 —— 定义从 4 列改成 5 列、
    /// 名字没动, 于是所有已存在的库永远停在 4 列, 而代码/文档/性能声明全按 5 列写。
    /// 三方对不上, 查询计划退化, 却没有任何东西报警。2026-07-27 真的这么栽过一次, 独立审查
    /// 逐库读 `sqlite_master` 才发现。
    ///
    /// 这里造的正是那个现场: 先种一个**旧定义**的同名索引, 再跑 `init_l1_schema`, 断言它被修回当前定义。
    #[test]
    fn stale_index_definition_is_rebuilt_not_silently_kept() {
        let c = Connection::open_in_memory().expect("内存库");
        init_l1_schema(&c).expect("首建");

        // 归一化后再比 —— 重建之后存进 sqlite_master 的是 `reconcile_index` 那条语句的原文, 排版跟
        // 最初批量建表那条不同。**列清单一致才是判据**, 空白差异不是问题(第一版拿原始字符串比,
        // 结果代码明明修对了却报红, 差的只是换行)。
        let cur = |c: &Connection| -> String {
            let sql: String = c
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_message_conv_time_full'",
                    [],
                    |r| r.get(0),
                )
                .expect("读索引定义");
            sql.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
        };
        let good = cur(&c);
        assert!(
            good.contains("source desc") && good.contains("source_native_id desc"),
            "首建就该是补满次键的版本(排序要的是全序, 少一列翻页会重/漏): {good}"
        );

        // 种一个旧定义(4 列, 缺尾部的 source)——就是历史上真实存在于用户库里的那个形态。
        c.execute_batch(
            "DROP INDEX idx_message_conv_time_full;
             CREATE INDEX idx_message_conv_time_full ON message
                 (account_id_sha, conv_id_sha, create_time DESC, source_native_id DESC);",
        )
        .expect("种旧定义");
        assert!(
            !cur(&c).ends_with("source desc)"),
            "前提: 现在该是缺尾键的旧定义, 实得 {}",
            cur(&c)
        );

        // 再跑一次 init —— 这正是用户升级后第一次 ingest/查询走的路径。
        init_l1_schema(&c).expect("升级路径上的 init");
        assert_eq!(
            cur(&c),
            good,
            "旧定义没被修回来 —— 那么所有已存在的库都会永远停在旧索引上, 而代码和文档都按新的写"
        );

        // ⚠️ **幂等这半条必须直接问 `reconcile_index` 有没有重建, 不能比 sql** ——
        //    重建写回去的正是同一条定义, 比 sql 在两种情况下**完全一样**, 那种断言从结构上不可能红。
        //    第一版就那么写的, 独立审查实测: 把 reconcile 改成"每次都 DROP+CREATE", 守卫照样全绿,
        //    而那正是这个修复引入的唯一新风险(大库每次开都重建 = 白卡几十秒, 且全程不报错)。
        //    `rootpage` 同样当不了探针: DROP 释放的页会被 CREATE 复用, 实测前后同值。
        for (name, sql) in INGEST_REBUILT_INDEXES {
            assert!(
                !reconcile_index(&c, name, sql).expect("核对"),
                "{name} 定义已一致却重建了"
            );
        }

        // **清单里每一条都要真被核对到**, 不是只护着上面那一条(审查方点名: 第一版只 reconcile 了 1 条,
        // 其余 13 条 message 索引仍是裸 CREATE IF NOT EXISTS, 下次改别的索引定义会原样再栽)。
        for (name, sql) in INGEST_REBUILT_INDEXES {
            c.execute_batch(&format!("DROP INDEX IF EXISTS {name};")).expect("先删");
            assert!(reconcile_index(&c, name, sql).expect("核对"), "{name} 没被建回来");
        }

        // **外层已经有事务时也必须能跑** —— `init_l1_schema` 会被调用方包在事务里调。
        // 我上一版把重建写成 `BEGIN; ...; COMMIT;`, 那时这条会红:
        // "cannot start a transaction within a transaction", 而且连接卡在事务态。
        // 为了修一个低概率的崩溃残留, 换来一个确定会炸的场景 —— 所以这条必须常驻。
        {
            let c2 = Connection::open_in_memory().expect("内存库");
            init_l1_schema(&c2).expect("首建");
            c2.execute_batch(
                "DROP INDEX idx_message_conv_time_full;
                 CREATE INDEX idx_message_conv_time_full ON message (account_id_sha, conv_id_sha, create_time DESC);",
            )
            .expect("降级成旧定义");
            c2.execute_batch("BEGIN;").expect("外层开事务");
            init_l1_schema(&c2).expect("外层已有事务时 init 必须仍能跑通(别用 BEGIN, 用 SAVEPOINT)");
            c2.execute_batch("COMMIT;").expect("外层提交");
            let sql: String = c2
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name='idx_message_conv_time_full'",
                    [],
                    |r| r.get(0),
                )
                .expect("读定义");
            assert!(
                sql.to_lowercase().contains("source desc)"),
                "外层事务里也该真修好: {sql}"
            );
        }

        // **切片必须对得上全集** —— message 那 4 条 + archive 那 2 条 == 全集 6 条, 顺序也要一致。
        // (拆成两段是为了让 init_message_table 不再依赖 archive 表存在; 但拆错了就会漏建索引。)
        assert_eq!(
            MESSAGE_REBUILT_INDEXES.len() + ARCHIVE_REBUILT_INDEXES.len(),
            INGEST_REBUILT_INDEXES.len(),
            "两段切片加起来必须等于全集"
        );
        for (i, (name, sql)) in MESSAGE_REBUILT_INDEXES
            .iter()
            .chain(ARCHIVE_REBUILT_INDEXES)
            .enumerate()
        {
            assert_eq!(
                (*name, *sql),
                INGEST_REBUILT_INDEXES[i],
                "第 {i} 条与全集对不上 —— 拆片和全集必须逐条一致"
            );
        }

        // **删索引那一步必须删的正是清单里这些** —— 漂开的后果不对称: 这里多删一条而清单没有,
        // 就是「删掉后永远建不回来」且静默。
        {
            let c4 = Connection::open_in_memory().expect("内存库");
            init_l1_schema(&c4).expect("首建");
            let names = || -> Vec<String> {
                let mut st = c4
                    .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' ORDER BY name")
                    .expect("查索引");
                let v: Vec<String> = st
                    .query_map([], |r| r.get::<_, String>(0))
                    .expect("迭代")
                    .filter_map(Result::ok)
                    .collect();
                v
            };
            let before = names();
            drop_ingest_indexes(&c4).expect("删");
            let after = names();
            let dropped: Vec<&String> = before.iter().filter(|n| !after.contains(n)).collect();
            assert_eq!(
                dropped.len(),
                INGEST_REBUILT_INDEXES.len(),
                "删掉的条数与清单对不上: 删了 {dropped:?}"
            );
            for (name, _) in INGEST_REBUILT_INDEXES {
                assert!(dropped.iter().any(|d| d.as_str() == *name), "{name} 在清单里却没被删");
            }
            create_ingest_indexes(&c4).expect("建回来");
            let restored = names();
            for n in &before {
                assert!(restored.contains(n), "{n} 被删掉后没建回来 —— 这就是「静默少一条索引」");
            }
        }

        // **错误路径不能留下烂摊子**: CREATE 失败时(磁盘满 / BUSY / 中断)必须回滚到 savepoint ——
        // 否则连接卡在事务里(写锁不放)、索引已被 DROP 掉。改动前审查方实测正是「索引=0, autocommit=false」,
        // 而且有外层事务时那个"只删没建"还会被外层 COMMIT **永久提交**。
        // 这是把「崩溃路径」修好的同时**必须**一起做的事, 不然错误路径比原来更糟。
        for outer in [false, true] {
            let c3 = Connection::open_in_memory().expect("内存库");
            init_l1_schema(&c3).expect("首建");
            if outer {
                c3.execute_batch("BEGIN;").expect("外层事务");
            }
            let r = reconcile_index(
                &c3,
                "idx_message_conv_time_full",
                "CREATE INDEX idx_message_conv_time_full ON message (nosuchcol)",
            );
            assert!(r.is_err(), "喂一条建不出来的定义, 该报错");
            let still: i64 = c3
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='idx_message_conv_time_full'",
                    [],
                    |r| r.get(0),
                )
                .expect("数索引");
            assert_eq!(still, 1, "CREATE 失败后索引不该丢(外层事务={outer})");
            assert_eq!(
                c3.is_autocommit(),
                !outer,
                "CREATE 失败后不该把连接卡在我们自己开的事务里(外层事务={outer})"
            );
            if outer {
                let _ = c3.execute_batch("COMMIT;");
            }
        }

        // **落库收尾那条路径必须走同一份定义** —— 它是每次全量 ingest 的最后一步, 用旧定义建回去的话
        // 库会长期停在错索引上, 下次 init 又改回来, 来回折腾且没人看得见。
        // 全 6 条都比, 不是只比一条(审查方 P3-5)。
        for (name, _) in INGEST_REBUILT_INDEXES {
            c.execute_batch(&format!("DROP INDEX IF EXISTS {name};")).expect("删");
        }
        create_ingest_indexes(&c).expect("落库收尾重建");
        for (name, sql) in INGEST_REBUILT_INDEXES {
            assert!(
                !reconcile_index(&c, name, sql).expect("核对"),
                "{name}: create_ingest_indexes 建出来的定义与 init 不一致"
            );
        }
    }
}
