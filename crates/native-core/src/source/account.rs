//! AccountDbSource — DbSource impl, 经 cipher `DbSession` 取数 (通用取数层, cipher impl 由构造方注入).
//!
//! 流程 (ADR-423 §3.4 + drain 设计双审 v2):
//! - `snapshot_dbs`: 扫 `db_dir` 列 `message_*.db` + 开账号会话 (1 账号 1 session, 全程复用)。
//! - `list_message_subsources`: 从 `sqlite_master` 列实际存在的 `Msg_<md5>` 表 (ground truth, 统一新/老库,
//!   避免引用不存在的表), 用 `Name2Id` 的 `md5(user_name)→user_name` 反解每张表的 `conv_id`。
//! - `drain_messages`: 单子源 `WHERE local_id > cur ORDER BY local_id LIMIT n`; `real_sender_id` 经
//!   `Name2Id` 的 `rowid→user_name` 在 Rust map 解 sender (非 SQL JOIN); `message_content` 走
//!   `hex(coalesce(.., x''))` (NULL 不跳行) → `get_blob_hex` 还原。
//!
//! 每库的 `Name2Id` 解析缓存在 self (`db_id → maps`), 跨子源/跨批复用 (避免每批重查 3383 行 Name2Id)。
//!
//! K-R4: 持有 `MasterKey`(其 Debug 已 sha8)+ `account_entry_db`/`db_dir`(含 wxid)→ 手写 Debug
//! (key 不露, 路径 sha8); 扫盘错误只露 io `ErrorKind`(不露路径明文)。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;

use super::{
    AvatarBatch, BizChatUserBatch, ChatroomBatch, ChatroomRawRow, ContactBatch, DbSnapshot, DbSource, DbSourceError,
    DrainCursor, EmoticonBatch, FMessageBatch, FavoriteBatch, FavoriteTagBatch, FinderBatch, GroupPayBatch,
    MessageBatch, MessageSubsource, MomentBatch, MomentFeedBatch, RedEnvelopeBatch, ResumeProbe, SessionBatch,
    SnsNotifyBatch, TransferBatch,
};
use crate::cipher::{Cipher, CipherRow, DbSession};
use crate::decoder::{
    AvatarRow, BizChatUserRow, ContactRow, EmoticonRow, FMessageRow, FavoriteRow, FavoriteTagRow, FinderRow,
    GroupPayRow, MessageRow, MomentFeedRow, RedEnvelopeRow, SessionRow, SnsNotifyRow, SnsRow, TransferRow,
};
use crate::key_provider::{sha8, MasterKey, Wxid};

/// 取全量 `rowid→user_name` (解 sender) + 反解 conv 所需的 user_name 全集 (build md5 map).
const NAME2ID_SQL: &str = "SELECT rowid AS rid, user_name FROM Name2Id";

/// 标签件: 取 `contact_label` 表 (联系人标签 id→名字对照; 14 行量级)。
/// 竞品 WeChatMsg db_v4 同款 `SELECT label_name_ FROM contact_label WHERE label_id_=?` 的批量版
/// (一次全取建 map, 避免每联系人一查)。表不存在 (低版本/变体库) → drain 端吞错降级空 map (labels 全 None)。
const CONTACT_LABEL_SQL: &str = "SELECT label_id_ AS lid, label_name_ AS lname FROM contact_label";

/// 列实际存在的 `Msg_` 族表 (ground truth)。`LIKE 'Msg\_%' ESCAPE '\'` — `\_` = 字面下划线
/// (SQLite 默认不把 `\` 当转义, 不加 ESCAPE 则 `_` 是通配符, drain 设计双审 P1-2)。
/// 仍需 [`is_msg_table`] 严格正则二次过滤 (排除 `Msg_<md5>_fts` 等辅助表)。
const MSG_TABLES_SQL: &str = "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'";

/// 一库 `Name2Id` 解析 (跨 drain 复用)。
struct Name2IdMaps {
    /// `real_sender_id` (= Name2Id.rowid) → 发送者 UserName (解 sender)。
    sender_by_rowid: HashMap<i64, String>,
    /// `md5(user_name)` 小写 hex → user_name (会话表名 `Msg_<md5>` 反解 conv_id)。
    conv_by_md5: HashMap<String, String>,
}

/// AccountDbSource — 经 [`Cipher`] 开的 [`DbSession`] 按子源 keyset 增量 drain (cipher impl 由构造方注入)。
pub struct AccountDbSource {
    cipher: Box<dyn Cipher>,
    /// 账号入口 db (open_account 用, e.g. `session/session.db`)。**含 wxid**。
    account_entry_db: PathBuf,
    /// master key (从 KeyProvider 取; 不可 Clone — move 持有, 传 `&self.key` 给 open_account)。
    key: MasterKey,
    /// 所属账号 (DbSnapshot.wxid / db_id 用)。
    wxid: Wxid,
    /// `message_*.db` 所在目录 (扫盘根)。**含 wxid**。
    db_dir: PathBuf,
    /// 账号会话 (首次 ensure 时开, 全程复用; Arc 便于克隆出不借 self 调 query)。
    session: Option<Arc<dyn DbSession>>,
    /// 每库 Name2Id 解析缓存 (db_id → maps)。
    name2id_cache: HashMap<String, Arc<Name2IdMaps>>,
    /// 公众号模式 (ADR-480): true → snapshot_dbs 扫 `biz_message_*.db` 而非 `message_*.db` (schema 全同,
    /// 复用整条 message pipeline; 落 message 表 source 列区分 `biz_message_N.db|Msg_xxx`)。默认 false。
    biz_mode: bool,
    /// R9 复审#3: `snapshot_dbs` 一趟同时扫 `message_*.db` + `biz_message_*.db` (biz_mode=false 时叠加 biz)。默认 false。
    /// live-index watch 用它覆盖公众号消息 —— 否则 biz 库既不在 message-watch (biz_mode=false 排除) 也不在
    /// source-watch (只管小库) → 公众号变化被发现但不导入 (复审#3)。
    include_biz: bool,
    /// 陌生人模式 (echotrace 同源): true → `drain_contacts` 从 `stranger` 表 (而非 `contact` 表) 取
    /// (列结构全同 22 列; 非好友但有往来的人)。复用整条 contact pipeline; 落同一 person 表, source 列区分
    /// `contact.db|stranger` (查询层 `WHERE source LIKE '%stranger%'` 筛)。默认 false。照 biz_mode 套路。
    stranger_mode: bool,
}

// K-R4: key 不露 (其 Debug 虽已 sha8, 仍不展示); account_entry_db/db_dir 含 wxid → sha8.
impl std::fmt::Debug for AccountDbSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountDbSource")
            .field("wxid", &format_args!("{}", self.wxid))
            .field("cipher", &self.cipher.name())
            .field("db_dir_sha8", &sha8(self.db_dir.to_string_lossy().as_bytes()))
            .field("session_open", &self.session.is_some())
            .field("cached_dbs", &self.name2id_cache.len())
            // key / account_entry_db 故意不露 (K-R4) → 非穷尽.
            .finish_non_exhaustive()
    }
}

impl AccountDbSource {
    /// 构造 — `cipher` 已就绪; `account_entry_db` 开账号; `db_dir` 扫 message_*.db。
    #[must_use]
    pub fn new(
        cipher: Box<dyn Cipher>,
        account_entry_db: PathBuf,
        key: MasterKey,
        wxid: Wxid,
        db_dir: PathBuf,
    ) -> Self {
        Self {
            cipher,
            account_entry_db,
            key,
            wxid,
            db_dir,
            session: None,
            name2id_cache: HashMap::new(),
            biz_mode: false,
            include_biz: false,
            stranger_mode: false,
        }
    }

    /// 切换公众号模式 (ADR-480): true → 下一轮 `snapshot_dbs` 扫 `biz_message_*.db`。
    /// 复用整条 message pipeline (schema 全同); 公众号消息落 message 表, source 列 `biz_message_N.db|...` 区分。
    pub fn set_biz_mode(&mut self, biz: bool) {
        self.biz_mode = biz;
    }

    /// R9 复审#3: 让 `snapshot_dbs` 一趟同时扫 `message_*.db` + `biz_message_*.db` (live-index watch 覆盖公众号消息)。
    pub fn set_include_biz(&mut self, include: bool) {
        self.include_biz = include;
    }

    /// 切换陌生人模式: true → 下一轮 `drain_contacts` 从 `stranger` 表取 (而非 `contact` 表; 列全同)。
    /// 复用整条 contact pipeline; 陌生人落同一 person 表, source 列 `contact.db|stranger` 区分。照 `set_biz_mode` 套路。
    pub fn set_stranger_mode(&mut self, stranger: bool) {
        self.stranger_mode = stranger;
    }

    /// 开账号会话 (幂等; 首次开, 后续返缓存 Arc)。
    async fn ensure_session(&mut self) -> Result<Arc<dyn DbSession>, DbSourceError> {
        if let Some(s) = &self.session {
            return Ok(s.clone());
        }
        let boxed = self.cipher.open_account(&self.account_entry_db, &self.key).await?;
        let arc: Arc<dyn DbSession> = Arc::from(boxed);
        self.session = Some(arc.clone());
        Ok(arc)
    }

    /// 取/建一库的 Name2Id 解析 (幂等; 按 db_id 缓存)。
    async fn ensure_name2id(&mut self, snapshot: &DbSnapshot) -> Result<Arc<Name2IdMaps>, DbSourceError> {
        if let Some(m) = self.name2id_cache.get(&snapshot.db_id) {
            return Ok(m.clone());
        }
        let session = self.ensure_session().await?;
        let rows = session
            .query(&snapshot.kind, &snapshot.sub_db_path, NAME2ID_SQL)
            .await?;
        let maps = Arc::new(build_name2id_maps(&rows));
        self.name2id_cache.insert(snapshot.db_id.clone(), maps.clone());
        Ok(maps)
    }
}

#[async_trait]
impl DbSource for AccountDbSource {
    async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError> {
        // 代码双审 P0/P1: 新一轮 snapshot 清 Name2Id 缓存 — 否则长跑/多轮复用同一实例时, 旧 map 反解不到
        // 期间新增的会话(新 Msg_ 表 md5 缺)→ list_message_subsources 把它当 unresolved 静默跳过整张表
        // (漏全部该会话消息); 新 sender 也解 None。每轮清掉, 下面 ensure_name2id 重查保证反解最新。
        self.name2id_cache.clear();

        // 先开账号会话 (fail-fast on bad key / 缺文件), 再扫盘。
        self.ensure_session().await?;

        let acct_sha = sha8(self.wxid.as_str().as_bytes());
        let entries = std::fs::read_dir(&self.db_dir).map_err(|e| DbSourceError::MapMissing {
            // K-R4: 只露 io ErrorKind (NotFound/PermissionDenied/...), 不露 db_dir 路径明文。
            what: format!("扫 db_dir 失败: {:?}", e.kind()),
        })?;

        let mut snaps = Vec::new();
        let mut skipped = 0usize;
        for ent in entries {
            // 代码双审 P0: 不用 entries.flatten() 静默吞 — 枚举项错 → warn+计数 (可能漏掉一个目标库, 不静默)。
            let ent = match ent {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(kind = ?e.kind(), "扫 db_dir: 枚举项失败, 跳过 (可能漏一库)");
                    skipped += 1;
                    continue;
                }
            };
            let path = ent.path();
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // 公众号模式扫 biz_message_*.db, 否则 message_*.db (ADR-480; schema 全同复用 message pipeline)。
            // R9 复审#3: biz_mode → 仅 biz (export 二次扫); 否则 regular, include_biz 时叠加 biz (watch 一趟覆盖两者)。
            let matches_db = message_db_matches(fname, self.biz_mode, self.include_biz);
            if !matches_db {
                continue;
            }
            // 代码双审 P0: 匹配到目标 db 但 metadata 读不到 → warn+计数 (不静默漏该库; fname 非敏感可露)。
            let meta = match ent.metadata() {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(kind = ?e.kind(), db = %fname, "扫 db_dir: 目标 db 读元数据失败, 跳过");
                    skipped += 1;
                    continue;
                }
            };
            if !meta.is_file() {
                continue;
            }
            let (mtime_ms, size_bytes) = file_stat(&meta);
            snaps.push(DbSnapshot {
                db_id: format!("{acct_sha}|{fname}"),
                wxid: self.wxid.clone(),
                kind: "message".to_string(),
                sub_db_path: path.clone(),
                rel_name: fname.to_string(),
                mtime_ms,
                size_bytes,
            });
        }
        if skipped > 0 {
            tracing::warn!(skipped, "扫 db_dir: 有项被跳过 (枚举/元数据错, 见上方 warn)");
        }
        // 稳定排序 (按 rel_name) — 确定性 drain 顺序。
        snaps.sort_by(|a, b| a.rel_name.cmp(&b.rel_name));
        Ok(snaps)
    }

    /// 该会话表当前的 `MAX(local_id)`(走主键, O(1))—— 供调用方判游标倒退。
    async fn max_local_id(
        &mut self,
        snapshot: &DbSnapshot,
        subsource: &MessageSubsource,
    ) -> Result<Option<i64>, DbSourceError> {
        if !is_msg_table(&subsource.table) {
            return Ok(None);
        }
        let session = self.ensure_session().await?;
        let sql = format!("SELECT MAX(local_id) AS m FROM \"{}\"", subsource.table);
        let rows = session.query(&snapshot.kind, &snapshot.sub_db_path, &sql).await?;
        Ok(rows.first().and_then(|r| r.get_i64("m")))
    }

    /// 一条 SQL 探回 [`ResumeProbe`] 三个信号 —— 见 trait 上的说明。
    ///
    /// 三处都走 rowid 主键点查, 真库量过跟"只取一行"没有可测的差别(0.281s vs 0.263s,
    /// 那 0.26 秒全是开加密库的钱)。表空 → `Missing`。
    async fn rebuild_sentinel(
        &mut self,
        snapshot: &DbSnapshot,
        subsource: &MessageSubsource,
        at: i64,
        depth: super::ProbeDepth,
    ) -> Result<ResumeProbe, DbSourceError> {
        if !is_msg_table(&subsource.table) {
            return Ok(ResumeProbe::Unsupported);
        }
        let session = self.ensure_session().await?;
        // 表名已白名单 (Msg_<32hex>, 无注入); `at` 是整数内联。
        //
        // **三个信号一条语句**(`local_id` 就是 rowid, 三处都走主键, 都是点查):
        //   外层 `WHERE local_id > 0 ORDER BY .. LIMIT 1` → 最老那行 (身份)
        //   `max(local_id)`                               → 表缩了没有
        //   `WHERE local_id = at`                         → 游标那行还在不在、还是不是原来那条
        //
        // ⚠️ 外层那个 `local_id > 0` **必须跟 drain 侧逐字一样**(独立复审 P3): drain 是
        // `WHERE local_id > since.local_id`, 首批 `since = 0`。少写它的话, 表里只要有一行
        // `local_id <= 0`, 两侧锚的就不是同一行 → 指纹**永远**对不上 → 每轮全量重扫重发。
        // (真库够不着 —— `local_id INTEGER PRIMARY KEY AUTOINCREMENT`, 随机 400 张表 MIN 全是 1
        // —— 但两侧口径不一致这件事本身是账, 不留。)
        //
        // ⚠️ 取正文**原始字节**(hex 再解回来)而不是 `length()`: 长度基数不够(同一秒同长度的两条文本
        // 就撞), 而且 `length()` 对 **TEXT 存储**数的是**字符**不是字节 —— 真库实测 66.2 万行里
        // 32% 的行两个数不等, 那样每轮都会误判成"表被重建"。
        // `prefix_rows` 只在 Deep 下要 —— 它是**唯一要扫行**的一项(其余全是主键点查)。
        // ⚠️ 这个 `local_id > 0` **必须跟 drain 侧逐字一样**(独立复审 P3: 新加的子查询漏了它,
        // 而同一条语句外层专门写了)。少写 = 探测数那些行、drain 不数 → 每轮 Deep 都判"行数变了"
        // → **每次查询全量重扫**。真库够不着(AUTOINCREMENT, MIN 全是 1), 但账要平。
        // 真库实测: 最大那张表(17.5 万行)约 +420 ms, 约 2.4 秒/百万行。见 `source::ProbeDepth`。
        let prefix_expr = match depth {
            super::ProbeDepth::Deep => format!(
                "(SELECT count(*) FROM \"{t}\" WHERE local_id > 0 AND local_id <= {at})",
                t = subsource.table
            ),
            super::ProbeDepth::Shallow => "NULL".to_string(),
        };
        let sql = format!(
            "SELECT local_id, create_time, local_type, hex(coalesce(message_content, x'')) AS mc_hex, \
             (SELECT max(local_id) FROM \"{t}\") AS max_id, \
             (SELECT coalesce(create_time, 0) FROM \"{t}\" WHERE local_id = {at}) AS cursor_ct, \
             (SELECT coalesce(server_id, 0) FROM \"{t}\" WHERE local_id = {at}) AS cursor_sid, \
             {prefix_expr} AS prefix_rows \
             FROM \"{t}\" WHERE local_id > 0 ORDER BY local_id LIMIT 1",
            t = subsource.table
        );
        let rows = session.query(&snapshot.kind, &snapshot.sub_db_path, &sql).await?;
        Ok(rows.first().map_or(ResumeProbe::Missing, |r| {
            ResumeProbe::Found(super::TableProbe {
                // 把**最老那行的 local_id** 也混进去: 老消息被删光、新表从 1 重来时, 光比内容可能撞。
                oldest_fp: super::row_fingerprint(
                    r.get_i64("local_id").unwrap_or(0),
                    r.get_i64("create_time").unwrap_or(0),
                    r.get_i64("local_type").unwrap_or(0),
                    &r.get_blob_hex("mc_hex").unwrap_or_default(),
                ),
                // 表非空(能走到这)⟹ `max(local_id)` 必有值; 读不出来就退化成 0, 调用方按"缩了"重扫,
                // 保守方向。
                max_id: r.get_i64("max_id").unwrap_or(0),
                // `coalesce(..,0)` 之后, 子查询只有在**那一行不存在**时才给 NULL → `None`。
                // 值是 NULL 的情况被归一成 0, 跟 drain 侧 `unwrap_or(0)` 同口径(codex round-6 P2)。
                cursor_ct: r.get_i64("cursor_ct"),
                cursor_sid: r.get_i64("cursor_sid"),
                // Shallow 时这一列是 SQL NULL -> None = "这一轮没探", **不是**"探出来是 0"。
                prefix_rows: r.get_i64("prefix_rows"),
            })
        }))
    }

    /// **单会话快路**(ADR-508 D24): 正着算表名 → 在 `sqlite_master` 点一下, **不读 `Name2Id`**。
    ///
    /// 全枚举那条路要建"md5 → conv_id"反查表, 得把整张 `Name2Id` 读出来; 真库 6 分片 2.2 万会话时
    /// 实测约 16 秒, 而"确保某会话最新"每次查询都要走一遍 —— 没有新消息也要干等。这里只查一张表存不存在。
    async fn find_message_subsource(
        &mut self,
        snapshot: &DbSnapshot,
        conv_id: &str,
    ) -> Result<Option<MessageSubsource>, DbSourceError> {
        let table = crate::decoder::anchor::msg_table_of(conv_id);
        // 表名是 md5 算出来的纯 hex, 仍过一次白名单(防调用方传进奇怪的 conv_id 把表名带歪)。
        if !is_msg_table(&table) {
            return Ok(None);
        }
        let session = self.ensure_session().await?;
        let sql = format!("SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'");
        let rows = session.query(&snapshot.kind, &snapshot.sub_db_path, &sql).await?;
        if rows.is_empty() {
            return Ok(None); // 这个分片里没有该会话 —— 正常(会话只落在某一个分片)
        }
        Ok(Some(MessageSubsource {
            table,
            conv_id: conv_id.to_string(),
        }))
    }

    async fn list_message_subsources(&mut self, snapshot: &DbSnapshot) -> Result<Vec<MessageSubsource>, DbSourceError> {
        let maps = self.ensure_name2id(snapshot).await?;
        let session = self.ensure_session().await?;
        let rows = session
            .query(&snapshot.kind, &snapshot.sub_db_path, MSG_TABLES_SQL)
            .await?;

        let mut subs = Vec::new();
        let mut unresolved = 0usize;
        for r in &rows {
            let Some(name) = r.get_str("name") else {
                continue;
            };
            // 严格白名单: ^Msg_[0-9a-f]{32}$ (排除 Name2Id / Msg_<md5>_fts 等)。
            if !is_msg_table(name) {
                continue;
            }
            let md5 = &name[4..]; // "Msg_" 后的 32 hex
            match maps.conv_by_md5.get(md5) {
                Some(conv) => subs.push(MessageSubsource {
                    table: name.to_string(),
                    conv_id: conv.clone(),
                }),
                // md5 在 Name2Id 反解不到 user_name (理论边界, 实测 3383/3383 全命中) → 跳过, 计数不静默。
                None => unresolved += 1,
            }
        }
        if unresolved > 0 {
            tracing::warn!(
                db_id = %snapshot.db_id,
                unresolved,
                "有 Msg_ 表 md5 在 Name2Id 反解不到会话, 已跳过 (不影响其余子源 drain)"
            );
        }
        Ok(subs)
    }

    async fn drain_messages(
        &mut self,
        snapshot: &DbSnapshot,
        subsource: &MessageSubsource,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<MessageBatch, DbSourceError> {
        // 防御: 表名必须是白名单 Msg_<32hex> (调用方应从 list_message_subsources 取; 这里兜底防注入)。
        if !is_msg_table(&subsource.table) {
            return Err(DbSourceError::MapMissing {
                what: "非法子源表名 (期望 Msg_<32hex>)".to_string(),
            });
        }
        let maps = self.ensure_name2id(snapshot).await?;
        let session = self.ensure_session().await?;

        // 表名已正则白名单 (纯 hex, 无注入); local_id / limit 是整数内联 (无注入)。
        let sql = format!(
            // `source` 列 (批E @提及 atuserlist): 真实 v4 Msg_ schema 恒有此列 (与 message_content/server_seq
            // 同为标准列)。alpha 假设当前版本 schema 有 source 列 (缺列 SELECT 会整批报错 → 响, 同 server_seq
            // 加列先例 ADR-453; codex 批E P2 提示的低版本缺列风险按此接受, 不加 pragma 探测)。
            "SELECT local_id, server_id, server_seq, origin_source, upload_status, download_status, \
             local_type, sort_seq, create_time, status, \
             hex(coalesce(message_content, x'')) AS mc_hex, hex(coalesce(source, x'')) AS src_hex, \
             real_sender_id \
             FROM \"{table}\" WHERE local_id > {cur} ORDER BY local_id LIMIT {limit}",
            table = subsource.table,
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query(&snapshot.kind, &snapshot.sub_db_path, &sql).await?;

        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_local_id = since.local_id;
        // ⚠️ **空批必须原样带回入参指纹**(codex round-1 P2): 批是空的时候 `next_cursor` 按契约等于入参游标,
        // 若这里初始化成 None, 调用方持久化它就把重建防护**擦掉**了。
        let mut resume_fp: Option<i64> = since.resume_fp;
        for r in &rows {
            // local_id 是 keyset 游标命脉 — 缺则 schema 漂移, 报错 (不静默推进错游标)。
            let local_id = r.get_i64("local_id").ok_or_else(|| DbSourceError::RowMap {
                db_id: snapshot.db_id.clone(),
                col: "local_id".to_string(),
            })?;
            let sender_username = r
                .get_i64("real_sender_id")
                .and_then(|rid| maps.sender_by_rowid.get(&rid).cloned());
            // mc_hex: hex(coalesce(message_content, x'')) 在健康数据上必是合法 hex (空 blob → "" → 空 Vec)。
            // None = 列缺 / dll 坏值 = 真异常 → fail-closed RowMap (代码双审 P0: 静默清空正文是最坏的数据丢失,
            // 且健康数据不触发)。
            let message_content = r.get_blob_hex("mc_hex").ok_or_else(|| DbSourceError::RowMap {
                db_id: snapshot.db_id.clone(),
                col: "mc_hex".to_string(),
            })?;
            // 其余整列 (server_id/local_type/sort_seq/create_time/status) 真实 schema 为 NOT NULL 整数:
            // 缺列会让 exec_query 直接 SQL 报错 (响); NULL→0 默认在健康数据不触发, 保留宽松不阻断整批。
            // src_hex: hex(coalesce(source, x'')) — 群消息 @提及 atuserlist (批E)。缺列/坏值 → 空 Vec
            // (宽松: source 是辅助元数据, 缺失只是无 @名单, 不阻断整批; 对比 mc_hex 是正文必须 fail-closed)。
            let msg_source = r.get_blob_hex("src_hex").unwrap_or_default();
            out.push(MessageRow {
                local_id,
                server_id: r.get_i64("server_id").unwrap_or(0),
                server_seq: r.get_i64("server_seq").unwrap_or(0),
                origin_source: r.get_i64("origin_source").unwrap_or(0),
                upload_status: r.get_i64("upload_status").unwrap_or(0),
                download_status: r.get_i64("download_status").unwrap_or(0),
                local_type: r.get_i64("local_type").unwrap_or(0),
                sort_seq: r.get_i64("sort_seq").unwrap_or(0),
                create_time: r.get_i64("create_time").unwrap_or(0),
                status: r.get_i64("status").unwrap_or(0),
                message_content,
                msg_source,
                sender_username,
            });
            if local_id > max_local_id {
                max_local_id = local_id;
            }
        }
        // 从 0 起扫的那一批, **第一行就是全表最老那一行** —— 顺手把身份锚点记进水位, 下次 drain
        // 拿它认"这还是不是同一张表"(见 `DrainCursor::resume_fp` / [`DbSource::rebuild_sentinel`])。
        //
        // ⚠️ 锚点是**最老那行**不是最新那行(第三轮对抗审 P2): 最新一条最容易被**就地改**
        // (图片视频上传完回写 CDN 字段 / 撤回改写正文), 拿它当身份等于每次上传都误判"表被重建"。
        // 这里白捡: `WHERE local_id > 0 ORDER BY local_id` 的第一行正是它, 不用额外查一次库,
        // 也省掉了"新会话第一轮没指纹 → 第二轮被迫重扫一次"。
        //
        // ⚠️ **只在 `since.local_id == 0` 时算**: 续扫批的第一行是"游标之后"的行, 不是全表最老那行。
        // 续扫时原样带回入参指纹 —— 空批也一样(codex round-1 P2: 擦掉它等于把重建防护关了)。
        //
        // **字段集必须跟 `rebuild_sentinel` 那边逐字一致**(顺序也一致), 否则两侧算不出同一个值
        // → 每轮误判成"表被重建"。两侧都用 `hex(coalesce(message_content, x''))` 解出来的**原始字节**。
        if since.local_id == 0 {
            if let Some(r) = out.first() {
                resume_fp = Some(super::row_fingerprint(
                    r.local_id,
                    r.create_time,
                    r.local_type,
                    &r.message_content,
                ));
            }
        }
        // 游标那一行的 `create_time` / `server_id` —— **本批最后一行就是新游标那一行**, 也是白捡的
        // (见 `DrainCursor::cursor_ct` / [`DbSource::rebuild_sentinel`])。空批保留入参。
        // `create_time` 这边是 `unwrap_or(0)` 出来的, 探测侧也 `coalesce(..,0)`, 两边同口径。
        let cursor_ct = out.last().map_or(since.cursor_ct, |r| Some(r.create_time));
        let cursor_sid = out.last().map_or(since.cursor_sid, |r| Some(r.server_id));
        // **已读段行数: 算术推进, 不查库**(见 `source::ProbeDepth`)。本批恰好读走 `(旧游标, 新游标]`
        // 里的**全部**行(SQL 就是 `WHERE local_id > 旧游标 ORDER BY local_id`), 所以
        // 新值 = 旧值 + 本批行数。从 0 起扫那一批, 旧值当 0 → **这个数就是这么白建起来的**。
        // 续扫批若入参没有(上次是 Shallow 路径推的水位)就保持没有, 不瞎猜。
        let prefix_rows = if since.local_id == 0 {
            Some(out.len() as i64)
        } else {
            since.prefix_rows.map(|n| n + out.len() as i64)
        };
        // has_more = 拿满 limit (limit=0 防御: 不判 more, 免空转)。
        let has_more = limit > 0 && fetched == limit;
        Ok(MessageBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_local_id,
                resume_fp,
                cursor_ct,
                cursor_sid,
                prefix_rows,
            },
            has_more,
        })
    }

    async fn drain_contacts(
        &mut self,
        contact_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<ContactBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // contact 表 keyset (隐式 rowid 单调); 列照 decoder/contact.rs 文档 (alias/is_in_chat_room 真跑验)。
        // ⚠️ 前提 (codex P2-b): 真实 v4 contact 表含 quan_pin/pin_yin_initial/remark_*(第一批) +
        //    verify_flag/delete_flag(第二批) + big_head_url/small_head_url/head_img_md5(第三批) +
        //    description/flag/chat_room_notify/chat_room_type(第五批) + extra_buffer(第七批 proto 解析) 列
        //    (2026-07-02 native 解密真实库已验 22 列)。旧/变体表缺列 →
        //    SELECT 报错 — alpha 接受当前版本 (同第一批拼音处理); 低版本探列降级 (PRAGMA table_info) 留 0.2.0+。
        // rowid/limit 整数内联无注入; 表名固定二选一 (contact / stranger) 无注入。
        // 陌生人模式 (echotrace 同源): 从 stranger 表取 (非好友但有往来; 列结构与 contact 全同 22 列)。
        let table = if self.stranger_mode { "stranger" } else { "contact" };
        let sql = format!(
            "SELECT rowid AS rid, username, local_type, nick_name, remark, alias, is_in_chat_room, \
             quan_pin, pin_yin_initial, remark_quan_pin, remark_pin_yin_initial, \
             verify_flag, delete_flag, \
             big_head_url, small_head_url, head_img_md5, \
             description, flag, chat_room_notify, chat_room_type, \
             hex(coalesce(extra_buffer, x'')) AS extra_hex \
             FROM {table} WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            table = table,
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("contact", contact_db, &sql).await?;
        // 标签件: 预加载 contact_label 表 id→名字 map (照 message drain 加载 Name2Id 一次的手法)。
        // 表不存在 (低版本/变体库) → 吞错降级空 map (labels 全 None, 不崩整条 contact drain)。
        let label_map = match session.query("contact", contact_db, CONTACT_LABEL_SQL).await {
            Ok(label_rows) => build_label_map(&label_rows),
            Err(_) => {
                tracing::debug!("contact_label 表不可查 (低版本/缺表), labels 降级为空");
                HashMap::new()
            }
        };
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // username = 联系人主键; rid = 游标命脉。缺则 schema 漂移报错 (不静默推进错游标)。
            let username = r.get_str("username").ok_or_else(|| DbSourceError::RowMap {
                db_id: "contact.db".to_string(),
                col: "username".to_string(),
            })?;
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "contact.db".to_string(),
                col: "rowid".to_string(),
            })?;
            let extra_buffer = r.get_blob_hex("extra_hex").unwrap_or_default();
            // 标签件: 从 extra_buffer f30 标签 id 串 + label_map 当场解析出标签名串 (照 Name2Id 解 sender 手法)。
            let labels = resolve_labels(&extra_buffer, &label_map);
            out.push(ContactRow {
                rowid: rid,
                username: username.to_string(),
                local_type: r.get_i64("local_type").unwrap_or(0),
                nick_name: r.get_str("nick_name").map(str::to_string),
                remark: r.get_str("remark").map(str::to_string),
                alias: r.get_str("alias").map(str::to_string),
                is_in_chat_room: r.get_i64("is_in_chat_room").unwrap_or(0),
                quan_pin: r.get_str("quan_pin").map(str::to_string),
                pin_yin_initial: r.get_str("pin_yin_initial").map(str::to_string),
                remark_quan_pin: r.get_str("remark_quan_pin").map(str::to_string),
                remark_pin_yin_initial: r.get_str("remark_pin_yin_initial").map(str::to_string),
                verify_flag: r.get_i64("verify_flag").unwrap_or(0),
                delete_flag: r.get_i64("delete_flag").unwrap_or(0),
                big_head_url: r.get_str("big_head_url").map(str::to_string),
                small_head_url: r.get_str("small_head_url").map(str::to_string),
                head_img_md5: r.get_str("head_img_md5").map(str::to_string),
                description: r.get_str("description").map(str::to_string),
                flag: r.get_i64("flag").unwrap_or(0),
                chat_room_notify: r.get_i64("chat_room_notify").unwrap_or(0),
                chat_room_type: r.get_i64("chat_room_type").unwrap_or(0),
                extra_buffer,
                labels,
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(ContactBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    /// contact 溯源 source 值: 陌生人模式 → `contact.db|stranger` (进 person PK 的 source 维,
    /// 与普通 `contact.db` 分行不覆盖; 查询层 `WHERE source LIKE '%stranger%'` 筛)。否则普通 `contact.db`。
    fn contact_source_label(&self) -> &'static str {
        if self.stranger_mode {
            "contact.db|stranger"
        } else {
            "contact.db"
        }
    }

    async fn drain_sessions(
        &mut self,
        session_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<SessionBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // SessionTable keyset (隐式 rowid 单调); 列照 decoder/session.rs (实测 session.db schema)。
        // rowid/limit 整数内联无注入; 表名 "SessionTable" 固定无注入。
        let sql = format!(
            "SELECT rowid AS rid, username, summary, last_sender_display_name, unread_count, \
             last_msg_type, last_msg_sub_type, sort_timestamp, \
             \"type\" AS session_type, is_hidden, status, draft, \
             last_msg_sender, last_timestamp, last_clear_unread_timestamp, \
             last_msg_locald_id, last_msg_ext_type, unread_first_msg_srv_id \
             FROM SessionTable WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("session", session_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // username = 会话主键; rid = 游标命脉。缺则 schema 漂移报错 (不静默推进错游标)。
            let username = r.get_str("username").ok_or_else(|| DbSourceError::RowMap {
                db_id: "session.db".to_string(),
                col: "username".to_string(),
            })?;
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "session.db".to_string(),
                col: "rowid".to_string(),
            })?;
            out.push(SessionRow {
                rowid: rid,
                username: username.to_string(),
                summary: r.get_str("summary").map(str::to_string),
                last_sender_display_name: r.get_str("last_sender_display_name").map(str::to_string),
                unread_count: r.get_i64("unread_count").unwrap_or(0),
                last_msg_type: r.get_i64("last_msg_type").unwrap_or(0),
                last_msg_sub_type: r.get_i64("last_msg_sub_type").unwrap_or(0),
                sort_timestamp: r.get_i64("sort_timestamp").unwrap_or(0),
                session_type: r.get_i64("session_type").unwrap_or(0),
                is_hidden: r.get_i64("is_hidden").unwrap_or(0),
                status: r.get_i64("status").unwrap_or(0),
                draft: r.get_str("draft").map(str::to_string),
                last_msg_sender: r.get_str("last_msg_sender").map(str::to_string),
                last_timestamp: r.get_i64("last_timestamp").unwrap_or(0),
                last_clear_unread_timestamp: r.get_i64("last_clear_unread_timestamp").unwrap_or(0),
                last_msg_locald_id: r.get_i64("last_msg_locald_id").unwrap_or(0),
                last_msg_ext_type: r.get_i64("last_msg_ext_type").unwrap_or(0),
                unread_first_msg_srv_id: r.get_i64("unread_first_msg_srv_id").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(SessionBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_favorites(
        &mut self,
        favorite_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FavoriteBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // fav_db_item keyset (local_id 单调 PK); content 本身不取 (大 blob) → 只 LENGTH。
        // codex 批B P1: content 是 TEXT, LENGTH(TEXT) 返字符数; CAST AS BLOB 取真字节长度 (非 ASCII XML 低估修正)。
        // local_id/limit 整数内联无注入; 表名/列名固定。"type" 关键字须 quote。
        let sql = format!(
            "SELECT local_id AS rid, server_id, \"type\" AS fav_type, update_time, \
             fromusr AS from_user, realchatname AS real_chat_name, source_id, \
             LENGTH(CAST(content AS BLOB)) AS content_len, \
             CASE WHEN \"type\"=18 THEN content ELSE NULL END AS note_content \
             FROM fav_db_item WHERE local_id > {cur} ORDER BY local_id LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("favorite", favorite_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // local_id = PK + 游标命脉; from_user = 来源。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "favorite.db".to_string(),
                col: "local_id".to_string(),
            })?;
            let from_user = r.get_str("from_user").ok_or_else(|| DbSourceError::RowMap {
                db_id: "favorite.db".to_string(),
                col: "fromusr".to_string(),
            })?;
            out.push(FavoriteRow {
                local_id: rid,
                server_id: r.get_i64("server_id").unwrap_or(0),
                fav_type: r.get_i64("fav_type").unwrap_or(0),
                update_time: r.get_i64("update_time").unwrap_or(0),
                from_user: from_user.to_string(),
                real_chat_name: r.get_str("real_chat_name").map(str::to_string),
                source_id: r.get_str("source_id").map(str::to_string),
                content_len: r.get_i64("content_len").unwrap_or(0),
                // 笔记 (type 18) 的 content XML (仅笔记取, 其它类型 NULL → None); decoder 解 <datadesc> 正文。
                note_content: r.get_str("note_content").map(str::to_string),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(FavoriteBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_favorite_tags(
        &mut self,
        favorite_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FavoriteTagBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // fav_bind_tag_db_item keyset (rowid 单调); LEFT JOIN fav_tag 取标签名 (缺→NULL→空串, 不丢绑定)。
        // rowid/limit 整数内联无注入; 表名/列名固定。别名 b/t 消歧。
        // **R16-3 codex P1 根治**: JOIN 键改 `t.local_id = b.tag_local_id`(**非** server_id)—— 未同步标签
        // server_id=0 时按 server_id JOIN 会交叉命中所有 server_id=0 标签 → 误标名; local_id 单库唯一 → 精确一名。
        let sql = format!(
            "SELECT b.rowid AS rid, b.tag_server_id AS tag_server_id, b.tag_local_id AS tag_local_id, \
             t.name AS tag_name, t.seq AS seq, b.fav_server_id AS fav_server_id, \
             b.fav_local_id AS fav_local_id, b.op_code AS op_code \
             FROM fav_bind_tag_db_item b LEFT JOIN fav_tag_db_item t ON t.local_id = b.tag_local_id \
             WHERE b.rowid > {cur} ORDER BY b.rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("favorite_tag", favorite_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "favorite.db".to_string(),
                col: "fav_bind_tag rowid".to_string(),
            })?;
            out.push(FavoriteTagRow {
                rowid: rid,
                tag_server_id: r.get_i64("tag_server_id").unwrap_or(0),
                tag_local_id: r.get_i64("tag_local_id").unwrap_or(0),
                // LEFT JOIN 标签缺 → NULL → 空串 (不丢绑定)。
                tag_name: r.get_str("tag_name").unwrap_or("").to_string(),
                seq: r.get_i64("seq").unwrap_or(0),
                fav_server_id: r.get_i64("fav_server_id").unwrap_or(0),
                fav_local_id: r.get_i64("fav_local_id").unwrap_or(0),
                op_code: r.get_i64("op_code").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(FavoriteTagBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_moments(
        &mut self,
        sns_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<MomentBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // SnsTimeLine keyset — tid = `INTEGER PRIMARY KEY DESC` = rowid 别名, **可为负** (雪花 id 重解释)。
        // ⚠️ 调用方 (run_sns_pipeline) 从 i64::MIN 起, 故 `tid > since` 覆盖负 tid (从 0 起会漏全部负值)。
        // content 是 TEXT XML → 直取 get_str (非 blob hex, 不同于 message_content)。
        // tid/limit 整数内联无注入 (i64::MIN 也是合法整数字面量); 表名 "SnsTimeLine" 固定无注入。
        let sql = format!(
            "SELECT tid, user_name, content FROM SnsTimeLine \
             WHERE tid > {cur} ORDER BY tid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("sns", sns_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_tid = since.local_id;
        for r in &rows {
            // tid = PK + 游标命脉; user_name = 发布者。缺则 schema 漂移报错 (不静默推进错游标)。
            let tid = r.get_i64("tid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "sns.db".to_string(),
                col: "tid".to_string(),
            })?;
            let user_name = r.get_str("user_name").ok_or_else(|| DbSourceError::RowMap {
                db_id: "sns.db".to_string(),
                col: "user_name".to_string(),
            })?;
            out.push(SnsRow {
                tid,
                user_name: user_name.to_string(),
                // content nullable/空 → 空串 (动态本体仍靠 tid/user_name 保留, assemble 退默认)。
                content: r.get_str("content").unwrap_or("").to_string(),
            });
            if tid > max_tid {
                max_tid = tid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(MomentBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_tid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_transfers(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<TransferBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // transferTable 全表重扫 keyset (隐式 rowid 单调分页)。bubble_clicked_flag 真库有 NULL → COALESCE(…,0)。
        // rowid/limit 整数内联无注入; 表名 "transferTable" + 列名固定。**金额不在本表** (在转账消息 XML, 不取)。
        let sql = format!(
            "SELECT rowid AS rid, transfer_id, transcation_id, message_server_id, \
             second_message_server_id, session_name, pay_sub_type, pay_payer, pay_receiver, \
             begin_transfer_time, last_modified_time, invalid_time, last_update_time, \
             delay_confirm_flag, COALESCE(bubble_clicked_flag, 0) AS bubble_clicked_flag \
             FROM transferTable WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("transfer", general_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉; transfer_id = 锚点/身份。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "transferTable rowid".to_string(),
            })?;
            let transfer_id = r.get_str("transfer_id").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "transfer_id".to_string(),
            })?;
            out.push(TransferRow {
                rowid: rid,
                transfer_id: transfer_id.to_string(),
                transcation_id: r.get_str("transcation_id").unwrap_or("").to_string(),
                message_server_id: r.get_i64("message_server_id").unwrap_or(0),
                second_message_server_id: r.get_i64("second_message_server_id").unwrap_or(0),
                session_name: r.get_str("session_name").unwrap_or("").to_string(),
                pay_sub_type: r.get_i64("pay_sub_type").unwrap_or(0),
                pay_payer: r.get_str("pay_payer").unwrap_or("").to_string(),
                pay_receiver: r.get_str("pay_receiver").unwrap_or("").to_string(),
                begin_transfer_time: r.get_i64("begin_transfer_time").unwrap_or(0),
                last_modified_time: r.get_i64("last_modified_time").unwrap_or(0),
                invalid_time: r.get_i64("invalid_time").unwrap_or(0),
                last_update_time: r.get_i64("last_update_time").unwrap_or(0),
                delay_confirm_flag: r.get_i64("delay_confirm_flag").unwrap_or(0),
                bubble_clicked_flag: r.get_i64("bubble_clicked_flag").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(TransferBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_red_envelopes(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<RedEnvelopeBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // redEnvelopeTable 全表重扫 keyset (隐式 rowid 单调分页)。rowid/limit 整数内联无注入; 表名/列名固定。
        // native_url 嵌 sendusername=wxid → 下游出口脱敏 (本层只搬运)。**无时间列** (红包时间靠消息 JOIN)。
        let sql = format!(
            "SELECT rowid AS rid, send_id, message_server_id, session_name, sender_user_name, \
             native_url, scene_id, hb_status, hb_type, receive_status \
             FROM redEnvelopeTable WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("red_envelope", general_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉; send_id = 锚点/身份。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "redEnvelopeTable rowid".to_string(),
            })?;
            let send_id = r.get_str("send_id").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "send_id".to_string(),
            })?;
            out.push(RedEnvelopeRow {
                rowid: rid,
                send_id: send_id.to_string(),
                message_server_id: r.get_i64("message_server_id").unwrap_or(0),
                session_name: r.get_str("session_name").unwrap_or("").to_string(),
                sender_user_name: r.get_str("sender_user_name").unwrap_or("").to_string(),
                native_url: r.get_str("native_url").unwrap_or("").to_string(),
                scene_id: r.get_i64("scene_id").unwrap_or(0),
                hb_status: r.get_i64("hb_status").unwrap_or(0),
                hb_type: r.get_i64("hb_type").unwrap_or(0),
                receive_status: r.get_i64("receive_status").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(RedEnvelopeBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_group_pays(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<GroupPayBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // groupPayTable 全表重扫 keyset (隐式 rowid 单调分页)。rowid/limit 整数内联无注入; 表名/列名固定 (全 4 列)。
        let sql = format!(
            "SELECT rowid AS rid, bill_no, session_name, message_local_id, message_create_time \
             FROM groupPayTable WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("group_pay", general_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉; bill_no = 锚点/身份。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "groupPayTable rowid".to_string(),
            })?;
            let bill_no = r.get_str("bill_no").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "bill_no".to_string(),
            })?;
            out.push(GroupPayRow {
                rowid: rid,
                bill_no: bill_no.to_string(),
                session_name: r.get_str("session_name").unwrap_or("").to_string(),
                message_local_id: r.get_i64("message_local_id").unwrap_or(0),
                message_create_time: r.get_i64("message_create_time").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(GroupPayBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_friend_verifies(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FMessageBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // FMessageTable 全表重扫 keyset (隐式 rowid 单调分页)。只取消费列; type_/timestamp_ 别名避 SQL 关键字。
        // **不取** encrypt_user_name_/ticket_/fmessage_detail_buf_ (低读值, ADR-469)。content_ 出口脱敏 (本层搬运)。
        let sql = format!(
            "SELECT rowid AS rid, user_name_ AS user_name, type_ AS ftype, timestamp_ AS ts, \
             is_sender_ AS is_sender, scene_ AS scene, content_ AS content \
             FROM FMessageTable WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("friend_verify", general_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉; user_name = 锚点/身份。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "FMessageTable rowid".to_string(),
            })?;
            let user_name = r.get_str("user_name").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "user_name_".to_string(),
            })?;
            out.push(FMessageRow {
                rowid: rid,
                user_name: user_name.to_string(),
                friend_type: r.get_i64("ftype").unwrap_or(0),
                timestamp: r.get_i64("ts").unwrap_or(0),
                is_sender: r.get_i64("is_sender").unwrap_or(0),
                scene: r.get_i64("scene").unwrap_or(0),
                content: r.get_str("content").unwrap_or("").to_string(),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(FMessageBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_finder_visits(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FinderBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // wcfinderuserpage 全表重扫 keyset (隐式 rowid 单调分页)。username = 视频号号主 wxid/微信号 (锚点);
        // extra_buffer = proto (assemble_finder 解 f2 昵称 / f5 访问时刻 / f6 URL)。ext_buffer BLOB → hex 搬运。
        // 空壳行 (proto 全空) 由 pipeline 跳过 (不在 SQL 过滤 — 保 rowid 游标连续不跳)。
        let sql = format!(
            "SELECT rowid AS rid, username AS username, \
             hex(coalesce(extra_buffer, x'')) AS extra_hex \
             FROM wcfinderuserpage WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("finder_visit", general_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉; username = 锚点/号主身份。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "wcfinderuserpage rowid".to_string(),
            })?;
            let owner_username = r.get_str("username").ok_or_else(|| DbSourceError::RowMap {
                db_id: "general.db".to_string(),
                col: "wcfinderuserpage.username".to_string(),
            })?;
            let extra_buffer = r.get_blob_hex("extra_hex").unwrap_or_default();
            out.push(FinderRow {
                rowid: rid,
                owner_username: owner_username.to_string(),
                extra_buffer,
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(FinderBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_moment_feeds(
        &mut self,
        sns_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<MomentFeedBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // SnsTopItem_1 全表重扫 keyset (隐式 rowid 单调分页)。username = 发布者 wxid; tid = 动态 id (可为负,
        // 但 rowid 单调正)。**summary 全空不取** (零价值列, ADR-474)。源有重复 tid 行 → sink upsert 去重。
        let sql = format!(
            "SELECT rowid AS rid, tid AS tid, username AS author, create_time AS ct, \
             last_read_time AS lrt, is_read AS ir \
             FROM SnsTopItem_1 WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("moment_feed", sns_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉; author = 发布者身份。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "sns.db".to_string(),
                col: "SnsTopItem_1 rowid".to_string(),
            })?;
            let author = r.get_str("author").ok_or_else(|| DbSourceError::RowMap {
                db_id: "sns.db".to_string(),
                col: "SnsTopItem_1.username".to_string(),
            })?;
            out.push(MomentFeedRow {
                rowid: rid,
                tid: r.get_i64("tid").unwrap_or(0),
                author: author.to_string(),
                create_time: r.get_i64("ct").unwrap_or(0),
                last_read_time: r.get_i64("lrt").unwrap_or(0),
                is_read: r.get_i64("ir").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(MomentFeedBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_sns_notifies(
        &mut self,
        sns_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<SnsNotifyBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // SnsMessage_tmp3 全表重扫 keyset (隐式 rowid 单调分页)。from_username = 互动者 wxid (锚点身份);
        // comment_id = 通知稳定 id (anchor)。type 别名避 SQL 关键字。源可能重复 → sink upsert 去重 (本层只搬运)。
        let sql = format!(
            "SELECT rowid AS rid, comment_id AS cid, feed_id AS fid, type AS ntype, from_username AS fu, \
             from_nickname AS fnk, to_username AS tu, to_nickname AS tnk, content AS ct_text, \
             create_time AS ct, is_unread AS iu, del_status AS ds, is_relative_me AS irm \
             FROM SnsMessage_tmp3 WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("sns_notify", sns_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉; from_user = 互动者身份。缺则 schema 漂移报错 (不静默推进错游标)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "sns.db".to_string(),
                col: "SnsMessage_tmp3 rowid".to_string(),
            })?;
            let from_user = r.get_str("fu").ok_or_else(|| DbSourceError::RowMap {
                db_id: "sns.db".to_string(),
                col: "SnsMessage_tmp3.from_username".to_string(),
            })?;
            out.push(SnsNotifyRow {
                rowid: rid,
                comment_id: r.get_i64("cid").unwrap_or(0),
                feed_id: r.get_i64("fid").unwrap_or(0),
                notify_type: r.get_i64("ntype").unwrap_or(0),
                from_user: from_user.to_string(),
                create_time: r.get_i64("ct").unwrap_or(0),
                from_nickname: r.get_str("fnk").map(str::to_string),
                to_user: r.get_str("tu").map(str::to_string),
                to_nickname: r.get_str("tnk").map(str::to_string),
                // 评论文本空串→None (无正文的赞类通知; 同 moment_feed summary 空不落语义)。
                content: r.get_str("ct_text").filter(|s| !s.is_empty()).map(str::to_string),
                is_unread: r.get_i64("iu").unwrap_or(0),
                del_status: r.get_i64("ds").unwrap_or(0),
                is_relative_me: r.get_i64("irm").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(SnsNotifyBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_emoticons(
        &mut self,
        emoticon_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<EmoticonBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // kNonStoreEmoticonTable 全表重扫 keyset (隐式 rowid 单调分页)。type_ 别名避 SQL 关键字; auth_key 低读值不取。
        let sql = format!(
            "SELECT rowid AS rid, md5 AS md5, type AS etype, caption AS caption, \
             product_id AS product_id, aes_key AS aes_key, cdn_url AS cdn_url, thumb_url AS thumb_url, \
             tp_url AS tp_url, extern_url AS extern_url, extern_md5 AS extern_md5, encrypt_url AS encrypt_url \
             FROM kNonStoreEmoticonTable WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("custom_emoticon", emoticon_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉。缺则 schema 漂移报错 (不静默推进错游标)。md5 是身份 (空串 pipeline 跳)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "emoticon.db".to_string(),
                col: "kNonStoreEmoticonTable rowid".to_string(),
            })?;
            out.push(EmoticonRow {
                rowid: rid,
                md5: r.get_str("md5").unwrap_or("").to_string(),
                emoticon_type: r.get_i64("etype").unwrap_or(0),
                caption: r.get_str("caption").unwrap_or("").to_string(),
                product_id: r.get_str("product_id").unwrap_or("").to_string(),
                aes_key: r.get_str("aes_key").unwrap_or("").to_string(),
                cdn_url: r.get_str("cdn_url").unwrap_or("").to_string(),
                thumb_url: r.get_str("thumb_url").unwrap_or("").to_string(),
                tp_url: r.get_str("tp_url").unwrap_or("").to_string(),
                extern_url: r.get_str("extern_url").unwrap_or("").to_string(),
                extern_md5: r.get_str("extern_md5").unwrap_or("").to_string(),
                encrypt_url: r.get_str("encrypt_url").unwrap_or("").to_string(),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(EmoticonBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_avatars(
        &mut self,
        head_image_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<AvatarBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // head_image 全表重扫 keyset (隐式 rowid 单调分页)。image_buffer BLOB 用 hex() 取 → get_blob_hex 还原 bytes。
        let sql = format!(
            "SELECT rowid AS rid, username AS username, md5 AS md5, \
             hex(coalesce(image_buffer, x'')) AS img, update_time AS update_time \
             FROM head_image WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("avatar_image", head_image_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉。缺则 schema 漂移报错。username 是身份 (空串 pipeline 跳)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "head_image.db".to_string(),
                col: "head_image rowid".to_string(),
            })?;
            out.push(AvatarRow {
                rowid: rid,
                username: r.get_str("username").unwrap_or("").to_string(),
                md5: r.get_str("md5").unwrap_or("").to_string(),
                image_buffer: r.get_blob_hex("img").unwrap_or_default(),
                update_time: r.get_i64("update_time").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(AvatarBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_bizchat_users(
        &mut self,
        bizchat_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<BizChatUserBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // user_info 全表重扫 keyset (隐式 rowid 单调分页)。reserved0..3/version/add_member_url 低读值不取。
        let sql = format!(
            "SELECT rowid AS rid, user_id AS user_id, brand_user_name AS brand_user_name, \
             user_name AS user_name, bit_flag AS bit_flag, head_img_url AS head_img_url, \
             profile_url AS profile_url \
             FROM user_info WHERE rowid > {cur} ORDER BY rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("bizchat", bizchat_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // rid = 游标命脉。缺则 schema 漂移报错 (不静默推进错游标)。user_id 是身份 (空串 pipeline 跳)。
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "bizchat.db".to_string(),
                col: "user_info rowid".to_string(),
            })?;
            out.push(BizChatUserRow {
                rowid: rid,
                user_id: r.get_str("user_id").unwrap_or("").to_string(),
                brand_user_name: r.get_str("brand_user_name").unwrap_or("").to_string(),
                user_name: r.get_str("user_name").unwrap_or("").to_string(),
                bit_flag: r.get_i64("bit_flag").unwrap_or(0),
                head_img_url: r.get_str("head_img_url").unwrap_or("").to_string(),
                profile_url: r.get_str("profile_url").unwrap_or("").to_string(),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(BizChatUserBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }

    async fn drain_chatrooms(
        &mut self,
        contact_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<ChatroomBatch, DbSourceError> {
        let session = self.ensure_session().await?;
        // chat_room 全表重扫 keyset (隐式 rowid 单调); username=群id, owner=群主, ext_buffer=成员 blob。
        // rowid/limit 整数内联无注入; 表名 "chat_room" 固定。ext_buffer coalesce 保证非 NULL hex。
        // chat_room LEFT JOIN contact 取群名 (chat_room 不存群名, 在 contact.nick_name where username=群id) +
        // LEFT JOIN chat_room_info_detail 取群公告 (批H; 公告在独立表 announcement_ 列, WDA 调研确认 +
        // 真库 inspect 验通 166 群有公告)。LEFT JOIN: 群无对应行 → NULL → None。别名 cr/c/cid 消歧。
        // 同表另取 xml_announcement_ (富媒体公告 XML, ADR-460 KI-A) + chat_room_status_ (群状态位, KI-B;
        // 语义待确认, 原值落库), 均 L2-only 不进 digest/payload (同 announcement_editor/publish_time)。
        let sql = format!(
            "SELECT cr.rowid AS rid, cr.username AS username, cr.owner AS owner, \
             hex(coalesce(cr.ext_buffer, x'')) AS ext_hex, c.nick_name AS room_name, \
             c.remark AS room_remark, \
             cid.announcement_ AS announcement, cid.announcement_editor_ AS ann_editor, \
             cid.announcement_publish_time_ AS ann_time, \
             cid.xml_announcement_ AS xml_announcement, cid.chat_room_status_ AS room_status \
             FROM chat_room cr LEFT JOIN contact c ON c.username = cr.username \
             LEFT JOIN chat_room_info_detail cid ON cid.username_ = cr.username \
             WHERE cr.rowid > {cur} ORDER BY cr.rowid LIMIT {limit}",
            cur = since.local_id,
            limit = limit,
        );
        let rows = session.query("contact", contact_db, &sql).await?;
        let fetched = rows.len();
        let mut out = Vec::with_capacity(fetched);
        let mut max_rid = since.local_id;
        for r in &rows {
            // username = 群主键; rid = 游标命脉。缺则 schema 漂移报错 (不静默推进错游标)。
            let chatroom_id = r.get_str("username").ok_or_else(|| DbSourceError::RowMap {
                db_id: "contact.db".to_string(),
                col: "chat_room.username".to_string(),
            })?;
            let rid = r.get_i64("rid").ok_or_else(|| DbSourceError::RowMap {
                db_id: "contact.db".to_string(),
                col: "chat_room.rowid".to_string(),
            })?;
            // owner 空串→None; ext_buffer 缺/坏→空 Vec (pipeline parse_roomdata 三态: 空→Invalid 整群标坏, 不阻塞 drain)。
            let owner = r.get_str("owner").filter(|s| !s.is_empty()).map(str::to_string);
            let ext_buffer = r.get_blob_hex("ext_hex").unwrap_or_default();
            out.push(ChatroomRawRow {
                rowid: rid,
                chatroom_id: chatroom_id.to_string(),
                owner,
                ext_buffer,
                chatroom_name: r.get_str("room_name").filter(|s| !s.is_empty()).map(str::to_string),
                // 群备注 (我给群的私人备注; contact.remark LEFT JOIN, 同群名来源; 未设 → NULL/空串 → None)。
                chatroom_remark: r.get_str("room_remark").filter(|s| !s.is_empty()).map(str::to_string),
                // 批H: 群公告 (chat_room_info_detail LEFT JOIN; 无公告的群 → NULL → None)。
                announcement: r.get_str("announcement").filter(|s| !s.is_empty()).map(str::to_string),
                announcement_editor: r.get_str("ann_editor").filter(|s| !s.is_empty()).map(str::to_string),
                announcement_publish_time: r.get_i64("ann_time").unwrap_or(0),
                // 富媒体公告 XML (ADR-460 KI-A; 缺/空 → None) + 群状态位 (KI-B; 未知/无 → 0)。
                xml_announcement: r
                    .get_str("xml_announcement")
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                chat_room_status: r.get_i64("room_status").unwrap_or(0),
            });
            if rid > max_rid {
                max_rid = rid;
            }
        }
        let has_more = limit > 0 && fetched == limit;
        Ok(ChatroomBatch {
            rows: out,
            next_cursor: DrainCursor {
                local_id: max_rid,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            },
            has_more,
        })
    }
}

/// 从 Name2Id 行建 `rowid→user_name` + `md5(user_name)→user_name`。
fn build_name2id_maps(rows: &[CipherRow]) -> Name2IdMaps {
    let mut sender_by_rowid = HashMap::new();
    let mut conv_by_md5 = HashMap::new();
    for r in rows {
        let Some(user_name) = r.get_str("user_name") else {
            continue;
        };
        if user_name.is_empty() {
            continue;
        }
        if let Some(rid) = r.get_i64("rid") {
            sender_by_rowid.insert(rid, user_name.to_string());
        }
        // md5 小写 hex (跟 Msg_<md5> 表名同算法; decoder/anchor.rs 同款 `{:x}`)。
        let md5 = format!("{:x}", md5::compute(user_name.as_bytes()));
        conv_by_md5.insert(md5, user_name.to_string());
    }
    Name2IdMaps {
        sender_by_rowid,
        conv_by_md5,
    }
}

/// 标签件: 从 `contact_label` 查询行建 `label_id → label_name` map (照 [`build_name2id_maps`] 手法)。
/// 空/坏行跳过 (缺 lid 或 lname → 忽略); 名字空串也存 (交由解析端拼接决定)。
fn build_label_map(rows: &[CipherRow]) -> HashMap<i64, String> {
    let mut map = HashMap::with_capacity(rows.len());
    for r in rows {
        let (Some(lid), Some(lname)) = (r.get_i64("lid"), r.get_str("lname")) else {
            continue;
        };
        map.insert(lid, lname.to_string());
    }
    map
}

/// 标签件: 解一个联系人的标签 id 串 (extra_buffer f30, 如 `"1,3,"`) → 标签名逗号拼串 (如 `"老板,客户"`)。
///
/// 照 message drain 的 Name2Id **当场解析** 手法: 逗号拆 id → 查 `label_map` 得名字 → 逗号拼。
/// 解不出的 id (map 无此 key / 非数字段) 跳过; 全解不出或无 f30 → None (= 无标签)。**infallible**。
fn resolve_labels(extra_buffer: &[u8], label_map: &HashMap<i64, String>) -> Option<String> {
    let id_list = crate::decoder::contact_extra::extract_label_list(extra_buffer)?;
    let names: Vec<&str> = id_list
        .split(',')
        .filter_map(|tok| tok.trim().parse::<i64>().ok())
        .filter_map(|id| label_map.get(&id).map(String::as_str))
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names.join(","))
    }
}

/// `message_<n>.db` (n 为 ≥1 位数字)。例: `message_0.db`。
fn is_message_db(name: &str) -> bool {
    let Some(mid) = name.strip_prefix("message_").and_then(|s| s.strip_suffix(".db")) else {
        return false;
    };
    !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit())
}

/// `biz_message_<digits>.db` (公众号消息库; ADR-480)。schema 与 `message_*.db` 全同, 复用 message pipeline。
fn is_biz_message_db(name: &str) -> bool {
    let Some(mid) = name.strip_prefix("biz_message_").and_then(|s| s.strip_suffix(".db")) else {
        return false;
    };
    !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit())
}

/// R9 复审#3: watch/ingest 的消息库文件名匹配。`biz_mode`=true → 仅 `biz_message_*.db` (export 二次扫);
/// 否则 `message_*.db`, 且 `include_biz`=true 时叠加 `biz_message_*.db` (live-index watch 一趟覆盖两者)。
fn message_db_matches(name: &str, biz_mode: bool, include_biz: bool) -> bool {
    if biz_mode {
        is_biz_message_db(name)
    } else {
        is_message_db(name) || (include_biz && is_biz_message_db(name))
    }
}

/// `^Msg_[0-9a-f]{32}$` — `Msg_` + 32 位小写 hex (md5)。排除 `Name2Id` / `Msg_<md5>_fts` 等。
fn is_msg_table(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 36 && &b[..4] == b"Msg_" && b[4..].iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// 文件 (mtime_ms, size_bytes) — mtime 取不到 → 0 (非致命, 仅元数据)。
fn file_stat(meta: &std::fs::Metadata) -> (i64, u64) {
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    (mtime_ms, meta.len())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::cipher::CipherError;

    // ── 纯函数 ──

    #[test]
    fn is_message_db_filters() {
        assert!(is_message_db("message_0.db"));
        assert!(is_message_db("message_10.db"));
        assert!(!is_message_db("message_.db")); // 无数字
        assert!(!is_message_db("message_x.db")); // 非数字
        assert!(!is_message_db("contact_0.db"));
        assert!(!is_message_db("message_0.db.bak"));
        assert!(!is_message_db("Message_0.db")); // 大小写敏感
                                                 // ADR-480: biz_message_*.db 不被普通 message 过滤器匹配 (避免混入常规 message ingest)。
        assert!(!is_message_db("biz_message_0.db"), "biz 不算普通 message");
        assert!(is_biz_message_db("biz_message_0.db"));
        assert!(is_biz_message_db("biz_message_1.db"));
        assert!(!is_biz_message_db("message_0.db"), "普通 message 不算 biz");
        assert!(!is_biz_message_db("biz_message_.db"));
    }

    /// R9 复审#3: message_db_matches —— 默认仅 regular / include_biz 叠加 biz / biz_mode 仅 biz。
    #[test]
    fn message_db_matches_include_biz() {
        // 默认 (biz_mode=false, include_biz=false): 仅 regular, biz 被排除 (复审#3 之前 watch 就漏这里)。
        assert!(message_db_matches("message_0.db", false, false));
        assert!(!message_db_matches("biz_message_0.db", false, false), "默认不含 biz");
        // include_biz=true (live-index watch): regular + biz 一趟都覆盖。
        assert!(message_db_matches("message_3.db", false, true));
        assert!(
            message_db_matches("biz_message_2.db", false, true),
            "include_biz 叠加 biz"
        );
        // biz_mode=true (export 二次扫): 仅 biz。
        assert!(message_db_matches("biz_message_1.db", true, false));
        assert!(!message_db_matches("message_1.db", true, false), "biz_mode 仅 biz");
        // 非消息库都不匹配。
        assert!(!message_db_matches("contact.db", false, true));
    }

    /// codex 批B P1: drain_favorites 的 `LENGTH(CAST(content AS BLOB))` 对 TEXT 列取**字节长度** (非字符数)。
    /// 中文 content: 3 汉字 = 9 字节 (UTF-8) ≠ 3 字符 → 验 CAST AS BLOB 修正 (LENGTH(TEXT) 会返 3 低估)。
    #[test]
    fn favorite_content_len_is_byte_length() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE fav_db_item (local_id INTEGER, content TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO fav_db_item VALUES (1, '收藏笔记')", [])
            .unwrap(); // 4 汉字 = 12 字节
        let byte_len: i64 = conn
            .query_row(
                "SELECT LENGTH(CAST(content AS BLOB)) FROM fav_db_item WHERE local_id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let char_len: i64 = conn
            .query_row("SELECT LENGTH(content) FROM fav_db_item WHERE local_id=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(char_len, 4, "LENGTH(TEXT) = 字符数 4 (低估)");
        assert_eq!(byte_len, 12, "LENGTH(CAST AS BLOB) = 字节数 12 (UTF-8 汉字 3 字节)");
    }

    #[test]
    fn is_msg_table_strict_regex() {
        let good = format!("Msg_{:x}", md5::compute(b"wxid_alice"));
        assert_eq!(good.len(), 36);
        assert!(is_msg_table(&good));
        assert!(!is_msg_table("Name2Id"));
        assert!(!is_msg_table("Msg_short"));
        assert!(!is_msg_table(&format!("{good}_fts"))); // FTS 辅助表 (有后缀)
        assert!(!is_msg_table("Msg_0123456789ABCDEF0123456789abcdef")); // 含大写
        assert!(!is_msg_table("Msg_0123456789abcdef0123456789abcde")); // 31 hex
    }

    #[test]
    fn build_name2id_maps_resolves_both() {
        let rows = vec![
            CipherRow::new(vec![
                ("rid".into(), Some("1".into())),
                ("user_name".into(), Some("wxid_alice".into())),
            ]),
            CipherRow::new(vec![
                ("rid".into(), Some("2".into())),
                ("user_name".into(), Some("grp@chatroom".into())),
            ]),
            // 空 user_name → 跳过
            CipherRow::new(vec![
                ("rid".into(), Some("3".into())),
                ("user_name".into(), Some(String::new())),
            ]),
        ];
        let m = build_name2id_maps(&rows);
        assert_eq!(m.sender_by_rowid.get(&1).map(String::as_str), Some("wxid_alice"));
        assert_eq!(m.sender_by_rowid.get(&2).map(String::as_str), Some("grp@chatroom"));
        assert!(!m.sender_by_rowid.contains_key(&3), "空 user_name 跳过");
        let md5_alice = format!("{:x}", md5::compute(b"wxid_alice"));
        assert_eq!(m.conv_by_md5.get(&md5_alice).map(String::as_str), Some("wxid_alice"));
    }

    // ── 标签件: build_label_map + resolve_labels ──

    /// 编码 extra_buffer 的 f30 标签 id 串 (proto: tag=(30<<3)|2, len, utf8)。
    fn extra_with_f30(id_list: &str) -> Vec<u8> {
        let mut out = vec![0xF2, 0x01]; // f30 tag (240|2=242) varint = [0xF2,0x01]
        out.push(id_list.len() as u8); // len (测试串短, 单字节)
        out.extend_from_slice(id_list.as_bytes());
        out
    }

    #[test]
    fn build_label_map_skips_bad_rows() {
        let rows = vec![
            CipherRow::new(vec![
                ("lid".into(), Some("1".into())),
                ("lname".into(), Some("老板".into())),
            ]),
            CipherRow::new(vec![
                ("lid".into(), Some("3".into())),
                ("lname".into(), Some("客户".into())),
            ]),
            // 缺 lname → 跳过
            CipherRow::new(vec![("lid".into(), Some("9".into()))]),
        ];
        let m = build_label_map(&rows);
        assert_eq!(m.get(&1).map(String::as_str), Some("老板"));
        assert_eq!(m.get(&3).map(String::as_str), Some("客户"));
        assert!(!m.contains_key(&9), "缺 lname 行跳过");
    }

    #[test]
    fn resolve_labels_joins_names() {
        let mut map = HashMap::new();
        map.insert(1, "老板".to_string());
        map.insert(3, "客户".to_string());
        // "1,3," → 老板,客户 (尾逗号空段被 parse 过滤)。
        assert_eq!(
            resolve_labels(&extra_with_f30("1,3,"), &map).as_deref(),
            Some("老板,客户")
        );
        // 单个 id。
        assert_eq!(resolve_labels(&extra_with_f30("3,"), &map).as_deref(), Some("客户"));
    }

    #[test]
    fn resolve_labels_edge_cases() {
        let mut map = HashMap::new();
        map.insert(1, "老板".to_string());
        // 无 f30 → None。
        assert_eq!(resolve_labels(&[], &map), None, "无 extra → None");
        // f30 存在但 id 全不在 map (如 "7,") → None (全解不出)。
        assert_eq!(resolve_labels(&extra_with_f30("7,"), &map), None, "id 不在 map → None");
        // 部分解得: "1,7," → 只有 1 命中 → "老板" (未知 id 跳过)。
        assert_eq!(
            resolve_labels(&extra_with_f30("1,7,"), &map).as_deref(),
            Some("老板"),
            "未知 id 跳过, 保留已知"
        );
        // 空 map → None (contact_label 缺表降级)。
        assert_eq!(
            resolve_labels(&extra_with_f30("1,"), &HashMap::new()),
            None,
            "空 map → None"
        );
    }

    // ── mock Cipher / DbSession (按 SQL 分派 canned 行; data 走 Arc<Mutex> 便于测缓存失效) ──

    #[derive(Clone)]
    struct MockData {
        name2id: Vec<(i64, String)>, // (rowid, user_name)
        tables: Vec<String>,         // sqlite_master 表名
        msg_rows: Vec<MsgRow>,       // drain 行
    }
    #[derive(Clone)]
    struct MsgRow {
        local_id: i64,
        real_sender_id: i64,
        content_hex: String,
    }

    type Shared = Arc<std::sync::Mutex<MockData>>;

    struct MockSession {
        data: Shared,
    }

    #[async_trait]
    impl DbSession for MockSession {
        async fn query(&self, _kind: &str, _sub_db: &Path, sql: &str) -> Result<Vec<CipherRow>, CipherError> {
            // 锁内取快照即解锁 (不跨 await 持锁)。
            let data = self.data.lock().unwrap().clone();
            if sql.contains("sqlite_master") {
                Ok(data
                    .tables
                    .iter()
                    .map(|n| CipherRow::new(vec![("name".into(), Some(n.clone()))]))
                    .collect())
            } else if sql.contains("Name2Id") {
                Ok(data
                    .name2id
                    .iter()
                    .map(|(rid, un)| {
                        CipherRow::new(vec![
                            ("rid".into(), Some(rid.to_string())),
                            ("user_name".into(), Some(un.clone())),
                        ])
                    })
                    .collect())
            } else {
                // drain: 返 msg_rows (mock 忽略 WHERE/LIMIT, 由测试控制期望)。
                Ok(data
                    .msg_rows
                    .iter()
                    .map(|m| {
                        CipherRow::new(vec![
                            ("local_id".into(), Some(m.local_id.to_string())),
                            ("server_id".into(), Some("9000".into())),
                            ("local_type".into(), Some("1".into())),
                            ("sort_seq".into(), Some("1700000000000".into())),
                            ("create_time".into(), Some("1700000000".into())),
                            ("status".into(), Some("4".into())),
                            ("mc_hex".into(), Some(m.content_hex.clone())),
                            ("real_sender_id".into(), Some(m.real_sender_id.to_string())),
                        ])
                    })
                    .collect())
            }
        }
    }

    struct MockCipher {
        data: Shared,
    }
    #[async_trait]
    impl Cipher for MockCipher {
        async fn open_account(&self, _db: &Path, _key: &MasterKey) -> Result<Box<dyn DbSession>, CipherError> {
            Ok(Box::new(MockSession {
                data: self.data.clone(),
            }))
        }
        async fn verify(&self, _db: &Path, _key: &MasterKey) -> Result<(), CipherError> {
            Ok(())
        }
        fn name(&self) -> &'static str {
            "mock"
        }
    }

    fn mk_source_shared(data: Shared, db_dir: PathBuf) -> AccountDbSource {
        AccountDbSource::new(
            Box::new(MockCipher { data }),
            PathBuf::from("/wx/session/session.db"),
            MasterKey::from_hex(&"a".repeat(64)).unwrap(),
            Wxid::try_new("wxid_self").unwrap(),
            db_dir,
        )
    }

    fn mk_source(data: MockData, db_dir: PathBuf) -> AccountDbSource {
        mk_source_shared(Arc::new(std::sync::Mutex::new(data)), db_dir)
    }

    #[tokio::test]
    async fn snapshot_dbs_scans_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "message_0.db",
            "message_10.db",
            "contact.db",
            "message_x.db",
            "note.txt",
        ] {
            std::fs::write(dir.path().join(f), b"x").unwrap();
        }
        let mut src = mk_source(
            MockData {
                name2id: vec![],
                tables: vec![],
                msg_rows: vec![],
            },
            dir.path().to_path_buf(),
        );
        let snaps = src.snapshot_dbs().await.unwrap();
        let names: Vec<&str> = snaps.iter().map(|s| s.rel_name.as_str()).collect();
        assert_eq!(
            names,
            vec!["message_0.db", "message_10.db"],
            "只取 message_<n>.db + 排序"
        );
        assert!(snaps[0].db_id.ends_with("|message_0.db"));
        assert_eq!(snaps[0].kind, "message");
    }

    #[tokio::test]
    async fn list_subsources_resolves_filters_skips() {
        let alice = format!("Msg_{:x}", md5::compute(b"wxid_alice"));
        let grp = format!("Msg_{:x}", md5::compute(b"grp@chatroom"));
        let orphan = "Msg_ffffffffffffffffffffffffffffffff".to_string(); // md5 无对应 Name2Id
        let data = MockData {
            name2id: vec![
                (1, "wxid_alice".into()),
                (2, "grp@chatroom".into()),
                (3, "wxid_bob".into()), // 仅 sender, 无 Msg_ 表
            ],
            tables: vec![
                alice.clone(),
                grp.clone(),
                format!("{alice}_fts"), // FTS → is_msg_table 过滤
                "Name2Id".into(),       // 非 Msg_ → 过滤
                orphan.clone(),         // 反解不到 → 跳过+计数
            ],
            msg_rows: vec![],
        };
        let dir = tempfile::tempdir().unwrap();
        let mut src = mk_source(data, dir.path().to_path_buf());
        let snap = DbSnapshot {
            db_id: format!("{}|message_0.db", sha8(b"wxid_self")),
            wxid: Wxid::try_new("wxid_self").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from("/wx/message_0.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 0,
            size_bytes: 0,
        };
        let subs = src.list_message_subsources(&snap).await.unwrap();
        let mut convs: Vec<&str> = subs.iter().map(|s| s.conv_id.as_str()).collect();
        convs.sort_unstable();
        assert_eq!(
            convs,
            vec!["grp@chatroom", "wxid_alice"],
            "解析 2 个, FTS/Name2Id/orphan 排除"
        );
        assert!(subs.iter().any(|s| s.table == alice && s.conv_id == "wxid_alice"));
    }

    #[tokio::test]
    async fn drain_maps_rows_sender_and_cursor() {
        let data = MockData {
            name2id: vec![(1, "wxid_alice".into())],
            tables: vec![],
            msg_rows: vec![
                MsgRow {
                    local_id: 5,
                    real_sender_id: 1,
                    content_hex: hex::encode("hi"),
                },
                MsgRow {
                    local_id: 7,
                    real_sender_id: 99,
                    content_hex: hex::encode("yo"),
                }, // 99 不在 map
            ],
        };
        let dir = tempfile::tempdir().unwrap();
        let mut src = mk_source(data, dir.path().to_path_buf());
        let snap = DbSnapshot {
            db_id: "s|message_0.db".into(),
            wxid: Wxid::try_new("wxid_self").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from("/wx/message_0.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 0,
            size_bytes: 0,
        };
        let sub = MessageSubsource {
            table: format!("Msg_{:x}", md5::compute(b"wxid_alice")),
            conv_id: "wxid_alice".into(),
        };
        let batch = src
            .drain_messages(
                &snap,
                &sub,
                &DrainCursor {
                    local_id: 0,
                    resume_fp: None,
                    cursor_ct: None,
                    cursor_sid: None,
                    prefix_rows: None,
                },
                10,
            )
            .await
            .unwrap();
        assert_eq!(batch.rows.len(), 2);
        assert_eq!(batch.rows[0].local_id, 5);
        assert_eq!(batch.rows[0].sender_username.as_deref(), Some("wxid_alice"));
        assert_eq!(batch.rows[0].message_content, b"hi");
        assert_eq!(batch.rows[1].sender_username, None, "rowid 99 不在 Name2Id → None");
        assert_eq!(batch.next_cursor.local_id, 7, "游标推进到最大 local_id");
        assert!(!batch.has_more, "2 行 < limit 10");
    }

    #[tokio::test]
    async fn drain_has_more_when_full() {
        let data = MockData {
            name2id: vec![],
            tables: vec![],
            msg_rows: vec![
                MsgRow {
                    local_id: 1,
                    real_sender_id: 0,
                    content_hex: String::new(),
                },
                MsgRow {
                    local_id: 2,
                    real_sender_id: 0,
                    content_hex: String::new(),
                },
            ],
        };
        let dir = tempfile::tempdir().unwrap();
        let mut src = mk_source(data, dir.path().to_path_buf());
        let snap = DbSnapshot {
            db_id: "s|message_0.db".into(),
            wxid: Wxid::try_new("wxid_self").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from("/wx/message_0.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 0,
            size_bytes: 0,
        };
        let sub = MessageSubsource {
            table: "Msg_0123456789abcdef0123456789abcdef".into(),
            conv_id: "wxid_x".into(),
        };
        // limit=2, 返 2 行 → has_more; 空 content_hex → 空 blob 不跳行。
        let batch = src
            .drain_messages(&snap, &sub, &DrainCursor::default(), 2)
            .await
            .unwrap();
        assert_eq!(batch.rows.len(), 2);
        assert!(batch.has_more, "拿满 limit → has_more");
        assert!(batch.rows[0].message_content.is_empty(), "空 blob 不跳行");
    }

    #[tokio::test]
    async fn drain_rejects_bad_table_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = mk_source(
            MockData {
                name2id: vec![],
                tables: vec![],
                msg_rows: vec![],
            },
            dir.path().to_path_buf(),
        );
        let snap = DbSnapshot {
            db_id: "s|message_0.db".into(),
            wxid: Wxid::try_new("wxid_self").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from("/wx/message_0.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 0,
            size_bytes: 0,
        };
        // 注入企图: 表名非白名单 → MapMissing (不发 query)。
        let sub = MessageSubsource {
            table: "Msg_x; DROP TABLE Name2Id".into(),
            conv_id: "wxid_x".into(),
        };
        let err = src
            .drain_messages(&snap, &sub, &DrainCursor::default(), 10)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DbSourceError::MapMissing { .. }),
            "非法表名应 MapMissing: {err:?}"
        );
    }

    /// K-R4: AccountDbSource Debug 不泄 wxid 明文 / 路径 / key.
    #[tokio::test]
    async fn source_debug_redacts() {
        let dir = tempfile::tempdir().unwrap();
        let src = mk_source(
            MockData {
                name2id: vec![],
                tables: vec![],
                msg_rows: vec![],
            },
            dir.path().join("wxid_self_secret_dir"),
        );
        let dbg = format!("{src:?}");
        assert!(!dbg.contains("wxid_self"), "Debug 泄 wxid: {dbg}");
        assert!(!dbg.contains("session.db"), "Debug 泄 entry 路径: {dbg}");
        assert!(!dbg.contains("aaaa"), "Debug 泄 key hex: {dbg}");
        assert!(dbg.contains("db_dir_sha8"), "应 db_dir sha8: {dbg}");
    }

    /// 代码双审 P0 (targeted): mc_hex 解不出 (列缺/非 hex) → RowMap (不静默清空正文)。
    #[tokio::test]
    async fn drain_bad_mc_hex_is_rowmap() {
        let data = MockData {
            name2id: vec![],
            tables: vec![],
            msg_rows: vec![MsgRow {
                local_id: 1,
                real_sender_id: 0,
                content_hex: "zznothex".into(),
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        let mut src = mk_source(data, dir.path().to_path_buf());
        let snap = DbSnapshot {
            db_id: "s|message_0.db".into(),
            wxid: Wxid::try_new("wxid_self").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from("/wx/message_0.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 0,
            size_bytes: 0,
        };
        let sub = MessageSubsource {
            table: "Msg_0123456789abcdef0123456789abcdef".into(),
            conv_id: "wxid_x".into(),
        };
        match src.drain_messages(&snap, &sub, &DrainCursor::default(), 10).await {
            Err(DbSourceError::RowMap { col, .. }) => assert_eq!(col, "mc_hex"),
            other => panic!("坏 mc_hex 应 RowMap, got {other:?}"),
        }
    }

    /// 代码双审 P0/P1: 第 2 轮 snapshot 清 Name2Id 缓存 → 长跑期间新增会话能被反解 (不因旧 map 静默漏)。
    #[tokio::test]
    async fn second_snapshot_round_refreshes_name2id_cache() {
        let alice = format!("Msg_{:x}", md5::compute(b"wxid_alice"));
        let bob = format!("Msg_{:x}", md5::compute(b"wxid_bob"));
        let shared = Arc::new(std::sync::Mutex::new(MockData {
            name2id: vec![(1, "wxid_alice".into())],
            tables: vec![alice.clone()],
            msg_rows: vec![],
        }));
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("message_0.db"), b"x").unwrap();
        let mut src = mk_source_shared(shared.clone(), dir.path().to_path_buf());

        // 第 1 轮: 只有 alice (snapshot → list, 填 Name2Id 缓存)。
        let snaps1 = src.snapshot_dbs().await.unwrap();
        let subs1 = src.list_message_subsources(&snaps1[0]).await.unwrap();
        assert_eq!(subs1.len(), 1, "第 1 轮 1 会话");

        // 模拟长跑期间新会话 bob 写入 (Name2Id 行 + Msg_ 表)。
        {
            let mut d = shared.lock().unwrap();
            d.name2id.push((2, "wxid_bob".into()));
            d.tables.push(bob.clone());
        }

        // 第 2 轮: snapshot_dbs 清缓存 → list 重查 Name2Id → 新会话 bob 被反解纳入。
        // (若不清缓存, 旧 conv_by_md5 反解不到 bob → 仍只 1 个 + unresolved warn。)
        let snaps2 = src.snapshot_dbs().await.unwrap();
        let subs2 = src.list_message_subsources(&snaps2[0]).await.unwrap();
        let mut convs: Vec<&str> = subs2.iter().map(|s| s.conv_id.as_str()).collect();
        convs.sort_unstable();
        assert_eq!(convs, vec!["wxid_alice", "wxid_bob"], "第 2 轮缓存刷新, 新会话纳入");
    }
}
