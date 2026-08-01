//! source — DbSource trait (ADR-405 §3.1 trait 3/7; 取数模型按 ADR-423 §3.4 重定).
//!
//! 责任: 从 cipher 开的账号会话 (`DbSession`) 按子源 (一张 `Msg_<md5(talker)>` 表 = 一个会话)
//! 按 `local_id` 单调游标增量 drain 消息 → decoder 输入 (`MessageRow`)。是 cipher (解密查询) 与
//! decoder (业务解码) 之间的取数适配层。
//!
//! 本 mod = trait + 类型 (`DbSnapshot` / `MessageSubsource` / `DrainCursor` / `MessageBatch` /
//! `DbSourceError`); impl = [`AccountDbSource`] (account.rs)。
//!
//! ## 取数模型 (ADR-423 §3.4 + drain 设计双审 v2)
//! 一个 message_N.db 含 N 张 `Msg_<md5(talker)>` 表 (每会话一张; 实测 message_0.db = 3383 张)。
//! 不做全局 `UNION ALL` 归并 (3383 分支 SQL 每批重 parse, 不扩展), 而是 **逐子源 keyset 分页**:
//!
//! 1. `snapshot_dbs` 扫盘列 `message_*.db` 子库 + 开账号会话 (1 账号 1 session, 全程复用)。
//! 2. `list_message_subsources` 枚举一个子库内的 `Msg_` 表 (子源) + 反解每张表的 `conv_id`。
//! 3. `drain_messages` 对单个子源跑 `WHERE local_id > cursor ORDER BY local_id LIMIT n` 增量读。
//!
//! adapter 主 loop: `for db in snapshot_dbs { for sub in list_message_subsources(db) { loop drain } }`。
//!
//! ## 游标 = 子源内 `local_id` 单调高水位 (drain 设计双审 v2)
//! 每子源 (db × `Msg_` 表) 各自一条 etl_state 水位 (键 `source="<rel_name>|<table>"`, `kind="message"`)。
//! `local_id` 是 `Msg_` 表 rowid (主键, 单调递增 = 新消息 append), keyset `WHERE local_id > cur` 增量。
//! 子源各自水位 → 新会话首扫自动纳入 (无水位=从 0), 删除会话残留水位无害 (表没了查空)。
//!
//! ⚠️ KI (local_id 单调假设): `local_id` 只覆盖 append/新建; 已 drain 行后续的就地改 (status/撤回/编辑)
//! 不会被 `local_id > cur` 重扫 (alpha 不追改; 同步/迁移异常兜底 = 子源水位清零全量 re-drain)。
//!
//! ## 跨 db 重复 = intended 每库 provenance (不在此去重)
//! 同一消息可能存在于多张 message_N.db (微信存储优化)。L1-schema `raw_payload_archive` UNIQUE +
//! L2 `message` PK + fingerprint canonical **都含 `source`** → 每库各留一份是 intended; 去重在 **QUERY 期**
//! (ADR-406 partial-hit merge, `dedup_key=server_id`), 不在 drain/ingest。故 drain 按 (db, 子源) emit 不去重。
//!
//! ## sender 解析 (Rust map, 非 SQL JOIN)
//! `Msg_.real_sender_id` = 同库 `Name2Id.rowid`; 取同库全量 `rowid→user_name` 在 Rust map 解 sender
//! (不在 SQL 做 JOIN — exec_query 单表更简单/稳定)。`conv_id` 反解同理: `md5(user_name)→user_name`。
//!
//! ## 字段非敏感 / K-R4
//! `DbSnapshot.sub_db_path` 含 wxid → 手写 Debug sha8; `MessageSubsource.conv_id` 含明文 wxid/chatroom_id
//! → 手写 Debug sha8; `MessageSubsource.table` 是 `Msg_<md5>` (哈希, 非明文)。`MessageRow` 脱敏由下游
//! decoder/event 出口处理 (本层只搬运)。

mod account;
use std::path::{Path, PathBuf};

pub use account::AccountDbSource;
use async_trait::async_trait;

use crate::decoder::{
    AvatarRow, BizChatUserRow, ContactRow, EmoticonRow, FMessageRow, FavoriteRow, FavoriteTagRow, FinderRow,
    GroupPayRow, MessageRow, MomentFeedRow, RedEnvelopeRow, SessionRow, SnsNotifyRow, SnsRow, TransferRow,
};
use crate::key_provider::{sha8, Wxid};

/// 一个源子库快照 (ADR-423 §3.4) — 一张 `message_N.db`。
///
/// K-R4 (代码双审 P0): `db_id` 用 **`sha8(wxid)|rel_name`**(非明文 wxid)— 跨账号唯一且非敏感,
/// 跟 etl_state `account_id_sha` 维度一致; `sub_db_path` 含 wxid → 手写 Debug sha8 (不 derive Debug)。
#[derive(Clone)]
pub struct DbSnapshot {
    /// 跨账号唯一 = **`sha8(wxid)|rel_name`**(非敏感, 不存明文 wxid)。两账号都有 message_0.db,
    /// 只留 rel_name 会撞键 → 必带 sha8(wxid) 段 (ADR-423 §3.4 双审 P0)。
    pub db_id: String,
    /// 所属账号 (Wxid Display/Debug 已 sha8, K-R4).
    pub wxid: Wxid,
    /// exec_query kind ("message" / "contact" / "session" / ...).
    pub kind: String,
    /// 子库绝对路径 (扫盘得)。**含 wxid** → Debug 出口 sha8。
    pub sub_db_path: PathBuf,
    /// 子库文件名 (e.g. "message_0.db") = etl_state.source 的库维度 (非敏感)。
    pub rel_name: String,
    /// 源 db mtime (毫秒).
    pub mtime_ms: i64,
    /// 源 db 大小 (字节).
    pub size_bytes: u64,
}

// K-R4 (代码双审 P0): 手写 Debug — sub_db_path 含 wxid → sha8; db_id 已是非敏感组合; wxid 走其 Display (已 sha8).
impl std::fmt::Debug for DbSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbSnapshot")
            .field("db_id", &self.db_id)
            .field("wxid", &format_args!("{}", self.wxid))
            .field("kind", &self.kind)
            .field("sub_db_path_sha8", &sha8(self.sub_db_path.to_string_lossy().as_bytes()))
            .field("rel_name", &self.rel_name)
            .field("mtime_ms", &self.mtime_ms)
            .field("size_bytes", &self.size_bytes)
            .finish()
    }
}

/// 一个消息子源 = 一张 `Msg_<md5(talker)>` 表 (= 一个会话)。
///
/// `table` 是子源稳定标识 (= etl_state `source` 的 conv 段; `Msg_<md5>` 是哈希, 非明文, 安全)。
/// `conv_id` 是会话标识 (单聊=对方 UserName / 群=`xxx@chatroom`), 由 `md5(user_name)→user_name` 反解
/// (Name2Id), **含明文 wxid/chatroom_id** → 手写 Debug sha8 (K-R4)。
#[derive(Clone, PartialEq, Eq)]
pub struct MessageSubsource {
    /// 子源表名 `Msg_<32位小写hex md5>` (白名单正则 `^Msg_[0-9a-f]{32}$` 校验过)。
    pub table: String,
    /// 会话标识 (供 `MessageContext.conv_id` + 群聊判定)。**含明文** → Debug 脱敏。
    pub conv_id: String,
}

// K-R4: conv_id 含明文 wxid/chatroom_id → Debug 走 sha8; table 是 md5 哈希, 非明文, 保留.
impl std::fmt::Debug for MessageSubsource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSubsource")
            .field("table", &self.table)
            .field("conv_id_sha8", &sha8(self.conv_id.as_bytes()))
            .finish()
    }
}

/// 把一行的若干整数字段混成一个 64 位指纹 —— **drain 侧和探测侧必须调同一个函数**, 否则两边算不出同一个值。
///
/// FNV-1a 变体, 无随机种子 → 跨进程跨次运行**确定**(不能用 `DefaultHasher`, 它带随机种子)。
///
/// ⚠️ **字段选择被审了三轮才定死**, 三次教训都记在这:
/// - `(server_id, create_time)` **认不出行**(round-1): 同会话同 `server_id`、只差 `status` 的真实行存在。
/// - `server_seq` / `status` **会就地变**(round-2): 消息同步时它们变而表没被重建 → 误判成重建 →
///   整个会话重扫重发。**可变字段绝不能进身份指纹。**
/// - 只留 `(create_time 秒, local_type, 正文长度)` **基数不够**(round-3): 同一秒发的两条同长度文本
///   就撞了 —— 重建后正好把这种行摆在游标位置, 指纹"对得上", 游标以下永久跳过。
///
/// 所以最终**混正文的全部字节**: 内容不可变、基数最高, 而且两侧对**同一串字节**算, 口径不可能漂。
/// (`length()` 那种取巧写法在 TEXT 存储下数的是字符不是字节, round-2 就栽在这。)
///
/// `local_id` 也进指纹(round-4): 锚点换成"**最老那一行**"以后, 老消息被清干净、新表从 1 重来时,
/// 光比内容有撞上的可能 —— 把行号一起混进去就没有。
/// 参数固定成四个, **不再用 `&[i64]` 传字段列表** —— 那种签名给"两侧字段集写得不一样"留了口子。
#[must_use]
pub fn row_fingerprint(local_id: i64, create_time: i64, local_type: i64, content: &[u8]) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    };
    for v in [local_id, create_time, local_type] {
        for b in v.to_le_bytes() {
            mix(b);
        }
    }
    for b in content {
        mix(*b);
    }
    h as i64
}

/// 探得多深 —— 只影响**要不要扫行**那一项(`prefix_rows`)。
///
/// 前四个信号全是主键点查, 白送; 第五个 `count(*)` 要扫已读那一段, 真库最大表 +420 ms、
/// 约 2.4 秒/百万行。所以按路径分:
///
/// | 路径 | 深度 | 为什么 |
/// |---|---|---|
/// | 全量 `ingest` | `Deep` | 一次性几十秒, 而它正是"第一次建立这个数"的时机 |
/// | 懒式刷新 `ensure_chat_fresh` | `Deep` | 一次只碰一个会话, 最坏 0.42 秒, 而闸开本来就要约 1.6 秒 |
/// | `watch` 每轮全子源循环 | `Shallow` | 750 万行 ≈ 18 秒/轮, 付不起 |
///
/// ⚠️ `Shallow` **不会让这个数变陈旧**: 它是"已读段的行数", 而每批 drain 恰好读走
/// `(旧游标, 新游标]` 里的**全部**行 —— 所以新值 = 旧值 + 本批行数, drain 侧**算术推进即可**,
/// 不用查库(见 `account.rs` 的 drain 实现)。`Deep` 是拿库里的真值**核对**它, 不是维护它。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeDepth {
    /// 只探四个点查信号。
    Shallow,
    /// 连"已读那一段的行数"一起探(要扫行)。
    Deep,
}

/// 探"这还是不是原来那张表、我的位置还算不算数"的三种结果。
///
/// ⚠️ **三态不能压成 `Option`**: 我第一版用 `Option<(i64,i64)>`, 把「这个 source 探不出来」和
/// 「那一行真没了」混成了同一个 `None` —— 于是所有没实现探测的 source(测试假 source / 小库源)
/// 全被判成"表被重建"去从 0 重扫, 既有单测 `resume_from_persisted_watermark` 当场变红。
/// 三种情况的处置**完全不同**, 所以显式列出来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeProbe {
    /// 这个 source 探不出来(默认实现)→ 调用方退回旧护栏, **不能**当成"表被重建"。
    Unsupported,
    /// 表里**一行都没有** → 聊天记录被清 / 换过表 → 重扫。
    Missing,
    /// 表非空, 几个信号一次探回来。
    Found(TableProbe),
}

/// 一次点查探回来的几个信号 —— **各管一件事, 缺一不可**(第五轮 codex P1 逼出来的)。
///
/// # ⚠️ 能力边界: 这是**便宜的快护栏, 不是"保证不漏"**(设计层评审)
///
/// 这些信号只约束**三个点**: 第一行、游标那行、最大 id ——
/// **`(第一行, 游标行)` 中间那一段没有任何信号覆盖**。两份副本只要首尾对得上、中间不一样,
/// 四个信号全过, 而 `WHERE local_id > 游标` 返空 → 中间那段**永久缺失**。
///
/// 这里分**两种形态**, 覆盖情况不一样:
/// - **形态②(有洞)**: 一份副本里某条被删过、另一份没删 → 行数差。真库全量: 6003 张表里 26 张有
///   中间空洞(38 个号), 约 1/53000; 还要叠"删之后才首次采到那段 + 之后恢复了删前的副本 +
///   那期间没新消息"。**"前缀行数"这个信号正好覆盖它。**
/// - **形态①(各自长了不同的消息, 行数一样)**: **不能排除**。我一度拿"`AUTOINCREMENT` 不重用号"
///   论证它造不出来 —— **那个论证是错的**: `AUTOINCREMENT` 只在**一条谱系内**防重用, 恢复/重建
///   旧副本会把 `sqlite_sequence` 一起带回去。找不到产生机制 ≠ 不存在, 而且**前缀行数也挡不住它**
///   (行数一样), 只有 O(已读行数) 的前缀摘要 / 全表重扫才行。
///
/// 防形态②该防"**行数差**"而不是内容摘要 —— 摘要既贵又会被正文合法回写(上传完写 CDN / 撤回)
/// 打成误报, 那是 round-2 / round-4 已经踩过两次的坑。
/// 成本实测: 最大表(17.5 万行) +420 ms, 中位数会话约 1 ms; 懒式刷新和全量 ingest 付得起,
/// `watch` 每轮全子源循环付不起(750 万行 ≈ 18 s/轮)。
/// ⚠️ 每加一个信号就要全体重扫一次(老水位缺这一项 → 强制重扫), 所以这种事**一次决定完**。
///
/// 细节和成本量化: `docs-dev/20-讨论沉淀/R22-表重建漏消息-双审收敛记录.md` §二。
///
/// 搬锚点那一版只留了 `oldest_fp`, 把"位置还算不算数"这一路**整个丢了** ——
/// 老锚点(游标那一行)是顺带管着它的: 那一行没了就重扫。下面两条把它补回来, 且都用**不会被就地改**
/// 的字段, 所以不会重蹈"发张图就全量重扫"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableProbe {
    /// **全表最老那一行**的指纹 —— 管「**这还是不是同一张表**」(重建检测)。
    /// 选最老那行是因为最新那行会被微信就地改(上传完回写 CDN 字段 / 撤回改写正文)。
    pub oldest_fp: i64,
    /// `MAX(local_id)` —— 管「**表缩了没有**」。
    ///
    /// 缩了而最老那行还在(换上一份更短的旧副本)时 `oldest_fp` 认不出来, 游标却还停在旧的高位:
    /// `WHERE local_id > 旧游标` 恒空, 而且源库不再长过旧游标就**永远不自愈**。
    /// 老锚点(游标那一行)靠"那一行没了"顺带管着这一格, 换锚点之后就得靠这个数显式判。
    pub max_id: i64,
    /// **游标那一行**的 `create_time`(那行不在 → `None`)—— 管「**我的位置还是不是原来那条消息**」。
    ///
    /// 补 `max_id` 挡不住的那一格: 换上的副本在游标那一格上是**另一条消息**, 且它比旧游标还长
    /// (旧游标 9, 新副本 1..4 原样 + 5..12 是别的消息)→ `max_id(12)>9` 不响, 而 5..9 永久漏。
    ///
    /// 只取 `create_time`: 它写入时定死, **上传回写和撤回都不改它**(撤回是另插一条系统消息,
    /// 真库实测 4.5 万行 `local_id` 零空洞), 所以不会误判。
    /// 值按 `coalesce(create_time, 0)` 归一 —— **必须跟 drain 侧的 `unwrap_or(0)` 一个口径**
    /// (codex round-6 P2: 一边 NULL→None、一边 NULL→0, 那行没动也会被判成换了人 → 每轮全量重扫)。
    /// 所以 `None` **只表示"那一行不存在"**, 不表示"那一行的时间是 NULL"。
    pub cursor_ct: Option<i64>,
    /// **已读那一段的行数** `count(*) WHERE local_id <= 游标`(用户 2026-07-30 拍板加)——
    /// 管「**已读那段里有没有被挖过洞**」, 也是**唯一**能覆盖"形态②"的信号(见上面的能力边界)。
    ///
    /// 前四个信号只看三个点(第一行 / 游标行 / 最大 id), 中间那段没人管。两份副本"一份有洞、
    /// 另一份没有"时四项全对得上, 而行数不一样 —— 这一项就是冲它去的。
    ///
    /// ⚠️ **它是唯一要扫行的信号**, 前四个都是主键点查。所以**只在慢路径开**
    /// (见 [`DbSource::rebuild_sentinel`] 的 `deep` 参数): 实测最大那张表(17.5 万行)+420 ms、
    /// 约 2.4 秒/百万行、中位数会话约 1 ms。懒式刷新(一次一个会话)和全量 ingest 付得起;
    /// `watch` 每轮全子源循环付不起(750 万行 ≈ 18 秒/轮)。
    ///
    /// `None` = **这一轮没探**(快路径), **不是**"探出来是 0" —— 两者处置完全不同:
    /// 没探就不比这一项, 探出来不一样才重扫。
    pub prefix_rows: Option<i64>,
    /// **游标那一行**的 `server_id` —— 给上面那条**加基数**(codex round-6 P1)。
    ///
    /// `create_time` 只到**秒**: 真库 4.5 万行里有 32 行跟别人同秒。换上的副本要是正好在游标那一格
    /// 摆了一条同秒的别的消息, 上面那条就认不出来 → 游标以下永久跳过。`server_id` 基数高得多,
    /// 加上它基本就撞不上。
    ///
    /// ⚠️ **它是"加基数", 不是"判定性身份"** —— 别写成"全不重复"(我上一版就这么写了, 独立复审
    /// 全量扫两个分片打脸): `message_0.db` 3386 张表 117 万行里, 有一张
    /// (`Msg_a1a98eab…`, 84 行)存在**非零 `server_id` 的真重复** —— 同一条消息在同一张表里存了两份
    /// (重新同步 / 漫游: 先进来的 `status=3, server_seq=0`, 后补的 `status=4, server_seq` 有值),
    /// `server_id` 和 `create_time` **两样都一样**。`message_5.db` 那边的重复则全是 `server_id=0` 的行。
    /// 这跟 [`row_fingerprint`] 文档里 round-1 那句「`(server_id, create_time)` 认不出行」是**同一件事**,
    /// 当时的判断是对的 —— 别让这里的措辞把它推翻。量级: 2 行 / 246 万, 不破护栏, 但它是**概率性**的。
    ///
    /// ⚠️ **`0` 要当"还不知道"而不是一个值**: 自己发出去的消息在服务端回执之前 `server_id` 是 0,
    /// 之后就地填上真值。拿它硬比等于把 round-4 那个"发一条消息就全量重扫"的坑再挖一遍 ——
    /// 所以两边**任一为 0 就不比这一项**, 退回只比 `create_time`。
    ///
    /// 这一项永久哑掉的面比想的大, 但**正好不要紧**(独立复审全量扫的数): `message_5.db` 2617 张表里
    /// 258 张含 `server_id=0` 的行, 其中 **184 张那个零值行就是最新那一行**(≈7% 的会话)→ 对它们
    /// 这一项永远不生效, 回填也救不了(探回来也是 0)。但**这 184 张里 181 张只有 1 行** ——
    /// 一行的表游标行就是最老那行, `oldest_fp` 已经把它整行内容全覆盖了, `sid` 本来就是多余的。
    pub cursor_sid: Option<i64>,
}

/// keyset 增量游标 = 子源内 `local_id` 单调高水位 (drain 设计双审 v2; 旧 `(ct,ss,lid)` 三元组是全局归并遗留, 删)。
///
/// 跟 state.rs `etl_state.watermark_value` 1:1 (序列化为裸 JSON 数字)。`0` = 初始 (从头 drain)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrainCursor {
    /// 源 db 行主键 (`Msg_.local_id` = rowid; 单调递增 = 新消息 append).
    pub local_id: i64,
    /// **最老那一行的指纹**(含它的 `local_id`)—— 用来认出"这还是不是同一张表"。
    ///
    /// 为什么需要它: `local_id` 单调**只在表没被重建过时**成立。微信迁移 / 清空聊天记录 / 换设备会把
    /// `Msg_<md5>` 表重建, id 从 1 重来。旧护栏只在"旧游标 > 新表最大 id"时重扫 —— 可**新表长过旧游标**
    /// 时(旧水位 5、新表 1..9)它就不响了, `WHERE local_id > 5` 只读到 6..9, **新的 1..5 永久漏掉**,
    /// 而各路信号全是干净的。所以除了位置还要记**那个位置上是哪一行**: 下次对不上就是换过表了。
    ///
    /// `None` = 老水位(升级前写的)没这一项 —— 那时只能退回旧护栏, 见 `run_message_body`。
    pub resume_fp: Option<i64>,
    /// **游标那一行的 `create_time`** —— 管「我停的这个位置还是不是原来那条消息」。
    ///
    /// `resume_fp`(最老那行)管的是"表还是不是同一张", 管不到"位置还算不算数": 用户删掉近期消息后
    /// SQLite 的 rowid **会重用**, 新消息重新从被删掉的号段发起, 游标却还停在高处 → 那一段永久跳过。
    /// 存 `create_time` 是因为它写入时定死, **上传回写 / 撤回都不改它**(见 [`TableProbe::cursor_ct`])。
    ///
    /// `None` = 游标为 0(还没停在任何行上)。**带 `fp` 却缺 `ct` 的老水位在解析时就被判成"重扫一次"**
    /// (codex round-6 P1: 不然那一轮要是没有新行, 空批不写水位 → `ct` 永远种不上 → 这道护栏
    /// **永久失效**)。处置跟"没有 `fp`"完全一致 —— 同样的暴露面就该同样处置。
    pub cursor_ct: Option<i64>,
    /// 游标那一行的 `server_id` —— 给 `cursor_ct` 加基数, 见 [`TableProbe::cursor_sid`]。
    /// `0` / `None` = 还不知道(服务端没回执 / 老水位), 那就不比这一项。
    pub cursor_sid: Option<i64>,
    /// 已读那一段的行数 —— 管"已读段里有没有被挖过洞", 见 [`TableProbe::prefix_rows`]。
    ///
    /// `None` = **上次是在快路径上推的水位, 没探过这一项**(`watch` 那条路不探)。
    /// 所以它跟前三项不一样: **缺席不判迁移、不强制重扫** —— 否则 `watch` 推一次水位、
    /// 懒式刷新就重扫一次, 两条路互相打架, 每次查询都全量重扫。
    /// 只有"两边都有值且不等"才算数。
    pub prefix_rows: Option<i64>,
}

impl DrainCursor {
    /// etl_state `watermark_key` 描述 (跟 state.rs 钉死值一致, 写水位时用).
    pub const KEY_DESC: &'static str = "local_id";

    /// 从 etl_state `watermark_value` 解析 —— 现行 `{"id":..,"fp":..}`, 老的是裸数字 `"<local_id>"`.
    ///
    /// 格式不符 (旧三元组 `[..]` / 非数 / 空) → `None`; 调用方按初始游标处理 (= 子源全量 re-drain,
    /// 跟 local_id 单调 KI 的兜底一致)。
    #[must_use]
    pub fn from_watermark_value(json: &str) -> Option<Self> {
        let t = json.trim();
        // 老格式: 裸数字(升级前写的, 没指纹)。
        if let Ok(local_id) = serde_json::from_str::<i64>(t) {
            return Some(Self {
                local_id,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            });
        }
        // 现行格式: `{"id":5,"fp":<最老那行的指纹>,"ct":<游标那行的 create_time>}`
        // (下面还要挡掉中途那一版 `{"id","sid","ct"}` —— 它没有 `fp`, 靠这一点区分)。
        let v: serde_json::Value = serde_json::from_str(t).ok()?;
        let local_id = v.get("id")?.as_i64()?;
        // ⚠️ **上一版的 `{"id","sid","ct"}` 必须强制重扫一次**(codex round-2 P1): 那一版的指纹是
        // `(server_id, create_time)` 两个裸字段, 换算不成现在的多列哈希。若只保留 `id` 而丢掉指纹,
        // 就退化成"老水位"那一支 → 从**当前**那一行种指纹 → 万一两版之间表被重建过, 游标以下永久跳过。
        // 认出这个格式就把游标归零: 全量重扫一次是安全动作, 且之后写的是新格式, 只发生一次。
        if v.get("fp").is_none() && (v.get("sid").is_some() || v.get("ct").is_some()) {
            return Some(Self::default());
        }
        let fp = v.get("fp").and_then(serde_json::Value::as_i64);
        let ct = v.get("ct").and_then(serde_json::Value::as_i64);
        // ⚠️ **少任何一项都得归零重扫一次**(codex round-6 / round-7 各报一次, 同一个形状)。
        // 跳过一道护栏是**可能永久**的: 那一轮要是没有游标以上的新行, 空批**不写水位** →
        // 那一项永远种不上 → 护栏再也不会启用。跟"没有 `fp`"是同一个暴露面, 处置就该一致 ——
        // 我在裸数字那一格已经吃过"处置不一致本身就是 bug"。
        //
        // `sid` 那一项要分清两件事: **键缺席** = 老格式(现行写法一定会写它, 哪怕值是 0)→ 重扫一次;
        // **值是 0** = "服务端还没回执, 这一项没意见" → 正常增量。所以判的是 `get("sid").is_none()`
        // 而不是 `== 0` —— 判成后者, 会让"游标停在一条还没回执的消息上"的会话**每轮全量重扫**。
        if local_id > 0 && (fp.is_none() || ct.is_none() || v.get("sid").is_none()) {
            return Some(Self::default());
        }
        // ⚠️ `n`(已读段行数)**缺席不判迁移、不强制重扫** —— 跟上面那三项**故意不一样**:
        // `watch` 那条路是 `Shallow`, 它推的水位本来就可能还没建立过这个数。若照那三项处置,
        // 就成了"watch 推一次 → 懒式刷新重扫一次", 两条路互相打架, 每次查询都全量重扫。
        // 它是**白建**的: 任何一次从 0 重扫(升级第一轮每个子源都有)顺手就把它算出来了。
        Some(Self {
            local_id,
            resume_fp: fp,
            cursor_ct: ct,
            cursor_sid: v.get("sid").and_then(serde_json::Value::as_i64),
            prefix_rows: v.get("n").and_then(serde_json::Value::as_i64),
        })
    }

    /// 序列化回 etl_state `watermark_value`.
    #[must_use]
    pub fn to_watermark_value(&self) -> String {
        // 有指纹就写新格式; 没有(初始 / 非消息源)保持裸数字 —— 老读者也认得。
        //
        // ⚠️ `sid` **一定要写, 哪怕值是 0**(codex round-7 P1)。0 的含义是"服务端还没回执, 这一项
        // 没意见", 跟"键根本不在"(=老格式, 要重扫一次)是两件事。省着不写就把两者混成一个,
        // 读那侧要么永远重扫、要么永远不重扫, 两条路都错。
        match (self.resume_fp, self.cursor_ct) {
            // `n` 没建立过就不写 —— 读那侧据此"不比这一项"(**不**判迁移, 见 `from_watermark_value`)。
            (Some(fp), Some(ct)) => match self.prefix_rows {
                Some(n) => format!(
                    r#"{{"id":{},"fp":{fp},"ct":{ct},"sid":{},"n":{n}}}"#,
                    self.local_id,
                    self.cursor_sid.unwrap_or(0)
                ),
                None => format!(
                    r#"{{"id":{},"fp":{fp},"ct":{ct},"sid":{}}}"#,
                    self.local_id,
                    self.cursor_sid.unwrap_or(0)
                ),
            },
            // 缺 `ct`: 照写 `fp`, 读回来那侧会判"重扫一次"再重新种全 —— 不能退回裸数字, 那连 `fp` 都丢了。
            (Some(fp), None) => format!(r#"{{"id":{},"fp":{fp}}}"#, self.local_id),
            (None, _) => self.local_id.to_string(),
        }
    }
}

/// 一批增量消息 (单子源 = 一张 `Msg_` 表 = 一个会话; keyset 推进)。
///
/// 本批所有行同会话 → `conv_id` 不在行内冗余, 由调用方从对应 [`MessageSubsource`] 取 (组 `MessageContext`)。
pub struct MessageBatch {
    /// 本批行 (按 `local_id` 升序)。
    pub rows: Vec<MessageRow>,
    /// 推进后游标 (= **本批返回行的最大 `local_id`**, 非扫描上界; 空批保持入参游标)。写 etl_state 水位。
    ///
    /// ⚠️ 推进 etl_state 须等 sink ack (rows + decode-error 事件都持久化后才写水位) — 这是 **adapter loop
    /// 契约**, 防 crash 漏行。DbSource 只保证: 给定 cursor 返 ≤limit 行 + 准确 `next_cursor`。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit; 上层据此决定是否继续 drain)。
    pub has_more: bool,
}

// MessageRow 含 PII (正文/sender) 且无 Debug → MessageBatch 手写 Debug 只露行数/游标/has_more,
// 不露行内容 (K-R4; 兼让调用方 `unwrap_err` 等可用)。
impl std::fmt::Debug for MessageBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批增量联系人 (`contact.db` 单 `contact` 表; keyset 按 rowid 推进)。
pub struct ContactBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<ContactRow>,
    /// 推进后游标 (= **本批返回行的最大 rowid**; 空批保持入参游标)。契约同 [`MessageBatch::next_cursor`]。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// ContactRow 含 PII (username/nick_name/remark/alias) 且无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for ContactBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批会话 (`session.db` 单 `SessionTable`; keyset 按 rowid 推进; 全表重扫同 contact)。
pub struct SessionBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<SessionRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// SessionRow 含 PII (username/summary/last_sender) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for SessionBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批收藏 (`favorite.db` 单 `fav_db_item`; keyset 按 local_id 推进; 全表重扫同 session; ADR-454)。
pub struct FavoriteBatch {
    /// 本批行 (按 local_id 升序)。
    pub rows: Vec<FavoriteRow>,
    /// 推进后游标 (= 本批最大 local_id; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// FavoriteRow 含 PII (from_user/real_chat_name) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for FavoriteBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FavoriteBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批收藏标签绑定 (`favorite.db` fav_bind_tag_db_item ⋈ fav_tag; keyset 按 rowid; ADR-454 批 B-2)。
pub struct FavoriteTagBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<FavoriteTagRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// FavoriteTagRow 含 PII (tag_name) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for FavoriteTagBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FavoriteTagBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批朋友圈动态 (`sns.db` 单 `SnsTimeLine`; keyset 按 tid 推进; 全表重扫同 favorite; ADR-467 件1)。
///
/// ⚠️ tid 是 `INTEGER PRIMARY KEY DESC` = rowid 别名, **雪花 id 可为负** → 游标从 `i64::MIN` 起 (非 0)。
pub struct MomentBatch {
    /// 本批行 (按 tid 升序)。
    pub rows: Vec<SnsRow>,
    /// 推进后游标 (= 本批最大 tid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// SnsRow 含 PII (user_name/content) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for MomentBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MomentBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批转账 (`general.db` 单 `transferTable`; keyset 按 rowid 推进; 全表重扫同 favorite; ADR-468)。
pub struct TransferBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<TransferRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// TransferRow 含 PII (session_name/payer/receiver wxid) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for TransferBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批红包 (`general.db` 单 `redEnvelopeTable`; keyset 按 rowid 推进; 全表重扫同 transfer; ADR-468 件2)。
pub struct RedEnvelopeBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<RedEnvelopeRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// RedEnvelopeRow 含 PII (session_name/sender wxid + native_url 嵌 wxid) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for RedEnvelopeBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedEnvelopeBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批群收款 (`general.db` 单 `groupPayTable`; keyset 按 rowid 推进; 全表重扫同 transfer; ADR-468 件3)。
pub struct GroupPayBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<GroupPayRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// GroupPayRow 含 PII (session_name wxid) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for GroupPayBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupPayBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批好友验证 (`general.db` 单 `FMessageTable`; keyset 按 rowid 推进; 全表重扫; ADR-469)。
pub struct FMessageBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<FMessageRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// FMessageRow 含 PII (user_name wxid + content 打招呼语) 无 Debug → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for FMessageBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FMessageBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批视频号主页记录 (`general.db` 单 `wcfinderuserpage`; keyset 按 rowid 推进; 全表重扫; ADR-473)。
pub struct FinderBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<FinderRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// FinderRow 含 owner_username (视频号号主 wxid) + extra_buffer (proto blob) 无 Debug → 手写只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for FinderBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinderBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批朋友圈好友动态索引 (`sns.db` 单 `SnsTopItem_1`; keyset 按 rowid 推进; 全表重扫; ADR-474)。
pub struct MomentFeedBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<MomentFeedRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// MomentFeedRow 含 author (发布者 wxid) 无 Debug → 手写只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for MomentFeedBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MomentFeedBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批朋友圈互动通知 (`sns.db` 单 `SnsMessage_tmp3`; keyset 按 rowid 推进; 全表重扫; 照 moment_feed ADR-474)。
pub struct SnsNotifyBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<SnsNotifyRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// SnsNotifyRow 含 from_user (互动者 wxid) + content (评论文本) 无 Debug → 手写只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for SnsNotifyBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnsNotifyBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批自定义表情 (`emoticon.db` 单 `kNonStoreEmoticonTable`; keyset 按 rowid 推进; 全表重扫; ADR-478)。
pub struct EmoticonBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<EmoticonRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// EmoticonRow 含 aes_key (密钥) 无 Debug → 手写只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for EmoticonBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmoticonBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批企微品牌号联系人 (`bizchat.db` 单 `user_info`; keyset 按 rowid 推进; 全表重扫; ADR-482)。
pub struct BizChatUserBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<BizChatUserRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// BizChatUserRow 含 user_id / user_name (PII) 无 Debug → 手写只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for BizChatUserBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BizChatUserBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// 一批头像图 (`head_image.db` 单 `head_image`; keyset 按 rowid 推进; 全表重扫; ADR-481)。
pub struct AvatarBatch {
    /// 本批行 (按 rowid 升序)。
    pub rows: Vec<AvatarRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// AvatarRow 含 username (wxid) + image_buffer (图 bytes) → 手写 Debug 只露行数/游标/has_more (K-R4)。
impl std::fmt::Debug for AvatarBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvatarBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// `chat_room` 表一行 = 一个群 (drain 原始行; `ext_buffer` 未解, pipeline 调 `parse_roomdata`)。
///
/// chat_room 在 **contact.db**。`ext_buffer` = 微信 ChatRoomData.members protobuf (群全员名单)。
/// K-R4: `chatroom_id` (xxx@chatroom) / `owner` (群主 wxid) 明文 → 手写 Debug sha8; ext_buffer 成员 blob → 仅露长度。
#[derive(Clone)]
pub struct ChatroomRawRow {
    /// chat_room 表 rowid (全表重扫本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 群 username `xxx@chatroom` (明文 → Debug sha8)。
    pub chatroom_id: String,
    /// 群主 wxid (可空; 明文 → Debug sha8)。
    pub owner: Option<String>,
    /// ChatRoomData.members protobuf blob (成员名单; pipeline 解; → Debug 仅长度)。
    pub ext_buffer: Vec<u8>,
    /// 群名 (contact.nick_name LEFT JOIN where username=chatroom_id; 缺/无对应行 → None; 明文 → Debug 仅长度)。
    pub chatroom_name: Option<String>,
    /// 群备注 (我给群的私人备注; contact.remark LEFT JOIN 同群名来源; 未设 → None; 明文 → Debug 仅长度)。
    pub chatroom_remark: Option<String>,
    /// 群公告 (批H; chat_room_info_detail.announcement_ LEFT JOIN; 缺 → None; 明文 → Debug 仅长度)。
    pub announcement: Option<String>,
    /// 群公告编辑者 wxid (批H; chat_room_info_detail.announcement_editor_; 缺 → None; 明文 → Debug sha8)。
    pub announcement_editor: Option<String>,
    /// 群公告发布时间秒 (批H; chat_room_info_detail.announcement_publish_time_; 无 → 0)。
    pub announcement_publish_time: i64,
    /// 富媒体群公告 XML (ADR-460 KI-A; chat_room_info_detail.xml_announcement_; 缺 → None; 可含内容 → Debug 仅长度)。
    pub xml_announcement: Option<String>,
    /// 群状态位 (ADR-460 KI-B; chat_room_info_detail.chat_room_status_; 语义待确认, 未知/无 → 0)。
    pub chat_room_status: i64,
}

// K-R4: chatroom_id/owner/editor 明文 → sha8; ext_buffer 成员 blob + 公告 (含 xml) → 仅露长度 (不露内容)。
impl std::fmt::Debug for ChatroomRawRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatroomRawRow")
            .field("rowid", &self.rowid)
            .field("chatroom_id_sha8", &sha8(self.chatroom_id.as_bytes()))
            .field("owner_sha8", &self.owner.as_ref().map(|o| sha8(o.as_bytes())))
            .field("ext_buffer_len", &self.ext_buffer.len())
            .field(
                "chatroom_name_len",
                &self.chatroom_name.as_ref().map(|n| n.chars().count()),
            )
            .field(
                "chatroom_remark_len",
                &self.chatroom_remark.as_ref().map(|r| r.chars().count()),
            )
            .field(
                "announcement_len",
                &self.announcement.as_ref().map(|a| a.chars().count()),
            )
            .field(
                "announcement_editor_sha8",
                &self.announcement_editor.as_ref().map(|e| sha8(e.as_bytes())),
            )
            .field("announcement_publish_time", &self.announcement_publish_time)
            .field(
                "xml_announcement_len",
                &self.xml_announcement.as_ref().map(|x| x.chars().count()),
            )
            .field("chat_room_status", &self.chat_room_status)
            .finish()
    }
}

/// 一批群 (`contact.db` 的 `chat_room` 表; **全表重扫** keyset 按 rowid 分页)。
///
/// chatroom 信息可变 (群名/成员/群主就地改) → 全表重扫 (cursor 仅本轮分页, 不读写 etl_state, 同 contact)。
pub struct ChatroomBatch {
    /// 本批行 (按 rowid 升序; 一行 = 一个群)。
    pub rows: Vec<ChatroomRawRow>,
    /// 推进后游标 (= 本批最大 rowid; 空批保持入参)。仅本轮分页 (全表重扫不落 etl_state)。
    pub next_cursor: DrainCursor,
    /// 是否还有更多 (= 本批拿满 limit)。
    pub has_more: bool,
}

// ChatroomRawRow 已手写 Debug 脱敏; ChatroomBatch 仍只露行数/游标/has_more (一致)。
impl std::fmt::Debug for ChatroomBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatroomBatch")
            .field("rows_len", &self.rows.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// DbSource 错误 (ADR-405 §3.3 CoreError 子 enum; K-R4 由内层错型出口脱敏).
#[derive(Debug, thiserror::Error)]
pub enum DbSourceError {
    /// cipher 层错 (open_account / exec_query 失败) — 透传 (CipherError 已脱敏).
    #[error("DbSource cipher: {0}")]
    Cipher(#[from] crate::cipher::CipherError),

    /// 源映射缺失 / 扫盘失败 / 子源非法. `what` 是元数据描述 (非 wxid/正文/路径明文)。
    #[error("DbSource 源映射缺失: {what}")]
    MapMissing { what: String },

    /// 行映射失败 (exec_query 行缺必需列). `col` 列名非敏感; `db_id` 已是组合 id.
    #[error("DbSource 行映射失败 (db_id={db_id}, 缺列={col})")]
    RowMap { db_id: String, col: String },
}

/// DbSource (ADR-405 §3.1 trait 3/7) — 从解密会话按子源 keyset 增量 drain.
///
/// impl 持有一个 `Box<dyn Cipher>` 开的账号 `DbSession` (ADR-423 §3.4: 一账号一 session, drain 全程存活)。
/// snapshot 扫盘列子库 + 开会话; list 枚举子源; drain 走 `session.query` keyset 分页 (禁 OFFSET)。
#[async_trait]
pub trait DbSource: Send + Sync {
    /// source 字典值 (raw-payload §4 一致): 固定 "native_wechat".
    fn source_type(&self) -> &'static str {
        "native_wechat"
    }

    /// 列举本轮要扫的子库快照 (扫盘 + 开账号会话)。
    async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError>;

    /// 枚举一个子库内的消息子源 (每张 `Msg_<md5>` 表 = 一个会话) + 反解 `conv_id`。
    async fn list_message_subsources(&mut self, snapshot: &DbSnapshot) -> Result<Vec<MessageSubsource>, DbSourceError>;

    /// **只找一个会话**的子源(R22 ADR-508 D24 会话级增量采集的快路)。
    ///
    /// 为什么要单独一条路: [`Self::list_message_subsources`] 要建"表名 md5 → conv_id"的**反查**表, 得把整张
    /// `Name2Id` 读出来 —— 真库 6 个分片 2.2 万会话时实测约 16 秒, 而"确保某会话最新"每次查询都要走一遍,
    /// 于是没有新消息也要等十几秒。只采一个会话时根本不需要反查: `conv_id` **正着**算 md5 就是表名,
    /// 在 `sqlite_master` 里点一下即可。
    ///
    /// 默认实现退回全枚举后过滤(语义等价, 只是慢), 所以既有实现不改也能编译。
    ///
    /// # Errors
    /// 同 [`Self::list_message_subsources`]。
    async fn find_message_subsource(
        &mut self,
        snapshot: &DbSnapshot,
        conv_id: &str,
    ) -> Result<Option<MessageSubsource>, DbSourceError> {
        let all = self.list_message_subsources(snapshot).await?;
        Ok(all.into_iter().find(|s| s.conv_id == conv_id))
    }

    /// 该子源表当前的 `MAX(local_id)` —— 用来判**游标倒退**(表被重建时 id 从 1 重来, 旧游标会永久
    /// 跳过新行, 且各路信号全是干净的)。
    ///
    /// 默认实现返 `None` = 探不出来 → 调用方不做这道护栏(退化成旧行为, 既有实现不改也能编译)。
    ///
    /// # Errors
    /// 查库失败。
    async fn max_local_id(
        &mut self,
        _snapshot: &DbSnapshot,
        _subsource: &MessageSubsource,
    ) -> Result<Option<i64>, DbSourceError> {
        Ok(None)
    }

    /// 一次点查探回 [`TableProbe`] 三个信号 —— 判"这还是不是同一张表 / 我的位置还算不算数"。
    ///
    /// ⚠️ **身份锚点必须是最老那行, 不能是游标那行**(第四轮对抗审 P2): 游标永远指向**最新一条**,
    /// 而最新一条恰恰最可能被**就地改** —— 图片/视频上传完会把 CDN 字段写回 `message_content`,
    /// 撤回会改写正文并改 `local_type`。拿它当身份, 一次普通的上传回写就被判成"表被重建" →
    /// 整个会话重扫重发。**最老那行**反过来是最稳的: 早就同步完了, 没人再动它。
    ///
    /// ⚠️ **但光有它不够**(第五轮 codex P1): 老锚点顺带管着"位置还算不算数", 搬走以后那一路空了 ——
    /// 所以同一次查询把 `max_id` 和**游标那行的 `create_time`** 一并带回。三个信号各管一件事,
    /// 见 [`TableProbe`] 每个字段的说明。
    ///
    /// `at` = 当前游标的 `local_id`(拿它点查 `cursor_ct`); `at <= 0` 时 `cursor_ct` 恒 `None`。
    ///
    /// 表是空的 → `Missing`(调用方按重扫处理)。
    /// 默认实现返 `Unsupported` = 探不出来 → 调用方退回旧护栏(既有实现不改也能编译)。
    ///
    /// # Errors
    /// 查库失败。
    async fn rebuild_sentinel(
        &mut self,
        _snapshot: &DbSnapshot,
        _subsource: &MessageSubsource,
        _at: i64,
        _depth: ProbeDepth,
    ) -> Result<ResumeProbe, DbSourceError> {
        Ok(ResumeProbe::Unsupported)
    }

    /// 从一个子源按 `local_id` 单调游标增量 drain 消息.
    ///
    /// SQL: `WHERE local_id > since.local_id ORDER BY local_id LIMIT limit` (禁 OFFSET, ADR-423 §3.4)。
    /// 返回 ≤limit 行 + `next_cursor` + `has_more`(是否拿满 limit)。
    ///
    /// ⚠️ **契约 (pipeline 运行时强校验)**: 非空批 `next_cursor.local_id` **必须 == 本批返回行的最大
    /// `local_id`**(是命中行最大值, 不是扫描上界, 不是 `since`)。pipeline 据此推进 etl_state 水位 — 若返
    /// 大于命中行最大的值会跳过 `(max, next_cursor]` 的行漏数据, pipeline 检测到 `next_cursor != max(rows)`
    /// 即返 `Invariant` 错。空批时 `next_cursor` = 入参 `since`。
    async fn drain_messages(
        &mut self,
        snapshot: &DbSnapshot,
        subsource: &MessageSubsource,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<MessageBatch, DbSourceError>;

    /// 从 `contact.db` 的 `contact` 表按 rowid 单调游标增量 drain 联系人.
    ///
    /// `contact_db` = contact.db 绝对路径 (adapter 定位)。单表无子源; SQL `WHERE rowid > since.local_id
    /// ORDER BY rowid LIMIT limit` (`DrainCursor.local_id` 复用为 rowid 高水位)。`next_cursor` 契约同
    /// [`drain_messages`](Self::drain_messages): 非空批 == 本批最大 rowid。
    async fn drain_contacts(
        &mut self,
        contact_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<ContactBatch, DbSourceError>;

    /// contact ETL 落 person 表时用的 `source` 溯源值 (进 person PK 的 source 维)。
    ///
    /// 默认 `"contact.db"` (普通联系人)。实现方可在陌生人等子模式下返不同值 (如 `"contact.db|stranger"`),
    /// 让同一 person 表按 source 分行不覆盖 (echotrace 同源; 查询层 `WHERE source LIKE '%stranger%'` 筛)。
    /// mock 用默认即可 — 不影响既有行为。
    fn contact_source_label(&self) -> &'static str {
        "contact.db"
    }

    /// 从 `contact.db` 的 `chat_room` 表 **全表重扫** drain 群 (一行 = 一个群)。
    ///
    /// chatroom 信息可变 (群名/成员/群主就地改) → 全表重扫 (同 contact: `DrainCursor.local_id` 复用为
    /// rowid 高水位, **仅本轮分页**, 不落 etl_state)。`contact_db` = contact.db 绝对路径 (chat_room 在此库)。
    /// SQL `SELECT rowid, username, owner, hex(ext_buffer) FROM chat_room WHERE rowid > since.local_id
    /// ORDER BY rowid LIMIT limit`。`next_cursor` 契约同 [`drain_messages`](Self::drain_messages):
    /// 非空批 == 本批最大 rowid。`ext_buffer` 在 pipeline 层调 `parse_roomdata` 解 (本层只搬运 blob)。
    async fn drain_chatrooms(
        &mut self,
        contact_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<ChatroomBatch, DbSourceError>;

    /// 从 `session.db` 的 `SessionTable` **全表重扫** drain 会话 (一行 = 一个会话/聊天列表项)。
    ///
    /// 会话状态可变 (unread/summary/sort 随消息变) → 全表重扫 (同 contact: `DrainCursor.local_id` 复用为
    /// rowid 高水位, **仅本轮分页**, 不落 etl_state)。`session_db` = session.db 绝对路径。
    /// **无 default** (同 contact/chatroom: 编译强制每个 impl 覆盖, 防新 impl 忘实现 → 静默 drain 不到会话;
    /// codex ② P1)。不取数 session 的 mock 显式返空批。
    async fn drain_sessions(
        &mut self,
        session_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<SessionBatch, DbSourceError>;

    /// 从 `favorite.db` 的 `fav_db_item` **全表重扫** drain 收藏 (一行 = 一条收藏; ADR-454)。
    ///
    /// 收藏项创建后基本不变 (重打标签 update_time bump) → 全表重扫 (同 session: `DrainCursor.local_id` 复用为
    /// fav_db_item.local_id 高水位, **仅本轮分页**, 不落 etl_state)。`favorite_db` = favorite.db 绝对路径。
    /// **无 default** (同 session: 编译强制每个 impl 覆盖, 防新 impl 忘实现)。不取数 favorite 的 mock 显式返空批。
    /// content 本身不取 (大 blob) → SQL 只 `LENGTH(content) AS content_len`。
    async fn drain_favorites(
        &mut self,
        favorite_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FavoriteBatch, DbSourceError>;

    /// 从 `favorite.db` 的 `fav_bind_tag_db_item ⋈ fav_tag_db_item` **全表重扫** drain 收藏标签绑定
    /// (一行 = 一条标签↔收藏绑定; ADR-454 批 B-2)。
    ///
    /// 绑定创建后基本不变 → 全表重扫 (同 favorite: `DrainCursor.local_id` 复用为 fav_bind_tag rowid 高水位,
    /// **仅本轮分页**, 不落 etl_state)。`favorite_db` = favorite.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。
    /// LEFT JOIN fav_tag 取标签名 (标签缺→空串, 不丢绑定)。
    async fn drain_favorite_tags(
        &mut self,
        favorite_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FavoriteTagBatch, DbSourceError>;

    /// 从 `sns.db` 的 `SnsTimeLine` **全表重扫** drain 朋友圈动态 (一行 = 一条动态; ADR-467 件1)。
    ///
    /// 动态本体创建后 immutable (点赞/评论计数变) → 全表重扫 (同 favorite: `DrainCursor.local_id` 复用为
    /// SnsTimeLine.tid 高水位, **仅本轮分页**, 不落 etl_state)。`sns_db` = sns.db 绝对路径。
    /// **无 default** (同 favorite: 编译强制每个 impl 覆盖)。⚠️ **tid 是有符号 (可为负) 的 rowid 别名** →
    /// 调用方 (run_sns_pipeline) 初始游标必须 `i64::MIN` (非 0, 否则 `tid > 0` 漏全部负 tid)。content 是
    /// TEXT XML, 直取 (非 blob hex)。
    async fn drain_moments(
        &mut self,
        sns_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<MomentBatch, DbSourceError>;

    /// 从 `general.db` 的 `transferTable` **全表重扫** drain 转账 (一行 = 一条转账; ADR-468)。
    ///
    /// 转账随状态推进就地 UPDATE (pay_sub_type/last_update_time 变) → 全表重扫 (同 favorite: `DrainCursor.local_id`
    /// 复用为 transferTable rowid 高水位, **仅本轮分页**, 不落 etl_state)。`general_db` = general.db 绝对路径。
    /// **无 default** (同 favorite: 编译强制每个 impl 覆盖)。bubble_clicked_flag 真库有 NULL → SQL COALESCE(…,0)。
    async fn drain_transfers(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<TransferBatch, DbSourceError>;

    /// 从 `general.db` 的 `redEnvelopeTable` **全表重扫** drain 红包 (一行 = 一条红包; ADR-468 件2)。
    ///
    /// 红包随领取状态推进就地 UPDATE (hb_status/receive_status 变) → 全表重扫 (同 transfer: `DrainCursor.local_id`
    /// 复用为 redEnvelopeTable rowid 高水位, **仅本轮分页**, 不落 etl_state)。`general_db` = general.db 绝对路径。
    /// **无 default** (同 transfer: 编译强制每个 impl 覆盖)。native_url 嵌 wxid → 下游出口脱敏 (本层只搬运)。
    async fn drain_red_envelopes(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<RedEnvelopeBatch, DbSourceError>;

    /// 从 `general.db` 的 `groupPayTable` **全表重扫** drain 群收款 (一行 = 一条群收款; ADR-468 件3)。
    ///
    /// 全表重扫 (同 transfer: `DrainCursor.local_id` 复用为 groupPayTable rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`general_db` = general.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。
    async fn drain_group_pays(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<GroupPayBatch, DbSourceError>;

    /// 从 `general.db` 的 `FMessageTable` **全表重扫** drain 好友验证 (一行 = 一条好友验证/打招呼; ADR-469)。
    ///
    /// 全表重扫 (同 transfer: `DrainCursor.local_id` 复用为 FMessageTable rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`general_db` = general.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。content 打招呼语
    /// 出口脱敏 (本层只搬运)。
    async fn drain_friend_verifies(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FMessageBatch, DbSourceError>;

    /// 从 `general.db` 的 `wcfinderuserpage` **全表重扫** drain 视频号主页记录 (一行 = 一个视频号; ADR-473)。
    ///
    /// 全表重扫 (同 transfer: `DrainCursor.local_id` 复用为 wcfinderuserpage rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`general_db` = general.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。extra_buffer proto
    /// 由 assemble_finder 解 (本层只搬运)。
    async fn drain_finder_visits(
        &mut self,
        general_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<FinderBatch, DbSourceError>;

    /// 从 `sns.db` 的 `SnsTopItem_1` **全表重扫** drain 朋友圈好友动态索引 (一行 = 一条好友动态; ADR-474)。
    ///
    /// 全表重扫 (同 transfer: `DrainCursor.local_id` 复用为 SnsTopItem_1 rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`sns_db` = sns.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。源有重复 tid 行 → sink
    /// upsert 去重 (本层只搬运)。
    async fn drain_moment_feeds(
        &mut self,
        sns_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<MomentFeedBatch, DbSourceError>;

    /// 从 `sns.db` 的 `SnsMessage_tmp3` **全表重扫** drain 朋友圈互动通知 (一行 = 一条互动通知; 照 moment_feed ADR-474)。
    ///
    /// 全表重扫 (同 moment_feed: `DrainCursor.local_id` 复用为 SnsMessage_tmp3 rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`sns_db` = sns.db 绝对路径 (与 moment_feed 同库)。**无 default** (编译强制每个 impl 覆盖)。
    async fn drain_sns_notifies(
        &mut self,
        sns_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<SnsNotifyBatch, DbSourceError>;

    /// 从 `emoticon.db` 的 `kNonStoreEmoticonTable` **全表重扫** drain 自定义表情 (一行 = 一个表情; ADR-478)。
    ///
    /// 全表重扫 (同 finder: `DrainCursor.local_id` 复用为 kNonStoreEmoticonTable rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`emoticon_db` = emoticon.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。aes_key 密钥
    /// 出口脱敏 (本层只搬运)。
    async fn drain_emoticons(
        &mut self,
        emoticon_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<EmoticonBatch, DbSourceError>;

    /// 从 `head_image.db` 的 `head_image` **全表重扫** drain 头像图 (一行 = 一联系人当前头像; ADR-481)。
    ///
    /// 全表重扫 (同 emoticon: `DrainCursor.local_id` 复用为 head_image rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`head_image_db` = head_image.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。
    /// image_buffer (图 bytes) 本层只搬运。
    async fn drain_avatars(
        &mut self,
        head_image_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<AvatarBatch, DbSourceError>;

    /// 从 `bizchat.db` 的 `user_info` **全表重扫** drain 企微品牌号联系人 (一行 = 一个企微号; ADR-482)。
    ///
    /// 全表重扫 (同 emoticon: `DrainCursor.local_id` 复用为 user_info rowid 高水位, **仅本轮分页**, 不落
    /// etl_state)。`bizchat_db` = bizchat.db 绝对路径。**无 default** (编译强制每个 impl 覆盖)。user_id
    /// (企微 wxid, PII) 出口脱敏 (本层只搬运)。
    async fn drain_bizchat_users(
        &mut self,
        bizchat_db: &Path,
        since: &DrainCursor,
        limit: usize,
    ) -> Result<BizChatUserBatch, DbSourceError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::Wxid;

    #[test]
    fn drain_cursor_watermark_round_trip() {
        let c = DrainCursor {
            local_id: 100,
            resume_fp: None,
            cursor_ct: None,
            cursor_sid: None,
            prefix_rows: None,
        };
        let wv = c.to_watermark_value();
        assert_eq!(wv, "100");
        let back = DrainCursor::from_watermark_value(&wv).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn drain_cursor_default_is_zero() {
        let c = DrainCursor::default();
        assert_eq!(
            c,
            DrainCursor {
                local_id: 0,
                resume_fp: None,
                cursor_ct: None,
                cursor_sid: None,
                prefix_rows: None,
            }
        );
        assert_eq!(c.to_watermark_value(), "0");
    }

    #[test]
    fn drain_cursor_bad_watermark_is_none() {
        assert!(DrainCursor::from_watermark_value("not json").is_none());
        assert!(DrainCursor::from_watermark_value("{}").is_none());
        // 旧三元组格式 → None (= 子源全量 re-drain 兜底)
        assert!(DrainCursor::from_watermark_value("[1, 2, 3]").is_none());
    }

    /// **水位格式演进的全格矩阵** —— 这一串前后改过五版, 每次出事都出在"老水位怎么读", 所以把
    /// 每种形状钉在一个表里, 一眼能看出哪一版会被强制重扫。
    ///
    /// 判据: `local_id == 0` ⟺ 强制从 0 重扫; `resume_fp == None` 也会被 `run_message_body`
    /// 判成"没指纹 → 重扫一次"。
    #[test]
    fn drain_cursor_watermark_format_matrix() {
        // (水位字面量, 期望的 local_id, 期望有没有 fp, 期望有没有 ct, 这一格是什么)
        let cases: &[(&str, i64, bool, bool, &str)] = &[
            ("100", 100, false, false, "升级前的裸数字 → 没指纹 → 上层强制重扫一次"),
            (
                r#"{"id":100,"sid":7,"ct":9}"#,
                0,
                false,
                false,
                "中途那版(指纹是 server_id/create_time 裸字段, 换算不成现在的哈希)→ 归零重扫",
            ),
            (
                r#"{"id":100,"fp":-42}"#,
                0,
                false,
                false,
                "有 fp 没 ct 那版 → 也归零重扫一次: 不然那一轮没新行就永远种不上 ct, 护栏永久失效",
            ),
            (
                r#"{"id":100,"fp":-42,"ct":1752216867}"#,
                0,
                false,
                false,
                "有 fp/ct 但 **sid 键缺席** = 老格式 → 也归零重扫一次(现行写法一定会写 sid, 哪怕值是 0)",
            ),
            (
                r#"{"id":100,"fp":-42,"ct":1752216867,"sid":0}"#,
                100,
                true,
                true,
                "sid **值是 0** = 服务端还没回执 → 正常增量, 位置只比 ct。跟键缺席是两回事",
            ),
            (
                r#"{"id":100,"fp":-42,"ct":1752216867,"sid":123456789}"#,
                100,
                true,
                true,
                "没有 n(已读段行数还没建立 / 上次是 Shallow 路径推的)→ **照常增量, 不判迁移**",
            ),
            (
                r#"{"id":100,"fp":-42,"ct":1752216867,"sid":123456789,"n":100}"#,
                100,
                true,
                true,
                "现行版: 五样齐 → 判据全生效",
            ),
        ];
        for (raw, want_id, want_fp, want_ct, what) in cases {
            let c = DrainCursor::from_watermark_value(raw).unwrap_or_else(|| panic!("{what}: `{raw}` 该解得出来"));
            assert_eq!(c.local_id, *want_id, "{what}: local_id");
            assert_eq!(c.resume_fp.is_some(), *want_fp, "{what}: 有没有 fp");
            assert_eq!(c.cursor_ct.is_some(), *want_ct, "{what}: 有没有 ct");
        }
        assert_eq!(
            DrainCursor::from_watermark_value(r#"{"id":100,"fp":-42,"ct":9,"sid":7}"#)
                .unwrap()
                .cursor_sid,
            Some(7),
            "sid 要真读进来"
        );
        // `n` 跟前三项**故意不一样**: 缺席**不判迁移** —— Shallow 路径(watch)推的水位本来就可能
        // 没有它; 判成迁移会让 watch 和懒式刷新互相打架 → 每次查询都全量重扫。
        let no_n = DrainCursor::from_watermark_value(r#"{"id":100,"fp":-42,"ct":9,"sid":7}"#).unwrap();
        assert_eq!(no_n.local_id, 100, "缺 n 不该被打回 0");
        assert_eq!(no_n.prefix_rows, None);
        assert_eq!(
            DrainCursor::from_watermark_value(r#"{"id":100,"fp":-42,"ct":9,"sid":7,"n":100}"#)
                .unwrap()
                .prefix_rows,
            Some(100)
        );

        // 写回来的形状。
        let full = DrainCursor {
            local_id: 5,
            resume_fp: Some(-42),
            cursor_ct: Some(7),
            cursor_sid: Some(9),
            prefix_rows: Some(5),
        };
        assert_eq!(full.to_watermark_value(), r#"{"id":5,"fp":-42,"ct":7,"sid":9,"n":5}"#);
        assert_eq!(
            DrainCursor::from_watermark_value(&full.to_watermark_value()).unwrap(),
            full
        );

        // sid == 0 = "服务端还没回执" → **照写 0**, 不能省: 省了就跟"老格式根本没这个键"分不开,
        // 读那侧要么永远重扫要么永远不重扫, 两条路都错(codex round-7 P1)。
        let sid0 = DrainCursor {
            cursor_sid: Some(0),
            ..full
        };
        assert_eq!(sid0.to_watermark_value(), r#"{"id":5,"fp":-42,"ct":7,"sid":0,"n":5}"#);
        assert_eq!(
            DrainCursor::from_watermark_value(&sid0.to_watermark_value()).unwrap(),
            sid0,
            "0 要原样读回来, 不能变成 None(那就成了'老格式')"
        );

        // 缺 ct 时**不能**退回裸数字(那会把 fp 一起丢掉); 读回来那侧再判"重扫一次"。
        let no_ct = DrainCursor {
            cursor_ct: None,
            cursor_sid: None,
            prefix_rows: None,
            ..full
        };
        assert_eq!(no_ct.to_watermark_value(), r#"{"id":5,"fp":-42}"#);
        assert_eq!(
            DrainCursor::from_watermark_value(&no_ct.to_watermark_value()).unwrap(),
            DrainCursor::default(),
            "缺 ct 读回来必须是归零游标 = 重扫一次"
        );
    }

    #[test]
    fn key_desc_is_local_id() {
        assert_eq!(DrainCursor::KEY_DESC, "local_id");
    }

    #[test]
    fn db_snapshot_constructs() {
        let snap = DbSnapshot {
            db_id: format!("{}|message_0.db", sha8(b"wxid_x")),
            wxid: Wxid::try_new("wxid_x").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from("/wx/db_storage/message/message_0.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 1_780_000_000_000,
            size_bytes: 4096,
        };
        assert_eq!(snap.rel_name, "message_0.db");
        assert_eq!(snap.kind, "message");
    }

    /// K-R4 (代码双审 P0): DbSnapshot Debug 不泄 sub_db_path 里的 wxid; db_id 非敏感; wxid 走 sha8.
    #[test]
    fn db_snapshot_debug_redacts_path_and_wxid() {
        let snap = DbSnapshot {
            db_id: format!("{}|message_0.db", sha8(b"wxid_secret_user")),
            wxid: Wxid::try_new("wxid_secret_user").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from(r"X:\xwechat_files\wxid_secret_user_abfe\message_0.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 0,
            size_bytes: 0,
        };
        let dbg = format!("{snap:?}");
        assert!(!dbg.contains("wxid_secret_user"), "Debug 泄 wxid: {dbg}");
        assert!(!dbg.contains("xwechat_files"), "Debug 泄绝对路径: {dbg}");
        assert!(dbg.contains("sub_db_path_sha8"), "应 path sha8: {dbg}");
        assert!(dbg.contains("message_0.db"), "rel_name 非敏感保留: {dbg}");
    }

    /// K-R4: MessageSubsource Debug 不泄 conv_id 明文 (wxid/chatroom_id); table 是 md5 哈希保留.
    #[test]
    fn message_subsource_debug_redacts_conv() {
        let sub = MessageSubsource {
            table: "Msg_0123456789abcdef0123456789abcdef".into(),
            conv_id: "wxid_peer_secret".into(),
        };
        let dbg = format!("{sub:?}");
        assert!(!dbg.contains("wxid_peer_secret"), "Debug 泄 conv 明文: {dbg}");
        assert!(dbg.contains("conv_id_sha8"), "应 conv sha8: {dbg}");
        assert!(
            dbg.contains("Msg_0123456789abcdef0123456789abcdef"),
            "table 哈希保留: {dbg}"
        );
    }

    /// DbSource trait 对象安全 (dyn) — adapter 主 loop 用 Box<dyn DbSource>.
    #[tokio::test]
    async fn db_source_trait_object_safe() {
        struct MockSource;
        #[async_trait]
        impl DbSource for MockSource {
            async fn snapshot_dbs(&mut self) -> Result<Vec<DbSnapshot>, DbSourceError> {
                Ok(vec![])
            }
            async fn list_message_subsources(
                &mut self,
                _snapshot: &DbSnapshot,
            ) -> Result<Vec<MessageSubsource>, DbSourceError> {
                Ok(vec![])
            }
            async fn drain_messages(
                &mut self,
                _snapshot: &DbSnapshot,
                _subsource: &MessageSubsource,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<MessageBatch, DbSourceError> {
                Ok(MessageBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_contacts(
                &mut self,
                _contact_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<ContactBatch, DbSourceError> {
                Ok(ContactBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_chatrooms(
                &mut self,
                _contact_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<ChatroomBatch, DbSourceError> {
                Ok(ChatroomBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_sessions(
                &mut self,
                _session_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<SessionBatch, DbSourceError> {
                Ok(SessionBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_favorites(
                &mut self,
                _favorite_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<FavoriteBatch, DbSourceError> {
                Ok(FavoriteBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_favorite_tags(
                &mut self,
                _favorite_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<FavoriteTagBatch, DbSourceError> {
                Ok(FavoriteTagBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_moments(
                &mut self,
                _sns_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<MomentBatch, DbSourceError> {
                Ok(MomentBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_transfers(
                &mut self,
                _general_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<TransferBatch, DbSourceError> {
                Ok(TransferBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_red_envelopes(
                &mut self,
                _general_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<RedEnvelopeBatch, DbSourceError> {
                Ok(RedEnvelopeBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_group_pays(
                &mut self,
                _general_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<GroupPayBatch, DbSourceError> {
                Ok(GroupPayBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_friend_verifies(
                &mut self,
                _general_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<FMessageBatch, DbSourceError> {
                Ok(FMessageBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_finder_visits(
                &mut self,
                _general_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<FinderBatch, DbSourceError> {
                Ok(FinderBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_moment_feeds(
                &mut self,
                _sns_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<MomentFeedBatch, DbSourceError> {
                Ok(MomentFeedBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_sns_notifies(
                &mut self,
                _sns_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<SnsNotifyBatch, DbSourceError> {
                Ok(SnsNotifyBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_emoticons(
                &mut self,
                _emoticon_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<EmoticonBatch, DbSourceError> {
                Ok(EmoticonBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }

            async fn drain_avatars(
                &mut self,
                _head_image_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<AvatarBatch, DbSourceError> {
                Ok(AvatarBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
            async fn drain_bizchat_users(
                &mut self,
                _bizchat_db: &Path,
                since: &DrainCursor,
                _limit: usize,
            ) -> Result<BizChatUserBatch, DbSourceError> {
                Ok(BizChatUserBatch {
                    rows: vec![],
                    next_cursor: *since,
                    has_more: false,
                })
            }
        }
        let mut s: Box<dyn DbSource> = Box::new(MockSource);
        assert_eq!(s.source_type(), "native_wechat");
        assert!(s.snapshot_dbs().await.unwrap().is_empty());
        let snap = DbSnapshot {
            db_id: "x|message_0.db".into(),
            wxid: Wxid::try_new("wxid_x").unwrap(),
            kind: "message".into(),
            sub_db_path: PathBuf::from("/m.db"),
            rel_name: "message_0.db".into(),
            mtime_ms: 0,
            size_bytes: 0,
        };
        assert!(s.list_message_subsources(&snap).await.unwrap().is_empty());
        let sub = MessageSubsource {
            table: "Msg_0123456789abcdef0123456789abcdef".into(),
            conv_id: "wxid_peer".into(),
        };
        let batch = s
            .drain_messages(&snap, &sub, &DrainCursor::default(), 1000)
            .await
            .unwrap();
        assert!(!batch.has_more);
        assert_eq!(batch.next_cursor, DrainCursor::default());
        assert!(batch.rows.is_empty());
        let cb = s
            .drain_contacts(Path::new("/c.db"), &DrainCursor::default(), 100)
            .await
            .unwrap();
        assert!(cb.rows.is_empty() && !cb.has_more);
        let crb = s
            .drain_chatrooms(Path::new("/c.db"), &DrainCursor::default(), 100)
            .await
            .unwrap();
        assert!(crb.rows.is_empty() && !crb.has_more);
    }

    /// K-R4: ChatroomRawRow Debug 不露 chatroom_id/owner 明文 + ext_buffer 成员内容.
    #[test]
    fn chatroom_raw_row_debug_redacts() {
        let row = ChatroomRawRow {
            rowid: 7,
            chatroom_id: "12345678@chatroom".into(),
            owner: Some("wxid_owner_secret".into()),
            ext_buffer: b"member-blob-bytes".to_vec(),
            chatroom_name: Some("秘密群名".into()),
            chatroom_remark: Some("秘密群备注".into()),
            announcement: Some("秘密公告内容".into()),
            announcement_editor: Some("wxid_editor_secret".into()),
            announcement_publish_time: 1_700_000_000,
            xml_announcement: Some("<xml>秘密富媒体公告</xml>".into()),
            chat_room_status: 0x80000,
        };
        let dbg = format!("{row:?}");
        assert!(!dbg.contains("12345678@chatroom"), "Debug 泄群 id: {dbg}");
        assert!(!dbg.contains("秘密公告内容"), "Debug 泄群公告: {dbg}");
        assert!(!dbg.contains("秘密富媒体公告"), "Debug 泄富媒体公告: {dbg}");
        assert!(!dbg.contains("秘密群备注"), "Debug 泄群备注: {dbg}");
        assert!(!dbg.contains("wxid_editor_secret"), "Debug 泄公告编辑者: {dbg}");
        assert!(!dbg.contains("wxid_owner_secret"), "Debug 泄群主: {dbg}");
        assert!(!dbg.contains("member-blob"), "Debug 泄成员 blob: {dbg}");
        assert!(dbg.contains("chatroom_id_sha8") && dbg.contains("ext_buffer_len"));
    }
}
