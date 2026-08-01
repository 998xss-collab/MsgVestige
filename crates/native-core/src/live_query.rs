//! live_query.rs — **L1-free 源库快查** + **持久化定位表**: 不建 L1 直查加密源库某会话消息。
//!
//! 用途: 存储紧张 / 小号, 不想解密出一份 GB 级 L1。三招把源库查询压快:
//! - **持久化定位表** (`conv_id → [(分片, Msg_<md5> 表)]` 存 JSON 小文件, 几百 KB): 新开程序加载缓存,
//!   **只重扫 mtime/size 变过的分片**, 没变的直接复用 → 冷启动从 "开全部 8 分片 ~45s" 降到 "只开变过的几个 ~几秒"。
//! - **按需只开相关分片** (lazy): 查某群只开它所在的 1-2 个分片 (不是全部)。
//! - **保温连接** (VFS 按需解密, ~11MB/分片): 开过的连接留着复用, 重复查毫秒。
//! - 排序按 `local_id` (rowid 主键, 天然索引) 取最近 N 行 —— **不按 create_time (微信没建索引, 大群全表排序 65s)**。
//!
//! 复用 ADR-500 `open_decrypted_db_vfs` + `decode_message_content`/`split_chatroom_sender`/`Name2Id`。
//! K-R4: key `Zeroizing`; **定位表文件只存 conv_id/表名 (会话标识, 非正文/非 key)**; 返回值含正文/wxid 调用方自负。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::cipher::{open_decrypted_db_vfs, CipherError};
use crate::decoder::{
    assemble_finder, classify_sysmsg, content_encoding, decode_local_type, decode_message_content, msg_anchor,
    parse_roomdata, resolve_sender_parts, split_chatroom_sender, FinderContext, FinderRow, RoomDataParse,
};
use crate::key_provider::{MasterKey, Wxid};

/// 一条查出来的消息 (已解码正文 + 全字段, R5 热查扩全)。
///
/// **字段与冷查 L1 `message` 行对齐** —— 派生字段 (msg_type_name/sys_type/decode_kind/source_native_id)
/// 全复用冷查 ingest 同一批**纯函数** ([`decode_local_type`]/[`classify_sysmsg`]/[`content_encoding`]/
/// [`msg_anchor`]), 故热=冷零漂移; 其余是 Msg_ 原始列直取 (无派生)。
/// **create_time 为毫秒** (R6 归一: Msg_ 原值 ×1000, 与冷查详情行同单位; `around` 锚点 center_time 亦毫秒,
/// 内部 ÷1000 比 Msg_ 的秒列)。
#[derive(Debug, Clone)]
pub struct QueriedMsg {
    /// 消息稳定标识 (= `msg_anchor(conv_id, local_id)`, 同冷查 `source_native_id`; 供 inspect/引用)。
    pub source_native_id: String,
    /// 所属会话 id (单聊=对方 wxid, 群=chatroom id; 同冷查 `message.conv_id`)。
    ///
    /// **R16-0 加**: 全局扫命令 (calls/links/files/events/mentions/biz…) 要按会话输出这一列 —— 数据本就在
    /// (`decode_msg_row` 的 `conv_id` 入参 / 全分片扫按 locator 逐会话迭代), 只是原先结构没带出来。
    pub conv_id: String,
    /// 微信源 db 行 id (keyset 主键)。
    pub local_id: i64,
    /// 服务端消息 id。
    pub server_id: i64,
    /// 服务端序列号。
    pub server_seq: i64,
    /// 消息来源分类 (Msg_ 现成列)。
    pub origin_source: i64,
    /// 媒体上传状态 (Msg_ 现成列)。
    pub upload_status: i64,
    /// 媒体下载状态 (Msg_ 现成列)。
    pub download_status: i64,
    /// 发送时间 (unix **毫秒**, R6 归一同冷查; 见结构体文档)。
    pub create_time: i64,
    /// 微信内排序键。
    pub sort_seq: i64,
    /// 消息状态枚举。
    pub status: i64,
    /// 微信源 db localType 原值 (`msg_type` 高低位打包前)。
    pub local_type: i64,
    /// 主类型枚举 (localType 低 32 位; 1=TEXT 3=IMAGE 49=APP 10000=SYSTEM …)。
    pub msg_type: i64,
    /// 主类型派生名 ("TEXT"/"IMAGE"/…)。
    pub msg_type_name: String,
    /// 子类型 (仅 APP_XML base==49 && sub!=0 时 Some)。
    pub msg_sub_type: Option<i64>,
    /// 子类型派生名 (同上条件)。
    pub msg_sub_type_name: Option<String>,
    /// 解码方式 ("plain"/"zstd"/…)。
    pub decode_kind: String,
    /// 正文 zstd/proto 解码**是否成功**(false = ZstdFail 损坏, decode_msg_row 已退空串)。冷查 ingest 遇此 emit
    /// SystemError **不落 message 表** → 冷查各命令没这行。**无 parse 的命令(biz)回调里须 `if !content_ok` 跳过**,
    /// 否则热多出冷查丢弃的解码失败行(codex biz P2)。有 parse 的命令(events/calls/…)靠 parse(空串)→None 自然跳,
    /// 不必读本字段。(此值也是 decode_msg_row 返回的 bool, scan 循环用它记 stats.content_failed_rows。)
    pub content_ok: bool,
    /// 系统消息 (msg_type 10000) 分类 revoke/pat/…; 非系统 None。
    pub sys_type: Option<String>,
    /// 单聊 / 群聊。
    pub is_chatroom: bool,
    /// 正文是否 XML payload (= `text.trim_start().starts_with('<')` —— 与冷查 `raw_xml_present` 同公式同源)。
    pub raw_xml_present: bool,
    /// 发送人 wxid。**R16-0 起与冷查同语义** —— 复用同一份 [`resolve_sender_parts`]: Name2Id > 群 content
    /// 前缀 > 单聊 status 方向 (2 已发=本账号 / 其它=对方 conv_id) > [`SENDER_UNKNOWN`](crate::decoder::SENDER_UNKNOWN) 占位。
    ///
    /// **恒 `Some`** —— 解不出返占位串 (同冷查 NOT NULL 语义); 保留 `Option` 只为不破坏既有 json 形状。
    /// 历史: R5 时热查是简版 (**前缀优先** + 解不出返 None), 与冷查有真分歧 (对抗审 R16-0-P2-1 逮出);
    /// R16-0 对齐冷查基准 = **Name2Id 优先** + 占位 (见 commit 5b87168, 测试 `hot_sender_matches_cold_semantics`)。
    pub sender: Option<String>,
    /// 解码后正文 (zstd 解压 / 明文; 群消息已去 `wxid:` 前缀)。
    pub text: String,
}

/// 一行原始 `Msg_` 读取 (SQL 列 → [`SourceQuery::decode_msg_row`] 组装 [`QueriedMsg`] 前的中间态)。
/// 列集与 native-core `source/account.rs` drain **同源** —— **R16-0 起含 `source` (msgsource) 列**
/// (原先减掉它: 彼时热查无 mentions 命令; 现 mentions 热查要从 msgsource 的 `<atuserlist>` 解 @名单,
/// 与冷查 `project_message_mention` 同源)。
struct RawMsgRead {
    local_id: i64,
    server_id: i64,
    server_seq: i64,
    origin_source: i64,
    upload_status: i64,
    download_status: i64,
    local_type: i64,
    sort_seq: i64,
    create_time: i64,
    status: i64,
    real_sender_id: Option<i64>,
    /// `hex(coalesce(message_content, x''))` (NULL→空; 下游 hex::decode 还原字节)。
    mc_hex: String,
    /// `hex(coalesce(source, x''))` — msgsource XML (含 `<atuserlist>` @名单)。**R16-0 加**: mentions 热查
    /// 唯一需要它 (冷查 `project_message_mention` 吃的就是这列; 其余派生表都从 `message_content` 抽)。
    /// 其余命令不读; 多读一列开销极小 (msgsource 通常几十字节)。NULL→空。
    src_hex: String,
}

/// 热查消息 SQL 列 (13 列; [`RawMsgRead`] 顺序读)。`latest_messages` / `messages_around` 共用免漂移。
/// **R16-0**: 末尾加 `source` (msgsource @名单) —— mentions 热查需要, 其余命令不读 (见 [`RawMsgRead::src_hex`])。
const MSG_COLS: &str = "local_id, server_id, server_seq, origin_source, upload_status, download_status, \
     local_type, sort_seq, create_time, status, real_sender_id, \
     hex(coalesce(message_content, x'')) AS mc, hex(coalesce(source, x'')) AS src";

/// `query_map` 回调: 一行 13 列 → [`RawMsgRead`] (须与 [`MSG_COLS`] 顺序一致)。latest/around 共用免抄。
fn read_raw_msg(r: &rusqlite::Row) -> rusqlite::Result<RawMsgRead> {
    Ok(RawMsgRead {
        local_id: r.get(0)?,
        server_id: r.get(1)?,
        server_seq: r.get(2)?,
        origin_source: r.get(3)?,
        upload_status: r.get(4)?,
        download_status: r.get(5)?,
        local_type: r.get(6)?,
        sort_seq: r.get(7)?,
        create_time: r.get(8)?,
        status: r.get(9)?,
        real_sender_id: r.get::<_, Option<i64>>(10)?,
        mc_hex: r.get::<_, String>(11)?,
        src_hex: r.get::<_, String>(12)?,
    })
}

/// 一条热查收藏 (**R16-1 小库快档**)。**字段与冷查 `favorites_query` 输出对齐** (6 键, 源库
/// `fav_db_item` 直取, 零解码)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedFavorite {
    /// 服务端收藏 id。
    pub server_id: i64,
    /// 收藏类型码 (源库列名是 `type`, 保留字故 SQL 里加引号)。
    pub fav_type: i64,
    /// 最后更新时刻 (unix 秒)。
    pub update_time: i64,
    /// 来源人 (源库 `fromusr`; L1 侧该列 `NOT NULL`)。
    pub from_user: String,
    /// 来源会话 (源库 `realchatname`)。**必须是 `Option`** —— L1 的 `real_chat_name` 是**可空列**,
    /// 冷查出 `null`; 热查若 `unwrap_or_default()` 成 `""`, 同一行冷热就一个 `null` 一个 `""` ——
    /// 消费方判 `=== null` 和 `=== ''` 行为不同。真库全量对拍逮到 **96 处**这种分叉(单测夹具照不出:
    /// 我夹具里那列填的都是非空值)。
    pub real_chat_name: Option<String>,
    /// 正文**字节**数 —— 冷查用 `LENGTH(CAST(content AS BLOB))`, **不是**裸 `LENGTH`
    /// (后者按**字符**数算, UTF-8 汉字低估 3 倍; 见 source/account.rs 的同款注释与测试)。热查照抄同口径。
    pub content_len: i64,
}

/// 一条热查好友验证 (**R16-1 小库快档**)。**字段与冷查 `friend_requests_query` 对齐** ——
/// 冷查出 6 列 + 一个 `scene_label` (由 native-query 侧的**纯函数** `friend_scene_label(scene)` 算,
/// 不进本结构: 内核只出源库真值, label 归皮层, 免两处各算一份漂移)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedFriendRequest {
    /// 申请时刻 (unix 秒; 源库 `timestamp_`)。
    pub timestamp: i64,
    /// 对方 wxid (源库 `user_name_`)。
    pub user_name: String,
    /// 好友类型码 (源库 `type_`)。
    pub friend_type: i64,
    /// 是否本账号发起 (源库 `is_sender_`)。
    pub is_sender: i64,
    /// 来源场景码 (源库 `scene_`; 皮层用 `friend_scene_label` 转中文)。
    pub scene: i64,
    /// 打招呼留言 (源库 `content_`; 冷查 json 里键名是 `greeting`)。
    pub content: String,
}

/// 一条热查视频号访问 (**R16-1**)。**字段与冷查 `finder_query` 的 5 键对齐**。
///
/// 与前三条(contacts/favorites/friend-requests)的**结构性差异**: 那三条的字段在源库里都是**现成的列**,
/// 照抄 SQL 就行; 本条的 `name`/`visit_time`/`profile_url` 全藏在 `extra_buffer` 这个 **proto BLOB** 里,
/// 得解码才拿得到 —— 这带来两个连锁后果, 见 [`read_hot_finder_visits`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedFinderVisit {
    /// 访问时刻 (unix 秒; proto f5)。
    pub visit_time: i64,
    /// 访问日期 (`date(visit_time,'unixepoch','localtime')`)。**必须用 SQLite 算, 不能用 Rust** ——
    /// 冷查是在 SQL 里算的, 带**本地时区**; 两边用不同的时区实现就会在日界线附近分叉。见内核里的注释。
    pub visit_date: String,
    /// 视频号昵称 (proto f2; 可空 —— 空**不代表**空壳行)。
    pub name: String,
    /// 号主 id (源库 `username` 列; wxid/微信号)。
    pub owner_username: String,
    /// 主页 URL (proto f6; 可空)。
    pub profile_url: String,
}

/// 一条热查自定义表情 (**R16-1**)。**字段与冷查 `CMD_EMOTICONS`(引擎)的 5 键对齐**。
///
/// 与前四条的**结构性差异**: 前四条冷查是**手写 `*_query`**(自己拼 SQL + json), 本条冷查走
/// **引擎 `emit_engine_query(&CMD_EMOTICONS)`** —— 引擎的 5 列(`caption`/`md5`/`emoticon_type`/
/// `product_id`/`cdn_url`)直接映射 L1 `custom_emoticon` 表的同名列。热查照**冷查的输出键**取源库对应列:
/// 源库 `emoticon.db` 的 `kNonStoreEmoticonTable`, 列名多数同名, 但 **源库 `type` → 输出 `emoticon_type`**
/// (ETL `drain_emoticons` 就是这么改名的, 见 source/account.rs)。
/// **`cdn_url` 要出**: 引擎里它标 `Fmt::Hidden`, 但那只藏 **table 渲染**, **json 照出**(真跑冷查
/// json 核过, 5 键全在)。别被"不露 cdn_url"的注释骗了 —— 那是 table。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedEmoticon {
    /// 中文描述 (源库 `caption`; L1 `caption`)。
    pub caption: String,
    /// 表情内容 md5 (源库/L1 `md5`; 身份)。
    pub md5: String,
    /// 类型码 (**源库 `type` → 输出 `emoticon_type`**; ETL 改的名)。
    pub emoticon_type: i64,
    /// 商品 id (源库/L1 `product_id`; 表情商店的)。
    pub product_id: String,
    /// CDN 下载 url (源库/L1 `cdn_url`; 引擎标 Hidden 只藏 table, json 出)。
    pub cdn_url: String,
}

/// 一条热查群成员 (**R16-1 降级件**)。**字段与冷查 `members_query` 的 5 键对齐**, 但两处**本质降级**
/// (用户 2026-07-18 决策⑦, 办法二):
///
/// 群成员在源库不是现成表 —— `contact.db` 的 `chat_room` 表是"**一群一行**", 成员全塞在 `ext_buffer`
/// **protobuf** 里(`parse_roomdata` 解, 同 finder 的 proto 难点)。冷查 L1 `chatroom_member` 是 ETL
/// **展开成多行 + 跨次 ingest 维护状态**的产物。热查直读源库**本质拿不到**两样:
/// - **`joined_at`(入群时间)**: 源库 proto 里**根本没存**, 是 ETL 跨次 ingest 累积算的 → 热查恒 `null`。
/// - **退群成员**: 已从 proto 移除, 冷查靠 L2 明文列**回读历史**保留; 热查只看得到**当前在群**的人。
///
/// 故 members 热查是**当前在群快照**, 皮层标 `partial:true`。冷热对拍**不是逐行相等**: 热是冷"在群成员"
/// 的子集、`joined_at` 热恒 null —— 这是唯一诚实的对等口径。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedMember {
    /// 成员 wxid (源库 proto `username`; 冷查键 `member_wxid`)。
    pub member_wxid: String,
    /// 群昵称 (源库 proto `group_nick`; 可空 → 冷查 ETL 走 non_empty 归 null, 热查同)。
    pub display_name: Option<String>,
    /// 角色 `"owner"`/`"admin"`/`"member"` —— **同 ETL 判定**(pipeline.rs:1703): 群主比 `chat_room.owner`
    /// 列, 再 admin 看 proto `is_admin`(field3 flags & 2048), 其余 member。
    pub role: String,
    /// 邀请人 wxid (源库 proto `invited_by`; 可空)。
    pub invited_by: Option<String>,
    // 注: **无 `joined_at`** —— 它源库拿不到, 皮层出 `null`(降级)。见结构体 doc。
}

/// 一条热查群 (**R16-1**)。**字段与冷查引擎 `CMD_CHATROOMS` 的 5 列对齐**。
///
/// 源库 `contact.db` 的 `chat_room` 表一群一行, 但群名/公告**不在** chat_room 表里 —— 同冷查 ETL 的
/// drain SQL(source/account.rs): `chat_room cr LEFT JOIN contact c ON c.username=cr.username`(群名 =
/// contact.nick_name)`LEFT JOIN chat_room_info_detail cid ON cid.username_=cr.username`(公告)。
/// `member_count` 从 `ext_buffer` proto 解出的成员数(同 members 的 `parse_roomdata`; Invalid → 0,
/// 同 pipeline.rs:1644)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedChatroom {
    /// 群 id (源库 `chat_room.username`; 冷查键 `chatroom_id`)。
    pub chatroom_id: String,
    /// 群名 (源库 `contact.nick_name` LEFT JOIN)。**冷查这列存空串 `""` 而非 null**
    /// —— `assemble_chatroom` 对 chatroom_name 用 `unwrap_or_default()`(非 Option), 跟 owner/公告用
    /// `non_empty` 归 null **不同**(硬约束⑤: 逐列对齐 L1 实际存法, 非一刀切)。故这里也 `unwrap_or_default`
    /// 出空串, 不 non_empty —— 否则 143 个无名群冷 `""` vs 热 `null` 分叉(真跑 parity 逮到)。
    pub chatroom_name: String,
    /// 群主 wxid (源库 `chat_room.owner`; 空串 → None)。
    pub owner_wxid: Option<String>,
    /// 成员数 (从 `ext_buffer` proto 解出的成员数; Invalid proto → 0)。
    pub member_count: i64,
    /// 群公告 (源库 `chat_room_info_detail.announcement_` LEFT JOIN; 空串 → None)。
    pub announcement: Option<String>,
}

/// 一条热查头像 (**R16-1**)。**字段与冷查引擎 `CMD_AVATARS` 的 3 列对齐**(不含头像 BLOB 本体)。
///
/// 源库 `head_image.db` 的 `head_image` 表(冷查 ETL 落 L1 `avatar_image`, 同名列直取)。**空 username 行
/// 冷查 pipeline 跳过**(username 是身份) → 热查 `WHERE username != ''` 对齐, 否则热比冷多行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedAvatar {
    /// 头像归属 wxid (源库 `head_image.username`; 空串行冷查跳过, 热查也滤)。
    pub username: String,
    /// 头像内容 md5 (源库 `head_image.md5`)。
    pub md5: String,
    /// 更新时刻 (源库 `head_image.update_time`, unix 秒; 冷查 JSON 出原始 i64, 非格式化)。
    pub update_time: i64,
}

/// 一条热查企微联系人 (**R16-1**)。**字段与冷查引擎 `CMD_BIZ_CONTACTS` 的 3 列对齐**。
///
/// 源库 `bizchat.db` 的 `user_info` 表(冷查 ETL 落 L1 `bizchat_user`, 同名列直取)。**空 user_id 行冷查
/// pipeline 跳过**(user_id 是身份/anchor, 空则无法定位) → 热查 `WHERE user_id != ''` 对齐。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedBizContact {
    /// 昵称 (源库 `user_info.user_name`; 空串保留 "", 同冷查直取)。
    pub user_name: String,
    /// 企微 id (源库 `user_info.user_id`; 身份, 空行冷查跳过热查也滤)。
    pub user_id: String,
    /// 品牌号 gh_ (源库 `user_info.brand_user_name`; 空串保留 "")。
    pub brand_user_name: String,
}

/// 一条热查朋友圈动态 (**R16-1**)。**字段与冷查 `moments_query` 的 7 键对齐**。
///
/// 源库 `sns.db` 的 `SnsTimeLine` 表(tid/user_name/content); content 是 `<SnsDataItem>` XML, 一切结构化
/// 字段(昵称/正文/媒体数/赞评数)从此抽 —— **复用 ETL 同一个 `assemble_sns`**(含 `count_interactions`
/// 两 wrapper 坑, 不重写)。全扫式(create_time 在 XML 里, SQL 排不了)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedMoment {
    /// 发布者 wxid (源库 `SnsTimeLine.user_name`; 冷查键 `author`)。
    pub author: String,
    /// 发布者昵称 (从 content XML 解; 可空 → 冷查 nullable)。
    pub author_nickname: Option<String>,
    /// 发布时刻 unix 秒 (从 content XML 解; 冷查 JSON 出原始 i64)。
    pub create_time: i64,
    /// 正文文字 (从 content XML `contentDesc` 解; 空串保留)。
    pub content_desc: String,
    /// 媒体数 (图/视频; 从 content XML 数)。
    pub media_count: i64,
    /// 点赞数 (从 content XML 两 wrapper 数, 同 ETL)。
    pub like_count: i64,
    /// 评论数 (从 content XML 两 wrapper 数, 同 ETL)。
    pub comment_count: i64,
}

/// 一条查出来的会话 (R5 热查扩全会话部分)。**字段与冷查 L1 `session` 行 (V3Session) 对齐** —— 会话数据几乎
/// 全是 `SessionTable` 原始列直取 (无正文解码/类型派生, 区别消息), 唯一派生 `summary_len` = 摘要**字符数**
/// (同冷查 `project_session` 的 char_len)。id 类字段 (username/last_msg_sender) 明文 (ADR-427 全程明文)。
#[derive(Debug, Clone)]
pub struct QueriedSession {
    /// 会话标识 (单聊=对方 wxid, 群=chatroom id; 同冷查 `username`, 供当 conv 查消息)。
    pub username: String,
    /// 单聊 / 群聊 (= `username.ends_with("@chatroom")`)。
    pub is_group: bool,
    /// 最后一条消息摘要 (明文; 可空)。
    pub summary: Option<String>,
    /// 摘要字符数 (派生, 同冷查 char_len)。
    pub summary_len: i64,
    /// 最后发言人展示名 (群里显示"谁: 内容"的谁; 可空)。
    pub last_sender_display_name: Option<String>,
    /// 未读数。
    pub unread_count: i64,
    /// 最后一条消息类型。
    pub last_msg_type: i64,
    /// 最后一条消息子类型。
    pub last_msg_sub_type: i64,
    /// 微信会话排序时间戳 (会话列表按它倒序)。
    pub sort_timestamp: i64,
    /// 会话类型 (`SessionTable."type"`)。
    pub session_type: i64,
    /// 是否隐藏会话。
    pub is_hidden: i64,
    /// 会话状态。
    pub status: i64,
    /// 草稿 (明文; 可空)。
    pub draft: Option<String>,
    /// 最后一条消息发送人 (id 类明文; 可空)。
    pub last_msg_sender: Option<String>,
    /// 最后一条消息时间戳。
    pub last_timestamp: i64,
    /// 上次清未读时间戳。
    pub last_clear_unread_timestamp: i64,
    /// 最后一条消息 local_id。
    pub last_msg_locald_id: i64,
    /// 最后一条消息 ext_type。
    pub last_msg_ext_type: i64,
    /// 未读首条消息 server_id。
    pub unread_first_msg_srv_id: i64,
}

/// 热查会话 SQL 列 (17 列, 无 rowid —— 热查不按游标翻页)。列名/别名与 native-core `source/account.rs`
/// `drain_sessions` **同源** (实测 `SessionTable` schema), 减 rowid。`"type"` 是 SQLite 关键字须引号。
const SESSION_COLS: &str = "username, summary, last_sender_display_name, unread_count, last_msg_type, \
     last_msg_sub_type, sort_timestamp, \"type\" AS session_type, is_hidden, status, draft, \
     last_msg_sender, last_timestamp, last_clear_unread_timestamp, last_msg_locald_id, \
     last_msg_ext_type, unread_first_msg_srv_id";

/// `query_map` 回调: 一行 → [`QueriedSession`] (按列名取, 与 [`SESSION_COLS`] 对应)。可空整数列 (NULL→0),
/// 文本列 Option。`summary_len` 派生字符数 (同冷查)。
fn read_session_row(r: &rusqlite::Row) -> rusqlite::Result<QueriedSession> {
    let username: String = r.get("username")?;
    let summary: Option<String> = r.get("summary")?;
    let int0 = |name: &str| -> rusqlite::Result<i64> { Ok(r.get::<_, Option<i64>>(name)?.unwrap_or(0)) };
    Ok(QueriedSession {
        is_group: username.ends_with("@chatroom"),
        summary_len: summary
            .as_deref()
            .map_or(0, |s| i64::try_from(s.chars().count()).unwrap_or(i64::MAX)),
        username,
        summary,
        last_sender_display_name: r.get("last_sender_display_name")?,
        unread_count: int0("unread_count")?,
        last_msg_type: int0("last_msg_type")?,
        last_msg_sub_type: int0("last_msg_sub_type")?,
        sort_timestamp: int0("sort_timestamp")?,
        session_type: int0("session_type")?,
        is_hidden: int0("is_hidden")?,
        status: int0("status")?,
        draft: r.get("draft")?,
        last_msg_sender: r.get("last_msg_sender")?,
        last_timestamp: int0("last_timestamp")?,
        last_clear_unread_timestamp: int0("last_clear_unread_timestamp")?,
        last_msg_locald_id: int0("last_msg_locald_id")?,
        last_msg_ext_type: int0("last_msg_ext_type")?,
        unread_first_msg_srv_id: int0("unread_first_msg_srv_id")?,
    })
}

/// **热查会话列表** (R5 扩全) —— 直查加密 `session.db` 的 `SessionTable`, 返 `(本页会话按 sort_timestamp 倒序,
/// **has_more (第6轮再审: limit+1 哨兵精确判)**, **全量数 (COUNT 失败=None)**, **本页行映射失败丢的行数**)`。区别旧
/// locator 法 (只列"有消息分片的 conv" + shard 数): 本法读**微信真实会话列表** + 全字段, 与冷查 `sessions` 同源同
/// 字段。session.db 是 SQLCipher 加密, 复用 [`open_decrypted_db_vfs`] 按需解密。开库后委托 [`query_hot_sessions`]
/// (纯 `&Connection` 逻辑, 可用内存库单测)。
///
/// # Errors
/// [`CipherError`] — session.db 解密/打开失败 (key 不对 / 库损坏)。prepare/查询失败亦归此 (记 warn! 保诊断)。
pub fn read_hot_sessions(
    session_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedSession>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(session_db, key)?;
    query_hot_sessions(&conn, session_db, limit, offset)
}

/// **R16-1**: 热查联系人 —— 直读加密 `contact.db`, 输出与冷查 `contacts_query` 的 5 字段对齐。
///
/// **合并 `contact` + `stranger` 两表** (对抗审 P2-3 逮出的行完整性缺口): 冷查的 person 表同时收好友
/// (`source=contact.db`) 与陌生人 (`source=contact.db|stranger`, ingest `--strangers` 落), 两表**列结构
/// 全同 22 列**, 而 `contacts_query` 的输出**不带 source 列** → 好友与陌生人本就混在一起出。热查只读
/// `contact` 表会**整个漏掉陌生人**。故 UNION ALL 两表。
///
/// **冷热差异 (§六 语义契约: 热=活源真值 / 冷=末次 ingest 快照, 易变面允许漂移)**: 若 ingest 时没跑
/// `--strangers`, 冷查 person 里就没有陌生人行, 而热查照样出 → **热可能比冷多**。这是"活值 vs 快照"的
/// 正常表现, 不是 bug。
/// **老库兼容**: `stranger` 表不存在 → 只出 `contact` 表 (宽松, 不整条失败)。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 `contact` 表查询失败 (`stranger` 表缺失不算错)。
pub fn read_hot_contacts(
    contact_db: &Path,
    key: &MasterKey,
    q: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedContact>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(contact_db, key)?;
    query_hot_contacts(&conn, contact_db, q, limit, offset)
}

/// **R16-1**: 热查视频号访问 —— 直读加密 `general.db` 的 `wcfinderuserpage`, 输出与冷查 `finder_query`
/// 的 5 键对齐。
///
/// **本条与前三条的三点结构性差异**(都源于"字段藏在 proto BLOB 里, 不是现成的列"):
///
/// 1. **必须全扫, 不能 SQL 分页**。空壳行(纯号主 id, 无频道数据也无访问时刻)在 ingest 落 L1 时被跳掉,
///    热查必须跳掉同一批 —— 但判据在 proto 的 f2/f5/f6 上, **SQL 过滤不了**(`WHERE` 写不出来)。若先
///    `LIMIT` 再跳, 本页会不足 limit 且 offset 全线错位。故: 全扫 → 解码 → 跳 → 内存排序 → 内存分页。
///    真库实测 723 行(L1)量级, 全扫无压力; 表大了要重估。
/// 2. **跳空壳走 [`crate::event::FinderVisitCreate::is_empty_shell`]**, 与 ingest **同一份判据**
///    (`pipeline.rs` 的 `run_finder_visit_pipeline` 也调它)。判据写两遍必漂 → 冷热行集分叉。
/// 3. **`visit_date` 用 SQLite 算, 不用 Rust**。冷查是 `date(visit_time,'unixepoch','localtime')`
///    在 SQL 里算的, 带**本地时区**; 这里若改用 Rust 的时区实现, 日界线附近就会跟冷查出不同的日期。
///    故解完 proto 拿到 `visit_time` 后, **回同一个 SQLite 用同一个 `date()` 算**(预编译语句复用)。
///
/// 排序 `visit_time DESC` 同冷查, 补 `owner_username DESC` 次键 —— 单键排序对并列行不保证稳定顺序,
/// OFFSET 翻页会重复/漏(同 friend_verify/session 的理由)。**冷查侧本条也一并补了次键**(R16 硬约束④:
/// 接一条 = 该条冷热两侧都得稳; 热稳冷不稳仍然不叫对等)。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_finder_visits(
    general_db: &Path,
    key: &MasterKey,
    self_wxid: &Wxid,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFinderVisit>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(general_db, key)?;
    query_hot_finder_visits(&conn, general_db, self_wxid, limit, offset)
}

/// [`read_hot_finder_visits`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
///
/// 契约同其它热查: 返 `(rows, has_more, total, dropped)`。`total` = **跳完空壳后表里的行数**, 与冷查
/// `SELECT count(*) FROM finder_visit` 同口径(L1 里本就没有空壳行) —— 注意它**不等于** `rows` 能给出的
/// 行数, 见函数体里 `non_shell` / `renderable` 两个分母的注释。
///
/// **一条无人保障的前提(轮5 审 P3, 已知未修)**: 冷热行集对等还依赖"源库 `username` 唯一"。真库 DDL 是
/// `CREATE TABLE wcfinderuserpage(username TEXT, extra_buffer BLOB)` —— **没有 PRIMARY KEY, 没有 UNIQUE**;
/// 而 L1 侧 `finder_anchor(owner_username)` 只由 username 派生 + `insert_finder_visit` 是
/// `INSERT OR REPLACE` → **一个 username 在 L1 只留一行, 热查却全返**。一旦源库出现重复 username,
/// 冷热的行集与 total 立刻分叉。
/// 实测**当前不发作**(真库 1341 行 / 1341 个不同 username / 0 重复), 但这是**数据凑巧, 不是约束保证**,
/// 且没有任何测试钉住它。(friend_verify 有完全相同的结构性缺口: 7967 行 / 7967 个不同 user_name。)
/// 排序次键**不依赖**这条(次键只求"冷热同键 → 顺序确定"), total 口径依赖。
fn query_hot_finder_visits(
    conn: &Connection,
    general_db: &Path,
    self_wxid: &Wxid,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFinderVisit>, bool, Option<usize>, usize), CipherError> {
    // 列与 source/account.rs 的 drain_finder_visits 同源。全扫 (无 WHERE/LIMIT): 空壳判据在 proto 里,
    // SQL 筛不掉 —— 先 LIMIT 再跳会让本页不足 limit 且 offset 错位。
    let sql = "SELECT rowid AS rid, username AS username, \
               hex(coalesce(extra_buffer, x'')) AS extra_hex FROM wcfinderuserpage";
    let mut st = conn.prepare(sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 finder_visit prepare 失败");
        CipherError::decrypt_failed(b"", Some(general_db))
    })?;
    let mut rows_iter = st.query([]).map_err(|e| {
        tracing::warn!(error = %e, "热查 finder_visit query 失败");
        CipherError::decrypt_failed(b"", Some(general_db))
    })?;
    // visit_date 专用: 同一个 SQLite 的 date(), 与冷查同口径同时区 (Rust 算会在日界线分叉)。
    let mut date_st = conn.prepare("SELECT date(?1, 'unixepoch', 'localtime')").map_err(|e| {
        tracing::warn!(error = %e, "热查 finder_visit date 预编译失败");
        CipherError::decrypt_failed(b"", Some(general_db))
    })?;
    // 热查不关心 provenance (那是 ingest 的事), 但 assemble_finder 要 ctx —— 给最小占位。
    // 复用 assemble_finder 而非自己解 proto: 空壳判据依赖的正是它的 unwrap_or 兜底后的值。
    let ctx = FinderContext {
        account_id: self_wxid.clone(),
        source: "general.db".to_string(),
        source_native_id: String::new(),
        ingest_time: 0,
    };
    let mut all: Vec<QueriedFinderVisit> = Vec::new();
    let mut dropped = 0usize;
    // 非空壳行数 = **冷查 `count(*)` 的口径**(表里有多少行), 与 `all.len()`(我解出了多少行) 分开记 ——
    // 见下方 `non_shell += 1` 处的注释。
    let mut non_shell = 0usize;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                let parsed = (|| -> rusqlite::Result<(i64, String, String)> {
                    Ok((
                        row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                        row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    ))
                })();
                let (rid, owner_username, extra_hex) = match parsed {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "热查 finder_visit 行映射失败, 跳过该行");
                        dropped += 1;
                        continue;
                    }
                };
                let extra_buffer = hex_to_bytes(&extra_hex);
                let frow = FinderRow {
                    rowid: rid,
                    owner_username,
                    extra_buffer,
                };
                let fv = assemble_finder(&frow, &ctx); // infallible
                                                       // 与 ingest 同一份判据 (pipeline.rs 也调它) —— 不跳就会比冷查多出这些行。
                if fv.is_empty_shell() {
                    continue;
                }
                // **计数必须在产出之前** —— 走到这就是"冷查 L1 里会有的一行", 无论下面产不产得出来。
                // 冷查 total = `SELECT count(*) FROM finder_visit` = **表里的行数**; 热查 total 若写成
                // `all.len()` 就成了"**我成功解出的行数**", 两者只在零丢弃时才碰巧相等。
                // (轮5 审的三段证据链: SQLite `date()` 对越界 visit_time 返 NULL → rusqlite 报错 → 这里
                //  continue → 而 all.len() 就少了一行 → 真跑冷查塞越界值实测 冷 total=724 / 热 723。
                //  我上个 commit 还写着"个别行丢是安全区、data 完整所以标 partial 就够" —— 恰好反了:
                //  data 是完整的, **total 不是**, 它悄悄比冷查少一个, 没人看得出来。)
                non_shell += 1;
                let visit_date: String = match date_st.query_row([fv.visit_time], |r| r.get(0)) {
                    Ok(d) => d,
                    Err(e) => {
                        // 已计入 non_shell(冷查那边有这行), 只是产不出来 → dropped 让皮层标 partial。
                        tracing::warn!(error = %e, "热查 finder_visit 日期换算失败, 跳过该行");
                        dropped += 1;
                        continue;
                    }
                };
                all.push(QueriedFinderVisit {
                    visit_time: fv.visit_time,
                    visit_date,
                    name: fv.name,
                    owner_username: fv.owner_username,
                    profile_url: fv.profile_url,
                });
            }
            Ok(None) => break,
            Err(e) => {
                // 游标中断 = 剩余行**全没读到**, 手上只是个前缀 → 直接报错, 理由见函数尾部那段注释
                // (全扫路径下, 半个前缀无论怎么标元数据都会把消费方带沟里: 标"到底了"藏数据,
                //  标"还有"则因每次扫同一前缀而死循环)。
                tracing::warn!(error = %e, "热查 finder_visit 扫描中断, 结果不完整 → 报错 (不返回半个前缀)");
                return Err(CipherError::decrypt_failed(b"", Some(general_db)));
            }
        }
    }
    // 排序同冷查 visit_time DESC, 补 owner_username 次键保翻页稳 (单键对并列行不保证稳定)。
    // sort_by 是稳定排序, 但这里全序已由两个键定死, 稳不稳都一样。
    all.sort_by(|a, b| {
        b.visit_time
            .cmp(&a.visit_time)
            .then_with(|| b.owner_username.cmp(&a.owner_username))
    });
    // **两个分母, 别混**(轮5 审 P2 + 我修它时踩出的第二个坑):
    // - `non_shell` = 表里非空壳的行数 = **冷查 `count(*)` 的口径** → 给 `total`。
    // - `renderable` = 我真解得出来的行数 → 给 `has_more`("还有**取得到**的行吗")。
    // 两者只在零丢弃时相等。拿 non_shell 当 has_more 的分母, 末页会永远报"还有"(那些行根本取不出来);
    // 拿 renderable 当 total, 又会比冷查少 —— 各归各。
    // 消费方由此拿到自洽的一组: total=3 / data=2 行 / dropped_rows=1 → "表里 3 行, 给你 2 行, 1 行读不出"。
    let renderable = all.len();
    let page: Vec<QueriedFinderVisit> = all.into_iter().skip(offset).take(limit).collect();
    // 【为什么游标中断在这条路上只能报错 —— codex 两轮才收敛】
    //
    // 中断 = 后面的行根本没读到, 手上只是个前缀。两种"温柔"的表达法都是错的:
    // - `has_more=false`(把前缀当精确 total): **谎称"到底了", 未读行全被藏掉**(codex 审 4)。
    // - `has_more=true`(我上一版的修法): 全扫每次从头扫, 中断若稳定发生在同一行, **每次前缀都一样** ——
    //   offset 一旦推进到前缀末尾, 就**永远**是"空页 + has_more=true" → 消费方死循环(codex 审 5)。
    //
    // **为什么 contacts/favorites/friend-requests 那三条可以用 has_more=true**: 它们是 **SQL 分页**,
    // 每次请求重新执行带 LIMIT/OFFSET 的 SQL, offset 真的会推进、能跨过坏行往后读; 全扫路径**逃不出去**。
    // —— 同一个写法在不同结构下一个安全一个死循环。这是我上一版照抄那三条的教训: "判据是**任何**热查
    //    路径"没错(那条判据本身是对的), 但**照搬实现**不行, 得看结构。
    //
    // (**个别行**产不出来是另一回事: 那时 total 照 non_shell 报[冷查那边有这行], data 少一行,
    //  dropped>0 让皮层标 partial —— 详见 `non_shell += 1` 处。轮5 审逮到我原先把这两件事混了。)
    //
    // limit==0 不许报 has_more=true: 那时 page 恒空、meta.limit=0, 消费方按 `offset += limit` 翻页
    // = `offset += 0` → **永不终止**(codex 审 4)。对齐 `Meta::offset_page` 的 `limit > 0` 要求。
    //
    let has_more = limit > 0 && offset.saturating_add(page.len()) < renderable;
    Ok((page, has_more, Some(non_shell), dropped))
}

/// hex 字符串 → 字节。奇数长度 / 非法字符 → **就此截断, 留已解出的前缀**。
///
/// **注意: 与 ingest 侧的 `get_blob_hex` 口径并不相同**(轮5 审 P3 实测 9 例中 5 例分叉)。那边是
/// `hex::decode(s).ok()` = **全有或全无**(有一个坏字符就整个 None → 空 buffer), 这边是截断留前缀。
/// 我原先在这写着"同 `get_blob_hex` 的宽容口径" —— **那是错的**, 会骗后人。
///
/// **当前不可达**: 两条路的 SQL 都是 `hex(coalesce(extra_buffer, x''))`, 而真库探针确认该列
/// `typeof` 全是 `blob`(1341 行) → SQLite 的 `hex()` **恒产出合法的偶数长 hex**, 两种口径结果相同。
/// 留这段注释是因为: 哪天那列混进别的类型, 这里就会与 ingest 解出**不同的 buffer** → 冷热字段分叉,
/// 而两边各自的测试都会绿。要动就统一成 all-or-nothing, 别再写"同口径"。
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let src = s.as_bytes();
    let mut out = Vec::with_capacity(src.len() / 2);
    let mut pos = 0;
    while pos + 1 < src.len() {
        let (Some(hi), Some(lo)) = ((src[pos] as char).to_digit(16), (src[pos + 1] as char).to_digit(16)) else {
            break;
        };
        out.push((hi * 16 + lo) as u8);
        pos += 2;
    }
    out
}

/// **R16-1**: 热查好友验证 —— 直读加密 `general.db` 的 `FMessageTable`, 输出与冷查
/// `friend_requests_query` 的 6 列对齐 (零解码; `scene_label` 由皮层纯函数算)。
///
/// 排序 `timestamp DESC` 同冷查; 补 **`user_name_` 次键** —— timestamp 真库有并列 (同秒多条申请),
/// 单键排序 SQLite 对并列行不保证稳定 → OFFSET 翻页会重复/漏。
///
/// **次键从 rowid 改成 user_name_**(轮4 审 P3-c): 原先热用 `rowid` / 冷用 `source_native_id` = 两边**不是
/// 同一个键**, 于是并列行的顺序对不上 —— 真库实测: 第 1166 行 热=(1767079812, wxid_8wny…)
/// 冷=(1767079812, wxid_gytp…)。`user_name_` 两边都有(冷查那边是 L1 的明文 `user_name` 列), 冷热同键 →
/// 顺序一致。**唯一性不是必需条件**: 次键只求"同键 → 顺序确定且一致"。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_friend_requests(
    general_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFriendRequest>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(general_db, key)?;
    query_hot_friend_requests(&conn, general_db, limit, offset)
}

/// [`read_hot_friend_requests`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。契约同 [`query_hot_contacts`]。
fn query_hot_friend_requests(
    conn: &Connection,
    general_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFriendRequest>, bool, Option<usize>, usize), CipherError> {
    // 列与 source/account.rs 的 drain_friend_verifies 同源 (源库列名带尾下划线)。
    const FR_COLS: &str = "timestamp_ AS timestamp, user_name_ AS user_name, type_ AS friend_type, \
         is_sender_ AS is_sender, scene_ AS scene, content_ AS content";
    let total: Option<usize> = conn
        .query_row("SELECT count(*) FROM FMessageTable", [], |r| r.get::<_, i64>(0))
        .ok()
        .and_then(|n| usize::try_from(n).ok());
    let probe = limit.saturating_add(1); // limit+1 哨兵 → has_more 精确
    let sql = format!(
        "SELECT {FR_COLS} FROM FMessageTable ORDER BY timestamp_ DESC, user_name_ DESC LIMIT {probe} OFFSET {offset}"
    );
    let mut st = conn.prepare(&sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 friend_verify prepare 失败");
        CipherError::decrypt_failed(b"", Some(general_db))
    })?;
    let mut rows_iter = st.query([]).map_err(|e| {
        tracing::warn!(error = %e, "热查 friend_verify query 失败");
        CipherError::decrypt_failed(b"", Some(general_db))
    })?;
    let mut rows: Vec<QueriedFriendRequest> = Vec::new();
    let mut dropped = 0usize;
    let mut has_more = false;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                // 审 P1-2: 判哨兵必须 **+dropped** —— 丢行会把哨兵行当数据行吃掉 → has_more 少报 →
                // 消费方停止翻页 = **静默藏数据**。模板 query_hot_sessions 是 `.saturating_add(dropped)`,
                // 我抄漏了这一项 (contacts/favorites/friend_requests 三处同错, 且模板还在往后 8 条扩散)。
                if rows.len().saturating_add(dropped) >= limit {
                    has_more = true;
                    break;
                }
                let parsed = (|| -> rusqlite::Result<QueriedFriendRequest> {
                    Ok(QueriedFriendRequest {
                        timestamp: row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                        user_name: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        friend_type: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                        is_sender: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                        scene: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                        content: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    })
                })();
                match parsed {
                    Ok(f) => rows.push(f),
                    Err(e) => {
                        tracing::warn!(error = %e, "热查 friend_verify 行映射失败, 跳过该行");
                        dropped += 1;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "热查 friend_verify 游标中断, 剩余行未读");
                dropped += 1;
                has_more = true; // 审 P2-7: 不谎报"到底了"
                break;
            }
        }
    }
    Ok((rows, has_more, total, dropped))
}

/// **R16-1**: 热查收藏 —— 直读加密 `favorite.db` 的 `fav_db_item`, 输出与冷查 `favorites_query` 的 6 字段对齐。
///
/// 零解码 (正文大 blob 本就不取, 只取字节长度)。`q` 子串过滤同冷查口径 (from_user / real_chat_name 两列)。
///
/// 一条 transfer 专表基础行 (**R16-4 hot money**; general.db `transferTable` 列子集, 同冷 `drain_transfers`
/// account.rs)。金额靠皮层扫 msg49 的 transcation_id→feedesc map 补 (本表不存金额)。
pub struct MoneyTransferRow {
    pub transfer_id: String,
    pub transcation_id: String,
    pub pay_sub_type: i64,
    pub pay_payer: String,
    pub pay_receiver: String,
    pub begin_transfer_time: i64,
}

/// 一条 red_envelope 专表基础行 (**R16-4 hot money**; general.db `redEnvelopeTable`)。红包无本地金额/时间戳。
pub struct MoneyRedRow {
    pub send_id: String,
    pub sender_user_name: String,
    pub session_name: String,
    pub hb_type: i64,
    pub receive_status: i64,
}

/// 一条 group_pay 专表基础行 (**R16-4 hot money**; general.db `groupPayTable`)。金额靠 msg49 bill_no→senderdes map,
/// 已付/总人数靠 msg49 payerlist 计数补。
pub struct MoneyGroupRow {
    pub bill_no: String,
    pub session_name: String,
    pub message_create_time: i64,
}

/// hot money 三专表基础行 (**R16-4**; general.db 全读 transferTable/redEnvelopeTable/groupPayTable)。
/// 金额/付款人计数由皮层 (native-query hot_money) 扫 msg49 appmsg 补 map。Vec 长度 = 该源真 COUNT (全读无 LIMIT)。
pub struct MoneyBase {
    pub transfers: Vec<MoneyTransferRow>,
    pub reds: Vec<MoneyRedRow>,
    pub groups: Vec<MoneyGroupRow>,
}

/// 直读加密 `general.db` 的三笔交易专表 (**R16-4 hot money 基础行**; 金额/人数皮层扫 msg49 补)。
///
/// 列名与 `source/account.rs` 的 `drain_transfers`/`drain_red_envelopes`/`drain_group_pays` 同源 (无尾下划线)。
/// 全表读 (无 LIMIT/OFFSET) —— money 分页在三源**合并后**内存切片 (同冷 money_query)。缺失列 `unwrap_or` 兜默认
/// (同冷 drain 宽松取)。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_money_base(general_db: &Path, key: &MasterKey) -> Result<MoneyBase, CipherError> {
    let conn = open_decrypted_db_vfs(general_db, key)?;
    query_hot_money_base(&conn, general_db)
}

/// [`read_hot_money_base`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
fn query_hot_money_base(conn: &Connection, general_db: &Path) -> Result<MoneyBase, CipherError> {
    let warn_err = |e: rusqlite::Error, what: &str| -> CipherError {
        tracing::warn!(error = %e, table = what, "热查 money 专表失败");
        CipherError::decrypt_failed(b"", Some(general_db))
    };
    // transferTable: 冷 drain 列 transfer_id/transcation_id/pay_sub_type/pay_payer/pay_receiver/begin_transfer_time。
    let mut transfers = Vec::new();
    {
        let mut st = conn
            .prepare(
                "SELECT transfer_id, transcation_id, pay_sub_type, pay_payer, pay_receiver, begin_transfer_time \
                 FROM transferTable",
            )
            .map_err(|e| warn_err(e, "transferTable"))?;
        let iter = st
            .query_map([], |r| {
                Ok(MoneyTransferRow {
                    transfer_id: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    transcation_id: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    pay_sub_type: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    pay_payer: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    pay_receiver: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    begin_transfer_time: r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                })
            })
            .map_err(|e| warn_err(e, "transferTable"))?;
        for row in iter.flatten() {
            transfers.push(row);
        }
    }
    // redEnvelopeTable: 冷 drain 列 send_id/sender_user_name/session_name/hb_type/receive_status。
    let mut reds = Vec::new();
    {
        let mut st = conn
            .prepare("SELECT send_id, sender_user_name, session_name, hb_type, receive_status FROM redEnvelopeTable")
            .map_err(|e| warn_err(e, "redEnvelopeTable"))?;
        let iter = st
            .query_map([], |r| {
                Ok(MoneyRedRow {
                    send_id: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    sender_user_name: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    session_name: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    hb_type: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    receive_status: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                })
            })
            .map_err(|e| warn_err(e, "redEnvelopeTable"))?;
        for row in iter.flatten() {
            reds.push(row);
        }
    }
    // groupPayTable: 冷 drain 列 bill_no/session_name/message_create_time。
    let mut groups = Vec::new();
    {
        let mut st = conn
            .prepare("SELECT bill_no, session_name, message_create_time FROM groupPayTable")
            .map_err(|e| warn_err(e, "groupPayTable"))?;
        let iter = st
            .query_map([], |r| {
                Ok(MoneyGroupRow {
                    bill_no: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    session_name: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    message_create_time: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                })
            })
            .map_err(|e| warn_err(e, "groupPayTable"))?;
        for row in iter.flatten() {
            groups.push(row);
        }
    }
    Ok(MoneyBase {
        transfers,
        reds,
        groups,
    })
}

/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_favorites(
    favorite_db: &Path,
    key: &MasterKey,
    q: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFavorite>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(favorite_db, key)?;
    query_hot_favorites(&conn, favorite_db, q, limit, offset)
}

/// [`read_hot_favorites`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。契约同 [`query_hot_contacts`]。
fn query_hot_favorites(
    conn: &Connection,
    favorite_db: &Path,
    q: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFavorite>, bool, Option<usize>, usize), CipherError> {
    // 列与 source/account.rs 的 drain_favorites 同源。**content_len 必须 CAST AS BLOB** ——
    // 裸 LENGTH 按字符算, UTF-8 汉字低估 3 倍 (冷查侧有专门测试锁这条)。`type` 是 SQL 保留字 → 加引号。
    const F_COLS: &str = "server_id, \"type\" AS fav_type, update_time, fromusr AS from_user, \
         realchatname AS real_chat_name, LENGTH(CAST(content AS BLOB)) AS content_len";
    // q 过滤同冷查 favorites_query 口径: from_user / real_chat_name 两列子串。
    let where_sql = if q.is_some() {
        "WHERE (fromusr LIKE '%'||?1||'%' OR realchatname LIKE '%'||?1||'%')"
    } else {
        ""
    };
    let total: Option<usize> = {
        let csql = format!("SELECT count(*) FROM fav_db_item {where_sql}");
        let r = q.map_or_else(
            || conn.query_row(&csql, [], |r| r.get::<_, i64>(0)),
            |s| conn.query_row(&csql, [s], |r| r.get::<_, i64>(0)),
        );
        r.ok().and_then(|n| usize::try_from(n).ok())
    };
    // has_more 走 limit+1 哨兵。
    //
    // **排序必须和冷查同键** —— 我原先写的是 `ORDER BY local_id DESC`, 注释还理直气壮地写着
    // "local_id 是该表主键(唯一) → 全序稳定, OFFSET 翻页不重不漏"。**稳定 ≠ 对等**: 冷查排的是
    // `update_time DESC`, 于是同一批数据两边顺序**完全不同** —— 真库全量对拍第 2 行就分歧
    // (热=(330,1779354083) 冷=(329,1779354334))。
    // 这正是 R16 硬约束④(接一条 = 冷热两侧都得对等且都得稳)存在的理由, 而 favorites 是我第 2 条接的、
    // 那时还没总结出这条, 就漏了。
    // 主键取 update_time(同冷查), 次键 local_id(源表主键 → 唯一 → 全序确定; **L1 favorite 表也有这一列**,
    // 故冷查那边能排同一个键)。
    let probe = limit.saturating_add(1);
    let sql = format!(
        "SELECT {F_COLS} FROM fav_db_item {where_sql} \
         ORDER BY update_time DESC, local_id DESC LIMIT {probe} OFFSET {offset}"
    );
    let mut st = conn.prepare(&sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 favorite prepare 失败");
        CipherError::decrypt_failed(b"", Some(favorite_db))
    })?;
    let mut rows_iter = if let Some(s) = q { st.query([s]) } else { st.query([]) }.map_err(|e| {
        tracing::warn!(error = %e, "热查 favorite query 失败");
        CipherError::decrypt_failed(b"", Some(favorite_db))
    })?;
    let mut rows: Vec<QueriedFavorite> = Vec::new();
    let mut dropped = 0usize;
    let mut has_more = false;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                // 审 P1-2: 判哨兵必须 **+dropped** —— 丢行会把哨兵行当数据行吃掉 → has_more 少报 →
                // 消费方停止翻页 = **静默藏数据**。模板 query_hot_sessions 是 `.saturating_add(dropped)`,
                // 我抄漏了这一项 (contacts/favorites/friend_requests 三处同错, 且模板还在往后 8 条扩散)。
                if rows.len().saturating_add(dropped) >= limit {
                    has_more = true; // 哨兵行: 只探不映射
                    break;
                }
                let parsed = (|| -> rusqlite::Result<QueriedFavorite> {
                    Ok(QueriedFavorite {
                        server_id: row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                        fav_type: row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                        update_time: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                        from_user: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                        // **走 ingest 同一个 `non_empty` 规矩**: 源库 realchatname 空值有时是 NULL、
                        // 有时是空串 ''; ETL(assemble_favorite)一律归一成 None 落 L1 的可空列 → 冷查出
                        // null。热查若照透传, 空串就出 ""、NULL 出 null —— 同一行冷热不一样。
                        // 真库全量对拍逮到 **96 处**(全是源库存空串那种), 单测夹具照不出(那列都填了非空值)。
                        real_chat_name: crate::decoder::non_empty(&row.get::<_, Option<String>>(4)?),
                        content_len: row.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    })
                })();
                match parsed {
                    Ok(f) => rows.push(f),
                    Err(e) => {
                        tracing::warn!(error = %e, "热查 favorite 行映射失败, 跳过该行");
                        dropped += 1;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                // 游标中断 (同 contacts/message 路, 审 P2-7): 剩余行全没 → 保守置 has_more, 不谎报"到底了"。
                tracing::warn!(error = %e, "热查 favorite 游标中断, 剩余行未读");
                dropped += 1;
                has_more = true;
                break;
            }
        }
    }
    Ok((rows, has_more, total, dropped))
}

/// **R16-1**: 热查自定义表情 —— 直读加密 `emoticon.db` 的 `kNonStoreEmoticonTable`, 输出与冷查
/// 引擎 `CMD_EMOTICONS` 的 5 键对齐(零解码)。auth 后即用, 不建 L1。
///
/// **本条是引擎路径热查的第一条**(前四条冷查是手写 `*_query`, 本条冷查走 `emit_engine_query`)。
/// 列映射照 ETL `drain_emoticons`: 源库 `type` → 输出 `emoticon_type`(改名), 其余同名。
/// 排序 `md5 DESC` 与冷查引擎**同键**(冷查侧也从 `rowid DESC` 改成了 `md5 DESC`, 见硬约束④)。
/// 冷查引擎无 `-q` 过滤 → 热查也不加。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_emoticons(
    emoticon_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedEmoticon>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(emoticon_db, key)?;
    query_hot_emoticons(&conn, emoticon_db, limit, offset)
}

/// [`read_hot_emoticons`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。契约同 [`query_hot_favorites`]。
fn query_hot_emoticons(
    conn: &Connection,
    emoticon_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedEmoticon>, bool, Option<usize>, usize), CipherError> {
    // 列与 source/account.rs 的 drain_emoticons 同源。`type` 是 SQL 保留字 + ETL 改名 → `"type" AS emoticon_type`。
    const E_COLS: &str = "caption, md5, \"type\" AS emoticon_type, product_id, cdn_url";
    // 审 P3 同判据: md5 非 schema-unique → 补 max-rowid 去重对齐冷查 emoticon_anchor(md5) INSERT OR REPLACE
    // (每 md5 留 max rowid)。**且 `md5 != ''`**: 冷查 pipeline.rs:1196 `if row.md5.is_empty()` 跳空 md5 行,
    // avatars/biz 兄弟热查都带了空键过滤(username/user_id != ''), 唯 emoticon 漏 → 独立审 P3-1: 空串 md5
    // 冷全跳、热 dedup 留 1 行 → 热多一行。补齐 `md5 != ''` 完全对称(NULL md5 dedup 子查询已排除)。
    const E_WHERE: &str = "WHERE md5 IS NOT NULL AND md5 != '' \
         AND rowid = (SELECT MAX(rowid) FROM kNonStoreEmoticonTable e2 WHERE e2.md5 = kNonStoreEmoticonTable.md5)";
    let total: Option<usize> = conn
        .query_row(
            &format!("SELECT count(*) FROM kNonStoreEmoticonTable {E_WHERE}"),
            [],
            |r| r.get::<_, i64>(0),
        )
        .ok()
        .and_then(|n| usize::try_from(n).ok());
    // md5 DESC 同冷查引擎 (硬约束④); md5 去重后每值一行 → 全序确定。
    let probe = limit.saturating_add(1); // limit+1 哨兵 → has_more 精确
    let sql = format!(
        "SELECT {E_COLS} FROM kNonStoreEmoticonTable {E_WHERE} ORDER BY md5 DESC LIMIT {probe} OFFSET {offset}"
    );
    let mut st = conn.prepare(&sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 emoticon prepare 失败");
        CipherError::decrypt_failed(b"", Some(emoticon_db))
    })?;
    let mut rows_iter = st.query([]).map_err(|e| {
        tracing::warn!(error = %e, "热查 emoticon query 失败");
        CipherError::decrypt_failed(b"", Some(emoticon_db))
    })?;
    let mut rows: Vec<QueriedEmoticon> = Vec::new();
    let mut dropped = 0usize;
    let mut has_more = false;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                // 判哨兵 **+dropped**(审 P1-2: 丢行会把哨兵当数据行吃掉 → has_more 少报 → 静默藏数据)。
                if rows.len().saturating_add(dropped) >= limit {
                    has_more = true;
                    break;
                }
                let parsed = (|| -> rusqlite::Result<QueriedEmoticon> {
                    Ok(QueriedEmoticon {
                        // caption/md5/product_id/cdn_url 在 L1 都是 NOT NULL, ETL 无 non_empty 归一
                        // (drain_emoticons 直取) → 热查照透传, 空串保留(硬约束⑤: 判据是 L1 是否 nullable)。
                        caption: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                        md5: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        emoticon_type: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                        product_id: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                        cdn_url: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    })
                })();
                match parsed {
                    Ok(e) => rows.push(e),
                    Err(e) => {
                        tracing::warn!(error = %e, "热查 emoticon 行映射失败, 跳过该行");
                        dropped += 1;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "热查 emoticon 游标中断, 剩余行未读");
                dropped += 1;
                has_more = true; // 审 P2-7: 不谎报"到底了"
                break;
            }
        }
    }
    Ok((rows, has_more, total, dropped))
}

/// **R16-1**: 热查头像 —— 直读加密 `head_image.db` 的 `head_image` 表, 输出与冷查引擎 `CMD_AVATARS` 的
/// 3 键对齐(不出头像 BLOB 本体)。SQL 分页(无 proto, 同 emoticons; 不同于 members/chatrooms 的全扫)。
///
/// # Errors
/// 解密 / 查询失败 → 携 [`CipherError`] 上抛。
pub fn read_hot_avatars(
    head_image_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedAvatar>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(head_image_db, key)?;
    query_hot_avatars(&conn, head_image_db, limit, offset)
}

/// [`read_hot_avatars`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。契约同 [`query_hot_emoticons`]。
fn query_hot_avatars(
    conn: &Connection,
    head_image_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedAvatar>, bool, Option<usize>, usize), CipherError> {
    // 列同 source/account.rs 的 drain_avatars。**WHERE username != '' 且非 NULL**: 冷查 pipeline 跳空
    // username 行(身份缺失) → 热查同口径, 否则热比冷多行。count 也带同谓词, total 才对得上。
    // 审 P3(avatars 独立审): username 非 schema-unique → 补 max-rowid 去重对齐冷查 avatar_anchor(username)
    // INSERT OR REPLACE(每 username 留 max rowid), 否则源库若有 dup username 热多行/冷一行分叉(同 chatrooms P2-1)。
    const A_WHERE: &str = "WHERE username IS NOT NULL AND username != '' \
         AND rowid = (SELECT MAX(rowid) FROM head_image h2 WHERE h2.username = head_image.username)";
    let total: Option<usize> = conn
        .query_row(&format!("SELECT count(*) FROM head_image {A_WHERE}"), [], |r| {
            r.get::<_, i64>(0)
        })
        .ok()
        .and_then(|n| usize::try_from(n).ok());
    // update_time DESC 同冷查引擎(硬约束④)+ 次键 username, md5 补全序(update_time 并列很常见, 单键翻页不稳;
    // rowid 冷热是两库不能用作对齐次键, username+md5 两皮都可访问)。
    let probe = limit.saturating_add(1); // limit+1 哨兵 → has_more 精确
    let sql = format!(
        "SELECT username, md5, update_time FROM head_image {A_WHERE} \
         ORDER BY update_time DESC, username, md5 LIMIT {probe} OFFSET {offset}"
    );
    let mut st = conn.prepare(&sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 avatar prepare 失败");
        CipherError::decrypt_failed(b"", Some(head_image_db))
    })?;
    let mut rows_iter = st.query([]).map_err(|e| {
        tracing::warn!(error = %e, "热查 avatar query 失败");
        CipherError::decrypt_failed(b"", Some(head_image_db))
    })?;
    let mut rows: Vec<QueriedAvatar> = Vec::new();
    let mut dropped = 0usize;
    let mut has_more = false;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                // 哨兵判 **+dropped**(同 emoticon: 丢行会把哨兵当数据吃掉 → has_more 少报)。
                if rows.len().saturating_add(dropped) >= limit {
                    has_more = true;
                    break;
                }
                let parsed = (|| -> rusqlite::Result<QueriedAvatar> {
                    Ok(QueriedAvatar {
                        // username/md5 在 L1 NOT NULL 直取(空 username 已被 WHERE 滤), update_time 缺→0(同 drain)。
                        username: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                        md5: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        update_time: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    })
                })();
                match parsed {
                    Ok(a) => rows.push(a),
                    Err(e) => {
                        tracing::warn!(error = %e, "热查 avatar 行映射失败, 跳过该行");
                        dropped += 1;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "热查 avatar 游标中断, 剩余行未读");
                dropped += 1;
                has_more = true; // 不谎报"到底了"
                break;
            }
        }
    }
    Ok((rows, has_more, total, dropped))
}

/// **R16-1**: 热查企微联系人 —— 直读加密 `bizchat.db` 的 `user_info` 表, 3 键对齐冷查引擎
/// `CMD_BIZ_CONTACTS`。SQL 分页(无 proto, 同 emoticons/avatars)。
///
/// # Errors
/// 解密 / 查询失败 → 携 [`CipherError`] 上抛。
pub fn read_hot_biz_contacts(
    bizchat_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedBizContact>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(bizchat_db, key)?;
    query_hot_biz_contacts(&conn, bizchat_db, limit, offset)
}

/// [`read_hot_biz_contacts`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。契约同 [`query_hot_avatars`]。
fn query_hot_biz_contacts(
    conn: &Connection,
    bizchat_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedBizContact>, bool, Option<usize>, usize), CipherError> {
    // 列同 source/account.rs 的 drain_bizchat_users。**WHERE user_id != '' 且非 NULL**: 冷查 pipeline 跳空
    // user_id 行(身份/anchor 缺失, pipeline.rs:1378) → 热查同口径, 否则热比冷多行。count 也带同谓词。
    // 审 P3 同判据: user_id 非 schema-unique → 补 max-rowid 去重对齐冷查 bizchat_anchor(user_id) INSERT OR REPLACE。
    const B_WHERE: &str = "WHERE user_id IS NOT NULL AND user_id != '' \
         AND rowid = (SELECT MAX(rowid) FROM user_info u2 WHERE u2.user_id = user_info.user_id)";
    let total: Option<usize> = conn
        .query_row(&format!("SELECT count(*) FROM user_info {B_WHERE}"), [], |r| {
            r.get::<_, i64>(0)
        })
        .ok()
        .and_then(|n| usize::try_from(n).ok());
    // user_name 同冷查引擎(硬约束④)+ 次键 user_id(user_name 可重名不唯一, user_id 是身份唯一; rowid 冷热
    // 两库不能对齐)补全序。
    let probe = limit.saturating_add(1); // limit+1 哨兵 → has_more 精确
    let sql = format!(
        "SELECT user_name, user_id, brand_user_name FROM user_info {B_WHERE} \
         ORDER BY user_name, user_id LIMIT {probe} OFFSET {offset}"
    );
    let mut st = conn.prepare(&sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 bizchat prepare 失败");
        CipherError::decrypt_failed(b"", Some(bizchat_db))
    })?;
    let mut rows_iter = st.query([]).map_err(|e| {
        tracing::warn!(error = %e, "热查 bizchat query 失败");
        CipherError::decrypt_failed(b"", Some(bizchat_db))
    })?;
    let mut rows: Vec<QueriedBizContact> = Vec::new();
    let mut dropped = 0usize;
    let mut has_more = false;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                if rows.len().saturating_add(dropped) >= limit {
                    has_more = true;
                    break;
                }
                let parsed = (|| -> rusqlite::Result<QueriedBizContact> {
                    Ok(QueriedBizContact {
                        // user_name/brand_user_name 空串保留(同冷查 drain 直取 unwrap_or("")); user_id 已被 WHERE 滤非空。
                        user_name: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                        user_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        brand_user_name: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    })
                })();
                match parsed {
                    Ok(b) => rows.push(b),
                    Err(e) => {
                        tracing::warn!(error = %e, "热查 bizchat 行映射失败, 跳过该行");
                        dropped += 1;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "热查 bizchat 游标中断, 剩余行未读");
                dropped += 1;
                has_more = true;
                break;
            }
        }
    }
    Ok((rows, has_more, total, dropped))
}

/// **R16-1**: 热查朋友圈动态 —— 直读加密 `sns.db` 的 `SnsTimeLine` 表, 复用 ETL `assemble_sns` 解 content
/// XML, 输出与冷查 `moments_query` 的 7 键对齐。`wxid` 供 `SnsContext.account_id`。
///
/// # Errors
/// 解密 / 查询失败 → 携 [`CipherError`] 上抛。
pub fn read_hot_moments(
    sns_db: &Path,
    key: &MasterKey,
    wxid: &Wxid,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedMoment>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(sns_db, key)?;
    query_hot_moments(&conn, sns_db, wxid, limit, offset)
}

/// [`read_hot_moments`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
///
/// **本条是全扫**(同 members/chatrooms): `create_time` 藏在 content XML 里、SQL 排不了 → 全取 `SnsTimeLine`
/// 每行 `assemble_sns` 解出 create_time 等 + 内存排序 + 分页。冷查 pipeline 对每行 assemble 无跳行 → 热查
/// 也全取无 WHERE。排序 `create_time DESC, "Sns_<tid>" DESC`(= 冷查 `create_time DESC, source[常量] DESC,
/// source_native_id DESC`, source_native_id=sns_anchor(tid)="Sns_<tid>" **字符串**序, 硬约束④逐位对齐)。
fn query_hot_moments(
    conn: &Connection,
    sns_db: &Path,
    wxid: &Wxid,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedMoment>, bool, Option<usize>, usize), CipherError> {
    use crate::decoder::{assemble_sns, parse_sns_create_time, sns_anchor, SnsContext, SnsRow};
    // content 是 TEXT XML → 直取(非 blob hex); 表名 SnsTimeLine 固定。全表(无 WHERE, 同冷查 pipeline 不跳行)。
    let sql = "SELECT tid, user_name, content FROM SnsTimeLine";
    let mut st = conn.prepare(sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 moments prepare 失败");
        CipherError::decrypt_failed(b"", Some(sns_db))
    })?;
    let rows_iter = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "热查 moments query 失败");
            CipherError::decrypt_failed(b"", Some(sns_db))
        })?;
    // **两阶段(perf)**: ① 全取行, 每行只 `parse_sns_create_time` 轻量取 create_time 定序(跳过贵的
    // count_interactions/媒体解析)→ 排序 → 切本页; ② **只对本页**行做完整 `assemble_sns`。省掉非本页行的
    // 完整解析开销(大账号几万动态尤显)。排序键 create_time 与完整解析出的**同代码路径**, 逐位一致不引入分叉。
    let mut dropped = 0usize;
    // (create_time, anchor 字符串, tid, user_name, content) —— create_time+anchor 排序键, 其余留作整页解析。
    let mut sortable: Vec<(i64, String, i64, String, String)> = Vec::new();
    for row in rows_iter {
        let (tid, user_name, content) = match row {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "热查 moments 丢弃坏行");
                dropped += 1;
                continue;
            }
        };
        let ct = parse_sns_create_time(&content); // 轻量: 只 TimelineObject/createTime, 不数赞评/媒体
        sortable.push((ct, sns_anchor(tid), tid, user_name, content));
    }
    // 排序同冷查: create_time DESC, source_native_id("Sns_<tid>" 字符串) DESC(source 常量省)。
    sortable.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let total = sortable.len();
    // **只对本页**做完整 assemble_sns(复用 ETL 同一个, 含 count_interactions 两 wrapper 坑; 不重写)。
    let page: Vec<QueriedMoment> = sortable
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(_ct, anchor, tid, user_name, content)| {
            let ctx = SnsContext {
                account_id: wxid.clone(),
                source: "sns.db".to_string(),
                source_native_id: anchor,
                ingest_time: 0, // 热查无 ingest 概念; 不进输出(冷查 moments_query 也不出 provenance)。
            };
            let sns = assemble_sns(
                &SnsRow {
                    tid,
                    user_name,
                    content,
                },
                &ctx,
            );
            QueriedMoment {
                author: sns.author,
                author_nickname: sns.author_nickname,
                create_time: sns.create_time,
                content_desc: sns.content_desc,
                media_count: sns.media_count,
                like_count: sns.like_count,
                comment_count: sns.comment_count,
            }
        })
        .collect();
    let has_more = limit > 0 && offset.saturating_add(page.len()) < total;
    Ok((page, has_more, Some(total), dropped))
}

/// 一条热查朋友圈点赞/评论 (**R16-3 子视图**)。**字段与冷查引擎 `CMD_INTERACTIONS`(表 `moment_interaction`)的
/// 5 输出键对齐**: create_time/kind/from_nickname/from_user/content。源同 moments —— `sns.db` 的 `SnsTimeLine`
/// content XML,一动态多互动(赞/评)逐条,复用 ETL 同一 `parse_sns_interactions`(与冷查投影
/// `project_moment_interaction` 同一函数 → 零漂移)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedMomentInteraction {
    /// 互动时刻 unix 秒 (`<create_time>`; 赞常缺 → 0; 冷查 JSON 出原始 i64)。
    pub create_time: i64,
    /// 类别 ("like" / "comment"; 冷查 EnumStr 只作 table, JSON 出原始)。
    pub kind: &'static str,
    /// 互动者缓存昵称 (可空)。
    pub from_nickname: Option<String>,
    /// 互动者 wxid (可空)。
    pub from_user: Option<String>,
    /// 评论文本 (赞 → None)。
    pub content: Option<String>,
}

/// 热查朋友圈点赞评论 (**R16-3 子视图**) —— 直读加密 `sns.db` 的 `SnsTimeLine`,逐动态
/// `parse_sns_interactions` 抽赞/评(**一动态多互动**),与冷查引擎 `CMD_INTERACTIONS` 的 5 键对齐。
///
/// **全扫式**(同 [`read_hot_moments`]):互动时刻/序号在 content XML 里、SQL 排不了 → 全取 `SnsTimeLine`
/// 每行 `parse_sns_interactions` 展开 + 内存排序 + 分页。排序 **(create_time, source_native_id, interaction_seq)
/// DESC** —— create_time/interaction_seq 用**真 i64 数值序**、source_native_id(`"Sns_<tid>"`)字节序,逐位
/// 对齐冷查 `CMD_INTERACTIONS.order_by`(`t.create_time DESC, t.source_native_id DESC, t.interaction_seq DESC`;
/// 后两键 R16-3 补,原单键 create_time 并列很多——赞的 create_time 常为 0)。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_moment_interactions(
    sns_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedMomentInteraction>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(sns_db, key)?;
    query_hot_moment_interactions(&conn, sns_db, limit, offset)
}

/// [`read_hot_moment_interactions`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
fn query_hot_moment_interactions(
    conn: &Connection,
    sns_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedMomentInteraction>, bool, Option<usize>, usize), CipherError> {
    use crate::decoder::{parse_sns_interactions, sns_anchor};
    // content 是 TEXT XML → 直取; 表名 SnsTimeLine 固定。全表(无 WHERE, 同冷查 pipeline 不跳行)。
    let sql = "SELECT tid, content FROM SnsTimeLine";
    let mut st = conn.prepare(sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 moment-interactions prepare 失败");
        CipherError::decrypt_failed(b"", Some(sns_db))
    })?;
    let rows_iter = st
        .query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "热查 moment-interactions query 失败");
            CipherError::decrypt_failed(b"", Some(sns_db))
        })?;
    // 排序键 (create_time i64, anchor String, seq i64) + 输出 (kind, from_nickname, from_user, content)。
    #[allow(clippy::type_complexity)]
    let mut all: Vec<(
        i64,
        String,
        i64,
        &'static str,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = Vec::new();
    let mut dropped = 0usize;
    for row in rows_iter {
        let (tid, content) = match row {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "热查 moment-interactions 丢弃坏行");
                dropped += 1;
                continue;
            }
        };
        let anchor = sns_anchor(tid); // "Sns_<tid>" = 冷查 source_native_id (逐位对齐)
                                      // 一动态多互动: parse_sns_interactions 与冷查投影 project_moment_interaction 同一函数 → 逐条对齐。
        for it in parse_sns_interactions(&content) {
            all.push((
                it.create_time,
                anchor.clone(),
                it.seq,
                it.kind,
                it.from_nickname,
                it.from_user,
                it.content,
            ));
        }
    }
    // 排序同冷查 CMD_INTERACTIONS.order_by: create_time DESC, source_native_id DESC, interaction_seq DESC。
    // 三键均**原生类型比较**(i64 数值 / String 字节) → 与 SQLite typed 列 DESC 逐位一致。
    all.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| b.2.cmp(&a.2)));
    let total = all.len();
    let page: Vec<QueriedMomentInteraction> = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(
            |(create_time, _anchor, _seq, kind, from_nickname, from_user, content)| QueriedMomentInteraction {
                create_time,
                kind,
                from_nickname,
                from_user,
                content,
            },
        )
        .collect();
    let has_more = limit > 0 && offset.saturating_add(page.len()) < total;
    Ok((page, has_more, Some(total), dropped))
}

/// 一条热查朋友圈互动通知 (**R16-3 子视图**)。**字段与冷查引擎 `CMD_SNS_NOTIFY`(表 `sns_notify`)的 5 输出键
/// 对齐**: create_time/notify_type/from_user/from_nickname/content。源 `sns.db` 的 `SnsMessage_tmp3`(直接列, 无
/// XML/proto, 一通知一行), 字段映射同冷查 drain(`account.rs` drain_sns_notifies + `assemble_sns_notify`)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedSnsNotify {
    /// 互动时刻 unix 秒 (`create_time`; 冷查 JSON 出原始 i64)。
    pub create_time: i64,
    /// 通知类型 (`type` 列; 1赞/2评论/4其它; 冷查 Fmt::Raw 出原始 i64)。
    pub notify_type: i64,
    /// 谁互动我 wxid (`from_username`; 明文 ADR-427)。
    pub from_user: String,
    /// 互动者缓存昵称 (`from_nickname`; 可空)。
    pub from_nickname: Option<String>,
    /// 评论文本 (`content`; **空串→None** 同冷查 drain; 赞类通知无正文 → None)。
    pub content: Option<String>,
}

/// 热查朋友圈互动通知 (**R16-3 子视图**) —— 直读加密 `sns.db` 的 `SnsMessage_tmp3`(**一通知一行**, 非一对多),
/// 与冷查引擎 `CMD_SNS_NOTIFY` 的 5 键对齐。
///
/// **全扫式**(同 [`read_hot_moments`]):互动时刻在直接列但热查读的是全表 → 全取 `SnsMessage_tmp3` + 内存排序 +
/// 分页。排序 **(create_time, source_native_id) DESC** —— create_time 真 i64 数值序、source_native_id
/// (`"SnsNotify_<rowid>"`)字节序, 逐位对齐冷查 `CMD_SNS_NOTIFY.order_by`(`t.create_time DESC, t.source_native_id
/// DESC`; 后键 R16-3 补, 原单键 create_time 并列)。rowid 唯一 → (create_time, anchor) 全序确定。**无行过滤**
/// (同冷查 pipeline 全表重扫无 WHERE)。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_sns_notify(
    sns_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedSnsNotify>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(sns_db, key)?;
    query_hot_sns_notify(&conn, sns_db, limit, offset)
}

/// [`read_hot_sns_notify`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
fn query_hot_sns_notify(
    conn: &Connection,
    sns_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedSnsNotify>, bool, Option<usize>, usize), CipherError> {
    use crate::decoder::sns_notify_anchor;
    // `type` 是 SQL 关键字 → 别名 ntype(同冷查 drain account.rs)。全表(无 WHERE, 同冷查 pipeline 不跳行)。
    let sql = "SELECT rowid, create_time, type AS ntype, from_username, from_nickname, content FROM SnsMessage_tmp3";
    let mut st = conn.prepare(sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 sns_notify prepare 失败");
        CipherError::decrypt_failed(b"", Some(sns_db))
    })?;
    let rows_iter = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,                      // rowid
                r.get::<_, Option<i64>>(1)?.unwrap_or(0), // create_time
                r.get::<_, Option<i64>>(2)?.unwrap_or(0), // ntype
                r.get::<_, Option<String>>(3)?,           // from_username (Option; NULL → 下面跳行)
                r.get::<_, Option<String>>(4)?,           // from_nickname
                r.get::<_, Option<String>>(5)?,           // content
            ))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "热查 sns_notify query 失败");
            CipherError::decrypt_failed(b"", Some(sns_db))
        })?;
    // 排序键 (create_time i64, anchor String) + 输出 (notify_type, from_user, from_nickname, content)。
    #[allow(clippy::type_complexity)]
    let mut all: Vec<(i64, String, i64, String, Option<String>, Option<String>)> = Vec::new();
    let mut dropped = 0usize;
    for row in rows_iter {
        let (rowid, create_time, ntype, from_user, from_nickname, content) = match row {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "热查 sns_notify 丢弃坏行");
                dropped += 1;
                continue;
            }
        };
        // codex sns_notify P2: from_username 是互动者身份(冷查 drain 视作**必填**, NULL → RowMap 错整个 ingest)。
        // 热查对 NULL 也 fail-closed —— **跳行 + dropped++**(标 partial), 不静默出 from_user=""(冷查绝不会有的坏行)。
        // 真库 from_username 100% 覆盖 → 实际不可达; 此为对齐冷查语义的防御。
        let Some(from_user) = from_user else {
            tracing::warn!("热查 sns_notify 丢弃 from_username 为空的行 (rowid={rowid})");
            dropped += 1;
            continue;
        };
        let anchor = sns_notify_anchor(rowid); // "SnsNotify_<rowid>" = 冷查 source_native_id (逐位对齐)
                                               // content 空串→None 同冷查 drain(account.rs:1049); 赞类通知无正文。
        let content = content.filter(|s| !s.is_empty());
        all.push((create_time, anchor, ntype, from_user, from_nickname, content));
    }
    // 排序同冷查 CMD_SNS_NOTIFY.order_by: create_time DESC, source_native_id DESC(create_time 数值序 / anchor 字节序)。
    all.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let total = all.len();
    let page: Vec<QueriedSnsNotify> = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(
            |(create_time, _anchor, notify_type, from_user, from_nickname, content)| QueriedSnsNotify {
                create_time,
                notify_type,
                from_user,
                from_nickname,
                content,
            },
        )
        .collect();
    let has_more = limit > 0 && offset.saturating_add(page.len()) < total;
    Ok((page, has_more, Some(total), dropped))
}

/// 一条热查收藏媒体 (**R16-3 子视图**)。**字段与冷查引擎 `CMD_FAV_MEDIA`(表 `favorite_media`)的 6 输出键对齐**:
/// fav_server_id/seq/data_type/media_md5/media_size/data_fmt。源 `favorite.db` 的 `fav_db_item`(笔记 type=18 的
/// content XML), 一收藏多媒体逐条, 复用 ETL 同一 `parse_note_media`(与冷查投影 `project_favorite_media` 同一函数)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedFavoriteMedia {
    /// 所属收藏 server_id (fav_db_item.server_id; 冷查 Fmt::Raw 出原始 i64)。
    pub fav_server_id: i64,
    /// 媒体在笔记内 0 基顺序 (冷查 Fmt::Raw 出原始 i64)。
    pub seq: i64,
    /// 媒体类别 (2图/6文件/8HTML; 冷查 Fmt::EnumI64 只作 table, JSON 出原始 i64)。
    pub data_type: i64,
    /// 媒体内容 md5 (`<fullmd5>`; parse_note_media 只收带 fullmd5 的项 → 恒非空)。
    pub media_md5: String,
    /// 媒体字节数 (`<fullsize>`; 冷查 Fmt::Bytes 只作 table, JSON 出原始 i64)。
    pub media_size: i64,
    /// 数据格式 (`<datafmt>` 去前导点; 可空)。
    pub data_fmt: Option<String>,
}

/// 热查收藏媒体 (**R16-3 子视图**) —— 直读加密 `favorite.db` 的 `fav_db_item`(笔记 type=18 的 content XML),
/// 逐收藏 `parse_note_media` 抽媒体引用(**一收藏多媒体**), 与冷查引擎 `CMD_FAV_MEDIA` 的 6 键对齐。
///
/// **全扫式**(同 [`read_hot_moment_interactions`]/[`read_hot_sns_notify`]; **非** [`read_hot_favorites`] 的
/// SQL-`ORDER BY`+`LIMIT/OFFSET`——那条媒体不解、排序键是直接列 → Claude fav_media P3-3 doc 更正):媒体在
/// content XML 里、SQL 排不了 → 全取 `fav_db_item`(只对 type=18 取 content, 同冷查 drain `CASE WHEN "type"=18`)
/// 每行 `parse_note_media` 展开 + 内存排序 + 分页。排序
/// **(fav_server_id, source_native_id, seq)** —— fav_server_id/seq 真 i64 数值序(fav_server_id DESC, **seq ASC**
/// 同冷查)、source_native_id("Favorite_<local_id>")字节序 DESC。**冷查 `CMD_FAV_MEDIA.order_by` 本单靠
/// (fav_server_id, seq) 不成全序**(未同步收藏 server_id=0 会并列)→ R16-3 补 source_native_id 次键 = favorite_media
/// PK 尾, 与本 3 键对齐。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_favorite_media(
    favorite_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFavoriteMedia>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(favorite_db, key)?;
    query_hot_favorite_media(&conn, favorite_db, limit, offset)
}

/// [`read_hot_favorite_media`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
fn query_hot_favorite_media(
    conn: &Connection,
    favorite_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFavoriteMedia>, bool, Option<usize>, usize), CipherError> {
    use crate::decoder::{favorite_anchor, parse_note_media};
    // note_content 只 type=18 (笔记) 取 content(同冷查 drain account.rs `CASE WHEN "type"=18`); `type` 关键字须引号。
    // 全表(无 WHERE, 同冷查 pipeline 不跳行)。
    let sql = "SELECT server_id, local_id, CASE WHEN \"type\"=18 THEN content ELSE NULL END AS note_content \
               FROM fav_db_item";
    let mut st = conn.prepare(sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 favorite-media prepare 失败");
        CipherError::decrypt_failed(b"", Some(favorite_db))
    })?;
    let rows_iter = st
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<i64>>(0)?.unwrap_or(0), // server_id
                r.get::<_, i64>(1)?,                      // local_id (anchor)
                r.get::<_, Option<String>>(2)?,           // note_content (type!=18 → NULL)
            ))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "热查 favorite-media query 失败");
            CipherError::decrypt_failed(b"", Some(favorite_db))
        })?;
    // 排序键 (fav_server_id i64, anchor String, seq i64) + 输出 (data_type, media_md5, media_size, data_fmt)。
    #[allow(clippy::type_complexity)]
    let mut all: Vec<(i64, String, i64, i64, String, i64, Option<String>)> = Vec::new();
    let mut dropped = 0usize;
    for row in rows_iter {
        let (server_id, local_id, note_content) = match row {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "热查 favorite-media 丢弃坏行");
                dropped += 1;
                continue;
            }
        };
        let anchor = favorite_anchor(local_id); // "Favorite_<local_id>" = 冷查 source_native_id (逐位对齐)
                                                // 一收藏多媒体: parse_note_media 与冷查投影 project_favorite_media 同一函数 → 逐条对齐 (只收带 fullmd5 的项)。
        for m in parse_note_media(note_content.as_deref()) {
            all.push((
                server_id,
                anchor.clone(),
                m.seq,
                m.data_type,
                m.media_md5,
                m.media_size,
                m.data_fmt,
            ));
        }
    }
    // 排序同冷查 CMD_FAV_MEDIA.order_by: fav_server_id DESC, source_native_id DESC, **seq ASC**(seq 无 DESC)。
    all.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| a.2.cmp(&b.2)));
    let total = all.len();
    let page: Vec<QueriedFavoriteMedia> = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(
            |(fav_server_id, _anchor, seq, data_type, media_md5, media_size, data_fmt)| QueriedFavoriteMedia {
                fav_server_id,
                seq,
                data_type,
                media_md5,
                media_size,
                data_fmt,
            },
        )
        .collect();
    let has_more = limit > 0 && offset.saturating_add(page.len()) < total;
    Ok((page, has_more, Some(total), dropped))
}

/// 一条热查收藏标签 (**R16-3 子视图**)。**字段与冷查引擎 `CMD_FAV_TAGS`(表 `favorite_tag`)的 3 输出键对齐**:
/// tag_server_id/fav_server_id/tag_name。源 `favorite.db` 的 `fav_bind_tag_db_item ⋈ fav_tag_db_item`(绑定表
/// LEFT JOIN 标签名表), 一绑定一行, 字段映射同冷查 drain(`account.rs` drain_favorite_tags)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedFavoriteTag {
    /// 标签服务端 id (fav_bind_tag_db_item.tag_server_id)。
    pub tag_server_id: i64,
    /// 所属收藏服务端 id (fav_bind_tag_db_item.fav_server_id)。
    pub fav_server_id: i64,
    /// 标签名 (fav_tag_db_item.name; LEFT JOIN 缺 → **空串**同冷查 drain)。
    pub tag_name: String,
}

/// 热查收藏标签 (**R16-3 子视图**) —— 直读加密 `favorite.db` 的 `fav_bind_tag_db_item LEFT JOIN fav_tag_db_item`
/// (取标签名), 与冷查引擎 `CMD_FAV_TAGS` 的 3 键对齐。
///
/// **全扫式 + 按 anchor 去重**(同 [`read_hot_moment_interactions`] 全载 + resolve 列表 HashMap 去重):冷查 L2
/// `favorite_tag` 按 `source_native_id`(=`favorite_tag_anchor(tag_local_id, fav_local_id)`, **R16-3 后用 local id**)
/// **upsert 去重**(一 (标签,收藏) 对一行) → 热查也须按同 anchor(local)去重; JOIN `ON t.local_id=b.tag_local_id`
/// 精确一名(非 server_id 交叉)→ 每绑定至多一行, local 锚每绑定唯一, 去重实为防御性 no-op。
/// 排序 **(tag_server_id, source_native_id) DESC** —— tag_server_id 真 i64 数值序、source_native_id
/// (`"FavoriteTag_<tag_local>_<fav_local>"`)字节序, 逐位对齐冷查 `CMD_FAV_TAGS.order_by`(`t.tag_server_id DESC,
/// t.source_native_id DESC`; 后键 R16-3 补, 原单键 tag_server_id 并列——一标签贴多收藏)。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_favorite_tags(
    favorite_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFavoriteTag>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(favorite_db, key)?;
    query_hot_favorite_tags(&conn, favorite_db, limit, offset)
}

/// [`read_hot_favorite_tags`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
fn query_hot_favorite_tags(
    conn: &Connection,
    favorite_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedFavoriteTag>, bool, Option<usize>, usize), CipherError> {
    use std::collections::HashMap;

    use crate::decoder::favorite_tag_anchor;
    // LEFT JOIN 同冷查 drain(account.rs drain_favorite_tags): 绑定表取标签名, 缺 → NULL(下面 → 空串)。
    // **JOIN 键 `t.local_id = b.tag_local_id`(R16-3 codex P1 根治)**: 非 server_id —— 未同步标签 server_id=0 按
    // server_id JOIN 会交叉命中所有 server_id=0 标签误标名; local_id 单库唯一 → 精确一名, 每绑定至多一行(无交叉)。
    // **ORDER BY b.rowid**: 同冷 drain, 让去重按 rowid 升序保后写(与冷 upsert 一致; local 锚唯一时其实每 anchor 一行,
    // 去重是防御性 no-op)。全表无 WHERE。取 tag_local_id/fav_local_id **构造锚**, tag_server_id/fav_server_id **只出**。
    let sql = "SELECT b.tag_server_id, b.fav_server_id, t.name AS tag_name, b.tag_local_id, b.fav_local_id \
               FROM fav_bind_tag_db_item b LEFT JOIN fav_tag_db_item t ON t.local_id = b.tag_local_id \
               ORDER BY b.rowid";
    let mut st = conn.prepare(sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 favorite-tags prepare 失败");
        CipherError::decrypt_failed(b"", Some(favorite_db))
    })?;
    let rows_iter = st
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<i64>>(0)?.unwrap_or(0),           // tag_server_id (只出)
                r.get::<_, Option<i64>>(1)?.unwrap_or(0),           // fav_server_id (只出)
                r.get::<_, Option<String>>(2)?.unwrap_or_default(), // tag_name (LEFT JOIN 缺 → 空串, 同冷查)
                r.get::<_, Option<i64>>(3)?.unwrap_or(0),           // tag_local_id (构造锚)
                r.get::<_, Option<i64>>(4)?.unwrap_or(0),           // fav_local_id (构造锚)
            ))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "热查 favorite-tags query 失败");
            CipherError::decrypt_failed(b"", Some(favorite_db))
        })?;
    // **按 anchor(local id)去重, 保后写**(对齐冷 L2 `INSERT OR REPLACE` upsert): local 锚 `FavoriteTag_<tag_local_id>_
    // <fav_local_id>` 每绑定唯一 → 去重实为防御性 no-op(local JOIN 后每绑定已至多一行); 保后写仍对齐冷 upsert。
    let mut by_anchor: HashMap<String, (i64, i64, String)> = HashMap::new();
    let mut dropped = 0usize;
    for row in rows_iter {
        let (tag_server_id, fav_server_id, tag_name, tag_local_id, fav_local_id) = match row {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "热查 favorite-tags 丢弃坏行");
                dropped += 1;
                continue;
            }
        };
        let anchor = favorite_tag_anchor(tag_local_id, fav_local_id); // "FavoriteTag_<tag_local>_<fav_local>" = 冷 source_native_id
        by_anchor.insert(anchor, (tag_server_id, fav_server_id, tag_name)); // 保后写 (覆盖) 对齐冷 upsert
    }
    // 排序键 (tag_server_id i64, anchor String) —— anchor 唯一 → 全序确定。
    let mut all: Vec<(i64, String, i64, String)> = by_anchor
        .into_iter()
        .map(|(anchor, (tsid, fsid, name))| (tsid, anchor, fsid, name))
        .collect();
    // 排序同冷查 CMD_FAV_TAGS.order_by: tag_server_id DESC, source_native_id DESC(数值序 / 字节序)。
    all.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    let total = all.len();
    let page: Vec<QueriedFavoriteTag> = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(tag_server_id, _anchor, fav_server_id, tag_name)| QueriedFavoriteTag {
            tag_server_id,
            fav_server_id,
            tag_name,
        })
        .collect();
    let has_more = limit > 0 && offset.saturating_add(page.len()) < total;
    Ok((page, has_more, Some(total), dropped))
}

/// **R16-1 降级件**: 热查群成员 —— 直读加密 `contact.db` 的 `chat_room`(取某群那一行, 解 `ext_buffer`
/// protobuf 展开成员), 输出与冷查 `members_query` 的 5 键对齐, 但 `joined_at` 恒 null、只返当前在群成员。
///
/// **本条是"全扫式"**(同 finder): 成员在 proto 里, SQL 筛不出"是不是管理员" → 全取该群成员 → 内存
/// 过滤(`admins_only`)+ 排序(`role, member_wxid` 同冷查)+ 分页。真库单群成员量级(几~几千)可接受。
///
/// `role`/退群/joined_at 的降级语义见 [`QueriedMember`]。**`degraded` 恒 true**(热查群成员本质是快照 +
/// 缺 joined_at) → 皮层据此标 `partial`。
///
/// # Errors
/// [`CipherError`] — 开库/解密 或 查询失败。
pub fn read_hot_members(
    contact_db: &Path,
    key: &MasterKey,
    chatroom: &str,
    admins_only: bool,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedMember>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(contact_db, key)?;
    query_hot_members(&conn, contact_db, chatroom, admins_only, limit, offset)
}

/// [`read_hot_members`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
fn query_hot_members(
    conn: &Connection,
    contact_db: &Path,
    chatroom: &str,
    admins_only: bool,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedMember>, bool, Option<usize>, usize), CipherError> {
    // 取该群那一行: username=群id, owner=群主 wxid, ext_buffer=成员 proto blob。列同 drain_chatrooms。
    // codex 审 P2: **只有 `QueryReturnedNoRows` 才是"群不存在"** → 空结果; 别的 SQL 错(schema 缺 chat_room/
    // ext_buffer、解码失败)必须上抛 —— `.ok()` 会把它们全吞成空群, 让坏库读被当成"空群"(冷查那边会报错,
    // 静默返空反而跟冷查分叉)。
    // codex 审 P2: chat_room.username **非 PK 可重复**(仅数字 id 是 PK)。冷查 ETL 按 chatroom_id
    // INSERT OR REPLACE(drain ORDER BY rowid 顺序处理 → 末个即 max rowid 胜)。故这里 `ORDER BY rowid DESC
    // LIMIT 1` 取 max rowid 那行对齐冷查, 而非 query_row 拿 SQLite 不保证的"第一行"。
    let row = conn.query_row(
        "SELECT owner, hex(coalesce(ext_buffer, x'')) FROM chat_room WHERE username = ?1 \
         ORDER BY rowid DESC LIMIT 1",
        [chatroom],
        |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                hex_to_bytes(&r.get::<_, Option<String>>(1)?.unwrap_or_default()),
            ))
        },
    );
    let (owner, ext_buffer): (Option<String>, Vec<u8>) = match row {
        Ok(v) => v,
        // 群不存在(或已退出/未同步) → 空结果, total=0(同冷查该群无成员)。
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok((Vec::new(), false, Some(0), 0));
        }
        Err(e) => {
            tracing::warn!(error = %e, "热查 members 读 chat_room 失败 (schema 缺/解码坏?)");
            return Err(CipherError::decrypt_failed(b"", Some(contact_db)));
        }
    };
    // 解 proto 展开成员。Invalid → 空; Suspicious(截断) → 用能解出的部分(add 幂等无害, 同 ETL 口径)。
    let members = match parse_roomdata(&ext_buffer) {
        RoomDataParse::Complete(m) | RoomDataParse::Suspicious(m) => m,
        RoomDataParse::Invalid => Vec::new(),
    };
    // 映射 + role 判定(**同 ETL pipeline.rs:1703**: 群主比 owner 列 / admin 看 is_admin / 其余 member)。
    let mut all: Vec<QueriedMember> = members
        .into_iter()
        .map(|m| {
            let role = if owner.as_deref() == Some(m.username.as_str()) {
                "owner"
            } else if m.is_admin {
                "admin"
            } else {
                "member"
            };
            QueriedMember {
                member_wxid: m.username,
                display_name: crate::decoder::non_empty(&m.group_nick),
                role: role.to_string(),
                invited_by: crate::decoder::non_empty(&m.invited_by),
            }
        })
        .filter(|m| !admins_only || m.role != "member") // admins_only: 只留 owner/admin(同冷查 where role!='member')
        .collect();
    // 排序同冷查 members_query: `ORDER BY role, member_wxid`(role 字典序: admin<member<owner)。
    all.sort_by(|a, b| a.role.cmp(&b.role).then_with(|| a.member_wxid.cmp(&b.member_wxid)));
    let total = all.len();
    let page: Vec<QueriedMember> = all.into_iter().skip(offset).take(limit).collect();
    // has_more 精确(全取过)。limit>0 守卫同 finder(limit=0 报 has_more=true 会让 offset+=0 死循环)。
    let has_more = limit > 0 && offset.saturating_add(page.len()) < total;
    let _ = contact_db; // (错误路径已用; 保留形参对齐其它内核签名)
    Ok((page, has_more, Some(total), 0))
}

/// 打开 `contact.db` 解密后查群列表 (**R16-1**; 字段对齐冷查引擎 `CMD_CHATROOMS`)。
///
/// 返 `(本页群, has_more, 全量数 Option, 丢行数)`, 契约同 [`read_hot_members`]。
///
/// # Errors
/// 解密 / 查询失败 → 携 [`CipherError`] 上抛。
pub fn read_hot_chatrooms(
    contact_db: &Path,
    key: &MasterKey,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedChatroom>, bool, Option<usize>, usize), CipherError> {
    let conn = open_decrypted_db_vfs(contact_db, key)?;
    query_hot_chatrooms(&conn, contact_db, limit, offset)
}
/// 热查 chatrooms 的一行原始值: (chatroom_id, owner, member BLOB, 群名, 群公告)。
///
/// 起个名字是因为裸的五元组会被 clippy 判 `type_complexity` —— 而且五个 `Option<String>` 摞在一起
/// 谁也记不住哪个是哪个。
type ChatroomRawRow = (String, Option<String>, Vec<u8>, Option<String>, Option<String>);

/// [`read_hot_chatrooms`] 的纯查询逻辑 (开库/解密剥离 → 可内存库单测)。
///
/// **本条是全扫**(同 finder/members): 排序键 `member_count` 要**逐群解 proto 数成员**才知道, SQL 排不了 →
/// 全取所有群 + 每群解 `ext_buffer` proto 数成员 + 内存排序(`member_count DESC, chatroom_id` 同冷查)+ 分页。
/// 群数量级(几百)全扫无压力。JOIN 群名/公告同冷查 drain SQL(source/account.rs)。
fn query_hot_chatrooms(
    conn: &Connection,
    contact_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedChatroom>, bool, Option<usize>, usize), CipherError> {
    // 同冷查 drain SQL: chat_room LEFT JOIN contact(群名)LEFT JOIN chat_room_info_detail(公告)。
    // 群名在 contact.nick_name(chat_room 表不存群名), 公告在独立 chat_room_info_detail 表。别名 cr/c/cid。
    // codex 审 P2: chat_room.username **非 PK 可重复**(仅数字 id 是 PK)。冷查按 chatroom_id INSERT OR REPLACE
    // 保 max rowid 那行 → 这里 `WHERE cr.rowid = (SELECT MAX(rowid) ... 同 username)` 每群只取 max rowid 行,
    // 否则重复 username 会让热查同 chatroom_id 出多行(冷查只一行)→ total/翻页分叉、同群重复出现。
    let sql = "SELECT cr.username AS chatroom_id, cr.owner AS owner, \
               hex(coalesce(cr.ext_buffer, x'')) AS ext_hex, \
               c.nick_name AS room_name, cid.announcement_ AS announcement \
               FROM chat_room cr LEFT JOIN contact c ON c.username = cr.username \
               LEFT JOIN chat_room_info_detail cid ON cid.username_ = cr.username \
               WHERE cr.rowid = (SELECT MAX(cr2.rowid) FROM chat_room cr2 WHERE cr2.username = cr.username)";
    let mut st = conn.prepare(sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 chatrooms prepare 失败");
        CipherError::decrypt_failed(b"", Some(contact_db))
    })?;
    let rows_iter = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                hex_to_bytes(&r.get::<_, Option<String>>(2)?.unwrap_or_default()),
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|e| {
            tracing::warn!(error = %e, "热查 chatrooms query 失败");
            CipherError::decrypt_failed(b"", Some(contact_db))
        })?;
    // 逐行收集 + **数丢弃行**(codex 审 P2 同判据: 别静默吞坏行 → 冷查 collect_ok 会计 dropped, 热查也计;
    // chatroom_id 是 PK 实际不会 NULL → 常态 dropped=0, 但坏库/类型漂移时诚实报数, 不静默藏群)。
    let mut raw: Vec<ChatroomRawRow> = Vec::new();
    let mut dropped = 0usize;
    for row in rows_iter {
        match row {
            Ok(v) => raw.push(v),
            Err(e) => {
                tracing::warn!(error = %e, "热查 chatrooms 丢弃坏行");
                dropped += 1;
            }
        }
    }
    let mut all: Vec<QueriedChatroom> = raw
        .into_iter()
        .map(|(chatroom_id, owner, ext_buffer, room_name, announcement)| {
            // member_count 从 proto 数成员(同 members); Invalid → 0(同 pipeline.rs:1644)。
            let member_count = match parse_roomdata(&ext_buffer) {
                RoomDataParse::Complete(m) | RoomDataParse::Suspicious(m) => m.len() as i64,
                RoomDataParse::Invalid => 0,
            };
            QueriedChatroom {
                chatroom_id,
                // 空/缺 → "" (同冷查 assemble_chatroom 的 unwrap_or_default; **不** non_empty)。
                chatroom_name: room_name.unwrap_or_default(),
                owner_wxid: crate::decoder::non_empty(&owner),
                member_count,
                announcement: crate::decoder::non_empty(&announcement),
            }
        })
        .collect();
    // 排序同冷查 CMD_CHATROOMS(member_count DESC)+ 次键 chatroom_id 补全序(冷查这次一并补, 防并列翻页不稳)。
    all.sort_by(|a, b| {
        b.member_count
            .cmp(&a.member_count)
            .then_with(|| a.chatroom_id.cmp(&b.chatroom_id))
    });
    let total = all.len();
    let page: Vec<QueriedChatroom> = all.into_iter().skip(offset).take(limit).collect();
    let has_more = limit > 0 && offset.saturating_add(page.len()) < total;
    let _ = contact_db;
    Ok((page, has_more, Some(total), dropped))
}

/// [`read_hot_contacts`] 的纯查询逻辑 (开库/解密剥离到调用方 → 可拿内存库单测)。
/// 返 `(本页联系人, has_more, 全量数 Option, 丢行数)`, 契约同 [`query_hot_sessions`]。
fn query_hot_contacts(
    conn: &Connection,
    contact_db: &Path,
    q: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedContact>, bool, Option<usize>, usize), CipherError> {
    // 5 列 = 冷查 contacts_query 的输出集 (源库直取, 无派生)。两表列结构全同 22 列。
    // (放在函数体最前面: clippy 的 items_after_statements 不许 const 夹在语句中间。)
    const C_COLS: &str = "username, nick_name, remark, alias, local_type";

    // stranger 表可能不存在 (老库/未启用) → 探测一次, 缺则只查 contact (宽松, 同冷查对缺表的容忍)。
    let has_stranger = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='stranger' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .is_ok();
    // q 子串过滤: 与冷查 contacts_query 同口径 (username/nick_name/remark/alias 四列 LIKE)。
    // 参数化 ?1 避免注入; 无 q 则恒真。
    let where_sql = if q.is_some() {
        "WHERE (username LIKE '%'||?1||'%' OR nick_name LIKE '%'||?1||'%' \
         OR remark LIKE '%'||?1||'%' OR alias LIKE '%'||?1||'%')"
    } else {
        ""
    };
    // UNION ALL 而非 UNION: **不去重** —— 同 wxid 真可能两表各一行 (冷查 person 也是两行, 其 PK 含 source),
    // 去重反而与冷查行数不符。
    //
    // **`_src` 判别列 (对抗审 P2-3)**: 次键必须**唯一**才能构成全序。原先拿 local_type 当次键 —— 它是普通
    // 数据列, 同 wxid 在两表里 local_type 相同时 `(username, local_type)` 就打平了, SQLite 对并列行顺序
    // 不保证 → OFFSET 翻页重复/遗漏。冷查用的是 `source`(person PK 成员, 两行必不同值), 且那边注释专门
    // 记着为什么次键必须唯一("单用 username 当 tiebreaker → 跨页边界严格 > 把并列 username 整片跳过 →
    // 静默丢联系人, 复现 anchor 688→98")。故这里造 0/1 判别列: 既恢复全序, 排序又正好对上冷查的 source
    // 升序 (contact.db 在 contact.db|stranger 前) —— 连"冷热并列内顺序相反"(审 P3-1) 一并对齐。
    let from_sql = if has_stranger {
        format!(
            "SELECT {C_COLS}, 0 AS _src FROM contact {where_sql} \
             UNION ALL SELECT {C_COLS}, 1 AS _src FROM stranger {where_sql}"
        )
    } else {
        format!("SELECT {C_COLS}, 0 AS _src FROM contact {where_sql}")
    };
    let total: Option<usize> = {
        let csql = format!("SELECT count(*) FROM ({from_sql})");
        let r = q.map_or_else(
            || conn.query_row(&csql, [], |r| r.get::<_, i64>(0)),
            |s| conn.query_row(&csql, [s], |r| r.get::<_, i64>(0)),
        );
        r.ok().and_then(|n| usize::try_from(n).ok())
    };
    // has_more 走 limit+1 哨兵 (同 query_hot_sessions, 精确且不依赖 COUNT)。
    // 排序 `(username, _src)`: username 只在**单表内**唯一, UNION ALL 后同 wxid 可两行 → 必须补个
    // **唯一**次键才成全序 (审 P2-3: 原用 local_type 是普通列, 两表相同就打平 → 翻页重复/漏)。
    let probe = limit.saturating_add(1);
    let sql = format!("SELECT * FROM ({from_sql}) ORDER BY username ASC, _src ASC LIMIT {probe} OFFSET {offset}");
    let mut st = conn.prepare(&sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 contact prepare 失败");
        CipherError::decrypt_failed(b"", Some(contact_db))
    })?;
    let mut rows_iter = if let Some(s) = q { st.query([s]) } else { st.query([]) }.map_err(|e| {
        tracing::warn!(error = %e, "热查 contact query 失败");
        CipherError::decrypt_failed(b"", Some(contact_db))
    })?;
    let mut rows: Vec<QueriedContact> = Vec::new();
    let mut dropped = 0usize;
    let mut has_more = false;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                // 审 P1-2: 判哨兵必须 **+dropped** —— 丢行会把哨兵行当数据行吃掉 → has_more 少报 →
                // 消费方停止翻页 = **静默藏数据**。模板 query_hot_sessions 是 `.saturating_add(dropped)`,
                // 我抄漏了这一项 (contacts/favorites/friend_requests 三处同错, 且模板还在往后 8 条扩散)。
                if rows.len().saturating_add(dropped) >= limit {
                    has_more = true; // 哨兵行: 只探不映射
                    break;
                }
                let parsed = (|| -> rusqlite::Result<QueriedContact> {
                    Ok(QueriedContact {
                        username: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                        // nick_name: unwrap_or_default 是**对的** —— L1 该列 NOT NULL, ETL 同样是
                        // unwrap_or_default(空串保留)。下面两列则相反, 见 QueriedContact 的字段 doc。
                        nick_name: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        // remark/alias 走 ingest 同一个 `non_empty` 规矩: 空串和 NULL 都归一成 None
                        // (= 未设)。照透传的话, 源库存空串的行冷查出 null 热查出 "" —— 真库对拍逮到 89852 处。
                        remark: crate::decoder::non_empty(&row.get::<_, Option<String>>(2)?),
                        alias: crate::decoder::non_empty(&row.get::<_, Option<String>>(3)?),
                        local_type: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    })
                })();
                match parsed {
                    Ok(c) => rows.push(c),
                    Err(e) => {
                        // 行映射失败非静默丢 (同 message/session 路): warn + 计数 → 皮层并入 partial。
                        tracing::warn!(error = %e, "热查 contact 行映射失败, 跳过该行");
                        dropped += 1;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                // 游标中断 (同 R16-0 审 P2-7): 剩余行全没 —— 这里没有表级计数器, 至少 warn + 当丢行,
                // 且**不**把 has_more 置 false 以免谎报"到底了"(保守: 有中断就当还有)。
                tracing::warn!(error = %e, "热查 contact 游标中断, 剩余行未读");
                dropped += 1;
                has_more = true;
                break;
            }
        }
    }
    Ok((rows, has_more, total, dropped))
}

/// [`read_hot_sessions`] 的纯查询逻辑 (开库/解密剥离到调用方 → 可拿内存 `SessionTable` 单测 has_more/丢行)。返
/// `(本页会话, has_more, 全量数 Option, 丢行数)`。
///
/// - **全量数**: 廉价 COUNT, 失败返 `None` (**第6轮复审#2**: 不 `unwrap_or(0)` 伪装 0; 皮层据 `None` 标 total_unknown
///   + partial)。仅供 `summary.total_sessions` **显示** —— has_more **不再依赖它**, 故 COUNT 失败不损分页精度。
/// - **has_more**: **第6轮再审(第三方 P3)** 走 **`limit+1` 哨兵行** —— 多取 1 行探边, 第 `limit+1` 行存在即"还有下一
///   页", **精确且不依赖 COUNT** (修原 `None` 分支 `data.len()+dropped>=limit` 在"满末页"多报一次空页, 违 §6 恒精确)。
///   哨兵行只探不映射/不计丢 → has_more 由**原始取到的行数**定、不受丢行影响。
///
/// # Errors
/// [`CipherError`] — prepare/query 失败 (记 warn! 保诊断; `rusqlite::Error` 只列名/类型无 PII)。
fn query_hot_sessions(
    conn: &Connection,
    session_db: &Path,
    limit: usize,
    offset: usize,
) -> Result<(Vec<QueriedSession>, bool, Option<usize>, usize), CipherError> {
    let total: Option<usize> = conn
        .query_row("SELECT count(*) FROM SessionTable", [], |r| r.get::<_, i64>(0))
        .ok()
        .and_then(|n| usize::try_from(n).ok());
    // 表名固定, probe/offset 数值内联无注入 (usize, 皮层已夹上界)。按 sort_timestamp 倒序 = 微信会话列表顺序 (最近在
    // 前)。复审#4: OFFSET → limit 外会话可翻页够到。**第4轮**: 补 `username` 次排序键 (sort_timestamp 真库有并列值,
    // 单键排序 SQLite 对并列行顺序不保证稳定, OFFSET 翻页会重复/漏; username 是 PK 唯一 → 全序确定翻页稳定)。
    let probe = limit.saturating_add(1); // 第三方 P3: 多取 1 行当哨兵
    let sql = format!(
        "SELECT {SESSION_COLS} FROM SessionTable ORDER BY sort_timestamp DESC, username DESC LIMIT {probe} OFFSET {offset}"
    );
    let mut st = conn.prepare(&sql).map_err(|e| {
        tracing::warn!(error = %e, "热查 session prepare 失败");
        CipherError::decrypt_failed(b"", Some(session_db))
    })?;
    let mut rows_iter = st.query([]).map_err(|e| {
        // 第6轮三审(Claude nit): query 失败也 warn (对齐 prepare 臂 + 本函数文档承诺)。rusqlite::Error 无 PII。
        tracing::warn!(error = %e, "热查 session query 失败");
        CipherError::decrypt_failed(b"", Some(session_db))
    })?;
    let mut rows: Vec<QueriedSession> = Vec::new();
    let mut dropped = 0usize;
    let mut has_more = false;
    loop {
        match rows_iter.next() {
            Ok(Some(row)) => {
                if rows.len().saturating_add(dropped) == limit {
                    // 已消费 limit 个原始行, 这是第 limit+1 行哨兵 → 还有下一页 (不映射/不计丢, 只探边)。
                    has_more = true;
                    break;
                }
                match read_session_row(row) {
                    Ok(s) => rows.push(s),
                    // 极罕见 (username 非空 PK / 整数列存整数; 真跑 15350 行 0 丢)。**第5轮复审(P2)**: 非静默 —— 记
                    // warn + **计数** (原只 warn, AI 会以为整页完整), 皮层据此标 partial。rusqlite::Error 无 PII。
                    Err(e) => {
                        tracing::warn!(error = %e, "热查 session 行映射失败, 跳过");
                        dropped += 1;
                    }
                }
            }
            Ok(None) => break, // 取尽 (< probe 行) → 到底, has_more 保持 false
            // 行推进(step)失败 = 游标级错 (中途损坏), 非单行列解码失败 → **硬错冒泡** (同 prepare/query, 文档一致):
            // 游标已坏无法可靠续读, fail-loud 比返半页更安全。第6轮三审(Claude nit): 补 warn 保诊断。rusqlite::Error 无 PII。
            Err(e) => {
                tracing::warn!(error = %e, "热查 session 行推进失败");
                return Err(CipherError::decrypt_failed(b"", Some(session_db)));
            }
        }
    }
    Ok((rows, has_more, total, dropped))
}

/// 分片指纹: (主库 mtime_ns, 主库 size, **WAL mtime_ns**, WAL size)。含 WAL 是关键 —— **新建群的新表
/// WeChat 先写 WAL 还没刷主库**, 只看主库会漏; 任一变化 → 重扫该分片。
type ShardStamp = (u64, u64, u64, u64);

/// 持久化定位表格式版本。**第5轮复审(codex P2)**: 旧版逻辑会给"部分损坏 (Name2Id/表名丢行) 却能开"的分片
/// **也存健康 stamp** → 升级后新二进制载到旧 locator, 那分片 stamp 命中被跳过重扫、`degraded` 永远 0、静默漏会话。
/// 版本对不上 (含旧格式无 version=0) → **弃整个 locator、强制全重扫一次**, 让新逻辑重判 degraded。改扫描/缓存
/// 语义时 bump 此值即让所有旧 locator 作废。
/// 定位表磁盘格式版本。**版本不符 → 整份弃掉重扫**(见 `build`)。
///
/// 语义变化(不只是结构变化)也要 bump —— 例如"某类表以前会被静默丢、现在要计降级",
/// 不 bump 的话已有用户的旧定位表会照旧 cache-hit, 修复对他们整个绕过。
/// 测试造定位表夹具时**按这个常量写**, 别硬编码数字。
pub const LOCATOR_VERSION: u32 = 3;

/// 持久化定位表文件内容 (JSON)。只含会话标识/表名/分片指纹, **不含正文/key**。
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedLocator {
    /// 格式版本 (见 [`LOCATOR_VERSION`]); 旧文件无此字段 → `#[serde(default)]` 得 0 → 版本不符被弃。
    #[serde(default)]
    version: u32,
    /// 分片文件名 → 指纹 (主库+WAL, 判该分片是否变了; 变了才重扫)。
    stamps: HashMap<String, ShardStamp>,
    /// conv_id → [(分片文件名, `Msg_<md5>` 表名)] (一会话可跨多分片)。
    locator: HashMap<String, Vec<(String, String)>>,
}

/// 一条热查联系人 (**R16-1 小库快档**)。**字段与冷查 `contacts_query` 的输出对齐** (5 键明文子集;
/// 冷查那 5 列本身就是源库 `contact` 表的直取列, 无派生、无解码)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueriedContact {
    /// 微信 id (`contact.username`; 单表内唯一 = PK)。
    pub username: String,
    /// 昵称。**`String` 是对的, 别跟下面两个搞混** —— L1 `person.nick_name` 是 `NOT NULL`, 而
    /// ETL(`assemble_contact`) 对它是 `unwrap_or_default()`(**空串保留, 不归一**)。
    pub nick_name: String,
    /// 备注 (自己给对方起的名)。**必须 `Option`**: L1 `person.remark` **可空**, 且 ETL 用 `non_empty`
    /// 把**空串归一成 NULL**(= 未设备注) → 冷查出 `null`。热查若 `String` + `unwrap_or_default()`,
    /// 同一行冷 `null` / 热 `""`。真库全量对拍逮到 —— 连同 `alias` 共 **89852 处**。
    pub remark: Option<String>,
    /// 微信号 (对方自定义 id)。**必须 `Option`**, 理由同 `remark`。
    pub alias: Option<String>,
    /// 联系人类型码 (`contact.local_type`)。
    pub local_type: i64,
}

/// 一张表最多留几个"被跳过的行号"。判据只用第 0 个, 其余纯粹为了告警里能报给用户。
pub const SKIPPED_IDS_CAP: usize = 8;

/// 一张表里**被跳过的行**(见 [`ScanStats::skipped_row_ids`])。
///
/// ⚠️ 这里只留**高于调用方给的下限**的那几个, 而且是最小的几个。为什么这么设计:
///
/// 判据要回答的只有一句 —— "有没有某个被跳过的行落在 `(旧位置, 新位置]` 里"。它等价于
/// `min{s : s > 旧位置} <= 新位置`, 也就是说**从扫描期带出去的信息, 一个行号就够了**。
/// 这不是近似, 是恒等。
///
/// 上一版把整个集合原样搬给调用方(64 上限 + 溢出区间 + 区间求交), 是因为记录点这一层
/// **不知道旧位置**。而那一层不知道, 不等于拿不到 —— 调用方本来就有, 传下来即可。
///
/// 这么一改, 之前栽过的三条全部**构造上不可能**(独立复审第二十三轮设计层复盘):
/// - "取最小被老坏行盖住": 集合在记录时就按下限过滤过了, 压根进不来;
/// - "撑爆上限 → 65 个早报过的行立起永久假告警": 同上, 那些行进不来;
/// - "溢出只有下界没上界 → 坏行全在新位置上面也假报": 判据天然带上界(`<= 新位置`)。
///
/// 上限也从"会改变语义的阈值"降级成**纯粹的展示预算**。这一条可以证:
///
/// 记下来的是 `R = {s : s > 下限}` 里**最小的 CAP 个`(扫描按行号升序, 所以先遇到的就是最小的)。
/// 判据问的是 `R` 里有没有 `<= 新位置` 的。
/// - `{s : s > 下限}` 里**有**元素 `<= 新位置` ⟹ 它的**最小值**也 `<= 新位置`,
///   而最小值必在 `R` 里 ⟹ 判据答"有"。
/// - `R` 里有元素 `<= 新位置` ⟹ 它本来就 `> 下限` ⟹ 判据答"有"是对的。
///
/// 两边互推, **精确等价** —— 截掉的那些恒不影响结论。
///
/// ⚠️ 但"上限调成几都行"**只对判据的结论成立**(第二十五轮变异全扫点出来的): 这个上限同时还是
/// ① 扫描期每张表 `ids` 的内存上界, ② 水位文件里 `NewHotMark::lost_ids` 的**落盘**上界 ——
/// 而那一项是**跨轮累积**的。调大 = 水位 JSON 无界增长。改它之前把这两件一起想。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkippedRows {
    /// **高于下限**的被跳过行号里, 最小的那几个(升序, 最多 [`SKIPPED_IDS_CAP`] 个)。
    ///
    /// 判据只看 `ids[0]`; 其余给告警用 —— 让用户能直接 `WHERE local_id IN (...)` 一把命中。
    pub ids: Vec<i64>,
    /// 有行**连行号本身都读不出来**(第 0 列都取不到)。位置说不清, 调用方按"可能越过了"算。
    ///
    /// ⚠️ **这一支在真库上构造不出来, 是有意留着的死代码**(2026-07-31 用户拍板留着 + 写清楚)。
    /// 两条都堵死了: ① `local_id INTEGER PRIMARY KEY AUTOINCREMENT` 就是 rowid 别名, 永远是整数,
    /// `row.get::<_, i64>(0)` 不可能失败; ② 这一列真要是压根不在, `prepare` 那一步就先失败了,
    /// 整张表走 `degraded_tables`, 根本走不到这里。
    ///
    /// 第二十五轮变异全扫坐实: 把这个字段的赋值删掉、或者把用它的那条判据删掉, **一条守卫都不红**,
    /// 而且另写探针也红不了 —— 因为它本来就到不了。它撑着一个字段、一个分支和一个 `&&` 条件,
    /// 是这套判据里**唯一没法证明的东西**。
    ///
    /// 那为什么不删: "宁可多报, 不能漏报"这条政策需要一个落点 —— 万一哪天微信换了 schema
    /// (比如 `local_id` 不再是主键别名), 有它兜着比静默漏掉强。**代价是它永远测不了, 认这个账。**
    pub unknown: bool,
}

/// [`SourceQuery::scan_all_messages`] 的扫描统计 —— 全局档命令据此标 `meta.summary.partial`。
///
/// **R16-0 (热查对等补全地基)**: 全库扫必然可能漏(分片打不开 / 表读不出 / 行映射失败 / `Name2Id` 缺 md5
/// 的表压根不在定位表里), 这些**不能静默** —— 调用方拿计数并入 partial, 别谎报"扫全了"。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanStats {
    /// 实际开扫的 (会话 × 分片表) 数 —— 注意"开扫"不等于"扫完", 中途游标断的表见 [`Self::truncated_tables`]。
    pub tables_scanned: usize,
    /// 回调看到的消息行数 (== `on_row` 实际调用次数, 含提前停那一行)。
    pub rows_seen: u64,
    /// **列转换**失败被丢的行数 (`read_raw_msg` 出错; 游标还活, 只坏这一行)。
    pub dropped_rows: usize,
    /// 打不开 / prepare / query 失败而**整张跳过**的表数 —— 一行没读到。
    pub degraded_tables: usize,
    /// **游标中途断**的表数 (对抗审 P3-5: 与上面区分 —— 这类表**扫了一半**, 已计入 `tables_scanned`,
    /// 剩余行永远看不到)。>0 = 结果不完整。
    pub truncated_tables: usize,
    /// **一路扫到底(EOF)的表**的键集, 键 = `"<分片 rel>\x1f<conv_id>"`。
    ///
    /// 为什么要这个集合、而不是让调用方从行里推(codex round-14 P1): `new --mode hot` 要判"这张表
    /// 这一轮扫全了没有", 我先用"看见了游标那一行 / 看见了游标之上的行"两个**地标**推 ——
    /// 而**表被重建**时(号从 1 重来、全部行都在旧游标底下、旧游标那行也没了)两个地标一个都拿不到,
    /// 于是被判成"没扫全"、水位原样保住 → **那些消息无限期看不到**, 正好是这一串要修的那个洞。
    /// 地标推不出来的东西, 扫描器自己是知道的: `rows.next()` 返 `Ok(None)` 就是扫到底了。
    ///
    /// 只在 `Ok(None)` 那一支插入; 整表跳过(`degraded_tables`)和游标中断(`truncated_tables`)都不插。
    pub complete_tables: std::collections::HashSet<String>,
    /// 每张表**被跳过的行**, 键同 [`Self::complete_tables`]。细节见 [`SkippedRows`]。
    ///
    /// 干什么用的: `new --mode hot` 判"是不是新"看的是行号 —— 一行读不出来被跳过、而同表更靠后的行
    /// 进了本批, 汇报位置就**越过了它**; 它此后恒 `<= 位置`, 哪怕后来又读得出来也永远不算新,
    /// **那条消息就永久看不见了**。调用方拿这个跟自己的汇报位置一比就知道有没有越过去。
    ///
    /// (2026-07-30 用户拍板"乙+": 这种丢可以接受 —— 位置只推到坏行之前的话, 永久坏行会把整张表
    /// 卡死、还占满名额饿死别的会话, 那是更糟的病。**但静默不行**, 所以有了这一项。)
    pub skipped_row_ids: std::collections::HashMap<String, SkippedRows>,
    /// **分片级**降级: sender 图 (`Name2Id`) 不全的**分片**数, **去重**。
    ///
    /// 对抗审 P2-4: 原先与行级计数混在一个 `content_degraded` 里 —— 而一个分片动辄被几千张会话表引用
    /// (实测本机 6 分片共 21197 张 `Msg_` 表), 按"会话×分片"累加会把它顶到上千, 再和行数加在同一个
    /// usize 里 → 出来的数既不是行数也不是分片数, 对调用方无意义。故拆开、且按分片去重。
    pub sender_degraded_shards: usize,
    /// **行级**降级: 正文解不出 / msgsource 解不出的**行**数 (行还在, 只是字段残缺)。见 P2-4。
    pub content_failed_rows: u64,
    /// **build 级**降级: 定位表构建时跳过的分片数 (对抗审 P2-5)。
    ///
    /// 为什么必须在这: 整分片打不开 → 其会话根本进不了定位表 → 全扫既不访问也不计数 → 其余字段全 0
    /// = "干净扫完了"。调用方照本结构标 partial 就会**漏掉整整一类不完整**。透传 `degraded_shards()`
    /// 让本结构**自足**, 不必调用方再去合第二路信号。
    pub build_degraded_shards: usize,
    /// 回调返 `false` 提前停 —— true = **结果非全量**(调用方别当扫完了)。
    pub stopped_early: bool,
}

/// R22 区间查 SQL(ADR-508 D3/D4 的排序契约在此**一处**定死; 表名来自定位表 = `sqlite_master` 白名单, 无注入)。
///
/// `ORDER BY create_time DESC, sort_seq DESC, local_id DESC` —— 单分片内 `source` 恒定, 故它等价于全局四键
/// 全序在本 step 上的限制。**改这行就会破坏全局分页的正确性**(每 step 取前 K 行 → 合并后取全局前 K 才不漏)。
/// 一次"回源之前"的源库探测结果(ADR-508 D18 水位 + D23 插入序栅栏)。
///
/// 三样都必须在**任何 Tier2 查询之前**取样 —— 抓完再取, 抓取期间新到的消息会被算进来却没被抓到。
#[derive(Debug, Clone)]
pub struct SourceWatermark {
    /// **已抓取安全前缀**(ms) = 跨全部命中分片的 `max(create_time) × 1000 - 1`。
    pub cursor_ms: i64,
    /// **回填地板**(ms): 自上次缓存(各分片的旧栅栏)以来新插入的行里, `create_time` 最早的那个。
    ///
    /// `Some(i64::MIN)` 是特例: **栅栏倒退**(源表被重建, `local_id` 从 1 重来)→ 手上的覆盖全部作废。
    ///
    /// `Some(f)` 说明有行的时间戳比"上次以为的最新"还早 —— 上层必须把 covered 收缩到 `f` **之前**,
    /// 否则那批行落在已 covered 区间里 = 永久查不出来且零信号(ADR-508 D23)。
    /// `None` = 自上次以来没有新行(或压根没新插入)。
    pub backfill_floor_ms: Option<i64>,
    /// 每个命中分片的**新栅栏** = 现在的 `max(local_id)`。② 与 coverage 一起写进 `query_cache_fence`。
    pub fences: Vec<(String, i64)>,
}

/// "这行的时间列坏了、任何窗口的 `BETWEEN` 都够不着"的判据 —— 冷热同一个集合。
///
/// 冷侧 `partial::count_l1_time_outliers` 把它拆成三条**各自能走索引寻址**的探针; 热侧源表没有
/// `create_time` 索引, 直接并进查询谓词即可。改这里必须同步改那边(有测试钉住)。
pub const OUTLIER_TIME_PRED: &str =
    "create_time IS NULL OR create_time > 9223372036854775807 OR create_time < -9223372036854775808";

/// L1-free 源库快查器 (持久化定位表 + 按需保温连接)。
pub struct SourceQuery {
    key: MasterKey,
    message_dir: PathBuf,
    locator_path: PathBuf,
    /// 按需保温连接 (分片全路径 → 只读 VFS 连接)。
    conns: HashMap<PathBuf, Connection>,
    /// 每分片 Name2Id rowid→sender (开分片时载入)。
    senders: HashMap<PathBuf, HashMap<i64, String>>,
    /// **要不要记"被跳过的行号", 以及每张表的下限**(键同 [`ScanStats::complete_tables`])。
    ///
    /// `None`(默认) = 一个都不记。全仓只有 `hot_new` 需要这份数据, 其余二十几个调用方白记一场。
    /// `Some(map)` = 记, 且只记**高于 `map[表]`(缺省 0)** 的那几个 —— 见 [`SkippedRows`] 说明
    /// 为什么下限必须由调用方给。
    skip_floors: Option<HashMap<String, i64>>,
    /// 持久化态 (stamps + locator); build 后就绪。
    persisted: PersistedLocator,
    built: bool,
    /// **复审#2/#5 + 第5轮#1 + R16 P2-6**: 本次 build 中被跳过的消息分片 (`message_<n>.db` **及**
    /// `biz_message_<n>.db`) 数 —— 打不开 / `Name2Id` 读不出 / `Msg_` 表列不出 / 消息目录读失败, 任一都算
    /// (这些分片的消息查不到 → 结果**不完整**)。**biz_message 库同样有 `Name2Id`** (ADR-480 §4 真跑: biz 分片
    /// 各带 96/12/4 行 Name2Id, 覆盖 104 张 Msg_ 表), 故其失败与主库**同等计入** —— 原按 `biz_` 前缀豁免是错的
    /// (会让公众号会话静默消失、partial/scan 两路信号都不响)。>0 时皮层给 `meta.summary.partial=true`, 别谎报 live-完整。
    degraded: usize,
    /// **复审(第5轮)#1**: 最近一次查询里**行映射失败被丢**的消息行数 (`read_raw_msg` 出错)。>0 = 结果漏了几行,
    /// 皮层并入 `partial` 信号 (原先只 warn 日志、调用方不知)。查询前不显式清零 —— 每次查询循环内**局部累加后覆盖**。
    query_dropped: usize,
    /// **复审(第6轮)#1**: 最近一次查询里**行在、但内容/发送人残缺**的计数 —— 正文解码失败 (返空串, 逐行判) 或
    /// 本次触碰的分片 sender 图不全 (见 [`Self::sender_degraded`], 逐分片判)。行没丢但字段不全, 皮层并入 `partial`。
    /// **纯每查询累加器** —— 查询函数循环内从零累加后覆盖; 不由 `build`/`ensure_shard_open` 直接写 (它们只填持久态)。
    content_degraded: usize,
    /// **R16-0 (对抗审 P2-7)**: 最近一次查询里**游标中途失败**的表数 —— `sqlite3_step` 在已出若干行后报错
    /// (损坏页 / IO), 游标就此终止 → **该表剩余行全部消失**。此前被当成"丢一行"(`query_dropped += 1`),
    /// 于是: 少报丢失量 + 不标表级降级 + `has_more`(= len+dropped>limit) 据此**谎报"没有更多消息"**。
    /// 纯每查询累加器 (查询函数循环内从零累加后覆盖)。
    query_degraded_tables: usize,
    /// **第6轮追修(codex/Claude 双审)**: 每分片 sender 图 (`Name2Id`) 的降级量 —— 整表读不出记 1, 部分行解码失败记
    /// 丢的行数。**持久**态 (随 `senders`/`conns` 保温, 跨查询不清), 因降级是分片的固有属性、非某次查询的瞬时值。
    /// 修 codex #2 (`ensure_shard_open` 的 `Ok` 分支原丢弃部分丢行数) + #3 (原用每查询计数器, 暖连接复用时第二次查询
    /// 早返回漏计)。查询循环每碰一个此表 >0 的分片就并入一次 `content_degraded` → `partial`, 每次查询都重算故不漏。
    sender_degraded: HashMap<PathBuf, usize>,
    /// **本账号 wxid** (R16-0 注入)。单聊 sender 方向回退要它 (`status==2` 已发 = 本账号发的)。
    ///
    /// 审 P2: 原热查手里**没有本账号**, 所以 sender 只能做"Name2Id or 群前缀"简版, 与冷查
    /// [`resolve_sender_parts`] 有真分歧 (单聊 SENT 方向解不出)。注入后热查复用同一份逻辑。
    self_wxid: String,
}

impl SourceQuery {
    /// 建查询器。`locator_path` = 定位表 JSON 存放处 (不存在则首次全扫后生成);
    /// `self_wxid` = **本账号 wxid** (单聊 sender 方向回退用, 见 [`Self::self_wxid`])。
    #[must_use]
    pub fn open(message_dir: PathBuf, key: MasterKey, locator_path: PathBuf, self_wxid: String) -> Self {
        Self {
            skip_floors: None,
            key,
            message_dir,
            locator_path,
            self_wxid,
            conns: HashMap::new(),
            senders: HashMap::new(),
            persisted: PersistedLocator::default(),
            built: false,
            degraded: 0,
            query_dropped: 0,
            query_degraded_tables: 0,
            content_degraded: 0,
            sender_degraded: HashMap::new(),
        }
    }

    /// 加载/增量刷新定位表: 加载 JSON → **只重扫 mtime/size 变过的分片** (没变的复用) → 存回。
    ///
    /// # Errors
    /// [`CipherError`] — 变过的分片解密/打开失败。
    pub fn build(&mut self) -> Result<(), CipherError> {
        if self.built {
            return Ok(());
        }
        // 加载已存定位表 (坏/缺 → 空, 全扫)。第5轮复审(codex P2): **版本不符 (含旧格式) → 弃**, 强制全重扫一次 ——
        // 旧版可能存了"部分损坏却健康"的 stamp, 直接信任会跨升级静默漏会话。
        self.persisted = std::fs::read(&self.locator_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedLocator>(&b).ok())
            .filter(|p| p.version == LOCATOR_VERSION)
            .unwrap_or_default();
        self.persisted.version = LOCATOR_VERSION; // 存回时带当前版本 (default 得 0, 补上)

        let (shards, dir_read_ok) = self.content_shards();
        let present: std::collections::HashSet<String> = shards.iter().filter_map(|p| rel_name(p)).collect();

        // 复审#1: 记本次尝试开的分片数 + 解密失败数。**全失败** = 极可能 key 不对/库整体损坏 → 结尾冒错,
        // 别静默返空 (伪装"实时无消息"+ live:true) —— content_shards 已过滤到 message_*.db, 正常 key 应全可解。
        let mut open_attempts = 0usize;
        let mut open_failures = 0usize;
        let mut cache_hits = 0usize; // 复审 NEW-1: stamp 命中 (跳过开) 的分片数 = "有缓存可查数据"的凭据。
                                     // **复审(第5轮)#1 + R16 P2-6**: 被跳过的消息分片数 (message_<n>.db **及** biz_message_<n>.db) —— 打不开 /
                                     // Name2Id 读不出 / Msg_ 表列不出, 任一都算丢消息数据 → 皮层标 partial。目录读失败也先计一笔 (整目录不可读 =
                                     // 丢全部)。biz_message 库同样有 Name2Id (ADR-480 §4), 故与主库同等计入 (原按 biz_ 前缀豁免实测是错的)。
        let mut degraded = usize::from(!dir_read_ok);
        for shard in &shards {
            let Some(rel) = rel_name(shard) else { continue };
            // R16 P2-6: message_<n>.db 与 biz_message_<n>.db 都带 Name2Id (ADR-480 §4), 都承载会话消息 —— 分片
            // 打不开 / Name2Id 读不出 / 表列不出, 两类一律算丢消息, 不再按 biz_ 前缀豁免 (那假设实测是错的)。
            let stamp = file_stamp(shard);
            if self.persisted.stamps.get(&rel) == Some(&stamp) {
                cache_hits += 1;
                continue; // 没变: 复用缓存的 locator 条目, 不开这分片 (有可查数据)。
            }
            // 变了 (或新分片): 开 + 重扫 Msg_ 表, 替换该分片的 locator 条目。
            open_attempts += 1;
            if self.ensure_shard_open(shard).is_err() {
                open_failures += 1;
                degraded += 1; // 分片打不开 = 丢消息 (全失败在循环后冒错; 部分失败标 partial)
                continue;
            }
            let Some(conn) = self.conns.get(shard) else { continue };
            let (md5_map, n2id_dropped) = match load_name2id(conn) {
                Ok(((_, md5), dropped)) => (md5, dropped),
                Err(_) => {
                    // 分片开了、但 Name2Id 整表读不出 = 表损坏丢消息 (biz_message 也有此表, ADR-480 §4)。
                    degraded += 1;
                    continue;
                }
            };
            let (tables, tbl_dropped) = match list_msg_tables(conn) {
                Ok((t, dropped)) => (t, dropped),
                Err(_) => {
                    degraded += 1; // Msg_ 表整列不出 = 丢消息
                    continue;
                }
            };
            // 第5轮复审#1(P1): Name2Id/表名有**行级**解码失败 (部分丢, 非整表失败, codex 逮) → 该分片标
            // degraded —— 那几个 conv/会话的定位缺了、结果不完整, 别静默。
            if n2id_dropped > 0 || tbl_dropped > 0 {
                degraded += 1;
            }
            // 先清掉旧的该分片条目 (表可能删/移).
            remove_shard_entries(&mut self.persisted.locator, &rel);
            // R22 (codex round-4): `Msg_<md5>` 表**在 Name2Id 里查不到对应用户名**时, 定位表登记不了它
            // (locator 按 conv_id 索引, 而 md5 不可逆) —— 原来这种表直接消失且**没有任何信号**, stamp 还照记,
            // 下次直接 cache-hit 不重扫 → 该会话的这片消息永久不可见, 而 `degraded_shards` 是 0、
            // `has_more=false`, R22-② 甚至会把它标成已缓存。现在按分片计一次降级, 让它可见。
            let mut unmapped = 0usize;
            for t in tables {
                if let Some(conv) = md5_map.get(&t[4..]) {
                    self.persisted
                        .locator
                        .entry(conv.clone())
                        .or_default()
                        .push((rel.clone(), t));
                } else {
                    unmapped += 1;
                }
            }
            if unmapped > 0 {
                tracing::warn!(
                    shard = rel.as_str(),
                    unmapped,
                    "Msg_ 表在 Name2Id 里查不到用户名, 无法登记定位表"
                );
                degraded += 1;
            }
            // **第5轮复审(codex P1)**: 仅**完整**扫描 (无丢行) 才记 stamp。否则下次 build 会把这"部分损坏"分片当缓存
            // 命中、跳过重扫 → 那次 `degraded` 归 0、**跨进程/重启后静默**漏那几个 conv (本次的 degraded 只在内存)。
            // 有丢行则**不记 stamp** → 下次 stamp 不匹配、重扫、重标 degraded (代价: 持久损坏分片每次重扫, 但损坏
            // 罕见, 正确性优先)。整表失败/打不开的分片本就在上面 continue、根本走不到这里, 天然不记 stamp。
            if n2id_dropped == 0 && tbl_dropped == 0 && unmapped == 0 {
                self.persisted.stamps.insert(rel, stamp);
            }
        }
        // 复审#1 + NEW-1: 冒 decrypt 错的条件 —— 本次尝试开的分片**全失败** 且**无任何缓存命中分片**。三条缺一不可:
        //   - `open_attempts > 0`: 全缓存命中 (啥都没开) 不误伤 —— 那时 key 错留给**查询**路径 (latest_messages 开分片) 冒。
        //   - `open_failures == open_attempts`: 有一个开成功就说明 key 对 (个别打不开是分片损坏问题, 非 key)。
        //   - `cache_hits == 0`: **NEW-1 修** —— 有缓存命中分片 = 旧 run 已成功建过、有可查数据, 别因这次某个新分片
        //     打不开就把整库查询判死; 那个坏分片的 conv 留给查询路径各自冒错。
        // 三条齐 = 极可能 key 不对/库整体损坏 (content_shards 已过滤到 message_*.db, 正常 key 应全可解) → 冒 decrypt 错
        // (皮层 hot_* 冠成"建定位表失败, key 不对/库损坏/没跑过 auth?"), 别静默返空 (伪装"实时无消息"+ live:true)。
        if open_attempts > 0 && open_failures == open_attempts && cache_hits == 0 {
            return Err(CipherError::decrypt_failed(
                b"",
                shards.first().map(std::path::PathBuf::as_path),
            ));
        }
        // 清掉已消失分片的条目/指纹.
        self.persisted.stamps.retain(|r, _| present.contains(r));
        let gone: Vec<String> = self
            .persisted
            .locator
            .values()
            .flatten()
            .map(|(r, _)| r.clone())
            .filter(|r| !present.contains(r))
            .collect();
        for r in gone {
            remove_shard_entries(&mut self.persisted.locator, &r);
        }

        // 存回 (best-effort).
        if let Ok(json) = serde_json::to_vec(&self.persisted) {
            let _ = std::fs::write(&self.locator_path, json);
        }
        // 复审#2/#5 + 第5轮#1: degraded = 本次 build 跳过的**主消息分片**数 (打不开 / Name2Id / 表列不出 / 目录读失败)。
        // 全失败已在上面冒错; 到这 degraded>0 = 有缓存兜底、部分主分片被容忍 → 那些分片的消息查不到、结果不完整。
        // 皮层据此标 `partial`, 不谎报 live-完整。
        self.degraded = degraded;
        self.built = true;
        Ok(())
    }

    /// **复审#2/#5 + 第5轮#1**: 本次 build 跳过的**主消息分片**数 (打不开 / Name2Id / Msg_ 表列不出 / 目录读失败)。
    /// 值 >0 = 结果可能漏这些分片的消息。皮层查完据此在 `meta.summary` 标 `partial` —— 热查虽 `live:true`, 但坏
    /// 分片的消息确实没读到, 得让调用方知道结果不完整。
    #[must_use]
    pub fn degraded_shards(&self) -> usize {
        self.degraded
    }

    /// **复审(第5轮)#1**: 最近一次 `latest_messages`/`messages_around` 里**行映射失败被丢**的行数 (>0 = 结果
    /// 漏了几行)。皮层并入 `partial` 信号。查询前不显式清零 —— 查询函数循环内累加后覆盖此值。
    #[must_use]
    pub fn last_query_dropped(&self) -> usize {
        self.query_dropped
    }

    /// **复审(第6轮)#1**: 最近一次查询里**行在、但内容/发送人残缺**的计数 (正文解不出 / 分片 `Name2Id` 发送人表
    /// 读不出)。>0 = 有行的正文或发送人是空的 (不是漏行, 是漏字段), 皮层并入 `partial` 信号。
    #[must_use]
    pub fn last_content_degraded(&self) -> usize {
        self.content_degraded
    }

    /// **R16-0 (对抗审 P2-7)**: 最近一次 `latest_messages`/`messages_around` 里**游标中途失败**的表数。
    ///
    /// 游标级错 (`sqlite3_step` 在已出若干行后报错: 损坏页 / IO) 会**终止游标** → 该表**剩余行全部消失**。
    /// 此前这被当成 [`Self::last_query_dropped`] 的"丢一行", 于是丢失量少报、表级不完整无信号, 而皮层的
    /// `has_more = len + dropped > limit` 吃这个少报值 → **可能谎报"没有更多消息了"**。>0 = 结果不完整,
    /// 皮层必须并入 `partial`。
    #[must_use]
    pub fn last_query_degraded_tables(&self) -> usize {
        self.query_degraded_tables
    }

    /// 会话清单 (conv_id, 是否群, 所在分片数)。
    ///
    /// # Errors
    /// 见 [`Self::build`].
    pub fn list_convs(&mut self) -> Result<Vec<(String, bool, usize)>, CipherError> {
        self.build()?;
        let mut out: Vec<(String, bool, usize)> = self
            .persisted
            .locator
            .iter()
            .map(|(c, locs)| (c.clone(), c.ends_with("@chatroom"), locs.len()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// **R16-0 地基: 全分片流式扫描原语** —— 遍历**所有会话 × 所有分片**的消息, 逐行回调。
    ///
    /// 谁用: 全局档命令 (stats/new/pii-scan/extract) + message 分片派生类 (calls/links/files/events/
    /// mentions/biz 的 `--all` 全局形)。它们要在全库里挑**稀疏**目标 (如"只带 url 的 appmsg"), 靠
    /// [`Self::latest_messages`] 的"按会话只开 1-2 分片"满足不了 top-N。
    ///
    /// **流式契约 (对抗审 P2 的硬要求)**: 每行解出即回调即丢, 内部**绝不 collect** —— `latest_messages`
    /// 是 collect-Vec 范式, 全库数百万行照搬必 OOM。回调返 `false` 提前停 (`stopped_early=true`)。
    ///
    /// **内存实情 (审纠正我的乐观断言)**: 不是"单分片 ~11MB"。逐分片 VFS 页缓存 + 该分片 Name2Id 图
    /// **全程保温** (`conns`/`senders` 复用不释放), 故峰值 ≈ N分片 × (页缓存 + sender 图), 大号可达数百 MB。
    ///
    /// **不完整性不静默**: 分片打不开 / 表读不出 / 行映射失败都计入 [`ScanStats`] 交调用方标 partial。
    /// ⚠️ 另有一类**天然漏**: `Name2Id` 缺 md5 的 `Msg_` 表压根进不了定位表 (见 [`Self::build`]), 全扫按
    /// 定位表迭代 → 这些会话不可见, 计在 `build` 的 `degraded` 里而非本函数。
    ///
    /// conv_id 从定位表 key 天然得到 (每行都带对的会话), 无需反解表名 md5。**扫描顺序按 conv_id 排序**
    /// (对抗审 P2-3: locator 是 HashMap, 不排则每进程随机, 配提前停 = 同命令两次结果不同)。
    ///
    /// **回调签名** `on_row(&QueriedMsg, &str, &str)` —— 第二参 = **解码后的 msgsource** (含 `<atuserlist>`
    /// @名单; 无 source / 未请求 → 空串); **第三参 = 本行的 `source` 串 = 冷查 `message.source` 列原样** = **rel_name
    /// 文件名单值**(pipeline.rs:332 `snapshot.rel_name`; ⚠️ Claude 审 P3-2: 非 pipeline.rs:21 doc 误写的 rel|table、
    /// 也非 etl_state 键)。**R16-2 地基(决策A)**: 派生命令(calls/links/…)冷查排序 `create_time DESC, source DESC,
    /// source_native_id DESC`, 同毫秒跨分片先按 source(=rel_name)分组 → 热查靠这第三参**逐字节对齐** cold, 否则
    /// 同毫秒跨分片 tie 分叉。6/7 消费方不读它 (传 `|_src|` 忽略即可)。
    /// 给 mentions 用: `QueriedMsg` 本身**不带**这字段 (codex 审 P1-1: 否则
    /// SELECT 了 source 也白搭, mentions 一行都发不出)。解码走冷查宽松口径 —— 失败退空串**并计**
    /// [`ScanStats::content_failed_rows`], 不因辅助元数据丢整条消息, 但也不静默。
    ///
    /// **`want_msgsource` 开关 (对抗审 P3-4)**: msgsource 真库**98.4% 是 zstd**(非空均 ~207B), 每行解它
    /// = 在 `message_content` 之外**再解压一次**。而 7 类消费方里只有 mentions 要 —— 故默认关: stats/new/
    /// pii-scan/extract/calls/links/… 传 `false` 跳过解压 (回调第二参恒空串), 只有 mentions 传 `true`。
    ///
    /// **`base_types` 类型预过滤 (R16-2 性能地基)**: `Some(&[base,…])` → SQL 加
    /// `WHERE (local_type & 0xFFFFFFFF) IN (…)`, **只把匹配 base 的行交给昂贵的 [`Self::decode_msg_row`]**
    /// (解压 message_content + 解 XML)。派生命令各只要稀疏的某几类 —— events=10000 / calls=50 /
    /// links 族=49 / …; 不过滤则全库数百万行**每行**解压一次(events 实测 >5 分钟)。SQLite `&` 是 64 位
    /// 位与, `local_type & 0xFFFFFFFF` = 低 32 位 = [`decode_local_type`] 的 `base` → 对**所有真实微信 base**
    /// (全 < 2³¹: 1/3/34/49/50/10000/…)与闭包里 `m.msg_type == base` **逐行等价**(见 decoder/local_type.rs +
    /// `scan_type_filter_sql_matches_*` 测)。⚠️ 仅假想 base ≥ 2³¹ 会分叉(SQL `& 0xFFFFFFFF` 无符号 vs Rust
    /// `as i32` 有符号), 微信无此 base 且调用方只传固定小值, 不可达。
    /// `base_types` 是 `i32` → 十进制拼接**无注入**(只能产 `-?[0-9]+`)。`None` = 不过滤(全局档
    /// stats/new/pii-scan/extract 照旧全扫); `Some(空集)` = 显式匹配 0 行(不静默退化成全扫)。
    /// ⚠️ 只减"解码哪些行", 不改任何降级/dropped 计数语义(匹配行解不出仍计 `dropped_rows`/`content_failed`)。
    ///
    /// # Errors
    /// - [`Self::build`] 失败 → [`CipherError`]。
    /// - **计划里有分片、却一个都没开成** → 返回该分片的 [`CipherError`] (codex 审 P1-2: 典型是缓存 key
    ///   过期/错而定位表 stamp 命中 → build 不开分片也成功; 若只计数返 `Ok(零行)`, **key 错就被伪装成
    ///   "没数据"**, 绕过既有 fail-fast)。
    /// - 单表级失败 (打不开 / prepare / 游标中断) **跳过并计数**, 不让一张坏表毁掉整次全扫。
    pub fn scan_all_messages<F>(
        &mut self,
        want_msgsource: bool,
        base_types: Option<&[i32]>,
        on_row: F,
    ) -> Result<ScanStats, CipherError>
    where
        F: FnMut(&QueriedMsg, &str, &str) -> bool,
    {
        self.scan_all_messages_impl(None, want_msgsource, base_types, on_row)
    }

    /// 打开"记下被跳过的行号"这个开关, 并给出**每张表的下限**(键 = `"<分片><会话>"`, 缺省 0)。
    ///
    /// 默认是关的 —— 全仓只有 `new --mode hot` 要这份数据, 其余二十几个 `scan_all_messages`
    /// 的调用方白记一场。下限为什么必须由调用方给, 见 [`SkippedRows`]。
    pub fn track_skipped_rows_above(&mut self, floors: HashMap<String, i64>) {
        self.skip_floors = Some(floors);
    }

    /// 这个开关**现在开着没有**(给测试用: 钉"扫完就该关掉"这条不变量)。
    #[must_use]
    pub fn is_tracking_skipped_rows(&self) -> bool {
        self.skip_floors.is_some()
    }

    /// 同 [`Self::scan_all_messages`] 但**只扫 conv_id 以 `conv_prefix` 起头的会话** —— 在会话计划层跳过不匹配的,
    /// **不开其表/不解码其消息**(比全扫再回调过滤省整批解码)。R16-2 `biz`(`conv_id LIKE 'gh_%'` 公众号消息)用:
    /// 全扫所有会话解码几百万只为挑 gh_ 子集太废, 会话层前缀过滤只扫 gh_ 会话(少数)。计数/降级语义与全扫一致。
    ///
    /// # Errors
    /// 同 [`Self::scan_all_messages`]。
    pub fn scan_conversations<F>(
        &mut self,
        conv_prefix: &str,
        want_msgsource: bool,
        base_types: Option<&[i32]>,
        on_row: F,
    ) -> Result<ScanStats, CipherError>
    where
        F: FnMut(&QueriedMsg, &str, &str) -> bool,
    {
        self.scan_all_messages_impl(Some(conv_prefix), want_msgsource, base_types, on_row)
    }

    fn scan_all_messages_impl<F>(
        &mut self,
        conv_prefix: Option<&str>,
        want_msgsource: bool,
        base_types: Option<&[i32]>,
        mut on_row: F,
    ) -> Result<ScanStats, CipherError>
    where
        F: FnMut(&QueriedMsg, &str, &str) -> bool,
    {
        self.build()?;
        let mut stats = ScanStats::default();
        // 跟 `plan` 同理: 下面循环里要 `&mut self`, 所以先把这份取出来。
        //
        // ⚠️ **用完即弃**(独立复审第二十四轮 P2): 下限只对**这一次**扫描有意义 —— 它是调用方
        // "我上次读到哪儿"的快照。留在字段里的话, 同一个 `SourceQuery` 被复用着扫第二遍时,
        // 下限还停在上一轮的位置 ⟹ 早报过的行重新进集合 ⟹ 第十九轮那个永久假告警原样复活。
        //
        // 今天没人复用(每处都是新建的), 但那是**调用约定**, 没有任何东西守着它;
        // 而 R18 瘦库/watch 那条线正朝"保温一个 `SourceQuery` 连着查"的方向走。
        // `take()` 一下, 不变量就从约定回到类型里 —— 想再扫必须再设一次。
        let skip_floors = self.skip_floors.take();
        // 借用: 遍历 self.persisted.locator 的同时要 &mut self (ensure_shard_open) → 先快照会话清单。
        // 代价是几千条 (String, Vec<(String,String)>) 的一次性 clone, 相对全库扫可忽略。
        let mut plan: Vec<(String, Vec<(String, String)>)> = self
            .persisted
            .locator
            .iter()
            .map(|(c, v)| (c.clone(), v.clone()))
            .collect();
        // 对抗审 P2-3: locator 是 HashMap, `.iter()` 顺序**每进程随机**(std 随机 seed)。而本原语的文档用途
        // 正是"全库挑稀疏目标取 top-N" + 回调可提前停 → 不排序则**同一命令跑两次拿到不同的 N 条**。
        // 同仓已有规范: list_convs 特意 sort_by; source/account.rs "稳定排序 = 确定性 drain 顺序"。
        plan.sort_by(|a, b| a.0.cmp(&b.0));
        // 对抗审 P2-5: 透传 build 级降级 (整分片打不开 → 其会话根本进不了定位表 → 全扫压根不访问、
        // 其余计数全 0 = "干净扫完"), 让 ScanStats **自足**, 调用方不必再去合第二路信号。
        stats.build_degraded_shards = self.degraded;
        let self_wxid = self.self_wxid.clone(); // 同理: 避免与 &mut self 借用打架
                                                // 对抗审 P2-4: sender 图不全的**分片**去重集 —— 原按"会话×分片"累加会放大上千倍。
        let mut sender_bad_shards: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        // codex 审 P2-1: **失败分片 memoize** —— 一个坏分片常被几百张表 (会话) 引用, `ensure_shard_open`
        // 失败不留缓存 → 不记住就会对同一分片重复几百次昂贵 VFS 解密 + 刷屏 warn。
        let mut failed_shards: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        // codex 审 P1-2: **全部分片都开不了必须报错**。典型场景: 定位表 stamp 命中 (build 不重开分片即成功)
        // 但缓存 key 已过期/错 → 每个 ensure 都失败。若只计数返回 Ok(零行), **key 错就伪装成"没数据"**,
        // 绕过既有 fail-fast。故: 一个分片都没开成 → 返回原始 CipherError。
        let mut any_shard_open = false;
        let mut last_open_err: Option<CipherError> = None;
        'scan: for (conv_id, locs) in plan {
            // R16-2 biz: 会话层前缀过滤 —— conv_id 不以 prefix 起头的会话**直接跳过**(不开表/不解码其消息),
            // 只扫匹配会话(如 gh_ 公众号)。不影响 stats(跳过的会话本就不该计入)。
            if conv_prefix.is_some_and(|p| !conv_id.starts_with(p)) {
                continue;
            }
            let is_group = conv_id.ends_with("@chatroom");
            for (rel, table) in locs {
                let shard = self.message_dir.join(&rel);
                if failed_shards.contains(&shard) {
                    stats.degraded_tables += 1; // 已知坏分片: 只计数, 不重试 (P2-1)
                    continue;
                }
                if let Err(e) = self.ensure_shard_open(&shard) {
                    tracing::warn!(shard = rel.as_str(), "全扫: 分片打不开, 跳过其全部表 (结果不完整)");
                    failed_shards.insert(shard.clone());
                    last_open_err = Some(e);
                    stats.degraded_tables += 1;
                    continue;
                }
                any_shard_open = true;
                if self.sender_degraded.get(&shard).is_some_and(|&d| d > 0) {
                    sender_bad_shards.insert(shard.clone()); // P2-4: 分片级**去重**, 不按会话累加
                }
                // 表名来自定位表 (源自 sqlite_master 白名单), 无注入。按 local_id 正序 = 主键顺扫。
                // R16-2 性能地基: base_types 类型预过滤 —— 只让匹配 base(msg_type 低 32 位)的行进 decode_msg_row
                // (贵在解压 message_content)。base_types 是 i32 → 十进制拼接无注入(只产 `-?[0-9]+`);
                // 空集 → `WHERE 0`(显式匹配 0 行, 不静默退化成全扫); None → 不过滤。见本方法 doc。
                let type_filter = match base_types {
                    Some(types) if !types.is_empty() => {
                        let list = types
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ");
                        // codex 审 P2: `typeof(local_type) <> 'integer'` 兜底 —— 若某行 local_type 存成
                        // NULL/BLOB/文本(损坏), 位与谓词在 read_raw_msg 前就判 false 会**静默滤掉**它;
                        // 而不过滤时这行会进 read_raw_msg → i64 转换失败 → dropped_rows++(partial 信号)。
                        // 故显式放行非整数 local_type 行, 让既有的映射失败计数照旧观测到它, 守住"不完整性不静默"。
                        // 合法整数但 base 不匹配的行仍被滤(优化不变: 它 typeof=integer 两条件都 false)。
                        format!(" WHERE (local_type & 4294967295) IN ({list}) OR typeof(local_type) <> 'integer'")
                    }
                    Some(_) => " WHERE 0".to_string(),
                    None => String::new(),
                };
                let sql = format!("SELECT {MSG_COLS} FROM \"{table}\"{type_filter} ORDER BY local_id");
                let conn = self.conns.get(&shard).expect("ensure 已开");
                let mut st = match conn.prepare(&sql) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(shard = rel.as_str(), error = %e, "全扫: prepare 失败, 跳过表");
                        stats.degraded_tables += 1;
                        continue;
                    }
                };
                // codex 审 P2-2: **游标失败 vs 列转换失败必须分开**。`query_map` 的 Err 会**终止游标**,
                // 当成"丢一行"会让该表**剩余行全部消失**却只记 dropped_rows=1 / degraded_tables=0 = 谎报完整。
                // 故手动 `Rows::next()`: Err(游标, 如损坏页/IO) → 标表 degraded 并停该表; 列转换失败 → 只丢该行。
                let mut rows = match st.query([]) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(shard = rel.as_str(), error = %e, "全扫: query 失败, 跳过表");
                        stats.degraded_tables += 1;
                        continue;
                    }
                };
                stats.tables_scanned += 1;
                let sender_map = self.senders.get(&shard);
                // R16-2 地基(决策A): 回调透 `source` 串 = 冷查 `message.source` 列**原样**, 给派生命令做跨分片排序次键。
                // ⚠️ Claude 审 P3-2 纠: message.source 实为 **rel_name 单值**(pipeline.rs:332 `source: snapshot.rel_name`)——
                // 非 line 21 doc 误写的 rel|table、也非 etl_state 键(pipeline.rs:287 `{rel}|{table}`)。故 src = **rel(文件名)**
                // 才与冷查 events_query/calls_query 的 `ORDER BY create_time DESC, source DESC, source_native_id DESC` 逐字节
                // 对齐。早期误用 rel|table 靠 table 恰是 source_native_id(`Msg_<md5>:<n>`)前缀"碰巧"排序等价, 但脆(msg_anchor
                // 或 source 取值一变即静默分叉); 现 rel-only 字面对齐、无隐式耦合。rel 后续 warn 还要用, 故 clone 不移。
                let src = rel.clone();
                // 这张表有没有**跳过行**(列映射失败)。跳了行的表**不算"扫全"** —— 那一行下一轮可能
                // 又读得出来, 于是"已读段行数"两轮之间不稳, 调用方会判成"表被换过"(独立复审 P2)。
                let mut skipped_in_table = false;
                loop {
                    let row = match rows.next() {
                        Ok(Some(row)) => row,
                        Ok(None) => {
                            // 该表一路扫到底 —— **中间没跳过行**才算数(见 `ScanStats::complete_tables`)。
                            if !skipped_in_table {
                                stats.complete_tables.insert(format!("{src}\u{1f}{conv_id}"));
                            }
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(shard = rel.as_str(), error = %e, "全扫: 游标中断, 该表剩余行未扫");
                            // P3-5: 这张表**扫了一半**(已计入 tables_scanned), 与"整张跳过"(degraded_tables)分开记。
                            stats.truncated_tables += 1;
                            break;
                        }
                    };
                    let rr = match read_raw_msg(row) {
                        Ok(rr) => rr,
                        Err(e) => {
                            tracing::warn!(shard = rel.as_str(), error = %e, "全扫: 行映射失败, 跳过该行");
                            stats.dropped_rows += 1; // 列转换失败: 只丢这一行, 游标还活着
                            skipped_in_table = true;
                            // 记下**跳过的行号**(第 0 列) —— 只在调用方明确要的时候记, 而且只记
                            // **高于它给的下限**的那几个最小值。为什么这么设计见 `SkippedRows`:
                            // 判据等价于 `min{s : s > 下限} <= 新位置`, 一个行号就够, 不用把整个集合搬出去。
                            if let Some(floors) = skip_floors.as_ref() {
                                let wk = format!("{src}\u{1f}{conv_id}");
                                let floor = floors.get(&wk).copied().unwrap_or(0);
                                match row.get::<_, i64>(0) {
                                    Ok(lid) if lid > floor => {
                                        let e = stats.skipped_row_ids.entry(wk).or_default();
                                        // 升序来的, 所以攒够就不用再看后面的 —— 后面只会更大。
                                        if e.ids.len() < SKIPPED_IDS_CAP && !e.ids.contains(&lid) {
                                            e.ids.push(lid);
                                        }
                                    }
                                    Ok(_) => {} // 在下限底下: 那一行早报给用户了, 不算丢
                                    Err(_) => {
                                        // 行号自己都读不出来: 位置说不清, 交给调用方按"可能越过了"算。
                                        stats.skipped_row_ids.entry(wk).or_default().unknown = true;
                                    }
                                }
                            }
                            continue;
                        }
                    };
                    // codex 审 P1-1: **msgsource 必须给回调** —— 本原语的头号消费方 mentions --all 要从
                    // `<atuserlist>` 解 @名单, 而 QueriedMsg 没这字段 (只有正文)。**宽松口径同冷查**
                    // (assemble_message: source 是辅助元数据, 解不出退空串, 绝不因它丢整条消息 —— 审 P3-4)。
                    // codex 复审 P2: **宽松 ≠ 静默**。source 若是损坏/截断 zstd, 退空串会让 mentions --all
                    // 悄悄漏掉 @名单, 而 content_degraded/dropped_rows 都不增 → 调用方误报"扫完整了"
                    // (违背本原语自己的"不完整性不静默"契约)。故: 行照留 (不因辅助元数据丢整条消息, 同冷查
                    // 宽松口径), 但**解码失败记进统计**。src_hex 为空 = 该消息本就无 msgsource (常态, 非降级)。
                    // P3-4: 只有真要 msgsource 的消费方(mentions)才付解压钱 —— 真库 98.4% 的 source 是 zstd,
                    // 不加这个开关等于给每行凭空多解压一次(6/7 消费方根本不读第二参)。
                    let msgsource = if !want_msgsource || rr.src_hex.is_empty() {
                        String::new()
                    } else {
                        match hex::decode(&rr.src_hex)
                            .ok()
                            .and_then(|b| decode_message_content(&b).ok())
                        {
                            Some(s) => s,
                            None => {
                                tracing::debug!(shard = rel.as_str(), "全扫: msgsource 解不出, @名单可能漏");
                                stats.content_failed_rows += 1; // P2-4: 行级 (与分片级分开)
                                String::new()
                            }
                        }
                    };
                    let (m, content_ok) = Self::decode_msg_row(is_group, &conv_id, sender_map, &rr, &self_wxid);
                    if !content_ok {
                        stats.content_failed_rows += 1; // P2-4: 行级
                    }
                    stats.rows_seen += 1;
                    // 流式核心: 回调即丢, 不进任何容器。第三参 src = rel_name(= 冷查 message.source, 决策A 跨分片排序次键)。
                    if !on_row(&m, &msgsource, &src) {
                        stats.stopped_early = true;
                        break 'scan;
                    }
                }
            }
        }
        stats.sender_degraded_shards = sender_bad_shards.len(); // P2-4: 去重后的分片数 (非会话×分片)
                                                                // P1-2: 计划里有分片、却一个都没开成 → key 错/库坏, 报错而非静默空结果。
        if !any_shard_open {
            if let Some(e) = last_open_err {
                return Err(e);
            }
        }
        Ok(stats)
    }

    /// 查某会话最近 `limit` 条 (跨分片 merge, 按时间倒序)。**只开该会话相关分片** (lazy)。
    ///
    /// # Errors
    /// [`CipherError`] — 建定位表 / 开分片 / 查询失败。
    pub fn latest_messages(&mut self, conv_id: &str, limit: usize) -> Result<Vec<QueriedMsg>, CipherError> {
        self.query_dropped = 0; // 第5轮复审(Claude nit): build 前重置, build 失败也不留上次旧值
        self.build()?;
        self.content_degraded = 0; // 第6轮(追修后): 纯每查询累加器清零; 发送人降级源在持久 sender_degraded 图, 循环里逐分片并入
        let is_group = conv_id.ends_with("@chatroom");
        let locs = self.persisted.locator.get(conv_id).cloned().unwrap_or_default();
        if locs.is_empty() {
            // R11: 会话不在定位表 → 空结果 (帮诊断"查了没数据")。conv_id 走 sha8。
            tracing::debug!(conv = %crate::key_provider::sha8(conv_id.as_bytes()), "会话不在定位表, 空结果");
        }
        let mut all: Vec<QueriedMsg> = Vec::new();
        let mut dropped = 0usize; // 第5轮#1: 累计行映射失败丢的行数 (跨分片); 循环后写入 self.query_dropped。
                                  // R16-0 (对抗审 P2-7): 游标中途失败的表数, 与"丢一行"分开记; 循环后写入 self.query_degraded_tables。
        let mut table_degraded = 0usize;
        let mut content_bad = 0usize; // 第6轮#1: 正文解不出的行数 (行在但正文空); 循环后并入 self.content_degraded。
        for (rel, table) in locs {
            let shard = self.message_dir.join(&rel);
            // R11: 查询路径打不开分片 = 硬错误(冒泡)→ warn!; build 的容忍跳过路径不记(审查 P2)。
            // (clippy manual_inspect: warn 是副作用、返回原错 → inspect_err 直接透传, 无需 map_err。)
            self.ensure_shard_open(&shard)
                .inspect_err(|_| tracing::warn!(shard = rel.as_str(), "分片解密打开失败"))?; // 按需只开这分片 (可能已开)
                                                                                             // 第6轮追修(codex #3/Claude): 本分片 sender 图不全 (整表失败/部分丢行) → 发送人可能空, 并入 partial。
                                                                                             // 读**持久** sender_degraded (非每查询计数器), 暖连接复用的第二次查询也照样重算不漏。每分片在本会话 locs
                                                                                             // 里至多一条 → 一分片至多 +1。
            if self.sender_degraded.get(&shard).is_some_and(|&d| d > 0) {
                content_bad += 1;
            }
            // 按 local_id (rowid 主键索引) 取最近 N 行; 表名 sqlite_master 白名单无注入。
            let sql = format!("SELECT {MSG_COLS} FROM \"{table}\" ORDER BY local_id DESC LIMIT {limit}");
            let conn = self.conns.get(&shard).expect("ensure 已开");
            let raw: Vec<RawMsgRead> = {
                // R11: prepare 失败 (吞 rusqlite 错) → 记 warn! 保诊断。rusqlite::Error 只含 SQL/表名(Msg_<md5> 安全), 无 PII; 分片只带文件名。
                // (clippy manual_inspect: warn 是副作用、返回的是**另一种**错 → inspect_err 记日志 + map_err 转错。)
                let mut st = conn
                    .prepare(&sql)
                    .inspect_err(|e| tracing::warn!(shard = rel.as_str(), error = %e, "热查 prepare 失败"))
                    .map_err(|_| CipherError::decrypt_failed(b"", Some(&shard)))?;
                // R16-0 (对抗审 P2-7): 手动游标 —— 必须区分 **游标中断**(sqlite3_step 在已出若干行后报错,
                // 如损坏页/IO → 游标终止 → **该表剩余行全部消失**) 与 **列转换失败**(只坏这一行, 游标还活)。
                // 原 query_map + filter_map 把前者当后者: 少报丢失量 + 不标表级降级, 而 hot.rs 的
                // has_more = len + dropped > limit 吃这个少报的 dropped → **谎报"没有更多消息了"**。
                let mut rows = st
                    .query([])
                    .map_err(|_| CipherError::decrypt_failed(b"", Some(&shard)))?;
                let mut acc: Vec<RawMsgRead> = Vec::new();
                loop {
                    match rows.next() {
                        Ok(Some(row)) => match read_raw_msg(row) {
                            Ok(rr) => acc.push(rr),
                            Err(e) => {
                                // 第5轮#1: 行映射失败**非静默丢** —— warn (无正文 PII) + 累加 dropped, 皮层并入 partial。
                                tracing::warn!(shard = rel.as_str(), error = %e, "热查 message 行映射失败, 跳过该行");
                                dropped += 1;
                            }
                        },
                        Ok(None) => break,
                        Err(e) => {
                            tracing::warn!(shard = rel.as_str(), error = %e, "热查 游标中断, 该表剩余行未读");
                            table_degraded += 1;
                            break;
                        }
                    }
                }
                acc
            };
            let sender_map = self.senders.get(&shard);
            for rr in raw {
                let (m, content_ok) = Self::decode_msg_row(is_group, conv_id, sender_map, &rr, &self.self_wxid);
                if !content_ok {
                    content_bad += 1; // 第6轮#1: 正文解不出
                }
                all.push(m);
            }
        }
        self.query_dropped = dropped; // 第5轮#1: 本次查询丢的行数 → 皮层 partial 信号
        self.query_degraded_tables = table_degraded; // R16-0 (审 P2-7): 游标中断的表数 → 皮层 partial 信号
        self.content_degraded += content_bad; // 第6轮(追修后): 本次查询正文解不出 + sender 图不全的分片数 (循环累加) → partial
        all.sort_by_key(|m| std::cmp::Reverse(m.create_time));
        all.truncate(limit);
        Ok(all)
    }

    /// 解一行原始消息 → [`QueriedMsg`] **全字段** (R5 扩全)。派生字段全复用冷查 ingest 同批**纯函数** (零漂移):
    /// [`content_encoding`](decode_kind) · [`decode_message_content`](正文) · [`split_chatroom_sender`]/Name2Id(发送人) ·
    /// [`decode_local_type`](msg_type/name/sub) · [`classify_sysmsg`](sys_type) · [`msg_anchor`](source_native_id)。
    /// 原始列 (server_id/status/sort_seq/…) 无派生直取。`latest_messages`/`messages_around` 共用。
    fn decode_msg_row(
        is_group: bool,
        conv_id: &str,
        sender_map: Option<&HashMap<i64, String>>,
        rr: &RawMsgRead,
        self_wxid: &str,
    ) -> (QueriedMsg, bool) {
        let bytes = hex::decode(&rr.mc_hex).unwrap_or_default();
        let decode_kind = content_encoding(&bytes).to_string();
        // R11: 有内容但解不出 → debug! (热路径, 仅 debug 级; 空内容是正常缺省不记)。只带类型/长度, 不带正文。
        // **第6轮复审#1**: 有内容却解不出 = 正文丢 → `content_ok=false`, 皮层据此并入 `partial` (原只 debug 静默空串)。
        let mut content_ok = true;
        let raw_text = decode_message_content(&bytes).unwrap_or_else(|_| {
            if !bytes.is_empty() {
                tracing::debug!(
                    local_type = rr.local_type,
                    len = bytes.len(),
                    "热查正文解不出, 空串兜底"
                );
                content_ok = false;
            }
            String::new()
        });
        // R16-0 (审 P2-1/P2-2): sender 改用**冷查同一份** [`resolve_sender_parts`] —— 候选优先级
        // Name2Id > 群 content 前缀 > 单聊 status 方向 (2 已发=本账号/其它=对方) > `SENDER_UNKNOWN` 占位。
        //
        // ⚠️ **本次两处行为变化 (对齐冷查基准, 非 bug)**:
        // 1. **群聊优先级翻转**: 原热查是"前缀优先"(`pfx.or_else(name2id)`), 冷查是"Name2Id 优先"
        //    (`[name2id, split]`, 且 `chatroom_name2id_sender` 测试钉死)。以冷查为准 → Name2Id 优先。
        // 2. **解不出不再是 None**: 原热查解不出返 None, 现返 `SENDER_UNKNOWN` 占位 (同冷查 NOT NULL 语义)。
        let (text, split_sender) = if is_group {
            let (pfx, body) = split_chatroom_sender(&raw_text);
            (body, pfx)
        } else {
            (raw_text, None) // 单聊无群前缀 (同冷查: split 恒 None)
        };
        let name2id = rr
            .real_sender_id
            .and_then(|r| sender_map.and_then(|m| m.get(&r).cloned()));
        // 参数顺序须对照 resolve_sender_parts(name2id, split_sender, is_chatroom, status, self_wxid, conv_id)
        // —— self_wxid/conv_id 同为 &str **可静默调换** (审 P2-2), 写反 = 单聊收发反转; 下方测试锁死方向。
        let sender = Some(
            resolve_sender_parts(name2id, split_sender, is_group, rr.status, self_wxid, conv_id)
                .as_str()
                .to_string(),
        );
        // 派生类型 (同冷查 assemble_message: decode_local_type; msg_sub_type 仅 base==49 && sub!=0 时 Some)。
        let lt = decode_local_type(rr.local_type);
        // sys_type: 系统消息 (base 10000) 按净正文分类 (同冷查 project_message 的 classify_sysmsg 路)。
        let sys_type = (lt.base == 10000).then(|| classify_sysmsg(&text).to_string());
        // raw_xml_present: 同冷查 assemble_message 的公式 (净正文 trim 后首字符 '<')。
        let raw_xml_present = text.trim_start().starts_with('<');
        let msg = QueriedMsg {
            source_native_id: msg_anchor(conv_id, rr.local_id),
            conv_id: conv_id.to_string(), // R16-0: 全局扫命令要按会话输出这列 (数据本在入参, 原先没带出)
            local_id: rr.local_id,
            server_id: rr.server_id,
            server_seq: rr.server_seq,
            origin_source: rr.origin_source,
            upload_status: rr.upload_status,
            download_status: rr.download_status,
            create_time: rr.create_time.saturating_mul(1000), // R6 归一: 秒 → 毫秒 (同冷查 assemble_message, 消热/冷单位差)。
            sort_seq: rr.sort_seq,
            status: rr.status,
            local_type: rr.local_type,
            msg_type: i64::from(lt.base),
            msg_type_name: lt.type_name.to_string(),
            msg_sub_type: lt.sub_type_name.map(|_| i64::from(lt.sub)),
            msg_sub_type_name: lt.sub_type_name.map(str::to_string),
            decode_kind,
            content_ok,
            sys_type,
            is_chatroom: is_group,
            raw_xml_present,
            sender,
            text,
        };
        (msg, content_ok)
    }

    /// 取某会话里锚点时间**前后**的消息 (消息上下文; ④ 对拍 WDA 逮出的缺口)。`before` 条更早
    /// (`create_time <= center`) + `after` 条更晚 (`create_time > center`), 跨分片按时间合并, 输出**按时间正序**。
    ///
    /// 锚点用 `center_time` (= hot 输出里的 `create_time`, **毫秒** R6 归一; LLM 可引用它; 不唯一无妨, 上下文近似即可)。
    ///
    /// # Errors
    /// 分片打不开 / 查询失败 → `CipherError`。
    pub fn messages_around(
        &mut self,
        conv_id: &str,
        center_time: i64,
        before: usize,
        after: usize,
    ) -> Result<Vec<QueriedMsg>, CipherError> {
        self.query_dropped = 0; // 第5轮复审(Claude nit): build 前重置, build 失败也不留上次旧值
        self.build()?;
        self.content_degraded = 0; // 第6轮(追修后): 每查询累加器清零 (降级源在持久 sender_degraded 图)
        let is_group = conv_id.ends_with("@chatroom");
        let locs = self.persisted.locator.get(conv_id).cloned().unwrap_or_default();
        if locs.is_empty() {
            tracing::debug!(conv = %crate::key_provider::sha8(conv_id.as_bytes()), "会话不在定位表, 空结果(around)");
        }
        let mut befores: Vec<QueriedMsg> = Vec::new();
        let mut afters: Vec<QueriedMsg> = Vec::new();
        // R6 归一: 输出 create_time 现为**毫秒**(同冷查), 故 center_time(= hot 输出 create_time)也是毫秒;
        // Msg_ 的 create_time 列是【秒】, 比对前 center ÷1000 转秒 (锚点近似, 秒级粒度足够)。
        let center_secs = center_time / 1000;
        let mut dropped = 0usize; // 第5轮#1: 累计行映射失败丢的行数 (跨分片+前后两窗)
        let mut table_degraded = 0usize; // R16-0 (审 P2-7): 游标中断的表数, 与"丢一行"分开记
        let mut content_bad = 0usize; // 第6轮#1: 正文解不出的行数
        for (rel, table) in locs {
            let shard = self.message_dir.join(&rel);
            // R11: 同 latest_messages —— 查询路径打不开分片 warn!(审查 P2; clippy manual_inspect: 用 inspect_err)。
            self.ensure_shard_open(&shard)
                .inspect_err(|_| tracing::warn!(shard = rel.as_str(), "分片解密打开失败(around)"))?;
            // 第6轮追修(codex #3/Claude): 同 latest_messages —— 本分片 sender 图不全 → 并入 partial (读持久 sender_degraded)。
            if self.sender_degraded.get(&shard).is_some_and(|&d| d > 0) {
                content_bad += 1;
            }
            // 表名 sqlite_master 白名单无注入; center_secs/limit 是数值。before: <=center 最近 N; after: >center 最早 N。
            let sql_before = format!(
                "SELECT {MSG_COLS} FROM \"{table}\" WHERE create_time <= {center_secs} ORDER BY create_time DESC LIMIT {before}"
            );
            let sql_after = format!(
                "SELECT {MSG_COLS} FROM \"{table}\" WHERE create_time > {center_secs} ORDER BY create_time ASC LIMIT {after}"
            );
            let sender_map = self.senders.get(&shard);
            let conn = self.conns.get(&shard).expect("ensure 已开");
            for (sql, dst) in [(&sql_before, &mut befores), (&sql_after, &mut afters)] {
                let raw: Vec<RawMsgRead> = {
                    // R11: prepare 失败保诊断 (同 latest_messages; clippy manual_inspect: inspect_err 记 + map_err 转)。
                    let mut st = conn
                        .prepare(sql)
                        .inspect_err(|e| tracing::warn!(shard = rel.as_str(), error = %e, "热查 prepare 失败(around)"))
                        .map_err(|_| CipherError::decrypt_failed(b"", Some(&shard)))?;
                    // R16-0 (对抗审 P2-7): 手动游标, 同 latest_messages —— 游标中断 (该表剩余行全没) 必须与
                    // 列转换失败 (只坏这一行) 分开, 否则少报丢失 + 不标降级 + has_more 谎报"没有更多"。
                    let mut rows = st
                        .query([])
                        .map_err(|_| CipherError::decrypt_failed(b"", Some(&shard)))?;
                    let mut acc: Vec<RawMsgRead> = Vec::new();
                    loop {
                        match rows.next() {
                            Ok(Some(row)) => match read_raw_msg(row) {
                                Ok(rr) => acc.push(rr),
                                Err(e) => {
                                    tracing::warn!(shard = rel.as_str(), error = %e, "热查 message 行映射失败, 跳过该行");
                                    dropped += 1;
                                }
                            },
                            Ok(None) => break,
                            Err(e) => {
                                tracing::warn!(shard = rel.as_str(), error = %e, "热查 游标中断(around), 该表剩余行未读");
                                table_degraded += 1;
                                break;
                            }
                        }
                    }
                    acc
                };
                for rr in raw {
                    let (m, content_ok) = Self::decode_msg_row(is_group, conv_id, sender_map, &rr, &self.self_wxid);
                    if !content_ok {
                        content_bad += 1; // 第6轮#1: 正文解不出
                    }
                    dst.push(m);
                }
            }
        }
        self.query_dropped = dropped; // 第5轮#1: 本次查询丢的行数 → 皮层 partial 信号
        self.query_degraded_tables = table_degraded; // R16-0 (审 P2-7): 游标中断的表数 → 皮层 partial 信号
        self.content_degraded += content_bad; // 第6轮(追修后): 正文解不出 + sender 图不全的分片数 (循环累加) → partial
                                              // 全分片合并后: befores 按时间倒序取前 `before` 条 (最近的), afters 正序取前 `after` 条; 拼成时间正序。
        befores.sort_by_key(|m| std::cmp::Reverse(m.create_time));
        befores.truncate(before);
        befores.reverse(); // desc → asc
        afters.sort_by_key(|m| m.create_time);
        afters.truncate(after);
        befores.extend(afters);
        Ok(befores)
    }

    /// 源库 message 分片目录(R22 执行器 stat 分片大小粗估行数用)。
    #[must_use]
    pub fn message_dir(&self) -> &Path {
        &self.message_dir
    }

    /// 本实例绑定的账号 wxid(open 时传入)。R22 执行器据此 fail-closed 校验"L1 侧账号 == 源库侧账号"——
    /// 传错会拼出"A 的缓存 + B 的源消息"的跨账号结果。
    #[must_use]
    pub fn self_wxid(&self) -> &str {
        &self.self_wxid
    }

    /// R22 partial-hit: 某会话命中的**源库分片清单** `(分片文件相对名, `Msg_<md5(conv_id)>` 表名)`。
    ///
    /// 走**持久定位表**(扫各分片 `Name2Id` 建), 故是"这个会话真在哪几个分片里"而非盲发全分片。空 = 该会话
    /// 不在定位表(该账号确实没有它的消息) → 上层出空结果, 同 [`Self::latest_messages`] 的语义, 不报错。
    ///
    /// **不依赖休眠的 `source_chat_to_db` / `source_chat_index` / `source_db_catalog`**(ADR-508 D2)。
    ///
    /// ⚠️ **长驻实例不会刷新定位表**: [`Self::build`] 成功一次后 `built = true` 就永远早返, 不再 stat 文件/
    /// 校验 stamp。所以同一个 `SourceQuery` 实例活得越久, 越可能看不到**新分片 / 新会话**(微信轮转到
    /// `message_N.db` 时同一 chat 会落到新分片)—— 而且**没有任何降级信号**: 旧分片查得好好的、
    /// `has_more=false`、`cache_eligible=true`, R22-② 甚至会把漏了新分片的那段标成已缓存。
    /// 当前三皮都是**每次查询新建**查询器, 所以够不着; **R22-④ 接 serve 时必须保持这条**(或显式重建实例)。
    ///
    /// # Errors
    /// [`CipherError`] —— 建定位表失败(开库/解密/扫 `Name2Id`)。
    pub fn shards_for(&mut self, conv_id: &str) -> Result<Vec<(String, String)>, CipherError> {
        self.build()?;
        Ok(self.persisted.locator.get(conv_id).cloned().unwrap_or_default())
    }

    /// 确保某分片已开 (VFS 保温连接 + 载 Name2Id sender)。已开则 no-op。
    fn ensure_shard_open(&mut self, shard: &Path) -> Result<(), CipherError> {
        if self.conns.contains_key(shard) {
            return Ok(());
        }
        // 打开失败保持沉默由调用方决定: build() 容忍跳过(静默), 查询路径冒泡时才 warn(审查 P2: warn 不放共享 helper)。
        let conn = open_decrypted_db_vfs(shard, &self.key)?;
        // **第6轮复审#1 + 追修(codex #2/#3, Claude 双审)**: sender 表 (Name2Id) 整表读不出 → 空表 (发送人会空); 或
        // 部分行解码失败 (`Ok` 带 dropped>0) → 图缺那几个发送人。两者都记入**持久** `sender_degraded[分片]` (非每查询
        // 计数器 —— 暖连接复用时 ensure 早返回不重开, 每查询计数器会漏第二次查询; 持久图则每次查询循环都重新并入
        // partial)。整表失败额外 warn (非静默兜底)。`rusqlite::Error` 无 PII (只 SQL/表名)。
        let senders = match load_name2id(&conn) {
            Ok(((s, _), dropped)) => {
                if dropped > 0 {
                    // codex #2: `Ok` 但部分 Name2Id 行丢 → 发送人图不全, 原 `|((s,_),_)| s` 丢弃此数、静默。
                    self.sender_degraded.insert(shard.to_path_buf(), dropped);
                }
                s
            }
            Err(e) => {
                tracing::warn!(error = %e, "热查 sender(Name2Id) 读取失败, 发送人可能空");
                self.sender_degraded.insert(shard.to_path_buf(), 1);
                HashMap::new()
            }
        };
        self.senders.insert(shard.to_path_buf(), senders);
        self.conns.insert(shard.to_path_buf(), conn);
        Ok(())
    }

    /// `message_dir` 下消息内容分片 (`message_<n>.db` / `biz_message_<n>.db`)。返 `(分片, 目录读成功?)` ——
    /// **复审(第5轮)#1**: 读消息目录失败 (非"目录空") 也是**丢数据**, 得让 build 据此标 degraded, 别静默返空。
    fn content_shards(&self) -> (Vec<PathBuf>, bool) {
        let mut v = Vec::new();
        // R11: 读消息目录失败 → 无分片 (查询会全空)。io::Error (read_dir) 不含路径, %e 安全。
        let rd = match std::fs::read_dir(&self.message_dir) {
            Ok(rd) => rd,
            Err(e) => {
                tracing::warn!(error = %e, "读消息目录失败, 无分片");
                return (v, false); // 目录读失败 → 调用方 (build) 标 degraded
            }
        };
        let mut scan_ok = true;
        for e in rd {
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    // 第5轮复审#1(P2, codex): 目录**遍历中途**出错 (瞬时 IO) 也漏分片 → 标 scan 失败, build 据此 degraded。
                    tracing::warn!(error = %err, "消息目录条目读取失败, 跳过");
                    scan_ok = false;
                    continue;
                }
            };
            let p = e.path();
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let stem = name.strip_suffix(".db").unwrap_or(name);
            let core = stem.strip_prefix("biz_").unwrap_or(stem);
            if let Some(n) = core.strip_prefix("message_") {
                if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
                    v.push(p);
                }
            }
        }
        (v, scan_ok)
    }
}

/// 分片文件名 (定位表 key, 便携).
fn rel_name(p: &Path) -> Option<String> {
    p.file_name().and_then(|s| s.to_str()).map(ToString::to_string)
}

/// 单文件 (mtime_ns, size); 缺失 = (0,0)。
fn one_stamp(p: &Path) -> (u64, u64) {
    let Ok(m) = std::fs::metadata(p) else { return (0, 0) };
    let mt = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos() as u64);
    (mt, m.len())
}

/// 分片指纹 = 主库 + **WAL** 指纹 (WAL 变=有新消息/新表未刷主库, 必纳入; 否则漏刚建的新群)。
fn file_stamp(p: &Path) -> ShardStamp {
    let (dm, ds) = one_stamp(p);
    let mut wal = p.as_os_str().to_os_string();
    wal.push("-wal");
    let (wm, ws) = one_stamp(Path::new(&wal));
    (dm, ds, wm, ws)
}

/// 删掉 locator 里所有指向某分片的条目 (重扫前清旧)。
fn remove_shard_entries(locator: &mut HashMap<String, Vec<(String, String)>>, rel: &str) {
    for locs in locator.values_mut() {
        locs.retain(|(r, _)| r != rel);
    }
    locator.retain(|_, locs| !locs.is_empty());
}

/// Name2Id 解析: (rowid→user 解 sender, md5(user)→user 反解 conv_id).
type Name2IdPair = (HashMap<i64, String>, HashMap<String, String>);

/// 载 Name2Id (rowid→user_name + md5→user_name)。返 `(映射对, 丢弃行数)` —— **第5轮复审#1(P1)**: 原
/// `filter_map(Result::ok)` **静默丢**行解码失败, 而少一行 = 少一个 conv 的 Msg_ 定位 → 会话消失却无信号。
/// 现在**计数**丢的行, 由 build 据此标 degraded/partial。整表 prepare/query 失败仍走 `?` 上抛。
fn load_name2id(conn: &Connection) -> Result<(Name2IdPair, usize), rusqlite::Error> {
    let mut sender = HashMap::new();
    let mut md5map = HashMap::new();
    let mut st = conn.prepare("SELECT rowid, user_name FROM Name2Id")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let mut dropped = 0usize;
    for row in rows {
        match row {
            Ok((rid, uname)) => {
                let md5 = format!("{:x}", md5::compute(uname.as_bytes()));
                sender.insert(rid, uname.clone());
                md5map.insert(md5, uname);
            }
            Err(e) => {
                tracing::warn!(error = %e, "Name2Id 行解码失败, 跳过 (某 conv 定位可能缺)");
                dropped += 1;
            }
        }
    }
    Ok(((sender, md5map), dropped))
}

/// 列 `Msg_<md5>` 表名。返 `(表名, 丢弃行数)` —— **第5轮复审#1(P1)**: 原 `filter_map(Result::ok)` 静默丢表名读
/// 取失败, 少一表 = 少一个会话 → 计数交 build 标 degraded。非 `Msg_` 表 (正常过滤掉) 不算丢。
fn list_msg_tables(conn: &Connection) -> Result<(Vec<String>, usize), rusqlite::Error> {
    let mut st =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'")?;
    let rows = st.query_map([], |r| r.get::<_, String>(0))?;
    let mut tables = Vec::new();
    let mut dropped = 0usize;
    for row in rows {
        match row {
            Ok(n) if is_msg_table(&n) => tables.push(n),
            Ok(_) => {} // 非 Msg_ 表 (如 Msg_*_fts): 正常过滤, 不算丢
            Err(e) => {
                tracing::warn!(error = %e, "Msg_ 表名读取失败, 跳过 (某会话可能缺)");
                dropped += 1;
            }
        }
    }
    Ok((tables, dropped))
}

/// `^Msg_[0-9a-f]{32}$` 严格判定。
fn is_msg_table(name: &str) -> bool {
    name.len() == 36
        && name.starts_with("Msg_")
        && name[4..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
// 三类定点豁免, 都是为了让测试夹具**照着协议原样写**, 别为迎合 lint 变得看不懂:
//   · decimal_literal_representation: `(5_i64 << 32) | 49` 是"高32位放子类型、低位放主类型"的真实编码,
//     把 49 写成 0x31 反而对不上文档里的十进制类型码。
//   · identity_op / erasing_op: `(5 << 3) | 0` 是 protobuf 线格式 (字段号 5, wire type 0), `| 0` 是**结构**,
//     删掉就看不出那一位在表达什么。
//   · format_collect: 测试里把字节转 hex 用 map+format! 最直白, 换 fold+write! 只是为了省一次分配。
#[allow(
    clippy::decimal_bitwise_operands,
    clippy::identity_op,
    clippy::erasing_op,
    clippy::format_collect
)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use rusqlite::Connection;

    use super::{
        is_msg_table, msg_anchor, query_hot_avatars, query_hot_biz_contacts, query_hot_chatrooms, query_hot_contacts,
        query_hot_emoticons, query_hot_favorites, query_hot_finder_visits, query_hot_friend_requests,
        query_hot_members, remove_shard_entries, RawMsgRead, SourceQuery, Wxid,
    };

    // --- 第6轮再审(第三方复审: P3 精度 + 回归测试缺口) ---
    // 会话查询/`Name2Id` 载入都吃 `&Connection` → 拿**内存明文 SQLite** 单测, 无需伪造加密夹具 (加密源库只有解密路径,
    // 无法在测试内造 SQLCipher 库)。covered: (1) has_more limit+1 哨兵精度含"满末页"边界; (2) 丢行计数且 has_more 不受
    // 丢行扰动; (3) Name2Id 部分行失败计 dropped (= ensure_shard_open 的 sender_degraded 探测源, codex #2)。
    // NOT covered (诚实标注, 非静默跳过): "同一 SourceQuery 暖复用第二次查询仍标 partial" 需真加密 message 分片夹具
    // (latest_messages 走 open_decrypted_db_vfs 不可内存造), 结构性正确性已由 codex+Claude 双审对真实复用调用点核过。

    /// 建内存 `SessionTable` (仅填 username + sort_timestamp, 余列 NULL → read_session_row 的 int0/Option 兜)。
    /// sort_timestamp 递减 = 第 0 个最新, ORDER BY DESC 下顺序确定。
    fn mem_session_conn(usernames: &[&str]) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-mem");
        conn.execute_batch(
            "CREATE TABLE SessionTable(
                username TEXT, summary TEXT, last_sender_display_name TEXT,
                unread_count INTEGER, last_msg_type INTEGER, last_msg_sub_type INTEGER,
                sort_timestamp INTEGER, \"type\" INTEGER, is_hidden INTEGER, status INTEGER,
                draft TEXT, last_msg_sender TEXT, last_timestamp INTEGER,
                last_clear_unread_timestamp INTEGER, last_msg_locald_id INTEGER,
                last_msg_ext_type INTEGER, unread_first_msg_srv_id INTEGER);",
        )
        .expect("create SessionTable");
        for (i, u) in usernames.iter().enumerate() {
            let ts = (usernames.len() - i) as i64;
            conn.execute(
                "INSERT INTO SessionTable(username, sort_timestamp) VALUES (?1, ?2)",
                rusqlite::params![u, ts],
            )
            .expect("insert session");
        }
        conn
    }

    #[test]
    fn hot_sessions_has_more_exact_at_boundaries() {
        // 第三方 P3: has_more 走 limit+1 哨兵, **满末页恒 false** (原 None 分支满末页多报一次空页)。
        let p = std::path::Path::new("mem.db");
        let conn = mem_session_conn(&["a", "b", "c", "d", "e"]); // 5 行, ts 5..1, DESC → a,b,c,d,e
                                                                 // 首页 limit=2 → 还有
        let (r0, hm0, total0, drop0) = super::query_hot_sessions(&conn, p, 2, 0).unwrap();
        assert_eq!(r0.len(), 2);
        assert!(hm0, "5 行取前 2 → 还有");
        assert_eq!(total0, Some(5), "COUNT 精确全量");
        assert_eq!(drop0, 0);
        // 末页正好取满 (offset=4, limit=1, 剩 1 行) → 到底 (哨兵不存在)
        let (r1, hm1, ..) = super::query_hot_sessions(&conn, p, 1, 4).unwrap();
        assert_eq!(r1.len(), 1);
        assert!(!hm1, "末页正好取满 → 到底 (P3 核心: 不多报空页)");
        // 最后 2 行一页取满 (offset=3, limit=2) → 到底
        let (r2, hm2, ..) = super::query_hot_sessions(&conn, p, 2, 3).unwrap();
        assert_eq!(r2.len(), 2);
        assert!(!hm2);
        // limit 大于剩余 (offset=3, limit=5) → 到底
        let (r3, hm3, ..) = super::query_hot_sessions(&conn, p, 5, 3).unwrap();
        assert_eq!(r3.len(), 2);
        assert!(!hm3);
        // 一页取满全部 5 行 (offset=0, limit=5) → 到底; 取 4 剩 1 → 还有
        let (_r4, hm4, ..) = super::query_hot_sessions(&conn, p, 5, 0).unwrap();
        assert!(!hm4, "一页取满全部 → 到底");
        let (_r5, hm5, ..) = super::query_hot_sessions(&conn, p, 4, 0).unwrap();
        assert!(hm5, "取 4 剩 1 → 还有");
        // offset 超界 → 空 + 到底
        let (r6, hm6, ..) = super::query_hot_sessions(&conn, p, 2, 10).unwrap();
        assert!(r6.is_empty());
        assert!(!hm6);
    }

    #[test]
    fn hot_sessions_drops_bad_rows_but_has_more_stays_exact() {
        // 坏行 (username NULL → read_session_row 的 get::<String> 失败) 计入 dropped, 且 has_more 由**原始取到行数**(哨兵)
        // 定、不受丢行影响 → "COUNT 失败且有坏行"类的 has_more 精度在此结构性成立 (哨兵不依赖 COUNT)。
        let p = std::path::Path::new("mem.db");
        let conn = mem_session_conn(&["a", "b", "c"]); // ts 3,2,1
        conn.execute(
            "INSERT INTO SessionTable(username, sort_timestamp) VALUES (NULL, 0)",
            [],
        )
        .unwrap(); // 第 4 行坏 (NULL username), ts=0 排最后
                   // limit=4 全取: 3 好 + 1 坏 → data=3, dropped=1, 无哨兵 → 到底
        let (rows, hm, total, dropped) = super::query_hot_sessions(&conn, p, 4, 0).unwrap();
        assert_eq!(rows.len(), 3, "3 好行映射成功");
        assert_eq!(dropped, 1, "1 坏行 (NULL username) 计入 dropped, 非静默");
        assert!(!hm, "4 行一页取满(含坏行) → 到底; 哨兵按原始行数判, 不因丢行误报还有");
        assert_eq!(total, Some(4), "COUNT 含坏行");
        // limit=2: 消费 2 原始行, 第 3 行哨兵存在 → 还有 (即便后续行会丢)
        let (_r, hm2, ..) = super::query_hot_sessions(&conn, p, 2, 0).unwrap();
        assert!(hm2, "取 2 行后仍有原始行 → 还有 (哨兵)");
    }

    /// **R16-3 fav_tags** (codex P1 + Claude P3-2 固化): query_hot_favorite_tags 的 LEFT JOIN(缺标签名→空串)+
    /// 按 anchor 去重**保后写**(对齐冷 upsert; ORDER BY b.rowid 升序 → insert 覆盖 → 最高 rowid 胜)+ 排序
    /// (tag_server_id DESC, source_native_id DESC)。内存夹具含: 一标签贴多收藏(同 tsid 破并列)/ 缺标签名(空串)/
    /// server_id=0 交叉 JOIN 多名(验保后写)。
    fn mem_fav_tag_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-mem");
        conn.execute_batch(
            "CREATE TABLE fav_tag_db_item(local_id INTEGER, server_id INTEGER, name TEXT);
             CREATE TABLE fav_bind_tag_db_item(tag_server_id INTEGER, fav_server_id INTEGER,
                 tag_local_id INTEGER, fav_local_id INTEGER);",
        )
        .expect("create fav tables");
        // 标签维表: local1/server100=工作 / local2/server200=生活 / **local3/server0=草稿(未同步)**。
        for (lid, sid, name) in [(1, 100, "工作"), (2, 200, "生活"), (3, 0, "草稿")] {
            conn.execute(
                "INSERT INTO fav_tag_db_item(local_id,server_id,name) VALUES (?1,?2,?3)",
                rusqlite::params![lid, sid, name],
            )
            .expect("insert tag");
        }
        // 绑定 (tag_server_id, fav_server_id, tag_local_id, fav_local_id): 工作→fav50/fav30, 生活→fav50,
        // **未同步草稿(server0/local3)绑两条不同收藏(fav70/fav80)** —— server_id 都 0 但 local 锚不同 → 不塌陷,
        // JOIN on local_id=3 精确得"草稿"(非交叉); 末绑定 tag_local_id=99 无对应标签 → LEFT JOIN NULL → 空串。
        for (tsid, fsid, tlid, flid) in [
            (100, 5, 1, 50),
            (100, 3, 1, 30),
            (200, 5, 2, 50),
            (0, 7, 3, 70),
            (0, 8, 3, 80),
            (999, 5, 99, 55),
        ] {
            conn.execute(
                "INSERT INTO fav_bind_tag_db_item(tag_server_id,fav_server_id,tag_local_id,fav_local_id) \
                 VALUES (?1,?2,?3,?4)",
                rusqlite::params![tsid, fsid, tlid, flid],
            )
            .expect("insert bind");
        }
        conn
    }

    #[test]
    fn hot_fav_tags_leftjoin_local_join_no_collapse() {
        let p = std::path::Path::new("fav.db");
        let conn = mem_fav_tag_conn();
        let (rows, has_more, total, dropped) = super::query_hot_favorite_tags(&conn, p, 100, 0).unwrap();
        assert_eq!(dropped, 0);
        assert!(!has_more);
        // **6 唯一 anchor(local id)**: 两条未同步 (server0) 绑定 local 锚不同 → **不塌陷**(server id 锚会塌成 1)。
        assert_eq!(total, Some(6), "local 锚 → 未同步两绑定不塌陷");
        assert_eq!(rows.len(), 6);
        // 排序 tag_server_id DESC, source_native_id(local 锚)DESC: 999 > 200 > 100(_1_50 > _1_30) > 0(_3_80 > _3_70)。
        let got: Vec<(i64, i64, &str)> = rows
            .iter()
            .map(|r| (r.tag_server_id, r.fav_server_id, r.tag_name.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (999, 5, ""), // tag_local_id=99 无对应标签 → LEFT JOIN NULL → 空串
                (200, 5, "生活"),
                (100, 5, "工作"), // 一标签(local1)贴多收藏, local 锚破并列
                (100, 3, "工作"),
                (0, 8, "草稿"), // **未同步 local JOIN 精确得"草稿"(非交叉误标)**
                (0, 7, "草稿"), // 另一未同步绑定 **不与上条塌陷**(local 锚不同)
            ],
            "local JOIN 精确名 + 未同步不塌陷 + LEFT JOIN 缺→空串 + local 锚全序"
        );
        // 翻页: offset=2 取 2 → 第 3、4 行 (100/5, 100/3)。
        let (pg, _hm, _t, _d) = super::query_hot_favorite_tags(&conn, p, 2, 2).unwrap();
        let pg_got: Vec<(i64, i64)> = pg.iter().map(|r| (r.tag_server_id, r.fav_server_id)).collect();
        assert_eq!(pg_got, vec![(100, 5), (100, 3)], "offset 翻页确定");
    }

    #[test]
    fn load_name2id_counts_dropped_rows() {
        // 第三方"Name2Id 部分行失败"类: 整表可读但个别行解码失败 (user_name NULL → get::<String> 失败) → 计 dropped,
        // 好行仍入 sender 图。ensure_shard_open 的 Ok 分支据此 dropped>0 记 sender_degraded → partial (codex #2 探测源)。
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE Name2Id(user_name TEXT);").unwrap();
        conn.execute("INSERT INTO Name2Id(rowid, user_name) VALUES (1, 'wxid_good')", [])
            .unwrap();
        conn.execute("INSERT INTO Name2Id(rowid, user_name) VALUES (2, NULL)", [])
            .unwrap(); // 坏行
        conn.execute("INSERT INTO Name2Id(rowid, user_name) VALUES (3, 'wxid_ok')", [])
            .unwrap();
        let ((sender, md5map), dropped) = super::load_name2id(&conn).unwrap();
        assert_eq!(dropped, 1, "1 行 (NULL user_name) 解码失败计入 dropped, 非静默");
        assert_eq!(sender.len(), 2, "2 好行入 sender 图");
        assert_eq!(sender.get(&1).map(String::as_str), Some("wxid_good"));
        assert_eq!(sender.get(&3).map(String::as_str), Some("wxid_ok"));
        assert_eq!(md5map.len(), 2, "2 好行入 md5→user 反解图");
    }

    #[test]
    fn msg_table_whitelist() {
        assert!(is_msg_table("Msg_0123456789abcdef0123456789abcdef"));
        assert!(!is_msg_table("Name2Id"));
        assert!(!is_msg_table("Msg_0123456789abcdef0123456789abcdef_fts"));
        assert!(!is_msg_table("Msg_XYZ"));
        assert!(!is_msg_table("Msg_0123456789ABCDEF0123456789ABCDEF"));
    }

    #[test]
    fn remove_shard_entries_drops_only_that_shard() {
        let mut loc: HashMap<String, Vec<(String, String)>> = HashMap::new();
        loc.insert(
            "g@chatroom".into(),
            vec![
                ("message_1.db".into(), "Msg_a".into()),
                ("message_2.db".into(), "Msg_a".into()),
            ],
        );
        loc.insert("x".into(), vec![("message_1.db".into(), "Msg_b".into())]);
        remove_shard_entries(&mut loc, "message_1.db");
        assert_eq!(
            loc["g@chatroom"],
            vec![("message_2.db".to_string(), "Msg_a".to_string())]
        );
        assert!(!loc.contains_key("x"), "只剩 message_1 条目的 conv 被清空");
    }

    /// R5 扩全: decode_msg_row 全字段 + 派生复用 ingest 纯函数 (与冷查零漂移)。local_type 打包
    /// (sub 5 << 32 | base 49) → APP_XML/LINK, 同真跑坐实的 21474836529。
    #[test]
    fn decode_msg_row_full_fields_link_appmsg() {
        let rr = RawMsgRead {
            local_id: 175,
            server_id: 7684,
            server_seq: 829,
            origin_source: 2,
            upload_status: 0,
            download_status: 0,
            local_type: (5_i64 << 32) | 0x31, // 0x31=49 (base type); hex 让 clippy 不嫌 bitwise 用十进制
            sort_seq: 1_700_000_000_000,
            create_time: 1_700_000_000,
            status: 3,
            real_sender_id: None,
            mc_hex: hex::encode(b"hi"), // 明文
            src_hex: String::new(),     // R16-0: 无 msgsource (本例不测 @提及)
        };
        let (m, content_ok) = SourceQuery::decode_msg_row(false, "wxid_peer", None, &rr, "wxid_self_acct");
        assert!(content_ok, "第6轮#1: 有效明文正文 → content_ok=true (不误报降级)");
        // R16-0 (审 P3-2): conv_id 透传断言 —— 全局扫命令 (calls/links/events…) 靠这列按会话归属。
        assert_eq!(m.conv_id, "wxid_peer", "R16-0: conv_id 透传自入参");
        // 派生 (复用 decode_local_type / content_encoding / msg_anchor)。
        assert_eq!(m.source_native_id, msg_anchor("wxid_peer", 175));
        assert_eq!(m.msg_type, 49);
        assert_eq!(m.msg_type_name, "APP_XML");
        assert_eq!(m.msg_sub_type, Some(5));
        assert_eq!(m.msg_sub_type_name.as_deref(), Some("LINK"));
        assert_eq!(m.decode_kind, "plain");
        assert_eq!(m.sys_type, None, "非系统消息无 sys_type");
        assert_eq!(m.text, "hi");
        // 原始列直取无派生。
        assert_eq!(m.local_id, 175);
        assert_eq!(m.server_id, 7684);
        assert_eq!(m.status, 3);
        assert_eq!(
            m.create_time, 1_700_000_000_000,
            "create_time R6 归一为毫秒 (×1000, 同冷查)"
        );
        assert!(!m.is_chatroom);
    }

    /// R5: 系统消息 (base 10000) → sys_type 由 classify_sysmsg 分类 (同冷查 project_message 路)。
    #[test]
    fn decode_msg_row_system_message_has_sys_type() {
        let rr = RawMsgRead {
            local_id: 1,
            server_id: 1,
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            local_type: 10000,
            sort_seq: 0,
            create_time: 0,
            status: 0,
            real_sender_id: None,
            mc_hex: hex::encode("你撤回了一条消息".as_bytes()),
            src_hex: String::new(), // R16-0: 无 msgsource
        };
        let (m, _content_ok) = SourceQuery::decode_msg_row(false, "wxid_x", None, &rr, "wxid_self_acct");
        assert_eq!(m.msg_type, 10000);
        assert_eq!(m.msg_type_name, "SYSTEM");
        assert_eq!(
            m.sys_type.as_deref(),
            Some("revoke"),
            "撤回文本 classify_sysmsg → revoke (同冷查)"
        );
    }

    /// **R16-2 性能地基 (类型预过滤的核心正确性)**: `scan_all_messages` 的 SQL 过滤
    /// `(local_type & 0xFFFFFFFF) IN (base…)` 必须与闭包侧口径 `decode_local_type(local_type).base == base`
    /// **逐行等价** —— 否则热查按 SQL 选行、冷查按 base 选行, 行集**静默分叉**(events/calls/links 全批受累)。
    ///
    /// 用普通内存表(免 SourceQuery/VFS/加密分片的重夹具)锁 SQLite 64 位**位与**语义对每个 R16-2 base
    /// (10000/50/49/1/3)== Rust `decode_local_type`。关键坏夹具: `base==49` 的行**高 32 位非 0**(带
    /// appmsg 子类型), 若误写成 `local_type IN (49)`(漏位与)就会漏掉所有带子类型的 appmsg → 此测逮死。
    #[test]
    fn scan_type_filter_sql_matches_decode_local_type_base() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE m(local_id INTEGER, local_type INTEGER);")
            .unwrap();
        // 各 base 造行: 纯 base(高位 0) + base==49 带子类型(高位非 0, 仍应认作 base 49)。
        let samples: &[i64] = &[
            1,                     // TEXT
            3,                     // IMAGE
            50,                    // VOIP
            10000,                 // SYSTEM
            49,                    // APP_XML sub=0
            (5_i64 << 32) | 49,    // APP_XML sub=5 (LINK) —— 高 32 位非 0
            (19_i64 << 32) | 49,   // APP_XML sub=19 (FORWARD)
            (2000_i64 << 32) | 49, // APP_XML sub=2000 (TRANSFER)
        ];
        for (i, &lt) in samples.iter().enumerate() {
            conn.execute(
                "INSERT INTO m(local_id, local_type) VALUES (?1, ?2)",
                rusqlite::params![i as i64, lt],
            )
            .unwrap();
        }
        // 每个 base: SQL 位与过滤选出的集 == Rust decode_local_type.base 口径选出的集。
        for base in [1_i32, 3, 49, 50, 10000] {
            let mut st = conn
                .prepare(&format!(
                    "SELECT local_type FROM m WHERE (local_type & 4294967295) IN ({base}) ORDER BY local_id"
                ))
                .unwrap();
            let mut sql_hits: Vec<i64> = st
                .query_map([], |r| r.get::<_, i64>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            sql_hits.sort_unstable();
            let mut rust_hits: Vec<i64> = samples
                .iter()
                .copied()
                .filter(|&lt| crate::decode_local_type(lt).base == base)
                .collect();
            rust_hits.sort_unstable();
            assert_eq!(
                sql_hits, rust_hits,
                "base {base}: SQL 位与过滤与 decode_local_type.base 口径分叉"
            );
        }
        // 多 base 同时(links 族/calls 常一次要 49+50): 49 出现 4 次(sub 0/5/19/2000)+ 50 一次 = 5 行。
        let mut st = conn
            .prepare("SELECT local_type FROM m WHERE (local_type & 4294967295) IN (49, 50) ORDER BY local_id")
            .unwrap();
        let multi: Vec<i64> = st
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(multi.len(), 5, "IN(49,50) 应命中 4 个 appmsg + 1 个 voip");
    }

    /// **R16-2 (codex 审 P2)**: 类型预过滤的 `typeof(local_type) <> 'integer'` 兜底 —— 损坏行
    /// (local_type 存 NULL/BLOB/文本)**不能**被 WHERE 静默滤掉, 否则它绕过 `read_raw_msg` 的 i64 转换
    /// 失败计数(`dropped_rows`), `partial` 信号丢, 违背 scan_all_messages "不完整性不静默"契约。
    /// 断言带兜底谓词放行损坏行(随后在 read_raw_msg 转换失败被计 dropped); 负对照证旧谓词会静默漏掉。
    #[test]
    fn scan_type_filter_admits_malformed_local_type_for_drop_accounting() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE m(local_id INTEGER, local_type INTEGER);")
            .unwrap();
        conn.execute("INSERT INTO m VALUES (1, 10000)", []).unwrap(); // 合法匹配
        conn.execute("INSERT INTO m VALUES (2, 1)", []).unwrap(); // 合法不匹配
        conn.execute("INSERT INTO m VALUES (3, NULL)", []).unwrap(); // 损坏: NULL
        conn.execute("INSERT INTO m VALUES (4, x'1027')", []).unwrap(); // 损坏: BLOB
                                                                        // 带兜底谓词(= scan_all_messages 现构造): 匹配行 + 所有非整数(损坏)行都放行。
        let guarded: Vec<i64> = conn
            .prepare("SELECT local_id FROM m WHERE (local_type & 4294967295) IN (10000) OR typeof(local_type) <> 'integer' ORDER BY local_id")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            guarded,
            vec![1, 3, 4],
            "带兜底: 匹配行(1)+损坏行(3 NULL,4 BLOB) 全放行, 合法不匹配(2)被滤"
        );
        // 负对照: 旧谓词(无兜底)漏掉损坏行 3/4 → 它们绕过 read_raw_msg 静默消失(codex P2 复现)。
        let unguarded: Vec<i64> = conn
            .prepare("SELECT local_id FROM m WHERE (local_type & 4294967295) IN (10000) ORDER BY local_id")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            unguarded,
            vec![1],
            "旧谓词漏掉损坏行 3/4 (证 P2: 静默丢, 无 dropped 计数)"
        );
    }

    /// **R16-1 (对抗审 P1-2 的修 · 坏夹具)**: 丢行时 `has_more` **不许少报**, 否则静默藏数据。
    ///
    /// 审真跑复现的剧情: 5 行在库、第 1 行映射失败、limit=2 → 判哨兵若写 `rows.len() >= limit`,
    /// 丢的那行会让**哨兵行被当数据行吃掉** → 返 2 行 + `has_more=false` → 消费方停止翻页, **后面
    /// 两行永远看不到**。模板 `query_hot_sessions` 本来就是 `.saturating_add(dropped)`, 我抄漏了,
    /// 而且同错扩散到 favorites/friend_requests。
    ///
    /// **为什么必须造坏夹具**: 原 `hot_contacts_has_more_is_exact` 的数据 0 丢行 → dropped 恒 0 →
    /// 两种写法结果**完全一样**、照绿。这正是"顺路数据测不到只在坏数据上发作的 bug"。故此测让
    /// nick_name 存 BLOB (`get::<String>` 必失败 → 该行被丢)。
    #[test]
    fn hot_contacts_has_more_not_understated_when_rows_dropped() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE contact(username TEXT PRIMARY KEY, nick_name, remark TEXT, alias TEXT, local_type INTEGER);
             INSERT INTO contact VALUES('wxid_1', x'DEADBEEF', 'r1', 'a1', 3);
             INSERT INTO contact VALUES('wxid_2', '昵称2', 'r2', 'a2', 3);
             INSERT INTO contact VALUES('wxid_3', '昵称3', 'r3', 'a3', 3);
             INSERT INTO contact VALUES('wxid_4', '昵称4', 'r4', 'a4', 3);
             INSERT INTO contact VALUES('wxid_5', '昵称5', 'r5', 'a5', 3);",
        )
        .unwrap();
        let (rows, has_more, total, dropped) = query_hot_contacts(&conn, Path::new("x"), None, 2, 0).unwrap();
        assert_eq!(dropped, 1, "BLOB 行映射失败 → 被丢");
        assert_eq!(total, Some(5), "库里确实 5 行");
        assert!(
            has_more,
            "丢行不许让 has_more 少报 —— 5 行在库只出了 {} 行, 若报 has_more=false 消费方就停翻页, \
             后面的行永远看不到 (审 P1-2 真跑复现过)",
            rows.len()
        );
    }

    /// **R16-1**: 热查 finder —— **跳空壳行的判据必须和 ingest 一模一样**, 且只跳"三者全空"的。
    ///
    /// 这条是本命令的真坑。夹具**故意造坏数据**(顺路夹具测不到):
    /// - 行1: 三者全空 = **真空壳** → ingest 不落 L1, 热查必须也跳
    /// - 行2: name/url 空但 **visit_time 非 0** → **不是空壳**(真库 723 行里头两条就长这样), 跳了就丢数据
    /// - 行3: 完整行
    /// - 行4: 与行3 **visit_time 并列** → 验次键把序定死
    ///
    /// 判据搞错任一边, 冷热行集就分叉 —— 而冷查测冷查、热查测热查, **两边各自都会绿**。
    #[test]
    fn hot_finder_skips_only_true_empty_shells_and_pages_stably() {
        // proto: f2(str)=name / f5(varint)=visit_time / f6(str)=url —— 同 decoder/finder.rs 的造法。
        fn proto(name: &str, ts: u64, url: &str) -> Vec<u8> {
            let mut b = Vec::new();
            let put_str = |b: &mut Vec<u8>, fno: u8, s: &str| {
                if s.is_empty() {
                    return;
                }
                b.push((fno << 3) | 2);
                b.push(u8::try_from(s.len()).unwrap());
                b.extend_from_slice(s.as_bytes());
            };
            put_str(&mut b, 2, name);
            if ts != 0 {
                b.push((5 << 3) | 0);
                let mut v = ts;
                loop {
                    let byte = u8::try_from(v & 0x7f).unwrap();
                    v >>= 7;
                    b.push(if v == 0 { byte } else { byte | 0x80 });
                    if v == 0 {
                        break;
                    }
                }
            }
            put_str(&mut b, 6, url);
            b
        }
        let hex = |v: &[u8]| v.iter().map(|b| format!("{b:02X}")).collect::<String>();

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE wcfinderuserpage(username TEXT, extra_buffer BLOB);")
            .unwrap();
        let rows = [
            ("wxid_shell", proto("", 0, "")),              // 真空壳 → 该跳
            ("wxid_tsonly", proto("", 1_784_109_436, "")), // 只有时刻 → **不是**空壳
            ("wxid_full", proto("频道A", 1_784_099_379, "https://x/a")),
            ("wxid_tie", proto("频道B", 1_784_099_379, "https://x/b")), // 与上行 visit_time 并列
        ];
        for (u, p) in &rows {
            conn.execute(
                "INSERT INTO wcfinderuserpage(username, extra_buffer) VALUES(?1, x'' || ?2)",
                rusqlite::params![u, hex(p)],
            )
            .ok();
            // x'' || hex 在部分 SQLite 版本不生效 → 直接塞 BLOB 更稳。
            conn.execute("DELETE FROM wcfinderuserpage WHERE username = ?1", [u])
                .unwrap();
            conn.execute(
                "INSERT INTO wcfinderuserpage(username, extra_buffer) VALUES(?1, ?2)",
                rusqlite::params![u, p.as_slice()],
            )
            .unwrap();
        }
        let me = Wxid::try_new("wxid_me").unwrap();

        let (all, has_more, total, dropped) = query_hot_finder_visits(&conn, Path::new("x"), &me, 50, 0).unwrap();
        assert_eq!(dropped, 0, "夹具无坏行");
        assert_eq!(
            total,
            Some(3),
            "4 行进去, 只有 wxid_shell 是三者全空的真空壳该跳 → 剩 3。\
             若得 2 = 把只有 visit_time 的行也当空壳跳了(真库那种行会被丢); 若得 4 = 没跳空壳(比冷查多行)"
        );
        assert!(!has_more, "50 > 3, 到底了");
        let names: Vec<&str> = all.iter().map(|r| r.owner_username.as_str()).collect();
        assert!(
            !names.contains(&"wxid_shell"),
            "真空壳必须跳 —— ingest 不落 L1, 热查留着就多行"
        );
        assert!(
            names.contains(&"wxid_tsonly"),
            "只有 visit_time 的行**不是**空壳, 跳了就丢真数据"
        );

        // visit_time DESC + owner_username DESC 次键: tie/full 并列 → 序必须定死。
        assert_eq!(
            names,
            ["wxid_tsonly", "wxid_tie", "wxid_full"],
            "排序该是 visit_time DESC, 并列时 owner_username DESC"
        );
        // 并列行上翻页不重不漏。
        let (p1, m1, _, _) = query_hot_finder_visits(&conn, Path::new("x"), &me, 2, 0).unwrap();
        let (p2, m2, _, _) = query_hot_finder_visits(&conn, Path::new("x"), &me, 2, 2).unwrap();
        assert!(m1, "第 1 页后还有");
        assert!(!m2, "第 2 页到底");
        let paged: Vec<&str> = p1.iter().chain(p2.iter()).map(|r| r.owner_username.as_str()).collect();
        assert_eq!(paged, names, "翻页拼起来 == 一次全取, 不重不漏");
        // visit_date 必须是 SQLite 的 localtime 口径 (与冷查同函数)。
        let want: String = conn
            .query_row("SELECT date(?1, 'unixepoch', 'localtime')", [1_784_099_379_i64], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            all[2].visit_date, want,
            "visit_date 必须走 SQLite date(), 不能 Rust 自己算"
        );

        // codex 审 P2: limit=0 且 offset<total 时若报 has_more=true, 消费方按 `offset += limit`
        // 翻页 = `offset += 0` → **永不终止**。
        let (z, zmore, ztotal, _) = query_hot_finder_visits(&conn, Path::new("x"), &me, 0, 0).unwrap();
        assert!(z.is_empty(), "limit=0 → 空页");
        assert!(
            !zmore,
            "limit=0 不许报 has_more=true —— 那会让 offset+=limit 的消费方死循环"
        );
        assert_eq!(ztotal, Some(3), "但 total 仍是真数");

        // offset 到底 / 超界: has_more 不许谎报还有。
        let (e1, m1, _, _) = query_hot_finder_visits(&conn, Path::new("x"), &me, 2, 3).unwrap();
        assert!(e1.is_empty() && !m1, "offset==total → 空页且到底");
        let (e2, m2, _, _) = query_hot_finder_visits(&conn, Path::new("x"), &me, 2, 999).unwrap();
        assert!(e2.is_empty() && !m2, "offset 超界 → 空页且到底");
    }

    /// **R16-1(轮5 审 P2)**: 有行**产不出来**时, `total` 仍须是**冷查 count(*) 的口径**(表里的行数),
    /// 不是"我成功解出的行数"。
    ///
    /// 审的三段证据链: SQLite `date(?,'unixepoch','localtime')` 对**越界** visit_time 返 NULL →
    /// rusqlite `get::<String>` 报错 → 我 `continue` → 而那个 continue 发生在 `all.len()` 之前 →
    /// **热 total 少一行**; 真跑冷查塞越界值实测 **冷 total=724 / 热 723**。
    /// proto f5 是 `u64 as i64`, 一个畸形/损坏的 buffer 就能解出 `i64::MAX` → 真会发生。
    ///
    /// 我上一版还写着"个别行丢是安全区: data 完整, 标 partial 就够" —— **恰好反了**: data 确实完整,
    /// **total 不完整**, 它悄悄比冷查少, 没人看得出来。→ 计数(non_shell)与产出(all)分开记。
    #[test]
    fn hot_finder_total_counts_rows_it_cannot_render() {
        fn proto_ts(ts: u64) -> Vec<u8> {
            let mut b = vec![(2 << 3) | 2, 3];
            b.extend_from_slice("aaa".as_bytes()); // f2 name 非空 → 不是空壳
            b.push((5 << 3) | 0); // f5 varint
            let mut v = ts;
            loop {
                let byte = u8::try_from(v & 0x7f).unwrap();
                v >>= 7;
                b.push(if v == 0 { byte } else { byte | 0x80 });
                if v == 0 {
                    break;
                }
            }
            b
        }
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE wcfinderuserpage(username TEXT, extra_buffer BLOB);")
            .unwrap();
        for (u, ts) in [
            ("wxid_ok1", 1_784_099_379_u64),
            ("wxid_bad", u64::try_from(i64::MAX).unwrap()), // date() 对它返 NULL → 产不出
            ("wxid_ok2", 1_784_109_436),
        ] {
            conn.execute(
                "INSERT INTO wcfinderuserpage(username, extra_buffer) VALUES(?1, ?2)",
                rusqlite::params![u, proto_ts(ts).as_slice()],
            )
            .unwrap();
        }
        let me = Wxid::try_new("wxid_me").unwrap();
        let (rows, has_more, total, dropped) = query_hot_finder_visits(&conn, Path::new("x"), &me, 50, 0).unwrap();

        assert_eq!(dropped, 1, "越界 visit_time 那行 date() 算不出 → 产不出, 计 dropped");
        assert_eq!(rows.len(), 2, "只产出 2 行");
        assert_eq!(
            total,
            Some(3),
            "**total 必须是 3(表里非空壳的行数 = 冷查 count(*) 的口径), 不是 2(我解出几行)** —— \
             报 2 的话冷 3/热 2 静默分叉, 而 data 看起来是完整的, 没人看得出来"
        );
        assert!(!has_more, "50 > 3, 到底了");
    }

    /// **R16-1(members, 降级件)**: 热查群成员 —— role 判定/排序/`admins_only` 过滤/`display_name` 空归 null
    /// 全对齐冷查 `members_query`; 且**明说降级**: `joined_at` 内核压根不出(源库 proto 无此字段, 皮填 null),
    /// 已退群成员源库不留(冷查 L1 跨账号累计才有) —— 热查只是**当前快照**。
    ///
    /// 造 `chat_room` 一行: `owner` 列=群主 wxid, `ext_buffer`=成员 proto blob (每成员 field1=wxid /
    /// field2=群昵称 / field3=admin flags bit2048 / field4=邀请人)。role 三态都要覆盖。
    #[test]
    fn hot_members_role_sort_and_admins_only_filter() {
        // ── proto 编码 helper (同 roomdata.rs 测试模块) ──
        fn varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let mut byte = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
                if v == 0 {
                    break;
                }
            }
            out
        }
        fn len_field(field_no: u64, payload: &[u8]) -> Vec<u8> {
            let mut out = varint((field_no << 3) | 2);
            out.extend(varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }
        fn str_field(field_no: u64, s: &str) -> Vec<u8> {
            len_field(field_no, s.as_bytes())
        }
        fn vfield(field_no: u64, v: u64) -> Vec<u8> {
            let mut out = varint(field_no << 3);
            out.extend(varint(v));
            out
        }
        // 一个成员 submessage (顶层 field_no 任取 1, parse_roomdata 只看内层)。
        fn member(fields: &[Vec<u8>]) -> Vec<u8> {
            let mut inner = Vec::new();
            for f in fields {
                inner.extend_from_slice(f);
            }
            len_field(1, &inner)
        }

        // owner=wxid_owner; 成员 4 个: owner / admin(bit2048) / 两个 member。
        let mut ext = Vec::new();
        ext.extend(member(&[str_field(1, "wxid_owner"), str_field(2, "群主老王")]));
        ext.extend(member(&[
            str_field(1, "wxid_admin"),
            str_field(2, "管理员小李"),
            vfield(3, 2049),            // 0x801 含 bit2048 → admin
            str_field(4, "wxid_owner"), // 被 owner 拉进群
        ]));
        ext.extend(member(&[str_field(1, "wxid_zoe"), str_field(2, "")])); // 群昵称空 → 皮出 null
        ext.extend(member(&[str_field(1, "wxid_amy"), str_field(2, "阿美")]));

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE chat_room(username TEXT PRIMARY KEY, owner TEXT, ext_buffer BLOB);")
            .unwrap();
        conn.execute(
            "INSERT INTO chat_room(username, owner, ext_buffer) VALUES('room@chatroom','wxid_owner',?1)",
            rusqlite::params![ext.as_slice()],
        )
        .unwrap();

        // ── 全量 (admins_only=false) ──
        let (all, has_more, total, dropped) =
            query_hot_members(&conn, Path::new("x"), "room@chatroom", false, 50, 0).unwrap();
        assert_eq!(dropped, 0, "members 不丢行");
        assert_eq!(total, Some(4), "4 个成员");
        assert!(!has_more, "50 > 4, 到底");
        // 排序 ORDER BY role, member_wxid (role 字典序 admin<member<owner)。
        let seq: Vec<(&str, &str)> = all.iter().map(|m| (m.role.as_str(), m.member_wxid.as_str())).collect();
        assert_eq!(
            seq,
            [
                ("admin", "wxid_admin"),
                ("member", "wxid_amy"),
                ("member", "wxid_zoe"),
                ("owner", "wxid_owner"),
            ],
            "role 升序(admin<member<owner), 同 role 内 member_wxid 升序 —— 同冷查 ORDER BY role, member_wxid"
        );
        // display_name: 空群昵称归 null (同冷查 non_empty), 非空原样。
        let zoe = all.iter().find(|m| m.member_wxid == "wxid_zoe").unwrap();
        assert_eq!(zoe.display_name, None, "群昵称空串 → null(非空串), 对齐冷查 non_empty");
        let admin = all.iter().find(|m| m.member_wxid == "wxid_admin").unwrap();
        assert_eq!(admin.display_name.as_deref(), Some("管理员小李"));
        assert_eq!(admin.invited_by.as_deref(), Some("wxid_owner"), "field4 = 邀请人");
        let owner = all.iter().find(|m| m.member_wxid == "wxid_owner").unwrap();
        assert_eq!(owner.role, "owner", "owner 列匹配 → owner, 优先于 admin/member 判定");
        assert_eq!(owner.invited_by, None, "无 field4 → 邀请人 null");

        // ── admins_only=true: 只留 owner/admin (同冷查 where role != 'member') ──
        let (only, _, otot, _) = query_hot_members(&conn, Path::new("x"), "room@chatroom", true, 50, 0).unwrap();
        let roles: Vec<&str> = only.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(
            roles,
            ["admin", "owner"],
            "admins_only 只剩 admin+owner, 两 member 滤掉"
        );
        assert_eq!(
            otot,
            Some(2),
            "admins_only 的 total 是过滤后的 2(同冷查 count 带 where)"
        );

        // ── 翻页不重不漏 (全序稳定) ──
        let (p1, m1, _, _) = query_hot_members(&conn, Path::new("x"), "room@chatroom", false, 2, 0).unwrap();
        let (p2, m2, _, _) = query_hot_members(&conn, Path::new("x"), "room@chatroom", false, 2, 2).unwrap();
        assert!(m1 && !m2, "第1页后还有, 第2页到底");
        let paged: Vec<&str> = p1.iter().chain(p2.iter()).map(|m| m.member_wxid.as_str()).collect();
        let full: Vec<&str> = all.iter().map(|m| m.member_wxid.as_str()).collect();
        assert_eq!(paged, full, "翻页拼起来 == 一次全取");

        // ── limit=0 守卫: 不许报 has_more=true (否则 offset+=0 死循环, 同 finder P2) ──
        let (z, zmore, ztot, _) = query_hot_members(&conn, Path::new("x"), "room@chatroom", false, 0, 0).unwrap();
        assert!(z.is_empty() && !zmore, "limit=0 → 空页且不谎报 has_more");
        assert_eq!(ztot, Some(4), "但 total 仍是真数 4");

        // ── 群不存在(退群/未同步): 空 + total=0, 不报错 ──
        let (none, nmore, ntot, _) = query_hot_members(&conn, Path::new("x"), "ghost@chatroom", false, 50, 0).unwrap();
        assert!(none.is_empty() && !nmore, "找不到群 → 空页");
        assert_eq!(ntot, Some(0), "找不到群 → total=0(同冷查该群无成员)");
    }

    /// **R16-1(codex 审 P2)**: schema 坏(无 `chat_room` 表)时必须**上抛 Err**, 不是 `.ok()` 吞成空群。
    /// 只有 `QueryReturnedNoRows`(群不存在)才是空结果; 坏库读被当空群 = 跟冷查(会报错)静默分叉。
    #[test]
    fn hot_members_propagates_schema_error_not_empty() {
        let conn = Connection::open_in_memory().unwrap();
        // 故意不建 chat_room 表 → query_row 报 "no such table"(非 QueryReturnedNoRows)。
        let r = query_hot_members(&conn, Path::new("x"), "g@chatroom", false, 50, 0);
        assert!(r.is_err(), "无 chat_room 表 → SQL 错必须上抛 Err(不是返回空群)");
    }

    /// **R16-1**: 热查群列表 —— member_count 从 proto 数成员/群名从 contact JOIN/公告从
    /// chat_room_info_detail JOIN/排序 `member_count DESC, chatroom_id`(次键防并列翻页不稳)。
    ///
    /// 造三表(同冷查 drain SQL 的 JOIN): `chat_room`(username/owner/ext_buffer)+ `contact`(群名
    /// nick_name)+ `chat_room_info_detail`(公告 announcement_)。member_count 复用 members 的 proto。
    #[test]
    fn hot_chatrooms_member_count_joins_and_sort() {
        // proto helper: 一个成员 = len_field(1, str_field(1, wxid))。
        fn varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let mut b = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if v == 0 {
                    break;
                }
            }
            out
        }
        fn member(wxid: &str) -> Vec<u8> {
            let mut inner = varint((1 << 3) | 2); // field1 wire2
            inner.extend(varint(wxid.len() as u64));
            inner.extend_from_slice(wxid.as_bytes());
            let mut out = varint((1 << 3) | 2); // 顶层 chunk
            out.extend(varint(inner.len() as u64));
            out.extend_from_slice(&inner);
            out
        }
        fn proto(members: &[&str]) -> Vec<u8> {
            let mut b = Vec::new();
            for m in members {
                b.extend(member(m));
            }
            b
        }

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE chat_room(username TEXT PRIMARY KEY, owner TEXT, ext_buffer BLOB);
             CREATE TABLE contact(username TEXT PRIMARY KEY, nick_name TEXT);
             CREATE TABLE chat_room_info_detail(username_ TEXT PRIMARY KEY, announcement_ TEXT);",
        )
        .unwrap();
        // 群A: 3 成员, 有群名+公告; 群B: 5 成员, 有群名无公告; 群C: 3 成员(与A并列), 无群名无公告。
        // (成员名 ≥6 字符才过 parse_roomdata 的 looks_like_username 启发式)。
        for (u, owner, mem) in [
            ("a@chatroom", "wxid_aa", proto(&["wxid_aa", "wxid_m1", "wxid_m2"])),
            (
                "b@chatroom",
                "wxid_bb",
                proto(&["wxid_bb", "wxid_m1", "wxid_m2", "wxid_m3", "wxid_m4"]),
            ),
            ("c@chatroom", "wxid_cc", proto(&["wxid_cc", "wxid_m1", "wxid_m2"])),
        ] {
            conn.execute(
                "INSERT INTO chat_room(username, owner, ext_buffer) VALUES(?1, ?2, ?3)",
                rusqlite::params![u, owner, mem.as_slice()],
            )
            .unwrap();
        }
        conn.execute("INSERT INTO contact VALUES('a@chatroom','群A名')", [])
            .unwrap();
        conn.execute("INSERT INTO contact VALUES('b@chatroom','群B名')", [])
            .unwrap();
        conn.execute("INSERT INTO chat_room_info_detail VALUES('a@chatroom','群A公告')", [])
            .unwrap();

        let (all, has_more, total, dropped) = query_hot_chatrooms(&conn, Path::new("x"), 50, 0).unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(total, Some(3), "3 个群");
        assert!(!has_more);
        // 排序 member_count DESC, 并列(A/C 都 3 人)按 chatroom_id 升序 → B(5) > a(3) > c(3)。
        let seq: Vec<(&str, i64)> = all.iter().map(|c| (c.chatroom_id.as_str(), c.member_count)).collect();
        assert_eq!(
            seq,
            [("b@chatroom", 5), ("a@chatroom", 3), ("c@chatroom", 3)],
            "member_count DESC + chatroom_id 次键(A/C 并列 3 人按 id 升序 a<c)"
        );
        // 群名/公告 JOIN + non_empty。
        let a = all.iter().find(|c| c.chatroom_id == "a@chatroom").unwrap();
        assert_eq!(a.chatroom_name, "群A名");
        assert_eq!(a.owner_wxid.as_deref(), Some("wxid_aa"));
        assert_eq!(a.announcement.as_deref(), Some("群A公告"));
        let b = all.iter().find(|c| c.chatroom_id == "b@chatroom").unwrap();
        assert_eq!(b.chatroom_name, "群B名");
        assert_eq!(b.announcement, None, "群B 无公告 → null(LEFT JOIN 缺行)");
        let c = all.iter().find(|c| c.chatroom_id == "c@chatroom").unwrap();
        // 群C 无 contact 行 → 群名 "" (空串, 同冷查 unwrap_or_default; 不是 null)。
        assert_eq!(c.chatroom_name, "", "群C 无 contact 行 → 群名 空串(对齐冷查存法)");
        assert_eq!(c.announcement, None);

        // 翻页不重不漏(并列群上)。
        let (p1, m1, _, _) = query_hot_chatrooms(&conn, Path::new("x"), 2, 0).unwrap();
        let (p2, m2, _, _) = query_hot_chatrooms(&conn, Path::new("x"), 2, 2).unwrap();
        assert!(m1 && !m2);
        let paged: Vec<&str> = p1.iter().chain(p2.iter()).map(|c| c.chatroom_id.as_str()).collect();
        assert_eq!(paged, ["b@chatroom", "a@chatroom", "c@chatroom"], "翻页拼起来==全取");
        // limit=0 守卫。
        let (z, zmore, ztot, _) = query_hot_chatrooms(&conn, Path::new("x"), 0, 0).unwrap();
        assert!(z.is_empty() && !zmore, "limit=0 空页不谎报");
        assert_eq!(ztot, Some(3));
    }

    /// **R16-1(codex 审 P2)**: `chat_room.username` **非 PK 可重复**(真 schema 数字 id 才是 PK)。冷查按
    /// chatroom_id INSERT OR REPLACE 保 max rowid 那行 → 热查 chatrooms/members 都得只取 max rowid 行, 否则
    /// 同 chatroom_id 出多行(冷查一行)→ total/翻页分叉。
    #[test]
    fn hot_chatrooms_and_members_dedup_by_max_rowid() {
        fn varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let mut b = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    b |= 0x80;
                }
                out.push(b);
                if v == 0 {
                    break;
                }
            }
            out
        }
        fn member(wxid: &str) -> Vec<u8> {
            let mut inner = varint((1 << 3) | 2);
            inner.extend(varint(wxid.len() as u64));
            inner.extend_from_slice(wxid.as_bytes());
            let mut out = varint((1 << 3) | 2);
            out.extend(varint(inner.len() as u64));
            out.extend_from_slice(&inner);
            out
        }
        fn proto(members: &[&str]) -> Vec<u8> {
            let mut b = Vec::new();
            for m in members {
                b.extend(member(m));
            }
            b
        }
        let conn = Connection::open_in_memory().unwrap();
        // username **非 PK**(数字 id 才是) → 允许 dup。同群两行: 旧行(rowid1, 2成员) + 新行(rowid2, 3成员)。
        conn.execute_batch(
            "CREATE TABLE chat_room(id INTEGER PRIMARY KEY, username TEXT, owner TEXT, ext_buffer BLOB);
             CREATE TABLE contact(username TEXT PRIMARY KEY, nick_name TEXT);
             CREATE TABLE chat_room_info_detail(username_ TEXT PRIMARY KEY, announcement_ TEXT);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_room(id, username, owner, ext_buffer) VALUES(1, 'g@chatroom', 'wxid_o', ?1)",
            rusqlite::params![proto(&["wxid_o", "wxid_m1"]).as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_room(id, username, owner, ext_buffer) VALUES(2, 'g@chatroom', 'wxid_o', ?1)",
            rusqlite::params![proto(&["wxid_o", "wxid_m1", "wxid_m2"]).as_slice()],
        )
        .unwrap();
        conn.execute("INSERT INTO contact VALUES('g@chatroom', '群')", [])
            .unwrap();

        // chatrooms: 只出 1 行(不是 2), member_count=3(max rowid=id2 那行, 3 成员)。
        let (rooms, _, total, _) = query_hot_chatrooms(&conn, Path::new("x"), 50, 0).unwrap();
        assert_eq!(
            total,
            Some(1),
            "dup username 只算 1 群(同冷查 INSERT OR REPLACE), 不是 2"
        );
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].member_count, 3, "取 max rowid 那行(3 成员), 不是旧行 2 成员");

        // members: 同群取 max rowid 行 → 3 成员(不是旧行 2)。
        let (mem, _, mtotal, _) = query_hot_members(&conn, Path::new("x"), "g@chatroom", false, 50, 0).unwrap();
        assert_eq!(mtotal, Some(3), "members 也取 max rowid 行 → 3 成员");
        assert_eq!(mem.len(), 3);
    }

    /// **R16-1**: 热查企微联系人 —— **空 user_id 行必须滤掉**(冷查 pipeline 跳身份缺失行)+ user_name 排序 +
    /// user_id 次键翻页稳。
    #[test]
    fn hot_biz_contacts_filters_empty_user_id_and_sorts() {
        let conn = Connection::open_in_memory().unwrap();
        // 空/NULL user_id 行冷查跳; 两行同 user_name('同名')验 user_id 次键。
        conn.execute_batch(
            "CREATE TABLE user_info(user_id TEXT, brand_user_name TEXT, user_name TEXT, bit_flag INTEGER);
             INSERT INTO user_info VALUES('ww_b@qy', 'gh_b', 'Bob', 0);
             INSERT INTO user_info VALUES('ww_a2@qy', 'gh_a', '同名', 0);
             INSERT INTO user_info VALUES('ww_a1@qy', 'gh_a', '同名', 0);
             INSERT INTO user_info VALUES('', 'gh_x', '空id被跳', 0);
             INSERT INTO user_info VALUES(NULL, 'gh_y', 'NULL被跳', 0);",
        )
        .unwrap();
        let (rows, has_more, total, dropped) = query_hot_biz_contacts(&conn, Path::new("x"), 50, 0).unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(total, Some(3), "5 行, 2 行空/NULL user_id 滤掉 → 3(同冷查 pipeline 跳)");
        assert!(!has_more);
        let ids: Vec<&str> = rows.iter().map(|b| b.user_id.as_str()).collect();
        assert!(!ids.contains(&""), "空 user_id 必须滤掉");
        // user_name 升序, 同名('同名')按 user_id 升序 → Bob, (同名,ww_a1), (同名,ww_a2)。
        let seq: Vec<(&str, &str)> = rows
            .iter()
            .map(|b| (b.user_name.as_str(), b.user_id.as_str()))
            .collect();
        assert_eq!(
            seq,
            [("Bob", "ww_b@qy"), ("同名", "ww_a1@qy"), ("同名", "ww_a2@qy")],
            "user_name 升序 + user_id 次键(同名按 user_id 升序 a1<a2)"
        );
        // 翻页不重不漏。
        let (p0, m0, _, _) = query_hot_biz_contacts(&conn, Path::new("x"), 2, 0).unwrap();
        let (p1, m1, _, _) = query_hot_biz_contacts(&conn, Path::new("x"), 2, 2).unwrap();
        assert!(m0 && !m1);
        let paged: Vec<&str> = p0.iter().chain(p1.iter()).map(|b| b.user_id.as_str()).collect();
        assert_eq!(paged, ["ww_b@qy", "ww_a1@qy", "ww_a2@qy"], "翻页拼起来==全取");
    }

    /// **R16-1**: 热查 friend-requests 字段对齐冷查 + **timestamp 并列时翻页不重不漏**。
    ///
    /// 后者是这条的真坑: 冷查按 `timestamp DESC` 排, 而真库同秒多条申请很常见 —— SQLite 对并列行
    /// 顺序**不保证稳定**, 单键排序下 OFFSET 翻页会重复/漏行。故补 rowid 次键成全序。
    #[test]
    fn hot_friend_requests_fields_and_stable_paging() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE FMessageTable(rowid_ INTEGER PRIMARY KEY, user_name_ TEXT, type_ INTEGER,
                 timestamp_ INTEGER, is_sender_ INTEGER, scene_ INTEGER, content_ TEXT);
             -- 三条**同一 timestamp** (真库常见: 同秒多条) → 单键排序会翻页不稳
             INSERT INTO FMessageTable VALUES(1,'wxid_a',2,1700000000,0,30,'你好我是A');
             INSERT INTO FMessageTable VALUES(2,'wxid_b',2,1700000000,0,17,'名片推荐来的');
             INSERT INTO FMessageTable VALUES(3,'wxid_c',2,1700000000,1,30,'我发出的申请');
             INSERT INTO FMessageTable VALUES(4,'wxid_d',2,1699999999,0,15,'更早的');",
        )
        .unwrap();
        let (rows, has_more, total, dropped) = query_hot_friend_requests(&conn, Path::new("x"), 100, 0).unwrap();
        assert_eq!(dropped, 0);
        assert!(!has_more);
        assert_eq!(total, Some(4));
        // 字段逐个对齐冷查 (源库列名带尾下划线 → 去掉)
        assert_eq!(
            rows[0].user_name, "wxid_c",
            "timestamp DESC + rowid DESC → 同秒内 rowid 大的在前"
        );
        assert_eq!(rows[0].is_sender, 1, "is_sender 透传");
        assert_eq!(
            rows[0].content, "我发出的申请",
            "content_ → content (冷查 json 键名 greeting)"
        );
        assert_eq!(rows[3].user_name, "wxid_d", "更早的排最后");
        assert_eq!(rows[1].scene, 17, "scene 码透传 (皮层用 friend_scene_label 转中文)");
        // **翻页不重不漏**: 同 timestamp 的三条分两页取, 并起来必须恰好是这三条、不重复
        let (p1, more1, _, _) = query_hot_friend_requests(&conn, Path::new("x"), 2, 0).unwrap();
        let (p2, _, _, _) = query_hot_friend_requests(&conn, Path::new("x"), 2, 2).unwrap();
        assert!(more1);
        let mut seen: Vec<&str> = p1.iter().chain(p2.iter()).map(|r| r.user_name.as_str()).collect();
        let n = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), n, "并列 timestamp 翻页**不重复**");
        assert_eq!(seen, vec!["wxid_a", "wxid_b", "wxid_c", "wxid_d"], "也**不漏**");
    }

    /// **R16-1**: contacts 的**可空列**必须走 ingest 同一个 `non_empty` 规矩 (空串/NULL 都 → `None`)。
    ///
    /// 真库全量对拍逮到 **89852 处** `alias`/`remark` 分叉: 源库存的是**空串**, ETL(`assemble_contact`)
    /// 用 `non_empty` 归一成 NULL 落 L1 的可空列 → 冷查出 `null`; 而热查照 `unwrap_or_default()` 出 `""`。
    /// **同一行, 冷 null 热空串** —— 消费方判 `=== null` 和 `=== ''` 行为不同。
    ///
    /// **为什么现有 6 个 hot_contacts 测试一个都没拦住**: 它们的夹具 remark/alias **全填了非空值**
    /// (`'r1'`/`'a1'` 这种) = 顺路夹具 —— 我把字段类型从 `String` 改成 `Option` + 加归一, 6 个测试**全绿**。
    /// 故本测试专造空串/NULL 两种形态。
    ///
    /// `nick_name` 反向锁: 它在 L1 是 `NOT NULL`、ETL 用 `unwrap_or_default()`(空串保留) —— **不能**
    /// 跟着归一, 否则又是反向分叉。
    #[test]
    fn hot_contacts_nullable_cols_normalize_empty_to_none() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE contact(username TEXT PRIMARY KEY, nick_name TEXT, remark TEXT, alias TEXT, local_type INTEGER);
             INSERT INTO contact VALUES('wxid_empty', '', '', '', 3);
             INSERT INTO contact VALUES('wxid_null', '昵称', NULL, NULL, 3);
             INSERT INTO contact VALUES('wxid_set', '昵称2', '备注', 'alias2', 3);",
        )
        .unwrap();
        let (rows, _, _, _) = query_hot_contacts(&conn, Path::new("x"), None, 10, 0).unwrap();
        let by = |u: &str| rows.iter().find(|r| r.username == u).unwrap().clone();

        let e = by("wxid_empty");
        assert_eq!(
            (e.remark, e.alias),
            (None, None),
            "**空串** remark/alias 必须归一成 None —— ETL 用 non_empty 归一后落 L1 的可空列, 冷查出 null; \
             热查照透传成 Some(\"\") 就出 \"\" → 冷热分叉 (真库对拍 89852 处全是这个形态)"
        );
        assert_eq!(
            e.nick_name, "",
            "但 nick_name **空串照留** —— L1 该列 NOT NULL, ETL 也是 unwrap_or_default"
        );

        let n = by("wxid_null");
        assert_eq!((n.remark, n.alias), (None, None), "NULL 同样 → None");

        let s = by("wxid_set");
        assert_eq!(
            (s.remark, s.alias),
            (Some("备注".to_string()), Some("alias2".to_string())),
            "有值的照出, 别误伤"
        );
    }

    /// **R16-1**: 热查 emoticons —— 锁 **源库 `type` → 输出 `emoticon_type`** 的改名 + `md5 DESC` 排序。
    ///
    /// `type` 是 SQL 保留字且 ETL 改了名: 若热查 SQL 写成裸 `type` 会语法错, 或忘了 `AS emoticon_type`
    /// 就跟冷查引擎的输出键对不上。夹具用**乱序 md5** 验 `md5 DESC` 真生效(冷查引擎同键)。
    #[test]
    fn hot_emoticons_type_rename_and_md5_order() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kNonStoreEmoticonTable(md5 TEXT, \"type\" INTEGER, caption TEXT,
                 product_id TEXT, aes_key TEXT, cdn_url TEXT, thumb_url TEXT, tp_url TEXT,
                 extern_url TEXT, extern_md5 TEXT, encrypt_url TEXT);
             INSERT INTO kNonStoreEmoticonTable VALUES('aaa', 3, '笑', 'p1', 'k', 'http://a', '', '', '', '', '');
             INSERT INTO kNonStoreEmoticonTable VALUES('ccc', 5, '哭', 'p2', 'k', 'http://c', '', '', '', '', '');
             INSERT INTO kNonStoreEmoticonTable VALUES('bbb', 7, '怒', 'p3', 'k', 'http://b', '', '', '', '', '');",
        )
        .unwrap();
        let (rows, has_more, total, dropped) = query_hot_emoticons(&conn, Path::new("x"), 50, 0).unwrap();
        assert_eq!(dropped, 0);
        assert!(!has_more);
        assert_eq!(total, Some(3));
        // md5 DESC (同冷查引擎) → ccc / bbb / aaa
        let md5s: Vec<&str> = rows.iter().map(|e| e.md5.as_str()).collect();
        assert_eq!(md5s, ["ccc", "bbb", "aaa"], "md5 DESC 同冷查引擎");
        // 源库 type 列 → emoticon_type 字段 (改名对上)
        assert_eq!(rows[0].emoticon_type, 5, "ccc 的 type=5 → emoticon_type");
        assert_eq!(rows[1].emoticon_type, 7, "bbb 的 type=7");
        assert_eq!(rows[0].caption, "哭");
        assert_eq!(rows[0].cdn_url, "http://c", "cdn_url 要出(json 层)");

        // 翻页不重不漏 (limit=1 逐页)
        let (p0, m0, _, _) = query_hot_emoticons(&conn, Path::new("x"), 1, 0).unwrap();
        let (p1, _, _, _) = query_hot_emoticons(&conn, Path::new("x"), 1, 1).unwrap();
        assert!(m0, "第 1 页后还有");
        assert_eq!(p0[0].md5, "ccc");
        assert_eq!(p1[0].md5, "bbb", "offset=1 接着第 2 个, 不重不漏");
    }

    /// **R16-1**: 热查头像 —— **空 username 行必须滤掉**(冷查 pipeline 跳身份缺失行, 否则热比冷多行)+
    /// update_time DESC + 次键 username 翻页稳。
    #[test]
    fn hot_avatars_filters_empty_username_and_sorts() {
        let conn = Connection::open_in_memory().unwrap();
        // 空/NULL username 行冷查 pipeline 跳(身份缺失); wxid_c 与 wxid_a 并列 update_time=300 验次键。
        conn.execute_batch(
            "CREATE TABLE head_image(username TEXT, md5 TEXT, update_time INTEGER, image_buffer BLOB);
             INSERT INTO head_image VALUES('wxid_a', 'md_a', 300, x'00');
             INSERT INTO head_image VALUES('wxid_b', 'md_b', 200, x'00');
             INSERT INTO head_image VALUES('', 'md_empty', 999, x'00');
             INSERT INTO head_image VALUES(NULL, 'md_null', 998, x'00');
             INSERT INTO head_image VALUES('wxid_c', 'md_c', 300, x'00');",
        )
        .unwrap();
        let (rows, has_more, total, dropped) = query_hot_avatars(&conn, Path::new("x"), 50, 0).unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(
            total,
            Some(3),
            "5 行进, 2 行空/NULL username 滤掉 → 3(同冷查 pipeline 跳空)"
        );
        assert!(!has_more);
        let names: Vec<&str> = rows.iter().map(|a| a.username.as_str()).collect();
        assert!(!names.contains(&""), "空 username 行必须滤掉");
        // update_time DESC, 并列(a/c 都 300)按 username 升序 → (300,a) (300,c) (200,b)。
        let seq: Vec<(&str, i64)> = rows.iter().map(|a| (a.username.as_str(), a.update_time)).collect();
        assert_eq!(
            seq,
            [("wxid_a", 300), ("wxid_c", 300), ("wxid_b", 200)],
            "update_time DESC + username 次键(并列 300 按 username 升序 a<c)"
        );
        assert_eq!(rows[0].md5, "md_a");
        // 翻页不重不漏(并列上)。
        let (p0, m0, _, _) = query_hot_avatars(&conn, Path::new("x"), 2, 0).unwrap();
        let (p1, m1, _, _) = query_hot_avatars(&conn, Path::new("x"), 2, 2).unwrap();
        assert!(m0 && !m1, "第1页后还有, 第2页到底");
        let paged: Vec<&str> = p0.iter().chain(p1.iter()).map(|a| a.username.as_str()).collect();
        assert_eq!(paged, ["wxid_a", "wxid_c", "wxid_b"], "翻页拼起来==全取");
    }

    /// **R16-1(avatars 审 P3)**: `head_image.username` 非 schema-unique → dup username 时热查取 max rowid
    /// 那行对齐冷查 avatar_anchor(username) INSERT OR REPLACE(每 username 一行), 不出多行。
    #[test]
    fn hot_avatars_dedup_by_max_rowid() {
        let conn = Connection::open_in_memory().unwrap();
        // 无 PK on username(真 schema); 同 username 两行(旧 md_old rowid1 + 新 md_new rowid2)。
        conn.execute_batch(
            "CREATE TABLE head_image(username TEXT, md5 TEXT, update_time INTEGER, image_buffer BLOB);
             INSERT INTO head_image VALUES('wxid_dup', 'md_old', 100, x'00');
             INSERT INTO head_image VALUES('wxid_dup', 'md_new', 200, x'00');
             INSERT INTO head_image VALUES('wxid_solo', 'md_s', 150, x'00');",
        )
        .unwrap();
        let (rows, _, total, _) = query_hot_avatars(&conn, Path::new("x"), 50, 0).unwrap();
        assert_eq!(
            total,
            Some(2),
            "dup username 只算 1(同冷查 INSERT OR REPLACE), 共 2 头像"
        );
        assert_eq!(rows.len(), 2);
        let dup = rows.iter().find(|a| a.username == "wxid_dup").unwrap();
        assert_eq!(dup.md5, "md_new", "取 max rowid 那行(新 md5), 不是旧的");
    }

    /// **R16-1**: 热查 favorites 的字段/口径对齐冷查 —— 重点锁 `content_len` 的 **CAST AS BLOB**。
    ///
    /// 为什么这条最要紧: 冷查 `favorites_query` 出的是 `LENGTH(CAST(content AS BLOB))` = 真**字节**数;
    /// 若热查图省事写裸 `LENGTH(content)` 就变成**字符**数 —— UTF-8 汉字直接低估 3 倍, 而两边字段名一样、
    /// 类型一样、测试若只比"键集"根本发现不了 (正是上一轮 P2-1 那种假绿)。故此测比**值**。
    ///
    /// **第三行(server_id=1003)的 `realchatname` 是 NULL —— 那是坏夹具, 别删**: 原先这测试两行的
    /// realchatname 都填了非空值 = **顺路夹具**, 于是"热查 `unwrap_or_default()` 把 null 变成空串"
    /// 这个冷热分叉**永远照不出来**(L1 该列可空 → 冷查出 null)。真库全量对拍逮到 **96 处**才发现。
    #[test]
    fn hot_favorites_content_len_is_bytes_not_chars() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE fav_db_item(local_id INTEGER PRIMARY KEY, server_id INTEGER, \"type\" INTEGER,
                 update_time INTEGER, fromusr TEXT, realchatname TEXT, content TEXT);
             INSERT INTO fav_db_item VALUES(1, 1001, 18, 1700000000, 'wxid_a', 'chat_a', '你好');
             INSERT INTO fav_db_item VALUES(2, 1002, 3, 1700000001, 'wxid_b', 'chat_b', 'ab');
             INSERT INTO fav_db_item VALUES(3, 1003, 3, 1700000002, 'wxid_c', NULL, 'x');
             INSERT INTO fav_db_item VALUES(4, 1004, 3, 1700000003, 'wxid_d', '', 'y');",
        )
        .unwrap();
        let (rows, has_more, total, dropped) = query_hot_favorites(&conn, Path::new("x"), None, 100, 0).unwrap();
        assert_eq!(dropped, 0);
        assert!(!has_more);
        assert_eq!(total, Some(4));
        // 排序 update_time DESC, local_id DESC (**同冷查**) → 1004 / 1003 / 1002 / 1001
        assert_eq!(rows[0].server_id, 1004);
        assert_eq!(rows[1].server_id, 1003);
        assert_eq!(rows[2].server_id, 1002);
        assert_eq!(rows[2].content_len, 2, "'ab' = 2 字节");
        assert_eq!(rows[3].server_id, 1001);
        assert_eq!(
            rows[3].content_len, 6,
            "'你好' = **6 字节**(CAST AS BLOB); 若写成裸 LENGTH 会是 2(字符数) → 与冷查不符"
        );
        assert_eq!(rows[3].fav_type, 18, "\"type\" 是保留字, 需引号取列");
        assert_eq!(rows[3].from_user, "wxid_a");
        assert_eq!(rows[3].real_chat_name, Some("chat_a".to_string()));
        // **空值的两种形态都得归一成 None** —— 走 ingest 同一个 `non_empty` 规矩:
        assert_eq!(
            rows[1].real_chat_name, None,
            "realchatname = NULL → None (server_id 1003)"
        );
        assert_eq!(
            rows[0].real_chat_name, None,
            "realchatname = **空串**也必须出 None (server_id 1004) —— ETL(assemble_favorite) 用 \
             non_empty 把空串归一成 NULL 落 L1, 冷查出 null; 热查若照透传成 Some(\"\") 就出 \"\" → \
             **同一行冷 null 热空串**。真库全量对拍逮到的 96 处**全是这个形态**(源库存的是空串, 不是 NULL) —— \
             而原先这测试两行都填非空值, 照不出来"
        );
    }

    /// favorites 的 `q` 过滤同冷查口径 (from_user / real_chat_name 两列), 且 COUNT 走同一过滤。
    #[test]
    fn hot_favorites_q_filter_matches_cold_columns() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE fav_db_item(local_id INTEGER PRIMARY KEY, server_id INTEGER, \"type\" INTEGER,
                 update_time INTEGER, fromusr TEXT, realchatname TEXT, content TEXT);
             INSERT INTO fav_db_item VALUES(1, 1, 3, 100, 'wxid_alice', 'room_x@chatroom', 'c1');
             INSERT INTO fav_db_item VALUES(2, 2, 3, 101, 'wxid_bob', 'room_y@chatroom', 'c2');",
        )
        .unwrap();
        let (rows, _, total, _) = query_hot_favorites(&conn, Path::new("x"), Some("alice"), 100, 0).unwrap();
        assert_eq!(rows.len(), 1, "q 命中 from_user");
        assert_eq!(total, Some(1), "COUNT 与行查同过滤");
        let (rows2, _, _, _) = query_hot_favorites(&conn, Path::new("x"), Some("room_y"), 100, 0).unwrap();
        assert_eq!(rows2.len(), 1, "q 也命中 real_chat_name");
    }

    /// 造一个含 `contact` + `stranger` 两表的内存库 (列取 5 个用到的; 真库两表全同 22 列)。
    fn mk_contact_db(with_stranger: bool) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE contact(username TEXT PRIMARY KEY, nick_name TEXT, remark TEXT, alias TEXT, local_type INTEGER);
             INSERT INTO contact VALUES('wxid_friend','好友昵称','备注A','alias_f',3);
             INSERT INTO contact VALUES('wxid_both','双表-好友态','备注B','alias_b',3);",
        )
        .unwrap();
        if with_stranger {
            // ⚠️ `wxid_both` 的 local_type 故意与 contact 表**相同 (都是 3)** —— 对抗审 P2-3 指出:
            // 原夹具给的是 3 vs 1, 于是 `(username, local_type)` 永远打不平, **造不出**"次键非唯一 →
            // 翻页重复/漏"的情形, 那个 bug 就永远测不到。现在打平, 全序只能靠 _src 判别列兜。
            conn.execute_batch(
                "CREATE TABLE stranger(username TEXT PRIMARY KEY, nick_name TEXT, remark TEXT, alias TEXT, local_type INTEGER);
                 INSERT INTO stranger VALUES('wxid_stranger','陌生人昵称','','alias_s',1);
                 INSERT INTO stranger VALUES('wxid_both','双表-陌生态','','alias_b2',3);",
            )
            .unwrap();
        }
        conn
    }

    /// **R16-1 (对抗审 P2-3 的修)**: 热查 contacts **必须合并 contact + stranger 两表**。
    ///
    /// 冷查 person 表同时收好友 (`source=contact.db`) 与陌生人 (`source=contact.db|stranger`), 而
    /// `contacts_query` 的输出**不带 source 列** → 两者本就混在一起出。热查只读 contact 表 = **整个漏掉
    /// 陌生人**(行完整性缺口, 且真库 fresh 夹具常无 stranger 行 → 审指出这类缺口正落在验收盲区)。
    #[test]
    fn hot_contacts_merges_contact_and_stranger() {
        let conn = mk_contact_db(true);
        let (rows, has_more, total, dropped) = query_hot_contacts(&conn, Path::new("x"), None, 100, 0).unwrap();
        assert_eq!(dropped, 0);
        assert!(!has_more);
        assert_eq!(
            total,
            Some(4),
            "两表合计 4 行 (UNION ALL **不去重** —— 同冷查 person 两 source 各一行)"
        );
        let names: Vec<&str> = rows.iter().map(|c| c.username.as_str()).collect();
        assert!(
            names.contains(&"wxid_stranger"),
            "陌生人不能漏 (只读 contact 表就会漏 = 审 P2-3)"
        );
        assert_eq!(
            names,
            vec!["wxid_both", "wxid_both", "wxid_friend", "wxid_stranger"],
            "同 wxid 跨两表出两行 (与冷查 person 行数一致) + 按 username 全序稳定"
        );
        // 并列 username 的**组内顺序**必须确定且对齐冷查 (source 升序: contact.db 在 stranger 前)。
        // 夹具里 wxid_both 两行的 local_type 已打平(都是 3) → 只有 _src 判别列能定序 (审 P2-3)。
        assert_eq!(
            rows[0].nick_name, "双表-好友态",
            "并列 username 组内: contact 表的行在前 (_src=0)"
        );
        assert_eq!(
            rows[1].nick_name, "双表-陌生态",
            "然后才是 stranger 表的 (_src=1), 对齐冷查 source 升序"
        );
    }

    /// **R16-1 (对抗审 P2-3 · 行为护栏)**: 并列 username 且 local_type 打平时, OFFSET 翻页不重不漏
    /// —— 全序由 `_src` 判别列兜住。
    ///
    /// ⚠️ **本测试是"行为护栏"不是"bug 复现" —— 别把它的绿当成 P2-3 被证伪**:
    /// 实测把 `ORDER BY username, _src` 换回 `username, local_type`(两行已刻意打平), 本测试**照样过**
    /// —— SQLite 在这种内存小表 + 简单查询下**恰好**保持了 UNION ALL 的插入顺序。但"恰好"不是"保证":
    /// 表变大 / 查询计划变(走索引或临时 B-tree) / SQLite 版本变, 打平行的相对顺序随时会变 → 逐页取时
    /// 同一行出两次、另一行永不出现。冷查侧记着这个坑的**真实复现**: anchor 688→98 静默丢联系人。
    ///
    /// 即: **这个 bug 在内存小库上造不出来**。加 `_src` 的依据是"次键必须唯一"这条原则 + 冷查已用
    /// `source` 这么做的先例, **不是**靠本测试证明的。本测试的作用只是防止以后有人把次键改回去。
    #[test]
    fn hot_contacts_paging_stable_when_tiebreaker_ties() {
        let conn = mk_contact_db(true); // 4 行, 其中 wxid_both 两行的 username+local_type 全打平
        let mut seen: Vec<String> = Vec::new();
        for off in [0usize, 1, 2, 3] {
            let (rows, _, _, _) = query_hot_contacts(&conn, Path::new("x"), None, 1, off).unwrap();
            assert_eq!(rows.len(), 1, "off={off} 应恰好取到 1 行");
            seen.push(format!("{}|{}", rows[0].username, rows[0].nick_name));
        }
        let n = seen.len();
        let mut uniq = seen.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), n, "逐页翻**不重复** (并列行靠 _src 定序)");
        assert_eq!(
            seen,
            vec![
                "wxid_both|双表-好友态".to_string(),
                "wxid_both|双表-陌生态".to_string(),
                "wxid_friend|好友昵称".to_string(),
                "wxid_stranger|陌生人昵称".to_string(),
            ],
            "逐页顺序与整页一致, **不漏**任何行"
        );
    }

    /// `stranger` 表不存在 (老库 / 未启用) → 只出 contact, **不整条失败** (宽松, 同冷查对缺表的容忍)。
    #[test]
    fn hot_contacts_tolerates_missing_stranger_table() {
        let conn = mk_contact_db(false);
        let (rows, _, total, dropped) = query_hot_contacts(&conn, Path::new("x"), None, 100, 0).unwrap();
        assert_eq!(rows.len(), 2, "只出 contact 表两行");
        assert_eq!(total, Some(2));
        assert_eq!(dropped, 0);
    }

    /// `q` 子串过滤与冷查 `contacts_query` 同口径 (username/nick_name/remark/alias 四列 LIKE),
    /// 且**跨两表都生效** (别只过滤 contact 表)。
    #[test]
    fn hot_contacts_q_filter_spans_both_tables() {
        let conn = mk_contact_db(true);
        // 命中陌生人表的昵称
        let (rows, _, total, _) = query_hot_contacts(&conn, Path::new("x"), Some("陌生人"), 100, 0).unwrap();
        assert_eq!(rows.len(), 1, "q 必须能命中 stranger 表的行");
        assert_eq!(rows[0].username, "wxid_stranger");
        assert_eq!(total, Some(1), "COUNT 也走同一过滤");
        // 命中两表同 wxid 的 alias 前缀
        let (rows2, _, _, _) = query_hot_contacts(&conn, Path::new("x"), Some("alias_b"), 100, 0).unwrap();
        assert_eq!(rows2.len(), 2, "alias_b / alias_b2 跨两表各一行");
    }

    /// has_more 走 limit+1 哨兵 (同 sessions): 满页时精确报"还有", 不多报空页。
    #[test]
    fn hot_contacts_has_more_is_exact() {
        let conn = mk_contact_db(true); // 共 4 行
        let (rows, has_more, _, _) = query_hot_contacts(&conn, Path::new("x"), None, 2, 0).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(has_more, "4 行取 2 → 还有");
        let (rows2, has_more2, _, _) = query_hot_contacts(&conn, Path::new("x"), None, 2, 2).unwrap();
        assert_eq!(rows2.len(), 2);
        assert!(!has_more2, "满末页不多报空页 (limit+1 哨兵精确)");
    }

    /// **R16-0 (审 P2-2 的修)**: 热查 sender 复用冷查 [`resolve_sender_parts`] 后, **锁死方向 + 优先级**。
    ///
    /// 为什么必须有: `self_wxid` / `conv_id` 同为 `&str` **可静默调换** —— 写反则编译过、其余测试全绿, 但
    /// **全库单聊 sender 收发反转**; 群聊优先级同理。改这段前热查侧**零 sender 断言**(审逮出), 故补此测试。
    /// 断言与冷查 message.rs 的 `single_chat_sent_sender_is_account` / `single_chat_received_sender_is_conv`
    /// / `chatroom_name2id_sender` 一一对应 —— 冷热同语义的守卫。
    #[test]
    fn hot_sender_matches_cold_semantics() {
        let mk = |status: i64, real_sender_id: Option<i64>, mc: &str| RawMsgRead {
            local_id: 1,
            server_id: 1,
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            local_type: 1,
            sort_seq: 0,
            create_time: 0,
            status,
            real_sender_id,
            mc_hex: hex::encode(mc.as_bytes()),
            src_hex: String::new(),
        };
        // 1. 单聊 status==2 (已发) → **本账号**, 不是 conv_id。self_wxid/conv_id 写反这条即挂。
        let rr = mk(2, None, "hi");
        let (m, _) = SourceQuery::decode_msg_row(false, "wxid_friend", None, &rr, "wxid_self_acct");
        assert_eq!(
            m.sender.as_deref(),
            Some("wxid_self_acct"),
            "单聊 SENT → 本账号 (同冷查)"
        );
        // 2. 单聊 status!=2 (已收) → **对方** (conv_id)。
        let rr = mk(4, None, "hi");
        let (m, _) = SourceQuery::decode_msg_row(false, "wxid_friend", None, &rr, "wxid_self_acct");
        assert_eq!(
            m.sender.as_deref(),
            Some("wxid_friend"),
            "单聊已收 → 对方 conv_id (同冷查)"
        );
        // 3. 群聊 **Name2Id 优先于 content 前缀** —— R16-0 翻转点 (原热查前缀优先; 冷查
        //    chatroom_name2id_sender 钉死 Name2Id 优先, 以冷查为基准)。
        let mut map = HashMap::new();
        map.insert(7i64, "wxid_member_a".to_string());
        let rr = mk(4, Some(7), "wxid_prefix_b:\n群里说话"); // 真实群前缀格式 = "<sender>:\n<正文>" (content.rs:67)
        let (m, _) = SourceQuery::decode_msg_row(true, "room@chatroom", Some(&map), &rr, "wxid_self_acct");
        assert_eq!(
            m.sender.as_deref(),
            Some("wxid_member_a"),
            "群聊 Name2Id 优先于前缀 (对齐冷查基准)"
        );
        assert_eq!(m.text, "群里说话", "群前缀已剥离");
        // 4. 群聊无 Name2Id → 降级到前缀。
        let rr = mk(4, None, "wxid_prefix_b:\n群里说话");
        let (m, _) = SourceQuery::decode_msg_row(true, "room@chatroom", None, &rr, "wxid_self_acct");
        assert_eq!(m.sender.as_deref(), Some("wxid_prefix_b"), "群聊无 Name2Id → 退前缀");
        // 5. 群聊两级都无 → **SENDER_UNKNOWN 占位**(不再是 None; 同冷查 NOT NULL 语义)。
        let rr = mk(4, None, "没有前缀的群消息");
        let (m, _) = SourceQuery::decode_msg_row(true, "room@chatroom", None, &rr, "wxid_self_acct");
        assert_eq!(
            m.sender.as_deref(),
            Some(crate::decoder::SENDER_UNKNOWN),
            "R16-0: 解不出 → 占位 (原热查返 None, 现同冷查占位)"
        );
    }
}
