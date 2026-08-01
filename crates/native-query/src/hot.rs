//! 热查出口 (查询内核抽取 §6③ 收尾) —— `sessions` / `messages` 直查**加密源库**
//! (骑 native-core [`SourceQuery`](native_core::SourceQuery)), 返 `QueryResult{data, meta.source=hot}`。
//!
//! **冷查/热查 async 分界** (§10 finding #4 决策): 冷查 [`run_query`](crate::run_query) 同步 (只读 L1);
//! 热查 async —— 但 async **仅因取 key** ([`cache_key`] 是 async), `SourceQuery` 本体全同步 (build /
//! list_convs / latest_messages 无 .await)。故只给这两个热查函数挂 async, **不**为它们把 24 个冷查
//! 函数统一改 async (零收益纯 churn)。
//!
//! **R16-2 (codex f02f1ff P1) 软依赖 tokio**: 原本"async 只是语法、本 crate 不依赖 tokio"。但 message 分片派生
//! 热查 (events/calls/…) 走 [`SourceQuery::scan_all_messages`] **同步全库扫**(大账号 16-48s)。HTTP serve 是
//! `#[tokio::main(flavor="current_thread")]` 单线程 —— 内联同步长扫钉死唯一 async 线程(健康检查/无关请求全卡 +
//! request-timeout 定时器 poll 不到无法 fire)。故这些热查内核把同步扫**下沉 `tokio::task::spawn_blocking`**
//! (同冷查 `cold()` 既定范式)。代价: 本 crate 现软依赖 tokio(仅 `rt` 的 spawn_blocking), hot_* **必须在
//! tokio runtime 内调**(CLI/MCP/HTTP 皆是)。小库直查热查 (sessions/messages/moments/…) 扫得少, 暂未下沉。
//!
//! **账号定位 helper 一并进核**: `resolve_message_dir` / `default_wechat_data_dir` / `wxid_from_dir_name`
//! / `query_locator_path` / `cache_key` 原在 msgvestige, 但 MCP/HTTP 依赖本 crate (非 msgvestige), 解析
//! 逻辑必须够得着 —— 故上移。msgvestige 仍用到的 (`default_wechat_data_dir`/`wxid_from_dir_name`/`cache_key`,
//! 被 auth/export/media 用) 从本 crate 回引。

// 热查直读源库: 行元组=列形状 · HashMap 参数只在本 crate 内传不需要泛化 hasher · 参数多是因为源库定位需要账号/目录/key/分片等多个独立输入。
#![allow(clippy::type_complexity, clippy::implicit_hasher, clippy::too_many_arguments)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use native_core::key_provider::CacheKeyProvider;
use native_core::{KeyProvider, MasterKey, QueriedMsg, QueriedSession, SourceQuery, Wxid};

use crate::{cli_err, Freshness, Meta, QueryResult, Source};

/// 一条待排序热查行 + 其排序键 (create_time, source, source_native_id)。**Ord 只比键**(payload `P` 不参与,
/// 故 `P` 无需 Ord)。键升序; [`TopN`] 用 `Reverse` 包成 min-heap。(source, source_native_id)=message PK 尾, 唯一
/// → 无 tie 确定序 (全扫/registry 命令冷查 order_by 均带这两列次键, 与之逐字节对齐)。
#[derive(Clone)]
struct Keyed<P> {
    ct: i64,
    src: String,
    snid: String,
    /// **第 4 排序键** (R16-2 mentions/group-events 一对多): 同一消息派生多行时按此破并列 (= mentioned_wxid 等 1:N 分量,
    /// 对齐冷查 order_by 末位)。**单行命令(每 (src,snid) 一行)传空串** —— 3 键 (ct,src,snid)=message PK 尾已唯一, tie="" 不影响。
    tie: String,
    payload: P,
}
impl<P> PartialEq for Keyed<P> {
    fn eq(&self, o: &Self) -> bool {
        (self.ct, &self.src, &self.snid, &self.tie) == (o.ct, &o.src, &o.snid, &o.tie)
    }
}
impl<P> Eq for Keyed<P> {}
impl<P> PartialOrd for Keyed<P> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl<P> Ord for Keyed<P> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.ct, &self.src, &self.snid, &self.tie).cmp(&(o.ct, &o.src, &o.snid, &o.tie))
    }
}

/// 有界 top-N 收集器 —— 全库扫时只留按 (create_time, source, source_native_id) **DESC** 的前 `need=offset+limit`
/// 行 + 分开精确计 `total`。内存 O(need) 而非 O(全量结果集)。
///
/// **codex media P1 + Claude 族级一致**: hot_* 原来把全部匹配行收进 `Vec` 再 sort+skip/take —— 稠密命令 (media
/// 338万行 × 数百字节 ≈ 2.4GB) 即便 limit=20 也吃全账号内存, HTTP serve 并发下可 OOM。有界堆把内存钉在 need 行,
/// 输出**逐字节等价**(无 tie 全序 → top-N 确定; total 单独计仍精确)。全 scan_all_messages 热内核 (media/events/
/// calls/links/files/locations/cards) 共用, 保持族级一致 (不单改 media 破坏模板)。
struct TopN<P> {
    need: usize,
    heap: std::collections::BinaryHeap<std::cmp::Reverse<Keyed<P>>>,
    total: usize,
}
/// 热扫翻页窗口上限: 有界堆最多留这么多行 (≈70MB @ media MediaCard ~700B)。深翻页 (offset+limit 超此) 拒之 ——
/// 走 cold(L1) 深翻页 (SQLite offset 无内存问题)。**codex 75dfce4 P1**: 否则 offset 可到 10M, need=offset+limit
/// 又让堆保留百万行 = 重现 OOM (有界堆只在 offset 小时才有界; 光有界堆挡不住客户端给深 offset)。
pub const MAX_HOT_SCAN_WINDOW: usize = 100_000;

/// 校验热扫翻页窗口 (offset+limit ≤ [`MAX_HOT_SCAN_WINDOW`]), 超则 `BadRequest`(不静默 clamp 免返错页)。
///
/// **在公开入口尽早调**(codex/Claude d416553 P2/P3): 每个热内核入口首行已调 → CLI/MCP 在开库前即拒;
/// **HTTP 皮侧还须在取 `HOT_SCAN_SEMAPHORE` permit 前调** —— 否则超窗坏请求会先占 permit(挤合法扫)+ cache_key +
/// spawn_blocking 开库 build(~秒)才返 400。深翻页/全量导出走 `--mode cold`(L1 SQLite offset 无内存上限)。
///
/// # Errors
/// `offset + limit > MAX_HOT_SCAN_WINDOW` → `BadRequest`。
pub fn check_hot_window(offset: usize, limit: usize) -> Result<()> {
    let need = offset.saturating_add(limit);
    if need > MAX_HOT_SCAN_WINDOW {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("热查翻页太深 (offset+limit={need} > {MAX_HOT_SCAN_WINDOW}); 深翻页请用 --mode cold 读 L1 (无内存上限), 或收窄查询"),
        ));
    }
    Ok(())
}

impl<P> TopN<P> {
    /// 构造。**无窗口守卫** —— 调用方(热内核入口)须先 [`check_hot_window`] 挡深 offset, 否则 need=offset+limit
    /// 随外部 offset 无界 = 重现 OOM。(7 热内核入口首行均已 `check_hot_window(offset, limit)?`。)
    fn new(offset: usize, limit: usize) -> Self {
        Self {
            need: offset.saturating_add(limit),
            heap: std::collections::BinaryHeap::new(),
            total: 0,
        }
    }
    /// 喂一行: 总是计入 `total`; `need>0` 时按键竞争进保留集 (满了且比集内最小键大才换入)。
    ///
    /// **Claude 75dfce4 P3-b (惰性 payload)**: 键 (ct, src, snid) 用**借用**先判是否入选, 只有胜出才 `make()`
    /// 构造 payload + clone src/snid —— 稠密扫 (media 338万) 落选行**零额外分配**(原来每行都先 clone payload 再判去留)。
    fn offer<F: FnOnce() -> P>(&mut self, ct: i64, src: &str, snid: &str, make: F) {
        self.offer_tie(ct, src, snid, "", make); // 单行命令: tie 空 (3 键 PK 尾已唯一)
    }
    /// 同 [`offer`](Self::offer) 但带**第 4 排序键 `tie`** —— R16-2 一对多命令 (mentions/group-events): 同一消息派生多行,
    /// 用 tie(= mentioned_wxid 等 1:N 分量, 对齐冷查 order_by 末位)破同 (ct,src,snid) 的并列, 保 offset 翻页确定不重漏。
    fn offer_tie<F: FnOnce() -> P>(&mut self, ct: i64, src: &str, snid: &str, tie: &str, make: F) {
        self.total += 1;
        if self.need == 0 {
            return; // offset=limit=0: 只计数不留行
        }
        // 只用借用的键判入选: 堆未满 → 入; 满了 → 键 (含 tie) > 集内最小键才入 (换掉最小)。
        let wins = self.heap.len() < self.need || {
            let min = &self.heap.peek().expect("need>0 → heap 非空").0;
            (ct, src, snid, tie) > (min.ct, min.src.as_str(), min.snid.as_str(), min.tie.as_str())
        };
        if wins {
            if self.heap.len() >= self.need {
                self.heap.pop(); // 满了先弹最小, 维持 top-need
            }
            // 胜出才付构造代价: clone src/snid/tie 做键 + make() 构造 payload。
            self.heap.push(std::cmp::Reverse(Keyed {
                ct,
                src: src.to_string(),
                snid: snid.to_string(),
                tie: tie.to_string(),
                payload: make(),
            }));
        }
    }
    /// 收工: 保留的 ≤need 行按键 **DESC** 排好 + `total`。调用方再 `.skip(offset).take(limit)`。
    fn finish(self) -> (Vec<Keyed<P>>, usize) {
        let total = self.total;
        let mut v: Vec<Keyed<P>> = self.heap.into_iter().map(|r| r.0).collect();
        v.sort_by(|a, b| b.cmp(a)); // DESC (min-heap 出来无序, 显式排)
        (v, total)
    }
}

/// 有界 bottom-N 收集器 —— [`TopN`] 的**升序镜像**: 全库扫时只留按 [`Keyed`] 键 **ASC** 的**最小** `need` 行 + 分开精确计
/// `total`。内存 O(need)。**`new`(R16-5)专用**: `hot_new` 把逻辑键 `(source, conv_id, local_id)` 编码进 Keyed(ct=0 恒定,
/// src=source, snid="conv_id\x1f零填充local_id")→ 取**到达序最小的 limit 条**(同冷 `new_query` `rowid ASC LIMIT` 前向追赶)。
/// (conv_id 必进键: local_id 是每会话表 rowid 非分片全局 → 无 conv_id 维则同分片跨会话碰撞。)TopN(保最大 DESC)方向相反。
/// 用**大顶堆**(无 `Reverse`, peek=最大)满了弹最大 → 留最小 need。(src,snid) 编码了 (src,conv_id,local_id) 唯一 → 无需第 4 键 tie。
struct BottomN<P> {
    need: usize,
    heap: std::collections::BinaryHeap<Keyed<P>>, // 大顶堆: peek=最大; 满了弹最大 → 留最小 need
    total: usize,
}
impl<P> BottomN<P> {
    fn new(limit: usize) -> Self {
        Self {
            need: limit,
            heap: std::collections::BinaryHeap::new(),
            total: 0,
        }
    }
    /// 喂一行: 总是计 `total`; `need>0` 时按键竞争进保留集 (满了且键**更小**才换入最大者)。惰性 payload 同 [`TopN::offer`]。
    fn offer<F: FnOnce() -> P>(&mut self, ct: i64, src: &str, snid: &str, make: F) {
        self.total += 1;
        if self.need == 0 {
            return;
        }
        // 借用键判入选: 堆未满 → 入; 满了 → 键 < 集内**最大**键才入 (换掉最大, 维持最小 need)。
        let wins = self.heap.len() < self.need || {
            let max = self.heap.peek().expect("need>0 → heap 非空");
            (ct, src, snid) < (max.ct, max.src.as_str(), max.snid.as_str())
        };
        if wins {
            if self.heap.len() >= self.need {
                self.heap.pop(); // 满了先弹最大, 维持 bottom-need
            }
            self.heap.push(Keyed {
                ct,
                src: src.to_string(),
                snid: snid.to_string(),
                tie: String::new(),
                payload: make(),
            });
        }
    }
    /// 收工: 保留的 ≤need 行按键 **ASC**(最旧优先, 同冷查 rowid ASC) + `total`。
    fn finish(self) -> (Vec<Keyed<P>>, usize) {
        let total = self.total;
        let mut v: Vec<Keyed<P>> = self.heap.into_iter().collect();
        v.sort(); // ASC (大顶堆出来无序, 显式升序排)
        (v, total)
    }
}

/// 一条热查消息 → json 行 (R5 扩全: 字段集与冷查 L1 `message` 行对齐)。`hot_messages` / `hot_messages_around`
/// 共用免抄。派生字段由 [`QueriedMsg`] 侧 (native-core) 复用 ingest 纯函数算好, 本层只做 json 映射不再派生。
/// 空 `sys_type`/`msg_sub_type*` → JSON `null` (serde 自然映射 `Option`)。**`sender` 自 R16-0 起恒非 null**
/// (解不出 = `@sender_unknown` 占位, 同冷查 NOT NULL 语义; 见 `QueriedMsg::sender`) —— 对抗审 P3-6 逮出本行漏改。
pub(crate) fn msg_json(m: &QueriedMsg) -> serde_json::Value {
    serde_json::json!({
        "source_native_id": m.source_native_id,
        // R16-0 (审 P3-5): conv_id 对外出列 —— 全局扫命令 (calls/links/files/events/mentions/biz)
        // 按会话归属靠它; 同冷查 message.conv_id。地基件里字段已带进 QueriedMsg, 此处才对外可见。
        "conv_id": m.conv_id,
        "local_id": m.local_id,
        "server_id": m.server_id,
        "server_seq": m.server_seq,
        "origin_source": m.origin_source,
        "upload_status": m.upload_status,
        "download_status": m.download_status,
        "create_time": m.create_time,
        "sort_seq": m.sort_seq,
        "status": m.status,
        "local_type": m.local_type,
        "msg_type": m.msg_type,
        "msg_type_name": m.msg_type_name,
        "msg_sub_type": m.msg_sub_type,
        "msg_sub_type_name": m.msg_sub_type_name,
        "decode_kind": m.decode_kind,
        "sys_type": m.sys_type,
        "is_chatroom": m.is_chatroom,
        "raw_xml_present": m.raw_xml_present,
        "sender": m.sender,
        "text": m.text,
    })
}

/// 一条热查会话 → json 行 (R5 扩全: 字段集与冷查 L1 `session` 行对齐)。`hot_sessions` 用。
/// 同发 `conv_id` (旧 hot_sessions 键名, 消费方拿它当 conv 查消息) + `username` (冷查同名); 二者同值。
/// 空 `summary`/`draft`/`last_msg_sender`/`last_sender_display_name` → JSON `null`。
fn session_json(s: &QueriedSession) -> serde_json::Value {
    serde_json::json!({
        "conv_id": s.username,
        "username": s.username,
        "is_group": s.is_group,
        "summary": s.summary,
        "summary_len": s.summary_len,
        "last_sender_display_name": s.last_sender_display_name,
        "unread_count": s.unread_count,
        "last_msg_type": s.last_msg_type,
        "last_msg_sub_type": s.last_msg_sub_type,
        "sort_timestamp": s.sort_timestamp,
        "session_type": s.session_type,
        "is_hidden": s.is_hidden,
        "status": s.status,
        "draft": s.draft,
        "last_msg_sender": s.last_msg_sender,
        "last_timestamp": s.last_timestamp,
        "last_clear_unread_timestamp": s.last_clear_unread_timestamp,
        "last_msg_locald_id": s.last_msg_locald_id,
        "last_msg_ext_type": s.last_msg_ext_type,
        "unread_first_msg_srv_id": s.unread_first_msg_srv_id,
    })
}

/// 一条热查联系人 → json 行 (**R16-1**: 字段集与冷查 `contacts_query` 输出对齐, 5 键)。
fn contact_json(c: &native_core::QueriedContact) -> serde_json::Value {
    serde_json::json!({
        "username": c.username,
        "nick_name": c.nick_name,
        "remark": c.remark,
        "alias": c.alias,
        "local_type": c.local_type,
    })
}

/// `contacts` 热查核 (**R16-1**) —— 直读加密 `contact.db`, **合并 contact + stranger 两表**
/// (对抗审 P2-3: 冷查 person 收两个 source 且输出不带 source 列, 只读 contact 会整个漏掉陌生人)。
/// 字段与冷查 [`crate::contacts_query`] 的 5 键对齐; auth 后即用, 不建 L1。
///
/// **分页差异 (诚实标注)**: 冷查走 keyset 游标 (person PK 含 source, username 非唯一);
/// 热查走 `offset` (源库单表内 username 唯一, UNION ALL 后补 local_type 次键保全序稳定)。
/// 数据行字段一致, 翻页机制不同 —— 同 sessions 的既有形态。
///
/// # Errors
/// 定位 / 取 key / contact.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_contacts(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    q: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let contact_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("contact")
        .join("contact.db");
    let key = cache_key(wxid).await?;
    let (contacts, has_more, total, dropped) = native_core::read_hot_contacts(&contact_db, &key, q, limit, offset)
        .context("查联系人失败 (contact.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = contacts.iter().map(contact_json).collect();
    // summary 契约同 hot_sessions: COUNT 失败 → total_unknown + partial (不伪装 0); 丢行 → partial + dropped_rows。
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_contacts".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_dropped(dropped as u64) // codex 审 P2: 走标准 meta.dropped_rows(不止 summary; with_dropped(0) 是 no-op)
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查收藏 → json 行 (**R16-1**: 6 键 = 冷查 `favorites_query` 输出集)。
fn favorite_json(f: &native_core::QueriedFavorite) -> serde_json::Value {
    serde_json::json!({
        "server_id": f.server_id,
        "fav_type": f.fav_type,
        "update_time": f.update_time,
        "from_user": f.from_user,
        "real_chat_name": f.real_chat_name,
        "content_len": f.content_len,
    })
}

/// `favorites` 热查核 (**R16-1**) —— 直读加密 `favorite.db` 的 `fav_db_item`, 字段与冷查
/// [`crate::favorites_query`] 的 6 键对齐 (零解码: 正文大 blob 本就不取, 只取字节长度)。
///
/// # Errors
/// 定位 / 取 key / favorite.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_favorites(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    q: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let fav_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("favorite")
        .join("favorite.db");
    let key = cache_key(wxid).await?;
    let (favs, has_more, total, dropped) = native_core::read_hot_favorites(&fav_db, &key, q, limit, offset)
        .context("查收藏失败 (favorite.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = favs.iter().map(favorite_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_favorites".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_dropped(dropped as u64) // codex 审 P2: 走标准 meta.dropped_rows(不止 summary; with_dropped(0) 是 no-op)
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查好友验证 → json 行 (**R16-1**: 7 键 = 冷查 `friend_requests_query` 输出集 = 6 列 + `scene_label`)。
///
/// **键名 `greeting` 不是 `content`** —— 冷查 json 对外就叫 `greeting` (源库列名是 `content_`)。热查照
/// **冷查的对外键名**, 不照源库列名: 两边同一个消费方, 键名漂了等于换了契约。
fn friend_request_json(f: &native_core::QueriedFriendRequest) -> serde_json::Value {
    serde_json::json!({
        "timestamp": f.timestamp,
        "user_name": f.user_name,
        "friend_type": f.friend_type,
        "is_sender": f.is_sender,
        "scene": f.scene,
        // label 走冷查同一个纯函数 (不在内核算): 两处各算一份必漂。
        "scene_label": crate::friend_scene_label(f.scene),
        "greeting": f.content,
    })
}

/// `friend-requests` 热查核 (**R16-1**) —— 直读加密 `general.db` 的 `FMessageTable` (ADR-469 同源),
/// 字段与冷查 [`crate::friend_requests_query`] 的 7 键对齐 (零解码)。auth 后即用, 不建 L1。
///
/// 冷查无 `-q` 过滤 → 热查也不加 (对齐是**对齐冷查的形状**, 不是顺手加料)。
///
/// # Errors
/// 定位 / 取 key / general.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_friend_requests(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let general_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("general")
        .join("general.db");
    let key = cache_key(wxid).await?;
    let (reqs, has_more, total, dropped) = native_core::read_hot_friend_requests(&general_db, &key, limit, offset)
        .context("查好友验证失败 (general.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = reqs.iter().map(friend_request_json).collect();
    // summary 契约同 hot_contacts/hot_favorites: COUNT 失败 → total_unknown + partial (不伪装 0)。
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_friend_requests".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_dropped(dropped as u64) // codex 审 P2: 走标准 meta.dropped_rows(不止 summary; with_dropped(0) 是 no-op)
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查视频号访问 → json 行 (**R16-1**: 5 键 = 冷查 `finder_query` 输出集)。
///
/// `visit_date` 由内核用**冷查同一个 SQLite `date()`** 算好 (不在这算): 冷查是 SQL 里
/// `date(visit_time,'unixepoch','localtime')`, 带本地时区 —— 皮层用 Rust 算就会在日界线附近分叉。
fn finder_visit_json(f: &native_core::QueriedFinderVisit) -> serde_json::Value {
    serde_json::json!({
        "visit_time": f.visit_time,
        "visit_date": f.visit_date,
        "name": f.name,
        "owner_username": f.owner_username,
        "profile_url": f.profile_url,
    })
}

/// `finder` 热查核 (**R16-1**) —— 直读加密 `general.db` 的 `wcfinderuserpage`, 字段与冷查
/// [`crate::finder_query`] 的 5 键对齐。auth 后即用, 不建 L1。
///
/// **本条是全扫**(不同于前三条的 SQL 分页): 空壳行的判据藏在 proto 里、SQL 过滤不了, 而 ingest 落 L1 时
/// 跳掉了它们 —— 热查必须用同一份判据跳掉同一批, 否则冷热行集分叉。故 total 精确、has_more 精确。
/// 真库量级 723 行, 全扫无压力。冷查无 `-q` 过滤 → 热查也不加。
///
/// # Errors
/// 定位 / 取 key / general.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_finder_visits(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let general_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("general")
        .join("general.db");
    let key = cache_key(wxid).await?;
    let (visits, has_more, total, dropped) =
        native_core::read_hot_finder_visits(&general_db, &key, wxid, limit, offset)
            .context("查视频号访问失败 (general.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = visits.iter().map(finder_visit_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_finder_visits".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    // **本条是全扫**(codex 审 v3 P2): dropped 是整表扫的累计数, **不进** page-local 语义的 `meta.dropped_rows`
    // (那会让每页都报同一整表 drop 数); 只留 summary.dropped_rows(整数据集"有洞"信号)。streaming 皮(SQL 分页)
    // 的 dropped 才是本页局部, 那些保留 with_dropped。
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查群成员 → json 行 (**R16-1 降级件**: 5 键 = 冷查 `members_query` 输出集)。
///
/// **`joined_at` 恒 null** —— 源库群成员 proto 里没有入群时刻这个字段, 冷查的 `joined_at` 来自 L1 落库时
/// 从系统消息派生累计, 热查拿不到 → 明说降级填 null (键在、值空, 不假装有)。
fn member_json(m: &native_core::QueriedMember) -> serde_json::Value {
    serde_json::json!({
        "member_wxid": m.member_wxid,
        "display_name": m.display_name,
        "role": m.role,
        "joined_at": serde_json::Value::Null, // 降级: 源库无此字段 (决策②)
        "invited_by": m.invited_by,
    })
}

/// `members` 热查核 (**R16-1 降级件**) —— 直读加密 `contact.db` 的 `chat_room` 那一行, 解 `ext_buffer`
/// proto 展开成员, 字段与冷查 [`crate::members_query`] 的 5 键对齐 (`joined_at` 恒 null)。
///
/// **明说降级** (决策②, 三处都在 summary 里标出来给调用方看):
/// 1. `joined_at` 恒 null —— 源库 proto 无入群时刻 (冷查从系统消息累计, 热查无源);
/// 2. **已退群成员不返回** —— 源库那一行只存**当前在群**成员, 退群的历史成员冷查 L1 跨账号累计才有;
/// 3. 故 `partial` 恒 true —— 热查是**当前快照**, 语义比冷查窄, 调用方须知情。
///
/// 本条是全扫 (同 finder): 成员在 proto 里, `admins_only`/role 判定 SQL 筛不出 → 全取该群成员后内存
/// 过滤+排序(`role, member_wxid` 同冷查)+分页。单群成员量级 (最大群几千) 全扫无压力。
///
/// # Errors
/// 定位 / 取 key / contact.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_members(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    chatroom: &str,
    admins_only: bool,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let contact_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("contact")
        .join("contact.db");
    let key = cache_key(wxid).await?;
    let (members, has_more, total, dropped) =
        native_core::read_hot_members(&contact_db, &key, chatroom, admins_only, limit, offset)
            .context("查群成员失败 (contact.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = members.iter().map(member_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_members".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    // **降级恒标** (决策②): 不像其它热查只在 dropped/total_unknown 时标 —— members 热查本身语义窄
    // (无 joined_at + 退群成员缺席), 每次都得让调用方知道这不是冷查那份完整历史。
    summary.insert("partial".into(), serde_json::json!(true));
    summary.insert(
        "degraded".into(),
        serde_json::json!("joined_at 恒 null (源库无此字段); 已退群成员不返回 (仅当前在群快照)"),
    );
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    // 全扫 (codex 审 v3 P2): 整表 dropped 只留 summary, 不进 page-local meta.dropped_rows(见 hot_finder_visits 注)。
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查自定义表情 → json 行 (**R16-1**: 5 键 = 冷查引擎 `CMD_EMOTICONS` 的输出集)。
///
/// `cdn_url` **要出** —— 引擎里它标 `Fmt::Hidden`, 但那只藏 table 渲染, json 照出(真跑冷查 json 核过)。
fn emoticon_json(e: &native_core::QueriedEmoticon) -> serde_json::Value {
    serde_json::json!({
        "caption": e.caption,
        "md5": e.md5,
        "emoticon_type": e.emoticon_type,
        "product_id": e.product_id,
        "cdn_url": e.cdn_url,
    })
}

/// `emoticons` 热查核 (**R16-1**) —— 直读加密 `emoticon.db` 的 `kNonStoreEmoticonTable`, 5 键对齐冷查引擎
/// `CMD_EMOTICONS`。auth 后即用, 不建 L1。
///
/// **本条是引擎路径热查的第一条**(前四条冷查是手写, 本条冷查走 `emit_engine_query`)。冷查引擎无 `-q`
/// 过滤 → 热查也不加。
///
/// # Errors
/// 定位 / 取 key / emoticon.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_emoticons(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let emoticon_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("emoticon")
        .join("emoticon.db");
    let key = cache_key(wxid).await?;
    let (emos, has_more, total, dropped) = native_core::read_hot_emoticons(&emoticon_db, &key, limit, offset)
        .context("查表情失败 (emoticon.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = emos.iter().map(emoticon_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_emoticons".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_dropped(dropped as u64) // codex 审 P2: 走标准 meta.dropped_rows(不止 summary; with_dropped(0) 是 no-op)
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查群 → json 行 (**R16-1**: 5 键 = 冷查引擎 `CMD_CHATROOMS` 输出集)。
fn chatroom_json(c: &native_core::QueriedChatroom) -> serde_json::Value {
    serde_json::json!({
        "chatroom_id": c.chatroom_id,
        "chatroom_name": c.chatroom_name,
        "owner_wxid": c.owner_wxid,
        "member_count": c.member_count,
        "announcement": c.announcement,
    })
}

/// `chatrooms` 热查核 (**R16-1**) —— 直读加密 `contact.db` 的 `chat_room` 表(LEFT JOIN contact 取群名 +
/// chat_room_info_detail 取公告, 同冷查 ETL drain SQL), 5 键对齐冷查引擎 `CMD_CHATROOMS`。auth 后即用, 不建 L1。
///
/// **本条是全扫**(同 members): 排序键 `member_count` 要逐群解 proto 数成员才知道, SQL 排不了 → 全取所有群 +
/// 每群解 proto 数成员 + 内存排序(`member_count DESC, chatroom_id` 同冷查)+ 分页。群数量级(几百)全扫无压力。
/// 冷查引擎无 `-q` 过滤 → 热查也不加。
///
/// # Errors
/// 定位 / 取 key / contact.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_chatrooms(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let contact_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("contact")
        .join("contact.db");
    let key = cache_key(wxid).await?;
    let (rooms, has_more, total, dropped) = native_core::read_hot_chatrooms(&contact_db, &key, limit, offset)
        .context("查群列表失败 (contact.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = rooms.iter().map(chatroom_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_chatrooms".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    // 全扫 (codex 审 v3 P2): 整表 dropped 只留 summary, 不进 page-local meta.dropped_rows(见 hot_finder_visits 注)。
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查头像 → json 行 (**R16-1**: 3 键 = 冷查引擎 `CMD_AVATARS` 输出集; update_time 出原始 i64)。
fn avatar_json(a: &native_core::QueriedAvatar) -> serde_json::Value {
    serde_json::json!({
        "username": a.username,
        "md5": a.md5,
        "update_time": a.update_time,
    })
}

/// `avatars` 热查核 (**R16-1**) —— 直读加密 `head_image.db` 的 `head_image` 表, 3 键对齐冷查引擎
/// `CMD_AVATARS`(不出头像 BLOB)。SQL 分页(无 proto, 同 emoticons)。auth 后即用, 不建 L1。
///
/// # Errors
/// 定位 / 取 key / head_image.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_avatars(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let head_image_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("head_image")
        .join("head_image.db");
    let key = cache_key(wxid).await?;
    let (avatars, has_more, total, dropped) = native_core::read_hot_avatars(&head_image_db, &key, limit, offset)
        .context("查头像失败 (head_image.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = avatars.iter().map(avatar_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_avatars".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_dropped(dropped as u64) // codex 审 P2: 走标准 meta.dropped_rows(不止 summary; with_dropped(0) 是 no-op)
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查企微联系人 → json 行 (**R16-1**: 3 键 = 冷查引擎 `CMD_BIZ_CONTACTS` 输出集)。
fn biz_contact_json(b: &native_core::QueriedBizContact) -> serde_json::Value {
    serde_json::json!({
        "user_name": b.user_name,
        "user_id": b.user_id,
        "brand_user_name": b.brand_user_name,
    })
}

/// `biz-contacts` 热查核 (**R16-1**) —— 直读加密 `bizchat.db` 的 `user_info` 表, 3 键对齐冷查引擎
/// `CMD_BIZ_CONTACTS`。SQL 分页(无 proto)。WHERE user_id != '' 对齐 pipeline 跳空。auth 后即用, 不建 L1。
///
/// # Errors
/// 定位 / 取 key / bizchat.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_biz_contacts(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let bizchat_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("bizchat")
        .join("bizchat.db");
    let key = cache_key(wxid).await?;
    let (biz, has_more, total, dropped) = native_core::read_hot_biz_contacts(&bizchat_db, &key, limit, offset)
        .context("查企微联系人失败 (bizchat.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = biz.iter().map(biz_contact_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_biz_contacts".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_dropped(dropped as u64)
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查朋友圈动态 → json 行 (**R16-1**: 7 键 = 冷查 `moments_query` 输出集)。
fn moment_json(m: &native_core::QueriedMoment) -> serde_json::Value {
    serde_json::json!({
        "author": m.author,
        "author_nickname": m.author_nickname,
        "create_time": m.create_time,
        "content_desc": m.content_desc,
        "media_count": m.media_count,
        "like_count": m.like_count,
        "comment_count": m.comment_count,
    })
}

/// `moments` 热查核 (**R16-1**) —— 直读加密 `sns.db` 的 `SnsTimeLine` 表, 复用 ETL `assemble_sns` 解
/// content XML, 7 键对齐冷查 `moments_query`。全扫(create_time 在 XML 里)。auth 后即用, 不建 L1。
///
/// # Errors
/// 定位 / 取 key / sns.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_moments(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let sns_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("sns")
        .join("sns.db");
    let key = cache_key(wxid).await?;
    let (moments, has_more, total, dropped) = native_core::read_hot_moments(&sns_db, &key, wxid, limit, offset)
        .context("查朋友圈失败 (sns.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = moments.iter().map(moment_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_moments".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    // 全扫 (codex 审 v3 P2): 整表 dropped 只留 summary, 不进 page-local meta.dropped_rows(见 hot_finder_visits 注)。
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查朋友圈点赞评论 → json 行 (**R16-3 子视图**: 5 键 = 冷查引擎 `CMD_INTERACTIONS` 输出集)。
fn interaction_json(it: &native_core::QueriedMomentInteraction) -> serde_json::Value {
    serde_json::json!({
        "create_time": it.create_time,
        // kind 出**原始** "like"/"comment"(冷查 Fmt::EnumStr 只作 table 渲染, JSON 出原始)。
        "kind": it.kind,
        "from_nickname": it.from_nickname,
        "from_user": it.from_user,
        "content": it.content,
    })
}

/// `interactions` 热查核 (**R16-3 子视图**) —— 直读加密 `sns.db` 的 `SnsTimeLine`, 逐动态 `parse_sns_interactions`
/// 抽赞/评(一动态多互动), 5 键对齐冷查引擎 `CMD_INTERACTIONS`(表 `moment_interaction`): create_time/kind/
/// from_nickname/from_user/content。全扫(互动时刻/序号在 XML 里, SQL 排不了)。与 moments 同源同解码函数。
///
/// # Errors
/// 定位 / 取 key / sns.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_interactions(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let sns_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("sns")
        .join("sns.db");
    let key = cache_key(wxid).await?;
    let (items, has_more, total, dropped) = native_core::read_hot_moment_interactions(&sns_db, &key, limit, offset)
        .context("查朋友圈点赞评论失败 (sns.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = items.iter().map(interaction_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_interactions".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查朋友圈互动通知 → json 行 (**R16-3 子视图**: 5 键 = 冷查引擎 `CMD_SNS_NOTIFY` 输出集)。
fn sns_notify_json(n: &native_core::QueriedSnsNotify) -> serde_json::Value {
    serde_json::json!({
        "create_time": n.create_time,
        "notify_type": n.notify_type,
        "from_user": n.from_user,
        "from_nickname": n.from_nickname,
        "content": n.content,
    })
}

/// `sns_notify`(朋友圈互动通知)热查核 (**R16-3 子视图**) —— 直读加密 `sns.db` 的 `SnsMessage_tmp3`(一通知一行),
/// 5 键对齐冷查引擎 `CMD_SNS_NOTIFY`(表 `sns_notify`): create_time/notify_type/from_user/from_nickname/content。
/// 全扫(全表重扫无过滤, 同冷查 pipeline)。
///
/// # Errors
/// 定位 / 取 key / sns.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_sns_notify(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let sns_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("sns")
        .join("sns.db");
    let key = cache_key(wxid).await?;
    let (items, has_more, total, dropped) = native_core::read_hot_sns_notify(&sns_db, &key, limit, offset)
        .context("查朋友圈互动通知失败 (sns.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = items.iter().map(sns_notify_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_sns_notify".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查收藏媒体 → json 行 (**R16-3 子视图**: 6 键 = 冷查引擎 `CMD_FAV_MEDIA` 输出集)。
fn favorite_media_json(m: &native_core::QueriedFavoriteMedia) -> serde_json::Value {
    serde_json::json!({
        "fav_server_id": m.fav_server_id,
        "seq": m.seq,
        // data_type 出**原始** i64 (2图/6文件/8HTML; 冷查 Fmt::EnumI64 只作 table)。
        "data_type": m.data_type,
        "media_md5": m.media_md5,
        // media_size 出**原始** i64 字节 (冷查 Fmt::Bytes 只作 table)。
        "media_size": m.media_size,
        "data_fmt": m.data_fmt,
    })
}

/// `favorite_media`(收藏媒体)热查核 (**R16-3 子视图**) —— 直读加密 `favorite.db` 的 `fav_db_item`(笔记 type=18
/// content), 逐收藏 `parse_note_media` 抽媒体引用(一收藏多媒体), 6 键对齐冷查引擎 `CMD_FAV_MEDIA`(表
/// `favorite_media`): fav_server_id/seq/data_type/media_md5/media_size/data_fmt。全扫。
///
/// # Errors
/// 定位 / 取 key / favorite.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_favorite_media(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let fav_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("favorite")
        .join("favorite.db");
    let key = cache_key(wxid).await?;
    let (items, has_more, total, dropped) = native_core::read_hot_favorite_media(&fav_db, &key, limit, offset)
        .context("查收藏媒体失败 (favorite.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = items.iter().map(favorite_media_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_fav_media".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查收藏标签 → json 行 (**R16-3 子视图**: 3 键 = 冷查引擎 `CMD_FAV_TAGS` 输出集)。
fn favorite_tag_json(t: &native_core::QueriedFavoriteTag) -> serde_json::Value {
    serde_json::json!({
        "tag_server_id": t.tag_server_id,
        "fav_server_id": t.fav_server_id,
        "tag_name": t.tag_name,
    })
}

/// `favorite_tag`(收藏标签)热查核 (**R16-3 子视图**) —— 直读加密 `favorite.db` 的 `fav_bind_tag_db_item LEFT JOIN
/// fav_tag_db_item`(绑定 ⋈ 标签名), 按 anchor 去重(同冷 L2 upsert), 3 键对齐冷查引擎 `CMD_FAV_TAGS`(表
/// `favorite_tag`): tag_server_id/fav_server_id/tag_name。全扫。
///
/// # Errors
/// 定位 / 取 key / favorite.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_favorite_tags(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    let fav_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("favorite")
        .join("favorite.db");
    let key = cache_key(wxid).await?;
    let (items, has_more, total, dropped) = native_core::read_hot_favorite_tags(&fav_db, &key, limit, offset)
        .context("查收藏标签失败 (favorite.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = items.iter().map(favorite_tag_json).collect();
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_fav_tags".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 一条热查红包领取明细 → json 行 (**R16-4 `money --claims`**: 5 键 = 冷查引擎 [`crate::CMD_HONGBAO`] 输出集)。
///
/// `create_time`/`conv_id` 来自消息本体; 其余 3 键取 `parse_hongbao_claim` 的
/// [`HongbaoClaim`](native_core::decoder::HongbaoClaim): send_id/is_own_envelope/peer_name (与冷查 L2
/// `message_hongbao_claim` 表同源, `project_message_hongbao_claim` 同一 `parse_hongbao_claim` → 零漂移)。
/// **is_own_envelope 出整数 0/1** (冷查该列存 i64, registry JSON 出原始值 Fmt::EnumI64 只作用 table; 出 bool 会
/// 与冷查 i64 逐字节分歧 —— 同 mentions is_at_all 教训)。
fn hongbao_claim_json(
    create_time: i64,
    conv_id: &str,
    claim: &native_core::decoder::HongbaoClaim,
) -> serde_json::Value {
    serde_json::json!({
        "create_time": create_time,
        "conv_id": conv_id,
        "send_id": claim.send_id,
        "is_own_envelope": i64::from(claim.is_own_envelope),
        "peer_name": claim.peer_name,
    })
}

/// `money --claims` 热查核 (**R16-4 registry 族**) —— `scan_all_messages` base_types=[10000] 扫系统消息(msg10000),
/// `parse_hongbao_claim`(与冷查 `project_message_hongbao_claim` 同一 parse → 零漂移)取红包领取通知。5 键对齐冷查
/// 引擎命令 [`crate::CMD_HONGBAO`]。排序/spawn_blocking/scan_permit 同 hot_cards; **冷查次键**已在 CMD_HONGBAO
/// order_by 补齐。
///
/// **content_ok guard** (同 events/biz): 先跳正文 zstd 解码失败行 —— 冷查 assemble_message 丢这些行,
/// `message_hongbao_claim` 表不含; 热查须跳, 防损坏行 text 碰巧含 "HongbaoIcon" 标记误落 (mentions 教训: 显式 guard)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_hongbao_claims(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫系统消息, 有界 TopN 留 top-(offset+limit) 按 create_time/source/source_native_id DESC(同 CMD_HONGBAO)。
        // payload=(conv_id, HongbaoClaim), json 由 hongbao_claim_json 出。
        let mut top: TopN<(String, native_core::decoder::HongbaoClaim)> = TopN::new(offset, limit);
        let stats = sq
            .scan_all_messages(false, Some(&[10000]), |m, _msgsource, src| {
                // content_ok guard: 冷查丢损坏行 → 热查也须跳 (防 text 碰巧含 "HongbaoIcon" 误落)。
                if m.content_ok {
                    let mt = i32::try_from(m.msg_type).unwrap_or(-1);
                    if let Some(claim) = native_core::decoder::parse_hongbao_claim(mt, &m.text) {
                        top.offer(m.create_time, src, &m.source_native_id, || (m.conv_id.clone(), claim));
                    }
                }
                true
            })
            .context("全扫系统消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| hongbao_claim_json(k.ct, &k.payload.0, &k.payload.1))
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_hongbao_claims".into(), serde_json::json!(total));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查红包领取扫描任务失败: {e}"),
        )
    })?
}

/// 一条热查群收款付款人 → json 行 (**R16-4 `money --payers`**: 4 键 = 冷查引擎 [`crate::CMD_GROUP_PAY_MEMBERS`] 输出集)。
///
/// bill_no/payer_wxid/amount_fen/pay_status 取 `parse_appmsg` 的 group_pay_members (与冷查 `project_group_pay_members`
/// 同一 `parse_appmsg` payerlist → 零漂移)。**amount_fen 出原始 i64 分, pay_status 出原始 0/1 整数** (冷查列存 i64,
/// registry JSON 出原始值; Fmt::Money/EnumI64 只作用 table)。
fn group_pay_member_json(bill_no: &str, payer_wxid: &str, amount_fen: i64, pay_status: i64) -> serde_json::Value {
    serde_json::json!({
        "bill_no": bill_no,
        "payer_wxid": payer_wxid,
        "amount_fen": amount_fen,
        "pay_status": pay_status,
    })
}

/// `money --payers` 热查核 (**R16-4 registry 族, 一对多**) —— `scan_all_messages` base_types=[49] 扫 appmsg 消息(msg49),
/// `parse_appmsg` 取 **type2001 带 newaa 群收款**的 payerlist(与冷查 `project_group_pay_members` 同一 parse → 零漂移),
/// **一群收款消息 → 多付款人行**。4 键对齐冷查引擎命令 [`crate::CMD_GROUP_PAY_MEMBERS`]。
///
/// **排序键是 bill_no (String) 非 create_time** → 不用 TopN(那是 create_time i64 键), 改**全量 collect + Vec sort**
/// (group_pay_member 小, 真跑 246 行): sort (bill_no DESC, source DESC, source_native_id DESC, payer_wxid DESC) 逐列
/// 同冷查 order_by(R16-4 补全 PK 尾次键)→ offset 跨页不重不漏。**content_ok guard** 同 events/claims(冷查 assemble
/// 丢损坏行不落 message 表 → 热查须跳)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_group_pay_members(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 一对多全收 (排序键 bill_no 是 String, 用 Vec+sort 非 TopN)。元组 = (bill_no, payer_wxid, amount_fen, pay_status, source, source_native_id)。
        let mut rows: Vec<(String, String, i64, i64, String, String)> = Vec::new();
        let stats = sq
            .scan_all_messages(false, Some(&[49]), |m, _msgsource, src| {
                // content_ok guard: 冷查丢损坏行 → 热查也须跳。
                if m.content_ok {
                    // parse_appmsg 同冷查 project_group_pay_members: group_pay_bill_no Some + members 非空 (非群收款 bill_no=None 跳)。
                    if let Some(card) = native_core::decoder::parse_appmsg(&m.text) {
                        if let Some(bill_no) = card.group_pay_bill_no {
                            // **同 payer 去重 keep-last** (codex P2): 冷查 sink 对同消息 payerlist 逐条 `INSERT OR REPLACE`
                            // 撞 PK (…, payer_wxid_sha) → 同 payer 多项时**后写覆盖**只落 1 行 (amount/status 取末次)。热查逐项
                            // push 会冷 1 行/热多行分叉。同消息 source_native_id 固定 → 去重键 = payer_wxid (= PK 尾)。真库暂无
                            // 重复 payer, 但契约须对齐冷 upsert (同 fav_tags dedup 1659b18)。HashMap 无序被下方全局 sort 洗掉。
                            let mut per_msg: std::collections::HashMap<String, (i64, i64)> =
                                std::collections::HashMap::new();
                            for (payer, amount, status) in card.group_pay_members {
                                per_msg.insert(payer, (amount, status)); // keep-last
                            }
                            for (payer, (amount, status)) in per_msg {
                                rows.push((
                                    bill_no.clone(),
                                    payer,
                                    amount,
                                    status,
                                    src.to_string(),
                                    m.source_native_id.clone(),
                                ));
                            }
                        }
                    }
                }
                true
            })
            .context("全扫群收款消息失败 (key 不对 / 库损坏?)")?;
        // 逐列同冷查 CMD_GROUP_PAY_MEMBERS order_by (bill_no DESC, source DESC, source_native_id DESC, payer_wxid DESC)。
        rows.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.4.cmp(&a.4))
                .then_with(|| b.5.cmp(&a.5))
                .then_with(|| b.1.cmp(&a.1))
        });
        let total = rows.len();
        let data: Vec<serde_json::Value> = rows
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(bill_no, payer, amount, status, _src, _snid)| {
                group_pay_member_json(&bill_no, &payer, amount, status)
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_group_pay_members".into(), serde_json::json!(total));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查群收款付款人扫描任务失败: {e}"),
        )
    })?
}

/// `money` 默认档热查核 (**R16-4, 两源混合 — R16 最复杂命令**) —— 三笔交易 (转账/红包/群收款) 合并时间线。
///
/// **源①** general.db 三专表 (transferTable/redEnvelopeTable/groupPayTable) 经 [`native_core::read_hot_money_base`]
/// VFS 直读拿基础行。**源②** msg49 appmsg (`scan_all_messages` base_types=[49] + `parse_appmsg`) 建三张 map 补金额/人数:
/// - `fee_map[transcation_id] = feedesc` (转账金额; 冷 JOIN message_app.transfer_fee, 只收非空, keep-first ≈ 冷 LIMIT 1)
/// - `amount_map[bill_no] = senderdes` (群收款金额; 冷 JOIN message_app.group_pay_amount, 同上)
/// - `member_agg[bill_no] = (已付, 总人数)` (冷 count group_pay_member; **按 (bill,snid,payer) 去重 keep-last** 对齐
///   冷 INSERT OR REPLACE PK, 已付=去重后 status==1 计数)
///
/// 组装成 (kind, time, who, detail) 后**合并全序** (时间 DESC, source DESC, source_native_id DESC; 红包 time=None 沉末尾)
/// 再 skip/take —— **detail 格式逐字节复刻冷查 query_transfers/red/group** (parity 兜底防漂移)。`total` = 选源真 COUNT
/// 之和 (专表全读 → Vec 长度即 COUNT, 同冷 money_query)。分页在合并后内存切片。
///
/// # Errors
/// 定位 / 取 key / general.db 解密 / 建定位表 / 扫描失败 → 携码上抛。
#[allow(clippy::too_many_lines)]
pub async fn hot_money(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    kind: crate::MoneyKind,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?;
    let general_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("general")
        .join("general.db");
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        // 源①: general.db 三专表基础行 (VFS 直读; 借 &key, 用完借用结束再把 key move 进 SourceQuery)。
        let base = native_core::read_hot_money_base(&general_db, &key)
            .context("读 general.db 交易专表失败 (解密失败? key 不对 / 没跑过 `auth`?)")?;
        // 源②: 扫 msg49 建 fee/amount/member map。
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build().context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        let mut fee_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut amount_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        // (bill_no, source_native_id, payer_wxid) → status; keep-last 去重 = 冷 group_pay_member INSERT OR REPLACE PK。
        let mut member_dedup: std::collections::HashMap<(String, String, String), i64> = std::collections::HashMap::new();
        let stats = sq
            .scan_all_messages(false, Some(&[49]), |m, _msgsource, _src| {
                if m.content_ok {
                    if let Some(card) = native_core::decoder::parse_appmsg(&m.text) {
                        // 转账金额: txid→feedesc (冷 JOIN 只收非空 + LIMIT 1)。用 `or_insert` keep-first。
                        // **keep-first vs 冷 LIMIT 1(无 ORDER BY)为何不分叉**(codex P2 复核): feedesc = 该笔交易金额,
                        // 是 **transcation_id 的不变量** —— 一笔转账收发两条消息带同 txid 但金额恒同(交易金额不会变)。
                        // 故同 txid 的所有 msg49 feedesc 逐字节相等, keep-first / LIMIT 1 / 任意行选出的**值都一样**,
                        // 与选中哪一行无关。实测坐实: `SELECT transfer_txid, COUNT(DISTINCT transfer_fee) FROM message_app
                        // GROUP BY transfer_txid HAVING COUNT(DISTINCT ...)>1` 真库返 0 行 (无冲突)。真跑 parity 2848 零分叉。
                        if let (Some(txid), Some(fee)) = (card.transfer_txid.as_ref(), card.transfer_fee.as_ref()) {
                            if !txid.is_empty() {
                                fee_map.entry(txid.clone()).or_insert_with(|| fee.clone());
                            }
                        }
                        // 群收款金额: bill_no→senderdes。同上 keep-first, senderdes = bill_no 不变量 (每人应付额恒定,
                        // 实测 COUNT(DISTINCT group_pay_amount) per bill_no 无 >1)。
                        if let (Some(bill), Some(amt)) = (card.group_pay_bill_no.as_ref(), card.group_pay_amount.as_ref())
                        {
                            if !bill.is_empty() {
                                amount_map.entry(bill.clone()).or_insert_with(|| amt.clone());
                            }
                        }
                        // 群收款付款人: (bill,snid,payer) keep-last 去重 (同 hot_group_pay_members)。
                        if let Some(bill) = card.group_pay_bill_no.as_ref() {
                            for (payer, _amt, status) in &card.group_pay_members {
                                member_dedup.insert(
                                    (bill.clone(), m.source_native_id.clone(), payer.clone()),
                                    *status,
                                );
                            }
                        }
                    }
                }
                true
            })
            .context("全扫交易消息失败 (key 不对 / 库损坏?)")?;
        // member_dedup → member_agg[bill_no] = (已付 status==1 计数, 总人数)。
        let mut member_agg: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
        for ((bill, _snid, _payer), status) in &member_dedup {
            let e = member_agg.entry(bill.clone()).or_insert((0, 0));
            e.1 += 1;
            if *status == 1 {
                e.0 += 1;
            }
        }
        // 组装 MoneyRow = (time: Option<i64>, kind: &str, who, detail, source, source_native_id)。detail 逐字节复刻冷查。
        let want = |k: crate::MoneyKind| kind == crate::MoneyKind::All || kind == k;
        let src = "general.db".to_string();
        #[allow(clippy::type_complexity)]
        let mut rows: Vec<(Option<i64>, &'static str, String, String, String, String)> = Vec::new();
        let mut total = 0usize;
        if want(crate::MoneyKind::Transfer) {
            total += base.transfers.len();
            for t in &base.transfers {
                let detail = fee_map
                    .get(&t.transcation_id)
                    .cloned()
                    .unwrap_or_else(|| format!("(金额见消息) 状态码{}", t.pay_sub_type));
                rows.push((
                    Some(t.begin_transfer_time),
                    "转账",
                    format!("{} → {}", t.pay_payer, t.pay_receiver),
                    detail,
                    src.clone(),
                    format!("Transfer_{}", t.transfer_id),
                ));
            }
        }
        if want(crate::MoneyKind::RedEnvelope) {
            total += base.reds.len();
            for r in &base.reds {
                let detail = format!(
                    "类型码{}/状态码{} @{} (金额本地不存)",
                    r.hb_type, r.receive_status, r.session_name
                );
                rows.push((
                    None,
                    "红包",
                    r.sender_user_name.clone(),
                    detail,
                    src.clone(),
                    format!("RedEnvelope_{}", r.send_id),
                ));
            }
        }
        if want(crate::MoneyKind::GroupPay) {
            total += base.groups.len();
            for g in &base.groups {
                let (paid, payers) = member_agg.get(&g.bill_no).copied().unwrap_or((0, 0));
                let amount = amount_map.get(&g.bill_no).map(String::as_str).unwrap_or("(金额?)");
                let detail = format!("{amount} 已付{paid}/{payers}人");
                rows.push((
                    Some(g.message_create_time),
                    "群收款",
                    g.session_name.clone(),
                    detail,
                    src.clone(),
                    format!("GroupPay_{}", g.bill_no),
                ));
            }
        }
        // 合并全序 (时间 DESC, source DESC, source_native_id DESC; None 红包沉末尾 = None<Some) —— 同冷 money_query sort。
        rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.4.cmp(&a.4)).then_with(|| b.5.cmp(&a.5)));
        let data: Vec<serde_json::Value> = rows
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(time, k, who, detail, _src, _snid)| serde_json::json!({"kind": k, "time": time, "who": who, "detail": detail}))
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_money".into(), serde_json::json!(total));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert("scan_truncated_tables".into(), serde_json::json!(stats.truncated_tables));
            summary.insert("scan_build_degraded_shards".into(), serde_json::json!(stats.build_degraded_shards));
            summary.insert("scan_content_failed".into(), serde_json::json!(stats.content_failed_rows));
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查交易扫描任务失败: {e}")))?
}

/// `pii-scan` 热查核 (**R16-5 慢档**) —— 全库扫文本消息 (msg1) 抽手机号/身份证。`scan_all_messages` base_types=[1] +
/// **纯函数复用** `crate::scan_pii_in_text`(与冷查 query_pii_scan 同一函数 → 零漂移)。**冷查有 GLOB 11 位预筛**(phone 11
/// /idcard 18 位都含 11 位数字串 → GLOB 匹配 ⊇ 所有 PII 消息; scan_pii_in_text 才是真检测)→ 热查扫全 msg1 + scan_pii_in_text
/// (非 PII 文本返空)结果**逐条同冷**。
///
/// **一消息多命中**(phone+idcard)→ 多行; 排序键 create_time(单键)非 registry, 用**全量 collect + Vec sort**
/// (create_time/source/source_native_id DESC + **消息内 scan 序 hit_seq ASC**)逐字节同冷 ORDER BY(已补次键)。top-N 无 offset。
/// `reveal=false` 时 `crate::mask_pii` 打码(同冷)。summary 计 phone_total/idcard_total/messages_flagged(全命中计数, 非仅 top-N)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_pii_scan(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    kind: crate::PiiKind,
    reveal: bool,
    limit: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(0, limit)?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    let want_phone = matches!(kind, crate::PiiKind::All | crate::PiiKind::Phone);
    let want_id = matches!(kind, crate::PiiKind::All | crate::PiiKind::Idcard);
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build().context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // (create_time, source, source_native_id, hit_seq, conv_id, sender, kind, value)。命中稀疏 → Vec 全收。
        #[allow(clippy::type_complexity)]
        let mut rows: Vec<(i64, String, String, usize, String, Option<String>, &'static str, String)> = Vec::new();
        let mut phone_total = 0usize;
        let mut id_total = 0usize;
        let mut msgs_flagged = 0usize;
        let stats = sq
            .scan_all_messages(false, Some(&[1]), |m, _msgsource, src| {
                // content_ok guard: 冷查 assemble 丢损坏行 → 热查也须跳 (空文本 scan 也返空, 但显式跳齐整)。
                if m.content_ok {
                    let hits = crate::scan_pii_in_text(&m.text, want_phone, want_id);
                    if !hits.is_empty() {
                        msgs_flagged += 1;
                    }
                    for (seq, (k, v)) in hits.into_iter().enumerate() {
                        if k == "手机号" {
                            phone_total += 1;
                        } else {
                            id_total += 1;
                        }
                        rows.push((
                            m.create_time,
                            src.to_string(),
                            m.source_native_id.clone(),
                            seq,
                            m.conv_id.clone(),
                            m.sender.clone(),
                            k,
                            v,
                        ));
                    }
                }
                true
            })
            .context("全扫文本消息失败 (key 不对 / 库损坏?)")?;
        // 同冷 ORDER BY create_time DESC, source DESC, source_native_id DESC + 消息内 hit_seq ASC。
        rows.sort_by(|a, b| {
            b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| b.2.cmp(&a.2)).then_with(|| a.3.cmp(&b.3))
        });
        let data: Vec<serde_json::Value> = rows
            .iter()
            .take(limit)
            .map(|(ct, _src, _snid, _seq, conv, sender, k, v)| {
                let value = if reveal { v.clone() } else { crate::mask_pii(k, v) };
                serde_json::json!({"create_time": ct, "conv_id": conv, "sender_wxid": sender, "kind": k, "value": value})
            })
            .collect();
        let has_more = data.len() < phone_total + id_total;
        let mut summary = serde_json::Map::new();
        summary.insert("messages_flagged".into(), serde_json::json!(msgs_flagged));
        summary.insert("phone_total".into(), serde_json::json!(phone_total));
        summary.insert("idcard_total".into(), serde_json::json!(id_total));
        summary.insert("shown".into(), serde_json::json!(data.len()));
        summary.insert("masked".into(), serde_json::json!(!reveal));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert("scan_truncated_tables".into(), serde_json::json!(stats.truncated_tables));
            summary.insert("scan_build_degraded_shards".into(), serde_json::json!(stats.build_degraded_shards));
            summary.insert("scan_content_failed".into(), serde_json::json!(stats.content_failed_rows));
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查 PII 扫描任务失败: {e}")))?
}

/// `extract` 热查核 (**R16-5 慢档**) —— 全库扫文本消息 (msg1) 抽 url/email/amount/phone/idcard。`scan_all_messages`
/// base_types=[1] + **纯函数复用** `crate::extract_matches`(与冷查 query_extract 同一函数; phone/idcard 内部走
/// scan_pii_in_text, 其余走 `crate::extract_regex`)。**冷查有 where_extra 预筛**(Url LIKE '%http%'/Email LIKE '%@%'
/// /Amount 无预筛/Phone-Idcard GLOB11)—— 都是 extract_matches 命中的**必要子串**(url 必含 http/email 必含 @/phone-idcard
/// 必含11位串)→ 预筛无损, 热查扫全 msg1 结果逐条同冷。
///
/// **一消息多命中→多行**; **有 offset**(全局跳前 offset 个命中再取 limit, 同冷); 全量 collect + Vec sort
/// (create_time/source/source_native_id DESC + 消息内 hit_seq ASC, 同冷 order_by 已带次键)。`date` 字段**每页用
/// in-memory SQLite `date(?,'unixepoch','localtime')` 算**(同 hot_events/biz; Rust 算日界线会分叉)。
///
/// # Errors
/// 正则编译 / 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_extract(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    kind: crate::ExtractKind,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?;
    let re = crate::extract_regex(kind).map_err(|e| cli_err(native_core::ErrorCode::Internal, e.to_string()))?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build().context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // (create_time, source, source_native_id, hit_seq, conv_id, sender, value)。
        // **内存注 (Claude 审 P3)**: 全量 collect 后 sort 取 top-(offset+limit)。dense 类(url/amount 无 where_extra 预筛)
        // 命中可达百万级(真跑 url 1.2M 命中 ~180MB, 通过无 OOM)。有界性靠: ① `HOT_SCAN_SEMAPHORE` scan_permit 限并发热扫
        // (serve 侧同时只跑少数)② `spawn_blocking` 只吃内存不冻 async 运行时 ③ 命中数被账号真实 msg1 数硬上界(有限)。
        // 最坏(amount 超大账号)可 O(命中数) 内存尖峰 —— 未来可换有界堆(需给 hit_seq ASC 编 tie, 见 TopN::offer_tie);
        // 当前保 Vec 与已双审 clean 的 hot_pii_scan 同构, 且 top-N 序需消息内 hit_seq ASC(全量 sort 天然满足)。
        #[allow(clippy::type_complexity)]
        let mut rows: Vec<(i64, String, String, usize, String, Option<String>, String)> = Vec::new();
        let mut msgs = 0usize;
        let mut total = 0usize;
        let stats = sq
            .scan_all_messages(false, Some(&[1]), |m, _msgsource, src| {
                if m.content_ok {
                    let hits = crate::extract_matches(&m.text, kind, re.as_ref());
                    if !hits.is_empty() {
                        msgs += 1;
                        total += hits.len();
                    }
                    for (seq, v) in hits.into_iter().enumerate() {
                        rows.push((
                            m.create_time,
                            src.to_string(),
                            m.source_native_id.clone(),
                            seq,
                            m.conv_id.clone(),
                            m.sender.clone(),
                            v,
                        ));
                    }
                }
                true
            })
            .context("全扫文本消息失败 (key 不对 / 库损坏?)")?;
        rows.sort_by(|a, b| {
            b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| b.2.cmp(&a.2)).then_with(|| a.3.cmp(&b.3))
        });
        // date 每页 in-memory SQLite localtime (同 hot_events/biz)。
        let dconn = rusqlite::Connection::open_in_memory()
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("date 计算失败: {e}")))?;
        let label = crate::extract_kind_label(kind);
        let data: Vec<serde_json::Value> = rows
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(ct, _src, _snid, _seq, conv, sender, v)| {
                let day: String = dconn
                    .query_row("SELECT date(?1/1000,'unixepoch','localtime')", [ct], |r| r.get(0))
                    .unwrap_or_default();
                serde_json::json!({"create_time": ct, "date": day, "conv_id": conv, "sender_wxid": sender, "kind": label, "value": v})
            })
            .collect();
        let has_more = offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("messages_matched".into(), serde_json::json!(msgs));
        summary.insert("total_matches".into(), serde_json::json!(total));
        summary.insert("shown".into(), serde_json::json!(data.len()));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert("scan_truncated_tables".into(), serde_json::json!(stats.truncated_tables));
            summary.insert("scan_build_degraded_shards".into(), serde_json::json!(stats.build_degraded_shards));
            summary.insert("scan_content_failed".into(), serde_json::json!(stats.content_failed_rows));
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查 extract 扫描任务失败: {e}")))?
}

/// `stats` 热查核 (**R16-5 慢档, 聚合命令**) —— 全库消息按维度 (--by type/conv/sender/day) 分组计数。
/// `scan_all_messages` base_types=None (**全类型, 非只 msg1**; 同冷查 stats 数 `count(*) FROM message`) + HashMap 累加。
/// 维度值: type←`m.msg_type_name`(扫时已算), conv←`m.conv_id`, sender←`m.sender`(空→"(空)" 同冷 unwrap_or),
/// day←in-memory SQLite `date(?,'unixepoch','localtime')`(同 events/biz; **按小时桶缓存**避 750万次调用: UTC 整点桶
/// 在整数时区下 1:1 落一个 localtime 日)。排序 (count DESC, label ASC) + skip/take, 同冷 `ORDER BY n DESC, label ASC`。
///
/// **parity 语义 (聚合非行列表)**: 冷热对拍不是保序子序列, 是**逐组计数单调** —— 冷每组 label 在热出现且热 count ≥ 冷
/// count (差=活源增长); 老数据组相等, 活跃组(最近 day/conv/sender)热更大。皮层/验收按此核, 非子序列。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_stats(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    by: crate::StatsBy,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        let dconn = rusqlite::Connection::open_in_memory()
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("date 计算失败: {e}")))?;
        let mut day_cache: std::collections::HashMap<i64, String> = std::collections::HashMap::new();
        let mut groups: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        let mut total: i64 = 0;
        let stats = sq
            .scan_all_messages(false, None, |m, _msgsource, _src| {
                total += 1;
                let label = match by {
                    crate::StatsBy::Type => m.msg_type_name.clone(),
                    crate::StatsBy::Conv => m.conv_id.clone(),
                    crate::StatsBy::Sender => m.sender.clone().unwrap_or_else(|| "(空)".to_string()),
                    crate::StatsBy::Day => {
                        // **15 分钟桶缓存** (codex P2): 每桶算一次 SQLite localtime date, 桶内消息共用。用 15 分钟(非小时)桶
                        // 因: 所有现代时区偏移都是 15 分钟倍数(印度+5:30/尼泊尔+5:45), 一个 15 分钟 UTC 窗口转 localtime 后
                        // 仍对齐 15 分钟网格、午夜(00:00)在 15 分钟边界 → 窗口不跨 localtime 日界 → 桶内 date 唯一。小时桶只对
                        // 整数时区安全(非整数时区一个 UTC 整点会跨午夜, 整桶被误并到首条日期)。DST 换偏移仍是整数小时不破对齐。
                        let bucket = m.create_time / 900_000;
                        day_cache
                            .entry(bucket)
                            .or_insert_with(|| {
                                dconn
                                    .query_row(
                                        "SELECT date(?1/1000,'unixepoch','localtime')",
                                        [m.create_time],
                                        |r| r.get::<_, Option<String>>(0),
                                    )
                                    .ok()
                                    .flatten()
                                    // date() 返 NULL(create_time 非法)→ "(空)" 对齐冷查 label.unwrap_or("(空)") (codex P2)。
                                    .unwrap_or_else(|| "(空)".to_string())
                            })
                            .clone()
                    }
                };
                *groups.entry(label).or_insert(0) += 1;
                true
            })
            .context("全扫消息失败 (key 不对 / 库损坏?)")?;
        // 排序同冷查 ORDER BY n DESC, label ASC。
        let mut sorted: Vec<(String, i64)> = groups.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let n_groups = sorted.len();
        let data: Vec<serde_json::Value> = sorted
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(l, n)| serde_json::json!({"label": l, "count": n}))
            .collect();
        let has_more = offset.saturating_add(data.len()) < n_groups;
        let dim = crate::stats_dimension_label(by);
        let mut summary = serde_json::Map::new();
        summary.insert("total_messages".into(), serde_json::json!(total));
        summary.insert("dimension".into(), serde_json::json!(dim));
        summary.insert("groups_shown".into(), serde_json::json!(data.len()));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查 stats 扫描任务失败: {e}"),
        )
    })?
}

/// 往保底集里塞一行 —— **按逻辑会话记名额, 且满了之后只让更靠前的会话顶掉更靠后的**。
///
/// 两件都是 codex 审 80b3e74 点出来的, 各自会让这个功能白做:
///
/// 一, **名额得按 `conv_id` 记, 不能按 (分片, 会话表) 记**。同一个会话可以同时存在于多个分片 ——
/// 真库实测 700 张同名 `Msg_` 表同时在 `message_0.db` 和 `message_5.db`。按表记的话, 一个横跨
/// 三个分片的会话会拿到三份保底名额, 把别的会话挤出去 —— 正是这个功能要治的那个毛病。
///
/// 二, **满了之后按"谁先扫到"丢是不安全的**, 所以这里用有序表 + "只有比现存最靠后那个会话更靠前
/// 才顶掉它", 拿到的就是 `conv_id` 最小的那一批, 跟分配那头同一个序。
///
/// ⚠️ **这个顶替分支目前是死代码, 而我原来给的理由是假的**(独立复审 656477c 后一轮点出来的):
/// 我写的是"扫描顺序是 (分片, 会话, 行号), 跨分片时会话不按 conv_id 升序" —— **不对**,
/// 计划那头(`live_query.rs`)是**先按 conv_id 排序**, 分片是内层循环。复审插桩量过:
/// 两万例里"满了且新会话到来"命中 58500 次, **真发生顶替 0 次**。
/// 留着不删是因为它是**兜底**: 哪天计划那头改了排序, 这里仍然给出对的结果, 而不是静默变成
/// "谁先扫到谁赢"。但别再拿那个假理由说事。
fn offer_floor(
    floors: &mut std::collections::BTreeMap<String, Vec<Keyed<NewRow>>>,
    floor_rows: &mut usize,
    conv_id: &str,
    limit: usize,
    per_conv: usize,
    row: impl FnOnce() -> Keyed<NewRow>,
) {
    if per_conv == 0 || limit == 0 {
        return;
    }
    if let Some(slot) = floors.get_mut(conv_id) {
        // ⚠️ **总量上限对老会话同样管用**(codex 审 1cdb2fd 的 P2): 早先这一支只看
        // `slot.len() < per_conv`, 于是 `limit=1, per_conv=100000` 时头一个会话能自己留下十万行 ——
        // 说好的"总量卡在 limit"当场作废, 内存变成 limit × per_conv。
        if slot.len() < per_conv && *floor_rows < limit {
            slot.push(row());
            *floor_rows += 1;
        }
        return;
    }
    if *floor_rows < limit {
        floors.insert(conv_id.to_string(), vec![row()]);
        *floor_rows += 1;
        return;
    }
    // 满了: 只有比现存最靠后那个会话更靠前, 才值得腾位置。
    //
    // ⚠️ **先借用着比, 真要顶替才 clone**(独立复审的 P3): 早先这里无条件 `.cloned()`。保底集填满之后,
    // **还没进保底集的那些会话**的每条新消息都会走到这儿(已经在集里的在上面 `get_mut` 那支就返回了) ——
    // `--reset` 时就是白分配一堆 String, 换来的是一个上面说的、永远不会走的分支。一次取值搞定,
    // 也不留那个够不着的 `else { return }`。
    let last = match floors.keys().next_back() {
        Some(last) if conv_id < last.as_str() => last.clone(),
        _ => return,
    };
    // ⚠️ **只腾一格, 不是把那个会话整个扔掉**(codex 审 1cdb2fd 的 P2): `per_conv > 1` 时,
    // 最靠后那个会话可能占着好几行, 而新来的只要一格。整个扔掉会多空出格子, 那些格子随后被
    // `apply_per_conv_floor` 拿全局最忙的会话填掉 —— 被扔的那个会话明明还装得下, 保底却没了。
    // 弹的是它**最后**那一行(行号最大的), 留下的仍是它的前缀 —— 水位那头靠这条。
    if let Some(slot) = floors.get_mut(&last) {
        slot.pop();
        *floor_rows -= 1;
        if slot.is_empty() {
            floors.remove(&last);
        }
    }
    floors.insert(conv_id.to_string(), vec![row()]);
    *floor_rows += 1;
}

/// **保底行先占位, 剩下的名额再按原来的顺序补** —— `--per-conv` 的全部逻辑。
///
/// `per_conv == 0` 原样返回, 一个字节都不动(默认就是这条)。
///
/// ⚠️ 不能"合并两边再取最小的 limit 条": 全局最小的 limit 条**就是** `kept`, 合完再截还是它,
/// 等于没做。保底的意思就是让后面会话的头几条**顶掉**前面会话的一部分。
///
/// ⚠️ 顺序性质不能破: 水位推进那一头假设"每张表展示的是它新行的前缀"。保底行取的是每张表的
/// **头 N 条** = 前缀; `kept` 本身是全局前缀 → 每张表也是前缀; 两边取并集再按键排序, 每张表拿到的
/// 仍然是前缀。截断也从尾巴截, 不破坏这一点。
///
/// 单拎成纯函数是为了**能测** —— `hot_new` 要真账号 + 加密库才跑得起来(那些测试全带 `#[ignore]`),
/// 逻辑埋在里面等于没人守。
fn apply_per_conv_floor(
    kept: Vec<Keyed<NewRow>>,
    floors: std::collections::BTreeMap<String, Vec<Keyed<NewRow>>>,
    limit: usize,
    per_conv: usize,
) -> Vec<Keyed<NewRow>> {
    if per_conv == 0 {
        return kept;
    }
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut out: Vec<Keyed<NewRow>> = Vec::with_capacity(limit);
    // 保底行按**会话顺序**依次占位。用有序表存的, 遍历本身就是 `conv_id` 升序 ——
    // 早先用 `HashMap` 存, 遍历序是随机的, 名额不够时"谁能占上"每次都不一样, 同样的库同样的水位
    // 两次跑结果会不同(我自己埋的坑, 守卫专门咬"跑五次结果必须一样")。
    //
    // ⚠️ **这一层确定了, 上一层还没有**(独立复审的 P3, 如实记): 一个会话横跨多个分片时,
    // **哪个分片的行**进保底集取决于 `locator` 里分片的排列顺序, 而那个顺序会随重扫历史变
    // (某个分片被重扫就会被挪到末尾)。所以跨分片会话在两次跑之间可能拿到不同分片的行。
    // **不丢数据**(每张表拿到的仍是它自己的前缀, 性质测两万例守着), 只是展示哪一条不完全确定。
    // 守卫只咬住了这一层, `floors` 是怎么攒出来的没人守。
    for row in floors.into_values().flatten() {
        if out.len() >= limit {
            break;
        }
        if seen.insert((row.src.clone(), row.snid.clone())) {
            out.push(row);
        }
    }
    for row in kept {
        if out.len() >= limit {
            break;
        }
        if seen.insert((row.src.clone(), row.snid.clone())) {
            out.push(row);
        }
    }
    out.sort_by(|a, b| (&a.src, &a.snid).cmp(&(&b.src, &b.snid)));
    out
}

/// `new` 一行的载荷 (时间/会话/发送者/类型/正文/行号/该表扫到这行为止吐了几行)。
type NewRow = (i64, String, Option<String>, String, String, i64, i64);

/// `new` 热查核 (**R16-5**) —— 源库**前向增量**: 全库扫消息, 用**逐会话表 `(src, conv_id) → max local_id` 水位**判"新":
/// 该会话表没见过(新会话/新分片) **或** `local_id > 该表水位` → 新消息。按 `(src, conv_id, local_id)` 升序(= 到达/ingest
/// 序, 同冷查 [`crate::new_query`] `rowid ASC` 语义)取最小 `limit` 条, 逐会话表把水位推到本批各表已扫出的最大 local_id。
/// 用 [`BottomN`](保最小)。
///
/// **为何逐会话表而非 create_time / 逐分片**(R16-5 双 P1 修 + 真跑坐实): 源库**分片**存储, 无全局插入计数器(那是 L1
/// ingest 的 rowid)。① create_time 当水位 → 漫游/多设备重登把**旧时间戳**历史消息此刻灌入, key < 水位被永久静默漏(冷走
/// rowid 能追到, 热漏 = P1-a)。② **`local_id` 是每会话 `Msg_<md5(conv)>` 表内的 AUTOINCREMENT rowid**(每会话各自从 1
/// 起, 一个分片文件含**数千张**这样的表 —— 真库 message_0.db 实测 3383 张表全部 MIN(local_id)=1), **非**分片内全局;
/// 故水位/排序键必须带 **conv_id 维(=物理表)**, 否则同分片跨会话 local_id 大量碰撞 → 除每文件最忙会话外全部漏新消息(逐分片
/// 版实测 3382/3383 会话下一条被吞)。③ 新到达(含灌入的旧历史)在其会话表拿**更大** local_id → 必 > 该表水位 → 追得到。
/// ④ 水位只推到**已扫出**的 local_id(读到前缀), 从不越过未读行 → 会话表截断/损坏也不永久漏(下轮恢复即追, 期间 `partial`
/// 诚实标)—— 故 partial 无需特殊处理, 逐会话表水位天然安全。
///
/// 与冷查 **L1 rowid** 水位**并存、各记各的**(用户①: 源库无 L1 rowid, L1 无源库 local_id, 两套后端各记各的位置)。
/// `wm=None` = `--reset` 全收。`summary.next_watermark` = 更新后的**逐会话表水位表** `{"src\x1fconv_id": max_local_id}` 供
/// 皮层持久化(空批时 == 旧水位, 幂等)。**drop 口径同冷**(跳 content_ok=false)。字段集 = 冷 `NewRow`; **行序按会话表分组**
/// (`(src,conv_id,local_id)` 到达序, **非** create_time 时序 —— datetime 仅参考列; 与冷 `rowid ASC` 同属到达序但分组粒度不同)。
///
/// `new --mode hot` 的逐会话表水位标记。
///
/// 原来这里只有一个裸的"读到第几条" —— 跟 L1 那条路修之前**一模一样**的病: 源库被换成另一份
/// 副本 / 表被重建时, `local_id <= 水位` 的消息**永远不会被报成"新"**, 用户只能自己想到 `--reset`。
/// (2026-07-30 用户拍板补护栏; 同批还补了瘦库那条。)
///
/// 加的这一项是 `n` = **已读那一段现在有几行**。这条路本来就**整表全扫**, 数一遍白送, 不多花一次查询。
/// 对不上就说明这张表不是原来那张了 → 把它的水位丢掉, **下一轮**整表当新的报出来。
///
/// ⚠️ **检出晚一轮**: "是不是新"这个判断在扫的过程中就要给出, 而"总共几行"要扫完才知道 ——
/// 所以本轮只能把水位复位、下一轮才补报。**不会永久漏**(复位之后那些行必然被报), 而且
/// summary 里的 `guard_reset_tables` 会如实说"这一轮复位了几张表", 不是静默的。
///
/// 老格式(裸数字)读得进来, `n` 记成 `None` = 还没建立 → 那一轮不比这一项, 扫完就建立起来了。
/// **不会因为升级就把全部历史当新的报一遍。**
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NewHotMark {
    /// 上次**报给用户**读到这张表的哪一行(`local_id`)。判"是不是新"用它。
    pub id: i64,
    /// **护栏的锚点** —— `n` / `ct` 量的是这一格, 跟 `id` 推到哪儿**无关**。`None` = 老水位, 当作 `id`。
    ///
    /// ⚠️ 这一层解耦是被逼出来的(独立复审连指三轮 + codex round-15 P1)。原来 `n` 隐式钉在 `id` 上,
    /// 于是"位置一推进, 旧的 n 就作废"—— 而"这一轮扫全了没有"和"这几行报给用户了没有"是**两件事**:
    ///   · 报给用户了就**必须**推 `id`, 不推就每轮重报同一批(还会把 `limit` 名额占满饿死别的表);
    ///   · 没扫全就**不能**拿偏小的数当基准。
    /// 绑在一起时只能二选一, 于是来回换了三轮: 整轮不写 → 全局关掉护栏 → 不推位置 → 永久卡住。
    /// 拆开之后两件事各走各的: `id` 照推, `gid` 只在"这张表扫全了且有新行"那一轮才跟上。
    /// 有永久坏行的表因此 `gid` 会停在老地方 —— **护栏仍然有效**(比的是老那一格), 只是覆盖面不再增长。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<i64>,
    /// 已读那一段的行数; `None` = 还没建立 / 这一轮扫得不全没敢写(下一轮扫一遍就有了)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<i64>,
    /// **游标那一行的 `create_time`**; `None` = 还没建立。
    ///
    /// 光比行数认不出"换了一份**行数一样**的副本"(codex round-12 P1): 那些行早被
    /// `local_id <= mark.id` 判成"不是新的"了, 于是**永久不报**。跟消息采集那条路的
    /// `TableProbe::cursor_ct` 同一个思路 —— `create_time` 写入时定死, 上传回写 / 撤回都不改它。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct: Option<i64>,
    /// **这张表越过去过一行读不出来的行** —— 那条消息此后永久报不出来。
    ///
    /// 一行列映射失败被跳过、而同表更靠后的行进了本批 ⟹ 汇报位置越过了它 ⟹ 它此后恒 `<= 位置`,
    /// 哪怕后来又读得出来也永远不算新。这是有意的取舍(2026-07-30 用户拍板"乙+"):
    /// 位置只推到坏行之前的话, **永久**坏行会把整张表卡死、还占满名额饿死别的会话 —— 那是更糟的病。
    /// 两条路口径不一致是有意的 —— 冷是批量导入, 卡住重来一次就好; 热是实时看, 一个永久坏行
    /// 卡死整张表等于这个功能废了。**但冷查也不是万能的**, 取决于坏在哪一列(逐处读码核过):
    ///
    /// | 坏在哪 | 热查 | 冷查 |
    /// |---|---|---|
    /// | 行号 `local_id` | 跳这一行 | **整批报错停下**(`source/account.rs` 硬 `?`) |
    /// | 其它整数列(`local_type`/`status`/`sort_seq`…) | 跳这一行 | 按 0 处理, **行照样落库** |
    /// | 正文解不开(zstd 坏) | 跳这一行 | 发一条错误事件, **也不落 `message` 表** |
    ///
    /// 所以"想找回那一行就走冷查"**只对中间那一类成立**。另外两类只能 `exec` 直接查源表看原始字节。
    ///
    /// **但静默不行。** 这个标记立起来之后**不会因为那一行恢复正常就自己灭**(丢的那一行不会自己回来),
    /// 每轮如实报进 `tables_with_lost_rows`。
    ///
    /// ⚠️ **有两条路会清掉它**(独立复审第二十一轮 P2 真跑逮到, 我原先三处都写成"只有 --reset"):
    /// ① `--reset`; ② **护栏复位**(源库像是换了一份副本) —— 换副本了, 旧那份丢的行跟这份没关系,
    /// 所以跟着清是对的, 而且这份里那行照样坏的话下一轮就重新立起来。但护栏复位**本身会误判**,
    /// 误判一次就白清一次, 所以别把它当"只有我主动才清得掉"。
    ///
    /// ⚠️ **那一行回不回得来要看它现在读不读得出来**
    /// (独立复审第十九轮真跑证过, 我原先三处都写死了"回不来", 错的):
    /// 后来又读得出来了 ⟹ 重扫会把它**补报出来**, 这是唯一能拿回来的正常途径;
    /// **一直**读不出来 ⟹ 确实回不来。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lost: bool,
    /// 丢的是**哪几行**(最多 [`native_core::SKIPPED_IDS_CAP`] 个, 升序)。
    ///
    /// 光说"这张表丢过一条"用户没法动手(独立复审第二十三轮 ④): 水位文件在临时目录、文件名是哈希,
    /// 他拿不到位置; 而"正文解不开"那一类在 SQL 里**根本没有特征**(那行在 SQLite 看来完全正常),
    /// 不给行号就只能把整表 dump 出来肉眼找 —— 最大的表十几万行。
    ///
    /// 行号在检测的那一刻就在手上, 顺手存下来, 告警就能打成 `local_id 7,19`,
    /// 用户 `WHERE local_id IN (7,19)` 一把命中。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lost_ids: Vec<i64>,
}

/// 扫描闭包里要用到的那两项水位, 单拎出来是为了**能 Copy** —— [`NewHotMark`] 本身带一个
/// `Vec`(丢的行号)不能 Copy, 而这个闭包是**每行**跑一次的, 整份 clone 太亏。
///
/// ⚠️ 放在 `NewHotMark` **后面**: 放前面会把它那整块 doc 抢过来 —— 文档块是连着的,
/// rustdoc 和 clippy 都不报, 独立复审第二十四轮是用眼睛看出来的。
#[derive(Clone, Copy)]
struct OldMark {
    id: i64,
    gid: Option<i64>,
}

/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_new(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    // 逐会话表水位 {"src\x1fconv_id": 标记}; `None` = `--reset` 全收。
    // 标记除了"读到第几条"还带**已读段行数**, 用来认"这张表被换过没有" —— 见 [`NewHotMark`]。
    wm: Option<std::collections::HashMap<String, NewHotMark>>,
    limit: usize,
    // **每个有新消息的会话至少先留几条**; `0` = 关(默认), 行为跟以前一模一样。
    //
    // 不开的时候是按 (分片, 会话表, 行号) 的固定顺序取全局最小的 limit 条 —— 排在前面的会话只要
    // 一直有新消息就会一直把名额占满, 后面的会话这一轮一条都出不来(数据不丢, 但当时看不到)。
    // 开了之后先给每个有新消息的会话留 `per_conv` 条, 剩下的名额再按原来的顺序补。
    //
    // 名额不够分时(会话数 × per_conv > limit): 仍按会话顺序发, 但每个会话最多先拿 per_conv 条 ——
    // 能露面的会话数比不开时多得多, 但不保证人人有份。这一条如实写在 `--per-conv` 的 help 里。
    per_conv: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(0, limit)?; // new 无 offset(水位驱动非偏移翻页); 深批量导出走 --mode cold
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫真跑完 → 并发闸对真在跑的扫生效 (同 events/stats 范式)
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // BottomN 保最小 limit 条, 逻辑键 = **(source, conv_id, local_id)**。**关键**(真跑+双审收敛): `local_id` 是**每会话
        // Msg_<md5(conv)> 表内**的 AUTOINCREMENT rowid(每会话各自从 1 起, 一个分片文件含数千张这样的表), **非**分片内全局。
        // 故水位/排序键必须带 conv_id 维(=物理表), 否则同分片跨会话 local_id 大量碰撞 → 除每文件最忙会话外全部漏新消息。
        // 编码进 Keyed(ct=0 恒定, src=source, snid="conv_id\x1f零填充local_id") → 排序 = (src, conv_id, local_id) 升序 = 到达序。
        // payload 末位是**扫描器吐到这行为止的序号** = "≤ 这行 local_id 的行数"(表内升序扫)。
        // 拿它算新的已读段行数, 口径跟解不解得开无关 —— 见闭包里 `content_ok` 那段说明。
        // **把"每张表的旧位置"传给扫描器**, 让它只记高于这个位置的跳行(见 `SkippedRows`)。
        // 这一步是这一串二十三轮打磨的收口: 判定原料放在**知道位置**的那一层, 之前四类 bug
        // 就全部构造上不可能了。缺省 0 = 没见过的表, 什么都算新。
        sq.track_skipped_rows_above(
            wm.as_ref()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.id)).collect())
                .unwrap_or_default(),
        );
        let mut bottom: BottomN<(i64, String, Option<String>, String, String, i64, i64)> = BottomN::new(limit);
        // `--per-conv` 用: 每张会话表的**头几条**新消息。表内按 local_id 升序扫, 直接取前 N 条就是最小的几条。
        // **总量卡在 limit**: 超出的反正也进不了最终结果, 留着只白占内存(首轮 / `--reset` 时两万张表
        // 全都有新消息, 不卡就是两万 × per_conv 行)。
        let mut floors: std::collections::BTreeMap<String, Vec<Keyed<NewRow>>> = std::collections::BTreeMap::new();
        let mut floor_rows = 0usize;
        // 护栏用: 每张会话表**扫描器这一轮吐了几行**(跟解不解得开无关, 见闭包里的说明)。
        // 表内按 local_id 升序扫 → 走到某一行时这个计数就是"≤ 该行的行数"。
        let mut yielded_per_table: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        // 上一行所属的表 (src, conv_id, 拼好的键) —— 见闭包里的说明。
        let mut last_key: Option<(String, String, String)> = None;
        // 每张表"≤ 上次读到那一格"的行数 —— 走到游标那一行(或第一行超过它)时从上面那个序号取。
        let mut seen_at_or_below: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        // 游标那一行**现在**的 `create_time` —— 跟水位里记的比, 认"这一格是不是还是原来那条消息"。
        let mut cursor_ct_now: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        // 同上, 但锚在**汇报位置 `id`** 上 —— 给"锚点追上来"用(见闭包里的说明)。
        // "≤ 汇报位置的最后一行" 的 (行号, 序号=该段行数, 时间) —— 给"锚点追上来"用。
        // 锚到真实存在的一行上, 三样永远配得齐(汇报位置那一行可能已经被删了)。
        // **本函数自己丢掉的行**的行号(正文解不开)。跟扫描器报的 `skipped_row_ids` 是两条路,
        // 后果一样 —— 合起来一起判"有没有越过去"。同样**逐个记**, 不能塌成一个最小值。
        let mut skipped_here: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
        let mut last_at_or_below_id: std::collections::HashMap<String, (i64, i64, i64)> =
            std::collections::HashMap::new();
        let stats = sq
            .scan_all_messages(false, None, |m, _msgsource, src| {
                // ⚠️ **护栏的记账全部要在 `content_ok` 过滤之前**(独立复审 P2 + codex round-15 P2):
                // 同一行"这一轮解不开、下一轮解得开"是真会发生的(微信就地回写 —— 图片视频上传完写
                // CDN 字段、撤回改写正文)。口径要是"我解得开的行", 两轮之间就不稳 → 下一轮判成
                // "已读段多出了行" → 复位 → 用户屏幕上重报整段历史。**连游标那一行本身**也可能
                // 一时解不开, 所以 `seen_at_or_below` / `cursor_ct_now` 也得在过滤之前记。
                //
                // 键**每张表只算一次**: 行按表分组来的, 缓存上一张表的键 → `format!` 从每行一次降到
                // 每表一次; 下面全程**借用**这个键, 只有往两个 map 里**插新表**时才拷一份
                // (codex round-15 P2: 之前每行 clone 两三次, 几百万行就是几百万次分配)。
                if last_key
                    .as_ref()
                    .is_none_or(|(s0, c0, _)| s0 != src || c0 != &m.conv_id)
                {
                    last_key = Some((src.to_string(), m.conv_id.clone(), format!("{src}\u{1f}{}", m.conv_id)));
                }
                let wk: &str = last_key.as_ref().map_or("", |(_, _, w)| w.as_str());
                let seq = match yielded_per_table.get_mut(wk) {
                    Some(v) => {
                        *v += 1;
                        *v
                    }
                    None => {
                        yielded_per_table.insert(wk.to_string(), 1);
                        1
                    }
                };
                // 这张表上一轮的水位。**判"是不是新"用 `id`, 护栏记账锚在 `gid`** —— 两件事分开(见字段说明)。
                // 只取护栏这一段真正要的两项 —— 整个结构现在带一个 Vec(丢的行号)不能 Copy,
                // 而这里在**每行**的闭包里跑, 整份 clone 一次太亏。字段名保持一致, 下面一个字不用改。
                let old_mark_here = wm
                    .as_ref()
                    .and_then(|map| map.get(wk))
                    .map(|m| OldMark { id: m.id, gid: m.gid });
                let old_id = old_mark_here.map(|mk| mk.id);
                if let Some(mk) = old_mark_here {
                    // 锚点落后于汇报位置时(那一轮没扫全却推进了 `id`), 顺手把"≤ id 那一段"也量一份 ——
                    // 这一轮要是扫全了, 就能让锚点**追上来**, 把没覆盖的那一段收掉(codex round-17 P3:
                    // 不追的话 `gid < id` 会永久粘住, 一个"恒 0 才正常"的信号变成永久非 0, 真出事没人看)。
                    // ⚠️ 只在**锚点确实落后**的表上量: 稳态下 `gid == id`, 量了也没人用, 而这个闭包
                    // **每行都跑一次**, 全表扫是百万行级 —— 白搭两次字符串键的哈希操作
                    // (codex 第十八轮 P2)。
                    if mk.gid.is_some_and(|g| g < mk.id) && m.local_id <= mk.id {
                        // 锚点要搬就搬到**≤ 汇报位置的最后一行**, 不是搬到汇报位置本身 ——
                        // 汇报位置那一行可能**已经被删了**(撤回/清理), 那样就拿不到它的时间戳。
                        // 锚在真实存在的一行上, 三样(行号/行数/时间)永远配得齐。
                        // 行是按行号升序来的, 所以一路盖上去, 最后停的就是最后一行。
                        last_at_or_below_id.insert(wk.to_string(), (m.local_id, seq, m.create_time));
                    }
                    let gid = mk.gid.unwrap_or(mk.id);
                    if m.local_id <= gid {
                        if m.local_id == gid {
                            // **游标那一行的时间** —— 光比行数认不出"换了一份行数一样的副本"
                            // (codex round-12 P1)。`create_time` 写入时定死, 上传回写 / 撤回都不改它。
                            cursor_ct_now.insert(wk.to_string(), m.create_time);
                        }
                        // 走到这行时的序号 = "≤ 这行的行数"。一路盖上去, 最后停在游标那一格。
                        match seen_at_or_below.get_mut(wk) {
                            Some(v) => *v = seq,
                            None => {
                                seen_at_or_below.insert(wk.to_string(), seq);
                            }
                        }
                    } else if !seen_at_or_below.contains_key(wk) {
                        // 第一次越过锚点: "≤ 锚点的行数" = 这行的序号 - 1。之后的行不再改它。
                        seen_at_or_below.insert(wk.to_string(), seq - 1);
                    }
                }
                // drop 口径同冷: 跳正文 zstd 解码失败行 (冷 ingest emit SystemError 不落 message 表 → new_query 没这行)。
                if !m.content_ok {
                    // ⚠️ **这是第二条丢行的路**(codex 第十九轮 P1)。扫描器那条("整行读不出来")我记了行号,
                    // 这条("行读得出来但正文解不开")当时漏了 —— 而后果一模一样: 这一行被丢掉、同表更靠后的
                    // 行照报, 位置就越过了它; 正文哪天恢复了(截断的 zstd 被补全)它也已经不算新, 永久看不见。
                    // 又是"修了被点名的、旁边同结构的没修"。
                    // 跟扫描器那份**同一个口径**(见 `SkippedRows`): 只记**高于旧位置**的,
                    // 而且只留最小的那几个 —— 判据要的就是"高于旧位置的最小那个", 一个就够。
                    // 在下限底下的行早报给用户了, 压根不算丢, 记进来只会制造假告警。
                    if m.local_id > old_id.unwrap_or(0) {
                        let v = skipped_here.entry(wk.to_string()).or_default();
                        if v.len() < native_core::SKIPPED_IDS_CAP {
                            v.push(m.local_id);
                        }
                    }
                    return true;
                }
                // 逐**会话表** (src, conv_id) 水位判"新": 该表没见过(新会话/新分片) 或 local_id > 该表水位。
                // `--reset`(wm=None)→ 全新。
                let is_new = old_id.is_none_or(|oid| m.local_id > oid);
                if is_new {
                    // snid = conv_id + US + 20 位零填充 local_id → (src, snid) 排序 = (src, conv_id, local_id), 每消息唯一。
                    let snid = format!("{}\u{1f}{:020}", m.conv_id, m.local_id);
                    let seq_here = seq;
                    let payload = || {
                        (
                            m.create_time,
                            m.conv_id.clone(),
                            m.sender.clone(),
                            m.msg_type_name.clone(),
                            m.text.clone(),
                            m.local_id,
                            seq_here,
                        )
                    };
                    // ⚠️ 键是 `conv_id`(逻辑会话)**不是 `wk`**(分片+会话表): 同一个会话可以同时在多个
                    // 分片里(真库 700 张同名表), 按表记名额的话它会拿到好几份保底, 把别的会话挤出去。
                    offer_floor(&mut floors, &mut floor_rows, &m.conv_id, limit, per_conv, || Keyed {
                        ct: 0,
                        src: src.to_string(),
                        snid: snid.clone(),
                        tie: String::new(),
                        payload: payload(),
                    });
                    bottom.offer(0, src, &snid, payload);
                }
                true
            })
            .context("全扫消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total_new) = bottom.finish(); // ASC by (source, conv_id, local_id) = 到达序
                                                 // ⚠️ **接线这两行的覆盖状况, 说准一点**(独立复审 ff12d69 的 P2 量出来的):
                                                 //   ① 这一行把 `per_conv` 交给分配函数 —— 换成 `0` 会红**两条**:
                                                 //      `audit_per_conv_floor_is_wired_into_hot_new` 和
                                                 //      `audit_per_conv_quota_counts_the_conversation_not_the_shard_table`
                                                 //      (后者的夹具 `limit=2`, 全局最小两条都是 A 的, 关掉保底 Z 就出不来);
                                                 //   ② 上面那行把 `conv_id`(不是 `wk`)交给 `offer_floor` —— 传错只红
                                                 //      `audit_per_conv_quota_counts_the_conversation_not_the_shard_table` 一条。
                                                 //   ①②都是**下变异真跑量出来的**, 不是推的 —— 早先 ① 这里写的"只有一条会红"
                                                 //   就是推错的(独立复审逮到)。以后改这段, 先跑一遍再写。
                                                 // **这两条都带 `#[ignore]`**(要真账号缓存的 key 造加密夹具), 而 CI 只跑
                                                 // `cargo test --workspace`, **不带 `--ignored`** —— 这两格在默认那趟里**没人守**。
                                                 // 复审实测: 这两个变异都能通过整个默认测试套。
                                                 //
                                                 // 上面那条性质测守的是**安全性**(不漏不重不越位), 不是功能 —— 把分配函数换成注释里点名的
                                                 // 错法, 它六条断言全过。别拿它当这两行的守卫。
                                                 //
                                                 // 改动这两行之前, 在有 key 的机器上跑:
                                                 // `cargo test -p native-query --test r22_d24_gate_race -- --ignored audit_per_conv`
        let kept = apply_per_conv_floor(kept, floors, limit, per_conv);
        // 逐**会话表** (src, conv_id) 推进: new_wm = 旧水位 ∪ 本批各会话表最大 local_id。BottomN 取最小 limit → 每会话表的
        // 展示行是其新行的 local_id **前缀**(同 (src,conv_id) 连续排、内按 local_id 升序), 故推到"本批该表最大 local_id"=
        // 推到已扫出前缀末尾, 从不越过未读/未展示行 → **截断/漏扫也不永久丢**(未进 new_wm 的行下轮仍 > 该表水位被追上)。
        // key = "src\x1fconv_id" (同 is_new 查询键); payload.1=conv_id, .5=local_id。
        // 新水位 = 旧水位 ∪ 本批各会话表最大 local_id, **并带上已读段行数**。
        let mut new_wm: std::collections::HashMap<String, NewHotMark> = wm.clone().unwrap_or_default();
        // 本轮每张会话表**展示了几行** —— 算新的已读段行数要用它(见下)。
        let mut kept_per_table: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        // 本轮各表**新游标那一行的时间**: 就在展示数据里, 不用额外查(payload.0 = create_time)。
        let mut new_cursor_ct: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
        let mut new_cursor_seq: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
        for k in &kept {
            let lid = k.payload.5;
            let wk = format!("{}\u{1f}{}", k.src, k.payload.1);
            *kept_per_table.entry(wk.clone()).or_insert(0) += 1;
            let ce = new_cursor_ct.entry(wk.clone()).or_insert((lid, k.payload.0));
            if lid >= ce.0 {
                *ce = (lid, k.payload.0);
            }
            // 同理记下"本表展示的最大那行的序号" = 新的"≤ 新 id 的行数"。
            let se = new_cursor_seq.entry(wk.clone()).or_insert((lid, k.payload.6));
            if lid >= se.0 {
                *se = (lid, k.payload.6);
            }
            let e = new_wm.entry(wk).or_insert(NewHotMark {
                id: lid,
                gid: None,
                n: None,
                ct: None,
                // 先按"没丢过"建, 扫完之后统一拿扫描器报的跳行行号跟位置比着立。
                lost: false,
                lost_ids: vec![],
            });
            if lid > e.id {
                e.id = lid;
            }
        }
        // **护栏**: 已读那一段现在的行数, 跟水位里记的对不上 = 这张表不是原来那张了
        // (换过副本 / 被重建 / 中间被挖过洞)。把它的水位丢掉 → 下一轮整表当新的报出来。
        // 老水位没记 `n`(升级第一轮)就不比这一项, 只把这一轮数出来的填进去。
        // 只对本页算 datetime (SQLite localtime, 同冷查 datetime(create_time/1000,'unixepoch','localtime'))。
        let dconn = rusqlite::Connection::open_in_memory()
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("datetime 计算失败: {e}")))?;
        // 行序 = (source, local_id) 到达序(同冷 rowid ASC), **不**按 create_time 重排 —— 保前向对拍确定性 + 对齐冷 new 语义。
        let data: Vec<serde_json::Value> = kept
            .iter()
            .map(|k| {
                let (ct, conv, sender, tname, text, _lid, _seq) = &k.payload;
                let dt: String = dconn
                    .query_row("SELECT datetime(?1/1000,'unixepoch','localtime')", [*ct], |r| r.get(0))
                    .unwrap_or_default();
                serde_json::json!({
                    "create_time": ct, "datetime": dt, "conv_id": conv,
                    "sender_wxid": sender, "msg_type_name": tname, "text_content": text,
                })
            })
            .collect();
        // has_more = 水位之上"新"总数 > 本批取的 limit (还有下一批待追)。
        let has_more = limit > 0 && total_new > limit;
        let mut summary = serde_json::Map::new();
        summary.insert("new_shown".into(), serde_json::json!(data.len()));
        summary.insert("total_new".into(), serde_json::json!(total_new));
        let mut guard_reset_tables = 0u64;
        // ⚠️ **"这一轮这张表扫全了没有"要逐表判, 不能一刀切**(codex round-12 P1 提出、round-13 P1 纠正)。
        //
        // 整表跳过 / 分片没打开 / 游标中途 break, 都会让"数出来的行数"**偏小** —— 拿偏小的数去比
        // 就把好端端的水位判成"表被换过"→ 复位 → 下一轮整表历史当新消息重报。
        // 我上一版拿**全局** partial 一刀切"这一轮谁都不比", codex 一轮就指出那更糟:
        // 真库上某个分片长期扫不全是常态(`hot.rs` 自己注释写着"partial 全来自 message_5.db 游标 break"),
        // 于是**整个账号的护栏被长期关掉** —— 换副本永远逮不着, 比偶尔误判严重得多。
        //
        // 逐表的完整性判据: **扫描器自己报的"这张表一路扫到底了"**(`ScanStats::complete_tables`)。
        //
        // ⚠️ 上一版我拿两个**地标**推(看见了游标那一行 / 看见了游标之上的行)—— codex round-14 P1 打穿:
        // **表被重建**时号从 1 重来、全部行都在旧游标底下、旧游标那一行也没了, **两个地标一个都拿不到**
        // → 判成"没扫全" → 水位原样保住 → 那些消息**无限期看不到**。而那正是这一串要修的那个洞本身。
        // 地标推不出来的东西扫描器是知道的(`rows.next()` 返 `Ok(None)` 就是扫到底), 让它直接报。
        for (wk, mark) in &mut new_wm {
            let advanced = kept_per_table.contains_key(wk);
            let prefix_complete = stats.complete_tables.contains(wk);
            let old_mark = wm.as_ref().and_then(|o| o.get(wk));
            if !prefix_complete {
                // 这张表这一轮没扫全 → **护栏状态原样留着**(它锚在 `gid` 上, 跟 `id` 推到哪儿无关),
                // 而 `id` **照常推进**。
                //
                // ⚠️ 上一版这里把 `id` 也退回去了 —— 那是回归(codex round-15 P1 + 独立复审真跑):
                // 有一行**永远**读不出来的表(列映射失败是那行数据本身的属性)每轮都进这一支, 于是水位
                // 永远推不动 → 同一批消息**每轮重报**, 而且它们每轮把全局 `limit` 名额占满,
                // **排在后面的会话表永远轮不到**。一行坏数据能让整个 `new` 停止前进。
                //
                // ⚠️ **推进之前先把锚点钉死**(codex round-16 P1): 老水位(升级前的 `{id,n,ct}`)没有 `gid`,
                // 读的时候当作等于 `id`。这一轮要是**没扫全却推进了 `id`**, `n`/`ct` 描述的还是**旧**那一格,
                // 而 `gid` 仍然缺席 → 下一轮 `unwrap_or(id)` 拿到的是**推进后**的 id → 拿"≤ 新 id 的行数"
                // 去比"≤ 旧 id 的行数" → 假复位 → 整段历史重报。
                // 所以在这里把推进前的那一格**显式写进 `gid`**, 让它跟 `n`/`ct` 对齐。
                if advanced && mark.gid.is_none() {
                    if let Some(o) = old_mark {
                        mark.gid = Some(o.gid.unwrap_or(o.id));
                    }
                }
                continue;
            }
            // 锚点这一轮被"追上来"过的话, 新那一格的时间戳记在这儿, 用来挡住后面按老规矩的覆写。
            let mut chased_ct: Option<i64> = None;
            match old_mark {
                // 这张表上一轮就有水位, 且这一轮前缀扫全了 → 拿两样跟它比: 已读段行数、游标那行的时间。
                Some(o) => {
                    let now_n = seen_at_or_below.get(wk).copied().unwrap_or(0);
                    let now_ct = cursor_ct_now.get(wk).copied();
                    // ⚠️ **只有"变多"才算数**(独立复审 P2): 行数**变少** = 已经报过的行没了(用户删消息),
                    // 那些行早报过, **不可能因此漏**; 真正会藏东西的是**变多** —— 游标底下多出没报过的行。
                    // 两个方向一视同仁的话, 用户在微信里删一条老消息, 这边就把整段历史当新的重报一遍。
                    // (冷查那条路的误判只是重扫一遍、幂等、用户看不见; 这条路的误判是**用户屏幕上多出
                    // 整段历史**。同一个判据, 两条路的代价不一样, 所以这里收窄, 冷查那边保守不动。)
                    let n_bad = matches!(o.n, Some(prev) if now_n > prev);
                    // `ct` 两边都有值才比 —— 一边没有只说明"还没建立", 不是"对不上"。
                    let ct_bad = matches!((o.ct, now_ct), (Some(prev), Some(now)) if prev != now);
                    if n_bad || ct_bad {
                        tracing::warn!(
                            rows_now = now_n,
                            rows_recorded = o.n,
                            ct_changed = ct_bad,
                            "[new] 已读段多出了行 / 游标那行换了人(源库换过副本?) → 该会话表水位复位, 下一轮整表补报"
                        );
                        *mark = NewHotMark {
                            id: 0,
                            gid: None,
                            n: None,
                            ct: None,
                            // 复位 = 源库像是换了一份副本, 整表从头重报 —— 旧那份里丢的行跟这份没关系,
                            // 标记跟着清。要是**这份**里那一行照样读不出来, 下一轮位置一越过它就重新立起来
                            // (只晚一轮, 跟这条路上别的信号一个节奏)。
                            lost: false,
                            lost_ids: vec![],
                        };
                        guard_reset_tables += 1;
                        continue;
                    }
                    // 对得上 → 记住配**推进之后那一格**的两样。
                    //
                    // ⚠️ `n` 必须加上"本轮展示了几行": `now_n` 数的是"≤ **旧** id", 而 `id` 已经推到本轮
                    // 展示的最大那行。少加这一项, 下一轮就拿"≤ 新 id"跟"≤ 旧 id"比 → **每轮都误判**。
                    // (真跑第一次就逮到, 写出来是 `{"id":4,"n":2}`。)
                    // 本轮展示的行**就是**这张表在 (旧 id, 新 id] 里的全部行 —— BottomN 对每张表取的是
                    // 它的最小那几行, 即新行的前缀; 而 `id` 只推到展示过的最大那行, 所以两者恰好配平,
                    // **即使 BottomN 把这张表截断了也配平**(截断只是让 id 推得少, 不会让计数多)。
                    // 新的"≤ 新 id 的行数" = 本轮展示的最大那行的**序号**(扫描器吐到那行为止吐了几行)。
                    // 用序号而不是 `now_n + 展示了几行`: 后者数的是"我解得开的行", 中间有解不开的行时
                    // 会偏小, 下一轮那行又解得开就判成"多出了行"(独立复审 P2)。
                    // 护栏锚点跟着推到本轮展示的最大那行 —— **只在这一支**(扫全了且比对通过)才动。
                    //
                    // ⚠️ **没新行也要把 `n` 刷一遍**(独立复审 P2, A/B 真跑坐实是我上一笔的回归):
                    // 锚点 `gid` 没动 ⟹ 这一轮量到的 `now_n` 跟水位里记的**量的是同一格**, 刷下去完全合法。
                    // 不刷的话 `n` 就**只往上走不往下走**: 用户每删一条老消息(微信里最日常的操作),
                    // 这张表的门槛就**永久**高一格 —— 之后"游标底下多出一条没报过的"要多出两条才响,
                    // 删得越多护栏越瞎。旁边 `ct` 那支本来就是 `now_ct.or(o.ct)`(没新行就用这一轮量的),
                    // `n` 漏了同一件事 —— 又是"修了一半、旁边同结构的没修"。
                    //
                    // 白捡一格: 表被清空后重建成同样多条**别的**消息时, `n` 冻着就认不出;
                    // 刷下去之后中间那一轮会量到 0, 下一轮"5 > 0"就逮到了。
                    match new_cursor_seq.get(wk) {
                        Some((lid, q)) => {
                            mark.gid = Some(*lid);
                            mark.n = Some(*q);
                        }
                        None => {
                            mark.n = Some(now_n);
                            // 锚点落后而这一轮扫全了 → **让它追上来**, 把 `(gid, id]` 那段收进覆盖面。
                            // ⚠️ 用的是**专门量的"≤ id 的行数"**, 不能拿"这张表一共吐了几行"顶 ——
                            // BottomN 会淘汰, "这一轮没展示"不等于"没有更靠后的行"(独立复审点了这个坑)。
                            //
                            // ⚠️⚠️ 锚点搬了, **时间戳必须跟着一起搬**, 而且要挡住下面那段的覆写 ——
                            // 不然 `gid` 指着新那一格、`ct` 还是旧那格的, 下一轮护栏自己把自己判成
                            // "这张表被换过" → 复位 → 整段历史重报(codex 第十八轮 P1, 真复现过)。
                            //
                            // 两样都拿到才敢搬: 汇报位置那一行**要是已经被删了**, `ct_at_id` 就没这一项,
                            // 这时候宁可继续落后(下次有新消息走正常推进那条路自然就好), 也不能配一个对不上的时间戳。
                            if mark.gid.is_some_and(|g| g < mark.id) {
                                if let Some((lid, q, c)) = last_at_or_below_id.get(wk) {
                                    mark.gid = Some(*lid);
                                    mark.n = Some(*q);
                                    chased_ct = Some(*c);
                                }
                            }
                        }
                    }
                    // 新游标那一行的时间: 位置推进过就取本轮展示数据里那一行的(白送, 不用额外查) ——
                    // 早先写成"推进过就清掉", 结果**一直有新消息的表永远建立不起这一项**(真跑逮到:
                    // 连跑三轮 `ct` 始终缺席)。位置没推进就沿用这一轮数出来的 / 上一轮记的。
                    mark.ct = if let Some(c) = chased_ct {
                        // 锚点刚搬过 → 用新那一格的时间, 别被下面两支覆写回旧的。
                        Some(c)
                    } else if advanced {
                        new_cursor_ct.get(wk).map(|(_, ct)| *ct)
                    } else {
                        // 没新行 → 锚点没动, 沿用这一轮量到的 / 上一轮记的。
                        now_ct.or(o.ct)
                    };
                }
                // 头一回见这张表(首轮 / --reset / 新会话): 全表都是新的, BottomN 取的是最小那几行,
                // 所以那一行的**序号**就等于"≤ 新 id 的行数"。顺手建立, 护栏从下一轮就生效, 不白等一轮。
                //
                // ⚠️ 这一支**也要**在"这张表扫全了"的前提下才走(上面 `!prefix_complete` 已经拦住):
                // 扫描器在前缀中间跳过一行时(列映射失败), 我的计数**根本看不见那一行** —— 建立出来的数
                // 就偏小, 那行下一轮又读得出来就成了"多出了行" → 复位 → 重报整段历史(独立复审 P2)。
                None => {
                    mark.gid = new_cursor_seq.get(wk).map(|(lid, _)| *lid);
                    mark.n = Some(new_cursor_seq.get(wk).map_or(0, |(_, q)| *q));
                    mark.ct = new_cursor_ct.get(wk).map(|(_, ct)| *ct);
                }
            }
        }
        // **越过去过读不出来的行**的表: 立个标记(用户拍板"乙+": 丢可以, 静默不行)。
        //
        // 判据是"跳过的那行行号 <= 汇报位置" —— 那一行此后恒不算新, 永久看不见。
        // 反过来跳过的行在汇报位置**上面**的话, 下一轮还会重新读它, 没丢, 不该立标记(不然就是狼来了)。
        // 扫描器连行号本身都读不出来时置 `unknown`: 位置说不清, 只能按"可能越过了"算 —— 宁可多报, 不能漏报。
        // ┌─ 一行怎样才会"永远报不出来" —— **所有出口的清单**。改这段之前先对着它过一遍。 ─┐
        // │ 条件是同一件事: 这一行**没被报给用户**, 而汇报位置**越过了它**(此后恒 `<= 位置`, 不算新)。 │
        // │                                                                                          │
        // │ ① 扫描器整行读不出来(列类型对不上, `read_raw_msg` 失败)  → `stats.skipped_row_ids` ✅ │
        // │ ② 行读得出来但正文解不开(截断 zstd, `content_ok=false`)   → `skipped_here`            ✅ │
        // │ ③ 展示名额淘汰(BottomN)                                   → **构造上不可能**            │
        // │    排序键 = `会话id + 零填充行号` 取最小 ⟹ 每张表留下的是**按行号连续的前缀**,           │
        // │    被淘汰的行号一定更大; 而位置只推到"留下的行里最大那个" ⟹ 永远越不过被淘汰的行。      │
        // │ ④ 整张表打不开(分片打不开 / prepare 失败)                  → **安全**: 一行没留下, 位置不动。│
        // │ ⑤ 游标中途断(`truncated_tables`)                          → **安全**, 但**理由不是"一行没留下"**│
        // │    —— 断之前那些行**已经吐给回调了**, 能进展示、能推位置(真库上这还是常态: 微信正在写      │
        // │    message_5.db)。安全是因为**已扫的是前缀**: 断点之后的行一行没读到, 位置推不过它们。     │
        // │    (第一版这里写的是"一行都没留下", 假的 —— 独立复审第十九轮当场点出。这张表的用途就是    │
        // │     "改之前对着它过一遍", 自己带一条假不变量, 下次有人拿它推别的就跟着瞎。)                │
        // │ ⑥ `is_new` 为假                                            → 定义上就是"早报过了", 不是丢。│
        // │                                                                                          │
        // │ 第十九轮就是栽在这张清单上: 我只认了 ①, ② 在同一个函数里隔六十行, 没想起来。             │
        // │ **新增任何一处"丢掉这一行"的分支, 都要回来往这张表里加一行, 并接进下面的判据。**          │
        // └──────────────────────────────────────────────────────────────────────────────────────┘
        for (wk, mark) in &mut new_wm {
            let old_id = wm.as_ref().and_then(|m| m.get(wk.as_str())).map_or(0, |m| m.id);
            // 两条丢行的路(扫描器的 / 本函数自己的)合起来, 取**最小**的那个行号。
            //
            // 两边记的都已经是"**高于旧位置**的最小那几个"(见 `SkippedRows`), 所以这里只剩一句话:
            // 那个最小值 `<= 新位置` 就说明这一轮把它越过去了 —— 那条消息从此永久报不出来。
            //
            // 这一行判据是**二十三轮打磨的终点**。中间栽过的四条全在"把整个集合搬出去、事后再想
            // 办法概括"这条路上: 判据没带下界(第十九轮) / 塌成一个最小值被老坏行盖住(第二十轮) /
            // 撑爆上限塞哨兵→假告警(第二十一轮) / 溢出只有下界没上界(第二十二轮)。
            // 根子是**把判定原料放在了不知道位置的那一层**。把下限传下去之后, 那四类全部
            // **构造上不可能** —— 不是靠守卫防住的, 是压根构造不出来。
            let from_scanner = stats.skipped_row_ids.get(wk.as_str());
            let lost_ids: Vec<i64> = {
                let mut v: Vec<i64> = from_scanner
                    .map(|e| e.ids.as_slice())
                    .into_iter()
                    .chain(skipped_here.get(wk.as_str()).map(Vec::as_slice))
                    .flatten()
                    .copied()
                    .filter(|sid| *sid <= mark.id)
                    .collect();
                v.sort_unstable();
                v.truncate(native_core::SKIPPED_IDS_CAP);
                v
            };
            // 行号本身读不出来 → 位置说不清, 只能按"可能越过了"算(真库够不着, 纯兜底)。
            let unknown_crossed = from_scanner.is_some_and(|e| e.unknown) && mark.id > old_id;
            if !lost_ids.is_empty() || unknown_crossed {
                mark.lost = true;
                // 把行号一并存下来 —— 光说"这张表丢过"用户没法动手(独立复审第二十三轮 ④):
                // 有了行号就能 `WHERE local_id IN (...)` 一把命中, 而且"正文解不开"那一类
                // 在 SQL 里**根本没有特征**, 不给行号就只能把整表 dump 出来肉眼找。
                for id in lost_ids {
                    if mark.lost_ids.len() < native_core::SKIPPED_IDS_CAP && !mark.lost_ids.contains(&id) {
                        mark.lost_ids.push(id);
                    }
                }
                mark.lost_ids.sort_unstable();
            }
        }
        summary.insert("next_watermark".into(), serde_json::json!(new_wm));
        // 这一串水位里, **越过去过读不出来的行**的会话表数。**恒 0 才是正常**;
        // 非 0 = 那几张表各有至少一条消息永久报不出来了(见 `NewHotMark::lost`)。
        // 跟上面两个数不一样: 这个**不会因为那一行恢复正常就自己灭**(`--reset` 和护栏复位会清, 见 `lost` 的说明)。
        summary.insert(
            "tables_with_lost_rows".into(),
            serde_json::json!(new_wm.values().filter(|m| m.lost).count()),
        );
        // 护栏这一轮复位了几张会话表(源库换过副本 / 表被重建)。**恒 0 才是正常**;
        // 非 0 说明下一轮会把那几张表整表当新的补报一遍 —— 让用户看得见, 不静默。
        summary.insert("guard_reset_tables".into(), serde_json::json!(guard_reset_tables));
        // **护栏覆盖不到汇报位置**的会话表数。**恒 0 才是正常。**
        //
        // 两种都算(codex round-17 P2: 我第一版只数了后者):
        //   ① `n` 压根没建立过 —— `--reset` 后第一轮就跳过了行, 或者这张表一直没扫全过。
        //      这时锚点 `unwrap_or(id)` 虽然等于 `id`, 但**没有基准可比** = 一点护栏都没有,
        //      而且有永久坏行的话会**一直**这样。这比"锚点落后"更糟, 却被漏数了。
        //   ② 锚点**落后**于汇报位置 —— `(gid, id]` 那一段没覆盖。
        // (刚被复位的表 `id == 0`, 不算 —— 它下一轮就重建。)
        //
        // ⚠️ ②不能光看 `gid < id` 就报(独立复审第十八轮 P2): 那一段里**一行都没有**的时候
        // (锚点已经追到"≤ 汇报位置的最后一行", 或者中间那几行后来被删光了), 缺口是**空的**,
        // 报出去就是狼来了 —— 而狼来了报久了, 真出事那一次也没人看。
        //
        // ⚠️⚠️ 判据是**自己去核**, 不是"扫全了就假定追赶成功了": 早先写成后者, 埋反例
        // (把追赶退回上一版)的时候当场看见 —— 锚点卡在第 5 行、6/7 两行明明就在没覆盖的那一段里,
        // 计数照报 0。判据信另一段代码"应该干了什么", 那另一段一旦出事这里就跟着瞎。
        // 这一串前面栽的四次都是这个形状。
        let guard_lagging_tables = new_wm
            .iter()
            .filter(|(wk, m)| {
                if m.id == 0 {
                    // 刚被复位, 下一轮整表重建, 没有要保的东西。
                    return false;
                }
                if m.n.is_none() {
                    return true; // 压根没基准 = 一道护栏都没有
                }
                let Some(g) = m.gid.filter(|g| *g < m.id) else {
                    return false; // 锚点跟汇报位置齐平, 没有缺口
                };
                // 锚点落后。那一段里**真的还有行吗**? 这一轮扫全了才答得上来:
                // 扫全 ⟹ "≤ 汇报位置的最后一行" 是准的, 它在锚点底下就说明缺口空了。
                match (
                    stats.complete_tables.contains(wk.as_str()),
                    last_at_or_below_id.get(wk.as_str()),
                ) {
                    (true, Some((last, _, _))) => *last > g,
                    (true, None) => false, // 扫全了而这一段一行都没有 → 没缺口
                    (false, _) => true,    // 没扫全 → 核不了, 如实报
                }
            })
            .count();
        summary.insert("guard_lagging_tables".into(), serde_json::json!(guard_lagging_tables));
        // 全扫式: 整表 dropped/降级只进 summary (R16-1 lesson②; 五源全回填)。partial = 本轮某会话表没扫全。
        // **两类不完整, 安全性不同**(codex R2/R3 逮 partial-非前缀 vs Claude R3 判前缀安全的分歧, 核实 live_query 扫描器坐实):
        //   ① `truncated_tables`(游标 next() Err → live_query.rs `break`, 停该表)= **前缀截断**: 已扫行必是 local_id 1..K
        //      连续前缀, 水位推到 K 不越未扫行 → **完全安全**, 下轮 >K 追上。`degraded_tables`(整表跳过)/新分片没扫到 = 该表
        //      不入 new_wm 保留旧水位 → 也安全。真跑坐实: 9.2M 扫的 partial 全来自 message_5.db 游标 break(truncated), dropped=0。
        //   ② `dropped_rows`(read_raw_msg 列映射失败 → live_query.rs `continue`, 游标活着跳该行)= 理论上表**中间空洞**:
        //      若空洞行 local_id 小、同表更大 local_id 进本批 → 水位越过空洞, 空洞行下轮 ≤水位被漏 (codex P1)。**权衡后仍推进**:
        //      (a) 列映射失败=该行数据真损坏, 几乎恒持久不可读(冷 ingest 同路径也读不出→冷也没这行, 非热独漏); (b) 若改"dropped>0
        //      不推进"则**持久坏行→永远卡在最旧批不前进**(比跳过一个本就读不出的行更糟, 且 --reset 也救不回); (c) partial=True
        //      如实标 + scan_dropped 计数暴露。故 = 有分析的降级权衡 (同 money keep-first design-safe 先例), 非疏漏。
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查 new 扫描任务失败: {e}")))?
}

/// `resolve-names` 热查核 (**R16-6**) —— wxid→显示名 (nick_name/remark/alias), 从源库 `contact.db` 读(对齐冷
/// [`crate::resolve_names_query`] 读 L1 `person`)。热复用 [`read_hot_contacts`](native_core::read_hot_contacts) 读全量
/// 联系人(q=None)再按请求 `wxids` 内存过滤 —— 名字查找是**小批 wxid→名**(≤200), 联系人总数通常 << 窗口上限, 一次读全
/// 过滤即可(非稠密翻页)。字段集 = 冷 resolve_names_query (wxid/nick_name/remark/alias)。联系人超窗口上限时 has_more →
/// 标 partial(可能漏, 诚实)。
///
/// # Errors
/// 定位 / 取 key / 开 contact.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_resolve_names(wxid: &Wxid, wechat_data_dir: Option<&str>, wxids: &[String]) -> Result<QueryResult> {
    if wxids.is_empty() {
        let meta = Meta::page(0, 0)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true });
        return Ok(QueryResult { data: vec![], meta });
    }
    let contact_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("contact")
        .join("contact.db");
    let key = cache_key(wxid).await?;
    let wxids_owned: Vec<String> = wxids.to_vec();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let wanted: std::collections::HashSet<&str> = wxids_owned.iter().map(String::as_str).collect();
        // 读全量源库联系人 (contact+stranger, q=None), 内存过滤到请求 wxids。窗口上限内一次读全 (名字查找非翻页)。
        let (contacts, has_more, _total, dropped) =
            native_core::read_hot_contacts(&contact_db, &key, None, MAX_HOT_SCAN_WINDOW, 0)
                .context("查联系人名字失败 (contact.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
        let data: Vec<serde_json::Value> = contacts
            .iter()
            .filter(|c| wanted.contains(c.username.as_str()))
            .map(|c| {
                serde_json::json!({
                    "wxid": c.username, "nick_name": c.nick_name, "remark": c.remark, "alias": c.alias
                })
            })
            .collect();
        let n = data.len();
        let mut meta = Meta::page(n, n)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_dropped(dropped as u64);
        // 联系人总数超窗口上限 (read_hot_contacts has_more) → 全量没读完, 可能漏某些请求 wxid → 诚实标 partial。
        if has_more || dropped > 0 {
            let mut summary = serde_json::Map::new();
            summary.insert("partial".into(), serde_json::json!(true));
            if has_more {
                summary.insert("contacts_over_window".into(), serde_json::json!(true));
            }
            if dropped > 0 {
                summary.insert("dropped_rows".into(), serde_json::json!(dropped));
            }
            meta = meta.with_summary(serde_json::Value::Object(summary));
        }
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查 resolve-names 任务失败: {e}"),
        )
    })?
}

/// `account` 热查核 (**R16-6**) —— 账号汇总计数 (persons/chatrooms/messages/moments/favorites), 从源库实时算(对齐冷
/// [`crate::account_query`] 读 L1 各表 count)。4 类**廉价计数**复用现有热 reader(limit=1 拿 `total` = 源表 `count(*)`):
/// persons/chatrooms 读 contact.db, moments 读 sns.db, favorites 读 favorite.db。**messages 需全扫**(源库无消息计数
/// 索引 → scan_all_messages 数 content_ok 行, 同冷 message 表口径; 这是 account 热的固有代价, 较慢)。account_id = 本
/// 账号 wxid。**某源 db 缺/解密失败** → 该计数记 0(同冷 `unwrap_or(0)` 缺表→0)+ `summary.sources_unavailable` 诚实标
/// (比冷静默 0 更诚实)。
///
/// # Errors
/// 定位 / 取 key 失败 → 携码上抛(各源 db 读失败**不**上抛, 记 0+partial)。
pub async fn hot_account(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    let storage_dir = resolve_db_storage_dir(wechat_data_dir, wxid)?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_w = wxid.clone();
    let wxid_s = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        let contact_db = storage_dir.join("contact").join("contact.db");
        // 4 类廉价计数 (reader limit=1 → 第 3 元 total = 源表 count(*)); 失败 → None → 0 + 记 unavailable。
        let persons_t = native_core::read_hot_contacts(&contact_db, &key, None, 1, 0)
            .ok()
            .and_then(|r| r.2);
        let rooms_t = native_core::read_hot_chatrooms(&contact_db, &key, 1, 0)
            .ok()
            .and_then(|r| r.2);
        let moments_t = native_core::read_hot_moments(&storage_dir.join("sns").join("sns.db"), &key, &wxid_w, 1, 0)
            .ok()
            .and_then(|r| r.2);
        let favs_t =
            native_core::read_hot_favorites(&storage_dir.join("favorite").join("favorite.db"), &key, None, 1, 0)
                .ok()
                .and_then(|r| r.2);
        // messages: 全扫数 content_ok 行 (同冷 message 表口径 —— ZstdFail 行 ingest 不落表, 热同跳)。
        // **codex R16-6 P2**: 扫描**降级**(某分片截断/损坏/dropped)时 scan_all_messages 仍返 Ok(只 warning), 计数会**偏低**
        // (真跑 message_5.db 损坏 → 热 8.29M < 冷 9.22M)。必须查 ScanStats 五源: (a) 硬失败(build/scan Err)→ 计 0 + 记
        // unavailable; (b) 降级但返 Ok → 返已数的 c(比 0 有用)但标 messages_approximate(计数偏低, 别当准数比 hot≥cold)。
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_s.clone());
        let (msgs, msg_hard_fail, msg_degraded) = match sq.build() {
            Ok(()) => {
                let mut c = 0i64;
                match sq.scan_all_messages(false, None, |m, _ms, _src| {
                    if m.content_ok {
                        c += 1;
                    }
                    true
                }) {
                    Ok(st) => {
                        // **Claude R16-6 P3**: `content_failed_rows`(ZstdFail 正文)冷热**同口径都排除**(冷 assemble_message
                        // 遇解码失败丢, 热 content_ok=false 同条件跳)→ messages 计数**仍与冷 count(*) 精确相等**, 不算 undercount;
                        // 含它会在"仅有预存损坏 zstd 正文"时误标 messages_approximate(假阳)。只这 4 源真使计数偏低(分片/表整个
                        // 没扫全或行读失败)。
                        let undercount =
                            (st.dropped_rows + st.degraded_tables + st.truncated_tables + st.build_degraded_shards)
                                as u64;
                        (c, false, undercount > 0)
                    }
                    Err(_) => (0, true, true), // 扫描硬失败 → 计 0
                }
            }
            Err(_) => (0, true, true), // build 失败 → 计 0
        };
        // unavailable = 廉价源读失败 + messages **硬失败**(降级但有近似 c 的不算 unavailable, 单独 messages_approximate 标)。
        let unavailable: Vec<&str> = [
            ("persons", persons_t.is_none()),
            ("chatrooms", rooms_t.is_none()),
            ("moments", moments_t.is_none()),
            ("favorites", favs_t.is_none()),
            ("messages", msg_hard_fail),
        ]
        .into_iter()
        .filter_map(|(n, missing)| missing.then_some(n))
        .collect();
        // **codex R16-6 P2**: **全部 5 源都读不出**(4 廉价 None + messages 硬失败)→ 报错, 非静默返全 0 假装"空账号"
        // (key 错/目录错/账号错时冷 unwrap_or(0) 会 0, 但那是缺表; 源库全解不开 = 访问失败该 fail-loud)。
        if unavailable.len() == 5 {
            return Err(cli_err(
                native_core::ErrorCode::AccountNotFound,
                "账号所有源库都读不出 (key 不对? 数据目录 / 账号对? 各 db 存在?) —— 是访问失败, 非空账号",
            ));
        }
        let i64opt = |t: Option<usize>| t.map_or(0, |v| v as i64);
        let row = serde_json::json!({
            "account_id": wxid_s,
            "persons": i64opt(persons_t),
            "chatrooms": i64opt(rooms_t),
            "messages": msgs,
            "moments": i64opt(moments_t),
            "favorites": i64opt(favs_t),
        });
        let mut meta = Meta::page(1, 1)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true });
        // partial = 任一源不可用 OR messages 扫描降级(计数偏低)。messages_approximate 单独标: messages 有值但扫描降级
        // (截断/损坏)→ 计数偏低, 消费方别拿它当准数比"hot≥cold"(真跑 message_5 损坏就是这情形)。
        if !unavailable.is_empty() || msg_degraded {
            let mut summary = serde_json::Map::new();
            summary.insert("partial".into(), serde_json::json!(true));
            if !unavailable.is_empty() {
                summary.insert("sources_unavailable".into(), serde_json::json!(unavailable));
            }
            if msg_degraded && !msg_hard_fail {
                summary.insert("messages_approximate".into(), serde_json::json!(true));
            }
            meta = meta.with_summary(serde_json::Value::Object(summary));
        }
        Ok(QueryResult { data: vec![row], meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查 account 任务失败: {e}")))?
}

/// 热 search 子串命中判定 —— **ASCII 大小写不敏感对齐冷查 FTS/LIKE**(Claude R16-6 P2): `query_has_ascii_alpha` 时把
/// 文本 `to_ascii_lowercase` 再比(只折叠 A-Z, 不动中文/UTF-8 多字节, 同 SQLite 默认); 纯中文/无 ASCII 字母 query 无 case
/// 差异 → 直接 `contains` 免每行分配。`query_lc` = query 的 `to_ascii_lowercase`(调用方算一次)。
fn search_text_hit(text: &str, query: &str, query_has_ascii_alpha: bool, query_lc: &str) -> bool {
    if query_has_ascii_alpha {
        text.to_ascii_lowercase().contains(query_lc)
    } else {
        text.contains(query)
    }
}

/// `inspect` 热查核 (**R16-6**) —— 查单条记录全字段 by (entity, id), 从源库实时读 (对齐冷 [`crate::inspect_query`]
/// 读 L1 单行)。按 entity 路由:
/// - **Contact**(id=wxid) → [`read_hot_contacts`](native_core::read_hot_contacts) 全量后内存找 `username==id`;
/// - **Chatroom**(id=chatroom_id) → [`read_hot_chatrooms`](native_core::read_hot_chatrooms) 找 `chatroom_id==id`;
/// - **Session**(id=wxid) → [`read_hot_sessions`](native_core::read_hot_sessions) 找 `username==id`;
/// - **Message**(id=source_native_id/锚) → `scan_all_messages` 找锚 (**较慢**: 锚 `Msg_<md5(会话)>:<local_id>`,
///   md5 单向不暴露会话 → 无法定向读, 只能全扫; **命中即早停** `break 'scan`, 均摊约半库)。
///
/// **字段集 = 各热命令的 json 映射器** (`msg_json`/`session_json`/`contact_json`/`chatroom_json`); 与冷 inspect 读**原始
/// L1 表行**是**两种重叠投影**, 非逐列相等 (**真库对拍坐实 4 实体**):
/// - **共享字段值一一相等** (message 18 共享 / session 18 共享 全等; 唯 session 两空值列冷 `null` vs 热 `''` 表示有别
///   —— session_json 既有非本件引入, 语义都是"无值");
/// - **冷多 L1 派生/元数据列** (`account_id`/`*_sha`/`*_len`/`source` 溯源 + `sender_wxid`/`text_content` 等 L1 列名);
///   contact/chatroom 尤窄 (冷 45/20 列 vs 热 **5 列列表集** —— contact 热只给 wxid/昵称/备注/alias/type 5 列, R5 未把 contact/chatroom 扩 detail);
/// - **热多便利列** (session 的 `conv_id`/`is_group`; message 的 `sender`/`text`/`local_id` 等热列名)。
/// 即 hot inspect 给**该记录实时可得字段** (够认人/读正文/定位), 非冷 L1 表逐列复制。读全量以 [`MAX_HOT_SCAN_WINDOW`] 为窗:
/// 联系人极多超窗时, 未命中可能是超窗漏读(非真无), 故 NotFound 文案提示"源库有此记录吗"; 命中即按 id 精确匹配为真。
///
/// # Errors
/// 定位 / 取 key / 读库 / 全扫失败 → 携码上抛;查无匹配 → `NotFound`。
pub async fn hot_inspect(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    entity: crate::InspectType,
    id: &str,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    let key = cache_key(wxid).await?;
    // 目录**惰性解析**(codex R16-6 P2): 捕获 Result 不急 `?`, 各实体臂只 `?` 自己那个库。否则急解析 msg_dir 会让
    // "账号有 contact/session 库但缺 db_storage/message 子目录"(如从没收发过消息的账号 —— resolve_message_dir 会
    // is_dir() 检查后 AccountNotFound)时, 连 Contact/Session/Chatroom 热查都被无关的 msg_dir 解析失败连累提前挂。
    let storage_dir = resolve_db_storage_dir(wechat_data_dir, wxid);
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid);
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    let id_owned = id.to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _permit = scan_permit;
        let id = id_owned.as_str();
        // `complete` = 该实体读**扫全了没有**(未命中时据此区分"确认不存在"vs"没扫全, 免武断假 NotFound; codex+Claude
        // R16-6 P2): contact/chatroom/session 看 read_hot_* 的 `has_more`(窗口没读满=没超窗)**且** `dropped`==0(没有
        // 行映射失败被丢); message 看 ScanStats 无整表/整分片被跳**且** dropped_rows==0。**dropped 必计入**: read_hot_*/
        // read_raw_msg 的行映射对严格列(如 i64)遇 NULL 会报错丢行(热丢), 而冷查 drain/映射用 `unwrap_or` 宽松兜底
        // 照样入 L1(冷有)—— 热丢了这行会 hit=None 却报"确认没找到 已扫全", 与冷分叉(冷能返)。故 dropped>0 时判不完整
        // →DbNotReady 让调用方知道该行没读全、去 cold 兜。命中(found=Some)时 complete 不参与(直接返记录)。
        let (found, complete): (Option<serde_json::Value>, bool) = match entity {
            crate::InspectType::Contact => {
                let contact_db = storage_dir?.join("contact").join("contact.db");
                // 把 id 作 q 下推 SQL LIKE 过滤 (username/nick/remark/alias 四列 WHERE), 结果集缩到极小 →
                // **根治超窗假 NotFound**: 联系人可 >10 万(MAX_HOT_SCAN_WINDOW), 无过滤只读前 10 万时远端目标会
                // 被漏读误报没找到; 下推后目标必在过滤集里 (username 精确 ⊆ LIKE 子串命中)。id 里的 `_`(wxid 常见)
                // 在 LIKE 里是通配 → 集合可能略宽, 但下面 `.find(username==id)` 精确匹配纠回, 正确性不受影响。
                let (contacts, has_more, _, dropped) =
                    native_core::read_hot_contacts(&contact_db, &key, Some(id), MAX_HOT_SCAN_WINDOW, 0)
                        .context("读源库 contact.db 失败 (key 不对 / 库损坏?)")?;
                (contacts.iter().find(|c| c.username == id).map(contact_json), !has_more && dropped == 0)
            }
            crate::InspectType::Chatroom => {
                let contact_db = storage_dir?.join("contact").join("contact.db");
                let (rooms, has_more, _, dropped) =
                    native_core::read_hot_chatrooms(&contact_db, &key, MAX_HOT_SCAN_WINDOW, 0)
                        .context("读源库 chatroom 失败 (key 不对 / 库损坏?)")?;
                (rooms.iter().find(|c| c.chatroom_id == id).map(chatroom_json), !has_more && dropped == 0)
            }
            crate::InspectType::Session => {
                let session_db = storage_dir?.join("session").join("session.db");
                let (sessions, has_more, _, dropped) =
                    native_core::read_hot_sessions(&session_db, &key, MAX_HOT_SCAN_WINDOW, 0)
                        .context("读源库 session.db 失败 (key 不对 / 库损坏?)")?;
                (sessions.iter().find(|s| s.username == id).map(session_json), !has_more && dropped == 0)
            }
            crate::InspectType::Message => {
                let mut sq = SourceQuery::open(msg_dir?, key, locator, wxid_owned);
                sq.build()
                    .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
                let mut hit: Option<serde_json::Value> = None;
                let stats = sq
                    .scan_all_messages(false, None, |m, _msgsource, _src| {
                        if m.source_native_id == id {
                            hit = Some(msg_json(m));
                            false // 命中即早停 (不必扫完全库)
                        } else {
                            true
                        }
                    })
                    .context("全扫消息失败")?;
                // 完整性: 无整表(truncated/degraded)、无整分片(build_degraded)被跳、**且 dropped_rows==0** 才算扫全。
                // **dropped_rows 必计入**(codex+Claude R16-6 P2, 我一度误排): `read_raw_msg` 对严格 i64 列(server_id/
                // create_time 等)遇 NULL → `get::<i64>()?` 报错 → 在 `on_row` 回调**前** `continue`(dropped_rows++), 目标
                // 行回调根本没见到 → hit=None; 而冷查 `drain_messages` 对同列用 `get_i64().unwrap_or(0)` NULL→0 **照样入
                // L1**(冷有) → 若热把这算"已扫全, 确认没找到"就与冷分叉(冷能返)。故 dropped>0 判不完整→DbNotReady 指向 cold。
                // **注意区分 `content_failed_rows`(ZstdFail 正文解码失败)**: 那类回调**触发过**、source_native_id 完好、
                // 目标可匹配, 且冷查也丢(ZstdFail 不落 L1) → 对等成立, 故**不**计入 complete(计入会过报不完整)。
                let complete = stats.truncated_tables == 0
                    && stats.degraded_tables == 0
                    && stats.build_degraded_shards == 0
                    && stats.dropped_rows == 0;
                (hit, complete)
            }
        };
        match found {
            Some(row) => {
                let meta = Meta::hot(false)
                    .with_source(Source::Hot)
                    .with_freshness(Freshness::Hot { live: true });
                Ok(QueryResult { data: vec![row], meta })
            }
            None if complete => Err(cli_err(
                native_core::ErrorCode::NotFound,
                format!(
                    "热查确认没找到 {entity:?} id={id} (已完整扫描源库; id 对吗? Message 的 id 是 source_native_id 锚 Msg_<md5>:<n>)"
                ),
            )),
            // 扫描不完整(该类记录 >10 万窗口 / 部分分片降级未扫全): 记录可能存在却没被扫到 → **不用 NotFound 而用
            // DbNotReady**(codex R16-6 P2 + 对齐本文件 hot_resolve/parse_forward 既定用法: 扫描不完整=可重试非确定不存在,
            // 别让调用方按 404 缓存"记录不存在")。HTTP 映 503(可重试), 语义上与"确认没找到"的 404 区分。
            None => Err(cli_err(
                native_core::ErrorCode::DbNotReady,
                format!(
                    "热查扫描不完整, 没法确认 {entity:?} id={id} 是否存在(超 10 万窗口 / 分片降级 / 有行映射失败被丢, 没扫全)—— 记录可能存在但这次没读到; 用 --mode cold 读 L1 确认(或重试)"
                ),
            )),
        }
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查 inspect 任务 join 失败: {e}")))?
}

/// `exec` 热查核 (**R16-6**): 对**原始加密源库**跑只读 SQL —— 裸 schema (`Msg_<md5>` 哈希表名 / `Name2Id` / 裸
/// `contact` 表 等, 与冷 exec 的 L1 投影 schema **完全不同**; 专家向, 配原始表名对照, 用 `SELECT name FROM sqlite_master
/// WHERE type='table'` 自查表名)。`source_db` 是账号 `db_storage/` 下的相对路径 (如 `contact/contact.db`、
/// `message/message_0.db`), 经 [`resolve_source_db`] 校验防穿越, 再走 [`exec_hardened_vfs`](crate::exec_hardened_vfs)
/// (VFS 按需解密 + 层 1+3a+3b+3c 硬只读 + DoS 界 + authorizer 挡 ATTACH)。**单库单分片**: 一次只连一个源库文件
/// (消息分片各是独立 db, 跨分片要逐个 exec)。
///
/// # Errors
/// 取 key / 路径校验(空/绝对/`..`)/ 开库(key 不对/非 SQLCipher 库)/ SQL 非只读 / DoS 界触发 → 携码上抛。
pub async fn hot_exec(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    source_db: &str,
    sql: &str,
    max_rows: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    let key = cache_key(wxid).await?;
    let source_path = resolve_source_db(wechat_data_dir, wxid, source_db)?;
    let sql = sql.to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _permit = scan_permit;
        let mut r = crate::exec_hardened_vfs(&source_path, &key, &sql, max_rows)?;
        // exec_query 内部固定标 Source::Cold(它本为读 L1 设计); 热查走 VFS 源库 → 改标 Hot/live 免误导调用方。
        r.meta = r
            .meta
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true });
        Ok(r)
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查 exec 任务 join 失败: {e}"),
        )
    })?
}

/// `dormant` 热查核 (**R16-6**): 最久没说话的会话 —— 全扫消息按 conv_id 聚合 (max create_time + count), 按 max
/// create_time **ASC** 排取页。对齐冷 [`crate::dormant_query`](`SELECT conv_id, date(max(create_time)), count(*)
/// FROM message GROUP BY conv_id ORDER BY max(create_time) ASC, conv_id ASC`)。**content_ok guard**: 只算解码成功行
/// (冷 L1 message 表不含 ZstdFail 行 → 计数/最后时刻对齐)。**次键 conv_id 唯一** → offset 翻页确定不重不漏 (静态全
/// 聚合 + 确定排序)。本页 date 用内存 SQLite `date(?,'unixepoch','localtime')` 算 (Rust 算日界线分叉, 同 events/biz)。
pub async fn hot_dormant(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    let key = cache_key(wxid).await?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _permit = scan_permit;
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 聚合: conv_id -> (max_create_time, count)。content_ok=false 跳 (对齐冷 L1 message 表口径)。
        let mut agg: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
        let stats = sq
            .scan_all_messages(false, None, |m, _msgsource, _src| {
                if m.content_ok {
                    let e = agg.entry(m.conv_id.clone()).or_insert((i64::MIN, 0));
                    if m.create_time > e.0 {
                        e.0 = m.create_time;
                    }
                    e.1 += 1;
                }
                true
            })
            .context("全扫消息失败 (key 不对 / 库损坏?)")?;
        let total = agg.len();
        let mut rows: Vec<(String, i64, i64)> = agg.into_iter().map(|(c, (t, n))| (c, t, n)).collect();
        // 冷 ORDER BY max(create_time) ASC, conv_id ASC —— conv_id 唯一次键确定翻页。
        rows.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        let dconn = rusqlite::Connection::open_in_memory()
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("date 计算失败: {e}")))?;
        let data: Vec<serde_json::Value> = rows
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(conv, ct, n)| {
                let day: String = dconn
                    .query_row("SELECT date(?1/1000,'unixepoch','localtime')", [*ct], |r| r.get(0))
                    .unwrap_or_default();
                serde_json::json!({"conv_id": conv, "last_message_day": day, "message_count": n})
            })
            .collect();
        let mut meta = Meta::offset_page(offset, data.len(), total, limit)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true });
        // 全扫降级 (整表/分片被跳或行丢) → partial(只进 summary, 不进 page-local dropped, R16-1 lesson②)。
        let degraded =
            stats.dropped_rows + stats.truncated_tables + stats.degraded_tables + stats.build_degraded_shards;
        if degraded > 0 {
            let mut summary = serde_json::Map::new();
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_degraded".into(), serde_json::json!(degraded));
            meta = meta.with_summary(serde_json::Value::Object(summary));
        }
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查 dormant 任务失败: {e}")))?
}

/// `followups` 热查核 (**R16-6**): 等我回的会话 —— 每会话最后一条**非系统**消息, 若发送人不是我 = 我欠回复。
/// 对齐冷 [`crate::followups_query`](`WITH last AS (max create_time per conv WHERE msg_type!=10000) SELECT ... JOIN ...
/// WHERE msg_type!=10000 AND sender_wxid IS NOT NULL AND sender_wxid<>account_id [AND is_chatroom=0]`)。全扫按 conv_id
/// 聚合出每会话 max create_time 的那(些)条非系统消息(**时间戳并列保多条** = 对齐冷 JOIN `create_time=mc` 可返多行),
/// 再筛发送人≠我(账号 wxid)且非空 [+ private_only→非群], 按 create_time/source/source_native_id **DESC** 排取页。
/// content_ok guard(冷 L1 message 表不含 ZstdFail 行)。datetime 本页用内存 SQLite `datetime(?,'unixepoch','localtime')` 算。
pub async fn hot_followups(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    private_only: bool,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    /// 每会话保留的"最后一条"候选 (时间戳并列可多条)。
    struct FollowupLast {
        ct: i64,
        sender: Option<String>,
        type_name: String,
        text: String,
        is_chatroom: bool,
        src: String,
        snid: String,
    }
    let key = cache_key(wxid).await?;
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _permit = scan_permit;
        let me = wxid_owned.clone(); // account_id = 本账号 wxid, 用于"发送人≠我"筛
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // conv_id -> (max_ct, 该 max_ct 上的全部非系统消息)。时间戳并列全留 → 对齐冷 JOIN `create_time=mc` 的多行。
        let mut agg: std::collections::HashMap<String, (i64, Vec<FollowupLast>)> = std::collections::HashMap::new();
        let stats = sq
            .scan_all_messages(false, None, |m, _msgsource, src| {
                if m.content_ok && m.msg_type != 10000 {
                    let e = agg.entry(m.conv_id.clone()).or_insert((i64::MIN, Vec::new()));
                    if m.create_time >= e.0 {
                        if m.create_time > e.0 {
                            e.0 = m.create_time;
                            e.1.clear();
                        }
                        e.1.push(FollowupLast {
                            ct: m.create_time,
                            sender: m.sender.clone(),
                            type_name: m.msg_type_name.clone(),
                            text: m.text.clone(),
                            is_chatroom: m.is_chatroom,
                            src: src.to_string(),
                            snid: m.source_native_id.clone(),
                        });
                    }
                }
                true
            })
            .context("全扫消息失败 (key 不对 / 库损坏?)")?;
        // 摊平 + 筛: 发送人非空且≠我 (对齐冷 sender_wxid IS NOT NULL AND <> account_id); private_only→非群。
        let mut flat: Vec<(String, FollowupLast)> = Vec::new();
        for (conv, (_mx, lasts)) in agg {
            for l in lasts {
                let sender_ok = l.sender.as_deref().is_some_and(|s| s != me);
                let priv_ok = !private_only || !l.is_chatroom;
                if sender_ok && priv_ok {
                    flat.push((conv.clone(), l));
                }
            }
        }
        let total = flat.len();
        // 冷 ORDER BY create_time DESC, source DESC, source_native_id DESC。
        flat.sort_by(|a, b| {
            b.1.ct
                .cmp(&a.1.ct)
                .then_with(|| b.1.src.cmp(&a.1.src))
                .then_with(|| b.1.snid.cmp(&a.1.snid))
        });
        let dconn = rusqlite::Connection::open_in_memory()
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("datetime 计算失败: {e}")))?;
        let data: Vec<serde_json::Value> = flat
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(conv, l)| {
                // **病理级冷热小分叉 (Claude R16-6 P3, 接受)**: 若 create_time 损坏到 SQLite 日期范围外(/1000 后秒值
                // 越界, 真实微信 ~1.7e9 秒**永不触发**), `datetime()` 返 NULL → 此处 `unwrap_or_default()` 得 `""` **保留行**;
                // 而冷查 FollowupRow 的 datetime 是非 Option String, `get::<String>` 遇 NULL 报错被 filter_map **丢行**
                // (count 仍含 = 幽灵 dropped)。即损坏时间戳下热多留一行(datetime="")、热更对(不丢真实 followup)。仅展示列差异。
                let dt: String = dconn
                    .query_row("SELECT datetime(?1/1000,'unixepoch','localtime')", [l.ct], |r| r.get(0))
                    .unwrap_or_default();
                serde_json::json!({
                    "last_create_time": l.ct, "datetime": dt, "conv_id": conv,
                    "last_sender_wxid": l.sender, "msg_type_name": l.type_name, "text_content": l.text,
                })
            })
            .collect();
        let mut meta = Meta::offset_page(offset, data.len(), total, limit)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true });
        let degraded =
            stats.dropped_rows + stats.truncated_tables + stats.degraded_tables + stats.build_degraded_shards;
        if degraded > 0 {
            let mut summary = serde_json::Map::new();
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_degraded".into(), serde_json::json!(degraded));
            meta = meta.with_summary(serde_json::Value::Object(summary));
        }
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查 followups 任务失败: {e}"),
        )
    })?
}

/// 解析 `--source-db` 相对路径到账号 `db_storage/` 下的绝对路径, **校验防路径穿越**: 拒绝空 / 绝对路径 / 含 `..`
/// (ParentDir) / 根 / 盘符前缀 (免逃出 db_storage 拿任意文件当库开); 若目标已存在再 canonicalize 核实**没被 symlink
/// 引出** db_storage (纵深)。返回校验后的绝对路径 (未必存在 —— 不存在留给 `open_decrypted_db_vfs` 报"打开失败")。
/// `--source-db` 相对路径的**纯词法安全校验**(不碰文件系统, 可单测): 拒空 / 绝对路径 / 含非 `Normal`-或-`CurDir`
/// 组件(即挡 `..`=ParentDir / 根=RootDir / 盘符=Prefix / UNC / verbatim `\\?\`)。**单靠 `is_absolute()` 不够** ——
/// Windows 下 `C:foo`(盘符相对)、`\foo`(根无盘符)的 `is_absolute()` 都返 false, 是 `components()` 的 Prefix/RootDir
/// 抓住它们。通过则 `storage.join(rel)` 必仍在 storage 下(无 `..` 逃不出)。
fn validate_source_db_rel(rel: &str) -> Result<()> {
    use std::path::Component;
    let relp = std::path::Path::new(rel);
    if rel.is_empty()
        || relp.is_absolute()
        || relp
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("--source-db 要 db_storage 下的相对路径 (非空/非绝对/不含 '..'), 如 contact/contact.db 或 message/message_0.db; 收到 {rel:?}"),
        ));
    }
    Ok(())
}

fn resolve_source_db(wechat_data_dir: Option<&str>, wxid: &Wxid, rel: &str) -> Result<PathBuf> {
    validate_source_db_rel(rel)?; // 词法先行 (不碰 fs, 坏 rel 不劳解析目录)
    let storage = resolve_db_storage_dir(wechat_data_dir, wxid)?;
    let full = storage.join(std::path::Path::new(rel));
    // 纵深防 symlink/junction 引出: canonicalize **最深已存在祖先** 后须仍在 storage 下。
    // codex R16-6 安全审: 原来只在 `full.exists()` 时 canon full —— **末级 db 文件不存在时整段跳过**, 一个被 junction
    // 引到库外的中间目录(末级文件不存在)就漏检了。改成从 full 往上找到第一个存在的祖先 canon 校验(storage 自身必存在,
    // 循环必终止)。**残留 TOCTOU**(校验后到 open 之间把目录换成 junction)无法纯路径校验消除, 但其前提=对 db_storage
    // 有写权限=攻击者已能直读全部库(游戏结束), 故非有效升级, 接受。
    let storage_canon = storage.canonicalize().map_err(|e| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            format!("db_storage 路径无法解析: {e}"),
        )
    })?;
    let mut probe = full.as_path();
    let anchor_canon = loop {
        if probe.exists() {
            break probe
                .canonicalize()
                .map_err(|e| cli_err(native_core::ErrorCode::BadRequest, format!("源库路径无法解析: {e}")))?;
        }
        match probe.parent() {
            Some(p) => probe = p,
            // 到根都不存在 —— storage 自身应已存在(上面 canon 成功), 理论到不了这里; 兜底拒。
            None => {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "--source-db 路径无有效祖先 —— 拒绝",
                ))
            }
        }
    };
    if !anchor_canon.starts_with(&storage_canon) {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--source-db 解析后逃出了 db_storage (symlink/junction?) —— 拒绝",
        ));
    }
    Ok(full)
}

/// `search` 热查核 (**R16-6, 🔴降级**) —— **无 FTS**: 全库扫消息 + `text_content.contains(query)` 子串匹配。冷查走
/// FTS5 trigram + **bm25 相关度**排序(需 `--build` 建索引); 热查源库无索引 → 只能全扫子串匹配, 按 **create_time DESC**
/// 出(同其它热命令)。
///
/// **ASCII 大小写**: 冷 FTS/LIKE 对 ASCII 大小写不敏感, 热 `contains` 本字节精确 → 已折叠对齐(query 含 ASCII 字母时
/// 每行 `to_ascii_lowercase` 再比, 见下), 否则 ASCII query 热会漏冷会返的 = 热⊊冷(Claude R16-6 P2)。
///
/// **🔴降级两处差异**(真跑坐实 "身份证号" cold 1000 ⊆ hot 16456): ① **排序**是时间序非 bm25 相关度(热拿不到 bm25)。
/// ② **热搜面更宽 → hot ⊋ cold**: 热搜**原始解码文本** `m.text`(含群消息全文 / appmsg 全文等), 冷 FTS 索引的
/// `message.text_content` 是 ingest **归一/抽取**后的窄文本 —— 故热能命中冷 text_content 没覆盖的真实子串(spot-check
/// 证热-only 是真实"...身份证号码..."纯文本群消息, 非误配)。**parity = 集子集**(`冷 LIKE ground-truth 命中 ⊆ 热 contains`,
/// 用 LIKE 而非 FTS 对齐子串语义), 非保序子序列(排序键本就不同)、非集相等(热更全)。对"热查全覆盖"这是**正向**(热更全)。
///
/// 字段集 = 冷 [`crate::search_query`] (create_time/conv_id/sender_wxid/text_content)。drop 同冷(跳 content_ok=false ——
/// FTS 只索引 message 表, ZstdFail 行 ingest 不落表故冷也搜不到)。空 query 返空(避 `contains("")` 恒真返全库)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_search(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    query: &str,
    limit: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(0, limit)?; // search 无 offset(冷查按相关度 top-N 无偏移); 深翻页走 --mode cold
                                 // codex P2: 空 query 早返空 —— 不建定位表、不全扫。否则 contains("") 恒真会返全库(语义错), 且即便被 !is_empty 挡住
                                 // 匹配仍白扫一遍 9.2M(昂贵)。冷查空 query FTS MATCH '' 也无意义 → 空 query 恒返空一致。
    if query.is_empty() {
        let mut meta = Meta::hot(false)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true });
        meta.limit = Some(limit as u64);
        return Ok(QueryResult { data: vec![], meta });
    }
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    let query_owned = query.to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit;
        let q = query_owned.as_str();
        // **ASCII 大小写不敏感对齐冷查**(Claude R16-6 P2): 冷 FTS trigram + <3字 LIKE 都对 ASCII 大小写**不敏感**(SQLite
        // 默认折叠 A-Z), 而 Rust `str::contains` 字节精确大小写敏感 → 若不折叠, 热对 "http" vs "HTTP" 会漏冷会返的 = 热⊊冷。
        // 优化: query 含 ASCII 字母才对每行文本 `to_ascii_lowercase`(折叠 A-Z, 不动中文/UTF-8 多字节, 同 SQLite 口径);
        // 纯中文/无 ASCII 字母 query 无大小写差异 → 直接 `contains` 免每行分配。
        let q_has_ascii_alpha = q.bytes().any(|b| b.is_ascii_alphabetic());
        let q_lc = q.to_ascii_lowercase();
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 有界 TopN 按 (create_time, source, source_native_id) DESC (同其它热命令; 无 bm25 → 时间序)。payload=(conv, sender, text)。
        let mut top: TopN<(String, Option<String>, String)> = TopN::new(0, limit);
        let stats = sq
            .scan_all_messages(false, None, |m, _msgsource, src| {
                // drop 同冷 (content_ok=false 行 ingest 不落 message 表 → FTS 搜不到)。q 非空 (入口已早返空 query)。
                if m.content_ok && search_text_hit(&m.text, q, q_has_ascii_alpha, &q_lc) {
                    top.offer(m.create_time, src, &m.source_native_id, || {
                        (m.conv_id.clone(), m.sender.clone(), m.text.clone())
                    });
                }
                true
            })
            .context("全扫消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .take(limit)
            .map(|k| {
                let (conv, sender, text) = k.payload;
                serde_json::json!({
                    "create_time": k.ct, "conv_id": conv, "sender_wxid": sender, "text_content": text,
                })
            })
            .collect();
        let has_more = limit > 0 && data.len() < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_matches".into(), serde_json::json!(total));
        // 🔴降级诚实标: 排序是时间序非 bm25 相关度。消费方按此判热 search 结果无相关度排名。
        summary.insert("degraded".into(), serde_json::json!("no_fts_bm25_ranking_time_order"));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查 search 扫描任务失败: {e}"),
        )
    })?
}

/// cache-only 取账号 master key (不 hook / 不碰微信 —— 取 key 是 `auth` 的事)。
///
/// # Errors
/// key 未缓存 / cache 损坏 → `AccountNotFound`。
pub async fn cache_key(wxid: &Wxid) -> Result<MasterKey> {
    CacheKeyProvider::new(None)
        .resolve(wxid)
        .await
        .context("取不到该账号的 key (未缓存 / cache 损坏) — 先跑 `msgvestige auth --wxid <你的 wxid>` 取一次 (会缓存)")
        .map_err(|e| cli_err(native_core::ErrorCode::AccountNotFound, e.to_string()))
}

/// 定位表 JSON 路径: 显式 `--locator-file` > 系统临时目录按 wxid 命名 (持久化, 几百 KB)。
#[must_use]
pub fn query_locator_path(explicit: Option<&str>, wxid: &Wxid) -> PathBuf {
    explicit.map_or_else(
        || std::env::temp_dir().join(format!("wxquery_locator_{}.json", wxid.as_str())),
        PathBuf::from,
    )
}

/// 默认微信数据目录: `%USERPROFILE%\Documents\xwechat_files` (探测到才返回)。
///
/// # Errors
/// 环境变量缺失 / 目录不存在 → `BadRequest` (提示用 `--wechat-data-dir`)。
pub fn default_wechat_data_dir() -> Result<PathBuf> {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(profile).join("Documents").join("xwechat_files");
        if p.is_dir() {
            return Ok(p);
        }
    }
    Err(cli_err(
        native_core::ErrorCode::BadRequest,
        "没找到微信数据目录 — 用 --wechat-data-dir 指向 xwechat_files (如 F:\\xwechat_files)",
    ))
}

/// 从单个目录名解析账号 wxid: `wxid_<id>_<设备后缀>` → `wxid_<id>`; 裸 `wxid_<id>` (无后缀) 原样;
/// 非 `wxid_` → None。
///
/// **假设**: 设备后缀是**单段** (真机实测 `_abfe`/`_c195` 单段) 且账号 id 段本身不含 `_` —— 多段后缀
/// (`_abfe_1` 之类) 会切错, 但失败方向安全 (取错 wxid → cache 查不到 → 报错要 --wxid, 绝不会用错 key)。
#[must_use]
pub fn wxid_from_dir_name(name: &str) -> Option<Wxid> {
    if !name.starts_with("wxid_") {
        return None;
    }
    let cand = if name.matches('_').count() >= 2 {
        name.rsplit_once('_').map_or(name, |(head, _)| head)
    } else {
        name
    };
    Wxid::try_new(cand).ok()
}

/// 从微信数据目录 + wxid 定位账号的 `db_storage` 目录 —— `message/` · `hardlink/` · `contact/` 等子库**目录**
/// 的公共父 (真库实证: media_0.db 在 `message/` 下、视频 hardlink 库在 `hardlink/` 下, 均非 db_storage 根直属)。
/// 账号目录名 = `<wxid>` 或 `<wxid>_<设备后缀>` (跟 `auth` detect 同切法 [`wxid_from_dir_name`])。
///
/// K-R4: 报错走 wxid Display (sha8), 不回显数据目录里的账号明文。
///
/// # Errors
/// 数据目录打不开 → `BadRequest`; 该账号 `db_storage` 不存在 → `AccountNotFound`。
pub fn resolve_db_storage_dir(wechat_data_dir: Option<&str>, wxid: &Wxid) -> Result<PathBuf> {
    let data_dir = match wechat_data_dir {
        Some(d) => PathBuf::from(d),
        None => default_wechat_data_dir()?,
    };
    let entries = std::fs::read_dir(&data_dir)
        .with_context(|| {
            format!(
                "打不开微信数据目录 {} (用 --wechat-data-dir 指向 xwechat_files)",
                data_dir.display()
            )
        })
        .map_err(|e| cli_err(native_core::ErrorCode::BadRequest, e.to_string()))?;
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if wxid_from_dir_name(name).as_ref() == Some(wxid) {
            let db_storage = entry.path().join("db_storage");
            if db_storage.is_dir() {
                return Ok(db_storage);
            }
        }
    }
    Err(cli_err(
        native_core::ErrorCode::AccountNotFound,
        format!("没找到账号 {wxid} 的 db_storage 目录 (账号目录在? 先对该账号跑过 auth?)"),
    ))
}

/// 从微信数据目录 + wxid 定位 `db_storage/message` 目录 (sessions / messages 直查加密源库用)。
/// 骑 [`resolve_db_storage_dir`] 定位账号 db_storage 再拼 `message`。
///
/// # Errors
/// 数据目录打不开 → `BadRequest`; 该账号消息目录不存在 → `AccountNotFound`。
pub fn resolve_message_dir(wechat_data_dir: Option<&str>, wxid: &Wxid) -> Result<PathBuf> {
    let msg_dir = resolve_db_storage_dir(wechat_data_dir, wxid)?.join("message");
    if msg_dir.is_dir() {
        return Ok(msg_dir);
    }
    Err(cli_err(
        native_core::ErrorCode::AccountNotFound,
        format!("没找到账号 {wxid} 的消息目录 db_storage/message (账号目录在? 先对该账号跑过 auth?)"),
    ))
}

/// 枚举 `dir` 下**全部** `<prefix>_<N>.db` 分片文件 (按 N 数值升序)。微信库**文件级分片**成 `media_0.db`/
/// `media_1.db`/… 和 `message_0.db`/…/`message_N.db`; 取用/导出只开 `_0` 会漏后续分片 = **丢数据**, 故必须枚举全部
/// (见 media 语音 + message 图片链路)。精确匹配 `<prefix>_<digits>.db` —— 排除 `-wal`/`-shm`/`.kvdb`/`.material`
/// 伴生文件 + `message_fts.db`/`message_resource.db` 一类非数字后缀。目录读不了 → 空 vec。
#[must_use]
pub fn db_shard_files(dir: &std::path::Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let full_prefix = format!("{prefix}_");
    let mut files: Vec<(u32, PathBuf)> = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(mid) = name
            .strip_prefix(full_prefix.as_str())
            .and_then(|s| s.strip_suffix(".db"))
        else {
            continue;
        };
        if mid.is_empty() || !mid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(n) = mid.parse::<u32>() {
            files.push((n, e.path()));
        }
    }
    files.sort_by_key(|(n, _)| *n);
    files.into_iter().map(|(_, p)| p).collect()
}

/// 枚举 message 目录下全部 `media_<N>.db` 媒体库分片 (语音 media_0/media_1/… 用; = [`db_shard_files`] prefix=media)。
#[must_use]
pub fn media_db_files(message_dir: &std::path::Path) -> Vec<PathBuf> {
    db_shard_files(message_dir, "media")
}

/// `sessions` 热查核 (R5 扩全) —— 直查加密 `session.db` 的 `SessionTable` (微信真实会话列表 + 全字段, 与冷查
/// L1 `session` 行对齐), 按 `sort_timestamp` 倒序取本页。**取代旧 locator 法** (旧法只列"有消息分片的 conv" +
/// shard 数、无会话元数据; 新法出摘要/未读/最后消息时间等 ~20 字段)。auth 后即用, 不建 L1。
///
/// `has_more` = 本页 < 全量 (§2 恒精确); 全量 `total` 是**廉价精确**的 (SessionTable `count(*)`), 进
/// `meta.summary.total_sessions`。呈现留皮。
///
/// # Errors
/// 定位 / 取 key / session.db 解密 / 查询失败 → 携码上抛。
pub async fn hot_sessions(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    _locator_file: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<QueryResult> {
    // R5 扩全: 直读加密 session.db (账号入口 db, db_storage/session/session.db)。旧 locator 参不再用
    // (会话直接从 SessionTable 读, 非从 message 分片推)。
    let session_db = resolve_db_storage_dir(wechat_data_dir, wxid)?
        .join("session")
        .join("session.db");
    let key = cache_key(wxid).await?;
    let (sessions, has_more, total, dropped) = native_core::read_hot_sessions(&session_db, &key, limit, offset)
        .context("查会话失败 (session.db 解密失败? key 不对 / 没对该账号跑过 `auth`?)")?;
    let data: Vec<serde_json::Value> = sessions.iter().map(session_json).collect();
    // has_more: **第6轮再审(第三方 P3)** 由内核 `limit+1` 哨兵**精确**给出 (不再依赖 COUNT / data.len —— 修原 None 分支
    // 满末页多报一次空页, 满足 §6 恒精确)。total 仅供下方 summary 显示 (COUNT 失败=None → total_unknown + partial)。
    // 复审(第4轮)#4: 回显 offset/limit。total_count 不铺顶层 (§14.1), 精确全量走 summary.total_sessions。
    // **第5轮**: 丢行标 partial+dropped_rows。**第6轮#2**: COUNT 失败 → total_unknown + partial (别伪装 total=0)。
    let mut summary = serde_json::Map::new();
    match total {
        Some(t) => {
            summary.insert("total_sessions".into(), serde_json::json!(t));
        }
        None => {
            summary.insert("total_unknown".into(), serde_json::json!(true));
        }
    }
    if dropped > 0 || total.is_none() {
        summary.insert("partial".into(), serde_json::json!(true));
    }
    if dropped > 0 {
        summary.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    let mut meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true })
        .with_dropped(dropped as u64) // codex 审 P2: 走标准 meta.dropped_rows(不止 summary; with_dropped(0) 是 no-op)
        .with_summary(serde_json::Value::Object(summary));
    meta.limit = Some(limit as u64);
    meta.offset = Some(offset as u64);
    Ok(QueryResult { data, meta })
}

/// 复审(第4轮)#2/#5: 热查消息 meta —— `has_more` + hot 标记 + `{live:true}`; 若 build **容忍跳过**了坏分片
/// (`degraded>0`) 则在 `summary` 标 `partial=true` + `unreadable_shards=N`, 明确告知调用方**结果可能漏了这些分片
/// 的消息** (虽 `live:true` 却不完整)。`degraded==0` (常态) → 不挂 summary, 形状不变。
///
/// **粒度=按 build 非按会话** (第4轮复审 P3, 有意保守): 只要该次 build 有坏分片, 本次调用的每个会话查询都标
/// `partial` —— 即便被查会话整个落在健康分片里。宁**多报**(提示"可能漏")不**漏报**(藏掉真丢数据); 精确到"这个
/// 会话是否真受影响"要按分片归属逐会话判, 留后。
fn hot_msg_meta(
    has_more: bool,
    degraded: usize,
    dropped: usize,
    content_degraded: usize,
    degraded_tables: usize,
) -> Meta {
    let meta = Meta::hot(has_more)
        .with_source(Source::Hot)
        .with_freshness(Freshness::Hot { live: true });
    // 第5轮#1: degraded (跳过的主消息分片) 或 dropped (行映射失败丢的行) 任一 >0 → 标 partial; 各计数省略为 0 的项。
    // 第6轮#1: content_degraded (行在但正文/发送人残缺) 也并入 partial → summary.degraded_fields。
    // R16-0 (对抗审 P2-7): degraded_tables (游标中断 → 该表**剩余行全没**) 也并入 —— 它比 dropped 严重:
    // dropped 是"丢了这几行", 它是"这张表后面全没了", 且 has_more 会因此谎报"没有更多"。
    if degraded == 0 && dropped == 0 && content_degraded == 0 && degraded_tables == 0 {
        return meta; // 常态: 不挂 summary, 形状不变
    }
    let mut s = serde_json::Map::new();
    s.insert("partial".into(), serde_json::json!(true));
    if degraded > 0 {
        s.insert("unreadable_shards".into(), serde_json::json!(degraded));
    }
    if dropped > 0 {
        s.insert("dropped_rows".into(), serde_json::json!(dropped));
    }
    if content_degraded > 0 {
        s.insert("degraded_fields".into(), serde_json::json!(content_degraded));
    }
    if degraded_tables > 0 {
        s.insert("truncated_tables".into(), serde_json::json!(degraded_tables));
    }
    // codex 审 P2 同判据: dropped 也走标准 meta.dropped_rows(不止 summary; with_dropped(0) no-op)。
    meta.with_dropped(dropped as u64)
        .with_summary(serde_json::Value::Object(s))
}

/// `messages` 热查核 —— 查某会话最近 N 条 (直查加密源库, 按 local_id 倒序取最近的)。
///
/// `has_more` 精确 (§6 恒精确, §14.1 热查只豁免 total_count 不豁免 has_more): fetch `limit+1` 探是否
/// 还有再截断到 `limit`。消息无廉价全量计数 → **省略 total_count** (§14.1)。呈现留皮。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 查消息失败 (会话 id 不对?) → 携码上抛。
pub async fn hot_messages(
    wxid: &Wxid,
    chat: &str,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
) -> Result<QueryResult> {
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    // R16-0: 注入本账号 wxid —— 单聊 sender 方向回退要它 (status==2 已发=本账号), 热查据此
    // 复用冷查同一份 resolve_sender_parts (见 live_query::SourceQuery::self_wxid)。
    let mut sq = SourceQuery::open(msg_dir, key, locator, wxid.as_str().to_string());
    // 先显式 build (与 hot_sessions 对称): key/库错误在此报, 不被下面 latest_messages 冠成"会话 id 不对"。
    sq.build()
        .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
    let mut msgs = sq
        .latest_messages(chat, limit.saturating_add(1))
        .context("查会话消息失败 (会话 id 不对? 先跑 `sessions` 看有哪些)")?;
    let dropped = sq.last_query_dropped();
    // **第5轮复审(另一AI, P2)**: 丢行会让 `has_more` **少报** —— fetch `limit+1` 里坏 1 条 → `msgs.len()==limit`
    // → `has_more=false`, 但后面其实还有大量消息, 藏了数据。把丢的行数计回: 原始取到 (parsed + dropped) 超 limit
    // 就还有。over-report 安全 (顶多让调用方多翻一空页); under-report 藏数据才是要命的。
    let has_more = msgs.len().saturating_add(dropped) > limit;
    msgs.truncate(limit);
    let data: Vec<serde_json::Value> = msgs.iter().map(msg_json).collect();
    Ok(QueryResult {
        data,
        meta: hot_msg_meta(
            has_more,
            sq.degraded_shards(),
            dropped,
            sq.last_content_degraded(),
            sq.last_query_degraded_tables(), // R16-0 审 P2-7: 游标中断 → 该表剩余行全没
        ),
    })
}

/// `messages` **上下文变体** (④ 对拍 WDA 补的缺口): 取某会话锚点时间 `center_time` 前 `before` 条 + 后
/// `after` 条, 按时间正序返。锚点用 create_time (hot 输出里有, LLM 从上一条消息/搜索命中引用)。
/// 窗口结果非分页 → `has_more=false`, 省 total_count (§14.1)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 查上下文失败 → 携码上抛。
pub async fn hot_messages_around(
    wxid: &Wxid,
    chat: &str,
    center_time: i64,
    before: usize,
    after: usize,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
) -> Result<QueryResult> {
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    // R16-0: 注入本账号 wxid —— 单聊 sender 方向回退要它 (status==2 已发=本账号), 热查据此
    // 复用冷查同一份 resolve_sender_parts (见 live_query::SourceQuery::self_wxid)。
    let mut sq = SourceQuery::open(msg_dir, key, locator, wxid.as_str().to_string());
    sq.build()
        .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
    let msgs = sq
        .messages_around(chat, center_time, before, after)
        .context("查消息上下文失败 (会话 id 不对? 先跑 `sessions` 看有哪些)")?;
    let data: Vec<serde_json::Value> = msgs.iter().map(msg_json).collect();
    Ok(QueryResult {
        data,
        meta: hot_msg_meta(
            false,
            sq.degraded_shards(),
            sq.last_query_dropped(),
            sq.last_content_degraded(),
            sq.last_query_degraded_tables(), // R16-0 审 P2-7
        ),
    })
}

/// `events` 热查核 (**R16-2 第一条 message 分片派生命令**) —— `scan_all_messages` 全局跨分片扫系统消息
/// (`msg_type==10000`; classify_sysmsg 已在 decode_msg_row 跑 → `QueriedMsg.sys_type` 直取, **零新解码**),
/// 6 键对齐冷查 [`crate::events_query`]。可选 `sys_type` 过滤。排序 `create_time DESC, source DESC,
/// source_native_id DESC` —— 第三参 `src`(= rel_name, **冷查 message.source 列原样**, 见 scan_all_messages
/// 头注 P3-2)是**地基决策A** 的跨分片次键, 同毫秒跨分片逐字节对齐冷查。**全扫式**: dropped 只进 summary(lesson②)。
///
/// **⚠️ 已知有界边界 (Claude 审 P3-1, 内测语料 0 例 → mandate② BLOCKED, 不假 ✓)**: 若某 type10000 消息
/// `message_content` **非空但解不出**(损坏 zstd), 冷查 ingest 走 `?` 传播 → 落 SystemError、**无 L2 message 行**
/// → cold `events_query` 看不到它; 而热查 `decode_msg_row` 宽松兜底(空文本 + classify_sysmsg("")=other)仍
/// **emit** 这行 → hot_events 多出一条空文本/other "幽灵"事件(且标 partial + `scan_content_failed>0`)。故
/// **content 损坏时 hot events ⊋ cold events**(calls 不受累: parse_voip("")=None 两侧都丢)。真库对拍
/// `content_failed==0` 故 172765 行零分叉; 该边界仅损坏语料触发, 造不出坏夹具 → 标 BLOCKED, 留后续(若接
/// scan_all_messages 透 content_ok 给闭包, 可让热查也丢损坏行以严格对齐 cold, 待真出现损坏语料再动地基)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_events(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    sys_type: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    // codex f02f1ff P1: 同步全库扫下沉 spawn_blocking —— HTTP serve=current_thread runtime(main.rs:608),
    // 内联会钉死唯一 async 线程(健康检查/无关请求全卡 + request-timeout 定时器 poll 不到无法 fire)。放阻塞池
    // → async 线程空出、超时可 fire。(CLI/MCP 一次性调用无害: spawn_blocking 走独立阻塞池, await 正常返回。)
    // 同冷查 cold() 的既定范式(native-http lib.rs §9)。key/msg_dir/locator 已在 await 前算好, 移进闭包。
    // codex 3a10c84 P1: `scan_permit`(HTTP 传 Some, CLI/MCP 传 None)**移进闭包**持到扫真跑完 —— 请求超时/断连丢
    // handler future 时 spawn_blocking 不被取消仍在跑; permit 留 async 作用域会提前释放 → 并发闸打穿、连发堆满阻塞池 +
    // 每 SourceQuery 数百 MB 累积耗尽内存。移进闭包 = 闸对"真在跑的扫"生效(同 cold/exec/search 范式)。
    let wxid_owned = wxid.as_str().to_string();
    let sys_type_owned = sys_type.map(str::to_string);
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到本闭包(扫描)结束才 drop → 并发闸对真在跑的扫生效
        let sys_type = sys_type_owned.as_deref();
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫收集系统消息。**有界 TopN**(codex media P1 族级一致): 只留 top-(offset+limit) 按 create_time/source/
        // source_native_id DESC(同冷查 events_query)。payload=(conv_id, sys_type, text), src 做跨分片次键。
        let mut top: TopN<(String, Option<String>, String)> = TopN::new(offset, limit);
        let stats = sq
            .scan_all_messages(false, Some(&[10000]), |m, _msgsource, src| {
                // base_types=[10000] 已在 SQL 侧保证 msg_type==10000(零解码浪费), 闭包只剩 sys_type 子过滤。
                // codex biz P2 **同构**(Claude events finding): 先跳**正文 zstd 解码失败行**(m.content_ok=false)。冷查
                // ingest 遇 ZstdFail emit SystemError **不落 message 表** → events_query(WHERE msg_type=10000)没这行;
                // events 与 biz 一样**无 parse 兜底**(sys_type=classify_sysmsg("")="other" 非 None → 空正文行不自跳,
                // 不像 calls/links 靠 parse(空串)→None), 故须显式跳, 否则热多出冷丢弃的幽灵行(空 text/other)破坏 parity +
                // 虚高 total_events + 移 offset 页。(a8dcaa1 只把 content_failed 记进 partial 降级信号, 不丢行 → 行集仍不齐。)
                if m.content_ok && (sys_type.is_none() || m.sys_type.as_deref() == sys_type) {
                    top.offer(m.create_time, src, &m.source_native_id, || {
                        (m.conv_id.clone(), m.sys_type.clone(), m.text.clone())
                    });
                }
                true
            })
            .context("全扫系统消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        // 只对本页算 date(SQLite date localtime, 同冷查 date(create_time/1000,'unixepoch','localtime'))。
        let dconn = rusqlite::Connection::open_in_memory()
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("date 计算失败: {e}")))?;
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (conv, st, text) = k.payload;
                let day: String = dconn
                    .query_row("SELECT date(?1/1000,'unixepoch','localtime')", [k.ct], |r| r.get(0))
                    .unwrap_or_default();
                serde_json::json!({
                    "create_time": k.ct, "date": day, "conv_id": conv,
                    "sys_type": st, "label": st.as_deref().map(crate::sys_type_label), "text": text,
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        // 全扫: 整表 dropped/降级只进 summary(不进 page-local meta.dropped_rows, R16-1 lesson②)。
        let mut summary = serde_json::Map::new();
        summary.insert("total_events".into(), serde_json::json!(total));
        // codex a8dcaa1 P2: **content_failed_rows 必须进降级** —— 系统消息正文解不出时 decode_msg_row 补空文本
        // + classify_sysmsg 退 other, 事件仍出但 sys_type/text 已错; 不计入则无过滤输出静默含错数据、
        // `--sys-type revoke` 还可能漏掉这条却不报 partial。content_failed_rows 是 u64, 其余 usize → 统一 u64。
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            // Claude 审 P3-2: partial 五源全回填, 否则唯一降级源是 truncated/build_degraded 时标了 partial 却报 0 无法定位。
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查系统事件扫描任务失败: {e}"),
        )
    })?
}

/// `calls` 热查核 (**R16-2**) —— `scan_all_messages` base_types=[50] 扫通话消息(msg50), `parse_voip` 解
/// `<voipmsg>`(**与冷查 `project_message_call` 同一 `parse_voip` → 零漂移**), 6 键对齐冷查 [`crate::calls_query`]。
/// **drop 口径同冷**: `parse_voip` 返 None(损坏/非通话摘要)不落 —— 冷查 `message_call` 表也只存 Some(sink.rs
/// `if let Some(call) = project_message_call`), 故热查必须同样跳过, 否则热⊋冷。计 `unparsed_voip` 进 summary(诚实,
/// 非 dropped: 冷查压根不存这些, 不算"丢")。排序 `create_time DESC, source DESC, source_native_id DESC`(第三参
/// `src` 跨分片次键)。**全扫式**: 整表 dropped 只进 summary(R16-1 lesson②)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_calls(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    // codex f02f1ff/3a10c84 P1: 同步全库扫下沉 spawn_blocking(current_thread 不钉死, 超时可 fire) + scan_permit
    // 移进闭包持到扫完(并发闸对真在跑的扫生效, HTTP 传 Some / CLI/MCP 传 None)。理由同 hot_events。
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫通话消息。**有界 TopN**(codex media P1 族级一致): 只留 top-(offset+limit) 按 create_time/source/
        // source_native_id DESC(同冷查 calls_query)。payload=(conv_id, invite_type, duration, display_content)。
        let mut top: TopN<(String, i64, i64, String)> = TopN::new(offset, limit);
        let mut unparsed: usize = 0;
        let stats = sq
            .scan_all_messages(false, Some(&[50]), |m, _msgsource, src| {
                // parse_voip 同冷查 project_message_call(msg_type + text_content): None(损坏/非通话)不落, 对齐 message_call。
                // m.msg_type 是 i64(decode 存 i64::from(base)); parse_voip 要 i32。base_types=[50] 已保证值=50, 无截断。
                let mt = i32::try_from(m.msg_type).unwrap_or(-1);
                if let Some(card) = native_core::decoder::parse_voip(mt, &m.text) {
                    top.offer(m.create_time, src, &m.source_native_id, || {
                        (m.conv_id.clone(), card.invite_type, card.duration, card.display_content)
                    });
                } else {
                    unparsed += 1; // msg50 但 parse_voip 解不出 → 冷查也不存, 计数不算 dropped
                }
                true
            })
            .context("全扫通话消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (conv, it, dur, disp) = k.payload;
                serde_json::json!({
                    "create_time": k.ct, "conv_id": conv, "kind": crate::call_kind(it),
                    "invite_type": it, "duration_sec": dur, "result": disp,
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        // 全扫: 整表 dropped/降级只进 summary(R16-1 lesson②)。
        let mut summary = serde_json::Map::new();
        summary.insert("total_calls".into(), serde_json::json!(total));
        if unparsed > 0 {
            summary.insert("unparsed_voip".into(), serde_json::json!(unparsed));
        }
        // codex a8dcaa1 P2: content_failed_rows 进降级 —— 通话正文解不出时 m.text 空 → parse_voip 退 None → 丢,
        // 冷查(project_message_call)也丢, 但热查该报 partial(有通话记录静默漏了)。content_failed_rows u64, 余 usize。
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            // Claude 审 P3-2: partial 五源全回填, 否则唯一降级源是 truncated/build_degraded 时标了 partial 却报 0 无法定位。
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查通话扫描任务失败: {e}")))?
}

/// `links` 热查核 (**R16-2 appmsg 族**) —— `scan_all_messages` base_types=[49] 扫 appmsg 消息(msg49), `parse_appmsg`
/// 解卡片(**与冷查 `project_message_app` 同一 `parse_appmsg` → 零漂移**), 取**有 url 的**(= 冷查 `links_query`
/// WHERE url != '')。6 键对齐冷查 [`crate::links_query`]。**drop 口径**: `parse_appmsg` None(msg49 但非 appmsg)不落
/// (冷查 message_app 也只存 Some, 计 `unparsed_appmsg`); `parse_appmsg` Some 但 **url 空** → 属别的子视图(file/小程序
/// 等), 跳过**非** unparsed。排序 `create_time DESC, source DESC, source_native_id DESC` + spawn_blocking + scan_permit
/// 同 hot_calls(codex f02f1ff/3a10c84 P1)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_links(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫 appmsg, 只留有 url 的。**有界 TopN**(codex media P1 族级一致): 只留 top-(offset+limit) 按 create_time/
        // source/source_native_id DESC(同冷查 links_query)。payload=(conv_id, title, url, app_type)。
        let mut top: TopN<(String, Option<String>, String, i64)> = TopN::new(offset, limit);
        let mut unparsed: usize = 0;
        let stats = sq
            .scan_all_messages(false, Some(&[49]), |m, _msgsource, src| {
                match native_core::decoder::parse_appmsg(&m.text) {
                    Some(card) => {
                        // links = appmsg WHERE url != ''(冷查 links_query)。空 url 属别的子视图, 跳过(非 unparsed)。
                        if let Some(url) = card.url.filter(|u| !u.is_empty()) {
                            top.offer(m.create_time, src, &m.source_native_id, || {
                                (m.conv_id.clone(), card.title, url, card.app_type)
                            });
                        }
                    }
                    None => unparsed += 1, // msg49 但 parse_appmsg 解不出 → 冷查 message_app 也不存
                }
                true
            })
            .context("全扫 appmsg 消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (conv, title, url, at) = k.payload;
                serde_json::json!({
                    "create_time": k.ct, "conv_id": conv, "title": title, "url": url,
                    "app_type": at, "type_label": crate::app_type_label(at),
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_links".into(), serde_json::json!(total));
        if unparsed > 0 {
            summary.insert("unparsed_appmsg".into(), serde_json::json!(unparsed));
        }
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查链接扫描任务失败: {e}")))?
}

/// `files` 热查核 (**R16-2 appmsg 族**) —— `scan_all_messages` base_types=[49] + `parse_appmsg`, 取**有 file_ext 的**
/// (= 冷查 `files_query` WHERE file_ext != '')。5 键对齐冷查 [`crate::files_query`]: create_time/conv_id/file_name
/// (=card.title 即文件名)/file_ext/file_size。drop 口径(parse_appmsg None 计 unparsed_appmsg, file_ext 空属别的
/// 子视图跳过)/排序/spawn_blocking/scan_permit 同 hot_links。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_files(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫 appmsg, 只留有 file_ext 的。**有界 TopN**(codex media P1 族级一致): 只留 top-(offset+limit) 按
        // create_time/source/source_native_id DESC(同冷查 files_query)。payload=(conv_id, file_name, file_ext, file_size)。
        let mut top: TopN<(String, Option<String>, String, i64)> = TopN::new(offset, limit);
        let mut unparsed: usize = 0;
        let stats = sq
            .scan_all_messages(false, Some(&[49]), |m, _msgsource, src| {
                match native_core::decoder::parse_appmsg(&m.text) {
                    Some(card) => {
                        // files = appmsg WHERE file_ext != ''(冷查 files_query)。空 file_ext 属别的子视图, 跳过(非 unparsed)。
                        if let Some(ext) = card.file_ext.filter(|e| !e.is_empty()) {
                            top.offer(m.create_time, src, &m.source_native_id, || {
                                (m.conv_id.clone(), card.title, ext, card.file_size)
                                // file_name = a.title
                            });
                        }
                    }
                    None => unparsed += 1, // msg49 但 parse_appmsg 解不出 → 冷查 message_app 也不存
                }
                true
            })
            .context("全扫 appmsg 消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (conv, name, ext, size) = k.payload;
                serde_json::json!({
                    "create_time": k.ct, "conv_id": conv, "file_name": name, "file_ext": ext, "file_size": size,
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_files".into(), serde_json::json!(total));
        if unparsed > 0 {
            summary.insert("unparsed_appmsg".into(), serde_json::json!(unparsed));
        }
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查文件扫描任务失败: {e}")))?
}

/// 一条热查位置消息 → json 行 (**R16-2**: 7 键 = 冷查引擎 [`crate::CMD_LOCATIONS`] 的输出集)。
///
/// `create_time`/`conv_id` 来自消息本体; 其余 5 键取 `parse_location` 的
/// [`LocationCard`](native_core::decoder::LocationCard)(scale/poiid/maptype/adcode 冷查 message_location 不落
/// → 热查也不出, 对齐 CMD_LOCATIONS)。lat/lng 出**裸 f64**(引擎 value_json 亦 Real→f64; `Fmt::Float(5)` 只
/// 影响 table 渲染不进 JSON)。键集由 `locations_hot_keys_match_cold_engine_columns` 守卫与冷查引擎对拍。
fn location_json(create_time: i64, conv_id: &str, loc: &native_core::decoder::LocationCard) -> serde_json::Value {
    serde_json::json!({
        "create_time": create_time,
        "conv_id": conv_id,
        "latitude": loc.latitude,
        "longitude": loc.longitude,
        "poiname": loc.poiname,
        "label": loc.label,
        "cityname": loc.cityname,
    })
}

/// `locations` 热查核 (**R16-2 registry 族**) —— `scan_all_messages` base_types=[48] + `parse_location`(与冷查
/// `project_message_location` 同一 parse_location → 零漂移)。7 键对齐冷查引擎命令 [`crate::CMD_LOCATIONS`]:
/// create_time/conv_id/latitude(f64)/longitude(f64)/poiname/label/cityname。**JSON 出原始值**(引擎 value_json
/// 亦 Real→f64/Text→String; Fmt::Float(5) 只作用 table 渲染不进 JSON)。**无子过滤**: message_location 存所有
/// parse_location Some 的 msg48(base_where None); parse_location None → unparsed。排序/spawn_blocking/scan_permit
/// 同 hot_calls。**冷查次键**已在 CMD_LOCATIONS order_by 补齐(5420d74)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_locations(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫位置消息。**有界 TopN**(codex media P1 族级一致): 只留 top-(offset+limit) 按 create_time/source/
        // source_native_id DESC(同冷查 CMD_LOCATIONS order_by)。payload=(conv_id, LocationCard), json 由 location_json 出。
        let mut top: TopN<(String, native_core::decoder::LocationCard)> = TopN::new(offset, limit);
        let mut unparsed: usize = 0;
        let stats = sq
            .scan_all_messages(false, Some(&[48]), |m, _msgsource, src| {
                // parse_location 同冷查 project_message_location(msg_type + text_content): None(损坏/非位置)不落, 对齐。
                let mt = i32::try_from(m.msg_type).unwrap_or(-1);
                if let Some(card) = native_core::decoder::parse_location(mt, &m.text) {
                    top.offer(m.create_time, src, &m.source_native_id, || (m.conv_id.clone(), card));
                } else {
                    unparsed += 1; // msg48 但 parse_location 解不出 → 冷查 message_location 也不存
                }
                true
            })
            .context("全扫位置消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| location_json(k.ct, &k.payload.0, &k.payload.1))
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_locations".into(), serde_json::json!(total));
        if unparsed > 0 {
            summary.insert("unparsed_location".into(), serde_json::json!(unparsed));
        }
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查位置扫描任务失败: {e}")))?
}

/// 一条热查名片消息 → json 行 (**R16-2**: 6 键 = 冷查引擎 [`crate::CMD_CARDS`] 的输出集)。
///
/// `create_time`/`conv_id` 来自消息本体; 其余 4 键取 `parse_card` 的
/// [`CardInfo`](native_core::decoder::CardInfo)。**键名映射**照冷查 CMD_CARDS: `card_nickname`←nickname、
/// `card_alias`←alias、`card_username`←username、**`company`←open_im_desc**(冷查列 `card_open_im_desc` 的
/// 对外 key 是 `company`)。CardInfo 的 sex/province/city/sign/big_head_url/small_head_url 冷查 message_card
/// 不落 → 热查也不出, drop 口径对齐。键集由 `cards_hot_keys_match_cold_engine_columns` 守卫与冷查引擎对拍。
fn card_json(create_time: i64, conv_id: &str, card: &native_core::decoder::CardInfo) -> serde_json::Value {
    serde_json::json!({
        "create_time": create_time,
        "conv_id": conv_id,
        "card_nickname": card.nickname,
        "card_alias": card.alias,
        "card_username": card.username,
        "company": card.open_im_desc,
    })
}

/// `cards` 热查核 (**R16-2 registry 族**) —— `scan_all_messages` base_types=[42] + `parse_card`(与冷查
/// `project_message_card` 同一 parse_card → 零漂移)。6 键对齐冷查引擎命令 [`crate::CMD_CARDS`]:
/// create_time/conv_id/card_nickname/card_alias/card_username/company。**无子过滤**: message_card 存所有
/// parse_card Some 的 msg42(base_where None); parse_card None(无 `<msg>` 根 / 无 username 属性)→ unparsed。
/// 排序/spawn_blocking/scan_permit 同 hot_locations。**冷查次键**已在 CMD_CARDS order_by 补齐(5420d74)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_cards(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫名片消息。**有界 TopN**(codex media P1 族级一致): 只留 top-(offset+limit) 按 create_time/source/
        // source_native_id DESC(同冷查 CMD_CARDS order_by)。payload=(conv_id, CardInfo), json 由 card_json 出。
        let mut top: TopN<(String, native_core::decoder::CardInfo)> = TopN::new(offset, limit);
        let mut unparsed: usize = 0;
        let stats = sq
            .scan_all_messages(false, Some(&[42]), |m, _msgsource, src| {
                // parse_card 同冷查 project_message_card(msg_type + text_content): None(非名片/无 username)不落, 对齐。
                let mt = i32::try_from(m.msg_type).unwrap_or(-1);
                if let Some(card) = native_core::decoder::parse_card(mt, &m.text) {
                    top.offer(m.create_time, src, &m.source_native_id, || (m.conv_id.clone(), card));
                } else {
                    unparsed += 1; // msg42 但 parse_card 解不出 → 冷查 message_card 也不存
                }
                true
            })
            .context("全扫名片消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| card_json(k.ct, &k.payload.0, &k.payload.1))
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_cards".into(), serde_json::json!(total));
        if unparsed > 0 {
            summary.insert("unparsed_card".into(), serde_json::json!(unparsed));
        }
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查名片扫描任务失败: {e}")))?
}

/// 一条热查媒体清单 → json 行 (**R16-2**: 7 键 = 冷查引擎 [`crate::CMD_MEDIA`] 的输出集)。
///
/// `create_time`/`conv_id` 来自消息本体; 其余 5 键取 `parse_media` 的
/// [`MediaCard`](native_core::decoder::MediaCard): media_kind←`card.media_kind.as_str()`(判别串
/// image/video/emoji/voice, 与冷查 L2 存的 media_kind 列同源)、md5/file_size/play_length/cdn_url。MediaCard 的
/// aes_key/thumb_url/extra_id 冷查 CMD_MEDIA 不露 → 热查也不出。`cdn_url` **要出**(引擎标 Fmt::Hidden 只藏 table
/// 不藏 json, 同 emoticons/真跑核过)。键集由 `media_hot_keys_match_cold_engine_columns` 守卫与冷查引擎对拍。
fn media_json(create_time: i64, conv_id: &str, card: &native_core::decoder::MediaCard) -> serde_json::Value {
    serde_json::json!({
        "create_time": create_time,
        "conv_id": conv_id,
        "media_kind": card.media_kind.as_str(),
        "md5": card.md5,
        "file_size": card.file_size,
        "play_length": card.play_length,
        "cdn_url": card.cdn_url,
    })
}

/// `media` 热查核 (**R16-2 registry 族**) —— `scan_all_messages` base_types=[3,34,43,47] + `parse_media`(与冷查
/// `project_message_media` 同一 parse_media → 零漂移)。7 键对齐冷查引擎命令 [`crate::CMD_MEDIA`]:
/// create_time/conv_id/media_kind/md5/file_size/play_length/cdn_url。**无子过滤**: message_media 存所有 parse_media
/// Some 的媒体消息(base_where None); parse_media None(非媒体/损坏/无 md5 无 cdn_url 且非语音有时长)→ unparsed。
/// **多类型扫**(图3/语音34/视频43/表情47), 比 locations/cards 单类型密。排序/spawn_blocking/scan_permit 同 hot_cards。
/// **冷查次键**已在 CMD_MEDIA order_by 补齐(本件)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_media(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫媒体消息(图/语音/视频/表情)。**有界 TopN**(codex media P1): 只留 top-(offset+limit) 按
        // create_time/source/source_native_id DESC(同冷查 CMD_MEDIA order_by), 内存 O(need) 不载全 338万。
        // payload=(conv_id, MediaCard) —— json 由 media_json 出(键与冷查引擎对齐, 守卫测钉)。
        let mut top: TopN<(String, native_core::decoder::MediaCard)> = TopN::new(offset, limit);
        let mut unparsed: usize = 0;
        let stats = sq
            .scan_all_messages(false, Some(&[3, 34, 43, 47]), |m, _msgsource, src| {
                // parse_media 同冷查 project_message_media(msg_type + text_content): None(非媒体/损坏/无引用非语音时长)不落, 对齐。
                let mt = i32::try_from(m.msg_type).unwrap_or(-1);
                if let Some(card) = native_core::decoder::parse_media(mt, &m.text) {
                    top.offer(m.create_time, src, &m.source_native_id, || (m.conv_id.clone(), card));
                } else {
                    unparsed += 1; // msg[3/34/43/47] 但 parse_media 解不出 → 冷查 message_media 也不存
                }
                true
            })
            .context("全扫媒体消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| media_json(k.ct, &k.payload.0, &k.payload.1))
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_media".into(), serde_json::json!(total));
        if unparsed > 0 {
            summary.insert("unparsed_media".into(), serde_json::json!(unparsed));
        }
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查媒体扫描任务失败: {e}")))?
}

/// `biz` 热查核 (**R16-2**) —— 公众号消息 (`conv_id LIKE 'gh_%'`)。**非单类型**: gh_ 会话消息跨所有 msg 类型, 故用
/// `scan_conversations("gh_", base_types=None)` **会话层前缀过滤**(只扫 gh_ 会话不解码别的会话, 比全扫再回调滤省
/// 整批解码), 不按类型过滤。5 键对齐冷查 [`crate::biz_query`]: create_time/date/gh_id/title/msg_type。**无 drop
/// 口径**: 所有 gh_ 消息都出(title 仅 msg49 appmsg 有、其余 None —— 镜像冷查 LEFT JOIN message_app)。date 每页按
/// SQLite localtime 算(同 hot_events, 皮层 Rust 算日界线会分叉)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_biz(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 会话层前缀过滤只扫 gh_ 公众号会话。**有界 TopN**。payload=(gh_id, msg_type, title); title 惰性
        // (只给胜出行 parse_appmsg —— 落选行不白解 appmsg XML)。
        let mut top: TopN<(String, i64, Option<String>)> = TopN::new(offset, limit);
        let stats = sq
            .scan_conversations("gh_", false, None, |m, _msgsource, src| {
                // codex biz P2: **跳过正文 zstd 解码失败行**(m.content_ok=false)。冷查 ingest 遇 ZstdFail emit
                // SystemError **不落 message 表** → biz_query 没这行; biz 无 parse 兜(不像 events/calls 靠 parse(空)→None
                // 自然跳), 故这里显式跳, 否则热多出冷丢弃的坏行破坏 parity + 移 offset 页。(stats.content_failed 已计。)
                if m.content_ok {
                    // biz = 所有(能解码的) gh_ 消息(不按类型 drop); title 仅 msg49 appmsg 有(镜像冷查 LEFT JOIN), 其余 None。
                    top.offer(m.create_time, src, &m.source_native_id, || {
                        let title = if m.msg_type == 49 {
                            native_core::decoder::parse_appmsg(&m.text).and_then(|c| c.title)
                        } else {
                            None
                        };
                        (m.conv_id.clone(), m.msg_type, title)
                    });
                }
                true
            })
            .context("全扫公众号(gh_)消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        // date 每页按 SQLite localtime 算(同冷查 biz_query: date(create_time/1000,'unixepoch','localtime'))。
        let dconn = rusqlite::Connection::open_in_memory()
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("date 计算失败: {e}")))?;
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (gh, mtype, title) = k.payload;
                let day: String = dconn
                    .query_row("SELECT date(?1/1000,'unixepoch','localtime')", [k.ct], |r| r.get(0))
                    .unwrap_or_default();
                serde_json::json!({
                    "create_time": k.ct, "date": day, "gh_id": gh, "title": title, "msg_type": mtype,
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_biz".into(), serde_json::json!(total));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查公众号扫描任务失败: {e}")))?
}

/// `thread` 热查核 (**R16-2 appmsg 族**) —— 引用回复 (msg49 appmsg type57 `<refermsg>`)。`scan_all_messages`
/// base_types=[49] + `parse_appmsg`(**与冷查 `project_message_app` 同一 `parse_appmsg` → 零漂移**), 取**有
/// refer_svrid 的**(= 冷查 [`crate::thread_query`] WHERE `refer_svrid IS NOT NULL AND refer_svrid != ''`)。
/// 6 键对齐冷查: create_time / conv_id / sender_wxid / reply_text(= `card.title` 回复者写的正文) / refer_type
/// (被引消息类型) / quoted_text(= `card.refer_content` 被引原文)。**sender 走路径A**(`m.sender`, R16-0 起恒
/// 非 null: 解不出用 `@sender_unknown` 占位 = 冷查 `message.sender_wxid` NOT NULL 语义, 见 `hot_sender_matches_cold_semantics`)。
/// **drop 口径**: `parse_appmsg` None(msg49 非 appmsg / 正文解码失败退空串)计 `unparsed_appmsg`(冷查 message_app
/// 也不存 → 天然跳掉 content_ok=false 行, 不像 biz 需显式检查); Some 但 refer_svrid 空 → 属别的 appmsg 子视图
/// (link/file/小程序等), 跳过**非** unparsed。排序 `create_time DESC, source DESC, source_native_id DESC` +
/// spawn_blocking + scan_permit 同 hot_links。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_thread(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒 (取 key / spawn / build 前)
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop → 并发闸对真在跑的扫生效
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 全扫 appmsg, 只留有 refer_svrid 的(引用回复)。**有界 TopN**(codex media P1 族级一致): 只留 top-(offset+limit)
        // 按 create_time/source/source_native_id DESC(同冷查 thread_query)。payload=(conv_id, sender, reply_text, refer_type, quoted_text)。
        let mut top: TopN<(String, Option<String>, Option<String>, i64, Option<String>)> = TopN::new(offset, limit);
        let mut unparsed: usize = 0;
        let stats = sq
            .scan_all_messages(false, Some(&[49]), |m, _msgsource, src| {
                match native_core::decoder::parse_appmsg(&m.text) {
                    Some(card) => {
                        // thread = appmsg WHERE refer_svrid 非空(冷查 thread_query)。空 refer_svrid 属别的子视图, 跳过(非 unparsed)。
                        if card.refer_svrid.as_deref().is_some_and(|s| !s.is_empty()) {
                            top.offer(m.create_time, src, &m.source_native_id, || {
                                (
                                    m.conv_id.clone(),
                                    m.sender.clone(),
                                    card.title,
                                    card.refer_type,
                                    card.refer_content,
                                )
                            });
                        }
                    }
                    None => unparsed += 1, // msg49 但 parse_appmsg 解不出 → 冷查 message_app 也不存
                }
                true
            })
            .context("全扫 appmsg 消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (conv, sender, reply_text, refer_type, quoted_text) = k.payload;
                serde_json::json!({
                    "create_time": k.ct, "conv_id": conv, "sender_wxid": sender,
                    "reply_text": reply_text, "refer_type": refer_type, "quoted_text": quoted_text,
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_thread".into(), serde_json::json!(total));
        if unparsed > 0 {
            summary.insert("unparsed_appmsg".into(), serde_json::json!(unparsed));
        }
        // codex thread P2: thread **出 sender_wxid** → `sender_degraded_shards`(某分片 Name2Id 图没全载 → sender
        // 可能是回退/@sender_unknown 占位)也须计进降级标 partial + 暴露, 否则 sender 静默降级调用方无从知。
        // (events/calls/links/files/locations/cards/media/biz 都不出 sender 故不计; thread 是唯一出 sender 的 scan 命令。)
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows
                + stats.degraded_tables
                + stats.truncated_tables
                + stats.build_degraded_shards
                + stats.sender_degraded_shards) as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
            summary.insert(
                "scan_sender_degraded".into(),
                serde_json::json!(stats.sender_degraded_shards),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| {
        cli_err(
            native_core::ErrorCode::Internal,
            format!("热查引用回复扫描任务失败: {e}"),
        )
    })?
}

/// `resolve` 热查核 (**R16-2**) —— 合并转发展开。**双模式**镜像冷查 [`crate::resolve_query`]。**按 (source, source_native_id)
/// 复合键**: 消息锚 source_native_id 跨分片重号(半数消息, local_id 每分片各自行号), 同 msg_id 可能对应多分片的**不同**转发。
/// - `msg_id=Some`(**展开**): scan base_types=[49] **全扫**(callback 恒 true, **不早停** —— codex P1: 早停依赖扫描顺序
///   可能盖住碰撞副本), 收匹配 `source_native_id==msg_id` **且 `source` 命中(source 给了)/或全收(source=None)** 的 `parse_forward`
///   子项; 同时记有转发的 distinct 分片 `fwd_sources`。**source=None 且 fwd_sources>1(跨分片不同消息)→ BadRequest 要 --source**;
///   扫描不完整(任一降级)→ **DbNotReady**(可重试, 别武断当单分片)。命中后 6 键对齐冷查 `query_forward_items`(seq/data_type/
///   type_label/source_name/data_title/data_desc)按 seq 升序(单分片内 seq 唯一)。查无 → NotFound。
/// - `msg_id=None`(**列表**): scan 全部 msg49, `parse_forward` 非空的 HashMap 按 **(source, source_native_id)** 聚 item_count,
///   按 **(item_count DESC, source_native_id ASC, source ASC)** 排序(同冷查 `query_forward_list`)。3 键 source/msg_id/item_count。
///
/// 转发消息不罕见(2万+)但 (source,anchor) 聚合内存 O(转发数) 可控。**drop 口径**: `parse_forward` 对非转发/空正文 msg49 返空 Vec
/// 天然跳(同冷查 `project_message_forward`, 故不需 content_ok)。hot item_count=`len(parse_forward)` == 冷 count(单 (source,anchor) 行)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛; 展开歧义(跨分片)→ BadRequest; 扫描不完整无法确认 → DbNotReady; 查无 → NotFound。
pub async fn hot_resolve(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    msg_id: Option<&str>,
    source: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    let msg_id_owned = msg_id.map(str::to_string);
    let source_owned = source.map(str::to_string);
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build().context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        let (data, total, stats) = if let Some(target_id) = msg_id_owned {
            // 展开模式。**R16-2 修 (锚跨分片重号)**: 锚 source_native_id **半数消息重号**(local_id 每分片各自行号),
            // 同 target_id 可能对应多分片的**不同转发**。故按 (source, source_native_id) **精确定位**, **不合并不同消息**:
            // source 给了只收该分片; source=None 先看落几个分片(有转发的), 跨多分片(歧义)→ BadRequest 要 --source。
            // 每消息行按 (source, source_native_id) 唯一, 不早停全扫顺带得 distinct 分片集。
            let mut items: Vec<native_core::decoder::ForwardItem> = Vec::new();
            let mut fwd_sources: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            let stats = sq
                .scan_all_messages(false, Some(&[49]), |m, _msgsource, src| {
                    if m.source_native_id == target_id {
                        let fwd =
                            native_core::decoder::parse_forward(i32::try_from(m.msg_type).unwrap_or(0), &m.text);
                        if !fwd.is_empty() {
                            // 只记**有转发**的分片(对齐冷查 forward_sources: message_forward_item 只存转发行)。
                            fwd_sources.insert(src.to_string());
                            if source_owned.as_deref().is_none_or(|s| s == src) {
                                items.extend(fwd);
                            }
                        }
                    }
                    true
                })
                .context("全扫找转发消息失败 (key 不对 / 库损坏?)")?;
            // codex P1: **歧义/查无判定要算全部降级类型**。不只 truncated/build-degraded(没扫到): degraded_tables(整表
            // 开/prepare/query 失败跳过)、dropped_rows(行映射失败丢)、content_failed_rows(正文解不出→parse_forward 空)
            // **任一都可能漏掉另一分片的碰撞转发** → 误判"单分片/查无"返错消息数据。故任何降级 → scan_incomplete。
            let scan_incomplete = (stats.dropped_rows
                + stats.degraded_tables
                + stats.truncated_tables
                + stats.build_degraded_shards)
                != 0
                || stats.content_failed_rows != 0;
            if source_owned.is_none() {
                // 歧义: source=None 但该 target_id 在多个分片各有转发 → 要 --source(对齐冷查 resolve_query 的 forward_sources 挡)。
                if fwd_sources.len() > 1 {
                    let srcs: Vec<String> = fwd_sources.into_iter().collect();
                    return Err(cli_err(
                        native_core::ErrorCode::BadRequest,
                        format!(
                            "msg_id {target_id} 在 {} 个分片各有一条不同的消息 ({}) —— 消息锚跨分片重号; 加 --source <分片> 精确定位(见 list 的 source 列)",
                            srcs.len(),
                            srcs.join(", ")
                        ),
                    ));
                }
                // 歧义判定靠**完整扫描**的 fwd_sources; 扫描不完整时可能漏了含碰撞副本的分片 → 无法确认非歧义 → DbNotReady
                // (冷查静态 L1 看全分片能定判; 热查截断时别武断当单分片返回其数据, 免与冷查分叉——加 --source 可绕过)。
                if scan_incomplete {
                    return Err(cli_err(
                        native_core::ErrorCode::DbNotReady,
                        format!(
                            "扫描不完整(有分片/表被跳过), 无法确认 {target_id} 是否跨分片重号; 重试(活源并发写撞), 或加 --source <分片> 精确定位, 或 --mode cold 查 L1"
                        ),
                    ));
                }
            }
            if items.is_empty() {
                // codex P2: 扫描不完整时目标可能在跳过的分片 → 不武断判 NotFound(假 404)。(source 给了时上面的 is_none 块没跑, 这里兜。)
                if scan_incomplete {
                    return Err(cli_err(
                        native_core::ErrorCode::DbNotReady,
                        format!(
                            "扫描不完整(有分片/表被跳过), 无法确认消息 {target_id} 是否存在; 重试(活源并发写撞), 或 --mode cold 查 L1"
                        ),
                    ));
                }
                return Err(cli_err(
                    native_core::ErrorCode::NotFound,
                    format!("消息 {target_id} 没有合并转发子项 (不是合并转发? id/source 不对?)"),
                ));
            }
            // items 来自**单个分片**(source 给了 或 distinct=1)→ 按 seq 升序(同冷查 query_forward_items ORDER BY seq)。
            items.sort_by_key(|a| a.seq);
            let total = items.len();
            let data: Vec<serde_json::Value> = items
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|it| {
                    serde_json::json!({
                        "seq": it.seq, "data_type": it.data_type,
                        "type_label": crate::forward_type_label(&it.data_type),
                        "source_name": it.source_name, "data_title": it.data_title, "data_desc": it.data_desc,
                    })
                })
                .collect();
            (data, total, stats)
        } else {
            // 列表模式。**R16-2 修 (锚重号)**: 按 **(source, source_native_id)** 分组(不再纯锚合并不同分片的**不同消息**)——
            // 对齐冷查 `query_forward_list` 的 `GROUP BY source, source_native_id`。每条转发独立一行, 带 source 供展开精确定位。
            // 每消息行 (source, source_native_id) 唯一 → 每键扫一次(+= 即赋一次)。
            let mut forwards_map: std::collections::HashMap<(String, String), i64> = std::collections::HashMap::new();
            let stats = sq
                .scan_all_messages(false, Some(&[49]), |m, _msgsource, src| {
                    let items =
                        native_core::decoder::parse_forward(i32::try_from(m.msg_type).unwrap_or(0), &m.text);
                    if !items.is_empty() {
                        *forwards_map.entry((src.to_string(), m.source_native_id.clone())).or_insert(0) +=
                            items.len() as i64;
                    }
                    true
                })
                .context("全扫转发消息失败 (key 不对 / 库损坏?)")?;
            // (item_count DESC, source_native_id ASC, source ASC) —— 同冷查 query_forward_list。
            let mut forwards: Vec<((String, String), i64)> = forwards_map.into_iter().collect();
            forwards.sort_by(|a, b| {
                b.1.cmp(&a.1).then_with(|| a.0 .1.cmp(&b.0 .1)).then_with(|| a.0 .0.cmp(&b.0 .0))
            });
            let total = forwards.len();
            let data: Vec<serde_json::Value> = forwards
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|((src, id), n)| serde_json::json!({"source": src, "msg_id": id, "item_count": n}))
                .collect();
            (data, total, stats)
        };
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        // 单一 total 键(两模式共用): 展开=子项数 / 列表=转发条数。CLI table_total("total_resolve") 冷读 total_count、热读此。
        summary.insert("total_resolve".into(), serde_json::json!(total));
        // resolve 不出 sender_wxid → 不计 sender_degraded(同 events/calls)。content_failed: 目标正文解不出 → parse 空 →
        // 展开 NotFound / 列表跳过(同冷查丢), 计进 partial 让调用方知有转发消息没解出。
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert("scan_truncated_tables".into(), serde_json::json!(stats.truncated_tables));
            summary.insert("scan_build_degraded_shards".into(), serde_json::json!(stats.build_degraded_shards));
            summary.insert("scan_content_failed".into(), serde_json::json!(stats.content_failed_rows));
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查合并转发扫描任务失败: {e}")))?
}

/// `mentions` 热查核 (**R16-2, 一对多**) —— 群消息 @提及。`scan_all_messages` **want_msgsource=true**(@名单在 msgsource 的
/// `<atuserlist>`, 真库 98.4% zstd, 逐行解)**base_types=None**(@可在任意类型群消息 —— 真库 type 1/49/10000, 但冷查
/// `project_message_mention` 只按 `is_chatroom` 过滤不按类型 → 热也全类型免漏)。每消息 `parse_mentions` **一@一行(一对多**,
/// 同冷查 message_mention; parse_mentions 去重同 wxid @两次)。6 键对齐冷查 [`crate::mentions_query`]: create_time/conv_id/
/// sender_wxid/mentioned_wxid/is_at_all/text_content。**sender 走路径A**(m.sender, 出 sender → 计 `sender_degraded_shards`, 同 thread)。
/// **排序 4 键**: create_time/source/source_native_id DESC + **末位 mentioned_wxid DESC**(破同消息多@的并列, offer_tie 第4键,
/// 对齐冷查 `ORDER BY ... mn.mentioned_wxid DESC`)。`who` 给了按 mentioned_wxid **子串**过滤(= 冷查 `LIKE '%who%'`)。
/// **drop 口径**: `!m.content_ok`(正文 zstd 坏 → 冷查整条不建, codex P2)/`!is_chatroom`(单聊无@语义, 同冷查)/
/// `parse_mentions` 空(无@)跳。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_mentions(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    who: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // codex/Claude d416553: 深翻页守卫尽早拒
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    let who_owned = who.map(str::to_string);
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 一对多: **有界 TopN + 第4键 mentioned_wxid**(offer_tie)。payload=(conv_id, sender, mentioned_wxid, is_at_all, text)。
        let mut top: TopN<(String, Option<String>, String, bool, String)> = TopN::new(offset, limit);
        let stats = sq
            .scan_all_messages(true, None, |m, msgsource, src| {
                // **codex mentions P2 (content_ok guard)**: 先跳**正文 zstd 解码失败行**(m.content_ok=false)。冷查 ingest
                // 遇正文解码失败 → `assemble_message` 返 Err → emit SystemError → **message 与 message_mention 都不建**
                // (decoder/message.rs:160 `?` 传播; msgsource 反是宽松 unwrap_or_default 不丢)。mentions 从 msgsource 解
                // @名单(非正文)→ 即便正文坏 msgsource 仍可解 → 不 guard 会发射冷查没有的行(同 hot_events/hot_biz 的显式跳)。
                // @提及只群消息(同冷查 project_message_mention: !is_chatroom 跳, 防单聊 source 含 atuserlist 误落)。
                if m.content_ok && m.is_chatroom {
                    for mention in native_core::decoder::parse_mentions(msgsource) {
                        // who 给了: mentioned_wxid **子串**匹配(= 冷查 WHERE mn.mentioned_wxid LIKE '%who%')。
                        if who_owned.as_deref().is_none_or(|w| mention.wxid.contains(w)) {
                            // 第4键 tie=mentioned_wxid 破同消息多@并列(对齐冷查末位排序键)。
                            top.offer_tie(m.create_time, src, &m.source_native_id, &mention.wxid, || {
                                (
                                    m.conv_id.clone(),
                                    m.sender.clone(),
                                    mention.wxid.clone(),
                                    mention.is_at_all,
                                    m.text.clone(),
                                )
                            });
                        }
                    }
                }
                true
            })
            .context("全扫 @提及消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (conv, sender, mw, aa, text) = k.payload;
                serde_json::json!({
                    "create_time": k.ct, "conv_id": conv, "sender_wxid": sender,
                    // **codex mentions P2**: is_at_all 出**整数 0/1** 对齐冷查(mn.is_at_all 是 INTEGER 列 → JSON number)。
                    // 出 bool 会破冷热字段对等, 且 CLI table 的 `.as_i64()` 对 JSON bool 返 None → @所有人 行渲染错。
                    "mentioned_wxid": mw, "is_at_all": i64::from(aa), "text_content": text,
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_mentions".into(), serde_json::json!(total));
        // mentions **出 sender_wxid** → `sender_degraded_shards` 计进降级(同 thread; 见 codex thread P2)。
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows
                + stats.degraded_tables
                + stats.truncated_tables
                + stats.build_degraded_shards
                + stats.sender_degraded_shards) as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
            summary.insert(
                "scan_sender_degraded".into(),
                serde_json::json!(stats.sender_degraded_shards),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查@提及扫描任务失败: {e}")))?
}

/// `group-events` 热查核 (**R16-2, 一对多**) —— 群成员进出 (join/remove)。`scan_all_messages` base_types=[10000]
/// (系统消息, 类型预过滤秒级) + `is_chatroom` 过滤(同冷查 `project_chatroom_member_events`: `msg_type!=10000 ||
/// !is_chatroom → 空`)。每消息 `parse_member_events(m.text)` **一成员一行(一对多**, 同冷查 enumerate) —— 从**正文**
/// (text_content)解, 故 content_ok=false 时 m.text 空 → parse 退空 Vec **天然跳**(不像 events 需显式 guard)。
/// 5 键对齐冷查引擎命令 [`crate::CMD_GROUP_EVENTS`](表 `chatroom_member_event`): event_time/conv_id/event_kind
/// (join/remove 原始, EnumStr 只作 table)/member_nickname/member_wxid。**排序 3 键**: event_time/source/**source_native_id**
/// (`{裸anchor}:{seq}` 逐成员唯一, 同冷查投影 source_native_id) DESC —— seq 嵌进 snid 即天然唯一, **不需第4键**;
/// 冷查 CMD_GROUP_EVENTS order_by 亦补 (source, source_native_id) 次键与之对齐。**不出消息 sender** → 无 sender_degraded
/// (member_wxid 是正文 XML 解出的进出成员, 非消息发送人 Name2Id 解析)。
///
/// # Errors
/// 定位 / 取 key / 建定位表 / 扫描失败 → 携码上抛。
pub async fn hot_group_events(
    wxid: &Wxid,
    wechat_data_dir: Option<&str>,
    locator_file: Option<&str>,
    limit: usize,
    offset: usize,
    scan_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<QueryResult> {
    check_hot_window(offset, limit)?; // 深翻页守卫尽早拒
    let msg_dir = resolve_message_dir(wechat_data_dir, wxid)?;
    let key = cache_key(wxid).await?;
    let locator = query_locator_path(locator_file, wxid);
    let wxid_owned = wxid.as_str().to_string();
    tokio::task::spawn_blocking(move || -> Result<QueryResult> {
        let _scan_permit = scan_permit; // 持到扫描结束才 drop
        let mut sq = SourceQuery::open(msg_dir, key, locator, wxid_owned);
        sq.build()
            .context("建定位表失败 (key 不对 / 库损坏 / 没对该账号跑过 `auth`?)")?;
        // 一对多: **有界 TopN**, 3 键 (event_time, source, source_native_id=anchor:seq) 唯一 → 用 offer(不需 tie)。
        // payload=(conv_id, event_kind, member_nickname, member_wxid)。
        let mut top: TopN<(String, &'static str, Option<String>, Option<String>)> = TopN::new(offset, limit);
        let stats = sq
            .scan_all_messages(false, Some(&[10000]), |m, _msgsource, src| {
                // 进出群只群消息(同冷查 project_chatroom_member_events: !is_chatroom 跳)。
                if m.is_chatroom {
                    // parse_member_events 从**正文**解 → content_ok=false 时 m.text 空 → 退空 Vec 天然跳(不需显式 guard)。
                    for (seq, ev) in native_core::decoder::parse_member_events(&m.text)
                        .into_iter()
                        .enumerate()
                    {
                        // source_native_id = 裸 anchor + ':' + 0基序号(同冷查投影, 逐成员唯一 → 3键即确定序)。
                        let snid = format!("{}:{seq}", m.source_native_id);
                        top.offer(m.create_time, src, &snid, || {
                            (
                                m.conv_id.clone(),
                                ev.kind,
                                ev.member_nickname.clone(),
                                ev.member_wxid.clone(),
                            )
                        });
                    }
                }
                true
            })
            .context("全扫群进出消息失败 (key 不对 / 库损坏?)")?;
        let (kept, total) = top.finish();
        let data: Vec<serde_json::Value> = kept
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|k| {
                let (conv, kind, nick, mwxid) = k.payload;
                serde_json::json!({
                    "event_time": k.ct, "conv_id": conv, "event_kind": kind,
                    "member_nickname": nick, "member_wxid": mwxid,
                })
            })
            .collect();
        let has_more = limit > 0 && offset.saturating_add(data.len()) < total;
        let mut summary = serde_json::Map::new();
        summary.insert("total_group_events".into(), serde_json::json!(total));
        let degraded: u64 = stats.content_failed_rows
            + (stats.dropped_rows + stats.degraded_tables + stats.truncated_tables + stats.build_degraded_shards)
                as u64;
        if degraded > 0 {
            summary.insert("partial".into(), serde_json::json!(true));
            summary.insert("scan_dropped".into(), serde_json::json!(stats.dropped_rows));
            summary.insert("scan_degraded_tables".into(), serde_json::json!(stats.degraded_tables));
            summary.insert(
                "scan_truncated_tables".into(),
                serde_json::json!(stats.truncated_tables),
            );
            summary.insert(
                "scan_build_degraded_shards".into(),
                serde_json::json!(stats.build_degraded_shards),
            );
            summary.insert(
                "scan_content_failed".into(),
                serde_json::json!(stats.content_failed_rows),
            );
        }
        let mut meta = Meta::hot(has_more)
            .with_source(Source::Hot)
            .with_freshness(Freshness::Hot { live: true })
            .with_summary(serde_json::Value::Object(summary));
        meta.limit = Some(limit as u64);
        meta.offset = Some(offset as u64);
        Ok(QueryResult { data, meta })
    })
    .await
    .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("热查群进出扫描任务失败: {e}")))?
}

#[cfg(test)]
mod tests {

    /// **随机造两万例, 核"每张表拿到的是它新行的前缀"** —— 这一格破了就是**永久漏消息**。
    ///
    /// 保底行和补位行取并集再截断, 会不会让某张表拿到"跳着的几行"(比如第 1 条和第 3 条、缺第 2 条)?
    /// 破了的话水位会推过那条没展示的行, 它以后再也不会被报出来。
    ///
    /// 这条是**独立复审写的**, 我原来没有 —— 它是唯一一条**不用真账号 key** 就能守住这一格的守卫
    /// (另外两条端到端的都要加密夹具, 带 `#[ignore]`)。原样收进来。
    /// 照 `hot_new` 的真实扫描序造输入: plan 按 conv_id 升序 → 该会话的各分片(顺序不保证) → 表内行号升序。
    ///
    /// 六条断言: 不超名额 / 无重复 / 排序对 / **每张表是前缀** / **没展示的行必须都在新水位之上** /
    /// has_more 说没有更多时一条不剩。
    #[test]
    fn prefix_invariant_holds_across_random_inputs() {
        use std::collections::{BTreeMap, HashMap};
        struct R(u64);
        impl R {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn below(&mut self, n: usize) -> usize {
                usize::try_from(self.next() % (n as u64)).unwrap()
            }
        }
        let mut rng = R(0x1234_5678_9abc_def0);
        let mut nonempty = 0u32;
        for case in 0..20000u32 {
            let n_convs = 1 + rng.below(6);
            let n_shards = 1 + rng.below(3);
            let limit = rng.below(9);
            let per_conv = rng.below(5);
            let convs: Vec<String> = (0..n_convs).map(|i| format!("c{i:03}@chatroom")).collect();
            let shards: Vec<String> = (0..n_shards).map(|i| format!("message_{i}.db")).collect();
            let mut tables: HashMap<(String, String), Vec<i64>> = HashMap::new();
            let mut locs: HashMap<String, Vec<String>> = HashMap::new();
            for c in &convs {
                let mut order: Vec<String> = shards.clone();
                for i in (1..order.len()).rev() {
                    let j = rng.below(i + 1);
                    order.swap(i, j);
                }
                let mut take: Vec<String> = Vec::new();
                for s in order {
                    if rng.below(3) == 0 {
                        continue;
                    }
                    let base = rng.below(4) as i64;
                    let n_new = rng.below(6);
                    if n_new == 0 {
                        continue;
                    }
                    let lids: Vec<i64> = (1..=n_new as i64).map(|k| base + k).collect();
                    tables.insert((s.clone(), c.clone()), lids);
                    take.push(s);
                }
                locs.insert(c.clone(), take);
            }
            // ── 照抄 hot_new 的行循环 ──
            let mut floors: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
            let mut floor_rows = 0usize;
            let mut bottom: super::BottomN<super::NewRow> = super::BottomN::new(limit);
            for c in &convs {
                for s in locs.get(c).into_iter().flatten() {
                    let Some(lids) = tables.get(&(s.clone(), c.clone())) else {
                        continue;
                    };
                    for (i, lid) in lids.iter().enumerate() {
                        let snid = format!("{c}\u{1f}{lid:020}");
                        let seq = i as i64 + 1;
                        let payload = || (0i64, c.clone(), None, "text".to_string(), String::new(), *lid, seq);
                        super::offer_floor(&mut floors, &mut floor_rows, c, limit, per_conv, || super::Keyed {
                            ct: 0,
                            src: s.clone(),
                            snid: snid.clone(),
                            tie: String::new(),
                            payload: payload(),
                        });
                        bottom.offer(0, s, &snid, payload);
                    }
                }
            }
            let (kept, total_new) = bottom.finish();
            let out = super::apply_per_conv_floor(kept, floors, limit, per_conv);
            if !out.is_empty() {
                nonempty += 1;
            }
            // ① 不超名额
            assert!(out.len() <= limit, "case {case}: 出了 {} 条 > 名额 {limit}", out.len());
            // ② 无重复
            let mut keys: Vec<(String, String)> = out.iter().map(|k| (k.src.clone(), k.snid.clone())).collect();
            let before = keys.len();
            keys.sort();
            keys.dedup();
            assert_eq!(before, keys.len(), "case {case}: 出现重复行");
            // ③ 按 (src, snid) 升序
            let mut s2 = keys.clone();
            s2.sort();
            let actual: Vec<(String, String)> = out.iter().map(|k| (k.src.clone(), k.snid.clone())).collect();
            assert_eq!(actual, s2, "case {case}: 结果没按 (src, snid) 排序");
            // ④ 每张表拿到的是它新行的前缀
            let mut got: HashMap<(String, String), Vec<i64>> = HashMap::new();
            for k in &out {
                got.entry((k.src.clone(), k.payload.1.clone()))
                    .or_default()
                    .push(k.payload.5);
            }
            for (tk, g) in &got {
                let mut g = g.clone();
                g.sort_unstable();
                let full = tables
                    .get(tk)
                    .unwrap_or_else(|| panic!("case {case}: 出现了不存在的表 {tk:?}"));
                assert_eq!(
                    &g[..],
                    &full[..g.len()],
                    "case {case}: 表 {tk:?} 拿到的不是前缀 (limit={limit}, per_conv={per_conv}); 该表新行 {full:?}"
                );
            }
            // ⑤ 没展示的行必须都还在新水位之上 —— 破了就是永久漏消息
            let mut new_id: HashMap<(String, String), i64> = HashMap::new();
            for k in &out {
                let e = new_id
                    .entry((k.src.clone(), k.payload.1.clone()))
                    .or_insert(k.payload.5);
                if k.payload.5 > *e {
                    *e = k.payload.5;
                }
            }
            for (tk, full) in &tables {
                let wm_id = new_id.get(tk).copied().unwrap_or(0);
                let shown = got.get(tk).cloned().unwrap_or_default();
                for lid in full {
                    if !shown.contains(lid) {
                        assert!(
                            *lid > wm_id,
                            "case {case}: 表 {tk:?} 第 {lid} 行没展示却被新水位 {wm_id} 越过 = 永久漏 (limit={limit}, per_conv={per_conv})"
                        );
                    }
                }
            }
            // ⑥ has_more 说没有更多时, 必须真的一条不剩
            if limit > 0 && total_new <= limit {
                assert_eq!(
                    out.len(),
                    total_new,
                    "case {case}: has_more=false 却少给了行 (limit={limit}, per_conv={per_conv})"
                );
            }
        }
        assert!(nonempty > 5000, "样本太水: 只有 {nonempty} 例出了行");
    }

    /// **保底集的总量真的卡在 `limit`, 且腾位置时只腾一格**(codex 审 1cdb2fd 的两条 P2)。
    ///
    /// 一, 老会话再来行时也得看总量。早先那一支只看"这个会话拿满没有", 于是
    /// `limit=1, per_conv=100000` 时头一个会话能自己留下十万行 —— 说好的"总量卡在 limit"作废,
    /// 内存变成 limit × per_conv。
    ///
    /// 二, 满了之后腾位置, 早先是把最靠后那个会话**整个扔掉**。`per_conv > 1` 时它可能占着好几行,
    /// 而新来的只要一格 —— 多空出来的格子随后被全局最忙的会话填掉, 被扔的那个明明还装得下,
    /// 保底却没了。
    #[test]
    fn floor_set_respects_the_global_cap_and_evicts_one_slot_at_a_time() {
        use std::collections::BTreeMap;
        let row = |conv: &str, lid: i64| {
            let c = conv.to_string();
            move || super::Keyed {
                ct: 0,
                src: "message_0.db".to_string(),
                snid: format!("{c}\u{1f}{lid:020}"),
                tie: String::new(),
                payload: (0i64, c.clone(), None, "text".to_string(), String::new(), lid, lid),
            }
        };

        // ① 总量卡死: limit=1 而 per_conv 很大, 头一个会话也只能留 1 行。
        let mut floors: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
        let mut n = 0usize;
        for i in 1..=50 {
            super::offer_floor(&mut floors, &mut n, "aaa", 1, 100_000, row("aaa", i));
        }
        assert_eq!(n, 1, "总量说卡在 limit 就得卡住, 实得 {n} 行");
        assert_eq!(floors["aaa"].len(), 1);

        // ② 腾位置只腾一格: 名额 3, 会话 zzz 先占 2 行、mmm 占 1 行 → 满。
        //    更靠前的 aaa 来了, 该只从 zzz 弹掉一行, 而不是把 zzz 整个扔掉。
        let mut floors: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
        let mut n = 0usize;
        super::offer_floor(&mut floors, &mut n, "mmm", 3, 2, row("mmm", 1));
        super::offer_floor(&mut floors, &mut n, "zzz", 3, 2, row("zzz", 1));
        super::offer_floor(&mut floors, &mut n, "zzz", 3, 2, row("zzz", 2));
        assert_eq!(n, 3, "夹具前提: 三格占满");
        super::offer_floor(&mut floors, &mut n, "aaa", 3, 2, row("aaa", 1));
        assert_eq!(n, 3, "总量不变");
        assert_eq!(
            floors.keys().cloned().collect::<Vec<_>>(),
            vec!["aaa", "mmm", "zzz"],
            "zzz 该留着(它只该被弹掉一行), 整个被扔掉的话它就没保底了"
        );
        assert_eq!(
            floors["zzz"].len(),
            1,
            "zzz 只该被弹掉一行, 实得 {} 行",
            floors["zzz"].len()
        );
        // 弹掉的得是它**最后**那一行 —— 留下的仍是前缀, 水位那头靠这条。
        assert_eq!(floors["zzz"][0].payload.5, 1, "留下的该是行号小的那条");
    }

    /// **保底名额按逻辑会话记, 且满了之后按会话顺序留 —— 不是"谁先扫到谁赢"**(codex 审 80b3e74 的两条 P2)。
    ///
    /// 一, 同一个会话可以同时在多个分片里(真库实测 700 张同名表)。按 (分片, 会话表) 记名额的话,
    /// 一个横跨三个分片的会话会拿到三份保底, 把别的会话挤出去 —— 正是这个功能要治的毛病。
    ///
    /// 二, 扫描顺序是 (分片, 会话, 行号), 跨分片时会话并不按 `conv_id` 升序来。满了之后先到先得的话,
    /// 靠后分片里的会话会赢过本该排在前面、只是还没扫到的会话 —— 跟对外说的"按会话顺序发"对不上。
    #[test]
    fn floor_quota_is_per_conversation_and_shortage_keeps_the_earliest() {
        use std::collections::BTreeMap;
        let row = |src: &str, conv: &str, lid: i64| {
            let (s, c) = (src.to_string(), conv.to_string());
            move || super::Keyed {
                ct: 0,
                src: s.clone(),
                snid: format!("{c}\u{1f}{lid:020}"),
                tie: String::new(),
                payload: (0i64, c.clone(), None, "text".to_string(), String::new(), lid, lid),
            }
        };

        // ① 同一个会话横跨三个分片, 保底 1 条 —— 只该占 1 个名额, 不是 3 个。
        let mut floors: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
        let mut n = 0usize;
        for shard in ["message_0.db", "message_1.db", "message_5.db"] {
            super::offer_floor(&mut floors, &mut n, "aaa@chatroom", 3, 1, row(shard, "aaa@chatroom", 1));
        }
        assert_eq!(n, 1, "横跨三个分片的同一个会话只该拿一份保底名额, 实得 {n}");
        // 名额还剩着, 别的会话进得来。
        super::offer_floor(
            &mut floors,
            &mut n,
            "zzz@chatroom",
            3,
            1,
            row("message_0.db", "zzz@chatroom", 1),
        );
        assert_eq!(floors.len(), 2, "别的会话该进得来");

        // ② 名额满了之后: 后扫到但**更靠前**的会话该顶掉最靠后那个; 后扫到又更靠后的进不来。
        let mut floors: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
        let mut n = 0usize;
        // 扫描顺序故意不是 conv_id 升序 (模拟跨分片)。
        for c in ["mmm", "zzz"] {
            super::offer_floor(&mut floors, &mut n, c, 2, 1, row("message_0.db", c, 1));
        }
        assert_eq!(floors.keys().cloned().collect::<Vec<_>>(), vec!["mmm", "zzz"]);
        // 更靠前的 aaa 后扫到 —— 该把最靠后的 zzz 顶掉。
        super::offer_floor(&mut floors, &mut n, "aaa", 2, 1, row("message_5.db", "aaa", 1));
        assert_eq!(
            floors.keys().cloned().collect::<Vec<_>>(),
            vec!["aaa", "mmm"],
            "满了之后该按会话顺序留最靠前的那批, 而不是谁先扫到谁赢"
        );
        assert_eq!(n, 2, "总数还是名额那么多");
        // 更靠后的 nnn 后扫到 —— 进不来。
        super::offer_floor(&mut floors, &mut n, "nnn", 2, 1, row("message_5.db", "nnn", 1));
        assert_eq!(
            floors.keys().cloned().collect::<Vec<_>>(),
            vec!["aaa", "mmm"],
            "更靠后的不该挤进来"
        );

        // ③ 关着的时候一行都不收。
        let mut floors: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
        let mut n = 0usize;
        super::offer_floor(&mut floors, &mut n, "aaa", 5, 0, row("message_0.db", "aaa", 1));
        assert!(floors.is_empty() && n == 0, "per_conv=0 时一行都不该收");
    }

    /// **`--per-conv`: 忙会话不许把名额占满, 而不开的时候一个字节都不变**。
    ///
    /// 不开时按 (分片, 会话, 行号) 取全局最小的 N 条 —— 排在前面又一直有新消息的会话会吃光名额,
    /// 后面的会话这一轮一条都出不来(数据不丢, 下次还在, 但当时看不到)。
    ///
    /// 三件一起钉:
    /// 1. `per_conv = 0` **原样返回**(默认路径, 行为不许变);
    /// 2. 开了之后安静会话的头几条**顶掉**忙会话的一部分;
    /// 3. 名额不够分时按会话键顺序发, 且结果**稳定**(HashMap 遍历序是随机的, 不排序的话同样的输入
    ///    两次跑结果不一样)。
    #[test]
    fn per_conv_floor_lets_quiet_chats_through_but_is_off_by_default() {
        use std::collections::BTreeMap;
        let row = |conv: &str, lid: i64| super::Keyed {
            ct: 0,
            src: "message_0.db".to_string(),
            snid: format!("{conv}\u{1f}{lid:020}"),
            tie: String::new(),
            payload: (
                0i64,
                conv.to_string(),
                None,
                "text".to_string(),
                String::new(),
                lid,
                lid,
            ),
        };
        // 忙会话 aaa 有 5 条新的, 安静会话 zzz 有 2 条。名额只有 5 条。
        let busy: Vec<_> = (1..=5).map(|i| row("aaa", i)).collect();
        let quiet: Vec<_> = (1..=2).map(|i| row("zzz", i)).collect();
        // 全局最小的 5 条全是 aaa 的 —— 这就是不开时的结果。
        let kept: Vec<_> = busy.clone();
        // ⚠️ 这里的键**故意带了分片前缀**(`wk` 形状), 跟生产路径不一样 —— 生产传的是纯 `conv_id`
        // (见 `offer_floor` 的注: 同一会话散在多个分片里, 按表记名额会拿到好几份保底)。
        // 这个测试量的是 `apply_per_conv_floor` 拿到保底集之后**怎么摆**, 而下面两个键的分片前缀
        // **完全一样**(都是 `message_0.db`), 所以加不加前缀不改它俩的先后, 结论一样。
        //
        // 注意这个理由**只在前缀相同时才成立**(独立复审的 P3, 我上一版把它写宽成"各自只在一个
        // 分片里"): 要是 zzz 在 `message_0.db`、aaa 在 `message_1.db`, 带前缀是 zzz 在前
        // (`message_0.db` < `message_1.db`), 不带前缀是 aaa 在前 —— 先后就翻了。
        // 别照着这儿去写生产代码。
        let mut floors: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
        floors.insert(
            "message_0.db\u{1f}aaa".to_string(),
            busy.iter().take(1).cloned().collect(),
        );
        floors.insert(
            "message_0.db\u{1f}zzz".to_string(),
            quiet.iter().take(1).cloned().collect(),
        );

        // ① 不开: 原样返回。
        let off = super::apply_per_conv_floor(kept.clone(), floors.clone(), 5, 0);
        let convs: Vec<&str> = off.iter().map(|k| k.payload.1.as_str()).collect();
        assert_eq!(convs, vec!["aaa"; 5], "不开的时候结果一个字节都不该变");

        // ② 开 1 条保底: zzz 得挤进来, 而且顶掉的是 aaa 最靠后那条。
        let on = super::apply_per_conv_floor(kept.clone(), floors.clone(), 5, 1);
        assert_eq!(on.len(), 5, "总数还是名额那么多");
        let convs: Vec<&str> = on.iter().map(|k| k.payload.1.as_str()).collect();
        assert!(convs.contains(&"zzz"), "安静会话必须露面: {convs:?}");
        assert_eq!(convs.iter().filter(|c| **c == "aaa").count(), 4, "忙会话让出一个名额");
        // 每个会话拿到的仍是它自己的前缀(水位推进那一头靠这条)。
        let aaa_lids: Vec<i64> = on
            .iter()
            .filter(|k| k.payload.1 == "aaa")
            .map(|k| k.payload.5)
            .collect();
        assert_eq!(aaa_lids, vec![1, 2, 3, 4], "忙会话拿到的得是它的前几条, 不能跳着拿");

        // ③ 名额不够分: 3 个会话每个保底 2 条 = 6 条, 而名额只有 3 条 —— 按会话键顺序发, 结果要稳定。
        let mut many: BTreeMap<String, Vec<super::Keyed<super::NewRow>>> = BTreeMap::new();
        for c in ["aaa", "mmm", "zzz"] {
            many.insert(format!("message_0.db\u{1f}{c}"), (1..=2).map(|i| row(c, i)).collect());
        }
        let tight = super::apply_per_conv_floor(vec![], many.clone(), 3, 2);
        let got: Vec<(String, i64)> = tight.iter().map(|k| (k.payload.1.clone(), k.payload.5)).collect();
        assert_eq!(
            got,
            vec![("aaa".to_string(), 1), ("aaa".to_string(), 2), ("mmm".to_string(), 1)],
            "名额不够就按会话键顺序发, 且必须每次都一样"
        );
        for _ in 0..5 {
            let again = super::apply_per_conv_floor(vec![], many.clone(), 3, 2);
            let g2: Vec<(String, i64)> = again.iter().map(|k| (k.payload.1.clone(), k.payload.5)).collect();
            assert_eq!(g2, got, "同样的输入跑多次结果必须一样 (HashMap 遍历序是随机的)");
        }
    }
    use super::*;

    /// **R16-6 exec 路径穿越校验** (Claude 安全审 P3: 安全关键的 `validate_source_db_rel` 原来零单测)。
    /// 向量表锁死: 各类逃逸(`..`/绝对/盘符相对/根/UNC/verbatim/NT命名空间/内部`..`)必**拒**, 库内正常相对路径
    /// (含反斜杠分隔)必**过**。防未来重构把 `components()` 检查退化成只 `is_absolute()`(会漏 `C:foo`/`\foo`)。
    #[test]
    fn validate_source_db_rel_blocks_traversal() {
        // 必拒 (逃逸向量)
        for bad in [
            "",                         // 空
            "..",                       // ParentDir
            "../contact/contact.db",    // 前导 ..
            "..\\..\\Windows\\win.ini", // 反斜杠 ..
            "message/../../contact.db", // 内部 ..
            "C:\\Windows\\win.ini",     // 绝对+盘符
            "C:contact.db",             // 盘符相对 (is_absolute=false, 靠 Prefix 挡)
            "\\Windows\\win.ini",       // 根无盘符 (is_absolute=false, 靠 RootDir 挡)
            "\\\\server\\share\\x.db",  // UNC
            "\\\\?\\C:\\x.db",          // verbatim
            "\\??\\C:\\x.db",           // NT 命名空间 (RootDir)
            "/etc/passwd",              // 绝对 (unix 风)
        ] {
            assert!(validate_source_db_rel(bad).is_err(), "应拒逃逸向量: {bad:?}");
        }
        // 必过 (库内正常相对路径)
        for ok in [
            "contact/contact.db",
            "message/message_0.db",
            "session/session.db",
            "contact\\contact.db",  // 反斜杠分隔 (Windows 正常)
            "./contact/contact.db", // CurDir 前缀
        ] {
            assert!(validate_source_db_rel(ok).is_ok(), "应放行库内相对路径: {ok:?}");
        }
    }

    /// **R16-1 冷热对等** (`friend-requests`): 两条路出的 json —— **键集 + 值都得一样**。
    ///
    /// R16 整件事的目标就是这个"对等"。但对等实际是**我手抄两遍键名**撑着的: 冷查的键在
    /// `handwritten.rs` 的 `json!` 里, 热查的在本文件 `friend_request_json` 里。抄漏/抄错一个
    /// (譬如把 `greeting` 写成 `content` —— 源库列名正是 `content_`, 手滑极自然), 两边就漂了, 而
    /// **各自的测试照样全绿**: 冷查测冷查的键、热查测热查的键, **没人比过两边**。故本测试同时跑两条路。
    ///
    /// 夹具喂**等价数据**: 一行 L1 `friend_verify` ⟷ 一个等价的 `QueriedFriendRequest` (= 源库
    /// `FMessageTable` 那行经内核映射后的样子)。**故意不走真库**: ① 真库要先跑完整条消息 ETL 才会有
    /// friend_verify 数据(实测几小时, 我试过被杀在导消息阶段, 表建了 0 行); ② 真库**测不出键名漂移**
    /// —— 漂了两边也各自绿, 只有并排比才看得见。
    #[test]
    fn friend_requests_hot_cold_json_parity() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE friend_verify (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                user_name_sha TEXT NOT NULL, friend_type INTEGER NOT NULL, timestamp INTEGER NOT NULL,
                is_sender INTEGER NOT NULL, scene INTEGER NOT NULL, content_len INTEGER NOT NULL,
                account_id TEXT NOT NULL, user_name TEXT NOT NULL, content TEXT NOT NULL,
                PRIMARY KEY (account_id_sha, source, source_native_id));
             INSERT INTO friend_verify VALUES
               ('sha','general','1','uw',3,1784283895,0,14,21,'me','wxid_alice','我是群聊的铭悦'),
               ('sha','general','2','uw',3,1784204826,1,17,12,'me','wxid_bob','我是橙子');",
        )
        .unwrap();
        let cold = crate::friend_requests_query(&conn, 10, 0).unwrap();

        // 热查侧: 同样两行经内核映射后的样子 (字段名 = 源库列去尾下划线; content 对外键是 greeting)。
        let hot_rows = [
            native_core::QueriedFriendRequest {
                timestamp: 1_784_283_895,
                user_name: "wxid_alice".into(),
                friend_type: 3,
                is_sender: 0,
                scene: 14,
                content: "我是群聊的铭悦".into(),
            },
            native_core::QueriedFriendRequest {
                timestamp: 1_784_204_826,
                user_name: "wxid_bob".into(),
                friend_type: 3,
                is_sender: 1,
                scene: 17,
                content: "我是橙子".into(),
            },
        ];
        let hot: Vec<serde_json::Value> = hot_rows.iter().map(friend_request_json).collect();

        assert_eq!(cold.data.len(), 2, "夹具 2 行都该出来 (冷查)");
        for (i, (c, h)) in cold.data.iter().zip(hot.iter()).enumerate() {
            let mut ck: Vec<_> = c.as_object().unwrap().keys().cloned().collect();
            let mut hk: Vec<_> = h.as_object().unwrap().keys().cloned().collect();
            ck.sort();
            hk.sort();
            assert_eq!(ck, hk, "第 {i} 行键集必须一致 —— 冷 {ck:?} vs 热 {hk:?}");
            assert_eq!(c, h, "第 {i} 行逐字段值也必须一致 (含 scene_label 这种皮层派生)");
        }
        // 再钉死键名本身 —— 免"两边一起改错"仍然绿 (上面的对拍只保证两边相同, 不保证相同的是对的)。
        let mut keys: Vec<&str> = hot[0].as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "friend_type",
                "greeting",
                "is_sender",
                "scene",
                "scene_label",
                "timestamp",
                "user_name"
            ],
            "对外 7 键 —— 是 greeting 不是 content (源库列叫 content_, 冷查对外一直叫 greeting)"
        );
    }

    /// **R16-1 冷热对等** (`finder`): 两条路出的 json —— 键集 + 值都得一样 (同 friend-requests 那条的理由:
    /// "对等"靠手抄两遍键名撑着, 抄漏了两边**各自的测试都照绿**, 只有并排比才看得见)。
    ///
    /// 本条额外钉一件事: **`visit_date` 两边必须是同一个 SQLite `date()` 算的**。冷查在 SQL 里算,
    /// 热查解完 proto 回 SQLite 算 —— 若哪天有人图省事在皮层用 Rust 算, 日界线附近就会分叉, 而这种
    /// 分叉一年只在少数几天出现、真库对拍多半照过。
    #[test]
    fn finder_hot_cold_json_parity() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE finder_visit (
                account_id_sha TEXT NOT NULL, source TEXT NOT NULL, source_native_id TEXT NOT NULL,
                owner_username_sha TEXT NOT NULL, visit_time INTEGER NOT NULL,
                account_id TEXT NOT NULL, owner_username TEXT NOT NULL, name TEXT NOT NULL,
                profile_url TEXT NOT NULL,
                PRIMARY KEY (account_id_sha, source, source_native_id));
             INSERT INTO finder_visit VALUES
               ('sha','general.db','FMessage_a','ows',1784099379,'me','a40754976','我猜猜猜','https://x/a'),
               ('sha','general.db','FMessage_b','ows',1784109436,'me','wxid_opqr7890stuv123','','');",
        )
        .unwrap();
        let cold = crate::finder_query(&conn, 10, 0).unwrap();

        // 热查侧: 同样两行经内核映射后的样子。visit_date 用**同一个 SQLite date()** 算 —— 与内核同源。
        let d = |ts: i64| -> String {
            conn.query_row("SELECT date(?1, 'unixepoch', 'localtime')", [ts], |r| r.get(0))
                .unwrap()
        };
        let hot_rows = [
            native_core::QueriedFinderVisit {
                visit_time: 1_784_109_436,
                visit_date: d(1_784_109_436),
                name: String::new(),
                owner_username: "wxid_opqr7890stuv123".into(),
                profile_url: String::new(),
            },
            native_core::QueriedFinderVisit {
                visit_time: 1_784_099_379,
                visit_date: d(1_784_099_379),
                name: "我猜猜猜".into(),
                owner_username: "a40754976".into(),
                profile_url: "https://x/a".into(),
            },
        ];
        let hot: Vec<serde_json::Value> = hot_rows.iter().map(finder_visit_json).collect();

        assert_eq!(cold.data.len(), 2, "夹具 2 行都该出来 (冷查)");
        for (i, (c, h)) in cold.data.iter().zip(hot.iter()).enumerate() {
            let mut ck: Vec<_> = c.as_object().unwrap().keys().cloned().collect();
            let mut hk: Vec<_> = h.as_object().unwrap().keys().cloned().collect();
            ck.sort();
            hk.sort();
            assert_eq!(ck, hk, "第 {i} 行键集必须一致 —— 冷 {ck:?} vs 热 {hk:?}");
            assert_eq!(c, h, "第 {i} 行逐字段值也必须一致 (含 visit_date 这种 SQL 派生)");
        }
        let mut keys: Vec<&str> = hot[0].as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["name", "owner_username", "profile_url", "visit_date", "visit_time"],
            "对外 5 键"
        );
    }

    /// **R16-1 冷热对等** (`emoticons`): 热查 json 的键 **== 冷查引擎 `CMD_EMOTICONS` 的列 key 集**。
    ///
    /// 本条冷查是**引擎路径**(不像前四条是手写 `*_query`), 冷查 json 的键**就是** `CMD_EMOTICONS.columns`
    /// 里每个 `Col.key`(含 `Fmt::Hidden` 的 —— 那只藏 table 不藏 json, 真跑核过)。所以对拍就是比
    /// "热查 `emoticon_json` 的键" vs "引擎命令声明的列 key" —— 抄漏一个键, 热查就跟冷查引擎对不上, 而
    /// 两边各自的测试都照绿(引擎那边根本没有键断言)。
    #[test]
    fn emoticons_hot_keys_match_cold_engine_columns() {
        // 冷查引擎会出的键 = CMD_EMOTICONS 每列的 key(Hidden 的 cdn_url 也出 json)。
        let mut cold_keys: Vec<&str> = crate::CMD_EMOTICONS.columns.iter().map(|c| c.key).collect();
        cold_keys.sort_unstable();

        // 热查一行经 emoticon_json 后的键。
        let hot = super::emoticon_json(&native_core::QueriedEmoticon {
            caption: "笑哭".into(),
            md5: "abc123".into(),
            emoticon_type: 3,
            product_id: String::new(),
            cdn_url: "http://x/y".into(),
        });
        let mut hot_keys: Vec<&str> = hot.as_object().unwrap().keys().map(String::as_str).collect();
        hot_keys.sort_unstable();

        assert_eq!(
            hot_keys, cold_keys,
            "热查 json 键必须与冷查引擎 CMD_EMOTICONS 的列 key 一字不差 —— 冷 {cold_keys:?} vs 热 {hot_keys:?}"
        );
        // 钉死具体键名 + cdn_url 在里面(免"两边一起漏"仍绿)。
        assert_eq!(
            hot_keys,
            ["caption", "cdn_url", "emoticon_type", "md5", "product_id"],
            "5 键, cdn_url 必出(Fmt::Hidden 只藏 table)"
        );
    }

    /// **R16-2**: 热查 locations 的 `location_json` 键集必须与冷查引擎 `CMD_LOCATIONS` 的列 key 一字不差。
    ///
    /// registry 族命令(同 emoticons/avatars): 冷查 json 键 = `CMD_LOCATIONS.columns` 每个 `Col.key`,
    /// 热查键内联在 `location_json` —— 两份手抄清单, 任一侧增删/改名/typo, 冷 golden 只守冷侧、各自单测各自绿,
    /// 无并排断言则冷热字段集静默漂移(Claude d4b5921 P3)。lat/lng 冷 `Fmt::Float(5)` 只影响 table, json 出裸 f64。
    #[test]
    fn locations_hot_keys_match_cold_engine_columns() {
        // 冷查引擎会出的键 = CMD_LOCATIONS 每列的 key。
        let mut cold_keys: Vec<&str> = crate::CMD_LOCATIONS.columns.iter().map(|c| c.key).collect();
        cold_keys.sort_unstable();

        // 热查一行经 location_json 后的键(LocationCard 的 scale/poiid/maptype/adcode 不进 json → 冷查也不落)。
        let card = native_core::decoder::LocationCard {
            latitude: 30.123_45,
            longitude: 120.678_90,
            scale: 15,
            label: Some("某某路 1 号".into()),
            poiname: Some("某某广场".into()),
            poiid: Some("poi_x".into()),
            maptype: 0,
            adcode: Some("330100".into()),
            cityname: Some("杭州".into()),
        };
        let hot = super::location_json(1_700_000_000, "a@chatroom", &card);
        let mut hot_keys: Vec<&str> = hot.as_object().unwrap().keys().map(String::as_str).collect();
        hot_keys.sort_unstable();

        assert_eq!(
            hot_keys, cold_keys,
            "热查 location_json 键必须与冷查引擎 CMD_LOCATIONS 列 key 一字不差 —— 冷 {cold_keys:?} vs 热 {hot_keys:?}"
        );
        // 钉死具体键名(免"两边一起漏"仍绿); lat/lng 出 f64 数值非字符串。
        assert_eq!(
            hot_keys,
            [
                "cityname",
                "conv_id",
                "create_time",
                "label",
                "latitude",
                "longitude",
                "poiname"
            ],
            "7 键钉死(scale/poiid/maptype/adcode 冷查不落 → 热查不出)"
        );
        assert!(
            hot["latitude"].is_f64() && hot["longitude"].is_f64(),
            "lat/lng 出裸 f64"
        );
    }

    /// **R16-2**: 热查 cards 的 `card_json` 键集必须与冷查引擎 `CMD_CARDS` 的列 key 一字不差。
    ///
    /// registry 族命令(同 locations/emoticons)。**关键**: 冷查列 `card_open_im_desc` 的对外 key 是 `company`
    /// (非 `card_open_im_desc`), card_json 必须映到 `company` 才对齐 —— 这测就是钉住这层非直觉映射 + 防
    /// CardInfo 的 sex/province/city/sign/head 6 个多余字段漏进 json。
    #[test]
    fn cards_hot_keys_match_cold_engine_columns() {
        // 冷查引擎会出的键 = CMD_CARDS 每列的 key。
        let mut cold_keys: Vec<&str> = crate::CMD_CARDS.columns.iter().map(|c| c.key).collect();
        cold_keys.sort_unstable();

        // 热查一行经 card_json 后的键(CardInfo 的 sex/province/city/sign/big_head_url/small_head_url 不进 json)。
        let card = native_core::decoder::CardInfo {
            username: "v3_abc".into(),
            sex: 1,
            nickname: Some("小王".into()),
            alias: Some("wangxiao".into()),
            province: Some("Zhejiang".into()),
            city: Some("Taizhou".into()),
            sign: Some("努力".into()),
            open_im_desc: Some("某某科技".into()),
            big_head_url: Some("http://x/0".into()),
            small_head_url: Some("http://x/1".into()),
        };
        let hot = super::card_json(1_700_000_000, "a@chatroom", &card);
        let mut hot_keys: Vec<&str> = hot.as_object().unwrap().keys().map(String::as_str).collect();
        hot_keys.sort_unstable();

        assert_eq!(
            hot_keys, cold_keys,
            "热查 card_json 键必须与冷查引擎 CMD_CARDS 列 key 一字不差 —— 冷 {cold_keys:?} vs 热 {hot_keys:?}"
        );
        // 钉死具体键名(免"两边一起漏"仍绿); company 映到 open_im_desc。
        assert_eq!(
            hot_keys,
            [
                "card_alias",
                "card_nickname",
                "card_username",
                "company",
                "conv_id",
                "create_time"
            ],
            "6 键钉死(sex/province/city/sign/head 冷查不落; company←open_im_desc)"
        );
        assert_eq!(
            hot["company"],
            serde_json::json!("某某科技"),
            "company 必取 CardInfo.open_im_desc"
        );
    }

    /// **R16-2**: 热查 media 的 `media_json` 键集必须与冷查引擎 `CMD_MEDIA` 的列 key 一字不差。
    ///
    /// registry 族命令(同 locations/cards)。**media_kind 出判别串**(as_str: image/video/emoji/voice, 非枚举);
    /// **cdn_url 冷查标 Fmt::Hidden 但出 json**(只藏 table, 同 emoticons); MediaCard 的 aes_key/thumb_url/extra_id
    /// 冷查 CMD_MEDIA 不露 → 热查不出。
    #[test]
    fn media_hot_keys_match_cold_engine_columns() {
        // 冷查引擎会出的键 = CMD_MEDIA 每列的 key(Hidden 的 cdn_url 也出 json)。
        let mut cold_keys: Vec<&str> = crate::CMD_MEDIA.columns.iter().map(|c| c.key).collect();
        cold_keys.sort_unstable();

        // 热查一行经 media_json 后的键(MediaCard 的 aes_key/thumb_url/extra_id 不进 json)。
        let card = native_core::decoder::MediaCard {
            media_kind: native_core::decoder::MediaKind::Video,
            md5: Some("abc123".into()),
            aes_key: Some("k".into()),
            cdn_url: Some("http://x/v".into()),
            thumb_url: Some("http://x/t".into()),
            file_size: 1024,
            play_length: 15,
            extra_id: Some("newmd5x".into()),
        };
        let hot = super::media_json(1_700_000_000, "a@chatroom", &card);
        let mut hot_keys: Vec<&str> = hot.as_object().unwrap().keys().map(String::as_str).collect();
        hot_keys.sort_unstable();

        assert_eq!(
            hot_keys, cold_keys,
            "热查 media_json 键必须与冷查引擎 CMD_MEDIA 列 key 一字不差 —— 冷 {cold_keys:?} vs 热 {hot_keys:?}"
        );
        // 钉死具体键名(免"两边一起漏"仍绿); media_kind 出判别串, cdn_url 出 json。
        assert_eq!(
            hot_keys,
            [
                "cdn_url",
                "conv_id",
                "create_time",
                "file_size",
                "md5",
                "media_kind",
                "play_length"
            ],
            "7 键钉死(aes_key/thumb_url/extra_id 冷查不露; cdn_url 必出即便 Fmt::Hidden)"
        );
        assert_eq!(
            hot["media_kind"],
            serde_json::json!("video"),
            "media_kind 出判别串 as_str 非枚举"
        );
    }

    /// **codex media P1**: 有界 [`TopN`] 的 top-(offset+limit) 必与"全收集再排序"逐行一致 + total 精确 + 保留集 ≤ need。
    /// 含同 create_time 不同 source 的 tie(靠 (source, source_native_id) 次键定序, 与冷查 order_by 一致)。
    #[test]
    fn topn_matches_full_sort_and_bounds_memory() {
        // (create_time, source, source_native_id, payload=序号)。故意乱序 + 同 ct 多 tie。
        let rows: [(i64, &str, &str, u32); 8] = [
            (100, "b", "1", 0),
            (100, "a", "2", 1),
            (200, "a", "1", 2),
            (50, "z", "9", 3),
            (200, "a", "2", 4),
            (150, "m", "5", 5),
            (100, "b", "0", 6),
            (200, "b", "1", 7),
        ];
        // 参考: 全收集 + 排序 DESC(create_time, source, source_native_id)。
        let mut full: Vec<(i64, &str, &str, u32)> = rows.to_vec();
        full.sort_by(|a, b| (b.0, b.1, b.2).cmp(&(a.0, a.1, a.2)));

        for (offset, limit) in [(0usize, 3usize), (2, 3), (0, 100), (5, 10), (0, 0)] {
            let mut top: TopN<u32> = TopN::new(offset, limit);
            for &(ct, src, snid, p) in &rows {
                top.offer(ct, src, snid, || p);
            }
            let (kept, total) = top.finish();
            assert_eq!(total, rows.len(), "total 恒精确 (全计数)");
            // 保留集 ≤ need (内存有界 —— 这条就是 codex P1 的修复保证)。
            assert!(
                kept.len() <= offset.saturating_add(limit),
                "保留 ≤ need, offset={offset} limit={limit}"
            );
            let got: Vec<u32> = kept.iter().skip(offset).take(limit).map(|k| k.payload).collect();
            let want: Vec<u32> = full.iter().skip(offset).take(limit).map(|r| r.3).collect();
            assert_eq!(got, want, "有界 top-N 必逐行等全排序, offset={offset} limit={limit}");
        }

        // codex 75dfce4 P1: 深翻页守卫 —— offset+limit 超 MAX_HOT_SCAN_WINDOW 必**拒**(不静默 clamp),
        // 否则堆随外部 offset 无界 = 重现 OOM。边界内 OK, 边界外(含 10M 深 offset)Err。
        assert!(check_hot_window(0, MAX_HOT_SCAN_WINDOW).is_ok(), "恰在窗口上限 OK");
        assert!(check_hot_window(MAX_HOT_SCAN_WINDOW, 1).is_err(), "超窗口 1 行必拒");
        assert!(
            check_hot_window(10_000_000, 200).is_err(),
            "10M 深 offset 必拒 (原 OOM 向量)"
        );
    }

    /// **R16-1**: 热查 chatrooms 的 `chatroom_json` 键集必须与冷查引擎 `CMD_CHATROOMS` 的列 key 一字不差。
    #[test]
    fn chatrooms_hot_keys_match_cold_engine_columns() {
        let mut cold_keys: Vec<&str> = crate::CMD_CHATROOMS.columns.iter().map(|c| c.key).collect();
        cold_keys.sort_unstable();
        let hot = super::chatroom_json(&native_core::QueriedChatroom {
            chatroom_id: "a@chatroom".into(),
            chatroom_name: "群".into(),
            owner_wxid: Some("wxid_a".into()),
            member_count: 3,
            announcement: None,
        });
        let mut hot_keys: Vec<&str> = hot.as_object().unwrap().keys().map(String::as_str).collect();
        hot_keys.sort_unstable();
        assert_eq!(
            hot_keys, cold_keys,
            "热查 chatroom_json 键必须与冷查引擎 CMD_CHATROOMS 列 key 一字不差 —— 冷 {cold_keys:?} vs 热 {hot_keys:?}"
        );
        assert_eq!(
            hot_keys,
            [
                "announcement",
                "chatroom_id",
                "chatroom_name",
                "member_count",
                "owner_wxid"
            ],
            "5 键钉死"
        );
    }

    /// **R16-1**: 热查 avatars 的 `avatar_json` 键集必须与冷查引擎 `CMD_AVATARS` 的列 key 一字不差。
    #[test]
    fn avatars_hot_keys_match_cold_engine_columns() {
        let mut cold_keys: Vec<&str> = crate::CMD_AVATARS.columns.iter().map(|c| c.key).collect();
        cold_keys.sort_unstable();
        let hot = super::avatar_json(&native_core::QueriedAvatar {
            username: "wxid_a".into(),
            md5: "abc".into(),
            update_time: 1_700_000_000,
        });
        let mut hot_keys: Vec<&str> = hot.as_object().unwrap().keys().map(String::as_str).collect();
        hot_keys.sort_unstable();
        assert_eq!(
            hot_keys, cold_keys,
            "热查 avatar_json 键必须与冷查引擎 CMD_AVATARS 列 key 一字不差 —— 冷 {cold_keys:?} vs 热 {hot_keys:?}"
        );
        assert_eq!(hot_keys, ["md5", "update_time", "username"], "3 键钉死");
    }

    /// **R16-1**: 热查 biz-contacts 的 `biz_contact_json` 键集必须与冷查引擎 `CMD_BIZ_CONTACTS` 一字不差。
    /// **R16-5**: `BottomN`(`new` 专用, 保最小 N ASC)—— 冷 `new_query` (`rowid ASC LIMIT`, 前向追赶) 的热镜像。
    /// `hot_new` 把逻辑键 `(source, local_id)` 编码进 Keyed(ct=0/src=source/snid=零填充 local_id), 故这里用
    /// Keyed 键 (ct,src,snid) 直接测 BottomN 通用性质: ① 保**最小** `need` 条(非 TopN 的最大); ② 输出 **ASC**;
    /// ③ 同首键按次键 (src,snid) 破并列; ④ **满堆淘汰最大键**(Claude P3 补: heap 满后 offer 更小键要换掉集内最大)。
    #[test]
    fn bottomn_keeps_smallest_ascending_with_composite_tiebreak() {
        // ① 保最小 3 + ② ASC: 喂 ct 50/10/40/20/30, need=3 → 留 10/20/30 升序 (非 30/40/50 也非 DESC)。
        let mut b: super::BottomN<i64> = super::BottomN::new(3);
        for ct in [50_i64, 10, 40, 20, 30] {
            b.offer(ct, "msg", &format!("{ct:08x}"), || ct);
        }
        let (kept, total) = b.finish();
        assert_eq!(total, 5, "total 计全部喂入 (含落选)");
        let cts: Vec<i64> = kept.iter().map(|k| k.ct).collect();
        assert_eq!(cts, [10, 20, 30], "保最小 3 且 ASC (TopN 会给最大 3 DESC)");

        // ③ 并列首键(ct=100)按 (src, snid) ASC 破 + ④ **满堆淘汰最大键**: 喂 4 条 need=3, 堆满后第 4 条(更小键)
        //    须换掉集内最大 (msg1/zzz)。喂入序打乱以确保是键、非到达序决定去留。
        let mut b2: super::BottomN<char> = super::BottomN::new(3);
        b2.offer(100, "msg1", "zzz", || 'X'); // 最大键 → 满堆后应被淘汰
        b2.offer(100, "msg1", "bbb", || 'A');
        b2.offer(100, "msg0", "zzz", || 'B'); // src 更小 (msg0<msg1) → 应最前, 尽管 snid 最大
        b2.offer(100, "msg1", "aaa", || 'C'); // 第 4 条: 堆满(=3), 键 (msg1,aaa) < 集内最大 (msg1,zzz) → 换入, 挤掉 X
        let (kept2, total2) = b2.finish();
        assert_eq!(total2, 4, "total 计全部 4 条");
        let order: Vec<(&str, &str)> = kept2.iter().map(|k| (k.src.as_str(), k.snid.as_str())).collect();
        assert_eq!(
            order,
            [("msg0", "zzz"), ("msg1", "aaa"), ("msg1", "bbb")],
            "复合键 (src,snid) ASC 破并列 + 淘汰最大 (msg1,zzz)"
        );
    }

    /// **R16-6**: 热 search 子串命中 ASCII 大小写不敏感, 对齐冷 FTS/LIKE(SQLite 默认折叠 A-Z)。
    #[test]
    fn search_text_hit_ascii_case_insensitive() {
        // 小写 query 命中大写文本 (冷 FTS/LIKE 恒不敏感, 热须同; 修前 contains 字节精确会漏)。
        assert!(
            super::search_text_hit("Visit HTTP://x now", "http", true, "http"),
            "小写 http 应命中大写 HTTP"
        );
        // 大写 query 命中小写文本。
        assert!(
            super::search_text_hit("visit http://x", "HTTP", true, "http"),
            "大写 HTTP 应命中小写 http"
        );
        // 混合大小写互命中。
        assert!(
            super::search_text_hit("a HtTp mixed", "hTtP", true, "http"),
            "混合大小写互命中"
        );
        // 不含子串 → 不命中。
        assert!(
            !super::search_text_hit("only ftp here", "http", true, "http"),
            "不含子串不命中"
        );
        // 中文 query (无 ASCII 字母): 直接 contains, 中文无大小写。
        assert!(
            super::search_text_hit("报名填身份证号码", "身份证号", false, "身份证号"),
            "中文子串直接命中"
        );
        assert!(
            !super::search_text_hit("无关文本内容", "身份证号", false, "身份证号"),
            "中文不含不命中"
        );
    }

    #[test]
    fn biz_contacts_hot_keys_match_cold_engine_columns() {
        let mut cold_keys: Vec<&str> = crate::CMD_BIZ_CONTACTS.columns.iter().map(|c| c.key).collect();
        cold_keys.sort_unstable();
        let hot = super::biz_contact_json(&native_core::QueriedBizContact {
            user_name: "Bob".into(),
            user_id: "ww_b@qy".into(),
            brand_user_name: "gh_b".into(),
        });
        let mut hot_keys: Vec<&str> = hot.as_object().unwrap().keys().map(String::as_str).collect();
        hot_keys.sort_unstable();
        assert_eq!(hot_keys, cold_keys, "冷 {cold_keys:?} vs 热 {hot_keys:?}");
        assert_eq!(hot_keys, ["brand_user_name", "user_id", "user_name"], "3 键钉死");
    }

    /// **R16-1**: 热查 moments 的 `moment_json` 键集必须与冷查 `moments_query` 的 7 键一字不差。
    /// (冷查手写路径无 CMD 常量; 钉死键名, 冷查改列这测试同步改。)
    #[test]
    fn moments_hot_keys_match_cold() {
        // 冷查 moments_query 输出的 7 键 (handwritten.rs json!)。
        let cold_keys = [
            "author",
            "author_nickname",
            "comment_count",
            "content_desc",
            "create_time",
            "like_count",
            "media_count",
        ];
        let hot = super::moment_json(&native_core::QueriedMoment {
            author: "wxid_a".into(),
            author_nickname: Some("阿甲".into()),
            create_time: 1_700_000_000,
            content_desc: "今天天气不错".into(),
            media_count: 2,
            like_count: 5,
            comment_count: 3,
        });
        let obj = hot.as_object().unwrap();
        let mut hot_keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        hot_keys.sort_unstable();
        assert_eq!(
            hot_keys, cold_keys,
            "热查 moment_json 键必须与冷查 moments_query 一字不差"
        );
        // author_nickname 是 Option → 透传(可 null); create_time 出原始 i64。
        assert_eq!(obj["create_time"], 1_700_000_000_i64);
        assert_eq!(obj["author_nickname"], "阿甲");
    }

    /// **R16-1 (members 降级件)**: 热查 `member_json` 的键集必须与冷查 `members_query` 一字不差,
    /// 且 `joined_at` **恒 null** (源库 proto 无入群时刻, 决策②降级) —— 键在、值空, 不假装有。
    #[test]
    fn members_hot_keys_match_cold_and_joined_at_null() {
        // 冷查 members_query 输出的 5 键 (handwritten.rs: json!({member_wxid, display_name, role,
        // joined_at, invited_by}))。手写路径无 CMD 常量可反射 → 钉死键名 (冷查改列这测试同步改)。
        let cold_keys = ["display_name", "invited_by", "joined_at", "member_wxid", "role"];

        let hot = super::member_json(&native_core::QueriedMember {
            member_wxid: "wxid_x".into(),
            display_name: Some("小明".into()),
            role: "admin".into(),
            invited_by: Some("wxid_owner".into()),
        });
        let obj = hot.as_object().unwrap();
        let mut hot_keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        hot_keys.sort_unstable();
        assert_eq!(
            hot_keys, cold_keys,
            "热查 member_json 键必须与冷查 members_query 一字不差 —— 冷 {cold_keys:?} vs 热 {hot_keys:?}"
        );
        // 降级钉死: joined_at 必须是 JSON null (不是缺键、不是 0、不是空串)。
        assert_eq!(
            obj.get("joined_at"),
            Some(&serde_json::Value::Null),
            "joined_at 恒 null (源库无此字段, 决策②降级) —— 键在值空"
        );
        // 非降级字段原样透传 (不被降级逻辑误伤)。
        assert_eq!(obj["member_wxid"], "wxid_x");
        assert_eq!(obj["role"], "admin");
        assert_eq!(obj["invited_by"], "wxid_owner");
    }

    /// `resolve_message_dir`: 造 `<dir>/wxid_test_abfe/db_storage/message` → 能按 `wxid_test` 定位到。
    #[test]
    fn resolve_message_dir_finds_account() {
        let tmp = std::env::temp_dir().join("nq_msgdir_find");
        let _ = std::fs::remove_dir_all(&tmp);
        let msg = tmp.join("wxid_test_abfe").join("db_storage").join("message");
        std::fs::create_dir_all(&msg).unwrap();
        let wxid = Wxid::try_new("wxid_test").unwrap();
        let got = resolve_message_dir(tmp.to_str(), &wxid).unwrap();
        assert_eq!(got, msg, "从 <wxid>_<后缀> 账号目录定位到 db_storage/message");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 无匹配账号目录 → Err (AccountNotFound)。
    #[test]
    fn resolve_message_dir_errs_when_absent() {
        let tmp = std::env::temp_dir().join("nq_msgdir_absent");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let wxid = Wxid::try_new("wxid_nope").unwrap();
        assert!(
            resolve_message_dir(tmp.to_str(), &wxid).is_err(),
            "无匹配账号目录 → Err"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 账号目录在但缺 `db_storage/message` 子目录 → Err (不误命中账号根)。
    #[test]
    fn resolve_message_dir_errs_when_message_subdir_missing() {
        let tmp = std::env::temp_dir().join("nq_msgdir_nomsg");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("wxid_test_abfe").join("db_storage")).unwrap();
        let wxid = Wxid::try_new("wxid_test").unwrap();
        assert!(
            resolve_message_dir(tmp.to_str(), &wxid).is_err(),
            "账号目录在但缺 db_storage/message → Err"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `media_db_files`: 枚举 media_<N>.db 按 N 数值升序, 排除伴生 (-wal/-shm/.kvdb/.material) 与无关文件。
    #[test]
    fn media_db_files_enumerates_shards_numeric_sorted() {
        let tmp = std::env::temp_dir().join("nq_media_files");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        for f in [
            "media_0.db",
            "media_1.db",
            "media_10.db",
            "media_2.db", // media 目标 (含 2 vs 10 数值序)
            "message_0.db",
            "message_3.db", // message 分片 (prefix 泛化)
            "media_0.db-wal",
            "media_0.db-shm",
            "media_1.kvdb",
            "media_0.db-first.material",
            "message_fts.db",
            "message_resource.db",
            "other.db", // 非数字后缀 / 无关 → 排除
        ] {
            std::fs::write(tmp.join(f), b"x").unwrap();
        }
        let names = |v: Vec<std::path::PathBuf>| -> Vec<String> {
            v.iter()
                .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            names(media_db_files(&tmp)),
            vec!["media_0.db", "media_1.db", "media_2.db", "media_10.db"],
            "media: 只取 media_<N>.db 按 N 数值升序 (2 在 10 前), 排除伴生/无关"
        );
        assert_eq!(
            names(db_shard_files(&tmp, "message")),
            vec!["message_0.db", "message_3.db"],
            "message: 只取 message_<N>.db, 排除 message_fts/message_resource (非数字后缀)"
        );
        assert!(media_db_files(&tmp.join("nonexist")).is_empty(), "目录不存在 → 空");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `query_locator_path`: 显式路径原样; 缺省走临时目录按 wxid 命名。
    #[test]
    fn query_locator_path_explicit_vs_default() {
        let wxid = Wxid::try_new("wxid_abc").unwrap();
        assert_eq!(
            query_locator_path(Some("C:/x/loc.json"), &wxid),
            PathBuf::from("C:/x/loc.json"),
            "显式 --locator-file 原样用"
        );
        let def = query_locator_path(None, &wxid);
        assert!(
            def.to_str().unwrap().contains("wxquery_locator_wxid_abc"),
            "缺省走临时目录按 wxid 命名"
        );
    }

    /// `wxid_from_dir_name`: 带后缀切头; 裸 wxid 原样; 非 wxid_ → None。
    #[test]
    fn wxid_from_dir_name_strips_suffix() {
        assert_eq!(
            wxid_from_dir_name("wxid_abc_abfe").map(|w| w.as_str().to_string()),
            Some("wxid_abc".into())
        );
        assert_eq!(
            wxid_from_dir_name("wxid_abc").map(|w| w.as_str().to_string()),
            Some("wxid_abc".into())
        );
        assert_eq!(wxid_from_dir_name("Backup"), None);
    }
}
