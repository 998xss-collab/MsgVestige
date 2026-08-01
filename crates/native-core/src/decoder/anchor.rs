//! anchor — `source_native_id` 复合 md5 锚点合成 (raw-payload-输出格式.md §4 注 r3 P0-B 钉死).
//!
//! **R14(2026-07-16): id 类锚全 8hex→32hex**。旧格式取 md5 前 8 位(32bit), 几千会话千分之几撞键 →
//! L1 message `INSERT OR REPLACE` 静默覆盖丢消息(person 表早用完整 sha 免疫)。现全系统统一完整 32 位 md5
//! (真库实测 native md5(conv_id) 完整 == 微信 `Msg_` 表名逐字节一致, verify_anchor_hash.py)。契约走 ADR-412/413 supersede(R14 步 E)。
//!
//! `source_native_id` 是 5 元组幂等键之一 (account_id_sha, source, **source_native_id**, event_action,
//! event_seq), 同时进 ADR-413 fingerprint canonical. 它是【稳定内部锚点】: **即使开 --enable-plaintext
//! 也保持 md5/sha 复合格式**, 不暴露原始 wxid / chatroom_id 明文 (§3.y.5 例外 — 锚点不走 4 桶隐私过滤).
//!
//! ## 钉死格式 (按 (event_type, event_action), 跟主文档 §4 注 + §6.x + ADR-412 §3.x 严格对齐)
//! - message.create:                `Msg_<md5_hex(conv_id)>:<localId>`        ← [`msg_anchor`]
//! - contact_update.create:         `Contact_<md5_hex(username)>`             ← [`contact_anchor`]
//! - chatroom_update.create:        `Chatroom_<md5_hex(chatroom_id)>`         ← [`chatroom_anchor`]
//! - chatroom_update.member_add:    `md5_hex(chatroom_id_sha + ":member:" + member_wxid_sha)` ← [`member_anchor`]
//! - chatroom_update.member_remove: 同 member_add 格式 (用 sha 值参与 md5)
//!
//! ## K-R4 红线 (输入裸值 vs sha 值)
//! - msg / contact / chatroom anchor 吃【裸 id】(conv_id / username / chatroom_id), **内部** md5 哈希化 —
//!   这是锚点合成的本职 (§3.y.5 例外: 输出 md5_hex 不暴露裸值, 不可反推). 函数 **绝不 log 裸输入**.
//! - member anchor 吃【已脱敏 sha 值】(chatroom_id_sha / member_wxid_sha), 再整体 md5 — 双层不可逆.
//!
//! 锚点不可逆 (md5 单向) → 默认 sha 模式下 source_native_id 不能反推原始 wxid (跟 R5 默认 sha 红线一致).

/// 全 32 位 md5 hex — id 类锚点(会话/联系人/群/成员/系统事件)的哈希化基元。**R14: 全 32 位不截断**
/// (旧 `md5_8hex` 取前 8 位 = 32bit, 几千会话千分之几撞键 → L1 message `INSERT OR REPLACE` 静默覆盖丢消息;
/// 已删, 全系统统一完整 32 位; 真库实测 native md5(conv_id) 完整 == 微信 Msg_ 表名逐字节一致, 见 verify_anchor_hash.py)。
///
/// 入参可能是裸 id(conv_id/username/chatroom_id) 或已脱敏 sha 值 — 内部 md5 哈希化, 输出不含明文;
/// 函数**绝不 log** 入参(锚点合成统一无 IO; K-R4)。
fn md5_hex(s: &str) -> String {
    format!("{:x}", md5::compute(s.as_bytes()))
}

/// 某会话在源库里的**表名** `Msg_<md5_hex(conv_id)>`。
///
/// 与 [`msg_anchor`] 同一个 md5, 抽出来是为了让"只采一个会话"能**正着**算表名, 不必去读整张 `Name2Id`
/// 建反查表(ADR-508 D24; 真库 2.2 万会话时那一步约 16 秒)。
#[must_use]
pub fn msg_table_of(conv_id: &str) -> String {
    format!("Msg_{}", md5_hex(conv_id))
}

/// message.create 锚点: `Msg_<md5_hex(conv_id)>:<local_id>` (raw-payload §6.1 / ADR-412 §3.x.1).
///
/// `conv_id` 是【裸会话 id】(单聊=对方 UserName / 群=`xxx@chatroom`) — 内部 md5, 输出不含明文.
/// `local_id` 是源 db 整数主键 (定位用, 非 PII, 明文拼接). 不 log 裸 `conv_id`.
#[must_use]
pub fn msg_anchor(conv_id: &str, local_id: i64) -> String {
    format!("Msg_{}:{}", md5_hex(conv_id), local_id)
}

/// 同 [`msg_anchor`] 的锚点, 但从**已知的 `Msg_<32hex>` 表名 talker**(= `md5(conv_id)` 全 32 hex)算, 不需原始 conv_id。
/// R14: 用**完整 32 位 talker**(不再截断前 8 位), 与 `msg_anchor` 的 `md5_hex(conv_id)` 完整对齐 —— 真库实测
/// native `md5(conv_id)` 完整 == 微信表名逐字节一致(verify_anchor_hash.py: 15068 会话 14931 命中、0 前8对完整不对),
/// 故媒体侧(表名 talker)与消息侧(conv_id 算)的锚必逐字节相等。
/// R10 媒体入仓用: 从消息表名直接构 `media_reference.source_native_id` 与 L1 `message` 对齐(否则媒体引用连不上消息)。
///
/// `talker_hex` 传全 32 位 md5 hex(表名去 `Msg_` 前缀), 归一小写。
#[must_use]
pub fn msg_anchor_from_talker_hex(talker_hex: &str, local_id: i64) -> String {
    format!("Msg_{}:{local_id}", talker_hex.to_ascii_lowercase())
}

/// contact_update.create 锚点: `Contact_<md5_hex(username)>` (raw-payload §6.2 / ADR-412 §3.x.3).
///
/// `username` 是【裸联系人 UserName】 — 内部 md5, 输出不含明文. 不 log 裸 `username`.
#[must_use]
pub fn contact_anchor(username: &str) -> String {
    format!("Contact_{}", md5_hex(username))
}

/// session_update.create 锚点: `Session_<md5_hex(username)>`。
///
/// `username` 是【裸会话标识】(对方 UserName / 群 `@chatroom`) — 内部 md5, 输出不含明文。不 log 裸 `username`。
#[must_use]
pub fn session_anchor(username: &str) -> String {
    format!("Session_{}", md5_hex(username))
}

/// favorite_update.create 锚点: `Favorite_<local_id>` (ADR-454)。
///
/// `local_id` 是 favorite.db `fav_db_item` 本地 PK (整数, 非 PII) — 明文直拼 (同 msg_anchor 的 local_id 后缀)。
/// 收藏无天然敏感 key (fromusr 是内容不是身份键), 本地 PK 即稳定锚点。不 log。
#[must_use]
pub fn favorite_anchor(local_id: i64) -> String {
    format!("Favorite_{local_id}")
}

/// favorite_tag_update.create 锚点: `FavoriteTag_<tag_local_id>_<fav_local_id>` (ADR-454 §3.1 批 B-2;
/// **R16-3 后改用 local id**)。
///
/// 绑定身份 = (标签**本地** id, 收藏**本地** id) 两整数 (非 PII) — 明文直拼。同一绑定确定映射同锚点。不 log。
///
/// **⚠️为何用 local id 而非 server id**(codex fav_tags P1 根治): **未同步**的标签/收藏 `server_id=0` → 用 server id
/// 拼锚会让不同绑定塌成同锚 (`FavoriteTag_0_0`)、PK 撞、丢标签。favorite.db **单库不分片**(不像 message_N.db),
/// `local_id` 单库唯一、无跨分片重号 → 是真身份; 且收藏本体锚 [`favorite_anchor`] 早用 local_id, 本函数改 local id
/// 是**跟本体统一口径**。JOIN 取标签名也须同改 `ON t.local_id = b.tag_local_id`(否则 server_id=0 交叉 JOIN 误标)。
#[must_use]
pub fn favorite_tag_anchor(tag_local_id: i64, fav_local_id: i64) -> String {
    format!("FavoriteTag_{tag_local_id}_{fav_local_id}")
}

/// sns_event.create 锚点: `Sns_<tid>` (ADR-467 件1)。
///
/// `tid` 是 sns.db `SnsTimeLine` PK (= rowid 别名; 雪花 id 可为负; 非 wxid) — 明文直拼 (同 favorite_anchor 的
/// local_id 后缀; 动态无天然敏感 key, tid 即稳定锚点)。不 log。
#[must_use]
pub fn sns_anchor(tid: i64) -> String {
    format!("Sns_{tid}")
}

/// transfer_update.create 锚点: `Transfer_<transfer_id>` (ADR-468)。
///
/// `transfer_id` 是 general.db `transferTable` 的转账单号 (TEXT, 真库 100% 唯一; 非 wxid) — 明文直拼
/// (同 sns_anchor 的 tid 后缀; 转账无天然敏感 key, 单号即稳定锚点)。不 log。
#[must_use]
pub fn transfer_anchor(transfer_id: &str) -> String {
    format!("Transfer_{transfer_id}")
}

/// red_envelope_update.create 锚点: `RedEnvelope_<send_id>` (ADR-468 件2)。
///
/// `send_id` 是 general.db `redEnvelopeTable` 的红包单号 (TEXT, 真库 100% 唯一; 非 wxid) — 明文直拼
/// (同 transfer_anchor; 红包无天然敏感 key, 单号即稳定锚点)。不 log。
#[must_use]
pub fn red_envelope_anchor(send_id: &str) -> String {
    format!("RedEnvelope_{send_id}")
}

/// group_pay_update.create 锚点: `GroupPay_<bill_no>` (ADR-468 件3)。
///
/// `bill_no` 是 general.db `groupPayTable` 的账单号 (TEXT 96hex, 真库 100% 唯一; 非 wxid) — 明文直拼
/// (同 transfer_anchor)。不 log。
#[must_use]
pub fn group_pay_anchor(bill_no: &str) -> String {
    format!("GroupPay_{bill_no}")
}

/// friend_verify_update.create 锚点: `FMessage_<md5_hex(user_name)>` (ADR-469)。
///
/// `user_name` 是【裸好友 wxid】(general.db `FMessageTable`, 真库 100% 唯一) — 内部 md5, 输出不含明文
/// (同 contact_anchor)。不 log 裸 `user_name`。
#[must_use]
pub fn friend_verify_anchor(user_name: &str) -> String {
    format!("FMessage_{}", md5_hex(user_name))
}

/// finder_visit_update.create 锚点: `Finder_<md5_hex(owner_username)>` (视频号号主 id → 内部 md5; ADR-473)。
#[must_use]
pub fn finder_anchor(owner_username: &str) -> String {
    format!("Finder_{}", md5_hex(owner_username))
}

/// moment_feed_update.create 锚点: `MomentFeed_<tid>` (tid 是雪花动态 id, 非 PII 直用; 真库唯一定位; ADR-474)。
#[must_use]
pub fn moment_feed_anchor(tid: i64) -> String {
    format!("MomentFeed_{tid}")
}

/// sns_notify_update.create 锚点: `SnsNotify_<local_id>` (SnsMessage_tmp3.local_id=rowid, 每通知唯一; 非 PII 直用)。
/// ⚠️ **用 local_id 不用 comment_id** —— comment_id 不唯一 (真库一 comment_id 对多通知, 688 行会塌到 98);
/// local_id 是行自身唯一 id。照 moment_feed ADR-474 (它用 tid 稳定唯一)。
#[must_use]
pub fn sns_notify_anchor(local_id: i64) -> String {
    format!("SnsNotify_{local_id}")
}

/// custom_emoticon_update.create 锚点: `Emoticon_<md5>` (md5 是表情内容哈希, 非 PII 直用; 真库唯一定位; ADR-478)。
#[must_use]
pub fn emoticon_anchor(md5: &str) -> String {
    format!("Emoticon_{md5}")
}

/// biz_chat_contact_update.create 锚点: `BizUser_<md5_hex(user_id)>` (企微 wxid → 内部 md5; ADR-482)。
///
/// `user_id` 是【裸企微 wxid】(bizchat.db `user_info`, 真库唯一) — 内部 md5, 输出不含明文
/// (照 finder/contact anchor; user_id 是 PII 故哈希, 非 emoticon md5 直用)。不 log 裸 `user_id`。
#[must_use]
pub fn bizchat_anchor(user_id: &str) -> String {
    format!("BizUser_{}", md5_hex(user_id))
}

/// avatar_image_update.create 锚点: `Avatar_<md5_hex(username)>` (联系人 id → 内部 md5; 永不含裸 wxid; ADR-481)。
///
/// 一联系人一当前头像行 (head_image.db); 换头像 md5 变 → digest 新 fingerprint, 但 anchor 稳定 (同一联系人)。
#[must_use]
pub fn avatar_anchor(username: &str) -> String {
    format!("Avatar_{}", md5_hex(username))
}

/// chatroom_update.create 锚点: `Chatroom_<md5_hex(chatroom_id)>` (raw-payload §6.3 / ADR-412 §3.x.3).
///
/// `chatroom_id` 是【裸群 id】(`xxx@chatroom`) — 内部 md5, 输出不含明文. 不 log 裸 `chatroom_id`.
#[must_use]
pub fn chatroom_anchor(chatroom_id: &str) -> String {
    format!("Chatroom_{}", md5_hex(chatroom_id))
}

/// chatroom_update.member_add / member_remove 锚点 (raw-payload §6.4/§6.5 / ADR-412 §3.x.4/§3.x.5).
///
/// 格式: `md5_hex(chatroom_id_sha + ":member:" + member_wxid_sha)` — 全 32 位 md5 hex.
/// **入参是已脱敏 sha 值** (非裸 wxid; K-R4 KI-7): 群 sha + 成员 wxid sha 用 `":member:"` 拼接再整体 md5.
/// member_add / member_remove 共用本格式 (alpha 稳定锚点钉死). 入参已脱敏, 但函数仍不 log.
#[must_use]
pub fn member_anchor(chatroom_id_sha: &str, member_wxid_sha: &str) -> String {
    md5_hex(&format!("{chatroom_id_sha}:member:{member_wxid_sha}"))
}

/// system_event.cursor_update 锚点: `cursor:<db>:<kind>:<md5_hex(watermark)>` (raw-payload §6.6 / ADR-412 §3.x.6).
///
/// `db` (源 db 文件名) / `kind` (事件类, e.g. "message") 是【元数据】明文直拼 (非 PII); `watermark`
/// (游标值, 可能含敏感序号/时间组合) 经 `md5_hex` 哈希. 不 log 裸 `watermark`.
#[must_use]
pub fn cursor_anchor(db: &str, kind: &str, watermark: &str) -> String {
    format!("cursor:{db}:{kind}:{}", md5_hex(watermark))
}

/// system_event.error 锚点: `error:<error_code>:<md5_hex(context)>` (raw-payload §6.7 / ADR-412 §3.x.7).
///
/// `error_code` (错误码枚举, e.g. "ZSTD_FAIL") 是【元数据】明文直拼 (非 PII); `context` (错误上下文,
/// 可能含 wxid/路径等敏感) 经 `md5_hex` 哈希. 不 log 裸 `context`.
#[must_use]
pub fn error_anchor(error_code: &str, context: &str) -> String {
    format!("error:{error_code}:{}", md5_hex(context))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 已知 md5 向量 (RFC 1321 / 通用测试集): md5("") = d41d8cd98f00b204e9800998ecf8427e.
    const MD5_EMPTY: &str = "d41d8cd98f00b204e9800998ecf8427e";
    // md5("abc") = 900150983cd24fb0d6963f7d28e17f72.
    const MD5_ABC: &str = "900150983cd24fb0d6963f7d28e17f72";

    /// md5_hex 全 32 位小写 hex, 对齐已知向量 (空串 + "abc").
    #[test]
    fn md5_hex_matches_known_vectors() {
        assert_eq!(md5_hex(""), MD5_EMPTY);
        assert_eq!(md5_hex("abc"), MD5_ABC);
        assert_eq!(md5_hex("abc").len(), 32, "全 32 hex");
        assert!(
            md5_hex("abc")
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "小写 hex"
        );
    }

    /// message 锚点格式: Msg_<md5_hex(conv_id)>:<localId>; conv_id 经 md5 不暴露明文.
    #[test]
    fn msg_anchor_format() {
        // conv_id="abc" → md5_hex(完整32位)=MD5_ABC; local_id=86680 明文拼接.
        assert_eq!(msg_anchor("abc", 86680), format!("Msg_{MD5_ABC}:86680"));
        let a = msg_anchor("wxid_friend@chatroom", 1);
        assert!(a.starts_with("Msg_"), "Msg_ 前缀");
        assert!(a.ends_with(":1"), "localId 明文后缀");
        assert!(!a.contains("wxid_friend"), "K-R4: 裸 conv_id 不出现在锚点");
    }

    /// 负 / 0 / i64::MAX localId 都原样明文拼 (源 db 主键定位, 非 PII).
    #[test]
    fn msg_anchor_local_id_edge() {
        assert_eq!(msg_anchor("abc", 0), format!("Msg_{MD5_ABC}:0"));
        assert_eq!(msg_anchor("abc", -1), format!("Msg_{MD5_ABC}:-1"));
        assert_eq!(msg_anchor("abc", i64::MAX), format!("Msg_{MD5_ABC}:{}", i64::MAX));
    }

    /// contact 锚点格式: Contact_<md5_hex(username)>; username 经 md5 不暴露.
    #[test]
    fn contact_anchor_format() {
        assert_eq!(contact_anchor("abc"), format!("Contact_{MD5_ABC}"));
        let a = contact_anchor("wxid_xiaoming");
        assert!(a.starts_with("Contact_"));
        assert_eq!(a.len(), "Contact_".len() + 32, "前缀 + 32 hex");
        assert!(!a.contains("wxid_xiaoming"), "K-R4: 裸 username 不出现");
    }

    /// sns 锚点格式: Sns_<tid> (tid 明文直拼; 负值也原样, 非 PII)。
    #[test]
    fn sns_anchor_format() {
        assert_eq!(sns_anchor(123), "Sns_123");
        assert_eq!(
            sns_anchor(-3_518_821_952_372_526_549),
            "Sns_-3518821952372526549",
            "负 tid 原样"
        );
        assert_eq!(sns_anchor(0), "Sns_0");
        assert_eq!(sns_anchor(5), sns_anchor(5), "确定性");
        assert_ne!(sns_anchor(1), sns_anchor(2), "不同 tid 区分");
    }

    /// sns_notify 锚点格式: SnsNotify_<comment_id> (通知 id 明文直拼; 负值也原样, 非 PII)。
    #[test]
    fn sns_notify_anchor_format() {
        assert_eq!(sns_notify_anchor(123_456_789), "SnsNotify_123456789");
        assert_eq!(sns_notify_anchor(0), "SnsNotify_0");
        assert_eq!(sns_notify_anchor(-1), "SnsNotify_-1", "负 local_id 原样");
        assert_eq!(sns_notify_anchor(5), sns_notify_anchor(5), "确定性");
        assert_ne!(sns_notify_anchor(1), sns_notify_anchor(2), "不同 local_id 区分");
    }

    /// transfer 锚点格式: Transfer_<transfer_id> (单号明文直拼; 非 wxid)。
    #[test]
    fn transfer_anchor_format() {
        assert_eq!(
            transfer_anchor("1000050001202507100225413996557"),
            "Transfer_1000050001202507100225413996557"
        );
        assert_eq!(transfer_anchor("abc"), "Transfer_abc");
        assert_eq!(transfer_anchor("x"), transfer_anchor("x"), "确定性");
        assert_ne!(transfer_anchor("a"), transfer_anchor("b"), "不同单号区分");
    }

    /// red_envelope 锚点格式: RedEnvelope_<send_id> (单号明文直拼; 非 wxid)。
    #[test]
    fn red_envelope_anchor_format() {
        assert_eq!(
            red_envelope_anchor("1000039801202604206261068705009"),
            "RedEnvelope_1000039801202604206261068705009"
        );
        assert_eq!(red_envelope_anchor("abc"), "RedEnvelope_abc");
        assert_ne!(red_envelope_anchor("a"), red_envelope_anchor("b"), "不同单号区分");
    }

    /// group_pay 锚点格式: GroupPay_<bill_no> (账单号明文直拼; 非 wxid)。
    #[test]
    fn group_pay_anchor_format() {
        assert_eq!(group_pay_anchor("694a900673c1"), "GroupPay_694a900673c1");
        assert_ne!(group_pay_anchor("a"), group_pay_anchor("b"), "不同账单号区分");
    }

    /// friend_verify 锚点格式: FMessage_<md5_hex(user_name)>; user_name 经 md5 不暴露明文。
    #[test]
    fn friend_verify_anchor_format() {
        assert_eq!(friend_verify_anchor("abc"), format!("FMessage_{MD5_ABC}"));
        let a = friend_verify_anchor("wxid_friend");
        assert!(a.starts_with("FMessage_"));
        assert_eq!(a.len(), "FMessage_".len() + 32, "前缀 + 32 hex");
        assert!(!a.contains("wxid_friend"), "K-R4: 裸 user_name 不出现");
    }

    /// bizchat 锚点格式: BizUser_<md5_hex(user_id)>; user_id (企微 wxid, PII) 经 md5 不暴露明文。
    #[test]
    fn bizchat_anchor_format() {
        assert_eq!(bizchat_anchor("abc"), format!("BizUser_{MD5_ABC}"));
        let a = bizchat_anchor("ww16xxxxxxxxxxxxxxxxxxx");
        assert!(a.starts_with("BizUser_"));
        assert_eq!(a.len(), "BizUser_".len() + 32, "前缀 + 32 hex");
        assert!(!a.contains("ww16"), "K-R4: 裸 user_id 不出现");
        assert_ne!(bizchat_anchor("a"), bizchat_anchor("b"), "不同 user_id 区分");
    }

    /// chatroom 锚点格式: Chatroom_<md5_hex(chatroom_id)>; chatroom_id 经 md5 不暴露.
    #[test]
    fn chatroom_anchor_format() {
        assert_eq!(chatroom_anchor("abc"), format!("Chatroom_{MD5_ABC}"));
        let a = chatroom_anchor("12345678@chatroom");
        assert!(a.starts_with("Chatroom_"));
        assert_eq!(a.len(), "Chatroom_".len() + 32);
        assert!(!a.contains("@chatroom"), "K-R4: 裸 chatroom_id 不出现");
    }

    /// member 锚点: md5_hex(chatroom_id_sha + ":member:" + member_wxid_sha), 全 32 hex.
    /// K-R4 KI-7: 入参是 sha 值 — 锚点用 sha 拼接, 等同对 "<a>:member:<b>" 整体 md5.
    #[test]
    fn member_anchor_uses_sha_values() {
        let room_sha = "aabbccdd"; // 群 sha (脱敏值)
        let mem_sha = "11223344"; // 成员 wxid sha (脱敏值)
        let got = member_anchor(room_sha, mem_sha);
        // 等同对拼接串整体 md5 (验合成逻辑 = md5_hex of "<room_sha>:member:<mem_sha>").
        assert_eq!(got, md5_hex("aabbccdd:member:11223344"));
        assert_eq!(got.len(), 32, "全 32 hex");
        assert!(got.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 全部锚点确定性: 同输入 → 同输出 (5 元组幂等键 + fingerprint canonical 依赖确定性).
    #[test]
    fn anchors_are_deterministic() {
        assert_eq!(msg_anchor("conv_x", 42), msg_anchor("conv_x", 42));
        assert_eq!(contact_anchor("wxid_z"), contact_anchor("wxid_z"));
        assert_eq!(chatroom_anchor("room@chatroom"), chatroom_anchor("room@chatroom"));
        assert_eq!(member_anchor("rs", "ms"), member_anchor("rs", "ms"));
    }

    /// 不同输入 → 不同锚点 (避免幂等键碰撞吞事件 — PoC-1 3 元组 UNIQUE 反模式).
    #[test]
    fn distinct_inputs_distinct_anchors() {
        assert_ne!(msg_anchor("a", 1), msg_anchor("b", 1), "conv_id 区分");
        assert_ne!(msg_anchor("a", 1), msg_anchor("a", 2), "local_id 区分");
        assert_ne!(contact_anchor("a"), contact_anchor("b"));
        assert_ne!(chatroom_anchor("a"), chatroom_anchor("b"));
        // member: 群相同成员不同 / 成员相同群不同 都得区分.
        assert_ne!(member_anchor("r", "m1"), member_anchor("r", "m2"));
        assert_ne!(member_anchor("r1", "m"), member_anchor("r2", "m"));
    }

    /// member_add / member_remove 共用同格式 → 同 (room_sha, member_sha) 给同锚点
    /// (退群再入用 event_action 区分, 不靠 source_native_id; KI-7 钉死).
    #[test]
    fn member_add_remove_share_anchor() {
        // 两次调用代表 add 与 remove 各取一次, 锚点相同 (action 在 5 元组另一维区分).
        assert_eq!(
            member_anchor("room_sha", "mem_sha"),
            member_anchor("room_sha", "mem_sha")
        );
    }

    /// cursor 锚点: cursor:<db>:<kind>:<md5_hex(watermark)>; db/kind 明文, watermark 哈希.
    #[test]
    fn cursor_anchor_format() {
        // watermark="abc" → md5_hex(完整)=MD5_ABC; db/kind 明文直拼.
        assert_eq!(
            cursor_anchor("message_0.db", "message", "abc"),
            format!("cursor:message_0.db:message:{MD5_ABC}")
        );
        let a = cursor_anchor("m.db", "message", "secret_watermark_xyz");
        assert!(a.starts_with("cursor:m.db:message:"), "db/kind 明文");
        assert!(!a.contains("secret_watermark"), "K-R4: 裸 watermark 不出现 (经 md5)");
    }

    /// error 锚点: error:<error_code>:<md5_hex(context)>; error_code 明文, context 哈希.
    #[test]
    fn error_anchor_format() {
        assert_eq!(error_anchor("ZSTD_FAIL", "abc"), format!("error:ZSTD_FAIL:{MD5_ABC}"));
        let a = error_anchor("DECODE_FAIL", "wxid_victim:/secret/path");
        assert!(a.starts_with("error:DECODE_FAIL:"), "error_code 明文");
        assert!(!a.contains("wxid_victim"), "K-R4: 裸 context 不出现 (经 md5)");
    }

    /// cursor/error 锚点确定性 + 区分.
    #[test]
    fn cursor_error_deterministic_and_distinct() {
        assert_eq!(cursor_anchor("d", "k", "w"), cursor_anchor("d", "k", "w"));
        assert_eq!(error_anchor("c", "x"), error_anchor("c", "x"));
        assert_ne!(cursor_anchor("d1", "k", "w"), cursor_anchor("d2", "k", "w"), "db 区分");
        assert_ne!(
            cursor_anchor("d", "k", "w1"),
            cursor_anchor("d", "k", "w2"),
            "watermark 区分"
        );
        assert_ne!(error_anchor("c1", "x"), error_anchor("c2", "x"), "code 区分");
    }
}
