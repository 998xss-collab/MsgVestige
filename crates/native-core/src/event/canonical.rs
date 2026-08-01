//! event::canonical — content_digest 输入字段提取 (ADR-413 content_digest 的 canonical_raw_values).
//!
//! 本 mod = PR2-3-j: 给 [`DecodedEvent`] 抽【content_digest 输入 map】, 喂 [`super::fingerprint::content_digest`].
//!
//! ## 字段集规则 (recon 对齐 ADR-412 §3.x line 238/242 + ADR-413 §3 line 129)
//! content_digest 字段 = ADR-412 §3.x 各事件"进 content_digest = 是"列中【非 provenance + 非临时】业务字段:
//! - **排 provenance** (account_id_sha / source / source_native_id / event_action 等进【外层 canonical_bytes】, 不重复)
//! - **排临时字段** (create_time / status / sort_seq / decode_kind / joined_at / left_at / last_update — 随重读变)
//!
//! ## 值约定 (跟 ADR-413 §3.y 向量一致, 隐私模式无关)
//! - **id 类**: 键 `{base}_sha`, 值 = `sha256_hex(原始 id)` (永不裸 wxid)
//! - **display / text 类**: 键 `{base}` (无后缀), 值 = **原文 raw** (e.g. 真昵称 / 真正文 — content_digest 内部用原值)
//! - **元数据类**: 键 `{base}`, 值 = 原生 (string / i32 / i64 / bool)
//! - **nullable**: None → 该键值 `null` (字段集稳定, 跨事件可比)

use std::collections::BTreeMap;

use serde_json::Value;

use super::decoded::DecodedEvent;
use super::privacy::sha256_hex;

/// id 类 nullable 字段 → `sha256_hex` 值 (None → null).
fn opt_id_sha(raw: Option<&str>) -> Value {
    raw.map_or(Value::Null, |s| Value::from(sha256_hex(s)))
}

/// display / text 类 nullable 字段 → 原文 raw (None → null).
fn opt_raw(raw: Option<&str>) -> Value {
    raw.map_or(Value::Null, Value::from)
}

/// content_digest 的**唯一合法输入** (ADR-426 §2.7.3 fingerprint 接口隔离)。
///
/// 私有字段 + 生产构造入口**仅** [`canonical_raw_values`] (接 [`DecodedEvent`]) → projection/storage
/// 的 `V3*` 类型在**编译期无法构造**本类型 → 不可能污染 content_digest 输入 (ADR-413 钉死值约定隐私无关:
/// id→sha / display·text→raw 原文; 业务表存 sha/明文与 fingerprint 解耦)。`content_digest` 经
/// [`Self::to_canonical_json`] 读内容。
pub struct CanonicalRawValues(BTreeMap<String, Value>);

impl CanonicalRawValues {
    /// 序列化为 canonical JSON 字节 (字典序 + compact + UTF-8 不转义; 喂 content_digest 哈希)。
    #[must_use]
    pub fn to_canonical_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("BTreeMap<String, Value> 序列化不会失败")
    }

    /// 测试专用构造 — 手构 map 验 content_digest 跨语言 golden 向量。
    /// **仅 `#[cfg(test)]`**: 生产代码 (含 projection/storage) 无此入口 → 编译期隔离不破。
    #[cfg(test)]
    #[must_use]
    pub fn from_map_for_test(map: BTreeMap<String, Value>) -> Self {
        Self(map)
    }
}

// cfg(test): 测试直接把 canonical_raw_values 产物当 BTreeMap 读 (索引 / len / contains_key) — 验字段集。
// 生产代码【无】 Deref → 仍只能经 to_canonical_json 用, 不暴露内部 map, 编译期隔离不破。
#[cfg(test)]
impl std::ops::Deref for CanonicalRawValues {
    type Target = BTreeMap<String, Value>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// 取事件的 content_digest 输入 ([`CanonicalRawValues`]; ADR-413: content_digest = SHA-256(其 canonical JSON)).
///
/// 字段集 = ADR-412 §3.x 各事件"进 content_digest = 是"列【非 provenance + 非临时】业务字段 (见 mod 文档规则).
#[must_use]
pub fn canonical_raw_values(event: &DecodedEvent) -> CanonicalRawValues {
    let mut m = BTreeMap::new();
    match event {
        // §3.x.1: conv_id_sha / sender_wxid_sha (id) + server_id / msg_type / msg_sub_type (元数据) + text_content (text).
        //
        // ⚠️ **传输状态列故意不进指纹**(用户 2026-07-27 拍板, ADR-508 D25): `status` / `upload_status` /
        // `download_status` / `sort_seq` / `server_seq` / `origin_source` / `local_type_raw` 会随消息生命周期
        // 变(发送中→已送达→已读), 而 archive 是 `INSERT OR IGNORE` —— 纳入指纹的话同一条消息每变一次状态
        // 就多一条 archive 记录, 全量库百万级会涨到千万级, 换来的却是分析价值极低的传输状态历史。
        //
        // **代价说清楚**: 于是 `archive` 记的是"**首次观测**到的那个版本", 而 `message` 表(覆盖写)记的是
        // **最新**状态 —— 两者在这几列上会不一致, 这是**设计如此**, 不是 bug。sink 文档里"L2 是可重放重建的
        // 物化视图"因此收窄成: **重放能重建除这几个传输状态列之外的一切**。有守卫测试钉住这条(见下方
        // `mutable_transport_columns_stay_out_of_digest`), 谁想把它们加进来会先撞到那条测试。
        DecodedEvent::Message(e) => {
            m.insert("conv_id_sha".into(), Value::from(sha256_hex(&e.conv_id)));
            m.insert(
                "sender_wxid_sha".into(),
                Value::from(sha256_hex(e.sender_wxid.as_str())),
            );
            m.insert("server_id".into(), Value::from(e.server_id.as_str()));
            m.insert("msg_type".into(), Value::from(e.msg_type));
            m.insert("msg_sub_type".into(), e.msg_sub_type.map_or(Value::Null, Value::from));
            m.insert("text_content".into(), Value::from(e.text_content.as_str()));
        }
        // §3.x.2: username_sha (id) + nick_name / remark / alias (display) + local_type / is_in_chat_room /
        //         verify_flag / delete_flag (元数据). verify/delete 独立状态 → 进 digest 溯源 (字段集 8, 第二批 supersede ADR-412)。
        DecodedEvent::ContactUpdate(e) => {
            m.insert("username_sha".into(), Value::from(sha256_hex(&e.username)));
            m.insert("nick_name".into(), Value::from(e.nick_name.as_str()));
            m.insert("remark".into(), opt_raw(e.remark.as_deref()));
            m.insert("alias".into(), opt_raw(e.alias.as_deref()));
            m.insert("local_type".into(), Value::from(e.local_type));
            m.insert("is_in_chat_room".into(), Value::from(e.is_in_chat_room));
            m.insert("verify_flag".into(), Value::from(e.verify_flag));
            m.insert("delete_flag".into(), Value::from(e.delete_flag));
        }
        // §3.x.3: chatroom_id_sha / owner_wxid_sha (id) + chatroom_name / announcement (display) + member_count (元数据).
        DecodedEvent::ChatroomCreate(e) => {
            m.insert("chatroom_id_sha".into(), Value::from(sha256_hex(&e.chatroom_id)));
            m.insert("chatroom_name".into(), Value::from(e.chatroom_name.as_str()));
            m.insert("announcement".into(), opt_raw(e.announcement.as_deref()));
            m.insert("owner_wxid_sha".into(), opt_id_sha(e.owner_wxid.as_deref()));
            m.insert("member_count".into(), Value::from(e.member_count));
        }
        // §3.x.4: chatroom_id_sha / member_wxid_sha (id) + display_name (display). joined_at 临时不进.
        DecodedEvent::ChatroomMemberAdd(e) => {
            m.insert("chatroom_id_sha".into(), Value::from(sha256_hex(&e.chatroom_id)));
            m.insert("member_wxid_sha".into(), Value::from(sha256_hex(&e.member_wxid)));
            m.insert("display_name".into(), opt_raw(e.display_name.as_deref()));
        }
        // §3.x.5: chatroom_id_sha / member_wxid_sha (id). left_at 临时不进.
        DecodedEvent::ChatroomMemberRemove(e) => {
            m.insert("chatroom_id_sha".into(), Value::from(sha256_hex(&e.chatroom_id)));
            m.insert("member_wxid_sha".into(), Value::from(sha256_hex(&e.member_wxid)));
        }
        // session_update: username_sha (id) + summary / last_sender (text/display raw) + unread_count /
        // last_msg_type / last_msg_sub_type (元数据). sort_timestamp 临时 (随消息变, 跟 summary 同步) 不进.
        DecodedEvent::SessionUpdate(e) => {
            m.insert("username_sha".into(), Value::from(sha256_hex(&e.username)));
            m.insert("summary".into(), opt_raw(e.summary.as_deref()));
            m.insert(
                "last_sender_display_name".into(),
                opt_raw(e.last_sender_display_name.as_deref()),
            );
            m.insert("unread_count".into(), Value::from(e.unread_count));
            m.insert("last_msg_type".into(), Value::from(e.last_msg_type));
            m.insert("last_msg_sub_type".into(), Value::from(e.last_msg_sub_type));
        }
        // favorite_update (ADR-454): server_id / fav_type / update_time (元数据) + from_user_sha (id) +
        // source_id (来源消息 hash id, 元数据). local_id / real_chat_name / content_len 只进 L2 不进 digest。
        DecodedEvent::FavoriteCreate(e) => {
            m.insert("server_id".into(), Value::from(e.server_id));
            m.insert("fav_type".into(), Value::from(e.fav_type));
            m.insert("update_time".into(), Value::from(e.update_time));
            m.insert("from_user_sha".into(), Value::from(sha256_hex(&e.from_user)));
            m.insert("source_id".into(), opt_raw(e.source_id.as_deref()));
        }
        // favorite_tag_update (ADR-454 批 B-2): tag_server_id / fav_server_id / op_code (元数据) + tag_name (text raw).
        // seq / tag_local_id / fav_local_id 只进 L2 (排序/本地 id) 不进 digest。
        DecodedEvent::FavoriteTagCreate(e) => {
            m.insert("tag_server_id".into(), Value::from(e.tag_server_id));
            m.insert("fav_server_id".into(), Value::from(e.fav_server_id));
            m.insert("tag_name".into(), Value::from(e.tag_name.as_str()));
            m.insert("op_code".into(), Value::from(e.op_code));
        }
        // sns_event (ADR-467 件1): tid / create_time / moment_type (元数据) + author_sha (id). 动态本体身份 +
        // immutable 属性 (恰 4 元)。⚠️ create_time 是**发布时间恒定不变** (不同于 message/session 的可变排序时间,
        // 那里 create_time/sort_timestamp 属临时不进 digest) → 朋友圈 create_time 是身份属性, 进 digest。
        // content_desc/media_count/like_count/comment_count/location/… 只进 L2 (点赞变不产新 fingerprint)。
        DecodedEvent::SnsCreate(e) => {
            m.insert("tid".into(), Value::from(e.tid));
            m.insert("author_sha".into(), Value::from(sha256_hex(&e.author)));
            m.insert("create_time".into(), Value::from(e.create_time));
            m.insert("moment_type".into(), Value::from(e.moment_type));
        }
        // transfer_update (ADR-468): transfer_id / pay_sub_type / begin_transfer_time (元数据+状态+时刻) +
        // payer_sha / receiver_sha (id). transcation_id / message_server_id / 其它时间 / flag / session_name
        // 只进 L2 不进 digest。⚠️ begin_transfer_time 发起时刻恒定 (身份属性, 同 sns create_time); pay_sub_type
        // 是状态 (变即产新 fingerprint = 状态流水) 进 digest; last_update_time 才临时 (随重读变) 不进。
        DecodedEvent::TransferCreate(e) => {
            m.insert("transfer_id".into(), Value::from(e.transfer_id.as_str()));
            m.insert("pay_sub_type".into(), Value::from(e.pay_sub_type));
            m.insert("begin_transfer_time".into(), Value::from(e.begin_transfer_time));
            m.insert("pay_payer_sha".into(), Value::from(sha256_hex(&e.pay_payer)));
            m.insert("pay_receiver_sha".into(), Value::from(sha256_hex(&e.pay_receiver)));
        }
        // red_envelope_update (ADR-468 件2): send_id / hb_type / hb_status / receive_status (元数据+类型+状态) +
        // sender_user_name_sha (id). message_server_id / session_name / native_url / scene_id 只进 L2 不进 digest。
        // hb_status/receive_status 状态变即产新 fingerprint (领取流水, 同 transfer pay_sub_type)。
        DecodedEvent::RedEnvelopeCreate(e) => {
            m.insert("send_id".into(), Value::from(e.send_id.as_str()));
            m.insert(
                "sender_user_name_sha".into(),
                Value::from(sha256_hex(&e.sender_user_name)),
            );
            m.insert("hb_type".into(), Value::from(e.hb_type));
            m.insert("hb_status".into(), Value::from(e.hb_status));
            m.insert("receive_status".into(), Value::from(e.receive_status));
        }
        // group_pay_update (ADR-468 件3): bill_no / message_create_time (元数据+时刻) + session_name_sha (id).
        // message_local_id 只进 L2 不进 digest。message_create_time 是群收款时刻恒定 (身份属性, 同 sns create_time)。
        DecodedEvent::GroupPayCreate(e) => {
            m.insert("bill_no".into(), Value::from(e.bill_no.as_str()));
            m.insert("session_name_sha".into(), Value::from(sha256_hex(&e.session_name)));
            m.insert("message_create_time".into(), Value::from(e.message_create_time));
        }
        // friend_verify_update (ADR-469): user_name_sha (id) + timestamp / is_sender / scene (元数据).
        // 好友 (真库唯一) + 时刻 + 方向 + 加好友来源。friend_type (恒 37) / content (打招呼语 text 类) 只进 L2。
        DecodedEvent::FriendVerifyCreate(e) => {
            m.insert("user_name_sha".into(), Value::from(sha256_hex(&e.user_name)));
            m.insert("timestamp".into(), Value::from(e.timestamp));
            m.insert("is_sender".into(), Value::from(e.is_sender));
            m.insert("scene".into(), Value::from(e.scene));
        }
        // finder_visit_update (ADR-473): owner_username_sha (id) + name / visit_time (元数据).
        // 视频号号主 (真库唯一) + 昵称 + 访问时刻。profile_url (主页 URL, 含频道 id) 只进 L2, 不进 digest。
        DecodedEvent::FinderVisitCreate(e) => {
            m.insert("owner_username_sha".into(), Value::from(sha256_hex(&e.owner_username)));
            m.insert("name".into(), Value::from(e.name.as_str()));
            m.insert("visit_time".into(), Value::from(e.visit_time));
        }
        // moment_feed_update (ADR-474): tid (动态身份) + author_sha (id) + create_time (元数据).
        // 哪条动态 (真库唯一 tid) + 谁发 + 发布时刻。last_read_time/is_read (读状态, is_read 99.5% 恒 1 噪音)
        // 只进 L2, 不进 digest (读状态变不产新 fingerprint)。
        DecodedEvent::MomentFeedCreate(e) => {
            m.insert("tid".into(), Value::from(e.tid));
            m.insert("author_sha".into(), Value::from(sha256_hex(&e.author)));
            m.insert("create_time".into(), Value::from(e.create_time));
        }
        // custom_emoticon_update (ADR-478): md5 (身份, 内容哈希非 PII) + caption (描述) + emoticon_type (元数据).
        // aes_key/urls/product_id 只进 L2 (密钥/资源引用/冗余), 不进 digest。
        DecodedEvent::CustomEmoticonCreate(e) => {
            m.insert("md5".into(), Value::from(e.md5.as_str()));
            m.insert("caption".into(), Value::from(e.caption.as_str()));
            m.insert("emoticon_type".into(), Value::from(e.emoticon_type));
        }
        // avatar_image_update (ADR-481): username_sha (联系人身份, id) + md5 (头像内容哈希).
        // md5 变 = 换头像 → 新 fingerprint = 头像变更史。image_buffer(图 bytes)/update_time 只进 L2 不进 digest。
        DecodedEvent::AvatarImageCreate(e) => {
            m.insert("username_sha".into(), Value::from(sha256_hex(&e.username)));
            m.insert("md5".into(), Value::from(e.md5.as_str()));
        }
        // sns_notify_update (照 moment_feed ADR-474): comment_id (通知身份) + feed_id (哪条动态) +
        // from_user_sha (id) + notify_type (元数据) + create_time (元数据) — 通知的不可变身份 (恰 5 元)。
        // ⚠️ create_time 是互动时刻恒定 (身份属性, 同 sns/moment_feed) → 进 digest。
        // is_unread/del_status/content/from_nickname/to_user/to_nickname/is_relative_me 只进 L2 不进 digest
        // (读状态/评论文本变不产新 fingerprint; 同 moment_feed 的 last_read_time/is_read)。
        DecodedEvent::SnsNotifyCreate(e) => {
            m.insert("comment_id".into(), Value::from(e.comment_id));
            m.insert("feed_id".into(), Value::from(e.feed_id));
            m.insert("from_user_sha".into(), Value::from(sha256_hex(&e.from_user)));
            m.insert("notify_type".into(), Value::from(e.notify_type));
            m.insert("create_time".into(), Value::from(e.create_time));
        }
        // biz_chat_contact_update (ADR-482): user_id_sha (企微 wxid, id) + brand_user_name (`gh_` 品牌 id) +
        // user_name (显示名). 企微号主 (真库唯一) + 品牌 + 显示名。head_img_url/profile_url/bit_flag 只进 L2, 不进 digest。
        DecodedEvent::BizChatContactCreate(e) => {
            m.insert("user_id_sha".into(), Value::from(sha256_hex(&e.user_id)));
            m.insert("brand_user_name".into(), Value::from(e.brand_user_name.as_str()));
            m.insert("user_name".into(), Value::from(e.user_name.as_str()));
        }
        // §3.x.6: kind / watermark_key / watermark_value (元数据). last_update 临时不进.
        DecodedEvent::SystemCursorUpdate(e) => {
            m.insert("kind".into(), Value::from(e.kind.as_str()));
            m.insert("watermark_key".into(), Value::from(e.watermark_key.as_str()));
            m.insert("watermark_value".into(), Value::from(e.watermark_value.as_str()));
        }
        // §3.x.7: error_code (元数据) + error_message / context_json (text raw) + occurred_at_canonical (元数据).
        DecodedEvent::SystemError(e) => {
            m.insert("error_code".into(), Value::from(e.error_code.as_str()));
            m.insert("error_message".into(), Value::from(e.error_message.as_str()));
            m.insert("context_json".into(), opt_raw(e.context_json.as_deref()));
            m.insert(
                "occurred_at_canonical".into(),
                Value::from(e.occurred_at_canonical.as_str()),
            );
        }
    }
    CanonicalRawValues(m)
}

#[cfg(test)]
mod tests {

    /// **传输状态列不得进内容指纹**(ADR-508 D25 的守卫)。
    ///
    /// 它们会随消息生命周期变(发送中→已送达→已读)。archive 是 `INSERT OR IGNORE`, 一旦纳入指纹,
    /// 同一条消息每变一次状态就多一条 archive 记录 —— 百万级库会涨到千万级, 换来的是分析价值极低的
    /// 传输状态历史。代价是 archive 记首次观测、`message` 表记最新, 这几列上两者不一致 = **设计如此**。
    ///
    /// 谁想把它们加进来, 会先撞到这条测试, 然后去读上面那段说明。
    #[test]
    fn mutable_transport_columns_stay_out_of_digest() {
        // 构造同 `message_canonical_fields`(那条测试已经把字段列全了)。
        let ev = DecodedEvent::Message(MessageCreate {
            provenance: prov(EventType::Message, EventAction::Create),
            server_id: "9".to_string(),
            server_seq: 7,
            origin_source: 2,
            upload_status: 1,
            download_status: 1,
            conv_id: "c".to_string(),
            sender_wxid: Wxid::try_new("wxid_x".to_string()).expect("wxid"),
            create_time: 1,
            sort_seq: 42,
            msg_type: 1,
            msg_sub_type: None,
            msg_type_name: "TEXT".to_string(),
            msg_sub_type_name: None,
            status: 3,
            local_type_raw: 1,
            is_chatroom: false,
            raw_xml_present: false,
            decode_kind: "plain".to_string(),
            text_content: "t".to_string(),
            msg_source: String::new(),
        });
        let keys: Vec<String> = canonical_raw_values(&ev).0.keys().cloned().collect();
        for banned in [
            "status",
            "upload_status",
            "download_status",
            "sort_seq",
            "server_seq",
            "origin_source",
            "local_type_raw",
        ] {
            assert!(
                !keys.contains(&banned.to_string()),
                "传输状态列 `{banned}` 进了内容指纹 —— archive 会按状态变化次数膨胀 (ADR-508 D25)。                 真要改, 先读 canonical_raw_values 里 Message 分支上面那段, 并同步 sink 的重放契约。"
            );
        }
        // 反向: 内容列必须在(否则指纹认不出内容变化)。
        for required in [
            "conv_id_sha",
            "sender_wxid_sha",
            "server_id",
            "msg_type",
            "text_content",
        ] {
            assert!(keys.contains(&required.to_string()), "内容列 `{required}` 不在指纹里");
        }
    }
    use super::super::bizchat::BizChatContactCreate;
    use super::super::chatroom::{ChatroomCreate, ChatroomMemberAdd, ChatroomMemberRemove};
    use super::super::contact::ContactUpdate;
    use super::super::emoticon::CustomEmoticonCreate;
    use super::super::favorite::FavoriteCreate;
    use super::super::favorite_tag::FavoriteTagCreate;
    use super::super::finder::FinderVisitCreate;
    use super::super::friend_verify::FriendVerifyCreate;
    use super::super::group_pay::GroupPayCreate;
    use super::super::message::MessageCreate;
    use super::super::moment_feed::MomentFeedCreate;
    use super::super::provenance::Provenance;
    use super::super::red_envelope::RedEnvelopeCreate;
    use super::super::session::SessionUpdate;
    use super::super::sns::SnsCreate;
    use super::super::sns_notify::SnsNotifyCreate;
    use super::super::system::{SystemCursorUpdate, SystemError};
    use super::super::transfer::TransferCreate;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn prov(t: EventType, a: EventAction) -> Provenance {
        Provenance {
            account_id: Wxid::try_new("wxid_acct_001").unwrap(),
            source: "x.db".to_string(),
            source_native_id: "anchor".to_string(),
            event_type: t,
            event_action: a,
            event_seq: 1,
            ingest_time: 1,
        }
    }

    /// provenance + 临时字段【绝不】进 content_digest (所有事件通用红线).
    fn assert_no_provenance_no_temporary(m: &BTreeMap<String, Value>) {
        for k in [
            // provenance (进外层 canonical_bytes)
            "account_id_sha",
            "account_id",
            "source",
            "source_native_id",
            "event_type",
            "event_action",
            "event_seq",
            "ingest_time",
            // 临时字段 (随重读变)
            "create_time",
            "sort_seq",
            "sort_timestamp",
            "status",
            "decode_kind",
            "local_type_raw",
            "raw_xml_present",
            "is_chatroom",
            "joined_at",
            "left_at",
            "last_update",
            "msg_type_name",
            "msg_sub_type_name",
        ] {
            assert!(!m.contains_key(k), "content_digest 不准含 provenance/临时字段 {k}");
        }
    }

    #[test]
    fn message_canonical_fields() {
        let ev = DecodedEvent::Message(MessageCreate {
            provenance: prov(EventType::Message, EventAction::Create),
            server_id: "9".to_string(),
            server_seq: 0,
            origin_source: 2,
            upload_status: 5,
            download_status: 7,
            conv_id: "wxid_conv".to_string(),
            sender_wxid: Wxid::try_new("wxid_send").unwrap(),
            create_time: 5,
            sort_seq: 5,
            msg_type: 1,
            msg_sub_type: Some(0),
            msg_type_name: "TEXT".to_string(),
            msg_sub_type_name: None,
            status: 2,
            local_type_raw: 1,
            is_chatroom: false,
            raw_xml_present: false,
            decode_kind: "plain".to_string(),
            text_content: "正文".to_string(),
            msg_source: String::new(),
        });
        let m = canonical_raw_values(&ev);
        // id 类 → _sha 键 + sha 值
        assert_eq!(m["conv_id_sha"], Value::from(sha256_hex("wxid_conv")));
        assert_eq!(m["sender_wxid_sha"], Value::from(sha256_hex("wxid_send")));
        // text 类 → base 键 + 原文 raw
        assert_eq!(m["text_content"], Value::from("正文"));
        // 元数据 → 原生
        assert_eq!(m["server_id"], Value::from("9"));
        assert_eq!(m["msg_type"], Value::from(1));
        assert_eq!(m["msg_sub_type"], Value::from(0));
        // 恰 6 字段, 无 provenance/临时; server_seq / origin_source / upload_status / download_status 是 L2
        // 元数据, **故意不进 digest** (批 A + 本批, digest 恒 6 元)。
        assert!(!m.contains_key("server_seq"), "server_seq 不得进 content_digest");
        assert!(!m.contains_key("origin_source"), "origin_source 不得进 content_digest");
        assert!(!m.contains_key("upload_status"), "upload_status 不得进 content_digest");
        assert!(
            !m.contains_key("download_status"),
            "download_status 不得进 content_digest"
        );
        assert_eq!(m.len(), 6);
        assert_no_provenance_no_temporary(&m);
        assert!(!m.contains_key("conv_id"), "id 类不出裸键");
    }

    /// favorite_update: content_digest 恰 5 元 (server_id/fav_type/update_time/from_user_sha/source_id);
    /// local_id/real_chat_name/content_len 只进 L2 **不进 digest** (ADR-454; codex 批B P2 锁死)。
    #[test]
    fn favorite_canonical_fields() {
        let ev = DecodedEvent::FavoriteCreate(FavoriteCreate {
            provenance: prov(EventType::FavoriteUpdate, EventAction::Create),
            server_id: 329,
            local_id: 156,
            fav_type: 14,
            update_time: 1_779_354_334,
            from_user: "wxid_src".to_string(),
            real_chat_name: Some("wxid_rc".to_string()),
            source_id: Some("hash_abc".to_string()),
            content_len: 2048,
            note_text: Some("笔记正文".to_string()),
            media: vec![],
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["server_id"], Value::from(329));
        assert_eq!(m["fav_type"], Value::from(14));
        assert_eq!(m["update_time"], Value::from(1_779_354_334_i64));
        assert_eq!(m["from_user_sha"], Value::from(sha256_hex("wxid_src")));
        assert_eq!(m["source_id"], Value::from("hash_abc"));
        // L2-only 字段 **不得进 digest** (ADR-471 note_text 同)。
        for k in ["local_id", "real_chat_name", "content_len", "from_user", "note_text"] {
            assert!(!m.contains_key(k), "favorite digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 5, "favorite digest 恰 5 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// favorite_tag_update: content_digest 恰 4 元 (tag_server_id/fav_server_id/tag_name/op_code);
    /// seq/tag_local_id/fav_local_id 只进 L2 **不进 digest** (ADR-454 批 B-2)。
    #[test]
    fn favorite_tag_canonical_fields() {
        let ev = DecodedEvent::FavoriteTagCreate(FavoriteTagCreate {
            provenance: prov(EventType::FavoriteTagUpdate, EventAction::Create),
            tag_server_id: 1,
            tag_local_id: 1,
            tag_name: "押金".to_string(),
            seq: 824_874_138,
            fav_server_id: 254,
            fav_local_id: 92,
            op_code: 1,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["tag_server_id"], Value::from(1));
        assert_eq!(m["fav_server_id"], Value::from(254));
        assert_eq!(
            m["tag_name"],
            Value::from("押金"),
            "标签名 raw 进 digest (同 nick/summary)"
        );
        assert_eq!(m["op_code"], Value::from(1));
        for k in ["seq", "tag_local_id", "fav_local_id"] {
            assert!(!m.contains_key(k), "favorite_tag digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 4, "favorite_tag digest 恰 4 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// sns_event (ADR-467 件1): content_digest 恰 4 元 (tid/author_sha/create_time/moment_type);
    /// content_desc/media_count/like_count/comment_count/location 只进 L2 **不进 digest**。
    /// ⚠️ 朋友圈 create_time 是**发布时间恒定** (身份属性) → 进 digest (故本测试不用排除 create_time 的
    /// assert_no_provenance_no_temporary 助手, 改手写 provenance 缺席断言)。
    #[test]
    fn sns_canonical_fields() {
        let ev = DecodedEvent::SnsCreate(SnsCreate {
            provenance: prov(EventType::SnsEvent, EventAction::Create),
            tid: -3_518_821_952_372_526_549,
            author: "wxid_author".to_string(),
            create_time: 1_779_546_990,
            moment_type: 15,
            content_desc: "正文会变但不进 digest".to_string(),
            author_nickname: Some("昵称".to_string()),
            source_user: None,
            location_label: Some("某地".to_string()),
            latitude: Some(1.0),
            longitude: Some(2.0),
            title: None,
            link_url: None,
            media_count: 3,
            like_count: 5,
            comment_count: 1,
            source_nickname: None,
            is_bidirectional_fan: 0,
            is_rich_text: 0,
            public_user_name: None,
            app_name: None,
            content_len: 999,
            raw_content: "<SnsDataItem/>".to_string(),
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["tid"], Value::from(-3_518_821_952_372_526_549_i64));
        assert_eq!(m["author_sha"], Value::from(sha256_hex("wxid_author")));
        assert_eq!(
            m["create_time"],
            Value::from(1_779_546_990_i64),
            "朋友圈 create_time 是身份属性进 digest"
        );
        assert_eq!(m["moment_type"], Value::from(15));
        // L2-only 字段 (点赞/评论/正文/位置/媒体计数) + raw_content 载体 **不得进 digest** (点赞变不产新 fingerprint)。
        for k in [
            "author",
            "content_desc",
            "author_nickname",
            "media_count",
            "like_count",
            "comment_count",
            "location_label",
            "latitude",
            "longitude",
            "title",
            "content_len",
            "raw_content",
        ] {
            assert!(!m.contains_key(k), "sns digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 4, "sns digest 恰 4 元");
        // provenance 缺席 (不用 assert_no_provenance_no_temporary — 那助手排除 create_time, 而 sns 要 create_time)。
        for k in [
            "account_id_sha",
            "account_id",
            "source",
            "source_native_id",
            "event_type",
            "event_action",
            "event_seq",
            "ingest_time",
        ] {
            assert!(!m.contains_key(k), "sns digest 不得含 provenance 字段 {k}");
        }
    }

    /// transfer_update (ADR-468): content_digest 恰 5 元 (transfer_id/pay_sub_type/begin_transfer_time/
    /// pay_payer_sha/pay_receiver_sha); transcation_id/message_server_id/其它时间/flag/session_name 只进 L2
    /// **不进 digest**。pay_sub_type 状态变即产新 fingerprint (状态流水); begin_transfer_time 发起时刻恒定 (身份)。
    #[test]
    fn transfer_canonical_fields() {
        let ev = DecodedEvent::TransferCreate(TransferCreate {
            provenance: prov(EventType::TransferUpdate, EventAction::Create),
            transfer_id: "1000050001202507100225413996557".to_string(),
            transcation_id: "53010001606113202507100928575102".to_string(),
            message_server_id: 6_379_941_610_914_610_151,
            second_message_server_id: 0,
            session_name: "wxid_peer".to_string(),
            pay_sub_type: 2,
            pay_payer: "wxid_payer".to_string(),
            pay_receiver: "wxid_recv".to_string(),
            begin_transfer_time: 1_752_162_563,
            last_modified_time: 1_752_162_564,
            invalid_time: 1_752_248_963,
            last_update_time: 1_752_217_991,
            delay_confirm_flag: 0,
            bubble_clicked_flag: 0,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["transfer_id"], Value::from("1000050001202507100225413996557"));
        assert_eq!(m["pay_sub_type"], Value::from(2));
        assert_eq!(m["begin_transfer_time"], Value::from(1_752_162_563_i64));
        assert_eq!(m["pay_payer_sha"], Value::from(sha256_hex("wxid_payer")));
        assert_eq!(m["pay_receiver_sha"], Value::from(sha256_hex("wxid_recv")));
        // L2-only 字段 **不得进 digest** (含裸 payer/receiver — digest 只存 sha)。
        for k in [
            "transcation_id",
            "message_server_id",
            "second_message_server_id",
            "session_name",
            "last_modified_time",
            "invalid_time",
            "last_update_time",
            "delay_confirm_flag",
            "bubble_clicked_flag",
            "pay_payer",
            "pay_receiver",
        ] {
            assert!(!m.contains_key(k), "transfer digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 5, "transfer digest 恰 5 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// red_envelope_update (ADR-468 件2): content_digest 恰 5 元 (send_id/sender_user_name_sha/hb_type/hb_status/
    /// receive_status); message_server_id/session_name/native_url/scene_id 只进 L2 **不进 digest**。
    #[test]
    fn red_envelope_canonical_fields() {
        let ev = DecodedEvent::RedEnvelopeCreate(RedEnvelopeCreate {
            provenance: prov(EventType::RedEnvelopeUpdate, EventAction::Create),
            send_id: "1000039801202604206261068705009".to_string(),
            message_server_id: 461_510_149_866_340,
            session_name: "grp@chatroom".to_string(),
            sender_user_name: "wxid_sender".to_string(),
            native_url: "wxpay://x?sendusername=wxid_sender".to_string(),
            scene_id: 1002,
            hb_status: 1,
            hb_type: 0,
            receive_status: 0,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["send_id"], Value::from("1000039801202604206261068705009"));
        assert_eq!(m["sender_user_name_sha"], Value::from(sha256_hex("wxid_sender")));
        assert_eq!(m["hb_type"], Value::from(0));
        assert_eq!(m["hb_status"], Value::from(1));
        assert_eq!(m["receive_status"], Value::from(0));
        // L2-only 字段 **不得进 digest** (含 native_url 嵌 wxid + 裸 sender)。
        for k in [
            "message_server_id",
            "session_name",
            "native_url",
            "scene_id",
            "sender_user_name",
        ] {
            assert!(!m.contains_key(k), "red_envelope digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 5, "red_envelope digest 恰 5 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// group_pay_update (ADR-468 件3): content_digest 恰 3 元 (bill_no/session_name_sha/message_create_time);
    /// message_local_id 只进 L2 **不进 digest**。
    #[test]
    fn group_pay_canonical_fields() {
        let ev = DecodedEvent::GroupPayCreate(GroupPayCreate {
            provenance: prov(EventType::GroupPayUpdate, EventAction::Create),
            bill_no: "694a900673c1395568318fac8f11e4e2".to_string(),
            session_name: "grp@chatroom".to_string(),
            message_local_id: 38,
            message_create_time: 1_767_141_814,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["bill_no"], Value::from("694a900673c1395568318fac8f11e4e2"));
        assert_eq!(m["session_name_sha"], Value::from(sha256_hex("grp@chatroom")));
        assert_eq!(m["message_create_time"], Value::from(1_767_141_814_i64));
        for k in ["message_local_id", "session_name"] {
            assert!(!m.contains_key(k), "group_pay digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 3, "group_pay digest 恰 3 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// friend_verify_update (ADR-469): content_digest 恰 4 元 (user_name_sha/timestamp/is_sender/scene);
    /// friend_type (恒 37) / content (打招呼语) 只进 L2 **不进 digest**。
    #[test]
    fn friend_verify_canonical_fields() {
        let ev = DecodedEvent::FriendVerifyCreate(FriendVerifyCreate {
            provenance: prov(EventType::FriendVerifyUpdate, EventAction::Create),
            user_name: "wxid_friend".to_string(),
            friend_type: 37,
            timestamp: 1_752_217_142,
            is_sender: 0,
            scene: 14,
            content: "你好我是老王".to_string(),
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["user_name_sha"], Value::from(sha256_hex("wxid_friend")));
        assert_eq!(m["timestamp"], Value::from(1_752_217_142_i64));
        assert_eq!(m["is_sender"], Value::from(0));
        assert_eq!(m["scene"], Value::from(14));
        for k in ["friend_type", "content", "user_name"] {
            assert!(!m.contains_key(k), "friend_verify digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 4, "friend_verify digest 恰 4 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// finder_visit_update (ADR-473): content_digest 恰 3 元 (owner_username_sha/name/visit_time);
    /// profile_url (主页 URL, 含频道 id) 只进 L2 **不进 digest**。
    #[test]
    fn finder_canonical_fields() {
        let ev = DecodedEvent::FinderVisitCreate(FinderVisitCreate {
            provenance: prov(EventType::FinderVisitUpdate, EventAction::Create),
            owner_username: "wxid_qrst2345uvwx678".to_string(),
            name: "小应5899".to_string(),
            visit_time: 1_752_221_077,
            profile_url: "https://channels.weixin.qq.com/x".to_string(),
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["owner_username_sha"], Value::from(sha256_hex("wxid_qrst2345uvwx678")));
        assert_eq!(m["name"], Value::from("小应5899"), "视频号昵称 raw 进 digest");
        assert_eq!(m["visit_time"], Value::from(1_752_221_077_i64));
        for k in ["profile_url", "owner_username"] {
            assert!(!m.contains_key(k), "finder digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 3, "finder digest 恰 3 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// moment_feed_update (ADR-474): content_digest 恰 3 元 (tid/author_sha/create_time);
    /// last_read_time/is_read (读状态) 只进 L2 **不进 digest**。⚠️ create_time 是发布时刻恒定 (身份属性,
    /// 同 sns) → 进 digest (故不用排除 create_time 的 assert_no_provenance_no_temporary 助手, 改手写 provenance 缺席)。
    #[test]
    fn moment_feed_canonical_fields() {
        let ev = DecodedEvent::MomentFeedCreate(MomentFeedCreate {
            provenance: prov(EventType::MomentFeedUpdate, EventAction::Create),
            tid: -3_652_952_694_686_404_033,
            author: "wxid_ijkl5678mnop901".to_string(),
            create_time: 1_763_557_360,
            last_read_time: 1_779_501_771,
            is_read: 1,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["tid"], Value::from(-3_652_952_694_686_404_033_i64));
        assert_eq!(m["author_sha"], Value::from(sha256_hex("wxid_ijkl5678mnop901")));
        assert_eq!(
            m["create_time"],
            Value::from(1_763_557_360_i64),
            "发布时刻是身份属性进 digest"
        );
        for k in ["last_read_time", "is_read", "author", "summary"] {
            assert!(!m.contains_key(k), "moment_feed digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 3, "moment_feed digest 恰 3 元");
        // provenance 缺席 (不用 assert_no_provenance_no_temporary — 那助手排除 create_time, 而 moment_feed 要 create_time)。
        for k in [
            "account_id_sha",
            "account_id",
            "source",
            "source_native_id",
            "event_type",
            "event_action",
            "event_seq",
            "ingest_time",
        ] {
            assert!(!m.contains_key(k), "moment_feed digest 不得含 provenance 字段 {k}");
        }
    }

    /// sns_notify_update (照 moment_feed ADR-474): content_digest 恰 5 元 (comment_id/feed_id/from_user_sha/
    /// notify_type/create_time); is_unread/del_status/content/from_nickname/to_user/to_nickname/is_relative_me
    /// 只进 L2 **不进 digest**。⚠️ create_time 是互动时刻恒定 (身份属性, 同 moment_feed) → 进 digest (故不用
    /// 排除 create_time 的 assert_no_provenance_no_temporary 助手, 改手写 provenance 缺席)。
    #[test]
    fn sns_notify_canonical_fields() {
        let ev = DecodedEvent::SnsNotifyCreate(SnsNotifyCreate {
            provenance: prov(EventType::SnsNotifyUpdate, EventAction::Create),
            comment_id: 123_456_789,
            feed_id: -3_652_952_694_686_404_033,
            notify_type: 2,
            from_user: "wxid_notify_from".to_string(),
            create_time: 1_763_557_360,
            from_nickname: Some("互动者昵称".to_string()),
            to_user: Some("wxid_reply_target".to_string()),
            to_nickname: Some("回复对象昵称".to_string()),
            content: Some("评论正文会变但不进 digest".to_string()),
            is_unread: 0,
            del_status: 0,
            is_relative_me: 0,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["comment_id"], Value::from(123_456_789_i64));
        assert_eq!(m["feed_id"], Value::from(-3_652_952_694_686_404_033_i64));
        assert_eq!(m["from_user_sha"], Value::from(sha256_hex("wxid_notify_from")));
        assert_eq!(m["notify_type"], Value::from(2));
        assert_eq!(
            m["create_time"],
            Value::from(1_763_557_360_i64),
            "互动时刻是身份属性进 digest"
        );
        // L2-only 字段 (读状态/评论文本/昵称/回复对象) **不得进 digest** (读状态/文本变不产新 fingerprint)。
        for k in [
            "is_unread",
            "del_status",
            "content",
            "from_nickname",
            "to_user",
            "to_nickname",
            "is_relative_me",
            "from_user",
        ] {
            assert!(!m.contains_key(k), "sns_notify digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 5, "sns_notify digest 恰 5 元");
        // provenance 缺席 (不用 assert_no_provenance_no_temporary — 那助手排除 create_time, 而 sns_notify 要 create_time)。
        for k in [
            "account_id_sha",
            "account_id",
            "source",
            "source_native_id",
            "event_type",
            "event_action",
            "event_seq",
            "ingest_time",
        ] {
            assert!(!m.contains_key(k), "sns_notify digest 不得含 provenance 字段 {k}");
        }
    }

    /// custom_emoticon_update (ADR-478): content_digest 恰 3 元 (md5/caption/emoticon_type);
    /// aes_key/urls/product_id 只进 L2 **不进 digest**。
    #[test]
    fn emoticon_canonical_fields() {
        let ev = DecodedEvent::CustomEmoticonCreate(CustomEmoticonCreate {
            provenance: prov(EventType::CustomEmoticonUpdate, EventAction::Create),
            md5: "c0c5d9625338df85".to_string(),
            emoticon_type: 1,
            caption: "微笑".to_string(),
            product_id: "p".to_string(),
            aes_key: "secretkey".to_string(),
            cdn_url: "http://x".to_string(),
            thumb_url: String::new(),
            tp_url: String::new(),
            extern_url: String::new(),
            extern_md5: "60bfd31a".to_string(),
            encrypt_url: String::new(),
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["md5"], Value::from("c0c5d9625338df85"));
        assert_eq!(m["caption"], Value::from("微笑"));
        assert_eq!(m["emoticon_type"], Value::from(1));
        for k in ["aes_key", "cdn_url", "product_id", "extern_md5"] {
            assert!(!m.contains_key(k), "emoticon digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 3, "emoticon digest 恰 3 元");
        assert_no_provenance_no_temporary(&m);
    }

    /// biz_chat_contact_update (ADR-482): content_digest 恰 3 元 (user_id_sha/brand_user_name/user_name);
    /// head_img_url/profile_url/bit_flag 只进 L2 **不进 digest**。
    #[test]
    fn bizchat_canonical_fields() {
        let ev = DecodedEvent::BizChatContactCreate(BizChatContactCreate {
            provenance: prov(EventType::BizChatContactUpdate, EventAction::Create),
            user_id: "ww16xxxxxxxxxxxxxxxxxxx".to_string(),
            brand_user_name: "gh_44bfefcbb4a5".to_string(),
            user_name: "白星".to_string(),
            head_img_url: "http://head/x".to_string(),
            profile_url: "https://work.weixin.qq.com/x".to_string(),
            bit_flag: 16,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["user_id_sha"], Value::from(sha256_hex("ww16xxxxxxxxxxxxxxxxxxx")));
        assert_eq!(m["brand_user_name"], Value::from("gh_44bfefcbb4a5"));
        assert_eq!(m["user_name"], Value::from("白星")); // display 原文
        for k in ["head_img_url", "profile_url", "bit_flag", "user_id"] {
            assert!(!m.contains_key(k), "bizchat digest 不得含 L2-only 字段 {k}");
        }
        assert_eq!(m.len(), 3, "bizchat digest 恰 3 元");
        assert_no_provenance_no_temporary(&m);
    }

    #[test]
    fn contact_canonical_fields() {
        let ev = DecodedEvent::ContactUpdate(ContactUpdate {
            provenance: prov(EventType::ContactUpdate, EventAction::Create),
            username: "wxid_c".to_string(),
            nick_name: "小明".to_string(),
            remark: Some("备注".to_string()),
            alias: None,
            local_type: 1,
            is_in_chat_room: false,
            quan_pin: None,
            pin_yin_initial: None,
            remark_quan_pin: None,
            remark_pin_yin_initial: None,
            verify_flag: 3,
            delete_flag: 1,
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
            signature: None,
            moments_cover_url: None,
            labels: None,
            friend_add_time: None,
            openim_company: None,
            openim_realname: None,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["username_sha"], Value::from(sha256_hex("wxid_c")));
        assert_eq!(m["nick_name"], Value::from("小明")); // display 原文
        assert_eq!(m["remark"], Value::from("备注"));
        assert_eq!(m["alias"], Value::Null); // None → null
        assert_eq!(m["local_type"], Value::from(1));
        // 状态标志进 digest (第二批 — 独立状态溯源, supersede ADR-412)
        assert_eq!(m["verify_flag"], Value::from(3));
        assert_eq!(m["delete_flag"], Value::from(1));
        assert_eq!(m.len(), 8, "contact digest 字段集 8 (第二批加 verify_flag/delete_flag)");
        assert_no_provenance_no_temporary(&m);
    }

    #[test]
    fn session_canonical_fields() {
        let ev = DecodedEvent::SessionUpdate(SessionUpdate {
            provenance: prov(EventType::SessionUpdate, EventAction::Create),
            username: "wxid_s".to_string(),
            summary: Some("在吗".to_string()),
            last_sender_display_name: Some("小红".to_string()),
            unread_count: 2,
            last_msg_type: 1,
            last_msg_sub_type: 0,
            sort_timestamp: 1_700_000_009_000,
            session_type: 1,
            is_hidden: 0,
            status: 0,
            draft: None,
            last_msg_sender: Some("wxid_last".to_string()),
            last_timestamp: 123,
            last_clear_unread_timestamp: 456,
            last_msg_locald_id: 7,
            last_msg_ext_type: 8,
            unread_first_msg_srv_id: 9,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["username_sha"], Value::from(sha256_hex("wxid_s")));
        assert_eq!(m["summary"], Value::from("在吗")); // text 类 → 原文 raw
        assert_eq!(m["last_sender_display_name"], Value::from("小红"));
        assert_eq!(m["unread_count"], Value::from(2));
        assert_eq!(m["last_msg_sub_type"], Value::from(0));
        assert!(
            !m.contains_key("sort_timestamp"),
            "sort_timestamp 临时不进 content_digest"
        );
        // 第四批会话状态列 (session_type/is_hidden/status/draft) 不进 digest (当前态筛选, 用户选不溯源)。
        assert!(!m.contains_key("session_type"), "会话状态不进 digest (第四批 L2-only)");
        assert!(!m.contains_key("is_hidden"));
        assert!(!m.contains_key("status"));
        assert!(!m.contains_key("draft"));
        // 第六批 6 列 (即使有值) 也不进 digest (L2-only, 同第四批状态列)。
        for k in [
            "last_msg_sender",
            "last_timestamp",
            "last_clear_unread_timestamp",
            "last_msg_locald_id",
            "last_msg_ext_type",
            "unread_first_msg_srv_id",
        ] {
            assert!(!m.contains_key(k), "第六批列不进 digest (L2-only): {k}");
        }
        assert_eq!(
            m.len(),
            6,
            "session digest 恒 6 字段 (第四/六批列不进; sort_timestamp 临时不进)"
        );
        assert_no_provenance_no_temporary(&m);
    }

    #[test]
    fn chatroom_create_canonical_fields() {
        let ev = DecodedEvent::ChatroomCreate(ChatroomCreate {
            is_still_member: true,
            provenance: prov(EventType::ChatroomUpdate, EventAction::Create),
            chatroom_id: "x@chatroom".to_string(),
            chatroom_name: "群".to_string(),
            chatroom_remark: Some("我的群备注".to_string()),
            announcement: None,
            owner_wxid: Some("wxid_owner".to_string()),
            member_count: 8,
            // 批H: 编辑者/发布时间设非默认 — 验它们**不进** digest (L2-only)。
            announcement_editor: Some("wxid_editor".to_string()),
            announcement_publish_time: 1_700_000_000,
            // ADR-460 KI-A/B: 富媒体公告 / 群状态位设非默认 — 验它们**不进** digest (L2-only)。
            xml_announcement: Some("<xml>富媒体公告</xml>".to_string()),
            chat_room_status: 0x80000,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["chatroom_id_sha"], Value::from(sha256_hex("x@chatroom")));
        assert_eq!(m["chatroom_name"], Value::from("群"));
        assert_eq!(m["announcement"], Value::Null);
        assert_eq!(m["owner_wxid_sha"], Value::from(sha256_hex("wxid_owner"))); // nullable id Some → sha
        assert_eq!(m["member_count"], Value::from(8));
        assert_eq!(
            m.len(),
            5,
            "chatroom digest 恒 5 (批H 编辑者/发布时间 + 群备注 + KI-A/B 富媒体公告/群状态位 L2-only 不进)"
        );
        assert!(!m.contains_key("announcement_editor"), "批H: 公告编辑者不进 digest");
        assert!(
            !m.contains_key("announcement_publish_time"),
            "批H: 公告发布时间不进 digest"
        );
        assert!(!m.contains_key("chatroom_remark"), "群备注 L2-only 不进 digest");
        assert!(!m.contains_key("xml_announcement"), "KI-A: 富媒体公告不进 digest");
        assert!(!m.contains_key("chat_room_status"), "KI-B: 群状态位不进 digest");
        assert!(
            !m.contains_key("is_still_member"),
            "ADR-493: 退群标记 L2-only 不进 digest"
        );
        assert_no_provenance_no_temporary(&m);
    }

    #[test]
    fn chatroom_member_add_remove_canonical_fields() {
        let add = DecodedEvent::ChatroomMemberAdd(ChatroomMemberAdd {
            provenance: prov(EventType::ChatroomUpdate, EventAction::MemberAdd),
            chatroom_id: "x@chatroom".to_string(),
            member_wxid: "wxid_m".to_string(),
            display_name: None,
            joined_at: Some(5),
            role: "admin".to_string(),
            invited_by: None,
        });
        let m = canonical_raw_values(&add);
        assert_eq!(m["chatroom_id_sha"], Value::from(sha256_hex("x@chatroom")));
        assert_eq!(m["member_wxid_sha"], Value::from(sha256_hex("wxid_m")));
        assert_eq!(m["display_name"], Value::Null);
        assert_eq!(m.len(), 3, "member_add 3 字段 (joined_at 临时不进)");
        assert_no_provenance_no_temporary(&m);

        let rm = DecodedEvent::ChatroomMemberRemove(ChatroomMemberRemove {
            provenance: prov(EventType::ChatroomUpdate, EventAction::MemberRemove),
            chatroom_id: "x@chatroom".to_string(),
            member_wxid: "wxid_m".to_string(),
            left_at: Some(9),
        });
        let m2 = canonical_raw_values(&rm);
        assert_eq!(m2.len(), 2, "member_remove 2 字段 (left_at 临时不进)");
        assert!(!m2.contains_key("left_at"));
        assert_no_provenance_no_temporary(&m2);
    }

    #[test]
    fn system_cursor_canonical_fields() {
        let ev = DecodedEvent::SystemCursorUpdate(SystemCursorUpdate {
            provenance: prov(EventType::SystemEvent, EventAction::CursorUpdate),
            kind: "message".to_string(),
            watermark_key: "k".to_string(),
            watermark_value: "[1]".to_string(),
            last_update: 9,
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["kind"], Value::from("message"));
        assert_eq!(m["watermark_key"], Value::from("k"));
        assert_eq!(m["watermark_value"], Value::from("[1]"));
        assert_eq!(m.len(), 3, "cursor 3 字段 (last_update 临时不进)");
        assert!(!m.contains_key("last_update"));
        assert_no_provenance_no_temporary(&m);
    }

    #[test]
    fn system_error_canonical_fields() {
        let ev = DecodedEvent::SystemError(SystemError {
            provenance: prov(EventType::SystemEvent, EventAction::Error),
            error_code: "E".to_string(),
            error_message: "出错了".to_string(),
            context_json: Some(r#"{"k":1}"#.to_string()),
            occurred_at_canonical: "ctx".to_string(),
        });
        let m = canonical_raw_values(&ev);
        assert_eq!(m["error_code"], Value::from("E"));
        // text 类 → 原文 raw (不是 _sha — recon 修后)
        assert_eq!(m["error_message"], Value::from("出错了"));
        assert_eq!(m["context_json"], Value::from(r#"{"k":1}"#));
        assert_eq!(m["occurred_at_canonical"], Value::from("ctx"));
        assert!(!m.contains_key("error_message_sha"), "content_digest 用原文非 _sha");
        assert_eq!(m.len(), 4);
        assert_no_provenance_no_temporary(&m);
    }

    /// content_digest 隐私模式无关: 同事件不同隐私模式不影响 canonical_raw_values (它本就用原值, 跟 mode 无关).
    #[test]
    fn canonical_is_privacy_mode_independent() {
        let ev = DecodedEvent::ContactUpdate(ContactUpdate {
            provenance: prov(EventType::ContactUpdate, EventAction::Create),
            username: "wxid_c".to_string(),
            nick_name: "小明".to_string(),
            remark: None,
            alias: None,
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
            signature: None,
            moments_cover_url: None,
            labels: None,
            friend_add_time: None,
            openim_company: None,
            openim_realname: None,
        });
        // canonical_raw_values 不接收 mode 参数 → 结构上就跟隐私模式无关 (原值); 这里确认昵称是原文非 sha
        let m = canonical_raw_values(&ev);
        assert_eq!(
            m["nick_name"],
            Value::from("小明"),
            "content_digest 用真昵称原文 (模式无关)"
        );
    }

    /// 字段扩充第一批 (2026-07-01): 4 拼音列**不进** content_digest (派生自 nick/remark, 只进 L2 person 表)。
    /// **第二批 (2026-07-01): verify_flag/delete_flag 独立状态**进** digest → contact 字段集 6→8 (supersede ADR-412);
    /// 拼音仍不进** — 本测试验拼音不进 (len 8 里 6 业务 + verify/delete, 无拼音); verify/delete 进见 contact_canonical_fields。
    #[test]
    fn contact_canonical_excludes_pinyin() {
        let ev = DecodedEvent::ContactUpdate(ContactUpdate {
            provenance: prov(EventType::ContactUpdate, EventAction::Create),
            username: "wxid_c".to_string(),
            nick_name: "小明".to_string(),
            remark: None,
            alias: None,
            local_type: 1,
            is_in_chat_room: false,
            quan_pin: Some("xiaoming".to_string()),
            pin_yin_initial: Some("XM".to_string()),
            remark_quan_pin: None,
            remark_pin_yin_initial: None,
            verify_flag: 0,
            delete_flag: 0,
            big_head_url: Some("https://wx.qlogo.cn/x/0".to_string()),
            small_head_url: Some("https://wx.qlogo.cn/x/96".to_string()),
            head_img_md5: Some("abc123def456".to_string()),
            description: Some("个性签名".to_string()),
            flag: 5,
            chat_room_notify: 1,
            chat_room_type: 2,
            sex: 2,
            country: Some("CN".to_string()),
            province: Some("Zhejiang".to_string()),
            city: Some("Hangzhou".to_string()),
            friend_source: 3,
            signature: Some("个性签名".to_string()),
            moments_cover_url: Some("http://shmmsns.qpic.cn/mmsns/x/0".to_string()),
            labels: Some("老板,客户".to_string()),
            friend_add_time: Some(1_698_674_704),
            openim_company: Some("某某科技有限公司".to_string()),
            openim_realname: Some("张三".to_string()),
        });
        let m = canonical_raw_values(&ev);
        assert!(!m.contains_key("quan_pin"), "拼音不进 digest (不 supersede)");
        assert!(!m.contains_key("pin_yin_initial"));
        assert!(!m.contains_key("remark_quan_pin"));
        // 第三批头像 3 列 (即使有值) 也不进 digest (用户选 1 不溯源换头像)。
        assert!(!m.contains_key("big_head_url"), "头像不进 digest (第三批 L2-only)");
        assert!(!m.contains_key("small_head_url"));
        assert!(!m.contains_key("head_img_md5"));
        // 第五批 4 列 (description/flag/chat_room_notify/chat_room_type) 即使有值也不进 digest (L2-only)。
        assert!(
            !m.contains_key("description"),
            "description 不进 digest (第五批 L2-only)"
        );
        assert!(!m.contains_key("flag"), "flag 不进 digest (第五批 L2-only)");
        assert!(!m.contains_key("chat_room_notify"));
        assert!(!m.contains_key("chat_room_type"));
        // 第七批 5 列 + 批 I 2 列 + 标签件 labels + 添加时间件 friend_add_time + 企微件 openim_company/realname
        // (extra_buffer 解出, 即使有值) 也不进 digest (L2-only)。
        for k in [
            "sex",
            "country",
            "province",
            "city",
            "friend_source",
            "signature",
            "moments_cover_url",
            "labels",
            "friend_add_time",
            "openim_company",
            "openim_realname",
        ] {
            assert!(
                !m.contains_key(k),
                "第七/八批/标签/添加时间/企微列不进 digest (L2-only): {k}"
            );
        }
        // 拼音+头像+第五+七批+标签+添加时间+企微仍不进 digest; verify/delete 第二批进 → 字段集恒 8。
        assert_eq!(
            m.len(),
            8,
            "contact digest 字段集恒 8 (拼音/头像/第五七批/标签/添加时间/企微不进; verify/delete 进)"
        );
    }
}
