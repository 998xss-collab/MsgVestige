//! projection — DecodedEvent 各变体 → L2 业务表行 (V3*) 投影 (纯映射, 不碰 db).
//!
//! decode (raw db → DecodedEvent) 的【下游】: 把已解码事件的 raw id/text 字段算 sha + 量字符长度,
//! 产出 L2 业务表行 (storage::V3*), 供 sink 写入. **纯函数无 io** — DecodedEvent 测试可手构,
//! 故本层【不依赖真实 db / decode】 (decode 是上游, 把 raw db 行变 DecodedEvent).
//!
//! ## K-R4
//! L2 业务表**按表策略**存 sha/len/metadata + 明文列 (ADR-426/427: 业务表存明文列 + 对应 _sha JOIN 键;
//! Debug 出口脱敏), 不受隐私模式影响 (archive payload_json 的 plaintext 模式是溯源层, 与 L2 无关).
//! 投影把 id 类算 sha + 存明文、text 类算 len + 存明文 (同源双轨 ADR-426 §2.7.1).
//!
//! PR2-9-a: project_message (模板); 后续 project_person / project_chatroom / ... 照此 pattern.

use crate::decoder::{
    classify_sysmsg, parse_appmsg, parse_card, parse_forward, parse_hongbao_claim, parse_location, parse_media,
    parse_member_events, parse_mentions, parse_sns_interactions, parse_sns_media, parse_voip,
};
use crate::event::avatar::AvatarImageCreate;
use crate::event::bizchat::BizChatContactCreate;
use crate::event::chatroom::{ChatroomCreate, ChatroomMemberAdd};
use crate::event::contact::ContactUpdate;
use crate::event::emoticon::CustomEmoticonCreate;
use crate::event::favorite::FavoriteCreate;
use crate::event::favorite_tag::FavoriteTagCreate;
use crate::event::finder::FinderVisitCreate;
use crate::event::friend_verify::FriendVerifyCreate;
use crate::event::group_pay::GroupPayCreate;
use crate::event::message::MessageCreate;
use crate::event::moment_feed::MomentFeedCreate;
use crate::event::red_envelope::RedEnvelopeCreate;
use crate::event::session::SessionUpdate;
use crate::event::sns::SnsCreate;
use crate::event::sns_notify::SnsNotifyCreate;
use crate::event::system::SystemCursorUpdate;
use crate::event::transfer::TransferCreate;
use crate::sha256_hex;
use crate::state::Watermark;
use crate::storage::{
    V3AvatarImage, V3BizchatUser, V3Chatroom, V3ChatroomMember, V3ChatroomMemberEvent, V3CustomEmoticon, V3Favorite,
    V3FavoriteMedia, V3FavoriteTag, V3FinderVisit, V3FriendVerify, V3GroupPay, V3GroupPayMember, V3Message,
    V3MessageApp, V3MessageCall, V3MessageCard, V3MessageForwardItem, V3MessageHongbaoClaim, V3MessageLocation,
    V3MessageMedia, V3MessageMention, V3Moment, V3MomentFeed, V3MomentInteraction, V3MomentMedia, V3Person,
    V3PersonAlias, V3RedEnvelope, V3Session, V3SnsNotify, V3Transfer,
};

/// char 数 → i64 (字符数非字节; 防 clippy cast 截断 — 超 i64::MAX 字符不可能但兜底).
fn char_len(s: &str) -> i64 {
    i64::try_from(s.chars().count()).unwrap_or(i64::MAX)
}

/// 投影错误 — raw 事件字段转 L2 列类型失败.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    /// server_id (源 db 给的 String) 不是合法整数 — L2 message.server_id 是 INTEGER.
    /// (server_id 是元数据非隐私, 错误带原值便于排查.)
    #[error("server_id is not a valid integer: {value:?}")]
    ServerIdNotInteger { value: String },
}

/// 投影 (message, create) 事件 → L2 message 行 ([`V3Message`]).
///
/// - id 类 (account_id / conv_id / sender_wxid) → sha256 hex;
/// - text_content → sha256 hex + char 长度;
/// - server_id (源 db String) → parse i64 (源应为数字);
/// - 元数据 (create_time / msg_type / is_chatroom / decode_kind / ...) 直传 (i32 拓 i64).
///
/// L2 表无明文列, 总是脱敏 (不看 PrivacyMode).
///
/// # Errors
/// [`ProjectionError::ServerIdNotInteger`]: server_id 非整数.
pub fn project_message(ev: &MessageCreate) -> Result<V3Message, ProjectionError> {
    let server_id = ev
        .server_id
        .parse::<i64>()
        .map_err(|_| ProjectionError::ServerIdNotInteger {
            value: ev.server_id.clone(),
        })?;
    Ok(V3Message {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        conv_id_sha: sha256_hex(&ev.conv_id),
        server_id,
        server_seq: ev.server_seq,
        origin_source: ev.origin_source,
        upload_status: ev.upload_status,
        download_status: ev.download_status,
        create_time: ev.create_time,
        sort_seq: ev.sort_seq,
        status: i64::from(ev.status),
        msg_type: i64::from(ev.msg_type),
        msg_type_name: ev.msg_type_name.clone(),
        msg_sub_type: ev.msg_sub_type.map(i64::from),
        msg_sub_type_name: ev.msg_sub_type_name.clone(),
        local_type_raw: ev.local_type_raw,
        sender_wxid_sha: sha256_hex(ev.sender_wxid.as_str()),
        is_chatroom: ev.is_chatroom,
        text_content_sha: sha256_hex(&ev.text_content),
        text_content_len: char_len(&ev.text_content),
        raw_xml_present: ev.raw_xml_present,
        decode_kind: ev.decode_kind.clone(),
        // 批F: 系统消息 (msg_type 10000) 按内容分类 → sys_type; 非系统消息 None (不落标签)。
        sys_type: (ev.msg_type == 10000).then(|| classify_sysmsg(&ev.text_content).to_string()),
        // 明文列与对应 _sha **同源** (ADR-426 §2.7.1 双轨一致, 调用方不分别传入)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        conv_id: ev.conv_id.clone(),
        sender_wxid: ev.sender_wxid.as_str().to_string(),
        text_content: ev.text_content.clone(),
    })
}

/// 投影 (contact_update, create) 事件 → L2 person 行 ([`V3Person`]). **infallible** (无 parse).
///
/// - `username` (id 类) → sha256; `nick_name`/`remark`/`alias` (display 类) → 【只量 char 长度】;
///   (display 名的 sha 不进 person 表 — 仅 nick_name/remark 的 sha 在 person_alias_by_account_min
///    [§3.1.5 该表只 remark_sha + nick_name_sha 两列]; alias 无 sha 列, 只在 person 表留 alias_len;
///    别名表由 [`project_person_alias`] 同步投 — 同一 ContactUpdate 两投, 互补);
/// - `remark`/`alias` 可空 → None 计 0 长度 (V3Person 的 `_len` 是 NOT NULL);
/// - `local_type` i32→i64; `is_in_chat_room` 直传.
#[must_use]
pub fn project_person(ev: &ContactUpdate) -> V3Person {
    V3Person {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        username_sha: sha256_hex(&ev.username),
        // 明文列与上面 _sha **同源** (都取 ev 的明文值 — ADR-426 §2.7.1 双轨一致, 调用方不分别传入)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        username: ev.username.clone(),
        nick_name: ev.nick_name.clone(),
        remark: ev.remark.clone(),
        alias: ev.alias.clone(),
        nick_name_len: char_len(&ev.nick_name),
        remark_len: ev.remark.as_deref().map_or(0, char_len),
        alias_len: ev.alias.as_deref().map_or(0, char_len),
        local_type: i64::from(ev.local_type),
        is_in_chat_room: ev.is_in_chat_room,
        // 拼音搜索列 (明文直传; 不进 content_digest — 派生自 nick/remark)。
        quan_pin: ev.quan_pin.clone(),
        pin_yin_initial: ev.pin_yin_initial.clone(),
        remark_quan_pin: ev.remark_quan_pin.clone(),
        remark_pin_yin_initial: ev.remark_pin_yin_initial.clone(),
        // 状态标志 (元数据直传; 进 content_digest — 独立状态溯源, 第二批)。
        verify_flag: ev.verify_flag,
        delete_flag: ev.delete_flag,
        // 头像列 (资源明文直传; 不进 content_digest — 第三批, 用户选 1 不溯源换头像)。
        big_head_url: ev.big_head_url.clone(),
        small_head_url: ev.small_head_url.clone(),
        head_img_md5: ev.head_img_md5.clone(),
        // 第五批 (明文直传; 只进 L2 不进 content_digest — 同头像先例)。
        description: ev.description.clone(),
        flag: ev.flag,
        chat_room_notify: ev.chat_room_notify,
        chat_room_type: ev.chat_room_type,
        // 第七批 (extra_buffer 解出; 只进 L2 不进 content_digest)。
        sex: ev.sex,
        country: ev.country.clone(),
        province: ev.province.clone(),
        city: ev.city.clone(),
        friend_source: ev.friend_source,
        // 批 I (extra_buffer 再解; 只进 L2 不进 content_digest)。signature 个性签名 / moments_cover_url 朋友圈封面。
        signature: ev.signature.clone(),
        moments_cover_url: ev.moments_cover_url.clone(),
        // 标签件 (extra_buffer f30 + contact_label map 解出; 只进 L2 不进 content_digest)。联系人标签名逗号分隔。
        labels: ev.labels.clone(),
        // 添加时间件 (ADR-486): 好友添加时间 (extra_buffer f41; 只进 L2 不进 content_digest)。
        friend_add_time: ev.friend_add_time,
        // 企微件: 企微 (@openim) 公司名/实名 (extra_buffer f4 内层 custom_info; 只进 L2 不进 content_digest)。
        openim_company: ev.openim_company.clone(),
        openim_realname: ev.openim_realname.clone(),
        // 批G flag 位解码 (2026-07-08 用户真机 ground-truth: 改设置 diff flag 坐实, ADR-503; 星标另竞品交叉验)。
        is_starred: flag_bit(ev.flag, 6),
        is_pinned: flag_bit(ev.flag, 11),
        // ⭐bit8 = 不让她看我 (屏蔽朋友圈/她看不到我) — 真机测坐实; 早先误用 bit16 (纠正 ADR-459)。
        blocks_moments: flag_bit(ev.flag, 8),
        chat_only: flag_bit(ev.flag, 23),
        // ⭐bit16 = 不看她 (我不看她的朋友圈) — 与 blocks_moments 是两个不同设置; 真机测坐实。
        hide_their_moments: flag_bit(ev.flag, 16),
        // 三档小补丁 (ADR-479): 折叠的群聊 bit28(0x10000000; CipherTalk sessionList.ts:170; 批G漏此位)。
        is_collapsed: flag_bit(ev.flag, 28),
        // 免打扰 (派生自 local_type+chat_room_notify; 只进 L2 不进 content_digest — 用户 2026-07-04 真人核对确认方向)。
        // 群(local_type=2) chat_room_notify=0 → 免打扰 (真库 1202静音/625提醒); 个人好友该字段无区分度(几乎全0) → 一律 false。
        is_muted: ev.local_type == 2 && ev.chat_room_notify == 0,
    }
}

/// 取 contact.flag 的第 `bit`(0-based) 位。位定义采同行 WDA(`generate_wechat_db_config.py` 注 + `routers/chat.py`
/// `_contact_flag_is_top`=`(flag>>11)&1` 实证): 星标 bit6(WDA 第7位) / 置顶 bit11(第12位) /
/// 屏蔽朋友圈 bit16(第17位) / 仅聊天 bit23(第24位)。负 flag(高位符号)按 u64 位取(与 WDA 一致)。
#[allow(clippy::cast_sign_loss)] // 有意按位重解释 i64→u64 (负 flag 高位符号当数据位, 与 WDA 一致)
fn flag_bit(flag: i64, bit: u32) -> bool {
    ((flag as u64 >> bit) & 1) == 1
}

/// 投影 (session_update, create) → L2 session 行 ([`V3Session`]). **infallible**.
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。summary (text_content) / last_sender (display_name) 仿 person:
/// 存明文 + `_len`, 不存 `_sha` (payload 脱敏模式现算 sha256; 表层全程明文 ADR-427)。
/// `sort_timestamp` 进表 (排序用) 但不进 content_digest (临时, canonical.rs)。
#[must_use]
pub fn project_session(ev: &SessionUpdate) -> V3Session {
    V3Session {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        username_sha: sha256_hex(&ev.username),
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        username: ev.username.clone(),
        unread_count: ev.unread_count,
        last_msg_type: ev.last_msg_type,
        last_msg_sub_type: ev.last_msg_sub_type,
        sort_timestamp: ev.sort_timestamp,
        summary_len: ev.summary.as_deref().map_or(0, char_len),
        summary: ev.summary.clone(),
        last_sender_len: ev.last_sender_display_name.as_deref().map_or(0, char_len),
        last_sender_display_name: ev.last_sender_display_name.clone(),
        // 会话状态列 (session_type/is_hidden/status 元数据直传; draft 明文+_len 同 summary; 进 L2 不进 digest)。
        session_type: ev.session_type,
        is_hidden: ev.is_hidden,
        status: ev.status,
        draft_len: ev.draft.as_deref().map_or(0, char_len),
        draft: ev.draft.clone(),
        // 第六批 (last_msg_sender 明文直传 / 5 元数据直传; 只进 L2 不进 content_digest — 同第四批状态列)。
        last_msg_sender: ev.last_msg_sender.clone(),
        last_timestamp: ev.last_timestamp,
        last_clear_unread_timestamp: ev.last_clear_unread_timestamp,
        last_msg_locald_id: ev.last_msg_locald_id,
        last_msg_ext_type: ev.last_msg_ext_type,
        unread_first_msg_srv_id: ev.unread_first_msg_srv_id,
    }
}

/// 投影 (message, create) 的 appmsg 卡片 → L2 message_app 行 ([`V3MessageApp`], ADR-455)。
///
/// 解 ev.text_content 的 `<appmsg>` XML (视频号/小程序/链接); **非 appmsg 消息返 None** (不落 message_app)。
/// **派生自 text_content** (已在 message content_digest) → message_app 表 L2-only, 不进 digest/payload。
#[must_use]
pub fn project_message_app(ev: &MessageCreate) -> Option<V3MessageApp> {
    // codex 批C P1: 只 APP_XML (msg_type 49) 才是 appmsg 卡片 — 防普通文本消息正文恰含 <appmsg> 误落 (如聊天转述)。
    if ev.msg_type != 49 {
        return None;
    }
    let card = parse_appmsg(&ev.text_content)?;
    Some(V3MessageApp {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        app_type: card.app_type,
        media_count: card.media_count,
        account_id: ev.provenance.account_id.as_str().to_string(),
        title: card.title,
        source_name: card.source_name,
        url: card.url,
        app_username: card.app_username,
        app_nickname: card.app_nickname,
        app_pagepath: card.app_pagepath,
        // 类型专属细节 (ADR-462: 文件/转账/引用/合并转发)。
        file_size: card.file_size,
        file_ext: card.file_ext,
        file_md5: card.file_md5,
        transfer_fee: card.transfer_fee,
        transfer_direction: card.transfer_direction,
        transfer_txid: card.transfer_txid,
        refer_svrid: card.refer_svrid,
        refer_type: card.refer_type,
        refer_content: card.refer_content,
        forward_item_count: card.forward_item_count,
        // 群收款金额 + 单号 (ADR-487: type 2001 带 newaa 从消息 XML 抽; 已付/参与人列表本地空只金额)。
        group_pay_amount: card.group_pay_amount,
        group_pay_bill_no: card.group_pay_bill_no,
        // 红包祝福语 + 个数 (ADR-468 §7.3: type 2001 从消息 XML 补; 金额确认死路不在此表)。
        red_envelope_wish: card.red_envelope_wish,
        red_envelope_count: card.red_envelope_count,
        // 音乐/礼物/直播 (ADR-462 扩; type 92/115/63)。
        music_desc: card.music_desc,
        gift_wish: card.gift_wish,
        gift_sku: card.gift_sku,
        live_status: card.live_status,
        live_desc: card.live_desc,
        // 支付场景类别名 (ADR-495; type 2000/2001 scenetext)。
        pay_scene_text: card.pay_scene_text,
    })
}

/// 投影 (message, create) 的媒体元数据 → L2 message_media 行 ([`V3MessageMedia`], ADR-456)。
///
/// 解 ev.text_content 的 `<img>`/`<videomsg>`/`<emoji>` XML (msg_type 3/43/47); **非媒体消息 / 无 md5 且无
/// cdn_url → None** (不落 message_media)。**派生自 text_content** (已在 message content_digest) →
/// message_media 表 L2-only, 不进 digest/payload。
#[must_use]
pub fn project_message_media(ev: &MessageCreate) -> Option<V3MessageMedia> {
    let card = parse_media(ev.msg_type, &ev.text_content)?;
    Some(V3MessageMedia {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        media_kind: card.media_kind.as_str().to_string(),
        file_size: card.file_size,
        play_length: card.play_length,
        account_id: ev.provenance.account_id.as_str().to_string(),
        md5: card.md5,
        aes_key: card.aes_key,
        cdn_url: card.cdn_url,
        thumb_url: card.thumb_url,
        extra_id: card.extra_id,
    })
}

/// 投影 (message, create) 的位置元数据 → L2 message_location 行 ([`V3MessageLocation`], ADR-462)。
///
/// 解 ev.text_content 的 `<location>` XML (msg_type 48); **非位置消息 / 无坐标 → None** (不落)。
/// **派生自 text_content** (已在 message content_digest) → message_location 表 L2-only, 不进 digest/payload。
#[must_use]
pub fn project_message_location(ev: &MessageCreate) -> Option<V3MessageLocation> {
    let card = parse_location(ev.msg_type, &ev.text_content)?;
    Some(V3MessageLocation {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        scale: card.scale,
        account_id: ev.provenance.account_id.as_str().to_string(),
        latitude: card.latitude,
        longitude: card.longitude,
        label: card.label,
        poiname: card.poiname,
        poiid: card.poiid,
        maptype: card.maptype,
        adcode: card.adcode,
        cityname: card.cityname,
    })
}

/// 投影 (message, create) 的通话元数据 → L2 message_call 行 ([`V3MessageCall`], ADR-475)。
///
/// 解 ev.text_content 的 `<voipmsg>` XML (msg_type 50); **非通话消息 / 无 voipmsg → None** (不落)。
/// **派生自 text_content** (已在 message content_digest) → message_call 表 L2-only, 不进 digest/payload。
#[must_use]
pub fn project_message_call(ev: &MessageCreate) -> Option<V3MessageCall> {
    let card = parse_voip(ev.msg_type, &ev.text_content)?;
    Some(V3MessageCall {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        invite_type: card.invite_type,
        room_type: card.room_type,
        call_state: card.call_state,
        duration: card.duration,
        account_id: ev.provenance.account_id.as_str().to_string(),
        display_content: card.display_content,
    })
}

/// 投影 (message, create) 的红包领取通知 → L2 message_hongbao_claim 行 ([`V3MessageHongbaoClaim`], ADR-504)。
///
/// 解 ev.text_content 的 sys=hongbao 领取通知 ("{A}领取了你的红包" / "你领取了{B}的红包"); **非领取通知 → None**。
/// **派生自 text_content** (已在 message content_digest) → L2-only, 不进 digest/payload。**金额不含** (微信不写进消息)。
#[must_use]
pub fn project_message_hongbao_claim(ev: &MessageCreate) -> Option<V3MessageHongbaoClaim> {
    let claim = parse_hongbao_claim(ev.msg_type, &ev.text_content)?;
    Some(V3MessageHongbaoClaim {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        send_id: claim.send_id,
        is_own_envelope: claim.is_own_envelope,
        account_id: ev.provenance.account_id.as_str().to_string(),
        peer_name: claim.peer_name,
    })
}

/// 投影 (message, create) 的 @提及名单 → L2 message_mention 行 ([`V3MessageMention`], ADR-457)。
///
/// 解 ev.msg_source 的 `<atuserlist>` (群消息 @谁); 无 @ → 空 Vec。**一消息多@ → 多行** (区别 message_app/media
/// 一消息一行)。**派生自 source 列** (非 message 身份字段) → message_mention 表 L2-only, 不进 digest/payload。
#[must_use]
pub fn project_message_mention(ev: &MessageCreate) -> Vec<V3MessageMention> {
    // codex 批E P2: @提及只在群消息 (单聊无 @所有人/@某人语义)。防单聊 source 恰含 <atuserlist> 误落。
    if !ev.is_chatroom {
        return Vec::new();
    }
    let account_id_sha = sha256_hex(ev.provenance.account_id.as_str());
    let account_id = ev.provenance.account_id.as_str().to_string();
    parse_mentions(&ev.msg_source)
        .into_iter()
        .map(|m| V3MessageMention {
            account_id_sha: account_id_sha.clone(),
            source: ev.provenance.source.clone(),
            source_native_id: ev.provenance.source_native_id.clone(),
            mentioned_wxid_sha: sha256_hex(&m.wxid),
            is_at_all: m.is_at_all,
            account_id: account_id.clone(),
            mentioned_wxid: m.wxid,
        })
        .collect()
}

/// 投影 (message, create) 的群成员进出事件 → L2 chatroom_member_event 行 ([`V3ChatroomMemberEvent`])。
///
/// guard `msg_type == 10000` (群成员系统消息), classify_sysmsg 确认 member_join/member_remove,
/// parse_member_events(ev.text_content) → 每 MemberEvent 一行。**一消息多成员 → 多行**:
/// `source_native_id = message anchor + ":" + seq` (逐行唯一序号, 保 PK 不塌陷 — remove 无 wxid 也不撞);
/// `msg_native_id` = 裸 message anchor (供 sink replace-projection 删整组)。conv_id=ev.conv_id、
/// event_time=ev.create_time。**派生自 text_content** (系统消息文本已在 message digest) → L2-only 不进 digest/payload。
/// 非 10000 / 非进出事件 / 非群聊 → 空 Vec。
#[must_use]
pub fn project_chatroom_member_events(ev: &MessageCreate) -> Vec<V3ChatroomMemberEvent> {
    // 群成员系统消息只在群聊 (单聊无进出事件); msg_type 10000 才是系统消息。
    if ev.msg_type != 10000 || !ev.is_chatroom {
        return Vec::new();
    }
    let account_id_sha = sha256_hex(ev.provenance.account_id.as_str());
    let account_id = ev.provenance.account_id.as_str().to_string();
    let conv_id_sha = sha256_hex(&ev.conv_id);
    let msg_native_id = ev.provenance.source_native_id.clone();
    parse_member_events(&ev.text_content)
        .into_iter()
        .enumerate()
        .map(|(seq, m)| V3ChatroomMemberEvent {
            account_id_sha: account_id_sha.clone(),
            source: ev.provenance.source.clone(),
            // 一消息多成员逐行唯一: 裸 anchor + ':' + 0 基序号 (remove 无 wxid 也保 PK 不塌陷)。
            source_native_id: format!("{msg_native_id}:{seq}"),
            msg_native_id: msg_native_id.clone(),
            conv_id_sha: conv_id_sha.clone(),
            member_wxid_sha: m.member_wxid.as_deref().map(sha256_hex),
            event_kind: m.kind.to_string(),
            inviter_wxid_sha: m.inviter_wxid.as_deref().map(sha256_hex),
            event_time: ev.create_time,
            account_id: account_id.clone(),
            conv_id: ev.conv_id.clone(),
            member_wxid: m.member_wxid,
            member_nickname: m.member_nickname,
            inviter_wxid: m.inviter_wxid,
        })
        .collect()
}

/// 投影 (message, create) 的群收款付款人名单 → L2 group_pay_member 行 (Vec, ADR-488)。
///
/// 解 ev.text_content 的 appmsg (type 2001 带 `<newaa>`) 的 payerlist; **一群收款消息多付款人 → 多行**。
/// 已付人数 = 行数。**派生自 text_content** (已在 message digest) → group_pay_member 表 L2-only, 不进 digest/payload。
/// 非 appmsg (msg_type≠49) / 非群收款 (无 billno) / 无付款人 → 空 Vec。
#[must_use]
pub fn project_group_pay_members(ev: &MessageCreate) -> Vec<V3GroupPayMember> {
    if ev.msg_type != 49 {
        return Vec::new();
    }
    let Some(card) = parse_appmsg(&ev.text_content) else {
        return Vec::new();
    };
    let (Some(bill_no), false) = (card.group_pay_bill_no, card.group_pay_members.is_empty()) else {
        return Vec::new();
    };
    let account_id_sha = sha256_hex(ev.provenance.account_id.as_str());
    let account_id = ev.provenance.account_id.as_str().to_string();
    card.group_pay_members
        .into_iter()
        .map(|(payer, amount, status)| V3GroupPayMember {
            account_id_sha: account_id_sha.clone(),
            source: ev.provenance.source.clone(),
            source_native_id: ev.provenance.source_native_id.clone(),
            payer_wxid_sha: sha256_hex(&payer),
            bill_no: bill_no.clone(),
            amount,
            pay_status: status,
            account_id: account_id.clone(),
            payer_wxid: payer,
        })
        .collect()
}

/// 投影 (message, create) 的名片信息 → L2 message_card 行 ([`V3MessageCard`], ADR-477)。
///
/// 解 ev.text_content 的 `<msg>` 属性 (msg_type 42); **非名片 / 无 username → None** (不落)。
/// **派生自 text_content** (已在 message content_digest) → message_card 表 L2-only, 不进 digest/payload。
#[must_use]
pub fn project_message_card(ev: &MessageCreate) -> Option<V3MessageCard> {
    let card = parse_card(ev.msg_type, &ev.text_content)?;
    Some(V3MessageCard {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        card_sex: card.sex,
        account_id: ev.provenance.account_id.as_str().to_string(),
        card_username: card.username,
        card_nickname: card.nickname,
        card_alias: card.alias,
        card_province: card.province,
        card_city: card.city,
        card_sign: card.sign,
        card_open_im_desc: card.open_im_desc,
        big_head_url: card.big_head_url,
        small_head_url: card.small_head_url,
    })
}

/// 投影 (message, create) 的合并转发子项 → L2 message_forward_item 行 ([`V3MessageForwardItem`], ADR-476)。
///
/// 解 ev.text_content 的 `<recorditem>` datalist (msg_type 49 子类 19); 非转发 → 空 Vec。**一转发多子项 → 多行**。
/// **派生自 text_content** (已在 message content_digest) → message_forward_item 表 L2-only, 不进 digest/payload。
#[must_use]
pub fn project_message_forward(ev: &MessageCreate) -> Vec<V3MessageForwardItem> {
    let account_id_sha = sha256_hex(ev.provenance.account_id.as_str());
    let account_id = ev.provenance.account_id.as_str().to_string();
    parse_forward(ev.msg_type, &ev.text_content)
        .into_iter()
        .map(|it| V3MessageForwardItem {
            account_id_sha: account_id_sha.clone(),
            source: ev.provenance.source.clone(),
            source_native_id: ev.provenance.source_native_id.clone(),
            seq: it.seq,
            data_type: it.data_type,
            data_size: it.data_size,
            account_id: account_id.clone(),
            source_name: it.source_name,
            source_time: it.source_time,
            data_title: it.data_title,
            data_desc: it.data_desc,
            media_md5: it.media_md5,
        })
        .collect()
}

/// 投影 (favorite_update, create) → L2 favorite 行 ([`V3Favorite`]). **infallible** (ADR-454)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`from_user` (id 类) → from_user_sha + 明文; `real_chat_name` (id 类,
/// nullable) / `source_id` (hash id, nullable) → 明文直传。content 本身不落 (只 content_len)。
#[must_use]
pub fn project_favorite(ev: &FavoriteCreate) -> V3Favorite {
    V3Favorite {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        server_id: ev.server_id,
        local_id: ev.local_id,
        fav_type: ev.fav_type,
        update_time: ev.update_time,
        from_user_sha: sha256_hex(&ev.from_user),
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        from_user: ev.from_user.clone(),
        real_chat_name: ev.real_chat_name.clone(),
        source_id: ev.source_id.clone(),
        content_len: ev.content_len,
        // 笔记正文 (ADR-471; L2-only 明文; 仅 type 18 非空)。
        note_text: ev.note_text.clone(),
    }
}

/// 投影 (favorite, create) 的媒体引用 → L2 favorite_media 行 ([`V3FavoriteMedia`], ADR-472)。
///
/// 一收藏多媒体 → **Vec**(无媒体 空 Vec)。**派生自 favorite content** → favorite_media L2-only 不进 digest/payload。
#[must_use]
pub fn project_favorite_media(ev: &FavoriteCreate) -> Vec<V3FavoriteMedia> {
    let account_id_sha = sha256_hex(ev.provenance.account_id.as_str());
    let account_id = ev.provenance.account_id.as_str().to_string();
    ev.media
        .iter()
        .map(|m| V3FavoriteMedia {
            account_id_sha: account_id_sha.clone(),
            source: ev.provenance.source.clone(),
            source_native_id: ev.provenance.source_native_id.clone(),
            seq: m.seq,
            fav_server_id: ev.server_id,
            account_id: account_id.clone(),
            data_type: m.data_type,
            media_md5: m.media_md5.clone(),
            media_size: m.media_size,
            data_fmt: m.data_fmt.clone(),
        })
        .collect()
}

/// 投影 (transfer_update, create) → L2 transfer 行 ([`V3Transfer`]). **infallible** (ADR-468)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`session_name`/`pay_payer`/`pay_receiver` (id 类) → _sha + 明文;
/// transfer_id/transcation_id (交易单号非 wxid) → 明文直传。金额不在本表 (只搬账号/状态/时间 + 消息链接)。
#[must_use]
pub fn project_transfer(ev: &TransferCreate) -> V3Transfer {
    V3Transfer {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        transfer_id: ev.transfer_id.clone(),
        transcation_id: ev.transcation_id.clone(),
        message_server_id: ev.message_server_id,
        second_message_server_id: ev.second_message_server_id,
        pay_sub_type: ev.pay_sub_type,
        session_name_sha: sha256_hex(&ev.session_name),
        pay_payer_sha: sha256_hex(&ev.pay_payer),
        pay_receiver_sha: sha256_hex(&ev.pay_receiver),
        begin_transfer_time: ev.begin_transfer_time,
        last_modified_time: ev.last_modified_time,
        invalid_time: ev.invalid_time,
        last_update_time: ev.last_update_time,
        delay_confirm_flag: ev.delay_confirm_flag,
        bubble_clicked_flag: ev.bubble_clicked_flag,
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        session_name: ev.session_name.clone(),
        pay_payer: ev.pay_payer.clone(),
        pay_receiver: ev.pay_receiver.clone(),
    }
}

/// 投影 (red_envelope_update, create) → L2 red_envelope 行 ([`V3RedEnvelope`]). **infallible** (ADR-468 件2)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`session_name`/`sender_user_name` (id 类) → _sha + 明文; send_id (红包单号
/// 非 wxid) 明文; `native_url` (嵌 wxid) 明文直传 (供后置件取详情; Debug/payload 出口才脱敏)。
#[must_use]
pub fn project_red_envelope(ev: &RedEnvelopeCreate) -> V3RedEnvelope {
    V3RedEnvelope {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        send_id: ev.send_id.clone(),
        message_server_id: ev.message_server_id,
        sender_user_name_sha: sha256_hex(&ev.sender_user_name),
        session_name_sha: sha256_hex(&ev.session_name),
        scene_id: ev.scene_id,
        hb_status: ev.hb_status,
        hb_type: ev.hb_type,
        receive_status: ev.receive_status,
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        native_url: ev.native_url.clone(),
        account_id: ev.provenance.account_id.as_str().to_string(),
        sender_user_name: ev.sender_user_name.clone(),
        session_name: ev.session_name.clone(),
    }
}

/// 投影 (group_pay_update, create) → L2 group_pay 行 ([`V3GroupPay`]). **infallible** (ADR-468 件3)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`session_name` (id 类) → _sha + 明文; bill_no (账单号非 wxid) 明文直传。
#[must_use]
pub fn project_group_pay(ev: &GroupPayCreate) -> V3GroupPay {
    V3GroupPay {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        bill_no: ev.bill_no.clone(),
        message_local_id: ev.message_local_id,
        message_create_time: ev.message_create_time,
        session_name_sha: sha256_hex(&ev.session_name),
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        session_name: ev.session_name.clone(),
    }
}

/// 投影 (friend_verify_update, create) → L2 friend_verify 行 ([`V3FriendVerify`]). **infallible** (ADR-469)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`user_name` (id 类) → _sha + 明文; `content` (打招呼语 text 类) 明文 +
/// content_len (字符数)。
#[must_use]
pub fn project_friend_verify(ev: &FriendVerifyCreate) -> V3FriendVerify {
    V3FriendVerify {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        user_name_sha: sha256_hex(&ev.user_name),
        friend_type: ev.friend_type,
        timestamp: ev.timestamp,
        is_sender: ev.is_sender,
        scene: ev.scene,
        content_len: char_len(&ev.content),
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        user_name: ev.user_name.clone(),
        content: ev.content.clone(),
    }
}

/// 投影 (finder_visit_update, create) → L2 finder_visit 行 ([`V3FinderVisit`]). **infallible** (ADR-473)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`owner_username` (号主 id 类) → _sha + 明文; `name` (昵称 display) /
/// `profile_url` (主页 URL 元数据 L2-only) 明文直传。`visit_time` = 访问时刻秒。
#[must_use]
pub fn project_finder_visit(ev: &FinderVisitCreate) -> V3FinderVisit {
    V3FinderVisit {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        owner_username_sha: sha256_hex(&ev.owner_username),
        visit_time: ev.visit_time,
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        owner_username: ev.owner_username.clone(),
        name: ev.name.clone(),
        profile_url: ev.profile_url.clone(),
    }
}

/// 投影 (custom_emoticon_update, create) → L2 custom_emoticon 行 ([`V3CustomEmoticon`]). **infallible** (ADR-478)。
///
/// 全明文直传 (ADR-427)。`md5` (身份) / `caption` / `emoticon_type` 进 digest; aes_key/urls/product_id 只进 L2。
#[must_use]
pub fn project_custom_emoticon(ev: &CustomEmoticonCreate) -> V3CustomEmoticon {
    V3CustomEmoticon {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        md5: ev.md5.clone(),
        emoticon_type: ev.emoticon_type,
        caption: ev.caption.clone(),
        account_id: ev.provenance.account_id.as_str().to_string(),
        product_id: ev.product_id.clone(),
        aes_key: ev.aes_key.clone(),
        cdn_url: ev.cdn_url.clone(),
        thumb_url: ev.thumb_url.clone(),
        tp_url: ev.tp_url.clone(),
        extern_url: ev.extern_url.clone(),
        extern_md5: ev.extern_md5.clone(),
        encrypt_url: ev.encrypt_url.clone(),
    }
}

/// 投影 (biz_chat_contact_update, create) → L2 bizchat_user 行 ([`V3BizchatUser`]). **infallible** (ADR-482)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`user_id` (企微 wxid, id 类) → _sha + 明文; `brand_user_name`/
/// `user_name` 进 digest; `head_img_url`/`profile_url`/`bit_flag` 只进 L2。
#[must_use]
pub fn project_bizchat_user(ev: &BizChatContactCreate) -> V3BizchatUser {
    V3BizchatUser {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        user_id_sha: sha256_hex(&ev.user_id),
        brand_user_name: ev.brand_user_name.clone(),
        user_name: ev.user_name.clone(),
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        user_id: ev.user_id.clone(),
        head_img_url: ev.head_img_url.clone(),
        profile_url: ev.profile_url.clone(),
        bit_flag: ev.bit_flag,
    }
}

/// 投影 (avatar_image_update, create) → L2 avatar_image 行 ([`V3AvatarImage`]). **infallible** (ADR-481)。
#[must_use]
pub fn project_avatar(ev: &AvatarImageCreate) -> V3AvatarImage {
    V3AvatarImage {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        username_sha: sha256_hex(&ev.username),
        md5: ev.md5.clone(),
        account_id: ev.provenance.account_id.as_str().to_string(),
        username: ev.username.clone(),
        image_buffer: ev.image_buffer.clone(),
        update_time: ev.update_time,
    }
}

/// 投影 (moment_feed_update, create) → L2 moment_feed 行 ([`V3MomentFeed`]). **infallible** (ADR-474)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`author` (发布者 id 类) → _sha + 明文; `tid`/`create_time` 进 digest;
/// `last_read_time`/`is_read` (读状态) 只进 L2。
#[must_use]
pub fn project_moment_feed(ev: &MomentFeedCreate) -> V3MomentFeed {
    V3MomentFeed {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        tid: ev.tid,
        author_sha: sha256_hex(&ev.author),
        create_time: ev.create_time,
        last_read_time: ev.last_read_time,
        is_read: ev.is_read,
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        author: ev.author.clone(),
    }
}

/// 投影 (sns_notify_update, create) → L2 sns_notify 行 ([`V3SnsNotify`]). **infallible** (照 moment_feed ADR-474)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`from_user`/`to_user` (id 类) → _sha + 明文;
/// `comment_id`/`feed_id`/`notify_type`/`create_time` 进 digest; 其余 (昵称/评论文本/读状态) 只进 L2。
#[must_use]
pub fn project_sns_notify(ev: &SnsNotifyCreate) -> V3SnsNotify {
    V3SnsNotify {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        comment_id: ev.comment_id,
        feed_id: ev.feed_id,
        notify_type: ev.notify_type,
        from_user_sha: sha256_hex(&ev.from_user),
        create_time: ev.create_time,
        to_user_sha: ev.to_user.as_deref().map(sha256_hex),
        is_unread: ev.is_unread,
        del_status: ev.del_status,
        is_relative_me: ev.is_relative_me,
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        from_user: ev.from_user.clone(),
        to_user: ev.to_user.clone(),
        from_nickname: ev.from_nickname.clone(),
        to_nickname: ev.to_nickname.clone(),
        content: ev.content.clone(),
    }
}

/// 投影 (sns_event, create) → L2 moment 行 ([`V3Moment`]). **infallible** (ADR-467 件1)。
///
/// 明文列与 _sha 同源 (ADR-426 §2.7.1)。`author` (id 类) → author_sha + 明文; `content_desc` (text 类) 明文 +
/// content_desc_len (char 数, 同 message text_content); `author_nickname`/`source_user`/`location_label`/`title`/
/// `link_url` (nullable) → 明文直传。content 本身不落 (只 content_len)。经纬度原值直传。
#[must_use]
pub fn project_moment(ev: &SnsCreate) -> V3Moment {
    V3Moment {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        tid: ev.tid,
        author_sha: sha256_hex(&ev.author),
        create_time: ev.create_time,
        moment_type: ev.moment_type,
        // 明文列与上面 _sha 同源 (ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        author: ev.author.clone(),
        author_nickname: ev.author_nickname.clone(),
        content_desc: ev.content_desc.clone(),
        content_desc_len: char_len(&ev.content_desc),
        source_user: ev.source_user.clone(),
        location_label: ev.location_label.clone(),
        latitude: ev.latitude,
        longitude: ev.longitude,
        title: ev.title.clone(),
        link_url: ev.link_url.clone(),
        media_count: ev.media_count,
        like_count: ev.like_count,
        comment_count: ev.comment_count,
        // 补列 (ADR-491): content XML 边角字段 (L2-only 不进 digest)。
        source_nickname: ev.source_nickname.clone(),
        is_bidirectional_fan: ev.is_bidirectional_fan,
        is_rich_text: ev.is_rich_text,
        public_user_name: ev.public_user_name.clone(),
        app_name: ev.app_name.clone(),
        content_len: ev.content_len,
    }
}

/// 投影 (sns_event, create) 的逐条媒体 → L2 moment_media 行 ([`V3MomentMedia`], ADR-467 件2a)。
///
/// 解 ev.raw_content (载体) 的 `<mediaList><media>…`; 无媒体 → 空 Vec。**一动态多媒体 → 多行** (media_seq 区分,
/// 同 message_mention)。**派生自 content XML** (content 不落但结构化媒体引用落) → moment_media 表 L2-only,
/// 不进 digest/payload。url/key (媒体资源+解密密钥) 明文列 (ADR-427)。
#[must_use]
pub fn project_moment_media(ev: &SnsCreate) -> Vec<V3MomentMedia> {
    let account_id_sha = sha256_hex(ev.provenance.account_id.as_str());
    let account_id = ev.provenance.account_id.as_str().to_string();
    parse_sns_media(&ev.raw_content)
        .into_iter()
        .map(|m| V3MomentMedia {
            account_id_sha: account_id_sha.clone(),
            source: ev.provenance.source.clone(),
            source_native_id: ev.provenance.source_native_id.clone(),
            media_seq: m.seq,
            media_type: m.media_type,
            account_id: account_id.clone(),
            media_id: m.media_id,
            url: m.url,
            thumb_url: m.thumb_url,
            md5: m.md5,
            video_md5: m.video_md5,
            url_key: m.url_key,
            enc_idx: m.enc_idx,
            token: m.token,
            enc_key: m.enc_key,
            width: m.width,
            height: m.height,
            total_size: m.total_size,
            video_duration: m.video_duration,
        })
        .collect()
}

/// 投影 (sns_event, create) 的逐条互动 → L2 moment_interaction 行 ([`V3MomentInteraction`], ADR-467 件2b)。
///
/// 解 ev.raw_content 的 `<like_user_list>`(赞) + `<comment_user_list>`(评论); 无互动 → 空 Vec。**一动态多互动 →
/// 多行** (interaction_seq 区分)。**派生自 content XML** → moment_interaction 表 L2-only, 不进 digest/payload。
/// from_user (id 类) → from_user_sha + 明文; content (评论文本)/from_nickname/ref_username 明文列 (ADR-427)。
#[must_use]
pub fn project_moment_interaction(ev: &SnsCreate) -> Vec<V3MomentInteraction> {
    let account_id_sha = sha256_hex(ev.provenance.account_id.as_str());
    let account_id = ev.provenance.account_id.as_str().to_string();
    parse_sns_interactions(&ev.raw_content)
        .into_iter()
        .map(|it| V3MomentInteraction {
            account_id_sha: account_id_sha.clone(),
            source: ev.provenance.source.clone(),
            source_native_id: ev.provenance.source_native_id.clone(),
            interaction_seq: it.seq,
            kind: it.kind.to_string(),
            type_raw: it.type_raw,
            // from_user 可空 (罕见畸形) → sha 空串 (稳定); 有值则 sha256。
            from_user_sha: it.from_user.as_deref().map(sha256_hex).unwrap_or_default(),
            account_id: account_id.clone(),
            from_user: it.from_user,
            from_nickname: it.from_nickname,
            content: it.content,
            comment_id: it.comment_id,
            ref_username: it.ref_username,
            ref_comment_id: it.ref_comment_id,
            create_time: it.create_time,
        })
        .collect()
}

/// 投影 (favorite_tag_update, create) → L2 favorite_tag 行 ([`V3FavoriteTag`]). **infallible** (ADR-454 批 B-2)。
///
/// 一条绑定 = 一行 (标签名去规范化)。tag_name (text_content 类) 明文直传 (ADR-427)。
#[must_use]
pub fn project_favorite_tag(ev: &FavoriteTagCreate) -> V3FavoriteTag {
    V3FavoriteTag {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        tag_server_id: ev.tag_server_id,
        tag_local_id: ev.tag_local_id,
        seq: ev.seq,
        fav_server_id: ev.fav_server_id,
        fav_local_id: ev.fav_local_id,
        op_code: ev.op_code,
        tag_name_len: char_len(&ev.tag_name),
        // 明文列 (ADR-426 §2.1)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        tag_name: ev.tag_name.clone(),
    }
}

/// 投影 (chatroom_update, create) 事件 → L2 chatroom 行 ([`V3Chatroom`]). **infallible**.
///
/// **nullable 区分** (跟 §3.1.6 列 NOT NULL 状态对齐):
/// - `chatroom_id` (id 类) → sha256; `owner_wxid` (id 类, **nullable** → owner_wxid_sha 是 nullable 列)
///   → None 保留 None / Some 算 sha;
/// - `chatroom_name`/`announcement` (display 类) → 【只量 char 长度】; announcement_len 是【NOT NULL】
///   → None 计 0 (不同于 owner_wxid_sha 的 nullable!);
/// - `member_count` 直传.
#[must_use]
pub fn project_chatroom(ev: &ChatroomCreate) -> V3Chatroom {
    V3Chatroom {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        chatroom_id_sha: sha256_hex(&ev.chatroom_id),
        // 明文列与上面 _sha **同源** (都取 ev 明文值 — ADR-426 §2.7.1 双轨一致)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        chatroom_id: ev.chatroom_id.clone(),
        owner_wxid: ev.owner_wxid.clone(),
        chatroom_name: ev.chatroom_name.clone(),
        announcement: ev.announcement.clone(),
        chatroom_name_len: char_len(&ev.chatroom_name),
        announcement_len: ev.announcement.as_deref().map_or(0, char_len),
        member_count: ev.member_count,
        owner_wxid_sha: ev.owner_wxid.as_deref().map(sha256_hex),
        // 批H: 群公告编辑者/发布时间 (L2-only 不进 digest/payload)。
        announcement_editor: ev.announcement_editor.clone(),
        announcement_publish_time: ev.announcement_publish_time,
        // KI-A/B: 富媒体公告 XML (明文列, 存原文) + 群状态位 (原值; L2-only 不进 digest/payload)。
        xml_announcement: ev.xml_announcement.clone(),
        chat_room_status: ev.chat_room_status,
        // 群备注 (L2-only 明文 + _len; 不进 digest/payload)。
        chatroom_remark: ev.chatroom_remark.clone(),
        chatroom_remark_len: ev.chatroom_remark.as_deref().map_or(0, char_len),
        // ADR-493: 我是否仍在此群 (L2-only 不进 digest/payload)。
        is_still_member: ev.is_still_member,
    }
}

/// 投影 (contact_update, create) 事件 → L2 person_alias 行 ([`V3PersonAlias`]). **infallible**.
///
/// person_alias_by_account_min (§3.1.5) 是 message→发送者快速 JOIN 拿 sha 的辅助表:
/// PK 是【2 元组】(account_id_sha, username_sha), 【无】 source/source_native_id 列.
/// 同一 ContactUpdate 既投 person ([`project_person`], 量 _len) 又投本表 (存 _sha) — 两表互补.
/// - account_id_sha / username_sha → sha256; `remark_sha` 可空 (remark None → None);
/// - `nick_name_sha` 必有 Some (nick_name 是 ContactUpdate 必填 String, 非 Option);
/// - **无 alias_sha 列** (§3.1.5 该表只 remark_sha + nick_name_sha; alias 仅在 person 表留 alias_len).
#[must_use]
pub fn project_person_alias(ev: &ContactUpdate) -> V3PersonAlias {
    V3PersonAlias {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        username_sha: sha256_hex(&ev.username),
        remark_sha: ev.remark.as_deref().map(sha256_hex),
        nick_name_sha: Some(sha256_hex(&ev.nick_name)),
        // 明文列与上面 _sha **同源** (ADR-426 §2.7.1 双轨一致)。nick_name 必填 → 明文也恒 Some。
        account_id: ev.provenance.account_id.as_str().to_string(),
        username: ev.username.clone(),
        remark: ev.remark.clone(),
        nick_name: Some(ev.nick_name.clone()),
    }
}

/// 投影 (chatroom_update, member_add) 事件 → L2 chatroom_member 行 ([`V3ChatroomMember`]) 的【新加群状态】.
/// **infallible**. 产物喂 [`crate::storage::upsert_chatroom_member_add`] (INSERT 新 / 同 PK 复活).
///
/// 【fresh-add 语义】 (§6.8 契约3c member_add → is_in_group=1, left_at=NULL):
/// - `is_in_group` 恒 true; `left_at` 恒 None (刚加群没退);
/// - chatroom_id / member_wxid (id 类) → sha256; `display_name` (display, nullable) → 量 char 长度
///   (display_name_len 是 NOT NULL → None 计 0); `joined_at` (nullable 元数据) → 直传 Option.
///
/// **member_remove 不在此投影** — remove 是 [`crate::storage::mark_chatroom_member_left`] 的【UPDATE】
/// (只翻 is_in_group=0 + left_at, 不产整行, 保留 joined_at); 其 left_at 取事件值或 now() 是 sink 装配的活 (推后续).
#[must_use]
pub fn project_chatroom_member_add(ev: &ChatroomMemberAdd) -> V3ChatroomMember {
    V3ChatroomMember {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        source_native_id: ev.provenance.source_native_id.clone(),
        chatroom_id_sha: sha256_hex(&ev.chatroom_id),
        member_wxid_sha: sha256_hex(&ev.member_wxid),
        // 明文列与上面 _sha **同源** (ADR-426 §2.7.1)。member_wxid 明文供退群闭环回读 (§1.1 死结)。
        account_id: ev.provenance.account_id.as_str().to_string(),
        chatroom_id: ev.chatroom_id.clone(),
        member_wxid: ev.member_wxid.clone(),
        display_name: ev.display_name.clone(),
        display_name_len: ev.display_name.as_deref().map_or(0, char_len),
        joined_at: ev.joined_at,
        left_at: None,
        is_in_group: true,
        // 第八批 role (owner/admin/member; L2-only 不进 digest)。
        role: ev.role.clone(),
        // 第九批 invited_by (邀请人 wxid; L2-only)。
        invited_by: ev.invited_by.clone(),
    }
}

/// 投影 (system_event, cursor_update) 事件 → etl_state 水位行 ([`Watermark`]). **infallible**.
///
/// 全元数据无敏感 (account_id_sha 已 sha; source/kind/watermark_*/last_update 是 cursor 描述, 无 wxid/正文):
/// account_id_sha=sha256(account_id); source/kind/watermark_key/watermark_value/last_update 直传.
#[must_use]
pub fn project_watermark(ev: &SystemCursorUpdate) -> Watermark {
    Watermark {
        account_id_sha: sha256_hex(ev.provenance.account_id.as_str()),
        source: ev.provenance.source.clone(),
        kind: ev.kind.clone(),
        watermark_key: ev.watermark_key.clone(),
        watermark_value: ev.watermark_value.clone(),
        last_update: ev.last_update,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::provenance::Provenance;
    use crate::event::{EventAction, EventType};
    use crate::key_provider::Wxid;

    fn sample() -> MessageCreate {
        MessageCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "message_5.db".to_string(),
                source_native_id: "Msg_a:1".to_string(),
                event_type: EventType::Message,
                event_action: EventAction::Create,
                event_seq: 42,
                ingest_time: 1,
            },
            server_id: "9876543210".to_string(),
            server_seq: 100,
            origin_source: 2,
            upload_status: 0,
            download_status: 0,
            conv_id: "wxid_friend_002".to_string(),
            sender_wxid: Wxid::try_new("wxid_sender_003").unwrap(),
            create_time: 1_699_000_000_000,
            sort_seq: 555,
            msg_type: 1,
            msg_sub_type: Some(0),
            msg_type_name: "TEXT".to_string(),
            msg_sub_type_name: None,
            status: 2,
            local_type_raw: 1,
            is_chatroom: false,
            raw_xml_present: false,
            decode_kind: "plain".to_string(),
            text_content: "晚上吃啥".to_string(),
            msg_source: "<msgsource><atuserlist><![CDATA[wxid_a,wxid_b]]></atuserlist></msgsource>".to_string(),
        }
    }

    /// 字段映射 + id/text 脱敏 + server_id parse + i32→i64.
    #[test]
    fn project_message_maps_and_shas() {
        let m = project_message(&sample()).unwrap();
        // provenance (account sha + source/native_id 直传)
        assert_eq!(m.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_eq!(m.source, "message_5.db");
        assert_eq!(m.source_native_id, "Msg_a:1");
        // id 类 sha256 — conv 跟 sender 取不同值, 验各自 sha 不混 (防错配)
        assert_eq!(m.conv_id_sha, sha256_hex("wxid_friend_002"));
        assert_eq!(m.sender_wxid_sha, sha256_hex("wxid_sender_003"));
        assert_ne!(m.conv_id_sha, m.sender_wxid_sha, "conv_id 跟 sender_wxid 不准错配");
        // server_id String→i64
        assert_eq!(m.server_id, 9_876_543_210);
        // text sha + char 长度 (中文"晚上吃啥" 4 字)
        assert_eq!(m.text_content_sha, sha256_hex("晚上吃啥"));
        assert_eq!(m.text_content_len, 4);
        // metadata 直传 + i32→i64
        assert_eq!(m.msg_type, 1);
        assert_eq!(m.status, 2);
        assert_eq!(m.msg_sub_type, Some(0));
        assert_eq!(m.msg_sub_type_name, None);
        assert_eq!(m.local_type_raw, 1);
        assert!(!m.is_chatroom);
        assert_eq!(m.decode_kind, "plain");
        assert_eq!(m.sys_type, None, "非系统消息 (msg_type 1) sys_type None");
    }

    /// 批F: msg_type 10000 → sys_type 按内容分类; 非 10000 → None。
    #[test]
    fn project_message_sys_type_classified() {
        let mut ev = sample();
        ev.msg_type = 10000;
        ev.text_content =
            r#"<sysmsg type="revokemsg"><revokemsg><content>"某人" 撤回了一条消息</content></revokemsg></sysmsg>"#
                .to_string();
        assert_eq!(
            project_message(&ev).unwrap().sys_type.as_deref(),
            Some("revoke"),
            "撤回系统消息 → revoke"
        );
        ev.text_content = r#""A"邀请"B"加入了群聊"#.to_string();
        assert_eq!(
            project_message(&ev).unwrap().sys_type.as_deref(),
            Some("member_join"),
            "入群 → member_join"
        );
        // 非系统消息 msg_type 恰含系统关键词也不分类 (guard msg_type==10000)。
        ev.msg_type = 1;
        ev.text_content = "他撤回了刚才说的话".to_string();
        assert_eq!(
            project_message(&ev).unwrap().sys_type,
            None,
            "普通文本消息 sys_type 恒 None (非 10000)"
        );
    }

    /// ADR-426 §2.7.1 双轨一致 (代号 = 明文的 sha) + §2.5 Debug 脱敏 (message 同 person 模式)。
    #[test]
    fn project_message_dual_track_and_debug_redact() {
        let m = project_message(&sample()).unwrap();
        // 双轨一致: _sha 列 == sha256(对应明文列), 同源不可错配。
        assert_eq!(m.account_id_sha, sha256_hex(&m.account_id));
        assert_eq!(m.conv_id_sha, sha256_hex(&m.conv_id));
        assert_eq!(m.sender_wxid_sha, sha256_hex(&m.sender_wxid));
        assert_eq!(m.text_content_sha, sha256_hex(&m.text_content));
        // 明文列存对 (第一类真实数据, 含聊天正文)。
        assert_eq!(m.conv_id, "wxid_friend_002");
        assert_eq!(m.sender_wxid, "wxid_sender_003");
        assert_eq!(m.text_content, "晚上吃啥");
        assert_eq!(
            m.text_content_len,
            i64::try_from(m.text_content.chars().count()).unwrap()
        );
        // K-R4 (§2.5): 持明文但 Debug 出口脱敏 — 不露裸 wxid / 正文。
        let dbg = format!("{m:?}");
        for raw in ["wxid_friend_002", "wxid_sender_003", "wxid_acct_001", "晚上吃啥"] {
            assert!(!dbg.contains(raw), "K-R4: V3Message Debug 含裸值 {raw}");
        }
    }

    /// nullable msg_sub_type / msg_sub_type_name 映射.
    #[test]
    fn project_message_nullable_subtype() {
        let mut ev = sample();
        ev.msg_sub_type = None;
        ev.msg_sub_type_name = Some("REVOKE".to_string());
        let m = project_message(&ev).unwrap();
        assert_eq!(m.msg_sub_type, None);
        assert_eq!(m.msg_sub_type_name, Some("REVOKE".to_string()));
    }

    /// K-R4: 投影产物 V3Message 全 sha/len/metadata, Debug 不含裸 wxid/正文.
    #[test]
    fn project_message_no_raw_leak() {
        let m = project_message(&sample()).unwrap();
        let dbg = format!("{m:?}");
        for raw in ["wxid_friend_002", "wxid_sender_003", "wxid_acct_001", "晚上吃啥"] {
            assert!(!dbg.contains(raw), "K-R4: 投影产物 V3Message 含裸值 {raw}");
        }
    }

    /// server_id 非整数 → ServerIdNotInteger (带原值).
    #[test]
    fn project_message_bad_server_id_errs() {
        let mut ev = sample();
        ev.server_id = "not-a-number".to_string();
        match project_message(&ev) {
            Err(ProjectionError::ServerIdNotInteger { value }) => assert_eq!(value, "not-a-number"),
            other => panic!("期望 ServerIdNotInteger, 实际 {other:?}"),
        }
    }

    // ── project_person (ContactUpdate → V3Person) ──

    fn sample_contact() -> ContactUpdate {
        ContactUpdate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "contact.db".to_string(),
                source_native_id: "Contact_a1b2".to_string(),
                event_type: EventType::ContactUpdate,
                event_action: EventAction::Create,
                event_seq: 7,
                ingest_time: 1,
            },
            username: "wxid_friend_002".to_string(),
            nick_name: "小明".to_string(),
            remark: Some("老同学".to_string()),
            alias: None,
            local_type: 1,
            is_in_chat_room: false,
            quan_pin: Some("xiaoming".to_string()),
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
        }
    }

    /// 字段映射 + username sha + display 名【只量 char 长度】(非 sha) + None display → 0 len.
    #[test]
    fn project_person_maps_len_and_sha() {
        let p = project_person(&sample_contact());
        assert_eq!(p.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_eq!(p.source, "contact.db");
        assert_eq!(p.source_native_id, "Contact_a1b2");
        assert_eq!(p.username_sha, sha256_hex("wxid_friend_002"));
        // display 名只量 char 长度 ("小明"=2 / "老同学"=3 字符)
        assert_eq!(p.nick_name_len, 2);
        assert_eq!(p.remark_len, 3);
        assert_eq!(p.alias_len, 0, "alias None → len 0 (V3Person _len NOT NULL)");
        assert_eq!(p.local_type, 1);
        assert!(!p.is_in_chat_room);
    }

    /// remark None → 0; alias Some → char 长度 (ascii "xiaoming" = 8).
    #[test]
    fn project_person_optional_display_lens() {
        let mut ev = sample_contact();
        ev.remark = None;
        ev.alias = Some("xiaoming".to_string());
        let p = project_person(&ev);
        assert_eq!(p.remark_len, 0, "remark None → 0");
        assert_eq!(p.alias_len, 8, "alias Some 8 字符");
        assert_eq!(p.nick_name_len, 2);
    }

    /// K-R4 (ADR-426 §2.5): V3Person 现持明文列, 但 Debug 出口脱敏 — 仍不含裸 username/昵称/备注。
    #[test]
    fn project_person_no_raw_leak() {
        let p = project_person(&sample_contact());
        let dbg = format!("{p:?}");
        for raw in ["wxid_friend_002", "wxid_acct_001", "小明", "老同学"] {
            assert!(!dbg.contains(raw), "K-R4: 投影产物 V3Person Debug 含裸值 {raw}");
        }
    }

    /// ADR-426 §2.7.1 双轨一致: 明文列与对应 _sha 列**同源派生** (sha = sha256(明文)), 不可错配。
    #[test]
    fn project_person_dual_track_consistent() {
        let p = project_person(&sample_contact());
        assert_eq!(
            p.username_sha,
            sha256_hex(&p.username),
            "username_sha 必 = sha256(明文 username)"
        );
        assert_eq!(
            p.account_id_sha,
            sha256_hex(&p.account_id),
            "account_id_sha 必 = sha256(明文 account_id)"
        );
        // 明文列存对 (第一类真实数据)
        assert_eq!(p.username, "wxid_friend_002");
        assert_eq!(p.account_id, "wxid_acct_001");
        assert_eq!(p.nick_name, "小明");
        assert_eq!(p.remark.as_deref(), Some("老同学"));
        assert_eq!(p.alias, None);
        // 明文与 _len 一致
        assert_eq!(p.nick_name_len, i64::try_from(p.nick_name.chars().count()).unwrap());
    }

    /// 字段扩充第二批: project_person 直传 verify_flag/delete_flag (i64 元数据, 进 content_digest)。
    #[test]
    fn project_person_maps_flags() {
        let mut ev = sample_contact();
        ev.verify_flag = 2;
        ev.delete_flag = 1;
        let p = project_person(&ev);
        assert_eq!(p.verify_flag, 2);
        assert_eq!(p.delete_flag, 1);
    }

    /// 批G flag 位解码 (2026-07-08 真机 ground-truth 坐实, ADR-503) — bit6 星标 / bit8 不让她看我(屏蔽) /
    /// bit11 置顶 / bit16 不看她 / bit23 仅聊天 / bit28 折叠群。
    #[test]
    fn project_person_decodes_flag_bits() {
        let mut ev = sample_contact();
        // flag=0 → 全 false。
        ev.flag = 0;
        let p0 = project_person(&ev);
        assert!(
            !p0.is_starred && !p0.is_pinned && !p0.blocks_moments && !p0.hide_their_moments && !p0.chat_only,
            "flag 0 → 全 false"
        );
        // 只 bit6 (0x40) → 只星标。
        ev.flag = 0x40;
        let p = project_person(&ev);
        assert!(p.is_starred, "bit6 → 星标");
        assert!(
            !p.is_pinned && !p.blocks_moments && !p.hide_their_moments && !p.chat_only,
            "其它位未设"
        );
        // ⭐真机测坐实: 不让她看我 = bit8 (0x100); 不看她 = bit16 (0x1_0000) — 两个不同位, 不能混。
        ev.flag = 0x100;
        let p = project_person(&ev);
        assert!(
            p.blocks_moments && !p.hide_their_moments,
            "bit8 → 屏蔽朋友圈(不让她看我), 非 bit16"
        );
        ev.flag = 0x1_0000;
        let p = project_person(&ev);
        assert!(p.hide_their_moments && !p.blocks_moments, "bit16 → 不看她, 非屏蔽");
        // 星标+不让她看我+置顶+不看她+仅聊天 全设 + 低位噪音(0x3)。
        ev.flag = 0x40 | 0x100 | 0x800 | 0x1_0000 | 0x80_0000 | 0x3;
        let p = project_person(&ev);
        assert!(
            p.is_starred && p.is_pinned && p.blocks_moments && p.hide_their_moments && p.chat_only,
            "五位全设"
        );
        // 只低位类别位 (0x4 好友类型) → flag 位全 false (不误判)。
        ev.flag = 0x4;
        let p = project_person(&ev);
        assert!(
            !p.is_starred && !p.is_pinned && !p.blocks_moments && !p.hide_their_moments && !p.chat_only,
            "低位类别位不触发"
        );
    }

    /// 免打扰 (2026-07-04 用户真人核对确认): 群(local_type=2) notify=0 → muted; 群 notify≠0 或个人 → false。
    #[test]
    fn project_person_is_muted_group_only() {
        let mut ev = sample_contact();
        // 群 + notify=0 → 免打扰。
        ev.local_type = 2;
        ev.chat_room_notify = 0;
        assert!(project_person(&ev).is_muted, "群 notify=0 → 免打扰");
        // 群 + notify=1 → 正常提醒。
        ev.chat_room_notify = 1;
        assert!(!project_person(&ev).is_muted, "群 notify=1 → 正常提醒");
        // 个人 (local_type=1) + notify=0 → 不判免打扰 (该字段对个人无区分度)。
        ev.local_type = 1;
        ev.chat_room_notify = 0;
        assert!(!project_person(&ev).is_muted, "个人 notify=0 → 不判免打扰");
    }

    /// 字段扩充第三批 (codex P2): project_person 端到端把 ContactUpdate 头像 3 列 → V3Person (只进 L2)。
    #[test]
    fn project_person_maps_head() {
        let mut ev = sample_contact();
        ev.big_head_url = Some("https://wx.qlogo.cn/x/0".to_string());
        ev.small_head_url = None;
        ev.head_img_md5 = Some("abc123".to_string());
        let p = project_person(&ev);
        assert_eq!(p.big_head_url.as_deref(), Some("https://wx.qlogo.cn/x/0"));
        assert_eq!(p.small_head_url, None);
        assert_eq!(p.head_img_md5.as_deref(), Some("abc123"));
    }

    /// 字段扩充第五批 (2026-07-02): project_person 端到端把 contact 补充列 → V3Person (只进 L2)。
    #[test]
    fn project_person_maps_batch5() {
        let mut ev = sample_contact();
        ev.description = Some("个性签名".to_string());
        ev.flag = 5;
        ev.chat_room_notify = 1;
        ev.chat_room_type = 2;
        let p = project_person(&ev);
        assert_eq!(p.description.as_deref(), Some("个性签名"));
        assert_eq!(p.flag, 5);
        assert_eq!(p.chat_room_notify, 1);
        assert_eq!(p.chat_room_type, 2);
    }

    /// 字段扩充第七批 (2026-07-02): project_person 端到端把 extra_buffer 解出的属性 → V3Person (只进 L2)。
    #[test]
    fn project_person_maps_batch7() {
        let mut ev = sample_contact();
        ev.sex = 2;
        ev.country = Some("CN".to_string());
        ev.province = Some("Zhejiang".to_string());
        ev.city = Some("Hangzhou".to_string());
        ev.friend_source = 3;
        let p = project_person(&ev);
        assert_eq!(p.sex, 2);
        assert_eq!(p.country.as_deref(), Some("CN"));
        assert_eq!(p.province.as_deref(), Some("Zhejiang"));
        assert_eq!(p.city.as_deref(), Some("Hangzhou"));
        assert_eq!(p.friend_source, 3);
    }

    /// 标签件: project_person 把 ContactUpdate.labels → V3Person.labels (只进 L2); None → None。
    #[test]
    fn project_person_maps_labels() {
        let mut ev = sample_contact();
        ev.labels = Some("老板,客户".to_string());
        assert_eq!(project_person(&ev).labels.as_deref(), Some("老板,客户"));
        ev.labels = None;
        assert_eq!(project_person(&ev).labels, None, "无标签 → None");
    }

    /// project_message_app (ADR-455): 普通文本消息 → None; appmsg 视频号消息 → Some(V3MessageApp) 字段正确。
    #[test]
    fn project_message_app_finder_and_none() {
        // 普通文本消息 → 无 appmsg → None。
        assert!(project_message_app(&sample()).is_none(), "文本消息不落 message_app");
        // codex 批C P1: msg_type=1 但正文恰含 <appmsg> XML (如聊天里转述) → None (非 APP_XML 不落)。
        let mut fake = sample();
        fake.text_content = r"<msg><appmsg><type>51</type></appmsg></msg>".to_string();
        assert!(
            project_message_app(&fake).is_none(),
            "msg_type=1 含 appmsg 正文仍不落 (guard msg_type)"
        );
        // 视频号 appmsg 消息 → Some。
        let mut ev = sample();
        ev.msg_type = 49;
        ev.text_content = r#"<msg><appmsg appid=""><title></title><type>51</type><url><![CDATA[http://v.qq/x]]></url><finderFeed><nickname><![CDATA[某视频号作者]]></nickname><mediaCount><![CDATA[3]]></mediaCount><username><![CDATA[v2_abc]]></username></finderFeed></appmsg></msg>"#.to_string();
        let app = project_message_app(&ev).expect("视频号消息应落 message_app");
        assert_eq!(app.app_type, 51);
        assert_eq!(app.app_nickname.as_deref(), Some("某视频号作者"));
        assert_eq!(app.app_username.as_deref(), Some("v2_abc"));
        assert_eq!(app.media_count, 3);
        assert_eq!(app.source_native_id, "Msg_a:1", "PK 与所属 message 一致");
        assert_eq!(app.account_id, "wxid_acct_001", "明文 account (ADR-427)");
    }

    /// project_message_hongbao_claim: sys=hongbao 领取通知 → Some (领取人/单号/方向); 非领取 → None (ADR-504)。
    #[test]
    fn project_message_hongbao_claim_some_and_none() {
        assert!(
            project_message_hongbao_claim(&sample()).is_none(),
            "文本消息不落 message_hongbao_claim"
        );
        // type10000 红包领取通知 (别人领我发的) → Some。
        let mut ev = sample();
        ev.msg_type = 10000;
        ev.text_content = r##"<img src="SystemMessages_HongbaoIcon.png"/>  阿婷领取了你的<_wc_custom_link_ color="#FD9931" href="weixin://weixinhongbao/opendetail?sendid=1000039801202511076348177429056">红包</_wc_custom_link_>"##.to_string();
        let claim = project_message_hongbao_claim(&ev).expect("领取通知应落 message_hongbao_claim");
        assert!(claim.is_own_envelope, "领取了你的 → 我发的被领");
        assert_eq!(claim.peer_name, "阿婷");
        assert_eq!(claim.send_id, "1000039801202511076348177429056");
        assert_eq!(claim.source_native_id, "Msg_a:1", "PK 与所属 message 一致");
        assert_eq!(claim.account_id, "wxid_acct_001", "明文 account (ADR-427)");
    }

    /// project_message_call: type50 通话消息 → Some (invite_type/时长/结果); 非通话 → None (ADR-475)。
    #[test]
    fn project_message_call_bubble_and_none() {
        // 文本消息 → 非通话 → None。
        assert!(project_message_call(&sample()).is_none(), "文本消息不落 message_call");
        // type50 气泡通话 → Some。
        let mut ev = sample();
        ev.msg_type = 50;
        ev.text_content = r#"<voipmsg type="VoIPBubbleMsg"><VoIPBubbleMsg><msg><![CDATA[通话时长 00:25]]></msg><room_type>1</room_type><msg_type>100</msg_type><duration>0</duration></VoIPBubbleMsg></voipmsg>"#.to_string();
        let call = project_message_call(&ev).expect("通话消息应落 message_call");
        assert_eq!(call.invite_type, -1);
        assert_eq!(call.room_type, 1);
        assert_eq!(call.call_state, 100);
        assert_eq!(call.display_content, "通话时长 00:25");
        assert_eq!(call.source_native_id, "Msg_a:1", "PK 与所属 message 一致");
        assert_eq!(call.account_id, "wxid_acct_001", "明文 account (ADR-427)");
    }

    /// project_message_forward: type49 合并转发 → 多子项行 (seq/发送人/内容); 非转发 → 空 (ADR-476)。
    #[test]
    fn project_message_forward_items_and_none() {
        assert!(
            project_message_forward(&sample()).is_empty(),
            "文本消息不落 message_forward_item"
        );
        let mut ev = sample();
        ev.msg_type = 49;
        ev.text_content = r#"<msg><appmsg><type>19</type><recorditem>&lt;recordinfo&gt;&lt;datalist count="2"&gt;&lt;dataitem datatype="1"&gt;&lt;sourcename&gt;安小米&lt;/sourcename&gt;&lt;datadesc&gt;绘本团&lt;/datadesc&gt;&lt;/dataitem&gt;&lt;dataitem datatype="2"&gt;&lt;sourcename&gt;小红&lt;/sourcename&gt;&lt;fullmd5&gt;abc123&lt;/fullmd5&gt;&lt;/dataitem&gt;&lt;/datalist&gt;&lt;/recordinfo&gt;</recorditem></appmsg></msg>"#.to_string();
        let items = project_message_forward(&ev);
        assert_eq!(items.len(), 2, "2 子项多行");
        assert_eq!(items[0].seq, 0);
        assert_eq!(items[0].data_type, "1");
        assert_eq!(items[0].source_name.as_deref(), Some("安小米"));
        assert_eq!(items[0].data_desc.as_deref(), Some("绘本团"));
        assert_eq!(items[1].seq, 1);
        assert_eq!(items[1].media_md5.as_deref(), Some("abc123"));
        assert_eq!(items[0].source_native_id, "Msg_a:1", "PK 与所属 message 一致");
        assert_eq!(items[0].account_id, "wxid_acct_001", "明文 account (ADR-427)");
    }

    /// project_group_pay_members: type2001 群收款 payerlist → 逐付款人多行 (已付人数=len); 非群收款→空 (ADR-488)。
    #[test]
    fn project_group_pay_members_and_none() {
        assert!(
            project_group_pay_members(&sample()).is_empty(),
            "文本消息不落 group_pay_member"
        );
        let mut ev = sample();
        ev.msg_type = 49;
        ev.text_content = r"<msg><appmsg><type>2001</type><wcpayinfo><senderdes><![CDATA[应付¥20.00]]></senderdes><newaa><billno><![CDATA[bill999]]></billno><payerlist>wxid_p1,2000,1|wxid_p2,2000,1|jinabc,2000,0</payerlist></newaa></wcpayinfo></appmsg></msg>".to_string();
        let ms = project_group_pay_members(&ev);
        assert_eq!(ms.len(), 3, "3 付款人 → 3 行 (已付人数派生自行数)");
        assert_eq!(ms[0].bill_no, "bill999", "单号 JOIN 键");
        assert_eq!(ms[0].amount, 2000, "金额分");
        assert_eq!(ms[0].pay_status, 1);
        assert_eq!(ms[2].pay_status, 0, "第3人状态 0");
        assert_eq!(ms[0].payer_wxid, "wxid_p1", "明文 wxid (ADR-427)");
        assert_eq!(ms[0].source_native_id, "Msg_a:1", "PK 与所属 message 一致");
        // 红包 (2001 无 newaa) → 不落 group_pay_member。
        let mut hb = sample();
        hb.msg_type = 49;
        hb.text_content = r"<msg><appmsg><type>2001</type><wcpayinfo><sendertitle><![CDATA[恭喜发财]]></sendertitle></wcpayinfo></appmsg></msg>".to_string();
        assert!(project_group_pay_members(&hb).is_empty(), "红包不落 group_pay_member");
        // K-R4: Debug 不泄付款人 wxid 裸值。
        let dbg = format!("{:?}", ms[0]);
        assert!(
            !dbg.contains("wxid_p1") && !dbg.contains("bill999"),
            "K-R4: payer_wxid/bill_no Debug 脱敏"
        );
        assert!(dbg.contains("payer_wxid_sha8") && dbg.contains("amount: 2000"));
    }

    /// K-R4: V3MessageApp 持明文但 Debug 脱敏 — 不含裸作者名。
    #[test]
    fn project_message_app_no_raw_leak() {
        let mut ev = sample();
        ev.msg_type = 49;
        ev.text_content = r"<msg><appmsg><type>33</type><title>某小程序标题</title><sourcedisplayname>某来源</sourcedisplayname><weappinfo><username><![CDATA[gh_x@app]]></username></weappinfo></appmsg></msg>".to_string();
        let dbg = format!("{:?}", project_message_app(&ev).unwrap());
        for raw in ["某小程序标题", "某来源", "wxid_acct_001"] {
            assert!(!dbg.contains(raw), "K-R4: V3MessageApp Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("title_sha8"));
    }

    // ── project_message_mention (MessageCreate.msg_source → V3MessageMention) ──

    /// sample 的 msg_source 含 atuserlist wxid_a,wxid_b → 2 行, PK/sha 正确, 明文落库。
    #[test]
    fn project_message_mention_maps_atuserlist() {
        let mut ev = sample();
        ev.is_chatroom = true; // @提及只在群消息
        let ms = project_message_mention(&ev);
        assert_eq!(ms.len(), 2, "两个被@ → 两行 (一消息多@多行)");
        assert_eq!(ms[0].mentioned_wxid, "wxid_a", "明文 wxid (ADR-427)");
        assert_eq!(ms[0].mentioned_wxid_sha, sha256_hex("wxid_a"), "sha 一致");
        assert_eq!(ms[0].source_native_id, "Msg_a:1", "PK = 所属 message");
        assert!(!ms[0].is_at_all);
        assert_eq!(ms[1].mentioned_wxid, "wxid_b");
    }

    /// 无 @ (msg_source 空 / 无 atuserlist) → 空 Vec; 单聊即便 source 含 atuserlist 也不落 (codex 批E P2 guard)。
    #[test]
    fn project_message_mention_none_when_no_at() {
        let mut ev = sample();
        ev.is_chatroom = true;
        ev.msg_source = String::new();
        assert!(project_message_mention(&ev).is_empty(), "无 source → 无 @行");
        ev.msg_source = "<msgsource><silence>1</silence></msgsource>".to_string();
        assert!(project_message_mention(&ev).is_empty(), "无 atuserlist → 无 @行");
        // 单聊 source 恰含 atuserlist → 仍不落 (is_chatroom guard)。
        ev.is_chatroom = false;
        ev.msg_source = "<atuserlist><![CDATA[wxid_x]]></atuserlist>".to_string();
        assert!(project_message_mention(&ev).is_empty(), "单聊不落 @提及 (guard)");
    }

    /// K-R4: V3MessageMention 持明文但 Debug 脱敏 — 不含裸被@wxid。
    #[test]
    fn project_message_mention_no_raw_leak() {
        let mut ev = sample();
        ev.is_chatroom = true;
        ev.msg_source = "<atuserlist><![CDATA[wxid_secret_at]]></atuserlist>".to_string();
        let dbg = format!("{:?}", project_message_mention(&ev)[0]);
        assert!(
            !dbg.contains("wxid_secret_at"),
            "K-R4: V3MessageMention Debug 泄裸被@wxid"
        );
        assert!(!dbg.contains("wxid_acct_001"), "K-R4: Debug 泄裸 account");
        assert!(dbg.contains("mentioned_wxid_sha8"));
    }

    // ── project_chatroom_member_events (MessageCreate msg_type=10000 → V3ChatroomMemberEvent) ──

    /// 结构化入群 XML, names 下 2 member → 2 行, anchor:seq 逐行唯一 (不塌陷), inviter/conv/time 正确。
    #[test]
    fn project_member_events_multi_join_no_collapse() {
        let mut ev = sample();
        ev.is_chatroom = true;
        ev.msg_type = 10000;
        ev.text_content = r#"<sysmsg type="sysmsgtemplate"><content_template><template>"$username$"邀请"$names$"加入了群聊</template><link_list><link name="username"><memberlist><member><username>wxid_inviter</username><nickname>邀请人</nickname></member></memberlist></link><link name="names"><memberlist><member><username>wxid_m1</username><nickname>甲</nickname></member><member><username>wxid_m2</username><nickname>乙</nickname></member></memberlist></link></link_list></content_template></sysmsg>"#.to_string();
        let evs = project_chatroom_member_events(&ev);
        assert_eq!(evs.len(), 2, "2 成员入群 → 2 行 (一消息多成员不塌陷)");
        // anchor:seq 逐行唯一。
        assert_eq!(evs[0].source_native_id, "Msg_a:1:0", "第一行 anchor:0");
        assert_eq!(evs[1].source_native_id, "Msg_a:1:1", "第二行 anchor:1");
        assert_ne!(evs[0].source_native_id, evs[1].source_native_id, "PK 逐行唯一");
        assert_eq!(evs[0].msg_native_id, "Msg_a:1", "裸 anchor 供删整组");
        assert_eq!(evs[0].member_wxid.as_deref(), Some("wxid_m1"));
        assert_eq!(
            evs[0].member_wxid_sha.as_deref(),
            Some(sha256_hex("wxid_m1").as_str()),
            "sha 一致"
        );
        assert_eq!(
            evs[0].inviter_wxid.as_deref(),
            Some("wxid_inviter"),
            "邀请人 = username link"
        );
        assert_eq!(evs[0].event_kind, "join");
        assert_eq!(evs[0].conv_id, "wxid_friend_002", "conv_id = ev.conv_id");
        assert_eq!(evs[0].event_time, 1_699_000_000_000, "event_time = ev.create_time");
        assert_eq!(evs[1].member_wxid.as_deref(), Some("wxid_m2"));
    }

    /// 非进出事件 / 非群聊 / 非 10000 → 空 Vec。
    #[test]
    fn project_member_events_empty_cases() {
        let mut ev = sample();
        // 非 10000 (普通文本) → 空。
        assert!(project_chatroom_member_events(&ev).is_empty(), "msg_type≠10000 → 空");
        // 10000 但单聊 → 空 (guard)。
        ev.msg_type = 10000;
        ev.is_chatroom = false;
        ev.text_content = r#"你将"张三"移出了群聊"#.to_string();
        assert!(
            project_chatroom_member_events(&ev).is_empty(),
            "单聊不落群成员事件 (guard)"
        );
        // 10000 群聊但非进出 (撤回) → 空。
        ev.is_chatroom = true;
        ev.text_content = "你撤回了一条消息".to_string();
        assert!(project_chatroom_member_events(&ev).is_empty(), "撤回非进出事件 → 空");
    }

    /// K-R4: V3ChatroomMemberEvent 持明文但 Debug 脱敏 — 不含裸 wxid/nickname/conv。
    #[test]
    fn project_member_events_no_raw_leak() {
        let mut ev = sample();
        ev.is_chatroom = true;
        ev.msg_type = 10000;
        ev.text_content = r#"<sysmsg type="sysmsgtemplate"><link_list><link name="kickoutname"><memberlist><member><username>wxid_kick_secret</username><nickname>被踢昵称秘</nickname></member></memberlist></link></link_list>移出了群聊</sysmsg>"#.to_string();
        let evs = project_chatroom_member_events(&ev);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event_kind, "remove");
        let dbg = format!("{:?}", evs[0]);
        for raw in ["wxid_kick_secret", "被踢昵称秘", "wxid_friend_002", "wxid_acct_001"] {
            assert!(!dbg.contains(raw), "K-R4: V3ChatroomMemberEvent Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("member_wxid_sha8") && dbg.contains("member_nickname_sha8"));
    }

    // ── project_session (SessionUpdate → V3Session) ──

    fn sample_session() -> SessionUpdate {
        SessionUpdate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "session.db".to_string(),
                source_native_id: "Session_a1b2".to_string(),
                event_type: EventType::SessionUpdate,
                event_action: EventAction::Create,
                event_seq: 3,
                ingest_time: 1_700_000_000_000,
            },
            username: "wxid_friend_002".to_string(),
            summary: Some("晚上吃饭吗".to_string()),
            last_sender_display_name: Some("小明".to_string()),
            unread_count: 5,
            last_msg_type: 1,
            last_msg_sub_type: 0,
            sort_timestamp: 1_700_000_009_000,
            session_type: 1,
            is_hidden: 0,
            status: 0,
            draft: None,
            last_msg_sender: None,
            last_timestamp: 0,
            last_clear_unread_timestamp: 0,
            last_msg_locald_id: 0,
            last_msg_ext_type: 0,
            unread_first_msg_srv_id: 0,
        }
    }

    /// 字段映射 + summary/sender 只量 char 长度 (晚上吃饭吗=5 / 小明=2) + 明文列。
    #[test]
    fn project_session_maps_len_and_plaintext() {
        let s = project_session(&sample_session());
        assert_eq!(s.username_sha, sha256_hex("wxid_friend_002"));
        assert_eq!(s.username, "wxid_friend_002");
        assert_eq!(s.unread_count, 5);
        assert_eq!(s.last_msg_type, 1);
        assert_eq!(s.sort_timestamp, 1_700_000_009_000);
        assert_eq!(s.summary.as_deref(), Some("晚上吃饭吗"));
        assert_eq!(s.summary_len, 5);
        assert_eq!(s.last_sender_display_name.as_deref(), Some("小明"));
        assert_eq!(s.last_sender_len, 2);
    }

    /// 字段扩充第四批 (2026-07-02): project_session 端到端把会话状态 4 列 → V3Session (只进 L2)。
    #[test]
    fn project_session_maps_status() {
        let mut ev = sample_session();
        ev.session_type = 2;
        ev.is_hidden = 1;
        ev.status = 5;
        ev.draft = Some("草稿甲".to_string());
        let s = project_session(&ev);
        assert_eq!(s.session_type, 2);
        assert_eq!(s.is_hidden, 1);
        assert_eq!(s.status, 5);
        assert_eq!(s.draft.as_deref(), Some("草稿甲"));
        assert_eq!(s.draft_len, 3, "草稿甲 = 3 字符");
    }

    /// 字段扩充第六批 (2026-07-02): project_session 端到端把 session 补充列 → V3Session (只进 L2)。
    #[test]
    fn project_session_maps_batch6() {
        let mut ev = sample_session();
        ev.last_msg_sender = Some("wxid_sender".to_string());
        ev.last_timestamp = 1_700_000_100_000;
        ev.last_clear_unread_timestamp = 1_700_000_050_000;
        ev.last_msg_locald_id = 42;
        ev.last_msg_ext_type = 3;
        ev.unread_first_msg_srv_id = 9_876_543_210;
        let s = project_session(&ev);
        assert_eq!(s.last_msg_sender.as_deref(), Some("wxid_sender"));
        assert_eq!(s.last_timestamp, 1_700_000_100_000);
        assert_eq!(s.last_clear_unread_timestamp, 1_700_000_050_000);
        assert_eq!(s.last_msg_locald_id, 42);
        assert_eq!(s.last_msg_ext_type, 3);
        assert_eq!(s.unread_first_msg_srv_id, 9_876_543_210);
    }

    /// None summary/sender → len 0 + None (V3Session _len NOT NULL / 明文列 nullable)。
    #[test]
    fn project_session_null_summary_sender() {
        let mut ev = sample_session();
        ev.summary = None;
        ev.last_sender_display_name = None;
        let s = project_session(&ev);
        assert_eq!(s.summary, None);
        assert_eq!(s.summary_len, 0, "summary None → len 0");
        assert_eq!(s.last_sender_display_name, None);
        assert_eq!(s.last_sender_len, 0);
    }

    /// ADR-426 §2.7.1 双轨一致 + ADR-427 全程明文: _sha 与明文同源, summary/sender 存明文真值。
    #[test]
    fn project_session_dual_track_consistent() {
        let s = project_session(&sample_session());
        assert_eq!(s.username_sha, sha256_hex(&s.username), "username_sha = sha256(明文)");
        assert_eq!(s.account_id_sha, sha256_hex(&s.account_id));
        assert_eq!(s.account_id, "wxid_acct_001");
        assert_eq!(s.summary.as_deref(), Some("晚上吃饭吗"), "summary 明文真值 (全程明文)");
        assert_eq!(s.summary_len, i64::try_from("晚上吃饭吗".chars().count()).unwrap());
    }

    /// K-R4: V3Session 持明文但 Debug 脱敏 — 不含裸 username/summary/sender。
    #[test]
    fn project_session_no_raw_leak() {
        let s = project_session(&sample_session());
        let dbg = format!("{s:?}");
        for raw in ["wxid_friend_002", "晚上吃饭吗", "小明", "wxid_acct_001"] {
            assert!(!dbg.contains(raw), "K-R4: V3Session Debug 含裸值 {raw}");
        }
    }

    // ── project_chatroom (ChatroomCreate → V3Chatroom) ──

    fn sample_chatroom() -> ChatroomCreate {
        ChatroomCreate {
            is_still_member: true,
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "chatroom.db".to_string(),
                source_native_id: "Chatroom_a1b2".to_string(),
                event_type: EventType::ChatroomUpdate,
                event_action: EventAction::Create,
                event_seq: 9,
                ingest_time: 1,
            },
            chatroom_id: "12345678@chatroom".to_string(),
            chatroom_name: "技术交流群".to_string(),
            chatroom_remark: Some("我的群备注".to_string()),
            announcement: Some("禁止广告".to_string()),
            owner_wxid: Some("wxid_owner_003".to_string()),
            member_count: 88,
            announcement_editor: Some("wxid_editor_x".to_string()),
            announcement_publish_time: 1_700_000_000,
            xml_announcement: Some("<xml>富媒体公告</xml>".to_string()),
            chat_room_status: 0x80000,
        }
    }

    /// 字段映射 + chatroom_id/owner sha + name/announcement 只量 char len + member_count.
    #[test]
    fn project_chatroom_maps() {
        let c = project_chatroom(&sample_chatroom());
        assert_eq!(c.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_eq!(c.source, "chatroom.db");
        assert_eq!(c.source_native_id, "Chatroom_a1b2");
        assert_eq!(c.chatroom_id_sha, sha256_hex("12345678@chatroom"));
        // display 只量 char len ("技术交流群"=5 / "禁止广告"=4 字符)
        assert_eq!(c.chatroom_name_len, 5);
        assert_eq!(c.announcement_len, 4);
        assert_eq!(c.member_count, 88);
        // owner_wxid nullable id 类 sha → Some
        assert_eq!(c.owner_wxid_sha, Some(sha256_hex("wxid_owner_003")));
        // 群备注 L2 明文 + _len ("我的群备注"=5 字符)
        assert_eq!(c.chatroom_remark.as_deref(), Some("我的群备注"), "群备注明文落库");
        assert_eq!(c.chatroom_remark_len, 5);
        // KI-A/B: 富媒体公告存原文 + 群状态位原值落库 (L2-only)
        assert_eq!(
            c.xml_announcement.as_deref(),
            Some("<xml>富媒体公告</xml>"),
            "富媒体公告明文落库"
        );
        assert_eq!(c.chat_room_status, 0x80000, "群状态位原值落库");
    }

    /// **nullable 区分**: announcement None → len 0 (NOT NULL 列); owner_wxid None → sha None (nullable 列).
    #[test]
    fn project_chatroom_null_distinction() {
        let mut ev = sample_chatroom();
        ev.announcement = None;
        ev.owner_wxid = None;
        let c = project_chatroom(&ev);
        assert_eq!(
            c.announcement_len, 0,
            "announcement None → 0 (announcement_len NOT NULL)"
        );
        assert_eq!(
            c.owner_wxid_sha, None,
            "owner_wxid None → None (owner_wxid_sha nullable)"
        );
    }

    /// K-R4: V3Chatroom 无裸 chatroom_id/群名/公告/群主.
    #[test]
    fn project_chatroom_no_raw_leak() {
        let c = project_chatroom(&sample_chatroom());
        let dbg = format!("{c:?}");
        for raw in [
            "12345678@chatroom",
            "wxid_owner_003",
            "wxid_acct_001",
            "技术交流群",
            "禁止广告",
            "我的群备注",
        ] {
            assert!(!dbg.contains(raw), "K-R4: 投影产物 V3Chatroom 含裸值 {raw}");
        }
    }

    // ── project_person_alias (ContactUpdate → V3PersonAlias, 复用 sample_contact) ──

    /// 字段映射: account/username sha; remark Some→Some(sha); nick_name 必填 → Some(sha); 无 source/alias_sha.
    #[test]
    fn project_person_alias_maps() {
        let a = project_person_alias(&sample_contact());
        assert_eq!(a.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_eq!(a.username_sha, sha256_hex("wxid_friend_002"));
        assert_eq!(a.remark_sha, Some(sha256_hex("老同学")));
        assert_eq!(a.nick_name_sha, Some(sha256_hex("小明")), "nick_name 必填 → 总 Some");
    }

    /// remark None → remark_sha None (nullable 列); nick_name 仍 Some.
    #[test]
    fn project_person_alias_none_remark() {
        let mut ev = sample_contact();
        ev.remark = None;
        let a = project_person_alias(&ev);
        assert_eq!(a.remark_sha, None, "remark None → remark_sha None");
        assert!(a.nick_name_sha.is_some(), "nick_name 必填总 Some");
    }

    /// K-R4: V3PersonAlias 全 sha — Debug 不含裸 username/昵称/备注.
    #[test]
    fn project_person_alias_no_raw_leak() {
        let a = project_person_alias(&sample_contact());
        let dbg = format!("{a:?}");
        for raw in ["wxid_friend_002", "wxid_acct_001", "小明", "老同学"] {
            assert!(!dbg.contains(raw), "K-R4: 投影产物 V3PersonAlias 含裸值 {raw}");
        }
    }

    // ── project_chatroom_member_add (ChatroomMemberAdd → V3ChatroomMember 新加群状态) ──

    fn sample_member_add() -> ChatroomMemberAdd {
        ChatroomMemberAdd {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "chatroom.db".to_string(),
                source_native_id: "room:member:wx_m".to_string(),
                event_type: EventType::ChatroomUpdate,
                event_action: EventAction::MemberAdd,
                event_seq: 11,
                ingest_time: 1,
            },
            chatroom_id: "12345678@chatroom".to_string(),
            member_wxid: "wxid_member_004".to_string(),
            display_name: Some("阿强".to_string()),
            joined_at: Some(1_699_000_000_000),
            role: "admin".to_string(),
            invited_by: Some("wxid_inviter".to_string()),
        }
    }

    /// 9 字段映射 + fresh-add 语义 (is_in_group=true / left_at=None / joined_at 直传); id 类 sha; display 量 len.
    #[test]
    fn project_chatroom_member_add_maps() {
        let m = project_chatroom_member_add(&sample_member_add());
        assert_eq!(m.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_eq!(m.source, "chatroom.db");
        assert_eq!(m.source_native_id, "room:member:wx_m");
        assert_eq!(m.chatroom_id_sha, sha256_hex("12345678@chatroom"));
        assert_eq!(m.member_wxid_sha, sha256_hex("wxid_member_004"));
        assert_eq!(m.display_name_len, 2, "阿强 = 2 字符");
        assert_eq!(m.joined_at, Some(1_699_000_000_000));
        // fresh-add 语义 (§6.8 契约3c member_add)
        assert!(m.is_in_group, "member_add → is_in_group=true");
        assert_eq!(m.left_at, None, "刚加群 left_at=None");
        assert_eq!(
            m.role, "admin",
            "第八批 role 映射 through (sample_member_add role=admin)"
        );
        assert_eq!(
            m.invited_by.as_deref(),
            Some("wxid_inviter"),
            "第九批 invited_by 映射 through"
        );
    }

    /// display_name None → display_name_len 0 (NOT NULL); joined_at None → None (nullable).
    #[test]
    fn project_chatroom_member_add_none_display_and_joined() {
        let mut ev = sample_member_add();
        ev.display_name = None;
        ev.joined_at = None;
        let m = project_chatroom_member_add(&ev);
        assert_eq!(
            m.display_name_len, 0,
            "display_name None → 0 (display_name_len NOT NULL)"
        );
        assert_eq!(m.joined_at, None, "joined_at None → None (nullable)");
        assert!(m.is_in_group);
        assert_eq!(m.left_at, None);
    }

    /// K-R4: V3ChatroomMember 无裸 chatroom_id/member_wxid/群昵称.
    #[test]
    fn project_chatroom_member_add_no_raw_leak() {
        let m = project_chatroom_member_add(&sample_member_add());
        let dbg = format!("{m:?}");
        for raw in ["12345678@chatroom", "wxid_member_004", "wxid_acct_001", "阿强"] {
            assert!(!dbg.contains(raw), "K-R4: 投影产物 V3ChatroomMember 含裸值 {raw}");
        }
    }

    // ── ADR-426 §2.7.1 双轨一致 (每个 _sha == sha256(对应明文列), 明文取自同一 ev) ──

    /// V3Chatroom: chatroom_id/owner/account 的 _sha 与明文同源; 正文明文取自 ev 原值.
    #[test]
    fn project_chatroom_dual_track_consistent() {
        let c = project_chatroom(&sample_chatroom());
        assert_eq!(c.account_id_sha, sha256_hex(&c.account_id));
        assert_eq!(c.chatroom_id_sha, sha256_hex(&c.chatroom_id));
        assert_eq!(c.owner_wxid_sha, c.owner_wxid.as_deref().map(sha256_hex));
        assert_eq!(c.chatroom_id, "12345678@chatroom");
        assert_eq!(c.chatroom_name, "技术交流群");
        assert_eq!(c.announcement.as_deref(), Some("禁止广告"));
        assert_eq!(c.owner_wxid.as_deref(), Some("wxid_owner_003"));
    }

    /// V3PersonAlias: account/username/remark/nick 的 _sha 与明文同源; nick_name 必填恒 Some.
    #[test]
    fn project_person_alias_dual_track_consistent() {
        let a = project_person_alias(&sample_contact());
        assert_eq!(a.account_id_sha, sha256_hex(&a.account_id));
        assert_eq!(a.username_sha, sha256_hex(&a.username));
        assert_eq!(a.remark_sha, a.remark.as_deref().map(sha256_hex));
        assert_eq!(a.nick_name_sha, a.nick_name.as_deref().map(sha256_hex));
        assert_eq!(a.username, "wxid_friend_002");
        assert_eq!(a.nick_name.as_deref(), Some("小明"));
        assert_eq!(a.remark.as_deref(), Some("老同学"));
    }

    /// V3ChatroomMember: account/chatroom/member 的 _sha 与明文同源; member_wxid 明文 (退群闭环回读源).
    #[test]
    fn project_chatroom_member_add_dual_track_consistent() {
        let m = project_chatroom_member_add(&sample_member_add());
        assert_eq!(m.account_id_sha, sha256_hex(&m.account_id));
        assert_eq!(m.chatroom_id_sha, sha256_hex(&m.chatroom_id));
        assert_eq!(m.member_wxid_sha, sha256_hex(&m.member_wxid));
        assert_eq!(m.member_wxid, "wxid_member_004", "member_wxid 明文存在 (退群回读源)");
        assert_eq!(m.chatroom_id, "12345678@chatroom");
        assert_eq!(m.display_name.as_deref(), Some("阿强"));
    }

    // ── project_watermark (SystemCursorUpdate → Watermark) ──

    /// 字段映射: account_id sha'd; source/kind/watermark_*/last_update 直传 (全元数据).
    #[test]
    fn project_watermark_maps() {
        let ev = SystemCursorUpdate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "message_5.db".to_string(),
                source_native_id: "cursor:m:msg".to_string(),
                event_type: EventType::SystemEvent,
                event_action: EventAction::CursorUpdate,
                event_seq: 5,
                ingest_time: 1,
            },
            kind: "message".to_string(),
            watermark_key: "(create_time, sort_seq, local_id)".to_string(),
            watermark_value: "[1780000000, 100]".to_string(),
            last_update: 2000,
        };
        let w = project_watermark(&ev);
        assert_eq!(w.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_ne!(w.account_id_sha, "wxid_acct_001", "account_id 脱敏");
        assert_eq!(w.source, "message_5.db");
        assert_eq!(w.kind, "message");
        assert_eq!(w.watermark_key, "(create_time, sort_seq, local_id)");
        assert_eq!(w.watermark_value, "[1780000000, 100]");
        assert_eq!(w.last_update, 2000);
    }

    // ── project_moment (SnsCreate → V3Moment; ADR-467 件1) ──

    fn sample_sns() -> SnsCreate {
        SnsCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "sns.db".to_string(),
                source_native_id: "Sns_-3518821952372526549".to_string(),
                event_type: EventType::SnsEvent,
                event_action: EventAction::Create,
                event_seq: 9,
                ingest_time: 1,
            },
            tid: -3_518_821_952_372_526_549,
            author: "wxid_author_002".to_string(),
            create_time: 1_779_546_990,
            moment_type: 1,
            content_desc: "晚上吃啥".to_string(),
            author_nickname: Some("小明".to_string()),
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
            raw_content: r#"<SnsDataItem><TimelineObject><ContentObject><type>1</type><mediaList><media><id>111</id><type>2</type><thumb type="1" key="K1">http://thumb/150</thumb><url type="1" md5="MD5A" key="K1" enc_idx="1">http://full/0</url><size width="1920" height="2560" totalSize="491021"/></media></mediaList></ContentObject></TimelineObject><LocalExtraInfo><nickname>作者</nickname><like_user_list><user_comment><username>wxid_liker</username><nickname>点赞人</nickname><type>1</type><create_time>1700000001</create_time></user_comment></like_user_list><comment_user_list><user_comment><comment_id>20</comment_id><username>wxid_commenter</username><nickname>评论人</nickname><content>好看</content><type>2</type><create_time>1700000002</create_time></user_comment></comment_user_list></LocalExtraInfo></SnsDataItem>"#.to_string(),
        }
    }

    /// 字段映射 + author sha + content_desc 明文 + char 长度 + 双轨一致 + 元数据直传。
    #[test]
    fn project_moment_maps_and_shas() {
        let m = project_moment(&sample_sns());
        assert_eq!(m.account_id_sha, sha256_hex("wxid_acct_001"));
        assert_eq!(m.source, "sns.db");
        assert_eq!(m.source_native_id, "Sns_-3518821952372526549");
        assert_eq!(m.tid, -3_518_821_952_372_526_549);
        assert_eq!(m.author_sha, sha256_hex("wxid_author_002"));
        assert_eq!(m.create_time, 1_779_546_990);
        assert_eq!(m.moment_type, 1);
        // 双轨一致 (明文 = sha 的原文)。
        assert_eq!(m.author_sha, sha256_hex(&m.author));
        assert_eq!(m.account_id_sha, sha256_hex(&m.account_id));
        // content_desc 明文 + char 长度 (晚上吃啥 = 4 字)。
        assert_eq!(m.content_desc, "晚上吃啥");
        assert_eq!(m.content_desc_len, 4);
        assert_eq!(m.author_nickname.as_deref(), Some("小明"));
        assert_eq!(m.location_label.as_deref(), Some("台州市"));
        assert_eq!(m.latitude, Some(121.382_042));
        assert_eq!(m.media_count, 1);
        assert_eq!(m.like_count, 3);
    }

    /// K-R4: V3Moment 持明文但 Debug 脱敏 — 不含裸 author/正文/昵称。
    #[test]
    fn project_moment_no_raw_leak() {
        let m = project_moment(&sample_sns());
        let dbg = format!("{m:?}");
        for raw in ["wxid_author_002", "晚上吃啥", "小明", "wxid_acct_001"] {
            assert!(!dbg.contains(raw), "K-R4: 投影产物 V3Moment Debug 含裸值 {raw}");
        }
    }

    /// project_moment_media (件2a): 解 raw_content 媒体 → V3MomentMedia 行; PK/字段/双轨正确。
    #[test]
    fn project_moment_media_maps() {
        let ms = project_moment_media(&sample_sns());
        assert_eq!(ms.len(), 1, "1 媒体 → 1 行");
        assert_eq!(ms[0].source_native_id, "Sns_-3518821952372526549", "PK = 所属 moment");
        assert_eq!(ms[0].account_id_sha, sha256_hex("wxid_acct_001"));
        assert_eq!(ms[0].media_seq, 0);
        assert_eq!(ms[0].media_type, 2, "图 type 2");
        assert_eq!(ms[0].url.as_deref(), Some("http://full/0"), "明文 url (ADR-427)");
        assert_eq!(ms[0].md5.as_deref(), Some("MD5A"));
        assert_eq!(ms[0].url_key.as_deref(), Some("K1"));
        assert_eq!(ms[0].width, 1920);
    }

    /// 无媒体动态 → 空 Vec。
    #[test]
    fn project_moment_media_empty_when_no_media() {
        let mut ev = sample_sns();
        ev.raw_content = "<SnsDataItem><TimelineObject><ContentObject><type>2</type><mediaList/></ContentObject></TimelineObject></SnsDataItem>".to_string();
        assert!(project_moment_media(&ev).is_empty(), "纯文字动态无媒体");
    }

    /// K-R4: V3MomentMedia Debug 脱敏 — 不含裸 url/md5/key。
    #[test]
    fn project_moment_media_no_raw_leak() {
        let dbg = format!("{:?}", project_moment_media(&sample_sns())[0]);
        for raw in ["http://full/0", "MD5A", "K1"] {
            assert!(!dbg.contains(raw), "K-R4: V3MomentMedia Debug 含裸值 {raw}");
        }
        assert!(dbg.contains("url_sha8"));
    }

    /// project_moment_interaction (件2b): 解 raw_content 赞+评论 → V3MomentInteraction 行; PK/字段/双轨。
    #[test]
    fn project_moment_interaction_maps() {
        let items = project_moment_interaction(&sample_sns());
        assert_eq!(items.len(), 2, "1 赞 + 1 评论 → 2 行");
        assert_eq!(items[0].kind, "like");
        assert_eq!(
            items[0].source_native_id, "Sns_-3518821952372526549",
            "PK = 所属 moment"
        );
        assert_eq!(items[0].from_user.as_deref(), Some("wxid_liker"));
        assert_eq!(items[0].from_user_sha, sha256_hex("wxid_liker"), "双轨一致");
        assert_eq!(items[0].content, None, "赞无 content");
        assert_eq!(items[1].kind, "comment");
        assert_eq!(items[1].content.as_deref(), Some("好看"), "评论文本明文 (ADR-427)");
        assert_eq!(items[1].from_user_sha, sha256_hex("wxid_commenter"));
    }

    /// 无互动动态 → 空 Vec。
    #[test]
    fn project_moment_interaction_empty() {
        let mut ev = sample_sns();
        ev.raw_content =
            "<SnsDataItem><LocalExtraInfo><nickname>作者</nickname></LocalExtraInfo></SnsDataItem>".to_string();
        assert!(project_moment_interaction(&ev).is_empty());
    }

    /// K-R4: V3MomentInteraction Debug 脱敏 — 不含裸 from_user/content/昵称。
    #[test]
    fn project_moment_interaction_no_raw_leak() {
        let dbg = format!("{:?}", project_moment_interaction(&sample_sns())[1]);
        for raw in ["wxid_commenter", "好看", "评论人"] {
            assert!(!dbg.contains(raw), "K-R4: V3MomentInteraction Debug 含裸值 {raw}");
        }
        assert!(dbg.contains("from_user_sha8") && dbg.contains("content_sha8"));
    }
}
