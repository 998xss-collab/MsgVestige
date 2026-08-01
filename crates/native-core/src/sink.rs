//! sink — DecodedEvent → L1 持久化 (archive 写 + L2 投影 insert). native-core 子系统 (ADR-416 §3.2.1).
//!
//! [`write_decoded_event`] 是 EventEmitter 消费端 / adapter 的【落库出口】: 把一条 [`DecodedEvent`]
//! (1) 先写 raw_payload_archive (溯源不可变, §6.8 契约5 archive-first), (2) 再投影 + 写 L2 业务表.
//! **一条事件的两步写在一个事务里** (原子: 要么都成要么都回滚; archive 是真相, L2 是物化视图可重放重建).
//!
//! ⚠️ **"可重放重建"有一处明确的例外**(用户 2026-07-27 拍板, ADR-508 D25): 消息的**传输状态列**
//! (`status` / `upload_status` / `download_status` / `sort_seq` / `server_seq` / `origin_source` /
//! `local_type_raw`) **不进 archive 的内容指纹**。它们随消息生命周期变(发送中→已送达→已读),
//! 而 archive 是 `INSERT OR IGNORE` —— 纳入指纹会让同一条消息每变一次状态就多一条 archive 记录
//! (百万级库涨到千万级), 换来的是分析价值极低的传输状态历史。
//!
//! 于是: **archive 记首次观测到的那个版本, `message` 表(覆盖写)记最新状态**, 两者在这几列上会不一致,
//! 这是**设计如此**。重放能重建的是"除这几个传输状态列之外的一切"。
//! 守卫: `event::canonical` 的 `mutable_transport_columns_stay_out_of_digest`(正反两向都验过)。
//!
//! `src_create_time_ms` 由【调用方 (adapter)】给 (从源 db 行取, ADR-413 §4 矩阵; system_event 用 0) —
//! 不在此提取 (事件结构体如 ContactUpdate 不带时间字段, adapter 才有源 db 行).
//!
//! ## L2 派发 (7 变体)
//! message→message 表 / contact→person + person_alias / chatroom_create→chatroom /
//! member_add→chatroom_member upsert / member_remove→mark_left (UPDATE 翻 is_in_group=0) /
//! cursor→etl_state 水位 / error→仅 archive (无 L2 表).

use rusqlite::{Connection, Transaction};

use crate::emit::emit;
use crate::event::decoded::DecodedEvent;
use crate::event::privacy::PrivacyMode;
use crate::projection::{
    project_avatar, project_bizchat_user, project_chatroom, project_chatroom_member_add,
    project_chatroom_member_events, project_custom_emoticon, project_favorite, project_favorite_media,
    project_favorite_tag, project_finder_visit, project_friend_verify, project_group_pay, project_group_pay_members,
    project_message, project_message_app, project_message_call, project_message_card, project_message_forward,
    project_message_hongbao_claim, project_message_location, project_message_media, project_message_mention,
    project_moment, project_moment_feed, project_moment_interaction, project_moment_media, project_person,
    project_person_alias, project_red_envelope, project_session, project_sns_notify, project_transfer,
    project_watermark, ProjectionError,
};
use crate::sha256_hex;
use crate::state::upsert_watermark;
use crate::storage::{
    delete_chatroom_member_events, delete_favorite_media, delete_group_pay_members, delete_message_app,
    delete_message_call, delete_message_card, delete_message_forward_items, delete_message_hongbao_claim,
    delete_message_location, delete_message_media, delete_message_mentions, delete_moment_interactions,
    delete_moment_media, insert_avatar_image, insert_bizchat_user, insert_chatroom, insert_chatroom_member_event,
    insert_custom_emoticon, insert_favorite, insert_favorite_media, insert_favorite_tag, insert_finder_visit,
    insert_friend_verify, insert_group_pay, insert_group_pay_member, insert_message, insert_message_app,
    insert_message_call, insert_message_card, insert_message_forward_item, insert_message_hongbao_claim,
    insert_message_location, insert_message_media, insert_message_mention, insert_moment, insert_moment_feed,
    insert_moment_interaction, insert_moment_media, insert_person, insert_person_alias, insert_record,
    insert_red_envelope, insert_session, insert_sns_notify, insert_transfer, mark_chatroom_member_left,
    upsert_chatroom_member_add,
};

/// sink 落库错误.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// L1 sqlite 写失败 (archive / L2 表 / 事务).
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),
    /// 投影失败 (e.g. message.server_id 非整数) — 整事务回滚.
    #[error("projection error: {0}")]
    Projection(#[from] ProjectionError),
}

/// 把一条 [`DecodedEvent`] 落库: archive 先写 + L2 投影 insert, **一事务原子**.
///
/// - `src_create_time_ms`: 源 db 事件时间 (adapter 按 ADR-413 §4 给; system_event 用 0; 进 fingerprint);
/// - `ingest_time`: adapter emit 时间毫秒 (不进 fingerprint, 仅存储 + 24h 滚动删);
/// - `mode`: 隐私模式 (控制 archive payload_json 明文范围; ADR-427 起 archive 默认明文, L2 表也持明文列, Debug 出口脱敏).
///
/// 任一步失败 → 事务回滚 (archive 行也撤销), 返 Err. archive 重放去重 (5 元组) → 重复事件 archive 撞键
/// 被忽略, L2 仍 idempotent upsert (无害).
///
/// # Errors
/// [`SinkError::Storage`] (sqlite 写/事务失败) / [`SinkError::Projection`] (投影失败).
pub fn write_decoded_event(
    conn: &mut Connection,
    event: &DecodedEvent,
    src_create_time_ms: u64,
    ingest_time: i64,
    mode: PrivacyMode,
) -> Result<(), SinkError> {
    let tx = conn.transaction()?;
    write_decoded_event_in_tx(&tx, event, src_create_time_ms, ingest_time, mode)?;
    tx.commit()?;
    Ok(())
}

/// 在【调用方已开的事务】内落库一条事件 (archive + L2), **不自己开/提交事务**。
///
/// 批量提交路径 (pipeline 一批多条共用一个事务) 复用本函数, 摊薄每条的事务开销 (每条 begin/commit →
/// 每批一次)。原子性由调用方的事务边界保证 (整批一起 commit/rollback); archive-first + 5 元组重放去重
/// 语义不变。[`write_decoded_event`] = 本函数 + 单条一事务 (兼容非批量 caller / 测试)。
///
/// # Errors
/// [`SinkError::Storage`] / [`SinkError::Projection`] (失败后调用方应回滚整个事务)。
pub fn write_decoded_event_in_tx(
    tx: &Transaction,
    event: &DecodedEvent,
    src_create_time_ms: u64,
    ingest_time: i64,
    mode: PrivacyMode,
) -> Result<(), SinkError> {
    // (1) archive 先写 (§6.8 契约5 — 溯源不可变 + 5 元组去重). insert_record 返 bool (是否新插); 撞键忽略.
    let record = emit(event, src_create_time_ms, ingest_time, mode);
    insert_record(tx, &record)?;

    // (2) L2 投影 + insert (派发到对应表/操作).
    match event {
        DecodedEvent::Message(m) => {
            let msg = project_message(m)?;
            // appmsg 卡片 (视频号/小程序/链接) → message_app 派生表 (非 appmsg None; ADR-455)。
            // replace-projection (codex 批C P1): 先按 message PK 删旧派生行, 再条件插 — 保 message 从
            // appmsg→非 appmsg (源内容/解析规则变) 时 message_app 不残留旧行, message↔message_app 恒一致。
            delete_message_app(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            if let Some(app) = project_message_app(m) {
                insert_message_app(tx, &app)?;
            }
            // 群收款逐付款人 (type2001 newaa payerlist `wxid,金额,状态`) → group_pay_member 派生表
            // (一群收款消息多付款人 → 多行; ADR-488)。同 message_mention replace-projection: 先按 message PK 删整组再逐条插。
            delete_group_pay_members(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            for member in project_group_pay_members(m) {
                insert_group_pay_member(tx, &member)?;
            }
            // 媒体元数据 (图/视频/表情 md5/aeskey/cdn) → message_media 派生表 (非媒体 None; ADR-456)。
            // 同 replace-projection: 先按 message PK 删旧派生行, 再条件插 — 保 message 从 媒体→非媒体 时不残留。
            delete_message_media(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            if let Some(media) = project_message_media(m) {
                insert_message_media(tx, &media)?;
            }
            // 位置 (local_type=48 经纬度/地点) → message_location 派生表 (非位置 None; ADR-462)。
            // 同 replace-projection: 先按 message PK 删旧位置行, 再条件插 — 保 message 从 位置→非位置 时不残留。
            delete_message_location(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            if let Some(loc) = project_message_location(m) {
                insert_message_location(tx, &loc)?;
            }
            // 通话记录 (type50 <voipmsg> 类型/时长/结果) → message_call 派生表 (非通话 None; ADR-475)。
            // 同 replace-projection: 先按 message PK 删旧通话行, 再条件插 — 保 message 从 通话→非通话 时不残留。
            delete_message_call(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            if let Some(call) = project_message_call(m) {
                insert_message_call(tx, &call)?;
            }
            // 红包领取通知 (sys=hongbao "谁领了红包": 领取人 + 单号 + 方向) → message_hongbao_claim 派生表 (非领取 None; ADR-504)。
            delete_message_hongbao_claim(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            if let Some(claim) = project_message_hongbao_claim(m) {
                insert_message_hongbao_claim(tx, &claim)?;
            }
            // 名片 (type42 <msg> 属性: 被推荐人 nickname/alias/省市/签名) → message_card 派生表 (非名片 None; ADR-477)。
            delete_message_card(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            if let Some(card) = project_message_card(m) {
                insert_message_card(tx, &card)?;
            }
            // @提及名单 (群消息 atuserlist) → message_mention 派生表 (一消息多@ → 多行; ADR-457)。
            // replace-projection: 先按 message PK 删该消息**所有** @行, 再逐条插 — 保 @名单变化不残留。
            delete_message_mentions(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            for mention in project_message_mention(m) {
                insert_message_mention(tx, &mention)?;
            }
            // 群成员进出事件 (msg_type=10000 入群/退群系统消息) → chatroom_member_event 派生表
            // (一消息多成员 → 多行; source_native_id=anchor:seq 逐行唯一)。同 message_mention 多行
            // replace-projection: 先按裸 message anchor (msg_native_id) 删该消息整组, 再逐条插。
            delete_chatroom_member_events(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            for evt in project_chatroom_member_events(m) {
                insert_chatroom_member_event(tx, &evt)?;
            }
            // 合并转发逐条子项 (type49 子类19 datalist) → message_forward_item 派生表 (非转发空; ADR-476)。
            // 同 message_mention 多行 replace-projection: 先按 message PK 删整组, 再逐条插。
            delete_message_forward_items(tx, &msg.account_id_sha, &msg.source, &msg.source_native_id)?;
            for item in project_message_forward(m) {
                insert_message_forward_item(tx, &item)?;
            }
            insert_message(tx, &msg)?;
        }
        DecodedEvent::ContactUpdate(c) => {
            // 同一 contact 两投: person 表 (量 _len) + person_alias 表 (存 _sha).
            insert_person(tx, &project_person(c))?;
            insert_person_alias(tx, &project_person_alias(c))?;
        }
        DecodedEvent::SessionUpdate(s) => {
            insert_session(tx, &project_session(s))?;
        }
        DecodedEvent::FavoriteCreate(fav) => {
            let f = project_favorite(fav);
            // 媒体引用 (笔记图片/文件 md5) → favorite_media 派生表 (一收藏多媒体 → 多行; ADR-472)。
            delete_favorite_media(tx, &f.account_id_sha, &f.source, &f.source_native_id)?;
            for media in project_favorite_media(fav) {
                insert_favorite_media(tx, &media)?;
            }
            insert_favorite(tx, &f)?;
        }
        DecodedEvent::FavoriteTagCreate(ft) => {
            insert_favorite_tag(tx, &project_favorite_tag(ft))?;
        }
        DecodedEvent::SnsCreate(sns) => {
            let moment = project_moment(sns);
            // 逐条媒体 (图/视频) → moment_media 派生表 (件2a)。replace-projection: 先按 moment PK 删旧媒体行,
            // 再逐条插 — 保媒体变化不残留 (同 message_mention 一消息多@整组删)。
            delete_moment_media(tx, &moment.account_id_sha, &moment.source, &moment.source_native_id)?;
            for media in project_moment_media(sns) {
                insert_moment_media(tx, &media)?;
            }
            // 逐条互动 (点赞/评论) → moment_interaction 派生表 (件2b)。同 replace-projection (点赞/评论增删不残留)。
            delete_moment_interactions(tx, &moment.account_id_sha, &moment.source, &moment.source_native_id)?;
            for it in project_moment_interaction(sns) {
                insert_moment_interaction(tx, &it)?;
            }
            insert_moment(tx, &moment)?;
        }
        DecodedEvent::TransferCreate(t) => {
            insert_transfer(tx, &project_transfer(t))?;
        }
        DecodedEvent::RedEnvelopeCreate(r) => {
            insert_red_envelope(tx, &project_red_envelope(r))?;
        }
        DecodedEvent::GroupPayCreate(g) => {
            insert_group_pay(tx, &project_group_pay(g))?;
        }
        DecodedEvent::FriendVerifyCreate(v) => {
            insert_friend_verify(tx, &project_friend_verify(v))?;
        }
        DecodedEvent::FinderVisitCreate(fv) => {
            insert_finder_visit(tx, &project_finder_visit(fv))?;
        }
        DecodedEvent::MomentFeedCreate(mf) => {
            insert_moment_feed(tx, &project_moment_feed(mf))?;
        }
        DecodedEvent::SnsNotifyCreate(sn) => {
            insert_sns_notify(tx, &project_sns_notify(sn))?;
        }
        DecodedEvent::CustomEmoticonCreate(e) => {
            insert_custom_emoticon(tx, &project_custom_emoticon(e))?;
        }
        DecodedEvent::AvatarImageCreate(e) => {
            insert_avatar_image(tx, &project_avatar(e))?;
        }
        DecodedEvent::BizChatContactCreate(e) => {
            insert_bizchat_user(tx, &project_bizchat_user(e))?;
        }
        DecodedEvent::ChatroomCreate(c) => {
            insert_chatroom(tx, &project_chatroom(c))?;
        }
        DecodedEvent::ChatroomMemberAdd(m) => {
            upsert_chatroom_member_add(tx, &project_chatroom_member_add(m))?;
        }
        DecodedEvent::ChatroomMemberRemove(m) => {
            // member_remove 是 UPDATE 翻 is_in_group=0 + left_at (保留 joined_at), 不产整行.
            // left_at 取事件值; 缺则回退 src_create_time (member_remove 的源时间即退群时间, ADR-413 §4 矩阵).
            let prov = &m.provenance;
            let left_at = m
                .left_at
                .unwrap_or_else(|| i64::try_from(src_create_time_ms).unwrap_or(i64::MAX));
            let affected = mark_chatroom_member_left(
                tx,
                &sha256_hex(prov.account_id.as_str()),
                &prov.source,
                &prov.source_native_id,
                left_at,
            )?;
            if affected == 0 {
                // §3.1.7: PK 不在业务表 → 仅业务表跳过 (archive 已写); 写 error system_event 推后续 KI.
                tracing::warn!(
                    "member_remove on PK absent from chatroom_member; L2 跳过 (archive 已写), error 事件推后续"
                );
            }
        }
        DecodedEvent::SystemCursorUpdate(c) => {
            upsert_watermark(tx, &project_watermark(c))?;
        }
        DecodedEvent::SystemError(_) => {
            // 系统错误无 L2 表 — 只进 archive (溯源事件日志), 不投 L2.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::chatroom::{ChatroomCreate, ChatroomMemberAdd, ChatroomMemberRemove};
    use crate::event::contact::ContactUpdate;
    use crate::event::message::MessageCreate;
    use crate::event::provenance::Provenance;
    use crate::event::session::SessionUpdate;
    use crate::event::system::SystemCursorUpdate;
    use crate::event::{EventAction, EventType};
    use crate::key_provider::Wxid;
    use crate::state::init_etl_state_table;
    use crate::storage::{
        init_archive_table, init_chatroom_member_event_table, init_chatroom_member_table, init_chatroom_table,
        init_group_pay_member_table, init_message_app_table, init_message_call_table, init_message_card_table,
        init_message_forward_item_table, init_message_hongbao_claim_table, init_message_location_table,
        init_message_media_table, init_message_mention_table, init_message_table, init_person_alias_table,
        init_person_table, init_session_table,
    };

    /// 真文件库 + 建全 L1 表 (archive + 各 L2 + etl_state).
    fn setup() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::storage::open(&dir.path().join("l1.db")).unwrap();
        init_archive_table(&conn).unwrap();
        init_message_table(&conn).unwrap();
        init_message_app_table(&conn).unwrap();
        init_message_media_table(&conn).unwrap();
        init_message_location_table(&conn).unwrap();
        init_message_call_table(&conn).unwrap();
        init_message_hongbao_claim_table(&conn).unwrap();
        init_message_card_table(&conn).unwrap();
        init_message_forward_item_table(&conn).unwrap();
        init_message_mention_table(&conn).unwrap();
        init_chatroom_member_event_table(&conn).unwrap();
        init_group_pay_member_table(&conn).unwrap();
        init_person_table(&conn).unwrap();
        init_person_alias_table(&conn).unwrap();
        init_chatroom_table(&conn).unwrap();
        init_chatroom_member_table(&conn).unwrap();
        init_session_table(&conn).unwrap();
        init_etl_state_table(&conn).unwrap();
        (dir, conn)
    }

    fn prov(t: EventType, a: EventAction, native: &str) -> Provenance {
        Provenance {
            account_id: Wxid::try_new("wxid_acct_001").unwrap(),
            source: "src.db".to_string(),
            source_native_id: native.to_string(),
            event_type: t,
            event_action: a,
            event_seq: 1,
            ingest_time: 1,
        }
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    fn msg(server_id: &str, native: &str) -> DecodedEvent {
        DecodedEvent::Message(MessageCreate {
            provenance: prov(EventType::Message, EventAction::Create, native),
            server_id: server_id.to_string(),
            server_seq: 0,
            origin_source: 0,
            upload_status: 0,
            download_status: 0,
            conv_id: "wxid_conv".to_string(),
            sender_wxid: Wxid::try_new("wxid_send").unwrap(),
            create_time: 100,
            sort_seq: 1,
            msg_type: 1,
            msg_sub_type: None,
            msg_type_name: "TEXT".to_string(),
            msg_sub_type_name: None,
            status: 1,
            local_type_raw: 1,
            is_chatroom: false,
            raw_xml_present: false,
            decode_kind: "plain".to_string(),
            text_content: "hi".to_string(),
            msg_source: String::new(),
        })
    }

    /// message: archive 行 + message 行各 1.
    #[test]
    fn message_writes_archive_and_l2() {
        let (_d, mut conn) = setup();
        write_decoded_event(&mut conn, &msg("123", "Msg:1"), 100, 200, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1, "archive 写了");
        assert_eq!(count(&conn, "message"), 1, "message L2 写了");
    }

    /// appmsg 消息 (ADR-455): 同事务 insert_message + insert_message_app; 视频号字段落库。
    fn appmsg_msg(native: &str, content: &str) -> DecodedEvent {
        let DecodedEvent::Message(mut mc) = msg("999", native) else {
            unreachable!()
        };
        mc.msg_type = 49;
        mc.msg_type_name = "APP_XML".to_string();
        mc.text_content = content.to_string();
        DecodedEvent::Message(mc)
    }

    #[test]
    fn appmsg_message_writes_message_app() {
        let (_d, mut conn) = setup();
        let finder = "<msg><appmsg><type>51</type><finderFeed><nickname><![CDATA[作者甲]]></nickname><mediaCount>5</mediaCount><username><![CDATA[v2_x]]></username></finderFeed></appmsg></msg>";
        write_decoded_event(
            &mut conn,
            &appmsg_msg("Msg:app1", finder),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "message"), 1, "message L2 写了");
        assert_eq!(count(&conn, "message_app"), 1, "appmsg → message_app 派生行");
        let nick: String = conn
            .query_row(
                "SELECT app_nickname FROM message_app WHERE source_native_id='Msg:app1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(nick, "作者甲", "视频号作者落库 (同事务)");
    }

    /// codex 批C P1: replace-projection — 同 PK 先 appmsg 后普通消息 → message_app 旧行清掉 (不残留)。
    #[test]
    fn message_app_replace_projection_clears_stale() {
        let (_d, mut conn) = setup();
        let finder = "<msg><appmsg><type>51</type><finderFeed><nickname><![CDATA[作者甲]]></nickname><username><![CDATA[v2_x]]></username></finderFeed></appmsg></msg>";
        // run1: appmsg → message_app 1 行。
        write_decoded_event(
            &mut conn,
            &appmsg_msg("Msg:p", finder),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "message_app"), 1, "首投 appmsg → 1 派生行");
        // run2: 同 PK 变普通文本消息 → message_app 应清空。
        write_decoded_event(&mut conn, &msg("999", "Msg:p"), 100, 300, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "message"), 1, "同 PK message upsert 仍 1");
        assert_eq!(
            count(&conn, "message_app"),
            0,
            "message 变非 appmsg → message_app 旧行清掉 (replace-projection)"
        );
    }

    /// ADR-456: 图片消息 (type 3) → 同事务 insert_message + insert_message_media; md5/cdn 落库。
    fn media_msg(native: &str, msg_type: i32, content: &str) -> DecodedEvent {
        let DecodedEvent::Message(mut mc) = msg("888", native) else {
            unreachable!()
        };
        mc.msg_type = msg_type;
        mc.msg_type_name = "IMAGE".to_string();
        mc.text_content = content.to_string();
        DecodedEvent::Message(mc)
    }

    #[test]
    fn media_message_writes_message_media() {
        let (_d, mut conn) = setup();
        let img = r#"<msg><img md5="8bbfc6c281f8aaaaaaaaaaaaaaaaaaaa" cdnmidimgurl="u1" length="500" /></msg>"#;
        write_decoded_event(
            &mut conn,
            &media_msg("Msg:img1", 3, img),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "message"), 1, "message L2 写了");
        assert_eq!(count(&conn, "message_media"), 1, "图片 → message_media 派生行");
        let (kind, md5): (String, String) = conn
            .query_row(
                "SELECT media_kind, md5 FROM message_media WHERE source_native_id='Msg:img1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(kind, "image");
        assert_eq!(md5, "8bbfc6c281f8aaaaaaaaaaaaaaaaaaaa", "md5 落库 (同事务)");
    }

    /// replace-projection — 同 PK 先图片后普通文本 → message_media 旧行清掉 (不残留)。
    #[test]
    fn message_media_replace_projection_clears_stale() {
        let (_d, mut conn) = setup();
        let img = r#"<msg><img md5="8bbfc6c281f8aaaaaaaaaaaaaaaaaaaa" cdnmidimgurl="u1" /></msg>"#;
        write_decoded_event(
            &mut conn,
            &media_msg("Msg:m", 3, img),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "message_media"), 1, "首投图片 → 1 派生行");
        write_decoded_event(&mut conn, &msg("999", "Msg:m"), 100, 300, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "message"), 1, "同 PK message upsert 仍 1");
        assert_eq!(
            count(&conn, "message_media"),
            0,
            "message 变非媒体 → message_media 旧行清掉 (replace-projection)"
        );
    }

    /// ADR-457: 群消息 @提及 → 同事务 insert_message + N 行 insert_message_mention。
    fn mention_msg(native: &str, source: &str) -> DecodedEvent {
        let DecodedEvent::Message(mut mc) = msg("777", native) else {
            unreachable!()
        };
        mc.is_chatroom = true;
        mc.msg_source = source.to_string();
        DecodedEvent::Message(mc)
    }

    #[test]
    fn mention_message_writes_message_mention() {
        let (_d, mut conn) = setup();
        let src = "<msgsource><atuserlist><![CDATA[wxid_a,wxid_b]]></atuserlist></msgsource>";
        write_decoded_event(
            &mut conn,
            &mention_msg("Msg:at1", src),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "message"), 1, "message L2 写了");
        assert_eq!(count(&conn, "message_mention"), 2, "两个被@ → 两行");
    }

    /// replace-projection — 同 PK @名单从 [a,b] 变 [c] → 旧两行清掉, 只剩 1 行 (不残留)。
    #[test]
    fn message_mention_replace_projection_clears_stale() {
        let (_d, mut conn) = setup();
        let src2 = "<atuserlist><![CDATA[wxid_a,wxid_b]]></atuserlist>";
        write_decoded_event(
            &mut conn,
            &mention_msg("Msg:at", src2),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "message_mention"), 2, "首投 2 @行");
        let src1 = "<atuserlist><![CDATA[wxid_c]]></atuserlist>";
        write_decoded_event(
            &mut conn,
            &mention_msg("Msg:at", src1),
            100,
            300,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(
            count(&conn, "message_mention"),
            1,
            "@名单变 → 旧行删净, 只剩新 1 行 (replace-projection)"
        );
    }

    /// 群成员进出事件: msg_type=10000 群系统消息 → 同事务 insert_message + N 行 insert_chatroom_member_event。
    fn member_evt_msg(native: &str, text: &str) -> DecodedEvent {
        let DecodedEvent::Message(mut mc) = msg("888", native) else {
            unreachable!()
        };
        mc.is_chatroom = true;
        mc.msg_type = 10000;
        mc.msg_type_name = "SYSTEM".to_string();
        mc.text_content = text.to_string();
        DecodedEvent::Message(mc)
    }

    #[test]
    fn member_join_multi_writes_chatroom_member_event() {
        let (_d, mut conn) = setup();
        // 结构化入群 XML, names 下 2 member → 2 行 (一消息多成员不塌陷)。
        let text = r#"<sysmsg type="sysmsgtemplate"><content_template><template>你邀请"$names$"加入了群聊</template><link_list><link name="names"><memberlist><member><username>wxid_m1</username><nickname>甲</nickname></member><member><username>wxid_m2</username><nickname>乙</nickname></member></memberlist></link></link_list></content_template></sysmsg>"#;
        write_decoded_event(
            &mut conn,
            &member_evt_msg("Msg:mj", text),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "message"), 1, "message L2 写了");
        assert_eq!(count(&conn, "chatroom_member_event"), 2, "2 成员入群 → 2 行 (不塌陷)");
        // 两行 source_native_id 逐行唯一 (anchor:0 / anchor:1)。
        let ids: Vec<String> = {
            let mut st = conn
                .prepare("SELECT source_native_id FROM chatroom_member_event ORDER BY source_native_id")
                .unwrap();
            st.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        assert_eq!(
            ids,
            vec!["Msg:mj:0".to_string(), "Msg:mj:1".to_string()],
            "anchor:seq 逐行唯一"
        );
        let kind: String = conn
            .query_row(
                "SELECT event_kind FROM chatroom_member_event WHERE source_native_id='Msg:mj:0'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kind, "join");
    }

    /// replace-projection — 同消息成员名单变 (2人→1人) → 旧两行删净只剩 1 行 (按 msg_native_id 删整组)。
    #[test]
    fn chatroom_member_event_replace_projection_clears_stale() {
        let (_d, mut conn) = setup();
        let two = r#"<sysmsg type="sysmsgtemplate"><link_list><link name="names"><memberlist><member><username>wxid_m1</username><nickname>甲</nickname></member><member><username>wxid_m2</username><nickname>乙</nickname></member></memberlist></link></link_list></sysmsg>加入了群聊"#;
        write_decoded_event(
            &mut conn,
            &member_evt_msg("Msg:re", two),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "chatroom_member_event"), 2, "首投 2 行");
        let one = r#"<sysmsg type="sysmsgtemplate"><link_list><link name="names"><memberlist><member><username>wxid_m3</username><nickname>丙</nickname></member></memberlist></link></link_list></sysmsg>加入了群聊"#;
        write_decoded_event(
            &mut conn,
            &member_evt_msg("Msg:re", one),
            100,
            300,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(
            count(&conn, "chatroom_member_event"),
            1,
            "成员名单变 → 旧行删净只剩新 1 行 (replace-projection)"
        );
    }

    /// contact: person + person_alias 各 1 (同一事件两投).
    #[test]
    fn contact_writes_person_and_alias() {
        let (_d, mut conn) = setup();
        let ev = DecodedEvent::ContactUpdate(ContactUpdate {
            provenance: prov(EventType::ContactUpdate, EventAction::Create, "Contact:1"),
            username: "wxid_friend".to_string(),
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
        write_decoded_event(&mut conn, &ev, 0, 200, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1);
        assert_eq!(count(&conn, "person"), 1, "person 写了");
        assert_eq!(count(&conn, "person_alias_by_account_min"), 1, "person_alias 写了");
    }

    fn session_ev(summary: Option<&str>, unread: i64, sort: i64) -> DecodedEvent {
        DecodedEvent::SessionUpdate(SessionUpdate {
            provenance: prov(EventType::SessionUpdate, EventAction::Create, "Session:1"),
            username: "wxid_peer".to_string(),
            summary: summary.map(str::to_string),
            last_sender_display_name: None,
            unread_count: unread,
            last_msg_type: 1,
            last_msg_sub_type: 0,
            sort_timestamp: sort,
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
        })
    }

    /// session: archive 行 + session L2 行各 1.
    #[test]
    fn session_writes_archive_and_l2() {
        let (_d, mut conn) = setup();
        write_decoded_event(
            &mut conn,
            &session_ev(Some("hi"), 3, 1000),
            0,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1, "archive 写了");
        assert_eq!(count(&conn, "session"), 1, "session L2 写了");
    }

    /// codex P1 锁定: archive content_digest 撞键 (summary/unread 同) 时 insert_session 仍**无条件 upsert**
    /// → L2 session.sort_timestamp 刷新 (sort_timestamp 不进 content_digest, 靠 projection upsert 保最新态)。
    #[test]
    fn session_archive_dedup_still_upserts_sort_timestamp() {
        let (_d, mut conn) = setup();
        // run1: summary=hi unread=3 sort=1000 → archive 新行 + session sort=1000.
        write_decoded_event(
            &mut conn,
            &session_ev(Some("hi"), 3, 1000),
            0,
            200,
            PrivacyMode::archive_canonical(),
        )
        .unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1);
        // run2: 同 summary/unread, 仅 sort=2000 变 → content_digest 同 → archive 撞键 (不增); insert_session 仍 upsert.
        write_decoded_event(
            &mut conn,
            &session_ev(Some("hi"), 3, 2000),
            0,
            300,
            PrivacyMode::archive_canonical(),
        )
        .unwrap();
        assert_eq!(
            count(&conn, "raw_payload_archive"),
            1,
            "summary/unread 同 → content_digest 同 → archive 撞键去重"
        );
        assert_eq!(count(&conn, "session"), 1, "同 PK upsert 不增行");
        let sort: i64 = conn
            .query_row("SELECT sort_timestamp FROM session", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            sort, 2000,
            "archive 撞键但 insert_session 无条件 upsert → sort_timestamp 刷新 (codex P1 锁定)"
        );
    }

    /// chatroom_create: chatroom 表写入.
    #[test]
    fn chatroom_create_writes_l2() {
        let (_d, mut conn) = setup();
        let ev = DecodedEvent::ChatroomCreate(ChatroomCreate {
            is_still_member: true,
            provenance: prov(EventType::ChatroomUpdate, EventAction::Create, "Chatroom:1"),
            chatroom_id: "x@chatroom".to_string(),
            chatroom_name: "群".to_string(),
            chatroom_remark: None,
            announcement: None,
            owner_wxid: None,
            member_count: 3,
            announcement_editor: None,
            announcement_publish_time: 0,
            xml_announcement: None,
            chat_room_status: 0,
        });
        write_decoded_event(&mut conn, &ev, 0, 200, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1);
        assert_eq!(count(&conn, "chatroom"), 1, "chatroom L2 写了");
    }

    /// cursor: etl_state 水位写入.
    #[test]
    fn cursor_writes_etl_state() {
        let (_d, mut conn) = setup();
        let ev = DecodedEvent::SystemCursorUpdate(SystemCursorUpdate {
            provenance: prov(EventType::SystemEvent, EventAction::CursorUpdate, "cursor:1"),
            kind: "message".to_string(),
            watermark_key: "k".to_string(),
            watermark_value: "[1]".to_string(),
            last_update: 5,
        });
        write_decoded_event(&mut conn, &ev, 0, 200, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1);
        assert_eq!(count(&conn, "etl_state"), 1, "水位写了");
    }

    /// member_add → chatroom_member upsert; 紧接 member_remove (同 PK) → mark_left 翻 is_in_group=0.
    #[test]
    fn member_add_then_remove() {
        let (_d, mut conn) = setup();
        let add = DecodedEvent::ChatroomMemberAdd(ChatroomMemberAdd {
            provenance: prov(EventType::ChatroomUpdate, EventAction::MemberAdd, "room:member:wx"),
            chatroom_id: "x@chatroom".to_string(),
            member_wxid: "wxid_m".to_string(),
            display_name: None,
            joined_at: Some(1000),
            role: "member".to_string(),
            invited_by: None,
        });
        write_decoded_event(&mut conn, &add, 1000, 200, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "chatroom_member"), 1);
        let in_group: bool = conn
            .query_row(
                "SELECT is_in_group FROM chatroom_member WHERE source_native_id='room:member:wx'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(in_group, "add 后在群");
        // remove (同 PK, native_id 同)
        let remove = DecodedEvent::ChatroomMemberRemove(ChatroomMemberRemove {
            provenance: prov(EventType::ChatroomUpdate, EventAction::MemberRemove, "room:member:wx"),
            chatroom_id: "x@chatroom".to_string(),
            member_wxid: "wxid_m".to_string(),
            left_at: Some(2000),
        });
        write_decoded_event(&mut conn, &remove, 2000, 300, PrivacyMode::default_sha()).unwrap();
        let (in_group2, left): (bool, Option<i64>) = conn
            .query_row(
                "SELECT is_in_group, left_at FROM chatroom_member WHERE source_native_id='room:member:wx'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(!in_group2, "remove 后退群");
        assert_eq!(left, Some(2000));
        assert_eq!(count(&conn, "chatroom_member"), 1, "退群不增行 (UPDATE)");
    }

    /// member_remove on 不在表的 PK → archive 仍写 + 不 panic (L2 跳过).
    #[test]
    fn member_remove_missing_pk_archive_only() {
        let (_d, mut conn) = setup();
        let remove = DecodedEvent::ChatroomMemberRemove(ChatroomMemberRemove {
            provenance: prov(
                EventType::ChatroomUpdate,
                EventAction::MemberRemove,
                "room:member:ghost",
            ),
            chatroom_id: "x@chatroom".to_string(),
            member_wxid: "wxid_ghost".to_string(),
            left_at: None,
        });
        write_decoded_event(&mut conn, &remove, 5000, 200, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1, "archive 仍写");
        assert_eq!(count(&conn, "chatroom_member"), 0, "L2 跳过 (PK 不在表)");
    }

    /// member_remove left_at=None 回退: 已存在成员行 → mark_left 用 src_create_time 落 left_at, 保留 joined_at.
    #[test]
    fn member_remove_left_at_falls_back_to_src_create_time() {
        let (_d, mut conn) = setup();
        let add = DecodedEvent::ChatroomMemberAdd(ChatroomMemberAdd {
            provenance: prov(EventType::ChatroomUpdate, EventAction::MemberAdd, "room:member:wx2"),
            chatroom_id: "x@chatroom".to_string(),
            member_wxid: "wxid_m2".to_string(),
            display_name: None,
            joined_at: Some(1000),
            role: "member".to_string(),
            invited_by: None,
        });
        write_decoded_event(&mut conn, &add, 1000, 200, PrivacyMode::default_sha()).unwrap();
        // remove with left_at=None, src_create_time=5000 → left_at 回退 5000
        let remove = DecodedEvent::ChatroomMemberRemove(ChatroomMemberRemove {
            provenance: prov(EventType::ChatroomUpdate, EventAction::MemberRemove, "room:member:wx2"),
            chatroom_id: "x@chatroom".to_string(),
            member_wxid: "wxid_m2".to_string(),
            left_at: None,
        });
        write_decoded_event(&mut conn, &remove, 5000, 300, PrivacyMode::default_sha()).unwrap();
        let (in_group, left, joined): (bool, Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT is_in_group, left_at, joined_at FROM chatroom_member WHERE source_native_id='room:member:wx2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(!in_group, "退群");
        assert_eq!(left, Some(5000), "left_at None → 回退 src_create_time 5000");
        assert_eq!(joined, Some(1000), "joined_at 保留 (UPDATE 不动)");
    }

    /// **事务原子性**: 投影失败 (message server_id 非整数) → 整事务回滚 (archive 行也撤销).
    #[test]
    fn projection_error_rolls_back_archive() {
        let (_d, mut conn) = setup();
        let err = write_decoded_event(
            &mut conn,
            &msg("not-int", "Msg:bad"),
            100,
            200,
            PrivacyMode::default_sha(),
        )
        .unwrap_err();
        assert!(matches!(err, SinkError::Projection(_)), "投影错");
        // 关键: archive 行被回滚 (不是 archive-written-but-L2-failed)
        assert_eq!(count(&conn, "raw_payload_archive"), 0, "事务回滚 — archive 行撤销");
        assert_eq!(count(&conn, "message"), 0);
    }

    /// system_error: 只写 archive, 无 L2 表.
    #[test]
    fn system_error_archive_only() {
        let (_d, mut conn) = setup();
        let ev = DecodedEvent::SystemError(crate::event::system::SystemError {
            provenance: prov(EventType::SystemEvent, EventAction::Error, "err:1"),
            error_code: "E1".to_string(),
            error_message: "boom".to_string(),
            context_json: None,
            occurred_at_canonical: "c".to_string(),
        });
        write_decoded_event(&mut conn, &ev, 0, 200, PrivacyMode::default_sha()).unwrap();
        assert_eq!(count(&conn, "raw_payload_archive"), 1, "error 进 archive");
    }
}
