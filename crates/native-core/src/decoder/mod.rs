//! decoder — cipher 解密出的明文 row/blob → 结构化 Event 字段 (decoder-解码.md).
//!
//! ## 责任与边界 (decoder-解码.md §1)
//! 是: SQLite 明文行 → 业务字段; zstd 解压 (微信 4.x message_content); proto 解析 (PackedInfoData);
//!     XML 解析 (朋友圈/群公告); 图片 .dat 解密.
//! 不是: 不做解密 (cipher 已给明文); 不做业务语义判定 (render_type/is_recalled 是上层);
//!       不做字段裁剪 (raw_payload schema 定).
//!
//! ## 红线 (decoder-解码.md §2)
//! 解码失败【单条消息】标坏不阻塞整体 — `Result<_, DecoderError>`, 错的那条上层 emit 一个 error event
//! (一条 zstd 损坏不能让整库 emit 中断).
//!
//! 本模块随 decode 各子任务增长: content → type → message → contact → anchor (本件) → chatroom → sns → image.

pub mod anchor;
pub mod appmsg;
pub mod avatar;
pub mod bizchat;
pub mod card;
pub mod chatroom;
pub mod contact;
pub mod contact_extra;
pub mod content;
pub mod dat;
pub mod emoticon;
pub mod favorite;
pub mod favorite_tag;
pub mod finder;
pub mod forward;
pub mod friend_verify;
pub mod group_pay;
pub mod hongbao_claim;
pub mod local_type;
pub mod location;
pub mod media;
pub mod memberevt;
pub mod mention;
pub mod message;
pub mod moment_feed;
pub mod packed_info;
pub mod red_envelope;
pub mod roomdata;
pub mod session;
pub mod sns;
pub mod sns_notify;
pub mod sysmsg;
pub mod transfer;
pub mod voip;

pub use anchor::{
    avatar_anchor, bizchat_anchor, chatroom_anchor, contact_anchor, cursor_anchor, emoticon_anchor, error_anchor,
    favorite_anchor, favorite_tag_anchor, finder_anchor, friend_verify_anchor, group_pay_anchor, member_anchor,
    moment_feed_anchor, msg_anchor, msg_anchor_from_talker_hex, red_envelope_anchor, session_anchor, sns_anchor,
    sns_notify_anchor, transfer_anchor,
};
pub use appmsg::{parse_appmsg, AppmsgCard};
pub use avatar::{assemble_avatar, AvatarContext, AvatarRow};
pub use bizchat::{assemble_bizchat, BizChatContext, BizChatUserRow};
pub use card::{parse_card, CardInfo};
pub use chatroom::{assemble_chatroom, ChatroomContext, ChatroomRow};
pub use contact::{assemble_contact, ContactContext, ContactRow};
pub use contact_extra::{parse_contact_extra, ContactExtra};
pub use content::{content_encoding, decode_message_content, split_chatroom_sender};
pub use dat::{
    decrypt_dat, derive_v2_xor, detect_format, detect_version, DatError, DatFormat, DatVersion, DecodedImage, ImageKey,
};
pub use emoticon::{assemble_emoticon, EmoticonContext, EmoticonRow};
pub use favorite::{assemble_favorite, parse_note_media, FavoriteContext, FavoriteRow};
pub use favorite_tag::{assemble_favorite_tag, FavoriteTagContext, FavoriteTagRow};
pub use finder::{assemble_finder, FinderContext, FinderRow};
pub use forward::{parse_forward, ForwardItem};
pub use friend_verify::{assemble_friend_verify, FMessageRow, FriendVerifyContext};
pub use group_pay::{assemble_group_pay, GroupPayContext, GroupPayRow};
pub use hongbao_claim::{parse_hongbao_claim, HongbaoClaim};
pub use local_type::{decode_local_type, LocalType};
pub use location::{parse_location, LocationCard};
pub use media::{parse_media, MediaCard, MediaKind};
pub use memberevt::{parse_member_events, MemberEvent};
pub use mention::{parse_mentions, Mention, NOTIFY_ALL};
pub use message::{assemble_message, resolve_sender_parts, MessageContext, MessageRow, SENDER_UNKNOWN};
pub use moment_feed::{assemble_moment_feed, MomentFeedContext, MomentFeedRow};
pub use packed_info::parse_image_md5;
pub use red_envelope::{assemble_red_envelope, RedEnvelopeContext, RedEnvelopeRow};
pub use roomdata::{parse_roomdata, RoomDataParse, RoomMember};
pub use session::{assemble_session, SessionContext, SessionRow};
pub use sns::{
    assemble_sns, parse_sns_create_time, parse_sns_interactions, parse_sns_media, SnsContext, SnsInteractionItem,
    SnsMediaItem, SnsRow,
};
pub use sns_notify::{assemble_sns_notify, SnsNotifyContext, SnsNotifyRow};
pub use sysmsg::classify_sysmsg;
pub use transfer::{assemble_transfer, TransferContext, TransferRow};
pub use voip::{parse_voip, VoipCard};

/// **空串归一成 `None`** —— 源库那些"可空"的文本列, 空值有时是 `NULL` 有时是 `''`, ETL 一律收成 `None`
/// 落 L1 的可空列。
///
/// **R16-1 抽出来共用**: 原先 `favorite.rs` / `chatroom.rs` 各有一份**同样的局部闭包**, 而热查
/// (`live_query.rs`) 直读源库时要的是**同一个规矩** —— 各写一份的下场是真库全量对拍逮到的那 **96 处**:
/// 源库 `realchatname` 存的是空串 `''`, ETL 用这个规矩归一成 NULL 落 L1 → 冷查出 `null`; 而热查照
/// 透传成 `Some("")` → 出 `""`。**同一行, 冷查 null 热查空串**, 消费方判 `=== null` 和 `=== ''` 行为不同。
/// 单测夹具照不出来 (我夹具里那列填的都是非空值)。
#[must_use]
pub fn non_empty(o: &Option<String>) -> Option<String> {
    o.as_ref().filter(|s| !s.is_empty()).cloned()
}

/// 解码错误 — 单条标坏不阻塞 (decoder-解码.md §3/§6).
///
/// 随 `decode_*` 子函数逐件增长 (本件 PR2-12-a 仅 content 解码用 [`DecoderError::ZstdFail`];
/// 完整契约 decoder-解码.md §3: ProtoFail / XmlFail / UnknownMsgType / Truncated 随对应 decode_* 落地).
#[derive(Debug, thiserror::Error)]
pub enum DecoderError {
    /// zstd 解压失败 (message_content 损坏 / 截断). 单条标坏 → 上层 emit error event.
    #[error("zstd decompress failed")]
    ZstdFail,
    /// 群聊既无 Name2Id 解析也无 content 前缀 sender — 无法定发送者 (罕见, 损坏行).
    ///
    /// **⚠️ historical only — 2026-07-01 起 `assemble_message` 不再构造此变体** (sender 无解改占位保留
    /// [`SENDER_UNKNOWN`](message::SENDER_UNKNOWN) 落库, 不再整条丢弃; 见 message.rs decision)。保留变体
    /// 仅为错误码枚举稳定 (`decoder_error_code` 历史 arm) + 未来严格模式可能复用。
    #[error("unresolved chatroom sender (local_id={local_id})")]
    UnresolvedSender {
        /// 源 db 行主键 (定位用, 非 PII).
        local_id: i64,
    },
    /// 解出的 sender 非法 UserName (空/超长/含空白控制符). K-R4: sender_sha8 脱敏不存裸值.
    ///
    /// **⚠️ historical only — 2026-07-01 起 `assemble_message` 不再构造此变体** (非法 sender 逐候选降级,
    /// 全失败改占位 [`SENDER_UNKNOWN`](message::SENDER_UNKNOWN) 保留)。保留同上。
    #[error("invalid sender username (sha8={sender_sha8})")]
    InvalidSender {
        /// 非法 sender 的 sha8 (脱敏锚点).
        sender_sha8: String,
    },
}
