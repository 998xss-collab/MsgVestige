//! message row 组装 — 解密明文 Msg_* 行 → [`MessageCreate`] 事件 (decoder-解码.md + ADR-412 §3.x.1).
//!
//! [`assemble_message`] 集成 3 个 decode 原语 (decode_message_content / split_chatroom_sender /
//! decode_local_type) + provenance 装配, 把一条真实 Msg_* 行转成 [`MessageCreate`].
//! event_seq 留 0 占位 — 由 [`compute_event_seq`](crate::event::assembly::compute_event_seq) 后置填 (adapter 接).
//!
//! ## 真实 schema (v4 `Msg_<md5(talker)>`, 实测 staging 9826/175197 行验证)
//! local_id / server_id / local_type (INT64: **低32=主类型, 高32=APP_XML 子类型**, 实测确认) / sort_seq /
//! real_sender_id (→Name2Id.rowid→user_name) / create_time (**秒**, ×1000 转 ms) / status (2 已发/4 已接) /
//! message_content (zstd 或明文 BLOB). **v4 无 IsSender 列** — sender 靠 real_sender_id→Name2Id (主) +
//! status 方向 (单聊兜底).

use super::content::{content_encoding, decode_message_content, split_chatroom_sender};
use super::local_type::decode_local_type;
use super::DecoderError;
use crate::event::message::MessageCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// status==2 = 已发送 (本账号发) — 单聊 sender 方向兜底。
///
/// ⚠️ **这个映射本仓自己标着"待跨版本验证", 别当已坐实** (对抗审 R16-0-P3-3 逮出原注释"实测 schema:
/// 2 已发/4 已接"与本仓基线矛盾): `baseline-message-explore-procedure.md` §K-402.2 明写"实测只看到
/// 3 和 4, **没有 2** … chatlog 文档 status=2/4 过时, 待跨版本验证"; 审真库实测 77705 行单聊 =
/// status 3 占 99.1% / 4 占 0.49% / **2 仅 0.23%**。
///
/// 目前**无害**: 真库 `real_sender_id` 经 Name2Id **100% 命中** (K-402 ✓), 候选 1 恒中 → 本方向分支
/// 一行都跑不到。但若 Name2Id 缺失 (换版本/新账号/库损坏) 而 status 语义又是错的, 会把**99% 的行**
/// (status=3) 判成对方发的 —— 用户自己发的全记到对方名下。要动 sender 逻辑前先把 K-402.2 验掉。
const STATUS_SENT: i64 = 2;

/// sender 无法解析时的**占位 UserName** — 逐候选 (Name2Id → 群 content 前缀 → 单聊 status 方向) 全部
/// 缺失或非法时的兜底.
///
/// **决策 (2026-07-01, 用户需求驱动 — 全量真跑暴露)**: 这类消息**正文有效、仅发送者未知**
/// (实测占解码错 ~100%: 13.2万 群聊无解 + 1.2万 sender 非法, 多为群系统消息如撤回/入群提示). 从旧的
/// "整条丢弃 + emit SystemError"(decoder §3 单条标坏, 原意仅针对**正文损坏** zstd/proto/xml) 改为
/// **占位保留落库** — 内容进 message 表可做分析, 靠 `WHERE sender_wxid = SENDER_UNKNOWN` 一键筛出.
/// 消息**类型**另存 msg_type_name 列, 故与真实发送者 / 真系统消息 (msg_type_name="SYSTEM") 不混。
/// **只有正文真损坏 (ZstdFail) 才仍丢弃 emit error**。
///
/// 哨兵值以 **`@` 开头**: `Wxid::try_new` 会接受 (仅挡 空/空白控制符/超长), 但真实微信 UserName 取不到
/// `@` 开头 (wxid_/gh_/自定义号/系统号皆非, `@chatroom` 是**后缀**) → **零撞车** (codex 双审 P1)。
/// 下游 sender 维度统计 (Top sender / 联系人 join) 须把本值当"未知发送者" bucket 过滤 (codex P2)。
pub const SENDER_UNKNOWN: &str = "@sender_unknown";

/// 解密明文 Msg_* 行 (调用方从 cipher 解密的 db SELECT, 已做 Name2Id JOIN 解 real_sender_id).
pub struct MessageRow {
    /// 源 db 行主键 (rowid).
    pub local_id: i64,
    /// 服务端 msg id (MsgSvrID).
    pub server_id: i64,
    /// 服务端序列号 (server_seq; 跨设备一致对齐锚点; 元数据, 进 L2 不进 digest — 批A 扫尾)。
    pub server_seq: i64,
    /// 消息来源分类 (origin_source; Msg_ 现成整数列; 元数据, 进 L2 不进 digest — L2-only)。
    pub origin_source: i64,
    /// 媒体上传状态 (upload_status; Msg_ 现成整数列; 元数据, 进 L2 不进 digest — L2-only)。
    pub upload_status: i64,
    /// 媒体下载状态 (download_status; Msg_ 现成整数列; 元数据, 进 L2 不进 digest — L2-only)。
    pub download_status: i64,
    /// localType INT64 (低32 主类型 / 高32 子类型).
    pub local_type: i64,
    /// 微信内排序键 (10位秒戳×1000 + 序号).
    pub sort_seq: i64,
    /// 源 db 消息时间 (**秒**).
    pub create_time: i64,
    /// 状态 (2 已发 / 4 已接 / 其它).
    pub status: i64,
    /// message_content BLOB raw 字节 (zstd 或明文; **按 BLOB 读** — 当 TEXT 读会让 zstd 字节碎 utf8).
    pub message_content: Vec<u8>,
    /// `source` 列 raw 字节 (msgsource XML; zstd 或明文; 群消息 @提及 atuserlist 在此; 批E).
    pub msg_source: Vec<u8>,
    /// real_sender_id 经 Name2Id JOIN 解出的发送者 UserName (群+单聊都可有; 未解析→None).
    pub sender_username: Option<String>,
}

/// 装配上下文 — 调用方 (adapter) 按 (db, 会话) 预备, 跨行复用.
pub struct MessageContext {
    /// 数据所属账号 UserName.
    pub account_id: Wxid,
    /// 会话标识 (单聊=对方 UserName / 群=`xxx@chatroom`).
    pub conv_id: String,
    /// 源 db 文件名 (e.g. `"message_0.db"`).
    pub source: String,
    /// 复合 md5 锚点 (调用方预合成, 永不含裸 wxid; → `provenance.source_native_id`).
    pub source_native_id: String,
    /// 摄取时刻 (毫秒).
    pub ingest_time: i64,
}

/// sender 逐候选解析的**纯参数版** (不吃 [`MessageRow`]/[`MessageContext`]) —— **冷热共用同一份语义**。
///
/// 按优先级 Name2Id > 群 content 前缀 > 单聊 status 方向, 每级**缺失或非法** (Wxid 校验不过) 就降到下一级;
/// 全部失败 → 占位 [`SENDER_UNKNOWN`] (codex 双审 P1: 非法主来源不压次来源)。群聊只有 [Name2Id, 前缀] 两级
/// 候选 (无 status 方向); 单聊只有 [Name2Id, status 方向] (无群前缀, `split_sender` 恒 None)。
///
/// **R16-0 抽出** (热查对等补全, 审 P2): 原逻辑锁在私有 `resolve_sender` 里且吃 ctx → **热查 (live_query)
/// 够不着**, 只能做"Name2Id or 群前缀"简版, 与冷查有真分歧 (单聊 SENT 方向解不出 / 无 SENDER_UNKNOWN 占位,
/// 见 `QueriedMsg::sender` 旧注)。抽此纯参数层后, 热查传 `self_wxid` 即可复用**同一份**逻辑 → 热=冷零漂移
/// (同 R5 派生字段复用 ingest 纯函数的路子)。纯函数, 不 log。
pub fn resolve_sender_parts(
    name2id: Option<String>,
    split_sender: Option<String>,
    is_chatroom: bool,
    status: i64,
    self_wxid: &str,
    conv_id: &str,
) -> Wxid {
    [
        name2id,      // 1. Name2Id (空/非法 → 跳下一级)
        split_sender, // 2. 群 content 前缀 (单聊恒 None)
        (!is_chatroom).then(|| {
            // 3. 单聊 status 方向: 2 已发 = 本账号 / 其它 = 对方 (conv_id)
            if status == STATUS_SENT {
                self_wxid.to_string()
            } else {
                conv_id.to_string()
            }
        }),
    ]
    .into_iter()
    .flatten()
    .find_map(|cand| Wxid::try_new(cand).ok())
    .unwrap_or_else(|| Wxid::new(SENDER_UNKNOWN)) // 4. 全失败 → 占位
}

/// 冷查 (ingest) 侧 sender 解析 —— **薄壳**, 逻辑全在 [`resolve_sender_parts`] (一份逻辑, 冷热不漂移)。
fn resolve_sender(row: &MessageRow, ctx: &MessageContext, is_chatroom: bool, split_sender: Option<String>) -> Wxid {
    resolve_sender_parts(
        row.sender_username.clone(),
        split_sender,
        is_chatroom,
        row.status,
        ctx.account_id.as_str(),
        &ctx.conv_id,
    )
}

/// 组装一条 [`MessageRow`] + [`MessageContext`] → [`MessageCreate`] (event_seq 留 0, 后置填).
///
/// 流程: decode_message_content (zstd) → 群聊拆 sender 前缀 → sender 逐候选解析 → decode_local_type → 装 provenance.
///
/// **sender 解析** (v4 无 IsSender): 逐候选 Name2Id (主, 单+群) > 群聊 content 前缀 (split) > 单聊 status
/// 方向 (2 已发=account / 其它=conv_id 收), 每级缺失/非法降下一级 > 占位 [`SENDER_UNKNOWN`] (正文有效, 仅
/// 发送者未知; 不再整条丢弃, 见 [`resolve_sender`])。
///
/// **create_time** 源是【秒】, ×1000 转 ms (MessageCreate 约定毫秒, 实测 staging 确认秒).
/// **msg_sub_type** 仅 APP_XML (base==49 && sub!=0) 时 Some(sub), 跟 msg_sub_type_name 同步.
///
/// # Errors
/// - [`DecoderError::ZstdFail`] — message_content zstd 帧损坏 (**唯一**丢弃路径: 正文真损坏才 error;
///   sender 无解 / 非法不再 error, 占位保留, 见 [`SENDER_UNKNOWN`])。
pub fn assemble_message(row: &MessageRow, ctx: &MessageContext) -> Result<MessageCreate, DecoderError> {
    // 1. message_content BLOB → 明文 (zstd 解压 / 明文回退) + decode_kind 元数据.
    let raw_text = decode_message_content(&row.message_content)?;
    let decode_kind = content_encoding(&row.message_content);

    // 1b. source 列 (msgsource XML, @提及 atuserlist) → 明文 (批E). **宽松**: source 是辅助元数据, 解码失败
    // (zstd 损坏) 不整条丢弃 (不像 message_content 是正文), 退空串 (无 @名单)。
    let msg_source = decode_message_content(&row.msg_source).unwrap_or_default();

    // 2. 群聊: 拆 content 头部 sender 前缀, 得 (前缀 sender, 净正文). 单聊无前缀.
    let is_chatroom = ctx.conv_id.ends_with("@chatroom");
    let (split_sender, text_content) = if is_chatroom {
        split_chatroom_sender(&raw_text)
    } else {
        (None, raw_text)
    };

    // 3. sender 逐候选解析 (缺失/非法降级, 全失败占位; 不整条丢弃).
    let sender_wxid = resolve_sender(row, ctx, is_chatroom, split_sender);

    // 4. localType 解 base/sub + 类型名.
    let lt = decode_local_type(row.local_type);
    // msg_sub_type 跟 sub_type_name 同步: Some(sub) 仅 base==49 && sub!=0.
    let msg_sub_type = lt.sub_type_name.map(|_| lt.sub);

    Ok(MessageCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::Message,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        server_id: row.server_id.to_string(),
        server_seq: row.server_seq,
        origin_source: row.origin_source,
        upload_status: row.upload_status,
        download_status: row.download_status,
        conv_id: ctx.conv_id.clone(),
        sender_wxid,
        create_time: row.create_time.saturating_mul(1000), // 秒 → ms
        sort_seq: row.sort_seq,
        msg_type: lt.base,
        msg_sub_type,
        msg_type_name: lt.type_name.to_string(),
        msg_sub_type_name: lt.sub_type_name.map(str::to_string),
        status: i32::try_from(row.status).unwrap_or(i32::MAX),
        local_type_raw: row.local_type,
        is_chatroom,
        raw_xml_present: text_content.trim_start().starts_with('<'),
        decode_kind: decode_kind.to_string(),
        text_content,
        msg_source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zstd_compress(bytes: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(bytes, 3).unwrap()
    }

    /// 打包 base/sub → localType INT64 (低32 base / 高32 sub).
    fn pack_local_type(base: i32, sub: i32) -> i64 {
        (i64::from(sub) << 32) | (i64::from(base) & 0xFFFF_FFFF)
    }

    fn ctx(conv: &str) -> MessageContext {
        MessageContext {
            account_id: Wxid::new("wxid_self_acct"),
            conv_id: conv.to_string(),
            source: "message_0.db".to_string(),
            source_native_id: "Msg_a1b2c3d4:1009".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    fn row(local_type: i64, status: i64, content: &[u8], sender: Option<&str>) -> MessageRow {
        MessageRow {
            local_id: 42,
            server_id: 9_876_543_210,
            server_seq: 777,
            origin_source: 3,
            upload_status: 5,
            download_status: 7,
            local_type,
            sort_seq: 1_751_612_388_000,
            create_time: 1_751_612_388, // 秒
            status,
            message_content: content.to_vec(),
            msg_source: Vec::new(),
            sender_username: sender.map(str::to_string),
        }
    }

    /// 单聊已接收 (status=4, 无 Name2Id) → sender = conv_id (对方); 文本+类型.
    #[test]
    fn single_chat_received_sender_is_conv() {
        let m = assemble_message(&row(1, 4, b"hello", None), &ctx("wxid_friend")).unwrap();
        assert_eq!(m.sender_wxid.as_str(), "wxid_friend");
        assert_eq!(m.text_content, "hello");
        assert_eq!(m.msg_type, 1);
        assert_eq!(m.msg_type_name, "TEXT");
        assert!(!m.is_chatroom);
        assert_eq!(m.create_time, 1_751_612_388_000, "秒×1000=ms");
        assert_eq!(m.provenance.event_seq, 0, "event_seq 占位");
    }

    /// 单聊已发送 (status=2, 无 Name2Id) → sender = account (本账号).
    #[test]
    fn single_chat_sent_sender_is_account() {
        let m = assemble_message(&row(1, 2, b"hi", None), &ctx("wxid_friend")).unwrap();
        assert_eq!(m.sender_wxid.as_str(), "wxid_self_acct");
    }

    /// Name2Id 解析优先于 status 方向 (单聊).
    #[test]
    fn name2id_overrides_status_direction() {
        let m = assemble_message(&row(1, 2, b"hi", Some("wxid_real_sender")), &ctx("wxid_friend")).unwrap();
        assert_eq!(m.sender_wxid.as_str(), "wxid_real_sender", "Name2Id 优先");
    }

    /// 群聊 + Name2Id → sender = Name2Id 值; is_chatroom=true.
    #[test]
    fn chatroom_name2id_sender() {
        let m = assemble_message(
            &row(1, 4, b"wxid_x:\nyo", Some("custom_member_id")),
            &ctx("abc@chatroom"),
        )
        .unwrap();
        assert_eq!(m.sender_wxid.as_str(), "custom_member_id", "自定义号成员 (Wxid 已放宽)");
        assert!(m.is_chatroom);
        assert_eq!(m.text_content, "yo", "群聊拆掉 sender 前缀");
    }

    /// 群聊无 Name2Id, 靠 content 前缀拆 sender.
    #[test]
    fn chatroom_content_prefix_sender() {
        let m = assemble_message(
            &row(1, 4, "wxid_grp_member:\n群里说话".as_bytes(), None),
            &ctx("abc@chatroom"),
        )
        .unwrap();
        assert_eq!(m.sender_wxid.as_str(), "wxid_grp_member");
        assert_eq!(m.text_content, "群里说话");
    }

    /// 群聊既无 Name2Id 也无 content 前缀 → 占位 SENDER_UNKNOWN 保留 (不再丢弃; 正文有效, 2026-07-01 改).
    #[test]
    fn chatroom_no_sender_falls_back_to_placeholder() {
        let m = assemble_message(&row(1, 4, b"no prefix here", None), &ctx("abc@chatroom")).unwrap();
        assert_eq!(m.sender_wxid.as_str(), SENDER_UNKNOWN, "无解 sender 占位保留");
        assert_eq!(m.text_content, "no prefix here", "正文完整保留");
        assert!(m.is_chatroom);
    }

    /// codex P1-3: 群聊 Name2Id 非法 + 无 content 前缀 → 逐候选全失败 → 占位 (INVALID_SENDER 落 L2).
    #[test]
    fn chatroom_invalid_name2id_no_prefix_falls_back_to_placeholder() {
        let m = assemble_message(&row(1, 4, b"no prefix", Some("bad sender")), &ctx("abc@chatroom")).unwrap();
        assert_eq!(m.sender_wxid.as_str(), SENDER_UNKNOWN, "非法 Name2Id + 无前缀 → 占位");
        assert_eq!(m.text_content, "no prefix", "正文完整保留");
    }

    /// codex P1-4: 逐候选降级 — 群聊 Name2Id 非法, 但 content 前缀合法 → 用前缀 (**不**占位, 非法主来源不压次来源).
    #[test]
    fn chatroom_invalid_name2id_falls_to_content_prefix() {
        let m = assemble_message(
            &row(1, 4, "wxid_real:\nhi".as_bytes(), Some("bad sender")),
            &ctx("abc@chatroom"),
        )
        .unwrap();
        assert_eq!(
            m.sender_wxid.as_str(),
            "wxid_real",
            "Name2Id 非法 → 降级到合法前缀, 不占位"
        );
        assert_eq!(m.text_content, "hi");
    }

    /// codex P1-4: 逐候选降级 — 单聊 Name2Id 非法 → 降级 status 方向 (对方 conv_id), 不占位.
    #[test]
    fn single_chat_invalid_name2id_falls_to_status_direction() {
        let m = assemble_message(&row(1, 4, b"hi", Some("bad sender")), &ctx("wxid_friend")).unwrap();
        assert_eq!(
            m.sender_wxid.as_str(),
            "wxid_friend",
            "Name2Id 非法 → 降级 status 方向 (对方), 不占位"
        );
    }

    /// zstd 压缩 content → 解压 + decode_kind=zstd.
    #[test]
    fn zstd_content_decompressed() {
        let blob = zstd_compress("压缩正文".as_bytes());
        let m = assemble_message(&row(1, 4, &blob, Some("wxid_a")), &ctx("wxid_a")).unwrap();
        assert_eq!(m.text_content, "压缩正文");
        assert_eq!(m.decode_kind, "zstd");
    }

    /// 明文 content → decode_kind=plain.
    #[test]
    fn plain_content_kind() {
        let m = assemble_message(&row(1, 4, b"plain", Some("wxid_a")), &ctx("wxid_a")).unwrap();
        assert_eq!(m.decode_kind, "plain");
    }

    /// APP_XML (base=49, sub=5 LINK) → msg_type/sub 全填 + raw_xml_present.
    #[test]
    fn app_xml_sub_type_and_xml_present() {
        let local_type = pack_local_type(49, 5); // base=49 APP_XML, sub=5 LINK
        let m = assemble_message(
            &row(local_type, 4, b"<appmsg>link</appmsg>", Some("wxid_a")),
            &ctx("wxid_a"),
        )
        .unwrap();
        assert_eq!(m.msg_type, 49);
        assert_eq!(m.msg_type_name, "APP_XML");
        assert_eq!(m.msg_sub_type, Some(5));
        assert_eq!(m.msg_sub_type_name.as_deref(), Some("LINK"));
        assert!(m.raw_xml_present, "<开头→xml present");
        assert_eq!(m.local_type_raw, local_type);
    }

    /// 非 APP_XML → msg_sub_type/name 均 None (跟 sub_type_name 同步).
    #[test]
    fn non_app_xml_no_sub() {
        let m = assemble_message(&row(3, 4, b"img", Some("wxid_a")), &ctx("wxid_a")).unwrap();
        assert_eq!(m.msg_type_name, "IMAGE");
        assert_eq!(m.msg_sub_type, None);
        assert_eq!(m.msg_sub_type_name, None);
        assert!(!m.raw_xml_present);
    }

    /// server_id i64 → String; status i64 → i32.
    #[test]
    fn scalar_field_conversions() {
        let m = assemble_message(&row(1, 4, b"x", Some("wxid_a")), &ctx("wxid_a")).unwrap();
        assert_eq!(m.server_id, "9876543210");
        assert_eq!(m.server_seq, 777, "server_seq 原样透传 (row helper 填 777)");
        assert_eq!(m.origin_source, 3, "origin_source 原样透传 (row helper 填 3)");
        assert_eq!(m.upload_status, 5, "upload_status 原样透传 (row helper 填 5)");
        assert_eq!(m.download_status, 7, "download_status 原样透传 (row helper 填 7)");
        assert_eq!(m.status, 4);
    }

    /// 批E: source 列 (明文 msgsource XML) → 解码进 msg_source; 空 source → 空串; source 坏 (zstd 损坏)
    /// 不丢整条 (宽松退空)。
    #[test]
    fn assemble_decodes_msg_source() {
        let mut r = row(1, 4, b"hello", Some("wxid_s"));
        r.msg_source = b"<msgsource><atuserlist><![CDATA[wxid_at]]></atuserlist></msgsource>".to_vec();
        let m = assemble_message(&r, &ctx("room@chatroom")).unwrap();
        assert!(m.msg_source.contains("wxid_at"), "source 明文解码进 msg_source");
        // 空 source → 空串。
        let m2 = assemble_message(&row(1, 4, b"hi", Some("wxid_s")), &ctx("wxid_a")).unwrap();
        assert_eq!(m2.msg_source, "", "无 source → 空串");
    }
}
