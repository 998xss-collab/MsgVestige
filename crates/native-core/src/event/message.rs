//! event::message — (message, create) 事件字段集 (ADR-412 §3.x.1).
//!
//! 本 mod = PR2-3-d: [`MessageCreate`] struct — 第一个完整事件字段集, **后续 per-event struct 的模板**
//! (PR2-3-e+ contact_update / chatroom_update / system_event 照此 pattern: 嵌 [`Provenance`] +
//! 业务字段 + `to_payload_json` 调 [`privacy::render_field`] 脱敏 + 手写 K-R4 Debug + 不 derive Serialize).
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 conv_id / sender_wxid / text_content 裸值被 `to_json` 误序列化.
//!   唯一出 payload 路径 = [`MessageCreate::to_payload_json`] (经脱敏关口).
//! - **手写 `Debug`** — conv_id / text_content 经 [`sha8`] 脱敏; sender_wxid ([`Wxid`]) + provenance
//!   ([`Provenance`] 内 account_id) 各自 Debug 自遮. 不准 derive Debug (会泄裸值).
//!
//! ## §7.2 红线 — message 事件【无 display_name 类字段】
//! message 源 db 表本就无昵称字段 (只有 talker_id/wxid), raw_payload 不做 L2 JOIN 出 display_name.
//! 故本 struct 无 display_name 类字段, 任何隐私开关下 payload 都不含昵称明文 (ADR-412 §3.y.2).

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::{sha8, Wxid};

/// (message, create) 事件字段集 (ADR-412 §3.x.1) — 一条聊天消息.
///
/// 字段归桶 (§3.y.1): conv_id / sender_wxid = **id 类** (默认 _sha); text_content = **text_content 类**
/// (默认 _sha + _len); 其余 = **元数据类** (永远明文); provenance 见 [`Provenance`].
pub struct MessageCreate {
    /// 共享溯源头 7 字段 (account_id / source / source_native_id / event_type / event_action / event_seq / ingest_time).
    pub provenance: Provenance,

    // ── 业务字段 (§3.x.1) ──
    /// 服务端消息 id (元数据 — 微信内部 id, 不含隐私, 永远明文; §3.y.5 server_id 不属 id 类).
    pub server_id: String,
    /// 服务端序列号 (元数据; 跨设备一致对齐锚点; 进 L2 不进 content_digest — 批A 扫尾)。
    pub server_seq: i64,
    /// 消息来源分类 (元数据; Msg_ origin_source 现成列; 进 L2 不进 content_digest/payload — L2-only)。
    pub origin_source: i64,
    /// 媒体上传状态 (元数据; Msg_ upload_status 现成列; 进 L2 不进 content_digest/payload — L2-only)。
    pub upload_status: i64,
    /// 媒体下载状态 (元数据; Msg_ download_status 现成列; 进 L2 不进 content_digest/payload — L2-only)。
    pub download_status: i64,
    /// chat 标识 raw (id 类: 单聊=对方 wxid, 群=chatroom id; 默认 conv_id_sha).
    pub conv_id: String,
    /// 发送者 wxid (id 类: 默认 sender_wxid_sha).
    pub sender_wxid: Wxid,
    /// 源 db 消息时间毫秒 (元数据; 进 fingerprint 的 src_create_time_ms).
    pub create_time: i64,
    /// 微信内排序键 (元数据, 临时).
    pub sort_seq: i64,
    /// 消息主类型枚举 (元数据).
    pub msg_type: i32,
    /// 消息子类型 (元数据, nullable).
    pub msg_sub_type: Option<i32>,
    /// 主类型派生名 "TEXT"/"IMAGE"/... (元数据).
    pub msg_type_name: String,
    /// 子类型派生名 (元数据, nullable).
    pub msg_sub_type_name: Option<String>,
    /// 消息状态枚举 (元数据, 临时).
    pub status: i32,
    /// 微信源 db localType 原值 (元数据).
    pub local_type_raw: i64,
    /// 单聊 / 群聊 (元数据).
    pub is_chatroom: bool,
    /// 是否有 XML payload (元数据).
    pub raw_xml_present: bool,
    /// 解码方式 "plain"/"zstd"/"proto"/"xml"/... (元数据, 临时).
    pub decode_kind: String,
    /// 消息正文 raw (text_content 类: 默认 text_content_sha + text_content_len; plaintext/--enable-text-content 明文).
    pub text_content: String,
    /// `source` 列解码后的 msgsource XML (群消息 @提及 atuserlist 在此; 批E)。**L2-only 派生源** — 不进
    /// content_digest (非 message 身份字段) 也不进 payload (含被 @ 的 wxid, 走 message_mention 表落库);
    /// project_message_mention 从此抽 @名单。Debug sha8 脱敏。
    pub msg_source: String,
}

impl MessageCreate {
    /// 渲染整条 message.create 的 payload_json (ADR-412 §3.x.1 字段集 + §3.y 隐私过滤, 唯一出口).
    ///
    /// 顺序: 先 provenance 7 字段, 再业务字段. 字符串字段经 [`render_field`] (类别驱动脱敏);
    /// 数字 / bool / nullable 直塞自然 JSON 类型.
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // 字符串字段 — 经脱敏关口 (类别驱动: Metadata 原名 / Id _sha / TextContent _sha+_len).
        render_field(&mut out, "server_id", &self.server_id, FieldCategory::Metadata, mode);
        render_field(&mut out, "conv_id", &self.conv_id, FieldCategory::Id, mode);
        render_field(
            &mut out,
            "sender_wxid",
            self.sender_wxid.as_str(),
            FieldCategory::Id,
            mode,
        );
        render_field(
            &mut out,
            "msg_type_name",
            &self.msg_type_name,
            FieldCategory::Metadata,
            mode,
        );
        match &self.msg_sub_type_name {
            Some(name) => render_field(&mut out, "msg_sub_type_name", name, FieldCategory::Metadata, mode),
            None => {
                out.insert("msg_sub_type_name".to_string(), Value::Null);
            }
        }
        render_field(
            &mut out,
            "decode_kind",
            &self.decode_kind,
            FieldCategory::Metadata,
            mode,
        );
        render_field(
            &mut out,
            "text_content",
            &self.text_content,
            FieldCategory::TextContent,
            mode,
        );

        // 数字 / bool 元数据 — 直塞 (天然非敏感).
        out.insert("create_time".to_string(), Value::from(self.create_time));
        out.insert("sort_seq".to_string(), Value::from(self.sort_seq));
        // 批A: server_seq **不进 payload** — 真库实测同一消息未同步→同步会 0→N 后变 (server_id 恒定,
        // server_seq 是 Msg_ 表唯一会后变的列)。增量水位 (local_id>cursor) 下旧行不重读 → L2 存的是
        // **首次 ingest 时的值** (未同步则恒 0, 不自动刷新), 仅 full rebuild/cursor reset 重读才取到新 N。
        // 若进 payload: rebuild 重读时 L2 UPSERT 刷 N, 而 archive 按 digest(不含 server_seq)去重冻 payload=0
        // → 重演批4 陈旧陷阱。故 L2-only: 只落 V3Message + 不进 content_digest (server_id 已唯一, 零去重价值)。
        // 同理 origin_source / upload_status / download_status (Msg_ 现成整数列) 亦 **不进 payload** — L2-only
        // 元数据 (媒体上传/下载状态会随传输进度后变), 只落 V3Message, 不进 content_digest。
        out.insert("msg_type".to_string(), Value::from(self.msg_type));
        out.insert(
            "msg_sub_type".to_string(),
            self.msg_sub_type.map_or(Value::Null, Value::from),
        );
        out.insert("status".to_string(), Value::from(self.status));
        out.insert("local_type_raw".to_string(), Value::from(self.local_type_raw));
        out.insert("is_chatroom".to_string(), Value::from(self.is_chatroom));
        out.insert("raw_xml_present".to_string(), Value::from(self.raw_xml_present));

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): conv_id / text_content 经 sha8 脱敏; sender_wxid + provenance 各自 Debug 自遮.
/// **不准 derive Debug** — 会泄 conv_id / text_content 裸值.
impl fmt::Debug for MessageCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageCreate")
            .field("provenance", &self.provenance)
            .field("server_id", &self.server_id)
            .field("server_seq", &self.server_seq)
            .field("origin_source", &self.origin_source)
            .field("upload_status", &self.upload_status)
            .field("download_status", &self.download_status)
            .field("conv_id_sha8", &sha8(self.conv_id.as_bytes()))
            .field("sender_wxid", &self.sender_wxid)
            .field("create_time", &self.create_time)
            .field("sort_seq", &self.sort_seq)
            .field("msg_type", &self.msg_type)
            .field("msg_sub_type", &self.msg_sub_type)
            .field("msg_type_name", &self.msg_type_name)
            .field("msg_sub_type_name", &self.msg_sub_type_name)
            .field("status", &self.status)
            .field("local_type_raw", &self.local_type_raw)
            .field("is_chatroom", &self.is_chatroom)
            .field("raw_xml_present", &self.raw_xml_present)
            .field("decode_kind", &self.decode_kind)
            .field("text_content_sha8", &sha8(self.text_content.as_bytes()))
            .field("text_content_len", &self.text_content.chars().count())
            .field("msg_source_sha8", &sha8(self.msg_source.as_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;

    fn sample() -> MessageCreate {
        MessageCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "message_5.db".to_string(),
                source_native_id: "Msg_a1b2c3d4:1009".to_string(),
                event_type: EventType::Message,
                event_action: EventAction::Create,
                event_seq: 42,
                ingest_time: 1_700_000_000_000,
            },
            server_id: "9876543210".to_string(),
            server_seq: 100,
            origin_source: 2,
            upload_status: 0,
            download_status: 0,
            conv_id: "wxid_friend_002".to_string(),
            sender_wxid: Wxid::try_new("wxid_friend_002").unwrap(),
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
            msg_source: String::new(),
        }
    }

    /// 默认模式: id 类 (conv_id/sender_wxid/account_id) 全 _sha; text_content _sha+_len; 元数据照原.
    #[test]
    fn payload_default_redacts_id_and_text() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        // id 类全脱敏
        assert_eq!(o["conv_id_sha"], Value::from(sha256_hex("wxid_friend_002")));
        assert_eq!(o["sender_wxid_sha"], Value::from(sha256_hex("wxid_friend_002")));
        assert!(o.contains_key("account_id_sha"));
        assert!(!o.contains_key("conv_id"), "K-R4: 默认不准出裸 conv_id");
        assert!(!o.contains_key("sender_wxid"), "K-R4: 默认不准出裸 sender_wxid");
        // text_content 脱敏 + len
        assert_eq!(o["text_content_sha"], Value::from(sha256_hex("晚上吃啥")));
        assert_eq!(o["text_content_len"], Value::from(4_i64));
        assert!(!o.contains_key("text_content"), "K-R4: 默认不准出裸正文");
        // 元数据照原
        assert_eq!(o["server_id"], Value::from("9876543210"));
        assert!(
            !o.contains_key("server_seq"),
            "批A: server_seq 是 L2-only, 不进 payload (0→N 后变会致归档陈旧)"
        );
        assert!(!o.contains_key("origin_source"), "origin_source L2-only, 不进 payload");
        assert!(!o.contains_key("upload_status"), "upload_status L2-only, 不进 payload");
        assert!(
            !o.contains_key("download_status"),
            "download_status L2-only, 不进 payload"
        );
        assert_eq!(o["msg_type"], Value::from(1));
        assert_eq!(o["is_chatroom"], Value::from(false));
    }

    /// plaintext 总开关: id 类 + text 全明文 (无后缀); source_native_id 例外仍 md5 锚点.
    #[test]
    fn payload_plaintext_exposes_all_sensitive() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["conv_id"], Value::from("wxid_friend_002"));
        assert_eq!(o["sender_wxid"], Value::from("wxid_friend_002"));
        assert_eq!(o["account_id"], Value::from("wxid_acct_001"));
        assert_eq!(o["text_content"], Value::from("晚上吃啥"));
        assert!(!o.contains_key("text_content_sha"));
        // 例外不变
        assert_eq!(o["source_native_id"], Value::from("Msg_a1b2c3d4:1009"));
    }

    /// --enable-text-content 只开 text 类, id 类 (conv_id/sender_wxid) 仍 sha (§3.y.5 id 只受总开关).
    #[test]
    fn text_switch_opens_text_but_not_id() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_text_content: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["text_content"], Value::from("晚上吃啥"), "text 开关后正文明文");
        assert!(o.contains_key("conv_id_sha"), "id 类不受 text 开关影响");
        assert!(o.contains_key("sender_wxid_sha"));
        assert!(!o.contains_key("conv_id"), "K-R4: text 开关不准泄 conv_id");
    }

    /// nullable 字段: None → JSON null.
    #[test]
    fn nullable_fields_render_null() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["msg_sub_type"], Value::from(0)); // Some(0)
        assert_eq!(o["msg_sub_type_name"], Value::Null); // None
                                                         // Some 分支
        let mut m = sample();
        m.msg_sub_type = None;
        m.msg_sub_type_name = Some("REVOKE".to_string());
        let p2 = m.to_payload_json(PrivacyMode::default_sha());
        let o2 = p2.as_object().unwrap();
        assert_eq!(o2["msg_sub_type"], Value::Null);
        assert_eq!(o2["msg_sub_type_name"], Value::from("REVOKE"));
    }

    /// §7.2 红线: message payload 任何模式都不含 display_name 类字段 (无昵称明文).
    #[test]
    fn message_has_no_display_name_fields() {
        for mode in [
            PrivacyMode::default_sha(),
            PrivacyMode {
                enable_display_name: true,
                ..Default::default()
            },
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        ] {
            let p = sample().to_payload_json(mode);
            let o = p.as_object().unwrap();
            for k in [
                "nick_name",
                "nick_name_sha",
                "remark",
                "remark_sha",
                "display_name",
                "display_name_sha",
            ] {
                assert!(!o.contains_key(k), "§7.2 红线: message 不准含 display_name 类字段 {k}");
            }
        }
    }

    /// K-R4: 默认模式 payload 序列化后不含任何裸敏感值.
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["wxid_friend_002", "wxid_acct_001", "晚上吃啥"] {
            assert!(!dumped.contains(raw), "K-R4: 默认模式 payload 泄漏裸值 {raw}");
        }
    }

    /// K-R4: 手写 Debug 不泄 conv_id / sender_wxid / text_content / account_id 裸值.
    #[test]
    fn debug_redacts_all_sensitive() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("wxid_friend_002"), "Debug 泄 conv_id/sender_wxid!");
        assert!(!dbg.contains("wxid_acct_001"), "Debug 泄 account_id!");
        assert!(!dbg.contains("晚上吃啥"), "Debug 泄 text_content!");
        // 脱敏字段在 (sha8 / len)
        assert!(dbg.contains("conv_id_sha8"));
        assert!(dbg.contains("text_content_sha8"));
        assert!(dbg.contains("text_content_len"));
    }

    /// 批E: msg_source (含被@wxid) **不进 payload** (任何模式) + Debug sha8 脱敏 (走 message_mention L2 表)。
    #[test]
    fn msg_source_not_in_payload_and_debug_redacted() {
        let mut m = sample();
        m.msg_source = "<atuserlist><![CDATA[wxid_at_secret]]></atuserlist>".to_string();
        for mode in [
            PrivacyMode::default_sha(),
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        ] {
            let dumped = serde_json::to_string(&m.to_payload_json(mode)).unwrap();
            assert!(
                !dumped.contains("msg_source"),
                "msg_source 不进 payload (L2-only, 走 message_mention)"
            );
            assert!(!dumped.contains("wxid_at_secret"), "K-R4: 被@wxid 不进 payload");
        }
        let dbg = format!("{m:?}");
        assert!(!dbg.contains("wxid_at_secret"), "K-R4: Debug 泄裸被@wxid");
        assert!(dbg.contains("msg_source_sha8"));
    }
}
