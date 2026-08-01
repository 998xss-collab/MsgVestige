//! `localType` 解码 — 微信 message localType (源 db INT64) → base/sub + chatlog 风格类型名.
//!
//! 微信把【主类型】(低 32 位) 和【appmsg 子类型】(高 32 位) 打包进一个 i64 `localType`. 子类型仅当
//! 主类型为 49 (APP_XML) 时有意义. 产出喂 [`MessageCreate`](crate::event::message::MessageCreate) 的
//! `msg_type` / `msg_sub_type` / `msg_type_name` / `msg_sub_type_name` 字段集 (ADR-412, 字段集单一真相).
//!
//! 注: decoder-解码.md §2 prose "type=1 是文本还是图片不在 decoder" 措辞不精确 — §4 已把字段集让位
//! ADR-412, 而 MessageCreate 明确含 `msg_type_name` 元数据字段, 故类型名派生属 decode 产出 (PoC 同款).

/// 微信 message `localType` (源 db INT64) 解码结果.
///
/// 纯元数据值类型 (无 PII): derive 标准 trait 便于下件组装/断言.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalType {
    /// 主类型 (低 32 位): 1=TEXT 3=IMAGE 34=VOICE … 10000=SYSTEM. → `MessageCreate::msg_type`.
    pub base: i32,
    /// 子类型 (高 32 位): 仅 `base==49` (APP_XML) 有意义. → `MessageCreate::msg_sub_type` 的 raw 值.
    pub sub: i32,
    /// 主类型派生名 (chatlog 风格): "TEXT"/"IMAGE"/…/"UNKNOWN". → `MessageCreate::msg_type_name`.
    pub type_name: &'static str,
    /// 子类型派生名: `Some` 仅当 `base==49 && sub!=0`; 否则 `None`. → `MessageCreate::msg_sub_type_name`.
    pub sub_type_name: Option<&'static str>,
}

/// 解码 message `localType` (INT64) → [`LocalType`].
///
/// `base` = 低 32 位, `sub` = 高 32 位 (PoC `local_type & 0xFFFFFFFF` / `>> 32`). 纯函数, 不 log.
/// 未知 base → `type_name="UNKNOWN"` (不报错, decoder-解码.md §6: UnknownMsgType 单条 emit system_event,
/// 那是上层组装的事; 本原语只给名).
#[must_use]
pub fn decode_local_type(local_type: i64) -> LocalType {
    let base = (local_type & 0xFFFF_FFFF) as i32;
    let sub = (local_type >> 32) as i32;
    LocalType {
        base,
        sub,
        type_name: base_type_name(base),
        sub_type_name: if base == 49 && sub != 0 {
            Some(appmsg_sub_type_name(sub))
        } else {
            None
        },
    }
}

/// 主类型码 → chatlog 风格名 (PoC `local_type_name` 同款).
fn base_type_name(base: i32) -> &'static str {
    match base {
        1 => "TEXT",
        3 => "IMAGE",
        34 => "VOICE",
        42 => "CARD",
        43 => "VIDEO",
        47 => "EMOJI",
        48 => "LOCATION",
        49 => "APP_XML",
        50 => "VOIP",
        62 => "VIDEO_ALT",
        10000 => "SYSTEM",
        _ => "UNKNOWN",
    }
}

/// APP_XML (base==49) 子类型码 → 名 (PoC `appmsg_sub_type_name` 同款).
fn appmsg_sub_type_name(sub: i32) -> &'static str {
    match sub {
        5 => "LINK",
        6 => "FILE",
        8 => "EMOJI_GIF",
        19 => "FORWARD",
        33 | 36 => "MINIAPP",
        51 => "VIDEO_CHANNEL",
        57 => "QUOTE",
        62 => "PAT",
        63 => "VIDEO_CHANNEL_ALT",
        87 => "GROUP_NOTICE",
        2000 => "TRANSFER",
        2001 => "RED_PACKET",
        2003 => "RED_PACKET_COVER",
        _ => "APP_SUB_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 把 base/sub 打包成 localType INT64 (decode 的逆).
    fn pack(base: i32, sub: i32) -> i64 {
        (i64::from(sub) << 32) | (i64::from(base) & 0xFFFF_FFFF)
    }

    #[test]
    fn text_type_no_sub() {
        let t = decode_local_type(1);
        assert_eq!(t.base, 1);
        assert_eq!(t.sub, 0);
        assert_eq!(t.type_name, "TEXT");
        assert_eq!(t.sub_type_name, None);
    }

    #[test]
    fn image_voice_system_names() {
        assert_eq!(decode_local_type(3).type_name, "IMAGE");
        assert_eq!(decode_local_type(34).type_name, "VOICE");
        assert_eq!(decode_local_type(10000).type_name, "SYSTEM");
    }

    #[test]
    fn unknown_base_falls_through() {
        let t = decode_local_type(999);
        assert_eq!(t.base, 999);
        assert_eq!(t.type_name, "UNKNOWN");
        assert_eq!(t.sub_type_name, None);
    }

    #[test]
    fn app_xml_with_link_sub() {
        let t = decode_local_type(pack(49, 5));
        assert_eq!(t.base, 49);
        assert_eq!(t.sub, 5);
        assert_eq!(t.type_name, "APP_XML");
        assert_eq!(t.sub_type_name, Some("LINK"));
    }

    #[test]
    fn app_xml_sub_zero_is_none() {
        // base==49 但 sub==0 → 无子类型名
        let t = decode_local_type(49);
        assert_eq!(t.base, 49);
        assert_eq!(t.sub, 0);
        assert_eq!(t.type_name, "APP_XML");
        assert_eq!(t.sub_type_name, None);
    }

    #[test]
    fn app_xml_unknown_sub() {
        let t = decode_local_type(pack(49, 9999));
        assert_eq!(t.sub_type_name, Some("APP_SUB_UNKNOWN"));
    }

    #[test]
    fn miniapp_dual_codes() {
        assert_eq!(decode_local_type(pack(49, 33)).sub_type_name, Some("MINIAPP"));
        assert_eq!(decode_local_type(pack(49, 36)).sub_type_name, Some("MINIAPP"));
    }

    #[test]
    fn transfer_redpacket_subs() {
        assert_eq!(decode_local_type(pack(49, 2000)).sub_type_name, Some("TRANSFER"));
        assert_eq!(decode_local_type(pack(49, 2001)).sub_type_name, Some("RED_PACKET"));
    }

    #[test]
    fn non_app_base_ignores_sub_bits() {
        // base!=49 时即便高 32 位有值, sub_type_name 也 None (子类型仅 APP_XML 有意义)
        let t = decode_local_type(pack(1, 5));
        assert_eq!(t.base, 1);
        assert_eq!(t.sub, 5);
        assert_eq!(t.type_name, "TEXT");
        assert_eq!(t.sub_type_name, None, "base!=49 不认子类型");
    }
}
