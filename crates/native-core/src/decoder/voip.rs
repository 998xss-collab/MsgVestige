//! decoder::voip — 从通话消息 (msg_type=50) 的 `<voipmsg>` XML 抽通话记录 (照 WeChatMsg parser_voip)。
//!
//! 真库实测 (2026-07-06 message_0) 本账号 type50 **全是气泡摘要形式** `<voipmsg type="VoIPBubbleMsg">`:
//! `<VoIPBubbleMsg><msg><![CDATA[通话时长 00:25]]></msg><room_type>1</room_type><msg_type>100</msg_type>
//! <duration>0</duration>...` —— `<msg>` = 通话结果文本 (通话时长/对方已取消/已在其它设备接听) 是关键字段。
//! 另一种邀请形式 (`voipinvitemsg`/`voiplocalinfo`, WeChatMsg 也处理) 本账号无, 但兼容: invite_type + diaplay_content。
//! **纯字符串抽标签, infallible** (返 Option: 非通话消息 / 损坏 → None)。仿 [`super::location`] (ADR-475)。

use std::fmt;

use super::appmsg::extract_tag;
use super::media::{extract_attr, open_tag_body};

/// 通话消息 local_type (WeChat 4.x localType 低 32 位主类型)。
const MSG_TYPE_VOIP: i32 = 50;

/// 从通话 XML 抽出的字段 (照 WeChatMsg link_parser.py parser_voip 语义)。
#[derive(Clone, PartialEq)]
pub struct VoipCard {
    /// 邀请类型: -1 气泡摘要 (VoIPBubbleMsg) / 0 视频 / 1 语音 (WeChatMsg invite_type 语义)。
    pub invite_type: i64,
    /// 通话房间类型 (`<room_type>`; 气泡形式常 1)。
    pub room_type: i64,
    /// 通话状态码 (voip `<msg_type>`: 100 正常摘要 / 101 已在其它设备接听)。
    pub call_state: i64,
    /// 时长秒 (`<duration>`; 气泡形式为 0, 实际时长在 display_content 文本 "通话时长 00:25" 里)。
    pub duration: i64,
    /// 通话结果显示文本 (气泡 `<msg>` / 邀请形式 `<diaplay_content>` 微信自身 typo; 如 "通话时长 00:25" / "对方已取消")。
    pub display_content: String,
}

/// 从消息 content (通话 XML) 抽通话字段。非通话 msg_type (50) → None; 无 `<voipmsg>` → None。**infallible**。
#[must_use]
pub fn parse_voip(msg_type: i32, content: &str) -> Option<VoipCard> {
    if msg_type != MSG_TYPE_VOIP {
        return None;
    }
    // voipmsg@type 决定形式 (VoIPBubbleMsg 气泡 vs 邀请)。无 <voipmsg> → 非通话/损坏。
    let attrs = open_tag_body(content, "voipmsg")?;
    let vtype = extract_attr(attrs, "type").unwrap_or_default();
    let is_bubble = vtype == "VoIPBubbleMsg";
    // 显示文本: 气泡 <msg> 优先, 邀请形式退 <diaplay_content> (微信 typo, 非笔误)。
    let display_content = extract_tag(content, "msg")
        .or_else(|| extract_tag(content, "diaplay_content"))
        .unwrap_or_default();
    // 全空 (无 type 无显示文本) → 损坏, 不落。
    if vtype.is_empty() && display_content.is_empty() {
        return None;
    }
    let invite_type = if is_bubble {
        -1
    } else {
        extract_tag(content, "invite_type")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    Some(VoipCard {
        invite_type,
        room_type: extract_tag(content, "room_type")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        call_state: extract_tag(content, "msg_type")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        duration: extract_tag(content, "duration")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        display_content,
    })
}

/// Debug: 通话字段全是系统生成的状态数字/文本 (非 PII), display_content 是 "通话时长 00:25" 类系统串直接露。
impl fmt::Debug for VoipCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoipCard")
            .field("invite_type", &self.invite_type)
            .field("room_type", &self.room_type)
            .field("call_state", &self.call_state)
            .field("duration", &self.duration)
            .field("display_content", &self.display_content)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 真库样本 (2026-07-06 message_0)。
    const BUBBLE: &str = r#"<voipmsg type="VoIPBubbleMsg"><VoIPBubbleMsg><msg><![CDATA[通话时长 00:25]]></msg><room_type>1</room_type><red_dot>false</red_dot><roomid>563918622145418552</roomid><msg_type>100</msg_type><duration>0</duration></VoIPBubbleMsg></voipmsg>"#;

    #[test]
    fn parse_bubble_call() {
        let v = parse_voip(50, BUBBLE).unwrap();
        assert_eq!(v.invite_type, -1, "气泡摘要 invite_type=-1");
        assert_eq!(v.room_type, 1);
        assert_eq!(v.call_state, 100, "voip msg_type 非气泡外层 msg_type");
        assert_eq!(v.duration, 0);
        assert_eq!(v.display_content, "通话时长 00:25", "<msg> 结果文本, 不误配 <msg_type>");
    }

    #[test]
    fn parse_cancelled_call() {
        let v = parse_voip(50, r#"<voipmsg type="VoIPBubbleMsg"><VoIPBubbleMsg><msg><![CDATA[对方已取消]]></msg><room_type>1</room_type><msg_type>100</msg_type></VoIPBubbleMsg></voipmsg>"#).unwrap();
        assert_eq!(v.display_content, "对方已取消");
    }

    #[test]
    fn parse_invite_form() {
        // 邀请形式 (兼容路, 本账号无但 WeChatMsg 有): invite_type 0=视频 + voiplocalinfo duration + diaplay_content。
        let x = r#"<voipmsg type="VoIPInviteMsg"><voipinvitemsg><invite_type>0</invite_type></voipinvitemsg><voiplocalinfo><duration>323</duration><diaplay_content><![CDATA[通话时长 05:23]]></diaplay_content></voiplocalinfo></voipmsg>"#;
        let v = parse_voip(50, x).unwrap();
        assert_eq!(v.invite_type, 0, "0=视频");
        assert_eq!(v.duration, 323);
        assert_eq!(v.display_content, "通话时长 05:23", "邀请形式退 diaplay_content");
    }

    #[test]
    fn non_voip_type_none() {
        assert!(parse_voip(1, BUBBLE).is_none(), "文本 type1 → None");
        assert!(parse_voip(49, BUBBLE).is_none(), "appmsg type49 → None");
        assert!(parse_voip(50, "<msg>x</msg>").is_none(), "type50 但无 <voipmsg> → None");
    }
}
