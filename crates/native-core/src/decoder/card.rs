//! decoder::card — 从名片消息 (msg_type=42) 的 `<msg …>` 属性抽被推荐人信息 (照 WeChatMsg parser_business)。
//!
//! 真库实测 (2026-07-06 message_0) 名片 content = `<msg bigheadimgurl=".." smallheadimgurl=".." username="v3_.."
//! nickname=".." alias=".." province=".." city=".." sex="1" sign=".." openimdesc=".." />` —— 全是 `<msg>` **属性**
//! (同位置消息)。`username` 是名片分享 token (v3_ 前缀, 被推荐人身份 wrapped)。**纯字符串抽属性, infallible**
//! (msg_type 非 42 → None)。仿 [`super::location`] (ADR-477)。
//!
//! ## K-R4 (名片是他人身份 PII)
//! nickname/alias/username/sign (被推荐人名/微信号/身份/签名) → [`CardInfo`] Debug sha8; head url → 只露长度;
//! province/city/sex 粗粒度 (非精确定位) 直露。L2 落库仍明文 (ADR-427 全程明文)。

use std::fmt;

use super::media::{attr_i64, extract_attr, open_tag_body};
use crate::key_provider::sha8;

/// 名片消息 local_type (WeChat 4.x localType 低 32 位主类型)。
const MSG_TYPE_CARD: i32 = 42;

/// 从名片 XML 抽出的被推荐人字段 (照 WeChatMsg parser_business)。
#[derive(Clone, PartialEq, Eq)]
pub struct CardInfo {
    /// 被推荐人身份 (`username`; v3_ 名片分享 token 或 wxid; id 类)。
    pub username: String,
    /// 性别 (`sex`; 0 未知 / 1 男 / 2 女)。
    pub sex: i64,
    /// 昵称 (`nickname`; 可空)。
    pub nickname: Option<String>,
    /// 微信号 (`alias`; 可空)。
    pub alias: Option<String>,
    /// 省 (`province`; 可空)。
    pub province: Option<String>,
    /// 市 (`city`; 可空)。
    pub city: Option<String>,
    /// 个性签名 (`sign`; 可空)。
    pub sign: Option<String>,
    /// 企微公司名 (`openimdesc`; 企微名片专用; 可空)。
    pub open_im_desc: Option<String>,
    /// 头像原图 URL (`bigheadimgurl`; 可空)。
    pub big_head_url: Option<String>,
    /// 小头像 URL (`smallheadimgurl`; 可空)。
    pub small_head_url: Option<String>,
}

/// 从消息 content (名片 XML) 抽被推荐人字段。非名片 msg_type (42) → None; 无 `<msg>` 根 → None。**infallible**。
#[must_use]
pub fn parse_card(msg_type: i32, content: &str) -> Option<CardInfo> {
    if msg_type != MSG_TYPE_CARD {
        return None;
    }
    // 名片属性在 <msg> 根标签上。无 <msg> = 损坏 (名片 content 恒有)。
    let attrs = open_tag_body(content, "msg")?;
    // username 是名片核心 (被推荐人身份) — 缺即损坏/占位, 不落。
    let username = extract_attr(attrs, "username")?;
    Some(CardInfo {
        username,
        sex: attr_i64(attrs, "sex"),
        nickname: extract_attr(attrs, "nickname"),
        alias: extract_attr(attrs, "alias"),
        province: extract_attr(attrs, "province"),
        city: extract_attr(attrs, "city"),
        sign: extract_attr(attrs, "sign"),
        open_im_desc: extract_attr(attrs, "openimdesc"),
        big_head_url: extract_attr(attrs, "bigheadimgurl"),
        small_head_url: extract_attr(attrs, "smallheadimgurl"),
    })
}

/// K-R4: 名片是他人身份 → Debug 脱敏 (nickname/alias/username/sign → sha8; head url 只露长度; province/city/sex 直露)。
impl fmt::Debug for CardInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        let l = |v: &Option<String>| v.as_deref().map(|s| s.chars().count());
        f.debug_struct("CardInfo")
            .field("username_sha8", &sha8(self.username.as_bytes()))
            .field("sex", &self.sex)
            .field("nickname_sha8", &o(&self.nickname))
            .field("alias_sha8", &o(&self.alias))
            .field("province", &self.province)
            .field("city", &self.city)
            .field("sign_sha8", &o(&self.sign))
            .field("open_im_desc_sha8", &o(&self.open_im_desc))
            .field("big_head_url_len", &l(&self.big_head_url))
            .field("small_head_url_len", &l(&self.small_head_url))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 真库结构 (2026-07-06 message_0): username 是 v3_ 名片 token。
    const CARD: &str = r#"<?xml version="1.0"?><msg bigheadimgurl="http://wx.qlogo.cn/x/0" smallheadimgurl="http://wx.qlogo.cn/x/132" username="v3_020b3826fd" nickname="小王" alias="wangxiao88" province="Zhejiang" city="Taizhou" sex="1" sign="努力生活" />"#;

    #[test]
    fn parse_full_card() {
        let c = parse_card(42, CARD).unwrap();
        assert_eq!(c.username, "v3_020b3826fd");
        assert_eq!(c.nickname.as_deref(), Some("小王"));
        assert_eq!(c.alias.as_deref(), Some("wangxiao88"));
        assert_eq!(c.province.as_deref(), Some("Zhejiang"));
        assert_eq!(c.city.as_deref(), Some("Taizhou"));
        assert_eq!(c.sex, 1);
        assert_eq!(c.sign.as_deref(), Some("努力生活"));
        assert!(c.big_head_url.is_some() && c.small_head_url.is_some());
        assert!(c.open_im_desc.is_none(), "非企微名片无 openimdesc");
    }

    #[test]
    fn non_card_type_none() {
        assert!(parse_card(1, CARD).is_none(), "文本 type1 → None");
        assert!(
            parse_card(42, "<msg></msg>").is_none(),
            "type42 但无 username 属性 → None"
        );
    }

    #[test]
    fn openim_card() {
        let c = parse_card(
            42,
            r#"<msg username="v3_x" nickname="张经理" openimdesc="某某科技有限公司" sex="1" />"#,
        )
        .unwrap();
        assert_eq!(c.open_im_desc.as_deref(), Some("某某科技有限公司"), "企微名片公司名");
    }

    #[test]
    fn k_r4_debug_redacts() {
        let dbg = format!("{:?}", parse_card(42, CARD).unwrap());
        for raw in ["小王", "wangxiao88", "v3_020b3826fd", "努力生活"] {
            assert!(!dbg.contains(raw), "K-R4: CardInfo Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("nickname_sha8") && dbg.contains("big_head_url_len"));
    }
}
