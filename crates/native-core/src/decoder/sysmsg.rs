//! decoder::sysmsg — 系统消息 (msg_type 10000) 分类 → sys_type 派生标签。
//!
//! 微信系统消息 (撤回/入群/拍一拍/红包/转账/置顶/踢人 等) 都是 msg_type 10000, 内容或是结构化
//! `<sysmsg type="X">` XML, 或是固定中文文本模板 (`"A"邀请"B"加入了群聊`)。本 mod 按**已知模式**把它们
//! 归到一个粗类 [`classify_sysmsg`] → message.sys_type 列 (ADR-458), 供"筛所有撤回/入群/红包事件"查询。
//! **纯字符串匹配, infallible** (未知 → "other")。
//!
//! ## 分类来源 (真库 type 10000 实测 + 同行 WDA `chat_helpers.py` 模式)
//! revoke(`<revokemsg>`) / pat(`拍了拍`) / hongbao(红包图标·领取) / transfer(`<paymsg>`) /
//! topmsg(`置顶`·mmchatroomtopmsg) / member_join(`加入了群聊`·sysmsgtemplate·delchatroommember) /
//! member_remove(`移出`·`移除`·`踢`) / group_dissolve(`解散该群聊`·ADR-492 §4.4.2 退群原因) /
//! other(其余 sysmsg / 未知)。
//!
//! ## K-R4
//! - sys_type 是**枚举标签**(revoke/join/… 固定串, 非用户内容) → 明文, 无需脱敏。
//! - 本 mod 只读 text_content 判类, 不抽用户名/正文 (那些在 message.text_content 已有)。

/// 系统消息粗分类 (msg_type 10000 的 text_content → sys_type 标签)。**非 10000 由调用方 guard**;
/// 本函数只按内容判类, 未知系统消息归 `"other"`。返回 `&'static str` 枚举标签。
#[must_use]
pub fn classify_sysmsg(content: &str) -> &'static str {
    // 顺序敏感: 先判专属强特征 (撤回/拍一拍/红包/转账), 再判群成员/置顶, 最后兜底。
    // codex 批F P1: revoke 收窄——只认 `<revokemsg>` 结构 或固定文本 `撤回了一条消息`, 不用裸 `撤回`
    // (防含"撤回"字样的其它系统消息如"邀请...撤回"误判)。
    if content.contains("revokemsg") || content.contains("撤回了一条消息") {
        "revoke"
    } else if content.contains("拍了拍") || content.contains("拍一拍") {
        "pat"
    } else if content.contains("HongbaoIcon") || (content.contains("红包") && content.contains("领取")) {
        "hongbao"
    } else if content.contains("type=\"paymsg\"") || content.contains("待接收") {
        "transfer"
    } else if content.contains("mmchatroomtopmsg") || content.contains("置顶了一条消息") {
        "topmsg"
    } else if content.contains("解散该群聊") {
        // ADR-492 §4.4.2: 群解散 ("群主 X 已解散该群聊" / "你已解散该群聊") — 退群原因之一。
        // 放在 member_remove 前: 解散文本不含"移出/移除/被踢", 顺序其实无碍, 但语义上先判解散更清晰。
        // 真跑 89 条全含"解散该群聊", 无其它 type=10000 携带"解散" → 0 误判 (probe 坐实)。
        "group_dissolve"
    } else if content.contains("移出了群聊") || content.contains("移除了群聊") || content.contains("被踢") {
        "member_remove"
    } else if content.contains("加入了群聊") || content.contains("加入群聊") {
        // codex 批F P1: 只认"加入群聊"文本, **不**用 `sysmsgtemplate`(通用模板容器, 非入群专属) → 未知模板归 other。
        // 真库入群模板 <template> 内含"加入了群聊" → 仍命中。
        "member_join"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke() {
        assert_eq!(
            classify_sysmsg(
                r#"<?xml version="1.0"?><sysmsg type="revokemsg"><revokemsg><content>"繁星" 撤回了一条消息</content></revokemsg></sysmsg>"#
            ),
            "revoke"
        );
        assert_eq!(classify_sysmsg("你撤回了一条消息"), "revoke", "纯文本撤回也识别");
    }

    #[test]
    fn pat() {
        assert_eq!(classify_sysmsg(r#""迷了璐" 拍了拍 "某人" [炸弹]"#), "pat");
    }

    #[test]
    fn hongbao() {
        assert_eq!(
            classify_sysmsg(r#"<img src="SystemMessages_HongbaoIcon.png"/> 有请强公子领取了你的红包"#),
            "hongbao"
        );
    }

    #[test]
    fn transfer() {
        assert_eq!(
            classify_sysmsg(r#"<sysmsg type="paymsg"><content><![CDATA[你有一笔待接收的转账]]></content></sysmsg>"#),
            "transfer"
        );
    }

    #[test]
    fn topmsg() {
        assert_eq!(
            classify_sysmsg(
                r#"<sysmsg type="mmchatroomtopmsg"><mmchatroomtopmsg><op>1</op></mmchatroomtopmsg></sysmsg>"#
            ),
            "topmsg"
        );
        assert_eq!(classify_sysmsg(r#""群主小助手"置顶了一条消息"#), "topmsg", "纯文本置顶");
    }

    #[test]
    fn member_join() {
        assert_eq!(classify_sysmsg(r#""小不点们"邀请"马樱花"加入了群聊"#), "member_join");
        assert_eq!(
            classify_sysmsg(
                r#"<sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template><template><![CDATA["$username$"邀请"$names$"加入了群聊]]></template></content_template></sysmsgtemplate></sysmsg>"#
            ),
            "member_join",
            "模板入群"
        );
    }

    #[test]
    fn member_remove() {
        assert_eq!(classify_sysmsg(r#""张三"将"李四"移出了群聊"#), "member_remove");
    }

    /// ADR-492 §4.4.2: 群解散两模板 (群主解散 / 我解散) — 真库 89 条全此二式。
    #[test]
    fn group_dissolve() {
        assert_eq!(
            classify_sysmsg(r#"群主"张三"已解散该群聊"#),
            "group_dissolve",
            "群主解散"
        );
        assert_eq!(classify_sysmsg("你已解散该群聊"), "group_dissolve", "我(群主)解散");
        // 解散不含"移出/移除/被踢" → 不落 member_remove; 顺序在其前 → 优先命中解散。
        assert_ne!(classify_sysmsg("你已解散该群聊"), "member_remove");
    }

    #[test]
    fn other_and_unknown() {
        assert_eq!(
            classify_sysmsg("<sysmsg type=\"functionmsg\"></sysmsg>"),
            "other",
            "未知 sysmsg → other"
        );
        assert_eq!(classify_sysmsg("某种没见过的系统提示"), "other");
    }

    /// codex 批F P1-1: revoke 收窄 — 含"撤回"字但非"撤回了一条消息"结构 → 不误判 revoke。
    #[test]
    fn revoke_narrowed_not_over_match() {
        // "撤回" 出现在别的语境 (非固定撤回句 + 无 revokemsg 标签) → other, 不误判 revoke。
        assert_eq!(
            classify_sysmsg("管理员开启了消息撤回限制功能"),
            "other",
            "含'撤回'字但非撤回事件 → 不误判"
        );
    }

    /// codex 批F P1-2: sysmsgtemplate 通用容器 — 无"加入群聊"文本 → other, 不误判 member_join。
    #[test]
    fn generic_sysmsgtemplate_is_other() {
        assert_eq!(
            classify_sysmsg(
                r#"<sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template><template><![CDATA[群管理提醒]]></template></content_template></sysmsgtemplate></sysmsg>"#
            ),
            "other",
            "非入群的 sysmsgtemplate → other (不再按容器名误判 member_join)"
        );
    }
}
