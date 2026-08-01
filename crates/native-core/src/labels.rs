//! labels — 静态码→中文映射 (导出/查询层显示用, **不落库**; ADR-505)。
//!
//! 微信这些"码→文字"是**编译进客户端**的 (Weixin.dll PE 分析确认无数据表: 0 指针引用 → 是代码 switch,
//! 挖不出成品表)。竞品 (WeChatDataAnalysis `_SOURCE_SCENE_LABELS`) 同样硬编码。我们**照抄已确认的码表**
//! (文字用微信 dll 里的原文串), 导出时把原始码渲染成中文; **不存冗余列** —— 原始码是事实源, 中文纯查表可算
//! (同 nick_name/message_dates 的"查询能算不单存"原则)。未知码返 None → 调用方显示"其他 (码 N)"。

/// `friend_source` (加好友来源码, contact.extra_buffer f8) → 中文。
///
/// 已确认码 (竞品 WCDA/WeChatFerry + 用户真人核对 + 微信 dll 原文串); 未知边缘码 (9/15/87/1000000…) 返 None。
/// 文字用微信客户端原文 ("通过扫一扫添加" 等, 从 Weixin.dll 4.1.11.24 字符串池取)。
#[must_use]
pub fn friend_source_label(code: i64) -> Option<&'static str> {
    Some(match code {
        0 => "未记录",             // 无来源码 (系统/默认)
        1 => "通过搜索QQ号添加",   // WCDA 1=QQ
        3 => "通过搜索微信号添加", // WCDA + 用户 3=微信号
        6 => "通过手机通讯录添加", // WCDA 6=手机通讯录
        14 => "通过群聊添加",      // WCDA + 其自测 14=群聊
        17 => "通过名片分享添加",  // WeChatFerry + 用户高把握 17=名片
        30 => "通过扫一扫添加",    // WCDA + WeChatFerry 两家 30=扫码
        45 => "无来源",            // 用户 2026-07-08 确认: 无准确来源的默认桶
        _ => return None,          // 未知 (9/15/87/1000000…) → 调用方显示 "其他 (码 N)"
    })
}

/// `friend_source` → 展示串 (已知返中文; 未知返 `其他 (码 N)`, 保留原码可查)。
#[must_use]
pub fn friend_source_display(code: i64) -> String {
    friend_source_label(code).map_or_else(|| format!("其他 (码 {code})"), str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_map_to_chinese() {
        assert_eq!(friend_source_label(30), Some("通过扫一扫添加"));
        assert_eq!(friend_source_label(14), Some("通过群聊添加"));
        assert_eq!(friend_source_label(17), Some("通过名片分享添加"));
        assert_eq!(friend_source_label(45), Some("无来源"));
        assert_eq!(friend_source_label(0), Some("未记录"));
    }

    #[test]
    fn unknown_code_falls_back_to_raw() {
        assert_eq!(friend_source_label(9), None);
        assert_eq!(friend_source_display(9), "其他 (码 9)");
        assert_eq!(friend_source_display(1_000_000), "其他 (码 1000000)");
        assert_eq!(friend_source_display(30), "通过扫一扫添加", "已知码 display 直接给中文");
    }
}
