//! decoder::hongbao_claim — 从红包领取系统消息 (msg_type=10000, sys_type=hongbao) 抽"谁领了红包"。
//!
//! 真库实测 (2026-07-08): 领取通知是系统消息, text_content 形如
//!   `<img src="SystemMessages_HongbaoIcon.png"/>  {名字}领取了你的<_wc_custom_link_ href="...opendetail?sendid={id}">红包</_wc_custom_link_>`
//! 两个方向:
//!   - `{A}领取了你的红包` = **别人领我发的** (A = 领取人, is_own_envelope=true) → "我发的红包谁领了"就靠这个。
//!   - `你领取了{B}的红包` = **我领别人的** (B = 发红包人, is_own_envelope=false)。
//!
//! href 里 `sendid` = 红包单号 (关联 red_envelope.send_id; 同一个群红包多领取人共享同一 sendid → 可 GROUP BY 聚人)。
//! **金额不在通知里** (微信不写进消息, 领取额只在服务器); 竞品无一解此领取通知 (只解发送消息)。ADR-504。
//! **纯字符串抽, infallible** (非红包领取通知 → None)。仿 [`super::voip`]。

/// 红包领取通知抽出的字段。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HongbaoClaim {
    /// 红包单号 (href `sendid=`; 关联 red_envelope.send_id)。
    pub send_id: String,
    /// true = 我发的红包被领 (`{A}领取了你的`); false = 我领别人的 (`你领取了{B}的`)。
    pub is_own_envelope: bool,
    /// 对方显示名 (我发的→领取人 A; 我领的→发红包人 B)。
    pub peer_name: String,
}

/// 系统消息 local_type (WeChat 系统消息)。
const MSG_TYPE_SYS: i32 = 10000;

/// 从系统消息 content 抽红包领取。非系统消息 / 无红包图标 / 非领取通知 → None。**infallible**。
#[must_use]
pub fn parse_hongbao_claim(msg_type: i32, content: &str) -> Option<HongbaoClaim> {
    if msg_type != MSG_TYPE_SYS || !content.contains("HongbaoIcon") {
        return None;
    }
    let send_id = extract_send_id(content)?;
    // 方向 1: "{A}领取了你的红包" — 别人领我发的 (我发的红包谁领了)。
    if let Some(idx) = content.find("领取了你的") {
        let name = clean_name(&content[..idx]);
        if !name.is_empty() {
            return Some(HongbaoClaim {
                send_id,
                is_own_envelope: true,
                peer_name: name,
            });
        }
    }
    // 方向 2: "你领取了{B}的红包" — 我领别人的。
    if let Some(rest) = content.split_once("你领取了").map(|x| x.1) {
        if let Some(end) = rest.find("的<").or_else(|| rest.find("的红包")) {
            let name = clean_name(&rest[..end]);
            if !name.is_empty() {
                return Some(HongbaoClaim {
                    send_id,
                    is_own_envelope: false,
                    peer_name: name,
                });
            }
        }
    }
    None
}

/// 从 `href="...opendetail?sendid=XXX..."` 抽 sendid (到 `&` / `"` / `<` 止)。
fn extract_send_id(content: &str) -> Option<String> {
    let after = content.split_once("sendid=").map(|x| x.1)?;
    let id: String = after
        .chars()
        .take_while(|&c| c != '&' && c != '"' && c != '<')
        .collect();
    (!id.is_empty()).then_some(id)
}

/// 清理领取人名字: 去掉前面的 `<img.../>` 前缀 (取最后一个 `/>` 之后) + trim 空白。
fn clean_name(before: &str) -> String {
    before.rsplit("/>").next().unwrap_or(before).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = r##"<img src="SystemMessages_HongbaoIcon.png"/>  阿婷领取了你的<_wc_custom_link_ color="#FD9931" href="weixin://weixinhongbao/opendetail?sendid=1000039801202511076348177429056">红包</_wc_custom_link_>"##;
    const MINE: &str = r##"<img src="SystemMessages_HongbaoIcon.png"/>  你领取了跳跳的<_wc_custom_link_ color="#FD9931" href="weixin://weixinhongbao/opendetail?sendid=1000039801202511197197943521018&sign=abc&ver=6">红包</_wc_custom_link_>"##;

    #[test]
    fn parses_others_claiming_mine() {
        let c = parse_hongbao_claim(10000, OWN).expect("别人领我的红包应解出");
        assert!(c.is_own_envelope, "领取了你的 → 我发的被领");
        assert_eq!(c.peer_name, "阿婷");
        assert_eq!(c.send_id, "1000039801202511076348177429056");
    }

    #[test]
    fn parses_me_claiming_others() {
        let c = parse_hongbao_claim(10000, MINE).expect("我领别人的红包应解出");
        assert!(!c.is_own_envelope, "你领取了X的 → 我领别人的");
        assert_eq!(c.peer_name, "跳跳");
        assert_eq!(c.send_id, "1000039801202511197197943521018", "sendid 到 & 止");
    }

    #[test]
    fn non_claim_returns_none() {
        assert!(parse_hongbao_claim(1, OWN).is_none(), "非系统消息 → None");
        assert!(
            parse_hongbao_claim(10000, "<img/>普通系统消息").is_none(),
            "无红包图标 → None"
        );
        assert!(
            parse_hongbao_claim(10000, r#"<img src="SystemMessages_HongbaoIcon.png"/>红包已过期未领取"#).is_none(),
            "红包系统消息但非领取(无 sendid/名字) → None"
        );
    }
}
