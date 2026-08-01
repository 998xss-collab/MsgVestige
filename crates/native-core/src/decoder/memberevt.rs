//! decoder::memberevt — 从群成员系统消息 (msg_type=10000) 抽成员进出事件 (入群/退群) →
//! 派生 L2 表 `chatroom_member_event` (谁在哪个群何时入/退群)。
//!
//! 群成员系统消息 (decoder 已把 zstd 解压进 text_content) 有两种承载形态, 由现有
//! [`classify_sysmsg`](super::sysmsg::classify_sysmsg) 分 `member_join` / `member_remove`:
//!
//! ## A. 入群 `member_join`
//! - **结构化 XML** (`<sysmsg type="sysmsgtemplate">`, 真库 582/845): `<link name="names">` 下**每个**
//!   `<member>` = 一个新入群成员 (`<username>`=wxid / `<nickname>`=昵称) → 一行 kind="join";
//!   `<link name="username">` 的 member wxid = **邀请人 inviter_wxid** (填到每行; 可缺 — 如"你邀请…"无此 link)。
//! - **纯文本** (真库 263/845, 如 `"甲"邀请"乙"加入了群聊`): 只有昵称无 wxid → 抽被邀请者昵称 (末个引号名),
//!   member_wxid=None, inviter=None (纯文本邀请人只有昵称, 本表不存 inviter 昵称)。
//! - **扫码结构化** (ADR-496 补, `"$adder$"通过扫描"$from$"分享的二维码加入群聊`): 新成员在 `<link name="adder">`,
//!   分享者在 `<link name="from">`(填 inviter_wxid)。
//! - **"你邀请"结构化** (ADR-496 补, `你邀请"$username$"加入了群聊…`): 无 names link, 被邀请者(新成员)在
//!   `<link name="username">`(guard `你邀请` 防误读标准式 username=邀请人)。
//!
//! ## B. 退群/被踢 `member_remove`
//! - **结构化 XML** (真库 2/2, `<link name="kickoutname">`): memberlist 里被移出者 `<username>`=wxid / `<nickname>` →
//!   一行 kind="remove" (member_wxid=Some, inviter=None)。
//! - **纯文本** (如 `你将"张三"移出了群聊` / `"管理员"将"李四"移出了群聊`): 抽被移出者昵称 (末个引号名),
//!   member_wxid=None (没 wxid 是真的, 不硬造)。
//!
//! **纯字符串抽取, infallible** (非入群/退群消息 → 空 Vec)。复用 appmsg 的 [`extract_tag`](super::appmsg::extract_tag)
//! helper (tag/CDATA 抽取), 具名 link scope / member 迭代自实现 (appmsg 无具名 link scoping)。
//!
//! ## K-R4
//! - member_wxid / inviter_wxid (id 类) → 上层 [`V3ChatroomMemberEvent`](crate::storage::V3ChatroomMemberEvent)
//!   明文列 + `_sha` + 手写 Debug sha8; member_nickname (display) → Debug 只露 sha8。
//! - 本 mod 派生自 text_content (已在 message content_digest); chatroom_member_event 表 **L2-only 不进 digest**。

use super::appmsg::extract_tag;

/// 一条群成员进出事件 (一条系统消息可产出多条 — 一次邀请多人)。
///
/// 结构化 XML 有 wxid; 纯文本只有昵称 (member_wxid=None)。**别为纯文本硬造 wxid**。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MemberEvent {
    /// 进/出成员 wxid (结构化 XML 有; 纯文本无 → None)。
    pub member_wxid: Option<String>,
    /// 进/出成员昵称 (display; 结构化/纯文本一般都有)。
    pub member_nickname: Option<String>,
    /// 邀请人 wxid (仅入群结构化 XML 的 `<link name="username">`; 纯文本/退群/自邀 → None)。
    pub inviter_wxid: Option<String>,
    /// 事件类别: `"join"`(入群) | `"remove"`(退群/被踢)。
    pub kind: &'static str,
}

/// 抽 `<link name="{link_name}">…</link>` 块内层 (scope 到具名 link; 无则 None)。
///
/// `<link_list>` 里多个 `<link name="username"|"names"|"kickoutname">`, [`extract_block`] 只取第一个 `<link>`,
/// 故按 `name="X"` 定位后再取其 `<memberlist>` 块。找 `name="{link_name}"` → 回退到该 `<link` 开头 →
/// 取到匹配的 `</link>`。
fn link_scope<'a>(text: &'a str, link_name: &str) -> Option<&'a str> {
    let needle = format!("name=\"{link_name}\"");
    let attr_pos = text.find(&needle)?;
    // 回退到本 `<link` 起始 (attr 之前最近的 "<link")。
    let link_start = text[..attr_pos].rfind("<link")?;
    let rest = &text[link_start..];
    let end = rest.find("</link>")?;
    Some(&rest[..end])
}

/// 迭代 scope 内所有 `<member>…</member>` 块 (一 memberlist 多 member; 畸形无闭合 → 停)。
fn member_blocks(scope: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = scope[i..].find("<member>") {
        let start = i + rel + "<member>".len();
        let Some(end_rel) = scope[start..].find("</member>") else {
            break; // 无闭合 = 畸形, 停 (防死循环)
        };
        out.push(&scope[start..start + end_rel]);
        i = start + end_rel + "</member>".len();
    }
    out
}

/// 从纯文本引号串抽昵称 (微信引号: 直双引号 `"` U+0022 + 中文弯引号 `“”` + 直角 `「」`)。
/// 返回**按出现序**的引号内昵称列表。真库入群纯文本 `"甲"邀请"乙"加入了群聊` → 依次抽出 甲 / 乙。
fn quoted_names(text: &str) -> Vec<String> {
    // 引号成对: 收集所有 (开/闭同符或中文成对) 之间的内容。用状态机: 遇任一引号符切换 in/out。
    // 中文 “ 开 ” 闭 / 「 开 」 闭 / 直 " 开闭同符 —— 统一按"任一引号符即分隔"切段, 取奇数段 (段内=名字)。
    const QUOTES: [char; 5] = ['"', '\u{201c}', '\u{201d}', '\u{300c}', '\u{300d}'];
    let mut names = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for ch in text.chars() {
        if QUOTES.contains(&ch) {
            if inside {
                // 闭合 → 收一段 (非空)。
                let name = cur.trim();
                if !name.is_empty() {
                    names.push(name.to_string());
                }
                cur.clear();
                inside = false;
            } else {
                inside = true;
                cur.clear();
            }
        } else if inside {
            cur.push(ch);
        }
    }
    names
}

/// 是否结构化 sysmsg XML (有 `<sysmsg` 壳)。真库入群/退群结构化态皆 `<sysmsg type="sysmsgtemplate">` 开头。
/// 用于: 结构化态没抽到成员时**不**退到引号提取 (防把 XML 属性引号 `name="names"` 误当昵称)。
fn is_structured(text: &str) -> bool {
    text.contains("<sysmsg")
}

/// 抽入群事件 (member_join): 结构化 XML → 每 names.member 一行 + inviter; 纯文本 → 单行昵称 (无 wxid)。
fn parse_join(text: &str) -> Vec<MemberEvent> {
    // 结构化: <link name="names"> 下每个 <member>。
    if let Some(names_scope) = link_scope(text, "names") {
        let members = member_blocks(names_scope);
        if !members.is_empty() {
            // 邀请人 = <link name="username"> 的第一个 member 的 wxid (可缺: "你邀请…" 无此 link)。
            let inviter_wxid = link_scope(text, "username")
                .and_then(|us| member_blocks(us).first().copied())
                .and_then(|mb| extract_tag(mb, "username"));
            return members
                .into_iter()
                .map(|mb| MemberEvent {
                    member_wxid: extract_tag(mb, "username"),
                    member_nickname: extract_tag(mb, "nickname"),
                    inviter_wxid: inviter_wxid.clone(),
                    kind: "join",
                })
                .collect();
        }
    }
    // (ADR-496 补抽) 扫码入群 `"$adder$"通过扫描"$from$"分享的二维码加入群聊`: 新成员在 `<link name="adder">`,
    //  分享者(拉人者)在 `<link name="from">`。adder 恒=扫码进群者=新成员, 无歧义。
    if let Some(adder_scope) = link_scope(text, "adder") {
        let members = member_blocks(adder_scope);
        if !members.is_empty() {
            let sharer = link_scope(text, "from")
                .and_then(|f| member_blocks(f).first().copied())
                .and_then(|mb| extract_tag(mb, "username"));
            return members
                .into_iter()
                .map(|mb| MemberEvent {
                    member_wxid: extract_tag(mb, "username"),
                    member_nickname: extract_tag(mb, "nickname"),
                    inviter_wxid: sharer.clone(), // 二维码分享者 ≈ 拉人者
                    kind: "join",
                })
                .collect();
        }
    }
    // (ADR-496 补抽) `你邀请"$username$"加入了群聊…`: 无 names link, 被邀请者(新成员)在 `<link name="username">`。
    //  ⚠️guard `你邀请` — 标准 `"$username$"邀请"$names$"` 里 username=**邀请人**(已被上面 names 分支处理并返回);
    //  仅"你邀请…"这种无 names、username=被邀请者的形态才走此分支, 防误把邀请人当新成员。
    if text.contains("你邀请") {
        if let Some(us_scope) = link_scope(text, "username") {
            let members = member_blocks(us_scope);
            if !members.is_empty() {
                return members
                    .into_iter()
                    .map(|mb| MemberEvent {
                        member_wxid: extract_tag(mb, "username"),
                        member_nickname: extract_tag(mb, "nickname"),
                        inviter_wxid: None, // "你"邀请 = 账号本人, 无独立邀请人 wxid
                        kind: "join",
                    })
                    .collect();
            }
        }
    }
    // 结构化 XML 但没抽到成员 (畸形空 memberlist) → 空, **不**退到引号提取 (否则会把 XML 属性引号
    //  如 name="names" 误当昵称)。仅真·纯文本 (无 sysmsg 壳) 才走引号提取。
    if is_structured(text) {
        return Vec::new();
    }
    // 纯文本 `"甲"邀请"乙"加入了群聊`: 被邀请者 = 末个引号名 (邀请人在前, 但本表不存 inviter 昵称)。
    // "你邀请\"乙\"…" → 只有一个引号名=被邀请者。取最后一个引号名作被邀请者昵称; 无引号名 → 无事件。
    let names = quoted_names(text);
    match names.last() {
        Some(nick) => vec![MemberEvent {
            member_wxid: None,
            member_nickname: Some(nick.clone()),
            inviter_wxid: None,
            kind: "join",
        }],
        None => Vec::new(),
    }
}

/// 抽退群事件 (member_remove): 结构化 XML → kickoutname memberlist 每 member 一行; 纯文本 → 末个引号名 (无 wxid)。
fn parse_remove(text: &str) -> Vec<MemberEvent> {
    // 结构化: <link name="kickoutname"> memberlist。真库 `你将"$kickoutname$"移出了群聊`。
    if let Some(kick_scope) = link_scope(text, "kickoutname") {
        let members = member_blocks(kick_scope);
        if !members.is_empty() {
            return members
                .into_iter()
                .map(|mb| MemberEvent {
                    member_wxid: extract_tag(mb, "username"),
                    member_nickname: extract_tag(mb, "nickname"),
                    inviter_wxid: None,
                    kind: "remove",
                })
                .collect();
        }
    }
    // 结构化 XML 但没抽到成员 → 空 (同 parse_join, 不退到引号提取防 XML 属性引号误挖)。
    if is_structured(text) {
        return Vec::new();
    }
    // 纯文本 `你将"张三"移出了群聊` / `"管理员"将"李四"移出了群聊`: 被移出者 = **末个**引号名
    //  (操作者若有名在前, 被移出者恒在"移出"前紧邻末位)。没 wxid 是真的, 不硬造。
    let names = quoted_names(text);
    match names.last() {
        Some(nick) => vec![MemberEvent {
            member_wxid: None,
            member_nickname: Some(nick.clone()),
            inviter_wxid: None,
            kind: "remove",
        }],
        None => Vec::new(),
    }
}

/// 从系统消息 text_content 抽群成员进出事件。**非入群/退群 (含非 10000) → 空 Vec**。**infallible**。
///
/// 由 [`classify_sysmsg`](super::sysmsg::classify_sysmsg) 判类: member_join → [`parse_join`]; member_remove →
/// [`parse_remove`]; 其余 → 空。一条邀请多人 → 多个 [`MemberEvent`] (投影层 per-行 seq 保 PK 唯一不塌陷)。
#[must_use]
pub fn parse_member_events(text_content: &str) -> Vec<MemberEvent> {
    match super::sysmsg::classify_sysmsg(text_content) {
        "member_join" => parse_join(text_content),
        "member_remove" => parse_remove(text_content),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 真库形态 (staging message_0.db, 2026-07-08 probe): 结构化入群 XML (582/845)。
    const JOIN_XML: &str = r#"2085****353@chatroom:
<sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template type="tmpl_type_profile">
<plain><![CDATA[]]></plain>
<template><![CDATA["$username$"邀请"$names$"加入了群聊]]></template>
<link_list>
<link name="username" type="link_profile"><memberlist><member><username><![CDATA[25984981768175054@openim]]></username><nickname><![CDATA[柠檬妈妈母婴]]></nickname></member></memberlist></link>
<link name="names" type="link_profile"><memberlist><member><username><![CDATA[tt5757107]]></username><nickname><![CDATA[琛、]]></nickname></member></memberlist><separator><![CDATA[、]]></separator></link>
</link_list></content_template></sysmsgtemplate></sysmsg>"#;

    // 多人入群 (names 下 2 member; 真库 local_id=14, bare text 无 CDATA; 无 <link name="username"> = 自邀"你邀请")。
    const JOIN_XML_MULTI: &str = r#"5013****926@chatroom:
<sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template type="tmpl_type_profile">
<template>你邀请"$names$"加入了群聊，并分享了$history$</template>
<link_list>
<link name="names" type="link_profile"><memberlist>
<member><username>wxid_n5sxxb5tdphl22</username><nickname>星星望月</nickname></member>
<member><username>luqingqing319</username><nickname>鹿一</nickname></member>
</memberlist><separator>、</separator></link>
</link_list></content_template></sysmsgtemplate></sysmsg>"#;

    // 退群结构化 XML (真库 2/2, kickoutname)。
    const REMOVE_XML: &str = r#"4570****024@chatroom:
<sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template type="tmpl_type_profile">
<template><![CDATA[你将"$kickoutname$"移出了群聊]]></template>
<link_list>
<link name="kickoutname" type="link_profile"><memberlist><member><username><![CDATA[wxid_i1ukzjy3f32c22]]></username><nickname><![CDATA[春风]]></nickname></member></memberlist></link>
</link_list></content_template></sysmsgtemplate></sysmsg>"#;

    #[test]
    fn join_xml_single_member_with_inviter() {
        let ev = parse_member_events(JOIN_XML);
        assert_eq!(ev.len(), 1, "names 下 1 member → 1 行");
        assert_eq!(ev[0].kind, "join");
        assert_eq!(ev[0].member_wxid.as_deref(), Some("tt5757107"), "被邀请者 wxid");
        assert_eq!(ev[0].member_nickname.as_deref(), Some("琛、"), "被邀请者昵称");
        assert_eq!(
            ev[0].inviter_wxid.as_deref(),
            Some("25984981768175054@openim"),
            "邀请人 = link name=username 的 member wxid"
        );
    }

    #[test]
    fn join_xml_multi_member_no_collapse() {
        // ⭐一条邀请多人 → 多行 (per-行 seq 保 PK 唯一, 不塌陷)。inviter 缺 (无 <link name=username>)。
        let ev = parse_member_events(JOIN_XML_MULTI);
        assert_eq!(ev.len(), 2, "names 下 2 member → 2 行 (不塌成 1)");
        assert_eq!(ev[0].member_wxid.as_deref(), Some("wxid_n5sxxb5tdphl22"));
        assert_eq!(ev[0].member_nickname.as_deref(), Some("星星望月"));
        assert_eq!(ev[1].member_wxid.as_deref(), Some("luqingqing319"));
        assert_eq!(ev[1].member_nickname.as_deref(), Some("鹿一"));
        assert!(ev[0].inviter_wxid.is_none(), "自邀(你邀请)无 inviter link → None");
        assert!(ev.iter().all(|e| e.kind == "join"));
    }

    // (ADR-496 补抽) 扫码入群结构化: 新成员在 adder link, 分享者在 from link。
    const JOIN_QR: &str = r#"4902****933@chatroom:
<sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template type="tmpl_type_profile">
<template><![CDATA["$adder$"通过扫描"$from$"分享的二维码加入群聊]]></template>
<link_list>
<link name="adder"><memberlist><member><username><![CDATA[wxid_scanner001]]></username><nickname><![CDATA[扫码人]]></nickname></member></memberlist></link>
<link name="from"><memberlist><member><username><![CDATA[wxid_sharer002]]></username><nickname><![CDATA[分享人]]></nickname></member></memberlist></link>
</link_list></content_template></sysmsgtemplate></sysmsg>"#;

    // (ADR-496 补抽) "你邀请$username$": 无 names, username=被邀请者。
    const JOIN_YOU_INVITE: &str = r#"4792****540@chatroom:
<sysmsg type="sysmsgtemplate"><sysmsgtemplate><content_template type="tmpl_type_profile">
<template><![CDATA[你邀请"$username$"加入了群聊，并分享了$history$]]></template>
<link_list>
<link name="username" type="link_profile"><memberlist><member><username><![CDATA[wxid_invitee003]]></username><nickname><![CDATA[被邀请者]]></nickname></member></memberlist></link>
<link name="history" type="link_history"></link>
</link_list></content_template></sysmsgtemplate></sysmsg>"#;

    #[test]
    fn join_qr_scan_adder_is_new_member() {
        // ADR-496: 扫码入群 → adder=新成员(有 wxid), from=分享者→inviter。
        let ev = parse_member_events(JOIN_QR);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, "join");
        assert_eq!(
            ev[0].member_wxid.as_deref(),
            Some("wxid_scanner001"),
            "adder=扫码进群的新成员"
        );
        assert_eq!(ev[0].member_nickname.as_deref(), Some("扫码人"));
        assert_eq!(
            ev[0].inviter_wxid.as_deref(),
            Some("wxid_sharer002"),
            "from=二维码分享者→inviter"
        );
    }

    #[test]
    fn join_you_invite_username_is_new_member() {
        // ADR-496: "你邀请X" 无 names, username=被邀请者(新成员), inviter=None(你本人)。
        let ev = parse_member_events(JOIN_YOU_INVITE);
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev[0].member_wxid.as_deref(),
            Some("wxid_invitee003"),
            "你邀请式: username=被邀请者"
        );
        assert_eq!(ev[0].member_nickname.as_deref(), Some("被邀请者"));
        assert!(ev[0].inviter_wxid.is_none(), "你邀请 = 本人邀请, 无独立 inviter wxid");
    }

    #[test]
    fn standard_invite_username_still_inviter_not_misread() {
        // ⚠️防误读: 标准 "$username$邀请$names$" 里 username=邀请人, 必走 names 分支(不被"你邀请"补抽误当新成员)。
        // JOIN_XML 不含 "你邀请", 有 names → username 仍是 inviter, 新成员是 names 的 tt5757107。
        let ev = parse_member_events(JOIN_XML);
        assert_eq!(
            ev[0].member_wxid.as_deref(),
            Some("tt5757107"),
            "新成员仍=names(非 username 邀请人)"
        );
        assert_eq!(
            ev[0].inviter_wxid.as_deref(),
            Some("25984981768175054@openim"),
            "username 仍是邀请人"
        );
    }

    #[test]
    fn join_plain_text_nickname_only_no_wxid() {
        // 纯文本 (263/845): 只有昵称无 wxid → member_wxid=None, inviter=None, 被邀请者=末引号名。
        let ev = parse_member_events(r#""乐乐@尚德菱门客服"邀请"四维ai还原@尚德菱门客服"加入了群聊"#);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, "join");
        assert!(ev[0].member_wxid.is_none(), "纯文本无 wxid — 不硬造");
        assert_eq!(
            ev[0].member_nickname.as_deref(),
            Some("四维ai还原@尚德菱门客服"),
            "被邀请者=末引号名"
        );
        assert!(ev[0].inviter_wxid.is_none(), "纯文本无邀请人 wxid");
    }

    #[test]
    fn remove_xml_with_wxid() {
        let ev = parse_member_events(REMOVE_XML);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, "remove");
        assert_eq!(
            ev[0].member_wxid.as_deref(),
            Some("wxid_i1ukzjy3f32c22"),
            "被移出者 wxid (结构化有)"
        );
        assert_eq!(ev[0].member_nickname.as_deref(), Some("春风"));
        assert!(ev[0].inviter_wxid.is_none(), "退群无 inviter");
    }

    #[test]
    fn remove_plain_text_nickname_only() {
        // 纯文本退群: 被移出者=末引号名, 无 wxid。
        let ev = parse_member_events(r#""管理员"将"李四"移出了群聊"#);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, "remove");
        assert!(ev[0].member_wxid.is_none(), "纯文本无 wxid");
        assert_eq!(
            ev[0].member_nickname.as_deref(),
            Some("李四"),
            "被移出者=末引号名 (操作者在前)"
        );
        // 自己踢人 `你将"张三"移出了群聊`: 操作者"你"无引号 → 唯一引号名=被移出者。
        let ev2 = parse_member_events(r#"你将"张三"移出了群聊"#);
        assert_eq!(ev2.len(), 1);
        assert_eq!(ev2[0].member_nickname.as_deref(), Some("张三"));
    }

    #[test]
    fn non_member_event_empty() {
        assert!(parse_member_events("你撤回了一条消息").is_empty(), "撤回 → 空");
        assert!(
            parse_member_events(r#""迷了璐" 拍了拍 "某人""#).is_empty(),
            "拍一拍 → 空"
        );
        assert!(parse_member_events("普通文本消息").is_empty(), "普通文本 → 空");
        assert!(parse_member_events("").is_empty(), "空串 → 空");
        assert!(
            parse_member_events("你已解散该群聊").is_empty(),
            "群解散 → 空 (非进出事件)"
        );
    }

    #[test]
    fn join_xml_missing_names_falls_back_empty_members() {
        // 结构化壳但 names 下无 member (畸形) → 走纯文本兜底; 无引号名 → 空。
        let x = r#"<sysmsg type="sysmsgtemplate"><link_list><link name="names"><memberlist></memberlist></link></link_list>加入了群聊</sysmsg>"#;
        assert!(parse_member_events(x).is_empty(), "空 memberlist + 无引号 → 空");
    }

    #[test]
    fn quoted_names_chinese_and_straight_quotes() {
        // 直双引号 U+0022 + 中文弯引号成对。
        assert_eq!(quoted_names(r#""甲"邀请"乙"加入了群聊"#), vec!["甲", "乙"]);
        assert_eq!(quoted_names("“张三”被移出"), vec!["张三"]);
        assert_eq!(quoted_names("无引号"), Vec::<String>::new());
    }
}
