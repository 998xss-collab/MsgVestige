//! decoder::appmsg — 从消息 `text_content` 的 `<appmsg>` XML 抽卡片结构化字段 (视频号/小程序/链接)。
//!
//! 微信 APP 消息 (msg_type 49) 的 content 是 `<msg><appmsg><type>N</type>...</appmsg></msg>` XML
//! (我们 decoder 已把 zstd 解压进 text_content)。本 mod 把这坨 XML 里**命名标签**抽成结构化字段 →
//! 派生 L2 表 message_app (ADR-455)。**纯字符串抽取, infallible** (返 `Option`: 非 appmsg / 无 type → None)。
//!
//! ## appmsg type (子类, `<appmsg><type>`)
//! 5=链接 / 6=文件 / 8=表情 / 19=聊天记录 / 33·36=小程序 / 51=视频号 / 57=引用 / 2000=转账 / 2001=红包。
//! 视频号看 `<finderFeed>` (作者 nickname / 视频号 id username / mediaCount); 小程序看 `<weappinfo>`
//! (gh id username / pagepath) + `<sourcedisplayname>` (来源); 通用 `<title>`/`<url>`。
//!
//! ## K-R4
//! - 抽出的 title/nickname/source 是内容/展示类 → [`AppmsgCard`] 手写 Debug 走 [`sha8`] 脱敏 (同 ContactExtra)。
//! - 本 mod 派生自 text_content (已在 message content_digest); message_app 表 **L2-only 不进 digest/payload**。

use std::fmt;

use crate::key_provider::sha8;

/// 从 appmsg XML 抽出的卡片字段 (视频号/小程序/链接通用)。
#[derive(Clone, PartialEq, Eq, Default)]
pub struct AppmsgCard {
    /// appmsg 子类 (`<appmsg><type>`; 5链接/33小程序/51视频号 等)。
    pub app_type: i64,
    /// 卡片标题 (`<title>`; 小程序卡片标题/链接标题, 可空)。
    pub title: Option<String>,
    /// 来源显示名 (`<sourcedisplayname>`; 小程序来源如"优时通", 可空)。
    pub source_name: Option<String>,
    /// 主链接 (`<url>`; 媒体/页面 url, 可空)。
    pub url: Option<String>,
    /// 应用标识 (视频号 `<finderFeed><username>` v2_ id / 小程序 `<weappinfo><username>` gh_xxx@app, 可空)。
    pub app_username: Option<String>,
    /// 视频号作者昵称 (`<finderFeed><nickname>`, 可空)。
    pub app_nickname: Option<String>,
    /// 视频号媒体数 (`<finderFeed><mediaCount>`; 非视频号为 0)。
    pub media_count: i64,
    /// 小程序页面路径 (`<weappinfo><pagepath>`, 可空)。
    pub app_pagepath: Option<String>,

    // ── 类型专属细节 (ADR-462; 竞品差距补; 非对应类型为 0/None) ──
    /// 文件字节数 (type 6 `<appattach><totallen>`; 非文件 0)。
    pub file_size: i64,
    /// 文件后缀 (type 6 `<appattach><fileext>`, 如 "apk"; 可空)。
    pub file_ext: Option<String>,
    /// 文件内容 md5 (type 6 `<appattach><md5>`; 可空)。
    pub file_md5: Option<String>,
    /// 转账金额串 (type 2000 `<wcpayinfo><feedesc>`, 如 "￥10.00"; 可空)。
    pub transfer_fee: Option<String>,
    /// 转账方向 (type 2000 `<wcpayinfo><paysubtype>`: 1=发出/3=收到 等; 非转账 0)。
    pub transfer_direction: i64,
    /// 转账交易号 (type 2000 `<wcpayinfo><transcationid>`; 可空)。
    pub transfer_txid: Option<String>,
    /// 被引消息服务端 id (type 57 `<refermsg><svrid>`; 可空)。
    pub refer_svrid: Option<String>,
    /// 被引消息类型 (type 57 `<refermsg><type>`; 非引用 0)。
    pub refer_type: i64,
    /// 被引消息内容 (type 57 `<refermsg><content>`; 引用的原文, 可空)。
    pub refer_content: Option<String>,
    /// 合并转发条数 (type 19 `<recorditem>` 里 `<datalist count="N">`; 非转发 0)。
    pub forward_item_count: i64,
    /// 红包祝福语/留言 (type 2001 `<wcpayinfo><sendertitle>`, 如 "恭喜发财大吉大利"/"基础工资"; 可空)。
    pub red_envelope_wish: Option<String>,
    /// 红包个数 (type 2001 `<wcpayinfo><nativeurl>` query `total_num`; 非红包 0)。
    pub red_envelope_count: i64,
    /// 群收款金额显示串 (type 2001 **带 `<newaa>`** 的群收款, `<wcpayinfo><senderdes>`, 含 ¥金额如 "应付¥8.00";
    ///  区别于红包=2001 无 newaa; 已付/参与人列表本地空 → 只有金额可解 ADR-487; 非群收款 None)。
    pub group_pay_amount: Option<String>,
    /// 群收款单号 (type 2001 群收款 `<wcpayinfo><newaa><billno>`; 供 JOIN general.db groupPayTable.bill_no; 可空)。
    pub group_pay_bill_no: Option<String>,
    /// 群收款逐付款人 (type 2001 群收款 `<newaa><payerlist>`; `wxid,金额分,状态` 逐条 `|` 分隔 — ADR-488):
    /// 每元组 = (付款人 wxid, 金额分, 状态)。已付人数=Vec 长度; 空=非群收款/无付款人。真库单1 28人¥20/单2 23人¥8。
    pub group_pay_members: Vec<(String, i64, i64)>,
    /// 支付场景类型名 (type 2000/2001 `<wcpayinfo><scenetext>`, 系统贴的类别标签如 "微信红包"/"群收款"/"活动账单";
    /// 非用户内容 = 低基数枚举 — ADR-495; 转账/红包/群收款均可有; 无 → None)。**与我方结构分类冗余, 图齐全而存**。
    pub pay_scene_text: Option<String>,

    // ── 音乐/礼物/直播 (ADR-462 扩; 竞品差距 type 92/115/63; 非对应类型 0/None) ──
    /// 音乐描述/歌手 (type 92 `<des>`; title/url 通用已抽; streamweburl 在合并转发路径非直路; 可空)。
    pub music_desc: Option<String>,
    /// 礼物祝福语 (type 115 `<wishmessage>`; CipherTalk exportService.ts:627; 可空)。
    pub gift_wish: Option<String>,
    /// 礼物名 (type 115 `<skutitle>`; 可空)。
    pub gift_sku: Option<String>,
    /// 视频号直播状态 (type 63 `<finderLive><liveStatus>`; 缺标签→0; ⚠️真库无样本, 0 或为合法状态码,
    ///  语义待样本验 — 用 live_status 判"有无直播卡片"须结合 app_type==63, 别单看 0 (双审 P1)。
    pub live_status: i64,
    /// 视频号直播标题 (type 63 `<finderLive><desc>`; 可空)。
    pub live_desc: Option<String>,
}

/// 找 `<tag ...>` 开标签结束位 (返 '>' 之后 byte index; **容忍属性** 如 `<appmsg appid="">`;
/// 边界防 `<title` 误配 `<titlebar`)。找第一个合法开标签。
fn open_tag_end(haystack: &str, tag: &str) -> Option<usize> {
    let needle = format!("<{tag}");
    let mut from = 0;
    loop {
        let pos = haystack[from..].find(&needle)? + from;
        let after = pos + needle.len();
        match haystack[after..].chars().next() {
            Some('>') => return Some(after + 1),
            // 有属性/自闭: 扫到本开标签的 '>'。
            Some(c) if c.is_whitespace() || c == '/' => {
                return Some(haystack[after..].find('>')? + after + 1);
            }
            // `<tagX` 误配 → 继续找下一个。
            _ => from = after,
        }
    }
}

/// 抽 `<tag ...>...</tag>` 的内层块 (给 finderFeed/weappinfo scope; 容忍开标签属性; 无则 None)。
fn extract_block<'a>(haystack: &'a str, tag: &str) -> Option<&'a str> {
    let start = open_tag_end(haystack, tag)?;
    let rest = &haystack[start..];
    let end = rest.find(&format!("</{tag}>"))?;
    Some(&rest[..end])
}

/// 抽 `<tag ...>...</tag>` 内容 (剥 CDATA + trim; 空 → None)。找**第一个** `<tag>` (主字段在前, 如 url 在 lowurl 前)。
/// `pub(crate)`: decoder/voip.rs 等同源 XML 子标签抽取复用 (open_tag_end 有边界检查, `msg` 不误配 `msg_type`)。
pub(crate) fn extract_tag(haystack: &str, tag: &str) -> Option<String> {
    let raw = extract_block(haystack, tag)?;
    // 剥 CDATA: <![CDATA[...]]> → 内部。
    let val = raw
        .trim()
        .strip_prefix("<![CDATA[")
        .and_then(|s| s.strip_suffix("]]>"))
        .unwrap_or_else(|| raw.trim())
        .trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// 剥掉 `haystack` 里指定标签的整块 `<tag ...>…</tag>` (给取外层 `<type>` 时排除嵌套块的 `<type>` 干扰)。
/// 无闭合 `</tag>` 则停止剥该标签 (畸形容错, 不死循环)。
/// `pub(crate)`: decoder/forward.rs 剥套娃 `<recordxml>` 防顶层字段串味复用 (ADR-476 F1)。
pub(crate) fn strip_blocks(haystack: &str, tags: &[&str]) -> String {
    let mut s = haystack.to_string();
    for tag in tags {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        // 反复剥同名多块; 每次找 open→对应 close 整段删。
        while let Some(start) = s.find(&open) {
            let Some(end_rel) = s[start..].find(&close) else {
                break; // 无闭合 = 畸形, 不再剥此 tag (防死循环)
            };
            s.replace_range(start..start + end_rel + close.len(), "");
        }
    }
    s
}

/// 从 URL 串抽 `name=<数字>` query 值 (红包 `total_num` 嵌在 nativeurl query `&total_num=16`, 非独立标签 →
/// 手扫; 取 `name=` 后的连续 ASCII 数字, 兼容出现在 query 中间或末尾)。无则 None。
fn query_param_i64(url: &str, name: &str) -> Option<i64> {
    let needle = format!("{name}=");
    let pos = url.find(&needle)? + needle.len();
    let digits: String = url[pos..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// 解群收款 payerlist `wxid,金额分,状态|wxid,金额分,状态|...` → 逐付款人 (wxid, 金额, 状态) (ADR-488)。
/// **infallible**: 坏条目跳过 (缺 wxid / 金额非数字); 空串 → 空 Vec。金额缺→0, 状态缺→0。
fn parse_payerlist(raw: &str) -> Vec<(String, i64, i64)> {
    raw.split('|')
        .filter_map(|entry| {
            let mut parts = entry.split(',');
            let wxid = parts.next()?.trim();
            if wxid.is_empty() {
                return None;
            }
            let amount = parts.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let status = parts.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            Some((wxid.to_string(), amount, status))
        })
        .collect()
}

/// 从消息 text_content (appmsg XML) 抽卡片字段。非 appmsg / 无 `<type>` → None (msg_type 49 才有意义, 但本函数
/// 不看 msg_type, 只看内容有没有 `<appmsg>` + `<type>`)。**infallible**。
#[must_use]
pub fn parse_appmsg(content: &str) -> Option<AppmsgCard> {
    // 定位 <appmsg> 块 (裸文本消息/图片等无此块 → None)。
    let appmsg = extract_block(content, "appmsg")?;
    // 取 appmsg **自己**的 <type>: 先剥 <refermsg>/<recorditem> 嵌套块 —— 它俩里的被引/被转发消息也有 <type>,
    //  真库实测 14 例 appmsg 的 <type> 排在 refermsg 之后, 不剥就会误取被引消息的 type (竞品 WCDA cross-check
    //  逮到; WCDA chat_helpers.py:1141 同防)。子字段仍从原 appmsg 抽 (下面 extract_block(appmsg, ...))。
    let type_scope = strip_blocks(appmsg, &["refermsg", "recorditem"]);
    // <type> 是 appmsg 必有的子类标识; 缺则不是有效卡片。
    let app_type: i64 = extract_tag(&type_scope, "type")?.parse().ok()?;

    let mut card = AppmsgCard {
        app_type,
        title: extract_tag(appmsg, "title"),
        source_name: extract_tag(appmsg, "sourcedisplayname"),
        url: extract_tag(appmsg, "url"),
        ..Default::default()
    };
    // 视频号 (finderFeed): 作者 nickname / 视频号 id username / mediaCount。
    if let Some(ff) = extract_block(appmsg, "finderFeed") {
        card.app_nickname = extract_tag(ff, "nickname");
        card.app_username = extract_tag(ff, "username");
        card.media_count = extract_tag(ff, "mediaCount").and_then(|s| s.parse().ok()).unwrap_or(0);
    }
    // 小程序 (weappinfo): gh id username / pagepath (finderFeed 已填则不覆盖 username — 两者不共存)。
    if let Some(wa) = extract_block(appmsg, "weappinfo") {
        if card.app_username.is_none() {
            card.app_username = extract_tag(wa, "username");
        }
        card.app_pagepath = extract_tag(wa, "pagepath");
    }
    // ── 类型专属细节 (ADR-462) ──
    // **⚠️ 必须按 app_type 精确分派, 不能只看子块存在**: 真库实测 <appattach> 不是文件专属 —— 链接(5)
    //  440/893、引用(57) 3097/4306 也带 <appattach>(缩略图), 只看块存在会把链接/引用的缩略图误当"文件大小/md5"落。
    match app_type {
        6 => {
            // 文件: appattach 里 totallen/fileext/md5。
            if let Some(aa) = extract_block(appmsg, "appattach") {
                card.file_size = extract_tag(aa, "totallen").and_then(|s| s.parse().ok()).unwrap_or(0);
                card.file_ext = extract_tag(aa, "fileext");
                card.file_md5 = extract_tag(aa, "md5");
            }
        }
        2000 => {
            // 转账: wcpayinfo 里 feedesc(金额)/paysubtype(方向)/transcationid。
            if let Some(wp) = extract_block(appmsg, "wcpayinfo") {
                card.transfer_fee = extract_tag(wp, "feedesc");
                card.transfer_direction = extract_tag(wp, "paysubtype").and_then(|s| s.parse().ok()).unwrap_or(0);
                card.transfer_txid = extract_tag(wp, "transcationid");
                card.pay_scene_text = extract_tag(wp, "scenetext"); // ADR-495: 支付场景类别名
            }
        }
        2001 => {
            // type 2001 = 红包 **或** 群收款(AA), 靠 `<newaa>` 块区分 (ADR-487 真库核实)。
            if let Some(wp) = extract_block(appmsg, "wcpayinfo") {
                card.pay_scene_text = extract_tag(wp, "scenetext"); // ADR-495: 红包/群收款共有的场景类别名
                if let Some(newaa) = extract_block(wp, "newaa") {
                    // 群收款: senderdes 含 ¥金额 (真库 8.00/30.00/15.00); billno 供 JOIN groupPayTable。
                    card.group_pay_amount = extract_tag(wp, "senderdes").or_else(|| extract_tag(wp, "receiverdes"));
                    card.group_pay_bill_no = extract_tag(newaa, "billno");
                    // 逐付款人 (ADR-488): payerlist `wxid,金额分,状态|...` (== customize_payerlist, 兜底)。已付人数=len。
                    card.group_pay_members = parse_payerlist(
                        &extract_tag(newaa, "payerlist")
                            .or_else(|| extract_tag(newaa, "customize_payerlist"))
                            .unwrap_or_default(),
                    );
                } else {
                    // 红包: sendertitle(祝福语/留言); total_num(个数)嵌 nativeurl query 非独立标签。
                    //  ⚠️**金额不在消息 XML** (微信设计, 真库核实红包消息无金额列) → 只补祝福语+个数。
                    //  真库 sendertitle==receivertitle 内容一致; 取 sendertitle, 空则兜 receivertitle (防边缘变体只填一个)。
                    card.red_envelope_wish =
                        extract_tag(wp, "sendertitle").or_else(|| extract_tag(wp, "receivertitle"));
                    card.red_envelope_count = extract_tag(wp, "nativeurl")
                        .and_then(|u| query_param_i64(&u, "total_num"))
                        .unwrap_or(0);
                }
            }
        }
        57 => {
            // 引用: refermsg 里 svrid(原消息id)/type/content(原文)。
            if let Some(rm) = extract_block(appmsg, "refermsg") {
                card.refer_svrid = extract_tag(rm, "svrid");
                card.refer_type = extract_tag(rm, "type").and_then(|s| s.parse().ok()).unwrap_or(0);
                card.refer_content = extract_tag(rm, "content");
            }
        }
        19 => {
            // 合并转发: recorditem 里 <datalist count="N"> 转发条数 (count 是属性, 手扫)。
            if let Some(ri) = extract_block(appmsg, "recorditem") {
                card.forward_item_count = ri
                    .find("count=\"")
                    .and_then(|p| ri[p + 7..].split('"').next())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        92 => {
            // 音乐分享: des(歌手/描述); title/url 通用已抽。streamweburl 在合并转发音乐路径非直路 (双审 aadbe23f)。
            card.music_desc = extract_tag(appmsg, "des");
        }
        115 => {
            // 微信礼物: wishmessage(祝福语)/skutitle(礼物名) (CipherTalk exportService.ts:627)。
            card.gift_wish = extract_tag(appmsg, "wishmessage");
            card.gift_sku = extract_tag(appmsg, "skutitle");
        }
        63 => {
            // 视频号**直播** (区别 51 视频号动态): finderLive 块 finderUsername/nickname/desc/liveStatus
            //  (chatlog_alpha mediamessage.go:421)。id/作者复用 app_username/app_nickname 列。
            if let Some(fl) = extract_block(appmsg, "finderLive") {
                card.app_username = extract_tag(fl, "finderUsername");
                card.app_nickname = extract_tag(fl, "nickname");
                card.live_desc = extract_tag(fl, "desc");
                card.live_status = extract_tag(fl, "liveStatus").and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        _ => {}
    }
    Some(card)
}

/// K-R4: title/nickname/source/url/username/pagepath 是内容/展示/链接类 → sha8 脱敏; app_type/media_count 明文。
impl fmt::Debug for AppmsgCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("AppmsgCard")
            .field("app_type", &self.app_type)
            .field("title_sha8", &o(&self.title))
            .field("source_name_sha8", &o(&self.source_name))
            .field("url_sha8", &o(&self.url))
            .field("app_username_sha8", &o(&self.app_username))
            .field("app_nickname_sha8", &o(&self.app_nickname))
            .field("media_count", &self.media_count)
            .field("app_pagepath_sha8", &o(&self.app_pagepath))
            // 类型专属脱敏: md5/交易号/引用原文 高熵 → sha8; **金额低熵(sha8 可字典枚举反推, codex P1)→ 只露有无**;
            //  大小/后缀/方向/id/类型/条数 明文。
            .field("file_size", &self.file_size)
            .field("file_ext", &self.file_ext)
            .field("file_md5_sha8", &o(&self.file_md5))
            .field("transfer_fee", &self.transfer_fee.as_ref().map(|_| "[redacted]"))
            .field("transfer_direction", &self.transfer_direction)
            .field("transfer_txid_sha8", &o(&self.transfer_txid))
            .field("refer_svrid", &self.refer_svrid)
            .field("refer_type", &self.refer_type)
            .field("refer_content_sha8", &o(&self.refer_content))
            .field("forward_item_count", &self.forward_item_count)
            // 红包祝福语=内容/展示类(自定义留言可含信息)→ sha8; 个数低敏明文。
            .field("red_envelope_wish_sha8", &o(&self.red_envelope_wish))
            .field("red_envelope_count", &self.red_envelope_count)
            // 群收款金额=财务低熵 → 只露有无 (同 transfer_fee); 单号=交易 id 高熵 → sha8。
            .field("group_pay_amount", &self.group_pay_amount.as_ref().map(|_| "[redacted]"))
            .field("group_pay_bill_no_sha8", &o(&self.group_pay_bill_no))
            .field("group_pay_members_len", &self.group_pay_members.len()) // K-R4: 含 wxid, 只露已付人数
            // 场景类别名=系统低基数枚举(微信红包/群收款), 非 PII → Debug 直露。
            .field("pay_scene_text", &self.pay_scene_text)

            // 音乐描述/礼物祝福语·名/直播标题=内容展示类 → sha8; 直播状态码明文。
            .field("music_desc_sha8", &o(&self.music_desc))
            .field("gift_wish_sha8", &o(&self.gift_wish))
            .field("gift_sku_sha8", &o(&self.gift_sku))
            .field("live_status", &self.live_status)
            .field("live_desc_sha8", &o(&self.live_desc))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINDER: &str = r#"<msg><appmsg appid=""><title></title><type>51</type><url><![CDATA[http://wxapp.tc.qq.com/vid]]></url><finderFeed><objectId><![CDATA[14764497635384170966]]></objectId><feedType>4</feedType><nickname><![CDATA[左滑看作业详情步骤2]]></nickname><mediaCount><![CDATA[7]]></mediaCount><username><![CDATA[v2_060000231003b20f]]></username></finderFeed></appmsg></msg>"#;

    const WEAPP: &str = r"<msg><appmsg><title>9.9元拼抢babycare纸尿裤</title><type>33</type><url>https://mp.weixin.qq.com/mp/waerrpage?appid=wx</url><sourcedisplayname>优时通</sourcedisplayname><weappinfo><username><![CDATA[gh_8fb1055af5ca@app]]></username><pagepath><![CDATA[misc-package/pages/groupbuy/index.html]]></pagepath></weappinfo></appmsg></msg>";

    #[test]
    fn parse_finder_feed() {
        let c = parse_appmsg(FINDER).unwrap();
        assert_eq!(c.app_type, 51, "视频号 type 51");
        assert_eq!(c.app_nickname.as_deref(), Some("左滑看作业详情步骤2"), "视频号作者");
        assert_eq!(c.app_username.as_deref(), Some("v2_060000231003b20f"), "视频号 id");
        assert_eq!(c.media_count, 7);
        assert_eq!(c.url.as_deref(), Some("http://wxapp.tc.qq.com/vid"));
        assert_eq!(c.title, None, "空 <title> → None");
    }

    #[test]
    fn parse_weapp() {
        let c = parse_appmsg(WEAPP).unwrap();
        assert_eq!(c.app_type, 33, "小程序 type 33");
        assert_eq!(c.title.as_deref(), Some("9.9元拼抢babycare纸尿裤"));
        assert_eq!(c.source_name.as_deref(), Some("优时通"), "小程序来源");
        assert_eq!(c.app_username.as_deref(), Some("gh_8fb1055af5ca@app"), "小程序 gh id");
        assert_eq!(
            c.app_pagepath.as_deref(),
            Some("misc-package/pages/groupbuy/index.html")
        );
        assert_eq!(c.media_count, 0, "非视频号 mediaCount 0");
    }

    #[test]
    fn parse_music_type92() {
        // 音乐分享 (type 92): title=歌名, des=歌手, url=页面。
        let c = parse_appmsg(r"<msg><appmsg><title>七里香</title><type>92</type><des>周杰伦</des><url>https://music.example/song</url></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 92);
        assert_eq!(c.title.as_deref(), Some("七里香"), "歌名=title");
        assert_eq!(c.music_desc.as_deref(), Some("周杰伦"), "歌手=des");
        assert_eq!(c.url.as_deref(), Some("https://music.example/song"));
    }

    #[test]
    fn parse_gift_type115() {
        // 微信礼物 (type 115): wishmessage=祝福语, skutitle=礼物名。
        let c = parse_appmsg(r"<msg><appmsg><type>115</type><wishmessage>祝你生日快乐</wishmessage><skutitle>快乐星球礼盒</skutitle></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 115);
        assert_eq!(c.gift_wish.as_deref(), Some("祝你生日快乐"), "祝福语");
        assert_eq!(c.gift_sku.as_deref(), Some("快乐星球礼盒"), "礼物名");
    }

    #[test]
    fn parse_finder_live_type63() {
        // 视频号直播 (type 63): finderLive 块 finderUsername/nickname/desc/liveStatus。
        let c = parse_appmsg(r"<msg><appmsg><type>63</type><finderLive><finderUsername>v2_live001</finderUsername><nickname>主播小王</nickname><desc>今晚8点开播</desc><liveStatus>2</liveStatus></finderLive></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 63);
        assert_eq!(
            c.app_username.as_deref(),
            Some("v2_live001"),
            "直播视频号 id 复用 app_username"
        );
        assert_eq!(c.app_nickname.as_deref(), Some("主播小王"), "主播复用 app_nickname");
        assert_eq!(c.live_desc.as_deref(), Some("今晚8点开播"), "直播标题");
        assert_eq!(c.live_status, 2, "直播状态");
        assert_eq!(c.media_count, 0, "直播非视频号动态 mediaCount 0");
    }

    #[test]
    fn parse_file() {
        // 文件 (type 6): title=文件名, appattach 里 totallen/fileext/md5。
        let c = parse_appmsg(r"<msg><appmsg><title>base.apk</title><type>6</type><appattach><totallen>19078200</totallen><fileext>apk</fileext><md5>4e9ecb5cf4fb25641451bbaaaaaaaaaa</md5></appattach></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 6);
        assert_eq!(c.title.as_deref(), Some("base.apk"), "文件名=title");
        assert_eq!(c.file_size, 19_078_200, "文件字节数");
        assert_eq!(c.file_ext.as_deref(), Some("apk"));
        assert_eq!(c.file_md5.as_deref(), Some("4e9ecb5cf4fb25641451bbaaaaaaaaaa"));
    }

    #[test]
    fn parse_transfer() {
        // 转账 (type 2000): wcpayinfo 里 feedesc(金额)/paysubtype(方向)/transcationid。
        let c = parse_appmsg(r"<msg><appmsg><title>微信转账</title><type>2000</type><wcpayinfo><paysubtype>3</paysubtype><feedesc><![CDATA[￥10.00]]></feedesc><transcationid><![CDATA[100050001abc]]></transcationid></wcpayinfo></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 2000);
        assert_eq!(c.transfer_fee.as_deref(), Some("￥10.00"), "金额");
        assert_eq!(c.transfer_direction, 3, "方向=paysubtype");
        assert_eq!(c.transfer_txid.as_deref(), Some("100050001abc"));
    }

    #[test]
    fn parse_hongbao() {
        // 红包 (type 2001): wcpayinfo 里 sendertitle(祝福语/留言); total_num 嵌 nativeurl query(非独立标签)。
        //  真库形态: sendertitle==receivertitle, total_num 在 nativeurl 末尾 &total_num=16。
        let c = parse_appmsg(r"<msg><appmsg><title>微信红包</title><type>2001</type><wcpayinfo><scenetext><![CDATA[微信红包]]></scenetext><receivertitle><![CDATA[恭喜发财大吉大利]]></receivertitle><sendertitle><![CDATA[恭喜发财大吉大利]]></sendertitle><nativeurl><![CDATA[wxpay://c2cbizmessagehandler/hongbao/receivehongbao?msgtype=1&channelid=1&sendid=1000039801&sendusername=wxid_x&ver=6&total_num=16]]></nativeurl><sceneid><![CDATA[1002]]></sceneid></wcpayinfo></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 2001);
        assert_eq!(
            c.red_envelope_wish.as_deref(),
            Some("恭喜发财大吉大利"),
            "红包祝福语=sendertitle"
        );
        assert_eq!(c.red_envelope_count, 16, "红包个数=nativeurl 的 total_num query");
        assert_eq!(
            c.pay_scene_text.as_deref(),
            Some("微信红包"),
            "ADR-495: 场景类别名=scenetext"
        );
        // K-R4: 祝福语(可含自定义信息如"代理扫码进群…")→ Debug sha8 不泄裸值; 个数明文。
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("恭喜发财大吉大利"), "K-R4: 红包祝福语 Debug 不泄裸值");
        assert!(dbg.contains("red_envelope_wish_sha8") && dbg.contains("red_envelope_count"));
        // 兜底: 只有 receivertitle (无 sendertitle) 也能抽到祝福语 (防边缘变体只填一个)。
        let r = parse_appmsg(r"<msg><appmsg><type>2001</type><wcpayinfo><receivertitle><![CDATA[新年快乐]]></receivertitle><nativeurl><![CDATA[wx://x?total_num=5]]></nativeurl></wcpayinfo></appmsg></msg>").unwrap();
        assert_eq!(
            r.red_envelope_wish.as_deref(),
            Some("新年快乐"),
            "sendertitle 缺 → 兜 receivertitle"
        );
        assert_eq!(r.red_envelope_count, 5);
        // 非红包类型 (转账 2000) red_envelope_* 保持默认 (按 app_type 精确分派, 不误填)。
        let x = parse_appmsg(r"<msg><appmsg><type>2000</type><wcpayinfo><feedesc><![CDATA[￥5.00]]></feedesc><nativeurl><![CDATA[wx://x?total_num=99]]></nativeurl></wcpayinfo></appmsg></msg>").unwrap();
        assert_eq!(x.red_envelope_wish, None, "转账不填红包祝福语");
        assert_eq!(
            x.red_envelope_count, 0,
            "转账不填红包个数 (2001 臂才抽, 不误取转账 nativeurl 的 total_num)"
        );
    }

    #[test]
    fn parse_group_pay() {
        // 群收款 (type 2001 **带 newaa**): senderdes 含 ¥金额; newaa/billno 单号 (ADR-487)。
        //  真库形态: 三个 list (payerlist/receiverlist/customize_payerlist) 恒空 → 只金额+单号可解。
        let c = parse_appmsg(r"<msg><appmsg><type>2001</type><wcpayinfo><senderdes><![CDATA[应付¥8.00]]></senderdes><receiverdes><![CDATA[待收款¥8.00]]></receiverdes><sceneid>1001</sceneid><newaa><billno><![CDATA[100600001aabbcc]]></billno><newaatype>2</newaatype><receiverlist>self,1,3,0</receiverlist><payerlist>wxid_a,2000,1|wxid_b,2000,0|jinabc,800,1</payerlist></newaa></wcpayinfo></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 2001);
        assert_eq!(c.group_pay_amount.as_deref(), Some("应付¥8.00"), "群收款金额=senderdes");
        assert_eq!(
            c.group_pay_bill_no.as_deref(),
            Some("100600001aabbcc"),
            "单号=newaa/billno"
        );
        // ⭐逐付款人 (ADR-488): payerlist `wxid,金额分,状态|...` → 3 条; 已付人数=len。
        assert_eq!(c.group_pay_members.len(), 3, "3 个付款人");
        assert_eq!(
            c.group_pay_members[0],
            ("wxid_a".to_string(), 2000, 1),
            "付款人1: wxid/金额分/状态"
        );
        assert_eq!(
            c.group_pay_members[1],
            ("wxid_b".to_string(), 2000, 0),
            "状态 0 (未付/边缘)"
        );
        assert_eq!(c.group_pay_members[2], ("jinabc".to_string(), 800, 1));
        // newaa 在场 → 走群收款臂, **不误填红包**。
        assert_eq!(c.red_envelope_wish, None, "群收款不填红包祝福语");
        assert_eq!(c.red_envelope_count, 0);
        // K-R4: 金额财务低熵 → Debug 只露有无; 单号高熵 → sha8; 付款人只露人数不露 wxid。
        let dbg = format!("{c:?}");
        assert!(
            !dbg.contains("8.00") && !dbg.contains("100600001"),
            "K-R4: 金额/单号 Debug 不泄裸值"
        );
        assert!(
            !dbg.contains("wxid_a") && !dbg.contains("jinabc"),
            "K-R4: 付款人 wxid Debug 不泄"
        );
        assert!(
            dbg.contains("group_pay_amount")
                && dbg.contains("group_pay_bill_no_sha8")
                && dbg.contains("group_pay_members_len: 3")
        );
        // senderdes 缺 → 兜 receiverdes。
        let r = parse_appmsg(r"<msg><appmsg><type>2001</type><wcpayinfo><receiverdes><![CDATA[待收款¥30.00]]></receiverdes><newaa><billno><![CDATA[bn2]]></billno></newaa></wcpayinfo></appmsg></msg>").unwrap();
        assert_eq!(
            r.group_pay_amount.as_deref(),
            Some("待收款¥30.00"),
            "senderdes 缺 → 兜 receiverdes"
        );
        // 红包 (2001 无 newaa) → 不误填群收款。
        let hb = parse_appmsg(r"<msg><appmsg><type>2001</type><wcpayinfo><sendertitle><![CDATA[恭喜发财]]></sendertitle><nativeurl><![CDATA[wx://x?total_num=5]]></nativeurl></wcpayinfo></appmsg></msg>").unwrap();
        assert_eq!(hb.group_pay_amount, None, "红包(无newaa)不填群收款金额");
        assert_eq!(hb.group_pay_bill_no, None);
        assert_eq!(hb.red_envelope_count, 5, "红包路径不受影响");
    }

    #[test]
    fn query_param_i64_extracts() {
        // total_num 在 query 末尾 / 中间 / 缺失 / 空值。
        assert_eq!(
            query_param_i64("wxpay://x?a=1&total_num=16", "total_num"),
            Some(16),
            "末尾"
        );
        assert_eq!(
            query_param_i64("wxpay://x?total_num=30&b=2", "total_num"),
            Some(30),
            "中间"
        );
        assert_eq!(query_param_i64("wxpay://x?a=1", "total_num"), None, "缺失→None");
        assert_eq!(query_param_i64("total_num=", "total_num"), None, "空值→None");
    }

    #[test]
    fn parse_quote() {
        // 引用 (type 57): refermsg 里 svrid(原消息id)/type/content(原文)。
        let c = parse_appmsg(r"<msg><appmsg><title>回复:好的</title><type>57</type><refermsg><type>1</type><svrid>7283910293847</svrid><content><![CDATA[原始被引消息文本]]></content></refermsg></appmsg></msg>").unwrap();
        assert_eq!(c.app_type, 57);
        assert_eq!(c.title.as_deref(), Some("回复:好的"), "回复文本=title");
        assert_eq!(c.refer_svrid.as_deref(), Some("7283910293847"), "被引消息 id");
        assert_eq!(c.refer_type, 1, "被引消息类型");
        assert_eq!(c.refer_content.as_deref(), Some("原始被引消息文本"), "被引原文");
    }

    #[test]
    fn parse_forward() {
        // 合并转发 (type 19): recorditem 里 <datalist count="N"> 转发条数。
        let c = parse_appmsg(r#"<msg><appmsg><title>群聊的聊天记录</title><type>19</type><recorditem><![CDATA[<recordinfo><datalist count="5"><dataitem/></datalist></recordinfo>]]></recorditem></appmsg></msg>"#).unwrap();
        assert_eq!(c.app_type, 19);
        assert_eq!(c.forward_item_count, 5, "转发 5 条");
    }

    #[test]
    fn k_r4_debug_redacts_typed_fields() {
        // K-R4: 文件 md5 / 转账金额+交易号 / 引用原文 敏感 → Debug sha8 不出裸值。
        let c = parse_appmsg(r"<msg><appmsg><title>t</title><type>2000</type><wcpayinfo><feedesc><![CDATA[￥888.88]]></feedesc><transcationid><![CDATA[SECRETTXID]]></transcationid></wcpayinfo></appmsg></msg>").unwrap();
        let dbg = format!("{c:?}");
        for raw in ["￥888.88", "SECRETTXID"] {
            assert!(!dbg.contains(raw), "K-R4: AppmsgCard Debug 泄裸值 {raw}");
        }
        // 金额低熵不 sha8 (可枚举反推), 只露有无 → [redacted]; 交易号高熵 sha8。
        assert!(dbg.contains("[redacted]"), "转账金额只露有无");
        assert!(dbg.contains("transfer_txid_sha8") && dbg.contains("transfer_direction"));
    }

    #[test]
    fn appattach_not_contaminating_non_file() {
        // ⚠️ 真库实测: 链接(5)/引用(57) 也带 <appattach>(缩略图) → 按 app_type 分派, file 字段只 type 6 才填。
        let link = parse_appmsg(r"<msg><appmsg><title>某链接</title><type>5</type><appattach><totallen>12345</totallen><md5>aaaa1111</md5></appattach></appmsg></msg>").unwrap();
        assert_eq!(link.app_type, 5);
        assert_eq!(link.file_size, 0, "链接的 appattach 缩略图不当文件大小");
        assert!(link.file_md5.is_none(), "链接不填 file_md5");
        // 引用带 appattach 同理: file 字段空, refer 字段正常。
        let quote = parse_appmsg(r"<msg><appmsg><title>回复</title><type>57</type><refermsg><svrid>9</svrid><type>3</type></refermsg><appattach><totallen>999</totallen></appattach></appmsg></msg>").unwrap();
        assert_eq!(quote.file_size, 0, "引用的 appattach 不当文件大小");
        assert_eq!(quote.refer_svrid.as_deref(), Some("9"), "引用字段正常填");
    }

    #[test]
    fn app_type_ignores_nested_type_in_refermsg() {
        // ⚠️ 竞品(WCDA)对拍逮到的真 bug: appmsg 的 <type>57 排在 refermsg 之后时, "第一个<type>" 会误取
        //  refermsg 里被引消息的 <type>(真库 14 例)。剥嵌套块后取 appmsg 自己的 type。
        let x = r"<msg><appmsg><title>引用回复</title><refermsg><type>3</type><svrid>9</svrid><content><![CDATA[原文]]></content></refermsg><type>57</type></appmsg></msg>";
        let c = parse_appmsg(x).unwrap();
        assert_eq!(c.app_type, 57, "取 appmsg 自己的 type 57 (非 refermsg 里的被引 type 3)");
        assert_eq!(c.refer_type, 3, "refermsg 里被引类型仍正确抽 3");
        assert_eq!(c.refer_svrid.as_deref(), Some("9"));
        assert_eq!(c.refer_content.as_deref(), Some("原文"));
        // recorditem 里的 <type> 同样不干扰 (合并转发 CDATA 内含被转发消息 type)。
        let f = parse_appmsg(r"<msg><appmsg><title>t</title><recorditem><![CDATA[<recordinfo><datalist count='2'><dataitem><type>1</type></dataitem></datalist></recordinfo>]]></recorditem><type>19</type></appmsg></msg>").unwrap();
        assert_eq!(f.app_type, 19, "取 appmsg 自己的 19 (非 recorditem 里的 1)");
    }

    #[test]
    fn non_appmsg_returns_none() {
        assert!(parse_appmsg("普通文本消息").is_none(), "裸文本无 appmsg → None");
        assert!(parse_appmsg("<msg><img /></msg>").is_none(), "图片消息无 appmsg → None");
        assert!(
            parse_appmsg("<msg><appmsg></appmsg></msg>").is_none(),
            "无 <type> → None"
        );
    }

    /// 边界: CDATA 内含特殊字符 (url query & / 中文) 完整抽; 空 title 跳过; 多 url 取第一个 (主)。
    /// (codex 批C P2: 本解析器是标签扫描器非真 XML parser; 属性含 `>` / CDATA 含 `</tag>` 是已知局限,
    ///  但卡片字段实测不出现 → 只锁常见形态。)
    #[test]
    fn cdata_special_chars_and_first_url() {
        let xml = "<msg><appmsg><type>5</type><title><![CDATA[标题&特殊<符>]]></title><url><![CDATA[https://a.com/x?p=1&q=2]]></url><lowurl><![CDATA[https://low]]></lowurl></appmsg></msg>";
        let c = parse_appmsg(xml).unwrap();
        assert_eq!(c.app_type, 5);
        assert_eq!(c.title.as_deref(), Some("标题&特殊<符>"), "CDATA 含 & < > 完整抽");
        assert_eq!(
            c.url.as_deref(),
            Some("https://a.com/x?p=1&q=2"),
            "url query & 完整; 取第一个非 lowurl"
        );
    }

    #[test]
    fn k_r4_debug_redacts() {
        let dbg = format!("{:?}", parse_appmsg(WEAPP).unwrap());
        for raw in ["babycare", "优时通", "gh_8fb1055af5ca"] {
            assert!(!dbg.contains(raw), "K-R4: AppmsgCard Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("title_sha8"));
    }
}
