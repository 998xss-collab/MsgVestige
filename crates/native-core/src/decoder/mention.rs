//! decoder::mention — 从群消息 `source` 列 (msgsource XML) 抽 @提及名单 (atuserlist)。
//!
//! 群消息的 `source` 列 (与 message_content 同为 zstd 压缩, decoder 已解压) 是
//! `<msgsource><atuserlist><![CDATA[wxid_a,wxid_b]]></atuserlist>...</msgsource>` XML。本 mod 把 atuserlist
//! 的逗号分隔 wxid 抽成 [`Mention`] 列表 → 派生 L2 表 message_mention (ADR-457)。**纯字符串抽取, infallible**
//! (无 atuserlist / 空 → 空 Vec)。
//!
//! ## 格式 (真库实测)
//! - 单个: `<atuserlist><![CDATA[queen2799]]></atuserlist>`;
//! - 多个 (含前导逗号): `<atuserlist><![CDATA[,wxid_a,wxid_b]]></atuserlist>`;
//! - @所有人: `<atuserlist><![CDATA[,notify@all]]></atuserlist>` → [`Mention::is_at_all`]。
//!
//! ## K-R4
//! - atuserlist 里是**被 @ 的 wxid** (id 类) → [`Mention`] 手写 Debug 走 [`sha8`] 脱敏。
//! - 本 mod 派生自 source 列 (不进 message content_digest — source 非 message 身份字段); message_mention 表
//!   **L2-only**。

use std::fmt;

use crate::key_provider::sha8;

/// @所有人 的 atuserlist 哨兵值 (微信固定串)。
pub const NOTIFY_ALL: &str = "notify@all";

/// 一条 @提及 (被 @ 的一个对象)。
#[derive(Clone, PartialEq, Eq)]
pub struct Mention {
    /// 被 @ 的 wxid (或 `notify@all` 哨兵)。
    pub wxid: String,
    /// 是否 @所有人 (wxid == `notify@all`)。
    pub is_at_all: bool,
}

/// 抽 `<atuserlist>...</atuserlist>` 内层文本 (剥 CDATA + trim; 无则 None)。
fn extract_atuserlist(source: &str) -> Option<&str> {
    let start = source.find("<atuserlist")?;
    // 开标签结束 '>' (容忍属性/自闭)。
    let after_open = source[start..].find('>')? + start + 1;
    // 自闭 `<atuserlist/>` → 无内容。
    if source[..after_open].ends_with("/>") {
        return None;
    }
    let rest = &source[after_open..];
    let end = rest.find("</atuserlist>")?;
    Some(rest[..end].trim())
}

/// 从消息 `source` (msgsource XML) 抽 @提及名单。无 atuserlist / 空 → 空 Vec。**infallible**。
/// 逗号分隔, 去空 + 去重 (同 wxid @ 两次算一次)。
#[must_use]
pub fn parse_mentions(source: &str) -> Vec<Mention> {
    let Some(inner) = extract_atuserlist(source) else {
        return Vec::new();
    };
    // 剥 CDATA (`<![CDATA[...]]>` → 内部)。
    let list = inner
        .strip_prefix("<![CDATA[")
        .and_then(|s| s.strip_suffix("]]>"))
        .unwrap_or(inner)
        .trim();
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for tok in list.split(',') {
        let w = tok.trim();
        if w.is_empty() || seen.contains(&w) {
            continue;
        }
        seen.push(w);
        out.push(Mention {
            wxid: w.to_string(),
            is_at_all: w == NOTIFY_ALL,
        });
    }
    out
}

/// K-R4: wxid 是 id 类 → sha8 脱敏; is_at_all 明文。
impl fmt::Debug for Mention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mention")
            .field("wxid_sha8", &sha8(self.wxid.as_bytes()))
            .field("is_at_all", &self.is_at_all)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_mention() {
        let src = "<msgsource><atuserlist><![CDATA[queen2799]]></atuserlist><silence>1</silence></msgsource>";
        let m = parse_mentions(src);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].wxid, "queen2799");
        assert!(!m[0].is_at_all);
    }

    #[test]
    fn multiple_with_leading_comma() {
        let src = "<msgsource><atuserlist><![CDATA[,wxid_a,wxid_b]]></atuserlist></msgsource>";
        let m = parse_mentions(src);
        assert_eq!(m.len(), 2, "前导逗号产生的空 token 被去掉");
        assert_eq!(m[0].wxid, "wxid_a");
        assert_eq!(m[1].wxid, "wxid_b");
    }

    #[test]
    fn notify_all() {
        let src = "<msgsource><atuserlist><![CDATA[,notify@all]]></atuserlist></msgsource>";
        let m = parse_mentions(src);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].wxid, "notify@all");
        assert!(m[0].is_at_all, "@所有人");
    }

    #[test]
    fn dedup_same_wxid() {
        let src = "<atuserlist><![CDATA[wxid_x,wxid_x,wxid_y]]></atuserlist>";
        let m = parse_mentions(src);
        assert_eq!(m.len(), 2, "同 wxid @ 两次算一次");
    }

    #[test]
    fn no_atuserlist_empty() {
        assert!(parse_mentions("<msgsource><silence>1</silence></msgsource>").is_empty());
        assert!(parse_mentions("普通消息无 source").is_empty());
        assert!(parse_mentions("").is_empty());
        // 空 atuserlist。
        assert!(parse_mentions("<atuserlist><![CDATA[]]></atuserlist>").is_empty());
        assert!(parse_mentions("<atuserlist></atuserlist>").is_empty());
    }

    #[test]
    fn atuserlist_no_cdata() {
        // 有些不带 CDATA (直接文本)。
        let m = parse_mentions("<atuserlist>wxid_z</atuserlist>");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].wxid, "wxid_z");
    }

    #[test]
    fn k_r4_debug_redacts() {
        let m = parse_mentions("<atuserlist><![CDATA[wxid_secret123]]></atuserlist>");
        let dbg = format!("{:?}", m[0]);
        assert!(!dbg.contains("wxid_secret123"), "K-R4: Mention Debug 泄裸 wxid");
        assert!(dbg.contains("wxid_sha8"));
    }
}
