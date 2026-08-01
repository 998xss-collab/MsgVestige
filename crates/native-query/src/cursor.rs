//! 不透明游标 (内核 §6): `base64url(版本 | account_sha8 | filter指纹 | 排序键…)`。
//!
//! 消费者**原样回传**、不解析;解码时校验 **版本 / account / filter 不符 → 视为失效**
//! (调用方转 `INVALID_CURSOR`,§13),把"失效可检测"落到实处。
//!
//! `排序键` = 上一页**末行的稳定排序列值**(keyset 续翻用;每资源的排序列见内核 §6 / doc③ §keyset:
//! messages=sort_seq+create_time+local_id · sessions=last_active+conv_id · contacts=wxid …)。
//! 游标绑 **account+filter 组合、不跨版本** —— 换账号/换过滤/换 API 版本的旧游标一律失效。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// 游标格式版本。改结构即 bump → 老游标解码版本校验不过 → `INVALID_CURSOR`。
const CURSOR_VERSION: &str = "1";
/// 字段分隔符 (US 控制符, 不出现在 sha8 / wxid / 时间戳 / id 等排序值里)。
const SEP: char = '\u{1f}';

/// 解出的游标:上一页末行的排序键值。调用方据此建 keyset `WHERE (sortcol…) < (值…)`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub sort_values: Vec<String>,
}

/// 编码为不透明串。`account_sha8` 当前账号指纹、`filter_hash` 本次查询过滤指纹(绑定用)。
#[must_use]
// ⚠️ rustc 1.96 的 ICE 绕行(不是嫌 lint 烦): clippy 给本函数出 pedantic 警告时
// **rustc 自己崩**(rustc_span:2439 断言, 崩在渲染阶段 → 一条警告都打不出来)。
// 1.83 不崩、1.96 与 nightly 都崩 ⇒ 编译器 bug, 升降版本都躲不掉。逐层二分定位到本函数。
// 同 native-core::mediastore::engine::open_work_item, 详见那里的完整排查记录。
#[allow(clippy::pedantic)]
pub fn encode(account_sha8: &str, filter_hash: &str, sort_values: &[String]) -> String {
    let mut parts = Vec::with_capacity(3 + sort_values.len());
    parts.push(CURSOR_VERSION.to_string());
    parts.push(account_sha8.to_string());
    parts.push(filter_hash.to_string());
    parts.extend(sort_values.iter().cloned());
    URL_SAFE_NO_PAD.encode(parts.join(&SEP.to_string()))
}

/// 解码 + 校验。**版本 / account / filter 不符,或 base64/utf8/结构坏 → `None`**(调用方转 `INVALID_CURSOR`)。
#[must_use]
pub fn decode(s: &str, account_sha8: &str, filter_hash: &str) -> Option<Cursor> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let parts: Vec<&str> = text.split(SEP).collect();
    if parts.len() < 3 {
        return None; // 结构坏 (至少要 版本+account+filter)
    }
    if parts[0] != CURSOR_VERSION || parts[1] != account_sha8 || parts[2] != filter_hash {
        return None; // 版本 / account / filter 不符 → 失效
    }
    Some(Cursor {
        sort_values: parts[3..].iter().map(|s| (*s).to_string()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_sort_values() {
        let vals = vec!["1720000000".to_string(), "wxid_abc".to_string()];
        let enc = encode("acc8", "filt9", &vals);
        let dec = decode(&enc, "acc8", "filt9").expect("同 account+filter 应解得开");
        assert_eq!(dec.sort_values, vals);
    }

    #[test]
    fn empty_sort_values_roundtrips() {
        let enc = encode("acc8", "filt9", &[]);
        assert_eq!(decode(&enc, "acc8", "filt9").unwrap().sort_values, Vec::<String>::new());
    }

    #[test]
    fn wrong_account_or_filter_is_invalid() {
        let enc = encode("acc8", "filt9", &["v".to_string()]);
        assert!(
            decode(&enc, "OTHER_ACC", "filt9").is_none(),
            "account 不符 → INVALID_CURSOR"
        );
        assert!(
            decode(&enc, "acc8", "OTHER_FILT").is_none(),
            "filter 不符 → INVALID_CURSOR"
        );
    }

    #[test]
    fn tampered_or_garbage_is_invalid() {
        let enc = encode("acc8", "filt9", &["v".to_string()]);
        // 改首字符 → 破坏 版本/account 段 → 校验不过 (首字节=版本 '1')。
        let mut chars: Vec<char> = enc.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(
            decode(&tampered, "acc8", "filt9").is_none(),
            "改首字符 → INVALID_CURSOR"
        );
        // 非 base64 垃圾串。
        assert!(
            decode("!!!not-base64!!!", "acc8", "filt9").is_none(),
            "垃圾 → INVALID_CURSOR"
        );
    }

    #[test]
    fn old_version_is_invalid() {
        // 手造版本 "0" 的串 → 版本校验不过 (跨版本失效)。
        let old = URL_SAFE_NO_PAD.encode(format!("0{SEP}acc8{SEP}filt9{SEP}v"));
        assert!(decode(&old, "acc8", "filt9").is_none(), "旧版本游标 → INVALID_CURSOR");
    }
}
