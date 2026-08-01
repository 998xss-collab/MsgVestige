//! roomdata — 解析微信 `contact.db` 的 `chat_room.ext_buffer`
//! (= 微信 ChatRoomData.members protobuf, 群**全员**名单)。
//!
//! 移植自 `wx-cli` daemon/query.rs (对真实微信 4.x ext_buffer 实证 + 启发式; 无 prost 依赖)。
//! ext_buffer = top-level **repeated length-delimited submessage**, 每 submessage = 一个成员:
//!
//! - field 1 = 成员 username (微信号, 必有)
//! - field 2 = 群昵称 / 群名片 (可空)
//! - field 3 = 状态位 flags (varint; `& 2048` = 群管理员, WDA 方案 3 群真值校准 + 本仓真库验证)
//! - field 4 = 邀请人 wxid (谁拉此成员进群; **不当群昵称、不优先当成员**; 第九批提取进 `RoomMember.invited_by`)
//!
//! 字段布局不完全规整 → 用 `looks_like_username` 等启发式挑, 防把 field4 邀请人误当成员。
//!
//! K-R4: 解出的 username / 群昵称是明文 PII, `RoomMember` 手写 Debug 脱敏 (sha8 / char_len)。

use std::collections::HashSet;
use std::fmt;

use crate::key_provider::sha8;

/// 群管理员状态位 — 成员 `field 3` flags & 此位 != 0 = 管理员 (WDA 方案, 3 群真值校准 + 本仓真库验证确认)。
/// 群主**不一定带此位**, 群主看 `chat_room.owner` 列。
const ADMIN_BIT: u64 = 2048;

/// 一个群成员 (解析中间产物, 持明文; 出口 Debug 脱敏)。
#[derive(Clone, PartialEq, Eq)]
pub struct RoomMember {
    pub username: String,
    pub group_nick: Option<String>,
    /// 群管理员 (成员 `field 3` 状态位 flags & [`ADMIN_BIT`] != 0)。群主见 `chat_room.owner`, 不看此位。
    pub is_admin: bool,
    /// 邀请人 wxid (成员 `field 4`; 谁把此成员拉进群; 可空 — field4 被当 username fallback 时无独立邀请人)。
    pub invited_by: Option<String>,
}

impl fmt::Debug for RoomMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoomMember")
            .field("username_sha8", &sha8(self.username.as_bytes()))
            .field(
                "group_nick_len",
                &self.group_nick.as_ref().map_or(0, |s| s.chars().count()),
            )
            .field("is_admin", &self.is_admin)
            .field(
                "invited_by_sha8",
                &self.invited_by.as_deref().map(|s| sha8(s.as_bytes())),
            )
            .finish()
    }
}

/// `parse_roomdata` 三态 (codex 设计审 P0: "部分解析成功"比"彻底失败"更危险 ——
/// `S_now` 不全会把仍在群的人误判退群 → 调用方据此 fail-closed)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomDataParse {
    /// 干净解析到 blob 末尾, ≥1 个合法成员 → 可放心做退群 diff。
    Complete(Vec<RoomMember>),
    /// 空 blob / 顶层结构坏 / 解不出任何成员 → 整群标坏, 不发任何成员事件。
    Invalid,
    /// 解出部分成员但有截断迹象 (顶层遍历未达 blob 末尾) →
    /// 调用方可 add 这些成员 (幂等无害), 但 **不可据此发退群** (名单可能不全)。
    Suspicious(Vec<RoomMember>),
}

/// 解析 ext_buffer → 群成员三态。
pub fn parse_roomdata(ext_buffer: &[u8]) -> RoomDataParse {
    if ext_buffer.is_empty() {
        return RoomDataParse::Invalid;
    }
    let (chunks, clean_eof) = proto_len_fields(ext_buffer);
    let mut members = Vec::new();
    let mut seen = HashSet::new();
    for (_, chunk) in &chunks {
        let strings = proto_string_fields(chunk);
        if strings.is_empty() {
            continue;
        }
        let Some(username) = pick_member_username(&strings) else {
            continue;
        };
        if !seen.insert(username.clone()) {
            continue; // 同一成员重复 chunk 去重
        }
        let group_nick = pick_group_nickname(&strings, &username);
        // 成员 field 3 = 状态位 flags; `& ADMIN_BIT` = 群管理员 (缺/坏 → 非管理员)。
        let is_admin = proto_first_varint(chunk, 3).is_some_and(|f| f & ADMIN_BIT != 0);
        // 成员 field 4 = 邀请人 wxid; 排除 field4 被当 username 的 fallback 情形 (== username 则无独立邀请人)。
        let invited_by = strings
            .iter()
            .find(|(f, _)| *f == 4)
            .map(|(_, v)| v.clone())
            .filter(|v| v != &username);
        members.push(RoomMember {
            username,
            group_nick,
            is_admin,
            invited_by,
        });
    }
    if members.is_empty() {
        return RoomDataParse::Invalid;
    }
    if clean_eof {
        RoomDataParse::Complete(members)
    } else {
        RoomDataParse::Suspicious(members)
    }
}

// ── 手写 protobuf 解析 (移植 wx-cli; 纯 varint + length-delimited, 无依赖) ──

/// varint 解码 → (value, next_offset)。坏 / 溢出 → None。
fn decode_varint(raw: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut pos = offset;
    while pos < raw.len() {
        let byte = raw[pos];
        pos += 1;
        let part = u64::from(byte & 0x7f);
        // 溢出保护 (codex 双审 P1): 第 10 字节 (shift==63) 只能贡献 1 bit; 更高位 = u64 溢出 → None (防坏 flags 误判 admin)。
        if shift == 63 && part > 1 {
            return None;
        }
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// 提取所有 length-delimited (wire type 2) field → (field_no, bytes)。
/// 返回 `(fields, clean_eof)`: `clean_eof` = 是否干净遍历到 raw 末尾
/// (false = 中途遇坏字节 break = **截断迹象**, 供三态判定)。
fn proto_len_fields(raw: &[u8]) -> (Vec<(u64, &[u8])>, bool) {
    let mut fields = Vec::new();
    let mut idx = 0usize;
    let clean_eof = loop {
        if idx == raw.len() {
            break true;
        }
        let Some((tag, next)) = decode_varint(raw, idx) else {
            break false;
        };
        if next <= idx {
            break false;
        }
        idx = next;
        let field_no = tag >> 3;
        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                let Some((_, next)) = decode_varint(raw, idx) else {
                    break false;
                };
                if next <= idx {
                    break false;
                }
                idx = next;
            }
            1 => {
                let Some(next) = idx.checked_add(8) else {
                    break false;
                };
                if next > raw.len() {
                    break false;
                }
                idx = next;
            }
            2 => {
                let Some((size, next)) = decode_varint(raw, idx) else {
                    break false;
                };
                if next <= idx {
                    break false;
                }
                idx = next;
                let Ok(size) = usize::try_from(size) else {
                    break false;
                };
                let Some(end) = idx.checked_add(size) else {
                    break false;
                };
                if end > raw.len() {
                    break false;
                }
                fields.push((field_no, &raw[idx..end]));
                idx = end;
            }
            5 => {
                let Some(next) = idx.checked_add(4) else {
                    break false;
                };
                if next > raw.len() {
                    break false;
                }
                idx = next;
            }
            _ => break false,
        }
    };
    (fields, clean_eof)
}

/// 取 chunk 内所有合法 UTF-8 string field → (field_no, text)。
fn proto_string_fields(raw: &[u8]) -> Vec<(u64, String)> {
    let (fields, _) = proto_len_fields(raw);
    fields
        .into_iter()
        .filter_map(|(field_no, value)| {
            if value.is_empty() || value.len() > 256 {
                return None;
            }
            let text = std::str::from_utf8(value).ok()?.trim().to_string();
            if text.is_empty() || text.chars().any(char::is_control) {
                return None;
            }
            Some((field_no, text))
        })
        .collect()
}

/// 扫 chunk 取指定 `target` field_no 的**首个** varint (wire type 0) — 群成员 `field 3` = 状态位 flags。
/// 手写解析 (同 [`proto_len_fields`] 边界规则, 跳过其它 wire type); 坏/缺/越界 → None (调用方降级默认非管理员)。
fn proto_first_varint(raw: &[u8], target: u64) -> Option<u64> {
    let mut idx = 0usize;
    while idx < raw.len() {
        let (tag, next) = decode_varint(raw, idx)?;
        if next <= idx {
            return None;
        }
        idx = next;
        let field_no = tag >> 3;
        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                let (v, next) = decode_varint(raw, idx)?;
                if next <= idx {
                    return None;
                }
                idx = next;
                if field_no == target {
                    return Some(v);
                }
            }
            1 => {
                idx = idx.checked_add(8)?;
                if idx > raw.len() {
                    return None;
                }
            }
            2 => {
                let (size, next) = decode_varint(raw, idx)?;
                idx = next;
                let size = usize::try_from(size).ok()?;
                idx = idx.checked_add(size)?;
                if idx > raw.len() {
                    return None;
                }
            }
            5 => {
                idx = idx.checked_add(4)?;
                if idx > raw.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

fn is_strong_username_hint(value: &str) -> bool {
    value.starts_with("wxid_") || value.ends_with("@chatroom") || value.starts_with("gh_") || value.contains('@')
}

fn looks_like_username(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if is_strong_username_hint(value) {
        return true;
    }
    if value.len() < 6 || value.len() > 32 || value.chars().any(char::is_whitespace) {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// 挑成员 username: field 1 优先 → field 4 次 → 启发式兜底。
fn pick_member_username(strings: &[(u64, String)]) -> Option<String> {
    for field_no in [1u64, 4u64] {
        if let Some((_, value)) = strings
            .iter()
            .find(|(f, value)| *f == field_no && looks_like_username(value))
        {
            return Some(value.clone());
        }
    }
    strings
        .iter()
        .find(|(_, value)| is_strong_username_hint(value))
        .or_else(|| strings.iter().find(|(_, value)| looks_like_username(value)))
        .map(|(_, value)| value.clone())
}

/// 挑群昵称: field 2 (群名片); 排除 = username / 像 username / 含换行 / 过长。
fn pick_group_nickname(strings: &[(u64, String)], username: &str) -> Option<String> {
    let mut best_score = i64::MIN;
    let mut best = String::new();
    for (idx, (field_no, value)) in strings.iter().enumerate() {
        if *field_no != 2 {
            continue;
        }
        let value = value.trim();
        if value.is_empty()
            || value == username
            || is_strong_username_hint(value)
            || value.contains('\n')
            || value.contains('\r')
            || value.len() > 64
        {
            continue;
        }
        let mut score = 0i64;
        if !looks_like_username(value) {
            score += 20;
        }
        score += (32usize.saturating_sub(value.len())) as i64;
        score = score * 1000 - idx as i64;
        if score > best_score {
            best_score = score;
            best = value.to_string();
        }
    }
    if best.is_empty() {
        None
    } else {
        Some(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── protobuf 编码 test helper ──
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
        out
    }

    /// length-delimited field (wire type 2): tag + len + bytes。
    fn len_field(field_no: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = varint((field_no << 3) | 2);
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn str_field(field_no: u64, s: &str) -> Vec<u8> {
        len_field(field_no, s.as_bytes())
    }

    /// varint field (wire type 0): tag + varint value (群成员 field 3 状态位 flags 用)。
    fn vfield(field_no: u64, v: u64) -> Vec<u8> {
        let mut out = varint(field_no << 3);
        out.extend(varint(v));
        out
    }

    /// 一个成员 submessage 包成 top-level chunk (top field_no 任意, 取 1)。
    fn member(inner_fields: &[(u64, &str)]) -> Vec<u8> {
        let mut inner = Vec::new();
        for (no, val) in inner_fields {
            inner.extend(str_field(*no, val));
        }
        len_field(1, &inner)
    }

    #[test]
    fn complete_two_members_field1_username_field2_nick() {
        let mut ext = Vec::new();
        ext.extend(member(&[(1, "wxid_alice"), (2, "群里的甲")]));
        ext.extend(member(&[(1, "wxid_bob")])); // 无群昵称
        match parse_roomdata(&ext) {
            RoomDataParse::Complete(m) => {
                assert_eq!(m.len(), 2);
                assert_eq!(m[0].username, "wxid_alice");
                assert_eq!(m[0].group_nick.as_deref(), Some("群里的甲"));
                assert_eq!(m[1].username, "wxid_bob");
                assert_eq!(m[1].group_nick, None);
            }
            other => panic!("期望 Complete, 得 {other:?}"),
        }
    }

    #[test]
    fn field4_inviter_not_taken_as_username_or_nick() {
        // field1=真成员, field2=群昵称, field4=邀请人(像 username) → 不影响。
        let ext = member(&[(1, "wxid_carol"), (2, "卡萝"), (4, "wxid_inviter")]);
        match parse_roomdata(&ext) {
            RoomDataParse::Complete(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].username, "wxid_carol", "field1 优先, 不取 field4");
                assert_eq!(m[0].group_nick.as_deref(), Some("卡萝"), "field4 不被当群昵称");
                assert_eq!(
                    m[0].invited_by.as_deref(),
                    Some("wxid_inviter"),
                    "field4 = 邀请人提取 (第九批)"
                );
            }
            other => panic!("期望 Complete, 得 {other:?}"),
        }
    }

    /// WDA 方案: 成员 field 3 = 状态位 flags, bit 2048 = 群管理员; 无/低位 = 非管理员。
    #[test]
    fn field3_flags_bit2048_marks_admin() {
        // A: field1 + field3=2049 (0x801 含 bit2048) → admin; B: field3=1 → 非; C: 无 field3 → 非。
        let mut a = str_field(1, "wxid_admin");
        a.extend(vfield(3, 2049));
        let mut b = str_field(1, "wxid_normal");
        b.extend(vfield(3, 1));
        let c = str_field(1, "wxid_nof3");
        let mut ext = len_field(1, &a);
        ext.extend(len_field(1, &b));
        ext.extend(len_field(1, &c));
        match parse_roomdata(&ext) {
            RoomDataParse::Complete(m) => {
                assert_eq!(m.len(), 3);
                assert!(m[0].is_admin, "field3 含 2048 → 管理员");
                assert!(!m[1].is_admin, "field3=1 无 2048 → 非管理员");
                assert!(!m[2].is_admin, "无 field3 → 非管理员");
            }
            other => panic!("期望 Complete, 得 {other:?}"),
        }
    }

    /// codex P1: field3 超长 varint (第 10 字节高位溢出) → decode None → 非管理员 (不 panic, 不误判)。
    #[test]
    fn field3_overflow_varint_not_admin() {
        // 成员内层: field1=wxid + field3 tag(0x18) + 9×0xff + 0x7f (第 10 字节 0x7f>1 触发溢出保护 → None)。
        let mut inner = str_field(1, "wxid_x");
        inner.push(0x18); // (3<<3)|0 = field3 wire0
        inner.extend(std::iter::repeat(0xff).take(9));
        inner.push(0x7f);
        let ext = len_field(1, &inner);
        match parse_roomdata(&ext) {
            RoomDataParse::Complete(m) => {
                assert_eq!(m.len(), 1, "username(field1)在前已取, 成员仍在");
                assert!(!m[0].is_admin, "溢出 field3 → decode None → 非管理员");
            }
            other => panic!("期望 Complete, 得 {other:?}"),
        }
    }

    #[test]
    fn suspicious_when_trailing_garbage() {
        // 一个干净成员 + 尾部坏字节(顶层遍历到不完整 varint break) → Suspicious。
        let mut ext = member(&[(1, "wxid_dave"), (2, "戴夫")]);
        ext.push(0xff); // 残留: 0xff 是未完成 varint (高位为 1 但后面没字节) → break 非干净 eof
        match parse_roomdata(&ext) {
            RoomDataParse::Suspicious(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].username, "wxid_dave");
            }
            other => panic!("期望 Suspicious, 得 {other:?}"),
        }
    }

    #[test]
    fn invalid_empty() {
        assert_eq!(parse_roomdata(&[]), RoomDataParse::Invalid);
    }

    #[test]
    fn invalid_garbage_no_member() {
        // 顶层是 length-delimited 但内容解不出任何合法 username → Invalid。
        let ext = member(&[(2, "只有昵称没微信号")]);
        assert_eq!(parse_roomdata(&ext), RoomDataParse::Invalid);
    }

    #[test]
    fn dedup_same_username_twice() {
        let mut ext = Vec::new();
        ext.extend(member(&[(1, "wxid_eve"), (2, "夏娃")]));
        ext.extend(member(&[(1, "wxid_eve"), (2, "夏娃二")])); // 重复 username
        match parse_roomdata(&ext) {
            RoomDataParse::Complete(m) => {
                assert_eq!(m.len(), 1, "同 username 去重保首条");
                assert_eq!(m[0].group_nick.as_deref(), Some("夏娃"));
            }
            other => panic!("期望 Complete, 得 {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_pii() {
        let m = RoomMember {
            username: "wxid_secret".into(),
            group_nick: Some("机密昵称".into()),
            is_admin: false,
            invited_by: Some("wxid_inviter_secret".into()),
        };
        let dbg = format!("{m:?}");
        assert!(!dbg.contains("wxid_secret"), "K-R4: Debug 不露 username");
        assert!(!dbg.contains("机密昵称"), "K-R4: Debug 不露群昵称");
        assert!(!dbg.contains("wxid_inviter_secret"), "K-R4: Debug 不露邀请人 wxid");
        assert!(dbg.contains("group_nick_len"));
        assert!(dbg.contains("invited_by_sha8"));
    }
}
