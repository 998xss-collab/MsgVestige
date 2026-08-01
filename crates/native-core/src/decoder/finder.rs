//! finder row 组装 — 明文 `wcfinderuserpage` 行 → [`FinderVisitCreate`] 事件 (视频号号主一条)。
//!
//! [`assemble_finder`] 把一条 `wcfinderuserpage` 行 (username + extra_buffer proto) 映射成 [`FinderVisitCreate`]。
//! **解 extra_buffer proto** (纯字节扫描, infallible): f2=昵称(str) / f5=访问时刻(varint) / f6=主页URL(str)。
//! 缺字段 → 空串 / 0。event_seq 留 0。仿 [`super::friend_verify`] (ADR-473, 视频号新域)。
//!
//! ## 真实 schema (general.db `wcfinderuserpage`, 消费列; 2026-07-06 inspect 坐实)
//! username (视频号**号主** wxid/微信号 = 锚点 + 身份; **非**频道 id) / extra_buffer (proto: f2 视频号昵称 /
//! f5 访问时刻秒 / f6 主页 URL, URL 里 `?username=v2_..@finder` 才是频道 id)。

use crate::event::finder::FinderVisitCreate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 明文 `wcfinderuserpage` 行 (drain 原始行; `extra_buffer` proto 未解, assemble 解)。
pub struct FinderRow {
    /// wcfinderuserpage rowid (本轮分页游标; 非业务 id)。
    pub rowid: i64,
    /// 视频号号主 id (username = wxid/微信号; 锚点 + 身份)。
    pub owner_username: String,
    /// 视频号信息 proto (extra_buffer; assemble 解 f2/f5/f6)。
    pub extra_buffer: Vec<u8>,
}

/// 装配上下文 — 调用方 (pipeline) 按 db 预备。
pub struct FinderContext {
    /// 数据所属账号 UserName。
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"general.db"`)。
    pub source: String,
    /// 锚点 (调用方预合成 `"Finder_<md5_hex(owner_username)>"`; → `provenance.source_native_id`)。
    pub source_native_id: String,
    /// 摄取时刻 (毫秒)。
    pub ingest_time: i64,
}

/// 读一个 protobuf varint (返 (值, 新 offset); 越界 → None)。
fn read_varint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let (mut v, mut s) = (0u64, 0u32);
    loop {
        let byte = *b.get(i)?;
        i += 1;
        v |= u64::from(byte & 0x7f) << s;
        if byte & 0x80 == 0 {
            return Some((v, i));
        }
        s += 7;
        if s >= 64 {
            return None; // 畸形 varint
        }
    }
}

/// 从 extra_buffer proto 取指定 field: 返 (str_field, varint_field)。**纯字节扫描, infallible** (畸形 → 停)。
/// 只取顶层字段 (wire type 2 len-delimited → bytes / 0 varint → int); 其它 wire type 跳过。
fn parse_finder_proto(buf: &[u8]) -> (Option<String>, Option<i64>, Option<String>) {
    let (mut name, mut visit_time, mut url) = (None, None, None);
    let mut i = 0;
    while i < buf.len() {
        let Some((tag, next)) = read_varint(buf, i) else { break };
        i = next;
        let field_no = tag >> 3;
        let wire = tag & 7;
        match wire {
            0 => {
                // varint
                let Some((v, next)) = read_varint(buf, i) else { break };
                i = next;
                if field_no == 5 {
                    visit_time = Some(v as i64);
                }
            }
            2 => {
                // len-delimited (string/bytes)
                let Some((len, next)) = read_varint(buf, i) else { break };
                i = next;
                let end = i.checked_add(len as usize).filter(|&e| e <= buf.len());
                let Some(end) = end else { break };
                let slice = &buf[i..end];
                i = end;
                if field_no == 2 || field_no == 6 {
                    if let Ok(s) = std::str::from_utf8(slice) {
                        let s = s.trim();
                        if !s.is_empty() {
                            if field_no == 2 {
                                name = Some(s.to_string());
                            } else {
                                url = Some(s.to_string());
                            }
                        }
                    }
                }
            }
            5 => i = i.saturating_add(4), // fixed32
            1 => i = i.saturating_add(8), // fixed64
            _ => break,                   // 未知 wire type → 停
        }
    }
    (name, visit_time, url)
}

/// 组装一条 [`FinderRow`] + [`FinderContext`] → [`FinderVisitCreate`] (event_seq 留 0, 后置填)。
///
/// 解 extra_buffer proto (f2 昵称 / f5 访问时刻 / f6 URL; 缺 → 空串/0)。`rowid` 是游标不进事件。**infallible**。
#[must_use]
pub fn assemble_finder(row: &FinderRow, ctx: &FinderContext) -> FinderVisitCreate {
    let (name, visit_time, url) = parse_finder_proto(&row.extra_buffer);
    FinderVisitCreate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::FinderVisitUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        owner_username: row.owner_username.clone(),
        name: name.unwrap_or_default(),
        visit_time: visit_time.unwrap_or(0),
        profile_url: url.unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一个 proto: f2(str)=昵称 / f5(varint)=时刻 / f6(str)=url。
    fn proto(name: &str, ts: u64, url: &str) -> Vec<u8> {
        let mut b = Vec::new();
        let put_str = |b: &mut Vec<u8>, fno: u8, s: &str| {
            b.push((fno << 3) | 2);
            b.push(s.len() as u8);
            b.extend_from_slice(s.as_bytes());
        };
        put_str(&mut b, 2, name);
        b.push(5 << 3); // f5 varint (wire type 0)
        let mut v = ts;
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            b.push(byte);
            if v == 0 {
                break;
            }
        }
        put_str(&mut b, 6, url);
        b
    }

    fn ctx() -> FinderContext {
        FinderContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "general.db".to_string(),
            source_native_id: "Finder_abcd1234".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    #[test]
    fn assemble_decodes_proto() {
        let row = FinderRow {
            rowid: 5,
            owner_username: "wxid_qrst2345uvwx678".to_string(),
            extra_buffer: proto("小应5899", 1_752_221_077, "https://channels.weixin.qq.com/x"),
        };
        let fv = assemble_finder(&row, &ctx());
        assert_eq!(fv.owner_username, "wxid_qrst2345uvwx678");
        assert_eq!(fv.name, "小应5899", "f2 昵称");
        assert_eq!(fv.visit_time, 1_752_221_077, "f5 访问时刻");
        assert_eq!(fv.profile_url, "https://channels.weixin.qq.com/x", "f6 URL");
        assert_eq!(fv.provenance.event_type, EventType::FinderVisitUpdate);
        assert_eq!(fv.provenance.event_seq, 0);
    }

    #[test]
    fn empty_or_malformed_proto_safe() {
        // 空 buffer → 空串/0, 不 panic。
        let fv = assemble_finder(
            &FinderRow {
                rowid: 1,
                owner_username: "u".into(),
                extra_buffer: vec![],
            },
            &ctx(),
        );
        assert_eq!(fv.name, "");
        assert_eq!(fv.visit_time, 0);
        assert_eq!(fv.profile_url, "");
        // 畸形 (截断 len) → 不 panic, 停在坏字段。
        let bad = vec![(2u8 << 3) | 2, 0xff]; // f2 声明超长但无数据
        let fv2 = assemble_finder(
            &FinderRow {
                rowid: 1,
                owner_username: "u".into(),
                extra_buffer: bad,
            },
            &ctx(),
        );
        assert_eq!(fv2.name, "", "截断 len 安全跳过");
    }
}
