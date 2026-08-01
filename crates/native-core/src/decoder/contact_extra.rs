//! contact_extra — 解析 `contact.extra_buffer` proto (联系人扩展属性)。
//!
//! 真实微信 4.x `contact.extra_buffer` = flat protobuf。字段映射 (2026-07-02 真库 3 个已知联系人核对确认):
//! - field 2  = **性别** (varint; 0=未知 / 1=男 / 2=女)
//! - field 4  = **个性签名** (string; 对方自设签名, 可含手机号; 空串=未设 — 批 I)。
//!    ⚠️ **企微联系人 (`username LIKE '%@openim'`) 的 f4 不是签名**: 是**嵌套 proto** `{f1 varint, f2 = JSON 串}`,
//!    JSON = `{"custom_info":[{"title":"<标签>","detail":[{...,"desc":"<真值>",...}]},…]}` (真库 2026-07-08 实测,
//!    300 个 @openim 全命中此结构)。抽 `title=="企业"` → detail[0].desc = **公司名** (`openim_company`);
//!    `title=="实名"` → detail[0].desc = **实名** (`openim_realname`)。检测法 = f4 内层 f2 是 `{`-开头且含 `"custom_info"`
//!    的 JSON → 企微 (此时 signature=None, 不把 JSON 当签名); 否则 f4 照旧当 utf8 签名。见 [`parse_openim_f4`]。
//! - field 5  = **国家 ISO 码** (string; 如 `CN` / `EE`; 空串=未设)
//! - field 6  = **省** (string; 英文/拼音 如 `Zhejiang`; 空串=未设)
//! - field 7  = **市** (string; 英文/拼音 如 `Hangzhou`; 空串=未设)
//! - field 8  = **好友来源** (varint; 加好友方式场景码 1/3/6/14/30…; 见 parse 注 — 早先误标 field 11 已纠)
//! - field 27 = **朋友圈封面图** (嵌套 proto; 内层 field 2 = `shmmsns.qpic.cn` 封面 URL; 空=未设 — 批 I)
//! - field 30 = **标签 id 列表** (string; 逗号分隔 label id 如 `"1,3,"`; 空=无标签 — 标签件, [`extract_label_list`])。
//!    竞品坐实 (WeChatMsg `contact_pb2` label_list f30 + chatlog): id→名字对照另在 `contact.contact_label` 表,
//!    由 [`source::account::drain_contacts`](crate::source) 预加载 map + 当场解析 (照 message Name2Id 手法)。
//!
//! 注: 地区存**英文/ISO 码非中文** (底座照原样存; 中文显示 = 展示层映射表)。手写 varint + len-delim 解析, 无 prost。
//! **infallible**: 坏 blob / 缺字段 → 默认值 (sex=0 / source=0 / 地区 None), 不 panic 不报错。
//! K-R4: 地区是明文 (非 wxid/正文红线, 同 nick 规矩 — 调用方 [`ContactUpdate`](crate::event::contact::ContactUpdate) Debug sha8 脱敏)。

/// contact.extra_buffer 解析结果 (联系人扩展属性; 全 L2-only 不进 content_digest)。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ContactExtra {
    /// 性别 (0=未知 / 1=男 / 2=女)。
    pub sex: i64,
    /// 国家 ISO 码 (如 `CN`; 未设→None)。
    pub country: Option<String>,
    /// 省 (英文/拼音; 未设→None)。
    pub province: Option<String>,
    /// 市 (英文/拼音; 未设→None)。
    pub city: Option<String>,
    /// 好友来源枚举 (加好友方式; 实测 1~3)。
    pub friend_source: i64,
    /// 个性签名 (f4; 对方自设, 可空; L2 明文, 可含手机号 → Debug sha8 脱敏 — 批 I)。
    pub signature: Option<String>,
    /// 朋友圈封面图 URL (f27 内层 f2; `shmmsns.qpic.cn` CDN, 可空; L2, Debug sha8 — 批 I)。
    pub moments_cover_url: Option<String>,
    /// 好友添加时间 (f41; varint unix 秒; 可空; L2 元数据 — 添加时间件 ADR-486)。
    /// ⭐ 实测发现 (2026-07-07): field 41 = 微信 UI "添加时间", 4 样本 (SY0070605/莉莉在目/小胡7/201822) 与 UI
    /// 一字不差。**超竞品逆向范围** (WeChatMsg contact.proto 最大 f38, chatlog 亦无) = 经验发现。覆盖率约 3.4%
    /// (仅微信回填过的联系人有; 老版本/未回填 → 无此 field → None; 应用层可 COALESCE friend_verify.timestamp 近似兜底)。
    pub friend_add_time: Option<i64>,
    /// 企微公司名 (企微联系人 f4 内层 custom_info `title=="企业"` 的 detail[0].desc; 非企微 → None; L2 明文,
    /// 可含公司全称/敏感 → Debug sha8 脱敏 — 企微件)。真库 300 个 @openim 中 294 有值 (~98%)。
    pub openim_company: Option<String>,
    /// 企微实名 (企微联系人 f4 内层 custom_info `title=="实名"` 的 detail[0].desc; 非企微 → None; L2 明文,
    /// 真实姓名 = PII → Debug sha8 脱敏 — 企微件)。真库 300 个 @openim 中 206 有值 (~69%)。
    pub openim_realname: Option<String>,
}

// K-R4 (codex 双审 P1): country/province/city 地区明文 + signature 个性签名(可含手机号) + moments_cover_url
// + openim_company/openim_realname (企微公司名/真实姓名, PII) → 手写 Debug sha8 脱敏, 防 `{extra:?}` 泄原文
// (类型 pub + re-export, 不靠调用方约束); sex/friend_source 元数据直显。
impl std::fmt::Debug for ContactExtra {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opt_sha8 = |o: &Option<String>| o.as_deref().map(|s| crate::key_provider::sha8(s.as_bytes()));
        f.debug_struct("ContactExtra")
            .field("sex", &self.sex)
            .field("country_sha8", &opt_sha8(&self.country))
            .field("province_sha8", &opt_sha8(&self.province))
            .field("city_sha8", &opt_sha8(&self.city))
            .field("friend_source", &self.friend_source)
            .field("signature_sha8", &opt_sha8(&self.signature))
            .field("moments_cover_url_sha8", &opt_sha8(&self.moments_cover_url))
            .field("friend_add_time", &self.friend_add_time) // 时间戳元数据, 非 PII → 直显
            .field("openim_company_sha8", &opt_sha8(&self.openim_company))
            .field("openim_realname_sha8", &opt_sha8(&self.openim_realname))
            .finish()
    }
}

/// varint 解码 → (value, next_offset)。坏 / 溢出 → None。
fn decode_varint(raw: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut pos = offset;
    while pos < raw.len() {
        let byte = raw[pos];
        pos += 1;
        let part = u64::from(byte & 0x7f);
        // 溢出保护 (codex 双审 P2): 第 10 字节 (shift==63) 只能贡献 1 bit; 更高位 = u64 溢出 → None (契约)。
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

/// 解析 extra_buffer → [`ContactExtra`]。**infallible** (坏/缺 → 默认)。
///
/// 扫 flat proto 顶层字段, 取每个目标 field 的**首个**值 (varint / utf8 string)。遇坏字节 break (已取的保留)。
#[must_use]
pub fn parse_contact_extra(extra_buffer: &[u8]) -> ContactExtra {
    let mut out = ContactExtra::default();
    // 显式 seen 标志 (codex 双审 P2): 不用 0/None 当"未见"哨兵 — 否则 sex=0(未知) 先出会被后面覆盖。
    // 严格 first-wins: 首个出现的目标 field 定值 (即使 sex=0 / 地区空串), 后续同 field 忽略。
    let (mut seen_sex, mut seen_source) = (false, false);
    let (mut seen_country, mut seen_province, mut seen_city) = (false, false, false);
    let (mut seen_signature, mut seen_cover) = (false, false);
    let mut seen_add_time = false;
    let mut idx = 0;
    while idx < extra_buffer.len() {
        let Some((tag, next)) = decode_varint(extra_buffer, idx) else {
            break;
        };
        idx = next;
        let field_no = tag >> 3;
        let wire_type = tag & 0x07;
        match wire_type {
            0 => {
                // varint: 性别 (f2) / 加好友来源场景 (f8)。
                // ⚠️ friend_source 是 **field 8** (2026-07-04 真机核: 竞品 WDA source_scene 读 f8, 值 1/3/6/10/14/30
                //    = QQ号/微信号/手机号/名片/群聊/扫一扫; 早先误读 f11(值 0-4, 语义不明) 与场景码对不上, 已纠)。
                let Some((v, next)) = decode_varint(extra_buffer, idx) else {
                    break;
                };
                idx = next;
                match field_no {
                    2 if !seen_sex => {
                        out.sex = i64::try_from(v).unwrap_or(0);
                        seen_sex = true;
                    }
                    8 if !seen_source => {
                        out.friend_source = i64::try_from(v).unwrap_or(0);
                        seen_source = true;
                    }
                    // 好友添加时间 (f41 varint unix 秒; first-wins; 0=未回填哨兵 → None, 同地区空串→None; 超 i64 → None — ADR-486)。
                    41 if !seen_add_time => {
                        out.friend_add_time = i64::try_from(v).ok().filter(|&t| t > 0);
                        seen_add_time = true;
                    }
                    _ => {}
                }
            }
            1 => {
                // fixed64: 跳过 8 字节。
                let Some(n) = idx.checked_add(8) else { break };
                if n > extra_buffer.len() {
                    break;
                }
                idx = n;
            }
            2 => {
                // len-delim: 个性签名 f4 / 地区串 f5-7 (utf8); 朋友圈封面 f27 (嵌套 proto); 其余跳过。
                let Some((size, next)) = decode_varint(extra_buffer, idx) else {
                    break;
                };
                idx = next;
                let Ok(size) = usize::try_from(size) else { break };
                let Some(end) = idx.checked_add(size) else { break };
                if end > extra_buffer.len() {
                    break;
                }
                let val = &extra_buffer[idx..end];
                idx = end;
                if field_no == 27 {
                    // 朋友圈封面 f27 = 嵌套 proto, 取内层 f2 = 封面 URL (first-wins; 坏/缺 → None)。
                    if !seen_cover {
                        seen_cover = true;
                        out.moments_cover_url = nested_first_string(val, 2);
                    }
                    continue;
                }
                // 企微件: f4 首次出现时先探是不是企微嵌套 proto (内层 f2 JSON 含 custom_info)。
                // 是 → 抽公司名/实名, signature 保持 None (标记 seen_signature 防误当签名); 否 → 落回下方普通 f4=签名。
                if field_no == 4 && !seen_signature {
                    if let Some((company, realname)) = parse_openim_f4(val) {
                        seen_signature = true; // 企微 f4 = 嵌套 JSON, 非签名 → 不再当签名解 (signature 留 None)。
                        out.openim_company = company;
                        out.openim_realname = realname;
                        continue;
                    }
                }
                let target = match field_no {
                    4 => Some((&mut seen_signature, &mut out.signature)),
                    5 => Some((&mut seen_country, &mut out.country)),
                    6 => Some((&mut seen_province, &mut out.province)),
                    7 => Some((&mut seen_city, &mut out.city)),
                    _ => None,
                };
                if let Some((seen, slot)) = target {
                    if !*seen {
                        *seen = true;
                        // 首个出现即定 (空串 → 保持 None = 未设; 后续同 field 忽略)。
                        if let Ok(s) = std::str::from_utf8(val) {
                            if !s.is_empty() {
                                *slot = Some(s.to_string());
                            }
                        }
                    }
                }
            }
            5 => {
                // fixed32: 跳过 4 字节。
                let Some(n) = idx.checked_add(4) else { break };
                if n > extra_buffer.len() {
                    break;
                }
                idx = n;
            }
            _ => break,
        }
    }
    out
}

/// 抽 extra_buffer **field 30 (标签 id 列表)** 的 len-delim utf8 字符串 (标签件)。
///
/// 值形如 `"1,3,"` (逗号分隔的 label id, 竞品 WeChatMsg `contact_pb2.label_list` / chatlog 坐实);
/// id→名字对照另在 `contact.contact_label` 表, 由调用方 (`drain_contacts`) 预加载 map + 当场解析。
/// 本函数只负责从 proto 抽出**原始 id 串** (不查 map, 不拆分)。
///
/// **infallible** (同 [`parse_contact_extra`] 契约): 坏字节 / 缺 f30 / 空串 → None, 不 panic。
/// first-wins: 只取首个 f30 (单值语义, 同 [`parse_contact_extra`])。
#[must_use]
pub fn extract_label_list(extra_buffer: &[u8]) -> Option<String> {
    let mut idx = 0;
    while idx < extra_buffer.len() {
        let (tag, next) = decode_varint(extra_buffer, idx)?;
        idx = next;
        let field_no = tag >> 3;
        match tag & 0x07 {
            0 => {
                // varint: 跳过 (性别 f2 / 来源 f8 等)。
                let (_, n) = decode_varint(extra_buffer, idx)?;
                idx = n;
            }
            1 => {
                // fixed64: 跳过 8 字节。
                idx = idx.checked_add(8)?;
                if idx > extra_buffer.len() {
                    return None;
                }
            }
            2 => {
                let (size, n) = decode_varint(extra_buffer, idx)?;
                idx = n;
                let size = usize::try_from(size).ok()?;
                let end = idx.checked_add(size)?;
                if end > extra_buffer.len() {
                    return None;
                }
                if field_no == 30 {
                    // 命中 f30 标签 id 串 → utf8 (空串 → None = 无标签; first-wins)。
                    return std::str::from_utf8(&extra_buffer[idx..end])
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                }
                idx = end;
            }
            5 => {
                // fixed32: 跳过 4 字节。
                idx = idx.checked_add(4)?;
                if idx > extra_buffer.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

/// 从嵌套 proto blob 取首个 `target_field` 的 len-delim utf8 字符串 (朋友圈封面 f27 内层 f2)。
/// **infallible**: 坏字节 / 缺字段 / 空串 → None, 不 panic (同 [`parse_contact_extra`] 契约)。
fn nested_first_string(blob: &[u8], target_field: u64) -> Option<String> {
    let mut idx = 0;
    while idx < blob.len() {
        let (tag, next) = decode_varint(blob, idx)?;
        idx = next;
        let field_no = tag >> 3;
        match tag & 0x07 {
            0 => {
                let (_, n) = decode_varint(blob, idx)?; // varint: 跳过
                idx = n;
            }
            1 => {
                idx = idx.checked_add(8)?; // fixed64
                if idx > blob.len() {
                    return None;
                }
            }
            2 => {
                let (size, n) = decode_varint(blob, idx)?;
                idx = n;
                let size = usize::try_from(size).ok()?;
                let end = idx.checked_add(size)?;
                if end > blob.len() {
                    return None;
                }
                if field_no == target_field {
                    // 命中 target 的 len-delim → utf8 string (空串→None)。
                    return std::str::from_utf8(&blob[idx..end])
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                }
                idx = end;
            }
            5 => {
                idx = idx.checked_add(4)?; // fixed32
                if idx > blob.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

/// 企微 (`@openim`) 联系人 f4 抽公司名/实名 (企微件)。
///
/// `f4_blob` = f4 的 len-delim 载荷 = 嵌套 proto `{f1 varint, f2 = JSON 字符串}`。
/// 内层 f2 JSON = `{"custom_info":[{"title":"<标签>","detail":[{…,"desc":"<真值>",…}]},…]}` (真库实测)。
/// 抽 `title=="企业"` → detail[0].desc = 公司名; `title=="实名"` → detail[0].desc = 实名。
///
/// **返回 `Some((company, realname))` 仅当**内层 f2 是 `{`-开头且 parse 成含 `"custom_info"` 数组的 JSON
/// (= 确系企微 f4, 非普通 utf8 签名)。company/realname 各自可空 (无对应 title / desc 空 → None)。
/// 非企微 f4 (普通签名串 / 内层非 JSON / 缺 custom_info) → `None` (调用方落回 f4=签名解)。
///
/// `detail` 兼容两形态: 真库是**已展开 JSON 数组** (`detail:[{…}]`); 亦兜底**字符串化 JSON 数组**
/// (`detail:"[{…}]"`, 部分微信版本/字段可能如此) — 后者再 parse 一层。**infallible**: 任何解析失败 → None。
fn parse_openim_f4(f4_blob: &[u8]) -> Option<(Option<String>, Option<String>)> {
    // 取内层 f2 JSON 串 (复用嵌套 proto 解析)。空 / 缺 → None。
    let json = nested_first_string(f4_blob, 2)?;
    // 快速门: 非 `{` 开头直接判非企微 (省 parse; 普通签名串到不了这 — f4 走此路仅因内层是嵌套 proto)。
    if !json.trim_start().starts_with('{') {
        return None;
    }
    let root: serde_json::Value = serde_json::from_str(&json).ok()?;
    let items = root.get("custom_info")?.as_array()?; // 无 custom_info → 非企微 → None
    let company = openim_desc_for_title(items, "企业");
    let realname = openim_desc_for_title(items, "实名");
    Some((company, realname))
}

/// 从 custom_info 数组找 `title==target` 元素 → 取 detail[0].desc (非空串 → Some)。
/// detail 兼容 JSON 数组 (真库) 或字符串化 JSON 数组 (兜底再 parse 一层)。无匹配 / 空 → None。
fn openim_desc_for_title(items: &[serde_json::Value], target: &str) -> Option<String> {
    for el in items {
        if el.get("title").and_then(serde_json::Value::as_str) != Some(target) {
            continue;
        }
        let detail = el.get("detail")?;
        // 形态 1: detail 已是 JSON 数组 (真库 300/300 皆如此)。
        if let Some(arr) = detail.as_array() {
            return desc_from_detail_array(arr);
        }
        // 形态 2 (兜底): detail 是字符串化 JSON 数组 → 再 parse 一层。
        if let Some(s) = detail.as_str() {
            if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(s) {
                return desc_from_detail_array(&arr);
            }
        }
        return None; // title 命中但 detail 形态不认 → None (不继续找同 title, first-wins)。
    }
    None
}

/// detail 数组 → [0]["desc"] 的非空串 (空串 / 缺 / 非串 → None)。
fn desc_from_detail_array(arr: &[serde_json::Value]) -> Option<String> {
    arr.first()
        .and_then(|first| first.get("desc"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── protobuf 编码 test helper ──
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
        out
    }
    fn vfield(field_no: u64, v: u64) -> Vec<u8> {
        let mut o = varint(field_no << 3);
        o.extend(varint(v));
        o
    }
    fn sfield(field_no: u64, s: &str) -> Vec<u8> {
        let mut o = varint((field_no << 3) | 2);
        o.extend(varint(s.len() as u64));
        o.extend_from_slice(s.as_bytes());
        o
    }

    /// 全字段 (仿真库 Hiheyxia: 女 / CN Zhejiang Hangzhou / 来源 3)。
    #[test]
    fn parse_full() {
        let mut b = Vec::new();
        b.extend(vfield(2, 2)); // 性别=女
        b.extend(vfield(3, 1)); // 无关字段
        b.extend(sfield(5, "CN"));
        b.extend(sfield(6, "Zhejiang"));
        b.extend(sfield(7, "Hangzhou"));
        b.extend(vfield(8, 3)); // 加好友来源场景 (field 8, 值 3=微信号)
        let e = parse_contact_extra(&b);
        assert_eq!(e.sex, 2);
        assert_eq!(e.country.as_deref(), Some("CN"));
        assert_eq!(e.province.as_deref(), Some("Zhejiang"));
        assert_eq!(e.city.as_deref(), Some("Hangzhou"));
        assert_eq!(e.friend_source, 3);
        assert_eq!(e.friend_add_time, None, "无 f41 → 添加时间 None");
    }

    /// 添加时间件 (ADR-486): f41 varint = 好友添加时间 unix 秒 (仿真库小胡7 1698674704=2023-10-30)。
    #[test]
    fn parse_friend_add_time() {
        let mut b = Vec::new();
        b.extend(vfield(2, 1)); // 性别 (前置字段, 确认 f41 在后仍能扫到)
        b.extend(vfield(8, 3)); // 好友来源
        b.extend(vfield(41, 1_698_674_704)); // 添加时间 = 2023-10-30
        let e = parse_contact_extra(&b);
        assert_eq!(e.friend_add_time, Some(1_698_674_704), "f41 varint → 添加时间 unix 秒");
        assert_eq!(e.sex, 1, "f41 不干扰其它字段");
        assert_eq!(e.friend_source, 3);
        // first-wins: 重复 f41 只取首个。
        b.extend(vfield(41, 999));
        assert_eq!(
            parse_contact_extra(&b).friend_add_time,
            Some(1_698_674_704),
            "f41 first-wins"
        );
        // 0 = 未回填哨兵 → None (真库 96 行, 非 1970 假日期)。
        let mut z = Vec::new();
        z.extend(vfield(2, 1));
        z.extend(vfield(41, 0));
        assert_eq!(parse_contact_extra(&z).friend_add_time, None, "f41=0 → None (哨兵)");
    }

    /// 国家级 (仿 Aaaayangmeimei: 男 / EE / 省市空)。
    #[test]
    fn parse_country_only() {
        let mut b = Vec::new();
        b.extend(vfield(2, 1));
        b.extend(sfield(5, "EE"));
        b.extend(sfield(6, "")); // 空串 → None
        b.extend(sfield(7, ""));
        b.extend(vfield(8, 3)); // 加好友来源场景 (field 8, 值 3=微信号)
        let e = parse_contact_extra(&b);
        assert_eq!(e.sex, 1);
        assert_eq!(e.country.as_deref(), Some("EE"));
        assert_eq!(e.province, None, "空串省 → None");
        assert_eq!(e.city, None);
        assert_eq!(e.friend_source, 3);
    }

    /// 地区全空 (仿 R1314521i: 男 / 地区空白)。
    #[test]
    fn parse_no_region() {
        let mut b = Vec::new();
        b.extend(vfield(2, 1));
        b.extend(sfield(5, ""));
        b.extend(vfield(8, 3)); // 加好友来源场景 (field 8, 值 3=微信号)
        let e = parse_contact_extra(&b);
        assert_eq!(e.sex, 1);
        assert_eq!(e.country, None);
        assert_eq!(e.province, None);
        assert_eq!(e.city, None);
    }

    /// 空 blob → 全默认 (infallible)。
    #[test]
    fn parse_empty() {
        let e = parse_contact_extra(&[]);
        assert_eq!(e, ContactExtra::default());
        assert_eq!(e.sex, 0);
        assert_eq!(e.friend_source, 0);
    }

    /// 坏字节 → 已取的保留, 不 panic (infallible)。
    #[test]
    fn parse_garbage_tail() {
        let mut b = vfield(2, 1);
        b.push(0xff); // 未完成 varint tag → break
        let e = parse_contact_extra(&b);
        assert_eq!(e.sex, 1, "坏尾前已取的保留");
    }

    /// 首值优先 (重复 field 取首个, 同 wx 单值语义)。
    #[test]
    fn parse_first_wins() {
        let mut b = vfield(2, 1);
        b.extend(vfield(2, 2)); // 第二个 f2 忽略
        assert_eq!(parse_contact_extra(&b).sex, 1);
    }

    /// codex P2: sex=0(未知) 首次出现即定, 不被后续覆盖 (0 不再当"未见"哨兵)。
    #[test]
    fn parse_sex_zero_first_wins() {
        let mut b = vfield(2, 0); // 首个 f2=0 (未知)
        b.extend(vfield(2, 2)); // 后续 f2=2 应忽略
        assert_eq!(parse_contact_extra(&b).sex, 0, "sex=0 首次即定, 不被覆盖");
        // 地区空串首次即定 None, 后续非空忽略 (严格 first-wins)。
        let mut r = sfield(5, "");
        r.extend(sfield(5, "CN"));
        assert_eq!(parse_contact_extra(&r).country, None, "空串国家首次即定 None, 后续忽略");
    }

    /// codex P2: 超长 varint (第 10 字节高位溢出) → decode 返 None → 该字段丢弃, 不 panic 不脏值。
    #[test]
    fn parse_varint_overflow_rejected() {
        // f2 tag=0x10 + value 9×0xff + 0x7f (第 10 字节 0x7f>1 触发溢出保护) → None → break, sex 保持默认 0。
        let mut b = vec![0x10];
        b.extend(std::iter::repeat(0xff).take(9));
        b.push(0x7f);
        assert_eq!(parse_contact_extra(&b).sex, 0, "溢出 varint 丢弃, sex 保持默认");
    }

    /// K-R4 (codex P1): ContactExtra Debug 不露地区原文 (province/city sha8 脱敏)。
    #[test]
    fn debug_redacts_region() {
        let mut b = Vec::new();
        b.extend(vfield(2, 2));
        b.extend(sfield(6, "Zhejiang"));
        b.extend(sfield(7, "Hangzhou"));
        let dbg = format!("{:?}", parse_contact_extra(&b));
        assert!(!dbg.contains("Zhejiang"), "K-R4: Debug 不露 province 原文");
        assert!(!dbg.contains("Hangzhou"), "K-R4: Debug 不露 city 原文");
        assert!(dbg.contains("province_sha8"));
        assert!(dbg.contains("sex: 2"));
    }

    /// 批 I: f4 个性签名 + f27 朋友圈封面 (嵌套 proto 内层 f2 URL) 解析。
    #[test]
    fn parse_signature_and_cover() {
        let url = "http://shmmsns.qpic.cn/mmsns/ABCdef123/0";
        // f27 内层 proto: f1=1 + f2=URL。
        let mut inner = vfield(1, 1);
        inner.extend(sfield(2, url));
        let mut b = vfield(2, 2); // 性别=女
        b.extend(sfield(4, "做自己 不太好也没关系")); // f4 签名
        b.extend(vfield(8, 17)); // 来源=名片
        b.extend(varint((27 << 3) | 2)); // f27 tag (len-delim)
        b.extend(varint(inner.len() as u64));
        b.extend_from_slice(&inner);
        let e = parse_contact_extra(&b);
        assert_eq!(e.signature.as_deref(), Some("做自己 不太好也没关系"), "f4 个性签名");
        assert_eq!(e.moments_cover_url.as_deref(), Some(url), "f27 内层 f2 封面 URL");
        assert_eq!(e.sex, 2);
        assert_eq!(e.friend_source, 17);
    }

    /// 批 I: f4 缺 → signature None; f27 内层无 f2 → cover None; 空串 f4 → None (infallible)。
    #[test]
    fn parse_signature_cover_absent() {
        let inner = vfield(1, 1); // f27 内层只有 f1, 无 f2 URL
        let mut b = vfield(2, 1);
        b.extend(varint((27 << 3) | 2));
        b.extend(varint(inner.len() as u64));
        b.extend_from_slice(&inner);
        let e = parse_contact_extra(&b);
        assert_eq!(e.signature, None, "无 f4 → None");
        assert_eq!(e.moments_cover_url, None, "f27 内层无 f2 → None");
        let mut b2 = sfield(4, ""); // 空串 f4
        b2.extend(vfield(2, 1));
        assert_eq!(parse_contact_extra(&b2).signature, None, "空串 f4 → None");
    }

    /// 批 I K-R4: Debug 不露签名原文 (可能含手机号) 与封面 URL。
    #[test]
    fn debug_redacts_signature_and_cover() {
        let url = "http://shmmsns.qpic.cn/mmsns/SECRET/0";
        let mut inner = vfield(1, 1);
        inner.extend(sfield(2, url));
        let mut b = sfield(4, "诚招小化13800138000");
        b.extend(varint((27 << 3) | 2));
        b.extend(varint(inner.len() as u64));
        b.extend_from_slice(&inner);
        let dbg = format!("{:?}", parse_contact_extra(&b));
        assert!(!dbg.contains("13800138000"), "K-R4: Debug 不露签名内手机号");
        assert!(!dbg.contains("SECRET"), "K-R4: Debug 不露封面 URL 原文");
        assert!(dbg.contains("signature_sha8"));
        assert!(dbg.contains("moments_cover_url_sha8"));
    }

    // ── 企微件: @openim f4 嵌套 JSON 抽公司名/实名 ──

    /// 构造企微 f4 载荷 = 嵌套 proto {f1=1, f2=<json>}。
    fn openim_f4_blob(json: &str) -> Vec<u8> {
        let mut inner = vfield(1, 1);
        inner.extend(sfield(2, json));
        // 顶层 f4 = len-delim 包 inner。
        let mut b = varint((4 << 3) | 2);
        b.extend(varint(inner.len() as u64));
        b.extend_from_slice(&inner);
        b
    }

    /// custom_info JSON (detail = 已展开数组, 真库形态)。
    const OPENIM_JSON: &str = r#"{"custom_info":[
        {"title":"来自","detail":[{"action":4,"action_param":{},"desc":"某来源","desc_type":0,"icon":""}]},
        {"title":"企业","detail":[{"action":4,"action_param":{},"desc":"某某科技有限公司","desc_type":0,"icon":""}]},
        {"title":"实名","detail":[{"action":4,"action_param":{},"desc":"张三","desc_type":0,"icon":""}]},
        {"title":"员工状态","detail":[{"action":4,"action_param":{},"desc":"在职","desc_type":0,"icon":""}]}
    ]}"#;

    /// 企微件: f4 嵌套 JSON → 抽出 openim_company/openim_realname; signature 保持 None (不把 JSON 当签名)。
    #[test]
    fn parse_openim_company_and_realname() {
        // 前置 f2 性别 + 后置 f8 来源, 确认 f4 在中间也能命中。
        let mut b = vfield(2, 1);
        b.extend(openim_f4_blob(OPENIM_JSON));
        b.extend(vfield(8, 3));
        let e = parse_contact_extra(&b);
        assert_eq!(
            e.openim_company.as_deref(),
            Some("某某科技有限公司"),
            "title=企业 → detail[0].desc = 公司名"
        );
        assert_eq!(
            e.openim_realname.as_deref(),
            Some("张三"),
            "title=实名 → detail[0].desc = 实名"
        );
        assert_eq!(e.signature, None, "企微 f4 是嵌套 JSON, 非签名 → signature 保持 None");
        assert_eq!(e.sex, 1, "f4 企微解析不干扰其它字段");
        assert_eq!(e.friend_source, 3);
    }

    /// 企微件: detail 为字符串化 JSON 数组 (兜底形态) 也能抽出 desc。
    #[test]
    fn parse_openim_detail_stringified() {
        let json = r#"{"custom_info":[
            {"title":"企业","detail":"[{\"desc\":\"兜底公司\",\"desc_type\":0}]"},
            {"title":"实名","detail":"[{\"desc\":\"李四\"}]"}
        ]}"#;
        let e = parse_contact_extra(&openim_f4_blob(json));
        assert_eq!(
            e.openim_company.as_deref(),
            Some("兜底公司"),
            "detail 字符串化数组 → 再 parse 一层取 desc"
        );
        assert_eq!(e.openim_realname.as_deref(), Some("李四"));
    }

    /// 企微件: 只有企业无实名 → realname None; 反之亦然 (各自可空)。
    #[test]
    fn parse_openim_partial_titles() {
        let only_company = r#"{"custom_info":[{"title":"企业","detail":[{"desc":"独角兽公司"}]}]}"#;
        let e = parse_contact_extra(&openim_f4_blob(only_company));
        assert_eq!(e.openim_company.as_deref(), Some("独角兽公司"));
        assert_eq!(e.openim_realname, None, "无 title=实名 → realname None");
        // desc 空串 → None。
        let empty_desc =
            r#"{"custom_info":[{"title":"企业","detail":[{"desc":""}]},{"title":"实名","detail":[{"desc":"王五"}]}]}"#;
        let e2 = parse_contact_extra(&openim_f4_blob(empty_desc));
        assert_eq!(e2.openim_company, None, "desc 空串 → None");
        assert_eq!(e2.openim_realname.as_deref(), Some("王五"));
    }

    /// 区分法: 普通联系人 f4 = utf8 签名串 (非 JSON) → 照旧当签名, openim_* 为 None。
    #[test]
    fn parse_normal_signature_not_openim() {
        let e = parse_contact_extra(&sfield(4, "做自己就好"));
        assert_eq!(e.signature.as_deref(), Some("做自己就好"), "普通 f4 仍当签名解");
        assert_eq!(e.openim_company, None, "非企微 → 无公司名");
        assert_eq!(e.openim_realname, None, "非企微 → 无实名");
        // f4 是 `{`-开头但非 custom_info JSON (碰巧的签名) → 不误判为企微, 当签名。
        let e2 = parse_contact_extra(&openim_f4_blob(r#"{"hello":"world"}"#));
        assert_eq!(e2.openim_company, None, "内层 JSON 无 custom_info → 非企微");
        assert_eq!(e2.openim_realname, None);
    }

    /// K-R4: Debug 不露公司名/实名原文 (PII → sha8 脱敏)。
    #[test]
    fn debug_redacts_openim_company_realname() {
        let json = r#"{"custom_info":[{"title":"企业","detail":[{"desc":"机密科技有限公司"}]},{"title":"实名","detail":[{"desc":"赵机密"}]}]}"#;
        let dbg = format!("{:?}", parse_contact_extra(&openim_f4_blob(json)));
        assert!(!dbg.contains("机密科技有限公司"), "K-R4: Debug 不露公司名原文");
        assert!(!dbg.contains("赵机密"), "K-R4: Debug 不露实名原文");
        assert!(dbg.contains("openim_company_sha8"));
        assert!(dbg.contains("openim_realname_sha8"));
    }

    // ── 标签件: extract_label_list (f30 标签 id 串) ──

    /// f30 标签 id 串抽取 (逗号分隔, 竞品实测形如 "1,3,")。
    #[test]
    fn extract_label_list_basic() {
        // 混入其它字段确认 f30 能在 walk 中被定位: f2=1(varint) + f30="1,3," + f8=3(varint)。
        let mut b = vfield(2, 1);
        b.extend(sfield(30, "1,3,"));
        b.extend(vfield(8, 3));
        assert_eq!(extract_label_list(&b).as_deref(), Some("1,3,"));
    }

    /// f30 缺 → None; 空串 f30 → None (无标签); 空 blob → None (infallible)。
    #[test]
    fn extract_label_list_absent_or_empty() {
        // 无 f30 (只有 f2/f5) → None。
        let mut b = vfield(2, 2);
        b.extend(sfield(5, "CN"));
        assert_eq!(extract_label_list(&b), None, "无 f30 → None");
        // 空串 f30 → None。
        assert_eq!(extract_label_list(&sfield(30, "")), None, "空串 f30 → None");
        // 空 blob → None。
        assert_eq!(extract_label_list(&[]), None, "空 blob → None");
    }

    /// first-wins: 重复 f30 取首个 (单值语义, 同 parse_contact_extra)。
    #[test]
    fn extract_label_list_first_wins() {
        let mut b = sfield(30, "1,");
        b.extend(sfield(30, "9,")); // 第二个 f30 忽略
        assert_eq!(extract_label_list(&b).as_deref(), Some("1,"));
    }

    /// 坏尾字节 → 已扫到 f30 前若命中则返, 否则 None, 不 panic (infallible)。
    #[test]
    fn extract_label_list_garbage_tail() {
        // f30 在坏字节前 → 命中即返 (return 早于坏尾)。
        let mut ok = sfield(30, "2,");
        ok.push(0xff); // 坏尾 (命中 f30 已 return, 不触及)
        assert_eq!(extract_label_list(&ok).as_deref(), Some("2,"));
        // 坏 tag 在 f30 前 → walk 中断返 None (不 panic)。
        let bad = vec![0xffu8]; // 未完成 varint tag
        assert_eq!(extract_label_list(&bad), None, "坏 tag → None 不 panic");
    }
}
