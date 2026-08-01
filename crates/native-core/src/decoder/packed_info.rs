//! decoder::packed_info — 解析消息 `packed_info_data` proto blob → 图片 .dat 定位 md5。
//!
//! 微信 4.x 消息行有 `packed_info_data` 列 (protobuf blob)。图片消息 (local_type=3) 的该 blob 里
//! 藏着**本地 .dat 文件名的 md5** —— 这跟消息正文 XML `<img md5=>` 里的 md5 **是两个不同的 hash**
//! (XML md5 = CDN 内容哈希, 真库实测与 .dat 文件名零匹配; packed_info md5 = 本地文件定位 md5,
//! 真库 300/300 命中 `msg/attach/<talker>/<月>/Img/<md5>_W.dat`)。**定位只能用 packed_info md5**。
//!
//! ## proto 结构 (真库实测, image local_type=3)
//! ```text
//! field 1 (varint) = 803       # 常量 (格式版本?)
//! field 2 (varint) = 4         # 常量
//! field 3 (LEN)    = 嵌套 {     # 图片才有; 文本消息只到 field 2 (5 字节 header)
//!     field 4 (LEN) = <32 字节 ASCII hex>   # = .dat 文件名 md5
//! }
//! ```
//! 抄同行 wxcli `media.py:HASH_RE.search(packed_info_data)` (它直接正则首个 32-hex); 本实现走**真 proto
//! walk** (field 3 → field 4) 更稳, 不会误抓 blob 里其他偶然 32-hex 串。
//!
//! ## 边界 / 红线
//! - **infallible**: 纯字节解析, 截断 / 畸形 / 非图片 → `None`, 不 panic (untrusted blob, bounds 全检)。
//! - md5 是文件定位符 (同文件名, 非正文/wxid/master key) → 不走 K-R4 sha8 (跟 [`super::media`] 的
//!   VideoLocation/file_name 同口径明文)。

/// 读一个 LEB128 varint (最多 10 字节)。越界 / 超长 / 溢出 → None。推进 `pos`。
fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    for i in 0..10 {
        let b = *data.get(*pos)?;
        *pos += 1;
        // 第 10 字节 (i==9, shift==63) 只能贡献 bit63 → payload 须 ≤1, 否则高位溢出 u64 静默丢失 =
        // 畸形 (codex P2: 拒了它才真"畸形 blob → None", 否则会把溢出串当合法 tag/len)。
        if i == 9 && b & 0x7f > 1 {
            return None;
        }
        val |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(val);
        }
        shift += 7;
    }
    None // 第 10 字节仍带续位 = 畸形
}

/// 读一个 LEN (wire type 2) 字段的负载切片。越界 → None。推进 `pos`。
fn read_len_slice<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    // try_from 而非 `as usize`: 32-bit target 上 u64→usize 会截断 (codex P2), 超 usize 直接判畸形。
    let len = usize::try_from(read_varint(data, pos)?).ok()?;
    let end = pos.checked_add(len)?;
    let slice = data.get(*pos..end)?;
    *pos = end;
    Some(slice)
}

/// 跳过一个已知 wire type 的字段负载 (varint / i64 / i32 / len)。未知 wire → None (停止, 视为畸形)。
fn skip_field(data: &[u8], pos: &mut usize, wire: u8) -> Option<()> {
    match wire {
        0 => {
            read_varint(data, pos)?;
        }
        1 => *pos = pos.checked_add(8).filter(|&e| e <= data.len())?,
        2 => {
            read_len_slice(data, pos)?;
        }
        5 => *pos = pos.checked_add(4).filter(|&e| e <= data.len())?,
        _ => return None, // wire 3/4 (group, 已弃) / 6/7 (非法) → 停
    }
    Some(())
}

/// 在一段 proto 里找 `target_field` 的 **LEN (wire 2)** 负载 (返首个匹配)。非 LEN 字段跳过。
fn find_len_field(data: &[u8], target_field: u64) -> Option<&[u8]> {
    let mut pos = 0;
    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let field = tag >> 3;
        let wire = (tag & 7) as u8;
        if field == target_field && wire == 2 {
            return read_len_slice(data, &mut pos);
        }
        skip_field(data, &mut pos, wire)?;
    }
    None
}

/// 从 `packed_info_data` proto 抽图片 .dat 文件名 md5 (field 3 嵌套 → field 4, 32-byte ASCII hex)。
///
/// 非图片消息 (无 field 3) / 无 field 4 / 长度非 32 / 含非 hex 字符 / 畸形 blob → `None`。
/// **infallible**。返回小写 hex 串 (微信本就小写, 这里只做校验不改写)。
#[must_use]
pub fn parse_image_md5(data: &[u8]) -> Option<String> {
    let nested = find_len_field(data, 3)?; // field 3 = 嵌套消息 (图片才有)
    let md5 = find_len_field(nested, 4)?; // field 4 = md5 字节
    if md5.len() != 32 || !md5.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    // 已校验全 ASCII hex → from_utf8 必成功。
    std::str::from_utf8(md5).ok().map(str::to_ascii_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合成图片 packed_info: field1=803, field2=4, field3{ field4 = md5 }。
    fn make_packed(md5: &[u8]) -> Vec<u8> {
        // 嵌套: field4 (tag 0x22 = 4<<3|2) + len + md5。
        let mut nested = vec![0x22, md5.len() as u8];
        nested.extend_from_slice(md5);
        // 顶层: field1 varint 803, field2 varint 4, field3 (tag 0x1A) len nested。
        let mut out = vec![0x08, 0xA3, 0x06, 0x10, 0x04, 0x1A, nested.len() as u8];
        out.extend_from_slice(&nested);
        out
    }

    #[test]
    fn parse_real_image_md5() {
        // 真库 local_id=88 的 packed_info (hex 08A30610041A2222206533...)。
        let raw = hex_bytes("08A30610041A2222206533653735316438346333643065383131383962323764366133643464636164");
        assert_eq!(
            parse_image_md5(&raw).as_deref(),
            Some("e3e751d84c3d0e81189b27d6a3d4dcad"),
            "真库图片 packed_info 抽出 .dat 文件名 md5"
        );
    }

    #[test]
    fn parse_synthetic_roundtrip() {
        let md5 = b"0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_image_md5(&make_packed(md5)).as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn uppercase_md5_lowercased() {
        let md5 = b"ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(
            parse_image_md5(&make_packed(md5)).as_deref(),
            Some("abcdef0123456789abcdef0123456789"),
            "大写 hex 归一化小写 (匹配磁盘文件名)"
        );
    }

    #[test]
    fn text_message_header_only_none() {
        // 文本消息 packed_info = 5 字节 header (只 field1+field2, 无 field3) → None。
        let raw = hex_bytes("08A3061004");
        assert!(parse_image_md5(&raw).is_none(), "无 field3 → None");
    }

    #[test]
    fn empty_and_garbage_none() {
        assert!(parse_image_md5(&[]).is_none());
        assert!(
            parse_image_md5(&[0xFF, 0xFF, 0xFF]).is_none(),
            "非法 wire → None 不 panic"
        );
        assert!(
            parse_image_md5(&[0x1A, 0x7F]).is_none(),
            "field3 声明 len 127 但无数据 → 越界 None"
        );
    }

    #[test]
    fn wrong_length_md5_none() {
        assert!(
            parse_image_md5(&make_packed(b"tooshort")).is_none(),
            "非 32 字节 → None"
        );
        assert!(
            parse_image_md5(&make_packed(b"0123456789abcdef0123456789abcdef00")).is_none(),
            "34 字节 → None"
        );
    }

    #[test]
    fn non_hex_md5_none() {
        // 32 字节但含非 hex (g/z) → None (防把任意 32-byte 串当 md5)。
        assert!(parse_image_md5(&make_packed(b"zzzz56789abcdef0123456789abcdef0")).is_none());
    }

    #[test]
    fn truncated_varint_none() {
        // 续位一直为 1 的畸形 varint → read_varint 10 字节后 None, 不死循环。
        let raw = [0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80];
        assert!(parse_image_md5(&raw).is_none());
    }

    #[test]
    fn overflow_varint_rejected() {
        // codex P2: 10 字节 varint 第 10 字节 payload=0x7f (>1) → 高位溢出 u64 → 判畸形 None,
        // 不静默截断当合法 len。field3 tag(0x1A) 后跟此溢出 varint 当 LEN。
        let raw = [0x1A, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F];
        assert!(parse_image_md5(&raw).is_none(), "溢出 varint → None 不静默截断");
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
