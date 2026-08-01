//! message_content blob 解码 — zstd 解压 + 明文回退.
//!
//! 微信 4.x 把 message 正文存进 `Msg_*.message_content` BLOB, 用 zstd 压缩 (魔数 0x28B52FFD).
//! 老格式 / 未压缩为明文. 本模块只负责 BLOB → 明文 String, 不解释业务字段 (那是上层).

use super::DecoderError;

/// zstd 帧魔数 (`0x28 0xB5 0x2F 0xFD`). 微信 4.x message_content 压缩头.
/// 见 RFC 8878 §3.1.1 (Magic_Number, little-endian 0xFD2FB528).
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// 检 BLOB 头 4 字节是否 zstd 魔数.
fn has_zstd_magic(raw: &[u8]) -> bool {
    raw.len() >= 4 && raw[..4] == ZSTD_MAGIC
}

/// 单条正文解压出来的**上限**. 超过就当这一条坏了 (走 [`DecoderError::ZstdFail`] 同一条路).
///
/// 为什么要这个闸: `zstd::stream::decode_all` 是**一次性解到内存、没有上界**的 —— 一条异常压缩的
/// 消息(数据损坏, 或者有人往库里塞了特制内容)能把导入进程的内存直接撑爆。而 ingest 是**整库几百万条
/// 连着跑**的, 撑爆一次整批就没了。
///
/// 16 MiB 怎么来的 —— **真库上量过, 不是拍的**(2026-07-31):
///
/// 全量口径(独立复审, 6 个分片 21197 张会话表 509 万行): 单条**解压后**最大 **713,670 字节(约 697 KiB)**,
/// 超过 1 MiB 的**零行**。也就是说这个闸留了 **24 倍**余量, 正常数据一条都碰不到;
/// 碰到的必然是坏数据或者构造出来的。
///
/// (我自己头一版只抽了 120 张表看**压缩后**的大小, 结论方向对但样本小、口径也不对 —— 记在这里
/// 提醒: 定这种阈值要量解压后的、要全量。)
///
/// ⚠️ **撞上这个闸 = 整条丢掉, 不截断**(2026-07-31 用户拍板)。曾经考虑过"留前 16 MiB + 标个截断",
/// 否掉了, 理由是: 触发的基本是坏数据或构造数据, 留前一半也是垃圾; 为一种正常数据永远碰不到的情况
/// 给全链路(三个皮 + 导出 + 搜索索引)铺一个新的内容状态不划算; 而"看着是条正常消息、其实内容不全"
/// 比直接丢更危险。丢不静默 —— 归档里那条"没解出来"的记录**永不清理**(见
/// [`prune_older_than`](crate::storage::prune_older_than)), 用户随时查得到。
///
/// ⚠️ **配套原则**: 以后要是真实数据开始逼近这个数, 该做的是**把上限调高**, 不是改成截断。
///
/// ⚠️ **这块说明是常量的, 别让它把函数的文档吃了** —— 头一版我把常量连同这十几行直接插在
/// [`decode_message_content`] 的文档中间, 中间没断开, 于是**整块连着函数那段一起挂到了常量上**:
/// 函数的公开文档只剩下 `# Errors`, 连"返回的是明文含 PII、调用方负责脱敏"那条契约都不见了。
/// 跟我在别处把结构体文档整块挪走是同一种手滑, 独立复审 `cargo doc` 渲染出来才逮到。
pub const MAX_DECOMPRESSED: usize = 16 * 1024 * 1024;

/// 这条 BLOB **解出来最多多少字节** —— 不解压, 只看帧头。
///
/// 干什么用的: 并行解码要**先分窗再解**, 而分窗得知道这一窗大概会占多少内存。等解完再数就晚了。
///
/// zstd 帧头里带 `Frame_Content_Size`(解压后有多大), 解码器自己会校验实际输出跟它对不对得上,
/// 对不上直接报帧损坏 —— 所以这个数拿来当上界是可信的。
///
/// **全量真库量过**(独立复审, 6 个分片 21197 张会话表 **509 万行**, 只读挂载):
/// 100% 是 zstd; **0 行**帧头读不出大小; **0 行**估值小于实际解出来的; 单条最大 713,670 字节。
/// `Frame_Header_Descriptor` 见到三种 —— `0x60` / `0x20` / `0xA0`(430 行), 都置了 `Single_Segment` 位,
/// 也就是**一定带**这个字段。
///
/// 分窗按这个数模拟跑下来: 4975 个窗里 **4974 个是满 1024 行**, 最小的一个 882 行 ——
/// R15 那点并行度一分没掉。
///
/// 帧头没写(或者读不出来)就按 [`MAX_DECOMPRESSED`] 算 —— 往大了猜, 宁可分窗分小些。
/// 非 zstd 的老格式就是原样明文, 长度等于自己。
///
/// ⚠️ **光估是不够的, 解压那头必须按这个数卡** —— codex 审出来的 P1: `get_frame_content_size`
/// 只报**第一帧**, 而 `zstd::stream::Decoder` 默认会**把拼在一起的帧全解开**。拿十六个 1 MiB 的帧
/// 拼成一条, 这里报 1 MiB、实际解出 16 MiB, 窗口预算被绕开十六倍, 加这道闸就白加了。
/// 所以 [`decode_message_content`] 解压时直接拿这个数当上限: 解出来比声明的多一个字节就判坏。
/// 真实数据声明和实际一字节不差(真库实测), 所以只有构造/损坏的数据会撞上。
#[must_use]
pub fn decoded_size_upper_bound(raw: &[u8]) -> usize {
    if !has_zstd_magic(raw) {
        return raw.len();
    }
    let declared = zstd::zstd_safe::get_frame_content_size(raw)
        .ok()
        .flatten()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(MAX_DECOMPRESSED);
    declared.min(MAX_DECOMPRESSED)
}

/// 解码 `message_content` BLOB → 明文文本.
///
/// - 空 BLOB → 空串 (合法: 部分系统消息 message_content 为空).
/// - zstd 魔数开头 → 解压; 帧损坏/截断 → [`DecoderError::ZstdFail`] (单条标坏, 上层 emit error
///   event 不阻塞整库 — decoder-解码.md §2).
/// - 无魔数 → 当未压缩明文 (老格式).
/// - 解压/明文字节按 **utf8-lossy** 转 String (非法字节 → U+FFFD): 媒体/APP_XML 正文仍是 utf8 文本,
///   偶有二进制残留不应让单条失败; 真正的硬错只有 zstd 帧损坏.
///
/// 返回的是【明文】(含 PII) — 调用方负责经 privacy 层 sha256 脱敏后才可入 log/L2 (K-R4). 本函数不 log.
///
/// # Errors
/// [`DecoderError::ZstdFail`] — BLOB 以 zstd 魔数开头但帧损坏 / 截断 / **解出来超过 [`MAX_DECOMPRESSED`]**,
/// 无法(或不应)解压.
pub fn decode_message_content(raw: &[u8]) -> Result<String, DecoderError> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    let bytes = if has_zstd_magic(raw) {
        // ⚠️ 上界不只是"估一下", 是**当场兑现的承诺**: 解压就按它卡, 解出来比它多一个字节就判坏。
        // 不这样的话, 拿这个估算去切并行窗口的那一头等于白做 —— 见 `decoded_size_upper_bound` 的注。
        decode_zstd_capped(raw, decoded_size_upper_bound(raw))?
    } else {
        raw.to_vec()
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// 带上限的 zstd 解压: **边解边数**, 超过 [`MAX_DECOMPRESSED`] 立刻停手, 不把整个膨胀结果读进内存.
///
/// ⚠️ 这里必须是**流式**的 —— 先 `decode_all` 再判大小等于没加闸(内存已经吃进去了)。
///
/// ⚠️ 曾经拆成"薄壳 + 收任意 `Read` 的泛型"两层, 理由是"泛型那层能塞个会数字节的 reader 进来,
/// 测压缩输入没被读完"。**那条测试从来没写出来, 也写不出来** —— 压缩流才 8 KB, zstd 一次读光,
/// 读没读完跟有没有闸无关(见 `zstd_bomb_is_capped` 的注)。独立复审点出来: 一层纯转发的壳 +
/// 一个泛型参数, 是为一个不存在的测试付的账, 而 doc 还在宣称这个能力。合回一层。
fn decode_zstd_capped<R: std::io::Read>(src: R, cap: usize) -> Result<Vec<u8>, DecoderError> {
    use std::io::Read;
    let mut out = Vec::new();
    // `take` 多读 1 字节: 读满 cap+1 就说明超了 —— 只用一次读取就能把"正好等于上限"和"超了"分开。
    zstd::stream::Decoder::new(src)
        .map_err(|_| DecoderError::ZstdFail)?
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| DecoderError::ZstdFail)?;
    if out.len() > cap {
        return Err(DecoderError::ZstdFail);
    }
    Ok(out)
}

/// `message_content` BLOB 编码判定 (给 [`MessageCreate`](crate::event::message::MessageCreate) 的
/// `decode_kind` 元数据用): zstd 魔数开头 → `"zstd"`; 空 → `"empty"`; 否则 `"plain"`.
/// 跟 [`decode_message_content`] 的分支判定同源 (复用 [`has_zstd_magic`]), 不重复解压.
#[must_use]
pub fn content_encoding(raw: &[u8]) -> &'static str {
    if raw.is_empty() {
        "empty"
    } else if has_zstd_magic(raw) {
        "zstd"
    } else {
        "plain"
    }
}

/// 群聊 message_content 头部 sender 前缀拆分.
///
/// 微信【群聊】里 message_content 文本前缀 `{sender_wxid}:\n{正文}` (1-on-1 无此前缀, real_sender_id
/// 另存). 返 `(sender_wxid, 正文)`; 拆分失败 (无 `":\n"` 或前缀不像 wxid) → `(None, 原文整体)`.
///
/// 启发式跟 chatlog `message_v4.go:72-78` 的 `SplitN(":\n", 2)` 同源 + PoC-1.2 P0-2 校验: 仅当 `":\n"`
/// 前的部分像 sender (非空 / <64 字节 / 无 `'<'` 无空格 — 排除正文恰含 `":\n"` 或 xml 的误判) 才认.
/// 用首个 `":\n"` 切 (sender 不含该序列), 正文里残留的 `":\n"` 原样留在 body.
///
/// 只该对【群聊】消息调用 (调用方据 is_chatroom 判定); 1-on-1 不调. 纯函数, 不 log.
pub fn split_chatroom_sender(content: &str) -> (Option<String>, String) {
    if let Some(idx) = content.find(":\n") {
        let sender = &content[..idx];
        if !sender.is_empty() && sender.len() < 64 && !sender.contains('<') && !sender.contains(' ') {
            let body = &content[idx + 2..];
            return (Some(sender.to_string()), body.to_string());
        }
    }
    (None, content.to_string())
}

#[cfg(test)]
mod tests {
    /// **解压炸弹要被闸拦住**。
    ///
    /// `zstd::stream::decode_all` 是一次性解到内存、没有上界的 —— 一条异常压缩的消息(数据损坏,
    /// 或者有人往库里塞了特制内容)能把导入进程撑爆, 而 ingest 是整库几百万条连着跑的, 爆一次整批就没了。
    ///
    /// 造的是**真的炸弹**: 256 MiB 全零压出来才 8 KB, 解开是上限 16 MiB 的十六倍。
    ///
    /// ⚠️ **这条只钉"拦住了", 钉不了"没把内存吃进去"** —— 后者我试了两个代理指标, **两个都不成立**,
    /// 记在这儿免得以后有人再加一条假的:
    /// - **耗时**: 埋"先 `decode_all` 再判大小"那个反例, 它照样 0.39 秒过 —— zstd 解全零本来就快。
    /// - **压缩输入读没读完**: 在**当前正确的代码上就不成立** —— 压缩流才 8 KB, zstd 一次就读光了,
    ///   读没读完跟有没有闸无关。
    ///
    /// 真正能区分两种实现的只有**分配了多少内存**(16 MiB vs 256 MiB), 而那要往整个 crate 塞一个计数
    /// 分配器, 为一条测试不值。"不把内存吃进去"这条**靠代码保证**: `decode_zstd_capped` 里那句
    /// `.take(MAX_DECOMPRESSED + 1)` 是加在**解压输出**上的, 改动它的人一眼看得见。
    #[test]
    fn zstd_bomb_is_capped() {
        let bomb = zstd::stream::encode_all(&vec![0u8; 256 * 1024 * 1024][..], 3).expect("压出炸弹");
        assert!(
            bomb.len() < 1024 * 1024,
            "炸弹本身该很小(实测 {} 字节), 否则这条测的不是它想测的",
            bomb.len()
        );
        assert!(super::has_zstd_magic(&bomb), "得走 zstd 那一支");
        assert!(
            matches!(
                super::decode_message_content(&bomb),
                Err(crate::decoder::DecoderError::ZstdFail)
            ),
            "解出来超上限该当坏行处理 —— 去掉闸的话这里会返回 Ok(一个 256 MiB 的串)"
        );
    }

    /// 上限**底下**的正常长正文不许被误拦 —— 闸紧过头等于把好消息也丢了。
    #[test]
    fn long_but_normal_content_still_decodes() {
        let text = "长正文测试".repeat(100_000); // 约 1.5 MB, 远低于 16 MiB 上限
        let packed = zstd::stream::encode_all(text.as_bytes(), 3).expect("压");
        let got = super::decode_message_content(&packed).expect("正常长正文不该被拦");
        assert_eq!(got, text, "解出来得跟原文一模一样");
    }

    /// **正好等于上限的那一条得放行**(独立复审埋变异逮到的空白)。
    ///
    /// 原先四条守卫挑的量是 256 MiB / 16 KiB / 1.5 MB —— 没有一条落在闸上。把 `>` 改成 `>=`
    /// (正好 16 MiB 的消息被误杀), 全仓 1075 条测试**一条不红**。
    ///
    /// 这条同时钉死实现里那个 `+1`: 流式读的上界是 `MAX + 1`, 少了那个 1, 正好 16 MiB 的内容
    /// 会被**截断**成 16 MiB 然后判定通过 —— 内容悄悄少一截, 比报错还糟。
    #[test]
    fn content_exactly_at_the_cap_is_let_through() {
        let text = vec![b'a'; super::MAX_DECOMPRESSED];
        let packed = zstd::stream::encode_all(&text[..], 3).expect("压");
        let got = super::decode_message_content(&packed).expect("正好等于上限, 不该被拦");
        assert_eq!(got.len(), super::MAX_DECOMPRESSED, "得原样解出来, 不许少一个字节");

        // 多一个字节就该拦 —— 上下各一格, 闸的位置就锁死了。
        let over = vec![b'a'; super::MAX_DECOMPRESSED + 1];
        let packed_over = zstd::stream::encode_all(&over[..], 3).expect("压");
        assert!(
            matches!(
                super::decode_message_content(&packed_over),
                Err(crate::decoder::DecoderError::ZstdFail)
            ),
            "超上限一个字节就该拦"
        );
    }

    /// **不解压就估出上界** —— 并行分窗全靠它, 估错了要么白白收窄窗口(性能), 要么窗口装不下(内存)。
    ///
    /// 真库实测(2026-07-31, `message_0.db` 抽 3 条): 帧头声明 188 / 260 / 183 字节, 跟实际解出来的
    /// **一字节不差**。微信的帧 `Frame_Header_Descriptor` 是 `0x60` / `0x20`, 都置了 `Single_Segment` 位,
    /// 也就是一定带这个字段。所以真实数据上窗口照样是满的 1024 行, 不会退化。
    #[test]
    fn size_upper_bound_reads_the_frame_header() {
        // `bulk::compress` 一把压完, 帧头带解压后大小 —— 跟微信库里的帧同形。
        let text = "正文".repeat(500);
        let declared = zstd::bulk::compress(text.as_bytes(), 3).expect("压");
        assert_eq!(
            super::decoded_size_upper_bound(&declared),
            text.len(),
            "帧头写了多大就该报多大"
        );

        // 流式压出来的帧不写这个字段 —— 读不出来就得**往大了猜**, 不能当成 0。
        let streamed = zstd::stream::encode_all(text.as_bytes(), 3).expect("压");
        let guess = super::decoded_size_upper_bound(&streamed);
        assert!(guess >= text.len(), "读不出来必须往大了猜, 猜小了窗口会装不下: {guess}");

        // 声明得比硬上限还大 → 夹到硬上限, 不然一条就能把预算算爆。
        let bomb = zstd::bulk::compress(&vec![0u8; 64 * 1024 * 1024], 3).expect("压");
        assert_eq!(
            super::decoded_size_upper_bound(&bomb),
            super::MAX_DECOMPRESSED,
            "超硬上限的按硬上限算 —— 反正真解也解不出来那么多"
        );

        // 老格式没压过, 明文多长就是多长。
        assert_eq!(super::decoded_size_upper_bound(b"plain text"), 10);
        assert_eq!(super::decoded_size_upper_bound(b""), 0);
    }

    /// **拼在一起的帧不许绕过上界**(codex 审 c4b5dbc 的 P1, 它自己复现过)。
    ///
    /// `get_frame_content_size` 只报**第一帧**, 而 zstd 的流式解码器默认会把拼在一起的帧全解开。
    /// 于是"估出来 1 MiB、实际解出 16 MiB"是可能的 —— 并行窗口按估值切, 预算就被绕开十六倍,
    /// 那道闸等于白加。
    ///
    /// 修法是让估值**当场兑现**: 解压就按它卡, 多一个字节判坏。所以这条同时钉两件 ——
    /// 估值仍然只看第一帧(不假装能看全), 但**解压结果绝不会超过估值**。
    #[test]
    fn concatenated_frames_cannot_outrun_the_estimate() {
        let one = zstd::bulk::compress(&vec![b'a'; 64 * 1024], 3).expect("压");
        let mut joined = Vec::new();
        for _ in 0..8 {
            joined.extend_from_slice(&one);
        }

        let est = super::decoded_size_upper_bound(&joined);
        assert_eq!(est, 64 * 1024, "帧头只报第一帧 —— 这是 zstd 的事实, 不装作能看全");

        // 老实现: 八帧全解开 = 512 KiB, 是估值的八倍, 窗口预算当场被绕开。
        assert!(
            matches!(
                super::decode_message_content(&joined),
                Err(crate::decoder::DecoderError::ZstdFail)
            ),
            "解出来超过声明的就得判坏 —— 否则估值管不住实际, 窗口预算是假的"
        );

        // 对照: 单帧的照常解, 别把正常数据一起误杀。
        let plain = super::decode_message_content(&one).expect("单帧正常");
        assert_eq!(plain.len(), 64 * 1024);
    }

    use super::*;

    fn zstd_compress(bytes: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(bytes, 0).unwrap()
    }

    #[test]
    fn empty_blob_returns_empty_string() {
        assert_eq!(decode_message_content(&[]).unwrap(), "");
    }

    #[test]
    fn zstd_roundtrip_utf8_text() {
        let blob = zstd_compress("你好 hello 🌏".as_bytes());
        assert_eq!(blob[..4], ZSTD_MAGIC, "压缩输出应带 zstd 魔数 (前提保证)");
        assert_eq!(decode_message_content(&blob).unwrap(), "你好 hello 🌏");
    }

    #[test]
    fn zstd_roundtrip_xml_appmsg() {
        // APP_XML (type 49) 正文也是 zstd 压缩的 utf8 xml
        let xml = "<msg><appmsg><title>link</title></appmsg></msg>";
        let blob = zstd_compress(xml.as_bytes());
        assert_eq!(decode_message_content(&blob).unwrap(), xml);
    }

    #[test]
    fn no_magic_treated_as_plain_utf8() {
        // 无 zstd 魔数 → 当未压缩明文 (老格式)
        assert_eq!(decode_message_content(b"plain text msg").unwrap(), "plain text msg");
    }

    #[test]
    fn short_blob_under_4_bytes_is_plain() {
        // < 4 字节不可能含完整魔数 → 当明文, 不误判
        assert_eq!(decode_message_content(b"hi").unwrap(), "hi");
        assert_eq!(decode_message_content(&[0x28]).unwrap(), "\u{28}"); // 单个魔数首字节也是明文
    }

    #[test]
    fn exact_magic_only_no_frame_body_is_zstd_fail() {
        // codex P2: 恰好 4 字节纯魔数、无帧体 → decode_all Err → ZstdFail (不 panic)
        assert!(matches!(
            decode_message_content(&ZSTD_MAGIC),
            Err(DecoderError::ZstdFail)
        ));
    }

    #[test]
    fn corrupt_zstd_frame_is_zstd_fail() {
        // 有魔数但帧体垃圾 → ZstdFail (不 panic, 单条标坏)
        let mut bad = ZSTD_MAGIC.to_vec();
        bad.extend_from_slice(&[0xff, 0x00, 0x12, 0x34, 0x56]);
        assert!(matches!(decode_message_content(&bad), Err(DecoderError::ZstdFail)));
    }

    #[test]
    fn truncated_zstd_frame_is_zstd_fail() {
        // zstd 帧被截断 (只留前半) → ZstdFail
        let full = zstd_compress("a fairly long message to compress so truncation breaks it".as_bytes());
        let truncated = &full[..full.len() / 2];
        assert!(matches!(decode_message_content(truncated), Err(DecoderError::ZstdFail)));
    }

    #[test]
    fn zstd_binary_payload_lossy_not_err() {
        // 解压出非 utf8 字节 → lossy 转 U+FFFD, 不报错 (单条不阻塞)
        let blob = zstd_compress(&[0xff, 0xfe, 0x00, 0x01, 0x80]);
        let r = decode_message_content(&blob).unwrap();
        assert!(r.contains('\u{FFFD}'), "非法 utf8 字节应被 lossy 替换为 U+FFFD");
    }

    // ── split_chatroom_sender ──

    #[test]
    fn split_wxid_sender() {
        assert_eq!(
            split_chatroom_sender("wxid_abc123:\nhello world"),
            (Some("wxid_abc123".to_string()), "hello world".to_string())
        );
    }

    #[test]
    fn split_numeric_sender() {
        // 群聊 sender 偶尔纯数字
        assert_eq!(
            split_chatroom_sender("12345678:\n嗨"),
            (Some("12345678".to_string()), "嗨".to_string())
        );
    }

    #[test]
    fn split_gh_sender_keeps_xml_body() {
        // sender 干净 + body 是 xml (群聊里 APP_XML 也带 sender 前缀) → 拆 sender, body 保留 xml
        let (sender, body) = split_chatroom_sender("gh_official:\n<msg><appmsg>x</appmsg></msg>");
        assert_eq!(sender.as_deref(), Some("gh_official"));
        assert_eq!(body, "<msg><appmsg>x</appmsg></msg>");
    }

    #[test]
    fn split_no_delimiter_returns_whole() {
        assert_eq!(
            split_chatroom_sender("just a plain message"),
            (None, "just a plain message".to_string())
        );
    }

    #[test]
    fn split_first_delimiter_only() {
        // 用首个 ":\n" 切, body 里残留 ":\n" 留着
        assert_eq!(
            split_chatroom_sender("wxid_a:\nline1:\nline2"),
            (Some("wxid_a".to_string()), "line1:\nline2".to_string())
        );
    }

    #[test]
    fn split_rejects_sender_with_space() {
        // ":\n" 前含空格 → 不像 sender, 当正文恰含 ":\n" 的误判 → 不拆
        assert_eq!(
            split_chatroom_sender("hello world:\nfoo"),
            (None, "hello world:\nfoo".to_string())
        );
    }

    #[test]
    fn split_rejects_sender_with_angle_bracket() {
        // ":\n" 前含 '<' (正文是 xml, ":\n" 在 xml 内) → 不拆
        assert_eq!(
            split_chatroom_sender("<msg>:\nbody"),
            (None, "<msg>:\nbody".to_string())
        );
    }

    #[test]
    fn split_rejects_empty_sender() {
        // ":\n" 开头, sender 为空 → 不拆
        assert_eq!(split_chatroom_sender(":\nbody"), (None, ":\nbody".to_string()));
    }

    #[test]
    fn split_rejects_overlong_sender() {
        // sender >= 64 字节 → 不像 wxid → 不拆
        let long = "a".repeat(70);
        let input = format!("{long}:\nbody");
        assert_eq!(split_chatroom_sender(&input), (None, input.clone()));
    }

    #[test]
    fn split_empty_body_ok() {
        // sender 后正文为空 → (Some, "")
        assert_eq!(
            split_chatroom_sender("wxid_a:\n"),
            (Some("wxid_a".to_string()), String::new())
        );
    }

    #[test]
    fn split_sender_63_ok_64_rejected_boundary() {
        // 双审 P2: <64 字节边界 — 63 拆, 64 拒
        let s63 = "a".repeat(63);
        assert_eq!(
            split_chatroom_sender(&format!("{s63}:\nx")),
            (Some(s63.clone()), "x".to_string())
        );
        let s64 = "a".repeat(64);
        let in64 = format!("{s64}:\nx");
        assert_eq!(split_chatroom_sender(&in64), (None, in64.clone()));
    }

    #[test]
    fn split_chinese_emoji_body_intact() {
        // 双审 P2: body 含中文/emoji 切割不碎 utf8
        assert_eq!(
            split_chatroom_sender("wxid_a:\n你好世界 🌏 test"),
            (Some("wxid_a".to_string()), "你好世界 🌏 test".to_string())
        );
    }
}
