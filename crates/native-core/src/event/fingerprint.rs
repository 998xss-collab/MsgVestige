//! event::fingerprint — event_seq / content_digest 算法 (ADR-413 §3.x).
//!
//! 本 mod = PR2-3-h: 重放幂等的稳定序号算法.
//! - [`content_digest`]: SHA-256(canonical_raw_values 字典序 compact JSON) — 事件内容指纹.
//! - [`EventFingerprint::compute`]: SHA-256(6 字段长度前缀 canonical_bytes) → fingerprint + event_seq.
//!
//! ## 重放保证
//! 同源事件重放 → 同 6 字段输入 → 同 canonical → 同 fingerprint → 同 event_seq → 5 元组去重.
//! 不用 MAX(seq)+1 自增 / 不用 emit/ingest 时间 (ADR-413 方案 A/D ❌).
//!
//! ## 纯算法边界
//! 本 mod 只做哈希; **哪些字段 + raw/sha 进 canonical_raw_values 是 decoder 的事** (按 ADR-412
//! §3.x "进 content_digest" 列 + ADR-413 §4 各事件 content_digest 公式, 后续 PR 落).
//!
//! ## 跨语言一致性
//! content_digest 用 `serde_json::to_vec(&BTreeMap)` = Python `json.dumps(sort_keys=True,
//! separators=(',',':'), ensure_ascii=False)` (字典序 + compact + UTF-8 不转义). 测试硬编码
//! ADR-413 §3.y 的 Python 参考 golden 值, 跨语言 (Rust/Python/Node) 跑同输入必同输出.

use sha2::{Digest, Sha256};

use super::canonical::CanonicalRawValues;

/// 往 buf 追加【u32_be 长度前缀 + 字段字节】 (ADR-413 §3.x canonical 编码; 防 P0-D 边界歧义).
fn push_len_prefixed(buf: &mut Vec<u8>, field: &[u8]) {
    let len = u32::try_from(field.len()).expect("canonical 字段长度超 u32 (不可能 — 都是 sha/锚点/文件名)");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(field);
}

/// canonical_bytes (ADR-413 §3.x): 4 串各带 u32_be 长度前缀 + src_create_time_ms 定长 u64_be
/// (无前缀) + content_digest_hex 带前缀. 长度前缀防 "m_5.db"+"abc" vs "m_5"+"dbabc" 撞键 (§3.y #3).
fn canonical_bytes(
    account_id_sha: &str,
    source: &str,
    source_native_id: &str,
    event_action: &str,
    src_create_time_ms: u64,
    content_digest_hex: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    push_len_prefixed(&mut buf, account_id_sha.as_bytes());
    push_len_prefixed(&mut buf, source.as_bytes());
    push_len_prefixed(&mut buf, source_native_id.as_bytes());
    push_len_prefixed(&mut buf, event_action.as_bytes());
    buf.extend_from_slice(&src_create_time_ms.to_be_bytes()); // 8 字节 BE 定长, 无前缀
    push_len_prefixed(&mut buf, content_digest_hex.as_bytes());
    buf
}

/// event_seq = fingerprint 前 8 字节 BE 解 i64 & 清符号位 → i63 [0, i64::MAX] (ADR-413 §3.x).
///
/// 不用 `.wrapping_abs()` — `i64::MIN.wrapping_abs() == i64::MIN` (仍负), 是已知陷阱.
fn event_seq_from_fingerprint(fingerprint: &[u8; 32]) -> i64 {
    let first8: [u8; 8] = fingerprint[0..8].try_into().expect("32 >= 8");
    let raw = i64::from_be_bytes(first8);
    raw & 0x7fff_ffff_ffff_ffff
}

/// 事件内容指纹 (ADR-413 §3.x): SHA-256([`CanonicalRawValues`] 字典序 compact JSON) 的 hex.
///
/// 输入是 [`CanonicalRawValues`] (非裸 BTreeMap) — fingerprint 接口隔离 (ADR-426 §2.7.3): 只 decode 层的
/// [`super::canonical::canonical_raw_values`] 能构造它, projection/storage 的 V3* **编译期被拒**; 值用
/// 【原始/canonical 形态】(id→sha / display·text→raw, 隐私无关 — 翻转业务表存 sha/明文不动 fingerprint).
#[must_use]
pub fn content_digest(input: &CanonicalRawValues) -> String {
    let json = input.to_canonical_json();
    let mut hasher = Sha256::new();
    hasher.update(&json);
    hex::encode(hasher.finalize())
}

/// event_seq fingerprint 结果 (ADR-413 §3.x).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFingerprint {
    /// SHA-256(canonical_bytes) 全 hex (64 字符) — 跨语言比对锚点.
    pub fingerprint_hex: String,
    /// fingerprint 前 8 字节 BE 解 i64 & 清符号位 → i63 [0, i64::MAX]. 进 provenance event_seq.
    pub event_seq: i64,
}

impl EventFingerprint {
    /// 算 fingerprint + event_seq (ADR-413 §3.x). 6 字段是【已脱敏/锚点形态】 (account_id_sha 是
    /// sha 非裸 wxid; source_native_id 是复合 md5 锚点) + content_digest_hex (先 [`content_digest`] 算).
    ///
    /// `src_create_time_ms`: 源 db 消息时间; system_event 用 0 (ADR-413 §4 fallback 矩阵).
    #[must_use]
    pub fn compute(
        account_id_sha: &str,
        source: &str,
        source_native_id: &str,
        event_action: &str,
        src_create_time_ms: u64,
        content_digest_hex: &str,
    ) -> Self {
        let canonical = canonical_bytes(
            account_id_sha,
            source,
            source_native_id,
            event_action,
            src_create_time_ms,
            content_digest_hex,
        );
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let fingerprint: [u8; 32] = hasher.finalize().into();
        Self {
            event_seq: event_seq_from_fingerprint(&fingerprint),
            fingerprint_hex: hex::encode(fingerprint),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;

    // ADR-413 §3.y 公共 account_id_sha (示意 sha256("wxid_test_001")).
    const ACCT: &str = "f5a9a7f4b2c1e0d3a8b6c4d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2";

    /// 测试向量 #1 (message.create) — content_digest **只含业务字段** (排 provenance, ADR-412 §3.x.1
    /// 非 provenance "是" 列 = conv_id_sha/sender_wxid_sha/server_id/msg_type/msg_sub_type/text_content;
    /// provenance 进外层 canonical_bytes 不重复进 content_digest, recon 对齐 ADR-412 line 238 + ADR-413 §3 line 129).
    #[test]
    fn vector_1_message_create_golden() {
        let mut m: BTreeMap<String, Value> = BTreeMap::new();
        m.insert(
            "conv_id_sha".into(),
            Value::from("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        );
        m.insert("msg_sub_type".into(), Value::from(0));
        m.insert("msg_type".into(), Value::from(1));
        m.insert(
            "sender_wxid_sha".into(),
            Value::from("b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1"),
        );
        m.insert("server_id".into(), Value::from("1234567890"));
        m.insert("text_content".into(), Value::from("hello world"));
        let cd = content_digest(&CanonicalRawValues::from_map_for_test(m));
        assert_eq!(
            cd, "821388d48a4a3fdba04f5bf01c16267532b8dde7150d91a32201cb487e22fe94",
            "VEC#1 content_digest (排 provenance, Rust+Python 交叉验)"
        );

        let fp = EventFingerprint::compute(
            ACCT,
            "message_5.db",
            "Msg_429f284e:86680",
            "create",
            1_780_507_337_000,
            &cd,
        );
        assert_eq!(
            fp.fingerprint_hex, "e8ac1d71551fd96b7fd1f2f5dcf48f04a46ed8a7a93d3638382f178e6968b42d",
            "VEC#1 fingerprint"
        );
        assert_eq!(
            fp.event_seq, 7_542_435_848_535_398_763,
            "VEC#1 event_seq (e8 高位置位 → 掩码清符号 0x68.. → 正数)"
        );
    }

    /// 测试向量 #2 (system_event.cursor_update, src_create_time_ms=0) — content_digest **只含业务字段**
    /// (排 provenance, ADR-412 §3.x.6 非 provenance "是" 列 = kind/watermark_key/watermark_value).
    #[test]
    fn vector_2_cursor_update_golden() {
        let mut m: BTreeMap<String, Value> = BTreeMap::new();
        m.insert("kind".into(), Value::from("message"));
        m.insert("watermark_key".into(), Value::from("(create_time, sort_seq, local_id)"));
        m.insert(
            "watermark_value".into(),
            Value::from("[1780000000, 1780000000000, 100]"),
        );
        let cd = content_digest(&CanonicalRawValues::from_map_for_test(m));
        assert_eq!(
            cd, "73a72b88d20acf7c1d6da18860e77a073a29aabf5fa374cccb5626a3a1ef0cb9",
            "VEC#2 content_digest (排 provenance, Rust+Python 交叉验)"
        );

        let fp = EventFingerprint::compute(
            ACCT,
            "message_5.db",
            "cursor:message_5.db:message:abc12345",
            "cursor_update",
            0,
            &cd,
        );
        assert_eq!(
            fp.fingerprint_hex, "e032ea16827ef953f9715b7f1aa41f8811f7a48ef623ba3a559a82fdbe1f5379",
            "VEC#2 fingerprint"
        );
        assert_eq!(fp.event_seq, 6_931_860_158_876_154_195, "VEC#2 event_seq");
    }

    /// 测试向量 #3 (P0-D 边界歧义) — 长度前缀让 X/Y 不撞 (无前缀会撞 "m_5.dbabc").
    #[test]
    fn vector_3_boundary_x_y_no_collision() {
        const CD: &str = "0000000000000000000000000000000000000000000000000000000000000001";
        // X: source="m_5.db" native="abc"
        let x = EventFingerprint::compute(ACCT, "m_5.db", "abc", "create", 1_780_507_337_000, CD);
        assert_eq!(
            x.fingerprint_hex, "e7d47ea534e9843f5f1c683cd87c0efe9edbf1b70b5de79839a52f4144af4eaa",
            "VEC#3 X fingerprint"
        );
        assert_eq!(x.event_seq, 7_481_744_128_991_659_071, "VEC#3 X event_seq");
        // Y: source="m_5" native="dbabc"
        let y = EventFingerprint::compute(ACCT, "m_5", "dbabc", "create", 1_780_507_337_000, CD);
        assert_eq!(
            y.fingerprint_hex, "a0072884652106cc5938fe0f6543bcb6d3b6ec697407dd9c3ea99ae0c61638d8",
            "VEC#3 Y fingerprint"
        );
        assert_eq!(y.event_seq, 2_307_857_883_148_125_900, "VEC#3 Y event_seq");
        // 关键: 长度前缀 → X≠Y (无前缀会拼成同 "m_5.dbabc" 撞键)
        assert_ne!(x.fingerprint_hex, y.fingerprint_hex, "P0-D: 长度前缀防边界撞键");
    }

    /// canonical_bytes 长度跟 ADR-413 §3.y #1 字节布局表一致 (192 bytes).
    #[test]
    fn canonical_bytes_length_matches_layout() {
        // content_digest_hex 用 VEC#1 真值 (recon 后 821388d4..; 长度永 64, 此测只校长度+时间偏移).
        let cb = canonical_bytes(
            ACCT,
            "message_5.db",
            "Msg_429f284e:86680",
            "create",
            1_780_507_337_000,
            "821388d48a4a3fdba04f5bf01c16267532b8dde7150d91a32201cb487e22fe94",
        );
        // 4+64 + 4+12 + 4+18 + 4+6 + 8 + 4+64 = 192 (ADR-413 §3.y #1 字节布局表)
        assert_eq!(cb.len(), 192);
        // src_create_time_ms 大端 8 字节 (0000019e8e81e128 = struct.pack('>Q', 1780507337000))
        assert_eq!(&cb[116..124], &hex::decode("0000019e8e81e128").unwrap()[..]);
    }

    /// event_seq i63 掩码: 最高位置位 (含 i64::MIN 陷阱) 都清成非负, 不用 wrapping_abs.
    #[test]
    fn event_seq_i63_mask_never_negative() {
        // 0x8000...00 = i64::MIN — wrapping_abs 会仍是 MIN (负), 掩码给 0
        let mut min_fp = [0u8; 32];
        min_fp[0] = 0x80;
        assert_eq!(event_seq_from_fingerprint(&min_fp), 0, "i64::MIN 陷阱: 掩码清符号 → 0");
        // 全 0xFF → 0x7fff_ffff_ffff_ffff (i63 max)
        assert_eq!(event_seq_from_fingerprint(&[0xFF; 32]), i64::MAX);
        // 全 0 → 0
        assert_eq!(event_seq_from_fingerprint(&[0u8; 32]), 0);
        // 任意输出都非负
        assert!(event_seq_from_fingerprint(&min_fp) >= 0);
    }

    /// content_digest 确定性 + 键序无关 (BTreeMap 自排序 — 插入顺序不影响).
    #[test]
    fn content_digest_key_order_independent() {
        let mut a: BTreeMap<String, Value> = BTreeMap::new();
        a.insert("b".into(), Value::from(2));
        a.insert("a".into(), Value::from(1));
        let mut b: BTreeMap<String, Value> = BTreeMap::new();
        b.insert("a".into(), Value::from(1));
        b.insert("b".into(), Value::from(2));
        assert_eq!(
            content_digest(&CanonicalRawValues::from_map_for_test(a)),
            content_digest(&CanonicalRawValues::from_map_for_test(b)),
            "BTreeMap 字典序 → 插入顺序无关"
        );
    }
}
