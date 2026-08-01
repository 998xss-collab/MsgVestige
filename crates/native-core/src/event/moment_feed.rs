//! event::moment_feed — (moment_feed_update, create) 事件字段集. 微信朋友圈好友动态索引
//! (sns.db `SnsTopItem_1`) 一条 = 一条好友朋友圈在我时间线出现的记录 (谁 + 何时发 + 我读没读)。
//!
//! 照 [`super::finder::FinderVisitCreate`] 模板 (sns.db 索引表 → alpha 事件; ADR-474)。
//! **真库坐实** (2026-07-06 inspect 加密 sns.db `SnsTopItem_1` 385989 行 / 301384 去重 tid): 纯活动索引,
//! **无正文** (`summary` 列全空) + 98.6% tid 内容不在 SnsTimeLine (moment 表) → 只有 "谁发 + 何时发 + 读没读"。
//! 列: tid (动态 id) / username (发布者 wxid) / create_time (发布秒) / last_read_time (我读时刻) / is_read。
//! `summary` 全空**不落** (零价值列)。用户明知空壳仍要 (2026-07-06 "还是做"): 给好友朋友圈活动时间线。
//!
//! ## content_digest (canonical.rs moment_feed 臂)
//! tid / author_sha / create_time — 动态 (身份) + 发布者 + 发布时刻 (3 元)。last_read_time/is_read (读状态,
//! is_read 真库 99.5% 恒 1 噪音) 只进 L2 不进 digest。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — author (发布者 wxid) 经 [`sha8`]; 其余数字元数据明文。
//! - author 出 payload 走 [`FieldCategory::Id`] (默认 sha)。tid 是雪花动态 id (非 PII) 明文。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (moment_feed_update, create) 事件字段集 — 一条好友朋友圈动态索引 (sns.db `SnsTopItem_1`)。
///
/// `source_native_id` = `"MomentFeed_<tid>"` (tid 是雪花动态 id, 非 PII 直用; 真库唯一定位一条动态)。
pub struct MomentFeedCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 朋友圈动态 id (SnsTopItem_1.tid; 雪花 id 可为负; anchor + digest 身份)。
    pub tid: i64,
    /// 发布者 wxid (SnsTopItem_1.username; id 类; 进 digest 用 sha)。
    pub author: String,
    /// 发布时刻 (SnsTopItem_1.create_time; unix 秒; 进 digest)。
    pub create_time: i64,
    /// 我读到此动态的时刻 (SnsTopItem_1.last_read_time; unix 秒; 读状态; 只进 L2)。
    pub last_read_time: i64,
    /// 是否已读 (SnsTopItem_1.is_read; 真库 99.5% 恒 1 噪音; 只进 L2)。
    pub is_read: i64,
}

impl MomentFeedCreate {
    /// 渲染整条 moment_feed_update.create 的 payload_json (唯一出口)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // id 类 (author 发布者 — 默认 sha).
        render_field(&mut out, "author", &self.author, FieldCategory::Id, mode);
        // 数字/元数据 — 直塞 (tid 雪花 id 非 PII; 读状态元数据)。
        out.insert("tid".to_string(), Value::from(self.tid));
        out.insert("create_time".to_string(), Value::from(self.create_time));
        out.insert("last_read_time".to_string(), Value::from(self.last_read_time));
        out.insert("is_read".to_string(), Value::from(self.is_read));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): author (发布者 wxid) 经 sha8; tid/时刻/读状态数字明文; provenance 自遮。
impl fmt::Debug for MomentFeedCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MomentFeedCreate")
            .field("provenance", &self.provenance)
            .field("tid", &self.tid)
            .field("author_sha8", &sha8(self.author.as_bytes()))
            .field("create_time", &self.create_time)
            .field("last_read_time", &self.last_read_time)
            .field("is_read", &self.is_read)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> MomentFeedCreate {
        MomentFeedCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "sns.db".to_string(),
                source_native_id: "MomentFeed_-3652952694686404033".to_string(),
                event_type: EventType::MomentFeedUpdate,
                event_action: EventAction::Create,
                event_seq: 5,
                ingest_time: 1_700_000_000_000,
            },
            // 真库样本 (2026-07-06 inspect SnsTopItem_1)。
            tid: -3_652_952_694_686_404_033,
            author: "wxid_ijkl5678mnop901".to_string(),
            create_time: 1_763_557_360,
            last_read_time: 1_779_501_771,
            is_read: 1,
        }
    }

    /// 默认模式: author 脱敏 _sha; tid/create_time/读状态照原; summary 不存 (无字段)。
    #[test]
    fn payload_default_redacts() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["author_sha"], Value::from(sha256_hex("wxid_ijkl5678mnop901")));
        assert!(!o.contains_key("author"), "K-R4: 默认不出裸发布者 wxid");
        assert_eq!(o["tid"], Value::from(-3_652_952_694_686_404_033_i64));
        assert_eq!(o["create_time"], Value::from(1_763_557_360_i64));
        assert_eq!(o["last_read_time"], Value::from(1_779_501_771_i64));
        assert_eq!(o["is_read"], Value::from(1));
        assert!(!o.contains_key("summary"), "summary 全空不落");
    }

    /// plaintext: author 明文 (ADR-427)。
    #[test]
    fn payload_plaintext_exposes() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["author"], Value::from("wxid_ijkl5678mnop901"));
    }

    /// K-R4: 默认 payload + Debug 不泄裸发布者 wxid。
    #[test]
    fn k_r4_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        let dbg = format!("{:?}", sample());
        for raw in ["wxid_ijkl5678mnop901", "wxid_acct_001"] {
            assert!(!dumped.contains(raw), "K-R4: payload 泄裸值 {raw}");
            assert!(!dbg.contains(raw), "K-R4: Debug 泄裸值 {raw}");
        }
        assert!(dbg.contains("author_sha8"));
    }
}
