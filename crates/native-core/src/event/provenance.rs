//! event::provenance — raw_payload 每条事件的共享溯源头 (ADR-412 §3.x provenance 7 字段).
//!
//! 本 mod = PR2-3-c: [`Provenance`] struct + [`Provenance::render_into`] payload 渲染.
//! 各事件字段集 struct (PR2-3-d+: MessageCreate / ContactUpdate 等) **嵌**本 struct, 复用 7 字段 +
//! render_into (DRY — provenance 字段在 §3.x 7 张表逐行重复, 单一真相收敛到这里).
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 `account_id` 裸 wxid 被任意 `to_json` 误序列化泄漏.
//!   唯一出 payload 路径 = [`Provenance::render_into`] (经 [`privacy::render_field`] 脱敏关口).
//! - `account_id` 用 [`Wxid`] 类型 (Debug/Display 自遮明文), 故本 struct `#[derive(Debug)]` 安全.
//! - `source_native_id` 是调用方预合成的复合 md5 锚点, **永不含裸 wxid**, plaintext 也保持 md5 (§3.y.5 例外).

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::{EventAction, EventType};
use crate::key_provider::Wxid;

/// raw_payload 事件共享溯源头 (ADR-412 §3.x provenance 7 字段 — 每事件字段集首段).
///
/// 字段归桶 (§3.y.1):
/// - `account_id`: **id 类** — 默认 `account_id_sha`, `--enable-plaintext` 后明文
/// - `source` / `event_type` / `event_action` / `event_seq` / `ingest_time`: **元数据类** — 永远明文
/// - `source_native_id`: **id 类例外** — 复合 md5 锚点, 永不脱敏也永不明文化 (原样直塞, §3.y.5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// 多账号隔离 — 本数据属哪个微信账号 (id 类: 默认 `account_id_sha`, plaintext 后明文).
    pub account_id: Wxid,
    /// 源 db 文件名 (元数据, e.g. `"message_5.db"`).
    pub source: String,
    /// 复合内部锚点 (e.g. `"Msg_<md5_hex(conv_id)>:<localId>"`) — 调用方预合成,
    /// **永不含裸 wxid/chatroom_id**, 即使 plaintext 也保持 md5 复合格式 (§3.y.5 例外).
    pub source_native_id: String,
    /// 事件类型 (元数据枚举, 永远明文 snake_case — e.g. `"message"`).
    pub event_type: EventType,
    /// 事件动作 (元数据枚举, 永远明文 snake_case — e.g. `"create"`).
    pub event_action: EventAction,
    /// ADR-413 fingerprint 生成的稳定序号 (元数据; i63 取值范围, 重放幂等). 由 fingerprint 计算填.
    pub event_seq: i64,
    /// adapter emit 时间 (毫秒, 元数据; 临时字段不进 fingerprint).
    pub ingest_time: i64,
}

impl Provenance {
    /// 把 7 个 provenance 字段按隐私模式渲染进 payload_json map (ADR-412 §3.y 唯一出口).
    ///
    /// 渲染规则:
    /// - `account_id`: 经 [`render_field`] id 类脱敏 (默认 `account_id_sha` / plaintext `account_id`)
    /// - `source`: 经 [`render_field`] 元数据 (原名明文)
    /// - `source_native_id`: 例外 — **不经 render_field**, 原样直塞 (复合 md5 锚点, §3.y.5)
    /// - `event_type` / `event_action`: 枚举 as_str 直塞 (元数据, 永远明文 snake_case)
    /// - `event_seq` / `ingest_time`: 数字直塞 (元数据, 天然非敏感)
    ///
    /// 注: provenance 无 display_name / text_content 类字段, 故 `enable_display_name` /
    /// `enable_text_content` 开关不改变本段输出 — 只有 `enable_plaintext` 影响 `account_id`.
    pub fn render_into(&self, out: &mut Map<String, Value>, mode: PrivacyMode) {
        // id 类 — 唯一受隐私模式影响的 provenance 字段 (K-R4: 必经脱敏关口).
        render_field(out, "account_id", self.account_id.as_str(), FieldCategory::Id, mode);
        // 元数据自由串 — 经关口走元数据路径 (原名明文).
        render_field(out, "source", &self.source, FieldCategory::Metadata, mode);
        // 例外: 复合 md5 锚点, 永不脱敏/明文化, 原样直塞 (§3.y.5).
        out.insert(
            "source_native_id".to_string(),
            Value::from(self.source_native_id.as_str()),
        );
        // 枚举元数据 — canonical snake_case 串直塞.
        out.insert("event_type".to_string(), Value::from(self.event_type.as_str()));
        out.insert("event_action".to_string(), Value::from(self.event_action.as_str()));
        // 数字元数据 — 直塞 (i63 序号 / emit 时间).
        out.insert("event_seq".to_string(), Value::from(self.event_seq));
        out.insert("ingest_time".to_string(), Value::from(self.ingest_time));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Provenance {
        Provenance {
            account_id: Wxid::try_new("wxid_acct_001".to_string()).unwrap(),
            source: "message_5.db".to_string(),
            source_native_id: "Msg_a1b2c3d4:1009".to_string(),
            event_type: EventType::Message,
            event_action: EventAction::Create,
            event_seq: 1_234_567_890,
            ingest_time: 1_700_000_000_000,
        }
    }

    /// 默认模式: account_id 脱敏成 _sha (64 hex), 无裸 account_id; 元数据照原.
    #[test]
    fn render_default_redacts_account_id() {
        let mut out = Map::new();
        sample().render_into(&mut out, PrivacyMode::default_sha());

        // id 类脱敏: 只有 _sha, 无裸值
        let sha = super::super::privacy::sha256_hex("wxid_acct_001");
        assert_eq!(out["account_id_sha"], Value::from(sha));
        assert!(!out.contains_key("account_id"), "K-R4: 默认模式不准出裸 account_id");
        // 元数据照原
        assert_eq!(out["source"], Value::from("message_5.db"));
        assert_eq!(out["source_native_id"], Value::from("Msg_a1b2c3d4:1009"));
        assert_eq!(out["event_type"], Value::from("message"));
        assert_eq!(out["event_action"], Value::from("create"));
        assert_eq!(out["event_seq"], Value::from(1_234_567_890_i64));
        assert_eq!(out["ingest_time"], Value::from(1_700_000_000_000_i64));
    }

    /// plaintext 总开关: account_id 出明文 (无后缀); source_native_id 例外仍是 md5 锚点不变.
    #[test]
    fn render_plaintext_exposes_account_id_but_anchor_stays_md5() {
        let mut out = Map::new();
        let mode = PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        };
        sample().render_into(&mut out, mode);

        assert_eq!(
            out["account_id"],
            Value::from("wxid_acct_001"),
            "plaintext 后 account_id 明文"
        );
        assert!(!out.contains_key("account_id_sha"), "明文模式无 _sha 后缀");
        // 例外: source_native_id 即使 plaintext 也原样 (复合 md5 锚点不解码)
        assert_eq!(
            out["source_native_id"],
            Value::from("Msg_a1b2c3d4:1009"),
            "§3.y.5 例外: source_native_id plaintext 下也保持 md5 锚点"
        );
    }

    /// source_native_id 在默认 / plaintext 两模式下值完全一致 (永不变, §3.y.5 例外强约束).
    #[test]
    fn source_native_id_identical_across_modes() {
        let mut def = Map::new();
        let mut pt = Map::new();
        sample().render_into(&mut def, PrivacyMode::default_sha());
        sample().render_into(
            &mut pt,
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        );
        assert_eq!(def["source_native_id"], pt["source_native_id"]);
    }

    /// display/text 开关不改变 provenance 输出 (本段无 display/text 类字段).
    #[test]
    fn display_text_switches_dont_affect_provenance() {
        let mut base = Map::new();
        sample().render_into(&mut base, PrivacyMode::default_sha());
        let mut with_dt = Map::new();
        sample().render_into(
            &mut with_dt,
            PrivacyMode {
                enable_display_name: true,
                enable_text_content: true,
                ..Default::default()
            },
        );
        assert_eq!(base, with_dt, "provenance 无 display/text 字段, 这俩开关不应改变输出");
    }

    /// K-R4: Provenance Debug 不泄裸 account_id (Wxid 自遮).
    #[test]
    fn debug_redacts_account_id() {
        let dbg = format!("{:?}", sample());
        assert!(
            !dbg.contains("wxid_acct_001"),
            "K-R4: Provenance Debug 泄漏裸 account_id!"
        );
    }

    /// codex r1 P2: plaintext 总开关【只】改变 account_id, 其余 6 字段跨模式完全一致 (回归守卫).
    /// 防将来误把 source / event_seq / ingest_time 等元数据/例外字段也跟 plaintext 联动.
    #[test]
    fn plaintext_only_changes_account_id_field() {
        let mut def = Map::new();
        let mut pt = Map::new();
        sample().render_into(&mut def, PrivacyMode::default_sha());
        sample().render_into(
            &mut pt,
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        );
        // 剔除受模式影响的 account_id 系列 (默认 _sha / plaintext 无后缀), 其余应全等
        def.remove("account_id_sha");
        pt.remove("account_id");
        assert_eq!(def, pt, "plaintext 只应改 account_id, 其余 6 字段不准变 (回归守卫)");
        // 且剔除后剩的就是 6 个非 account 字段 (无额外敏感键残留)
        assert_eq!(def.len(), 6, "provenance 除 account_id 外应恰 6 字段");
        for k in ["account_id", "account_id_sha"] {
            assert!(!def.contains_key(k), "剔除后不应再有 {k}");
        }
    }

    /// 枚举字段在所有模式都是明文 snake_case 串.
    #[test]
    fn enum_fields_always_snake_case_plaintext() {
        for mode in [
            PrivacyMode::default_sha(),
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        ] {
            let mut out = Map::new();
            let mut p = sample();
            p.event_type = EventType::SystemEvent;
            p.event_action = EventAction::CursorUpdate;
            p.render_into(&mut out, mode);
            assert_eq!(out["event_type"], Value::from("system_event"));
            assert_eq!(out["event_action"], Value::from("cursor_update"));
        }
    }
}
