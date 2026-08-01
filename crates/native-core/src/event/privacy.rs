//! event::privacy — payload_json 隐私过滤模型 (ADR-412 §3.y 单一收敛真源).
//!
//! 本 mod = PR2-3-b 核: 字段类别 4 桶 + 隐私 3 开关 + `render_field` 输出渲染.
//! 各事件字段集 struct (PR2-3-c+) 调 `render_field` 把 raw 值按类别 + 模式写进 payload_json map.
//!
//! ## K-R4 红线 (明文 wxid / 正文绝不裸出)
//! - 默认模式 (无开关): id / display_name / text_content 类全 sha256 脱敏; 只有元数据类明文.
//! - `render_field` 是 payload_json【字符串字段】输出的唯一脱敏关口 — 字段集 struct 不准绕过它直塞明文.
//! - 数字元数据 (时间戳 / 序号 / `_len`) 天然非 wxid/正文, 调用方直接塞 (不经本关口, 按构造安全).
//!
//! ## 真源
//! ADR-412 §3.y.1 (4 桶 × 3 开关) / §3.y.4 (默认模式输出) / §3.y.5 (id 类 plaintext 澄清).
//! `_len` = 字符长度 i64 (§3.x.1 字段表 line 270); `_sha` = sha256 全 hex 64 字符 (§3.y.5 line 513).

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// 字段类别 4 桶 (ADR-412 §3.y.1 — 决定脱敏策略).
///
/// 归桶严格跟 §3.x 字段集表对齐:
/// - `Metadata`: 时间戳 / 序号 / 类型枚举 / 长度 / **server_id** — 永远明文 (§3.y.5 例外:
///   server_id 是微信内部整数 id, 隐私无关, 归元数据类 **不属 id 类**)
/// - `Id`: wxid / chatroom_id / message_id 族 (sender_wxid / username / owner_wxid /
///   member_wxid / conv_id / account_id) — 默认 `_sha`, 仅 `--enable-plaintext` 明文
///   ⚠️ **source_native_id 不走本桶** (§3.y.5 例外) — 它是调用方**预合成的复合 md5 锚点**
///   (e.g. `"cursor:<db>:<kind>:<md5_hex(...)>"` / `"error:<code>:<md5_hex(...)>"`),
///   **永不含裸 wxid / chatroom_id**, 即使 `--enable-plaintext` 也保持 md5 复合格式 (不解码回明文).
///   调用方按 `Metadata` 风格原样塞 (`Value::String`), 不经 `Id` 桶脱敏
/// - `DisplayName`: 昵称 / 备注 / 别名 / 群名 / 群公告 — 默认 `_sha` + `_len`,
///   `--enable-display-name` 或 `--enable-plaintext` 明文
/// - `TextContent`: 消息正文 / 错误消息 / 上下文 JSON — 默认 `_sha` + `_len`,
///   `--enable-text-content` 或 `--enable-plaintext` 明文
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCategory {
    /// 永远明文 (时间戳 / 序号 / 类型枚举 / 长度 / server_id).
    Metadata,
    /// 默认 sha, 仅总开关明文 (wxid / chatroom_id 族; source_native_id 除外).
    Id,
    /// 默认 sha + len, display 或总开关明文 (昵称 / 备注 / 群名 / 公告).
    DisplayName,
    /// 默认 sha + len, text 或总开关明文 (正文 / 错误消息 / 上下文 JSON).
    TextContent,
}

/// 隐私 3 开关 (ADR-412 §3.y.1 + raw-payload §7.1) — 控制 payload_json 明文范围.
///
/// 优先级 (§3.y.1 line 450-453):
///   1. `enable_plaintext`【最高总开关】 — 等同所有开关全开 + id 类也明文 (元数据类一直明文)
///   2. `enable_display_name` + `enable_text_content` 可独立同开 — 类别并集
///   3. 默认 (全 false) — id / display_name / text_content 全 sha 脱敏 (K-R4 安全缺省)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrivacyMode {
    /// 仅 display_name 类输出明文 (不影响 id / text 类).
    pub enable_display_name: bool,
    /// 仅 text_content 类输出明文 (不影响 id / display 类).
    pub enable_text_content: bool,
    /// 总开关 — id / display_name / text_content 全明文 (元数据类本就明文).
    pub enable_plaintext: bool,
}

impl PrivacyMode {
    /// 全 sha 脱敏模式 (无任何开关)。
    ///
    /// ⚠️ ADR-426 §2.2 翻转后**不再是 archive 写入缺省** (archive 默认明文 [`Self::archive_canonical`]);
    /// 本模式供【出底座边界】(导出/API/缓存) 脱敏 (§2.4 KI-3 关口 — 底座内存明文真值, 出边界才脱敏)。
    #[must_use]
    pub fn default_sha() -> Self {
        Self::default()
    }

    /// 底座 archive 写入模式 (ADR-426 §2.2): 全明文 canonical。
    ///
    /// archive `payload_json` = 底座内 canonical storage (溯源/重放), 存第一类真实数据明文; 脱敏上移
    /// 出底座边界 (§2.4)。= `enable_plaintext` (id/display/text 全明文; 元数据本就明文)。
    #[must_use]
    pub fn archive_canonical() -> Self {
        Self {
            enable_plaintext: true,
            enable_display_name: false,
            enable_text_content: false,
        }
    }

    /// 某字段类别在当前模式下是否输出明文 (§3.y.1 优先级).
    ///
    /// - 元数据类: 永远明文 (跟隐私无关)
    /// - id 类: 仅 `enable_plaintext` 总开关 (§3.y.5 — display/text 开关**不影响** id)
    /// - display_name 类: `enable_plaintext || enable_display_name`
    /// - text_content 类: `enable_plaintext || enable_text_content`
    #[must_use]
    pub fn is_plaintext(self, category: FieldCategory) -> bool {
        match category {
            FieldCategory::Metadata => true,
            FieldCategory::Id => self.enable_plaintext,
            FieldCategory::DisplayName => self.enable_plaintext || self.enable_display_name,
            FieldCategory::TextContent => self.enable_plaintext || self.enable_text_content,
        }
    }
}

/// sha256 全 hex (64 字符) — payload_json `_sha` 后缀值 (ADR-412 §3.y.5 / ADR-413 §3 "64 ASCII chars").
///
/// ⚠️ 跟 log 脱敏的 [`crate::sha8`] (8 字符短锚点) 区分: 本函数是 payload 契约值, 全 32 字节 hex.
#[must_use]
pub fn sha256_hex(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// 把一个【字符串字段】按类别 + 隐私模式渲染进 payload_json map (ADR-412 §3.y.4 唯一脱敏关口).
///
/// `base_name` = 无后缀基名 (e.g. `"sender_wxid"` / `"text_content"` / `"server_id"`).
/// 输出 key (跟 §3.y.4):
/// - 元数据类: `base_name` = raw (永远明文原名)
/// - id 类 — 默认: `{base_name}_sha` = sha256 (**无 `_len`**, §3.y.4 line 504); 明文: `base_name` = raw
/// - display_name / text_content 类 — 默认: `{base_name}_sha` = sha256 + `{base_name}_len` = 字符长度;
///   明文: `base_name` = raw
///
/// ⚠️ K-R4: 字段集 struct 的敏感字符串字段必须经本函数出 payload, 不准绕过直塞明文.
/// ⚠️ source_native_id 不用本函数 (§3.y.5 例外): 它必须是调用方预合成的复合 md5 锚点,
///   **永不含裸 wxid/chatroom_id**, 即使 plaintext 模式也原样保持 md5 (调用方按 `Value::String` 直塞).
/// ⚠️ 数字元数据 (时间戳 / 序号 / `_len`) 不用本函数 (天然非敏感, 调用方按 `Value::from(i64)` 直接塞).
pub fn render_field(
    out: &mut Map<String, Value>,
    base_name: &str,
    raw: &str,
    category: FieldCategory,
    mode: PrivacyMode,
) {
    if mode.is_plaintext(category) {
        // 明文模式 (含元数据类永远): 无后缀原名.
        out.insert(base_name.to_string(), Value::from(raw));
        return;
    }
    // sha 脱敏模式 (默认): _sha 后缀.
    out.insert(format!("{base_name}_sha"), Value::from(sha256_hex(raw)));
    // display_name / text_content 类额外带 _len 字符长度 (id 类无 _len, §3.y.4 line 504-505).
    if matches!(category, FieldCategory::DisplayName | FieldCategory::TextContent) {
        let len = i64::try_from(raw.chars().count()).unwrap_or(i64::MAX);
        out.insert(format!("{base_name}_len"), Value::from(len));
    }
}

/// 渲染【可空】敏感字符串字段 (§3.x nullable 列, e.g. remark / alias / announcement / owner_wxid).
///
/// `Some(v)` → 同 [`render_field`]. `None` → 按类别输出 **null 占位**, 保持 key 结构跟 `Some` 一致
/// (schema 稳定, 消费方不必区分"字段缺失"vs"值为空"):
/// - 明文模式 (含元数据): `base_name` = null
/// - id 类 sha 模式: `{base_name}_sha` = null (无 _len)
/// - display_name / text_content 类 sha 模式: `{base_name}_sha` = null + `{base_name}_len` = null
///
/// ⚠️ K-R4 同 [`render_field`]: None 也不会泄漏 (null 占位无内容).
pub fn render_opt_field(
    out: &mut Map<String, Value>,
    base_name: &str,
    raw: Option<&str>,
    category: FieldCategory,
    mode: PrivacyMode,
) {
    match raw {
        Some(v) => render_field(out, base_name, v, category, mode),
        None => {
            if mode.is_plaintext(category) {
                out.insert(base_name.to_string(), Value::Null);
            } else {
                out.insert(format!("{base_name}_sha"), Value::Null);
                if matches!(category, FieldCategory::DisplayName | FieldCategory::TextContent) {
                    out.insert(format!("{base_name}_len"), Value::Null);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认模式 (全 sha): id → 仅 _sha (无 _len); display/text → _sha + _len; 元数据 → 原名明文.
    #[test]
    fn default_sha_redacts_all_sensitive() {
        let mode = PrivacyMode::default_sha();
        let mut out = Map::new();
        render_field(&mut out, "sender_wxid", "wxid_abc", FieldCategory::Id, mode);
        render_field(&mut out, "nick_name", "小明", FieldCategory::DisplayName, mode);
        render_field(&mut out, "text_content", "hello", FieldCategory::TextContent, mode);
        render_field(&mut out, "server_id", "123456", FieldCategory::Metadata, mode);

        // id 类: 只有 _sha, 无明文, 无 _len (§3.y.4 line 504)
        assert_eq!(out["sender_wxid_sha"], Value::from(sha256_hex("wxid_abc")));
        assert!(!out.contains_key("sender_wxid"), "id 类默认不准出明文 (K-R4)");
        assert!(!out.contains_key("sender_wxid_len"), "id 类无 _len");
        // display 类: _sha + _len
        assert_eq!(out["nick_name_sha"], Value::from(sha256_hex("小明")));
        assert_eq!(out["nick_name_len"], Value::from(2_i64));
        assert!(!out.contains_key("nick_name"), "display 类默认不准出明文");
        // text 类: _sha + _len
        assert_eq!(out["text_content_sha"], Value::from(sha256_hex("hello")));
        assert_eq!(out["text_content_len"], Value::from(5_i64));
        assert!(!out.contains_key("text_content"), "text 类默认不准出明文 (K-R4)");
        // 元数据类: 原名明文
        assert_eq!(out["server_id"], Value::from("123456"));
    }

    /// id 类只受 plaintext 总开关 (§3.y.5) — display/text 开关不影响它.
    #[test]
    fn id_only_honors_plaintext_switch() {
        let id = FieldCategory::Id;
        assert!(!PrivacyMode::default_sha().is_plaintext(id));
        // display / text 开关不动 id
        assert!(!PrivacyMode {
            enable_display_name: true,
            ..Default::default()
        }
        .is_plaintext(id));
        assert!(!PrivacyMode {
            enable_text_content: true,
            ..Default::default()
        }
        .is_plaintext(id));
        assert!(
            !PrivacyMode {
                enable_display_name: true,
                enable_text_content: true,
                ..Default::default()
            }
            .is_plaintext(id),
            "display+text 同开也不动 id (§3.y.5)"
        );
        // 仅总开关明文
        assert!(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        }
        .is_plaintext(id));
    }

    /// 仅 --enable-display-name: display 明文, id/text 仍 sha (§3.y.3 矩阵).
    #[test]
    fn display_name_switch_isolates() {
        let mode = PrivacyMode {
            enable_display_name: true,
            ..Default::default()
        };
        let mut out = Map::new();
        render_field(&mut out, "nick_name", "小明", FieldCategory::DisplayName, mode);
        render_field(&mut out, "sender_wxid", "wxid_abc", FieldCategory::Id, mode);
        render_field(&mut out, "text_content", "hi", FieldCategory::TextContent, mode);
        // display 明文 (无后缀, 无 _len)
        assert_eq!(out["nick_name"], Value::from("小明"));
        assert!(!out.contains_key("nick_name_sha"));
        assert!(!out.contains_key("nick_name_len"));
        // id / text 仍 sha
        assert!(out.contains_key("sender_wxid_sha"));
        assert!(out.contains_key("text_content_sha"));
        assert!(!out.contains_key("text_content"), "text 不受 display 开关影响");
    }

    /// 仅 --enable-text-content: text 明文, id/display 仍 sha (§3.y.3 矩阵).
    #[test]
    fn text_content_switch_isolates() {
        let mode = PrivacyMode {
            enable_text_content: true,
            ..Default::default()
        };
        let mut out = Map::new();
        render_field(&mut out, "text_content", "hi", FieldCategory::TextContent, mode);
        render_field(&mut out, "sender_wxid", "wxid_abc", FieldCategory::Id, mode);
        render_field(&mut out, "nick_name", "小明", FieldCategory::DisplayName, mode);
        // text 明文
        assert_eq!(out["text_content"], Value::from("hi"));
        assert!(!out.contains_key("text_content_sha"));
        // id / display 仍 sha
        assert!(out.contains_key("sender_wxid_sha"));
        assert!(out.contains_key("nick_name_sha"), "display 不受 text 开关影响");
    }

    /// --enable-plaintext 总开关: id/display/text 全明文 (无后缀), 元数据仍明文 (§3.y.3 矩阵).
    #[test]
    fn plaintext_switch_opens_all() {
        let mode = PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        };
        let mut out = Map::new();
        render_field(&mut out, "sender_wxid", "wxid_abc", FieldCategory::Id, mode);
        render_field(&mut out, "nick_name", "小明", FieldCategory::DisplayName, mode);
        render_field(&mut out, "text_content", "hello", FieldCategory::TextContent, mode);
        assert_eq!(out["sender_wxid"], Value::from("wxid_abc"));
        assert_eq!(out["nick_name"], Value::from("小明"));
        assert_eq!(out["text_content"], Value::from("hello"));
        // 全无后缀
        for k in ["sender_wxid_sha", "nick_name_sha", "nick_name_len", "text_content_sha"] {
            assert!(!out.contains_key(k), "总开关后无 {k} 后缀");
        }
    }

    /// ADR-426 §2.2: archive_canonical (底座 archive 写入缺省) = 全明文 (id/display/text 全 plaintext).
    #[test]
    fn archive_canonical_is_all_plaintext() {
        let mode = PrivacyMode::archive_canonical();
        assert!(mode.is_plaintext(FieldCategory::Id), "archive id 类明文");
        assert!(mode.is_plaintext(FieldCategory::DisplayName), "archive display 类明文");
        assert!(mode.is_plaintext(FieldCategory::TextContent), "archive text 类明文");
        assert!(mode.is_plaintext(FieldCategory::Metadata));
        // 等价 enable_plaintext 总开关
        assert_eq!(
            mode,
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            }
        );
    }

    /// 元数据类在所有模式下永远明文原名.
    #[test]
    fn metadata_always_plaintext() {
        for mode in [
            PrivacyMode::default_sha(),
            PrivacyMode {
                enable_display_name: true,
                ..Default::default()
            },
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        ] {
            assert!(mode.is_plaintext(FieldCategory::Metadata));
            let mut out = Map::new();
            render_field(&mut out, "source", "wechat", FieldCategory::Metadata, mode);
            assert_eq!(out["source"], Value::from("wechat"));
            assert!(!out.contains_key("source_sha"));
        }
    }

    /// sha256_hex 是 64 字符全 hex, 确定性, 跟 sha8 (8 字符) 区分.
    #[test]
    fn sha256_hex_is_64_chars_deterministic() {
        let a = sha256_hex("wxid_abc");
        let b = sha256_hex("wxid_abc");
        assert_eq!(a, b, "确定性");
        assert_eq!(a.len(), 64, "全 sha256 hex = 64 字符 (≠ sha8 的 8)");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, sha256_hex("wxid_xyz"), "不同输入不同 hash");
    }

    /// K-R4 红线: 默认模式下 raw wxid / 正文绝不出现在任何 value 里.
    #[test]
    fn default_mode_never_leaks_raw_sensitive() {
        let mode = PrivacyMode::default_sha();
        let mut out = Map::new();
        render_field(&mut out, "sender_wxid", "wxid_secret_001", FieldCategory::Id, mode);
        render_field(
            &mut out,
            "text_content",
            "私密正文内容",
            FieldCategory::TextContent,
            mode,
        );
        let dumped = serde_json::to_string(&out).unwrap();
        assert!(!dumped.contains("wxid_secret_001"), "K-R4: 默认模式裸 wxid 泄漏!");
        assert!(!dumped.contains("私密正文内容"), "K-R4: 默认模式裸正文泄漏!");
    }

    /// _len 是字符长度不是字节长度 (§3.x.1 字段表 "字符长度") — 中文 2 字符 ≠ 6 字节.
    #[test]
    fn len_is_char_count_not_byte() {
        let mode = PrivacyMode::default_sha();
        let mut out = Map::new();
        render_field(&mut out, "text_content", "中文", FieldCategory::TextContent, mode);
        // "中文" = 2 字符 / 6 UTF-8 字节 — 契约是字符数
        assert_eq!(out["text_content_len"], Value::from(2_i64));
    }

    /// render_opt_field: None 按类别出 null 占位 (key 结构跟 Some 一致, schema 稳定).
    #[test]
    fn render_opt_field_none_yields_null_placeholders() {
        let def = PrivacyMode::default_sha();
        // id 类 None: 仅 _sha = null (无 _len)
        let mut o = Map::new();
        render_opt_field(&mut o, "owner_wxid", None, FieldCategory::Id, def);
        assert_eq!(o["owner_wxid_sha"], Value::Null);
        assert!(!o.contains_key("owner_wxid_len"), "id 类无 _len");
        assert!(!o.contains_key("owner_wxid"));
        // display 类 None: _sha + _len 都 null
        let mut o2 = Map::new();
        render_opt_field(&mut o2, "remark", None, FieldCategory::DisplayName, def);
        assert_eq!(o2["remark_sha"], Value::Null);
        assert_eq!(o2["remark_len"], Value::Null);
        // 明文模式 None: base = null
        let mut o3 = Map::new();
        let pt = PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        };
        render_opt_field(&mut o3, "remark", None, FieldCategory::DisplayName, pt);
        assert_eq!(o3["remark"], Value::Null);
        assert!(!o3.contains_key("remark_sha"));
    }

    /// render_opt_field: Some 跟 render_field 完全一致 (委托).
    #[test]
    fn render_opt_field_some_delegates_to_render_field() {
        let def = PrivacyMode::default_sha();
        let mut a = Map::new();
        let mut b = Map::new();
        render_opt_field(&mut a, "remark", Some("老王"), FieldCategory::DisplayName, def);
        render_field(&mut b, "remark", "老王", FieldCategory::DisplayName, def);
        assert_eq!(a, b);
    }
}
