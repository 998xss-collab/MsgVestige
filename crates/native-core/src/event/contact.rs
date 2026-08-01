//! event::contact — (contact_update, create) 事件字段集 (ADR-412 §3.x.2).
//!
//! 本 mod = PR2-3-e: [`ContactUpdate`] struct — **第一个含 display_name 类字段的事件** (nick_name /
//! remark / alias), 验证 [`privacy`] 的 DisplayName 桶 + 可空字段渲染 ([`privacy::render_opt_field`]).
//! 照 [`super::message::MessageCreate`] 模板 (嵌 [`Provenance`] + to_payload_json + 手写 Debug + 不 derive Serialize).
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`** — 防 username / nick_name / remark / alias 裸值被误序列化.
//! - **手写 `Debug`** — username / nick_name / remark / alias 经 [`sha8`] 脱敏; provenance.account_id 自遮.
//!
//! ## username 为何用 String 不用 Wxid
//! 联系人 username 是异构微信 UserName (个人 wxid_ / 自定义号 / 公众号 gh_ / filehelper / 群 @chatroom 等).
//! 用 String 跟 message 的 conv_id 一致 — 事件字段层统一持原始 UserName + render_field id 类脱敏 (投影/
//! 命名边界保留 raw UserName, **非**因 [`Wxid::try_new`] 有格式约束; PR2-12-d-pre 后 Wxid 也已不卡前缀).

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, render_opt_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (contact_update, create) 事件字段集 (ADR-412 §3.x.2) — 一个联系人.
///
/// 字段归桶 (§3.y.1): username = **id 类**; nick_name / remark / alias = **display_name 类**
/// (默认 _sha + _len, --enable-display-name 或 plaintext 明文); local_type / is_in_chat_room = **元数据类**.
/// text_content 类: 无 (contact 源表无消息正文).
pub struct ContactUpdate {
    /// 共享溯源头 7 字段 (source_native_id = `"Contact_<md5_hex(username)>"`).
    pub provenance: Provenance,

    // ── 业务字段 (§3.x.2) ──
    /// 联系人 id raw (id 类: 异构 wxid_/gh_/filehelper 等; 默认 username_sha).
    pub username: String,
    /// 昵称 (display_name 类: 默认 nick_name_sha + nick_name_len).
    pub nick_name: String,
    /// 备注 (display_name 类, nullable: 默认 remark_sha + remark_len, None → null 占位).
    pub remark: Option<String>,
    /// 别名 (display_name 类, nullable: 默认 alias_sha + alias_len, None → null 占位).
    pub alias: Option<String>,
    /// 联系人 type 1=好友 / 2=群(chatroom 会话) / 4=群成员 (元数据; is_muted 靠 local_type==2 判群, 真库 1204 行实证)。
    pub local_type: i32,
    /// 是否在群里 (元数据).
    pub is_in_chat_room: bool,

    // ── 拼音搜索列 (display_name 类, nullable; 进 L2 person 表**不进 content_digest** — 派生自 nick/remark,
    //     nick/remark 变则 digest 变触发更新, 拼音跟着更新一致; 故不扩 ADR-412 §3.x.2 digest 字段集/不 supersede)。
    /// 昵称全拼 (quan_pin; 搜索用, 可空).
    pub quan_pin: Option<String>,
    /// 昵称拼音首字母 (pin_yin_initial; 可空).
    pub pin_yin_initial: Option<String>,
    /// 备注全拼 (remark_quan_pin; 可空).
    pub remark_quan_pin: Option<String>,
    /// 备注拼音首字母 (remark_pin_yin_initial; 可空).
    pub remark_pin_yin_initial: Option<String>,

    // ── 状态标志 (元数据类, i64; **进 content_digest** 溯源 — verify/delete 是独立状态非派生:
    //     好友验证/软删除能独立于 nick/remark 变化 → 进 digest 才能追"何时删/验"。字段集 6→8, supersede ADR-412)。
    /// 好友验证标志 (verify_flag; 元数据直塞, 不脱敏).
    pub verify_flag: i64,
    /// 软删除标志 (delete_flag; 元数据直塞, 不脱敏).
    pub delete_flag: i64,

    // ── 头像列 (资源类, nullable; **只进 L2 person 表, 不进 payload_json/archive, 不进 content_digest** — codex P1-1:
    //     头像独立不进 digest, 若进 payload 则 archive 按 fingerprint 去重致头像陈旧 (不像拼音跟 nick 走), 故只进 L2 UPSERT 保最新;
    //     big/small URL CDN 刷新噪音 + md5 高频低价值, 用户 2026-07-02 选 1 不溯源。见 ADR-450 §3)。
    /// 大头像 URL (big_head_url; 资源, 可空; 只进 L2 person, Debug sha8 脱敏).
    pub big_head_url: Option<String>,
    /// 小头像 URL (small_head_url; 资源, 可空).
    pub small_head_url: Option<String>,
    /// 头像内容 md5 (head_img_md5; 资源标识, 可空).
    pub head_img_md5: Option<String>,

    // ── 第五批 (2026-07-02): contact 补充列 (**只进 L2 person, 不进 payload_json/archive/content_digest** —
    //     同头像 L2-only 先例: 独立不进 digest → 若进 payload 则 archive 按 fingerprint 去重致陈旧)。
    /// 个性签名 / 描述 (description; 文本类, 可空; 只进 L2, Debug sha8 脱敏).
    pub description: Option<String>,
    /// 联系人标志位 (flag; 元数据 bitfield 含星标/黑名单等位; 只进 L2, digest 决策待定).
    pub flag: i64,
    /// 群消息通知设置 (chat_room_notify; 元数据).
    pub chat_room_notify: i64,
    /// 群类型 (chat_room_type; 元数据).
    pub chat_room_type: i64,

    // ── 第七批 (2026-07-02): extra_buffer 解出的扩展属性 (**只进 L2, 不进 payload_json/archive/digest** — 同第五批 L2-only)。
    /// 性别 (0未知/1男/2女; 元数据直显)。
    pub sex: i64,
    /// 国家 ISO 码 (地区, nullable; L2 明文, Debug sha8 脱敏)。
    pub country: Option<String>,
    /// 省 (地区, nullable; 英文/拼音, L2 明文, Debug sha8)。
    pub province: Option<String>,
    /// 市 (地区, nullable; L2 明文, Debug sha8)。
    pub city: Option<String>,
    /// 好友来源枚举 (元数据直显)。
    pub friend_source: i64,

    // ── 批 I (2026-07-04): extra_buffer 再解 (**只进 L2, 不进 payload_json/archive/digest** — 同第七批 L2-only)。
    /// 个性签名 (extra_buffer f4; 对方自设, nullable; L2 明文, 可含手机号 → Debug sha8 脱敏)。
    pub signature: Option<String>,
    /// 朋友圈封面图 URL (extra_buffer f27 内层 f2; 资源, nullable; L2, Debug sha8)。
    pub moments_cover_url: Option<String>,

    // ── 标签件: 联系人标签名 (**只进 L2 person, 不进 payload_json/archive/digest** — 同批 I L2-only)。
    /// 联系人标签名, 逗号分隔 (如 `"老板,客户"`; drain 端由 extra_buffer f30 标签 id 串 + `contact_label` 表
    /// id→名字 map 解好; 无标签 → None)。标签名用户自设可能敏感 (如 "老板") → L2 明文, Debug sha8 脱敏。
    pub labels: Option<String>,

    // ── 添加时间件 (ADR-486): 好友添加时间 (**只进 L2 person, 不进 payload_json/archive/digest** — 同批 I L2-only)。
    /// 好友添加时间 (extra_buffer f41 varint unix 秒; 无/老版本未回填 → None)。时间戳元数据, 非 PII, Debug 直显。
    pub friend_add_time: Option<i64>,

    // ── 企微件: 企微 (@openim) 联系人公司名/实名 (**只进 L2 person, 不进 payload_json/archive/digest** — 同批 I L2-only)。
    /// 企微公司名 (extra_buffer f4 内层 custom_info title=="企业" 的 detail[0].desc; 非企微 → None)。
    /// 公司全称可含敏感信息 → L2 明文, Debug sha8 脱敏。
    pub openim_company: Option<String>,
    /// 企微实名 (extra_buffer f4 内层 custom_info title=="实名" 的 detail[0].desc; 非企微 → None)。
    /// 真实姓名 = PII → L2 明文, Debug sha8 脱敏。
    pub openim_realname: Option<String>,
}

impl ContactUpdate {
    /// 渲染整条 contact_update.create 的 payload_json (ADR-412 §3.x.2 + §3.y, 唯一出口).
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);

        // id 类.
        render_field(&mut out, "username", &self.username, FieldCategory::Id, mode);
        // display_name 类 (nick_name 必有; remark / alias 可空).
        render_field(&mut out, "nick_name", &self.nick_name, FieldCategory::DisplayName, mode);
        render_opt_field(
            &mut out,
            "remark",
            self.remark.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "alias",
            self.alias.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        // 数字 / bool 元数据 — 直塞.
        out.insert("local_type".to_string(), Value::from(self.local_type));
        out.insert("is_in_chat_room".to_string(), Value::from(self.is_in_chat_room));
        // 拼音列 (display_name 类, nullable — 默认 _sha+_len, --enable-display-name/plaintext 出原文)。
        render_opt_field(
            &mut out,
            "quan_pin",
            self.quan_pin.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "pin_yin_initial",
            self.pin_yin_initial.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "remark_quan_pin",
            self.remark_quan_pin.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        render_opt_field(
            &mut out,
            "remark_pin_yin_initial",
            self.remark_pin_yin_initial.as_deref(),
            FieldCategory::DisplayName,
            mode,
        );
        // 状态标志 (元数据类 — 直塞, 同 local_type; 进 content_digest 但 payload 无脱敏需求)。
        out.insert("verify_flag".to_string(), Value::from(self.verify_flag));
        out.insert("delete_flag".to_string(), Value::from(self.delete_flag));
        // 头像列**不进 payload_json** (codex P1-1): 头像独立不进 content_digest → 若进 payload 则 archive
        // 按 fingerprint 去重、头像变不产新 archive → payload 头像陈旧 (不像拼音派生自 nick、跟 nick 更新)。
        // 故头像只进 L2 person (project_person UPSERT 每轮刷最新); payload / raw_payload_archive 完全不含头像。
        // 第五批 (description/flag/chat_room_notify/chat_room_type) 同理**不进 payload_json** (L2-only,
        // 独立不进 digest → 进 payload 会陈旧); 只走 project_person → L2 person UPSERT。
        // 第七批 (sex/country/province/city/friend_source, extra_buffer 解出) 同样**不进 payload_json** (L2-only)。
        // 批 I (signature/moments_cover_url, extra_buffer 再解) 同样**不进 payload_json** (L2-only)。
        // 标签件 (labels, extra_buffer f30 + contact_label map 解出) 同样**不进 payload_json** (L2-only)。
        // 添加时间件 (friend_add_time, extra_buffer f41) 同样**不进 payload_json** (L2-only; 独立不进 digest → 进 payload 会陈旧)。
        // 企微件 (openim_company/openim_realname, extra_buffer f4 内层 custom_info) 同样**不进 payload_json** (L2-only)。

        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): username / nick_name / remark / alias 经 sha8 脱敏; provenance 自遮.
/// **不准 derive Debug** — 会泄昵称 / 备注 / 别名裸值.
impl fmt::Debug for ContactUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let opt_sha8 = |o: &Option<String>| o.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("ContactUpdate")
            .field("provenance", &self.provenance)
            .field("username_sha8", &sha8(self.username.as_bytes()))
            .field("nick_name_sha8", &sha8(self.nick_name.as_bytes()))
            .field("remark_sha8", &opt_sha8(&self.remark))
            .field("alias_sha8", &opt_sha8(&self.alias))
            .field("quan_pin_sha8", &opt_sha8(&self.quan_pin))
            .field("pin_yin_initial_sha8", &opt_sha8(&self.pin_yin_initial))
            .field("remark_quan_pin_sha8", &opt_sha8(&self.remark_quan_pin))
            .field("remark_pin_yin_initial_sha8", &opt_sha8(&self.remark_pin_yin_initial))
            .field("local_type", &self.local_type)
            .field("is_in_chat_room", &self.is_in_chat_room)
            .field("verify_flag", &self.verify_flag)
            .field("delete_flag", &self.delete_flag)
            .field("big_head_url_sha8", &opt_sha8(&self.big_head_url))
            .field("small_head_url_sha8", &opt_sha8(&self.small_head_url))
            .field("head_img_md5_sha8", &opt_sha8(&self.head_img_md5))
            .field("description_sha8", &opt_sha8(&self.description))
            .field("flag", &self.flag)
            .field("chat_room_notify", &self.chat_room_notify)
            .field("chat_room_type", &self.chat_room_type)
            .field("sex", &self.sex)
            .field("country_sha8", &opt_sha8(&self.country))
            .field("province_sha8", &opt_sha8(&self.province))
            .field("city_sha8", &opt_sha8(&self.city))
            .field("friend_source", &self.friend_source)
            .field("signature_sha8", &opt_sha8(&self.signature))
            .field("moments_cover_url_sha8", &opt_sha8(&self.moments_cover_url))
            .field("labels_sha8", &opt_sha8(&self.labels))
            .field("friend_add_time", &self.friend_add_time) // 时间戳元数据, 非 PII → 直显
            .field("openim_company_sha8", &opt_sha8(&self.openim_company)) // 企微公司名 (可含敏感) → sha8
            .field("openim_realname_sha8", &opt_sha8(&self.openim_realname)) // 企微实名 (PII) → sha8
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::privacy::sha256_hex;
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> ContactUpdate {
        ContactUpdate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "contact.db".to_string(),
                source_native_id: "Contact_a1b2c3d4".to_string(),
                event_type: EventType::ContactUpdate,
                event_action: EventAction::Create,
                event_seq: 7,
                ingest_time: 1_700_000_000_000,
            },
            username: "wxid_friend_002".to_string(),
            nick_name: "小明".to_string(),
            remark: Some("老同学".to_string()),
            alias: None,
            local_type: 1,
            is_in_chat_room: false,
            quan_pin: Some("xiaoming".to_string()),
            pin_yin_initial: Some("xm".to_string()),
            remark_quan_pin: None,
            remark_pin_yin_initial: None,
            verify_flag: 0,
            delete_flag: 0,
            big_head_url: Some("https://wx.qlogo.cn/mmhead/ver_1/abc/0".to_string()),
            small_head_url: None,
            head_img_md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
            description: Some("爱生活".to_string()),
            flag: 0,
            chat_room_notify: 0,
            chat_room_type: 0,
            sex: 1,
            country: Some("CN".to_string()),
            province: Some("Zhejiang".to_string()),
            city: Some("Hangzhou".to_string()),
            friend_source: 3,
            signature: Some("热爱生活".to_string()),
            moments_cover_url: Some("http://shmmsns.qpic.cn/mmsns/xxx/0".to_string()),
            labels: Some("老板,客户".to_string()),
            friend_add_time: Some(1_698_674_704),
            openim_company: Some("某某科技有限公司".to_string()),
            openim_realname: Some("张三".to_string()),
        }
    }

    /// 默认模式: username 脱敏 _sha; display 类 _sha+_len; alias None → null 占位; 元数据照原.
    #[test]
    fn payload_default_redacts_id_and_display() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        // id 类
        assert_eq!(o["username_sha"], Value::from(sha256_hex("wxid_friend_002")));
        assert!(!o.contains_key("username"));
        // display 类 (nick_name 必有 + len)
        assert_eq!(o["nick_name_sha"], Value::from(sha256_hex("小明")));
        assert_eq!(o["nick_name_len"], Value::from(2_i64));
        assert!(!o.contains_key("nick_name"), "K-R4: 默认不准出裸昵称");
        // remark Some → _sha + _len
        assert_eq!(o["remark_sha"], Value::from(sha256_hex("老同学")));
        assert_eq!(o["remark_len"], Value::from(3_i64));
        // alias None → null 占位 (key 在, 值 null)
        assert_eq!(o["alias_sha"], Value::Null);
        assert_eq!(o["alias_len"], Value::Null);
        // 元数据照原
        assert_eq!(o["local_type"], Value::from(1));
        assert_eq!(o["is_in_chat_room"], Value::from(false));
    }

    /// plaintext: username + 全 display 明文; alias None → null; source_native_id 例外不变.
    #[test]
    fn payload_plaintext_exposes_all() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["username"], Value::from("wxid_friend_002"));
        assert_eq!(o["nick_name"], Value::from("小明"));
        assert_eq!(o["remark"], Value::from("老同学"));
        assert_eq!(o["alias"], Value::Null, "alias None plaintext 也 null");
        assert!(!o.contains_key("nick_name_sha"));
        assert_eq!(o["source_native_id"], Value::from("Contact_a1b2c3d4"));
    }

    /// --enable-display-name 只开 display 类, username (id) 仍 sha (§3.y.5 id 只受总开关).
    #[test]
    fn display_switch_opens_display_but_not_id() {
        let p = sample().to_payload_json(PrivacyMode {
            enable_display_name: true,
            ..Default::default()
        });
        let o = p.as_object().unwrap();
        assert_eq!(o["nick_name"], Value::from("小明"), "display 开关后昵称明文");
        assert_eq!(o["remark"], Value::from("老同学"));
        assert!(o.contains_key("username_sha"), "id 类不受 display 开关影响");
        assert!(!o.contains_key("username"), "K-R4: display 开关不准泄 username");
    }

    /// K-R4: 默认模式 payload 序列化后不含任何裸敏感值.
    #[test]
    fn k_r4_default_no_raw_leak() {
        let p = sample().to_payload_json(PrivacyMode::default_sha());
        let dumped = serde_json::to_string(&p).unwrap();
        for raw in ["wxid_friend_002", "wxid_acct_001", "小明", "老同学"] {
            assert!(!dumped.contains(raw), "K-R4: 默认模式 payload 泄漏裸值 {raw}");
        }
    }

    /// K-R4: 手写 Debug 不泄 username / nick_name / remark / alias / account_id 裸值.
    #[test]
    fn debug_redacts_all_sensitive() {
        let mut c = sample();
        c.alias = Some("xiaoming".to_string());
        let dbg = format!("{c:?}");
        for raw in ["wxid_friend_002", "wxid_acct_001", "小明", "老同学", "xiaoming"] {
            assert!(!dbg.contains(raw), "Debug 泄漏裸值 {raw}!");
        }
        assert!(dbg.contains("nick_name_sha8"));
    }

    /// 字段扩充第二批: verify_flag/delete_flag 是元数据类 — payload 默认模式也直塞 (不脱敏), Debug 直显。
    #[test]
    fn payload_and_debug_include_flags() {
        let mut c = sample();
        c.verify_flag = 2;
        c.delete_flag = 1;
        // payload 元数据直塞 (默认脱敏模式也出原值, 同 local_type)。
        let p = c.to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        assert_eq!(o["verify_flag"], Value::from(2));
        assert_eq!(o["delete_flag"], Value::from(1));
        // Debug 直显 (元数据非敏感, 不 sha8)。
        let dbg = format!("{c:?}");
        assert!(dbg.contains("verify_flag: 2"), "Debug 直显 verify_flag");
        assert!(dbg.contains("delete_flag: 1"), "Debug 直显 delete_flag");
    }

    /// 字段扩充第五批: description 只进 L2 (不进 payload); Debug description sha8 脱敏, flag/notify/type 直显。
    #[test]
    fn batch5_not_in_payload_debug_redacts_description() {
        let mut c = sample();
        c.description = Some("我的个性签名".to_string());
        c.flag = 5;
        c.chat_room_notify = 1;
        c.chat_room_type = 2;
        // payload 不含第五批任何列 (L2-only, 同头像)。
        let p = c.to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        for k in [
            "description",
            "description_sha",
            "flag",
            "chat_room_notify",
            "chat_room_type",
        ] {
            assert!(!o.contains_key(k), "第五批列不进 payload: {k}");
        }
        // plaintext 模式也不进 payload (彻底不在 archive)。
        let pp = c.to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        assert!(
            !pp.as_object().unwrap().contains_key("description"),
            "plaintext 也不出 description"
        );
        // Debug: description sha8 脱敏 (不露原文); flag/notify/type 元数据直显。
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("我的个性签名"), "K-R4: Debug 不露 description 原文");
        assert!(dbg.contains("description_sha8"));
        assert!(dbg.contains("flag: 5"));
        assert!(dbg.contains("chat_room_notify: 1"));
        assert!(dbg.contains("chat_room_type: 2"));
    }

    /// 添加时间件 (ADR-486): friend_add_time 只进 L2 (不进 payload, 含 plaintext); Debug 直显 (时间戳非 PII)。
    #[test]
    fn friend_add_time_not_in_payload_debug_shows_direct() {
        let c = sample(); // friend_add_time = Some(1_698_674_704)
                          // 默认 + plaintext 模式都不进 payload (L2-only, 彻底不在 archive)。
        for mode in [
            PrivacyMode::default_sha(),
            PrivacyMode {
                enable_plaintext: true,
                ..Default::default()
            },
        ] {
            let p = c.to_payload_json(mode);
            assert!(
                !p.as_object().unwrap().contains_key("friend_add_time"),
                "friend_add_time 不进 payload"
            );
        }
        // Debug 直显时间戳 (非 PII, 不脱敏)。
        assert!(
            format!("{c:?}").contains("friend_add_time: Some(1698674704)"),
            "Debug 直显添加时间"
        );
    }

    /// 字段扩充第七批: sex/地区/来源 只进 L2 (不进 payload); Debug 地区 sha8 脱敏, sex/source 直显。
    #[test]
    fn batch7_not_in_payload_debug_redacts_region() {
        let c = sample(); // sex=1 / country=CN / province=Zhejiang / city=Hangzhou / friend_source=3
        let p = c.to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        for k in ["sex", "country", "province", "city", "friend_source"] {
            assert!(!o.contains_key(k), "第七批列不进 payload: {k}");
        }
        // plaintext 也不进 payload (彻底不在 archive)。
        let pp = c.to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        assert!(
            !pp.as_object().unwrap().contains_key("province"),
            "plaintext 也不出 province"
        );
        // Debug: 地区 sha8 (不露 Zhejiang/Hangzhou 原文); sex/source 元数据直显。
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("Zhejiang"), "K-R4: Debug 不露 province 原文");
        assert!(!dbg.contains("Hangzhou"), "K-R4: Debug 不露 city 原文");
        assert!(dbg.contains("sex: 1"));
        assert!(dbg.contains("friend_source: 3"));
        assert!(dbg.contains("province_sha8"));
    }

    /// 字段扩充批 I: signature/moments_cover_url 只进 L2 (不进 payload); Debug sha8 脱敏 (签名可含手机号)。
    #[test]
    fn batch_i_not_in_payload_debug_redacts_signature() {
        let mut c = sample();
        c.signature = Some("诚招小化13800138000".to_string());
        c.moments_cover_url = Some("http://shmmsns.qpic.cn/mmsns/SECRET/0".to_string());
        // payload 不含批 I列 (L2-only)。
        let p = c.to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        for k in ["signature", "moments_cover_url"] {
            assert!(!o.contains_key(k), "批 I列不进 payload: {k}");
        }
        // plaintext 也不进 payload (彻底不在 archive)。
        let pp = c.to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        assert!(
            !pp.as_object().unwrap().contains_key("signature"),
            "plaintext 也不出 signature"
        );
        // Debug: 签名内手机号 + 封面 URL 都脱敏。
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("13800138000"), "K-R4: Debug 不露签名内手机号");
        assert!(!dbg.contains("SECRET"), "K-R4: Debug 不露封面 URL");
        assert!(dbg.contains("signature_sha8"));
        assert!(dbg.contains("moments_cover_url_sha8"));
    }

    /// 标签件: labels 只进 L2 (不进 payload, plaintext 也不出); Debug sha8 脱敏 (标签名可敏感如 "老板")。
    #[test]
    fn labels_not_in_payload_debug_redacts() {
        let mut c = sample();
        c.labels = Some("老板,前女友".to_string());
        // payload 不含 labels (L2-only)。
        let p = c.to_payload_json(PrivacyMode::default_sha());
        assert!(
            !p.as_object().unwrap().contains_key("labels"),
            "labels 不进 payload (L2-only)"
        );
        // plaintext 也不进 payload (彻底不在 archive)。
        let pp = c.to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        assert!(
            !pp.as_object().unwrap().contains_key("labels"),
            "plaintext 也不出 labels"
        );
        // Debug: 标签名脱敏 (不露原文)。
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("老板"), "K-R4: Debug 不露标签名原文");
        assert!(!dbg.contains("前女友"), "K-R4: Debug 不露标签名原文");
        assert!(dbg.contains("labels_sha8"));
    }

    /// 企微件: openim_company/openim_realname 只进 L2 (不进 payload, plaintext 也不出); Debug sha8 脱敏 (公司名/实名 = PII)。
    #[test]
    fn openim_not_in_payload_debug_redacts() {
        let mut c = sample();
        c.openim_company = Some("机密科技有限公司".to_string());
        c.openim_realname = Some("赵机密".to_string());
        // payload 不含企微列 (L2-only)。
        let p = c.to_payload_json(PrivacyMode::default_sha());
        let o = p.as_object().unwrap();
        for k in ["openim_company", "openim_realname"] {
            assert!(!o.contains_key(k), "企微件列不进 payload: {k}");
        }
        // plaintext 也不进 payload (彻底不在 archive)。
        let pp = c.to_payload_json(PrivacyMode {
            enable_plaintext: true,
            ..Default::default()
        });
        assert!(
            !pp.as_object().unwrap().contains_key("openim_company"),
            "plaintext 也不出 openim_company"
        );
        // Debug: 公司名/实名脱敏 (不露原文)。
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("机密科技有限公司"), "K-R4: Debug 不露公司名原文");
        assert!(!dbg.contains("赵机密"), "K-R4: Debug 不露实名原文");
        assert!(dbg.contains("openim_company_sha8"));
        assert!(dbg.contains("openim_realname_sha8"));
    }
}
