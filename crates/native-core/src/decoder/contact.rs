//! contact row 组装 — 解密明文 contact 表行 → [`ContactUpdate`] 事件 (ADR-412 §3.x.2).
//!
//! [`assemble_contact`] 把一条真实 contact 行映射成 [`ContactUpdate`]. **无 decode/无 sender 解析** —
//! contact 字段都是明文列, username 是 String (非 Wxid) → 本函数 **infallible** (无 Result).
//! event_seq 留 0 (compute_event_seq 后置填).
//!
//! ## 真实 schema (v4 `contact` 表, 消费列: username/local_type/alias/remark/nick_name/is_in_chat_room
//! ## + 拼音 4 列 [第一批] + verify_flag/delete_flag [第二批] + 头像 3 列 [第三批]
//! ## + description/flag/chat_room_notify/chat_room_type [第五批]
//! ## + extra_buffer 解析→性别/国/省/市/好友来源 [第七批] + 个性签名/朋友圈封面 [批 I] (见 contact_extra.rs))
//! username (UserName 主键) / nick_name (昵称) / remark (备注, 可空) / alias (**微信号**, 可空) /
//! local_type (联系人类型) / is_in_chat_room (0/1) / quan_pin·pin_yin_initial·remark_quan_pin·
//! remark_pin_yin_initial (拼音搜索, 可空, 不进 digest) / verify_flag·delete_flag (状态标志, 进 content_digest).

use crate::event::contact::ContactUpdate;
use crate::event::provenance::Provenance;
use crate::event::{EventAction, EventType};
use crate::key_provider::Wxid;

/// 解密明文 contact 表行 (调用方从 cipher 解密的 db SELECT).
pub struct ContactRow {
    /// 源 db 行 rowid (= 取数游标键; assemble 不用, 仅供 adapter pipeline 推进/校验游标, 同 `MessageRow.local_id`).
    pub rowid: i64,
    /// 联系人 UserName (contact.username).
    pub username: String,
    /// 联系人类型 (contact.local_type; 元数据, 不解释).
    pub local_type: i64,
    /// 昵称 (contact.nick_name; 可空 → 空串).
    pub nick_name: Option<String>,
    /// 备注 (contact.remark; 可空).
    pub remark: Option<String>,
    /// 别名 / 微信号 (contact.alias; 可空).
    pub alias: Option<String>,
    /// 是否在群里 (contact.is_in_chat_room; 0/1).
    pub is_in_chat_room: i64,
    /// 昵称全拼 (contact.quan_pin; 搜索用, 可空).
    pub quan_pin: Option<String>,
    /// 昵称拼音首字母 (contact.pin_yin_initial; 搜索用, 可空).
    pub pin_yin_initial: Option<String>,
    /// 备注全拼 (contact.remark_quan_pin; 搜索用, 可空).
    pub remark_quan_pin: Option<String>,
    /// 备注拼音首字母 (contact.remark_pin_yin_initial; 搜索用, 可空).
    pub remark_pin_yin_initial: Option<String>,
    /// 好友验证标志 (contact.verify_flag; 元数据, 进 content_digest 溯源 — 独立状态非派生, 记好友关系变化).
    pub verify_flag: i64,
    /// 软删除标志 (contact.delete_flag; 元数据, 进 content_digest 溯源 — 记删好友时点).
    pub delete_flag: i64,
    /// 大头像 URL (contact.big_head_url; 资源, 可空; 进 L2 不进 digest — CDN 链接会刷新).
    pub big_head_url: Option<String>,
    /// 小头像 URL (contact.small_head_url; 资源, 可空; 进 L2 不进 digest).
    pub small_head_url: Option<String>,
    /// 头像内容 md5 (contact.head_img_md5; 资源标识, 可空; 进 L2 不进 digest — 用户选 1 不溯源换头像).
    pub head_img_md5: Option<String>,
    // ── 第五批 (2026-07-02): contact 补充列 (全进 L2 不进 content_digest — 同头像 L2-only 先例)。
    /// 用户私备注/评价 (contact.description; **非个性签名** — 真库仅 0.1% 有值, 内容如"谨慎使用/催钱猛";
    /// 个性签名另在 extra_buffer f4 [批 I]。可空; 进 L2, Debug sha8 脱敏).
    pub description: Option<String>,
    /// 联系人标志位 (contact.flag; 元数据 bitfield, 含星标/黑名单等位; 进 L2, digest 决策待定).
    pub flag: i64,
    /// 群消息通知设置 (contact.chat_room_notify; 元数据).
    pub chat_room_notify: i64,
    /// 群类型 (contact.chat_room_type; 元数据).
    pub chat_room_type: i64,
    /// 扩展属性原始 blob (contact.extra_buffer; proto — 第七批 assemble 解析出性别/国/省/市/好友来源)。
    pub extra_buffer: Vec<u8>,
    /// 标签名 (标签件; **drain 端已解析** — extra_buffer f30 标签 id 串 → `contact_label` 表 id→名字 map →
    /// 逗号拼名字如 `"老板,客户"`; 无标签/全解不出 → None)。assemble 直透传 (不在此解析: id→名字 map 只在 drain 层)。
    /// 只进 L2 person 表, 不进 content_digest。
    pub labels: Option<String>,
}

/// 装配上下文 — 调用方 (adapter) 按 db 预备.
pub struct ContactContext {
    /// 数据所属账号 UserName.
    pub account_id: Wxid,
    /// 源 db 文件名 (e.g. `"contact.db"`).
    pub source: String,
    /// 复合 md5 锚点 (调用方预合成 `"Contact_<md5_hex(username)>"`; → `provenance.source_native_id`).
    pub source_native_id: String,
    /// 摄取时刻 (毫秒).
    pub ingest_time: i64,
}

/// 组装一条 [`ContactRow`] + [`ContactContext`] → [`ContactUpdate`] (event_seq 留 0, 后置填).
///
/// 纯字段映射 (无 decode/sender 解析). 空串 remark/alias → `None` (= 未设); nick_name 缺 → 空串
/// (ContactUpdate.nick_name 非 Option). 不 log. **infallible**.
#[must_use]
pub fn assemble_contact(row: &ContactRow, ctx: &ContactContext) -> ContactUpdate {
    // 空串 → None (= 未设备注/别名), 跟 ContactUpdate 的 nullable 语义一致.
    let non_empty = |o: &Option<String>| o.as_ref().filter(|s| !s.is_empty()).cloned();
    // 第七批: extra_buffer proto 解出扩展属性 (infallible; 坏/缺 → 默认 sex=0/source=0/地区 None)。
    let extra = crate::decoder::contact_extra::parse_contact_extra(&row.extra_buffer);
    ContactUpdate {
        provenance: Provenance {
            account_id: ctx.account_id.clone(),
            source: ctx.source.clone(),
            source_native_id: ctx.source_native_id.clone(),
            event_type: EventType::ContactUpdate,
            event_action: EventAction::Create,
            event_seq: 0, // 占位, compute_event_seq 后置填
            ingest_time: ctx.ingest_time,
        },
        username: row.username.clone(),
        nick_name: row.nick_name.clone().unwrap_or_default(),
        remark: non_empty(&row.remark),
        alias: non_empty(&row.alias),
        local_type: i32::try_from(row.local_type).unwrap_or(i32::MAX),
        is_in_chat_room: row.is_in_chat_room != 0,
        // 拼音列 (搜索用, 空串→None; 进 L2 person 表不进 content_digest — 派生自 nick/remark)。
        quan_pin: non_empty(&row.quan_pin),
        pin_yin_initial: non_empty(&row.pin_yin_initial),
        remark_quan_pin: non_empty(&row.remark_quan_pin),
        remark_pin_yin_initial: non_empty(&row.remark_pin_yin_initial),
        // 状态标志 (元数据直传; 进 content_digest 溯源 — verify/delete 独立状态, 非派生自 nick/remark)。
        verify_flag: row.verify_flag,
        delete_flag: row.delete_flag,
        // 头像列 (资源, 空串→None; 进 L2 不进 content_digest — CDN URL 刷新噪音 + 换头像高频不溯源)。
        big_head_url: non_empty(&row.big_head_url),
        small_head_url: non_empty(&row.small_head_url),
        head_img_md5: non_empty(&row.head_img_md5),
        // 第五批 (进 L2 不进 digest — 同头像先例): description 文本 non_empty; flag/notify/type 元数据直传。
        description: non_empty(&row.description),
        flag: row.flag,
        chat_room_notify: row.chat_room_notify,
        chat_room_type: row.chat_room_type,
        // 第七批: extra_buffer 解出 (进 L2 不进 digest, 同上 L2-only)。sex/friend_source i64; 地区 Option<String>。
        sex: extra.sex,
        country: extra.country,
        province: extra.province,
        city: extra.city,
        friend_source: extra.friend_source,
        // 批 I: extra_buffer 再解 (同 L2-only)。signature 个性签名(f4) / moments_cover_url 朋友圈封面(f27 内层 f2)。
        signature: extra.signature,
        moments_cover_url: extra.moments_cover_url,
        // 添加时间件 (ADR-486): 好友添加时间 (extra_buffer f41 varint unix 秒; 同 L2-only 元数据)。
        friend_add_time: extra.friend_add_time,
        // 企微件: 企微 (@openim) 公司名/实名 (extra_buffer f4 内层 custom_info title==企业/实名; 同 L2-only)。
        openim_company: extra.openim_company,
        openim_realname: extra.openim_realname,
        // 标签件: labels 名字串 (drain 端已从 f30 标签 id 串 + contact_label map 解好, 此处直透传; 同 L2-only)。
        labels: row.labels.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ContactContext {
        ContactContext {
            account_id: Wxid::new("wxid_self_acct"),
            source: "contact.db".to_string(),
            source_native_id: "Contact_a1b2c3d4".to_string(),
            ingest_time: 1_700_000_000_000,
        }
    }

    fn row(username: &str, nick: Option<&str>, remark: Option<&str>, alias: Option<&str>) -> ContactRow {
        ContactRow {
            rowid: 1,
            username: username.to_string(),
            local_type: 1,
            nick_name: nick.map(str::to_string),
            remark: remark.map(str::to_string),
            alias: alias.map(str::to_string),
            is_in_chat_room: 0,
            quan_pin: None,
            pin_yin_initial: None,
            remark_quan_pin: None,
            remark_pin_yin_initial: None,
            verify_flag: 0,
            delete_flag: 0,
            big_head_url: None,
            small_head_url: None,
            head_img_md5: None,
            description: None,
            flag: 0,
            chat_room_notify: 0,
            chat_room_type: 0,
            extra_buffer: Vec::new(),
            labels: None,
        }
    }

    /// 全字段填: username/nick/remark/alias 直映 + provenance 装配 + event_seq 占位.
    #[test]
    fn full_contact_maps_all() {
        let c = assemble_contact(
            &row("wxid_friend", Some("小明"), Some("老同学"), Some("xiaoming88")),
            &ctx(),
        );
        assert_eq!(c.username, "wxid_friend");
        assert_eq!(c.nick_name, "小明");
        assert_eq!(c.remark.as_deref(), Some("老同学"));
        assert_eq!(c.alias.as_deref(), Some("xiaoming88"));
        assert_eq!(c.provenance.event_type, EventType::ContactUpdate);
        assert_eq!(c.provenance.event_seq, 0, "event_seq 占位");
    }

    /// 自定义号 UserName (无 wxid_) — username 是 String 不卡格式.
    #[test]
    fn custom_id_username_ok() {
        let c = assemble_contact(&row("custom_no_prefix", Some("Name"), None, None), &ctx());
        assert_eq!(c.username, "custom_no_prefix");
    }

    /// 空串 remark/alias → None (= 未设); nick_name 缺 → 空串.
    #[test]
    fn empty_optionals_become_none() {
        let c = assemble_contact(&row("wxid_a", None, Some(""), Some("")), &ctx());
        assert_eq!(c.nick_name, "", "nick_name 缺 → 空串 (非 Option)");
        assert_eq!(c.remark, None, "空 remark → None");
        assert_eq!(c.alias, None, "空 alias → None");
    }

    /// local_type/is_in_chat_room 标量映射.
    #[test]
    fn scalar_metadata_maps() {
        let mut r = row("wxid_a", Some("n"), None, None);
        r.local_type = 4;
        r.is_in_chat_room = 1;
        let c = assemble_contact(&r, &ctx());
        assert_eq!(c.local_type, 4);
        assert!(c.is_in_chat_room);
    }

    /// 双审 P2: local_type 宽窄转换饱和 (i64 超 i32 范围 → i32::MAX, 不 panic).
    #[test]
    fn local_type_saturates() {
        let mut r = row("wxid_a", Some("n"), None, None);
        r.local_type = i64::MAX;
        assert_eq!(assemble_contact(&r, &ctx()).local_type, i32::MAX);
    }

    /// 字段扩充第一批 (2026-07-01): 4 拼音列映射 + 空串 → None (跟 remark/alias 同 non_empty 规矩)。
    #[test]
    fn pinyin_columns_map_and_empty_to_none() {
        let mut r = row("wxid_a", Some("小明"), None, None);
        r.quan_pin = Some("xiaoming".into());
        r.pin_yin_initial = Some("XM".into());
        r.remark_quan_pin = Some(String::new()); // 空串 → None
        r.remark_pin_yin_initial = None;
        let c = assemble_contact(&r, &ctx());
        assert_eq!(c.quan_pin.as_deref(), Some("xiaoming"));
        assert_eq!(c.pin_yin_initial.as_deref(), Some("XM"));
        assert_eq!(c.remark_quan_pin, None, "空串 → None");
        assert_eq!(c.remark_pin_yin_initial, None);
    }

    /// 字段扩充第二批 (2026-07-01): verify_flag/delete_flag 直传映射 (i64 元数据, 非 non_empty 处理)。
    #[test]
    fn verify_delete_flags_map() {
        let mut r = row("wxid_a", Some("小明"), None, None);
        r.verify_flag = 2;
        r.delete_flag = 1;
        let c = assemble_contact(&r, &ctx());
        assert_eq!(c.verify_flag, 2);
        assert_eq!(c.delete_flag, 1);
    }

    /// 字段扩充第三批 (2026-07-02): 头像 3 列映射 + 空串 → None (同拼音 non_empty)。
    #[test]
    fn head_columns_map_and_empty_to_none() {
        let mut r = row("wxid_a", Some("小明"), None, None);
        r.big_head_url = Some("https://wx.qlogo.cn/x/0".into());
        r.small_head_url = Some(String::new()); // 空串 → None
        r.head_img_md5 = Some("abc123".into());
        let c = assemble_contact(&r, &ctx());
        assert_eq!(c.big_head_url.as_deref(), Some("https://wx.qlogo.cn/x/0"));
        assert_eq!(c.small_head_url, None, "空串 → None");
        assert_eq!(c.head_img_md5.as_deref(), Some("abc123"));
    }

    /// 字段扩充第五批 (2026-07-02): contact 补充列映射 (description non_empty; flag/notify/type i64 直传)。
    #[test]
    fn batch5_columns_map() {
        let mut r = row("wxid_a", Some("小明"), None, None);
        r.description = Some("爱生活爱微信".into());
        r.flag = 3;
        r.chat_room_notify = 1;
        r.chat_room_type = 2;
        let c = assemble_contact(&r, &ctx());
        assert_eq!(c.description.as_deref(), Some("爱生活爱微信"));
        assert_eq!(c.flag, 3);
        assert_eq!(c.chat_room_notify, 1);
        assert_eq!(c.chat_room_type, 2);
        r.description = Some(String::new());
        assert_eq!(
            assemble_contact(&r, &ctx()).description,
            None,
            "空串 description → None"
        );
    }

    /// 字段扩充第七批 (2026-07-02): assemble 解 extra_buffer proto → 性别/国/来源 (映射见 contact_extra.rs)。
    #[test]
    fn batch7_extra_buffer_parsed() {
        let mut r = row("wxid_a", Some("小明"), None, None);
        // proto: f2=2(女) [0x10,0x02] / f5="CN" [0x2a,0x02,'C','N'] / f8=3(加好友来源场景) [0x40,0x03]
        r.extra_buffer = vec![0x10, 0x02, 0x2a, 0x02, 0x43, 0x4e, 0x40, 0x03];
        let c = assemble_contact(&r, &ctx());
        assert_eq!(c.sex, 2, "f2 性别=女");
        assert_eq!(c.country.as_deref(), Some("CN"), "f5 国家");
        assert_eq!(c.friend_source, 3, "f8 加好友来源场景=3(微信号)");
        // 空 extra_buffer → 默认 (sex=0, 地区 None)。
        r.extra_buffer = Vec::new();
        let c2 = assemble_contact(&r, &ctx());
        assert_eq!(c2.sex, 0);
        assert_eq!(c2.country, None);
    }

    /// 字段扩充批 I (2026-07-04): assemble 解 extra_buffer → signature(f4)/moments_cover_url(f27) 透传。
    #[test]
    fn batch_i_signature_cover_parsed() {
        let mut r = row("wxid_a", Some("小明"), None, None);
        r.extra_buffer = vec![0x22, 0x02, 0x68, 0x69]; // f4="hi" [tag=(4<<3)|2, len=2, 'h','i']
        let c = assemble_contact(&r, &ctx());
        assert_eq!(c.signature.as_deref(), Some("hi"), "f4 个性签名透传");
        assert_eq!(c.moments_cover_url, None, "无 f27 → None");
    }

    /// 标签件: labels 由 drain 端解好, assemble 直透传 (无解析); None → None。
    #[test]
    fn labels_passthrough() {
        let mut r = row("wxid_a", Some("小明"), None, None);
        r.labels = Some("老板,客户".to_string());
        assert_eq!(
            assemble_contact(&r, &ctx()).labels.as_deref(),
            Some("老板,客户"),
            "labels 透传"
        );
        r.labels = None;
        assert_eq!(assemble_contact(&r, &ctx()).labels, None, "无标签 → None");
    }
}
