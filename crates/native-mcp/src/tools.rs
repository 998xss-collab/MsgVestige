//! wx_ 工具 (④文档 §3) —— 各工具**直调 native-query 共享内核**(三皮同核, 不重写查询), 输出经 [`crate::fold`] 折叠。
//!
//! **分派用 match 不用函数指针注册表** (比 WDA 的 Python 注册表更贴 Rust: 避开异步 fn 装箱; 冷查同步/热查
//! async 在 match 臂里自然区分)。`tool_defs()` = tools/list 的静态清单; `call_tool()` = tools/call 的分派。
//!
//! **首批** (验证冷+热+协议整条链): wx_contacts(冷·keyset 游标) · wx_account(冷·汇总) · wx_sessions(热·读源库) ·
//! wx_current_time(工具类)。其余 16 个逐步补 (每个同样是"取 ctx→调核→折叠"薄壳)。

// 工具处理函数保持统一的 async 签名(哪怕个别不 await), 便于分发器一视同仁。
#![allow(clippy::unused_async)]

use serde_json::{json, Value};

use crate::error::{tool_err, tool_err_with, tool_ok};
use crate::{fold, Ctx};

/// tools/list 的工具清单 (name + description + inputSchema; 面向 LLM 的自然语言描述 + JSON Schema 参数)。
#[must_use]
pub fn tool_defs() -> Vec<Value> {
    let mut defs = vec![
        json!({
            "name": "wx_contacts",
            "description": "查联系人 (人/群/公众号)。按昵称/备注/微信号/wxid 子串搜。返回本页 + 游标翻页。找人用它先拿到 wxid, 再传给消息类工具。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("query", schema_str("按昵称/备注/微信号/wxid 子串过滤; 省略=全部")),
                ("limit", schema_int("本页最多几个 (默认 20, 上限 100)", 1, 100)),
                ("cursor", schema_str("翻页游标 (上次返回的 next_cursor); **仅 cold**, 实时查用 offset")),
                ("offset", schema_int("跳过前几个 (**仅 hot** 翻页; cold 用 cursor)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_account",
            "description": "当前账号概览: 账号 id + 各类数据条数 (联系人/群/消息/朋友圈/收藏)。先看规模再决定怎么查。默认读 L1; mode=hot 实时聚合加密微信库计数 (messages 全扫较慢, 要 account)。",
            "inputSchema": gated_schema_obj(&[
                ("account", schema_str("多账号库指定账号 wxid; 单账号省略")),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时聚合微信库计数(messages 全扫慢, 要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
            ], &[]),
        }),
        json!({
            "name": "wx_sessions",
            "description": "列会话 (我和谁聊过; 群和单聊)。默认实时读微信库; mode=cold 读 L1 投影库 (快但可能旧)。返回会话标识, 再用它当 conv 查消息。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: hot 实时读微信库(默认) / cold 读 L1(快但可能旧) / auto 有 L1 走冷否则热", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多列几个 (默认 20, 上限 100)", 1, 100)),
                ("offset", schema_int("跳过前几个 (翻页; 配 limit 够到更早的会话, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号必填, 或用服务器默认账号")),
            ], &[]),
        }),
        json!({
            "name": "wx_messages",
            "description": "查某会话消息。核心工具。默认实时读微信库取最近 N 条; mode=cold 读 L1 投影库 (快但可能旧, 支持 offset 翻页); around=某条消息 create_time 取前后文 (仅实时查)。先用 wx_sessions/wx_contacts 拿会话标识再传 conv。",
            "inputSchema": schema_obj(&[
                ("conv", schema_str("会话: 对方 wxid 或群 id (形如 xxxx@chatroom)")),
                ("refresh", schema_bool("冷查前先把该会话新消息补进 L1 (缺省 true; false = 读现有的, 快但可能不是最新)")),
                ("mode", schema_enum("查询模式: hot 实时(默认) / cold 读 L1(快但可能旧) / auto 有 L1 走冷否则热。around 仅 hot 支持", &["hot", "cold", "auto"])),
                ("limit", schema_int("最近模式最多取几条 (默认 10, 上限 50)", 1, 50)),
                ("offset", schema_int("冷查翻页偏移 (默认 0; 仅 mode=cold 支持, 实时查不支持)", 0, 10_000_000)),
                ("around", schema_int("锚点消息的 create_time (来自上一条消息/搜索命中); 给了就取它前后文而非最近 (仅 mode=hot)", 0, i64::MAX)),
                ("before", schema_int("around 模式: 锚点前几条 (默认 5, 上限 25)", 0, 25)),
                ("after", schema_int("around 模式: 锚点后几条 (默认 5, 上限 25)", 0, 25)),
                ("account", schema_str("账号 wxid; 多账号必填或用服务器默认账号")),
            ], &["conv"]),
        }),
        json!({
            "name": "wx_search",
            "description": "全文搜索消息正文 (中文子串)。默认读 L1 (FTS5 按相关度 bm25 排); mode=hot 全扫加密微信库拿实时 (🔴降级: 无 FTS, 全库扫子串, 无相关度排名按时间序, 大账号较慢, 要 account)。只返命中片段。",
            "inputSchema": gated_schema_obj(&[
                ("query", schema_str("搜索关键词")),
                ("limit", schema_int("最多几条命中 (默认 10, 上限 50)", 1, 50)),
                ("account", schema_str("多账号库指定账号 wxid")),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时全扫微信库(🔴降级无相关度排名, 要 account) / cold 读 L1 FTS(bm25 排)", &["hot", "cold", "auto"])),
            ], &["query"]),
        }),
        json!({
            "name": "wx_stats",
            "description": "消息统计排行 (top-N)。by=day 按天计数 / sender 按发送人 / conv 按会话 / type 按消息类型。默认读 L1; mode=hot 全扫加密微信库拿实时 (大账号较慢)。",
            "inputSchema": gated_schema_obj(&[
                ("by", schema_enum("统计维度", &["day", "sender", "conv", "type"])),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("top-N (默认 30, 上限 50)", 1, 50)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_dormant",
            "description": "沉睡会话排行 (最久没说话的会话排前面, top-N)。返 conv_id + 最后消息日期 + 消息数。默认读 L1; mode=hot 全扫加密微信库拿实时 (大账号较慢, 要 account)。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("top-N (默认 15, 上限 50)", 1, 50)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_followups",
            "description": "待回复会话 (每会话最后一条是对方发的、本账号还没回 = 待跟进, top-N)。默认读 L1; mode=hot 全扫加密微信库拿实时 (大账号较慢, 要 account)。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("private_only", schema_bool("只看私聊 (排除群聊; 一对一里\"对方问了没答\"更常见)")),
                ("limit", schema_int("top-N (默认 30, 上限 50)", 1, 50)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_money",
            "description": "查转账/红包/群收款合并时间线。kind=all 全部 / transfer 转账 / red-envelope 红包 / group-pay 群收款。默认读 L1; mode=hot 直读微信库 (general.db 专表 + 扫消息补金额/人数) 拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("kind", schema_enum("类型", &["all", "transfer", "red-envelope", "group-pay"])),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 20, 上限 100)", 1, 100)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_members",
            "description": "查群成员 (名字/角色/入群时间/邀请人)。大群可能几千人, 用 limit 控量, 按 has_more 判断是否还有。默认读 L1; mode=hot 直读微信库拿实时在群名单, 但降级: 入群时间(joined_at)显示为空、已退群成员不返回 (只给当前在群快照), summary 里 partial=true。",
            "inputSchema": schema_obj(&[
                ("chatroom", schema_str("群 id (形如 xxxx@chatroom)")),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库当前在群名单(要 account, 降级见描述) / cold 读 L1(快, 含入群时间和退群历史)", &["hot", "cold", "auto"])),
                ("admins_only", schema_bool("只列群主/管理员")),
                ("limit", schema_int("最多几个 (默认 100, 上限 500)", 1, 500)),
                ("offset", schema_int("跳过前几个 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &["chatroom"]),
        }),
        json!({
            "name": "wx_favorites",
            "description": "查我的收藏。按内容子串搜。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("query", schema_str("按内容子串过滤; 省略=全部")),
                ("limit", schema_int("最多几条 (默认 20, 上限 100)", 1, 100)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_friend_requests",
            "description": "查好友申请记录 (谁申请加我 / 我加谁; 含来源场景)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 20, 上限 100)", 1, 100)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_channels",
            "description": "查视频号浏览足迹。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 20, 上限 100)", 1, 100)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_emoticons",
            "description": "查自定义表情目录 (中文描述/内容md5/类型/CDN链接)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 20, 上限 100)", 1, 100)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_chatrooms",
            "description": "查群列表 (群id/群名/群主/成员数/公告), 按成员数倒序。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几个 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几个 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_avatars",
            "description": "查头像清单 (归属wxid/内容md5/更新时刻; 不含图片本体), 按更新时间倒序。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几个 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几个 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_biz_contacts",
            "description": "查企微(企业微信)联系人 (昵称/企微id/品牌号gh_)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几个 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几个 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_moments",
            "description": "查朋友圈动态 (作者/时间/正文/媒体数/赞评数)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 20, 上限 100)", 1, 100)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_interactions",
            "description": "查朋友圈点赞评论 (谁赞了/评论了哪条动态: 时间/类别(赞/评论)/互动者昵称+wxid/评论文本)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_sns_notify",
            "description": "查朋友圈互动通知 (谁赞了/评论了我的动态: 时间/类型/互动者昵称+wxid/评论文本)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_fav_media",
            "description": "查收藏媒体 (收藏笔记里的图片/文件/HTML: 所属收藏id/序号/类别/md5/字节数/格式)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_fav_tags",
            "description": "查收藏标签 (哪条收藏被贴了什么标签: 标签id/所属收藏id/标签名)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_hongbao_claims",
            "description": "查红包领取明细 (谁领了每个红包: 时间/会话/红包单号/我领的还是我发的被领/对方昵称), 按时间倒序。对应 money --claims。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_group_pay_members",
            "description": "查群收款逐付款人 (每笔群收款每人: 账单号/付款人wxid/金额分/已付未付), 按账单号倒序。对应 money --payers。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_pii_scan",
            "description": "扫全库文本消息里的疑似隐私号码 (手机号/身份证), 按时间倒序。默认打码 (reveal=true 显全, 慎用)。默认读 L1; mode=hot 全扫加密微信库拿实时数据 (大账号较慢)。",
            "inputSchema": gated_schema_obj(&[
                ("kind", schema_enum("类型: all 全部 / phone 手机号 / idcard 身份证", &["all", "phone", "idcard"])),
                ("reveal", schema_bool("是否显全不打码 (默认 false 打码; true 慎用, 泄隐私)")),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_extract",
            "description": "从全库文本消息抽结构化信息 (链接url/邮箱/金额/手机号/身份证), 按时间倒序。不打码。默认读 L1; mode=hot 全扫加密微信库拿实时数据 (大账号较慢)。",
            "inputSchema": gated_schema_obj(&[
                ("kind", schema_enum("抽取类型: url 链接 / email 邮箱 / amount 金额 / phone 手机号 / idcard 身份证", &["url", "email", "amount", "phone", "idcard"])),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_events",
            "description": "查群系统事件 (进群/退群/撤回/拍一拍/群公告/红包转账提示等 type10000 系统消息), 按时间倒序。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("sys_type", schema_str("只看某类事件 (member_join/member_remove/revoke/pat/topmsg/group_dissolve/hongbao/transfer/other); 省略=全部")),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_calls",
            "description": "查通话记录 (语音/视频通话的时间/对方/时长/结果, type50 VoIP 消息)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_biz",
            "description": "查公众号消息 (gh_ 会话的图文推送标题/时间/msg_type; 跨所有消息类型)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_mentions",
            "description": "查群消息 @提及 (谁在群里 @了谁/是否@所有人/原消息)。给 query=某人 wxid 只看被@那人的 (填自己=看@我的)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("query", schema_str("只看被 @ 的某人 (子串匹配 mentioned_wxid; 省略=所有 @提及)")),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_thread",
            "description": "查引用回复 (谁回复了什么/引用的原文, appmsg type57 refermsg)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_links",
            "description": "查分享的链接/卡片 (标题/网址/应用类型, appmsg 消息里带 url 的)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_files",
            "description": "查文件消息 (文件名/后缀/大小, appmsg 消息里带文件的)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_locations",
            "description": "查位置分享 (经纬度/地点名/城市, type48 位置消息)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_group_events",
            "description": "查群成员进出记录 (谁进群/退群, 昵称+wxid+时间; type10000 系统消息派生, 一条消息可含多个成员)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_cards",
            "description": "查分享的名片 (被推荐人 昵称/微信号/身份/企微公司名, type42 名片消息)。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_inspect",
            "description": "查单条记录的完整字段 (消息/联系人/群/会话)。消息 id 传 source_native_id。两种模式: (1) 不传 field = 返整行全字段 (取全字段逃生口; 超预算时截长字段并在 meta.truncated_fields 指明哪些没读全); (2) 传 field+offset = 分段读某个超长字段, 按 next_offset 递进直到 has_more=false 拼回完整内容 (读某条消息全文用这个)。默认 auto(有 L1 读冷否则热); mode=hot 直读加密微信库实时查 (要 account; message 需全扫找锚较慢, contact/chatroom 字段少于冷)。",
            "inputSchema": gated_schema_obj(&[
                ("type", schema_enum("实体类型", &["contact", "chatroom", "session", "message"])),
                ("id", schema_str("记录标识 (联系人/群/会话=其 id; 消息=source_native_id)")),
                ("field", schema_str("可选: 只读某个字段 (分段模式); 配 offset 从该字符偏移续读。省略=返整行全字段")),
                ("offset", schema_int("field 分段模式: 从该字符偏移开始读 (默认 0; 用上次返回的 next_offset 续读)", 0, 100_000_000)),
                ("account", schema_str("多账号库指定账号 wxid; 实时查 (hot) 也要 (或用服务器默认账号)")),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读加密微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
            ], &["type", "id"]),
        }),
        json!({
            "name": "wx_get_media",
            "description": "取媒体引用 (图片/视频/语音/表情的 md5+类型+大小, 不返裸数据)。拿到引用再按需取实际文件。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("limit", schema_int("最多几条 (默认 30, 上限 200)", 1, 200)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("账号 wxid; 多账号库必填, 实时查也要 (或用服务器默认账号)")),
            ], &[]),
        }),
        json!({
            "name": "wx_resolve_names",
            "description": "批量把 wxid 换成显示名 (昵称/备注)。查完消息后用它把满屏 wxid 换成人能认的名字, 好向用户复述。默认 auto(有 L1 读冷否则热); mode=hot 实时读加密微信库 contact.db (要 account)。",
            "inputSchema": schema_obj(&[
                ("wxids", schema_arr_str("要解析成名字的 wxid 数组")),
                ("account", schema_str("多账号库指定账号 wxid")),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库 contact.db(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
            ], &["wxids"]),
        }),
        json!({
            "name": "wx_list_accounts",
            "description": "列出已缓存 key、可查的账号 wxid。多账号时先看有哪些账号, 再把选定的 wxid 传给各工具的 account 参。",
            "inputSchema": schema_obj(&[], &[]),
        }),
        json!({
            "name": "wx_resolve",
            "description": "展开合并转发消息 (别人打包发来的一串聊天记录)。给 msg_id 展开里面的子消息; 不给则列出所有合并转发消息供挑选。默认读 L1; mode=hot 直读微信库拿实时数据。",
            "inputSchema": gated_schema_obj(&[
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 实时读微信库(要 account) / cold 读 L1(快但可能旧)", &["hot", "cold", "auto"])),
                ("msg_id", schema_str("要展开的合并转发消息 id; 省略=列出所有合并转发")),
                ("source", schema_str("展开时精确定位分片(消息 id 跨分片会重号, 用 list 结果里的 source 值; 省略且不重号时可不填)")),
                ("limit", schema_int("最多几条 (默认 20, 上限 100)", 1, 100)),
                ("offset", schema_int("跳过前几条 (翻页, 默认 0)", 0, 10_000_000)),
                ("account", schema_str("多账号库指定账号 wxid; 实时查也要")),
            ], &[]),
        }),
        json!({
            "name": "contact_pack",
            "description": "某联系人一把梭概览: 名字/备注 + 最近几条聊天。快速了解某个人时用。",
            "inputSchema": schema_obj(&[
                ("wxid", schema_str("联系人 wxid")),
                ("account", schema_str("账号 wxid; 多账号必填或用服务器默认")),
            ], &["wxid"]),
        }),
        json!({
            "name": "session_pack",
            "description": "某会话一把梭概览: 会话标识 + 最近几条消息。快速了解某个群/单聊时用。",
            "inputSchema": schema_obj(&[
                ("conv", schema_str("对方 wxid 或群 id (xxxx@chatroom)")),
                ("account", schema_str("账号 wxid; 多账号必填或用服务器默认")),
            ], &["conv"]),
        }),
        json!({
            "name": "wx_describe",
            "description": "拉查询流程/工具字典。不确定用哪个工具、conv 怎么传、多账号怎么办时先调它。",
            "inputSchema": schema_obj(&[], &[]),
        }),
        json!({
            "name": "wx_current_time",
            "description": "本机当前时间 (unix 秒)。LLM 锚不住'今天/上周'时先调它, 再据此换算相对时间。",
            "inputSchema": schema_obj(&[], &[]),
        }),
        json!({
            "name": "wx_exec",
            "description": "只读 SQL 逃生口: 固定工具覆盖不了的查询 (自定义聚合 / 多表 JOIN / 特殊过滤) 时, 直接跑一条只读 SELECT。仅单条 SELECT/WITH/EXPLAIN (无写、无分号多语句; ATTACH/PRAGMA 会被拒)。不清楚表和列先跑 `SELECT name,sql FROM sqlite_master WHERE type='table'` 看结构。默认 cold 查 L1 投影库 (非账号隔离, 多账号库自己在 SQL 里按 account_id 过滤)。mode=hot 直查**加密源库原始裸 schema** (要 source_db 选库 + account): 表名是 Msg_<md5>/Name2Id/裸 contact 等, 与 L1 完全不同, 专家向。优先用专用工具 (已折叠好、更省 token), exec 是兜底。",
            "inputSchema": schema_obj(&[
                ("sql", schema_str("一条只读 SQL: SELECT / WITH / EXPLAIN (无写操作, 无分号分隔的多语句)")),
                ("max_rows", schema_int("最多返回几行 (默认 100, 上限 1000; 超出截断, 看 meta.has_more)", 1, 1000)),
                ("mode", schema_enum("查询模式: auto 有 L1 走冷否则热(默认) / hot 直查加密源库原始 schema(要 source_db+account) / cold 查 L1 投影库", &["hot", "cold", "auto"])),
                ("source_db", schema_str("mode=hot 必填: 源库相对路径 (db_storage 下, 如 contact/contact.db / message/message_0.db / session/session.db)")),
                ("account", schema_str("多账号库指定账号 wxid; mode=hot 也要 (或用服务器默认账号)")),
            ], &["sql"]),
        }),
        json!({
            "name": "wx_capture_list",
            "description": "看选择性采集清单 (R19): 当前圈定了哪些群/好友让 ingest/watch 只增量存。空清单=全采所有会话。**只读** —— 圈定/停采走 CLI `capture add/rm` (采集目标是本地配置, 只读服务不暴露写)。清单极大 (数千会话) 超 max_bytes 时本工具返头部 + `oversized` 标注 (无分页参数, 忽略 notice 里泛化的 limit 提示); 取全量请调大 `max_bytes`, 或走不封字节的 CLI `capture list` / HTTP `GET /capture`。",
            "inputSchema": schema_obj(&[
                ("account", schema_str("多账号库指定账号 wxid; 单账号库可省 (自动检测唯一账号)")),
            ], &[]),
        }),
    ];
    // 给每个工具补统一的 max_bytes 参数 (响应字节预算, 所有返数据路径都认它)。wx_current_time 是无 args 的纯时钟、
    // 响应恒极小, 略过 (免宣传一个它其实忽略的参数)。
    for d in &mut defs {
        if d.get("name").and_then(Value::as_str) == Some("wx_current_time") {
            continue;
        }
        if let Some(props) = d.pointer_mut("/inputSchema/properties").and_then(Value::as_object_mut) {
            props.insert(
                "max_bytes".into(),
                schema_int(
                    "本次响应字节预算 (默认 49152=48KiB; 结果被截 meta._budget.truncated=true 时调高重查, 最高 524288=512KiB)。",
                    16_384,
                    524_288,
                ),
            );
        }
    }
    defs
}

/// tools/call 分派。恒返 tool-result `Value` (成功=tool_ok / 失败=tool_err isError), 不抛协议错。
pub async fn call_tool(name: &str, args: &Value, ctx: &Ctx) -> Value {
    // codex 审 P2: 分页参数若**存在但非非负整数**(字符串 "30"/负数/小数)→ 显式报错。inputSchema 声明这些是
    // integer[0,..], 但 MCP server 不强制 schema → arg_limit/arg_count 的 as_u64 会把非法值当缺省静默返第一页
    // (返成功但错页)。这里一处兜住所有工具(null=当缺省放行)。
    for key in ["limit", "offset", "before", "after"] {
        if let Some(v) = args.get(key) {
            if !v.is_null() && !v.is_u64() {
                return tool_err(
                    "分页参数不对",
                    &format!("{key} 要是非负整数 (收到 {v}); 别传字符串/负数/小数"),
                );
            }
        }
    }
    // round-15 codex P2: `confirm` 若存在但非布尔 → 显式报错(**不依赖 mode**)。原 `parse_confirm_arg` 只在
    //   `mcp_cost_gate` 的 hot 臂调, mode=cold 时绕过 → `{"mode":"cold","confirm":"true"}` 会静默接受畸形值,
    //   与 CLI(clap)/HTTP(serde 拒) 不一致。这里一处兜住所有工具/所有 mode(缺省/null 放行, 同上分页校验口径)。
    if let Err(e) = parse_confirm_arg(args) {
        return e;
    }
    match name {
        "wx_contacts" => wx_contacts(args, ctx).await,
        "wx_account" => wx_account(args, ctx).await,
        "wx_sessions" => wx_sessions(args, ctx).await,
        "wx_messages" => wx_messages(args, ctx).await,
        "wx_search" => wx_search(args, ctx).await,
        "wx_stats" => wx_stats(args, ctx).await,
        "wx_dormant" => wx_dormant(args, ctx).await,
        "wx_followups" => wx_followups(args, ctx).await,
        "wx_money" => wx_money(args, ctx).await,
        "wx_members" => wx_members(args, ctx).await,
        "wx_favorites" => wx_favorites(args, ctx).await,
        "wx_friend_requests" => wx_friend_requests(args, ctx).await,
        "wx_channels" => wx_channels(args, ctx).await,
        "wx_emoticons" => wx_emoticons(args, ctx).await,
        "wx_chatrooms" => wx_chatrooms(args, ctx).await,
        "wx_avatars" => wx_avatars(args, ctx).await,
        "wx_biz_contacts" => wx_biz_contacts(args, ctx).await,
        "wx_moments" => wx_moments(args, ctx).await,
        "wx_interactions" => wx_interactions(args, ctx).await,
        "wx_sns_notify" => wx_sns_notify(args, ctx).await,
        "wx_fav_media" => wx_fav_media(args, ctx).await,
        "wx_fav_tags" => wx_fav_tags(args, ctx).await,
        "wx_hongbao_claims" => wx_hongbao_claims(args, ctx).await,
        "wx_group_pay_members" => wx_group_pay_members(args, ctx).await,
        "wx_pii_scan" => wx_pii_scan(args, ctx).await,
        "wx_extract" => wx_extract(args, ctx).await,
        "wx_events" => wx_events(args, ctx).await,
        "wx_calls" => wx_calls(args, ctx).await,
        "wx_biz" => wx_biz(args, ctx).await,
        "wx_mentions" => wx_mentions(args, ctx).await,
        "wx_thread" => wx_thread(args, ctx).await,
        "wx_links" => wx_links(args, ctx).await,
        "wx_files" => wx_files(args, ctx).await,
        "wx_locations" => wx_locations(args, ctx).await,
        "wx_group_events" => wx_group_events(args, ctx).await,
        "wx_cards" => wx_cards(args, ctx).await,
        "wx_inspect" => wx_inspect(args, ctx).await,
        "wx_get_media" => wx_get_media(args, ctx).await,
        "wx_resolve_names" => wx_resolve_names(args, ctx).await,
        "wx_list_accounts" => wx_list_accounts(args, ctx).await,
        "wx_resolve" => wx_resolve(args, ctx).await,
        "contact_pack" => contact_pack(args, ctx).await,
        "session_pack" => session_pack(args, ctx).await,
        "wx_describe" => wx_describe(args, ctx),
        "wx_current_time" => wx_current_time(),
        "wx_exec" => wx_exec(args, ctx).await,
        "wx_capture_list" => wx_capture_list(args, ctx).await, // R19 选择性采集清单 (只读反映)
        _ => tool_err("未知工具", &format!("'{name}' 不是可用工具; 调 tools/list 看清单")),
    }
}

// ── 工具实现 (薄壳: 取 ctx + args → 调 native-query → 折叠) ──

/// 冷查通用: 从 ctx 取 L1 路径 + 从 args 取 account → 打开**账号 scoped** 连接。
/// 返 (conn, l1_path, account_sha) 或 Err(tool_err)。
fn open_cold(args: &Value, ctx: &Ctx) -> Result<(rusqlite::Connection, String, Option<String>), Value> {
    let Some(l1) = ctx.l1_db.clone() else {
        return Err(tool_err(
            "服务器未配置 L1 数据库",
            "启动 mcp 时用 --l1-db 指向 ingest 产出的 L1 库",
        ));
    };
    let account = resolve_account(args, ctx, &l1)?;
    let account_sha = account.as_deref().map(native_core::sha256_hex);
    match native_query::open_l1_scoped(&l1, account_sha.as_deref()) {
        Ok(conn) => Ok((conn, l1, account_sha)),
        Err(e) => Err(tool_err("打不开数据库", &err_str(&e))),
    }
}

/// 解析要用的账号 (H3 + 审查 P1-2/3): 工具 `account` 参 > 服务器 `default_account`。**无显式账号时**探测库里
/// 真实账号维度 (跨所有含 `account_id_sha` 的表并集, **不是**只探 person):
/// - 恰 1 个账号 → `Ok(None)` (单账号库, 不过滤 = 那一个)。
/// - >1 个账号 → `Err` 列候选让 LLM 选 (别静默合并两账号; instructions 承诺的"列候选"在此落地)。
/// - **探不出** (打库失败 / 无账号表 / 旧库缺列) → `Err` **fail-closed** (判不出维度就别裸查, 防仅存于
///   message 的二号账号被并库泄漏)。
fn resolve_account(args: &Value, ctx: &Ctx, l1: &str) -> Result<Option<String>, Value> {
    let explicit = arg_account(args).or_else(|| ctx.default_account.clone());
    // fail-closed 决策收敛在共享内核 (三皮同核, 免 MCP/HTTP 漂移; 审查 P1-2/3)。
    match native_query::resolve_account(l1, explicit) {
        Ok(native_query::AccountResolution::Use(a)) => Ok(a),
        Ok(native_query::AccountResolution::Ambiguous { candidates }) => Err(tool_err_with(
            "多账号库需指定账号",
            "传 account 参选一个 (或先 wx_list_accounts 看有哪些); 候选见 candidates",
            Some(json!(candidates)),
        )),
        Err(e) => Err(tool_err(
            "无法确定库里的账号 (判不出账号维度)",
            &format!("请显式传 account (wxid) 指定要查哪个账号; 底层: {}", err_str(&e)),
        )),
    }
}

async fn wx_contacts(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let q = args.get("query").and_then(Value::as_str);
    let limit = arg_limit(args, 20, 100);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            // 冷查是 keyset 游标 / 热查是 offset —— 给了 cursor 却要热查 = 参数组合矛盾, 显式拒。
            // (照 CLI `cmd_contacts` 的镜像守卫: 别静默忽略用户的翻页意图。)
            if args.get("cursor").is_some() {
                return tool_err(
                    "cursor 用不了",
                    "cursor 是冷查的 keyset 游标; 实时查请用 offset 翻页 (或 mode=cold 走 L1)",
                );
            }
            let wxid = match hot_wxid(args, ctx, "联系人") {
                Ok(w) => w,
                Err(e) => return e,
            };
            let offset = arg_count(args, "offset", 0, 10_000_000);
            match native_query::hot_contacts(&wxid, ctx.wechat_data_dir.as_deref(), q, limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查联系人失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            // codex 审 P2: 冷查是 **keyset 游标**, 压根不吃 offset —— 收下却不传给 `contacts_query`
            // 就是**静默吞**(用户给 offset 拿到的是第一页, 还 isError=false)。
            // 这条 CLI 侧修过一次(`cmd_contacts` 冷分支拒 offset), 我接 MCP/HTTP 时**原样又犯了两遍**。
            // 判据是"**每一皮 × 每个分支**, 这参数被读了吗", 不是"CLI 那条修了就完事"。
            // **判据: offset 键只要出现, 就必须是合法的 0; 其余一律拒** —— 不能写成
            // `.and_then(as_u64).is_some_and(|o| o != 0)`: 那样 `offset: -1` / `"abc"` / `1.5` 的
            // `as_u64()` 全返 None → `is_some_and` 给 false → **不拒** → 照样静默走冷查返第一页,
            // 守卫等于只挡住了合法的正整数 (codex 复审逮到)。
            // MCP 服务端**不校验 inputSchema**(`tools/call` 原样转发 arguments), 这些畸形值真能传进来。
            if let Some(v) = args.get("offset") {
                if v.as_u64() != Some(0) {
                    return tool_err(
                        "offset 用不了",
                        "offset 是实时查(mode=hot)的翻页方式; 冷查请用 cursor 续翻 (上次返回的 next_cursor)",
                    );
                }
            }
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let cursor = args.get("cursor").and_then(Value::as_str);
            match native_query::contacts_query(&conn, &l1, account_sha.as_deref(), q, limit, cursor) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args), // 挂 freshness (轮7 审 P2)
                Err(e) => tool_err("查联系人失败", &err_str(&e)),
            }
        }
    }
}

async fn wx_account(args: &Value, ctx: &Ctx) -> Value {
    // R16-6 双模: 冷读 L1 各表 count; 热聚合源库实时计数 (messages 全扫较慢)。
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "账号统计") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, 0).await {
                return err;
            }
            match native_query::hot_account(&wxid, ctx.wechat_data_dir.as_deref(), None, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时账号统计失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, _l1, _sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::account_query(&conn) {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查账号概览失败", &err_str(&e)),
            }
        }
    }
}

async fn wx_sessions(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 20, 100);
    // 复审#4: offset → 会话超 limit 可翻页够到。
    let offset = arg_count(args, "offset", 0, 10_000_000);
    // R6: mode 派发 (auto 按服务端有无 --l1-db)。
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let account = arg_account(args).or_else(|| ctx.default_account.clone());
            let Some(acc) = account else {
                return tool_err(
                    "需要指定账号",
                    "实时查会话要 account (wxid); 或设默认账号; 或 mode=cold 走 L1",
                );
            };
            let Ok(wxid) = acc.parse::<native_core::Wxid>() else {
                return tool_err("账号格式不对", "account 要是合法的 wxid (如 wxid_ 开头)");
            };
            match native_query::hot_sessions(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查会话失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::cold_sessions_query(&conn, limit, offset) {
                Ok(mut r) => {
                    if let Some(f) = native_query::cold_freshness(&l1, account_sha.as_deref()) {
                        r.meta = r.meta.with_freshness(f);
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("冷查会话失败 (库是 L1?)", &err_str(&e)),
            }
        }
    }
}

fn wx_current_time() -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    tool_ok(
        &json!({
            "epoch_seconds": now,
            "note": "本机当前时间 (unix 秒); '今天/上周'等相对时间据此换算"
        }),
        fold::DEFAULT_MAX_BYTES, // 无 args 的纯时钟, 响应恒极小; 用默认预算即可。
    )
}

/// R22 懒式落库 (ADR-508 D24): 冷查前把**一个会话**的新消息补进 L1。
///
/// 返 `Some(错误 Value)` = 没补成, 调用方应当**直接返回它**而不是继续读旧数据 —— 静默跳过等于
/// 告诉 AI "这是最新的"。要显式读现有的传 `refresh=false`。
/// 读该会话上次被补到什么时候 (给信封的 `chat_refreshed_at`); 取不到就省略, 不谎报。
fn chat_refreshed_of(args: &Value, ctx: &Ctx, chat: &str) -> Option<i64> {
    let l1 = ctx.l1_db.as_deref()?;
    let acc = arg_account(args).or_else(|| ctx.default_account.clone())?;
    let wxid = native_core::key_provider::Wxid::try_new(acc).ok()?;
    native_query::chat_refreshed_at(std::path::Path::new(l1), &wxid, chat)
}

/// 返 `Ok(Some(原因))` = 没补成但数据可读(照读 L1, 原因进信封的 `refresh_skipped`);
/// `Ok(None)` = 补成了; `Err` = 真出错, 调用方直接返回它。
///
/// **没补成不报错**: "冷库拷到别的机器上自足查"是本仓一直成立的契约, 硬失败会打断它。
/// 但也**不能装作补过了** —— 原因进结构化输出, AI 看得见(D24 审 P1)。
async fn refresh_chat(args: &Value, ctx: &Ctx, chat: &str) -> Result<Option<&'static str>, Value> {
    let Some(l1) = ctx.l1_db.as_deref() else {
        return Err(tool_err("冷查要 L1 库", "服务端起 mcp 时给 --l1-db"));
    };
    let account = arg_account(args).or_else(|| ctx.default_account.clone());
    let Some(acc) = account else {
        // 没账号 = 够不着源库 → 降级读现有的并标记, 不硬失败。
        return Ok(Some("source_unavailable"));
    };
    let wxid = match native_core::key_provider::Wxid::try_new(acc) {
        Ok(w) => w,
        Err(e) => return Err(tool_err("wxid 不合法", &e.to_string())),
    };
    match native_query::ensure_chat_fresh(std::path::Path::new(l1), &wxid, chat, ctx.wechat_data_dir.as_deref()).await {
        Ok(r) => Ok(r.skip_reason()),
        Err(e) => Err(tool_err(
            "补入新消息失败 (要读 L1 现有的请传 refresh=false)",
            &err_str(&e),
        )),
    }
}

async fn wx_messages(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let Some(chat) = args.get("conv").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return tool_err(
            "需要指定会话",
            "conv 传对方 wxid 或群 id (形如 xxxx@chatroom); 不知道先调 wx_sessions",
        );
    };
    let around = args.get("around").and_then(Value::as_i64);
    // R6: mode 派发 (auto 按服务端有无 --l1-db)。
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            // R6: offset 不支持实时查消息 (hot_messages/around 返最近 N, 无分页) → offset>0 显式拒, **不静默吞**
            // (对齐 HTTP get_messages; 否则 AI 传 offset 拿回恒最近页, 误以为在翻页 → 重复页/死循环)。
            if arg_count(args, "offset", 0, 10_000_000) > 0 {
                return tool_err(
                    "offset 不支持实时查消息",
                    "实时查返最近 N 条无分页; 深翻历史用 mode=cold, 或去掉 offset",
                );
            }
            let account = arg_account(args).or_else(|| ctx.default_account.clone());
            let Some(acc) = account else {
                return tool_err(
                    "需要指定账号",
                    "实时查消息要 account (wxid); 或设默认账号; 或 mode=cold 走 L1",
                );
            };
            let Ok(wxid) = acc.parse::<native_core::Wxid>() else {
                return tool_err("账号格式不对", "account 要是合法 wxid");
            };
            // around=某条消息 create_time → 取前后文 (④ 对拍缺口); 否则取最近 N。
            if let Some(center) = around {
                let before = arg_count(args, "before", 5, 25);
                let after = arg_count(args, "after", 5, 25);
                return match native_query::hot_messages_around(
                    &wxid,
                    chat,
                    center,
                    before,
                    after,
                    ctx.wechat_data_dir.as_deref(),
                    None,
                )
                .await
                {
                    Ok(r) => {
                        let b = arg_max_bytes(args);
                        tool_ok(&fold::envelope(&r, b), b)
                    }
                    Err(e) => tool_err("查消息上下文失败 (会话 id 对? 账号 key 缓存了?)", &err_str(&e)),
                };
            }
            let limit = arg_limit(args, 10, 50); // 消息默认 10 顶 50 (§2.2)
            match native_query::hot_messages(&wxid, chat, ctx.wechat_data_dir.as_deref(), None, limit).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查消息失败 (会话 id 对? 账号 key 缓存了?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            // 冷查无消息上下文 (around 只实时查有) → 显式报错, **不静默忽略 around**。
            if around.is_some() {
                return tool_err(
                    "冷查不支持消息上下文",
                    "around (前后文) 只实时查 (mode=hot) 有; 去掉 around, 或用 mode=hot",
                );
            }
            // R22 懒式落库: 先把这个会话的新消息补进 L1, 于是冷查结果总是最新的。判据是插入序
            // (`WHERE local_id > 游标`)不是时间 —— 回填 / 表重建 / 乱序 / 同秒并发都不漏。
            // `refresh=false` 显式读 L1 现有的。没补成时**不报错**(冷库自足查的契约), 但把原因
            // 带进信封的 `refresh_skipped` —— 不能让 AI 以为拿到的是最新的。
            let mut skip_reason: Option<&'static str> = None;
            if args.get("refresh").and_then(Value::as_bool) != Some(false) {
                match refresh_chat(args, ctx, chat).await {
                    Ok(r) => skip_reason = r,
                    Err(e) => return e,
                }
            }
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let limit = arg_limit(args, 10, 50);
            let offset = arg_count(args, "offset", 0, 10_000_000);
            match native_query::cold_messages_query(&conn, chat, limit, offset) {
                Ok(mut r) => {
                    // R22: 账号级 ingested_at 之外, 再报**这个会话**补到什么时候 —— 懒式落库按会话推进,
                    // 你查的这个可能刚补过, 别的还停在几个月前。
                    //
                    // ⚠️ 原来这里是 `if let Some(f) = cold_freshness(..)`(第四轮对抗审 P1): 而 `cold_freshness`
                    // 在 `etl_state` **没水位**时返 `None` —— `ingest --no-messages` 建的库、或多账号库里
                    // 查一个没有消息水位的账号, 都落这一格。于是 `refresh_skipped` 和 `chat_refreshed_at`
                    // 一起蒸发, AI 拿到 0 条消息 + 空 meta, 正是信封文档写死要防的那种"这个会话有 0 条消息"。
                    let chat_at = chat_refreshed_of(args, ctx, chat);
                    let base = native_query::cold_freshness(&l1, account_sha.as_deref());
                    if base.is_some() || chat_at.is_some() || skip_reason.is_some() {
                        let f = base
                            .unwrap_or(native_query::Freshness::Cold {
                                ingested_at: None,
                                stale: None,
                                chat_refreshed_at: None,
                                refresh_skipped: None,
                            })
                            .with_chat_refreshed_at(chat_at)
                            .with_refresh_skipped(skip_reason);
                        r.meta = r.meta.with_freshness(f);
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("冷查消息失败 (库是 L1?)", &err_str(&e)),
            }
        }
    }
}

async fn wx_search(args: &Value, ctx: &Ctx) -> Value {
    // R16-6 🔴降级双模: 冷=FTS5 bm25 (search 特殊: FTS 靠 message.rowid 关联 → 非 scoped conn + 显式账号过滤);
    // 热=全库扫 text.contains 子串 (无 FTS/无 bm25, 时间序)。
    let Some(q) = args.get("query").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return tool_err("需要搜索词", "query 传要搜的关键词");
    };
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 10, 50); // search 默认 10 顶 50 (§2.2)
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "搜索") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, limit).await {
                return err;
            }
            match native_query::hot_search(&wxid, ctx.wechat_data_dir.as_deref(), None, q, limit, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时搜索失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let Some(l1) = ctx.l1_db.as_deref() else {
                return tool_err(
                    "服务器未配置 L1 数据库",
                    "启动 mcp 时用 --l1-db 指向 L1 库 (或 mode=hot 走实时全扫)",
                );
            };
            let account = match resolve_account(args, ctx, l1) {
                Ok(a) => a,
                Err(e) => return e,
            };
            let account_sha = account.as_deref().map(native_core::sha256_hex);
            let conn = match native_query::open_l1(l1) {
                Ok(c) => c,
                Err(e) => return tool_err("打不开数据库", &err_str(&e)),
            };
            match native_query::search_query(&conn, q, limit as i64, account_sha.as_deref()) {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("搜索失败 (先建过全文索引?)", &err_str(&e)),
            }
        }
    }
}

/// exec 并发闸 (R7, 镜像 HTTP `EXEC_SEMAPHORE(4)`): 当前 stdio 传输**串行** (一次一请求) 故暂非瓶颈, 但
/// [`crate::handle_line`] 传输无关 (将来可挂并发 HTTP/SSE 传输) → 提前限并发, 全局 exec RAM 有界 (单请求
/// exec_hardened 8MB/单值 + 64MB/结果 界, × 4)。第 5+ 请求 await 排队 (只占小请求态)。
static EXEC_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// wx_exec: 只读 SQL 逃生口 (R7/⑪) —— 镜像 HTTP `/exec`, 调**同一份** [`native_query::exec_hardened`] (硬只读
/// 三层: is_readonly_sql + READ_ONLY 开库 + authorizer 拒 ATTACH/PRAGMA; DoS 界: 8MB/单值 + 15s 算力)。MCP 侧
/// 另加三道: (1) 层1 **快拒** (写/多语句在开库+spawn 前即回 isError), (2) **并发闸** (EXEC_SEMAPHORE), (3)
/// **spawn_blocking** —— 裸 SQL 可跑无界算力, 必移出 stdio async 线程, 否则一条笛卡尔积把整个 MCP 进程冻住
/// (stdio 单进程, 无 HTTP 的多线程池)。输出走 [`fold::exec_envelope`] (保列 + 值级脱敏 + 48KB 封顶)。
async fn wx_exec(args: &Value, ctx: &Ctx) -> Value {
    let Some(sql) = args
        .get("sql")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return tool_err("需要 sql", "sql 传一条只读 SELECT / WITH / EXPLAIN 语句");
    };
    // 层1 快拒: 明显写 / 分号多语句在开库 + spawn_blocking **前**就回 isError (不劳开库)。exec_hardened 内再兜一道。
    if !native_query::is_readonly_sql(sql) {
        return tool_err(
            "只允许只读 SQL",
            "仅单条 SELECT / WITH / EXPLAIN (无写操作, 无分号分隔的多语句); 改数据 / ATTACH / PRAGMA 不支持",
        );
    }
    // max_rows: exec 默认 100 顶 1000 (LLM 消费 + fold 48KB 封顶; 内存另有 exec_hardened 8MB/单值 + 64MB/结果 界兜)。
    let max_rows = args
        .get("max_rows")
        .and_then(Value::as_u64)
        .map_or(100, |n| usize::try_from(n).unwrap_or(100).clamp(1, 1000));
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let sql = sql.to_string();
    let b = arg_max_bytes(args);
    // R16-6 双模: 冷跑 L1 投影 schema (exec_hardened); 热跑源库原始裸 schema (hot_exec → exec_hardened_vfs, --source-db
    // 选库)。并发闸 EXEC_SEMAPHORE + CPU 隔离 spawn_blocking 两路都要 (裸 SQL 可跑无界算力)。
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let Some(source_db) = args.get("source_db").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
                return tool_err(
                    "热查 exec 需要 source_db",
                    "source_db 传源库相对路径 (db_storage 下, 如 contact/contact.db / message/message_0.db); 用 SELECT name FROM sqlite_master WHERE type='table' 查表名",
                );
            };
            let wxid = match hot_wxid(args, ctx, "exec") {
                Ok(w) => w,
                Err(e) => return e,
            };
            let source_db = source_db.to_string();
            // 并发闸 permit 传进 hot_exec 的 scan_permit —— hot_exec 内部 spawn_blocking 持到真跑完 (不随 future 取消提前释放)。
            let permit = EXEC_SEMAPHORE.acquire().await.expect("exec semaphore 不会关闭");
            match native_query::hot_exec(
                &wxid,
                ctx.wechat_data_dir.as_deref(),
                &source_db,
                &sql,
                max_rows,
                Some(permit),
            )
            .await
            {
                Ok(r) => tool_ok(&fold::exec_envelope(&r, b), b),
                Err(e) => tool_err(
                    "热查 exec 失败 (源库路径对? 账号 key 缓存了? SQL 只读? 表名对?)",
                    &err_str(&e),
                ),
            }
        }
        native_query::EffectiveMode::Cold => {
            let Some(l1) = ctx.l1_db.clone() else {
                return tool_err(
                    "服务器未配置 L1 数据库",
                    "启动 mcp 时用 --l1-db 指向 ingest 产出的 L1 库 (或 mode=hot + source_db 直查源库)",
                );
            };
            // 并发闸 + CPU 隔离: permit 移进闭包持到真跑完 (spawn_blocking 不随 future 取消, permit 若在 async 作用域会
            // 提前释放打穿并发闸); spawn_blocking 把同步阻塞 SQL 移出 stdio async 线程。
            let permit = EXEC_SEMAPHORE.acquire().await.expect("exec semaphore 不会关闭");
            let joined = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                native_query::exec_hardened(&l1, &sql, max_rows)
            })
            .await;
            match joined {
                Ok(Ok(r)) => tool_ok(&fold::exec_envelope(&r, b), b),
                Ok(Err(e)) => tool_err("exec 查询失败 (被只读策略拒 / SQL 语法 / 表名列名错?)", &err_str(&e)),
                Err(join_e) => tool_err("exec 任务失败", &join_e.to_string()),
            }
        }
    }
}

/// `wx_stats` — 消息分组统计。**R16-5 起冷热双模** (热走 hot_stats 全扫全类型 HashMap 累加拿实时; 冷走 stats_query 读 L1)。
async fn wx_stats(args: &Value, ctx: &Ctx) -> Value {
    let by = match args.get("by").and_then(Value::as_str).unwrap_or("day") {
        "type" => native_query::StatsBy::Type,
        "conv" => native_query::StatsBy::Conv,
        "sender" => native_query::StatsBy::Sender,
        "day" => native_query::StatsBy::Day,
        other => return tool_err("by 取值不对", &format!("'{other}' 无效; 取 type/conv/sender/day 之一")),
    };
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 50); // top-N (§2.2)
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "统计") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, limit).await {
                return err;
            }
            match native_query::hot_stats(&wxid, ctx.wechat_data_dir.as_deref(), None, by, limit, 0, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时统计失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::stats_query(&conn, by, limit, 0) {
                Ok(r) => cold_ok(r, &l1, sha.as_deref(), args),
                Err(e) => tool_err("统计失败", &err_str(&e)),
            }
        }
    }
}

/// `wx_dormant` — 沉睡会话排行 (最久没说话的会话)。**R16-6 起冷热双模** (冷 `dormant_query` 读 L1 message
/// GROUP BY conv_id; 热 `hot_dormant` 全扫源库聚合每会话最后说话时间, 较慢)。offset 恒 0 (取 top-N 不翻页)。
async fn wx_dormant(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 15, 50); // top-N (对齐 CLI 默认 15)
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "沉睡会话") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, limit).await {
                return err;
            }
            match native_query::hot_dormant(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, 0, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err(
                    "实时查沉睡会话失败 (账号 key 缓存了? 数据目录对? 全扫较慢)",
                    &err_str(&e),
                ),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::dormant_query(&conn, limit, 0) {
                Ok(r) => cold_ok(r, &l1, sha.as_deref(), args),
                Err(e) => tool_err("查沉睡会话失败", &err_str(&e)),
            }
        }
    }
}

/// `wx_followups` — 待回复会话 (每会话最后一条是对方发的、本账号还没回 = 待跟进)。**R16-6 起冷热双模** (冷
/// `followups_query` 读 L1 message JOIN; 热 `hot_followups` 全扫源库聚合每会话末条非系统消息, 较慢)。offset 恒 0。
async fn wx_followups(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let private_only = args.get("private_only").and_then(Value::as_bool).unwrap_or(false);
    let limit = arg_limit(args, 30, 50); // top-N (对齐 CLI 默认 30)
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "待回复会话") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, limit).await {
                return err;
            }
            match native_query::hot_followups(
                &wxid,
                ctx.wechat_data_dir.as_deref(),
                None,
                private_only,
                limit,
                0,
                None,
            )
            .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err(
                    "实时查待回复会话失败 (账号 key 缓存了? 数据目录对? 全扫较慢)",
                    &err_str(&e),
                ),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::followups_query(&conn, private_only, limit, 0) {
                Ok(r) => cold_ok(r, &l1, sha.as_deref(), args),
                Err(e) => tool_err("查待回复会话失败", &err_str(&e)),
            }
        }
    }
}

/// `wx_money` — 查交易 (转账/红包/群收款合并时间线)。**R16-4 起冷热双模** (默认档两源混合: 热走 hot_money
/// 读 general.db 专表 + 扫 msg49 补金额/人数; 冷走 money_query 读 L1)。`kind` 选源。
async fn wx_money(args: &Value, ctx: &Ctx) -> Value {
    let kind = match args.get("kind").and_then(Value::as_str).unwrap_or("all") {
        "all" => native_query::MoneyKind::All,
        "transfer" => native_query::MoneyKind::Transfer,
        "red-envelope" | "red_envelope" => native_query::MoneyKind::RedEnvelope,
        "group-pay" | "group_pay" => native_query::MoneyKind::GroupPay,
        other => {
            return tool_err(
                "kind 取值不对",
                &format!("'{other}' 无效; 取 all/transfer/red-envelope/group-pay"),
            )
        }
    };
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 20, 100);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "交易") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, limit).await {
                return err;
            }
            match native_query::hot_money(&wxid, ctx.wechat_data_dir.as_deref(), None, kind, limit, 0, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查交易失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, _l1, _sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::money_query(&conn, kind, limit, 0) {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查转账/红包失败", &err_str(&e)),
            }
        }
    }
}

/// `wx_members` — 查群成员。**R16-1 起冷热双模式 (降级件)**: hot 直读加密 `contact.db` 的 `chat_room`
/// 行解 proto; cold 读 L1 chatroom_member。
///
/// **热查明说降级** (决策②): `joined_at` 恒 null (源库 proto 无入群时刻); 已退群成员不返回 (仅当前在群快照);
/// summary 里 `partial:true`+`degraded` 说明 —— AI 调用方据此知道这份比冷查窄。
async fn wx_members(args: &Value, ctx: &Ctx) -> Value {
    let Some(chatroom) = args.get("chatroom").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return tool_err(
            "需要指定群",
            "chatroom 传群 id (形如 xxxx@chatroom); 不知道先调 wx_sessions/wx_contacts",
        );
    };
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let admins_only = args.get("admins_only").and_then(Value::as_bool).unwrap_or(false);
    let limit = arg_limit(args, 100, 500); // 审查 P1-6: list 工具必须有 limit (大群防击穿 48KB)。
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "群成员") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_members(
                &wxid,
                ctx.wechat_data_dir.as_deref(),
                chatroom,
                admins_only,
                limit,
                offset,
            )
            .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查群成员失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::members_query(&conn, chatroom, admins_only, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查群成员失败", &err_str(&e)),
            }
        }
    }
}

async fn wx_favorites(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let q = args.get("query").and_then(Value::as_str);
    let limit = arg_limit(args, 20, 100);
    // offset 冷热共用, 且在派发前算一次 (CLI 侧审 P3-3: 写在热分支里冷查就漏夹)。
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "收藏") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_favorites(&wxid, ctx.wechat_data_dir.as_deref(), q, limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查收藏失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::favorites_query(&conn, q, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args), // 挂 freshness (轮7 审 P2)
                Err(e) => tool_err("查收藏失败", &err_str(&e)),
            }
        }
    }
}

async fn wx_friend_requests(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 20, 100);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "好友申请") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_friend_requests(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查好友申请失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::friend_requests_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args), // 挂 freshness (轮7 审 P2)
                Err(e) => tool_err("查好友申请失败", &err_str(&e)),
            }
        }
    }
}

async fn wx_channels(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 20, 100);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "视频号足迹") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_finder_visits(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查视频号足迹失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::finder_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args), // 挂 freshness (轮7 审 P2)
                Err(e) => tool_err("查视频号足迹失败", &err_str(&e)),
            }
        }
    }
}

/// **R16-1**: 自定义表情 —— 引擎路径热查的第一条。冷查走引擎 `run_query(&CMD_EMOTICONS)`(读 L1),
/// 热查走 `hot_emoticons`(直读加密 emoticon.db)。5 键对齐。
async fn wx_emoticons(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 20, 100);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "表情") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_emoticons(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查表情失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            // 引擎冷查: cold_target 建 QueryTarget → run_query(&CMD_EMOTICONS)。挂 freshness 同 cold_ok
            // (引擎的 run_query 内部不挂; 三皮 meta 一致要 MCP 这边补 —— l1/account_sha 从 target 取)。
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_EMOTICONS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查表情失败 (ingest 了表情?)", &err_str(&e)),
            }
        }
    }
}

/// **R16-1**: 群列表 —— 引擎路径热查。冷查走引擎 `run_query(&CMD_CHATROOMS)`(读 L1),热查走
/// `hot_chatrooms`(直读加密 contact.db 的 chat_room, LEFT JOIN 群名/公告, proto 数成员)。5 键对齐。
async fn wx_chatrooms(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "群列表") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_chatrooms(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查群列表失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_CHATROOMS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查群列表失败 (ingest 了群?)", &err_str(&e)),
            }
        }
    }
}

/// **R16-1**: 头像清单 —— 引擎路径热查。冷查 `run_query(&CMD_AVATARS)`(读 L1), 热查 `hot_avatars`
/// (直读加密 head_image.db)。3 键对齐(不出头像 BLOB)。
async fn wx_avatars(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "头像") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_avatars(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查头像失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_AVATARS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查头像失败 (ingest 了头像?)", &err_str(&e)),
            }
        }
    }
}

/// **R16-1**: 企微联系人 —— 引擎路径热查。冷查 `run_query(&CMD_BIZ_CONTACTS)`(读 L1), 热查
/// `hot_biz_contacts`(直读加密 bizchat.db)。3 键对齐。
async fn wx_biz_contacts(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "企微联系人") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_biz_contacts(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查企微联系人失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_BIZ_CONTACTS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查企微联系人失败 (ingest 了企微?)", &err_str(&e)),
            }
        }
    }
}

/// **R16-1**: 朋友圈动态本体 —— 手写路径热查。冷查 `moments_query`(读 L1 moment 表), 热查 `hot_moments`
/// (直读加密 sns.db 的 SnsTimeLine, 复用 assemble_sns 解)。7 键对齐。
async fn wx_moments(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 20, 100);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "朋友圈") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_moments(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查朋友圈失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::moments_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查朋友圈失败 (ingest 了朋友圈?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_interactions` (**R16-3 子视图, 从零建**) — 朋友圈点赞评论(moment 派生)冷热双模式, 镜像 CLI `moments
/// --interactions` / HTTP `/moments/interactions`。热走 `hot_interactions`(读 sns.db SnsTimeLine 逐动态
/// parse_sns_interactions 抽赞/评, 一动态多互动), 冷走引擎 `run_query(&CMD_INTERACTIONS)` 读 L1 moment_interaction。
/// 5 键对齐: create_time/kind(like/comment)/from_nickname/from_user/content。
async fn wx_interactions(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "朋友圈点赞评论") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_interactions(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查朋友圈点赞评论失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_INTERACTIONS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查朋友圈点赞评论失败 (ingest 了朋友圈?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_sns_notify` (**R16-3 子视图, 从零建**) — 朋友圈互动通知(谁赞/评了我)冷热双模式, 镜像 CLI `moments
/// --inbox` / HTTP `/moments/inbox`。热走 `hot_sns_notify`(读 sns.db SnsMessage_tmp3 一通知一行), 冷走引擎
/// `run_query(&CMD_SNS_NOTIFY)` 读 L1 sns_notify。5 键对齐: create_time/notify_type/from_user/from_nickname/content。
async fn wx_sns_notify(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "朋友圈互动通知") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_sns_notify(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查朋友圈互动通知失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_SNS_NOTIFY, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查朋友圈互动通知失败 (ingest 了朋友圈?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_fav_media` (**R16-3 子视图, 从零建**) — 收藏媒体(收藏笔记里的图/文件/HTML)冷热双模式, 镜像 CLI
/// `favorites --media` / HTTP `/favorites/media`。热走 `hot_favorite_media`(读 favorite.db fav_db_item 笔记
/// content 逐收藏 parse_note_media 抽媒体), 冷走引擎 `run_query(&CMD_FAV_MEDIA)` 读 L1 favorite_media。6 键对齐:
/// fav_server_id/seq/data_type/media_md5/media_size/data_fmt。
async fn wx_fav_media(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "收藏媒体") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_favorite_media(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查收藏媒体失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_FAV_MEDIA, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查收藏媒体失败 (ingest 了收藏?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_fav_tags` (**R16-3 子视图, 从零建**) — 收藏标签(哪些收藏被贴了什么标签)冷热双模式, 镜像 CLI
/// `favorites --tags` / HTTP `/favorites/tags`。热走 `hot_favorite_tags`(读 favorite.db fav_bind_tag ⋈ fav_tag,
/// 按 anchor 去重), 冷走引擎 `run_query(&CMD_FAV_TAGS)` 读 L1 favorite_tag。3 键对齐:
/// tag_server_id/fav_server_id/tag_name。
async fn wx_fav_tags(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "收藏标签") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_favorite_tags(&wxid, ctx.wechat_data_dir.as_deref(), limit, offset).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查收藏标签失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_FAV_TAGS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查收藏标签失败 (ingest 了收藏?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_hongbao_claims` (**R16-4 money 子视图**) — 红包领取明细冷热双模式, 镜像 CLI `money --claims` / HTTP
/// `/money/claims`。热走 `hot_hongbao_claims`(scan msg10000 + parse_hongbao_claim), 冷走引擎 `run_query(&CMD_HONGBAO)`
/// 读 L1 message_hongbao_claim。5 键对齐: create_time/conv_id/send_id/is_own_envelope/peer_name。
async fn wx_hongbao_claims(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "红包领取明细") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_hongbao_claims(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None)
                .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查红包领取失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_HONGBAO, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查红包领取失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_group_pay_members` (**R16-4 money 子视图, 一对多**) — 群收款逐付款人冷热双模式, 镜像 CLI `money --payers` /
/// HTTP `/money/payers`。热走 `hot_group_pay_members`(scan msg49 + parse_appmsg payerlist, 一群收款消息多付款人),
/// 冷走引擎 `run_query(&CMD_GROUP_PAY_MEMBERS)` 读 L1 group_pay_member。4 键对齐: bill_no/payer_wxid/amount_fen/pay_status。
async fn wx_group_pay_members(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "群收款付款人") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_group_pay_members(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None)
                .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查群收款付款人失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_GROUP_PAY_MEMBERS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查群收款付款人失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_pii_scan` (**R16-5 慢档, 从零建**) — 全库扫文本 PII (手机号/身份证) 冷热双模式, 镜像 CLI `pii-scan`。
/// 热走 `hot_pii_scan`(scan msg1 + `scan_pii_in_text` 纯函数), 冷走 `pii_scan_query` 读 L1。默认打码。
async fn wx_pii_scan(args: &Value, ctx: &Ctx) -> Value {
    let kind = match args.get("kind").and_then(Value::as_str).unwrap_or("all") {
        "all" => native_query::PiiKind::All,
        "phone" => native_query::PiiKind::Phone,
        "idcard" => native_query::PiiKind::Idcard,
        other => return tool_err("kind 取值不对", &format!("'{other}' 无效; 取 all/phone/idcard")),
    };
    let reveal = args.get("reveal").and_then(Value::as_bool).unwrap_or(false);
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "PII 扫描") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, limit).await {
                return err;
            }
            match native_query::hot_pii_scan(&wxid, ctx.wechat_data_dir.as_deref(), None, kind, reveal, limit, None)
                .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时扫 PII 失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            // R16-5 复审 (Claude P2): 冷分支走 cold_ok 挂 cold_freshness (三皮 meta 契约)。
            let (conn, l1, sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::pii_scan_query(&conn, kind, reveal, limit) {
                Ok(r) => cold_ok(r, &l1, sha.as_deref(), args),
                Err(e) => tool_err("扫 PII 失败", &err_str(&e)),
            }
        }
    }
}

/// `wx_extract` (**R16-5 慢档, 从零建**) — 从全库文本抽 url/email/amount/phone/idcard 冷热双模式, 镜像 CLI `extract`
/// / HTTP `/extract`。热走 `hot_extract`(scan msg1 + `extract_matches` 纯函数), 冷走 `extract_query` 读 L1。不打码。
async fn wx_extract(args: &Value, ctx: &Ctx) -> Value {
    let kind = match args.get("kind").and_then(Value::as_str).unwrap_or("url") {
        "url" | "link" => native_query::ExtractKind::Url,
        "email" => native_query::ExtractKind::Email,
        "amount" => native_query::ExtractKind::Amount,
        "phone" => native_query::ExtractKind::Phone,
        "idcard" | "id" => native_query::ExtractKind::Idcard,
        other => {
            return tool_err(
                "kind 取值不对",
                &format!("'{other}' 无效; 取 url/email/amount/phone/idcard"),
            )
        }
    };
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "抽取") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_extract(&wxid, ctx.wechat_data_dir.as_deref(), None, kind, limit, offset, None)
                .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时抽取失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            // R16-5 复审 (Claude P2): 冷分支走 cold_ok 挂 cold_freshness (三皮 meta 契约: HTTP/CLI/MCP 冷查都带快照新鲜度)。
            let (conn, l1, sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::extract_query(&conn, kind, limit, offset) {
                Ok(r) => cold_ok(r, &l1, sha.as_deref(), args),
                Err(e) => tool_err("抽取失败", &err_str(&e)),
            }
        }
    }
}

/// `wx_events` (**R16-2**) — 群系统事件 (type10000) 冷热双模式, 镜像 CLI `events` / HTTP `/messages?kind=system`。
/// 可选 `sys_type` 过滤 (成员进出/撤回/拍一拍/…)。热查走 `hot_events`(scan_all_messages base_types=[10000]
/// 类型预过滤, 秒级); 冷查走 `events_query`(L1 message type10000)。6 键对齐, fold 不吞任何列 (无 URL/密钥列)。
async fn wx_events(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    // codex 66e76ec P2: sys_type 若**存在但非字符串**(数字/对象)→ 报错, 不让 as_str() 静默转 None 后返全部
    // (= 静默把过滤查询变成无过滤, 同 mode/分页的"present-but-malformed → 显式错"口径)。
    if args.get("sys_type").is_some_and(|v| !v.is_null() && !v.is_string()) {
        return tool_err("sys_type 参数不对", "sys_type 需是字符串 (或省略); 收到非字符串值");
    }
    let sys_type = args.get("sys_type").and_then(Value::as_str).filter(|s| !s.is_empty());
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "群系统事件") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_events(
                &wxid,
                ctx.wechat_data_dir.as_deref(),
                None,
                sys_type,
                limit,
                offset,
                None,
            )
            .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查群系统事件失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::events_query(&conn, sys_type, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查群系统事件失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_calls` (**R16-2**) — 通话记录 (type50 VoIP) 冷热双模式, 镜像 CLI `calls` / HTTP `/messages?kind=call`。
/// 热走 `hot_calls`(scan_all_messages base_types=[50] + parse_voip, drop 口径同 message_call); 冷走 `calls_query`。
/// 6 键对齐, fold 不吞列 (无 URL/密钥列)。
async fn wx_calls(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "通话记录") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_calls(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查通话记录失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::calls_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查通话记录失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_biz` (**R16-2**) — 公众号消息(gh_ 会话, 跨所有类型)冷热双模式, 镜像 CLI `biz` / HTTP `/messages?kind=biz`。
/// 热走 `hot_biz`(scan_conversations("gh_") 会话层前缀过滤 + parse_appmsg 取 title), 冷走 `biz_query`。5 键对齐。
async fn wx_biz(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "公众号消息") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_biz(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查公众号消息失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::biz_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查公众号消息失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_mentions` (**R16-2, 一对多**) — 群消息 @提及, 冷热双模式, 镜像 CLI `mentions` / HTTP `/messages?mentions=`。
/// 热走 `hot_mentions`(scan want_msgsource + parse_mentions 一@一行, sender 路径A), 冷走 `mentions_query`。6 键对齐
/// (create_time/conv_id/sender_wxid/mentioned_wxid/is_at_all/text_content)。`query` 给了按被@人 wxid 子串过滤。
async fn wx_mentions(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    // codex mentions P2: query 给了非串 → 拒(不静默当没过滤返全集)。
    let who = match arg_opt_str(args, "query") {
        Ok(w) => w,
        Err(e) => return tool_err("query 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "@提及") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_mentions(&wxid, ctx.wechat_data_dir.as_deref(), None, who, limit, offset, None)
                .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查 @提及失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::mentions_query(&conn, who, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查 @提及失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_thread` (**R16-2 appmsg 族**) — 引用回复(appmsg type57 有 refer_svrid)冷热双模式, 镜像 CLI `thread` /
/// HTTP `/messages?quote=true`。热走 `hot_thread`(scan_all_messages base_types=[49] + parse_appmsg 取有 refer_svrid
/// 的, sender 走路径A), 冷走 `thread_query`。6 键对齐(create_time/conv_id/sender_wxid/reply_text/refer_type/quoted_text)。
async fn wx_thread(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "引用回复") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_thread(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查引用回复失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::thread_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查引用回复失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_links` (**R16-2 appmsg 族**) — 分享链接/卡片(appmsg WHERE url!='')冷热双模式, 镜像 CLI `links` /
/// HTTP `/messages?kind=link`。热走 `hot_links`(scan_all_messages base_types=[49] + parse_appmsg 取有 url 的),
/// 冷走 `links_query`。6 键对齐。fold 保留 url 列(决策⑥: MCP 也出网址, 不删 URL 类)。
async fn wx_links(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "分享的链接") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_links(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查链接失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::links_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查链接失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_files` (**R16-2 appmsg 族**) — 文件消息(appmsg WHERE file_ext!='')冷热双模式, 镜像 CLI `files` /
/// HTTP `/messages?kind=file`。热走 `hot_files`(scan_all_messages base_types=[49] + parse_appmsg 取有 file_ext 的),
/// 冷走 `files_query`。5 键对齐 (create_time/conv_id/file_name/file_ext/file_size)。
async fn wx_files(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "文件消息") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_files(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查文件失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::files_query(&conn, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("查文件失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_locations` (**R16-2 registry 族**) — 位置分享(type48)冷热双模式, 镜像 CLI `locations` / HTTP `/messages?kind=location`。
/// 热走 `hot_locations`(scan msg48 + parse_location), 冷走引擎 `run_query(&CMD_LOCATIONS)`(照 R16-1 wx_avatars 范式)。7 键对齐。
async fn wx_locations(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "位置分享") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_locations(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查位置失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_LOCATIONS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查位置失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_group_events` (**R16-2 registry 族, 一对多**) — 群成员进出(msg10000 派生)冷热双模式, 镜像 CLI `group-events`
/// / HTTP `/api/v1/group-events`。热走 `hot_group_events`(scan msg10000 + parse_member_events 一成员一行), 冷走引擎
/// `run_query(&CMD_GROUP_EVENTS)` 读 L1 `chatroom_member_event`。5 键对齐: event_time/conv_id/event_kind(join/remove)/
/// member_nickname/member_wxid。
async fn wx_group_events(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "群进出记录") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_group_events(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查群进出失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_GROUP_EVENTS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查群进出失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

/// `wx_cards` (**R16-2 registry 族**) — 名片(type42)冷热双模式, 镜像 CLI `cards` / HTTP `/api/v1/cards`。
/// 热走 `hot_cards`(scan msg42 + parse_card), 冷走引擎 `run_query(&CMD_CARDS)`(照 R16-1 wx_avatars 范式)。6 键对齐。
async fn wx_cards(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "名片") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_cards(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查名片失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_CARDS, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查名片失败 (ingest 了消息?)", &err_str(&e)),
            }
        }
    }
}

async fn wx_inspect(args: &Value, ctx: &Ctx) -> Value {
    // R16-6 冷热双模: 冷 inspect_query 读 L1 单行; 热 hot_inspect 按 entity 路由源库实时读 (message 全扫找锚较慢;
    // contact/chatroom 热字段是列表集 < 冷完整 L1 列, 降级)。capping 逻辑冷热统一 (两路都返 QueryResult 单行)。
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    let entity = match args.get("type").and_then(Value::as_str).unwrap_or("") {
        "contact" => native_query::InspectType::Contact,
        "chatroom" => native_query::InspectType::Chatroom,
        "session" => native_query::InspectType::Session,
        "message" => native_query::InspectType::Message,
        other => {
            return tool_err(
                "type 取值不对",
                &format!("'{other}' 无效; 取 contact/chatroom/session/message"),
            )
        }
    };
    let Some(id) = args.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return tool_err(
            "需要指定 id",
            "id 传要查的记录标识 (联系人/群/会话=其 id; 消息=source_native_id)",
        );
    };
    let budget = arg_max_bytes(args);
    // 可选 field+offset = **单字段分段读**; 不传 field = 普通模式 (整条全字段)。
    let field = args.get("field").and_then(Value::as_str).filter(|s| !s.is_empty());
    let offset = arg_count(args, "offset", 0, 100_000_000);
    // 冷热各自取单行 QueryResult (查无/失败各分支自理错误), 再统一 capping。
    let r = match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "单条记录") {
                Ok(w) => w,
                Err(e) => return e,
            };
            // R21 成本门只对 message 实体挂 —— 只 hot_inspect 的 Message 臂全扫; contact/chatroom/session 直读各自库。
            if matches!(entity, native_query::InspectType::Message) {
                if let Some(err) = mcp_cost_gate(&wxid, ctx, args, 0, 0).await {
                    return err;
                }
            }
            match native_query::hot_inspect(&wxid, ctx.wechat_data_dir.as_deref(), None, entity, id, None).await {
                Ok(r) => r,
                Err(e) => {
                    return tool_err(
                        "实时查单条记录失败 (id 对? 账号 key 缓存了? message 全扫较慢)",
                        &err_str(&e),
                    )
                }
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, _l1, _sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::inspect_query(&conn, entity, id) {
                Ok(r) => r,
                Err(e) => return tool_err("没找到该记录 (id 对? 该表 ingest 了?)", &err_str(&e)),
            }
        }
    };
    // 逃生口取整条/单字段, **字节预算受控** (原 fold::detail 不封顶 = 一条无界返回路径)。普通模式截长字段
    // + 标 meta.truncated_fields 指路; field 模式分段返该字段脱敏内容 (offset/next_offset/has_more), 多次拼回完整。
    match field {
        Some(f) => tool_ok(&fold::inspect_field(&r, f, offset, budget), budget),
        None => tool_ok(&fold::inspect_capped(&r, budget), budget),
    }
}

/// `wx_get_media` (**R16-2 起冷热双模**) — 返媒体**引用** (md5+类型+大小等, 非裸 base64; §9.1)。
/// 热走 `hot_media`(scan msg[3/34/43/47] + parse_media), 冷走引擎 `run_query(&CMD_MEDIA)`。7 键对齐。
/// (R16-2 修: 原来 offset 硬编码 0 翻不了页 + 只冷查; 现补 mode/offset。)
async fn wx_get_media(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    // Claude d0813f0 P3: 对齐 registry 族 (wx_calls/links/files/locations/cards 均 30/200), 原 20/100 是离群历史残留。
    let limit = arg_limit(args, 30, 200);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "媒体清单") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_media(&wxid, ctx.wechat_data_dir.as_deref(), None, limit, offset, None).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时查媒体失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let target = match cold_target(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::run_query(&native_query::CMD_MEDIA, &target, limit, offset) {
                Ok(mut r) => {
                    if let Ok(l1) = target.require_l1_db() {
                        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
                            r.meta = r.meta.with_freshness(f);
                        }
                    }
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("查媒体失败 (ingest 了媒体?)", &err_str(&e)),
            }
        }
    }
}

fn wx_describe(args: &Value, _ctx: &Ctx) -> Value {
    // §2.1: 主动拉字典/查询流程提示 (关键提示不能只放 resource, 宿主多不自动喂; 故给 tool)。
    let tools: Vec<Value> = tool_defs()
        .iter()
        .map(|t| json!({ "name": t["name"], "description": t["description"] }))
        .collect();
    tool_ok(
        &json!({
            "tools": tools,
            "flow": "模糊人名/群名 → wx_contacts 搜到 wxid → wx_messages/wx_sessions 查。conv 传 wxid 或群 id \
                     (形如 xxxx@chatroom)。多账号库各工具传 account (wxid)。'今天/上周'先 wx_current_time 锚。\
                     要某条消息全文/某记录全字段 → wx_inspect。响应默认 48KB, 需要更大传 max_bytes (最高 512KB)。",
            "notes": "只读; list 类 limit 保持小按 has_more 翻页; meta.source 标 hot(实时)/cold(L1) 别把陈旧当最新; \
                      meta._budget 报本次预算/实际字节/是否截断, truncated=true 时调大 max_bytes 或用 field+offset 分段。"
        }),
        arg_max_bytes(args),
    )
}

async fn wx_resolve_names(args: &Value, ctx: &Ctx) -> Value {
    // R16-6 双模: 冷读 L1 person; 热读源库 contact.db(名字实时)。
    let wxids: Vec<String> = args
        .get("wxids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();
    if wxids.is_empty() {
        return tool_err("需要 wxid 列表", "wxids 传要解析成名字的 wxid 数组");
    }
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "解析名字") {
                Ok(w) => w,
                Err(e) => return e,
            };
            match native_query::hot_resolve_names(&wxid, ctx.wechat_data_dir.as_deref(), &wxids).await {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时解析名字失败 (账号 key 缓存了? 数据目录对?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let wxids_ref: Vec<&str> = wxids.iter().map(String::as_str).collect();
            // Claude R16-6 P2: 走 cold_ok(非裸 tool_ok)挂 meta.freshness —— 对齐同族冷双模工具(wx_contacts 等) + HTTP
            // /names 冷查, 否则 MCP 冷 resolve-names 独缺 ingested_at, LLM 判不出名字数据多旧(三皮 meta 契约破)。
            let (conn, l1, sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::resolve_names_query(&conn, &wxids_ref) {
                Ok(r) => cold_ok(r, &l1, sha.as_deref(), args),
                Err(e) => tool_err("解析名字失败", &err_str(&e)),
            }
        }
    }
}

async fn wx_list_accounts(args: &Value, _ctx: &Ctx) -> Value {
    use native_core::key_provider::CacheKeyProvider;
    use native_core::KeyProvider;
    // 返**可用的 wxid** (非 sha8) —— LLM 拿它当各工具 account 参; 本地自读自数据 (④文档 §8 数据出境已声明)。
    match CacheKeyProvider::new(None).resolve_all().await {
        Ok(map) => {
            let mut accounts: Vec<String> = map.keys().map(|w| w.as_str().to_string()).collect();
            accounts.sort();
            tool_ok(
                &json!({
                    "accounts": accounts,
                    "note": "已缓存 key 的账号 wxid; 传给各工具的 account 参数选账号"
                }),
                arg_max_bytes(args),
            )
        }
        Err(e) => tool_err("读账号缓存失败 (先跑过 auth 取 key?)", &e.to_string()),
    }
}

/// `wx_capture_list` (R19 选择性采集) — 看当前圈定采集哪些会话 (只读反映; 镜像 CLI `capture list` / HTTP `GET /capture`)。
/// 空清单=全采。**增删走 CLI** `capture add/rm` (只读服务不暴露写; R20 config-CLI-only 先例)。
async fn wx_capture_list(args: &Value, ctx: &Ctx) -> Value {
    let Some(l1) = ctx.l1_db.clone() else {
        return tool_err(
            "服务器未配置 L1 数据库",
            "启动 mcp 时用 --l1-db 指向 ingest 产出的 L1 库",
        );
    };
    // 账号: 工具 arg > 服务器 default_account (codex round-1 P2)。**审 round-6 P2**: 用 arg_opt_str 校验 —— account 存在但
    // **非字符串** (JSON 数字/对象) → 显式 tool_err, 非静默 None 回退 default 返别账号清单 (与其它工具 sys_type/mode 同口径)。
    let account = match arg_opt_str(args, "account") {
        Ok(a) => a.map(str::to_string).or_else(|| ctx.default_account.clone()),
        Err(e) => return tool_err("account 参数不对", &e),
    };
    // 审 round-8 codex 2 P2: 走**共享** capture_targets_query + fold::envelope (三皮一致), 替原自建 {targets,count,note}。
    // 原自建**非**标准 {data,meta} 信封 → (a) 缺 meta.account, 空清单无法归属账号 (与 HTTP/CLI 不齐); (b) 大清单/长 note
    // 超 max_bytes 时 tool_ok 的**按行折叠**认不出裸 `targets` 键 → fallback 把整个 payload 丢成 `data:[]`, 且本工具无
    // limit/offset/filter 无法缩查 = 超上限的清单**永久取不到**。共享路径: capture_targets_query 已填 meta.account=sha8,
    // fold::envelope 按行折叠可控缩减 (与其它 MCP 冷查工具同款)。空库无账号 (resolve→None→空清单) / 多账号未指定
    // (Err Ambiguous→tool_err) 均由 capture_targets_query 内部处理; "空=全采" 语义在工具 description 里 (同 HTTP 无 note)。
    let b = arg_max_bytes(args);
    match native_query::capture_targets_query(&l1, account) {
        Ok(r) => tool_ok(&fold::envelope(&r, b), b),
        Err(e) => tool_err("读采集清单失败 (多账号库需给 account)", &e.to_string()),
    }
}

/// `wx_resolve` (**R16-2 起冷热双模**) — 展开合并转发, 镜像 CLI `resolve` / HTTP `/messages?kind=forward`。**双模式**:
/// 给 msg_id=展开该条子项 / 不给=列所有转发。热走 `hot_resolve`(scan msg49 + parse_forward), 冷走 `resolve_query`。
async fn wx_resolve(args: &Value, ctx: &Ctx) -> Value {
    let mode = match arg_mode_auto(args) {
        Ok(m) => m,
        Err(e) => return tool_err("mode 参数不对", &e),
    };
    // codex mentions P2 (同类 present-but-malformed 静默放宽): msg_id 给了非串会被静默当"没给"→ 从"展开该条"
    // 悄悄退成"列全部转发"; 故显式拒非串。
    let msg_id = match arg_opt_str(args, "msg_id") {
        Ok(m) => m,
        Err(e) => return tool_err("msg_id 参数不对", &e),
    };
    // R16-2: source(分片)精确定位跨分片重号的转发(见 list 的 source 列)。
    let source = match arg_opt_str(args, "source") {
        Ok(s) => s,
        Err(e) => return tool_err("source 参数不对", &e),
    };
    let limit = arg_limit(args, 20, 100);
    let offset = arg_count(args, "offset", 0, 10_000_000);
    match mode.effective(ctx.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = match hot_wxid(args, ctx, "合并转发") {
                Ok(w) => w,
                Err(e) => return e,
            };
            if let Some(err) = mcp_cost_gate(&wxid, ctx, args, offset, limit).await {
                return err;
            }
            match native_query::hot_resolve(
                &wxid,
                ctx.wechat_data_dir.as_deref(),
                None,
                msg_id,
                source,
                limit,
                offset,
                None,
            )
            .await
            {
                Ok(r) => {
                    let b = arg_max_bytes(args);
                    tool_ok(&fold::envelope(&r, b), b)
                }
                Err(e) => tool_err("实时展开合并转发失败 (msg_id 对? 账号 key 缓存了?)", &err_str(&e)),
            }
        }
        native_query::EffectiveMode::Cold => {
            let (conn, l1, account_sha) = match open_cold(args, ctx) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match native_query::resolve_query(&conn, msg_id, source, limit, offset) {
                Ok(r) => cold_ok(r, &l1, account_sha.as_deref(), args),
                Err(e) => tool_err("展开合并转发失败 (msg_id 对? 该库有合并转发?)", &err_str(&e)),
            }
        }
    }
}

/// 组合工具复用: 取某账号某会话近期消息 (热)。无账号/失败 → 空数组 (pack 尽力而为, 不整体报错; §9.2)。
async fn pack_recent_messages(account: Option<&str>, conv: &str, ctx: &Ctx, limit: usize) -> Value {
    let Some(acc) = account else { return json!([]) };
    let Ok(wxid) = acc.parse::<native_core::Wxid>() else {
        return json!([]);
    };
    match native_query::hot_messages(&wxid, conv, ctx.wechat_data_dir.as_deref(), None, limit).await {
        Ok(r) => json!(fold::rows(&r.data)),
        Err(_) => json!([]),
    }
}

async fn contact_pack(args: &Value, ctx: &Ctx) -> Value {
    let Some(target) = args.get("wxid").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return tool_err("需要联系人 wxid", "wxid 传要了解的联系人");
    };
    // open_cold 内 resolve_account: 多账号未指定 → 透出候选错 (isError+candidates), **不再静默吞成空**
    // (审查 P1-5: 否则 LLM 收到空 pack 会下"查无此人"错结论)。
    let (conn, _l1, _sha) = match open_cold(args, ctx) {
        Ok(t) => t,
        Err(e) => return e,
    };
    // 联系人信息 (冷·scoped): 数据取不到 → 空 (OK); 区别于上面的"需选账号/真错"(已透 isError)。
    let contact = native_query::resolve_names_query(&conn, &[target])
        .map(|r| json!(fold::rows(&r.data)))
        .unwrap_or_else(|_| json!([]));
    // 近期消息 (热·各子段各自限量, §9.2 别拼一坨爆)。
    let account = arg_account(args).or_else(|| ctx.default_account.clone());
    let recent = pack_recent_messages(account.as_deref(), target, ctx, 5).await;
    // 第5轮#3: pack 不走 envelope 的 budget_fold → 显式套字节封顶 (长聊天内容会破预算)。
    let budget = arg_max_bytes(args);
    tool_ok(
        &fold::cap_pack(json!({ "contact": contact, "recent_messages": recent }), budget),
        budget,
    )
}

async fn session_pack(args: &Value, ctx: &Ctx) -> Value {
    let Some(conv) = args.get("conv").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return tool_err(
            "需要会话标识",
            "conv 传对方 wxid 或群 id (xxxx@chatroom); 不知道先 wx_sessions",
        );
    };
    // 热查必需账号 (定位账号库 + 取 key); 缺 → 透出 isError, **不静默空**成"查无消息" (审查 P1-5; 与
    // wx_sessions/wx_messages 一致 —— 无 wxid 本就查不了热数据)。
    let Some(acc) = arg_account(args).or_else(|| ctx.default_account.clone()) else {
        return tool_err(
            "需要指定账号",
            "session_pack 读实时消息要 account (wxid) 或服务器默认账号; 多账号先 wx_list_accounts",
        );
    };
    let is_group = conv.ends_with("@chatroom");
    let recent = pack_recent_messages(Some(&acc), conv, ctx, 10).await;
    // 第5轮#3: pack 不走 envelope 的 budget_fold → 显式套字节封顶 (长聊天内容会破预算)。
    let budget = arg_max_bytes(args);
    tool_ok(
        &fold::cap_pack(
            json!({ "conv": conv, "is_group": is_group, "recent_messages": recent }),
            budget,
        ),
        budget,
    )
}

// ── helper ──

/// 冷查引擎命令 (run_query) 用的 QueryTarget: l1 路径 + account (wxid; run_query 内部 sha256 建遮蔽视图)。
fn cold_target(args: &Value, ctx: &Ctx) -> Result<native_query::QueryTarget, Value> {
    let Some(l1) = ctx.l1_db.clone() else {
        return Err(tool_err("服务器未配置 L1 数据库", "启动 mcp 时用 --l1-db 指向 L1 库"));
    };
    let account = resolve_account(args, ctx, &l1)?; // H3: default fallback + 多账号无account 列候选。
                                                    // R16-1: QueryTarget 转热冷通用后字段变多 (mode/wxid/wechat_data_dir)。本 helper 名副其实只服务
                                                    // **冷查**派发 → 用 ::cold 构造器, 别手写全字段 (将来加字段就又炸一圈)。要热查的 MCP 工具自走 hot_*。
    Ok(native_query::QueryTarget::cold(l1, account))
}

/// 携码 CliError → 取人话消息 (不外泄底层细节)。
fn err_str(e: &anyhow::Error) -> String {
    e.to_string()
}

/// account 参数 (wxid); 空串当 None。
fn arg_account(args: &Value) -> Option<String> {
    args.get("account")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// 读**可选字符串**参数(过滤/定位类): 缺省 / `null` / 空串 → `None`(视同未给); 是字符串 → `Some`; **其它类型
/// (数字 / 布尔 / 对象 / 数组)→ `Err`**。
///
/// **codex mentions P2 (present-but-malformed 静默放宽)**: 原来各工具直接 `.and_then(Value::as_str)`, 调用方给了
/// 错类型的过滤(如 `query: 123`)会被静默当成"没给过滤"→ 悄悄返**全集**而非报错。MCP schema 服务端不强制,
/// 故在 handler 侧显式拒: 给了非串就是坏请求。R16 引入的带可选串过滤的工具(mentions/resolve)统一走此。
fn arg_opt_str<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str()).filter(|s| !s.is_empty())),
        Some(_) => Err(format!("{key} 必须是字符串")),
    }
}

/// limit 参数: 缺省 `default`, 夹到 `[1, hard]` (§2.2 每工具硬顶)。
fn arg_limit(args: &Value, default: usize, hard: usize) -> usize {
    args.get("limit")
        .and_then(Value::as_u64)
        .map_or(default, |n| (usize::try_from(n).unwrap_or(default)).clamp(1, hard))
}

/// 计数参数 (before/after): 缺省 `default`, 夹到 `[0, hard]` (0 = 该方向不取)。
fn arg_count(args: &Value, key: &str, default: usize, hard: usize) -> usize {
    args.get(key)
        .and_then(Value::as_u64)
        .map_or(default, |n| (usize::try_from(n).unwrap_or(default)).clamp(0, hard))
}

/// `max_bytes` 参数 (可选, 本次响应字节预算): 缺省 → [`fold::DEFAULT_MAX_BYTES`] (49152, 保旧调用兼容); 传了 →
/// [`fold::resolve_budget`] 钳到 `[MIN_MAX_BYTES, HARD_MAX_BYTES]` (16384~524288)。穿透折叠层 + tool_ok 兜底闸。
fn arg_max_bytes(args: &Value) -> usize {
    fold::resolve_budget(args.get("max_bytes").and_then(Value::as_u64))
}

/// `mode` 参解析, **缺省值由调用方给**: `hot`/`cold`/`auto`。非法值 → `Err` (皮层 tool_err, **不静默退默认**)。
///
/// **为什么缺省值不能写死**(R16-1): `wx_sessions`/`wx_messages` 缺省 **Hot** —— 那是 R6 给它俩单独定的
/// 语义(它们本来就是实时优先)。而 R16-1 新接热查的那批(`wx_contacts`/`wx_favorites`/
/// `wx_friend_requests`/`wx_channels`)**原本全是冷查**, 缺省若也给 Hot, 现有调用方(不传 mode)会**从冷查
/// 变成热查** —— 服务端明明配了 `--l1-db` 却跑去碰微信库 = 最大意外。故它们缺省 **Auto**
/// (有 L1 照旧走冷、零破坏; 只有显式 `mode=hot` 或服务端没配 L1 才走热)。与 CLI 侧 `QueryTarget`
/// 默认 Auto 的理由完全相同。
fn arg_mode_or(args: &Value, default: native_query::QueryMode) -> Result<native_query::QueryMode, String> {
    match args.get("mode") {
        None => Ok(default),
        Some(Value::String(s)) => match s.as_str() {
            "hot" => Ok(native_query::QueryMode::Hot),
            "cold" => Ok(native_query::QueryMode::Cold),
            "auto" => Ok(native_query::QueryMode::Auto),
            other => Err(format!("mode 无效: {other} (hot / cold / auto)")),
        },
        // mode 键存在但非字符串 (JSON 数字/布尔/对象) → 显式 Err, **不静默退默认** (与非法字符串值一致)。
        Some(_) => Err("mode 要是字符串: hot / cold / auto".to_string()),
    }
}

/// R6 `mode` 参 (缺省 = `Hot` 默认实时) —— `wx_sessions`/`wx_messages` 专用, 见 [`arg_mode_or`]。
fn arg_mode(args: &Value) -> Result<native_query::QueryMode, String> {
    arg_mode_or(args, native_query::QueryMode::Hot)
}

/// R16-1 起新接热查的工具用: 缺省 **Auto**(有 L1 走冷 = 老行为零破坏), 理由见 [`arg_mode_or`]。
fn arg_mode_auto(args: &Value) -> Result<native_query::QueryMode, String> {
    arg_mode_or(args, native_query::QueryMode::Auto)
}

/// R16-1 热查分支取账号 wxid: 显式 `account` > 服务端默认账号; 都没有 → `Err` 提示 (**不静默走冷**)。
///
/// 四条新接热查的工具共用 —— 免得同一段"取账号 + parse + 报错话术"抄四遍再各自漂移。
fn hot_wxid(args: &Value, ctx: &Ctx, what: &str) -> Result<native_core::Wxid, Value> {
    let account = arg_account(args).or_else(|| ctx.default_account.clone());
    let Some(acc) = account else {
        return Err(tool_err(
            "需要指定账号",
            &format!("实时查{what}要 account (wxid); 或给服务器设默认账号; 或 mode=cold 走 L1"),
        ));
    };
    acc.parse::<native_core::Wxid>()
        .map_err(|_| tool_err("账号格式不对", "account 要是合法的 wxid (如 wxid_ 开头)"))
}

/// R21 全扫成本门（MCP 皮）—— 三皮共享决策核 [`native_query::full_scan_cost_gate`] 的 MCP 呈现。
/// **`Blocked`（超强制阈值且无 `confirm`）/ 翻页越界 → `Some(isError)`**（工具直接 `return` 它）; 其余
/// （Silent/Hint/ConfirmedProceed）→ `None` 放行。`confirm` 从 `args["confirm"]`（bool）取。
///
/// **MCP/HTTP 只硬拦 `Blocked`**（多分钟全扫）; 软 `Hint`（提示档, 会跑完但慢）不打断 —— 非交互皮无 stderr,
/// 硬拦已达 R21 专防"盲发多分钟全扫"目的（三皮对等的是**硬门**; 软提示是 CLI stderr-only 交互特性）。
/// 全扫工具在调对应 `hot_*` **前**调本门; chat 定向查（messages/messages_around）、biz、inspect 非 message
/// 臂 **不调**（同 CLI 排除口径）。
/// 解析 MCP `confirm` arg 为**严格布尔**（round-13 codex P2）: 缺省/null → false; 真布尔 → 原值; **其它类型
/// (如 `"true"`/`1`/`[]`) → `Err(tool_err)` 显式报参数错, 不静默当 false**。MCP 服务端不校验 inputSchema, 故须
/// 运行时拒 —— 否则用户明明传了 confirm 却被无视继续拦(或非全扫端静默吞), 且与 CLI(clap bool)/HTTP(serde 拒非
/// bool→400) 三皮不一致。
fn parse_confirm_arg(args: &Value) -> Result<bool, Value> {
    match args.get("confirm") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(tool_err(
            "confirm 参数类型错",
            "confirm 必须是布尔 (true/false); 收到非布尔值 —— 传 true 强制执行慢查, 或省略该参数",
        )),
    }
}

async fn mcp_cost_gate(
    wxid: &native_core::Wxid,
    ctx: &Ctx,
    args: &Value,
    offset: usize,
    limit: usize,
) -> Option<Value> {
    use native_core::query_planner::profile::GateOutcome;
    let confirm = match parse_confirm_arg(args) {
        Ok(c) => c,
        Err(e) => return Some(e), // 非布尔 confirm → 显式参数错(不静默当 false)
    };
    match native_query::full_scan_cost_gate(wxid, ctx.wechat_data_dir.as_deref(), offset, limit, confirm).await {
        Ok(r) => match r.outcome {
            GateOutcome::Blocked { .. } => Some(tool_err(
                "慢查被 R21 成本门拦下",
                &format!(
                    "该查询要全扫 {} 个 message 分片、估算 {} 秒 ({}); 传 confirm=true 强制执行, 或先对该账号 `msgvestige ingest` 建 L1 库后用 mode=cold (走索引, ms 级)",
                    r.shard_count,
                    r.estimated_secs(),
                    r.profile_label()
                ),
            )),
            _ => None, // Silent / Hint / ConfirmedProceed → 放行
        },
        Err(e) => Some(tool_err("翻页/参数错", &err_str(&e))), // check_hot_window 越界等
    }
}

/// 冷查结果**挂上 freshness 后**折成 MCP 响应 —— R16-1 起冷查工具的统一冷查出口。
///
/// **抽出来是因为漏过一次**(轮7 三皮审逮到 P2): `wx_contacts`/`wx_favorites`/`wx_friend_requests`/
/// `wx_channels` 四条冷分支都**忘了挂 `cold_freshness`** —— 而 `wx_sessions`/`wx_messages` 有。后果:
/// 同一条冷查, CLI/HTTP 的 `meta.freshness` 带 `ingested_at`(告诉消费方 L1 这份数据多旧), MCP 却**没有**
/// → 给 LLM 的那皮拿不到新鲜度信号, **三皮 meta 契约破了**。
/// 而这条 CLI 侧对拍(`r16_parity.py` 只比 CLI 冷 vs CLI 热)结构上照不到, 是三皮 meta 对拍才逮出来的。
/// → 收进一个 helper, 一份逻辑四条共用: 后面接第 5、6 条冷查照调它, 想漏都漏不掉。
///
/// `l1`/`account_sha` 来自 [`open_cold`](自身返回的 `(conn, l1, account_sha)`)。
fn cold_ok(mut r: native_query::QueryResult, l1: &str, account_sha: Option<&str>, args: &Value) -> Value {
    if let Some(f) = native_query::cold_freshness(l1, account_sha) {
        r.meta = r.meta.with_freshness(f);
    }
    let b = arg_max_bytes(args);
    tool_ok(&fold::envelope(&r, b), b)
}

// ── JSON Schema 构造 helper (手搓, 不用 schemars 派生; 同 WDA 思路) ──

fn schema_obj(props: &[(&str, Value)], required: &[&str]) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in props {
        map.insert((*k).to_string(), v.clone());
    }
    let mut out = json!({ "type": "object", "properties": Value::Object(map), "additionalProperties": false });
    if !required.is_empty() {
        out["required"] = json!(required);
    }
    out
}

/// R21 成本门工具专用 schema —— 在 [`schema_obj`] 基础上追加 `confirm` 布尔属性。
///
/// **为什么单独一个**: 接了 [`mcp_cost_gate`] 的工具在估算超强制阈值时返回 isError, 让调用方传
/// `confirm=true` 重试; 但 [`schema_obj`] 设了 `additionalProperties: false`, 严格按 schema 校验的
/// MCP 宿主若 schema 没声明 `confirm` 就发不出这个重试 → 慢查在 MCP 上被永久拦死 (轮6 codex P1)。
/// 用 `gated_schema_obj` = 声明"本工具挂了成本门"; 契约测试 `every_gated_tool_advertises_confirm`
/// 核对它与 `mcp_cost_gate` 接线一致 (漏挂/多挂都红)。
fn gated_schema_obj(props: &[(&str, Value)], required: &[&str]) -> Value {
    let mut p = props.to_vec();
    p.push((
        "confirm",
        schema_bool("R21 成本门: 该热查要全扫所有 message 分片, 估算超强制阈值会被拦 (isError); 传 true 强制执行, 或改 mode=cold 走 L1 索引 (ms 级)"),
    ));
    schema_obj(&p, required)
}

fn schema_str(desc: &str) -> Value {
    json!({ "type": "string", "description": desc })
}

fn schema_int(desc: &str, min: i64, max: i64) -> Value {
    json!({ "type": "integer", "description": desc, "minimum": min, "maximum": max })
}

fn schema_enum(desc: &str, variants: &[&str]) -> Value {
    json!({ "type": "string", "description": desc, "enum": variants })
}

fn schema_bool(desc: &str) -> Value {
    json!({ "type": "boolean", "description": desc })
}

fn schema_arr_str(desc: &str) -> Value {
    json!({ "type": "array", "description": desc, "items": { "type": "string" } })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{arg_mode, call_tool, contact_pack, wx_account};
    use crate::Ctx;

    /// round-13 codex P2: `confirm` arg 严格布尔 —— 缺省/null=false, 布尔取原值, **非布尔 (字符串/数字/数组) 显式
    /// Err(不静默当 false)**, 与 CLI/HTTP 三皮一致。
    #[test]
    fn confirm_arg_rejects_non_bool() {
        assert!(!super::parse_confirm_arg(&json!({})).unwrap(), "缺省 → false");
        assert!(
            !super::parse_confirm_arg(&json!({ "confirm": null })).unwrap(),
            "null → false"
        );
        assert!(
            super::parse_confirm_arg(&json!({ "confirm": true })).unwrap(),
            "true → true"
        );
        assert!(
            !super::parse_confirm_arg(&json!({ "confirm": false })).unwrap(),
            "false → false"
        );
        assert!(
            super::parse_confirm_arg(&json!({ "confirm": "true" })).is_err(),
            "字符串 \"true\" → 拒"
        );
        assert!(
            super::parse_confirm_arg(&json!({ "confirm": 1 })).is_err(),
            "数字 1 → 拒"
        );
        assert!(
            super::parse_confirm_arg(&json!({ "confirm": [] })).is_err(),
            "数组 → 拒"
        );
    }

    /// 轮6 双审收敛 (codex P1 + Claude P2 独立都逮): 每个挂了成本门 (`mcp_cost_gate`) 的工具, 其
    /// inputSchema 必须声明 `confirm` 布尔属性 —— 否则 `additionalProperties:false` 下严格按 schema
    /// 校验的 MCP 宿主发不出 `confirm=true` 重试, 慢查在 MCP 上被永久拦死 (而门的 isError 文案却让传
    /// confirm, 自相矛盾)。源码自省 (dispatch 里工具名==handler fn 名), 接线一改测试自动跟, 不靠手维护清单。
    #[test]
    fn every_gated_tool_advertises_confirm() {
        let src = include_str!("tools.rs");
        let mut gated = std::collections::BTreeSet::<String>::default();
        let mut cur = String::new();
        for line in src.lines() {
            let t = line.trim_start();
            if t.starts_with("mod tests") {
                break; // 只扫非测试代码, 免得扫到本测试源码里的字面量
            }
            if let Some(rest) = t.strip_prefix("async fn ") {
                cur = rest.split('(').next().unwrap_or("").trim().to_string();
            }
            if t.contains("mcp_cost_gate(") && !t.starts_with("async fn ") {
                gated.insert(cur.clone()); // 调用点 → 归属其外层 handler fn
            }
        }
        assert!(
            gated.len() >= 20,
            "扫出的挂门工具数异常: {} (预期 ~22); 源码自省逻辑失效",
            gated.len()
        );

        let defs = super::tool_defs();
        let find = |name: &str| defs.iter().find(|d| d["name"] == name).cloned();

        // 正向: 每个挂门工具都声明 confirm 布尔
        for g in &gated {
            let d = find(g).unwrap_or_else(|| {
                panic!("挂门 handler `{g}` 在 tool_defs 无同名工具 (工具名==fn名 假设破裂, 测试需修)")
            });
            assert_eq!(
                d["inputSchema"]["properties"]["confirm"]["type"], "boolean",
                "挂门工具 `{g}` schema 没声明 confirm 布尔 (additionalProperties:false 下客户端发不出 confirm 重试)"
            );
        }
        // 反向: 没挂门的工具不该冒出 confirm (防 gated_schema_obj 误用到非全扫工具)
        for d in &defs {
            let name = d["name"].as_str().unwrap_or("");
            let has_confirm = !d["inputSchema"]["properties"]["confirm"].is_null();
            let is_gated = gated.contains(name);
            assert_eq!(
                has_confirm, is_gated,
                "工具 `{name}`: confirm 属性存在={has_confirm} 与挂门={is_gated} 不一致"
            );
        }
    }

    /// R6 修: `arg_mode` 非字符串 mode (JSON 数字/布尔) 显式 `Err`, **不静默退默认 Hot** (缺省才 Hot)。
    #[test]
    fn arg_mode_non_string_is_err_not_silent_default() {
        assert_eq!(
            arg_mode(&json!({})).unwrap(),
            native_query::QueryMode::Hot,
            "缺省 → Hot"
        );
        assert_eq!(
            arg_mode(&json!({"mode": "cold"})).unwrap(),
            native_query::QueryMode::Cold
        );
        assert_eq!(
            arg_mode(&json!({"mode": "auto"})).unwrap(),
            native_query::QueryMode::Auto
        );
        assert!(arg_mode(&json!({"mode": "bogus"})).is_err(), "非法字符串 → Err");
        assert!(
            arg_mode(&json!({"mode": 123})).is_err(),
            "数字 mode 报错, 不静默退默认 Hot"
        );
        assert!(arg_mode(&json!({"mode": true})).is_err(), "布尔 mode 报错");
    }

    /// 写一个含指定 (account_id_sha, account_id) person 行的临时 L1 文件, 返路径。
    fn write_l1(name: &str, accounts: &[(&str, &str)]) -> std::path::PathBuf {
        let tmp = std::env::temp_dir().join(name);
        let _ = std::fs::remove_file(&tmp);
        let c = rusqlite::Connection::open(&tmp).unwrap();
        native_core::storage::init_l1_schema(&c).unwrap();
        for (accsha, acc) in accounts {
            c.execute(
                "INSERT INTO person \
                 (account_id_sha, source, source_native_id, username_sha, account_id, username, \
                  nick_name, nick_name_len, remark_len, alias_len, local_type, is_in_chat_room) \
                 VALUES (?1, 's', ?2, ?3, ?4, ?4, 'n', 0, 0, 0, 1, 0)",
                rusqlite::params![accsha, format!("nid-{acc}"), format!("ush-{acc}"), acc],
            )
            .unwrap();
        }
        tmp
    }

    fn ctx_for(path: &std::path::Path) -> Ctx {
        Ctx {
            l1_db: Some(path.to_str().unwrap().to_string()),
            wechat_data_dir: None,
            default_account: None,
        }
    }

    /// R19 (审 round-1 P2): `wx_capture_list` 认服务器 default_account —— 多账号库 + 配默认 + 无 account 参 → 用默认
    /// (非误报歧义), 与其他 MCP 工具一致。
    #[tokio::test]
    async fn capture_list_uses_default_account() {
        // 审 round-11 codex P1: account_id_sha 必须 = sha256(wxid) (真数据态) —— round-10 的显式账号校验
        // (resolve_capture_account_sha 对 populated L1 校验 account ∈ 数据账号) 下, 假 sha 会让 default=wxid_alice
        // 被误判"不在库"而拒。用真 sha256_hex 建 fixture。
        let sha_alice = native_core::sha256_hex("wxid_alice");
        let sha_bob = native_core::sha256_hex("wxid_bob");
        let tmp = write_l1(
            "mcp_cap_default.db",
            &[(&sha_alice, "wxid_alice"), (&sha_bob, "wxid_bob")],
        );
        // 无默认 + 无参 → 多账号未指定 → isError (歧义)。经 call_tool 分发 (与其他 MCP 测试一致)。
        let bare = call_tool("wx_capture_list", &json!({}), &ctx_for(&tmp)).await;
        assert_eq!(bare["isError"], true, "多账号无默认无参 → 歧义报错");
        // 配默认 wxid_alice → 用默认 → 成功 (空清单, 非歧义)。
        let ctx = Ctx {
            l1_db: Some(tmp.to_str().unwrap().to_string()),
            wechat_data_dir: None,
            default_account: Some("wxid_alice".to_string()),
        };
        let out = call_tool("wx_capture_list", &json!({}), &ctx).await;
        assert_eq!(out["isError"], false, "配了 default_account → 用它, 不报歧义");
        let _ = std::fs::remove_file(&tmp);
    }

    /// R19 (审 round-6 P2): wx_capture_list 收**非字符串** account (JSON 数字) → 显式报错, 非静默回退 default 返别账号清单。
    #[tokio::test]
    async fn capture_list_rejects_non_string_account() {
        let tmp = write_l1("mcp_cap_badacct.db", &[(&"a".repeat(64), "wxid_solo")]);
        let out = call_tool("wx_capture_list", &json!({ "account": 123 }), &ctx_for(&tmp)).await;
        assert_eq!(out["isError"], true, "非字符串 account → 报错 (非静默默认)");
        let _ = std::fs::remove_file(&tmp);
    }

    /// 审查 P1-2 + P1-5: 多账号库 + 未指定 account → contact_pack **透出 isError + 候选**, 不静默空成
    /// "查无此人"。(open_cold → resolve_account 在建 hot 查询前就拦下, 故无需 wechat_data_dir。)
    #[tokio::test]
    async fn contact_pack_multi_account_surfaces_error_not_empty() {
        let tmp = write_l1(
            "mcp_two_acct.db",
            &[(&"a".repeat(64), "wxid_alice"), (&"b".repeat(64), "wxid_bob")],
        );
        let out = contact_pack(&json!({ "wxid": "wxid_alice" }), &ctx_for(&tmp)).await;
        assert_eq!(out["isError"], true, "多账号未指定 → isError (非静默空)");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("candidates"), "带候选账号让 LLM 选");
        let _ = std::fs::remove_file(&tmp);
    }

    /// 单账号库无 account 参 → 裸查成功 (不因新探测逻辑误判多账号逼选; 审查 P1-2 反向)。
    #[tokio::test]
    async fn single_account_no_arg_is_ok() {
        let tmp = write_l1("mcp_one_acct.db", &[(&"a".repeat(64), "wxid_solo")]);
        let out = wx_account(&json!({}), &ctx_for(&tmp)).await;
        assert_eq!(out["isError"], false, "单账号 → 成功, 不逼选账号");
        let _ = std::fs::remove_file(&tmp);
    }

    /// **R16-1(codex 审 P2)**: 分页参数**存在但非非负整数**(字符串/负数/小数)→ call_tool 顶层显式报错,
    /// 不被 arg_limit/arg_count 的 as_u64 当缺省静默返第一页(返成功但错页)。null 当缺省放行。
    #[tokio::test]
    async fn call_tool_rejects_malformed_pagination() {
        let tmp = write_l1("mcp_pag.db", &[(&"a".repeat(64), "wxid_solo")]);
        let ctx = ctx_for(&tmp);
        // 字符串 offset → isError。
        let out = call_tool("wx_chatrooms", &json!({ "offset": "30" }), &ctx).await;
        assert_eq!(out["isError"], true, "offset 字符串 '30' → 报错(非静默返第一页)");
        assert!(out["content"][0]["text"].as_str().unwrap().contains("分页参数"));
        // 负数 limit → isError。
        let out = call_tool("wx_avatars", &json!({ "limit": -5 }), &ctx).await;
        assert_eq!(out["isError"], true, "limit 负数 → 报错");
        // 小数 offset → isError。
        let out = call_tool("wx_members", &json!({ "chatroom": "g@chatroom", "offset": 1.5 }), &ctx).await;
        assert_eq!(out["isError"], true, "offset 小数 → 报错");
        // null offset = 当缺省, 放行(不因 null 误报)。
        let out = call_tool("wx_account", &json!({ "offset": null }), &ctx).await;
        assert_eq!(out["isError"], false, "offset=null 当缺省放行, 不误报");
        let _ = std::fs::remove_file(&tmp);
    }

    /// **round-15 codex P2**: `confirm` 非布尔 → call_tool **顶层**显式报错, **不依赖 mode** —— gated 工具 mode=cold
    /// 时也拒(原 `parse_confirm_arg` 只在 `mcp_cost_gate` 的 hot 臂调, cold 会漏)。缺省/null/合法布尔放行。
    #[tokio::test]
    async fn call_tool_rejects_non_bool_confirm_any_mode() {
        let tmp = write_l1("mcp_confirm.db", &[(&"a".repeat(64), "wxid_solo")]);
        let ctx = ctx_for(&tmp);
        // 字符串 confirm + gated 工具 + mode=cold → 顶层拒(不进 cold 臂 = 证不依赖 mode)。
        let out = call_tool("wx_money", &json!({ "mode": "cold", "confirm": "true" }), &ctx).await;
        assert_eq!(out["isError"], true, "confirm 字符串 + cold gated → 报错(不依赖 mode)");
        assert!(out["content"][0]["text"].as_str().unwrap().contains("confirm"));
        // 数字 confirm(任意工具)→ isError。
        let out = call_tool("wx_account", &json!({ "confirm": 1 }), &ctx).await;
        assert_eq!(out["isError"], true, "confirm 数字 1 → 报错");
        // confirm=null / 合法布尔 → 不因 confirm 报错(wx_account 简单工具在最小库成功)。
        let out = call_tool("wx_account", &json!({ "confirm": null }), &ctx).await;
        assert_eq!(out["isError"], false, "confirm=null → 不误报");
        let out = call_tool("wx_account", &json!({ "confirm": true }), &ctx).await;
        assert_eq!(out["isError"], false, "confirm=true 合法布尔 → 放行");
        let _ = std::fs::remove_file(&tmp);
    }

    /// **R16-2**: `wx_events` 已接线 (三皮之 MCP) —— 坏 mode 走进 handler 的 mode 校验报错, 而非
    /// dispatch 默认 arm 的"未知工具" → 证 dispatch 真路由到 `wx_events`(非漏建 schema/arm)。
    /// mode 校验在开库前, 故无需 message 表夹具。
    #[tokio::test]
    async fn wx_events_wired_not_unknown_tool() {
        let tmp = write_l1("mcp_events_wire.db", &[(&"a".repeat(64), "wxid_solo")]);
        let ctx = ctx_for(&tmp);
        let bad = call_tool("wx_events", &json!({ "mode": "bogus" }), &ctx).await;
        assert_eq!(bad["isError"], true, "坏 mode → 报错");
        let m = bad["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            !m.contains("未知工具"),
            "wx_events 应已接线 (走 mode 校验), 而非未知工具; got={m}"
        );
        assert!(m.contains("mode"), "错误应来自 wx_events 的 mode 校验; got={m}");
        // codex 66e76ec P2: sys_type 非字符串(数字)→ 报错, 不静默转 None 后返全部。
        let bad_sys = call_tool("wx_events", &json!({ "sys_type": 123 }), &ctx).await;
        assert_eq!(bad_sys["isError"], true, "sys_type 数字 → 报错(非静默无过滤)");
        assert!(
            bad_sys["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("sys_type"),
            "错误应指明 sys_type"
        );
        // R16-2 calls/links/files/locations/cards/get_media: wx_* 同样已接线 (坏 mode → mode 校验, 非未知工具)。
        for tool in [
            "wx_calls",
            "wx_links",
            "wx_files",
            "wx_locations",
            "wx_cards",
            "wx_get_media",
            "wx_biz",
            "wx_mentions",
            "wx_group_events",
            "wx_interactions",
            "wx_sns_notify",
            "wx_fav_media",
            "wx_fav_tags",
            "wx_hongbao_claims",
            "wx_group_pay_members",
            "wx_pii_scan",
            "wx_extract",
            "wx_stats",
        ] {
            let bad = call_tool(tool, &json!({ "mode": "bogus" }), &ctx).await;
            assert_eq!(bad["isError"], true, "{tool} 坏 mode → 报错");
            let m = bad["content"][0]["text"].as_str().unwrap_or_default();
            assert!(
                !m.contains("未知工具") && m.contains("mode"),
                "{tool} 应已接线; got={m}"
            );
        }
        let _ = std::fs::remove_file(&tmp);
    }

    /// **codex mentions P2 (present-but-malformed 静默放宽)**: R16 带可选串过滤的工具, 过滤参数**存在但非字符串**
    /// (数字/对象/布尔)→ 显式报错, 不被 `as_str()` 静默转 None 后返全集。null / 省略 = 当缺省放行。
    /// 覆盖 `arg_opt_str` 的三皮之 MCP 应用点: wx_mentions.query / wx_resolve.msg_id / wx_resolve.source。
    #[tokio::test]
    async fn r16_optional_string_filters_reject_non_string() {
        let tmp = write_l1("mcp_optstr.db", &[(&"a".repeat(64), "wxid_solo")]);
        let ctx = ctx_for(&tmp);
        // wx_mentions: query 数字 → 报错 (非静默返全部 @提及)。
        let bad = call_tool("wx_mentions", &json!({ "query": 123 }), &ctx).await;
        assert_eq!(bad["isError"], true, "wx_mentions query 数字 → 报错");
        assert!(
            bad["content"][0]["text"].as_str().unwrap_or_default().contains("query"),
            "错误应指明 query"
        );
        // wx_resolve: msg_id 对象 → 报错 (非静默从'展开'退成'列全部')。
        let bad = call_tool("wx_resolve", &json!({ "msg_id": { "x": 1 } }), &ctx).await;
        assert_eq!(bad["isError"], true, "wx_resolve msg_id 对象 → 报错");
        assert!(
            bad["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("msg_id"),
            "错误应指明 msg_id"
        );
        // wx_resolve: source 布尔 → 报错。
        let bad = call_tool("wx_resolve", &json!({ "source": true }), &ctx).await;
        assert_eq!(bad["isError"], true, "wx_resolve source 布尔 → 报错");
        assert!(
            bad["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("source"),
            "错误应指明 source"
        );
        // null / 省略 = 当缺省放行 (不因 null 误报; 走冷查空库仍成功)。
        let ok = call_tool("wx_mentions", &json!({ "query": null }), &ctx).await;
        assert_eq!(ok["isError"], false, "query=null 当缺省放行, 不误报");
        let _ = std::fs::remove_file(&tmp);
    }
}
