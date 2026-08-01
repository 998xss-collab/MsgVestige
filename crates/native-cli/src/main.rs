//! msgvestige — alpha CLI binary (调 native-core API)。
//!
//! 子命令 (cli-命令行.md §3, 逐件实装):
//! - auth (PR2-14-a): 取 key + 缓存. 扫微信数据目录检测账号 wxid → `resolve(wxid)` hook 取当前账号 key →
//!   chain 自动 write-back cache (K-R2)。**ciphertalk 只能 resolve(wxid), 不能枚举** (codex r1 P0 修正)。
//!
//! main 直接组装 `Box<dyn KeyProvider>` (不抽 CliBackend trait — ADR-405 §3.7 / cli-命令行.md §4)。
//! K-R4: 明文 wxid / master_key 不入 log/stdout — Wxid Display 走 sha8, master key 不打印。

// CLI 里就近声明的辅助 item(常量/小函数)紧挨着用它的那段, 比堆到文件顶部更好读 ——
// 这个文件近万行, 顶部集中声明等于让人来回翻。
#![allow(clippy::items_after_statements)]

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
// ② CLI 自足 — ingest / watch 复用 msgvestige-adapter 的定位 + 编排 + 监听引擎 (与 msgvestige-adapter bin 同一份, 免抄免漂移)。
use native_adapter::{
    locate_account_dbs, run_full_ingest, run_message_watch, run_source_watch, run_thin_watch, IngestPlan,
    MessageWatchOpts, SourceWatchOpts, ThinWatchOpts,
};
// 就地解密加密微信库 (--cipher native): 薄封装 open_decrypted_db + 解密句柄 DecryptedDb (K-R4 错误脱敏在 native-core)。
use native_core::cipher::{open_decrypted_db, DecryptedDb};
use native_core::key_provider::{CacheKeyProvider, ChainedKeyProvider, CliKeyProvider, KeyProvider, MasterKey, Wxid};
use native_core::{AccountDbSource, PrivacyMode};
// 信封 / 游标 / keyset 分页 / 错误码已抽进共享查询内核 native-query (§6①); 皮层一行引全, 各 call site 不变。
use native_query::{
    cache_key, classify_error, cli_err, default_wechat_data_dir, emit_envelope, hot_messages, hot_sessions,
    needs_ingest_err, open_l1, open_l1_resolved, render_table, run_query, wxid_from_dir_name, CliError, ExtractKind,
    InspectType, Meta, MoneyKind, PiiKind, QueryCommand, QueryTarget, Source, StatsBy,
};

/// R2/⑧ logs bundle — 日志诊断包打包 (收集/脱敏/写 zip; 单测在模块内)。
mod logs_bundle;

#[derive(Parser)]
// 版本号带上**是从哪一笔提交建出来的** —— 工作区的版本号一直写死是 `0.1.0-alpha`, 而包名
// 分了 alpha.1/2/3, 于是拿到包的人跑 `--version` 分不出手里是哪一版, 出问题也没法定位到代码。
// `BUILD_GIT_SHA` 由 build.rs 填(拿不到 git 就是 `unknown`; 工作区有未提交改动会标出来)。
#[command(
    name = "msgvestige",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("BUILD_GIT_SHA"), ")"),
    about = "微信数据基座 alpha CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// 确认执行慢查 —— 成本预估超强制阈值 (主号 15s / 副号 30s) 的全扫命令默认被拒; 加此才执行。
    #[arg(long, global = true)]
    confirm: bool,

    /// 免打扰 —— 压掉"估算 X 秒建议 cache add"的成本提示 (仍拦超强制阈值的, 除非 --confirm)。
    #[arg(long, global = true)]
    quiet: bool,
}

/// R21 全扫成本门的进程级开关 —— 顶层 `--confirm`/`--quiet` 的镜像 ([`real_main`] 解析 argv 后 set 一次)。
///
/// clap 全局 flag 落在顶层 [`Cli`], 而各 `cmd_*` handler 只收自己的 `Args`; 用进程级静态传门开关,
/// 免去给 ~19 个全扫命令 handler 逐个改签名 (加法式接线, 不动 native-core/native-query)。
/// 单线程 CLI: `real_main` set 于 dispatch 前, 所有 handler 后跑 → 必见已 set 值。
static GATE_CONFIRM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// 见 [`GATE_CONFIRM`]。
static GATE_QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Subcommand)]
enum Command {
    /// 版本 / 环境信息 — 打印 cli 版本 + 平台 / 架构 (装机排查第一步)
    Version,
    /// 取 key + 缓存 — 检测微信账号, hook 取当前登录账号 master key 并 DPAPI 缓存
    Auth(AuthArgs),
    /// MCP 服务器 — 给 AI (Claude 等) 直接问微信数据 (JSON-RPC over stdio, 只读)
    Mcp(McpArgs),
    /// HTTP API 服务器 — REST 端点供程序/网页前端查微信数据 (只读, 只监听本机)
    Serve(ServeArgs),
    /// 建 L1 库 — 直读加密微信库解密 + ETL 落 L1 (先 auth 缓存 key; 默认只导消息, --all 全量; 之后各查询命令即用)
    Ingest(IngestArgs),
    /// 实时监听 — 轮询消息库, 有新消息就增量抽取 (合并 WAL 读实时数据; 默认临时观察 tail-f 不动真库)
    Watch(WatchArgs),
    /// 选择性采集 — capture add/rm/list 圈定某些群/好友, 之后 ingest/watch 只增量存圈定会话 (没圈=全采; 写 L1 的 capture_targets)。
    /// ⚠️ 白名单只由当前及更新版本的二进制强制; 别用更旧版本的二进制打开带白名单的库 (旧版无此过滤、会无视白名单全采)。
    Capture(CaptureArgs),
    /// 从 L1 db 导出业务表到 JSONL — 联系人/群/会话/收藏 (直读明文 L1, 一行一 JSON 对象)
    Export(ExportArgs),
    /// 解密图片 — 遍历(已解密)message db 定位 .dat, 用账号 image key 解密落图 (best-effort)
    ///
    /// 退出码: 有失败项就返回非 0 (2026-07-29 起; 之前一律 0)。零产出零失败(比如源文件都被微信清理了)仍返 0。
    DecryptImages(DecryptImagesArgs),
    /// 导出视频 — 遍历(已解密)message db 视频消息, 经 hardlink 定位, 明文拷出 / 加密降级 (不解密)
    ///
    /// 退出码: 有失败项就返回非 0 (2026-07-29 起; 之前一律 0)。零产出零失败(比如源文件都被微信清理了)仍返 0。
    ExportVideos(ExportVideosArgs),
    /// 导出语音 — 读(已解密)media_0.db 的 VoiceInfo, SILK v3 解码 → WAV 落盘
    ///
    /// 退出码: 有失败项就返回非 0 (2026-07-29 起; 之前一律 0)。零产出零失败(比如源文件都被微信清理了)仍返 0。
    ExportVoices(ExportVoicesArgs),
    /// 媒体入内容仓 — voice/video/image 按内容 sha256 收进 CAS 内容仓 + 侧车账本 (去重/逐项状态; 替批量导出)
    ///
    /// 退出码: 有失败项就返回非 0 (2026-07-29 起; 之前一律 0)。零产出零失败(比如源文件都被微信清理了)仍返 0。
    MediaIngest(MediaIngestArgs),
    /// 解密表情包 — 读 emoticon.db 拿 md5+aeskey+URL, 从 CDN 下载加密字节 → AES-128-CBC 解密落图 (需联网)
    ///
    /// 退出码: 有失败项就返回非 0 (2026-07-29 起; 之前一律 0)。零产出零失败(比如源文件都被微信清理了)仍返 0。
    DecryptEmoji(DecryptEmojiArgs),
    /// 导出朋友圈媒体 — 读 L1 moment_media 拿 url/token/key, CDN 下载 → WxIsaac64 (node WASM) XOR 解密落图 (需联网+node)
    ///
    /// 退出码: 有失败项就返回非 0 (2026-07-29 起; 之前一律 0)。零产出零失败(比如源文件都被微信清理了)仍返 0。
    ExportSnsMedia(ExportSnsMediaArgs),
    /// 对账 — native 解密加密库 vs 竞品解密的明文库, 逐表比 row count + 内容 SHA-256 digest
    Reconcile(ReconcileArgs),
    /// 全文搜索 — 在 L1 db 的 message 正文里搜关键词 (FTS5 trigram, 中文子串; 首用 --build 建索引)
    ///
    /// 已知边界: 建索引记住"上次读到哪一格", 判断"还是不是原来那个库"用的探针比消息采集那条少一个
    /// (不含"已读段行数"), 为的是不拖慢。所以"某段被挖了洞、后来又补回来"这种情况, 搜索索引盖不住 ——
    /// 结果是搜不到那几条, 但消息本身在库里, 用 messages 查得到, 数据不丢。
    /// 觉得搜不全就 --build --rebuild 重建一遍。
    Search(SearchArgs),
    /// 列出所有会话 — 直查加密 session.db 的 SessionTable (auth 后即用, 不建 L1; 出完整字段)
    Sessions(SessionsArgs),
    /// 查某会话最近消息 — 直查加密源库 (auth 后即用, 不建 L1)
    Messages(MessagesArgs),
    /// 装机 / 环境自检 — native-only 6 项 (平台 / 微信目录 / wx_key.dll / key 缓存 / 临时目录 / ffmpeg); 有 🛑 失败则 exit 1
    Doctor(DoctorArgs),
    /// 查 / 搜联系人 — 读 L1 person 表 (只读; 须先 ingest 产出 L1)
    Contacts(ContactsArgs),
    /// 查群成员 — 读 L1 chatroom_member 表 (只读; 须先 ingest 产出 L1)
    Members(MembersArgs),
    /// 查收藏 — 读 L1 favorite 表 (只读)
    Favorites(FavoritesArgs),
    /// 查朋友圈 — 读 L1 moment 表 (只读; 须先 --sns ingest)。子视图: --interactions / --feed / --inbox
    Moments(MomentsArgs),
    /// 当前账号信息 — 读 L1 各表行数统计 (只读)
    Account(AccountArgs),
    /// 查通话记录 — 读 L1 message_call ⋈ message (只读; 语音/视频通话时长与结果)
    Calls(CallsArgs),
    /// 查位置分享 — 读 L1 message_location ⋈ message (只读; 经纬度/POI/地址/城市)
    Locations(LocationsArgs),
    /// 查名片 — 读 L1 message_card ⋈ message (只读; 分享的联系人/公众号名片)
    Cards(CardsArgs),
    /// 查媒体清单 — 读 L1 message_media ⋈ message (只读; 图/视频/文件/语音的 md5/大小/时长/CDN)
    Media(MediaArgs),
    /// 查群进出记录 — 读 L1 chatroom_member_event (只读; 谁进群/退群/被踢 + 邀请人 + 时间)
    GroupEvents(GroupEventsArgs),
    /// 查自定义表情 — 读 L1 custom_emoticon (只读; 表情描述/md5/product/CDN)
    Emoticons(EmoticonsArgs),
    /// 查头像清单 — 读 L1 avatar_image (只读; 联系人/md5/更新时间; 不含 BLOB)
    Avatars(AvatarsArgs),
    /// 查企微联系人 — 读 L1 bizchat_user (只读; 显示名/wxid/品牌号)
    BizContacts(BizContactsArgs),
    /// 查群列表 — 读 L1 chatroom (只读; 群名/群主/人数/公告; 补 inspect 只能查单个的空白)
    Chatrooms(ChatroomsArgs),
    /// 查好友申请/验证 — 读 L1 friend_verify 表 (只读; 加好友来源场景 + 打招呼语)
    FriendRequests(FriendRequestsArgs),
    /// 查 @提及 — 读 L1 message_mention ⋈ message (只读; 可 -q 按被@人过滤, 填自己 wxid 看"@我")
    Mentions(MentionsArgs),
    /// 查交易 — 转账/红包/群收款合并时间线 (读 L1 transfer/red_envelope/group_pay; 金额 JOIN message_app; 只读)
    Money(MoneyArgs),
    /// 统计 — 消息按 类型/会话/发送人/日期 聚合排行 (读 L1 message; 只读)
    Stats(StatsArgs),
    /// 沉睡会话 — 最久没说话的会话排行 (读 L1 message; 按最近一条消息时间升序; 只读)
    Dormant(DormantArgs),
    /// 看详情 — inspect <type> <id> 单条记录全字段 (type=contact/chatroom/session/message; 只读 L1; 解同 wxid 歧义)
    Inspect(InspectArgs),
    /// 看/清 master key 缓存 — 列已缓存账号(只出 wxid+key指纹, 绝不出明文key); --clear <wxid> 清一条
    Cache(CacheArgs),
    /// 打印明文 master key — key show --wxid <w> --i-understand → 明文 key hex 到 stdout (接 chatlog/wx-cli 等; 需 --i-understand 确认)
    Key(KeyArgs),
    /// 管理常驻搜索索引 — live-index status/build/clear (build 建全文索引 + 增量触发器, 之后 ingest 自动进索引)
    LiveIndex(LiveIndexArgs),
    /// 展开合并转发 — 列合并转发消息 / --msg-id 展开某条逐子项 (读 L1 message_forward_item; 只读)
    Resolve(ResolveArgs),
    /// 看设置 — config show 看生效配置(日志级别/目录) / config path 看配置文件在哪 (读 config.toml; 只读)
    Config(ConfigArgs),
    /// 打日志诊断包 — logs bundle 把日志+配置+版本/OS 打成 zip (已脱敏; 内测报 bug 用; 只读)
    Logs(LogsArgs),
    /// 列分享的链接/卡片 — message_app 里带 url 的 (链接/小程序/视频号) ⋈ message 取时间/会话 (读 L1; 只读)
    Links(LinksArgs),
    /// 列文件消息 — message_app 里的文件传输 (文件名/后缀/大小) ⋈ message 取时间/会话 (读 L1; 只读)
    Files(FilesArgs),
    /// 扫隐私号码 — 文本消息里疑似手机号/身份证号 (身份证走校验位过滤误报; 默认打码, --reveal 显全; 只读)
    PiiScan(PiiScanArgs),
    /// 列引用回复 — message_app 里带 refermsg 的 (回复正文 + 被引原文) ⋈ message 取时间/会话 (读 L1; 只读)
    Thread(ThreadArgs),
    /// 列访问过的视频号 (视频号名/号主/访问时刻/主页链接; 只读; --mode hot 可直读微信库拿实时数据)
    Finder(FinderArgs),
    /// 列公众号图文推送 — message 里 gh_ 公众号会话 (文章标题/公众号/时间; 读 L1; 只读)
    Biz(BizArgs),
    /// 原始 payload dump — raw_payload_archive 溯源 (给 --native-id 转出整条原始事件 JSON; 读 L1; 只读)
    ///
    /// 注意: 这张表是滚动窗口, 不是长期存档 —— 默认只留最近 24 小时 (config 的
    /// adapter.archive_retention_hours 可改, 1~720 小时)。查不到老记录是正常的; 业务数据在
    /// message / person 等表里, 不受这个窗口影响。
    Msgraw(MsgrawArgs),
    /// 列群系统事件 — 进群/退群/撤回/拍一拍/置顶等 (message type10000 按 sys_type 分类; 读 L1; 只读)
    Events(EventsArgs),
    /// 只读 SQL 逃生口 — 直接对 L1 库跑 SELECT (高级用法; 拒绝写操作/多语句; 只读)
    Exec(ExecArgs),
    /// 抽取结构化信息 — 从文本消息抽 url/email/amount/phone/idcard (一次一类; 读 L1; 只读)
    Extract(ExtractArgs),
    /// 增量看新消息 — 上次之后新到的 (记住水位; 给 --l1-db 读 L1, 不给就直读微信库, --mode 可强制; 只读)
    ///
    /// 两个已知边界, 都不会当成错误报出来, 知道了就不会误以为"程序说没有就是真没有":
    ///
    /// 一, 一次最多给 N 条 (默认 50), 按会话顺序发。一直在来消息的会话会占着名额, 安静会话
    /// 这一次可能轮不上 —— 数据不会丢, 没发出来的下次还在。想都看到就把 -n 调大,
    /// 或者用 --per-conv 给每个会话先留几条 (只有实时模式认这个参数, 详见它自己的说明)。
    /// --format json 里能看出还有没有没给的: 实时模式给 total_new / new_shown, 冷查只给 has_more
    /// (只说明还有没有下一批, 不给条数)。注意 total_new 只有这一轮全扫干净时才准 —— 有表没扫全
    /// (被打断 / 打不开 / 没排进计划) 时那些表的新消息没被数进去, 这个数会偏少, 要连同一份 json 里的
    /// partial 和几个 scan_ 开头的计数一起看。
    ///
    /// 二, 换过数据库副本时可能认不出来。实时模式判断"还是不是原来那个库", 靠的是每张聊天表上
    /// 留的一个记号: 记号那一行的时间变了就算换过; 从头到它为止 (含它自己) 有多少行, 变多了也算
    /// 换过 (变少多半是你自己删了消息, 那不该重报)。所以时间没变、行数也没变多的两份副本会被当成
    /// 同一个库, 中间那段内容不一样的话就永远读不到。另外, 头一次看这张表 (或者刚 --reset 过) 时
    /// 两项都还没有基准, 这一轮什么都不比, 扫完才立起来; 基准已经有了、但换进来的副本里压根没有
    /// 记号那一行 (比如它行数更少) 时, 时间那一项哑火, 只剩行数一项在守 —— 而行数只在变多时才算。
    /// 换过数据目录、从备份恢复过、或者觉得历史不对劲, 用 --reset 从头重扫一遍。
    ///
    /// 还有一种情况这道保险会失效: 某一轮某张表没扫全, 记号就停在原地不往前走, 它和你实际读到的
    /// 位置之间那一段就没有保险; 那张表要是一直扫不全, 这道判断就一直不跑。多数时候命令跑完会打
    /// 一行"N 张会话表的护栏覆盖不全"提醒你 —— 但不是每一种都报得出来。成因有五类、哪几类在
    /// --format json 里查得到、什么时候报什么时候不报, 都列在 快速开始.md 的「已知做不到的」那一节
    /// (发布包里带这份文档)。
    New(NewArgs),
    /// 漏回 — 对方最后说话、我还没回的会话 (每会话末条非系统消息是对方发的; 读 L1; 只读)
    Followups(FollowupsArgs),
    /// 清除本地数据 — 删工具自身痕迹 (key缓存/日志/temp; 默认预演, --yes 才真删; 不碰你的 L1/导出)
    Wipe(WipeArgs),
    /// 存图片 image key — V2 完整图解密用 (手填 --image-key/--image-xor 或自动扫微信内存) → 独立 image cache,
    /// serve `/media/img` 读它解 V2 完整图 (V0 缩略图/明文不需)。跟 master key `auth` 分开 (image key 是另一把)。
    ImageKey(ImageKeyArgs),
}

/// `image-key` 参数 — 存账号图片 image key (aes+xor) 到独立 cache (serve `/media/img` 解 V2 完整图用)。
#[derive(Args)]
struct ImageKeyArgs {
    /// 账号 wxid (image key 按账号存)。
    #[arg(long)]
    wxid: String,
    /// image AES key (16 ASCII, wx_key 给的 aesKey 原样, 别 hex-decode)。跟 `--image-xor` 一起给 = 手填;
    /// 都省 = 自动扫微信内存 (需微信在跑 + 点开过几张图)。
    #[arg(long)]
    image_key: Option<String>,
    /// image XOR key (hex 单字节, 如 d3 / 0xd3)。跟 `--image-key` 一起给或一起省。
    #[arg(long)]
    image_xor: Option<String>,
    /// 账号目录 (自动扫时从其 `msg/attach` 取 V2 样本做交叉验证锚; 手填时不用)。
    #[arg(long)]
    account_dir: Option<String>,
}

#[derive(Args)]
struct DecryptEmojiArgs {
    /// (已解密的) emoticon.db 路径 (含 kNonStoreEmoticonTable: md5 / aes_key / *_url)。
    #[arg(long)]
    emoticon_db: String,
    /// 输出目录 (落解密后的表情图; 自动创建)。
    #[arg(long)]
    out_dir: String,
    /// 最多解多少个表情 (缺省全部)。
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Args)]
struct ExportSnsMediaArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 输出目录 (落解密后的朋友圈图/视频; 自动创建)。
    #[arg(long)]
    out_dir: String,
    /// 最多导出多少条 (开发验证用 --limit 几条即可, 别全量)。
    #[arg(long)]
    limit: Option<usize>,
    /// vendor 的 weflow_wasm keystream 目录 (含 weflow_wasm_keystream.js + wasm_video_decode.wasm/.js);
    /// 缺省依次找 WECHAT_SNS_WASM_DIR → cli 同目录/vendor/weflow_wasm。运行期需系统 node。
    #[arg(long)]
    wasm_dir: Option<String>,
}

#[derive(Args)]
struct ExportVideosArgs {
    /// (已解密的) message db 路径 (含 Msg_<talker> 表; 视频消息 local_type=43)。
    #[arg(long)]
    message_db: String,
    /// (已解密的) 视频 hardlink db 路径 (video_hardlink_info_v4 + dir2id; md5→文件名+月份定位)。
    #[arg(long)]
    hardlink_db: String,
    /// 微信账号目录 (xwechat_files\wxid_..._abfe, msg/video 所在)。
    #[arg(long)]
    account_dir: String,
    /// 输出目录 (落明文视频; 自动创建)。
    #[arg(long)]
    out_dir: String,
    /// 最多拷出多少明文视频 (缺省全部)。
    #[arg(long)]
    limit: Option<usize>,
    /// 解密选项 — `--cipher native` 直读加密 message + hardlink 库 (无需先手动解密)。省略 = 须是已解密明文库。
    #[command(flatten)]
    decrypt: DecryptOpts,
}

#[derive(Args)]
struct ExportVoicesArgs {
    /// media_0.db 路径 (含 VoiceInfo 表; 语音 SILK v3 BLOB)。会枚举同目录全部 media_<N>.db 分片一起导
    /// (媒体库文件级分片 media_0/media_1/…; 只导单个会漏语音); 指到 media_0.db 即可导全部分片。
    #[arg(long)]
    media_db: String,
    /// 输出目录 (落 .wav; 自动创建; 不能在 media_0.db 所在目录内)。
    #[arg(long)]
    out_dir: String,
    /// 最多导出多少条 (缺省全部; 开发验证用 --limit 几条即可, 别全量导 1.1 万)。
    #[arg(long)]
    limit: Option<usize>,
    /// 转成 MP3 (体积小、通用; 需 ffmpeg)。缺省留 WAV (零依赖、能直接听)。
    #[arg(long)]
    mp3: bool,
    /// ffmpeg 路径 (仅 --mp3 用; 缺省依次找 WECHAT_FFMPEG → cli 同目录 → PATH)。
    #[arg(long)]
    ffmpeg: Option<String>,
    /// 解密选项 — `--cipher native` 直读加密 media_0.db (无需先手动解密)。省略 = 须是已解密明文库。
    #[command(flatten)]
    decrypt: DecryptOpts,
}

/// `media-ingest` 收哪种媒体。
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum IngestKind {
    /// 语音 (media_0.db VoiceInfo → SILK→WAV)。
    Voice,
    /// 视频 (message db local_type=43 → hardlink 定位明文 mp4)。
    Video,
    /// 图片 (message db local_type=3 → packed_info 定位 .dat 解密)。
    Image,
}

#[derive(Args)]
struct MediaIngestArgs {
    /// 内容仓根目录 — 每账号一仓 `<store-root>/<账号sha8>/`(账本 ledger.db + by-content 内容文件落这; 自动创建)。
    #[arg(long)]
    store_root: String,
    /// 收哪几种媒体 (可多次: `--kind voice --kind image`; 缺省 = 三种都收)。
    #[arg(long, value_enum)]
    kind: Vec<IngestKind>,
    /// media_0.db 路径 (voice 用; 枚举同目录 media_<N>.db 分片)。
    #[arg(long)]
    media_db: Option<String>,
    /// message_0.db 路径 (video/image 用; 枚举同目录 message_<N>.db 分片)。
    #[arg(long)]
    message_db: Option<String>,
    /// hardlink.db 路径 (video 定位明文视频用)。
    #[arg(long)]
    hardlink_db: Option<String>,
    /// 账号数据目录 (video/image 用; `msg/video` 与 `msg/attach` 所在, 如 `…/xwechat_files/wxid_xxx_yyy`)。
    #[arg(long)]
    account_dir: Option<String>,
    /// 账号级 image key (解 V2 完整图; 须与 --image-xor 成对给)。都不给则只收无需 key 的 V0 缩略图。
    #[arg(long, requires = "image_xor")]
    image_key: Option<String>,
    /// image key 的 xor 字节 (须与 --image-key 成对给)。
    #[arg(long, requires = "image_key")]
    image_xor: Option<String>,
    /// 每种媒体最多收多少条 (缺省全部; 开发验证用 --limit 几十条)。
    #[arg(long)]
    limit: Option<usize>,
    /// 解密选项 — `--cipher native` 直读加密源库 (`--wxid` 查缓存 key; 省略 = 输入须已解密明文库)。--wxid 也用于绑定内容仓账号。
    #[command(flatten)]
    decrypt: DecryptOpts,
}

#[derive(Args)]
struct ExportArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 导出哪张表: contacts / groups / sessions / favorites / messages。
    #[arg(long)]
    table: String,
    /// 输出文件 (缺省写 stdout)。
    #[arg(long)]
    out: Option<String>,
    /// 输出格式: jsonl (默认) / csv (Excel 友好) / html (浏览器直接看)。
    #[arg(long, default_value = "jsonl")]
    format: String,
    /// 仅导某会话 (conv_id, 如 xxx@chatroom; 只对 --table messages 生效)。
    #[arg(long)]
    chat: Option<String>,
}

#[derive(Args)]
struct SearchArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 搜索关键词 (在 message.text_content 里子串匹配; ≥3 字走 trigram 索引, <3 字 LIKE 兜底)。
    #[arg(long)]
    query: Option<String>,
    /// (重)建全文索引 message_fts (首次搜索前必须建一次; 之后有新消息也要重建才搜得到)。
    #[arg(long)]
    build: bool,
    /// 最多返回几条 (按 bm25 相关度)。
    #[arg(long, default_value_t = 20)]
    limit: i64,
    /// 输出格式 (table 给人看 / json 走 {data, meta} 给脚本/AI)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
    /// thin 独立瘦库路径 (`live-index build --tier thin --thin-db` 建的) —— 给了则搜它
    /// (自存 content, 出 msg_id + snippet 高亮), 否则搜 --l1-db 的 message_fts。
    #[arg(long)]
    thin_db: Option<String>,
    // R21: --confirm/--quiet 已上提为顶层全局 flag (见 Cli), 各全扫命令共用; 此处不再单列。
}

/// 查询命令输出格式 (sessions / messages …)。table 给人看, json 走 {data, meta} 信封。
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutFormat {
    /// 终端表格 (默认)。
    Table,
    /// JSON (`{data: [...], meta: {...}}`), 脚本 / AI 用。
    Json,
}

#[derive(Args)]
struct SessionsArgs {
    /// 账号 wxid (实时查/auto: 查缓存 key + 定位账号库, 须先跑过 `auth`)。冷查不需要。
    #[arg(long)]
    wxid: Option<String>,
    /// 微信数据目录 (实时查; 默认探测 %USERPROFILE%\Documents\xwechat_files)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// 查询模式: hot 实时读微信库 (默认) / cold 读 L1 投影库 (快但可能旧, 需 --l1-db) / auto 有 L1 走冷否则热。
    #[arg(long, value_enum, default_value = "hot")]
    mode: native_query::QueryMode,
    /// L1 db 路径 (冷查 / auto 用)。
    #[arg(long)]
    l1_db: Option<String>,
    /// 多账号 L1 隔离: 指定账号 wxid (冷查; 单账号库省略)。
    #[arg(long)]
    account: Option<String>,
    /// 最多列几个会话。
    #[arg(short = 'n', long, default_value_t = 50)]
    limit: usize,
    /// 跳过前几个 (翻页; 配 --limit 够到 limit 之外的会话)。
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
    /// 定位表 JSON 路径 (持久化, 缺省系统临时目录按 wxid 命名)。
    #[arg(long)]
    locator_file: Option<String>,
}

#[derive(Args)]
struct MessagesArgs {
    /// 会话: 对方 wxid, 或群 id (形如 `xxxx@chatroom`)。不知道就先跑 `sessions`。
    chat: String,
    /// 账号 wxid (实时查/auto: 查缓存 key + 定位账号库, 须先跑过 `auth`)。冷查不需要。
    #[arg(long)]
    wxid: Option<String>,
    /// 微信数据目录 (实时查; 默认探测 %USERPROFILE%\Documents\xwechat_files)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// 查询模式: hot 实时读微信库 (默认) / cold 读 L1 投影库 (快但可能旧, 需 --l1-db) / auto 有 L1 走冷否则热。
    #[arg(long, value_enum, default_value = "hot")]
    mode: native_query::QueryMode,
    /// L1 db 路径 (冷查 / auto 用)。
    #[arg(long)]
    l1_db: Option<String>,
    /// 多账号 L1 隔离: 指定账号 wxid (冷查; 单账号库省略)。
    #[arg(long)]
    account: Option<String>,
    /// 最多取几条 (按 local_id 倒序取最近的)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
    /// 定位表 JSON 路径 (持久化, 缺省系统临时目录按 wxid 命名)。
    #[arg(long)]
    locator_file: Option<String>,
    /// 直接读 L1 现有的, 不先去微信库补新消息 (快, 但可能不是最新)。
    ///
    /// 默认 (给了 --wxid 时): 先把这个会话的新消息补进 L1 再查, 所以结果总是最新的。
    /// 没给 --wxid 时读不到微信库, 本来就只能读 L1 现有的。
    #[arg(long)]
    no_refresh: bool,
}

#[derive(Args)]
struct DecryptImagesArgs {
    /// (已解密的) message db 路径 (含 Msg_<talker> 表)。消息驱动模式必填; `--full-images` 扫盘模式不需要。
    #[arg(long)]
    message_db: Option<String>,
    /// 微信账号目录 (xwechat_files\wxid_..._abfe, msg/attach 所在)。
    #[arg(long)]
    account_dir: String,
    /// 扫盘模式: 直接递归 msg/attach 解 V2 完整原图 (含 wxgf 动图, 转 GIF), 不走 message db。
    /// 缺省是消息驱动模式 (走 message packed_info, 主要拿 V0 缩略图)。完整图文件名是本地 hash 从消息推不出,
    /// 只能扫盘 → 要 wxgf 动图/全分辨率图就用这个。
    #[arg(long)]
    full_images: bool,
    /// 朋友圈缓存扫盘模式: 扫 `cache/<年-月>/Sns/Img/**` 解 V2 .dat 落图 (账号 image key, 同聊天图;
    /// 零联网、零 WASM、不过期)。补 `export-sns-media`(走 CDN 下载)老 URL 过期的盲区。不走 message db。
    #[arg(long)]
    sns_cache_images: bool,
    /// 账号 image AES key (16 位 ASCII, 直接当 key 不 hex-decode; wx_key/内存扫取)。
    /// 连同 --image-xor 都省略 → 自动扫微信内存取 key (仅 Windows x64; 微信须在跑)。
    #[arg(long, value_name = "ASCII16")]
    image_key: Option<String>,
    /// 账号 image XOR key (十六进制字节, 如 d3 或 0xd3)。跟 --image-key 一起给 (手填) 或 一起省 (自动扫)。
    #[arg(long, value_name = "HEXBYTE")]
    image_xor: Option<String>,
    /// 输出目录 (落解密后的图; 自动创建)。
    #[arg(long)]
    out_dir: String,
    /// 最多导出多少张 (缺省全部)。
    #[arg(long)]
    limit: Option<usize>,
    /// ffmpeg 可执行路径 (把 wxgf 动图转成 GIF)。缺省依次找: 环境变量 WECHAT_FFMPEG → cli 同目录
    /// ffmpeg[.exe] → PATH。没找到则 wxgf 留 `.wxgf` 不转 (内容不丢)。
    #[arg(long)]
    ffmpeg: Option<String>,
    /// 解密选项 — `--cipher native` 直读加密 message db (无需先手动解密)。图 .dat 的 image key 仍走 --image-key / 自动扫。
    #[command(flatten)]
    decrypt: DecryptOpts,
}

#[derive(Args)]
struct AuthArgs {
    /// 指定账号 wxid (默认扫微信数据目录自动检测; 多账号时必填)。
    #[arg(long)]
    wxid: Option<String>,
    /// 微信数据目录 (xwechat_files; 默认探测 %USERPROFILE%\Documents\xwechat_files)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// 模式 A: 不重启微信 (保留当前窗口, 等用户手动注销重登)。默认模式 B: 杀 + 重启 + 扫码。
    #[arg(long)]
    no_restart: bool,
    /// 钉死微信主进程 PID (默认自动发现)。
    #[arg(long)]
    wechat_pid: Option<u32>,
    /// 兜底: 直接提供 master key (64 hex), 跳过 hook (须配 --wxid)。
    #[arg(long, value_name = "HEX")]
    master_key_hex: Option<String>,
    /// 非扰动内存扫: 从运行中的微信进程内存直接扫成品 enc_key 存 cache (不杀/不重启/不扫码;
    /// 要求该账号正登录运行; 仅 Windows-x64; 多账号须配 --wxid 指目标账号)。
    #[arg(long)]
    scan: bool,
}

/// `mcp` 服务器参数 —— 数据源配置 (启动时定, 各工具据此查)。
#[derive(Args)]
struct McpArgs {
    /// 冷查 L1 库路径 (ingest 产出; 联系人/账号/朋友圈等读它)。省略则冷查工具报未配置。
    #[arg(long)]
    l1_db: Option<String>,
    /// 热查 (会话/消息直读加密源库) 的微信数据目录 (xwechat_files; 省略则热查工具报未配置)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// 默认账号 wxid (工具未显式给 account 时用; 热查必需 —— 定位账号库 + 取缓存 key)。
    #[arg(long)]
    wxid: Option<String>,
}

/// `serve` HTTP API 服务器参数 —— 数据源 + 监听地址。
#[derive(Args)]
struct ServeArgs {
    /// 冷查 L1 库路径 (联系人/账号/朋友圈等读它)。
    #[arg(long)]
    l1_db: Option<String>,
    /// 热查 (会话/消息) 的微信数据目录 (xwechat_files)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// 默认账号 wxid (端点未给 account 时用)。
    #[arg(long)]
    wxid: Option<String>,
    /// 监听地址 (默认 loopback; 绑 0.0.0.0 = 非公网方案, 无 TLS/限流)。
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// 监听端口。
    #[arg(long, default_value_t = 8420)]
    port: u16,
    /// 开启实时事件 (`/events` SSE): 起后台 watch 持续解密活微信库、增量落 --l1-db (需 --wxid + --l1-db)。
    /// 不加 = 纯只读服务 (无 /events)。
    #[arg(long)]
    watch: bool,
    /// (--watch) 后台监听轮询间隔 ms (盯活库 mtime; 越小越实时越耗)。
    #[arg(long, default_value_t = 800)]
    poll_ms: u64,
    /// 朋友圈加密媒体 (`/media/moment:`) 的 node keystream 脚本目录 (含 weflow_wasm_keystream.js +
    /// wasm_video_decode.wasm/.js; 需系统装 node)。省略 → 退到 env WECHAT_SNS_WASM_DIR / exe 同目录 vendor/weflow_wasm。
    #[arg(long)]
    sns_wasm_dir: Option<String>,
    /// ffmpeg 可执行路径 (wxgf 动图/静图 → GIF/PNG 当场转码; `/media/img|emoji|moment`)。
    /// 省略 → 退到 env WECHAT_FFMPEG / exe 同目录 / PATH。缺则 wxgf 出 octet-stream (内容不丢)。
    #[arg(long)]
    ffmpeg: Option<String>,
    /// (可选加固) 每请求总超时秒数: 非流式端点超此 → 408。省略 = 不限 (合法慢查询默认不被切)。
    /// `/events`(SSE) 与 `/media`(大流/联网) 恒不受此限。
    #[arg(long)]
    request_timeout_secs: Option<u64>,
    /// (可选加固) 最大并发在途请求数: 超出排队等待 (背压)。省略 = 不限。
    #[arg(long)]
    max_concurrent: Option<usize>,
    /// 实时索引档: off / cold (静态 L1 冷查, 不内嵌维护) / full (隐含 --watch + 全源库监听 L1 全表实时; 需 --wxid + --l1-db)。
    /// 不给 = 用 config 持久默认 (`config set live-index`; per-account > global > off)。
    #[arg(long, value_enum)]
    live_index: Option<LiveIndexTier>,
}

/// 就地解密后端 (`--cipher`)。目前仅 `native` (纯 Rust SQLCipher, 内存不落盘)。
/// 省略 = 输入库须是已解密明文文件 (现状)。
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum CipherKind {
    /// 纯 Rust SQLCipher4 解密 (全程内存, 不落明文文件; key 走 cache 或 --master-key-hex)。
    Native,
}

/// 解密选项 — 各导出/解密命令共用 (`#[command(flatten)]` 进各 Args)。
///
/// 给了 `--cipher` = 就地解密**加密**微信库 (不必先手动解密); 否则读**已解密**明文库 (现状)。
/// key 来源: `--master-key-hex` 直供 > cache 查 `--wxid` (**只读 cache, 不 hook / 不碰微信** — 取 key 是 `auth` 的事)。
#[derive(Args)]
struct DecryptOpts {
    /// 就地解密加密微信库 (`native` = 纯 Rust, 无需先手动解密)。省略 = 输入须是已解密明文 sqlite。
    #[arg(long, value_enum)]
    cipher: Option<CipherKind>,
    /// 账号 wxid (`--cipher` 时查已缓存的 key 用; 省略则从 --account-dir / 库路径自动检测)。
    #[arg(long)]
    wxid: Option<String>,
    /// 兜底: 直接给 master key (64 hex) 就地解密, 跳过 cache (`--cipher` 时用; 不回显)。
    #[arg(long, value_name = "HEX")]
    master_key_hex: Option<String>,
}

#[derive(Args)]
struct ReconcileArgs {
    /// 加密库路径 (native 解密它; 须配 --cipher native + wxid/key)。
    #[arg(long)]
    enc_db: String,
    /// 竞品/WDA 解密好的明文库路径 (直接读; 须与 enc-db 同一个库同 schema)。
    #[arg(long)]
    plain_db: String,
    /// 只对这些表 (逗号分隔; 省略 = 两库共有的全部用户表)。
    #[arg(long)]
    only: Option<String>,
    /// 解密选项 — enc-db 走 --cipher native + key 解密 (plain-db 是明文, 不用 key)。
    #[command(flatten)]
    decrypt: DecryptOpts,
}

// CliError / cli_err 已移至 native-query::error (§6①); 经上方 `use native_query::{...}` 引入, 调用点不变
// (CliError 字段改 pub 供跨 crate 构造 + render_cli_error 读 hint)。

// open_l1 (打库→BAD_REQUEST) / needs_ingest_err (缺表→NEEDS_INGEST) 已移至 native-query::engine (§6②);
// 经上方 `use native_query::{open_l1, needs_ingest_err}` 引入, 30+ 冷查命令调用点不变。

// classify_error 已移至 native-query::error (§6①); render_cli_error (下方) + main() 退出码经 `use` 调它 ——
// 分类进核, 呈现 (render/退出码) 留皮。

/// 渲染 `{_error, _hint}` 到 **stderr** (JSON;stdout 留给成功的 `{data,meta}`)。
/// K-R4: hint 由源头脱敏 (Wxid Display=sha8), 此处不再触碰明文。
fn render_cli_error(e: &anyhow::Error) {
    let code = classify_error(e);
    let hint = e
        .downcast_ref::<CliError>()
        .map_or_else(|| e.to_string(), |c| c.hint.clone());
    let out = serde_json::json!({ "_error": code.code(), "_hint": hint });
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| format!(r#"{{"_error":"{}"}}"#, code.code()))
    );
}

fn main() -> std::process::ExitCode {
    match real_main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            render_cli_error(&e);
            // exit_code() ∈ {2,3,4,5,6,7,70} → 稳落 u8 (doc② §二.5)。
            std::process::ExitCode::from(classify_error(&e).exit_code() as u8)
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn real_main() -> Result<()> {
    // 先装日志 (含 panic 钩子) 再解析 argv —— 早启动 panic (Cli::parse / config) 也落文件 + 脱敏, 对齐 msgvestige-adapter (审查 P2)。
    // 统一日志 (logging-日志.md 任务 1 + 收尾②): 读 config.toml (默认路径) 应用 log_dir/log_level;
    // 缺文件/坏文件走默认兜底。终端 + 按天文件; RUST_LOG > config.log_level > default (init_logging EnvFilter 保证)。
    // K-R4 脱敏靠类型层 (Wxid sha8) + common::redact。
    let cfg = native_core::config::load_or_default(&native_core::config::default_config_path());
    common::log::init_logging(&cfg.observability.log_level, &cfg.observability.log_dir);
    // R3 panic 钩子自测: 仅 debug + 环境变量触发 (release 编不进), 验 panic→日志 脱敏落文件。
    // 消息含明文 wxid → 日志里应变 wxid_<sha8>。(master key 靠类型层 MasterKey 无 Display 根本进不了消息, 不靠这里擦)
    #[cfg(debug_assertions)]
    assert!(
        std::env::var_os("__NATIVE_LOG_PANIC_SELFTEST").is_none(),
        "panic 自测: 坏账号 wxid_abcd1234efgh567 在 decode step 5"
    );
    let cli = Cli::parse();
    // R21: 顶层全局 --confirm/--quiet 镜像进静态, 供各全扫命令的成本门 (cost_gate_full_scan) 读取。
    GATE_CONFIRM.store(cli.confirm, std::sync::atomic::Ordering::Relaxed);
    GATE_QUIET.store(cli.quiet, std::sync::atomic::Ordering::Relaxed);
    match cli.command {
        Command::Version => cmd_version(),
        Command::Auth(args) => {
            let wxid = resolve_target_wxid(&args)?;
            // --scan: 非扰动内存扫 (不动微信); 否则走原 cache→ciphertalk→cli 链 (可能杀重启)。
            let ok = if args.scan {
                cmd_auth_scan(&args, &wxid).await?
            } else {
                let chain = build_key_chain(&args, &wxid)?;
                cmd_auth(&chain, &wxid).await?
            };
            if !ok {
                // 信封审 rank12: 别裸 exit(1) 逃契约 (1 ∉ 退出码闭集且无 {_error}) —— 走 cli_err
                // 出 {_error} 信封 + 闭集退出码 (失败原因已在上面日志; 无专码 → INTERNAL/70)。
                return Err(cli_err(
                    native_core::ErrorCode::Internal,
                    "auth 未取到该账号的 key (微信在跑? 看上面日志的失败原因)",
                ));
            }
            Ok(())
        }
        Command::Mcp(args) => cmd_mcp(&args).await,
        Command::Serve(args) => cmd_serve(&args).await,
        Command::Ingest(args) => cmd_ingest(&args).await,
        Command::Watch(args) => cmd_watch(&args).await,
        Command::Export(args) => cmd_export(&args),
        Command::DecryptImages(args) => {
            // --cipher native 时先取 db 解密 key (cache-only, 不 hook); 缺 --wxid 从 account_dir 名检测。
            let db_key = resolve_export_key(&args.decrypt, detect_wxid_from_path(Path::new(&args.account_dir))).await?;
            cmd_decrypt_images(&args, db_key.as_ref())
        }
        Command::ImageKey(args) => cmd_image_key(&args),
        Command::ExportVideos(args) => {
            let db_key = resolve_export_key(&args.decrypt, detect_wxid_from_path(Path::new(&args.account_dir))).await?;
            cmd_export_videos(&args, db_key.as_ref())
        }
        Command::ExportVoices(args) => {
            // media_0.db 路径含 wxid_<id>_<后缀> 祖先段 → 检测账号 (缺 --wxid 时)。
            let db_key = resolve_export_key(&args.decrypt, detect_wxid_from_path(Path::new(&args.media_db))).await?;
            cmd_export_voices(&args, db_key.as_ref())
        }
        Command::MediaIngest(args) => {
            // --wxid 必给 (绑定内容仓账号); --cipher 时它也用于查缓存 key。
            let db_key = resolve_export_key(&args.decrypt, None).await?;
            cmd_media_ingest(&args, db_key.as_ref())
        }
        Command::DecryptEmoji(args) => {
            // reqwest::blocking 内部起自己的 tokio runtime, 不能在 #[tokio::main] 的 async 上下文里跑
            //  (drop runtime 会 panic) → 丢到独立 OS 线程跑, 隔开两个 runtime。
            match std::thread::scope(|s| s.spawn(|| cmd_decrypt_emoji(&args)).join()) {
                Ok(res) => res,
                Err(_) => bail!("表情包解密线程 panic"),
            }
        }
        Command::ExportSnsMedia(args) => {
            // 同 DecryptEmoji: reqwest::blocking 丢独立线程隔 tokio runtime。
            match std::thread::scope(|s| s.spawn(|| cmd_export_sns_media(&args)).join()) {
                Ok(res) => res,
                Err(_) => bail!("朋友圈媒体导出线程 panic"),
            }
        }
        Command::Reconcile(args) => {
            // enc-db 走 --cipher native 解密; wxid 缺则从 enc-db 路径祖先目录检测。
            let db_key = resolve_export_key(&args.decrypt, detect_wxid_from_path(Path::new(&args.enc_db))).await?;
            cmd_reconcile(&args, db_key.as_ref())
        }
        Command::Search(args) => cmd_search(&args).await, // R16-6: 冷热派发 → async
        Command::Sessions(args) => cmd_sessions(&args).await,
        Command::Messages(args) => cmd_messages(&args).await,
        Command::Doctor(args) => cmd_doctor(&args).await,
        Command::Contacts(args) => cmd_contacts(&args).await, // R16-1: 冷热派发 → async (热查取 key 是 async)
        Command::Members(args) => cmd_members(&args).await,   // R16-1: 冷热派发 → async (降级件)
        Command::Favorites(args) => cmd_favorites(&args).await, // R16-1: 冷热派发 → async
        Command::Moments(args) => cmd_moments(&args).await,   // R16-1: 主表冷热派发 → async
        Command::Account(args) => cmd_account(&args).await,   // R16-6: 冷热派发 → async
        Command::Calls(args) => cmd_calls(&args).await,
        Command::Locations(args) => cmd_locations(&args).await,
        Command::Cards(args) => cmd_cards(&args).await,
        Command::Media(args) => cmd_media(&args).await,
        Command::GroupEvents(args) => cmd_group_events(&args).await,
        Command::Emoticons(args) => cmd_emoticons(&args).await,
        Command::BizContacts(args) => cmd_biz_contacts(&args).await, // R16-1: 冷热派发 → async
        Command::Chatrooms(args) => cmd_chatrooms(&args).await,      // R16-1: 冷热派发 → async
        Command::Avatars(args) => cmd_avatars(&args).await,          // R16-1: 冷热派发 → async
        Command::FriendRequests(args) => cmd_friend_requests(&args).await,
        Command::Mentions(args) => cmd_mentions(&args).await,
        Command::Money(args) => cmd_money(&args).await,
        Command::Stats(args) => cmd_stats(&args).await,
        Command::Dormant(args) => cmd_dormant(&args).await, // R16-6: 冷热派发 → async
        Command::Inspect(args) => cmd_inspect(&args).await, // R16-6: 冷热派发 → async
        Command::Cache(args) => cmd_cache(&args).await,
        Command::Key(args) => cmd_key(&args).await,
        Command::LiveIndex(args) => cmd_live_index(&args).await,
        Command::Resolve(args) => cmd_resolve(&args).await,
        Command::Config(args) => cmd_config(&args),
        Command::Capture(args) => cmd_capture(&args), // R19 选择性采集 (纯 sqlite 操作, sync)
        Command::Logs(args) => cmd_logs(&args),
        Command::Links(args) => cmd_links(&args).await,
        Command::Files(args) => cmd_files(&args).await,
        Command::PiiScan(args) => cmd_pii_scan(&args).await,
        Command::Thread(args) => cmd_thread(&args).await,
        Command::Finder(args) => cmd_finder(&args).await,
        Command::Biz(args) => cmd_biz(&args).await,
        Command::Msgraw(args) => cmd_msgraw(&args),
        Command::Events(args) => cmd_events(&args).await, // R16-2: 冷热派发 → async
        Command::Exec(args) => cmd_exec(&args).await,     // R16-6: 冷热派发 → async
        Command::Extract(args) => cmd_extract(&args).await,
        Command::New(args) => cmd_new(&args).await, // R16-5: 冷热派发 → async
        Command::Followups(args) => cmd_followups(&args).await, // R16-6: 冷热派发 → async
        Command::Wipe(args) => cmd_wipe(&args),
    }
}

#[derive(Args)]
struct DoctorArgs {
    /// 账号 wxid (给了则查该账号 key 是否已缓存; 不给跳过 key 检查)。
    #[arg(long)]
    wxid: Option<String>,
    /// 微信数据目录 (默认探测 %USERPROFILE%\Documents\xwechat_files)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// 已建好的 L1 库路径 (给了则查它跟本程序配不配; 不给跳过这一项)。
    ///
    /// 换新版本后建议带上: 库结构变过的话旧库用不了, 每条查询都会失败, 只能重建。
    //
    // ↑ 上面是用户看得见的 `--help`, **只写"要做什么"**。设计理由写在这里(普通注释):
    //   schema 版本升过两次 (1→2 R14 消息锚 / 2→3 R16-3 favorite_tag 锚) 且**不做迁移** ——
    //   版本不符时每条读命令都返 SCHEMA_MISMATCH, 库只能删掉从加密源全量重建。
    //   不带 --l1-db 的 doctor 查不出这件事, 会报「环境就绪」, 用户在第一条查询上才撞墙。
    //   (二轮审查逮到; 本轮又补了"有 message 表但无版本行"的旧库判据, 跟写侧门禁对齐。)
    //   注: 内部编号和 markdown 标记不能进 ///, 有测试 `subcommand_help_has_no_internal_narrative`
    //   守着 —— 我第一版就是写进 /// 才被它逮到的。
    #[arg(long)]
    l1_db: Option<String>,
}

/// doctor 单项自检等级。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CheckLevel {
    Pass,
    Warn,
    Fail,
}

impl CheckLevel {
    fn icon(self) -> &'static str {
        match self {
            CheckLevel::Pass => "✅",
            CheckLevel::Warn => "⚠️",
            CheckLevel::Fail => "🛑",
        }
    }
}

/// `doctor` — 装机 / 环境自检 (native-only 6 项; 有 🛑 失败则 exit 1)。
/// ADR-411 §3.2 原 7 项里 wcdb_api.dll / Node 随 sidecar 退役已去; config 版本校验待 config 命令。
async fn cmd_doctor(args: &DoctorArgs) -> Result<()> {
    eprintln!("msgvestige doctor — 环境自检");
    let mut checks: Vec<(CheckLevel, &'static str, String)> = Vec::new();

    // 1. 平台 (自动扫 key 仅 win-x64; 其他平台可手填 --master-key-hex)。
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    checks.push((CheckLevel::Pass, "平台", "Windows x64".into()));
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    checks.push((
        CheckLevel::Warn,
        "平台",
        "非 Windows x64 — auth 自动扫内存取 key 不可用, 需手填 --master-key-hex".into(),
    ));

    // 2. 微信数据目录 (探测到 + 至少一个账号目录)。
    checks.push(check_wechat_dir(args.wechat_data_dir.as_deref()));
    // 3. wx_key.dll (auth hook 取 key 依赖; vendored)。
    checks.push(check_wx_key_dll());
    // 4. key 缓存 (给 --wxid 才查; 命中 = 已 auth)。
    checks.push(check_key_cache(args.wxid.as_deref()).await);
    // 5. 临时目录可写 (定位表 / 缓存落这)。
    checks.push(check_temp_writable());
    // 5.5 L1 库 schema 版本 (给 --l1-db 才查) —— **换版本后最该查的一项**。
    if let Some(db) = args.l1_db.as_deref() {
        checks.push(check_l1_schema(db));
    }
    // 6. ffmpeg (可选: 语音转 mp3 / 图片 wxgf 转码)。
    checks.push(match native_core::media::resolve_ffmpeg(None) {
        Some(p) => (CheckLevel::Pass, "ffmpeg", format!("找到 {}", p.display())),
        None => (
            CheckLevel::Warn,
            "ffmpeg",
            "未找到 (语音转 mp3 / 图片 wxgf 转码不可用; 装 ffmpeg 或设 WECHAT_FFMPEG, 可选)".into(),
        ),
    });

    let (mut n_pass, mut n_warn, mut n_fail) = (0u32, 0u32, 0u32);
    for (level, name, detail) in &checks {
        println!("  {} {name:<12} {detail}", level.icon());
        match level {
            CheckLevel::Pass => n_pass += 1,
            CheckLevel::Warn => n_warn += 1,
            CheckLevel::Fail => n_fail += 1,
        }
    }
    eprintln!(
        "\n结果: {n_pass} 通过 / {n_warn} 警告 / {n_fail} 失败 → {}",
        if n_fail > 0 {
            "环境未就绪 (先修 🛑 项)"
        } else {
            "环境就绪"
        }
    );
    if n_fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// 检查微信数据目录可达 + 至少一个账号目录 (wxid_*)。
fn check_wechat_dir(explicit: Option<&str>) -> (CheckLevel, &'static str, String) {
    let dir = match explicit {
        Some(d) => PathBuf::from(d),
        None => match default_wechat_data_dir() {
            Ok(d) => d,
            Err(_) => {
                return (
                    CheckLevel::Fail,
                    "微信数据目录",
                    "没探测到 xwechat_files — 用 --wechat-data-dir 指定".into(),
                )
            }
        },
    };
    let accounts = detect_account_wxids(&dir);
    if accounts.is_empty() {
        (
            CheckLevel::Fail,
            "微信数据目录",
            format!("{} 下没有账号目录 (wxid_*) — 确认微信装过 + 路径对", dir.display()),
        )
    } else {
        (
            CheckLevel::Pass,
            "微信数据目录",
            format!("{} (检测到 {} 个账号)", dir.display(), accounts.len()),
        )
    }
}

/// 检查已建好的 L1 库跟当前二进制的 schema 版本配不配 (给 `--l1-db` 才跑)。
///
/// **为什么要有这一项**: schema 版本不匹配时, **每一条读命令**都返 `SCHEMA_MISMATCH` —— 不只是
/// `ingest`, 连 `contacts` / `sessions` / `search` 都查不了, 而库只能删掉从加密源全量重建
/// (导过聊天记录的话就是几小时 + 几十 GB 重来)。而在这一项之前, doctor **完全看不到 L1 库**,
/// 换版本后跑 doctor 会报「环境就绪」, 用户在第一条查询才撞墙。快速开始文档的「换新版本」
/// 一节原本就让人跑 doctor 验证 —— 那步等于没验。(审查方逮到的。)
///
/// 只读打开, 绝不建库、绝不写 (doctor 是自检不是修复)。
fn check_l1_schema(path: &str) -> (CheckLevel, &'static str, String) {
    const NAME: &str = "L1 库 schema";
    let p = Path::new(path);
    if !p.is_file() {
        // **判 Fail 不判 Warn**。我最初写的是 Warn("路径不对 ≠ 库坏了, 用户可能只是敲错"),
        // 审查方一句话打穿: ⚠️ 不进失败计数 ⇒ 整体仍报「环境就绪」+ 退出码 0。而这条检查
        // 正是「换新版本后确认旧库还能不能用」的唯一手段 —— 用户少打一个字母就拿到绿灯,
        // 然后拿一个可能已经作废的库继续用。**用户明确点名要查某个文件, 没找到 = 没查成,
        // 不能算通过。** 目录也走这条 (is_file 为假), 提示里一并说清。
        let what = if p.is_dir() {
            "是个目录, 不是文件"
        } else {
            "找不到"
        };
        return (
            CheckLevel::Fail,
            NAME,
            format!("{what}: {path} — 这一项没查成(不是查过了没问题); 路径写对了吗?"),
        );
    }
    // 只读开: 不存在也不建空库 (open_readonly 的契约)。
    let conn = match native_core::storage::open_readonly(p) {
        Ok(c) => c,
        Err(e) => return (CheckLevel::Fail, NAME, format!("打不开 (不是 sqlite / 已损坏?): {e}")),
    };
    // **SQLite 打开是惰性的** —— 上面那个 open 连纯文本文件都会"成功", 要到第一次真读才报错。
    // 所以必须显式探一下: 不探的话上面那个 Fail 分支**永远走不到**, 而一个乱七八糟的文件会掉进
    // 最后那个"读不到版本号"的 Warn, 报成"可能是很老的 L1 库" —— 把"根本不是数据库"说成
    // "版本旧", 指错方向。(拿一个内容为 "not a database at all" 的 .db 实测出来的。)
    if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)) {
        return (
            CheckLevel::Fail,
            NAME,
            format!("不是能用的 sqlite 库 (文件损坏 / 根本不是数据库): {e}"),
        );
    }
    // key 名走 native-core 的常量, **不硬编码字符串** —— 我第一版写的是 'schema_version',
    // 真库里其实叫 'version'(exec 查出来的), 硬编码会静默变成"永远读不到版本号"→ 恒 Warn。
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            [native_core::storage::META_KEY_VERSION],
            |r| r.get(0),
        )
        .ok();
    match stored.as_deref() {
        Some(v) if v == native_core::storage::SCHEMA_VERSION => {
            (CheckLevel::Pass, NAME, format!("版本 {v}, 跟本程序一致 — 可以接着用"))
        }
        Some(v) => (
            CheckLevel::Fail,
            NAME,
            format!(
                "版本 {v}, 本程序要 {} — 这个库用不了了: 每条查询都会报 SCHEMA_MISMATCH。\
                 只能删掉它重跑一次 ingest 全量重建 (密钥缓存不受影响, 不用重新 auth)",
                native_core::storage::SCHEMA_VERSION
            ),
        ),
        // 没有版本行。**判据必须跟写侧 (storage.rs 的 init 门禁) 一致**: 那边是
        // `is_fresh = stored.is_none() && !has_msg_table` —— 无版本行**且**无 message 表才算
        // "空白新库", 否则一律拒。doctor 原先只实现了 `Some(v) != VERSION` 那一半, 于是
        // "有 message 表、无版本行"的**旧库**落进 Warn ⇒ 总评「环境就绪」⇒ 退出码 0,
        // 而用户接着 ingest 会被硬拒 SCHEMA_MISMATCH、查询报 NEEDS_INGEST。
        // **doctor 的放行集合比 ingest 宽 = 体检说行、真用不行**, 正是「换新版本」那节要防的事。
        // (五轮审查逮到。同型: doctor 找 wx_key 的候选也曾跟真加载器不一致。)
        None => {
            let has_msg: bool = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='message'",
                    [],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if has_msg {
                (
                    CheckLevel::Fail,
                    NAME,
                    format!(
                        "有数据但读不到版本号 — 是旧版本建的库, 本程序要 {}。这个库用不了了: \
                         查询会报 NEEDS_INGEST、ingest 会被拒。只能删掉重跑一次 ingest 全量重建",
                        native_core::storage::SCHEMA_VERSION
                    ),
                )
            } else {
                (
                    CheckLevel::Warn,
                    NAME,
                    "空库 / 读不到版本号 — 还没 ingest 过, 或者这不是本程序建的库。跑一次 ingest 就好".into(),
                )
            }
        }
    }
}

/// 检查 vendored wx_key.dll 存在 (auth hook 取 key 依赖; 候选跟 ciphertalk 加载回退一致)。
fn check_wx_key_dll() -> (CheckLevel, &'static str, String) {
    let mut cands: Vec<PathBuf> = vec![PathBuf::from("vendor/wx_key/wx_key.dll"), PathBuf::from("wx_key.dll")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            cands.push(dir.join("wx_key.dll"));
            cands.push(dir.join("vendor").join("wx_key").join("wx_key.dll"));
        }
    }
    match cands.iter().find(|p| p.is_file()) {
        Some(p) => (CheckLevel::Pass, "wx_key.dll", format!("找到 {}", p.display())),
        None => (
            // Warn 而非 Fail: 这个 dll 只服务 `auth`(不带 --scan)那条 hook 路;
            // 默认推荐的 `auth --scan` 走 native-keyscan 纯 Rust, 压根不加载它
            // (见 native-keyscan crate 头: "不碰 wcdb_api.dll / electron / Python")。
            //
            // ⚠️ 这里原先写的是「auth 取新账号 key 会失败 … 打包版应含此 dll, 缺了查杀软 / 重新解压」
            //    —— 两句都不对, 而且会把人引去追一个不存在的问题:
            //    ① `auth --scan` 不需要它, 说"会失败"是错的(精简包里没有这个 dll, --scan 实测取到 key);
            //    ② 发布包**故意不带**它(见包内清单.md), 所以"缺了查杀软 / 重新解压"是让人白折腾。
            CheckLevel::Warn,
            "wx_key.dll",
            "没找到 — 不影响默认路径 (auth --scan 走纯 Rust 内存扫, 不需要它); 只有不带 --scan 的 auth 回退路要它。发布包故意不带, 这条 warn 属正常"
                .into(),
        ),
    }
}

/// 检查 key 缓存 (给 --wxid 才查; cache 命中 = 已对该账号 auth 过)。
/// 提示里回显用户自己给的 `--wxid` 明文 (用户输入, 非从库挖; 可照做 auth 命令)。
async fn check_key_cache(wxid: Option<&str>) -> (CheckLevel, &'static str, String) {
    let Some(w) = wxid else {
        return (
            CheckLevel::Warn,
            "key 缓存",
            "未给 --wxid, 跳过 (给 --wxid <你的 wxid> 可查 key 是否已缓存)".into(),
        );
    };
    let Ok(parsed) = w.parse::<Wxid>() else {
        return (
            CheckLevel::Fail,
            "key 缓存",
            format!("--wxid {w} 非法 (须合法微信 wxid)"),
        );
    };
    match cache_key(&parsed).await {
        Ok(_) => (CheckLevel::Pass, "key 缓存", format!("{w} 的 key 已缓存")),
        Err(_) => (
            CheckLevel::Warn,
            "key 缓存",
            format!("{w} 未缓存 — 跑 `msgvestige auth --wxid {w}` 取一次"),
        ),
    }
}

/// 检查系统临时目录可写 (定位表 / 缓存落这)。
fn check_temp_writable() -> (CheckLevel, &'static str, String) {
    let probe = std::env::temp_dir().join("msgvestige-doctor-probe.tmp");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            (
                CheckLevel::Pass,
                "临时目录可写",
                std::env::temp_dir().display().to_string(),
            )
        }
        Err(e) => (
            CheckLevel::Fail,
            "临时目录可写",
            format!("写失败: {e} (检查磁盘 / 权限)"),
        ),
    }
}

// QueryTarget (冷查共享查询目标; 派生 clap::Args 供 flatten) 已移至 native-query::target (§6②);
// 经上方 `use native_query::QueryTarget` 引入, 各命令 `#[command(flatten)] target: QueryTarget` 不变。

#[derive(Args)]
struct ContactsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 关键词过滤 (在 昵称 / 备注 / 微信号 / wxid 里子串匹配)。
    #[arg(short = 'q', long)]
    query: Option<String>,
    /// 本页条数 (冷查 keyset 分页用 --cursor 续翻; 热查用 --offset)。
    #[arg(short = 'n', long, default_value_t = 50)]
    limit: usize,
    /// 续翻游标 (冷查专用; 上一页 meta.next_cursor 原样回传; 换账号/换 -q 的旧游标失效 → INVALID_CURSOR)。
    #[arg(long)]
    cursor: Option<String>,
    // 【设计理由走 // 不走 ///】—— /// 的**每一段**都会被 clap 打进用户的 `--help`(多段时进 long_help,
    // `help=` 只盖短 help 盖不住它 —— codex 审 P3 逮到, 我原以为 help= 就够了)。故: /// 只写用户话,
    // 理由写这里。机器扫由 subcommand_help_has_no_internal_narrative 兜底。
    //
    // 热查走 offset 而非 keyset 游标: 源库单表内 username 唯一, 不需要冷查那套跨 source 的复合游标。
    // 没有本参数时热查是死胡同 —— 返 has_more=true 却无路可翻, 只能 --limit 99999 全量灌内存。
    /// 跳过前 N 条 (实时查翻页用; 冷查请用 --cursor)。
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct MembersArgs {
    /// 群 id (形如 `xxxx@chatroom`)。
    chatroom: String,
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 只列群主 / 管理员。
    #[arg(long)]
    admins_only: bool,
    /// 最多列几个 (默认 1000; 大群防全量载入 —— 与核 `members_query` 的 SQL LIMIT 对齐)。
    #[arg(long, default_value_t = 1000)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃 —— 冷查 members_query 本就收 offset, 热查同口径)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `contacts` — 查 / 搜联系人 (读 L1 person 表; **keyset 游标分页**, 只读)。查数+游标+json+meta 在核
/// `contacts_query` (排序键 username 唯一→tiebreaker; `-q` 子串过滤; 游标绑库路径指纹+过滤指纹; 换库/换 `-q`
/// 旧游标 decode 不过 → INVALID_CURSOR 携码原样上抛→退出 2), 此薄壳只呈现。table 的 display 优选
/// (备注→昵称→占位) 是纯 table 装饰, 逐行读**核 json**; 游标绑的 `acct` 位在核算 (sha8(L1 路径), ③b 前占位)。
///
/// **R16-1**: 冷查分支抽出 —— 走 scoped L1 → `contacts_query` (keyset 游标) → 挂 freshness。
/// 缺 `--l1-db` → `require_l1_db` 报错**不静默转热** (R6 语义: 用户要冷查却偷偷碰微信库 = 最小意外违背)。
fn cli_cold_contacts(args: &ContactsArgs) -> Result<native_query::QueryResult> {
    let conn = open_l1_resolved(&args.target)?;
    let l1 = args.target.require_l1_db()?;
    let mut r = native_query::contacts_query(
        &conn,
        l1,
        args.target.account_sha().as_deref(),
        args.query.as_deref(),
        args.limit,
        args.cursor.as_deref(),
    )?;
    if let Some(f) = native_query::cold_freshness(l1, args.target.account_sha().as_deref()) {
        r.meta = r.meta.with_freshness(f);
    }
    Ok(r)
}

/// `contacts` — 查/搜联系人。**R16-1 起冷热双模式** (`--mode hot` 默认直读加密 contact.db, 合并
/// contact+stranger 两表; `--mode cold` 读 L1 person 走 keyset 游标)。
async fn cmd_contacts(args: &ContactsArgs) -> Result<()> {
    // R16-1: 冷热派发 (照 cmd_sessions 模板)。hot 需 --wxid; cold 需 --l1-db (缺则各自报错, 不静默转对面)。
    //
    // 夹上界在**派发之前**算一次、冷热共用 —— 照 cmd_sessions。写在热分支里面的话冷分支就漏
    // (对抗审 P3-3 真跑逮到 favorites/friend-requests: 冷查 `offset as i64` 遇 usize::MAX 回绕成 -1,
    //  SQLite 把负 OFFSET 当 0 → **返回第一页**, 还理直气壮报 offset=18446744073709551615)。
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            // 热查走 offset (冷查是 keyset 游标) —— 数据行字段一致, 翻页机制不同, 已在 hot_contacts 标注。
            // 给了 --cursor 却要热查 = 参数组合矛盾, 显式拒 (别静默忽略用户的翻页意图)。
            if args.cursor.is_some() {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "--cursor 是冷查的 keyset 游标; 热查请用 --offset 翻页 (或加 --mode cold --l1-db <库> 走冷查)"
                        .to_string(),
                ));
            }
            native_query::hot_contacts(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                args.query.as_deref(),
                args.limit,
                offset,
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            // 对抗审 P2-1 (真跑逮到, HEAD 上活着): 冷查是 keyset 游标, `cli_cold_contacts` **从头到尾
            // 不读 args.offset** —— `contacts --mode cold --offset 40000` 静默返回**第一页**且 exit 0,
            // meta 里 has_more 恒 true、offset 缺席 → 按 `offset += limit` while has_more 翻页的
            // 客户端/AI **永远拿第一页、永不终止**。
            //
            // 而**镜像守卫就在上面 10 行**(--cursor + hot → 拒, 注释还写着"别静默忽略用户的翻页意图")
            // —— 反过来的 --offset + cold 却没人管。这是同一模式的第 5 次: 修了被点名的, 漏了旁边对称的。
            if args.offset != 0 {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "--offset 是实时查的翻页方式; 冷查请用 --cursor 续翻 (把上一页 meta.next_cursor 原样回传), \
                     或加 --mode hot --wxid <账号> 走实时查"
                        .to_string(),
                ));
            }
            cli_cold_contacts(args)?
        }
    };
    match args.format {
        OutFormat::Table => {
            eprintln!(
                "联系人 (本页 {} 个{}):",
                r.data.len(),
                if r.meta.has_more { ", 还有下页" } else { "" }
            );
            for row in &r.data {
                let username = row["username"].as_str().unwrap_or_default();
                let nick = row["nick_name"].as_str();
                let remark = row["remark"].as_str();
                let alias = row["alias"].as_str().unwrap_or_default();
                let display = remark
                    .filter(|s| !s.is_empty())
                    .or_else(|| nick.filter(|s| !s.is_empty()))
                    .unwrap_or("(无昵称/备注)");
                println!("{display}  [{username}]  {alias}");
            }
            if let Some(nc) = &r.meta.next_cursor {
                eprintln!("下一页: --cursor {nc}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// **R16-1**: members 冷查分支 —— scoped L1 → `members_query` → 挂 freshness。
/// 缺 `--l1-db` → `require_l1_db` 报错**不静默转热** (R6 语义)。
fn cli_cold_members(args: &MembersArgs, offset: usize) -> Result<native_query::QueryResult> {
    let conn = open_l1_resolved(&args.target)?;
    let mut r = native_query::members_query(&conn, &args.chatroom, args.admins_only, args.limit, offset)
        .context("查 chatroom_member 表失败")?;
    if let Some(f) = native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref()) {
        r.meta = r.meta.with_freshness(f);
    }
    Ok(r)
}

/// `members` — 查群成员。**R16-1 起冷热双模式 (降级件)**: `--mode hot` 直读加密 `contact.db` 的
/// `chat_room` 行 (解 ext_buffer proto 展开成员, 5 字段对齐冷查); `--mode cold` 读 L1 chatroom_member 表。
/// 查数+json+meta 在核, 此薄壳只呈现。table `tag` (owner/admin/member → 群主/管理/成员) 是纯 table 装饰,
/// 读**核 json** 的 role。
///
/// **热查明说降级** (决策②): `joined_at` 恒 null (源库 proto 无入群时刻); **已退群成员不返回** (源库那一行
/// 只存当前在群成员); summary 里 `partial:true`+`degraded` 说明串会打给调用方 —— table 模式额外印一行降级提示。
async fn cmd_members(args: &MembersArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let is_hot = matches!(args.target.effective_mode(), native_query::EffectiveMode::Hot);
    let r = if is_hot {
        let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
        native_query::hot_members(
            &wxid,
            args.target.wechat_data_dir.as_deref(),
            &args.chatroom,
            args.admins_only,
            args.limit,
            offset,
        )
        .await?
    } else {
        cli_cold_members(args, offset)?
    };
    match args.format {
        OutFormat::Table => {
            // R16-1: 走 table_total (热查 total 在 summary; 冷查在 total_count) —— 两皮都能读到真数。
            let total = table_total(&r.meta, "total_members");
            match total {
                Some(t) => eprintln!(
                    "群 {} 成员 {t} 人{}:",
                    args.chatroom,
                    if args.admins_only { " (仅群主/管理员)" } else { "" }
                ),
                None => eprintln!("群 {} 成员 (总数未知; 本页 {} 人):", args.chatroom, r.data.len()),
            }
            if is_hot {
                eprintln!("  [降级] joined_at 显示为空 (源库无此字段); 已退群成员不在列 (仅当前在群快照)");
            }
            for row in &r.data {
                let wxid = row["member_wxid"].as_str().unwrap_or_default();
                let display = row["display_name"].as_str().unwrap_or("");
                let tag = match row["role"].as_str().unwrap_or_default() {
                    "owner" => "群主",
                    "admin" => "管理",
                    _ => "成员",
                };
                println!("{tag}  {wxid}  {display}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct FavoritesArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 关键词过滤 (在 来源人 / 会话名 里子串匹配)。
    #[arg(short = 'q', long)]
    query: Option<String>,
    /// 只看收藏标签明细 (标签名 + 所属收藏; 覆盖 -q, 走 favorite_tag)。
    // Claude fav_media P3-4: 与 --media 互斥 (clap 报错), 免"同给时哪个优先"的静默行为(旧 tags 先/新 media 先)。
    #[arg(long, conflicts_with = "media")]
    tags: bool,
    /// 只看收藏媒体明细 (类型/md5/大小/格式; 覆盖 -q, 走 favorite_media)。
    #[arg(long)]
    media: bool,
    /// 最多列几个。
    #[arg(short = 'n', long, default_value_t = 50)]
    limit: usize,
    // 补 P2-1 的漏网: 审只点了 contacts, 我就只给 contacts 加 —— 而 favorites 热查同样返 has_more=true
    // 却无路可翻(cmd_favorites 里 offset 硬编码 0)。判据是"哪些命令有这毛病", 不是"审点了哪个"。
    // (理由写 // 不写 ///: /// 会被 clap 打进用户 --help。)
    /// 跳过前 N 条 (翻页用; 主表与 --tags / --media 子视图都支持)。
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct MomentsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 只看朋友圈点赞评论 (赞/评 + 互动者 + 评论内容; 走 moment_interaction)。
    #[arg(long)]
    interactions: bool,
    /// 只看好友朋友圈索引 (作者/时间/已读; 走 moment_feed)。
    #[arg(long)]
    feed: bool,
    /// 只看朋友圈互动通知 (通知类型/谁/内容; 走 sns_notify)。
    #[arg(long)]
    inbox: bool,
    /// 最多列几条。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 主表冷热都吃; 子视图暂只出第一页)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct AccountArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// **R16-1**: favorites 冷查分支 —— scoped L1 → `favorites_query` → 挂 freshness。
/// 缺 `--l1-db` → `require_l1_db` 报错**不静默转热**。
fn cli_cold_favorites(args: &FavoritesArgs, offset: usize) -> Result<native_query::QueryResult> {
    let conn = open_l1_resolved(&args.target)?;
    let mut r = native_query::favorites_query(&conn, args.query.as_deref(), args.limit, offset)
        .context("查 favorite 表失败")?;
    if let Some(f) = native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref()) {
        r.meta = r.meta.with_freshness(f);
    }
    Ok(r)
}

/// `favorites` — 查收藏。**R16-1 起冷热双模式**: `--mode hot` 直读加密 `favorite.db` 的 `fav_db_item`
/// (零解码, 6 字段对齐冷查); `--mode cold` 读 L1 favorite 表。查数+json+meta 在核, 此薄壳只呈现。
/// 乙: `--tags` / `--media` 子视图折进本命令 → 走查询引擎的 favorite_tag / favorite_media (guards 留皮)。
///
/// **子视图仍是冷查独占** (R16-3 才补它们的热查): `--tags`/`--media` 背的是**独立派生表**
/// (favorite_tag / favorite_media), 不是本命令主表 —— 热查这两个属对抗审 P2-1 点名的"子视图独立解码"。
async fn cmd_favorites(args: &FavoritesArgs) -> Result<()> {
    // **--media (favorite_media, R16-3): 冷热双模 + offset** —— 热走 hot_favorite_media 直读 favorite.db fav_db_item
    // (笔记 type=18 content) 逐收藏 parse_note_media 抽媒体 (一对多)。
    if args.media {
        let offset = args.offset.min(10_000_000);
        return match args.target.effective_mode() {
            native_query::EffectiveMode::Cold => emit_engine_query_at(
                &native_query::CMD_FAV_MEDIA,
                &args.target,
                args.limit,
                offset,
                args.format,
            ),
            native_query::EffectiveMode::Hot => {
                let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
                let r =
                    native_query::hot_favorite_media(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset)
                        .await?;
                match args.format {
                    OutFormat::Table => {
                        match table_total(&r.meta, "total_fav_media") {
                            Some(t) => eprintln!("收藏媒体 {t} 条 (取前 {}):", args.limit),
                            None => eprintln!("收藏媒体 (本页 {} 条):", r.data.len()),
                        }
                        for row in &r.data {
                            let fsid = row["fav_server_id"].as_i64().unwrap_or_default();
                            let seq = row["seq"].as_i64().unwrap_or_default();
                            // 冷查引擎 table 走 Fmt::EnumI64(2图/6文件/8HTML); 热 table 同映射 (JSON 出原始 i64)。
                            // codex fav_media P2: **未映射值出原始数字**(同冷查 EnumI64 的 map_or_else→c.to_string),
                            // 不打 "?"(真库有 3/4 等未映射类型, 打 "?" 会丢信息且与冷查 table 分叉)。
                            let dt = match row["data_type"].as_i64().unwrap_or_default() {
                                2 => "图".to_string(),
                                6 => "文件".to_string(),
                                8 => "HTML".to_string(),
                                n => n.to_string(),
                            };
                            let md5 = row["media_md5"].as_str().unwrap_or_default();
                            let size = row["media_size"].as_i64().unwrap_or_default();
                            let fmt = row["data_fmt"].as_str().unwrap_or_default();
                            // media_size 出 `{n}B` 对齐冷查 Fmt::Bytes(Claude P3-2: 原 `字节` 与冷表分叉)。
                            println!("收藏#{fsid} 媒体{seq}  {dt}  {md5}  {size}B  {fmt}");
                        }
                        Ok(())
                    }
                    OutFormat::Json => emit_envelope(&r.data, r.meta),
                }
            }
        };
    }
    // --tags (favorite_tag) 仍冷查专用 (R16-3 fav_tags 件补热查 + offset); offset 暂显式拒 (不静默吞)。
    // **--tags (favorite_tag, R16-3): 冷热双模 + offset** —— 热走 hot_favorite_tags 直读 favorite.db
    // fav_bind_tag_db_item ⋈ fav_tag_db_item, 按 anchor 去重 (同冷 L2 upsert)。
    if args.tags {
        let offset = args.offset.min(10_000_000);
        return match args.target.effective_mode() {
            native_query::EffectiveMode::Cold => emit_engine_query_at(
                &native_query::CMD_FAV_TAGS,
                &args.target,
                args.limit,
                offset,
                args.format,
            ),
            native_query::EffectiveMode::Hot => {
                let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
                let r =
                    native_query::hot_favorite_tags(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset)
                        .await?;
                match args.format {
                    OutFormat::Table => {
                        match table_total(&r.meta, "total_fav_tags") {
                            Some(t) => eprintln!("收藏标签 {t} 条 (取前 {}):", args.limit),
                            None => eprintln!("收藏标签 (本页 {} 条):", r.data.len()),
                        }
                        for row in &r.data {
                            let tsid = row["tag_server_id"].as_i64().unwrap_or_default();
                            let fsid = row["fav_server_id"].as_i64().unwrap_or_default();
                            let name = row["tag_name"].as_str().unwrap_or_default();
                            println!("标签#{tsid} 「{name}」→ 收藏#{fsid}");
                        }
                        Ok(())
                    }
                    OutFormat::Json => emit_envelope(&r.data, r.meta),
                }
            }
        };
    }
    // R16-1: 主表冷热派发 (照 cmd_contacts 模板)。夹上界在**派发前**算一次冷热共用 (审 P3-3: 原先写在
    // 热分支里, 冷查漏夹 → `offset as i64` 遇 usize::MAX 回绕 -1 → SQLite 当 0 → 返回第一页)。
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            native_query::hot_favorites(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                args.query.as_deref(),
                args.limit,
                offset,
            )
            .await?
        }
        native_query::EffectiveMode::Cold => cli_cold_favorites(args, offset)?,
    };
    match args.format {
        OutFormat::Table => {
            // R16-1: 走 table_total —— 热查的 total 在 summary 里, 直接读 meta.total_count 恒是 None → 打 "0 条"。
            match table_total(&r.meta, "total_favorites") {
                Some(t) => eprintln!("收藏 {t} 条 (取前 {}):", args.limit),
                None => eprintln!("收藏 (总数未知; 本页 {} 条):", r.data.len()),
            }
            for row in &r.data {
                let sid = row["server_id"].as_i64().unwrap_or_default();
                let ftype = row["fav_type"].as_i64().unwrap_or_default();
                let utime = row["update_time"].as_i64().unwrap_or_default();
                let clen = row["content_len"].as_i64().unwrap_or_default();
                let who = row["from_user"]
                    .as_str()
                    .or_else(|| row["real_chat_name"].as_str())
                    .unwrap_or("?");
                println!("[{utime}] type{ftype}  {who}  内容{clen}字节 (id={sid})");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// `moments` — 查朋友圈动态 (读 L1 moment 表; 只读)。查数+json+meta 在核 `moments_query`, 此薄壳只呈现。
/// 乙: `--interactions` / `--feed` / `--inbox` 子视图折进本命令 → moment_interaction / moment_feed / sns_notify (走引擎)。
/// table who (昵称空退回 author) + preview (截断) 装饰留皮, 读**核已组好的 json** 字段。
async fn cmd_moments(args: &MomentsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    // 子视图 feed/inbox 仍冷查专用(好友feed/通知无热查对应, 分属 R16-5/后续)。
    // **interactions (R16-3): 冷热双模** —— 热走 hot_interactions 直读 sns.db SnsTimeLine 逐动态 parse_sns_interactions。
    if args.interactions {
        return match args.target.effective_mode() {
            native_query::EffectiveMode::Cold => emit_engine_query_at(
                &native_query::CMD_INTERACTIONS,
                &args.target,
                args.limit,
                offset,
                args.format,
            ),
            native_query::EffectiveMode::Hot => {
                let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
                let r =
                    native_query::hot_interactions(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset)
                        .await?;
                match args.format {
                    OutFormat::Table => {
                        match table_total(&r.meta, "total_interactions") {
                            Some(t) => eprintln!("朋友圈点赞评论 {t} 条 (取前 {}):", args.limit),
                            None => eprintln!("朋友圈点赞评论 (本页 {} 条):", r.data.len()),
                        }
                        for row in &r.data {
                            let ct = row["create_time"].as_i64().unwrap_or_default();
                            // 冷查引擎 table 走 Fmt::EnumStr(like→赞/comment→评论); 热 table 同映射对齐 (JSON 出原始)。
                            let kind = match row["kind"].as_str().unwrap_or_default() {
                                "like" => "赞",
                                "comment" => "评论",
                                other => other,
                            };
                            let nick = row["from_nickname"].as_str().unwrap_or_default();
                            let from = row["from_user"].as_str().unwrap_or_default();
                            let content = row["content"].as_str().unwrap_or_default();
                            println!("[{ct}] {kind}  {nick} ({from}): {content}");
                        }
                        Ok(())
                    }
                    OutFormat::Json => emit_envelope(&r.data, r.meta),
                }
            }
        };
    }
    if args.feed {
        return emit_engine_query_at(
            &native_query::CMD_MOMENT_FEED,
            &args.target,
            args.limit,
            offset,
            args.format,
        );
    }
    // **inbox (sns_notify, R16-3): 冷热双模** —— 热走 hot_sns_notify 直读 sns.db SnsMessage_tmp3 (一通知一行)。
    if args.inbox {
        return match args.target.effective_mode() {
            native_query::EffectiveMode::Cold => emit_engine_query_at(
                &native_query::CMD_SNS_NOTIFY,
                &args.target,
                args.limit,
                offset,
                args.format,
            ),
            native_query::EffectiveMode::Hot => {
                let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
                let r = native_query::hot_sns_notify(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset)
                    .await?;
                match args.format {
                    OutFormat::Table => {
                        match table_total(&r.meta, "total_sns_notify") {
                            Some(t) => eprintln!("朋友圈互动通知 {t} 条 (取前 {}):", args.limit),
                            None => eprintln!("朋友圈互动通知 (本页 {} 条):", r.data.len()),
                        }
                        for row in &r.data {
                            let ct = row["create_time"].as_i64().unwrap_or_default();
                            let nt = row["notify_type"].as_i64().unwrap_or_default();
                            let nick = row["from_nickname"].as_str().unwrap_or_default();
                            let from = row["from_user"].as_str().unwrap_or_default();
                            let content = row["content"].as_str().unwrap_or_default();
                            println!("[{ct}] type{nt}  {nick} ({from}): {content}");
                        }
                        Ok(())
                    }
                    OutFormat::Json => emit_envelope(&r.data, r.meta),
                }
            }
        };
    }
    // 主表 moments: **R16-1 起冷热双模式**。热查直读加密 sns.db 的 SnsTimeLine(复用 assemble_sns), 7 键对齐冷查。
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            native_query::hot_moments(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset).await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::moments_query(&conn, args.limit, offset)
                .context("查 moment 表失败")
                .map_err(|e| needs_ingest_err(e, "先跑 `msgvestige ingest --sns` 导入朋友圈表"))?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            match table_total(&r.meta, "total_moments") {
                Some(t) => eprintln!("朋友圈动态 {t} 条 (取前 {}):", args.limit),
                None => eprintln!("朋友圈动态 (本页 {} 条):", r.data.len()),
            }
            for row in &r.data {
                let author = row["author"].as_str().unwrap_or_default();
                let ctime = row["create_time"].as_i64().unwrap_or_default();
                let desc = row["content_desc"].as_str().unwrap_or_default();
                let media = row["media_count"].as_i64().unwrap_or_default();
                let likes = row["like_count"].as_i64().unwrap_or_default();
                let comments = row["comment_count"].as_i64().unwrap_or_default();
                let who = row["author_nickname"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(author);
                let preview: String = desc.chars().take(50).collect::<String>().replace('\n', " ");
                println!("[{ctime}] {who}: {preview}  (媒体{media}/赞{likes}/评{comments})");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// `account` — 当前账号信息 (读 L1 各表行数统计; 只读)。账号 id 是用户自己的, 合理出口。**薄壳**:
/// 查数/json/meta 在核 [`native_query::account_query`] (data=[单汇总行], Meta::page(1,1)+cold), 此壳只呈现。
async fn cmd_account(args: &AccountArgs) -> Result<()> {
    // R16-6 双模: 冷 account_query 读 L1 各表 count; 热 hot_account 聚合源库计数(messages 需全扫, 较慢)。
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            native_query::account_query(&conn).context("查账号统计失败")?
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, 0).await?; // R21 全扫成本门 (account 不分页)
            native_query::hot_account(&wxid, args.target.wechat_data_dir.as_deref(), None, None)
                .await
                .context("实时账号统计失败 (账号 key 缓存了? 数据目录对? messages 全扫较慢)")?
        }
    };
    match args.format {
        OutFormat::Table => {
            let row = &r.data[0]; // account_query 恒返单行。
            eprintln!("账号: {}", row["account_id"].as_str().unwrap_or("(空库?)"));
            // Claude R16-6 P2: 热降级标(messages_approximate/sources_unavailable)暴露到**默认 table** 输出(仿 members
            // 的 `[降级]` 行), 否则只在 --format json 可见, 人读默认视图会把偏低的消息数当准数。
            if let Some(s) = r.meta.summary.as_ref() {
                if s.get("partial").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                    let mut notes: Vec<String> = Vec::new();
                    if s.get("messages_approximate")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                    {
                        notes.push("消息计数偏低 (源库分片瞬态截断/损坏未扫全)".to_string());
                    }
                    if let Some(un) = s.get("sources_unavailable").and_then(serde_json::Value::as_array) {
                        let names: Vec<&str> = un.iter().filter_map(serde_json::Value::as_str).collect();
                        if !names.is_empty() {
                            notes.push(format!("源不可用记 0: {}", names.join(",")));
                        }
                    }
                    eprintln!("  [降级] {}", notes.join("; "));
                }
            }
            println!(
                "联系人 {} / 群 {} / 消息 {} / 朋友圈 {} / 收藏 {}",
                row["persons"].as_i64().unwrap_or(0),
                row["chatrooms"].as_i64().unwrap_or(0),
                row["messages"].as_i64().unwrap_or(0),
                row["moments"].as_i64().unwrap_or(0),
                row["favorites"].as_i64().unwrap_or(0)
            );
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct CallsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct LocationsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct CardsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct MediaArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct GroupEventsArgs {
    /// 查询目标 (L1 库 / 实时查微信库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页)。
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct EmoticonsArgs {
    /// 查询目标 (L1 库 / 实时查微信库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct AvatarsArgs {
    /// 查询目标 (L1 库 / 实时查微信库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按更新时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷查引擎只出第一页, 翻页用 --mode hot)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用; 冷查只出第一页)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct BizContactsArgs {
    /// 查询目标 (L1 库 / 实时查微信库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条。
    #[arg(short = 'n', long, default_value_t = 50)]
    limit: usize,
    /// 跳过前 N 条 (翻页)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct ChatroomsArgs {
    /// 查询目标 (L1 库 / 实时查微信库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按成员数倒序)。
    #[arg(short = 'n', long, default_value_t = 50)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷查引擎只出第一页, 翻页用 --mode hot)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用; 冷查只出第一页)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct FriendRequestsArgs {
    /// 查询目标 (L1 库 / 实时查微信库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 50)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃 —— 冷查 `friend_requests_query` 本就收 offset, 热查同口径)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Args)]
struct MentionsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 只看被 @ 的某人 (子串匹配 mentioned_wxid; 填自己 wxid = 看"@我的消息")。
    #[arg(short = 'q', long)]
    query: Option<String>,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `calls` — 查通话记录 (type50 <voipmsg>; 只读)。查数+json+meta 在核, 此薄壳只呈现。
/// **R16-2 起冷热双模式**: `--mode hot` scan_all_messages 全局扫 msg50 + parse_voip(与冷查 project_message_call
/// 零漂移); `--mode cold` 读 L1 message_call ⋈ message。6 键对齐。table 走 table_total(热查 total 在 summary)。
async fn cmd_calls(args: &CallsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            native_query::hot_calls(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file: 用默认 (系统临时目录按 wxid 命名)
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::calls_query(&conn, args.limit, offset)
                .context("查 message_call 表失败")
                .map_err(|e| needs_ingest_err(e, "先 ingest 消息 (通话是 type50 消息派生的 message_call 表)"))?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            // R16-2: table_total(热查 total 在 summary.total_calls; 冷查在 meta.total_count)。
            let total = table_total(&r.meta, "total_calls").unwrap_or(0);
            eprintln!("通话记录 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let ctime = row["create_time"].as_i64().unwrap_or_default();
                let kind = row["kind"].as_str().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let dur = row["duration_sec"].as_i64().unwrap_or_default();
                let result = row["result"].as_str().unwrap_or_default();
                println!("[{ctime}] {kind} {conv}  时长{dur}s  {result}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

// ── 查询引擎命令薄壳 (§6② 后) ──
// 引擎本体 (Fmt/Col/QueryCommand/value_json/render_cell/REGISTRY/run_query/render_table + 15 CMD_*)
// 已移 native-query::engine。此处只留**皮层**: clap Args → 调 `run_query` 拿 QueryResult → 按 format 呈现。

/// 引擎命令统一出口: 调内核 `run_query` 拿 `QueryResult`, 按 `format` 呈现 (呈现留皮, §3)。
/// - **json**: `emit_envelope(data, meta)` —— meta 是内核已组好的 `Meta::page(..).with_source(Cold)`,
///   与旧 `print_query_json(&data, total)` 逐字节同。
/// - **table**: 表头 `label N 条 (取前 M):` 打 **stderr** (旧 `run_query` table 分支即 `eprintln!`),
///   数据行经 `render_table`(读 json data 按 `Fmt` 渲)打 stdout。`total` 取自 `meta.total_count`
///   (引擎恒走 `Meta::page` → 必有值; 空 data → render_table 空串 → 不打行, 同旧逐行 println)。
fn emit_engine_query(cmd: &QueryCommand, target: &QueryTarget, limit: usize, format: OutFormat) -> Result<()> {
    emit_engine_query_at(cmd, target, limit, 0, format)
}

/// [`emit_engine_query`] 带 offset 版 (**R16-1 审 P3-②**: 引擎 `run_query` 本就吃 offset, HTTP/MCP 冷查
/// 都翻页; CLI 冷查原先 emit_engine_query 写死 offset=0 + 拒 --offset → 三皮分叉。这里放开, CLI 冷查也翻页)。
fn emit_engine_query_at(
    cmd: &QueryCommand,
    target: &QueryTarget,
    limit: usize,
    offset: usize,
    format: OutFormat,
) -> Result<()> {
    let mut r = run_query(cmd, target, limit, offset)?;
    // R16-1: 引擎冷查也挂 freshness —— **判据是"所有冷查、三皮都该有 freshness"**, 不是"手写的才挂"。
    // `run_query`(engine.rs) 内部不挂; HTTP 的 cold_cmd 挂、MCP 冷查也挂 → CLI 这条不挂就三皮 meta 对不上。
    // 这修的是引擎命令**一整类**(locations/cards/media/emoticons/avatars/biz…)的 CLI 缺口, 不止 emoticon。
    if let Ok(l1) = target.require_l1_db() {
        if let Some(f) = native_query::cold_freshness(l1, target.account_sha().as_deref()) {
            r.meta = r.meta.with_freshness(f);
        }
    }
    match format {
        OutFormat::Table => {
            let total = r.meta.total_count.unwrap_or(0);
            eprintln!("{} {total} 条 (取前 {limit}):", cmd.label);
            print!("{}", render_table(cmd, &r.data));
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// `locations` — 查位置分享 (type48 `<location>`; 只读)。**R16-2 起冷热双模式**: `--mode hot` scan_all_messages
/// 全局扫 msg48 + parse_location; `--mode cold` 走查询引擎 `run_query(&CMD_LOCATIONS)` 读 L1 message_location。
/// 7 键对齐。table 走 table_total; lat/lng 用 `{:.5}` 匹配引擎 Fmt::Float(5)(纯 table 装饰, JSON 出原始 f64)。
async fn cmd_locations(args: &LocationsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => emit_engine_query_at(
            &native_query::CMD_LOCATIONS,
            &args.target,
            args.limit,
            offset,
            args.format,
        ),
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            let r = native_query::hot_locations(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_locations") {
                        Some(t) => eprintln!("位置分享 {t} 条 (取前 {}):", args.limit),
                        None => eprintln!("位置分享 (总数未知; 本页 {} 条):", r.data.len()),
                    }
                    for row in &r.data {
                        let ct = row["create_time"].as_i64().unwrap_or_default();
                        let conv = row["conv_id"].as_str().unwrap_or_default();
                        let lat = row["latitude"].as_f64().unwrap_or_default();
                        let lng = row["longitude"].as_f64().unwrap_or_default();
                        let poi = row["poiname"].as_str().unwrap_or_default();
                        // codex 6ba1ba2 P2: 补 label(地址串)—— 冷查引擎渲染全 7 列含 label, 热 table 别丢。
                        let label = row["label"].as_str().unwrap_or_default();
                        let city = row["cityname"].as_str().unwrap_or_default();
                        println!("[{ct}] {conv}  ({lat:.5},{lng:.5})  {poi}  {label}  {city}");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// `cards` — 查分享的名片 (**R16-2 registry 族**: 冷热双模; 冷走引擎, 热走 hot_cards scan msg42)。
async fn cmd_cards(args: &CardsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            emit_engine_query_at(&native_query::CMD_CARDS, &args.target, args.limit, offset, args.format)
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            let r = native_query::hot_cards(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_cards") {
                        Some(t) => eprintln!("名片 {t} 条 (取前 {}):", args.limit),
                        None => eprintln!("名片 (总数未知; 本页 {} 条):", r.data.len()),
                    }
                    for row in &r.data {
                        let ct = row["create_time"].as_i64().unwrap_or_default();
                        let conv = row["conv_id"].as_str().unwrap_or_default();
                        let nick = row["card_nickname"].as_str().unwrap_or_default();
                        let alias = row["card_alias"].as_str().unwrap_or_default();
                        let uname = row["card_username"].as_str().unwrap_or_default();
                        let company = row["company"].as_str().unwrap_or_default();
                        println!("[{ct}] {conv}  {nick} ({alias})  {uname}  {company}");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// `media` — 查媒体清单 (**R16-2 registry 族**: 冷热双模; 冷走引擎, 热走 hot_media scan msg[3/34/43/47])。
async fn cmd_media(args: &MediaArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            emit_engine_query_at(&native_query::CMD_MEDIA, &args.target, args.limit, offset, args.format)
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            let r = native_query::hot_media(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_media") {
                        Some(t) => eprintln!("媒体清单 {t} 条 (取前 {}):", args.limit),
                        None => eprintln!("媒体清单 (总数未知; 本页 {} 条):", r.data.len()),
                    }
                    for row in &r.data {
                        let ct = row["create_time"].as_i64().unwrap_or_default();
                        let conv = row["conv_id"].as_str().unwrap_or_default();
                        let kind = row["media_kind"].as_str().unwrap_or_default();
                        let md5 = row["md5"].as_str().unwrap_or_default();
                        let size = row["file_size"].as_i64().unwrap_or_default();
                        let play = row["play_length"].as_i64().unwrap_or_default();
                        // cdn_url 冷查 Fmt::Hidden 不上 table → 热 table 也不显 (对齐; json 两路都出)。
                        println!("[{ct}] {conv}  {kind}  md5={md5}  {size}B  play={play}");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// `group-events` — 查群进出记录 (**R16-2 registry 族**: 冷热双模; 冷走引擎读 L1 `chatroom_member_event`,
/// 热走 `hot_group_events` scan msg10000 + parse_member_events 一对多)。5 键对齐 [`native_query::CMD_GROUP_EVENTS`]:
/// event_time/conv_id/event_kind(join/remove 原始; table 映射进群/退群)/member_nickname/member_wxid。
async fn cmd_group_events(args: &GroupEventsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => emit_engine_query_at(
            &native_query::CMD_GROUP_EVENTS,
            &args.target,
            args.limit,
            offset,
            args.format,
        ),
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            let r = native_query::hot_group_events(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发
            )
            .await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_group_events") {
                        Some(t) => eprintln!("群进出 {t} 条 (取前 {}):", args.limit),
                        None => eprintln!("群进出 (总数未知; 本页 {} 条):", r.data.len()),
                    }
                    for row in &r.data {
                        let ct = row["event_time"].as_i64().unwrap_or_default();
                        let conv = row["conv_id"].as_str().unwrap_or_default();
                        // 冷查引擎 table 走 Fmt::EnumStr(join→进群/remove→退群); 热 table 同映射对齐显示 (JSON 仍出原始)。
                        let kind = match row["event_kind"].as_str().unwrap_or_default() {
                            "join" => "进群",
                            "remove" => "退群",
                            other => other,
                        };
                        let nick = row["member_nickname"].as_str().unwrap_or_default();
                        let mwxid = row["member_wxid"].as_str().unwrap_or_default();
                        println!("[{ct}] {conv}  {kind}  {nick} ({mwxid})");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// `emoticons` — 查自定义表情目录。**R16-1 起冷热双模式**: `--mode hot` 直读加密 `emoticon.db` 的
/// `kNonStoreEmoticonTable`(5 键对齐冷查引擎); `--mode cold` 走引擎读 L1 `custom_emoticon`。
///
/// **本条是引擎路径热查的第一条** —— 冷查侧走 `emit_engine_query`(引擎 `render_table`), 而不是手写
/// `*_query`。热查分支自己呈现, table 表头**必须走 `table_total`**(引擎的 `emit_engine_query` 内部是
/// `total_count.unwrap_or(0)` —— 那对冷查引擎对[total_count 恒有值], 但热查 total 走 summary、直读恒 None
/// → 会打 "0 条"。所以热查不能复用 emit_engine_query 的呈现)。
async fn cmd_emoticons(args: &EmoticonsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            // 审 P3-②: 冷查引擎 run_query 本就吃 offset → CLI 也翻页, 不再拒(原写死 0 造成三皮分叉)。
            emit_engine_query_at(
                &native_query::CMD_EMOTICONS,
                &args.target,
                args.limit,
                offset,
                args.format,
            )
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            let r =
                native_query::hot_emoticons(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset).await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_emoticons") {
                        Some(t) => eprintln!("自定义表情 {t} 条 (取前 {}):", args.limit),
                        None => eprintln!("自定义表情 (总数未知; 本页 {} 条):", r.data.len()),
                    }
                    for row in &r.data {
                        let cap = row["caption"].as_str().unwrap_or_default();
                        let md5 = row["md5"].as_str().unwrap_or_default();
                        let ty = row["emoticon_type"].as_i64().unwrap_or_default();
                        println!("type{ty}  {md5}  {cap}");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// `avatars` — 查头像清单 (不露 BLOB)。**R16-1 起冷热双模式**: `--mode hot` 直读加密 `head_image.db` 的
/// `head_image` 表(3 键对齐冷查引擎, WHERE username!='' 对齐 pipeline 跳空); `--mode cold` 走引擎读 L1
/// `avatar_image`。热查分支自呈现(table 走 table_total, 同 emoticons/chatrooms 不能复用 emit_engine_query)。
async fn cmd_avatars(args: &AvatarsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            // 审 P3-②: 冷查引擎 run_query 本就吃 offset → CLI 也翻页, 不再拒。
            emit_engine_query_at(
                &native_query::CMD_AVATARS,
                &args.target,
                args.limit,
                offset,
                args.format,
            )
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            let r =
                native_query::hot_avatars(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset).await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_avatars") {
                        Some(t) => eprintln!("头像 {t} 个 (取前 {}):", args.limit),
                        None => eprintln!("头像 (总数未知; 本页 {} 个):", r.data.len()),
                    }
                    for row in &r.data {
                        let u = row["username"].as_str().unwrap_or_default();
                        let md5 = row["md5"].as_str().unwrap_or_default();
                        let t = row["update_time"].as_i64().unwrap_or_default();
                        println!("[{t}] {u}  {md5}");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// `biz-contacts` — 查企微品牌号联系人。**R16-1 起冷热双模式**: `--mode hot` 直读加密 `bizchat.db` 的
/// `user_info` 表(3 键对齐冷查引擎, WHERE user_id!='' 对齐 pipeline 跳空); `--mode cold` 走引擎读 L1
/// `bizchat_user`。热查分支自呈现(table 走 table_total)。
async fn cmd_biz_contacts(args: &BizContactsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => emit_engine_query_at(
            &native_query::CMD_BIZ_CONTACTS,
            &args.target,
            args.limit,
            offset,
            args.format,
        ),
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            let r = native_query::hot_biz_contacts(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset)
                .await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_biz_contacts") {
                        Some(t) => eprintln!("企微联系人 {t} 个 (取前 {}):", args.limit),
                        None => eprintln!("企微联系人 (总数未知; 本页 {} 个):", r.data.len()),
                    }
                    for row in &r.data {
                        let un = row["user_name"].as_str().unwrap_or_default();
                        let uid = row["user_id"].as_str().unwrap_or_default();
                        let brand = row["brand_user_name"].as_str().unwrap_or_default();
                        println!("{un}  {uid}  {brand}");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// `chatrooms` — 查群列表。**R16-1 起冷热双模式**: `--mode hot` 直读加密 `contact.db` 的 `chat_room`
/// 表(LEFT JOIN 群名/公告, member_count 解 proto 数成员, 5 键对齐冷查引擎); `--mode cold` 走引擎读 L1
/// `chatroom` 表。热查分支自己呈现, table 表头走 `table_total`(同 emoticons: 引擎 emit_engine_query 内部
/// 是 total_count.unwrap_or(0), 热查 total 在 summary → 不能复用)。
async fn cmd_chatrooms(args: &ChatroomsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            // 审 P3-②: 冷查引擎 run_query 本就吃 offset(HTTP/MCP 冷查都翻页)→ CLI 也翻页, 不再拒。
            emit_engine_query_at(
                &native_query::CMD_CHATROOMS,
                &args.target,
                args.limit,
                offset,
                args.format,
            )
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            let r =
                native_query::hot_chatrooms(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset).await?;
            match args.format {
                OutFormat::Table => {
                    match table_total(&r.meta, "total_chatrooms") {
                        Some(t) => eprintln!("群 {t} 个 (取前 {}):", args.limit),
                        None => eprintln!("群 (总数未知; 本页 {} 个):", r.data.len()),
                    }
                    for row in &r.data {
                        let id = row["chatroom_id"].as_str().unwrap_or_default();
                        let name = row["chatroom_name"].as_str().unwrap_or("");
                        let cnt = row["member_count"].as_i64().unwrap_or_default();
                        let nm: String = name.chars().take(24).collect::<String>().replace('\n', " ");
                        println!("{cnt} 人  {id}  {nm}");
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
            Ok(())
        }
    }
}

/// **R16-1**: friend-requests 冷查分支 —— scoped L1 → `friend_requests_query` → 挂 freshness。
/// 缺 `--l1-db` → `require_l1_db` 报错**不静默转热** (R6 语义)。
fn cli_cold_friend_requests(args: &FriendRequestsArgs, offset: usize) -> Result<native_query::QueryResult> {
    let conn = open_l1_resolved(&args.target)?;
    let mut r = native_query::friend_requests_query(&conn, args.limit, offset)
        .context("查 friend_verify 表失败")
        .map_err(|e| needs_ingest_err(e, "先跑 `msgvestige ingest --friend-verify` 导入好友验证表"))?;
    if let Some(f) = native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref()) {
        r.meta = r.meta.with_freshness(f);
    }
    Ok(r)
}

/// `friend-requests` — 查好友申请/验证。**R16-1 起冷热双模式**: `--mode hot` 直读加密 `general.db` 的
/// `FMessageTable` (零解码, 7 字段对齐冷查); `--mode cold` 读 L1 friend_verify 表。查数+json+meta 在核,
/// 此薄壳只呈现 —— table 的方向箭头 / `greeting` 截断是纯装饰, `scene_label` 读**核已组好的 json** (不重算)。
async fn cmd_friend_requests(args: &FriendRequestsArgs) -> Result<()> {
    // R16-1: 主表冷热派发 (照 cmd_contacts/cmd_favorites 模板)。hot 需 --wxid; cold 需 --l1-db。
    // 夹上界在**派发前**算一次冷热共用 (审 P3-3, 同 contacts/favorites)。
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            native_query::hot_friend_requests(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset).await?
        }
        native_query::EffectiveMode::Cold => cli_cold_friend_requests(args, offset)?,
    };
    match args.format {
        OutFormat::Table => {
            // R16-1: 走 table_total (热查 total 在 summary; 直读 meta.total_count 恒 None → 打 "0 条")。
            match table_total(&r.meta, "total_friend_requests") {
                Some(t) => eprintln!("好友申请/验证 {t} 条 (取前 {}):", args.limit),
                None => eprintln!("好友申请/验证 (总数未知; 本页 {} 条):", r.data.len()),
            }
            for row in &r.data {
                let ts = row["timestamp"].as_i64().unwrap_or_default();
                let wxid = row["user_name"].as_str().unwrap_or_default();
                let dir = if row["is_sender"].as_i64().unwrap_or_default() == 1 {
                    "我申请→"
                } else {
                    "←申请我"
                };
                let hello: String = row["greeting"]
                    .as_str()
                    .unwrap_or_default()
                    .chars()
                    .take(40)
                    .collect::<String>()
                    .replace('\n', " ");
                let scene_label = row["scene_label"].as_str().unwrap_or_default();
                println!("[{ts}] {dir} {wxid}  ({scene_label})  {hello}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// `mentions` — 查 @提及记录 (读 L1 message_mention ⋈ message; 只读)。查数+json+meta 在核 `mentions_query`,
/// 此薄壳只呈现。table `@所有人`/`@{人}` 判定 + preview 截断是纯 table 装饰, 读**核 json** 的字段。
async fn cmd_mentions(args: &MentionsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            // **R16-2 起冷热双模**: 热走 hot_mentions(scan want_msgsource + parse_mentions 一对多, sender 路径A)。
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            native_query::hot_mentions(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.query.as_deref(),
                args.limit,
                offset,
                None, // scan_permit
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::mentions_query(&conn, args.query.as_deref(), args.limit, offset)
                .context("查 message_mention 表失败")
                .map_err(|e| needs_ingest_err(e, "先 ingest 消息 (@提及是消息派生的 message_mention 表)"))?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            // R16-2: table_total(热查 total 在 summary.total_mentions; 冷查在 meta.total_count)。
            let total = table_total(&r.meta, "total_mentions").unwrap_or(0);
            eprintln!(
                "@提及 {total} 条{} (取前 {}):",
                if args.query.is_some() {
                    " (已过滤被@人)"
                } else {
                    ""
                },
                args.limit
            );
            for row in &r.data {
                let ctime = row["create_time"].as_i64().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let sender = row["sender_wxid"].as_str().unwrap_or_default();
                let mentioned = row["mentioned_wxid"].as_str().unwrap_or_default();
                let target = if row["is_at_all"].as_i64().unwrap_or_default() == 1 {
                    "@所有人".to_string()
                } else {
                    format!("@{mentioned}")
                };
                let preview: String = row["text_content"]
                    .as_str()
                    .unwrap_or_default()
                    .chars()
                    .take(40)
                    .collect::<String>()
                    .replace('\n', " ");
                println!("[{ctime}] {conv}  {sender} {target}: {preview}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

// money 的 `MoneyRow`/`MoneyKind` + 3 子查 (`query_transfers`/`query_red_envelopes`/`query_group_pays`) +
// 合并出口 `money_query` 已移 native-query::handwritten (§6③ 第五批); `MoneyKind` 经上方 `use` 引入 (皮 flatten 复用)。
#[derive(Args)]
struct MoneyArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 交易类型 (all / transfer / red-envelope / group-pay)。
    #[arg(long, value_enum, default_value_t = MoneyKind::All)]
    kind: MoneyKind,
    /// 只看红包领取明细 (谁领了每个红包; 覆盖 --kind, 走 message_hongbao_claim)。
    #[arg(long)]
    claims: bool,
    /// 只看群收款逐付款人 (每人金额/状态; 覆盖 --kind, 走 group_pay_member)。
    #[arg(long)]
    payers: bool,
    /// 最多列几条 (合并后按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 20)]
    limit: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `money` — 查交易 (转账/红包/群收款合并成一条时间线; 读 L1; 只读)。三表合并+排序+截断+json+meta 在核
/// `money_query` (`--kind` 选源, total_count = 被选源真 COUNT 之和), 此薄壳只呈现。
/// 乙: `--claims` / `--payers` 子视图折进本命令 → 走查询引擎的 message_hongbao_claim / group_pay_member
/// (拦在调 `money_query` 之前)。table 逐行读**核 json** (time=null → `[--]`; baked 明细串核内已产出)。
async fn cmd_money(args: &MoneyArgs) -> Result<()> {
    if args.claims {
        // R16-4: --claims 冷热双模 (冷走引擎 CMD_HONGBAO, 热走 hot_hongbao_claims scan msg10000)。money 子视图不翻页 → offset 0。
        match args.target.effective_mode() {
            native_query::EffectiveMode::Cold => {
                return emit_engine_query(&native_query::CMD_HONGBAO, &args.target, args.limit, args.format);
            }
            native_query::EffectiveMode::Hot => {
                let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
                cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
                let r = native_query::hot_hongbao_claims(
                    &wxid,
                    args.target.wechat_data_dir.as_deref(),
                    None, // locator_file
                    args.limit,
                    0,    // offset: money 子视图不翻页
                    None, // scan_permit: CLI 一次性调用无并发, 不设闸
                )
                .await?;
                match args.format {
                    OutFormat::Table => {
                        match table_total(&r.meta, "total_hongbao_claims") {
                            Some(t) => eprintln!("红包领取 {t} 条 (取前 {}):", args.limit),
                            None => eprintln!("红包领取 (总数未知; 本页 {} 条):", r.data.len()),
                        }
                        for row in &r.data {
                            let ct = row["create_time"].as_i64().unwrap_or_default();
                            let conv = row["conv_id"].as_str().unwrap_or_default();
                            let send = row["send_id"].as_str().unwrap_or_default();
                            let own = if row["is_own_envelope"].as_i64().unwrap_or_default() == 1 {
                                "我发的被领"
                            } else {
                                "我领的"
                            };
                            let peer = row["peer_name"].as_str().unwrap_or_default();
                            println!("[{ct}] {conv}  {send}  {own}  {peer}");
                        }
                    }
                    OutFormat::Json => emit_envelope(&r.data, r.meta)?,
                }
                return Ok(());
            }
        }
    }
    if args.payers {
        // R16-4: --payers 冷热双模 (冷走引擎 CMD_GROUP_PAY_MEMBERS, 热走 hot_group_pay_members scan msg49 payerlist)。
        match args.target.effective_mode() {
            native_query::EffectiveMode::Cold => {
                return emit_engine_query(
                    &native_query::CMD_GROUP_PAY_MEMBERS,
                    &args.target,
                    args.limit,
                    args.format,
                );
            }
            native_query::EffectiveMode::Hot => {
                let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
                cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
                let r = native_query::hot_group_pay_members(
                    &wxid,
                    args.target.wechat_data_dir.as_deref(),
                    None, // locator_file
                    args.limit,
                    0,    // offset: money 子视图不翻页
                    None, // scan_permit: CLI 一次性调用无并发, 不设闸
                )
                .await?;
                match args.format {
                    OutFormat::Table => {
                        match table_total(&r.meta, "total_group_pay_members") {
                            Some(t) => eprintln!("群收款付款人 {t} 条 (取前 {}):", args.limit),
                            None => eprintln!("群收款付款人 (总数未知; 本页 {} 条):", r.data.len()),
                        }
                        for row in &r.data {
                            let bill = row["bill_no"].as_str().unwrap_or_default();
                            let payer = row["payer_wxid"].as_str().unwrap_or_default();
                            let fen = row["amount_fen"].as_i64().unwrap_or_default();
                            let paid = if row["pay_status"].as_i64().unwrap_or_default() == 1 {
                                "已付"
                            } else {
                                "未付"
                            };
                            println!("{bill}  {payer}  ¥{:.2}  {paid}", fen as f64 / 100.0);
                        }
                    }
                    OutFormat::Json => emit_envelope(&r.data, r.meta)?,
                }
                return Ok(());
            }
        }
    }
    // R16-4: 默认档冷热双模 (冷走 money_query 读 L1; 热走 hot_money 两源混合 general.db 专表 + msg49 map)。
    let (r, total): (native_query::QueryResult, u64) = match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let r = native_query::money_query(&conn, args.kind, args.limit, 0)?;
            let total = r.meta.total_count.unwrap_or(0); // 冷: offset_page 设 total_count
            (r, total)
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
            let r = native_query::hot_money(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.kind,
                args.limit,
                0,    // offset: money 默认档不翻页 (同冷 money_query 传 0)
                None, // scan_permit: CLI 一次性调用无并发
            )
            .await?;
            // 热: summary.total_money (约束③); table_total 返 i64 → 转 u64 对齐冷 total_count 类型。
            let total = table_total(&r.meta, "total_money")
                .and_then(|t| u64::try_from(t).ok())
                .unwrap_or(0);
            (r, total)
        }
    };
    match args.format {
        OutFormat::Table => {
            eprintln!("交易 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let ts = row["time"].as_i64().map_or_else(|| "--".to_string(), |t| t.to_string());
                let kind = row["kind"].as_str().unwrap_or_default();
                let who = row["who"].as_str().unwrap_or_default();
                let detail = row["detail"].as_str().unwrap_or_default();
                println!("[{ts}] {kind}  {who}  {detail}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct FilesArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// 字节数 → 人话 (整数除, 粗略; 避 f64 lint)。
fn human_size(b: i64) -> String {
    const K: i64 = 1024;
    if b < K {
        format!("{b} B")
    } else if b < K * K {
        format!("{} KB", b / K)
    } else if b < K * K * K {
        format!("{} MB", b / (K * K))
    } else {
        format!("{} GB", b / (K * K * K))
    }
}

/// `files` — 列文件消息 (appmsg WHERE file_ext!=''; 只读)。查数+json+meta 在核, 此薄壳只呈现。
/// **R16-2 起冷热双模式**: `--mode hot` scan_all_messages 全局扫 msg49 + parse_appmsg 取有 file_ext 的;
/// `--mode cold` 读 L1 message_app ⋈ message。5 键对齐。table 走 table_total(热查 total 在 summary)。`human_size` 留皮。
async fn cmd_files(args: &FilesArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            native_query::hot_files(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None,
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::files_query(&conn, args.limit, offset).context("查 message_app 文件失败")?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            let total = table_total(&r.meta, "total_files").unwrap_or(0);
            eprintln!("文件消息 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let ctime = row["create_time"].as_i64().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let fname = row["file_name"].as_str().filter(|s| !s.is_empty()).unwrap_or("(无名)");
                let preview: String = fname.chars().take(40).collect::<String>().replace('\n', " ");
                println!(
                    "[{ctime}] {conv}  {preview}  .{}  {}",
                    row["file_ext"].as_str().unwrap_or("?"),
                    human_size(row["file_size"].as_i64().unwrap_or_default())
                );
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct LinksArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `links` — 列分享的链接/卡片 (appmsg WHERE url!=''; 只读)。查数+json+meta 在核, 此薄壳只呈现。
/// **R16-2 起冷热双模式**: `--mode hot` scan_all_messages 全局扫 msg49 + parse_appmsg(与冷查 project_message_app
/// 零漂移, 取有 url 的); `--mode cold` 读 L1 message_app ⋈ message。6 键对齐。table 走 table_total(热查 total 在 summary)。
async fn cmd_links(args: &LinksArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            native_query::hot_links(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file: 用默认
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::links_query(&conn, args.limit, offset).context("查 message_app 链接失败")?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            let total = table_total(&r.meta, "total_links").unwrap_or(0);
            eprintln!("分享的链接/卡片 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let ctime = row["create_time"].as_i64().unwrap_or_default();
                let type_label = row["type_label"].as_str().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let url = row["url"].as_str().unwrap_or_default();
                let t = row["title"].as_str().filter(|s| !s.is_empty()).unwrap_or("(无标题)");
                let preview: String = t.chars().take(30).collect::<String>().replace('\n', " ");
                println!("[{ctime}] {type_label} {conv}  {preview}  {url}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct PiiScanArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 扫哪类 (all=手机+身份证 默认 / phone / idcard)。
    #[arg(long, value_enum, default_value_t = PiiKind::All)]
    kind: PiiKind,
    /// 最多列几条命中 (按时间倒序; 真总数仍报全量)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 显示完整号码 (默认打码, 如 138****8000)。⚠️ 明文回显敏感信息, 慎用。
    #[arg(long, default_value_t = false)]
    reveal: bool,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// 读 `meta.summary` 里的整数域字段 (summary 命令 table 皮渲表头/百分比用; 缺失或非整数 → 0)。
/// stats/extract/pii-scan 的汇总数 (总消息数/命中数/…) 只在核算, 皮从 `meta.summary` 取, 不重查库。
fn summary_i64(meta: &Meta, key: &str) -> i64 {
    meta.summary
        .as_ref()
        .and_then(|s| s.get(key))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

/// **R16-1**: table 表头的"总共多少条" —— **冷热通用**, 取不到返 `None` (表头须说"未知", 别报 0)。
///
/// 冷查放 `meta.total_count`; **热查按 §14.1 恒不铺顶层 `total_count`** (hot.rs:427 "total_count 不铺顶层
/// (§14.1), 精确全量走 summary.total_sessions"), 精确全量在 `meta.summary.<hot_key>`; COUNT 失败时
/// summary 里是 `total_unknown: true` → 本函数返 `None`。
///
/// **表头要打总数的命令, 一律走本函数**, 别直接 `meta.total_count.unwrap_or(0)`: 那在热查下恒取
/// `None` → 打 "0 条" 然后列出满满一页。`favorites --mode hot` 真中过 —— R16-1 接热查时我把冷查表头
/// 原样留着, 而 `Meta::hot` 的 `total_count` 恒 `None` (envelope.rs:184)。`contacts` 躲过纯属它表头
/// 用的是 `data.len()`。
///
/// **判据是"用哪个 `Meta` 构造器", 不是"冷查还是热查"**(对抗审 P3-4 纠): 我原先在这写的是"另 14 处是
/// **纯冷查**命令, 那里 total_count 恒有值" —— **"冷查 ⇒ total_count 有值"是个假不变量**:
/// `Meta::cold_page` / `Meta::cursor_page` 同样 `total_count: None`。那 14 处安全**只是因为它们恰好都
/// 用了 `offset_page`/`page`**。判据错了就会再犯: 哪天某个冷查命令为修 HOLE-2 式的多报把 `Meta::page`
/// 换成 `Meta::cold_page`, 它的表头立刻静默打 "0 条" 再列满一页 —— 和 favorites 那个 bug 一模一样,
/// 却发生在**纯冷查**路径上。
///
/// → 真正的规矩: **凡表头读 `total_count` 的命令, 其 query fn 必须用 `offset_page`/`page`**; 用别的
/// 构造器 (hot / cold_page / cursor_page) 就得走本函数并给出 `hot_key`。与冷热无关。
fn table_total(meta: &Meta, hot_key: &str) -> Option<i64> {
    if let Some(t) = meta.total_count {
        return i64::try_from(t).ok();
    }
    meta.summary
        .as_ref()
        .and_then(|s| s.get(hot_key))
        .and_then(serde_json::Value::as_i64)
}

/// `pii-scan` — 扫文本消息里疑似手机号/身份证号 (读 L1 message; 只读; 默认打码)。扫号 + **打码/显全 (按
/// `--reveal`) + json + meta 都在核 `pii_scan_query`** (打码放核 → 三皮隐私行为一致); 此薄壳只按 format 呈现:
/// table 表头/命中数读 `meta.summary`, 数据行读**核 json** 的 value (核已按 reveal 打码或显全)。
async fn cmd_pii_scan(args: &PiiScanArgs) -> Result<()> {
    // R16-5: 冷热双模 (冷 pii_scan_query 读 L1; 热 hot_pii_scan 全扫 msg1 + 纯函数 scan_pii_in_text)。
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::pii_scan_query(&conn, args.kind, args.reveal, args.limit)
                .context("扫 message 文本 PII 失败")?;
            // R16-5 复审 (Claude P2): 冷分支挂 cold_freshness (三皮 meta 契约; 热分支已带 Freshness::Hot)。
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
            native_query::hot_pii_scan(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.kind,
                args.reveal,
                args.limit,
                None, // scan_permit: CLI 一次性调用无并发
            )
            .await
            .context("实时扫 PII 失败 (账号 key 缓存了? 数据目录对?)")?
        }
    };
    match args.format {
        OutFormat::Table => {
            let msgs = summary_i64(&r.meta, "messages_flagged");
            let phone_total = summary_i64(&r.meta, "phone_total");
            let id_total = summary_i64(&r.meta, "idcard_total");
            eprintln!(
                "疑似隐私号码: {msgs} 条文本消息命中 (手机 {phone_total} / 身份证 {id_total}); 取前 {} 条 {}",
                args.limit,
                if args.reveal { "[显全]" } else { "[打码]" }
            );
            for row in &r.data {
                let ctime = row["create_time"].as_i64().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let who = row["sender_wxid"].as_str().unwrap_or("?");
                let kind = row["kind"].as_str().unwrap_or_default();
                let value = row["value"].as_str().unwrap_or_default();
                println!("[{ctime}] {conv}  {who}  {kind}  {value}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct ThreadArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// 取文本前 n 字, 换行压成空格 (预览用)。
fn preview_line(s: Option<&str>, n: usize, empty: &'static str) -> String {
    match s.filter(|t| !t.is_empty()) {
        Some(t) => t.chars().take(n).collect::<String>().replace('\n', " "),
        None => empty.to_string(),
    }
}

/// `thread` — 列引用回复。**R16-2 起冷热双模**: `--mode hot` 走 hot_thread(scan_all_messages base_types=[49] +
/// parse_appmsg 取有 refer_svrid 的, sender 走路径A); `--mode cold` 读 L1 message_app ⋈ message。6 键对齐, 查数+json
/// +meta 在核。table `preview_line` (纯 table 截断装饰, 不进 json) 留皮, 读**核 json** 的 reply_text/quoted_text。
async fn cmd_thread(args: &ThreadArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            native_query::hot_thread(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::thread_query(&conn, args.limit, offset).context("查 message_app 引用回复失败")?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            // R16-2: table_total(热查 total 在 summary.total_thread; 冷查在 meta.total_count)。
            let total = table_total(&r.meta, "total_thread").unwrap_or(0);
            eprintln!("引用回复 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let ctime = row["create_time"].as_i64().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let who = row["sender_wxid"].as_str().unwrap_or("?");
                let reply = preview_line(row["reply_text"].as_str(), 30, "(空)");
                let quoted = preview_line(row["quoted_text"].as_str(), 40, "(无原文)");
                println!("[{ctime}] {conv}  {who}  回复「{reply}」 → 引用「{quoted}」");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct FinderArgs {
    /// 查询目标 (L1 库 / 实时查微信库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按访问时刻倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃 —— 冷查 finder_query 本就收 offset, 热查同口径)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// **R16-1**: finder 冷查分支 —— scoped L1 → `finder_query` → 挂 freshness。
/// 缺 `--l1-db` → `require_l1_db` 报错**不静默转热** (R6 语义)。
fn cli_cold_finder(args: &FinderArgs, offset: usize) -> Result<native_query::QueryResult> {
    let conn = open_l1_resolved(&args.target)?;
    let mut r = native_query::finder_query(&conn, args.limit, offset).context("查 finder_visit 失败")?;
    if let Some(f) = native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref()) {
        r.meta = r.meta.with_freshness(f);
    }
    Ok(r)
}

/// `finder` — 列访问过的视频号。**R16-1 起冷热双模式**: `--mode hot` 直读加密 `general.db` 的
/// `wcfinderuserpage` (解 proto + 跳空壳行, 5 字段对齐冷查); `--mode cold` 读 L1 finder_visit 表。
/// 查数+json+meta 在核, 此薄壳只呈现。
async fn cmd_finder(args: &FinderArgs) -> Result<()> {
    // 夹上界在派发前算一次, 冷热共用 (审 P3-3: 写在热分支里冷查就漏夹 → offset 回绕返回第一页)。
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            native_query::hot_finder_visits(&wxid, args.target.wechat_data_dir.as_deref(), args.limit, offset).await?
        }
        native_query::EffectiveMode::Cold => cli_cold_finder(args, offset)?,
    };
    match args.format {
        OutFormat::Table => {
            // R16-1: 走 table_total (热查 total 在 summary; 直读 meta.total_count 恒 None → 打 "0 个")。
            let total = table_total(&r.meta, "total_finder_visits");
            match total {
                Some(t) => eprintln!("访问过的视频号 {t} 个 (取前 {}):", args.limit),
                None => eprintln!("访问过的视频号 (总数未知; 本页 {} 个):", r.data.len()),
            }
            for row in &r.data {
                let day = row["visit_date"].as_str().unwrap_or_default();
                let name = row["name"].as_str().unwrap_or_default();
                let owner = row["owner_username"].as_str().unwrap_or_default();
                let url = row["profile_url"].as_str().unwrap_or_default();
                let nm: String = name.chars().take(24).collect::<String>().replace('\n', " ");
                let ow: String = owner.chars().take(22).collect();
                println!("[{day}] {nm}  ({ow})  {url}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct BizArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按推送时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `biz` — 列公众号图文推送 (读 L1 message gh_ 会话 ⋈ message_app; 只读)。查数+json+meta 在核 `biz_query`,
/// 此薄壳只呈现。table headline (图文 title 或 `(type{n} 非图文)` 兜底) 是纯 table 装饰, 读**核 json** 字段。
async fn cmd_biz(args: &BizArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            // **R16-2 起冷热双模**: 热走 hot_biz(scan_conversations("gh_") 会话层前缀过滤 + parse_appmsg 取 title)。
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            // R21 成本门**不挂 biz**(审 round-2/3 两审一致): hot_biz 走 scan_conversations("gh_"), 在会话计划层 continue 跳过
            // 非 gh_ 会话、不开其表/不解码, I/O ∝ gh_ 子集 ≪ 全字节; 用全扫估算(按总分片字节)会大幅过估 → 每次误拦 biz。
            // 同 messages(定向)/inspect(非 message 臂)的排除原则。**残余**: 重公众号账号(10万+ gh_)biz 可数十秒无保护 ——
            // 精确 biz 门需按 gh_ 会话数估(R22 partial-hit 有元数据后可做), 甲 stat-only 阶段暂缺。
            native_query::hot_biz(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::biz_query(&conn, args.limit, offset).context("查公众号消息失败")?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            // R16-2: table_total(热查 total 在 summary.total_biz; 冷查在 meta.total_count)。
            let total = table_total(&r.meta, "total_biz").unwrap_or(0);
            eprintln!("公众号图文推送 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let day = row["date"].as_str().unwrap_or_default();
                let gh = row["gh_id"].as_str().unwrap_or_default();
                let mtype = row["msg_type"].as_i64().unwrap_or_default();
                // 图文 (type49) 有 title; 其余 (文本/图片/系统) 无卡片 → 标注类型。
                let headline = match row["title"].as_str().filter(|s| !s.is_empty()) {
                    Some(t) => t.chars().take(40).collect::<String>().replace('\n', " "),
                    None => format!("(type{mtype} 非图文)"),
                };
                println!("[{day}] {gh}  {headline}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct MsgrawArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 只看某条源 native id (如 Msg_429f284e:1; 给了就 dump 整条 payload_json, 不给则列预览)。
    ///
    /// 查不到多半是超出保留窗口被清了 (默认 24 小时), 不是程序漏给; 见本命令说明。
    #[arg(long)]
    native_id: Option<String>,
    /// 只看某个源库 (如 message_0.db)。同一个会话表可能同时存在于多个分片, 光给 native-id
    /// 会返回多条; 结果里的 source 列告诉你各是哪个分片, 这个参数用来直接钉死一条。
    ///
    /// 按"这个分片"算: 消息那类 source 就是库名本身, 水位那类是 "库名|表名", 两种都算在内。
    /// 跟 --native-id 一样, 查无是退出码 3 (NOT_FOUND), 不是空表。
    #[arg(long)]
    source: Option<String>,
    /// 最多列几条 (按 id 倒序 = 最近 ingest 在前)。
    #[arg(short = 'n', long, default_value_t = 20)]
    limit: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `msgraw` — 原始 payload dump (读 L1 raw_payload_archive; 只读)。查数+json+meta 在核 `msgraw_query`,
/// 此薄壳只呈现 + 保 NOT_FOUND (定向查无) 判定。给 --native-id 时逐条 dump 整条 payload (溯源/调试); 不给时列预览。
///
/// 核 json `payload` 存**解析后**的 Value; table 皮从该 Value 重建原串: `Value::String` (非法 JSON 回退)
/// 取原串, 否则 `to_string`/`to_string_pretty` 重序列化 —— ingest 存 `payload_json` 走
/// `serde_json::to_string(Value)` (排序紧凑, 无 preserve_order), 故往返逐字节等旧码直读原串。
fn cmd_msgraw(args: &MsgrawArgs) -> Result<()> {
    // R16-6: msgraw **⚫无热查** —— `raw_payload_archive` 是 **ingest 归档产物**(落库时存的原始 payload_json), 加密源库
    // 物理**无此表**。`--mode hot`(或 `--mode auto` 且没给 `--l1-db` → 解析成 Hot)→ 明确报"做不了", 而非静默走冷 /
    // 冒出 confusing 的缺库错。这是 ⚫ 命令的"热查对等"= 诚实拒绝 + 指路冷查。
    if matches!(args.target.effective_mode(), native_query::EffectiveMode::Hot) {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "msgraw 无热查模式: raw_payload_archive 是 ingest 归档产物, 加密源库物理无此表。请用冷查 (给 --l1-db <L1库>, 或加 --mode cold)。",
        ));
    }
    let conn = open_l1_resolved(&args.target)?;
    // ⚠️ **两个过滤条件的查无处置要一致**(独立复审 656477c 的 P3): 原先只有 `--native-id` 算
    // "定向查", 给了 `--source` 查无却是退出码 0 + 空表 —— 两个都是定向过滤, 处置该一样。
    let targeted = args.native_id.is_some() || args.source.is_some();
    let r = native_query::msgraw_query(&conn, args.native_id.as_deref(), args.source.as_deref(), args.limit, 0)
        .context("查 raw_payload_archive 失败")?;
    let total = r.meta.total_count.unwrap_or(0);
    // 精确 --native-id 定向查无 → NOT_FOUND/3 (契约审 #7: 对齐 inspect/resolve 的"定向查无=NOT_FOUND")。
    if targeted && total == 0 {
        // ⚠️ 提示要说清**是哪个条件把它排除掉的**: 原先不管给了什么都报"没找到 native-id 为 X",
        // 而 `--native-id X --source Y` 撞空时 X 明明在库里, 被排除的是 Y —— 那句话指错了原因。
        let what = match (args.native_id.as_deref(), args.source.as_deref()) {
            (Some(n), Some(s)) => format!("native-id 为 {n} 且来自 {s} 的原始事件"),
            (Some(n), None) => format!("native-id 为 {n} 的原始事件"),
            (None, Some(s)) => format!("来自 {s} 的原始事件"),
            (None, None) => unreachable!("targeted 为真时至少给了一个条件"),
        };
        return Err(cli_err(native_core::ErrorCode::NotFound, format!("没找到{what}")));
    }
    match args.format {
        OutFormat::Table => {
            eprintln!("原始 payload 归档 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let id = row["id"].as_i64().unwrap_or_default();
                let etype = row["event_type"].as_str().unwrap_or_default();
                let action = row["event_action"].as_str().unwrap_or_default();
                let nid = row["source_native_id"].as_str().unwrap_or_default();
                // 源库名要打出来: `source_native_id` 不带分片, 同名会话表可以同时在多个分片里
                // (真库实测 700 张), 不打的话用户看到两条一模一样的行, 认不出哪条是哪个分片的。
                let src = row["source"].as_str().unwrap_or_default();
                let payload = &row["payload"];
                if targeted {
                    // 精确定位 → dump 整条 (对象 pretty; 非法 JSON 回退存的 String 取原串)。
                    let pretty = match payload {
                        serde_json::Value::String(raw) => raw.clone(),
                        v => serde_json::to_string_pretty(v).unwrap_or_default(),
                    };
                    println!("── #{id} {etype}/{action} {src} {nid} ──\n{pretty}");
                } else {
                    // 预览原串: String 回退取原串, 否则紧凑重序列化 (== ingest 存的 payload_json)。
                    let raw = payload
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| serde_json::to_string(payload).unwrap_or_default());
                    let preview: String = raw.chars().take(70).collect::<String>().replace('\n', " ");
                    println!("#{id} {etype}/{action}  {src}  {nid}  {preview}");
                }
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct EventsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 只看某类事件 (sys_type: member_join/member_remove/revoke/pat/topmsg/group_dissolve/hongbao/transfer/other)。
    #[arg(long)]
    sys_type: Option<String>,
    /// 最多列几条 (按时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `events` — 列群系统事件 (读 L1 message type10000; 只读)。查数+json+meta 在核 `events_query`, 此薄壳只呈现。
/// `sys_type_label` 已迁核 (json 预组 `label`); table 读**核 json** 的 label (为空回退 "?") + preview_line 截断留皮。
/// **R16-2 起冷热双模式**: `--mode hot` scan_all_messages 全局跨分片扫系统消息(msg_type10000,
/// classify_sysmsg 零新解码); `--mode cold` 读 L1 message。6 键对齐。table 走 table_total(热查 total 在 summary)。
async fn cmd_events(args: &EventsArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    // Claude 审 P3-1: 空串 sys_type 归 None(= 无过滤), 三皮统一 —— 否则 CLI/HTTP 原样传 Some("") →
    // `WHERE sys_type=''` 恒 0 行, 而 MCP filter(!is_empty) 返全部 → 同一空过滤查询三皮行集分叉。
    let sys_type = args.sys_type.as_deref().filter(|s| !s.is_empty());
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            native_query::hot_events(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file: 用默认 (系统临时目录按 wxid 命名)
                sys_type,
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发, 不设闸
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::events_query(&conn, sys_type, args.limit, offset).context("查群系统事件失败")?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            let total = table_total(&r.meta, "total_events").unwrap_or(0);
            eprintln!("群系统事件 {total} 条 (取前 {}):", args.limit);
            for row in &r.data {
                let day = row["date"].as_str().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let label = row["label"].as_str().unwrap_or("?");
                let desc = preview_line(row["text"].as_str(), 50, "(无描述)");
                println!("[{day}] {conv}  [{label}]  {desc}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct ExecArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 只读 SQL (SELECT / WITH / EXPLAIN; 单条, 不能含分号分隔的多语句)。
    sql: String,
    /// 最多打印几行 (防手滑全表刷屏; 超出截断并提示)。
    #[arg(long, default_value_t = 1000)]
    max_rows: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
    /// 【热查专用】(--mode hot): 跑 SQL 的源库 —— db_storage 下的相对路径 (裸 schema, 专家向), 如
    /// `contact/contact.db`、`message/message_0.db`、`session/session.db`。用 `SELECT name FROM sqlite_master
    /// WHERE type='table'` 自查表名。冷查(读 L1)忽略此参。
    #[arg(long)]
    source_db: Option<String>,
}

#[derive(Args)]
struct NewArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按入库到达顺序=rowid 升序, 通常≈时间序; 下次接着看)。
    #[arg(short = 'n', long, default_value_t = 50)]
    limit: usize,
    /// 每个有新消息的会话先留几条 (默认 0 = 不开, 跟以前一样)。
    ///
    /// 不开时按会话固定顺序发, 排在前面又一直有新消息的会话会把名额占满, 后面的会话这一轮
    /// 一条都出不来 (数据不丢, 下次还在, 但当时看不到)。开了就先给每个有新消息的会话留这么多条,
    /// 剩下的名额再按原来的顺序补。
    ///
    /// 名额不够分时 (会话数乘这个数超过 -n) 仍按会话顺序发, 每个会话最多先拿这么多 ——
    /// 能露面的会话通常比不开时多, 但不保证人人有份; 想都看到就把 -n 调大。
    ///
    /// 别把它开到接近 -n: 露面的会话不但不会变多, 还可能比不开时更少。保底按会话 id (wxid/群号,
    /// 不是显示名) 排序攒, 而不开时是按 (分片, 会话 id, 行号) 取 —— 分片在前, 两个顺序不一样。
    /// 会话 id 最靠前的那个会话若落在靠后的分片里, 开到满额时它排第一、只要新消息够多就把名额全占走,
    /// 而不开时那些名额本来会分给靠前分片里的一堆会话。留几条就写几条, 别顶着 -n 写。
    /// (完整例子和例外见文档 快速开始.md 的「已知做不到的」。)
    ///
    /// 只有实时模式认这个参数。走冷查时给了大于 0 的值会当场报错, 不会闷声不管。什么时候算冷查:
    /// 显式 --mode cold, 或者不写 --mode (默认 auto) 又给了 --l1-db。显式写了 --mode hot 的话,
    /// 哪怕同时给了 --l1-db 也还是走实时, 这个参数照常生效。
    #[arg(long, default_value_t = 0)]
    per_conv: usize,
    /// 清空水位 (下次从头看全部)。
    ///
    /// 也会清掉"这张表丢过消息"的提示。那一行回不回得来, 看它现在读不读得出来:
    /// 后来又读得出来了, 重扫就会把它补报出来(这是唯一能拿回来的办法); 一直读不出来就确实回不来。
    ///
    /// 想看那一行到底是什么, 用 `exec` 直接查那张表看原始字节。
    /// (建 L1 走 `--mode cold` 只在"坏的是普通整数列"时能拿到; 正文解不开、或者行号本身坏了,
    /// 冷查那条路也拿不到。)
    #[arg(long, default_value_t = false)]
    reset: bool,
    /// 只看不推进水位 (预览; 下次仍从同一水位)。
    ///
    /// 不能跟 `--reset` 一起用: 那个会真的删掉水位文件, 跟"预览"是反的。
    // (为什么设成互斥: 一起给的话水位没了、又什么都不写回去, 而屏幕上还说着"下次仍从同一水位" ——
    //  自称预览却留下不可逆的副作用。独立复审第二十一轮 P2。)
    #[arg(long, default_value_t = false, conflicts_with = "reset")]
    no_advance: bool,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `new` 的水位文件路径 (temp_dir + (l1_db, account) 哈希; **按库+账号**各记"上次看到哪")。
/// codex-R8 P1: account 进 key —— 多账号库不同 `--account` 各自水位, 不共用游标互相串跳。文件名版本 `wm2`
/// (R8 水位语义从 create_time 改 rowid, 旧 `wm` 文件不兼容 → 换名忽略=从头, 见 cmd_new 的 "r:" 前缀解析)。
fn new_watermark_path(l1_db: &str, account_sha: Option<&str>) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    l1_db.hash(&mut h);
    account_sha.hash(&mut h);
    std::env::temp_dir().join(format!("msgvestige_new_wm2_{:016x}.txt", h.finish()))
}

/// 当前账号在 L1 里的 **max(rowid)** —— `new` 水位跨重建/恢复/VACUUM 的 max 护栏用 (R14): 水位 rid > 此值 = 状态被截短
/// (恢复较小备份 / VACUUM / 换小库) → 从头重扫。多账号加 `account_id_sha` 谓词(rowid 全局, 但只关心本账号有没有被截短)。
/// 空表 → max 为 NULL → None; 读错 → None。调用方对 None 保守从头(fail-closed)。走 rowid btree 右端, O(log n)。
fn new_account_max_rowid(conn: &rusqlite::Connection, account_sha: Option<&str>) -> Option<i64> {
    let get = |r: &rusqlite::Row| r.get::<_, Option<i64>>(0);
    match account_sha {
        Some(sha) => conn
            .query_row(
                "SELECT max(rowid) FROM message WHERE account_id_sha=?1",
                rusqlite::params![sha],
                get,
            )
            .ok()
            .flatten(),
        None => conn.query_row("SELECT max(rowid) FROM message", [], get).ok().flatten(),
    }
}

/// 消息正文预览: XML (媒体/卡片, 以 < 开头) 显示成 [类型], 否则截断文本。
fn msg_body_preview(type_name: Option<&str>, text: Option<&str>, n: usize) -> String {
    match text.filter(|s| !s.is_empty()) {
        Some(t) if t.trim_start().starts_with('<') => {
            format!("[{}]", type_name.unwrap_or("非文本"))
        }
        Some(t) => t.chars().take(n).collect::<String>().replace('\n', " "),
        None => format!("[{}]", type_name.unwrap_or("空")),
    }
}

/// `new` — 增量看新消息 (读 L1 message; 水位存 temp; 只读库)。查数+json+meta 在核 `new_query`, 此薄壳只做
/// **水位文件 I/O** (读 temp 水位[含代号+max(rowid)双信号跨重建校验] → 调核 → 呈现 → 除非 `--no-advance` 才把末条 {rowid,gen} 写回) + 呈现。
/// `new` 冷热派发 (**R16-5**)。冷 = L1 rowid 水位前向追赶; 热 = 源库复合键水位前向追赶。**两套水位并存各记各的**
/// (用户①: 冷读 L1 各记 rowid, 热读源库各记 (create_time,source,source_native_id); 源库无 L1 rowid、L1 无源库位置)。
async fn cmd_new(args: &NewArgs) -> Result<()> {
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            // ⚠️ **给了但不生效的参数要当场报错, 不许静默吞**(独立复审的 P2)。
            // `new` 默认 `--mode auto`, 给了 `--l1-db` 就走冷查, 而冷查这条路根本不读 `--per-conv` ——
            // 用户写了参数、命令正常返回、行为一点没变, 而且 help 里也没说它只对实时模式生效。
            // 这个仓库为同一类毛病做过硬报错(非热查命令上给 `--mode hot` 直接拒), 这里照办。
            if args.per_conv > 0 {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "--per-conv 只对实时模式生效 (--mode hot); 冷查读的是 L1 库, 不走那套名额分配。去掉 --per-conv, 或者加 --mode hot --wxid <账号> 走实时。"
                        .to_string(),
                ));
            }
            cmd_new_cold(args)
        }
        native_query::EffectiveMode::Hot => cmd_new_hot(args).await,
    }
}

/// 热 `new` 水位文件路径 —— 按 (wxid + **解析规范化后的绝对消息目录**) 分区。**codex P2**: 用规范化绝对路径(非原始
/// `--wechat-data-dir` 字符串)做键 —— 防同 wxid 不同工作目录/相对参数解析到不同源库却共用水位, 或默认目录变化时旧水位
/// 误命中。与冷水位 [`new_watermark_path`] **完全独立的文件**(前缀 `hotwm` vs `new_wm2`, 扩展名 `.json` vs `.txt`)。
fn new_hot_watermark_path(wxid: &Wxid, resolved_msg_dir: &std::path::Path) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    wxid.as_str().hash(&mut h);
    // canonicalize 把相对/软链/`.` 归一为唯一绝对路径; 失败(罕见)退回解析后的原路径 (已比原始参数强)。
    let canon = std::fs::canonicalize(resolved_msg_dir).unwrap_or_else(|_| resolved_msg_dir.to_path_buf());
    canon.hash(&mut h);
    std::env::temp_dir().join(format!("msgvestige_new_hotwm_{:016x}.json", h.finish()))
}

/// 热 `new`: 源库前向增量。水位=**逐会话表 `{"src\x1fconv_id": max_local_id}` 表**存独立 JSON 文件; `--reset`/首次=从头全收。
/// (`local_id` 是每会话 Msg_ 表内 rowid 非分片全局, 故水位按 (分片,会话) 分——见 `hot_new` doc。)内核返
/// `summary.next_watermark`(更新后的逐会话表水位表, 恒 ⊇ 旧水位)供持久化。皮层只当**不透明 `HashMap<String,i64>`**读写, 不解析键。
///
/// ⚠️ **一行读不出来时冷热两条路口径不同, 是有意的**(2026-07-30 用户拍板"乙+"):
/// 冷查(批量导入)遇到坏行: 行号或正文坏了**拦下整批**报错(卡住重来一次就好), 普通整数列坏了按 0 落库。
/// 热查(实时看)按列的真实类型读, 对不上就**跳过那一行继续**, 因为停在坏行
/// 那儿不动的话, 一个**永久**坏行就能让整张表永远卡住、还占满名额让别的会话看不到新消息。
/// 代价是位置越过它之后那条消息永久报不出来。**但不许静默**: 水位里给那张表立一个
/// 标记, 每轮如实报进 `summary.tables_with_lost_rows` + 默认输出的告警行。
/// 把"哪几张表丢了哪几行"拼成告警里那一行。
///
/// 单拎成纯函数是为了**能测** —— 这套告警是"丢可以、静默不行"那条契约的唯一落点, 而它整个活在
/// 皮层。第二十五轮变异全扫量出来: 皮层六个变异(连"把告警整块删掉"在内)**一条守卫都不红**。
///
/// 两件必须对, 否则用户拿着它动不了手(独立复审第二十三/二十四轮各栽过一次):
/// - **分片名要带 `message/` 前缀** —— 水位键里存的是纯文件名, 而 `exec --source-db` 要的是
///   db_storage 下的相对路径。少了前缀照抄会开库失败, 报的还是"key 不对"这种误导性错误。
/// - **行号缺席要说明白为什么** —— 升级前标下的 `lost` 没有行号, 而记录点按"高于当前位置"过滤,
///   那些行早在位置底下、以后再也补不上。不说明白用户会以为是程序漏给了。
fn format_lost_tables(marks: &[(String, Vec<i64>)]) -> String {
    marks
        .iter()
        .map(|(k, ids)| {
            let where_ids = if ids.is_empty() {
                " 行号不详(升级前标的; `new --reset` 重扫一遍能重新定位)".to_string()
            } else {
                format!(
                    " local_id {}",
                    ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
                )
            };
            match k.split_once('\u{1f}') {
                Some((shard, conv)) => format!("{conv}(在 message/{shard}){where_ids}"),
                None => format!("{k}{where_ids}"),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn cmd_new_hot(args: &NewArgs) -> Result<()> {
    use std::collections::HashMap;
    let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
    // R21 全扫成本门 —— **须在删/读水位前** (codex round-2 P1: --reset 先删水位再 Blocked 会丢游标 → 下次 new 重放全部历史)。
    cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?;
    // 解析真实消息目录 → 水位文件按它分区 (codex P2)。解析失败 fail-closed (hot_new 内部也会同样失败)。
    let msg_dir = native_query::resolve_message_dir(args.target.wechat_data_dir.as_deref(), &wxid)
        .context("定位源库消息目录失败 (数据目录对? 该账号存在?)")?;
    let wm_path = new_hot_watermark_path(&wxid, &msg_dir);
    // --reset: 删水位文件。删失败(除 NotFound)**报错** —— 否则 reset 没落地, 下轮又读旧水位以为重置了 (codex P3)。
    if args.reset {
        match std::fs::remove_file(&wm_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("--reset 删热水位文件失败 {}", wm_path.display()));
            }
        }
    }
    // 读逐会话表水位表。--reset / 读不出 / 格式坏 → None=全收 (保守: 坏文件不静默半信)。
    //
    // **两种格式都认**(2026-07-30 补护栏): 现行 `{"id":N,"n":M}` 带**已读段行数**, 用来认"这张表
    // 被换过没有"; 老的是裸数字 `N`。老的照读、`n` 记成 None —— 那一轮不比这一项, 扫完就建立起来。
    // **不能让升级本身触发"全部历史当新的报一遍"**, 所以这里必须兼容老格式, 不能让它解析失败。
    let wm: Option<HashMap<String, native_query::NewHotMark>> = if args.reset {
        None
    } else {
        std::fs::read_to_string(&wm_path).ok().and_then(|s| {
            serde_json::from_str::<HashMap<String, native_query::NewHotMark>>(&s)
                .ok()
                .or_else(|| {
                    serde_json::from_str::<HashMap<String, i64>>(&s).ok().map(|old| {
                        old.into_iter()
                            .map(|(k, id)| {
                                (
                                    k,
                                    native_query::NewHotMark {
                                        id,
                                        gid: None,
                                        n: None,
                                        ct: None,
                                        // 老格式(裸数字)只有位置, 没有这一项。当"没丢过"读进来 ——
                                        // 升级前真丢过的话这边无从得知, 但只要那一行还在被跳过,
                                        // 下一轮就重新立起来。
                                        lost: false,
                                        lost_ids: vec![],
                                    },
                                )
                            })
                            .collect()
                    })
                })
        })
    };
    let wm_desc = wm
        .as_ref()
        .map_or_else(|| "从头(全收)".to_string(), |m| format!("{} 会话表有水位", m.len()));
    // 内核要拿走这份水位; 预览模式还得读它里头**已经落盘的**丢标记, 所以留一份。
    let wm_for_call = wm.clone();
    let mut r = native_query::hot_new(
        &wxid,
        args.target.wechat_data_dir.as_deref(),
        None,
        wm_for_call,
        args.limit,
        args.per_conv,
        None,
    )
    .await
    .context("实时查新消息失败 (账号 key 缓存了? 数据目录对?)")?;
    // 下轮水位 = summary.next_watermark (更新后的逐会话表水位表)。先取 (emit_envelope 会 move r.meta)。
    let next_wm: Option<HashMap<String, native_query::NewHotMark>> = r
        .meta
        .summary
        .as_ref()
        .and_then(|s| s.get("next_watermark"))
        .and_then(|w| serde_json::from_value::<HashMap<String, native_query::NewHotMark>>(w.clone()).ok());
    let partial = r
        .meta
        .summary
        .as_ref()
        .and_then(|s| s.get("partial"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // 护栏这一轮复位了几张会话表(源库被换成另一份副本 / 表被重建)。**恒 0 才是正常。**
    // 非 0 = 下一轮会把那几张表整表当新的补报一遍 —— 默认输出也要说, 不能只写进 JSON 元数据
    // (codex round-12 P2: 我提交正文写着"不静默", 而表格输出根本没读这个数)。
    let guard_reset = r
        .meta
        .summary
        .as_ref()
        .and_then(|s| s.get("guard_reset_tables"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    // 护栏覆盖不到汇报位置的会话表数(有永久读不出来的行)。**恒 0 才是正常。**
    // ⚠️ 跟上面那个一样**必须进默认输出** —— codex round-17 P2: 我两轮前刚修过
    // "写进 JSON 元数据但表格输出没读"这个毛病, 加新计数时又犯了一遍。
    let guard_lagging = r
        .meta
        .summary
        .as_ref()
        .and_then(|s| s.get("guard_lagging_tables"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    // ⚠️ **预览模式下只认已经落盘的**(codex 第十九轮 P2): `--no-advance` 照样算一份"假如推进了
    // 会是什么样"的水位, 于是会对着一个**根本没写下去**的位置喊"这条消息永久丢了" ——
    // 而实际水位没动, 那一行修好之后照样报得出来。已经存在水位文件里的标记该报还是要报。
    //
    // ⚠️ **必须在分格式之前改掉 `summary` 本身**(codex 第二十轮 P2): 上一版只在表格那一支盖住,
    // 而 `--format json` 走另一支直接把内核算的原样吐出去。又是"修了被点名的分支、旁边的没修"。
    //
    // ⚠️⚠️ **整份水位都得换回落盘的那份, 不能只摘掉标记**(codex 第二十一轮 P2): 上一版只删了
    // `lost`, 却把**推进过的 `id` 留着** —— 于是吐出去的水位描述的是"已经越过第 6 行"的位置,
    // 而丢行数报 0。调用方拿这份 `next_watermark` 存下来再喂回来, **第 6 行就静默跳过了**。
    // 我修 P2 反倒造出一个更糟的半吊子状态。
    //
    // 现在的口径很直白: `--no-advance` = 什么都没写下去, 所以 `next_watermark` 就是**磁盘上那份**
    // (没有水位文件时是空的)。想看"假如推进了会怎样"就别加这个参数。
    let lost_marks: Vec<(String, Vec<i64>)> = if args.no_advance {
        let persisted: Vec<(String, Vec<i64>)> = wm
            .as_ref()
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| v.lost)
                    .map(|(k, v)| (k.clone(), v.lost_ids.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(serde_json::Value::Object(sum)) = r.meta.summary.as_mut() {
            sum.insert("tables_with_lost_rows".into(), serde_json::json!(persisted.len()));
            sum.insert(
                "next_watermark".into(),
                serde_json::json!(wm.clone().unwrap_or_default()),
            );
            // 别让调用方以为这份是"下一轮该用的" —— 它就是当前磁盘上那份, 一个字没动。
            sum.insert("watermark_advanced".into(), serde_json::json!(false));
            // ⚠️ **只纠正"描述落盘状态"的字段, 护栏那两个数不动**(codex 第二十二轮 P2 ×2)。
            //
            // 上一版我把 `guard_reset_tables` / `guard_lagging_tables` 也在这儿另算了一套, 两个毛病:
            //   ① 这两个数在**上面几十行就已经取进局部变量**了, 表格输出用的是那份 —— 于是 JSON 拿到
            //      我改过的、表格拿到没改的。同一个"修了这支旁边那支没修", 这一件里第三次。
            //   ② 我另算的那套**比内核那套粗**: 内核会核"缺口里到底还有没有行"(那几行后来被删光了
            //      就不算缺口), 我只看 `gid < id` —— 于是预览会假报"覆盖不全"。
            //
            // 根子是我把这两个数当成了"描述磁盘状态"的。其实它们是**本轮扫描的观察**:
            // "这一轮护栏认为哪几张表像是被换过 / 哪几张核不了", 扫描是真扫了的, 照实报就对。
            // 真正需要纠正的只有描述**落盘状态**的那几项 —— 水位本身, 和 `lost` 这个持久标记
            // (它一旦写下去就不会自己灭, 所以预览里绝不能提前说)。这个不对称是有意的。
        }
        persisted
    } else {
        r.meta
            .summary
            .as_ref()
            .and_then(|s| s.get("next_watermark"))
            .and_then(serde_json::Value::as_object)
            .map(|w| {
                w.iter()
                    .filter(|(_, v)| v.get("lost").and_then(serde_json::Value::as_bool) == Some(true))
                    .map(|(k, v)| {
                        let ids = v
                            .get("lost_ids")
                            .and_then(serde_json::Value::as_array)
                            .map(|a| a.iter().filter_map(serde_json::Value::as_i64).collect())
                            .unwrap_or_default();
                        (k.clone(), ids)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    match args.format {
        OutFormat::Table => {
            eprintln!(
                "新消息 {} 条 (热查 · 水位 {wm_desc}{}{}):",
                r.data.len(),
                if args.no_advance { " · 预览不推进" } else { "" },
                if partial {
                    " · ⚠部分会话表没扫全(源库被写/损坏), 未扫消息下轮追上"
                } else {
                    ""
                }
            );
            if guard_lagging > 0 {
                // ⚠️ 这个数跟下面那个**不是一类**: 复位是"这一轮发生的事"(下轮自然归 0),
                // 覆盖不全是**存在水位里的状态**, 会一直锁着直到那张表来了新消息 / `--reset`。
                // 所以话得分两种情况说, 不能都用"刚出事"的口吻。
                //
                // ⚠️ 也别一口咬定原因: 落后的来源既可能是"某行读不出来", 也可能是**游标中断**
                // (真库上 message_5.db 就是这种, 微信正在写)。而且 `scan_dropped` 这些键
                // **只在本轮真有降级时才存在** —— 锁着的老状态那一轮源库可能完全正常,
                // 指过去是空的(独立复审第十八轮 P3)。
                if partial {
                    eprintln!(
                        "⚠ {guard_lagging} 张会话表的护栏覆盖不全 —— 本轮这些表没扫全(有读不出来的行, 或者读到一半被打断),
  \n                         所以\"这一段有没有被换过\"核不了。数据照常报, 只是少一道保险;
  \n                         --format json 里 scan_dropped(坏行) / scan_truncated_tables(读到一半断) 分得清是哪种。"
                    );
                } else {
                    eprintln!(
                        "⚠ {guard_lagging} 张会话表的护栏覆盖不全 —— 本轮源库是好的, 这是早先某一轮留下的状态:
  \n                         那时候没扫全、位置却往前走了, 中间那一段就再没被护栏盖住。数据照常报, 只是少一道保险。
  \n                         这个数会一直挂着, 等那张表来了新消息自己就好; 想立刻清掉用 `new --reset`(代价是整表重报一遍)。"
                    );
                }
            }
            // ⚠️ **得说是哪几张表**(独立复审第十九轮 P2): 光给个数, 却让用户"直接查那张表" ——
            // 水位文件在临时目录、文件名是哈希, 皮层契约还写明"只当不透明表读写、不解析键",
            // 用户根本拿不到身份。"不许静默"的落点是**用户能动手**, 只给个数离能动手还差一步。
            // ⚠️ **分片名不能丢**(codex 第二十一轮 P2): 同一个会话可能跨多个分片, 只打会话 id
            // 会打出重复的名字; 而热查 `exec` **必须给 `--source-db`** —— 少了分片名, "去查那张表"
            // 这句话用户还是执行不了。键本来就是 `分片 + 会话`, 原样拆开打全。
            // 分片名得是 `--source-db` 真吃得下的那个(独立复审第二十三轮 ④): 水位键里存的是纯文件名
            // (`rel_name()` = `file_name()`), 而 `--source-db` 要 db_storage 下的**相对路径**。上一版
            // 直接把纯文件名打出来让用户填 —— 照做会解析成 `db_storage/biz_message_0.db`, 开库失败,
            // 报的还是"key 不对?"这种误导性错误。消息分片全在 `message/` 下(真库核过), 补上前缀。
            //
            // 顺带把**丢的行号**一并打出来: 光给表名用户还是没法动手 —— 尤其"正文解不开"那一类
            // 在 SQL 里根本没有特征(那行在 SQLite 看来完全正常), 不给行号只能整表 dump 出来肉眼找。
            let lost_names = format_lost_tables(&lost_marks);
            if !lost_marks.is_empty() {
                eprintln!(
                    "⚠ {} 张会话表各有至少一条消息再也报不出来了: {lost_names}",
                    lost_marks.len()
                );
                eprintln!(
                    "  那几行读不出来(数据本身坏了), 而同一张表更靠后的消息已经报过, 位置越过去了。\n  \
                     这是有意的取舍: 停在坏行那儿不动的话, 一行坏数据就能让整张表永远卡住、\n  \
                     还占满名额让别的会话看不到新消息。\n  \
                     上面每条是: 会话(在 分片) 行号。想看那几行原始的样子(下面一行整段复制):\n  \
                     msgvestige exec --mode hot --wxid <账号> --source-db <分片> \"SELECT local_id, typeof(local_type), length(message_content), hex(substr(message_content,1,32)) FROM Msg_<会话id的md5> WHERE local_id IN (<行号>)\"\n  \
                     (表名 = Msg_ 加会话 id 的 md5; SELECT name FROM sqlite_master 能列出来。)\n  \
                     这个提示不会因为那一行恢复正常就自己灭(护栏复位或 `new --reset` 会清掉)。\n  \
                     那一行后来又读得出来的话, 重扫会把它补报出来; 一直读不出来就确实回不来。"
                );
            }
            if guard_reset > 0 {
                eprintln!(
                    "⚠ {guard_reset} 张会话表的水位被复位 —— 源库像是换成了另一份副本(恢复备份 / 迁移?)。
                     下一轮 `new` 会把这几张表整个当新的报一遍, 是有意的: 那些消息此前被旧水位挡着永远看不到。"
                );
            }
            for row in &r.data {
                let dt = row["datetime"].as_str().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let who = row["sender_wxid"].as_str().unwrap_or("?");
                let body = msg_body_preview(row["msg_type_name"].as_str(), row["text_content"].as_str(), 40);
                println!("[{dt}] {conv}  {who}  {body}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    // 推进 (除非 --no-advance)。逐会话表水位恒 ⊇ 旧(只增/推进, 从不越过未扫行)→ 无条件写安全, 无需"partial 不推";
    // 未扫到的会话表保留旧水位(hot_new: new_wm = old.clone() + 本批推进), 下轮追上。
    if !args.no_advance {
        if let Some(map) = next_wm {
            std::fs::write(&wm_path, serde_json::to_string(&map).unwrap_or_default())
                .with_context(|| format!("写热水位文件失败 {}", wm_path.display()))?;
        }
    }
    Ok(())
}

fn cmd_new_cold(args: &NewArgs) -> Result<()> {
    // codex-R8 P1: account_sha 先解析 —— 水位文件路径按 (库+账号) 分区, 多账号库各账号独立水位不串跳。resolve_account_sha
    // fail-closed (多账号未指定 → 报错); 账号隔离靠 new_query 内显式 account_id_sha 谓词 (裸 conn 无遮蔽视图, 复合游标需 rowid)。
    let account_sha = native_query::resolve_account_sha(args.target.require_l1_db()?, args.target.account.clone())?;
    let wm_path = new_watermark_path(args.target.require_l1_db()?, account_sha.as_deref());
    if args.reset {
        // 跟热查那条 `--reset` 同口径: 删失败(除"本来就没有")**报错**, 不能静默 ——
        // 否则 reset 没落地, 下轮又读到旧水位, 而用户以为已经重置了。
        // (热查那边早就是这么写的, 冷查这边一直是 `let _ =` 静默; 独立复审第二十二轮 P3 点出。)
        match std::fs::remove_file(&wm_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("--reset 删冷水位文件失败 {}", wm_path.display()));
            }
        }
    }
    let conn = open_l1(args.target.require_l1_db()?)?;
    // R9/R14 六方复审收敛: 水位跨 **L1 重建/恢复/re-ingest/VACUUM** 失效防护 —— rowid 只在当前表实例单调递增, 状态被换掉后
    // 旧水位 `rowid>N` 会静默漏消息。用**两个正交信号**(取代早期脆弱的 src/nid 身份校验 —— 它在 REPLACE 换位时会误重置全量重投):
    //   ① **实例代号** l1_generation (建库随机, 文件级重建=新代号): 水位代号 != 当前代号 → 文件被换/重建 → 从头。
    //   ② **max(rowid) 护栏**: 水位 rid > 当前账号 max(rowid) → 状态被截短(恢复较小备份 / VACUUM / 换小库)→ 从头。
    //      `INSERT OR REPLACE` 使 max **增长**(rid<=max 恒真)→ 正常增量/末条状态更新不误伤, **不重犯"REPLACE 全量重投"**。
    // codex-R11 P2: 代号读**出错**(非缺表, db corrupt/locked) → fail-closed 强制从头, 不静默信任旧水位。
    let cur_gen_res = native_core::storage::get_l1_generation(&conn);
    let cur_gen = cur_gen_res.as_ref().ok().and_then(std::clone::Clone::clone);
    let acct_max = new_account_max_rowid(&conn, account_sha.as_deref());
    let wm_rowid: i64 = if args.reset || cur_gen_res.is_err() {
        0
    } else {
        std::fs::read_to_string(&wm_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| {
                let rid = v.get("rowid")?.as_i64()?;
                // ② max 护栏(先): rid 越过当前账号 max(rowid) → 状态截短 → 从头。max 取不到(空库/读错)也从头(保守 fail-closed)。
                if acct_max.is_none_or(|mx| rid > mx) {
                    return None;
                }
                // ① 代号: 两边都有→相等继续/不等从头; 一边有一边无→代际不一致(旧库升级/换库)从头; 两边都无(旧库)→ max 护栏
                // 已挡截短, 直接信 rowid(不再查身份 → 免 REPLACE 换位误重投; 同代同大小换库属天文级, 且旧库下次 ingest 补代号自愈)。
                match (v.get("gen").and_then(serde_json::Value::as_str), cur_gen.as_deref()) {
                    (Some(wg), Some(cg)) => (wg == cg).then_some(rid),
                    (Some(_), None) | (None, Some(_)) => None,
                    (None, None) => Some(rid),
                }
            })
            .unwrap_or(0)
    };
    // codex-R14 P1: 护栏/gen 判"从头"(wm_rowid=0) 但文件里有旧水位 → **立即删 stale 文件持久化这个 reset**。否则本批空
    // (无新数据 → new_wm=None 不写文件)时旧水位残留, 下轮同文件 clear+reingest 后又读到失效旧水位 `{100,G}` → 漏 1..100。
    // (--reset 上面已删。删失败无妨: 下轮 max/gen 仍会判从头, 只是重复判定。)
    if wm_rowid == 0 && !args.reset {
        let _ = std::fs::remove_file(&wm_path);
    }
    let mut r = native_query::new_query(&conn, wm_rowid, args.limit, account_sha.as_deref()).context("查新消息失败")?;
    // R16-5 fix-by-criterion: 冷分支统一挂 cold_freshness (契约要求所有冷分支带新鲜度; 冷 new 原漏)。with_freshness 只填
    // freshness 字段不动 summary(scanned_rowid 仍在, 皮层推进不受影响)。
    if let Some(f) = native_query::cold_freshness(args.target.require_l1_db()?, account_sha.as_deref()) {
        r.meta = r.meta.with_freshness(f);
    }
    // 水位推进用核返 scanned_rowid (含读取失败的坏行 → 整批全坏也能推过, 不死循环)。空批无 scanned_rowid → 不推 (无新消息)。
    // 先取 (emit_envelope 会 move r.meta)。
    let new_wm: Option<i64> = r
        .meta
        .summary
        .as_ref()
        .and_then(|s| s.get("scanned_rowid"))
        .and_then(serde_json::Value::as_i64);
    match args.format {
        OutFormat::Table => {
            eprintln!(
                "新消息 {} 条 (水位 rowid>{wm_rowid}{}):",
                r.data.len(),
                if args.no_advance { " · 预览不推进" } else { "" }
            );
            for row in &r.data {
                let dt = row["datetime"].as_str().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let who = row["sender_wxid"].as_str().unwrap_or("?");
                let body = msg_body_preview(row["msg_type_name"].as_str(), row["text_content"].as_str(), 40);
                println!("[{dt}] {conv}  {who}  {body}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    // 推进水位 (除非 --no-advance; 有新消息才写)。R14: 存 {rowid, gen(L1代号)} 供下轮 代号 + max 双信号校验 (不再存 src/nid
    // 身份 —— 身份校验在 REPLACE 换位时误重置, 已由 max(rowid) 护栏取代)。cur_gen=None(旧库)→ "gen":null, 下轮读 as_str→None。
    if !args.no_advance {
        if let Some(rid) = new_wm {
            let wm_json = serde_json::json!({ "rowid": rid, "gen": cur_gen });
            std::fs::write(&wm_path, wm_json.to_string())
                .with_context(|| format!("写水位文件失败 {}", wm_path.display()))?;
        }
    }
    Ok(())
}

#[derive(Args)]
struct FollowupsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 最多列几条 (按最后消息时间倒序)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 只看私聊 (排除群聊; "对方问了没答"更常在一对一)。
    #[arg(long, default_value_t = false)]
    private_only: bool,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `followups` — 漏回会话 (读 L1 message; 只读)。查数+json+meta 在核 `followups_query`, 此薄壳只呈现。
/// table who (发送人回退 "?") + msg_body_preview (XML/空/截断装饰) 留皮, 读**核 json** 的字段。
async fn cmd_followups(args: &FollowupsArgs) -> Result<()> {
    // R16-6 双模: 冷 followups_query 读 L1 message JOIN; 热 hot_followups 全扫源库聚合(较慢)。offset 恒 0(此命令不翻页)。
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            native_query::followups_query(&conn, args.private_only, args.limit, 0).context("查漏回会话失败")?
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
            native_query::hot_followups(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None,
                args.private_only,
                args.limit,
                0,
                None,
            )
            .await
            .context("实时查漏回会话失败 (账号 key 缓存了? 数据目录对? 全扫较慢)")?
        }
    };
    match args.format {
        OutFormat::Table => {
            let total = r.meta.total_count.unwrap_or(0);
            eprintln!(
                "漏回会话 {total} 个 (对方最后说话我没回{}; 取前 {}):",
                if args.private_only { " · 仅私聊" } else { "" },
                args.limit
            );
            for row in &r.data {
                let dt = row["datetime"].as_str().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let who = row["last_sender_wxid"].as_str().unwrap_or("?");
                let body = msg_body_preview(row["msg_type_name"].as_str(), row["text_content"].as_str(), 40);
                println!("[{dt}] {conv}  {who}  {body}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct WipeArgs {
    /// 真删 (不给只预演, 列出会删什么但不动手)。
    #[arg(long, default_value_t = false)]
    yes: bool,
    /// 保留 key 缓存 (只清日志/temp; 不用重新 auth)。
    #[arg(long, default_value_t = false)]
    keep_keys: bool,
}

/// 导出类命令的收尾: 按**真实产出**决定图标和退出码, 而不是"跑完了就打勾"。
///
/// # 为什么要有这个
///
/// 六个导出命令 (`decrypt-images` / `export-videos` / `export-voices` / `decrypt-emoji` /
/// `export-sns-media` / `media-ingest`) 原先**一个文件都没导出来也打 ✅ 并返回 0**。
/// 实测: 扫到 5512 条视频、落盘 0 个文件, 照样显示成功、退出码 0。
/// 真实信息藏在旁边一行小字里 (`落 0 / 失败 5512`), 但人先看到的是那个勾;
/// 写脚本调用的人更惨 —— 程序对外报告"成功", 脚本判断不出失败。
///
/// # 判据 (用户 2026-07-29 明确选了彻底版: **连退出码一起改**)
///
/// | 情况 | 图标 | 退出码 |
/// |---|---|---|
/// | 有产出、无失败 | ✅ | 0 |
/// | 有产出、有失败 | ⚠️ | **非 0** |
/// | 零产出、有失败 | 🛑 | **非 0** |
/// | 零产出、零失败, 但源文件已不在 (`unavailable`) | ✅ | 0 |
/// | 压根没东西可导 (`attempted == 0`) | ✅ | 0 |
///
/// **`unavailable` 那一档是关键**: 微信会自动清理旧媒体, 文件在数据库里有记录但盘上没有了。
/// 这种"扫到 5512 条、全都已清理"**不是失败** —— 工具没坏, 重试也没用, 报错只会让人白折腾。
/// 但也不能装作导成功了, 所以文案要说清"都被微信清理了"。
/// (没有这一档的话, 这个再正常不过的场景会被判成 🛑 全失败。)
///
/// **这是对外行为变更**: 已有脚本若靠"退出码 0 = 跑过了"判断, 行为会变。
/// 每个命令的 `--help` 里都写了这一条。
///
/// `hint` 是失败时给用户的下一步提示 (各命令的失败原因不同, 由调用方给)。
fn export_outcome(attempted: u64, produced: u64, failed: u64, unavailable: u64, what: &str, hint: &str) -> Result<()> {
    if failed > 0 {
        let head = if produced == 0 {
            format!("{what}: 扫到 {attempted} 个但一个也没导出来")
        } else {
            format!("{what}: 导出 {produced} 个, 但有 {failed} 个失败")
        };
        return Err(cli_err(
            native_core::ErrorCode::Internal,
            format!("{head} (失败 {failed})。{hint}"),
        ));
    }
    // 零失败零产出: 要么本来就没东西可导, 要么源文件都被微信清理了 —— 都不是错。
    let _ = (attempted, produced, unavailable);
    Ok(())
}

/// wipe 固定目标 (工具自身痕迹, 非 temp 部分): (路径, 说明, 是否 key 缓存)。
/// base = %LOCALAPPDATA%\msgvestige (= config 默认路径的父目录)。
fn wipe_fixed_targets(base: &Path, keep_keys: bool) -> Vec<(PathBuf, &'static str, bool)> {
    let mut t: Vec<(PathBuf, &'static str, bool)> = Vec::new();
    if !keep_keys {
        t.push((base.join("cache").join("keys.enc"), "key 缓存 (删了要重新 auth)", true));
        // image_keys.enc 原先漏了 —— wipe 承诺「清工具自身本地痕迹」, 漏一个缓存文件
        // 就是留了痕迹。它跟 keys.enc 同目录、同性质 (cache::ImageKeyCache 写的图片 AES key),
        // 且同样受 --keep-keys 保护: 两个都是"删了要重新取"的密钥缓存, 语义一致。
        // (审查方拿快速开始文档的「怎么卸干净」跟 wipe 实际输出对拍时逮到的: 文档列了它, wipe 没删。)
        t.push((
            base.join("cache").join("image_keys.enc"),
            "图片 key 缓存 (删了要重新扫)",
            true,
        ));
    }
    t.push((base.join("logs"), "日志目录", false));
    t.push((base.join("data"), "数据目录 (若有)", false));
    t
}

/// `wipe` — 清工具自身本地痕迹 (key缓存/日志/temp 水位+定位)。默认预演, --yes 才真删。
/// **绝不碰用户的 L1 db / 导出文件** (那些是用户指定路径, 不在工具痕迹里)。
fn cmd_wipe(args: &WipeArgs) -> Result<()> {
    // base = config 默认路径 (…/msgvestige/config.toml) 的父目录 = …/msgvestige。
    let base = native_core::config::default_config_path()
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let mut plan = wipe_fixed_targets(&base, args.keep_keys);
    // temp 里的 new 水位 + query 定位文件 (前缀匹配, 只删本工具产的)。
    let tmp = std::env::temp_dir();
    if let Ok(rd) = std::fs::read_dir(&tmp) {
        for e in rd.flatten() {
            let path = e.path();
            let n = e.file_name().to_string_lossy().into_owned();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            // codex-R10 P2: **精确**匹配生成器格式 `msgvestige_new_wm{,2}_<16 hex>.txt` 且是**文件**(非目录) —— 原松前缀
            // `starts_with("msgvestige_new_wm")` 会误匹配 `msgvestige_new_wm2_backup.txt`、甚至同名**目录**(下面走
            // remove_dir_all 递归删)。覆盖 wm_ / wm2_ / 未来版本号, 但严格 16 位十六进制 stem + .txt + is_file 三重闸。
            let is_wm = path.is_file()
                && n.strip_prefix("msgvestige_new_wm")
                    .and_then(|s| s.strip_prefix("2_").or_else(|| s.strip_prefix('_')))
                    .and_then(|s| s.strip_suffix(".txt"))
                    .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
            // Claude-R11 P3: 同 is_wm 补 `is_file()` —— 否则名为 `wxquery_locator_*.json` 的**目录**会被下方 remove_dir_all
            // 递归删。定位文件恒是文件, 加闸不影响正常清理, 只挡住同名目录误删。
            let is_loc = path.is_file() && n.starts_with("wxquery_locator_") && ext.eq_ignore_ascii_case("json");
            // R16-5 Claude P2: **热** `new` 逐分片水位文件 `msgvestige_new_hotwm_<16hex>.json` —— 前缀 `..._hotwm_`
            // 第 15 字符 `h`≠`w` 故 is_wm(`..._new_wm`)不匹配、扩展名 `.json`≠`.txt` 双重漏网。补独立闸(同 16 位 hex + is_file),
            // 否则 `wipe` 清冷水位却漏清热水位 = 用户以为重置了 new 进度实际热 new 下轮仍续旧水位 (与"修按判据全扫"同型)。
            let is_hotwm = path.is_file()
                && n.strip_prefix("msgvestige_new_hotwm_")
                    .and_then(|s| s.strip_suffix(".json"))
                    .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
            // 五轮审查 P1: **`watch` 的观察用临时库** `%TEMP%\wxwatch-<pid>\watch_tmp_l1.db`。
            // 不加 `--to-l1` 时(**默认**的观察模式)每次 watch 都建一个, 里面是**解密后的明文
            // 聊天记录** —— 实测一次 8 秒的 watch 就留下 1.62 GB / 29 万条消息, 外加 -wal/-shm。
            // 清理只在循环正常 return 时跑, 而 CLI watch 没有优雅关停信号、`--secs` 默认 0 = 永久
            // ⇒ **照 --help 说的方式 (Ctrl-C) 停就必然遗留**。
            // 而 wipe 原先完全看不见它: 三个闸子只认文件、且都是 msgvestige_/wxquery_ 前缀。
            // 这是本轮同型判据(「wipe 的清单 vs 实际会写的所有位置」)最严重的一处漏网 ——
            // 漏掉的偏偏是最大、最敏感的那个。用 is_dir 单独收, 下方走 remove_dir_all。
            let is_watch_tmp = path.is_dir()
                && n.strip_prefix("wxwatch-")
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
            if is_watch_tmp {
                plan.push((path, "watch 临时库 (含明文聊天记录)", false));
            } else if is_wm || is_loc || is_hotwm {
                plan.push((path, "临时文件 (水位/定位)", false));
            }
        }
    }

    if args.yes {
        eprintln!("清除工具本地数据 (base={}):", base.display());
    } else {
        eprintln!("预演 — 以下会被删 (加 --yes 才真删; base={}):", base.display());
    }
    let mut existed = 0usize;
    let mut removed = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for (path, desc, _is_key) in &plan {
        if !path.exists() {
            continue;
        }
        existed += 1;
        println!("  ● {desc}  {}", path.display());
        if args.yes {
            let res = if path.is_dir() {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_file(path)
            };
            match res {
                Ok(()) => removed += 1,
                // 日志目录里有本进程正打开的日志文件 → 删不掉是正常的, 如实报不当失败。
                Err(e) => failed.push(format!("{} ({e})", path.display())),
            }
        }
    }
    if existed == 0 {
        eprintln!("没有可清的本地数据 (工具痕迹已干净)。");
    } else if args.yes {
        eprintln!("已删 {removed}/{existed} 项。");
        if !failed.is_empty() {
            eprintln!("以下删不掉 (多半是本进程正打开的日志, 退出后再跑一次即可):");
            for f in &failed {
                eprintln!("  ⚠️ {f}");
            }
        }
    } else {
        eprintln!(
            "共 {existed} 项存在。加 --yes 真删{}。",
            if args.keep_keys {
                ""
            } else {
                " (含 key 缓存 → 之后要重新 auth; 想保留加 --keep-keys)"
            }
        );
    }
    Ok(())
}

/// `version` — 打印版本 + 平台/架构 (装机排查第一步; 无需 key / 库)。
fn cmd_version() -> Result<()> {
    println!("msgvestige {} (alpha)", env!("CARGO_PKG_VERSION"));
    println!("平台: {} / {}", std::env::consts::OS, std::env::consts::ARCH);
    Ok(())
}

/// `exec` — 只读 SQL 逃生口 (读 L1; 只读连接 + SELECT 白名单双保险)。守卫/取数/json 出口在核
/// (`is_readonly_sql`/`run_exec_query`/`exec_query`); 此薄壳: 守卫 pre-check(在 `open_l1` **前**拒写 →
/// 坏路径/写 SQL 不打库即 BAD_REQUEST/2) + 按 format 呈现。**table 走 `run_exec_query` 有序 cols/行保 SQL
/// 列序** (json 的排序 Map 丢列序), json 走 `exec_query`。
async fn cmd_exec(args: &ExecArgs) -> Result<()> {
    if !native_query::is_readonly_sql(&args.sql) {
        // 参数非法 → BAD_REQUEST(退出2), 不是 INTERNAL/70 (信封审: 语义校验错该给类型码)。守卫须在开库前:
        // 写 SQL / 坏路径不打库即拒 (cmd_exec_write_emits_bad_request_exit2 契约)。冷热两路都先过这道。
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "只允许只读查询 (SELECT / WITH / EXPLAIN), 且不能含分号分隔的多条语句",
        ));
    }
    // R16-6 双模: 冷 exec 跑 L1 **投影** schema; 热 exec 跑源库**原始**裸 schema (--source-db 选库, exec_hardened_vfs
    // VFS 按需解密 + 同一套硬只读+DoS界)。
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            match args.format {
                OutFormat::Table => {
                    let (cols, out_rows, truncated) = native_query::run_exec_query(&conn, &args.sql, args.max_rows)?;
                    println!("{}", cols.join(" | "));
                    for r in &out_rows {
                        let line: Vec<String> = r.iter().map(native_query::sql_value_display).collect();
                        println!("{}", line.join(" | "));
                    }
                    eprintln!(
                        "({} 行{})",
                        out_rows.len(),
                        if truncated {
                            format!(", 已截断 — 超过 --max-rows {}, 请加 LIMIT 或调大", args.max_rows)
                        } else {
                            String::new()
                        }
                    );
                }
                OutFormat::Json => {
                    let r = native_query::exec_query(&conn, &args.sql, args.max_rows)?;
                    emit_envelope(&r.data, r.meta)?;
                }
            }
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            let Some(source_db) = args.source_db.as_deref() else {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "热查 exec (--mode hot) 要 --source-db 指定源库 (db_storage 下相对路径, 如 contact/contact.db / message/message_0.db); 冷查 exec 读 L1 不用",
                ));
            };
            let r = native_query::hot_exec(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                source_db,
                &args.sql,
                args.max_rows,
                None,
            )
            .await
            .context("热查 exec 失败 (源库路径对? 账号 key 缓存了? SQL 只读?)")?;
            match args.format {
                OutFormat::Table => {
                    // 热查返 QueryResult(json 行); 渲染成表 (列取自首行键, 顺序为 json map 序)。
                    if let Some(first) = r.data.first().and_then(serde_json::Value::as_object) {
                        let cols: Vec<String> = first.keys().cloned().collect();
                        println!("{}", cols.join(" | "));
                        for row in &r.data {
                            if let Some(obj) = row.as_object() {
                                let line: Vec<String> = cols
                                    .iter()
                                    .map(|c| {
                                        native_query::json_value_display(obj.get(c).unwrap_or(&serde_json::Value::Null))
                                    })
                                    .collect();
                                println!("{}", line.join(" | "));
                            }
                        }
                    }
                    // run_exec_query 满 max_rows 即截断 → data.len()==max_rows 作截断信号 (启发, 不依赖 Meta 具体字段)。
                    let truncated = r.data.len() >= args.max_rows;
                    eprintln!(
                        "({} 行{}; 热查源库 {source_db})",
                        r.data.len(),
                        if truncated {
                            format!(", 可能已截断 — 达 --max-rows {}, 请加 LIMIT 或调大", args.max_rows)
                        } else {
                            String::new()
                        }
                    );
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
        }
    }
    Ok(())
}

#[derive(Args)]
struct ExtractArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 抽哪类 (url / email / amount / phone / idcard; 一次一类)。
    #[arg(long, value_enum)]
    kind: ExtractKind,
    /// 最多列几条命中 (真总数仍报全量)。
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `extract` — 从文本消息抽结构化信息 (读 L1 message; 只读; 不打码)。抽取 + json + meta 都在核
/// `extract_query`; 此薄壳只按 format 呈现: table 表头/命中数读 `meta.summary` + `extract_kind_label`,
/// 数据行读**核 json** 的 value (table 皮再截 80 字装饰)。
async fn cmd_extract(args: &ExtractArgs) -> Result<()> {
    // R16-5: 冷热双模 (冷 extract_query 读 L1; 热 hot_extract 全扫 msg1 + 纯函数 extract_matches)。offset 0 (extract 不翻页)。
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::extract_query(&conn, args.kind, args.limit, 0).context("抽取失败")?;
            // R16-5 复审 (Claude P2): 冷分支挂 cold_freshness (三皮 meta 契约; 热分支已带 Freshness::Hot)。
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
            native_query::hot_extract(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.kind,
                args.limit,
                0,    // offset
                None, // scan_permit
            )
            .await
            .context("实时抽取失败 (账号 key 缓存了? 数据目录对?)")?
        }
    };
    match args.format {
        OutFormat::Table => {
            let label = native_query::extract_kind_label(args.kind);
            let msgs = summary_i64(&r.meta, "messages_matched");
            let total = summary_i64(&r.meta, "total_matches");
            eprintln!("抽取[{label}]: {msgs} 条消息命中 (共 {total} 个); 取前 {}", args.limit);
            for row in &r.data {
                let day = row["date"].as_str().unwrap_or_default();
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let who = row["sender_wxid"].as_str().unwrap_or("?");
                let val: String = row["value"].as_str().unwrap_or_default().chars().take(80).collect();
                println!("[{day}] {conv}  {who}  {val}");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ConfigAction {
    /// 看生效配置 (日志级别/目录/metrics)。
    Show,
    /// 看配置文件在哪 (存不存在)。
    Path,
}

#[derive(Args)]
struct ConfigArgs {
    /// 动作: show (看生效配置, 默认) / path (看配置文件路径) / set (设持久默认档)。
    /// (普通 String 位置参而非 value_enum —— clap 不支持 value_enum 位置参后再跟 KEY/VALUE 位置参。)
    #[arg(default_value = "show")]
    action: String,
    /// `set` 的键: `tier`(四档友好名, 推荐) 或 `live-index`(规范值, 兼容)。位置参: `config set tier 快搜`。
    #[arg(value_name = "KEY")]
    key: Option<String>,
    /// `set` 的值: tier 键用 裸跑/快搜/冷库/全速 (或 off/thin/cold/full); live-index 键用 off/thin/cold/full。设档后打印手动生效指引 (声明式, 不自动建库)。位置参。
    #[arg(value_name = "VALUE")]
    value: Option<String>,
    /// `set live-index` 时: 只设某账号默认档 (per-account 覆盖); 不给 = 设全局默认。
    #[arg(long)]
    account: Option<String>,
    /// 配置文件路径 (缺省 = 默认 %LOCALAPPDATA%\msgvestige\config.toml)。
    #[arg(long)]
    config: Option<String>,
    /// 输出格式 (table / json; show 时用)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LogsAction {
    /// 把日志 + 配置 + 版本/OS 打成一个 zip (内测报 bug 用; 已脱敏)。
    Bundle,
}

#[derive(Args)]
struct LogsArgs {
    /// 动作: bundle (打诊断包; 目前唯一动作)。
    #[arg(value_enum, default_value_t = LogsAction::Bundle)]
    action: LogsAction,
    /// 输出 zip 路径 (缺省 = ./native-logs-bundle-<时间戳>.zip)。
    #[arg(long)]
    out: Option<String>,
    /// 只收最近 N 天日志 (缺省 = 全部, 最多留 14 天)。
    #[arg(long)]
    days: Option<u32>,
    /// 配置文件路径 (缺省 = 默认 %LOCALAPPDATA%\msgvestige\config.toml)。
    #[arg(long)]
    config: Option<String>,
}

/// `logs bundle` — 打日志诊断包 (⑧ R2)。收 已脱敏日志 + 版本/OS + (脱敏)config.toml → zip。
/// K-R4: 不收 key 缓存/明文 key; config 里 auth_password 打码; 明文 wxid 兜底擦除 (见 logs_bundle 模块)。
fn cmd_logs(args: &LogsArgs) -> Result<()> {
    match args.action {
        LogsAction::Bundle => cmd_logs_bundle(args),
    }
}

fn cmd_logs_bundle(args: &LogsArgs) -> Result<()> {
    // 配置: 拿 log_dir + (存在则)打进包。
    let config_path = args
        .config
        .as_deref()
        .map_or_else(native_core::config::default_config_path, PathBuf::from);
    let cfg = native_core::config::load_or_default(&config_path);
    let obs = &cfg.observability;

    // log_dir 里可能是 %LOCALAPPDATA% 占位, 展开成真实路径去收日志。
    let log_dir = PathBuf::from(common::log::expand_env(&obs.log_dir));
    let log_files = logs_bundle::collect_log_files(&log_dir, args.days);

    // 输出路径: 默认带时间戳 (不覆盖旧包)。
    let now = chrono::Local::now();
    let out = args.out.as_deref().map_or_else(
        || PathBuf::from(format!("native-logs-bundle-{}.zip", now.format("%Y%m%d-%H%M%S"))),
        PathBuf::from,
    );

    // info.txt: 版本/系统/时间/日志范围 + 脱敏说明。
    let file_list = if log_files.is_empty() {
        "(无)".to_string()
    } else {
        log_files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let info = format!(
        "msgvestige 日志诊断包\n\
         生成时间 : {}\n\
         版本     : {}\n\
         系统/架构: {} / {}\n\
         日志目录 : {}\n\
         日志级别 : {}\n\
         日志文件 : {} 个 [{}]\n\
         \n\
         【脱敏说明】本包不含 key 缓存 / 明文 master key; config 里 auth_password/默认账号等敏感字段已打码;\n\
         日志在写入时按 K-R4 脱敏 (wxid 显示为 sha8 指纹, master key 不打印), 打包时又对明文\n\
         wxid_ 形态做了一层兜底擦除。可放心发给开发者排 bug。\n",
        now.format("%Y-%m-%d %H:%M:%S %z"),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        log_dir.display(),
        obs.log_level,
        log_files.len(),
        file_list,
    );

    // config.toml: 存在才收, 且脱敏 (auth_password 打码)。
    let config_text = if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(t) => Some(logs_bundle::redact_config(&t)),
            Err(e) => {
                eprintln!("⚠️  读 config.toml 失败, 跳过 ({e})");
                None
            }
        }
    } else {
        None
    };
    let had_config = config_text.is_some();

    let report = logs_bundle::build_bundle(&info, &log_files, config_text, &out)?;

    println!("{}", report.out_path.display());
    eprintln!(
        "✅ 日志诊断包已生成: 收了 {} 个日志文件 + info.txt{} (未压缩 {} KB)。",
        report.log_file_count,
        if had_config { " + config.toml(脱敏)" } else { "" },
        report.total_uncompressed / 1024,
    );
    eprintln!("   包内容: {}", report.entries.join(", "));
    if report.wxid_scrubbed > 0 {
        eprintln!(
            "⚠️  发现并擦除了 {} 处明文 wxid — 包里已打码, 但这说明某处日志写入漏了脱敏 (K-R4), 请连同本包告知开发者。",
            report.wxid_scrubbed
        );
    }
    for w in &report.warnings {
        eprintln!("⚠️  {w}");
    }
    if report.log_file_count == 0 {
        eprintln!("   (log_dir 下暂无 native.log* — 可能还没跑过命令, 或 log_dir 指向别处。)");
    }
    Ok(())
}

/// R20 声明式四档: 设档 (`config set tier`) 后打印"接下来手动跑什么"的指引。**绝不自动触发**建库/watch/全量扫 ——
/// 建库是小时级重活 (R14 重建实测数小时), 一句切档偷偷触发太危险 (用户 2026-07-20 定案)。命令里 `<...>` 由用户填路径。
fn tier_declarative_guidance(tier: &str) -> String {
    match tier {
        "off" => "裸跑档: 无索引库, 直接热查 (如 `search --mode hot` / 各查询命令直读源库), 无需额外命令。".to_string(),
        "thin" => "快搜档 (声明式, 需手动跑, 不自动触发): 首建 `live-index build --tier thin --l1-db <L1> --thin-db <瘦库>`; \
                   常驻维护 `watch --live-index thin --thin-db <瘦库> --wxid <WXID>`。"
            .to_string(),
        "cold" => "冷库档 (声明式, 需手动跑): 建库 `ingest --all --l1-db <L1> --wxid <WXID>` 一次, 之后各查询命令 `--l1-db <L1>` 冷查。\
                   静态不实时维护 (要最新则重 ingest, 或改用 全速 档)。"
            .to_string(),
        "full" => "全速档 (声明式, 需手动跑): 首建 `ingest --all --l1-db <L1> --wxid <WXID>`; \
                   常驻实时维护 `watch --live-index full --to-l1 --l1-db <L1> --wxid <WXID>`。"
            .to_string(),
        _ => String::new(),
    }
}

/// `config` — 看设置 (config.toml; 只读)。show=生效配置, path=配置文件位置。改设置=编辑 config.toml (启动生效)。
#[derive(Args)]
struct CaptureArgs {
    /// 动作: list (看当前采集清单, 默认) / add (圈定采某会话) / rm (停采某会话)。
    /// (普通 String 位置参: `capture add <CONV_ID>`; 照 config 模式, 非 value_enum 以便后跟位置参。)
    #[arg(default_value = "list")]
    action: String,
    /// 会话标识 (add/rm 用): 单聊填对方 wxid, 群填 `xxx@chatroom`。位置参: `capture add wxid_abc`。
    #[arg(value_name = "CONV_ID")]
    conv_id: Option<String>,
    /// L1 库路径 (采集清单 capture_targets 存这里; add/rm 写、list 读)。
    #[arg(long)]
    l1_db: String,
    /// 目标账号 wxid (多账号 L1 必给; 单账号库可省, 自动检测唯一账号)。
    #[arg(long)]
    account: Option<String>,
    /// add 时可选备注 (谁/为什么圈; 存 note 列)。
    #[arg(long)]
    note: Option<String>,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// R19: 解析 capture 目标账号的 `account_id_sha` (CLI 层: 校验 wxid + 空库→报错要 `--account`)。
/// 具体 sha 解析走三皮共享 [`native_query::resolve_capture_account_sha`] (单账号库返真实 sha, 非 `None`)。
fn resolve_capture_account(l1_db: &str, explicit: Option<&str>) -> Result<String> {
    if let Some(w) = explicit {
        if w.parse::<Wxid>().is_err() {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "--account 非法 (须合法微信 wxid)".to_string(),
            ));
        }
    }
    native_query::resolve_capture_account_sha(l1_db, explicit.map(str::to_string))?.ok_or_else(|| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "L1 库无数据、无法自动确定账号; 请用 --account <你的wxid> 指定".to_string(),
        )
    })
}

/// 校验 L1 存在 (add/rm 前; 防 `Connection::open` 对错路径**新建空库**)。
fn capture_ensure_l1(l1_db: &str) -> Result<()> {
    if !std::path::Path::new(l1_db).is_file() {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("--l1-db {l1_db} 不存在 (capture 圈定存进已建的 L1; 先 `ingest` 建库)"),
        ));
    }
    Ok(())
}

/// 读写打开 L1 (capture add/rm 写 capture_targets)。**不夺 `acquire_watch_lock` OS 锁** —— capture 是配置写、非
/// L1 维护, 要能在 watch 运行中改采集目标; 与 watch 的写靠 SQLite WAL 单写者 + `busy_timeout` 串行 (防 SQLITE_BUSY 立即失败)。
fn capture_open_l1_write(l1_db: &str) -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open(l1_db)
        .map_err(|e| cli_err(native_core::ErrorCode::BadRequest, format!("打不开 L1 db {l1_db}: {e}")))?;
    conn.busy_timeout(std::time::Duration::from_secs(30))
        .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("设 busy_timeout 失败: {e}")))?;
    // 审 round-2 P2: 写前坐实是真 L1 —— 防 typo 的 --l1-db 指向无关 sqlite 库时 capture add 在那 CREATE capture_targets + 写行污染。
    // 查核心表 raw_payload_archive (每个 ingest 产出的 L1 必有, init_l1_schema 建; 非 sqlite → query 报错 → false)。缺 = 非 L1 → 拒。
    let is_l1 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='raw_payload_archive'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);
    if !is_l1 {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("--l1-db {l1_db} 不是有效 L1 库 (缺 raw_payload_archive; 确认路径指向 ingest 产出的 L1, 别误指其它 sqlite 文件)"),
        ));
    }
    // 审 round-7/10 P2: schema 版本 + 新鲜度门禁 —— 与写侧 `init_l1_schema` (storage.rs:51-57) **逐字对齐**, 使
    // capture 写入接受的库集 == ingest/watch 写入接受的库集 (否则 capture add 报成功、下次 ingest 却 SCHEMA_MISMATCH 拒
    // = 写接受读拒不一致)。init 判据: `is_fresh = 无版本 meta 且无 message 表` (真空首建放行); `stored != 当前版本 && !is_fresh → 拒`。
    // 覆盖两类被 init 拒的库: (a) 有版本 meta 但过时 (round-7); (b) **无版本 meta 但已有 message 表** = versionless-legacy
    // 旧库 (round-10 codex P2: 我 round-7 只判 Some(v)!=VERSION, 漏了 stored=None+有 message 这类 init 也拒的旧库)。
    let stored = native_core::storage::get_meta(&conn, native_core::storage::META_KEY_VERSION)
        .ok()
        .flatten();
    let has_msg_table = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='message'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);
    let is_fresh = stored.is_none() && !has_msg_table; // 真空首建 (无版本 + 无 message) → 放行, 同 init。
    if stored.as_deref() != Some(native_core::storage::SCHEMA_VERSION) && !is_fresh {
        return Err(cli_err(
            native_core::ErrorCode::SchemaMismatch,
            format!(
                "L1 库 schema 版本不符 (库 {stored:?}, 需 {}): capture 写入与 ingest/list 一致拒旧库 (避免 add 成功却下次 \
                 ingest 报 SCHEMA_MISMATCH)。请删掉此 L1、从加密源全量重建后再改采集目标。",
                native_core::storage::SCHEMA_VERSION
            ),
        ));
    }
    Ok(conn)
}

/// add/rm 取会话标识 (缺/空 → 报错)。
fn capture_require_conv(args: &CaptureArgs) -> Result<&str> {
    let conv = args
        .conv_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                format!("capture {} 需给会话标识 (单聊 wxid / 群 xxx@chatroom)", args.action),
            )
        })?;
    // 审 round-3/6 P2: 用 `Wxid::try_new` 校验 conv_id —— 它是微信 UserName 的**单一真相**校验 (接受 wxid_/自定义/gh_/
    // @chatroom/系统号, 拒**空白/控制符/超长 >128**; 见 config.rs 同款委托)。conv_id 正是这些 UserName 之一。typo (含空白/
    // 控制/超长) 会激活**不可命中**的白名单 → 后续 ingest/watch 跳过所有会话却报成功。不用严格"必 wxid_"(会误拒群/公众号/legacy)。
    if conv.parse::<native_core::Wxid>().is_err() {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("会话标识非法 (须合法微信 UserName: 单聊 wxid / 群 xxx@chatroom / gh_ 公众号 等, ≤128 无空白控制符): {conv:?}"),
        ));
    }
    Ok(conv)
}

/// R19 选择性采集 — `capture list/add/rm`。圈定的会话存 L1 的 `capture_targets`; `run_message_body` drain 前只采圈定
/// 会话 (没圈=全采)。**声明式** (照 R20): add/rm 只改 capture_targets, **不自动触发** watch/建库 (watch 下次任一 source
/// 变化触发时读到; --print 观察读启动快照)。三皮里 **CLI 管全增删查, MCP/HTTP 只 list** (只读服务不变量 + R20 config-CLI-only 先例)。
fn cmd_capture(args: &CaptureArgs) -> Result<()> {
    match args.action.as_str() {
        "list" => {
            // 审 round-12 P2 (codex+Claude 收敛): CLI list 也坐实是 L1 —— 与三皮 capture_targets_query 共享 ensure_l1_marker,
            // 别对非 L1/无关 sqlite 误报"空清单=全采"(写侧 capture add/rm 已拒非 L1, 读侧 list 须一致; round-11 只修了
            // capture_targets_query 的 None 分支, 漏了 CLI list 整条自建流程 + 显式账号 Some 分支)。
            {
                let c = native_query::open_l1(&args.l1_db)?;
                native_query::ensure_l1_marker(&c)?;
            }
            // 审 round-1 P3: list 容忍无账号 —— 空库无账号 → 空清单 (与 MCP/HTTP 一致, 非报错); 多账号未指定仍 Err(Ambiguous)。
            let sha = native_query::resolve_capture_account_sha(&args.l1_db, args.account.clone())?;
            let acct8 = sha
                .as_deref()
                .map_or_else(|| "—".to_string(), |s| s.get(..8).unwrap_or(s).to_string());
            let list = match &sha {
                Some(s) => {
                    let conn = native_query::open_l1(&args.l1_db)?; // 只读
                    native_core::capture::list_capture_targets(&conn, s)
                        .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("读采集清单失败: {e}")))?
                }
                None => Vec::new(), // 空库无账号 → 空清单 (全采)
            };
            match args.format {
                OutFormat::Json => {
                    let rows: Vec<serde_json::Value> = list
                        .iter()
                        .map(|t| serde_json::json!({"conv_id": t.conv_id, "added_at": t.added_at, "note": t.note}))
                        .collect();
                    let n = rows.len();
                    // 审 round-8 codex P2: json 也填 meta.account=sha8 —— 与 HTTP (capture_targets_query) + 下方 table 的
                    // acct8 一致, 空清单也能归属账号。print_query_json 不带 account, 故此处直接 emit_envelope 建带 account 的 meta。
                    let mut meta = Meta::page(n, n).with_source(Source::Cold);
                    if let Some(s) = &sha {
                        meta.account = Some(s.get(..8).unwrap_or(s).to_string());
                    }
                    emit_envelope(&rows, meta)?;
                }
                OutFormat::Table => {
                    if list.is_empty() {
                        eprintln!("采集清单为空 (账号 {acct8}) → 全采所有会话。");
                        eprintln!("(圈定: `capture add <会话wxid或群@chatroom> --l1-db {}`)", args.l1_db);
                    } else {
                        eprintln!(
                            "采集清单 (账号 {acct8}, 共 {} 个 → ingest/watch 只采这些会话):",
                            list.len()
                        );
                        for t in &list {
                            let note = t.note.as_deref().map_or(String::new(), |n| format!("  # {n}"));
                            println!("{}{note}", t.conv_id);
                        }
                    }
                }
            }
            Ok(())
        }
        "add" => {
            let account_sha = resolve_capture_account(&args.l1_db, args.account.as_deref())?;
            let acct8 = account_sha.get(..8).unwrap_or(&account_sha).to_string();
            let conv_id = capture_require_conv(args)?;
            capture_ensure_l1(&args.l1_db)?;
            let conn = capture_open_l1_write(&args.l1_db)?;
            native_core::capture::init_capture_targets(&conn).map_err(|e| {
                cli_err(
                    native_core::ErrorCode::Internal,
                    format!("建 capture_targets 失败: {e}"),
                )
            })?;
            // 审 round-1 P3: 记 add 前该账号是否空 (空=当前全采) → 首圈醒目提示"全采→只采"翻转 (typo 误圈会静默总抑制)。
            let was_all = native_core::capture::read_capture_targets(&conn, &account_sha)
                .map(|o| o.is_none())
                .unwrap_or(false);
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_millis()).ok())
                .unwrap_or(0);
            native_core::capture::add_capture_target(&conn, &account_sha, conv_id, args.note.as_deref(), now_ms)
                .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("写采集清单失败: {e}")))?;
            let total = native_core::capture::list_capture_targets(&conn, &account_sha)
                .map(|v| v.len())
                .unwrap_or(0);
            if args.format == OutFormat::Json {
                print_query_json(
                    &[
                        serde_json::json!({"action": "add", "conv_id": conv_id, "account_sha8": acct8, "total_targets": total, "flipped_to_selective": was_all}),
                    ],
                    1,
                )?;
            } else {
                eprintln!("已圈定采集会话「{conv_id}」(账号 {acct8}); 当前采集 {total} 个会话。");
                if was_all {
                    eprintln!("⚠️ 首个圈定 → 从「全采所有会话」切到「只采圈定」, 其余会话今后停采 (确认 conv_id 无误; typo 会致只采不存在会话=几乎全停, 可再 rm 恢复)。");
                }
                // 审 round-2 P1: 诚实说清生效时机 —— 已写 capture_targets, 但**正在跑的 --print 观察用启动快照, 需重启才应用**。
                eprintln!("(生效: 下次 ingest / --to-l1 watch 从下次 source 变化起只采圈定; 正在跑的 `watch --print` 观察用启动快照、需重启。停采 `capture rm {conv_id}`; 清空=全采)");
            }
            Ok(())
        }
        "rm" => {
            let account_sha = resolve_capture_account(&args.l1_db, args.account.as_deref())?;
            let acct8 = account_sha.get(..8).unwrap_or(&account_sha).to_string();
            let conv_id = capture_require_conv(args)?;
            capture_ensure_l1(&args.l1_db)?;
            let conn = capture_open_l1_write(&args.l1_db)?;
            native_core::capture::init_capture_targets(&conn).map_err(|e| {
                cli_err(
                    native_core::ErrorCode::Internal,
                    format!("建 capture_targets 失败: {e}"),
                )
            })?;
            let removed = native_core::capture::remove_capture_target(&conn, &account_sha, conv_id)
                .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("改采集清单失败: {e}")))?;
            let total = native_core::capture::list_capture_targets(&conn, &account_sha)
                .map(|v| v.len())
                .unwrap_or(0);
            if args.format == OutFormat::Json {
                print_query_json(
                    &[
                        serde_json::json!({"action": "rm", "conv_id": conv_id, "removed": removed, "account_sha8": acct8, "total_targets": total}),
                    ],
                    1,
                )?;
            } else if removed {
                eprintln!("已停采会话「{conv_id}」(账号 {acct8}); 当前采集 {total} 个会话。");
                if total == 0 {
                    eprintln!("(清单已空 → 回到全采所有会话)");
                }
                // 审 round-2 P1: 同 add —— 正在跑的 --print 观察用启动快照, 需重启才反映停采。
                eprintln!("(生效: 下次 ingest / --to-l1 watch; 正在跑的 `watch --print` 观察需重启才反映)");
            } else {
                eprintln!("会话「{conv_id}」本就不在采集清单 (账号 {acct8}); 无改动。");
            }
            Ok(())
        }
        other => Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("capture 动作须 list/add/rm (给了 {other:?}); 用法: capture add <会话> --l1-db <L1>"),
        )),
    }
}

fn cmd_config(args: &ConfigArgs) -> Result<()> {
    let path = args
        .config
        .as_deref()
        .map_or_else(native_core::config::default_config_path, std::path::PathBuf::from);
    let exists = path.exists();
    match args.action.as_str() {
        "path" if args.format == OutFormat::Json => {
            // 契约审: --format json 须走 {data,meta}, 别裸 println 路径 (否则脚本 json.loads 崩)。
            print_query_json(
                &[serde_json::json!({"config_path": path.display().to_string(), "exists": exists})],
                1,
            )?;
        }
        "path" => {
            println!("{}", path.display());
            eprintln!(
                "({})",
                if exists {
                    "存在"
                } else {
                    "不存在 — 现在全用默认值; 建这个文件写 [observability] 段即可改日志设置"
                }
            );
        }
        "show" => {
            let cfg = native_core::config::load_or_default(&path);
            let obs = &cfg.observability;
            let src = if exists {
                path.display().to_string()
            } else {
                "默认值 (无配置文件)".to_string()
            };
            match args.format {
                OutFormat::Table => {
                    eprintln!("生效配置 (来源: {src}):");
                    println!("log_level       = {}", obs.log_level);
                    println!("log_dir         = {}", obs.log_dir);
                    println!("metrics_enabled = {}", obs.metrics_enabled);
                    // R9 复审 R2#7: config show 显示 live-index 持久默认档 (原来不显示, 用户看不到已设的档)。
                    let li = &cfg.live_index;
                    let li_def = if li.default.is_empty() {
                        "off"
                    } else {
                        li.default.as_str()
                    };
                    println!(
                        "live_index      = {li_def} (global 默认档; per-account 覆盖 {} 个)",
                        li.accounts.len()
                    );
                    eprintln!("(改日志设置编辑 [observability] 段; live-index 默认档用 `config set live-index`, 下次启动生效)");
                }
                OutFormat::Json => {
                    // §2 golden: data 须**数组** + 走标准信封 (信封审: 原 data=对象硬破 golden;
                    // meta.source 被塞成"配置来源"字符串非枚举)。config 是本地静态读 = source:cold
                    // (同 account/cache 约定); 配置来源/路径/存在性挪进 data (是关于配置本身的数据, 非 meta 标准字段)。
                    let li_def = if cfg.live_index.default.is_empty() {
                        "off".to_string()
                    } else {
                        cfg.live_index.default.clone()
                    };
                    let row = serde_json::json!({
                        "log_level": obs.log_level,
                        "log_dir": obs.log_dir,
                        "metrics_enabled": obs.metrics_enabled,
                        "live_index_default": li_def, // R9 复审 R2#7: 显示持久默认档
                        "live_index_account_overrides": cfg.live_index.accounts.len(),
                        "config_source": src,
                        "config_path": path.display().to_string(),
                        "config_exists": exists
                    });
                    print_query_json(&[row], 1)?;
                }
            }
        }
        "set" => {
            // R9 件3 + R20: `config set <key> <value> [--account <wxid>]` —— 写 [live_index] 持久档。两 key 写同一档:
            //   · `live-index`(旧兼容): 值 = 规范档 off/thin/cold/full。
            //   · `tier`(R20 四档): 值 = 友好名 裸跑/快搜/冷库/全速 (或英文规范), 经 tier_canonical 映射。
            // **声明式** (用户 2026-07-20 定案: 建库是小时级重活, 一句切档偷偷触发几小时建库太危险): 写档后**只打印
            // "接下来请手动跑 xxx"指引, 绝不自动触发**建库/watch/全量扫。
            let key = args.key.as_deref().unwrap_or_default();
            let raw = args.value.as_deref().unwrap_or_default();
            let canonical = match key {
                "live-index" => {
                    if !matches!(raw, "off" | "thin" | "cold" | "full") {
                        return Err(cli_err(
                            native_core::ErrorCode::BadRequest,
                            format!("live-index 档须 off/thin/cold/full (给了 {raw:?})"),
                        ));
                    }
                    raw.to_string()
                }
                "tier" => native_core::config::tier_canonical(raw)
                    .ok_or_else(|| {
                        cli_err(
                            native_core::ErrorCode::BadRequest,
                            format!("tier 须 ∈ 裸跑/快搜/冷库/全速 (或 off/thin/cold/full; 给了 {raw:?})"),
                        )
                    })?
                    .to_string(),
                _ => {
                    return Err(cli_err(
                        native_core::ErrorCode::BadRequest,
                        format!(
                            "config set 支持 key=tier|live-index (给了 {key:?}); \
                             用法: config set tier 裸跑|快搜|冷库|全速 [--account <wxid>]"
                        ),
                    ));
                }
            };
            // account 若给须合法 wxid (与 watch/serve 同一套校验)。
            if let Some(acc) = &args.account {
                if acc.parse::<Wxid>().is_err() {
                    return Err(cli_err(
                        native_core::ErrorCode::BadRequest,
                        "--account 非法 (须合法微信 wxid)".to_string(),
                    ));
                }
            }
            native_core::config::set_live_index_tier(&path, &canonical, args.account.as_deref())
                .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("写 config 失败: {e}")))?;
            // K-R4: 展示脱敏 —— account wxid 只出 sha8, 不出明文 (config.toml 文件里存明文是用户自己的文件)。
            let acc_sha8 = args
                .account
                .as_deref()
                .map(|a| native_core::sha256_hex(a)[..8].to_string());
            let guidance = tier_declarative_guidance(&canonical);
            if args.format == OutFormat::Json {
                print_query_json(
                    &[serde_json::json!({
                        "key": key,
                        "tier": canonical,
                        "scope": if args.account.is_some() { "account" } else { "global" },
                        "account_sha8": acc_sha8,
                        "config_path": path.display().to_string(),
                        "next_step": guidance, // R20 声明式: 手动指引 (机器可读; **不自动触发**)
                    })],
                    1,
                )?;
            } else {
                let scope = acc_sha8
                    .as_deref()
                    .map_or_else(|| "全局默认".to_string(), |s| format!("账号 {s} 默认"));
                eprintln!("已设 {key} {scope} = {canonical} (写入 {})", path.display());
                eprintln!("{guidance}"); // R20 声明式: 打印手动指引, 绝不自动触发建库/watch。
            }
        }
        other => {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                format!("未知 config 动作 {other:?} (须 show / path / set)"),
            ));
        }
    }
    Ok(())
}

#[derive(Args)]
struct ResolveArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 展开某条合并转发的子项 (给 message 的 source_native_id; 不给 = 列出所有合并转发消息供挑)。
    #[arg(long)]
    msg_id: Option<String>,
    /// 展开时精确定位分片 (消息 id 跨分片会重号, 用 list 结果里的 source 值; 省略且不重号时可不填)。
    #[arg(long)]
    source: Option<String>,
    /// 列表模式取前几 / 展开模式取前几子项。
    #[arg(short = 'n', long, default_value_t = 20)]
    limit: usize,
    /// 跳过前 N 条 (翻页; 冷热都吃)。
    #[arg(long, default_value_t = 0, help = "跳过前 N 条 (翻页用)")]
    offset: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `resolve` — 展开合并转发 (读 L1 message_forward_item; 只读)。双模式查数/NOT_FOUND/json+meta 在核
/// `resolve_query`(`--msg-id` 展开查无→退出3; 列表供挑 id); 此薄壳按 format 呈现: table 读 `r.data`
/// by key(`type_label` 已 baked) + `r.meta.total_count` 渲表头(preview 截断留皮), json 走信封。
async fn cmd_resolve(args: &ResolveArgs) -> Result<()> {
    let offset = args.offset.min(10_000_000);
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Hot => {
            // **R16-2 起冷热双模**: 热走 hot_resolve(scan msg49 + parse_forward, 展开点查/列表全收)。
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), offset, args.limit).await?; // R21 全扫成本门
            native_query::hot_resolve(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None, // locator_file
                args.msg_id.as_deref(),
                args.source.as_deref(),
                args.limit,
                offset,
                None, // scan_permit: CLI 一次性调用无并发
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::resolve_query(
                &conn,
                args.msg_id.as_deref(),
                args.source.as_deref(),
                args.limit,
                offset,
            )?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
    };
    match args.format {
        OutFormat::Table => {
            // R16-2: table_total(热查 total 在 summary.total_resolve; 冷查在 meta.total_count)。
            let total = table_total(&r.meta, "total_resolve").unwrap_or(0);
            if let Some(msg_id) = &args.msg_id {
                eprintln!("合并转发 {msg_id}: {total} 个子项 (取前 {}):", args.limit);
                for row in &r.data {
                    let seq = row["seq"].as_i64().unwrap_or_default();
                    let label = row["type_label"].as_str().unwrap_or_default();
                    let who = row["source_name"].as_str().unwrap_or("?");
                    let content = row["data_title"].as_str().or(row["data_desc"].as_str()).unwrap_or("");
                    let preview: String = content.chars().take(50).collect::<String>().replace('\n', " ");
                    println!("  [{seq}] {label} {who}: {preview}");
                }
            } else {
                eprintln!(
                    "合并转发消息 {total} 条 (取前 {}; 用 --msg-id <id> [--source <分片>] 展开):",
                    args.limit
                );
                for row in &r.data {
                    let id = row["msg_id"].as_str().unwrap_or_default();
                    let src = row["source"].as_str().unwrap_or_default();
                    let n = row["item_count"].as_i64().unwrap_or_default();
                    println!("{id}  [{src}]  ({n} 子项)");
                }
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum KeyAction {
    /// 打印明文 master key hex 到 stdout (需 --i-understand)。
    Show,
}

/// `key` 参数 (R8/⑩): show 打印明文 master key。
#[derive(Args)]
struct KeyArgs {
    /// 动作: show (打印明文 key; 目前唯一)。
    #[arg(value_enum, default_value_t = KeyAction::Show)]
    action: KeyAction,
    /// 账号 wxid (从缓存取该账号 key; 须先 `auth` 缓存)。
    #[arg(long)]
    wxid: String,
    /// 我知道这会把明文 master key 打到屏幕 (缺则拒绝)。
    #[arg(long)]
    i_understand: bool,
}

/// `key show` — 打印明文 master key 到 **stdout(仅此一个出口)**。破 K-R4(明文 key)→ 需 --i-understand
/// + ADR-506 豁免。给用户拿 key 接外部工具(chatlog/wx-cli)。**key 绝不进日志/错误/Debug/panic** —— 只
/// `to_hex()` → stdout 一处。
async fn cmd_key(args: &KeyArgs) -> Result<()> {
    match args.action {
        KeyAction::Show => cmd_key_show(args).await,
    }
}

/// R9 件3: `live-index` 管理动作 (spec §5)。
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LiveIndexAction {
    /// 看当前索引状态 (触发器在否 / 索引行数)。
    Status,
    /// 建/重建索引 (`--tier full`: 全文索引 + 增量触发器; `--tier thin`: 独立瘦库, 尚不完整)。
    Build,
    /// 删索引回 off (删触发器 + message_fts 表)。
    Clear,
}

/// `live-index` 参数 (R9 件3): 管理常驻索引 (status / build / clear)。索引维护是否在跑由 watch/serve 载体
/// (`--live-index`) 决定; 本命令独立管索引这个真文件。
#[derive(Args)]
struct LiveIndexArgs {
    /// 动作: status (默认) / build / clear。
    #[arg(value_enum, default_value_t = LiveIndexAction::Status)]
    action: LiveIndexAction,
    /// L1 库路径 (索引所在: full 的 message_fts 在 L1 库内)。
    #[arg(long)]
    l1_db: String,
    /// build 档位 (full = message_fts + 触发器; thin = 独立瘦库 --thin-db)。
    #[arg(long, value_enum, default_value_t = LiveIndexTier::Full)]
    tier: LiveIndexTier,
    /// thin 独立瘦库路径 (build --tier thin 用; 从 --l1-db 的 message 正文灌 trigram FTS, 自成一库不挂 L1)。
    #[arg(long)]
    thin_db: Option<String>,
    /// 只看某个账号 (填 wxid)。一个 L1 里有多个账号时, 建 thin 索引必须给 (不给会拒); 单账号不用给。
    #[arg(long)]
    account: Option<String>,
}

/// `live-index` — 管理常驻搜索索引 (R9 件3)。**与 `search --build` 归并**: build --tier full 复用
/// [`native_core::storage::build_message_fts_incremental`] (件1: 全量 rebuild + 增量触发器)。
#[allow(clippy::unused_async)] // 对齐 async 命令派发 (Command::LiveIndex => cmd_live_index(..).await); 内部同步无 await
async fn cmd_live_index(args: &LiveIndexArgs) -> Result<()> {
    use native_core::storage;
    let l1 = Path::new(&args.l1_db);
    if !l1.is_file() {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("--l1-db {} 不存在 (live-index 在已 ingest 的 L1 上管索引)", args.l1_db),
        ));
    }
    match args.action {
        LiveIndexAction::Status => {
            // 双审 P3: status 是纯读 → open_readonly (不 RW+create+WAL 改动 L1 文件)。
            let conn = storage::open_readonly(l1)
                .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, format!("打不开 L1 db {}", args.l1_db)))?;
            let triggers = storage::message_fts_triggers_exist(&conn);
            let fts_rows: i64 = conn
                .query_row("SELECT count(*) FROM message_fts", [], |r| r.get(0))
                .unwrap_or(-1);
            // R9 复审R3#4: indexed_through = L1 最新消息数据时刻 MAX(create_time)/1000 (unix 秒; message-scoped 非全源
            // floor)。旧版 etl_state MIN(last_update) 是墙钟非数据时刻+只覆盖消息源+被休眠分片拖成假旧 → 谎报, 已撤。
            // 与 message_total 的 count 合一次全表扫 (SQLite 单扫同出 count+MAX)。status 稀有可承受全表扫。
            let (msg_total, ct_ms): (i64, Option<i64>) = conn
                .query_row("SELECT count(*), MAX(create_time) FROM message", [], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?))
                })
                .unwrap_or((-1, None));
            let indexed_through: Option<i64> = ct_ms.map(|ms| ms / 1000); // create_time 毫秒 (R6 归一 ×1000) → 秒。
            println!(
                "live-index status: message_fts 索引={} · 增量触发器={} · message {} 条 · indexed_through={} · 后续 ingest {}自动进索引",
                if fts_rows >= 0 { format!("{fts_rows} 行") } else { "未建".to_string() },
                if triggers { "在" } else { "无" },
                if msg_total >= 0 { msg_total.to_string() } else { "?".to_string() },
                indexed_through.map_or_else(|| "无".to_string(), |t| t.to_string()),
                if triggers { "会" } else { "不会 (需先 build)" }
            );
            Ok(())
        }
        LiveIndexAction::Build => match args.tier {
            // 双审 P3: off = 无常驻索引, build --tier off 语义矛盾 → 拒 (别静默建 full 索引)。
            LiveIndexTier::Off => Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "build --tier off 无意义 (off = 无常驻索引); 建索引用 --tier full 或 thin, 删索引用 clear".to_string(),
            )),
            // R20: cold(冷库)不是可"建索引"档 —— 它是 L1 静态冷查, 用 `ingest --all` 建 L1 即可, 无需 live-index build。
            LiveIndexTier::Cold => Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "build --tier cold 无意义 (冷库=L1 静态冷查); 建 L1 用 `ingest --all --l1-db <L1>`, 不走 live-index build"
                    .to_string(),
            )),
            LiveIndexTier::Full => {
                // R9 复审#6: build full 写 message_fts + 触发器 → 取单写者锁 (防与 serve/watch full / ingest / search --build 并发互毁)。
                let _index_lock = storage::acquire_watch_lock(l1)
                    .map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?;
                let conn = storage::open(l1).map_err(|_| {
                    cli_err(native_core::ErrorCode::BadRequest, format!("打不开 L1 db {} (可写)", args.l1_db))
                })?;
                let t0 = std::time::Instant::now();
                let n = storage::build_message_fts_incremental(&conn)
                    .context("live-index build (message_fts) 失败 (message 表在?)")?;
                eprintln!(
                    "✅ live-index build --tier full: message_fts {n} 行 + 增量触发器, {}ms —— 后续 ingest/watch 自动维护",
                    t0.elapsed().as_millis()
                );
                Ok(())
            }
            LiveIndexTier::Thin => {
                let thin_path = args.thin_db.as_deref().ok_or_else(|| {
                    cli_err(native_core::ErrorCode::BadRequest, "build --tier thin 需 --thin-db <瘦库路径>".to_string())
                })?;
                // R4 复审 P1: thin 无账号列, 多账号 L1 全灌会混数据 → build 前 resolve_account fail-closed (多账号未给
                // --account 则拒), 并把 account_id_sha 作 SELECT 谓词 → thin 只含该账号正文 (搜它不泄别账号)。
                let acct_sha = native_query::resolve_account_sha(&args.l1_db, args.account.clone())?;
                // 双审 P3: 只 SELECT message (纯读) → open_readonly (同 status 修; 不写锁/不改 L1 WAL)。
                let src = storage::open_readonly(l1)
                    .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, format!("打不开 L1 db {}", args.l1_db)))?;
                // R5 复审 P1#1: 确定 thin 库要**绑定**的账号 sha —— acct_sha 有(多账号/显式)直接用; None(单账号库)取那
                // 唯一账号的 sha, 让 thin 库恒绑一个具体账号, search 时核对 (防用别账号 --account 搜出本库数据)。空库 → 空串。
                let bound_sha: String = match acct_sha.clone() {
                    Some(s) => s,
                    None => native_query::account_shas(&src).ok().and_then(|v| v.into_iter().next()).unwrap_or_default(),
                };
                let mut thin = storage::open(Path::new(thin_path)).map_err(|_| {
                    cli_err(native_core::ErrorCode::BadRequest, format!("打不开 thin db {thin_path} (可写)"))
                })?;
                storage::init_thin_fts(&thin).context("建 thin FTS 失败")?;
                storage::init_thin_meta(&thin).context("建 thin_meta 失败")?;
                let t0 = std::time::Instant::now();
                // 从 L1 message 全扫正文 → 灌 thin (rowid = thin_rowid(source, source_native_id) = daemon 同键 →
                // 先 build 再 daemon 维护同一瘦库时按 (分片,锚) 去重、不整库重复倒排; 白盒 P2-1 + codex P1 补 source)。事务批量。
                let tx = thin.transaction().context("thin 事务失败")?;
                // R9 复审#5 + codex 末轮 P1: rebuild 前 **DROP + 重建** thin_fts (非只 DELETE 清行)。只清行有两患:
                // ① 旧 schema 库 (无 source 列) 清行不换 schema → 后续带 source 的 INSERT "no such column" 挂;
                // ② init 是 CREATE IF NOT EXISTS 不清残留。DROP 重建同时清残留 + 升 schema, 事务内原子, 保证 thin == 当前 L1。
                tx.execute_batch("DROP TABLE IF EXISTS thin_fts;").context("DROP 旧 thin 失败")?;
                storage::init_thin_fts(&tx).context("重建 thin FTS 失败")?;
                let mut n: i64 = 0;
                {
                    // R5b 复审 P1: **恒按 bound_sha 过滤**, 不再"单账号库全灌"。全灌有 TOCTOU —— resolve 判定单账号后、
                    // 到这条 SELECT 之间若并发 ingest 灌入第二账号 B, 全灌会把 B 也灌进 thin 却仍绑定 A → `search --account A`
                    // 校验通过泄漏 B。按 bound_sha 过滤则 thin 内容恒 == 绑定账号, 与并发无关。空库 (bound_sha="") 才全灌 (无可泄)。
                    // params_from_iter(Option<&str>) 产 0/1 参恰配 sql 有无 `?1`; &str 借 bound_sha 本体 (活到块尾)。
                    let sql = if bound_sha.is_empty() {
                        "SELECT source, source_native_id, text_content FROM message WHERE text_content <> ''"
                    } else {
                        "SELECT source, source_native_id, text_content FROM message \
                         WHERE text_content <> '' AND account_id_sha = ?1"
                    };
                    let filter = (!bound_sha.is_empty()).then_some(bound_sha.as_str());
                    let mut st = src.prepare(sql).context("查 L1 message 失败 (库是 L1?)")?;
                    let rows = st
                        .query_map(rusqlite::params_from_iter(filter), |r| {
                            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
                        })
                        .context("扫 message 失败")?;
                    for row in rows {
                        let (source, msg_id, text) = row.context("读 message 行失败")?;
                        // 白盒 P2-1 + codex P1: rowid = thin_rowid(source 分片, 锚), 与 daemon (thin.rs) 同键 →
                        // build+daemon 混用去重不重复; 含 source 防跨分片同 source_native_id 撞键覆盖丢消息。
                        // source 列亦存 (codex P2: 结果带分片身份, 跨分片同锚可唯一 rejoin L1)。
                        storage::insert_thin_msg(
                            &tx,
                            native_core::thin::thin_rowid(&source, &msg_id),
                            &source,
                            &msg_id,
                            &text,
                        )
                        .context("插 thin 失败")?;
                        n += 1;
                    }
                }
                // R5 复审 P1#1: 同事务绑定账号 → search 核对 (thin_fts 无账号列, 靠这个防跨账号搜)。
                storage::set_thin_account(&tx, &bound_sha).context("写 thin 账号绑定失败")?;
                // codex 复审 P1: 标记 rowkey 键方案版本 (build 全按当前 v2=含分片方案重灌) → daemon 后续维护认版本一致不误清。
                storage::set_thin_rowkey_version(&tx, storage::THIN_ROWKEY_VERSION).context("写 thin rowkey 版本失败")?;
                tx.commit().context("thin 提交失败")?;
                storage::optimize_thin_fts(&thin).context("thin optimize 失败")?;
                let acct_note = if bound_sha.is_empty() {
                    "全库".to_string()
                } else {
                    format!("账号 sha8 {}", bound_sha.chars().take(8).collect::<String>())
                };
                eprintln!(
                    "✅ live-index build --tier thin: {n} 条正文灌入 thin FTS ({thin_path}, 绑定 {acct_note}), {}ms —— \
                     独立瘦搜索库 (不挂 L1; 搜它: `search --query <词> --thin-db {thin_path}`; 搜时给 --account 会核对相符)",
                    t0.elapsed().as_millis()
                );
                eprintln!(
                    "ℹ️ thin 现状: 本命令是一次性构建快照 (已按账号过滤+绑定, 搜它不泄别账号); 需常驻实时增量则跑 \
                     `watch --live-index thin --thin-db {thin_path}` (tail 源库把新消息增量灌同一瘦库, 与 build 同 rowid 键去重)。\
                     注: `serve --live-index thin` 不后台维护瘦库 (按 off 起纯查询), 实时维护须独立跑上面的 watch。"
                );
                Ok(())
            }
        },
        LiveIndexAction::Clear => {
            // R9 复审#6: clear 删 message_fts + 触发器 → 取单写者锁 (防与 serve/watch full / build / ingest 并发互毁)。
            let _index_lock = storage::acquire_watch_lock(l1)
                .map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?;
            let conn = storage::open(l1).map_err(|_| {
                cli_err(native_core::ErrorCode::BadRequest, format!("打不开 L1 db {} (可写)", args.l1_db))
            })?;
            storage::drop_message_fts_triggers(&conn).context("删触发器失败")?;
            conn.execute_batch("DROP TABLE IF EXISTS message_fts;")
                .context("删 message_fts 失败")?;
            eprintln!("✅ live-index clear: 删增量触发器 + message_fts 索引 (回 off; 搜索退化 LIKE 全表扫)");
            Ok(())
        }
    }
}

async fn cmd_key_show(args: &KeyArgs) -> Result<()> {
    if !args.i_understand {
        bail!("key show 会把明文 master key 打到屏幕(别人看屏/录屏/共享终端即泄露)。确认请加 --i-understand。");
    }
    let wxid: Wxid = args
        .wxid
        .parse()
        .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--wxid 非法 (须合法微信 wxid)"))?;
    // cache-only 取 key(同热查, 不碰微信进程); 未缓存 → cache_key 报错, 错误里**不含 key 字节**。
    let key = cache_key(&wxid)
        .await
        .context("取 key 失败 (先对该账号跑 `auth` 缓存 key?)")?;
    // 明文 key hex → **仅 stdout**。to_hex 是 MasterKey 唯一明文导出口, key 只经此一处。
    // 补审 P3: hex 明文副本包 Zeroizing, 打印后清零内存 (对齐 provider.rs to_hex 约定)。
    let hex = zeroize::Zeroizing::new(key.to_hex());
    println!("{}", hex.as_str());
    eprintln!("⚠️ 已打印明文 master key 到 stdout — 用完清屏; 谁拿到它 = 拿到你的解密权。");
    Ok(())
}

#[derive(Args)]
struct CacheArgs {
    /// 清掉某 wxid 的缓存 key (给了就清这一条; 不给 = 只列出不改动)。
    #[arg(long)]
    clear: Option<String>,
    /// 缓存文件路径 (缺省 = 默认 %LOCALAPPDATA%\msgvestige\cache\keys.enc)。
    #[arg(long)]
    cache_file: Option<String>,
    /// 输出格式 (table / json; list 时用)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// 从 `MasterKey` 的 Debug 抽 key 指纹 sha8 —— **K-R4 授权的唯一跨 crate 出口** (`as_bytes` 是 pub(crate)
/// 够不着, Debug 定死只露 `sha8(raw_bytes)`; 与 image key `sha8(&aes)` 同源)。
fn key_fingerprint(mk: &MasterKey) -> String {
    let dbg = format!("{mk:?}"); // 形如 "MasterKey(sha8=f0e1d2c3)"
    dbg.strip_prefix("MasterKey(sha8=")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(&dbg)
        .to_string()
}

/// `cache` — 看/清 master key 缓存。**K-R4: 账号与 key 都只出 sha8 指纹, 绝不出明文 wxid/key** (遵 msgvestige 模块策略)。
async fn cmd_cache(args: &CacheArgs) -> Result<()> {
    let provider = CacheKeyProvider::new(args.cache_file.as_deref().map(std::path::PathBuf::from));
    // 清一条 (invalidate; 可逆——下次 auth 重新缓存)。
    if let Some(wxid_str) = &args.clear {
        let wxid: Wxid = wxid_str
            .parse()
            .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--clear 的 wxid 非法"))?;
        let removed = provider.invalidate(&wxid).context("清缓存失败")?;
        // 回显走 Wxid Display (sha8), 不回显用户传入的明文 wxid。
        if args.format == OutFormat::Json {
            // 契约审: --format json 须走 {data,meta} (K-R4: account 只出 sha8)。
            print_query_json(
                &[serde_json::json!({"account_sha8": wxid.to_string(), "cleared": removed})],
                1,
            )?;
        } else if removed {
            println!("已清掉账号 {wxid} 的缓存 key (下次导出需重新 `auth`)");
        } else {
            println!("账号 {wxid} 本来就没缓存 (no-op)");
        }
        return Ok(());
    }
    // list: resolve_all 拿所有缓存账号; 账号走 Wxid Display=sha8, key 走 fingerprint, 明文都不落地。
    let all = provider.resolve_all().await.context("读缓存失败 (DPAPI 解密不了?)")?;
    let mut entries: Vec<(String, String)> = all
        .iter()
        .map(|(w, mk)| (format!("{w}"), key_fingerprint(mk)))
        .collect();
    entries.sort();
    match args.format {
        OutFormat::Table => {
            eprintln!(
                "已缓存 {} 个账号的 key (文件 {}):",
                entries.len(),
                provider.path.display()
            );
            for (acct_sha, fp) in &entries {
                println!("账号={acct_sha}  key指纹={fp}");
            }
            if entries.is_empty() {
                eprintln!("(空 — 先跑 `msgvestige auth --wxid <你的wxid>` 缓存一次)");
            }
        }
        OutFormat::Json => {
            let data: Vec<serde_json::Value> = entries
                .iter()
                .map(|(a, fp)| serde_json::json!({"account_sha8": a, "key_fingerprint_sha8": fp}))
                .collect();
            print_query_json(&data, entries.len())?;
        }
    }
    Ok(())
}

// InspectType (+ table_key) 已移至 native-query::handwritten (§6③ specials; 经上方 `use native_query::InspectType`
// 引入 —— InspectArgs.entity + cmd_inspect + 消歧单测调用点不变)。

#[derive(Args)]
struct InspectArgs {
    /// 实体类型 (contact/chatroom/session/message) —— 决定查哪张表, 解同 wxid 歧义。
    #[arg(value_enum)]
    entity: InspectType,
    /// 该实体稳定 id (contact/session=wxid或conv · chatroom=群id · message=source_native_id)。
    id: String,
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `inspect <type> <id>` — 看单条记录全字段 (contact/chatroom/session/message; 只读 L1)。type 决定查哪张表
/// → 解 person↔session 同 wxid 歧义; 消歧映射/取行/NOT_FOUND/json 信封在核 (`InspectType::table_key`/
/// `fetch_row`/`inspect_query`)。此薄壳按 format 呈现: **table 走 `fetch_row` 的有序列逐行渲染** (保 schema 列序 —
/// json 的排序 Map 丢列序, 故不读 `r.data`); json 走 `inspect_query`。查无 → `CliError{NotFound}`/退出3 (两路各构造同款)。
async fn cmd_inspect(args: &InspectArgs) -> Result<()> {
    // R16-6 双模: 冷 inspect_query/fetch_row 读 L1 单行(保 schema 列序); 热 hot_inspect 按 entity 路由源库实时读
    // (message 需全扫找锚, 较慢; contact/chatroom 热字段是列表集 < 冷完整 L1 列, 降级见 hot_inspect doc)。
    match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            match args.format {
                OutFormat::Table => {
                    let (table, key_col) = args.entity.table_key();
                    // table 保 schema 列序 → 读 fetch_row 的有序列 (非排序 json)。查无 → NOT_FOUND/退出3。
                    let Some(row) = native_query::fetch_row(&conn, table, key_col, &args.id)? else {
                        return Err(cli_err(
                            native_core::ErrorCode::NotFound,
                            format!(
                                "没找到 {table} 记录 {key_col}={} (id 对? 该库 ingest 了 {table}?)",
                                args.id
                            ),
                        ));
                    };
                    eprintln!("{table} 记录 [{key_col}={}]:", args.id);
                    for (name, v) in &row {
                        println!("{name:>26} : {}", native_query::json_value_display(v));
                    }
                }
                OutFormat::Json => {
                    let r = native_query::inspect_query(&conn, args.entity, &args.id)?;
                    emit_envelope(&r.data, r.meta)?;
                }
            }
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            // R21 成本门**仅对 message 实体挂** —— codex round-2 P1: 只 hot_inspect 的 Message 分支调 scan_all_messages;
            // contact/chatroom/session 直读各自库, 无条件挂门会按 message 分片大小误拒这些便宜查 (over-block)。
            if matches!(args.entity, native_query::InspectType::Message) {
                cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, 0).await?;
                // inspect message 不分页
            }
            let r = native_query::hot_inspect(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None,
                args.entity,
                &args.id,
                None,
            )
            .await
            .context("实时查单条记录失败 (账号 key 缓存了? 数据目录对? message 全扫较慢)")?;
            match args.format {
                OutFormat::Table => {
                    let (table, key_col) = args.entity.table_key();
                    // 热查返单 json-object 行 → 逐字段打印(降级注: contact/chatroom 字段少于冷)。
                    eprintln!("{table} 记录 [{key_col}={}] (热查/源库实时):", args.id);
                    if let Some(obj) = r.data.first().and_then(serde_json::Value::as_object) {
                        for (name, v) in obj {
                            println!("{name:>26} : {}", native_query::json_value_display(v));
                        }
                    }
                }
                OutFormat::Json => emit_envelope(&r.data, r.meta)?,
            }
        }
    }
    Ok(())
}

#[derive(Args)]
struct DormantArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 列最久没说话的前几个会话。
    #[arg(short = 'n', long, default_value_t = 15)]
    limit: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
}

/// `dormant` — 沉睡会话排行 (读 L1 message; 只读)。查数+json+meta 在核 `dormant_query`, 此薄壳只呈现。
/// table kind (conv_id 后缀判 群/单聊) 装饰留皮, 读**核已组好的 json** 字段。
async fn cmd_dormant(args: &DormantArgs) -> Result<()> {
    // R16-6 双模: 冷 dormant_query 读 L1 message GROUP BY; 热 hot_dormant 全扫源库聚合(较慢)。offset 恒 0(此命令不翻页)。
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            native_query::dormant_query(&conn, args.limit, 0).context("查 message 表失败")?
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
            native_query::hot_dormant(&wxid, args.target.wechat_data_dir.as_deref(), None, args.limit, 0, None)
                .await
                .context("实时查最久没说话会话失败 (账号 key 缓存了? 数据目录对? 全扫较慢)")?
        }
    };
    match args.format {
        OutFormat::Table => {
            eprintln!("最久没说话的 {} 个会话 (最近一条消息时间升序):", r.data.len());
            for row in &r.data {
                let conv = row["conv_id"].as_str().unwrap_or_default();
                let last = row["last_message_day"].as_str().unwrap_or_default();
                let n = row["message_count"].as_i64().unwrap_or_default();
                let kind = if conv.ends_with("@chatroom") { "群" } else { "单聊" };
                println!("[{last}] {kind}  {conv}  (共 {n} 条)");
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

#[derive(Args)]
struct StatsArgs {
    /// 查询目标 (L1 库; ③ flatten)。
    #[command(flatten)]
    target: QueryTarget,
    /// 聚合维度 (type / conv / sender / day)。
    #[arg(long, value_enum, default_value_t = StatsBy::Type)]
    by: StatsBy,
    /// 排行取前几名。
    #[arg(short = 'n', long, default_value_t = 10)]
    limit: usize,
    /// 输出格式 (table / json)。
    #[arg(long, value_enum, default_value_t = OutFormat::Table)]
    format: OutFormat,
    // R21: --confirm/--quiet 已上提为顶层全局 flag (见 Cli), 各全扫命令共用; 此处不再单列。
}

/// `stats` — 消息聚合统计 (读 L1 message; 只读)。聚合 + has_more 探测 + json + meta 都在核 `stats_query`;
/// 此薄壳只按 format 呈现: table 表头/百分比分母 (总消息数) 读 `meta.summary` + `stats_dimension_label`,
/// 数据行读**核 json** 的 label/count。
async fn cmd_stats(args: &StatsArgs) -> Result<()> {
    // R16-5: 冷热双模 (冷 stats_query 读 L1 GROUP BY; 热 hot_stats 全扫全类型 HashMap 累加)。聚合命令 offset 0。
    let r = match args.target.effective_mode() {
        native_query::EffectiveMode::Cold => {
            let conn = open_l1_resolved(&args.target)?;
            let mut r = native_query::stats_query(&conn, args.by, args.limit, 0).context("查 message 表统计失败")?;
            if let Some(f) =
                native_query::cold_freshness(args.target.require_l1_db()?, args.target.account_sha().as_deref())
            {
                r.meta = r.meta.with_freshness(f);
            }
            r
        }
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
            // R21 计划引擎门: stats 热查**全扫全类型** message 分片 = 最慢查, 挂门 (甲 by-criterion 全覆盖)。
            cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, args.limit).await?; // R21 全扫成本门
            native_query::hot_stats(
                &wxid,
                args.target.wechat_data_dir.as_deref(),
                None,
                args.by,
                args.limit,
                0,
                None,
            )
            .await
            .context("实时统计失败 (账号 key 缓存了? 数据目录对?)")?
        }
    };
    match args.format {
        OutFormat::Table => {
            let total = summary_i64(&r.meta, "total_messages");
            let dim = native_query::stats_dimension_label(args.by);
            eprintln!("消息总数 {total} · 按{dim}排行 (前 {}):", args.limit);
            for row in &r.data {
                let n = row["count"].as_i64().unwrap_or_default();
                let label = row["label"].as_str().unwrap_or_default();
                // 整数千分比 (避免 i64→f64 精度损失 lint), 显示成 X.Y%。
                let permille = if total > 0 { n * 1000 / total } else { 0 };
                println!("{n:>10}  {:>2}.{}%  {label}", permille / 10, permille % 10);
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// `mcp` — MCP 服务器 (JSON-RPC over stdio, 只读; ④文档)。**stdio 传输壳**: 逐行读 stdin JSON →
/// [`native_mcp::handle_line`] 分派 (协议+工具在 native-mcp, 传输无关) → 写 stdout (换行分隔)。
/// 日志走 stderr, 不污染 stdout 的 JSON-RPC 流。EOF (客户端断开) → 正常退出。
async fn cmd_mcp(args: &McpArgs) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let ctx = native_mcp::Ctx {
        l1_db: args.l1_db.clone(),
        wechat_data_dir: args.wechat_data_dir.clone(),
        default_account: args.wxid.clone(),
    };
    eprintln!(
        "MCP 服务器就绪 (JSON-RPC over stdio, 只读){}",
        args.l1_db.as_deref().map(|p| format!("; L1={p}")).unwrap_or_default()
    );
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("读 stdin 失败: {e}")))?;
        if n == 0 {
            break; // EOF → 客户端断开, 正常退出
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(resp) = native_mcp::handle_line(trimmed, &ctx).await {
            let s = serde_json::to_string(&resp).unwrap_or_else(|_| {
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"serialize failed"}}"#.to_string()
            });
            stdout
                .write_all(s.as_bytes())
                .await
                .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("写 stdout 失败: {e}")))?;
            stdout.write_all(b"\n").await.ok();
            stdout.flush().await.ok();
        }
    }
    Ok(())
}

/// `serve` — HTTP API 服务器 (REST, 只读; ③文档)。调 [`native_http::serve`] (axum), 阻塞到关停 (Ctrl-C)。
/// R9 件3: 解析生效 live-index 档 —— CLI 显式 `--live-index` 优先; 否则查 config 持久默认
/// (`config set live-index`; per-account 覆盖 > global default > off)。`wxid` 空串 → 只查 global default。
fn resolve_live_index_tier(explicit: Option<LiveIndexTier>, wxid: &str) -> LiveIndexTier {
    if let Some(t) = explicit {
        return t;
    }
    let cfg = native_core::config::load_or_default(&native_core::config::default_config_path());
    match cfg.live_index.tier_for(wxid).as_str() {
        "thin" => LiveIndexTier::Thin,
        "cold" => LiveIndexTier::Cold, // R20 冷库: 静态档 (watch/serve 不起 daemon)。
        "full" => LiveIndexTier::Full,
        _ => LiveIndexTier::Off,
    }
}

/// R9 复审R3#3 + 自审: 后台 watch 线程存活信号守卫。**`Drop` 时置 `false`** —— 保证线程无论**正常返回 / `Err`
/// 退出 / `panic` 展开 / 提前 `return`** 任一路径退出, `live_index_alive` 都被置 false (status 的 `live` 不假报)。
///
/// 原写法把 `store(false)` 放在 `rt.block_on(...)` **之后**: watch future 若 `panic`, 展开会**跳过**该行 → alive
/// 停在 `true` → status 谎报 `live:true` (线程实际已死)。RAII 守卫在线程闭包**首行**建、退出必 drop, 堵死此漏。
struct AliveGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn cmd_serve(args: &ServeArgs) -> Result<()> {
    // --watch: 起独立 OS 线程跑后台 watch (run_message_watch future 持 rusqlite Connection 跨 await = !Send,
    // 不能 tokio::spawn; 用专用线程 + 自己的 current_thread runtime)。持续解密活库增量落主 L1, 进度信号 → /events。
    let mut events_progress = None;
    let mut watch_ctl: Option<(tokio::sync::watch::Sender<bool>, std::thread::JoinHandle<()>)> = None;
    // R9 件5: serve --live-index full 隐含起监听 (消息 watch + 下方小库 watch), 让 L1 全表实时供 HTTP cold 查询。
    let mut src_watch_ctl: Option<(tokio::sync::watch::Sender<bool>, std::thread::JoinHandle<()>)> = None;
    // R9 复审R3#3: 后台监听线程**存活信号** (watch/full 时建; 任一线程退出/崩溃置 false → /live-index/status 真实报
    // live, 不再拿启动期静态 flag 假报)。两监听线程共用一把: 任一死 = 索引不再全实时。
    let mut live_index_alive: Option<std::sync::Arc<std::sync::atomic::AtomicBool>> = None;
    // R9 件3+P3: 解析生效档。**无 --wxid 时不从 config 取 full** —— 纯只读 serve (无账号) 无法 watch, 全局
    // default=full 不应令其硬失败; 只显式 --live-index 或带 --wxid 时才可能 full。
    let serve_tier = match args.wxid.as_deref() {
        Some(w) => resolve_live_index_tier(args.live_index, w),
        None => args.live_index.unwrap_or(LiveIndexTier::Off),
    };
    // R18: serve 内嵌 thin daemon 维护接线随后 (件2 daemon 已实现: `watch --live-index thin` 可单独跑维护瘦库)。
    // serve 遇 thin 档暂**按 off 起** (纯查询服务, 不在 serve 进程内维护瘦库), 明确提示用 watch 单独维护 ——
    // 不硬错 (daemon 非"未实现")、也不静默假装 serve 在维护 (免用户以为起了瘦索引实则没监听)。
    if serve_tier == LiveIndexTier::Thin {
        eprintln!(
            "[serve] --live-index thin: serve 内嵌维护接线随后, 本次按 off 起 (纯查询)。\
             瘦库维护请另跑 `watch --live-index thin --thin-db <瘦库>`; 搜它 `search --query <词> --thin-db <瘦库>`。"
        );
    }
    // R20 冷库: 静态 L1 档, serve 只做冷查 (读 L1), **不内嵌维护** (与 full 不同; 声明式=不自动起 daemon)。
    if serve_tier == LiveIndexTier::Cold {
        eprintln!(
            "[serve] --live-index cold: 冷库档 = 静态 L1, serve 只冷查读 L1, 不内嵌维护。\
             要刷新 L1 重跑 `ingest --all`; 要实时维护则用 `--live-index full`。"
        );
    }
    let full = serve_tier == LiveIndexTier::Full;
    // R9 件6: watch / live-index full 写真 L1 → 取**单写者锁** (spec §7 P1)。guard 在函数作用域, 持到 serve 返回
    // (后台 watch/source-watch 线程整个生命周期持有); 另一 watch/serve full 进程再取此 L1 → INDEX_LOCKED。
    // 纯查询 serve (无 --watch 无 full) 不写 L1 → 不取锁 (只读多开无碍)。
    let _index_lock = if args.watch || full {
        let l1 = args.l1_db.as_ref().ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--watch/--live-index full 需 --l1-db (后台监听落库目标)".to_string(),
            )
        })?;
        Some(
            native_core::storage::acquire_watch_lock(Path::new(l1))
                .map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?,
        )
    } else {
        None
    };
    if args.watch || full {
        let l1 = args.l1_db.clone().ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--watch 需 --l1-db (后台监听落库目标)".to_string(),
            )
        })?;
        let wxid_s = args.wxid.clone().ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--watch 需 --wxid (监听哪个账号)".to_string(),
            )
        })?;
        let wxid: Wxid = wxid_s.parse().map_err(|_| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--wxid 非法 (须合法微信 wxid)".to_string(),
            )
        })?;
        let data_dir = match &args.wechat_data_dir {
            Some(d) => PathBuf::from(d),
            None => default_wechat_data_dir()?,
        };
        let paths = locate_account_dbs(&data_dir, &wxid).map_err(|e| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                format!("定位账号 db 失败 (用 --wechat-data-dir 指向 xwechat_files): {e}"),
            )
        })?;
        let key = cache_key(&wxid).await?; // 启动时取一次 (cache 优先, 不碰微信); 后台 watch 全程复用, 不重复提取。
        let poll_ms = args.poll_ms; // 下限 clamp 已下沉到 run_message_watch 入口 (一处覆盖 serve/watch 两调用点)。
        let (prog_tx, prog_rx) = tokio::sync::watch::channel(0u64);
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let wxid_t = wxid.clone();
        // R9 复审R3#3: 建存活信号 (两监听共用一把); 消息线程退出时置 false → status 真实报 live。
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        live_index_alive = Some(alive.clone());
        let alive_msg = alive;
        let handle = std::thread::Builder::new()
            .name("events-watch".into())
            .spawn(move || {
                // R9 复审R3#3 自审: 存活守卫置于闭包首行 → 正常/Err/panic/早退任一路径退出都 store(false)。
                let _alive_guard = AliveGuard(alive_msg);
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("[events] 后台 watch runtime 建失败: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    let cipher: Box<dyn native_core::cipher::Cipher> =
                        Box::new(native_core::cipher::NativeCipher::new_live());
                    let mut source = AccountDbSource::new(
                        cipher,
                        paths.account_entry_db.clone(),
                        key,
                        wxid_t.clone(),
                        paths.message_dir.clone(),
                    );
                    source.set_include_biz(true); // R9 复审#3: watch 一趟覆盖公众号消息 (biz_message_*.db)
                    let mut watch_dbs = Vec::new();
                    if let Ok(rd) = std::fs::read_dir(&paths.message_dir) {
                        for e in rd.flatten() {
                            let p = e.path();
                            if p.extension().is_some_and(|x| x == "db") {
                                watch_dbs.push(p);
                            }
                        }
                    }
                    let opts = MessageWatchOpts {
                        print: false,
                        to_l1: true,
                        poll: std::time::Duration::from_millis(poll_ms),
                        max_secs: 0,
                        watch_dbs,
                        cancel: Some(cancel_rx),
                        progress: Some(prog_tx),
                    };
                    if let Err(e) = run_message_watch(
                        &mut source,
                        Path::new(&l1),
                        &wxid_t,
                        PrivacyMode::archive_canonical(),
                        4000,
                        opts,
                    )
                    .await
                    {
                        eprintln!("[events] 后台 watch 退出: {e}");
                    }
                });
                // 存活信号由 `_alive_guard`(闭包首行 AliveGuard)在此闭包 drop 时置 false —— 覆盖 panic 展开路径。
            })
            .map_err(|e| {
                cli_err(
                    native_core::ErrorCode::Internal,
                    format!("起 events-watch 线程失败: {e}"),
                )
            })?;
        events_progress = Some(prog_rx);
        watch_ctl = Some((cancel_tx, handle));
        eprintln!(
            "实时事件启用: 后台监听 {} (poll {poll_ms}ms) → GET /api/v1/events",
            &native_core::sha256_hex(&wxid_s)[..8]
        );
    }
    // R9 件5: serve --live-index full → 额外起小库监听线程 (独立 locate + cache_key; run_source_watch 持
    // Connection 跨 await = !Send 用专用 OS 线程 + current_thread runtime, 同消息 watch)。让 L1 全 31 表实时。
    if full {
        let l1 = args.l1_db.clone().ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--live-index full 需 --l1-db".to_string(),
            )
        })?;
        let wxid_s = args.wxid.clone().ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--live-index full 需 --wxid".to_string(),
            )
        })?;
        let wxid: Wxid = wxid_s
            .parse()
            .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--wxid 非法".to_string()))?;
        let data_dir = match &args.wechat_data_dir {
            Some(d) => PathBuf::from(d),
            None => default_wechat_data_dir()?,
        };
        let poll_ms = args.poll_ms;
        let (src_cancel_tx, src_cancel_rx) = tokio::sync::watch::channel(false);
        let alive_src = live_index_alive.clone(); // R9 复审R3#3: 源库线程退出也置存活信号 false
        let handle = std::thread::Builder::new()
            .name("source-watch".into())
            .spawn(move || {
                // R9 复审R3#3 自审: 存活守卫置于闭包首行 → 正常/Err/panic/早退任一路径退出都 store(false)。
                let _alive_guard = alive_src.map(AliveGuard);
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("[source-watch] 后台 runtime 建失败: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    let paths = match locate_account_dbs(&data_dir, &wxid) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[source-watch] 定位账号 db 失败: {e}");
                            return;
                        }
                    };
                    let key = match cache_key(&wxid).await {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("[source-watch] 取 key 失败: {e}");
                            return;
                        }
                    };
                    let cipher: Box<dyn native_core::cipher::Cipher> =
                        Box::new(native_core::cipher::NativeCipher::new_live());
                    let mut source = AccountDbSource::new(
                        cipher,
                        paths.account_entry_db.clone(),
                        key,
                        wxid.clone(),
                        paths.message_dir.clone(),
                    );
                    let src_opts = SourceWatchOpts {
                        poll: std::time::Duration::from_millis(poll_ms),
                        max_secs: 0,
                        debounce: std::time::Duration::from_secs(5),
                        cancel: Some(src_cancel_rx),
                    };
                    if let Err(e) = run_source_watch(
                        &mut source,
                        &paths,
                        Path::new(&l1),
                        &wxid,
                        PrivacyMode::archive_canonical(),
                        4000,
                        src_opts,
                    )
                    .await
                    {
                        eprintln!("[source-watch] 退出: {e}");
                    }
                });
                // 存活信号由 `_alive_guard`(闭包首行 AliveGuard)在此闭包 drop 时置 false —— 覆盖 panic 展开路径。
                // (两监听任一死 = 索引不再全实时; live = full && alive.load()。)
            })
            .map_err(|e| {
                cli_err(
                    native_core::ErrorCode::Internal,
                    format!("起 source-watch 线程失败: {e}"),
                )
            })?;
        src_watch_ctl = Some((src_cancel_tx, handle));
        eprintln!("R9 --live-index full: 后台全源库监听已起 (L1 全 31 表实时供 HTTP cold 查询)。");
    }

    let state = native_http::AppState {
        l1_db: args.l1_db.clone(),
        wechat_data_dir: args.wechat_data_dir.clone(),
        sns_wasm_dir: args.sns_wasm_dir.clone(),
        ffmpeg: args.ffmpeg.clone(),
        default_account: args.wxid.clone(),
        events_progress,
        shutdown: None, // serve() 内部注入关停广播 (Ctrl-C → 通知 SSE 流收尾)
        // §9 可选加固 (默认关): 请求超时 (秒→Duration) + 最大并发。
        request_timeout: args.request_timeout_secs.map(std::time::Duration::from_secs),
        max_concurrent: args.max_concurrent,
        live_index_full: full, // R9 件6+R3#4: full 时冷查 freshness 据线程存活出 stale (活 false/死 true)。
        live_index_alive,      // R9 复审R3#3: 后台线程存活信号 (status live 据此真实报, 线程死不假报 live:true)。
    };
    let host: std::net::IpAddr = args.host.parse().map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            format!("--host 非法 IP: {}", args.host),
        )
    })?;
    let addr = std::net::SocketAddr::new(host, args.port);
    eprintln!(
        "HTTP API 服务器启动 http://{addr} (只读){}",
        if host.is_loopback() {
            ""
        } else {
            " ⚠️非 loopback: 无 TLS/限流, 非公网方案"
        }
    );
    let r = native_http::serve(state, addr)
        .await
        .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("serve 失败: {e}")));
    // serve 返回 (Ctrl-C 优雅关停) → 停后台 watch (cancel + join 干净收尾)。
    if let Some((cancel_tx, handle)) = watch_ctl {
        let _ = cancel_tx.send(true);
        let _ = handle.join();
    }
    // R9 件5: full 的小库监听线程同样优雅关停 (cancel → 线程收到跳出循环 → join)。
    if let Some((cancel_tx, handle)) = src_watch_ctl {
        let _ = cancel_tx.send(true);
        let _ = handle.join();
    }
    r
}

/// 实时查 (mode=hot, 或 auto 无 L1) 需 --wxid; 缺 → 报错**不静默** (R6: 别让用户以为查了却没定位账号)。
fn cli_require_wxid(wxid: Option<&str>) -> Result<Wxid> {
    wxid.ok_or_else(|| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "实时查 (--mode=hot, 或 auto 无 --l1-db) 需 --wxid; 要冷查改 --mode=cold --l1-db <L1 库>",
        )
    })?
    .parse()
    .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--wxid 非法 (须合法微信 wxid)"))
}

/// 冷查会话列表 (mode=cold, 或 auto 有 L1): scoped L1 → [`native_query::cold_sessions_query`] → 挂 freshness
/// (`ingested_at` 导入时间)。缺 --l1-db → 报错**不静默转热** (R6: 用户要冷查却慢查/碰微信 = 最小意外违背)。
fn cli_cold_sessions(args: &SessionsArgs, offset: usize) -> Result<native_query::QueryResult> {
    let l1 = args
        .l1_db
        .as_deref()
        .ok_or_else(|| cli_err(native_core::ErrorCode::BadRequest, "--mode=cold 需 --l1-db 指向 L1 库"))?;
    // R9 复审R3#1: cold sessions/messages 也 resolve_account fail-closed (未给 --account 多账号 → 报错不裸开混)。
    let account_sha = native_query::resolve_account_sha(l1, args.account.clone())?;
    let conn = native_query::open_l1_scoped(l1, account_sha.as_deref())
        .map_err(|e| cli_err(native_core::ErrorCode::BadRequest, format!("打不开 L1 库: {e}")))?;
    let mut r = native_query::cold_sessions_query(&conn, args.limit, offset)?;
    if let Some(f) = native_query::cold_freshness(l1, account_sha.as_deref()) {
        r.meta = r.meta.with_freshness(f);
    }
    Ok(r)
}

/// 冷查会话消息 (mode=cold, 或 auto 有 L1): scoped L1 → [`native_query::cold_messages_query`] → 挂 freshness。
/// 冷查取最近 `limit` 条 (offset=0, 同热查只取最近; 冷查 offset 翻页能力核已有, CLI 暂不暴露)。
fn cli_cold_messages(args: &MessagesArgs, skip: Option<&str>) -> Result<native_query::QueryResult> {
    let l1 = args
        .l1_db
        .as_deref()
        .ok_or_else(|| cli_err(native_core::ErrorCode::BadRequest, "--mode=cold 需 --l1-db 指向 L1 库"))?;
    // R9 复审R3#1: cold sessions/messages 也 resolve_account fail-closed (未给 --account 多账号 → 报错不裸开混)。
    let account_sha = native_query::resolve_account_sha(l1, args.account.clone())?;
    let conn = native_query::open_l1_scoped(l1, account_sha.as_deref())
        .map_err(|e| cli_err(native_core::ErrorCode::BadRequest, format!("打不开 L1 库: {e}")))?;
    let mut r = native_query::cold_messages_query(&conn, &args.chat, args.limit, 0)?;
    // 没水位(全新库 / `ingest --no-messages` 建的库)时 `cold_freshness` 返 None —— 那也得把 skip 说出来,
    // 否则又回到"200 + 一批数据, 没有任何字段说这次没补成"。宁缺 ingested_at 不谎报。
    let base = native_query::cold_freshness(l1, account_sha.as_deref());
    if base.is_some() || skip.is_some() {
        let f = base
            .unwrap_or(native_query::Freshness::Cold {
                ingested_at: None,
                stale: None,
                chat_refreshed_at: None,
                refresh_skipped: None,
            })
            .with_refresh_skipped(skip);
        r.meta = r.meta.with_freshness(f);
    }
    Ok(r)
}

/// `sessions` — 列出所有会话 (直查加密 session.db 的 SessionTable, R5 扩全全字段; auth 后即用, 不建 L1)。**薄壳**:
/// 调 [`native_query::hot_sessions`] 取 `{data, meta}`; json 直 emit, table 表头/行留皮 (从预组
/// json data 读, 全量数从 `meta.summary.total_sessions` 取 —— 与冷查 render_table 同"皮从 data 渲"路)。
async fn cmd_sessions(args: &SessionsArgs) -> Result<()> {
    // 复审 P3: offset 夹到 [0, 1e7] (对齐 HTTP clamp_offset / MCP arg_count 上界) —— 防超大 offset 撑爆 SQLite
    // OFFSET (i64) + 三皮一致。offset 是 usize 数值, 无注入。
    let offset = args.offset.min(10_000_000);
    // R6: mode 派发 (auto 按有无 --l1-db)。hot 需 --wxid; cold 需 --l1-db (缺则各自报错, 不静默转对面)。
    let r = match args.mode.effective(args.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.wxid.as_deref())?;
            // 审 R21 round-1 (codex P2): **不在此挂成本门** —— hot_sessions 读 `session/session.db` (SessionTable),
            // **不扫 message 分片、不调 scan_all_messages**。挂账号级全分片门会误拦大消息账号的这个便宜命令。
            // 成本门属**全扫**命令 (调 scan_all_messages 的), 待集中到 scan 入口 (见 memory R21 修计划)。
            hot_sessions(
                &wxid,
                args.wechat_data_dir.as_deref(),
                args.locator_file.as_deref(),
                args.limit,
                offset,
            )
            .await?
        }
        native_query::EffectiveMode::Cold => cli_cold_sessions(args, offset)?,
    };
    match args.format {
        OutFormat::Table => {
            match r.meta.summary.as_ref().and_then(|s| s["total_sessions"].as_u64()) {
                Some(t) => eprintln!("会话 {t} 个 (取前 {}):", args.limit),
                None => eprintln!("会话 (取前 {}):", args.limit),
            }
            // R5 扩全: table 预览 = 类型 + conv_id + 未读 + 摘要 (全字段走 --format json)。
            for v in &r.data {
                let unread = v["unread_count"].as_i64().unwrap_or(0);
                let unread_s = if unread > 0 {
                    format!(" [未读{unread}]")
                } else {
                    String::new()
                };
                let summary: String = v["summary"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(40)
                    .collect::<String>()
                    .replace('\n', " ");
                println!(
                    "{}  {}{}  {}",
                    if v["is_group"].as_bool().unwrap_or(false) {
                        "群  "
                    } else {
                        "单聊"
                    },
                    v["conv_id"].as_str().unwrap_or("?"),
                    unread_s,
                    summary
                );
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// R21 计划引擎门 (甲档) —— **CLI 皮薄壳**。决策核 [`native_query::full_scan_cost_gate`] **三皮共享**(见
/// native-query `gate.rs`; 窗口/key 预检 + 估算 + 阈值 → GateReport)。本壳只: (a) 取 CLI 顶层全局 `--confirm`/
/// `--quiet` (b) 调核 (c) 按 CLI 呈现 —— Silent 静默 / Hint stderr(--quiet 压)/ Blocked → `cli_err(BadRequest)`
/// exit 2 / ConfirmedProceed 告知。~19 个全扫命令热分支首调本壳; chat 定向查 (messages/messages_around)、biz、
/// inspect 非 message 臂 **不调**(见核 doc 排除口径)。
///
/// **退出码调和**: ADR-407 §3.5 说 exit 1; 但 §13 冻结退出码闭集无 exit-1, 用 [`ErrorCode::BadRequest`](exit 2)
/// = "查询超支被拒, 加 --confirm"。核返 GateReport, 本壳把 `Blocked` 映射成 BadRequest。
async fn cost_gate_full_scan(
    wxid: &native_core::Wxid,
    wechat_data_dir: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    use native_core::query_planner::profile::GateOutcome;
    let confirm = GATE_CONFIRM.load(Relaxed);
    let quiet = GATE_QUIET.load(Relaxed);
    // 决策核三皮共享 (窗口/key 预检 + 估算 + 阈值)。窗口越界 → Err(BadRequest) 上抛; 其余返 GateReport。
    let report = native_query::full_scan_cost_gate(wxid, wechat_data_dir, offset, limit, confirm).await?;
    let (secs, label, n) = (report.estimated_secs(), report.profile_label(), report.shard_count);
    match report.outcome {
        GateOutcome::Silent => {}
        GateOutcome::Hint { .. } => {
            if !quiet {
                eprintln!(
                    "⚠ 估算 {secs} 秒 ({label}, 跨 {n} 分片); 若常查建议先 `msgvestige ingest` 建 L1 库, 之后用 --mode cold 走索引 (ms 级)"
                );
            }
        }
        GateOutcome::Blocked { .. } => {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                format!("估算 {secs} 秒 ({label}, 跨 {n} 分片); 加 --confirm 强制执行, 或先 msgvestige ingest 建 L1 后用 --mode cold (走索引快)"),
            ));
        }
        GateOutcome::ConfirmedProceed { .. } => {
            if !quiet {
                eprintln!("估算 {secs} 秒 ({label}), --confirm 已传, 执行中...");
            }
        }
    }
    Ok(())
}

/// R22 (ADR-508 D24): 冷查前把**一个会话**增量采进 L1。没 L1 库 / 取不到 key 时如实报错 (不静默降级 ——
/// 静默跳过会让用户以为读到的是最新的)。别的写者正维护该会话 → 提示后照读 L1 现有的。
/// R22 (ADR-508 D24): 冷查前把**一个会话**增量采进 L1。共享实现在 `native_query::ensure_chat_fresh`,
/// 三皮同一份 —— 这里只负责把结果讲给终端用户听。
async fn refresh_one_chat(
    wxid_s: &str,
    chat: &str,
    wechat_data_dir: Option<&str>,
    l1_db: Option<&str>,
) -> Result<Option<&'static str>> {
    let Some(l1) = l1_db else {
        anyhow::bail!("冷查要 --l1-db");
    };
    let wxid = native_core::key_provider::Wxid::try_new(wxid_s.to_string())
        .map_err(|e| anyhow::anyhow!("wxid 不合法: {e}"))?;
    let fresh = native_query::ensure_chat_fresh(std::path::Path::new(l1), &wxid, chat, wechat_data_dir).await?;
    // ⚠️ **必须把 skip 原因返回给调用方**(第四轮对抗审 P1): 原来只 `eprintln!` 到 stderr, 于是
    // `--format json` 的消费者(脚本 / AI)拿到退出码 0 + 一批消息 + 一个只有 `ingested_at` 的 freshness,
    // **没有任何机器可读字段**说这次没补全 —— 跟 HTTP 那格是同一个病, 只是换了张皮。
    let skip = fresh.skip_reason();
    match fresh {
        native_query::ChatFreshness::AlreadyFresh => {}
        native_query::ChatFreshness::SourceUnavailable { why } => {
            eprintln!("注意: 够不着微信库({why}) —— 下面读到的是 L1 里已有的, 可能不是最新。");
        }
        // 跟"够不着"分开讲: 这一格**能修** —— 那个坏文件一走就自愈, 所以要告诉用户怎么办。
        native_query::ChatFreshness::SourceDegraded { why, stats } => {
            eprintln!("注意: {why}");
            if stats.messages_decoded > 0 {
                eprintln!(
                    "      其余分片已补入 {} 条, 只有上面那几片没看成。",
                    stats.messages_decoded
                );
            }
            // ⚠️ **别在这里写死处置建议**(第四轮对抗审 P2): `SourceDegraded` 现在装三种原因
            // (分片读不开 / 白名单中途被改 / 子源卡住), 写死一句"去删那个坏文件"会把另外两种
            // 原因的用户支去翻微信目录。建议由产生原因的那一方放进 `why`, 这里只讲后果。
            eprintln!("      所以下面可能少了那部分消息。");
        }
        native_query::ChatFreshness::NotCovered => {
            eprintln!(
                "注意: 这个会话没被采集覆盖(采集白名单排除? 公众号会话?) —— 下面读到的是 L1 里已有的,                  可能不是最新。用 capture add 把它圈进来, 或换 --mode hot 直读微信库。"
            );
        }
        native_query::ChatFreshness::Ingested { stats, lease_kept } => {
            if stats.messages_decoded > 0 || stats.decode_errors > 0 {
                eprintln!(
                    "已补入该会话新消息: 解出 {} 条, 解码失败 {} 条",
                    stats.messages_decoded, stats.decode_errors
                );
            }
            if !lease_kept {
                eprintln!("提示: 采集耗时较久, 期间可能有别的写者在做同一份活 (数据无碍)");
            }
        }
        native_query::ChatFreshness::SkippedHeld { until } => {
            eprintln!(
                "注意: 该会话正被别的写者维护(租约到 {until}), 本次没补 —— 下面读到的是 L1 现有的,                  可能还差对方正在写的那批。稍后重试可拿到最新。"
            );
        }
    }
    Ok(skip)
}

async fn cmd_messages(args: &MessagesArgs) -> Result<()> {
    // R6: mode 派发 (auto 按有无 --l1-db)。hot 需 --wxid; cold 需 --l1-db。冷查取最近 limit (offset=0, 同热查)。
    let r = match args.mode.effective(args.l1_db.is_some()) {
        native_query::EffectiveMode::Hot => {
            let wxid = cli_require_wxid(args.wxid.as_deref())?;
            // 审 R21 round-1 (codex+Claude P2): **不在此挂成本门** —— hot_messages 是 chat **定向查**
            // (latest_messages(chat) 只读 1 个分片, 持久 locator 命中后 <1s), **不调 scan_all_messages 全扫**。
            // 账号级全分片粗估会误拦常规账号的定向查 (ADR-407 §4: 指定 chat_id 只路由 1 个 db)。成本门属**全扫**命令
            // (search/stats 等调 scan_all_messages 的), 待集中到 scan 入口 (见 memory R21 修计划)。
            hot_messages(
                &wxid,
                &args.chat,
                args.wechat_data_dir.as_deref(),
                args.locator_file.as_deref(),
                args.limit,
            )
            .await?
        }
        native_query::EffectiveMode::Cold => {
            // R22 (ADR-508 D24) 懒式落库: 冷查**之前**先把这个会话增量采进 L1, 于是冷查结果永远是最新的。
            // 判据是插入序 (`WHERE local_id > 游标`) 不是时间 —— 回填 / 表重建 / 乱序 / 同秒并发全都不漏。
            // 够不着源库 (没 --wxid) 或用户显式 --no-refresh 时跳过, 读 L1 现有的。
            let mut skip: Option<&'static str> = None;
            if !args.no_refresh {
                if let Some(w) = args.wxid.as_deref() {
                    skip =
                        refresh_one_chat(w, &args.chat, args.wechat_data_dir.as_deref(), args.l1_db.as_deref()).await?;
                } else {
                    // ⚠️ 没 `--wxid` = 够不着源库, 这一格**也得标出来**(外部复审 P2): HTTP / MCP 都会标,
                    // 只有 CLI 悄悄读旧 L1 → `--format json` 的消费者看不出"这次压根没刷新"。
                    // 三皮行为必须一致; 而且本函数的文档自己写着"不静默降级"。
                    skip = Some("source_unavailable");
                    eprintln!("注意: 没给 --wxid, 这次没有去补新消息 —— 下面读到的是 L1 里已有的。");
                }
            }
            cli_cold_messages(args, skip)?
        }
    };
    match args.format {
        OutFormat::Table => {
            eprintln!("{} 最近 {} 条:", args.chat, r.data.len());
            for v in &r.data {
                let preview: String = v["text"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(60)
                    .collect::<String>()
                    .replace('\n', " ");
                println!(
                    "[{}] type{} {}: {}",
                    v["create_time"].as_i64().unwrap_or(0),
                    v["local_type"].as_i64().unwrap_or(0),
                    v["sender"].as_str().unwrap_or("?"),
                    preview
                );
            }
        }
        OutFormat::Json => emit_envelope(&r.data, r.meta)?,
    }
    Ok(())
}

/// **冷查**列表出口 (open_readonly L1 命令) —— 薄壳, `{data, meta}` + `meta.source=cold` (②)。
/// `has_more` = 本页行数 < `total` (§2 恒精确);③④ 后续在需要处直接建 [`Meta`] 填 account/游标。
fn print_query_json(data: &[serde_json::Value], total: usize) -> Result<()> {
    emit_envelope(data, Meta::page(data.len(), total).with_source(Source::Cold))
}
// print_query_json_cold (冷查·无廉价全量 exec 出口) 已随 exec 移核 —— exec json 现走 native-query::exec_query
// + emit_envelope; 其余冷查命令 (moments/new/dormant/stats/…) 早已直接 emit_envelope(&r.data, r.meta)。

/// cache-only 取账号 master key (不 hook / 不碰微信 — 取 key 是 `auth` 的事)。
/// `ingest` — 建 L1 库 (直读加密微信库解密 + ETL 落 L1)。复用 msgvestige-adapter 的定位 + 编排引擎
/// (与 msgvestige-adapter bin 同一份 `run_full_ingest`, 免抄免漂移)。key 走 cache-only (先 `auth` 缓存)。
/// 默认只导消息; 各类型开关同 msgvestige-adapter; `--all` = 全量。
#[derive(Args)]
#[allow(clippy::struct_excessive_bools)] // CLI flag struct: 18 类型开关是 clap 惯例 (同 msgvestige-adapter Args)。
struct IngestArgs {
    /// 账号 wxid (如 wxid_abcd1234efgh567)。
    #[arg(long)]
    wxid: String,
    /// 微信数据目录 (xwechat_files; 省略则自动探测)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// 产出 L1 库路径。
    #[arg(long)]
    l1_db: String,
    /// 每页条数 (page-by-page, 禁全量; 须 ≥ 1)。
    #[arg(long, default_value_t = 4000)]
    batch_limit: usize,
    /// 消息 decode 并行度; 省略 = 逻辑线程 50% (min 1); 须 ≥ 1。只惠消息主体, 其它类型仍串行。
    #[arg(long)]
    jobs: Option<usize>,
    /// 出边界脱敏 archive payload (默认明文; opt-in 才 sha 化)。
    #[arg(long)]
    redact_payload: bool,
    /// 建全部类型 (等价打开下面所有类型开关)。
    #[arg(long)]
    all: bool,
    /// 跳过消息导入 (默认导消息)。
    #[arg(long)]
    no_messages: bool,
    /// 导联系人。
    #[arg(long)]
    contacts: bool,
    /// 导群 (chatroom)。
    #[arg(long)]
    chatrooms: bool,
    /// 导会话列表 (session)。
    #[arg(long)]
    sessions: bool,
    /// 导收藏 (favorite + favorite_tag)。
    #[arg(long)]
    favorites: bool,
    /// 导朋友圈 (moment)。
    #[arg(long)]
    sns: bool,
    /// 导转账 (transfer)。
    #[arg(long)]
    transfers: bool,
    /// 导红包 (red_envelope)。
    #[arg(long)]
    red_envelopes: bool,
    /// 导群收款 (group_pay)。
    #[arg(long)]
    group_pays: bool,
    /// 导好友验证 (friend_verify)。
    #[arg(long)]
    friend_verifies: bool,
    /// 导视频号访问 (finder_visit)。
    #[arg(long)]
    finder_visits: bool,
    /// 导好友朋友圈索引 (moment_feed)。
    #[arg(long)]
    moment_feeds: bool,
    /// 导朋友圈互动通知 (sns_notify)。
    #[arg(long)]
    sns_notifies: bool,
    /// 导自定义表情 (custom_emoticon)。
    #[arg(long)]
    emoticons: bool,
    /// 导头像 (avatar_image)。
    #[arg(long)]
    avatars: bool,
    /// 导企微联系人 (bizchat_user)。
    #[arg(long)]
    bizchat: bool,
    /// 导公众号消息 (biz_message; 二次扫消息库带 biz 模式)。
    #[arg(long)]
    biz_messages: bool,
    /// 导陌生人 (stranger; 二次扫联系人库带 stranger 模式)。
    #[arg(long)]
    strangers: bool,
}

/// `ingest` — 直读加密微信库解密 + ETL 落 L1。定位/取 key/编排全复用现成件。
async fn cmd_ingest(args: &IngestArgs) -> Result<()> {
    if args.batch_limit < 1 {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--batch-limit 须 ≥ 1 (page-by-page, 禁全量)".to_string(),
        ));
    }
    // R15 --jobs: 解析消息 decode 并行度 (省略 = 逻辑线程 50% min 1, 见 default_ingest_jobs)。校验 ≥ 1。
    // 专用 rayon 池在 run_message_pipeline_jobs 内按 workers 建 (钳到逻辑核数; 非全局池, 不污染 keyscan)。
    let workers = match args.jobs {
        Some(0) => {
            return Err(cli_err(native_core::ErrorCode::BadRequest, "--jobs 须 ≥ 1".to_string()));
        }
        Some(n) => n,
        None => native_core::default_ingest_jobs(),
    };
    // R15 batch_limit 上界的 CLI 早校验移到 plan 构造之后 (仅 plan.messages 且并行时才拒; 审 Round-C P2)。
    let wxid: Wxid = args.wxid.parse().map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "--wxid 非法 (须合法微信 wxid)".to_string(),
        )
    })?;
    // R9 复审#6: ingest 批量写 L1 → 取单写者锁, 防与 serve/watch full 常驻监听并发双写同一 L1 (重复倒排/索引互毁)。
    let _index_lock = native_core::storage::acquire_watch_lock(Path::new(&args.l1_db))
        .map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?;
    // 定位账号 db (db_storage/session 入口 + message/ 扫盘根); 复用 msgvestige-adapter 定位逻辑。
    let data_dir = match &args.wechat_data_dir {
        Some(d) => PathBuf::from(d),
        None => default_wechat_data_dir()?,
    };
    let paths = locate_account_dbs(&data_dir, &wxid).map_err(|e| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            format!("定位账号 db 失败 (用 --wechat-data-dir 指向 xwechat_files): {e}"),
        )
    })?;
    // 取 key (cache-only; 缺则提示先 auth)。
    let key = cache_key(&wxid).await?;
    // ADR-427: 底座内 canonical 明文; --redact-payload opt-in 出边界脱敏。
    let mode = if args.redact_payload {
        PrivacyMode::default_sha()
    } else {
        PrivacyMode::archive_canonical()
    };
    // `--all` 也必须尊重 `--no-messages` —— 原先这里是**光秃秃的 `IngestPlan::all()`**, 整个分支
    // 不读 `args.no_messages` → `ingest --no-messages --all` **照导消息**, 零提示。
    // 实测代价: 3.2GB / 一个多小时(日志 "开始 message ingest…"), 而用户明明写了"跳过消息导入"。
    // 又一例"参数在某分支被静默吞"。`--all --no-messages` 的意图明确且有用(建全部类型但别导消息 ——
    // 正是建小型对照库的姿势), 该被支持, 不该被忽略。
    let plan = if args.all {
        IngestPlan {
            messages: !args.no_messages,
            ..IngestPlan::all()
        }
    } else {
        IngestPlan {
            messages: !args.no_messages,
            contacts: args.contacts,
            chatrooms: args.chatrooms,
            sessions: args.sessions,
            favorites: args.favorites,
            sns: args.sns,
            transfers: args.transfers,
            red_envelopes: args.red_envelopes,
            group_pays: args.group_pays,
            friend_verifies: args.friend_verifies,
            finder_visits: args.finder_visits,
            moment_feeds: args.moment_feeds,
            sns_notifies: args.sns_notifies,
            emoticons: args.emoticons,
            avatars: args.avatars,
            bizchat: args.bizchat,
            biz_messages: args.biz_messages,
            strangers: args.strangers,
        }
    };
    // 注(审 Round-D): R15 并行 decode 分窗 → 峰值内存有界不随 batch_limit 涨, 故无 batch_limit 上界 CLI 校验
    // (前几轮的上界随分窗设计删除)。
    eprintln!("native cipher (纯 Rust 解密), 开始 ingest → {} …", args.l1_db);
    let cipher: Box<dyn native_core::cipher::Cipher> = Box::new(native_core::cipher::NativeCipher::new());
    let mut source = AccountDbSource::new(
        cipher,
        paths.account_entry_db.clone(),
        key,
        wxid.clone(),
        paths.message_dir.clone(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let results = run_full_ingest(
        &mut source,
        &paths,
        Path::new(&args.l1_db),
        &wxid,
        mode,
        args.batch_limit,
        &plan,
        now,
        workers,
    )
    .await
    .map_err(|e| {
        // R14(codex P2/Claude P1): L1 版本迁移门禁(init_l1_schema 抛 SQLITE_MISMATCH, 穿透 .context 夹层)→ SchemaMismatch
        // (退出6, 透传删库重建提示); 其它 ingest 失败(解密/IO)→ Internal。用 {e:#} 打全 anyhow 链(否则底层门禁提示被顶层 context 盖掉)。
        let schema_drift = e.chain().any(|c| {
            matches!(c.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(f, _)) if f.extended_code == rusqlite::ffi::SQLITE_MISMATCH)
        });
        let code = if schema_drift {
            native_core::ErrorCode::SchemaMismatch
        } else {
            native_core::ErrorCode::Internal
        };
        cli_err(code, format!("ingest 失败: {e:#}"))
    })?;
    eprintln!("✅ ingest 完成 ({} 类落库):", results.len());
    for (label, stats) in &results {
        // 群这一类不走 `messages_decoded` —— 它记在 `chatrooms_created` / `members_added`
        // 上。只打 messages_decoded 会报「chatroom: 落库 0 条」, 而真库里 chatroom 表实际
        // 落了 1599 行、chatroom_member 6.9 万行。用户跑第二步看到 0 会以为群没导进去。
        // (审查方拿 `exec` 数真实行数对拍逮到的。)
        if stats.chatrooms_created > 0 || stats.members_added > 0 {
            eprintln!(
                "  {label}: 落库 群 {} 个 · 成员 +{}{}",
                stats.chatrooms_created,
                stats.members_added,
                if stats.members_removed > 0 {
                    format!(" · 退群 -{}", stats.members_removed)
                } else {
                    String::new()
                }
            );
        } else if stats.decode_errors > 0 {
            eprintln!(
                "  {label}: 落库 {} 条 (解码失败 {})",
                stats.messages_decoded, stats.decode_errors
            );
        } else {
            eprintln!("  {label}: 落库 {} 条", stats.messages_decoded);
        }
    }
    Ok(())
}

/// `watch` — 实时监听消息库增量 (件3, ADR-499)。live cipher 合并 WAL 拿未刷盘最新消息。
/// R9 实时索引档 (spec §14.5): off / thin / full。CLI `--live-index` 临时覆盖 + (件3) config 持久默认共用。
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[value(rename_all = "lowercase")]
enum LiveIndexTier {
    /// 默认: 无常驻索引 (watch 只消息 tail-f; 冷查静态 / 热查实时)。
    #[default]
    Off,
    /// 独立瘦搜索索引 (只搜索, 不挂 L1, 存储小)。
    Thin,
    /// 冷库: L1 建一次 (ingest --all) 静态冷查, 不 watch 维护 (作 config 默认时 watch/serve 视为静态、不起 daemon, 冷查直读 L1)。
    Cold,
    /// 全源库监听 (L1 全表跟源库实时: 消息 tail-f + 小库整表重跑)。
    Full,
}

/// 默认临时观察 (tail-f 打印, 不动真 L1); `--to-l1` 才写持久 L1。复用 msgvestige-adapter 的 run_message_watch。
/// R9 `--live-index full` → 同起全源库监听 (run_source_watch), 让 L1 全表实时 (隐含写真 L1)。
#[derive(Args)]
struct WatchArgs {
    /// 账号 wxid。
    #[arg(long)]
    wxid: String,
    /// 微信数据目录 (xwechat_files; 省略则自动探测)。
    #[arg(long)]
    wechat_data_dir: Option<String>,
    /// L1 库路径 (off/full 档需要, --to-l1 或 full 时写入; 观察模式不动它; thin 档不用可省)。
    // thin 档走 --thin-db 独立瘦库、不碰 L1 → 此参在 thin 分支不读 (codex 复审 P3: 勿把评审标签/markdown 写进 clap doc, 会漏进 --help 且挂 subcommand_help_has_no_internal_narrative 测)。
    #[arg(long)]
    l1_db: Option<String>,
    /// 每页条数 (page-by-page, 禁全量; 须 ≥ 1)。
    #[arg(long, default_value_t = 4000)]
    batch_limit: usize,
    /// 出边界脱敏 archive payload (默认明文)。
    #[arg(long)]
    redact_payload: bool,
    /// 写真实 L1 (持久, 库随消息更新); 默认关 = 临时库观察 (拷真库水位 tail-f, 不动真库)。
    #[arg(long)]
    to_l1: bool,
    /// 关掉新消息打印 (默认开; 只写库不看流时用)。
    #[arg(long)]
    no_print: bool,
    /// 轮询间隔 (毫秒)。
    #[arg(long, default_value_t = 800)]
    poll_ms: u64,
    /// 跑满秒数即停 (0 = 永久, 直到 Ctrl-C; demo/测试给个值)。
    #[arg(long, default_value_t = 0)]
    secs: u64,
    /// 实时索引档: off (默认, 只消息 tail-f) / thin (+独立瘦搜索索引) / cold (静态 L1, watch 无维护、直接返回提示) / full (+全源库监听, L1 全表实时)。
    #[arg(long, value_enum)]
    live_index: Option<LiveIndexTier>,
    /// `--live-index thin` 的独立瘦库路径 (自存正文 FTS; 不建 L1)。thin 档必给。
    #[arg(long)]
    thin_db: Option<String>,
}

/// `watch` — 实时监听消息增量 (live cipher 合并 WAL); 复用现成 run_message_watch。
/// R9 `--live-index full`: 同起全源库监听 (小库整表重跑), 消息 tail-f + 小库监听并行。
async fn cmd_watch(args: &WatchArgs) -> Result<()> {
    if args.batch_limit < 1 {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--batch-limit 须 ≥ 1 (page-by-page, 禁全量)".to_string(),
        ));
    }
    let wxid: Wxid = args.wxid.parse().map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "--wxid 非法 (须合法微信 wxid)".to_string(),
        )
    })?;
    // codex 复审 P2: 先解析生效档 + 早验各档必需路径 (在 locate_account_dbs / cache_key 取 key 副作用之前)。
    // l1_db 转 Option 后 clap 不再早拒缺参; 若不早验, off/full 缺 --l1-db 会先触发账号定位 / 取 key, 报无关错误
    // 而非直接告知缺哪个路径。resolve_live_index_tier 只读 config (无取 key 等副作用), 可安全前移。
    let tier = resolve_live_index_tier(args.live_index, &args.wxid);
    // R20 冷库: 静态 L1 档, **不实时维护** → watch 无意义。声明式给清晰指引后直接返回, 不起 daemon。
    if tier == LiveIndexTier::Cold {
        eprintln!(
            "[watch] --live-index cold: 冷库档是静态 L1 (不实时维护) —— 无需 watch。冷查直读 L1 (各查询命令 --l1-db <L1>); \
             要刷新则重跑 `ingest --all`, 要实时维护则改用 `--live-index full`。"
        );
        return Ok(());
    }
    match tier {
        LiveIndexTier::Thin if args.thin_db.is_none() => {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "--live-index thin 需 --thin-db <瘦库路径> (自存正文 FTS, 不建 L1)".to_string(),
            ));
        }
        LiveIndexTier::Off | LiveIndexTier::Full if args.l1_db.is_none() => {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "watch (off/full 档) 需 --l1-db <L1 库路径>; 仅 thin 档可省".to_string(),
            ));
        }
        _ => {}
    }
    let data_dir = match &args.wechat_data_dir {
        Some(d) => PathBuf::from(d),
        None => default_wechat_data_dir()?,
    };
    let paths = locate_account_dbs(&data_dir, &wxid).map_err(|e| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            format!("定位账号 db 失败 (用 --wechat-data-dir 指向 xwechat_files): {e}"),
        )
    })?;
    let key = cache_key(&wxid).await?;
    let mode = if args.redact_payload {
        PrivacyMode::default_sha()
    } else {
        PrivacyMode::archive_canonical()
    };
    // R9 件5: full = 消息 tail-f + 全源库监听, **两独立 OS 线程真并行**。source 持 rusqlite Connection 跨 await
    // = !Send → 不能跨线程 move (各线程内建); 且 tokio::join! 同任务协作调度会因 pipeline 同步解密 block 饿死
    // 另一 watch (实测 source-watch 12s 未起) → 必须独立线程。full 隐含写真 L1 (to_l1=true)。
    // (tier 已在上方早验段解析并校验必需路径; 此处直接用。)
    if tier == LiveIndexTier::Thin {
        // R18 件2: thin 持久档 —— 消息 tail-f → 独立瘦搜索库 (不建 L1)。单 watch (无 full 的小库线程);
        // source 持 !Send Connection 跨 await → 独立 OS 线程 + current_thread runtime (同 full 的 msg 线程)。
        let thin_db = args.thin_db.clone().ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--live-index thin 需 --thin-db <瘦库路径> (自存正文 FTS, 不建 L1)".to_string(),
            )
        })?;
        // 单写者锁: 锁**瘦库本身** (非 L1; 防两 thin watch 进程双写同库 → 重复倒排/锁争, spec §7 P1)。
        let _lock = native_core::storage::acquire_watch_lock(Path::new(&thin_db))
            .map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?;
        let (paths_t, wxid_t) = (paths.clone(), wxid.clone());
        let (poll, secs, bl) = (args.poll_ms, args.secs, args.batch_limit);
        eprintln!("[watch] --live-index thin: 消息 tail-f → 独立瘦搜索库 {thin_db} (不建 L1)。");
        let t = std::thread::spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            rt.block_on(async move {
                let key = cache_key(&wxid_t).await?; // 线程内重取 (MasterKey !Clone; cache-only 不重复提取)。
                let cipher: Box<dyn native_core::cipher::Cipher> =
                    Box::new(native_core::cipher::NativeCipher::new_live());
                let mut source = AccountDbSource::new(
                    cipher,
                    paths_t.account_entry_db.clone(),
                    key,
                    wxid_t.clone(),
                    paths_t.message_dir.clone(),
                );
                source.set_include_biz(true); // 覆盖公众号消息 (biz_message_*.db, 同 full)。
                let mut wdbs = Vec::new();
                if let Ok(rd) = std::fs::read_dir(&paths_t.message_dir) {
                    for e in rd.flatten() {
                        let p = e.path();
                        if p.extension().is_some_and(|x| x == "db") {
                            wdbs.push(p);
                        }
                    }
                }
                let opts = ThinWatchOpts {
                    poll: std::time::Duration::from_millis(poll),
                    max_secs: secs,
                    watch_dbs: wdbs,
                    cancel: None,
                };
                run_thin_watch(&mut source, Path::new(&thin_db), &wxid_t, bl, opts).await
            })
        });
        return t
            .join()
            .map_err(|_| cli_err(native_core::ErrorCode::Internal, "thin watch 线程 panic".to_string()))?
            .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("thin watch 失败: {e}")));
    }
    if tier == LiveIndexTier::Full {
        // R17(方案B 激活推迟到 R22): **保留 L1 进程排他锁**。两审(codex+Claude 换角度)收敛逮出: 撤锁只撤 watch 一半 →
        // 破了它与仍持此锁的 {ingest/build/clear/search-build/serve} 的互斥(R9 件6 的锁, 注释明说要跟 watch full 互斥) →
        // `live-index clear` 删 FTS 表 vs watch 触发器并发损毁 message_fts / watch 摄取卡死。R17 只交付统一驱动 + 租约
        // primitive + L2 入口(底座); 真正"撤锁换协作多写者"(daemon-free query-write 共存 + 业务写 fencing + serve/FTS
        // 维护命令统一迁租约 + owner-UUID)整体做进 R22。
        let l1_db = args.l1_db.as_deref().ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--live-index full 需 --l1-db <L1 库路径> (L1 全表实时维护)".to_string(),
            )
        })?;
        let _index_lock = native_core::storage::acquire_watch_lock(Path::new(l1_db))
            .map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?;
        let (paths_a, paths_b) = (paths.clone(), paths.clone());
        let (wxid_a, wxid_b) = (wxid.clone(), wxid.clone());
        let (l1_a, l1_b) = (l1_db.to_string(), l1_db.to_string());
        let (poll, secs, bl, print, redact) = (
            args.poll_ms,
            args.secs,
            args.batch_limit,
            !args.no_print,
            args.redact_payload,
        );
        eprintln!("[watch] --live-index full: 消息 tail-f + 全源库监听 (两线程真并行, L1 全表实时)。");
        // 双审 P2: 共享 cancel 通道 —— 任一线程结束 (Err 退 / max_secs 到) → send(true) 通知另一线程退, 防另一线程
        // (secs=0 无限跑) 令 join 永久阻塞 → 进程半失效 (一 watch 死、另一空转, 既不退也不报)。
        let (cancel_tx, cancel_rx_msg) = tokio::sync::watch::channel(false);
        let cancel_rx_src = cancel_rx_msg.clone();
        let cancel_tx_src = cancel_tx.clone();
        // 消息 tail-f 线程 (move 外面已取的 key)。
        let msg_t = std::thread::spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            let r = rt.block_on(async move {
                let mode = if redact {
                    PrivacyMode::default_sha()
                } else {
                    PrivacyMode::archive_canonical()
                };
                let cipher: Box<dyn native_core::cipher::Cipher> =
                    Box::new(native_core::cipher::NativeCipher::new_live());
                let mut source = AccountDbSource::new(
                    cipher,
                    paths_a.account_entry_db.clone(),
                    key,
                    wxid_a.clone(),
                    paths_a.message_dir.clone(),
                );
                source.set_include_biz(true); // R9 复审#3: watch full 覆盖公众号消息 (biz_message_*.db)
                let mut wdbs = Vec::new();
                if let Ok(rd) = std::fs::read_dir(&paths_a.message_dir) {
                    for e in rd.flatten() {
                        let p = e.path();
                        if p.extension().is_some_and(|x| x == "db") {
                            wdbs.push(p);
                        }
                    }
                }
                let opts = MessageWatchOpts {
                    print,
                    to_l1: true,
                    poll: std::time::Duration::from_millis(poll),
                    max_secs: secs,
                    watch_dbs: wdbs,
                    cancel: Some(cancel_rx_msg),
                    progress: None,
                };
                run_message_watch(&mut source, Path::new(&l1_a), &wxid_a, mode, bl, opts).await
            });
            let _ = cancel_tx.send(true); // 双审 P2: 结束 (Err/完成) → 通知 src 线程退, 防 src_t.join 永久阻塞。
            r
        });
        // 小库监听线程 (MasterKey 不 Clone → 线程内重取 cache key, cache-only 不重复提取)。
        let src_t = std::thread::spawn(move || -> anyhow::Result<()> {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            let r = rt.block_on(async move {
                let key2 = cache_key(&wxid_b).await?;
                let mode = if redact {
                    PrivacyMode::default_sha()
                } else {
                    PrivacyMode::archive_canonical()
                };
                let cipher: Box<dyn native_core::cipher::Cipher> =
                    Box::new(native_core::cipher::NativeCipher::new_live());
                let mut source = AccountDbSource::new(
                    cipher,
                    paths_b.account_entry_db.clone(),
                    key2,
                    wxid_b.clone(),
                    paths_b.message_dir.clone(),
                );
                let src_opts = SourceWatchOpts {
                    poll: std::time::Duration::from_millis(poll),
                    max_secs: secs,
                    debounce: std::time::Duration::from_secs(5), // 小库至多每 5s 重跑 (防 session/contact 高频变)。
                    cancel: Some(cancel_rx_src),
                };
                run_source_watch(&mut source, &paths_b, Path::new(&l1_b), &wxid_b, mode, bl, src_opts).await
            });
            let _ = cancel_tx_src.send(true); // 双审 P2: 结束 → 通知 msg 线程退。
            r
        });
        let r1 = msg_t
            .join()
            .map_err(|_| cli_err(native_core::ErrorCode::Internal, "消息 watch 线程 panic".to_string()))?;
        let r2 = src_t
            .join()
            .map_err(|_| cli_err(native_core::ErrorCode::Internal, "源库 watch 线程 panic".to_string()))?;
        r1.map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("watch 消息失败: {e}")))?;
        r2.map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("watch 源库失败: {e}")))?;
        return Ok(());
    }
    // (thin 档已在上面 tier==Thin 分支处理并 return; 此处只剩 off。)
    // off: 单 source 消息 tail-f (现有路径)。off/观察档仍需 L1 路径 (run_message_watch 落库/参照)。thin 才可省 (P2-2)。
    let l1_db = args.l1_db.as_deref().ok_or_else(|| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "watch (off/观察档) 需 --l1-db <L1 库路径>; 仅 thin 档可省".to_string(),
        )
    })?;
    // R17(方案B 激活推迟 R22): 保留 L1 进程排他锁 —— --to-l1 写真 L1 取单写者锁(R9 件6: 防与 ingest/build/clear/serve
    // 并发双写同一 L1 互毁索引; 两审收敛坐实撤锁会破此互斥)。撤锁换协作多写者整体做进 R22。临时观察 (off, 不写真 L1) 不取。
    let _index_lock = if args.to_l1 {
        Some(
            native_core::storage::acquire_watch_lock(Path::new(l1_db))
                .map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?,
        )
    } else {
        None
    };
    let mut watch_dbs = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&paths.message_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "db") {
                watch_dbs.push(p);
            }
        }
    }
    eprintln!(
        "native cipher LIVE (合并 WAL 实时前沿), watch {} …",
        if args.to_l1 {
            format!("→ 写真 L1 {l1_db}")
        } else {
            "(临时观察, 不动真 L1)".to_string()
        }
    );
    let cipher: Box<dyn native_core::cipher::Cipher> = Box::new(native_core::cipher::NativeCipher::new_live());
    let mut source = AccountDbSource::new(
        cipher,
        paths.account_entry_db.clone(),
        key,
        wxid.clone(),
        paths.message_dir.clone(),
    );
    source.set_include_biz(true); // R9 复审#3: watch 一趟覆盖公众号消息 (biz_message_*.db)
    let opts = MessageWatchOpts {
        print: !args.no_print,
        to_l1: args.to_l1,
        poll: std::time::Duration::from_millis(args.poll_ms),
        max_secs: args.secs,
        watch_dbs,
        cancel: None,   // CLI watch: 无优雅关停信号 (Ctrl-C 退)
        progress: None, // CLI watch: 不需要进度通知 (仅 serve /events 用)
    };
    run_message_watch(&mut source, Path::new(l1_db), &wxid, mode, args.batch_limit, opts)
        .await
        .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("watch 失败: {e}")))?;
    Ok(())
}

// cache_key / query_locator_path / resolve_message_dir / default_wechat_data_dir 已上移至
// native-query::hot (§6③ 收尾: sessions/messages 进核 —— MCP/HTTP 依赖 native-query 故解析 helper 上移)。
// 仍用到的 (cache_key/default_wechat_data_dir, 被 auth/export/media 用) 经上方 `use native_query::{...}` 回引。

/// `search` — 在 L1 message 正文里全文搜索 (FTS5 trigram, 中文子串; ADR-502)。
/// `--build` (重)建 `message_fts` 索引 (external-content, 不复制正文) **+ 建增量触发器**; `--query` 搜关键词。
/// 首次搜索前须先 `--build` 一次; **R9 件1: build 后触发器自动增量维护 —— 后续 ingest 新消息无需再手动重建**。
/// `search` 冷热派发 (**R16-6, 🔴降级**)。冷 = FTS5 trigram+bm25(需 --build 建索引); 热 = 全库扫 `text.contains` 子串
/// (无 FTS/无 bm25 排序, 按 create_time DESC)。`--build`/`--thin-db` 是 L1 索引操作 = **冷专用**(热查源库无 FTS)。
async fn cmd_search(args: &SearchArgs) -> Result<()> {
    // R18: 独立瘦库搜索 —— 只给 --thin-db 无 --l1-db → 直搜瘦库自存 FTS (返 msg_id + 高亮片段), **不碰 L1**
    // (thin daemon `watch --live-index thin` 产的独立瘦库 = "不建库秒搜" 本意; 现有 --thin-db+--l1-db 组合仍走冷查加速)。
    // 须在下面 hot 判定**前** (无 --l1-db 时 effective_mode=Hot 会拒 --thin-db)。
    if args.thin_db.is_some() && args.target.l1_db.is_none() {
        return cmd_search_thin_standalone(args);
    }
    if matches!(args.target.effective_mode(), native_query::EffectiveMode::Hot) {
        // 热 search: 只支持 --query 全扫子串; --build/--thin-db(L1 索引操作)在热模式明确拒绝(不静默忽略)。
        if args.build || args.thin_db.is_some() {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "热 search (--mode hot) 无 FTS 索引: --build / --thin-db 是 L1 索引操作, 只冷查可用。热 search 只支持 --query 全库扫子串匹配 (无相关度排名, 按时间序)。",
            ));
        }
        // 空 query 也拒 (Claude P3: 对齐 MCP/HTTP 的 filter(!is_empty); 否则 --query "" 会白扫 / 与冷不一致)。
        let q = args.query.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--query 必填且非空 (热 search 全库扫子串)",
            )
        })?;
        let wxid = cli_require_wxid(args.target.wxid.as_deref())?;
        // R21 计划引擎门: search 热查全库扫 message 分片子串 = 慢查, 挂门 (甲 by-criterion 全覆盖)。
        let limit = usize::try_from(args.limit.max(0)).unwrap_or(0);
        cost_gate_full_scan(&wxid, args.target.wechat_data_dir.as_deref(), 0, limit).await?; // R21: limit 先算, 门用它做翻页窗口校验
        let r = native_query::hot_search(&wxid, args.target.wechat_data_dir.as_deref(), None, q, limit, None)
            .await
            .context("实时搜索失败 (账号 key 缓存了? 数据目录对?)")?;
        match args.format {
            OutFormat::Table => {
                let total = summary_i64(&r.meta, "total_matches");
                eprintln!(
                    "搜索 \"{q}\" 命中 {total} 条 (热查 · 全库扫子串, 无相关度排名按时间序, 取前 {}):",
                    args.limit
                );
                for row in &r.data {
                    // 同冷 print_search: 原始 create_time (ms), 不格式化。
                    let preview: String = row["text_content"]
                        .as_str()
                        .unwrap_or_default()
                        .chars()
                        .take(80)
                        .collect::<String>()
                        .replace('\n', " ");
                    println!(
                        "  [{}] {}｜{}: {preview}",
                        row["create_time"].as_i64().unwrap_or_default(),
                        row["conv_id"].as_str().unwrap_or_default(),
                        row["sender_wxid"].as_str().unwrap_or_default()
                    );
                }
            }
            OutFormat::Json => emit_envelope(&r.data, r.meta)?,
        }
        return Ok(());
    }
    cmd_search_cold(args)
}

/// R18: 独立瘦库搜索 (仅 `--thin-db` 无 `--l1-db`) —— 直搜 thin daemon 产的独立瘦 FTS, 返 `(msg_id, snippet)`,
/// **不碰 L1** (thin "不建库秒搜" 本意)。trigram, `--query` <3 字空结果 (无 LIKE 兜底, 走热/冷 LIKE)。只读打开。
fn cmd_search_thin_standalone(args: &SearchArgs) -> Result<()> {
    use native_core::storage;
    let thin_path = args.thin_db.as_deref().unwrap_or_default(); // 调用点已判 is_some。
    let q = args.query.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "--query 必填且非空 (瘦库搜索)".to_string(),
        )
    })?;
    let conn = storage::open_readonly(Path::new(thin_path))
        .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, format!("打不开瘦库 {thin_path}")))?;
    // codex 末轮 P1: 旧 schema 库 (无 source 列) 只读搜索无从迁移 → 给清晰"重建"提示, 别抛裸 "no such column: source"。
    if !storage::thin_fts_has_source(&conn).unwrap_or(false) {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "瘦库是旧版本 schema (无 source 列) —— 请用当前版本 `live-index build --tier thin` 或 `watch --live-index thin` 重建后再搜".to_string(),
        ));
    }
    // 账号绑定核对 (**两侧都 fail-closed**, 对齐 combined 路 `(None,_)=>Err` 的安全口径):
    // - 给了 --account (黑盒审 P2-4): 要求瘦库已绑且相符, 防用别账号 --account 搜出本库 / 搜未绑库泄漏。
    // - 没给 --account (codex/Agent B 复审 P2-1): 要求瘦库已绑**具体账号** (Some 非空)。未绑 (None) / 空绑 ("")
    //   → 拒裸搜, 防遗留/外来**多账号**瘦库无守卫裸搜跨账号泄漏。当前 build/daemon 恒绑定具体账号 sha, 故正常库不受影响;
    //   仅拦下"非本代码所建 / 空 L1 建的"库。
    let bound = storage::get_thin_account(&conn).ok().flatten();
    match args.target.account.as_deref() {
        Some(acct) => {
            let want = native_core::sha256_hex(acct);
            if bound.as_deref() != Some(want.as_str()) {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "瘦库账号绑定与 --account 不符 (或瘦库未绑账号); 防跨账号搜 —— 换库或去掉 --account".to_string(),
                ));
            }
        }
        None => {
            if bound.as_deref().unwrap_or("").is_empty() {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "瘦库未绑定具体账号 (未绑或空绑) —— 拒裸搜防跨账号泄漏; 用当前 build/daemon 重建瘦库 (会绑定账号) 后再搜 (给 --account 也不行: 未绑库任何账号都不匹配)".to_string(),
                ));
            }
        }
    }
    // R18 (黑盒审 P1): has_more 用 **limit+1 探针** (search_thin 满 limit 取、无 COUNT) —— 镜像 combined 路, 别把
    // 截断的 top-N 谎报成完整 (HOLE-2 反模式)。json 走 emit_envelope(cold_page + source=LiveIndex), **不手搓**
    // (原手搓缺"恒给"的 has_more、多塞非契约 count 破 golden §2)。
    let limit = usize::try_from(args.limit.max(0)).unwrap_or(0);
    let mut hits = storage::search_thin(&conn, q, limit.saturating_add(1)).map_err(|e| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            format!("瘦库搜索失败 (库是 thin FTS?): {e}"),
        )
    })?;
    let has_more = hits.len() > limit;
    hits.truncate(limit);
    match args.format {
        OutFormat::Table => {
            eprintln!(
                "瘦库搜索 \"{q}\" 命中 {}{} 条 (独立瘦库 · trigram · (msg_id, source 分片) + 高亮片段):",
                hits.len(),
                if has_more { "+ (还有更多, 加 --limit)" } else { "" }
            );
            for (msg_id, source, snippet) in &hits {
                println!("  {msg_id} [{source}]  {snippet}");
            }
        }
        OutFormat::Json => {
            // 返 (msg_id, source, snippet): 跨分片同锚须连 source 才能唯一 rejoin L1 (codex 复审 P2)。
            let data: Vec<serde_json::Value> = hits
                .iter()
                .map(|(m, src, s)| serde_json::json!({ "msg_id": m, "source": src, "snippet": s }))
                .collect();
            let mut meta = native_query::Meta::cold_page(has_more).with_source(native_query::Source::LiveIndex);
            if let Some(b) = &bound {
                meta.account = Some(b.chars().take(8).collect());
            }
            native_query::emit_envelope(&data, meta)?;
        }
    }
    Ok(())
}

fn cmd_search_cold(args: &SearchArgs) -> Result<()> {
    use native_core::storage;
    let l1 = Path::new(args.target.require_l1_db()?);
    if args.build {
        // 建索引在**已有** L1 上做 → 不存在先拒 (契约审: 别让可写 open CREATE 空库留脏文件; 坏路径→BAD_REQUEST/2)。
        if !l1.is_file() {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                format!(
                    "--l1-db {} 不存在 (--build 在已 ingest 的 L1 上建索引, 不新建库)",
                    l1.display() // R16-1: l1_db 转 Option, 复用上面 require_l1_db 解出的路径
                ),
            ));
        }
        // R9 复审#6: build 写 FTS + 触发器 → 取单写者锁, 防与 serve/watch full 或另一 build 并发互毁索引/触发器。
        let _index_lock =
            storage::acquire_watch_lock(l1).map_err(|e| cli_err(native_core::ErrorCode::IndexLocked, e))?;
        // 建索引要写库 → 可写 open; 打开失败 → BAD_REQUEST/2。
        let conn = storage::open(l1).map_err(|_| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                format!("打不开 L1 db {} (可写, 建全文索引)", l1.display()),
            )
        })?;
        // R5 复审 P1#1: --query 时把账号 fail-closed 检查**移到重建前** —— 多账号未给 --account 立即拒, 别等
        // build_message_fts 重建完整索引(大库很慢)后才报 ACCOUNT_AMBIGUOUS 白跑一场。R4 补的守卫(原在重建后)前移。
        let query_acct_sha: Option<Option<String>> = match &args.query {
            Some(_) => Some(native_query::resolve_account_sha(
                args.target.require_l1_db()?,
                args.target.account.clone(),
            )?),
            None => None,
        };
        let t0 = std::time::Instant::now();
        let n = storage::build_message_fts_incremental(&conn).context("建全文索引失败 (message 表在?)")?;
        eprintln!(
            "✅ 全文索引已建 (message_fts): {n} 条消息, {}ms; 增量触发器已建 —— 后续 ingest 新消息自动进索引, 不用再 --build",
            t0.elapsed().as_millis()
        );
        if let (Some(q), Some(acct_sha)) = (&args.query, query_acct_sha) {
            // acct_sha 已在重建前算好 (fail-closed 检查提前); 未给 --account 的多账号库上面已拒。
            print_search(&conn, q, args.limit, acct_sha.as_deref(), args.format)?;
        }
        return Ok(());
    }
    let q = args.query.as_deref().ok_or_else(|| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "--query 必填 (或用 --build 只建索引)",
        )
    })?;
    // R9 件2: --thin-db 给 → 搜独立瘦库 (search_thin: msg_id + snippet 高亮; 自存 content 不挂 L1)。
    if let Some(thin_path) = args.thin_db.as_deref() {
        let conn = storage::open_readonly(Path::new(thin_path)).map_err(|_| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                format!("打不开 thin db {thin_path} (先 `live-index build --tier thin --thin-db {thin_path}`)"),
            )
        })?;
        // codex 末轮 P1: 旧 schema 库 (无 source 列) 只读搜索无从迁移 → 给清晰"重建"提示, 别抛裸 "no such column: source"。
        if !storage::thin_fts_has_source(&conn).unwrap_or(false) {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "瘦库是旧版本 schema (无 source 列) —— 请用当前版本 `live-index build --tier thin` 或 `watch --live-index thin` 重建后再搜".to_string(),
            ));
        }
        // R5/R6 复审 P1#1: thin 库账号隔离 —— **先看绑定, 恒拒无绑定库** (不再"不带 --account 就放行")。
        let bound = storage::get_thin_account(&conn).context("读 thin 账号绑定失败")?;
        match (&bound, args.target.account.as_deref()) {
            // R6 复审 P1: **无账号绑定 (旧版 build 无 thin_meta 表) → 恒拒**, 不管有没有 --account。旧库可能含多账号正文
            // (R4 前 build 不按账号过滤), 裸搜会泄漏。无从自证单账号 → fail-closed 要求重建 (新库恒写绑定)。
            (None, _) => {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    format!(
                        "thin 库 {thin_path} 无账号绑定 (旧版 build 无 thin_meta, 可能含多账号内容, 无从核对) —— 重建以绑定账号: `live-index build --tier thin --thin-db {thin_path} --account <wxid>`"
                    ),
                ));
            }
            // 绑了 + 给了 --account 不符 → 拒 (跨账号: A 的库被 --account B 搜)。
            (Some(bound_sha), Some(req_wxid)) if *bound_sha != native_core::sha256_hex(req_wxid) => {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    format!(
                        "thin 库 {thin_path} 绑定的是另一个账号 (sha8 {}), 与 --account {} (sha8 {}) 不符 —— 换对应账号的 thin 库, 或重建: `live-index build --tier thin --thin-db {thin_path} --account {req_wxid}`",
                        bound_sha.chars().take(8).collect::<String>(),
                        req_wxid,
                        &native_core::sha256_hex(req_wxid)[..8]
                    ),
                ));
            }
            // 绑了 + 相符, 或绑了 + 没给 --account (搜本库唯一绑定账号) → 放行。
            (Some(_), _) => {}
        }
        // R7 复审 P2 (Claude 对抗审): thin 搜索 has_more 用 **limit+1 探针** (search_thin 满 limit 取, 无 COUNT/无 +1) ——
        // 镜像 search_query 范式。原 `Meta::page(len,len)` 把本页行数当总数 → 命中 >limit 时误报 total_count=limit +
        // has_more=false (HOLE-2 反模式), 把截断的 top-N 谎报成完整。cold_page 省 total_count (FTS bm25 top-N 无廉价精确
        // 计数) + 显式 has_more。原真跑 (limit=20, 3 命中) 未触及此截断边界。
        let limit = args.limit.max(0) as usize;
        let mut hits =
            storage::search_thin(&conn, q, limit.saturating_add(1)).context("thin 搜索失败 (库是 thin FTS?)")?;
        let has_more = hits.len() > limit;
        hits.truncate(limit);
        // R6 复审 P2: thin 搜索也遵 `--format` —— json 出 {data,meta} 信封 (source=live-index + account sha8), 别只文本行
        // (原直打, AI/脚本调用拿不到契约结构)。bound 已在上方核对过, 此处直接用于 meta.account。
        match args.format {
            OutFormat::Json => {
                // 返 (msg_id, source, snippet): 跨分片同锚须连 source 才唯一 rejoin L1 (codex 复审 P2)。
                let data: Vec<serde_json::Value> = hits
                    .iter()
                    .map(|(msg_id, source, snippet)| {
                        serde_json::json!({ "msg_id": msg_id, "source": source, "snippet": snippet })
                    })
                    .collect();
                let mut meta = native_query::Meta::cold_page(has_more).with_source(native_query::Source::LiveIndex);
                if let Some(b) = &bound {
                    meta.account = Some(b.chars().take(8).collect());
                }
                native_query::emit_envelope(&data, meta)?;
            }
            OutFormat::Table => {
                eprintln!(
                    "[search] thin \"{q}\" 命中 {} 条{} (取前 {}):",
                    hits.len(),
                    if has_more { "+" } else { "" },
                    limit
                );
                for (msg_id, source, snippet) in &hits {
                    println!("  {msg_id} [{source}]｜{snippet}");
                }
            }
        }
        return Ok(());
    }
    // search 用**非 scoped** conn: FTS 路靠 `message.rowid` 关联 message_fts, message 被遮蔽视图替换则
    // rowid 断 → 账号隔离改走 search_query → search_messages 的**显式谓词** (account_sha 传下去)。
    let conn = open_l1(args.target.require_l1_db()?)?;
    // R9 复审R3#1: search 也 resolve_account fail-closed —— 未给 --account 多账号库 → 报错 (不搜全账号混);
    // 否则用解析出的 account_sha 作 search_messages 的显式谓词 (FTS 非 scoped conn, 靠显式过滤隔离)。
    let acct_sha = native_query::resolve_account_sha(args.target.require_l1_db()?, args.target.account.clone())?;
    let has_fts: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='message_fts'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has_fts == 0 {
        eprintln!(
            "[search] 提示: 未建全文索引 → 走全表 LIKE 扫描 (大库慢); `search --l1-db {} --build` 建索引后 ms 级。",
            args.target.l1_db.as_deref().unwrap_or("<L1库>") // R16-1: l1_db 转 Option (本路径必有值, 兜底占位)
        );
    }
    print_search(&conn, q, args.limit, acct_sha.as_deref(), args.format)
}

/// 打印搜索命中 (L1 明文库, 用户查自己数据; 时间 / 会话 / 发送者 / 正文预览)。搜索取数/has_more/json+meta
/// 在核 `search_query` (fetch limit+1 探 has_more + `Meta::cold_page`); 此薄壳按 format 呈现: table 计时
/// (`{}ms`)/预览截断留皮 (读 `r.data` by key), json 走信封。(`--build` 建 FTS 索引=写, 在 `cmd_search` 皮不在此。)
fn print_search(
    conn: &rusqlite::Connection,
    query: &str,
    limit: i64,
    account_sha: Option<&str>,
    format: OutFormat,
) -> Result<()> {
    match format {
        OutFormat::Table => {
            let t0 = std::time::Instant::now();
            let r = native_query::search_query(conn, query, limit, account_sha)?;
            eprintln!(
                "[search] \"{query}\" 命中 {} 条 (取前 {limit}, {}ms):",
                r.data.len(),
                t0.elapsed().as_millis()
            );
            for row in &r.data {
                let text = row["text_content"].as_str().unwrap_or_default();
                let preview: String = text.chars().take(80).collect::<String>().replace('\n', " ");
                // 时间/会话/发送者内联读 (不绑局部, 避 conn↔conv 近名 lint; 输出同旧)。
                println!(
                    "  [{}] {}｜{}: {preview}",
                    row["create_time"].as_i64().unwrap_or_default(),
                    row["conv_id"].as_str().unwrap_or_default(),
                    row["sender_wxid"].as_str().unwrap_or_default()
                );
            }
        }
        OutFormat::Json => {
            let r = native_query::search_query(conn, query, limit, account_sha)?;
            emit_envelope(&r.data, r.meta)?;
        }
    }
    Ok(())
}

/// `decrypt-emoji` — 读 emoticon.db → 每个表情从 CDN 下载加密字节 → AES-128-CBC 解密 → 落图。**需联网** (打
/// 微信 CDN, http)。微信自定义表情不在本地明文存, 只能下载解密 (竞品 WCDA 同款; ADR-461)。best-effort。
fn cmd_decrypt_emoji(args: &DecryptEmojiArgs) -> Result<()> {
    use std::io::Read as _;

    use native_core::decoder::{detect_format, DatFormat};
    use native_core::media::{decrypt_emoticon, read_emoticons};

    // codex P1: 限单个表情响应大小 (http 无 TLS, 坏/注入响应能爆内存)。表情包实际最大几 MB, 30 MiB 足够。
    const MAX_EMOJI_BYTES: u64 = 30 * 1024 * 1024;

    let out_dir = Path::new(&args.out_dir);
    let conn = native_core::storage::open_readonly(Path::new(&args.emoticon_db)).map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "打不开 emoticon.db (只读; 须已解密的明文 sqlite; 含 kNonStoreEmoticonTable)",
        )
    })?;
    let refs = read_emoticons(&conn).context(
        // 同上: 指到加密的真 emoticon.db 会撞这里, 而原文案把加密问题赖到"表结构不符"。
        // ⚠️ `decrypt-emoji` **没有 `--cipher` 参数**(实测 --help 里没有), 所以这里不能像
        // export-voices 那样叫人加 --cipher —— 照做只会撞 `unexpected argument`。
        // 它只吃已解密的明文库。(上一轮我把两条命令的提示写成一样的, 对这条不成立。)
        "读 emoticon.db 失败 (库是加密的? 本命令只吃已经解密好的明文 sqlite —— 先解密再指过来; 它没有 --cipher 开关)",
    )?;
    anyhow::ensure!(
        !refs.is_empty(),
        "emoticon.db 里没有带 aes_key + URL 的表情 (kNonStoreEmoticonTable 空?)"
    );

    std::fs::create_dir_all(out_dir).with_context(|| format!("建输出目录 {} 失败", args.out_dir))?;
    // 20s 超时; http (CDN 是 http 非 https, 无需 TLS)。
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("建 http 客户端失败")?;

    let total = args.limit.map_or(refs.len(), |l| l.min(refs.len()));
    let (mut written, mut failed) = (0usize, 0usize);
    eprintln!("从 CDN 下载解密 {total} 个表情 (需联网)…");
    for r in refs.iter().take(total) {
        // 逐 URL 候选试: 下载 → CBC 解密 → 是已知图才落 (K-R4: 不打印 url/key)。
        let mut done = false;
        for url in &r.urls {
            let Ok(resp) = client.get(url).send() else { continue };
            if !resp.status().is_success() {
                continue;
            }
            // Content-Length 预检超限就跳 (省下载); 无 CL 或谎报则靠下面 take 硬限流兜底。
            if resp.content_length().is_some_and(|n| n > MAX_EMOJI_BYTES) {
                continue;
            }
            let mut bytes = Vec::new();
            if resp.take(MAX_EMOJI_BYTES).read_to_end(&mut bytes).is_err() {
                continue; // 读失败 / 超限截断出错 → 试下一候选
            }
            if bytes.is_empty() {
                continue; // 空响应 (URL 失效) → 试下一候选
            }
            let Some(img) = decrypt_emoticon(&bytes, &r.aes_key) else {
                continue;
            };
            let fmt = detect_format(&img);
            if fmt == DatFormat::Unknown {
                continue; // 解出不是已知图 (key/URL 不对) → 试下一候选
            }
            let out = out_dir.join(format!("{}.{}", r.md5, fmt.ext()));
            // 同 image_export: 写失败(磁盘满等)可能留半截文件, 删掉免得用户当成好文件。
            let wrote = match std::fs::write(&out, &img) {
                Ok(()) => true,
                Err(_) => {
                    let _ = std::fs::remove_file(&out);
                    false
                }
            };
            if wrote {
                written += 1;
                done = true;
                break;
            }
        }
        if !done {
            failed += 1; // 所有 URL 都下不到/解不出 (多为 URL 失效)
        }
    }
    eprintln!(
        "{} 表情包解密: {total} 个 → 落图 {written} / 失败(URL失效或解不出) {failed} → {}",
        if written == 0 && total > 0 {
            "🛑"
        } else if failed > 0 {
            "⚠️"
        } else {
            "✅"
        },
        args.out_dir
    );
    export_outcome(
        total as u64,
        written as u64,
        failed as u64,
        0, // CDN 下载没有"源文件被本地清理"这一档: 链接失效直接算 failed
        "表情包解密",
        "表情包只存在微信 CDN 上, 老表情的链接会失效 —— 全失败多半是这个, 不是你配置错了。",
    )
}

/// `export-sns-media` — 朋友圈媒体导出 (ADR-467 件3)。读 L1 moment_media 拿 url/token/enc_idx/url_key,
/// CDN 下载 (`url?token=X&idx=N`) → enc_idx=1 用 WxIsaac64 (node WASM) XOR 解密 (图全文/视频前128KB) →
/// 落 .jpg/.png/.mp4。best-effort (URL 失效/解不出跳过)。**需联网 + 系统 node**。
fn cmd_export_sns_media(args: &ExportSnsMediaArgs) -> Result<()> {
    use std::io::Read as _;

    use native_core::decoder::{detect_format, DatFormat};
    use native_core::media::{build_download_url, decrypt_sns_media, read_sns_media_refs};

    // SNS 视频可能几十 MB; 100 MiB 上限防坏响应爆内存 (同 emoji MAX_EMOJI_BYTES)。
    const MAX_MEDIA_BYTES: u64 = 100 * 1024 * 1024;

    // 定位 vendor 的 node keystream 脚本 (换机器需装 node; ADR-467 件3 可移植性代价)。
    let wasm_dir = resolve_sns_wasm_dir(args.wasm_dir.as_deref())?;
    let node_script = wasm_dir.join("weflow_wasm_keystream.js");
    if !node_script.is_file() {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!(
                "找不到 {}/weflow_wasm_keystream.js (--wasm-dir 需含 keystream 脚本 + wasm_video_decode.wasm/.js)",
                wasm_dir.display()
            ),
        ));
    }

    let out_dir = Path::new(&args.out_dir);
    let conn = open_l1_resolved(&args.target)?;
    let refs = read_sns_media_refs(&conn).context("读 moment_media 失败 (表结构不符?)")?;
    if refs.is_empty() {
        return Err(cli_err(
            native_core::ErrorCode::NeedsIngest,
            "moment_media 里没有带 url 的媒体 (先跑 `msgvestige ingest --sns`)",
        ));
    }
    std::fs::create_dir_all(out_dir).with_context(|| format!("建输出目录 {} 失败", args.out_dir))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("建 http 客户端失败")?;

    let total = args.limit.map_or(refs.len(), |l| l.min(refs.len()));
    let (mut written, mut failed) = (0usize, 0usize);
    eprintln!("从 CDN 下载解密 {total} 条朋友圈媒体 (需联网 + node)…");
    for r in refs.iter().take(total) {
        // 下载 (K-R4: 不打印 url/token/key)。
        let url = build_download_url(&r.url, r.token.as_deref(), &r.enc_idx);
        let Ok(resp) = client.get(&url).send() else {
            failed += 1;
            continue;
        };
        if !resp.status().is_success() || resp.content_length().is_some_and(|n| n > MAX_MEDIA_BYTES) {
            failed += 1;
            continue;
        }
        let mut bytes = Vec::new();
        if resp.take(MAX_MEDIA_BYTES).read_to_end(&mut bytes).is_err() || bytes.is_empty() {
            failed += 1; // URL 失效 / 读失败
            continue;
        }
        // 解密 (enc_idx=1 走 node WxIsaac64 XOR; 明文原样)。
        let Ok(dec) = decrypt_sns_media(bytes, r, &node_script) else {
            failed += 1; // 缺 key / node 失败
            continue;
        };
        // 文件名主干: md5 优先, 否则 moment PK + seq。
        let stem = r
            .md5
            .clone()
            .unwrap_or_else(|| format!("{}_{}", r.source_native_id, r.media_seq));
        // 视频落 .mp4 (不校验图头); 图校验图头 (解不出正确图头 = key/URL 不对, 跳)。
        let out = if r.media_type == 6 {
            out_dir.join(format!("{stem}.mp4"))
        } else {
            let fmt = detect_format(&dec);
            if fmt == DatFormat::Unknown {
                failed += 1;
                continue;
            }
            out_dir.join(format!("{stem}.{}", fmt.ext()))
        };
        // 同上: 写失败可能留半截文件, 删掉。
        let wrote = match std::fs::write(&out, &dec) {
            Ok(()) => true,
            Err(_) => {
                let _ = std::fs::remove_file(&out);
                false
            }
        };
        if wrote {
            written += 1;
        } else {
            failed += 1;
        }
    }
    eprintln!(
        "{} 朋友圈媒体导出: {total} 条 → 落 {written} / 失败(URL失效或解不出) {failed} → {}",
        if written == 0 && total > 0 {
            "🛑"
        } else if failed > 0 {
            "⚠️"
        } else {
            "✅"
        },
        args.out_dir
    );
    export_outcome(
        total as u64,
        written as u64,
        failed as u64,
        0, // 同上, CDN 路没有本地清理这一档
        "朋友圈媒体导出",
        "两种可能: 老动态的 CDN 链接失效(常见), 或者 node/wasm 没配好(精简包不带, 用完整版包试)。",
    )
}

/// 定位 vendor 的 weflow_wasm 目录: `--wasm-dir` → `WECHAT_SNS_WASM_DIR` env → cli 同目录 `vendor/weflow_wasm`。
fn resolve_sns_wasm_dir(arg: Option<&str>) -> Result<std::path::PathBuf> {
    use std::path::PathBuf;
    if let Some(d) = arg {
        return Ok(PathBuf::from(d));
    }
    if let Ok(d) = std::env::var("WECHAT_SNS_WASM_DIR") {
        return Ok(PathBuf::from(d));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(cand) = exe.parent().map(|p| p.join("vendor").join("weflow_wasm")) {
            if cand.is_dir() {
                return Ok(cand);
            }
        }
    }
    Err(cli_err(
        native_core::ErrorCode::BadRequest,
        "需 --wasm-dir 指 weflow_wasm 目录 (或设 WECHAT_SNS_WASM_DIR); 该目录须含 weflow_wasm_keystream.js + wasm_video_decode.wasm/.js, 且系统装 node",
    ))
}

/// `decrypt-images` — 图片解密落图。两模式: 缺省**消息驱动** (走 message db packed_info, 主拿 V0 缩略图);
/// `--full-images` **扫盘** (递归 msg/attach 解 V2 完整原图 + wxgf 动图)。best-effort。
fn cmd_decrypt_images(args: &DecryptImagesArgs, db_key: Option<&MasterKey>) -> Result<()> {
    use native_core::media::{export_full_images, export_images, export_sns_cache_images};

    // K-R4: --account-dir / --message-db 路径含 wxid, 报错不回显原路径 (只描述性提示)。
    let account_dir = Path::new(&args.account_dir);
    if !account_dir.is_dir() {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--account-dir 不是有效目录 (须指向 xwechat_files 下账号目录)",
        ));
    }
    let acct_canon = account_dir.canonicalize().context("--account-dir 无法规范化")?;
    // 防污染: canonical 比较 (挡 .. / 大小写 / symlink 绕过, 非纯词法; codex P1)。**不预建 out_dir**
    //  (否则拒绝路径也会在 account_dir 里留空目录 = 部分违背"别写进微信目录")。out_dir 由 export 创建。
    let out_dir = Path::new(&args.out_dir);
    let out_canon = canonical_nonexistent(out_dir).context("--out-dir 路径无效")?;
    if out_canon.starts_with(&acct_canon) {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--out-dir 不能落在 --account-dir 内 (会把图写进微信目录); 换个位置",
        ));
    }

    // key 来源: 手填 (--image-key + --image-xor) 或自动扫微信内存 (都省略时; 样本从 msg/attach 扫, 不用 db)。
    let key = resolve_image_key(args, account_dir)?;

    let stats = if args.sns_cache_images {
        // 朋友圈缓存扫盘模式: 扫 cache/<月>/Sns/Img/** 解 V2 落图, 不需 message db。
        export_sns_cache_images(&account_dir.join("cache"), &key, out_dir, args.limit)
    } else if args.full_images {
        // 扫盘模式: 递归解 V2 完整原图 (含 wxgf), 不需 message db。
        export_full_images(account_dir, &key, out_dir, args.limit)
    } else {
        // 消息驱动模式: 走 message db packed_info 定位 (主拿 V0 缩略图)。
        let db = args
            .message_db
            .as_deref()
            .context("消息驱动模式须给 --message-db (要 V2 完整图/wxgf 动图请加 --full-images 走扫盘模式)")?;
        // db_key: --cipher native 时就地解密 message db; 否则读已解密明文。图 .dat 的 image key 是 `key` (另一回事)。
        let conn_src = open_source_db(Path::new(db), db_key, "message db")?;
        export_images(conn_src.conn(), account_dir, &key, out_dir, args.limit).context("图片导出失败 (db 级错误)")?
    };
    let mode_label = if args.sns_cache_images {
        "朋友圈缓存扫盘"
    } else if args.full_images {
        "扫盘全分辨率图"
    } else {
        "消息驱动 缩略图"
    };
    eprintln!(
        "{} 图片导出 ({mode_label}): 扫到 {} 张 → 落图 {} / wxgf动图 {} / 已清理(盘上无) {} / 失败 {} → {}",
        if stats.failed > 0 {
            if stats.written + stats.wxgf == 0 {
                "🛑"
            } else {
                "⚠️"
            }
        } else {
            "✅"
        },
        stats.scanned,
        stats.written,
        stats.wxgf,
        stats.missing,
        stats.failed,
        args.out_dir
    );
    // wxgf 也算产出 —— 留了原文件, 内容没丢, 装了 ffmpeg 重跑就能转 GIF。
    // missing(已清理) 单列: 微信自己把文件删了, 不是本工具的失败。
    let img_outcome = export_outcome(
        stats.scanned as u64,
        (stats.written + stats.wxgf) as u64,
        stats.failed as u64,
        stats.missing as u64,
        "图片导出",
        "看上面的分项: 失败多半是 .dat 解密失败或写盘失败; 若大量「已清理」那是微信自己删的, 重试无用。",
    );
    // wxgf 动图 (内层 HEVC): 有 ffmpeg 就转 GIF, 没有就留 .wxgf (内容不丢, 装 ffmpeg 后重跑再转)。
    if stats.wxgf > 0 {
        match native_core::media::resolve_ffmpeg(args.ffmpeg.as_deref()) {
            Some(ff) => {
                let (ok, fail) = transcode_wxgf_dir(&ff, out_dir);
                eprintln!("   wxgf→图: 转出 {ok} / 失败 {fail} (静图→PNG 无损 / 动图→GIF; 转成功删 .wxgf)");
            }
            None => eprintln!(
                "   ⚠️ {} 个 wxgf 动图已解密留 .wxgf, 但没找到 ffmpeg → 未转 GIF \
                 (装 ffmpeg 或 --ffmpeg <路径> / 设 WECHAT_FFMPEG 后重跑本命令即可转)",
                stats.wxgf
            ),
        }
    }
    // 结论放**最后**返回: 上面 wxgf 转码那段还要打印, 提前 `?` 会把它吞掉。
    img_outcome
}

// ffmpeg/ffprobe 解析 + wxgf 帧数 + **字节级**转码已提到 native_core::media::wxgf (serve + cli 共用, 去重):
// resolve_ffmpeg / resolve_ffprobe / wxgf_frame_count / transcode_wxgf_bytes。本文件仅留 transcode_wxgf_dir
// (目录批量版, cli decrypt-images 专用: 原地 rename + 删 .wxgf, serve 用不到)。

/// 把 `out_dir` 里所有 `.wxgf` 转成图: **单帧静图→PNG (无损, 全分辨率照片/截图别用 256 色 GIF 掉质),
/// 多帧动图→GIF**。转成功删 .wxgf 只留图; 转失败留 .wxgf (内容不丢, 可重试)。返回 (转出数, 失败数)。
///
/// wxgf 内层是 HEVC, 但 ffmpeg **自动检测对部分 wxgf 不可靠** (实测 36 张自动只认 16), 故一律 `-f hevc`
/// 强制 HEVC 解复用器 (全认)。帧数用 ffprobe 探 (取不到就当动图走 GIF, 保动画不丢)。
fn transcode_wxgf_dir(ffmpeg: &Path, out_dir: &Path) -> (usize, usize) {
    let (mut ok, mut fail) = (0usize, 0usize);
    let ffprobe = native_core::media::resolve_ffprobe(ffmpeg); // 跟 ffmpeg 同目录 (vendored 一起)
    let Ok(entries) = std::fs::read_dir(out_dir) else {
        return (0, 0);
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.extension().is_some_and(|e| e.eq_ignore_ascii_case("wxgf")) {
            continue;
        }
        // 探不到帧数 → 当动图 (map_or 默认 true): GIF 保动画不丢, 只是静图会掉质 (次优兜底)。
        let animated = ffprobe
            .as_deref()
            .and_then(|pp| native_core::media::wxgf_frame_count(pp, &p))
            .is_none_or(|n| n > 1);
        let ext = if animated { "gif" } else { "png" };
        let out_img = p.with_extension(ext);
        // codex P1: 转到唯一临时文件, 成功再 rename → 失败**绝不碰**同名已有输出图 (上次成功的 / 用户手放的)。
        // 临时名保留正确扩展名 (.png/.gif) 让 ffmpeg 从扩展名选对 muxer。
        let tmp_out = p.with_extension(format!("wxgf2img.{ext}"));
        let mut cmd = std::process::Command::new(ffmpeg);
        cmd.args(["-y", "-loglevel", "error", "-f", "hevc", "-i"]).arg(&p);
        if !animated {
            cmd.args(["-frames:v", "1"]); // 静图只取首帧 → PNG
        }
        cmd.arg(&tmp_out);
        // 有界超时 (§8 round2 P3: 病态 HEVC 不挂死整批; 单文件超时 kill 计 fail 留 .wxgf, 内容不丢, 批量继续)。
        if native_core::media::status_with_timeout(cmd, std::time::Duration::from_secs(30))
            && tmp_out.is_file()
            && std::fs::rename(&tmp_out, &out_img).is_ok()
        {
            let _ = std::fs::remove_file(&p); // 转成功 → 删 .wxgf 只留图
            ok += 1;
        } else {
            let _ = std::fs::remove_file(&tmp_out); // 只清临时半成品, 不碰 out_img
            fail += 1; // 留 .wxgf (内容不丢, 可重试)
        }
    }
    (ok, fail)
}

/// `image-key` —— 取账号图片 image key (手填 `--image-key`/`--image-xor` 或自动扫微信内存) → 存独立
/// `ImageKeyCache` (serve `/media/img` 读它解 V2 完整图)。跟 master key `auth` 分开: image key 是另一把
/// (账号级 AES + XOR)。K-R4: 不回显 key 原值, 报账号走 Wxid Display (sha8)。
fn cmd_image_key(args: &ImageKeyArgs) -> Result<()> {
    let wxid = native_core::Wxid::try_new(&args.wxid)
        .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--wxid 非法 (须 wxid_<id>)"))?;
    let (key, source) = match (args.image_key.as_deref(), args.image_xor.as_deref()) {
        (Some(k), Some(x)) => (parse_explicit_image_key(k, x)?, "manual"),
        (None, None) => {
            let dir = args.account_dir.as_deref().context(
                "自动扫 image key 需 --account-dir (从 msg/attach 取 V2 样本); 或手填 --image-key/--image-xor",
            )?;
            (scan_image_key_auto(Path::new(dir))?, "scan")
        }
        _ => {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "--image-key 和 --image-xor 要么都给 (手填) 要么都不给 (自动扫) — 现在只给了一个",
            ))
        }
    };
    native_core::ImageKeyCache::new(None)
        .store(&wxid, &key.aes, key.xor, source)
        .context("存 image key 到 cache 失败")?;
    eprintln!("✅ image key 已存 (账号 {wxid}, 源 {source}) → serve /media/img 可解 V2 完整图");
    Ok(())
}

/// image key 来源分派: `--image-key`+`--image-xor` **都给** = 手填; **都省** = 自动扫微信内存 (仅 win-x64)。
/// 只给一个 → 报错 (要么都给要么都不给, 避免半套 key)。
fn resolve_image_key(args: &DecryptImagesArgs, account_dir: &Path) -> Result<native_core::decoder::ImageKey> {
    match (args.image_key.as_deref(), args.image_xor.as_deref()) {
        (Some(k), Some(x)) => parse_explicit_image_key(k, x),
        (None, None) => scan_image_key_auto(account_dir),
        _ => Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--image-key 和 --image-xor 要么都填 (手填 key) 要么都不填 (自动扫内存取 key) — 现在只给了一个",
        )),
    }
}

/// 手填路: 解析 `--image-key` (16 ASCII) + `--image-xor` (hex 单字节)。K-R4: 报错不回显 key 原值。
fn parse_explicit_image_key(image_key: &str, image_xor: &str) -> Result<native_core::decoder::ImageKey> {
    let key_bytes = image_key.as_bytes();
    if key_bytes.len() != 16 {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!(
                "--image-key 须 16 位 ASCII (当前 {} 位) — 填 wx_key 给的 aesKey 原样, 别 hex-decode",
                key_bytes.len()
            ),
        ));
    }
    let mut aes = [0u8; 16];
    aes.copy_from_slice(key_bytes);
    let xor_hex = image_xor.trim().trim_start_matches("0x").trim_start_matches("0X");
    let xor = u8::from_str_radix(xor_hex, 16).map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "--image-xor 非法 (须是十六进制字节, 如 d3 或 0xd3)",
        )
    })?;
    Ok(native_core::decoder::ImageKey { aes, xor })
}

/// 自动扫路 (Windows x64): 收 V2 样本 → 扫微信内存取 AES key → 从样本尾反推 XOR。K-R4: key 只 sha8 打印。
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn scan_image_key_auto(account_dir: &Path) -> Result<native_core::decoder::ImageKey> {
    use native_core::decoder::{derive_v2_xor, ImageKey};
    use native_core::media::collect_v2_samples;
    use native_keyscan::{scan_image_key, sha8, WeixinProcess};

    eprintln!("未给 --image-key → 自动扫微信内存取 image key…");
    // 1. 从 msg/attach 直接扫 V2 完整图**池** (≥2 张互不相同)。不经 message db: packed_info 的 md5 指向
    //    V0 缩略图, 顺它走拿不到 V2 (账号级 AES key 只加密完整图)。收较大池 (10): scan 只需前几张做锚,
    //    derive 要从整池找 JPEG/PNG (codex P2: 前几张若全 WXGF/GIF/WEBP 会误报 xor 反推失败 → 大池分离
    //    "验证锚"与"xor 推导样本")。
    let pool = collect_v2_samples(account_dir, 10);
    anyhow::ensure!(
        pool.len() >= 2,
        "只找到 {} 张 V2 完整图样本 (交叉验证需 ≥2) — 该账号多数图只存了缩略图(没点开下原图); \
         手填 --image-key/--image-xor 绕过",
        pool.len()
    );
    // scan 锚: 取前 4 张 (锚少更快, 每张都要过 is_image_head; ≥2 即够多锚交叉验证把假阳压到 0)。
    let anchors: Vec<&[u8]> = pool.iter().take(4).map(Vec::as_slice).collect();

    // 2. 开微信进程扫 AES key (瞬态驻留 → 重试多轮; 期间可在微信里点开几张图触发 key 加载)。
    let proc =
        WeixinProcess::open(None).context("打开微信进程失败 (微信没在跑? 手填 --image-key/--image-xor 绕过内存扫)")?;
    let mut aes = None;
    for round in 1..=8 {
        if let Some(k) = scan_image_key(&proc, &anchors) {
            eprintln!("第 {round}/8 轮扫到 image AES key");
            aes = Some(k);
            break;
        }
    }
    let aes = aes
        .context("8 轮没扫到 image key (key 瞬态; 在微信里点开几张图触发加载再重跑, 或手填 --image-key/--image-xor)")?;

    // 3. 从**整池** (不止前 4 锚) 找 JPEG/PNG 样本反推账号 XOR → 前几张全 WXGF 也能从后面的 JPEG 推出。
    let xor = pool
        .iter()
        .find_map(|s| derive_v2_xor(s, &aes))
        .context("AES key 扫到但 xor 反推失败 (整池无 JPEG/PNG 尾样本?); 手填 --image-xor 补上")?;

    eprintln!("✅ 自动取 image key 成功 (aes sha8={}, xor 已反推)", sha8(&aes));
    Ok(ImageKey { aes, xor })
}

/// 非 Windows-x64: 内存扫不可用 → 要求手填 key。
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn scan_image_key_auto(_account_dir: &Path) -> Result<native_core::decoder::ImageKey> {
    Err(cli_err(
        native_core::ErrorCode::BadRequest,
        "自动扫 image key 仅 Windows x64 支持 — 用 --image-key + --image-xor 手填 (wx_key/内存扫取)",
    ))
}

/// `export-videos` — 遍历 message db 视频消息 (local_type=43), 经 hardlink 定位, 明文拷出 / 加密降级。
/// 视频**不解密** (微信视频加密无账号级 key; 明文那份靠转码缓存, 加密的降级提示微信里播一次)。best-effort。
fn cmd_export_videos(args: &ExportVideosArgs, db_key: Option<&MasterKey>) -> Result<()> {
    use native_core::media::export_videos;

    // K-R4: --account-dir / *-db 路径含 wxid, 报错不回显原路径 (只描述性提示)。
    let account_dir = Path::new(&args.account_dir);
    if !account_dir.is_dir() {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--account-dir 不是有效目录 (须指向 xwechat_files 下账号目录)",
        ));
    }
    let acct_canon = account_dir.canonicalize().context("--account-dir 无法规范化")?;
    // 防污染: out_dir 不能落在 account_dir 内 (会把视频写回微信目录)。canonical 比较 + 不预建 (同 decrypt-images)。
    let out_dir = Path::new(&args.out_dir);
    let out_canon = canonical_nonexistent(out_dir).context("--out-dir 路径无效")?;
    if out_canon.starts_with(&acct_canon) {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--out-dir 不能落在 --account-dir 内 (会把视频写进微信目录); 换个位置",
        ));
    }

    // db_key: --cipher native 时就地解密两库 (同账号同 master key); 否则读已解密明文。
    // 双审 P2: 两库 image 同时驻留内存 (视频导出需 message↔hardlink 交替查, 无法先 drain 一库), 峰值 ≈ 两库之和。
    let msg_src = open_source_db(Path::new(&args.message_db), db_key, "message db")?;
    let hardlink_src = open_source_db(
        Path::new(&args.hardlink_db),
        db_key,
        "hardlink db (video_hardlink_info_v4)",
    )?;
    let stats = export_videos(msg_src.conn(), hardlink_src.conn(), account_dir, out_dir, args.limit)
        .context("视频导出失败 (db 级错误)")?;
    // codex P2: --limit 达到即提前返回 → 统计是"扫到第 N 个明文前"的截断前缀, 非全库; 命中时注明避免误读。
    let truncated = args.limit.is_some_and(|l| stats.plaintext >= l);
    eprintln!(
        "{} 视频导出: 扫到 {} 条{} → 明文拷出 {} / 加密降级 {} / 已清理(盘上无) {} / 失败 {} → {}",
        if stats.failed > 0 {
            if stats.plaintext + stats.encrypted == 0 {
                "🛑"
            } else {
                "⚠️"
            }
        } else {
            "✅"
        },
        stats.scanned,
        if truncated {
            " (达 --limit 提前停, 统计为截断前缀; 去掉 --limit 看全量)"
        } else {
            ""
        },
        stats.plaintext,
        stats.encrypted,
        stats.missing,
        stats.failed,
        args.out_dir
    );
    // 加密降级也算产出(拷出了加密原文, 内容没丢); missing 是微信自己清的, 不算失败。
    export_outcome(
        stats.scanned as u64,
        (stats.plaintext + stats.encrypted) as u64,
        stats.failed as u64,
        stats.missing as u64,
        "视频导出",
        "看上面的分项: 大量「已清理」是微信自己删了盘上文件, 重试无用; 「失败」才是真出错。",
    )
}

/// `export-voices` — 遍历(已解密)media_0.db 的 VoiceInfo, SILK v3 解码 → WAV 落盘。best-effort (ADR-465 件 2)。
fn cmd_export_voices(args: &ExportVoicesArgs, db_key: Option<&MasterKey>) -> Result<()> {
    use native_core::media::export_voices;

    // K-R4: media_db 路径含 wxid, 报错不回显原路径 (只描述性提示)。
    let media_path = Path::new(&args.media_db);
    // 防污染: out_dir 不能落在 media_0.db 所在目录内 (会把 wav 写进微信数据目录)。
    // 双审 P2-b: parent() 对裸文件名 (无目录分隔) 返回 Some("") 空路径, "".canonicalize() 在 Windows Err
    // → 误拒。空则退当前目录 "."。
    let media_dir = media_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let media_dir_canon = media_dir.canonicalize().map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "--media-db 所在目录无法规范化 (确认路径正确)",
        )
    })?;
    let out_canon = canonical_nonexistent(Path::new(&args.out_dir)).context("--out-dir 路径无效")?;
    if out_canon.starts_with(&media_dir_canon) {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "--out-dir 不能落在 media_0.db 所在目录内 (会写进微信数据目录); 换个位置",
        ));
    }

    // **枚举同目录全部 media_<N>.db 分片**导出 (媒体库文件级分片 media_0/media_1/…; 只导 --media-db 单个会漏
    // 其它分片里的语音 = 丢数据)。给 media_0.db 即导全部分片; 非常规命名/单文件退回该显式路径。
    // db_key: --cipher native 时就地解密; 否则读已解密明文 (同一账号 key 通用于各分片)。
    let mut shards = native_query::media_db_files(media_dir);
    if shards.is_empty() {
        shards = vec![media_path.to_path_buf()];
    }
    let mut stats = native_core::media::VoiceExportStats::default();
    for shard in &shards {
        let remaining = args.limit.map(|l| l.saturating_sub(stats.exported));
        if remaining == Some(0) {
            break; // 已达全局 --limit
        }
        let media_src = open_source_db(shard, db_key, "media db (含 VoiceInfo 表)")?;
        let s = export_voices(media_src.conn(), Path::new(&args.out_dir), remaining).context(
            // 用户照文档「直接指到库文件」指到**加密的**真库时就撞这里。原文案只说
            // "db 级错误", 看不出是加密问题 —— 而 open_source_db 里那句正确提示
            // ("须是已解密明文 sqlite; 或加 --cipher native") 走不到: SQLite 惰性打开,
            // is_file 过了、open 也"成功", 要到真读表才炸。跟已修的 doctor L1 同一类死分支。
            "语音导出失败 (库是加密的? 加 `--cipher native --wxid <你的 wxid>` 直读加密库; 或先解密成明文 sqlite)",
        )?;
        stats.scanned += s.scanned;
        stats.exported += s.exported;
        stats.partial += s.partial;
        stats.failed += s.failed;
    }
    let truncated = args.limit.is_some_and(|l| stats.exported >= l);
    eprintln!(
        "{} 语音导出: {} 个 media 分片 · 扫 {} 条{} → 完整 {} .wav / 不完整 {} .partial.wav(截断/中途坏, 供预览非归档) / 失败(非SILK/坏/写盘) {} → {}",
        if stats.failed > 0 {
            if stats.exported + stats.partial == 0 { "🛑" } else { "⚠️" }
        } else {
            "✅"
        },
        shards.len(),
        stats.scanned,
        if truncated { " (达 --limit 提前停; 去掉 --limit 看全量)" } else { "" },
        stats.exported, stats.partial, stats.failed, args.out_dir
    );
    // --mp3: 把落的 wav 转 MP3 (ffmpeg 外部, 同 wxgf 转码套路; 转成功删 wav 只留 mp3, 失败留 wav 不丢内容)。
    // 含 .partial.wav (预览也转)。
    if args.mp3 && stats.exported + stats.partial > 0 {
        match native_core::media::resolve_ffmpeg(args.ffmpeg.as_deref()) {
            Some(ff) => {
                let (ok, fail) = transcode_wav_dir_to_mp3(&ff, Path::new(&args.out_dir));
                eprintln!("   wav→mp3: 转出 {ok} / 失败 {fail} (libmp3lame -q:a 4; 转成功删 .wav)");
            }
            None => eprintln!(
                "   ⚠️ --mp3 但没找到 ffmpeg → 留 .wav (装 ffmpeg 或 --ffmpeg <路径> / 设 WECHAT_FFMPEG 后重跑; wav 也能听)"
            ),
        }
    }
    // 不完整的 .partial.wav 也算产出(能听个大概, 内容没全丢)。语音没有"源文件被清理"这一档。
    export_outcome(
        stats.scanned as u64,
        (stats.exported + stats.partial) as u64,
        stats.failed as u64,
        0,
        "语音导出",
        "失败多是那条记录不是 SILK 格式、数据损坏、或写盘失败 —— 看上面的分项。",
    )
}

/// 枚举 message db **文件级分片** (`message_0.db … message_N.db` 同目录; 只读单个会漏别的分片 = 丢数据, 见两级分片契约)。
/// 排除 `message_fts.db` / `message_resource.db` (非会话消息表)。空则退回给的单文件。
fn message_shards(message_db: &str) -> Result<Vec<std::path::PathBuf>> {
    let p = Path::new(message_db);
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // 复审 P1: **不 fail-open** —— 目录枚举失败直接报错, 别静默退回单文件把别的分片丢了(两级分片契约: 丢分片=丢数据)。
    let entries = std::fs::read_dir(dir).map_err(|_| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            "枚举 message 分片目录失败 (确认 --message-db 路径正确)",
        )
    })?;
    let mut out = Vec::new();
    for e in entries {
        let e = e.map_err(|_| cli_err(native_core::ErrorCode::Internal, "读 message 分片目录项失败"))?;
        let name = e.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("message_").and_then(|r| r.strip_suffix(".db")) {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                out.push(e.path());
            }
        }
    }
    // 枚举**成功**但确无数字分片(非常规布局)→ 退回用户给的单文件(此时无分片可丢)。
    if out.is_empty() {
        out.push(p.to_path_buf());
    }
    out.sort();
    Ok(out)
}

/// `media-ingest` (R10 §11-②) — voice/video/image 按内容 sha256 收进 CAS 内容仓 + 侧车账本 (去重 + 逐项状态; 替批量导出)。
/// `--wxid` 算 `account_id_sha` 绑定内容仓; `--cipher native` 就地解密源库; 文件级分片全枚举。`--limit` 是**每种媒体全局**上限。
fn cmd_media_ingest(args: &MediaIngestArgs, db_key: Option<&MasterKey>) -> Result<()> {
    // 跨三类媒体的总计 —— 收尾按它决定图标和退出码 (见 export_outcome)。
    // 原先收尾是无条件 ✅ 且不带任何计数, 三类全被跳过时也打勾。
    let (mut total_discovered, mut total_produced, mut total_failed) = (0u64, 0u64, 0u64);
    use native_core::mediastore::{
        open_ledger, run_image_ingest, run_video_ingest, run_voice_ingest, ImageIngestStats, StoreLayout,
        VideoIngestStats, VoiceIngestStats,
    };

    let Some(wxid) = args.decrypt.wxid.as_deref() else {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            "media-ingest 需要 --wxid <wxid> 绑定内容仓账号",
        ));
    };
    // 复审 P1: --wxid 必须合法, 且**与源路径检测出的账号一致** —— 否则明文/`--master-key-hex` 模式下把账号 A 的库配
    // 账号 B 的 --wxid, A 的媒体会以 B 的 account_id_sha 入仓(open_ledger 只验自报的 B, 挡不住)= 账号串味。
    let wxid_parsed: Wxid = wxid
        .parse()
        .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--wxid 非法 (须合法微信 wxid)"))?;
    // 复审 P1: 含 --hardlink-db(它也是视频物化数据源, 漏它则 A 的 message/account 配 B 的 hardlink 会串味/漏视频)。
    for src in [&args.media_db, &args.message_db, &args.hardlink_db, &args.account_dir]
        .into_iter()
        .flatten()
    {
        if let Some(detected) = detect_wxid_from_path(Path::new(src)) {
            if detected != wxid_parsed {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "--wxid 与源库/目录路径检测到的账号不一致 (防账号串味); 核对 --wxid 或换对应账号的库/目录",
                ));
            }
        }
    }
    let account_id_sha = native_core::sha256_hex(wxid);
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0);
    // 块1(F2): 本次 ingest 的 run_id(pid+时刻; attempt/work provenance 用, 三源共用一个 run)。
    let run_id = format!("run-{}-{}", std::process::id(), now);

    // 复审 P1/P2: 内容仓与微信源目录**双向不相交**(仓在源内 or 源在仓内都拒——都会污染微信数据/被清理)。源路径先**绝对化**
    // (裸相对名如 `media_0.db` 的 parent 为空会漏检; `--store-root cas` 单段相对也 canon 不了)—— 全部 abs 后再比。
    let abs = |p: &str| -> std::path::PathBuf {
        let pb = std::path::PathBuf::from(p);
        if pb.is_absolute() {
            pb
        } else {
            std::env::current_dir().unwrap_or_default().join(pb)
        }
    };
    let store_canon = canonical_nonexistent(&abs(&args.store_root)).context("--store-root 路径无效")?;
    let mut src_dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Some(a) = &args.account_dir {
        src_dirs.push(abs(a));
    }
    for db in [&args.media_db, &args.message_db, &args.hardlink_db]
        .into_iter()
        .flatten()
    {
        let ad = abs(db);
        src_dirs.push(ad.parent().map_or(ad.clone(), Path::to_path_buf));
    }
    for sd in &src_dirs {
        if let Ok(sd_canon) = sd.canonicalize() {
            if store_canon.starts_with(&sd_canon) || sd_canon.starts_with(&store_canon) {
                return Err(cli_err(
                    native_core::ErrorCode::BadRequest,
                    "--store-root 与微信源库/账号目录不能相互包含 (会污染微信数据、可能被微信清理); 放到无关位置",
                ));
            }
        }
    }

    // 账号仓目录名用 sha8 前缀 (K-R4: 不落明文 wxid 到盘)。账本 + media_reference 仍存全 account_id_sha。
    let acct_dir = &account_id_sha[..account_id_sha.len().min(16)];
    let layout = StoreLayout::new(Path::new(&args.store_root), acct_dir);
    std::fs::create_dir_all(layout.account_root()).context("建内容仓账号目录失败")?;
    // R14: 账本版本迁移门禁(open_ledger 抛 SQLITE_MISMATCH)→ SchemaMismatch(退出6, 透传删库重建); 其它(账号/损坏/IO)→ Internal(别一刀切 BadRequest 把损坏误报成参数错)。
    let ledger = open_ledger(&layout.ledger(), &account_id_sha, now).map_err(|e| {
        let schema_drift = e.chain().any(|c| {
            matches!(c.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(f, _)) if f.extended_code == rusqlite::ffi::SQLITE_MISMATCH)
        });
        let code = if schema_drift {
            native_core::ErrorCode::SchemaMismatch
        } else {
            native_core::ErrorCode::Internal
        };
        cli_err(code, format!("打开/建 CAS 账本失败: {e:#}"))
    })?;

    let kinds = if args.kind.is_empty() {
        vec![IngestKind::Voice, IngestKind::Video, IngestKind::Image]
    } else {
        args.kind.clone()
    };

    for kind in kinds {
        match kind {
            IngestKind::Voice => {
                let Some(mp) = &args.media_db else {
                    eprintln!("⏭  voice 跳过: 没给 --media-db");
                    continue;
                };
                let media_dir = Path::new(mp)
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let mut shards = native_query::media_db_files(media_dir);
                if shards.is_empty() {
                    shards = vec![std::path::PathBuf::from(mp)];
                }
                // F3(复审 codex P1-3/P2): 逐 message 分片 open→scan→**drop** 建 svr_id→消息锚映射 —— 免多解密库同时驻留内存;
                // 且在 media 分片循环**外建一次**(锚映射对所有 media 分片不变, 别每片重扫全 message 库)。--message-db 缺 → 空 = 全降级。
                let mut anchor: native_core::mediastore::VoiceAnchorMap = std::collections::HashMap::new();
                if let Some(mdb) = &args.message_db {
                    for mshard in message_shards(mdb)? {
                        let msrc = open_source_db(&mshard, db_key, "message db (语音锚)")?;
                        let mname = mshard.file_name().and_then(|n| n.to_str()).unwrap_or("message.db");
                        native_core::mediastore::scan_voice_anchors_into(msrc.conn(), mname, &mut anchor)?;
                        // msrc 在此 drop —— 下轮开下一分片前释放本分片(解密)库内存。
                    }
                }
                let mut agg = VoiceIngestStats::default();
                for shard in &shards {
                    let done = agg.stored + agg.deduped + agg.partial;
                    let remaining = args.limit.map(|l| l.saturating_sub(done));
                    if remaining == Some(0) {
                        break;
                    }
                    let src = open_source_db(shard, db_key, "media db (VoiceInfo)")?;
                    let sid = format!(
                        "voice:{}",
                        shard.file_name().and_then(|n| n.to_str()).unwrap_or("media")
                    );
                    let s = run_voice_ingest(
                        src.conn(),
                        &anchor,
                        &ledger,
                        &account_id_sha,
                        &run_id,
                        &sid,
                        &layout,
                        remaining,
                        now,
                    )
                    .context("语音入仓失败")?;
                    agg.discovered += s.discovered;
                    agg.stored += s.stored;
                    agg.deduped += s.deduped;
                    agg.partial += s.partial;
                    agg.failed += s.failed;
                }
                eprintln!(
                    "🔊 语音: 发现 {} · 入仓 {} (去重 {}) · 不完整 {} · 失败 {}",
                    agg.discovered, agg.stored, agg.deduped, agg.partial, agg.failed
                );
                total_discovered += agg.discovered as u64;
                total_produced += (agg.stored + agg.deduped + agg.partial) as u64; // 去重也算成功(内容已在仓里)
                total_failed += agg.failed as u64;
            }
            IngestKind::Video => {
                let (Some(mdb), Some(hl), Some(acct)) = (&args.message_db, &args.hardlink_db, &args.account_dir) else {
                    eprintln!("⏭  video 跳过: 需 --message-db + --hardlink-db + --account-dir");
                    continue;
                };
                let hard = open_source_db(Path::new(hl), db_key, "hardlink db")?;
                let mut agg = VideoIngestStats::default();
                for shard in message_shards(mdb)? {
                    let done = agg.stored + agg.deduped;
                    let remaining = args.limit.map(|l| l.saturating_sub(done));
                    if remaining == Some(0) {
                        break;
                    }
                    let src = open_source_db(&shard, db_key, "message db")?;
                    // db_source = 分片文件名(对齐 L1 message.source; kind 前缀由驱动内部给 source_scan)。
                    let db_source = shard.file_name().and_then(|n| n.to_str()).unwrap_or("message.db");
                    let s = run_video_ingest(
                        src.conn(),
                        hard.conn(),
                        Path::new(acct),
                        &ledger,
                        &account_id_sha,
                        &run_id,
                        db_source,
                        &layout,
                        remaining,
                        now,
                    )
                    .context("视频入仓失败")?;
                    agg.discovered += s.discovered;
                    agg.stored += s.stored;
                    agg.deduped += s.deduped;
                    agg.partial += s.partial;
                    agg.failed += s.failed;
                }
                eprintln!(
                    "🎬 视频: 发现 {} · 入仓 {} (去重 {} · 截断 {}) · 无明文/失败 {}",
                    agg.discovered, agg.stored, agg.deduped, agg.partial, agg.failed
                );
                total_discovered += agg.discovered as u64;
                total_produced += (agg.stored + agg.deduped + agg.partial) as u64;
                total_failed += agg.failed as u64;
            }
            IngestKind::Image => {
                let (Some(mdb), Some(acct)) = (&args.message_db, &args.account_dir) else {
                    eprintln!("⏭  image 跳过: 需 --message-db + --account-dir");
                    continue;
                };
                // 复审 P2: --image-key 与 --image-xor 必须**成对**给 —— 只给一个静默降成 None(只收缩略图)会误导用户以为在解完整图。
                let img_key = match (&args.image_key, &args.image_xor) {
                    (Some(k), Some(x)) => Some(parse_explicit_image_key(k, x)?),
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(cli_err(
                            native_core::ErrorCode::BadRequest,
                            "--image-key 与 --image-xor 需成对给 (只给一个不行); 都不给则只收无需 key 的 V0 缩略图",
                        ));
                    }
                    (None, None) => None,
                };
                let mut agg = ImageIngestStats::default();
                for shard in message_shards(mdb)? {
                    let done = agg.stored + agg.deduped;
                    let remaining = args.limit.map(|l| l.saturating_sub(done));
                    if remaining == Some(0) {
                        break;
                    }
                    let src = open_source_db(&shard, db_key, "message db")?;
                    let db_source = shard.file_name().and_then(|n| n.to_str()).unwrap_or("message.db");
                    let s = run_image_ingest(
                        src.conn(),
                        Path::new(acct),
                        img_key.as_ref(),
                        &ledger,
                        &account_id_sha,
                        &run_id,
                        db_source,
                        &layout,
                        remaining,
                        now,
                    )
                    .context("图片入仓失败")?;
                    agg.discovered += s.discovered;
                    agg.stored += s.stored;
                    agg.deduped += s.deduped;
                    agg.failed += s.failed;
                }
                eprintln!(
                    "🖼  图片: 发现 {} · 入仓 {} (去重 {}) · 失败 {}{}",
                    agg.discovered,
                    agg.stored,
                    agg.deduped,
                    agg.failed,
                    if img_key.is_none() {
                        " (无 --image-key, 只收 V0 缩略图)"
                    } else {
                        ""
                    }
                );
                total_discovered += agg.discovered as u64;
                total_produced += (agg.stored + agg.deduped) as u64;
                total_failed += agg.failed as u64;
            }
        }
    }
    eprintln!(
        "{} media-ingest 完: 发现 {total_discovered} · 入仓 {total_produced} · 失败 {total_failed} → 内容仓 {}",
        if total_failed > 0 {
            if total_produced == 0 {
                "🛑"
            } else {
                "⚠️"
            }
        } else {
            "✅"
        },
        layout.account_root().display()
    );
    // 原先这行是无条件 ✅ 且**一个计数都不带** —— 三种媒体全因缺参数被跳过时也照样打勾。
    // 现在汇总三类的发现/入仓/失败, 按同一判据决定图标和退出码。
    export_outcome(
        total_discovered,
        total_produced,
        total_failed,
        0,
        "media-ingest",
        "看上面每类的分项; 若某类显示「跳过」是缺对应参数 (--media-db / --message-db / --hardlink-db / --account-dir)。",
    )
}

/// 把 `out_dir` 里所有 `.wav` 转 MP3 (ffmpeg `libmp3lame -q:a 4`, 同 WDA `_convert_wav_to_mp3`)。
/// 转成功删 `.wav` 只留 mp3; 转失败留 `.wav` (内容不丢)。返回 (转出数, 失败数)。
/// 同 [`transcode_wxgf_dir`] 的唯一临时文件 + rename 模式 (失败绝不碰已有 mp3)。
fn transcode_wav_dir_to_mp3(ffmpeg: &Path, out_dir: &Path) -> (usize, usize) {
    let (mut ok, mut fail) = (0usize, 0usize);
    let Ok(entries) = std::fs::read_dir(out_dir) else {
        return (0, 0);
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.extension().is_some_and(|e| e.eq_ignore_ascii_case("wav")) {
            continue;
        }
        let out_mp3 = p.with_extension("mp3");
        let tmp_out = p.with_extension("wav2mp3.mp3"); // 唯一临时, 成功再 rename
        let mut cmd = std::process::Command::new(ffmpeg);
        cmd.args(["-y", "-loglevel", "error", "-i"])
            .arg(&p)
            .args(["-vn", "-codec:a", "libmp3lame", "-q:a", "4"])
            .arg(&tmp_out);
        // 有界超时 (§8 round2 P3: 病态 wav 不挂死整批; 单文件超时 kill 计 fail 留 wav, 内容不丢, 批量继续)。
        if native_core::media::status_with_timeout(cmd, std::time::Duration::from_secs(60))
            && tmp_out.is_file()
            && std::fs::rename(&tmp_out, &out_mp3).is_ok()
        {
            let _ = std::fs::remove_file(&p); // 转成功 → 删 wav
            ok += 1;
        } else {
            let _ = std::fs::remove_file(&tmp_out); // 清临时半成品, 留 wav
            fail += 1;
        }
    }
    (ok, fail)
}

/// 求 `p` 的绝对规范路径而**不创建它** (out_dir 可能还不存在): canonicalize 最近的已存在祖先 +
/// 拼未存在的尾部。用于污染检查时避免预建目录 (codex 件4 P1: 不在拒绝路径下留空目录)。
fn canonical_nonexistent(p: &Path) -> Result<PathBuf> {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p;
    loop {
        if let Ok(c) = cur.canonicalize() {
            let mut out = c;
            for seg in tail.iter().rev() {
                out.push(seg);
            }
            return Ok(out);
        }
        let name = cur.file_name().context("--out-dir 路径无有效末段")?;
        tail.push(name.to_os_string());
        cur = cur.parent().context("--out-dir 无有效父目录 (盘符不存在?)")?;
    }
}

/// 微信子库句柄 — 已解密明文文件 (`open_readonly`) 或 加密库就地解密 (native, 内存不落盘)。
/// 两分支都给 `&Connection`, 命令体统一 `.conn()` 查询, 不关心来源。
enum SourceDb {
    Plain(rusqlite::Connection),
    Decrypted(DecryptedDb),
}

impl SourceDb {
    fn conn(&self) -> &rusqlite::Connection {
        match self {
            SourceDb::Plain(c) => c,
            SourceDb::Decrypted(d) => d.conn(),
        }
    }
}

/// 打开一个微信子库: 给 `key` = **native 就地解密**加密库 (全程内存, 不落盘); 不给 = `open_readonly` 已解密明文库。
/// `what` 仅用于报错描述 (K-R4: 不回显含 wxid 的原路径; 解密错误已在 native-core 脱敏)。
fn open_source_db(path: &Path, key: Option<&MasterKey>, what: &str) -> Result<SourceDb> {
    // 坏路径先拦 → BAD_REQUEST/2 (契约审: 否则 open 失败经 .with_context 归 INTERNAL/70; 只查存在性,
    // 不碰 key/解密失败, 免误判)。K-R4: 路径含 wxid, 报错只给描述不回显路径。
    if !path.is_file() {
        return Err(cli_err(
            native_core::ErrorCode::BadRequest,
            format!("{what} 路径不存在或不是文件"),
        ));
    }
    match key {
        Some(k) => {
            let db = open_decrypted_db(path, k)
                .with_context(|| format!("解密{what}失败 (key 不对 / 库损坏 / 非加密库; 确认已对该账号跑过 `auth`)"))?;
            Ok(SourceDb::Decrypted(db))
        }
        None => {
            let c = native_core::storage::open_readonly(path).with_context(|| {
                format!("打不开{what} (只读; 须是已解密明文 sqlite; 或加 --cipher native 直读加密库)")
            })?;
            Ok(SourceDb::Plain(c))
        }
    }
}

/// 导出/解密命令的 db 解密 key — **cache-only** (不 hook / 不碰微信, 取 key 是 `auth` 的事) + `--master-key-hex` 兜底。
///
/// 返回 `None` = 没开 `--cipher` (读已解密明文库); `Some` = 拿到 master key; 要求解密但取不到 → `Err` (提示先 auth)。
/// `detected_wxid` = 命令从自身路径 (account_dir / 库路径) 检测的账号, `--wxid` 未给时兜底。
async fn resolve_export_key(opts: &DecryptOpts, detected_wxid: Option<Wxid>) -> Result<Option<MasterKey>> {
    if opts.cipher.is_none() {
        return Ok(None); // 已解密明文库模式 (现状, 不解密)
    }
    // 1. 显式 hex 兜底 (跳过 cache)。
    if let Some(hex) = &opts.master_key_hex {
        let mk = MasterKey::from_hex(hex).map_err(|_| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--master-key-hex 解析失败 (须 64 hex)",
            )
        })?;
        return Ok(Some(mk));
    }
    // 2. cache 查 wxid (K-R2 持久层; 命中不 hook)。--wxid 优先, 否则用命令检测到的账号。
    let wxid = match &opts.wxid {
        Some(w) => w
            .parse::<Wxid>()
            .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--wxid 非法 (须合法微信 wxid)"))?,
        None => detected_wxid.ok_or_else(|| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--cipher 需要账号 wxid 查缓存的 key — 给 --wxid <wxid> (或让命令能从路径检测到账号), 或给 --master-key-hex",
            )
        })?,
    };
    let cache = CacheKeyProvider::new(None);
    // key 未缓存 → ACCOUNT_NOT_FOUND/4 (对齐 sessions/messages 的 cache_key; 契约审: 别归 INTERNAL/70,
    // 脚本要能把'先跑 auth 缓存'与'工具崩了'分开)。
    let mk = cache.resolve(&wxid).await.map_err(|_| {
        cli_err(
            native_core::ErrorCode::AccountNotFound,
            "cache 里没有该账号的 key — 先跑 `msgvestige auth --wxid <你的 wxid>` 取一次 (会缓存, 之后导出直接用, 不再碰微信)",
        )
    })?;
    Ok(Some(mk))
}

// wxid_from_dir_name 已上移至 native-query::hot (resolve_message_dir 依赖它); 经上方
// `use native_query::wxid_from_dir_name` 回引 (detect_wxid_from_path / detect_account_wxids 仍用)。

/// 从路径或其祖先目录名找账号 wxid —— 取**最深**匹配的 `wxid_` 祖先段 (假设账号目录是库最近的 `wxid_` 祖先;
/// 真实微信目录如此)。给 `--cipher` 缺 `--wxid` 时兜底。**失败方向安全** (双审 P1): 取错/取不到 →
/// cache 查不到 key → 报错要 --wxid, 绝不会用错 key 解错库。
fn detect_wxid_from_path(p: &Path) -> Option<Wxid> {
    p.ancestors()
        .filter_map(|anc| anc.file_name()?.to_str())
        .find_map(wxid_from_dir_name)
}

/// `reconcile` — native 解密 enc-db, 打开 plain-db (竞品明文), 逐表比 row count + 内容 digest (ADR-428 M3-d 收尾)。
/// 封存分片 (message_0.db 两份大小相同) 期望逐表全等 = native 解密 == 竞品解密 (逐字节)。
fn cmd_reconcile(args: &ReconcileArgs, db_key: Option<&MasterKey>) -> Result<()> {
    use native_core::reconcile::reconcile_tables;
    // 坏路径先拦 → BAD_REQUEST/2 (契约审 #6; 只查存在性, 不碰 open_source_db 的解密失败, 免误判 key 错为参数错)。
    // K-R4: 路径含 wxid, 报错只给参数名不回显路径。
    for (p, label) in [(&args.enc_db, "--enc-db"), (&args.plain_db, "--plain-db")] {
        if !Path::new(p).is_file() {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                format!("{label} 路径不存在或不是文件"),
            ));
        }
    }
    // enc-db: --cipher native 时 native 解密; plain-db: 竞品已解密的明文, 直接只读。
    let enc = open_source_db(Path::new(&args.enc_db), db_key, "加密库 (native 解密)")?;
    let plain = open_source_db(Path::new(&args.plain_db), None, "明文库 (竞品解密)")?;
    let only: Option<Vec<String>> = args.only.as_ref().map(|s| {
        s.split(',')
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect()
    });
    let report = reconcile_tables(enc.conn(), plain.conn(), only.as_deref())
        .context("对账失败 (db 级错误; 表结构不符 / WITHOUT ROWID 表需 --only 排除?)")?;
    anyhow::ensure!(
        !report.compares.is_empty() || !report.enc_only.is_empty() || !report.plain_only.is_empty(),
        "两库没有任何用户表 (schema 不同 / --only 没命中?)"
    );
    let mut content_ok = true;
    eprintln!("{:>32} | native行数 | 明文行数 | 一致", "表");
    for c in &report.compares {
        let ok = c.matches();
        content_ok = content_ok && ok;
        eprintln!(
            "{:>32} | {:>9} | {:>8} | {}",
            c.table,
            c.enc_rows,
            c.plain_rows,
            if ok { "✅" } else { "❌ 不一致" }
        );
    }
    // 双审 P1-2: 表集合对称差不能静默 — 一边独有表也算不一致 (计入 all_match)。
    let show = |v: &[String]| -> String {
        let head: Vec<String> = v.iter().take(6).cloned().collect();
        head.join(", ") + if v.len() > 6 { " …" } else { "" }
    };
    if !report.enc_only.is_empty() {
        eprintln!(
            "⚠️ native 独有 {} 张表 (明文库无; 新旧快照对比多为新增会话): {}",
            report.enc_only.len(),
            show(&report.enc_only)
        );
    }
    if !report.plain_only.is_empty() {
        eprintln!(
            "⚠️ 明文库独有 {} 张表 (native 库无): {}",
            report.plain_only.len(),
            show(&report.plain_only)
        );
    }
    // 双审 P1-3: --only 指定但没对账到的表名 (拼错 / 不在交集) 显式报, 不静默吞。
    if let Some(sel) = &only {
        let hit: std::collections::HashSet<&String> = report.compares.iter().map(|c| &c.table).collect();
        let miss: Vec<&String> = sel.iter().filter(|s| !hit.contains(s)).collect();
        if !miss.is_empty() {
            eprintln!("⚠️ --only 指定但未对账到 (拼错 / 不在两库交集): {miss:?}");
        }
    }
    let n_ok = report.compares.iter().filter(|c| c.matches()).count();
    let set_diff = if report.enc_only.is_empty() && report.plain_only.is_empty() {
        String::new()
    } else {
        format!(
            " · 表集合有差异 (native 独有 {} / 明文独有 {})",
            report.enc_only.len(),
            report.plain_only.len()
        )
    };
    eprintln!(
        "\n对账: {}/{} 张比对表逐字节一致{} {}",
        n_ok,
        report.compares.len(),
        set_diff,
        if report.all_match() {
            "→ native 解密 == 竞品解密 ✅"
        } else {
            "→ 有差异 (见上, 判断是否时间差)"
        }
    );
    eprintln!(
        "注: 仅对封存分片 (如 message_0.db 写满不再变) 可靠; 活跃库因 native 只读快照不含活跃 WAL 最新行, 可能假阳。"
    );
    Ok(())
}

/// `export` — 打开 L1 db, 查业务表, 导 JSONL 到文件/stdout。
fn cmd_export(args: &ExportArgs) -> Result<()> {
    use std::io::Write as _;

    use native_core::export::{export, ExportFormat, ExportTable};
    let table = ExportTable::parse(&args.table)
        .with_context(|| {
            format!(
                "--table 不认识 {:?} (可选: contacts/groups/sessions/favorites/messages)",
                args.table
            )
        })
        .map_err(|e| cli_err(native_core::ErrorCode::BadRequest, e.to_string()))?;
    let format = ExportFormat::parse(&args.format)
        .with_context(|| format!("--format 不认识 {:?} (可选: jsonl/csv/html)", args.format))
        .map_err(|e| cli_err(native_core::ErrorCode::BadRequest, e.to_string()))?;
    let chat = args.chat.as_deref();
    // 只读打开 (export 纯读; 文件不存在报错而非静默建空库)。
    let conn = open_l1_resolved(&args.target)?;
    let n = if let Some(path) = &args.out {
        // codex P1: --out == --l1-db 会 File::create 截断 L1 库 (数据丢失) → 拒绝同路径。
        // 互斥选项冲突 → BAD_REQUEST(退出2), 非 INTERNAL/70 (信封审)。
        if std::path::Path::new(path) == std::path::Path::new(args.target.require_l1_db()?) {
            return Err(cli_err(
                native_core::ErrorCode::BadRequest,
                "--out 不能等于 --l1-db (会截断源库); 换个输出路径",
            ));
        }
        let mut f =
            std::io::BufWriter::new(std::fs::File::create(path).with_context(|| format!("建输出文件 {path} 失败"))?);
        let n = export(&conn, table, format, chat, &mut f)?;
        f.flush().with_context(|| format!("写/刷 {path} 失败 (磁盘满?)"))?;
        eprintln!("✅ 导出 {n} 行 {:?} ({:?}) → {path}", args.table, format);
        n
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let n = export(&conn, table, format, chat, &mut lock)?;
        eprintln!("✅ 导出 {n} 行 {:?} ({:?}) → stdout", args.table, format);
        n
    };
    let _ = n;
    Ok(())
}

/// `auth --scan` — 非扰动内存扫: fast 路从运行中的微信进程扫成品 enc_key → 存 cache。
/// 不杀微信 / 不重启 / 不扫码。前提: 目标账号正登录运行 (其库已加载 → WCDB 内存里缓存了成品 enc_key)。
/// 用 native-keyscan 的公开 `scan_key`(Fast): 内部读账号入口库首页当锚点 + 开进程 + verify 压候选到真 key。
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
async fn cmd_auth_scan(args: &AuthArgs, wxid: &Wxid) -> Result<bool> {
    use native_keyscan::{scan_key, KeyMode, ScanOptions};
    let data_dir = match &args.wechat_data_dir {
        Some(d) => PathBuf::from(d),
        None => default_wechat_data_dir()?,
    };
    let paths = locate_account_dbs(&data_dir, wxid).map_err(|e| {
        cli_err(
            native_core::ErrorCode::BadRequest,
            format!("定位账号 db 失败 (用 --wechat-data-dir 指向 xwechat_files): {e}"),
        )
    })?;
    eprintln!("非扰动内存扫 full 路 (Weixin.dll 提 internal_db_key → 扫裸 key 候选 XOR 反混淆 → PBKDF2-256000; 不杀 / 不重启微信)…");
    let opts = ScanOptions {
        mode: KeyMode::Full, // full: raw_key XOR internal_db_key(从 dll) → 256000 派生; 新版微信(4.1.x)把内存 key XOR 混淆了, fast(enc_key 字符串)扫不到, 必走 full
        anchor_db: paths.account_entry_db.clone(),
        pid: args.wechat_pid, // None = 自动枚举 Weixin.exe 取主进程 (内存最大)
        dll_path: None,       // None = 从进程已加载模块自动定位 Weixin.dll
        rounds: 256_000,      // v4 PBKDF2 轮数
    };
    // 超时早停: 账号已加载时 key 秒级命中; 没加载则逐候选 ×PBKDF2-256000 穷举很慢 (>2min)。
    // 起线程跑 scan_key, 90s 没结果就判"账号没加载"快速失败 (CLI 进程随即退出即回收该线程)。
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(scan_key(&opts));
    });
    let outcome = match rx.recv_timeout(std::time::Duration::from_secs(90)) {
        Ok(r) => r.map_err(|e| {
            cli_err(
                native_core::ErrorCode::Internal,
                format!("内存扫 key 失败 (目标账号正登录运行且解锁了? 多账号确认 --wxid 指当前登录那个): {e}"),
            )
        })?,
        Err(_) => {
            return Err(cli_err(
                native_core::ErrorCode::Internal,
                "内存扫超时 (>90s) — 目标账号很可能没登录 / 没加载进内存 (WCDB 未缓存其 key); \
                 确认 --wxid 是当前活跃账号, 并在微信里点开过几个聊天让它加载数据"
                    .to_string(),
            ));
        }
    };
    // KeyMaterial.as_bytes() = SQLCipher 直接用的 32B 成品 key; 存 cache (同 ciphertalk 格式, provenance=keyscan)。
    let key = MasterKey::from_bytes(*outcome.material().as_bytes());
    let fp = key_fingerprint(&key);
    CacheKeyProvider::new(None)
        .store(wxid, &key, "keyscan")
        .await
        .map_err(|e| cli_err(native_core::ErrorCode::Internal, format!("写 key cache 失败: {e}")))?;
    eprintln!("✅ 已扫到并缓存 {wxid} 的 key (非扰动 full 路, 全程未动微信; sha8={fp})");
    Ok(true)
}

/// 非 Windows-x64: 内存扫不可用 (扫进程内存是 windows-x64 gated)。
// `async` 是为了跟 Windows 版**签名一致**(调用点一视同仁 await), 桩里没有 await 是必然的。
#[allow(clippy::unused_async)]
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
async fn cmd_auth_scan(_args: &AuthArgs, _wxid: &Wxid) -> Result<bool> {
    Err(cli_err(
        native_core::ErrorCode::BadRequest,
        "auth --scan 仅 Windows x64 支持 — 用默认 auth (hook) 或 --master-key-hex".to_string(),
    ))
}

/// `auth` — `resolve(wxid)` hook 取 key (cache 命中则跳过 hook), chain 自动缓存。
/// 接 `&dyn KeyProvider` (注入点, §4 D2); 返 true = 取到。
async fn cmd_auth(provider: &dyn KeyProvider, wxid: &Wxid) -> Result<bool> {
    eprintln!("正在为 {wxid} 取 key (cache 命中则跳过 hook)…");
    // P1 (Claude r1): ciphertalk hook 取【当前运行微信】的 key, 不校验是否 = wxid;
    //   多账号下若扫/登录错号, key 会缓存到错 wxid (永久 cache 固化)。完整修待迁移件
    //   让 ciphertalk 回报实际登录 wxid + 一致性校验; 当前 stderr 警示。
    eprintln!("⚠️  hook 取的是当前运行/扫码登录微信的 key — 请确保它就是 {wxid} (多账号勿扫错号)。");
    match provider.resolve(wxid).await {
        Ok(_key) => {
            // _key 立即 Drop (ZeroizeOnDrop); K-R4 绝不打印 master key 原值。
            println!("✅ {wxid} 的 master key 已取到并缓存 (下次直接走 cache 不再 hook)。");
            Ok(true)
        }
        Err(e) => {
            eprintln!("⚠️  取 key 失败: {e}");
            Ok(false)
        }
    }
}

/// wxid 来源优先级: `--wxid` > 扫微信目录检测 (单账号自动取, 多账号要 `--wxid`)。
fn resolve_target_wxid(args: &AuthArgs) -> Result<Wxid> {
    if let Some(w) = &args.wxid {
        return w
            .parse()
            .map_err(|_| cli_err(native_core::ErrorCode::BadRequest, "--wxid 非法 (须合法微信 wxid)"));
    }
    let data_dir = resolve_wechat_data_dir(args)?;
    let wxids = detect_account_wxids(&data_dir);
    // 账号解析错 → ACCOUNT_* (退出4), 非 INTERNAL/70 (信封审 + 内核 §11: 多账号列候选让调用方选)。
    match wxids.len() {
        0 => Err(cli_err(
            native_core::ErrorCode::AccountNotFound,
            format!(
                "在 {} 没检测到微信账号目录 (wxid_*) — 用 --wxid 指定, 或 --wechat-data-dir 指向 xwechat_files",
                data_dir.display()
            ),
        )),
        1 => Ok(wxids.into_iter().next().expect("len==1")),
        _ => Err(cli_err(
            native_core::ErrorCode::AccountAmbiguous,
            format!(
                "检测到 {} 个账号 {:?} — 用 --wxid 指定一个",
                wxids.len(),
                wxids.iter().map(ToString::to_string).collect::<Vec<_>>()
            ),
        )),
    }
}

/// 微信数据目录: `--wechat-data-dir` > 默认探测 (`%USERPROFILE%\Documents\xwechat_files`)。
fn resolve_wechat_data_dir(args: &AuthArgs) -> Result<PathBuf> {
    if let Some(d) = &args.wechat_data_dir {
        return Ok(PathBuf::from(d));
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(profile).join("Documents").join("xwechat_files");
        if p.is_dir() {
            return Ok(p);
        }
    }
    Err(cli_err(
        native_core::ErrorCode::BadRequest,
        "没找到微信数据目录 — 用 --wechat-data-dir 指向 xwechat_files (如 F:\\xwechat_files)",
    ))
}

/// 扫 `data_dir` 下 `wxid_<id>_<设备后缀>` 目录, 提取账号 wxid (去最后一段 `_后缀`)。
/// 实测目录名如 `wxid_abcd1234efgh567_abfe` → wxid `wxid_abcd1234efgh567`。
fn detect_account_wxids(data_dir: &Path) -> Vec<Wxid> {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut out: Vec<Wxid> = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // 目录名 → 账号 wxid (切法集中在 wxid_from_dir_name; 双审 P1: 与 detect_wxid_from_path 共享,
        // 非 wxid_ 目录返回 None 跳过; 裸 wxid_<id> 不误切成 "wxid", 多段后缀假设见 helper 注释)。
        if let Some(w) = wxid_from_dir_name(name) {
            if !out.contains(&w) {
                out.push(w);
            }
        }
    }
    out
}

/// 组装 `[cache, ciphertalk(win), cli]` 链 (默认顺序, K-R2 cache-first + 自动 write-back)。
fn build_key_chain(args: &AuthArgs, wxid: &Wxid) -> Result<ChainedKeyProvider> {
    let mut sources: Vec<Box<dyn KeyProvider>> = Vec::new();
    // 1. cache — 持久层 + chain 自动 write-back 目标。
    sources.push(Box::new(CacheKeyProvider::new(None)));
    // 2. ciphertalk — windows-only, hook 运行中微信取当前账号 master key。
    #[cfg(target_os = "windows")]
    {
        use std::sync::Arc;

        use native_core::key_provider::{CipherTalkProvider, StdoutNotifier};
        let ct = CipherTalkProvider::new(None)
            .with_notifier(Arc::new(StdoutNotifier))
            .with_restart_wechat(!args.no_restart)
            .with_wechat_pid_override(args.wechat_pid)
            .with_confirm_callback(confirm_kill_wechat);
        sources.push(Box::new(ct));
    }
    // 3. cli 兜底 — --master-key-hex 直供 (配目标 wxid)。
    let inline = args
        .master_key_hex
        .as_deref()
        .map(MasterKey::from_hex)
        .transpose()
        .map_err(|_| {
            cli_err(
                native_core::ErrorCode::BadRequest,
                "--master-key-hex 解析失败 (须 64 hex)",
            )
        })?;
    let cli_wxid = if inline.is_some() { Some(wxid.clone()) } else { None };
    sources.push(Box::new(CliKeyProvider::new(inline, cli_wxid)?));
    Ok(ChainedKeyProvider::new(sources))
}

/// 杀微信前 consent (K-R1: 不静默 kill 用户微信)。返 true = 用户同意。
#[cfg(target_os = "windows")]
fn confirm_kill_wechat(pid: Option<u32>) -> bool {
    use std::io::Write;
    let suffix = pid.map(|p| format!(" (pid={p})")).unwrap_or_default();
    eprint!("⚠️  将杀掉并重启微信{suffix} 以 hook 取 key (需重新扫码登录)。继续? [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    // §6③ specials 移核: exec/inspect/resolve 的查询助手现在 native-query (皮层非 test 调用点用 `native_query::`
    // 前缀; 这些直测就近引入省前缀, 断言不变)。InspectType 经 crate 根 `use native_query::InspectType` 由 super::* 带入。
    use native_query::{
        fetch_row, forward_sources, forward_type_label, is_readonly_sql, query_forward_items, query_forward_list,
        run_exec_query, sql_value_display,
    };

    use super::*;

    /// R20 声明式: `tier_declarative_guidance` 四档指引 —— 各档提对手动命令; 冷库(静态)不提 watch; off 说无需; 无自动触发。
    #[test]
    fn r20_tier_guidance_declarative_per_tier() {
        let thin = tier_declarative_guidance("thin");
        assert!(
            thin.contains("build --tier thin") && thin.contains("watch --live-index thin"),
            "快搜指引应提 build + watch thin"
        );
        let cold = tier_declarative_guidance("cold");
        assert!(cold.contains("ingest --all"), "冷库指引应提 ingest --all");
        assert!(!cold.contains("watch"), "冷库=静态不 watch → 指引不提 watch");
        let full = tier_declarative_guidance("full");
        assert!(
            full.contains("ingest --all") && full.contains("watch --live-index full"),
            "全速指引应提 ingest + watch full"
        );
        // codex 复审 P2: watch/ingest 需 --wxid, 指引命令必须带 (否则用户照抄被 clap 拒)。
        assert!(thin.contains("--wxid"), "快搜 watch 指引含 --wxid (可直接跑)");
        assert!(cold.contains("--wxid"), "冷库 ingest 指引含 --wxid");
        assert!(full.contains("--wxid"), "全速 ingest+watch 指引含 --wxid");
        assert!(tier_declarative_guidance("off").contains("无需"), "裸跑说无需额外命令");
        assert!(tier_declarative_guidance("garbage").is_empty(), "未知档兜底空串");
    }

    /// 跟 [`subcommand_help_has_no_internal_narrative`] 同一条规矩, 但盯的是**运行时打给用户的话**。
    ///
    /// 为什么要单开一条: 那条只扫 `--help`(clap 渲染出来的), 扫不到 `eprintln!`。
    /// 结果就是我在 `new` 的几行告警里留了裸粗体记号, 一路提交、一路自测全绿,
    /// 最后是独立复审用眼睛看出来的(第十九轮 P3)。**能机器扫的就别靠眼睛。**
    ///
    /// 【v1 挡不住什么 —— 独立复审第二十一轮当场机器扫出来的】
    /// - **只扫 `main.rs` 一个文件**: 而 `refresh.rs` 拼好的串会被 `eprintln!("注意: {why}")` 原样打出来。
    ///   讽刺的是那一轮我正好在改那个函数, 隔壁一行的记号原封不动。
    /// - **只认 `eprintln!`/`println!`**: `.context(…)` / `cli_err(…)` / `anyhow!` / `bail!` 出错时
    ///   照样打到用户脸上; `eprint!` 的 y/N 提示也是。
    /// - **往上数 8 行的窗口**: main.rs 里有 14 个 print 的实参跨度超过 8 行, 最长的跨 23 行。
    /// - **判据比旁边那条笨**: 旁边用 `markdown_stars()`(要求成对且中间有字), 迭代三版才把
    ///   打码示例 `138****8000` 和 glob 路径 `Sns/Img/**` 摘出来; v1 只 `contains("**")`, 会误报。
    ///
    /// v2 全改了: 扫 3 个 crate 的 src、按括号配平取完整实参、共用 `markdown_stars()`。
    ///
    /// 【它仍然挡不住什么 —— 别高估】
    /// 运行时才拼出来的记号(`format!("{a}{b}")` 里 a、b 各带一半)、宏名被 `use` 改过的、
    /// 以及我没列进 `EMITTERS` 的发射点。它是防退化的网, 不是证明。
    ///
    /// **最容易漏的一类**: 在别处 `format!` 好一段话存起来, 到发射点只剩 `eprintln!("{why}")` ——
    /// 字面量不在发射点那一行。v2 写这条局限的时候我以为"只能靠自觉", codex 第二十二轮当场举出
    /// **两个当下就在违反它的例子** —— 也就是说这条局限不是理论上的, 是正在漏。
    ///
    /// 所以 v3 把 `format!(` 也收进来了(一跑逮出 5 处, 全是真给用户看的话: doctor 的诊断、
    /// schema 不匹配的提示、导出失败、库被占用)。代价是会扫到一些只在内部流转的 `format!`,
    /// 但**裸粗体记号本来就不该出现在任何字符串里**, 所以这个"误报"其实没有成本。
    ///
    /// 仍然漏的: 记号被拆在两段里拼(`format!("{a}{b}")`)、`tracing::warn!` 那一路(它进日志文件
    /// 不进终端, 但 `logs bundle` 会打包给人看)。它是防退化的网, 不是证明。
    /// **丢行告警的内容**(第二十五轮变异全扫: 皮层这一层原先零守卫)。
    ///
    /// 这套告警是"丢可以、静默不行"那条契约的唯一落点, 而独立复审量出来: 皮层六个变异
    /// (连"把告警整块删掉"在内)一条守卫都不红。这条盖住其中两个 ——
    /// 分片名少了 `message/` 前缀(照抄会开库失败、还报"key 不对"), 和行号缺席不说明白。
    ///
    /// ⚠️ **盖不住的**: "整块告警删掉"和"水位永不落盘"这两个变异要跑进程才逮得到,
    /// 而加密源库夹具在 native-query 的测试里、跨 crate 用不了。这两格仍然空着, 已记在收敛记录里。
    #[test]
    fn lost_table_warning_is_actionable() {
        let one = super::format_lost_tables(&[("biz_message_0.db\u{1f}gh_abc".into(), vec![7, 19])]);
        assert!(
            one.contains("message/biz_message_0.db"),
            "分片名必须带 message/ 前缀, 否则 exec --source-db 照抄跑不通: {one}"
        );
        assert!(
            one.contains("local_id 7,19"),
            "行号得打出来, 用户拿它 WHERE local_id IN(...) 一把命中: {one}"
        );

        let legacy = super::format_lost_tables(&[("biz_message_0.db\u{1f}gh_abc".into(), vec![])]);
        assert!(
            legacy.contains("行号不详") && legacy.contains("--reset"),
            "升级前标的没有行号, 得说明白为什么 + 怎么重新定位, 别让用户以为程序漏给了: {legacy}"
        );

        let two = super::format_lost_tables(&[("a.db\u{1f}c1".into(), vec![1]), ("b.db\u{1f}c2".into(), vec![2])]);
        assert!(two.contains("c1") && two.contains("c2"), "多张表都要列出来: {two}");
    }

    #[test]
    fn runtime_messages_have_no_bare_markdown() {
        /// 会把字面量打到用户眼前的发射点。新增一类就往这儿加一行。
        const EMITTERS: &[&str] = &[
            "eprintln!(",
            "println!(",
            "eprint!(",
            "print!(",
            "writeln!(",
            "context(",
            "with_context(",
            "cli_err(",
            "anyhow!(",
            "bail!(",
            "ensure!(",
            "format!(",
        ];
        fn markdown_stars(s: &str) -> bool {
            let parts: Vec<&str> = s.split("**").collect();
            if parts.len() < 3 {
                return false;
            }
            parts
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == 1 && *i < parts.len() - 1)
                .any(|(_, seg)| !seg.trim().is_empty())
        }
        /// 配平时要跨行记住的状态。
        ///
        /// v3 只让**块注释**跨行存活, 字符串没有 —— 而这个文件里到处是跨行字符串(我自己写的
        /// 那几段告警就是)。后果: 续行被当成代码, 里头一个落单的 `)` 就把实参提前收掉,
        /// 再往后的裸粗体记号**正好漏过** —— 这恰恰是这道关卡存在的理由(codex 第二十三轮 P2)。
        /// 上一行没收尾的那个字符串是什么样的。
        #[derive(Clone, Copy)]
        enum StrKind {
            /// 普通串 `"..."`, 靠行尾 `\` 续行。
            Normal,
            /// 原始串 `r"..."` / `r#"..."#`, 记住有几个 `#` 才知道怎么收尾。
            Raw(usize),
        }
        #[derive(Default)]
        struct ScanState {
            in_block_comment: bool,
            in_string: Option<StrKind>,
        }
        /// 数这一行的括号净增量, **跳过字符串/字符字面量/注释里的括号**, 并把跨行状态留在 `st` 里。
        ///
        /// 两个方向都被真跑逮过(独立复审第二十二轮):
        /// - 吃太少 → 漏报: 提示里写个 `1)` 编号, 那个落单右括号让配平提前归 0;
        /// - 吃太多 → 报到无辜的行上: 落单 `(` 让配平再也回不到 0, 一路吃到文件末尾。
        fn depth_delta(line: &str, st: &mut ScanState) -> i32 {
            let chars: Vec<char> = line.chars().collect();
            let (mut at, mut depth) = (0usize, 0i32);
            // 上一行没收尾的字符串: 先把它吃完。
            if let Some(kind) = st.in_string {
                match kind {
                    StrKind::Raw(h) => {
                        let close: String = std::iter::once('"').chain(std::iter::repeat_n('#', h)).collect();
                        let rest: String = chars.iter().collect();
                        match rest.find(&close) {
                            Some(found) => {
                                at = rest[..found].chars().count() + close.chars().count();
                                st.in_string = None;
                            }
                            None => return 0,
                        }
                    }
                    StrKind::Normal => {
                        // 普通串靠行尾 `\` 续行; 找到没被转义的 `"` 就收尾。
                        while at < chars.len() {
                            match chars[at] {
                                '\\' => at += 2,
                                '"' => {
                                    at += 1;
                                    st.in_string = None;
                                    break;
                                }
                                _ => at += 1,
                            }
                        }
                        if st.in_string.is_some() {
                            return 0;
                        }
                    }
                }
            }
            while at < chars.len() {
                if st.in_block_comment {
                    if chars[at] == '*' && chars.get(at + 1) == Some(&'/') {
                        st.in_block_comment = false;
                        at += 2;
                    } else {
                        at += 1;
                    }
                    continue;
                }
                match chars[at] {
                    '/' if chars.get(at + 1) == Some(&'/') => return depth, // 行尾注释: 后面全不算
                    '/' if chars.get(at + 1) == Some(&'*') => {
                        st.in_block_comment = true;
                        at += 2;
                    }
                    // 原始字符串 r"..." / r#"..."# —— 里面没有转义
                    'r' if matches!(chars.get(at + 1), Some('"' | '#')) => {
                        let mut h = 0usize;
                        let mut j = at + 1;
                        while chars.get(j) == Some(&'#') {
                            h += 1;
                            j += 1;
                        }
                        if chars.get(j) != Some(&'"') {
                            at += 1;
                            continue;
                        }
                        j += 1;
                        let close: String = std::iter::once('"').chain(std::iter::repeat_n('#', h)).collect();
                        let rest: String = chars[j..].iter().collect();
                        match rest.find(&close) {
                            Some(found) => at = j + rest[..found].chars().count() + close.chars().count(),
                            None => {
                                st.in_string = Some(StrKind::Raw(h)); // 跨行了, 留给下一行
                                return depth;
                            }
                        }
                    }
                    '"' => {
                        at += 1;
                        let mut closed = false;
                        while at < chars.len() {
                            match chars[at] {
                                '\\' if at + 1 >= chars.len() => {
                                    // 行尾的 `\` = 续行, 这个串还没完
                                    at += 1;
                                }
                                '\\' => at += 2,
                                '"' => {
                                    at += 1;
                                    closed = true;
                                    break;
                                }
                                _ => at += 1,
                            }
                        }
                        if !closed {
                            st.in_string = Some(StrKind::Normal); // 跨行了, 留给下一行
                            return depth;
                        }
                    }
                    // 字符字面量 '(' —— 但别把生命周期 'a 当字符
                    '\'' if chars.get(at + 1) == Some(&'\\') || chars.get(at + 2) == Some(&'\'') => {
                        at += 1;
                        while at < chars.len() {
                            match chars[at] {
                                '\\' => at += 2,
                                '\'' => {
                                    at += 1;
                                    break;
                                }
                                _ => at += 1,
                            }
                        }
                    }
                    '(' => {
                        depth += 1;
                        at += 1;
                    }
                    ')' => {
                        depth -= 1;
                        at += 1;
                    }
                    _ => at += 1,
                }
            }
            depth
        }
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mut files = vec![];
        // ⚠️ **别只扫我改过的那几个 crate**(独立复审第二十二轮 P3): `msgvestige-adapter` 有 34 处
        // 发射点、`native-http` 有 9 处, 一样打给用户。今天它们是干净的, 但没扫 = 不设防。
        for c in [
            "msgvestige",
            "native-query",
            "native-core",
            "msgvestige-adapter",
            "native-http",
        ] {
            walk(&root.join(c).join("src"), &mut files);
        }
        assert!(files.len() > 10, "没扫到文件, 路径推错了: {root:?}");

        let mut bad: Vec<String> = vec![];
        for f in &files {
            let Ok(src) = std::fs::read_to_string(f) else { continue };
            let lines: Vec<&str> = src.lines().collect();
            let mut i = 0;
            while i < lines.len() {
                let t = lines[i].trim_start();
                // ⚠️ 得看**词边界**, 不能光 `contains`:
                //   · 前面紧挨着引号 = 把宏名当字符串写(下面 `EMITTERS` 自己那张表就是), 不算;
                //   · 前面紧挨着字母/下划线 = 撞上了更长的名字 —— `eprintln!(` 里就**包含**
                //     `println!(`, `with_context(` 里包含 `context(`。第一版只查引号,
                //     于是 `"eprintln!("` 那一行经由 `println!(` 又把自己扫了出来。
                let is_emit = EMITTERS.iter().any(|m| {
                    lines[i].match_indices(m).any(|(at, _)| {
                        at == 0
                            || !lines[i][..at]
                                .chars()
                                .next_back()
                                .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '"')
                    })
                });
                if t.starts_with("//") || !is_emit {
                    i += 1;
                    continue;
                }
                // 按括号配平吃完整个实参 —— 不再用"往上数 N 行"的窗口。
                let (mut depth, mut arg, start) = (0i32, String::new(), i);
                let mut st = ScanState::default();
                while i < lines.len() {
                    let line = lines[i];
                    if !line.trim_start().starts_with("//") {
                        arg.push_str(line);
                        depth += depth_delta(line, &mut st);
                    }
                    i += 1;
                    if depth <= 0 {
                        break;
                    }
                }
                if markdown_stars(&arg) {
                    let rel = f.strip_prefix(root).unwrap_or(f);
                    bad.push(format!(
                        "  {}:{} {}",
                        rel.display(),
                        start + 1,
                        lines[start].trim().chars().take(60).collect::<String>()
                    ));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "以下运行时消息里有裸的 markdown 粗体记号 (终端上原样打出来, 用户看到的是两个星号):\n{}\n\
             —— 想强调就换措辞, 别用记号。",
            bad.join("\n")
        );
    }

    /// **R16-1 (codex 审 P3)**: **每个子命令的 `--help` 全文**都不许出现内部叙事 —— 机器扫, 不靠我记得。
    ///
    /// **为什么非要机器扫**: 这个毛病我连犯三轮 ——
    /// 轮1 泄了 mode/wxid/wechat-data-dir; 轮2"修好"了那三个, 但同结构的 l1-db/account 照泄, 且我在
    /// 同一 commit 里新加的 `ContactsArgs.offset` 又原样犯一遍; 轮3 我给它们加 `help=` 并在 commit 里
    /// 宣布修好 —— **而我修完压根没再跑一次 `--help`**。codex 逮到: clap 把**多段** `///` 当 `long_help`,
    /// `help=` 只覆盖**短** help, 所以 `--help` 照泄。最讽刺的是我为防泄漏而写的那段警告本身也泄了。
    ///
    /// 三次都栽在同一处: 判据靠脑子记 + 修完不验。→ 换成本测试: 它一次扫**全部子命令 × 全部参数**的
    /// long help, 新加字段自动纳入, 想泄都泄不出去。
    ///
    /// 允许的写法: 内部叙事一律 `//` 普通注释 (代码里照样读得到, 只是不进 rustdoc/help);
    /// `///` 只写给用户看的话。
    #[test]
    fn subcommand_help_has_no_internal_narrative() {
        use clap::CommandFactory;
        // 【这个测试挡得住什么、挡不住什么 —— 别高估它】
        //
        // v1 扫词表 → codex 逮到: "名字叫无内部叙事, 实现只查我硬编码的几个词" —— media-ingest 的
        //   "R10 §11-②"、serve 的 "R9/§7"、export-sns-media 的 "ADR-467" 全溜过, 测试照绿。
        // v2 改扫形状 → 独立审逮到: **毛病没变, 只是从"词表只挡得住我想到的词"变成"形状只挡得住我
        //   想到的形状"** —— "件2/件5"(LiveIndexTier 的 variant doc, 泄进 3 个命令)、
        //   "接口设计-③http-api规格.md"、"② CDN 下载" 照样溜, 12 处。最扎眼的对照: `serve --host` 里的
        //   "③文档 §7" 被逮到(撞 §\d), **同一条命令描述**里的 "接口设计-③http-api规格.md" 安然无恙
        //   (不撞任何我想到的形状)。
        // v3(本版) 把这三类形状补上。
        //
        // **它仍然不完备, 别拿它的绿当护身符**: 它挡的是"已知会泄的几类形状", 不是"内部叙事"这个概念本身。
        // 新的编号体系 / 新的内部文件名 / 新行话照样溜。**判据是"用户看不看得懂这句话", 机器判不了。**
        // → 加 CLI 字段或命令时, 除了跑本测试, **必须自己读一遍 `--help` 的渲染结果**。
        //   (独立审就是这么逮到那 12 处的: 把 59 个子命令的 --help 全渲染出来读了一遍。)
        let internal_shape = regex::Regex::new(
            r"(?x)
              §\d                     # 章节号 §14 / §11-②
            | \bR\d+\b                # 里程碑号 R9 / R10 / R16 (\b 挡住 Range/RGB24)
            | \bADR-\d+               # 决策号 ADR-467
            | \bP[1-3]-\d             # 审查编号 P2-1
            | \bK-[A-Z]?\d            # 内部约束号 K-402 / K-R4
            | 件\d                     # v3: 内部分件号 件2 / 件5
            | [①-⑳]                    # v3: 带圈数字 = 内部编号习惯
            | 接口设计-                 # v3: 内部文档名 (用户手上没有这些 .md)
            ",
        )
        .unwrap();
        // 词表补形状抓不到的: 内部结构体名 / 只有开发者懂的行话。
        const LEAKS: &[&str] = &[
            "对抗审",
            "golden_json",
            "SessionsArgs",
            "ContactsArgs",
            "FavoritesArgs",
            "QueryTarget",
            "实测逮到",
            "死胡同",
            "复审",
        ];
        // markdown 加粗 `**文字**`: 终端不渲染 → 用户看到的就是字面星号。
        //
        // 判据必须是"成对 + 中间包着文字"。因为 doc 里有两种**正当**星号, 是给用户看的准确写法,
        // 不该为迁就本扫描去改:
        //   · 打码示例 `138****8000` —— 星号间无文字 (中间段为空)
        //   · glob 路径 `Sns/Img/**` —— 没有闭合的第二个 `**` (尾段不算被包围)
        // 这两条都是本规则**真误报过**才补的: v1 直扫 "**" 报了 pii-scan 的打码; v2 判"两侧是不是
        // 数字"又报了 decrypt-images 的 glob。验证规则本身也会有 bug, 迭代了三版。
        fn markdown_stars(line: &str) -> bool {
            let parts: Vec<&str> = line.split("**").collect();
            if parts.len() < 3 {
                return false; // 不足两个 `**` → 不可能成对包围
            }
            // 奇数段 = 被一对 `**` 夹住的内容; 最后一段后面没有闭合的 `**`, 不算。
            parts
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == 1 && *i < parts.len() - 1)
                .any(|(_, seg)| !seg.trim().is_empty())
        }
        let mut cmd = Cli::command();
        cmd.build();
        let mut bad: Vec<String> = Vec::new();
        let snip = |l: &str| l.trim().chars().take(90).collect::<String>();
        for sub in cmd.get_subcommands() {
            let help = sub.clone().render_long_help().to_string();
            for leak in LEAKS {
                if let Some(line) = help.lines().find(|l| l.contains(leak)) {
                    bad.push(format!("  `{} --help` 泄 {:?}: …{}…", sub.get_name(), leak, snip(line)));
                }
            }
            // 形状扫: 每处都报 (不是只报第一处) —— 上一版只报首个匹配, 修一处露一处, 我在那儿打了半天地鼠。
            for line in help.lines() {
                if let Some(m) = internal_shape.find(line) {
                    bad.push(format!(
                        "  `{} --help` 泄内部标识 {:?}: …{}…",
                        sub.get_name(),
                        m.as_str(),
                        snip(line)
                    ));
                }
                if markdown_stars(line) {
                    bad.push(format!(
                        "  `{} --help` 有裸 markdown `**`: …{}…",
                        sub.get_name(),
                        snip(line)
                    ));
                }
            }
        }
        bad.sort();
        bad.dedup();
        assert!(
            bad.is_empty(),
            "以下 --help 含内部叙事 (共 {} 处) —— 把 /// 里的设计理由降级成 // 普通注释:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// **`--all` 必须尊重 `--no-messages`** —— 别让"跳过消息"被 `--all` 静默吃掉。
    ///
    /// 真踩到: `ingest --no-messages --all` 照导消息 —— **3.2GB / 一个多小时**(日志坐实
    /// "开始 message ingest…"), 而 `--no-messages` 的 help 白纸黑字写着"跳过消息导入"。根因是
    /// `let plan = if args.all { IngestPlan::all() }` 这一支**整个不读 `args.no_messages`**。
    /// 又一例"参数在某分支被静默吞"(本轮 P1-1 是 35 个查询命令吞 --mode, 这条是 ingest 吞 --no-messages)。
    ///
    /// `--all --no-messages` 的意图明确且有用: **建全部类型但别导消息** = 建小型对照库的姿势。
    #[test]
    fn ingest_all_still_honors_no_messages() {
        // 这里直接验计划构造的语义 (`main` 里那段 if/else 的两支)。
        let all_but_msgs = native_adapter::IngestPlan {
            messages: false,
            ..native_adapter::IngestPlan::all()
        };
        assert!(!all_but_msgs.messages, "--all --no-messages → **不导消息**");
        // 其余类型一个不少 (否则就成了"--no-messages 把 --all 也废了")。
        assert!(all_but_msgs.contacts, "--all 的其余类型照建: contacts");
        assert!(all_but_msgs.strangers, "--all 的其余类型照建: strangers");
        assert!(all_but_msgs.avatars, "--all 的其余类型照建: avatars");
        assert!(all_but_msgs.biz_messages, "--all 的其余类型照建: biz_messages");
        // 对照: 光 --all(不给 --no-messages) 该导消息。
        assert!(native_adapter::IngestPlan::all().messages, "光 --all → 导消息");
    }

    /// **R16-1**: `table_total` 冷热三态 —— 守"热查表头别报 0 条"。
    ///
    /// **真 bug 复现**: `Meta::hot` 的 `total_count` 恒 `None` (envelope.rs:184 —— §14.1 定的: 热查不铺顶层
    /// total_count, 精确全量走 summary), 而我接 favorites 热查时把冷查表头 `meta.total_count.unwrap_or(0)`
    /// 原样留着 → `favorites --mode hot` 打 **"收藏 0 条 (取前 50):" 然后列出 50 条**。
    ///
    /// 现有测试一条都碰不到它 (table 是 eprintln, 没人测) —— 所以这里直测纯函数。R16-1 后面还有 8 条命令
    /// 要接热查, 每条的表头都会经过 `table_total`, 钉死三态免再抄错。
    #[test]
    fn table_total_reads_hot_summary_not_just_total_count() {
        use native_query::Source;
        // ① 冷查: total_count 有值 → 直接用。
        let cold = Meta::offset_page(0, 3, 42, 50).with_source(Source::Cold);
        assert_eq!(
            table_total(&cold, "total_favorites"),
            Some(42),
            "冷查该读 meta.total_count"
        );
        // ② 热查 COUNT 成功: total_count 恒 None, 真值只在 summary.<key> 里。
        let hot = Meta::hot(true)
            .with_source(Source::Hot)
            .with_summary(serde_json::json!({"total_favorites": 42}));
        assert_eq!(
            hot.total_count, None,
            "前提: §14.1 热查不铺顶层 total_count —— 这条若变了, 本测试就失去意义, 该重审而不是改断言"
        );
        assert_eq!(
            table_total(&hot, "total_favorites"),
            Some(42),
            "热查该回落 summary —— 直读 total_count 得 None → 表头打 0 条却列满一页 (favorites 真中过)"
        );
        // ③ 热查 COUNT 失败: summary 是 total_unknown → None (表头须说"未知", 不许伪装 0)。
        let unknown = Meta::hot(true)
            .with_source(Source::Hot)
            .with_summary(serde_json::json!({"total_unknown": true, "partial": true}));
        assert_eq!(
            table_total(&unknown, "total_favorites"),
            None,
            "COUNT 失败该返 None 让表头说'未知', 别伪装成 0"
        );
    }

    /// R9 复审R3#3 自审: `AliveGuard` Drop 时置 false —— **正常 drop / panic 展开**两路径都置 (堵 watch future
    /// panic 时旧写法 `store(false)` 被展开跳过、status 假报 live:true 的洞)。
    #[test]
    fn alive_guard_stores_false_on_drop_and_panic() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        // 正常 drop: 出作用域 → false。
        let a = Arc::new(AtomicBool::new(true));
        {
            let _g = AliveGuard(a.clone());
            assert!(a.load(Ordering::Relaxed), "guard 在时仍 true");
        }
        assert!(!a.load(Ordering::Relaxed), "guard drop → false");
        // panic 展开路径: catch_unwind 里建 guard 后 panic → 展开仍 drop guard → false (这是旧写法漏的路径)。
        let b = Arc::new(AtomicBool::new(true));
        let b2 = b.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = AliveGuard(b2);
            panic!("模拟 watch future panic");
        }));
        assert!(r.is_err(), "确实 panic 了");
        assert!(
            !b.load(Ordering::Relaxed),
            "panic 展开也 drop guard → false (不假报 live)"
        );
    }

    /// ⑥ inspect 消歧: type→(表,key) 映射 —— contact 与 session 都 key 在 username 但**不同表**,
    /// 是解 person↔session 同 wxid 歧义的核心 (inspect session X 查 session 表, inspect contact X 查 person 表)。
    #[test]
    fn inspect_type_table_key_disambiguates() {
        assert_eq!(InspectType::Contact.table_key(), ("person", "username"));
        assert_eq!(InspectType::Session.table_key(), ("session", "username"));
        assert_eq!(InspectType::Chatroom.table_key(), ("chatroom", "chatroom_id"));
        assert_eq!(InspectType::Message.table_key(), ("message", "source_native_id"));
        assert_ne!(
            InspectType::Contact.table_key().0,
            InspectType::Session.table_key().0,
            "contact 与 session 须映射不同表, 否则同 wxid 串表"
        );
    }

    /// ⑥ 消歧端到端(补 HOLE-2): person 与 session 同 key 列 username 不同表, 同一 wxid 各返各表行不串。
    /// 锁运行时路由 (上面的常量映射测锁不到"真查不串"); table_key→fetch_row 走真表。
    #[test]
    fn inspect_disambiguates_same_key_across_tables() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE person (username TEXT, mark TEXT)", [])
            .unwrap();
        conn.execute("CREATE TABLE session (username TEXT, mark TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO person VALUES ('wxid_x', 'I_AM_PERSON')", [])
            .unwrap();
        conn.execute("INSERT INTO session VALUES ('wxid_x', 'I_AM_SESSION')", [])
            .unwrap();

        let mark = |row: &[(String, serde_json::Value)]| row.iter().find(|(k, _)| k == "mark").unwrap().1.clone();
        let (pt, pk) = InspectType::Contact.table_key();
        let (st, sk) = InspectType::Session.table_key();
        let prow = fetch_row(&conn, pt, pk, "wxid_x").unwrap().expect("person 有 wxid_x");
        let srow = fetch_row(&conn, st, sk, "wxid_x").unwrap().expect("session 有 wxid_x");
        // 同一 wxid_x: contact→person 返 I_AM_PERSON, session→session 返 I_AM_SESSION → 不串。
        assert_eq!(mark(&prow), serde_json::json!("I_AM_PERSON"));
        assert_eq!(mark(&srow), serde_json::json!("I_AM_SESSION"));
        assert_ne!(prow, srow, "同 key 不同表须返不同行");
    }

    /// E0 接线: `CliError` 携码 → 分类到该码 + 对应退出码;未携码的 anyhow → `INTERNAL`/70。
    #[test]
    fn cli_error_classifies_to_code_and_exit() {
        let coded: anyhow::Error = CliError {
            code: native_core::ErrorCode::NotFound,
            hint: "会话查无".into(),
        }
        .into();
        assert_eq!(classify_error(&coded), native_core::ErrorCode::NotFound);
        assert_eq!(classify_error(&coded).exit_code(), 3, "NOT_FOUND → 退出码 3");

        let generic = anyhow::anyhow!("未分类错误");
        assert_eq!(classify_error(&generic), native_core::ErrorCode::Internal);
        assert_eq!(classify_error(&generic).exit_code(), 70, "未分类 → INTERNAL/70");
    }

    /// **命令级**错误码 (信封审 rank-1 补: golden 只测纯函数 exit_code() 查表, 未测命令**真 emit** 码
    /// = 假绿)。此测走 cmd_exec 真路径: 拒写 → 真产出 CliError{BadRequest} → classify → 退出 2
    /// (只读守卫在开库前, 无需真库)。与 cli_err 携码修复配套, 防退化回无码 bail!→INTERNAL/70。
    #[tokio::test] // R16-6: cmd_exec 转 async (冷热双模) → 测试也 async
    async fn cmd_exec_write_emits_bad_request_exit2() {
        let args = ExecArgs {
            // R16-1: QueryTarget 转热冷通用 → 用 ::cold 构造器 (exec 是冷查命令)。
            target: QueryTarget::cold("nonexistent.db".to_string(), None),
            sql: "DELETE FROM person".to_string(),
            max_rows: 10,
            format: OutFormat::Json,
            source_db: None, // R16-6: 热查专用参, 冷查/本测不用
        };
        let err = cmd_exec(&args).await.expect_err("写 SQL 应被只读守卫拒");
        assert_eq!(
            classify_error(&err),
            native_core::ErrorCode::BadRequest,
            "拒写 → BAD_REQUEST"
        );
        assert_eq!(classify_error(&err).exit_code(), 2, "BAD_REQUEST → 退出 2");
    }
    use async_trait::async_trait;
    use native_core::key_provider::{KeyError, KeyProviderCapabilities};

    /// mock — resolve(wxid) 返回固定 key 或错 (cmd_auth 注入测试, 不碰真实 hook/微信)。
    struct MockProvider {
        ok: bool,
    }
    #[async_trait]
    impl KeyProvider for MockProvider {
        async fn resolve(&self, _wxid: &Wxid) -> Result<MasterKey, KeyError> {
            if self.ok {
                Ok(MasterKey::from_bytes([0u8; 32]))
            } else {
                Err(KeyError::ConsentDenied)
            }
        }
        fn name(&self) -> &'static str {
            "mock"
        }
        fn capabilities(&self) -> KeyProviderCapabilities {
            KeyProviderCapabilities::default()
        }
    }

    #[tokio::test]
    async fn cmd_auth_ok_returns_true() {
        let p = MockProvider { ok: true };
        let w = Wxid::try_new("wxid_alice").unwrap();
        assert!(cmd_auth(&p, &w).await.unwrap());
    }

    #[tokio::test]
    async fn cmd_auth_err_returns_false() {
        let p = MockProvider { ok: false };
        let w = Wxid::try_new("wxid_bob").unwrap();
        assert!(!cmd_auth(&p, &w).await.unwrap());
    }

    #[test]
    fn detect_strips_device_suffix_and_skips_non_wxid() {
        let tmp = std::env::temp_dir().join("native_cli_auth_test_detect");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("wxid_abcd1234efgh567_abfe")).unwrap();
        std::fs::create_dir_all(tmp.join("wxid_0d6wfw0jfxlc22_c195")).unwrap();
        std::fs::create_dir_all(tmp.join("wxid_aaaaaaaaaaaaaaaa")).unwrap(); // 裸目录无设备后缀 (codex r2 P2 guard)
        std::fs::create_dir_all(tmp.join("Backup")).unwrap(); // 非 wxid_ → 跳过
        std::fs::create_dir_all(tmp.join("all_users")).unwrap();
        let mut wxids = detect_account_wxids(&tmp)
            .iter()
            .map(|w| w.as_str().to_string())
            .collect::<Vec<_>>();
        wxids.sort();
        // 带后缀的去后缀; 裸目录 fallback 整个名 (不误切成 "wxid")
        assert_eq!(
            wxids,
            vec!["wxid_0d6wfw0jfxlc22", "wxid_aaaaaaaaaaaaaaaa", "wxid_abcd1234efgh567"]
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn detect_empty_when_dir_missing() {
        let nope = std::env::temp_dir().join("native_cli_auth_nonexistent_xyz123");
        assert!(detect_account_wxids(&nope).is_empty());
    }

    #[test]
    fn canonical_nonexistent_resolves_via_existing_ancestor() {
        // out_dir 不存在时: canonical 已存在祖先 (temp) + 拼未存在尾部, 不创建目录。
        let tmp = std::env::temp_dir();
        let target = tmp.join("ncli_nonexist_abc987").join("deeper");
        let c = canonical_nonexistent(&target).unwrap();
        assert!(c.starts_with(tmp.canonicalize().unwrap()), "解析路径在 temp 规范前缀下");
        assert!(c.ends_with("deeper"), "保留未存在尾部末段");
        assert!(!target.exists(), "canonical_nonexistent 不创建目录");
    }

    // ---- --cipher native 解密接线 (语音/图片/视频导出直读加密库, 无需先手动解密) ----

    /// detect_wxid_from_path: 从加密 media_0.db 路径的账号目录段 (wxid_<id>_<设备后缀>) 提 wxid。
    #[test]
    fn detect_wxid_from_encrypted_db_path() {
        let p = Path::new("X:/xwechat_files/wxid_abcd1234efgh567_abfe/db_storage/media_0.db");
        assert_eq!(
            detect_wxid_from_path(p).map(|w| w.as_str().to_string()),
            Some("wxid_abcd1234efgh567".to_string())
        );
    }

    /// detect_wxid_from_path: 路径里没有 wxid_ 段 → None (逼用户显式 --wxid)。
    #[test]
    fn detect_wxid_from_path_none_when_absent() {
        assert!(detect_wxid_from_path(Path::new("C:/data/backup/media_0.db")).is_none());
    }

    /// resolve_export_key: 没开 --cipher → None (读已解密明文库, 现状; 不解密)。
    #[tokio::test]
    async fn resolve_key_none_without_cipher() {
        let opts = DecryptOpts {
            cipher: None,
            wxid: Some("wxid_x".into()),
            master_key_hex: None,
        };
        assert!(resolve_export_key(&opts, None).await.unwrap().is_none());
    }

    /// resolve_export_key: --cipher + --master-key-hex → 直接用 hex (跳过 cache, 不需要 wxid)。
    #[tokio::test]
    async fn resolve_key_hex_takes_priority() {
        let opts = DecryptOpts {
            cipher: Some(CipherKind::Native),
            wxid: None,
            master_key_hex: Some("ab".repeat(32)), // 64 hex
        };
        assert!(resolve_export_key(&opts, None).await.unwrap().is_some());
    }

    /// resolve_export_key: --cipher + 坏 hex → Err (不静默当没解密)。
    #[tokio::test]
    async fn resolve_key_bad_hex_errs() {
        let opts = DecryptOpts {
            cipher: Some(CipherKind::Native),
            wxid: None,
            master_key_hex: Some("zz".repeat(32)), // 64 字符但非 hex
        };
        assert!(resolve_export_key(&opts, None).await.is_err());
    }

    /// resolve_export_key: --cipher 但无 hex + 无 wxid + 检测不到账号 → Err (提示 --wxid / 先 auth), 不碰 cache。
    #[tokio::test]
    async fn resolve_key_native_needs_wxid() {
        let opts = DecryptOpts {
            cipher: Some(CipherKind::Native),
            wxid: None,
            master_key_hex: None,
        };
        assert!(resolve_export_key(&opts, None).await.is_err());
    }

    /// open_source_db: 不给 key = open_readonly 已解密明文库, conn() 能查行 (加密分支靠真跑验证)。
    #[test]
    fn open_source_db_plain_reads_rows() {
        let tmp = std::env::temp_dir().join("ncli_source_plain_test.db");
        let _ = std::fs::remove_file(&tmp);
        {
            let c = rusqlite::Connection::open(&tmp).unwrap();
            c.execute_batch("CREATE TABLE t(a INTEGER); INSERT INTO t VALUES (42);")
                .unwrap();
        }
        let src = open_source_db(&tmp, None, "test db").unwrap();
        let n: i64 = src.conn().query_row("SELECT a FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 42, "Plain 分支 conn() 应能查已解密库");
        let _ = std::fs::remove_file(&tmp);
    }

    // sessions/messages 接线 helper (resolve_message_dir / query_locator_path / wxid_from_dir_name)
    // 的单测已随函数上移至 native-query::hot 的 #[cfg(test)] (§6③ 收尾)。

    // ---- doctor 检查 ----

    #[test]
    fn doctor_wechat_dir_pass_and_fail() {
        let tmp = std::env::temp_dir().join("ncli_doctor_wxdir");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("wxid_test_abfe")).unwrap();
        let (lvl, _, _) = check_wechat_dir(tmp.to_str());
        assert_eq!(lvl, CheckLevel::Pass, "有账号目录 → Pass");

        let empty = std::env::temp_dir().join("ncli_doctor_empty");
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir_all(&empty).unwrap();
        let (lvl2, _, _) = check_wechat_dir(empty.to_str());
        assert_eq!(lvl2, CheckLevel::Fail, "无账号目录 → Fail");

        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn doctor_temp_writable_passes() {
        let (lvl, _, _) = check_temp_writable();
        assert_eq!(lvl, CheckLevel::Pass, "系统临时目录一般可写");
    }

    #[tokio::test]
    async fn doctor_key_cache_warn_and_fail() {
        // 未给 --wxid → Warn (跳过, 不碰 cache)。
        let (lvl, _, _) = check_key_cache(None).await;
        assert_eq!(lvl, CheckLevel::Warn, "未给 --wxid → Warn");
        // 非法 wxid → Fail (parse 失败, 不碰 cache)。
        let (lvl2, _, _) = check_key_cache(Some("!bad wxid!")).await;
        assert_eq!(lvl2, CheckLevel::Fail, "非法 wxid → Fail");
    }

    // ---- contacts / members 查询 ----

    #[test]
    fn members_query_filters_in_group_and_admins() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO chatroom_member \
             (account_id_sha, source, source_native_id, chatroom_id_sha, member_wxid_sha, \
              account_id, chatroom_id, member_wxid, display_name, display_name_len, is_in_group, role) \
             VALUES \
             ('a','s','n1','cs','m1','acc','g@chatroom','wxid_owner','群主',6,1,'owner'), \
             ('a','s','n2','cs','m2','acc','g@chatroom','wxid_a','甲',3,1,'member'), \
             ('a','s','n3','cs','m3','acc','g@chatroom','wxid_left','走',3,0,'member')",
            [],
        )
        .unwrap();
        let all = native_query::members_query(&conn, "g@chatroom", false, 100, 0).unwrap();
        assert_eq!(all.data.len(), 2, "只看在群 (is_in_group=1), 排除已退");
        assert_eq!(all.meta.total_count, Some(2), "total = COUNT 全量在群人数");
        let admins = native_query::members_query(&conn, "g@chatroom", true, 100, 0).unwrap();
        assert_eq!(admins.data.len(), 1, "仅群主/管理员 (role!=member)");
        assert_eq!(admins.data[0]["member_wxid"], "wxid_owner");
        // 审查 P1-6: SQL LIMIT 真截断 (大群防击穿); total 仍报全量 (截断诚实)。
        let limited = native_query::members_query(&conn, "g@chatroom", false, 1, 0).unwrap();
        assert_eq!(limited.data.len(), 1, "limit=1 → 只返 1 行");
        assert_eq!(
            limited.meta.total_count,
            Some(2),
            "total 仍 = 全量 2 (limit 只截数据不截 total)"
        );
        // ④ offset (members 的 offset 是 SQL 内联 `OFFSET {offset}`, 直接测这条路): 逐页翻到尾, 两成员都够得着。
        let m0 = native_query::members_query(&conn, "g@chatroom", false, 1, 0).unwrap();
        let m1 = native_query::members_query(&conn, "g@chatroom", false, 1, 1).unwrap();
        assert!(m0.meta.has_more, "2 在群成员, 第 1 页后还有");
        assert_ne!(
            m0.data[0]["member_wxid"], m1.data[0]["member_wxid"],
            "第 2 页是另一个成员 (offset 前进)"
        );
        assert!(!m1.meta.has_more, "第 2 页到底");
        assert_eq!(
            native_query::members_query(&conn, "g@chatroom", false, 1, 2)
                .unwrap()
                .data
                .len(),
            0,
            "offset 超界 → 空"
        );
    }

    /// 审查 P1-4: person PK=(account_id_sha, source, username_sha), **username 非唯一** —— 同 wxid 跨两
    /// source 两行 (contact.db / contact.db|stranger, --strangers 发货路径)。单用 username 当 keyset
    /// tiebreaker → 跨页边界严格 `>` 把并列 username 整片跳过 → 静默丢联系人。(username, source) 复合键守恒。
    #[test]
    fn contacts_pagination_conserves_duplicate_username_across_sources() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let insert = |source: &str, uname: &str, nick: &str| {
            conn.execute(
                "INSERT INTO person \
                 (account_id_sha, source, source_native_id, username_sha, account_id, username, \
                  nick_name, nick_name_len, remark_len, alias_len, local_type, is_in_chat_room) \
                 VALUES ('a', ?1, ?2, ?3, 'acc', ?4, ?5, 0, 0, 0, 1, 0)",
                rusqlite::params![
                    source,
                    format!("{source}-{uname}"),
                    format!("sha-{uname}-{source}"),
                    uname,
                    nick
                ],
            )
            .unwrap();
        };
        insert("contact.db", "wxid_aaa", "甲");
        insert("contact.db", "wxid_dup", "重名-联系人"); // 并列 username (source A)
        insert("contact.db|stranger", "wxid_dup", "重名-陌生人"); // 并列 username (source B)
        insert("contact.db", "wxid_zzz", "丙");

        // keyset 逐页 (limit=1 强制每并列组跨页) 并集。
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..50 {
            let r = native_query::contacts_query(&conn, ":memory:", None, None, 1, cursor.as_deref()).unwrap();
            for row in &r.data {
                seen.push(row["username"].as_str().unwrap().to_string());
            }
            match r.meta.next_cursor.clone() {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(
            seen.len(),
            4,
            "跨页并集须含全部 4 行 (含并列 username 的两 source), 一行不丢"
        );
        let dup = seen.iter().filter(|u| *u == "wxid_dup").count();
        assert_eq!(dup, 2, "并列 username 的两行都要在 (单键 tiebreaker 会在跨页丢掉 1 行)");
    }

    #[test]
    fn sns_feed_query_reads_moment() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO moment (account_id_sha, source, source_native_id, tid, author_sha, \
             create_time, moment_type, account_id, author, content_desc, content_desc_len, \
             media_count, like_count, comment_count, content_len) \
             VALUES ('a','sns','t1',1,'as',100,1,'acc','wxid_x','动态内容',12,2,5,3,12)",
            [],
        )
        .unwrap();
        let r = native_query::moments_query(&conn, 10, 0).unwrap();
        assert_eq!(r.data.len(), 1);
        assert_eq!(r.data[0]["author"], "wxid_x", "author");
        assert_eq!(r.data[0]["content_desc"], "动态内容", "content_desc");
        assert_eq!(r.data[0]["like_count"], 5, "like_count");
    }

    #[test]
    fn favorites_query_empty_ok() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let r = native_query::favorites_query(&conn, None, 50, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(0), "空 favorite 表 0 行");
        assert!(r.data.is_empty());
    }

    // ---- calls / friend-requests / mentions 查询 (第二批) ----

    /// 塞一条最小合法 message 行 (calls/mentions 的 JOIN 靠它取时间/正文)。
    fn insert_test_message(
        conn: &rusqlite::Connection,
        native_id: &str,
        conv: &str,
        sender: &str,
        ctime: i64,
        text: &str,
    ) {
        conn.execute(
            "INSERT INTO message \
             (account_id_sha, source, source_native_id, conv_id_sha, server_id, create_time, \
              sort_seq, status, msg_type, msg_type_name, local_type_raw, sender_wxid_sha, \
              is_chatroom, text_content_sha, text_content_len, raw_xml_present, decode_kind, \
              account_id, conv_id, sender_wxid, text_content) \
             VALUES ('a','msg',?1,'cs',1,?4,1,0,1,'文本',1,'ss',1,'ts',?6,0,'plain','acc',?2,?3,?5)",
            rusqlite::params![native_id, conv, sender, ctime, text, text.chars().count() as i64],
        )
        .unwrap();
    }

    #[test]
    fn calls_query_joins_message_for_time() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "n1", "wxid_friend", "wxid_friend", 1000, "");
        conn.execute(
            "INSERT INTO message_call \
             (account_id_sha, source, source_native_id, invite_type, room_type, call_state, \
              duration, account_id, display_content) \
             VALUES ('a','msg','n1',1,0,101,42,'acc','通话时长 00:42')",
            [],
        )
        .unwrap();
        let r = native_query::calls_query(&conn, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(1), "真总数 (count JOIN)");
        assert_eq!(r.data.len(), 1);
        assert_eq!(r.data[0]["create_time"], 1000, "create_time 来自 JOIN 的 message");
        assert_eq!(r.data[0]["invite_type"], 1, "invite_type=1 语音");
        assert_eq!(r.data[0]["duration_sec"], 42, "duration 秒");
        assert_eq!(r.data[0]["kind"], "语音", "kind label 预组进 json");
        assert_eq!(native_query::call_kind(1), "语音");
        assert_eq!(native_query::call_kind(0), "视频");
        assert_eq!(native_query::call_kind(-1), "气泡");
    }

    #[test]
    fn friend_requests_query_orders_desc() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO friend_verify \
             (account_id_sha, source, source_native_id, user_name_sha, friend_type, timestamp, \
              is_sender, scene, content_len, account_id, user_name, content) \
             VALUES \
             ('a','fmsg','n1','us',2,100,0,17,6,'acc','wxid_a','你好'), \
             ('a','fmsg','n2','us',2,200,1,30,0,'acc','wxid_b','')",
            [],
        )
        .unwrap();
        let r = native_query::friend_requests_query(&conn, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(2), "真总数");
        assert_eq!(r.data.len(), 2);
        assert_eq!(r.data[0]["timestamp"], 200, "时间倒序, 最新在前");
        assert_eq!(r.data[1]["user_name"], "wxid_a");
        // 截断诚实性: limit 1 → 只回 1 行, 但 total 仍报真实 2 (双审逮出的"6 条 vs 7925"修复)。
        let few = native_query::friend_requests_query(&conn, 1, 0).unwrap();
        assert_eq!(few.data.len(), 1, "limit=1 只回 1 行");
        assert_eq!(few.meta.total_count, Some(2), "但真总数仍是 2, 不被 limit 截断");
        // ⭐④ offset 分页 (全数据可达): limit=1 逐页翻 —— offset 0/1 各取 1 行, 2 行**全够得着**(不封顶藏数据);
        // has_more offset 感知 (第 1 页 true, 第 2 页到底 false); offset 超界 → 空。
        let p0 = native_query::friend_requests_query(&conn, 1, 0).unwrap();
        let p1 = native_query::friend_requests_query(&conn, 1, 1).unwrap();
        let p2 = native_query::friend_requests_query(&conn, 1, 2).unwrap();
        assert_eq!(p0.data[0]["timestamp"], 200, "第 1 页 = 最新");
        assert!(p0.meta.has_more, "第 1 页后还有 (offset+shown < total)");
        assert_eq!(p1.data[0]["timestamp"], 100, "第 2 页 = 次新 (offset 够得着尾巴)");
        assert!(!p1.meta.has_more, "第 2 页到底");
        assert_eq!(p2.data.len(), 0, "offset 超界 → 空");
        assert!(!p2.meta.has_more, "超界无 has_more");

        // ⭐ timestamp **并列**时翻页不重不漏 —— 上面那批夹具(ts=100/200, 互不相同)**够不着这条**:
        // 轮4 审做过负向验证 —— 把 ORDER BY 的次键撤掉改回单键, **117 个测试全绿**, 一条都没碰到这个改动。
        // "有测试" ≠ "测到了": 顺路夹具(时间戳恰好互不相同)测不出只在并列数据上发作的 bug。
        // 真库确实有并列: 7967 行 / 7961 个不同 timestamp → 6 行并列, 最大组 3 行。
        conn.execute(
            "INSERT INTO friend_verify \
             (account_id_sha, source, source_native_id, user_name_sha, friend_type, timestamp, \
              is_sender, scene, content_len, account_id, user_name, content) \
             VALUES \
             ('a','fmsg','t1','us',2,300,0,17,0,'acc','wxid_t3',''), \
             ('a','fmsg','t2','us',2,300,0,17,0,'acc','wxid_t1',''), \
             ('a','fmsg','t3','us',2,300,0,17,0,'acc','wxid_t2','')",
            [],
        )
        .unwrap();
        let full = native_query::friend_requests_query(&conn, 10, 0).unwrap();
        let all: Vec<&str> = full
            .data
            .iter()
            .map(|r| r["user_name"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            &all[..3],
            ["wxid_t3", "wxid_t2", "wxid_t1"],
            "ts=300 三行并列 → 必须按次键 user_name DESC 定序 (单键排序下这三行顺序不保证)"
        );
        // 逐页翻这 5 行, 每行恰好出现一次 —— 并列组横跨页边界时最容易重复/漏。
        let mut seen: Vec<String> = Vec::new();
        for off in 0..5 {
            let pg = native_query::friend_requests_query(&conn, 1, off).unwrap();
            seen.push(pg.data[0]["user_name"].as_str().unwrap_or_default().to_string());
        }
        let mut uniq = seen.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(
            uniq.len(),
            5,
            "limit=1 翻 5 页 → 5 行各出现恰好一次, 不重不漏: {seen:?}"
        );
        assert_eq!(seen, all, "逐页翻出来的顺序 == 一次全取的顺序");

        assert_eq!(native_query::friend_scene_label(17), "名片添加");
        assert!(
            native_query::friend_scene_label(30).starts_with("场景"),
            "未知场景码原样报数不瞎标"
        );
    }

    #[test]
    fn mentions_query_joins_and_filters() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "n1", "g@chatroom", "wxid_sender", 500, "@张三 在吗");
        conn.execute(
            "INSERT INTO message_mention \
             (account_id_sha, source, source_native_id, mentioned_wxid_sha, is_at_all, \
              account_id, mentioned_wxid) \
             VALUES \
             ('a','msg','n1','ws',0,'acc','wxid_zhangsan'), \
             ('a','msg','n1','wall',1,'acc','notify@all')",
            [],
        )
        .unwrap();
        let all = native_query::mentions_query(&conn, None, 10, 0).unwrap();
        assert_eq!(all.meta.total_count, Some(2), "无过滤真总数");
        assert_eq!(all.data.len(), 2, "两条 @ (一 @人 一 @所有人)");
        let filtered = native_query::mentions_query(&conn, Some("zhangsan"), 10, 0).unwrap();
        assert_eq!(
            filtered.meta.total_count,
            Some(1),
            "过滤后真总数 (count 也 respect 过滤)"
        );
        assert_eq!(filtered.data.len(), 1, "按 mentioned_wxid 子串过滤");
        assert_eq!(filtered.data[0]["mentioned_wxid"], "wxid_zhangsan");
        assert_eq!(
            filtered.data[0]["text_content"], "@张三 在吗",
            "text_content 来自 JOIN 的 message"
        );
    }

    // ---- money 转账/红包/群收款 (第二批) ----

    /// 塞一条最小 message_app 行 (转账金额靠 transfer_txid JOIN, 群收款金额靠 group_pay_bill_no JOIN)。
    fn insert_test_message_app(
        conn: &rusqlite::Connection,
        native_id: &str,
        transfer_fee: Option<&str>,
        transfer_txid: Option<&str>,
        group_pay_amount: Option<&str>,
        group_pay_bill_no: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id, \
              transfer_fee, transfer_txid, group_pay_amount, group_pay_bill_no) \
             VALUES ('a','msg',?1,2000,0,'acc',?2,?3,?4,?5)",
            rusqlite::params![
                native_id,
                transfer_fee,
                transfer_txid,
                group_pay_amount,
                group_pay_bill_no
            ],
        )
        .unwrap();
    }

    /// 塞一条最小 transfer 行 (21 列全 NOT NULL, 非关键列填占位; 金额靠 transcation_id 关联 message_app.transfer_txid)。
    fn insert_test_transfer(
        conn: &rusqlite::Connection,
        native_id: &str,
        transcation_id: &str,
        sub_type: i64,
        time: i64,
        payer: &str,
        receiver: &str,
    ) {
        conn.execute(
            "INSERT INTO transfer \
             (account_id_sha, source, source_native_id, transfer_id, transcation_id, \
              message_server_id, second_message_server_id, pay_sub_type, session_name_sha, \
              pay_payer_sha, pay_receiver_sha, begin_transfer_time, last_modified_time, \
              invalid_time, last_update_time, delay_confirm_flag, bubble_clicked_flag, \
              account_id, session_name, pay_payer, pay_receiver) \
             VALUES ('a','msg',?1,'TID',?2,0,0,?3,'ss','ps','rs',?4,0,0,0,0,0,'acc','会话',?5,?6)",
            rusqlite::params![native_id, transcation_id, sub_type, time, payer, receiver],
        )
        .unwrap();
    }

    #[test]
    fn money_transfer_join_amount_and_fallback() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // 转账1: message_app.transfer_txid == transfer.transcation_id → 出真金额 (真库实测坐实的正确键)。
        insert_test_message_app(&conn, "t1", Some("￥10.00"), Some("TXID-AAA"), None, None);
        insert_test_transfer(&conn, "tr1", "TXID-AAA", 3, 5000, "wxid_payer", "wxid_receiver");
        // 转账2: transcation_id 无匹配 message_app → 回退状态码。
        insert_test_transfer(&conn, "tr2", "TXID-NONE", 4, 4000, "wxid_a", "wxid_b");
        let (rows, total) = native_query::query_transfers(&conn, 10).unwrap();
        assert_eq!(total, 2, "真总数");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "转账");
        assert_eq!(
            rows[0].1,
            Some(5000),
            "时间倒序 (transfer 自带 begin_transfer_time), tr1 在前"
        );
        assert!(
            rows[0].3.contains("￥10.00"),
            "transcation_id==transfer_txid → 真金额, got: {}",
            rows[0].3
        );
        assert!(rows[1].3.contains("状态码4"), "无匹配 → 回退状态码, got: {}", rows[1].3);
    }

    #[test]
    fn money_group_pay_amount_and_paid_count() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO group_pay \
             (account_id_sha, source, source_native_id, bill_no, message_local_id, \
              message_create_time, session_name_sha, account_id, session_name) \
             VALUES ('a','msg','gp1','BILL1',1,6000,'ss','acc','项目群')",
            [],
        )
        .unwrap();
        // 同 bill_no 的另一条消息 (提醒/结算) group_pay_amount 为 NULL 且 rowid 更小 → 子查询必须靠
        // `IS NOT NULL` 守卫跳过它, 否则 LIMIT 1 会先撞上 NULL 丢掉真金额 (双审 Finding 1 回归防线)。
        insert_test_message_app(&conn, "gpdecoy", None, None, None, Some("BILL1"));
        // 金额靠 bill_no JOIN message_app.group_pay_amount (message_app 的 native_id 与 JOIN 无关)。
        insert_test_message_app(&conn, "gpapp", None, None, Some("应付¥8.00"), Some("BILL1"));
        // 2 付款人, 1 已付 (pay_status=1)。
        conn.execute(
            "INSERT INTO group_pay_member \
             (account_id_sha, source, source_native_id, payer_wxid_sha, bill_no, amount, \
              pay_status, account_id, payer_wxid) \
             VALUES ('a','msg','gp1','p1s','BILL1',800,1,'acc','wxid_p1'), \
                    ('a','msg','gp1','p2s','BILL1',800,0,'acc','wxid_p2')",
            [],
        )
        .unwrap();
        let (rows, total) = native_query::query_group_pays(&conn, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].0, "群收款");
        assert!(
            rows[0].3.contains("应付¥8.00"),
            "金额 via bill_no JOIN, got: {}",
            rows[0].3
        );
        assert!(
            rows[0].3.contains("已付1/2人"),
            "已付人数=count pay_status=1, got: {}",
            rows[0].3
        );
    }

    /// ⭐④ offset: money 三表合并的 offset 分页 (审查 Group A critic 点名的最高危未测路)。各源 fetch
    /// limit+offset 后合并排序 skip/take —— 关键: 第 2 页跨到**另一个源**, 证明"合并 top-N ⊆ 各源 top-N"成立。
    #[test]
    fn money_offset_pages_across_merged_sources() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // 两转账 (5000/2000) + 一群收款 (4000) → 合并时间倒序: 5000转 · 4000群收 · 2000转。
        insert_test_transfer(&conn, "tr1", "TXA", 3, 5000, "wxid_a", "wxid_b");
        insert_test_transfer(&conn, "tr2", "TXB", 3, 2000, "wxid_a", "wxid_b");
        conn.execute(
            "INSERT INTO group_pay (account_id_sha, source, source_native_id, bill_no, message_local_id, \
             message_create_time, session_name_sha, account_id, session_name) \
             VALUES ('a','msg','gp1','BILL1',1,4000,'ss','acc','群')",
            [],
        )
        .unwrap();
        let page = |off: usize| native_query::money_query(&conn, native_query::MoneyKind::All, 1, off).unwrap();
        let (p0, p1, p2, p3) = (page(0), page(1), page(2), page(3));
        assert_eq!(p0.meta.total_count, Some(3), "3 笔 (2 转账 + 1 群收款)");
        assert_eq!(
            p0.meta.offset,
            Some(0),
            "meta.offset 回显 (锁 P2 修复: offset_page 写 offset 字段)"
        );
        assert_eq!(p1.meta.offset, Some(1), "meta.offset 随页回显");
        assert_eq!(p0.data[0]["time"], 5000, "第 1 页 = 最新转账");
        assert!(p0.meta.has_more, "还有下一页");
        // 关键: 第 2 页是**另一个源** (群收款), 证明各源 fetch limit+offset 后合并正确, offset 够得着跨源尾巴。
        assert_eq!(p1.data[0]["time"], 4000, "第 2 页 = 群收款 (跨源)");
        assert_eq!(p2.data[0]["time"], 2000, "第 3 页 = 次新转账");
        assert!(!p2.meta.has_more, "第 3 页到底");
        assert_eq!(p3.data.len(), 0, "offset 超界 → 空");
        let times: Vec<i64> = [&p0, &p1, &p2]
            .iter()
            .flat_map(|p| p.data.iter().map(|r| r["time"].as_i64().unwrap()))
            .collect();
        assert_eq!(times, vec![5000, 4000, 2000], "逐页并集 = 全集时间倒序, 一条不丢不重");
    }

    #[test]
    fn money_red_envelope_no_time_no_amount() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO red_envelope \
             (account_id_sha, source, source_native_id, send_id, message_server_id, \
              sender_user_name_sha, session_name_sha, scene_id, hb_status, hb_type, \
              receive_status, native_url, account_id, sender_user_name, session_name) \
             VALUES ('a','msg','re1','SID',1,'ss','sess',1,4,0,1,'url','acc','wxid_sender','群红包')",
            [],
        )
        .unwrap();
        let (rows, total) = native_query::query_red_envelopes(&conn, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].0, "红包");
        assert_eq!(rows[0].1, None, "红包无自带时间戳 → None (不瞎编时间)");
        assert!(
            rows[0].3.contains("金额本地不存"),
            "红包金额本地不存 (设计), got: {}",
            rows[0].3
        );
    }

    // ---- stats 聚合 (第二批) ----

    #[test]
    fn stats_group_by_sender_and_conv() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "m1", "convA", "wxid_a", 1000, "hi");
        insert_test_message(&conn, "m2", "convA", "wxid_a", 2000, "yo");
        insert_test_message(&conn, "m3", "convB", "wxid_b", 3000, "x");
        // 按发送人: wxid_a 2 条 > wxid_b 1 条 (count DESC)。
        let (total, by_sender, dropped, has_more) = native_query::query_stats(&conn, StatsBy::Sender, 10, 0).unwrap();
        assert_eq!(total, 3, "消息总数");
        assert_eq!(dropped, 0, "健康数据无丢弃 (R4 复审R3#5: query_stats 返丢弃数)");
        assert!(
            !has_more,
            "2 个 sender 组 < limit 10 → 无下一页 (R5 复审P2#3: query_stats 返 has_more)"
        );
        assert_eq!(by_sender[0], ("wxid_a".to_string(), 2), "发得最多的排第一");
        assert_eq!(by_sender[1], ("wxid_b".to_string(), 1));
        // 按会话: convA 2 条 > convB 1 条。
        let (_, by_conv, _, _) = native_query::query_stats(&conn, StatsBy::Conv, 10, 0).unwrap();
        assert_eq!(by_conv[0], ("convA".to_string(), 2), "最热会话排第一");
        // limit 生效: 只取第一名 + 还有第二组 → has_more true (R5 复审P2#3)。
        let (_, top1, _, top1_more) = native_query::query_stats(&conn, StatsBy::Sender, 1, 0).unwrap();
        assert_eq!(top1.len(), 1, "limit=1 只回排行第一");
        assert!(top1_more, "limit=1 但有 2 个 sender 组 → has_more true");
    }

    #[test]
    fn dormant_orders_by_oldest_last_activity() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // convOld 最后一条在 1000; convNew 最后一条在 5000 (更近)。
        insert_test_message(&conn, "d1", "convOld", "wxid_a", 1000, "");
        insert_test_message(&conn, "d2", "convNew", "wxid_b", 3000, "");
        insert_test_message(&conn, "d3", "convNew", "wxid_b", 5000, "");
        let r = native_query::dormant_query(&conn, 10, 0).unwrap();
        assert_eq!(r.data.len(), 2, "两个会话");
        assert_eq!(r.data[0]["conv_id"], "convOld", "最久没说话 (last=1000) 排第一");
        assert_eq!(r.data[1]["conv_id"], "convNew", "last=5000 排后");
        assert_eq!(r.data[1]["message_count"], 2, "convNew 有 2 条消息");
    }

    #[test]
    fn inspect_dumps_row_and_reports_missing() {
        use rusqlite::types::Value;
        // 值展示: BLOB 只报字节数不倒原始字节。
        assert_eq!(sql_value_display(&Value::Null), "(null)");
        assert_eq!(sql_value_display(&Value::Integer(42)), "42");
        assert_eq!(sql_value_display(&Value::Text("hi".to_string())), "hi");
        assert_eq!(sql_value_display(&Value::Blob(vec![0u8; 5])), "<5 字节 BLOB>");
        // fetch_row 通用取行: 存在→Some(有序列), 不存在→None (临时表验通用性, 不依赖 person 全 schema)。
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE t (id TEXT, val INTEGER)", []).unwrap();
        conn.execute("INSERT INTO t VALUES ('a', 7)", []).unwrap();
        let row = fetch_row(&conn, "t", "id", "a").unwrap().expect("存在→Some");
        assert_eq!(
            row,
            vec![
                ("id".to_string(), serde_json::json!("a")),
                ("val".to_string(), serde_json::json!(7)),
            ],
            "有序列全出 (列序 = schema 序)"
        );
        assert!(fetch_row(&conn, "t", "id", "zzz").unwrap().is_none(), "不存在→None");
    }

    #[test]
    fn cache_key_fingerprint_extracts_sha8_no_leak() {
        let mk = MasterKey::from_hex(&"ab".repeat(32)).unwrap();
        let fp = key_fingerprint(&mk);
        assert_eq!(fp.len(), 8, "指纹是 8 char sha8, got: {fp}");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "全 hex, got: {fp}");
        assert!(format!("{mk:?}").contains(&fp), "指纹取自 MasterKey Debug 的 sha8");
        // K-R4: MasterKey Debug 绝不含明文 key hex。
        assert!(!format!("{mk:?}").contains(&"ab".repeat(32)), "Debug 不露明文 key");
    }

    #[test]
    fn resolve_lists_and_expands_forward() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // 一条合并转发 fwd1, 2 个子项 (seq 0 文本 / seq 1 图片)。
        conn.execute(
            "INSERT INTO message_forward_item \
             (account_id_sha, source, source_native_id, seq, data_type, data_size, \
              account_id, source_name, data_title, data_desc) \
             VALUES ('a','msg','fwd1',0,'1',10,'acc','张三','标题A','内容A'), \
                    ('a','msg','fwd1',1,'2',20,'acc','李四',NULL,'图片B')",
            [],
        )
        .unwrap();
        let (total_f, list) = query_forward_list(&conn, 10, 0).unwrap();
        assert_eq!(total_f, 1, "1 条合并转发消息 ((source,msg_id) 分组)");
        // R16-2: 列表带 source(分片) —— (source, msg_id, 子项数)。
        assert_eq!(
            list[0],
            ("msg".to_string(), "fwd1".to_string(), 2),
            "分片 msg 的 fwd1 有 2 子项"
        );
        // R16-2: query_forward_items 加 source 参数(None=不指定分片)。
        let (total_i, items) = query_forward_items(&conn, "fwd1", None, 10, 0).unwrap();
        assert_eq!(total_i, 2);
        assert_eq!(items[0].0, 0, "seq 0 在前");
        assert_eq!(items[1].0, 1, "seq 1 在后");
        // 给定 source 精确定位: source=msg 命中 2 条 / source=其它 命中 0。
        assert_eq!(
            query_forward_items(&conn, "fwd1", Some("msg"), 10, 0).unwrap().0,
            2,
            "source=msg 命中"
        );
        assert_eq!(
            query_forward_items(&conn, "fwd1", Some("other"), 10, 0).unwrap().0,
            0,
            "source=other 不命中"
        );
        // forward_sources: fwd1 落在分片 [msg]。
        assert_eq!(
            forward_sources(&conn, "fwd1").unwrap(),
            vec!["msg".to_string()],
            "fwd1 分片集"
        );
        assert_eq!(forward_type_label("1"), "文本");
        assert_eq!(forward_type_label("2"), "图片");
        assert!(forward_type_label("99").starts_with("类型"), "未知类型码原样报数");
        // 不存在的 msg_id → 0 子项。
        let (none, _) = query_forward_items(&conn, "nope", None, 10, 0).unwrap();
        assert_eq!(none, 0);
    }

    /// R16-2 锚重号回归 (Claude P3-3): 同 source_native_id 跨分片 = **两条不同**转发 → 复合键分开 / 展开无 source 歧义
    /// BadRequest / --source 精确定位单分片。锁死"别把不同消息合并"。
    #[test]
    fn resolve_collision_compound_key_splits_by_shard() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // 锚 'dup' 在两分片各一条不同转发: message_0.db 有 2 子项 / message_5.db 有 3 子项。
        conn.execute(
            "INSERT INTO message_forward_item \
             (account_id_sha, source, source_native_id, seq, data_type, data_size, account_id, source_name, data_title, data_desc) \
             VALUES ('a','message_0.db','dup',0,'1',0,'acc','甲','t0','d0'), \
                    ('a','message_0.db','dup',1,'1',0,'acc','乙',NULL,'d1'), \
                    ('a','message_5.db','dup',0,'2',0,'acc','丙','x0','y0'), \
                    ('a','message_5.db','dup',1,'2',0,'acc','丁',NULL,'y1'), \
                    ('a','message_5.db','dup',2,'2',0,'acc','戊',NULL,'y2')",
            [],
        )
        .unwrap();
        // 列表: 复合键 → **2 行**(每分片一条独立转发), 非合并成一行 5 子项。item_count DESC → message_5.db(3) 先。
        let (total, list) = query_forward_list(&conn, 10, 0).unwrap();
        assert_eq!(total, 2, "复合键: 两分片的 dup 是两条独立转发, 非合并");
        assert_eq!(list[0], ("message_5.db".to_string(), "dup".to_string(), 3));
        assert_eq!(list[1], ("message_0.db".to_string(), "dup".to_string(), 2));
        // forward_sources: dup 落两分片。
        assert_eq!(
            forward_sources(&conn, "dup").unwrap(),
            vec!["message_0.db".to_string(), "message_5.db".to_string()]
        );
        // 展开无 source (歧义) → BadRequest (报"跨分片重号加 --source"), **不合并**。
        let err = native_query::resolve_query(&conn, Some("dup"), None, 10, 0).unwrap_err();
        assert!(err.to_string().contains("分片"), "跨分片歧义 → 报错列分片, got: {err}");
        // 展开 --source message_0.db → 只该分片 2 子项 (不含 message_5.db 的)。
        let r = native_query::resolve_query(&conn, Some("dup"), Some("message_0.db"), 10, 0).unwrap();
        assert_eq!(r.data.len(), 2, "--source message_0.db → 只 2 子项");
        assert_eq!(r.data[0]["data_desc"], "d0", "取 message_0.db 的内容, 非 message_5.db");
    }

    #[test]
    fn config_load_or_default_reads_observability_and_falls_back() {
        // 临时 config.toml (只 [observability]) → load_or_default 应读到自定义值 (证 config 真被读)。
        let dir = std::env::temp_dir().join(format!("nativecli-cfgtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[observability]\nlog_level = \"debug\"\nlog_dir = 'X:/custom/logs'\n",
        )
        .unwrap();
        let cfg = native_core::config::load_or_default(&path);
        assert_eq!(cfg.observability.log_level, "debug", "读到自定义 log_level");
        assert_eq!(cfg.observability.log_dir, "X:/custom/logs", "读到自定义 log_dir");
        // 缺文件 → 默认兜底 (不报错)。
        let cfg2 = native_core::config::load_or_default(&dir.join("nope.toml"));
        assert_eq!(cfg2.observability.log_level, "info", "缺文件→默认 info");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn links_query_joins_message_app_url() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "L1", "convX", "wxid_s", 9000, "看这个");
        // L1 的 message_app 带 url (app_type 5 = 链接)。
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id, title, url) \
             VALUES ('a','msg','L1',5,0,'acc','好文章','https://example.com/a')",
            [],
        )
        .unwrap();
        // 另一条 message_app 无 url → 不计入。
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id) \
             VALUES ('a','msg','L2',49,0,'acc')",
            [],
        )
        .unwrap();
        let r = native_query::links_query(&conn, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(1), "只有 L1 有 url");
        assert_eq!(r.data.len(), 1);
        assert_eq!(r.data[0]["create_time"], 9000, "create_time 来自 JOIN 的 message");
        assert_eq!(r.data[0]["url"], "https://example.com/a", "url");
        assert_eq!(r.data[0]["type_label"], "链接", "type_label 预组进 json");
        assert_eq!(native_query::app_type_label(5), "链接");
        assert_eq!(native_query::app_type_label(51), "视频号");
        assert!(native_query::app_type_label(99).starts_with("类型"), "未知码原样报数");
    }

    #[test]
    fn files_query_joins_message_app_file() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "F1", "convY", "wxid_s", 8800, "文件");
        // F1 的 message_app 是文件 (file_ext 非空)。
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id, title, file_ext, file_size) \
             VALUES ('a','msg','F1',6,0,'acc','报表.xlsx','xlsx',2097152)",
            [],
        )
        .unwrap();
        // 无 file_ext → 不计。
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id) \
             VALUES ('a','msg','F2',5,0,'acc')",
            [],
        )
        .unwrap();
        let r = native_query::files_query(&conn, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(1), "只有 F1 有 file_ext");
        assert_eq!(r.data[0]["create_time"], 8800, "create_time 来自 JOIN");
        assert_eq!(r.data[0]["file_ext"], "xlsx");
        assert_eq!(r.data[0]["file_size"], 2_097_152);
        assert_eq!(human_size(2_097_152), "2 MB");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(3072), "3 KB");
    }

    // 用已算好校验位的真·身份证形号 (非真人): 110101199003070011 末位=1, 11010119900307002X 末位=X。
    #[test]
    fn pii_helpers_checksum_mobile_mask() {
        // 手机号段判定
        assert!(native_query::is_cn_mobile("13800138000"), "138 号段合法");
        assert!(!native_query::is_cn_mobile("12800138000"), "第二位 2 不是号段");
        assert!(!native_query::is_cn_mobile("1380013800"), "10 位不算");
        // 身份证校验位: 真号过, 改末位即挂
        assert!(native_query::id_checksum_ok("110101199003070011"), "校验位正确");
        assert!(!native_query::id_checksum_ok("110101199003070012"), "末位错→校验失败");
        assert!(native_query::id_checksum_ok("11010119900307002X"), "末位 X 型校验通过");
        assert!(
            native_query::id_checksum_ok("11010119900307002x"),
            "小写 x 也认 (to_ascii_uppercase)"
        );
        // 打码
        assert_eq!(native_query::mask_pii("手机号", "13800138000"), "138****8000");
        assert_eq!(
            native_query::mask_pii("身份证", "110101199003070011"),
            "1101**********0011"
        );
        // 极大数字串扫描: 逗号分隔的两个手机都能扫到 (无正则边界消耗坑)
        let hits = native_query::scan_pii_in_text("联系13800138000，13900139000", true, false);
        assert_eq!(hits.len(), 2, "逗号分隔两号都命中");
    }

    #[test]
    fn pii_scan_only_text_msgtype_and_checksum() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // A(文本): 真手机 + 真身份证 → 1 手机 + 1 身份证
        insert_test_message(
            &conn,
            "A",
            "convX",
            "wxid_a",
            9000,
            "电话13800138000 身份证110101199003070011",
        );
        // B(文本): 校验位错的 18 位数字 → 不该命中
        insert_test_message(&conn, "B", "convX", "wxid_b", 8000, "号码110101199003070012 无效");
        // D(文本): X 结尾身份证 → 命中 (走 17位+X 分支)
        insert_test_message(&conn, "D", "convX", "wxid_d", 7000, "证件11010119900307002X");
        // C(图片 msg_type=3): text_content 是 XML 含手机号形数字 → 必须被类型过滤排除
        conn.execute(
            "INSERT INTO message \
             (account_id_sha, source, source_native_id, conv_id_sha, server_id, create_time, \
              sort_seq, status, msg_type, msg_type_name, local_type_raw, sender_wxid_sha, \
              is_chatroom, text_content_sha, text_content_len, raw_xml_present, decode_kind, \
              account_id, conv_id, sender_wxid, text_content) \
             VALUES ('a','msg','C','cs',1,6000,1,0,3,'图片',3,'ss',1,'ts',20,1,'plain','acc','convX','wxid_c', \
                     '<img cdnurl=\"13800138000000\"/>')",
            [],
        )
        .unwrap();
        let (msgs, phone_total, id_total, rows) = native_query::query_pii_scan(&conn, PiiKind::All, 10).unwrap();
        assert_eq!(msgs, 2, "只 A、D 命中 (B 校验挂, C 是图片被类型过滤)");
        assert_eq!(phone_total, 1, "只 A 有手机 (C 的图片 XML 不扫)");
        assert_eq!(id_total, 2, "A 数字身份证 + D 的 X 身份证");
        assert_eq!(rows.len(), 3, "2 消息共 3 条命中 (A 手机+身份证, D 身份证)");
        // 时间倒序: A(9000) 在最前
        assert_eq!(rows[0].0, 9000);
        // 只扫手机
        let (_, p_only, i_only, _) = native_query::query_pii_scan(&conn, PiiKind::Phone, 10).unwrap();
        assert_eq!(p_only, 1);
        assert_eq!(i_only, 0, "kind=phone 不扫身份证");
    }

    /// R16-5 复审 (Claude 对抗审观察): 同 `create_time` 跨消息命中的**次键 tiebreak** (source, source_native_id DESC) ——
    /// 锁死冷查 ORDER BY 补的次键, 防未来改动静默打破冷热 parity。原 `pii_scan_only_text_msgtype_and_checksum` 的
    /// create_time 全不同 (9000/8000/7000), tie 分支一次没跑到; 本测试专造同秒。热查 hot_pii_scan 用同键同向 sort, 故此
    /// 冷侧序即冷热共同全序。
    #[test]
    fn pii_scan_tiebreak_same_create_time_orders_by_source_native_id() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // 两条同 create_time(5000) 文本消息各带一手机 → source 相同 ('msg'), 次键落 source_native_id DESC。
        insert_test_message(&conn, "Z1", "convT", "wxid_1", 5000, "电话13800138000");
        insert_test_message(&conn, "Z2", "convT", "wxid_2", 5000, "电话13900139000");
        let (_, _, _, rows) = native_query::query_pii_scan(&conn, PiiKind::Phone, 10).unwrap();
        assert_eq!(rows.len(), 2, "两条各一手机命中");
        assert_eq!(rows[0].0, 5000);
        assert_eq!(rows[1].0, 5000);
        // source_native_id DESC: "Z2" > "Z1" → Z2(wxid_2) 在前 (与热查 hot_pii_scan sort 同键同向 → 冷热同序)。
        assert_eq!(
            rows[0].2.as_deref(),
            Some("wxid_2"),
            "同秒次键 source_native_id DESC → Z2 在前"
        );
        assert_eq!(rows[1].2.as_deref(), Some("wxid_1"));
    }

    #[test]
    fn thread_query_joins_reply_and_quote() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // R1: 引用回复 (reply 消息行 + message_app 带 refer_svrid)。
        insert_test_message(&conn, "R1", "convZ", "wxid_replier", 5000, "<xml appmsg>");
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id, \
              title, refer_svrid, refer_type, refer_content) \
             VALUES ('a','msg','R1',57,0,'acc','链接买不了','7283910293847',1,'原始被引商品文案')",
            [],
        )
        .unwrap();
        // R2: 普通卡片, 无 refer_svrid → 不算引用回复。
        insert_test_message(&conn, "R2", "convZ", "wxid_x", 4000, "<xml>");
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id, title, url) \
             VALUES ('a','msg','R2',5,0,'acc','某链接','https://x')",
            [],
        )
        .unwrap();
        let r = native_query::thread_query(&conn, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(1), "只 R1 是引用回复 (R2 无 refer_svrid)");
        assert_eq!(r.data.len(), 1);
        assert_eq!(r.data[0]["create_time"], 5000, "reply create_time 来自 JOIN 的 message");
        assert_eq!(r.data[0]["sender_wxid"], "wxid_replier", "reply 发送人");
        assert_eq!(r.data[0]["reply_text"], "链接买不了", "reply 正文 = a.title");
        assert_eq!(
            r.data[0]["quoted_text"], "原始被引商品文案",
            "被引原文 = a.refer_content"
        );
        // 预览工具: 空/换行处理
        assert_eq!(preview_line(None, 10, "(空)"), "(空)");
        assert_eq!(preview_line(Some("a\nb"), 10, "(空)"), "a b");
    }

    #[test]
    fn finder_query_orders_by_visit_time_desc() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let ins = |nid: &str, vt: i64, name: &str, owner: &str| {
            conn.execute(
                "INSERT INTO finder_visit \
                 (account_id_sha, source, source_native_id, owner_username_sha, visit_time, \
                  account_id, owner_username, name, profile_url) \
                 VALUES ('a','general',?1,'os',?2,'acc',?3,?4,'https://channels.weixin.qq.com/x')",
                rusqlite::params![nid, vt, owner, name],
            )
            .unwrap();
        };
        ins("F1", 1_783_512_264, "莉莉在目", "wxid_older");
        ins("F2", 1_783_531_859, "一造物社DIY", "wxid_newer");
        let r = native_query::finder_query(&conn, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(2));
        assert_eq!(
            r.data[0]["visit_time"], 1_783_531_859_i64,
            "最新访问在前 (visit_time DESC)"
        );
        assert_eq!(r.data[0]["name"], "一造物社DIY", "name");
        assert_eq!(r.data[0]["owner_username"], "wxid_newer", "owner_username");
        assert!(
            !r.data[0]["visit_date"].as_str().unwrap_or_default().is_empty(),
            "date(visit_time,unixepoch) 非空"
        );
        // 真总数不被 limit 截断
        let few = native_query::finder_query(&conn, 1, 0).unwrap();
        assert_eq!(few.meta.total_count, Some(2), "真总数仍 2");
        assert_eq!(few.data.len(), 1);
    }

    #[test]
    fn biz_query_filters_gh_and_joins_title() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // B1: gh_ 公众号图文 (message + message_app 带 title)。create_time 毫秒。
        insert_test_message(&conn, "B1", "gh_abc", "gh_abc", 1_700_000_000_000, "<xml appmsg>");
        conn.execute(
            "INSERT INTO message_app \
             (account_id_sha, source, source_native_id, app_type, media_count, account_id, title) \
             VALUES ('a','msg','B1',5,0,'acc','公众号文章标题')",
            [],
        )
        .unwrap();
        // B2: gh_ 纯文本推送 (无图文卡片)。
        insert_test_message(&conn, "B2", "gh_xyz", "gh_xyz", 1_600_000_000_000, "纯文本推送");
        // N1: 非 gh_ 普通好友消息 → 必须排除。
        insert_test_message(&conn, "N1", "wxid_friend", "wxid_friend", 1_500_000_000_000, "普通消息");
        let r = native_query::biz_query(&conn, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(2), "只 gh_ 会话 (B1、B2), N1 排除");
        assert_eq!(r.data.len(), 2);
        assert_eq!(r.data[0]["gh_id"], "gh_abc", "最新 (B1, 毫秒时间倒序) 在前");
        assert_eq!(r.data[0]["title"], "公众号文章标题", "图文标题来自 message_app");
        assert!(
            !r.data[0]["date"].as_str().unwrap_or_default().is_empty(),
            "date(create_time/1000) 非空"
        );
        assert_eq!(r.data[1]["gh_id"], "gh_xyz");
        assert!(r.data[1]["title"].is_null(), "纯文本无图文卡片 → title None");
    }

    /// **冷查给了 `--per-conv` 要当场报错, 不许静默吞**(独立复审的 P2)。
    ///
    /// `new` 默认 `--mode auto`, 给了 `--l1-db` 就走冷查, 而冷查那条路根本不读这个参数 ——
    /// 用户写了参数、命令正常返回、行为一点没变。这个仓库为同一类毛病做过硬报错
    /// (非热查命令上给 `--mode hot` 直接拒), 这里照办。
    #[tokio::test]
    async fn per_conv_in_cold_mode_is_refused_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("cold.db");
        {
            let conn = rusqlite::Connection::open(&l1).unwrap();
            native_core::storage::init_l1_schema(&conn).unwrap();
        }
        let args = |per_conv: usize| super::NewArgs {
            target: super::QueryTarget {
                l1_db: Some(l1.to_string_lossy().into_owned()),
                mode: native_query::QueryMode::Cold,
                wxid: None,
                wechat_data_dir: None,
                account: None,
            },
            limit: 5,
            per_conv,
            reset: false,
            no_advance: true,
            format: super::OutFormat::Json,
        };
        // 不给参数: 冷查照常跑得通(空库, 没新消息)。
        assert!(
            super::cmd_new(&args(0)).await.is_ok(),
            "不给 --per-conv 时冷查该照常运行"
        );
        // 给了参数: 必须报错, 而不是跑通了但参数没生效。
        let err = super::cmd_new(&args(3)).await.expect_err("冷查给了 --per-conv 该拒");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--per-conv") && msg.contains("--mode hot"),
            "提示得说清它只对实时模式生效、以及怎么改: {msg}"
        );
    }

    /// **`--source` 要按"整个分片"算, 不是精确等值**(独立复审 656477c 的 P3, 它在真库 520 万行上量的)。
    ///
    /// `source` 列有两种形状: 消息和解码失败那类是 `message_1.db`(518 万行), 水位那类是
    /// `message_1.db|Msg_<表名>`(1.6 万行)。精确等值只匹配前一种 —— `--source message_0.db` 会
    /// **静默漏掉**同一分片的全部水位记录, 而 help 和 OpenAPI 都写着"只看某个源库",
    /// 读起来是"这个库的全部"。
    #[test]
    fn msgraw_source_matches_the_whole_shard_not_just_exact_equality() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let ins = |src: &str, nid: &str, action: &str| {
            conn.execute(
                "INSERT INTO raw_payload_archive                  (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)                  VALUES ('a',?1,?2,'message',?3,0,111,'{}')",
                rusqlite::params![src, nid, action],
            )
            .unwrap();
        };
        ins("message_0.db", "Msg_a:1", "create"); // 消息: source 就是库名
        ins("message_0.db|Msg_a", "cursor:x", "cursor_update"); // 水位: 库名|表名
        ins("message_5.db", "Msg_b:1", "create"); // 别的分片, 不该被带进来

        let r = native_query::msgraw_query(&conn, None, Some("message_0.db"), 10, 0).unwrap();
        assert_eq!(
            r.meta.total_count,
            Some(2),
            "同一分片的两种形状都得算进来 —— 精确等值会静默漏掉水位那一类"
        );
        let srcs: Vec<&str> = r.data.iter().map(|x| x["source"].as_str().unwrap_or("")).collect();
        assert!(srcs.iter().any(|s| s.contains('|')), "水位那条得在: {srcs:?}");
        assert!(
            !srcs.iter().any(|s| s.starts_with("message_5")),
            "别的分片不许被带进来: {srcs:?}"
        );
    }

    /// **`--source` 从命令行到内核那根线**(独立复审 656477c 的 P2)。
    ///
    /// 上面那条只调 `native_query::msgraw_query`, **不经过 `cmd_msgraw`**。审查方把
    /// `args.source.as_deref()` 换成 `None`, 全工作区一条不红 —— 内核的过滤有守卫, 皮到内核那根线没有。
    /// 真回归的症状是: 用户 `--source message_5.db` 想钉死一条, 静默拿回全部分片的行, 而
    /// `total_count` 跟着一起说谎 —— 溯源命令给错答案。
    ///
    /// 这条走 `cmd_msgraw`(命令入口本身), 用退出码分辨: 给了分片而那个分片没有 → NOT_FOUND(3);
    /// 线断了的话会拿到全部行 → 退出码 0, 当场红。
    #[test]
    fn msgraw_source_flag_is_actually_wired_to_the_query() {
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("wired.db");
        {
            let conn = rusqlite::Connection::open(&l1).unwrap();
            native_core::storage::init_l1_schema(&conn).unwrap();
            conn.execute(
                "INSERT INTO raw_payload_archive                  (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)                  VALUES ('a','message_0.db','Msg_abc:1','message','create',0,111,'{}')",
                [],
            )
            .unwrap();
        }
        let args = |src: Option<&str>| super::MsgrawArgs {
            target: super::QueryTarget {
                l1_db: Some(l1.to_string_lossy().into_owned()),
                mode: native_query::QueryMode::Cold,
                wxid: None,
                wechat_data_dir: None,
                account: None,
            },
            native_id: None,
            source: src.map(str::to_string),
            limit: 20,
            format: super::OutFormat::Json,
        };
        // 库里只有 message_0.db 那一条。
        assert!(
            super::cmd_msgraw(&args(Some("message_0.db"))).is_ok(),
            "对得上的分片该查得到"
        );
        let miss = super::cmd_msgraw(&args(Some("message_9.db")));
        assert!(
            miss.is_err(),
            "给了库里没有的分片就该 NOT_FOUND —— 这条不红就说明 --source 根本没传下去"
        );
    }

    /// **同一个 native-id 在两个分片里各有一条 —— 结果得认得出谁是谁**(外部复审 P2)。
    ///
    /// `source_native_id` 形如 `Msg_<表名>:<行号>`, **不带分片**。而同名会话表可以同时存在于
    /// 多个分片 —— 真库实测 700 张同名 `Msg_` 表同时在 `message_0.db` 和 `message_5.db`。
    /// 光给 `--native-id` 会返回多条, 而原先结果里**没有任何字段**能告诉用户哪条来自哪个分片,
    /// 而这个命令干的就是溯源。给了 `source` 列才认得出, 再给 `--source` 就能直接钉死一条。
    #[test]
    fn msgraw_tells_which_shard_each_row_came_from() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let ins = |src: &str, nid: &str| {
            conn.execute(
                "INSERT INTO raw_payload_archive                  (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json)                  VALUES ('a',?1,?2,'message','create',0,111,'{}')",
                rusqlite::params![src, nid],
            )
            .unwrap();
        };
        // 同一个会话表同时在两个分片里, native-id 一模一样。
        ins("message_0.db", "Msg_abc:7");
        ins("message_5.db", "Msg_abc:7");

        let both = native_query::msgraw_query(&conn, Some("Msg_abc:7"), None, 10, 0).unwrap();
        assert_eq!(both.meta.total_count, Some(2), "两个分片各一条, 都该返回");
        let shards: Vec<&str> = both.data.iter().map(|r| r["source"].as_str().unwrap_or("")).collect();
        assert!(
            shards.contains(&"message_0.db") && shards.contains(&"message_5.db"),
            "结果里必须带分片名, 否则两条长得一模一样, 用户认不出: {shards:?}"
        );

        // 给了分片就只剩一条。
        let one = native_query::msgraw_query(&conn, Some("Msg_abc:7"), Some("message_5.db"), 10, 0).unwrap();
        assert_eq!(one.meta.total_count, Some(1), "钉死分片后只该剩一条");
        assert_eq!(one.data[0]["source"], "message_5.db");

        // 只给分片不给 native-id 也得能过滤 (两个条件各自独立)。
        let by_shard = native_query::msgraw_query(&conn, None, Some("message_0.db"), 10, 0).unwrap();
        assert_eq!(by_shard.meta.total_count, Some(1), "只按分片过滤也要算数");
        assert_eq!(by_shard.data[0]["source"], "message_0.db");
    }

    #[test]
    fn msgraw_query_filters_by_native_id() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let ins = |nid: &str, action: &str, seq: i64, payload: &str| {
            conn.execute(
                "INSERT INTO raw_payload_archive \
                 (account_id_sha, source, source_native_id, event_type, event_action, event_seq, ingest_time, payload_json) \
                 VALUES ('a','msg',?1,'message',?2,?3,111,?4)",
                rusqlite::params![nid, action, seq, payload],
            )
            .unwrap();
        };
        ins("Msg_1:1", "create", 0, r#"{"conv_id":"c1","msg_type":1}"#);
        ins("Msg_1:1", "update", 0, r#"{"conv_id":"c1","msg_type":1,"upd":true}"#);
        ins("Msg_2:1", "create", 0, r#"{"conv_id":"c2"}"#);
        // 全表
        let r = native_query::msgraw_query(&conn, None, None, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(3), "全表 3 条");
        assert_eq!(r.data.len(), 3);
        // 精确定位 Msg_1:1 (create+update 两条)
        let r1 = native_query::msgraw_query(&conn, Some("Msg_1:1"), None, 10, 0).unwrap();
        assert_eq!(r1.meta.total_count, Some(2), "Msg_1:1 有 create + update 两条");
        assert!(
            r1.data.iter().all(|row| row["source_native_id"] == "Msg_1:1"),
            "全是 Msg_1:1"
        );
        assert!(
            r1.data[0]["payload"].get("conv_id").is_some(),
            "payload 解析后含 conv_id 字段"
        );
        // 不存在的 id → 0
        let r0 = native_query::msgraw_query(&conn, Some("Msg_9:9"), None, 10, 0).unwrap();
        assert_eq!(r0.meta.total_count, Some(0));
        assert!(r0.data.is_empty());
    }

    #[test]
    fn events_query_filters_type10000_and_sys_type() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let sys = |nid: &str, ct: i64, stype: &str, text: &str| {
            conn.execute(
                "INSERT INTO message \
                 (account_id_sha, source, source_native_id, conv_id_sha, server_id, create_time, \
                  sort_seq, status, msg_type, msg_type_name, local_type_raw, sender_wxid_sha, \
                  is_chatroom, text_content_sha, text_content_len, raw_xml_present, decode_kind, \
                  account_id, conv_id, sender_wxid, sys_type, text_content) \
                 VALUES ('a','msg',?1,'cs',1,?2,1,0,10000,'SYSTEM',10000,'ss',1,'ts',0,0,'plain','acc','g@chatroom','sysmsg',?3,?4)",
                rusqlite::params![nid, ct, stype, text],
            )
            .unwrap();
        };
        sys("E1", 3000, "member_join", "\"小A\"邀请\"小B\"加入了群聊");
        sys("E2", 2000, "revoke", "\"小C\"撤回了一条消息");
        // 普通文本消息 → 不算系统事件。
        insert_test_message(&conn, "N1", "g@chatroom", "wxid_x", 1000, "普通聊天");
        // 全部系统事件
        let r = native_query::events_query(&conn, None, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(2), "只 2 条 type10000 (N1 是普通消息排除)");
        assert_eq!(r.data[0]["create_time"], 3000, "时间倒序, member_join 最新在前");
        assert!(
            !r.data[0]["date"].as_str().unwrap_or_default().is_empty(),
            "date 列非空"
        );
        assert_eq!(r.data[0]["sys_type"], "member_join");
        assert_eq!(r.data[0]["label"], "入群", "label (sys_type_label) 预组进 json");
        // 按类型过滤
        let r1 = native_query::events_query(&conn, Some("revoke"), 10, 0).unwrap();
        assert_eq!(r1.meta.total_count, Some(1), "只 1 条 revoke");
        assert_eq!(r1.data[0]["text"], "\"小C\"撤回了一条消息");
        // 标签映射
        assert_eq!(native_query::sys_type_label("member_join"), "入群");
        assert_eq!(native_query::sys_type_label("revoke"), "撤回");
        assert_eq!(native_query::sys_type_label("未知码"), "未知码", "未知原样");
    }

    #[test]
    fn exec_readonly_guard_rejects_writes() {
        // 放行只读
        assert!(is_readonly_sql("SELECT * FROM message"));
        assert!(is_readonly_sql("  select 1  "));
        assert!(is_readonly_sql("SELECT count(*) FROM message;"), "尾分号可接受");
        assert!(is_readonly_sql("WITH x AS (SELECT 1) SELECT * FROM x"));
        assert!(is_readonly_sql("EXPLAIN SELECT 1"));
        // 挡掉写 / 危险 / 多语句
        assert!(!is_readonly_sql("DELETE FROM message"), "写操作拒绝");
        assert!(!is_readonly_sql("UPDATE message SET x=1"), "写操作拒绝");
        assert!(!is_readonly_sql("DROP TABLE message"), "DDL 拒绝");
        assert!(!is_readonly_sql("PRAGMA writable_schema=1"), "PRAGMA 拒绝");
        assert!(!is_readonly_sql("ATTACH DATABASE 'x' AS y"), "ATTACH 拒绝");
        assert!(!is_readonly_sql("SELECT 1; DROP TABLE message"), "多语句拒绝");
        assert!(!is_readonly_sql("SELECT 1; DELETE FROM message;"), "多语句拒绝");
        assert!(!is_readonly_sql("SELECTX"), "非 SELECT 关键字前缀拒绝");
    }

    #[test]
    fn exec_query_returns_cols_rows_and_truncates() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "X1", "cA", "wxid_1", 100, "一");
        insert_test_message(&conn, "X2", "cA", "wxid_2", 200, "二");
        insert_test_message(&conn, "X3", "cB", "wxid_3", 300, "三");
        // 动态列: 分组统计
        let (cols, rows, trunc) = run_exec_query(
            &conn,
            "SELECT conv_id, count(*) AS n FROM message GROUP BY conv_id ORDER BY conv_id",
            100,
        )
        .unwrap();
        assert_eq!(cols, vec!["conv_id".to_string(), "n".to_string()], "列名动态取回");
        assert_eq!(rows.len(), 2, "cA + cB 两组");
        assert!(!trunc);
        // cA 有 2 条
        assert_eq!(sql_value_display(&rows[0][0]), "cA");
        assert_eq!(sql_value_display(&rows[0][1]), "2");
        // max_rows 截断
        let (_c, r2, trunc2) = run_exec_query(&conn, "SELECT source_native_id FROM message", 2).unwrap();
        assert_eq!(r2.len(), 2, "max_rows=2 只取 2 行");
        assert!(trunc2, "被截断");
    }

    #[test]
    fn extract_matches_per_kind() {
        // url: 两个链接, 消息内去重顺序
        let ure = native_query::extract_regex(ExtractKind::Url).unwrap().unwrap();
        assert_eq!(
            native_query::extract_matches("看 https://a.com/x 和 http://b.cn 哦", ExtractKind::Url, Some(&ure)),
            vec!["https://a.com/x".to_string(), "http://b.cn".to_string()]
        );
        // email
        let ere = native_query::extract_regex(ExtractKind::Email).unwrap().unwrap();
        assert_eq!(
            native_query::extract_matches("联系 a.b@c.com 谢谢", ExtractKind::Email, Some(&ere)),
            vec!["a.b@c.com".to_string()]
        );
        // amount: 后缀 元 型
        let are = native_query::extract_regex(ExtractKind::Amount).unwrap().unwrap();
        let am = native_query::extract_matches("押金30元 包两餐", ExtractKind::Amount, Some(&are));
        assert!(am.iter().any(|s| s == "30元"), "抽到 30元, 实得 {am:?}");
        // phone/idcard 不用正则, 走手写扫描
        assert!(native_query::extract_regex(ExtractKind::Phone).unwrap().is_none());
        assert_eq!(
            native_query::extract_matches("电话13800138000找我", ExtractKind::Phone, None),
            vec!["13800138000".to_string()]
        );
        assert_eq!(native_query::extract_kind_label(ExtractKind::Url), "链接");
    }

    #[test]
    fn extract_query_url_end_to_end() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "U1", "cA", "wxid_1", 300, "点 https://x.com/buy 看看");
        insert_test_message(&conn, "U2", "cA", "wxid_2", 200, "没链接的普通消息");
        let (msgs, total, rows) = native_query::query_extract(&conn, ExtractKind::Url, 10, 0).unwrap();
        assert_eq!(msgs, 1, "只 U1 有 url (LIKE %http% 预筛 + 正则)");
        assert_eq!(total, 1);
        assert_eq!(rows[0].4, "https://x.com/buy");
        assert_eq!(rows[0].2, "cA", "conv_id");
    }

    #[test]
    fn new_query_watermark_and_preview() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "N1", "cA", "wxid_1", 100, "老消息");
        insert_test_message(&conn, "N2", "cA", "wxid_2", 200, "新消息");
        insert_test_message(&conn, "N3", "cB", "wxid_3", 300, "更新的");
        // 水位 rowid>1 → 只 N2(rowid2), N3(rowid3); 单账号库 account_sha=None (无显式谓词)。rowid 序=插入序=此处 ct 序。
        let r = native_query::new_query(&conn, 1, 10, None).unwrap();
        assert_eq!(r.data.len(), 2, "水位后只 2 条");
        assert_eq!(r.data[0]["create_time"], 200, "rowid 升序 N2 在前");
        assert_eq!(r.data[1]["create_time"], 300);
        // limit 从头 (rowid>0)
        let r2 = native_query::new_query(&conn, 0, 2, None).unwrap();
        assert_eq!(r2.data.len(), 2, "limit=2");
        assert_eq!(r2.data[0]["create_time"], 100, "从头 N1 先");
        // 正文预览: XML→[类型], 文本→截断, None→[类型]
        assert_eq!(msg_body_preview(Some("图片"), Some("<?xml v=1?>"), 40), "[图片]");
        assert_eq!(msg_body_preview(Some("文本"), Some("你好\n世界"), 40), "你好 世界");
        assert_eq!(msg_body_preview(Some("语音"), None, 40), "[语音]");
        // 水位文件路径: 同 (库,账号) 确定, 异库/异账号不同 (codex-R8 P1)
        assert_eq!(new_watermark_path("a.db", None), new_watermark_path("a.db", None));
        assert_ne!(new_watermark_path("a.db", None), new_watermark_path("b.db", None));
        assert_ne!(
            new_watermark_path("a.db", Some("shaA")),
            new_watermark_path("a.db", Some("shaB"))
        );
    }

    /// codex-R8 P1 防回归: **同 create_time 多条 + rowid 游标跨批不丢** (真库单毫秒挤 282 > limit=50 → 原 create_time
    /// 游标批边界永久跳过同毫秒剩余)。rowid 游标 `rowid > wm` 唯一且随 ingest 单调 → 精确续批不漏。
    #[test]
    fn new_query_rowid_cursor_no_skip_on_dup_create_time() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        insert_test_message(&conn, "D0", "cA", "wxid_0", 400, "早"); // rowid1, 早于同毫秒组
        insert_test_message(&conn, "D1", "cA", "wxid_1", 500, "同毫秒一"); // rowid2, 三条同 create_time=500
        insert_test_message(&conn, "D2", "cA", "wxid_2", 500, "同毫秒二"); // rowid3
        insert_test_message(&conn, "D3", "cA", "wxid_3", 500, "同毫秒三"); // rowid4
                                                                           // 第一批 limit=2 从头 (rowid>0): 取 rowid1,2 = 早+同毫秒一 —— 批边界正落在 ct=500 组内
        let r1 = native_query::new_query(&conn, 0, 2, None).unwrap();
        assert_eq!(r1.data.len(), 2);
        assert!(r1.meta.has_more, "读满 limit → 保守报还有");
        let wm_rid = r1.meta.summary.as_ref().unwrap()["scanned_rowid"].as_i64().unwrap();
        assert_eq!(wm_rid, 2, "本批末条 rowid=2");
        // 第二批 rowid>2 续: 同 ct=500 的剩余两条 (二/三) **不被跳过** —— create_time 游标 `>500` 会全跳掉, 这是回归靶
        let r2 = native_query::new_query(&conn, wm_rid, 10, None).unwrap();
        let texts: Vec<&str> = r2.data.iter().filter_map(|r| r["text_content"].as_str()).collect();
        assert_eq!(r2.data.len(), 2, "同毫秒剩余 2 条不丢, 实得 {texts:?}");
        assert!(
            texts.contains(&"同毫秒二") && texts.contains(&"同毫秒三"),
            "边界同 ct 消息全取到, 实得 {texts:?}"
        );
        assert!(!r2.meta.has_more, "取完到底");
    }

    #[test]
    fn followups_last_message_inbound() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        // insert_test_message 的 account_id='acc' = "我"; sender='acc' 是我发, 别的是对方。
        // cA: 我先说→对方后说 → 末条对方 = 漏回
        insert_test_message(&conn, "A1", "cA", "acc", 100, "我问");
        insert_test_message(&conn, "A2", "cA", "wxid_friend", 200, "对方答, 等我回");
        // cB: 对方先说→我后回 → 末条是我 = 不算漏回
        insert_test_message(&conn, "B1", "cB", "wxid_friend", 100, "对方问");
        insert_test_message(&conn, "B2", "cB", "acc", 200, "我回了");
        // cC: 对方说(t=100)→之后来了系统消息(t=200) → 末条非系统仍是对方 = 漏回
        insert_test_message(&conn, "C1", "cC", "wxid_friend", 100, "对方最后说");
        conn.execute(
            "INSERT INTO message \
             (account_id_sha, source, source_native_id, conv_id_sha, server_id, create_time, \
              sort_seq, status, msg_type, msg_type_name, local_type_raw, sender_wxid_sha, \
              is_chatroom, text_content_sha, text_content_len, raw_xml_present, decode_kind, \
              account_id, conv_id, sender_wxid, sys_type, text_content) \
             VALUES ('a','msg','C2','cs',1,200,1,0,10000,'SYSTEM',10000,'ss',1,'ts',0,0,'plain','acc','cC','sysmsg','revoke','撤回了')",
            [],
        )
        .unwrap();
        let r = native_query::followups_query(&conn, false, 10, 0).unwrap();
        assert_eq!(r.meta.total_count, Some(2), "cA + cC 漏回 (cB 我回了不算)");
        // 按末条时间倒序: cA(200) 在 cC(100·系统200不计) 前
        assert_eq!(r.data[0]["conv_id"], "cA", "cA 末条时间 200 最新");
        assert_eq!(r.data[0]["last_sender_wxid"], "wxid_friend", "末条是对方发的");
        assert_eq!(r.data[1]["conv_id"], "cC", "cC 末条非系统是对方(t=100)");
        assert!(r.data.iter().all(|row| row["conv_id"] != "cB"), "cB 不在漏回里");
        // private_only: cA/cB/cC 都是群聊 (insert_test_message is_chatroom=1) → 私聊过滤后 0
        let r_priv = native_query::followups_query(&conn, true, 10, 0).unwrap();
        assert_eq!(
            r_priv.meta.total_count,
            Some(0),
            "测试消息全 is_chatroom=1, 仅私聊过滤后无"
        );
        assert!(r_priv.data.is_empty());
    }

    #[test]
    fn wipe_targets_respect_keep_keys_and_stay_in_base() {
        let base = Path::new("C:/x/msgvestige");
        let all = wipe_fixed_targets(base, false);
        assert!(
            all.iter().any(|(p, _, k)| *k && p.ends_with("keys.enc")),
            "默认含 key 缓存"
        );
        assert!(
            all.iter().any(|(p, _, k)| *k && p.ends_with("image_keys.enc")),
            "默认含图片 key 缓存"
        );
        let kept = wipe_fixed_targets(base, true);
        assert!(kept.iter().all(|(_, _, k)| !*k), "keep_keys 后不含 key 缓存项");
        // **别写死数字**: 原来是 `kept.len() + 1`, 加了 image_keys.enc 之后就红了
        // (那次我只做了真跑验证、没跑测试套, 红了两轮才发现)。
        // 改成按"标了 is_key 的项数"算 —— 以后再加/减 key 类目标, 这条断言自动跟上,
        // 而它要守的性质 (keep_keys 恰好且只少掉 key 类) 一点没放松。
        let key_count = all.iter().filter(|(_, _, k)| *k).count();
        assert!(key_count >= 2, "至少两项 key 缓存 (keys.enc + image_keys.enc)");
        assert_eq!(
            all.len(),
            kept.len() + key_count,
            "keep_keys 恰少掉全部 key 类目标, 不多不少"
        );
        // 所有目标都在 base 之下 (绝不越界删外部)
        assert!(
            all.iter().all(|(p, _, _)| p.starts_with(base)),
            "全在 msgvestige 目录下"
        );
    }

    /// 覆盖守卫 (引擎设计 §6/§8): `init_l1_schema` 建的每张 L1 表, 要么在查询引擎登记表 (REGISTRY)、
    /// 要么被某手写命令覆盖、要么显式豁免 (infra/导出专用)。以后 storage.rs 新增 L1 表却没配任何
    /// 命令 → 本测试红。地板守卫: 只抓"全新表零命令", 抓不到同表派生新视图漂移 (那靠人审)。
    #[test]
    fn every_l1_table_has_command_or_exempt() {
        use std::collections::BTreeSet;
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        native_core::storage::init_l1_schema(&conn).unwrap();
        let actual: BTreeSet<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();

        // 1. 引擎登记表覆盖 (纯"名词→单表 SELECT"; REGISTRY 已移 native-query::engine, §6②)。
        let registry: BTreeSet<&str> = native_query::REGISTRY.iter().map(|c| c.table).collect();

        // 2. 手写命令覆盖 (逻辑超出单表 SELECT: 多表合并/游标/反向 JOIN/聚合)。右侧注明服务它的命令。
        let handwritten: BTreeSet<&str> = [
            "chatroom_member",      // members
            "favorite",             // favorites (默认列表 + -q)
            "finder_visit",         // finder
            "friend_verify",        // friend-requests
            "group_pay",            // money (query_group_pays)
            "message",              // messages (+ 大量命令的 JOIN 基表)
            "message_app",          // links / files / biz / thread
            "message_call",         // calls
            "message_forward_item", // thread (合并转发)
            "message_mention",      // mentions
            "moment",               // moments (默认动态)
            "person",               // contacts (keyset 游标)
            "red_envelope",         // money (query_red_envelopes)
            "session",              // sessions
            "transfer",             // money (query_transfers)
        ]
        .into_iter()
        .collect();

        // 3. 显式豁免 (init_l1_schema 建但非 L1 查询面: infra/审计/导出专用)。
        let exempt: BTreeSet<&str> = [
            "raw_payload_archive",         // 原始事件审计存档 (非查询面)
            "person_alias_by_account_min", // 别名索引 (name 解析内部用)
            "etl_state",                   // ETL 水位 (ingest 内部)
            "l1_generation",               // L1 实例代号 (new 水位跨重建检测, ingest 内部)
            "moment_media",                // 朋友圈媒体引用 → export-sns-media 导出, 无查询命令
            "schema_meta",                 // R14: schema 版本登记 (init_l1_schema 门禁建 + 播种版本, infra 非查询面)
            "write_lease", // R17: 多写者协调租约表 (write_lease.rs; infra 协调面, 无查询命令; 方案B 激活推迟 R22)
            "chat_refresh_state", // R22: 会话上次采集时的源库分片签名 (缓存控制面, 非数据投影)
            "capture_targets", // R19: 选择性采集白名单 (采集控制面, 非数据投影; 由 `capture` 命令增删查, 非 REGISTRY/handwritten 数据查询)
        ]
        .into_iter()
        .collect();

        let uncovered: Vec<&str> = actual
            .iter()
            .map(String::as_str)
            .filter(|t| !registry.contains(t) && !handwritten.contains(t) && !exempt.contains(t))
            .collect();
        assert!(
            uncovered.is_empty(),
            "L1 表无命令且未豁免 (加查询命令或列入 exempt): {uncovered:?}"
        );

        // 反向守卫: 三个集合里列了 init_l1_schema 根本不建的表 = 陈旧幽灵项, 该清理。
        let phantom: Vec<&str> = registry
            .iter()
            .chain(handwritten.iter())
            .chain(exempt.iter())
            .copied()
            .filter(|t| !actual.contains(*t))
            .collect();
        assert!(
            phantom.is_empty(),
            "登记表/手写/豁免 含 init_l1_schema 不建的幽灵表: {phantom:?}"
        );
    }
}
