//! msgvestige-adapter (bin) — message ETL ingest 端到端薄壳 (§11.5-7 取数链端到端接线)。
//!
//! 把可测 lib ([`native_adapter`]) 接到真实依赖: args → 取 key (cache/--master-key-hex) →
//! 定位账号 db → `NativeCipher` (纯 Rust 解密) → `AccountDbSource` → `run_message_ingest`。
//!
//! 真依赖 (KeyProvider / cipher) 环境耦合不可单测; 可测逻辑 (定位 / 编排) 在 lib。
//! K-R4: 明文 wxid / master key 不入 stdout/log — wxid 走 sha8, key 永不打印。

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use native_adapter::{locate_account_dbs, run_full_ingest, run_message_watch, IngestPlan, MessageWatchOpts};
use native_core::key_provider::{CacheKeyProvider, KeyProvider};
use native_core::{sha8, AccountDbSource, MasterKey, PipelineStats, PrivacyMode, Wxid};

#[derive(Parser)]
#[command(name = "msgvestige-adapter", version, about = "微信数据基座 alpha — message ETL ingest")]
#[allow(clippy::struct_excessive_bools)] // CLI flag struct: 19 bool (redact/contacts/chatrooms/sessions/favorites/sns/transfers/red_envelopes/group_pays/friend_verifies/finder_visits/moment_feeds/sns_notifies/emoticons/avatars/biz_messages/bizchat/strangers/no_messages) 是 clap 惯例
struct Args {
    /// 账号 wxid (如 wxid_abcd1234efgh567)。
    #[arg(long)]
    wxid: String,
    /// 微信数据目录 (xwechat_files; 内含 <wxid>_<后缀>/db_storage/...)。
    #[arg(long)]
    wechat_data_dir: String,
    /// L1 输出库路径 (不存在则建)。
    #[arg(long)]
    l1_db: String,
    /// 单批 drain 行数上限 (page-by-page, 禁全量)。默认 4000: 实测 vs 1000 提速 ~15% (少刷盘), 内存占用仍小。
    #[arg(long, default_value_t = 4000)]
    batch_limit: usize,
    /// 直接提供 master key (64 hex), 跳过 cache/hook。
    #[arg(long, value_name = "HEX")]
    master_key_hex: Option<String>,
    /// 隐私: payload_json 出边界脱敏全 sha (ADR-426 §2.2 默认 archive 明文 canonical; 本 flag opt-in 脱敏)。
    #[arg(long)]
    redact_payload: bool,
    /// 也跑 contact ingest (默认只 message; contact.db 存在才跑)。
    #[arg(long)]
    contacts: bool,
    /// 也跑 chatroom 群成员 ingest (默认关; contact.db 的 chat_room 表存在才跑)。
    #[arg(long)]
    chatrooms: bool,
    /// 也跑 session 会话列表 ingest (默认关; session.db 即账号入口 db, 必在才到此步)。
    #[arg(long)]
    sessions: bool,
    /// 也跑 favorite 收藏 ingest (默认关; favorite.db 存在才跑; ADR-454)。
    #[arg(long)]
    favorites: bool,
    /// 也跑 sns 朋友圈 ingest (默认关; sns.db 存在才跑; ADR-467 件1)。
    #[arg(long)]
    sns: bool,
    /// 也跑 transfer 转账 ingest (默认关; general.db 存在才跑; ADR-468)。
    #[arg(long)]
    transfers: bool,
    /// 也跑 red_envelope 红包 ingest (默认关; general.db 存在才跑; ADR-468 件2)。
    #[arg(long)]
    red_envelopes: bool,
    /// 也跑 group_pay 群收款 ingest (默认关; general.db 存在才跑; ADR-468 件3)。
    #[arg(long)]
    group_pays: bool,
    /// 也跑 friend_verify 好友验证 ingest (默认关; general.db 存在才跑; ADR-469)。
    #[arg(long)]
    friend_verifies: bool,
    /// 也跑 finder_visit 视频号主页 ingest (默认关; general.db 存在才跑; ADR-473)。
    #[arg(long)]
    finder_visits: bool,
    /// 也跑 moment_feed 朋友圈好友动态索引 ingest (默认关; sns.db 存在才跑; ADR-474)。
    #[arg(long)]
    moment_feeds: bool,
    /// 也跑 sns_notify 朋友圈互动通知 ingest (默认关; sns.db 存在才跑; 照 moment_feed ADR-474)。
    #[arg(long)]
    sns_notifies: bool,
    /// 也跑 custom_emoticon 自定义表情 ingest (默认关; emoticon.db 存在才跑; ADR-478)。
    #[arg(long)]
    emoticons: bool,
    /// 也跑 avatar_image 头像图 ingest (默认关; head_image.db 存在才跑; ADR-481)。
    #[arg(long)]
    avatars: bool,
    /// 也跑 bizchat_user 企微品牌号联系人 ingest (默认关; bizchat.db 存在才跑; ADR-482)。
    #[arg(long)]
    bizchat: bool,
    /// 也跑 biz_message 公众号消息 ingest (默认关; biz_message_*.db 存在才跑; 复用 message pipeline; ADR-480)。
    #[arg(long)]
    biz_messages: bool,
    /// 也跑 stranger 陌生人 ingest (默认关; contact.db 存在才跑; 复用 contact pipeline 从 stranger 表取,
    /// 落 person 表 source 列 `contact.db|stranger` 区分; echotrace 同源)。
    #[arg(long)]
    strangers: bool,
    /// 跳过 message ingest (配 --contacts/--chatrooms/--sessions 做 non-message)。
    #[arg(long)]
    no_messages: bool,
    /// 实时监听模式 (件3, ADR-499): 轮询消息库, 有新消息就增量抽取 (live cipher 合并 WAL). 开则只跑 watch, 不跑一次性 ingest。
    #[arg(long)]
    watch: bool,
    /// watch: 写**真实 L1** (持久); 默认关 = 临时库观察 (拷真库水位 tail-f, **不动真库**)。
    #[arg(long)]
    watch_to_l1: bool,
    /// watch: 关掉"新消息打印" (默认开; 只写库不看流时用)。
    #[arg(long)]
    watch_no_print: bool,
    /// watch: 轮询间隔 (毫秒)。
    #[arg(long, default_value_t = 800)]
    watch_poll_ms: u64,
    /// watch: 跑满秒数即停 (0 = 永久, 直到 Ctrl-C; demo/测试给个值)。
    #[arg(long, default_value_t = 0)]
    watch_secs: u64,
    /// L1-free 源库快查: 列出所有会话 (conv_id + 是否群 + 所在分片数)。不建 L1, 直查加密源库。
    #[arg(long)]
    list_convs: bool,
    /// L1-free 源库快查: 查某会话 (conv_id, 如 `xxx@chatroom` 或对方 wxid) 最近消息。不建 L1。
    #[arg(long, value_name = "CONV_ID")]
    query_conv: Option<String>,
    /// 源库快查: 取最近几条 (配合 `--query-conv`)。
    #[arg(long, default_value_t = 20)]
    query_limit: usize,
    /// 源库快查: 定位表 JSON 存放路径 (持久化, 几百 KB; 缺省 = 系统临时目录下按 wxid 命名)。
    #[arg(long, value_name = "PATH")]
    locator_file: Option<String>,
    /// 源库快查: 强制重建定位表 (删掉缓存全扫一遍; 正常不用, 平时自动按分片指纹增量刷新)。
    #[arg(long)]
    rebuild_locator: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // 统一日志 (logging-日志.md 任务 1 + 收尾②): 启动读 config.toml (默认路径) 应用 log_dir/log_level;
    // 缺文件/坏文件走默认兜底。RUST_LOG > config.log_level > default (init_logging EnvFilter 保证)。
    let cfg = native_core::config::load_or_default(&native_core::config::default_config_path());
    common::log::init_logging(&cfg.observability.log_level, &cfg.observability.log_dir);
    let args = Args::parse();
    // 代码双审 P2: batch_limit=0 尽早拒 (否则 locate/key 都白做)。
    anyhow::ensure!(args.batch_limit >= 1, "--batch-limit 须 ≥ 1 (page-by-page, 禁全量)");
    let wxid: Wxid = args.wxid.parse().context("--wxid 非法 (须合法微信 wxid)")?;
    // ADR-426 §2.2: archive payload 默认明文 (底座内 canonical storage); --redact-payload opt-in 出边界脱敏。
    let mode = if args.redact_payload {
        PrivacyMode::default_sha()
    } else {
        PrivacyMode::archive_canonical()
    };

    // 1. 定位账号 db (db_storage/session/session.db 入口 + message/ 扫盘根)。
    let paths = locate_account_dbs(Path::new(&args.wechat_data_dir), &wxid).context("定位账号 db 失败")?;

    // 2. 取 master key (cache 优先; --master-key-hex 直供)。
    let key = acquire_key(&args, &wxid).await?;

    // 2.4 L1-free 源库快查 (ADR-501): 不建 L1, 保温 VFS 连接 + 定位表直查加密源库。存储紧张/小号用。
    if args.list_convs || args.query_conv.is_some() {
        use std::time::Instant;
        let locator_path = args.locator_file.clone().map_or_else(
            || std::env::temp_dir().join(format!("wxquery_locator_{}.json", args.wxid)),
            std::path::PathBuf::from,
        );
        if args.rebuild_locator {
            let _ = std::fs::remove_file(&locator_path); // 强制全扫重建。
            tracing::info!("[query] --rebuild-locator: 已删缓存, 将全扫重建");
        }
        // R16-0: 注入本账号 wxid (单聊 sender 方向回退用, 见 SourceQuery::self_wxid)。
        let mut sq = native_core::SourceQuery::open(
            paths.message_dir.clone(),
            key,
            locator_path,
            args.wxid.as_str().to_owned(),
        );
        let t0 = Instant::now();
        sq.build()
            .context("建定位表/开源库失败 (key 不对 / 已对该账号跑过 auth?)")?;
        tracing::info!("[query] 定位表就绪, 保温连接已开 ({}ms)", t0.elapsed().as_millis());
        if args.list_convs {
            let convs = sq.list_convs().context("列会话失败")?;
            tracing::info!("[query] 会话数={} (前 50):", convs.len());
            for (c, is_grp, nshards) in convs.iter().take(50) {
                println!("{} {c}  (分片×{nshards})", if *is_grp { "群" } else { "单聊" });
            }
        }
        if let Some(conv) = &args.query_conv {
            let t1 = Instant::now();
            let msgs = sq.latest_messages(conv, args.query_limit).context("查会话消息失败")?;
            let cold = t1.elapsed().as_millis();
            let t2 = Instant::now();
            let _ = sq.latest_messages(conv, args.query_limit).context("暖查失败")?;
            let warm = t2.elapsed().as_millis();
            tracing::info!(
                "[query] conv(sha8={}) 最近 {} 条 (冷 {cold}ms / 暖 {warm}ms):",
                sha8(conv.as_bytes()),
                msgs.len()
            );
            for m in &msgs {
                let preview: String = m.text.chars().take(60).collect();
                println!(
                    "  [{}] type{} {}: {}",
                    m.create_time,
                    m.local_type,
                    m.sender.as_deref().unwrap_or("?"),
                    preview
                );
            }
        }
        return Ok(());
    }

    // 2.5 实时 watch (件3, ADR-499): live cipher (合并 WAL 拿未刷盘最新消息), 只跑 watch, 不跑一次性 ingest。
    if args.watch {
        // 盯 message_dir 下所有 *.db (mtime 门控; 过包含无害) — 在 message_dir move 进 source 前先收集。
        let mut watch_dbs = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&paths.message_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "db") {
                    watch_dbs.push(p);
                }
            }
        }
        tracing::info!("native cipher LIVE (合并 WAL 实时前沿)…");
        let cipher: Box<dyn native_core::cipher::Cipher> = Box::new(native_core::cipher::NativeCipher::new_live());
        let mut source = AccountDbSource::new(cipher, paths.account_entry_db, key, wxid.clone(), paths.message_dir);
        let opts = MessageWatchOpts {
            print: !args.watch_no_print,
            to_l1: args.watch_to_l1,
            poll: std::time::Duration::from_millis(args.watch_poll_ms),
            max_secs: args.watch_secs,
            watch_dbs,
            cancel: None,   // adapter bin watch: 无优雅关停信号 (Ctrl-C 退)
            progress: None, // adapter bin watch: 不需要进度通知 (仅 serve /events 用)
        };
        run_message_watch(&mut source, Path::new(&args.l1_db), &wxid, mode, args.batch_limit, opts)
            .await
            .context("watch 失败")?;
        return Ok(());
    }

    // 3. cipher → source. 纯 Rust 解密 (ADR-428 M3-e, 默认且唯一路径). 用 clone 构造 source
    // (不 move paths 的 account_entry_db / message_dir) → paths 全程可用, 可整体 &paths 传
    // run_full_ingest (session 域直接读 paths.account_entry_db, 免单独克隆)。
    tracing::info!("native cipher (纯 Rust 解密)…");
    let cipher: Box<dyn native_core::cipher::Cipher> = Box::new(native_core::cipher::NativeCipher::new());
    let mut source = AccountDbSource::new(
        cipher,
        paths.account_entry_db.clone(),
        key,
        wxid.clone(),
        paths.message_dir.clone(),
    );

    // 5-19. 18 域 ingest 编排 → 可复用引擎 run_full_ingest (msgvestige 共用同一编排)。
    // plan 由 CLI flag 拼 (messages = !no_messages); 各域顺序 / 文件存在 guard / else 分支 / label 全在 lib 内保持。
    let plan = IngestPlan {
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
    };
    let results = run_full_ingest(
        &mut source,
        &paths,
        Path::new(&args.l1_db),
        &wxid,
        mode,
        args.batch_limit,
        &plan,
        now_millis(),
        // adapter bin (dev/调试入口) 保持串行 workers=1; R15 并行经 msgvestige `ingest --jobs` 主路径交付。
        1,
    )
    .await?;
    for (label, stats) in &results {
        report_stats(label, &wxid, stats);
    }

    Ok(())
}

/// 报告一次 ingest 的统计 (非敏感: 全计数 + wxid sha8; message 计数=消息数, contact 计数=联系人数)。
fn report_stats(label: &str, wxid: &Wxid, stats: &PipelineStats) {
    let stalled = if stats.stalled_subsources > 0 {
        format!(" / ⚠️ {} 卡住子源", stats.stalled_subsources)
    } else {
        String::new()
    };
    // chatroom ingest: 群成员 add/remove 计数 (message/contact 恒 0 → 不显示)。
    let members = if stats.members_added > 0 || stats.members_removed > 0 || stats.invalid_chatrooms > 0 {
        format!(
            " / 群成员 +{} -{} / {} 无效群",
            stats.members_added, stats.members_removed, stats.invalid_chatrooms
        )
    } else {
        String::new()
    };
    println!(
        "✅ {label} ingest 完成 (账号 sha8={}): {} 库 / {} 子源 / {} 行落库 / {} 解码错 / {} 游标推进 / {} 批{}{}",
        sha8(wxid.as_str().as_bytes()),
        stats.dbs,
        stats.subsources,
        stats.messages_decoded,
        stats.decode_errors,
        stats.cursor_updates,
        stats.batches,
        stalled,
        members,
    );
}

/// 取 master key。**ingest 非交互**: 不含 ciphertalk hook (那会杀/重启微信)。
///
/// - `--master-key-hex` 给了 → **直供 override** (代码双审 P1): 不读 cache (不被 stale cache 遮蔽)、
///   不写回 cache (不把【未经验证】的 key 污染 cache; auth 流程才该验证后写回)。
/// - 否则 → **只读 cache** (prior `msgvestige auth` 已 ciphertalk 验证并缓存); 单 provider 不 write-back。
///
/// 注 (KI): cache 里的 key 若已过期, open 会 HMAC 失败报错; alpha 不自动失效 cache, 重跑 auth 刷新。
async fn acquire_key(args: &Args, wxid: &Wxid) -> Result<MasterKey> {
    if let Some(hex) = &args.master_key_hex {
        return MasterKey::from_hex(hex).context("--master-key-hex 解析失败 (须 64 hex)");
    }
    let cache = CacheKeyProvider::new(None);
    cache
        .resolve(wxid)
        .await
        .context("cache 无该账号 key — 先跑 `msgvestige auth` 取 key, 或传 --master-key-hex")
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
