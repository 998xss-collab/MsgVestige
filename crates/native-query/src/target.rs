//! 查询目标 (查询内核抽取 §4/§5) —— 三皮查询入口统一吃的"查哪个库 / 哪个账号 / 哪个模式"。
//!
//! P0: `l1_db`(冷查 L1 路径)。**③b**: 加 `account`(多账号隔离)。§14 `mode`(热/冷双模式) 留位。
//! 带 `clap::Args` 派生: CLI 侧各查询命令 `#[command(flatten)] target: QueryTarget` 复用同一份参数;
//! MCP/HTTP 皮**不经 clap**, 直接 `QueryTarget { l1_db: ..., account: None }` 构造 (字段 pub) 即可, clap 派生只是 inert。

/// 查询命令共享查询目标 (③ flatten)。`l1_db` + ③b `account` + **R16-1 热冷通用三件套**。
///
/// **R16-1 (热查对等补全) 的地基改动**: 本结构原是**冷查专用** —— `l1_db` 必需, 因为那时只有冷查
/// flatten 它 (**37** 个命令结构; 我原先写的 38 是粗 grep 把一行注释也数进去了 —— 对抗审 P3-4 逮到,
/// 它按 Command 分支口径数是 36。数字本身不影响结论, 但别再拿粗 grep 的数当实测);
/// 而 sessions/messages 的热查是后加的、用的是**另一套独立字段**。这正是对抗审 P1-2 "三皮不对等"的根。
/// 要让这批命令都拿到 `--mode`, 必须把本结构改成热冷通用:
/// - `l1_db` **必需 → 可选**: 热查 (`--mode hot`, 默认) 根本不需要 L1 库; 只有冷查/auto 命中才要。
///   显式 `--mode cold` 却没给 `--l1-db` → **报错, 不静默转热** (R6 既有语义: 用户要冷查却偷偷去碰
///   微信库 = 最小意外违背)。
/// - 新增 `mode`/`wxid`/`wechat_data_dir`: 热查要用它们定位微信库 + 取 key。
#[derive(clap::Args, Debug, Clone)]
pub struct QueryTarget {
    /// L1 db 路径 (ingest 产出的库)。**R16-1 起可选** —— 热查不需要; 冷查/auto 才用。
    #[arg(long, help = "L1 库路径 (ingest 产出的库; 冷查 / auto 用, 实时查不需要)")]
    pub l1_db: Option<String>,
    // 注: **本结构体每个字段**的 /// 都会被 clap 原样打进用户 --help(37 个命令全带) —— 故每个字段都得
    // 显式 `help=` 写给用户看的一句话 (`help=` 优先于 ///, 于是 /// 可以照留给 rustdoc 讲设计理由)。
    //
    // 对抗审 P3-2 点名的是 mode/wxid/wechat-data-dir 泄了"此默认由 golden_json 守着""实测逮到过"连同
    // `**` 星号 —— 我只修了**被点名的那三个**就宣布清了。真跑 `contacts --help` 才发现同结构体的
    // l1-db/account 照泄("**R16-1 起可选**"/"建**临时过滤视图**遮蔽…exec/inspect 逃生口")。
    // 判据是"**这个结构体的字段**", 不是"审查点到的字段" —— 加字段时照此办。
    //
    // 【为什么默认 auto 而不是 hot】sessions/messages 默认 hot 是 R6 给它俩单独定的语义; 而 flatten
    // 本结构的 37 个命令**原本全是冷查**, 用户传 --l1-db 就是要冷查。默认 hot 会让所有现有用法要么
    // 报错(缺 --wxid)要么改去碰微信库 = 最大意外。auto 则: 老用法照旧走冷、只给 --wxid 时自动走热。
    // 此默认由 golden_json 端到端守着(设成 hot 会让 `contacts --l1-db <库>` 直接退出码 2, 实测逮到过)。
    #[arg(
        long,
        value_enum,
        default_value_t = QueryMode::Auto,
        help = "查询模式: auto(默认, 给了 --l1-db 就查 L1、否则实时读微信库) / cold(查 L1, 需 --l1-db) / hot(实时读微信库, 需 --wxid)"
    )]
    pub mode: QueryMode,
    #[arg(long, help = "账号 wxid (--mode hot 时用: 定位微信数据目录 + 取已缓存的 key)")]
    pub wxid: Option<String>,
    #[arg(
        long,
        help = "微信数据目录 xwechat_files (--mode hot 时用; 省略则自动探测 %USERPROFILE%\\Documents\\xwechat_files)"
    )]
    pub wechat_data_dir: Option<String>,
    /// ③b 多账号隔离: 指定账号 **wxid**(如 `wxid_xxx`)→ 只返回该账号数据。仅**多账号 L1**(一个库 ingest 了
    /// 多个账号)才需要;单账号 L1 省略即可(不加过滤)。内部 `sha256(wxid)` 匹配各表 `account_id_sha` 列 ——
    /// 对所有账号域表建**临时过滤视图**遮蔽(裸表名自动命中,连 exec/inspect 逃生口也隔离;`main.<表>` 显式绕过)。
    #[arg(
        long,
        help = "只看某个账号的数据 (填 wxid; 仅当一个 L1 库里 ingest 了多个账号时才需要)"
    )]
    pub account: Option<String>,
}

impl QueryTarget {
    /// **R16-1**: 构造一个**冷查**目标 (MCP/HTTP 皮不经 clap, 手写 5 个字段太脆 —— 将来加字段就又炸一圈)。
    ///
    /// 用于那些**只走冷查**的内部 helper (如 MCP/HTTP 的 registry 派发)。要热查的端点自己走
    /// `hot_*` 函数, 不经本构造器。
    #[must_use]
    pub fn cold(l1_db: String, account: Option<String>) -> Self {
        Self {
            l1_db: Some(l1_db),
            mode: QueryMode::Cold,
            wxid: None,
            wechat_data_dir: None,
            account,
        }
    }

    /// `account`(wxid)→ `account_id_sha`(= `sha256_hex(wxid)`, 64 hex);无 account → None。
    /// 供 [`open_l1_scoped`](crate::open_l1_scoped) 建遮蔽视图 + `meta.account` 标签(取前 8 位)用。
    #[must_use]
    pub fn account_sha(&self) -> Option<String> {
        self.account.as_deref().map(native_core::sha256_hex)
    }

    /// **R16-1**: 本目标落定的实际走向 —— `auto` 按"有没有给 `--l1-db`"消解为冷/热。
    ///
    /// 显式 `cold` 但没给 `--l1-db` 仍返 [`EffectiveMode::Cold`] —— 皮层据此报"要冷查却没配 L1",
    /// **不在此静默转热** (同 [`QueryMode::effective`] 的既有语义)。
    #[must_use]
    pub fn effective_mode(&self) -> EffectiveMode {
        self.mode.effective(self.l1_db.is_some())
    }

    /// **R16-1**: 冷查路径取 L1 库路径 + **显式 `--mode hot` 的收口拒绝**。
    ///
    /// **为什么把 hot 的拒绝放这**(对抗审 P1-1): `QueryTarget` 被几十个命令 flatten, 而只有一部分真接了
    /// 热查派发。其余命令直接进 `open_l1_resolved` → 本函数, **从头到尾不读 `mode`** —— 于是
    /// `stats --mode hot --wxid X` 会**静默走冷查**、拿 L1 快照还退 0, 而 `stats --help` 明写着
    /// "--mode hot: 直读加密微信库 = 实时"。**参数在某分支被无声吞是本库老毛病**
    /// (native-http/src/lib.rs:2602 早就对投影的 `mode=hot` 显式 400、并注明这条教训), R16-1 差点把
    /// 它一次铺到 35 个命令上。
    ///
    /// 本函数是**唯一收口点** —— `open_l1_resolved` 走它, 绕开 `open_l1_resolved` 的 `cmd_new`/
    /// `cmd_search` 也走它; 而真接了热查的命令, 其热分支**根本不调本函数**, 故不误伤。
    ///
    /// **报错里不列"哪些命令有实时版"的名单**(对抗审 P3-2): 那份名单每接一条热查就过期一次 —— 上一版
    /// 硬写"目前只有 sessions/messages/contacts/favorites", 而 friend-requests 刚接上热查, 这句没跟着
    /// 改, 于是它**明确告诉用户 friend-requests 没有实时版 —— 而它有**。手抄的清单必然漏, 这是本轮
    /// 反复栽的同一个坑。况且真有热查的命令走不到这个分支, 根本不需要在这列谁有。
    ///
    /// # Errors
    /// - 显式 `--mode hot` 但该命令无热查实现 → [`crate::CliError`] (`BadRequest`, "暂无实时版")。
    /// - `cold`/`auto` 却没给 `--l1-db` → [`crate::CliError`] (`BadRequest`, 要 `--l1-db`)。
    pub fn require_l1_db(&self) -> anyhow::Result<&str> {
        // 走到这 = 本命令在冷查路径上。用户却显式点了 hot → 说明这命令还没有实时版:
        // **报错, 不静默降级成冷查**(否则用户以为拿的是实时数据, 实际是 L1 快照)。
        if self.mode == QueryMode::Hot {
            return Err(crate::cli_err(
                native_core::ErrorCode::BadRequest,
                "该命令暂无实时版 (--mode hot 尚未支持) —— 请改用 --mode cold --l1-db <L1库>, \
                 或省略 --mode 走默认 auto。(某个命令支不支持实时版, 看它自己的 --help)"
                    .to_string(),
            ));
        }
        self.l1_db.as_deref().ok_or_else(|| {
            crate::cli_err(
                native_core::ErrorCode::BadRequest,
                "该命令要读 L1 库但没给 --l1-db (先跑 `ingest` 建库, 或用 --l1-db 指向已有库)".to_string(),
            )
        })
    }
}

/// **R6 查询模式** (`--mode` / `?mode=` / MCP `mode` 三皮共享): 消费者显式选数据来源。
/// **默认 `Hot`(实时)** —— 用户 2026-07-15 定: R6 判不了 L1 新旧(单标量水位必谎报新鲜, 逐源精确判定属 R9),
/// 默认实时最稳(每次最新、不会不留神拿旧数据); R9 能可靠判新旧后再把默认改 `Auto`。
#[derive(clap::ValueEnum, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum QueryMode {
    // 注: 这几行 doc 会被 clap 打进**所有**用本枚举的命令的 `--help` (Possible values) —— 故只写
    // 用户视角的一句话: 不写"默认"(谁是默认取决于各命令自己的 default_value_t: sessions/messages
    // 独立字段默认 Hot; QueryTarget flatten 的那批默认 Auto), 不写章节号/里程碑号, 不写 ** 星号
    // (终端不渲染, 用户看到的就是字面的星号)。
    //
    // 这条注释是我上一轮写的, 当时只改掉了"默认"那处矛盾 —— 而同一行里的"内核 §14 auto 语义"就在
    // 眼皮底下没动, 于是 §14 泄进了 38 个命令的 --help。判据是"用户看不看得懂这句话", 不是"审点没点它"。
    // 现在有 subcommand_help_has_no_internal_narrative 测试机器扫, 不靠这条注释。
    /// 直读加密微信库, 拿实时数据 (要 --wxid + 已缓存的 key)。
    #[default]
    Hot,
    /// 读 ingest 产出的 L1 库: 快, 但数据可能旧 (响应里带 ingested_at 标明导入时间)。
    Cold,
    /// 给了 --l1-db 就读 L1 (并标出导入时间); 没给就直读微信库拿实时数据。
    Auto,
}

/// [`QueryMode`] 按"有无 L1"落定后的**实际**走向 (`auto` 已消解为冷/热二选一)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveMode {
    Hot,
    Cold,
}

impl QueryMode {
    /// 定实际走冷还是热: 显式 `hot`/`cold` 照办; `auto` 有 L1 → 冷、无 L1 → 热。
    /// 显式 `cold` 但无 L1 时仍返 [`EffectiveMode::Cold`] —— 皮层据此报"要冷查却没配 L1", **不在此静默转热**
    /// (静默转热 = 用户要快却慢查、要不碰微信却碰了, 违最小意外)。
    #[must_use]
    pub fn effective(self, has_l1: bool) -> EffectiveMode {
        match self {
            QueryMode::Hot => EffectiveMode::Hot,
            QueryMode::Cold => EffectiveMode::Cold,
            QueryMode::Auto => {
                if has_l1 {
                    EffectiveMode::Cold
                } else {
                    EffectiveMode::Hot
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EffectiveMode, QueryMode};

    #[test]
    fn mode_default_is_hot() {
        assert_eq!(QueryMode::default(), QueryMode::Hot, "R6 默认实时 (用户定)");
    }

    #[test]
    fn effective_dispatch() {
        // 显式照办 (不看 L1)。
        assert_eq!(QueryMode::Hot.effective(true), EffectiveMode::Hot);
        assert_eq!(QueryMode::Hot.effective(false), EffectiveMode::Hot);
        assert_eq!(QueryMode::Cold.effective(true), EffectiveMode::Cold);
        assert_eq!(
            QueryMode::Cold.effective(false),
            EffectiveMode::Cold,
            "显式 cold 无 L1 仍 Cold (皮层报错, 不静默转热)"
        );
        // auto 按有无 L1。
        assert_eq!(
            QueryMode::Auto.effective(true),
            EffectiveMode::Cold,
            "auto + 有 L1 → 冷"
        );
        assert_eq!(
            QueryMode::Auto.effective(false),
            EffectiveMode::Hot,
            "auto + 无 L1 → 热"
        );
    }
}
