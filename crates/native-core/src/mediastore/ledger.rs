//! 侧车账本 `ledger.db` 的 schema(R10 §11-① · 落 §12-A 的关系 DDL / 约束)。
//!
//! **状态分属不同实体**(§二, 逐维归实体, 不塞一张表一组抽象字段, 否则多来源并发互相覆盖):
//! - claimed/writing/verifying/publishing 归 `work_item`;
//! - ready / missing_on_disk 归 `asset_presence`;
//! - **源头没有 / 需扫盘 / 联网失败 / blocked_missing_image_key / encrypted_no_plain_cache 归 `source_locator`**(§二/§九/§12-F:
//!   这些是**源级**状态, 落 `source_locator.source_state` 枚举, 不作游离文字标签);
//! - 只有缩略图·待升级 / 已高清 由 `variant.clarity` 表达(thumb=待升级/hd·original=已高清);
//! - 未校验 / 已校验 / 已损坏·隔离 归 `verification`(挂 asset)。
//!
//! **身份三键分清**(§12-A, 三者键**不同**别混):
//! - `media_reference`: 以 L1 message PK `(account_id_sha, source, source_native_id)` + 判别段 `(role, media_seq)` 为键。
//! - `source_locator`: 源库身份 + talker/local_id/svr_id/anchor 组合键(同源去重)。
//! - `asset_registry`: 对外 `MediaRef{kind,key,version}` 键(§5c serve 那一跳)。
//!
//! **generation**: `reference_generation`/`view_generation` 等各实体自己的版本; GC 比对 reference_generation(§12-A/B)。
//! DDL 是**当前地基**(补一处加一处, 不宣称已列全); 崩溃协议/GC 状态机细节随 §11 后续步骤补。

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

/// 账本 schema 版本(迁移门禁用; 复用 L1 `schema_meta` 模式)。
///
/// 复审2 P1: **DDL 不兼容变更必 bump**。`CREATE TABLE IF NOT EXISTS` 对既存旧表是 no-op, 光靠它升级不了旧库的约束 —— 版本门禁
/// 靠本常数把旧库拒在门外(账本是**源库可重建的派生 CAS 索引**, pre-1.0 不做迁移: 版本不符即删账本、从源重建, 见 [`open_ledger`])。
/// v1(eb6d2c7)→ v2(加 canonical 约束/触发器/pin RESTRICT/work_item 结构化列等)→ **v3(F5a: clarity **数据语义**变更 —— 旧代码把无
/// key 缩略图误记 clarity='original', 新版按变体记 'thumb'/'hd'/'original'; DDL 结构没变故指纹门禁不触发, 但老账本按旧语义写的行会让
/// preferred 重算把误标缩略当原图 → **bump 版本**让门禁拒旧库、删重建。复审 codex P1: **数据语义变更也须 bump**, 非只 DDL 结构变更)
/// → **v4(块1 双审: attempt 加 XOR CHECK `((result_asset_id IS NULL)!=(error_code IS NULL))` —— DDL 结构变更, 指纹本自动门禁, 版本同步 bump 保一致)**
/// → **v5(R14: 消息锚 8hex→32hex 全扩 —— `media_reference`/`work_item` 的 `source_native_id` 锚变长, DDL 结构没变故指纹门禁不触发,
/// 但旧 v4 库的 8hex 锚与新 32hex 混用会插重复 `media_reference`/连不上重建后的 L1, 故 bump 让 `open_ledger` 拒旧库、删账本从源重建)**。
pub const LEDGER_SCHEMA_VERSION: &str = "5";

const META_VERSION: &str = "version";
const META_ACCOUNT: &str = "account_id_sha";
const META_MIGRATION: &str = "migration_history";
/// schema 指纹(复审4 P1: DDL 的 sha256; open 时比对, 自动版本门禁, 不靠手动 bump)。
const META_FINGERPRINT: &str = "schema_fingerprint";

/// **全部账本 DDL**(建表 + 约束触发器; 幂等 `CREATE ... IF NOT EXISTS`)。见各段 doc 的 §引用。
/// 复审4 P1: 抽成常数 —— 既喂 `execute_batch` 建库, 又对它算 sha256 存 [`META_FINGERPRINT`], open 时比对; DDL 一改(即便忘
/// bump [`LEDGER_SCHEMA_VERSION`])指纹就变 → 自动拒旧库(pre-1.0 不迁移, 删账本从源重建)。**写入契约**(复审4 P1): CAS 表
/// **禁用 `INSERT OR REPLACE`/`REPLACE INTO`** —— REPLACE = 隐式 DELETE 旧行, 对 SET NULL 子(attempt.result_asset_id, 为让 GC
/// 能删资产必须 SET NULL 不能 RESTRICT)会静默丢 provenance, SQLite 无法在库级禁 REPLACE; 一律用 `INSERT`/`ON CONFLICT DO
/// UPDATE|NOTHING`/显式 `UPDATE`(下方 grep 关卡 `no_replace_in_cas_writes` 挡回退)。RESTRICT 子边挡的是更严重的 variant/满足度丢失。
const LEDGER_DDL: &str = "
        -- schema_meta: 版本 + 账号绑定 + 迁移历史(§12-A; 每次打开校验账号绑定 + 迁移门禁, 复用 L1 模式)。
        -- 复审3 P2: 单列 TEXT PK 一律显式 NOT NULL —— SQLite rowid 表的非 INTEGER 主键**不自动禁 NULL**(历史坑),
        -- 不写 NOT NULL 可插入多行 key=NULL 破唯一身份(schema_meta/locator/work_id/... 同类, 逐张补)。
        CREATE TABLE IF NOT EXISTS schema_meta (
            key        TEXT PRIMARY KEY NOT NULL,
            value      TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        -- asset: **字节事实**(§二)。asset_id=`sha256:<hex>`; hex 裸供索引/路径; 只存字节, 不含 kind/来源(那些是多对多)。
        -- 复审 P1: hex 是**权威 CAS 物理路径**(§五 StoreLayout, NTFS 大小写不敏感)—— 必须 canonical: 64 位**小写** hex、
        -- 与 asset_id 一致、且 **UNIQUE**。否则 'sha256:AB..' 与 'sha256:ab..' 两行落到同一 NTFS 路径, GC 删一行连带删掉另一行仍
        -- 被引用的字节(不可再生)。lifecycle(复审 P2): tombstoned=有意 GC 目标(§12-E), 区别于 asset_presence.missing_on_disk
        -- (意外丢失, 需 repair, §四)—— 无此区分则 repair 会把已 GC 的资产当「意外丢失」重新拉回, 与 GC 打架。
        CREATE TABLE IF NOT EXISTS asset (
            -- 复审2 P2: asset_id 必 **NOT NULL** —— SQLite 非 INTEGER 主键允许 NULL(历史 bug), 且 `NULL='sha256:'||hex` CHECK 结果为
            -- NULL 不算失败 → 合法 hex 配 NULL asset_id 能入库, 破身份。NOT NULL 堵死。
            asset_id   TEXT PRIMARY KEY NOT NULL CHECK (asset_id = 'sha256:' || hex),  -- 'sha256:<hex>'
            -- 复审2 P2: CHECK 收紧到 **字母表 [0-9a-f]**(NOT GLOB '*[^0-9a-f]*' 蕴含小写 + 排非 hex 字符), 与 AssetId::parse 对齐;
            -- 否则 'z'×64 / 含 '/' 的串能过 length+lower 却被 Rust parse 拒, 且 '/' 流入 §五 物理路径。
            hex        TEXT NOT NULL UNIQUE
                       CHECK (length(hex) = 64 AND hex NOT GLOB '*[^0-9a-f]*'),  -- 64 位纯小写 hex; 权威物理路径, 去重靠它
            size       INTEGER NOT NULL CHECK (size >= 0),
            ext        TEXT,                             -- 检测扩展名(可空; **不进权威路径**, by-chat 从账本取, §12-A)
            mime       TEXT,
            lifecycle  TEXT NOT NULL DEFAULT 'live' CHECK (lifecycle IN ('live','tombstoned')),  -- §12-E 有意退役标记
            created_at INTEGER NOT NULL
        );

        -- 复审3 P1(结构性, 非又一个触发器): asset/logical_media 的子表 FK 一律 **ON DELETE RESTRICT** 不用 CASCADE。
        -- 原因: `INSERT OR REPLACE` 父表 = 隐式 DELETE 旧行 + INSERT 新行; CASCADE 子会在删旧行时**静默清空**(触发器守卫此刻
        -- 看不到父行→放行), 新父行插回后 NO ACTION 的 root(media_reference/registry/locator)又重新满足 → 落成「active root
        -- 指向零 variant 的组」/「verified 资产变 unverified」, 无报错、不可恢复(§一唯一解析链 / §12-B 主可达链 / §四完整性被悄悄破)。
        -- RESTRICT 让父表 REPLACE 在「子还在」时**直接失败**(work_item 的子 attempt/journal 本就是 RESTRICT, 故它天然免疫 = 修法信号);
        -- 合法拆除改**显式先删子再删父**(与 §12-E 先退役边再 tombstone 的有序拆除一致)。三轮 REPLACE 打地鼠到此从结构上封死。

        -- asset_presence: 在盘存在性(§二 状态分实体)。**非 GC root**(纯物理状态)。
        CREATE TABLE IF NOT EXISTS asset_presence (
            asset_id   TEXT PRIMARY KEY NOT NULL REFERENCES asset(asset_id) ON DELETE RESTRICT,
            state      TEXT NOT NULL CHECK (state IN ('ready','missing_on_disk')),
            checked_at INTEGER NOT NULL
        );

        -- verification: 校验状态(§二; 未校验/已校验/损坏隔离)。**非 root**。
        CREATE TABLE IF NOT EXISTS verification (
            asset_id    TEXT PRIMARY KEY NOT NULL REFERENCES asset(asset_id) ON DELETE RESTRICT,
            state       TEXT NOT NULL CHECK (state IN ('unverified','verified','corrupt')),
            method      TEXT,                            -- 'hash' / 'decode'
            verified_at INTEGER
        );

        -- asset_role: asset ↔ kind 多对多(§二; 同字节多角色)。**非 root**(逻辑标注)。
        CREATE TABLE IF NOT EXISTS asset_role (
            asset_id TEXT NOT NULL REFERENCES asset(asset_id) ON DELETE RESTRICT,
            kind     TEXT NOT NULL,                      -- 开放枚举 chat_image/video/voice/avatar/emoticon/sns/file/...
            PRIMARY KEY (asset_id, kind)
        );

        -- asset_source: asset ↔ 来源 多对多(§二; 同字节多来源)。**非 root**(provenance)。
        CREATE TABLE IF NOT EXISTS asset_source (
            asset_id      TEXT NOT NULL REFERENCES asset(asset_id) ON DELETE RESTRICT,
            source_ref    TEXT NOT NULL,                 -- 来源标识串
            PRIMARY KEY (asset_id, source_ref)
        );

        -- logical_media: 逻辑组(§二)。preferred **必须是本组 active 成员**(§12-A)—— 复审 P1: 不靠应用层, 由下方触发器强制。
        -- 无鸡生蛋: 先插 preferred=NULL 的组 → 插 variant → 再 UPDATE preferred(见 trg_preferred_*)。
        CREATE TABLE IF NOT EXISTS logical_media (
            logical_group_id   TEXT PRIMARY KEY NOT NULL,
            preferred_asset_id TEXT REFERENCES asset(asset_id),
            created_at         INTEGER NOT NULL
        );

        -- variant: 成员边 group↔asset × 清晰度 × 派生 profile(§二; 归组置信度放边上; §12-E 边退役状态机)。variant 不重复。
        -- clarity(复审 P2-3): thumb/hd/original 三值枚举 —— 升级状态(待升级/已高清)由本列表达, 不另设列(§二)。
        -- logical_group_id **RESTRICT**(复审3 P1): 见上方 asset 子表说明; 删组须先显式删其 variant(REPLACE 父组不再能静默清空成员)。
        CREATE TABLE IF NOT EXISTS variant (
            logical_group_id TEXT NOT NULL REFERENCES logical_media(logical_group_id) ON DELETE RESTRICT,
            asset_id         TEXT NOT NULL REFERENCES asset(asset_id),
            clarity          TEXT NOT NULL DEFAULT 'original' CHECK (clarity IN ('thumb','hd','original')),
            derivation       TEXT NOT NULL DEFAULT 'none',       -- none/wav/mp3/wxgf_jpg/... 转码 profile(§一 派生扩展点)
            confidence       REAL NOT NULL DEFAULT 1.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
            edge_state       TEXT NOT NULL DEFAULT 'active' CHECK (edge_state IN ('active','retired','tombstoned')),
            PRIMARY KEY (logical_group_id, asset_id, clarity, derivation)
        );
        CREATE INDEX IF NOT EXISTS idx_variant_asset ON variant(asset_id);

        -- 复审 P1: preferred 完整性触发器(§12-A「preferred 必须同组成员」+ §12-E「先重指再退役」)。
        -- ① 插/改 preferred 时它必须是本组 active variant 成员 —— 否则组 A 可把组 B 的 asset 设 preferred, MediaRef(A) 返回 B 的字节(串引用)。
        CREATE TRIGGER IF NOT EXISTS trg_preferred_ins
        BEFORE INSERT ON logical_media
        WHEN NEW.preferred_asset_id IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM variant v WHERE v.logical_group_id = NEW.logical_group_id
                             AND v.asset_id = NEW.preferred_asset_id AND v.edge_state = 'active')
        BEGIN SELECT RAISE(ABORT, 'preferred_asset_id 必须是本组 active variant 成员'); END;
        CREATE TRIGGER IF NOT EXISTS trg_preferred_upd
        BEFORE UPDATE OF preferred_asset_id ON logical_media
        WHEN NEW.preferred_asset_id IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM variant v WHERE v.logical_group_id = NEW.logical_group_id
                             AND v.asset_id = NEW.preferred_asset_id AND v.edge_state = 'active')
        BEGIN SELECT RAISE(ABORT, 'preferred_asset_id 必须是本组 active variant 成员'); END;
        -- ② 不许删/退役 preferred 的**最后一条 active 边**(§12-E: 先把 preferred 重指到别的 active 成员再退役), 避免留悬空 preferred。
        CREATE TRIGGER IF NOT EXISTS trg_preferred_edge_del
        BEFORE DELETE ON variant
        WHEN EXISTS (SELECT 1 FROM logical_media m WHERE m.logical_group_id = OLD.logical_group_id
                     AND m.preferred_asset_id = OLD.asset_id)
             AND NOT EXISTS (SELECT 1 FROM variant v WHERE v.logical_group_id = OLD.logical_group_id
                             AND v.asset_id = OLD.asset_id AND v.edge_state = 'active'
                             AND NOT (v.clarity = OLD.clarity AND v.derivation = OLD.derivation))
        BEGIN SELECT RAISE(ABORT, '该 asset 仍是本组 preferred 的最后 active 边, 先重指 preferred 再删'); END;
        CREATE TRIGGER IF NOT EXISTS trg_preferred_edge_retire
        BEFORE UPDATE OF edge_state ON variant
        WHEN OLD.edge_state = 'active' AND NEW.edge_state <> 'active'
             AND EXISTS (SELECT 1 FROM logical_media m WHERE m.logical_group_id = OLD.logical_group_id
                         AND m.preferred_asset_id = OLD.asset_id)
             AND NOT EXISTS (SELECT 1 FROM variant v WHERE v.logical_group_id = OLD.logical_group_id
                             AND v.asset_id = OLD.asset_id AND v.edge_state = 'active'
                             AND NOT (v.clarity = OLD.clarity AND v.derivation = OLD.derivation))
        BEGIN SELECT RAISE(ABORT, '该 asset 仍是本组 preferred 的最后 active 边, 先重指 preferred 再退役'); END;
        -- ③ 复审2 P1: variant 身份列(logical_group_id/asset_id/clarity/derivation, 即 PK)**不可 UPDATE** —— 上面 del/retire 守卫只盯
        -- DELETE 与 UPDATE OF edge_state; 若允许 `UPDATE variant SET logical_group_id='g2'` 把 preferred 的边搬到别组, 会绕过守卫留悬空
        -- preferred(串引用)。边是不可变身份, 变清晰度/派生/归属一律 retire 旧边 + 插新边(§七 高清作新 asset), 不原地改键。
        CREATE TRIGGER IF NOT EXISTS trg_variant_identity_immutable
        BEFORE UPDATE OF logical_group_id, asset_id, clarity, derivation ON variant
        WHEN NEW.logical_group_id <> OLD.logical_group_id OR NEW.asset_id <> OLD.asset_id
             OR NEW.clarity <> OLD.clarity OR NEW.derivation <> OLD.derivation
        BEGIN SELECT RAISE(ABORT, 'variant 身份列(group/asset/clarity/derivation)不可改, 退役旧边+插新边'); END;

        -- media_reference: **以 L1 message PK 为基** + 判别段 → group(§12-A: 不能只 message_id, 否则串引用/GC 误判)。
        -- **GC root**(active): media_reference→group→variant→asset 是主可达链。generation 供 GC / 引用撤销(§12-C)。
        -- 引擎契约: `media_seq` DEFAULT 0 是**载重字段** —— 一条消息挂多个媒体(合并转发/多图)时引擎**必须**为每个媒体位
        -- 递增 media_seq; 否则同 (account,source,native_id,role) 塌成一行(PK 冲突), 后写 REPLACE 冲掉前面全部媒体引用。
        CREATE TABLE IF NOT EXISTS media_reference (
            account_id_sha       TEXT NOT NULL,
            source               TEXT NOT NULL,
            source_native_id     TEXT NOT NULL,
            role                 TEXT NOT NULL,          -- media 判别(哪个媒体位)
            media_seq            INTEGER NOT NULL DEFAULT 0,
            logical_group_id     TEXT NOT NULL REFERENCES logical_media(logical_group_id),
            reference_generation INTEGER NOT NULL DEFAULT 0,   -- GC 比对
            last_seen_generation INTEGER NOT NULL DEFAULT 0,   -- §12-C 引用撤销(只完整覆盖扫描才撤「未见」)
            ref_state            TEXT NOT NULL DEFAULT 'active' CHECK (ref_state IN ('active','tombstoned')),
            PRIMARY KEY (account_id_sha, source, source_native_id, role, media_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_media_reference_group ON media_reference(logical_group_id);

        -- source_locator: 源身份 → group(§二 同源去重)。**GC root 仅在 retention='active' 时**(§12-E; 纯 provenance 行不永久
        -- 钉内容)—— 但无消息锚的扫盘孤图**只**被它系到 group(§12-B: 漏它则孤图入账即被误删)。
        -- source_state(复审 P2-3): §二/§九 把源级状态(源头没有/需扫盘/联网失败/blocked_missing_image_key/encrypted_no_plain_cache)
        --   落这里, 不作游离文字标签; 与 work_item 的执行态分开(源状态多来源共享, work 态是某次尝试的)。
        -- retention(复审 P2-3): 从自由文本收紧为 NULL(纯溯源) | 'active'(充当 root) —— 否则拼写漂移会静默改变 GC root 判定。
        -- 引擎契约(复审 P2-4): locator_key 必须是**带版本前缀的确定性编码**(如 'v1:<db_id>:<talker>:<local_id>:<svr_id>:<anchor>');
        --   编码一旦变必须 bump 版本并迁移, 否则同一源换编码 → 重复归组 / GC 误判。
        -- 引擎契约(复审 P3): 无消息锚的扫盘孤图, 其 locator retention **必须 = 'active'**(与入账同事务), 否则它不算 root → 孤图被误删。
        CREATE TABLE IF NOT EXISTS source_locator (
            locator_key      TEXT PRIMARY KEY NOT NULL,  -- 版本化确定性编码: 源库身份 + talker/local_id/svr_id/anchor(复审3 P2: NOT NULL)
            logical_group_id TEXT NOT NULL REFERENCES logical_media(logical_group_id),
            source_state     TEXT NOT NULL DEFAULT 'ok'
                             CHECK (source_state IN ('ok','source_absent','needs_scan','network_failed',
                                                     'blocked_missing_image_key','encrypted_no_plain_cache')),
            retention        TEXT CHECK (retention IS NULL OR retention = 'active'),  -- 'active' 才充当 root
            created_at       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_source_locator_group ON source_locator(logical_group_id);

        -- asset_registry: 对外 MediaRef{kind,key,version} → group(§二; §5c serve)。键**区别于** media_reference/source_locator。
        -- 复审 P2: **GC root**(§12-B 6 root 之一)—— 消息删后 media_reference tombstone, group 可能只剩本表系着(外部消费者仍
        -- 握 /media/{md5}); GC 不认它当 root 会把仍被 serve 的资产误删、且源消息已删=不可再生。引擎 GC 可达遍历必纳入本表。
        -- ref_version(复审 P1): 头像字节会变 → 必带非空 version(§一/§12-A), 各版独立 asset。CHECK 是存储层硬闸:
        -- 即便上层构造器被绕过, 空 version 的 avatar 引用也进不来, 否则同 locator 两版头像主键冲突 → 历史坍塌 / immutable-ETag 契约破。
        CREATE TABLE IF NOT EXISTS asset_registry (
            ref_kind         TEXT NOT NULL,
            ref_key          TEXT NOT NULL,
            ref_version      TEXT NOT NULL DEFAULT '',   -- 头像带 version; 其余空串
            logical_group_id TEXT NOT NULL REFERENCES logical_media(logical_group_id),
            PRIMARY KEY (ref_kind, ref_key, ref_version),
            CHECK (ref_kind <> 'avatar' OR ref_version <> '')
        );
        CREATE INDEX IF NOT EXISTS idx_asset_registry_group ON asset_registry(logical_group_id);

        -- avatar_capture: 头像历史(§12-A; 各版独立 asset)。**GC root**(旧头像可能只被它引用, §12-B)。
        CREATE TABLE IF NOT EXISTS avatar_capture (
            subject_id         TEXT NOT NULL,            -- 联系人身份
            asset_id           TEXT NOT NULL REFERENCES asset(asset_id),
            source_update_time INTEGER,
            captured_at        INTEGER NOT NULL,
            locator            TEXT,
            PRIMARY KEY (subject_id, asset_id)
        );
        CREATE INDEX IF NOT EXISTS idx_avatar_capture_asset ON avatar_capture(asset_id);

        -- pin: 显式保留(§12-B **GC root**; pin/unpin 见 §十三-5)。
        -- 复审 P1: **ON DELETE RESTRICT**(不是 CASCADE)—— pin 是「别删我」的显式 root; 若 CASCADE, 删 logical_media 会静默抹掉 pin、
        -- 连带 variant 级联消失、asset 随后可被 GC, pin 形同虚设。RESTRICT 强制**先显式 unpin** 才能删组(§十三-5 删要确认)。
        CREATE TABLE IF NOT EXISTS pin (
            logical_group_id TEXT PRIMARY KEY NOT NULL REFERENCES logical_media(logical_group_id) ON DELETE RESTRICT,
            reason           TEXT,
            pinned_at        INTEGER NOT NULL
        );

        -- attempt: provenance(§12-A 补丁2 落点; 追哪次尝试产哪个 asset)。**非 GC root**(纯 provenance, §12-B)。
        -- 复审 P2: result_asset_id 用 **ON DELETE SET NULL**(不是默认 RESTRICT)—— attempt 是 provenance 不该挡回收;
        -- 若 RESTRICT, 每次成功尝试写 result_asset_id 后该 asset 永远删不掉(FK 拒), provenance 悄悄变硬 GC 闸。
        -- SET NULL 保住「哪次尝试产过哪 asset」的行、只把资产指针置空, GC 可继续。
        -- 复审 P2-6: work_id 加 FK → work_item(否则拼错的 work_id 无法 fencing/恢复); RESTRICT 强制先清 attempt 再删 work_item。
        CREATE TABLE IF NOT EXISTS attempt (
            attempt_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id             TEXT NOT NULL,
            work_id            TEXT NOT NULL REFERENCES work_item(work_id) ON DELETE RESTRICT,
            source_fingerprint TEXT,
            key_fingerprint    TEXT,
            decoder_version    TEXT,
            result_asset_id    TEXT REFERENCES asset(asset_id) ON DELETE SET NULL,
            error_code         TEXT,
            attempted_at       INTEGER NOT NULL,
            -- F2 契约(codex P2): 成功记 result_asset_id / 失败记 error_code。**写入 XOR** 由 record_attempt() 的 ensure 保证
            -- (拦 (Some,Some)/(None,None), 给可读报错)。存储层 CHECK **只禁 (Some,Some)** —— result_asset_id 是 ON DELETE SET NULL,
            -- GC 删 asset 会把成功行 (Some,None)→(None,None); 若 CHECK 强制 XOR 会令该 UPDATE 违约 → abort 删除 → 每个入仓 asset
            -- 变成删不掉的硬 GC root(违 attempt 非-root 契约; 复审二轮 codex P1)。故容许 GC 后的 (None,None), 仅拦双非空歧义。
            CHECK (NOT (result_asset_id IS NOT NULL AND error_code IS NOT NULL))
        );
        CREATE INDEX IF NOT EXISTS idx_attempt_work ON attempt(work_id);

        -- work_item: 每工作项状态 + **lease fencing**(§二/§12-B; claim 递增 lease_epoch, 续租/提交 CAS 校验 → 过期 worker
        -- 永不能提交)。确定性 work_id = account+source_identity+source_native_id+role+observed_generation(§12-C)。**非 GC root**(§12-B)。
        -- 复审 P2-4: media_reference 判别段 (source/source_native_id/role/media_seq) 作**结构化列**存 —— 否则崩溃恢复只能从不透明
        -- work_id 串里反解「这活对应哪条消息哪个媒体位」。UNIQUE 自然键防同一 (媒体位×generation) 重复建 work。
        CREATE TABLE IF NOT EXISTS work_item (
            work_id             TEXT PRIMARY KEY NOT NULL,
            account_id_sha      TEXT NOT NULL,
            source_identity     TEXT NOT NULL,           -- 源 DB 身份(provenance; 与下方 media 判别段正交)
            source              TEXT NOT NULL,           -- media_reference.source(哪个消息源表)
            source_native_id    TEXT NOT NULL,           -- media_reference.source_native_id
            role                TEXT NOT NULL,           -- media_reference.role(哪个媒体位)
            media_seq           INTEGER NOT NULL DEFAULT 0,
            state               TEXT NOT NULL DEFAULT 'pending'
                                 CHECK (state IN ('pending','claimed','writing','verifying','publishing','done','failed')),
            lease_owner         TEXT,
            lease_epoch         INTEGER NOT NULL DEFAULT 0,
            lease_deadline      INTEGER,
            observed_generation INTEGER NOT NULL DEFAULT 0,
            retry_count         INTEGER NOT NULL DEFAULT 0,
            next_retry_at       INTEGER,                 -- §12-D 持久 UTC deadline
            error_code          TEXT,
            updated_at          INTEGER NOT NULL,
            -- 复审2 P2: 自然键必含 source_identity(§12-C work key = account+source_identity+source_native_id+role+observed_generation)
            -- —— 否则源 DB 轮换后两实例同 native_id/role/seq/generation 会撞键, 第二个合法 work 被 UNIQUE 误拒(native_id 跨库可重复)。
            UNIQUE (account_id_sha, source_identity, source, source_native_id, role, media_seq, observed_generation)
        );
        CREATE INDEX IF NOT EXISTS idx_work_item_state ON work_item(state);

        -- source_scan: 每源 discover cursor + 覆盖(§12-C; source-map = db×Msg表 各一条, 非单 cursor)。**非 GC root**(§12-B; 纯 cursor)。
        -- coverage=complete 才能撤「未见」引用(§12-C: 部分/失败扫描不得触发 GC)。
        CREATE TABLE IF NOT EXISTS source_scan (
            source_identity      TEXT PRIMARY KEY NOT NULL,
            keyset_watermark     TEXT,
            discovery_epoch      INTEGER NOT NULL DEFAULT 0,
            coverage             TEXT NOT NULL DEFAULT 'partial' CHECK (coverage IN ('partial','complete')),
            wal_generation       TEXT,
            snapshot_fingerprint TEXT,
            scanned_at           INTEGER
        );

        -- materialization_journal: 崩溃恢复(§四/§12-B; reserved→staged→verified→publish_intent→published→accounted)。
        -- 已 published 但未 accounted 的孤儿, 恢复须重验后收养/隔离(§四反例)。
        -- 复审 P2: **in-flight 行是 GC root**(§12-B 6 root 之一)—— asset 已落盘但引用未写(published 未 accounted)时,
        -- 并发 GC 不认 journal.asset_id 为 root 会删掉正入账的 asset。引擎 GC 遍历必把 未到 accounted 相位的 journal.asset_id 当 root。
        -- 复审 P2-6: work_id 加 FK → work_item(拼错的 journal 无法 fencing/恢复/充当 root); RESTRICT 保护 in-flight。
        -- 相位相关 CHECK: verified 起 asset_id 必有(已算出 sha256); published/accounted 起 final_path 必有(已 rename 入位)。
        -- 否则 phase='published' 却 asset_id/final_path 为空的坏行会骗过恢复协议(§四: published 文件须重验收养)。
        CREATE TABLE IF NOT EXISTS materialization_journal (
            journal_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            work_id      TEXT NOT NULL REFERENCES work_item(work_id) ON DELETE RESTRICT,
            asset_id     TEXT,
            phase        TEXT NOT NULL
                         CHECK (phase IN ('reserved','staged','verified','publish_intent','published','accounted')),
            staging_path TEXT,
            final_path   TEXT,
            updated_at   INTEGER NOT NULL,
            CHECK (phase IN ('reserved','staged') OR asset_id IS NOT NULL),
            CHECK (phase NOT IN ('published','accounted') OR final_path IS NOT NULL)
        );
        CREATE INDEX IF NOT EXISTS idx_journal_work ON materialization_journal(work_id);

        -- materialized_view_entry: by-chat 视图(§12-E; path/mode/asset/generation/state)。指针变只标 dirty 幂等重建;
        -- GC 删 asset 必级联清本表硬链入口(§12-E 自审逮: 否则硬链钉 inode 空间不回收)。**非 root**(可重建缓存)。
        CREATE TABLE IF NOT EXISTS materialized_view_entry (
            view_path       TEXT PRIMARY KEY NOT NULL,
            asset_id        TEXT NOT NULL REFERENCES asset(asset_id),
            link_mode       TEXT NOT NULL CHECK (link_mode IN ('linked','copied')),
            view_generation INTEGER NOT NULL DEFAULT 0,
            entry_state     TEXT NOT NULL DEFAULT 'clean' CHECK (entry_state IN ('clean','dirty')),
            updated_at      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_view_entry_asset ON materialized_view_entry(asset_id);
        ";

/// 建**全部账本表 + 约束触发器**(幂等)。**`pub(crate)` 不对外**(复审 P2): 不开 `foreign_keys` pragma —— 唯一对外入口是
/// [`open_ledger`], 它建 schema **前**开 `foreign_keys=ON`; 裸 `Connection` 直调本函数会 FK 关、孤儿可写入。
///
/// # Errors
/// rusqlite 执行失败(建表/索引/触发器)。
pub(crate) fn init_ledger_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(LEDGER_DDL)
        .context("建 mediastore 账本 schema 失败")?;
    Ok(())
}

/// 当前 [`LEDGER_DDL`] 的 sha256 hex 指纹(复审4 P1: schema 自动版本门禁)。
fn ddl_fingerprint() -> String {
    crate::sha256_hex(LEDGER_DDL)
}

/// 打开/建侧车账本 `ledger.db`, 建 schema, 校验/播种账号绑定(§12-A: 每次打开校验 account_id_sha + 迁移门禁, 复用 L1 模式)。
/// `account_id_sha` = 本仓归属账号(sha256(wxid)); 已有账本绑定不符 → 拒(防跨账号误用)。
///
/// # Errors
/// 打库 / 建 schema / 账号绑定不符 失败。
pub fn open_ledger(path: &std::path::Path, account_id_sha: &str, now: i64) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("打开账本 {} 失败", path.display()))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("开 foreign_keys 失败")?;
    // 复审2 P1: recursive_triggers=ON —— 默认(OFF)下 `INSERT OR REPLACE` 的隐式 DELETE **不触发** DELETE 触发器, preferred 守卫
    // 会被 REPLACE 绕过。开 ON 让 REPLACE / FK 级联的删都过 trg_preferred_edge_del(守卫只 RAISE 不改表, 无递归风险)。
    conn.pragma_update(None, "recursive_triggers", "ON")
        .context("开 recursive_triggers 失败")?;
    // 复审 P1/P3: 建表 + 账号绑定/版本校验放**同一事务** —— 否则"建表成功但写绑定前崩溃"会留下有表无账号的半成品库,
    // 下次别账号打开就把它静默收养。事务原子: (schema + 绑定) 要么全落, 要么回滚成空文件(下次当全新库重建)。
    let tx = conn.unchecked_transaction().context("开账本初始化事务失败")?;
    // 复审 P1/复审2 P1(fail-closed): 区分**真空库**与**残缺库** —— 建 schema 前看库里**是否已有任何用户表**(不只 schema_meta:
    // schema_meta 被删/损坏但 asset/media_reference 等数据表尚在的库, 只查 schema_meta 会误判成真空 → 为任意账号重绑定 = 账号串味)。
    // 有任何表却查不到账号绑定 = 半成品/损坏, 拒绝收养; 只有一张表都没有的真空库才播种。
    let had_any_table = any_user_table_exists(&conn)?;
    init_ledger_schema(&conn)?;
    match get_meta(&conn, META_ACCOUNT)? {
        None if had_any_table => {
            anyhow::bail!(
                "账本 {} 已有数据表却无账号绑定 —— 疑似半成品/损坏库(既往初始化未完成或 schema_meta 丢失), 拒绝自动收养; 请删账本重建或人工核查",
                path.display()
            );
        }
        None => {
            // 真空库首次播种(§12-A)。
            set_meta(&conn, META_VERSION, LEDGER_SCHEMA_VERSION, now)?;
            set_meta(&conn, META_ACCOUNT, account_id_sha, now)?;
            set_meta(&conn, META_MIGRATION, "[]", now)?;
            set_meta(&conn, META_FINGERPRINT, &ddl_fingerprint(), now)?; // 复审4 P1: 存 schema 指纹
        }
        Some(bound) if bound != account_id_sha => {
            anyhow::bail!(
                "账本 {} 绑定的是另一个账号 (sha8 {})，与请求账号 (sha8 {}) 不符 —— 换对应账号的仓, 或删账本重建",
                path.display(),
                bound.chars().take(8).collect::<String>(),
                account_id_sha.chars().take(8).collect::<String>()
            );
        }
        Some(_) => {
            // 账号相符 → 再过**版本迁移门禁**(§12-A; 复审 P3: 原实现只校账号不校版本, 是纯写不读的门)。
            // 现为 "5"(R14 起; v4→5 = 消息锚 8→32hex 语义变)。stored != current = 别的版本或损坏 → 拒(pre-1.0 不迁移, 删账本从源重建)。
            // R14: 版本不符抛 **SqliteFailure(SQLITE_MISMATCH)** 而非 anyhow bail —— CLI 边界 downcast 识别为 SchemaMismatch(退出6, 提示删库重建), 不归 INTERNAL。
            // 将来加 schema v6: 在此按 stored→current 跑迁移, 成功后 set_meta(META_VERSION, current) 并追加 migration_history。
            let stored = get_meta(&conn, META_VERSION)?.unwrap_or_default();
            if stored != LEDGER_SCHEMA_VERSION {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
                    Some(format!(
                        "账本 {} 的 schema 版本 {stored} 与本二进制支持的 {LEDGER_SCHEMA_VERSION} 不符 —— 删账本、从加密源重建(pre-1.0 不迁移)",
                        path.display()
                    )),
                )
                .into());
            }
            // 复审4 P1: schema **指纹**门禁(自动, 逮"DDL 改了但忘 bump 版本") —— 指纹缺失(旧库)或不符即拒。
            let stored_fp = get_meta(&conn, META_FINGERPRINT)?.unwrap_or_default();
            if stored_fp != ddl_fingerprint() {
                // R14(codex 复审 P2): 指纹门禁同版本门禁抛 SqliteFailure(SQLITE_MISMATCH) 而非 anyhow bail —— CLI downcast 统一归
                // SchemaMismatch(退出6, 提示删库重建), 否则指纹漂移(DDL 变忘 bump / 旧库无指纹)会掉回 INTERNAL/70、脚本分不清。
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
                    Some(format!(
                        "账本 {} 的 schema 指纹与当前二进制不符(DDL 已变或旧库无指纹)—— pre-1.0 不迁移, 删账本从源重建",
                        path.display()
                    )),
                )
                .into());
            }
        }
    }
    tx.commit().context("提交账本初始化失败")?;
    Ok(conn)
}

// 复审4 P1: 用 `ON CONFLICT DO UPDATE` 不用 `INSERT OR REPLACE` —— schema_meta 虽无子表(REPLACE 本安全), 但 CAS 表全域禁
// REPLACE(见 LEDGER_DDL 写入契约 + no_replace_in_cas_writes 关卡), 这里也统一, 免得成为"唯一豁免"被日后照抄到有子表的写。
fn set_meta(conn: &Connection, key: &str, value: &str, updated_at: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO schema_meta (key, value, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        rusqlite::params![key, value, updated_at],
    )?;
    Ok(())
}

fn get_meta(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM schema_meta WHERE key = ?1",
        rusqlite::params![key],
        |r| r.get(0),
    )
    .optional()
}

/// 库里是否已有**任何用户表**(排除 sqlite_ 内部表)。复审2 P1: open_ledger 建 schema 前区分真空库/残缺库用 ——
/// 只要有一张自己的表就算"非真空", 残缺库(schema_meta 丢了但数据表还在)也不会被误判成真空而被别账号收养。
fn any_user_table_exists(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

// @@GUARD:PROD_END@@  生产段到此为止; no_replace_in_cas_writes 只扫此标记之前(下方测试段故意用 REPLACE 验拦截)。
#[cfg(test)]
mod tests {
    use super::*;

    /// 掐掉一行的行尾注释(Rust `//` 或 SQL `--`, 取最早出现处), 返回代码部分。本文件生产段无字符串字面量含 `//`/`--`, 故安全。
    fn strip_line_comment(line: &str) -> &str {
        let mut end = line.len();
        if let Some(p) = line.find("//") {
            end = end.min(p);
        }
        if let Some(p) = line.find("--") {
            end = end.min(p);
        }
        &line[..end]
    }
    /// 去注释 + **归一化空白**(制表/换行/多空格→单空格)+ 大写 —— 复审5 P2: 防 `INSERT OR\tREPLACE\tINTO` / 跨行拆词逃过。
    fn normalize_sql(code: &str) -> String {
        code.lines()
            .map(strip_line_comment)
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_uppercase()
    }

    #[test]
    fn no_replace_in_cas_writes() {
        // 复审4 P1 关卡 + 复审5 P2 加固: CAS 写禁用 `INSERT OR REPLACE`/`REPLACE INTO`(REPLACE 隐式删旧行会静默丢 SET NULL 子的
        // provenance, SQLite 无法库级禁)。扫本文件**生产段**(显式 sentinel 之前; 测试段故意用 REPLACE 验拦截, 排除), 去注释 +
        // 归一化空白后按令牌短语查 —— 不再逐行按固定排版, 制表/续行/行尾注释都不漏不误。日后引擎写 CAS 表照抄 REPLACE 挡回退。
        // 扫 mediastore 里**所有写 CAS 表**的源文件(ledger.rs 建库+meta / engine.rs commit 入账); 各取 sentinel 之前生产段。
        for (name, src) in [
            ("ledger.rs", include_str!("ledger.rs")),
            ("engine.rs", include_str!("engine.rs")),
            ("voice.rs", include_str!("voice.rs")),
            ("video.rs", include_str!("video.rs")),
            ("image.rs", include_str!("image.rs")),
        ] {
            let prod = src.split("// @@GUARD:PROD_END@@").next().expect("sentinel 必在");
            let norm = normalize_sql(prod);
            assert!(
                !norm.contains("INSERT OR REPLACE"),
                "{name}: CAS 写禁 INSERT OR REPLACE(见 LEDGER_DDL 写入契约)"
            );
            assert!(
                !norm.contains("REPLACE INTO"),
                "{name}: CAS 写禁 REPLACE INTO(见 LEDGER_DDL 写入契约)"
            );
        }
        // 自证归一化真能逮住变体(制表/跨行), 不是纸面关卡。
        assert!(
            normalize_sql("INSERT OR\tREPLACE\tINTO x").contains("INSERT OR REPLACE"),
            "制表变体须逮到"
        );
        assert!(
            normalize_sql("REPLACE\n   INTO x").contains("REPLACE INTO"),
            "跨行变体须逮到"
        );
        // 行尾注释里的 REPLACE 不算(去注释后不触发)。
        assert!(
            !normalize_sql("SELECT 1; // 禁止 REPLACE INTO").contains("REPLACE INTO"),
            "注释里的不算"
        );
    }

    #[test]
    fn schema_inits_all_tables_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_ledger_schema(&conn).unwrap();
        init_ledger_schema(&conn).unwrap(); // 幂等
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for t in [
            "asset",
            "asset_presence",
            "asset_registry",
            "asset_role",
            "asset_source",
            "attempt",
            "avatar_capture",
            "logical_media",
            "materialization_journal",
            "materialized_view_entry",
            "media_reference",
            "pin",
            "schema_meta",
            "source_locator",
            "source_scan",
            "variant",
            "verification",
            "work_item",
        ] {
            assert!(tables.contains(&t.to_string()), "缺表 {t}; 实有 {tables:?}");
        }
    }

    #[test]
    fn open_ledger_binds_and_rejects_other_account() {
        let dir = std::env::temp_dir().join(format!("ms_ledger_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ledger.db");
        let _ = std::fs::remove_file(&p);
        {
            let conn = open_ledger(&p, "acctA_sha", 1000).unwrap();
            assert_eq!(get_meta(&conn, META_ACCOUNT).unwrap().as_deref(), Some("acctA_sha"));
        }
        // 同账号重开 OK
        assert!(open_ledger(&p, "acctA_sha", 2000).is_ok(), "同账号重开");
        // 别账号拒
        assert!(open_ledger(&p, "acctB_sha", 3000).is_err(), "跨账号必拒");
        let _ = std::fs::remove_file(&p);
    }

    /// 建内存账本 + foreign_keys ON + recursive_triggers ON(镜像 open_ledger, 让 REPLACE/级联触发守卫)。
    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn.pragma_update(None, "recursive_triggers", "ON").unwrap();
        init_ledger_schema(&conn).unwrap();
        conn
    }
    /// 合法 (asset_id, hex)。
    fn asset_pair(c: char) -> (String, String) {
        let hex = std::iter::repeat(c).take(64).collect::<String>();
        (format!("sha256:{hex}"), hex)
    }
    /// 插一条合法 asset, 返回 asset_id。
    fn ins_asset(conn: &Connection, c: char) -> String {
        let (id, hex) = asset_pair(c);
        conn.execute(
            "INSERT INTO asset(asset_id,hex,size,lifecycle,created_at) VALUES(?1,?2,10,'live',0)",
            rusqlite::params![id, hex],
        )
        .unwrap();
        id
    }

    #[test]
    fn foreign_key_and_check_enforced() {
        let conn = mem();
        let (id, hex) = asset_pair('a');
        // asset size 负 → CHECK 拒(用合法 hex 隔离出 size)。
        assert!(
            conn.execute(
                "INSERT INTO asset(asset_id,hex,size,created_at) VALUES(?1,?2,-1,0)",
                rusqlite::params![id, hex],
            )
            .is_err(),
            "size<0 违 CHECK"
        );
        // variant 指向不存在 asset → FK 拒
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g1',0)",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO variant(logical_group_id,asset_id) VALUES('g1','sha256:nope')",
                []
            )
            .is_err(),
            "variant→缺 asset 违 FK"
        );
    }

    #[test]
    fn asset_hex_canonical_and_unique() {
        let conn = mem();
        // asset_id 与 hex 不一致 → CHECK 拒
        assert!(
            conn.execute(
                "INSERT INTO asset(asset_id,hex,size,created_at) VALUES('sha256:aaa',?1,1,0)",
                rusqlite::params![std::iter::repeat('b').take(64).collect::<String>()],
            )
            .is_err(),
            "asset_id != 'sha256:'||hex 违 CHECK"
        );
        // 大写 hex → CHECK 拒(NTFS 大小写不敏感撞路径)
        let up = std::iter::repeat('A').take(64).collect::<String>();
        assert!(
            conn.execute(
                "INSERT INTO asset(asset_id,hex,size,created_at) VALUES(?1,?2,1,0)",
                rusqlite::params![format!("sha256:{up}"), up],
            )
            .is_err(),
            "大写 hex 违 CHECK"
        );
        // 复审2 P2: 非 hex 字符(小写但含 'z' / '/')→ CHECK 拒(字母表对齐 AssetId::parse)
        for bad in ["z".repeat(64), format!("{}/{}", "a".repeat(32), "b".repeat(31))] {
            assert!(
                conn.execute(
                    "INSERT INTO asset(asset_id,hex,size,created_at) VALUES(?1,?2,1,0)",
                    rusqlite::params![format!("sha256:{bad}"), bad],
                )
                .is_err(),
                "非 hex 字符违 CHECK: {bad}"
            );
        }
        // 复审2 P2: asset_id = NULL 配合法 hex → NOT NULL 拒(SQLite 非 INTEGER PK 允许 NULL 的历史坑)
        assert!(
            conn.execute(
                "INSERT INTO asset(asset_id,hex,size,created_at) VALUES(NULL,?1,1,0)",
                rusqlite::params![std::iter::repeat('c').take(64).collect::<String>()],
            )
            .is_err(),
            "NULL asset_id 违 NOT NULL"
        );
        // 合法插入 OK; 同 hex 再插 → UNIQUE 拒
        ins_asset(&conn, 'a');
        let (id2, hex2) = (format!("sha256:{}", "a".repeat(64)), "a".repeat(64));
        assert!(
            conn.execute(
                "INSERT INTO asset(asset_id,hex,size,created_at) VALUES(?1,?2,1,0)",
                rusqlite::params![id2, hex2],
            )
            .is_err(),
            "重复 hex 违 UNIQUE"
        );
    }

    #[test]
    fn preferred_must_be_active_group_member() {
        let conn = mem();
        let a = ins_asset(&conn, 'a');
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g1',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO variant(logical_group_id,asset_id,clarity,derivation,edge_state) VALUES('g1',?1,'original','none','active')",
            rusqlite::params![a],
        )
        .unwrap();
        // 指本组 active 成员 → OK
        conn.execute(
            "UPDATE logical_media SET preferred_asset_id=?1 WHERE logical_group_id='g1'",
            rusqlite::params![a],
        )
        .unwrap();
        // 跨组: g2 preferred=A(A 非 g2 成员)→ 触发器拒(串引用)
        assert!(
            conn.execute(
                "INSERT INTO logical_media(logical_group_id,preferred_asset_id,created_at) VALUES('g2',?1,0)",
                rusqlite::params![a],
            )
            .is_err(),
            "跨组 preferred 必拒"
        );
        // 退役 preferred 的最后 active 边 → 触发器拒(§12-E 先重指再退役)
        assert!(
            conn.execute(
                "UPDATE variant SET edge_state='retired' WHERE logical_group_id='g1' AND asset_id=?1",
                rusqlite::params![a],
            )
            .is_err(),
            "退役 preferred 最后 active 边必拒"
        );
    }

    #[test]
    fn variant_identity_immutable_and_replace_guarded() {
        // 复审2 P1: 堵住上一版触发器绕过的两条路 —— UPDATE 搬边 + INSERT OR REPLACE。
        let conn = mem();
        let a = ins_asset(&conn, 'a');
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g1',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g2',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO variant(logical_group_id,asset_id,clarity,derivation,edge_state) VALUES('g1',?1,'original','none','active')",
            rusqlite::params![a],
        )
        .unwrap();
        conn.execute(
            "UPDATE logical_media SET preferred_asset_id=?1 WHERE logical_group_id='g1'",
            rusqlite::params![a],
        )
        .unwrap();
        // ① 搬边到别组(UPDATE logical_group_id)→ trg_variant_identity_immutable 拒(否则 g1.preferred 悬空)
        assert!(
            conn.execute(
                "UPDATE variant SET logical_group_id='g2' WHERE logical_group_id='g1' AND asset_id=?1",
                rusqlite::params![a]
            )
            .is_err(),
            "UPDATE 搬 variant 归属必拒"
        );
        // ② INSERT OR REPLACE 把 active 边换成 retired 边 → recursive_triggers=ON 下隐式 DELETE 触发守卫, 拒
        assert!(
            conn.execute(
                "INSERT OR REPLACE INTO variant(logical_group_id,asset_id,clarity,derivation,edge_state) VALUES('g1',?1,'original','none','retired')",
                rusqlite::params![a],
            )
            .is_err(),
            "REPLACE 退役 preferred 最后 active 边必拒(recursive_triggers)"
        );
    }

    #[test]
    fn explicit_group_teardown_under_restrict() {
        // 复审3 P1: variant→logical_media 改 RESTRICT 后, 一步删有 variant 的组必被挡; 正确拆除 = 清 preferred → 删 variant → 删组
        // (显式有序, 与 §12-E 先退役边再 tombstone 一致; 也堵死 REPLACE 父组静默清空成员)。
        let conn = mem();
        let a = ins_asset(&conn, 'a');
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO variant(logical_group_id,asset_id,clarity,derivation,edge_state) VALUES('g',?1,'original','none','active')",
            rusqlite::params![a],
        )
        .unwrap();
        conn.execute(
            "UPDATE logical_media SET preferred_asset_id=?1 WHERE logical_group_id='g'",
            rusqlite::params![a],
        )
        .unwrap();
        // 一步删组 → RESTRICT 挡(variant 还引用它)
        assert!(
            conn.execute("DELETE FROM logical_media WHERE logical_group_id='g'", [])
                .is_err(),
            "有 variant 一步删组必被 RESTRICT 挡"
        );
        // 显式拆除: 清 preferred → 删 variant → 删组
        conn.execute(
            "UPDATE logical_media SET preferred_asset_id=NULL WHERE logical_group_id='g'",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM variant WHERE logical_group_id='g'", [])
            .unwrap();
        conn.execute("DELETE FROM logical_media WHERE logical_group_id='g'", [])
            .expect("清子后删组成功");
    }

    #[test]
    fn replace_on_parent_tables_blocked() {
        // 复审3 P1(结构性封): INSERT OR REPLACE 父表(asset/logical_media)不再能静默清空 CASCADE 子 —— RESTRICT 让隐式 DELETE 失败。
        let conn = mem();
        let a = ins_asset(&conn, 'a');
        conn.execute(
            "INSERT INTO asset_presence(asset_id,state,checked_at) VALUES(?1,'ready',0)",
            rusqlite::params![a],
        )
        .unwrap();
        // REPLACE 有子(presence)的 asset → RESTRICT 挡, 且 presence 没被静默清
        assert!(
            conn.execute(
                "INSERT OR REPLACE INTO asset(asset_id,hex,size,created_at) VALUES(?1,?2,10,1)",
                rusqlite::params![a, "a".repeat(64)],
            )
            .is_err(),
            "REPLACE 有子的 asset 必被 RESTRICT 挡"
        );
        let pcount: i64 = conn
            .query_row("SELECT count(*) FROM asset_presence", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pcount, 1, "asset_presence 未被 REPLACE 静默清空");
        // REPLACE 有 variant 的 group → RESTRICT 挡, variant 保留
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g',0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO variant(logical_group_id,asset_id,clarity,derivation,edge_state) VALUES('g',?1,'original','none','active')",
            rusqlite::params![a],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT OR REPLACE INTO logical_media(logical_group_id,created_at) VALUES('g',999)",
                []
            )
            .is_err(),
            "REPLACE 有 variant 的组必被 RESTRICT 挡"
        );
        let vcount: i64 = conn
            .query_row("SELECT count(*) FROM variant WHERE logical_group_id='g'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(vcount, 1, "variant 未被 REPLACE 静默清空");
    }

    #[test]
    fn null_pk_rejected_on_swept_tables() {
        // 复审3 P2: 单列 TEXT PK 全补 NOT NULL —— 抽查两张验 NULL 被拒。
        let conn = mem();
        assert!(
            conn.execute("INSERT INTO schema_meta(key,value,updated_at) VALUES(NULL,'v',0)", [])
                .is_err(),
            "schema_meta NULL key 拒"
        );
        assert!(
            conn.execute(
                "INSERT INTO work_item(work_id,account_id_sha,source_identity,source,source_native_id,role,updated_at) \
                 VALUES(NULL,'a','s','s','n','r',0)",
                [],
            )
            .is_err(),
            "work_item NULL work_id 拒"
        );
    }

    #[test]
    fn variant_state_and_confidence_updates_allowed() {
        // 复审2 自锁: trg_variant_identity_immutable 只该挡 PK 列; 合法的 edge_state 退役 / confidence 重评必须放行(非 preferred 边)。
        let conn = mem();
        let a = ins_asset(&conn, 'a');
        let b = ins_asset(&conn, 'b');
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g',0)",
            [],
        )
        .unwrap();
        for id in [&a, &b] {
            conn.execute(
                "INSERT INTO variant(logical_group_id,asset_id,clarity,derivation,edge_state) VALUES('g',?1,'original','none','active')",
                rusqlite::params![id],
            )
            .unwrap();
        }
        // preferred 指 a; 退役 b(非 preferred)→ 放行
        conn.execute(
            "UPDATE logical_media SET preferred_asset_id=?1 WHERE logical_group_id='g'",
            rusqlite::params![a],
        )
        .unwrap();
        conn.execute(
            "UPDATE variant SET edge_state='retired' WHERE logical_group_id='g' AND asset_id=?1",
            rusqlite::params![b],
        )
        .expect("退役非 preferred 边应放行");
        // 改 confidence(非身份列)→ 放行
        conn.execute(
            "UPDATE variant SET confidence=0.5 WHERE logical_group_id='g' AND asset_id=?1",
            rusqlite::params![a],
        )
        .expect("改 confidence 应放行");
    }

    #[test]
    fn avatar_registry_requires_version() {
        let conn = mem();
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g',0)",
            [],
        )
        .unwrap();
        assert!(
            conn.execute(
                "INSERT INTO asset_registry(ref_kind,ref_key,ref_version,logical_group_id) VALUES('avatar','loc','','g')",
                [],
            )
            .is_err(),
            "avatar 空 version 违 CHECK"
        );
        conn.execute(
            "INSERT INTO asset_registry(ref_kind,ref_key,ref_version,logical_group_id) VALUES('avatar','loc','v1','g')",
            [],
        )
        .unwrap();
        // 非头像空 version OK
        conn.execute(
            "INSERT INTO asset_registry(ref_kind,ref_key,ref_version,logical_group_id) VALUES('chat_image','md5','','g')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn pin_restrict_blocks_group_delete() {
        let conn = mem();
        conn.execute(
            "INSERT INTO logical_media(logical_group_id,created_at) VALUES('g',0)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO pin(logical_group_id,pinned_at) VALUES('g',0)", [])
            .unwrap();
        assert!(
            conn.execute("DELETE FROM logical_media WHERE logical_group_id='g'", [])
                .is_err(),
            "pin RESTRICT 挡删组(须先 unpin)"
        );
    }

    #[test]
    fn journal_fk_and_phase_checks() {
        let conn = mem();
        conn.execute(
            "INSERT INTO work_item(work_id,account_id_sha,source_identity,source,source_native_id,role,updated_at) \
             VALUES('w1','acct','sid','src','nid','r',0)",
            [],
        )
        .unwrap();
        // 坏 work_id → FK 拒
        assert!(
            conn.execute(
                "INSERT INTO materialization_journal(work_id,phase,updated_at) VALUES('nope','reserved',0)",
                []
            )
            .is_err(),
            "journal 坏 work_id 违 FK"
        );
        // published 却 final_path 空 → CHECK 拒
        assert!(
            conn.execute(
                "INSERT INTO materialization_journal(work_id,asset_id,phase,final_path,updated_at) \
                 VALUES('w1','sha256:x','published',NULL,0)",
                [],
            )
            .is_err(),
            "published 无 final_path 违 CHECK"
        );
        // reserved 相位允许 asset_id/final_path 空 → OK
        conn.execute(
            "INSERT INTO materialization_journal(work_id,phase,updated_at) VALUES('w1','reserved',0)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn open_ledger_rejects_partial_and_version_drift() {
        let dir = std::env::temp_dir().join(format!("ms_ledger_pv_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 残缺库: 有 schema_meta 表但无账号绑定 → open_ledger 拒收养
        let p1 = dir.join("partial.db");
        let _ = std::fs::remove_file(&p1);
        {
            let c = Connection::open(&p1).unwrap();
            c.execute(
                "CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL)",
                [],
            )
            .unwrap();
        }
        assert!(open_ledger(&p1, "acct", 0).is_err(), "残缺库(有表无账号)必拒");
        let _ = std::fs::remove_file(&p1);
        // 复审2 P1: schema_meta 丢了但**数据表还在**的残缺库 → 也必拒(had_any_table, 否则别账号收养 = 串味)
        let p1b = dir.join("partial_nometa.db");
        let _ = std::fs::remove_file(&p1b);
        {
            let c = Connection::open(&p1b).unwrap();
            c.execute("CREATE TABLE asset(asset_id TEXT PRIMARY KEY, hex TEXT)", [])
                .unwrap();
        }
        assert!(open_ledger(&p1b, "acct", 0).is_err(), "有数据表无 schema_meta 也必拒");
        let _ = std::fs::remove_file(&p1b);
        // 版本漂移: 篡改 version 后重开 → 拒
        let p2 = dir.join("ver.db");
        let _ = std::fs::remove_file(&p2);
        {
            let c = open_ledger(&p2, "acct", 0).unwrap();
            c.execute("UPDATE schema_meta SET value='999' WHERE key='version'", [])
                .unwrap();
        }
        assert!(open_ledger(&p2, "acct", 1).is_err(), "版本不符必拒");
        let _ = std::fs::remove_file(&p2);
        // 复审4 P1: 指纹漂移(版本仍对但 DDL 变了模拟成篡改指纹)→ 拒; 且首开确实种了指纹。
        let p3 = dir.join("fp.db");
        let _ = std::fs::remove_file(&p3);
        {
            let c = open_ledger(&p3, "acct", 0).unwrap();
            assert_eq!(
                get_meta(&c, META_FINGERPRINT).unwrap().as_deref(),
                Some(ddl_fingerprint().as_str()),
                "首开种指纹"
            );
            c.execute(
                "UPDATE schema_meta SET value='deadbeef' WHERE key='schema_fingerprint'",
                [],
            )
            .unwrap();
        }
        assert!(
            open_ledger(&p3, "acct", 1).is_err(),
            "指纹不符必拒(DDL 变了没 bump 版本也逮得到)"
        );
        let _ = std::fs::remove_file(&p3);
    }
}
