# L1 SQLite Schema 数据库设计

> **状态**: Level C (§11.5-1 第 1 件交付, 主文档)
> **责任**: 本地缓存 Tier 1 SQLite 表结构 + capability_backlog + migration 脚本
> **关联**: §11.5-1 / ADR-401 (本件 L1 表结构定型) / 待 ADR-402 (migration 策略)
> **基线**: 需求文档 v3.6.1-frozen §5.3 (capability backlog) / §6.6 (多账号) / §6.8 (raw_payload 契约)
> **单一真相**: 本文档 = L1 schema 契约源, 其他文档不准复制字段, 只能引用本文件 §3 / §4

---

## 1. L1 是什么

```
L1 SQLite = 用户机器上的【本地数据库】 — 两层职能合一:
   · 事件溯源层: adapter emit 流的本地落点 (raw_payload_archive 必写, 不依赖用户操作)
   · 缓存加速层: 用户主动 cache add 后, 高频 chat 业务表填充 (可选, 不写也跑)

用户主动 `native-cli cache add <chat>` 后:
   · 把高频 chat 数据从源 db 复制 + 解码 + 写入 L1 业务表 (message / person / ...)
   · 后续查询走 L1 业务表, 不再回源 db (快 10-100 倍)

不论用户是否 cache add:
   · adapter 跑起来就持续写 raw_payload_archive (D4 强约束 + 24h 重放窗口)
   · 业务表 cache 跟 archive 是【独立两层】, 责任分清

每个 wxid 独立 L1 文件 (多账号物理隔离 — 需求 §6.6):
   %LOCALAPPDATA%\native-cli\cache\<wxid_sha>.db
```

## 2. Architecture Invariants 红线

```
⚠️ 每个 wxid 独立 L1 文件, 不共用
   理由: 多账号物理隔离 (需求 §6.6 — sidecar 共享无状态, key 缓存 / 数据 wxid 独立)
   实现: cache_dir/<wxid_sha>.db, CLI --wxid 切换打开不同文件

⚠️ raw_payload_archive 必须先写 payload_json (经隐私过滤的 raw_payload JSON), 然后 emit / 写业务表
   理由: 故障恢复 (需求 §6.8 契约 5) + 事件溯源 (D4 强约束) + R5 红线 (ADR-426 §2.2 翻: archive 默认明文 canonical)
   实现: SqliteSink.write_*_with_archive() 用事务级保证, archive + business 同事务
   关键: archive.payload_json【不准存】 完整 sidecar 原始行 — 否则源 db 原字段明文 / 联系人备注昵称 等会进 L1, 打穿 R5
        ADR-426 §2.2: archive 默认明文 (第一类真值入 payload canonical); 出边界默认明文 (ADR-427 翻转); opt-in 脱敏时才 _sha / _len (机制保留)
        具体过滤规则跟 §6.14 笛卡尔积联动, 钉在 §11.5-8 ADR-412

⚠️ raw_payload_archive UNIQUE = 5 元组
   (account_id_sha, source, source_native_id, event_action, event_seq)
   理由: 需求 §6.8 契约 3 (a)(b)(c)(d) 4 条行为约束的最小满足集
        · (a) 多账号 + 多源 db 隔离 → account_id_sha + source
        · (b) 撤回不被吞 → event_action
        · (c) 同事件多实例区分 (群成员先退后加再退) → event_seq
        · (d) 重放去重 → 同事件唯一键相同, 上层去重
   event_seq 生成规则: 由确定性 fingerprint 算法生成, 同一真实事件重放必须生成相同 seq
        【不准用 MAX(seq)+1 自增】 — 会让 WAL 重读 / cursor 重置后同事件得不同键, 违反契约 3 (d)
        具体 fingerprint 算法在 §11.5-8 ADR-413 钉死, 本 ADR archive 跟随
   字段组成最终钉死权在 §11.5-8 ADR-413, 本文档跟随

⚠️ schema_meta 必须有, 记录版本号 + migration 历史
   理由: 升级时知道当前在哪一版, 跑哪些 migration; capability_backlog 状态聚合
   实现: 每 L1 文件 schema_meta 第一行写 (version, '1', now())

⚠️ L1 schema 跟 raw_payload 字段集【对应】 但【不强相等】
   raw_payload = 事件流 (有 event_action 子分)
   L1 = 业务表 (按业务实体存)
   两者【不同模型】, 需要 L1.5 转化层 (上层应用做)

⚠️ 28 缺口字段【不准】 进 alpha schema 占位 (需求 §5.3 D 路线)
   理由: 占位会变 NULL 假合同 (SELECT wallet_amount → NULL 误判"无红包")
   实现: 进 capability_backlog 表跟踪, 0.2.0+ 真挖到字段时 ALTER ADD COLUMN (显式 schema 变化)

⚠️ 所有【含业务实体】 业务表 + archive + 6 张地图表 (含 etl_state) 必含 account_id_sha 列
   理由: 跟需求 §6.8 契约 3 (a) 多账号隔离对齐; 即使物理分库下冗余, 设计层一致性
   实现: account_id_sha 列 NOT NULL, 写入时校验 = 当前 db 的 wxid

   【豁免清单】 (单 db 文件【登记表】 性质, 不含 account_id_sha 列):
      · schema_meta (§3.1.1) — key-value 元数据, 自身存 ('account_id_sha', '<wxid_sha>') 行锁定文件归属
      · capability_backlog (§3.1.9) — 28 字段【每个 L1 文件内的同构副本】 (非物理共享 1 行);
                                       行【内容】 跨 wxid 文件一致, 但物理上每文件 1 行, 由 v1 seed + migration 事务保证软一致
                                       跨文件一致性维护机制详 §4.5
   理由: 这两张是【文件级登记】 表, 强加 account_id_sha 列纯冗余无语义
```

---

## 3. 表结构 (完整 DDL — alpha 范围)

> **⚠️ ADR-427 (默认明文)**: 系统默认输出明文真值。下文"默认 sha 模式"现指 **opt-in 脱敏档** (`--redact-payload`), 保留作命名对照, **非系统默认**。
> 字段命名风格: snake_case, sha 字段以 `_sha` 后缀标识 (默认 sha 模式; plaintext 模式下值是真字符串)
>
> 长度字段 `_len` (e.g. `nick_name_len`) 留作【默认 sha 模式下的长度元数据】 — 上层判断"有没有备注 / 大概多长", 不泄露内容

### 3.1 alpha 业务表 (29 张)

#### 3.1.1 schema_meta — 版本号 + migration 历史 + 状态聚合

> **登记表性质** (跟 §2 红线豁免清单): 本表【无 account_id_sha 列】 — 自身存 `('account_id_sha', '<wxid_sha>')` 行锁定本文件归属, 不需要在每行重复

```sql
CREATE TABLE IF NOT EXISTS schema_meta (
    key                 TEXT    NOT NULL,
    value               TEXT    NOT NULL,
    updated_at          INTEGER NOT NULL,
    PRIMARY KEY (key)
);

-- 初始化插入 (用 unixepoch() 取当前时间):
-- ('version',           '1',                       unixepoch())
-- ('created_at',        '<unix_ts>',               unixepoch())
-- ('app_version',       '0.1.0-alpha',             unixepoch())
-- ('migration_history', '[]',                      unixepoch())
--    JSON 数组, 初始空; v1 自身【不算 migration】, 只记真实跨版本 (v1→v2 起追加)
-- ('account_id_sha',    '<wxid_sha>',              unixepoch())
--    锁定本文件归属, 业务表写入时校验 account_id_sha = 本行 value
```

#### 3.1.2 raw_payload_archive — 事件溯源 + 24h 重放窗口

```sql
CREATE TABLE IF NOT EXISTS raw_payload_archive (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,         -- e.g. "message_5.db"
    source_native_id    TEXT    NOT NULL,         -- e.g. "Msg_<md5>:86680"
    event_type          TEXT    NOT NULL,         -- "message" / "contact_update" / "chatroom_update" / "sns_event" / "system_event"
    event_action        TEXT    NOT NULL,         -- "create" / "recall" / "update" / "member_add" / "member_remove" / "cursor_update" / "error" / ...
    event_seq           INTEGER NOT NULL,         -- 同 action 多实例区分; 由确定性 fingerprint 算法生成 (详 §11.5-8 ADR-413)
    ingest_time         INTEGER NOT NULL,         -- adapter emit 时间 (不是源消息时间)
    payload_json        TEXT    NOT NULL,         -- 经 raw_payload 第一层标准化 + 隐私过滤后的 payload JSON
                                                  -- 【不准】 存完整 sidecar exec_query 原始行 (会含源 db 原字段明文 / 联系人备注昵称等)
                                                  -- 默认 sha 模式: 敏感字段只 _sha / _len; plaintext 模式才允许明文字段
                                                  -- 具体过滤规则: §11.5-8 ADR-412 钉死; 跟 §6.14 笛卡尔积联动
    UNIQUE (account_id_sha, source, source_native_id, event_action, event_seq)
);

CREATE INDEX IF NOT EXISTS idx_archive_account_ingest
    ON raw_payload_archive (account_id_sha, ingest_time DESC);
    -- 24h 滚动删除用 (DELETE WHERE ingest_time < unixepoch() - 86400)

CREATE INDEX IF NOT EXISTS idx_archive_event_type
    ON raw_payload_archive (event_type, event_action);
    -- 按事件类型 / action 过滤回放
```

> **关键决策记录** (跟 ADR-401 §3 同步):
> · `event_type` 列冗余于 source_native_id (一定程度上)? 否, source_native_id 跨 event_type 复用 — e.g. message + contact_update 都可能用同一 wxid 做 native_id; 需要 event_type 列做路由
> · `event_seq` 生成规则: **由确定性 fingerprint 算法生成** — 同一真实事件不论 emit 几次, fingerprint 必须给出相同 seq; 不同真实事件 (含同 native_id 同 action 但实际是新实例) 必须不同 seq. 算法细节钉在 §11.5-8 ADR-413.
> · **【不准用 MAX(seq)+1 自增】 反例**: WAL 重读 / cursor 重置导致同一真实事件被 adapter 重新读到 → MAX+1 → 新 seq → archive 唯一键不同 → INSERT OR IGNORE 不去重 → 上层认为是新事件 → 违反契约 3 (d) "重放去重"
> · `payload_json` 命名: 早期草稿写 `raw_json` 暗示"完整原始行", 跟 R5 默认 sha 红线冲突 (codex r1 P0-A); 改 `payload_json` 强调【经标准化 + 隐私过滤后的 payload】

#### 3.1.3 message — 消息业务表

```sql
CREATE TABLE IF NOT EXISTS message (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,
    conv_id_sha         TEXT    NOT NULL,         -- chat id (单聊=对方wxid, 群=chatroom@chatroom)
    server_id           INTEGER NOT NULL,
    server_seq          INTEGER NOT NULL DEFAULT 0, -- 服务端消息序号 (账号级同步序号; 批A/ADR-453, L2-only 不进 digest; ~90%为0, 0→N后变)
    create_time         INTEGER NOT NULL,
    sort_seq            INTEGER NOT NULL,         -- 微信内排序 (create_time*1000+本地序)
    status              INTEGER NOT NULL,
    msg_type            INTEGER NOT NULL,
    msg_type_name       TEXT    NOT NULL,         -- "TEXT" / "IMAGE" / ...
    msg_sub_type        INTEGER,                  -- nullable
    msg_sub_type_name   TEXT,
    local_type_raw      INTEGER NOT NULL,         -- 微信源 db 原 localType
    sender_wxid_sha     TEXT    NOT NULL,
    is_chatroom         INTEGER NOT NULL,         -- 0/1 boolean
    text_content_sha    TEXT    NOT NULL,
    text_content_len    INTEGER NOT NULL,
    raw_xml_present     INTEGER NOT NULL,         -- 0/1 — 是否有 XML payload (引用 / 卡片等)
    decode_kind         TEXT    NOT NULL,         -- "plain" / "zstd" / "proto" / "xml" / "decode_failed"
    sys_type            TEXT,                     -- 系统消息(type 10000)分类 revoke/pat/hongbao/transfer/topmsg/member_join/member_remove/other (批F/ADR-458, nullable, L2-only 不进 digest); 非系统消息 NULL
    -- 明文列 (ADR-426 §2.1 第一类真实数据; 与对应 _sha 同源, project_message 统一构造)。
    account_id          TEXT    NOT NULL,         -- = account_id_sha 的明文 wxid
    conv_id             TEXT    NOT NULL,         -- = conv_id_sha 的明文 (对方 wxid / chatroom@chatroom)
    sender_wxid         TEXT    NOT NULL,         -- = sender_wxid_sha 的明文 wxid
    text_content        TEXT    NOT NULL,         -- = text_content_sha 的明文正文
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_message_conv_time
    ON message (account_id_sha, conv_id_sha, create_time DESC);
    -- 主查询路径: 某 chat 的消息按时间倒序

CREATE INDEX IF NOT EXISTS idx_message_server_id
    ON message (account_id_sha, server_id);
    -- 服务端 id 反查

CREATE INDEX IF NOT EXISTS idx_message_type
    ON message (account_id_sha, msg_type);
    -- 按类型过滤 (e.g. 只看图片)

CREATE INDEX IF NOT EXISTS idx_message_conv_time_full
    ON message (account_id_sha, conv_id_sha, create_time DESC, source_native_id DESC, source DESC);
    -- 2026-07-27 加: 上面那条 idx_message_conv_time 只覆盖到 create_time, 而「取某会话最近 N 条」的
    -- ORDER BY 是三键 (create_time DESC, source_native_id DESC, source DESC) —— 后两键要 source 是因为
    -- 一个会话跨多个分片是常态、两边 local_id 会重号, 主键尾就是 (source, source_native_id)。
    -- 索引只覆盖第一键时 SQLite 得建临时 B 树把整个会话排一遍: 210 万条的群实测 4.2 秒。
    -- 补全三键后走纯 SEARCH, 0.1 毫秒。
    -- ⚠️ 只有**可写**开库(ingest / 查询侧补数)才会建它; 只读打开或拷到别的机器的冷库拿不到,
    --   那些场景仍是慢的 —— 目前没有迁移命令, 这是已知缺口。

CREATE INDEX IF NOT EXISTS idx_message_hongbao_claim_send
    ON message_hongbao_claim (account_id_sha, send_native_id);
    -- 红包领取记录按发出方消息反查
```

> **本节与 `native_core::storage::init_message_table` 必须逐条一致** —— 有测试守着
> (`schema_doc_lists_every_message_index`), 加索引不更新本节会红。
> 曾经漂过: 2026-07-27 加 `idx_message_conv_time_full` 时只改了代码, 本节漏了两条, 补审才发现。

> alpha 28 缺口字段不在本表 — 见 §4 capability_backlog

#### 3.1.4 person — 联系人主表

```sql
CREATE TABLE IF NOT EXISTS person (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,         -- = Contact_<md5 前8位>; 溯源/archive 用, 不当主键 (会撞)
    username_sha        TEXT    NOT NULL,         -- 联系人 wxid 全长 sha; 身份键 (不撞)
    -- 明文列 (ADR-426 §2.1 第一类真实数据; 与对应 _sha 同源, project_person 统一构造保证一致)。
    account_id          TEXT    NOT NULL,
    username            TEXT    NOT NULL,
    nick_name           TEXT    NOT NULL,
    remark              TEXT,
    alias               TEXT,
    nick_name_len       INTEGER NOT NULL,
    remark_len          INTEGER NOT NULL,
    alias_len           INTEGER NOT NULL,
    local_type          INTEGER NOT NULL,         -- 微信 contact type (1=好友 / 4=群成员 / ...)
    is_in_chat_room     INTEGER NOT NULL,
    -- 拼音搜索列 (字段扩充第一批 2026-07-01; 明文 nullable, 搜索用, 不进 content_digest — 派生自 nick/remark)。
    quan_pin               TEXT,
    pin_yin_initial        TEXT,
    remark_quan_pin        TEXT,
    remark_pin_yin_initial TEXT,
    -- 状态标志 (字段扩充第二批 2026-07-01; 进 content_digest — 独立状态溯源, ADR-412 §3.x.2 + 双绑 ADR-413;
    --   INTEGER NOT NULL DEFAULT 0 → 旧库 ALTER ADD 补列不报错)。
    verify_flag         INTEGER NOT NULL DEFAULT 0,
    delete_flag         INTEGER NOT NULL DEFAULT 0,
    -- 头像列 (字段扩充第三批 2026-07-02; 资源明文 nullable; 进 L2 不进 content_digest — 用户选 1 不溯源换头像)。
    big_head_url        TEXT,
    small_head_url      TEXT,
    head_img_md5        TEXT,
    -- 补充列 (字段扩充第五批 2026-07-02; 进 L2 不进 content_digest — 同头像 L2-only, ADR-450 §3;
    --   description 明文 nullable; flag/chat_room_notify/chat_room_type INTEGER NOT NULL DEFAULT 0 → 旧库 ALTER ADD 补列)。
    description         TEXT,
    flag                INTEGER NOT NULL DEFAULT 0,
    chat_room_notify    INTEGER NOT NULL DEFAULT 0,
    chat_room_type      INTEGER NOT NULL DEFAULT 0,
    -- 扩展属性 (字段扩充第七批 2026-07-02; extra_buffer proto 解出; 进 L2 不进 content_digest — ADR-450 §3;
    --   地区存英文/ISO 码 CN/Zhejiang/Hangzhou 非中文, 底座照原样; sex 0未知/1男/2女)。
    sex                 INTEGER NOT NULL DEFAULT 0,
    country             TEXT,
    province            TEXT,
    city                TEXT,
    friend_source       INTEGER NOT NULL DEFAULT 0,
    -- flag 位解码 (字段扩充批G 2026-07-03; 采同行 WDA 位定义; 进 L2 不进 content_digest — ADR-459/450 §3)。
    --   星标 bit6 / 置顶 bit11(WDA 代码确认) / 屏蔽朋友圈 bit16 / 仅聊天 bit23 (0-based; WDA "第N位" 1-based)。
    is_starred          INTEGER NOT NULL DEFAULT 0,
    is_pinned           INTEGER NOT NULL DEFAULT 0,
    blocks_moments      INTEGER NOT NULL DEFAULT 0,
    chat_only           INTEGER NOT NULL DEFAULT 0,
    -- 免打扰 (字段扩充 2026-07-04; 派生 local_type+chat_room_notify; 进 L2 不进 content_digest — ADR-463)。
    --   群(local_type=2) chat_room_notify=0 → 1=免打扰 (用户真人核对确认方向, 真库 1204 群); 个人该字段无区分度→恒 0。
    is_muted            INTEGER NOT NULL DEFAULT 0,
    -- 补充列 (字段扩充批 I 2026-07-04; extra_buffer 再解; 进 L2 不进 content_digest — ADR-464)。
    --   signature=个性签名 (f4; 对方自设, 真库 17.5%; 可含手机号 → Debug sha8); moments_cover_url=朋友圈封面图 URL (f27 内层 f2; 真库 14.1%)。
    signature           TEXT,
    moments_cover_url   TEXT,
    -- 身份键用 username_sha (全长不撞) 而非 source_native_id (= Contact_<md5 前8位>, 不同 username
    -- 前8位可能相同 → 撞键 → 后写覆盖丢人); 跟 §3.1.5 person_alias 身份键 (account_id_sha, username_sha) 一致.
    -- ⚠ 此 PK 变更对既存库不自动生效: CREATE TABLE IF NOT EXISTS 不改已建表 PK; 旧库需重建或走 §9 迁移.
    -- ⚠ 明文列 (account_id/username/nick_name/remark/alias) = ADR-426 隐私模型翻转落地; 拼音/状态标志/头像/第五批/第七批/批G/第八批 = 字段扩充
    --   (代码 storage.rs init_person_table 为准, 共 39 列 + ensure_person_extra_columns 旧库 ALTER 补列)。
    PRIMARY KEY (account_id_sha, source, username_sha)
);

CREATE INDEX IF NOT EXISTS idx_person_username
    ON person (account_id_sha, username_sha);
```

#### 3.1.5 person_alias_by_account_min — 联系人简化别名表

```sql
-- PoC-1 沿用. 用于 message → 发送者快速 JOIN 拿 sha (不是 plaintext 关联)
-- 上层 L1.5 / 应用层做明文关联要订阅 contact_update 事件维护映射

CREATE TABLE IF NOT EXISTS person_alias_by_account_min (
    account_id_sha      TEXT NOT NULL,
    username_sha        TEXT NOT NULL,
    remark_sha          TEXT,
    nick_name_sha       TEXT,
    PRIMARY KEY (account_id_sha, username_sha)
);
```

#### 3.1.6 chatroom — 群信息

```sql
CREATE TABLE IF NOT EXISTS chatroom (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,
    chatroom_id_sha     TEXT    NOT NULL,         -- 群 id sha (e.g. xxxxxxxx@chatroom)
    chatroom_name_len   INTEGER NOT NULL,
    announcement_len    INTEGER NOT NULL,
    member_count        INTEGER NOT NULL,
    owner_wxid_sha      TEXT,                     -- nullable — 已解散群 / 历史群可能没群主信息
    announcement_editor        TEXT,              -- 批H/ADR-460: 群公告编辑者 wxid (nullable; L2-only 不进 digest)
    announcement_publish_time  INTEGER NOT NULL DEFAULT 0, -- 批H: 群公告发布时间秒 (L2-only)
    chatroom_remark            TEXT,              -- ADR-470: 我给群的私人备注 (contact.remark; nullable; L2-only 不进 digest)
    chatroom_remark_len        INTEGER NOT NULL DEFAULT 0, -- ADR-470: 群备注字符数
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_chatroom_id
    ON chatroom (account_id_sha, chatroom_id_sha);
```

> ⚠️ 上表省了 ADR-426 明文列 (account_id/chatroom_id/owner_wxid/chatroom_name/announcement/chatroom_remark); 代码 storage.rs
> init_chatroom_table 为准 (共 **17 列** + ensure_chatroom_columns 旧库 ALTER 补批H两列 + ADR-470 群备注两列)。**群公告 announcement**
> (批H/ADR-460) 来自 `chat_room_info_detail.announcement_` (独立表, drain LEFT JOIN; 非 ext_buffer), 本就在
> ChatroomCreate digest, 填充=166 群一次性重 fingerprint (字段集不变不 supersede)。**群备注 chatroom_remark**
> (ADR-470) 来自 `contact.remark`(群作为通讯录记录, 同群名 nick_name 来源 LEFT JOIN); **私人可变标注 → L2-only
> 不进 digest/payload**(同批G/H, 不动冻结 ChatroomUpdate schema); 真跑 93/1438 群有备注(92 ≠ 群名)。

#### 3.1.7 chatroom_member — 群成员

```sql
CREATE TABLE IF NOT EXISTS chatroom_member (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,         -- 复合 native id, e.g. "<chatroom>:member:<wxid>"
    chatroom_id_sha     TEXT    NOT NULL,
    member_wxid_sha     TEXT    NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; member_wxid 明文供退群闭环回读, project_chatroom_member_add 同源)。
    account_id          TEXT    NOT NULL,
    chatroom_id         TEXT    NOT NULL,
    member_wxid         TEXT    NOT NULL,
    display_name        TEXT,
    display_name_len    INTEGER NOT NULL,         -- 群昵称长度 (默认 sha 模式)
    joined_at           INTEGER,                  -- nullable — 历史成员可能没记录
    left_at             INTEGER,                  -- nullable — 当前在群时 NULL; 退群时 = unixepoch()
    is_in_group         INTEGER NOT NULL DEFAULT 1, -- 0/1 boolean — 1 = 当前在群; 0 = 已退群
    -- 成员角色 (字段扩充第八批 2026-07-02; owner/admin/member; L2-only 不进 digest — ADR-452;
    --   owner=chat_room.owner, admin=ext_buffer field3 flags&2048; role 首次 add 定不随重扫刷新)。
    role                TEXT    NOT NULL DEFAULT 'member',
    -- 邀请人 wxid (字段扩充第九批 2026-07-02; id 类明文 nullable; 谁拉此成员进群; L2-only 不进 digest — ADR-452; 成员 ext_buffer field4)。
    invited_by          TEXT,
    -- ⚠ 代码 storage.rs init_chatroom_member_table 为准 (共 15 列: 9 + 4 明文 ADR-426 + role 第八批 + invited_by 第九批; ensure_chatroom_member_columns 旧库 ALTER 补 role/invited_by)。
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_chatroom_member_chatroom
    ON chatroom_member (account_id_sha, chatroom_id_sha, is_in_group);
    -- 查询当前在群成员: WHERE chatroom_id_sha=? AND is_in_group=1

CREATE INDEX IF NOT EXISTS idx_chatroom_member_wxid
    ON chatroom_member (account_id_sha, member_wxid_sha);
```

> **群成员先退后加再退** 场景 (需求 §6.8 契约 3 c):
> · raw_payload_archive 里 3 条记录 (event_seq 区分: 退 1 / 加 2 / 退 3) — **完整事件历史在 archive**
> · chatroom_member 业务表保留【曾出现成员的一行当前状态】 — 不是多版本历史表;
>   同一 (account_id_sha, source, source_native_id) PK 通过 UPDATE 翻 is_in_group / left_at; 完整事件历史走 archive 重放
> · adapter 处理:
>     - member_add → INSERT OR UPDATE (是新 PK 则 INSERT; 同 PK 旧记录则 UPDATE is_in_group=1, left_at=NULL, joined_at=unixepoch())
>     - member_remove → UPDATE is_in_group=0, left_at=unixepoch();
>                      PK 必已在表里; 不在则【仅业务表跳过】 + 写一条 error system_event;
>                      **archive 不依赖 PK 是否在业务表里, 仍必先写**(D4 强约束 / §2 红线第 2 条)
> · 查询当前在群: `WHERE is_in_group=1`; 查询曾在群: 不加该条件
> · 区别老版骨架"INSERT OR REPLACE" 表达 — REPLACE 会丢 joined_at 等历史信息, 也不能产生"0 条"; 现版 UPDATE 模式保留【当前状态行】

#### 3.1.8 session — 会话 (聊天列表)

```sql
CREATE TABLE IF NOT EXISTS session (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,
    username_sha        TEXT    NOT NULL,         -- 会话对方 wxid sha (单聊) / 群 sha
    -- 明文列 (ADR-426 §2.1 第一类; 与 _sha 同源, project_session 统一构造)。
    account_id          TEXT    NOT NULL,
    username            TEXT    NOT NULL,
    unread_count        INTEGER NOT NULL,
    last_msg_type       INTEGER NOT NULL,
    last_msg_sub_type   INTEGER NOT NULL,
    sort_timestamp      INTEGER NOT NULL,         -- 列表排序时间 (置顶 / 最新消息)
    -- 会话展示列 (summary=text_content / last_sender=display_name; 明文 + _len, ADR-427 全程明文)。
    summary_len         INTEGER NOT NULL,
    summary             TEXT,
    last_sender_len     INTEGER NOT NULL,
    last_sender_display_name TEXT,
    -- 会话状态列 (字段扩充第四批 2026-07-02; 进 L2 不进 content_digest — 当前态筛选; draft=没发草稿 text_content 脱敏)。
    session_type        INTEGER NOT NULL DEFAULT 0,
    is_hidden           INTEGER NOT NULL DEFAULT 0,
    status              INTEGER NOT NULL DEFAULT 0,
    draft_len           INTEGER NOT NULL DEFAULT 0,
    draft               TEXT,
    -- session 补充列 (字段扩充第六批 2026-07-02; 进 L2 不进 content_digest — ADR-451; last_msg_sender id 类明文 nullable, 5 元数据)。
    last_msg_sender              TEXT,
    last_timestamp               INTEGER NOT NULL DEFAULT 0,
    last_clear_unread_timestamp  INTEGER NOT NULL DEFAULT 0,
    last_msg_locald_id           INTEGER NOT NULL DEFAULT 0,
    last_msg_ext_type            INTEGER NOT NULL DEFAULT 0,
    unread_first_msg_srv_id      INTEGER NOT NULL DEFAULT 0,
    -- ⚠ 代码 storage.rs init_session_table 为准 (共 25 列: 第四批 19 + 第六批 6; ensure_session_columns 旧库 ALTER 补列)。
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_session_username
    ON session (account_id_sha, username_sha);

CREATE INDEX IF NOT EXISTS idx_session_sort
    ON session (account_id_sha, sort_timestamp DESC);
    -- 主查询: 聊天列表按时间倒序
```

#### 3.1.9 capability_backlog — 28 缺口字段跟踪 (需求 §5.3 D 路线)

> **登记表性质** (跟 §2 红线豁免清单 + §4.5 跨文件一致性维护): 本表【无 account_id_sha 列】 —
> 28 字段【每个 L1 文件内的同构副本】 (非物理共享 1 行);
> 行【内容】 通过版本化 seed + 每文件 migration 事务收敛 (软一致);
> 中间态允许跨文件状态不一致 (主号 v2 'shipped' / 副号 v1 'unimplemented');
> 上层应用查询必须走【当前 --wxid 文件】, **不准跨 wxid 聚合** (反例详 §4.5 D 段);
> seed 内容 / status 变化必须走 schema/backlog migration (不准不同 binary 漂 v1 seed)

```sql
CREATE TABLE IF NOT EXISTS capability_backlog (
    field_category      TEXT    NOT NULL,         -- "wallet" / "linked_account" / "miniprogram" / "wechat_sport" / "login_log" / "favorite" / "contact_extra"
    field_name          TEXT    NOT NULL,         -- 候选字段名 (e.g. "wallet_amount")
    src_table           TEXT,                     -- 微信源 db 表 (nullable — 调研中可空)
    src_column          TEXT,                     -- 微信源 db 列 (nullable)
    reference_project   TEXT,                     -- 有无现成参考 (e.g. "wx-cli" / "chatlog" / "")
    target_milestone    TEXT    NOT NULL,         -- "0.2.0" / "0.3.0" / "1.0.0+"
    status              TEXT    NOT NULL,         -- "unimplemented" / "researching" / "ready" / "shipped"
    notes               TEXT,                     -- 自由文本
    updated_at          INTEGER NOT NULL,
    PRIMARY KEY (field_category, field_name)
);

CREATE INDEX IF NOT EXISTS idx_backlog_status
    ON capability_backlog (status);

CREATE INDEX IF NOT EXISTS idx_backlog_milestone
    ON capability_backlog (target_milestone);
```

> 28 字段初始填充 → §4.1; 字段【真挖完】 转正流程 → §4.4

#### 3.1.10 favorite — 收藏 (favorite.db fav_db_item 骨架, ADR-454)

> **新事件类型** `favorite_update` (扩 alpha, 照 session ADR-412 先例; config-events §7.3 组合 7→9)。
> 收藏条目骨架: 类型/收藏时间/来源。**content 本身不落** (最大 288KB XML/proto, 按 type 拆是大件 ADR-454 KI-B → 只存 content_len)。
> 标签体系 (fav_tag/fav_bind_tag M:N) 留批 B-2。`from_user` (来源 wxid/@chatroom) L2 明文 (ADR-427) + from_user_sha (JOIN 键)。

```sql
CREATE TABLE IF NOT EXISTS favorite (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,         -- "favorite.db"
    source_native_id  TEXT    NOT NULL,         -- "Favorite_<local_id>" (锚点)
    server_id         INTEGER NOT NULL,         -- 服务端主键 (进 digest)
    local_id          INTEGER NOT NULL,         -- 本地 PK (只进 L2)
    fav_type          INTEGER NOT NULL,         -- 收藏类型 (真库) 1文本/2图片/4视频/5链接/6位置/14聊天记录/18笔记 (进 digest)
    update_time       INTEGER NOT NULL,         -- 收藏时间 unix 秒 (进 digest)
    from_user_sha     TEXT    NOT NULL,         -- 来源 wxid/@chatroom 的 sha (JOIN 键)
    -- 明文列 (ADR-426 §2.1; project_favorite 同源填)
    account_id        TEXT    NOT NULL,
    from_user         TEXT    NOT NULL,         -- 来源用户明文 (ADR-427)
    real_chat_name    TEXT,                     -- 群内真实发送者 (id 类, nullable, 只进 L2)
    source_id         TEXT,                     -- 来源消息 hash id (进 digest, nullable)
    content_len       INTEGER NOT NULL,         -- content 字节长度 (content 本身不落, 只进 L2)
    note_text         TEXT,                     -- ADR-471: 笔记正文 (仅 type 18; content <datadesc> 解; L2-only, nullable)
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_favorite_type
    ON favorite (account_id_sha, fav_type);

CREATE INDEX IF NOT EXISTS idx_favorite_update_time
    ON favorite (account_id_sha, update_time DESC);
    -- 主查询: 收藏按时间倒序

CREATE INDEX IF NOT EXISTS idx_favorite_from_user
    ON favorite (account_id_sha, from_user_sha);
```

> content_digest = server_id + fav_type + update_time + from_user_sha + source_id (ADR-454; 唯一标识+溯源一条收藏)。
> **note_text** (ADR-471) 仅 type 18 笔记, 从 content XML `<datadesc>` 解正文 (drain `CASE WHEN type=18 THEN content`;
> XML 实体解码 `&#x0A;` 等); **L2-only 不进 digest/payload** (私人内容 + 冻结事件, 同群备注; note 编辑 bump update_time
> 已在 digest → 刷新)。旧 favorite 表走 `ensure_favorite_columns` ALTER 补。真跑 13 笔记 12 有正文 (1 纯媒体无 datadesc)。
> content 其它类型 (聊天记录/图/视频…) 拆解仍 backlog (ADR-454 KI-B)。

#### 3.1.10b favorite_media — 收藏媒体引用 (笔记图片/文件 md5, ADR-472)

> **favorite 第二投影** (一收藏多媒体 → 多行, PK 含 seq; 同 message_media/mention)。从收藏 content 的 `<dataitem>` 抽每个带
> `<fullmd5>` 的项 (图片/文件/HTML; 纯文本无 md5 跳)。**L2-only 不进 digest/payload**。让 L1 自洽 —— 应用层光读 L1 就能定位笔记图片:
> `media_md5`(=fullmd5) = **本地缓存文件解密后 md5**, app 据此 md5→本地 `business/favorite/data`(V2 加密, image key 解) 文件 (ADR-472 §1)。

```sql
CREATE TABLE IF NOT EXISTS favorite_media (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,     -- 所属 favorite 的 PK (一收藏多媒体 → 多行)
    seq               INTEGER NOT NULL,     -- 媒体在笔记内顺序 (0-based)
    fav_server_id     INTEGER NOT NULL,     -- 所属收藏 server_id (查询便利)
    account_id        TEXT    NOT NULL,
    data_type         INTEGER NOT NULL,     -- dataitem datatype (2图/6文件/8HTML)
    media_md5         TEXT    NOT NULL,     -- fullmd5 = 内容md5 = 本地缓存解密后md5 (app 定位键)
    media_size        INTEGER NOT NULL,     -- fullsize 字节数
    data_fmt          TEXT,                 -- datafmt (jpg/htm; nullable)
    PRIMARY KEY (account_id_sha, source, source_native_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_favorite_media_md5
    ON favorite_media (account_id_sha, media_md5);
```

> 只存**引用**不存字节 (图片解密是应用层的事, 底座给 md5 定位键; 同 message_media 只存 md5/cdn)。不存 cdn_datakey/cdn_dataurl
> (是 key + CDN 死路登录墙)。现仅 type 18 笔记 (drain 只取笔记 content); 其它收藏类型媒体后续。真跑 213 行/13 笔记 (图片 198/HTML 13)。

#### 3.1.11 favorite_tag — 收藏标签绑定 (favorite.db fav_bind_tag ⋈ fav_tag, ADR-454 批 B-2)

> **新事件类型** `favorite_tag_update` (扩 alpha; config-events §7.3 组合 9→10)。**一条绑定 = 一行**
> (标签名去规范化): 查"某收藏的标签" = WHERE fav_server_id=X; 查"某标签的收藏" = WHERE tag_server_id=Y。
> `tag_name` (用户标签, 可能敏感) L2 明文 (ADR-427) + Debug sha8。孤儿标签 (0 绑定) 不落 (空标签无意义)。

```sql
CREATE TABLE IF NOT EXISTS favorite_tag (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,         -- "favorite.db"
    source_native_id  TEXT    NOT NULL,         -- "FavoriteTag_<tag_server_id>_<fav_server_id>" (绑定锚点)
    tag_server_id     INTEGER NOT NULL,         -- 标签服务端 id (进 digest)
    tag_local_id      INTEGER NOT NULL,         -- 标签本地 id (只进 L2)
    seq               INTEGER NOT NULL,         -- 标签顺序 (只进 L2)
    fav_server_id     INTEGER NOT NULL,         -- 收藏服务端 id (进 digest)
    fav_local_id      INTEGER NOT NULL,         -- 收藏本地 id (只进 L2)
    op_code           INTEGER NOT NULL,         -- 1=add (进 digest, add/remove 态)
    tag_name_len      INTEGER NOT NULL,
    account_id        TEXT    NOT NULL,
    tag_name          TEXT    NOT NULL,         -- 标签名明文 (ADR-427; 去规范化到每条绑定; 进 digest)
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_favorite_tag_fav
    ON favorite_tag (account_id_sha, fav_server_id);

CREATE INDEX IF NOT EXISTS idx_favorite_tag_tag
    ON favorite_tag (account_id_sha, tag_server_id);
```

> content_digest = tag_server_id + fav_server_id + tag_name + op_code (ADR-454 B-2; 恰 4 元)。

#### 3.1.12 message_app — 消息卡片 (视频号/小程序/链接 + 类型专属细节, ADR-455/462/468)

> **message 第二投影**(同 person_alias, **不是新事件类型**)。从 message `text_content` 的 `<appmsg>` XML 抽卡片
> 结构化字段 → 稀疏表(只 appmsg 消息一行, 非 appmsg 不落)。PK = 所属 message 的 PK。**派生自 text_content**
> (已在 message content_digest)→ **L2-only 不进 digest/payload**(同拼音派生列)。title/nickname 明文(ADR-427)+ Debug sha8。
> **24 列** = 12 通用(ADR-455) + 10 类型专属(ADR-462: 文件/转账/引用/合并转发) + 2 红包(ADR-468 §7.3: 祝福语/个数)。

```sql
CREATE TABLE IF NOT EXISTS message_app (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,         -- = 所属 message 的 PK
    app_type          INTEGER NOT NULL,         -- appmsg 子类 (5链接/33小程序/51视频号/2000转账/2001红包 等)
    media_count       INTEGER NOT NULL,         -- 视频号媒体数 (非视频号 0)
    account_id        TEXT    NOT NULL,
    title             TEXT,                     -- 卡片标题 (明文)
    source_name       TEXT,                     -- 来源显示名 (小程序 sourcedisplayname)
    url               TEXT,                     -- 主链接
    app_username      TEXT,                     -- 视频号 v2_ id / 小程序 gh_xxx@app
    app_nickname      TEXT,                     -- 视频号作者
    app_pagepath      TEXT,                     -- 小程序页面路径
    -- 类型专属细节 (ADR-462; 非对应类型 0/None)
    file_size          INTEGER NOT NULL DEFAULT 0,  -- 文件字节数 (type 6)
    file_ext           TEXT,                    -- 文件后缀 (type 6)
    file_md5           TEXT,                    -- 文件 md5 (type 6)
    transfer_fee       TEXT,                    -- 转账金额串 (type 2000, 如 ￥10.00)
    transfer_direction INTEGER NOT NULL DEFAULT 0, -- 转账方向 (type 2000)
    transfer_txid      TEXT,                    -- 转账交易号 (type 2000)
    refer_svrid        TEXT,                    -- 被引消息 id (type 57)
    refer_type         INTEGER NOT NULL DEFAULT 0,  -- 被引消息类型 (type 57)
    refer_content      TEXT,                    -- 被引消息原文 (type 57)
    forward_item_count INTEGER NOT NULL DEFAULT 0, -- 合并转发条数 (type 19)
    -- 红包细节 (ADR-468 §7.3; 从 type 2001 <wcpayinfo> 抽; 非红包 0/None)
    red_envelope_wish  TEXT,                    -- 红包祝福语/留言 (sendertitle; 明文 + Debug sha8)
    red_envelope_count INTEGER NOT NULL DEFAULT 0, -- 红包个数 (nativeurl total_num)
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_message_app_type
    ON message_app (account_id_sha, app_type);

CREATE INDEX IF NOT EXISTS idx_message_app_username
    ON message_app (account_id_sha, app_username);
```

> 派生自 text_content, **不进 content_digest**(message digest 恒 6)。解析器 decoder/appmsg.rs::parse_appmsg。
> 旧库 (12/22 列) 走 `ensure_message_app_columns` ALTER 补齐, 列序与 fresh CREATE 一致 (幂等)。

#### 3.1.13 message_media — 媒体元数据 (图/视频/表情/语音, ADR-456)

> **message 第二投影**(与 message_app 并列, **不是新事件类型**)。从 message `text_content` 的 `<img>`/`<videomsg>`/
> `<emoji>`/`<voicemsg>` XML 抽 md5/aeskey/cdn/尺寸/时长 → 稀疏表(只媒体消息一行, msg_type 3/43/47/34 且有 md5 或
> cdn_url 才落; **语音例外**: 只要有时长即落, 见下)。
> PK = 所属 message 的 PK。**派生自 text_content**(已在 message content_digest)→ **L2-only 不进 digest/payload**。
> md5/aes_key/cdn_url(媒体资源引用, aes_key 是解密密钥)明文(ADR-427)+ Debug sha8。采同行 WDA 属性名。

```sql
CREATE TABLE IF NOT EXISTS message_media (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,         -- = 所属 message 的 PK
    media_kind        TEXT    NOT NULL,         -- image(3) / video(43) / emoji(47) / voice(34)
    file_size         INTEGER NOT NULL,         -- 文件字节数 (length/len; 未知 0)
    play_length       INTEGER NOT NULL,         -- 视频时长秒 (playlength; 非视频 0)
    account_id        TEXT    NOT NULL,
    md5               TEXT,                     -- 媒体内容 MD5 (hardlink 索引键)
    aes_key           TEXT,                     -- CDN 解密密钥 (aeskey)
    cdn_url           TEXT,                     -- 主 CDN (图 cdnmidimgurl / 视频 cdnvideourl / 表情 cdnurl)
    thumb_url         TEXT,                     -- 缩略图 CDN (cdnthumburl; 表情无)
    extra_id          TEXT,                     -- 图片 hdmd5 / 视频 newmd5 / 表情 productid
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_message_media_kind
    ON message_media (account_id_sha, media_kind);

CREATE INDEX IF NOT EXISTS idx_message_media_md5
    ON message_media (account_id_sha, md5);
```

> 派生自 text_content, **不进 content_digest**(message digest 恒 6)。解析器 decoder/media.rs::parse_media(词边界防 md5 误配 cdnthumbmd5)。
>
> **语音 (msg_type 34) 也入本表**(真库实证:L1 `msgcol-l1.db` 有 395 条 `media_kind='voice'` 行)。语音 `message_content` 是
> **zstd 压缩的 `<voicemsg>` XML**(裸字节看着像二进制, 是压缩壳; decoder 解压后 parse_media 正常抽取)。voice 行列语义:
> `cdn_url`=`voiceurl`(CDN 兜底地址)、`md5`=`voicemd5`(真库常空)、`play_length`=`voicelength`(毫秒)、`extra_id`=`voiceformat`
> (4=SILK)、`aes_key`=CDN 解密钥。keep-gate 对语音放宽:**只要有时长即落**(voicelength 100% 覆盖, voiceurl/voicemd5 部分缺)。
> **本地音频字节不由本表的 md5 定位** —— 存源库 `media_0.db.VoiceInfo.voice_data`, 按 **`message.server_id ↔ VoiceInfo.svr_id`**
> 定位(真库实证 11034/11034 命中、svr_id 1:1 唯一), 由 `voice_export`(ADR-465)解码导出 WAV/MP3。`media_kind` 列无 CHECK 约束, voice 行不被拒。

#### 3.1.13b message_location — 消息位置 (经纬度/POI, ADR-462)

> **message 第二投影**(与 message_app/media/mention 并列, **不是新事件类型**)。从 message `text_content` 的
> `<location>` XML 抽经纬度/地址/POI → 稀疏表(只 local_type=48 位置消息一行, 非位置不落)。PK = 所属 message 的 PK。
> **派生自 text_content**(已在 message content_digest)→ **L2-only 不进 digest/payload**。label/poiname/poiid
> (地址/地点/POI id)明文(ADR-427)+ Debug sha8; 经纬度原值不换算(REAL, 北纬/东经正)。

```sql
CREATE TABLE IF NOT EXISTS message_location (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,
    scale             INTEGER NOT NULL,     -- 地图缩放级别
    account_id        TEXT    NOT NULL,
    latitude          REAL    NOT NULL,     -- 纬度 (北纬正)
    longitude         REAL    NOT NULL,     -- 经度 (东经正)
    label             TEXT,                 -- 地址串
    poiname           TEXT,                 -- 地点名
    poiid             TEXT,                 -- 腾讯地图 POI id
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_message_location_acct
    ON message_location (account_id_sha);
```

> 派生自 text_content, **不进 content_digest**(message digest 恒 6)。投影 project_message_location(非位置返 None)。
> sink replace-projection: 重投前 delete_message_location(消息从 位置→非位置 不残留旧派生行, 同 message_media)。

#### 3.1.14 message_mention — 群 @提及 (atuserlist, ADR-457)

> **message 第二投影**(与 message_app/media 并列, **不是新事件类型**)。从群消息 `source` 列(msgsource XML)的
> `<atuserlist>` 抽被 @ 的 wxid → **一消息多@ → 多行**(PK 含 mentioned_wxid_sha; 区别 message_app/media 一消息一行)。
> **派生自 source 列**(需加 source 进 message drain, 走 ADR-453 加列链路)→ **msg_source/message_mention L2-only**
> 不进 digest(source 非 message 身份字段)/payload(含被@wxid, 走本表)。mentioned_wxid 明文(ADR-427)+ Debug sha8。

```sql
CREATE TABLE IF NOT EXISTS message_mention (
    account_id_sha     TEXT    NOT NULL,
    source             TEXT    NOT NULL,
    source_native_id   TEXT    NOT NULL,         -- 所属 message 的 PK (一消息多@ → 多行)
    mentioned_wxid_sha TEXT    NOT NULL,         -- 被 @ 的 wxid sha (或 notify@all 的 sha)
    is_at_all          INTEGER NOT NULL,         -- 1 = @所有人 (notify@all)
    account_id         TEXT    NOT NULL,
    mentioned_wxid     TEXT    NOT NULL,         -- 明文 wxid (或 notify@all)
    PRIMARY KEY (account_id_sha, source, source_native_id, mentioned_wxid_sha)
);

CREATE INDEX IF NOT EXISTS idx_message_mention_wxid
    ON message_mention (account_id_sha, mentioned_wxid_sha);
```

> 派生自 source 列, **不进 content_digest**(message digest 恒 6)。解析器 decoder/mention.rs::parse_mentions(抽 atuserlist CDATA, 逗号分隔去空去重)。双向查: 某消息@谁 WHERE source_native_id / 某人被谁@ WHERE mentioned_wxid_sha。

#### 3.1.14b message_call — 通话记录 (voip, type50, ADR-475)

> **message 第二投影**(与 message_app/media/mention 并列, **不是新事件类型**)。从 message `text_content` 的
> `<voipmsg>` XML 抽通话类型/状态/时长 → 稀疏表(只 type50 通话消息一行, 非通话不落)。PK = 所属 message 的 PK。
> **派生自 text_content**(已在 message content_digest)→ **L2-only 不进 digest/payload**。invite_type/room_type/
> call_state/duration 粗粒度直露; display_content(通话结果文本, 如 "通话时长 00:25")明文(ADR-427)。

```sql
CREATE TABLE IF NOT EXISTS message_call (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,
    invite_type       INTEGER NOT NULL,     -- -1 气泡 / 0 视频 / 1 语音
    room_type         INTEGER NOT NULL,
    call_state        INTEGER NOT NULL,     -- voip msg_type 100/101
    duration          INTEGER NOT NULL,     -- 时长秒
    account_id        TEXT    NOT NULL,
    display_content   TEXT    NOT NULL,     -- 通话结果文本
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_message_call_acct
    ON message_call (account_id_sha);
```

> 派生自 text_content, **不进 content_digest**(message digest 恒 6)。解析器 decoder/voip.rs::parse_voip。
> sink replace-projection: 重投前 delete_message_call(消息重解码不残留旧派生行, 同 message_media)。真跑 1173/1187 解出。

#### 3.1.14c message_card — 名片消息 (type42, ADR-477)

> **message 第二投影**(**不是新事件类型**)。从 message `text_content` 的 `<msg .../>` 属性抽被推荐人名片 →
> 稀疏表(只 type42 名片消息一行)。PK = 所属 message 的 PK。**派生自 text_content**(已在 digest)→
> **L2-only 不进 digest/payload**。card_username(v3_ 分享 token 或 wxid)/nickname/alias/sign 明文(ADR-427)+
> Debug sha8; province/city 粗粒度直露。

```sql
CREATE TABLE IF NOT EXISTS message_card (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,
    card_sex          INTEGER NOT NULL,
    account_id        TEXT    NOT NULL,
    card_username     TEXT    NOT NULL,     -- 被推荐人身份 (v3_ token 或 wxid)
    card_nickname     TEXT,
    card_alias        TEXT,                 -- 微信号
    card_province     TEXT,
    card_city         TEXT,
    card_sign         TEXT,
    card_open_im_desc TEXT,                 -- 企微公司名
    big_head_url      TEXT,
    small_head_url    TEXT,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_message_card_acct
    ON message_card (account_id_sha);
```

> 派生自 text_content, **不进 content_digest**(message digest 恒 6)。解析器 decoder/card.rs::parse_card
> (open_tag_body + extract_attr 抽属性)。sink replace-projection: 重投前 delete_message_card。真跑 299/299 解出。

#### 3.1.14d message_forward_item — 合并转发逐条明细 (type49 子类19, ADR-476)

> **message 第二投影**(**不是新事件类型**)。从 message `text_content` 的 `<recordinfo>`(**HTML 实体编码, 非 CDATA**)
> 抽合并转发 datalist → **一转发多子项 → 多行**(PK 含 seq)。**派生自 text_content**(已在 digest)→
> **L2-only 不进 digest/payload**。source_name/data_title/data_desc 明文(ADR-427); 套娃转发(子项 datatype=19)
> 深度感知抽取, 200 子项封顶。

```sql
CREATE TABLE IF NOT EXISTS message_forward_item (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,     -- 所属 message 的 PK (一转发多子项 → 多行)
    seq               INTEGER NOT NULL,     -- datalist 内 0 基序号
    data_type         TEXT    NOT NULL,     -- datatype (1 文本 / 2 图片 / 19 套娃 / …)
    data_size         INTEGER NOT NULL,
    account_id        TEXT    NOT NULL,
    source_name       TEXT,                 -- 原发送人
    source_time       TEXT,                 -- 原发送时间串
    data_title        TEXT,                 -- 子项标题
    data_desc         TEXT,                 -- 子项内容
    media_md5         TEXT,                 -- 子媒体 fullmd5
    PRIMARY KEY (account_id_sha, source, source_native_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_message_forward_item_acct
    ON message_forward_item (account_id_sha, source, source_native_id);
```

> 派生自 text_content, **不进 content_digest**(message digest 恒 6)。解析器 decoder/forward.rs::parse_forward
> (recordinfo 先 decode_xml_entities 解 HTML 实体, 文本字段二次解码防双重编码; 深度感知 dataitem_blocks 拆套娃;
> F1 双审: 顶层字段从 strip_blocks(recordxml) 抽防子项串味)。sink replace-projection: 重投前 delete_message_forward_items。
> 真跑 2424 转发 → 3682 子项。

#### 3.1.15 moment — 朋友圈动态本体 (sns.db SnsTimeLine, ADR-467 件1)

> **新事件类型** `sns_event`(扩 alpha)。sns.db `SnsTimeLine` 一条动态 → 一行。`author`(发布者 wxid)明文 +
> author_sha(JOIN/digest 键);`content_desc`(正文, text 类)明文 + _len(同 message text_content);**原始 content
> XML 不落**(只 content_len 尺寸)。经纬度原值不换算(nullable REAL)。逐条媒体见 §3.1.16 moment_media, 逐条赞/评论
> 见 §3.1.17 moment_interaction。⚠️ tid(雪花动态 id)可为负(ADR-467 KI-A: 游标从 i64::MIN 起, tid>0 会漏光)。

```sql
CREATE TABLE IF NOT EXISTS moment (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,
    tid               INTEGER NOT NULL,
    author_sha        TEXT    NOT NULL,
    create_time       INTEGER NOT NULL,
    moment_type       INTEGER NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; project_moment 同源填)。
    account_id        TEXT    NOT NULL,
    author            TEXT    NOT NULL,
    author_nickname   TEXT,
    content_desc      TEXT    NOT NULL,
    content_desc_len  INTEGER NOT NULL,
    source_user       TEXT,
    location_label    TEXT,
    latitude          REAL,
    longitude         REAL,
    title             TEXT,
    link_url          TEXT,
    media_count       INTEGER NOT NULL,
    like_count        INTEGER NOT NULL,
    comment_count     INTEGER NOT NULL,
    content_len       INTEGER NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_moment_author
    ON moment (account_id_sha, author_sha);
CREATE INDEX IF NOT EXISTS idx_moment_create_time
    ON moment (account_id_sha, create_time DESC);
CREATE INDEX IF NOT EXISTS idx_moment_type
    ON moment (account_id_sha, moment_type);
```

> content_digest = tid + author_sha + create_time + moment_type (ADR-467 件1; 恰 4 元; 动态身份 + immutable 属性)。
> ⚠️ create_time = **发布时间恒定**(身份属性进 digest, 不同于 message 可变排序时间); content_desc/media_count/
> like_count/comment_count/位置 只进 L2(点赞变不产新 fingerprint)。真跑 11917 条 0 错。

#### 3.1.16 moment_media — 朋友圈逐条媒体 (SnsTimeLine content <media>, ADR-467 件2a)

> **moment 第二投影**(一动态多图/视频 → 多行, PK 含 media_seq; 同 message_mention 一消息多@多行)。从动态 content
> XML 的每个 `<media>` 抽 url/md5/key/尺寸 → **content 本身不落但结构化媒体引用落**。**L2-only 不进 digest/payload**。
> url/thumb/md5/url_key/enc_key(媒体资源引用, url_key/enc_key 是解密密钥)明文(ADR-427)+ Debug sha8。

```sql
CREATE TABLE IF NOT EXISTS moment_media (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,     -- 所属 moment 的 PK (一动态多媒体 → 多行)
    media_seq         INTEGER NOT NULL,     -- mediaList 内序号 (0-based)
    media_type        INTEGER NOT NULL,     -- 2图/6视频/3封面
    account_id        TEXT    NOT NULL,
    media_id          TEXT,
    url               TEXT,
    thumb_url         TEXT,
    md5               TEXT,
    video_md5         TEXT,
    url_key           TEXT,                 -- SNS 媒体 CBC 解密 key
    enc_idx           TEXT,
    token             TEXT,                 -- CDN 下载 token (件3 下载用)
    enc_key           TEXT,                 -- 视频加密 key
    width             INTEGER NOT NULL,
    height            INTEGER NOT NULL,
    total_size        INTEGER NOT NULL,
    video_duration    REAL,
    PRIMARY KEY (account_id_sha, source, source_native_id, media_seq)
);

CREATE INDEX IF NOT EXISTS idx_moment_media_moment
    ON moment_media (account_id_sha, source, source_native_id);
CREATE INDEX IF NOT EXISTS idx_moment_media_md5
    ON moment_media (account_id_sha, md5);
```

> 派生自 content XML, **不进 content_digest**。投影 project_moment_media(无媒体空 Vec)。sink replace-projection:
> 重投前 delete_moment_media 整组删(媒体变化不残留)。真跑 24423 行, 对账 media_count == 行数 PASS。

#### 3.1.17 moment_interaction — 朋友圈逐条互动 (赞/评论, ADR-467 件2b)

> **moment 第二投影**(一动态多赞/评论 → 多行, PK 含 interaction_seq; 同 moment_media)。从动态 content XML 的
> `like_user_list`(赞)/`comment_user_list`(评论)抽每条互动 → **L2-only 不进 digest/payload**。⚠️ 赞在
> like_user_list、评论在**独立** comment_user_list 两个 wrapper(早期只读前者漏光评论, 已修 8676787)。from_user
> (互动者 wxid)明文 + from_user_sha(JOIN 键);content(评论文本)/from_nickname/ref_username(回复对象)明文, Debug sha8。

```sql
CREATE TABLE IF NOT EXISTS moment_interaction (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,     -- 所属 moment 的 PK (一动态多互动 → 多行)
    interaction_seq   INTEGER NOT NULL,     -- 跨 like/comment 连续序号 (0-based)
    kind              TEXT    NOT NULL,      -- 'like' / 'comment'
    type_raw          INTEGER NOT NULL,      -- user_comment <type> 原值 (1赞/2评论/4其它)
    from_user_sha     TEXT    NOT NULL,
    account_id        TEXT    NOT NULL,
    from_user         TEXT,                  -- 互动者 wxid 明文
    from_nickname     TEXT,
    content           TEXT,                  -- 评论文本 (赞 NULL)
    comment_id        TEXT,
    ref_username      TEXT,                  -- 回复对象 wxid (comment reply)
    ref_comment_id    TEXT,
    create_time       INTEGER NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id, interaction_seq)
);

CREATE INDEX IF NOT EXISTS idx_moment_interaction_moment
    ON moment_interaction (account_id_sha, source, source_native_id);
CREATE INDEX IF NOT EXISTS idx_moment_interaction_from
    ON moment_interaction (account_id_sha, from_user_sha);
```

> 派生自 content XML, **不进 content_digest**。投影 project_moment_interaction(无互动空 Vec)。sink replace-projection:
> 重投前 delete_moment_interactions 整组删。对账: 行数 == moment.like_count + comment_count(真跑赞 4217/评论 2656 双 PASS)。

#### 3.1.18 moment_feed — 朋友圈好友动态索引 (sns.db SnsTopItem_1, ADR-474)

> **新事件类型** `moment_feed_update`(扩 alpha 第 17 事件类型)。sns.db `SnsTopItem_1` = 好友动态索引(谁发了哪条),
> 区别 §3.1.15 moment(动态本体)。`author`(发布者 wxid)明文 + author_sha;tid(动态 id, 雪花可为负)/create_time
> 进 digest;last_read_time(我读秒)/is_read(真库 99.5% 恒 1 噪音)只进 L2。锚点 source_native_id = `MomentFeed_<tid>`。

```sql
CREATE TABLE IF NOT EXISTS moment_feed (
    account_id_sha   TEXT    NOT NULL,
    source           TEXT    NOT NULL,
    source_native_id TEXT    NOT NULL,
    tid              INTEGER NOT NULL,
    author_sha       TEXT    NOT NULL,
    create_time      INTEGER NOT NULL,
    last_read_time   INTEGER NOT NULL,
    is_read          INTEGER NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; project_moment_feed 同源填)。
    account_id       TEXT    NOT NULL,
    author           TEXT    NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_moment_feed_author_time
    ON moment_feed (account_id_sha, author_sha, create_time DESC);
```

> content_digest = tid + author_sha + create_time (ADR-474; 恰 3 元; 哪条动态 + 谁发 + 发布时刻)。
> ⚠️ tid 可为负 → 游标从 i64::MIN 起(真库全负, tid>0 会漏光); last_read_time/is_read(读状态)只进 L2。

#### 3.1.19 transfer — 转账 (general.db, ADR-468)

> **新事件类型** `transfer_update`(扩 alpha)。general.db 转账专表 → 一笔转账一行。**账号/状态/时间全在本表**
> (推翻旧结论"转账账号解不出" — 那是只从消息 XML 解);**金额仍在转账消息 XML**, 靠 message_server_id JOIN。
> session_name/pay_payer/pay_receiver(id 类)明文 + _sha;transfer_id/transcation_id 是交易号(非 wxid)明文。

```sql
CREATE TABLE IF NOT EXISTS transfer (
    account_id_sha           TEXT    NOT NULL,
    source                   TEXT    NOT NULL,
    source_native_id         TEXT    NOT NULL,
    transfer_id              TEXT    NOT NULL,
    transcation_id           TEXT    NOT NULL,
    message_server_id        INTEGER NOT NULL,
    second_message_server_id INTEGER NOT NULL,
    pay_sub_type             INTEGER NOT NULL,
    session_name_sha         TEXT    NOT NULL,
    pay_payer_sha            TEXT    NOT NULL,
    pay_receiver_sha         TEXT    NOT NULL,
    begin_transfer_time      INTEGER NOT NULL,
    last_modified_time       INTEGER NOT NULL,
    invalid_time             INTEGER NOT NULL,
    last_update_time         INTEGER NOT NULL,
    delay_confirm_flag       INTEGER NOT NULL,
    bubble_clicked_flag      INTEGER NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; project_transfer 同源填)。
    account_id               TEXT    NOT NULL,
    session_name             TEXT    NOT NULL,
    pay_payer                TEXT    NOT NULL,
    pay_receiver             TEXT    NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_transfer_payer
    ON transfer (account_id_sha, pay_payer_sha);
CREATE INDEX IF NOT EXISTS idx_transfer_receiver
    ON transfer (account_id_sha, pay_receiver_sha);
CREATE INDEX IF NOT EXISTS idx_transfer_begin_time
    ON transfer (account_id_sha, begin_transfer_time DESC);
```

> content_digest = transfer_id + pay_sub_type + begin_transfer_time + pay_payer_sha + pay_receiver_sha (ADR-468; 恰 5 元)。
> ⚠️ begin_transfer_time 发起时刻恒定(身份); pay_sub_type 状态变即产新 fingerprint(状态流水); last_update_time 才临时不进。
> transcation_id/message_server_id/其它时间/flag/session_name 只进 L2。真跑 2176 行。

#### 3.1.20 red_envelope — 红包 (general.db redEnvelopeTable, ADR-468 件2)

> **新事件类型** `red_envelope_update`(扩 alpha)。general.db `redEnvelopeTable` → 一个红包一行。sender_user_name/
> session_name(id 类)明文 + _sha;send_id 是红包单号(非 wxid)明文。`native_url`(wxpay 领取 URL, query 嵌 wxid
> 三重脱敏)存明文供后置件取详情 — Debug 只露长度。**金额不在本表**(在红包消息 XML);**无时间列**(靠消息 JOIN)。

```sql
CREATE TABLE IF NOT EXISTS red_envelope (
    account_id_sha       TEXT    NOT NULL,
    source               TEXT    NOT NULL,
    source_native_id     TEXT    NOT NULL,
    send_id              TEXT    NOT NULL,
    message_server_id    INTEGER NOT NULL,
    sender_user_name_sha TEXT    NOT NULL,
    session_name_sha     TEXT    NOT NULL,
    scene_id             INTEGER NOT NULL,
    hb_status            INTEGER NOT NULL,
    hb_type              INTEGER NOT NULL,
    receive_status       INTEGER NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; project_red_envelope 同源填)。
    native_url           TEXT    NOT NULL,
    account_id           TEXT    NOT NULL,
    sender_user_name     TEXT    NOT NULL,
    session_name         TEXT    NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_red_envelope_sender
    ON red_envelope (account_id_sha, sender_user_name_sha);
CREATE INDEX IF NOT EXISTS idx_red_envelope_session
    ON red_envelope (account_id_sha, session_name_sha);
CREATE INDEX IF NOT EXISTS idx_red_envelope_type
    ON red_envelope (account_id_sha, hb_type);
```

> content_digest = send_id + sender_user_name_sha + hb_type + hb_status + receive_status (ADR-468 件2; 恰 5 元)。
> hb_status/receive_status 状态变即产新 fingerprint(领取流水, 同 transfer pay_sub_type); message_server_id/
> session_name/native_url/scene_id 只进 L2。真跑 579 行。

#### 3.1.21 group_pay — 群收款 (general.db groupPayTable, ADR-468 件3)

> **新事件类型** `group_pay_update`(扩 alpha)。general.db `groupPayTable` → 一次群收款一行。session_name(id 类)
> 明文 + _sha;bill_no 是账单号(非 wxid)明文。**金额/分摊不在本表**(在群收款消息 XML; message_local_id 供 JOIN)。

```sql
CREATE TABLE IF NOT EXISTS group_pay (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,
    bill_no             TEXT    NOT NULL,
    message_local_id    INTEGER NOT NULL,
    message_create_time INTEGER NOT NULL,
    session_name_sha    TEXT    NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; project_group_pay 同源填)。
    account_id          TEXT    NOT NULL,
    session_name        TEXT    NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_group_pay_session
    ON group_pay (account_id_sha, session_name_sha);
CREATE INDEX IF NOT EXISTS idx_group_pay_time
    ON group_pay (account_id_sha, message_create_time DESC);
```

> content_digest = bill_no + session_name_sha + message_create_time (ADR-468 件3; 恰 3 元)。
> message_create_time 群收款时刻恒定(身份, 同 sns create_time); message_local_id 只进 L2。真跑 11 行。

#### 3.1.22 friend_verify — 好友验证/打招呼 (general.db FMessageTable, ADR-469)

> **新事件类型** `friend_verify_update`(扩 alpha)。general.db `FMessageTable` → 一条好友验证一行。`scene` = 加好友
> 来源(坐实 person.friend_source 语义)。user_name(好友 wxid)明文 + _sha;content(打招呼语, text 类)明文 +
> content_len。**不存** encrypt_user_name/ticket/fmessage_detail_buf(低读值, drain 未取)。

```sql
CREATE TABLE IF NOT EXISTS friend_verify (
    account_id_sha   TEXT    NOT NULL,
    source           TEXT    NOT NULL,
    source_native_id TEXT    NOT NULL,
    user_name_sha    TEXT    NOT NULL,
    friend_type      INTEGER NOT NULL,
    timestamp        INTEGER NOT NULL,
    is_sender        INTEGER NOT NULL,
    scene            INTEGER NOT NULL,
    content_len      INTEGER NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; project_friend_verify 同源填)。
    account_id       TEXT    NOT NULL,
    user_name        TEXT    NOT NULL,
    content          TEXT    NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_friend_verify_scene
    ON friend_verify (account_id_sha, scene);
CREATE INDEX IF NOT EXISTS idx_friend_verify_time
    ON friend_verify (account_id_sha, timestamp DESC);
```

> content_digest = user_name_sha + timestamp + is_sender + scene (ADR-469; 恰 4 元)。
> friend_type(恒 37)/content(打招呼语)只进 L2。真跑 7905 行。

#### 3.1.23 finder_visit — 视频号号主访问 (general.db wcfinderuserpage, ADR-473)

> **新事件类型** `finder_visit_update`(扩 alpha 第 16 事件类型)。general.db `wcfinderuserpage` → 一个视频号号主一行
> (extra_buffer proto: f2=昵称 / f5=访问时刻 / f6=主页 URL)。owner_username(号主 wxid/微信号, **非**频道 id —
> ADR-473 §3.2 真库坐实纠正: 频道 id 在 profile_url 里)明文 + _sha;name(昵称)明文;profile_url(主页 URL 含频道 id,
> L2-only)明文。锚点 source_native_id = `Finder_<md5_8hex(owner_username)>`。
> ⚠️ **空壳行跳过**(ADR-473 §3.4): 真库 ~46% 是纯号主 id 空壳(proto 全空)。`run_finder_visit_pipeline` 在 assemble 后判
> `name.is_empty() && visit_time==0 && profile_url.is_empty()` → skip(既不 archive 也不落 L2);drain 不在 SQL 过滤
> (保 rowid 游标连续), 跳过数 `tracing::info!` 记账(No silent caps)。

```sql
CREATE TABLE IF NOT EXISTS finder_visit (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,
    owner_username_sha  TEXT    NOT NULL,
    visit_time          INTEGER NOT NULL,
    -- 明文列 (ADR-426 §2.1 第一类; project_finder_visit 同源填)。
    account_id          TEXT    NOT NULL,
    owner_username      TEXT    NOT NULL,
    name                TEXT    NOT NULL,
    profile_url         TEXT    NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_finder_visit_time
    ON finder_visit (account_id_sha, visit_time DESC);
```

> content_digest = owner_username_sha + name + visit_time (ADR-473; 恰 3 元; 号主 + 昵称 + 访问时刻)。
> profile_url(主页 URL, 含频道 id 冗余, 从 owner_username 可关联)只进 L2 不进 digest。

#### 3.1.24 custom_emoticon — 自定义表情 (emoticon.db kNonStoreEmoticonTable, ADR-478)

> **新事件类型** `CustomEmoticonCreate`(第 18 个 alpha 事件)。emoticon.db `kNonStoreEmoticonTable` 一条表情 → 一行。
> md5(表情内容身份, anchor `Emoticon_<md5>`)+ caption(中文描述)+ emoticon_type 进 digest(3 元);
> **aes_key(解密密钥)/各 url L2-only 不进 digest/payload**(K-R4: aes_key → Debug sha8)。空 md5 跳过。

```sql
CREATE TABLE IF NOT EXISTS custom_emoticon (
    account_id_sha    TEXT    NOT NULL,
    source            TEXT    NOT NULL,
    source_native_id  TEXT    NOT NULL,
    md5               TEXT    NOT NULL,     -- 表情内容 md5 (身份)
    emoticon_type     INTEGER NOT NULL,
    caption           TEXT    NOT NULL,     -- 中文描述
    account_id        TEXT    NOT NULL,
    product_id        TEXT    NOT NULL,
    aes_key           TEXT    NOT NULL,     -- 解密密钥
    cdn_url           TEXT    NOT NULL,
    thumb_url         TEXT    NOT NULL,
    tp_url            TEXT    NOT NULL,
    extern_url        TEXT    NOT NULL,
    extern_md5        TEXT    NOT NULL,     -- echotrace 查表键之一
    encrypt_url       TEXT    NOT NULL,
    PRIMARY KEY (account_id_sha, source, source_native_id)
);

CREATE INDEX IF NOT EXISTS idx_custom_emoticon_md5
    ON custom_emoticon (account_id_sha, md5);
```

> digest 3 元(md5/caption/emoticon_type)由 canonical 测试锁。解析器 decoder/emoticon.rs。真跑 15/15 落库。

#### 3.1.25 (无新表) biz_message 公众号消息 — 复用 §3.1.3 message 表 (ADR-480)

> **公众号消息不新增表**。biz_message_*.db 的 Msg_ schema 与普通 message 库完全一致(17 列)→ 复用整条 message
> pipeline(`AccountDbSource.biz_mode` 开关切 `is_biz_message_db` 过滤器, kind 仍 "message")。公众号消息落进同一
> §3.1.3 `message` 表, `source` 列 `biz_message_N.db|Msg_xxx` 与普通消息 `message_N.db|Msg_xxx` 区分
> (应用层 `WHERE source LIKE 'biz_message%'` 筛)。**白捡**: 所有 message 派生表(message_app 文章卡片 / media /
> mention / call / card / forward)自动生效, 零额外代码。etl_state 水位键含 rel_name(biz vs 普通)不撞。真跑 4932 公众号
> 消息 → message 表 + 4883 自动派生 message_app 卡片。

### 3.2 alpha 元数据 / 地图表 (6 张)

> **重要**: 本节钉【表结构】, 【怎么用】 在 §11.5-4 query-planner-查询规划.md 钉死 — 跟 D4 决策一致 (单一真相红线, 不双写)

#### 3.2.1 etl_state — 增量水位 (cursor)

```sql
CREATE TABLE IF NOT EXISTS etl_state (
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,         -- 源 db (e.g. "message_5.db") 或 "_global_" (全局水位)
    kind                TEXT    NOT NULL,         -- event_type, e.g. "message" / "contact_update"
    watermark_key       TEXT    NOT NULL,         -- e.g. "(create_time, sort_seq, local_id)"
    watermark_value     TEXT    NOT NULL,         -- JSON 元组 e.g. "[1780000000, 1780000000000, 100]"
    last_update         INTEGER NOT NULL,
    PRIMARY KEY (account_id_sha, source, kind)
);
```

#### 3.2.2 source_db_catalog — 已发现的源 db 清单

```sql
CREATE TABLE IF NOT EXISTS source_db_catalog (
    account_id_sha      TEXT    NOT NULL,
    db_path_sha         TEXT    NOT NULL,         -- 路径 sha (默认 sha 模式)
    db_path             TEXT,                     -- nullable — 默认 NULL; plaintext 模式下完整路径
    db_size_bytes       INTEGER NOT NULL,
    db_mtime            INTEGER NOT NULL,
    db_kind             TEXT    NOT NULL,         -- "message" / "contact" / "session" / "media" / "config" / "unknown"
    last_scanned_at     INTEGER NOT NULL,
    PRIMARY KEY (account_id_sha, db_path_sha)
);

CREATE INDEX IF NOT EXISTS idx_db_catalog_kind
    ON source_db_catalog (account_id_sha, db_kind);
```

#### 3.2.3 source_chat_index — chat → 源 db 明细映射

```sql
CREATE TABLE IF NOT EXISTS source_chat_index (
    account_id_sha      TEXT    NOT NULL,
    chat_id_sha         TEXT    NOT NULL,         -- chat 标识 sha (跟 message.conv_id_sha 对齐)
    db_path_sha         TEXT    NOT NULL,
    message_count       INTEGER,                  -- nullable — 未扫前 NULL
    last_msg_time       INTEGER,                  -- nullable
    PRIMARY KEY (account_id_sha, chat_id_sha, db_path_sha)
);

CREATE INDEX IF NOT EXISTS idx_chat_index_db
    ON source_chat_index (account_id_sha, db_path_sha);
```

#### 3.2.4 source_chat_to_db — chat 跨 db 分布【物化聚合表】

```sql
-- 物化聚合表 (注意: 是真表 CREATE TABLE, 不是 SQL VIEW)
-- 从 source_chat_index 派生: 每 chat 一行, 用于 inspect / cost model 快速查询
-- 刷新责任方 + 刷新触发条件 (写入时 / 定期 / 显式 refresh) 推 §11.5-4 query planner 钉

CREATE TABLE IF NOT EXISTS source_chat_to_db (
    account_id_sha          TEXT    NOT NULL,
    chat_id_sha             TEXT    NOT NULL,
    total_message_count     INTEGER NOT NULL,
    db_count                INTEGER NOT NULL,     -- chat 分布在几个 db
    first_msg_time          INTEGER,
    last_msg_time           INTEGER,
    PRIMARY KEY (account_id_sha, chat_id_sha)
);
```

> KI: source_chat_index 跟 source_chat_to_db 部分冗余 (后者可由前者 GROUP BY 算出). 保留 to_db 用于 cost model 快查; §11.5-4 query planner 收敛时复审是否合并 (走 supersede ADR)

#### 3.2.5 source_db_timerange — 每 db 时间窗

```sql
CREATE TABLE IF NOT EXISTS source_db_timerange (
    account_id_sha      TEXT    NOT NULL,
    db_path_sha         TEXT    NOT NULL,
    min_msg_time        INTEGER,                  -- nullable — 空 db / 未扫
    max_msg_time        INTEGER,
    PRIMARY KEY (account_id_sha, db_path_sha)
);
```

#### 3.2.6 source_query_plans — 查询计划缓存

```sql
CREATE TABLE IF NOT EXISTS source_query_plans (
    account_id_sha      TEXT    NOT NULL,
    query_signature_sha TEXT    NOT NULL,         -- 查询参数 sha (chat_id + 时间窗 + 关键词等)
    plan_json           TEXT    NOT NULL,
    estimated_cost      INTEGER,                  -- 估算 ms
    last_used_at        INTEGER NOT NULL,
    hit_count           INTEGER NOT NULL,
    PRIMARY KEY (account_id_sha, query_signature_sha)
);

CREATE INDEX IF NOT EXISTS idx_query_plans_lru
    ON source_query_plans (account_id_sha, last_used_at DESC);
    -- LRU 淘汰策略: 保留 last_used_at DESC 前 N 行, 删除其余
    -- 具体 SQL 跟 N 取值 (按 cache_size_mb / 行数上限) 推 §11.5-4 query planner 钉
```

### 3.3 0.2.0+ 预留表 (只列名)

```
favorite 骨架     ✅ 已落 §3.1.10 (ADR-454 扩 alpha); 剩 标签体系 (批 B-2) + content 拆解 (大件, ADR-454 KI-B) 仍 backlog
moment            ✅ 已落 §3.1.15~3.1.18 (ADR-467/474 扩 alpha; 动态本体 + 逐条媒体/互动 + 好友动态索引); 纯 Rust 全量路 (本地缓存 .dat 扫盘) 留后
attachment_blob   附件二进制 / 媒体索引 — 0.2.0+

具体 schema 跟字段调研走, 0.2.0 ADR-401-supersede 再钉.
```

### 3.4 PRAGMA 设定 (打开 L1 文件时强制 + 顺序敏感)

```sql
-- ⚠️ 顺序敏感: page_size 必须在【任何 CREATE TABLE 之前】 设置, 否则不生效
-- 新库初始化:
PRAGMA page_size = 4096;            -- 默认 4096 (SQLite 推荐, 跟微信编码习惯一致;
                                    -- 后续 SQLCipher 加密时 page-by-page 处理)

-- 然后设其他 PRAGMA:
PRAGMA journal_mode = WAL;          -- 并发读写
PRAGMA synchronous = NORMAL;        -- 性能 / 安全平衡
PRAGMA foreign_keys = ON;           -- 严格外键 (虽然本 schema 当前不用 FK, 留扩展)
PRAGMA temp_store = MEMORY;         -- 临时表走内存
PRAGMA busy_timeout = 5000;         -- 5 秒等锁后退避 (跟 §7 失败模式对齐)

-- 然后才 CREATE TABLE ... (见 §3.1 / §3.2)

-- 已存在库改 page_size 必须 VACUUM (耗时); 本 schema migration 设计【不准】 改 page_size
```

> SQLCipher 加密: PoC-1 调研期不加密 (ADR-029 R5); alpha 看用户机器策略 (Windows ACL / DPAPI 密钥)
> 详见 cipher-加密.md / ADR-404

---

## 4. capability_backlog 字段策略 (跟需求 §5.3)

### 4.1 28 缺口字段 alpha 分布 (路线图位置)

| 字段类别 | 字段数 (估) | 路线图位置 | status (初始) | reference_project |
|---|---|---|---|---|
| wallet (钱包/红包/转账) | ~7 | 0.3.0+ 探索, 1.0.0 前完成 | unimplemented | "" |
| linked_account (通讯录关联) | ~1 | 0.3.0+ 探索 | unimplemented | "" |
| favorite (收藏骨架) | ~8 | **alpha 已落** (ADR-454 §3.1.10) | shipped | "wx-cli" |
| favorite (标签 M:N) | ~4 | **alpha 已落** (ADR-454 §3.1.11 批 B-2) | shipped | "wx-cli" |
| favorite (content 拆解) | ~? | 大件 (按 type 拆, ADR-454 KI-B) | researching | "wx-cli" |
| miniprogram (小程序) | ~4 | 1.0.0 后 backlog | unimplemented | "" |
| wechat_sport (微信运动) | ~3 | 1.0.0 后 backlog | unimplemented | "" |
| login_log (登录日志) | ~3 | 1.0.0 后 backlog | unimplemented | "" |
| contact_extra (联系人扩展) | ~4 | 0.3.0+ 探索 | unimplemented | "" |
| **合计** | **~28** | | | |

> 具体 28 字段名 / 微信源 db 表列定位 → 跟字段调研走, 由 ADR-401 实施 PR 在数据迁移 / seed 脚本里填初值

### 4.2 写入规则

```
进入 capability_backlog 的【唯一渠道】:
   1. 字段调研发现一个【缺口字段】 → INSERT 一条
   2. 调研推进 → UPDATE status / notes / updated_at
   3. 真挖到字段 (有 src_table + src_column) → UPDATE status='ready'

【不准】 直接 ALTER 业务表加占位字段 (会变 NULL 假合同, 违反需求 §5.3)
```

### 4.3 查询规则 (上层应用 / CLI 暴露)

```sql
-- 上层应用判断"这个字段能用吗":
SELECT status FROM capability_backlog
WHERE field_category = ? AND field_name = ?;

-- CLI 看 backlog 状态:
SELECT field_category, COUNT(*), status
FROM capability_backlog GROUP BY field_category, status;

-- 即将转正的字段 (status='ready'):
SELECT field_category, field_name, target_milestone
FROM capability_backlog WHERE status='ready';
```

### 4.4 字段转正流程 (capability_backlog → 业务表 alpha schema)

```
1. capability_backlog UPDATE status='ready'
2. 写 ADR (例: ADR-450 wallet_amount 进 alpha) — 必须含:
   · src_table + src_column 实证
   · 跟现有字段冲突分析
   · migration 脚本草稿
3. 写 migration 脚本 (schema_meta.version + 1):
   ALTER TABLE message ADD COLUMN wallet_amount INTEGER;  -- 显式 schema 变化
4. raw-payload-输出格式.md 字段集同步加 (跟 ADR-412 联动)
5. UPDATE status='shipped'
```

> 这是【显式 schema 变化】 — 上层应用一看 schema 改了就知道新字段可用; 区别于 PoC-1 阶段【偷偷加占位字段】 的反模式

### 4.5 跨 wxid 文件 capability_backlog 一致性维护 (r2 P1-merge-2 修订)

```
背景: 需求 §6.6 多账号物理隔离 — 每 wxid 独立 L1 文件 (%LOCALAPPDATA%\native-cli\cache\<wxid_sha>.db).
      capability_backlog 是【登记表性质】 (§2 豁免), 每文件独立 28 行,
      行【内容】 跨文件应保持一致 (软一致), 不是物理共享 1 行 (硬一致).

跨文件一致性维护机制:

A. 起点 — v1 seed 一致性:
   · 每个 L1 文件 v1 初始化 (§5.2 步骤 7) 跑同一份 seed 脚本
   · seed 脚本随 binary 发版, 保证所有 wxid 文件起点完全一致
   · **v1 seed immutable** — 不准不同 binary 版本漂 v1 seed; seed 内容 / status 变化必须 bump migration
       (e.g. seed 加新字段 / 改 status 默认值 → schema_meta.version + 1 走 migration 链, 不准沉默改 v1 seed)
   · 反例预防: binary 0.1.0 → 0.1.1 改 v1 seed wallet_amount status 默认值 (不 bump version)
              → 旧 wxid_A v1 文件 status='unimplemented'; 新 wxid_B v1 文件 status='researching'
              → 软一致破, 跨文件漂移

B. 演进 — migration 一致性:
   · 字段转正流程 (§4.4) 步骤 1+5 影响 capability_backlog (status 翻 'ready' → 'shipped')
   · 这两步必须在【每个 wxid 文件】 的 v(N) → v(N+1) migration 事务内跑
   · binary 启动时检测 schema_meta.version, 自动跑 migration → 每个 --wxid 切换都触发自身文件 migration
   · 所有 wxid 文件升到 binary 期望版本 vN 后, capability_backlog 整体一致

B-1. migration 失败兜底 (§5.4):
   · 副号 migration 失败 → §5.4 兜底 abort + 备份 + 用户决定;
   · 副号文件永久卡老版本 vM (M < N) 时, 该 wxid 整体不可访问 (不是【部分字段可用】);
   · 上层应用层面 wxid_B 不可用 → 直接返回错误, 不查 capability_backlog;
   · 跟 D 段约束兼容 — D 段假设是【可访问 wxid 文件之间的】 状态一致性, 不 cover【wxid 不可访问】

C. 中间态 (部分文件已升 / 部分未升) — 上层应用约束:
   · 用户启动 native-cli --wxid wxid_A 后, 后台跑 wxid_A migration 期间
       同时另一会话启动 native-cli --wxid wxid_B (新建 v1 文件) — wxid_B 文件尚未升级
   · 此时上层应用查 capability_backlog 状态【可能跨文件不一致】 (主号 'shipped' / 副号 'unimplemented')
   · 上层应用【硬约束】:
       - 查 capability_backlog 必须走【当前 --wxid 文件】, **不准跨 wxid 文件聚合**
       - 例: SELECT status FROM <wxid_A.db>.capability_backlog 查主号; 切到副号要重 SELECT <wxid_B.db>
       - 如果上层暴露 "wallet_amount 能用吗" API, 必须挂【当前会话 wxid】 上下文, 不全局缓存
   · 单 wxid 用户不受影响 (单文件一致); 多账号用户 (需求 §6.6) 上层必须遵循上述约束

D. 反例预防:
   · 错误做法: 上层应用启动时一次性读 capability_backlog 缓存"全局字段可用清单"
                 用户切 wxid 时仍用缓存 → 主号 v2 / 副号 v1 错配 → SELECT message.wallet_amount → "no such column"
   · 正确做法: 上层应用每次切 --wxid 时重新读【目标文件】 capability_backlog
                 或: 上层应用查具体字段时附带 wxid 参数 + 读对应文件

→ 跟需求 §6.6 多账号支持 + §5.3 D 路线一致
→ 跟 §11.5-3 native-core trait / §11.5-4 query planner 接口设计强相关 (推 ADR-405 钉死 wxid 上下文传递)
```

---

## 5. migration 策略 (待 ADR-402 收敛)

### 5.1 版本号管理

```
schema_meta.value WHERE key='version' = 当前 schema 版本号 (int, 单调递增)

【术语定义】: binary 期望版本 = binary 编译时钉死的 schema 版本号
   e.g. native-cli v0.2.0 期望 schema v2
   启动时 schema_meta.version < binary 期望版本 → 自动跑 migration
   schema_meta.version > binary 期望版本 → 拒绝启动 (旧版 binary 不识别新 schema)

v1: 本文档 §3 全表 (alpha 起始)
v2+: 走 ADR + 升级脚本

升级路径:
   v1 → v2:  加字段 (ALTER ADD COLUMN, 必须有默认值)
   v2 → v3:  重命名字段 (CREATE NEW TABLE + COPY + DROP OLD)
   v3 → v4:  拆表 / 合表 / UNIQUE 约束变更 (大改, 走 ADR + 双审)
```

### 5.2 v1 初始 schema (本文档 §3 全表)

```
v1 初始化时 (顺序敏感):
   1. PRAGMA 全设 (§3.4) — 【注意】 page_size 必须在 CREATE TABLE 之前!
   2. 创建 schema_meta 表 (§3.1.1)
   3. 插入 schema_meta 初始 5 行:
        ('version',           '1',           unixepoch())
        ('created_at',        unixepoch(),   unixepoch())
        ('app_version',       '0.1.0-alpha', unixepoch())
        ('migration_history', '[]',          unixepoch())  -- v1 自身不算 migration
        ('account_id_sha',    '<wxid_sha>',  unixepoch())
   4. 创建 §3.1.2 ~ §3.1.9 余下 8 张业务表
   5. 创建 §3.2 6 张元数据表
   6. 不创建 §3.3 0.2.0+ 表
   7. seed capability_backlog 28 字段 (status='unimplemented' / 'researching', updated_at=unixepoch())
```

### 5.3 升级路径示例 (v1 → v2: wallet_amount 字段转正)

> 本节 SQL 必须【可执行】 — 拿 sqlite3 跑一遍要过. r1 codex/Claude 反例已验证.

```sql
-- migration_001_v1_to_v2.sql
BEGIN TRANSACTION;

ALTER TABLE message ADD COLUMN wallet_amount INTEGER;  -- 默认 NULL (老消息没钱包)

UPDATE schema_meta
   SET value='2',
       updated_at=unixepoch()
 WHERE key='version';

UPDATE schema_meta
   SET value=json_insert(
        value,
        '$[#]',
        json_object(
            'from', 1,
            'to', 2,
            'at', unixepoch(),
            'note', 'wallet_amount per ADR-450'
        )
       ),
       updated_at=unixepoch()
 WHERE key='migration_history';

UPDATE capability_backlog
   SET status='shipped',
       updated_at=unixepoch()
 WHERE field_category='wallet' AND field_name='wallet_amount';

COMMIT;
```

**用法笺记**:
- `unixepoch()` 是 SQLite 内置(3.38+; 微信本地 sqlite 满足). 别用 `now` (没该函数)
- `json_insert` 跟 `json_set` 对 `'$[#]'` 数组追加都有效, 但 `json_insert` **不覆盖已存值**, 语义更严, 跟 §3.1.1 "每次 migration 追加" 对齐
- `json_object(k, v, ...)` 比字符串拼 `json('{...}')` 安全, 不怕 note 含 `'` / `"` 字符破 SQL

### 5.4 兼容矩阵 + 失败兜底

```
启动时检测 schema_meta.value WHERE key='version':
   · < binary 期望版本 → 自动跑 migration 序列 + 备份原 db
   · = binary 期望版本 → 正常启动
   · > binary 期望版本 → 拒绝启动 (用户装了旧版 binary)

migration 失败:
   1. 自动 rollback 事务
   2. 保留备份文件 (<wxid>.db.bak.<old_version>)
   3. abort 启动, 提示用户:
      "schema migration v{old} → v{new} 失败, 备份在 X, 请联系开发"
   4. 【不自动回滚到老版本】 — 由用户决定下一步

详细 migration 状态机 + 跨版本跳跃 (v1 → v3) 走 ADR-402
```

---

## 6. 跟其他模块的引用

```
被依赖:
   · query_planner (query-planner-查询规划.md) — 查 Tier 1 + 用 §3.2 地图表做路由
   · cli (cli-命令行.md) — cache add / wipe / inspect 写读 L1
   · adapter (adapter-适配器.md) — raw_payload_archive 写入 + 业务表事务
   · raw-payload-输出格式.md (§11.5-8) — 字段集对应 (但不强相等; raw_payload 跟 L1 是两个模型)

依赖:
   · rusqlite (PoC-1 已用) / 未来 SQLx 候选
   · 02-schemas/config-events-配置和事件.md — event_type / event_action 枚举定义
   · 需求 §5.3 / §6.6 / §6.8 (基线)

不依赖 (虽然字段相似):
   · 源微信 db schema — 经 adapter 标准化, L1 不直连
```

---

## 7. 失败模式

```
磁盘满 (CoreError::Sink(SinkError::DiskFull)) → MATRIX §2 #6 拒绝写入 + 提示清理 / 改 cache_dir
schema 版本不匹配    → 升级路径 (§5) / 拒绝启动 (旧版 binary)
锁死 (concurrent)   → MATRIX §2 #10/#14 (SQLite WAL 自然支持; busy_timeout = 5s 后退避)
db 文件损坏         → MATRIX §2 #7 间接 (rebuild-map 兜底走 #7 dirty 路径; 物理损坏检测推 0.2.0+ 独立 KI)
account_id 不匹配   → 写入时校验 = schema_meta.account_id_sha, 不匹配 abort
                      理由: 防 cache_dir 文件被错配 (e.g. 用户改路径后串号)
capability_backlog UNIQUE 冲突 → INSERT OR REPLACE (调研中字段可覆盖)
archive 表 5 元组冲突 → INSERT OR IGNORE (重放场景, 同事件多次 emit 上层去重)
                       【不是】 INSERT OR REPLACE (replace 会改 ingest_time, 影响 24h 滚动)
```

---

## 8. 测试入口

```
单测:    crates/native-core/src/schema/l1/ 内
         · 每张表 CREATE / INSERT / SELECT 单测
         · capability_backlog 状态迁移测
         · schema_meta migration_history JSON 追加测

集成:    tests/l1_migration.rs (v1 → v2 → v3 升级链)
         tests/l1_archive_idempotent.rs (5 元组 UNIQUE 验证, 含群成员先退后加再退反例)
         tests/l1_multi_account_isolation.rs (两个 wxid_sha 文件不串)

E2E:     §11.5-12 E2E-1 装机闭环 (含 L1 首次创建 + capability_backlog seed)
         §11.5-12 E2E-2 24h 长稳跑 (验证 raw_payload_archive 滚动删除)
         §11.5-12 E2E-3 撤回事件 (验证 archive 不吞)
         §11.5-12 E2E-4 群成员先退后加再退 (验证 event_seq 区分)

性能:    §11.1 验收档
         · L1 命中 p95 < 100ms (主号 / 副号)
         · raw_payload_archive INSERT 吞吐 ≥ 5k/s (单文件)
```

---

## 9. 从 PoC-1 迁移 (具体 SQL diff)

> 详细 PoC-1 代码 → docs-dev 迁移路径在 §11.5-9 / ADR-415; 本节只列 SQL 层 diff

### 9.1 PoC-1 现有 (wechat-poc-0/crates/v3-l1-sink/src/lib.rs) → docs-dev v1

| PoC-1 表 | docs-dev v1 | 改动 |
|---|---|---|
| `raw_payload_archive` | `raw_payload_archive` | **加** account_id_sha / event_type / event_action / event_seq;   **改名** kind→event_type, created_at→ingest_time;   UNIQUE 从 3 元组 → 5 元组 |
| `etl_state` | `etl_state` | **加** account_id_sha 列, PK 三元组 |
| `message` | `message` | **加** account_id_sha, PK 改三元组 (account_id_sha + source + source_native_id) |
| `person` | `person` | **加** account_id_sha, PK 改三元组 (PR2-2 修正: 第三列用 username_sha 而非 source_native_id, 消除 8hex 撞车) |
| `person_alias_by_account_min` | `person_alias_by_account_min` | 字段已是 account_id_sha 命名 — 无改 |
| `session` | `session` | **加** account_id_sha, PK 改三元组 |
| (无) | `schema_meta` | **新表** |
| (无) | `chatroom` | **新表** |
| (无) | `chatroom_member` | **新表** |
| (无) | `capability_backlog` | **新表** |
| (无) | `source_db_catalog` 等 6 张地图 | **新表** |

### 9.2 PoC-1 → v1 SQL migration 模式 (示意)

> **范围**: 完整可执行 migration 脚本由 §11.5-9 / ADR-415 实施 PR 钉死, 本节给出【一段完整可执行示例】 (raw_payload_archive 改造) + 其余表【模式说明】.
>
> r1 反例 (codex P1-1 / Claude P1-5): 草稿用 `(...)` 占位 + `now` 不合法 SQL → 不能执行. r2 改: 给一段完整可跑, 其余 push §11.5-9.

#### 完整可执行示例 — raw_payload_archive 3 元组 → 5 元组改造

```sql
BEGIN TRANSACTION;

-- 取当前 wxid_sha (从 schema_meta — 假设 schema_meta 表已通过本 migration 步骤 1 创建并 seed)
-- 实际 §11.5-9 实施 PR 用 ATTACH / 临时变量, 这里示意逻辑

-- Step 1: 创建新结构 archive (5 元组 UNIQUE + payload_json)
CREATE TABLE raw_payload_archive_new (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id_sha      TEXT    NOT NULL,
    source              TEXT    NOT NULL,
    source_native_id    TEXT    NOT NULL,
    event_type          TEXT    NOT NULL,
    event_action        TEXT    NOT NULL,
    event_seq           INTEGER NOT NULL,
    ingest_time         INTEGER NOT NULL,
    payload_json        TEXT    NOT NULL,
    UNIQUE (account_id_sha, source, source_native_id, event_action, event_seq)
);

-- Step 2: 历史数据复制 (近似映射, 缺字段填默认)
INSERT INTO raw_payload_archive_new
    (account_id_sha, source, source_native_id, event_type, event_action, event_seq,
     ingest_time, payload_json)
SELECT
    (SELECT value FROM schema_meta WHERE key='account_id_sha'),  -- 取本文件 wxid
    source, source_native_id,
    kind,                                          -- PoC-1 kind = event_type 语义对齐
    'create',                                      -- 历史数据全标 create (无 event_action 区分)
    1,                                             -- event_seq 起始 1 (历史无重放, 视为单一实例)
    created_at,                                    -- PoC-1 created_at → ingest_time
    raw_json                                       -- PoC-1 raw_json → payload_json
                                                   -- ⚠️ 实际 §11.5-9 实施时要按 ADR-412 隐私过滤规则【重过滤】
                                                   -- 本示意只展示字段映射, 不展示隐私重过滤层
FROM raw_payload_archive;

-- Step 3: 切表
DROP TABLE raw_payload_archive;
ALTER TABLE raw_payload_archive_new RENAME TO raw_payload_archive;

-- Step 4: 创建索引 (§3.1.2 完整 DDL)
CREATE INDEX idx_archive_account_ingest
    ON raw_payload_archive (account_id_sha, ingest_time DESC);
CREATE INDEX idx_archive_event_type
    ON raw_payload_archive (event_type, event_action);

COMMIT;
```

#### 其余表改造模式 (推 §11.5-9 实施 PR)

```
message / person / session / etl_state — 同 (新表 + COPY + DROP OLD + RENAME) 模式
   · 改造点: 加 account_id_sha 列 + PK 改三元组 + 索引重建
   · 历史 account_id_sha 值: 从 schema_meta 取 (单文件单 wxid)

新增表 (PoC-1 没): schema_meta / chatroom / chatroom_member / capability_backlog
              + 6 张地图表 (source_db_catalog / source_chat_index / source_chat_to_db /
                            source_db_timerange / source_query_plans / etl_state)
   · 直接 CREATE + seed 初始数据

历史地图表 seed (PoC-1 没采集):
   · source_db_catalog / chat_index / db_timerange — 走 native-cli rebuild-map 重新扫描填
   · capability_backlog — 走 ADR-415 实施 PR 内 seed 脚本填初始 28 字段
   · query_plans — 空表起步, 跑起来填
```

### 9.3 改名映射 (便利 grep)

```
PoC-1                          → docs-dev v1
─────────────────────────────────────────
RawPayload.kind                → RawPayload.event_type (+加 event_action / event_seq)
RawPayload.created_at          → RawPayload.ingest_time
RawPayload.raw_json            → RawPayload.payload_json (语义改: 经隐私过滤的 payload JSON; 详 §3.1.2)
SqliteSink.write_*_with_archive → 保留 trait, impl 内事务改写 archive 5 元组
PoC-1 V3Message (lib.rs)       → docs-dev v1 同字段集 + 加 account_id_sha 列
poc-1-2-router                 → native-core::query_planner 模块 (跟 ADR-415 §3.14 / ADR-416 §3.2.1 / §11.5-4 ADR-406 钉死, r2 修订)
```

---

## 10. 已知问题 / 跨件待对齐 (KI)

```
KI-1: PoC-1 v3-l1-sink/src/lib.rs 当前判重 = UNIQUE(source, source_native_id, kind)
      仅 3 元组, 缺 account_id_sha / event_action / event_seq.
      撤回 + 群成员先退后加再退【会被吞】 + WAL 重读 / cursor 重置后重放也会撞键
      → 跟需求 §6.8 契约 3 (b)(c)(d) 冲突.
      → 不阻塞本文档 / ADR-401 落地; **推 §11.5-9 / ADR-415 代码迁移阶段修**
        (跟踪走 §11.5-9 件状态机, 不挪到 capability_backlog — backlog 是【28 缺口字段跟踪】 表,
         加 'infra' 类别会打穿表语义)

KI-2: 唯一键字段组成 + event_seq fingerprint 算法【单一收敛在 ADR-401 §10 KI-B】.
      详见 docs-dev/40-ADR/ADR-401-l1-schema-定型.md §10 KI-B.
      (本主文档不再复述 — 避免单一真相违反; r2 P1-merge-4 修订)

KI-3: source_chat_index 跟 source_chat_to_db 部分冗余 (后者可由前者 GROUP BY 算).
      保留 to_db 用于 cost model 快查; §11.5-4 query planner 收敛时复审是否合并.

KI-4: 28 缺口字段【具体字段名】 待字段调研产出, 本文档 §4.1 只列类别 + 估数.
      ADR-401 实施 PR 在 seed 脚本里填初值 (status='unimplemented' / 'researching').

KI-5: account_id_sha 命名跟 raw-payload-输出格式.md §4 写的 "account_id"  字面不一致
      (后者没带 _sha 后缀). 实际是同一字段 — 默认 sha 模式下值是 sha, plaintext 模式下值是真 wxid.
      → 推 §11.5-8 字段集 ADR-412 收敛时统一命名 (建议跟本文档保持 _sha 后缀, 显示编码方式).
      同 KI 影响 source 字段命名 (主文档 §3 全表 `source TEXT NOT NULL` 直接存文件名,
      没区分 sha 模式) — 推 ADR-412 一并审.

KI-6: archive.payload_json 隐私过滤规则【单一收敛在 ADR-401 §10 KI-B】.
      详见 docs-dev/40-ADR/ADR-401-l1-schema-定型.md §10 KI-B.
      (本主文档不再复述 — 避免单一真相违反; r2 P1-merge-4 修订)

KI-7: chatroom_member.source_native_id (业务表 §3.1.7 用复合 "<chatroom>:member:<wxid>")
      跟 raw_payload_archive.source_native_id (§3.1.2) 的语义对齐: 同事件应当用同样的复合
      派生 id 才能 JOIN 反查. 推 §11.5-8 ADR-413 一并钉死.

KI-8: §1 + §2 红线区分两层职能 (archive 必写 / 业务表可选) — 责任边界跟 §11.5-3 adapter
      接口 + §11.5-4 query planner 强耦合. 本 ADR 已明示, 但具体 trait 接口 (e.g. adapter
      启动时是否必须 ensure archive table 存在 + cache add 跟 archive 写入是否走同一事务)
      推 §11.5-3 / ADR-405 钉.
```

---

> **维护规则** (跟 CONTRIBUTING.md §2): 改 §3 任何表字段必走新 ADR 或 supersede ADR-401.
> **单一真相红线**: 其他文档 (raw-payload-输出格式.md / decoder-解码.md / query-planner-查询规划.md / cli-命令行.md) 引用 L1 schema 时只引用本文件章节号, 不复制字段.
