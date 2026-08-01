//! token 预算折叠 (④文档 §2.2) —— 把内核查询结果 `{data, meta}` 收窄成给 LLM 的紧凑输出。
//!
//! **折叠 = 投影, 不是丢字段** (④文档洞1): 去掉 LLM 永远用不上的 digest/密钥/hex/原始 payload,
//! 长正文截断留摘要 (给"用 wx_inspect 取全文"逃生口), **必留昵称/时间/正文摘要**(LLM 靠它推理+向用户复述)。
//! 整行逃生口走 wx_inspect / detail=full (非本层职责)。

use serde_json::{json, Value};

/// 单次工具结果的字节**默认**预算 (49152 = 48KiB)。不传 `max_bytes` 时用它 —— 保持旧调用完全兼容。
/// 行数管不住体积 (一条巨 recordinfo 就爆) → 超则收窄/截行 + 提示分页。~48KB ≈ 中文 1.5-2 字节/token
/// → 约 8-12K token (§2.2 backstop)。
pub const DEFAULT_MAX_BYTES: usize = 48 * 1024;

/// 调用方可申请的字节预算**硬上限** (524288 = 512KiB)。`max_bytes` 超此值必钳到此 —— 不能无限放大 (防单条
/// 结果撑爆 LLM 上下文 / 内存)。
pub const HARD_MAX_BYTES: usize = 512 * 1024;

/// 调用方可申请的字节预算**下限** (16384 = 16KiB)。低于此值钳到此 —— 太小连骨架+提示都放不下、失去意义。
pub const MIN_MAX_BYTES: usize = 16 * 1024;

/// **封口预留** (复审 codex/Claude 双 P1): 所有折叠路径 (`budget_fold`/`cap_pack`/`inspect_capped`/`inspect_field`)
/// 都按 `budget - 此值` 来 fit, **给 [`enforce_budget`] 事后盖的 `meta._budget` 子对象 (~140B 最坏) + budget_fold
/// 步骤1 的 content_truncated notice (~80B) 预留位** —— 否则 fit 到 budget 后盖 `_budget` 就撑破、兜底闸把整页
/// 数据清空 (P1: 本能返的结果被清成空)。512 = 最坏 ~220B 的 2.3x 余量。
const SEAL_RESERVE: usize = 512;

/// 一个字符在 **JSON 字符串里**占的字节数 (serde_json 转义规则): `"`/`\`/`\n\r\t` + backspace/formfeed → 2 字节
/// 短转义; 其它控制字符 (<0x20) → 6 字节 `\u00XX`; 余者 = UTF-8 原字节 (serde_json 不转义 `/` 与非 ASCII)。
/// **复审 codex/Claude P1**: `inspect_field` 分段必须按此 (非 `len_utf8`) 算 —— 满是引号/反斜杠/控制符的字段
/// 序列化后膨胀 2~6x, 只按原字节切会让 `content` 序列化后破 budget。
fn json_str_byte_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
        c if (c as u32) < 0x20 => 6, // 其它控制字符 → \u00XX
        c => c.len_utf8(),
    }
}

/// 把调用方给的 `max_bytes` 解析成本次请求的预算: 不传 → [`DEFAULT_MAX_BYTES`]; 传了则钳到
/// `[MIN_MAX_BYTES, HARD_MAX_BYTES]` (超上限钳上限, 不能无限放大; 低于下限钳下限)。
#[must_use]
pub fn resolve_budget(max_bytes: Option<u64>) -> usize {
    match max_bytes {
        None => DEFAULT_MAX_BYTES,
        Some(n) => {
            let n = usize::try_from(n).unwrap_or(HARD_MAX_BYTES);
            n.clamp(MIN_MAX_BYTES, HARD_MAX_BYTES)
        }
    }
}

/// 截断时给 AI 的"下一档"建议预算 (128/256/512 KiB): 返回**严格大于当前预算**的最小档; 已达最高档 → `None`
/// (无更高可建议, `suggested_max_bytes` 省略)。让 AI 看到 `truncated=true` 后能一步跳到够用的档、不用瞎试。
#[must_use]
pub fn suggest_next_budget(current: usize) -> Option<usize> {
    [128 * 1024, 256 * 1024, HARD_MAX_BYTES]
        .into_iter()
        .find(|&tier| tier > current)
}

/// 长文本截断阈值 (字符; §2.2 正文超长截 ~500-1000 字)。
const TEXT_TRUNC_CHARS: usize = 800;

/// LLM 永不需要的列: 命中即删 (digest 影子列 / 加密密钥 / hex blob / 原始 payload)。
///
/// **H4 修**: 密钥判据收紧到精确 crypto 名 (旧 `contains("aes")`/`ends_with("_key")` 会误杀 `sort_key`
/// 等正常列)。**保留** `account_id` (账号主人自己的 wxid, MCP 自读自数据需知是谁的, 非泄漏; 冗余的
/// `account_id_sha` 才删)。
///
/// **R16-1 (用户 2026-07-18 决策⑥, 办法二): URL 类不再删**。原先删 `cdn_url`/`thumb_url`/`head_url`/
/// `cover_url` —— 但 CLI/HTTP 都出这些, MCP 删了就三皮不一致(emoticon 三皮对拍 NO-GO: MCP 少 cdn_url)。
/// 用户拍板 MCP 也出网址、三套死磕一致(MCP 额度已调大, "省 token"不再是理由)。
/// **密钥/二进制仍删**: 它们从**不在任何列表命令的输出里**(引擎/手写查询不 SELECT 密钥, 密钥只在媒体
/// 下载内部用)→ CLI/HTTP 也不出 → 删它们不破坏三皮一致, 纯是别把 crypto key 冒给 LLM。三皮对拍验证此
/// 前提: 某命令若真在输出里带密钥列 → 对拍红, 再议。
fn is_dropped_key(k: &str) -> bool {
    // digest 影子列 (LLM 永不需要 digest)。
    k.ends_with("_sha")
        // 加密密钥 (精确名, 不误杀 sort_key/primary_key 等正常 _key 列)。
        || k.contains("aeskey") || k.contains("aes_key") || k == "file_key" || k == "cdn_key"
        // 原始 payload / hex blob / 二进制缓冲。
        || k == "raw_xml"
        || k == "raw_payload"
        || k == "recordinfo"
        || k == "extra_buffer"
        || k.ends_with("_hex")
        || k.ends_with("_blob")
}

/// XML 属性名是否敏感 (其值须抹除)。`name` 已小写 ASCII。
///
/// **值级脱敏的由来** (审查 P1-1): 媒体消息 (msg_type 3/43/47/49) 正文是原始 XML
/// `<img aeskey=".." cdnthumburl=".." md5=".."/>`, 密钥/CDN 址内嵌在 `text_content`/`text` **列的值**里 ——
/// 列名不命中 [`is_dropped_key`] (它只按列名判黑), 且 800 字截断留头恰好保住头部 aeskey → 整串 AES 密钥
/// 喂给 LLM。故必须扫**属性值**脱敏, 不能只按列名。
///
/// **R16-1 决策⑥(用户 2026-07-18, 办法二): 只抹密钥, URL/md5 保留**。原先这里连 `cdn`/`encrypturl`/
/// `md5` 也抹 —— 但那是 URL/内容摘要不是密钥, 而 CLI/HTTP 不抹(它们直接序列化原 QueryResult) → 带媒体
/// XML 的消息行 MCP 跟 CLI/HTTP 不一致(codex 审 P1)。我只改了顶层 `is_dropped_key` 的列, 漏了 XML 值级
/// 这第二处删 URL 的地方 —— **判据是"所有抹 URL 的地方", 不是"想到的那一处"**(本轮反复栽的坑)。
/// → 现在**只抹真密钥** `aeskey`(含 `cdnthumbaeskey` —— 名字带 cdn 但它是密钥, `has(aeskey)` 命中)。
/// URL(`cdnthumburl`/`encrypturl` 等)与 `md5`(内容摘要, 顶层字段 CLI/HTTP 都出)一律保留。
fn is_secret_attr(name: &[u8]) -> bool {
    fn has(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }
    // **只匹配真 AES 密钥**。`cdnthumbaeskey` 名字含 cdn 但含 aeskey → 命中, 仍抹(密钥优先)。
    // URL(cdn*url/encrypturl)与 md5(内容摘要)**不再匹配** → 保留, 与 CLI/HTTP 一致。
    has(name, b"aeskey")
}

/// 抹除 XML 里敏感属性的值 (`aeskey="X"` → `aeskey="***"`), 保结构与正文不动。返 `Some` 仅当确有抹除。
/// **只在 ASCII 引号边界切** (属性名/`=`/引号皆 ASCII, 值整段拷贝或整段换 `***`) → 输出恒合法 UTF-8。
fn redact_xml_secrets(s: &str) -> Option<String> {
    if !s.contains('=') {
        return None; // 快路: 无 `=` 不可能是属性 XML (绝大多数文本消息)。
    }
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    let mut changed = false;
    while pos < bytes.len() {
        let byte = bytes[pos];
        if !byte.is_ascii_alphabetic() {
            out.push(byte);
            pos += 1;
            continue;
        }
        // 读属性名 [A-Za-z0-9_:.-]。
        let name_start = pos;
        let mut name_end = pos;
        while name_end < bytes.len()
            && (bytes[name_end].is_ascii_alphanumeric() || matches!(bytes[name_end], b'_' | b':' | b'.' | b'-'))
        {
            name_end += 1;
        }
        // name [ws] '=' [ws] quote value quote ?
        let mut after_name = name_end;
        while after_name < bytes.len() && matches!(bytes[after_name], b' ' | b'\t' | b'\r' | b'\n') {
            after_name += 1;
        }
        let mut handled = false;
        if after_name < bytes.len() && bytes[after_name] == b'=' {
            let mut quote_at = after_name + 1;
            while quote_at < bytes.len() && matches!(bytes[quote_at], b' ' | b'\t' | b'\r' | b'\n') {
                quote_at += 1;
            }
            if quote_at < bytes.len() && (bytes[quote_at] == b'"' || bytes[quote_at] == b'\'') {
                let quote = bytes[quote_at];
                let val_start = quote_at + 1;
                let mut val_end = val_start;
                while val_end < bytes.len() && bytes[val_end] != quote {
                    val_end += 1;
                }
                if val_end < bytes.len() {
                    // name..=..开引号 原样; 敏感属性值换 ***; 闭引号原样。
                    let name: Vec<u8> = bytes[name_start..name_end].iter().map(u8::to_ascii_lowercase).collect();
                    out.extend_from_slice(&bytes[name_start..val_start]);
                    if is_secret_attr(&name) {
                        out.extend_from_slice(b"***");
                        changed = true;
                    } else {
                        out.extend_from_slice(&bytes[val_start..val_end]);
                    }
                    out.push(quote);
                    pos = val_end + 1;
                    handled = true;
                }
            }
        }
        if !handled {
            // 非属性形态 (无 `=`/无引号/引号未闭合): 标识符原样拷回, 后续字节下一轮再处理。
            out.extend_from_slice(&bytes[name_start..name_end]);
            pos = name_end;
        }
    }
    changed.then(|| String::from_utf8(out).unwrap_or_else(|_| s.to_string()))
}

/// 折叠一行 (json 对象): 删折叠列 + **值级脱敏** (媒体 XML 内嵌密钥) + 长文本截到 `text_limit` 字留摘要。
/// 非对象原样。`text_limit=usize::MAX` → 不截长文 ([`detail`] 逃生口用), 但脱敏/删列仍生效。
fn fold_row(mut row: Value, text_limit: usize) -> Value {
    let Some(obj) = row.as_object_mut() else { return row };
    obj.retain(|k, _| !is_dropped_key(k));
    scrub_and_truncate(obj, text_limit, "；用 wx_inspect 取全文");
    row
}

/// exec 输出**仍须删的密钥列** (审查 R7-P2): 裸 crypto 密钥列 (媒体解密用) 对 (可能被 prompt-injection 操纵的)
/// LLM 是**纯泄漏、无分析价值** —— 即便 exec "保列" 也删这几个。区别 [`is_dropped_key`] (fixed 工具删一大批含
/// `_sha`): 这里**只**删 crypto 密钥子集, 保 `_sha` 摘要/结构列 (分组键/分析价值, 非密钥)。判据对齐 is_dropped_key
/// 的 crypto 子集。为何必须按**列名**删: `redact_xml_secrets` 只抹 XML 属性值 (`aeskey="X"`), 拦不住**裸密钥列**
/// (值不是 XML、无 `=` → redact 直接 None 放行)。
fn is_exec_secret_key(k: &str) -> bool {
    k.contains("aeskey") || k.contains("aes_key") || k == "file_key" || k == "cdn_key"
}

/// [`exec_envelope`] 专用行折叠 (R7): **保留列** (不施 fixed 工具的 [`is_dropped_key`] 大删) —— exec 的列由 LLM
/// 自己的 SELECT 决定, 删 `_sha` 会把 `GROUP BY conv_id_sha` 分组键误删致分析失真。**但**裸 crypto 密钥列仍删
/// ([`is_exec_secret_key`], 审查 R7-P2) + 值级 XML 密钥脱敏 + 长文截断。
fn fold_row_keep_cols(mut row: Value, text_limit: usize) -> Value {
    let Some(obj) = row.as_object_mut() else { return row };
    obj.retain(|k, _| !is_exec_secret_key(k)); // R7-P2: 裸 crypto 密钥列必删 (保 _sha/结构列)。
    scrub_and_truncate(obj, text_limit, "；缩小查询或用 substr() 取摘要");
    row
}

/// 对一行各字符串值施加**值级 XML 密钥脱敏 + 长文截断** (不改列集合)。脱敏在截断**前** —— 头部 aeskey 也不会
/// 被"留头"漏出。`trunc_hint` = 截断提示尾缀 (fixed 工具指 wx_inspect; exec 指 substr, 因 exec 行无 inspect id)。
fn scrub_and_truncate(obj: &mut serde_json::Map<String, Value>, text_limit: usize, trunc_hint: &str) {
    for v in obj.values_mut() {
        let Some(s) = v.as_str() else { continue };
        let scrubbed = redact_xml_secrets(s);
        let base: &str = scrubbed.as_deref().unwrap_or(s);
        let nchars = base.chars().count();
        let new_val: Option<String> = if nchars > text_limit {
            let head: String = base.chars().take(text_limit).collect();
            Some(format!("{head}…（正文共 {nchars} 字，已截断{trunc_hint}）"))
        } else if scrubbed.is_some() {
            Some(base.to_string()) // 未超长但脱敏了 → 用脱敏值替换。
        } else {
            None
        };
        if let Some(nv) = new_val {
            *v = json!(nv);
        }
    }
}

/// 折叠一批行 (删敏感列 + 截长文, 默认字数上限); 组合工具 (pack) 各子段各自折叠用。
#[must_use]
pub fn rows(data: &[Value]) -> Vec<Value> {
    data.iter().map(|r| fold_row(r.clone(), TEXT_TRUNC_CHARS)).collect()
}

/// wx_inspect **普通模式** (不指定 field): 逃生口取整条记录全字段 —— 删敏感列 + 值级脱敏, 默认**不截长文**
/// (inspect 本职=返完整字段)。**但受字节预算** (本次修: 原不封顶 = 一条无界返回路径): 超预算则保留小字段、把
/// 超长字符串字段逐次减半截到 fit, 标 `meta.truncated_fields=[{field,total_chars}]` + `meta.note` 提示用
/// `field`+`offset` 分段读全 (见 [`inspect_field`])。`truncated=true` 由 `_budget` 统一盖。绝不无上限。
#[must_use]
pub fn inspect_capped(r: &native_query::QueryResult, budget: usize) -> Value {
    let meta = serde_json::to_value(&r.meta).unwrap_or_else(|_| json!({}));
    // **复审 codex/Claude P1**: fit 到 `budget - SEAL_RESERVE`, 给 tool_ok 事后盖 `meta._budget` 预留位。
    let fit = budget.saturating_sub(SEAL_RESERVE);
    // 步骤 0: 全脱敏 + 删敏感列, 不截 (usize::MAX)。绝大多数记录在预算内 → 原样返 (行为同旧 detail)。
    let full: Vec<Value> = r.data.iter().map(|row| fold_row(row.clone(), usize::MAX)).collect();
    if json!({ "data": &full, "meta": &meta }).to_string().len() <= fit {
        return json!({ "data": full, "meta": meta });
    }
    // 超预算: 逐次减半 per-字段字符预算到 fit 或 100 字底 —— 小字段(短于预算)不动、长字段截断 (同 budget_fold 步骤1)。
    let mut text_limit = TEXT_TRUNC_CHARS;
    let (data, used_limit) = loop {
        let data: Vec<Value> = r.data.iter().map(|row| fold_row(row.clone(), text_limit)).collect();
        if text_limit <= 100 || json!({ "data": &data, "meta": &meta }).to_string().len() <= fit {
            break (data, text_limit);
        }
        text_limit /= 2;
    };
    let truncated_fields = collect_truncated_fields(&r.data, used_limit);
    let mut m = meta.as_object().cloned().unwrap_or_default();
    if !truncated_fields.is_empty() {
        m.insert("truncated_fields".into(), json!(truncated_fields));
        m.insert(
            "note".into(),
            json!("部分长字段已按预算截断; 调大 max_bytes, 或用 wx_inspect 带 field+offset 分段读全某字段。"),
        );
    }
    json!({ "data": data, "meta": Value::Object(m) })
}

/// 列出 inspect 行里**会被 `used_limit` 截断**的字符串字段 (脱敏后字符数 > used_limit)。给 AI 指明"哪些字段
/// 没读全 + 原始多长", 让它用 `field`+`offset` 分段取。敏感列 (已被 [`is_dropped_key`] 删) 不列。
fn collect_truncated_fields(rows: &[Value], used_limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else { continue };
        for (k, v) in obj {
            if is_dropped_key(k) {
                continue;
            }
            let Some(s) = v.as_str() else { continue };
            let scrubbed = redact_xml_secrets(s);
            let base: &str = scrubbed.as_deref().unwrap_or(s);
            let nchars = base.chars().count();
            if nchars > used_limit {
                out.push(json!({ "field": k, "total_chars": nchars }));
            }
        }
    }
    out
}

/// wx_inspect **单字段分段模式** (`field=X, offset=N`): 分段返回该字段**脱敏后**内容 —— 从字符偏移 `offset` 起、
/// 按字节预算取整数个字符 (不切 UTF-8 码点), 返 `{field, content, offset, next_offset, has_more, total_chars}`。
/// **脱敏在切段之前** (`redact_xml_secrets` 先抹 aeskey/cdn*url/md5) → 跨段拼接也拼不出敏感值。多次 offset 递进
/// 读 (下次 offset ← 本次 next_offset) 直到 has_more=false → 拼回完整**脱敏后**内容。敏感列 (aeskey 等裸列) 拒读。
#[must_use]
pub fn inspect_field(r: &native_query::QueryResult, field: &str, offset: usize, budget: usize) -> Value {
    let meta = serde_json::to_value(&r.meta).unwrap_or_else(|_| json!({}));
    let note = |msg: &str| json!({ "field": field, "content": Value::Null, "meta": &meta, "note": msg });
    let Some(row) = r.data.first().and_then(Value::as_object) else {
        return note("无此记录 (inspect 未命中)");
    };
    if is_dropped_key(field) {
        return note("该字段是敏感列 (密钥/CDN/原始 payload), 不提供读取");
    }
    let Some(v) = row.get(field) else {
        return note("记录无此字段; 先用普通 wx_inspect (不带 field) 看有哪些字段");
    };
    let Some(raw) = v.as_str() else {
        // 非字符串 (数值/bool/null) — 天然小, 整值返回, 无需分段。
        return json!({ "field": field, "content": v.clone(), "offset": 0, "next_offset": 0, "has_more": false, "meta": meta });
    };
    // 脱敏在切段前 (跨段拼不出密钥)。按**字符**偏移分段 (spec: 字符偏移), 每段取字节预算内最多字符、不切码点。
    let redacted = redact_xml_secrets(raw);
    let content: &str = redacted.as_deref().unwrap_or(raw);
    let chars: Vec<char> = content.chars().collect();
    let total_chars = chars.len();
    let start = offset.min(total_chars);
    // 先量骨架(含 meta, 不含 tool_ok 后加的 _budget)开销 + 预留 _budget/数字增长 → 剩下给 content bytes,
    // 保证 tool_ok 盖 _budget 后整体仍 ≤ budget (不触发兜底闸截 content 破坏 next_offset 对齐)。
    let skeleton = json!({
        "field": field, "content": "", "offset": start, "next_offset": total_chars,
        "has_more": true, "total_chars": total_chars, "meta": &meta,
    });
    let overhead = skeleton.to_string().len() + SEAL_RESERVE;
    let chunk_budget = budget.saturating_sub(overhead);
    let mut end = start;
    let mut bytes = 0usize;
    while end < total_chars {
        // **复审 codex/Claude P1**: 按**序列化后**字节数 (转义膨胀), 非 len_utf8 —— content 是 JSON 字符串,
        // 引号/反斜杠/控制符会膨胀, 只按原字节切会让最终序列化破 budget。
        let cb = json_str_byte_len(chars[end]);
        if bytes + cb > chunk_budget {
            break;
        }
        bytes += cb;
        end += 1;
    }
    // 进度保证: 一个字符都放不下 (实际不可达: min 预算 16KB ≫ overhead+单字符最坏 6B) → 至少 1 字符, 防 offset 卡死。
    // (此时该段可能略超 budget, 但 enforce_budget 兜底闸对 content 形态也封顶 —— P1 修后 shape-agnostic。)
    if end == start && start < total_chars {
        end = start + 1;
    }
    let chunk: String = chars[start..end].iter().collect();
    json!({
        "field": field,
        "content": chunk,
        "offset": start,
        "next_offset": end,
        "has_more": end < total_chars,
        "total_chars": total_chars,
        "meta": meta,
    })
}

/// **复审(第5轮)#3**: 给 **pack 类** 组合响应 (`contact_pack`/`session_pack` 的 `{…, recent_messages:[…]}`) 套
/// 字节封顶 —— 它们不走 [`envelope`] 的 `budget_fold`, `recent_messages` 太长 (长聊天内容) 会破 `MAX_BYTES`。
/// 超则从**尾部**砍 `recent_messages` 到 fit (二分; 输出随保留条数单调增) + 标 `recent_truncated=true` + `note`。
/// 非 pack 形态 (无 `recent_messages` 数组) 或本就不超 → 原样返回。(`wx_inspect` 的 [`detail`] 是**有意**的
/// 不封顶逃生口 —— 单条记录、巨 blob 列已被 [`is_dropped_key`] 删, 实践上有界; 不在此列。)
#[must_use]
pub fn cap_pack(pack: Value, budget: usize) -> Value {
    // **复审 codex/Claude P1**: fit 到 `budget - SEAL_RESERVE`, 给 tool_ok 事后盖的 `meta._budget` 预留位 (pack
    // 无 meta 键, enforce_budget 会新建 → 更需预留), 否则封口后破 budget、兜底闸又管不了 recent_messages 形态。
    let fit = budget.saturating_sub(SEAL_RESERVE);
    if pack.to_string().len() <= fit {
        return pack;
    }
    // 到这 pack 已 > budget。**第5轮复审 P3-1(Claude)**: 非对象 / 无 recent_messages 数组 (非预期 pack 形态)
    // 也别原样返超限值 —— 返最小对象, 令"≤ budget"**真无条件** (现有两调用方必带 recent_messages 数组, 此护栏)。
    let minimal = || {
        json!({
            "oversized": true,
            "recent_truncated": true,
            "note": format!("响应超 {}KB 预算; 调大 max_bytes、或换 wx_inspect / wx_messages 分开取。", budget / 1024),
        })
    };
    let Some(obj) = pack.as_object() else { return minimal() };
    let Some(recent) = obj.get("recent_messages").and_then(Value::as_array) else {
        return minimal();
    };
    let recent = recent.clone();
    let build = |kept: usize| -> Value {
        let mut m = obj.clone();
        m.insert("recent_messages".into(), json!(recent[..kept].to_vec()));
        if kept < recent.len() {
            m.insert("recent_truncated".into(), json!(true));
            m.insert(
                "note".into(),
                json!(format!(
                    "近期消息超 {}KB 预算, {} 条仅返回前 {} 条; 调大 max_bytes 或用 wx_messages 按会话取全。",
                    budget / 1024,
                    recent.len(),
                    kept
                )),
            );
        }
        Value::Object(m)
    };
    // 二分找最大保留条数 (骨架 + kept 条单调增)。fit(0) = 骨架 + 空数组, 骨架小故恒真 → 下界稳; 循环不变式
    // `fit(lo)=true` → 返回值 ≤ budget (骨架本身即便超也只能尽力返 kept=0, 但 pack 骨架远小于预算)。
    let mut lo = 0usize;
    let mut hi = recent.len();
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if build(mid).to_string().len() <= fit {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let out = build(lo);
    // 第5轮复审#3(P2, codex): 连 kept=0 (空 recent) 都超 = **骨架自己**超 (如 session_pack 未校验的超长 conv) →
    // build(0) 仍破 fit。兜底最小对象 (骨架也丢), 令**无条件** ≤ fit (盖 _budget 后 ≤ budget)。
    if out.to_string().len() > fit {
        return minimal();
    }
    out
}

/// 内核 [`QueryResult`](native_query::QueryResult) → 折叠后的 `{data, meta}` json。
/// `meta` 小 (has_more/total_count/source/account/next_cursor…) 原样保留 —— LLM 靠 has_more/source 判断
/// 是否还有 + 数据冷热鲜旧 (别把近似当精确、别把冷查陈旧当最新)。
///
/// **字节封顶 = 适应性收窄文本, 绝不丢行** (H1 修): 超 [`MAX_BYTES`] 就把每字段文本预算减半重折, 直到 fit
/// 或收到 100 字底 (行数已被各工具 limit 顶住, 边界有界)。**丢行会让 `meta.next_cursor`/`has_more` 撒谎**
/// (游标指向被丢的末行 → 下页永久跳过), 故此处只缩文本不动行数。
///
/// **按 compact 量测 == 按实发形态量测** (审查 P2-8): [`crate::error::tool_ok`] 用 compact `to_string` 交付
/// (非 pretty), 故这里 `to_string()` 的字节量就是客户端实收量, 封顶不会被缩进/换行撑破。
#[must_use]
pub fn envelope(r: &native_query::QueryResult, budget: usize) -> Value {
    let meta = serde_json::to_value(&r.meta).unwrap_or_else(|_| json!({}));
    budget_fold(&meta, &r.data, fold_row, budget)
}

/// 自适应字节封顶的共享收窄逻辑 (`envelope`/`exec_envelope` 复用):
/// 1. **先缩文本**: 每字段文本预算逐次减半 (至 100 字底) 尽量 fit `MAX_BYTES` —— 不动行数, `has_more`/`next_cursor`
///    保持诚实 (H1: 丢行会让游标撒谎)。绝大多数结果在这步就 fit。
/// 2. **仍超则真截行** (复审#5: 48KB 是**硬**闸不是软提示): 压到 100 字底还超 = 行数×最小行体积撑破, 从尾部
///    砍行到 fit。截行会让"前翻游标"跳过被砍行 → 故**抹掉 `next_cursor` + 置 `has_more=true` + 挂 `oversized`
///    提示**, 逼 LLM 用**更小 limit 重查**而非前翻 (前翻会静默跳过未返回的行)。宁可少返 + 显式告知, 也不超发撑爆
///    上下文、更不假装"就这些"。单行即超 (理论不至于, 文本已压到 100 字) → 回空 + 指 `wx_inspect` 取该行。
fn budget_fold(meta: &Value, data_src: &[Value], fold_one: impl Fn(Value, usize) -> Value, budget: usize) -> Value {
    // **复审 codex/Claude P1**: 所有 fit 判定按 `fit = budget - SEAL_RESERVE`, 给 tool_ok 事后盖的 `meta._budget`
    // (~140B) + 下方 content_truncated notice (~80B) 预留位。否则 fit 到 budget 后盖 _budget 就破 budget, 兜底闸把
    // 整页数据清空 (P1: 本能返的结果被清成空)。SEAL_RESERVE=512 ≫ 220B 事后增量。
    let fit = budget.saturating_sub(SEAL_RESERVE);
    // 步骤 1: 缩文本到 fit 或到 100 字底。
    let mut text_limit = TEXT_TRUNC_CHARS;
    let folded: Vec<Value> = loop {
        let data: Vec<Value> = data_src.iter().map(|row| fold_one(row.clone(), text_limit)).collect();
        if text_limit <= 100 || json!({ "data": &data, "meta": meta }).to_string().len() <= fit {
            break data;
        }
        text_limit /= 2;
    };
    // 步骤 1 常态出口: 已 fit。若 budget 逼得 text_limit 降到默认 (TEXT_TRUNC_CHARS) 以下 = 正文被预算压缩 (行全
    // 在但每行正文比默认更短) → 标 `content_truncated`, 皮层据此 truncated=true + 给 suggested, 别让 AI 以为拿到
    // 全文。真库跑逮出: 100 行在 128KB 预算下正文被压 ~13KB 却曾报 truncated=false。text_limit==默认 = 没压, 原样回。
    if json!({ "data": &folded, "meta": meta }).to_string().len() <= fit {
        if text_limit < TEXT_TRUNC_CHARS {
            let mut m = meta.as_object().cloned().unwrap_or_default();
            m.insert("content_truncated".into(), json!(true));
            m.insert(
                "notice".into(),
                json!(format!(
                    "正文按 {}KB 预算压缩 (行全在, 每行正文比默认更短); 调大 max_bytes 取更全正文。",
                    budget / 1024
                )),
            );
            return json!({ "data": folded, "meta": Value::Object(m) });
        }
        return json!({ "data": folded, "meta": meta });
    }
    // 步骤 2: 压到底仍超 → 从尾砍行到 fit。**复审#3**: fit 判定必须按**最终形态**量 (含 oversized/notice/has_more
    // 开销) —— 之前只按原 meta 判、加完 notice 又撑破, 硬闸漏气。**第4轮 P3**: 二分找最大 fit 的 kept (输出字节随
    // kept 单调不减 —— 行字节远压过 notice 位数波动, 且 build_oversized(0) 因丢 summary 恒最小), 免线性逐行重
    // 序列化 (大 exec 结果 CPU 尖峰)。`fit(0)` 恒真 (build_oversized 在 0 仍超时连 summary 也丢) → 二分下界稳,
    // 循环不变式 `fit(lo)=true` → 返回值必 ≤ MAX_BYTES。
    let mut lo = 0usize;
    let mut hi = folded.len();
    while lo < hi {
        let mid = (lo + hi).div_ceil(2); // 偏上取整 → 收敛到"最大 fit"
        if build_oversized(meta, &folded, mid, fit, budget).to_string().len() <= fit {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    build_oversized(meta, &folded, lo, fit, budget)
}

/// 构造"超限"输出 (复审第4轮修): `data`=前 `kept` 行;`meta`=原 meta 抹掉 `next_cursor`、置 `has_more`/`oversized`、
/// 挂 `notice`。notice 文案含 `kept`/总行数, 故大小随 kept 变 —— 调用方 (budget_fold 步骤2) 对每个候选 kept 量
/// **本函数返回值**的字节数, 保证最终输出 (含 notice) ≤ MAX_BYTES。
fn build_oversized(meta: &Value, folded: &[Value], kept: usize, fit: usize, budget: usize) -> Value {
    let mut m = meta.as_object().cloned().unwrap_or_default();
    m.remove("next_cursor"); // 截行后前翻游标会跳过被砍行 → 抹掉, 强制重查。
    m.insert("has_more".into(), json!(true)); // 确有更多 (被砍的行) → 诚实置 true。
    m.insert("oversized".into(), json!(true));
    let notice = if kept == 0 {
        format!(
            "结果超 {}KB 预算, 限内无法返回整行; 缩小查询范围、或调大 max_bytes、或用 wx_inspect 逐条取。",
            budget / 1024
        )
    } else {
        format!(
            "结果超 {}KB 预算, {} 行仅返回前 {} 行 (每行已压到摘要)。调大 max_bytes 或用更小 limit 重查取全 —— 勿用 next_cursor 前翻 (会跳过未返回的行)。",
            budget / 1024,
            folded.len(),
            kept
        )
    };
    m.insert("notice".into(), json!(notice));
    let out = json!({ "data": folded[..kept].to_vec(), "meta": Value::Object(m.clone()) });
    // **第4轮复审 P3**: kept==0 (空行) 仍超 budget = 撑破的不是行、是 meta 里唯一**无界**字段 `summary`
    // (超大命令汇总)。末路连 `summary` 也丢 → 令"输出 ≤ budget"**无条件**成立 (今各调用方 summary 都是小整数
    // 聚合, 不可达; 纯护栏 + 让契约声明不打折)。summary 未超时保留。
    if kept == 0 && out.to_string().len() > fit {
        m.remove("summary");
        return json!({ "data": Vec::<Value>::new(), "meta": Value::Object(m) });
    }
    out
}

/// `wx_exec` 专用折叠 (R7/⑪) —— exec = **裸 SQL 逃生口**, 列由 LLM 自己的 SELECT 决定。区别 [`envelope`]:
/// **不删列** (envelope 的 [`is_dropped_key`] 会把 `GROUP BY conv_id_sha` 的分组键 / `SELECT *` 的 payload 列
/// 删掉 → 分析查询结果失真/错), 只施 (1) 值级 XML 密钥脱敏 (媒体消息内嵌 aeskey/cdn*url → ***, 廉价保险, 不碰
/// 数值/摘要) + (2) 自适应 48KB 字节封顶 (超则减半文本预算重折, **绝不丢行** —— 丢行会让 meta.has_more 撒谎)。
///
/// **裸 crypto 密钥列** (aeskey/aes_key/file_key/cdn_key) 即便"保列"也**删** (审查 R7-P2: 对可能被 prompt-injection
/// 操纵的 LLM 是纯泄漏、无分析价值; 见 [`is_exec_secret_key`])。其余列 (含 `_sha` 摘要 / CDN URL / payload) 保真透出
/// —— 与消息正文同, LLM 本就该看 (折叠版); XML 内嵌密钥另由 `redact_xml_secrets` 值级抹。比 HTTP `/exec` (啥都不
/// 折叠、密钥列直出) **更严**; 非 scoped 跨账号仍操作者自负 (见 ADR-507)。
#[must_use]
pub fn exec_envelope(r: &native_query::QueryResult, budget: usize) -> Value {
    let meta = serde_json::to_value(&r.meta).unwrap_or_else(|_| json!({}));
    budget_fold(&meta, &r.data, fold_row_keep_cols, budget)
}

/// **统一预算盖章 + 无条件兜底闸** (方式一): 给最终 `structured` 的 `meta._budget` 盖上传输层预算信息 (不污染
/// 三皮共享 Meta 顶层字段集), 并保证最终紧凑 JSON **≤ budget**。[`crate::error::tool_ok`] 每条成功响应都过此。
///
/// - `_budget`: `{budget_bytes, hard_max_bytes, truncated, response_bytes, suggested_max_bytes?}`。`truncated` =
///   折叠层是否已截 (envelope 的 oversized / cap_pack 的 recent_truncated / inspect 的 truncated_fields); 截了才给
///   `suggested_max_bytes` (下一档)。`response_bytes` = 最终真实紧凑字节 (回填, 见下)。
/// - **兜底闸**: 折叠层 (envelope/cap_pack/inspect_*) 已把数据路径控在 ≤ budget; 万一某路径绕过折叠直返超限,
///   这里丢 `data` (无界部分) + 标 oversized, 令"≤ budget"**无条件**成立 (最后一道闸, 实践极少触发)。
/// - **response_bytes 回填不破闸**: 先占位 = budget (数字最宽), 量最终字节 `actual` (≤ budget), 再回填
///   `response_bytes = actual` (≤ budget → 位数 ≤ 占位 → 回填只令输出变窄或不变, 绝不撑破)。
#[must_use]
pub fn enforce_budget(structured: Value, budget: usize) -> Value {
    let truncated_fold = detect_truncated(&structured);
    let mut root = match structured {
        Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("data".into(), other);
            m
        }
    };
    let mut meta = root.get("meta").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut bm = serde_json::Map::new();
    bm.insert("budget_bytes".into(), json!(budget));
    bm.insert("hard_max_bytes".into(), json!(HARD_MAX_BYTES));
    bm.insert("truncated".into(), json!(truncated_fold));
    bm.insert("response_bytes".into(), json!(budget)); // 占位 (数字最宽); 量完回填真实值。
    if truncated_fold {
        if let Some(s) = suggest_next_budget(budget) {
            bm.insert("suggested_max_bytes".into(), json!(s));
        }
    }
    meta.insert("_budget".into(), Value::Object(bm));
    root.insert("meta".into(), Value::Object(meta.clone()));
    let mut out = Value::Object(root);
    // 兜底闸 (**复审 codex/Claude P1: shape-agnostic**): 含占位 _budget 的最终形态若仍超 budget = 折叠被绕过/漏预留
    // → **丢所有顶层载荷** (data / content / recent_messages / accounts / field… 任意形态) + 丢 meta 里仅有的两个
    // 无界字段 summary / truncated_fields (后者项数随字段数增、受 schema 约束但非构造性有界), 只留 meta 小字段,
    // 令"≤ budget"对**任意响应形态、任意字段数**无条件成立。原版只丢 `data`, 管不了
    // inspect_field 的 content / pack 的 recent_messages / list_accounts 的 accounts (那些形态仍超发)。折叠层现已
    // 预留 SEAL_RESERVE, 此闸实践几乎不触发; 但它才是"硬上限"的构造性保证, 必须对所有形态成立。
    if out.to_string().len() > budget {
        meta.remove("summary");
        meta.remove("truncated_fields"); // 复审 R1(codex/Claude): tf 项数随字段数无界(受 schema 约束) → 兜底也丢, 令硬上限真无条件
        meta.insert("oversized".into(), json!(true));
        meta.insert(
            "note".into(),
            json!("响应超预算且未经折叠, 已丢弃载荷; 缩小查询或调大 max_bytes。"),
        );
        if let Some(b) = meta.get_mut("_budget").and_then(Value::as_object_mut) {
            b.insert("truncated".into(), json!(true));
            if let Some(s) = suggest_next_budget(budget) {
                b.insert("suggested_max_bytes".into(), json!(s)); // 兜底截也是预算截断 → 补 suggested (Claude nit)
            }
        }
        out = json!({ "data": [], "meta": Value::Object(meta) }); // 只留 meta, 丢一切顶层载荷
    }
    // 回填 response_bytes 到**不动点** (**复审 codex P3**): 占位=budget (数字最宽), 量 actual 回填后位数可能变窄使
    // 体积再缩 → 迭代到稳定 (≤4 次收敛)。全程只变窄 (≤ 之前) → 绝不破闸; 令 response_bytes 报最终真实字节。
    for _ in 0..4 {
        let actual = out.to_string().len();
        if out.pointer("/meta/_budget/response_bytes").and_then(Value::as_u64) == Some(actual as u64) {
            break;
        }
        if let Some(b) = out.pointer_mut("/meta/_budget").and_then(Value::as_object_mut) {
            b.insert("response_bytes".into(), json!(actual));
        }
    }
    out
}

/// 折叠层是否已因预算**截断**了内容 (决定 `_budget.truncated` + 要不要给 `suggested_max_bytes`)。`inspect_field`
/// 的 `has_more` 是**正常分段翻页** (自带 `next_offset`, 非预算硬截), 不算 truncated。
fn detect_truncated(v: &Value) -> bool {
    v.pointer("/meta/oversized").and_then(Value::as_bool).unwrap_or(false)
        || v.pointer("/meta/content_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || v.pointer("/meta/truncated_fields").is_some()
        || v.get("recent_truncated").and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{envelope, exec_envelope, fold_row, inspect_capped, redact_xml_secrets};

    /// 复审#5: 48KB 是**硬**闸 —— 行数×大字段撑破 100 字底时, 真截行到 fit + 挂 oversized/notice + 抹
    /// next_cursor (逼用更小 limit 重查、不前翻跳行), 绝不静默超发撑爆上下文。
    #[test]
    fn envelope_hard_caps_bytes_when_flooring_insufficient() {
        use native_query::{Meta, QueryResult, Source};
        // 200 行, 每行 2000 字长文 —— 即便压到 100 字底, 200×(~100字+字段名+结构) 也远超 48KB。
        let rows: Vec<serde_json::Value> = (0..200)
            .map(|i| json!({ "id": i, "text": "内".repeat(2000), "nick_name": "张三丰同学甲乙丙" }))
            .collect();
        let r = QueryResult {
            data: rows,
            meta: Meta::cursor_page(true, Some("OPAQUE_CURSOR".into()), 100).with_source(Source::Cold),
        };
        let out = envelope(&r, super::DEFAULT_MAX_BYTES);
        let bytes = out.to_string().len();
        assert!(
            bytes <= super::DEFAULT_MAX_BYTES,
            "硬闸: 输出 {bytes} 字节须 ≤ {}",
            super::DEFAULT_MAX_BYTES
        );
        assert_eq!(out["meta"]["oversized"], json!(true), "超限须挂 oversized 标记");
        assert_eq!(out["meta"]["has_more"], json!(true), "截行后确有更多 → has_more=true");
        assert!(
            out["meta"].get("next_cursor").is_none(),
            "截行后须抹 next_cursor (防前翻静默跳行)"
        );
        assert!(
            out["meta"]["notice"].as_str().unwrap().contains("重查"),
            "notice 须提示用更小 limit 重查"
        );
        let n = out["data"].as_array().unwrap().len();
        assert!(n > 0 && n < 200, "截行后返部分行 (0<{n}<200)");
    }

    /// 复审(第4轮)#3: **临界字节** —— 大量小行, 截行落点离 48KB 只差几十字节, 加 notice 会把最终撑破
    /// (前一版就漏了 142 字节)。用许多小行 (截行粒度细 → 落点贴近上限) 逼出这个临界, 断言**最终输出 (含 notice)
    /// ≤ MAX_BYTES**。修前此测必挂, 修后 (build_oversized 按最终形态量) 必过。
    #[test]
    fn envelope_hard_cap_holds_including_notice_at_boundary() {
        use native_query::{Meta, QueryResult, Source};
        // 4000 小行 (~每行 20-30 字节 folded) → 远超 48KB, 截行粒度细 → 最大 fit 前缀贴着上限, notice(~150B)
        // 若不计入必超。行内无长文 (不触发文本收窄), 直接进步骤2 截行。
        let rows: Vec<serde_json::Value> = (0..4000).map(|i| json!({ "id": i, "t": "hi" })).collect();
        let r = QueryResult {
            data: rows,
            meta: Meta::cursor_page(true, Some("BOUNDARY_CURSOR".into()), 500).with_source(Source::Cold),
        };
        let out = envelope(&r, super::DEFAULT_MAX_BYTES);
        let bytes = out.to_string().len();
        assert!(
            bytes <= super::DEFAULT_MAX_BYTES,
            "临界: 含 notice 的最终输出 {bytes} 字节须 ≤ {}",
            super::DEFAULT_MAX_BYTES
        );
        assert_eq!(out["meta"]["oversized"], json!(true), "超限须挂 oversized");
        assert!(out["meta"]["notice"].as_str().is_some(), "须挂 notice");
        assert!(out["meta"].get("next_cursor").is_none(), "截行后须抹 next_cursor");
        let n = out["data"].as_array().unwrap().len();
        assert!(n > 0 && n < 4000, "截行后返部分行 (0<{n}<4000)");
    }

    /// 复审(第4轮)P3: `meta.summary` 超大 (meta 里唯一**无界**字段) 时, 连空行都超 → `build_oversized` 末路
    /// 连 summary 也丢, 令"≤ MAX_BYTES"**无条件**成立 (今各调用方 summary 都是小整数聚合, 不可达; 纯护栏)。
    #[test]
    fn envelope_hard_cap_holds_with_huge_summary() {
        use native_query::{Meta, QueryResult, Source};
        let r = QueryResult {
            data: (0..100).map(|i| json!({ "id": i, "t": "x" })).collect(),
            meta: Meta::hot(true)
                .with_source(Source::Hot)
                .with_summary(json!({ "blob": "z".repeat(60_000) })),
        };
        let out = envelope(&r, super::DEFAULT_MAX_BYTES);
        let bytes = out.to_string().len();
        assert!(
            bytes <= super::DEFAULT_MAX_BYTES,
            "超大 summary 也须封顶: {bytes} ≤ {}",
            super::DEFAULT_MAX_BYTES
        );
        assert_eq!(out["meta"]["oversized"], json!(true), "超限挂 oversized");
        assert!(out["meta"].get("summary").is_none(), "末路连无界 summary 也丢");
        assert_eq!(out["data"].as_array().unwrap().len(), 0, "summary 撑破 → 空行");
    }

    /// 复审(第5轮)#3: pack 类响应 (recent_messages 太长) 也字节封顶 —— cap_pack 砍 recent_messages 尾部到 fit
    /// + 标 recent_truncated/note; 骨架字段 (conv) 保留。
    #[test]
    fn cap_pack_truncates_long_recent_messages() {
        use super::cap_pack;
        let recent: Vec<serde_json::Value> = (0..300).map(|i| json!({ "id": i, "text": "聊".repeat(400) })).collect();
        let pack = json!({ "conv": "x@chatroom", "is_group": true, "recent_messages": recent });
        let out = cap_pack(pack, super::DEFAULT_MAX_BYTES);
        let bytes = out.to_string().len();
        assert!(
            bytes <= super::DEFAULT_MAX_BYTES,
            "pack 须封顶: {bytes} ≤ {}",
            super::DEFAULT_MAX_BYTES
        );
        assert_eq!(out["recent_truncated"], json!(true), "截断须标记");
        assert!(out["note"].as_str().is_some(), "须挂 note");
        assert_eq!(out["conv"], "x@chatroom", "骨架字段保留");
        let n = out["recent_messages"].as_array().unwrap().len();
        assert!(n > 0 && n < 300, "截尾后返部分 (0<{n}<300)");
    }

    /// cap_pack 对照: 不超时原样返回 (不加 recent_truncated)。
    #[test]
    fn cap_pack_small_untouched() {
        use super::cap_pack;
        let pack = json!({ "conv": "y", "recent_messages": [json!({ "text": "hi" })] });
        let out = cap_pack(pack.clone(), super::DEFAULT_MAX_BYTES);
        assert_eq!(out, pack, "小 pack 原样");
        assert!(out.get("recent_truncated").is_none());
    }

    /// 复审(第5轮)#3(P2, codex): pack **骨架自己**超 48KB (超长 conv + 空 recent) → cap_pack 兜底返最小对象,
    /// 仍**无条件** ≤ MAX_BYTES。
    #[test]
    fn cap_pack_skeleton_overflow_still_capped() {
        use super::cap_pack;
        let pack = json!({ "conv": "x".repeat(60_000), "is_group": false, "recent_messages": [] });
        let out = cap_pack(pack, super::DEFAULT_MAX_BYTES);
        assert!(
            out.to_string().len() <= super::DEFAULT_MAX_BYTES,
            "骨架超也须封顶 ≤ MAX_BYTES"
        );
        assert_eq!(out["oversized"], json!(true), "标 oversized");
    }

    /// 复审(第5轮)P3-1(Claude): cap_pack **无条件** ≤ MAX_BYTES —— 非 pack 形态 (非对象 / 无 recent_messages
    /// 数组 / recent 非数组) 的超限值也走最小兜底、不原样返超限。锁死"无条件封顶"契约。
    #[test]
    fn cap_pack_non_pack_shapes_still_capped() {
        use super::cap_pack;
        let a = cap_pack(json!("z".repeat(60_000)), super::DEFAULT_MAX_BYTES); // 非对象超限
        assert!(a.to_string().len() <= super::DEFAULT_MAX_BYTES, "非对象超限→兜底 ≤ MAX");
        assert_eq!(a["oversized"], json!(true));
        let b = cap_pack(
            json!({ "conv": "y", "blob": "z".repeat(60_000) }),
            super::DEFAULT_MAX_BYTES,
        ); // 对象超限但无 recent_messages
        assert!(
            b.to_string().len() <= super::DEFAULT_MAX_BYTES,
            "无 recent 数组→兜底 ≤ MAX"
        );
        assert_eq!(b["oversized"], json!(true));
        let c = cap_pack(
            json!({ "conv": "z".repeat(60_000), "recent_messages": "notarray" }),
            super::DEFAULT_MAX_BYTES,
        ); // recent 非数组
        assert!(
            c.to_string().len() <= super::DEFAULT_MAX_BYTES,
            "recent 非数组→兜底 ≤ MAX"
        );
        assert_eq!(c["oversized"], json!(true));
    }

    /// 复审#5 对照: 结果不超 48KB 时 **不截行、不挂 oversized** (常态路径不受硬闸影响, 行全在)。
    #[test]
    fn envelope_small_result_untouched() {
        use native_query::{Meta, QueryResult, Source};
        let rows: Vec<serde_json::Value> = (0..5).map(|i| json!({ "id": i, "text": "短消息" })).collect();
        let r = QueryResult {
            data: rows,
            meta: Meta::cursor_page(true, Some("C".into()), 100).with_source(Source::Cold),
        };
        let out = envelope(&r, super::DEFAULT_MAX_BYTES);
        assert!(out["meta"].get("oversized").is_none(), "小结果不该挂 oversized");
        assert_eq!(out["meta"]["next_cursor"], json!("C"), "小结果 next_cursor 原样保留");
        assert_eq!(out["data"].as_array().unwrap().len(), 5, "小结果行全在");
    }

    /// exec_envelope (R7): **保留 `_sha`/结构列** (区别 envelope 删列 —— 分析查询 `GROUP BY conv_id_sha` 不能
    /// 丢分组键), 但 (P2) **裸 crypto 密钥列必删** + 值级脱敏 XML 内嵌 aeskey (裸 SQL 也不漏媒体密钥)。
    #[test]
    fn exec_envelope_keeps_cols_drops_key_cols_redacts_xml() {
        use native_query::{Meta, QueryResult, Source};
        let r = QueryResult {
            data: vec![json!({
                "conv_id_sha": "abc123",
                "n": 42,
                "aeskey": "RAWKEY0123456789",
                "file_key": "RAWFILEKEY",
                "text_content": r#"<img aeskey="LEAKME" cdnthumburl="http://x/y" md5="M"/>"#,
            })],
            meta: Meta::cold_page(false).with_source(Source::Cold),
        };
        let out = exec_envelope(&r, super::DEFAULT_MAX_BYTES);
        let row = &out["data"][0];
        assert_eq!(row["conv_id_sha"], "abc123", "exec 不删 _sha 列 (GROUP BY 分组键须留)");
        assert_eq!(row["n"], 42, "数值列原样");
        assert!(
            row.get("aeskey").is_none(),
            "R7-P2: 裸 aeskey 密钥列必删 (redact 拦不住裸列)"
        );
        assert!(row.get("file_key").is_none(), "R7-P2: 裸 file_key 密钥列必删");
        let t = row["text_content"].as_str().unwrap();
        // R16-1 决策⑥: XML 值级脱敏只抹密钥, URL 保留(同 fixed 工具)。exec 的**裸密钥列** aeskey/file_key
        // 仍删(上面已验) —— 那是"别让 LLM 通过 exec 拿密钥"的安全底线, 与 URL 保留正交。
        assert!(!t.contains("LEAKME"), "XML 内嵌 aeskey 值仍脱敏(密钥底线)");
        assert!(t.contains("x/y"), "XML 内嵌 CDN URL 保留(决策⑥, URL 非密钥)");
    }

    /// 媒体消息 XML: **aeskey 值抹 ***; URL/md5 值保留**(R16-1 决策⑥); 结构 + 非敏感属性不动。
    ///
    /// 原先 cdn*url/md5 也抹 —— 但 CLI/HTTP 不抹(直接序列化原文), 带媒体 XML 的行 MCP 就跟另两皮不一致
    /// (codex 审 P1)。用户拍板 MCP 也出网址 → 只抹真密钥。**`cdnthumbaeskey` 名字带 cdn 但它是密钥,
    /// 仍抹**(密钥优先, `has(aeskey)` 命中)。
    #[test]
    fn media_xml_only_aeskey_redacted_urls_and_md5_kept() {
        let xml = r#"<msg><img aeskey="AESSECRET1234" cdnthumbaeskey="THUMBKEY" cdnthumburl="http://cdn.qq/abc" cdnbigimgurl="http://cdn.qq/big" encrypturl="http://cdn.qq/enc" md5="DEADBEEFMD5" length="2048"></img></msg>"#;
        let folded = fold_row(json!({ "text_content": xml, "nick_name": "张三" }), 8000);
        let t = folded["text_content"].as_str().unwrap();
        // 密钥必抹(含名字带 cdn 的 cdnthumbaeskey)。
        assert!(!t.contains("AESSECRET1234"), "aeskey 值必抹");
        assert!(!t.contains("THUMBKEY"), "cdnthumbaeskey 是密钥(名字带 cdn 也抹)");
        assert!(t.contains(r#"aeskey="***""#), "aeskey 结构保留值换 ***");
        // URL/md5 现在**保留**(三皮一致)。
        assert!(
            t.contains("cdn.qq/abc") && t.contains("cdn.qq/big"),
            "CDN URL 保留(决策⑥)"
        );
        assert!(t.contains("cdn.qq/enc"), "encrypturl 保留");
        assert!(t.contains("DEADBEEFMD5"), "md5 内容摘要保留");
        assert!(t.contains(r#"length="2048""#), "非敏感属性 length 原样");
        assert_eq!(folded["nick_name"], "张三", "普通字段不动");
    }

    /// 长媒体 XML: aeskey 在头部, 正文超 800 字截断留头 —— 脱敏在截断**前**, 头部 aeskey 也不漏 (审查 P1-1)。
    #[test]
    fn long_media_xml_no_key_leak_after_truncation() {
        let filler = "文".repeat(2000);
        let xml = format!(r#"<img aeskey="LEAKONE" cdnbigimgurl="http://x/big">{filler}</img>"#);
        let folded = fold_row(json!({ "text": xml }), 800);
        let t = folded["text"].as_str().unwrap();
        assert!(!t.contains("LEAKONE"), "截断后头部 aeskey 仍不漏");
        assert!(t.contains("已截断"), "长文仍截断留摘要");
    }

    /// 普通文本 (含 `=` 但无敏感属性) 不误伤。
    #[test]
    fn plain_text_not_touched() {
        assert!(redact_xml_secrets("1+1=2 很简单").is_none());
        assert!(redact_xml_secrets("没有等号的中文文本").is_none());
        assert!(
            redact_xml_secrets(r#"<a width="10" height="20"/>"#).is_none(),
            "非敏感属性不动"
        );
    }

    /// 折叠列 (影子 _sha / 原始 payload / 密钥列名) 按列名删除 (H4 既有能力回归)。
    #[test]
    fn dropped_columns_removed() {
        let folded = fold_row(
            json!({ "text": "hi", "conv_id_sha": "abc", "raw_xml": "<x/>", "aeskey": "k" }),
            800,
        );
        assert!(folded.get("conv_id_sha").is_none(), "_sha 影子列删");
        assert!(folded.get("raw_xml").is_none(), "raw_xml payload 删");
        assert!(folded.get("aeskey").is_none(), "aeskey 列名命中删");
        assert_eq!(folded["text"], "hi");
    }

    /// **R16-1 决策⑥(用户 2026-07-18, 办法二)**: URL 类**保留**(三皮一致), 密钥/二进制仍删。
    ///
    /// 原先 fold 删 cdn_url/thumb_url/head_url/cover_url → MCP 三皮少字段(emoticon 对拍 NO-GO)。
    /// 用户拍板 MCP 也出网址。此测试钉死: URL 保留 + 密钥/二进制仍删(别把两类搞混又倒回去)。
    #[test]
    fn urls_kept_but_secrets_still_dropped() {
        let folded = fold_row(
            json!({
                "cdn_url": "http://x/a", "thumb_url": "http://x/t", "head_url": "http://x/h",
                "cover_url": "http://x/c",
                "aes_key": "SEKRET", "cdn_key": "K", "extra_buffer": "deadbeef",
                "some_hex": "ab", "some_blob": "xx", "id_sha": "zz", "caption": "笑"
            }),
            8000,
        );
        // 这四个是**旧规则真删过、决策⑥改政策后才保留**的 URL 键 (cdn_url/thumb_url/head_url/cover_url) ——
        // 才是政策变更的有效回归守卫; 不放 profile_url 这类**旧规则本就不删**的键(断言恒真、对"改了什么"误导, 审 P3)。
        for u in ["cdn_url", "thumb_url", "head_url", "cover_url"] {
            assert!(folded.get(u).is_some(), "{u} 应保留(三皮一致): {folded:?}");
        }
        // 密钥/二进制/影子列**仍删**(不在列表命令输出里, 删不破坏一致; 纯防 crypto key 泄给 LLM)。
        for s in ["aes_key", "cdn_key", "extra_buffer", "some_hex", "some_blob", "id_sha"] {
            assert!(folded.get(s).is_none(), "{s} 应仍删: {folded:?}");
        }
        assert_eq!(folded["caption"], "笑", "正常列不动");
    }

    /// inspect_capped (inspect 逃生口): 预算够时不截长文 (返完整), 但仍脱敏 aeskey + 删敏感列 (审查 P1-7 + P1-1)。
    #[test]
    fn inspect_capped_no_truncation_when_budget_ample() {
        use native_query::{Meta, QueryResult, Source};
        let long = format!(r#"<img aeskey="SEKRET">{}</img>"#, "字".repeat(3000));
        let r = QueryResult {
            data: vec![json!({ "text_content": long, "recordinfo": "<huge/>" })],
            meta: Meta::page(1, 1).with_source(Source::Cold),
        };
        // ~3000 字 (~9KB) ≪ 512KB → 不截。
        let out = inspect_capped(&r, super::HARD_MAX_BYTES);
        let t = out["data"][0]["text_content"].as_str().unwrap();
        assert!(t.chars().count() > 3000, "预算够 → 不截断长文 (逃生口返完整)");
        assert!(!t.contains("SEKRET"), "仍脱敏 aeskey");
        assert!(out["data"][0].get("recordinfo").is_none(), "仍删敏感列");
        assert!(
            out["meta"].get("truncated_fields").is_none(),
            "没截 → 无 truncated_fields"
        );
    }

    // ══════ MCP 返回预算件 (max_bytes 参数 + 全路径硬上限 + wx_inspect 分段) ══════

    use native_query::{Meta, QueryResult, Source};

    use super::{
        cap_pack, enforce_budget, inspect_field, resolve_budget, DEFAULT_MAX_BYTES, HARD_MAX_BYTES, MIN_MAX_BYTES,
    };

    /// 造超 512KB 的宽结果 (每行长中文正文)。
    fn huge_result(rows: usize) -> QueryResult {
        let data: Vec<serde_json::Value> = (0..rows)
            .map(|i| json!({ "id": i, "text": "中".repeat(3000), "nick_name": "张三丰" }))
            .collect();
        QueryResult {
            data,
            meta: Meta::cursor_page(true, Some("C".into()), 100).with_source(Source::Cold),
        }
    }

    /// resolve_budget: 不传=默认 49152; 钳到 [16384, 524288]; 超上限钳上限、低于下限钳下限。
    #[test]
    fn resolve_budget_clamps_range() {
        assert_eq!(resolve_budget(None), DEFAULT_MAX_BYTES, "不传 → 默认 48KiB(49152)");
        assert_eq!(DEFAULT_MAX_BYTES, 49152);
        assert_eq!(resolve_budget(Some(131_072)), 131_072, "128KiB 原样");
        assert_eq!(resolve_budget(Some(262_144)), 262_144, "256KiB 原样");
        assert_eq!(
            resolve_budget(Some(9_999_999)),
            HARD_MAX_BYTES,
            "9999999 → 钳 512KiB(524288)"
        );
        assert_eq!(HARD_MAX_BYTES, 524_288);
        assert_eq!(resolve_budget(Some(1000)), MIN_MAX_BYTES, "低于下限 → 钳 16KiB(16384)");
        assert_eq!(resolve_budget(Some(524_288)), HARD_MAX_BYTES, "正好硬顶");
    }

    /// 普通 envelope 超长结果: 默认 → ≤49152; 128KB → 返更多但 ≤131072; 256KB → 比 128KB 更多且 ≤262144。
    /// 覆盖: 默认不超 / max_bytes=131072 超 48KB 不超 128KB / max_bytes=262144 不超 256KB / notice 计入。
    #[test]
    fn envelope_honors_various_budgets() {
        let r = huge_result(400); // 全量 ≫ 512KB
        let d = envelope(&r, DEFAULT_MAX_BYTES).to_string().len();
        assert!(d <= 49152, "默认预算 → ≤48KiB: {d}");
        let m = envelope(&r, 131_072).to_string().len();
        assert!(m <= 131_072, "128KiB 预算 → ≤128KiB: {m}");
        assert!(m > 49152, "128KiB 预算真能返超 48KB (预算被用上): {m}");
        let l = envelope(&r, 262_144).to_string().len();
        assert!(l <= 262_144, "256KiB 预算 → ≤256KiB: {l}");
        assert!(l > m, "256KiB 比 128KiB 返更多: {l} > {m}");
    }

    /// exec_envelope 超长结果也受预算 (默认 + 128KB 各自 ≤ 上限)。
    #[test]
    fn exec_envelope_honors_budget() {
        let r = huge_result(400);
        assert!(
            exec_envelope(&r, DEFAULT_MAX_BYTES).to_string().len() <= 49152,
            "exec 默认 ≤48KiB"
        );
        let m = exec_envelope(&r, 131_072).to_string().len();
        assert!(m <= 131_072 && m > 49152, "exec 128KiB 预算真用上且 ≤128KiB: {m}");
    }

    /// contact_pack/session_pack 走 cap_pack: 超长 recent 也受预算 (默认 + 128KB)。
    #[test]
    fn cap_pack_honors_budget() {
        let recent: Vec<serde_json::Value> = (0..2000)
            .map(|i| json!({ "id": i, "text": "聊".repeat(300) }))
            .collect();
        let pack = || json!({ "conv": "x@chatroom", "recent_messages": recent.clone() });
        assert!(
            cap_pack(pack(), DEFAULT_MAX_BYTES).to_string().len() <= 49152,
            "pack 默认 ≤48KiB"
        );
        let m = cap_pack(pack(), 131_072).to_string().len();
        assert!(m <= 131_072 && m > 49152, "pack 128KiB 预算真用上且 ≤128KiB: {m}");
    }

    /// wx_inspect 普通模式: 单条巨字段超预算 → 截长字段 + meta.truncated_fields 指明 (field+原始字符数)。
    #[test]
    fn inspect_capped_truncates_and_marks_fields() {
        let big = "超".repeat(60_000); // ~180KB 单字段
        let r = QueryResult {
            data: vec![json!({ "small": "hi", "big": big })],
            meta: Meta::page(1, 1).with_source(Source::Cold),
        };
        let out = inspect_capped(&r, DEFAULT_MAX_BYTES);
        assert!(out.to_string().len() <= 49152, "inspect 普通模式默认 ≤48KiB");
        assert_eq!(out["data"][0]["small"], "hi", "小字段保留");
        let tf = out["meta"]["truncated_fields"].as_array().expect("有 truncated_fields");
        assert!(tf.iter().any(|f| f["field"] == "big"), "big 字段标为被截");
        assert!(
            tf.iter()
                .any(|f| f["field"] == "big" && f["total_chars"] == json!(60_000)),
            "报原始字符数"
        );
    }

    /// wx_inspect 单字段分段: 小预算多次读, next_offset 递进, 拼回 == 完整脱敏内容; 含中文+emoji 不切码点。
    #[test]
    fn inspect_field_segments_reassemble_full() {
        let full: String = "消息内容🀄😀".repeat(5000); // 30000 字符, ~100KB, 无 '=' → redact 不动
        let r = QueryResult {
            data: vec![json!({ "big": &full })],
            meta: Meta::page(1, 1).with_source(Source::Cold),
        };
        let budget = MIN_MAX_BYTES; // 16KiB → 多段
        let mut acc = String::new();
        let mut offset = 0usize;
        let mut guard = 0;
        loop {
            let out = inspect_field(&r, "big", offset, budget);
            let sealed = enforce_budget(out, budget); // 模拟 tool_ok 盖 _budget
            assert!(sealed.to_string().len() <= budget, "每段(含 _budget) ≤ budget");
            acc.push_str(sealed["content"].as_str().unwrap());
            let next = usize::try_from(sealed["next_offset"].as_u64().unwrap()).unwrap();
            let has_more = sealed["has_more"].as_bool().unwrap();
            assert!(next > offset || !has_more, "offset 必前进 (否则死循环)");
            offset = next;
            if !has_more {
                break;
            }
            guard += 1;
            assert!(guard < 100, "分段不该超 100 次");
        }
        assert_eq!(acc, full, "分段拼回 == 完整内容 (中文+emoji 未切码点)");
        assert_eq!(acc.chars().count(), 30_000);
    }

    /// wx_inspect 单字段: 字段 >512KB, 各档预算 (48/128/512KB) 每段(含 _budget) 都 ≤ 预算 + has_more。
    #[test]
    fn inspect_field_huge_various_budgets() {
        let full = "x".repeat(600_000); // >512KB
        let r = QueryResult {
            data: vec![json!({ "big": &full })],
            meta: Meta::page(1, 1).with_source(Source::Cold),
        };
        for budget in [DEFAULT_MAX_BYTES, 131_072, HARD_MAX_BYTES] {
            let sealed = enforce_budget(inspect_field(&r, "big", 0, budget), budget);
            assert!(
                sealed.to_string().len() <= budget,
                "field 段(含 _budget) ≤ budget={budget}"
            );
            assert_eq!(sealed["has_more"], json!(true), "600KB 字段一段读不完 → has_more");
        }
    }

    /// wx_inspect 分段: 字段内嵌 aeskey → 每段脱敏, 跨段拼接也拼不出密钥 (切段前先 redact)。
    #[test]
    fn inspect_field_redacts_across_segments() {
        let full = format!(r#"<img aeskey="SEKRET_KEY_MATERIAL">{}</img>"#, "填".repeat(20_000));
        let r = QueryResult {
            data: vec![json!({ "big": &full })],
            meta: Meta::page(1, 1).with_source(Source::Cold),
        };
        let budget = MIN_MAX_BYTES;
        let mut acc = String::new();
        let mut offset = 0usize;
        loop {
            let out = inspect_field(&r, "big", offset, budget);
            acc.push_str(out["content"].as_str().unwrap());
            offset = usize::try_from(out["next_offset"].as_u64().unwrap()).unwrap();
            if !out["has_more"].as_bool().unwrap() {
                break;
            }
        }
        assert!(
            !acc.contains("SEKRET_KEY_MATERIAL"),
            "跨段拼接也不含明文 aeskey (脱敏在切段前)"
        );
        assert!(acc.contains(r#"aeskey="***""#), "aeskey 值抹成 ***, 结构保留");
    }

    /// enforce_budget: 盖 meta._budget 五字段 + response_bytes ≤ budget; 未截时 truncated=false 无 suggested。
    #[test]
    fn enforce_budget_stamps_meta() {
        let small = json!({ "data": [json!({ "x": 1 })], "meta": { "source": "cold" } });
        let out = enforce_budget(small, DEFAULT_MAX_BYTES);
        let b = &out["meta"]["_budget"];
        assert_eq!(b["budget_bytes"], json!(49152));
        assert_eq!(b["hard_max_bytes"], json!(524_288));
        assert_eq!(b["truncated"], json!(false), "小结果未截");
        assert!(b.get("suggested_max_bytes").is_none(), "未截 → 无 suggested");
        let rb = b["response_bytes"].as_u64().unwrap();
        assert!(rb <= 49152 && rb > 0, "response_bytes 是实际字节且 ≤ budget: {rb}");
    }

    /// 全路径硬上限: 即便某响应绕过折叠直返超限, enforce_budget 兜底丢 data → **无条件** ≤ budget + truncated。
    #[test]
    fn enforce_budget_backstops_unfolded_oversized() {
        // 未经折叠的超限 {data,meta} (data 巨大)。
        let bypass = json!({
            "data": (0..5000).map(|i| json!({ "id": i, "t": "z".repeat(200) })).collect::<Vec<_>>(),
            "meta": { "source": "cold" }
        });
        let out = enforce_budget(bypass, DEFAULT_MAX_BYTES);
        assert!(out.to_string().len() <= 49152, "兜底闸: 未折叠超限也 ≤ budget");
        assert_eq!(
            out["meta"]["_budget"]["truncated"],
            json!(true),
            "兜底截 → truncated=true"
        );
        assert_eq!(out["meta"]["oversized"], json!(true), "标 oversized");
    }

    /// oversized envelope 截断时 _budget.truncated=true 且给 suggested_max_bytes 下一档 (让 AI 一步跳够用档)。
    #[test]
    fn truncated_response_suggests_next_tier() {
        let r = huge_result(400);
        let out = enforce_budget(envelope(&r, DEFAULT_MAX_BYTES), DEFAULT_MAX_BYTES);
        assert_eq!(out["meta"]["_budget"]["truncated"], json!(true), "超长截断 → truncated");
        assert_eq!(
            out["meta"]["_budget"]["suggested_max_bytes"],
            json!(131_072),
            "48KiB 档建议下一档 128KiB"
        );
        assert!(out.to_string().len() <= 49152, "含 _budget/notice 仍 ≤ budget");
    }

    /// 真库跑逮出 (id=4): 预算逼正文压到默认以下、但行全在 (未砍行) 也要 truncated=true (原只认砍行 oversized,
    /// 漏报正文被压)。行全在 → 非 oversized; content_truncated → _budget.truncated=true + suggested。
    #[test]
    fn content_shrunk_but_rows_kept_still_truncated() {
        let data: Vec<serde_json::Value> = (0..30).map(|i| json!({ "id": i, "text": "字".repeat(1500) })).collect();
        let r = QueryResult {
            data,
            meta: Meta::cursor_page(true, Some("C".into()), 100).with_source(Source::Cold),
        };
        let budget = 32 * 1024; // 32KiB: 30 行默认 800 截 ≈75KB 超 → 压正文到 fit, 但 30 行全留
        let out = envelope(&r, budget);
        assert!(out.to_string().len() <= budget, "≤ budget");
        assert_eq!(out["data"].as_array().unwrap().len(), 30, "行全在 (没进步骤2 砍行)");
        assert_eq!(
            out["meta"]["content_truncated"],
            json!(true),
            "正文被预算压缩 → content_truncated"
        );
        assert!(out["meta"].get("oversized").is_none(), "没砍行 → 非 oversized");
        let sealed = enforce_budget(out, budget);
        assert_eq!(
            sealed["meta"]["_budget"]["truncated"],
            json!(true),
            "content_truncated → _budget.truncated"
        );
        assert_eq!(
            sealed["meta"]["_budget"]["suggested_max_bytes"],
            json!(131_072),
            "32KiB 建议下一档 128KiB"
        );
    }

    // ── 复审 codex+Claude 双 P1 追修回归 ──

    /// **codex#1 / Claude P2-C**: 折叠层必须给 `_budget` 预留位 —— 否则 fit 到 budget 后盖 _budget 破 budget、兜底闸
    /// 清空整页。断言 `enforce_budget(envelope) ≤ budget` **且非空** (本能返的结果不被清成空), 跨多规模×多档预算。
    #[test]
    fn sealed_envelope_within_budget_and_not_nuked() {
        let nuke_note = "响应超预算且未经折叠, 已丢弃载荷; 缩小查询或调大 max_bytes。";
        for rows in [10usize, 200, 2000] {
            for budget in [MIN_MAX_BYTES, DEFAULT_MAX_BYTES, 131_072] {
                let data: Vec<serde_json::Value> = (0..rows)
                    .map(|i| json!({ "id": i, "text": "消息".repeat(20) }))
                    .collect();
                let r = QueryResult {
                    data,
                    meta: Meta::cursor_page(true, Some("C".into()), 100).with_source(Source::Cold),
                };
                let sealed = enforce_budget(envelope(&r, budget), budget);
                let bytes = sealed.to_string().len();
                assert!(bytes <= budget, "sealed rows={rows} budget={budget}: {bytes} 超预算");
                assert!(
                    !sealed["data"].as_array().unwrap().is_empty(),
                    "rows={rows} budget={budget}: 本能返却被兜底清空 (P1)"
                );
                assert_ne!(sealed["meta"]["note"].as_str(), Some(nuke_note), "不该触发兜底闸");
            }
        }
    }

    /// **codex#1 / Claude P1-B**: `cap_pack` 也须预留 → `enforce_budget(cap_pack) ≤ budget`。
    #[test]
    fn sealed_cap_pack_within_budget() {
        let recent: Vec<serde_json::Value> = (0..500).map(|i| json!({ "id": i, "text": "聊".repeat(200) })).collect();
        for budget in [MIN_MAX_BYTES, DEFAULT_MAX_BYTES, 131_072] {
            let pack = json!({ "conv": "x@chatroom", "recent_messages": recent.clone() });
            let sealed = enforce_budget(cap_pack(pack, budget), budget);
            assert!(sealed.to_string().len() <= budget, "sealed cap_pack budget={budget} 超");
        }
    }

    /// **codex#3 / Claude P1-A** (headline): 满是引号/反斜杠/控制符的字段序列化后膨胀 ~2x; inspect_field 按
    /// **序列化长度**切段 → `enforce_budget(inspect_field) ≤ budget` (原按 len_utf8 切会破 budget)。
    #[test]
    fn inspect_field_escape_heavy_within_budget() {
        let full: String = "\"\\\t".repeat(200_000); // 每字符都是 2 字节转义, 600K 字符 → 序列化 ~1.2MB
        let r = QueryResult {
            data: vec![json!({ "big": &full })],
            meta: Meta::page(1, 1).with_source(Source::Cold),
        };
        for budget in [MIN_MAX_BYTES, DEFAULT_MAX_BYTES, HARD_MAX_BYTES] {
            let sealed = enforce_budget(inspect_field(&r, "big", 0, budget), budget);
            let bytes = sealed.to_string().len();
            assert!(
                bytes <= budget,
                "转义膨胀字段 sealed budget={budget}: {bytes} 超 (须按序列化长度切)"
            );
            assert_eq!(sealed["has_more"], json!(true), "600K 字符一段读不完");
        }
    }

    /// **codex#2 / Claude P1-B**: 兜底闸 shape-agnostic —— 非 `data` 形态 (顶层 content, 如 inspect_field) 绕过
    /// 折叠直返超限也封顶 (原只丢 data, 管不了 content)。
    #[test]
    fn backstop_caps_non_data_content_shape() {
        let bypass = json!({ "field": "big", "content": "z".repeat(600_000), "meta": { "source": "cold" } });
        let sealed = enforce_budget(bypass, DEFAULT_MAX_BYTES);
        assert!(sealed.to_string().len() <= 49152, "content 形态兜底也 ≤ budget");
        assert_eq!(
            sealed["meta"]["_budget"]["truncated"],
            json!(true),
            "兜底截 → truncated"
        );
        assert!(sealed.get("content").is_none(), "content 载荷已丢 (只留 meta+data:[])");
    }

    /// **codex P3**: `response_bytes` 报**最终真实**紧凑字节 (不动点回填), 非略偏大的占位量。
    #[test]
    fn response_bytes_reports_exact_serialized_len() {
        for budget in [MIN_MAX_BYTES, DEFAULT_MAX_BYTES, HARD_MAX_BYTES] {
            let r = QueryResult {
                data: vec![json!({ "id": 1, "text": "hi" })],
                meta: Meta::hot(false).with_source(Source::Hot),
            };
            let sealed = enforce_budget(envelope(&r, budget), budget);
            let reported = sealed["meta"]["_budget"]["response_bytes"].as_u64().unwrap();
            let actual = sealed.to_string().len() as u64;
            assert_eq!(reported, actual, "budget={budget}: response_bytes 须 == 最终序列化字节");
        }
    }

    /// **复审 R1 加固 (codex/Claude nit)**: 兜底闸也丢 `truncated_fields` —— 它项数随字段数无界 (受 schema 约束但非
    /// 构造性有界)。喂一个 meta 里塞了巨量 truncated_fields 的绕过响应, 兜底后仍 ≤ budget (原只丢 summary 会漏它)。
    #[test]
    fn backstop_drops_unbounded_truncated_fields() {
        let huge_tf: Vec<serde_json::Value> = (0..3000)
            .map(|i| json!({ "field": format!("field_number_{i}"), "total_chars": 99_999 }))
            .collect();
        // 巨 truncated_fields (~3000×~45B ≈135KB) 塞进 meta, data 只占位 → 兜底必须把 tf 也丢掉才 ≤ budget。
        let bypass = json!({
            "data": [json!({ "x": 1 })],
            "meta": { "source": "cold", "truncated_fields": huge_tf }
        });
        let sealed = enforce_budget(bypass, DEFAULT_MAX_BYTES);
        assert!(
            sealed.to_string().len() <= 49152,
            "巨 truncated_fields 兜底也须 ≤ budget"
        );
        assert!(
            sealed["meta"].get("truncated_fields").is_none(),
            "兜底丢 truncated_fields"
        );
        assert_eq!(
            sealed["meta"]["_budget"]["truncated"],
            json!(true),
            "兜底截 → truncated"
        );
    }
}
