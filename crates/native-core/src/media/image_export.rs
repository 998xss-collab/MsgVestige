//! 图片批量导出 (ADR-461 件4) — 遍历 message db 定位 + 解密图片 `.dat` → 落图文件。
//!
//! 串起前三件: [`parse_image_md5`](crate::decoder::parse_image_md5) (件2 从 packed_info 抽定位 md5) →
//! [`resolve_image`](super::image_resolve::resolve_image) (件2 算 .dat 路径) → 逐候选探 FS →
//! [`decrypt_dat`](crate::decoder::decrypt_dat) (件1 解密) → 写图。
//!
//! **best-effort** (ADR-421 媒体口径): 单张定位不到 (微信已清理) / 解密失败 / 写盘失败都不中断整体,
//! 只累计到 [`ImageExportStats`]。**只有 db 级错误** (表损坏 / SQL 失败) 才 `Err` 中止。
//!
//! `conn` = **已解密**的 message db (明文 sqlite; 加密源的解密走 cipher, 是上层/后续件的事)。
//! `account_dir` = xwechat_files 账号目录 (`msg/attach` 所在)。`key` = 账号级 image key (件3 提取或手传)。

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use super::image_resolve::{resolve_image, ImageVariant};
use crate::decoder::{
    decrypt_dat, detect_version, parse_image_md5, DatError, DatFormat, DatVersion, DecodedImage, ImageKey,
};

/// 导出统计 (best-effort: 单张失败不中断)。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImageExportStats {
    /// 扫到的图片消息数 (local_type=3 且 packed_info 抽出定位 md5)。
    pub scanned: usize,
    /// 成功解密并落**直接可看的图** (jpg/png/gif/webp/bmp)。
    pub written: usize,
    /// 解出是 **wxgf 动图容器** → 落 `.wxgf` (内层 HEVC), 待 cli 层 ffmpeg 转码成 GIF; 不计 written。
    pub wxgf: usize,
    /// 定位到路径但盘上文件不存在 (微信已清理, 约占 30%)。
    pub missing: usize,
    /// 文件在但读/解密/写盘失败。
    pub failed: usize,
}

/// io + 解密错误合流 (per-image best-effort, 不外抛)。
#[derive(Debug, thiserror::Error)]
enum ImageWriteError {
    #[error("io")]
    Io(#[from] std::io::Error),
    #[error("decrypt")]
    Decrypt(#[from] DatError),
    /// 解密成功但解出的不是已知图格式 — 大概率 key 错/文件损坏, 不写垃圾 .bin (codex 件4 P1)。
    #[error("unknown image format (likely wrong key)")]
    UnknownFormat,
}

/// 遍历 `conn` 里所有 `Msg_<32hex>` 表的图片消息, 定位 .dat → 解密 → 写 `out_dir`。best-effort。
/// `limit` = 最多落多少张 (None 全部)。返回统计; 仅 db 级错误 `Err`。
pub fn export_images(
    conn: &Connection,
    account_dir: &Path,
    key: &ImageKey,
    out_dir: &Path,
    limit: Option<usize>,
) -> rusqlite::Result<ImageExportStats> {
    let mut stats = ImageExportStats::default();
    // 尽力建输出目录 (失败留给后面 fs::write 报 → 计 failed, 不在此中止)。
    let _ = fs::create_dir_all(out_dir);

    for table in msg_content_tables(conn)? {
        // 表名 = Msg_<talker md5>; 只认 32-hex talker (挡 Msg_ 前缀但非会话表 → 列缺失 SQL 报错)。
        let Some(talker) = table.strip_prefix("Msg_") else {
            continue;
        };
        if talker.len() != 32 || !talker.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }

        let sql = format!(
            "SELECT local_id, create_time, packed_info_data FROM \"{table}\" \
             WHERE local_type = 3 AND packed_info_data IS NOT NULL"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
        })?;

        for row in rows {
            if limit.is_some_and(|l| stats.written >= l) {
                return Ok(stats);
            }
            let (local_id, create_time, packed) = row?;
            let Some(md5) = parse_image_md5(&packed) else {
                continue; // 非图片 packed_info / 畸形 → 跳
            };
            stats.scanned += 1;

            // 逐候选 (完整→高清→缩略) 探 FS。区分"不存在"(→试下一个/missing) 与真 IO 错
            // (权限/坏盘 → failed, 别当 missing 掩盖问题; codex 件4 P2)。
            let mut hit = None;
            let mut probe_io_err = false;
            for loc in resolve_image(talker, create_time, &md5) {
                let p = account_dir.join(&loc.rel_path);
                match fs::metadata(&p) {
                    Ok(m) if m.is_file() => {
                        hit = Some(p);
                        break;
                    }
                    Ok(_) => {}                                              // 是目录 (不该) → 跳
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // 没有 → 探下一个
                    Err(_) => probe_io_err = true,                           // 权限/IO 错
                }
            }
            let Some(dat_path) = hit else {
                if probe_io_err {
                    stats.failed += 1; // 探测遇真 IO 错 → failed
                } else {
                    stats.missing += 1; // 纯不存在 = 微信已清理
                }
                continue;
            };

            match decrypt_and_write(&dat_path, key, out_dir, &format!("{talker}_{local_id}")) {
                Ok(DatFormat::Wxgf) => stats.wxgf += 1, // 落了 .wxgf, 待 ffmpeg 转码 (非直接可看的图)
                Ok(_) => stats.written += 1,            // jpg/png/gif/webp/bmp 直接可看
                Err(_) => stats.failed += 1,            // 读/解密/Unknown/写失败 → best-effort 跳
            }
        }
    }
    Ok(stats)
}

/// 按 `(talker_md5, local_id)` 取**单张**图片 → 解码后的图字节 (HTTP `/media/img:<talker_md5>:<local_id>` 用)。
/// 读该会话表那行的 `packed_info_data` → [`parse_image_md5`] 抽定位 md5 → [`resolve_image`] 候选 (完整→高清→缩略)
/// → 逐候选探 FS + [`decrypt_dat`] 解密, 取**第一个解得开的**。
///
/// `image_key`: **V2 完整图**需账号 aes —— `None` 时 V2 候选解不开被跳过, 自然落到 **V0 缩略图** (`_t_W.dat`,
/// 单字节 XOR 解码器自推, 不需 key); V1 (固定全局 key) / 明文也不需 `image_key`。故 `None` 也能出缩略图,
/// 给了 key 才可能出完整图 (且该完整图在盘上, 多数图用户没下原图只有缩略图)。
///
/// 无此消息 / `packed_info` 无 md5 / 候选全不存在或全解不开 → `Ok(None)`。`talker_md5` 非 32-hex → `Ok(None)`。
/// 返回 [`DecodedImage`] (含 `format`: jpg/png/gif/webp/bmp/**wxgf**——wxgf 需上层 ffmpeg 转码)。
///
/// # Errors
/// rusqlite 查询失败 (会话表结构异常等 db 级错误)。
pub fn fetch_image_one_located(
    msg_conn: &Connection,
    account_dir: &Path,
    image_key: Option<&ImageKey>,
    talker_md5: &str,
    local_id: i64,
) -> rusqlite::Result<Option<(DecodedImage, ImageVariant)>> {
    if talker_md5.len() != 32 || !talker_md5.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let table = format!("Msg_{talker_md5}");
    // §8 P1 (分片健壮性): 一张 Msg_<talker> 表只在**拥有它的那个** message_N.db 里 (每分片只是全部会话的子集);
    // serve_image 逐分片调本函数, 非拥有分片没这表。rusqlite "no such table" 是 SqliteFailure, `.optional()` **只**吞
    // QueryReturnedNoRows 不吞它 → 会经 `?` 上抛把'表不在这分片'当硬错误 (误映 409), 真实可解的图永取不到。故**先判表
    // 存在**, 缺表 → Ok(None) 让分片循环续到下一分片 (与 voice_info_tables / msg_content_tables 先枚举 sqlite_master 一致)。
    let table_exists: bool = msg_conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table.as_str()],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !table_exists {
        return Ok(None);
    }
    let row: Option<(i64, Vec<u8>)> = msg_conn
        .query_row(
            &format!(
                "SELECT create_time, packed_info_data FROM \"{table}\" \
                 WHERE local_id = ?1 AND local_type = 3 AND packed_info_data IS NOT NULL"
            ),
            [local_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((create_time, packed)) = row else {
        return Ok(None);
    };
    let Some(md5) = parse_image_md5(&packed) else {
        return Ok(None);
    };
    // 候选序 = 完整→高清→缩略。decrypt_dat: V0/V1/明文用 image_key=None 也解; V2 无 key / 错 key → Err 或 Ok{Unknown}
    // → 都跳到下一候选 (自然落到 V0 缩略图)。取第一个**解出真图**的。
    for loc in resolve_image(talker_md5, create_time, &md5) {
        let p = account_dir.join(&loc.rel_path);
        let Ok(data) = fs::read(&p) else { continue }; // 不存在 / IO 错 → 试下一候选 (best-effort)
                                                       // §8 P3: decrypt_dat 对错/陈旧 key 的 V2 段返 Ok{format:Unknown, 垃圾字节} (从不校验 key) —— 别把垃圾当图返
                                                       // 200, 也别短路掉无 key 也能解的缩略图退路; Unknown 跳到下一候选 (同 decrypt_and_write 拒 Unknown 的口径)。
        if let Ok(img) = decrypt_dat(&data, image_key) {
            if img.format != DatFormat::Unknown {
                return Ok(Some((img, loc.variant)));
            }
        }
    }
    Ok(None)
}

/// HTTP `/media/img` 单件:只要解码后的图, 不关心变体(缩略/完整)。见 [`fetch_image_one_located`]。
///
/// # Errors
/// rusqlite 查询失败。
pub fn fetch_image_one(
    msg_conn: &Connection,
    account_dir: &Path,
    image_key: Option<&ImageKey>,
    talker_md5: &str,
    local_id: i64,
) -> rusqlite::Result<Option<DecodedImage>> {
    Ok(fetch_image_one_located(msg_conn, account_dir, image_key, talker_md5, local_id)?.map(|(img, _)| img))
}

/// 从账号 `msg/attach` 目录**直接扫**出前 `want` 张**互不相同**的 V2 `.dat` 原始字节 — 给 image key
/// 内存扫做交叉验证锚 + xor 反推 (msgvestige 自动取 key 用)。
///
/// **走文件系统不经 message db**: V2 = 完整原图 (账号级 AES key 加密, 文件名裸 `<md5>.dat`); 缩略图是
/// V0 (单字节 XOR, 解码器自推 key, 不需 AES) 不收 —— 而 message 里 packed_info 的 md5 指向的正是缩略图,
/// 顺它走只会拿到 V0, 碰不到 V2。故直接递归 `msg/attach` 读头判 V2。**只读头 6 字节筛** (省掉整读成千张
/// V0 缩略图), 命中 V2 才整读 (xor 反推需完整文件尾)。满 `want` 即停。
///
/// 去重按整文件字节 (同图多处缓存 = 同内容 → 只收一张), 保证多锚是真不同样本 (单锚在海量滑窗下撞假阳)。
/// 返回 < `want` 张 = 该账号 V2 完整图少 (用户多数图只留了缩略图, 没点开下原图) — 调用方据此提示。
#[must_use]
pub fn collect_v2_samples(account_dir: &Path, want: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    if want == 0 {
        return out;
    }
    // 迭代式深度遍历 (显式栈, 不递归 → 无深度爆栈风险)。
    let mut stack = vec![account_dir.join("msg").join("attach")];
    while let Some(dir) = stack.pop() {
        if out.len() >= want {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue; // 目录不存在 / 无权限 → 跳
        };
        for entry in entries.flatten() {
            if out.len() >= want {
                break;
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file()
                && path.extension().is_some_and(|e| e.eq_ignore_ascii_case("dat"))
                // 只收 `Img/` 下的 .dat (图片专属目录) — 多锚验证要求每张都是合法图锚, 一张非图坏锚就废掉整次
                // 扫描 (同 WXGF 风险); 限定 Img 挡掉 msg/attach 里潜在的 Video/File/Emoji .dat 污染。
                && path.parent().and_then(Path::file_name).is_some_and(|n| n == "Img")
            {
                // 先读头 6 字节判 V2 (省掉整读大量 V0 缩略图); 是 V2 才整读 (反推 xor 需完整文件尾)。
                if is_v2_dat_head(&path) {
                    if let Ok(data) = fs::read(&path) {
                        if detect_version(&data) == DatVersion::V2 && !out.contains(&data) {
                            out.push(data);
                        }
                    }
                }
            }
        }
    }
    out
}

/// 只读文件头 6 字节判是否 V2 `.dat` (`\x07\x08V2\x08\x07`) — 避免整读大量非 V2 文件 (collect_v2_samples 用)。
fn is_v2_dat_head(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 6];
    f.read_exact(&mut head).is_ok() && head == *b"\x07\x08V2\x08\x07"
}

/// 文件名是不是**缩略图** `.dat` (`_t` 段: `<md5>_t_W.dat` / `_t_NW.dat` / `<md5>_t.dat`)。
/// 全分辨率导出跳过缩略图 (缩略归 message-driven)。md5 是 hex 无 `t`, 故 `_t_` 只出现在缩略图名, 不误伤全图。
fn is_thumb_dat(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("_t_") || lower.ends_with("_t.dat")
}

/// 读 .dat → 解密 → 写 `out_dir/<name>.<ext>`。返回落盘的格式 (调用方据此计 written/wxgf)。
/// `name` = 唯一文件名主干 (message 路走 `<talker>_<local_id>`; 扫盘路走 .dat 的 md5 stem)。
fn decrypt_and_write(
    dat_path: &Path,
    key: &ImageKey,
    out_dir: &Path,
    name: &str,
) -> Result<DatFormat, ImageWriteError> {
    let data = fs::read(dat_path)?;
    let img = decrypt_dat(&data, Some(key))?;
    // 解出来不是已知图 (jpg/png/gif/webp/bmp/wxgf) = 大概率 key 错/损坏 → 算失败, 不写 .bin 垃圾 (codex P1)。
    if img.format == DatFormat::Unknown {
        return Err(ImageWriteError::UnknownFormat);
    }
    // wxgf → 落 `.wxgf` (内层 HEVC, 待 ffmpeg 转 GIF); 其余落对应图扩展名 (直接可看)。
    let out = out_dir.join(format!("{name}.{}", img.format.ext()));
    // 写失败(最常见是**磁盘满**, 也可能是权限/路径)时 `fs::write` 可能已经落了**半截文件**。
    // 不清掉的话: 计数记成 failed, 但那个残缺文件还躺在输出目录里 —— 用户看到文件在, 以为是好的,
    // 打开才发现是坏的。写失败就顺手删掉残留, 让"目录里有的都是完整的"成立。
    if let Err(e) = fs::write(&out, &img.bytes) {
        let _ = fs::remove_file(&out); // best-effort: 删不掉也不改变"这次写失败"的结论
        return Err(e.into());
    }
    Ok(img.format)
}

/// **扫盘**导出全分辨率图 (区别于 [`export_images`] 走 message packed_info 只能定位到 V0 缩略图路径)。
///
/// 递归 `msg/attach/*/*/Img/` 解**所有非 `_t` 缩略图**的 `.dat` (跳缩略图)。⚠️ **全类型都解不只 V2**
/// (2026-07-04 修 XOR-WXGF 漏解 bug): 全分辨率图落盘有多种编码 —— **V2** 三段 AES 头 (`<md5>.dat`) /
/// **V0 单字节 XOR** (含 **wxgf 动图/HEVC 图**、全图 JPEG 2048px、XOR-PNG; 头如 `a4ab..` = wxgf XOR key) /
/// **明文**。早先只认 V2 头 → 漏 XOR 式 WXGF (本账号 ~852 含唯一动图) + 全图 V0-JPEG 等。`decrypt_dat` 已
/// 能认全部 (V2/V0-magic反推/明文/wxgf), 交它解。静态图落 jpg/png/gif; **wxgf 落 `.wxgf`** (待 cli ffmpeg 转)。
/// 文件名用 .dat 的 stem (多是 md5)。
///
/// `limit` = 最多扫多少张 (None 全部; codex P2 按 scanned 计)。best-effort: 单张读/解/写失败只计 failed。
/// **无 missing** (扫盘只见在盘文件)。
#[must_use]
pub fn export_full_images(
    account_dir: &Path,
    key: &ImageKey,
    out_dir: &Path,
    limit: Option<usize>,
) -> ImageExportStats {
    let mut stats = ImageExportStats::default();
    let _ = fs::create_dir_all(out_dir);
    let mut stack = vec![account_dir.join("msg").join("attach")];
    while let Some(dir) = stack.pop() {
        if limit.is_some_and(|l| stats.scanned >= l) {
            break; // codex P2: limit 按已扫 V2 数算 (非成功数) — 遇错 key/坏文件也不会远超 limit 递归全盘。
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if limit.is_some_and(|l| stats.scanned >= l) {
                break; // codex P2 一致: 内外 limit 都按 scanned (原内层用 written+wxgf 不一致)。
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            // 处理 Img/ 下的 .dat, **跳过 `_t` 缩略图** (缩略归 message-driven; 本模式要全分辨率)。
            // ⚠️ **全类型都解不再只挑 V2** (2026-07-04 修): 全分辨率图有多种落盘 —— V2 三段头 / **V0 单字节 XOR**
            // (含 wxgf 动图/HEVC 图 `_W.dat` + 全图 JPEG 2048px + XOR-PNG) / 明文。只认 V2 会漏一大片 (本账号实测
            // 漏 ~852 张 XOR 式 WXGF 含唯一动图 + 全图 V0-JPEG 等); decrypt_dat 已能认全部, 交它解。
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let is_img_dat = ft.is_file()
                && name.to_ascii_lowercase().ends_with(".dat")
                && path.parent().and_then(Path::file_name).is_some_and(|n| n == "Img");
            if !is_img_dat || is_thumb_dat(name) {
                continue;
            }
            stats.scanned += 1;
            // 文件名主干 = .dat 的 stem (去 .dat, 多是 md5); 非法则用 "img" 兜 (罕见)。
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("img");
            match decrypt_and_write(&path, key, out_dir, stem) {
                Ok(DatFormat::Wxgf) => stats.wxgf += 1, // wxgf 动图/HEVC 图 → 落 .wxgf 待转码
                Ok(_) => stats.written += 1,            // jpg/png/gif/webp 直接可看
                Err(_) => stats.failed += 1,            // 解不出 (非图/坏/key 错) → 跳
            }
        }
    }
    stats
}

/// 扫**朋友圈本地缓存** `cache/<年-月>/Sns/Img/**` 解 V2 .dat 落图 (ADR-489; 朋友圈媒体获取①本地缓存路,
/// 补②CDN 下载老 URL 过期盲区)。SNS 缓存图 = **V2 .dat 格式** (头 `\x07\x08V2\x08\x07`, 账号级 image key
/// AES+XOR, 与聊天图同款; 真库 40/40 解出有效 JPEG 坐实)。文件名为 hash **无扩展名** (区别 msg/attach 的 `.dat`),
/// 故不按扩展名过滤, 直接交 `decrypt_dat` 认 (V2/V0/明文/wxgf); 非图 → failed 跳。零联网、零 WASM、不过期。
///
/// `limit` = 最多扫多少张 (None 全部; 按 scanned 计, 同 [`export_full_images`])。best-effort: 单张失败只计 failed。
#[must_use]
pub fn export_sns_cache_images(
    cache_dir: &Path,
    key: &ImageKey,
    out_dir: &Path,
    limit: Option<usize>,
) -> ImageExportStats {
    let mut stats = ImageExportStats::default();
    let _ = fs::create_dir_all(out_dir);
    // 收各月 `<cache>/<年-月>/Sns/Img` 根 (只扫 Img, 跳 Temp 临时目录)。
    let mut stack: Vec<PathBuf> = Vec::new();
    if let Ok(months) = fs::read_dir(cache_dir) {
        for m in months.flatten() {
            let sns_img = m.path().join("Sns").join("Img");
            if sns_img.is_dir() {
                stack.push(sns_img);
            }
        }
    }
    while let Some(dir) = stack.pop() {
        if limit.is_some_and(|l| stats.scanned >= l) {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if limit.is_some_and(|l| stats.scanned >= l) {
                break;
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path); // 递归 `Img/<2hex 前缀>/` 子目录
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            stats.scanned += 1;
            // 文件名 = hash (无扩展名); 直接兜给 decrypt_and_write, 由 decrypt_dat 认格式, 非图算 failed。
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("sns");
            match decrypt_and_write(&path, key, out_dir, name) {
                Ok(DatFormat::Wxgf) => stats.wxgf += 1,
                Ok(_) => stats.written += 1,
                Err(_) => stats.failed += 1,
            }
        }
    }
    stats
}

/// 列出所有 `Msg_` 前缀表名 (会话消息表; talker 合法性由调用方 hex 校验)。`pub(crate)`: video_export 复用。
pub(crate) fn msg_content_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    // ESCAPE 让 `_` 当字面量 (否则 LIKE 里 `_` 是单字符通配)。
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\'")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TALKER: &str = "b3010f26cfa89d420c8d8183bb3d5f5b";

    /// 合成图片 packed_info blob (field1=803, field2=4, field3{ field4 = md5 })。
    fn packed_info(md5: &str) -> Vec<u8> {
        let mut nested = vec![0x22, md5.len() as u8];
        nested.extend_from_slice(md5.as_bytes());
        let mut out = vec![0x08, 0xA3, 0x06, 0x10, 0x04, 0x1A, nested.len() as u8];
        out.extend_from_slice(&nested);
        out
    }

    /// 建内存 message db, 插一张 Msg_<talker> 表 + 若干图片行。
    fn msg_db(rows: &[(i64, i64, Vec<u8>)]) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(&format!(
            "CREATE TABLE \"Msg_{TALKER}\" (local_id INTEGER, local_type INTEGER, create_time INTEGER, packed_info_data BLOB);"
        ))
        .unwrap();
        for (lid, ct, packed) in rows {
            c.execute(
                &format!("INSERT INTO \"Msg_{TALKER}\" (local_id, local_type, create_time, packed_info_data) VALUES (?1, 3, ?2, ?3)"),
                rusqlite::params![lid, ct, packed],
            )
            .unwrap();
        }
        c
    }

    fn dummy_key() -> ImageKey {
        ImageKey {
            aes: *b"f55dbb3da8a161c6",
            xor: 0xD3,
        }
    }

    #[test]
    fn empty_db_zero_stats() {
        let c = Connection::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let stats = export_images(&c, tmp.path(), &dummy_key(), &tmp.path().join("out"), None).unwrap();
        assert_eq!(stats, ImageExportStats::default());
    }

    #[test]
    fn image_row_but_file_absent_counts_missing() {
        // 有图片消息但 account_dir 里没有对应 .dat → missing++ (不 failed, 不 panic)。
        let md5 = "e3e751d84c3d0e81189b27d6a3d4dcad";
        let c = msg_db(&[(88, 1_752_143_852, packed_info(md5))]);
        let tmp = tempfile::tempdir().unwrap();
        let stats = export_images(&c, tmp.path(), &dummy_key(), &tmp.path().join("out"), None).unwrap();
        assert_eq!(stats.scanned, 1, "扫到 1 张图片消息");
        assert_eq!(stats.missing, 1, "盘上无文件 → missing");
        assert_eq!(stats.written, 0);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn non_image_packed_info_skipped() {
        // 文本消息的 packed_info (只 field1+field2, 无 md5) → 不计 scanned。
        let c = msg_db(&[(1, 1_752_143_852, vec![0x08, 0xA3, 0x06, 0x10, 0x04])]);
        let tmp = tempfile::tempdir().unwrap();
        let stats = export_images(&c, tmp.path(), &dummy_key(), &tmp.path().join("out"), None).unwrap();
        assert_eq!(stats.scanned, 0, "无定位 md5 → 不计 scanned");
    }

    #[test]
    fn non_talker_table_ignored() {
        // Msg_ 前缀但非 32-hex talker (如 Msg_dbInfo) → 跳过, 不因列缺失 SQL 报错。
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE \"Msg_dbInfo\" (x INTEGER);").unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let stats = export_images(&c, tmp.path(), &dummy_key(), &tmp.path().join("out"), None).unwrap();
        assert_eq!(stats, ImageExportStats::default(), "非会话表跳过, 无错");
    }

    /// `fetch_image_one` (HTTP 单件): 明文图 image_key=None 也取到; 无此消息 / 非法 talker → None。
    #[test]
    fn fetch_image_one_plaintext_no_key() {
        let md5 = "e3e751d84c3d0e81189b27d6a3d4dcad";
        let ct = 1_752_143_852_i64;
        let c = msg_db(&[(88, ct, packed_info(md5))]);
        let tmp = tempfile::tempdir().unwrap();
        // 写明文 jpg 到 resolve_image 的完整图候选路径 (decrypt_dat 认 Plain, 不需 key)。
        let rel = &resolve_image(TALKER, ct, md5)[0].rel_path;
        let p = tmp.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4]).unwrap(); // jpg magic
                                                                      // image_key=None 也取到 (明文不需 key)。
        let img = fetch_image_one(&c, tmp.path(), None, TALKER, 88)
            .unwrap()
            .expect("命中明文图");
        assert_eq!(img.format, DatFormat::Jpg, "认出 jpg");
        assert_eq!(&img.bytes[..3], &[0xFF, 0xD8, 0xFF], "明文原样返回");
        // 不存在的 local_id → None; 非 32-hex talker → None。
        assert!(
            fetch_image_one(&c, tmp.path(), None, TALKER, 999).unwrap().is_none(),
            "无此消息 → None"
        );
        assert!(
            fetch_image_one(&c, tmp.path(), None, "xyz", 88).unwrap().is_none(),
            "非法 talker → None"
        );
    }

    /// `fetch_image_one` V2 完整图: **有 image key** → 解出原始明文; **无 key** → 该 V2 候选解不开 → None
    /// (盘上只有 _W.dat 一个 V2 文件, 无缩略图退路)。证 serve 有 cache key 才能出 V2 完整图。
    #[test]
    fn fetch_image_one_v2_needs_key() {
        use crate::decoder::dat::test_support::{fake_jpeg, make_v2};
        let md5 = "e3e751d84c3d0e81189b27d6a3d4dcad";
        let ct = 1_752_143_852_i64;
        let key = dummy_key();
        let plain = fake_jpeg(3000);
        let dat = make_v2(&plain, &key, 1024, 500); // 三段 AES-ECB + raw + XOR 封装
        let c = msg_db(&[(88, ct, packed_info(md5))]);
        let tmp = tempfile::tempdir().unwrap();
        // 只写完整图候选 _W.dat (V2), 不写缩略图 → 验"无 key 无退路时确实 None"。
        let rel = &resolve_image(TALKER, ct, md5)[0].rel_path;
        let p = tmp.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, &dat).unwrap();
        // 有 key → 解出完整图 = 原始明文。
        let img = fetch_image_one(&c, tmp.path(), Some(&key), TALKER, 88)
            .unwrap()
            .expect("有 key 解 V2 完整图");
        assert_eq!(img.format, DatFormat::Jpg, "认出 jpg");
        assert_eq!(img.bytes, plain, "V2 解出 = 原始明文 (端到端还原)");
        // 无 key → V2 候选解不开, 又无缩略图候选 → None。
        assert!(
            fetch_image_one(&c, tmp.path(), None, TALKER, 88).unwrap().is_none(),
            "无 key V2 解不开且无缩略图退路 → None"
        );
    }

    /// §8 审查修: (P1) 分片不含该会话表 → Ok(None) 非 Err (让 serve_image 续下一分片, 不误报 409);
    /// (P3) V2 用错 key 解成 Unknown 垃圾 → 跳过不返 (别把垃圾当图 200)。
    #[test]
    fn fetch_image_one_missing_table_and_wrong_key_skip() {
        use crate::decoder::dat::test_support::{fake_jpeg, make_v2};
        use crate::decoder::ImageKey;
        let tmp = tempfile::tempdir().unwrap();
        // P1: 空库 (无任何 Msg_ 表, 模拟非拥有分片) → Ok(None) 非 "no such table" Err。
        let empty = Connection::open_in_memory().unwrap();
        assert!(
            fetch_image_one(&empty, tmp.path(), None, TALKER, 88).unwrap().is_none(),
            "分片无该会话表 → Ok(None) 非 Err (P1)"
        );
        // P3: V2 .dat 用错 key → decrypt 成 Unknown 垃圾 → 跳过, 无缩略图退路 → None (不返垃圾字节)。
        let md5 = "e3e751d84c3d0e81189b27d6a3d4dcad";
        let ct = 1_752_143_852_i64;
        let dat = make_v2(&fake_jpeg(2000), &dummy_key(), 1024, 500);
        let c = msg_db(&[(88, ct, packed_info(md5))]);
        let rel = &resolve_image(TALKER, ct, md5)[0].rel_path;
        let p = tmp.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, &dat).unwrap();
        let wrong = ImageKey {
            aes: *b"0000000000000000",
            xor: 0x00,
        };
        assert!(
            fetch_image_one(&c, tmp.path(), Some(&wrong), TALKER, 88)
                .unwrap()
                .is_none(),
            "错 key V2 解成 Unknown → 跳过 → None (不返垃圾) (P3)"
        );
    }

    #[test]
    fn end_to_end_decrypt_and_write() {
        // 合成一张 V2 .dat 放进 account_dir 的正确路径, 跑 export_images → 落出真图字节。
        use crate::decoder::dat::test_support::{fake_jpeg, make_v2};
        use crate::decoder::{detect_format, DatFormat};
        let md5 = "e3e751d84c3d0e81189b27d6a3d4dcad";
        let create_time = 1_752_143_852_i64;
        let key = dummy_key();

        // 用真 fake JPEG 明文过一遍 V2 封装 (三段 AES-ECB + raw + XOR), 保证 decrypt_dat 能还原。
        let plain = fake_jpeg(3000);
        let dat = make_v2(&plain, &key, 1024, 500);

        let tmp = tempfile::tempdir().unwrap();
        // 月份按本地时区算 → 用 resolve_image 得到的路径, 保证 export 里探到。
        let rel = &resolve_image(TALKER, create_time, md5)[0].rel_path;
        let dat_path = tmp.path().join(rel);
        fs::create_dir_all(dat_path.parent().unwrap()).unwrap();
        fs::write(&dat_path, &dat).unwrap();

        let out = tmp.path().join("out");
        let c = msg_db(&[(88, create_time, packed_info(md5))]);
        let stats = export_images(&c, tmp.path(), &key, &out, None).unwrap();
        assert_eq!(stats.written, 1, "端到端解密落 1 张");
        assert_eq!(stats.missing, 0);

        let written = fs::read(out.join(format!("{TALKER}_88.{}", DatFormat::Jpg.ext()))).unwrap();
        assert_eq!(written, plain, "落盘字节 = 原始明文 (端到端还原)");
        assert_eq!(detect_format(&written), DatFormat::Jpg);
    }

    #[test]
    fn collect_v2_samples_walks_attach_dir() {
        // collect 直接扫 msg/attach 找 V2 (裸 <md5>.dat), 跳 V0 缩略图, 去重, 满 want 即停。
        use crate::decoder::dat::test_support::{fake_jpeg, make_v2};
        let key = dummy_key();
        let v2a = make_v2(&fake_jpeg(3000), &key, 1024, 500);
        let v2b = make_v2(&fake_jpeg(2000), &key, 512, 300); // 内容不同于 v2a
                                                             // V0 缩略图 = 明文 JPEG 整体单字节 XOR (头 2c0b2c.. 非 V2 magic → is_v2_dat_head 跳过, 不整读)。
        let v0_thumb: Vec<u8> = fake_jpeg(800).iter().map(|&b| b ^ 0xD3).collect();

        let tmp = tempfile::tempdir().unwrap();
        let img_dir = tmp
            .path()
            .join("msg")
            .join("attach")
            .join("000abc")
            .join("2024-09")
            .join("Img");
        fs::create_dir_all(&img_dir).unwrap();
        fs::write(img_dir.join("aaaa.dat"), &v2a).unwrap(); // V2 完整图
        fs::write(img_dir.join("bbbb.dat"), &v2b).unwrap(); // V2 完整图 (不同)
        fs::write(img_dir.join("aaaa_W.dat"), &v0_thumb).unwrap(); // V0 缩略图 → 不收
        fs::write(img_dir.join("dup.dat"), &v2a).unwrap(); // 同 v2a 内容 → 去重

        let samples = collect_v2_samples(tmp.path(), 6);
        assert_eq!(samples.len(), 2, "收 2 张互不相同 V2 (V0 缩略图跳过 + 重复去重)");
        for s in &samples {
            assert_eq!(detect_version(s), DatVersion::V2, "收的都是 V2");
        }
        assert_eq!(collect_v2_samples(tmp.path(), 1).len(), 1, "满 want=1 即停");
        assert!(collect_v2_samples(tmp.path(), 0).is_empty(), "want=0 → 空");
        let empty = tempfile::tempdir().unwrap();
        assert!(collect_v2_samples(empty.path(), 6).is_empty(), "无 attach → 空");
    }

    #[test]
    fn export_full_images_all_types_skip_thumbs() {
        // 扫盘导出全分辨率图: V2 + V0-JPEG全图 + V0-XOR-WXGF(动图) + 明文 都解; **只跳 `_t` 缩略图**。
        use crate::decoder::dat::test_support::{fake_jpeg, make_v2};
        let key = dummy_key();
        let v2_jpg = make_v2(&fake_jpeg(3000), &key, 1024, 500); // V2 JPEG 完整图
        let mut wxgf_plain = b"wxgf\x12\x00\x02\x07".to_vec(); // 0x12 动图
        wxgf_plain.extend(std::iter::repeat(0x5a).take(2000));
        let v2_wxgf = make_v2(&wxgf_plain, &key, 512, 300); // V2 wxgf
        let v0_jpg_full: Vec<u8> = fake_jpeg(2000).iter().map(|&b| b ^ 0xD3).collect(); // V0-JPEG 全图 (_W)
        let v0_xor_wxgf: Vec<u8> = wxgf_plain.iter().map(|&b| b ^ 0xD3).collect(); // **XOR 式 WXGF (漏解 bug)**
        let v0_thumb: Vec<u8> = fake_jpeg(400).iter().map(|&b| b ^ 0xD3).collect(); // 缩略图

        let tmp = tempfile::tempdir().unwrap();
        let img_dir = tmp
            .path()
            .join("msg")
            .join("attach")
            .join("000abc")
            .join("2024-09")
            .join("Img");
        fs::create_dir_all(&img_dir).unwrap();
        fs::write(img_dir.join("aaaa.dat"), &v2_jpg).unwrap();
        fs::write(img_dir.join("bbbb.dat"), &v2_wxgf).unwrap();
        fs::write(img_dir.join("cccc_W.dat"), &v0_jpg_full).unwrap(); // 全图 V0-JPEG → 收 (不是 _t)
        fs::write(img_dir.join("dddd_W.dat"), &v0_xor_wxgf).unwrap(); // XOR-WXGF 动图 → 收 (bug 修点)
        fs::write(img_dir.join("eeee_t_W.dat"), &v0_thumb).unwrap(); // _t 缩略图 → 跳

        let out = tmp.path().join("out");
        let stats = export_full_images(tmp.path(), &key, &out, None);
        assert_eq!(stats.scanned, 4, "扫 4 张非缩略 (跳 _t_W)");
        assert_eq!(stats.written, 2, "V2-JPEG + V0-JPEG全图 落图");
        assert_eq!(stats.wxgf, 2, "V2-wxgf + XOR-WXGF 都落 .wxgf (含之前漏的 XOR 式)");
        assert!(out.join("aaaa.jpg").is_file());
        assert!(out.join("cccc_W.jpg").is_file(), "V0-JPEG 全图不再被漏");
        assert!(out.join("dddd_W.wxgf").is_file(), "XOR 式 WXGF 不再被漏 (bug 修)");
        assert!(!out.join("eeee_t_W.jpg").exists(), "_t 缩略图跳过");
        // limit 按 scanned。
        let s2 = export_full_images(tmp.path(), &key, &tmp.path().join("out2"), Some(2));
        assert_eq!(s2.scanned, 2, "limit=2 只扫 2 张");
    }

    #[test]
    fn wxgf_inner_written_as_wxgf_counted_separately() {
        // V2 .dat 解密后内层是 wxgf 动图容器 → 落 .wxgf (待 ffmpeg 转码), 计 stats.wxgf 非 written。
        use crate::decoder::dat::test_support::make_v2;
        let md5 = "e3e751d84c3d0e81189b27d6a3d4dcad";
        let create_time = 1_752_143_852_i64;
        let key = dummy_key();
        let mut plain = b"wxgf\x13\x00\x02\x07".to_vec(); // 明文以 wxgf magic 开头 (模拟动图内层)
        plain.extend(std::iter::repeat(0x5a).take(3000));
        let dat = make_v2(&plain, &key, 1024, 500);

        let tmp = tempfile::tempdir().unwrap();
        let dat_path = tmp.path().join(&resolve_image(TALKER, create_time, md5)[0].rel_path);
        fs::create_dir_all(dat_path.parent().unwrap()).unwrap();
        fs::write(&dat_path, &dat).unwrap();

        let out = tmp.path().join("out");
        let c = msg_db(&[(88, create_time, packed_info(md5))]);
        let stats = export_images(&c, tmp.path(), &key, &out, None).unwrap();
        assert_eq!(stats.wxgf, 1, "wxgf 动图计 stats.wxgf");
        assert_eq!(stats.written, 0, "wxgf 不计 written (非直接可看的图)");
        assert_eq!(stats.failed, 0, "wxgf 不算失败");
        let wf = out.join(format!("{TALKER}_88.wxgf"));
        assert!(wf.is_file(), "落 .wxgf 文件");
        assert_eq!(
            fs::read(&wf).unwrap(),
            plain,
            "落盘 = 解出的 wxgf 字节 (原样保留待转码)"
        );
    }

    #[test]
    fn export_sns_cache_only_scans_sns_img() {
        // 朋友圈缓存扫盘: 扫 cache/<月>/Sns/Img/** 的 V2 (无扩展名 hash 文件); 跳 Temp / 非 Sns 目录 (ADR-489)。
        use crate::decoder::dat::test_support::{fake_jpeg, make_v2};
        let key = dummy_key();
        let v2a = make_v2(&fake_jpeg(2000), &key, 512, 300);
        let v2b = make_v2(&fake_jpeg(1500), &key, 512, 300);

        let tmp = tempfile::tempdir().unwrap();
        // 两个月的 Sns/Img (含 2-hex 前缀子目录, 文件名 = hash 无扩展名)。
        let img1 = tmp.path().join("2026-06").join("Sns").join("Img").join("01");
        let img2 = tmp.path().join("2026-05").join("Sns").join("Img").join("ab");
        fs::create_dir_all(&img1).unwrap();
        fs::create_dir_all(&img2).unwrap();
        fs::write(img1.join("200daa36443fc2327b6d2e99818a36"), &v2a).unwrap();
        fs::write(img2.join("28e44197576be952cdfb81639800af"), &v2b).unwrap();
        // 不该扫的: Sns/Temp 临时目录 + 非 Sns 的 Other 目录。
        let sns_temp = tmp.path().join("2026-06").join("Sns").join("Temp");
        let other = tmp.path().join("2026-06").join("Other");
        fs::create_dir_all(&sns_temp).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::write(sns_temp.join("t1"), &v2a).unwrap();
        fs::write(other.join("x1"), &v2b).unwrap();

        let out = tmp.path().join("out");
        let stats = export_sns_cache_images(tmp.path(), &key, &out, None);
        assert_eq!(stats.scanned, 2, "只扫 Sns/Img 下 2 文件 (跳 Temp/Other)");
        assert_eq!(stats.written, 2, "两张 V2 JPEG 解密落图");
        assert_eq!(stats.failed, 0);
        assert!(
            out.join("200daa36443fc2327b6d2e99818a36.jpg").is_file(),
            "hash 名 + .jpg 落盘"
        );
        assert!(out.join("28e44197576be952cdfb81639800af.jpg").is_file());
        // limit 按 scanned。
        let s2 = export_sns_cache_images(tmp.path(), &key, &tmp.path().join("out2"), Some(1));
        assert_eq!(s2.scanned, 1, "limit=1 只扫 1 张");
    }

    #[test]
    fn unknown_format_counts_failed_not_written() {
        // codex P1: V2 .dat 解出来不是图 (非 magic 明文, 如 key 错) → 算 failed, 不写垃圾 .bin。
        use crate::decoder::dat::test_support::make_v2;
        let md5 = "e3e751d84c3d0e81189b27d6a3d4dcad";
        let create_time = 1_752_143_852_i64;
        let key = dummy_key();
        // 明文全 0x00 (无图 magic) → decrypt_dat Ok 但 format=Unknown。
        let non_image = vec![0u8; 3000];
        let dat = make_v2(&non_image, &key, 1024, 500);

        let tmp = tempfile::tempdir().unwrap();
        let dat_path = tmp.path().join(&resolve_image(TALKER, create_time, md5)[0].rel_path);
        fs::create_dir_all(dat_path.parent().unwrap()).unwrap();
        fs::write(&dat_path, &dat).unwrap();

        let out = tmp.path().join("out");
        let c = msg_db(&[(88, create_time, packed_info(md5))]);
        let stats = export_images(&c, tmp.path(), &key, &out, None).unwrap();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.failed, 1, "Unknown 格式 → failed");
        assert_eq!(stats.written, 0, "不写 .bin 垃圾");
        // 确认没落任何文件。
        assert!(!out.join(format!("{TALKER}_88.bin")).exists(), "不该写 .bin");
    }
}
