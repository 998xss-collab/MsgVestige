//! 视频批量导出 (ADR-421 §3, PR2-13-c) — 遍历 message db 视频消息 → hardlink 定位 → 明文拷贝 / 加密降级。
//!
//! 串起 PR2-13-a/b: 视频消息 (local_type=43) 的 `message_content` (zstd) 解压 → `<videomsg md5=..>` 取
//! **md5**(hardlink 连接键, ADR-421 §184 实测命中最多) → [`resolve_video`](super::resolve::resolve_video)
//! (md5 查 hardlink_db 得候选路径) → 逐候选探 FS 读头 → [`classify_video`](super::video_detect::classify_video)
//! 判明文/加密 → **明文拷贝 .mp4 / 加密降级**(不解密; 微信视频加密无账号级 key, 明文那份靠转码缓存)。
//!
//! **跟图片的关键区别**: ①视频**不解密**(明文文件直接拷, 加密文件跳过降级) ②定位靠**独立 hardlink_db**
//! (需另传解密的 hardlink 库 conn), 非 packed_info 直算 ③md5 来自 zstd 解压的 content XML, 非 packed_info。
//!
//! **best-effort** (ADR-421 媒体口径): 单条定位不到 / 读失败 / 拷失败都不中断, 只累计 [`VideoExportStats`];
//! 仅 db 级错误 (表损坏 / SQL 失败) 才 `Err`。

use std::fs;
use std::io::Read;
use std::path::Path;

use rusqlite::Connection;

use super::image_export::msg_content_tables;
use super::resolve::resolve_video;
use super::video_detect::{classify_video, VideoKind, VIDEO_HEAD_LEN};
use crate::decoder::{decode_message_content, parse_media};

/// 视频消息的 `local_type` (ADR-421 §184; 微信 4.x)。
const LOCAL_TYPE_VIDEO: i64 = 43;

/// 导出统计 (best-effort: 单条失败不中断)。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VideoExportStats {
    /// 扫到的视频消息数 (local_type=43 且从 content 取出 md5)。
    pub scanned: usize,
    /// 明文视频成功拷出。
    pub plaintext: usize,
    /// 定位到文件但**加密降级** (`_raw` 原始版 / 非raw 但内容加密; 不解密, 提示"微信里播一次后或可导出")。
    pub encrypted: usize,
    /// md5 不在 hardlink / hardlink 命中但盘上无文件 (微信已清理)。
    pub missing: usize,
    /// 探测 / 拷贝遇真 IO 错 (权限 / 坏盘)。
    pub failed: usize,
}

/// 遍历 `msg_conn` 里所有 `Msg_<32hex>` 表的视频消息 (local_type=43), 用 `hardlink_conn` 定位 → 明文拷贝 /
/// 加密降级。`limit` = 最多**拷出**多少明文视频 (None 全部)。返回统计; 仅 db 级错误 `Err`。
///
/// `hardlink_conn` = **已解密**的视频 hardlink 库 (`video_hardlink_info_v4` + `dir2id`; 生产经 cipher 解密)。
/// `account_dir` = xwechat_files 账号目录 (`msg/video/<月份>/` 所在)。
pub fn export_videos(
    msg_conn: &Connection,
    hardlink_conn: &Connection,
    account_dir: &Path,
    out_dir: &Path,
    limit: Option<usize>,
) -> rusqlite::Result<VideoExportStats> {
    let mut stats = VideoExportStats::default();
    let _ = fs::create_dir_all(out_dir); // 尽力建; 失败留给后面 copy 报 → failed。

    for table in msg_content_tables(msg_conn)? {
        let Some(talker) = table.strip_prefix("Msg_") else {
            continue;
        };
        if talker.len() != 32 || !talker.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }

        let sql = format!(
            "SELECT local_id, message_content FROM \"{table}\" \
             WHERE local_type = {LOCAL_TYPE_VIDEO} AND message_content IS NOT NULL"
        );
        let mut stmt = msg_conn.prepare(&sql)?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;

        for row in rows {
            if limit.is_some_and(|l| stats.plaintext >= l) {
                return Ok(stats);
            }
            let (local_id, content_blob) = row?;
            // content: zstd 解压 (坏帧 → 跳, best-effort) → parse_media 取视频 md5 (hardlink 连接键)。
            let Ok(content) = decode_message_content(&content_blob) else {
                continue;
            };
            let Some(md5) = parse_media(43, &content).and_then(|c| c.md5) else {
                continue; // 无 videomsg / 无 md5 → 跳 (占位/损坏)
            };
            stats.scanned += 1;

            // hardlink 定位候选 (非 _raw 明文优先排前); 逐候选探 FS + 分类, 取第一个存在且明文的拷出。
            let locs = resolve_video(hardlink_conn, &md5)?;
            classify_and_export(&locs, account_dir, out_dir, talker, local_id, &mut stats);
        }
    }
    Ok(stats)
}

/// 按视频**内容 md5** 定位**单个视频的明文文件路径** (HTTP `/media/vid:<md5>` 用; 视频不解密, 明文 .mp4 供
/// 文件级 Range 直接流)。`md5` = 冷投影 `message_media.md5` (hardlink 索引键) → [`resolve_video`] 得候选 → 逐候选
/// 探 FS + [`classify_video`], 取第一个**存在且明文**的路径。md5 不在 hardlink / 候选全加密 (`_raw`) 或已清理 → `Ok(None)`。
///
/// `hardlink_conn` = 已解密视频 hardlink 库; `account_dir` = xwechat_files 账号目录 (`msg/video/…` 所在)。
/// (md5-key 设计: md5 由 message_media 直接给, **视频不读 message 分片** —— 比 talker+local_id 少开 6 个 message 库。)
///
/// # Errors
/// rusqlite 查询失败 (hardlink 表异常等 db 级错误)。
pub fn locate_video_by_md5(
    hardlink_conn: &Connection,
    account_dir: &Path,
    md5: &str,
) -> rusqlite::Result<Option<std::path::PathBuf>> {
    // md5 由调用方 (handler parse) 校验 32-hex; resolve_video 内 file_name 有路径穿越守护, md5 是 SQL 绑定参数。
    for loc in resolve_video(hardlink_conn, md5)? {
        let p = account_dir.join(&loc.rel_path);
        if let Ok(Some(head)) = read_head(&p, VIDEO_HEAD_LEN) {
            if matches!(classify_video(&head), VideoKind::Plaintext) {
                return Ok(Some(p)); // 明文视频文件路径, HTTP 层文件级 Range 流
            }
        }
    }
    Ok(None)
}

/// 对一个视频 md5 的候选路径列表: 逐候选探 FS + `classify_video`, 取第一个**存在且明文**的拷出;
/// 有存在但全加密 → encrypted; 全不存在 → missing; 探/拷 IO 错 → failed。更新 `stats`。
fn classify_and_export(
    locs: &[super::resolve::VideoLocation],
    account_dir: &Path,
    out_dir: &Path,
    talker: &str,
    local_id: i64,
    stats: &mut VideoExportStats,
) {
    let mut saw_encrypted = false;
    let mut io_err = false; // 探测读失败 **或拷贝失败** = 真 IO 问题 (权限/坏盘/盘满); 优先于 encrypted 报 failed。
    for loc in locs {
        let p = account_dir.join(&loc.rel_path);
        match read_head(&p, VIDEO_HEAD_LEN) {
            Ok(Some(head)) => match classify_video(&head) {
                VideoKind::Plaintext => {
                    // 明文: 整文件拷出 (视频不解密, 明文文件本身可播)。命名 <talker>_<local_id>.mp4 防跨会话撞名。
                    let out = out_dir.join(format!("{talker}_{local_id}.mp4"));
                    match fs::copy(&p, &out) {
                        Ok(_) => {
                            stats.plaintext += 1;
                            return; // 拷出一个即够 (候选是同一视频的不同版本)
                        }
                        // codex P1: 拷失败别直接 return —— 记 IO 错继续试后续候选 (本候选可能瞬时不可读,
                        // 后面还有可用明文候选)。全候选都拷不出才在末尾计 failed。
                        Err(_) => io_err = true,
                    }
                }
                VideoKind::Encrypted => saw_encrypted = true, // 记下, 继续看有没有明文候选
            },
            Ok(None) => {} // 文件不存在 → 探下一候选
            Err(_) => io_err = true,
        }
    }
    // 没拷出任何明文。codex P1: 真 IO 错 (探测/拷贝失败) **优先**报 failed —— 别被 encrypted 吞掉权限/坏盘问题;
    // 无 IO 错但有加密候选 → 加密降级; 纯不存在 → missing。
    if io_err {
        stats.failed += 1;
    } else if saw_encrypted {
        stats.encrypted += 1;
    } else {
        stats.missing += 1;
    }
}

/// 读文件头至多 `max` 字节 (给 `classify_video` 判文件头 `ftyp` box)。文件不存在 → `Ok(None)`; 真 IO 错 → `Err`。
fn read_head(path: &Path, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    match fs::File::open(path) {
        Ok(f) => {
            let mut buf = Vec::new();
            // take(max): 读到 max 字节或 EOF (whichever first); 大视频只读头, 不整读。
            f.take(max as u64).read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TALKER: &str = "b3010f26cfa89d420c8d8183bb3d5f5b";
    const VMD5: &str = "41318a6159dd261d3f10a19d6bf72dd1"; // 命中下面 hardlink 的 md5

    /// zstd 压缩 videomsg content (md5=VMD5)。
    fn video_content() -> Vec<u8> {
        let xml = format!(
            r#"<msg><videomsg aeskey="d1c6" cdnvideourl="3057vid" length="936153" playlength="5" md5="{VMD5}" newmd5="dddddddddddddddddddddddddddddddd" /></msg>"#
        );
        zstd::stream::encode_all(xml.as_bytes(), 0).unwrap()
    }

    /// 建内存 message db, 插 Msg_<talker> 表 + 若干视频行 (local_type=43)。
    fn msg_db(rows: &[(i64, Vec<u8>)]) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(&format!(
            "CREATE TABLE \"Msg_{TALKER}\" (local_id INTEGER, local_type INTEGER, message_content BLOB);"
        ))
        .unwrap();
        for (lid, content) in rows {
            c.execute(
                &format!("INSERT INTO \"Msg_{TALKER}\" (local_id, local_type, message_content) VALUES (?1, 43, ?2)"),
                rusqlite::params![lid, content],
            )
            .unwrap();
        }
        c
    }

    /// 建内存 hardlink db: VMD5 → file_name(dir1=1→dir2id rowid 1=2024-09)。file_name 可控 (_raw 与否)。
    fn hardlink_db(file_name: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE dir2id (username TEXT);
             CREATE TABLE video_hardlink_info_v4 (md5 TEXT, file_name TEXT, dir1 INTEGER, dir2 INTEGER);",
        )
        .unwrap();
        c.execute("INSERT INTO dir2id (rowid, username) VALUES (1,'2024-09')", [])
            .unwrap();
        c.execute(
            "INSERT INTO video_hardlink_info_v4 (md5, file_name, dir1, dir2) VALUES (?1, ?2, 1, 0)",
            rusqlite::params![VMD5, file_name],
        )
        .unwrap();
        c
    }

    /// 造一个明文 mp4 头 (首盒 `ftyp`) — classify_video 判 Plaintext。
    fn plaintext_mp4() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&16u32.to_be_bytes());
        v.extend_from_slice(b"ftyp");
        v.extend_from_slice(b"isom\0\0\x02\0");
        v
    }

    /// 无 `ftyp` 首盒的字节 (随机/整体加密/损坏/非视频) — classify_video 判 Encrypted 降级。
    fn no_ftyp_bytes() -> Vec<u8> {
        vec![0x21, 0x11, 0x45, 0x00, 0x14, 0x50, 0x01, 0x46, 0xff, 0xf1, 0x00, 0x00]
    }

    #[test]
    fn empty_db_zero_stats() {
        let mc = Connection::open_in_memory().unwrap();
        let hc = hardlink_db("x.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let stats = export_videos(&mc, &hc, tmp.path(), &tmp.path().join("out"), None).unwrap();
        assert_eq!(stats, VideoExportStats::default());
    }

    #[test]
    fn video_msg_file_absent_counts_missing() {
        // 有视频消息 + md5 命中 hardlink, 但盘上无文件 → missing。
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("aaaa.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let stats = export_videos(&mc, &hc, tmp.path(), &tmp.path().join("out"), None).unwrap();
        assert_eq!(stats.scanned, 1, "扫到 1 条视频消息");
        assert_eq!(stats.missing, 1, "盘上无文件 → missing");
        assert_eq!(stats.plaintext, 0);
    }

    #[test]
    fn plaintext_video_copied() {
        // 明文视频 (文件头 ftyp 健全) → 拷出到 out_dir。
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("clip.mp4");
        let tmp = tempfile::tempdir().unwrap();
        // 放明文 mp4 到解析出的路径 msg/video/2024-09/clip.mp4。
        let vpath = tmp.path().join("msg").join("video").join("2024-09").join("clip.mp4");
        fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        fs::write(&vpath, plaintext_mp4()).unwrap();

        let out = tmp.path().join("out");
        let stats = export_videos(&mc, &hc, tmp.path(), &out, None).unwrap();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.plaintext, 1, "明文视频拷出");
        assert_eq!(stats.encrypted, 0);
        let copied = out.join(format!("{TALKER}_7.mp4"));
        assert!(copied.is_file(), "拷出文件存在");
        assert_eq!(fs::read(&copied).unwrap(), plaintext_mp4(), "拷出=原字节");
    }

    /// `locate_video_by_md5` (HTTP /media/vid:<md5>): md5 命中明文 → 文件路径; md5 不在 → None; 内容加密 → None。
    #[test]
    fn locate_video_by_md5_plaintext_hit_else_none() {
        let hc = hardlink_db("clip.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let vpath = tmp.path().join("msg").join("video").join("2024-09").join("clip.mp4");
        fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        // 明文 (ftyp 健全) → 返回该路径。
        fs::write(&vpath, plaintext_mp4()).unwrap();
        assert_eq!(
            locate_video_by_md5(&hc, tmp.path(), VMD5).unwrap(),
            Some(vpath.clone()),
            "md5 命中明文视频 → 文件路径"
        );
        // md5 不在 hardlink → None。
        assert!(
            locate_video_by_md5(&hc, tmp.path(), "ffffffffffffffffffffffffffffffff")
                .unwrap()
                .is_none(),
            "md5 不存在 → None"
        );
        // 内容加密 (无 ftyp 首盒) → None (视频不解密, 加密的给不了)。
        fs::write(&vpath, no_ftyp_bytes()).unwrap();
        assert!(
            locate_video_by_md5(&hc, tmp.path(), VMD5).unwrap().is_none(),
            "内容加密视频 → None (不解密)"
        );
    }

    #[test]
    fn raw_name_video_is_plaintext_copied() {
        // 真库推翻"_raw=加密": _raw 是原画命名非加密; 内容是合法 mp4 (ftyp) → 明文拷出 (不再按文件名降级)。
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("clip_raw.mp4"); // _raw 原画版
        let tmp = tempfile::tempdir().unwrap();
        let vpath = tmp
            .path()
            .join("msg")
            .join("video")
            .join("2024-09")
            .join("clip_raw.mp4");
        fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        fs::write(&vpath, plaintext_mp4()).unwrap();

        let out = tmp.path().join("out");
        let stats = export_videos(&mc, &hc, tmp.path(), &out, None).unwrap();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.plaintext, 1, "_raw 内容合法 mp4 → 明文拷出");
        assert_eq!(stats.encrypted, 0, "_raw 不再当加密");
        assert!(out.join(format!("{TALKER}_7.mp4")).is_file(), "拷出文件存在");
    }

    #[test]
    fn no_ftyp_header_downgraded_encrypted() {
        // 文件头非合法 mp4 (随机字节 / 整体加密 / 损坏) → encrypted 降级, 不拷 (避免导出乱码 .mp4)。
        let mc = msg_db(&[(7, video_content())]);
        let hc = hardlink_db("clip.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let vpath = tmp.path().join("msg").join("video").join("2024-09").join("clip.mp4");
        fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        fs::write(&vpath, no_ftyp_bytes()).unwrap(); // 无 ftyp 首盒

        let out = tmp.path().join("out");
        let stats = export_videos(&mc, &hc, tmp.path(), &out, None).unwrap();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.encrypted, 1, "无 ftyp 头 → 降级");
        assert_eq!(stats.plaintext, 0, "不拷非明文");
        assert!(!out.join(format!("{TALKER}_7.mp4")).exists(), "降级视频不落文件");
    }

    #[test]
    fn non_video_message_not_scanned() {
        // 非 43 (如文本) 不该被扫 (WHERE local_type=43 过滤)。造一条 local_type=1 的行。
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(&format!(
            "CREATE TABLE \"Msg_{TALKER}\" (local_id INTEGER, local_type INTEGER, message_content BLOB);"
        ))
        .unwrap();
        c.execute(
            &format!("INSERT INTO \"Msg_{TALKER}\" (local_id, local_type, message_content) VALUES (1, 1, ?1)"),
            rusqlite::params![video_content()],
        )
        .unwrap();
        let hc = hardlink_db("x.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let stats = export_videos(&c, &hc, tmp.path(), &tmp.path().join("out"), None).unwrap();
        assert_eq!(stats.scanned, 0, "非 43 不扫");
    }

    #[test]
    fn limit_caps_plaintext() {
        // limit=1: 两条明文视频只拷第一条。
        let mc = msg_db(&[(7, video_content()), (8, video_content())]);
        let hc = hardlink_db("clip.mp4");
        let tmp = tempfile::tempdir().unwrap();
        let vpath = tmp.path().join("msg").join("video").join("2024-09").join("clip.mp4");
        fs::create_dir_all(vpath.parent().unwrap()).unwrap();
        fs::write(&vpath, plaintext_mp4()).unwrap();
        let stats = export_videos(&mc, &hc, tmp.path(), &tmp.path().join("out"), Some(1)).unwrap();
        assert_eq!(stats.plaintext, 1, "limit=1 只拷 1 条");
    }
}
