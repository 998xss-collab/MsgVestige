//! 视频 hardlink 解析 (ADR-421 §3.2, PR2-13-b) — 从视频 md5 查 hardlink_db 得真实文件路径(候选)。
//!
//! hardlink_db schema (实测 staging 解密副本):
//! `video_hardlink_info_v4` (md5, file_name, dir1, dir2): md5 → 文件名 + dir1 (同 md5 可多行);
//! `dir2id` (username): rowid → 目录名; **dir1 查 dir2id rowid** 得月份目录 (如 "2023-01", dir2 没用);
//! 真实路径 = `<account>/msg/video/<月份>/<file_name>`。
//!
//! 输入已解密 hardlink_db conn (生产经 cipher.decrypt 解密 — alpha sidecar; 测试用 staging 解密副本)。
//! 跟 WeLive `hardlink-video` 同款机制 (04-welive.md §2.6)。
//!
//! 真实验证 (staging hardlink.db 全 7730 行, Claude r1 复核): 文件存在的路径 **月份 100% 对** (0 月份错);
//! 余下 5283 历史已删 + 598 行 dir1 指向非月份目录 (dir2id 混 username 哈希, 本函数 is_month_dir 跳过)。
//! resolve 纯 db 查不碰 FS — **文件存在性由 cli 层逐候选探**。
//!
//! 同 md5 多行 (实测 1240 个 md5 多行, 最多 106 行 — 历史重发 / `_raw`+解码兄弟):
//! 返回全部候选, **非 `_raw` (明文可导出) 排前, `_raw` (加密降级) 殿后**; cli 取第一个存在且明文的。

use rusqlite::{Connection, OptionalExtension};

use super::video_detect::is_raw_name;

/// 视频文件定位结果 (路径相对 account 目录)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoLocation {
    /// 实际文件名 (如 `xxx.mp4` 或 `xxx_raw.mp4`)。
    pub file_name: String,
    /// 月份目录 (如 `2023-01`)。
    pub month_dir: String,
    /// 相对 account 目录的路径 (`msg/video/<月份>/<file_name>`)。
    pub rel_path: String,
}

/// 月份目录格式校验 (`YYYY-MM`) — 挡掉 dir1 指向 dir2id 里非月份行 (username 哈希, 实测 598)。
fn is_month_dir(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 7 || b[4] != b'-' {
        return false;
    }
    if !b[..4].iter().all(u8::is_ascii_digit) || !b[5..].iter().all(u8::is_ascii_digit) {
        return false;
    }
    // 月份 01..=12 (挡 2023-99 / 0000-00 这种形状匹配但非法月份)。
    let mm = (b[5] - b'0') * 10 + (b[6] - b'0');
    (1..=12).contains(&mm)
}

/// 某表是否存在 (缺表健壮性: 直查缺表会 "no such table" 上抛被上层误映 409, 见 §8 P1/P2)。
fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false))
}

/// 从视频 md5 查 hardlink_db 得所有候选位置, 非 `_raw` (明文) 优先排序。
/// 空 Vec = md5 不存在 / 候选全被过滤 (dir1 无月份 / 文件名异常) / **hardlink.db 无该表** (从没发过视频的账号 /
/// 版本表名漂移)。调用方 (cli/serve) 逐候选探 FS, 据空判 404。
pub fn resolve_video(conn: &Connection, md5: &str) -> rusqlite::Result<Vec<VideoLocation>> {
    // §8 P2 (兄弟 bug, 同 image P1 根因): hardlink.db 可能不含 video_hardlink_info_v4 / dir2id 表 —— 直查会
    // rusqlite "no such table" 上抛, 被 serve_video/classify_error 误映 409 NeedsIngest (应 404)。缺表 → 空 Vec。
    if !table_exists(conn, "video_hardlink_info_v4")? || !table_exists(conn, "dir2id")? {
        return Ok(Vec::new());
    }
    // ORDER BY rowid: 同 md5 多行给确定序 (否则 SQLite 返回序无契约保证)。
    let mut stmt = conn.prepare("SELECT file_name, dir1 FROM video_hardlink_info_v4 WHERE md5 = ?1 ORDER BY rowid")?;
    let rows = stmt.query_map([md5], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;

    let mut out = Vec::new();
    for row in rows {
        let (file_name, dir1) = row?;
        // 防御: file_name 含路径分隔 / 穿越 → 跳过 (真实数据 0 例, 防未来脏数据穿越)。
        if file_name.contains('/') || file_name.contains('\\') || file_name.contains("..") {
            continue;
        }
        // dir1 → dir2id.rowid → 月份; dir1 指向非月份行 (实测 598) → 跳过, 不拼伪路径。
        let dir_name: Option<String> = conn
            .query_row("SELECT username FROM dir2id WHERE rowid = ?1", [dir1], |r| r.get(0))
            .optional()?;
        let Some(month_dir) = dir_name.filter(|d| is_month_dir(d)) else {
            continue;
        };
        let rel_path = format!("msg/video/{month_dir}/{file_name}");
        out.push(VideoLocation {
            file_name,
            month_dir,
            rel_path,
        });
    }
    // 同 md5 多候选: 非 `_raw` (压缩解码缓存) 优先, `_raw` (原画版) 殿后 —— 排序偏好, 非加密判据
    // (真库复核: 两者皆明文, 见 video_detect 模块头)。复用 is_raw_name (大小写不敏感); stable sort + ORDER BY rowid 保确定序。
    out.sort_by_key(|loc| is_raw_name(&loc.file_name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建内存 hardlink_db (video_hardlink_info_v4 + dir2id), 插实测样本。
    fn hardlink_db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE dir2id (username TEXT);
             CREATE TABLE video_hardlink_info_v4 (md5 TEXT, file_name TEXT, dir1 INTEGER, dir2 INTEGER);",
        )
        .unwrap();
        // dir2id rowid 1→2022-12, 2→2023-01, 3→2023-02; rowid 4 = 非月份 (username 哈希, 实测有这类)。
        c.execute(
            "INSERT INTO dir2id (rowid, username) VALUES
               (1,'2022-12'),(2,'2023-01'),(3,'2023-02'),(4,'0b198d3f9c8e7a6b5c4d')",
            [],
        )
        .unwrap();
        // 实测样本: md5=41318a.. → 90e5fef3.._raw.mp4 dir1=2(→2023-01); 0c4ebb.. → 0bf5f00..mp4。
        c.execute(
            "INSERT INTO video_hardlink_info_v4 (md5, file_name, dir1, dir2) VALUES
               ('41318a6159dd261d3f10a19d6bf72dd1', '90e5fef31e74b7c02aa8698abaa39663_raw.mp4', 2, 0),
               ('0c4ebb1e1e8cfd32da18dc0afdd2aadb', '0bf5f000efaaf3cfa0ba677166f4e007.mp4', 2, 0)",
            [],
        )
        .unwrap();
        c
    }

    /// §8 P2 (兄弟 bug): hardlink.db 缺 video_hardlink_info_v4 / dir2id 表 → Ok(空 Vec) 非 "no such table" Err
    /// (否则 serve_video 误映 409)。
    #[test]
    fn resolve_video_missing_table_returns_empty() {
        // 空库 (无任何表)。
        let empty = Connection::open_in_memory().unwrap();
        assert!(
            resolve_video(&empty, "41318a6159dd261d3f10a19d6bf72dd1")
                .unwrap()
                .is_empty(),
            "缺 video_hardlink_info_v4 → 空 Vec 非 Err"
        );
        // 有 v4 无 dir2id → 也空 (dir2id 查月份也会缺表)。
        let no_dir2 = Connection::open_in_memory().unwrap();
        no_dir2
            .execute_batch(
                "CREATE TABLE video_hardlink_info_v4 (md5 TEXT, file_name TEXT, dir1 INTEGER, dir2 INTEGER);",
            )
            .unwrap();
        assert!(
            resolve_video(&no_dir2, "41318a6159dd261d3f10a19d6bf72dd1")
                .unwrap()
                .is_empty(),
            "缺 dir2id → 空 Vec 非 Err"
        );
    }

    #[test]
    fn resolve_known_raw_md5() {
        let c = hardlink_db();
        let locs = resolve_video(&c, "41318a6159dd261d3f10a19d6bf72dd1").unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].month_dir, "2023-01"); // dir1=2 → dir2id rowid 2
        assert_eq!(
            locs[0].rel_path,
            "msg/video/2023-01/90e5fef31e74b7c02aa8698abaa39663_raw.mp4"
        );
    }

    #[test]
    fn resolve_known_nonraw_md5() {
        let c = hardlink_db();
        let locs = resolve_video(&c, "0c4ebb1e1e8cfd32da18dc0afdd2aadb").unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(
            locs[0].rel_path,
            "msg/video/2023-01/0bf5f000efaaf3cfa0ba677166f4e007.mp4"
        );
    }

    #[test]
    fn resolve_unknown_md5_empty() {
        let c = hardlink_db();
        assert!(resolve_video(&c, "deadbeefdeadbeef").unwrap().is_empty());
    }

    #[test]
    fn dup_md5_nonraw_first() {
        // 同 md5 两行: _raw (加密) + 非raw (明文). 明文应排前 (cli 优先探明文)。Claude r1 P1。
        let c = hardlink_db();
        c.execute(
            "INSERT INTO video_hardlink_info_v4 (md5, file_name, dir1, dir2) VALUES
               ('dupmd5', 'aaaa_raw.mp4', 2, 0),
               ('dupmd5', 'aaaa.mp4', 3, 0)",
            [],
        )
        .unwrap();
        let locs = resolve_video(&c, "dupmd5").unwrap();
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].file_name, "aaaa.mp4"); // 非raw 明文优先
        assert_eq!(locs[1].file_name, "aaaa_raw.mp4"); // _raw 殿后
    }

    #[test]
    fn is_month_dir_validates_range() {
        assert!(is_month_dir("2023-01"));
        assert!(is_month_dir("2023-12"));
        assert!(!is_month_dir("2023-13")); // 月份超范围 (codex r2)
        assert!(!is_month_dir("2023-00"));
        assert!(!is_month_dir("0b198d3f9c8e7a6b5c4d")); // username 哈希
        assert!(!is_month_dir("2023-1")); // 长度不对
    }

    #[test]
    fn dir1_non_month_skipped() {
        // dir1=4 → dir2id rowid 4 = 非月份 (username 哈希) → 跳过, 不拼伪路径。Claude r1 P0(598 行)。
        let c = hardlink_db();
        c.execute(
            "INSERT INTO video_hardlink_info_v4 (md5,file_name,dir1,dir2) VALUES ('hh','x.mp4',4,0)",
            [],
        )
        .unwrap();
        assert!(resolve_video(&c, "hh").unwrap().is_empty());
    }

    #[test]
    fn dir1_no_row_skipped() {
        // dir1=99 无对应 dir2id 行 → 跳过。
        let c = hardlink_db();
        c.execute(
            "INSERT INTO video_hardlink_info_v4 (md5,file_name,dir1,dir2) VALUES ('nn','y.mp4',99,0)",
            [],
        )
        .unwrap();
        assert!(resolve_video(&c, "nn").unwrap().is_empty());
    }

    #[test]
    fn filename_path_traversal_skipped() {
        // 防御: file_name 含路径穿越 → 跳过 (真实数据无, 防脏数据)。Claude r1 P2。
        let c = hardlink_db();
        c.execute(
            "INSERT INTO video_hardlink_info_v4 (md5,file_name,dir1,dir2) VALUES
               ('eviltrav', '../../etc/passwd', 2, 0),
               ('eviltrav', 'sub/dir/x.mp4', 2, 0)",
            [],
        )
        .unwrap();
        assert!(resolve_video(&c, "eviltrav").unwrap().is_empty());
    }
}
