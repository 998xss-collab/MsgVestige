//! 语音导出 (件 2, ADR-465) — 遍历 media_0.db `VoiceInfo` → SILK 解码 → WAV 落盘。
//!
//! 视频/图片要"消息 → md5 → hardlink/packed_info → 找磁盘文件"多步定位; 语音**数据直接在
//! `media_0.db` 的 `VoiceInfo.voice_data` BLOB** (微信变体 SILK v3, 24kHz mono), 一步到位:
//! 读 BLOB → [`decode_silk_report`] → [`pcm_to_wav`] → 落 `voice_<svr_id>.wav`。
//! `media_conn` = **已解密**的 media_0.db (生产经 cipher 解密; 调研/验证用 staging 解密副本)。best-effort;
//! 解出但**不完整**的语音 (截断/中途坏) 落 `.partial.wav` 并单独计数, 不当归档成功 (BUG-2)。

use std::fs;
use std::path::Path;

use native_silk::{decode_silk_report, pcm_to_wav, SAMPLE_RATE_HZ};
use rusqlite::{Connection, OptionalExtension};

/// 语音导出统计。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct VoiceExportStats {
    /// 扫到的 `VoiceInfo` 行数。
    pub scanned: usize,
    /// **完整**解码 (`is_complete`) + 落盘的干净 `voice_<svr_id>.wav` 数。
    pub exported: usize,
    /// 解出但**不完整** (截断 / SDK 中途失败 / 残留字节) → 落 `voice_<svr_id>.partial.wav` 供预览,
    /// **不当归档成功** (BUG-2: 别把半截语音静默计成功、绕过导一个查一个)。
    pub partial: usize,
    /// 解码失败 (非 SILK / 空 / 坏) 或写盘失败, 跳过不中断整批。
    pub failed: usize,
}

/// 枚举 media_0.db 里所有 `VoiceInfo%` 语音表 (按名排序)。**微信语音量大时把 `VoiceInfo` 分表**成
/// `VoiceInfo` / `VoiceInfo1` / … / `VoiceInfoN`(竞品 CipherTalk/WeLive 均以 `LIKE 'VoiceInfo%'` 自适应探测)。
/// 只读单表 `VoiceInfo` 会**漏掉分表里的语音 = 丢数据**, 故取用/导出都必须枚举全部分表。真库实测小库为单表,
/// 但大历史库会分表 → 必须枚举, 不能赌单表。
///
/// # Errors
/// rusqlite 查询失败 (sqlite_master 读不到 / 库坏)。
fn voice_info_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'VoiceInfo%' ORDER BY name")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names)
}

/// 遍历 `media_conn` (已解密 media_0.db) **全部 `VoiceInfo%` 分表** → `decode_silk` → `pcm_to_wav` → 落
/// `voice_<svr_id>.wav`。`limit` = 最多**导出**多少条 (`None` 全部)。返回统计; 仅 db 级错误 `Err`。
///
/// # Errors
/// rusqlite 查询失败 (表缺 / 库坏)。
pub fn export_voices(
    media_conn: &Connection,
    out_dir: &Path,
    limit: Option<usize>,
) -> rusqlite::Result<VoiceExportStats> {
    let mut stats = VoiceExportStats::default();
    let _ = fs::create_dir_all(out_dir); // 尽力建; 失败留给 write 报 → failed。

    // 枚举全部 VoiceInfo% 分表 (只读单表会漏分表语音 = 丢数据)。
    for table in voice_info_tables(media_conn)? {
        let mut stmt = media_conn.prepare(&format!(
            "SELECT svr_id, voice_data FROM \"{table}\" WHERE voice_data IS NOT NULL ORDER BY create_time"
        ))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;

        for row in rows {
            if limit.is_some_and(|l| stats.exported >= l) {
                return Ok(stats); // 达 limit 提前停 (统计为截断前缀)
            }
            let (svr_id, blob) = row?;
            stats.scanned += 1;
            // decode_silk_report best-effort: 非 SILK / 空 / 坏 → Err → 计 failed 跳过 (不中断整批);
            // Ok 附完整性报告 (BUG-2: 据此分 完整=exported / 不完整=partial, 不静默当成功)。
            let Ok((pcm, report)) = decode_silk_report(&blob) else {
                stats.failed += 1;
                continue;
            };
            let wav = pcm_to_wav(&pcm, SAMPLE_RATE_HZ);
            // svr_id = 服务器消息 id (跨分表全局唯一) → 命名 voice_<svr_id>.wav。**行级不分片**: 真库
            // distinct svr_id=行数 (1:1) · data_index 恒 '0' (字段存在但未启用行级分片, 每条一行完整数据) ·
            // svr_id 无 0/NULL。故按 svr_id 命名不撞不丢片。(**表级**分表 VoiceInfoN 由外层枚举覆盖。)
            // BUG-2: 完整 → voice_<svr_id>.wav 计 exported; 不完整 (截断/中途坏) → voice_<svr_id>.partial.wav
            // 供预览、计 partial (明确标名, 不混入干净归档, 不当归档成功)。
            let complete = report.is_complete();
            let name = if complete {
                format!("voice_{svr_id}.wav")
            } else {
                format!("voice_{svr_id}.partial.wav")
            };
            if fs::write(out_dir.join(name), &wav).is_ok() {
                if complete {
                    stats.exported += 1;
                } else {
                    stats.partial += 1;
                }
            } else {
                stats.failed += 1;
            }
        }
    }
    Ok(stats)
}

/// 单条取语音 → WAV 字节 (serve `/media/voice:<svr_id>` 按需取用)。按 `svr_id` 查**全部 `VoiceInfo%` 分表**
/// (svr_id 跨分表全局唯一 1:1, 见 [`voice_info_tables`]/[`export_voices`] 注释), 解微信变体 SILK v3 → PCM → WAV。
/// **必须枚举分表**: 只查单表 `VoiceInfo` 会漏掉大库分表 `VoiceInfoN` 里的语音 = 丢数据。
///
/// 各分表都无此 svr_id / `voice_data` 为 NULL → `Ok(None)` (handler 映 404); 命中但解码失败 (非 SILK / 空 /
/// 坏) → `Ok(None)` (best-effort, 同批量导出计 `failed` 的处置; svr_id 唯一故不再查其它分表)。**截断/不完整
/// 仍返回已解出的 WAV** —— on-demand 单件取用容忍半截 (能放就放), 区别于 [`export_voices`] 批量归档把不完整落
/// `.partial.wav` 单列 (那是归档完整性口径)。
///
/// # Errors
/// rusqlite 查询失败 (sqlite_master / 分表读不到 / 库坏)。
pub fn fetch_voice_wav(media_conn: &Connection, svr_id: i64) -> rusqlite::Result<Option<Vec<u8>>> {
    for table in voice_info_tables(media_conn)? {
        let blob: Option<Vec<u8>> = media_conn
            .query_row(
                &format!("SELECT voice_data FROM \"{table}\" WHERE svr_id = ?1 AND voice_data IS NOT NULL"),
                [svr_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(blob) = blob else { continue }; // 此分表无 → 查下一分表
                                                 // 命中: best-effort 解 (非 SILK / 空 / 坏 → None; 完整或截断都取已解出的 PCM, 预览容忍半截)。
                                                 // svr_id 跨分表唯一 → 命中即定, 解不出也不再翻其它分表。
        let Ok((pcm, _report)) = decode_silk_report(&blob) else {
            return Ok(None);
        };
        return Ok(Some(pcm_to_wav(&pcm, SAMPLE_RATE_HZ)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真微信语音样本 (同 native-silk fixture)。
    const REAL_SAMPLE: &[u8] = include_bytes!("../../../native-silk/tests/fixtures/wechat_voice_sample.silk");

    fn voice_db(rows: &[(i64, &[u8])]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE VoiceInfo(chat_name_id INTEGER, create_time INTEGER, local_id INTEGER, \
             svr_id INTEGER, voice_data BLOB, data_index TEXT DEFAULT '0');",
        )
        .unwrap();
        for (i, (svr, blob)) in rows.iter().enumerate() {
            conn.execute(
                "INSERT INTO VoiceInfo(create_time, svr_id, voice_data) VALUES (?1, ?2, ?3)",
                rusqlite::params![i as i64, svr, blob.to_vec()],
            )
            .unwrap();
        }
        conn
    }

    /// 端到端: 真样本导出 .wav + 坏 blob 计 failed 不中断。
    #[test]
    fn export_real_and_bad() {
        let conn = voice_db(&[(12345, REAL_SAMPLE), (67890, b"not silk")]);
        let tmp = std::env::temp_dir().join("nsilk_voice_test_a");
        let _ = fs::remove_dir_all(&tmp);
        let stats = export_voices(&conn, &tmp, None).unwrap();
        assert_eq!(stats.scanned, 2);
        assert_eq!(stats.exported, 1, "真样本导出");
        assert_eq!(stats.failed, 1, "坏 blob 计 failed 不中断");
        let wav = fs::read(tmp.join("voice_12345.wav")).unwrap();
        assert_eq!(&wav[0..4], b"RIFF", "WAV 头");
        let _ = fs::remove_dir_all(&tmp);
    }

    /// limit 截断: 只导 N 条。
    #[test]
    fn limit_truncates() {
        let conn = voice_db(&[(1001, REAL_SAMPLE), (1002, REAL_SAMPLE), (1003, REAL_SAMPLE)]);
        let tmp = std::env::temp_dir().join("nsilk_voice_test_b");
        let _ = fs::remove_dir_all(&tmp);
        let stats = export_voices(&conn, &tmp, Some(2)).unwrap();
        assert_eq!(stats.exported, 2, "limit=2 只导 2");
        let _ = fs::remove_dir_all(&tmp);
    }

    /// BUG-2: 不完整语音 (真样本 + 尾随截断 packet) → 计 partial + 落 `.partial.wav`, **不当归档成功**。
    #[test]
    fn incomplete_voice_counted_partial_not_exported() {
        // 真样本 (完整) 后接一个长度头声称 0x7FFF 但无 payload 的截断 packet → 解出真样本 PCM 但 exit=TruncatedPayload。
        let mut blob = REAL_SAMPLE.to_vec();
        blob.extend_from_slice(&[0xFF, 0x7F]);
        let conn = voice_db(&[(555, &blob)]);
        let tmp = std::env::temp_dir().join("nsilk_voice_test_partial");
        let _ = fs::remove_dir_all(&tmp);
        let stats = export_voices(&conn, &tmp, None).unwrap();
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.exported, 0, "不完整不当归档成功");
        assert_eq!(stats.partial, 1, "不完整计 partial");
        assert_eq!(stats.failed, 0);
        assert!(
            tmp.join("voice_555.partial.wav").is_file(),
            "落 .partial.wav (供预览, 明确标名)"
        );
        assert!(!tmp.join("voice_555.wav").exists(), "不落干净归档名");
        let _ = fs::remove_dir_all(&tmp);
    }

    /// 双审 P3: 同 svr_id 多行 → 后写覆盖 (真库实证 svr_id 唯一, 不会发生; 此测钉住命名契约,
    /// 防将来微信改行级分片时静默丢数据 —— 届时该红灯并改按 data_index 聚合)。
    #[test]
    fn duplicate_svr_id_last_write_wins() {
        let conn = voice_db(&[(999, REAL_SAMPLE), (999, REAL_SAMPLE)]); // 人造同 svr_id (真库不会有)
        let tmp = std::env::temp_dir().join("nsilk_voice_test_dup");
        let _ = fs::remove_dir_all(&tmp);
        let stats = export_voices(&conn, &tmp, None).unwrap();
        assert_eq!(stats.scanned, 2, "扫 2 行");
        assert_eq!(stats.exported, 2, "两行都各自解码+写 (第 2 次覆盖同名)");
        // 同 svr_id → 同文件名 → 只剩 1 文件 (后写覆盖)。真库 svr_id 唯一故不撞; 此断言固化行为。
        let n = fs::read_dir(&tmp).unwrap().count();
        assert_eq!(n, 1, "同 svr_id 后写覆盖 → 只剩 1 文件");
        let _ = fs::remove_dir_all(&tmp);
    }

    /// `fetch_voice_wav` (serve 单件): 命中 svr_id → Some(WAV, RIFF 头); svr_id 不存在 → None;
    /// 坏 blob → None (best-effort, 不 Err 中断)。
    #[test]
    fn fetch_voice_wav_by_svr_id() {
        let conn = voice_db(&[(12345, REAL_SAMPLE), (67890, b"not silk")]);
        let wav = fetch_voice_wav(&conn, 12345).unwrap().expect("命中 svr_id → Some");
        assert_eq!(&wav[0..4], b"RIFF", "WAV 头");
        assert!(
            fetch_voice_wav(&conn, 99999).unwrap().is_none(),
            "svr_id 不存在 → None (404)"
        );
        assert!(
            fetch_voice_wav(&conn, 67890).unwrap().is_none(),
            "坏 blob → None (best-effort)"
        );
    }

    /// **表级分表** (VoiceInfo + VoiceInfo1): 枚举两分表; fetch 取得到分表里的 svr_id; export 导全部分表并集。
    /// 回归防线: 只读单表 `VoiceInfo` 会漏 `VoiceInfo1` 的语音 = 丢数据 (大历史库会分表)。
    #[test]
    fn sharded_voiceinfo_tables_all_covered() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE VoiceInfo(create_time INTEGER, svr_id INTEGER, voice_data BLOB);\
             CREATE TABLE VoiceInfo1(create_time INTEGER, svr_id INTEGER, voice_data BLOB);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO VoiceInfo(create_time, svr_id, voice_data) VALUES (1, 111, ?1)",
            rusqlite::params![REAL_SAMPLE.to_vec()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO VoiceInfo1(create_time, svr_id, voice_data) VALUES (2, 222, ?1)",
            rusqlite::params![REAL_SAMPLE.to_vec()],
        )
        .unwrap();
        assert_eq!(
            voice_info_tables(&conn).unwrap(),
            vec!["VoiceInfo", "VoiceInfo1"],
            "枚举两分表"
        );
        // fetch: 单表 + 分表的 svr_id 都取得到 (不漏)。
        assert!(fetch_voice_wav(&conn, 111).unwrap().is_some(), "取 VoiceInfo 的");
        assert!(
            fetch_voice_wav(&conn, 222).unwrap().is_some(),
            "取分表 VoiceInfo1 的 (不漏分表)"
        );
        assert!(fetch_voice_wav(&conn, 999).unwrap().is_none(), "两分表都无 → None");
        // export: 两分表并集全导。
        let tmp = std::env::temp_dir().join("nsilk_voice_sharded");
        let _ = fs::remove_dir_all(&tmp);
        let stats = export_voices(&conn, &tmp, None).unwrap();
        assert_eq!(stats.exported, 2, "两分表各 1 条都导 (不漏分表)");
        assert!(tmp.join("voice_111.wav").is_file(), "VoiceInfo 的");
        assert!(
            tmp.join("voice_222.wav").is_file(),
            "分表 VoiceInfo1 的也导出 (回归: 曾会漏)"
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}
