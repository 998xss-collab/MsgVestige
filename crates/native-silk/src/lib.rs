//! native-silk — 微信语音 SILK v3 解码 (件 1)。
//!
//! 微信语音消息 (msg_type=34) 的音频存在 `media_0.db` 的 `VoiceInfo.voice_data` BLOB,
//! 编码 = **微信变体 SILK v3**: 标准 `#!SILK_V3` 魔数前多一个 `0x02` 字节, 24kHz mono。
//! 本 crate 把这段字节解成 PCM (`i16`, 24kHz mono), 供上层 (件 2) 封装成 WAV / MP3。
//!
//! ## 实现
//! vendored Skype SILK SDK C 源码 (`silk/`, BSD-3-Clause, 见 `silk/VENDOR.md`), `build.rs` 用 `cc`
//! 编成静态库链接 + **手写 FFI** (下方 `extern` 块; 刻意不用 bindgen 免 libclang, 可移植性更优)。
//! 运行期零新增依赖 (C 静态进产物, 实测依赖 ⊆ msgvestige-adapter); 编译期只需 C 编译器 (项目编
//! rusqlite bundled SQLite 已需 MSVC; Linux/Mac 由 `cc` 自动选 gcc/clang)。
//!
//! ## 为何不用纯 Rust
//! 现存纯 Rust "SILK" 库解的都是 **Opus 容器内 SILK** (上限 16kHz, 与独立 SILK v3 比特流不兼容,
//! 无微信要的 24kHz super-wideband 档); 自研完整独立 SILK v3 解码器 4-8 人周。故 vendored C 是正解
//! (业界事实标准 `kn007/silk-v3-decoder` 3.2k★ 同源)。

#![allow(unsafe_code)] // 本 crate = Skype SILK SDK C 库的 FFI 封装, extern "C" + 调用必须 unsafe (同 native-keyscan/native-sqlcipher 的 FFI)。

use std::os::raw::{c_int, c_void};

/// 微信语音固定采样率 (Hz)。
pub const SAMPLE_RATE_HZ: u32 = 24000;

/// 每帧样本缓冲上限。**安全不变量** (双审 P2 坐实): `decode_silk` 固定 `api_sample_rate=24000` →
/// C 每次 `Decode` 输出 ≤ `MAX_FRAME_LENGTH` = 20ms×24kHz = **480 样本** (SKP_Silk_define.h), 远 < 2048。
/// C 把 `n_samples_out` 当**纯输出** (不读传入容量), 靠此不变量 + 下方 `got.min(FRAME_BUF)` clamp 双重保证不越界。
/// ⚠️ 将来若改 `api_sample_rate` (如 48000, resample 路径写 ≤960) 需重核此边界 (仍 < 2048 但推理变)。
const FRAME_BUF: usize = 2048;

/// SILK 解码错误。
#[derive(Debug, thiserror::Error)]
pub enum SilkError {
    /// 数据头不是 SILK v3 (缺 `#!SILK_V3` 魔数)。
    #[error("非 SILK v3 数据 (缺 #!SILK_V3 魔数)")]
    NotSilk,
    /// 解码未产出任何样本 (空 / 坏数据)。
    #[error("SILK 解码产出 0 样本")]
    Empty,
}

// ── FFI: Skype SILK SDK decode API (SKP_Silk_SDK_API.h / SKP_Silk_control.h) ──

/// `SKP_SILK_SDK_DecControlStruct` (5×i32; API_sampleRate 是输入, 其余是解码器输出状态)。
#[repr(C)]
struct DecControl {
    api_sample_rate: i32,
    frame_size: i32,
    frames_per_packet: i32,
    more_internal_decoder_frames: i32,
    in_band_fec_offset: i32,
}

extern "C" {
    fn SKP_Silk_SDK_Get_Decoder_Size(dec_size: *mut i32) -> c_int;
    fn SKP_Silk_SDK_InitDecoder(dec_state: *mut c_void) -> c_int;
    fn SKP_Silk_SDK_Decode(
        dec_state: *mut c_void,
        dec_control: *mut DecControl,
        lost_flag: c_int,
        in_data: *const u8,
        n_bytes_in: c_int,
        samples_out: *mut i16,
        n_samples_out: *mut i16,
    ) -> c_int;
}

/// SILK v3 标准魔数。
const SILK_MAGIC: &[u8] = b"#!SILK_V3";

/// 解码结束方式 (归档严格模式判据)。**微信 SILK 流正常以字节耗尽结束** (无显式结束标记, 参考实现
/// `kn007/silk-v3-decoder` 亦 `while fread==1 && nBytes>0`), 故 [`SilkExit::Complete`] = while 读到字节
/// 末尾自然结束; 其余均为异常早退 (损坏 / 截断)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SilkExit {
    /// packet 流读到字节末尾自然结束 (无早退) — 完整。
    Complete,
    /// 遇 0 / 负长度 packet 提前停 (微信正常流无此标记, 视为损坏)。
    ZeroLenPacket,
    /// 声明的 payload 长度超过剩余字节 (数据被截断) 提前停。
    TruncatedPayload,
}

/// 解码报告: 结束方式 + 中途解码失败计数 + 字节消费进度。归档路径据 [`DecodeReport::is_complete`] 判可信。
#[derive(Debug, Clone, Copy)]
pub struct DecodeReport {
    /// packet 流如何结束。
    pub exit: SilkExit,
    /// 中途 `SKP_Silk_SDK_Decode` 返回非 0 (该 packet 剩余帧被跳过) 的次数。
    pub decode_errors: u32,
    /// 已消费字节数 (含头)。
    pub bytes_consumed: usize,
    /// 总字节数。
    pub total_bytes: usize,
}

impl DecodeReport {
    /// 是否完整、干净解码 (归档可信): 字节走完 ([`SilkExit::Complete`]) + 无中途解码失败 + 无残留字节。
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.exit == SilkExit::Complete && self.decode_errors == 0 && self.bytes_consumed == self.total_bytes
    }
}

/// 把微信 `voice_data` (SILK v3 字节) 解成 PCM, 附带完整性报告 ([`DecodeReport`])。
///
/// 剥头 (微信变体前导 `0x02` + `#!SILK_V3`; 或标准 `#!SILK_V3`) → 逐 packet (2 字节 LE 长度 + payload)
/// 逐内部帧 `SKP_Silk_SDK_Decode`。**best-effort** 解 (中途失败 / 截断保留已解部分), 但 [`DecodeReport`]
/// 如实报告是否完整 —— **归档路径应查 [`DecodeReport::is_complete`]**, 不完整时别当归档成功
/// (BUG-2: 避免把半截语音导成"结构合法的短音频", 绕过导一个查一个)。头不对 → [`SilkError::NotSilk`];
/// 全程 0 样本 → [`SilkError::Empty`]。**不 panic** (坏 / 截断靠 `get` 边界检查安全退出)。
///
/// # Errors
/// [`SilkError::NotSilk`] (缺魔数) / [`SilkError::Empty`] (解出 0 样本)。
pub fn decode_silk_report(data: &[u8]) -> Result<(Vec<i16>, DecodeReport), SilkError> {
    // 剥头: 微信变体 = 0x02 + 魔数; 标准 = 魔数。
    let start = if data.first() == Some(&0x02) && data.get(1..).is_some_and(|d| d.starts_with(SILK_MAGIC)) {
        1 + SILK_MAGIC.len()
    } else if data.starts_with(SILK_MAGIC) {
        SILK_MAGIC.len()
    } else {
        return Err(SilkError::NotSilk);
    };

    let mut pos = start;
    let mut pcm = Vec::new();
    let mut exit = SilkExit::Complete; // 默认: while 自然结束 = 完整; 早退时下方改写。
    let mut decode_errors = 0u32;

    // SAFETY: 调 Skype SILK SDK。dec_state 按 SDK 返回的 size 分配、全程有效; payload 是 data 的合法子切片
    // (get 边界检查); samples_out 是栈上固定 FRAME_BUF 缓冲, n_samples_out 传入上限、SDK 写回实际数 (下方 clamp)。
    unsafe {
        let mut dec_size = 0i32;
        SKP_Silk_SDK_Get_Decoder_Size(&mut dec_size);
        if dec_size <= 0 {
            return Err(SilkError::Empty);
        }
        let mut state = vec![0u8; dec_size as usize];
        SKP_Silk_SDK_InitDecoder(state.as_mut_ptr().cast::<c_void>());

        let mut ctrl = DecControl {
            api_sample_rate: SAMPLE_RATE_HZ as i32,
            frame_size: 0,
            frames_per_packet: 0,
            more_internal_decoder_frames: 0,
            in_band_fec_offset: 0,
        };

        // 每 packet: 2 字节 LE payload 长度 (取不到 = 读完, while 自然结束 = Complete)。
        while let Some(len_bytes) = data.get(pos..pos + 2) {
            let n_bytes = i16::from_le_bytes([len_bytes[0], len_bytes[1]]);
            if n_bytes <= 0 {
                exit = SilkExit::ZeroLenPacket; // 未把这 2 字节计入消费 (损坏标记)
                break;
            }
            let n = n_bytes as usize;
            let Some(payload) = data.get(pos + 2..pos + 2 + n) else {
                exit = SilkExit::TruncatedPayload; // payload 不足, 未消费此 packet
                break;
            };
            pos += 2 + n;

            // packet 内可能多个内部帧: 循环至 more_internal_decoder_frames == 0。
            loop {
                let mut frame = [0i16; FRAME_BUF];
                let mut n_samples = FRAME_BUF as i16;
                let ret = SKP_Silk_SDK_Decode(
                    state.as_mut_ptr().cast::<c_void>(),
                    &mut ctrl,
                    0,
                    payload.as_ptr(),
                    n_bytes as c_int,
                    frame.as_mut_ptr(),
                    &mut n_samples,
                );
                if ret != 0 {
                    decode_errors += 1; // best-effort: 跳过该 packet 剩余帧, 继续下个 packet (但记为不完整)
                    break;
                }
                let got = (n_samples.max(0) as usize).min(FRAME_BUF);
                pcm.extend_from_slice(&frame[..got]);
                if ctrl.more_internal_decoder_frames == 0 {
                    break;
                }
            }
        }
    }

    if pcm.is_empty() {
        return Err(SilkError::Empty);
    }
    let report = DecodeReport {
        exit,
        decode_errors,
        bytes_consumed: pos,
        total_bytes: data.len(),
    };
    Ok((pcm, report))
}

/// 把微信 `voice_data` 解成 PCM (best-effort 预览; **丢弃完整性报告**)。归档场景改用 [`decode_silk_report`]
/// 并查 [`DecodeReport::is_complete`]。头不对 → [`SilkError::NotSilk`]; 0 样本 → [`SilkError::Empty`]。
///
/// # Errors
/// [`SilkError::NotSilk`] / [`SilkError::Empty`]。
pub fn decode_silk(data: &[u8]) -> Result<Vec<i16>, SilkError> {
    decode_silk_report(data).map(|(pcm, _report)| pcm)
}

/// PCM (`i16` mono) → WAV 字节 (16-bit PCM 单声道)。**零依赖** (纯拼 44 字节 header + 小端样本)。
/// 供件 2 把 [`decode_silk`] 的 PCM 落成可播放 `.wav` (MP3 另经 ffmpeg 外部转, cli 层)。
#[must_use]
pub fn pcm_to_wav(pcm: &[i16], sample_rate: u32) -> Vec<u8> {
    let data_len = (pcm.len() * 2) as u32;
    let mut w = Vec::with_capacity(44 + data_len as usize);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&(36 + data_len).to_le_bytes()); // 整文件 - 8
    w.extend_from_slice(b"WAVE");
    w.extend_from_slice(b"fmt ");
    w.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk 大小
    w.extend_from_slice(&1u16.to_le_bytes()); // 格式 = PCM
    w.extend_from_slice(&1u16.to_le_bytes()); // 声道 = mono
    w.extend_from_slice(&sample_rate.to_le_bytes());
    w.extend_from_slice(&(sample_rate * 2).to_le_bytes()); // byte rate = rate × block_align
    w.extend_from_slice(&2u16.to_le_bytes()); // block align = mono×16bit = 2
    w.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    w.extend_from_slice(b"data");
    w.extend_from_slice(&data_len.to_le_bytes());
    for s in pcm {
        w.extend_from_slice(&s.to_le_bytes());
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真微信语音样本 (media_0.db/VoiceInfo.voice_data 一条, 2003 字节, 头 `02` + `#!SILK_V3`)。
    const REAL_SAMPLE: &[u8] = include_bytes!("../tests/fixtures/wechat_voice_sample.silk");

    /// 端到端: 真样本解出合理 PCM (~1s @ 24kHz)。
    #[test]
    fn decode_real_wechat_sample() {
        let pcm = decode_silk(REAL_SAMPLE).expect("真样本应解码成功");
        // 2003 字节 SILK ≈ 1.1s 语音 ≈ 26400 样本 @ 24kHz。宽松断言 (> 半秒)。
        assert!(pcm.len() > 12000, "解出样本数 {} 太少 (真跑 ~26400)", pcm.len());
        let secs = pcm.len() as f64 / f64::from(SAMPLE_RATE_HZ);
        assert!((0.5..5.0).contains(&secs), "时长 {secs:.2}s 不合理");
    }

    /// BUG-2: 真样本 (完整语音) → is_complete()==true (Complete + 0 errors + 无残留字节)。
    #[test]
    fn report_complete_on_real_sample() {
        let (pcm, rep) = decode_silk_report(REAL_SAMPLE).expect("真样本应解码");
        assert!(!pcm.is_empty());
        assert_eq!(rep.exit, SilkExit::Complete, "真样本以字节耗尽自然结束");
        assert_eq!(rep.decode_errors, 0);
        assert_eq!(rep.bytes_consumed, rep.total_bytes, "无残留字节");
        assert!(rep.is_complete(), "真样本完整");
    }

    /// BUG-2: 真样本 + 尾随截断 packet (长度头声称 0x7FFF 但无 payload) → 解出部分 PCM 但 is_complete()==false。
    #[test]
    fn report_incomplete_on_trailing_truncated_packet() {
        let mut data = REAL_SAMPLE.to_vec();
        data.extend_from_slice(&[0xFF, 0x7F]); // 声称 32767 字节 payload, 实际 0 → TruncatedPayload
        let (pcm, rep) = decode_silk_report(&data).expect("真样本部分仍解出");
        assert!(!pcm.is_empty(), "已解出真样本 PCM");
        assert_eq!(rep.exit, SilkExit::TruncatedPayload, "尾随 packet 截断");
        assert!(!rep.is_complete(), "不完整 → 归档不可信");
    }

    /// 微信变体头 (0x02 前导) 正确剥离。
    #[test]
    fn wechat_variant_header_stripped() {
        assert_eq!(REAL_SAMPLE[0], 0x02, "真样本是微信变体 (0x02 前导)");
        assert_eq!(&REAL_SAMPLE[1..10], SILK_MAGIC, "0x02 后是标准魔数");
        assert!(decode_silk(REAL_SAMPLE).is_ok(), "能解 = 头正确剥离");
    }

    /// 标准 SILK 头 (剥掉 0x02) 也认 (兼容非微信 SILK)。
    #[test]
    fn standard_silk_header_accepted() {
        let standard = &REAL_SAMPLE[1..];
        assert_eq!(&standard[..9], SILK_MAGIC);
        assert!(decode_silk(standard).is_ok(), "标准 SILK 头 (无 0x02) 也应解");
    }

    /// 非 SILK 数据 → NotSilk, 不 panic。
    #[test]
    fn non_silk_rejected() {
        assert!(matches!(
            decode_silk(b"not a silk file at all"),
            Err(SilkError::NotSilk)
        ));
        assert!(matches!(decode_silk(&[]), Err(SilkError::NotSilk)));
        assert!(matches!(decode_silk(&[0x02, 0x00, 0x01]), Err(SilkError::NotSilk)));
    }

    /// 截断数据 (头 + 半 packet) 不 panic (Ok 部分 / Empty 均可)。
    #[test]
    fn truncated_no_panic() {
        let _ = decode_silk(&REAL_SAMPLE[..50]);
        let _ = decode_silk(&REAL_SAMPLE[..12]); // 刚好头后就断
    }

    /// 双审 P3: 有效头 + 长度声称超过剩余字节 → 走 payload 截断 break, 不 panic。
    #[test]
    fn header_then_oversized_length_claim() {
        let mut data = REAL_SAMPLE[..10].to_vec(); // 微信头 (0x02 + #!SILK_V3)
        data.extend_from_slice(&[0xFF, 0x7F]); // 长度=0x7FFF=32767, 但后面无字节 → get(pos..pos+n)=None → break
        let _ = decode_silk(&data); // 不 panic (截断 break → Empty)
    }

    /// 双审 P3: 奇数尾字节 (剩 1 字节, 读不出 2 字节长度) → while let 自然退出, 不 panic。
    #[test]
    fn odd_trailing_byte_natural_exit() {
        let mut data = REAL_SAMPLE[..10].to_vec(); // 头
        data.push(0x00); // 剩 1 字节 → get(pos..pos+2)=None → while 退出
        let _ = decode_silk(&data); // 不 panic
    }

    /// pcm_to_wav: header 结构正确 (RIFF/WAVE/data + 长度 + 采样率)。
    #[test]
    fn wav_header_correct() {
        let pcm = vec![0i16, 100, -100, 32767, -32768];
        let wav = pcm_to_wav(&pcm, 24000);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[36..40], b"data");
        assert_eq!(wav.len(), 44 + pcm.len() * 2, "44 header + 5×2 data");
        assert_eq!(
            u32::from_le_bytes([wav[40], wav[41], wav[42], wav[43]]) as usize,
            pcm.len() * 2,
            "data 长度"
        );
        assert_eq!(
            u32::from_le_bytes([wav[24], wav[25], wav[26], wav[27]]),
            24000,
            "采样率"
        );
    }

    /// 端到端: 真样本 decode → wav (RIFF 头 + 长度自洽)。
    #[test]
    fn decode_then_wav() {
        let pcm = decode_silk(REAL_SAMPLE).unwrap();
        let wav = pcm_to_wav(&pcm, SAMPLE_RATE_HZ);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(wav.len(), 44 + pcm.len() * 2);
    }
}
