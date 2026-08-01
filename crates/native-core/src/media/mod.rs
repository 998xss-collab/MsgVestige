//! media — 媒体导出 (CLI 侧, 非 raw_payload emit; ADR-421 §3.5).
//!
//! alpha 范围 (ADR-421 §3.1):
//! - 图片 .dat → .jpg 解 XOR (V1/V2/wxgf) — 待后续子件 (从 poc-1-2-media-placeholder 迁).
//! - 视频 .mp4 走 hardlink_db 取明文, 不解密 (实测 2009 文件 1104 明文/905 加密降级).
//!
//! PR2-13-a: 视频明文/加密判定 (文件名 _raw 主判 + mdat NAL H.264/H.265, ADR-421 §3.3) — 纯逻辑。
//! PR2-13-b: 视频 hardlink 解析 (resolve_video — md5 查 hardlink_db 得真实路径, ADR-421 §3.2)。

pub mod emoticon;
pub mod image_export;
pub mod image_resolve;
pub mod resolve;
pub mod sns_media;
/// 媒体子进程有界执行 (超时 kill + stdout 上限); wxgf(ffmpeg) + sns_media(node) 共用。crate 内部。
pub(crate) mod subprocess;
pub mod video_detect;
pub mod video_export;
pub mod voice_export;
pub mod wxgf;

pub use emoticon::{decrypt_emoticon, read_emoticon_one, read_emoticons, EmoticonRef};
pub use image_export::{
    collect_v2_samples, export_full_images, export_images, export_sns_cache_images, fetch_image_one,
    fetch_image_one_located, ImageExportStats,
};
pub use image_resolve::{resolve_image, ImageLocation, ImageVariant};
pub use resolve::{resolve_video, VideoLocation};
pub use sns_media::{
    build_download_url, decrypt_sns_media, read_sns_media_ref_one, read_sns_media_refs, sns_keystream, SnsMediaError,
    SnsMediaRef,
};
pub use subprocess::{output_with_timeout, status_with_timeout};
pub use video_detect::{classify_video, VideoKind, VIDEO_HEAD_LEN};
pub use video_export::{export_videos, locate_video_by_md5, VideoExportStats};
pub use voice_export::{export_voices, fetch_voice_wav, VoiceExportStats};
pub use wxgf::{resolve_ffmpeg, resolve_ffprobe, transcode_wxgf_bytes, wxgf_frame_count};
