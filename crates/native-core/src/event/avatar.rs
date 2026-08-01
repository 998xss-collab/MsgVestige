//! event::avatar — (avatar_image_update, create) 事件字段集. 微信头像图
//! (head_image.db `head_image` 表) 一条 = 一个联系人/群的当前头像图 (原始 JPEG/PNG bytes)。
//!
//! 照 [`super::emoticon::CustomEmoticonCreate`] 模板 (head_image.db 专表 → alpha 事件; ADR-481)。
//! **真库坐实** (2026-07-07 inspect head_image 17935 行 4 列): username (联系人/群 id) /
//! md5 (头像内容 md5 = 身份) / image_buffer (BLOB, 原始图 bytes, 100% 非空 avg 5KB/max 42KB) /
//! update_time。照抄竞品 chatlog (v4 GetAvatar) / WeChatMsg (head_image.py PNG) / WeLive (head-images)。
//!
//! ## content_digest (canonical.rs avatar 臂)
//! username_sha (联系人身份) + md5 (头像内容哈希) — 2 元。**md5 变 = 换了头像 → 新 fingerprint =
//! 头像变更史**。image_buffer (图 bytes) / update_time 只进 L2。
//!
//! ## K-R4 红线
//! - **不 derive `Serialize`**; **手写 `Debug`** — username (联系人 wxid) sha8; image_buffer 只露字节长度;
//!   md5 直露 (内容哈希非 PII)。

use std::fmt;

use serde_json::{Map, Value};

use super::privacy::{render_field, FieldCategory, PrivacyMode};
use super::provenance::Provenance;
use crate::key_provider::sha8;

/// (avatar_image_update, create) 事件字段集 — 一个联系人/群的当前头像图 (head_image.db `head_image`)。
///
/// `source_native_id` = `"Avatar_<username_sha256>"` (永不含裸 wxid; 一联系人一当前头像行)。
pub struct AvatarImageCreate {
    /// 共享溯源头 7 字段.
    pub provenance: Provenance,

    /// 联系人/群 id (`username`; wxid_/gh_/@chatroom; id 类; 进 digest 走 sha; Debug sha8)。
    pub username: String,
    /// 头像内容 md5 (`md5`; 身份 + 变更锚; 内容哈希非 PII; 进 digest 直露)。
    pub md5: String,
    /// 原始头像图 bytes (`image_buffer` BLOB; JPEG/PNG; **只进 L2**, Debug 只露字节长度)。
    pub image_buffer: Vec<u8>,
    /// 头像更新时刻秒 (`update_time`; 元数据; 只进 L2)。
    pub update_time: i64,
}

impl AvatarImageCreate {
    /// 渲染整条 avatar_image_update.create 的 payload_json (唯一出口)。
    ///
    /// md5 (内容哈希非 PII) + username (id 类, 按 mode sha/明文) 进 payload; image_buffer (图 bytes) /
    /// update_time **只进 L2 不进 payload** (bytes 冗余 + 头像换了 payload 会陈旧, 同头像 URL 先例)。
    #[must_use]
    pub fn to_payload_json(&self, mode: PrivacyMode) -> Value {
        let mut out = Map::new();
        self.provenance.render_into(&mut out, mode);
        // username = id 类 (走唯一脱敏关口: 默认 username_sha, 明文 username); md5 = 内容哈希非 PII 直塞。
        render_field(&mut out, "username", &self.username, FieldCategory::Id, mode);
        out.insert("md5".to_string(), Value::from(self.md5.as_str()));
        Value::Object(out)
    }
}

/// 手写 Debug (K-R4): username (联系人 wxid) sha8; image_buffer 只露字节长度; md5 直露 (非 PII); provenance 自遮。
impl fmt::Debug for AvatarImageCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvatarImageCreate")
            .field("provenance", &self.provenance)
            .field("username_sha8", &sha8(self.username.as_bytes()))
            .field("md5", &self.md5)
            .field("image_buffer_len", &self.image_buffer.len())
            .field("update_time", &self.update_time)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EventAction, EventType};
    use super::*;
    use crate::key_provider::Wxid;

    fn sample() -> AvatarImageCreate {
        AvatarImageCreate {
            provenance: Provenance {
                account_id: Wxid::try_new("wxid_acct_001").unwrap(),
                source: "head_image.db".to_string(),
                source_native_id: "Avatar_9f2b7c...".to_string(),
                event_type: EventType::AvatarImageUpdate,
                event_action: EventAction::Create,
                event_seq: 3,
                ingest_time: 1_700_000_000_000,
            },
            username: "wxid_friend_001".to_string(),
            md5: "a1b2c3d4e5f60718".to_string(),
            image_buffer: vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10], // JPEG 头样例
            update_time: 1_752_000_000,
        }
    }

    /// payload (明文 archive canonical): username/md5 出; image_buffer/update_time 不出 (只进 L2)。
    #[test]
    fn payload_omits_bytes_and_update_time() {
        let ev = sample();
        let v = ev.to_payload_json(PrivacyMode::archive_canonical());
        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("md5").unwrap(), "a1b2c3d4e5f60718");
        assert_eq!(obj.get("username").unwrap(), "wxid_friend_001");
        assert!(obj.get("image_buffer").is_none(), "图 bytes 不进 payload");
        assert!(obj.get("update_time").is_none(), "update_time 只进 L2");
    }

    /// 默认 sha 模式: username 走 username_sha (不裸 wxid, 无裸 username 键)。
    #[test]
    fn payload_sha_mode_hashes_username() {
        let ev = sample();
        let v = ev.to_payload_json(PrivacyMode::default_sha());
        let obj = v.as_object().unwrap();
        assert!(obj.get("username").is_none(), "sha 模式无裸 username 键");
        assert!(obj.get("username_sha").is_some(), "sha 模式走 username_sha");
        assert_ne!(
            obj.get("username_sha").unwrap(),
            "wxid_friend_001",
            "username_sha 不裸露 wxid"
        );
    }

    /// K-R4: Debug 不含裸 username / 不含图 bytes (只露长度)。
    #[test]
    fn debug_redacts_username_and_bytes() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("wxid_friend_001"), "Debug 不裸 username");
        assert!(dbg.contains("username_sha8"), "username 走 sha8");
        assert!(dbg.contains("image_buffer_len"), "图 bytes 只露长度");
        assert!(dbg.contains("md5"), "md5 直露 (非 PII)");
    }
}
