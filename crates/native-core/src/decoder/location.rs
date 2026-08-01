//! decoder::location — 从位置消息 (local_type=48) 的 `<location>` XML 抽经纬度/地点 (ADR-462)。
//!
//! 位置消息 content 是 `<msg><location x=".." y=".." label=".." poiname=".." poiid=".." .../></msg>`。
//! `x`=纬度(lat) / `y`=经度(lng) / `label`=地址串 / `poiname`=地点名 / `poiid`=腾讯地图 POI id。
//! 抽成结构化字段 → 派生 L2 表 message_location (同行 chatlog/WeFlow/wechat-decrypt 都有位置字段)。
//! **纯字符串抽属性, infallible** (返 Option: 非位置消息 / 无坐标 → None)。
//!
//! ## K-R4 (位置是敏感 PII)
//! lat/lng/poiname/label/poiid 精确定位用户 → [`LocationCard`] Debug 走 sha8 脱敏 (poiname/label/poiid)
//! + lat/lng 只留**两位小数**粗化 (不出精确坐标)。L2 落库仍明文 (ADR-427 全程明文)。

use std::fmt;

use super::media::{attr_i64, extract_attr, open_tag_body};
use crate::key_provider::sha8;

/// 位置消息 local_type (WeChat 4.x localType 低 32 位主类型)。
const MSG_TYPE_LOCATION: i32 = 48;

/// 从位置 XML 抽出的字段。
#[derive(Clone, PartialEq)]
pub struct LocationCard {
    /// 纬度 (`x`, 北纬正)。
    pub latitude: f64,
    /// 经度 (`y`, 东经正)。
    pub longitude: f64,
    /// 地图缩放级别 (`scale`; 未知 0)。
    pub scale: i64,
    /// 地址串 (`label`; 可空)。
    pub label: Option<String>,
    /// 地点名 (`poiname`; 可空)。
    pub poiname: Option<String>,
    /// 腾讯地图 POI id (`poiid`; 可空)。
    pub poiid: Option<String>,
    /// 地图类型 (`maptype`; 未知 0; 三档小补丁 ADR-479, 照 chatlog mediamessage.go:113)。
    pub maptype: i64,
    /// 行政区划码 (`adcode`; 6 位数字; 可空)。
    pub adcode: Option<String>,
    /// 城市名 (`cityname`; 可空)。
    pub cityname: Option<String>,
}

/// 从消息 content (位置 XML) 抽位置字段。非位置 msg_type (48) → None; 有 `<location>` 但缺经纬度
/// (损坏/占位) → None。**infallible**。
#[must_use]
pub fn parse_location(msg_type: i32, content: &str) -> Option<LocationCard> {
    if msg_type != MSG_TYPE_LOCATION {
        return None;
    }
    let attrs = open_tag_body(content, "location")?;
    // 经纬度是位置的核心 — 缺任一即视为损坏/占位, 不落。
    let latitude: f64 = extract_attr(attrs, "x").and_then(|s| s.parse().ok())?;
    let longitude: f64 = extract_attr(attrs, "y").and_then(|s| s.parse().ok())?;
    // 坐标合理性 (挡 NaN/Inf/超范围脏数据)。
    if !latitude.is_finite() || !longitude.is_finite() {
        return None;
    }
    if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
        return None;
    }
    Some(LocationCard {
        latitude,
        longitude,
        scale: attr_i64(attrs, "scale"),
        label: extract_attr(attrs, "label"),
        poiname: extract_attr(attrs, "poiname"),
        poiid: extract_attr(attrs, "poiid"),
        maptype: attr_i64(attrs, "maptype"),
        adcode: extract_attr(attrs, "adcode"),
        cityname: extract_attr(attrs, "cityname"),
    })
}

/// K-R4: 位置敏感 → Debug 脱敏。poiname/label/poiid → sha8; lat/lng 只留两位小数 (粗化, 不出精确坐标)。
impl fmt::Debug for LocationCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = |v: &Option<String>| v.as_deref().map(|s| sha8(s.as_bytes()));
        f.debug_struct("LocationCard")
            .field("lat~", &format!("{:.2}", self.latitude))
            .field("lng~", &format!("{:.2}", self.longitude))
            .field("scale", &self.scale)
            .field("label_sha8", &o(&self.label))
            .field("poiname_sha8", &o(&self.poiname))
            .field("poiid_sha8", &o(&self.poiid))
            .field("maptype", &self.maptype)
            .field("adcode", &self.adcode)
            .field("cityname", &self.cityname)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOC: &str = r#"<?xml version="1.0"?><msg><location x="28.386938" y="121.395126" scale="15" label="浙江省台州市黄岩区中科路" maptype="0" poiname="台州万达广场" poiid="qqmap_3200835909041289207" poiPhone="0576-86998989" /></msg>"#;

    #[test]
    fn parse_full_location() {
        let l = parse_location(48, LOC).unwrap();
        assert!((l.latitude - 28.386_938).abs() < 1e-6);
        assert!((l.longitude - 121.395_126).abs() < 1e-6);
        assert_eq!(l.scale, 15);
        assert_eq!(l.label.as_deref(), Some("浙江省台州市黄岩区中科路"));
        assert_eq!(l.poiname.as_deref(), Some("台州万达广场"));
        assert_eq!(l.poiid.as_deref(), Some("qqmap_3200835909041289207"));
    }

    #[test]
    fn non_location_type_none() {
        assert!(parse_location(1, LOC).is_none(), "文本 type 1 → None");
        assert!(parse_location(49, LOC).is_none(), "appmsg type 49 → None");
        assert!(
            parse_location(48, "<msg></msg>").is_none(),
            "type 48 但无 <location> → None"
        );
    }

    #[test]
    fn missing_coords_none() {
        assert!(
            parse_location(48, r#"<msg><location scale="15" label="x" /></msg>"#).is_none(),
            "无 x/y → None"
        );
        assert!(
            parse_location(48, r#"<msg><location x="28.0" /></msg>"#).is_none(),
            "只有 x 缺 y → None"
        );
    }

    #[test]
    fn out_of_range_coords_none() {
        assert!(
            parse_location(48, r#"<msg><location x="200.0" y="10.0" /></msg>"#).is_none(),
            "纬度超范围 → None"
        );
        assert!(
            parse_location(48, r#"<msg><location x="10.0" y="999.0" /></msg>"#).is_none(),
            "经度超范围 → None"
        );
    }

    #[test]
    fn optional_fields_absent() {
        // 只有坐标, 无 label/poiname/poiid → 仍落 (核心是坐标)。
        let l = parse_location(48, r#"<msg><location x="0.0" y="0.0" /></msg>"#).unwrap();
        assert!(l.latitude.abs() < 1e-9 && l.longitude.abs() < 1e-9, "坐标解析为 0");
        assert!(l.label.is_none() && l.poiname.is_none() && l.poiid.is_none());
        assert_eq!(l.scale, 0);
    }

    #[test]
    fn k_r4_debug_redacts() {
        let dbg = format!("{:?}", parse_location(48, LOC).unwrap());
        for raw in ["台州万达广场", "浙江省台州市黄岩区中科路", "qqmap_3200835909041289207"] {
            assert!(!dbg.contains(raw), "K-R4: LocationCard Debug 泄裸值 {raw}");
        }
        assert!(!dbg.contains("28.386938"), "K-R4: 精确纬度不出");
        assert!(dbg.contains("28.39"), "粗化两位小数");
        assert!(dbg.contains("poiname_sha8"));
    }
}
