use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct Preference {
    pub value: Value,
}
#[derive(Debug, Clone, Deserialize)]
pub struct PreferenceSaved {
    pub message: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct SetPreference {
    pub value: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tracking {
    pub opted_in: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub preferred_region: Option<String>,
    #[serde(default)]
    pub region_strict: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetVersionSetting {
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_versions: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionSettings {
    #[serde(default)]
    pub settings: Vec<VersionSetting>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionSetting {
    pub id: Option<String>,
    pub scope: String,
    pub target_id: Option<String>,
    pub enabled: bool,
    pub max_versions: Option<i32>,
    pub retention_days: Option<i32>,
    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SettingSaved {
    pub message: String,
}

pub fn preference(key: &str) -> Endpoint<(), Preference> {
    Endpoint::new(Method::Get, format!("/api/v1/preferences/{}", component(key)), false)
}
pub fn set_preference(key: &str) -> Endpoint<SetPreference, PreferenceSaved> {
    Endpoint::new(Method::Put, format!("/api/v1/preferences/{}", component(key)), true)
}
pub fn tracking() -> Endpoint<(), Tracking> {
    Endpoint::new(Method::Get, "/api/v1/me/tracking", false)
}
pub fn set_tracking() -> Endpoint<Tracking, Tracking> {
    Endpoint::new(Method::Put, "/api/v1/me/tracking", true)
}
pub fn region() -> Endpoint<(), Region> {
    Endpoint::new(Method::Get, "/api/v1/me/region", false)
}
pub fn set_region() -> Endpoint<Region, Region> {
    Endpoint::new(Method::Put, "/api/v1/me/region", true)
}

pub fn version_settings(scope: Option<&str>, target_id: Option<&str>) -> Endpoint<(), VersionSettings> {
    let mut query = Vec::new();
    if let Some(scope) = scope {
        query.push(format!("scope={}", component(scope)));
    }
    if let Some(target_id) = target_id {
        query.push(format!("target_id={}", component(target_id)));
    }
    let path = if query.is_empty() {
        "/api/v1/version-settings".to_owned()
    } else {
        format!("/api/v1/version-settings?{}", query.join("&"))
    };
    Endpoint::new(Method::Get, path, false)
}

pub fn set_version_setting() -> Endpoint<SetVersionSetting, SettingSaved> {
    Endpoint::new(Method::Put, "/api/v1/version-settings", true)
}
