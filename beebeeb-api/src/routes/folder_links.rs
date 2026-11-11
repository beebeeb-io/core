use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Patch {
    #[serde(default)]
    pub access_level: Option<String>,
    #[serde(default)]
    pub label_encrypted: Option<String>,
    #[serde(default)]
    pub expires_in_hours: Option<Option<i64>>,
    #[serde(default)]
    pub cap_bytes: Option<Option<i64>>,
    #[serde(default)]
    pub paused: Option<bool>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Link {
    pub id: String,
    pub folder_id: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}
#[derive(Debug, Clone, Deserialize)]
pub struct List {
    #[serde(default)]
    pub links: Vec<Link>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeResponse {
    pub message: String,
}

pub fn list(folder_id: Option<&str>) -> Endpoint<(), List> {
    let path = folder_id.map_or_else(
        || "/api/v1/shares/folder-links".to_string(),
        |id| format!("/api/v1/shares/folder-links?folder_id={}", component(id)),
    );
    Endpoint::new(Method::Get, path, false)
}
pub fn update(id: &str) -> Endpoint<Patch, Link> {
    Endpoint::new(
        Method::Patch,
        format!("/api/v1/shares/folder-links/{}", component(id)),
        true,
    )
}
pub fn revoke(id: &str) -> Endpoint<(), RevokeResponse> {
    Endpoint::new(
        Method::Delete,
        format!("/api/v1/shares/folder-links/{}", component(id)),
        false,
    )
}
