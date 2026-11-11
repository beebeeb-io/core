use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Create {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    pub wrapped_private_key: String,
    pub wrap_nonce: String,
    #[serde(default)]
    pub target_folder_id: Option<String>,
    #[serde(default)]
    pub max_files: Option<i32>,
    #[serde(default)]
    pub max_total_bytes: Option<i64>,
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
}
#[derive(Clone, Deserialize)]
pub struct FileRequest {
    pub id: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    pub closed: bool,
    #[serde(default)]
    pub closed_at: Option<String>,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}
crate::redacted_debug!(FileRequest; show: [id, title, closed, closed_at, extra]; hide: [token]);
#[derive(Clone, Deserialize)]
pub struct Created {
    pub id: String,
    pub token: String,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}
crate::redacted_debug!(Created; show: [id, extra]; hide: [token]);
#[derive(Debug, Clone, Deserialize)]
pub struct List {
    #[serde(default)]
    pub file_requests: Vec<FileRequest>,
}

pub fn create() -> Endpoint<Create, Created> {
    Endpoint::new(Method::Post, "/api/v1/file-requests", true)
}
pub fn list() -> Endpoint<(), List> {
    Endpoint::new(Method::Get, "/api/v1/file-requests", false)
}
pub fn close(id: &str) -> Endpoint<(), FileRequest> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/file-requests/{}/close", component(id)),
        false,
    )
}
pub fn delete(id: &str) -> Endpoint<(), ()> {
    Endpoint::new(
        Method::Delete,
        format!("/api/v1/file-requests/{}", component(id)),
        false,
    )
}
pub fn public_get(token: &str) -> Endpoint<(), FileRequest> {
    Endpoint::new(Method::Get, format!("/api/v1/r/{}", component(token)), false)
        .public()
        .sensitive_path()
}
