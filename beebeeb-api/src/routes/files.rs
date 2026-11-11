use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub name_encrypted: Option<String>,
    #[serde(default)]
    pub is_folder: bool,
    #[serde(default)]
    pub is_trashed: bool,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListResponse {
    #[serde(default)]
    pub files: Vec<FileEntry>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateFolder {
    pub name_encrypted: String,
    pub parent_id: Option<String>,
    pub folder_id: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct UpdateFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_encrypted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Option<String>>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Ids {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreVersionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_encrypted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_metadata_encrypted: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileVersion {
    pub id: String,
    pub version_number: i32,
    pub size_bytes: u64,
    pub chunk_count: u32,
    pub created_at: String,
    pub source: String,
    #[serde(default)]
    pub version_metadata_encrypted: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Versions {
    pub file_id: String,
    pub current_version: i32,
    #[serde(default)]
    pub versions: Vec<FileVersion>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageUsage {
    pub used_bytes: i64,
    pub plan_limit_bytes: i64,
    pub plan_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrashResponse {
    pub message: String,
    pub trashed_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PermanentDeleteResponse {
    pub message: String,
}

pub fn get(id: &str) -> Endpoint<(), FileEntry> {
    Endpoint::new(Method::Get, format!("/api/v1/files/{}", component(id)), false)
}
pub fn list(parent_id: Option<&str>, trashed: bool) -> Endpoint<(), ListResponse> {
    list_page(parent_id, trashed, None, None)
}
pub fn list_page(
    parent_id: Option<&str>,
    trashed: bool,
    cursor: Option<&str>,
    limit: Option<u16>,
) -> Endpoint<(), ListResponse> {
    let mut path = format!("/api/v1/files?trashed={trashed}");
    if let Some(id) = parent_id {
        path.push_str("&parent_id=");
        path.push_str(&component(id));
    }
    if let Some(cursor) = cursor {
        path.push_str("&cursor=");
        path.push_str(&component(cursor));
    }
    if let Some(limit) = limit {
        path.push_str("&limit=");
        path.push_str(&limit.to_string());
    }
    Endpoint::new(Method::Get, path, false).limits(0, 16 * 1024 * 1024)
}
pub fn create_folder() -> Endpoint<CreateFolder, FileEntry> {
    Endpoint::new(Method::Post, "/api/v1/files/folder", true)
}
pub fn update(id: &str) -> Endpoint<UpdateFile, FileEntry> {
    Endpoint::new(Method::Patch, format!("/api/v1/files/{}", component(id)), true).capabilities()
}
pub fn trash(id: &str) -> Endpoint<(), TrashResponse> {
    Endpoint::new(Method::Delete, format!("/api/v1/files/{}", component(id)), false)
}
pub fn trash_many() -> Endpoint<Ids, serde_json::Value> {
    Endpoint::new(Method::Post, "/api/v1/files/trash", true)
}
pub fn restore(id: &str) -> Endpoint<(), serde_json::Value> {
    Endpoint::new(Method::Post, format!("/api/v1/files/{}/restore", component(id)), false)
}
pub fn permanent_delete(id: &str) -> Endpoint<(), PermanentDeleteResponse> {
    Endpoint::new(
        Method::Delete,
        format!("/api/v1/files/{}/permanent", component(id)),
        false,
    )
}
pub fn permanent_delete_many() -> Endpoint<Ids, serde_json::Value> {
    Endpoint::new(Method::Post, "/api/v1/files/permanent", true)
}
pub fn index(hash: Option<&str>) -> Endpoint<(), serde_json::Value> {
    let path = hash.map_or_else(
        || "/api/v1/files/index".to_string(),
        |hash| format!("/api/v1/files/index?hash={}", component(hash)),
    );
    Endpoint::new(Method::Get, path, false).limits(0, 32 * 1024 * 1024)
}
pub fn versions(id: &str) -> Endpoint<(), Versions> {
    Endpoint::new(Method::Get, format!("/api/v1/files/{}/versions", component(id)), false)
}
pub fn restore_version(id: &str, version_id: &str) -> Endpoint<RestoreVersionRequest, serde_json::Value> {
    Endpoint::new(
        Method::Post,
        format!(
            "/api/v1/files/{}/versions/{}/restore",
            component(id),
            component(version_id)
        ),
        true,
    )
}
pub fn usage() -> Endpoint<(), StorageUsage> {
    Endpoint::new(Method::Get, "/api/v1/files/usage", false)
}
