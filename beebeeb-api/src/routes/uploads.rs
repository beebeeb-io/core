use crate::{Endpoint, Method, RawEndpoint, request::component};
use beebeeb_types::ChunkProfile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct InitRequest {
    pub file_id: Option<String>,
    pub file_name: String,
    pub file_size_bytes: u64,
    pub parent_id: Option<String>,
    pub profile: ChunkProfile,
    pub preferred_region: Option<String>,
    pub chunk_size_bytes: Option<u64>,
    pub chunk_count: Option<u64>,
    pub is_media: bool,
    pub base_version_number: Option<i32>,
    pub created_at: Option<String>,
    pub conflict_created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_metadata_encrypted: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InitResponse {
    pub upload_session_id: String,
    pub file_id: String,
    pub chunk_size_bytes: u64,
    pub chunk_count: u64,
    #[serde(default)]
    pub transport: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CompleteRequest {
    #[serde(default)]
    pub name_encrypted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_metadata_encrypted: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbandonResponse {
    pub id: String,
    pub status: String,
    pub previous_version_number: Option<i32>,
    pub deleted: bool,
}

pub fn init() -> Endpoint<InitRequest, InitResponse> {
    Endpoint::new(Method::Post, "/api/v1/uploads/init", true).capabilities()
}
pub fn chunk(session: &str, index: u32) -> RawEndpoint<Vec<u8>> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Put,
            format!("/api/v1/uploads/{}/chunks/{index}", component(session)),
            true,
        )
        .capabilities()
        .raw_body()
        .limits(256 * 1024 * 1024 + 28, 1024),
    )
}
pub fn complete(session: &str) -> Endpoint<CompleteRequest, serde_json::Value> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/uploads/{}/complete", component(session)),
        true,
    )
    .capabilities()
}
pub fn heartbeat(session: &str) -> Endpoint<(), serde_json::Value> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/uploads/{}/heartbeat", component(session)),
        false,
    )
    .capabilities()
}
pub fn abandon(file_id: &str) -> Endpoint<(), AbandonResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/files/{}/upload/abandon", component(file_id)),
        false,
    )
}
