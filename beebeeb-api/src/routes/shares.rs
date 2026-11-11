use crate::{Endpoint, Method, RawEndpoint, request::component};
use serde::{Deserialize, Serialize};

/// A share as the owner's listings (`mine`, `by_file`) and the public answers (`public_get`,
/// `verify`) describe it. None of them carries the token: the server keeps only its hash, and the
/// owner gets the link back from `owner_wrapped_token` (core's `share_flow::link::rebuild_link`).
#[derive(Debug, Clone, Deserialize)]
pub struct Share {
    pub id: String,
    #[serde(default)]
    pub file_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}
#[derive(Debug, Clone, Deserialize)]
pub struct List {
    #[serde(default)]
    pub shares: Vec<Share>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeResponse {
    #[serde(default)]
    pub message: Option<String>,
}
#[derive(Clone, Deserialize)]
pub struct ChunkManifest {
    pub chunk_count: u32,
    pub size_bytes: u64,
    pub chunks: Vec<ChunkDescription>,
    pub download_token: String,
    pub download_token_expires_at: String,
}
crate::redacted_debug!(ChunkManifest; show: [chunk_count, size_bytes, chunks, download_token_expires_at]; hide: [download_token]);
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkDescription {
    pub index: u32,
    pub size_bytes: u64,
}
#[derive(Clone, Serialize)]
pub struct Verify {
    pub passphrase: String,
}

pub fn mine() -> Endpoint<(), List> {
    Endpoint::new(Method::Get, "/api/v1/shares/mine", false)
}
pub fn by_file(file_id: &str) -> Endpoint<(), List> {
    Endpoint::new(
        Method::Get,
        format!("/api/v1/shares/by-file/{}", component(file_id)),
        false,
    )
}
pub fn revoke(id: &str) -> Endpoint<(), RevokeResponse> {
    Endpoint::new(Method::Delete, format!("/api/v1/shares/{}", component(id)), false)
}
pub fn public_get(token: &str) -> Endpoint<(), Share> {
    Endpoint::new(Method::Get, format!("/api/v1/shares/{}", component(token)), false)
        .public()
        .sensitive_path()
}
pub fn verify(token: &str) -> Endpoint<Verify, Share> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/shares/{}/verify", component(token)),
        true,
    )
    .public()
    .sensitive_path()
}
pub fn download(token: &str) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/shares/{}/download", component(token)),
            false,
        )
        .public()
        .sensitive_path()
        .limits(0, 256 * 1024 * 1024 + 28),
    )
}

pub fn chunk_manifest(token: &str, passphrase: Option<&str>) -> Endpoint<(), ChunkManifest> {
    let endpoint = Endpoint::new(
        Method::Get,
        format!("/api/v1/shares/{}/chunks", component(token)),
        false,
    )
    .public()
    .sensitive_path()
    .limits(0, 1024 * 1024);
    match passphrase {
        Some(passphrase) => endpoint.header("X-Share-Passphrase", passphrase),
        None => endpoint,
    }
}

pub fn chunk(token: &str, index: u32, download_token: &str, passphrase: Option<&str>) -> RawEndpoint<()> {
    let endpoint = Endpoint::new(
        Method::Get,
        format!("/api/v1/shares/{}/chunks/{index}", component(token)),
        false,
    )
    .public()
    .sensitive_path()
    .header("X-Share-Download-Token", download_token)
    .limits(0, 256 * 1024 * 1024 + 28);
    RawEndpoint::new(match passphrase {
        Some(passphrase) => endpoint.header("X-Share-Passphrase", passphrase),
        None => endpoint,
    })
}
