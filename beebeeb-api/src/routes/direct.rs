use crate::{Endpoint, Method, request::component};
pub use beebeeb_core::direct_transfer::wire::{
    Discovery, DownloadGrantRequest, DownloadGrantResponse, UploadCommitRequest, UploadCommitResponse,
    UploadGrantRequest, UploadGrantResponse,
};

pub fn capabilities() -> Endpoint<(), Discovery> {
    Endpoint::new(Method::Get, "/api/v1/transfer/capabilities", false).limits(0, 256 * 1024)
}
pub fn download_grants(id: &str) -> Endpoint<DownloadGrantRequest, DownloadGrantResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/files/{}/download-grants", component(id)),
        true,
    )
    .capabilities()
    .limits(1024, 1024 * 1024)
}
pub fn upload_grant(session: &str, index: u32) -> Endpoint<UploadGrantRequest, UploadGrantResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/uploads/{}/chunks/{index}/grant", component(session)),
        true,
    )
    .capabilities()
    .limits(1024, 64 * 1024)
}
pub fn upload_commit(session: &str, index: u32) -> Endpoint<UploadCommitRequest, UploadCommitResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/uploads/{}/chunks/{index}/commit", component(session)),
        true,
    )
    .capabilities()
    .limits(1024, 64 * 1024)
}
