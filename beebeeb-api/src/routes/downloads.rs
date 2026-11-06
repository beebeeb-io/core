use crate::{Endpoint, Method, RawEndpoint, request::component};

pub fn file(id: &str) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(Method::Get, format!("/api/v1/files/{}/download", component(id)), false)
            .limits(0, 256 * 1024 * 1024 + 28),
    )
}
pub fn version(id: &str, version: i32) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/files/{}/versions/{version}/download", component(id)),
            false,
        )
        .limits(0, 256 * 1024 * 1024 + 28),
    )
}

pub fn chunk(id: &str, index: u32, object_version_id: &str) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!(
                "/api/v1/files/{}/chunks/{index}?object_version_id={}",
                component(id),
                component(object_version_id)
            ),
            false,
        )
        .limits(0, 256 * 1024 * 1024 + 29),
    )
}

pub fn share_file(token: &str) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/shares/{}/download", component(token)),
            false,
        )
        .public()
        .sensitive_path()
        .limits(0, 256 * 1024 * 1024 + 29),
    )
}
