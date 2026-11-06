use crate::{Endpoint, Method, RawEndpoint, request::component};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Summary {
    pub count: u64,
    pub size_bytes: u64,
}
pub fn get(file_id: &str) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/files/{}/thumbnail/preview", component(file_id)),
            false,
        )
        .limits(0, 32 * 1024 * 1024),
    )
}
pub fn delete(file_id: &str) -> Endpoint<(), ()> {
    Endpoint::new(
        Method::Delete,
        format!("/api/v1/files/{}/thumbnail/preview", component(file_id)),
        false,
    )
}
pub fn clear() -> Endpoint<(), serde_json::Value> {
    Endpoint::new(Method::Delete, "/api/v1/files/previews", false)
}
pub fn summary() -> Endpoint<(), Summary> {
    Endpoint::new(Method::Get, "/api/v1/files/previews/summary", false)
}
