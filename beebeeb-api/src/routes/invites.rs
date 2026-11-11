use crate::{Endpoint, Method, request::component};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Invite {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub file_id: Option<String>,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}
#[derive(Debug, Clone, Deserialize)]
pub struct List {
    #[serde(default)]
    pub invites: Vec<Invite>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct StatusResponse {
    pub message: String,
    pub status: String,
}
pub fn incoming() -> Endpoint<(), List> {
    Endpoint::new(Method::Get, "/api/v1/shares/invites/incoming", false)
}
pub fn sent() -> Endpoint<(), List> {
    Endpoint::new(Method::Get, "/api/v1/shares/invites/sent", false)
}
pub fn deny(id: &str) -> Endpoint<(), StatusResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/shares/invites/{}/deny", component(id)),
        false,
    )
}
pub fn withdraw(id: &str) -> Endpoint<(), StatusResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/shares/invites/{}/withdraw", component(id)),
        false,
    )
}
