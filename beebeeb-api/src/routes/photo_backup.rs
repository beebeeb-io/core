use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub identifiers: Vec<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct CheckResult {
    #[serde(default)]
    pub already_backed_up: Vec<String>,
    #[serde(default)]
    pub needs_backup: Vec<String>,
    #[serde(default)]
    pub backed_up: Vec<BackedUp>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct BackedUp {
    pub local_identifier: String,
    pub file_id: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Mark {
    pub local_identifier: String,
    pub file_id: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct MarkResult {
    pub local_identifier: String,
    pub file_id: String,
    pub device_id: String,
    pub status: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Stats {
    pub total_backed_up: u64,
    pub total_size_bytes: u64,
    #[serde(default)]
    pub last_backup_at: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Identifiers {
    pub identifiers: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct IdPage {
    #[serde(default)]
    pub ids: Vec<String>,
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// The header the server keys every photo-backup association by
/// (`photo_backup_state (user_id, device_id, local_identifier)`). A request
/// without it lands in the account's shared `''` map, where one device's
/// photo ids collide with another's, so every keyed route below takes the
/// device id: the platform's canonical one, never one core makes up. The
/// server trims it and reads one over 128 bytes as missing.
pub const DEVICE_ID_HEADER: &str = "X-Beebeeb-Device-Id";

pub fn check(device_id: &str) -> Endpoint<Check, CheckResult> {
    Endpoint::new(Method::Post, "/api/v1/files/photo-backup/check", true).header(DEVICE_ID_HEADER, device_id)
}
pub fn mark(device_id: &str) -> Endpoint<Mark, MarkResult> {
    Endpoint::new(Method::Post, "/api/v1/files/photo-backup/mark", true).header(DEVICE_ID_HEADER, device_id)
}
pub fn stats() -> Endpoint<(), Stats> {
    Endpoint::new(Method::Get, "/api/v1/files/photo-backup/stats", false)
}
pub fn identifiers(device_id: &str) -> Endpoint<(), Identifiers> {
    Endpoint::new(Method::Get, "/api/v1/files/photo-backup/identifiers", false)
        .limits(0, 16 * 1024 * 1024)
        .header(DEVICE_ID_HEADER, device_id)
}
pub fn ids(device_id: &str, cursor: Option<&str>, limit: u16) -> Endpoint<(), IdPage> {
    let path = cursor.map_or_else(
        || format!("/api/v1/files/photo-backup/ids?limit={limit}"),
        |cursor| {
            format!(
                "/api/v1/files/photo-backup/ids?limit={limit}&cursor={}",
                component(cursor)
            )
        },
    );
    Endpoint::new(Method::Get, path, false)
        .limits(0, 16 * 1024 * 1024)
        .header(DEVICE_ID_HEADER, device_id)
}
pub fn clear_association(device_id: &str, file_id: &str) -> Endpoint<(), super::Empty> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/files/{}/photo-backup/clear-association", component(file_id)),
        false,
    )
    .header(DEVICE_ID_HEADER, device_id)
}
