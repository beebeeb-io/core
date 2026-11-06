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

pub fn check() -> Endpoint<Check, CheckResult> {
    Endpoint::new(Method::Post, "/api/v1/files/photo-backup/check", true)
}
pub fn mark() -> Endpoint<Mark, MarkResult> {
    Endpoint::new(Method::Post, "/api/v1/files/photo-backup/mark", true)
}
pub fn stats() -> Endpoint<(), Stats> {
    Endpoint::new(Method::Get, "/api/v1/files/photo-backup/stats", false)
}
pub fn identifiers() -> Endpoint<(), Identifiers> {
    Endpoint::new(Method::Get, "/api/v1/files/photo-backup/identifiers", false).limits(0, 16 * 1024 * 1024)
}
pub fn ids(cursor: Option<&str>, limit: u16) -> Endpoint<(), IdPage> {
    let path = cursor.map_or_else(
        || format!("/api/v1/files/photo-backup/ids?limit={limit}"),
        |cursor| {
            format!(
                "/api/v1/files/photo-backup/ids?limit={limit}&cursor={}",
                component(cursor)
            )
        },
    );
    Endpoint::new(Method::Get, path, false).limits(0, 16 * 1024 * 1024)
}
pub fn clear_association(file_id: &str) -> Endpoint<(), super::Empty> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/files/{}/photo-backup/clear-association", component(file_id)),
        false,
    )
}
