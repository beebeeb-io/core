use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub hostname: String,
    pub platform: String,
    #[serde(default)]
    pub bb_version: Option<String>,
    pub last_seen: String,
    pub created_at: String,
    #[serde(default)]
    pub client_key: Option<String>,
    #[serde(default)]
    pub hostname_encrypted: Option<String>,
    #[serde(default)]
    pub hardware_id: Option<String>,
    #[serde(default)]
    pub reported_name: Option<String>,
    #[serde(default)]
    pub reported_by_device: Option<bool>,
    #[serde(default)]
    pub holds_key: Option<bool>,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub session_type: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub last_heartbeat: Option<String>,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}
#[derive(Clone, Serialize)]
pub struct Register {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_encrypted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bb_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_name: Option<String>,
}
crate::redacted_debug!(Register; show: [client_key, hostname_encrypted, hostname, platform, bb_version, hardware_id, reported_name]; hide: [push_token]);
#[derive(Debug, Clone, Serialize)]
pub struct CreateSession {
    pub device_id: String,
    pub name: String,
    pub session_type: String,
    #[serde(default)]
    pub local_path: Option<String>,
    pub remote_path: String,
    #[serde(default)]
    pub heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    pub alert_after_missed: Option<u32>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Devices {
    #[serde(default)]
    pub devices: Vec<Device>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Sessions {
    #[serde(default)]
    pub sessions: Vec<Session>,
}

pub fn list() -> Endpoint<(), Devices> {
    Endpoint::new(Method::Get, "/api/v1/clients/devices", false)
}
pub fn register() -> Endpoint<Register, Device> {
    Endpoint::new(Method::Post, "/api/v1/clients/devices", true)
}
pub fn remove(id: &str) -> Endpoint<(), ()> {
    Endpoint::new(
        Method::Delete,
        format!("/api/v1/clients/devices/{}", component(id)),
        false,
    )
}
pub fn sessions() -> Endpoint<(), Sessions> {
    Endpoint::new(Method::Get, "/api/v1/clients/sessions", false)
}
pub fn create_session() -> Endpoint<CreateSession, Session> {
    Endpoint::new(Method::Post, "/api/v1/clients/sessions", true)
}
pub fn end_session(id: &str) -> Endpoint<(), ()> {
    Endpoint::new(
        Method::Delete,
        format!("/api/v1/clients/sessions/{}", component(id)),
        false,
    )
}
