use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize)]
pub struct ChangePassword {
    pub current_password: String,
    pub new_password: String,
}
#[derive(Clone, Serialize)]
pub struct TotpCode {
    pub code: String,
}
#[derive(Clone, Serialize, Default)]
pub struct TotpSetupRequest {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub confirm_token: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct TotpSetup {
    pub secret: String,
    #[serde(default)]
    pub qr_uri: Option<String>,
    #[serde(default)]
    pub backup_codes: Vec<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct TotpChangeResponse {
    pub message: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct DataExport {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub download_url: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct DeleteRequest {
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
}

pub fn change_password() -> Endpoint<ChangePassword, ()> {
    Endpoint::new(Method::Post, "/api/v1/auth/change-password", true)
}
pub fn setup_totp() -> Endpoint<TotpSetupRequest, TotpSetup> {
    Endpoint::new(Method::Post, "/api/v1/auth/2fa/setup", true)
}
pub fn enable_totp() -> Endpoint<TotpCode, TotpChangeResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/2fa/enable", true)
}
pub fn disable_totp() -> Endpoint<TotpCode, TotpChangeResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/2fa/disable", true)
}
pub fn request_export() -> Endpoint<(), DataExport> {
    Endpoint::new(Method::Post, "/api/v1/me/data-export", false)
}
pub fn export_status(id: &str) -> Endpoint<(), DataExport> {
    Endpoint::new(Method::Get, format!("/api/v1/me/data-export/{}", component(id)), false)
}
pub fn freeze() -> Endpoint<(), serde_json::Value> {
    Endpoint::new(Method::Post, "/api/v1/me/freeze", false)
}
pub fn unfreeze() -> Endpoint<(), serde_json::Value> {
    Endpoint::new(Method::Post, "/api/v1/me/unfreeze", false)
}
pub fn request_deletion() -> Endpoint<DeleteRequest, serde_json::Value> {
    Endpoint::new(Method::Post, "/api/v1/account/delete/request", true)
}
