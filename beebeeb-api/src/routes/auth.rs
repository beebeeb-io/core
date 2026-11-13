use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::Empty;
use crate::{Endpoint, Method, RawEndpoint, request::component};

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub email_verified: bool,
    /// The account's count of password changes, when the server reports it. A device compares
    /// it with its screen-lock check record to learn that the record is stale.
    #[serde(default)]
    pub password_counter: Option<u64>,
}

#[derive(Clone, Serialize)]
pub struct CodeRequest {
    pub code: Zeroizing<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct PublicKey {
    pub user_id: String,
    pub public_key: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct LogoutResponse {
    pub message: String,
}
#[derive(Clone, Serialize)]
pub struct OpaqueStartRequest {
    pub email: String,
    pub client_message: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct OpaqueStartResponse {
    pub server_message: String,
    pub server_state: String,
    #[serde(default = "current_ksf")]
    pub ksf_version: u16,
}
fn current_ksf() -> u16 {
    1
}
#[derive(Clone, Serialize)]
pub struct OpaqueFinishRequest {
    pub email: String,
    pub client_message: String,
    pub server_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_identity_secret: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_password_proof: bool,
}
#[derive(Clone, Deserialize)]
pub struct OpaqueFinishResponse {
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub device_confirmation_secret: Option<String>,
    #[serde(default)]
    pub requires_2fa: Option<bool>,
    #[serde(default)]
    pub partial_token: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub key_state: Option<String>,
    #[serde(default)]
    pub password_proven: Option<String>,
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
    #[serde(default)]
    pub hardware_identity_secret: Option<String>,
}
impl std::fmt::Debug for OpaqueFinishResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaqueFinishResponse")
            .field("session_token", &self.session_token.as_ref().map(|_| "[REDACTED]"))
            .field(
                "device_confirmation_secret",
                &self.device_confirmation_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("requires_2fa", &self.requires_2fa)
            .field("partial_token", &self.partial_token.as_ref().map(|_| "[REDACTED]"))
            .field("user_id", &self.user_id)
            .field("key_state", &self.key_state)
            .field("password_proven", &self.password_proven.as_ref().map(|_| "[REDACTED]"))
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field(
                "hardware_identity_secret",
                &self.hardware_identity_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}
#[derive(Clone, Serialize)]
pub struct TwoFactorRequest {
    pub partial_token: Zeroizing<String>,
    pub code: Zeroizing<String>,
}
#[derive(Clone, Deserialize)]
pub struct TwoFactorResponse {
    pub user_id: String,
    pub session_token: String,
    #[serde(default)]
    pub key_state: Option<String>,
    #[serde(default)]
    pub salt: Option<String>,
    #[serde(default)]
    pub hardware_identity_secret: Option<String>,
}
impl std::fmt::Debug for TwoFactorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorResponse")
            .field("user_id", &self.user_id)
            .field("session_token", &"[REDACTED]")
            .field("key_state", &self.key_state)
            .field("salt", &self.salt)
            .field(
                "hardware_identity_secret",
                &self.hardware_identity_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

pub fn opaque_start() -> Endpoint<OpaqueStartRequest, OpaqueStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/opaque/login-start", true).public()
}
pub fn opaque_finish() -> Endpoint<OpaqueFinishRequest, OpaqueFinishResponse> {
    Endpoint::new(Method::Post, "/api/v1/opaque/login-finish", true).public()
}
pub fn complete_two_factor() -> Endpoint<TwoFactorRequest, TwoFactorResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/2fa/verify", true).public()
}
pub fn logout() -> Endpoint<(), LogoutResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/logout", false)
}
pub fn me() -> Endpoint<(), User> {
    Endpoint::new(Method::Get, "/api/v1/auth/me", false)
}
pub fn verify_email() -> Endpoint<CodeRequest, Empty> {
    Endpoint::new(Method::Post, "/api/v1/auth/verify-email", true)
}
pub fn resend_verification() -> Endpoint<(), Empty> {
    Endpoint::new(Method::Post, "/api/v1/auth/resend-verification", false)
}
pub fn public_key(user_id: &str) -> Endpoint<(), PublicKey> {
    Endpoint::new(
        Method::Get,
        format!("/api/v1/auth/public-key/{}", component(user_id)),
        false,
    )
}
pub fn breach_range(prefix: &str) -> RawEndpoint<()> {
    RawEndpoint::new(
        Endpoint::new(
            Method::Get,
            format!("/api/v1/auth/pwned-range/{}", component(prefix)),
            false,
        )
        .public()
        .limits(0, 256 * 1024),
    )
}
