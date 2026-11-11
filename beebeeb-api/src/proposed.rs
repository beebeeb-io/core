//! Proposed server API. These descriptors become usable only when the server
//! implements the corresponding additive routes.

use crate::{Endpoint, Method, request::component};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::routes::Timestamp;
use beebeeb_core::system_folders::Service;

pub fn request_email_code() -> Endpoint<EmailCodeRequest, EmailCodeChallenge> {
    Endpoint::new(Method::Post, "/api/v1/auth/email-code/request", true).public()
}

pub fn submit_email_code() -> Endpoint<EmailCodeSubmit, EmailCodeTicket> {
    Endpoint::new(Method::Post, "/api/v1/auth/email-code/verify", true).public()
}

pub fn start_device_link() -> Endpoint<DeviceLinkStart, DeviceLinkStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/devices/link/start", true)
}

pub fn pending_device_links() -> Endpoint<(), PendingDeviceLinks> {
    Endpoint::new(Method::Get, "/api/v1/devices/links/pending", false)
}

pub fn get_device_link(id: &str) -> Endpoint<(), DeviceLinkDetail> {
    Endpoint::new(Method::Get, format!("/api/v1/devices/link/{}", component(id)), false)
}

pub fn approve_device_link(id: &str) -> Endpoint<DeviceLinkApproval, OkResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/devices/link/{}/approve", component(id)),
        true,
    )
}

pub fn deny_device_link(id: &str) -> Endpoint<(), OkResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/devices/link/{}/deny", component(id)),
        false,
    )
}

pub fn device_link_result(id: &str) -> Endpoint<(), DeviceLinkResult> {
    Endpoint::new(
        Method::Get,
        format!("/api/v1/devices/link/{}/result", component(id)),
        false,
    )
}

pub fn ack_device_link(id: &str) -> Endpoint<(), OkResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/devices/link/{}/ack", component(id)),
        false,
    )
}

pub fn send_device_link_pake(id: &str) -> Endpoint<DeviceLinkPakeMessage, OkResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/devices/link/{}/pake", component(id)),
        true,
    )
}

pub fn get_device_link_pake(id: &str) -> Endpoint<(), DeviceLinkPakeResult> {
    get_device_link_pake_for_role(id, DeviceLinkRole::NewDevice)
}

pub fn get_device_link_pake_for_role(id: &str, role: DeviceLinkRole) -> Endpoint<(), DeviceLinkPakeResult> {
    Endpoint::new(
        Method::Get,
        format!(
            "/api/v1/devices/link/{}/pake?role={}",
            component(id),
            match role {
                DeviceLinkRole::NewDevice => "new_device",
                DeviceLinkRole::Approver => "approver",
            }
        ),
        false,
    )
}

pub fn start_key_proof() -> Endpoint<(), KeyProofChallenge> {
    Endpoint::new(Method::Post, "/api/v1/auth/key-proof/start", false)
}

pub fn finish_key_proof() -> Endpoint<KeyProofAnswer, KeyProofFinish> {
    Endpoint::new(Method::Post, "/api/v1/auth/key-proof/finish", true)
}

pub fn recovery_challenge() -> Endpoint<RecoveryChallengeRequest, RecoveryChallenge> {
    Endpoint::new(Method::Post, "/api/v1/recovery/challenge", true).public()
}

pub fn start_recovery() -> Endpoint<RecoveryStart, RecoveryStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/recovery/start", true).public()
}

pub fn recovery_status(id: &str) -> Endpoint<(), RecoveryStatus> {
    Endpoint::new(Method::Get, format!("/api/v1/recovery/{}", component(id)), false).bearer()
}

pub fn cancel_recovery(id: &str) -> Endpoint<(), OkResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/recovery/{}/cancel", component(id)),
        false,
    )
}

pub fn cancel_recovery_with_token(id: &str) -> Endpoint<RecoveryCancel, OkResponse> {
    Endpoint::new(Method::Post, format!("/api/v1/recovery/{}/cancel", component(id)), true).public()
}

pub fn recovery_opaque_register(id: &str) -> Endpoint<RecoveryOpaqueRegister, RecoveryOpaqueRegisterResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/recovery/{}/opaque-register", component(id)),
        true,
    )
    .bearer()
}

pub fn complete_recovery(id: &str) -> Endpoint<RecoveryComplete, RecoveryCompleteResponse> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/recovery/{}/complete", component(id)),
        true,
    )
    .bearer()
}

pub fn enable_service(service: Service) -> Endpoint<ServiceEnable, ServiceFolder> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/services/{}/enable", component(service.as_str())),
        true,
    )
}

pub fn disable_service(service: Service) -> Endpoint<ServiceDisable, ServiceDisableResult> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/services/{}/disable", component(service.as_str())),
        true,
    )
}

pub fn complete_snapshot() -> Endpoint<(), super::routes::sync::Snapshot> {
    Endpoint::new(Method::Get, "/api/v1/sync/snapshot/complete", false).limits(0, 32 * 1024 * 1024)
}

pub fn mint_upload_token(upload_session_id: &str) -> Endpoint<(), UploadToken> {
    Endpoint::new(
        Method::Post,
        format!("/api/v1/uploads/{}/token", component(upload_session_id)),
        false,
    )
}

pub fn store_passkey_copy() -> Endpoint<PasskeyCopyStore, OkResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/vault-key-escrow", true)
}

pub fn get_passkey_copy(credential_id: &str) -> Endpoint<(), PasskeyCopy> {
    Endpoint::new(
        Method::Get,
        format!("/api/v1/auth/vault-key-escrow/{}", component(credential_id)),
        false,
    )
}

pub fn list_account_sessions() -> Endpoint<(), AccountSessions> {
    Endpoint::new(Method::Get, "/api/v1/auth/sessions", false)
}

pub fn revoke_account_session(id: &str) -> Endpoint<(), AccountSessionRevoked> {
    Endpoint::new(
        Method::Delete,
        format!("/api/v1/auth/sessions/{}", component(id)),
        false,
    )
}

pub fn confirm_opaque_start() -> Endpoint<ConfirmOpaqueStart, ConfirmOpaqueStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/confirm-opaque-start", true).step_up()
}

pub fn confirm_opaque_finish() -> Endpoint<ConfirmOpaqueFinish, Confirmation> {
    Endpoint::new(Method::Post, "/api/v1/auth/confirm-opaque-finish", true).step_up()
}

pub fn change_password_start() -> Endpoint<ChangePasswordStart, ChangePasswordStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/change-password-start", true)
}

pub fn change_password_finish() -> Endpoint<ChangePasswordFinish, ChangedPasswordSession> {
    Endpoint::new(Method::Post, "/api/v1/auth/change-password-finish", true)
}

pub fn change_email_start() -> Endpoint<ChangeEmailStart, ChangeEmailStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/me/email/start", true)
}

pub fn change_email_finish() -> Endpoint<ChangeEmailFinish, ChangedEmail> {
    Endpoint::new(Method::Post, "/api/v1/me/email/finish", true)
}

#[derive(Clone, Serialize)]
pub struct EmailCodeRequest {
    pub email: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailCodeChallenge {
    pub challenge: String,
    pub expires_at: Timestamp,
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct EmailCodeSubmit {
    pub challenge: String,
    pub code: Zeroizing<String>,
}

#[derive(Clone, Deserialize)]
pub struct EmailCodeTicket {
    pub email_code_ticket: String,
    pub expires_in: u64,
}

impl std::fmt::Debug for EmailCodeTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailCodeTicket")
            .field("email_code_ticket", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceLinkStart {
    pub session_id: String,
    pub public_key: String,
    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceLinkStartResponse {
    #[serde(default)]
    pub id: String,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PendingDeviceLinks {
    #[serde(default)]
    pub links: Vec<PendingDeviceLink>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PendingDeviceLink {
    pub id: String,
    pub session_id: String,
    pub device_name: String,
    pub reported_by_device: bool,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceLinkDetail {
    pub id: String,
    pub session_id: String,
    pub public_key: String,
    pub device_name: String,
    pub reported_by_device: bool,
    pub status: DeviceLinkStatus,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceLinkApproval {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_public: Option<String>,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLinkRole {
    NewDevice,
    Approver,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceLinkPakeMessage {
    pub role: DeviceLinkRole,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceLinkPakeResult {
    pub status: DeviceLinkPakeStatus,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLinkPakeStatus {
    Pending,
    Ready,
    Finished,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLinkStatus {
    Pending,
    Approved,
    Denied,
    Acked,
    Expired,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceLinkResult {
    pub status: DeviceLinkStatus,
    #[serde(default)]
    pub approver_public: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub ciphertext: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyProofChallenge {
    pub session_id: String,
    pub account_id: String,
    pub nonce: String,
    pub server_public_key: String,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Serialize)]
pub struct KeyProofAnswer {
    pub response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_code_ticket: Option<String>,
}
crate::redacted_debug!(KeyProofAnswer; show: [response]; hide: [email_code_ticket]);

#[derive(Clone, Deserialize)]
pub struct KeyProofFinish {
    pub key_state: String,
    #[serde(default)]
    pub hardware_identity_secret: Option<String>,
}

impl std::fmt::Debug for KeyProofFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyProofFinish")
            .field("key_state", &self.key_state)
            .field(
                "hardware_identity_secret",
                &self.hardware_identity_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct RecoveryChallengeRequest {
    pub email: String,
}

#[derive(Clone, Deserialize)]
pub struct RecoveryChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub server_public: String,
    pub canonical_email: String,
    pub expires_at: Timestamp,
}

#[derive(Clone, Serialize)]
pub struct RecoveryStart {
    pub email: String,
    pub challenge_id: String,
    pub response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_proven: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct RecoveryStartResponse {
    pub id: String,
    pub status: String,
    pub ready_at: Timestamp,
    pub recovery_token: String,
}

impl std::fmt::Debug for RecoveryStartResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryStartResponse")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("ready_at", &self.ready_at)
            .field("recovery_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct RecoveryStatus {
    pub status: String,
    pub ready_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Clone, Default, Serialize)]
pub struct RecoveryCancel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_token: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct RecoveryComplete {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque_registration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verification_code: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator: Option<AuthenticatorChange>,
}

#[derive(Clone, Serialize)]
pub struct AuthenticatorChange {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for AuthenticatorChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatorChange")
            .field("action", &self.action)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct RecoveryOpaqueRegister {
    pub client_message: String,
}

#[derive(Clone, Deserialize)]
pub struct RecoveryOpaqueRegisterResponse {
    pub server_message: String,
}

#[derive(Clone, Deserialize)]
pub struct RecoveryCompleteResponse {
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub key_state: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

impl std::fmt::Debug for RecoveryCompleteResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCompleteResponse")
            .field("session_token", &self.session_token.as_ref().map(|_| "[REDACTED]"))
            .field("key_state", &self.key_state)
            .field("user_id", &self.user_id)
            .field("status", &self.status)
            .finish()
    }
}

/// A system service folder is always at the top level (LD-0113: the server's
/// live CHECK refuses a parent, and answers 400 to one), so the request has
/// no `parent_id`.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceEnable {
    pub folder_id: String,
    pub name_encrypted: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceFolder {
    pub service: String,
    pub enabled: bool,
    pub folder_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceDisable {
    pub move_to_trash: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceDisableResult {
    pub service: String,
    pub enabled: bool,
    pub folder_id: Option<String>,
    #[serde(default)]
    pub moved_to_trash: Option<bool>,
    #[serde(default)]
    pub trashed_count: Option<u64>,
}

#[derive(Clone, Deserialize)]
pub struct UploadToken {
    pub token: String,
    pub upload_session_id: String,
    pub expires_at: Timestamp,
}

impl std::fmt::Debug for UploadToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadToken")
            .field("token", &"[REDACTED]")
            .field("upload_session_id", &self.upload_session_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct PasskeyCopyStore {
    pub credential_id: String,
    pub encrypted_vault_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Clone, Deserialize)]
pub struct PasskeyCopy {
    pub credential_id: String,
    pub encrypted_vault_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountSessions {
    #[serde(default)]
    pub sessions: Vec<AccountSession>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountSession {
    pub id: String,
    pub is_current: bool,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountSessionRevoked {
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct ConfirmOpaqueStart {
    pub client_message: String,
}

#[derive(Clone, Deserialize)]
pub struct ConfirmOpaqueStartResponse {
    pub server_message: String,
    pub server_state: String,
    pub ksf_version: u16,
}

#[derive(Clone, Serialize)]
pub struct ConfirmOpaqueFinish {
    pub client_message: String,
    pub server_state: String,
}

#[derive(Clone, Deserialize)]
pub struct Confirmation {
    pub confirmation_token: String,
    pub expires_at: Timestamp,
}

#[derive(Clone, Serialize)]
pub struct ChangePasswordStart {
    pub client_message: String,
}

#[derive(Clone, Deserialize)]
pub struct ChangePasswordStartResponse {
    pub server_message: String,
}

#[derive(Clone, Serialize)]
pub struct ChangePasswordFinish {
    pub client_message: String,
}

#[derive(Clone, Deserialize)]
pub struct ChangedPasswordSession {
    pub session_token: String,
    pub user_id: String,
    #[serde(default)]
    pub key_state: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct ChangeEmailStart {
    pub new_email: String,
    pub opaque_client_message: String,
}

#[derive(Clone, Deserialize)]
pub struct ChangeEmailStartResponse {
    pub server_message: String,
    pub email_change_token: String,
}

#[derive(Clone, Serialize)]
pub struct ChangeEmailFinish {
    pub email_change_token: String,
    pub opaque_registration: String,
    pub recovery_check: String,
    pub x25519_public_key: String,
}

#[derive(Clone, Deserialize)]
pub struct ChangedEmail {
    pub email: String,
}
