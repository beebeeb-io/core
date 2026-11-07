use crate::{Endpoint, Method};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingDocument {
    pub schema: u32,
    pub generated_at: String,
    pub ttl_seconds: u32,
    pub client: OnboardingClient,
    pub stage: OnboardingStage,
    #[serde(default)]
    pub signup: Option<OnboardingSignup>,
    #[serde(default)]
    pub policy: Option<OnboardingPolicy>,
    pub steps: Vec<OnboardingStep>,
    pub blocking: bool,
    #[serde(default)]
    pub copy: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub fallback: Option<OnboardingFallback>,
    #[serde(flatten)]
    pub extra: super::ExtraFields,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStage {
    PreAccount,
    Account,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingClient {
    pub status: String,
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub recommended_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingSignup {
    pub allowed: bool,
    pub mode: String,
    pub reason: Option<String>,
    pub web_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingPolicy {
    pub password: OnboardingPasswordPolicy,
    pub recovery_phrase: OnboardingRecoveryPhrasePolicy,
    pub terms: OnboardingTermsPolicy,
    pub email_code: OnboardingEmailCodePolicy,
    pub pilot_key: OnboardingPilotKeyPolicy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingPasswordPolicy {
    pub min_length: u32,
    pub breach_check: OnboardingBreachCheck,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingBreachCheck {
    pub endpoint: String,
    pub fail_open: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingRecoveryPhrasePolicy {
    pub word_count: u32,
    pub verify_word_count: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingTermsPolicy {
    pub version: String,
    pub url: String,
    pub privacy_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingEmailCodePolicy {
    pub length: u32,
    pub ttl_seconds: u32,
    pub resend_after_seconds: u32,
    pub ticket_ttl_seconds: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingPilotKeyPolicy {
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingStep {
    pub id: String,
    pub status: String,
    pub required: bool,
    pub ui: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingFallback {
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct EmailStart {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pilot_key: Option<String>,
}
crate::redacted_debug!(EmailStart; show: [email]; hide: [pilot_key]);
#[derive(Debug, Clone, Deserialize)]
pub struct EmailStartResponse {
    pub message: String,
}
#[derive(Clone, Serialize)]
pub struct EmailVerify {
    pub email: String,
    pub code: String,
}
crate::redacted_debug!(EmailVerify; show: [email]; hide: [code]);
#[derive(Clone, Deserialize)]
pub struct SignupTicket {
    pub signup_ticket: String,
}
crate::redacted_debug!(SignupTicket; show: []; hide: [signup_ticket]);
#[derive(Clone, Serialize)]
pub struct RegistrationStart {
    pub email: String,
    pub signup_ticket: String,
    pub client_message: String,
}
crate::redacted_debug!(RegistrationStart; show: [email, client_message]; hide: [signup_ticket]);
#[derive(Clone, Serialize)]
pub struct RegistrationFinish {
    pub email: String,
    pub client_message: String,
    pub hardware_id: String,
    pub x25519_public_key: String,
    pub recovery_check: String,
    pub signup_ticket: String,
    pub terms_version: String,
}
crate::redacted_debug!(RegistrationFinish; show: [email, client_message, hardware_id, x25519_public_key, recovery_check, terms_version]; hide: [signup_ticket]);

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationStartResponse {
    pub server_message: String,
}

#[derive(Clone, Deserialize)]
pub struct RegistrationFinishResponse {
    pub user_id: String,
    pub session_token: String,
    #[serde(default)]
    pub key_state: Option<String>,
}

pub fn document(authenticated: bool) -> Endpoint<(), OnboardingDocument> {
    let endpoint = Endpoint::new(Method::Get, "/api/v1/onboarding", false);
    if authenticated { endpoint } else { endpoint.public() }
}
pub fn email_start() -> Endpoint<EmailStart, EmailStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/auth/signup/email-start", true).public()
}
pub fn email_verify() -> Endpoint<EmailVerify, SignupTicket> {
    Endpoint::new(Method::Post, "/api/v1/auth/signup/email-verify", true).public()
}
pub fn register_start() -> Endpoint<RegistrationStart, RegistrationStartResponse> {
    Endpoint::new(Method::Post, "/api/v1/opaque/register-start", true).public()
}
pub fn register_finish() -> Endpoint<RegistrationFinish, RegistrationFinishResponse> {
    Endpoint::new(Method::Post, "/api/v1/opaque/register-finish", true).public()
}
