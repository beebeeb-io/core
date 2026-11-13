use std::{future::Future, pin::Pin};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use beebeeb_api::{
    flows::NewDeviceFlow,
    proposed,
    routes::{auth, devices},
};
use beebeeb_core::{
    CoreError,
    kdf::MasterKey,
    key_proof::{KeyProofBinding, KeyProofChallenge as CoreKeyProofChallenge, answer_challenge},
    opaque_protocol::{
        client_login_finish, client_login_finish_legacy_upgrade, client_login_start, client_registration_finish,
        client_registration_start,
    },
    passkey_seal::{PasskeySealedMasterKey, open_master_key, seal_master_key},
    screen_lock::PendingScreenCheck,
};
use zeroize::Zeroizing;

use crate::{Client, ClientError, SecretError, SecretStore, Session, session::HardwareIdentity};

mod account;
mod install;
mod lock;
mod lock_password;
mod new_device;
mod passkey;
mod recovery;
mod sign_in;
mod signup;

pub use account::*;
pub use lock::*;
pub use lock_password::ScreenUnlock;
pub use new_device::*;
pub use passkey::*;
pub use recovery::*;
pub use signup::*;

const LEGACY_ACCOUNT: &str = "auth.legacy-upgrade-account";

/// Canonical account lookup form used by the server: trim, then Unicode
/// lowercase. No provider-specific rewriting or Unicode normalization occurs.
pub fn canonical_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

pub struct LegacyUpgradeAuthorization {
    canonical_email: String,
}

impl LegacyUpgradeAuthorization {
    /// Loads a local migration decision recorded before the network login.
    /// A server response can never construct this authorization.
    pub fn from_trusted_local_record(
        store: &dyn SecretStore,
        canonical_email: &str,
    ) -> Result<Option<Self>, SecretError> {
        let Some(recorded) = store.get(LEGACY_ACCOUNT)? else {
            return Ok(None);
        };
        let recorded = String::from_utf8(recorded.to_vec()).map_err(|_| SecretError::Corrupt)?;
        Ok((recorded == canonical_email).then(|| Self {
            canonical_email: canonical_email.to_owned(),
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKeyState {
    Unknown,
    Legacy,
    Locked,
    Proven,
}

impl SessionKeyState {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, AuthError> {
        match value {
            None => Ok(Self::Unknown),
            Some("legacy") => Ok(Self::Legacy),
            Some("locked") => Ok(Self::Locked),
            Some("proven") => Ok(Self::Proven),
            Some(_) => Err(AuthError::MalformedAnswer),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInStateKind {
    TwoFactor,
    PasswordAccepted,
    RecoveryPasswordProven,
}

pub enum SignInChallenge {
    TwoFactor(TwoFactorChallenge),
    PasswordAccepted(PasswordAccepted),
    RecoveryPasswordProven(RecoveryPasswordProof),
}

impl SignInChallenge {
    pub fn kind(&self) -> SignInStateKind {
        match self {
            Self::TwoFactor(_) => SignInStateKind::TwoFactor,
            Self::PasswordAccepted(_) => SignInStateKind::PasswordAccepted,
            Self::RecoveryPasswordProven(_) => SignInStateKind::RecoveryPasswordProven,
        }
    }

    pub fn canonical_email(&self) -> &str {
        match self {
            Self::TwoFactor(state) => &state.canonical_email,
            Self::PasswordAccepted(state) => &state.canonical_email,
            Self::RecoveryPasswordProven(state) => &state.canonical_email,
        }
    }
}

impl std::fmt::Debug for SignInChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SignInChallenge").field(&self.kind()).finish()
    }
}

pub struct TwoFactorChallenge {
    pub(crate) partial_token: Zeroizing<String>,
    pub(crate) canonical_email: String,
    pub(crate) legacy_upgrade_required: bool,
    pub(crate) hardware_id: Option<String>,
    /// The stretched password of this sign-in, waiting for the owner it is sealed to.
    pub(crate) screen_check: Option<PendingScreenCheck>,
}

impl std::fmt::Debug for TwoFactorChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorChallenge")
            .field("partial_token", &"[REDACTED]")
            .field("canonical_email", &self.canonical_email)
            .field("legacy_upgrade_required", &self.legacy_upgrade_required)
            .field("hardware_id", &self.hardware_id)
            .field("screen_check", &self.screen_check.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

pub struct PasswordAccepted {
    pub(crate) session_token: Zeroizing<String>,
    pub(crate) canonical_email: String,
    pub(crate) owner: String,
    pub(crate) key_state: SessionKeyState,
    pub(crate) legacy_upgrade_required: bool,
    pub(crate) factor_satisfied: bool,
    pub(crate) email_code_satisfied: bool,
    pub(crate) authenticator_required: bool,
    pub(crate) hardware_id: Option<String>,
    pub(crate) hardware_identity_secret: Option<Zeroizing<String>>,
    /// The stretched password of this sign-in. It becomes the screen-lock check record in
    /// the step that saves the installed session, never before.
    pub(crate) screen_check: Option<PendingScreenCheck>,
}

impl PasswordAccepted {
    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn canonical_email(&self) -> &str {
        &self.canonical_email
    }

    pub fn key_state(&self) -> SessionKeyState {
        self.key_state
    }

    pub fn legacy_upgrade_required(&self) -> bool {
        self.legacy_upgrade_required
    }

    pub fn should_offer_passkey_copy(&self) -> bool {
        !self.legacy_upgrade_required
    }
}

impl std::fmt::Debug for PasswordAccepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordAccepted")
            .field("session_token", &"[REDACTED]")
            .field("canonical_email", &self.canonical_email)
            .field("owner", &self.owner)
            .field("key_state", &self.key_state)
            .field("legacy_upgrade_required", &self.legacy_upgrade_required)
            .field("factor_satisfied", &self.factor_satisfied)
            .field("email_code_satisfied", &self.email_code_satisfied)
            .field("authenticator_required", &self.authenticator_required)
            .field("hardware_id", &self.hardware_id)
            .field(
                "hardware_identity_secret",
                &self.hardware_identity_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("screen_check", &self.screen_check.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

pub struct RecoveryPasswordProof {
    token: Zeroizing<String>,
    canonical_email: String,
}

#[derive(Default)]
struct SignInOptions {
    hardware_id: Option<String>,
    hardware_identity_secret: Option<String>,
    request_password_proof: bool,
}

impl std::fmt::Debug for RecoveryPasswordProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryPasswordProof")
            .field("token", &"[REDACTED]")
            .field("canonical_email", &self.canonical_email)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct InstalledSession {
    owner: String,
    generation: u64,
}

impl InstalledSession {
    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// One-shot proof that the coordinator successfully purged the previous
/// account before an account-replacing install begins.
#[derive(Debug)]
pub struct AccountReplacement {
    _private: (),
}

impl AccountReplacement {
    pub fn is_authorized(&self) -> bool {
        true
    }

    #[allow(dead_code)]
    pub(crate) fn authorized() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Client(ClientError),
    #[error("account creation is available on the web")]
    SignupWebOnly { signup_url: String },
    #[error("this sign-in requires a hardware identity")]
    HardwareIdentityRequired,
    #[error("sign-in cryptography failed")]
    Crypto,
    /// The password step-up did not confirm the password: it is not the account's, or
    /// the server refused the proof or has locked password checks after failed guesses
    /// (it answers those alike). The session itself is still signed in.
    #[error("the password was not confirmed")]
    PasswordNotConfirmed,
    #[error("the sign-in answer is malformed")]
    MalformedAnswer,
    #[error("{step}: invalid {field} in the server answer")]
    InvalidAnswer { step: &'static str, field: &'static str },
    #[error("{step}: {requirement}")]
    InvalidTransition {
        step: &'static str,
        requirement: &'static str,
    },
    #[error("legacy account upgrade was not authorized by local migration state")]
    LegacyUpgradeNotAuthorized,
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error("account-key proof failed")]
    KeyProof,
    #[error("the sign-in state does not belong to the stored account")]
    AccountOwnership,
    #[error("another account is stored on this device")]
    AnotherAccountOnDevice,
    #[error("the platform passkey prompt failed")]
    PasskeyPrompt,
    #[error(transparent)]
    Onboarding(#[from] beebeeb_core::onboarding::CeremonyError),
    #[error("the PDF and text recovery-kit files must both be saved")]
    RecoveryKitIncomplete,
    #[error("recovery is waiting until {ready_at}")]
    RecoveryWaiting { ready_at: beebeeb_api::routes::Timestamp },
    #[error("recovery is not ready to complete")]
    RecoveryNotReady,
    #[error("the replacement mailbox must be verified before recovery can complete")]
    RecoveryEmailVerificationRequired,
    #[error("the server recovery answer does not identify the recovered account")]
    RecoveryAccountIdentityMissing,
    /// The password path of the screen lock is not enabled for this client
    /// (`ClientConfig::lock_password_path`): nothing was checked and nothing was counted.
    #[error("the password check of the screen lock is not available")]
    PasswordCheckUnavailable,
    /// The local check could not run (Argon2id could not allocate its memory). Nothing was
    /// counted; fall back to platform verification or the online check.
    #[error("the local password check is unavailable")]
    LocalCheckUnavailable,
    /// Too many wrong tries: no password is checked before the wait is over.
    #[error("too many wrong tries: wait before the next one")]
    PasswordTryWait { wait_ms: u64 },
    /// The server's own limit on password checks. Not a wrong try.
    #[error("the server limits password checks: wait before the next one")]
    PasswordCheckLimited { wait_ms: Option<u64> },
    /// The server cannot be reached, and this step needs the password proven to the server.
    #[error("the server cannot be reached to prove the password")]
    PasswordProofOffline,
}

impl From<ClientError> for AuthError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Api(beebeeb_api::ApiError::SignupWebOnly { signup_url }) => Self::SignupWebOnly { signup_url },
            error if server_code(&error, 403, "hardware_identity_required") => Self::HardwareIdentityRequired,
            error => Self::Client(error),
        }
    }
}

fn server_code(error: &ClientError, status: u16, code: &str) -> bool {
    matches!(
        error,
        ClientError::Api(beebeeb_api::ApiError::Server(server))
            if server.status == status && server.code.as_deref() == Some(code)
    )
}

pub(crate) fn sign_in_state(
    canonical_email: String,
    mut response: auth::OpaqueFinishResponse,
    legacy_upgrade_required: bool,
    hardware_id: Option<String>,
    requested_password_proof: bool,
) -> Result<SignInChallenge, AuthError> {
    if let Some(password_proven) = response.password_proven.take() {
        if !requested_password_proof
            || password_proven.is_empty()
            || response.session_token.is_some()
            || response.partial_token.is_some()
            || response.user_id.is_some()
            || response.key_state.is_some()
            || response.requires_2fa.is_some()
            || response.expires_in_seconds != Some(600)
        {
            return Err(AuthError::InvalidAnswer {
                step: "OPAQUE password proof",
                field: "proof-only fields",
            });
        }
        return Ok(SignInChallenge::RecoveryPasswordProven(RecoveryPasswordProof {
            token: Zeroizing::new(password_proven),
            canonical_email,
        }));
    }
    if requested_password_proof || response.expires_in_seconds.is_some() {
        return Err(AuthError::InvalidAnswer {
            step: "OPAQUE login finish",
            field: "password-proof fields",
        });
    }

    enum TokenKind {
        FullSession,
        TwoFactor,
    }
    let token_kind = match (
        response.requires_2fa,
        response.session_token.as_deref(),
        response.partial_token.as_deref(),
    ) {
        (None | Some(false), Some(session_token), None) if !session_token.is_empty() => TokenKind::FullSession,
        (Some(true), None, Some(partial_token)) if !partial_token.is_empty() => TokenKind::TwoFactor,
        _ => {
            return Err(AuthError::InvalidAnswer {
                step: "OPAQUE login finish",
                field: "token combination",
            });
        }
    };
    if matches!(token_kind, TokenKind::TwoFactor) {
        let partial_token = response.partial_token.take().ok_or(AuthError::InvalidAnswer {
            step: "OPAQUE login finish",
            field: "token combination",
        })?;
        return Ok(SignInChallenge::TwoFactor(TwoFactorChallenge {
            partial_token: Zeroizing::new(partial_token),
            canonical_email,
            legacy_upgrade_required,
            hardware_id,
            screen_check: None,
        }));
    }
    let session_token = response.session_token.take().ok_or(AuthError::InvalidAnswer {
        step: "OPAQUE login finish",
        field: "token combination",
    })?;
    if response.partial_token.is_some() {
        return Err(AuthError::InvalidAnswer {
            step: "OPAQUE login finish",
            field: "token combination",
        });
    }
    let owner = response.user_id.ok_or(AuthError::InvalidAnswer {
        step: "OPAQUE login finish",
        field: "user_id",
    })?;
    if owner.is_empty() {
        return Err(AuthError::InvalidAnswer {
            step: "OPAQUE login finish",
            field: "full-session fields",
        });
    }
    Ok(SignInChallenge::PasswordAccepted(PasswordAccepted {
        session_token: Zeroizing::new(session_token),
        canonical_email,
        owner,
        key_state: SessionKeyState::parse(response.key_state.as_deref()).map_err(|_| AuthError::InvalidAnswer {
            step: "OPAQUE login finish",
            field: "key_state",
        })?,
        legacy_upgrade_required,
        factor_satisfied: false,
        email_code_satisfied: false,
        authenticator_required: false,
        hardware_id,
        hardware_identity_secret: None,
        screen_check: None,
    }))
}

fn decode_key_proof_challenge(value: &proposed::KeyProofChallenge) -> Result<CoreKeyProofChallenge, AuthError> {
    let nonce = decode_fixed_no_pad::<32>(&value.nonce).map_err(|_| AuthError::InvalidAnswer {
        step: "key-proof start",
        field: "nonce",
    })?;
    let server_public = decode_fixed_no_pad::<32>(&value.server_public_key).map_err(|_| AuthError::InvalidAnswer {
        step: "key-proof start",
        field: "server_public_key",
    })?;
    Ok(CoreKeyProofChallenge::from_parts(nonce, server_public))
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], AuthError> {
    let bytes = STANDARD.decode(value).map_err(|_| AuthError::MalformedAnswer)?;
    bytes.try_into().map_err(|_| AuthError::MalformedAnswer)
}

fn decode_fixed_no_pad<const N: usize>(value: &str) -> Result<[u8; N], AuthError> {
    let bytes = STANDARD_NO_PAD.decode(value).map_err(|_| AuthError::MalformedAnswer)?;
    bytes.try_into().map_err(|_| AuthError::MalformedAnswer)
}

impl From<CoreError> for AuthError {
    fn from(_: CoreError) -> Self {
        Self::Crypto
    }
}
