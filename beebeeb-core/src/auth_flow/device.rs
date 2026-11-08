//! Sign in with another device: the requesting side and the approving side.
//!
//! The requester opens the `/api/v1/auth/cli` socket (the transport is the caller's) and speaks
//! [`DeviceRequest`]'s frames; it never sends a secret, only its ephemeral P-256 public key and
//! what it can say about itself. The approver, already signed in, runs [`Approval`]:
//!
//! ```text
//! Approval::lookup(code)      ──► GET  /api/v1/auth/cli-pubkey?code=XXXX-XXXX     (session)
//!   on_response ◄── {ecdh_public_key_b64, request: RequesterFacts}  → PendingApproval
//! PendingApproval::approve(typed_code, password, master_key)
//!                             ──► step-up, purpose cli_device_approval bound to the code
//!                             ──► POST /api/v1/auth/cli-session {user_code} + X-Confirm-Token
//!   ◄── {session_token}         (a new session for the requester, minted by the server)
//!                             ──► POST /api/v1/auth/cli-authorize {user_code, nonce_b64,
//!                                  encrypted_payload_b64, browser_ecdh_public_b64}
//! ```
//!
//! The payload `{session_token, master_key_b64}` is sealed to the requester's key with
//! [`crate::cli_auth::encrypt_for_requester`]; the server relays ciphertext only. Every secret
//! in transit (password, confirm token, the new session token, the master key, the plaintext
//! payload) is `Zeroizing`. A native user-verification prompt before [`PendingApproval::approve`]
//! is the platform's job (desktop: Windows Hello); this module requires the password step-up
//! regardless, because the server's claim refuses anything but a `cli_device_approval` token.
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::step_up::{StepUp, StepUpPurpose, StepUpStep};
use super::{AuthFlowError, HttpRequest, HttpResponse, RequestAuth, b64, b64_decode, normalize_device_code};
use crate::cli_auth::{CliEphemeralKey, encrypt_for_requester};

pub const DEVICE_SOCKET_PATH: &str = "/api/v1/auth/cli";
pub const PUBKEY_PATH: &str = "/api/v1/auth/cli-pubkey";
pub const CLAIM_PATH: &str = "/api/v1/auth/cli-session";
pub const RELAY_PATH: &str = "/api/v1/auth/cli-authorize";
pub const DENY_PATH: &str = "/api/v1/auth/cli-deny";

/// The approval payload `{session_token, master_key_b64}`, borrowed fields only.
#[derive(serde::Serialize)]
struct ApprovalPayload<'a> {
    session_token: &'a str,
    master_key_b64: &'a str,
}

/// Serializes the approval payload straight into one pre-sized wiped buffer: no intermediate
/// `serde_json::Value` or `String` holds the session token or the encoded master key, and the
/// buffer never reallocates (a reallocation would free an unwiped copy).
pub(crate) fn approval_plaintext(
    session_token: &str,
    master_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, AuthFlowError> {
    let master_b64 = Zeroizing::new(b64().encode(master_key));
    // JSON escaping can at most sextuple a byte (`\u00XX`); keys and punctuation are fixed.
    let cap = 64 + 6 * session_token.len() + master_b64.len();
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    let payload = ApprovalPayload {
        session_token,
        master_key_b64: master_b64.as_str(),
    };
    serde_json::to_writer(&mut *buf, &payload).map_err(|_| AuthFlowError::Protocol("approval payload"))?;
    Ok(buf)
}

// ── The requesting side ──────────────────────────────────────────────────────

/// What the requesting device reports about itself. The approver sees these labelled
/// "reported by the device": they are hints, never proof.
#[derive(Clone, Debug, Default)]
pub struct DeviceFacts {
    pub device_name: Option<String>,
    pub client: String,
    pub client_version: String,
    pub os: String,
}

/// The keys that arrived from the approving device. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceCredentials {
    pub session_token: String,
    pub master_key: [u8; 32],
}

/// What a socket frame meant.
pub enum DeviceRequestEvent {
    /// The server issued a code: show it with the QR (`verification_uri`, which carries no code).
    Waiting {
        user_code: String,
        verification_uri: String,
        expires_in: u64,
    },
    /// Approved: the keys decrypted on this device.
    Approved(DeviceCredentials),
}

/// One request to be signed in by another device. Holds the ephemeral key; a new request
/// (Ask again, Get a new code) is a new `DeviceRequest`.
pub struct DeviceRequest {
    key: CliEphemeralKey,
    user_code: Option<String>,
    finished: bool,
}

impl Default for DeviceRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceRequest {
    pub fn new() -> Self {
        Self {
            key: CliEphemeralKey::generate(),
            user_code: None,
            finished: false,
        }
    }

    /// The first frame to send on the socket.
    pub fn init_frame(&self, facts: &DeviceFacts) -> String {
        let mut frame = json!({
            "ecdh_public_key_b64": b64().encode(self.key.public_key_bytes()),
            "client": facts.client,
            "client_version": facts.client_version,
            "os": facts.os,
        });
        if let Some(name) = facts.device_name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            frame["device_name"] = json!(name);
        }
        frame.to_string()
    }

    /// The code the server issued, once it has.
    pub fn user_code(&self) -> Option<&str> {
        self.user_code.as_deref()
    }

    /// Interpret one text frame from the server.
    pub fn on_frame(&mut self, text: &str) -> Result<DeviceRequestEvent, AuthFlowError> {
        if self.finished {
            return Err(AuthFlowError::WrongState);
        }
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|_| AuthFlowError::Protocol("frame is not json"))?;
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            self.finished = true;
            return Err(match err {
                "timeout" | "expired" => AuthFlowError::Expired,
                "denied" => AuthFlowError::Denied,
                _ => AuthFlowError::Protocol("server refused the request"),
            });
        }
        if self.user_code.is_none() {
            let code = v
                .get("user_code")
                .and_then(|c| c.as_str())
                .ok_or(AuthFlowError::Protocol("missing user_code"))?;
            let code = normalize_device_code(code).ok_or(AuthFlowError::Protocol("malformed user_code"))?;
            let uri = v
                .get("verification_uri")
                .and_then(|c| c.as_str())
                .unwrap_or_default()
                .to_owned();
            let expires_in = v.get("expires_in").and_then(|c| c.as_u64()).unwrap_or(300);
            self.user_code = Some(code.clone());
            return Ok(DeviceRequestEvent::Waiting {
                user_code: code,
                verification_uri: uri,
                expires_in,
            });
        }
        self.finished = true;
        let field = |k: &'static str| v.get(k).and_then(|x| x.as_str()).ok_or(AuthFlowError::KeysDidNotArrive);
        let nonce = b64_decode(field("nonce_b64")?).map_err(|_| AuthFlowError::KeysDidNotArrive)?;
        let ct = b64_decode(field("encrypted_payload_b64")?).map_err(|_| AuthFlowError::KeysDidNotArrive)?;
        let approver = b64_decode(field("browser_ecdh_public_b64")?).map_err(|_| AuthFlowError::KeysDidNotArrive)?;
        let plain = Zeroizing::new(
            self.key
                .decrypt_browser_payload(&approver, &nonce, &ct)
                .map_err(|_| AuthFlowError::KeysDidNotArrive)?,
        );
        parse_credentials(&plain)
    }
}

fn parse_credentials(plain: &[u8]) -> Result<DeviceRequestEvent, AuthFlowError> {
    #[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
    struct Wire {
        session_token: String,
        master_key_b64: String,
    }
    let wire: Wire = serde_json::from_slice(plain).map_err(|_| AuthFlowError::KeysDidNotArrive)?;
    let key = Zeroizing::new(b64_decode(&wire.master_key_b64).map_err(|_| AuthFlowError::KeysDidNotArrive)?);
    if key.len() != 32 || wire.session_token.is_empty() {
        return Err(AuthFlowError::KeysDidNotArrive);
    }
    let mut creds = DeviceCredentials {
        session_token: wire.session_token.clone(),
        master_key: [0u8; 32],
    };
    creds.master_key.copy_from_slice(&key);
    Ok(DeviceRequestEvent::Approved(creds))
}

// ── The approving side ───────────────────────────────────────────────────────

/// What the server knows about the request. `requested_at`, `expires_at`, `ip` and `country`
/// are measured by the server; the rest is reported by the requesting device (unverified).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct RequesterFacts {
    pub requested_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
}

impl RequesterFacts {
    /// Seconds until the request expires at `now_unix` (negative once expired), or `None`
    /// when the server's timestamp does not parse.
    pub fn seconds_left(&self, now_unix: i64) -> Option<i64> {
        chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .ok()
            .map(|t| t.timestamp() - now_unix)
    }
}

/// Starts an approval.
pub struct Approval;

impl Approval {
    /// Look up a waiting request by the code typed on this device.
    pub fn lookup(code: &str) -> Result<(ApprovalLookup, HttpRequest), AuthFlowError> {
        let code = normalize_device_code(code).ok_or(AuthFlowError::RequestNotFound)?;
        let req = HttpRequest::get(format!("{PUBKEY_PATH}?code={code}"), RequestAuth::Session);
        Ok((ApprovalLookup { code }, req))
    }
}

impl Approval {
    /// Deny a waiting request by its code (DW-A09 "Denied"). The requesting device's socket
    /// gets `{"error":"denied"}`. No step-up: denying grants nothing.
    pub fn deny(code: &str) -> Result<(Denial, HttpRequest), AuthFlowError> {
        let code = normalize_device_code(code).ok_or(AuthFlowError::RequestNotFound)?;
        let req = HttpRequest::post(DENY_PATH, json!({ "user_code": code }), RequestAuth::Session);
        Ok((Denial, req))
    }
}

/// A sent denial, waiting for the server's answer.
pub struct Denial;

impl Denial {
    /// `404` covers an unknown, expired or already-claimed code (the server counts each as a guess).
    pub fn on_response(self, resp: HttpResponse) -> Result<(), AuthFlowError> {
        if resp.status == 404 {
            return Err(AuthFlowError::RequestNotFound);
        }
        if !resp.ok() {
            return Err(AuthFlowError::from_status(&resp));
        }
        if resp.body.get("denied").and_then(|d| d.as_bool()) != Some(true) {
            return Err(AuthFlowError::Protocol("deny not confirmed"));
        }
        Ok(())
    }
}

pub struct ApprovalLookup {
    code: String,
}

impl ApprovalLookup {
    pub fn on_response(self, resp: HttpResponse) -> Result<PendingApproval, AuthFlowError> {
        if resp.status == 404 {
            return Err(AuthFlowError::RequestNotFound);
        }
        if !resp.ok() {
            return Err(AuthFlowError::from_status(&resp));
        }
        let requester_public = b64_decode(resp.str_field("ecdh_public_key_b64")?)?;
        let facts: RequesterFacts = resp
            .body
            .get("request")
            .filter(|r| !r.is_null())
            .map(|r| serde_json::from_value(r.clone()).map_err(|_| AuthFlowError::Protocol("request facts")))
            .transpose()?
            .unwrap_or_default();
        Ok(PendingApproval {
            code: self.code,
            requester_public,
            facts,
        })
    }
}

/// A request found and shown for review.
pub struct PendingApproval {
    code: String,
    requester_public: Vec<u8>,
    facts: RequesterFacts,
}

impl PendingApproval {
    pub fn facts(&self) -> &RequesterFacts {
        &self.facts
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    /// Approve stays disabled until the typed code matches the request (DW-A13).
    pub fn code_matches(&self, typed: &str) -> bool {
        normalize_device_code(typed).as_deref() == Some(self.code.as_str())
    }

    /// Deny the request shown for review.
    pub fn deny(self) -> (Denial, HttpRequest) {
        let req = HttpRequest::post(DENY_PATH, json!({ "user_code": self.code }), RequestAuth::Session);
        (Denial, req)
    }

    /// Approve: step up with the password (purpose `cli_device_approval`, bound to the code),
    /// then claim and relay. The caller has already raised its native user-verification prompt.
    pub fn approve(
        self,
        typed_code: &str,
        password: &[u8],
        master_key: &[u8; 32],
    ) -> Result<(ApproveRun, HttpRequest), AuthFlowError> {
        if !self.code_matches(typed_code) {
            return Err(AuthFlowError::InvalidInput("typed code does not match the request"));
        }
        let (step_up, req) = StepUp::start(
            password,
            StepUpPurpose::DeviceApproval {
                code: self.code.clone(),
            },
        )?;
        Ok((
            ApproveRun {
                code: self.code,
                requester_public: self.requester_public,
                master_key: Zeroizing::new(*master_key),
                stage: ApproveStage::StepUp(Box::new(step_up)),
            },
            req,
        ))
    }
}

enum ApproveStage {
    StepUp(Box<StepUp>),
    Claim,
    Relay,
    Done,
}

/// An approval in flight.
pub struct ApproveRun {
    code: String,
    requester_public: Vec<u8>,
    master_key: Zeroizing<[u8; 32]>,
    stage: ApproveStage,
}

pub enum ApproveStep {
    Send(HttpRequest),
    /// The keys were relayed to the requesting device.
    Approved,
}

impl ApproveRun {
    pub fn on_response(&mut self, resp: HttpResponse) -> Result<ApproveStep, AuthFlowError> {
        match std::mem::replace(&mut self.stage, ApproveStage::Done) {
            ApproveStage::StepUp(mut step_up) => match step_up.on_response(resp)? {
                StepUpStep::Send(req) => {
                    self.stage = ApproveStage::StepUp(step_up);
                    Ok(ApproveStep::Send(req))
                }
                StepUpStep::Confirmed(token) => {
                    self.stage = ApproveStage::Claim;
                    let claim = HttpRequest::post(CLAIM_PATH, json!({ "user_code": self.code }), RequestAuth::Session);
                    Ok(ApproveStep::Send(token.attach(claim)))
                }
            },
            ApproveStage::Claim => {
                if resp.status == 409 {
                    return Err(AuthFlowError::AlreadyHandled);
                }
                if resp.status == 404 {
                    return Err(AuthFlowError::RequestNotFound);
                }
                if !resp.ok() {
                    return Err(AuthFlowError::from_status(&resp));
                }
                let session_token = Zeroizing::new(resp.str_field("session_token")?.to_owned());
                let plain = approval_plaintext(&session_token, &self.master_key)?;
                let sealed = encrypt_for_requester(&self.requester_public, &plain)
                    .map_err(|_| AuthFlowError::Protocol("requester key"))?;
                self.master_key.zeroize();
                self.stage = ApproveStage::Relay;
                Ok(ApproveStep::Send(HttpRequest::post(
                    RELAY_PATH,
                    json!({
                        "user_code": self.code,
                        "nonce_b64": b64().encode(sealed.nonce),
                        "encrypted_payload_b64": b64().encode(&sealed.ciphertext),
                        "browser_ecdh_public_b64": b64().encode(&sealed.approver_public),
                    }),
                    RequestAuth::Session,
                )))
            }
            ApproveStage::Relay => {
                if resp.status == 404 {
                    return Err(AuthFlowError::Expired);
                }
                if !resp.ok() {
                    return Err(AuthFlowError::from_status(&resp));
                }
                Ok(ApproveStep::Approved)
            }
            ApproveStage::Done => Err(AuthFlowError::WrongState),
        }
    }
}
