//! Share one file with a person (web `share-dialog.tsx` single-file branch).
//!
//! ```text
//! MemberInvite::start ──► POST /api/v1/shares/invites {file_id, recipient_email}
//!   on_response ◄── {invite_id, status, recipient_public_key?}
//!     status "claimed" + key ──► (key ≠ expected mark? Done(PeerKeyChanged), nothing sealed)
//!                               ──► POST /api/v1/shares/invites/{id}/approve {encrypted_file_key}
//!     otherwise               ──► Done(Invited)  (the recipient has no account or key yet)
//!   on_response ◄── 2xx ──► Done(Shared); a failed approval ──► Done(AwaitingApproval)
//! ```
//!
//! Like web, a failed approval is not an error: the invite exists and stays claimed, and the
//! owner can approve it later with [`approve_request`].
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{
    ShareFlowError, b64, b64_decode, canonical_item_id, own_file_key, own_master, path_id, require_ok,
    seal_file_key_for_member, str_field,
};
use crate::auth_flow::{HttpRequest, HttpResponse, RequestAuth};
use crate::kdf::{FileKey, MasterKey};

pub const INVITES_PATH: &str = "/api/v1/shares/invites";

/// What is being shared. `is_folder` is required on purpose (web: "ALWAYS pass isFolder"):
/// a folder shared through the file path would give the recipient a share that never opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareTarget {
    pub item_id: String,
    pub is_folder: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteOutcome {
    /// The recipient had a key: the file key was sealed for them and the share is live.
    /// `recipient_public_key` is the exact key it was sealed to: a host computes the safety number
    /// and keeps its "compared" mark from these bytes, never from a separate key lookup.
    Shared {
        invite_id: String,
        recipient_public_key: [u8; 32],
    },
    /// The invite was sent; the key goes over once the recipient claims it.
    Invited { invite_id: String, status: String },
    /// The recipient claimed it but sealing or approving failed: approve it later.
    /// `recipient_public_key` is set when the key was sealed and only the approval failed.
    AwaitingApproval {
        invite_id: String,
        recipient_public_key: Option<[u8; 32]>,
    },
    /// The server's key for the recipient is not the one the host's "compared" mark was made
    /// against (`expected_peer_fingerprint`): nothing was sealed. The invite exists and stays
    /// claimed; the host shows the changed-key warning and, only if the user accepts the new key,
    /// approves with [`approve_request`] and no expected fingerprint. `code()` is `peer_key_changed`.
    PeerKeyChanged {
        invite_id: String,
        recipient_public_key: [u8; 32],
    },
}

impl InviteOutcome {
    /// `peer_key_changed` for [`InviteOutcome::PeerKeyChanged`], the same code
    /// [`ShareFlowError::PeerKeyChanged`] has; `None` otherwise.
    pub fn refusal_code(&self) -> Option<&'static str> {
        matches!(self, Self::PeerKeyChanged { .. }).then_some("peer_key_changed")
    }
}

/// An approval body and the exact recipient key the file key was sealed to (public).
#[derive(Debug)]
pub struct SealedApproval {
    pub request: HttpRequest,
    pub recipient_public_key: [u8; 32],
}

#[derive(Debug)]
pub enum InviteStep {
    Send(HttpRequest),
    Done(InviteOutcome),
}

enum Stage {
    AwaitInvite,
    AwaitApprove {
        invite_id: String,
        recipient_public_key: [u8; 32],
    },
    Done,
}

pub struct MemberInvite {
    file_id: String,
    master: MasterKey,
    file_key: FileKey,
    expected_peer_fingerprint: Option<[u8; 32]>,
    stage: Stage,
}

impl std::fmt::Debug for MemberInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberInvite")
            .field("file_id", &self.file_id)
            .finish_non_exhaustive()
    }
}

/// Web lower-cases the address before the invite (`recipientEmail = raw.toLowerCase()`).
pub(crate) fn check_email(email: &str) -> Result<String, ShareFlowError> {
    let email = email.trim();
    let at = email.find('@').ok_or(ShareFlowError::InvalidInput("email"))?;
    if at == 0 || at + 1 == email.len() || email.chars().any(char::is_whitespace) || email.len() > 254 {
        return Err(ShareFlowError::InvalidInput("email"));
    }
    Ok(email.to_lowercase())
}

/// The server's `recipient_public_key`, checked against the host's "compared" mark BEFORE anything
/// is sealed: a different key is [`ShareFlowError::PeerKeyChanged`].
pub(crate) fn recipient_key(
    recipient_public_key_b64: &str,
    expected_peer_fingerprint: Option<&[u8; 32]>,
) -> Result<[u8; 32], ShareFlowError> {
    let public: [u8; 32] = b64_decode(recipient_public_key_b64)?
        .as_slice()
        .try_into()
        .map_err(|_| ShareFlowError::Protocol("recipient key length"))?;
    if let Some(expected) = expected_peer_fingerprint {
        let actual: [u8; 32] = Sha256::digest(public).into();
        if !bool::from(actual.ct_eq(expected)) {
            return Err(ShareFlowError::PeerKeyChanged);
        }
    }
    Ok(public)
}

/// The approval body: the file key sealed for `recipient_public_key_b64` (web `buildApprovalKeyBlob`,
/// file branch). With `expected_peer_fingerprint` (SHA-256 of the key a "compared" mark was made
/// against) a server key that differs is refused with `peer_key_changed` and nothing is sealed.
pub fn approve_request(
    invite_id: &str,
    file_id: &str,
    recipient_public_key_b64: &str,
    master: &MasterKey,
    file_key: &FileKey,
    expected_peer_fingerprint: Option<&[u8; 32]>,
) -> Result<SealedApproval, ShareFlowError> {
    let invite_id = path_id(invite_id)?;
    let file_id = canonical_item_id(file_id, "file id")?;
    let public = recipient_key(recipient_public_key_b64, expected_peer_fingerprint)?;
    let sealed = seal_file_key_for_member(master, &public, file_id, file_key)?;
    Ok(SealedApproval {
        request: HttpRequest::post(
            &format!("{INVITES_PATH}/{invite_id}/approve"),
            json!({ "encrypted_file_key": b64(&sealed) }),
            RequestAuth::Session,
        ),
        recipient_public_key: public,
    })
}

/// What a claimed invite with a server key turns into: send the approval, or stop (changed key,
/// or a seal that failed). Shared by the file and the folder flow.
pub(crate) enum ClaimedStep {
    Send(SealedApproval),
    Done(InviteOutcome),
}

pub(crate) fn on_claimed(
    invite_id: &str,
    item_id: &str,
    recipient_public_key_b64: &str,
    master: &MasterKey,
    key: &FileKey,
    expected_peer_fingerprint: Option<&[u8; 32]>,
) -> ClaimedStep {
    match approve_request(
        invite_id,
        item_id,
        recipient_public_key_b64,
        master,
        key,
        expected_peer_fingerprint,
    ) {
        Ok(sealed) => ClaimedStep::Send(sealed),
        Err(ShareFlowError::PeerKeyChanged) => match recipient_key(recipient_public_key_b64, None) {
            Ok(recipient_public_key) => ClaimedStep::Done(InviteOutcome::PeerKeyChanged {
                invite_id: invite_id.to_owned(),
                recipient_public_key,
            }),
            Err(_) => ClaimedStep::Done(awaiting(invite_id, None)),
        },
        Err(_) => ClaimedStep::Done(awaiting(invite_id, None)),
    }
}

pub(crate) fn awaiting(invite_id: &str, recipient_public_key: Option<[u8; 32]>) -> InviteOutcome {
    InviteOutcome::AwaitingApproval {
        invite_id: invite_id.to_owned(),
        recipient_public_key,
    }
}

impl MemberInvite {
    /// `file_key` is the key that opens the row (the caller resolves it, as web's `shareFileKey`).
    /// `expected_peer_fingerprint` is the fingerprint of the host's "compared" mark for this
    /// person, if it has one: a different server key ends in [`InviteOutcome::PeerKeyChanged`].
    pub fn start(
        target: &ShareTarget,
        email: &str,
        master: &MasterKey,
        file_key: &FileKey,
        expected_peer_fingerprint: Option<[u8; 32]>,
    ) -> Result<(Self, HttpRequest), ShareFlowError> {
        if target.is_folder {
            // A folder goes through `folder::FolderInvite` (its key rules), never the file path.
            return Err(ShareFlowError::InvalidInput("is_folder: use FolderInvite"));
        }
        let file_id = canonical_item_id(&target.item_id, "item id")?;
        let email = check_email(email)?;
        let request = HttpRequest::post(
            INVITES_PATH,
            json!({ "file_id": file_id, "recipient_email": email }),
            RequestAuth::Session,
        );
        Ok((
            Self {
                file_id: file_id.to_owned(),
                master: own_master(master),
                file_key: own_file_key(file_key),
                expected_peer_fingerprint,
                stage: Stage::AwaitInvite,
            },
            request,
        ))
    }

    pub fn on_response(&mut self, resp: HttpResponse) -> Result<InviteStep, ShareFlowError> {
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::AwaitInvite => {
                require_ok(&resp)?;
                let invite_id = path_id(str_field(&resp, "invite_id")?)?.to_owned();
                let status = str_field(&resp, "status")?.to_owned();
                let key = resp.body.get("recipient_public_key").and_then(|v| v.as_str());
                match key {
                    Some(key) if status == "claimed" => match on_claimed(
                        &invite_id,
                        &self.file_id,
                        key,
                        &self.master,
                        &self.file_key,
                        self.expected_peer_fingerprint.as_ref(),
                    ) {
                        ClaimedStep::Send(sealed) => {
                            self.stage = Stage::AwaitApprove {
                                invite_id,
                                recipient_public_key: sealed.recipient_public_key,
                            };
                            Ok(InviteStep::Send(sealed.request))
                        }
                        ClaimedStep::Done(outcome) => Ok(InviteStep::Done(outcome)),
                    },
                    _ => Ok(InviteStep::Done(InviteOutcome::Invited { invite_id, status })),
                }
            }
            Stage::AwaitApprove {
                invite_id,
                recipient_public_key,
            } => Ok(InviteStep::Done(if resp.ok() {
                InviteOutcome::Shared {
                    invite_id,
                    recipient_public_key,
                }
            } else {
                awaiting(&invite_id, Some(recipient_public_key))
            })),
            Stage::Done => Err(ShareFlowError::WrongState),
        }
    }
}
