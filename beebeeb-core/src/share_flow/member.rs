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

/// What the host knows about the recipient's key at seal time. REQUIRED on every member seal: there
/// is no default, so a host cannot skip the comparison by omission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerKeyExpectation {
    /// The host holds a "compared" mark; this is the fingerprint ([`safety::key_fingerprint`]) of
    /// the key it was made against. A server key with another fingerprint is refused with
    /// `peer_key_changed`, before any seal byte exists.
    Compared([u8; 32]),
    /// The host has no compared mark for this person (never compared, or none stored).
    NotCompared,
}

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
    /// against (`Compared`): nothing was sealed. The invite exists and stays
    /// claimed; the host shows the changed-key warning and, only if the user accepts the new key,
    /// approves with [`approve_request`], `Compared(key_fingerprint(key))` for the bytes carried here. `code()` is `peer_key_changed`.
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
    peer_key: PeerKeyExpectation,
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

/// The server's `recipient_public_key`: validated as a sharing key (32 bytes, bit 255 clear, not a
/// small-order point: `invalid_input`, the same rule as the safety number), then checked against the
/// host's expectation BEFORE anything is sealed: a different key is [`ShareFlowError::PeerKeyChanged`].
pub(crate) fn recipient_key(
    recipient_public_key_b64: &str,
    expectation: PeerKeyExpectation,
) -> Result<[u8; 32], ShareFlowError> {
    let raw = b64_decode(recipient_public_key_b64)?;
    if raw.len() != 32 {
        return Err(ShareFlowError::Protocol("recipient key length"));
    }
    let public = super::safety::sharing_key(&raw)?;
    if let PeerKeyExpectation::Compared(expected) = expectation {
        let actual: [u8; 32] = Sha256::digest(public).into();
        if !bool::from(actual.ct_eq(&expected)) {
            return Err(ShareFlowError::PeerKeyChanged);
        }
    }
    Ok(public)
}

/// The approval body: the file key sealed for `recipient_public_key_b64` (web `buildApprovalKeyBlob`,
/// file branch). The ONLY public member seal. With `Compared(fingerprint)` (SHA-256 of the key a
/// "compared" mark was made against) a server key that differs is refused with `peer_key_changed`
/// and nothing is sealed.
///
/// "Share anyway" after `peer_key_changed { key }`: call this again with THOSE bytes
/// (`recipient_public_key_b64 = b64(key)`) and `Compared(key_fingerprint(key))`, never with a
/// re-fetched server key. If the server swapped the key again in between, the bytes still match
/// the expectation and the user's accepted key is what is sealed; a key the user never saw is
/// never sealed to. The host then updates its mark to that fingerprint.
pub fn approve_request(
    invite_id: &str,
    file_id: &str,
    recipient_public_key_b64: &str,
    master: &MasterKey,
    file_key: &FileKey,
    expectation: PeerKeyExpectation,
) -> Result<SealedApproval, ShareFlowError> {
    let invite_id = path_id(invite_id)?;
    let file_id = canonical_item_id(file_id, "file id")?;
    let public = recipient_key(recipient_public_key_b64, expectation)?;
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
    expectation: PeerKeyExpectation,
) -> ClaimedStep {
    match approve_request(invite_id, item_id, recipient_public_key_b64, master, key, expectation) {
        Ok(sealed) => ClaimedStep::Send(sealed),
        Err(ShareFlowError::PeerKeyChanged) => {
            match recipient_key(recipient_public_key_b64, PeerKeyExpectation::NotCompared) {
                Ok(recipient_public_key) => ClaimedStep::Done(InviteOutcome::PeerKeyChanged {
                    invite_id: invite_id.to_owned(),
                    recipient_public_key,
                }),
                Err(_) => ClaimedStep::Done(awaiting(invite_id, None)),
            }
        }
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
    /// `peer_key` is required: `Compared(fingerprint of the host's mark)` makes a different server
    /// key end in [`InviteOutcome::PeerKeyChanged`]; `NotCompared` when the host has no mark.
    pub fn start(
        target: &ShareTarget,
        email: &str,
        master: &MasterKey,
        file_key: &FileKey,
        peer_key: PeerKeyExpectation,
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
                peer_key,
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
                        self.peer_key,
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
