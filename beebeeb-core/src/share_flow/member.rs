//! Share one file with a person (web `share-dialog.tsx` single-file branch).
//!
//! ```text
//! MemberInvite::start ──► POST /api/v1/shares/invites {file_id, recipient_email}
//!   on_response ◄── {invite_id, status, recipient_public_key?}
//!     status "claimed" + key ──► POST /api/v1/shares/invites/{id}/approve {encrypted_file_key}
//!     otherwise               ──► Done(Invited)  (the recipient has no account or key yet)
//!   on_response ◄── 2xx ──► Done(Shared); a failed approval ──► Done(AwaitingApproval)
//! ```
//!
//! Like web, a failed approval is not an error: the invite exists and stays claimed, and the
//! owner can approve it later with [`approve_request`].
use serde_json::json;

use super::{
    ShareFlowError, b64, b64_decode, own_file_key, own_master, path_id, require_ok, seal_file_key_for_member, str_field,
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
    Shared { invite_id: String },
    /// The invite was sent; the key goes over once the recipient claims it.
    Invited { invite_id: String, status: String },
    /// The recipient claimed it but sealing or approving failed: approve it later.
    AwaitingApproval { invite_id: String },
}

#[derive(Debug)]
pub enum InviteStep {
    Send(HttpRequest),
    Done(InviteOutcome),
}

enum Stage {
    AwaitInvite,
    AwaitApprove { invite_id: String },
    Done,
}

pub struct MemberInvite {
    file_id: String,
    master: MasterKey,
    file_key: FileKey,
    stage: Stage,
}

impl std::fmt::Debug for MemberInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberInvite")
            .field("file_id", &self.file_id)
            .finish_non_exhaustive()
    }
}

fn check_email(email: &str) -> Result<&str, ShareFlowError> {
    let email = email.trim();
    let at = email.find('@').ok_or(ShareFlowError::InvalidInput("email"))?;
    if at == 0 || at + 1 == email.len() || email.chars().any(char::is_whitespace) || email.len() > 254 {
        return Err(ShareFlowError::InvalidInput("email"));
    }
    Ok(email)
}

/// The approval body: the file key sealed for `recipient_public_key_b64` (web `buildApprovalKeyBlob`,
/// file branch).
pub fn approve_request(
    invite_id: &str,
    file_id: &str,
    recipient_public_key_b64: &str,
    master: &MasterKey,
    file_key: &FileKey,
) -> Result<HttpRequest, ShareFlowError> {
    let invite_id = path_id(invite_id)?;
    let public: [u8; 32] = b64_decode(recipient_public_key_b64)?
        .as_slice()
        .try_into()
        .map_err(|_| ShareFlowError::Protocol("recipient key length"))?;
    let sealed = seal_file_key_for_member(master, &public, file_id, file_key)?;
    Ok(HttpRequest::post(
        &format!("{INVITES_PATH}/{invite_id}/approve"),
        json!({ "encrypted_file_key": b64(&sealed) }),
        RequestAuth::Session,
    ))
}

impl MemberInvite {
    /// `file_key` is the key that opens the row (the caller resolves it, as web's `shareFileKey`).
    pub fn start(
        target: &ShareTarget,
        email: &str,
        master: &MasterKey,
        file_key: &FileKey,
    ) -> Result<(Self, HttpRequest), ShareFlowError> {
        if target.is_folder {
            return Err(ShareFlowError::FolderInviteUnsupported);
        }
        let file_id = path_id(&target.item_id).map_err(|_| ShareFlowError::InvalidInput("item id"))?;
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
                    Some(key) if status == "claimed" => {
                        match approve_request(&invite_id, &self.file_id, key, &self.master, &self.file_key) {
                            Ok(req) => {
                                self.stage = Stage::AwaitApprove { invite_id };
                                Ok(InviteStep::Send(req))
                            }
                            Err(_) => Ok(InviteStep::Done(InviteOutcome::AwaitingApproval { invite_id })),
                        }
                    }
                    _ => Ok(InviteStep::Done(InviteOutcome::Invited { invite_id, status })),
                }
            }
            Stage::AwaitApprove { invite_id } => Ok(InviteStep::Done(if resp.ok() {
                InviteOutcome::Shared { invite_id }
            } else {
                InviteOutcome::AwaitingApproval { invite_id }
            })),
            Stage::Done => Err(ShareFlowError::WrongState),
        }
    }
}
