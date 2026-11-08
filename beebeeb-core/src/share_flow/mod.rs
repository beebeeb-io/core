//! Share flows as plain logic, shared by desktop (Rust), mobile (UniFFI) and web (WASM).
//!
//! Ported from web (`src/lib/crypto.ts`, `share-dialog.tsx`, `share-link.ts`,
//! `approve-invite-crypto.ts`) with byte-identical output; web's `test/share-wrap-kat.test.ts`
//! vectors are pinned in this module's tests. Like [`crate::auth_flow`] every flow is **sans-IO**:
//! it hands the caller an [`HttpRequest`] and takes the [`HttpResponse`] back.
//!
//! ```mermaid
//! flowchart LR
//!   A[member::MemberInvite] -->|POST /shares/invites| S[(server)]
//!   S -->|claimed + recipient key| B[seal file key for recipient]
//!   B -->|POST /shares/invites/id/approve| S
//!   C[link::CreateLink] -->|POST /shares: wrapped_file_key, owner blobs, token| S
//!   S -->|id| D[full link: /s/token#key=K_c]
//! ```
//!
//! - [`member`]: a person share of one file. The file key is sealed for the recipient with
//!   X25519 + HKDF (`beebeeb-share`, info = the file id) + AES-256-GCM, `nonce(12) || ciphertext`.
//!   A folder invite needs the folder-key rules of task 2133 and is not ported yet: asking for
//!   one is [`ShareFlowError::FolderInviteUnsupported`], never a silent file share.
//! - [`link`]: a double-encrypted public link. A random client key `K_c` wraps the file key
//!   (`nonce(12) || ciphertext(48)`, no AAD); `K_c` and the raw token are also wrapped under the
//!   owner's master key so the owner can rebuild the link later. `K_c` lives only in the link's
//!   `#key=` fragment.
//!
//! Secrets (master key, file keys, `K_c`, the full link) are held in zeroizing buffers and never
//! appear in a `Debug` print or an error. Errors are codes; a server body is never echoed.
use std::fmt;

use base64::Engine;
use beebeeb_types::{CipherSuite, EncryptedBlob};
use zeroize::Zeroizing;

use crate::auth_flow::{HttpRequest, HttpResponse};
use crate::encrypt::{decrypt_chunk, encrypt_chunk};
use crate::kdf::{FileKey, MasterKey};
use crate::opaque::{derive_share_key, derive_x25519_private, x25519_shared_secret};

pub mod link;
pub mod member;

#[cfg(test)]
mod tests;

/// `nonce(12) || ciphertext(32) || tag(16)`: a wrapped 32-byte key.
pub const WRAPPED_KEY_LEN: usize = 60;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The typed 409 refusals the server gives for sharing (web `SHARE_REFUSAL_CODES`).
pub const SHARE_REFUSAL_CODES: [&str; 6] = [
    "trial_sharing_unavailable",
    "trial_share_limit_reached",
    "plan_required",
    "account_lapsed",
    "trial_ended",
    "trial_cancelled_read_only",
];

/// Why a share flow stopped. `code()` is the stable string a host maps to copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareFlowError {
    InvalidInput(&'static str),
    /// Folder invites are not ported to core yet (they carry `folder_key_id` and the 2133 rules).
    FolderInviteUnsupported,
    /// A typed server refusal, one of [`SHARE_REFUSAL_CODES`].
    Refused(&'static str),
    NotFound,
    Unauthorized,
    RateLimited {
        retry_after_secs: u64,
    },
    Server {
        status: u16,
    },
    Protocol(&'static str),
    /// A wrap or unwrap failed (wrong key, a damaged blob). Never says which byte.
    Crypto,
    WrongState,
}

impl ShareFlowError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::FolderInviteUnsupported => "folder_invite_unsupported",
            Self::Refused(code) => code,
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::RateLimited { .. } => "rate_limited",
            Self::Server { .. } => "server",
            Self::Protocol(_) => "protocol",
            Self::Crypto => "crypto",
            Self::WrongState => "wrong_state",
        }
    }

    /// The error for a non-2xx answer: a typed refusal keeps its code; otherwise by status.
    pub fn from_status(resp: &HttpResponse) -> Self {
        let code = resp
            .body
            .get("code")
            .and_then(|v| v.as_str())
            .or_else(|| resp.body.get("error").and_then(|v| v.as_str()));
        if let Some(known) = code.and_then(|c| SHARE_REFUSAL_CODES.iter().find(|k| **k == c)) {
            return Self::Refused(known);
        }
        match resp.status {
            401 | 403 => Self::Unauthorized,
            404 => Self::NotFound,
            429 => Self::RateLimited {
                retry_after_secs: resp.retry_after_secs.unwrap_or(30),
            },
            status => Self::Server { status },
        }
    }
}

impl fmt::Display for ShareFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(why) => write!(f, "invalid_input ({why})"),
            Self::Protocol(why) => write!(f, "protocol ({why})"),
            Self::Server { status } => write!(f, "server ({status})"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for ShareFlowError {}

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, ShareFlowError> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| ShareFlowError::Protocol("invalid base64"))
}

/// A server-issued id that goes into a path: hex digits and `-` only, so it cannot add a segment.
pub(crate) fn path_id(id: &str) -> Result<&str, ShareFlowError> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(ShareFlowError::Protocol("bad id"));
    }
    Ok(id)
}

fn frame(blob: EncryptedBlob) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.ciphertext);
    out
}

fn split(frame: &[u8]) -> Result<EncryptedBlob, ShareFlowError> {
    if frame.len() < NONCE_LEN + TAG_LEN {
        return Err(ShareFlowError::Crypto);
    }
    Ok(EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: frame[..NONCE_LEN].to_vec(),
        ciphertext: frame[NONCE_LEN..].to_vec(),
    })
}

/// Web's `wrapKeyForShare`: AES-256-GCM under the raw 32-byte `wrap_key`, random nonce, no AAD.
/// Returns `nonce(12) || ciphertext || tag(16)` (60 bytes for a 32-byte key).
pub fn wrap_key_for_share(wrap_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ShareFlowError> {
    let key = FileKey::from_bytes(*wrap_key);
    encrypt_chunk(&key, plaintext)
        .map(frame)
        .map_err(|_| ShareFlowError::Crypto)
}

/// Web's `unwrapKeyFromShare`: the inverse of [`wrap_key_for_share`].
pub fn unwrap_key_from_share(wrap_key: &[u8; 32], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, ShareFlowError> {
    let key = FileKey::from_bytes(*wrap_key);
    decrypt_chunk(&key, &split(wrapped)?)
        .map(Zeroizing::new)
        .map_err(|_| ShareFlowError::Crypto)
}

fn member_share_key(master: &MasterKey, peer_public: &[u8; 32], file_id: &str) -> Result<FileKey, ShareFlowError> {
    let private = derive_x25519_private(master);
    let shared = x25519_shared_secret(&private, peer_public).map_err(|_| ShareFlowError::Crypto)?;
    let share_key = derive_share_key(&shared, file_id.as_bytes());
    Ok(FileKey::from_bytes(*share_key))
}

/// Web's `encryptFileKeyForSharing` + the `nonce || ciphertext` concatenation the invite approval
/// sends: the owner seals `file_key` for the recipient's X25519 public key.
pub fn seal_file_key_for_member(
    master: &MasterKey,
    recipient_public: &[u8; 32],
    file_id: &str,
    file_key: &FileKey,
) -> Result<Vec<u8>, ShareFlowError> {
    let share_key = member_share_key(master, recipient_public, file_id)?;
    encrypt_chunk(&share_key, file_key.as_bytes())
        .map(frame)
        .map_err(|_| ShareFlowError::Crypto)
}

/// The recipient side of [`seal_file_key_for_member`]: open with the recipient's master key and the
/// owner's X25519 public key.
pub fn open_member_file_key(
    master: &MasterKey,
    owner_public: &[u8; 32],
    file_id: &str,
    sealed: &[u8],
) -> Result<FileKey, ShareFlowError> {
    let share_key = member_share_key(master, owner_public, file_id)?;
    let plain = Zeroizing::new(decrypt_chunk(&share_key, &split(sealed)?).map_err(|_| ShareFlowError::Crypto)?);
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| ShareFlowError::Crypto)?;
    Ok(FileKey::from_bytes(bytes))
}

/// The display form of a share link: everything before `#`. The key part never leaves Rust.
pub fn display_form(link: &str) -> String {
    link.split('#').next().unwrap_or_default().to_owned()
}

/// Copy a master key into a value the flow owns (wiped on drop).
pub(crate) fn own_master(master: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(master.to_bytes())
}

pub(crate) fn own_file_key(key: &FileKey) -> FileKey {
    FileKey::from_bytes(*key.as_bytes())
}

pub(crate) fn require_ok(resp: &HttpResponse) -> Result<(), ShareFlowError> {
    if resp.ok() {
        Ok(())
    } else {
        Err(ShareFlowError::from_status(resp))
    }
}

pub(crate) fn str_field<'a>(resp: &'a HttpResponse, key: &str) -> Result<&'a str, ShareFlowError> {
    resp.body
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(ShareFlowError::Protocol("missing field"))
}

/// `DELETE /api/v1/shares/{id}`: revoke a link (no crypto; here so every client sends the same).
pub fn revoke_link_request(share_id: &str) -> Result<HttpRequest, ShareFlowError> {
    Ok(HttpRequest::delete(
        format!("/api/v1/shares/{}", path_id(share_id)?),
        crate::auth_flow::RequestAuth::Session,
    ))
}

/// `DELETE /api/v1/shares/invites/{id}`: cancel a person share.
pub fn cancel_invite_request(invite_id: &str) -> Result<HttpRequest, ShareFlowError> {
    Ok(HttpRequest::delete(
        format!("/api/v1/shares/invites/{}", path_id(invite_id)?),
        crate::auth_flow::RequestAuth::Session,
    ))
}
