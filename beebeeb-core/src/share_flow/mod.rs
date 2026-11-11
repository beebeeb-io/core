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
//!   A folder through this path is refused; folders go through [`folder`].
//! - [`folder`]: a person share of a folder, with the task-2133 key rules ([`folder_keys`]): one
//!   key per folder (custody record, else the newest active invite's owner copy that opens), never
//!   minted while an active invite has no provable owner copy, L7 or legacy child wraps by the
//!   folder's custody state, and `folder_key_id` on the invite.
//!   [`folder::FolderShare::link`] is a live folder link over the same custody key.
//! - [`request`]: a file request (a per-request X25519 keypair, `R_priv` wrapped under the master key).
//! - [`bundle`]: one link over an ordered set of files (the file-link token leg, many items).
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

pub mod access;
pub mod bundle;
pub mod folder;
pub mod folder_keys;
pub mod link;
pub mod member;
pub mod request;
pub mod safety;

#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod folder_tests;
#[cfg(test)]
mod safety_tests;
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
    /// The folder (or a folder above it) was seen with a custody record and the server now says it
    /// has none (L7c/L7d), or the folder id is no UUID. Never falls back to the legacy format.
    FolderKeysUnavailable,
    /// The folder has active invites but no owner copy opens with proof (task 2133): never mint.
    FolderKeyUnverified,
    /// The folder has flag-off invites and no custody record; its keys need the upgrade first.
    FolderNeedsUpgrade,
    /// More descendants than a share can carry, or a server that cannot page them all.
    FolderTooLarge,
    /// A typed server refusal, one of [`SHARE_REFUSAL_CODES`].
    Refused(&'static str),
    NotFound,
    /// A 401: the session is not accepted. A 403 is [`Self::Forbidden`].
    Unauthorized,
    /// A 403 refusal, never the session: `code` is the server's own (`sharing_paused`,
    /// `email_unverified`, `billing_read_only`, ...), or `forbidden` when the body names no code.
    /// [`Self::code`] is `forbidden`; [`Self::host_code`] is `code`.
    Forbidden {
        code: String,
    },
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
    /// The server's key for a person is not the one the host's "compared" mark was made against:
    /// nothing was sealed (B05e).
    PeerKeyChanged,
}

impl ShareFlowError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::FolderKeysUnavailable => "folder_keys_unavailable",
            Self::FolderKeyUnverified => "folder_key_unverified",
            Self::FolderNeedsUpgrade => "folder_needs_upgrade",
            Self::FolderTooLarge => "folder_too_large",
            Self::Refused(code) => code,
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden { .. } => "forbidden",
            Self::RateLimited { .. } => "rate_limited",
            Self::Server { .. } => "server",
            Self::Protocol(_) => "protocol",
            Self::Crypto => "crypto",
            Self::WrongState => "wrong_state",
            Self::PeerKeyChanged => "peer_key_changed",
        }
    }

    /// The code a host maps to copy: the server's own for [`Self::Forbidden`], else [`Self::code`].
    pub fn host_code(&self) -> &str {
        match self {
            Self::Forbidden { code } => code,
            other => other.code(),
        }
    }

    /// The error for a non-2xx answer: a typed refusal keeps its code; otherwise by status.
    pub fn from_status(resp: &HttpResponse) -> Self {
        let code = body_code(resp);
        if let Some(known) = code.and_then(|c| SHARE_REFUSAL_CODES.iter().find(|k| **k == c)) {
            return Self::Refused(known);
        }
        match resp.status {
            401 => Self::Unauthorized,
            403 => Self::Forbidden {
                code: code.filter(|c| is_wire_code(c)).unwrap_or("forbidden").to_owned(),
            },
            404 => Self::NotFound,
            429 => Self::RateLimited {
                retry_after_secs: resp.retry_after_secs.unwrap_or(30),
            },
            status => Self::Server { status },
        }
    }
}

/// A refusal's code: `code`, else `error` (the server's two-field contract).
pub(crate) fn body_code(resp: &HttpResponse) -> Option<&str> {
    resp.body
        .get("code")
        .and_then(|v| v.as_str())
        .or_else(|| resp.body.get("error").and_then(|v| v.as_str()))
}

/// A stable code, not text: an older server's account-frozen 403 puts a sentence in `error`, which is
/// never kept (a newer one sends `account_frozen`).
fn is_wire_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

impl fmt::Display for ShareFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(why) => write!(f, "invalid_input ({why})"),
            Self::Forbidden { code } => write!(f, "forbidden ({code})"),
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

/// An item id that is HKDF info or an invite match key: it must already be a canonical lower-case
/// hyphenated UUID, else `InvalidInput(what)`. Never normalized: a different spelling of the same
/// UUID would derive a different key and miss the server's invite rows (item-id "Never break").
pub(crate) fn canonical_item_id<'a>(id: &'a str, what: &'static str) -> Result<&'a str, ShareFlowError> {
    match uuid::Uuid::parse_str(id) {
        Ok(u) if u.hyphenated().to_string() == id => Ok(id),
        _ => Err(ShareFlowError::InvalidInput(what)),
    }
}

pub(crate) fn frame(blob: EncryptedBlob) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.ciphertext);
    out
}

pub(crate) fn split(frame: &[u8]) -> Result<EncryptedBlob, ShareFlowError> {
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
pub(crate) fn seal_file_key_for_member(
    master: &MasterKey,
    recipient_public: &[u8; 32],
    file_id: &str,
    file_key: &FileKey,
) -> Result<Vec<u8>, ShareFlowError> {
    let file_id = canonical_item_id(file_id, "file id")?;
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
    let file_id = canonical_item_id(file_id, "file id")?;
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
    MasterKey::from_bytes(*master.to_bytes())
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
