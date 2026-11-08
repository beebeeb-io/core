//! The folder-key rules a folder invite runs on (web `folder-share-crypto.ts`, `custody-memory.ts`).
//!
//! - **Custody memory** (decisions L7c/L7d): once a device has seen a valid custody record for a
//!   folder, "no record" for it, or for any folder under it, is
//!   [`ShareFlowError::FolderKeysUnavailable`], never the legacy format. The host keeps the set
//!   durably (web: `localStorage` key `beebeeb.custodySeen.v1`); the flow reads it and asks the
//!   host to add an id with every step that carries one.
//! - **Active invites** (task 2133): a folder's invites with status `invited`, `claimed` or
//!   `approved`, newest first by `created_at`. `expires_at` is ignored on purpose: a skewed clock
//!   must never decide to mint a new key.
//! - **Child wraps:** L7 (bound to shared root, item and kind) for a folder with custody; the
//!   legacy unbound wrap (`nonce || ct`, no AAD) only for a flag-off invite-only folder (L7b).
use std::collections::BTreeSet;

use serde_json::Value;

use super::{ShareFlowError, b64, frame};
use crate::kdf::{self, FileKey, MasterKey};

/// L7 child kind of a file (web `FOLDER_CHILD_FILE`).
pub const FOLDER_CHILD_FILE: u8 = 1;
/// L7 child kind of a folder (web `FOLDER_CHILD_FOLDER`).
pub const FOLDER_CHILD_FOLDER: u8 = 2;
/// Web `MAX_ANCESTOR_WALK`.
pub const MAX_ANCESTOR_WALK: usize = 64;
/// Web `SHARE_PAGE_LIMIT`: the page size the descendant listing asks for.
pub const SHARE_PAGE_LIMIT: usize = 500;
/// Web `FILE_LIST_HARD_CAP`: more descendants than this is refused, never half-shared.
pub const FILE_LIST_HARD_CAP: usize = 50_000;

const ACTIVE_STATUSES: [&str; 3] = ["invited", "claimed", "approved"];

/// A folder id in its canonical form (lower-case, hyphenated), from any form a UUID parser takes
/// (simple, braced, `urn:uuid:`). `None` for an id that is no UUID: it counts as seen (it refuses).
pub fn canonical_folder_id(id: &str) -> Option<String> {
    uuid::Uuid::parse_str(id).ok().map(|u| u.hyphenated().to_string())
}

/// The device's custody memory, as the host stored it. `unreadable` is a stored value that exists
/// but is not a list of canonical UUIDs: it might have held any folder, so it counts as all of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustodyMemory {
    pub seen: BTreeSet<String>,
    pub unreadable: bool,
}

impl CustodyMemory {
    pub fn new<I: IntoIterator<Item = String>>(ids: I, unreadable: bool) -> Self {
        Self {
            seen: ids.into_iter().filter_map(|id| canonical_folder_id(&id)).collect(),
            unreadable,
        }
    }

    /// Seen with custody, in any form of its id. An id that is no UUID counts as seen.
    pub fn has_seen(&self, folder_id: &str) -> bool {
        match canonical_folder_id(folder_id) {
            Some(id) => self.unreadable || self.seen.contains(&id),
            None => true,
        }
    }

    /// Whether this device has seen custody for any folder at all.
    pub fn has_any(&self) -> bool {
        self.unreadable || !self.seen.is_empty()
    }

    pub(crate) fn mark(&mut self, folder_id: &str) -> Result<String, ShareFlowError> {
        let id = canonical_folder_id(folder_id).ok_or(ShareFlowError::FolderKeysUnavailable)?;
        self.seen.insert(id.clone());
        Ok(id)
    }
}

/// One row of `GET /api/v1/shares/invites/sent`, the fields the key rules read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentInvite {
    pub id: String,
    pub status: String,
    pub created_at: String,
    pub owner_blob: Option<String>,
}

/// Web `activeFolderInvites`: this folder's folder invites, active by status, newest first.
pub fn active_folder_invites(body: &Value, folder_id: &str) -> Result<Vec<SentInvite>, ShareFlowError> {
    let list = body
        .get("invites")
        .and_then(Value::as_array)
        .ok_or(ShareFlowError::Protocol("invites list"))?;
    let mut out: Vec<SentInvite> = list
        .iter()
        .filter(|i| i.get("is_folder_share").and_then(Value::as_bool) == Some(true))
        .filter(|i| i.get("file_id").and_then(Value::as_str) == Some(folder_id))
        .filter(|i| {
            i.get("status")
                .and_then(Value::as_str)
                .is_some_and(|s| ACTIVE_STATUSES.contains(&s))
        })
        .map(|i| SentInvite {
            id: i.get("id").and_then(Value::as_str).unwrap_or_default().to_owned(),
            status: i.get("status").and_then(Value::as_str).unwrap_or_default().to_owned(),
            created_at: i
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            owner_blob: i
                .get("encrypted_owner_folder_key")
                .and_then(Value::as_str)
                .filter(|b| !b.is_empty())
                .map(str::to_owned),
        })
        .collect();
    // Newest first; a stable sort keeps the server's order for equal timestamps, as web's does.
    out.sort_by(|x, y| y.created_at.cmp(&x.created_at));
    Ok(out)
}

/// Web `uniqueOwnerBlobs`: the owner blobs of `active`, newest first, each once.
pub fn unique_owner_blobs(active: &[SentInvite]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    active
        .iter()
        .filter_map(|i| i.owner_blob.clone())
        .filter(|b| seen.insert(b.clone()))
        .collect()
}

/// The folder's wrap format (L7b): a fact about the folder, never chosen by trying one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderWrapFormat {
    /// The folder has a custody record: L7 child wraps, `format: "l7"` on the wire.
    L7,
    /// A flag-off invite-only folder: legacy unbound child wraps, no `format` field.
    LegacyInvite,
}

fn uuid_bytes(id: &str, what: &'static str) -> Result<[u8; 16], ShareFlowError> {
    uuid::Uuid::parse_str(id)
        .map(|u| *u.as_bytes())
        .map_err(|_| ShareFlowError::InvalidInput(what))
}

/// Web `sealFolderChild`: one child key sealed under the folder key in the folder's format, base64.
pub fn seal_folder_child(
    format: FolderWrapFormat,
    folder_key: &FileKey,
    root_id: &str,
    item_id: &str,
    is_folder: bool,
    child_key: &FileKey,
) -> Result<String, ShareFlowError> {
    match format {
        FolderWrapFormat::L7 => {
            let kind = if is_folder {
                FOLDER_CHILD_FOLDER
            } else {
                FOLDER_CHILD_FILE
            };
            let root = uuid_bytes(root_id, "root id")?;
            let item = uuid_bytes(item_id, "item id")?;
            kdf::wrap_folder_child(folder_key, &root, &item, kind, child_key)
                .map(|b| b64(&frame(b)))
                .map_err(|_| ShareFlowError::Crypto)
        }
        FolderWrapFormat::LegacyInvite => crate::encrypt::encrypt_chunk(folder_key, child_key.as_bytes())
            .map(|b| b64(&frame(b)))
            .map_err(|_| ShareFlowError::Crypto),
    }
}

/// Web `encryptOwnerFolderKey`: the owner's purpose-bound copy on an invite (2255), base64.
pub fn owner_copy_b64(master: &MasterKey, folder_id: &str, folder_key: &FileKey) -> Result<String, ShareFlowError> {
    kdf::wrap_invite_owner_copy(master, folder_id.as_bytes(), folder_key)
        .map(|b| b64(&frame(b)))
        .map_err(|_| ShareFlowError::Crypto)
}

/// Web `folderKeyId`: standard base64 (padded) of core's 32-byte `folder_key_id`.
pub fn folder_key_id_b64(folder_key: &FileKey) -> String {
    b64(&crate::folder_key::folder_key_id(folder_key.as_bytes()))
}

/// The outcome of opening one owner copy in its purpose-bound format.
pub(crate) enum OwnerCopyOpen {
    Opened(FileKey),
    /// An authentication failure: only this may fall through to the legacy proof.
    AuthFailed,
}

/// Web `openOwnerCopy`, first half: the purpose-bound format. A copy that is not 60 bytes reads as an
/// authentication failure, as core's WASM export says it.
pub(crate) fn open_owner_copy(
    master: &MasterKey,
    folder_id: &str,
    blob: &[u8],
) -> Result<OwnerCopyOpen, ShareFlowError> {
    if blob.len() != super::WRAPPED_KEY_LEN {
        return Ok(OwnerCopyOpen::AuthFailed);
    }
    match kdf::unwrap_invite_owner_copy(master, folder_id.as_bytes(), &super::split(blob)?) {
        Ok(key) => Ok(OwnerCopyOpen::Opened(key)),
        Err(crate::error::CoreError::Decryption) => Ok(OwnerCopyOpen::AuthFailed),
        Err(_) => Err(ShareFlowError::Crypto),
    }
}

/// The folder's rows for a legacy proof (`GET …/folder-keys`): `(file_id bytes, wrap bytes)`.
/// A malformed row reads as an empty id or wrap, which core skips (as the WASM export does).
/// `(file_id bytes, wrap bytes)` rows for core's legacy proof.
pub(crate) type ProofRows = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) fn proof_rows(body: &Value) -> Result<ProofRows, ShareFlowError> {
    let keys = body
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(ShareFlowError::Protocol("folder keys"))?;
    Ok(keys
        .iter()
        .map(|row| {
            let field = |n: &str| row.get(n).and_then(Value::as_str).unwrap_or_default();
            let wrap = super::b64_decode(field("encrypted_file_key")).unwrap_or_default();
            (field("file_id").as_bytes().to_vec(), wrap)
        })
        .collect())
}
