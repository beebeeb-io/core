//! Owner and shared-folder key envelopes for sync clients.
//!
//! Owner custody is AES-GCM under `derive_file_key(master, item_id.as_bytes())`;
//! shared-folder custody uses the existing random folder key directly. Both
//! use the established `nonce[12] || ciphertext[32] || tag[16]` frame. Item IDs
//! are canonical UUID strings, as in the web owner-custody format, never binary
//! UUID bytes. No new key is minted during resolution.

use crate::CoreError;
use crate::encrypt::{decrypt_chunk_raw, encrypt_chunk_raw};
use crate::kdf::{FileKey, MasterKey, derive_file_key};
use zeroize::Zeroizing;

/// The source of a resolved key; safe to inspect without exposing key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    Derived,
    OwnerWrap,
    FolderWrap,
}

/// A key is only a candidate until the caller authenticates the item's metadata
/// and completes content authentication before adopting or publishing it.
pub struct ResolvedOwnedKey {
    pub key: FileKey,
    pub origin: KeyOrigin,
}

pub struct FolderWrap<'a> {
    pub folder_key: &'a FileKey,
    pub wrapped_key: &'a [u8],
}

/// Seal a file or folder-name key to its owner's item-specific wrapping key.
pub fn wrap_key_to_owner(master: &MasterKey, item_id: &str, key: &FileKey) -> Result<Vec<u8>, CoreError> {
    let wrapping_key = derive_file_key(master, item_id.as_bytes());
    wrap_child_key(&wrapping_key, key)
}

/// Open the owner's canonical item envelope, independently of links or ancestry.
pub fn unwrap_owner_key(master: &MasterKey, item_id: &str, frame: &[u8]) -> Result<FileKey, CoreError> {
    let wrapping_key = derive_file_key(master, item_id.as_bytes());
    unwrap_child_key(&wrapping_key, frame)
}

/// Wrap an existing child key under the permanent random shared-folder key.
/// The core raw sealer draws a fresh OS-random nonce on every call.
pub fn wrap_child_key(folder_key: &FileKey, key: &FileKey) -> Result<Vec<u8>, CoreError> {
    encrypt_chunk_raw(folder_key, key.as_bytes())
}

/// Refuse malformed envelopes and wipe the decrypted temporary on every exit.
pub fn unwrap_child_key(folder_key: &FileKey, frame: &[u8]) -> Result<FileKey, CoreError> {
    if frame.len() != 60 {
        return Err(CoreError::Decryption);
    }
    let plaintext = Zeroizing::new(decrypt_chunk_raw(folder_key, frame)?);
    if plaintext.len() != 32 {
        return Err(CoreError::Decryption);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&plaintext);
    Ok(FileKey::from_bytes(*bytes))
}

/// Prefer owner custody, then shared-folder custody. A present owner envelope
/// or known foreign origin forbids falling back to the legacy derived key.
pub fn resolve_owned_key(
    master: &MasterKey,
    item_id: &str,
    owner_wrap: Option<&[u8]>,
    folder_wrap: Option<FolderWrap<'_>>,
    foreign_added: bool,
) -> Result<ResolvedOwnedKey, CoreError> {
    if let Some(frame) = owner_wrap {
        if let Ok(key) = unwrap_owner_key(master, item_id, frame) {
            return Ok(ResolvedOwnedKey {
                key,
                origin: KeyOrigin::OwnerWrap,
            });
        }
    }
    if let Some(wrap) = folder_wrap {
        if let Ok(key) = unwrap_child_key(wrap.folder_key, wrap.wrapped_key) {
            return Ok(ResolvedOwnedKey {
                key,
                origin: KeyOrigin::FolderWrap,
            });
        }
    }
    if owner_wrap.is_some() || foreign_added {
        return Err(CoreError::Decryption);
    }
    Ok(ResolvedOwnedKey {
        key: derive_file_key(master, item_id.as_bytes()),
        origin: KeyOrigin::Derived,
    })
}
