//! Owner and shared-folder key envelopes for sync clients.
//!
//! Owner item-adoption envelopes keep their established file-key format. They
//! are distinct from permanent shared-root custody, which MUST use the L6
//! custody adapters below. Shared child envelopes use L7 root/item/kind AAD;
//! the shared root is never inferred from an item's current parent. No key is
//! minted and no unbound child/custody reader is used as a fallback.

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

/// Context from the row's authenticated shared-folder inventory: root ID and
/// item kind. The child ID is always resolve_owned_key's own item_id argument.
pub struct FolderWrap<'a> {
    pub shared_folder_id: &'a str,
    pub kind: u8,
    pub folder_key: &'a FileKey,
    pub wrapped_key: &'a [u8],
}

/// Seal an item-adoption key to the owner's item-specific wrapping key.
/// This is the established owner_wrapped_file_key format, NOT permanent root
/// custody. Use [`wrap_folder_custody`] for shared_folders custody records.
pub fn wrap_key_to_owner(master: &MasterKey, item_id: &str, key: &FileKey) -> Result<Vec<u8>, CoreError> {
    let wrapping_key = derive_file_key(master, item_id.as_bytes());
    encrypt_chunk_raw(&wrapping_key, key.as_bytes())
}

/// Open an owner_wrapped_file_key item-adoption envelope, independently of links
/// or ancestry. Permanent shared-root custody uses [`unwrap_folder_custody`].
pub fn unwrap_owner_key(master: &MasterKey, item_id: &str, frame: &[u8]) -> Result<FileKey, CoreError> {
    let wrapping_key = derive_file_key(master, item_id.as_bytes());
    unwrap_item_owner_frame(&wrapping_key, frame)
}

/// Seal permanent shared-root custody through the L6 purpose key and AAD.
/// The record ID uses canonical UUID string bytes, matching C1's custody API.
pub fn wrap_folder_custody(master: &MasterKey, root_id: &str, key: &FileKey) -> Result<Vec<u8>, CoreError> {
    Ok(key_frame(crate::kdf::wrap_folder_custody(master, root_id.as_bytes(), key)?))
}

/// Open only L6 custody. Legacy invite seeds must be read explicitly elsewhere;
/// a permanent custody record never falls back to a legacy item/name frame.
pub fn unwrap_folder_custody(master: &MasterKey, root_id: &str, frame: &[u8]) -> Result<FileKey, CoreError> {
    crate::kdf::unwrap_folder_custody(master, root_id.as_bytes(), &key_blob(frame)?)
}

/// Wrap a child key under L7: shared ROOT UUID, item UUID and kind (1=file,
/// 2=folder). IDs are converted to the 16-byte UUIDs required by C1.
pub fn wrap_child_key(
    folder_key: &FileKey,
    shared_folder_id: &str,
    item_id: &str,
    kind: u8,
    key: &FileKey,
) -> Result<Vec<u8>, CoreError> {
    let root = child_uuid(shared_folder_id)?;
    let item = child_uuid(item_id)?;
    Ok(key_frame(crate::kdf::wrap_folder_child(folder_key, root.as_bytes(), item.as_bytes(), kind, key)?))
}

/// Open only the row's L7 root/item/kind-bound child envelope.
pub fn unwrap_child_key(
    folder_key: &FileKey,
    shared_folder_id: &str,
    item_id: &str,
    kind: u8,
    frame: &[u8],
) -> Result<FileKey, CoreError> {
    let root = child_uuid(shared_folder_id)?;
    let item = child_uuid(item_id)?;
    crate::kdf::unwrap_folder_child(folder_key, root.as_bytes(), item.as_bytes(), kind, &key_blob(frame)?)
}

fn child_uuid(id: &str) -> Result<uuid::Uuid, CoreError> {
    uuid::Uuid::parse_str(id).map_err(|_| CoreError::InvalidInput("child wrap requires a UUID".into()))
}

fn key_blob(frame: &[u8]) -> Result<beebeeb_types::EncryptedBlob, CoreError> {
    if frame.len() != 60 {
        return Err(CoreError::Decryption);
    }
    Ok(beebeeb_types::EncryptedBlob {
        cipher_suite: beebeeb_types::CipherSuite::V1Aes256Gcm,
        nonce: frame[..12].to_vec(),
        ciphertext: frame[12..].to_vec(),
    })
}

fn key_frame(blob: beebeeb_types::EncryptedBlob) -> Vec<u8> {
    let mut frame = blob.nonce;
    frame.extend_from_slice(&blob.ciphertext);
    frame
}

// Existing owner-file adoption frame. This is not permanent root custody.
fn unwrap_item_owner_frame(folder_key: &FileKey, frame: &[u8]) -> Result<FileKey, CoreError> {
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

/// Prefer owner item adoption, then an L7 shared-folder child envelope. A present owner envelope
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
        if let Ok(key) = unwrap_child_key(wrap.folder_key, wrap.shared_folder_id, item_id, wrap.kind, wrap.wrapped_key) {
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
