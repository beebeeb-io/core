//! Owner and shared-folder key envelopes for sync clients.
//!
//! Owner item-adoption envelopes use the L8 purpose key and AAD. Permanent
//! shared-root custody uses the distinct L6 purpose key and AAD. Shared child envelopes use L7 root/item/kind AAD;
//! the shared root is never inferred from an item's current parent. No key is
//! minted and no unbound child/custody reader is used as a fallback.
//!
//! # Item classes (task 2275)
//!
//! [`crate::item_id::ItemClass`] decides how a row's key is found:
//!
//! * **Owner** ids derive their key under the string, binary or read-only
//!   uppercase-repair convention (SF-0002). Child wraps and L8 envelopes are
//!   ignored for them. Upper-repair rows are read-only and get no
//!   [`WriteTarget`].
//! * **Foreign** ids are never derived. Their key comes from an L8 owner
//!   envelope or an L7 child wrap, and either key must authenticate the item's
//!   served name.
//!
//! [`WriteTarget`] is issued only for a row this module resolved, and carries
//! the id, the key and the name's chunk-format pin, so a replacement write
//! cannot be sealed under a guessed id or key.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::CoreError;
use crate::chunk_stream::ExpectedChunkFormat;
use crate::encrypt::{NameMetadata, decrypt_file_metadata_with_key};
use crate::kdf::{FileKey, MasterKey, OwnerKeyConvention, derive_file_key, resolve_owner_key_with};

/// The source of a resolved key; safe to inspect without exposing key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Derived under the canonical string id (the writable convention).
    Derived,
    /// Derived under the legacy 16-byte binary UUID (read/write).
    DerivedBinary,
    /// Derived under the uppercase id (SF-0002). READ-ONLY: no write target.
    DerivedUpperRepair,
    /// Opened from the row's L8 owner envelope.
    OwnerWrap,
    /// Opened from the row's L7 shared-folder child wrap.
    FolderWrap,
    /// The 2236 request-upload content key `C`.
    RequestContent,
}

impl KeyOrigin {
    /// Stable name for bindings and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "derived",
            Self::DerivedBinary => "derived_binary",
            Self::DerivedUpperRepair => "derived_upper_repair",
            Self::OwnerWrap => "owner_wrap",
            Self::FolderWrap => "folder_wrap",
            Self::RequestContent => "request_content",
        }
    }

    fn from_convention(convention: OwnerKeyConvention) -> Self {
        match convention {
            OwnerKeyConvention::String => Self::Derived,
            OwnerKeyConvention::Binary => Self::DerivedBinary,
            OwnerKeyConvention::UpperRepair => Self::DerivedUpperRepair,
        }
    }
}

/// The item's served name: either an authenticated encrypted envelope or the
/// legacy plaintext form (which authenticates nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedName {
    /// The name envelope opened under the row's key.
    Encrypted(NameMetadata),
    /// A plaintext legacy name. Carries no chunk-format pin.
    Plaintext(String),
}

impl ResolvedName {
    /// The chunk-format pin the name records, if any.
    pub fn pin(&self) -> ExpectedChunkFormat {
        match self {
            Self::Encrypted(meta) => meta.chunk_format,
            Self::Plaintext(_) => ExpectedChunkFormat::Unrecorded,
        }
    }

    /// The metadata, if the name was an encrypted envelope.
    pub fn metadata(&self) -> Option<&NameMetadata> {
        match self {
            Self::Encrypted(meta) => Some(meta),
            Self::Plaintext(_) => None,
        }
    }
}

/// The id, key and pin a replacement write must use (task 2275, L13).
///
/// Issued only by [`resolve_owned_key`] for a resolved, writable row. There is
/// no public constructor: a caller cannot point a write at an id or key core
/// did not resolve. Fields are private so the key cannot be swapped out.
pub struct WriteTarget {
    item_id: String,
    key: FileKey,
    pin: ExpectedChunkFormat,
}

impl WriteTarget {
    fn new(item_id: &str, key: &FileKey, pin: ExpectedChunkFormat) -> Self {
        Self {
            item_id: item_id.to_string(),
            key: FileKey::from_bytes(*key.as_bytes()),
            pin,
        }
    }

    /// The row id, canonical lowercase hyphenated.
    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    /// The key the write must be sealed under.
    pub fn key(&self) -> &FileKey {
        &self.key
    }

    /// The chunk-format pin the write must keep.
    pub fn pin(&self) -> ExpectedChunkFormat {
        self.pin
    }
}

impl std::fmt::Debug for WriteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteTarget")
            .field("item_id", &self.item_id)
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}

/// A resolved row.
pub struct ResolvedOwnedKey {
    /// The row's file key.
    pub key: FileKey,
    /// Where the key came from.
    pub origin: KeyOrigin,
    /// The served name, authenticated where it is an envelope.
    pub name: ResolvedName,
    /// The write target, or `None` when the row is read-only (upper-repair
    /// rows) — never `Some` for a foreign row without an authenticated name.
    pub write_target: Option<WriteTarget>,
}

impl std::fmt::Debug for ResolvedOwnedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedOwnedKey")
            .field("origin", &self.origin)
            .field("name", &self.name)
            .field("write_target", &self.write_target)
            .finish_non_exhaustive()
    }
}

/// The row's stored chunk 0, used to pick an owner id convention when the name
/// is plaintext (task 2275, L12).
pub struct FirstChunk<'a> {
    /// The frame's 12-byte nonce.
    pub nonce: &'a [u8],
    /// The frame's ciphertext plus tag.
    pub ciphertext: &'a [u8],
    /// The chunk index; only `0` can identify the key.
    pub index: u32,
}

/// The expected shared ROOT ID and item kind for the row. The child ID is
/// always resolve_owned_key's own item_id argument.
pub struct FolderWrap<'a> {
    pub shared_folder_id: &'a str,
    pub kind: u8,
    pub folder_key: &'a FileKey,
    pub wrapped_key: &'a [u8],
}

/// Seal an owner file-key adoption envelope with the L8 purpose key and AAD.
/// Item IDs use the same canonical UUID string bytes as L6 custody records.
///
/// Foreign item ids only; an owner id is [`CoreError::InvalidInput`].
pub fn wrap_owner_file_key(master: &MasterKey, item_id: &str, key: &FileKey) -> Result<Vec<u8>, CoreError> {
    Ok(key_frame(crate::kdf::wrap_owner_file_key(
        master,
        item_id.as_bytes(),
        key,
    )?))
}

/// Open only L8 owner adoption. No legacy name, content or owner-wrap fallback.
/// Foreign item ids only.
pub fn unwrap_owner_file_key(master: &MasterKey, item_id: &str, frame: &[u8]) -> Result<FileKey, CoreError> {
    crate::kdf::unwrap_owner_file_key(master, item_id.as_bytes(), &key_blob(frame)?)
}

/// Seal permanent shared-root custody through the L6 purpose key and AAD.
/// The record ID uses canonical UUID string bytes, matching C1's custody API.
pub fn wrap_folder_custody(master: &MasterKey, root_id: &str, key: &FileKey) -> Result<Vec<u8>, CoreError> {
    Ok(key_frame(crate::kdf::wrap_folder_custody(
        master,
        root_id.as_bytes(),
        key,
    )?))
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
    Ok(key_frame(crate::kdf::wrap_folder_child(
        folder_key,
        root.as_bytes(),
        item.as_bytes(),
        kind,
        key,
    )?))
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

/// L14: does this row's L7 child wrap open to exactly `expected`?
///
/// True only when the wrap opens under `folder_key` for this root/item/kind AND
/// the opened key equals `expected` in constant time. Any error (bad frame,
/// wrong root, wrong kind) is `false`. The opened key is zeroized on drop.
pub fn child_wrap_matches(
    folder_key: &FileKey,
    shared_folder_id: &str,
    item_id: &str,
    kind: u8,
    wrap: &[u8],
    expected: &FileKey,
) -> bool {
    let Ok(mut opened) = unwrap_child_key(folder_key, shared_folder_id, item_id, kind, wrap) else {
        return false;
    };
    let matched: bool = opened.as_bytes().ct_eq(expected.as_bytes()).into();
    opened.zeroize();
    matched
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

fn chunk_frame(first_chunk: &FirstChunk<'_>) -> Result<Vec<u8>, CoreError> {
    if first_chunk.index != 0 {
        return Err(CoreError::InvalidInput(
            "an owner file without an encrypted name is identified by chunk 0 only".into(),
        ));
    }
    let mut frame = Vec::with_capacity(first_chunk.nonce.len() + first_chunk.ciphertext.len());
    frame.extend_from_slice(first_chunk.nonce);
    frame.extend_from_slice(first_chunk.ciphertext);
    Ok(frame)
}

fn authenticated_name(key: &FileKey, name_encrypted: &str) -> Option<NameMetadata> {
    decrypt_file_metadata_with_key(key, name_encrypted).ok()
}

fn write_target(item_id: &str, key: &FileKey, origin: KeyOrigin, name: &ResolvedName) -> Option<WriteTarget> {
    match origin {
        KeyOrigin::DerivedUpperRepair | KeyOrigin::RequestContent => None,
        _ => Some(WriteTarget::new(item_id, key, name.pin())),
    }
}

/// Resolve a row's key from its id class, the served name and (for foreign
/// ids) the row's wraps (task 2275, L12/L13).
///
/// Owner id, encrypted name: string, then binary, then read-only upper-repair;
/// the first key that opens the name wins. `owner_wrap`/`folder_wrap` are
/// ignored entirely.
///
/// Owner id, plaintext name: a folder (`folder == true`) uses the string
/// convention; a file must present `first_chunk` (index 0) that authenticates
/// under one of the conventions; with no chunk it is an error.
///
/// Foreign id: the L8 `owner_wrap`, if it opens and the name authenticates,
/// else the L7 `folder_wrap` under the same conditions, else an error. A
/// derived key is never used for a foreign id.
pub fn resolve_owned_key(
    master: &MasterKey,
    item_id: &str,
    owner_wrap: Option<&[u8]>,
    folder_wrap: Option<FolderWrap<'_>>,
    name_encrypted: &str,
    first_chunk: Option<FirstChunk<'_>>,
) -> Result<ResolvedOwnedKey, CoreError> {
    match crate::item_id::item_class(item_id)? {
        crate::item_id::ItemClass::Owner => resolve_owner_row(master, item_id, name_encrypted, first_chunk),
        crate::item_id::ItemClass::Foreign => {
            resolve_foreign_row(master, item_id, owner_wrap, folder_wrap, name_encrypted)
        }
    }
}

fn resolve_owner_row(
    master: &MasterKey,
    item_id: &str,
    name_encrypted: &str,
    first_chunk: Option<FirstChunk<'_>>,
) -> Result<ResolvedOwnedKey, CoreError> {
    if name_encrypted.starts_with('{') {
        let (key, convention, meta) = resolve_owner_key_with(
            master,
            item_id,
            |key| authenticated_name(key, name_encrypted),
            "name does not authenticate under any known owner key convention",
        )?;
        let origin = KeyOrigin::from_convention(convention);
        let name = ResolvedName::Encrypted(meta);
        let target = write_target(item_id, &key, origin, &name);
        return Ok(ResolvedOwnedKey {
            key,
            origin,
            name,
            write_target: target,
        });
    }

    // A plaintext name proves nothing. No chunk means the caller declared a
    // folder; the string convention is the only writable owner convention for
    // one. A file must present chunk 0 and let it pick the convention.
    let plaintext = name_encrypted.to_string();
    let (key, origin) = match first_chunk {
        None => (derive_file_key(master, item_id.as_bytes()), KeyOrigin::Derived),
        Some(chunk) => {
            let frame = chunk_frame(&chunk)?;
            let (key, convention) = crate::kdf::owner_file_key_for_content(master, item_id, &frame)?;
            (key, KeyOrigin::from_convention(convention))
        }
    };
    let name = ResolvedName::Plaintext(plaintext);
    let target = write_target(item_id, &key, origin, &name);
    Ok(ResolvedOwnedKey {
        key,
        origin,
        name,
        write_target: target,
    })
}

fn resolve_foreign_row(
    master: &MasterKey,
    item_id: &str,
    owner_wrap: Option<&[u8]>,
    folder_wrap: Option<FolderWrap<'_>>,
    name_encrypted: &str,
) -> Result<ResolvedOwnedKey, CoreError> {
    if name_encrypted.starts_with('{') {
        if let Some(frame) = owner_wrap {
            if let Ok(key) = unwrap_owner_file_key(master, item_id, frame) {
                if let Some(meta) = authenticated_name(&key, name_encrypted) {
                    let name = ResolvedName::Encrypted(meta);
                    let target = write_target(item_id, &key, KeyOrigin::OwnerWrap, &name);
                    return Ok(ResolvedOwnedKey {
                        key,
                        origin: KeyOrigin::OwnerWrap,
                        name,
                        write_target: target,
                    });
                }
            }
        }
        if let Some(wrap) = folder_wrap {
            if let Ok(key) = unwrap_child_key(
                wrap.folder_key,
                wrap.shared_folder_id,
                item_id,
                wrap.kind,
                wrap.wrapped_key,
            ) {
                if let Some(meta) = authenticated_name(&key, name_encrypted) {
                    let name = ResolvedName::Encrypted(meta);
                    let target = write_target(item_id, &key, KeyOrigin::FolderWrap, &name);
                    return Ok(ResolvedOwnedKey {
                        key,
                        origin: KeyOrigin::FolderWrap,
                        name,
                        write_target: target,
                    });
                }
            }
        }
    }
    Err(CoreError::InvalidInput(
        "foreign item id has no owner envelope or child wrap that opens and authenticates its name".into(),
    ))
}

/// A 2236 request-upload row: the uploader sealed a content key `C` to the
/// owner's request key, and the row is read-only content-wise.
pub struct RequestRowKeys {
    /// The upload's content key `C`.
    pub content_key: FileKey,
    /// The key that authenticates the name.
    pub name_key: FileKey,
    /// Where the name key came from (`Derived`, `DerivedBinary` or
    /// `RequestContent`).
    pub name_origin: KeyOrigin,
    /// The authenticated name metadata.
    pub name: NameMetadata,
}

/// Resolve a 2236 request row (task 2275, §4): content under `C`, name under a
/// derived owner convention or under `C`. Request rows are read-only and never
/// carry a [`WriteTarget`].
#[allow(clippy::too_many_arguments)]
pub fn resolve_request_row(
    master: &MasterKey,
    item_id: &str,
    request_id: &[u8],
    wrapped_request_private: &[u8],
    wrap_nonce: &[u8],
    sender_ephemeral_pubkey: &[u8; 32],
    wrapped_content_key: &[u8],
    name_encrypted: &str,
) -> Result<RequestRowKeys, CoreError> {
    if !name_encrypted.starts_with('{') {
        return Err(CoreError::InvalidInput(
            "a request row's name must be an encrypted envelope".into(),
        ));
    }
    let request_private =
        crate::file_request::unwrap_request_private(master, request_id, wrapped_request_private, wrap_nonce)?;
    let content = crate::file_request::open_request_upload(
        &request_private,
        sender_ephemeral_pubkey,
        item_id.as_bytes(),
        wrapped_content_key,
    )?;
    let content_key = FileKey::from_bytes(*content);

    if crate::item_id::item_class(item_id)? == crate::item_id::ItemClass::Owner {
        let derived = resolve_owner_key_with(
            master,
            item_id,
            |key| authenticated_name(key, name_encrypted),
            "request row name does not authenticate",
        );
        if let Ok((key, convention, meta)) = derived {
            return Ok(RequestRowKeys {
                content_key,
                name_key: key,
                name_origin: KeyOrigin::from_convention(convention),
                name: meta,
            });
        }
    }
    if let Some(meta) = authenticated_name(&content_key, name_encrypted) {
        return Ok(RequestRowKeys {
            content_key: FileKey::from_bytes(*content_key.as_bytes()),
            name_key: content_key,
            name_origin: KeyOrigin::RequestContent,
            name: meta,
        });
    }
    Err(CoreError::InvalidInput(
        "request row name does not authenticate under a derived key or the content key".into(),
    ))
}
