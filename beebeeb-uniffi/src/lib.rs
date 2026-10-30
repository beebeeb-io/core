use std::sync::{Arc, Mutex};

use zeroize::{Zeroize, Zeroizing};

use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor, ChunkFormat, ExpectedChunkFormat, SessionResume};
use beebeeb_core::client_meta;
use beebeeb_core::constellation;
use beebeeb_core::encrypt;
use beebeeb_core::kdf;
use beebeeb_core::media;
use beebeeb_core::recovery;
use beebeeb_types::{CipherSuite, EncryptedBlob};

uniffi::setup_scaffolding!();

#[cfg(test)]
mod folder_link_2237c {
    use super::*;

    #[test]
    fn invite_2255_proof_and_owner_copy_through_handles() {
        let v = vector("invite_owner_copy_v1");
        let master = MasterKeyHandle::from_keychain_bytes(bytes(&v, "master_key_hex")).unwrap();
        let wire = bytes(&v, "wrapped_hex");
        let folder_id = v["record_id"].as_str().unwrap().to_string();
        let key = master
            .unwrap_invite_owner_copy(folder_id.clone(), wire[..12].to_vec(), wire[12..].to_vec())
            .unwrap();
        assert_eq!(key.key_id().unwrap(), id(bytes(&v, "plaintext_hex")));
        let copy = master.wrap_invite_owner_copy(folder_id.clone(), &key).unwrap();
        assert_eq!(
            master
                .unwrap_invite_owner_copy(folder_id.clone(), copy.nonce, copy.ciphertext)
                .unwrap()
                .key_id()
                .unwrap(),
            key.key_id().unwrap()
        );
        assert!(
            master
                .unwrap_invite_owner_copy("other".into(), wire[..12].to_vec(), wire[12..].to_vec())
                .is_err()
        );
        // L9 legacy opener: one core call over the folder's rows; the unproven
        // candidate never leaves core.
        let folder = FileKeyHandle::from_key_bytes(vec![0xF8; 32]).unwrap();
        let name_key = master.derive_file_key(folder_id.as_bytes().to_vec()).unwrap();
        let wire = |d: EncryptedData| [d.nonce, d.ciphertext].concat();
        let legacy = wire(name_key.wrap_key(&folder).unwrap());
        let child = master.derive_file_key(b"child".to_vec()).unwrap();
        let row = |file_id: &str, wrap: Vec<u8>| LegacyFolderKeyRow {
            file_id: file_id.into(),
            wrap,
        };
        let proof = wire(folder.wrap_key(&child).unwrap());
        let opened = master
            .open_legacy_invite_owner_copy(folder_id.clone(), legacy.clone(), vec![row("child", proof.clone())])
            .unwrap()
            .unwrap();
        assert_eq!(opened.key_id().unwrap(), folder.key_id().unwrap());
        assert!(
            master
                .open_legacy_invite_owner_copy(folder_id.clone(), legacy.clone(), vec![row("other", proof)])
                .unwrap()
                .is_none()
        );
        assert!(
            master
                .open_legacy_invite_owner_copy(folder_id.clone(), legacy, vec![])
                .unwrap()
                .is_none()
        );
        // The folder's 32-byte name JSON is never a key, whatever rows come with it.
        let name = FileKeyHandle::from_key_bytes(br#"{"name":"Docs","mime_type":null}"#.to_vec()).unwrap();
        let name_blob = wire(name_key.wrap_key(&name).unwrap());
        let known = wire(name.wrap_key(&child).unwrap());
        assert!(
            master
                .open_legacy_invite_owner_copy(folder_id, name_blob, vec![row("child", known)])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn l7_vectors_and_context_failures_through_handles() {
        for family in ["folder_child_file_v1", "folder_child_folder_v1"] {
            let v = vector(family);
            let folder = FileKeyHandle::from_key_bytes(bytes(&v, "folder_key_hex")).unwrap();
            let wire = bytes(&v, "wrapped_hex");
            let root = v["shared_folder_id"].as_str().unwrap().to_string();
            let item = v["item_id"].as_str().unwrap().to_string();
            let kind = v["kind"].as_u64().unwrap() as u8;
            let child = folder
                .unwrap_folder_child(
                    root.clone(),
                    item.clone(),
                    kind,
                    wire[..12].to_vec(),
                    wire[12..].to_vec(),
                )
                .unwrap();
            assert_eq!(child.key_id().unwrap(), id(bytes(&v, "child_key_hex")));
            let b = folder
                .wrap_folder_child(root.clone(), item.clone(), kind, &child)
                .unwrap();
            assert_eq!(
                folder
                    .unwrap_folder_child(root.clone(), item.clone(), kind, b.nonce, b.ciphertext)
                    .unwrap()
                    .key_id()
                    .unwrap(),
                child.key_id().unwrap()
            );
            for (r, i, k) in [
                ("00000000-0000-4000-8000-000000000099".into(), item.clone(), kind),
                (root.clone(), "00000000-0000-4000-8000-000000000099".into(), kind),
                (root.clone(), item.clone(), 3 - kind),
                (root.clone(), item.clone(), 0),
                ("bad".into(), item.clone(), kind),
            ] {
                assert!(
                    folder
                        .unwrap_folder_child(r, i, k, wire[..12].to_vec(), wire[12..].to_vec())
                        .is_err()
                );
            }
        }
    }
    #[test]
    fn l6_published_vectors_open_through_handles() {
        for family in ["folder_custody_v1", "link_owner_key_v1", "link_owner_token_v1"] {
            let v = vector(family);
            let master = MasterKeyHandle::from_keychain_bytes(bytes(&v, "master_key_hex")).unwrap();
            let wire = bytes(&v, "wrapped_hex");
            let record = v["record_id"].as_str().unwrap().to_string();
            match family {
                "folder_custody_v1" => {
                    let key = master
                        .unwrap_folder_custody(record, wire[..12].to_vec(), wire[12..].to_vec())
                        .unwrap();
                    assert_eq!(key.key_id().unwrap(), id(bytes(&v, "plaintext_hex")));
                }
                "link_owner_key_v1" => assert_eq!(
                    master
                        .unwrap_link_owner_key(record, wire[..12].to_vec(), wire[12..].to_vec())
                        .unwrap(),
                    bytes(&v, "plaintext_hex")
                ),
                _ => assert_eq!(
                    master
                        .unwrap_link_owner_token(record, wire[..12].to_vec(), wire[12..].to_vec())
                        .unwrap(),
                    bytes(&v, "plaintext_hex")
                ),
            }
        }
        let v = vector("folder_link_passphrase_nfd");
        let handle = FileKeyHandle::from_folder_link_passphrase(
            bytes(&v, "k_c_hex"),
            v["passphrase"].as_str().unwrap().into(),
            v["token"].as_str().unwrap().into(),
        )
        .unwrap();
        assert_eq!(handle.key_id().unwrap(), id(bytes(&v, "link_key_hex")));
    }

    #[test]
    fn l6_master_handle_wraps_without_exporting_master_bytes() {
        let master = MasterKeyHandle::from_keychain_bytes(vec![0x40; 32]).unwrap();
        let inner = FileKeyHandle::from_key_bytes(vec![0x60; 32]).unwrap();
        let wrapped = master.wrap_key(&inner).unwrap();
        let wrapper = FileKeyHandle::from_key_bytes(vec![0x40; 32]).unwrap();
        assert_eq!(
            wrapper
                .unwrap_key(wrapped.nonce, wrapped.ciphertext)
                .unwrap()
                .key_id()
                .unwrap(),
            inner.key_id().unwrap()
        );
        let token = master.wrap_bytes(b"token".to_vec()).unwrap();
        assert_eq!(wrapper.decrypt_chunk(token.nonce, token.ciphertext).unwrap(), b"token");
    }

    #[test]
    fn l6_master_handle_purpose_wraps_round_trip() {
        let master = MasterKeyHandle::from_keychain_bytes(vec![0x40; 32]).unwrap();
        let inner = FileKeyHandle::from_key_bytes(vec![0x60; 32]).unwrap();
        let custody = master.wrap_folder_custody("folder".into(), &inner).unwrap();
        assert_eq!(
            master
                .unwrap_folder_custody("folder".into(), custody.nonce.clone(), custody.ciphertext.clone())
                .unwrap()
                .key_id()
                .unwrap(),
            inner.key_id().unwrap()
        );
        assert!(
            master
                .unwrap_folder_custody("other".into(), custody.nonce, custody.ciphertext)
                .is_err()
        );
        let owner = master.wrap_link_owner_key("share".into(), &inner).unwrap();
        assert_eq!(
            master
                .unwrap_link_owner_key("share".into(), owner.nonce.clone(), owner.ciphertext.clone())
                .unwrap(),
            vec![0x60; 32]
        );
        assert!(
            master
                .unwrap_link_owner_token("share".into(), owner.nonce, owner.ciphertext)
                .is_err()
        );
        let token = master.wrap_link_owner_token("share".into(), b"token".to_vec()).unwrap();
        assert_eq!(
            master
                .unwrap_link_owner_token("share".into(), token.nonce, token.ciphertext)
                .unwrap(),
            b"token"
        );
    }

    #[test]
    fn l8_owner_file_vector_and_round_trip_through_handles() {
        let v = vector("owner_wrapped_file_key");
        let master = MasterKeyHandle::from_keychain_bytes(bytes(&v, "master_key_hex")).unwrap();
        let item = v["file_id"].as_str().unwrap().to_string();
        let frame = bytes(&v, "expected_frame_hex");
        let inner = master
            .unwrap_owner_file_key(item.clone(), frame[..12].to_vec(), frame[12..].to_vec())
            .unwrap();
        assert_eq!(inner.key_id().unwrap(), id(bytes(&v, "child_key_hex")));
        let blob = master.wrap_owner_file_key(item.clone(), &inner).unwrap();
        assert_eq!(blob.nonce.len() + blob.ciphertext.len(), 60);
        assert_eq!(
            master
                .unwrap_owner_file_key(item, blob.nonce, blob.ciphertext)
                .unwrap()
                .key_id()
                .unwrap(),
            inner.key_id().unwrap()
        );
        assert!(
            master
                .unwrap_owner_file_key("other".into(), frame[..12].to_vec(), frame[12..].to_vec())
                .is_err()
        );
        let custody = master
            .wrap_folder_custody(v["file_id"].as_str().unwrap().into(), &inner)
            .unwrap();
        assert!(
            master
                .unwrap_owner_file_key(v["file_id"].as_str().unwrap().into(), custody.nonce, custody.ciphertext)
                .is_err()
        );
    }

    #[test]
    fn l8_owner_handle_rejects_content_names_legacy_and_bad_lengths() {
        let master = MasterKeyHandle::from_keychain_bytes(vec![0x40; 32]).unwrap();
        let item = "11111111-1111-4111-8111-111111111111";
        let legacy_key = master.derive_file_key(item.as_bytes().to_vec()).unwrap();
        let content = legacy_key.encrypt_chunk(vec![0x55; 32]).unwrap();
        assert_eq!(content.ciphertext.len(), 48);
        assert!(
            master
                .unwrap_owner_file_key(item.into(), content.nonce, content.ciphertext)
                .is_err()
        );
        let name = master.encrypt_name(item.into(), "test".into(), None).unwrap();
        let blob: EncryptedBlob = serde_json::from_str(&name).unwrap();
        assert_eq!(blob.ciphertext.len(), 48);
        assert!(
            master
                .unwrap_owner_file_key(item.into(), blob.nonce, blob.ciphertext)
                .is_err()
        );
        let inner = FileKeyHandle::from_key_bytes(vec![0x60; 32]).unwrap();
        let legacy = legacy_key.wrap_key(&inner).unwrap();
        assert!(
            master
                .unwrap_owner_file_key(item.into(), legacy.nonce, legacy.ciphertext)
                .is_err()
        );
        for (nonce, ciphertext) in [
            (vec![0; 11], vec![0; 48]),
            (vec![0; 12], vec![0; 47]),
            (vec![0; 12], vec![0; 49]),
        ] {
            assert!(master.unwrap_owner_file_key(item.into(), nonce, ciphertext).is_err());
        }
        assert!(master.wrap_owner_file_key(String::new(), &inner).is_err());
        assert!(
            master
                .unwrap_owner_file_key(String::new(), vec![0; 12], vec![0; 48])
                .is_err()
        );
    }

    fn vector(name: &str) -> serde_json::Value {
        let doc: serde_json::Value = serde_json::from_str(include_str!("../../test-vectors/vectors.json")).unwrap();
        doc["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()
            .clone()
    }

    fn bytes(v: &serde_json::Value, field: &str) -> Vec<u8> {
        v[field]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }

    fn id(bytes: Vec<u8>) -> Vec<u8> {
        beebeeb_core::folder_key::folder_key_id(&bytes.try_into().unwrap()).to_vec()
    }

    #[test]
    fn unwrap_key_round_trips_and_refuses_any_other_length() {
        let a = FileKeyHandle::from_key_bytes(vec![0xa1; 32]).unwrap();
        let b = FileKeyHandle::from_key_bytes(vec![0xb2; 32]).unwrap();
        let wrap = b.wrap_key(&a).unwrap();
        let opened = b.unwrap_key(wrap.nonce.clone(), wrap.ciphertext.clone()).unwrap();
        assert_eq!(opened.key_id().unwrap(), a.key_id().unwrap());
        // Same-handle wrapping must not take the same non-reentrant lock twice.
        let self_wrap = a.wrap_key(&a).unwrap();
        assert_eq!(
            a.unwrap_key(self_wrap.nonce, self_wrap.ciphertext)
                .unwrap()
                .key_id()
                .unwrap(),
            a.key_id().unwrap()
        );
        for len in [0, 31, 33, 64] {
            let wrap = b.encrypt_chunk(vec![0x42; len]).unwrap();
            assert!(
                matches!(
                    b.unwrap_key(wrap.nonce, wrap.ciphertext),
                    Err(CryptoError::InvalidInput { .. })
                ),
                "accepted plaintext length {len}"
            );
        }
        let mut corrupt = wrap.ciphertext;
        corrupt[0] ^= 1;
        assert!(b.unwrap_key(wrap.nonce, corrupt).is_err());
        for len in [0, 11, 13] {
            assert!(b.unwrap_key(vec![0; len], vec![0; 48]).is_err());
        }
        *b.inner.lock().unwrap() = None;
        assert!(b.wrap_key(&a).is_err());
        assert!(b.key_id().is_err());
    }

    #[test]
    fn wrap_key_is_60_bytes_on_the_wire() {
        let a = FileKeyHandle::from_key_bytes(vec![0xa1; 32]).unwrap();
        let b = FileKeyHandle::from_key_bytes(vec![0xb2; 32]).unwrap();
        let wrap = b.wrap_key(&a).unwrap();
        assert_eq!(wrap.nonce.len(), 12);
        assert_eq!(wrap.ciphertext.len(), 48);
        assert_eq!(wrap.nonce.len() + wrap.ciphertext.len(), 60);
    }

    #[test]
    fn unwrap_key_opens_the_web_made_wrap() {
        let v = vector("key_wrap_v1");
        let wrapper = FileKeyHandle::from_key_bytes(bytes(&v, "wrapper_key_hex")).unwrap();
        let wrap = bytes(&v, "wrapped_hex");
        let inner = wrapper.unwrap_key(wrap[..12].to_vec(), wrap[12..].to_vec()).unwrap();
        assert_eq!(inner.key_id().unwrap(), id(bytes(&v, "inner_key_hex")));
    }

    #[test]
    fn from_folder_link_matches_the_combine_vector() {
        let v = vector("combine_folder_link_key");
        let plain = FileKeyHandle::from_folder_link(bytes(&v, "k_c_hex"), None).unwrap();
        assert_eq!(
            plain.key_id().unwrap(),
            id(bytes(&v, "expected_without_passphrase_hex"))
        );
        let protected =
            FileKeyHandle::from_folder_link(bytes(&v, "k_c_hex"), Some(bytes(&v, "passphrase_stretch_hex"))).unwrap();
        assert_eq!(
            protected.key_id().unwrap(),
            id(bytes(&v, "expected_with_passphrase_hex"))
        );
        for len in [0, 31, 33] {
            assert!(matches!(
                FileKeyHandle::from_folder_link(vec![0; len], None),
                Err(CryptoError::InvalidInput { .. })
            ));
            assert!(matches!(
                FileKeyHandle::from_folder_link(vec![0; 32], Some(vec![0; len])),
                Err(CryptoError::InvalidInput { .. })
            ));
        }
    }

    #[test]
    fn from_folder_link_passphrase_matches_the_web_derivation() {
        let v = vector("folder_link_passphrase");
        let h = FileKeyHandle::from_folder_link_passphrase(
            bytes(&v, "k_c_hex"),
            v["passphrase"].as_str().unwrap().into(),
            v["token"].as_str().unwrap().into(),
        )
        .unwrap();
        assert_eq!(h.key_id().unwrap(), id(bytes(&v, "link_key_hex")));
    }

    #[test]
    fn passphrase_token_and_kc_are_all_required() {
        let v = vector("folder_link_passphrase");
        let kc = bytes(&v, "k_c_hex");
        let pass = v["passphrase"].as_str().unwrap();
        let token = v["token"].as_str().unwrap();
        let expected = id(bytes(&v, "link_key_hex"));
        let wrong_pass =
            FileKeyHandle::from_folder_link_passphrase(kc.clone(), format!("{pass}!"), token.into()).unwrap();
        let wrong_token =
            FileKeyHandle::from_folder_link_passphrase(kc.clone(), pass.into(), format!("{token}!")).unwrap();
        let mut other_kc = kc;
        other_kc[0] ^= 1;
        let wrong_kc = FileKeyHandle::from_folder_link_passphrase(other_kc, pass.into(), token.into()).unwrap();
        for h in [wrong_pass, wrong_token, wrong_kc] {
            assert_ne!(h.key_id().unwrap(), expected);
        }
    }

    #[test]
    fn generate_makes_distinct_keys() {
        let a = FileKeyHandle::generate().unwrap();
        let b = FileKeyHandle::generate().unwrap();
        assert_ne!(a.key_id().unwrap(), b.key_id().unwrap());
    }
}

// ---------------------------------------------------------------------------
// Error type — UniFFI-compatible enum
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoError {
    #[error("encryption failed: {detail}")]
    Encryption { detail: String },

    #[error("decryption failed: ciphertext is invalid or key is wrong")]
    Decryption,

    #[error("key derivation failed: {detail}")]
    Kdf { detail: String },

    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,

    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },

    #[error("OPAQUE protocol error: {detail}")]
    Opaque { detail: String },

    #[error("operation cancelled")]
    Cancelled,

    #[error("I/O error: {detail}")]
    Io { detail: String },
}

impl From<beebeeb_core::CoreError> for CryptoError {
    fn from(e: beebeeb_core::CoreError) -> Self {
        match e {
            beebeeb_core::CoreError::Encryption(s) => CryptoError::Encryption { detail: s },
            beebeeb_core::CoreError::Decryption => CryptoError::Decryption,
            beebeeb_core::CoreError::Kdf(s) => CryptoError::Kdf { detail: s },
            beebeeb_core::CoreError::InvalidRecoveryPhrase => CryptoError::InvalidRecoveryPhrase,
            beebeeb_core::CoreError::InvalidInput(s) => CryptoError::InvalidInput { detail: s },
            beebeeb_core::CoreError::Opaque(s) => CryptoError::Opaque { detail: s },
            beebeeb_core::CoreError::Cancelled => CryptoError::Cancelled,
            beebeeb_core::CoreError::Io(s) => CryptoError::Io { detail: s },
        }
    }
}

// ---------------------------------------------------------------------------
// Return types — UniFFI records
// ---------------------------------------------------------------------------

/// One row of a shared folder's legacy key table, for the L9 proof (task 2255):
/// `file_id` as the server lists it, `wrap` = nonce(12) || ciphertext || tag.
#[derive(uniffi::Record)]
pub struct LegacyFolderKeyRow {
    pub file_id: String,
    pub wrap: Vec<u8>,
}

/// Result of encrypting a chunk or metadata. Contains the cipher suite
/// identifier, a random nonce, and the ciphertext (including the GCM tag).
#[derive(uniffi::Record)]
pub struct EncryptedData {
    pub cipher_suite: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Master key bytes returned from `derive_master_key`.
#[derive(uniffi::Record)]
pub struct MasterKeyResult {
    pub key: Vec<u8>,
}

/// One encrypted client-metadata row (task 1922): `record_key` is the record's
/// client key, `device_key` the parent device's (absent for the device
/// hostname), `field` is 1-4 and `envelope` is a `bbcm1.` string.
#[derive(uniffi::Record)]
pub struct ClientMetaItem {
    pub record_key: String,
    pub device_key: Option<String>,
    pub field: u8,
    pub envelope: String,
}

/// One opened client-metadata row: `ok` false means this row failed and
/// `value` is absent. One bad row never fails the batch.
#[derive(uniffi::Record)]
pub struct ClientMetaOpened {
    pub ok: bool,
    pub value: Option<String>,
}

fn client_meta_uuid(s: &str) -> Result<uuid::Uuid, CryptoError> {
    uuid::Uuid::parse_str(s).map_err(|_| CryptoError::InvalidInput {
        detail: "record_key/device_key must be a UUID".into(),
    })
}

fn client_meta_optional_uuid(s: Option<&str>) -> Result<Option<uuid::Uuid>, CryptoError> {
    s.map(client_meta_uuid).transpose()
}

fn client_meta_field(field: u8) -> Result<client_meta::ClientMetaField, CryptoError> {
    client_meta::ClientMetaField::try_from(field).map_err(CryptoError::from)
}

/// Shorten a client-metadata string for sealing (task 1922): over 1024 UTF-8
/// bytes, keep the last 1021 bytes on a char boundary behind a leading `…`.
#[uniffi::export]
pub fn fit_for_seal(s: String) -> String {
    client_meta::fit_for_seal(&s)
}

/// Result of starting an OPAQUE registration or login.
#[derive(uniffi::Record)]
pub struct OpaqueStartResult {
    pub message: Vec<u8>,
    pub state: Vec<u8>,
}

/// Result of finishing an OPAQUE client login.
#[derive(uniffi::Record)]
pub struct OpaqueLoginFinishResult {
    pub message: Vec<u8>,
    pub session_key: Vec<u8>,
    pub export_key: Vec<u8>,
}

/// Result of generating a recovery phrase.
#[derive(uniffi::Record)]
pub struct RecoveryPhraseResult {
    pub phrase: String,
    pub master_key: Vec<u8>,
}

/// A single encrypted chunk (nonce + ciphertext) for batch decryption.
#[derive(uniffi::Record)]
pub struct EncryptedChunkData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A request's X25519 private key wrapped under the owner's master key
/// (AES-256-GCM ciphertext + nonce). Stored server-side.
#[derive(uniffi::Record)]
pub struct WrappedRequestPrivate {
    pub wrapped: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// A content key sealed to a request public key: the uploader's ephemeral
/// X25519 public key and the wrapped content key (raw `nonce ‖ ciphertext`).
#[derive(uniffi::Record)]
pub struct SealedRequestUpload {
    pub e_pub: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

/// Info about a single encrypted chunk written to disk by `encrypt_file`.
#[derive(uniffi::Record)]
pub struct EncryptedChunkInfo {
    pub chunk_index: u32,
    pub output_path: String,
    pub nonce: Vec<u8>,
    pub plaintext_size: u64,
    pub ciphertext_size: u64,
}

/// Result of encrypting a complete file to disk chunks.
#[derive(uniffi::Record)]
pub struct EncryptedFileInfo {
    pub chunks: Vec<EncryptedChunkInfo>,
    pub total_plaintext_bytes: u64,
    pub total_ciphertext_bytes: u64,
    pub chunk_size_bytes: u64,
}

/// Result of decrypting chunk files back to a single file.
#[derive(uniffi::Record)]
pub struct DecryptedFileInfo {
    pub output_path: String,
    pub total_bytes: u64,
    pub chunks_processed: u32,
}

/// Result of decrypting a name_encrypted blob with MIME type.
#[derive(uniffi::Record)]
pub struct DecryptedNameWithMime {
    pub name: String,
    pub mime_type: Option<String>,
}

/// One `(file_id, name_encrypted)` input to the batch `decrypt_names` (task 0806).
#[derive(uniffi::Record)]
pub struct BatchNameItem {
    /// Hyphenated-lowercase UUID string (the server-canonical file id).
    pub file_id: String,
    /// The `name_encrypted` JSON envelope.
    pub name_encrypted: String,
}

/// One result of the batch `decrypt_names` (task 0806). On success `name` is set
/// (`mime_type` optional) and `error` is None; on failure `error` is set and the
/// others are None. One failed item never fails the whole batch.
#[derive(uniffi::Record)]
pub struct BatchNameResult {
    pub name: Option<String>,
    pub mime_type: Option<String>,
    pub error: Option<String>,
}

/// Parsed encrypted metadata payload (nonce + ciphertext bytes).
#[derive(uniffi::Record)]
pub struct EncryptedMetadataParts {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// File progress callback — UniFFI callback interface for Swift/Kotlin
// ---------------------------------------------------------------------------

#[uniffi::export(callback_interface)]
pub trait FileProgressCallback: Send + Sync {
    fn on_progress(&self, chunks_completed: u32, chunks_total: u32);
}

/// Adapter: bridges the UniFFI callback interface to the core trait.
struct ProgressAdapter<'a> {
    inner: &'a dyn FileProgressCallback,
}

impl<'a> beebeeb_core::file_encrypt::FileProgressCallback for ProgressAdapter<'a> {
    fn on_progress(&self, chunks_completed: u32, chunks_total: u32) {
        self.inner.on_progress(chunks_completed, chunks_total);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn file_key_from_slice(key: &[u8]) -> Result<kdf::FileKey, CryptoError> {
    let mut bytes: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "key must be exactly 32 bytes".into(),
    })?;
    let fk = kdf::FileKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(fk)
}

fn master_key_from_slice(key: &[u8]) -> Result<kdf::MasterKey, CryptoError> {
    let mut bytes: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "master_key must be exactly 32 bytes".into(),
    })?;
    let mk = kdf::MasterKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(mk)
}

fn encrypted_blob_to_data(blob: &EncryptedBlob) -> EncryptedData {
    let suite = match blob.cipher_suite {
        CipherSuite::V1Aes256Gcm => "V1Aes256Gcm",
    };
    EncryptedData {
        cipher_suite: suite.to_string(),
        nonce: blob.nonce.clone(),
        ciphertext: blob.ciphertext.clone(),
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte master key from a password and salt (>= 16 bytes) via
/// Argon2id. Returns the key bytes.
#[uniffi::export]
pub fn derive_master_key(password: String, salt: Vec<u8>) -> Result<MasterKeyResult, CryptoError> {
    let mk = kdf::derive_master_key(&password, &salt)?;
    let bytes = mk.to_bytes();
    Ok(MasterKeyResult { key: bytes.to_vec() })
}

/// Derive a per-file encryption key from a master key and file ID via
/// HKDF-SHA256. Returns the 32-byte file key.
#[uniffi::export]
pub fn derive_file_key(master_key: Vec<u8>, file_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let fk = kdf::derive_file_key(&mk, &file_id);
    Ok(fk.as_bytes().to_vec())
}

/// Generate a canonical share token (task 0708): 20 bytes of OS randomness as
/// URL-safe-no-pad base64 (27 chars). Mobile mints this for A1 owner-recoverable
/// shares so the client-supplied `token` matches the server's format exactly
/// (single canonical impl shared with web/WASM via `beebeeb-core`).
#[uniffi::export]
pub fn generate_share_token() -> String {
    beebeeb_core::share_token::generate_share_token()
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt a plaintext chunk with AES-256-GCM. Returns the encrypted data
/// containing cipher suite, nonce, and ciphertext.
#[uniffi::export]
pub fn encrypt_chunk(key: Vec<u8>, plaintext: Vec<u8>) -> Result<EncryptedData, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = encrypt::encrypt_chunk(&fk, &plaintext)?;
    Ok(encrypted_blob_to_data(&blob))
}

/// Decrypt a ciphertext chunk that was produced by `encrypt_chunk`.
#[uniffi::export]
pub fn decrypt_chunk(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };
    Ok(encrypt::decrypt_chunk(&fk, &blob)?)
}

/// Decrypt a sequence of encrypted chunks and write the plaintext to a file.
///
/// Chunks are decrypted sequentially and written in order; peak memory is
/// bounded by the size of the largest single chunk's plaintext, not the
/// total file size. The output file is created (truncating any existing
/// file) before the first chunk.
///
/// On `Err`, the output file may exist on disk in a partially-written
/// state — the caller is responsible for deleting it so a downstream
/// cache layer does not treat the partial file as complete.
///
/// Returns the total number of plaintext bytes written.
///
/// **Task 1908:** `file_id` (the id the file was uploaded under) and
/// `expected_chunk_format` (from the file's encrypted metadata,
/// `decrypt_file_metadata`: 0 = unrecorded, 2 = v2) are required: the chunks
/// are opened as one file's ordered stream — v2 frames are bound to (file id,
/// upload, index, last), v1 files still open when the metadata records no
/// format. Reordered, spliced, duplicated, dropped or truncated v2 chunks fail.
/// The output is atomic (core `.tmp` + rename).
#[uniffi::export]
pub fn decrypt_chunks_to_file(
    key: Vec<u8>,
    file_id: String,
    expected_chunk_format: u8,
    chunks: Vec<EncryptedChunkData>,
    output_path: String,
) -> Result<u64, CryptoError> {
    let key = Zeroizing::new(key);
    let fk = file_key_from_slice(&key)?;
    let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
    let chunk_pairs: Vec<(Vec<u8>, Vec<u8>)> = chunks.into_iter().map(|c| (c.nonce, c.ciphertext)).collect();
    encrypt::decrypt_chunks_to_file(&fk, &file_id, expected, chunk_pairs, &output_path).map_err(CryptoError::from)
}

/// Decrypt a contiguous encrypted body into a file.
///
/// `body` is the wire format produced by stacking encrypted chunks back
/// to back: each chunk is `nonce (12 bytes) || ciphertext (chunk_size +
/// 16 byte AES-GCM tag)`. All chunks but the last produce `chunk_size`
/// bytes of plaintext; the final chunk is whatever remains.
///
/// Compared to `decrypt_chunks_to_file`, this variant lets the caller
/// hand over the full encrypted blob without pre-slicing — Rust performs
/// the chunk boundaries internally. Saves N small `ByteArray` allocations
/// + per-chunk marshalling overhead across the FFI for files with many
/// chunks (a 100 MB / 1 MB-chunk file is one allocation here vs. 200
/// across the bridge with the pre-sliced variant).
///
/// Streams chunk-by-chunk — peak memory is one plaintext chunk, not the
/// full file. Returns the total number of plaintext bytes written.
///
/// **Atomic output:** core writes plaintext to a sibling `.tmp` and renames it
/// to `output_path` only on full success; on any error the `.tmp` is removed and
/// `output_path` is never created/overwritten. Callers no longer need to clean
/// up a partial file on `Err`, and an existence-based cache cannot serve a
/// truncated decrypt.
///
/// **Task 1908:** `file_id` (the id the file was uploaded under) is required —
/// it is bound into every v2 frame together with the upload's version id, the
/// chunk index and the last-chunk flag — and so is `expected_chunk_format`
/// from the file's encrypted metadata (0 = unrecorded, 2 = v2). v1 files still
/// open when the metadata records no format. A reordered/spliced/truncated v2
/// body fails.
#[uniffi::export]
pub fn decrypt_contiguous_to_file(
    file_key: Vec<u8>,
    file_id: String,
    expected_chunk_format: u8,
    body: Vec<u8>,
    chunk_size: u64,
    output_path: String,
) -> Result<u64, CryptoError> {
    let file_key = Zeroizing::new(file_key);
    let fk = file_key_from_slice(&file_key)?;
    let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
    encrypt::decrypt_contiguous_to_file(&fk, &file_id, expected, &body, chunk_size, &output_path)
        .map_err(CryptoError::from)
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// Encrypt a UTF-8 metadata string (filename, path, etc.) with AES-256-GCM.
#[uniffi::export]
pub fn encrypt_metadata(key: Vec<u8>, metadata: String) -> Result<EncryptedData, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = encrypt::encrypt_metadata(&fk, &metadata)?;
    Ok(encrypted_blob_to_data(&blob))
}

/// Decrypt a metadata blob back to a UTF-8 string.
#[uniffi::export]
pub fn decrypt_metadata(key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<String, CryptoError> {
    let fk = file_key_from_slice(&key)?;
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    };
    Ok(encrypt::decrypt_metadata(&fk, &blob)?)
}

// ---------------------------------------------------------------------------
// Name encryption (encrypt_name / decrypt_name)
// ---------------------------------------------------------------------------

/// Encrypt a filename + optional MIME type into the canonical JSON envelope.
/// The result is a JSON string containing cipher_suite, nonce, and ciphertext.
#[uniffi::export]
pub fn encrypt_name(
    master_key: Vec<u8>,
    file_id: String,
    filename: String,
    mime_type: Option<String>,
) -> Result<String, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    encrypt::encrypt_name(&mk, &file_id, &filename, mime_type.as_deref()).map_err(CryptoError::from)
}

/// Decrypt a `name_encrypted` JSON envelope back to a plaintext filename.
/// Handles both new format (`{"name":"...","mime_type":"..."}`) and legacy bare strings.
#[uniffi::export]
pub fn decrypt_name(master_key: Vec<u8>, file_id: String, name_encrypted: String) -> Result<String, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    encrypt::decrypt_name(&mk, &file_id, &name_encrypted).map_err(CryptoError::from)
}

/// Decrypt a `name_encrypted` JSON envelope and return both the filename and
/// the MIME type (if present in the encrypted payload).
#[uniffi::export]
pub fn decrypt_name_with_mime(
    master_key: Vec<u8>,
    file_id: String,
    name_encrypted: String,
) -> Result<DecryptedNameWithMime, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let (name, mime) = encrypt::decrypt_name_with_mime(&mk, &file_id, &name_encrypted).map_err(CryptoError::from)?;
    Ok(DecryptedNameWithMime { name, mime_type: mime })
}

// ---------------------------------------------------------------------------
// Media utilities
// ---------------------------------------------------------------------------

/// Returns `true` if the given MIME type represents media (image or video).
/// Single source of truth for all clients.
#[uniffi::export]
pub fn is_media(mime_type: Option<String>) -> bool {
    media::is_media(mime_type.as_deref())
}

/// Guess the MIME type from a filename extension.
/// Returns `None` for unknown extensions.
#[uniffi::export]
pub fn guess_mime_type(filename: String) -> Option<String> {
    media::guess_mime_type(&filename).map(|s| s.to_string())
}

/// Returns `true` if the given MIME type can be previewed in-app.
#[uniffi::export]
fn is_previewable(mime_type: Option<String>) -> bool {
    beebeeb_core::media::is_previewable(mime_type.as_deref())
}

/// Returns `true` if the file extension indicates a previewable file.
#[uniffi::export]
fn is_previewable_by_extension(filename: String) -> bool {
    beebeeb_core::media::is_previewable_by_extension(&filename)
}

// ---------------------------------------------------------------------------
// Recovery phrase
// ---------------------------------------------------------------------------

/// Generate a new 12-word BIP39 recovery phrase and the corresponding master
/// key. The phrase IS the master secret.
#[uniffi::export]
pub fn generate_recovery_phrase() -> Result<RecoveryPhraseResult, CryptoError> {
    let (phrase, mk) = recovery::generate_recovery_phrase()?;
    let bytes = mk.to_bytes();
    Ok(RecoveryPhraseResult {
        phrase,
        master_key: bytes.to_vec(),
    })
}

/// Recover a master key from a 12-word BIP39 recovery phrase.
/// Returns the 32-byte master key.
#[uniffi::export]
pub fn recover_from_phrase(phrase: String) -> Result<Vec<u8>, CryptoError> {
    let mk = recovery::recover_from_phrase(&phrase)?;
    Ok(mk.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// OPAQUE protocol
// ---------------------------------------------------------------------------

/// Start OPAQUE client registration. Returns the registration message and
/// client state (both needed for the finish step).
#[uniffi::export]
pub fn opaque_registration_start(password: Vec<u8>) -> Result<OpaqueStartResult, CryptoError> {
    let result = beebeeb_core::opaque_protocol::client_registration_start(&password)?;
    Ok(OpaqueStartResult {
        message: result.message,
        state: result.state,
    })
}

/// Finish OPAQUE client registration. Takes the client state from the start
/// step, the password, and the server's response. Returns the registration
/// upload bytes to send to the server.
#[uniffi::export]
pub fn opaque_registration_finish(
    client_state: Vec<u8>,
    password: Vec<u8>,
    server_response: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    Ok(beebeeb_core::opaque_protocol::client_registration_finish(
        &client_state,
        &password,
        &server_response,
    )?)
}

/// Start OPAQUE client login. Returns the login message and client state.
#[uniffi::export]
pub fn opaque_login_start(password: Vec<u8>) -> Result<OpaqueStartResult, CryptoError> {
    let result = beebeeb_core::opaque_protocol::client_login_start(&password)?;
    Ok(OpaqueStartResult {
        message: result.message,
        state: result.state,
    })
}

/// Finish OPAQUE client login. Returns the finalization message, the session
/// key, and the export key (used to derive the master key envelope).
///
/// `ksf_version` selects the KSF the account's password file was registered
/// under (0 = legacy Identity KSF, anything else = current Argon2id). Mobile
/// reads it from the login-start response and passes it through verbatim; the
/// KSF must match or finish fails.
#[uniffi::export]
pub fn opaque_login_finish(
    client_state: Vec<u8>,
    password: Vec<u8>,
    server_response: Vec<u8>,
    ksf_version: u32,
) -> Result<OpaqueLoginFinishResult, CryptoError> {
    let result =
        beebeeb_core::opaque_protocol::client_login_finish(&client_state, &password, &server_response, ksf_version)?;
    Ok(OpaqueLoginFinishResult {
        message: result.message,
        session_key: result.session_key,
        export_key: result.export_key,
    })
}

// ---------------------------------------------------------------------------
// X25519 identity + sharing
// ---------------------------------------------------------------------------

/// Derive an X25519 secret scalar from a master key. Returns 32 bytes.
#[uniffi::export]
pub fn derive_x25519_private(master_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    Ok(beebeeb_core::opaque::derive_x25519_private(&mk).to_vec())
}

/// Derive an X25519 public point from a secret scalar. Returns 32 bytes.
#[uniffi::export]
pub fn derive_x25519_public(private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let pk: [u8; 32] = private_key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "secret scalar must be 32 bytes".into(),
    })?;
    Ok(beebeeb_core::opaque::derive_x25519_public(&pk).to_vec())
}

/// Compute an X25519 shared secret from my secret scalar and their public point.
/// Returns 32-byte shared secret.
#[uniffi::export]
pub fn x25519_shared_secret(my_private: Vec<u8>, their_public: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let priv_key: [u8; 32] = my_private.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "secret scalar must be 32 bytes".into(),
    })?;
    let pub_key: [u8; 32] = their_public.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "public key must be 32 bytes".into(),
    })?;
    let shared = beebeeb_core::opaque::x25519_shared_secret(&priv_key, &pub_key)
        .map_err(|e| CryptoError::InvalidInput { detail: e.to_string() })?;
    Ok(shared.to_vec())
}

/// Derive a share key from a shared secret and file ID. Returns 32-byte share key.
#[uniffi::export]
pub fn derive_share_key(shared_secret: Vec<u8>, file_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let ss: [u8; 32] = shared_secret.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "shared_secret must be 32 bytes".into(),
    })?;
    Ok(beebeeb_core::opaque::derive_share_key(&ss, &file_id).to_vec())
}

/// Compute a recovery check value from a master key. Returns 32-byte check value.
/// This is stored server-side so we can verify a recovery phrase produces the
/// correct master key.
#[uniffi::export]
pub fn compute_recovery_check(master_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    Ok(beebeeb_core::opaque::compute_recovery_check(&mk).to_vec())
}

/// A shared folder's key id (task 2133): a one-way id of the folder's 32-byte
/// key, for a server to compare folder keys without learning them (HKDF-SHA256,
/// info `beebeeb/folder-key-id/v1`). Returns 32 bytes; not secret, and never a
/// key. Wipes the copy of the key this function owns.
#[uniffi::export]
pub fn folder_key_id(folder_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mut folder_key = folder_key;
    let key = <[u8; 32]>::try_from(folder_key.as_slice()).map(Zeroizing::new);
    folder_key.zeroize();
    let key = key.map_err(|_| CryptoError::InvalidInput {
        detail: "folder_key must be exactly 32 bytes".into(),
    })?;
    Ok(beebeeb_core::folder_key::folder_key_id(&key).to_vec())
}

// ---------------------------------------------------------------------------
// File requests (sealed-box / ECIES per request)
// ---------------------------------------------------------------------------

/// Derive the per-request private-key-wrapping key from the owner's master key.
/// Returns 32 bytes.
#[uniffi::export]
pub fn derive_request_wrap_key(master_key: Vec<u8>, request_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    Ok(beebeeb_core::file_request::derive_request_wrap_key(&mk, &request_id).to_vec())
}

/// Wrap a request's X25519 private key under the owner's master key.
#[uniffi::export]
pub fn wrap_request_private(
    master_key: Vec<u8>,
    request_id: Vec<u8>,
    r_priv: Vec<u8>,
) -> Result<WrappedRequestPrivate, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let r_priv_arr: [u8; 32] = r_priv.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "r_priv must be 32 bytes".into(),
    })?;
    let (wrapped, nonce) = beebeeb_core::file_request::wrap_request_private(&mk, &request_id, &r_priv_arr)?;
    Ok(WrappedRequestPrivate { wrapped, nonce })
}

/// Unwrap a request's X25519 private key. Returns 32 bytes.
#[uniffi::export]
pub fn unwrap_request_private(
    master_key: Vec<u8>,
    request_id: Vec<u8>,
    wrapped: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let mk = master_key_from_slice(&master_key)?;
    let r_priv = beebeeb_core::file_request::unwrap_request_private(&mk, &request_id, &wrapped, &nonce)?;
    Ok(r_priv.to_vec())
}

/// Seal a content key to a request's public key (anonymous uploader path).
#[uniffi::export]
pub fn seal_to_request(
    r_pub: Vec<u8>,
    file_id: Vec<u8>,
    content_key: Vec<u8>,
) -> Result<SealedRequestUpload, CryptoError> {
    let r_pub_arr: [u8; 32] = r_pub.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "r_pub must be 32 bytes".into(),
    })?;
    let content_key_arr: [u8; 32] = content_key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "content_key must be 32 bytes".into(),
    })?;
    let sealed = beebeeb_core::file_request::seal_to_request(&r_pub_arr, &file_id, &content_key_arr)?;
    Ok(SealedRequestUpload {
        e_pub: sealed.e_pub.to_vec(),
        wrapped_key: sealed.wrapped_key,
    })
}

/// Open a sealed request upload (owner decrypt path). Returns the 32-byte content key.
#[uniffi::export]
pub fn open_request_upload(
    r_priv: Vec<u8>,
    e_pub: Vec<u8>,
    file_id: Vec<u8>,
    wrapped_key: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let r_priv_arr: [u8; 32] = r_priv.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "r_priv must be 32 bytes".into(),
    })?;
    let e_pub_arr: [u8; 32] = e_pub.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "e_pub must be 32 bytes".into(),
    })?;
    let content_key = beebeeb_core::file_request::open_request_upload(&r_priv_arr, &e_pub_arr, &file_id, &wrapped_key)?;
    Ok(content_key.to_vec())
}

// ---------------------------------------------------------------------------
// Object handles — keys stay in Rust memory; only export_for_keychain crosses
// ---------------------------------------------------------------------------

/// Opaque handle to a MasterKey. The key bytes never leave Rust except via
/// `export_for_keychain`, which is only called once to persist to the OS keychain.
#[derive(uniffi::Object)]
pub struct MasterKeyHandle {
    inner: Mutex<Option<kdf::MasterKey>>,
}

impl MasterKeyHandle {
    fn new(mk: kdf::MasterKey) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(mk)),
        })
    }

    fn with_key<T, F: FnOnce(&kdf::MasterKey) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(f).ok_or(CryptoError::InvalidInput {
            detail: "key handle has been cleared".into(),
        })
    }
}

#[uniffi::export]
impl MasterKeyHandle {
    /// Reconstruct a MasterKeyHandle from a 12-word BIP39 recovery phrase.
    #[uniffi::constructor]
    pub fn from_recovery_phrase(phrase: String) -> Result<Arc<Self>, CryptoError> {
        let mk = recovery::recover_from_phrase(&phrase)?;
        Ok(Self::new(mk))
    }

    /// Reconstruct a MasterKeyHandle from 32 raw bytes read from the OS keychain.
    #[uniffi::constructor]
    pub fn from_keychain_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, CryptoError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidInput {
            detail: "keychain bytes must be exactly 32 bytes".into(),
        })?;
        let mk = kdf::MasterKey::from_bytes(arr);
        Ok(Self::new(mk))
    }

    /// Derive a FileKeyHandle for the given file ID.
    pub fn derive_file_key(&self, file_id: Vec<u8>) -> Result<Arc<FileKeyHandle>, CryptoError> {
        self.with_key(|mk| {
            let fk = kdf::derive_file_key(mk, &file_id);
            FileKeyHandle::new(fk)
        })
    }

    /// Legacy direct-master wrap for existing protocols. Folder custody and
    /// link recovery MUST use the purpose-bound methods below instead.
    pub fn wrap_key(&self, inner: &FileKeyHandle) -> Result<EncryptedData, CryptoError> {
        let key = inner.with_key(|key| Zeroizing::new(*key.as_bytes()))?;
        self.wrap_bytes(key.to_vec())
    }

    /// Wrap bytes without exporting the master key across the FFI boundary.
    pub fn wrap_bytes(&self, bytes: Vec<u8>) -> Result<EncryptedData, CryptoError> {
        let bytes = Zeroizing::new(bytes);
        self.with_key(|mk| {
            let raw = Zeroizing::new(mk.to_bytes());
            encrypt::encrypt_chunk(&kdf::FileKey::from_bytes(*raw), &bytes)
        })?
        .map(|blob| encrypted_blob_to_data(&blob))
        .map_err(Into::into)
    }

    /// L8 owner adoption. Key material stays in native handles.
    pub fn wrap_owner_file_key(&self, item_id: String, inner: &FileKeyHandle) -> Result<EncryptedData, CryptoError> {
        let key = inner.with_key(|key| kdf::FileKey::from_bytes(*key.as_bytes()))?;
        self.with_key(|mk| kdf::wrap_owner_file_key(mk, item_id.as_bytes(), &key))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    /// Open only L8 and return an opaque handle, never raw file-key bytes.
    pub fn unwrap_owner_file_key(
        &self,
        item_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Arc<FileKeyHandle>, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        let key = self.with_key(|mk| kdf::unwrap_owner_file_key(mk, item_id.as_bytes(), &blob))??;
        Ok(FileKeyHandle::new(key))
    }

    /// L9 (task 2255): open a LEGACY invite owner copy; `Some` only when core
    /// proves it over the folder's `rows` (at most 64 distinct ids, one call).
    /// The unproven candidate never leaves core. Attack B is a named residual.
    pub fn open_legacy_invite_owner_copy(
        &self,
        folder_id: String,
        legacy_copy: Vec<u8>,
        rows: Vec<LegacyFolderKeyRow>,
    ) -> Result<Option<Arc<FileKeyHandle>>, CryptoError> {
        let key = self.with_key(|master| {
            kdf::open_legacy_invite_owner_copy(
                master,
                folder_id.as_bytes(),
                &legacy_copy,
                rows.iter().map(|row| (row.file_id.as_bytes(), row.wrap.as_slice())),
            )
        })?;
        Ok(key.map(FileKeyHandle::new))
    }

    pub fn wrap_invite_owner_copy(
        &self,
        folder_id: String,
        inner: &FileKeyHandle,
    ) -> Result<EncryptedData, CryptoError> {
        let key = inner.with_key(|key| kdf::FileKey::from_bytes(*key.as_bytes()))?;
        self.with_key(|master| kdf::wrap_invite_owner_copy(master, folder_id.as_bytes(), &key))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    pub fn unwrap_invite_owner_copy(
        &self,
        folder_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Arc<FileKeyHandle>, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        let key = self.with_key(|master| kdf::unwrap_invite_owner_copy(master, folder_id.as_bytes(), &blob))??;
        Ok(FileKeyHandle::new(key))
    }

    pub fn wrap_folder_custody(&self, folder_id: String, inner: &FileKeyHandle) -> Result<EncryptedData, CryptoError> {
        let key = inner.with_key(|key| kdf::FileKey::from_bytes(*key.as_bytes()))?;
        self.with_key(|mk| kdf::wrap_folder_custody(mk, folder_id.as_bytes(), &key))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    pub fn unwrap_folder_custody(
        &self,
        folder_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Arc<FileKeyHandle>, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        let key = self.with_key(|mk| kdf::unwrap_folder_custody(mk, folder_id.as_bytes(), &blob))??;
        Ok(FileKeyHandle::new(key))
    }

    pub fn wrap_link_owner_key(&self, share_id: String, inner: &FileKeyHandle) -> Result<EncryptedData, CryptoError> {
        let key = inner.with_key(|key| kdf::FileKey::from_bytes(*key.as_bytes()))?;
        self.with_key(|mk| kdf::wrap_link_owner_key(mk, share_id.as_bytes(), &key))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    /// The link fragment is the deliberate export exception: JS puts K_c in
    /// the URL. The account master key never crosses this boundary.
    pub fn unwrap_link_owner_key(
        &self,
        share_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        let key = self.with_key(|mk| kdf::unwrap_link_owner_key(mk, share_id.as_bytes(), &blob))??;
        Ok(key.as_bytes().to_vec())
    }

    pub fn wrap_link_owner_token(&self, share_id: String, token: Vec<u8>) -> Result<EncryptedData, CryptoError> {
        let token = Zeroizing::new(token);
        self.with_key(|mk| kdf::wrap_link_owner_token(mk, share_id.as_bytes(), &token))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    pub fn unwrap_link_owner_token(
        &self,
        share_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        let token = self.with_key(|mk| kdf::unwrap_link_owner_token(mk, share_id.as_bytes(), &blob))??;
        Ok(token.to_vec())
    }

    /// Derive the X25519 secret scalar from the master key. Returns 32 bytes.
    pub fn derive_x25519_private(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|mk| beebeeb_core::opaque::derive_x25519_private(mk).to_vec())
    }

    /// Export the raw 32-byte key for writing to the OS keychain.
    /// Only call this once at account setup; never log or transmit the result.
    pub fn export_for_keychain(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|mk| mk.to_bytes().to_vec())
    }

    /// Compute the recovery-check value (stored server-side to verify the phrase).
    pub fn compute_recovery_check(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|mk| beebeeb_core::opaque::compute_recovery_check(mk).to_vec())
    }

    /// Encrypt a filename + optional MIME type using the handle's master key.
    pub fn encrypt_name(
        &self,
        file_id: String,
        filename: String,
        mime_type: Option<String>,
    ) -> Result<String, CryptoError> {
        self.with_key(|mk| encrypt::encrypt_name(mk, &file_id, &filename, mime_type.as_deref()))?
            .map_err(CryptoError::from)
    }

    /// [`encrypt_name`](Self::encrypt_name) that also records the file's chunk
    /// format in the encrypted metadata (task 1908): `chunk_format` 2 = every
    /// upload of this file id is v2, 0 = record nothing (identical to
    /// `encrypt_name`). New file: the encryptor's format (2 only if it wrote
    /// v2). Rename / replace: the value `decrypt_file_metadata` returned for the
    /// file — never upgrade a file with v1 history, never drop a recorded 2.
    pub fn encrypt_name_with_chunk_format(
        &self,
        file_id: String,
        filename: String,
        mime_type: Option<String>,
        chunk_format: u8,
    ) -> Result<String, CryptoError> {
        let chunk_format = ExpectedChunkFormat::from_u8(chunk_format)?;
        self.with_key(|mk| {
            encrypt::encrypt_name_with_chunk_format(mk, &file_id, &filename, mime_type.as_deref(), chunk_format)
        })?
        .map_err(CryptoError::from)
    }

    /// Decrypt a `name_encrypted` envelope into name, MIME type and the
    /// `chunk_format` every content reader of this file must be given
    /// (0 = unrecorded, 2 = v2) — task 1908.
    pub fn decrypt_name_metadata(
        &self,
        file_id: String,
        name_encrypted: String,
    ) -> Result<NameMetadataDto, CryptoError> {
        let meta = self
            .with_key(|mk| encrypt::decrypt_name_metadata(mk, &file_id, &name_encrypted))?
            .map_err(CryptoError::from)?;
        Ok(NameMetadataDto::from(meta))
    }

    /// The metadata reader for FILES (task 1908 round 3): exactly
    /// `decrypt_name_metadata`, except that a plaintext (non-JSON)
    /// `name_encrypted` is refused. A plaintext name carries no chunk-format
    /// pin, so accepting it for a file lets a server re-enable frame-0
    /// detection. Take the content reader's `chunk_format` from THIS for every
    /// file; `decrypt_name_metadata` stays for folders / display.
    pub fn decrypt_file_metadata(
        &self,
        file_id: String,
        name_encrypted: String,
    ) -> Result<NameMetadataDto, CryptoError> {
        let meta = self
            .with_key(|mk| encrypt::decrypt_file_metadata(mk, &file_id, &name_encrypted))?
            .map_err(CryptoError::from)?;
        Ok(NameMetadataDto::from(meta))
    }

    /// Decrypt a `name_encrypted` envelope using the handle's master key.
    pub fn decrypt_name(&self, file_id: String, name_encrypted: String) -> Result<String, CryptoError> {
        self.with_key(|mk| encrypt::decrypt_name(mk, &file_id, &name_encrypted))?
            .map_err(CryptoError::from)
    }

    /// Decrypt a `name_encrypted` envelope and return both filename and MIME type.
    pub fn decrypt_name_with_mime(
        &self,
        file_id: String,
        name_encrypted: String,
    ) -> Result<DecryptedNameWithMime, CryptoError> {
        let (name, mime) = self
            .with_key(|mk| encrypt::decrypt_name_with_mime(mk, &file_id, &name_encrypted))?
            .map_err(CryptoError::from)?;
        Ok(DecryptedNameWithMime { name, mime_type: mime })
    }

    /// Batch-decrypt many file names in ONE FFI call (task 0806 — folder-load
    /// perf). The key never crosses FFI (derived in core from this handle). Each
    /// result mirrors `decrypt_name_with_mime` + tries both the string-UUID and
    /// legacy binary-UUID key forms; a bad item yields `error` for that item only.
    /// Order + length match `items`. An unparseable `file_id` is an item error.
    pub fn decrypt_names(&self, items: Vec<BatchNameItem>) -> Result<Vec<BatchNameResult>, CryptoError> {
        // Parse file_ids up front, keeping index alignment with `items`.
        let parsed: Vec<Option<uuid::Uuid>> = items.iter().map(|it| it.file_id.parse().ok()).collect();
        let batch_input: Vec<(uuid::Uuid, &str)> = items
            .iter()
            .zip(&parsed)
            .filter_map(|(it, id)| id.map(|u| (u, it.name_encrypted.as_str())))
            .collect();

        let mut batch = self
            .with_key(|mk| encrypt::decrypt_names(mk, &batch_input))?
            .into_iter();

        let out = parsed
            .iter()
            .map(|id| match id {
                None => BatchNameResult {
                    name: None,
                    mime_type: None,
                    error: Some("invalid file_id".to_string()),
                },
                Some(_) => match batch.next() {
                    Some(Ok((name, mime))) => BatchNameResult {
                        name: Some(name),
                        mime_type: mime,
                        error: None,
                    },
                    _ => BatchNameResult {
                        name: None,
                        mime_type: None,
                        error: Some("decryption failed".to_string()),
                    },
                },
            })
            .collect();
        Ok(out)
    }

    /// Seal one encrypted client-metadata field (task 1922). `device_key` must
    /// be `None` for field 1 (a device hostname) and `Some` for fields 2-4; the
    /// derived key and the master key never cross FFI.
    pub fn seal_client_meta(
        &self,
        record_key: String,
        device_key: Option<String>,
        field: u8,
        plaintext: String,
    ) -> Result<String, CryptoError> {
        let record = client_meta_uuid(&record_key)?;
        let device = client_meta_optional_uuid(device_key.as_deref())?;
        let field = client_meta_field(field)?;
        self.with_key(|mk| client_meta::seal_client_meta(mk, &record, device.as_ref(), field, &plaintext))?
            .map_err(CryptoError::from)
    }

    /// Open one `bbcm1.` client-metadata envelope (task 1922).
    pub fn open_client_meta(
        &self,
        record_key: String,
        device_key: Option<String>,
        field: u8,
        envelope: String,
    ) -> Result<String, CryptoError> {
        let record = client_meta_uuid(&record_key)?;
        let device = client_meta_optional_uuid(device_key.as_deref())?;
        let field = client_meta_field(field)?;
        self.with_key(|mk| client_meta::open_client_meta(mk, &record, device.as_ref(), field, &envelope))?
            .map_err(CryptoError::from)
    }

    /// Open many client-metadata rows under ONE derived key (task 1922). Order
    /// and length match `items`; a bad row yields `ok: false` for that row only.
    /// A cleared key handle is an error for the whole call, not a batch of
    /// `ok: false` rows that would look like decryption failures.
    pub fn open_client_meta_many(&self, items: Vec<ClientMetaItem>) -> Result<Vec<ClientMetaOpened>, CryptoError> {
        self.with_key(|mk| {
            let key = client_meta::ClientMetaKey::new(mk);
            // Parse the rows first so the valid ones go through core's one-key
            // batch; per-row parse failures stay `ok: false`.
            let mut parsed = Vec::with_capacity(items.len());
            let mut shape_ok = Vec::with_capacity(items.len());
            for item in items {
                let row = client_meta_uuid(&item.record_key).and_then(|record| {
                    Ok((
                        record,
                        client_meta_optional_uuid(item.device_key.as_deref())?,
                        client_meta_field(item.field)?,
                        item.envelope,
                    ))
                });
                shape_ok.push(row.is_ok());
                if let Ok(row) = row {
                    parsed.push(row);
                }
            }
            let mut opened = key.open_many(&parsed).into_iter();
            shape_ok
                .into_iter()
                .map(|ok| {
                    if !ok {
                        return ClientMetaOpened { ok: false, value: None };
                    }
                    match opened.next() {
                        Some(Ok(value)) => ClientMetaOpened {
                            ok: true,
                            value: Some(value),
                        },
                        _ => ClientMetaOpened { ok: false, value: None },
                    }
                })
                .collect()
        })
    }

    /// Encrypt a file from disk, writing each chunk as a `.enc` file.
    ///
    /// Reads the input file chunk-by-chunk, encrypts with AES-256-GCM,
    /// writes `nonce || ciphertext` to `{output_dir}/{chunk_index}.enc`.
    /// Peak memory: 2x chunk_size.
    ///
    /// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
    pub fn encrypt_file(
        &self,
        file_id: String,
        input_path: String,
        output_dir: String,
        profile: String,
        callback: Option<Box<dyn FileProgressCallback>>,
    ) -> Result<EncryptedFileInfo, CryptoError> {
        use std::path::Path;

        let chunk_profile = match profile.as_str() {
            "desktop" => beebeeb_types::ChunkProfile::Desktop,
            "cli" => beebeeb_types::ChunkProfile::Cli,
            "web" => beebeeb_types::ChunkProfile::Web,
            "mobile" => beebeeb_types::ChunkProfile::Mobile,
            "backup" => beebeeb_types::ChunkProfile::BackupAgent,
            _ => {
                return Err(CryptoError::InvalidInput {
                    detail: format!("unknown profile: {profile}"),
                });
            }
        };

        let adapter = callback.as_ref().map(|cb| ProgressAdapter { inner: cb.as_ref() });
        let core_cb: Option<&dyn beebeeb_core::file_encrypt::FileProgressCallback> = adapter
            .as_ref()
            .map(|a| a as &dyn beebeeb_core::file_encrypt::FileProgressCallback);

        let result = self.with_key(|mk| {
            beebeeb_core::file_encrypt::encrypt_file_to_chunks(
                mk,
                &file_id,
                Path::new(&input_path),
                Path::new(&output_dir),
                chunk_profile,
                core_cb,
            )
        })??;

        Ok(EncryptedFileInfo {
            chunks: result
                .chunks
                .into_iter()
                .map(|c| EncryptedChunkInfo {
                    chunk_index: c.chunk_index,
                    output_path: c.output_path.to_string_lossy().into_owned(),
                    nonce: c.nonce,
                    plaintext_size: c.plaintext_size,
                    ciphertext_size: c.ciphertext_size,
                })
                .collect(),
            total_plaintext_bytes: result.total_plaintext_bytes,
            total_ciphertext_bytes: result.total_ciphertext_bytes,
            chunk_size_bytes: result.chunk_size_bytes,
        })
    }

    /// Decrypt chunk files back to a single output file.
    ///
    /// Reads each chunk file (containing `nonce || ciphertext`), decrypts,
    /// and writes plaintext to output. Atomic rename at end.
    ///
    /// `expected_chunk_format` (task 1908) comes from the file's encrypted
    /// metadata (`decrypt_file_metadata`): 0 = unrecorded, 2 = v2.
    pub fn decrypt_file(
        &self,
        file_id: String,
        expected_chunk_format: u8,
        chunk_paths: Vec<String>,
        output_path: String,
        callback: Option<Box<dyn FileProgressCallback>>,
    ) -> Result<DecryptedFileInfo, CryptoError> {
        use std::path::{Path, PathBuf};

        let path_bufs: Vec<PathBuf> = chunk_paths.iter().map(PathBuf::from).collect();
        let path_refs: Vec<&Path> = path_bufs.iter().map(|p| p.as_path()).collect();

        let adapter = callback.as_ref().map(|cb| ProgressAdapter { inner: cb.as_ref() });
        let core_cb: Option<&dyn beebeeb_core::file_encrypt::FileProgressCallback> = adapter
            .as_ref()
            .map(|a| a as &dyn beebeeb_core::file_encrypt::FileProgressCallback);

        let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
        let result = self.with_key(|mk| {
            beebeeb_core::file_encrypt::decrypt_chunks_to_file(
                mk,
                &file_id,
                expected,
                &path_refs,
                Path::new(&output_path),
                core_cb,
            )
        })??;

        Ok(DecryptedFileInfo {
            output_path: result.output_path.to_string_lossy().into_owned(),
            total_bytes: result.total_bytes,
            chunks_processed: result.chunks_processed,
        })
    }
}

/// Opaque handle to a FileKey. Created via `MasterKeyHandle::derive_file_key`
/// for a key derived from the account's master key, or via
/// [`FileKeyHandle::from_key_bytes`] for one the app holds as 32 bytes.
#[derive(uniffi::Object)]
pub struct FileKeyHandle {
    inner: Mutex<Option<kdf::FileKey>>,
}

impl FileKeyHandle {
    fn new(fk: kdf::FileKey) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(fk)),
        })
    }

    fn with_key<T, F: FnOnce(&kdf::FileKey) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(f).ok_or(CryptoError::InvalidInput {
            detail: "key handle has been cleared".into(),
        })
    }
}

#[uniffi::export]
impl FileKeyHandle {
    /// A handle for a per-file key the app holds as raw bytes and that is NOT
    /// derived from the account's master key: a file-request upload's content
    /// key (`open_request_upload`), a shared file's key. Task 1958 round 4: the
    /// with-key name, note and thumbnail functions of this handle
    /// (`encrypt_name_for`, `decrypt_file_metadata`, `encrypt_note_for`, ...)
    /// were reachable only through `MasterKeyHandle::derive_file_key`, so not
    /// for these keys. The WASM side takes the same bytes (`fileKey`).
    ///
    /// Exactly 32 bytes, anything else is an `InvalidInput` error. The input is
    /// zeroized once copied into the key.
    #[uniffi::constructor]
    pub fn from_key_bytes(key: Vec<u8>) -> Result<Arc<Self>, CryptoError> {
        let key = Zeroizing::new(key);
        Ok(Self::new(file_key_from_slice(&key)?))
    }

    /// A fresh random key, independent of the account master key.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>, CryptoError> {
        Ok(Self::new(kdf::FileKey::generate()?))
    }

    /// Combine a link fragment and optional 32-byte Argon2id stretch in core.
    /// Owned secret inputs are wiped on success and every error path.
    #[uniffi::constructor]
    pub fn from_folder_link(k_c: Vec<u8>, passphrase_stretch: Option<Vec<u8>>) -> Result<Arc<Self>, CryptoError> {
        let k_c = Zeroizing::new(k_c);
        let stretch = passphrase_stretch.map(Zeroizing::new);
        let k_c: &[u8; 32] = k_c.as_slice().try_into().map_err(|_| CryptoError::InvalidInput {
            detail: "link fragment key must be exactly 32 bytes".into(),
        })?;
        let stretch: Option<&[u8; 32]> =
            stretch
                .as_ref()
                .map(|s| s.as_slice().try_into())
                .transpose()
                .map_err(|_| CryptoError::InvalidInput {
                    detail: "passphrase stretch must be exactly 32 bytes".into(),
                })?;
        let key = Zeroizing::new(kdf::combine_folder_link_key(k_c, stretch));
        Ok(Self::new(kdf::FileKey::from_bytes(*key)))
    }

    /// Stretch then combine; memory/KDF errors propagate without a plain-link fallback.
    #[uniffi::constructor]
    pub fn from_folder_link_passphrase(
        k_c: Vec<u8>,
        passphrase: String,
        token: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let k_c = Zeroizing::new(k_c);
        let passphrase = Zeroizing::new(passphrase);
        let token = Zeroizing::new(token);
        let k_c: &[u8; 32] = k_c.as_slice().try_into().map_err(|_| CryptoError::InvalidInput {
            detail: "link fragment key must be exactly 32 bytes".into(),
        })?;
        let stretch = kdf::derive_folder_link_passphrase_stretch(&passphrase, &token)?;
        let key = Zeroizing::new(kdf::combine_folder_link_key(k_c, Some(&stretch)));
        Ok(Self::new(kdf::FileKey::from_bytes(*key)))
    }

    /// AES-256-GCM key wrap, no AAD: 12-byte nonce and 48-byte ciphertext.
    pub fn wrap_key(&self, inner: &FileKeyHandle) -> Result<EncryptedData, CryptoError> {
        // Drop the inner lock before borrowing the wrapper (self-wrap is valid).
        let key = inner.with_key(|fk| Zeroizing::new(*fk.as_bytes()))?;
        self.with_key(|fk| encrypt::encrypt_chunk(fk, &*key))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    /// Authenticate a wrap and keep its exactly 32-byte plaintext in a handle.
    pub fn unwrap_key(&self, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<Arc<FileKeyHandle>, CryptoError> {
        let key = Zeroizing::new(self.decrypt_chunk(nonce, ciphertext)?);
        Ok(Self::new(file_key_from_slice(&key)?))
    }

    /// L7 authenticated child wrap. IDs are UUID strings; AAD uses their 16 raw bytes.
    pub fn wrap_folder_child(
        &self,
        shared_folder_id: String,
        item_id: String,
        kind: u8,
        inner: &FileKeyHandle,
    ) -> Result<EncryptedData, CryptoError> {
        let root = uuid::Uuid::parse_str(&shared_folder_id).map_err(|_| CryptoError::InvalidInput {
            detail: "invalid shared folder UUID".into(),
        })?;
        let item = uuid::Uuid::parse_str(&item_id).map_err(|_| CryptoError::InvalidInput {
            detail: "invalid item UUID".into(),
        })?;
        let inner = inner.with_key(|k| kdf::FileKey::from_bytes(*k.as_bytes()))?;
        self.with_key(|k| kdf::wrap_folder_child(k, root.as_bytes(), item.as_bytes(), kind, &inner))?
            .map(|b| encrypted_blob_to_data(&b))
            .map_err(Into::into)
    }
    pub fn unwrap_folder_child(
        &self,
        shared_folder_id: String,
        item_id: String,
        kind: u8,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Arc<FileKeyHandle>, CryptoError> {
        let root = uuid::Uuid::parse_str(&shared_folder_id).map_err(|_| CryptoError::InvalidInput {
            detail: "invalid shared folder UUID".into(),
        })?;
        let item = uuid::Uuid::parse_str(&item_id).map_err(|_| CryptoError::InvalidInput {
            detail: "invalid item UUID".into(),
        })?;
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        self.with_key(|k| kdf::unwrap_folder_child(k, root.as_bytes(), item.as_bytes(), kind, &blob))?
            .map(Self::new)
            .map_err(Into::into)
    }

    /// One-way public key identifier; never exports the key itself.
    pub fn key_id(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|fk| beebeeb_core::folder_key::folder_key_id(fk.as_bytes()).to_vec())
    }

    pub fn encrypt_chunk(&self, plaintext: Vec<u8>) -> Result<EncryptedData, CryptoError> {
        self.with_key(|fk| encrypt::encrypt_chunk(fk, &plaintext))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    pub fn decrypt_chunk(&self, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        self.with_key(|fk| encrypt::decrypt_chunk(fk, &blob))?
            .map_err(Into::into)
    }

    /// [`MasterKeyHandle::decrypt_name_metadata`] with this file key (share
    /// recipients, file-request content keys) — task 1908.
    pub fn decrypt_name_metadata(&self, name_encrypted: String) -> Result<NameMetadataDto, CryptoError> {
        let meta = self
            .with_key(|fk| encrypt::decrypt_name_metadata_with_key(fk, &name_encrypted))?
            .map_err(CryptoError::from)?;
        Ok(NameMetadataDto::from(meta))
    }

    /// [`MasterKeyHandle::decrypt_file_metadata`] with this file key: refuses a
    /// plaintext `name_encrypted` (task 1908 round 3). Use it for files.
    pub fn decrypt_file_metadata(&self, name_encrypted: String) -> Result<NameMetadataDto, CryptoError> {
        let meta = self
            .with_key(|fk| encrypt::decrypt_file_metadata_with_key(fk, &name_encrypted))?
            .map_err(CryptoError::from)?;
        Ok(NameMetadataDto::from(meta))
    }

    /// Seal a thumbnail (already-encoded image bytes) for upload: `nonce(12) ||
    /// ciphertext || tag(16)`, the wire format thumbnails already use. The ONLY
    /// way to seal a thumbnail (task 1908 round 3) — not `encrypt_chunk`: after
    /// the gated seal switch it uses the thumbnail subkey, so a thumbnail can
    /// never be served as file content.
    pub fn encrypt_thumbnail(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let plaintext = Zeroizing::new(plaintext);
        self.with_key(|fk| encrypt::encrypt_thumbnail(fk, &plaintext))?
            .map_err(Into::into)
    }

    /// Seal a thumbnail of an EXISTING file (replace / new version /
    /// regenerated thumbnail) under the rule of its recorded pin (task 1908
    /// round 4): `recorded_pin` = the `chunk_format` that
    /// `decrypt_file_metadata` returned (0 = unrecorded, 2 = v2). A v2 pin is
    /// always sealed under the thumbnail subkey; 0 behaves like
    /// `encrypt_thumbnail`. Any other code is an error.
    pub fn encrypt_thumbnail_for(&self, plaintext: Vec<u8>, recorded_pin: u8) -> Result<Vec<u8>, CryptoError> {
        let pin = ExpectedChunkFormat::from_u8(recorded_pin)?;
        let plaintext = Zeroizing::new(plaintext);
        self.with_key(|fk| encrypt::encrypt_thumbnail_for(fk, &plaintext, pin))?
            .map_err(Into::into)
    }

    /// Open a thumbnail frame (`nonce || ct || tag`): the thumbnail subkey
    /// first, then the legacy raw file key (every thumbnail stored before the
    /// switch). The ONLY way to open a thumbnail — not `decrypt_chunk`.
    pub fn decrypt_thumbnail(&self, frame: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        self.with_key(|fk| encrypt::decrypt_thumbnail(fk, &frame))?
            .map_err(Into::into)
    }

    /// Seal a file note for a file with no recorded pin yet (task 1908 round
    /// 5): returns the canonical `EncryptedBlob` JSON to store in
    /// `note_encrypted`. Follows the gated seal switch, like
    /// `encrypt_thumbnail`. For a note on an EXISTING file use
    /// `encrypt_note_for` with the file's recorded pin. The ONLY way to seal a
    /// note — not `encrypt_chunk` / an `encrypt_metadata`-style call under the
    /// file key (a raw-key note can stand in for a v2 file's name and content).
    pub fn encrypt_note(&self, note: String) -> Result<String, CryptoError> {
        let note = Zeroizing::new(note);
        self.with_key(|fk| encrypt::encrypt_note(fk, &note))?
            .map_err(Into::into)
    }

    /// Seal a note of an EXISTING file under the rule of its recorded pin
    /// (task 1908 round 5): `recorded_pin` = the `chunk_format` that
    /// `decrypt_file_metadata` returned for this file (0 = unrecorded, 2 = v2),
    /// never a server field. A v2 pin is always sealed under the note subkey;
    /// 0 behaves like `encrypt_note`. Any other code is an error.
    pub fn encrypt_note_for(&self, note: String, recorded_pin: u8) -> Result<String, CryptoError> {
        let pin = ExpectedChunkFormat::from_u8(recorded_pin)?;
        let note = Zeroizing::new(note);
        self.with_key(|fk| encrypt::encrypt_note_for(fk, &note, pin))?
            .map_err(Into::into)
    }

    /// Seal the name/MIME envelope under THIS file key, by the rule of a
    /// recorded pin (task 1958). The only name writer that takes a key, so it
    /// serves keys not derived from the master key (file-request uploads,
    /// shared-folder files). A v2 pin records `chunk_format: 2` and is always
    /// sealed under the name subkey; 0 follows the current write rule. Any
    /// other code is an error. `recorded_pin`:
    /// - an EXISTING file (rename): the `chunk_format` that
    ///   `decrypt_file_metadata` returned for this file (0 = unrecorded,
    ///   2 = v2), never a server field;
    /// - a NEW file (e.g. a file-request upload): the pin of the format its
    ///   content was written in, `recorded_for(encryptor.format())` (2 for a v2
    ///   upload, 0 for v1), as at any upload. Nothing else is allowed for a new
    ///   file.
    pub fn encrypt_name_for(
        &self,
        filename: String,
        mime_type: Option<String>,
        recorded_pin: u8,
    ) -> Result<String, CryptoError> {
        let pin = ExpectedChunkFormat::from_u8(recorded_pin)?;
        let filename = Zeroizing::new(filename);
        self.with_key(|fk| encrypt::encrypt_name_for(fk, &filename, mime_type.as_deref(), pin))?
            .map_err(Into::into)
    }

    /// Open a `note_encrypted` envelope: the note subkey first, then the
    /// legacy raw file key (notes stored before the switch). A plaintext value
    /// is an error. The ONLY way to open a note — not `decrypt_chunk` or the
    /// name readers.
    pub fn decrypt_note(&self, note_encrypted: String) -> Result<String, CryptoError> {
        self.with_key(|fk| encrypt::decrypt_note(fk, &note_encrypted))?
            .map_err(Into::into)
    }

    /// Random-access open of ONE file-content frame (`nonce || ct || tag`) at a
    /// known position — for seeking readers (video streaming) that cannot use
    /// the sequential [`ChunkDecryptorHandle`]. `index` is the chunk the caller
    /// asked for and `is_last` is `index == chunk_count - 1`; a server that
    /// serves another chunk or lies about the count fails the tag.
    ///
    /// `format` (1 = v1 legacy, 2 = v2) must come from authenticated data — 2
    /// when the encrypted metadata records v2, else the `chunk_format()` of a
    /// decryptor that opened chunk 0 — never from a server field.
    /// `version_id` (12 bytes, v2 only; ignored for v1) is the `version_id()` of
    /// a decryptor that opened chunk 0, or chunk 0's first 12 bytes: frames of
    /// another upload of the same file id fail.
    pub fn decrypt_chunk_frame(
        &self,
        file_id: String,
        version_id: Vec<u8>,
        index: u32,
        is_last: bool,
        format: u8,
        frame: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let format = ChunkFormat::from_u8(format)?;
        self.with_key(|fk| {
            beebeeb_core::chunk_stream::open_chunk(fk, &file_id, &version_id, index, is_last, format, &frame)
        })?
        .map_err(Into::into)
    }

    pub fn encrypt_metadata(&self, metadata: String) -> Result<EncryptedData, CryptoError> {
        self.with_key(|fk| encrypt::encrypt_metadata(fk, &metadata))?
            .map(|blob| encrypted_blob_to_data(&blob))
            .map_err(Into::into)
    }

    pub fn decrypt_metadata(&self, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Result<String, CryptoError> {
        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        };
        self.with_key(|fk| encrypt::decrypt_metadata(fk, &blob))?
            .map_err(Into::into)
    }
}

// ---------------------------------------------------------------------------
// Streaming chunk primitive — UniFFI handles (mobile/desktop convergence)
// ---------------------------------------------------------------------------
//
// These wrap `beebeeb_core::chunk_stream::{ChunkEncryptor, ChunkDecryptor}` — the
// ONE shared chunk loop — so mobile/desktop drop their bespoke encrypt loops and
// converge on core. The key is derived IN CORE from a borrowed `&MasterKeyHandle`
// (via `with_key`); raw key bytes never cross the FFI boundary.
//
// THREADING CONTRACT (single-consumer): a handle is a stateful, ordered cursor.
// Drive each handle from ONE logical sequence — `next_chunk`/`push_chunk` advance
// an internal index, so concurrent calls would interleave chunk indices and
// corrupt the stream. The `Mutex` exists only because `#[uniffi::Object]` requires
// `Send + Sync`; it is a safety backstop against a torn read, NOT a license for
// concurrent use. There is deliberately NO UniFFI callback inside these handles —
// a callback invoked while the lock is held could re-enter the handle and
// deadlock (contrast `MasterKeyHandle::encrypt_file`, which takes a progress
// callback but never re-enters). Progress is reported by the caller counting the
// chunks it pulls.

/// One encrypted chunk produced by [`ChunkEncryptorHandle`]:
/// `data` = `nonce(12) || ciphertext || tag(16)`.
#[derive(uniffi::Record)]
pub struct EncryptedChunkDto {
    pub index: u32,
    pub data: Vec<u8>,
}

/// One decrypted chunk produced by [`ChunkDecryptorHandle`].
#[derive(uniffi::Record)]
pub struct DecryptedChunkDto {
    pub index: u32,
    pub data: Vec<u8>,
}

/// What to do with an interrupted upload session — see
/// [`ChunkEncryptorHandle::resume_policy`] (task 1908 round 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SessionResumeAction {
    /// Keep the session; re-PUT from chunk 0 (the server skips stored frames).
    ContinueSession,
    /// Never PUT to the old session again; upload from chunk 0 into a new one.
    RestartWithFreshSession,
}

impl From<SessionResume> for SessionResumeAction {
    fn from(r: SessionResume) -> Self {
        match r {
            SessionResume::ContinueSession => SessionResumeAction::ContinueSession,
            SessionResume::RestartWithFreshSession => SessionResumeAction::RestartWithFreshSession,
        }
    }
}

/// Decrypted name metadata (task 1908): `chunk_format` is what every content
/// reader of the file must be given (0 = unrecorded, 2 = v2).
#[derive(uniffi::Record)]
pub struct NameMetadataDto {
    pub name: String,
    pub mime_type: Option<String>,
    pub chunk_format: u8,
}

impl From<encrypt::NameMetadata> for NameMetadataDto {
    fn from(m: encrypt::NameMetadata) -> Self {
        Self {
            name: m.name,
            mime_type: m.mime_type,
            chunk_format: m.chunk_format.as_u8(),
        }
    }
}

/// Summary returned by [`ChunkDecryptorHandle::finish`] after the end-of-stream
/// check (task 1908).
#[derive(uniffi::Record)]
pub struct ChunkDecryptorSummaryDto {
    pub chunk_count: u32,
    /// 1 = v1 legacy, 2 = v2 (position-bound).
    pub format: u8,
}

/// Summary returned by [`ChunkEncryptorHandle::finish`] after the integrity guard.
#[derive(uniffi::Record)]
pub struct ChunkEncryptorSummaryDto {
    pub chunk_count: u32,
    pub total_plaintext: u64,
    pub total_ciphertext: u64,
    pub chunk_size_bytes: u64,
}

fn parse_chunk_profile(profile: &str) -> Result<beebeeb_types::ChunkProfile, CryptoError> {
    match profile {
        "desktop" => Ok(beebeeb_types::ChunkProfile::Desktop),
        "cli" => Ok(beebeeb_types::ChunkProfile::Cli),
        "web" => Ok(beebeeb_types::ChunkProfile::Web),
        "mobile" => Ok(beebeeb_types::ChunkProfile::Mobile),
        "backup" => Ok(beebeeb_types::ChunkProfile::BackupAgent),
        _ => Err(CryptoError::InvalidInput {
            detail: format!("unknown profile: {profile}"),
        }),
    }
}

/// Stateful streaming encryptor handle. Single-consumer (see module note).
///
/// `inner` is `None` only after [`finish`](Self::finish) has consumed the
/// encryptor; any method called afterwards returns `InvalidInput`.
#[derive(uniffi::Object)]
pub struct ChunkEncryptorHandle {
    inner: Mutex<Option<ChunkEncryptor>>,
}

impl ChunkEncryptorHandle {
    /// Run `f` against the live encryptor, or error if it has been finished.
    fn with_inner<T, F: FnOnce(&mut ChunkEncryptor) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
        let enc = guard.as_mut().ok_or(CryptoError::InvalidInput {
            detail: "chunk encryptor handle has been finished or cleared".into(),
        })?;
        Ok(f(enc))
    }
}

#[uniffi::export]
impl ChunkEncryptorHandle {
    /// PULL constructor: stream-encrypt a file from disk. The file is stat'd for
    /// its size and the chunk plan is derived from (`size`, `profile`). The key is
    /// derived in core from the borrowed master key.
    ///
    /// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
    #[uniffi::constructor]
    pub fn from_file(
        master_key: &MasterKeyHandle,
        file_id: String,
        input_path: String,
        profile: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let chunk_profile = parse_chunk_profile(&profile)?;
        let path = std::path::Path::new(&input_path);
        let metadata = std::fs::metadata(path).map_err(|e| CryptoError::Io {
            detail: format!("stat input: {e}"),
        })?;
        let file_size = metadata.len();
        let file = std::fs::File::open(path).map_err(|e| CryptoError::Io {
            detail: format!("open input: {e}"),
        })?;
        // Bound the read-ahead buffer to one chunk (≤8 MiB) — the primitive reads
        // one chunk at a time regardless.
        let plan = beebeeb_types::plan_chunks(file_size, chunk_profile);
        let buf_cap = (plan.chunk_size_bytes as usize).clamp(8 * 1024, 8 * 1024 * 1024);
        let reader = std::io::BufReader::with_capacity(buf_cap, file);
        let enc =
            master_key.with_key(|mk| ChunkEncryptor::from_reader(mk, &file_id, file_size, chunk_profile, reader))??;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(enc)),
        }))
    }

    /// PUSH constructor: the caller slices the plaintext and feeds chunks via
    /// [`push_chunk`](Self::push_chunk). Plan derived from (`file_size`, `profile`).
    #[uniffi::constructor]
    pub fn for_push(
        master_key: &MasterKeyHandle,
        file_id: String,
        file_size: u64,
        profile: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let chunk_profile = parse_chunk_profile(&profile)?;
        let enc = master_key.with_key(|mk| ChunkEncryptor::for_push(mk, &file_id, file_size, chunk_profile))??;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(enc)),
        }))
    }

    /// PULL: emit the next encrypted chunk, or `None` once the plan is exhausted.
    pub fn next_chunk(&self) -> Result<Option<EncryptedChunkDto>, CryptoError> {
        let chunk = self.with_inner(|e| e.next_chunk())??;
        Ok(chunk.map(|c| EncryptedChunkDto {
            index: c.index,
            data: c.data,
        }))
    }

    /// PUSH: encrypt one caller-provided plaintext chunk.
    pub fn push_chunk(&self, plaintext: Vec<u8>) -> Result<EncryptedChunkDto, CryptoError> {
        let chunk = self.with_inner(|e| e.push_chunk(&plaintext))??;
        Ok(EncryptedChunkDto {
            index: chunk.index,
            data: chunk.data,
        })
    }

    /// The chunk plan (size + count) this encryptor follows.
    pub fn chunk_plan(&self) -> Result<ChunkPlanResult, CryptoError> {
        let plan = self.with_inner(|e| e.chunk_plan())?;
        Ok(ChunkPlanResult {
            chunk_size_bytes: plan.chunk_size_bytes,
            chunk_count: plan.chunk_count,
        })
    }

    /// Expected total ciphertext bytes: `file_size + 28 * chunk_count`. Use for
    /// `upload_init` without reading the whole file.
    pub fn expected_total_ciphertext(&self) -> Result<u64, CryptoError> {
        self.with_inner(|e| e.expected_total_ciphertext())
    }

    /// How many chunks have been emitted so far.
    pub fn chunks_emitted(&self) -> Result<u32, CryptoError> {
        self.with_inner(|e| e.chunks_emitted())
    }

    /// The chunk format this encryptor writes: 1 = v1, 2 = v2 (task 1908).
    /// Still 1 during the read-only rollout phase. Record it at upload via
    /// `encrypt_name_with_chunk_format` (2 if this is 2, else 0) so readers
    /// can pin it.
    pub fn chunk_format(&self) -> Result<u8, CryptoError> {
        self.with_inner(|e| e.format().as_u8())
    }

    /// Replace / new version of an EXISTING file (task 1908 round 4, I-1):
    /// write in the format the file's recorded pin requires. `recorded_pin` =
    /// the `chunk_format` that `decrypt_file_metadata` returned for the file
    /// (0 = unrecorded, 2 = v2) — never a server field. A v2 pin forces v2
    /// frames even during the read-only phase (the server keeps the v2
    /// metadata on replace, so v1 frames would never open); 0 keeps the default
    /// write format. Call it right after the constructor, before the first
    /// chunk (afterwards it errors and the handle stays usable as it was). Any
    /// other code is an error.
    ///
    /// **New-file rule (lead ruling 2026-10-17):** pass 2 ONLY when it was
    /// read from an EXISTING file's authenticated metadata. A brand-new file
    /// makes NO call (the default write format applies) and records
    /// `chunk_format()` in its name; passing 2 for a new file would create a
    /// v2 file before the switch. Core cannot enforce this; each client keeps
    /// a test that its new-file path never calls this with 2.
    pub fn apply_recorded_pin(&self, recorded_pin: u8) -> Result<(), CryptoError> {
        let pin = ExpectedChunkFormat::from_u8(recorded_pin)?;
        let mut guard = self.inner.lock().unwrap();
        let enc = guard.as_ref().ok_or(CryptoError::InvalidInput {
            detail: "chunk encryptor handle has been finished or cleared".into(),
        })?;
        if enc.chunks_emitted() != 0 {
            return Err(CryptoError::InvalidInput {
                detail: "apply_recorded_pin must be called before the first chunk".into(),
            });
        }
        // Checked above, so `with_recorded_pin` cannot fail and the handle is
        // never left empty.
        let enc = guard.take().expect("checked Some above");
        *guard = Some(enc.with_recorded_pin(pin)?);
        Ok(())
    }

    /// Resuming an interrupted upload (task 1908 round 3): may THIS (new)
    /// encryptor continue the old server upload session? `stored_format` is the
    /// `chunk_format()` the client persisted next to the session id when it
    /// opened the session (1 = v1, 2 = v2), or `None` when the resume record
    /// does not say. Only a v1 session resumed by a v1 encryptor may continue;
    /// everything else (always for v2) must abandon the session and upload
    /// from chunk 0 into a FRESH session — a v2 upload's frames all bind one
    /// version id, and a new encryptor has a new one. Restart = `POST
    /// /api/v1/files/{id}/upload/abandon` (or wait for the lease to expire),
    /// then init again; on a 409 retry that, never fall back to the old session.
    pub fn resume_policy(&self, stored_format: Option<u8>) -> Result<SessionResumeAction, CryptoError> {
        let stored = stored_format.map(ChunkFormat::from_u8).transpose()?;
        self.with_inner(|e| SessionResumeAction::from(e.resume_policy(stored)))
    }

    /// Consume the encryptor (by value) and return the summary after the integrity
    /// guard (detects a source that shrank). The handle is unusable afterwards.
    pub fn finish(&self) -> Result<ChunkEncryptorSummaryDto, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
        let enc = guard.take().ok_or(CryptoError::InvalidInput {
            detail: "chunk encryptor handle has been finished or cleared".into(),
        })?;
        let summary = enc.finish().map_err(CryptoError::from)?;
        Ok(ChunkEncryptorSummaryDto {
            chunk_count: summary.chunk_count,
            total_plaintext: summary.total_plaintext,
            total_ciphertext: summary.total_ciphertext,
            chunk_size_bytes: summary.chunk_size_bytes,
        })
    }
}

/// Stateful streaming decryptor handle. Single-consumer (see module note).
#[derive(uniffi::Object)]
pub struct ChunkDecryptorHandle {
    inner: Mutex<Option<ChunkDecryptor>>,
}

impl ChunkDecryptorHandle {
    fn with_inner<T, F: FnOnce(&mut ChunkDecryptor) -> T>(&self, f: F) -> Result<T, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
        let dec = guard.as_mut().ok_or(CryptoError::InvalidInput {
            detail: "chunk decryptor handle has been cleared".into(),
        })?;
        Ok(f(dec))
    }
}

#[uniffi::export]
impl ChunkDecryptorHandle {
    /// PULL constructor: stream-decrypt an encrypted file from disk.
    /// `chunk_size_bytes` is the PLAINTEXT chunk size used at encryption (the wire
    /// frame is `nonce(12) + chunk_size + tag(16)`). Errors if it is 0.
    ///
    /// `expected_chunk_format` (task 1908) comes from the file's encrypted
    /// metadata (`decrypt_file_metadata`): 0 = unrecorded, 2 = v2.
    #[uniffi::constructor]
    pub fn from_file(
        master_key: &MasterKeyHandle,
        file_id: String,
        expected_chunk_format: u8,
        chunk_size_bytes: u64,
        input_path: String,
    ) -> Result<Arc<Self>, CryptoError> {
        let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
        let file = std::fs::File::open(std::path::Path::new(&input_path)).map_err(|e| CryptoError::Io {
            detail: format!("open input: {e}"),
        })?;
        let buf_cap = (chunk_size_bytes as usize)
            .saturating_add(28)
            .clamp(8 * 1024, 8 * 1024 * 1024);
        let reader = std::io::BufReader::with_capacity(buf_cap, file);
        let dec = master_key
            .with_key(|mk| ChunkDecryptor::from_reader(mk, &file_id, expected, chunk_size_bytes, reader))??;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(dec)),
        }))
    }

    /// PUSH constructor: the caller feeds wire frames via
    /// [`push_frame`](Self::push_frame). Each frame is self-describing, so no chunk
    /// size is needed.
    ///
    /// `expected_chunk_format` (task 1908) comes from the file's encrypted
    /// metadata (`decrypt_file_metadata`): 0 = unrecorded, 2 = v2.
    #[uniffi::constructor]
    pub fn for_push(
        master_key: &MasterKeyHandle,
        file_id: String,
        expected_chunk_format: u8,
    ) -> Result<Arc<Self>, CryptoError> {
        let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
        let dec = master_key.with_key(|mk| ChunkDecryptor::for_push(mk, &file_id, expected))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(dec)),
        }))
    }

    /// PUSH constructor from a [`FileKeyHandle`] — for callers that hold the
    /// file key but not the owner's master key (share / shared-link recipients).
    /// Preferred over [`for_push_with_file_key`](Self::for_push_with_file_key):
    /// the raw key never reaches Swift/Kotlin. `file_id` must be the id the file
    /// was uploaded under (bound into every v2 frame).
    #[uniffi::constructor]
    pub fn for_push_with_file_key_handle(
        file_key: &FileKeyHandle,
        file_id: String,
        expected_chunk_format: u8,
    ) -> Result<Arc<Self>, CryptoError> {
        let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
        // Copy into a fresh zeroize-on-drop key owned by the decryptor
        // (`FileKey::from_bytes` wipes its by-value input).
        let fk = file_key.with_key(|fk| kdf::FileKey::from_bytes(*fk.as_bytes()))?;
        let dec = ChunkDecryptor::for_push_with_file_key(fk, &file_id, expected);
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(dec)),
        }))
    }

    /// PUSH constructor from a raw 32-byte file key, for hosts that only have
    /// the bytes. Prefer [`for_push_with_file_key_handle`](Self::for_push_with_file_key_handle).
    /// The owned copy that crosses the FFI is zeroized here; the host's own
    /// copy is the host's to wipe.
    #[uniffi::constructor]
    pub fn for_push_with_file_key(
        file_key: Vec<u8>,
        file_id: String,
        expected_chunk_format: u8,
    ) -> Result<Arc<Self>, CryptoError> {
        let file_key = Zeroizing::new(file_key);
        let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)?;
        let fk = file_key_from_slice(&file_key)?;
        let dec = ChunkDecryptor::for_push_with_file_key(fk, &file_id, expected);
        Ok(Arc::new(Self {
            inner: Mutex::new(Some(dec)),
        }))
    }

    /// The file's chunk format (1 = v1 legacy, 2 = v2) once chunk 0 has been
    /// opened; `None` before.
    pub fn chunk_format(&self) -> Result<Option<u8>, CryptoError> {
        self.with_inner(|d| d.format().map(ChunkFormat::as_u8))
    }

    /// v2: the upload's version id (chunk 0's 12-byte nonce) once chunk 0 has
    /// authenticated — what a seeking reader passes to
    /// `FileKeyHandle.decrypt_chunk_frame`. `None` before chunk 0 and for v1.
    pub fn version_id(&self) -> Result<Option<Vec<u8>>, CryptoError> {
        self.with_inner(|d| d.version_id().map(|v| v.to_vec()))
    }

    /// End-of-stream check, consuming the decryptor. MUST be called after the
    /// last pushed frame: it fails if no frame was pushed or if a v2 file ended
    /// before its last chunk (truncation). Treat an `Err` as a failed download
    /// and discard the plaintext. The pull form runs the same check at EOF.
    pub fn finish(&self) -> Result<ChunkDecryptorSummaryDto, CryptoError> {
        let mut guard = self.inner.lock().unwrap();
        let dec = guard.take().ok_or(CryptoError::InvalidInput {
            detail: "chunk decryptor handle has been finished or cleared".into(),
        })?;
        let summary = dec.finish().map_err(CryptoError::from)?;
        Ok(ChunkDecryptorSummaryDto {
            chunk_count: summary.chunk_count,
            format: summary.format.as_u8(),
        })
    }

    /// PULL: emit the next decrypted chunk, or `None` at clean EOF.
    pub fn next_chunk(&self) -> Result<Option<DecryptedChunkDto>, CryptoError> {
        let chunk = self.with_inner(|d| d.next_chunk())??;
        Ok(chunk.map(|c| DecryptedChunkDto {
            index: c.index,
            data: c.data,
        }))
    }

    /// PUSH: decrypt one caller-provided wire frame (`nonce || ciphertext || tag`).
    pub fn push_frame(&self, frame: Vec<u8>) -> Result<DecryptedChunkDto, CryptoError> {
        let chunk = self.with_inner(|d| d.push_frame(&frame))??;
        Ok(DecryptedChunkDto {
            index: chunk.index,
            data: chunk.data,
        })
    }
}

// ---------------------------------------------------------------------------
// Streaming handle smoke tests (in-process — exercises the Send+Sync stateful
// path). Verifies the Rust handle logic + roundtrip; NOT a real on-device upload.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod chunk_stream_handle_tests {
    use super::*;

    fn mk_handle() -> Arc<MasterKeyHandle> {
        // Any 32 bytes is a valid master key for a roundtrip test.
        MasterKeyHandle::from_keychain_bytes(vec![7u8; 32]).unwrap()
    }

    /// What the metadata records for a file written by the default encryptor.
    fn default_expected() -> u8 {
        ExpectedChunkFormat::recorded_for(beebeeb_core::chunk_stream::WRITE_FORMAT).as_u8()
    }

    #[test]
    fn push_roundtrip_via_handles() {
        let mk = mk_handle();
        let file_id = "ffi-push-roundtrip".to_string();
        let data = b"hello via the uniffi chunk-stream handle".to_vec();

        let enc = ChunkEncryptorHandle::for_push(&mk, file_id.clone(), data.len() as u64, "mobile".into()).unwrap();
        assert_eq!(enc.chunk_plan().unwrap().chunk_count, 1);
        // Read-only rollout phase: the FFI encryptor still writes v1.
        assert_eq!(
            enc.chunk_format().unwrap(),
            1,
            "WRITE_FORMAT is v1 until the gated switch"
        );
        let frame = enc.push_chunk(data.clone()).unwrap();
        assert_eq!(frame.index, 0);
        assert_ne!(frame.data, data); // ciphertext != plaintext
        let summary = enc.finish().unwrap();
        assert_eq!(summary.chunk_count, 1);
        assert_eq!(summary.total_plaintext, data.len() as u64);

        let dec = ChunkDecryptorHandle::for_push(&mk, file_id, default_expected()).unwrap();
        let out = dec.push_frame(frame.data).unwrap();
        assert_eq!(out.index, 0);
        assert_eq!(out.data, data);
        assert_eq!(dec.chunk_format().unwrap(), Some(1));
        let s = dec.finish().unwrap();
        assert_eq!((s.chunk_count, s.format), (1, 1));
    }

    /// Task 1908: two equal-size v2 chunks (as a client writes them after the
    /// gated v2 switch). Core-written via the dev-only `test-support` feature.
    fn two_v2_frames(mk: &MasterKeyHandle, file_id: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
        // 5 MiB on the "mobile" ladder (4 MiB chunks) => 2 chunks.
        let data: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 253) as u8).collect();
        let frames = mk
            .with_key(|m| {
                let mut enc =
                    ChunkEncryptor::for_push(m, file_id, data.len() as u64, beebeeb_types::ChunkProfile::Mobile)
                        .unwrap()
                        .with_format(ChunkFormat::V2)
                        .unwrap();
                let cs = enc.chunk_plan().chunk_size_bytes as usize;
                let frames: Vec<Vec<u8>> = data.chunks(cs).map(|c| enc.push_chunk(c).unwrap().data).collect();
                enc.finish().unwrap();
                frames
            })
            .unwrap();
        assert_eq!(frames.len(), 2);
        (data, frames)
    }

    #[test]
    fn handle_rejects_reorder_and_truncation() {
        let mk = mk_handle();
        let (_, frames) = two_v2_frames(&mk, "ffi-v2");

        for expected in [0u8, 2] {
            // Out of order: chunk 1 pushed first.
            let dec = ChunkDecryptorHandle::for_push(&mk, "ffi-v2".into(), expected).unwrap();
            assert!(dec.push_frame(frames[1].clone()).is_err());

            // Truncated: only chunk 0, then finish.
            let dec = ChunkDecryptorHandle::for_push(&mk, "ffi-v2".into(), expected).unwrap();
            dec.push_frame(frames[0].clone()).unwrap();
            assert!(
                dec.finish().is_err(),
                "finish must reject a v2 stream without its last chunk"
            );
        }
        // Unknown expected-format codes are refused, not treated as "detect".
        for bad in [1u8, 3] {
            assert!(ChunkDecryptorHandle::for_push(&mk, "ffi-v2".into(), bad).is_err());
        }
    }

    #[test]
    fn handle_v2_pin_refuses_name_blob_as_frame0() {
        // Review round 2 P1-1 through the FFI: metadata records v2, the server
        // serves the file's own name blob as its only frame.
        let mk = mk_handle();
        let id = "ffi-downgrade";
        let ne = mk
            .encrypt_name_with_chunk_format(id.into(), "a.pdf".into(), Some("application/pdf".into()), 2)
            .unwrap();
        let meta = mk.decrypt_name_metadata(id.into(), ne.clone()).unwrap();
        assert_eq!((meta.name.as_str(), meta.chunk_format), ("a.pdf", 2));
        let blob = parse_name_blob(&ne);
        let forged = [blob.nonce, blob.ciphertext].concat();
        let dec = ChunkDecryptorHandle::for_push(&mk, id.into(), meta.chunk_format).unwrap();
        assert!(dec.push_frame(forged).is_err());
        // A name written without a format reads back as 0 (unrecorded).
        let legacy = mk.encrypt_name(id.into(), "a.pdf".into(), None).unwrap();
        assert_eq!(mk.decrypt_name_metadata(id.into(), legacy).unwrap().chunk_format, 0);
        assert!(
            mk.encrypt_name_with_chunk_format(id.into(), "a".into(), None, 1)
                .is_err()
        );
    }

    #[test]
    fn handle_file_metadata_refuses_plaintext_folder_reader_keeps_it() {
        // Round 3 P1-B through the FFI: files refuse a plaintext name.
        let mk = mk_handle();
        let id = "ffi-plaintext";
        assert!(mk.decrypt_file_metadata(id.into(), "innocent.txt".into()).is_err());
        assert_eq!(
            mk.decrypt_name_metadata(id.into(), "Photos".into()).unwrap().name,
            "Photos"
        );
        let fk = mk.derive_file_key(id.as_bytes().to_vec()).unwrap();
        assert!(fk.decrypt_file_metadata("innocent.txt".into()).is_err());
        // A real envelope reads through both file readers.
        let ne = mk.encrypt_name(id.into(), "a.pdf".into(), None).unwrap();
        assert_eq!(mk.decrypt_file_metadata(id.into(), ne.clone()).unwrap().name, "a.pdf");
        assert_eq!(fk.decrypt_file_metadata(ne).unwrap().chunk_format, 0);
    }

    #[test]
    fn handle_thumbnail_roundtrip_and_resume_policy() {
        let mk = mk_handle();
        let fk = mk.derive_file_key(b"ffi-thumb".to_vec()).unwrap();
        let sealed = fk.encrypt_thumbnail(b"webp bytes".to_vec()).unwrap();
        assert_eq!(fk.decrypt_thumbnail(sealed).unwrap(), b"webp bytes");

        // Round 3 P1-A through the FFI: the default (v1) encryptor may continue
        // a v1 session; an unrecorded record restarts; unknown codes are errors.
        let enc = ChunkEncryptorHandle::for_push(&mk, "ffi-resume".into(), 10, "mobile".into()).unwrap();
        assert_eq!(
            enc.resume_policy(Some(1)).unwrap(),
            SessionResumeAction::ContinueSession
        );
        for stored in [None, Some(2)] {
            assert_eq!(
                enc.resume_policy(stored).unwrap(),
                SessionResumeAction::RestartWithFreshSession,
                "stored {stored:?}"
            );
        }
        assert!(enc.resume_policy(Some(3)).is_err());
    }

    #[test]
    fn handle_replace_of_a_v2_pinned_file_uses_the_recorded_pin() {
        // Task 1908 round 4, I-1 through the FFI: pin from the file's metadata
        // -> apply_recorded_pin -> the new version reads back under that pin.
        let mk = mk_handle();
        let id = "ffi-replace-v2";
        let name = mk
            .encrypt_name_with_chunk_format(id.into(), "a.pdf".into(), None, 2)
            .unwrap();
        let pin = mk.decrypt_file_metadata(id.into(), name).unwrap().chunk_format;
        assert_eq!(pin, 2);
        let data = b"replaced content of a v2-pinned file".to_vec();
        let enc = ChunkEncryptorHandle::for_push(&mk, id.into(), data.len() as u64, "mobile".into()).unwrap();
        enc.apply_recorded_pin(pin).unwrap();
        assert_eq!(enc.chunk_format().unwrap(), 2, "a v2-pinned file must be written as v2");
        let frame = enc.push_chunk(data.clone()).unwrap();
        enc.finish().unwrap();
        let dec = ChunkDecryptorHandle::for_push(&mk, id.into(), pin).unwrap();
        assert_eq!(dec.push_frame(frame.data).unwrap().data, data);
        dec.finish().unwrap();

        // Unrecorded keeps the write format; unknown codes are errors.
        let enc0 = ChunkEncryptorHandle::for_push(&mk, "ffi-replace-v1".into(), 4, "mobile".into()).unwrap();
        enc0.apply_recorded_pin(0).unwrap();
        assert_eq!(enc0.chunk_format().unwrap(), default_write_format());
        for bad in [1u8, 3] {
            let e = ChunkEncryptorHandle::for_push(&mk, "ffi-bad-pin".into(), 4, "mobile".into()).unwrap();
            assert!(e.apply_recorded_pin(bad).is_err(), "pin code {bad}");
        }
    }

    #[test]
    fn handle_thumbnail_for_a_v2_pin_is_not_raw_key_sealed() {
        let mk = mk_handle();
        let fk = mk.derive_file_key(b"ffi-thumb-pin".to_vec()).unwrap();
        let sealed = fk.encrypt_thumbnail_for(b"webp".to_vec(), 2).unwrap();
        assert_eq!(fk.decrypt_thumbnail(sealed.clone()).unwrap(), b"webp");
        assert!(
            fk.decrypt_chunk(sealed[..12].to_vec(), sealed[12..].to_vec()).is_err(),
            "a v2-pinned thumbnail must not open under the raw file key"
        );
        assert!(fk.encrypt_thumbnail_for(b"webp".to_vec(), 7).is_err());
    }

    #[test]
    fn handle_note_for_a_v2_pin_is_subkey_sealed_and_not_a_name() {
        // Task 1908 round 5 through the FFI: a note written for a v2-pinned
        // file never sits under the raw file key and never opens as the
        // file's metadata (the downgrade a raw-key note allowed).
        let mk = mk_handle();
        let id = "ffi-note-v2";
        let name = mk
            .encrypt_name_with_chunk_format(id.into(), "a.pdf".into(), None, 2)
            .unwrap();
        let pin = mk.decrypt_file_metadata(id.into(), name).unwrap().chunk_format;
        assert_eq!(pin, 2);
        let fk = mk.derive_file_key(id.as_bytes().to_vec()).unwrap();
        let note = fk.encrypt_note_for("ffi note".into(), pin).unwrap();
        assert_eq!(fk.decrypt_note(note.clone()).unwrap(), "ffi note");
        let blob = parse_name_blob(&note);
        assert!(
            fk.decrypt_chunk(blob.nonce.clone(), blob.ciphertext.clone()).is_err(),
            "a v2-pinned note must not open under the raw file key"
        );
        assert!(
            fk.decrypt_file_metadata(note.clone()).is_err(),
            "a v2 note must not open as the file's metadata"
        );
        assert!(mk.decrypt_file_metadata(id.into(), note).is_err());

        // Unrecorded follows the write switch; unknown codes are errors.
        let n0 = fk.encrypt_note_for("n0".into(), 0).unwrap();
        assert_eq!(fk.decrypt_note(n0).unwrap(), "n0");
        assert_eq!(fk.decrypt_note(fk.encrypt_note("n".into()).unwrap()).unwrap(), "n");
        for bad in [1u8, 7] {
            assert!(fk.encrypt_note_for("x".into(), bad).is_err(), "pin code {bad}");
        }
        assert!(fk.decrypt_note("a plaintext note".into()).is_err());
    }

    #[test]
    fn handle_name_for_keeps_the_pin_under_a_file_key_handle_1958() {
        // Task 1958 through the FFI: the rename writer of a FileKeyHandle keeps
        // a v2 pin, seals under the name subkey, and for a derived key reads back
        // through the master-key reader too.
        let mk = mk_handle();
        let id = "ffi-name-for";
        let fk = mk.derive_file_key(id.as_bytes().to_vec()).unwrap();
        let renamed = fk
            .encrypt_name_for("renamed.pdf".into(), Some("application/pdf".into()), 2)
            .unwrap();
        let meta = fk.decrypt_file_metadata(renamed.clone()).unwrap();
        assert_eq!((meta.name.as_str(), meta.chunk_format), ("renamed.pdf", 2));
        assert_eq!(
            mk.decrypt_file_metadata(id.into(), renamed.clone())
                .unwrap()
                .chunk_format,
            2
        );
        let blob = parse_name_blob(&renamed);
        assert!(
            fk.decrypt_chunk(blob.nonce.clone(), blob.ciphertext.clone()).is_err(),
            "a v2-pinned name must not open under the raw file key"
        );
        let r0 = fk.encrypt_name_for("r0.txt".into(), None, 0).unwrap();
        assert_eq!(fk.decrypt_file_metadata(r0).unwrap().chunk_format, 0);
        for bad in [1u8, 7] {
            assert!(fk.encrypt_name_for("x".into(), None, bad).is_err(), "pin code {bad}");
        }
    }

    /// The key of the published given-key name vectors (task 1958): 32 bytes
    /// NOT derived from any master key.
    const GIVEN_FILE_KEY: [u8; 32] = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];

    #[test]
    fn a_non_derived_key_reaches_the_name_writer_and_reader_1958_r4() {
        // Task 1958 round 4 (Codex P1): a key the app holds as bytes (a
        // file-request upload's content key, a shared file's key) becomes a
        // FileKeyHandle, and its name round-trips with the pin: what Swift and
        // Kotlin could not do while `derive_file_key` was the only way in.
        let fk = FileKeyHandle::from_key_bytes(GIVEN_FILE_KEY.to_vec()).unwrap();
        for pin in [0u8, 2] {
            let sealed = fk
                .encrypt_name_for("request-upload.pdf".into(), Some("application/pdf".into()), pin)
                .unwrap();
            let meta = fk.decrypt_file_metadata(sealed.clone()).unwrap();
            assert_eq!(meta.name, "request-upload.pdf", "pin {pin}");
            assert_eq!(meta.mime_type.as_deref(), Some("application/pdf"), "pin {pin}");
            assert_eq!(meta.chunk_format, pin, "pin {pin}");
            // The same key as core's, byte for byte: core's with-key reader opens it.
            let core_meta =
                encrypt::decrypt_file_metadata_with_key(&kdf::FileKey::from_bytes(GIVEN_FILE_KEY), &sealed).unwrap();
            assert_eq!(core_meta.chunk_format.as_u8(), pin, "pin {pin}");
        }
        // The rest of the handle is reachable for such a key too (notes).
        let note = fk.encrypt_note_for("a note".into(), 2).unwrap();
        assert_eq!(fk.decrypt_note(note).unwrap(), "a note");
    }

    #[test]
    fn file_key_handle_from_key_bytes_refuses_other_lengths_1958_r4() {
        for len in [0usize, 16, 31, 33, 64] {
            match FileKeyHandle::from_key_bytes(vec![0x42; len]) {
                Err(CryptoError::InvalidInput { .. }) => {}
                Err(other) => panic!("{len} bytes: wrong error {other:?}"),
                Ok(_) => panic!("{len} bytes must be refused"),
            }
        }
    }

    /// The default write format's code (1 during the read-only phase).
    fn default_write_format() -> u8 {
        beebeeb_core::chunk_stream::WRITE_FORMAT.as_u8()
    }

    /// Parse a native `name_encrypted` envelope (numeric-array JSON).
    fn parse_name_blob(json: &str) -> beebeeb_types::EncryptedBlob {
        let (nonce, ciphertext) = beebeeb_core::metadata_wire::parse_encrypted_metadata(json).unwrap();
        beebeeb_types::EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce,
            ciphertext,
        }
    }

    #[test]
    fn handle_with_file_key_and_random_access_frame_open() {
        let mk = mk_handle();
        let (data, frames) = two_v2_frames(&mk, "ffi-fk");
        let fk = mk.derive_file_key(b"ffi-fk".to_vec()).unwrap();
        let fk_bytes = mk
            .with_key(|m| kdf::derive_file_key(m, b"ffi-fk").as_bytes().to_vec())
            .unwrap();

        // File-key decryptors (share recipient path): raw bytes and handle.
        for dec in [
            ChunkDecryptorHandle::for_push_with_file_key(fk_bytes.clone(), "ffi-fk".into(), 2).unwrap(),
            ChunkDecryptorHandle::for_push_with_file_key_handle(&fk, "ffi-fk".into(), 2).unwrap(),
        ] {
            let mut out = Vec::new();
            for f in &frames {
                out.extend(dec.push_frame(f.clone()).unwrap().data);
            }
            assert_eq!(dec.version_id().unwrap().unwrap(), frames[0][..12].to_vec());
            dec.finish().unwrap();
            assert_eq!(out, data);
        }

        // Wrong file id with the right key fails.
        let dec = ChunkDecryptorHandle::for_push_with_file_key_handle(&fk, "other".into(), 2).unwrap();
        assert!(dec.push_frame(frames[0].clone()).is_err());

        // Random access: right position + version opens; wrong position, last
        // flag, version or format fails.
        let vid = frames[0][..12].to_vec();
        assert_eq!(
            fk.decrypt_chunk_frame("ffi-fk".into(), vid.clone(), 1, true, 2, frames[1].clone())
                .unwrap(),
            data[4 * 1024 * 1024..]
        );
        let (_, other_upload) = two_v2_frames(&mk, "ffi-fk");
        for (v, i, last, fmt, frame) in [
            (vid.clone(), 0, false, 2, frames[1].clone()),
            (vid.clone(), 1, false, 2, frames[1].clone()),
            (vid.clone(), 1, true, 1, frames[1].clone()),
            (vid.clone(), 1, true, 9, frames[1].clone()),
            (vid.clone(), 1, true, 2, other_upload[1].clone()),
            (other_upload[0][..12].to_vec(), 1, true, 2, frames[1].clone()),
            (vid[..11].to_vec(), 1, true, 2, frames[1].clone()),
        ] {
            assert!(fk.decrypt_chunk_frame("ffi-fk".into(), v, i, last, fmt, frame).is_err());
        }
    }

    #[test]
    fn contiguous_to_file_binds_file_id_and_rejects_swap() {
        let mk = mk_handle();
        let (data, frames) = two_v2_frames(&mk, "ffi-contig");
        let fk_bytes = mk
            .with_key(|m| kdf::derive_file_key(m, b"ffi-contig").as_bytes().to_vec())
            .unwrap();
        let dir = std::env::temp_dir().join("bb_uniffi_contig_1908");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.bin").to_string_lossy().into_owned();
        let cs = 4 * 1024 * 1024u64;

        let n = decrypt_contiguous_to_file(
            fk_bytes.clone(),
            "ffi-contig".into(),
            2,
            frames.concat(),
            cs,
            out.clone(),
        )
        .unwrap();
        assert_eq!(n, data.len() as u64);
        std::fs::remove_file(&out).unwrap();

        // Truncated to chunk 0: rejected, nothing written.
        assert!(
            decrypt_contiguous_to_file(
                fk_bytes.clone(),
                "ffi-contig".into(),
                2,
                frames[0].clone(),
                cs,
                out.clone()
            )
            .is_err()
        );
        assert!(!std::path::Path::new(&out).exists());

        // Pre-sliced variant: wrong file id rejected; right id opens.
        let pairs = || -> Vec<EncryptedChunkData> {
            frames
                .iter()
                .map(|f| EncryptedChunkData {
                    nonce: f[..12].to_vec(),
                    ciphertext: f[12..].to_vec(),
                })
                .collect()
        };
        assert!(decrypt_chunks_to_file(fk_bytes.clone(), "not-the-id".into(), 2, pairs(), out.clone()).is_err());
        assert_eq!(
            decrypt_chunks_to_file(fk_bytes, "ffi-contig".into(), 2, pairs(), out.clone()).unwrap(),
            data.len() as u64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finished_handle_rejects_reuse() {
        let mk = mk_handle();
        let enc = ChunkEncryptorHandle::for_push(&mk, "x".into(), 4, "mobile".into()).unwrap();
        let _ = enc.push_chunk(vec![1, 2, 3, 4]).unwrap();
        enc.finish().unwrap();
        assert!(enc.push_chunk(vec![0]).is_err());
        assert!(enc.finish().is_err());
        assert!(enc.next_chunk().is_err());
    }

    #[test]
    fn wrong_key_decrypt_errors() {
        let mk = mk_handle();
        let enc = ChunkEncryptorHandle::for_push(&mk, "secret".into(), 5, "mobile".into()).unwrap();
        let frame = enc.push_chunk(b"hello".to_vec()).unwrap();
        let wrong = MasterKeyHandle::from_keychain_bytes(vec![9u8; 32]).unwrap();
        let dec = ChunkDecryptorHandle::for_push(&wrong, "secret".into(), default_expected()).unwrap();
        assert!(dec.push_frame(frame.data).is_err());
    }

    #[test]
    fn pull_file_roundtrip_via_handles() {
        use std::io::Write;
        let mk = mk_handle();
        let dir = std::env::temp_dir().join("beebeeb_uniffi_chunk_stream_pull");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("in.bin");
        // 9 MiB → mobile profile 4 MiB chunks → 3 chunks (4 + 4 + 1).
        let content: Vec<u8> = (0..9 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        std::fs::write(&input, &content).unwrap();

        let enc = ChunkEncryptorHandle::from_file(
            &mk,
            "pullfile".into(),
            input.to_string_lossy().into_owned(),
            "mobile".into(),
        )
        .unwrap();
        let chunk_size = enc.chunk_plan().unwrap().chunk_size_bytes;
        assert_eq!(chunk_size, 4 * 1024 * 1024);

        let enc_path = dir.join("in.enc");
        let mut out_file = std::fs::File::create(&enc_path).unwrap();
        let mut frames = 0u32;
        while let Some(c) = enc.next_chunk().unwrap() {
            out_file.write_all(&c.data).unwrap();
            frames += 1;
        }
        out_file.flush().unwrap();
        drop(out_file);
        assert_eq!(frames, 3);
        let summary = enc.finish().unwrap();
        assert_eq!(summary.total_plaintext, content.len() as u64);

        let dec = ChunkDecryptorHandle::from_file(
            &mk,
            "pullfile".into(),
            default_expected(),
            chunk_size,
            enc_path.to_string_lossy().into_owned(),
        )
        .unwrap();
        let mut recovered = Vec::new();
        while let Some(c) = dec.next_chunk().unwrap() {
            recovered.extend_from_slice(&c.data);
        }
        assert_eq!(recovered, content);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Doc comments are copied into the generated glue (JSDoc in the `.js` and `.d.ts`, Kotlin and Swift doc
    /// comments in the UniFFI bindings). A block-comment closer inside one ends the comment early, which
    /// is a SyntaxError in the glue; an opener starts a nested comment that Kotlin and Swift then wait to
    /// see closed. Neither can be seen by `cargo test` of the generated code, so the source is checked.
    #[test]
    fn no_doc_comment_contains_a_block_comment_token() {
        let offending: Vec<String> = include_str!("lib.rs")
            .lines()
            .enumerate()
            .filter(|(_, line)| {
                let line = line.trim_start();
                line.starts_with("///") || line.starts_with("//!")
            })
            .filter(|(_, line)| line.contains("/*") || line.contains("*/"))
            .map(|(i, line)| format!("lib.rs:{}: {}", i + 1, line.trim()))
            .collect();
        assert!(
            offending.is_empty(),
            "use line comments (or words) inside doc comments, never a block-comment token:\n{}",
            offending.join("\n")
        );
    }

    const TEST_SALT: &[u8] = b"test-salt-16bytes";
    const TEST_FILE_ID: &[u8] = b"file-0001";

    #[test]
    fn roundtrip_derive_master_key() {
        let result = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        assert_eq!(result.key.len(), 32);
    }

    #[test]
    fn roundtrip_derive_file_key() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let fk = derive_file_key(mk.key, TEST_FILE_ID.to_vec()).unwrap();
        assert_eq!(fk.len(), 32);
    }

    #[test]
    fn roundtrip_encrypt_decrypt_chunk() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let fk = derive_file_key(mk.key, TEST_FILE_ID.to_vec()).unwrap();
        let plaintext = b"hello, beebeeb!";

        let encrypted = encrypt_chunk(fk.clone(), plaintext.to_vec()).unwrap();
        assert_eq!(encrypted.cipher_suite, "V1Aes256Gcm");

        let decrypted = decrypt_chunk(fk, encrypted.nonce, encrypted.ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_encrypt_decrypt_metadata() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let fk = derive_file_key(mk.key, TEST_FILE_ID.to_vec()).unwrap();
        let filename = "photos/vacation/IMG_2024.jpg";

        let encrypted = encrypt_metadata(fk.clone(), filename.into()).unwrap();
        let recovered = decrypt_metadata(fk, encrypted.nonce, encrypted.ciphertext).unwrap();
        assert_eq!(recovered, filename);
    }

    #[test]
    fn roundtrip_recovery_phrase() {
        let result = generate_recovery_phrase().unwrap();
        let words: Vec<&str> = result.phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(result.master_key.len(), 32);

        let recovered = recover_from_phrase(result.phrase).unwrap();
        assert_eq!(recovered, result.master_key);
    }

    #[test]
    fn opaque_registration_start_works() {
        let result = opaque_registration_start(b"test-password".to_vec()).unwrap();
        assert!(!result.message.is_empty());
        assert!(!result.state.is_empty());
    }

    #[test]
    fn opaque_login_start_works() {
        let result = opaque_login_start(b"test-password".to_vec()).unwrap();
        assert!(!result.message.is_empty());
        assert!(!result.state.is_empty());
    }

    #[test]
    fn x25519_keypair_roundtrip() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let private = derive_x25519_private(mk.key).unwrap();
        assert_eq!(private.len(), 32);

        let public = derive_x25519_public(private.clone()).unwrap();
        assert_eq!(public.len(), 32);
        assert_ne!(private, public);
    }

    #[test]
    fn x25519_shared_secret_works() {
        let mk_a = derive_master_key("alice".into(), TEST_SALT.to_vec()).unwrap();
        let mk_b = derive_master_key("bob-b".into(), TEST_SALT.to_vec()).unwrap();

        let priv_a = derive_x25519_private(mk_a.key).unwrap();
        let pub_a = derive_x25519_public(priv_a.clone()).unwrap();
        let priv_b = derive_x25519_private(mk_b.key).unwrap();
        let pub_b = derive_x25519_public(priv_b.clone()).unwrap();

        let shared_ab = x25519_shared_secret(priv_a, pub_b).unwrap();
        let shared_ba = x25519_shared_secret(priv_b, pub_a).unwrap();
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn derive_share_key_works() {
        let mk_a = derive_master_key("alice".into(), TEST_SALT.to_vec()).unwrap();
        let mk_b = derive_master_key("bob-b".into(), TEST_SALT.to_vec()).unwrap();

        let priv_a = derive_x25519_private(mk_a.key).unwrap();
        let pub_b = derive_x25519_public(derive_x25519_private(mk_b.key).unwrap()).unwrap();

        let shared = x25519_shared_secret(priv_a, pub_b).unwrap();
        let sk = derive_share_key(shared, b"test-file-uuid".to_vec()).unwrap();
        assert_eq!(sk.len(), 32);
    }

    // --- Constellation transfer tests ---

    // Same fixed vector as beebeeb-core/tests/transfer_vectors.rs — the
    // salt-mismatch guard. If the UniFFI wrapper ever routed through the
    // salt-less derivation, these byte assertions would fail.
    const TRANSFER_FIXED_SHARED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    const TRANSFER_FIXED_SESSION_ID: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    ];
    // hex 47e363480624b26317cc25882f5274a1464cf44ac7658c792cbae33c0c0a62d1
    const TRANSFER_EXPECTED_KEY: [u8; 32] = [
        0x47, 0xe3, 0x63, 0x48, 0x06, 0x24, 0xb2, 0x63, 0x17, 0xcc, 0x25, 0x88, 0x2f, 0x52, 0x74, 0xa1, 0x46, 0x4c,
        0xf4, 0x4a, 0xc7, 0x65, 0x8c, 0x79, 0x2c, 0xba, 0xe3, 0x3c, 0x0c, 0x0a, 0x62, 0xd1,
    ];
    // hex 8ef0155a
    const TRANSFER_EXPECTED_SAS: [u8; 4] = [0x8e, 0xf0, 0x15, 0x5a];

    #[test]
    fn transfer_derive_key_matches_fixed_vector() {
        let tk = transfer_derive_key(TRANSFER_FIXED_SHARED.to_vec(), TRANSFER_FIXED_SESSION_ID.to_vec()).unwrap();
        assert_eq!(tk, TRANSFER_EXPECTED_KEY.to_vec());
    }

    #[test]
    fn transfer_derive_sas_bytes_matches_fixed_vector_and_is_salted() {
        let sas =
            transfer_derive_sas_bytes(TRANSFER_FIXED_SHARED.to_vec(), TRANSFER_FIXED_SESSION_ID.to_vec()).unwrap();
        assert_eq!(sas, TRANSFER_EXPECTED_SAS.to_vec());

        // SALTED (transfer) must differ from the salt-less helper for the same inputs.
        let saltless = derive_sas_bytes(TRANSFER_FIXED_SHARED.to_vec(), b"beebeeb-sas-v1".to_vec(), 4);
        assert_ne!(sas, saltless, "transfer SAS must be salted, not salt-less");
    }

    #[test]
    fn transfer_roundtrip_via_existing_blob_and_x25519_exports() {
        // Exercises the exact exports a mobile sender/receiver composes:
        // random private -> derive_x25519_public -> x25519_shared_secret ->
        // transfer_derive_key -> encrypt_blob / decrypt_blob.
        let sender_priv = vec![0x11u8; 32];
        let receiver_priv = vec![0x22u8; 32];
        let sender_pub = derive_x25519_public(sender_priv.clone()).unwrap();
        let receiver_pub = derive_x25519_public(receiver_priv.clone()).unwrap();

        let sender_shared = x25519_shared_secret(sender_priv, receiver_pub).unwrap();
        let receiver_shared = x25519_shared_secret(receiver_priv, sender_pub).unwrap();
        assert_eq!(sender_shared, receiver_shared);

        let session_id = TRANSFER_FIXED_SESSION_ID.to_vec();
        let sender_key = transfer_derive_key(sender_shared, session_id.clone()).unwrap();
        let receiver_key = transfer_derive_key(receiver_shared, session_id).unwrap();
        assert_eq!(sender_key, receiver_key);

        let payload = b"mobile constellation payload".to_vec();
        let blob = encrypt_blob(sender_key, payload.clone()).unwrap();
        let recovered = decrypt_blob(receiver_key, blob).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn transfer_sas_to_words_returns_four_words() {
        let words = transfer_sas_to_words(vec![0u8, 1, 2, 3]).unwrap();
        assert_eq!(words.len(), 4);
        assert!(words.iter().all(|w| !w.is_empty()));
    }

    #[test]
    fn transfer_derive_key_rejects_bad_lengths() {
        assert!(transfer_derive_key(vec![0u8; 16], TRANSFER_FIXED_SESSION_ID.to_vec()).is_err());
        assert!(transfer_derive_key(TRANSFER_FIXED_SHARED.to_vec(), vec![0u8; 8]).is_err());
    }

    #[test]
    fn compute_recovery_check_works() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let check = compute_recovery_check(mk.key).unwrap();
        assert_eq!(check.len(), 32);
    }

    #[test]
    fn file_request_wrap_unwrap_roundtrip() {
        let mk = derive_master_key("owner".into(), TEST_SALT.to_vec()).unwrap();
        let request_id = b"req-uniffi-001".to_vec();
        // The request private key is itself an X25519 scalar.
        let r_priv = derive_x25519_private(mk.key.clone()).unwrap();

        let wrap_key = derive_request_wrap_key(mk.key.clone(), request_id.clone()).unwrap();
        assert_eq!(wrap_key.len(), 32);

        let wrapped = wrap_request_private(mk.key.clone(), request_id.clone(), r_priv.clone()).unwrap();
        let recovered = unwrap_request_private(mk.key, request_id, wrapped.wrapped, wrapped.nonce).unwrap();
        assert_eq!(recovered, r_priv);
    }

    #[test]
    fn file_request_seal_open_roundtrip() {
        let mk = derive_master_key("owner".into(), TEST_SALT.to_vec()).unwrap();
        let r_priv = derive_x25519_private(mk.key).unwrap();
        let r_pub = derive_x25519_public(r_priv.clone()).unwrap();
        let file_id = b"uniffi-uploaded-file".to_vec();
        let content_key = vec![0x42u8; 32];

        let sealed = seal_to_request(r_pub, file_id.clone(), content_key.clone()).unwrap();
        assert_eq!(sealed.e_pub.len(), 32);
        let opened = open_request_upload(r_priv, sealed.e_pub, file_id, sealed.wrapped_key).unwrap();
        assert_eq!(opened, content_key);
    }

    #[test]
    fn wrong_key_size_returns_error() {
        let result = derive_file_key(vec![0u8; 16], TEST_FILE_ID.to_vec());
        assert!(result.is_err());
    }

    // --- MasterKeyHandle tests ---

    #[test]
    fn master_key_handle_from_recovery_phrase_roundtrip() {
        let phrase_result = generate_recovery_phrase().unwrap();
        let handle = MasterKeyHandle::from_recovery_phrase(phrase_result.phrase.clone()).unwrap();
        // export_for_keychain should return the same bytes as the free function
        let exported = handle.export_for_keychain().unwrap();
        assert_eq!(exported, phrase_result.master_key);
    }

    #[test]
    fn master_key_handle_from_keychain_bytes() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
        let exported = handle.export_for_keychain().unwrap();
        assert_eq!(exported, mk.key);
    }

    #[test]
    fn master_key_handle_bad_keychain_bytes() {
        let result = MasterKeyHandle::from_keychain_bytes(vec![0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn master_key_handle_derive_file_key() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let fk_handle = handle.derive_file_key(TEST_FILE_ID.to_vec()).unwrap();

        // Encrypt then decrypt via the FileKeyHandle
        let plaintext = b"handle roundtrip";
        let enc = fk_handle.encrypt_chunk(plaintext.to_vec()).unwrap();
        let dec = fk_handle.decrypt_chunk(enc.nonce, enc.ciphertext).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn master_key_handle_derive_x25519() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
        let priv_via_handle = handle.derive_x25519_private().unwrap();
        let priv_via_free = derive_x25519_private(mk.key).unwrap();
        assert_eq!(priv_via_handle, priv_via_free);
    }

    #[test]
    fn master_key_handle_recovery_check() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
        let check_via_handle = handle.compute_recovery_check().unwrap();
        let check_via_free = compute_recovery_check(mk.key).unwrap();
        assert_eq!(check_via_handle, check_via_free);
    }

    // --- FileKeyHandle tests ---

    #[test]
    fn file_key_handle_encrypt_decrypt_metadata() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let fk_handle = handle.derive_file_key(TEST_FILE_ID.to_vec()).unwrap();

        let name = "documents/taxes/2025.pdf";
        let enc = fk_handle.encrypt_metadata(name.into()).unwrap();
        let dec = fk_handle.decrypt_metadata(enc.nonce, enc.ciphertext).unwrap();
        assert_eq!(dec, name);
    }

    // --- encrypt_name / decrypt_name tests ---

    #[test]
    fn roundtrip_encrypt_decrypt_name() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let file_id = "file-0001";
        let filename = "vacation.jpg";
        let mime = Some("image/jpeg".to_string());

        let encrypted = encrypt_name(mk.key.clone(), file_id.into(), filename.into(), mime).unwrap();
        let decrypted = decrypt_name(mk.key, file_id.into(), encrypted).unwrap();
        assert_eq!(decrypted, filename);
    }

    #[test]
    fn roundtrip_encrypt_decrypt_name_with_mime() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let file_id = "file-0002";
        let filename = "report.pdf";
        let mime = Some("application/pdf".to_string());

        let encrypted = encrypt_name(mk.key.clone(), file_id.into(), filename.into(), mime.clone()).unwrap();
        let result = decrypt_name_with_mime(mk.key, file_id.into(), encrypted).unwrap();
        assert_eq!(result.name, filename);
        assert_eq!(result.mime_type, mime);
    }

    #[test]
    fn encrypt_name_no_mime() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let file_id = "file-0003";

        let encrypted = encrypt_name(mk.key.clone(), file_id.into(), "notes.txt".into(), None).unwrap();
        let result = decrypt_name_with_mime(mk.key, file_id.into(), encrypted).unwrap();
        assert_eq!(result.name, "notes.txt");
        assert_eq!(result.mime_type, None);
    }

    #[test]
    fn master_key_handle_encrypt_decrypt_name() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let file_id = "file-0004";

        let encrypted = handle
            .encrypt_name(file_id.into(), "photo.png".into(), Some("image/png".into()))
            .unwrap();
        let decrypted = handle.decrypt_name(file_id.into(), encrypted).unwrap();
        assert_eq!(decrypted, "photo.png");
    }

    #[test]
    fn master_key_handle_decrypt_name_with_mime() {
        let mk = derive_master_key("password".into(), TEST_SALT.to_vec()).unwrap();
        let handle = MasterKeyHandle::from_keychain_bytes(mk.key).unwrap();
        let file_id = "file-0005";

        let encrypted = handle
            .encrypt_name(file_id.into(), "video.mp4".into(), Some("video/mp4".into()))
            .unwrap();
        let result = handle.decrypt_name_with_mime(file_id.into(), encrypted).unwrap();
        assert_eq!(result.name, "video.mp4");
        assert_eq!(result.mime_type, Some("video/mp4".into()));
    }

    // --- media utility tests ---

    #[test]
    fn is_media_image() {
        assert!(is_media(Some("image/jpeg".into())));
        assert!(is_media(Some("image/png".into())));
        assert!(is_media(Some("video/mp4".into())));
        assert!(!is_media(Some("application/pdf".into())));
        assert!(!is_media(None));
    }

    #[test]
    fn guess_mime_type_known_extensions() {
        assert_eq!(guess_mime_type("photo.jpg".into()), Some("image/jpeg".into()));
        assert_eq!(guess_mime_type("doc.pdf".into()), Some("application/pdf".into()));
        assert_eq!(guess_mime_type("clip.mp4".into()), Some("video/mp4".into()));
        assert_eq!(guess_mime_type("unknown.xyz".into()), None);
    }

    // --- plan_chunks tests ---

    #[test]
    fn plan_chunks_small_file() {
        let result = plan_chunks(10_000_000, "mobile".into()).unwrap();
        assert_eq!(result.chunk_size_bytes, 4 * 1024 * 1024); // 4 MiB for files <= 64 MiB
        assert_eq!(result.chunk_count, 3); // ceil(10_000_000 / 4_194_304)
    }

    #[test]
    fn plan_chunks_large_file() {
        // N=32 ladder: 2e9 bytes (~1.86 GiB) → base_chunk_size = 64 MiB.
        let result = plan_chunks(2_000_000_000, "desktop".into()).unwrap();
        assert_eq!(result.chunk_size_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn plan_chunks_cli_profile_is_accepted() {
        // The new "cli" profile parses (128 MiB static cap; not binding here).
        let result = plan_chunks(2_000_000_000, "cli".into()).unwrap();
        assert_eq!(result.chunk_size_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn plan_chunks_unknown_profile_errors() {
        let result = plan_chunks(1000, "unknown".into());
        assert!(result.is_err());
    }

    // --- Constellation tests ---

    #[test]
    fn constellation_session_roundtrip() {
        let init = constellation_new_session(300);
        assert_eq!(init.confirm_code.len(), 8);

        let decoder = ConstellationDecoderHandle::new();
        let mut recovered: Option<ConstellationPayloadDto> = None;
        for frame_index in 0..16u32 {
            let frame = constellation_encode(init.payload.clone(), frame_index).unwrap();
            let observations: Vec<ObservedNodeDto> = frame
                .nodes
                .iter()
                .enumerate()
                .map(|(i, n)| ObservedNodeDto {
                    idx: i as u32,
                    brightness: n.brightness,
                    confidence: 1.0,
                })
                .collect();
            recovered = decoder.ingest_frame(observations);
            if recovered.is_some() {
                break;
            }
        }
        let recovered = recovered.expect("decoder recovers payload");
        assert_eq!(recovered.session_id, init.payload.session_id);
        assert_eq!(recovered.ephemeral_pubkey, init.payload.ephemeral_pubkey);
        assert!(constellation_verify_code(recovered, init.confirm_code));
    }
}

// ---------------------------------------------------------------------------
// Blob encrypt/decrypt (P3-1: search index encryption)
// ---------------------------------------------------------------------------

/// Encrypt an arbitrary byte buffer with AES-256-GCM.
///
/// Returns `nonce (12 bytes) || ciphertext`. The key must be exactly 32 bytes.
/// Used by the search index and anywhere an opaque blob needs authenticated encryption.
#[uniffi::export]
pub fn encrypt_blob(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let k: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "key must be exactly 32 bytes".into(),
    })?;
    beebeeb_core::blob::encrypt_blob(&k, &plaintext).map_err(CryptoError::from)
}

/// Decrypt a blob produced by `encrypt_blob`.
///
/// Expects `nonce (12 bytes) || ciphertext`. Returns the original plaintext.
#[uniffi::export]
pub fn decrypt_blob(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let k: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "key must be exactly 32 bytes".into(),
    })?;
    beebeeb_core::blob::decrypt_blob(&k, &ciphertext).map_err(CryptoError::from)
}

// ---------------------------------------------------------------------------
// Metadata wire format (P3-6: metadata serialization)
// ---------------------------------------------------------------------------

/// Serialize a nonce + ciphertext pair into the canonical JSON metadata format.
///
/// Output: `{"nonce":"<base64>","ciphertext":"<base64>"}`.
#[uniffi::export]
pub fn serialize_encrypted_metadata(nonce: Vec<u8>, ciphertext: Vec<u8>) -> String {
    beebeeb_core::metadata_wire::serialize_encrypted_metadata(&nonce, &ciphertext)
}

/// Parse a JSON-encoded encrypted metadata payload.
///
/// Accepts both base64 strings (canonical) and numeric arrays (legacy).
/// Returns a record with `nonce` and `ciphertext` byte vectors.
#[uniffi::export]
pub fn parse_encrypted_metadata(payload: String) -> Result<EncryptedMetadataParts, CryptoError> {
    let (nonce, ciphertext) =
        beebeeb_core::metadata_wire::parse_encrypted_metadata(&payload).map_err(CryptoError::from)?;
    Ok(EncryptedMetadataParts { nonce, ciphertext })
}

// ---------------------------------------------------------------------------
// SHA-256 (P3-4)
// ---------------------------------------------------------------------------

/// Compute the SHA-256 digest of `data`. Returns a 32-byte hash.
#[uniffi::export]
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    beebeeb_core::hash::sha256(&data)
}

// ---------------------------------------------------------------------------
// SAS byte derivation (P2-4)
// ---------------------------------------------------------------------------

/// Derive `length` bytes from a shared secret using HKDF-SHA256.
///
/// Used for SAS word derivation — the word list lookup stays in JS/Swift.
/// `info` is typically `b"beebeeb-sas-v1"` or similar context string.
///
/// NOTE: this is the SALT-LESS (salt = None) helper. For the Constellation
/// transfer channel use `transfer_derive_sas_bytes` below, which is SALTED with
/// the session id — the two are NOT interchangeable.
#[uniffi::export]
pub fn derive_sas_bytes(shared_secret: Vec<u8>, info: Vec<u8>, length: u32) -> Vec<u8> {
    beebeeb_core::hash::derive_sas_bytes(&shared_secret, &info, length as usize)
}

// ---------------------------------------------------------------------------
// Constellation transfer (ephemeral device-to-device E2E channel)
// ---------------------------------------------------------------------------
//
// The transfer key + SAS are HKDF-SHA256 expansions of the X25519 ECDH shared
// secret SALTED with the 16-byte session id (info = "beebeeb-transfer-v1" /
// "beebeeb-sas-v1"). These two exports are the salted derivations; they are
// deliberately DISTINCT from the salt-less `derive_sas_bytes` above.
//
// For the rest of the mobile sender/receiver flow, REUSE the existing exports
// (no new symbols needed):
//   - keypair:  generate 32 random bytes (Swift/Kotlin SecRandom) as the
//               private scalar, then `derive_x25519_public(private)` — matches
//               the WASM `transfer_generate_keypair` precedent (EphemeralSecret
//               can't cross FFI).
//   - ECDH:     `x25519_shared_secret(my_private, their_public)`.
//   - AES-GCM:  `encrypt_blob(key, plaintext)` / `decrypt_blob(key, ciphertext)`
//               — identical `nonce(12) || ciphertext+tag` wire format as
//               `transfer::encrypt_transfer`/`decrypt_transfer`.
//   - SAS words: `transfer_sas_to_words` (below) keeps the wordlist single-sourced.

/// Derive the 32-byte AES-256 transfer key from a shared secret + session id.
///
/// `HKDF-SHA256(ikm = shared_secret, salt = session_id, info = "beebeeb-transfer-v1")`.
/// SALTED with `session_id`. `shared_secret` must be 32 bytes, `session_id` 16.
#[uniffi::export]
pub fn transfer_derive_key(shared_secret: Vec<u8>, session_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let ss: [u8; 32] = shared_secret.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "shared_secret must be 32 bytes".into(),
    })?;
    let sid: [u8; 16] = session_id.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "session_id must be 16 bytes".into(),
    })?;
    Ok(beebeeb_core::transfer::derive_transfer_key(&ss, &sid).to_vec())
}

/// Derive the 4-byte SAS material from a shared secret + session id.
///
/// `HKDF-SHA256(ikm = shared_secret, salt = session_id, info = "beebeeb-sas-v1")`.
/// SALTED with `session_id` — distinct from the salt-less `derive_sas_bytes`.
/// Both devices computing the same 4 bytes (4 SAS words) is the MITM check.
#[uniffi::export]
pub fn transfer_derive_sas_bytes(shared_secret: Vec<u8>, session_id: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let ss: [u8; 32] = shared_secret.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "shared_secret must be 32 bytes".into(),
    })?;
    let sid: [u8; 16] = session_id.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "session_id must be 16 bytes".into(),
    })?;
    Ok(beebeeb_core::transfer::derive_sas(&ss, &sid).to_vec())
}

/// Map 4 SAS bytes to the 4 canonical transfer words.
///
/// Keeps the 256-word transfer wordlist single-sourced in core so Swift/Kotlin
/// and web render identical words for the same SAS bytes. Input must be 4 bytes.
#[uniffi::export]
pub fn transfer_sas_to_words(sas_bytes: Vec<u8>) -> Result<Vec<String>, CryptoError> {
    let sas: [u8; 4] = sas_bytes.try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "sas_bytes must be exactly 4 bytes".into(),
    })?;
    Ok(beebeeb_core::transfer::sas_to_words(&sas).to_vec())
}

// ---------------------------------------------------------------------------
// Upload protocol — synchronous blocking wrapper for Swift/Kotlin
// ---------------------------------------------------------------------------

/// Error from the upload protocol (UniFFI-compatible enum).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum UploadError {
    #[error("network error: {detail}")]
    Network { detail: String },

    #[error("server error (HTTP {status}): {detail}")]
    ServerError { status: u16, detail: String },

    #[error("client error (HTTP {status}): {detail}")]
    ClientError { status: u16, detail: String },

    #[error("rate limited — retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("I/O error: {detail}")]
    UploadIo { detail: String },

    #[error("invalid response: {detail}")]
    InvalidResponse { detail: String },

    #[error("invalid input: {detail}")]
    UploadInvalidInput { detail: String },

    #[error("max retries exhausted ({attempts} attempts): {last_error}")]
    MaxRetriesExhausted { attempts: u32, last_error: String },
}

impl From<beebeeb_upload::UploadError> for UploadError {
    fn from(e: beebeeb_upload::UploadError) -> Self {
        match e {
            beebeeb_upload::UploadError::Network(s) => UploadError::Network { detail: s },
            beebeeb_upload::UploadError::ServerError { status, message } => UploadError::ServerError {
                status,
                detail: message,
            },
            beebeeb_upload::UploadError::ClientError { status, message } => UploadError::ClientError {
                status,
                detail: message,
            },
            beebeeb_upload::UploadError::RateLimited { retry_after_secs } => {
                UploadError::RateLimited { retry_after_secs }
            }
            beebeeb_upload::UploadError::IoError(s) => UploadError::UploadIo { detail: s },
            beebeeb_upload::UploadError::InvalidResponse(s) => UploadError::InvalidResponse { detail: s },
            beebeeb_upload::UploadError::InvalidInput(s) => UploadError::UploadInvalidInput { detail: s },
            beebeeb_upload::UploadError::MaxRetriesExhausted { attempts, last_error } => {
                UploadError::MaxRetriesExhausted { attempts, last_error }
            }
        }
    }
}

/// Result of a successful file upload.
#[derive(uniffi::Record)]
pub struct UploadResultData {
    pub file_id: String,
    pub upload_session_id: String,
    pub chunks_uploaded: u32,
    pub total_bytes: u64,
}

/// Callback interface for upload progress. Implemented by Swift/Kotlin.
#[uniffi::export(callback_interface)]
pub trait UploadProgressCallback: Send + Sync {
    fn on_chunk_uploaded(&self, chunk_index: u32, total_chunks: u32);
    fn on_complete(&self, file_id: String);
    fn on_error(&self, error: String);
}

/// Bridge from UniFFI callback to core upload callback.
///
/// `Send + Sync` are inherited from the trait bound on
/// [`UploadProgressCallback`] — no `unsafe impl` is needed because shared
/// references to a `Sync` trait object are already `Send + Sync`.
struct UploadCallbackBridge<'a>(&'a dyn UploadProgressCallback);

impl beebeeb_upload::UploadProgressCallback for UploadCallbackBridge<'_> {
    fn on_chunk_uploaded(&self, chunk_index: u32, total_chunks: u32) {
        self.0.on_chunk_uploaded(chunk_index, total_chunks);
    }
    fn on_complete(&self, file_id: &str) {
        self.0.on_complete(file_id.to_string());
    }
    fn on_error(&self, error: &str) {
        self.0.on_error(error.to_string());
    }
}

/// Upload encrypted chunk files to the server. Blocking — call from Swift's
/// `Task { }` or Kotlin's `withContext(Dispatchers.IO) { }`.
///
/// Creates a tokio runtime internally and blocks until complete.
// FFI surface (UniFFI): the flat argument list IS the Swift/Kotlin ABI; a
// params struct would have to be mirrored in both bindings for no benefit.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn upload_encrypted_file(
    api_url: String,
    token: String,
    file_id: String,
    name_encrypted: String,
    parent_id: Option<String>,
    mime_type: Option<String>,
    is_media: bool,
    chunk_paths: Vec<String>,
    original_size: u64,
    created_at: Option<String>,
    callback: Option<Box<dyn UploadProgressCallback>>,
) -> Result<UploadResultData, UploadError> {
    let bridge = callback.as_ref().map(|cb| UploadCallbackBridge(cb.as_ref()));
    let core_cb: Option<Box<dyn beebeeb_upload::UploadProgressCallback + '_>> =
        bridge.map(|b| Box::new(b) as Box<dyn beebeeb_upload::UploadProgressCallback>);

    let result = beebeeb_upload::upload_encrypted_file(
        &api_url,
        &token,
        &file_id,
        &name_encrypted,
        parent_id,
        mime_type,
        is_media,
        chunk_paths,
        original_size,
        created_at,
        core_cb,
    )?;

    Ok(UploadResultData {
        file_id: result.file_id,
        upload_session_id: result.upload_session_id,
        chunks_uploaded: result.chunks_uploaded,
        total_bytes: result.total_bytes,
    })
}

// ---------------------------------------------------------------------------
// Quota / plan helpers
// ---------------------------------------------------------------------------

/// Return the base storage quota (in bytes) for a plan slug.
#[uniffi::export]
pub fn plan_base_storage_bytes(plan_slug: String) -> i64 {
    beebeeb_types::Plan::from_slug(&plan_slug).base_storage_bytes()
}

/// Compute the effective quota after add-ons and bonus bytes.
#[uniffi::export]
pub fn plan_effective_quota(plan_slug: String, extra_tb: i64, bonus_bytes: i64) -> i64 {
    let plan = beebeeb_types::Plan::from_slug(&plan_slug);
    beebeeb_types::effective_quota(plan, extra_tb, bonus_bytes)
}

/// Maximum additional TB a plan may purchase.
#[uniffi::export]
pub fn plan_max_extra_tb(plan_slug: String) -> i64 {
    beebeeb_types::Plan::from_slug(&plan_slug).max_extra_tb()
}

/// Whether the plan supports purchasing extra storage.
#[uniffi::export]
pub fn plan_can_add_storage(plan_slug: String) -> bool {
    beebeeb_types::Plan::from_slug(&plan_slug).can_add_storage()
}

/// Monthly cost in cents for a plan with optional add-ons.
#[uniffi::export]
pub fn plan_monthly_cost_cents(plan_slug: String, extra_tb: i64, extra_users: i64) -> i64 {
    let plan = beebeeb_types::Plan::from_slug(&plan_slug);
    beebeeb_types::monthly_cost_cents(plan, extra_tb, extra_users)
}

/// Format a byte count as a human-readable SI string (e.g. "5.0 TB").
#[uniffi::export]
pub fn storage_format_si(bytes: i64) -> String {
    beebeeb_types::format_storage_si(bytes)
}

// ---------------------------------------------------------------------------
// Chunk planning
// ---------------------------------------------------------------------------

/// Result of planning chunks for a file upload. Contains the chunk size and
/// count needed for the given file size and client profile.
#[derive(uniffi::Record)]
pub struct ChunkPlanResult {
    pub chunk_size_bytes: u64,
    pub chunk_count: u64,
}

/// Plan how to split a file into chunks for upload based on the client profile.
///
/// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
/// Returns the chunk size and count for the given file size.
#[uniffi::export]
pub fn plan_chunks(file_size_bytes: u64, profile: String) -> Result<ChunkPlanResult, CryptoError> {
    // Single-source the profile vocabulary through parse_chunk_profile so the
    // "cli" profile (and any future addition) can't drift between call sites.
    let p = parse_chunk_profile(&profile)?;
    let plan = beebeeb_types::plan_chunks(file_size_bytes, p);
    Ok(ChunkPlanResult {
        chunk_size_bytes: plan.chunk_size_bytes,
        chunk_count: plan.chunk_count,
    })
}

// ---------------------------------------------------------------------------
// Constellation visual auth codec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationPayloadDto {
    pub session_id: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expires_at_unix_ms: u64,
    pub confirm_code_hash: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationNodeDto {
    pub kind: u8,
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub brightness: f32,
    pub pulse_phase: f32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationEdgeDto {
    pub from_idx: u32,
    pub to_idx: u32,
    pub weight: f32,
    pub flow_speed: f32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationFrameDto {
    pub frame_index: u32,
    pub seed: u64,
    pub nodes: Vec<ConstellationNodeDto>,
    pub edges: Vec<ConstellationEdgeDto>,
    pub ring_phase: f32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ConstellationSessionInitDto {
    pub payload: ConstellationPayloadDto,
    pub confirm_code: String,
    pub ephemeral_private: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ObservedNodeDto {
    pub idx: u32,
    pub brightness: f32,
    pub confidence: f32,
}

fn payload_to_dto(p: &constellation::ConstellationPayload) -> ConstellationPayloadDto {
    ConstellationPayloadDto {
        session_id: p.session_id.to_vec(),
        ephemeral_pubkey: p.ephemeral_pubkey.to_vec(),
        nonce: p.nonce.to_vec(),
        expires_at_unix_ms: p.expires_at_unix_ms,
        confirm_code_hash: p.confirm_code_hash.to_vec(),
    }
}

fn payload_from_dto(dto: &ConstellationPayloadDto) -> Result<constellation::ConstellationPayload, CryptoError> {
    let session_id: [u8; 16] = dto
        .session_id
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidInput {
            detail: "session_id must be 16 bytes".into(),
        })?;
    let ephemeral_pubkey: [u8; 32] =
        dto.ephemeral_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidInput {
                detail: "ephemeral_pubkey must be 32 bytes".into(),
            })?;
    let nonce: [u8; 16] = dto.nonce.as_slice().try_into().map_err(|_| CryptoError::InvalidInput {
        detail: "nonce must be 16 bytes".into(),
    })?;
    let confirm_code_hash: [u8; 32] =
        dto.confirm_code_hash
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidInput {
                detail: "confirm_code_hash must be 32 bytes".into(),
            })?;
    Ok(constellation::ConstellationPayload {
        session_id,
        ephemeral_pubkey,
        nonce,
        expires_at_unix_ms: dto.expires_at_unix_ms,
        confirm_code_hash,
    })
}

/// Generate a fresh pairing session (display side).
#[uniffi::export]
pub fn constellation_new_session(expires_in_secs: u32) -> ConstellationSessionInitDto {
    let init = constellation::constellation_new_session(expires_in_secs);
    ConstellationSessionInitDto {
        payload: payload_to_dto(&init.payload),
        confirm_code: init.confirm_code,
        ephemeral_private: init.ephemeral_private.to_vec(),
    }
}

/// Encode `payload` into the visualisation frame at `frame_index`.
#[uniffi::export]
pub fn constellation_encode(
    payload: ConstellationPayloadDto,
    frame_index: u32,
) -> Result<ConstellationFrameDto, CryptoError> {
    let p = payload_from_dto(&payload)?;
    let frame = constellation::constellation_encode(&p, frame_index);
    Ok(ConstellationFrameDto {
        frame_index: frame.frame_index,
        seed: frame.seed,
        nodes: frame
            .nodes
            .into_iter()
            .map(|n| ConstellationNodeDto {
                kind: n.kind,
                x: n.x,
                y: n.y,
                z: n.z,
                brightness: n.brightness,
                pulse_phase: n.pulse_phase,
            })
            .collect(),
        edges: frame
            .edges
            .into_iter()
            .map(|e| ConstellationEdgeDto {
                from_idx: e.from_idx,
                to_idx: e.to_idx,
                weight: e.weight,
                flow_speed: e.flow_speed,
            })
            .collect(),
        ring_phase: frame.ring_phase,
    })
}

/// Constant-time verify a 6-digit code against a payload.
#[uniffi::export]
pub fn constellation_verify_code(payload: ConstellationPayloadDto, code: String) -> bool {
    let Ok(p) = payload_from_dto(&payload) else {
        return false;
    };
    constellation::constellation_verify_code(&p, &code)
}

/// Stateful decoder handle.
#[derive(uniffi::Object)]
pub struct ConstellationDecoderHandle {
    inner: constellation::ConstellationDecoder,
}

#[uniffi::export]
impl ConstellationDecoderHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: constellation::ConstellationDecoder::new(),
        })
    }

    /// Feed one observed frame. Returns the recovered payload when the
    /// codeword is complete, otherwise `None`.
    pub fn ingest_frame(&self, observations: Vec<ObservedNodeDto>) -> Option<ConstellationPayloadDto> {
        let obs: Vec<constellation::ObservedNode> = observations
            .into_iter()
            .map(|o| constellation::ObservedNode {
                idx: o.idx,
                brightness: o.brightness,
                confidence: o.confidence,
            })
            .collect();
        self.inner.ingest_frame(&obs).map(|p| payload_to_dto(&p))
    }

    pub fn progress(&self) -> f32 {
        self.inner.progress()
    }

    pub fn shards_collected(&self) -> u32 {
        self.inner.shards_collected()
    }

    pub fn frames_ingested(&self) -> u32 {
        self.inner.frames_ingested()
    }

    pub fn reset(&self) {
        self.inner.reset();
    }
}

// ---------------------------------------------------------------------------
// Thumbnail generation
// ---------------------------------------------------------------------------
//
// NOTE: The WebP-encode path (generate_thumbnail_*) is gated behind the
// `webp-encode` feature. When building for iOS, beebeeb-uniffi is compiled
// WITHOUT this feature so that the webp C binding is not linked (it conflicts
// with aws-lc-sys during iOS cross-compilation). iOS generates WebP thumbnails
// natively via PhotoKit/vImage and calls `resize_for_thumbnail` instead.
//
// For all other targets (CLI, desktop, server, Android), `webp-encode` is
// enabled and the full generate_thumbnail_* API is available.

/// Error from thumbnail generation (UniFFI-compatible enum).
///
/// Always available — used by both `resize_for_thumbnail` and
/// `generate_thumbnail_*`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ThumbnailError {
    #[error("no ladder step produced output under max_bytes")]
    AllStepsFailed,
    #[error("resize failed: {detail}")]
    ResizeFailed { detail: String },
    #[error("encode failed: {detail}")]
    EncodeFailed { detail: String },
    #[error("invalid input: {detail}")]
    ThumbnailInvalidInput { detail: String },
}

impl From<beebeeb_core::thumbnail::ThumbnailError> for ThumbnailError {
    fn from(e: beebeeb_core::thumbnail::ThumbnailError) -> Self {
        match e {
            beebeeb_core::thumbnail::ThumbnailError::AllStepsFailed => ThumbnailError::AllStepsFailed,
            beebeeb_core::thumbnail::ThumbnailError::ResizeFailed(s) => ThumbnailError::ResizeFailed { detail: s },
            beebeeb_core::thumbnail::ThumbnailError::EncodeFailed(s) => ThumbnailError::EncodeFailed { detail: s },
            beebeeb_core::thumbnail::ThumbnailError::InvalidInput(s) => {
                ThumbnailError::ThumbnailInvalidInput { detail: s }
            }
        }
    }
}

/// Resize RGBA pixel data for thumbnail use. Always available (no WebP
/// dependency). The longest side is scaled to `max_dimension` preserving
/// aspect ratio. If the source already fits, the buffer is returned as-is.
///
/// Returns `(resized_rgba, new_width, new_height)` packed as three fields.
///
/// iOS calls this and then encodes to WebP natively via vImage/ImageIO.
#[derive(uniffi::Record)]
pub struct ResizeResult {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[uniffi::export]
pub fn resize_for_thumbnail(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
    max_dimension: u32,
) -> Result<ResizeResult, ThumbnailError> {
    let (resized, w, h) = beebeeb_core::thumbnail::resize_for_thumbnail(&rgba, src_width, src_height, max_dimension)?;
    Ok(ResizeResult {
        rgba: resized,
        width: w,
        height: h,
    })
}

// --- WebP encode path (disabled for iOS) ------------------------------------

#[cfg(feature = "webp-encode")]
/// A single quality-cascade step for thumbnail generation.
#[derive(uniffi::Record)]
pub struct ThumbnailLadderStep {
    pub max_dimension: u32,
    pub quality: f32,
}

#[cfg(feature = "webp-encode")]
/// Configuration for thumbnail generation.
#[derive(uniffi::Record)]
pub struct ThumbnailConfigData {
    pub ladder: Vec<ThumbnailLadderStep>,
    pub target_bytes: u64,
    pub max_bytes: u64,
}

#[cfg(feature = "webp-encode")]
/// Result of thumbnail generation.
#[derive(uniffi::Record)]
pub struct ThumbnailResult {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub quality: f32,
    pub step_index: u32,
}

#[cfg(feature = "webp-encode")]
fn config_from_dto(dto: &ThumbnailConfigData) -> beebeeb_core::thumbnail::ThumbnailConfig {
    beebeeb_core::thumbnail::ThumbnailConfig {
        ladder: dto
            .ladder
            .iter()
            .map(|s| beebeeb_core::thumbnail::LadderStep {
                max_dimension: s.max_dimension,
                quality: s.quality,
            })
            .collect(),
        target_bytes: dto.target_bytes as usize,
        max_bytes: dto.max_bytes as usize,
    }
}

/// Generate a lossy WebP thumbnail from raw RGBA pixel data.
///
/// Tries each step in the config's quality ladder in order. Returns the
/// first result that fits under `target_bytes`. If none fit the target but
/// one fits under `max_bytes`, returns that as a fallback.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
    config: ThumbnailConfigData,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = config_from_dto(&config);
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

/// Convenience: generate a thumbnail using the built-in "medium" config.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail_medium(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = beebeeb_core::thumbnail::ThumbnailConfig::medium();
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

/// Convenience: generate a thumbnail using the built-in "small" config.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail_small(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = beebeeb_core::thumbnail::ThumbnailConfig::small();
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

/// Convenience: generate a thumbnail using the built-in "large" config.
///
/// Not available when building for iOS (feature `webp-encode` is disabled).
#[cfg(feature = "webp-encode")]
#[uniffi::export]
pub fn generate_thumbnail_large(
    rgba: Vec<u8>,
    src_width: u32,
    src_height: u32,
) -> Result<ThumbnailResult, ThumbnailError> {
    let cfg = beebeeb_core::thumbnail::ThumbnailConfig::large();
    let out = beebeeb_core::thumbnail::generate_thumbnail(&rgba, src_width, src_height, &cfg)?;
    Ok(ThumbnailResult {
        data: out.data,
        width: out.width,
        height: out.height,
        quality: out.quality,
        step_index: out.step_index as u32,
    })
}

// ---------------------------------------------------------------------------
// PDF generation
// ---------------------------------------------------------------------------

/// Generate a recovery kit PDF with a title, recovery words, and metadata.
///
/// Returns the raw PDF bytes (valid PDF 1.4).
#[uniffi::export]
pub fn generate_recovery_pdf(
    title: String,
    words: Vec<String>,
    metadata_keys: Vec<String>,
    metadata_values: Vec<String>,
) -> Result<Vec<u8>, CryptoError> {
    if metadata_keys.len() != metadata_values.len() {
        return Err(CryptoError::InvalidInput {
            detail: "metadata_keys and metadata_values must have the same length".into(),
        });
    }
    let pairs: Vec<(&str, &str)> = metadata_keys
        .iter()
        .zip(metadata_values.iter())
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    Ok(beebeeb_core::pdf::generate_recovery_pdf(&title, &words, &pairs))
}

// ---------------------------------------------------------------------------
// Archive parsing
// ---------------------------------------------------------------------------

/// A single entry inside an archive (TAR, GZ, TGZ).
#[derive(uniffi::Record)]
pub struct ArchiveEntryDto {
    pub name: String,
    pub size: u64,
    pub is_directory: bool,
}

/// List entries in a TAR archive from raw bytes.
#[uniffi::export]
pub fn list_tar_entries(data: Vec<u8>) -> Result<Vec<ArchiveEntryDto>, CryptoError> {
    let entries = beebeeb_core::archive::list_tar_entries(&data)?;
    Ok(entries.into_iter().map(archive_entry_to_dto).collect())
}

/// Decompress gzip-compressed data.
#[uniffi::export]
pub fn decompress_gzip(data: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    beebeeb_core::archive::decompress_gzip(&data).map_err(CryptoError::from)
}

/// List entries in an archive, detecting format from the filename extension.
///
/// Supported: `.tar`, `.gz`, `.tgz`, `.tar.gz`.
#[uniffi::export]
pub fn list_archive(data: Vec<u8>, filename: String) -> Result<Vec<ArchiveEntryDto>, CryptoError> {
    let entries = beebeeb_core::archive::list_archive(&data, &filename)?;
    Ok(entries.into_iter().map(archive_entry_to_dto).collect())
}

fn archive_entry_to_dto(e: beebeeb_core::archive::ArchiveEntry) -> ArchiveEntryDto {
    ArchiveEntryDto {
        name: e.name,
        size: e.size,
        is_directory: e.is_directory,
    }
}

// ---------------------------------------------------------------------------
// Download + decrypt — synchronous blocking wrapper for Swift/Kotlin
// ---------------------------------------------------------------------------

/// Result of a successful file download + decrypt.
#[derive(uniffi::Record)]
pub struct DownloadResultData {
    pub output_path: String,
    pub plaintext_size: u64,
    pub chunks_decrypted: u32,
}

/// Callback interface for download progress. Implemented by Swift/Kotlin.
#[uniffi::export(callback_interface)]
pub trait DownloadProgressCallback: Send + Sync {
    fn on_chunk_decrypted(&self, chunk_index: u32, total_chunks: u32);
    fn on_complete(&self, output_path: String);
    fn on_error(&self, error: String);
}

/// Bridge from UniFFI callback to core download callback.
///
/// `Send + Sync` are inherited from the trait bound on
/// [`DownloadProgressCallback`] — no `unsafe impl` is needed because shared
/// references to a `Sync` trait object are already `Send + Sync`.
struct DownloadCallbackBridge<'a>(&'a dyn DownloadProgressCallback);

impl beebeeb_upload::DownloadProgressCallback for DownloadCallbackBridge<'_> {
    fn on_chunk_decrypted(&self, chunk_index: u32, total_chunks: u32) {
        self.0.on_chunk_decrypted(chunk_index, total_chunks);
    }
    fn on_complete(&self, output_path: &str) {
        self.0.on_complete(output_path.to_string());
    }
    fn on_error(&self, error: &str) {
        self.0.on_error(error.to_string());
    }
}

/// Download an encrypted file, decrypt it, and write plaintext to disk.
/// Blocking — call from Swift `Task { }` or Kotlin `withContext(Dispatchers.IO)`.
///
/// Uses the MasterKeyHandle to derive the per-file key via HKDF, then
/// fetches `GET /api/v1/files/{file_id}/download`, splits into chunks,
/// decrypts each with AES-256-GCM, and writes to `output_path`.
///
/// `expected_chunk_format` (task 1908) comes from the file's encrypted
/// metadata (`decrypt_file_metadata`): 0 = unrecorded, 2 = v2.
#[uniffi::export]
pub fn download_and_decrypt_file(
    api_url: String,
    token: String,
    master_key_handle: &MasterKeyHandle,
    file_id: String,
    expected_chunk_format: u8,
    output_path: String,
    callback: Option<Box<dyn DownloadProgressCallback>>,
) -> Result<DownloadResultData, UploadError> {
    let expected = ExpectedChunkFormat::from_u8(expected_chunk_format)
        .map_err(|e| UploadError::UploadInvalidInput { detail: e.to_string() })?;
    // Extract the raw master key bytes while the lock is held, then release.
    let mk_bytes = master_key_handle
        .with_key(|mk| mk.to_bytes())
        .map_err(|_| UploadError::UploadInvalidInput {
            detail: "master key handle has been cleared".into(),
        })?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);

    let bridge = callback.as_ref().map(|cb| DownloadCallbackBridge(cb.as_ref()));
    let core_cb: Option<Box<dyn beebeeb_upload::DownloadProgressCallback + '_>> =
        bridge.map(|b| Box::new(b) as Box<dyn beebeeb_upload::DownloadProgressCallback>);

    let result =
        beebeeb_upload::download_and_decrypt_file(&api_url, &token, &mk, &file_id, expected, &output_path, core_cb)?;

    Ok(DownloadResultData {
        output_path: result.output_path,
        plaintext_size: result.plaintext_size,
        chunks_decrypted: result.chunks_decrypted,
    })
}

// ---------------------------------------------------------------------------
// FileProvider SQLite cache — UniFFI object
// ---------------------------------------------------------------------------

/// A cached file/folder entry for the iOS FileProvider extension.
#[derive(uniffi::Record)]
pub struct CachedFileEntryData {
    pub id: String,
    pub parent_id: Option<String>,
    pub name_encrypted: Option<String>,
    pub name_decrypted: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub is_folder: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

fn cache_entry_to_dto(e: beebeeb_core::fp_cache::CachedFileEntry) -> CachedFileEntryData {
    CachedFileEntryData {
        id: e.id,
        parent_id: e.parent_id,
        name_encrypted: e.name_encrypted,
        name_decrypted: e.name_decrypted,
        mime_type: e.mime_type,
        size_bytes: e.size_bytes,
        is_folder: e.is_folder,
        created_at: e.created_at,
        updated_at: e.updated_at,
    }
}

fn cache_entry_from_dto(d: &CachedFileEntryData) -> beebeeb_core::fp_cache::CachedFileEntry {
    beebeeb_core::fp_cache::CachedFileEntry {
        id: d.id.clone(),
        parent_id: d.parent_id.clone(),
        name_encrypted: d.name_encrypted.clone(),
        name_decrypted: d.name_decrypted.clone(),
        mime_type: d.mime_type.clone(),
        size_bytes: d.size_bytes,
        is_folder: d.is_folder,
        created_at: d.created_at.clone(),
        updated_at: d.updated_at.clone(),
    }
}

/// Opaque handle to a FileProviderCache SQLite database.
///
/// Thread-safe — the underlying connection is mutex-protected.
#[derive(uniffi::Object)]
pub struct FileProviderCacheHandle {
    inner: beebeeb_core::fp_cache::FileProviderCache,
}

#[uniffi::export]
impl FileProviderCacheHandle {
    /// Open (or create) the cache database at `db_path`.
    /// Pass `":memory:"` for an in-memory database (tests).
    #[uniffi::constructor]
    pub fn open(db_path: String) -> Result<Arc<Self>, CryptoError> {
        let cache = beebeeb_core::fp_cache::FileProviderCache::open(&db_path)?;
        Ok(Arc::new(Self { inner: cache }))
    }

    /// Insert or update entries in bulk. Returns the number of rows affected.
    pub fn upsert_entries(&self, entries: Vec<CachedFileEntryData>) -> Result<u32, CryptoError> {
        let core_entries: Vec<beebeeb_core::fp_cache::CachedFileEntry> =
            entries.iter().map(cache_entry_from_dto).collect();
        let count = self.inner.upsert_entries(&core_entries)?;
        Ok(count as u32)
    }

    /// Get all children of a parent folder. Pass `None` for root items.
    pub fn get_children(&self, parent_id: Option<String>) -> Result<Vec<CachedFileEntryData>, CryptoError> {
        let entries = self.inner.get_children(parent_id.as_deref())?;
        Ok(entries.into_iter().map(cache_entry_to_dto).collect())
    }

    /// Get a single item by ID.
    pub fn get_item(&self, id: String) -> Result<Option<CachedFileEntryData>, CryptoError> {
        let entry = self.inner.get_item(&id)?;
        Ok(entry.map(cache_entry_to_dto))
    }

    /// Delete a single entry by ID. Returns `true` if a row was deleted.
    pub fn delete_item(&self, id: String) -> Result<bool, CryptoError> {
        self.inner.delete_item(&id).map_err(CryptoError::from)
    }

    /// Delete all entries. Returns the number of rows deleted.
    pub fn clear(&self) -> Result<u32, CryptoError> {
        let count = self.inner.clear()?;
        Ok(count as u32)
    }

    /// Return the total number of cached entries.
    pub fn count(&self) -> Result<u32, CryptoError> {
        let count = self.inner.count()?;
        Ok(count as u32)
    }
}

// ---------------------------------------------------------------------------
// Search index (task 0784) — UniFFI binding for beebeeb_core::search_index.
// Bindings only; the 0778-B algorithm + crypto are unchanged.
// ---------------------------------------------------------------------------

use beebeeb_core::{search_index, search_sync};

/// One file's (id, name) pair for [`SearchIndexHandle::build`].
#[derive(uniffi::Record)]
pub struct SearchFileEntry {
    pub file_id: String,
    pub name: String,
}

/// An encrypted shard page: opaque ciphertext `blob` plus its (non-secret)
/// `bucket`/`page` coordinates. `blob` is `nonce || ciphertext || tag`.
#[derive(uniffi::Record)]
pub struct EncryptedShardDto {
    pub bucket: u32,
    pub page: u32,
    pub blob: Vec<u8>,
}

fn shard_to_dto(s: search_index::EncryptedShard) -> EncryptedShardDto {
    EncryptedShardDto {
        bucket: s.bucket,
        page: s.page,
        blob: s.blob,
    }
}
fn dto_to_shard(d: EncryptedShardDto) -> search_index::EncryptedShard {
    search_index::EncryptedShard {
        bucket: d.bucket,
        page: d.page,
        blob: d.blob,
    }
}

/// A mutable client-side search index. Build it from a file list, mutate it
/// incrementally (`upsert`/`remove` return the dirty bucket set), query it, and
/// (de)serialize it to encrypted shards for sync. Crypto runs in core against the
/// borrowed master key — raw key bytes never cross FFI.
#[derive(uniffi::Object)]
pub struct SearchIndexHandle {
    inner: Mutex<search_index::SearchIndex>,
}

#[uniffi::export]
impl SearchIndexHandle {
    /// Empty index with the given shard count (clamped to ≥ 1).
    #[uniffi::constructor]
    pub fn new(num_shards: u32) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(search_index::SearchIndex::new(num_shards)),
        })
    }

    /// Build from `(file_id, name)` pairs.
    #[uniffi::constructor]
    pub fn build(files: Vec<SearchFileEntry>, num_shards: u32) -> Arc<Self> {
        let pairs: Vec<(String, String)> = files.into_iter().map(|f| (f.file_id, f.name)).collect();
        Arc::new(Self {
            inner: Mutex::new(search_index::SearchIndex::build(&pairs, num_shards)),
        })
    }

    /// Reconstruct from encrypted shards (decrypts each with the master key).
    /// `num_shards` must match the value the shards were built with.
    #[uniffi::constructor]
    pub fn from_encrypted_shards(
        master_key: &MasterKeyHandle,
        shards: Vec<EncryptedShardDto>,
        num_shards: u32,
    ) -> Result<Arc<Self>, CryptoError> {
        let core_shards: Vec<search_index::EncryptedShard> = shards.into_iter().map(dto_to_shard).collect();
        let idx = master_key
            .with_key(|mk| search_index::SearchIndex::from_encrypted_shards(mk, &core_shards, num_shards))??;
        Ok(Arc::new(Self { inner: Mutex::new(idx) }))
    }

    /// Shard count this index uses.
    pub fn num_shards(&self) -> u32 {
        self.inner.lock().unwrap().num_shards()
    }

    /// Number of indexed files.
    pub fn file_count(&self) -> u64 {
        self.inner.lock().unwrap().file_count() as u64
    }

    /// Insert or update a file (add or rename). Returns the buckets whose shards
    /// changed — re-encrypt only these for an incremental sync.
    pub fn upsert(&self, file_id: String, name: String) -> Vec<u32> {
        self.inner.lock().unwrap().upsert(&file_id, &name).into_iter().collect()
    }

    /// Remove a file. Returns the dirty bucket set (empty if not indexed).
    pub fn remove(&self, file_id: String) -> Vec<u32> {
        self.inner.lock().unwrap().remove(&file_id).into_iter().collect()
    }

    /// Search; returns the matching `file_id`s.
    pub fn query(&self, term: String) -> Vec<String> {
        self.inner.lock().unwrap().query(&term).into_iter().collect()
    }

    /// Encrypt every non-empty shard page of the index.
    pub fn encrypt_shards(&self, master_key: &MasterKeyHandle) -> Result<Vec<EncryptedShardDto>, CryptoError> {
        let idx = self.inner.lock().unwrap();
        let shards = master_key.with_key(|mk| idx.encrypt_shards(mk))??;
        Ok(shards.into_iter().map(shard_to_dto).collect())
    }

    /// Encrypt only the given buckets' shard pages (incremental sync) — pass the
    /// dirty set from `upsert`/`remove`. An emptied bucket yields no pages.
    pub fn encrypt_buckets(
        &self,
        master_key: &MasterKeyHandle,
        buckets: Vec<u32>,
    ) -> Result<Vec<EncryptedShardDto>, CryptoError> {
        let set: std::collections::BTreeSet<u32> = buckets.into_iter().collect();
        let idx = self.inner.lock().unwrap();
        let shards = master_key.with_key(|mk| idx.encrypt_buckets(mk, &set))??;
        Ok(shards.into_iter().map(shard_to_dto).collect())
    }
}

/// A shard reference (coordinate + last-known version) for [`search_index_sync_plan`].
#[derive(uniffi::Record)]
pub struct ShardRefDto {
    pub bucket: u32,
    pub page: u32,
    pub version: i64,
}

/// A shard coordinate — a target in a [`SyncPlanDto`].
#[derive(uniffi::Record)]
pub struct ShardCoordDto {
    pub bucket: u32,
    pub page: u32,
}

/// The shard sync plan: coordinates to PUT / GET / DELETE on the server.
#[derive(uniffi::Record)]
pub struct SyncPlanDto {
    pub to_put: Vec<ShardCoordDto>,
    pub to_get: Vec<ShardCoordDto>,
    pub to_delete: Vec<ShardCoordDto>,
}

/// Compute which shards to PUT/GET/DELETE to converge the client's `local` set
/// with the server `remote` manifest (last-writer-wins). `local_is_authoritative`
/// = true treats a server-only coordinate as a stale shard to DELETE (use after a
/// full local rebuild); false treats it as a shard to GET.
#[uniffi::export]
pub fn search_index_sync_plan(
    local: Vec<ShardRefDto>,
    remote: Vec<ShardRefDto>,
    local_is_authoritative: bool,
) -> SyncPlanDto {
    let to_ref = |r: &ShardRefDto| search_sync::ShardRef {
        bucket: r.bucket,
        page: r.page,
        version: r.version,
    };
    let local: Vec<_> = local.iter().map(to_ref).collect();
    let remote: Vec<_> = remote.iter().map(to_ref).collect();
    let plan = search_sync::diff_manifest(&local, &remote, local_is_authoritative);
    let to_coord = |c: &search_sync::ShardCoord| ShardCoordDto {
        bucket: c.bucket,
        page: c.page,
    };
    SyncPlanDto {
        to_put: plan.to_put.iter().map(to_coord).collect(),
        to_get: plan.to_get.iter().map(to_coord).collect(),
        to_delete: plan.to_delete.iter().map(to_coord).collect(),
    }
}

// ---------------------------------------------------------------------------
// Onboarding (task 1744): password policy, breach check, signup ceremony
// ---------------------------------------------------------------------------
//
// Thin wrappers over `beebeeb_core::onboarding`. All logic lives in core; this
// section only converts types. The ceremony and the breach check are handles
// (`#[uniffi::Object]`) so the password, phrase and master key stay in Rust
// memory in zeroizing buffers; the master key leaves the ceremony as a
// `MasterKeyHandle`, never as bytes.

use beebeeb_core::onboarding as onb;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasswordStrengthDto {
    TooShort,
    Fair,
    Good,
    Strong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PasswordHintDto {
    None,
    NeedMoreCharacters,
    MixCaseAndAddNumberOrSymbol,
    MixCase,
    AddNumberOrSymbol,
}

/// Result of evaluating a password against the server's policy. Contains no
/// part of the password.
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasswordEvaluationDto {
    pub length: u32,
    pub min_length: u32,
    pub missing_characters: u32,
    pub meets_minimum: bool,
    pub has_mixed_case: bool,
    pub has_number_or_symbol: bool,
    pub strength: PasswordStrengthDto,
    /// Meter level 1 (too short) to 4 (strong).
    pub level: u8,
    pub hint: PasswordHintDto,
}

impl From<onb::PasswordEvaluation> for PasswordEvaluationDto {
    fn from(e: onb::PasswordEvaluation) -> Self {
        Self {
            length: e.length,
            min_length: e.min_length,
            missing_characters: e.missing_characters,
            meets_minimum: e.meets_minimum,
            has_mixed_case: e.has_mixed_case,
            has_number_or_symbol: e.has_number_or_symbol,
            strength: match e.strength {
                onb::PasswordStrength::TooShort => PasswordStrengthDto::TooShort,
                onb::PasswordStrength::Fair => PasswordStrengthDto::Fair,
                onb::PasswordStrength::Good => PasswordStrengthDto::Good,
                onb::PasswordStrength::Strong => PasswordStrengthDto::Strong,
            },
            level: e.strength.level(),
            hint: match e.hint {
                onb::PasswordHint::None => PasswordHintDto::None,
                onb::PasswordHint::NeedMoreCharacters => PasswordHintDto::NeedMoreCharacters,
                onb::PasswordHint::MixCaseAndAddNumberOrSymbol => PasswordHintDto::MixCaseAndAddNumberOrSymbol,
                onb::PasswordHint::MixCase => PasswordHintDto::MixCase,
                onb::PasswordHint::AddNumberOrSymbol => PasswordHintDto::AddNumberOrSymbol,
            },
        }
    }
}

/// Evaluate a password against the server's `policy.password.min_length`
/// (clamped up to the core floor of 12).
#[uniffi::export]
pub fn evaluate_password(password: String, min_length: u32) -> PasswordEvaluationDto {
    // UniFFI hands over an owned String; wipe that allocation when we are done.
    let password = Zeroizing::new(password);
    let policy = onb::PasswordPolicy::from_server(min_length);
    onb::evaluate_password(&password, &policy).into()
}

/// Verdict of a breach check. `NotRequired` is constructed by the app when the
/// onboarding document declares no breach check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BreachVerdictDto {
    Clean,
    Breached { count: u64 },
    CheckFailedAllowed,
    CheckFailedBlocked,
    NotRequired,
}

impl From<onb::BreachVerdict> for BreachVerdictDto {
    fn from(v: onb::BreachVerdict) -> Self {
        match v {
            onb::BreachVerdict::Clean => Self::Clean,
            onb::BreachVerdict::Breached { count } => Self::Breached { count },
            onb::BreachVerdict::CheckFailedAllowed => Self::CheckFailedAllowed,
            onb::BreachVerdict::CheckFailedBlocked => Self::CheckFailedBlocked,
            onb::BreachVerdict::NotRequired => Self::NotRequired,
        }
    }
}

impl From<BreachVerdictDto> for onb::BreachVerdict {
    fn from(v: BreachVerdictDto) -> Self {
        match v {
            BreachVerdictDto::Clean => Self::Clean,
            BreachVerdictDto::Breached { count } => Self::Breached { count },
            BreachVerdictDto::CheckFailedAllowed => Self::CheckFailedAllowed,
            BreachVerdictDto::CheckFailedBlocked => Self::CheckFailedBlocked,
            BreachVerdictDto::NotRequired => Self::NotRequired,
        }
    }
}

/// Whether the app may let the user continue with this password. `Breached`
/// and `CheckFailedBlocked` stop it. Kept in core so apps do not re-derive it.
#[uniffi::export]
pub fn breach_verdict_allows_proceeding(verdict: BreachVerdictDto) -> bool {
    onb::BreachVerdict::from(verdict).allows_proceeding()
}

/// True when the corpus was not actually consulted (outage, either policy).
#[uniffi::export]
pub fn breach_verdict_check_failed(verdict: BreachVerdictDto) -> bool {
    onb::BreachVerdict::from(verdict).check_failed()
}

/// k-anonymity breach check for one password. Core hashes and matches; **the app
/// makes the HTTP call**, to the endpoint the onboarding document declares in
/// `policy.password.breach_check.endpoint` (Beebeeb's own API, never a third
/// party). Only `prefix()` (5 hex chars) may be sent. The rest of the digest
/// stays in this handle and is zeroized when it is released.
///
/// The handle is bound to the password it was made from and remembers the
/// answer: pass it to `SignupCeremonyHandle.set_password`, which refuses a
/// check made for a different password. A response body over 262144 bytes is
/// treated as an outage, so stop reading the response at that size.
#[derive(uniffi::Object)]
pub struct BreachCheckHandle {
    check: Mutex<onb::BreachCheck>,
}

#[uniffi::export]
impl BreachCheckHandle {
    #[uniffi::constructor]
    pub fn new(password: String) -> Arc<Self> {
        let password = Zeroizing::new(password);
        Arc::new(Self {
            check: Mutex::new(onb::BreachCheck::new(&password)),
        })
    }

    /// The 5 upper-case hex characters to send to the server.
    pub fn prefix(&self) -> String {
        lock_tolerant(&self.check).prefix().to_owned()
    }

    /// Record the answer and return the verdict for display. `body` is the
    /// response text of a 2xx answer, or `None` when the request failed
    /// (network error, timeout, non-2xx). An empty body counts as a failed
    /// request. `fail_open` is `policy.password.breach_check.fail_open` and
    /// only shapes this display value: the ceremony applies the value it was
    /// constructed with.
    ///
    /// `requested_prefix` is the prefix the request URL (or the cache entry)
    /// actually used. If it is not this password's prefix this throws
    /// `BreachPrefixMismatch` and records nothing: a body for another prefix
    /// would otherwise evaluate as clean.
    pub fn evaluate(
        &self,
        requested_prefix: String,
        body: Option<String>,
        fail_open: bool,
    ) -> Result<BreachVerdictDto, OnboardingError> {
        let response = match body.as_deref() {
            Some(b) => onb::BreachResponse::Body(b),
            None => onb::BreachResponse::Unavailable,
        };
        lock_tolerant(&self.check)
            .record_and_evaluate(&requested_prefix, response, fail_open)
            .map(Into::into)
            .map_err(Into::into)
    }
}

/// Lock a mutex, recovering the data if a panic in another call poisoned it:
/// one panicking call must not turn every later call on the handle into a
/// panic across the FFI boundary.
fn lock_tolerant<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CeremonyStepDto {
    VerifyEmail,
    SetPassword,
    SavePhrase,
    ConfirmPhrase,
    CreateAccount,
    Done,
}

impl From<onb::CeremonyStep> for CeremonyStepDto {
    fn from(s: onb::CeremonyStep) -> Self {
        match s {
            onb::CeremonyStep::VerifyEmail => Self::VerifyEmail,
            onb::CeremonyStep::SetPassword => Self::SetPassword,
            onb::CeremonyStep::SavePhrase => Self::SavePhrase,
            onb::CeremonyStep::ConfirmPhrase => Self::ConfirmPhrase,
            onb::CeremonyStep::CreateAccount => Self::CreateAccount,
            onb::CeremonyStep::Done => Self::Done,
        }
    }
}

/// The server step id a ceremony step belongs to (`save_recovery_phrase` for
/// both phrase parts).
#[uniffi::export]
pub fn ceremony_step_spec_id(step: CeremonyStepDto) -> String {
    let core = match step {
        CeremonyStepDto::VerifyEmail => onb::CeremonyStep::VerifyEmail,
        CeremonyStepDto::SetPassword => onb::CeremonyStep::SetPassword,
        CeremonyStepDto::SavePhrase => onb::CeremonyStep::SavePhrase,
        CeremonyStepDto::ConfirmPhrase => onb::CeremonyStep::ConfirmPhrase,
        CeremonyStepDto::CreateAccount => onb::CeremonyStep::CreateAccount,
        CeremonyStepDto::Done => onb::CeremonyStep::Done,
    };
    core.spec_step_id().to_owned()
}

/// Errors from the signup ceremony. Distinct from [`CryptoError`] so the UI can
/// branch on the cause (too short, breached, wrong word) without parsing text.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OnboardingError {
    #[error("cannot {action} yet: step {blocking:?} is not done")]
    StepNotDone { action: String, blocking: CeremonyStepDto },

    #[error("cannot {action}: {reason}")]
    InvalidState { action: String, reason: String },

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("password is too short: {length} characters, minimum {min_length}")]
    PasswordTooShort { length: u32, min_length: u32 },

    #[error("password appears in {count} known breaches")]
    PasswordBreached { count: u64 },

    #[error("the breach check could not run and the server requires it")]
    BreachCheckBlocked,

    #[error("the breach check is required and has not been answered")]
    BreachCheckMissing,

    #[error("the breach check was run for a different password")]
    BreachCheckStale,

    #[error("the breach lookup was made for a different prefix than this password's")]
    BreachPrefixMismatch,

    #[error("the recovery phrase is not available")]
    PhraseUnavailable,

    #[error("expected {expected} words, got {got}")]
    PhraseAnswerCount { expected: u32, got: u32 },

    #[error("one or more words are incorrect")]
    PhraseWordMismatch,

    #[error("crypto error: {detail}")]
    Crypto { detail: String },
}

impl From<onb::BreachError> for OnboardingError {
    fn from(e: onb::BreachError) -> Self {
        match e {
            onb::BreachError::PrefixMismatch => Self::BreachPrefixMismatch,
        }
    }
}

impl From<onb::CeremonyError> for OnboardingError {
    fn from(e: onb::CeremonyError) -> Self {
        match e {
            onb::CeremonyError::StepNotDone { action, blocking } => Self::StepNotDone {
                action: action.to_owned(),
                blocking: blocking.into(),
            },
            onb::CeremonyError::InvalidState { action, reason } => Self::InvalidState {
                action: action.to_owned(),
                reason: reason.to_owned(),
            },
            onb::CeremonyError::PasswordMismatch => Self::PasswordMismatch,
            onb::CeremonyError::PasswordTooShort { length, min_length } => {
                Self::PasswordTooShort { length, min_length }
            }
            onb::CeremonyError::PasswordBreached { count } => Self::PasswordBreached { count },
            onb::CeremonyError::BreachCheckBlocked => Self::BreachCheckBlocked,
            onb::CeremonyError::BreachCheckMissing => Self::BreachCheckMissing,
            onb::CeremonyError::BreachCheckStale => Self::BreachCheckStale,
            onb::CeremonyError::PhraseUnavailable => Self::PhraseUnavailable,
            onb::CeremonyError::PhraseAnswerCount { expected, got } => Self::PhraseAnswerCount {
                expected: expected as u32,
                got: got as u32,
            },
            onb::CeremonyError::PhraseWordMismatch => Self::PhraseWordMismatch,
            onb::CeremonyError::Crypto(c) => Self::Crypto { detail: c.to_string() },
        }
    }
}

/// What `opaque/register-finish` takes from the client. No `Debug`: the
/// recovery binding must not end up in a log line by accident.
#[derive(Clone, uniffi::Record)]
pub struct RegistrationFinishDto {
    pub upload: Vec<u8>,
    pub x25519_public: Vec<u8>,
    pub recovery_check: Vec<u8>,
}

/// The signup ceremony state machine, one per signup attempt. Single-consumer:
/// drive it from one sequence (the `Mutex` is only the `Send + Sync` backstop
/// UniFFI requires). Call `abandon()` when the flow is left (back, cancel,
/// error): releasing the handle also wipes the password, phrase and master key
/// it holds, but only when ARC or the GC gets round to it.
#[derive(uniffi::Object)]
pub struct SignupCeremonyHandle {
    inner: Mutex<onb::SignupCeremony>,
}

impl SignupCeremonyHandle {
    fn with<T>(&self, f: impl FnOnce(&mut onb::SignupCeremony) -> T) -> T {
        let mut guard = lock_tolerant(&self.inner);
        f(&mut guard)
    }
}

#[uniffi::export]
impl SignupCeremonyHandle {
    /// `min_length` = `policy.password.min_length`; `email_verification_required`
    /// = the document lists a required `verify_email_code`; `verify_word_count`
    /// = `policy.recovery_phrase.verify_word_count`; `breach_check_required` =
    /// the document declares a breach check, with `breach_fail_open` =
    /// `policy.password.breach_check.fail_open` (applied by the ceremony, not
    /// by the caller).
    #[uniffi::constructor]
    pub fn new(
        min_length: u32,
        email_verification_required: bool,
        verify_word_count: u32,
        breach_check_required: bool,
        breach_fail_open: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(onb::SignupCeremony::new(onb::CeremonyConfig {
                password_policy: onb::PasswordPolicy::from_server(min_length),
                email_verification_required,
                verify_word_count,
                breach: if breach_check_required {
                    onb::BreachPolicy::Required {
                        fail_open: breach_fail_open,
                    }
                } else {
                    onb::BreachPolicy::NotRequired
                },
            })),
        })
    }

    /// Abandon the signup: wipe the password, phrase and master key and return
    /// to a fresh ceremony. Call on back, cancel and error exits.
    pub fn abandon(&self) {
        self.with(|c| c.wipe());
    }

    /// First pending step, or `Done`.
    pub fn step(&self) -> CeremonyStepDto {
        self.with(|c| c.step()).into()
    }

    /// Every pending step in canonical order.
    pub fn pending_steps(&self) -> Vec<CeremonyStepDto> {
        self.with(|c| c.pending_steps()).into_iter().map(Into::into).collect()
    }

    /// The server accepted the email code.
    pub fn email_verified(&self) {
        self.with(|c| c.email_verified());
    }

    /// The server reported the signup ticket expired: back to the code step,
    /// password and confirmed phrase kept.
    pub fn email_ticket_invalidated(&self) {
        self.with(|c| c.email_ticket_invalidated());
    }

    /// The user changed the email address after it was verified: back to the
    /// code step, password and confirmed phrase kept.
    pub fn email_changed(&self) {
        self.with(|c| c.email_changed());
    }

    /// Validate and store the password. `breach` is the `BreachCheckHandle`
    /// made for **this** password, after `evaluate` recorded the endpoint's
    /// answer; pass `None` when the document declares no breach check. Throws
    /// `PasswordMismatch`, `PasswordTooShort`, `BreachCheckMissing`,
    /// `BreachCheckStale`, `PasswordBreached` or `BreachCheckBlocked`.
    pub fn set_password(
        &self,
        password: String,
        confirmation: String,
        breach: Option<Arc<BreachCheckHandle>>,
    ) -> Result<PasswordEvaluationDto, OnboardingError> {
        let password = Zeroizing::new(password);
        let confirmation = Zeroizing::new(confirmation);
        Ok(self
            .with(|c| match &breach {
                Some(handle) => {
                    let guard = lock_tolerant(&handle.check);
                    c.set_password(&password, &confirmation, Some(&guard))
                }
                None => c.set_password(&password, &confirmation, None),
            })?
            .into())
    }

    /// Generate the recovery phrase and master key (Argon2id, about a second).
    /// Idempotent.
    pub fn begin_phrase(&self) -> Result<(), OnboardingError> {
        Ok(self.with(|c| c.begin_phrase())?)
    }

    /// The phrase to show. Throws `PhraseUnavailable` before `begin_phrase` or
    /// after the phrase was confirmed (it is wiped then). The returned string
    /// is a plain copy owned by the host runtime and cannot be wiped: call this
    /// only while rendering the phrase and drop the reference afterwards.
    pub fn phrase(&self) -> Result<String, OnboardingError> {
        Ok(self.with(|c| c.phrase().map(|p| p.as_str().to_owned()))?)
    }

    /// The user confirms they saved the phrase.
    pub fn acknowledge_phrase(&self) -> Result<(), OnboardingError> {
        Ok(self.with(|c| c.acknowledge_phrase())?)
    }

    /// 1-based word positions to ask for, ascending, stable for this phrase.
    pub fn challenge_positions(&self) -> Result<Vec<u32>, OnboardingError> {
        Ok(self.with(|c| c.challenge_positions())?)
    }

    /// `answers` in `challenge_positions` order. Throws `PhraseWordMismatch` /
    /// `PhraseAnswerCount`; retryable.
    pub fn confirm_phrase(&self, answers: Vec<String>) -> Result<(), OnboardingError> {
        // Each answer is a word of the recovery phrase: wipe our copies on return.
        let answers: Vec<Zeroizing<String>> = answers.into_iter().map(Zeroizing::new).collect();
        Ok(self.with(|c| c.confirm_phrase(&answers))?)
    }

    /// OPAQUE step 1: the `RegistrationRequest` for `opaque/register-start`.
    /// Throws `StepNotDone` until every other required step is done.
    pub fn start_registration(&self) -> Result<Vec<u8>, OnboardingError> {
        Ok(self.with(|c| c.start_registration().map(|r| r.message))?)
    }

    /// OPAQUE step 2, from the server's `register-start` response.
    pub fn finish_registration(&self, server_message: Vec<u8>) -> Result<RegistrationFinishDto, OnboardingError> {
        let r = self.with(|c| c.finish_registration(&server_message))?;
        Ok(RegistrationFinishDto {
            upload: r.upload,
            x25519_public: r.x25519_public.to_vec(),
            recovery_check: r.recovery_check.to_vec(),
        })
    }

    /// The server rejected `register-finish` in a retryable way.
    pub fn registration_failed(&self) {
        self.with(|c| c.registration_failed());
    }

    /// The server accepted `register-finish`. Returns the master key as a
    /// handle (the bytes never cross FFI); the ceremony wipes everything else.
    pub fn account_created(&self) -> Result<Arc<MasterKeyHandle>, OnboardingError> {
        let key = self.with(|c| c.account_created())?;
        Ok(MasterKeyHandle::new(key))
    }
}

// ---------------------------------------------------------------------------
// Direct S3 transfers (task 2173): the client rules of `beebeeb_core::direct_transfer`
// ---------------------------------------------------------------------------
//
// Thin wrappers. ALL logic lives in core; this section converts types. The app
// keeps its own HTTP stack (URLSession / OkHttp) and asks these rules whether a
// storage link may be followed, what an API answer means, and what to do next
// (windows, renewals, fallbacks), exactly as the CLI, desktop and web do.
//
// A planner is one sequence's cursor (the `Mutex` is only UniFFI's Send+Sync
// backstop): drive it from ONE place, and feed it `now_ms` (Unix milliseconds)
// on every call. Errors carry stable string codes; no error text ever contains
// a URL. A presigned URL is a bearer capability until it expires: do not log
// `DirectChunkGrantDto.url`, use `direct_redact_url` / `direct_scrub_text`.

use beebeeb_core::direct_transfer as dt;

/// The contract's names and numbers, so no client re-types them.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DirectConstantsDto {
    pub cap_object_download_v1: String,
    pub cap_object_upload_v1: String,
    pub capabilities_header: String,
    pub discovery_path: String,
    pub max_window: u32,
    pub default_window: u32,
    pub chunk_overhead: u32,
    /// The time bounds every client applies (clients design 6.2), in milliseconds.
    pub storage_connect_timeout_ms: u32,
    pub storage_get_idle_ms: u32,
    pub discovery_timeout_ms: u32,
    pub api_call_timeout_ms: u32,
    pub background_put_resource_timeout_ms: u32,
    /// The largest discovery body a client should read.
    pub max_discovery_body_bytes: u32,
    /// The largest grant-window body a client should read.
    pub max_grant_body_bytes: u32,
    /// The largest ciphertext chunk the client will ever see (256 MiB plus the AEAD overhead).
    pub max_chunk_body_bytes: u64,
}

#[uniffi::export]
pub fn direct_transfer_constants() -> DirectConstantsDto {
    DirectConstantsDto {
        cap_object_download_v1: dt::CAP_OBJECT_DOWNLOAD_V1.to_owned(),
        cap_object_upload_v1: dt::CAP_OBJECT_UPLOAD_V1.to_owned(),
        capabilities_header: dt::CAPABILITIES_HEADER.to_owned(),
        discovery_path: dt::DISCOVERY_PATH.to_owned(),
        max_window: dt::wire::MAX_WINDOW,
        default_window: dt::wire::DEFAULT_WINDOW,
        chunk_overhead: dt::wire::CHUNK_OVERHEAD as u32,
        storage_connect_timeout_ms: timeout_ms(dt::timeouts::STORAGE_CONNECT_TIMEOUT),
        storage_get_idle_ms: timeout_ms(dt::timeouts::STORAGE_GET_IDLE),
        discovery_timeout_ms: timeout_ms(dt::timeouts::DISCOVERY_TIMEOUT),
        api_call_timeout_ms: timeout_ms(dt::timeouts::API_CALL_TIMEOUT),
        background_put_resource_timeout_ms: timeout_ms(dt::timeouts::BACKGROUND_PUT_RESOURCE_TIMEOUT),
        // The three response caps are appended last, so a client that copies fields positionally
        // (older generated bindings) keeps every earlier field where it was.
        max_discovery_body_bytes: dt::wire::MAX_DISCOVERY_BYTES as u32,
        max_grant_body_bytes: dt::wire::MAX_GRANT_BODY_BYTES as u32,
        max_chunk_body_bytes: beebeeb_core::chunk_stream::MAX_CHUNK_SIZE + dt::wire::CHUNK_OVERHEAD,
    }
}

/// A fixed bound in milliseconds (every one is a few minutes at most).
fn timeout_ms(d: std::time::Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// The most a storage PUT of `len` ciphertext bytes may take, in milliseconds: a minute plus the
/// chunk at 1 Mbit/s (`60 s + ceil(len / 131072) s`). Any length is safe: a huge one is a long timeout.
#[uniffi::export]
pub fn direct_storage_put_total_ms(len: u64) -> u64 {
    u64::try_from(dt::timeouts::storage_put_total(len).as_millis()).unwrap_or(u64::MAX)
}

/// The most a storage GET of `len` ciphertext bytes may take, in milliseconds (the same formula as a PUT).
#[uniffi::export]
pub fn direct_storage_get_total_ms(len: u64) -> u64 {
    u64::try_from(dt::timeouts::storage_get_total(len).as_millis()).unwrap_or(u64::MAX)
}

/// A background URL session's resource timeout for a storage PUT, in milliseconds. No app timer runs in
/// the background, so this is the only bound; it stays under the server's late-write fence from any
/// start up to the link's expiry.
#[uniffi::export]
pub fn direct_background_put_resource_timeout_ms() -> u64 {
    u64::try_from(dt::timeouts::BACKGROUND_PUT_RESOURCE_TIMEOUT.as_millis()).unwrap_or(u64::MAX)
}

/// `/api/v1/files/{id}/download-grants` for `file_id`.
#[uniffi::export]
pub fn direct_download_grants_path(file_id: String) -> String {
    dt::download_grants_path(&file_id)
}

/// Why a call into the direct-transfer rules failed. Every variant carries a
/// stable `code`; none carries a URL.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DirectTransferError {
    /// A storage link was refused: `malformed`, `not_https`, `userinfo`,
    /// `ip_literal`, `loopback`, `bad_host`, `port`, `host_not_listed`,
    /// `bucket_not_listed`, `bad_path`.
    #[error("the storage link was refused: {code}")]
    LinkRefused { code: String },

    /// The discovery body could not be decoded: `discovery_too_large`,
    /// `discovery_malformed`.
    #[error("the discovery answer could not be used: {code}")]
    Discovery { code: String },

    /// A call that does not fit the planner's state (a bug in the caller):
    /// `not_in_flight`, `not_fetched`, `out_of_order`, `api_route_failure`.
    #[error("the planner was driven out of order: {code}")]
    Plan { code: String },

    /// `call` was none of `discovery`, `download_grant`, `pinned_chunk`.
    #[error("unknown call")]
    UnknownCall,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DirectStorageBucketDto {
    pub host: String,
    pub bucket: String,
}

/// The answer of `GET /api/v1/transfer/capabilities`.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DirectDiscoveryDto {
    pub download: Vec<String>,
    pub upload: Vec<String>,
    pub storage_hosts: Vec<String>,
    pub storage_buckets: Vec<DirectStorageBucketDto>,
    pub max_window: Option<u32>,
    pub url_ttl_seconds: Option<u64>,
}

impl From<dt::Discovery> for DirectDiscoveryDto {
    fn from(d: dt::Discovery) -> Self {
        Self {
            download: d.download,
            upload: d.upload,
            storage_hosts: d.storage_hosts,
            storage_buckets: d
                .storage_buckets
                .into_iter()
                .map(|b| DirectStorageBucketDto {
                    host: b.host,
                    bucket: b.bucket,
                })
                .collect(),
            max_window: d.max_window,
            url_ttl_seconds: d.url_ttl_seconds,
        }
    }
}

impl From<DirectDiscoveryDto> for dt::Discovery {
    fn from(d: DirectDiscoveryDto) -> Self {
        Self {
            download: d.download,
            upload: d.upload,
            storage_hosts: d.storage_hosts,
            storage_buckets: d
                .storage_buckets
                .into_iter()
                .map(|b| dt::StorageBucket {
                    host: b.host,
                    bucket: b.bucket,
                })
                .collect(),
            max_window: d.max_window,
            url_ttl_seconds: d.url_ttl_seconds,
        }
    }
}

/// Decode a discovery body. Unknown fields are ignored, missing lists are empty.
#[uniffi::export]
pub fn parse_direct_discovery(body: Vec<u8>) -> Result<DirectDiscoveryDto, DirectTransferError> {
    dt::Discovery::from_json(&body)
        .map(DirectDiscoveryDto::from)
        .map_err(|e| DirectTransferError::Discovery {
            code: match e {
                dt::WireError::TooLarge(_) => "discovery_too_large",
                dt::WireError::Malformed => "discovery_malformed",
            }
            .to_owned(),
        })
}

/// Does the server offer direct downloads, and how many grants to ask per window.
#[uniffi::export]
pub fn direct_discovery_offers_download(discovery: DirectDiscoveryDto) -> bool {
    dt::Discovery::from(discovery).offers_download()
}

/// May the app follow this storage link? `api_base` is the API origin in use.
/// Throws `LinkRefused` with the refusal code; the message never contains the URL.
#[uniffi::export]
pub fn direct_check_storage_url(
    url: String,
    discovery: DirectDiscoveryDto,
    api_base: String,
) -> Result<(), DirectTransferError> {
    dt::check_storage_url(&url, &dt::Discovery::from(discovery), &api_base).map_err(|r| {
        DirectTransferError::LinkRefused {
            code: r.code().to_owned(),
        }
    })
}

/// What a storage GET answer means. `Stored` only for a `200` whose `Content-Length` is exactly
/// the grant's length; `Failed` carries the status (`0` means there was no HTTP answer).
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectStorageGetDto {
    Stored,
    Failed { status: u16 },
}

/// Check a storage GET answer: `Stored` only for `200` with `Some(expected)`.
#[uniffi::export]
pub fn direct_check_storage_get(status: u16, content_length: Option<u64>, expected: u64) -> DirectStorageGetDto {
    storage_get_dto(dt::check_storage_get(status, content_length, expected))
}

/// Check the body a storage GET actually delivered: `Stored` only when the counted bytes are
/// exactly the grant. `Content-Length` is only the head; a truncated stream ends short.
#[uniffi::export]
pub fn direct_check_storage_body(received: u64, expected: u64) -> DirectStorageGetDto {
    storage_get_dto(dt::check_storage_body(received, expected))
}

fn storage_get_dto(got: dt::StorageGet) -> DirectStorageGetDto {
    match got {
        dt::StorageGet::Stored => DirectStorageGetDto::Stored,
        dt::StorageGet::Failed { status } => DirectStorageGetDto::Failed { status },
    }
}

/// When `wire_bytes` received since `start_ms` at `kbps` KiB/s lets the next storage request
/// start. `kbps == 0` returns `i64::MIN`: there is no ceiling.
#[uniffi::export]
pub fn direct_paced_until_ms(start_ms: i64, wire_bytes: u64, kbps: u64) -> i64 {
    dt::paced_until_ms(start_ms, wire_bytes, kbps)
}

/// The process class, which sets the ciphertext-in-flight cap.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectMemoryClassDto {
    Native,
    Browser,
    MobileApp,
    MobileExtension,
}

impl From<DirectMemoryClassDto> for dt::MemoryClass {
    fn from(c: DirectMemoryClassDto) -> Self {
        match c {
            DirectMemoryClassDto::Native => dt::MemoryClass::Native,
            DirectMemoryClassDto::Browser => dt::MemoryClass::Browser,
            DirectMemoryClassDto::MobileApp => dt::MemoryClass::MobileApp,
            DirectMemoryClassDto::MobileExtension => dt::MemoryClass::MobileExtension,
        }
    }
}

/// The ciphertext bytes a process of `class` may hold at once (256, 64, 64, 16 MiB). The planner
/// clamps the chunk count to at least one, so this is a ceiling, never a reason to fail.
#[uniffi::export]
pub fn direct_max_in_flight_bytes(class: DirectMemoryClassDto) -> u64 {
    dt::max_in_flight_bytes(class.into())
}

/// May this client use the direct transport for `direction`? True only when discovery offers it
/// AND every pair in `discovery.storage_buckets` is in `pairs`. Hosts compare ASCII
/// case-insensitively, buckets exactly.
#[uniffi::export]
pub fn direct_pairs_allowed(
    discovery: DirectDiscoveryDto,
    direction: DirectDirectionDto,
    pairs: Vec<DirectStorageBucketDto>,
) -> bool {
    let pairs: Vec<dt::StorageBucket> = pairs
        .into_iter()
        .map(|p| dt::StorageBucket {
            host: p.host,
            bucket: p.bucket,
        })
        .collect();
    dt::pairs_allowed(&dt::Discovery::from(discovery), direction.into(), &pairs)
}

/// A URL for a log line: scheme and host only.
#[uniffi::export]
pub fn direct_redact_url(url: String) -> String {
    dt::redact(&url)
}

/// Text that may contain URLs, made safe to print.
#[uniffi::export]
pub fn direct_scrub_text(text: String) -> String {
    dt::scrub(&text)
}

/// What an API answer means.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum DirectOutcomeDto {
    /// 2xx: decode the body and go on.
    Proceed,
    /// Discovery only: this server has no direct transport; cache that.
    NotSupported,
    /// No direct transport right now: use the API for this file now.
    UseApiNow,
    /// This file is served over the API. For an UPLOAD call it means this session cannot go direct:
    /// abandon the session and init again WITHOUT the capability token.
    ApiForThisFile,
    /// `version_unavailable`: discard and restart from fresh metadata.
    Restart,
    /// 429 / `replace_in_progress` / `commit_in_progress`: wait, then ask again.
    Backoff { millis: u64 },
    /// 401, 403 or a JSON 404: do not fall back.
    Terminal { status: u16, error: Option<String> },
    /// The pinned chunk route and the upload calls: a failure that may pass (5xx, no answer). For the
    /// pinned route the bounded backoff is `direct_pinned_retry_decision`; the retry rules of an upload
    /// chunk (the grant cap, the attempts, the waits) are core's `UploadChunkState`, which is not
    /// exported yet, so do NOT pass an upload outcome to `direct_pinned_retry_decision` (it knows no
    /// grant cap and answers give-up for `Regrant`).
    Retry,
    /// `upload_commit` only: the staged chunk is not there; ask for a new link and send it again.
    Regrant,
    /// `upload_commit` only (409 `commit_in_progress`): the server holds the chunk's commit lock, up to
    /// 420 s after a failed copy. Wait (`millis` is the server's stated wait, `None` when it sent none)
    /// and commit again; it is not a failure. core's `UploadChunkState` bounds the wait (the lock TTL
    /// plus 30 s = 450 s, polls no faster than once a second) but is not exported yet: a host that
    /// handles this itself must bound it the same way, and not count a hold as one of its failures.
    Held { millis: Option<u64> },
}

impl DirectOutcomeDto {
    fn from_core(o: &dt::Outcome) -> Self {
        match o {
            dt::Outcome::Proceed => Self::Proceed,
            dt::Outcome::NotSupported => Self::NotSupported,
            dt::Outcome::UseApiNow => Self::UseApiNow,
            dt::Outcome::ApiForThisFile => Self::ApiForThisFile,
            dt::Outcome::Restart => Self::Restart,
            dt::Outcome::Backoff(d) => Self::Backoff {
                millis: d.as_millis() as u64,
            },
            dt::Outcome::Terminal(t) => Self::Terminal {
                status: t.status,
                error: t.error.clone(),
            },
            dt::Outcome::Retry => Self::Retry,
            dt::Outcome::Regrant => Self::Regrant,
            dt::Outcome::Held(d) => Self::Held {
                millis: d.map(|d| d.as_millis() as u64),
            },
            // `Outcome` is non-exhaustive: a variant added later is the safe one.
            _ => Self::UseApiNow,
        }
    }

    fn to_core(&self) -> dt::Outcome {
        match self {
            Self::Proceed => dt::Outcome::Proceed,
            Self::NotSupported => dt::Outcome::NotSupported,
            Self::UseApiNow => dt::Outcome::UseApiNow,
            Self::ApiForThisFile => dt::Outcome::ApiForThisFile,
            Self::Restart => dt::Outcome::Restart,
            Self::Backoff { millis } => dt::Outcome::Backoff(std::time::Duration::from_millis(*millis)),
            Self::Terminal { status, error } => dt::Outcome::Terminal(dt::Terminal {
                status: *status,
                error: error.clone(),
            }),
            Self::Retry => dt::Outcome::Retry,
            Self::Regrant => dt::Outcome::Regrant,
            Self::Held { millis } => dt::Outcome::Held(millis.map(std::time::Duration::from_millis)),
        }
    }
}

/// What to do after a failed attempt on the pinned per-chunk route.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum DirectRetryDecisionDto {
    /// Wait this long, then try again.
    Wait { millis: u64 },
    /// Stop: act on the outcome (restart, terminal) or hand the file to the API stream.
    GiveUp,
}

/// The shared retry policy of the pinned per-chunk route (4 attempts, 150 s of waiting in all, a
/// stated `Retry-After` kept, otherwise 1 s doubling). `outcome` is `classify_direct_answer`'s
/// answer for `"pinned_chunk"`; `attempt` is the 1-based number of the attempt that just failed;
/// `waited_ms` is the total waited so far.
#[uniffi::export]
pub fn direct_pinned_retry_decision(outcome: DirectOutcomeDto, attempt: u32, waited_ms: u64) -> DirectRetryDecisionDto {
    match dt::PinnedRetry::default().decide(attempt, std::time::Duration::from_millis(waited_ms), &outcome.to_core()) {
        dt::RetryDecision::Wait(d) => DirectRetryDecisionDto::Wait {
            millis: d.as_millis() as u64,
        },
        dt::RetryDecision::GiveUp => DirectRetryDecisionDto::GiveUp,
    }
}

/// Classify an API answer. `call` is `"discovery"`, `"download_grant"`, `"pinned_chunk"`,
/// `"upload_grant"` or `"upload_commit"`; pass `status` 0 when there was no HTTP answer. `body` is whatever was read of the
/// body (at most 64 KiB is looked at); `retry_after` is the raw header value.
#[uniffi::export]
pub fn classify_direct_answer(
    call: String,
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
    retry_after: Option<String>,
) -> Result<DirectOutcomeDto, DirectTransferError> {
    let call = dt::Call::from_code(&call).ok_or(DirectTransferError::UnknownCall)?;
    let answer = dt::ApiAnswer::from_parts(status, content_type.as_deref(), &body, retry_after.as_deref());
    Ok(DirectOutcomeDto::from_core(&dt::classify(call, &answer)))
}

/// `POST /api/v1/files/{id}/download-grants` body.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DirectGrantRequestDto {
    pub object_version_id: Option<String>,
    pub start_index: u32,
    pub count: u32,
    pub renewal: bool,
}

/// A presigned storage link: a bearer capability until it expires (it carries the signature in its
/// query). It is an OBJECT, not a string, so that no generated `toString()` (Kotlin), `description`
/// (Swift) or `print` can show it: its `Debug` and `Display` are the redacted form (scheme and host),
/// and so is the derived `Debug`/`toString()` of every record that holds one. The only way to the
/// link is [`DirectSignedUrl::raw`], by name, so it shows up in a review: pass it to the HTTP client
/// and nowhere else.
///
/// On Kotlin, `toString()` of the object, or of a record that holds one, throws
/// `IllegalStateException` once the object has been `destroy()`ed or `close()`d, like any call on a
/// released object: do not log a grant after releasing it.
///
/// It exports no `Eq` or `Hash` on purpose. UniFFI 0.31.1 generates Kotlin `equals` and `hashCode`
/// that lower the object's handle with no check that it was destroyed, so comparing or hashing a
/// released link (or a grant or poll that holds one) would be a use-after-free in native code.
/// Compare the links' text (`raw()`) when a comparison is needed.
#[derive(uniffi::Object, PartialEq, Eq)]
#[uniffi::export(Debug, Display)]
pub struct DirectSignedUrl {
    url: String,
}

impl std::fmt::Display for DirectSignedUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&dt::redact(&self.url))
    }
}

impl std::fmt::Debug for DirectSignedUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirectSignedUrl({})", dt::redact(&self.url))
    }
}

#[uniffi::export]
impl DirectSignedUrl {
    /// A link from its text. The engine builds its own; this is for an app's tests (a `Fetch` poll
    /// made by hand). The text is not checked: `direct_check_storage_url` is the check.
    #[uniffi::constructor]
    pub fn new(url: String) -> Arc<Self> {
        Arc::new(Self { url })
    }

    /// The full presigned link, to hand to the HTTP client. Never log it.
    pub fn raw(&self) -> String {
        self.url.clone()
    }

    /// Scheme and host only: safe for a log line.
    pub fn redacted(&self) -> String {
        dt::redact(&self.url)
    }
}

/// One presigned link. `url` is a bearer capability, and cannot be printed by accident: see
/// [`DirectSignedUrl`].
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DirectChunkGrantDto {
    pub index: u32,
    pub method: String,
    pub url: Arc<DirectSignedUrl>,
    pub length: u64,
    pub expires_at: String,
}

/// How a file ends when it cannot go on directly.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum DirectVerdictDto {
    /// Discard any partial output and download the file again on the API path.
    ApiForFile,
    /// The pinned version changed: discard and restart from fresh metadata.
    Restart,
    /// An authorization answer: do not fall back.
    Terminal { status: u16, error: Option<String> },
    /// A chunk failed authentication from storage and from the API: a hard error.
    Corrupt,
}

/// What the app must do now.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum DirectPollDto {
    /// `POST` this body to `direct_download_grants_path(file_id)` with the
    /// capability header, then report the answer.
    RequestWindow { request: DirectGrantRequestDto },
    /// `GET grant.url.raw()` (`grant.url` is a `DirectSignedUrl`, not a string) with a client that
    /// sends nothing else (no cookies, no `Authorization`), redirects off; accept only `200` whose
    /// `Content-Length` is `grant.length`.
    Fetch { index: u32, grant: DirectChunkGrantDto },
    /// `GET /api/v1/files/{id}/chunks/{index}?object_version_id=<pinned>`.
    FetchViaApi { index: u32, object_version_id: String },
    /// Nothing to start. `until_ms` is the next moment the planner can act by
    /// itself; `None` means it waits for a request that is outstanding.
    Wait { until_ms: Option<i64> },
    /// Every chunk has been consumed.
    Done,
    /// Cannot go on directly.
    Stop { verdict: DirectVerdictDto },
}

impl DirectPollDto {
    fn from_core(p: &dt::Poll) -> Self {
        match p {
            dt::Poll::RequestWindow(r) => Self::RequestWindow {
                request: DirectGrantRequestDto {
                    object_version_id: r.object_version_id.clone(),
                    start_index: r.start_index,
                    count: r.count,
                    renewal: r.renewal,
                },
            },
            dt::Poll::Fetch { index, grant } => Self::Fetch {
                index: *index,
                grant: DirectChunkGrantDto {
                    index: grant.index,
                    method: grant.method.clone(),
                    url: DirectSignedUrl::new(grant.url.clone()),
                    length: grant.length,
                    expires_at: grant.expires_at.clone(),
                },
            },
            dt::Poll::FetchViaApi {
                index,
                object_version_id,
            } => Self::FetchViaApi {
                index: *index,
                object_version_id: object_version_id.clone(),
            },
            dt::Poll::Wait { until_ms } => Self::Wait { until_ms: *until_ms },
            dt::Poll::Done => Self::Done,
            dt::Poll::Stop(v) => Self::Stop {
                verdict: match v {
                    dt::Verdict::ApiForFile => DirectVerdictDto::ApiForFile,
                    dt::Verdict::Restart => DirectVerdictDto::Restart,
                    dt::Verdict::Terminal(t) => DirectVerdictDto::Terminal {
                        status: t.status,
                        error: t.error.clone(),
                    },
                    dt::Verdict::Corrupt => DirectVerdictDto::Corrupt,
                },
            },
        }
    }
}

/// The version's geometry, once the first window was accepted.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DirectGeometryDto {
    pub chunk_count: u32,
    pub chunk_size: u64,
    pub encrypted_size: u64,
    pub original_size: u64,
}

/// The outcome of handing a window answer to the planner.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum DirectWindowAnswerDto {
    Accepted,
    /// The body was not the contract's JSON; handled like any window the server
    /// could not serve. Poll again.
    Malformed,
    /// The answer broke the contract (`transport`, `file_mismatch`,
    /// `version_changed`, `geometry`, `grants`, `length`, `method`,
    /// `authority_<refusal>`, `expiry`, `unexpected`). Poll again.
    Refused {
        code: String,
    },
}

fn plan_error(e: dt::PlanError) -> DirectTransferError {
    DirectTransferError::Plan {
        code: e.code().to_owned(),
    }
}

/// The download planner for ONE file: when to ask the API for a window of
/// links, which chunk to fetch next (at most 4 in flight, in order), when to
/// renew a link, and when a chunk goes to the pinned API route. It performs no
/// I/O and holds no clock. See `DirectPollDto` for what each poll asks of you;
/// decrypt chunks in order and report each with `consumed`, or `chunk_unauthentic`
/// when one does not authenticate.
#[derive(uniffi::Object)]
pub struct DirectDownloadPlannerHandle {
    inner: Mutex<dt::DownloadPlanner>,
}

#[uniffi::export]
impl DirectDownloadPlannerHandle {
    /// `discovery` is what `parse_direct_discovery` returned; `jitter_seed` any
    /// integer (random in production).
    #[uniffi::constructor]
    pub fn new(discovery: DirectDiscoveryDto, api_base: String, file_id: String, jitter_seed: u64) -> Arc<Self> {
        let discovery = dt::Discovery::from(discovery);
        let config = dt::PlannerConfig::from_discovery(&discovery, jitter_seed);
        Arc::new(Self {
            inner: Mutex::new(dt::DownloadPlanner::new(config, discovery, &api_base, &file_id)),
        })
    }

    /// What to do now. Call again after every report.
    pub fn poll(&self, now_ms: i64) -> DirectPollDto {
        DirectPollDto::from_core(&lock_tolerant(&self.inner).poll(now_ms))
    }

    /// The window answer for the outstanding request, as the raw response body.
    pub fn window_answered(&self, body: Vec<u8>, now_ms: i64) -> DirectWindowAnswerDto {
        match lock_tolerant(&self.inner).window_answered_bytes(&body, now_ms) {
            dt::WindowAnswer::Accepted => DirectWindowAnswerDto::Accepted,
            dt::WindowAnswer::Malformed => DirectWindowAnswerDto::Malformed,
            dt::WindowAnswer::Refused(v) => DirectWindowAnswerDto::Refused {
                code: v.code().to_owned(),
            },
        }
    }

    /// The window request failed; `outcome` is what `classify_direct_answer`
    /// returned (or `UseApiNow` for a network error).
    pub fn window_failed(&self, outcome: DirectOutcomeDto, now_ms: i64) {
        lock_tolerant(&self.inner).window_failed(outcome.to_core(), now_ms);
    }

    /// A 2xx window response whose body could not be decoded at all.
    pub fn window_malformed(&self) {
        lock_tolerant(&self.inner).window_malformed();
    }

    /// Chunk `index` arrived whole (status 200 and the right length).
    pub fn fetch_ok(&self, index: u32) -> Result<(), DirectTransferError> {
        lock_tolerant(&self.inner).fetch_ok(index).map_err(plan_error)
    }

    /// The transfer of chunk `index` from storage failed (any non-200, a short
    /// body, a wrong length, a network error, an expired link).
    pub fn fetch_failed(&self, index: u32, now_ms: i64) -> Result<(), DirectTransferError> {
        lock_tolerant(&self.inner)
            .fetch_failed(index, now_ms)
            .map_err(plan_error)
    }

    /// The pinned API route failed for chunk `index` after the caller's own retries.
    pub fn api_fetch_failed(&self, index: u32) -> Result<(), DirectTransferError> {
        lock_tolerant(&self.inner).api_fetch_failed(index).map_err(plan_error)
    }

    /// Chunk `index` arrived but did not authenticate when decrypted.
    pub fn chunk_unauthentic(&self, index: u32) -> Result<(), DirectTransferError> {
        lock_tolerant(&self.inner).chunk_unauthentic(index).map_err(plan_error)
    }

    /// Chunk `index` has been decrypted and written. Strictly in order.
    pub fn consumed(&self, index: u32) -> Result<(), DirectTransferError> {
        lock_tolerant(&self.inner).consumed(index).map_err(plan_error)
    }

    /// The ciphertext length of chunk `index` once the first window was accepted, else `None`.
    /// The grant's `length` is this number; check a storage answer against it.
    pub fn chunk_length(&self, index: u32) -> Option<u64> {
        lock_tolerant(&self.inner)
            .geometry()
            .and_then(|g| g.chunk_length(index))
    }

    /// The version's geometry, once the first window was accepted.
    pub fn geometry(&self) -> Option<DirectGeometryDto> {
        lock_tolerant(&self.inner).geometry().map(|g| DirectGeometryDto {
            chunk_count: g.chunk_count,
            chunk_size: g.chunk_size,
            encrypted_size: g.encrypted_size,
            original_size: g.original_size,
        })
    }

    /// The pinned `object_version_id`, once the first window was accepted.
    pub fn pinned_version(&self) -> Option<String> {
        lock_tolerant(&self.inner).pinned_version().map(str::to_owned)
    }

    /// Chunks decrypted and written so far.
    pub fn consumed_count(&self) -> u32 {
        lock_tolerant(&self.inner).consumed_count()
    }

    /// Chunk requests (storage or API) currently outstanding.
    pub fn in_flight(&self) -> u32 {
        lock_tolerant(&self.inner).in_flight() as u32
    }

    /// Cap the ciphertext bytes held at once (fetching, or fetched and waiting to be decrypted in order):
    /// the planner then holds `clamp(floor(bytes / (chunk_size + 28)), 1, 4)` chunks. Call it before the first `poll`.
    pub fn set_max_in_flight_bytes(&self, bytes: u64) {
        lock_tolerant(&self.inner).set_max_in_flight_bytes(Some(bytes));
    }

    /// Did the storage breaker trip? It does when a chunk used up its renewals and no chunk of this transfer has
    /// come whole from storage: from then on every remaining chunk is a `FetchViaApi` poll. When the file ends
    /// with this `true`, record `DirectHealthHandle.gave_up(Download, now_ms)`.
    pub fn storage_given_up(&self) -> bool {
        lock_tolerant(&self.inner).storage_given_up()
    }
}

/// What to do about discovery right now.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum DirectLookupDto {
    /// Ask the server.
    Fetch,
    /// Use this answer (it may still say the server offers nothing).
    Cached { discovery: DirectDiscoveryDto },
    /// Do not ask; use the API.
    UseApi,
}

/// How long a discovery answer is trusted (10 minutes), and whether to ask
/// again. A JSON 404 and two failed attempts are each remembered for the same ten minutes, then the
/// client probes again; within a trust period a failed attempt is retried once.
#[derive(uniffi::Object)]
pub struct DirectDiscoveryCacheHandle {
    inner: Mutex<dt::DiscoveryCache>,
}

#[uniffi::export]
impl DirectDiscoveryCacheHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(dt::DiscoveryCache::new()),
        })
    }

    pub fn lookup(&self, now_ms: i64) -> DirectLookupDto {
        match lock_tolerant(&self.inner).lookup(now_ms) {
            dt::Lookup::Fetch => DirectLookupDto::Fetch,
            dt::Lookup::Cached(d) => DirectLookupDto::Cached { discovery: d.into() },
            dt::Lookup::UseApi => DirectLookupDto::UseApi,
        }
    }

    /// Record the result of a discovery call: the `classify_direct_answer`
    /// outcome and the response body (or `None`).
    pub fn record(&self, outcome: DirectOutcomeDto, body: Option<Vec<u8>>, now_ms: i64) {
        let discovery = body.and_then(|b| dt::Discovery::from_json(&b).ok());
        lock_tolerant(&self.inner).record(&outcome.to_core(), discovery, now_ms);
    }
}

/// Which way the bytes go.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectDirectionDto {
    Download,
    Upload,
}

impl From<DirectDirectionDto> for dt::Direction {
    fn from(d: DirectDirectionDto) -> Self {
        match d {
            DirectDirectionDto::Download => dt::Direction::Download,
            DirectDirectionDto::Upload => dt::Direction::Upload,
        }
    }
}

/// Whether this client may start a direct transfer now, per direction: after a transfer gave up direct, no
/// new one of that direction starts for ten minutes. One per API base and account. `now_ms` is Unix
/// milliseconds (or a monotonic clock, used consistently). `last_gave_up_ms` / `restore` let a client that
/// relaunches often persist the two timestamps. A recorded time later than "now" counts as expired.
#[derive(uniffi::Object)]
pub struct DirectHealthHandle {
    inner: Mutex<dt::DirectHealth>,
}

#[uniffi::export]
impl DirectHealthHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(dt::DirectHealth::new()),
        })
    }

    /// A transfer of `direction` gave up direct.
    pub fn gave_up(&self, direction: DirectDirectionDto, now_ms: i64) {
        lock_tolerant(&self.inner).gave_up(direction.into(), now_ms);
    }

    /// May a new direct transfer of `direction` start now?
    pub fn may_start(&self, direction: DirectDirectionDto, now_ms: i64) -> bool {
        lock_tolerant(&self.inner).may_start(direction.into(), now_ms)
    }

    /// As `may_start`, for a file that may already have given up direct: it never may again (`file_gave_up`).
    pub fn may_start_file(&self, direction: DirectDirectionDto, now_ms: i64, file_gave_up: bool) -> bool {
        lock_tolerant(&self.inner).may_start_file(direction.into(), now_ms, file_gave_up)
    }

    /// When the last give-up of `direction` was recorded.
    pub fn last_gave_up_ms(&self, direction: DirectDirectionDto) -> Option<i64> {
        lock_tolerant(&self.inner).last_gave_up_ms(direction.into())
    }

    /// Put back a timestamp `last_gave_up_ms` returned earlier.
    pub fn restore(&self, direction: DirectDirectionDto, last_gave_up_ms: i64) {
        lock_tolerant(&self.inner).restore(direction.into(), last_gave_up_ms);
    }
}

/// The transport a resume record names.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectRecordedTransportDto {
    Api,
    Direct,
}

/// What the client learned from discovery when it asked just now.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectDiscoveryStateDto {
    /// The server answered; `upload`: it lists the direct upload transport.
    Offers { upload: bool },
    /// A JSON 404: the server has no direct transfer at all.
    NotSupported,
    /// No usable answer (a 5xx, a timeout, a bare 404, a body that did not decode).
    Unknown,
    /// 401 or 403: the login is not valid.
    Unauthorized,
}

/// What to do with the unfinished upload.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectResumeActionDto {
    ContinueApi,
    ContinueDirect,
    /// Abandon the session, clear the record, start again on the API.
    AbandonToApi,
    /// Keep the record and fail the file for this run.
    KeepRecordAndFail,
    /// Keep the record and ask the user to sign in again.
    KeepRecordAndReauthenticate,
}

/// What to do with an unfinished upload found on disk. A recorded direct session is given up only on a
/// definite no: the user forced the API (`forced_api`), or the server says it offers no direct uploads. It is
/// never given up because discovery could not be read this time. One rule, so no client writes it by hand.
#[uniffi::export]
pub fn direct_resume_transport(
    recorded: DirectRecordedTransportDto,
    discovery: DirectDiscoveryStateDto,
    forced_api: bool,
) -> DirectResumeActionDto {
    let recorded = match recorded {
        DirectRecordedTransportDto::Api => dt::RecordedTransport::Api,
        DirectRecordedTransportDto::Direct => dt::RecordedTransport::Direct,
    };
    let discovery = match discovery {
        DirectDiscoveryStateDto::Offers { upload } => dt::DiscoveryState::Offers { upload },
        DirectDiscoveryStateDto::NotSupported => dt::DiscoveryState::NotSupported,
        DirectDiscoveryStateDto::Unknown => dt::DiscoveryState::Unknown,
        DirectDiscoveryStateDto::Unauthorized => dt::DiscoveryState::Unauthorized,
    };
    match dt::resume_transport(recorded, discovery, forced_api) {
        dt::ResumeAction::ContinueApi => DirectResumeActionDto::ContinueApi,
        dt::ResumeAction::ContinueDirect => DirectResumeActionDto::ContinueDirect,
        dt::ResumeAction::AbandonToApi => DirectResumeActionDto::AbandonToApi,
        dt::ResumeAction::KeepRecordAndFail => DirectResumeActionDto::KeepRecordAndFail,
        dt::ResumeAction::KeepRecordAndReauthenticate => DirectResumeActionDto::KeepRecordAndReauthenticate,
    }
}

#[cfg(test)]
mod search_index_binding_tests {
    use super::*;

    fn test_master_key() -> Arc<MasterKeyHandle> {
        MasterKeyHandle::from_keychain_bytes(vec![7u8; 32]).unwrap()
    }

    #[test]
    fn round_trip_through_binding_finds_nested_term() {
        let mk = test_master_key();
        let files = vec![
            SearchFileEntry {
                file_id: "top".into(),
                name: "readme.txt".into(),
            },
            SearchFileEntry {
                file_id: "deep".into(),
                name: "buried_treasure_xyzzy.txt".into(),
            },
        ];
        let idx = SearchIndexHandle::build(files, search_index::DEFAULT_NUM_SHARDS);

        let shards = idx.encrypt_shards(&mk).unwrap();
        assert!(!shards.is_empty());
        let restored = SearchIndexHandle::from_encrypted_shards(&mk, shards, idx.num_shards()).unwrap();

        assert_eq!(restored.query("xyzzy".into()), vec!["deep".to_string()]);
        assert_eq!(restored.file_count(), 2);

        // Incremental: dirty buckets drive a partial re-encrypt.
        let dirty = restored.upsert("new".into(), "another_file.pdf".into());
        assert!(!dirty.is_empty());
        assert!(!restored.encrypt_buckets(&mk, dirty).unwrap().is_empty());
        assert_eq!(restored.query("another".into()), vec!["new".to_string()]);
    }

    #[test]
    fn wrong_master_key_fails_decrypt_through_binding() {
        let mk = test_master_key();
        let idx = SearchIndexHandle::build(
            vec![SearchFileEntry {
                file_id: "a".into(),
                name: "secret.txt".into(),
            }],
            search_index::DEFAULT_NUM_SHARDS,
        );
        let shards = idx.encrypt_shards(&mk).unwrap();
        let wrong = MasterKeyHandle::from_keychain_bytes(vec![9u8; 32]).unwrap();
        assert!(SearchIndexHandle::from_encrypted_shards(&wrong, shards, idx.num_shards()).is_err());
    }

    #[test]
    fn sync_plan_through_binding() {
        let local = vec![ShardRefDto {
            bucket: 1,
            page: 0,
            version: 2,
        }];
        let remote = vec![ShardRefDto {
            bucket: 3,
            page: 0,
            version: 1,
        }];
        let plan = search_index_sync_plan(local, remote, true);
        assert_eq!(plan.to_put.len(), 1);
        assert_eq!(plan.to_put[0].bucket, 1);
        assert_eq!(plan.to_delete.len(), 1);
        assert_eq!(plan.to_delete[0].bucket, 3);
        assert!(plan.to_get.is_empty());
    }
}

#[cfg(test)]
mod onboarding_binding_tests {
    use super::*;

    const GOOD_PW: &str = "correct horse battery staple";

    #[test]
    fn evaluate_password_maps_policy_and_floor() {
        let e = evaluate_password("aaaaaaa".into(), 1); // hostile min_length 1
        assert_eq!(e.min_length, 12, "core floor of 12 applies through the binding");
        assert!(!e.meets_minimum);
        assert_eq!(e.strength, PasswordStrengthDto::TooShort);
        assert_eq!(e.hint, PasswordHintDto::NeedMoreCharacters);
        let strong = evaluate_password("aaaaaaaaaaA1".into(), 12);
        assert_eq!(
            (strong.strength, strong.level, strong.hint),
            (PasswordStrengthDto::Strong, 4, PasswordHintDto::None)
        );
    }

    #[test]
    fn breach_handle_prefix_and_outage_policy() {
        let h = BreachCheckHandle::new("password".into());
        assert_eq!(h.prefix(), "5BAA6");
        assert_eq!(
            h.evaluate(h.prefix(), None, true).unwrap(),
            BreachVerdictDto::CheckFailedAllowed
        );
        assert_eq!(
            h.evaluate(h.prefix(), None, false).unwrap(),
            BreachVerdictDto::CheckFailedBlocked
        );
        assert!(breach_verdict_allows_proceeding(BreachVerdictDto::CheckFailedAllowed));
        assert!(!breach_verdict_allows_proceeding(BreachVerdictDto::CheckFailedBlocked));
        assert!(breach_verdict_check_failed(BreachVerdictDto::CheckFailedAllowed));
        let hit = h
            .evaluate(
                h.prefix(),
                Some("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9\r\n".into()),
                true,
            )
            .unwrap();
        assert_eq!(hit, BreachVerdictDto::Breached { count: 9 });
        assert!(!breach_verdict_allows_proceeding(hit));
        // An empty body is an outage (review M2), not clean.
        assert_eq!(
            h.evaluate(h.prefix(), Some(String::new()), false).unwrap(),
            BreachVerdictDto::CheckFailedBlocked
        );
    }

    #[test]
    fn breach_handle_refuses_another_prefix() {
        let h = BreachCheckHandle::new("password".into());
        let err = h
            .evaluate(
                "ABCDE".into(),
                Some("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n".into()),
                true,
            )
            .expect_err("mismatched prefix must be refused");
        assert!(matches!(err, OnboardingError::BreachPrefixMismatch), "{err}");
    }

    #[test]
    fn ceremony_errors_map_to_distinct_variants() {
        let c = SignupCeremonyHandle::new(12, true, 3, false, true);
        assert_eq!(c.step(), CeremonyStepDto::VerifyEmail);
        assert!(matches!(
            c.start_registration(),
            Err(OnboardingError::StepNotDone {
                blocking: CeremonyStepDto::VerifyEmail,
                ..
            })
        ));
        c.email_verified();
        assert!(matches!(
            c.set_password("short".into(), "short".into(), None),
            Err(OnboardingError::PasswordTooShort {
                length: 5,
                min_length: 12
            })
        ));
        assert!(matches!(
            c.set_password(GOOD_PW.into(), "other".into(), None),
            Err(OnboardingError::PasswordMismatch)
        ));
        assert!(matches!(c.phrase(), Err(OnboardingError::PhraseUnavailable)));
        assert_eq!(
            ceremony_step_spec_id(CeremonyStepDto::ConfirmPhrase),
            "save_recovery_phrase"
        );
    }

    #[test]
    fn breach_gate_is_bound_to_the_handle_and_the_ceremonys_own_policy() {
        let clean = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n".to_string();
        let c = SignupCeremonyHandle::new(12, false, 3, true, false);

        // Required and absent.
        assert!(matches!(
            c.set_password(GOOD_PW.into(), GOOD_PW.into(), None),
            Err(OnboardingError::BreachCheckMissing)
        ));
        // A clean answer recorded for another password is stale.
        let other = BreachCheckHandle::new("an older password!".into());
        other.evaluate(other.prefix(), Some(clean.clone()), true).unwrap();
        assert!(matches!(
            c.set_password(GOOD_PW.into(), GOOD_PW.into(), Some(other)),
            Err(OnboardingError::BreachCheckStale)
        ));
        // Outage: the ceremony's fail_open (false) wins over what the caller showed the user.
        let down = BreachCheckHandle::new(GOOD_PW.into());
        assert_eq!(
            down.evaluate(down.prefix(), None, true).unwrap(),
            BreachVerdictDto::CheckFailedAllowed
        );
        assert!(matches!(
            c.set_password(GOOD_PW.into(), GOOD_PW.into(), Some(down)),
            Err(OnboardingError::BreachCheckBlocked)
        ));
        // Breached.
        let suffix = onb::BreachQuery::from_password(GOOD_PW).suffix().to_owned();
        let hit = BreachCheckHandle::new(GOOD_PW.into());
        hit.evaluate(hit.prefix(), Some(format!("{suffix}:4\r\n")), true)
            .unwrap();
        assert!(matches!(
            c.set_password(GOOD_PW.into(), GOOD_PW.into(), Some(hit)),
            Err(OnboardingError::PasswordBreached { count: 4 })
        ));
        assert_eq!(
            c.step(),
            CeremonyStepDto::SetPassword,
            "no rejection stored the password"
        );
        // Clean passes.
        let ok = BreachCheckHandle::new(GOOD_PW.into());
        ok.evaluate(ok.prefix(), Some(clean), false).unwrap();
        assert!(c.set_password(GOOD_PW.into(), GOOD_PW.into(), Some(ok)).is_ok());
    }

    #[test]
    fn abandon_wipes_and_a_poisoned_lock_does_not_brick_the_handle() {
        let c = SignupCeremonyHandle::new(12, false, 3, false, true);
        c.set_password(GOOD_PW.into(), GOOD_PW.into(), None).unwrap();
        assert_ne!(c.step(), CeremonyStepDto::SetPassword);
        c.abandon();
        assert_eq!(c.step(), CeremonyStepDto::SetPassword);
        assert!(matches!(c.phrase(), Err(OnboardingError::PhraseUnavailable)));

        // Poison the mutex with a panicking closure; later calls still work (review L10).
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.with(|_| panic!("boom"));
        }));
        assert!(poisoned.is_err());
        assert_eq!(c.step(), CeremonyStepDto::SetPassword);
        c.email_changed();
    }

    /// Whole ceremony through the binding against a real server-side OPAQUE,
    /// ending in a `MasterKeyHandle` whose key equals what the phrase recovers.
    #[test]
    fn full_ceremony_through_the_binding_hands_back_a_key_handle() {
        let server_setup = beebeeb_core::opaque_protocol::create_server_setup();
        let username = b"binding@beebeeb.io";

        let c = SignupCeremonyHandle::new(12, false, 3, false, true);
        c.set_password(GOOD_PW.into(), GOOD_PW.into(), None).unwrap();
        c.begin_phrase().unwrap();
        let phrase = c.phrase().unwrap();
        c.acknowledge_phrase().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let answers: Vec<String> = c
            .challenge_positions()
            .unwrap()
            .iter()
            .map(|p| words[*p as usize - 1].to_owned())
            .collect();
        c.confirm_phrase(answers).unwrap();
        assert_eq!(c.step(), CeremonyStepDto::CreateAccount);

        let msg = c.start_registration().unwrap();
        let server_msg =
            beebeeb_core::opaque_protocol::server_registration_start(&server_setup, &msg, username).unwrap();
        let fin = c.finish_registration(server_msg).unwrap();
        assert_eq!(fin.x25519_public.len(), 32);
        assert_eq!(fin.recovery_check.len(), 32);
        assert!(!fin.upload.is_empty());

        let handle = c.account_created().unwrap();
        let from_handle = handle.with_key(|mk| mk.to_bytes()).unwrap();
        let from_phrase = recovery::recover_from_phrase(&phrase).unwrap().to_bytes();
        assert_eq!(from_handle, from_phrase);
        assert_eq!(c.step(), CeremonyStepDto::Done);
        assert!(
            matches!(c.phrase(), Err(OnboardingError::PhraseUnavailable)),
            "phrase wiped"
        );
    }
}

#[cfg(test)]
mod folder_key_id_2133 {
    use super::*;

    #[test]
    fn a_folder_key_that_is_not_32_bytes_is_invalid_input() {
        for len in [31usize, 33] {
            assert!(
                matches!(folder_key_id(vec![0x80; len]), Err(CryptoError::InvalidInput { .. })),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn the_32_byte_vector_matches() {
        let key: Vec<u8> = (0x80u8..=0x9f).collect();
        let id = folder_key_id(key).expect("a 32-byte key");
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "e07f022dd6a140210b19530af0a6b316ec4f06b3a2b086fdf0c03c761baf3b07");
    }
}

#[cfg(test)]
mod direct_transfer_binding_tests {
    //! The cross-client contract vectors, run through the EXPORTED functions and handle of this
    //! crate. The same file `beebeeb-core` runs through core directly: a binding that drifts
    //! from core fails here.

    use beebeeb_core::direct_transfer::vectors::{self, CacheSurface, HealthSurface, PlannerSurface, Surface};
    use serde_json::{Value, json};

    use super::*;

    struct UniffiSurface;

    struct UniffiPlanner(Arc<DirectDownloadPlannerHandle>);

    struct UniffiCache(Arc<DirectDiscoveryCacheHandle>);

    struct UniffiHealth(Arc<DirectHealthHandle>);

    fn direction_dto(code: &str) -> DirectDirectionDto {
        match code {
            "download" => DirectDirectionDto::Download,
            "upload" => DirectDirectionDto::Upload,
            other => panic!("unknown direction {other:?}"),
        }
    }

    /// A storage answer as the contract's JSON. The kind is core's, not a copy in the test.
    fn storage_answer_json(dto: DirectStorageGetDto) -> Value {
        let got = match dto {
            DirectStorageGetDto::Stored => dt::StorageGet::Stored,
            DirectStorageGetDto::Failed { status } => dt::StorageGet::Failed { status },
        };
        match got {
            dt::StorageGet::Stored => json!({"kind": got.kind()}),
            dt::StorageGet::Failed { status } => json!({"kind": got.kind(), "status": status}),
        }
    }

    impl HealthSurface for UniffiHealth {
        fn gave_up(&mut self, direction: &str, now_ms: i64) {
            self.0.gave_up(direction_dto(direction), now_ms);
        }
        fn may_start(&self, direction: &str, now_ms: i64) -> bool {
            self.0.may_start(direction_dto(direction), now_ms)
        }
        fn may_start_file(&self, direction: &str, now_ms: i64, file_gave_up: bool) -> bool {
            self.0.may_start_file(direction_dto(direction), now_ms, file_gave_up)
        }
        fn last_gave_up_ms(&self, direction: &str) -> Option<i64> {
            self.0.last_gave_up_ms(direction_dto(direction))
        }
        fn restore(&mut self, direction: &str, last_gave_up_ms: i64) {
            self.0.restore(direction_dto(direction), last_gave_up_ms);
        }
    }

    impl CacheSurface for UniffiCache {
        fn lookup(&self, now_ms: i64) -> String {
            match self.0.lookup(now_ms) {
                DirectLookupDto::Fetch => "fetch",
                DirectLookupDto::Cached { .. } => "cached",
                DirectLookupDto::UseApi => "use_api",
            }
            .to_string()
        }

        fn record(&mut self, outcome: &Value, body: Option<&[u8]>, now_ms: i64) {
            self.0.record(outcome_dto(outcome), body.map(<[u8]>::to_vec), now_ms);
        }
    }

    fn discovery_dto(v: &Value) -> DirectDiscoveryDto {
        let d: dt::Discovery = serde_json::from_value(v.clone()).expect("discovery");
        d.into()
    }

    /// The host hands outcomes back to core (a planner's `window_failed`, the pinned retry decision, the
    /// discovery cache): every kind must come back as itself, `Regrant` and `Retry` included.
    #[test]
    fn every_outcome_survives_a_round_trip_through_core() {
        for outcome in [
            DirectOutcomeDto::Proceed,
            DirectOutcomeDto::NotSupported,
            DirectOutcomeDto::UseApiNow,
            DirectOutcomeDto::ApiForThisFile,
            DirectOutcomeDto::Restart,
            DirectOutcomeDto::Backoff { millis: 1500 },
            DirectOutcomeDto::Terminal {
                status: 403,
                error: None,
            },
            DirectOutcomeDto::Terminal {
                status: 404,
                error: Some("not found".to_string()),
            },
            DirectOutcomeDto::Retry,
            DirectOutcomeDto::Regrant,
            DirectOutcomeDto::Held { millis: None },
            DirectOutcomeDto::Held { millis: Some(3000) },
        ] {
            assert_eq!(DirectOutcomeDto::from_core(&outcome.to_core()), outcome);
        }
    }

    fn outcome_value(o: &DirectOutcomeDto) -> Value {
        match o {
            DirectOutcomeDto::Proceed => json!({"kind": "proceed"}),
            DirectOutcomeDto::NotSupported => json!({"kind": "not_supported"}),
            DirectOutcomeDto::UseApiNow => json!({"kind": "use_api_now"}),
            DirectOutcomeDto::ApiForThisFile => json!({"kind": "api_for_this_file"}),
            DirectOutcomeDto::Restart => json!({"kind": "restart"}),
            DirectOutcomeDto::Backoff { millis } => json!({"kind": "backoff", "millis": millis}),
            DirectOutcomeDto::Terminal { status, error } => {
                json!({"kind": "terminal", "status": status, "error": error})
            }
            DirectOutcomeDto::Retry => json!({"kind": "retry"}),
            DirectOutcomeDto::Regrant => json!({"kind": "regrant"}),
            DirectOutcomeDto::Held { millis } => json!({"kind": "held", "millis": millis}),
        }
    }

    fn outcome_dto(v: &Value) -> DirectOutcomeDto {
        match v["kind"].as_str().unwrap() {
            "proceed" => DirectOutcomeDto::Proceed,
            "not_supported" => DirectOutcomeDto::NotSupported,
            "use_api_now" => DirectOutcomeDto::UseApiNow,
            "api_for_this_file" => DirectOutcomeDto::ApiForThisFile,
            "restart" => DirectOutcomeDto::Restart,
            "retry" => DirectOutcomeDto::Retry,
            "regrant" => DirectOutcomeDto::Regrant,
            "held" => DirectOutcomeDto::Held {
                millis: v["millis"].as_u64(),
            },
            "backoff" => DirectOutcomeDto::Backoff {
                millis: v["millis"].as_u64().unwrap(),
            },
            "terminal" => DirectOutcomeDto::Terminal {
                status: v["status"].as_u64().unwrap() as u16,
                error: v["error"].as_str().map(str::to_owned),
            },
            other => panic!("unknown outcome {other}"),
        }
    }

    fn poll_value(p: DirectPollDto) -> Value {
        match p {
            DirectPollDto::RequestWindow { request } => json!({"kind": "request_window", "request": {
                "object_version_id": request.object_version_id, "start_index": request.start_index,
                "count": request.count, "renewal": request.renewal}}),
            DirectPollDto::Fetch { index, grant } => {
                json!({"kind": "fetch", "index": index, "url": grant.url.raw(), "length": grant.length})
            }
            DirectPollDto::FetchViaApi {
                index,
                object_version_id,
            } => json!({"kind": "fetch_via_api", "index": index, "object_version_id": object_version_id}),
            DirectPollDto::Wait { until_ms } => json!({"kind": "wait", "until_ms": until_ms}),
            DirectPollDto::Done => json!({"kind": "done"}),
            DirectPollDto::Stop { verdict } => {
                let v = match verdict {
                    DirectVerdictDto::ApiForFile => json!({"kind": "api_for_file"}),
                    DirectVerdictDto::Restart => json!({"kind": "restart"}),
                    DirectVerdictDto::Terminal { status, error } => {
                        json!({"kind": "terminal", "status": status, "error": error})
                    }
                    DirectVerdictDto::Corrupt => json!({"kind": "corrupt"}),
                };
                json!({"kind": "stop", "verdict": v})
            }
        }
    }

    fn plan_code(e: DirectTransferError) -> String {
        match e {
            DirectTransferError::Plan { code } => code,
            other => panic!("unexpected error {other:?}"),
        }
    }

    impl Surface for UniffiSurface {
        type Planner = UniffiPlanner;
        type Cache = UniffiCache;
        type Health = UniffiHealth;

        fn cache(&self) -> UniffiCache {
            UniffiCache(DirectDiscoveryCacheHandle::new())
        }

        fn health(&self) -> UniffiHealth {
            UniffiHealth(DirectHealthHandle::new())
        }

        fn resume_transport(&self, recorded: &str, discovery: &Value, forced_api: bool) -> String {
            let recorded = match recorded {
                "api" => DirectRecordedTransportDto::Api,
                "direct" => DirectRecordedTransportDto::Direct,
                other => panic!("unknown recorded transport {other:?}"),
            };
            let state = match discovery["kind"].as_str().unwrap() {
                "offers" => DirectDiscoveryStateDto::Offers {
                    upload: discovery["upload"].as_bool().unwrap(),
                },
                "not_supported" => DirectDiscoveryStateDto::NotSupported,
                "unknown" => DirectDiscoveryStateDto::Unknown,
                "unauthorized" => DirectDiscoveryStateDto::Unauthorized,
                other => panic!("unknown discovery state {other:?}"),
            };
            match direct_resume_transport(recorded, state, forced_api) {
                DirectResumeActionDto::ContinueApi => "continue_api",
                DirectResumeActionDto::ContinueDirect => "continue_direct",
                DirectResumeActionDto::AbandonToApi => "abandon_to_api",
                DirectResumeActionDto::KeepRecordAndFail => "keep_record_and_fail",
                DirectResumeActionDto::KeepRecordAndReauthenticate => "keep_record_and_reauthenticate",
            }
            .to_string()
        }

        fn check_storage_url(&self, url: &str, discovery: &Value, api_base: &str) -> Result<(), String> {
            direct_check_storage_url(url.to_owned(), discovery_dto(discovery), api_base.to_owned()).map_err(|e| match e
            {
                DirectTransferError::LinkRefused { code } => code,
                other => panic!("unexpected error {other:?}"),
            })
        }

        fn classify(
            &self,
            call: &str,
            status: u16,
            content_type: Option<&str>,
            body: &[u8],
            retry_after: Option<&str>,
        ) -> Value {
            let outcome = classify_direct_answer(
                call.to_owned(),
                status,
                content_type.map(str::to_owned),
                body.to_vec(),
                retry_after.map(str::to_owned),
            )
            .expect("known call");
            outcome_value(&outcome)
        }

        fn redact(&self, input: &str) -> String {
            direct_redact_url(input.to_owned())
        }

        fn pinned_retry(&self, outcome: &Value, attempt: u32, waited_ms: u64) -> Value {
            match direct_pinned_retry_decision(outcome_dto(outcome), attempt, waited_ms) {
                DirectRetryDecisionDto::Wait { millis } => json!({"kind": "wait", "millis": millis}),
                DirectRetryDecisionDto::GiveUp => json!({"kind": "give_up"}),
            }
        }

        fn scrub(&self, input: &str) -> String {
            direct_scrub_text(input.to_owned())
        }

        fn chunk_length(&self, chunk_count: u32, chunk_size: u64, encrypted_size: u64, index: u32) -> Option<u64> {
            // Not exported on its own: reached through the planner's length check. Core's value is the contract.
            dt::Geometry {
                chunk_count,
                chunk_size,
                encrypted_size,
                original_size: 0,
            }
            .chunk_length(index)
        }

        fn check_storage_get(&self, status: u16, content_length: Option<u64>, expected: u64) -> Value {
            storage_answer_json(direct_check_storage_get(status, content_length, expected))
        }

        fn check_storage_body(&self, received: u64, expected: u64) -> Value {
            storage_answer_json(direct_check_storage_body(received, expected))
        }

        fn paced_until_ms(&self, start_ms: i64, wire_bytes: u64, kbps: u64) -> i64 {
            direct_paced_until_ms(start_ms, wire_bytes, kbps)
        }

        fn max_in_flight_bytes(&self, class: &str) -> u64 {
            let class = match class {
                "native" => DirectMemoryClassDto::Native,
                "browser" => DirectMemoryClassDto::Browser,
                "mobile_app" => DirectMemoryClassDto::MobileApp,
                "mobile_extension" => DirectMemoryClassDto::MobileExtension,
                other => panic!("unknown memory class {other:?}"),
            };
            direct_max_in_flight_bytes(class)
        }

        fn pairs_allowed(&self, discovery: &Value, direction: &str, allowlist: &Value) -> bool {
            let pairs: Vec<DirectStorageBucketDto> = allowlist
                .as_array()
                .expect("allowlist")
                .iter()
                .map(|p| DirectStorageBucketDto {
                    host: p["host"].as_str().expect("host").to_owned(),
                    bucket: p["bucket"].as_str().expect("bucket").to_owned(),
                })
                .collect();
            direct_pairs_allowed(discovery_dto(discovery), direction_dto(direction), pairs)
        }

        fn planner(&self, discovery: &Value, api_base: &str, file_id: &str, seed: u64) -> UniffiPlanner {
            UniffiPlanner(DirectDownloadPlannerHandle::new(
                discovery_dto(discovery),
                api_base.to_owned(),
                file_id.to_owned(),
                seed,
            ))
        }
    }

    impl PlannerSurface for UniffiPlanner {
        fn poll(&mut self, now_ms: i64) -> Value {
            poll_value(self.0.poll(now_ms))
        }

        fn window_answered(&mut self, body: &[u8], now_ms: i64) -> Result<(), String> {
            match self.0.window_answered(body.to_vec(), now_ms) {
                DirectWindowAnswerDto::Accepted => Ok(()),
                DirectWindowAnswerDto::Malformed => Err("malformed".to_owned()),
                DirectWindowAnswerDto::Refused { code } => Err(code),
            }
        }

        fn window_failed(&mut self, outcome: &Value, now_ms: i64) {
            self.0.window_failed(outcome_dto(outcome), now_ms);
        }

        fn window_malformed(&mut self) {
            self.0.window_malformed();
        }

        fn fetch_ok(&mut self, index: u32) -> Result<(), String> {
            self.0.fetch_ok(index).map_err(plan_code)
        }

        fn fetch_failed(&mut self, index: u32, now_ms: i64) -> Result<(), String> {
            self.0.fetch_failed(index, now_ms).map_err(plan_code)
        }

        fn api_fetch_failed(&mut self, index: u32) -> Result<(), String> {
            self.0.api_fetch_failed(index).map_err(plan_code)
        }

        fn chunk_unauthentic(&mut self, index: u32) -> Result<(), String> {
            self.0.chunk_unauthentic(index).map_err(plan_code)
        }

        fn consumed(&mut self, index: u32) -> Result<(), String> {
            self.0.consumed(index).map_err(plan_code)
        }

        fn inspect(&self) -> Value {
            json!({
                "geometry": self.0.geometry().map(|g| json!({
                    "chunk_count": g.chunk_count, "chunk_size": g.chunk_size,
                    "encrypted_size": g.encrypted_size, "original_size": g.original_size})),
                "pinned_version": self.0.pinned_version(),
                "consumed": self.0.consumed_count(),
                "in_flight": self.0.in_flight(),
            })
        }

        fn set_max_in_flight_bytes(&mut self, bytes: u64) {
            self.0.set_max_in_flight_bytes(bytes);
        }

        fn storage_given_up(&self) -> bool {
            self.0.storage_given_up()
        }
    }

    #[test]
    fn the_exported_surface_passes_every_row_of_the_vectors() {
        let report = vectors::run_all(&UniffiSurface);
        assert_eq!(
            report,
            vectors::expected_report(),
            "a section that did not run is a failure"
        );
    }

    #[test]
    fn the_time_bounds_and_the_storage_totals_follow_core() {
        // A 4 MiB chunk (plus the AEAD overhead): 60 s + 33 s, in milliseconds.
        let len = 4 * 1024 * 1024 + 28;
        assert_eq!(direct_storage_put_total_ms(len), 93_000);
        assert_eq!(direct_storage_get_total_ms(len), 93_000);
        assert_eq!(direct_storage_put_total_ms(0), 60_000);
        assert_eq!(direct_background_put_resource_timeout_ms(), 240_000);
        // A hostile length is a long timeout, not a wrap to a short one.
        assert!(direct_storage_put_total_ms(u64::MAX) > direct_storage_put_total_ms(256 * 1024 * 1024 + 28));
        let c = direct_transfer_constants();
        assert_eq!(
            (
                c.storage_connect_timeout_ms,
                c.storage_get_idle_ms,
                c.discovery_timeout_ms,
                c.api_call_timeout_ms,
                c.background_put_resource_timeout_ms
            ),
            (15_000, 30_000, 15_000, 60_000, 240_000),
            "the numbers of the clients design, 6.2"
        );
    }

    #[test]
    fn constants_discovery_and_the_cache_follow_core() {
        let c = direct_transfer_constants();
        assert_eq!(c.cap_object_download_v1, "object-download-v1");
        assert_eq!(c.capabilities_header, "X-Beebeeb-Capabilities");
        assert_eq!((c.max_window, c.default_window, c.chunk_overhead), (32, 8, 28));
        assert_eq!(
            direct_download_grants_path("f".to_owned()),
            "/api/v1/files/f/download-grants"
        );

        let body =
            br#"{"download":["object-download-v1"],"upload":null,"storage_hosts":["s3.storage.test"],"future":1}"#;
        let d = parse_direct_discovery(body.to_vec()).unwrap();
        assert!(direct_discovery_offers_download(d.clone()) && d.upload.is_empty());
        assert!(matches!(
            parse_direct_discovery(b"[]".to_vec()),
            Err(DirectTransferError::Discovery { code }) if code == "discovery_malformed"
        ));
        assert!(matches!(
            parse_direct_discovery(vec![b' '; dt::wire::MAX_DISCOVERY_BYTES + 1]),
            Err(DirectTransferError::Discovery { code }) if code == "discovery_too_large"
        ));

        let cache = DirectDiscoveryCacheHandle::new();
        assert_eq!(cache.lookup(0), DirectLookupDto::Fetch);
        cache.record(DirectOutcomeDto::Proceed, Some(body.to_vec()), 1_000);
        assert!(matches!(cache.lookup(1_000), DirectLookupDto::Cached { .. }));
        assert_eq!(
            cache.lookup(1_000 + 10 * 60 * 1000),
            DirectLookupDto::Fetch,
            "trusted for 10 minutes"
        );
        let gone = DirectDiscoveryCacheHandle::new();
        gone.record(DirectOutcomeDto::NotSupported, None, 0);
        assert_eq!(gone.lookup(1), DirectLookupDto::UseApi, "NotSupported is remembered");
    }

    #[test]
    fn the_jitter_seed_reaches_the_planner() {
        // The same failure, on planners seeded differently, waits different times (equal jitter);
        // the same seed repeats. A binding that drops the seed would give every client one schedule.
        let vectors = vectors::vectors();
        let t0 = vectors["t0_ms"].as_i64().unwrap();
        let file_id = vectors["file_id"].as_str().unwrap().to_owned();
        let wait_after_a_failure = |seed: u64| -> i64 {
            let p = DirectDownloadPlannerHandle::new(
                discovery_dto(&vectors["discoveries"]["std"]),
                "https://api.beebeeb.test".to_owned(),
                file_id.clone(),
                seed,
            );
            p.poll(t0);
            let window = vectors["planner"][0]["steps"][2]["response"].clone();
            assert_eq!(
                p.window_answered(serde_json::to_vec(&window).unwrap(), t0),
                DirectWindowAnswerDto::Accepted
            );
            for _ in 0..3 {
                p.poll(t0);
            }
            p.fetch_failed(0, t0).unwrap();
            match p.poll(t0) {
                DirectPollDto::Wait { until_ms: Some(t) } => t,
                other => panic!("expected a wait for the renewal, got {other:?}"),
            }
        };
        let waits: Vec<i64> = (1..=6).map(wait_after_a_failure).collect();
        assert!(waits.iter().any(|w| *w != waits[0]), "{waits:?}");
        assert_eq!(wait_after_a_failure(3), wait_after_a_failure(3));
    }

    #[test]
    fn a_chunk_length_is_the_stride_and_the_last_chunk_is_short() {
        // The binding must not flatten every index to the stride: the last chunk is whatever the
        // grant's encrypted size leaves, and an index past the window has no length at all.
        let vectors = vectors::vectors();
        let t0 = vectors["t0_ms"].as_i64().unwrap();
        let p = DirectDownloadPlannerHandle::new(
            discovery_dto(&vectors["discoveries"]["std"]),
            "https://api.beebeeb.test".to_owned(),
            vectors["file_id"].as_str().unwrap().to_owned(),
            7,
        );
        assert_eq!(p.chunk_length(0), None, "no geometry before a window is accepted");
        p.poll(t0);
        let window = vectors["planner"][0]["steps"][2]["response"].clone();
        assert_eq!(
            p.window_answered(serde_json::to_vec(&window).unwrap(), t0),
            DirectWindowAnswerDto::Accepted
        );
        // One window, three chunks: stride 1028 (1000 + 28), encrypted size 2584.
        assert_eq!(p.chunk_length(0), Some(1028), "the first chunk is a full stride");
        assert_eq!(p.chunk_length(1), Some(1028), "a middle chunk is a full stride");
        assert_eq!(p.chunk_length(2), Some(528), "the last chunk is short");
        assert_eq!(p.chunk_length(3), None, "past the end there is no chunk");
    }

    #[test]
    fn unknown_calls_and_driving_errors_are_typed() {
        assert!(matches!(
            classify_direct_answer("nope".to_owned(), 200, None, vec![], None),
            Err(DirectTransferError::UnknownCall)
        ));
        let p = DirectDownloadPlannerHandle::new(
            DirectDiscoveryDto::from(dt::Discovery::default()),
            "https://api.beebeeb.test".to_owned(),
            "f".to_owned(),
            1,
        );
        assert!(matches!(p.fetch_ok(0), Err(DirectTransferError::Plan { code }) if code == "not_in_flight"));
        assert!(
            matches!(p.consumed(0), Err(DirectTransferError::Plan { code }) if code == "out_of_order" || code == "not_fetched")
        );
    }

    #[test]
    fn a_signed_url_is_built_from_text_and_prints_none_of_it() {
        let text = "https://s3.storage.test/bb-01/k?X-Amz-Signature=SECRETSIG";
        let a = DirectSignedUrl::new(text.to_owned());
        let other = DirectSignedUrl::new(format!("{text}x"));
        assert_eq!(a.raw(), text);
        // Rust-side equality exists (the derives of the records need it); the bindings do not export it.
        assert_eq!(*a, *DirectSignedUrl::new(text.to_owned()));
        assert_ne!(*a, *other);
        assert!(!format!("{a:?} {a}").contains("SECRETSIG"));
    }

    /// The committed Swift and Kotlin are what the apps compile. A change to the exported surface of the link
    /// (its redacted `toString`, the constructor, the traits it must NOT export) must come with regenerated files.
    #[test]
    fn the_committed_bindings_carry_the_signed_url_surface() {
        let swift = include_str!("../bindings/beebeeb_uniffi.swift");
        assert!(
            swift.contains(
                "open class DirectSignedUrl: DirectSignedUrlProtocol, @unchecked Sendable, \
                 CustomDebugStringConvertible, CustomStringConvertible {"
            ),
            "Swift: DirectSignedUrl is printed through its Rust Display/Debug, and is not Equatable or Hashable"
        );
        assert!(
            swift.contains("public convenience init(url: String)"),
            "Swift: the constructor"
        );
        let header = include_str!("../bindings/beebeeb_uniffiFFI.h");
        let kotlin_sources = [
            include_str!("../bindings/uniffi/beebeeb_uniffi/beebeeb_uniffi.kt"),
            include_str!("../../bindings/kotlin/uniffi/beebeeb_uniffi/beebeeb_uniffi.kt"),
        ];
        // UniFFI 0.31.1's Kotlin `equals`/`hashCode` lower the object's handle with no destroyed check: comparing
        // or hashing a released link, grant or poll would be a use-after-free in native code. None is exported.
        for exported in [
            "directsignedurl_uniffi_trait_eq",
            "directsignedurl_uniffi_trait_hash",
            "directchunkgrantdto_uniffi_trait",
            "directpolldto_uniffi_trait",
        ] {
            assert!(!header.contains(exported), "C header exports {exported}");
            assert!(!swift.contains(exported), "Swift calls {exported}");
            for kotlin in kotlin_sources {
                assert!(!kotlin.contains(exported), "Kotlin calls {exported}");
            }
        }
        for held_in in [
            "public struct DirectChunkGrantDto: Equatable",
            "public struct DirectChunkGrantDto: Hashable",
            "public enum DirectPollDto: Equatable",
            "public enum DirectPollDto: Hashable",
        ] {
            assert!(!swift.contains(held_in), "Swift: {held_in}");
        }
        for kotlin in kotlin_sources {
            let class = kotlin
                .split("open class DirectSignedUrl")
                .nth(1)
                .expect("Kotlin: DirectSignedUrl is generated")
                .split("object FfiConverterTypeDirectSignedUrl")
                .next()
                .unwrap();
            for needed in ["override fun toString()", "constructor(`url`: kotlin.String)"] {
                assert!(class.contains(needed), "Kotlin: DirectSignedUrl lacks {needed}");
            }
            for forbidden in ["override fun equals(", "override fun hashCode("] {
                assert!(!class.contains(forbidden), "Kotlin: DirectSignedUrl has {forbidden}");
            }
        }
    }

    #[test]
    fn a_grant_never_prints_its_signature() {
        let link = "https://s3.storage.test/bb-01/k?X-Amz-Signature=SECRETSIG";
        let grant = DirectChunkGrantDto {
            index: 0,
            method: "GET".to_owned(),
            url: DirectSignedUrl::new(link.to_owned()),
            length: 1,
            expires_at: "2027-01-15T08:05:00Z".to_owned(),
        };
        // Everything a generated binding can print: the record's Debug (what Kotlin's data-class
        // `toString()` and Swift's reflection reach through the object), the object's own Debug and
        // Display (what the exported `toString()` / `description` call), and the enum around it.
        let shown = format!(
            "{grant:?} {:?} {} {:?} {}",
            DirectPollDto::Fetch {
                index: 0,
                grant: grant.clone()
            },
            grant.url,
            grant.url,
            grant.url.redacted(),
        );
        assert!(!shown.contains("SECRETSIG") && !shown.contains("X-Amz"), "{shown}");
        assert!(
            shown.contains("s3.storage.test"),
            "the host is still visible for a log line: {shown}"
        );
        // The one way to the link is explicit, by name.
        assert_eq!(grant.url.raw(), link);
        let err = direct_check_storage_url(
            "https://evil.test@s3.storage.test/bb-01/k?X-Amz-Signature=SECRETSIG".to_owned(),
            DirectDiscoveryDto::from(dt::Discovery::default()),
            "https://api.beebeeb.test".to_owned(),
        )
        .unwrap_err();
        assert!(
            !err.to_string().contains("SECRETSIG") && !err.to_string().contains("evil.test"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod client_meta_binding_tests {
    //! Task 1922: the UniFFI `MasterKeyHandle` methods, keys staying in Rust.
    use super::*;

    fn master() -> Arc<MasterKeyHandle> {
        MasterKeyHandle::from_keychain_bytes(vec![0x40u8; 32]).unwrap()
    }

    const RECORD: &str = "19220000-0000-4000-8000-000000000001";
    const DEVICE: &str = "19220000-0000-4000-8000-0000000000aa";

    #[test]
    fn client_meta_round_trip_and_many() {
        let m = master();
        let host = m
            .seal_client_meta(RECORD.into(), None, 1, "MacBook-Air".into())
            .unwrap();
        assert!(host.starts_with("bbcm1."));
        assert_eq!(
            m.open_client_meta(RECORD.into(), None, 1, host.clone()).unwrap(),
            "MacBook-Air"
        );
        // Field 1 must not carry a device key.
        assert!(
            m.seal_client_meta(RECORD.into(), Some(DEVICE.into()), 1, "x".into())
                .is_err()
        );
        let path = m
            .seal_client_meta(RECORD.into(), Some(DEVICE.into()), 3, "/Users/guus/Taxes".into())
            .unwrap();
        let rows = m
            .open_client_meta_many(vec![
                ClientMetaItem {
                    record_key: RECORD.into(),
                    device_key: None,
                    field: 1,
                    envelope: host,
                },
                ClientMetaItem {
                    record_key: RECORD.into(),
                    device_key: Some(DEVICE.into()),
                    field: 3,
                    envelope: path,
                },
                ClientMetaItem {
                    record_key: RECORD.into(),
                    device_key: Some(DEVICE.into()),
                    field: 4,
                    envelope: "not-an-envelope".into(),
                },
                ClientMetaItem {
                    record_key: "not-a-uuid".into(),
                    device_key: None,
                    field: 1,
                    envelope: "bbcm1.x".into(),
                },
                ClientMetaItem {
                    record_key: RECORD.into(),
                    device_key: None,
                    field: 5,
                    envelope: "bbcm1.x".into(),
                },
            ])
            .unwrap();
        assert_eq!(rows.len(), 5);
        assert!(rows[0].ok);
        assert_eq!(rows[0].value.as_deref(), Some("MacBook-Air"));
        assert!(rows[1].ok);
        assert_eq!(rows[1].value.as_deref(), Some("/Users/guus/Taxes"));
        for row in &rows[2..] {
            assert!(!row.ok);
            assert!(row.value.is_none());
        }
    }

    /// A cleared key handle fails the whole batch; it must not turn into
    /// silent `ok: false` rows that look like per-row decryption failures.
    #[test]
    fn a_cleared_handle_makes_the_batch_an_error() {
        let m = master();
        *m.inner.lock().unwrap() = None;
        assert!(m.open_client_meta_many(vec![]).is_err());
        assert!(m.seal_client_meta(RECORD.into(), None, 1, "x".into()).is_err());
    }

    /// The batch takes one lock and derives the key once: the export block has
    /// no per-row `with_key` and no per-row `ClientMetaKey::new` any more.
    #[test]
    fn the_batch_derives_the_key_once() {
        let src = include_str!("lib.rs");
        let at = src
            .find("pub fn open_client_meta_many")
            .expect("the batch export exists");
        let body = &src[at..];
        let end = body.find("\n    }\n").expect("end of the batch function");
        let body = &body[..end];
        assert_eq!(
            body.matches("with_key(").count(),
            1,
            "exactly one lock for the whole batch: {body}"
        );
        assert_eq!(
            body.matches("ClientMetaKey::new").count(),
            1,
            "exactly one derive for the whole batch: {body}"
        );
        assert!(
            !body.contains("open_client_meta_row"),
            "the row helper is no longer called per row from the export block: {body}"
        );
    }

    #[test]
    fn fit_for_seal_is_exported_and_caps_at_1024_bytes() {
        assert_eq!(fit_for_seal("short".into()), "short");
        let long = "é".repeat(700);
        let fitted = fit_for_seal(long);
        assert!(fitted.len() <= 1024, "{} bytes", fitted.len());
        assert!(fitted.starts_with('…'));
        assert!(fitted.is_char_boundary(3));
    }
}
