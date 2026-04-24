use wasm_bindgen::prelude::*;

use beebeeb_core::kdf;
use beebeeb_core::encrypt;
use beebeeb_core::recovery;
use beebeeb_types::CipherSuite;
use beebeeb_types::EncryptedBlob;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte master key from a password and salt (>= 16 bytes) via
/// Argon2id. Returns a JS object `{ key: Uint8Array }`.
#[wasm_bindgen]
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<JsValue, JsError> {
    let mk = kdf::derive_master_key(password, salt).map_err(|e| JsError::new(&e.to_string()))?;
    let bytes = mk.to_bytes();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"key".into(), &js_sys::Uint8Array::from(&bytes[..]).into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Derive a per-file encryption key from a master key and file ID via
/// HKDF-SHA256. Both `master_key` and `file_id` are raw byte slices.
/// Returns the 32-byte file key as `Uint8Array`.
#[wasm_bindgen]
pub fn derive_file_key(master_key: &[u8], file_id: &[u8]) -> Result<Vec<u8>, JsError> {
    let mk_bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be exactly 32 bytes"))?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);
    let fk = kdf::derive_file_key(&mk, file_id);
    Ok(fk.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encrypt a plaintext chunk with AES-256-GCM. Returns a JS object
/// `{ cipher_suite: string, nonce: Uint8Array, ciphertext: Uint8Array }`.
#[wasm_bindgen]
pub fn encrypt_chunk(key: &[u8], plaintext: &[u8]) -> Result<JsValue, JsError> {
    let fk = file_key_from_slice(key)?;
    let blob = encrypt::encrypt_chunk(&fk, plaintext).map_err(|e| JsError::new(&e.to_string()))?;
    encrypted_blob_to_js(&blob)
}

/// Decrypt a ciphertext chunk that was produced by `encrypt_chunk`.
/// `key`, `nonce`, and `ciphertext` are raw byte slices.
#[wasm_bindgen]
pub fn decrypt_chunk(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let fk = file_key_from_slice(key)?;
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: nonce.to_vec(),
        ciphertext: ciphertext.to_vec(),
    };
    encrypt::decrypt_chunk(&fk, &blob).map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// Encrypt a UTF-8 metadata string (filename, path, etc.) with AES-256-GCM.
/// Returns the same JS object shape as `encrypt_chunk`.
#[wasm_bindgen]
pub fn encrypt_metadata(key: &[u8], metadata: &str) -> Result<JsValue, JsError> {
    let fk = file_key_from_slice(key)?;
    let blob = encrypt::encrypt_metadata(&fk, metadata).map_err(|e| JsError::new(&e.to_string()))?;
    encrypted_blob_to_js(&blob)
}

/// Decrypt a metadata blob back to a UTF-8 string.
#[wasm_bindgen]
pub fn decrypt_metadata(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<String, JsError> {
    let fk = file_key_from_slice(key)?;
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: nonce.to_vec(),
        ciphertext: ciphertext.to_vec(),
    };
    encrypt::decrypt_metadata(&fk, &blob).map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Recovery phrase
// ---------------------------------------------------------------------------

/// Generate a new 12-word BIP39 recovery phrase and the corresponding master
/// key. Returns `{ phrase: string, master_key: Uint8Array }`.
#[wasm_bindgen]
pub fn generate_recovery_phrase() -> Result<JsValue, JsError> {
    let (phrase, mk) = recovery::generate_recovery_phrase().map_err(|e| JsError::new(&e.to_string()))?;
    let bytes = mk.to_bytes();

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"phrase".into(), &JsValue::from_str(&phrase))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(&obj, &"master_key".into(), &js_sys::Uint8Array::from(&bytes[..]).into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Recover a master key from a 12-word BIP39 recovery phrase.
/// Returns the 32-byte master key as `Uint8Array`.
#[wasm_bindgen]
pub fn recover_from_phrase(phrase: &str) -> Result<Vec<u8>, JsError> {
    let mk = recovery::recover_from_phrase(phrase).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(mk.to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reconstruct a `FileKey` from a 32-byte slice received from JS.
fn file_key_from_slice(key: &[u8]) -> Result<kdf::FileKey, JsError> {
    let bytes: [u8; 32] = key
        .try_into()
        .map_err(|_| JsError::new("key must be exactly 32 bytes"))?;
    Ok(kdf::FileKey::from_bytes(bytes))
}

/// Convert an `EncryptedBlob` into a plain JS object with separate fields
/// for better JS ergonomics.
fn encrypted_blob_to_js(blob: &EncryptedBlob) -> Result<JsValue, JsError> {
    let obj = js_sys::Object::new();

    let suite = match blob.cipher_suite {
        CipherSuite::V1Aes256Gcm => "V1Aes256Gcm",
    };

    js_sys::Reflect::set(&obj, &"cipher_suite".into(), &JsValue::from_str(suite))
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(&obj, &"nonce".into(), &js_sys::Uint8Array::from(blob.nonce.as_slice()).into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"ciphertext".into(),
        &js_sys::Uint8Array::from(blob.ciphertext.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;

    Ok(obj.into())
}
