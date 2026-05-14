use wasm_bindgen::prelude::*;

use beebeeb_core::encrypt;
use beebeeb_core::kdf;
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
// OPAQUE protocol
// ---------------------------------------------------------------------------

/// Start OPAQUE client registration. Returns `{ message: Uint8Array, state: Uint8Array }`.
#[wasm_bindgen]
pub fn opaque_registration_start(password: &[u8]) -> Result<JsValue, JsError> {
    let result =
        beebeeb_core::opaque_protocol::client_registration_start(password).map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"message".into(),
        &js_sys::Uint8Array::from(result.message.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"state".into(),
        &js_sys::Uint8Array::from(result.state.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Finish OPAQUE client registration. Returns `Uint8Array` (registration upload).
#[wasm_bindgen]
pub fn opaque_registration_finish(
    client_state: &[u8],
    password: &[u8],
    server_response: &[u8],
) -> Result<Vec<u8>, JsError> {
    beebeeb_core::opaque_protocol::client_registration_finish(client_state, password, server_response)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Start OPAQUE client login. Returns `{ message: Uint8Array, state: Uint8Array }`.
#[wasm_bindgen]
pub fn opaque_login_start(password: &[u8]) -> Result<JsValue, JsError> {
    let result =
        beebeeb_core::opaque_protocol::client_login_start(password).map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"message".into(),
        &js_sys::Uint8Array::from(result.message.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"state".into(),
        &js_sys::Uint8Array::from(result.state.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Finish OPAQUE client login. Returns `{ message: Uint8Array, session_key: Uint8Array, export_key: Uint8Array }`.
#[wasm_bindgen]
pub fn opaque_login_finish(client_state: &[u8], password: &[u8], server_response: &[u8]) -> Result<JsValue, JsError> {
    let result = beebeeb_core::opaque_protocol::client_login_finish(client_state, password, server_response)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"message".into(),
        &js_sys::Uint8Array::from(result.message.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"session_key".into(),
        &js_sys::Uint8Array::from(result.session_key.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"export_key".into(),
        &js_sys::Uint8Array::from(result.export_key.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

// ---------------------------------------------------------------------------
// X25519 identity + sharing
// ---------------------------------------------------------------------------

/// Derive X25519 signing key from master key. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn derive_x25519_private(master_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let mk_bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be 32 bytes"))?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);
    Ok(beebeeb_core::opaque::derive_x25519_private(&mk).to_vec())
}

/// Derive X25519 verification key from signing key. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn derive_x25519_public(private_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let pk: [u8; 32] = private_key
        .try_into()
        .map_err(|_| JsError::new("private_key must be 32 bytes"))?;
    Ok(beebeeb_core::opaque::derive_x25519_public(&pk).to_vec())
}

/// Compute X25519 shared secret for sharing. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn x25519_shared_secret(my_private: &[u8], their_public: &[u8]) -> Result<Vec<u8>, JsError> {
    let priv_key: [u8; 32] = my_private
        .try_into()
        .map_err(|_| JsError::new("signing key must be 32 bytes"))?;
    let pub_key: [u8; 32] = their_public
        .try_into()
        .map_err(|_| JsError::new("public key must be 32 bytes"))?;
    Ok(beebeeb_core::opaque::x25519_shared_secret(&priv_key, &pub_key).to_vec())
}

/// Derive a share key from a shared secret + file ID. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn derive_share_key(shared_secret: &[u8], file_id: &[u8]) -> Result<Vec<u8>, JsError> {
    let ss: [u8; 32] = shared_secret
        .try_into()
        .map_err(|_| JsError::new("shared_secret must be 32 bytes"))?;
    Ok(beebeeb_core::opaque::derive_share_key(&ss, file_id).to_vec())
}

/// Compute recovery check from master key. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn compute_recovery_check(master_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let mk_bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be 32 bytes"))?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);
    Ok(beebeeb_core::opaque::compute_recovery_check(&mk).to_vec())
}

// ---------------------------------------------------------------------------
// Chunk planning
// ---------------------------------------------------------------------------

/// Plan how to split a file into chunks for upload based on the client profile.
///
/// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
/// Returns `{ chunk_size_bytes: number, chunk_count: number }`.
#[wasm_bindgen]
pub fn plan_chunks(file_size_bytes: u64, profile: &str) -> Result<JsValue, JsError> {
    let p = match profile {
        "desktop" => beebeeb_types::ChunkProfile::Desktop,
        "web" => beebeeb_types::ChunkProfile::Web,
        "mobile" => beebeeb_types::ChunkProfile::Mobile,
        "backup" => beebeeb_types::ChunkProfile::BackupAgent,
        _ => return Err(JsError::new(&format!("unknown profile: {profile}"))),
    };
    let plan = beebeeb_types::plan_chunks(file_size_bytes, p);
    Ok(serde_wasm_bindgen::to_value(&serde_json::json!({
        "chunk_size_bytes": plan.chunk_size_bytes,
        "chunk_count": plan.chunk_count,
    }))?)
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
    js_sys::Reflect::set(
        &obj,
        &"nonce".into(),
        &js_sys::Uint8Array::from(blob.nonce.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"ciphertext".into(),
        &js_sys::Uint8Array::from(blob.ciphertext.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;

    Ok(obj.into())
}
