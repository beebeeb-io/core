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

/// Decrypt a sequence of encrypted chunks and return the concatenated plaintext.
/// Each chunk is a JS object `{ nonce: Uint8Array, ciphertext: Uint8Array }`.
/// Returns the full plaintext as `Uint8Array`.
#[wasm_bindgen]
pub fn decrypt_chunks(key: &[u8], chunks: JsValue) -> Result<Vec<u8>, JsError> {
    let fk = file_key_from_slice(key)?;
    let arr = js_sys::Array::from(&chunks);
    let mut result = Vec::new();

    for i in 0..arr.length() {
        let chunk = arr.get(i);
        let nonce = js_sys::Reflect::get(&chunk, &"nonce".into())
            .map_err(|e| JsError::new(&format!("missing nonce: {e:?}")))?;
        let ciphertext = js_sys::Reflect::get(&chunk, &"ciphertext".into())
            .map_err(|e| JsError::new(&format!("missing ciphertext: {e:?}")))?;

        let nonce_bytes = js_sys::Uint8Array::new(&nonce).to_vec();
        let ct_bytes = js_sys::Uint8Array::new(&ciphertext).to_vec();

        let blob = EncryptedBlob {
            cipher_suite: CipherSuite::V1Aes256Gcm,
            nonce: nonce_bytes,
            ciphertext: ct_bytes,
        };
        let plaintext = encrypt::decrypt_chunk(&fk, &blob)
            .map_err(|e| JsError::new(&e.to_string()))?;
        result.extend_from_slice(&plaintext);
    }

    Ok(result)
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
// Media utilities
// ---------------------------------------------------------------------------

/// Returns `true` if the given MIME type can be previewed in-app.
#[wasm_bindgen]
pub fn is_previewable(mime_type: Option<String>) -> bool {
    beebeeb_core::media::is_previewable(mime_type.as_deref())
}

/// Returns `true` if the file extension indicates a previewable file.
#[wasm_bindgen]
pub fn is_previewable_by_extension(filename: &str) -> bool {
    beebeeb_core::media::is_previewable_by_extension(filename)
}

// ---------------------------------------------------------------------------
// Quota / plan helpers
// ---------------------------------------------------------------------------

/// Return the base storage quota (in bytes) for a plan slug.
#[wasm_bindgen]
pub fn plan_base_storage_bytes(plan_slug: &str) -> i64 {
    beebeeb_types::Plan::from_slug(plan_slug).base_storage_bytes()
}

/// Compute the effective quota after add-ons and bonus bytes.
#[wasm_bindgen]
pub fn plan_effective_quota(plan_slug: &str, extra_tb: i64, bonus_bytes: i64) -> i64 {
    let plan = beebeeb_types::Plan::from_slug(plan_slug);
    beebeeb_types::effective_quota(plan, extra_tb, bonus_bytes)
}

/// Maximum additional TB a plan may purchase.
#[wasm_bindgen]
pub fn plan_max_extra_tb(plan_slug: &str) -> i64 {
    beebeeb_types::Plan::from_slug(plan_slug).max_extra_tb()
}

/// Whether the plan supports purchasing extra storage.
#[wasm_bindgen]
pub fn plan_can_add_storage(plan_slug: &str) -> bool {
    beebeeb_types::Plan::from_slug(plan_slug).can_add_storage()
}

/// Monthly cost in cents for a plan with optional add-ons.
#[wasm_bindgen]
pub fn plan_monthly_cost_cents(plan_slug: &str, extra_tb: i64, extra_users: i64) -> i64 {
    let plan = beebeeb_types::Plan::from_slug(plan_slug);
    beebeeb_types::monthly_cost_cents(plan, extra_tb, extra_users)
}

/// Format a byte count as a human-readable SI string (e.g. "5.0 TB").
#[wasm_bindgen]
pub fn storage_format_si(bytes: i64) -> String {
    beebeeb_types::format_storage_si(bytes)
}

// ---------------------------------------------------------------------------
// PDF generation
// ---------------------------------------------------------------------------

/// Generate a recovery kit PDF with a title, recovery words, and metadata.
///
/// `metadata_keys` and `metadata_values` are parallel arrays of key-value pairs.
/// Returns the raw PDF bytes as `Uint8Array`.
#[wasm_bindgen]
pub fn generate_recovery_pdf(
    title: &str,
    words: JsValue,
    metadata_keys: JsValue,
    metadata_values: JsValue,
) -> Result<Vec<u8>, JsError> {
    let words_arr = js_sys::Array::from(&words);
    let keys_arr = js_sys::Array::from(&metadata_keys);
    let values_arr = js_sys::Array::from(&metadata_values);

    if keys_arr.length() != values_arr.length() {
        return Err(JsError::new(
            "metadata_keys and metadata_values must have the same length",
        ));
    }

    let words_vec: Vec<String> = (0..words_arr.length())
        .map(|i| words_arr.get(i).as_string().unwrap_or_default())
        .collect();

    let keys_vec: Vec<String> = (0..keys_arr.length())
        .map(|i| keys_arr.get(i).as_string().unwrap_or_default())
        .collect();
    let values_vec: Vec<String> = (0..values_arr.length())
        .map(|i| values_arr.get(i).as_string().unwrap_or_default())
        .collect();

    let pairs: Vec<(&str, &str)> = keys_vec
        .iter()
        .zip(values_vec.iter())
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    Ok(beebeeb_core::pdf::generate_recovery_pdf(title, &words_vec, &pairs))
}

// ---------------------------------------------------------------------------
// Archive parsing
// ---------------------------------------------------------------------------

/// List entries in a TAR archive from raw bytes.
/// Returns a JS array of `{ name: string, size: number, is_directory: boolean }`.
#[wasm_bindgen]
pub fn list_tar_entries(data: &[u8]) -> Result<JsValue, JsError> {
    let entries =
        beebeeb_core::archive::list_tar_entries(data).map_err(|e| JsError::new(&e.to_string()))?;
    archive_entries_to_js(&entries)
}

/// Decompress gzip-compressed data. Returns `Uint8Array`.
#[wasm_bindgen]
pub fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, JsError> {
    beebeeb_core::archive::decompress_gzip(data).map_err(|e| JsError::new(&e.to_string()))
}

/// List entries in an archive, detecting format from the filename extension.
/// Supports `.tar`, `.gz`, `.tgz`, `.tar.gz`.
/// Returns a JS array of `{ name: string, size: number, is_directory: boolean }`.
#[wasm_bindgen]
pub fn list_archive(data: &[u8], filename: &str) -> Result<JsValue, JsError> {
    let entries = beebeeb_core::archive::list_archive(data, filename)
        .map_err(|e| JsError::new(&e.to_string()))?;
    archive_entries_to_js(&entries)
}

fn archive_entries_to_js(entries: &[beebeeb_core::archive::ArchiveEntry]) -> Result<JsValue, JsError> {
    let arr = js_sys::Array::new_with_length(entries.len() as u32);
    for (i, entry) in entries.iter().enumerate() {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"name".into(), &JsValue::from_str(&entry.name))
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
        js_sys::Reflect::set(&obj, &"size".into(), &JsValue::from_f64(entry.size as f64))
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
        js_sys::Reflect::set(
            &obj,
            &"is_directory".into(),
            &JsValue::from_bool(entry.is_directory),
        )
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
        arr.set(i as u32, obj.into());
    }
    Ok(arr.into())
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
