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

/// Generate a canonical share token (task 0708): 20 bytes of OS randomness as
/// URL-safe-no-pad base64 (27 chars). Web mints this for A1 owner-recoverable
/// shares so the client-supplied `token` matches the server's format exactly
/// (single canonical impl shared with native/UniFFI via `beebeeb-core`).
#[wasm_bindgen]
pub fn generate_share_token() -> String {
    beebeeb_core::share_token::generate_share_token()
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
        let plaintext = encrypt::decrypt_chunk(&fk, &blob).map_err(|e| JsError::new(&e.to_string()))?;
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
///
/// `ksf_version` selects the KSF the account's password file was registered
/// under (0 = legacy Identity KSF, anything else = current Argon2id). The web
/// client reads it from the login-start response (`server_state` JSON) and
/// passes it through verbatim. The KSF must match or finish fails.
#[wasm_bindgen]
pub fn opaque_login_finish(
    client_state: &[u8],
    password: &[u8],
    server_response: &[u8],
    ksf_version: u32,
) -> Result<JsValue, JsError> {
    let result =
        beebeeb_core::opaque_protocol::client_login_finish(client_state, password, server_response, ksf_version)
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
    let shared =
        beebeeb_core::opaque::x25519_shared_secret(&priv_key, &pub_key).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(shared.to_vec())
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
// File requests (sealed-box / ECIES per request)
// ---------------------------------------------------------------------------

/// Derive the per-request private-key-wrapping key from the owner's master key.
/// `master_key` is 32 bytes, `request_id` is arbitrary bytes. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn derive_request_wrap_key(master_key: &[u8], request_id: &[u8]) -> Result<Vec<u8>, JsError> {
    let mk_bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be 32 bytes"))?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);
    Ok(beebeeb_core::file_request::derive_request_wrap_key(&mk, request_id).to_vec())
}

/// Wrap a request's X25519 private key under the owner's master key.
/// Returns `{ wrapped: Uint8Array, nonce: Uint8Array }`.
#[wasm_bindgen]
pub fn wrap_request_private(master_key: &[u8], request_id: &[u8], r_priv: &[u8]) -> Result<JsValue, JsError> {
    let mk_bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be 32 bytes"))?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);
    let r_priv_arr: [u8; 32] = r_priv.try_into().map_err(|_| JsError::new("r_priv must be 32 bytes"))?;
    let (wrapped, nonce) = beebeeb_core::file_request::wrap_request_private(&mk, request_id, &r_priv_arr)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"wrapped".into(),
        &js_sys::Uint8Array::from(wrapped.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"nonce".into(),
        &js_sys::Uint8Array::from(nonce.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Unwrap a request's X25519 private key. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn unwrap_request_private(
    master_key: &[u8],
    request_id: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, JsError> {
    let mk_bytes: [u8; 32] = master_key
        .try_into()
        .map_err(|_| JsError::new("master_key must be 32 bytes"))?;
    let mk = kdf::MasterKey::from_bytes(mk_bytes);
    let r_priv = beebeeb_core::file_request::unwrap_request_private(&mk, request_id, wrapped, nonce)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(r_priv.to_vec())
}

/// Seal a content key to a request's public key (anonymous uploader path).
/// `r_pub` and `content_key` are 32 bytes; `file_id` is arbitrary bytes.
/// Returns `{ e_pub: Uint8Array, wrapped_key: Uint8Array }`.
#[wasm_bindgen]
pub fn seal_to_request(r_pub: &[u8], file_id: &[u8], content_key: &[u8]) -> Result<JsValue, JsError> {
    let r_pub_arr: [u8; 32] = r_pub.try_into().map_err(|_| JsError::new("r_pub must be 32 bytes"))?;
    let content_key_arr: [u8; 32] = content_key
        .try_into()
        .map_err(|_| JsError::new("content_key must be 32 bytes"))?;
    let sealed = beebeeb_core::file_request::seal_to_request(&r_pub_arr, file_id, &content_key_arr)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"e_pub".into(),
        &js_sys::Uint8Array::from(&sealed.e_pub[..]).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &"wrapped_key".into(),
        &js_sys::Uint8Array::from(sealed.wrapped_key.as_slice()).into(),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Open a sealed request upload (owner decrypt path). Recovers the content key.
/// `r_priv` and `e_pub` are 32 bytes; `file_id` is arbitrary bytes. Returns 32-byte `Uint8Array`.
#[wasm_bindgen]
pub fn open_request_upload(
    r_priv: &[u8],
    e_pub: &[u8],
    file_id: &[u8],
    wrapped_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    let r_priv_arr: [u8; 32] = r_priv.try_into().map_err(|_| JsError::new("r_priv must be 32 bytes"))?;
    let e_pub_arr: [u8; 32] = e_pub.try_into().map_err(|_| JsError::new("e_pub must be 32 bytes"))?;
    let content_key = beebeeb_core::file_request::open_request_upload(&r_priv_arr, &e_pub_arr, file_id, wrapped_key)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(content_key.to_vec())
}

// ---------------------------------------------------------------------------
// Chunk planning
// ---------------------------------------------------------------------------

/// Parse a client-profile string into a [`beebeeb_types::ChunkProfile`].
///
/// Accepts `"desktop"`, `"web"`, `"mobile"`, or `"backup"`. Shared by
/// [`plan_chunks`] and [`WasmChunkEncryptor`] so the profile vocabulary cannot
/// drift between the two surfaces.
fn parse_profile(profile: &str) -> Result<beebeeb_types::ChunkProfile, JsError> {
    match profile {
        "desktop" => Ok(beebeeb_types::ChunkProfile::Desktop),
        "cli" => Ok(beebeeb_types::ChunkProfile::Cli),
        "web" => Ok(beebeeb_types::ChunkProfile::Web),
        "mobile" => Ok(beebeeb_types::ChunkProfile::Mobile),
        "backup" => Ok(beebeeb_types::ChunkProfile::BackupAgent),
        _ => Err(JsError::new(&format!("unknown profile: {profile}"))),
    }
}

/// Plan how to split a file into chunks for upload based on the client profile.
///
/// `profile` must be one of: `"desktop"`, `"web"`, `"mobile"`, `"backup"`.
/// Returns `{ chunk_size_bytes: number, chunk_count: number }`.
#[wasm_bindgen]
pub fn plan_chunks(file_size_bytes: u64, profile: &str) -> Result<JsValue, JsError> {
    let p = parse_profile(profile)?;
    let plan = beebeeb_types::plan_chunks(file_size_bytes, p);
    // Serialize via a typed struct (NOT serde_json::Value) so serde-wasm-bindgen
    // emits a plain JS object, not a Map. See 0655.
    #[derive(serde::Serialize)]
    struct ChunkPlanJs {
        chunk_size_bytes: u64,
        chunk_count: u64,
    }
    Ok(serde_wasm_bindgen::to_value(&ChunkPlanJs {
        chunk_size_bytes: plan.chunk_size_bytes,
        chunk_count: plan.chunk_count,
    })?)
}

// ---------------------------------------------------------------------------
// Streaming chunk encryption (push form)
// ---------------------------------------------------------------------------

/// Stateful, single-file streaming encryptor for the web client.
///
/// WASM is single-threaded and cannot `Read` a browser `File`, so the web
/// client uses the **push** form of the shared `beebeeb-core` primitive: JS
/// slices the `Blob` and hands each plaintext chunk to [`push_chunk`], and core
/// encrypts it. This converges the web client onto the exact same crypto loop
/// (and wire format) as the CLI/desktop/mobile clients — the per-file key is
/// derived **once** inside core and never recombined in JS.
///
/// Lifecycle: construct with [`new`](Self::new) (or
/// [`withChunkSize`](Self::with_chunk_size) when the server dictates the chunk
/// size), call [`pushChunk`](Self::push_chunk) once per slice in order, then
/// [`finish`](Self::finish) to run the integrity guard and get the summary.
///
/// This is the first stateful `#[wasm_bindgen]` struct in the crate: it proves
/// the constructor + `&mut self` method + by-value `self` (consuming `finish`)
/// pattern across the JS boundary.
#[wasm_bindgen]
pub struct WasmChunkEncryptor {
    inner: beebeeb_core::chunk_stream::ChunkEncryptor,
}

#[wasm_bindgen]
impl WasmChunkEncryptor {
    /// Create a push-form encryptor whose chunk plan is derived from
    /// `file_size` + `profile` (the client ladder).
    ///
    /// `master_key` must be exactly 32 bytes; it is copied into a `MasterKey`
    /// (zeroized on drop). `profile` is one of `"desktop"`, `"web"`, `"mobile"`,
    /// `"backup"`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        master_key: &[u8],
        file_id: String,
        file_size: u64,
        profile: &str,
    ) -> Result<WasmChunkEncryptor, JsError> {
        let mk = master_key_from_slice(master_key)?;
        let p = parse_profile(profile)?;
        let inner = beebeeb_core::chunk_stream::ChunkEncryptor::for_push(&mk, &file_id, file_size, p)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { inner })
    }

    /// Create a push-form encryptor with an explicit, server-dictated chunk
    /// size. Use this when the v2 upload-init response overrode `chunk_size`
    /// so the client plan can't diverge from what the server expects.
    #[wasm_bindgen(js_name = withChunkSize)]
    pub fn with_chunk_size(
        master_key: &[u8],
        file_id: String,
        file_size: u64,
        chunk_size_bytes: u64,
    ) -> Result<WasmChunkEncryptor, JsError> {
        let mk = master_key_from_slice(master_key)?;
        let inner = beebeeb_core::chunk_stream::ChunkEncryptor::for_push_with_chunk_size(
            &mk,
            &file_id,
            file_size,
            chunk_size_bytes,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { inner })
    }

    /// Encrypt one plaintext chunk and return the full wire frame
    /// (`nonce(12) || ciphertext || tag(16)`) for JS to PUT directly — no
    /// recombination needed on the JS side. Errors if more chunks are pushed
    /// than the plan allows.
    #[wasm_bindgen(js_name = pushChunk)]
    pub fn push_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .push_chunk(plaintext)
            .map(|c| c.data)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Planned number of chunks for this file.
    #[wasm_bindgen(getter, js_name = chunkCount)]
    pub fn chunk_count(&self) -> u32 {
        // chunk_count is validated to fit in u32 by the core constructor.
        self.inner.chunk_plan().chunk_count as u32
    }

    /// Plaintext chunk size in bytes (the last chunk may be smaller). Returned
    /// as a JS number (`f64`) to avoid `BigInt` at the boundary.
    #[wasm_bindgen(getter, js_name = chunkSize)]
    pub fn chunk_size(&self) -> f64 {
        self.inner.chunk_plan().chunk_size_bytes as f64
    }

    /// Expected total ciphertext bytes (`file_size + 28 * chunk_count`), the
    /// value the client passes to `upload_init` as the total. Returned as a JS
    /// number (`f64`).
    #[wasm_bindgen(getter, js_name = expectedTotalCiphertext)]
    pub fn expected_total_ciphertext(&self) -> f64 {
        self.inner.expected_total_ciphertext() as f64
    }

    /// How many chunks have been pushed so far.
    #[wasm_bindgen(getter, js_name = chunksEmitted)]
    pub fn chunks_emitted(&self) -> u32 {
        self.inner.chunks_emitted()
    }

    /// Consume the encryptor, run the integrity guard (all planned chunks
    /// emitted and the ciphertext total matches), and return the summary
    /// `{ chunk_count, total_plaintext, total_ciphertext, chunk_size_bytes }`.
    /// Errors if the source shrank (fewer chunks/bytes than planned).
    pub fn finish(self) -> Result<JsValue, JsError> {
        let summary = self.finish_summary().map_err(|e| JsError::new(&e.to_string()))?;
        // Serialize via a typed struct (NOT serde_json::Value) so serde-wasm-bindgen
        // emits a plain JS object, not a Map. See 0655. chunk_count is u32.
        #[derive(serde::Serialize)]
        struct FinishSummaryJs {
            chunk_count: u32,
            total_plaintext: u64,
            total_ciphertext: u64,
            chunk_size_bytes: u64,
        }
        Ok(serde_wasm_bindgen::to_value(&FinishSummaryJs {
            chunk_count: summary.chunk_count,
            total_plaintext: summary.total_plaintext,
            total_ciphertext: summary.total_ciphertext,
            chunk_size_bytes: summary.chunk_size_bytes,
        })?)
    }
}

impl WasmChunkEncryptor {
    /// Testable seam for the consuming `finish`: runs the core integrity guard
    /// and returns the native summary without crossing the JS boundary, so unit
    /// tests can exercise the by-value `finish` path without a JS runtime.
    fn finish_summary(self) -> Result<beebeeb_core::chunk_stream::ChunkEncryptorSummary, beebeeb_core::CoreError> {
        self.inner.finish()
    }
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
    let entries = beebeeb_core::archive::list_tar_entries(data).map_err(|e| JsError::new(&e.to_string()))?;
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
    let entries = beebeeb_core::archive::list_archive(data, filename).map_err(|e| JsError::new(&e.to_string()))?;
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
        js_sys::Reflect::set(&obj, &"is_directory".into(), &JsValue::from_bool(entry.is_directory))
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

/// Reconstruct a `MasterKey` from a 32-byte slice received from JS. The
/// resulting `MasterKey` owns the bytes and zeroizes them on drop.
fn master_key_from_slice(key: &[u8]) -> Result<kdf::MasterKey, JsError> {
    let bytes: [u8; 32] = key
        .try_into()
        .map_err(|_| JsError::new("master_key must be exactly 32 bytes"))?;
    Ok(kdf::MasterKey::from_bytes(bytes))
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

// ---------------------------------------------------------------------------
// Search index (task 0784) — wasm-bindgen wrapper for search_index.
// Bindings only; the 0778-B algorithm + crypto are unchanged.
// ---------------------------------------------------------------------------

use beebeeb_core::search_index;
use beebeeb_core::search_sync;

fn reflect_string(item: &JsValue, key: &str) -> Result<String, JsError> {
    js_sys::Reflect::get(item, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new(&format!("each entry needs a string `{key}`")))
}

fn reflect_u32(item: &JsValue, key: &str) -> Result<u32, JsError> {
    js_sys::Reflect::get(item, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_f64())
        .map(|n| n as u32)
        .ok_or_else(|| JsError::new(&format!("each shard needs a number `{key}`")))
}

/// `[{bucket, page, blob: Uint8Array}]` — the JS shape of an encrypted shard list.
fn shards_to_js(shards: &[search_index::EncryptedShard]) -> JsValue {
    let arr = js_sys::Array::new();
    for s in shards {
        let obj = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&obj, &"bucket".into(), &JsValue::from_f64(s.bucket as f64));
        let _ = js_sys::Reflect::set(&obj, &"page".into(), &JsValue::from_f64(s.page as f64));
        let _ = js_sys::Reflect::set(&obj, &"blob".into(), &js_sys::Uint8Array::from(&s.blob[..]).into());
        arr.push(&obj);
    }
    arr.into()
}

fn js_to_shards(shards: &JsValue) -> Result<Vec<search_index::EncryptedShard>, JsError> {
    let arr = js_sys::Array::from(shards);
    let mut out = Vec::with_capacity(arr.length() as usize);
    for item in arr.iter() {
        let bucket = reflect_u32(&item, "bucket")?;
        let page = reflect_u32(&item, "page")?;
        let blob_val = js_sys::Reflect::get(&item, &"blob".into()).map_err(|_| JsError::new("shard missing `blob`"))?;
        let blob = js_sys::Uint8Array::new(&blob_val).to_vec();
        out.push(search_index::EncryptedShard { bucket, page, blob });
    }
    Ok(out)
}

/// A stateful, client-side search index over a vault's file names.
///
/// Build it from a file list, mutate it incrementally (`upsert`/`remove` return
/// the dirty bucket set as a `Uint32Array`), query it (returns a `string[]` of
/// file_ids), and (de)serialize it to encrypted shards for sync. The master key
/// crosses as 32 raw bytes; crypto runs in core.
#[wasm_bindgen]
pub struct WasmSearchIndex {
    inner: search_index::SearchIndex,
}

#[wasm_bindgen]
impl WasmSearchIndex {
    /// Empty index with the given shard count (clamped to ≥ 1).
    #[wasm_bindgen(constructor)]
    pub fn new(num_shards: u32) -> WasmSearchIndex {
        Self {
            inner: search_index::SearchIndex::new(num_shards),
        }
    }

    /// Build from `files` — a JS array of `{ fileId, name }` objects.
    pub fn build(files: JsValue, num_shards: u32) -> Result<WasmSearchIndex, JsError> {
        let arr = js_sys::Array::from(&files);
        let mut pairs: Vec<(String, String)> = Vec::with_capacity(arr.length() as usize);
        for item in arr.iter() {
            pairs.push((reflect_string(&item, "fileId")?, reflect_string(&item, "name")?));
        }
        Ok(Self {
            inner: search_index::SearchIndex::build(&pairs, num_shards),
        })
    }

    /// Reconstruct from encrypted shards (`[{bucket, page, blob: Uint8Array}]`),
    /// decrypting each with the 32-byte master key.
    #[wasm_bindgen(js_name = fromEncryptedShards)]
    pub fn from_encrypted_shards(
        master_key: &[u8],
        shards: JsValue,
        num_shards: u32,
    ) -> Result<WasmSearchIndex, JsError> {
        let mk = master_key_from_slice(master_key)?;
        let core_shards = js_to_shards(&shards)?;
        let inner = search_index::SearchIndex::from_encrypted_shards(&mk, &core_shards, num_shards)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { inner })
    }

    /// Shard count this index uses.
    #[wasm_bindgen(getter, js_name = numShards)]
    pub fn num_shards(&self) -> u32 {
        self.inner.num_shards()
    }

    /// Number of indexed files.
    #[wasm_bindgen(getter, js_name = fileCount)]
    pub fn file_count(&self) -> u32 {
        self.inner.file_count() as u32
    }

    /// Insert or update a file. Returns the dirty bucket set (`Uint32Array`).
    pub fn upsert(&mut self, file_id: String, name: String) -> Vec<u32> {
        self.inner.upsert(&file_id, &name).into_iter().collect()
    }

    /// Remove a file. Returns the dirty bucket set (`Uint32Array`).
    pub fn remove(&mut self, file_id: String) -> Vec<u32> {
        self.inner.remove(&file_id).into_iter().collect()
    }

    /// Search; returns the matching file_ids as a `string[]`.
    pub fn query(&self, term: String) -> Vec<String> {
        self.inner.query(&term).into_iter().collect()
    }

    /// Encrypt every non-empty shard page → `[{bucket, page, blob: Uint8Array}]`.
    #[wasm_bindgen(js_name = encryptShards)]
    pub fn encrypt_shards(&self, master_key: &[u8]) -> Result<JsValue, JsError> {
        let mk = master_key_from_slice(master_key)?;
        let shards = self
            .inner
            .encrypt_shards(&mk)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(shards_to_js(&shards))
    }

    /// Encrypt only the given buckets (incremental sync) — pass the dirty set.
    #[wasm_bindgen(js_name = encryptBuckets)]
    pub fn encrypt_buckets(&self, master_key: &[u8], buckets: Vec<u32>) -> Result<JsValue, JsError> {
        let mk = master_key_from_slice(master_key)?;
        let set: std::collections::BTreeSet<u32> = buckets.into_iter().collect();
        let shards = self
            .inner
            .encrypt_buckets(&mk, &set)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(shards_to_js(&shards))
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShardRefJs {
    bucket: u32,
    page: u32,
    version: i64,
}

#[derive(serde::Serialize)]
struct ShardCoordJs {
    bucket: u32,
    page: u32,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncPlanJs {
    to_put: Vec<ShardCoordJs>,
    to_get: Vec<ShardCoordJs>,
    to_delete: Vec<ShardCoordJs>,
}

/// Compute the shard sync plan to converge `local` (the client's shard set) with
/// `remote` (the server manifest from `GET /api/v1/search-index/shards`), LWW.
/// `local`/`remote` are arrays of `{ bucket, page, version }`; returns
/// `{ toPut, toGet, toDelete }` arrays of `{ bucket, page }`. See the core
/// `search_sync::diff_manifest` doc for the `localIsAuthoritative` semantics.
#[wasm_bindgen(js_name = searchIndexSyncPlan)]
pub fn search_index_sync_plan(
    local: JsValue,
    remote: JsValue,
    local_is_authoritative: bool,
) -> Result<JsValue, JsError> {
    let local: Vec<ShardRefJs> = serde_wasm_bindgen::from_value(local).map_err(|e| JsError::new(&e.to_string()))?;
    let remote: Vec<ShardRefJs> = serde_wasm_bindgen::from_value(remote).map_err(|e| JsError::new(&e.to_string()))?;
    let to_ref = |r: &ShardRefJs| search_sync::ShardRef {
        bucket: r.bucket,
        page: r.page,
        version: r.version,
    };
    let l: Vec<_> = local.iter().map(to_ref).collect();
    let rem: Vec<_> = remote.iter().map(to_ref).collect();
    let plan = search_sync::diff_manifest(&l, &rem, local_is_authoritative);
    let to_coord = |c: &search_sync::ShardCoord| ShardCoordJs {
        bucket: c.bucket,
        page: c.page,
    };
    let out = SyncPlanJs {
        to_put: plan.to_put.iter().map(to_coord).collect(),
        to_get: plan.to_get.iter().map(to_coord).collect(),
        to_delete: plan.to_delete.iter().map(to_coord).collect(),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Batch name decryption (task 0806)
// ---------------------------------------------------------------------------

/// Batch-decrypt file names in ONE WASM call (task 0806 — folder-load perf).
///
/// `items` is a JS array of `{ fileId: string, nameEncrypted: string }`.
/// `master_key` is the 32 raw bytes. Returns a JS array (same order + length as
/// `items`) of `{ name: string|null, mimeType: string|null, error: string|null }`
/// — `name` set on success, `error` set on failure (bad blob / unparseable
/// fileId / wrong key). One bad item never fails the batch. Mirrors core
/// `decrypt_names` (string-UUID then legacy binary-UUID key attempt).
#[wasm_bindgen]
pub fn decrypt_names(master_key: &[u8], items: JsValue) -> Result<JsValue, JsError> {
    let mk = master_key_from_slice(master_key)?;

    // Parse the JS input. Keep owned Strings so we can borrow &str into the batch.
    let arr = js_sys::Array::from(&items);
    let mut parsed: Vec<(Option<uuid::Uuid>, String)> = Vec::with_capacity(arr.length() as usize);
    for item in arr.iter() {
        let file_id = js_sys::Reflect::get(&item, &"fileId".into())
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| JsError::new("each item needs a string `fileId`"))?;
        let name_encrypted = js_sys::Reflect::get(&item, &"nameEncrypted".into())
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| JsError::new("each item needs a string `nameEncrypted`"))?;
        parsed.push((file_id.parse::<uuid::Uuid>().ok(), name_encrypted));
    }

    // Batch-decrypt the items whose fileId parsed; preserve index alignment.
    let batch_input: Vec<(uuid::Uuid, &str)> = parsed
        .iter()
        .filter_map(|(id, enc)| id.map(|u| (u, enc.as_str())))
        .collect();
    let mut batch = encrypt::decrypt_names(&mk, &batch_input).into_iter();

    let out = js_sys::Array::new();
    for (id, _) in &parsed {
        let obj = js_sys::Object::new();
        match id {
            None => {
                let _ = js_sys::Reflect::set(&obj, &"name".into(), &JsValue::NULL);
                let _ = js_sys::Reflect::set(&obj, &"mimeType".into(), &JsValue::NULL);
                let _ = js_sys::Reflect::set(&obj, &"error".into(), &JsValue::from_str("invalid file_id"));
            }
            Some(_) => match batch.next() {
                Some(Ok((name, mime))) => {
                    let _ = js_sys::Reflect::set(&obj, &"name".into(), &JsValue::from_str(&name));
                    let _ = js_sys::Reflect::set(
                        &obj,
                        &"mimeType".into(),
                        &mime.map(|m| JsValue::from_str(&m)).unwrap_or(JsValue::NULL),
                    );
                    let _ = js_sys::Reflect::set(&obj, &"error".into(), &JsValue::NULL);
                }
                _ => {
                    let _ = js_sys::Reflect::set(&obj, &"name".into(), &JsValue::NULL);
                    let _ = js_sys::Reflect::set(&obj, &"mimeType".into(), &JsValue::NULL);
                    let _ = js_sys::Reflect::set(&obj, &"error".into(), &JsValue::from_str("decryption failed"));
                }
            },
        }
        out.push(&obj);
    }
    Ok(out.into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use beebeeb_core::chunk_stream::ChunkDecryptor;

    /// Deterministic, non-trivial test data.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Decrypt WASM-produced frames with the core push decryptor and return the
    /// concatenated plaintext — proves the wrapper emits the standard wire
    /// format and the FileKey derivation matches.
    fn decrypt_frames(mk: &kdf::MasterKey, file_id: &str, frames: &[Vec<u8>]) -> Vec<u8> {
        let mut dec = ChunkDecryptor::for_push(mk, file_id);
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&dec.push_frame(f).unwrap().data);
        }
        out
    }

    #[test]
    fn with_chunk_size_push_roundtrip_and_finish() {
        let mk = kdf::derive_master_key("test-password", b"test-salt-16bytes").unwrap();
        let mk_bytes = mk.to_bytes();
        let file_id = "wasm-file-1";
        let data = pattern(40);

        // Explicit 16-byte chunks => 3 frames (16 + 16 + 8); exercises the
        // server-dictated-chunk-size constructor.
        let mut enc =
            WasmChunkEncryptor::with_chunk_size(&mk_bytes, file_id.to_string(), data.len() as u64, 16).unwrap();
        assert_eq!(enc.chunk_count(), 3);
        assert_eq!(enc.chunk_size(), 16.0);
        assert_eq!(enc.expected_total_ciphertext(), (40 + 28 * 3) as f64);

        let mut frames = Vec::new();
        for slice in data.chunks(16) {
            frames.push(enc.push_chunk(slice).unwrap());
        }
        assert_eq!(enc.chunks_emitted(), 3);
        assert_eq!(frames[0].len(), 16 + 28);
        assert_eq!(frames[2].len(), 8 + 28);

        // Ciphertext frames must not equal the plaintext slices.
        assert_ne!(frames[0], data[..16].to_vec());

        // By-value finish runs the integrity guard.
        let summary = enc.finish_summary().unwrap();
        assert_eq!(summary.chunk_count, 3);
        assert_eq!(summary.total_plaintext, 40);
        assert_eq!(summary.total_ciphertext, 40 + 28 * 3);

        // Round-trips back to the original via the core decryptor.
        assert_eq!(decrypt_frames(&mk, file_id, &frames), data);
    }

    #[test]
    fn new_profile_constructor_roundtrip() {
        let mk = kdf::derive_master_key("another-password", b"another-salt-16b").unwrap();
        let mk_bytes = mk.to_bytes();
        let file_id = "wasm-file-2";
        let data = pattern(1000); // < 4 MiB floor => single chunk on any profile

        let mut enc = WasmChunkEncryptor::new(&mk_bytes, file_id.to_string(), data.len() as u64, "web").unwrap();
        assert_eq!(enc.chunk_count(), 1);

        let chunk_size = enc.chunk_size() as usize;
        let mut frames = Vec::new();
        for slice in data.chunks(chunk_size) {
            frames.push(enc.push_chunk(slice).unwrap());
        }
        enc.finish_summary().unwrap();
        assert_eq!(decrypt_frames(&mk, file_id, &frames), data);
    }

    // NOTE: error-path coverage (bad key length, unknown profile, push beyond
    // plan, u32 chunk_count guard) lives in core's `chunk_stream` tests. It is
    // NOT duplicated here because the wrapper's error variant is a `JsError`,
    // whose constructor calls a wasm-bindgen import that panics on a non-wasm
    // host — so an `is_err()` assertion can't run under `cargo test`. The
    // wrapper's error paths are still compile-checked.
}
