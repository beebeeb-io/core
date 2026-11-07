//! Streaming chunk decryption (push form), task 1908. Moved out of `lib.rs`
//! when the constructors began to take the decrypted metadata (core #74 crypto
//! review, P2-4).

use beebeeb_core::chunk_stream::{ChunkDecryptor, ExpectedChunkFormat, VersionCommitment};
use beebeeb_core::kdf;
use wasm_bindgen::prelude::*;

use crate::{expected_from_u8, file_key_from_slice, master_key_from_slice, version_commitment_from_js};

/// The fields of `decrypt_file_metadata(...)` a content reader needs. Pass the
/// whole object that function returned: `{ chunk_format, version_id,
/// version_counter }` (`version_id` as its 24 hex digits).
#[derive(serde::Deserialize)]
pub(crate) struct DecryptorMetadataJs {
    pub(crate) chunk_format: u8,
    #[serde(default)]
    pub(crate) version_id: Option<String>,
    #[serde(default)]
    pub(crate) version_counter: Option<f64>,
}

/// The format pin and version commitment a decryptor enforces. A record with
/// a commitment binds frame 0 to it; a record with neither field is legacy
/// metadata, readable but unprotected (core's compatibility rule); a record
/// with only one of the two is refused.
pub(crate) fn metadata_pin(
    metadata: &DecryptorMetadataJs,
) -> Result<(ExpectedChunkFormat, Option<VersionCommitment>), String> {
    let expected = ExpectedChunkFormat::from_u8(metadata.chunk_format).map_err(|e| e.to_string())?;
    let version = match (&metadata.version_id, metadata.version_counter) {
        (None, None) => None,
        (Some(id), Some(counter)) => {
            let bytes = decode_version_id(id).ok_or("version_id must be 24 hex digits")?;
            if !counter.is_finite()
                || counter.fract() != 0.0
                || counter < 1.0
                || counter > beebeeb_core::chunk_stream::MAX_VERSION_COUNTER as f64
            {
                return Err("version_counter must be a positive safe integer".into());
            }
            Some(VersionCommitment::new(bytes, counter as u64).map_err(|e| e.to_string())?)
        }
        _ => return Err("version_id and version_counter must be supplied together".into()),
    };
    Ok((expected, version))
}

fn decode_version_id(text: &str) -> Option<[u8; 12]> {
    if text.len() != 24 || !text.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; 12];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(bytes)
}

fn metadata_from_js(metadata: JsValue) -> Result<(ExpectedChunkFormat, Option<VersionCommitment>), JsError> {
    if metadata.is_undefined() || metadata.is_null() {
        return Err(JsError::new(
            "metadata is required: pass what decrypt_file_metadata returned",
        ));
    }
    let metadata: DecryptorMetadataJs = serde_wasm_bindgen::from_value(metadata)
        .map_err(|_| JsError::new("metadata must be what decrypt_file_metadata returned"))?;
    metadata_pin(&metadata).map_err(|e| JsError::new(&e))
}

/// Stateful, single-file streaming decryptor for the web client — the ONE way
/// web should decrypt file content (downloads, previews, shared links).
///
/// Reads v2 (position-bound) and v1 (legacy) files. Both constructors take the
/// object `decrypt_file_metadata(...)` returned for the version being read
/// (task 1908, core #74 P2-4): its `chunk_format` (0 = unrecorded, 2 = v2) and,
/// when the record carries one, its version commitment, which frame 0 must
/// match, so the server cannot serve another upload in its place. A missing
/// object, or one with only half a commitment, is refused; a legacy record
/// with no commitment stays readable but unprotected. In v2 every frame must
/// be the next chunk in order and from the same upload as chunk 0, and nothing
/// may follow the last one; [`finish`] fails if the file ended before its last
/// chunk (truncation). JS must treat any thrown error — from `pushFrame` or
/// `finish` — as a failed download and discard the plaintext it has buffered.
///
/// Replaces the per-chunk `decrypt_chunk(fileKey, nonce, ciphertext)` loop for
/// file content: that generic function has no position and can only open v1
/// frames (it stays for key unwrapping).
///
/// [`finish`]: Self::finish
#[wasm_bindgen]
pub struct WasmChunkDecryptor {
    pub(crate) inner: ChunkDecryptor,
}

#[wasm_bindgen]
impl WasmChunkDecryptor {
    /// Decryptor for the owner: the file key is derived in core from the
    /// 32-byte master key and `file_id`. `metadata` is what
    /// `decrypt_file_metadata` returned for this version.
    #[wasm_bindgen(constructor)]
    pub fn new(master_key: &[u8], file_id: String, metadata: JsValue) -> Result<WasmChunkDecryptor, JsError> {
        let mk = master_key_from_slice(master_key)?;
        let (expected, version) = metadata_from_js(metadata)?;
        Ok(Self::with_pin(
            kdf::derive_file_key(&mk, file_id.as_bytes()),
            &file_id,
            expected,
            version,
        ))
    }

    /// Decryptor from an already-unwrapped 32-byte file key (share / shared-link
    /// recipients). `file_id` must be the id the file was uploaded under;
    /// `metadata` is what `decrypt_file_metadata_with_key` returned.
    #[wasm_bindgen(js_name = fromFileKey)]
    pub fn from_file_key(file_key: &[u8], file_id: String, metadata: JsValue) -> Result<WasmChunkDecryptor, JsError> {
        let fk = file_key_from_slice(file_key)?;
        let (expected, version) = metadata_from_js(metadata)?;
        Ok(Self::with_pin(fk, &file_id, expected, version))
    }

    /// Protected current or historical read. Supply the fields from that
    /// version's own decrypted metadata record.
    #[wasm_bindgen(js_name = forVersion)]
    pub fn for_version(
        master_key: &[u8],
        file_id: String,
        expected_chunk_format: u8,
        version_id: &[u8],
        version_counter: f64,
    ) -> Result<WasmChunkDecryptor, JsError> {
        let mk = master_key_from_slice(master_key)?;
        let expected = expected_from_u8(expected_chunk_format)?;
        let version = version_commitment_from_js(version_id, version_counter)?;
        let file_key = kdf::derive_file_key(&mk, file_id.as_bytes());
        Ok(Self::with_pin(file_key, &file_id, expected, Some(version)))
    }

    /// v2: the upload's version id (chunk 0's 12-byte nonce) once chunk 0 has
    /// authenticated — what a seeking reader passes to `decrypt_chunk_frame`.
    /// `undefined` before chunk 0 and for v1 files.
    #[wasm_bindgen(getter, js_name = versionId)]
    pub fn version_id(&self) -> Option<Vec<u8>> {
        self.inner.version_id().map(|v| v.to_vec())
    }

    /// Decrypt the next wire frame (`nonce(12) || ciphertext || tag(16)`),
    /// returning its plaintext. Frames must be pushed in order from chunk 0.
    #[wasm_bindgen(js_name = pushFrame)]
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .push_frame(frame)
            .map(|c| c.data)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// The file's chunk format once chunk 0 has been opened: 1 = v1, 2 = v2;
    /// 0 before the first frame.
    #[wasm_bindgen(getter)]
    pub fn format(&self) -> u8 {
        self.inner.format().map(|f| f.as_u8()).unwrap_or(0)
    }

    /// How many frames have been decrypted so far.
    #[wasm_bindgen(getter, js_name = chunksDecrypted)]
    pub fn chunks_decrypted(&self) -> u32 {
        self.inner.chunks_decrypted()
    }

    /// Consume the decryptor and run the end-of-stream check. Throws if no frame
    /// was pushed or a v2 file ended before its last chunk. Returns
    /// `{ chunk_count, format }`.
    pub fn finish(self) -> Result<JsValue, JsError> {
        let summary = self.inner.finish().map_err(|e| JsError::new(&e.to_string()))?;
        #[derive(serde::Serialize)]
        struct DecryptSummaryJs {
            chunk_count: u32,
            format: u8,
        }
        Ok(serde_wasm_bindgen::to_value(&DecryptSummaryJs {
            chunk_count: summary.chunk_count,
            format: summary.format.as_u8(),
        })?)
    }
}

impl WasmChunkDecryptor {
    /// The one construction path: every constructor applies the record's
    /// commitment when it has one.
    pub(crate) fn with_pin(
        file_key: kdf::FileKey,
        file_id: &str,
        expected: ExpectedChunkFormat,
        version: Option<VersionCommitment>,
    ) -> Self {
        Self {
            inner: ChunkDecryptor::for_version_with_file_key(file_key, file_id, expected, version),
        }
    }
}

#[cfg(test)]
mod tests;
