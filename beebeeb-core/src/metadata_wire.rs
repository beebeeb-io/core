//! Encrypted metadata wire format — serialize/parse the JSON envelope.
//!
//! The canonical format is: `{"nonce": "<base64>", "ciphertext": "<base64>"}`.
//!
//! Legacy clients may have stored numeric arrays instead of base64 strings:
//! `{"nonce": [12, 34, ...], "ciphertext": [56, 78, ...]}`.
//! Both formats are accepted on parse; only base64 is emitted on serialize.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use beebeeb_types::CipherSuite;

use crate::CoreError;

/// Serialize a nonce + ciphertext pair into the canonical JSON wire format.
///
/// Output: `{"nonce":"<base64>","ciphertext":"<base64>"}`
pub fn serialize_encrypted_metadata(nonce: &[u8], ciphertext: &[u8]) -> String {
    let obj = serde_json::json!({
        "nonce": B64.encode(nonce),
        "ciphertext": B64.encode(ciphertext),
    });
    obj.to_string()
}

/// Parse a JSON-encoded encrypted metadata payload.
///
/// Accepts two formats:
/// - **Base64 strings** (canonical): `{"nonce":"AAAA...","ciphertext":"BBBB..."}`
/// - **Numeric arrays** (legacy): `{"nonce":[0,1,2,...],"ciphertext":[3,4,5,...]}`
///
/// Returns `(nonce_bytes, ciphertext_bytes)`.
pub fn parse_encrypted_metadata(payload: &str) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let v: serde_json::Value = serde_json::from_str(payload).map_err(|e| CoreError::InvalidInput(e.to_string()))?;

    let nonce = parse_field(&v, "nonce")?;
    let ciphertext = parse_field(&v, "ciphertext")?;

    Ok((nonce, ciphertext))
}

/// Parse a single field that may be either a base64 string or a numeric array.
fn parse_field(obj: &serde_json::Value, field: &str) -> Result<Vec<u8>, CoreError> {
    let val = obj
        .get(field)
        .ok_or_else(|| CoreError::InvalidInput(format!("missing field \"{field}\" in metadata payload")))?;

    match val {
        serde_json::Value::String(s) => B64
            .decode(s)
            .map_err(|e| CoreError::InvalidInput(format!("invalid base64 in field \"{field}\": {e}"))),
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| CoreError::InvalidInput(format!("non-byte value in legacy array field \"{field}\"")))
            })
            .collect(),
        _ => Err(CoreError::InvalidInput(format!(
            "field \"{field}\" must be a base64 string or numeric array"
        ))),
    }
}

/// A decoded metadata envelope, with the wire policy explicit per field.
///
/// Readers accept every stored form (spec move 2, map §5.3): `nonce` and
/// `ciphertext` as base64 strings or numeric arrays, independently; the mobile
/// short keys `n` / `c` when the canonical key is absent; and `cipher_suite`
/// absent, `null` or `"V1Aes256Gcm"`.
///
/// `cipher_suite: None` means the payload did not name one. The only suite is
/// V1, so callers assume it exactly as [`parse_encrypted_metadata`] already
/// does. Naming any other suite is an error, never a silent downgrade. Fields
/// this type does not know are ignored.
///
/// [`MetadataEnvelope::encode`] writes the one canonical form — the frozen
/// base64 writer — and never emits a `cipher_suite`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataEnvelope {
    /// The cipher suite the payload named, if it named one.
    pub cipher_suite: Option<CipherSuite>,
    /// The 12-byte AES-GCM nonce.
    pub nonce: Vec<u8>,
    /// The ciphertext (plaintext plus the 16-byte GCM tag).
    pub ciphertext: Vec<u8>,
}

impl MetadataEnvelope {
    /// Decode any accepted stored form.
    pub fn decode(payload: &str) -> Result<Self, CoreError> {
        let value: serde_json::Value =
            serde_json::from_str(payload).map_err(|e| CoreError::InvalidInput(e.to_string()))?;
        Ok(Self {
            cipher_suite: parse_cipher_suite(&value)?,
            nonce: parse_named_field(&value, "nonce", "n")?,
            ciphertext: parse_named_field(&value, "ciphertext", "c")?,
        })
    }

    /// Encode into the canonical wire format. Delegates to the frozen writer, so
    /// the bytes are identical to [`serialize_encrypted_metadata`].
    ///
    /// Refuses a nonce that is not exactly 12 bytes (AES-GCM's nonce length)
    /// with [`CoreError::InvalidInput`]; anything else would produce a payload
    /// no reader can open.
    ///
    /// # Names, thumbnails and notes are not this pair
    ///
    /// This is the generic envelope: it carries no AAD and no field identity,
    /// so a reader can open a value sealed for one field as if it were
    /// another. New writes keep the fields apart by PURPOSE SUBKEY: one
    /// per-file HKDF subkey per purpose (`beebeeb/name/v1`,
    /// `beebeeb/thumb/v1`, `beebeeb/note/v1`, all in [`crate::encrypt`]), and a
    /// thumbnail additionally seals with an empty AAD.
    ///
    /// Seal a name with [`crate::encrypt::encrypt_name_for_new_item`] (a new
    /// row) or [`crate::encrypt::encrypt_name_for_target`] (an existing row);
    /// a thumbnail with `encrypt_thumbnail_for_new_item` /
    /// `encrypt_thumbnail_for_target`; a note with
    /// `encrypt_note_for_new_item` / `encrypt_note_for_target`.
    /// [`crate::encrypt::encrypt_name`] is `#[deprecated]` for writes. Read
    /// with [`crate::encrypt::decrypt_file_metadata`],
    /// [`crate::encrypt::decrypt_note`] and
    /// [`crate::encrypt::decrypt_thumbnail`] — never through
    /// [`crate::encrypt::decrypt_metadata`], which checks no AAD and cannot
    /// tell which field a value was sealed for.
    pub fn encode(&self) -> Result<String, CoreError> {
        if self.nonce.len() != 12 {
            return Err(CoreError::InvalidInput(format!(
                "metadata nonce must be 12 bytes, got {}",
                self.nonce.len()
            )));
        }
        Ok(serialize_encrypted_metadata(&self.nonce, &self.ciphertext))
    }
}

/// `cipher_suite` is optional: absent or `null` means "the caller assumes V1".
/// A named suite must be one this core version knows.
fn parse_cipher_suite(value: &serde_json::Value) -> Result<Option<CipherSuite>, CoreError> {
    match value.get("cipher_suite") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(named) => serde_json::from_value(named.clone())
            .map(Some)
            .map_err(|e| CoreError::InvalidInput(format!("unsupported cipher_suite: {e}"))),
    }
}

/// Read a field by its canonical name, falling back to the mobile short alias
/// only when the canonical key is absent (so an explicit `null` still errors).
fn parse_named_field(value: &serde_json::Value, canonical: &str, short: &str) -> Result<Vec<u8>, CoreError> {
    if value.get(canonical).is_some() {
        parse_field(value, canonical)
    } else if value.get(short).is_some() {
        parse_field(value, short)
    } else {
        Err(CoreError::InvalidInput(format!(
            "missing field \"{canonical}\" in metadata payload"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_base64() {
        let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let ciphertext = vec![100, 101, 102, 103, 104];

        let json = serialize_encrypted_metadata(&nonce, &ciphertext);
        let (parsed_nonce, parsed_ct) = parse_encrypted_metadata(&json).unwrap();

        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_ct, ciphertext);
    }

    #[test]
    fn parse_legacy_numeric_arrays() {
        let payload = r#"{"nonce":[1,2,3,4,5,6,7,8,9,10,11,12],"ciphertext":[100,101,102]}"#;
        let (nonce, ct) = parse_encrypted_metadata(payload).unwrap();
        assert_eq!(nonce, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(ct, vec![100, 101, 102]);
    }

    #[test]
    fn parse_mixed_formats() {
        // nonce as base64, ciphertext as legacy array
        let nonce_b64 = B64.encode([1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let payload = format!(r#"{{"nonce":"{}","ciphertext":[100,101,102]}}"#, nonce_b64);
        let (nonce, ct) = parse_encrypted_metadata(&payload).unwrap();
        assert_eq!(nonce, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(ct, vec![100, 101, 102]);
    }

    #[test]
    fn serialize_produces_valid_json() {
        let json = serialize_encrypted_metadata(&[0xAA; 12], &[0xBB; 32]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("nonce").unwrap().is_string());
        assert!(v.get("ciphertext").unwrap().is_string());
    }

    #[test]
    fn parse_missing_field_errors() {
        let payload = r#"{"nonce":"AAAA"}"#;
        assert!(parse_encrypted_metadata(payload).is_err());
    }

    #[test]
    fn parse_invalid_base64_errors() {
        let payload = r#"{"nonce":"!!!invalid!!!","ciphertext":"AAAA"}"#;
        assert!(parse_encrypted_metadata(payload).is_err());
    }

    #[test]
    fn parse_invalid_json_errors() {
        assert!(parse_encrypted_metadata("not json at all").is_err());
    }

    #[test]
    fn parse_legacy_out_of_range_byte_errors() {
        let payload = r#"{"nonce":[256],"ciphertext":[0]}"#;
        assert!(parse_encrypted_metadata(payload).is_err());
    }

    #[test]
    fn empty_data_roundtrip() {
        let json = serialize_encrypted_metadata(&[], &[]);
        let (nonce, ct) = parse_encrypted_metadata(&json).unwrap();
        assert!(nonce.is_empty());
        assert!(ct.is_empty());
    }
}
