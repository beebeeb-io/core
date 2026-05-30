//! Encrypted metadata wire format — serialize/parse the JSON envelope.
//!
//! The canonical format is: `{"nonce": "<base64>", "ciphertext": "<base64>"}`.
//!
//! Legacy clients may have stored numeric arrays instead of base64 strings:
//! `{"nonce": [12, 34, ...], "ciphertext": [56, 78, ...]}`.
//! Both formats are accepted on parse; only base64 is emitted on serialize.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

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
