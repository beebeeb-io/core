//! Contact safety numbers (relayed-key pinning design, D1/D2) for Swift and
//! Kotlin, so the apps show the same number as web (crypto review,
//! P2-7). The format is `beebeeb_core::contact_keys`, proved by
//! `test-vectors/safety_number.json`.

use beebeeb_core::contact_keys;

use crate::CryptoError;

/// The 60-digit safety number two contacts compare (12 groups of 5, joined).
/// Each email is normalised by core first; keys are the contacts' 32-byte
/// X25519 public keys. The same on both sides whatever the argument order.
#[uniffi::export]
pub fn safety_number(
    email_a: String,
    public_key_a: Vec<u8>,
    email_b: String,
    public_key_b: Vec<u8>,
) -> Result<String, CryptoError> {
    let key = |bytes: Vec<u8>| -> Result<[u8; 32], CryptoError> {
        bytes.try_into().map_err(|_| CryptoError::InvalidInput {
            detail: "public key must be 32 bytes".into(),
        })
    };
    Ok(contact_keys::safety_number(
        &email_a,
        &key(public_key_a)?,
        &email_b,
        &key(public_key_b)?,
    )?)
}

/// An account email in the server's stored form (Rust `str::trim`, then
/// Unicode lower case). Use it for every email that names a contact or a pin.
#[uniffi::export]
pub fn normalize_email(raw: String) -> String {
    contact_keys::normalize_email(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binding_matches_every_safety_number_vector() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../test-vectors/safety_number.json")).unwrap();
        let rows = doc["vectors"].as_array().unwrap();
        assert_eq!(rows.len(), 8);
        for row in rows {
            let field = |name: &str| row[name].as_str().unwrap().to_owned();
            let key = |name: &str| {
                let text = field(name);
                (0..text.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                    .collect::<Vec<u8>>()
            };
            let number = safety_number(
                field("email_a"),
                key("public_key_a_hex"),
                field("email_b"),
                key("public_key_b_hex"),
            )
            .unwrap();
            assert_eq!(number, field("safety_number"), "{}", field("name"));
        }
        assert_eq!(normalize_email("\u{0085}A@B.test\u{00A0}".into()), "a@b.test");
        assert_eq!(normalize_email("\u{FEFF}a@b.test".into()), "\u{FEFF}a@b.test");
        assert!(safety_number("a".into(), vec![0; 31], "b".into(), vec![0; 32]).is_err());
    }
}
