//! Pure contact-key fingerprints, safety numbers, and pin comparisons.

use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::CoreError;

pub(crate) const KEY_FINGERPRINT_DOMAIN: &[u8] = b"beebeeb/contact-key/fingerprint/v1";
/// Prefix of each party's safety-number input (relayed-key pinning design, D2).
pub(crate) const SAFETY_NUMBER_DOMAIN: &[u8] = b"beebeeb-safety-number-v1";
/// SHA-512 rounds per party, as in Signal: each try at grinding a key whose
/// number matches costs this many hashes.
pub const SAFETY_NUMBER_ROUNDS: u32 = 5200;

/// The result of comparing a presented contact-key fingerprint with a pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinCheck {
    /// No fingerprint has been pinned yet.
    New,
    /// The presented fingerprint matches the existing pin.
    Unchanged,
    /// The presented fingerprint differs from the existing pin.
    Changed,
}

/// Fingerprint a public key under the contact-key domain.
pub fn key_fingerprint(public_key: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KEY_FINGERPRINT_DOMAIN);
    hash.update(public_key);
    hash.finalize().into()
}

/// An account email in the server's stored form: trim, then Unicode lower case.
///
/// No IDNA and no provider rewriting, so two addresses the server keeps apart
/// as two accounts stay apart here too.
///
/// **The trim is Rust's `str::trim`, pinned:** it strips the Unicode
/// `White_Space` characters (U+0009-U+000D, U+0020, U+0085, U+00A0, U+1680,
/// U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, U+3000) and nothing else, as
/// the server's `canonical_email` does. JavaScript's `String.prototype.trim`
/// differs (it strips U+FEFF and keeps U+0085), so a web client calls this
/// function through WASM (`normalizeEmail`, `safetyNumber`) and never trims an
/// email itself. `test-vectors/contact_safety_number.json` holds a row for each side
/// of the difference.
pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Derive the safety number two contacts compare out of band.
///
/// Each email is normalized first ([`normalize_email`]). Per party, the input
/// is `"beebeeb-safety-number-v1" || u32_be(len(email)) || email || public_key`;
/// it is hashed [`SAFETY_NUMBER_ROUNDS`] times as `h = SHA-512(h || public_key)`,
/// and the first 30 bytes of the result, as six 5-byte chunks each taken as
/// `u40_be mod 100000`, give 30 digits. The two parties' digits are sorted and
/// joined, so both sides get the same 60 digits, shown as 12 groups of 5.
///
/// Only public data goes in; the digits are display material, not a key. An
/// email longer than `u32::MAX` bytes is `InvalidInput`.
pub fn safety_number(
    email_a: &str,
    public_key_a: &[u8; 32],
    email_b: &str,
    public_key_b: &[u8; 32],
) -> Result<String, CoreError> {
    let a = safety_number_half(email_a, public_key_a)?;
    let b = safety_number_half(email_b, public_key_b)?;
    Ok(if a <= b { a + &b } else { b + &a })
}

fn safety_number_half(email: &str, public_key: &[u8; 32]) -> Result<String, CoreError> {
    let email = normalize_email(email);
    let length =
        u32::try_from(email.len()).map_err(|_| CoreError::InvalidInput("safety number: email is too long".into()))?;
    let mut input = Vec::with_capacity(SAFETY_NUMBER_DOMAIN.len() + 4 + email.len() + public_key.len());
    input.extend_from_slice(SAFETY_NUMBER_DOMAIN);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(email.as_bytes());
    input.extend_from_slice(public_key);
    // Signal's iteration: every round hashes the previous value with the key
    // appended, starting from the input itself.
    let mut hash = Sha512::new().chain_update(&input).chain_update(public_key).finalize();
    for _ in 1..SAFETY_NUMBER_ROUNDS {
        hash = Sha512::new().chain_update(hash).chain_update(public_key).finalize();
    }
    let mut digits = String::with_capacity(30);
    for chunk in hash[..30].chunks_exact(5) {
        let value = chunk.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        digits.push_str(&format!("{:05}", value % 100_000));
    }
    Ok(digits)
}

/// Compare a presented fingerprint with an optional remembered pin.
///
/// This function performs no storage. Callers persist a new pin only after
/// applying their own first-use or changed-key policy.
pub fn check_pin(remembered: Option<&[u8; 32]>, presented: &[u8; 32]) -> PinCheck {
    match remembered {
        None => PinCheck::New,
        Some(pin) if bool::from(pin.ct_eq(presented)) => PinCheck::Unchanged,
        Some(_) => PinCheck::Changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct SafetyNumberVectors {
        domain: String,
        rounds: u32,
        vectors: Vec<SafetyNumberVector>,
    }

    #[derive(serde::Deserialize)]
    struct SafetyNumberVector {
        name: String,
        email_a: String,
        public_key_a_hex: String,
        email_b: String,
        public_key_b_hex: String,
        party_a: String,
        party_b: String,
        safety_number: String,
    }

    fn key(hex_text: &str) -> [u8; 32] {
        hex::decode(hex_text).unwrap().try_into().unwrap()
    }

    #[test]
    fn safety_number_matches_the_independent_vectors() {
        let doc: SafetyNumberVectors =
            serde_json::from_str(include_str!("../../test-vectors/contact_safety_number.json")).unwrap();
        assert_eq!(doc.domain.as_bytes(), SAFETY_NUMBER_DOMAIN);
        assert_eq!(doc.rounds, SAFETY_NUMBER_ROUNDS);
        assert_eq!(doc.vectors.len(), 8);
        for row in &doc.vectors {
            let (a, b) = (key(&row.public_key_a_hex), key(&row.public_key_b_hex));
            assert_eq!(
                safety_number_half(&row.email_a, &a).unwrap(),
                row.party_a,
                "{}: party a",
                row.name
            );
            assert_eq!(
                safety_number_half(&row.email_b, &b).unwrap(),
                row.party_b,
                "{}: party b",
                row.name
            );
            let number = safety_number(&row.email_a, &a, &row.email_b, &b).unwrap();
            assert_eq!(number, row.safety_number, "{}: pair", row.name);
            assert_eq!(
                safety_number(&row.email_b, &b, &row.email_a, &a).unwrap(),
                number,
                "{}: both sides see the same number",
                row.name
            );
            assert_eq!(number.len(), 60);
            assert!(number.bytes().all(|digit| digit.is_ascii_digit()));
        }
        let by_name = |name: &str| &doc.vectors.iter().find(|row| row.name == name).unwrap().safety_number;
        assert_eq!(by_name("typed_forms_normalize"), by_name("ascii"));
        assert_ne!(by_name("other_email_same_key"), by_name("ascii"));
        assert_ne!(by_name("other_key_same_email"), by_name("ascii"));
        // The pinned trim: Unicode White_Space goes, U+FEFF stays.
        assert_eq!(by_name("nel_and_nbsp_are_trimmed"), by_name("ascii"));
        assert_ne!(by_name("bom_is_kept"), by_name("ascii"));
        assert_eq!(normalize_email("\u{0085}A@B.test\u{00A0}"), "a@b.test");
        assert_eq!(normalize_email("\u{FEFF}a@b.test"), "\u{FEFF}a@b.test");
    }

    #[test]
    fn pin_checks_are_pure() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let fingerprint = key_fingerprint(&alice);
        assert_eq!(check_pin(None, &fingerprint), PinCheck::New);
        assert_eq!(check_pin(Some(&fingerprint), &fingerprint), PinCheck::Unchanged);
        assert_eq!(check_pin(Some(&key_fingerprint(&bob)), &fingerprint), PinCheck::Changed);
    }
}
