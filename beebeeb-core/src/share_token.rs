//! Canonical share-token generator (task 0708).
//!
//! A share token is the public, unguessable identifier in a share URL
//! (`/s/<token>`). It is NOT key material — it's a random opaque id — but with
//! the A1 owner-recoverable flow the *client* generates it (so it can wrap it
//! under the owner's master key before sending). It therefore MUST be generated
//! in a format the server's A1 validator accepts: `SHARE_TOKEN_BYTES` of OS
//! randomness, URL-safe base64 **without padding** (27 chars for 20 bytes).
//!
//! This is the single canonical implementation: web consumes it via WASM,
//! mobile via UniFFI. The server keeps its own byte-identical-format generator
//! for the legacy server-generates path; tests on both sides pin the format
//! identical (server `is_valid_share_token` decodes → 20 bytes; see task 0708).

use base64::Engine;
use rand::RngCore;

/// Random bytes behind a share token (160 bits — unguessable).
pub const SHARE_TOKEN_BYTES: usize = 20;

/// Generate a fresh share token: [`SHARE_TOKEN_BYTES`] of OS randomness encoded
/// as URL-safe base64 with no padding (27 chars). `OsRng` is the cryptographic
/// OS RNG (on wasm it is browser crypto via getrandom's `js` feature, matching
/// the rest of this crate's nonce/keypair generation).
pub fn generate_share_token() -> String {
    let mut bytes = [0u8; SHARE_TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_27char_urlsafe_nopad_of_20_bytes() {
        for _ in 0..100 {
            let t = generate_share_token();
            assert_eq!(t.len(), 27, "20 bytes url-safe-no-pad base64 == 27 chars");
            assert!(
                t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "url-safe charset only (no '+' '/' '='): {t}"
            );
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&t)
                .expect("token must be valid url-safe-no-pad base64");
            assert_eq!(decoded.len(), SHARE_TOKEN_BYTES, "decodes to exactly 20 bytes");
        }
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(generate_share_token(), generate_share_token());
    }
}
