//! Amber Constellation — open-source visual auth codec.
//!
//! Encodes a small ephemeral pairing payload as an animated 3D "constellation"
//! of amber nodes and edges. The pattern is designed to be conveyed visually
//! between two devices (display ↔ camera) during the pairing flow.
//!
//! Security comes from ephemeral keys plus a 6-digit confirmation code, **not**
//! from hiding the algorithm — every part of this module is public.
//!
//! ## Layout
//!
//! - [`frame`]    — public types ([`ConstellationPayload`], [`ConstellationFrame`], …)
//! - [`geometry`] — deterministic node positions on twin fibonacci spheres
//! - [`encoder`]  — payload → Reed-Solomon shards → per-frame brightness pattern
//! - [`decoder`]  — observed brightnesses → recovered payload (stateful)

pub mod decoder;
pub mod encoder;
pub mod frame;
pub mod geometry;

pub use decoder::ConstellationDecoder;
pub use encoder::constellation_encode;
pub use frame::{
    ConstellationEdge, ConstellationFrame, ConstellationNode, ConstellationPayload,
    ConstellationSessionInit, ObservedEdge, ObservedNode,
};

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use std::time::{SystemTime, UNIX_EPOCH};

/// Hash a 6-digit confirmation code into the 32 bytes stored in the payload.
///
/// Uses SHA-256 over `domain_tag || code_bytes` so the hash is bound to this
/// codec and not interchangeable with an arbitrary digest of the digits.
pub fn hash_confirm_code(code: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"beebeeb.constellation.confirm.v1\0");
    h.update(code.as_bytes());
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Verify a user-entered code against the hash inside a payload.
pub fn constellation_verify_code(payload: &ConstellationPayload, code: &str) -> bool {
    use subtle_compare::compare;
    let h = hash_confirm_code(code);
    compare(&h, &payload.confirm_code_hash)
}

mod subtle_compare {
    /// Constant-time byte comparison.
    pub fn compare(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

/// Generate a fresh pairing session: ephemeral X25519 keypair + 6-digit
/// confirmation code + the payload to display.
///
/// `expires_in_secs` is added to the current wall clock to set
/// `expires_at_unix_ms`. The displaying device should reject incoming
/// pairings whose payload has expired.
pub fn constellation_new_session(expires_in_secs: u32) -> ConstellationSessionInit {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    // Six-digit numeric code (zero-padded). 1_000_000 outcomes — plenty of
    // entropy when combined with the 5-minute session expiry.
    let mut code_bytes = [0u8; 4];
    OsRng.fill_bytes(&mut code_bytes);
    let code_value = u32::from_le_bytes(code_bytes) % 1_000_000;
    let confirm_code = format!("{:06}", code_value);
    let confirm_code_hash = hash_confirm_code(&confirm_code);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let expires_at_unix_ms = now_ms.saturating_add((expires_in_secs as u64) * 1000);

    let payload = ConstellationPayload {
        session_id,
        ephemeral_pubkey: public.to_bytes(),
        nonce,
        expires_at_unix_ms,
        confirm_code_hash,
    };

    ConstellationSessionInit {
        payload,
        confirm_code,
        ephemeral_private: private.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_valid() {
        let init = constellation_new_session(300);
        assert_eq!(init.confirm_code.len(), 6);
        assert!(init.confirm_code.chars().all(|c| c.is_ascii_digit()));
        assert!(init.payload.expires_at_unix_ms > 0);
        assert_ne!(init.ephemeral_private, [0u8; 32]);
        assert_ne!(init.payload.ephemeral_pubkey, [0u8; 32]);
    }

    #[test]
    fn confirm_code_verifies() {
        let init = constellation_new_session(60);
        assert!(constellation_verify_code(&init.payload, &init.confirm_code));
        assert!(!constellation_verify_code(&init.payload, "000000"));
        assert!(!constellation_verify_code(&init.payload, ""));
    }

    #[test]
    fn distinct_sessions_differ() {
        let a = constellation_new_session(60);
        let b = constellation_new_session(60);
        assert_ne!(a.payload.session_id, b.payload.session_id);
        assert_ne!(a.confirm_code, b.confirm_code);
        assert_ne!(a.payload.ephemeral_pubkey, b.payload.ephemeral_pubkey);
    }

    #[test]
    fn full_pairing_roundtrip() {
        // Display side: create session
        let init = constellation_new_session(300);

        // Scanner side: feed encoded frames (clean, no noise) into decoder
        let decoder = ConstellationDecoder::new();
        let mut recovered = None;
        for frame_index in 0..16u32 {
            let frame = constellation_encode(&init.payload, frame_index);
            let obs: Vec<ObservedNode> = frame
                .nodes
                .iter()
                .enumerate()
                .map(|(i, n)| ObservedNode {
                    idx: i as u32,
                    brightness: n.brightness,
                    confidence: 1.0,
                })
                .collect();
            recovered = decoder.ingest_frame(&obs);
            if recovered.is_some() {
                break;
            }
        }

        let recovered = recovered.expect("scanner recovers payload");
        assert_eq!(recovered, init.payload);

        // Scanner enters the code shown on the display
        assert!(constellation_verify_code(&recovered, &init.confirm_code));
    }
}
