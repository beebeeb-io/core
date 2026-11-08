//! The share safety number: 60 digits two people compare out of band to check that the sharing
//! key each one's app sealed to is the key the other one really holds.
//!
//! The shape is Signal's numeric fingerprint (v1). Per party:
//!
//! ```mermaid
//! flowchart LR
//!   A["h = 0x0000 || key || user_id"] --> B["5200 times: h = SHA-512(h || key)"]
//!   B --> C["h[0..30] as 6 chunks of 5 bytes"]
//!   C --> D["each chunk: big-endian u40 mod 100000, 5 digits"]
//! ```
//!
//! Both parties' 30 digits are joined, the lower user id (byte order) first, so both sides show
//! the same 60 digits (12 groups of 5).
//!
//! `key` is the 32-byte raw X25519 public key the server distributes for that user's sharing key
//! (standard base64 on the wire), the same bytes the member-share seal uses
//! ([`super::seal_file_key_for_member`]). Public keys only: nothing secret goes in or out.
//! `peer_fingerprint` is SHA-256 of the peer's key bytes, which a host stores with its local
//! "compared" mark; a changed peer key no longer matches the mark.
use sha2::{Digest, Sha256, Sha512};

use super::ShareFlowError;

/// Rounds of SHA-512 per party (Signal's numeric fingerprint).
pub const SAFETY_ITERATIONS: usize = 5200;
/// Fingerprint format version, prefixed as two big-endian bytes.
const SAFETY_VERSION: [u8; 2] = [0, 0];
/// Digits in the full safety number.
pub const SAFETY_DIGITS: usize = 60;

/// The number to show and the peer's key fingerprint to keep with a "compared" mark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyNumber {
    /// 60 ASCII digits, no separators. Display as 12 groups of 5.
    pub digits: String,
    /// SHA-256 of the peer's public key bytes.
    pub peer_fingerprint: [u8; 32],
}

impl SafetyNumber {
    /// The digits as 12 groups of 5.
    pub fn groups(&self) -> Vec<&str> {
        (0..12).map(|i| &self.digits[i * 5..i * 5 + 5]).collect()
    }
}

fn key32(bytes: &[u8]) -> Result<&[u8; 32], ShareFlowError> {
    bytes
        .try_into()
        .map_err(|_| ShareFlowError::InvalidInput("public key length"))
}

/// One party's 30 digits.
fn party_digits(user_id: &str, public_key: &[u8; 32]) -> String {
    let mut h: Vec<u8> = Vec::with_capacity(2 + 32 + user_id.len());
    h.extend_from_slice(&SAFETY_VERSION);
    h.extend_from_slice(public_key);
    h.extend_from_slice(user_id.as_bytes());
    for _ in 0..SAFETY_ITERATIONS {
        let mut d = Sha512::new();
        d.update(&h);
        d.update(public_key);
        h = d.finalize().to_vec();
    }
    let mut out = String::with_capacity(30);
    for chunk in h[..30].chunks_exact(5) {
        let v = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        out.push_str(&format!("{:05}", v % 100_000));
    }
    out
}

/// The safety number between the signed-in user and a peer. Both sides compute the same digits.
pub fn safety_number(
    own_user_id: &str,
    own_public_key: &[u8],
    peer_user_id: &str,
    peer_public_key: &[u8],
) -> Result<SafetyNumber, ShareFlowError> {
    if own_user_id.is_empty() || peer_user_id.is_empty() {
        return Err(ShareFlowError::InvalidInput("user id"));
    }
    let own_key = key32(own_public_key)?;
    let peer_key = key32(peer_public_key)?;
    let own = party_digits(own_user_id, own_key);
    let peer = party_digits(peer_user_id, peer_key);
    // Lower user id first; equal ids (never expected) fall back to key order so the result is still symmetric.
    let own_first = (own_user_id.as_bytes(), own_key.as_slice()) <= (peer_user_id.as_bytes(), peer_key.as_slice());
    let digits = if own_first { own + &peer } else { peer + &own };
    Ok(SafetyNumber {
        digits,
        peer_fingerprint: Sha256::digest(peer_key).into(),
    })
}

/// SHA-256 of a public key: the value a "compared" mark is keyed by.
pub fn key_fingerprint(public_key: &[u8]) -> Result<[u8; 32], ShareFlowError> {
    Ok(Sha256::digest(key32(public_key)?).into())
}
