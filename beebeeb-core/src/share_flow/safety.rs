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
//! (standard base64 on the wire, bit 255 clear, never a small-order point), the same bytes the member-share seal uses
//! ([`super::member::approve_request`]). Public keys only: nothing secret goes in or out.
//! `peer_fingerprint` is SHA-256 of the peer's key bytes, which a host stores with its local
//! "compared" mark; a changed peer key no longer matches the mark.
use sha2::{Digest, Sha256, Sha512};

use super::ShareFlowError;
use crate::item_id::parse_canonical;
use crate::kdf::MasterKey;
use crate::opaque::{derive_x25519_private, derive_x25519_public};

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

/// A sharing public key as the seal accepts it: 32 bytes, bit 255 clear (canonical X25519 encoding),
/// and not a small-order point (the seal refuses those as non-contributory).
pub(crate) fn sharing_key(bytes: &[u8]) -> Result<[u8; 32], ShareFlowError> {
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ShareFlowError::InvalidInput("public key length"))?;
    if key[31] & 0x80 != 0 {
        return Err(ShareFlowError::InvalidInput("public key encoding"));
    }
    // A clamped scalar is a multiple of 8, so any fixed one sends a small-order point to the
    // identity: the same `was_contributory` rule `x25519_shared_secret` applies to the seal.
    let probe = x25519_dalek::StaticSecret::from([0x5a; 32]);
    if !probe
        .diffie_hellman(&x25519_dalek::PublicKey::from(key))
        .was_contributory()
    {
        return Err(ShareFlowError::InvalidInput("public key small order"));
    }
    Ok(key)
}

fn user_id(id: &str) -> Result<(), ShareFlowError> {
    parse_canonical(id)
        .map(|_| ())
        .map_err(|_| ShareFlowError::InvalidInput("user id"))
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

/// The safety number between the signed-in user and a peer. The own sharing key is derived here
/// from the master key (`derive_x25519_public(derive_x25519_private(master))`), never taken from
/// a host or the server. `peer_public_key` must be the exact bytes the share was sealed to (the
/// `recipient_public_key` a member seal returns). Both sides compute the same digits.
pub fn safety_number(
    master: &MasterKey,
    own_user_id: &str,
    peer_user_id: &str,
    peer_public_key: &[u8],
) -> Result<SafetyNumber, ShareFlowError> {
    let own_key = derive_x25519_public(&derive_x25519_private(master));
    safety_number_for_keys(own_user_id, &own_key, peer_user_id, peer_public_key)
}

/// [`safety_number`] over two given keys: the vector form (`test-vectors/safety_number.json`).
/// User ids are canonical lowercase hyphenated UUIDs and must differ.
pub(crate) fn safety_number_for_keys(
    own_user_id: &str,
    own_public_key: &[u8],
    peer_user_id: &str,
    peer_public_key: &[u8],
) -> Result<SafetyNumber, ShareFlowError> {
    user_id(own_user_id)?;
    user_id(peer_user_id)?;
    if own_user_id == peer_user_id {
        return Err(ShareFlowError::InvalidInput("own user id equals peer user id"));
    }
    let own_key = sharing_key(own_public_key)?;
    let peer_key = sharing_key(peer_public_key)?;
    let own = party_digits(own_user_id, &own_key);
    let peer = party_digits(peer_user_id, &peer_key);
    // Lower user id (byte order) first; the ids are distinct, so this is a strict order.
    let digits = if own_user_id.as_bytes() < peer_user_id.as_bytes() {
        own + &peer
    } else {
        peer + &own
    };
    Ok(SafetyNumber {
        digits,
        peer_fingerprint: Sha256::digest(peer_key).into(),
    })
}

/// SHA-256 of a public key: the value a "compared" mark is keyed by.
pub fn key_fingerprint(public_key: &[u8]) -> Result<[u8; 32], ShareFlowError> {
    Ok(Sha256::digest(sharing_key(public_key)?).into())
}
