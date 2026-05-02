//! X25519 key exchange + HKDF derivations for the transfer channel.
//!
//! Both devices generate an ephemeral X25519 keypair, exchange public keys
//! through the relay, and ECDH to a shared 32-byte secret. The transfer key
//! and the 4-byte SAS material are both HKDF-SHA256 expansions of that
//! shared secret, salted with the 16-byte session id. The session id is
//! mixed in via `salt` (not `info`) so that two transfers between the same
//! pair of fresh ephemeral keys would still derive distinct keys.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use super::wordlist::WORDLIST;

const TRANSFER_KEY_INFO: &[u8] = b"beebeeb-transfer-v1";
const SAS_INFO: &[u8] = b"beebeeb-sas-v1";

/// Ephemeral X25519 keypair. The secret is consumed by [`derive_shared_secret`]
/// and zeroized when dropped — `EphemeralSecret` is intentionally not `Clone`.
pub struct TransferKeypair {
    pub secret: EphemeralSecret,
    pub public: PublicKey,
}

/// Generate a fresh ephemeral X25519 keypair.
pub fn generate_keypair() -> TransferKeypair {
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    TransferKeypair { secret, public }
}

/// Compute the X25519 ECDH shared secret. The local secret is consumed.
pub fn derive_shared_secret(my_secret: EphemeralSecret, their_public: &PublicKey) -> [u8; 32] {
    let shared = my_secret.diffie_hellman(their_public);
    *shared.as_bytes()
}

/// Derive the 32-byte AES-256 transfer key:
/// `HKDF-SHA256(ikm = shared_secret, salt = session_id, info = "beebeeb-transfer-v1")`.
pub fn derive_transfer_key(shared_secret: &[u8; 32], session_id: &[u8; 16]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(session_id), shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(TRANSFER_KEY_INFO, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    *okm
}

/// Derive the 4-byte Short Authenticated String material from the same
/// shared secret using a different `info` tag. Both devices computing the
/// same words is the MITM check.
pub fn derive_sas(shared_secret: &[u8; 32], session_id: &[u8; 16]) -> [u8; 4] {
    let hk = Hkdf::<Sha256>::new(Some(session_id), shared_secret);
    let mut okm = [0u8; 4];
    hk.expand(SAS_INFO, &mut okm)
        .expect("HKDF-SHA256 expand for 4 bytes cannot fail");
    okm
}

/// Map the 4 SAS bytes to 4 words from the 256-word wordlist (1 byte per word).
pub fn sas_to_words(sas_bytes: &[u8; 4]) -> [String; 4] {
    [
        WORDLIST[sas_bytes[0] as usize].to_string(),
        WORDLIST[sas_bytes[1] as usize].to_string(),
        WORDLIST[sas_bytes[2] as usize].to_string(),
        WORDLIST[sas_bytes[3] as usize].to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_exchange_roundtrip_yields_same_shared_secret() {
        let alice = generate_keypair();
        let bob = generate_keypair();

        let alice_pub = alice.public;
        let bob_pub = bob.public;

        let alice_shared = derive_shared_secret(alice.secret, &bob_pub);
        let bob_shared = derive_shared_secret(bob.secret, &alice_pub);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn fresh_keypairs_yield_different_shared_secrets() {
        let alice1 = generate_keypair();
        let bob1 = generate_keypair();
        let alice2 = generate_keypair();
        let bob2 = generate_keypair();

        let bob1_pub = bob1.public;
        let bob2_pub = bob2.public;

        let s1 = derive_shared_secret(alice1.secret, &bob1_pub);
        let s2 = derive_shared_secret(alice2.secret, &bob2_pub);

        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_transfer_key_is_deterministic() {
        let shared = [0x42u8; 32];
        let session_id = [0x07u8; 16];
        let k1 = derive_transfer_key(&shared, &session_id);
        let k2 = derive_transfer_key(&shared, &session_id);
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_transfer_key_changes_with_session_id() {
        let shared = [0x42u8; 32];
        let id1 = [0x01u8; 16];
        let id2 = [0x02u8; 16];
        assert_ne!(derive_transfer_key(&shared, &id1), derive_transfer_key(&shared, &id2));
    }

    #[test]
    fn transfer_key_and_sas_use_different_info_tags() {
        // Same shared/session — but transfer-key bytes must not collide with SAS bytes
        let shared = [0x42u8; 32];
        let session_id = [0x07u8; 16];
        let tk = derive_transfer_key(&shared, &session_id);
        let sas = derive_sas(&shared, &session_id);
        assert_ne!(&tk[..4], &sas[..]);
    }

    #[test]
    fn sas_is_deterministic() {
        let shared = [0xAAu8; 32];
        let session_id = [0x55u8; 16];
        let s1 = derive_sas(&shared, &session_id);
        let s2 = derive_sas(&shared, &session_id);
        assert_eq!(s1, s2);
    }

    #[test]
    fn sas_changes_with_session_id() {
        let shared = [0xAAu8; 32];
        let id1 = [0x01u8; 16];
        let id2 = [0x02u8; 16];
        assert_ne!(derive_sas(&shared, &id1), derive_sas(&shared, &id2));
    }

    #[test]
    fn sas_changes_with_shared_secret() {
        let s1 = [0x01u8; 32];
        let s2 = [0x02u8; 32];
        let session_id = [0x07u8; 16];
        assert_ne!(derive_sas(&s1, &session_id), derive_sas(&s2, &session_id));
    }

    #[test]
    fn sas_to_words_yields_four_lowercase_words() {
        let words = sas_to_words(&[0, 1, 2, 3]);
        assert_eq!(words.len(), 4);
        for w in &words {
            assert!(!w.is_empty());
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn sas_to_words_indexes_full_byte_range() {
        let lo = sas_to_words(&[0, 0, 0, 0]);
        let hi = sas_to_words(&[255, 255, 255, 255]);
        assert_ne!(lo, hi);
        // first/last entries must be different
        assert_ne!(lo[0], hi[0]);
    }
}
