//! One-time proof that a client holds the account master key.
//!
//! This module is pure apart from OS randomness when a challenge is created.
//! It performs no storage or network I/O. A verifier is consumed by its only
//! verification attempt, so challenge state cannot be reused accidentally.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::CoreError;
use crate::kdf::MasterKey;

pub(crate) const KEY_INFO: &[u8] = b"beebeeb/key-proof/mac-key/v1";
pub(crate) const TRANSCRIPT_DOMAIN: &[u8] = b"beebeeb/key-proof/transcript/v1";
const ACCOUNT_KEY_INFO: &[u8] = b"beebeeb-x25519-identity";
const NONCE_LEN: usize = 32;
pub const SERIALIZED_VERIFIER_LEN: usize = 64;

type HmacSha256 = Hmac<Sha256>;

/// The purpose and injectively encoded account binding of a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProofBinding<'a> {
    Session { session_id: &'a [u8], account_id: &'a [u8] },
    Recovery { canonical_email: &'a [u8] },
}

/// Public half of a one-time server challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyProofChallenge {
    nonce: [u8; NONCE_LEN],
    server_public: [u8; 32],
}

impl KeyProofChallenge {
    pub fn from_parts(nonce: [u8; NONCE_LEN], server_public: [u8; 32]) -> Self {
        Self { nonce, server_public }
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn server_public(&self) -> &[u8; 32] {
        &self.server_public
    }
}

/// Opaque server state for exactly one verification attempt.
pub struct KeyProofVerifier {
    server_private: Zeroizing<[u8; 32]>,
    challenge: KeyProofChallenge,
}

impl std::fmt::Debug for KeyProofVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyProofVerifier([REDACTED])")
    }
}

/// A public authentication tag. It contains no account or ephemeral key.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyProofResponse {
    tag: [u8; 32],
}

impl KeyProofResponse {
    pub fn from_bytes(tag: [u8; 32]) -> Self {
        Self { tag }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.tag
    }
}

impl std::fmt::Debug for KeyProofResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyProofResponse([REDACTED])")
    }
}

/// Create a fresh one-time X25519 challenge and its opaque verifier state.
pub fn create_challenge() -> Result<(KeyProofChallenge, KeyProofVerifier), CoreError> {
    let mut private = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut *private)
        .and_then(|_| rand::rngs::OsRng.try_fill_bytes(&mut nonce))
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    challenge_from_parts(*private, nonce)
}

/// Answer a challenge from an opaque master-key handle.
pub fn answer_challenge(
    master_key: &MasterKey,
    binding: KeyProofBinding<'_>,
    challenge: &KeyProofChallenge,
) -> Result<KeyProofResponse, CoreError> {
    let account_private = derive_account_private(master_key)?;
    let account_secret = StaticSecret::from(*account_private);
    let account_public = PublicKey::from(&account_secret).to_bytes();
    let shared = account_secret.diffie_hellman(&PublicKey::from(challenge.server_public));
    if !shared.was_contributory() {
        return Err(CoreError::InvalidInput(
            "key-proof server public key is non-contributory".into(),
        ));
    }
    let tag = compute_tag(
        shared.as_bytes(),
        binding,
        &challenge.nonce,
        &account_public,
        &challenge.server_public,
    )?;
    Ok(KeyProofResponse { tag })
}

impl KeyProofVerifier {
    /// Consume this verifier into secret state suitable for short-lived shared
    /// storage. Bytes 0..32 are the ephemeral private key and 32..64 the nonce.
    /// The returned buffer wipes itself on drop and must never be logged or
    /// persisted outside an expiring secret store.
    pub fn export_state(self) -> Zeroizing<[u8; SERIALIZED_VERIFIER_LEN]> {
        let mut state = Zeroizing::new([0u8; SERIALIZED_VERIFIER_LEN]);
        state[..32].copy_from_slice(&*self.server_private);
        state[32..].copy_from_slice(&self.challenge.nonce);
        state
    }

    /// Restore verifier state exported by [`Self::export_state`].
    pub fn import_state(state: &[u8]) -> Result<Self, CoreError> {
        let state: &[u8; SERIALIZED_VERIFIER_LEN] = state
            .try_into()
            .map_err(|_| CoreError::InvalidInput("invalid key-proof verifier state length".into()))?;
        let mut private = [0u8; 32];
        private.copy_from_slice(&state[..32]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&state[32..]);
        let (_, verifier) = challenge_from_parts(private, nonce)?;
        Ok(verifier)
    }

    /// Verify one response against the account public key. This consumes the
    /// verifier on success and failure; a retry requires a fresh challenge.
    pub fn verify(
        self,
        account_public: &[u8; 32],
        binding: KeyProofBinding<'_>,
        response: &KeyProofResponse,
    ) -> Result<(), CoreError> {
        let server_secret = StaticSecret::from(*self.server_private);
        let shared = server_secret.diffie_hellman(&PublicKey::from(*account_public));
        if !shared.was_contributory() {
            return Err(CoreError::InvalidInput(
                "key-proof account public key is non-contributory".into(),
            ));
        }
        let expected = compute_tag(
            shared.as_bytes(),
            binding,
            &self.challenge.nonce,
            account_public,
            &self.challenge.server_public,
        )?;
        if bool::from(expected.ct_eq(&response.tag)) {
            Ok(())
        } else {
            Err(CoreError::Decryption)
        }
    }

    /// Deterministic construction used only by published known-answer vectors.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_test_parts(
        server_private: [u8; 32],
        nonce: [u8; NONCE_LEN],
    ) -> Result<(KeyProofChallenge, Self), CoreError> {
        challenge_from_parts(server_private, nonce)
    }
}

fn challenge_from_parts(
    server_private: [u8; 32],
    nonce: [u8; NONCE_LEN],
) -> Result<(KeyProofChallenge, KeyProofVerifier), CoreError> {
    let server_private = Zeroizing::new(server_private);
    let server_secret = StaticSecret::from(*server_private);
    let server_public = PublicKey::from(&server_secret).to_bytes();
    if server_public == [0u8; 32] {
        return Err(CoreError::Encryption("invalid key-proof ephemeral key".into()));
    }
    let challenge = KeyProofChallenge { nonce, server_public };
    let verifier = KeyProofVerifier {
        server_private,
        challenge: challenge.clone(),
    };
    Ok((challenge, verifier))
}

fn derive_account_private(master_key: &MasterKey) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut private = Zeroizing::new([0u8; 32]);
    hk.expand(ACCOUNT_KEY_INFO, &mut *private)
        .map_err(|_| CoreError::Kdf("account X25519 derivation failed".into()))?;
    Ok(private)
}

fn compute_tag(
    shared_secret: &[u8; 32],
    binding: KeyProofBinding<'_>,
    nonce: &[u8; NONCE_LEN],
    account_public: &[u8; 32],
    server_public: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(KEY_INFO, &mut *key)
        .map_err(|_| CoreError::Kdf("key-proof MAC derivation failed".into()))?;
    let mut mac = HmacSha256::new_from_slice(&*key).map_err(|_| CoreError::Kdf("invalid key-proof MAC key".into()))?;
    mac.update(TRANSCRIPT_DOMAIN);
    match binding {
        KeyProofBinding::Session { session_id, account_id } => {
            mac.update(b"session");
            update_field(&mut mac, session_id)?;
            update_field(&mut mac, account_id)?;
        }
        KeyProofBinding::Recovery { canonical_email } => {
            mac.update(b"recovery");
            update_field(&mut mac, canonical_email)?;
        }
    }
    mac.update(nonce);
    mac.update(account_public);
    mac.update(server_public);
    Ok(mac.finalize().into_bytes().into())
}

fn update_field(mac: &mut HmacSha256, bytes: &[u8]) -> Result<(), CoreError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| CoreError::InvalidInput("key-proof binding is too long".into()))?;
    mac.update(&len.to_be_bytes());
    mac.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opaque::{derive_x25519_private, derive_x25519_public};

    fn fixture() -> (MasterKey, KeyProofChallenge, KeyProofVerifier) {
        let master = MasterKey::from_bytes([0x41; 32]);
        let (challenge, verifier) = KeyProofVerifier::from_test_parts([0x73; 32], [0x19; 32]).unwrap();
        (master, challenge, verifier)
    }

    #[test]
    fn session_proof_round_trips() {
        let (master, challenge, verifier) = fixture();
        let binding = KeyProofBinding::Session {
            session_id: b"session-1",
            account_id: b"account-1",
        };
        let response = answer_challenge(&master, binding, &challenge).unwrap();
        let account_public = derive_x25519_public(&derive_x25519_private(&master));
        verifier.verify(&account_public, binding, &response).unwrap();
    }

    #[test]
    fn verifier_round_trips_through_expiring_store_state() {
        let (master, challenge, verifier) = fixture();
        let binding = KeyProofBinding::Session {
            session_id: b"session-1",
            account_id: b"account-1",
        };
        let response = answer_challenge(&master, binding, &challenge).unwrap();
        let state = verifier.export_state();
        let verifier = KeyProofVerifier::import_state(&state[..]).unwrap();
        let account_public = derive_x25519_public(&derive_x25519_private(&master));
        verifier.verify(&account_public, binding, &response).unwrap();
    }

    #[test]
    fn purpose_and_every_binding_are_authenticated() {
        let cases = [
            KeyProofBinding::Session {
                session_id: b"session-2",
                account_id: b"account-1",
            },
            KeyProofBinding::Session {
                session_id: b"session-1",
                account_id: b"account-2",
            },
            KeyProofBinding::Recovery {
                canonical_email: b"person@example.test",
            },
        ];
        for wrong_binding in cases {
            let (master, challenge, verifier) = fixture();
            let response = answer_challenge(
                &master,
                KeyProofBinding::Session {
                    session_id: b"session-1",
                    account_id: b"account-1",
                },
                &challenge,
            )
            .unwrap();
            let account_public = derive_x25519_public(&derive_x25519_private(&master));
            assert!(matches!(
                verifier.verify(&account_public, wrong_binding, &response),
                Err(CoreError::Decryption)
            ));
        }
    }

    #[test]
    fn low_order_points_are_rejected_on_both_sides() {
        let (master, _, verifier) = fixture();
        assert!(
            verifier
                .verify(
                    &[0u8; 32],
                    KeyProofBinding::Recovery {
                        canonical_email: b"person@example.test",
                    },
                    &KeyProofResponse::from_bytes([0u8; 32]),
                )
                .is_err()
        );
        let challenge = KeyProofChallenge::from_parts([1u8; 32], [0u8; 32]);
        assert!(
            answer_challenge(
                &master,
                KeyProofBinding::Recovery {
                    canonical_email: b"person@example.test",
                },
                &challenge,
            )
            .is_err()
        );
    }
}
