use bip39::Mnemonic;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::CoreError;
use crate::kdf::MasterKey;

/// Fixed salt used when deriving a master key from recovery-phrase entropy.
// NB: trailing "x" is a historical artifact — do not change without migration,
// existing recovery keys depend on this exact salt.
const RECOVERY_SALT: &[u8] = b"beebeeb-recovery-v1x";

/// Generate a new 12-word BIP39 recovery phrase and the corresponding master key.
///
/// The recovery phrase IS the master secret. The 128 bits of entropy backing
/// the mnemonic are fed through Argon2id to produce a 32-byte master key.
/// This same key is then encrypted with the user's password for daily login.
///
/// The password never derives its own independent master key — it only wraps
/// the recovery-phrase-derived key for convenience. If the user loses both
/// their password and recovery phrase, the data is gone.
pub fn generate_recovery_phrase() -> Result<(String, MasterKey), CoreError> {
    let mnemonic = Mnemonic::generate_in_with(&mut OsRng, bip39::Language::English, 12)
        .map_err(|e| CoreError::Kdf(format!("mnemonic generation failed: {e}")))?;

    // The 128 bits of entropy backing the mnemonic are key-adjacent material:
    // they derive the master key. Wrap in `Zeroizing` so the buffer is wiped on
    // Drop along EVERY path (success, the `?` early-return below) — no leftover
    // key-adjacent bytes linger in memory.
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let mk = derive_key_from_entropy(&entropy)?;

    Ok((mnemonic.to_string(), mk))
}

/// Recover a master key from a 12-word BIP39 recovery phrase.
///
/// Returns [`CoreError::InvalidRecoveryPhrase`] if the phrase is malformed or
/// has an invalid checksum.
pub fn recover_from_phrase(phrase: &str) -> Result<MasterKey, CoreError> {
    let mnemonic: Mnemonic = phrase.parse().map_err(|_| CoreError::InvalidRecoveryPhrase)?;

    // Same rationale as `generate_recovery_phrase`: this entropy is the master
    // secret. `Zeroizing` wipes it on Drop on both the Ok and Err paths of
    // `derive_key_from_entropy` so no key-adjacent bytes survive.
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    derive_key_from_entropy(&entropy)
}

fn derive_key_from_entropy(entropy: &[u8]) -> Result<MasterKey, CoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params =
        Params::new(256 * 1024, 4, 2, Some(32)).map_err(|e| CoreError::Kdf(format!("invalid argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(entropy, RECOVERY_SALT, &mut *output)
        .map_err(|e| CoreError::Kdf(format!("argon2 hashing failed: {e}")))?;

    Ok(MasterKey::from_zeroizing(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_phrase_roundtrip() {
        let (phrase, original_key) = generate_recovery_phrase().unwrap();

        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12, "phrase must be 12 words");

        let recovered_key = recover_from_phrase(&phrase).unwrap();
        assert_eq!(original_key.as_bytes(), recovered_key.as_bytes());
    }

    #[test]
    fn invalid_phrase_returns_error() {
        let result = recover_from_phrase("not a valid recovery phrase at all");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_word_count_returns_error() {
        let result = recover_from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        );
        assert!(result.is_err());
    }

    #[test]
    fn each_generation_produces_unique_phrase() {
        let (phrase1, _) = generate_recovery_phrase().unwrap();
        let (phrase2, _) = generate_recovery_phrase().unwrap();
        assert_ne!(phrase1, phrase2, "two generated phrases should differ");
    }

    #[test]
    fn known_phrase_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mk1 = recover_from_phrase(phrase).unwrap();
        let mk2 = recover_from_phrase(phrase).unwrap();
        assert_eq!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn empty_phrase_returns_error() {
        let result = recover_from_phrase("");
        assert!(result.is_err());
    }

    /// Entropy hygiene: wrapping the BIP39 entropy in `Zeroizing` must not change
    /// behaviour — generate and recover must still produce the identical master
    /// key. (The zeroize-on-Drop property itself is a memory invariant that
    /// cannot be observed from safe Rust without reading freed memory; this test
    /// pins the round-trip so a future refactor of the wrapper can't silently
    /// break key derivation.)
    #[test]
    fn entropy_zeroizing_preserves_roundtrip() {
        // Argon2id at 256 MiB is expensive in debug; a few iterations suffice to
        // pin the invariant without making the suite crawl.
        for _ in 0..3 {
            let (phrase, original_key) = generate_recovery_phrase().unwrap();
            let recovered_key = recover_from_phrase(&phrase).unwrap();
            assert_eq!(
                original_key.as_bytes(),
                recovered_key.as_bytes(),
                "zeroizing the entropy buffer must not affect derived key"
            );
        }
    }
}
