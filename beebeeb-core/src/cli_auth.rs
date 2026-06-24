//! CLI device-authorization handshake crypto (P-256 ECDH + HKDF-SHA256 + AES-256-GCM).
//!
//! This is the crypto behind `bb login`'s browser device-authorization flow. It is
//! **separate from OPAQUE**: OPAQUE ([`crate::opaque_protocol`]) is the password
//! login used by web/mobile; this handshake is how a `bb` CLI receives an existing
//! session's credentials from an *already-logged-in browser*. The CLI never sees the
//! password — the browser re-encrypts the live `{session_token, master_key, email}`
//! to the CLI's ephemeral key.
//!
//! ```text
//!   1. CLI generates an ephemeral P-256 keypair, sends its public key to the server.
//!   2. Browser (web client) fetches that CLI public key, generates its OWN ephemeral
//!      P-256 keypair, computes ECDH, derives an AES key, encrypts the payload, and
//!      returns {nonce, ciphertext, browser_public_key} (the server is a blind relay).
//!   3. CLI computes the same ECDH shared secret from its ephemeral private key + the
//!      browser's public key, re-derives the AES key, and decrypts.
//! ```
//!
//! The wire format is **byte-identical** to the web client's inline WebCrypto
//! (`repos/web/src/pages/cli-auth.tsx`, `ecdhEncryptPayload`) and the prior
//! hand-rolled CLI implementation. Moving it here removes the per-client crypto
//! drift (the project's "all crypto in core" rule) without any protocol change —
//! `tests/cli_auth_vectors.rs` pins the derivation so live `bb login` is unaffected.
//!
//! ## Derivation
//!
//! - **Curve:** NIST P-256 (secp256r1), ECDH.
//! - **Shared secret:** `raw_secret_bytes()` — the 32-byte X-coordinate of the ECDH
//!   point. Matches WebCrypto `deriveBits({name:'ECDH'}, ..., 256)`.
//! - **KDF (v1, current):** `key = HKDF-SHA256(ikm = shared_secret, salt = None,
//!   info = "beebeeb-cli-auth-v1")[..32]`.
//! - **AEAD:** AES-256-GCM with a caller-supplied 12-byte nonce.
//!
//! ## Raw-secret fallback (legacy v0.4 web app)
//!
//! Before the HKDF was introduced (web ≤ v0.4), the browser used the raw 32-byte
//! shared secret **directly** as the AES key (no HKDF). [`decrypt_cli_payload`] tries
//! the HKDF key first, then falls back to the raw secret, preserving compatibility
//! with any old payload still in flight. The current web client only ever emits the
//! HKDF form; the fallback exists purely to not break an old browser build.
//!
//! No primitive here hand-rolls ECDH, HKDF, or AES — the CLI calls these functions so
//! the handshake is identical to the browser's.

use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::CoreError;

/// HKDF `info` label for the CLI auth key. MUST match the web client
/// (`repos/web/src/pages/cli-auth.tsx`) and never change without a coordinated
/// migration — it is part of the wire contract.
const CLI_AUTH_INFO: &[u8] = b"beebeeb-cli-auth-v1";

/// The CLI's ephemeral P-256 keypair for one login attempt.
///
/// Holds the private half (a `SecretKey`, never serialized off the device) and the
/// SEC1-uncompressed public bytes (`0x04 || X || Y`, 65 bytes) the CLI sends to the
/// server. The private half is consumed by [`Self::decrypt_browser_payload`] /
/// [`Self::shared_secret`]; the `SecretKey` zeroizes its scalar on drop.
pub struct CliEphemeralKey {
    secret: SecretKey,
    public_uncompressed: Vec<u8>,
}

impl CliEphemeralKey {
    /// Generate a fresh ephemeral P-256 keypair using the OS CSPRNG.
    ///
    /// This is the production path — `bb login` mints a one-shot keypair per attempt.
    pub fn generate() -> Self {
        Self::from_secret(SecretKey::random(&mut OsRng))
    }

    /// Construct from a fixed 32-byte private scalar.
    ///
    /// Intended for deterministic cross-binding test vectors (so a fixed CLI key can
    /// reproduce the exact ECDH the browser/WebCrypto produced). Production code uses
    /// [`Self::generate`]. Errors if `scalar` is not a valid P-256 private key
    /// (zero or ≥ the curve order).
    pub fn from_secret_bytes(scalar: &[u8; 32]) -> Result<Self, CoreError> {
        let secret = SecretKey::from_slice(scalar)
            .map_err(|e| CoreError::InvalidInput(format!("invalid P-256 private scalar: {e}")))?;
        Ok(Self::from_secret(secret))
    }

    fn from_secret(secret: SecretKey) -> Self {
        let public_uncompressed = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
        Self {
            secret,
            public_uncompressed,
        }
    }

    /// The SEC1-uncompressed public key bytes (`0x04 || X || Y`, 65 bytes) to send to
    /// the server so the browser can perform its side of the ECDH.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_uncompressed
    }

    /// Compute the raw P-256 ECDH shared secret (32-byte X-coordinate) with the
    /// browser's ephemeral public key (SEC1 bytes, compressed or uncompressed).
    ///
    /// Errors if `browser_public` is not a valid point on the curve.
    pub fn shared_secret(&self, browser_public: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
        let browser_pub = PublicKey::from_sec1_bytes(browser_public)
            .map_err(|e| CoreError::InvalidInput(format!("invalid browser public key (not on curve): {e}")))?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), browser_pub.as_affine());
        let raw = shared.raw_secret_bytes();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(raw.as_slice());
        Ok(out)
    }

    /// Decrypt a browser-produced CLI-auth payload end to end.
    ///
    /// Performs the P-256 ECDH with `browser_public`, then [`decrypt_cli_payload`]
    /// (HKDF key first, raw-secret fallback second). Returns the plaintext bytes
    /// (the caller parses the `{session_token, master_key_b64, email}` JSON).
    ///
    /// Errors on an invalid browser public key, a bad nonce length, or if neither the
    /// HKDF nor the raw-secret key authenticates the ciphertext.
    pub fn decrypt_browser_payload(
        &self,
        browser_public: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let shared = self.shared_secret(browser_public)?;
        decrypt_cli_payload(&shared, nonce, ciphertext)
    }
}

/// Derive the AES-256 key from the ECDH shared secret.
///
/// `key = HKDF-SHA256(ikm = shared_secret, salt = None, info = "beebeeb-cli-auth-v1")[..32]`.
pub fn derive_cli_auth_key(shared_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(CLI_AUTH_INFO, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    okm
}

/// AES-256-GCM decrypt with an explicit nonce and key.
fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
    if nonce.len() != 12 {
        return Err(CoreError::InvalidInput(format!(
            "AES-GCM nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    cipher
        .decrypt(GenericArray::from_slice(nonce), ciphertext)
        .map_err(|_| CoreError::Decryption)
}

/// Decrypt a CLI-auth payload from the ECDH shared secret, trying the HKDF key first
/// then the raw-secret fallback (legacy v0.4 web app).
///
/// - **HKDF (current):** `key = HKDF-SHA256(shared_secret, info = "beebeeb-cli-auth-v1")`.
/// - **Raw fallback (legacy):** `key = shared_secret` used directly as the AES-256 key.
///
/// Returns the plaintext on the first key that authenticates, or [`CoreError::Decryption`]
/// if neither does (ECDH mismatch or tampered ciphertext). Errors on a bad nonce length.
pub fn decrypt_cli_payload(shared_secret: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
    if nonce.len() != 12 {
        return Err(CoreError::InvalidInput(format!(
            "AES-GCM nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }
    let hkdf_key = derive_cli_auth_key(shared_secret);
    aes_gcm_decrypt(&hkdf_key, nonce, ciphertext)
        // Backward-compat: v0.4 web app used the raw shared secret as the AES key.
        .or_else(|_| aes_gcm_decrypt(shared_secret, nonce, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    /// Simulate the BROWSER side: generate an ephemeral keypair, ECDH against the
    /// CLI's public key, derive the AES key (HKDF or raw), and AES-256-GCM encrypt.
    /// Returns `(browser_public_uncompressed, nonce, ciphertext)`.
    fn browser_encrypt(cli_public: &[u8], plaintext: &[u8], use_hkdf: bool) -> (Vec<u8>, [u8; 12], Vec<u8>) {
        let cli_pub = PublicKey::from_sec1_bytes(cli_public).unwrap();
        let browser_secret = EphemeralSecret::random(&mut OsRng);
        let browser_public = browser_secret.public_key().to_encoded_point(false).as_bytes().to_vec();

        let shared = browser_secret.diffie_hellman(&cli_pub);
        let mut shared_bytes = [0u8; 32];
        shared_bytes.copy_from_slice(shared.raw_secret_bytes().as_slice());

        let key: [u8; 32] = if use_hkdf {
            *derive_cli_auth_key(&shared_bytes)
        } else {
            shared_bytes
        };

        let nonce = [0x07u8; 12];
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext).unwrap();
        (browser_public, nonce, ciphertext)
    }

    #[test]
    fn hkdf_roundtrip() {
        let cli = CliEphemeralKey::generate();
        let payload = br#"{"session_token":"tok","master_key_b64":"AAAA","email":"a@beebeeb.io"}"#;
        let (browser_pub, nonce, ct) = browser_encrypt(cli.public_key_bytes(), payload, true);

        let pt = cli.decrypt_browser_payload(&browser_pub, &nonce, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn raw_secret_fallback_roundtrip() {
        // Legacy v0.4 web app: raw shared secret used directly as the AES key.
        let cli = CliEphemeralKey::generate();
        let payload = b"legacy-v0.4-payload";
        let (browser_pub, nonce, ct) = browser_encrypt(cli.public_key_bytes(), payload, false);

        let pt = cli.decrypt_browser_payload(&browser_pub, &nonce, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let cli = CliEphemeralKey::generate();
        let browser_secret = EphemeralSecret::random(&mut OsRng);
        let browser_public = browser_secret.public_key().to_encoded_point(false).as_bytes().to_vec();

        let cli_pub = PublicKey::from_sec1_bytes(cli.public_key_bytes()).unwrap();
        let browser_shared = browser_secret.diffie_hellman(&cli_pub);
        let cli_shared = cli.shared_secret(&browser_public).unwrap();
        assert_eq!(cli_shared.as_slice(), browser_shared.raw_secret_bytes().as_slice());
    }

    #[test]
    fn wrong_browser_key_fails_to_decrypt() {
        let cli = CliEphemeralKey::generate();
        let payload = b"secret";
        let (_browser_pub, nonce, ct) = browser_encrypt(cli.public_key_bytes(), payload, true);

        // A DIFFERENT browser key → different shared secret → neither HKDF nor raw
        // key authenticates.
        let other = CliEphemeralKey::generate();
        let wrong_browser_pub = other.public_key_bytes().to_vec();
        let err = cli
            .decrypt_browser_payload(&wrong_browser_pub, &nonce, &ct)
            .unwrap_err();
        assert!(matches!(err, CoreError::Decryption));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let cli = CliEphemeralKey::generate();
        let payload = b"do-not-tamper";
        let (browser_pub, nonce, mut ct) = browser_encrypt(cli.public_key_bytes(), payload, true);
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(matches!(
            cli.decrypt_browser_payload(&browser_pub, &nonce, &ct).unwrap_err(),
            CoreError::Decryption
        ));
    }

    #[test]
    fn invalid_browser_public_key_is_rejected() {
        let cli = CliEphemeralKey::generate();
        // Not a valid SEC1 point.
        let garbage = [0x04u8; 65];
        let err = cli.shared_secret(&garbage).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn bad_nonce_length_is_rejected() {
        let shared = [0x11u8; 32];
        let err = decrypt_cli_payload(&shared, &[0u8; 11], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn public_key_is_uncompressed_sec1() {
        let cli = CliEphemeralKey::generate();
        let pk = cli.public_key_bytes();
        assert_eq!(pk.len(), 65, "uncompressed P-256 point is 65 bytes");
        assert_eq!(pk[0], 0x04, "uncompressed SEC1 prefix");
    }

    #[test]
    fn each_keypair_is_fresh() {
        let a = CliEphemeralKey::generate();
        let b = CliEphemeralKey::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn from_secret_bytes_is_deterministic() {
        let scalar = [0x11u8; 32];
        let a = CliEphemeralKey::from_secret_bytes(&scalar).unwrap();
        let b = CliEphemeralKey::from_secret_bytes(&scalar).unwrap();
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn from_secret_bytes_roundtrips_with_browser() {
        // A fixed CLI key still completes the handshake against a random browser key.
        let cli = CliEphemeralKey::from_secret_bytes(&[0x11u8; 32]).unwrap();
        let payload = b"fixed-key-payload";
        let (browser_pub, nonce, ct) = browser_encrypt(cli.public_key_bytes(), payload, true);
        let pt = cli.decrypt_browser_payload(&browser_pub, &nonce, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn from_secret_bytes_rejects_zero_scalar() {
        // The all-zero scalar is not a valid P-256 private key. (CliEphemeralKey holds
        // key material and deliberately does not derive Debug, so match without
        // unwrap_err, which would require Debug on the Ok variant.)
        match CliEphemeralKey::from_secret_bytes(&[0u8; 32]) {
            Err(CoreError::InvalidInput(_)) => {}
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("zero scalar must be rejected"),
        }
    }

    #[test]
    fn derive_cli_auth_key_is_deterministic() {
        let shared = [0x42u8; 32];
        assert_eq!(*derive_cli_auth_key(&shared), *derive_cli_auth_key(&shared));
    }

    #[test]
    fn derive_cli_auth_key_varies_by_secret() {
        let a = derive_cli_auth_key(&[0x01u8; 32]);
        let b = derive_cli_auth_key(&[0x02u8; 32]);
        assert_ne!(*a, *b);
    }
}
