//! File-request sealed-box (ECIES) primitives.
//!
//! File requests are the inverse of sharing: an account-less uploader encrypts a
//! file's content key to a *request's* public key, and the owner later unwraps it
//! with their master key. Each request owns its own X25519 keypair; the private
//! half is wrapped under the owner's master key and stored server-side (the server
//! never sees it in the clear).
//!
//! Two HKDF labels, both HKDF-SHA256, both `salt = None`, both with the label as
//! the `info` prefix (matching the conventions in [`crate::kdf`] / [`crate::opaque`]):
//!
//! | Purpose                  | Derivation                                                                    |
//! |--------------------------|-------------------------------------------------------------------------------|
//! | Request private-wrap key | `wrk = HKDF(ikm = master_key, info = "beebeeb-file-request-priv-v1" ‖ request_id)` |
//! | Per-upload seal key      | `sk  = HKDF(ikm = ecdh_shared_secret, info = "beebeeb-file-request-seal-v1" ‖ file_id)` |
//!
//! All symmetric encryption is AES-256-GCM (`CipherSuite::V1Aes256Gcm`), reusing
//! the helpers in [`crate::encrypt`]. The ECDH shared secret is computed with
//! [`crate::opaque::x25519_shared_secret`], which rejects low-order points.
//!
//! No primitive here hand-rolls X25519, HKDF, or AES — every client (web/WASM,
//! mobile/UniFFI, CLI, desktop) calls these functions so the wire format is
//! byte-identical everywhere (proven by `tests/cross_platform_vectors.rs`).

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use beebeeb_types::{CipherSuite, EncryptedBlob};

use crate::CoreError;
use crate::encrypt::{decrypt_chunk, decrypt_chunk_raw, encrypt_chunk, encrypt_chunk_raw};
use crate::kdf::{FileKey, MasterKey};
use crate::opaque::{derive_x25519_public, x25519_shared_secret};

/// HKDF `info` prefix for deriving the per-request private-key-wrapping key.
const PRIV_WRAP_INFO: &[u8] = b"beebeeb-file-request-priv-v1";
/// HKDF `info` prefix for deriving the per-upload seal key.
const SEAL_INFO: &[u8] = b"beebeeb-file-request-seal-v1";

/// The result of sealing a content key to a request public key.
///
/// `e_pub` is the ephemeral X25519 public key the uploader generated; the owner
/// needs it to reconstruct the ECDH shared secret. `wrapped_key` is the content
/// key encrypted under the per-upload seal key (raw `nonce ‖ ciphertext` form).
pub struct SealedUpload {
    pub e_pub: [u8; 32],
    pub wrapped_key: Vec<u8>,
}

/// Derive the per-request private-key-wrapping key from the owner's master key.
///
/// `wrk = HKDF-SHA256(ikm = master_key, salt = None, info = "beebeeb-file-request-priv-v1" ‖ request_id)`.
/// Deterministic: the same `(master_key, request_id)` always yields the same key.
pub fn derive_request_wrap_key(master_key: &MasterKey, request_id: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut info = Vec::with_capacity(PRIV_WRAP_INFO.len() + request_id.len());
    info.extend_from_slice(PRIV_WRAP_INFO);
    info.extend_from_slice(request_id);

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    okm
}

/// Wrap a request's X25519 private key under the owner's master key.
///
/// Returns `(wrapped, nonce)` — the AES-256-GCM ciphertext (incl. GCM tag) and the
/// random 12-byte nonce. Stored server-side so the owner can later rebuild the
/// request link / decrypt uploads; the server never sees `r_priv` in the clear.
pub fn wrap_request_private(
    master_key: &MasterKey,
    request_id: &[u8],
    r_priv: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let wrk = derive_request_wrap_key(master_key, request_id);
    let wrap_key = FileKey::from_bytes(*wrk);
    let blob = encrypt_chunk(&wrap_key, r_priv)?;
    Ok((blob.ciphertext, blob.nonce))
}

/// Inverse of [`wrap_request_private`]: recover the request's X25519 private key.
pub fn unwrap_request_private(
    master_key: &MasterKey,
    request_id: &[u8],
    wrapped: &[u8],
    nonce: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let wrk = derive_request_wrap_key(master_key, request_id);
    let wrap_key = FileKey::from_bytes(*wrk);
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: nonce.to_vec(),
        ciphertext: wrapped.to_vec(),
    };
    let mut plaintext = decrypt_chunk(&wrap_key, &blob)?;
    let result = to_key32(&plaintext);
    plaintext.zeroize();
    result
}

/// Seal a content key to a request's public key (anonymous uploader path).
///
/// Generates a fresh ephemeral X25519 keypair, computes the ECDH shared secret
/// with `r_pub`, derives the per-upload seal key (bound to `file_id`), and wraps
/// `content_key` under it with AES-256-GCM. The ephemeral private key is discarded
/// when this function returns. Fails if `r_pub` is a low-order point.
pub fn seal_to_request(r_pub: &[u8; 32], file_id: &[u8], content_key: &[u8; 32]) -> Result<SealedUpload, CoreError> {
    // Fresh ephemeral keypair. The private half never leaves this function.
    let mut e_priv = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *e_priv);
    let e_pub = derive_x25519_public(&e_priv);

    // ECDH → seal key. x25519_shared_secret rejects low-order r_pub.
    let shared = x25519_shared_secret(&e_priv, r_pub)?;
    let seal_key = FileKey::from_bytes(*derive_seal_key(&shared, file_id));

    // wrapped_key = nonce ‖ AES-256-GCM(seal_key, content_key)
    let wrapped_key = encrypt_chunk_raw(&seal_key, content_key)?;

    Ok(SealedUpload { e_pub, wrapped_key })
}

/// Inverse of [`seal_to_request`]: recover the content key (owner decrypt path).
///
/// Computes the ECDH shared secret from the owner's request private key and the
/// uploader's ephemeral public key, re-derives the per-upload seal key, and
/// decrypts `wrapped_key`. Fails if `e_pub` is a low-order point, the seal key is
/// wrong, or the ciphertext was tampered with.
pub fn open_request_upload(
    r_priv: &[u8; 32],
    e_pub: &[u8; 32],
    file_id: &[u8],
    wrapped_key: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let shared = x25519_shared_secret(r_priv, e_pub)?;
    let seal_key = FileKey::from_bytes(*derive_seal_key(&shared, file_id));
    let mut plaintext = decrypt_chunk_raw(&seal_key, wrapped_key)?;
    let result = to_key32(&plaintext);
    plaintext.zeroize();
    result
}

/// Derive the per-upload seal key from the ECDH shared secret and file id.
///
/// `sk = HKDF-SHA256(ikm = shared_secret, salt = None, info = "beebeeb-file-request-seal-v1" ‖ file_id)`.
fn derive_seal_key(shared_secret: &[u8; 32], file_id: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut info = Vec::with_capacity(SEAL_INFO.len() + file_id.len());
    info.extend_from_slice(SEAL_INFO);
    info.extend_from_slice(file_id);

    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    okm
}

/// Copy a decrypted 32-byte key into a zeroizing buffer, rejecting wrong lengths.
fn to_key32(plaintext: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if plaintext.len() != 32 {
        return Err(CoreError::Decryption);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_master_key;

    fn test_master_key() -> MasterKey {
        derive_master_key("file-request-test-pw", b"sixteen-byte-salt").unwrap()
    }

    fn request_keypair() -> ([u8; 32], [u8; 32]) {
        // Any 32 bytes is a valid X25519 scalar (clamping is applied internally).
        let r_priv = [0x11u8; 32];
        let r_pub = derive_x25519_public(&r_priv);
        (r_priv, r_pub)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (r_priv, r_pub) = request_keypair();
        let file_id = b"file-req-roundtrip-001";
        let content_key = [0x42u8; 32];

        let sealed = seal_to_request(&r_pub, file_id, &content_key).unwrap();
        let opened = open_request_upload(&r_priv, &sealed.e_pub, file_id, &sealed.wrapped_key).unwrap();
        assert_eq!(*opened, content_key);
    }

    #[test]
    fn open_with_wrong_request_private_fails() {
        let (_r_priv, r_pub) = request_keypair();
        let file_id = b"file-req-wrongkey";
        let content_key = [0x07u8; 32];

        let sealed = seal_to_request(&r_pub, file_id, &content_key).unwrap();

        let wrong_priv = [0x22u8; 32];
        assert!(open_request_upload(&wrong_priv, &sealed.e_pub, file_id, &sealed.wrapped_key).is_err());
    }

    #[test]
    fn open_with_wrong_file_id_fails() {
        let (r_priv, r_pub) = request_keypair();
        let content_key = [0x09u8; 32];

        let sealed = seal_to_request(&r_pub, b"file-id-A", &content_key).unwrap();
        assert!(open_request_upload(&r_priv, &sealed.e_pub, b"file-id-B", &sealed.wrapped_key).is_err());
    }

    #[test]
    fn seal_rejects_low_order_request_public() {
        // All-zeros is a low-order point: x25519_shared_secret must reject it.
        let zero_pub = [0u8; 32];
        let content_key = [0x33u8; 32];
        assert!(seal_to_request(&zero_pub, b"f", &content_key).is_err());
    }

    #[test]
    fn open_rejects_low_order_ephemeral_public() {
        let (r_priv, _r_pub) = request_keypair();
        let zero_e_pub = [0u8; 32];
        // wrapped_key length is irrelevant — the low-order check fails first.
        let err = open_request_upload(&r_priv, &zero_e_pub, b"f", &[0u8; 28]).unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn open_rejects_tampered_wrapped_key() {
        let (r_priv, r_pub) = request_keypair();
        let file_id = b"file-req-tamper";
        let content_key = [0x55u8; 32];

        let mut sealed = seal_to_request(&r_pub, file_id, &content_key).unwrap();
        // Flip a ciphertext byte (after the 12-byte nonce prefix).
        let last = sealed.wrapped_key.len() - 1;
        sealed.wrapped_key[last] ^= 0xFF;
        assert!(open_request_upload(&r_priv, &sealed.e_pub, file_id, &sealed.wrapped_key).is_err());
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let (_r_priv, r_pub) = request_keypair();
        let content_key = [0x01u8; 32];
        let a = seal_to_request(&r_pub, b"f", &content_key).unwrap();
        let b = seal_to_request(&r_pub, b"f", &content_key).unwrap();
        assert_ne!(a.e_pub, b.e_pub, "ephemeral public keys must differ per seal");
        assert_ne!(a.wrapped_key, b.wrapped_key, "wrapped keys must differ per seal");
    }

    #[test]
    fn derive_request_wrap_key_deterministic() {
        let mk = test_master_key();
        let k1 = derive_request_wrap_key(&mk, b"request-id-abc");
        let k2 = derive_request_wrap_key(&mk, b"request-id-abc");
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_request_wrap_key_varies_by_request_id() {
        let mk = test_master_key();
        let k1 = derive_request_wrap_key(&mk, b"request-1");
        let k2 = derive_request_wrap_key(&mk, b"request-2");
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn wrap_unwrap_private_roundtrip() {
        let mk = test_master_key();
        let request_id = b"req-roundtrip-xyz";
        let (r_priv, _r_pub) = request_keypair();

        let (wrapped, nonce) = wrap_request_private(&mk, request_id, &r_priv).unwrap();
        let recovered = unwrap_request_private(&mk, request_id, &wrapped, &nonce).unwrap();
        assert_eq!(*recovered, r_priv);
    }

    #[test]
    fn unwrap_private_wrong_request_id_fails() {
        let mk = test_master_key();
        let (r_priv, _r_pub) = request_keypair();

        let (wrapped, nonce) = wrap_request_private(&mk, b"req-A", &r_priv).unwrap();
        assert!(unwrap_request_private(&mk, b"req-B", &wrapped, &nonce).is_err());
    }

    #[test]
    fn unwrap_private_wrong_master_key_fails() {
        let mk = test_master_key();
        let other = derive_master_key("different-pw", b"sixteen-byte-salt").unwrap();
        let request_id = b"req-master-mismatch";
        let (r_priv, _r_pub) = request_keypair();

        let (wrapped, nonce) = wrap_request_private(&mk, request_id, &r_priv).unwrap();
        assert!(unwrap_request_private(&other, request_id, &wrapped, &nonce).is_err());
    }

    #[test]
    fn full_owner_uploader_pipeline() {
        // Owner: create request keypair, wrap private under master key.
        let mk = test_master_key();
        let request_id = b"req-full-pipeline";
        let (r_priv, r_pub) = request_keypair();
        let (wrapped_priv, wrap_nonce) = wrap_request_private(&mk, request_id, &r_priv).unwrap();

        // Uploader: seal a content key to r_pub (only the public key is known).
        let file_id = b"uploaded-file-001";
        let content_key = [0xABu8; 32];
        let sealed = seal_to_request(&r_pub, file_id, &content_key).unwrap();

        // Owner: unwrap r_priv, then open the upload.
        let recovered_priv = unwrap_request_private(&mk, request_id, &wrapped_priv, &wrap_nonce).unwrap();
        let opened = open_request_upload(&recovered_priv, &sealed.e_pub, file_id, &sealed.wrapped_key).unwrap();
        assert_eq!(*opened, content_key);
    }
}
