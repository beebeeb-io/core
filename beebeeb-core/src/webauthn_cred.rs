//! WebAuthn credential primitives: a P-256 keypair, ES256 signatures and the COSE_Key encoding of the
//! public key. A passkey provider (Beebeeb Pass) builds authenticator data and attestation on top of
//! these; the clients never touch `p256` themselves.
//!
//! - **Keypair:** NIST P-256, the private scalar as 32 zeroizing bytes ([`CredentialKey::to_secret_bytes`]).
//! - **ES256:** ECDSA over SHA-256 of `authenticatorData || clientDataHash` (RFC 6979 deterministic nonce),
//!   returned DER-encoded as WebAuthn requires. `s` is not normalised: WebAuthn does not require low-s.
//! - **COSE_Key** (RFC 9052, CTAP2 canonical form): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, 77 bytes.
//!
//! - **Stored private key:** PKCS#8 `PrivateKeyInfo` DER whose `ECPrivateKey` carries only the scalar
//!   (a fixed 35-byte header, then the 32 bytes), base64 in the vault item. The public key leaves as
//!   `SubjectPublicKeyInfo` DER (a fixed 26-byte header, then the 65 SEC1 bytes). Both are read strictly:
//!   only the exact form written here opens. Every copy of the scalar and of its DER is wiped on drop.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{NonZeroScalar, PublicKey, SecretKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CoreError;

/// COSE algorithm identifier for ES256.
pub const COSE_ALG_ES256: i64 = -7;

/// Length of the COSE_Key encoding produced by [`cose_public_key`].
pub const COSE_KEY_LEN: usize = 77;

/// CBOR prefix of the fixed-shape key map up to the x coordinate's byte string header:
/// map(5), 1:2 (EC2), 3:-7 (ES256), -1:1 (P-256), -2: bytes(32).
const COSE_HEAD: [u8; 10] = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
/// `-3:` bytes(32), between the x and y coordinates.
const COSE_Y_HEAD: [u8; 3] = [0x22, 0x58, 0x20];

/// DER `SubjectPublicKeyInfo` header for an uncompressed P-256 key (the 65 SEC1 bytes follow).
const SPKI_P256_HEAD: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// PKCS#8 `PrivateKeyInfo` header for a P-256 key whose `ECPrivateKey` carries only the scalar (the 32
/// bytes follow).
const PKCS8_P256_HEAD: [u8; 35] = [
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
];

/// Length of the PKCS#8 DER written by [`CredentialKey::to_pkcs8_der`].
pub const PKCS8_DER_LEN: usize = PKCS8_P256_HEAD.len() + 32;
/// Length of the SPKI DER written by [`CredentialKey::public_key_spki_der`].
pub const SPKI_DER_LEN: usize = SPKI_P256_HEAD.len() + 65;
/// Length of the padded standard base64 of the PKCS#8 DER.
const PKCS8_B64_LEN: usize = PKCS8_DER_LEN.div_ceil(3) * 4;

/// A P-256 credential keypair.
pub struct CredentialKey {
    key: SigningKey,
}

impl CredentialKey {
    /// A fresh keypair from the OS CSPRNG (a non-zero scalar; an RNG failure panics rather than
    /// returning a weak key, as in `cli_auth`).
    pub fn generate() -> Self {
        Self::from_secret(SecretKey::from(NonZeroScalar::generate()))
    }

    /// From a 32-byte private scalar. Errors when it is zero or not below the curve order.
    pub fn from_secret_bytes(scalar: &[u8; 32]) -> Result<Self, CoreError> {
        let secret = SecretKey::from_slice(scalar)
            .map_err(|e| CoreError::InvalidInput(format!("invalid P-256 private scalar: {e}")))?;
        Ok(Self::from_secret(secret))
    }

    fn from_secret(secret: SecretKey) -> Self {
        Self {
            key: SigningKey::from(secret),
        }
    }

    /// The private scalar, wiped on drop.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        let mut bytes = self.key.to_bytes();
        out.copy_from_slice(&bytes);
        bytes.as_mut_slice().zeroize();
        out
    }

    /// The private key as PKCS#8 DER (67 bytes: the fixed header, then the scalar), wiped on drop.
    pub fn to_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let mut der = Zeroizing::new(Vec::with_capacity(PKCS8_DER_LEN));
        der.extend_from_slice(&PKCS8_P256_HEAD);
        der.extend_from_slice(&self.to_secret_bytes()[..]);
        der
    }

    /// From the PKCS#8 DER that [`to_pkcs8_der`](Self::to_pkcs8_der) writes. Any other length, header
    /// or scalar range is an error.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CoreError> {
        if der.len() != PKCS8_DER_LEN || der[..PKCS8_P256_HEAD.len()] != PKCS8_P256_HEAD {
            return Err(CoreError::InvalidInput("not a P-256 PKCS#8 private key".into()));
        }
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(&der[PKCS8_P256_HEAD.len()..]);
        Self::from_secret_bytes(&scalar)
    }

    /// The PKCS#8 DER as padded standard base64 (92 characters), the form stored in a vault item. The
    /// string is written into a buffer of its final size and wiped on drop.
    pub fn to_pkcs8_base64(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(PKCS8_B64_LEN));
        STANDARD.encode_string(&self.to_pkcs8_der()[..], &mut out);
        out
    }

    /// From the base64 that [`to_pkcs8_base64`](Self::to_pkcs8_base64) writes. The decoded DER is
    /// wiped before this returns.
    pub fn from_pkcs8_base64(b64: &str) -> Result<Self, CoreError> {
        let bad = || CoreError::InvalidInput("not a P-256 PKCS#8 private key".into());
        if b64.len() != PKCS8_B64_LEN {
            return Err(bad());
        }
        let mut der = Zeroizing::new([0u8; PKCS8_B64_LEN / 4 * 3]);
        let n = STANDARD.decode_slice(b64, &mut der[..]).map_err(|_| bad())?;
        Self::from_pkcs8_der(&der[..n])
    }

    /// The public key as `SubjectPublicKeyInfo` DER (91 bytes), what WebAuthn's `getPublicKey()` returns.
    pub fn public_key_spki_der(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(SPKI_DER_LEN);
        der.extend_from_slice(&SPKI_P256_HEAD);
        der.extend_from_slice(&self.public_key_sec1());
        der
    }

    /// The SEC1-uncompressed public key (`0x04 || X || Y`, 65 bytes).
    pub fn public_key_sec1(&self) -> [u8; 65] {
        let point = PublicKey::from(self.key.verifying_key()).to_sec1_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// The COSE_Key of the public key (see [`cose_public_key`]).
    pub fn cose_public_key(&self) -> Vec<u8> {
        cose_public_key(&self.public_key_sec1()).expect("a generated key is a valid point")
    }

    /// ES256 over `authenticator_data || client_data_hash`, DER-encoded.
    pub fn sign(&self, authenticator_data: &[u8], client_data_hash: &[u8; 32]) -> Vec<u8> {
        let sig: Signature = self.key.sign(&signed_message(authenticator_data, client_data_hash));
        sig.to_der().as_bytes().to_vec()
    }
}

fn signed_message(authenticator_data: &[u8], client_data_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(authenticator_data.len() + 32);
    msg.extend_from_slice(authenticator_data);
    msg.extend_from_slice(client_data_hash);
    msg
}

/// Check a DER ES256 signature over `authenticator_data || client_data_hash` against a COSE_Key.
/// What a relying party does; here it backs the tests and any provider self-check. `Ok(false)` is a
/// well-formed signature that does not match; an unparsable key or signature is an error.
pub fn verify(
    cose_key: &[u8],
    authenticator_data: &[u8],
    client_data_hash: &[u8; 32],
    signature_der: &[u8],
) -> Result<bool, CoreError> {
    let sec1 = parse_cose_public_key(cose_key)?;
    let public = PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| CoreError::InvalidInput("public key is not on the P-256 curve".into()))?;
    let verifying = VerifyingKey::from(public);
    let sig = Signature::from_der(signature_der)
        .map_err(|_| CoreError::InvalidInput("invalid DER ES256 signature".into()))?;
    Ok(verifying
        .verify(&signed_message(authenticator_data, client_data_hash), &sig)
        .is_ok())
}

/// COSE_Key bytes for a SEC1-uncompressed P-256 public key. Errors when the point is not on the curve.
pub fn cose_public_key(sec1_uncompressed: &[u8; 65]) -> Result<Vec<u8>, CoreError> {
    let bad = || CoreError::InvalidInput("invalid P-256 public key".into());
    if sec1_uncompressed[0] != 0x04 {
        return Err(bad());
    }
    PublicKey::from_sec1_bytes(sec1_uncompressed).map_err(|_| bad())?;
    let mut out = Vec::with_capacity(COSE_KEY_LEN);
    out.extend_from_slice(&COSE_HEAD);
    out.extend_from_slice(&sec1_uncompressed[1..33]);
    out.extend_from_slice(&COSE_Y_HEAD);
    out.extend_from_slice(&sec1_uncompressed[33..65]);
    Ok(out)
}

/// The SEC1-uncompressed public key from a COSE_Key. Accepts only the exact canonical ES256 / P-256
/// form that [`cose_public_key`] writes; anything else is an error.
pub fn parse_cose_public_key(cose: &[u8]) -> Result<[u8; 65], CoreError> {
    let bad = || CoreError::InvalidInput("not an ES256 P-256 COSE_Key".into());
    if cose.len() != COSE_KEY_LEN
        || cose[..COSE_HEAD.len()] != COSE_HEAD
        || cose[COSE_HEAD.len() + 32..COSE_HEAD.len() + 32 + COSE_Y_HEAD.len()] != COSE_Y_HEAD
    {
        return Err(bad());
    }
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&cose[COSE_HEAD.len()..COSE_HEAD.len() + 32]);
    out[33..].copy_from_slice(&cose[COSE_HEAD.len() + 32 + COSE_Y_HEAD.len()..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6979 A.2.5, P-256 / SHA-256, message "sample".
    const X: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    const UX: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
    const UY: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
    const R: &str = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
    const S: &str = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

    fn key() -> CredentialKey {
        let x: [u8; 32] = hex::decode(X).unwrap().try_into().unwrap();
        CredentialKey::from_secret_bytes(&x).unwrap()
    }

    /// WebAuthn signs authData || clientDataHash; the RFC vector signs the bare message, so split
    /// "sample" into a 6-byte "authData" and an all-in-hash input only through `Signer` directly.
    #[test]
    fn rfc6979_vector_signs_exactly() {
        let sig: Signature = key().key.sign(b"sample");
        let (r, s) = sig.split_bytes();
        assert_eq!(hex::encode(r), R);
        assert_eq!(hex::encode(s), S);
    }

    #[test]
    fn public_key_matches_vector() {
        let p = key().public_key_sec1();
        assert_eq!(hex::encode(&p[1..33]), UX);
        assert_eq!(hex::encode(&p[33..]), UY);
    }

    #[test]
    fn webauthn_sign_verifies_and_rejects_tampering() {
        let k = CredentialKey::generate();
        let auth_data = [7u8; 37];
        let hash = [9u8; 32];
        let der = k.sign(&auth_data, &hash);
        assert_eq!(der[0], 0x30);
        let cose = k.cose_public_key();
        assert!(verify(&cose, &auth_data, &hash, &der).unwrap());
        let mut other = auth_data;
        other[0] ^= 1;
        assert!(!verify(&cose, &other, &hash, &der).unwrap());
        assert!(!verify(&cose, &auth_data, &[8u8; 32], &der).unwrap());
        let wrong = CredentialKey::generate().cose_public_key();
        assert!(!verify(&wrong, &auth_data, &hash, &der).unwrap());
        assert!(verify(&cose, &auth_data, &hash, &der[..der.len() - 1]).is_err());
    }

    #[test]
    fn vector_key_signs_over_concatenation() {
        // The same key through the WebAuthn entry point: signature must verify and equal a direct
        // signature over the concatenated bytes (deterministic nonce).
        let k = key();
        let auth_data = b"sample, 37 bytes of authenticator ok";
        let hash = [1u8; 32];
        let der = k.sign(auth_data, &hash);
        let mut msg = auth_data.to_vec();
        msg.extend_from_slice(&hash);
        let direct: Signature = k.key.sign(&msg);
        assert_eq!(der, direct.to_der().as_bytes());
        assert!(verify(&k.cose_public_key(), auth_data, &hash, &der).unwrap());
    }

    #[test]
    fn cose_known_encoding_and_round_trip() {
        let k = key();
        let cose = k.cose_public_key();
        assert_eq!(cose.len(), COSE_KEY_LEN);
        let expect = format!("a501020326200121582060{}", &UX[2..]) + &format!("225820{UY}");
        assert_eq!(hex::encode(&cose), expect);
        assert_eq!(parse_cose_public_key(&cose).unwrap(), k.public_key_sec1());
        assert_eq!(cose_public_key(&k.public_key_sec1()).unwrap(), cose);
    }

    #[test]
    fn cose_rejects_malformed_and_off_curve() {
        let cose = key().cose_public_key();
        assert!(parse_cose_public_key(&cose[..76]).is_err());
        let mut bad_alg = cose.clone();
        bad_alg[4] = 0x27; // -8
        assert!(parse_cose_public_key(&bad_alg).is_err());
        let mut off = key().public_key_sec1();
        off[64] ^= 1;
        assert!(cose_public_key(&off).is_err());
        let mut compressed = key().public_key_sec1();
        compressed[0] = 0x02;
        assert!(cose_public_key(&compressed).is_err());
    }

    #[test]
    fn pkcs8_and_spki_known_bytes() {
        // The bytes the Pass crate wrote before the wrap moved here (pass 419195f).
        let scalar: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let k = CredentialKey::from_secret_bytes(&scalar).unwrap();
        let der = k.to_pkcs8_der();
        let head = "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420";
        assert_eq!(hex::encode(&der[..]), format!("{head}{}", hex::encode(scalar)));
        assert_eq!(der.len(), PKCS8_DER_LEN);
        let b64 = k.to_pkcs8_base64();
        assert_eq!(
            b64.as_str(),
            "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA=="
        );
        assert_eq!(b64.capacity(), b64.len(), "written into a buffer of its final size");
        assert_eq!(STANDARD.decode(b64.as_str()).unwrap(), der[..]);
        let again = CredentialKey::from_pkcs8_base64(&b64).unwrap();
        assert_eq!(again.public_key_sec1(), k.public_key_sec1());
        assert_eq!(*CredentialKey::from_pkcs8_der(&der).unwrap().to_secret_bytes(), scalar);

        let spki = key().public_key_spki_der();
        assert_eq!(spki.len(), SPKI_DER_LEN);
        assert_eq!(
            hex::encode(&spki),
            format!("3059301306072a8648ce3d020106082a8648ce3d03010703420004{UX}{UY}")
        );
    }

    #[test]
    fn pkcs8_open_is_strict() {
        let k = key();
        let der = k.to_pkcs8_der();
        assert!(CredentialKey::from_pkcs8_der(&der[..66]).is_err());
        let mut long = der.to_vec();
        long.push(0);
        assert!(CredentialKey::from_pkcs8_der(&long).is_err());
        let mut head = der.to_vec();
        head[1] ^= 1;
        assert!(CredentialKey::from_pkcs8_der(&head).is_err());
        let mut zero = der.to_vec();
        zero[35..].fill(0);
        assert!(CredentialKey::from_pkcs8_der(&zero).is_err());
        let b64 = k.to_pkcs8_base64();
        assert!(CredentialKey::from_pkcs8_base64(&b64[..88]).is_err());
        assert!(CredentialKey::from_pkcs8_base64(&b64.replace('=', "")).is_err());
        assert!(CredentialKey::from_pkcs8_base64(&format!("{}!===", &b64[..88])).is_err());
        assert!(CredentialKey::from_pkcs8_base64("").is_err());
    }

    #[test]
    fn secret_bytes_round_trip_and_range() {
        let k = CredentialKey::generate();
        let again = CredentialKey::from_secret_bytes(&k.to_secret_bytes()).unwrap();
        assert_eq!(again.public_key_sec1(), k.public_key_sec1());
        assert!(CredentialKey::from_secret_bytes(&[0u8; 32]).is_err());
        assert!(CredentialKey::from_secret_bytes(&[0xff; 32]).is_err());
    }
}
