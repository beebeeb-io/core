//! Pure cryptographic primitives for approving a new device.
//!
//! This module performs no network or storage I/O. A relay transports the QR
//! fields, one-shot PAKE messages, and sealed blob without learning account
//! key material. The legacy transfer words, Constellation codec, and CLI auth
//! protocol must not be used to move account keys.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CoreError;
use crate::kdf::MasterKey;

pub(crate) const FINGERPRINT_DOMAIN: &[u8] = b"beebeeb/device-link/fingerprint/v1";
pub(crate) const QR_KEY_INFO: &[u8] = b"beebeeb/device-link/qr-seal/v2/key";
pub(crate) const QR_AAD_DOMAIN: &[u8] = b"beebeeb/device-link/qr-seal/v2";
pub(crate) const PAKE_IDENTITY_DOMAIN: &[u8] = b"beebeeb/device-link/pake/v1";
pub(crate) const PAKE_KEY_INFO: &[u8] = b"beebeeb/device-link/pake-seal/v1/key";
pub(crate) const PAKE_AAD_DOMAIN: &[u8] = b"beebeeb/device-link/pake-seal/v1";

const NONCE_LEN: usize = 12;
const CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/// Public fields encoded in the device-link QR. It deliberately carries no
/// approval code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLinkQr {
    session_id: [u8; 16],
    fingerprint: [u8; 32],
}

impl DeviceLinkQr {
    pub fn from_parts(session_id: [u8; 16], fingerprint: [u8; 32]) -> Self {
        Self {
            session_id,
            fingerprint,
        }
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Check that the relayed public key matches the fingerprint captured in
    /// the QR before sealing any account material.
    pub fn verify_public_key(&self, relayed_public_key: &[u8; 32]) -> bool {
        bool::from(fingerprint(relayed_public_key).ct_eq(&self.fingerprint))
    }
}

/// SHA-256 fingerprint of a device-link public key under a dedicated domain.
pub fn fingerprint(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_DOMAIN);
    hash.update(public_key);
    hash.finalize().into()
}

/// New-device state. The X25519 private key and typed code never leave this
/// opaque, single-use handle.
pub struct NewDeviceLink {
    session_id: [u8; 16],
    public: [u8; 32],
    secrets: DeviceLinkSecrets,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct DeviceLinkSecrets {
    private: [u8; 32],
    typed_code: String,
}

impl std::fmt::Debug for NewDeviceLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewDeviceLink")
            .field("session_id", &self.session_id)
            .field("public", &self.public)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl NewDeviceLink {
    pub fn generate(session_id: [u8; 16]) -> Result<Self, CoreError> {
        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut *secret_bytes)
            .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self {
            session_id,
            public,
            secrets: DeviceLinkSecrets {
                private: *secret_bytes,
                typed_code: generate_typed_code()?,
            },
        })
    }

    pub fn qr(&self) -> DeviceLinkQr {
        DeviceLinkQr {
            session_id: self.session_id,
            fingerprint: fingerprint(&self.public),
        }
    }

    /// The one-time public key uploaded separately for the approver to fetch.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// The separate code the person types on the approving device. It is not
    /// included in [`DeviceLinkQr`].
    pub fn typed_code(&self) -> &str {
        &self.secrets.typed_code
    }

    /// Consume the one-time receiver state and try to open sealed account
    /// material. Success and failure both destroy the link secret and code, so
    /// callers cannot retry a link after a typo or forged blob.
    ///
    /// ```compile_fail
    /// use beebeeb_core::device_link::{NewDeviceLink, SealedAccountKeyMaterial};
    /// let link = NewDeviceLink::generate([1; 16]).unwrap();
    /// let sealed = SealedAccountKeyMaterial::from_parts(
    ///     [1; 16], [2; 32], [3; 32], [4; 12], vec![0; 48],
    /// ).unwrap();
    /// let retry = sealed.clone();
    /// let _ = link.open("K7QM-4WTD", sealed);
    /// let _ = link.open("K7QM-4WTD", retry); // the attempt consumed `link`
    /// ```
    pub fn open(self, typed_code: &str, sealed: SealedAccountKeyMaterial) -> Result<AccountKeyMaterial, CoreError> {
        if sealed.session_id != self.session_id || sealed.recipient_public != self.public {
            return Err(CoreError::Decryption);
        }
        let supplied_code = normalize_typed_code(typed_code).map_err(|_| CoreError::Decryption)?;
        let expected_code = normalize_typed_code(&self.secrets.typed_code).map_err(|_| CoreError::Decryption)?;
        if !bool::from(supplied_code[..].ct_eq(&expected_code[..])) {
            return Err(CoreError::Decryption);
        }
        let secret = StaticSecret::from(self.secrets.private);
        let shared = secret.diffie_hellman(&PublicKey::from(sealed.approver_public));
        if !shared.was_contributory() {
            return Err(CoreError::Decryption);
        }
        let key = qr_seal_key(shared.as_bytes(), &expected_code).map_err(|_| CoreError::Decryption)?;
        let aad = qr_seal_aad(&sealed.session_id, &sealed.recipient_public, &sealed.approver_public);
        let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| CoreError::Decryption)?;
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&sealed.nonce),
                    Payload {
                        msg: &sealed.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::Decryption)?,
        );
        if plaintext.len() != 32 {
            return Err(CoreError::Decryption);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(AccountKeyMaterial {
            master_key: MasterKey::from_zeroizing(bytes),
        })
    }

    /// Consume this link to make its one allowed camera-less attempt. The
    /// generated code is moved into SPAKE2 and wiped before this returns.
    ///
    /// ```compile_fail
    /// use beebeeb_core::device_link::NewDeviceLink;
    /// let link = NewDeviceLink::generate([1; 16]).unwrap();
    /// let _ = link.start_pake();
    /// let _ = link.start_pake(); // the attempt consumed `link`
    /// ```
    pub fn start_pake(self) -> Result<(TypedCodePake, Vec<u8>), CoreError> {
        start_pake(&self.secrets.typed_code, &self.session_id, TypedCodeRole::NewDevice)
    }
}

/// Opaque account-key material passed between core operations without a raw
/// byte return.
pub struct AccountKeyMaterial {
    master_key: MasterKey,
}

impl std::fmt::Debug for AccountKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKeyMaterial([REDACTED])")
    }
}

impl AccountKeyMaterial {
    pub fn from_master_key(master_key: MasterKey) -> Self {
        Self { master_key }
    }

    pub fn into_master_key(self) -> MasterKey {
        self.master_key
    }
}

/// Relay-safe encrypted account material. Its ciphertext is public, but its
/// fields are kept structured so callers cannot accidentally omit AAD inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAccountKeyMaterial {
    session_id: [u8; 16],
    recipient_public: [u8; 32],
    approver_public: [u8; 32],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedAccountKeyMaterial {
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn recipient_public(&self) -> &[u8; 32] {
        &self.recipient_public
    }

    pub fn approver_public(&self) -> &[u8; 32] {
        &self.approver_public
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn from_parts(
        session_id: [u8; 16],
        recipient_public: [u8; 32],
        approver_public: [u8; 32],
        nonce: [u8; NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Result<Self, CoreError> {
        if ciphertext.len() != 48 {
            return Err(CoreError::InvalidInput(format!(
                "device-link ciphertext must be 48 bytes, got {}",
                ciphertext.len()
            )));
        }
        Ok(Self {
            session_id,
            recipient_public,
            approver_public,
            nonce,
            ciphertext,
        })
    }
}

/// Verify the QR fingerprint and seal account material to its X25519 key.
pub fn seal_for_new_device(
    qr: &DeviceLinkQr,
    relayed_public_key: &[u8; 32],
    typed_code: &str,
    material: AccountKeyMaterial,
) -> Result<SealedAccountKeyMaterial, CoreError> {
    if !qr.verify_public_key(relayed_public_key) {
        return Err(CoreError::InvalidInput(
            "device-link public key does not match QR fingerprint".into(),
        ));
    }
    let approver_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let approver_public = PublicKey::from(&approver_secret).to_bytes();
    let shared = approver_secret.diffie_hellman(&PublicKey::from(*relayed_public_key));
    if !shared.was_contributory() {
        return Err(CoreError::InvalidInput(
            "device-link recipient public key is non-contributory".into(),
        ));
    }
    let code = normalize_typed_code(typed_code)?;
    let key = qr_seal_key(shared.as_bytes(), &code)?;
    let aad = qr_seal_aad(&qr.session_id, relayed_public_key, &approver_public);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    let cipher =
        Aes256Gcm::new_from_slice(&*key).map_err(|_| CoreError::Encryption("invalid device-link seal key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: material.master_key.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Encryption("device-link sealing failed".into()))?;
    Ok(SealedAccountKeyMaterial {
        session_id: qr.session_id,
        recipient_public: *relayed_public_key,
        approver_public,
        nonce,
        ciphertext,
    })
}

fn qr_seal_key(shared_secret: &[u8; 32], code: &[u8; 8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let mut input = Zeroizing::new([0u8; 40]);
    input[..32].copy_from_slice(shared_secret);
    input[32..].copy_from_slice(code);
    let hk = Hkdf::<Sha256>::new(None, &*input);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(QR_KEY_INFO, &mut *key)
        .map_err(|_| CoreError::Kdf("device-link key derivation failed".into()))?;
    Ok(key)
}

fn qr_seal_aad(session_id: &[u8; 16], recipient_public: &[u8; 32], approver_public: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(QR_AAD_DOMAIN.len() + 80);
    aad.extend_from_slice(QR_AAD_DOMAIN);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(recipient_public);
    aad.extend_from_slice(approver_public);
    aad
}

fn generate_typed_code() -> Result<String, CoreError> {
    let mut random = [0u8; 8];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    let mut code = String::with_capacity(9);
    for (index, byte) in random.into_iter().enumerate() {
        if index == 4 {
            code.push('-');
        }
        code.push(CODE_ALPHABET[(byte & 31) as usize] as char);
    }
    Ok(code)
}

fn normalize_typed_code(code: &str) -> Result<Zeroizing<[u8; 8]>, CoreError> {
    let mut normalized = Zeroizing::new([0u8; 8]);
    let mut len = 0usize;
    for byte in code.bytes() {
        if byte == b'-' || byte.is_ascii_whitespace() {
            continue;
        }
        let byte = byte.to_ascii_uppercase();
        if len >= normalized.len() || !CODE_ALPHABET.contains(&byte) {
            return Err(CoreError::InvalidInput(
                "device-link code must contain eight valid characters".into(),
            ));
        }
        normalized[len] = byte;
        len += 1;
    }
    if len != normalized.len() {
        return Err(CoreError::InvalidInput(
            "device-link code must contain eight valid characters".into(),
        ));
    }
    Ok(normalized)
}

/// Role in the typed-code PAKE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypedCodeRole {
    NewDevice,
    Approver,
}

/// Single-use SPAKE2 attempt for the typed-code-only path.
///
/// The relay receives only the two 33-byte messages, so it has no verifier for
/// offline guesses. Consuming `self` in [`Self::finish`] limits each local link
/// attempt to one peer message. On the new device it can only be constructed by
/// consuming [`NewDeviceLink`], so QR and PAKE cannot retry the same link/code.
pub struct TypedCodePake {
    state: Spake2<Ed25519Group>,
}

impl std::fmt::Debug for TypedCodePake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TypedCodePake([REDACTED])")
    }
}

impl TypedCodePake {
    pub fn start_approver(code: &str, session_id: &[u8; 16]) -> Result<(Self, Vec<u8>), CoreError> {
        start_pake(code, session_id, TypedCodeRole::Approver)
    }

    pub fn finish(self, peer_message: &[u8]) -> Result<TypedCodeChannel, CoreError> {
        let shared = Zeroizing::new(self.state.finish(peer_message).map_err(|_| CoreError::Decryption)?);
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(PAKE_KEY_INFO, &mut *key)
            .map_err(|_| CoreError::Kdf("typed-code channel derivation failed".into()))?;
        Ok(TypedCodeChannel { key })
    }
}

fn start_pake(code: &str, session_id: &[u8; 16], role: TypedCodeRole) -> Result<(TypedCodePake, Vec<u8>), CoreError> {
    let password = normalize_typed_code(code)?;
    let mut new_device_identity = Vec::with_capacity(PAKE_IDENTITY_DOMAIN.len() + session_id.len() + 1);
    new_device_identity.extend_from_slice(PAKE_IDENTITY_DOMAIN);
    new_device_identity.extend_from_slice(session_id);
    new_device_identity.push(0);
    let mut approver_identity = Vec::with_capacity(PAKE_IDENTITY_DOMAIN.len() + session_id.len() + 1);
    approver_identity.extend_from_slice(PAKE_IDENTITY_DOMAIN);
    approver_identity.extend_from_slice(session_id);
    approver_identity.push(1);
    let password_bytes: &[u8] = &password[..];
    let password = Password::new(password_bytes);
    let new_device_identity = Identity::new(&new_device_identity);
    let approver_identity = Identity::new(&approver_identity);
    let (state, outbound) = match role {
        TypedCodeRole::NewDevice => {
            Spake2::<Ed25519Group>::start_a(&password, &new_device_identity, &approver_identity)
        }
        TypedCodeRole::Approver => Spake2::<Ed25519Group>::start_b(&password, &new_device_identity, &approver_identity),
    };
    Ok((TypedCodePake { state }, outbound))
}

/// Opaque channel established by one successful typed-code PAKE attempt.
pub struct TypedCodeChannel {
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for TypedCodeChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TypedCodeChannel([REDACTED])")
    }
}

/// Account material sealed through the typed-code PAKE channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakeSealedAccountKeyMaterial {
    session_id: [u8; 16],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl PakeSealedAccountKeyMaterial {
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn from_parts(session_id: [u8; 16], nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Result<Self, CoreError> {
        if ciphertext.len() != 48 {
            return Err(CoreError::InvalidInput(format!(
                "typed-code ciphertext must be 48 bytes, got {}",
                ciphertext.len()
            )));
        }
        Ok(Self {
            session_id,
            nonce,
            ciphertext,
        })
    }
}

impl TypedCodeChannel {
    /// Consume the PAKE channel and seal account material for relay.
    pub fn seal(
        self,
        session_id: [u8; 16],
        material: AccountKeyMaterial,
    ) -> Result<PakeSealedAccountKeyMaterial, CoreError> {
        let aad = pake_aad(&session_id);
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&*self.key)
            .map_err(|_| CoreError::Encryption("invalid typed-code channel key".into()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: material.master_key.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::Encryption("typed-code sealing failed".into()))?;
        Ok(PakeSealedAccountKeyMaterial {
            session_id,
            nonce,
            ciphertext,
        })
    }

    /// Consume the PAKE channel and open relayed account material.
    pub fn open(self, sealed: PakeSealedAccountKeyMaterial) -> Result<AccountKeyMaterial, CoreError> {
        let aad = pake_aad(&sealed.session_id);
        let cipher = Aes256Gcm::new_from_slice(&*self.key).map_err(|_| CoreError::Decryption)?;
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&sealed.nonce),
                    Payload {
                        msg: &sealed.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::Decryption)?,
        );
        if plaintext.len() != 32 {
            return Err(CoreError::Decryption);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(AccountKeyMaterial {
            master_key: MasterKey::from_zeroizing(bytes),
        })
    }
}

fn pake_aad(session_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAKE_AAD_DOMAIN.len() + session_id.len());
    aad.extend_from_slice(PAKE_AAD_DOMAIN);
    aad.extend_from_slice(session_id);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MasterKey;

    #[test]
    fn qr_and_typed_code_are_separate_and_sealed_material_is_bound() {
        let new_device = NewDeviceLink::generate([4u8; 16]).unwrap();
        assert_eq!(new_device.typed_code().len(), 9);
        assert_eq!(&new_device.typed_code()[4..5], "-");
        let qr = new_device.qr();
        assert!(qr.verify_public_key(new_device.public_key()));
        let code = new_device.typed_code().to_owned();
        let alternate = code.to_ascii_lowercase().replace('-', " ");

        let material = AccountKeyMaterial::from_master_key(MasterKey::from_bytes([8u8; 32]));
        let sealed = seal_for_new_device(&qr, new_device.public_key(), &alternate, material).unwrap();
        let opened = new_device.open(&code, sealed).unwrap().into_master_key();
        assert_eq!(opened.as_bytes(), &[8u8; 32]);
    }

    #[test]
    fn qr_seal_rejects_wrong_code_like_a_forged_blob() {
        let new_device = NewDeviceLink::generate([4u8; 16]).unwrap();
        let qr = new_device.qr();
        let code = new_device.typed_code().to_owned();
        let mut wrong_code = code.clone().into_bytes();
        wrong_code[0] = if wrong_code[0] == b'2' { b'3' } else { b'2' };
        let wrong_code = String::from_utf8(wrong_code).unwrap();
        let material = AccountKeyMaterial::from_master_key(MasterKey::from_bytes([8u8; 32]));
        let sealed = seal_for_new_device(&qr, new_device.public_key(), &code, material).unwrap();
        assert!(matches!(
            new_device.open(&wrong_code, sealed),
            Err(CoreError::Decryption)
        ));
    }

    #[test]
    fn qr_seal_rejects_forgery_with_the_same_error() {
        let new_device = NewDeviceLink::generate([4u8; 16]).unwrap();
        let qr = new_device.qr();
        let code = new_device.typed_code().to_owned();
        let material = AccountKeyMaterial::from_master_key(MasterKey::from_bytes([8u8; 32]));
        let sealed = seal_for_new_device(&qr, new_device.public_key(), &code, material).unwrap();
        let mut ciphertext = sealed.ciphertext().to_vec();
        ciphertext[0] ^= 1;
        let forged = SealedAccountKeyMaterial::from_parts(
            *sealed.session_id(),
            *sealed.recipient_public(),
            *sealed.approver_public(),
            *sealed.nonce(),
            ciphertext,
        )
        .unwrap();
        assert!(matches!(new_device.open(&code, forged), Err(CoreError::Decryption)));
    }

    #[test]
    fn low_order_recipient_is_rejected() {
        let qr = DeviceLinkQr::from_parts([4u8; 16], fingerprint(&[0u8; 32]));
        let material = AccountKeyMaterial::from_master_key(MasterKey::from_bytes([8u8; 32]));
        assert!(seal_for_new_device(&qr, &[0u8; 32], "K7QM-4WTD", material).is_err());
    }

    #[test]
    fn typed_code_pake_agrees_only_for_the_same_code() {
        let session = [3u8; 16];
        let new_device = NewDeviceLink::generate(session).unwrap();
        let code = new_device.typed_code().to_owned();
        let (alice, alice_message) = new_device.start_pake().unwrap();
        let (bob, bob_message) = TypedCodePake::start_approver(&code, &session).unwrap();
        let alice = alice.finish(&bob_message).unwrap();
        let bob = bob.finish(&alice_message).unwrap();
        let sealed = alice
            .seal(
                [5u8; 16],
                AccountKeyMaterial::from_master_key(MasterKey::from_bytes([6u8; 32])),
            )
            .unwrap();
        let opened = bob.open(sealed).unwrap().into_master_key();
        assert_eq!(opened.as_bytes(), &[6u8; 32]);
    }

    #[test]
    fn typed_code_pake_wrong_code_cannot_open() {
        let session = [3u8; 16];
        let new_device = NewDeviceLink::generate(session).unwrap();
        let mut wrong_code = new_device.typed_code().as_bytes().to_vec();
        wrong_code[0] = if wrong_code[0] == b'2' { b'3' } else { b'2' };
        let wrong_code = String::from_utf8(wrong_code).unwrap();
        let (alice, alice_message) = new_device.start_pake().unwrap();
        let (mallory, mallory_message) = TypedCodePake::start_approver(&wrong_code, &session).unwrap();
        let alice = alice.finish(&mallory_message).unwrap();
        let mallory = mallory.finish(&alice_message).unwrap();
        let sealed = alice
            .seal(
                [5u8; 16],
                AccountKeyMaterial::from_master_key(MasterKey::from_bytes([6u8; 32])),
            )
            .unwrap();
        assert!(mallory.open(sealed).is_err());
    }

    #[test]
    fn link_secret_container_wipes_on_every_drop_path() {
        fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        requires_zeroize_on_drop::<DeviceLinkSecrets>();
    }
}
