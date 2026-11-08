//! Pure cryptographic primitives for approving a new device.
//!
//! This module performs no network or storage I/O. A relay transports the QR
//! fields, one-shot PAKE messages, and sealed blob without learning account
//! key material. The legacy transfer words, Constellation codec, and CLI auth
//! protocol must not be used to move account keys.
//!
//! # Two paths
//!
//! **QR path** ([`seal_for_new_device`], [`NewDeviceLink::open`]). The new
//! device shows a QR ([`NewDeviceLink::qr_payload`]) that commits to its
//! one-time X25519 key and carries its canonical device name. The approver
//! hands the raw scanned text to [`DeviceLinkQr::parse`]; there is no
//! constructor from loose bytes, so the fingerprint and the name can only come
//! from a scan. The approver shows the scanned name
//! ([`DeviceLinkQr::device_name`]), never the relay's report, and the seal
//! refuses a relayed name that differs from it (Guus's ruling of 2026-11-07,
//! "bind the name into the QR now"). The approver checks the relayed key
//! against the scanned fingerprint and seals to it. **Only that check stops a
//! key substitution.** The typed code is mixed into the seal key, but it gives
//! no protection against a substituted key: whoever holds the substituted
//! private key knows the X25519 secret and can try all 2^40 codes offline
//! against the 48-byte sealed blob. A fingerprint that did not come from a
//! camera scan of the new device's own screen (for example one computed from a
//! server-relayed key on a computer without a camera) protects nothing; such an
//! approver must use the typed-code path.
//!
//! **Typed-code path** ([`TypedCodeApprover`], [`NewDeviceLink::answer_typed_code`]).
//! SPAKE2 over Ed25519 (the `spake2` crate's fixed M and N; asymmetric A/B
//! roles: the new device is A, the approver is B), keyed by the 8-symbol code,
//! with explicit key confirmation in both directions (the 1783 design's D4/D5
//! with its SPAKE2 amendment). The relay carries one message per role, so the
//! approver speaks first:
//!
//! 1. Approver → relay: `0x02 ‖ SPAKE2(B)` (34 bytes).
//! 2. New device → relay: `0x02 ‖ SPAKE2(A) ‖ r ‖ Td` (82 bytes). `r` is 16
//!    fresh random bytes; `Td` is the new device's confirmation tag.
//! 3. The approver checks `Td` **before it seals anything**. A wrong code, a
//!    forged message, or device facts the server rewrote all fail here, and the
//!    approver sees the failure ([`TypedCodeApprover::confirm`] returns
//!    [`CoreError::Decryption`]).
//! 4. Approver → relay: nonce and `Tb ‖ AES-256-GCM(master key)` (80 bytes).
//!    The new device checks `Tb` before it opens the payload.
//!
//! Transcript and keys: `ADa = SHA-256(PAKE_ADA_DOMAIN ‖ lv(sid) ‖ lv(r) ‖
//! lv(device_name))` with the name in its [`canonical_device_name`] form;
//! `TH = SHA-256(PAKE_TRANSCRIPT_DOMAIN ‖ lv(sid) ‖ lv(ADa) ‖ lv(A) ‖ lv(B))`;
//! three keys are HKDF-SHA256 with salt `TH` over the SPAKE2 output, one per
//! confirmation direction and one for the payload; `Td = HMAC(k_td, TH)`,
//! `Tb = HMAC(k_tb, TH)`. `lv` is a `u32` big-endian length prefix.
//!
//! # Residuals
//!
//! `spake2` 0.4 copies the code into its own `Password` and state and keeps the
//! secret scalars; none of them derive `Zeroize`, so they are freed without
//! being wiped. Core's own copies (the normalised code, the SPAKE2 output and
//! every derived key) are `Zeroizing`. The window is one five-minute,
//! single-use link, during which both devices hold the master key anyway.
//! `sha2`/`hmac` cannot wipe their block buffers, nor curve25519-dalek its
//! scalar-multiplication temporaries (the 1783 design's D2 residual).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
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
pub(crate) const PAKE_IDENTITY_DOMAIN: &[u8] = b"beebeeb/device-link/pake-identity/v2";
pub(crate) const PAKE_ADA_DOMAIN: &[u8] = b"beebeeb/device-link/pake-ada/v2";
pub(crate) const PAKE_TRANSCRIPT_DOMAIN: &[u8] = b"beebeeb/device-link/pake-transcript/v2";
pub(crate) const PAKE_CONFIRM_NEW_DEVICE_INFO: &[u8] = b"beebeeb/device-link/pake-confirm/v2/new-device";
pub(crate) const PAKE_CONFIRM_APPROVER_INFO: &[u8] = b"beebeeb/device-link/pake-confirm/v2/approver";
pub(crate) const PAKE_KEY_INFO: &[u8] = b"beebeeb/device-link/pake-seal/v2/key";
pub(crate) const PAKE_AAD_DOMAIN: &[u8] = b"beebeeb/device-link/pake-seal/v2";

/// Text prefix of the QR payload: `beebeeb-link:v2:` followed by the unpadded
/// base64url form of `session_id (16) ‖ fingerprint (32) ‖ device_name`, the
/// name as its [`canonical_device_name`] UTF-8 (1 to [`MAX_DEVICE_NAME_BYTES`]
/// bytes). Version 2 replaced the unshipped `v1` (no name) with the ruling of
/// 2026-11-07; a `v1` payload is refused.
pub const QR_PAYLOAD_PREFIX: &str = "beebeeb-link:v2:";
/// Most Unicode scalars a canonical device name keeps.
pub const MAX_DEVICE_NAME_SCALARS: usize = 64;
/// Most UTF-8 bytes a canonical device name keeps (the relay's own limit).
pub const MAX_DEVICE_NAME_BYTES: usize = 160;

const NONCE_LEN: usize = 12;
const CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
/// Session id and fingerprint, before the name.
const QR_FIXED_BYTES: usize = 16 + 32;
/// The longest payload body: the fixed part and the longest canonical name.
const QR_MAX_PAYLOAD_BYTES: usize = QR_FIXED_BYTES + MAX_DEVICE_NAME_BYTES;
/// Unpadded base64url length of [`QR_MAX_PAYLOAD_BYTES`].
const QR_MAX_BODY_CHARS: usize = QR_MAX_PAYLOAD_BYTES.div_ceil(3) * 4;
const PAKE_WIRE_VERSION: u8 = 2;
const SPAKE2_SIDE_A: u8 = b'A';
const SPAKE2_SIDE_B: u8 = b'B';
const SPAKE2_MESSAGE_LEN: usize = 33;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 32;
const APPROVER_MESSAGE_LEN: usize = 1 + SPAKE2_MESSAGE_LEN;
const NEW_DEVICE_MESSAGE_LEN: usize = 1 + SPAKE2_MESSAGE_LEN + SALT_LEN + TAG_LEN;
const SEALED_MASTER_KEY_LEN: usize = 32 + 16;
const PAKE_SEALED_LEN: usize = TAG_LEN + SEALED_MASTER_KEY_LEN;
/// The SPAKE2 identity role bytes and the payload AAD's direction byte.
const ROLE_NEW_DEVICE: u8 = 0;
const ROLE_APPROVER: u8 = 1;
/// Bytes `curve25519_dalek::Scalar::random` draws (spake2 0.4's only RNG use).
const SCALAR_SEED_LEN: usize = 64;

type HmacSha256 = Hmac<Sha256>;

/// Public fields encoded in the device-link QR. It deliberately carries no
/// approval code. An approver obtains one only from scanned text
/// ([`Self::parse`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLinkQr {
    session_id: [u8; 16],
    fingerprint: [u8; 32],
    device_name: String,
}

impl DeviceLinkQr {
    /// Parse the raw text a camera scanned from the new device's QR. Leading
    /// and trailing ASCII white space is ignored. Anything else that is not
    /// exactly [`QR_PAYLOAD_PREFIX`] plus the base64url of 48 bytes and a
    /// canonical device name is refused: another prefix (the old `v1` too), a
    /// missing or empty name, a name that is not UTF-8, longer than
    /// [`MAX_DEVICE_NAME_BYTES`], or not in its [`canonical_device_name`] form.
    pub fn parse(scanned: &str) -> Result<Self, CoreError> {
        let refused = || CoreError::InvalidInput("not a Beebeeb device-link QR".into());
        let body = scanned
            .trim_matches(|c: char| c.is_ascii_whitespace())
            .strip_prefix(QR_PAYLOAD_PREFIX)
            .ok_or_else(refused)?;
        if body.len() > QR_MAX_BODY_CHARS {
            return Err(refused());
        }
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| refused())?;
        if bytes.len() <= QR_FIXED_BYTES || bytes.len() > QR_MAX_PAYLOAD_BYTES {
            return Err(refused());
        }
        let device_name = std::str::from_utf8(&bytes[QR_FIXED_BYTES..]).map_err(|_| refused())?;
        if canonical_device_name(device_name).map_err(|_| refused())? != device_name {
            return Err(refused());
        }
        let mut session_id = [0u8; 16];
        let mut fingerprint = [0u8; 32];
        session_id.copy_from_slice(&bytes[..16]);
        fingerprint.copy_from_slice(&bytes[16..QR_FIXED_BYTES]);
        Ok(Self {
            session_id,
            fingerprint,
            device_name: device_name.to_owned(),
        })
    }

    /// The text to render as the QR.
    pub fn payload(&self) -> String {
        let mut bytes = Vec::with_capacity(QR_FIXED_BYTES + self.device_name.len());
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.fingerprint);
        bytes.extend_from_slice(self.device_name.as_bytes());
        format!("{QR_PAYLOAD_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// The new device's canonical name as it showed it in its own QR. This is
    /// the name an approver shows, never the relay's report: the relay's name
    /// is unauthenticated, the scanned one came from the device's screen.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Whether the relay reports the same name the QR carries. The comparison
    /// is exact: the new device sends the canonical form, and the relay's own
    /// trim never changes it, so any difference is a rewrite.
    pub fn matches_relayed_name(&self, relayed_device_name: &str) -> bool {
        self.device_name == relayed_device_name
    }

    /// Check that the relayed public key matches the fingerprint captured in
    /// the QR before sealing any account material.
    pub fn verify_public_key(&self, relayed_public_key: &[u8; 32]) -> bool {
        bool::from(fingerprint(relayed_public_key).ct_eq(&self.fingerprint))
    }
}

/// SHA-256 fingerprint of a device-link public key under a dedicated domain.
/// Crate-private: a fingerprint computed from a relayed key would verify any
/// key the relay chose (see the module documentation).
pub(crate) fn fingerprint(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_DOMAIN);
    hash.update(public_key);
    hash.finalize().into()
}

/// The one canonical form of the name a new device reports about itself.
///
/// Removes every control character (`char::is_control`), core's display
/// controls (bidi embeddings, overrides, isolates and marks, zero-width space
/// and the others in `invisible::ACTOR_NAME_STRIPPED`) and also ZWNJ and ZWJ;
/// trims Unicode white space (`str::trim`, as the relay does); keeps at most
/// [`MAX_DEVICE_NAME_SCALARS`] scalars and [`MAX_DEVICE_NAME_BYTES`] bytes, cut
/// at a scalar boundary, and trims the end again. A name with nothing left is
/// `InvalidInput`. The function is idempotent; the new device sends this form,
/// so the relay's own trim never changes it, and the approver refuses a name
/// that is not in it.
pub fn canonical_device_name(raw: &str) -> Result<String, CoreError> {
    let filtered: String = raw.chars().filter(|c| !is_name_control(*c)).collect();
    let mut name = String::with_capacity(filtered.len().min(MAX_DEVICE_NAME_BYTES));
    for (count, c) in filtered.trim().chars().enumerate() {
        if count >= MAX_DEVICE_NAME_SCALARS || name.len() + c.len_utf8() > MAX_DEVICE_NAME_BYTES {
            break;
        }
        name.push(c);
    }
    let kept = name.trim_end().len();
    name.truncate(kept);
    if name.is_empty() {
        return Err(CoreError::InvalidInput("device name has no visible character".into()));
    }
    Ok(name)
}

fn is_name_control(c: char) -> bool {
    c.is_control()
        || c == '\u{200C}'
        || c == '\u{200D}'
        || crate::invisible::in_ranges(&crate::invisible::ACTOR_NAME_STRIPPED, c)
}

/// New-device state. The X25519 private key and typed code never leave this
/// opaque, single-use handle.
pub struct NewDeviceLink {
    session_id: [u8; 16],
    public: [u8; 32],
    device_name: String,
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
            .field("device_name", &self.device_name)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl NewDeviceLink {
    /// Start a link. `device_name` is canonicalised ([`canonical_device_name`]);
    /// send [`Self::device_name`] to the relay, never the raw input, because the
    /// typed-code confirmation binds exactly that form.
    pub fn generate(session_id: [u8; 16], device_name: &str) -> Result<Self, CoreError> {
        let device_name = canonical_device_name(device_name)?;
        let secret_bytes = random_array::<32>()?;
        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self {
            session_id,
            public,
            device_name,
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
            device_name: self.device_name.clone(),
        }
    }

    /// The text to show as this link's QR ([`DeviceLinkQr::payload`]).
    pub fn qr_payload(&self) -> String {
        self.qr().payload()
    }

    /// The one-time public key uploaded separately for the approver to fetch.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    /// The canonical device name to send to the relay.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// The separate code the person types on the approving device. It is not
    /// included in [`DeviceLinkQr`].
    pub fn typed_code(&self) -> &str {
        &self.secrets.typed_code
    }

    /// QR path: consume the one-time receiver state and try to open sealed
    /// account material. Success and failure both destroy the link secret and
    /// code, so callers cannot retry a link after a forged blob. The link uses
    /// its own code; the person types the code only on the approver.
    ///
    /// ```compile_fail
    /// use beebeeb_core::device_link::{NewDeviceLink, SealedAccountKeyMaterial};
    /// let link = NewDeviceLink::generate([1; 16], "Laptop").unwrap();
    /// let sealed = SealedAccountKeyMaterial::from_parts(
    ///     [1; 16], [2; 32], [3; 32], [4; 12], vec![0; 48],
    /// ).unwrap();
    /// let retry = sealed.clone();
    /// let _ = link.open(sealed);
    /// let _ = link.open(retry); // the attempt consumed `link`
    /// ```
    pub fn open(self, sealed: SealedAccountKeyMaterial) -> Result<AccountKeyMaterial, CoreError> {
        if sealed.session_id != self.session_id || sealed.recipient_public != self.public {
            return Err(CoreError::Decryption);
        }
        let code = normalize_typed_code(&self.secrets.typed_code).map_err(|_| CoreError::Decryption)?;
        let secret = StaticSecret::from(self.secrets.private);
        let shared = secret.diffie_hellman(&PublicKey::from(sealed.approver_public));
        if !shared.was_contributory() {
            return Err(CoreError::Decryption);
        }
        let key = qr_seal_key(shared.as_bytes(), &code).map_err(|_| CoreError::Decryption)?;
        let aad = qr_seal_aad(&sealed.session_id, &sealed.recipient_public, &sealed.approver_public);
        open_master_key(&key, &sealed.nonce, &sealed.ciphertext, &aad)
    }

    /// Typed-code path: consume this link to answer the approver's one SPAKE2
    /// message. Returns the receiver for the sealed payload and the message to
    /// relay (role `new_device`). The link is spent whatever happens next.
    ///
    /// `spake2` 0.4 copies the code into its own state and never wipes it (see
    /// the module's residuals); this handle's own copy is wiped on drop.
    ///
    /// ```compile_fail
    /// use beebeeb_core::device_link::NewDeviceLink;
    /// let link = NewDeviceLink::generate([1; 16], "Laptop").unwrap();
    /// let _ = link.answer_typed_code(&[0; 34]);
    /// let _ = link.answer_typed_code(&[0; 34]); // the attempt consumed `link`
    /// ```
    pub fn answer_typed_code(self, approver_message: &[u8]) -> Result<(TypedCodeReceiver, Vec<u8>), CoreError> {
        if approver_message.len() != APPROVER_MESSAGE_LEN || approver_message[0] != PAKE_WIRE_VERSION {
            return Err(malformed());
        }
        let message_b = &approver_message[1..];
        check_peer_element(message_b, SPAKE2_SIDE_B)?;
        let code = normalize_typed_code(&self.secrets.typed_code)?;
        let (state, message_a) = spake2_start(&code, &self.session_id, ROLE_NEW_DEVICE)?;
        let shared = Zeroizing::new(state.finish(message_b).map_err(|_| malformed())?);
        let salt = random_array::<SALT_LEN>()?;
        let facts = device_facts_hash(&self.session_id, &salt, &self.device_name)?;
        let keys = PakeKeys::derive(&shared, &self.session_id, &facts, &message_a, message_b)?;
        let new_device_tag = keys.tag(&keys.confirm_new_device)?;
        let approver_tag = keys.tag(&keys.confirm_approver)?;
        let mut outbound = Vec::with_capacity(NEW_DEVICE_MESSAGE_LEN);
        outbound.push(PAKE_WIRE_VERSION);
        outbound.extend_from_slice(&message_a);
        outbound.extend_from_slice(&*salt);
        outbound.extend_from_slice(&new_device_tag);
        Ok((
            TypedCodeReceiver {
                session_id: self.session_id,
                seal_key: keys.seal,
                approver_tag,
            },
            outbound,
        ))
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
        if ciphertext.len() != SEALED_MASTER_KEY_LEN {
            return Err(CoreError::InvalidInput(format!(
                "device-link ciphertext must be {SEALED_MASTER_KEY_LEN} bytes, got {}",
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

/// QR path: verify the scanned fingerprint and name, and seal account
/// material to the relayed X25519 key.
///
/// `qr` must come from [`DeviceLinkQr::parse`] over text scanned from the new
/// device's screen. `relayed_device_name` is the name the relay reports for
/// this link; a name that differs from [`DeviceLinkQr::device_name`] is refused
/// before anything is sealed. The fingerprint check is the only protection
/// against a substituted key: `typed_code` is mixed into the seal key, but
/// anyone holding the substituted private key can recover it offline (see the
/// module documentation). Without a scan, use the typed-code path.
pub fn seal_for_new_device(
    qr: &DeviceLinkQr,
    relayed_public_key: &[u8; 32],
    relayed_device_name: &str,
    typed_code: &str,
    material: AccountKeyMaterial,
) -> Result<SealedAccountKeyMaterial, CoreError> {
    if !qr.matches_relayed_name(relayed_device_name) {
        return Err(CoreError::InvalidInput(
            "the relayed device name is not the name in the scanned QR".into(),
        ));
    }
    if !qr.verify_public_key(relayed_public_key) {
        return Err(CoreError::InvalidInput(
            "device-link public key does not match QR fingerprint".into(),
        ));
    }
    let approver_secret = StaticSecret::from(*random_array::<32>()?);
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
    let (nonce, ciphertext) = seal_master_key(&key, &material, &aad)?;
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

fn seal_master_key(
    key: &[u8; 32],
    material: &AccountKeyMaterial,
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CoreError> {
    let nonce = *random_array::<NONCE_LEN>()?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::Encryption("invalid device-link key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: material.master_key.as_bytes(),
                aad,
            },
        )
        .map_err(|_| CoreError::Encryption("device-link sealing failed".into()))?;
    Ok((nonce, ciphertext))
}

fn open_master_key(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<AccountKeyMaterial, CoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::Decryption)?;
    let mut plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
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

fn random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>, CoreError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    Ok(bytes)
}

fn generate_typed_code() -> Result<String, CoreError> {
    let random = random_array::<8>()?;
    let mut code = String::with_capacity(9);
    for (index, byte) in random.iter().enumerate() {
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

fn malformed() -> CoreError {
    CoreError::InvalidInput("malformed device-link PAKE message".into())
}

/// Refuse a peer SPAKE2 message unless it is the expected side and a canonical,
/// decodable Edwards point that is not of small order.
fn check_peer_element(message: &[u8], side: u8) -> Result<(), CoreError> {
    if message.len() != SPAKE2_MESSAGE_LEN || message[0] != side {
        return Err(malformed());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&message[1..]);
    let point = CompressedEdwardsY(bytes).decompress().ok_or_else(malformed)?;
    if point.is_small_order() || point.compress().to_bytes() != bytes {
        return Err(malformed());
    }
    Ok(())
}

/// Hands spake2 the scalar seed core drew with `try_fill_bytes`, so a failing
/// OS RNG is an error before the exchange instead of a panic inside it.
/// Anything past the seed reads as zeros and is counted, so a spake2 or
/// curve25519-dalek change that draws more is refused, never used.
struct PreDrawnSeed {
    seed: Zeroizing<[u8; SCALAR_SEED_LEN]>,
    requested: usize,
}

impl PreDrawnSeed {
    fn draw() -> Result<Self, CoreError> {
        Ok(Self {
            seed: random_array::<SCALAR_SEED_LEN>()?,
            requested: 0,
        })
    }
}

impl RngCore for PreDrawnSeed {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let start = self.requested.min(SCALAR_SEED_LEN);
        let end = self.requested.saturating_add(dest.len()).min(SCALAR_SEED_LEN);
        let (seeded, rest) = dest.split_at_mut(end - start);
        seeded.copy_from_slice(&self.seed[start..end]);
        rest.fill(0);
        self.requested = self.requested.saturating_add(dest.len());
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for PreDrawnSeed {}

fn pake_identity(session_id: &[u8; 16], role: u8) -> Identity {
    let mut identity = Vec::with_capacity(PAKE_IDENTITY_DOMAIN.len() + session_id.len() + 1);
    identity.extend_from_slice(PAKE_IDENTITY_DOMAIN);
    identity.extend_from_slice(session_id);
    identity.push(role);
    Identity::new(&identity)
}

fn spake2_start(code: &[u8; 8], session_id: &[u8; 16], role: u8) -> Result<(Spake2<Ed25519Group>, Vec<u8>), CoreError> {
    let new_device = pake_identity(session_id, ROLE_NEW_DEVICE);
    let approver = pake_identity(session_id, ROLE_APPROVER);
    // spake2 0.4 copies the code into this `Password` and its state, unwiped
    // (module residuals).
    let password = Password::new(&code[..]);
    let mut seed = PreDrawnSeed::draw()?;
    let (state, message) = if role == ROLE_NEW_DEVICE {
        Spake2::<Ed25519Group>::start_a_with_rng(&password, &new_device, &approver, &mut seed)
    } else {
        Spake2::<Ed25519Group>::start_b_with_rng(&password, &new_device, &approver, &mut seed)
    };
    if seed.requested != SCALAR_SEED_LEN || message.len() != SPAKE2_MESSAGE_LEN {
        return Err(CoreError::Encryption("unexpected SPAKE2 randomness use".into()));
    }
    Ok((state, message))
}

fn update_lv(hash: &mut Sha256, bytes: &[u8]) -> Result<(), CoreError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| CoreError::InvalidInput("device-link field is too long".into()))?;
    hash.update(len.to_be_bytes());
    hash.update(bytes);
    Ok(())
}

/// The salted hash of the facts the new device reports about itself (ADa).
fn device_facts_hash(session_id: &[u8; 16], salt: &[u8; SALT_LEN], device_name: &str) -> Result<[u8; 32], CoreError> {
    let mut hash = Sha256::new();
    hash.update(PAKE_ADA_DOMAIN);
    update_lv(&mut hash, session_id)?;
    update_lv(&mut hash, salt)?;
    update_lv(&mut hash, device_name.as_bytes())?;
    Ok(hash.finalize().into())
}

/// Keys of one typed-code exchange, all bound to the transcript hash.
struct PakeKeys {
    transcript: [u8; 32],
    confirm_new_device: Zeroizing<[u8; 32]>,
    confirm_approver: Zeroizing<[u8; 32]>,
    seal: Zeroizing<[u8; 32]>,
}

impl PakeKeys {
    fn derive(
        shared: &[u8],
        session_id: &[u8; 16],
        facts: &[u8; 32],
        message_a: &[u8],
        message_b: &[u8],
    ) -> Result<Self, CoreError> {
        let mut hash = Sha256::new();
        hash.update(PAKE_TRANSCRIPT_DOMAIN);
        update_lv(&mut hash, session_id)?;
        update_lv(&mut hash, facts)?;
        update_lv(&mut hash, message_a)?;
        update_lv(&mut hash, message_b)?;
        let transcript: [u8; 32] = hash.finalize().into();
        let hk = Hkdf::<Sha256>::new(Some(&transcript), shared);
        let expand = |info: &[u8]| -> Result<Zeroizing<[u8; 32]>, CoreError> {
            let mut key = Zeroizing::new([0u8; 32]);
            hk.expand(info, &mut *key)
                .map_err(|_| CoreError::Kdf("typed-code key derivation failed".into()))?;
            Ok(key)
        };
        Ok(Self {
            transcript,
            confirm_new_device: expand(PAKE_CONFIRM_NEW_DEVICE_INFO)?,
            confirm_approver: expand(PAKE_CONFIRM_APPROVER_INFO)?,
            seal: expand(PAKE_KEY_INFO)?,
        })
    }

    fn tag(&self, key: &[u8; 32]) -> Result<[u8; TAG_LEN], CoreError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|_| CoreError::Kdf("invalid typed-code confirmation key".into()))?;
        mac.update(&self.transcript);
        Ok(mac.finalize().into_bytes().into())
    }
}

fn pake_aad(session_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAKE_AAD_DOMAIN.len() + session_id.len() + 1);
    aad.extend_from_slice(PAKE_AAD_DOMAIN);
    aad.extend_from_slice(session_id);
    // Direction: only the approver seals, only the new device opens.
    aad.push(ROLE_APPROVER);
    aad
}

/// Approver half of one typed-code attempt, after its SPAKE2 message (role
/// `approver`) went out.
pub struct TypedCodeApprover {
    session_id: [u8; 16],
    device_name: String,
    message_b: Vec<u8>,
    state: Spake2<Ed25519Group>,
}

impl std::fmt::Debug for TypedCodeApprover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedCodeApprover")
            .field("session_id", &self.session_id)
            .field("device_name", &self.device_name)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl TypedCodeApprover {
    /// Start an attempt for the link `session_id` whose relayed device name is
    /// `device_name`. The name must already be canonical
    /// ([`canonical_device_name`]): a relay that rewrites it is refused here
    /// rather than repaired. Show the person this exact name; the confirmation
    /// then proves the new device reported it. Returns the message to relay.
    pub fn start(typed_code: &str, session_id: &[u8; 16], device_name: &str) -> Result<(Self, Vec<u8>), CoreError> {
        if canonical_device_name(device_name)? != device_name {
            return Err(CoreError::InvalidInput("relayed device name is not canonical".into()));
        }
        let code = normalize_typed_code(typed_code)?;
        let (state, message_b) = spake2_start(&code, session_id, ROLE_APPROVER)?;
        let mut outbound = Vec::with_capacity(APPROVER_MESSAGE_LEN);
        outbound.push(PAKE_WIRE_VERSION);
        outbound.extend_from_slice(&message_b);
        Ok((
            Self {
                session_id: *session_id,
                device_name: device_name.to_owned(),
                message_b,
                state,
            },
            outbound,
        ))
    }

    /// The device name this attempt binds (not yet confirmed).
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Check the new device's answer before anything is sealed. The attempt is
    /// spent either way.
    ///
    /// `Err(CoreError::Decryption)`: the answer is well formed but its
    /// confirmation tag is wrong, so the code did not match or the device's
    /// facts were altered; show it to the person as a failed attempt. Any other
    /// error: the answer is malformed.
    pub fn confirm(self, new_device_message: &[u8]) -> Result<ConfirmedTypedApproval, CoreError> {
        if new_device_message.len() != NEW_DEVICE_MESSAGE_LEN || new_device_message[0] != PAKE_WIRE_VERSION {
            return Err(malformed());
        }
        let message_a = &new_device_message[1..1 + SPAKE2_MESSAGE_LEN];
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&new_device_message[1 + SPAKE2_MESSAGE_LEN..1 + SPAKE2_MESSAGE_LEN + SALT_LEN]);
        let presented = &new_device_message[1 + SPAKE2_MESSAGE_LEN + SALT_LEN..];
        check_peer_element(message_a, SPAKE2_SIDE_A)?;
        let shared = Zeroizing::new(self.state.finish(message_a).map_err(|_| malformed())?);
        let facts = device_facts_hash(&self.session_id, &salt, &self.device_name)?;
        let keys = PakeKeys::derive(&shared, &self.session_id, &facts, message_a, &self.message_b)?;
        let expected = keys.tag(&keys.confirm_new_device)?;
        if !bool::from(expected.ct_eq(presented)) {
            return Err(CoreError::Decryption);
        }
        let approver_tag = keys.tag(&keys.confirm_approver)?;
        Ok(ConfirmedTypedApproval {
            session_id: self.session_id,
            device_name: self.device_name,
            seal_key: keys.seal,
            approver_tag,
        })
    }
}

/// An approver attempt whose new device proved it knows the code and reported
/// [`Self::device_name`].
pub struct ConfirmedTypedApproval {
    session_id: [u8; 16],
    device_name: String,
    seal_key: Zeroizing<[u8; 32]>,
    approver_tag: [u8; TAG_LEN],
}

impl std::fmt::Debug for ConfirmedTypedApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmedTypedApproval")
            .field("session_id", &self.session_id)
            .field("device_name", &self.device_name)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl ConfirmedTypedApproval {
    /// The device name the new device reported, now authenticated.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Consume the confirmed attempt and seal account material for relay.
    pub fn seal(self, material: AccountKeyMaterial) -> Result<PakeSealedAccountKeyMaterial, CoreError> {
        let (nonce, sealed) = seal_master_key(&self.seal_key, &material, &pake_aad(&self.session_id))?;
        let mut ciphertext = Vec::with_capacity(PAKE_SEALED_LEN);
        ciphertext.extend_from_slice(&self.approver_tag);
        ciphertext.extend_from_slice(&sealed);
        Ok(PakeSealedAccountKeyMaterial { nonce, ciphertext })
    }
}

/// New-device half of a typed-code attempt after it answered: it opens only a
/// payload that carries the approver's confirmation tag.
pub struct TypedCodeReceiver {
    session_id: [u8; 16],
    seal_key: Zeroizing<[u8; 32]>,
    approver_tag: [u8; TAG_LEN],
}

impl std::fmt::Debug for TypedCodeReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedCodeReceiver")
            .field("session_id", &self.session_id)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl TypedCodeReceiver {
    /// Consume the receiver and open relayed account material. The approver's
    /// tag is checked first; both failures are `CoreError::Decryption`.
    pub fn open(self, sealed: PakeSealedAccountKeyMaterial) -> Result<AccountKeyMaterial, CoreError> {
        let (presented, ciphertext) = sealed.ciphertext.split_at(TAG_LEN);
        if !bool::from(self.approver_tag.ct_eq(presented)) {
            return Err(CoreError::Decryption);
        }
        open_master_key(&self.seal_key, &sealed.nonce, ciphertext, &pake_aad(&self.session_id))
    }
}

/// Account material sealed through the typed-code exchange: the approver's tag
/// followed by AES-256-GCM of the master key (80 bytes). The link session id is
/// held by both ends, not by this relayed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakeSealedAccountKeyMaterial {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl PakeSealedAccountKeyMaterial {
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// `Tb (32) ‖ AES-256-GCM ciphertext and tag (48)`, as relayed.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn from_parts(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Result<Self, CoreError> {
        if ciphertext.len() != PAKE_SEALED_LEN {
            return Err(CoreError::InvalidInput(format!(
                "typed-code ciphertext must be {PAKE_SEALED_LEN} bytes, got {}",
                ciphertext.len()
            )));
        }
        Ok(Self { nonce, ciphertext })
    }
}

#[cfg(test)]
mod tests;
