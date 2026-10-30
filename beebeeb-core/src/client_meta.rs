//! Encrypted sync-client metadata (task 1922): the `bbcm1.` envelope.
//!
//! Key: `HKDF-SHA256(ikm = master, salt = none, info = "beebeeb/client-meta/v1/key")`.
//! AAD: `"beebeeb/client-meta/v1" || u32_be(36) || record_key || u32_be(len(device_key))
//! || device_key || u8(field)`. Payload: `u16_be(len) || utf8 || zeros` padded to
//! `max(32, roundup(2 + len, 32))`. Envelope: `"bbcm1." || base64url-no-pad(nonce || ct || tag)`.
//! The module's tests were written before the implementation (the compile error is
//! in the lane's `red.log`).

use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::kdf::{FileKey, MasterKey};

// ── Wire constants (frozen in the 1922 spec, section 00) ────────────────────

/// Envelope prefix. Case-sensitive; anything else is `InvalidInput`.
pub const ENVELOPE_PREFIX: &str = "bbcm1.";
/// AAD domain tag: `"beebeeb/client-meta/v1"` (22 bytes).
pub const AAD_DOMAIN: &[u8; 22] = b"beebeeb/client-meta/v1";
/// HKDF-SHA256 `info` of the per-user client-metadata key.
pub const CLIENT_META_KEY_INFO: &[u8; 26] = b"beebeeb/client-meta/v1/key";

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// `nonce(12) || ciphertext || tag(16)` for the smallest 32-byte payload.
const MIN_BODY: usize = NONCE_LEN + 32 + TAG_LEN; // 60
/// Largest body: a 1056-byte padded payload (a 1024-byte text).
const MAX_BODY: usize = NONCE_LEN + 1056 + TAG_LEN; // 1084
/// Longest accepted UTF-8 plaintext.
const MAX_TEXT: usize = 1024;
/// Longest accepted envelope string (`bbcm1.` + base64url of [`MAX_BODY`]).
const MAX_ENVELOPE_CHARS: usize = 1452;

/// The four client-metadata fields. Codes 5 and 6 stay reserved (task 1922 Q3:
/// `current_file` and `detail` are discarded, never sealed).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientMetaField {
    DeviceHostname = 1,
    SessionName = 2,
    SessionLocalPath = 3,
    SessionRemotePath = 4,
}

impl TryFrom<u8> for ClientMetaField {
    type Error = CoreError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Ok(match code {
            1 => Self::DeviceHostname,
            2 => Self::SessionName,
            3 => Self::SessionLocalPath,
            4 => Self::SessionRemotePath,
            other => {
                return Err(CoreError::InvalidInput(format!(
                    "unknown client-meta field code {other} (codes 1-4 only)"
                )));
            }
        })
    }
}

/// The per-user client-metadata key:
/// `HKDF-SHA256(ikm = master, salt = none, info = "beebeeb/client-meta/v1/key")`.
///
/// Private to this module: a `FileKey` also fits `encrypt_chunk`, so the derived
/// key must never cross a binding boundary. Bindings use [`ClientMetaKey`], an
/// opaque handle that holds only this key.
fn client_meta_key(master: &MasterKey) -> FileKey {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(CLIENT_META_KEY_INFO, &mut *okm)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    FileKey::from_bytes(*okm)
}

/// An opaque holder for the derived client-metadata key.
///
/// Exists so the WASM/UniFFI handles can keep the derived key in Rust memory
/// without this module ever exporting the derivation or a `FileKey`.
pub struct ClientMetaKey {
    key: FileKey,
}

impl ClientMetaKey {
    /// Derive the client-metadata key from a master key.
    pub fn new(master: &MasterKey) -> Self {
        Self {
            key: client_meta_key(master),
        }
    }

    /// Seal one field. See [`seal_client_meta`].
    pub fn seal(
        &self,
        record_key: &Uuid,
        device_key: Option<&Uuid>,
        field: ClientMetaField,
        plaintext: &str,
    ) -> Result<String, CoreError> {
        let nonce = fresh_nonce()?;
        seal_with_nonce(&self.key, record_key, device_key, field, plaintext, &nonce)
    }

    /// Open one field. See [`open_client_meta`].
    pub fn open(
        &self,
        record_key: &Uuid,
        device_key: Option<&Uuid>,
        field: ClientMetaField,
        envelope: &str,
    ) -> Result<String, CoreError> {
        let aad = aad_for(record_key, device_key, field)?;
        open_envelope(&self.key, envelope, &aad)
    }

    /// Open many fields with one derived key. See [`open_client_meta_many`].
    pub fn open_many(&self, items: &[(Uuid, Option<Uuid>, ClientMetaField, String)]) -> Vec<Result<String, CoreError>> {
        items
            .iter()
            .map(|(record, device, field, envelope)| self.open(record, device.as_ref(), *field, envelope))
            .collect()
    }
}

/// Seal one client-metadata field into a `bbcm1.` envelope.
///
/// `device_key` is `None` for [`ClientMetaField::DeviceHostname`] and `Some` for
/// fields 2-4; any other combination is `InvalidInput`.
pub fn seal_client_meta(
    master: &MasterKey,
    record_key: &Uuid,
    device_key: Option<&Uuid>,
    field: ClientMetaField,
    plaintext: &str,
) -> Result<String, CoreError> {
    ClientMetaKey::new(master).seal(record_key, device_key, field, plaintext)
}

/// Open a `bbcm1.` envelope for one field.
pub fn open_client_meta(
    master: &MasterKey,
    record_key: &Uuid,
    device_key: Option<&Uuid>,
    field: ClientMetaField,
    envelope: &str,
) -> Result<String, CoreError> {
    ClientMetaKey::new(master).open(record_key, device_key, field, envelope)
}

/// Open many rows under ONE derived key. A bad row yields its own error.
pub fn open_client_meta_many(
    master: &MasterKey,
    items: &[(Uuid, Option<Uuid>, ClientMetaField, String)],
) -> Vec<Result<String, CoreError>> {
    ClientMetaKey::new(master).open_many(items)
}

/// Shorten a path/name for sealing: over 1024 UTF-8 bytes, keep the last 1021
/// bytes on a char boundary behind a leading `…`; otherwise unchanged.
pub fn fit_for_seal(s: &str) -> String {
    if s.len() <= MAX_TEXT {
        return s.to_string();
    }
    let mut start = s.len() - (MAX_TEXT - 3);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &s[start..])
}

// ── Internals ───────────────────────────────────────────────────────────────

/// `domain || u32_be(36) || record_key || u32_be(len(device_key)) || device_key || u8(field)`.
fn aad_for(record_key: &Uuid, device_key: Option<&Uuid>, field: ClientMetaField) -> Result<Vec<u8>, CoreError> {
    let record = record_key.hyphenated().to_string();
    let device = match (field, device_key) {
        (ClientMetaField::DeviceHostname, None) => String::new(),
        (ClientMetaField::DeviceHostname, Some(_)) => {
            return Err(CoreError::InvalidInput(
                "a device hostname (field 1) must not carry a device key".into(),
            ));
        }
        (_, Some(device)) => device.hyphenated().to_string(),
        (_, None) => {
            return Err(CoreError::InvalidInput(format!(
                "field {} requires its parent device key",
                field as u8
            )));
        }
    };

    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 4 + record.len() + 4 + device.len() + 1);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(
        &u32::try_from(record.len())
            .expect("a client-meta record key is at most 36 bytes")
            .to_be_bytes(),
    );
    aad.extend_from_slice(record.as_bytes());
    aad.extend_from_slice(
        &u32::try_from(device.len())
            .expect("a client-meta device key is at most 36 bytes")
            .to_be_bytes(),
    );
    aad.extend_from_slice(device.as_bytes());
    aad.push(field as u8);
    Ok(aad)
}

/// `max(32, roundup(2 + len, 32))`: one padding rule for seal and open.
fn padded_len(text_len: usize) -> usize {
    (2 + text_len).div_ceil(32) * 32
}

/// `u16_be(len) || utf8 || zeros` padded to [`padded_len`].
fn payload_for(plaintext: &str) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let bytes = plaintext.as_bytes();
    if bytes.len() > MAX_TEXT {
        // Fixed message: the actual length is exactly what padding hides.
        return Err(CoreError::InvalidInput(
            "client-meta plaintext exceeds the 1024-byte limit (use fit_for_seal)".into(),
        ));
    }
    let padded = padded_len(bytes.len());
    let mut payload = Zeroizing::new(Vec::with_capacity(padded));
    payload.extend_from_slice(
        &u16::try_from(bytes.len())
            .expect("MAX_TEXT is 1024, which fits u16")
            .to_be_bytes(),
    );
    payload.extend_from_slice(bytes);
    payload.resize(padded, 0);
    Ok(payload)
}

/// A fresh 96-bit nonce from the OS RNG. A failure is an error, never a panic.
fn fresh_nonce() -> Result<[u8; NONCE_LEN], CoreError> {
    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *nonce)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    Ok(*nonce)
}

/// The one seal path: AAD, payload, then `seal_raw_with_nonce`. The public
/// seal draws a fresh nonce; the vector seam and the core API both end up here.
fn seal_with_nonce(
    key: &FileKey,
    record_key: &Uuid,
    device_key: Option<&Uuid>,
    field: ClientMetaField,
    plaintext: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<String, CoreError> {
    let aad = aad_for(record_key, device_key, field)?;
    let payload = payload_for(plaintext)?;
    seal_envelope(key, nonce, &payload, &aad)
}

fn seal_envelope(key: &FileKey, nonce: &[u8; NONCE_LEN], payload: &[u8], aad: &[u8]) -> Result<String, CoreError> {
    let frame = crate::encrypt::seal_raw_with_nonce(key, nonce, payload, aad)?;
    Ok(format!(
        "{ENVELOPE_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&frame)
    ))
}

fn open_envelope(key: &FileKey, envelope: &str, aad: &[u8]) -> Result<String, CoreError> {
    let body = envelope
        .strip_prefix(ENVELOPE_PREFIX)
        .ok_or_else(|| CoreError::InvalidInput("client-meta envelope must start with \"bbcm1.\"".into()))?;
    if envelope.len() > MAX_ENVELOPE_CHARS {
        return Err(CoreError::Decryption);
    }
    let raw = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| CoreError::Decryption)?,
    );
    if raw.len() < MIN_BODY || raw.len() > MAX_BODY || (raw.len() - (NONCE_LEN + TAG_LEN)) % 32 != 0 {
        return Err(CoreError::Decryption);
    }
    let plain = Zeroizing::new(crate::encrypt::open_raw_with_aad(key, &raw, aad)?);
    if plain.len() < 2 {
        return Err(CoreError::Decryption);
    }
    let len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
    if len > MAX_TEXT {
        return Err(CoreError::Decryption);
    }
    if plain.len() != padded_len(len) {
        return Err(CoreError::Decryption);
    }
    if plain[2 + len..].iter().any(|&b| b != 0) {
        return Err(CoreError::Decryption);
    }
    std::str::from_utf8(&plain[2..2 + len])
        .map(str::to_owned)
        .map_err(|_| CoreError::Decryption)
}

/// Fixed-nonce seal, `cfg(test)` / `test-support` only (the same gate as the
/// other known-answer seams; never compiled into a shipped client).
#[cfg(any(test, feature = "test-support"))]
pub fn seal_client_meta_with_nonce(
    master: &MasterKey,
    record_key: &Uuid,
    device_key: Option<&Uuid>,
    field: ClientMetaField,
    plaintext: &str,
    nonce: [u8; NONCE_LEN],
) -> Result<String, CoreError> {
    let key = client_meta_key(master);
    seal_with_nonce(&key, record_key, device_key, field, plaintext, &nonce)
}

/// Seal an arbitrary payload under a given nonce — `cfg(test)` only, so the
/// padding/length refusal can be exercised with an authenticated bad body.
#[cfg(test)]
fn seal_payload_with_nonce(
    key: &FileKey,
    nonce: &[u8; NONCE_LEN],
    payload: &[u8],
    aad: &[u8],
) -> Result<String, CoreError> {
    seal_envelope(key, nonce, payload, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const MASTER_KEY: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = 0x40 + i as u8;
            i += 1;
        }
        k
    };

    fn mk() -> MasterKey {
        MasterKey::from_bytes(MASTER_KEY)
    }

    fn record() -> Uuid {
        Uuid::parse_str("19220000-0000-4000-8000-000000000001").unwrap()
    }

    fn record2() -> Uuid {
        Uuid::parse_str("19220000-0000-4000-8000-000000000002").unwrap()
    }

    fn device_a() -> Uuid {
        Uuid::parse_str("19220000-0000-4000-8000-0000000000aa").unwrap()
    }

    fn device_b() -> Uuid {
        Uuid::parse_str("19220000-0000-4000-8000-0000000000bb").unwrap()
    }

    fn session_key(field: ClientMetaField) -> Option<Uuid> {
        // Field 1 is a device's own hostname: no parent device key.
        if field == ClientMetaField::DeviceHostname {
            None
        } else {
            Some(device_a())
        }
    }

    /// `CoreError` is not `PartialEq`; assert the one variant these tests expect.
    fn assert_decryption(result: Result<String, CoreError>) {
        assert!(
            matches!(result, Err(CoreError::Decryption)),
            "expected Decryption, got {result:?}"
        );
    }

    #[test]
    fn round_trips_every_field() {
        let m = mk();
        for field in [
            ClientMetaField::DeviceHostname,
            ClientMetaField::SessionName,
            ClientMetaField::SessionLocalPath,
            ClientMetaField::SessionRemotePath,
        ] {
            let text = format!("value for {field:?} — ünïcode");
            let sealed = seal_client_meta(&m, &record(), session_key(field).as_ref(), field, &text).unwrap();
            assert!(sealed.starts_with("bbcm1."), "{sealed}");
            let opened = open_client_meta(&m, &record(), session_key(field).as_ref(), field, &sealed).unwrap();
            assert_eq!(opened, text);
        }
    }

    #[test]
    fn a_field_swap_fails() {
        let m = mk();
        let sealed = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "Taxes").unwrap();
        assert_decryption(open_client_meta(
            &m,
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionLocalPath,
            &sealed,
        ));
    }

    #[test]
    fn a_record_key_swap_fails() {
        let m = mk();
        let sealed = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "Taxes").unwrap();
        assert_decryption(open_client_meta(
            &m,
            &record2(),
            Some(&device_a()),
            ClientMetaField::SessionName,
            &sealed,
        ));
    }

    #[test]
    fn a_device_key_swap_fails() {
        let m = mk();
        let sealed = seal_client_meta(
            &m,
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionLocalPath,
            "/Users/guus/Taxes",
        )
        .unwrap();
        assert_decryption(open_client_meta(
            &m,
            &record(),
            Some(&device_b()),
            ClientMetaField::SessionLocalPath,
            &sealed,
        ));
    }

    #[test]
    fn device_key_misuse_is_invalid_input() {
        let m = mk();
        assert!(matches!(
            seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::DeviceHostname, "mac"),
            Err(CoreError::InvalidInput(_))
        ));
        for field in [
            ClientMetaField::SessionName,
            ClientMetaField::SessionLocalPath,
            ClientMetaField::SessionRemotePath,
        ] {
            assert!(matches!(
                seal_client_meta(&m, &record(), None, field, "x"),
                Err(CoreError::InvalidInput(_))
            ));
        }
        // And the open path refuses the same combinations.
        let sealed = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "x").unwrap();
        assert!(matches!(
            open_client_meta(&m, &record(), None, ClientMetaField::SessionName, &sealed),
            Err(CoreError::InvalidInput(_))
        ));
    }

    #[test]
    fn another_master_key_fails() {
        let sealed = seal_client_meta(
            &mk(),
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionName,
            "Taxes",
        )
        .unwrap();
        let mut other = MASTER_KEY;
        other[0] ^= 0xff;
        assert_decryption(open_client_meta(
            &MasterKey::from_bytes(other),
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionName,
            &sealed,
        ));
    }

    #[test]
    fn one_bucket_gives_equal_lengths_and_the_next_bucket_is_longer() {
        let m = mk();
        let seal = |s: &str| {
            seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, s)
                .unwrap()
                .len()
        };
        // 2 + len <= 32 => the 32-byte bucket.
        assert_eq!(seal("abc"), seal("abcdefghij"));
        assert_eq!(seal("abc"), seal(&"x".repeat(30)));
        // 2 + 31 > 32 => the 64-byte bucket.
        assert!(seal(&"x".repeat(31)) > seal(&"x".repeat(30)));
    }

    #[test]
    fn len_1024_is_ok_and_1025_is_invalid_input() {
        let m = mk();
        let ok = "a".repeat(1024);
        let sealed =
            seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionLocalPath, &ok).unwrap();
        assert!(sealed.len() <= 1452, "{} chars", sealed.len());
        assert_eq!(
            open_client_meta(
                &m,
                &record(),
                Some(&device_a()),
                ClientMetaField::SessionLocalPath,
                &sealed
            )
            .unwrap(),
            ok
        );
        assert!(matches!(
            seal_client_meta(
                &m,
                &record(),
                Some(&device_a()),
                ClientMetaField::SessionLocalPath,
                &"a".repeat(1025)
            ),
            Err(CoreError::InvalidInput(_))
        ));
    }

    #[test]
    fn fit_for_seal_keeps_a_char_boundary_tail_within_1024_bytes() {
        assert_eq!(fit_for_seal("short"), "short");
        let long = "é".repeat(700); // 1400 bytes
        let fitted = fit_for_seal(&long);
        assert!(fitted.len() <= 1024, "{} bytes", fitted.len());
        assert!(fitted.starts_with('…'));
        assert!(long.ends_with(&fitted[3..]));
        assert_eq!(fitted.len(), 3 + 1020); // 510 whole é, no split scalar
        assert!(fitted.is_char_boundary(3));
        // Exactly at the limit: unchanged.
        let exact = "b".repeat(1024);
        assert_eq!(fit_for_seal(&exact), exact);
        assert_eq!(fit_for_seal(&"b".repeat(1025)).len(), 3 + 1021);
    }

    #[test]
    fn malformed_envelopes_are_refused() {
        use base64::Engine;
        let m = mk();
        let good = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "abc").unwrap();
        let open = |s: &str| open_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, s);

        // Unknown prefix, and a case-different one.
        assert!(matches!(open("bbcm2.abc"), Err(CoreError::InvalidInput(_))));
        assert!(matches!(
            open(&good.replacen("bbcm1.", "BBCM1.", 1)),
            Err(CoreError::InvalidInput(_))
        ));
        // Padded base64: re-encode a 64-byte-bucket wire WITH '=' padding.
        let bucket2 = seal_client_meta(
            &m,
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionName,
            &"p".repeat(31),
        )
        .unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&bucket2[6..])
            .unwrap();
        let padded = format!("bbcm1.{}", base64::engine::general_purpose::URL_SAFE.encode(&raw));
        assert!(padded.contains('='));
        assert_decryption(open(&padded));
        // Too short a body.
        let short = format!(
            "bbcm1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 20])
        );
        assert_decryption(open(&short));
        // A body whose length is not 28 + 32k.
        let odd = format!(
            "bbcm1.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 61])
        );
        assert_decryption(open(&odd));
    }

    #[test]
    fn a_bad_padding_byte_is_refused() {
        // Authenticate a payload whose padding is not all zero, via the seam.
        let m = mk();
        let key = client_meta_key(&m);
        let aad = aad_for(&record(), Some(&device_a()), ClientMetaField::SessionName).unwrap();
        let mut payload = vec![0u8, 3, b'a', b'b', b'c'];
        payload.resize(32, 0);
        payload[31] = 1;
        let sealed = seal_payload_with_nonce(&key, &[0x11; 12], &payload, &aad).unwrap();
        assert_decryption(open_client_meta(
            &m,
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionName,
            &sealed,
        ));
        // A declared length that does not match the authenticated length.
        let mut payload = vec![0u8, 31, b'a'];
        payload.resize(32, 0);
        let sealed = seal_payload_with_nonce(&key, &[0x12; 12], &payload, &aad).unwrap();
        assert_decryption(open_client_meta(
            &m,
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionName,
            &sealed,
        ));
    }

    #[test]
    fn two_seals_of_the_same_input_differ() {
        let m = mk();
        let a = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "same").unwrap();
        let b = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "same").unwrap();
        assert_ne!(a, b, "a fresh nonce per seal");
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn open_many_derives_once_and_isolates_bad_rows() {
        let m = mk();
        let good = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "one").unwrap();
        let bad = seal_client_meta(&m, &record(), Some(&device_b()), ClientMetaField::SessionName, "two").unwrap();
        let items = vec![
            (record(), Some(device_a()), ClientMetaField::SessionName, good),
            (record(), Some(device_a()), ClientMetaField::SessionName, bad),
            (
                record(),
                Some(device_a()),
                ClientMetaField::SessionLocalPath,
                "not-an-envelope".to_string(),
            ),
        ];
        let out = open_client_meta_many(&m, &items);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].as_ref().unwrap(), "one");
        assert!(matches!(out[1], Err(CoreError::Decryption)));
        assert!(out[2].is_err());
    }

    #[test]
    fn client_meta_key_known_answer_is_independent() {
        // HKDF-SHA256(salt = none, ikm = master, info = "beebeeb/client-meta/v1/key"),
        // computed with the hkdf crate directly (the `independent_subkey` pattern)
        // and with a hand-rolled RFC 5869 HMAC-SHA256 in Python:
        // 7d2b02da5f6ae330b0d74dfa80ea7b00d42369887dad84168e9343f9e464ad44
        let m = mk();
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, m.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(CLIENT_META_KEY_INFO, &mut okm).unwrap();
        assert_eq!(client_meta_key(&m).as_bytes(), &okm);
        assert_eq!(
            hex::encode(client_meta_key(&m).as_bytes()),
            "7d2b02da5f6ae330b0d74dfa80ea7b00d42369887dad84168e9343f9e464ad44"
        );
        assert_eq!(CLIENT_META_KEY_INFO, b"beebeeb/client-meta/v1/key");
        assert_eq!(AAD_DOMAIN, b"beebeeb/client-meta/v1");
        assert_eq!(AAD_DOMAIN.len(), 22);
    }

    #[test]
    fn the_aad_layout_is_pinned() {
        let aad = aad_for(&record(), Some(&device_a()), ClientMetaField::SessionRemotePath).unwrap();
        let mut want = b"beebeeb/client-meta/v1".to_vec();
        want.extend_from_slice(&36u32.to_be_bytes());
        want.extend_from_slice(b"19220000-0000-4000-8000-000000000001");
        want.extend_from_slice(&36u32.to_be_bytes());
        want.extend_from_slice(b"19220000-0000-4000-8000-0000000000aa");
        want.push(4);
        assert_eq!(aad, want);
        // Field 1 carries an empty (length 0) device key.
        let aad = aad_for(&record(), None, ClientMetaField::DeviceHostname).unwrap();
        let mut want = b"beebeeb/client-meta/v1".to_vec();
        want.extend_from_slice(&36u32.to_be_bytes());
        want.extend_from_slice(b"19220000-0000-4000-8000-000000000001");
        want.extend_from_slice(&0u32.to_be_bytes());
        want.push(1);
        assert_eq!(aad, want);
    }

    #[test]
    fn padding_buckets_decode_to_bodies_of_60_and_92_bytes() {
        use base64::Engine;
        let m = mk();
        let body_len = |text: &str| {
            let sealed =
                seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, text).unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&sealed[ENVELOPE_PREFIX.len()..])
                .unwrap()
                .len()
        };
        // nonce(12) + padded payload(32) + tag(16); then one 32-byte bucket more.
        assert_eq!(body_len(""), 60);
        assert_eq!(body_len("abc"), 60);
        assert_eq!(body_len(&"x".repeat(30)), 60);
        assert_eq!(body_len(&"x".repeat(31)), 92);
        assert_eq!(body_len(&"x".repeat(62)), 92);
    }

    #[test]
    fn over_limit_envelopes_are_refused() {
        use base64::Engine;
        let m = mk();
        let good = seal_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, "abc").unwrap();
        let open = |s: &str| open_client_meta(&m, &record(), Some(&device_a()), ClientMetaField::SessionName, s);

        // The 1452-character cap, refused before any base64 work.
        let long = format!("{good}{}", "A".repeat(MAX_ENVELOPE_CHARS));
        assert!(long.len() > MAX_ENVELOPE_CHARS);
        assert_decryption(open(&long));

        // The decoded MAX_BODY: one 32-byte bucket past the largest payload.
        let too_big = format!(
            "{ENVELOPE_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; MAX_BODY + 32])
        );
        assert_decryption(open(&too_big));
    }

    #[test]
    fn the_over_limit_seal_error_does_not_leak_the_plaintext_length() {
        let err = seal_client_meta(
            &mk(),
            &record(),
            Some(&device_a()),
            ClientMetaField::SessionLocalPath,
            &"a".repeat(2000),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.ends_with("client-meta plaintext exceeds the 1024-byte limit (use fit_for_seal)"),
            "{err}"
        );
        // The padding hides the length; the error must not publish it again.
        assert!(!err.contains("2000"), "{err}");
    }

    #[test]
    fn field_codes_are_one_to_four_and_the_rest_is_invalid_input() {
        for (code, field) in [
            (1u8, ClientMetaField::DeviceHostname),
            (2, ClientMetaField::SessionName),
            (3, ClientMetaField::SessionLocalPath),
            (4, ClientMetaField::SessionRemotePath),
        ] {
            assert!(matches!(ClientMetaField::try_from(code), Ok(f) if f == field));
            assert_eq!(field as u8, code);
        }
        for code in [0u8, 5, 6, 255] {
            assert!(matches!(
                ClientMetaField::try_from(code),
                Err(CoreError::InvalidInput(_))
            ));
        }
    }
}
