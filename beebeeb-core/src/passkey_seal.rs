//! Seal an account master key under WebAuthn PRF output.
//!
//! The server stores only the returned opaque blob. It has neither the passkey
//! PRF output nor the derived wrapping key and therefore cannot open the blob.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::CoreError;
use crate::kdf::MasterKey;

pub(crate) const PASSKEY_SEAL_KEY_INFO: &[u8] = b"beebeeb/passkey-seal/v1/key";
pub(crate) const PASSKEY_SEAL_AAD_DOMAIN: &[u8] = b"beebeeb/passkey-seal/v1";
const NONCE_LEN: usize = 12;
const MASTER_KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WIRE_VERSION: u8 = 1;
const SEALED_LEN: usize = 1 + NONCE_LEN + MASTER_KEY_LEN + TAG_LEN;
const MAX_CONTEXT_FIELD_LEN: usize = 4 * 1024;

/// Opaque server-storable passkey-sealed master-key blob.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeySealedMasterKey {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl std::fmt::Debug for PasskeySealedMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeySealedMasterKey")
            .field("bytes", &SEALED_LEN)
            .finish()
    }
}

impl PasskeySealedMasterKey {
    /// Encode as `version || nonce || ciphertext || tag`, opaque to the server.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SEALED_LEN);
        bytes.push(WIRE_VERSION);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Parse the fixed-size passkey-seal wire representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != SEALED_LEN {
            return Err(CoreError::InvalidInput(format!(
                "passkey-sealed master key must be {SEALED_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if bytes[0] != WIRE_VERSION {
            return Err(CoreError::InvalidInput(format!(
                "unsupported passkey-seal version {}",
                bytes[0]
            )));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1..1 + NONCE_LEN]);
        Ok(Self {
            nonce,
            ciphertext: bytes[1 + NONCE_LEN..].to_vec(),
        })
    }
}

/// AES-GCM associated data: `domain ‖ version ‖ u32_be(len) ‖ account ‖
/// u32_be(len) ‖ credential`. The wire version byte is inside the AAD (crypto
/// review, P3), so a later format cannot reuse a version-1 blob under
/// another version byte. No 61-byte blob had shipped when this was added.
fn context(version: u8, account_id: &[u8], credential_id: &[u8]) -> Result<Vec<u8>, CoreError> {
    if account_id.is_empty() || credential_id.is_empty() {
        return Err(CoreError::InvalidInput(
            "account id and credential id must not be empty".into(),
        ));
    }
    if account_id.len() > MAX_CONTEXT_FIELD_LEN || credential_id.len() > MAX_CONTEXT_FIELD_LEN {
        return Err(CoreError::InvalidInput(format!(
            "account id and credential id must be at most {MAX_CONTEXT_FIELD_LEN} bytes"
        )));
    }
    let account_len =
        u32::try_from(account_id.len()).map_err(|_| CoreError::InvalidInput("account id is too long".into()))?;
    let credential_len =
        u32::try_from(credential_id.len()).map_err(|_| CoreError::InvalidInput("credential id is too long".into()))?;
    let capacity = PASSKEY_SEAL_AAD_DOMAIN
        .len()
        .checked_add(9)
        .and_then(|n| n.checked_add(account_id.len()))
        .and_then(|n| n.checked_add(credential_id.len()))
        .ok_or_else(|| CoreError::InvalidInput("passkey-seal context is too long".into()))?;
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(PASSKEY_SEAL_AAD_DOMAIN);
    aad.push(version);
    aad.extend_from_slice(&account_len.to_be_bytes());
    aad.extend_from_slice(account_id);
    aad.extend_from_slice(&credential_len.to_be_bytes());
    aad.extend_from_slice(credential_id);
    Ok(aad)
}

fn wrapping_key(prf_output: &[u8]) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    if prf_output.len() != 32 {
        return Err(CoreError::InvalidInput(format!(
            "passkey PRF output must be 32 bytes, got {}",
            prf_output.len()
        )));
    }
    let hk = Hkdf::<Sha256>::new(None, prf_output);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(PASSKEY_SEAL_KEY_INFO, &mut *key)
        .map_err(|_| CoreError::Kdf("passkey wrapping-key derivation failed".into()))?;
    Ok(key)
}

/// Seal a master-key handle under passkey PRF output.
pub fn seal_master_key(
    master_key: &MasterKey,
    prf_output: &[u8],
    account_id: &[u8],
    credential_id: &[u8],
) -> Result<PasskeySealedMasterKey, CoreError> {
    let key = wrapping_key(prf_output)?;
    let aad = context(WIRE_VERSION, account_id, credential_id)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CoreError::Encryption(format!("OS randomness unavailable: {e}")))?;
    let cipher =
        Aes256Gcm::new_from_slice(&*key).map_err(|_| CoreError::Encryption("invalid passkey wrapping key".into()))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: master_key.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Encryption("passkey sealing failed".into()))?;
    Ok(PasskeySealedMasterKey { nonce, ciphertext })
}

/// Open a passkey-sealed blob into an opaque master-key handle.
pub fn open_master_key(
    sealed: &PasskeySealedMasterKey,
    prf_output: &[u8],
    account_id: &[u8],
    credential_id: &[u8],
) -> Result<MasterKey, CoreError> {
    let key = wrapping_key(prf_output)?;
    let aad = context(WIRE_VERSION, account_id, credential_id)?;
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
    if plaintext.len() != MASTER_KEY_LEN {
        return Err(CoreError::Decryption);
    }
    let mut bytes = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(MasterKey::from_zeroizing(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::MasterKey;

    #[test]
    fn roundtrip_is_bound_to_account_and_credential() {
        let master = MasterKey::from_bytes([9u8; 32]);
        let prf = [3u8; 32];
        let sealed = seal_master_key(&master, &prf, b"account-a", b"credential-a").unwrap();
        let opened = open_master_key(&sealed, &prf, b"account-a", b"credential-a").unwrap();
        assert_eq!(opened.as_bytes(), master.as_bytes());
        assert!(open_master_key(&sealed, &prf, b"account-b", b"credential-a").is_err());
        assert!(open_master_key(&sealed, &prf, b"account-a", b"credential-b").is_err());
        let wire = sealed.to_bytes();
        assert_eq!(PasskeySealedMasterKey::from_bytes(&wire).unwrap(), sealed);
        assert!(PasskeySealedMasterKey::from_bytes(&wire[1..]).is_err());
    }

    #[test]
    fn the_wire_version_is_inside_the_associated_data() {
        let master = MasterKey::from_bytes([9u8; 32]);
        let prf = [3u8; 32];
        let sealed = seal_master_key(&master, &prf, b"account-a", b"credential-a").unwrap();
        let cipher = Aes256Gcm::new_from_slice(&*wrapping_key(&prf).unwrap()).unwrap();
        let open_with = |aad: &[u8]| {
            cipher.decrypt(
                Nonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad,
                },
            )
        };
        let versioned = context(WIRE_VERSION, b"account-a", b"credential-a").unwrap();
        assert!(open_with(&versioned).is_ok());
        let mut unversioned = versioned.clone();
        unversioned.remove(PASSKEY_SEAL_AAD_DOMAIN.len());
        assert!(
            open_with(&unversioned).is_err(),
            "the version byte must be authenticated"
        );
        assert!(open_with(&context(2, b"account-a", b"credential-a").unwrap()).is_err());
    }
}
