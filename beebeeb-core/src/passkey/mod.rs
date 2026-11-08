//! Passkey vault (B15): unlock the vault (master) key with a passkey's PRF output.
//!
//! ONE implementation for every client: desktop calls it in Rust, mobile through UniFFI, web through WASM. A client
//! only performs its platform's WebAuthn call (webauthn.dll, ASAuthorization, Credential Manager,
//! `navigator.credentials`) and hands core the response and the PRF output.
//!
//! The format is the web client's (`repos/web/src/lib/passkey-vault.ts`), byte for byte, so a passkey added on one
//! client unlocks the vault on every other one:
//!
//! ```mermaid
//! flowchart LR
//!   L["PRF eval input = 'beebeeb.io/vault-wrap-key/v1' zero-padded to 32"] -->|"WebAuthn PRF: SHA-256('WebAuthn PRF' || 0x00 || input)"| S[hmac-secret salt]
//!   S -->|authenticator HMAC| P[PRF output, 32 bytes]
//!   P -->|"HKDF-SHA256, salt empty, info 'beebeeb.io/vault-wrap/v1'"| W[wrap key]
//!   W -->|"AES-256-GCM, no AAD"| B["escrow blob = nonce(12) || ct(32) || tag(16)"]
//! ```
//!
//! **Where the PRF salt hash is applied.** The WebAuthn PRF extension never hands the eval input to the
//! authenticator: the client computes `SHA-256("WebAuthn PRF" || 0x00 || input)` and passes THAT as the CTAP2
//! `hmac-secret` salt. A browser does this itself, so web passes [`prf_eval_input`]. A native caller that speaks
//! `hmac-secret` directly (webauthn.dll with `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`, a CTAP2 library) must
//! pass [`hmac_secret_salt`] instead, which is that hash already applied. A native API that takes PRF inputs (and
//! hashes them itself, like the browser) gets [`prf_eval_input`]. Either way the authenticator sees the same salt
//! and returns the same 32-byte PRF output (pinned by `test-vectors/passkey_vault.json`).
//!
//! There is no non-PRF fallback key: a passkey without PRF signs in but cannot unlock the vault (the password or the
//! recovery phrase is still needed). Web's `localStorage` fallback is never ported.

pub mod ceremony;
pub mod flow;
#[cfg(test)]
mod tests;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::CoreError;
use crate::kdf::MasterKey;

/// The PRF eval input's label, zero-padded to 32 bytes by [`prf_eval_input`] (web: `prfExtensionInputs`).
pub const PRF_INPUT_LABEL: &[u8] = b"beebeeb.io/vault-wrap-key/v1";
/// HKDF-SHA256 `info` that turns the PRF output into the vault wrap key (web: `deriveWrapKeyFromPrf`).
pub const VAULT_WRAP_INFO: &[u8] = b"beebeeb.io/vault-wrap/v1";
/// The WebAuthn PRF extension's fixed context string (W3C WebAuthn L3 §10.1.4), with its 0x00 separator.
pub const WEBAUTHN_PRF_CONTEXT: &[u8] = b"WebAuthn PRF\x00";
/// A PRF (hmac-secret) output is 32 bytes.
pub const PRF_OUTPUT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// An escrow blob: `nonce(12) || ciphertext(32) || tag(16)`.
pub const VAULT_BLOB_LEN: usize = NONCE_LEN + 32 + TAG_LEN;

/// The PRF eval input every client passes as `prf.eval.first`: [`PRF_INPUT_LABEL`] zero-padded to 32 bytes.
pub fn prf_eval_input() -> [u8; 32] {
    let mut input = [0u8; 32];
    input[..PRF_INPUT_LABEL.len()].copy_from_slice(PRF_INPUT_LABEL);
    input
}

/// The CTAP2 `hmac-secret` salt for [`prf_eval_input`]: `SHA-256("WebAuthn PRF" || 0x00 || input)`. For a native
/// caller that talks `hmac-secret` directly (see the module docs); a browser applies this hash itself.
pub fn hmac_secret_salt() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WEBAUTHN_PRF_CONTEXT);
    hasher.update(prf_eval_input());
    hasher.finalize().into()
}

/// A passkey's PRF output (32 bytes). Zeroized on drop, never `Clone`, never printed.
pub struct PrfOutput(Zeroizing<[u8; 32]>);

impl PrfOutput {
    /// Take a PRF output from the platform. Exactly 32 bytes, else `InvalidInput`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != PRF_OUTPUT_LEN {
            return Err(CoreError::InvalidInput("PRF output must be 32 bytes".into()));
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }
}

impl std::fmt::Debug for PrfOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrfOutput(..)")
    }
}

/// The wrap key: HKDF-SHA256 over the PRF output, empty salt, info [`VAULT_WRAP_INFO`] (web: `deriveWrapKeyFromPrf`).
pub(crate) fn derive_wrap_key(prf: &PrfOutput) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(&[]), prf.0.as_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(VAULT_WRAP_INFO, key.as_mut_slice())
        .map_err(|e| CoreError::Kdf(e.to_string()))?;
    Ok(key)
}

fn wrap_cipher(prf: &PrfOutput) -> Result<Aes256Gcm, CoreError> {
    let key = derive_wrap_key(prf)?;
    Aes256Gcm::new_from_slice(key.as_slice()).map_err(|e| CoreError::Encryption(e.to_string()))
}

/// Wrap the vault (master) key under a passkey's PRF output, with a fresh random nonce. Returns the escrow blob
/// (`nonce || ct || tag`, [`VAULT_BLOB_LEN`] bytes) the server stores and cannot open.
pub fn wrap_vault_key(prf: &PrfOutput, master_key: &MasterKey) -> Result<Vec<u8>, CoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    wrap_vault_key_with_nonce(prf, master_key, nonce)
}

/// [`wrap_vault_key`] with a chosen nonce: the vectors only. A nonce is never reused under one PRF output in
/// production (the caller there is `wrap_vault_key`).
pub(crate) fn wrap_vault_key_with_nonce(
    prf: &PrfOutput,
    master_key: &MasterKey,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, CoreError> {
    let cipher = wrap_cipher(prf)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: master_key.as_bytes(),
                aad: &[],
            },
        )
        .map_err(|e| CoreError::Encryption(e.to_string()))?;
    let mut blob = Vec::with_capacity(VAULT_BLOB_LEN);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Open an escrow blob with a passkey's PRF output. Anything but exactly [`VAULT_BLOB_LEN`] bytes is
/// `InvalidInput`; a wrong PRF output or a changed byte is `Decryption`. The key goes straight into a [`MasterKey`].
pub fn unwrap_vault_key(prf: &PrfOutput, blob: &[u8]) -> Result<MasterKey, CoreError> {
    if blob.len() != VAULT_BLOB_LEN {
        return Err(CoreError::InvalidInput(format!(
            "vault blob must be {VAULT_BLOB_LEN} bytes"
        )));
    }
    let cipher = wrap_cipher(prf)?;
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let plain = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &[] })
            .map_err(|_| CoreError::Decryption)?,
    );
    if plain.len() != 32 {
        return Err(CoreError::Decryption);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(MasterKey::from_zeroizing(key))
}
