//! Key schedule of the Beebeeb Pass browser pairing (desktop app and browser extension).
//!
//! The pairing state machine and its wire messages live in the Pass crate; every derivation is here.
//!
//! - **Commit:** `SHA-256(ext_pub || salt)`. The extension sends it before it sees the app's key, so
//!   neither side can grind the 6-digit code.
//! - **Transcript:** `ext_pub || app_pub || salt || pair_id || account` (32 + 32 + 16 + 16 + 32 bytes).
//! - **Schedule:** HKDF-SHA256 with the transcript as salt and the X25519 shared secret as input key;
//!   the code, the pair key and the MAC key are three expansions with their own info labels.
//! - **Key confirmation:** `HMAC-SHA256(mac_key, "ext" | "app" || transcript)`, checked in constant time.
//! - **Channel keys:** HKDF-SHA256 with `ext_nonce || app_nonce` as salt and the pair key as input
//!   key; one key per direction.
//!
//! The labels are `v1` and fixed: a change is a new `v2` label, never an edit in place.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::kdf::FileKey;
use crate::opaque::x25519_shared_secret;

/// SHA-256 domain prefix of the account tag.
pub const ACCOUNT_DOMAIN: &[u8] = b"beebeeb/pass/browser/v1/account";
/// HKDF info of the 6-digit comparison code.
pub const CODE_INFO: &[u8] = b"beebeeb/pass/browser/v1/code";
/// HKDF info of the long-lived pair key.
pub const PAIR_KEY_INFO: &[u8] = b"beebeeb/pass/browser/v1/key";
/// HKDF info of the key-confirmation MAC key.
pub const MAC_KEY_INFO: &[u8] = b"beebeeb/pass/browser/v1/mac";
/// HKDF info of the extension-to-app channel key.
pub const EXT_TO_APP_INFO: &[u8] = b"beebeeb/pass/browser/v1/ext-to-app";
/// HKDF info of the app-to-extension channel key.
pub const APP_TO_EXT_INFO: &[u8] = b"beebeeb/pass/browser/v1/app-to-ext";

const TRANSCRIPT_LEN: usize = 32 + 32 + 16 + 16 + 32;

/// Which end of the pairing a value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSide {
    Ext,
    App,
}

impl PairSide {
    /// The other end.
    pub fn peer(self) -> Self {
        match self {
            PairSide::Ext => PairSide::App,
            PairSide::App => PairSide::Ext,
        }
    }

    fn mac_prefix(self) -> &'static [u8] {
        match self {
            PairSide::Ext => b"ext",
            PairSide::App => b"app",
        }
    }
}

/// `SHA-256("beebeeb/pass/browser/v1/account" || lowercase(trim(email)))`.
pub fn account_tag(email: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ACCOUNT_DOMAIN);
    h.update(email.trim().to_lowercase().as_bytes());
    h.finalize().into()
}

/// The extension's commitment to its public key and salt: `SHA-256(ext_pub || salt)`.
pub fn commit(ext_pub: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ext_pub);
    h.update(salt);
    h.finalize().into()
}

/// Whether a revealed key and salt match an earlier [`commit`] (constant time).
pub fn commit_matches(commit_value: &[u8; 32], ext_pub: &[u8; 32], salt: &[u8; 16]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(commit(ext_pub, salt).ct_eq(commit_value))
}

/// What one side derives from the handshake. The keys are wiped on drop and never printed.
pub struct PairKeys {
    code: String,
    key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
    transcript: [u8; TRANSCRIPT_LEN],
}

impl PairKeys {
    /// Derive from this side's X25519 private key and the public handshake values. `side` says whose
    /// private key `my_private` is. Errors when the peer's public key gives an all-zero shared secret.
    pub fn derive(
        side: PairSide,
        my_private: &[u8; 32],
        ext_pub: &[u8; 32],
        app_pub: &[u8; 32],
        salt: &[u8; 16],
        pair_id: &[u8; 16],
        account: &[u8; 32],
    ) -> Result<Self, CoreError> {
        let their_pub = match side {
            PairSide::Ext => app_pub,
            PairSide::App => ext_pub,
        };
        let shared = x25519_shared_secret(my_private, their_pub)?;
        let mut transcript = [0u8; TRANSCRIPT_LEN];
        transcript[..32].copy_from_slice(ext_pub);
        transcript[32..64].copy_from_slice(app_pub);
        transcript[64..80].copy_from_slice(salt);
        transcript[80..96].copy_from_slice(pair_id);
        transcript[96..].copy_from_slice(account);
        let hk = Hkdf::<Sha256>::new(Some(&transcript), &*shared);
        let mut code_bytes = [0u8; 4];
        hk.expand(CODE_INFO, &mut code_bytes).expect("4 bytes");
        let code = format!("{:06}", u32::from_be_bytes(code_bytes) % 1_000_000);
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(PAIR_KEY_INFO, &mut *key).expect("32 bytes");
        let mut mac_key = Zeroizing::new([0u8; 32]);
        hk.expand(MAC_KEY_INFO, &mut *mac_key).expect("32 bytes");
        Ok(Self {
            code,
            key,
            mac_key,
            transcript,
        })
    }

    /// The 6 digits both screens show.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The long-lived pair key. Store it only after the peer's MAC verified.
    pub fn pair_key(&self) -> Zeroizing<[u8; 32]> {
        self.key.clone()
    }

    fn mac_state(&self, side: PairSide) -> Hmac<Sha256> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&*self.mac_key).expect("any key length");
        m.update(side.mac_prefix());
        m.update(&self.transcript);
        m
    }

    /// The key-confirmation MAC that `side` sends.
    pub fn confirmation_mac(&self, side: PairSide) -> [u8; 32] {
        self.mac_state(side).finalize().into_bytes().into()
    }

    /// Whether `mac` is the key-confirmation MAC of `sender` (constant time).
    pub fn verify_confirmation_mac(&self, sender: PairSide, mac: &[u8; 32]) -> bool {
        self.mac_state(sender).verify_slice(mac).is_ok()
    }
}

/// The two AEAD keys of one connection.
pub struct ChannelKeys {
    pub ext_to_app: FileKey,
    pub app_to_ext: FileKey,
}

/// Per-connection channel keys from the pair key and both connection nonces.
pub fn channel_keys(pair_key: &[u8; 32], ext_nonce: &[u8; 16], app_nonce: &[u8; 16]) -> ChannelKeys {
    let mut salt = [0u8; 32];
    salt[..16].copy_from_slice(ext_nonce);
    salt[16..].copy_from_slice(app_nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), pair_key);
    let derive = |info: &[u8]| {
        let mut k = Zeroizing::new([0u8; 32]);
        hk.expand(info, &mut *k).expect("32 bytes");
        FileKey::from_bytes(*k)
    };
    ChannelKeys {
        ext_to_app: derive(EXT_TO_APP_INFO),
        app_to_ext: derive(APP_TO_EXT_INFO),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opaque::derive_x25519_public;

    // Known answers written by the Pass crate's own `pair.rs` before this schedule moved here
    // (pass 419195f): the move must not change one byte.
    const EXT_PUB: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
    const APP_PUB: &str = "605a725d2a4adfeeb1a29e17edd621c1b7593ee8cdbc44ac6c4ab6e2f805d23c";
    const ACCOUNT: &str = "eef03228fc80cf4172f61f3be23cab2acb1f0f499cf21d75d02ea7d4080741a1";
    const COMMIT: &str = "ab4240c23fed83126bc813535c06a93cd1b1f2fde5ddc9cb83c87352aba8066b";
    const CODE: &str = "123883";
    const KEY: &str = "1497059add042db2b177c134a767f805f053f6e946aee4a91961eed843314b1d";
    const MAC_EXT: &str = "3bab0f254f4c9b58e3451cc13ed2e0dd9ae8f200a6486d04e51e3ff7d356b4ea";
    const MAC_APP: &str = "972f1b86df2fc687854690a9a06aed53ffa7a95657cf035ece4cdcfc4a1d0548";
    const EXT_TO_APP: &str = "c3bf0617dcaa8df85d48daa97f0058ad5184c51c5e38bccb76ebf34787e22e89";
    const APP_TO_EXT: &str = "62aed519d44ca0535f494b8513aad49d9efc84b754f36ada4d0f1ec0042ad6a6";

    struct Fixed {
        ext_priv: [u8; 32],
        app_priv: [u8; 32],
        ext_pub: [u8; 32],
        app_pub: [u8; 32],
        salt: [u8; 16],
        pair_id: [u8; 16],
        account: [u8; 32],
    }

    fn fixed() -> Fixed {
        let ext_priv: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let app_priv: [u8; 32] = std::array::from_fn(|i| 0xa0 ^ (i as u8));
        Fixed {
            ext_priv,
            app_priv,
            ext_pub: derive_x25519_public(&ext_priv),
            app_pub: derive_x25519_public(&app_priv),
            salt: std::array::from_fn(|i| 0x30 + i as u8),
            pair_id: std::array::from_fn(|i| 0x50 + i as u8),
            account: account_tag("Ada@Example.org"),
        }
    }

    fn derive(f: &Fixed, side: PairSide) -> PairKeys {
        let private = if side == PairSide::Ext {
            &f.ext_priv
        } else {
            &f.app_priv
        };
        PairKeys::derive(side, private, &f.ext_pub, &f.app_pub, &f.salt, &f.pair_id, &f.account).unwrap()
    }

    #[test]
    fn known_answers_from_the_pass_crate() {
        let f = fixed();
        assert_eq!(hex::encode(f.ext_pub), EXT_PUB);
        assert_eq!(hex::encode(f.app_pub), APP_PUB);
        assert_eq!(hex::encode(f.account), ACCOUNT);
        assert_eq!(account_tag("  ada@example.ORG "), f.account);
        assert_eq!(hex::encode(commit(&f.ext_pub, &f.salt)), COMMIT);
        for side in [PairSide::Ext, PairSide::App] {
            let k = derive(&f, side);
            assert_eq!(k.code(), CODE);
            assert_eq!(hex::encode(*k.pair_key()), KEY);
            assert_eq!(hex::encode(k.confirmation_mac(PairSide::Ext)), MAC_EXT);
            assert_eq!(hex::encode(k.confirmation_mac(PairSide::App)), MAC_APP);
        }
        let key: [u8; 32] = hex::decode(KEY).unwrap().try_into().unwrap();
        let ext_nonce: [u8; 16] = std::array::from_fn(|i| 0x70 + i as u8);
        let app_nonce: [u8; 16] = std::array::from_fn(|i| 0x90 + i as u8);
        let ch = channel_keys(&key, &ext_nonce, &app_nonce);
        assert_eq!(hex::encode(ch.ext_to_app.as_bytes()), EXT_TO_APP);
        assert_eq!(hex::encode(ch.app_to_ext.as_bytes()), APP_TO_EXT);
        // The nonce order is part of the salt.
        let swapped = channel_keys(&key, &app_nonce, &ext_nonce);
        assert_ne!(hex::encode(swapped.ext_to_app.as_bytes()), EXT_TO_APP);
    }

    #[test]
    fn confirmation_mac_is_bound_to_the_sender_and_the_transcript() {
        let f = fixed();
        let ext = derive(&f, PairSide::Ext);
        let app = derive(&f, PairSide::App);
        let from_app = app.confirmation_mac(PairSide::App);
        assert!(ext.verify_confirmation_mac(PairSide::App, &from_app));
        // A side's own MAC reflected back is not the peer's.
        assert!(!ext.verify_confirmation_mac(PairSide::App, &ext.confirmation_mac(PairSide::Ext)));
        let mut bad = from_app;
        bad[31] ^= 1;
        assert!(!ext.verify_confirmation_mac(PairSide::App, &bad));
        // Any other transcript field gives other keys.
        let mut other = fixed();
        other.pair_id[0] ^= 1;
        let k = derive(&other, PairSide::Ext);
        assert_ne!(*k.pair_key(), *ext.pair_key());
        assert!(!k.verify_confirmation_mac(PairSide::App, &from_app));
    }

    #[test]
    fn commit_binds_key_and_salt() {
        let f = fixed();
        let c = commit(&f.ext_pub, &f.salt);
        assert!(commit_matches(&c, &f.ext_pub, &f.salt));
        assert!(!commit_matches(&c, &f.app_pub, &f.salt));
        let mut salt = f.salt;
        salt[0] ^= 1;
        assert!(!commit_matches(&c, &f.ext_pub, &salt));
    }

    #[test]
    fn a_low_order_peer_key_is_refused() {
        let f = fixed();
        let zero = [0u8; 32];
        assert!(
            PairKeys::derive(
                PairSide::Ext,
                &f.ext_priv,
                &f.ext_pub,
                &zero,
                &f.salt,
                &f.pair_id,
                &f.account
            )
            .is_err()
        );
    }
}
