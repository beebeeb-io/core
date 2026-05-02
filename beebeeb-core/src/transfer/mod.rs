//! Constellation peer transfer — ephemeral E2E channel between two devices.
//!
//! Two devices establish a transfer key via X25519 ECDH, derive a 4-word
//! Short Authenticated String (SAS) from the same shared secret, and exchange
//! a single encrypted blob via the server relay. The server only sees ciphertext
//! and two ephemeral public keys.
//!
//! ## Layout
//!
//! - [`crypto`]    — X25519 key exchange, HKDF transfer-key + SAS derivation
//! - [`encrypt`]   — AES-256-GCM transfer encryption (`nonce || ciphertext`)
//! - [`wordlist`]  — 256-word SAS wordlist (one byte per word)
//! - [`bundle`]    — multi-file bundle codec for sending several files in one blob
//!
//! See `docs/superpowers/specs/2026-05-02-constellation-peer-transfer-design.md`.

pub mod bundle;
pub mod crypto;
pub mod encrypt;
pub mod wordlist;

pub use bundle::{bundle_files, unbundle_files};
pub use crypto::{
    TransferKeypair, derive_sas, derive_shared_secret, derive_transfer_key, generate_keypair, sas_to_words,
};
pub use encrypt::{decrypt_transfer, encrypt_transfer};
