//! Local account database for native Beebeeb products.
//!
//! A caller supplies a distinct database path for every account and product.
//! The database is deliberately not encrypted: decrypted names and other local
//! metadata are stored as plaintext. On Apple platforms, the caller must put
//! the database and decrypted cache files in a container protected with
//! `NSFileProtectionCompleteUntilFirstUserAuthentication`, and must keep the
//! database, its `-wal` and `-shm` sidecars, caches, and thumbnails out of
//! device backups. Apple callers should set `URLResourceValues.isExcludedFromBackup`
//! on each of those URLs (or locate cache files below `Library/Caches`).
//!
//! Cache files must be published with
//! [`beebeeb_core::path_safety::TrustedDirectory`] before their index row is
//! committed. Its directory-handle API avoids a check-then-rename race.
//!
//! Signing out here removes only this product's database. The platform must
//! first increment the account generation in its shared keychain group so other
//! processes stop work; a device-wide sign-out coordinates every product and
//! separately removes keychain key material.

mod error;
mod migrations;
mod model;
mod store;

pub use error::{Result, StoreError};
pub use model::*;
pub use store::*;
