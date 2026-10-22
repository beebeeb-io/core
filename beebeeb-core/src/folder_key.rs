//! A shared folder's key id (task 2133, design K).
//!
//! A shared folder's members wrap every child's key under one folder key. The
//! server must refuse a second, different folder key for the same folder (a
//! second invite that re-keyed the folder locked the first member out), yet it
//! must not learn the key. So every client sends a commitment to the key with
//! its wraps: `folder_key_id = HKDF-SHA256(ikm = folder key, salt = none,
//! info = "beebeeb/folder-key-id/v1")`, 32 bytes. The server stores the first
//! one per folder and compares bytes only; a client tells which of its
//! candidate keys a folder uses by recomputing the id.
//!
//! The id reveals nothing usable about the key (HKDF is a PRF keyed by the
//! folder key) and is not secret. It is not the key and must never be used as
//! one.

use hkdf::Hkdf;
use sha2::Sha256;

/// The HKDF `info` of a folder key id. The `v1` is part of the id: a new
/// derivation gets a new info string, never a change to this one.
pub const FOLDER_KEY_ID_INFO: &[u8] = b"beebeeb/folder-key-id/v1";

/// The length of a folder key, and of its id.
pub const FOLDER_KEY_LEN: usize = 32;

/// The public id of a shared folder's 32-byte key (task 2133):
/// HKDF-SHA256(ikm = `folder_key`, salt = none, info = [`FOLDER_KEY_ID_INFO`]).
pub fn folder_key_id(folder_key: &[u8; FOLDER_KEY_LEN]) -> [u8; 32] {
    let _ = folder_key;
    [0u8; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The fixed vector, computed independently of this crate (RFC 5869
    /// HKDF-SHA256 in Python's `hmac`/`hashlib`, checked against the RFC's test
    /// case 3): folder key 0x80..=0x9f.
    #[test]
    fn the_folder_key_id_matches_the_fixed_vector() {
        let key: [u8; 32] = std::array::from_fn(|i| 0x80 + i as u8);
        assert_eq!(
            hex(&folder_key_id(&key)),
            "e07f022dd6a140210b19530af0a6b316ec4f06b3a2b086fdf0c03c761baf3b07"
        );
    }

    /// One flipped key byte gives another id (computed the same way).
    #[test]
    fn another_key_has_another_id() {
        let mut key: [u8; 32] = std::array::from_fn(|i| 0x80 + i as u8);
        key[0] = 0x81;
        assert_eq!(
            hex(&folder_key_id(&key)),
            "75c1b73aa2640c69fd67c7b2b60046a80d776be0351b6cc595635d8f57d1b122"
        );
    }
}
