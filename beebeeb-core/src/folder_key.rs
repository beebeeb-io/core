//! A shared folder's key id (task 2133).
//!
//! `folder_key_id = HKDF-SHA256(ikm = folder key, salt = none, info =
//! "beebeeb/folder-key-id/v1")`, 32 bytes: a one-way id of a folder key, meant
//! for a server to compare folder keys without learning them. A client tells
//! which of its candidate keys an id names by recomputing it.
//!
//! With no salt, HKDF's extract step is HMAC-SHA256 under an all-zero salt over
//! the key, and the id is the expand of that pseudorandom key under the info
//! string. The id reveals nothing usable about the key and is not secret. It
//! commits to the key it was computed from, but it CANNOT prove that wraps sent
//! with it were made under that key. It is not the key and must never be used
//! as one.

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
    let hk = Hkdf::<Sha256>::new(None, folder_key);
    let mut id = [0u8; 32];
    hk.expand(FOLDER_KEY_ID_INFO, &mut id)
        .expect("HKDF-SHA256 expand for 32 bytes cannot fail");
    id
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
