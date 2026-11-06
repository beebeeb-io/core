//! Request-row rename sealers (task 2275 §15).
//!
//! Split out of `encrypt.rs`, which is already over the file-size ratchet.
//!
//! Which entry point guarantees what:
//! - [`encrypt_name_for_rename_target`] seals under the key and pin of a
//!   resolved [`RenameTarget`]. It cannot point the owner's new name at the
//!   anonymous uploader's `C` or at a guessed pin.
//! - [`encrypt_name_for_request_rename`] is the bindings' entry point (they
//!   cannot construct a core `RenameTarget` and hold no sealing key). It
//!   re-derives the §15 string-convention key from the row id and refuses a
//!   non-owner (F) id. It performs NO name or seal check, so the caller must
//!   pass the pin the row's authenticated name recorded.
//!
//! Pin risk, both directions. Callers pass the pin from the resolver's
//! [`RenameTarget`], never from a server field:
//! - pin 2 on a v1 row: the row is unreadable until it is renamed again with
//!   the correct pin;
//! - pin 0 on a v2 row: the recorded 2 is dropped, frame-0 detection is back
//!   on, and a server can serve the uploader's old no-AAD name blob under `C`
//!   as a one-frame v1 file.

use crate::CoreError;
use crate::chunk_stream::ExpectedChunkFormat;
use crate::kdf::{MasterKey, derive_file_key};
use crate::owned_keys::RenameTarget;

/// Seal a request-row rename through the row's [`RenameTarget`]: the key and
/// the recorded pin both come from the resolved row, so a caller cannot seal
/// the owner's new name under the anonymous uploader's `C`.
pub fn encrypt_name_for_rename_target(
    target: &RenameTarget,
    filename: &str,
    mime_type: Option<&str>,
) -> Result<String, CoreError> {
    match target.version() {
        Some(version) => {
            crate::encrypt::encrypt_name_for_version(target.key(), filename, mime_type, target.pin(), version)
        }
        None => crate::encrypt::encrypt_name_for(target.key(), filename, mime_type, target.pin()),
    }
}

/// Seal a request-row rename from `(master, item_id, pin)` instead of a
/// [`RenameTarget`]. This is the bindings' path: they cannot construct a core
/// `RenameTarget` and hold no sealing key, so the sealer re-derives the §15
/// string-convention key from the item id. `pin` is the row's recorded chunk
/// format.
///
/// It refuses a non-owner (F) id with the same class check the resolver runs.
/// It performs NO name or seal check: the caller must pass the pin from the
/// resolver's [`RenameTarget`], never a server field. Pin risk, both
/// directions: a pin of 2 on a v1 row makes the file unreadable until it is
/// renamed again with the correct pin; a pin of 0 on a v2 row drops the
/// recorded 2 and turns frame-0 detection back on, so a server can serve the
/// uploader's old no-AAD name blob under `C` as a one-frame v1 file. That gives
/// no new secret: the derivation needs only the master key and the public item
/// id (both already the caller's), and the result is the §15 string key, never
/// the content key `C` that the anonymous uploader holds.
pub fn encrypt_name_for_request_rename(
    master_key: &MasterKey,
    item_id: &str,
    pin: ExpectedChunkFormat,
    filename: &str,
    mime_type: Option<&str>,
) -> Result<String, CoreError> {
    encrypt_name_for_request_rename_with_version(master_key, item_id, pin, None, filename, mime_type)
}

/// Version-preserving request-row rename for binding callers that cannot hold a
/// core [`RenameTarget`]. `version` comes from the resolved row's authenticated
/// metadata; passing `None` is only for an unprotected legacy row.
pub fn encrypt_name_for_request_rename_with_version(
    master_key: &MasterKey,
    item_id: &str,
    pin: ExpectedChunkFormat,
    version: Option<crate::chunk_stream::VersionCommitment>,
    filename: &str,
    mime_type: Option<&str>,
) -> Result<String, CoreError> {
    if crate::item_id::item_class(item_id)? != crate::item_id::ItemClass::Owner {
        return Err(CoreError::InvalidInput(
            "request row class check: a request row must have an owner item id; foreign items resolve only via L8 or L7"
                .into(),
        ));
    }
    let key = derive_file_key(master_key, item_id.as_bytes());
    match version {
        Some(version) => crate::encrypt::encrypt_name_for_version(&key, filename, mime_type, pin, version),
        None => crate::encrypt::encrypt_name_for(&key, filename, mime_type, pin),
    }
}
