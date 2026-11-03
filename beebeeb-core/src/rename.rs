//! Request-row rename sealers (task 2275 §15).
//!
//! Split out of `encrypt.rs`, which is already over the file-size ratchet. The
//! core entry point takes the resolved [`RenameTarget`], so a caller cannot
//! point the owner's new name at the anonymous uploader's `C` or at a guessed
//! pin. The bindings cannot construct a core `RenameTarget` and hold no
//! sealing key, so they expose [`encrypt_name_for_request_rename`], which
//! re-derives the §15 string-convention key from the row id.

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
    crate::encrypt::encrypt_name_for(target.key(), filename, mime_type, target.pin())
}

/// Seal a request-row rename from `(master, item_id, pin)` instead of a
/// [`RenameTarget`]. This is the bindings' path: they cannot construct a core
/// `RenameTarget` and hold no sealing key, so the sealer re-derives the §15
/// string-convention key from the item id. `pin` is the row's recorded chunk
/// format.
///
/// It performs NO class, name or seal checks: any `item_id` and `pin` are
/// accepted, as [`crate::encrypt::encrypt_name_for`] itself does. That gives no
/// new secret: the derivation needs only the master key and the public item id
/// (both already the caller's), and the result is the §15 string key, never
/// the content key `C` that the anonymous uploader holds.
pub fn encrypt_name_for_request_rename(
    master_key: &MasterKey,
    item_id: &str,
    pin: ExpectedChunkFormat,
    filename: &str,
    mime_type: Option<&str>,
) -> Result<String, CoreError> {
    let key = derive_file_key(master_key, item_id.as_bytes());
    crate::encrypt::encrypt_name_for(&key, filename, mime_type, pin)
}
