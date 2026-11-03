//! The batch readers of the name/metadata decryptors (move 1 of the core
//! consolidation, spec §16.2): a folder listing or a file page decrypts in one
//! call instead of one WASM/UniFFI crossing per row.
//!
//! These live beside `encrypt` so that file stays within its size ratchet. They
//! are new, additive API (`core::encrypt_batch::*`); the single-item readers in
//! `core::encrypt` keep their names and signatures.

use crate::CoreError;
use crate::encrypt::{NameMetadata, decrypt_file_metadata, decrypt_name_metadata};

/// Batch form of [`decrypt_name_metadata`] for a folder listing: one call for N
/// rows, results in input order, and a bad row is an `Err` for that row only —
/// it never fails the batch. The input is the clients' own shape, `(file_id,
/// name_encrypted)`, with the id as the server-canonical string, so a JSON page
/// needs no conversion.
///
/// Per row it follows [`decrypt_name_metadata`] exactly: a plaintext legacy
/// name is accepted (folders, display). For the pin a file's content reader
/// must use, call [`decrypt_files_metadata`], which refuses plaintext like
/// [`decrypt_file_metadata`]. Parallel off-wasm and sequential on wasm32, the
/// same split as [`crate::encrypt::decrypt_names`].
pub fn decrypt_names_metadata(
    master_key: &crate::kdf::MasterKey,
    items: &[(String, &str)],
) -> Vec<Result<NameMetadata, CoreError>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use rayon::prelude::*;
        items
            .par_iter()
            .map(|(file_id, name_encrypted)| decrypt_name_metadata(master_key, file_id, name_encrypted))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        items
            .iter()
            .map(|(file_id, name_encrypted)| decrypt_name_metadata(master_key, file_id, name_encrypted))
            .collect()
    }
}

/// Batch form of [`decrypt_file_metadata`]: the per-row content pins for a file
/// listing in one call. Same input shape, ordering and per-row error rule as
/// [`decrypt_names_metadata`]. A plaintext name is refused for that row
/// (`InvalidInput`), never read as a legacy name — the same P1-B rule as the
/// single-item file reader.
pub fn decrypt_files_metadata(
    master_key: &crate::kdf::MasterKey,
    items: &[(String, &str)],
) -> Vec<Result<NameMetadata, CoreError>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use rayon::prelude::*;
        items
            .par_iter()
            .map(|(file_id, name_encrypted)| decrypt_file_metadata(master_key, file_id, name_encrypted))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        items
            .iter()
            .map(|(file_id, name_encrypted)| decrypt_file_metadata(master_key, file_id, name_encrypted))
            .collect()
    }
}
