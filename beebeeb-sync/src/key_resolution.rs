//! Pure key resolution shared by sync clients; no transport or persistence.

pub use beebeeb_core::owned_keys::{
    FirstChunk, FolderWrap, KeyOrigin, RequestRowKeys, ResolvedName, ResolvedOwnedKey, WriteTarget, child_wrap_matches,
    resolve_owned_key, resolve_request_row, unwrap_child_key, unwrap_folder_custody, unwrap_owner_file_key,
    wrap_child_key, wrap_folder_custody, wrap_owner_file_key,
};
