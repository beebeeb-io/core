//! Pure key resolution shared by sync clients; no transport or persistence.

pub use beebeeb_core::owned_keys::{
    FolderWrap, KeyOrigin, ResolvedOwnedKey, resolve_owned_key, unwrap_child_key, unwrap_owner_key, wrap_child_key,
    wrap_key_to_owner, wrap_folder_custody, unwrap_folder_custody,
};
