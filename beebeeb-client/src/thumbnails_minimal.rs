//! Thumbnail bytes are sealed and opened only by core's purpose-specific API.

pub use beebeeb_core::encrypt::{
    decrypt_thumbnail_for_metadata, encrypt_thumbnail_for_new_item, encrypt_thumbnail_for_target,
};
pub use beebeeb_core::thumbnail::{ThumbnailConfig, ThumbnailVariant, resize_for_thumbnail};
