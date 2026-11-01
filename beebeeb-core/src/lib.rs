pub mod archive;
pub mod blob;
pub mod chunk_stream;
pub mod cli_auth;
pub mod client_meta;
pub mod constellation;
pub mod direct_transfer;
pub mod encrypt;
pub mod error;
pub mod file_encrypt;
pub mod file_request;
pub mod folder_key;
// rusqlite-backed; native targets only so beebeeb-wasm builds in place (0653).
#[cfg(not(target_arch = "wasm32"))]
pub mod fp_cache;
pub mod hash;
pub mod item_id;
pub mod kdf;
#[cfg(test)]
mod label_table_tests;
pub mod media;
pub mod metadata_wire;
pub mod onboarding;
pub mod opaque;
pub mod opaque_protocol;
pub mod owned_keys;
pub mod pdf;
pub mod recovery;
pub mod search_index;
pub mod search_sync;
pub mod share_token;
pub mod sync;
#[cfg(any(test, feature = "test-support"))]
pub mod test_vectors_v2;
pub mod thumbnail;
pub mod transfer;
pub mod zip;

pub use error::CoreError;
