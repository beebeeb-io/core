//! Typed descriptors for the non-administrative product API.

pub mod account;
pub mod auth;
pub mod devices;
pub mod direct;
pub mod downloads;
pub mod file_requests;
pub mod files;
pub mod folder_links;
pub mod invites;
pub mod notifications;
pub mod onboarding;
pub mod photo_backup;
pub mod previews;
#[cfg(feature = "purchases")]
pub mod purchases;
pub mod search;
pub mod settings;
pub mod shares;
pub mod sync;
pub mod thumbnails;
pub mod uploads;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An empty JSON object used by server routes that return `{}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Empty {}

/// A server timestamp remains an RFC 3339 string at this I/O-free layer.
pub type Timestamp = String;

/// Additive fields from a server response can be retained without weakening
/// the types of fields this crate relies on.
pub type ExtraFields = std::collections::BTreeMap<String, Value>;
