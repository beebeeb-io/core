//! The device manifest, `.device.json` (spec §4.2 rule 4).
//!
//! The file is encrypted like any other file; this module only parses and
//! writes its plaintext. v1 is a superset of the shape iOS already writes
//! (`BackupService.ts` `DeviceManifest`): desktop adds `platform` and
//! `folders`. Parsing is tolerant, so every existing iOS file parses unchanged
//! and a round trip keeps what this version does not know. A file is only
//! unreadable when it is not a JSON object: one field or folder entry this
//! version cannot read never hides the device id, or the device would create
//! a new suffixed folder and orphan its backup (delta 3 #7).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use beebeeb_types::backup::Platform;

use crate::CoreError;

/// The manifest version this module writes.
pub const MANIFEST_VERSION: u32 = 1;

fn manifest_version() -> u32 {
    MANIFEST_VERSION
}

/// One device's manifest. Unknown fields are kept in `other` and written back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceManifest {
    #[serde(default = "manifest_version")]
    pub version: u32,
    /// The device's id, a string identity: desktop's machine-derived UUID, an
    /// iOS id, or an iOS legacy `beebeeb_device_id` value carried forward
    /// verbatim. `None` when the file has no id, or one that is not a string
    /// (that value is kept verbatim in `other`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_name: String,
    /// `None` when the file has no platform (iOS files) or one this version
    /// does not know (kept verbatim in `other`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// Desktop's per-folder state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<FolderState>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

/// One backed-up folder of a desktop. Unknown fields are kept in `other` and
/// written back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FolderState {
    /// A `Category` key (`"pictures"`, `"custom:<name>"`, ...).
    pub category: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub last_pass_at_ms: Option<i64>,
    #[serde(default)]
    pub items: u64,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

/// The fields of a `folders` entry this version knows.
const FOLDER_FIELDS: [&str; 4] = ["category", "enabled", "last_pass_at_ms", "items"];

/// One `folders` entry, leniently: a missing or null field takes its default;
/// an entry that still does not fit (not an object, no string category, a
/// field of the wrong type) is `None`, and only it is dropped.
fn folder_state(entry: Value) -> Option<FolderState> {
    let Value::Object(mut entry) = entry else {
        return None;
    };
    entry.retain(|key, value| !(value.is_null() && FOLDER_FIELDS.contains(&key.as_str())));
    serde_json::from_value(Value::Object(entry)).ok()
}

/// The error never quotes the document: a manifest holds a device name.
fn invalid(detail: &str) -> CoreError {
    CoreError::InvalidInput(format!("device manifest: {detail}"))
}

fn json_error(e: &serde_json::Error) -> CoreError {
    invalid(&format!(
        "not a valid manifest ({:?} error at line {}, column {})",
        e.classify(),
        e.line(),
        e.column()
    ))
}

/// Parse a decrypted `.device.json`. A `device_id` that is not a string and a
/// `platform` this version does not know do not fail the file: they parse as
/// `None` and their value is kept in `other`, so it is written back unchanged.
/// Any string id is the id, a legacy non-UUID one included (review #7).
///
/// Only a document that is not a JSON object is an error (delta 3 #7). A
/// `version` or `device_name` that is null or of the wrong type takes its
/// default; `folders` that is not a list is empty; each `folders` entry is
/// read on its own (a missing or null field takes its default, and an entry
/// that still does not fit is dropped alone, so the next write leaves it out).
pub fn parse_manifest(json: &str) -> Result<DeviceManifest, CoreError> {
    let mut object = match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(object)) => object,
        Ok(_) => return Err(invalid("not a JSON object")),
        Err(e) => return Err(json_error(&e)),
    };
    if object
        .get("version")
        .is_some_and(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()).is_none())
    {
        object.remove("version");
    }
    if object.get("device_name").is_some_and(|v| !v.is_string()) {
        object.remove("device_name");
    }
    let folders: Vec<FolderState> = match object.remove("folders") {
        Some(Value::Array(entries)) => entries.into_iter().filter_map(folder_state).collect(),
        _ => Vec::new(),
    };
    let mut kept = Map::new();
    let id_ok = |v: &Value| v.is_null() || v.is_string();
    if object.get("device_id").is_some_and(|v| !id_ok(v)) {
        kept.insert("device_id".to_string(), object.remove("device_id").unwrap_or_default());
    }
    let platform_ok = |v: &Value| v.is_null() || serde_json::from_value::<Platform>(v.clone()).is_ok();
    if object.get("platform").is_some_and(|v| !platform_ok(v)) {
        kept.insert("platform".to_string(), object.remove("platform").unwrap_or_default());
    }
    let mut manifest: DeviceManifest = serde_json::from_value(Value::Object(object)).map_err(|e| json_error(&e))?;
    manifest.folders = folders;
    manifest.other.extend(kept);
    Ok(manifest)
}

/// Write a manifest as compact JSON with its keys sorted, so the same manifest
/// always gives the same bytes. A field this version knows always wins over
/// text of the same name kept in `other`: a renamed device is written with
/// its new name. `other` keeps `device_id` / `platform` text only while the
/// field itself is `None` (the text parse could not read). A folder's known
/// fields likewise win over its kept text.
pub fn serialize_manifest(m: &DeviceManifest) -> String {
    let (keep_id_text, keep_platform_text) = (m.device_id.is_none(), m.platform.is_none());
    let mut m = m.clone();
    m.other.retain(|key, _| match key.as_str() {
        "version" | "device_name" | "folders" => false,
        "device_id" => keep_id_text,
        "platform" => keep_platform_text,
        _ => true,
    });
    for folder in &mut m.folders {
        folder.other.retain(|key, _| !FOLDER_FIELDS.contains(&key.as_str()));
    }
    // A manifest is plain JSON data (string keys only), so neither step can
    // fail; an empty object is never written in its place.
    let value = serde_json::to_value(&m).expect("a DeviceManifest is plain JSON");
    serde_json::to_string(&value).expect("a JSON value always serializes")
}
