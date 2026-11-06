//! The device manifest, `.device.json` (spec §4.2 rule 4).
//!
//! The file is encrypted like any other file; this module only parses and
//! writes its plaintext. v1 is a superset of the shape iOS already writes
//! (`BackupService.ts` `DeviceManifest`): desktop adds `platform` and
//! `folders`. Parsing is tolerant, so every existing iOS file parses unchanged
//! and a round trip keeps what this version does not know.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

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
    /// `None` when the file has no id, or an id that is not a UUID (that text
    /// is kept verbatim in `other`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
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

/// One backed-up folder of a desktop.
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

/// Parse a decrypted `.device.json`. A `device_id` that is not a UUID and a
/// `platform` this version does not know do not fail the file: they parse as
/// `None` and their text is kept in `other`, so it is written back unchanged.
pub fn parse_manifest(json: &str) -> Result<DeviceManifest, CoreError> {
    let mut object = match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(object)) => object,
        Ok(_) => return Err(invalid("not a JSON object")),
        Err(e) => return Err(json_error(&e)),
    };
    let mut kept = Map::new();
    let id_ok = |v: &Value| v.is_null() || v.as_str().is_some_and(|s| Uuid::parse_str(s).is_ok());
    if object.get("device_id").is_some_and(|v| !id_ok(v)) {
        kept.insert("device_id".to_string(), object.remove("device_id").unwrap_or_default());
    }
    let platform_ok = |v: &Value| v.is_null() || serde_json::from_value::<Platform>(v.clone()).is_ok();
    if object.get("platform").is_some_and(|v| !platform_ok(v)) {
        kept.insert("platform".to_string(), object.remove("platform").unwrap_or_default());
    }
    let mut manifest: DeviceManifest = serde_json::from_value(Value::Object(object)).map_err(|e| json_error(&e))?;
    manifest.other.extend(kept);
    Ok(manifest)
}

/// Write a manifest as compact JSON with its keys sorted, so the same manifest
/// always gives the same bytes. A field this version knows always wins over
/// text of the same name kept in `other`: a renamed device is written with
/// its new name. `other` keeps `device_id` / `platform` text only while the
/// field itself is `None` (the text parse could not read).
pub fn serialize_manifest(m: &DeviceManifest) -> String {
    let (keep_id_text, keep_platform_text) = (m.device_id.is_none(), m.platform.is_none());
    let mut m = m.clone();
    m.other.retain(|key, _| match key.as_str() {
        "version" | "device_name" | "folders" => false,
        "device_id" => keep_id_text,
        "platform" => keep_platform_text,
        _ => true,
    });
    // A manifest is plain JSON data (string keys only), so neither step can
    // fail; an empty object is never written in its place.
    let value = serde_json::to_value(&m).expect("a DeviceManifest is plain JSON");
    serde_json::to_string(&value).expect("a JSON value always serializes")
}
