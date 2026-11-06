//! LD-0113: the backup rules the web client needs (spec
//! `2026-11-06-backup-from-source-design.md` §4.4, §8). The protection rule
//! with its words, one crossing per listing for the "is this protected" bit,
//! and the device manifest (to show a device's name, model and last backup).
//! Dialog copy stays in the web UI. An unknown mutation or role string throws,
//! never passes (plan Amendment 1, item 3).
use beebeeb_core::backup::{Mutation, check_mutation, parse_manifest};
use beebeeb_types::backup::SystemRole;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// `null`, `undefined` or `""` is no role; `"backups_root"` is the root.
fn parse_role(role: Option<&str>) -> Result<Option<SystemRole>, JsError> {
    match role {
        None | Some("") => Ok(None),
        Some(s) => SystemRole::parse(s)
            .map(Some)
            .ok_or_else(|| JsError::new("unknown system role")),
    }
}

/// The words to show when `mutation` (`"trash" | "delete" | "rename" |
/// "move"`) of a row with `role` is refused, or `undefined` when it is
/// allowed.
#[wasm_bindgen(js_name = backupCheckMutation)]
pub fn backup_check_mutation(role: Option<String>, mutation: &str) -> Result<Option<String>, JsError> {
    let m = Mutation::parse(mutation).ok_or_else(|| JsError::new("unknown mutation"))?;
    Ok(check_mutation(parse_role(role.as_deref())?, m)
        .err()
        .map(|p| p.message.to_string()))
}

/// One byte per row of a listing (its `system_role`, `""` for none): 1 when
/// the row is protected (no trash, delete, rename or move), else 0.
#[wasm_bindgen(js_name = backupProtectionMany)]
pub fn backup_protection_many(roles: Vec<String>) -> Result<Vec<u8>, JsError> {
    roles
        .iter()
        .map(|r| parse_role(Some(r)).map(|role| u8::from(check_mutation(role, Mutation::Trash).is_err())))
        .collect()
}

/// Parse a decrypted `.device.json` into a plain object: the known fields and
/// every unknown one, as core keeps them.
#[wasm_bindgen(js_name = backupParseManifest)]
pub fn backup_parse_manifest(json: &str) -> Result<JsValue, JsError> {
    let manifest = parse_manifest(json).map_err(|e| JsError::new(&e.to_string()))?;
    manifest
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&e.to_string()))
}
