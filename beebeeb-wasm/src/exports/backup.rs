//! LD-0113: the backup rules the web client needs (spec
//! `2026-11-06-backup-from-source-design.md` §4.4, §8). The protection rule
//! with its words, one crossing per listing for the "is this protected" bit,
//! and the device manifest (to show a device's name, model and last backup).
//! Dialog copy stays in the web UI. An unknown mutation or role string throws,
//! never passes (plan Amendment 1, item 3), except in the per-row protection
//! bit, where an unknown role is protected (review #8): a role the server adds
//! later must never break an older bundle's listing.
use beebeeb_core::backup::{Mutation, check_drive_mutation, check_mutation, parse_manifest};
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

/// The drive rule (the web drive view of the Backups tree follows the drive
/// surfaces): the words to show when `mutation` of a row at (`isRoot`) or
/// under (`underRoot`) the Backups root is refused, or `undefined`.
/// `ownActiveSource`: the original's path when the row is this device's own
/// backup of a folder still being backed up. An unknown mutation throws.
#[wasm_bindgen(js_name = backupCheckDriveMutation)]
pub fn backup_check_drive_mutation(
    is_root: bool,
    under_root: bool,
    own_active_source: Option<String>,
    mutation: &str,
) -> Result<Option<String>, JsError> {
    let m = Mutation::parse(mutation).ok_or_else(|| JsError::new("unknown mutation"))?;
    Ok(
        check_drive_mutation(is_root, under_root, own_active_source.as_deref(), m)
            .err()
            .map(|p| p.message.into_owned()),
    )
}

/// One byte per row of a listing (its `system_role`, `""` for none): 1 when
/// the row is protected (no trash, delete, rename or move), else 0. A role this
/// build does not know is protected (1), never an error: it fails safe, and the
/// rest of the listing still renders.
#[wasm_bindgen(js_name = backupProtectionMany)]
pub fn backup_protection_many(roles: Vec<String>) -> Vec<u8> {
    protection_bits(&roles)
}

pub(crate) fn protection_bits(roles: &[String]) -> Vec<u8> {
    roles
        .iter()
        .map(|r| match r.as_str() {
            "" => u8::from(check_mutation(None, Mutation::Trash).is_err()),
            s => SystemRole::parse(s).map_or(1, |role| u8::from(check_mutation(Some(role), Mutation::Trash).is_err())),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::protection_bits;

    /// Review #8: an unknown role is protected, never an error.
    #[test]
    fn unknown_role_is_protected() {
        let roles = ["backups_root", "", "photos_root", "Backups"].map(String::from);
        assert_eq!(protection_bits(&roles), [1, 0, 1, 1]);
    }
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
