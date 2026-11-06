//! LD-0113: the backup rules the web client needs (spec
//! `2026-11-06-backup-from-source-design.md` §4.4, §8; spec Amendment 8). The
//! protection rules with their words (the web is an app surface:
//! `backupCheckAppMutation`), one crossing per listing for the "is this the
//! root" bit, and the device manifest (to show a device's name, model and last
//! backup). Dialog copy stays in the web UI. An unknown mutation, position or
//! role string throws, never passes (plan Amendment 1, item 3), except in the
//! per-row protection bit, where an unknown role is protected (review #8): a
//! role the server adds later must never break an older bundle's listing.
use beebeeb_core::backup::{
    BackupPosition, MSG_BADGE, Mutation, check_app_mutation, check_drive_mutation, check_root_mutation,
    is_hidden_backup_item, parse_manifest,
};
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

fn parse_mutation(mutation: &str) -> Result<Mutation, JsError> {
    Mutation::parse(mutation).ok_or_else(|| JsError::new("unknown mutation"))
}

fn parse_position(position: &str) -> Result<BackupPosition, JsError> {
    BackupPosition::parse(position).ok_or_else(|| JsError::new("unknown backup position"))
}

/// The server's root rule: the words to show when `mutation` (`"trash" |
/// "delete" | "rename" | "move" | "create" | "write"`) of a row with `role` is
/// refused, or `undefined` when it is allowed. Only the root's trash, delete,
/// rename and move are refused; the web's own views use
/// `backupCheckAppMutation`.
#[wasm_bindgen(js_name = backupCheckRootMutation)]
pub fn backup_check_root_mutation(role: Option<String>, mutation: &str) -> Result<Option<String>, JsError> {
    let m = parse_mutation(mutation)?;
    Ok(check_root_mutation(parse_role(role.as_deref())?, m)
        .err()
        .map(|p| p.message.to_string()))
}

/// The app rule (spec Amendment 8): the words to show when `mutation` of a row
/// at `position` (`"root" | "device_folder" | "manifest" | "category_folder" |
/// "inside" | "outside"`, from `backupPositionAtDepth`; for `"create"`, the
/// folder the new item goes into) is refused, or `undefined`. A move checks
/// the row with `"move"` and the destination folder with `"create"`.
#[wasm_bindgen(js_name = backupCheckAppMutation)]
pub fn backup_check_app_mutation(position: &str, mutation: &str) -> Result<Option<String>, JsError> {
    let m = parse_mutation(mutation)?;
    Ok(check_app_mutation(parse_position(position)?, m)
        .err()
        .map(|p| p.message.to_string()))
}

/// The drive rule (Explorer, Finder, the iOS Files app), with the same words:
/// nothing at or under the root is changed in a drive surface. `undefined`
/// when allowed. `ownActiveSource`: the original's path when the row is this
/// device's own backup of a folder still being backed up.
#[wasm_bindgen(js_name = backupCheckDriveMutation)]
pub fn backup_check_drive_mutation(
    position: &str,
    own_active_source: Option<String>,
    mutation: &str,
) -> Result<Option<String>, JsError> {
    let m = parse_mutation(mutation)?;
    Ok(
        check_drive_mutation(parse_position(position)?, own_active_source.as_deref(), m)
            .err()
            .map(|p| p.message.into_owned()),
    )
}

/// The position of the row `name`, `depth` folders below the flagged root
/// (`null` or `undefined`: not under it): `"outside"`, `"root"` (0),
/// `"device_folder"` (1), `"manifest"` (2, a device folder's `.device.json`),
/// `"category_folder"` (2) or `"inside"` (3 or more).
#[wasm_bindgen(js_name = backupPositionAtDepth)]
pub fn backup_position_at_depth(depth: Option<u32>, name: &str) -> String {
    BackupPosition::at_depth(depth.map(|d| d as usize), name)
        .as_str()
        .to_string()
}

/// `true` for a row no listing ever shows (a device folder's `.device.json`);
/// `depth` and `name` as for `backupPositionAtDepth`.
#[wasm_bindgen(js_name = backupIsHiddenItem)]
pub fn backup_is_hidden_item(depth: Option<u32>, name: &str) -> bool {
    is_hidden_backup_item(depth.map(|d| d as usize), name)
}

/// The badge every client shows on the Backups root (`"Read-only"`).
#[wasm_bindgen(js_name = backupRootBadge)]
pub fn backup_root_badge() -> String {
    MSG_BADGE.to_string()
}

/// One byte per row of a listing (its `system_role`, `""` for none): 1 when
/// the row is the protected root (no trash, delete, rename or move), else 0. A role this
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
            "" => u8::from(check_root_mutation(None, Mutation::Trash).is_err()),
            s => SystemRole::parse(s).map_or(1, |role| {
                u8::from(check_root_mutation(Some(role), Mutation::Trash).is_err())
            }),
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
