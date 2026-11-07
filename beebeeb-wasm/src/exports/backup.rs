//! LD-0113: the backup rules the web client needs (spec
//! `2026-11-06-backup-from-source-design.md` §4.4, §8; spec Amendment 8). The
//! protection rules with their words (the web is an app surface:
//! `backupCheckAppMutation`), one crossing per listing for the "is this the
//! root" bit, and the device manifest (to show a device's name, model and last
//! backup). Dialog copy stays in the web UI. An unknown mutation, position or
//! role string throws, never passes (plan Amendment 1, item 3), except in the
//! per-row protection bit, where an unknown role is protected (review #8): a
//! role the server adds later must never break an older bundle's listing.
//! Why a backup stops and its words (spec Amendment 12, LD-0121): the web
//! shows both notification types with core's words; a notification row is
//! read leniently, like the server's own new types.
use beebeeb_core::backup::{
    BackupPassGate, BackupPosition, MSG_BACK_UP_AGAIN, MSG_BADGE, MSG_STOP_CHECK_FAILED, Mutation, ReceivedNotice,
    StopFolder, StopListing, StoppedBackup, check_app_mutation, check_drive_mutation, check_root_mutation,
    first_pass_baseline, is_hidden_backup_item, parse_backup_notice, parse_manifest,
};
use beebeeb_types::backup::{BackupStopReason, Category, SystemRole};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
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

// ── Why a backup stops (spec Amendment 12, LD-0121) ───────────────────────

#[derive(Deserialize)]
struct StopFolderJs {
    category: String,
    #[serde(default)]
    category_folder_id: Option<String>,
    #[serde(default)]
    category_folder_live: Option<bool>,
}

#[derive(Deserialize)]
struct StopListingJs {
    device_folder_id: String,
    device_folder_live: bool,
    folders: Vec<StopFolderJs>,
}

#[derive(Serialize)]
struct StoppedJs {
    category: String,
    reason: &'static str,
}

/// The largest integer a JS number holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// A whole number of milliseconds from a JS number (an integer, or a float
/// with no fraction within the safe range), else `None`.
fn whole_ms(value: &serde_json::Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        value
            .as_f64()
            .filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER)
            .map(|f| f as i64)
    })
}

/// The backup notices among `rows`, read leniently: a row that is not a backup
/// notice is skipped whatever its shape (no `type`, no time, another type). A
/// backup notice without a whole `created_at_ms` throws: the call cannot place
/// it before or after the last pass, and guessing either way is wrong.
fn backup_notices(rows: &[serde_json::Value]) -> Result<Vec<ReceivedNotice>, JsError> {
    let mut notices = Vec::new();
    for row in rows {
        let Some(kind) = row.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(notice) = parse_backup_notice(kind, row.get("data").unwrap_or(&serde_json::Value::Null)) else {
            continue;
        };
        let created_at_ms = row
            .get("created_at_ms")
            .and_then(whole_ms)
            .ok_or_else(|| JsError::new("a backup notice row has no whole created_at_ms"))?;
        notices.push(ReceivedNotice { notice, created_at_ms });
    }
    Ok(notices)
}

fn parse_uuid(field: &str, s: &str) -> Result<Uuid, JsError> {
    Uuid::parse_str(s).map_err(|_| JsError::new(&format!("{field} is not a UUID")))
}

fn parse_stop_reason(reason: &str) -> Result<BackupStopReason, JsError> {
    BackupStopReason::parse(reason).ok_or_else(|| JsError::new("unknown backup stop reason"))
}

/// Which backups turn off on this pass, and why (spec Amendment 12, steps
/// 1-4): `[{category, reason}]` in category key order, empty when nothing
/// changes. `notices`: the `notifications` rows (`{type, data,
/// created_at_ms}`); a row that is not a backup notice is skipped whatever its
/// shape, and a backup notice without a whole `created_at_ms` throws. `lastPassAtMs`: on the
/// server's clock, when this device's previous pass started, or when the
/// person last turned a backup on or chose "Back up again" since. `listing`:
/// `{device_folder_id, device_folder_live, folders: [{category,
/// category_folder_id, category_folder_live}]}`. An unknown category key or an
/// id that is not a UUID throws.
#[wasm_bindgen(js_name = backupStop)]
pub fn backup_stop(notices: JsValue, last_pass_at_ms: f64, listing: JsValue) -> Result<JsValue, JsError> {
    let last_pass_at_ms = last_pass(last_pass_at_ms)?;
    let notices = notices_from_js(notices)?;
    let listing = listing_from_js(listing)?;
    to_js(&stopped_js(beebeeb_core::backup::backup_stop(
        &notices,
        last_pass_at_ms,
        &listing,
    )))
}

fn last_pass(last_pass_at_ms: f64) -> Result<i64, JsError> {
    whole_ms(&serde_json::Value::from(last_pass_at_ms))
        .ok_or_else(|| JsError::new("lastPassAtMs is not a whole number of milliseconds"))
}

fn notices_from_js(notices: JsValue) -> Result<Vec<ReceivedNotice>, JsError> {
    let rows: Vec<serde_json::Value> =
        serde_wasm_bindgen::from_value(notices).map_err(|e| JsError::new(&format!("invalid notices: {e}")))?;
    backup_notices(&rows)
}

fn listing_from_js(listing: JsValue) -> Result<StopListing, JsError> {
    let listing: StopListingJs =
        serde_wasm_bindgen::from_value(listing).map_err(|e| JsError::new(&format!("invalid listing: {e}")))?;
    Ok(StopListing {
        device_folder_id: parse_uuid("device_folder_id", &listing.device_folder_id)?,
        device_folder_live: listing.device_folder_live,
        folders: listing
            .folders
            .iter()
            .map(|f| {
                Ok(StopFolder {
                    category: Category::from_key(&f.category).ok_or_else(|| JsError::new("unknown category key"))?,
                    category_folder_id: f
                        .category_folder_id
                        .as_deref()
                        .map(|id| parse_uuid("category_folder_id", id))
                        .transpose()?,
                    category_folder_live: f.category_folder_live,
                })
            })
            .collect::<Result<Vec<_>, JsError>>()?,
    })
}

fn stopped_js(stopped: Vec<StoppedBackup>) -> Vec<StoppedJs> {
    stopped
        .into_iter()
        .map(|s| StoppedJs {
            category: s.category.key(),
            reason: s.reason.as_str(),
        })
        .collect()
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&e.to_string()))
}

/// The reason a `notifications` row (`type`, `data`) gives, or `undefined` for
/// a row that is not a backup notice: to show the notification with
/// `backupStopWords`. A removal whose reason this build does not know is
/// `"unknown_removal"` (its own words, never the "deleted" ones).
#[wasm_bindgen(js_name = backupNoticeReason)]
pub fn backup_notice_reason(kind: &str, data: JsValue) -> Option<String> {
    let data: serde_json::Value = serde_wasm_bindgen::from_value(data).unwrap_or(serde_json::Value::Null);
    parse_backup_notice(kind, &data).map(|n| n.reason().as_str().to_string())
}

/// The words a stopped backup shows (spec Amendment 12), followed by the
/// action `backupAgainAction()`. `device` is the device's name and `folder`
/// the folder's display name; the four account-wide reasons name neither. An
/// unknown reason throws.
#[wasm_bindgen(js_name = backupStopWords)]
pub fn backup_stop_words(reason: &str, device: &str, folder: &str) -> Result<String, JsError> {
    Ok(beebeeb_core::backup::backup_stop_words(
        parse_stop_reason(reason)?,
        device,
        folder,
    ))
}

/// The action every stopped backup offers: `"Back up again"`.
#[wasm_bindgen(js_name = backupAgainAction)]
pub fn backup_again_action() -> String {
    MSG_BACK_UP_AGAIN.to_string()
}

// ── The first pass and a failed notice check (spec Amendment 12c) ─────────

/// The outcome of `backupPassGate`.
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum PassGateJs {
    Run { stopped: Vec<StoppedJs> },
    CheckFailed,
}

/// The `lastPassAtMs` of a device with none under this engine yet (spec
/// Amendment 12c): `setupAtMs`, the moment backups were set up on this device,
/// or `legacyLastBackupMs`, an upgraded device's last successful backup under
/// the old engine; with both, the earlier; with neither, 0 (any removal notice
/// stops the backup). Both on the server's clock; a value that is not a whole
/// number of milliseconds throws.
#[wasm_bindgen(js_name = backupFirstPassBaseline)]
pub fn backup_first_pass_baseline(
    setup_at_ms: Option<f64>,
    legacy_last_backup_ms: Option<f64>,
) -> Result<f64, JsError> {
    let whole = |field: &str, v: Option<f64>| {
        v.map(|v| {
            whole_ms(&serde_json::Value::from(v))
                .ok_or_else(|| JsError::new(&format!("{field} is not a whole number of milliseconds")))
        })
        .transpose()
    };
    Ok(first_pass_baseline(
        whole("setupAtMs", setup_at_ms)?,
        whole("legacyLastBackupMs", legacy_last_backup_ms)?,
    ) as f64)
}

/// What one pass does before it uploads anything (spec Amendments 12, 12c):
/// `{outcome: "run", stopped: [{category, reason}]}` when the notices were
/// read (as `backupStop`), or `{outcome: "check_failed"}` when
/// `noticesFetchOk` is false (a server or network error, or a page missing):
/// upload nothing, turn nothing off, show `backupCheckFailedWords()`, retry at
/// the next scheduled pass, and keep `lastPassAtMs` where it was. `notices`
/// is not read when the fetch failed.
#[wasm_bindgen(js_name = backupPassGate)]
pub fn backup_pass_gate(
    notices_fetch_ok: bool,
    notices: JsValue,
    last_pass_at_ms: f64,
    listing: JsValue,
) -> Result<JsValue, JsError> {
    let last_pass_at_ms = last_pass(last_pass_at_ms)?;
    let listing = listing_from_js(listing)?;
    let notices = if notices_fetch_ok {
        Some(notices_from_js(notices)?)
    } else {
        None
    };
    to_js(
        &match beebeeb_core::backup::backup_pass_gate(notices.as_deref(), last_pass_at_ms, &listing) {
            BackupPassGate::Run { stopped } => PassGateJs::Run {
                stopped: stopped_js(stopped),
            },
            BackupPassGate::CheckFailed => PassGateJs::CheckFailed,
        },
    )
}

/// The words when the notices could not be read: "Couldn't check — will
/// retry."
#[wasm_bindgen(js_name = backupCheckFailedWords)]
pub fn backup_check_failed_words() -> String {
    MSG_STOP_CHECK_FAILED.to_string()
}
