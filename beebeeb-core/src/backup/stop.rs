//! Why a backup stops, and its words (spec Amendments 12 and 12a, LD-0121;
//! Guus, 2026-11-06: "Stop, say why, offer Back up again").
//!
//! When the account's files are removed (the person's own "Erase all files",
//! the admin reset, the inactive cleanup, the billing wipe or the grace
//! clock), every backup on every device turns off on its next pass, says why
//! and offers "Back up again". A backup never undoes an erase and never fills
//! the account up again by itself. The server says why through one
//! `notifications` row ([`BackupNotice`]); the device decides here, from those
//! notices, the time of its last pass and its own listing.

use beebeeb_types::backup::{BackupNotice, BackupStopReason, Category, NOTICE_BACKUP_DELETED, NOTICE_FILES_REMOVED};
use serde_json::Value;
use uuid::Uuid;

use super::plan::{FolderPresence, folder_presence};

/// The action every stopped backup offers. It starts the folder again: a
/// device folder restored from Trash is found again by its manifest, and what
/// is already there counts as backed up (spec rules 3 and 10), so nothing is
/// uploaded twice.
pub const MSG_BACK_UP_AGAIN: &str = "Back up again";

/// The words for [`BackupStopReason::EraseRequest`].
pub const MSG_STOP_ERASE_REQUEST: &str = "Your files were erased, so backups are off.";
/// The words for [`BackupStopReason::AccountLapsed`].
pub const MSG_STOP_ACCOUNT_LAPSED: &str = "Your files were removed after the account lapsed, so backups are off.";
/// The words for [`BackupStopReason::InactiveCleanup`].
pub const MSG_STOP_INACTIVE_CLEANUP: &str =
    "Your files were removed because the account was inactive, so backups are off.";
/// The words for [`BackupStopReason::AccountReset`].
pub const MSG_STOP_ACCOUNT_RESET: &str = "Your files were removed when the account was reset, so backups are off.";
/// The words for [`BackupStopReason::UnknownRemoval`]: a removal whose reason
/// this build does not know (spec Amendment 12b, Guus 2026-11-07 19:04, G6).
/// Never the "deleted" words, which may be untrue.
pub const MSG_STOP_UNKNOWN_REMOVAL: &str = "Your files were removed, so backups are off.";

/// The words a stopped backup shows (spec Amendment 12's table and 12b's
/// seventh line), each followed by the action [`MSG_BACK_UP_AGAIN`]. `device`
/// is this device's name and `folder` the backed-up folder's display name; the
/// five account-wide reasons name neither:
///
/// - `BackupDeleted`: "`device`'s backup of `folder` was deleted from another
///   device." (spec §4.2 rule 11)
/// - `EraseRequest`, `AccountLapsed`, `InactiveCleanup`, `AccountReset`,
///   `UnknownRemoval`: the `MSG_STOP_*` lines
/// - `Unknown`: "`device`'s backup of `folder` was deleted, so it is off."
pub fn backup_stop_words(reason: BackupStopReason, device: &str, folder: &str) -> String {
    match reason {
        BackupStopReason::BackupDeleted => format!("{device}'s backup of {folder} was deleted from another device."),
        BackupStopReason::EraseRequest => MSG_STOP_ERASE_REQUEST.to_string(),
        BackupStopReason::AccountLapsed => MSG_STOP_ACCOUNT_LAPSED.to_string(),
        BackupStopReason::InactiveCleanup => MSG_STOP_INACTIVE_CLEANUP.to_string(),
        BackupStopReason::AccountReset => MSG_STOP_ACCOUNT_RESET.to_string(),
        BackupStopReason::UnknownRemoval => MSG_STOP_UNKNOWN_REMOVAL.to_string(),
        BackupStopReason::Unknown => format!("{device}'s backup of {folder} was deleted, so it is off."),
    }
}

/// Read one `notifications` row (`type` and `data`) as a backup notice.
/// `None` for a row of any other type. It never fails on a backup row: a
/// `files_removed` row whose reason is missing or not one this build knows
/// still removes, with [`BackupStopReason::UnknownRemoval`] and its own words
/// (stop and say why, Amendment 12b); in a `backup_deleted` row
/// an id that is missing or not a string names no folder (a folder that is
/// really gone still stops through the listing).
pub fn parse_backup_notice(kind: &str, data: &Value) -> Option<BackupNotice> {
    match kind {
        NOTICE_FILES_REMOVED => Some(BackupNotice::FilesRemoved {
            reason: data
                .get("reason")
                .and_then(Value::as_str)
                .and_then(BackupStopReason::parse)
                .filter(|reason| reason.files_removed())
                .unwrap_or(BackupStopReason::UnknownRemoval),
        }),
        NOTICE_BACKUP_DELETED => Some(BackupNotice::BackupDeleted {
            device_folder_id: id_text(data.get("device_folder_id")).unwrap_or_default(),
            category_folder_id: id_text(data.get("category_folder_id")),
        }),
        _ => None,
    }
}

/// An id field as text: a string as it is, any other present value as its
/// JSON (which is never a UUID, so it names no folder), absent or `null` as
/// `None`. A malformed category id therefore never reads as the device folder.
fn id_text(field: Option<&Value>) -> Option<String> {
    match field {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

/// A backup notice as the device read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedNotice {
    pub notice: BackupNotice,
    /// When the server wrote it (the row's `created_at`), in milliseconds
    /// since the epoch, on the server's clock.
    pub created_at_ms: i64,
}

/// One backup this device has turned on, as its listing shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopFolder {
    pub category: Category,
    /// The category folder (`Backups/<device>/<category>`), `None` when it was
    /// never created (a first backup).
    pub category_folder_id: Option<Uuid>,
    /// `Some(false)` only when the category folder existed and is now trashed
    /// or gone; `None` when it never existed (as [`folder_presence`]).
    pub category_folder_live: Option<bool>,
}

/// What the device's listing shows of its own backups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopListing {
    /// This device's folder (`find_device_folder`).
    pub device_folder_id: Uuid,
    /// `false` only when this device's folder existed and is now trashed or
    /// gone.
    pub device_folder_live: bool,
    /// The backups turned on on this device; one that is already off is not
    /// listed.
    pub folders: Vec<StopFolder>,
}

/// A backup that turns off, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoppedBackup {
    pub category: Category,
    pub reason: BackupStopReason,
}

/// Which backups turn off on this pass, and why (spec Amendment 12, steps 1-4).
///
/// Only a notice the server wrote after `last_pass_at_ms` counts
/// (`created_at_ms > last_pass_at_ms`). `last_pass_at_ms` is on the SERVER's
/// clock, like the notices: the time this device's previous pass of these
/// backups started (for example the `Date` of the response that listed the
/// notices then), or, when the person turned a backup on or chose "Back up
/// again" after that, the moment they did. A device clock that runs ahead
/// must never be passed here: it would hide a notice, and the pass would fill
/// the account up again.
///
/// 1. A `files_removed` notice turns off **every** listed backup with its
///    reason, even when the folders are still there (the grace clock removes
///    files, not folders). With several, the newest wins (Amendment 12a);
///    on a tie, the reason whose wire string sorts first.
/// 2. Otherwise, for each backup: a `backup_deleted` notice that names this
///    device's folder, with no category id or with this backup's category
///    folder, turns it off as `BackupDeleted`. A notice whose device folder is
///    another device's (or does not parse) counts for nothing here; a folder
///    that is really gone still stops at step 3.
/// 3. Otherwise, a device or category folder that is trashed or gone with no
///    notice turns it off as `Unknown` (the person dismissed the notice before
///    the device saw it, or the device was offline a long time).
/// 4. Otherwise it stays on. A folder restored from Trash before the pass,
///    with no notice, changes nothing.
///
/// Steps 2 and 3 are taken per backup, so a notice about one folder never
/// hides another folder that is gone without one. The result is in category
/// key order; empty means nothing changes. It does not depend on the order of
/// `notices`.
pub fn backup_stop(notices: &[ReceivedNotice], last_pass_at_ms: i64, listing: &StopListing) -> Vec<StoppedBackup> {
    let fresh: Vec<&ReceivedNotice> = notices.iter().filter(|n| n.created_at_ms > last_pass_at_ms).collect();
    // Step 1: the newest files_removed notice; on a tie, the smallest wire
    // string, so the answer does not depend on the order of `notices`.
    let removed = fresh
        .iter()
        .filter(|n| matches!(n.notice, BackupNotice::FilesRemoved { .. }))
        .map(|n| (n.created_at_ms, n.notice.reason()))
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.as_str().cmp(a.1.as_str())));

    let mut device_deleted = false;
    let mut categories_deleted: Vec<Uuid> = Vec::new();
    for n in &fresh {
        if let BackupNotice::BackupDeleted {
            device_folder_id,
            category_folder_id,
        } = &n.notice
        {
            // Only a notice about this device's folder counts; a category
            // notice must name both this device's folder and the category's.
            if Uuid::parse_str(device_folder_id).ok() != Some(listing.device_folder_id) {
                continue;
            }
            match category_folder_id {
                Some(category) => categories_deleted.extend(Uuid::parse_str(category).ok()),
                None => device_deleted = true,
            }
        }
    }

    let mut stopped: Vec<StoppedBackup> = listing
        .folders
        .iter()
        .filter_map(|folder| {
            let reason = if let Some((_, reason)) = removed {
                reason
            } else if device_deleted
                || folder
                    .category_folder_id
                    .is_some_and(|id| categories_deleted.contains(&id))
            {
                BackupStopReason::BackupDeleted
            } else if folder_presence(listing.device_folder_live, folder.category_folder_live)
                != FolderPresence::Present
            {
                BackupStopReason::Unknown
            } else {
                return None;
            };
            Some(StoppedBackup {
                category: folder.category.clone(),
                reason,
            })
        })
        .collect();
    stopped.sort_by_key(|s| s.category.key());
    stopped
}
