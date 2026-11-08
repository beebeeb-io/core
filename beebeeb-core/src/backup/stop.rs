//! Why a backup stops, and its words (spec Amendments 12, 12a, 12b, 12c and 12d,
//! LD-0121; Guus, 2026-11-06: "Stop, say why, offer Back up again").
//!
//! When the account's files are removed (the person's own "Erase all files",
//! the admin reset, the inactive cleanup, the billing wipe or the grace
//! clock), every backup on every device turns off on its next pass, says why
//! and offers "Back up again". A backup never undoes an erase and never fills
//! the account up again by itself. The server says why through one
//! `notifications` row ([`BackupNotice`]); the device decides here, from those
//! notices, the time of its last pass and its own listing. Since Amendment 12d
//! a pass reads with an overlap margin ([`NOTICE_OVERLAP_MS`]) and remembers
//! the notice ids it acted on ([`backup_pass_gate_v2`]).

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
///
/// **Superseded by [`backup_stop_v2`]** (spec Amendment 12d, server #415
/// review finding 1). A notice's `created_at` is the start of the server
/// transaction that writes it, not its commit; a pass that read the notices
/// while that transaction was still open records a `last_pass_at_ms` later
/// than the notice, and this strict filter then never counts it. Kept
/// unchanged for v0.2.3 callers.
pub fn backup_stop(notices: &[ReceivedNotice], last_pass_at_ms: i64, listing: &StopListing) -> Vec<StoppedBackup> {
    let fresh: Vec<(&BackupNotice, i64)> = notices
        .iter()
        .filter(|n| n.created_at_ms > last_pass_at_ms)
        .map(|n| (&n.notice, n.created_at_ms))
        .collect();
    stop_for(&fresh, listing)
}

/// Steps 1-4 of [`backup_stop`] over the notices that count, each with its
/// `created_at_ms`.
fn stop_for(fresh: &[(&BackupNotice, i64)], listing: &StopListing) -> Vec<StoppedBackup> {
    // Step 1: the newest files_removed notice; on a tie, the smallest wire
    // string, so the answer does not depend on the order of `notices`.
    let removed = fresh
        .iter()
        .filter(|(notice, _)| matches!(notice, BackupNotice::FilesRemoved { .. }))
        .map(|(notice, created_at_ms)| (*created_at_ms, notice.reason()))
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.as_str().cmp(a.1.as_str())));

    let mut device_deleted = false;
    let mut categories_deleted: Vec<Uuid> = Vec::new();
    for (notice, _) in fresh {
        if let BackupNotice::BackupDeleted {
            device_folder_id,
            category_folder_id,
        } = notice
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

// ── The first pass and a failed notice check (spec Amendment 12c) ─────────

/// The words a device shows when it could not read the notices (spec
/// Amendment 12c, Guus 2026-11-07 20:45: "Skip the pass, retry later"). The
/// backup is not off: the pass is skipped and the next one checks again.
pub const MSG_STOP_CHECK_FAILED: &str = "Couldn't check \u{2014} will retry.";

/// The `last_pass_at_ms` of a device that has none under this engine yet
/// (spec Amendment 12c: "When backups were set up"). Only notices newer than
/// it stop its backups. Both inputs are on the server's clock, like
/// `last_pass_at_ms` (a device clock that runs ahead would hide a notice):
///
/// - `setup_at_ms`: the moment backups were turned on on this device (a fresh
///   setup or a reinstall). Turning them on is the person's choice, so older
///   notices do not apply.
/// - `legacy_last_backup_ms`: an upgraded device's last successful backup
///   under the old mirror engine (desktop 0.8.22 or earlier). The old engine
///   never read the notices, so one written after that backup still counts.
///
/// With both known the EARLIER wins: a later baseline hides more notices, and
/// the earlier one never lets an emptied account fill up again. On an upgraded
/// device that is the old engine's last backup, since "set up" there is the
/// new engine's first start, after any notice the old engine missed. With
/// neither known it is 0, so any removal notice stops the backup and offers
/// "Back up again". A client passes
/// `last_pass_at_ms.unwrap_or_else(|| first_pass_baseline(..))` to
/// [`backup_pass_gate`].
pub fn first_pass_baseline(setup_at_ms: Option<i64>, legacy_last_backup_ms: Option<i64>) -> i64 {
    match (setup_at_ms, legacy_last_backup_ms) {
        (Some(setup), Some(legacy)) => setup.min(legacy),
        (Some(at), None) | (None, Some(at)) => at,
        (None, None) => 0,
    }
}

/// What one pass does before it uploads anything (spec Amendments 12 and
/// 12c).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackupPassGate {
    /// The notices were read. `stopped` (from [`backup_stop`]) turn off and
    /// show their words; every other listed backup runs its pass, and the
    /// client records this pass's start as its next `last_pass_at_ms`.
    Run { stopped: Vec<StoppedBackup> },
    /// The notices could not be read (a server or network error, or any page
    /// of them missing): the pass uploads nothing and turns nothing off, the
    /// device shows [`MSG_STOP_CHECK_FAILED`], and the next scheduled pass
    /// retries. `last_pass_at_ms` stays where it was: a skipped pass is not a
    /// pass, so a notice it could not read still counts next time.
    CheckFailed,
}

/// Decide a pass: `notices` is `None` when they could not be read completely,
/// else every backup notice since the last pass (as for [`backup_stop`]).
/// Without them the pass cannot know whether the account was emptied, so it
/// is skipped ([`BackupPassGate::CheckFailed`]) rather than run.
///
/// **Superseded by [`backup_pass_gate_v2`]** (spec Amendment 12d), for the
/// reason given on [`backup_stop`]. Kept unchanged for v0.2.3 callers.
pub fn backup_pass_gate(
    notices: Option<&[ReceivedNotice]>,
    last_pass_at_ms: i64,
    listing: &StopListing,
) -> BackupPassGate {
    match notices {
        Some(notices) => BackupPassGate::Run {
            stopped: backup_stop(notices, last_pass_at_ms, listing),
        },
        None => BackupPassGate::CheckFailed,
    }
}

// ── The overlap margin and acknowledged notices (spec Amendment 12d) ──────

/// How far before `last_pass_at_ms` a notice still counts: 10 minutes (spec
/// Amendment 12d, server #415 review finding 1).
///
/// A notice's `created_at` is the START of the server transaction that writes
/// it (Amendment 12a: the transaction of the run's first removal), not its
/// commit. A pass that read the notices while that transaction was still open
/// did not see the row, yet records a `last_pass_at_ms` later than the row's
/// `created_at`; a strict `created_at_ms > last_pass_at_ms` would then never
/// count it, and the backup would upload again the files the server just
/// removed. So a notice counts when
/// `created_at_ms > last_pass_at_ms - NOTICE_OVERLAP_MS`, and the ids already
/// acknowledged keep that overlap from counting one notice twice
/// ([`backup_stop_v2`]). Ten minutes is far longer than the transactions that
/// write a notice (one erase batch, one file or one folder delete), and covers
/// a skew between the API's and the database's clocks and the one-second
/// resolution of a `Date` header.
pub const NOTICE_OVERLAP_MS: i64 = 10 * 60 * 1000;

/// The `since` a client sends to `GET /api/v1/notifications` (server LD-0141;
/// integer milliseconds on the server's clock, inclusive) so the listing holds
/// every notice [`backup_stop_v2`] can count:
/// `last_pass_at_ms - NOTICE_OVERLAP_MS`, never below 0. A listing fetched from
/// `last_pass_at_ms` itself would leave out the overlap.
pub fn notices_since(last_pass_at_ms: i64) -> i64 {
    last_pass_at_ms.saturating_sub(NOTICE_OVERLAP_MS).max(0)
}

/// A backup notice as the device listed it, with the row's id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedNotice {
    /// The `notifications` row's `id` as the server lists it (a UUID),
    /// compared exactly. `None` or empty when the client has no id: such a
    /// notice is never acknowledged, so it counts on every pass whose window
    /// holds it (a stop shown twice is safe, a notice skipped is not), and an
    /// empty id never acknowledges every notice without one at once.
    pub id: Option<String>,
    pub notice: BackupNotice,
    /// When the server wrote it (the row's `created_at`), in milliseconds
    /// since the epoch, on the server's clock.
    pub created_at_ms: i64,
}

impl ListedNotice {
    fn ack_id(&self) -> Option<&str> {
        self.id.as_deref().filter(|id| !id.is_empty())
    }
}

/// What [`backup_stop_v2`] decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopOutcome {
    /// The backups that turn off, and why, in category key order (as
    /// [`backup_stop`]).
    pub stopped: Vec<StoppedBackup>,
    /// The acknowledged notice ids to keep, in place of the set passed in:
    /// the id of every notice in this pass's window, sorted. That is each
    /// notice this pass acted on and each acknowledged one still in the
    /// window; an id whose notice has left the window is dropped, so the set
    /// stays small. Store it in the same write as the stops and the new
    /// `last_pass_at_ms`, never before them, and keep it when the person
    /// chooses "Back up again".
    pub acknowledged: Vec<String>,
}

/// Which backups turn off on this pass, and why (spec Amendments 12 and 12d):
/// [`backup_stop`] with the overlap margin and acknowledged ids.
///
/// - A notice is in this pass's window when
///   `created_at_ms > last_pass_at_ms - NOTICE_OVERLAP_MS`. `last_pass_at_ms`
///   is on the server's clock, as for [`backup_stop`]; the client fetches the
///   notices from [`notices_since`]`(last_pass_at_ms)`.
/// - A notice in the window whose id is in `acknowledged` (the set the
///   previous pass returned) counts for nothing: this device already acted on
///   it, so a backup the person turned back on with "Back up again" after it
///   never stops on it again.
/// - Every other notice in the window counts, and steps 1-4 of
///   [`backup_stop`] decide; with several `files_removed` notices the newest
///   that counts wins.
///
/// Accepted edge: a backup turned on (or turned back on) within
/// [`NOTICE_OVERLAP_MS`] after a removal notice this device never acted on
/// stops once on its next pass, with that notice's words; "Back up again"
/// then finds it acknowledged. That errs toward stopping: an emptied account
/// never fills up again by itself.
///
/// The answer does not depend on the order of `notices` or `acknowledged`.
pub fn backup_stop_v2(
    notices: &[ListedNotice],
    last_pass_at_ms: i64,
    acknowledged: &[String],
    listing: &StopListing,
) -> StopOutcome {
    let from = last_pass_at_ms.saturating_sub(NOTICE_OVERLAP_MS);
    let window: Vec<&ListedNotice> = notices.iter().filter(|n| n.created_at_ms > from).collect();
    let counted: Vec<(&BackupNotice, i64)> = window
        .iter()
        .filter(|n| n.ack_id().is_none_or(|id| !acknowledged.iter().any(|a| a == id)))
        .map(|n| (&n.notice, n.created_at_ms))
        .collect();
    let mut kept: Vec<String> = window.iter().filter_map(|n| n.ack_id()).map(str::to_string).collect();
    kept.sort();
    kept.dedup();
    StopOutcome {
        stopped: stop_for(&counted, listing),
        acknowledged: kept,
    }
}

/// What one pass does before it uploads anything (spec Amendments 12, 12c
/// and 12d).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackupPassGateV2 {
    /// The notices were read. `stopped` turn off and show their words; every
    /// other listed backup runs its pass. The client stores, in one write,
    /// the stops, this pass's start as its next `last_pass_at_ms`, and
    /// `acknowledged` in place of its acknowledged set
    /// ([`StopOutcome::acknowledged`]).
    Run {
        stopped: Vec<StoppedBackup>,
        acknowledged: Vec<String>,
    },
    /// The notices could not be read completely: as
    /// [`BackupPassGate::CheckFailed`]. Both `last_pass_at_ms` and the
    /// acknowledged set stay where they were.
    CheckFailed,
}

/// Decide a pass (spec Amendments 12c and 12d): `notices` is `None` when they
/// could not be read completely (a server or network error, or any page
/// missing), else every backup notice from [`notices_since`]`(last_pass_at_ms)`
/// on. `acknowledged` is the set the previous pass returned (empty on a
/// device's first pass). Otherwise as [`backup_stop_v2`].
pub fn backup_pass_gate_v2(
    notices: Option<&[ListedNotice]>,
    last_pass_at_ms: i64,
    acknowledged: &[String],
    listing: &StopListing,
) -> BackupPassGateV2 {
    match notices {
        Some(notices) => {
            let StopOutcome { stopped, acknowledged } = backup_stop_v2(notices, last_pass_at_ms, acknowledged, listing);
            BackupPassGateV2::Run { stopped, acknowledged }
        }
        None => BackupPassGateV2::CheckFailed,
    }
}
