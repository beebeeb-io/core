//! The pass gate (backup spec Amendments 12 and 12c, core `CLAUDE.md` Never
//! break: "a stopped backup never fills the account up again by itself").
//!
//! Before a pass queues anything it reads every `files_removed` and
//! `backup_deleted` notice written since its last pass (the server's LD-0141
//! filter), reads whether its device and category folders are still live, and
//! asks core's [`backup_pass_gate`]:
//!
//! - `CheckFailed` (a notice page or a folder read failed, or the server did
//!   not filter): the pass uploads nothing and turns nothing off, and its
//!   `last_pass_at` stays, so the next pass reads the same notices again.
//! - `Run` with a stopped backup: the backup turns off with core's reason, its
//!   queued uploads are cancelled, and nothing uploads until the person
//!   chooses "Back up again" ([`super::BackupService::back_up_again`]).
//! - `Run` with nothing stopped: the pass runs, and its start on the server's
//!   clock becomes the next `last_pass_at`.
//!
//! The one call into core is [`decide`], so a later core gate (an overlap
//! margin and acknowledged notice ids, core v0.2.4) changes only that function
//! and [`next_last_pass_at`].

use beebeeb_api::{ApiError, routes::notifications as api};
use beebeeb_core::backup::{
    BackupPassGate, ReceivedNotice, StopFolder, StopListing, backup_pass_gate, first_pass_baseline, parse_backup_notice,
};
use beebeeb_types::backup::{BackupStopReason, Category, NOTICE_BACKUP_DELETED, NOTICE_FILES_REMOVED};
use chrono::DateTime;
use serde_json::Value;
use uuid::Uuid;

use super::{AssetKind, BackupConfiguration};
use crate::{Client, ClientError};

/// The most notice pages one pass reads (500 rows each). A listing that does
/// not end by then is not complete, so the pass is skipped.
const MAX_NOTICE_PAGES: usize = 64;

/// How far before the previous pass's start the next pass reads the notices
/// again. A notice is dated when its job's transaction starts and seen when
/// it commits, and the server's nodes and database keep their own clocks, so
/// a pass that starts while a removal is still committing would otherwise
/// step past its notice. Reading a notice twice is harmless: one that would
/// stop this backup already stopped it the first time. The client's stand-in
/// for core's own overlap margin (core v0.2.4).
pub const NOTICE_OVERLAP_MS: i64 = 10 * 60 * 1000;

/// Why this device's backup is off, and how far the notices were read when it
/// turned off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupStop {
    pub reason: BackupStopReason,
    /// Server clock, milliseconds: the pass's start or the newest notice it
    /// read, whichever is later. "Back up again" moves `last_pass_at` here,
    /// so the notices the person has seen do not stop the backup again.
    pub through_ms: i64,
}

/// The pass gate's durable state, kept by the platform next to the manifest
/// ([`super::BackupManifestStore`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackupPassState {
    /// Server clock, milliseconds: where the next pass starts reading the
    /// notices. `None` until this device's first pass under this engine;
    /// [`first_pass_baseline`] stands in for it until then.
    pub last_pass_at_ms: Option<i64>,
    /// `Some` while the backup is off. A stopped backup queues nothing.
    pub stopped: Option<BackupStop>,
}

/// The device and category folders a pass checks, found once per configured
/// folder from its place below the Backups root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckedFolder {
    pub(crate) id: String,
    pub(crate) device_folder_id: String,
    pub(crate) category_folder_id: Option<String>,
}

/// What a pass does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassDecision {
    Run,
    Stopped(BackupStop),
    CheckFailed,
}

/// The notices one pass read, all pages.
pub(crate) struct NoticeRead {
    notices: Vec<ReceivedNotice>,
    /// The first page's `Date`: this pass's start on the server's clock.
    server_now_ms: Option<i64>,
}

/// The category a kind of asset is backed up as.
pub(crate) fn category(kind: AssetKind) -> Category {
    match kind {
        AssetKind::Photo => Category::CameraRoll,
        AssetKind::ContactSnapshot => Category::Contacts,
        AssetKind::CalendarSnapshot => Category::Calendar,
    }
}

/// The `last_pass_at` this pass reads from: the last pass's, or, on this
/// device's first pass, core's baseline from what the platform knows.
pub(crate) fn baseline(state: &BackupPassState, configuration: &BackupConfiguration) -> i64 {
    state
        .last_pass_at_ms
        .unwrap_or_else(|| first_pass_baseline(configuration.setup_at_ms, configuration.legacy_last_backup_ms))
}

/// Core's decision for one pass. `read` is `None` when the notices could not
/// be read completely, `listing` when the folders could not be read.
pub(crate) fn decide(read: Option<&NoticeRead>, baseline: i64, listing: Option<&StopListing>) -> PassDecision {
    let Some(listing) = listing else {
        return PassDecision::CheckFailed;
    };
    match backup_pass_gate(read.map(|read| read.notices.as_slice()), baseline, listing) {
        BackupPassGate::CheckFailed => PassDecision::CheckFailed,
        BackupPassGate::Run { stopped } => match (stopped.first(), read) {
            (None, _) => PassDecision::Run,
            (Some(stop), Some(read)) => PassDecision::Stopped(BackupStop {
                reason: stop.reason,
                through_ms: read
                    .notices
                    .iter()
                    .map(|notice| notice.created_at_ms)
                    .chain(read.server_now_ms)
                    .fold(baseline, i64::max),
            }),
            (Some(_), None) => PassDecision::CheckFailed,
        },
    }
}

/// The `last_pass_at` after a pass that ran: its start on the server's clock
/// less [`NOTICE_OVERLAP_MS`], never earlier than the one it read from. Without
/// the server's clock it stays where it was.
pub(crate) fn next_last_pass_at(read: &NoticeRead, baseline: i64) -> i64 {
    read.server_now_ms
        .map_or(baseline, |now| now.saturating_sub(NOTICE_OVERLAP_MS).max(baseline))
}

fn rfc3339_ms(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|time| time.timestamp_millis())
}

/// An HTTP `Date` (IMF-fixdate, second precision) in milliseconds.
fn http_date_ms(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|time| time.timestamp_millis())
}

impl Client {
    /// Every backup notice written at or after `since_ms` (server clock), all
    /// pages. `None` when any page failed, a row could not be dated, the
    /// server did not filter (no `next_cursor` key), a cursor repeated, or the
    /// listing ran past [`MAX_NOTICE_PAGES`]: the pass then cannot know
    /// whether the account was emptied.
    pub(crate) async fn backup_notices_since(&self, since_ms: i64) -> Option<NoticeRead> {
        let types = [NOTICE_FILES_REMOVED, NOTICE_BACKUP_DELETED];
        let mut notices = Vec::new();
        let mut server_now_ms = None;
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        for page_number in 0..MAX_NOTICE_PAGES {
            let endpoint = api::filtered(&types, since_ms, cursor.as_deref());
            let (page, date) = self.execute_with_date(&endpoint, &()).await.ok()?;
            if page_number == 0 {
                server_now_ms = date.as_deref().and_then(http_date_ms);
            }
            for row in page.notifications {
                let data = row.data.unwrap_or(Value::Null);
                let Some(notice) = parse_backup_notice(&row.kind, &data) else {
                    continue;
                };
                notices.push(ReceivedNotice {
                    notice,
                    created_at_ms: rfc3339_ms(&row.created_at)?,
                });
            }
            match page.next_cursor? {
                None => {
                    return Some(NoticeRead { notices, server_now_ms });
                }
                Some(next) if next.is_empty() || !seen_cursors.insert(next.clone()) => return None,
                Some(next) => cursor = Some(next),
            }
        }
        None
    }

    /// Whether row `id` is live: present and not in the Trash. A row the
    /// server no longer has (404, or 403 for a row that is not this
    /// account's any more) is gone. Any other failure is an error: the pass
    /// cannot tell.
    async fn backup_row_live(&self, id: &str) -> Result<bool, ClientError> {
        match self.get_file(id).await {
            Ok(row) => Ok(!row.is_trashed),
            Err(ClientError::Api(ApiError::Server(server))) if matches!(server.status, 403 | 404) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// What core's stop rule needs of this device's backup: its device folder,
    /// and the one backup the service writes (into `folder`), each with
    /// whether it is still live. `None` when a read failed or an id is not a
    /// server id.
    pub(crate) async fn backup_stop_listing(&self, folder: &CheckedFolder, kind: AssetKind) -> Option<StopListing> {
        let device_folder_id = Uuid::parse_str(&folder.device_folder_id).ok()?;
        let device_folder_live = self.backup_row_live(&folder.device_folder_id).await.ok()?;
        let (category_folder_id, category_folder_live) = match folder.category_folder_id.as_deref() {
            Some(id) => (
                Some(Uuid::parse_str(id).ok()?),
                Some(self.backup_row_live(id).await.ok()?),
            ),
            None => (None, None),
        };
        Some(StopListing {
            device_folder_id,
            device_folder_live,
            folders: vec![StopFolder {
                category: category(kind),
                category_folder_id,
                category_folder_live,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beebeeb_types::backup::BackupNotice;

    fn listing() -> StopListing {
        StopListing {
            device_folder_id: Uuid::nil(),
            device_folder_live: true,
            folders: vec![StopFolder {
                category: Category::CameraRoll,
                category_folder_id: None,
                category_folder_live: None,
            }],
        }
    }

    fn removed(at: i64) -> ReceivedNotice {
        ReceivedNotice {
            notice: BackupNotice::FilesRemoved {
                reason: BackupStopReason::EraseRequest,
            },
            created_at_ms: at,
        }
    }

    #[test]
    fn a_stop_reaches_past_the_newest_notice_and_the_pass_start() {
        let read = NoticeRead {
            notices: vec![removed(5_000), removed(9_000)],
            server_now_ms: Some(8_000),
        };
        assert_eq!(
            decide(Some(&read), 1_000, Some(&listing())),
            PassDecision::Stopped(BackupStop {
                reason: BackupStopReason::EraseRequest,
                through_ms: 9_000,
            })
        );
    }

    #[test]
    fn no_notices_or_no_listing_skips_the_pass() {
        let read = NoticeRead {
            notices: Vec::new(),
            server_now_ms: Some(8_000),
        };
        assert_eq!(decide(None, 0, Some(&listing())), PassDecision::CheckFailed);
        assert_eq!(decide(Some(&read), 0, None), PassDecision::CheckFailed);
        assert_eq!(decide(Some(&read), 0, Some(&listing())), PassDecision::Run);
    }

    #[test]
    fn the_next_baseline_overlaps_and_never_goes_back() {
        let read = |now| NoticeRead {
            notices: Vec::new(),
            server_now_ms: now,
        };
        assert_eq!(
            next_last_pass_at(&read(Some(NOTICE_OVERLAP_MS * 3)), 0),
            NOTICE_OVERLAP_MS * 2
        );
        assert_eq!(next_last_pass_at(&read(Some(NOTICE_OVERLAP_MS)), 5), 5);
        assert_eq!(next_last_pass_at(&read(None), 42), 42);
    }

    #[test]
    fn http_dates_and_notice_times_read_in_milliseconds() {
        assert_eq!(http_date_ms("Sun, 08 Nov 2026 03:10:00 GMT"), Some(1_794_107_400_000));
        assert_eq!(rfc3339_ms("2026-11-08T03:10:00.123Z"), Some(1_794_107_400_123));
        assert_eq!(http_date_ms("yesterday"), None);
    }
}
