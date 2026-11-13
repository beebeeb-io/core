//! The pass gate (backup spec Amendments 12, 12c and 12d, core `CLAUDE.md`
//! Never break: "a stopped backup never fills the account up again by
//! itself").
//!
//! Before a pass queues anything it reads every `files_removed` and
//! `backup_deleted` notice from core's [`notices_since`](beebeeb_core::backup::notices_since)`(last_pass_at)` on
//! (the server's LD-0141 filter; the 10-minute overlap is core's
//! `NOTICE_OVERLAP_MS`), reads whether its device and category folders are
//! still live, and asks core's [`backup_pass_gate_v2`] with the notice ids
//! the last pass acknowledged:
//!
//! - `CheckFailed` (a notice page or a folder read failed, or the server did
//!   not filter): the pass uploads nothing and turns nothing off, and its
//!   `last_pass_at` and acknowledged ids stay, so the next pass reads the same
//!   notices again.
//! - `Run` with a stopped backup: the backup turns off with core's reason, its
//!   queued uploads are cancelled, and nothing uploads until the person
//!   chooses "Back up again" ([`super::BackupService::back_up_again`]).
//! - `Run` with nothing stopped: the pass runs.
//!
//! Either `Run` is stored in ONE write (Amendment 12d rule 4): the stop, this
//! pass's start on the server's clock as the next `last_pass_at`, and the
//! acknowledged ids core returned in place of the old set. The set is kept by
//! "Back up again", so a notice the person has seen never stops the backup
//! again. There is no overlap rule here: core's is the one rule.

use beebeeb_api::{ApiError, routes::notifications as api};
use beebeeb_core::backup::{
    BackupPassGateV2, ListedNotice, StopFolder, StopListing, backup_pass_gate_v2, first_pass_baseline,
    parse_backup_notice,
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

/// Why this device's backup is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupStop {
    pub reason: BackupStopReason,
}

/// The pass gate's durable state, kept by the platform next to the manifest
/// ([`super::BackupManifestStore`]). Every field is written together, in one
/// write: a store that keeps one without the others breaks Amendment 12d.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupPassState {
    /// Server clock, milliseconds: the last pass's start. The next pass reads
    /// the notices from core's [`notices_since`](beebeeb_core::backup::notices_since) of it. `None` until this
    /// device's first pass under this engine; [`first_pass_baseline`] stands
    /// in for it until then.
    pub last_pass_at_ms: Option<i64>,
    /// `Some` while the backup is off. A stopped backup queues nothing.
    pub stopped: Option<BackupStop>,
    /// The notice ids the last pass acknowledged (core's
    /// [`backup_pass_gate_v2`]), sorted: a notice among them never counts
    /// again. Kept by "Back up again", unchanged by a failed check.
    pub acknowledged: Vec<String>,
}

/// The device and category folders a pass checks, found once per configured
/// folder from its place below the Backups root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckedFolder {
    pub(crate) id: String,
    pub(crate) device_folder_id: String,
    pub(crate) category_folder_id: Option<String>,
    /// The server no longer has the configured folder: it stands in for the
    /// device folder, never live, so the gate can only stop or skip the pass.
    pub(crate) gone: bool,
}

impl CheckedFolder {
    /// A configured folder the server no longer has.
    pub(crate) fn gone(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            device_folder_id: id.to_owned(),
            category_folder_id: None,
            gone: true,
        }
    }
}

/// What a pass does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassDecision {
    Run,
    Stopped(BackupStop),
    CheckFailed,
}

/// Core's answer for one pass, before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gate {
    /// The notices or the folders could not be read: store nothing.
    CheckFailed,
    /// Store, in one write, `stop` (when the backup turns off), the pass's
    /// start as `last_pass_at` and `acknowledged` in place of the old set.
    Decided {
        stop: Option<BackupStop>,
        acknowledged: Vec<String>,
    },
}

/// The notices one pass read, all pages.
pub(crate) struct NoticeRead {
    notices: Vec<ListedNotice>,
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

/// Core's decision for one pass ([`backup_pass_gate_v2`]). `read` is `None`
/// when the notices could not be read completely, `listing` when the folders
/// could not be read; `acknowledged` is the stored set.
pub(crate) fn decide(
    read: Option<&NoticeRead>,
    baseline: i64,
    acknowledged: &[String],
    listing: Option<&StopListing>,
) -> Gate {
    let (Some(read), Some(listing)) = (read, listing) else {
        return Gate::CheckFailed;
    };
    match backup_pass_gate_v2(Some(read.notices.as_slice()), baseline, acknowledged, listing) {
        BackupPassGateV2::CheckFailed => Gate::CheckFailed,
        BackupPassGateV2::Run { stopped, acknowledged } => Gate::Decided {
            stop: stopped.first().map(|stop| BackupStop { reason: stop.reason }),
            acknowledged,
        },
    }
}

/// The next `last_pass_at`: this pass's start on the server's clock (core
/// applies the overlap when the next pass reads), never earlier than the one
/// it read from. Without the server's clock it stays where it was.
pub(crate) fn pass_start(read: &NoticeRead, baseline: i64) -> i64 {
    read.server_now_ms.map_or(baseline, |now| now.max(baseline))
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
    /// Every backup notice written at or after `since_ms` (server clock; the
    /// pass sends core's [`notices_since`](beebeeb_core::backup::notices_since) of its `last_pass_at`), all pages,
    /// each with its row id. `None` when any page failed, a row could not be dated, the
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
                notices.push(ListedNotice {
                    id: Some(row.id),
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
        match self.get_file_inner(id).await {
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
        let device_folder_live = !folder.gone && self.backup_row_live(&folder.device_folder_id).await.ok()?;
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
    use beebeeb_core::backup::{NOTICE_OVERLAP_MS, notices_since};
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

    fn removed(id: &str, at: i64) -> ListedNotice {
        ListedNotice {
            id: Some(id.to_owned()),
            notice: BackupNotice::FilesRemoved {
                reason: BackupStopReason::EraseRequest,
            },
            created_at_ms: at,
        }
    }

    fn read(notices: Vec<ListedNotice>, now: Option<i64>) -> NoticeRead {
        NoticeRead {
            notices,
            server_now_ms: now,
        }
    }

    #[test]
    fn a_notice_inside_the_overlap_stops_and_is_acknowledged() {
        // Written while the last pass (at 100 minutes) read: dated before it.
        let late = removed("n1", 100 * 60_000 - 60_000);
        assert_eq!(
            decide(
                Some(&read(vec![late], Some(110 * 60_000))),
                100 * 60_000,
                &[],
                Some(&listing())
            ),
            Gate::Decided {
                stop: Some(BackupStop {
                    reason: BackupStopReason::EraseRequest
                }),
                acknowledged: vec!["n1".into()],
            }
        );
    }

    #[test]
    fn an_acknowledged_notice_never_counts_again() {
        let seen = removed("n1", 100 * 60_000 - 60_000);
        assert_eq!(
            decide(
                Some(&read(vec![seen], Some(110 * 60_000))),
                100 * 60_000,
                &["n1".into()],
                Some(&listing())
            ),
            Gate::Decided {
                stop: None,
                acknowledged: vec!["n1".into()],
            }
        );
    }

    #[test]
    fn no_notices_or_no_listing_skips_the_pass() {
        let empty = read(Vec::new(), Some(8_000));
        assert_eq!(decide(None, 0, &[], Some(&listing())), Gate::CheckFailed);
        assert_eq!(decide(Some(&empty), 0, &[], None), Gate::CheckFailed);
        assert_eq!(
            decide(Some(&empty), 0, &[], Some(&listing())),
            Gate::Decided {
                stop: None,
                acknowledged: Vec::new()
            }
        );
    }

    #[test]
    fn the_next_baseline_is_the_pass_start_and_never_goes_back() {
        assert_eq!(
            pass_start(&read(Vec::new(), Some(NOTICE_OVERLAP_MS * 3)), 0),
            NOTICE_OVERLAP_MS * 3
        );
        assert_eq!(pass_start(&read(Vec::new(), Some(4)), 5), 5);
        assert_eq!(pass_start(&read(Vec::new(), None), 42), 42);
    }

    #[test]
    fn http_dates_and_notice_times_read_in_milliseconds() {
        assert_eq!(http_date_ms("Sun, 08 Nov 2026 03:10:00 GMT"), Some(1_794_107_400_000));
        assert_eq!(rfc3339_ms("2026-11-08T03:10:00.123Z"), Some(1_794_107_400_123));
        assert_eq!(http_date_ms("yesterday"), None);
    }

    // ── The 12d vectors through the service's own decision ─────────────────

    fn case_listing(v: &Value) -> StopListing {
        StopListing {
            device_folder_id: Uuid::parse_str(v["device_folder_id"].as_str().unwrap()).unwrap(),
            device_folder_live: v["device_folder_live"].as_bool().unwrap(),
            folders: v["folders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| StopFolder {
                    category: Category::from_key(f["category"].as_str().unwrap()).unwrap(),
                    category_folder_id: f["category_folder_id"].as_str().map(|id| Uuid::parse_str(id).unwrap()),
                    category_folder_live: f["category_folder_live"].as_bool(),
                })
                .collect(),
        }
    }

    /// The notices as the service reads its rows: an id that is missing or
    /// not a string is `None`.
    fn case_read(case: &Value) -> NoticeRead {
        let notices = case["notices"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| {
                parse_backup_notice(n["type"].as_str().unwrap(), &n["data"]).map(|notice| ListedNotice {
                    id: n["id"].as_str().map(str::to_owned),
                    notice,
                    created_at_ms: n["created_at_ms"].as_i64().unwrap(),
                })
            })
            .collect();
        read(notices, None)
    }

    /// Every `stop_ack`, `gate_ack`, `notices_since` and `notice_overlap` case
    /// of `backup_plan.json` (Amendment 12d) through [`decide`], the
    /// service's one call into core, and the `since` it sends. The service
    /// stores the first stop's reason (core orders stops by category key).
    #[test]
    fn the_12d_vectors_hold_through_the_service_decision() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/consolidation/backup_plan.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut counts = (0, 0, 0, 0);
        for case in doc["cases"].as_array().unwrap() {
            let id = case["id"].as_str().unwrap();
            let kind = case["kind"].as_str().unwrap();
            match kind {
                "stop_ack" | "gate_ack" => {
                    let fetched = case["notices_fetch_ok"].as_bool().unwrap_or(true);
                    let read = case_read(case);
                    let acknowledged: Vec<String> = case["acknowledged"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|a| a.as_str().unwrap().to_owned())
                        .collect();
                    let got = decide(
                        fetched.then_some(&read),
                        case["last_pass_at_ms"].as_i64().unwrap(),
                        &acknowledged,
                        Some(&case_listing(&case["listing"])),
                    );
                    let expect = &case["expect"];
                    let want = if expect["outcome"] == "check_failed" {
                        Gate::CheckFailed
                    } else {
                        Gate::Decided {
                            stop: expect["stopped"].as_array().unwrap().first().map(|stop| BackupStop {
                                reason: BackupStopReason::parse(stop["reason"].as_str().unwrap()).unwrap(),
                            }),
                            acknowledged: expect["acknowledged"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|a| a.as_str().unwrap().to_owned())
                                .collect(),
                        }
                    };
                    assert_eq!(got, want, "{id}");
                    if kind == "stop_ack" {
                        counts.0 += 1;
                    } else {
                        counts.1 += 1;
                    }
                }
                "notices_since" => {
                    counts.2 += 1;
                    let got = notices_since(case["last_pass_at_ms"].as_i64().unwrap());
                    assert_eq!(got, case["expect"].as_i64().unwrap(), "{id}");
                }
                "notice_overlap" => {
                    counts.3 += 1;
                    assert_eq!(NOTICE_OVERLAP_MS, case["expect"].as_i64().unwrap(), "{id}");
                }
                _ => {}
            }
        }
        assert_eq!(
            doc["cases"].as_array().unwrap().len(),
            154,
            "the whole backup_plan file"
        );
        assert_eq!(counts, (17, 4, 4, 1), "12d case counts per kind");
    }
}
