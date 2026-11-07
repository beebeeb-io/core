//! Why a backup stops, and its words, for iOS (and later Android): spec
//! Amendment 12, LD-0121. Every function forwards to `beebeeb_core::backup`;
//! no rule lives here. A notice row is read leniently (a row of another type
//! is skipped, a removal with an unknown reason still stops); every other
//! string this side parses (a category key, an id, a reason) that it does not
//! know is `CryptoError::InvalidInput`.

use beebeeb_core::backup as rules;
use beebeeb_types::backup::{BackupStopReason, Category};

use super::{invalid, parse_id};
use crate::CryptoError;

/// One `notifications` row as the server lists it.
#[derive(uniffi::Record)]
pub struct BackupNoticeRow {
    /// The row's `type` (`"files_removed"`, `"backup_deleted"`, or any other
    /// type, which is skipped).
    pub kind: String,
    /// The row's `data`, as JSON text. Text that does not parse reads as
    /// `null`.
    pub data_json: String,
    /// The row's `created_at`, in milliseconds since the epoch (server clock).
    pub created_at_ms: i64,
}

/// One backup turned on on this device, as the listing shows it.
#[derive(uniffi::Record)]
pub struct BackupStopFolder {
    /// A category key (`"camera_roll"`, `"custom:<name>"`, ...).
    pub category: String,
    /// `None` when the category folder was never created (a first backup).
    pub category_folder_id: Option<String>,
    /// `Some(false)` only when the category folder existed and is now trashed
    /// or gone.
    pub category_folder_live: Option<bool>,
}

#[derive(uniffi::Record)]
pub struct BackupStopListing {
    pub device_folder_id: String,
    /// `false` only when this device's folder existed and is now trashed or
    /// gone.
    pub device_folder_live: bool,
    pub folders: Vec<BackupStopFolder>,
}

/// A backup that turns off: its category key and the reason
/// (`"backup_deleted"`, `"erase_request"`, `"account_lapsed"`,
/// `"inactive_cleanup"`, `"account_reset"`, `"unknown_removal"`, `"unknown"`).
#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupStopped {
    pub category: String,
    pub reason: String,
}

fn notice_data(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap_or(serde_json::Value::Null)
}

fn parse_reason(reason: &str) -> Result<BackupStopReason, CryptoError> {
    BackupStopReason::parse(reason).ok_or_else(|| invalid("unknown backup stop reason"))
}

/// Which backups turn off on this pass, and why (spec Amendment 12, steps
/// 1-4). `last_pass_at_ms` is on the server's clock, like the notices: when
/// this device's previous pass of these backups started, or when the person
/// last turned a backup on or chose "Back up again" since. Empty means nothing
/// changes. An unknown category key or an id that is not a UUID in the listing
/// is `InvalidInput`.
#[uniffi::export]
pub fn backup_stop(
    notices: Vec<BackupNoticeRow>,
    last_pass_at_ms: i64,
    listing: BackupStopListing,
) -> Result<Vec<BackupStopped>, CryptoError> {
    let notices = received_notices(&notices);
    let listing = stop_listing(listing)?;
    Ok(stopped_dtos(rules::backup_stop(&notices, last_pass_at_ms, &listing)))
}

/// The backup notices among the rows (another kind is skipped; data that is
/// not JSON reads as `null`).
fn received_notices(rows: &[BackupNoticeRow]) -> Vec<rules::ReceivedNotice> {
    rows.iter()
        .filter_map(|row| {
            rules::parse_backup_notice(&row.kind, &notice_data(&row.data_json)).map(|notice| rules::ReceivedNotice {
                notice,
                created_at_ms: row.created_at_ms,
            })
        })
        .collect()
}

fn stop_listing(listing: BackupStopListing) -> Result<rules::StopListing, CryptoError> {
    Ok(rules::StopListing {
        device_folder_id: parse_id("device_folder_id", &listing.device_folder_id)?,
        device_folder_live: listing.device_folder_live,
        folders: listing
            .folders
            .into_iter()
            .map(|f| {
                Ok(rules::StopFolder {
                    category: Category::from_key(&f.category).ok_or_else(|| invalid("unknown category key"))?,
                    category_folder_id: f
                        .category_folder_id
                        .as_deref()
                        .map(|id| parse_id("category_folder_id", id))
                        .transpose()?,
                    category_folder_live: f.category_folder_live,
                })
            })
            .collect::<Result<Vec<_>, CryptoError>>()?,
    })
}

fn stopped_dtos(stopped: Vec<rules::StoppedBackup>) -> Vec<BackupStopped> {
    stopped
        .into_iter()
        .map(|s| BackupStopped {
            category: s.category.key(),
            reason: s.reason.as_str().to_string(),
        })
        .collect()
}

/// The `last_pass_at_ms` of a device with none under this engine yet (spec
/// Amendment 12c): the moment backups were set up on this device, or an
/// upgraded device's last successful backup under the old engine; with both,
/// the earlier; with neither, 0 (any removal notice stops the backup). Both on
/// the server's clock.
#[uniffi::export]
pub fn backup_first_pass_baseline(setup_at_ms: Option<i64>, legacy_last_backup_ms: Option<i64>) -> i64 {
    rules::first_pass_baseline(setup_at_ms, legacy_last_backup_ms)
}

/// What one pass does before it uploads anything (spec Amendments 12, 12c).
#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BackupPassGate {
    /// The notices were read: `stopped` turn off with their words; every
    /// other listed backup runs, and this pass's start becomes the next
    /// `last_pass_at_ms`.
    Run { stopped: Vec<BackupStopped> },
    /// The notices could not be read: upload nothing, turn nothing off, show
    /// `backup_check_failed_words()`, retry at the next scheduled pass, and
    /// keep `last_pass_at_ms` where it was.
    CheckFailed,
}

/// Decide a pass. `notices_fetch_ok` is `false` when the notices could not be
/// read completely (a server or network error, or a page missing); `notices`
/// is then ignored. Otherwise as `backup_stop`.
#[uniffi::export]
pub fn backup_pass_gate(
    notices_fetch_ok: bool,
    notices: Vec<BackupNoticeRow>,
    last_pass_at_ms: i64,
    listing: BackupStopListing,
) -> Result<BackupPassGate, CryptoError> {
    let listing = stop_listing(listing)?;
    let notices = received_notices(&notices);
    Ok(
        match rules::backup_pass_gate(
            notices_fetch_ok.then_some(notices.as_slice()),
            last_pass_at_ms,
            &listing,
        ) {
            rules::BackupPassGate::Run { stopped } => BackupPassGate::Run {
                stopped: stopped_dtos(stopped),
            },
            rules::BackupPassGate::CheckFailed => BackupPassGate::CheckFailed,
        },
    )
}

/// The words when the notices could not be read: "Couldn't check — will
/// retry."
#[uniffi::export]
pub fn backup_check_failed_words() -> String {
    rules::MSG_STOP_CHECK_FAILED.to_string()
}

/// The reason a `notifications` row gives, or `None` for a row that is not a
/// backup notice: for showing the notification itself with
/// `backup_stop_words`.
#[uniffi::export]
pub fn backup_notice_reason(kind: String, data_json: String) -> Option<String> {
    rules::parse_backup_notice(&kind, &notice_data(&data_json)).map(|n| n.reason().as_str().to_string())
}

/// The words a stopped backup shows (spec Amendment 12), followed by the
/// action `backup_again_action()`. `device` is this device's name and
/// `folder` the folder's display name; the four account-wide reasons name
/// neither.
#[uniffi::export]
pub fn backup_stop_words(reason: String, device: String, folder: String) -> Result<String, CryptoError> {
    Ok(rules::backup_stop_words(parse_reason(&reason)?, &device, &folder))
}

/// The action every stopped backup offers: `"Back up again"`.
#[uniffi::export]
pub fn backup_again_action() -> String {
    rules::MSG_BACK_UP_AGAIN.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_cases() -> Vec<serde_json::Value> {
        let path = format!(
            "{}/../test-vectors/consolidation/backup_plan.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("json");
        doc["cases"].as_array().expect("cases").clone()
    }

    fn of_kind(kind: &str) -> Vec<serde_json::Value> {
        plan_cases().into_iter().filter(|c| c["kind"] == kind).collect()
    }

    /// Every stop case of the shared vector through the binding, the rows as
    /// a client reads them (data as JSON text).
    #[test]
    fn uniffi_backup_stop_matches_every_stop_case() {
        let cases = of_kind("stop");
        assert_eq!(cases.len(), 22);
        for case in &cases {
            let notices = case["notices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| BackupNoticeRow {
                    kind: n["type"].as_str().unwrap().to_string(),
                    data_json: n["data"].to_string(),
                    created_at_ms: n["created_at_ms"].as_i64().unwrap(),
                })
                .collect();
            let l = &case["listing"];
            let listing = BackupStopListing {
                device_folder_id: l["device_folder_id"].as_str().unwrap().to_string(),
                device_folder_live: l["device_folder_live"].as_bool().unwrap(),
                folders: l["folders"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| BackupStopFolder {
                        category: f["category"].as_str().unwrap().to_string(),
                        category_folder_id: f["category_folder_id"].as_str().map(str::to_string),
                        category_folder_live: f["category_folder_live"].as_bool(),
                    })
                    .collect(),
            };
            let got = backup_stop(notices, case["last_pass_at_ms"].as_i64().unwrap(), listing).unwrap();
            let want: Vec<BackupStopped> = case["expect"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| BackupStopped {
                    category: s["category"].as_str().unwrap().to_string(),
                    reason: s["reason"].as_str().unwrap().to_string(),
                })
                .collect();
            assert_eq!(got, want, "{}", case["id"]);
        }
    }

    #[test]
    fn uniffi_backup_notice_reason_and_words_match_the_vectors() {
        let notices = of_kind("notice");
        assert_eq!(notices.len(), 10);
        for case in &notices {
            let got = backup_notice_reason(case["type"].as_str().unwrap().to_string(), case["data"].to_string());
            let want = case["expect"]["reason"].as_str().map(str::to_string);
            assert_eq!(got, want, "{}", case["id"]);
        }
        let words = of_kind("stop_words");
        assert_eq!(words.len(), 7);
        for case in &words {
            let got = backup_stop_words(
                case["reason"].as_str().unwrap().to_string(),
                case["device"].as_str().unwrap().to_string(),
                case["folder"].as_str().unwrap().to_string(),
            )
            .unwrap();
            assert_eq!(got, case["expect"].as_str().unwrap(), "{}", case["id"]);
        }
        assert_eq!(
            backup_again_action(),
            of_kind("stop_action")[0]["expect"].as_str().unwrap()
        );
        // Data that is not JSON reads as null: a removal still stops.
        assert_eq!(
            backup_notice_reason("files_removed".to_string(), "{not json".to_string()).as_deref(),
            Some("unknown_removal")
        );
    }

    #[test]
    fn uniffi_backup_stop_unknown_strings_are_errors() {
        let listing = |category: &str, device: &str, folder: Option<&str>| BackupStopListing {
            device_folder_id: device.to_string(),
            device_folder_live: true,
            folders: vec![BackupStopFolder {
                category: category.to_string(),
                category_folder_id: folder.map(str::to_string),
                category_folder_live: Some(true),
            }],
        };
        let dev = "00000064-0000-4000-8000-0000000000aa";
        assert!(backup_stop(vec![], 0, listing("pictures", dev, Some(dev))).is_ok());
        for bad in [
            listing("Pictures", dev, None),
            listing("custom:", dev, None),
            listing("pictures", "GLegion", None),
            listing("pictures", dev, Some("not-a-uuid")),
        ] {
            assert!(matches!(
                backup_stop(vec![], 0, bad),
                Err(CryptoError::InvalidInput { .. })
            ));
        }
        for bad in ["Unknown", "erased_request", ""] {
            assert!(matches!(
                backup_stop_words(bad.to_string(), String::new(), String::new()),
                Err(CryptoError::InvalidInput { .. })
            ));
        }
    }

    fn rows(case: &serde_json::Value) -> Vec<BackupNoticeRow> {
        case["notices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| BackupNoticeRow {
                kind: n["type"].as_str().unwrap().to_string(),
                data_json: n["data"].to_string(),
                created_at_ms: n["created_at_ms"].as_i64().unwrap(),
            })
            .collect()
    }

    fn listing_dto(l: &serde_json::Value) -> BackupStopListing {
        BackupStopListing {
            device_folder_id: l["device_folder_id"].as_str().unwrap().to_string(),
            device_folder_live: l["device_folder_live"].as_bool().unwrap(),
            folders: l["folders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| BackupStopFolder {
                    category: f["category"].as_str().unwrap().to_string(),
                    category_folder_id: f["category_folder_id"].as_str().map(str::to_string),
                    category_folder_live: f["category_folder_live"].as_bool(),
                })
                .collect(),
        }
    }

    /// Amendment 12c through the binding: every baseline and gate case, and
    /// the check-failed words.
    #[test]
    fn uniffi_backup_first_pass_baseline_and_pass_gate_match_the_vectors() {
        let baselines = of_kind("baseline");
        assert_eq!(baselines.len(), 5);
        for case in &baselines {
            let got = backup_first_pass_baseline(case["setup_at_ms"].as_i64(), case["legacy_last_backup_ms"].as_i64());
            assert_eq!(got, case["expect"].as_i64().unwrap(), "{}", case["id"]);
        }
        let gates = of_kind("gate");
        assert_eq!(gates.len(), 5);
        for case in &gates {
            let got = backup_pass_gate(
                case["notices_fetch_ok"].as_bool().unwrap(),
                rows(case),
                case["last_pass_at_ms"].as_i64().unwrap(),
                listing_dto(&case["listing"]),
            )
            .unwrap();
            let want = match case["expect"]["outcome"].as_str().unwrap() {
                "check_failed" => BackupPassGate::CheckFailed,
                "run" => BackupPassGate::Run {
                    stopped: case["expect"]["stopped"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| BackupStopped {
                            category: s["category"].as_str().unwrap().to_string(),
                            reason: s["reason"].as_str().unwrap().to_string(),
                        })
                        .collect(),
                },
                other => panic!("unknown outcome {other}"),
            };
            assert_eq!(got, want, "{}", case["id"]);
        }
        assert_eq!(
            backup_check_failed_words(),
            of_kind("check_failed_words")[0]["expect"].as_str().unwrap()
        );
    }
}
