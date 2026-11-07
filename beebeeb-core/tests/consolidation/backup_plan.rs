//! LD-0113 — the backup pass planner, removed-elsewhere, folder presence and
//! rebuilding records (spec §4.2 rules 9-11), with the rebuild's clock rule
//! (LD-0123).
//!
//! Cases live in `test-vectors/consolidation/backup_plan.json`, written by
//! `test-vectors/tools/make_backup_plan_vectors.py`. The two Review Focus tests
//! (plan Review Focus 4 and 5) are Rust tests below the vector runner.

use std::collections::HashSet;

use beebeeb_core::backup::{
    BackupRecord, FolderPresence, PassBudget, PassPlan, REBUILD_FLOOR_MS, RebuildClock, RecordRef, RecordState,
    RemoteEntry, SourceEntry, UploadReason, folder_presence, normalize_key, plan_pass, rebuild_clock_from_date,
    records_from_remote, records_from_remote_with_clock,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub const CONCEPT: &str = "backup_plan";

fn uuid(v: &Value) -> Uuid {
    Uuid::parse_str(v.as_str().expect("uuid string")).expect("uuid")
}

fn s(v: &Value) -> String {
    v.as_str().expect("string").to_string()
}

fn entry(v: &Value) -> SourceEntry {
    SourceEntry {
        key: s(&v["key"]),
        is_dir: v["is_dir"].as_bool().expect("is_dir"),
        size: v["size"].as_u64().expect("size"),
        modified_ms: v["modified_ms"].as_i64().expect("modified_ms"),
    }
}

fn record(v: &Value) -> BackupRecord {
    BackupRecord {
        key: s(&v["key"]),
        size: v["size"].as_u64().expect("size"),
        modified_ms: v["modified_ms"].as_i64().expect("modified_ms"),
        remote_id: uuid(&v["remote_id"]),
        uploaded_at_ms: v["uploaded_at_ms"].as_i64().expect("uploaded_at_ms"),
        state: serde_json::from_value(v["state"].clone()).expect("state"),
    }
}

fn record_json(r: &BackupRecord) -> Value {
    json!({
        "key": r.key,
        "size": r.size,
        "modified_ms": r.modified_ms,
        "remote_id": r.remote_id.to_string(),
        "uploaded_at_ms": r.uploaded_at_ms,
        "state": serde_json::to_value(r.state).expect("state"),
    })
}

fn list<T>(v: &Value, f: impl Fn(&Value) -> T) -> Vec<T> {
    v.as_array().expect("array").iter().map(f).collect()
}

/// The plan as the vector file writes it.
fn plan_json(plan: &PassPlan) -> Value {
    json!({
        "uploads": plan.uploads.iter().map(|u| json!({
            "key": u.key,
            "size": u.size,
            "reason": match u.reason { UploadReason::New => "new", UploadReason::Changed => "changed" },
            "record_key": u.record_key,
            "remote_id": u.remote_id.map(|id| id.to_string()),
        })).collect::<Vec<_>>(),
        "moves": plan.moves.iter().map(|m| json!({
            "remote_id": m.remote_id.to_string(),
            "from_key": m.from_key,
            "to_key": m.to_key,
        })).collect::<Vec<_>>(),
        "folders": plan.folders,
        "mark_removed_elsewhere": plan.mark_removed_elsewhere.iter().map(|m| json!({
            "key": m.key,
            "remote_id": m.remote_id.to_string(),
        })).collect::<Vec<_>>(),
        "unchanged": plan.unchanged,
        "gone_locally": plan.gone_locally,
        "deferred": plan.deferred,
        "held": plan.held,
        "deferred_unknown": plan.deferred_unknown,
    })
}

fn run_plan_case(case: &Value) -> Value {
    let live: HashSet<Uuid> = list(&case["live_remote"], uuid).into_iter().collect();
    let budget = PassBudget {
        max_uploads: case["budget"]["max_uploads"].as_u64().expect("max_uploads") as usize,
        max_bytes: case["budget"]["max_bytes"].as_u64().expect("max_bytes"),
    };
    plan_json(&plan_pass(
        &list(&case["entries"], entry),
        &list(&case["records"], record),
        &live,
        case["live_remote_complete"].as_bool().expect("live_remote_complete"),
        &list(&case["unseen"], s),
        &list(&case["held"], s),
        budget,
    ))
}

#[test]
fn backup_plan_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 77, "every named backup_plan case is present");

    let (mut plans, mut keys, mut presences, mut rebuilds) = (0, 0, 0, 0);
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "plan" => {
                plans += 1;
                assert_eq!(run_plan_case(case), case["expect"], "{id}");
                // The plan does not depend on the order the walk or the store
                // lists things in.
                let mut reversed = case.clone();
                for field in ["entries", "records"] {
                    reversed[field].as_array_mut().expect("array").reverse();
                }
                assert_eq!(run_plan_case(&reversed), case["expect"], "{id}: reversed inputs");
            }
            "normalize_key" => {
                keys += 1;
                assert_eq!(
                    normalize_key(case["raw"].as_str().unwrap()),
                    s(&case["expected"]),
                    "{id}"
                );
            }
            "presence" => {
                presences += 1;
                let got = folder_presence(
                    case["device_folder_live"].as_bool().unwrap(),
                    case["category_folder_live"].as_bool(),
                );
                let want = match case["expect"].as_str().unwrap() {
                    "present" => FolderPresence::Present,
                    "category_deleted" => FolderPresence::CategoryDeleted,
                    "device_deleted" => FolderPresence::DeviceDeleted,
                    other => panic!("{id}: unknown presence {other}"),
                };
                assert_eq!(got, want, "{id}");
            }
            "rebuild" => {
                rebuilds += 1;
                let remote = list(&case["remote"], |v| RemoteEntry {
                    key: s(&v["key"]),
                    remote_id: uuid(&v["remote_id"]),
                    size: v["size"].as_u64().unwrap(),
                    uploaded_at_ms: v["uploaded_at_ms"].as_i64().unwrap(),
                });
                let clock = RebuildClock {
                    offset_ms: case["clock"]["offset_ms"].as_i64(),
                    margin_ms: case["clock"]["margin_ms"].as_u64().expect("margin_ms"),
                };
                assert!(
                    clock.offset_ms.is_some() || case["clock"]["offset_ms"].is_null(),
                    "{id}: offset_ms is an integer or null"
                );
                let got: Vec<Value> = records_from_remote_with_clock(&remote, &list(&case["entries"], entry), clock)
                    .iter()
                    .map(record_json)
                    .collect();
                assert_eq!(Value::Array(got), case["expect"], "{id}");
            }
            other => panic!("{id}: unknown kind `{other}`"),
        }
    }
    println!(
        "backup_plan: {} cases ({plans} plan, {keys} normalize_key, {presences} presence, {rebuilds} rebuild)",
        cases.len()
    );
    assert_eq!(
        (plans, keys, presences, rebuilds),
        (52, 4, 5, 16),
        "case counts per kind"
    );
}

/// The v0.2.1 rule, "uploaded strictly after the last change": offset 0,
/// margin 0.
const EXACT: RebuildClock = RebuildClock {
    offset_ms: Some(0),
    margin_ms: 0,
};

const UNLIMITED: PassBudget = PassBudget {
    max_uploads: usize::MAX,
    max_bytes: u64::MAX,
};

fn file(key: &str, size: u64, modified_ms: i64) -> SourceEntry {
    SourceEntry {
        key: key.to_string(),
        is_dir: false,
        size,
        modified_ms,
    }
}

fn backed_up(key: &str, size: u64, modified_ms: i64, uploaded_at_ms: i64) -> BackupRecord {
    BackupRecord {
        key: key.to_string(),
        size,
        modified_ms,
        remote_id: Uuid::new_v4(),
        uploaded_at_ms,
        state: RecordState::BackedUp,
    }
}

/// Review Focus 5: `IMG.JPG` -> `img.jpg` on a case-insensitive filesystem is a
/// server-side move, never a second upload, and never two keys for one file.
#[test]
fn case_only_rename_is_a_move() {
    let record = backed_up("Trip/IMG.JPG", 4_000_000, 1_700_000_000_000, 1_700_000_100_000);
    let live: HashSet<Uuid> = [record.remote_id].into_iter().collect();
    let plan = plan_pass(
        &[file("Trip/img.jpg", 4_000_000, 1_700_000_000_000)],
        std::slice::from_ref(&record),
        &live,
        true,
        &[],
        &[],
        UNLIMITED,
    );
    assert!(
        plan.uploads.is_empty(),
        "a case-only rename uploads nothing: {:?}",
        plan.uploads
    );
    assert_eq!(plan.moves.len(), 1);
    assert_eq!(plan.moves[0].remote_id, record.remote_id);
    assert_eq!(
        (plan.moves[0].from_key.as_str(), plan.moves[0].to_key.as_str()),
        ("Trip/IMG.JPG", "Trip/img.jpg")
    );
    assert_eq!((plan.gone_locally, plan.unchanged, plan.deferred), (0, 0, 0));
}

/// Review Focus 4: clocks before 1970 or far in the future, and FAT's 2-second
/// mtimes. Nothing panics, equal is unchanged, a rounded mtime is a change
/// (an upload, never a silent "already backed up"), and the rebuild rule never
/// marks an entry whose last change is not strictly before the upload.
#[test]
fn plan_and_rebuild_handle_negative_future_and_coarse_mtimes() {
    let times = [-1_000, i64::MAX / 2, 1_762_430_402_000, i64::MIN, i64::MAX, 0];
    // Equal stats are unchanged, whatever the clock said.
    for &m in &times {
        let record = backed_up("a.jpg", 7, m, 1_762_430_500_000);
        let live: HashSet<Uuid> = [record.remote_id].into_iter().collect();
        let plan = plan_pass(&[file("a.jpg", 7, m)], &[record], &live, true, &[], &[], UNLIMITED);
        assert_eq!((plan.unchanged, plan.uploads.len()), (1, 0), "modified_ms {m}");
    }
    // A FAT/exFAT copy rounds the mtime to 2 s: a different value, so it uploads.
    let record = backed_up("a.jpg", 7, 1_762_430_401_337, 1_762_430_500_000);
    let live: HashSet<Uuid> = [record.remote_id].into_iter().collect();
    let plan = plan_pass(
        &[file("a.jpg", 7, 1_762_430_402_000)],
        &[record],
        &live,
        true,
        &[],
        &[],
        UNLIMITED,
    );
    assert_eq!(plan.uploads.len(), 1);
    assert_eq!(plan.uploads[0].reason, UploadReason::Changed);

    // Rebuild: marked only when uploaded strictly after the last change.
    let uploads = [
        i64::MIN,
        -1_001,
        -1_000,
        -999,
        0,
        1_762_430_402_000,
        i64::MAX / 2,
        i64::MAX,
    ];
    let mut marked = 0;
    for &m in &times {
        for (i, &uploaded_at_ms) in uploads.iter().enumerate() {
            let remote = [RemoteEntry {
                key: "a.jpg".to_string(),
                remote_id: Uuid::from_u128(i as u128 + 1),
                size: 7,
                uploaded_at_ms,
            }];
            let records = records_from_remote_with_clock(&remote, &[file("a.jpg", 7, m)], EXACT);
            if uploaded_at_ms > m {
                assert_eq!(records.len(), 1, "modified {m}, uploaded {uploaded_at_ms}");
                assert_eq!(records[0].modified_ms, m);
                marked += 1;
            } else {
                assert!(
                    records.is_empty(),
                    "a newer file was marked backed up: modified {m}, uploaded {uploaded_at_ms}"
                );
            }
        }
    }
    assert!(marked > 0, "the grid must contain marked cases, or it proves nothing");
}

/// Plan Amendment 1, items 5-6: a folder the walk could not list is not gone.
/// Without the rule, its record would count as gone and become the source of a
/// server move out of a folder that is merely unreadable.
#[test]
fn unreadable_folder_records_are_not_gone_or_move_sources() {
    let hidden = backed_up("closed/a.jpg", 9, 1_700_000_000_000, 1_700_000_100_000);
    let marked_elsewhere = backed_up("closed/deep/b.jpg", 9, 1_700_000_000_000, 1_700_000_100_000);
    let live: HashSet<Uuid> = [hidden.remote_id].into_iter().collect();
    let plan = plan_pass(
        &[file("open/a.jpg", 9, 1_700_000_000_000)],
        &[hidden, marked_elsewhere],
        &live,
        true,
        &["closed".to_string()],
        &[],
        UNLIMITED,
    );
    assert!(
        plan.moves.is_empty(),
        "no move out of an unreadable folder: {:?}",
        plan.moves
    );
    assert_eq!(plan.uploads.len(), 1);
    assert_eq!(plan.uploads[0].reason, UploadReason::New);
    assert_eq!(plan.gone_locally, 0);
    assert!(
        plan.mark_removed_elsewhere.is_empty(),
        "{:?}",
        plan.mark_removed_elsewhere
    );
}

/// The same for a folder that is not local (OneDrive online-only, iCloud
/// dataless). Its name is NFD on disk (an HFS+-era macOS folder); the walk
/// keys it NFC, as it keys the records, and unseen keys match raw.
#[test]
fn notlocal_folder_records_are_not_move_sources() {
    let record = backed_up("Ren\u{e9}/IMG_1.jpg", 9, 1_700_000_000_000, 1_700_000_100_000);
    let live: HashSet<Uuid> = [record.remote_id].into_iter().collect();
    let plan = plan_pass(
        &[file("Camera/IMG_1.jpg", 9, 1_700_000_000_000)],
        &[record],
        &live,
        true,
        &["Ren\u{e9}".to_string()],
        &[],
        UNLIMITED,
    );
    assert!(plan.moves.is_empty(), "{:?}", plan.moves);
    assert_eq!((plan.uploads.len(), plan.gone_locally), (1, 0));
}

/// Review #1: N keys that keep failing (N >= max_uploads), first in key order,
/// still let every other file through: held keys are skipped and charged
/// nothing.
#[test]
fn failing_first_key_does_not_starve_others() {
    let budget = PassBudget {
        max_uploads: 3,
        max_bytes: u64::MAX,
    };
    let mut entries: Vec<SourceEntry> = (0..4)
        .map(|i| file(&format!("a{i}.pst"), 9, 1_700_000_000_000))
        .collect();
    entries.extend((0..5).map(|i| file(&format!("b{i}.jpg"), 9, 1_700_000_000_000)));
    let held: Vec<String> = (0..4).map(|i| format!("a{i}.pst")).collect();
    let plan = plan_pass(&entries, &[], &HashSet::new(), true, &[], &held, budget);
    let keys: Vec<&str> = plan.uploads.iter().map(|u| u.key.as_str()).collect();
    assert_eq!(keys, ["b0.jpg", "b1.jpg", "b2.jpg"]);
    assert_eq!((plan.held, plan.deferred), (4, 2));
    // Without the host's held list the same entries starve: every pass plans
    // the four failing keys first.
    let starved = plan_pass(&entries, &[], &HashSet::new(), true, &[], &[], budget);
    assert!(starved.uploads.iter().all(|u| u.key.ends_with(".pst")));
}

/// Review #2 (lead 17:28): a record whose id is missing from an incomplete
/// listing is unknown, not dead. A change to its file waits for a complete
/// listing: no Changed or New upload, no move, no mark.
#[test]
fn incomplete_listing_defers_unlisted_record_change() {
    let record = backed_up("a.jpg", 9, 1_700_000_000_000, 1_700_000_100_000);
    let changed = [file("a.jpg", 10, 1_700_000_200_000)];
    let partial = plan_pass(
        &changed,
        std::slice::from_ref(&record),
        &HashSet::new(),
        false,
        &[],
        &[],
        UNLIMITED,
    );
    assert!(partial.uploads.is_empty(), "{:?}", partial.uploads);
    assert!(partial.moves.is_empty() && partial.mark_removed_elsewhere.is_empty());
    assert_eq!(partial.deferred_unknown, 1);
    // The next pass, with a complete listing, decides: the copy is gone, so the
    // file comes back as a new file (ruling A) and the record is marked.
    let complete = plan_pass(
        &changed,
        std::slice::from_ref(&record),
        &HashSet::new(),
        true,
        &[],
        &[],
        UNLIMITED,
    );
    assert_eq!(complete.uploads.len(), 1);
    assert_eq!(complete.uploads[0].reason, UploadReason::New);
    assert_eq!(complete.uploads[0].record_key.as_deref(), Some("a.jpg"));
    assert_eq!(complete.uploads[0].remote_id, None);
    assert_eq!(
        complete.mark_removed_elsewhere,
        [RecordRef {
            key: "a.jpg".to_string(),
            remote_id: record.remote_id
        }]
    );
}

// ── LD-0123: the rebuild's clock rule ─────────────────────────────────────

const HOUR: i64 = 3_600_000;
const MINUTE: i64 = 60_000;
/// The server's clock at the upload.
const T: i64 = 1_762_430_400_000;

fn remote(key: &str, n: u128, size: u64, uploaded_at_ms: i64) -> RemoteEntry {
    RemoteEntry {
        key: key.to_string(),
        remote_id: Uuid::from_u128(n),
        size,
        uploaded_at_ms,
    }
}

fn marked(records: &[BackupRecord]) -> Vec<&str> {
    records.iter().map(|r| r.key.as_str()).collect()
}

/// A device clock 1 h behind: an edit made 20 minutes after the upload (same
/// size) has an mtime 40 minutes before it. Without the offset the copy looks
/// newer than the edit and the edit is never uploaded.
#[test]
fn rebuild_device_clock_behind_same_size_edit_uploads_again() {
    let edited = file("report.docx", 4_096, T + 20 * MINUTE - HOUR);
    let copy = [remote("report.docx", 1, 4_096, T)];
    let clock = RebuildClock {
        offset_ms: Some(HOUR),
        margin_ms: 2_500,
    };
    let records = records_from_remote_with_clock(&copy, std::slice::from_ref(&edited), clock);
    assert!(
        records.is_empty(),
        "a same-size edit after the upload was marked: {records:?}"
    );
    // With no offset known only the floor guards: it covers a clock up to 10
    // minutes behind (here 9, the edit 1 minute after the upload), through the
    // v0.2.1 entry point too. A clock further behind needs the measured offset.
    let nine_behind = file("report.docx", 4_096, T + MINUTE - 9 * MINUTE);
    assert!(records_from_remote(&copy, std::slice::from_ref(&nine_behind)).is_empty());
    // An edit made long enough before the upload is backed up.
    let older = file("report.docx", 4_096, T - 2 * HOUR);
    assert_eq!(
        marked(&records_from_remote_with_clock(&copy, &[older], clock)),
        ["report.docx"]
    );
}

/// A device clock 1 h ahead: a copy made 30 minutes after the edit reads as
/// made before the mtime. With no offset known the file uploads once more,
/// and once that upload has a record the planner leaves it alone: once more,
/// never a loop. With the offset measured it is backed up at once.
#[test]
fn rebuild_device_clock_ahead_uploads_once_more_only() {
    let entry = file("IMG_1.jpg", 9, T - 30 * MINUTE + HOUR);
    let copy = [remote("IMG_1.jpg", 1, 9, T)];
    let rebuilt = records_from_remote_with_clock(&copy, std::slice::from_ref(&entry), RebuildClock::UNKNOWN);
    assert!(rebuilt.is_empty());
    let live: HashSet<Uuid> = [Uuid::from_u128(1)].into_iter().collect();
    let first = plan_pass(std::slice::from_ref(&entry), &rebuilt, &live, true, &[], &[], UNLIMITED);
    assert_eq!(first.uploads.len(), 1, "uploaded once more");
    assert_eq!(first.uploads[0].reason, UploadReason::New);
    // The host writes the record when that upload completes.
    let uploaded = BackupRecord {
        key: entry.key.clone(),
        size: entry.size,
        modified_ms: entry.modified_ms,
        remote_id: Uuid::from_u128(2),
        uploaded_at_ms: T + 5 * MINUTE,
        state: RecordState::BackedUp,
    };
    let live: HashSet<Uuid> = [Uuid::from_u128(1), Uuid::from_u128(2)].into_iter().collect();
    let next = plan_pass(
        std::slice::from_ref(&entry),
        &[uploaded],
        &live,
        true,
        &[],
        &[],
        UNLIMITED,
    );
    assert_eq!((next.uploads.len(), next.unchanged), (0, 1), "only once: {next:?}");
    // With the offset measured, the copy is backed up without an upload.
    let measured = RebuildClock {
        offset_ms: Some(-HOUR),
        margin_ms: 2_500,
    };
    assert_eq!(
        marked(&records_from_remote_with_clock(&copy, &[entry], measured)),
        ["IMG_1.jpg"]
    );
}

/// A small measured offset (the device 1.5 s behind) and its margin: backed up
/// only when uploaded after `mtime + offset + margin`, strictly.
#[test]
fn rebuild_offset_measured_within_margin_marks_backed_up() {
    let clock = RebuildClock {
        offset_ms: Some(1_500),
        margin_ms: 2_300,
    };
    let copies = [
        remote("a.jpg", 1, 7, T + 3_801),
        remote("b.jpg", 2, 7, T + 3_800),
        remote("c.jpg", 3, 7, T + 3_000),
    ];
    let entries = [file("a.jpg", 7, T), file("b.jpg", 7, T), file("c.jpg", 7, T)];
    let records = records_from_remote_with_clock(&copies, &entries, clock);
    assert_eq!(marked(&records), ["a.jpg"]);
    assert_eq!(records[0].remote_id, Uuid::from_u128(1));
    // The helper measures such a clock from a listing response: the header's
    // whole second, sent 200 ms before the device's midpoint.
    let measured = rebuild_clock_from_date(
        Some("Thu, 06 Nov 2025 12:00:01 GMT"),
        1_762_430_398_400,
        1_762_430_398_800,
    );
    assert_eq!(
        measured,
        RebuildClock {
            offset_ms: Some(1_762_430_401_000 - 1_762_430_398_600),
            margin_ms: 2_400,
        }
    );
}

/// No offset known: a copy counts only when uploaded more than 10 minutes
/// after the mtime. The floor is a minimum, so a wider margin still counts.
#[test]
fn rebuild_no_offset_known_uses_ten_minute_floor() {
    let floor = REBUILD_FLOOR_MS as i64;
    assert_eq!(floor, 10 * MINUTE);
    let copies = [remote("a.jpg", 1, 7, T + floor), remote("b.jpg", 2, 7, T + floor + 1)];
    let entries = [file("a.jpg", 7, T), file("b.jpg", 7, T)];
    assert_eq!(
        marked(&records_from_remote_with_clock(
            &copies,
            &entries,
            RebuildClock::UNKNOWN
        )),
        ["b.jpg"]
    );
    // The v0.2.1 entry point is the same rule with no offset known.
    assert_eq!(marked(&records_from_remote(&copies, &entries)), ["b.jpg"]);
    let wide = RebuildClock {
        offset_ms: None,
        margin_ms: 20 * MINUTE as u64,
    };
    assert!(records_from_remote_with_clock(&copies, &entries, wide).is_empty());
}

/// Every failure of the measurement leans toward uploading again: no header,
/// one that does not parse, or a response "received" before it was sent gives
/// the unknown clock, where the floor applies. Extreme values never panic and
/// never mark a copy the exact inequality would not.
#[test]
fn rebuild_clock_failures_and_extremes_lean_toward_uploading() {
    for (date, sent, received) in [
        (None, 0, 10),
        (Some(""), 0, 10),
        (Some("yesterday"), 0, 10),
        (Some("Thu, 06 Nov 2025 12:00:01 GMT"), 10, 9),
    ] {
        assert_eq!(
            rebuild_clock_from_date(date, sent, received),
            RebuildClock::UNKNOWN,
            "{date:?}"
        );
    }
    let huge = rebuild_clock_from_date(Some("Thu, 06 Nov 2025 12:00:01 GMT"), i64::MIN, i64::MAX);
    assert_eq!(huge.margin_ms, u64::MAX, "a round trip past u64 saturates the margin");
    let values = [i64::MIN, -1, 0, 1, i64::MAX];
    for &offset in &values {
        for margin in [0, 1, u64::MAX] {
            let clock = RebuildClock {
                offset_ms: Some(offset),
                margin_ms: margin,
            };
            for &uploaded in &values {
                for &modified in &values {
                    let want = i128::from(uploaded) > i128::from(modified) + i128::from(offset) + i128::from(margin);
                    assert_eq!(
                        clock.copy_is_newer(uploaded, modified),
                        want,
                        "{offset} {margin} {uploaded} {modified}"
                    );
                }
            }
        }
    }
}
