//! LD-0113 — the backup pass planner, removed-elsewhere, folder presence and
//! rebuilding records (spec §4.2 rules 9-11), with the rebuild's clock rule
//! (LD-0123), and why a backup stops with its words (spec Amendments 12 and
//! 12a, LD-0121), read with the overlap margin and acknowledged ids (12d).
//!
//! Cases live in `test-vectors/consolidation/backup_plan.json`, written by
//! `test-vectors/tools/make_backup_plan_vectors.py`. The two Review Focus tests
//! (plan Review Focus 4 and 5) are Rust tests below the vector runner.

use std::collections::HashSet;

use beebeeb_core::backup::{
    BackupPassGate, BackupPassGateV2, BackupRecord, FolderPresence, ListedNotice, MSG_BACK_UP_AGAIN,
    MSG_STOP_CHECK_FAILED, NOTICE_OVERLAP_MS, PassBudget, PassPlan, REBUILD_FLOOR_MS, RebuildClock, ReceivedNotice,
    RecordRef, RecordState, RemoteEntry, SourceEntry, StopFolder, StopListing, StopOutcome, StoppedBackup,
    UploadReason, backup_pass_gate, backup_pass_gate_v2, backup_stop, backup_stop_v2, backup_stop_words,
    first_pass_baseline, folder_presence, normalize_key, notices_since, parse_backup_notice, plan_pass,
    rebuild_clock_from_date, records_from_remote, records_from_remote_with_clock,
};
use beebeeb_types::backup::{BackupNotice, BackupStopReason, Category};
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
    assert_eq!(cases.len(), 154, "every named backup_plan case is present");

    let (mut plans, mut keys, mut presences, mut rebuilds) = (0, 0, 0, 0);
    let (mut stops, mut notices, mut words, mut actions) = (0, 0, 0, 0);
    let (mut baselines, mut gates, mut check_failed) = (0, 0, 0);
    let (mut stop_acks, mut gate_acks, mut sinces, mut overlaps) = (0, 0, 0, 0);
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
            "stop" => {
                stops += 1;
                assert_eq!(run_stop_case(case), case["expect"], "{id}");
                // The answer does not depend on the order of the notices.
                let mut reversed = case.clone();
                reversed["notices"].as_array_mut().expect("array").reverse();
                assert_eq!(run_stop_case(&reversed), case["expect"], "{id}: reversed notices");
            }
            "notice" => {
                notices += 1;
                let got = parse_backup_notice(case["type"].as_str().unwrap(), &case["data"])
                    .map(|n| json!({"type": n.kind(), "reason": n.reason().as_str()}));
                assert_eq!(got.unwrap_or(Value::Null), case["expect"], "{id}");
            }
            "stop_words" => {
                words += 1;
                let reason = BackupStopReason::parse(case["reason"].as_str().unwrap()).expect("reason");
                let got = backup_stop_words(
                    reason,
                    case["device"].as_str().unwrap(),
                    case["folder"].as_str().unwrap(),
                );
                assert_eq!(got, s(&case["expect"]), "{id}");
            }
            "stop_action" => {
                actions += 1;
                assert_eq!(MSG_BACK_UP_AGAIN, s(&case["expect"]), "{id}");
            }
            "baseline" => {
                baselines += 1;
                let got = first_pass_baseline(case["setup_at_ms"].as_i64(), case["legacy_last_backup_ms"].as_i64());
                assert_eq!(got, case["expect"].as_i64().expect("expect"), "{id}");
            }
            "gate" => {
                gates += 1;
                let notices = received(case);
                let fetched = case["notices_fetch_ok"].as_bool().expect("notices_fetch_ok");
                let got = match backup_pass_gate(
                    fetched.then_some(notices.as_slice()),
                    case["last_pass_at_ms"].as_i64().expect("last_pass_at_ms"),
                    &stop_listing(&case["listing"]),
                ) {
                    BackupPassGate::Run { stopped } => json!({"outcome": "run", "stopped": stopped_json(&stopped)}),
                    BackupPassGate::CheckFailed => json!({"outcome": "check_failed"}),
                };
                assert_eq!(got, case["expect"], "{id}");
            }
            "check_failed_words" => {
                check_failed += 1;
                assert_eq!(MSG_STOP_CHECK_FAILED, s(&case["expect"]), "{id}");
            }
            "stop_ack" => {
                stop_acks += 1;
                assert_eq!(run_stop_ack_case(case), case["expect"], "{id}");
                // The answer does not depend on the order of the notices or
                // of the acknowledged ids.
                let mut reversed = case.clone();
                for field in ["notices", "acknowledged"] {
                    reversed[field].as_array_mut().expect("array").reverse();
                }
                assert_eq!(run_stop_ack_case(&reversed), case["expect"], "{id}: reversed inputs");
            }
            "gate_ack" => {
                gate_acks += 1;
                let notices = listed(case);
                let fetched = case["notices_fetch_ok"].as_bool().expect("notices_fetch_ok");
                let got = match backup_pass_gate_v2(
                    fetched.then_some(notices.as_slice()),
                    case["last_pass_at_ms"].as_i64().expect("last_pass_at_ms"),
                    &acknowledged(case),
                    &stop_listing(&case["listing"]),
                ) {
                    BackupPassGateV2::Run { stopped, acknowledged } => {
                        json!({"outcome": "run", "stopped": stopped_json(&stopped), "acknowledged": acknowledged})
                    }
                    BackupPassGateV2::CheckFailed => json!({"outcome": "check_failed"}),
                };
                assert_eq!(got, case["expect"], "{id}");
            }
            "notices_since" => {
                sinces += 1;
                let got = notices_since(case["last_pass_at_ms"].as_i64().expect("last_pass_at_ms"));
                assert_eq!(got, case["expect"].as_i64().expect("expect"), "{id}");
            }
            "notice_overlap" => {
                overlaps += 1;
                assert_eq!(NOTICE_OVERLAP_MS, case["expect"].as_i64().expect("expect"), "{id}");
            }
            other => panic!("{id}: unknown kind `{other}`"),
        }
    }
    println!(
        "backup_plan: {} cases ({plans} plan, {keys} normalize_key, {presences} presence, {rebuilds} rebuild, \
         {stops} stop, {notices} notice, {words} stop_words, {actions} stop_action, {baselines} baseline, \
         {gates} gate, {check_failed} check_failed_words, {stop_acks} stop_ack, {gate_acks} gate_ack, \
         {sinces} notices_since, {overlaps} notice_overlap)",
        cases.len()
    );
    assert_eq!(
        (plans, keys, presences, rebuilds),
        (52, 4, 5, 16),
        "case counts per kind"
    );
    assert_eq!(
        (stops, notices, words, actions),
        (22, 10, 7, 1),
        "stop case counts per kind"
    );
    assert_eq!((baselines, gates, check_failed), (5, 5, 1), "12c case counts per kind");
    assert_eq!(
        (stop_acks, gate_acks, sinces, overlaps),
        (17, 4, 4, 1),
        "12d case counts per kind"
    );
}

/// The notices of a stop case, read the way a client reads its rows.
fn received(case: &Value) -> Vec<ReceivedNotice> {
    case["notices"]
        .as_array()
        .expect("notices")
        .iter()
        .filter_map(|n| {
            parse_backup_notice(n["type"].as_str().expect("type"), &n["data"]).map(|notice| ReceivedNotice {
                notice,
                created_at_ms: n["created_at_ms"].as_i64().expect("created_at_ms"),
            })
        })
        .collect()
}

fn stop_listing(v: &Value) -> StopListing {
    StopListing {
        device_folder_id: uuid(&v["device_folder_id"]),
        device_folder_live: v["device_folder_live"].as_bool().expect("device_folder_live"),
        folders: list(&v["folders"], |f| StopFolder {
            category: Category::from_key(f["category"].as_str().expect("category")).expect("category key"),
            category_folder_id: f["category_folder_id"]
                .as_str()
                .map(|id| Uuid::parse_str(id).expect("uuid")),
            category_folder_live: f["category_folder_live"].as_bool(),
        }),
    }
}

fn stopped_json(stopped: &[StoppedBackup]) -> Value {
    Value::Array(
        stopped
            .iter()
            .map(|s| json!({"category": s.category.key(), "reason": s.reason.as_str()}))
            .collect(),
    )
}

/// The notices of a 12d case with their ids, read the way a client reads its
/// rows: an id that is missing or not a string is `None`.
fn listed(case: &Value) -> Vec<ListedNotice> {
    case["notices"]
        .as_array()
        .expect("notices")
        .iter()
        .filter_map(|n| {
            parse_backup_notice(n["type"].as_str().expect("type"), &n["data"]).map(|notice| ListedNotice {
                id: n["id"].as_str().map(str::to_string),
                notice,
                created_at_ms: n["created_at_ms"].as_i64().expect("created_at_ms"),
            })
        })
        .collect()
}

fn acknowledged(case: &Value) -> Vec<String> {
    list(&case["acknowledged"], s)
}

fn run_stop_ack_case(case: &Value) -> Value {
    let StopOutcome { stopped, acknowledged } = backup_stop_v2(
        &listed(case),
        case["last_pass_at_ms"].as_i64().expect("last_pass_at_ms"),
        &acknowledged(case),
        &stop_listing(&case["listing"]),
    );
    json!({"stopped": stopped_json(&stopped), "acknowledged": acknowledged})
}

fn run_stop_case(case: &Value) -> Value {
    stopped_json(&backup_stop(
        &received(case),
        case["last_pass_at_ms"].as_i64().expect("last_pass_at_ms"),
        &stop_listing(&case["listing"]),
    ))
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

// ── LD-0121: why a backup stops (spec Amendment 12, steps 1-4) ────────────

const LAST: i64 = 1_762_430_400_000;

fn dev() -> Uuid {
    Uuid::from_u128(100)
}

fn pictures_folder() -> Uuid {
    Uuid::from_u128(101)
}

/// Pictures and Documents backed up from this device; `pictures_live` and the
/// device folder as the listing shows them.
fn two_backups(device_live: bool, pictures_live: bool) -> StopListing {
    StopListing {
        device_folder_id: dev(),
        device_folder_live: device_live,
        folders: vec![
            StopFolder {
                category: Category::Pictures,
                category_folder_id: Some(pictures_folder()),
                category_folder_live: Some(pictures_live),
            },
            StopFolder {
                category: Category::Documents,
                category_folder_id: Some(Uuid::from_u128(102)),
                category_folder_live: Some(true),
            },
        ],
    }
}

fn files_removed(reason: BackupStopReason, created_at_ms: i64) -> ReceivedNotice {
    ReceivedNotice {
        notice: BackupNotice::FilesRemoved { reason },
        created_at_ms,
    }
}

fn backup_deleted(category: Option<Uuid>, created_at_ms: i64) -> ReceivedNotice {
    ReceivedNotice {
        notice: BackupNotice::BackupDeleted {
            device_folder_id: dev().to_string(),
            category_folder_id: category.map(|id| id.to_string()),
        },
        created_at_ms,
    }
}

fn stopped(pairs: &[(Category, BackupStopReason)]) -> Vec<StoppedBackup> {
    pairs
        .iter()
        .map(|(category, reason)| StoppedBackup {
            category: category.clone(),
            reason: *reason,
        })
        .collect()
}

/// Step 1: "Erase all files" turns every backup of this device off.
#[test]
fn stop_files_erased_turns_all_folders_off() {
    let got = backup_stop(
        &[files_removed(BackupStopReason::EraseRequest, LAST + 1)],
        LAST,
        &two_backups(true, true),
    );
    assert_eq!(
        got,
        stopped(&[
            (Category::Documents, BackupStopReason::EraseRequest),
            (Category::Pictures, BackupStopReason::EraseRequest),
        ])
    );
    assert_eq!(
        backup_stop_words(got[0].reason, "GLegion", "Documents"),
        "Your files were erased, so backups are off."
    );
}

/// Step 1 holds when the folders are still there: the grace clock removes
/// files, not folders, and a backup with holes it never refills is a silent
/// loss.
#[test]
fn stop_account_lapsed_with_folders_present_turns_all_off() {
    let got = backup_stop(
        &[files_removed(BackupStopReason::AccountLapsed, LAST + 60_000)],
        LAST,
        &two_backups(true, true),
    );
    assert_eq!(got.len(), 2);
    assert!(
        got.iter().all(|s| s.reason == BackupStopReason::AccountLapsed),
        "{got:?}"
    );
}

/// Step 2: a step-up delete of one category folder from another device turns
/// that one backup off with the rule-11 words.
#[test]
fn stop_backup_deleted_category_turns_one_off() {
    let got = backup_stop(
        &[backup_deleted(Some(pictures_folder()), LAST + 1)],
        LAST,
        &two_backups(true, false),
    );
    assert_eq!(got, stopped(&[(Category::Pictures, BackupStopReason::BackupDeleted)]));
    assert_eq!(
        backup_stop_words(got[0].reason, "GLegion", Category::Pictures.display_name()),
        "GLegion's backup of Pictures was deleted from another device."
    );
}

/// Step 3: a folder gone with no notice (dismissed, or the device was offline)
/// turns off with the vaguer words.
#[test]
fn stop_folder_gone_without_notice_uses_unknown_words() {
    let got = backup_stop(&[], LAST, &two_backups(true, false));
    assert_eq!(got, stopped(&[(Category::Pictures, BackupStopReason::Unknown)]));
    assert_eq!(
        backup_stop_words(got[0].reason, "GLegion", "Pictures"),
        "GLegion's backup of Pictures was deleted, so it is off."
    );
}

/// Only a notice written after the last pass counts: one the device already
/// acted on (or one from before the person chose "Back up again") never stops
/// it again.
#[test]
fn stop_notice_older_than_last_pass_ignored() {
    let old = [
        files_removed(BackupStopReason::EraseRequest, LAST - 1),
        backup_deleted(Some(pictures_folder()), LAST - 5),
        files_removed(BackupStopReason::AccountReset, LAST),
    ];
    assert_eq!(backup_stop(&old, LAST, &two_backups(true, true)), []);
}

/// Step 4: a folder restored from Trash before the pass, with no notice,
/// changes nothing.
#[test]
fn stop_restored_before_pass_no_notice_no_change() {
    assert_eq!(backup_stop(&[], LAST, &two_backups(true, true)), []);
    // With the notice it does stop (the accepted edge of Amendment 12).
    assert_eq!(
        backup_stop(&[backup_deleted(None, LAST + 1)], LAST, &two_backups(true, true)).len(),
        2
    );
}

/// Amendment 12b (Guus, 2026-11-07 19:04, G6): a `files_removed` notice whose
/// reason this build does not recognise stops every backup with its own line,
/// "Your files were removed, so backups are off.", never the `unknown` row's
/// "was deleted" words, which would be untrue (the folders are still there).
#[test]
fn stop_files_removed_unknown_reason_uses_the_removed_words() {
    let row = parse_backup_notice("files_removed", &json!({"reason": "billing_v2"})).expect("a backup notice");
    // The notice itself carries the reason, not only `reason()`: a client that
    // stores or re-serialises the notice keeps the right words.
    assert_eq!(
        row,
        BackupNotice::FilesRemoved {
            reason: BackupStopReason::UnknownRemoval
        }
    );
    let got = backup_stop(
        &[ReceivedNotice {
            notice: row,
            created_at_ms: LAST + 1,
        }],
        LAST,
        &two_backups(true, true),
    );
    assert_eq!(
        got,
        stopped(&[
            (Category::Documents, BackupStopReason::UnknownRemoval),
            (Category::Pictures, BackupStopReason::UnknownRemoval),
        ])
    );
    for s in &got {
        assert_eq!(
            backup_stop_words(s.reason, "GLegion", s.category.display_name()),
            "Your files were removed, so backups are off."
        );
    }
}

// ── Amendment 12c: the first pass's baseline and the pass gate ────────────

/// A fresh setup (a reinstall, or backups turned on for the first time): the
/// moment backups were turned on. A notice from before it does not apply.
#[test]
fn first_pass_baseline_fresh_setup_uses_the_setup_time() {
    let setup = LAST + 3_600_000;
    assert_eq!(first_pass_baseline(Some(setup), None), setup);
    let older = [files_removed(BackupStopReason::EraseRequest, setup - 1)];
    assert_eq!(
        backup_stop(&older, first_pass_baseline(Some(setup), None), &two_backups(true, true)),
        []
    );
}

/// An upgraded device: the old engine's last backup, which also wins over the
/// setup time (the new engine's first start). A notice written in between,
/// which the old engine never read, stops the backup: an emptied account never
/// fills up again.
#[test]
fn first_pass_baseline_upgraded_device_uses_the_old_engines_last_backup() {
    let legacy = LAST - 86_400_000;
    let setup = LAST + 3_600_000;
    assert_eq!(first_pass_baseline(None, Some(legacy)), legacy);
    assert_eq!(first_pass_baseline(Some(setup), Some(legacy)), legacy);
    assert_eq!(
        first_pass_baseline(Some(legacy), Some(setup)),
        legacy,
        "the earlier, whichever it is"
    );
    let missed = [files_removed(BackupStopReason::AccountLapsed, legacy + 1)];
    let got = backup_stop(
        &missed,
        first_pass_baseline(Some(setup), Some(legacy)),
        &two_backups(true, true),
    );
    assert_eq!(got.len(), 2, "both backups stop: {got:?}");
}

/// Neither known: 0, so any removal notice stops the backup.
#[test]
fn first_pass_baseline_unknown_is_zero_so_any_notice_stops() {
    assert_eq!(first_pass_baseline(None, None), 0);
    let any = [files_removed(BackupStopReason::InactiveCleanup, 1)];
    assert_eq!(
        backup_stop(&any, first_pass_baseline(None, None), &two_backups(true, true)).len(),
        2
    );
}

/// The notices could not be read: skip the pass (upload nothing, stop
/// nothing), say "Couldn't check — will retry.", retry next pass.
#[test]
fn pass_gate_check_failed_uploads_nothing_and_stops_nothing() {
    assert_eq!(
        backup_pass_gate(None, LAST, &two_backups(false, false)),
        BackupPassGate::CheckFailed
    );
    assert_eq!(MSG_STOP_CHECK_FAILED, "Couldn't check \u{2014} will retry.");
    // With the notices read, the same listing stops both backups.
    match backup_pass_gate(Some(&[]), LAST, &two_backups(false, false)) {
        BackupPassGate::Run { stopped } => assert_eq!(stopped.len(), 2),
        other => panic!("{other:?}"),
    }
}

// ── Amendment 12d: the overlap margin and acknowledged notice ids ─────────

fn with_id(id: &str, n: ReceivedNotice) -> ListedNotice {
    ListedNotice {
        id: Some(id.to_string()),
        notice: n.notice,
        created_at_ms: n.created_at_ms,
    }
}

/// The gap (server #415 review finding 1), as a story. The previous pass
/// started at `pass` and read the notices while the grace clock's transaction
/// was still open, so it saw none; that transaction's notice carries its
/// START, 30 s before the pass. The strict rule never counts it; the overlap
/// does, once: after "Back up again" the acknowledged id keeps it from
/// stopping the backup again.
#[test]
fn stop_v2_counts_a_notice_whose_transaction_was_open_at_the_read_once() {
    let pass = LAST;
    let notice = files_removed(BackupStopReason::AccountLapsed, pass - 30_000);
    let backups = two_backups(true, true);

    // The old rule: missed for good, and the pass would fill the account up again.
    assert_eq!(backup_stop(std::slice::from_ref(&notice), pass, &backups), []);

    // The new rule: the next pass stops both backups and acknowledges the notice.
    let listed = [with_id("n1", notice)];
    let first = backup_stop_v2(&listed, pass, &[], &backups);
    assert_eq!(
        first.stopped,
        stopped(&[
            (Category::Documents, BackupStopReason::AccountLapsed),
            (Category::Pictures, BackupStopReason::AccountLapsed),
        ])
    );
    assert_eq!(first.acknowledged, ["n1"]);

    // The person chooses "Back up again" two minutes later: last_pass_at moves
    // there, and the notice is still inside the margin.
    let back_up_again = pass + 120_000;
    let again = backup_stop_v2(&listed, back_up_again, &first.acknowledged, &backups);
    assert_eq!(again.stopped, [], "an acknowledged notice never stops a backup again");
    assert_eq!(again.acknowledged, ["n1"], "still in the window, so still kept");
    // Without the acknowledged id it would stop again.
    assert_eq!(backup_stop_v2(&listed, back_up_again, &[], &backups).stopped.len(), 2);
    // Once the notice has left the window, its id is dropped.
    let later = back_up_again + NOTICE_OVERLAP_MS;
    assert_eq!(
        backup_stop_v2(&listed, later, &first.acknowledged, &backups),
        StopOutcome {
            stopped: vec![],
            acknowledged: vec![],
        }
    );
}

/// With nothing acknowledged, the new rule is the old rule moved back by the
/// margin: every stop case of the shared vector, ids or not.
#[test]
fn stop_v2_is_the_old_rule_moved_back_by_the_margin() {
    let cases: Vec<Value> = super::cases(CONCEPT)
        .into_iter()
        .filter(|c| c["kind"] == "stop")
        .collect();
    assert_eq!(cases.len(), 22);
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let last = case["last_pass_at_ms"].as_i64().unwrap();
        let listing = stop_listing(&case["listing"]);
        let old = received(case);
        for with_ids in [false, true] {
            let new: Vec<ListedNotice> = old
                .iter()
                .enumerate()
                .map(|(i, n)| ListedNotice {
                    id: with_ids.then(|| format!("n{i:02}")),
                    notice: n.notice.clone(),
                    created_at_ms: n.created_at_ms,
                })
                .collect();
            let got = backup_stop_v2(&new, last + NOTICE_OVERLAP_MS, &[], &listing);
            assert_eq!(stopped_json(&got.stopped), case["expect"], "{id} (ids: {with_ids})");
            let want: Vec<String> = new
                .iter()
                .filter(|n| with_ids && n.created_at_ms > last)
                .filter_map(|n| n.id.clone())
                .collect();
            assert_eq!(got.acknowledged, want, "{id} (ids: {with_ids})");
        }
    }
}

/// The `since` a client fetches from holds every notice the window counts:
/// fetched from `last_pass_at_ms` itself, the overlap would be left out.
#[test]
fn notices_since_fetches_every_notice_the_window_counts() {
    let backups = two_backups(true, true);
    for last in [0, 1, NOTICE_OVERLAP_MS - 1, NOTICE_OVERLAP_MS, LAST, i64::MAX] {
        let since = notices_since(last);
        assert!(since >= 0, "{last}");
        for created_at_ms in [
            0,
            1,
            since - 1,
            since,
            since + 1,
            last - 1,
            last,
            last.saturating_add(1),
        ] {
            if created_at_ms < 0 {
                continue;
            }
            let notice = [with_id(
                "n",
                files_removed(BackupStopReason::EraseRequest, created_at_ms),
            )];
            let counted = !backup_stop_v2(&notice, last, &[], &backups).stopped.is_empty();
            // The server's `since` is inclusive.
            assert!(
                !counted || created_at_ms >= since,
                "last {last}: a counted notice at {created_at_ms} is outside since {since}"
            );
        }
    }
    assert_eq!(notices_since(LAST), LAST - 600_000);
    assert_eq!(notices_since(i64::MIN), 0);
}

/// The pass gate with the margin: a failed fetch decides nothing, so both
/// `last_pass_at_ms` and the acknowledged set stay; otherwise as
/// `backup_stop_v2`.
#[test]
fn pass_gate_v2_check_failed_decides_nothing() {
    let ack = ["n1".to_string()];
    assert_eq!(
        backup_pass_gate_v2(None, LAST, &ack, &two_backups(false, false)),
        BackupPassGateV2::CheckFailed
    );
    let listed = [with_id("n2", files_removed(BackupStopReason::EraseRequest, LAST - 1))];
    match backup_pass_gate_v2(Some(&listed), LAST, &ack, &two_backups(true, true)) {
        BackupPassGateV2::Run { stopped, acknowledged } => {
            assert_eq!(stopped.len(), 2);
            assert_eq!(acknowledged, ["n2"], "n1 is not in this listing, so it is dropped");
        }
        other => panic!("{other:?}"),
    }
}
