//! LD-0113 — the backup pass planner, removed-elsewhere, folder presence and
//! rebuilding records (spec §4.2 rules 9-11).
//!
//! Cases live in `test-vectors/consolidation/backup_plan.json`, written by
//! `test-vectors/tools/make_backup_plan_vectors.py`. The two Review Focus tests
//! (plan Review Focus 4 and 5) are Rust tests below the vector runner.

use std::collections::HashSet;

use beebeeb_core::backup::{
    BackupRecord, FolderPresence, PassBudget, PassPlan, RecordState, RemoteEntry, SourceEntry, UploadReason,
    folder_presence, normalize_key, plan_pass, records_from_remote,
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
        })).collect::<Vec<_>>(),
        "moves": plan.moves.iter().map(|m| json!({
            "remote_id": m.remote_id.to_string(),
            "from_key": m.from_key,
            "to_key": m.to_key,
        })).collect::<Vec<_>>(),
        "folders": plan.folders,
        "mark_removed_elsewhere": plan.mark_removed_elsewhere,
        "unchanged": plan.unchanged,
        "gone_locally": plan.gone_locally,
        "deferred": plan.deferred,
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
        &list(&case["unseen"], s),
        budget,
    ))
}

#[test]
fn backup_plan_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 53, "every named backup_plan case is present");

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
                let got: Vec<Value> = records_from_remote(&remote, &list(&case["entries"], entry))
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
        (34, 4, 5, 10),
        "case counts per kind"
    );
}

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
        let plan = plan_pass(&[file("a.jpg", 7, m)], &[record], &live, &[], UNLIMITED);
        assert_eq!((plan.unchanged, plan.uploads.len()), (1, 0), "modified_ms {m}");
    }
    // A FAT/exFAT copy rounds the mtime to 2 s: a different value, so it uploads.
    let record = backed_up("a.jpg", 7, 1_762_430_401_337, 1_762_430_500_000);
    let live: HashSet<Uuid> = [record.remote_id].into_iter().collect();
    let plan = plan_pass(&[file("a.jpg", 7, 1_762_430_402_000)], &[record], &live, &[], UNLIMITED);
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
            let records = records_from_remote(&remote, &[file("a.jpg", 7, m)]);
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
        &["closed".to_string()],
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
/// dataless), given in NFD as a macOS walk may first see it.
#[test]
fn notlocal_folder_records_are_not_move_sources() {
    let record = backed_up("Ren\u{e9}/IMG_1.jpg", 9, 1_700_000_000_000, 1_700_000_100_000);
    let live: HashSet<Uuid> = [record.remote_id].into_iter().collect();
    let plan = plan_pass(
        &[file("Camera/IMG_1.jpg", 9, 1_700_000_000_000)],
        &[record],
        &live,
        &["Rene\u{301}".to_string()],
        UNLIMITED,
    );
    assert!(plan.moves.is_empty(), "{:?}", plan.moves);
    assert_eq!((plan.uploads.len(), plan.gone_locally), (1, 0));
}
