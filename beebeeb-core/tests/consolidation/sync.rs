//! Move 13 — the one conflict rule (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/sync.json`. The rule is a new pure
//! API beside core's CRDT `sync`; nothing existing in `sync` or `beebeeb-sync`
//! changed.

use beebeeb_core::sync::conflict::{
    AuthenticatedVersionId, ConflictOutcome, ConflictPolicy, Resolution, VersionInfo, auto_resolution_deadline,
    is_conflict, keep_both_name, resolution_due,
};
use beebeeb_core::sync::{CompleteSnapshot, InMemorySyncStore, IncompleteSnapshot, SyncEngine, SyncPosition};
use serde_json::Value;

pub const CONCEPT: &str = "sync";

fn version_of(value: &Value) -> VersionInfo {
    VersionInfo {
        authenticated_version: AuthenticatedVersionId::new(value["hash"].as_str().expect("hash")).expect("identity"),
        modified_at: value["modified_at"].as_u64().expect("modified_at"),
    }
}

fn base_of(case: &Value) -> Option<VersionInfo> {
    case["base"].as_object().map(|_| version_of(&case["base"]))
}

#[test]
fn sync_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 21, "every named sync case is present");

    let mut conflicts = 0;
    let mut deadlines = 0;
    let mut outcomes = 0;
    let mut names = 0;

    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "conflict" => {
                conflicts += 1;
                let local = version_of(&case["local"]);
                let remote = version_of(&case["remote"]);
                let base = base_of(case);
                let want = case["expect"].as_bool().expect("expect");
                match &base {
                    Some(base) => assert_eq!(is_conflict(&local, &remote, base), want, "{id}"),
                    None => {
                        // No shared base: equal hashes are nothing to resolve,
                        // different hashes are a conflict.
                        assert_eq!(
                            local.authenticated_version != remote.authenticated_version,
                            want,
                            "{id}: missing base"
                        );
                    }
                }
            }
            "deadline" => {
                deadlines += 1;
                let detected_at = case["detected_at"].as_u64().expect("detected_at");
                let now = case["now"].as_u64().expect("now");
                let deadline = case["expect_deadline"].as_u64().expect("deadline");
                assert_eq!(auto_resolution_deadline(detected_at), Some(deadline), "{id}");
                assert_eq!(
                    resolution_due(detected_at, now),
                    case["expect_due"].as_bool().unwrap(),
                    "{id}"
                );
                let waiting = ConflictPolicy {
                    auto_resolve_after_secs: 24 * 3600,
                };
                assert_eq!(waiting.deadline(detected_at), Some(deadline), "{id}: waiting policy");
                // The shipped policy keeps both at once: it has no deadline.
                assert_eq!(
                    ConflictPolicy::DEFAULT.deadline(detected_at),
                    None,
                    "{id}: shipped policy"
                );
            }
            "outcome" => {
                outcomes += 1;
                let policy = case["wait_secs"]
                    .as_u64()
                    .map_or(ConflictPolicy::DEFAULT, |wait| ConflictPolicy {
                        auto_resolve_after_secs: wait,
                    });
                if policy == ConflictPolicy::DEFAULT {
                    assert_ne!(case["expect"], "needs_user", "{id}: the shipped policy never asks");
                }
                let outcome = policy.resolve(
                    &version_of(&case["local"]),
                    &version_of(&case["remote"]),
                    base_of(case).as_ref(),
                    case["detected_at"].as_u64().expect("detected_at"),
                    case["now"].as_u64().expect("now"),
                );
                assert_eq!(outcome.as_str(), case["expect"].as_str().expect("expect"), "{id}");
                // Never auto-pick a side: the only automatic outcome is Keep Both.
                assert!(
                    matches!(
                        outcome,
                        ConflictOutcome::Clean | ConflictOutcome::NeedsUser | ConflictOutcome::AutoKeepBoth
                    ),
                    "{id}"
                );
            }
            "keep-both" => {
                names += 1;
                let taken: std::collections::HashSet<String> = case["taken"]
                    .as_array()
                    .expect("taken")
                    .iter()
                    .map(|value| value.as_str().expect("name").to_string())
                    .collect();
                let got = keep_both_name(
                    case["original"].as_str().expect("original"),
                    case["device"].as_str().expect("device"),
                    case["hhmm"].as_str().expect("hhmm"),
                    &taken,
                )
                .expect("valid HH.MM vector");
                assert_eq!(got, case["expected"].as_str().expect("expected"), "{id}");
                assert!(got.len() <= 255, "{id}: name limit");
                assert!(!taken.contains(&got.to_lowercase()), "{id}: must not collide");
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    assert_eq!((conflicts, deadlines, outcomes, names), (7, 3, 4, 7));
    for required in [
        "sync_both_directions_diverge",
        "sync_24h_due",
        "sync_conflict_auto_keep_both",
        "sync_conflict_keeps_both_at_once",
        "sync_conflict_waits_for_user",
        "sync_keep_both_counter",
        "sync_keep_both_hostile_device",
    ] {
        assert!(cases.iter().any(|case| case["id"] == required), "missing `{required}`");
    }
    // The user's three choices still exist and keep their wire names.
    assert_eq!(
        [
            Resolution::KeepLocal.as_str(),
            Resolution::KeepRemote.as_str(),
            Resolution::KeepBoth.as_str()
        ],
        ["local", "remote", "both"]
    );
}

#[test]
fn incomplete_snapshot_has_no_delete_authority() {
    let mut engine = SyncEngine::with_store("device".into(), InMemorySyncStore::default()).expect("store");
    let snapshot = IncompleteSnapshot::new(Vec::new());
    let before = engine.tree_size();
    engine.observe_incomplete_snapshot(snapshot).expect("merge");
    assert_eq!(engine.tree_size(), before);
}

#[test]
fn complete_snapshot_is_tied_to_a_known_position() {
    let mut engine = SyncEngine::with_store("device".into(), InMemorySyncStore::default()).expect("store");
    let snapshot = CompleteSnapshot::new(Vec::new(), SyncPosition::new(40, 7)).expect("position");
    engine.apply_complete_snapshot(snapshot).expect("snapshot");
    assert_eq!(engine.position(), SyncPosition::new(40, 7));
}

#[test]
fn conflict_deadline_overflow_is_never_due() {
    assert_eq!(auto_resolution_deadline(u64::MAX), None);
    assert!(!resolution_due(u64::MAX, u64::MAX));
}

#[test]
fn keep_both_rejects_unvalidated_time() {
    let taken = std::collections::HashSet::new();
    assert!(keep_both_name("report.txt", "phone", "../../bad", &taken).is_err());
    assert!(keep_both_name("report.txt", "phone", "24.00", &taken).is_err());
}
