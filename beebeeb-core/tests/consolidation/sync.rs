//! Move 13 — the one conflict rule (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/sync.json`. The rule is a new pure
//! API beside core's CRDT `sync`; nothing existing in `sync` or `beebeeb-sync`
//! changed.

use beebeeb_core::sync::conflict::{
    ConflictOutcome, ConflictPolicy, Resolution, VersionInfo, auto_resolution_deadline, is_conflict, keep_both_name,
    resolution_due,
};
use serde_json::Value;

pub const CONCEPT: &str = "sync";

fn version_of(value: &Value) -> VersionInfo {
    VersionInfo {
        hash: value["hash"].as_str().expect("hash").to_string(),
        modified_at: value["modified_at"].as_u64().expect("modified_at"),
    }
}

fn base_of(case: &Value) -> Option<VersionInfo> {
    case["base"].as_object().map(|_| version_of(&case["base"]))
}

#[test]
fn sync_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 19, "every named sync case is present");

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
                        assert_eq!(local.hash != remote.hash, want, "{id}: missing base");
                    }
                }
            }
            "deadline" => {
                deadlines += 1;
                let detected_at = case["detected_at"].as_u64().expect("detected_at");
                let now = case["now"].as_u64().expect("now");
                let deadline = case["expect_deadline"].as_u64().expect("deadline");
                assert_eq!(auto_resolution_deadline(detected_at), deadline, "{id}");
                assert_eq!(
                    resolution_due(detected_at, now),
                    case["expect_due"].as_bool().unwrap(),
                    "{id}"
                );
                assert_eq!(ConflictPolicy::DEFAULT.deadline(detected_at), deadline, "{id}: policy");
            }
            "outcome" => {
                outcomes += 1;
                let policy = ConflictPolicy::DEFAULT;
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
                );
                assert_eq!(got, case["expected"].as_str().expect("expected"), "{id}");
                assert!(got.len() <= 255, "{id}: name limit");
                assert!(!taken.contains(&got.to_lowercase()), "{id}: must not collide");
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    assert_eq!((conflicts, deadlines, outcomes, names), (7, 3, 3, 6));
    for required in [
        "sync_both_directions_diverge",
        "sync_24h_due",
        "sync_conflict_auto_keep_both",
        "sync_keep_both_counter",
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
