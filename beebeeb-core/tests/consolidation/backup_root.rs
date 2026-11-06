//! LD-0113 — the Backups root: resolution and the duplicate-merge plan (spec
//! §4.2 rules 5-6).
//!
//! Cases live in `test-vectors/consolidation/backup_root.json`, written by
//! `test-vectors/tools/make_backup_root_vectors.py`.

use beebeeb_core::backup::{MergeNode, MergeStep, RootCandidate, RootPlan, plan_merge, resolve_root};
use beebeeb_types::backup::SystemRole;
use serde_json::Value;
use uuid::Uuid;

pub const CONCEPT: &str = "backup_root";

fn uuid(v: &Value) -> Uuid {
    Uuid::parse_str(v.as_str().expect("uuid string")).expect("uuid")
}

fn candidate(v: &Value) -> RootCandidate {
    RootCandidate {
        id: uuid(&v["id"]),
        name: v["name"].as_str().map(str::to_string),
        is_trashed: v["is_trashed"].as_bool().expect("is_trashed"),
        created_at_ms: v["created_at_ms"].as_i64().expect("created_at_ms"),
        system_role: v["system_role"]
            .as_str()
            .map(|s| SystemRole::parse(s).expect("known role")),
    }
}

fn node(v: &Value) -> MergeNode {
    MergeNode {
        id: uuid(&v["id"]),
        name: v["name"].as_str().expect("name").to_string(),
        is_folder: v["is_folder"].as_bool().expect("is_folder"),
        children: v["children"].as_array().expect("children").iter().map(node).collect(),
    }
}

fn step(v: &Value) -> MergeStep {
    if let Some(m) = v.get("move") {
        MergeStep::Move {
            id: uuid(&m["id"]),
            new_parent: uuid(&m["new_parent"]),
        }
    } else if let Some(m) = v.get("move_renamed") {
        MergeStep::MoveRenamed {
            id: uuid(&m["id"]),
            new_parent: uuid(&m["new_parent"]),
            new_name: m["new_name"].as_str().expect("new_name").to_string(),
        }
    } else {
        MergeStep::Trash { id: uuid(&v["trash"]) }
    }
}

fn expected_plan(v: &Value) -> RootPlan {
    if v == "create" {
        RootPlan::Create
    } else if let Some(id) = v.get("use") {
        RootPlan::Use(uuid(id))
    } else {
        let claim = &v["claim"];
        RootPlan::Claim {
            id: uuid(&claim["id"]),
            merge_from: claim["merge_from"]
                .as_array()
                .expect("merge_from")
                .iter()
                .map(uuid)
                .collect(),
        }
    }
}

#[test]
fn backup_root_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 20, "every named backup_root case is present");

    let (mut roots, mut merges) = (0, 0);
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "root" => {
                roots += 1;
                let candidates: Vec<RootCandidate> = case["candidates"]
                    .as_array()
                    .expect("candidates")
                    .iter()
                    .map(candidate)
                    .collect();
                assert_eq!(resolve_root(&candidates), expected_plan(&case["expect"]), "{id}");
                // The answer must not depend on the listing order: every client
                // sees the same rows in its own order.
                let mut reversed = candidates.clone();
                reversed.reverse();
                assert_eq!(
                    resolve_root(&reversed),
                    expected_plan(&case["expect"]),
                    "{id}: reversed"
                );
            }
            "merge" => {
                merges += 1;
                let duplicates: Vec<MergeNode> = case["duplicates"]
                    .as_array()
                    .expect("duplicates")
                    .iter()
                    .map(node)
                    .collect();
                let got = plan_merge(
                    &node(&case["survivor"]),
                    &duplicates,
                    case["clash_label"].as_str().expect("clash_label"),
                    case["hhmm"].as_str().expect("hhmm"),
                );
                let want: Vec<MergeStep> = case["expect"].as_array().expect("expect").iter().map(step).collect();
                assert_eq!(got, want, "{id}");
            }
            other => panic!("{id}: unknown kind `{other}`"),
        }
    }
    println!("backup_root: {} cases ({roots} root, {merges} merge)", cases.len());
    assert_eq!((roots, merges), (12, 8), "case counts per kind");
}
