//! LD-0113 — backup protection and skip rules (spec §4.2 rules 1, 7, 8).
//!
//! Cases live in `test-vectors/consolidation/backup_protect.json`, written by an
//! independent Python generator. Every client runs the same file through its own
//! binding.

use beebeeb_core::backup::{
    EntryAttrs, Mutation, SkipReason, backup_rel_path, category_folder_name, check_drive_mutation, check_mutation,
    custom_category_name, own_backup_refusal, skip_reason,
};
use beebeeb_types::backup::{Category, SystemRole};
use serde_json::Value;

pub const CONCEPT: &str = "backup_protect";

fn role(case: &Value) -> Option<SystemRole> {
    match &case["role"] {
        Value::Null => None,
        Value::String(s) => Some(SystemRole::parse(s).unwrap_or_else(|| panic!("{}: unknown role {s}", case["id"]))),
        other => panic!("{}: role must be a string or null, got {other}", case["id"]),
    }
}

fn reason_key(reason: Option<SkipReason>) -> Value {
    match reason {
        None => Value::Null,
        Some(r) => Value::String(r.as_str().to_string()),
    }
}

#[test]
fn backup_protect_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 80, "every named backup_protect case is present");

    let (mut mutations, mut skips, mut layout, mut drives) = (0, 0, 0, 0);
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "mutation" => {
                mutations += 1;
                let m = Mutation::parse(case["mutation"].as_str().expect("mutation"))
                    .unwrap_or_else(|| panic!("{id}: unknown mutation"));
                let got = match check_mutation(role(case), m) {
                    Ok(()) => "ok".to_string(),
                    Err(protected) => protected.message.to_string(),
                };
                assert_eq!(got, case["expect"].as_str().expect("expect"), "{id}");
            }
            "skip" => {
                skips += 1;
                let attrs = EntryAttrs {
                    is_dir: case["is_dir"].as_bool().expect("is_dir"),
                    is_link: case["is_link"].as_bool().expect("is_link"),
                    not_local: case["not_local"].as_bool().expect("not_local"),
                };
                let got = skip_reason(case["name"].as_str().expect("name"), &attrs);
                assert_eq!(reason_key(got), case["expect"], "{id}");
            }
            "rel_path" => {
                layout += 1;
                let category = Category::from_key(case["category"].as_str().expect("category")).expect("category key");
                let got = backup_rel_path(
                    case["device"].as_str().expect("device"),
                    &category,
                    case["rel"].as_str().expect("rel"),
                );
                assert_eq!(got, case["expected"].as_str().expect("expected"), "{id}");
            }
            "own_backup_refusal" => {
                layout += 1;
                let got = own_backup_refusal(case["source_path"].as_str().expect("source_path"));
                assert_eq!(got, case["expected"].as_str().expect("expected"), "{id}");
            }
            "drive_mutation" => {
                drives += 1;
                let m = Mutation::parse(case["mutation"].as_str().expect("mutation")).expect("known mutation");
                let got = match check_drive_mutation(
                    case["is_root"].as_bool().expect("is_root"),
                    case["under_root"].as_bool().expect("under_root"),
                    case["own_active_source"].as_str(),
                    m,
                ) {
                    Ok(()) => "ok".to_string(),
                    Err(protected) => protected.message.to_string(),
                };
                assert_eq!(got, case["expect"].as_str().expect("expect"), "{id}");
            }
            "custom_name" => {
                layout += 1;
                let taken: Vec<&str> = case["taken"]
                    .as_array()
                    .expect("taken")
                    .iter()
                    .map(|t| t.as_str().expect("taken name"))
                    .collect();
                let got = custom_category_name(case["raw"].as_str().expect("raw"), &taken);
                assert_eq!(got, case["expected"].as_str().expect("expected"), "{id}");
                // The stored name is the server folder's name: cleaning it again changes nothing.
                assert_eq!(
                    category_folder_name(&Category::Custom(got.clone())),
                    got,
                    "{id}: category folder"
                );
            }
            other => panic!("{id}: unknown kind `{other}`"),
        }
    }
    println!(
        "backup_protect: {} cases ({mutations} mutation, {drives} drive, {skips} skip, {layout} layout)",
        cases.len()
    );
    assert_eq!(
        (mutations, drives, skips, layout),
        (13, 16, 34, 17),
        "case counts per kind"
    );
}
