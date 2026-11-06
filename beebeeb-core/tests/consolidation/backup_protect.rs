//! LD-0113 — backup protection and skip rules (spec §4.2 rules 1, 7, 8;
//! Amendments 7 and 8).
//!
//! Cases live in `test-vectors/consolidation/backup_protect.json`, written by an
//! independent Python generator. Every client runs the same file through its own
//! binding.

use beebeeb_core::backup::{
    BackupPosition, EntryAttrs, MSG_BADGE, Mutation, Protected, ROOT_NAME, SkipReason, backup_rel_path,
    category_folder_name, check_app_mutation, check_drive_mutation, check_root_mutation, custom_category_name,
    is_hidden_backup_item, own_backup_refusal, skip_reason,
};
use beebeeb_types::backup::{Category, ORIGIN_BACKUP, ORIGIN_HEADER, SystemRole};
use serde_json::Value;

pub const CONCEPT: &str = "backup_protect";

fn role(case: &Value) -> Option<SystemRole> {
    match &case["role"] {
        Value::Null => None,
        Value::String(s) => Some(SystemRole::parse(s).unwrap_or_else(|| panic!("{}: unknown role {s}", case["id"]))),
        other => panic!("{}: role must be a string or null, got {other}", case["id"]),
    }
}

fn mutation(case: &Value) -> Mutation {
    Mutation::parse(case["mutation"].as_str().expect("mutation"))
        .unwrap_or_else(|| panic!("{}: unknown mutation", case["id"]))
}

fn position(case: &Value) -> BackupPosition {
    BackupPosition::parse(case["position"].as_str().expect("position"))
        .unwrap_or_else(|| panic!("{}: unknown position", case["id"]))
}

fn words(result: Result<(), Protected>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(protected) => protected.message.to_string(),
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
    assert_eq!(cases.len(), 163, "every named backup_protect case is present");

    let (mut roots, mut apps, mut drives, mut positions, mut names, mut skips, mut layout) = (0, 0, 0, 0, 0, 0, 0);
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "names" => {
                names += 1;
                assert_eq!(ROOT_NAME, case["root_name"].as_str().expect("root_name"), "{id}");
                assert_eq!(MSG_BADGE, case["badge"].as_str().expect("badge"), "{id}");
                assert_eq!(
                    ORIGIN_HEADER,
                    case["origin_header"].as_str().expect("origin_header"),
                    "{id}"
                );
                assert_eq!(
                    ORIGIN_BACKUP,
                    case["origin_backup"].as_str().expect("origin_backup"),
                    "{id}"
                );
            }
            "root_mutation" => {
                roots += 1;
                let got = words(check_root_mutation(role(case), mutation(case)));
                assert_eq!(got, case["expect"].as_str().expect("expect"), "{id}");
            }
            "position" => {
                positions += 1;
                let depth = case["depth"].as_u64().map(|d| usize::try_from(d).expect("depth"));
                let name = case["name"].as_str().expect("name");
                let got = BackupPosition::at_depth(depth, name);
                assert_eq!(got.as_str(), case["expected"].as_str().expect("expected"), "{id}");
                assert_eq!(BackupPosition::parse(got.as_str()), Some(got), "{id}: round trip");
                assert_eq!(
                    is_hidden_backup_item(depth, name),
                    case["hidden"].as_bool().expect("hidden"),
                    "{id}: hidden"
                );
            }
            "app_mutation" => {
                apps += 1;
                let got = words(check_app_mutation(position(case), mutation(case)));
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
                let got = words(check_drive_mutation(
                    position(case),
                    case["own_active_source"].as_str(),
                    mutation(case),
                ));
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
        "backup_protect: {} cases ({names} names, {roots} root, {positions} position, {apps} app, {drives} drive, \
         {skips} skip, {layout} layout)",
        cases.len()
    );
    assert_eq!(
        (names, roots, positions, apps, drives, skips, layout),
        (1, 19, 11, 36, 43, 34, 19),
        "case counts per kind"
    );
}
