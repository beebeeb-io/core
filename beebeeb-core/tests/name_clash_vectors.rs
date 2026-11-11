//! `test-vectors/name_clash_v1.json`: numbered names, drive conflict names and
//! the normalised form, against an independent Python generator.

use beebeeb_core::name_clash::{ItemKind, TakenNames, drive_conflict_name, numbered_candidates, numbered_name};
use beebeeb_core::name_tag::normalize_for_tag;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/name_clash_v1.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read the vectors")).expect("parse the vectors")
}

fn kind(case: &Value) -> ItemKind {
    match case["item"].as_str().expect("item") {
        "file" => ItemKind::File,
        "folder" => ItemKind::Folder,
        other => panic!("unknown item kind `{other}`"),
    }
}

fn taken(case: &Value) -> TakenNames {
    let mut taken = TakenNames::new();
    for name in case["taken"].as_array().expect("taken") {
        taken.insert(name.as_str().expect("taken name"));
    }
    taken
}

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case[field].as_str().unwrap_or_else(|| panic!("{field}"))
}

#[test]
fn name_clash_vectors_match_core() {
    let doc = vectors();
    let cases = doc["cases"].as_array().expect("cases");
    let mut counts = [0usize; 4];
    for case in cases {
        let id = text(case, "id");
        match text(case, "kind") {
            "numbered" => {
                counts[0] += 1;
                let got = numbered_name(text(case, "original"), kind(case), &taken(case));
                assert_eq!(got, text(case, "expected"), "{id}");
                assert!(got.len() <= 255, "{id}: {} bytes", got.len());
            }
            "drive" => {
                counts[1] += 1;
                let got = drive_conflict_name(text(case, "original"), kind(case), text(case, "device"), &taken(case));
                assert_eq!(got, text(case, "expected"), "{id}");
                assert!(got.len() <= 255, "{id}: {} bytes", got.len());
            }
            "candidates" => {
                counts[2] += 1;
                let count = case["count"].as_u64().expect("count") as usize;
                let want: Vec<&str> = case["expected"]
                    .as_array()
                    .expect("expected")
                    .iter()
                    .map(|name| name.as_str().expect("candidate"))
                    .collect();
                assert_eq!(
                    numbered_candidates(text(case, "original"), kind(case), count),
                    want,
                    "{id}"
                );
            }
            "normalize" => {
                counts[3] += 1;
                let a = normalize_for_tag(text(case, "a")).ok();
                let b = normalize_for_tag(text(case, "b")).ok();
                assert_eq!(a.as_deref(), case["normalized_a"].as_str(), "{id}: a");
                assert_eq!(b.as_deref(), case["normalized_b"].as_str(), "{id}: b");
                assert_eq!(a == b, case["same"].as_bool().expect("same"), "{id}: same");
                // Idempotent: the normalised form normalises to itself.
                if let Some(a) = a {
                    assert_eq!(normalize_for_tag(&a).as_deref(), Ok(a.as_str()), "{id}: idempotent");
                }
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }
    assert_eq!(counts, [11, 9, 2, 15], "every vector group is present");
    assert_eq!(
        doc["unicode"],
        beebeeb_core::name_tag::unicode_version(),
        "one Unicode version"
    );
}
