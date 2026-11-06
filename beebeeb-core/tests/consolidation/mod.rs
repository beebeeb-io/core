//! Part 3's shared cross-client vector harness (spec §16.5).
//!
//! One JSON file per concept in `test-vectors/consolidation/`, one module per
//! concept beside this file. The harness is deliberately strict: a file with no
//! `description`, no `source` or an empty `cases` list is a red — an empty
//! vector proves nothing and must never read as a pass.
//!
//! A concept's runner calls [`cases`] and executes them against core. This
//! module owns only the file format and the registry, so every concept fails
//! the same way when its file is missing or empty.

use serde_json::Value;
use std::path::PathBuf;

pub mod backup_device;
pub mod backup_protect;
pub mod backup_root;
pub mod download;
pub mod envelope;
pub mod error_body;
pub mod format;
pub mod name;
pub mod path_safety;
pub mod plan;
pub mod preview;
pub mod preview_platforms;
pub mod recovery;
pub mod retry;
pub mod share_link;
pub mod sync;
pub mod thumbnail;

/// Every concept of spec §16.2, in map order. Each name is a module here and a
/// file stem under `test-vectors/consolidation/`.
pub const CONCEPTS: &[&str] = &[
    name::CONCEPT,
    envelope::CONCEPT,
    preview::CONCEPT,
    format::CONCEPT,
    plan::CONCEPT,
    retry::CONCEPT,
    error_body::CONCEPT,
    recovery::CONCEPT,
    share_link::CONCEPT,
    download::CONCEPT,
    path_safety::CONCEPT,
    thumbnail::CONCEPT,
    sync::CONCEPT,
];

/// `test-vectors/consolidation/<concept>.json`, next to the crate.
pub fn vector_path(concept: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors/consolidation")
        .join(format!("{concept}.json"))
}

/// Read one concept file. A missing file names the concept it belongs to.
pub fn load(concept: &str) -> Value {
    let path = vector_path(concept);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()))
}

/// Validate the shared document shape and return the case count.
/// An empty case list is an error, never a pass (spec §16.5).
pub fn validate(concept: &str, doc: &Value) -> Result<usize, String> {
    match doc["description"].as_str() {
        Some(s) if !s.trim().is_empty() => {}
        _ => return Err(format!("{concept}.json needs a non-empty `description`")),
    }
    match doc["source"].as_str() {
        Some(s) if !s.trim().is_empty() => {}
        _ => return Err(format!("{concept}.json needs a non-empty `source`")),
    }
    let cases = doc["cases"]
        .as_array()
        .ok_or_else(|| format!("{concept}.json needs a `cases` array"))?;
    if cases.is_empty() {
        return Err(format!(
            "{concept}.json has an empty case list — that is a red, not a pass"
        ));
    }
    for (i, case) in cases.iter().enumerate() {
        match case["id"].as_str() {
            Some(id) if !id.trim().is_empty() => {}
            _ => return Err(format!("{concept}.json case {i} needs a non-empty `id`")),
        }
    }
    Ok(cases.len())
}

/// Load and validate one concept's cases. Concept runners start here.
pub fn cases(concept: &str) -> Vec<Value> {
    let doc = load(concept);
    let count = validate(concept, &doc).unwrap_or_else(|e| panic!("{e}"));
    let cases = doc["cases"].as_array().cloned().unwrap_or_default();
    assert_eq!(cases.len(), count);
    cases
}

#[test]
fn concept_registry_is_the_thirteen_moves() {
    assert_eq!(CONCEPTS.len(), 13, "spec §16.2 has 13 core-side moves");
    let mut seen = std::collections::BTreeSet::new();
    for concept in CONCEPTS {
        assert!(seen.insert(*concept), "duplicate concept `{concept}`");
    }
}

#[test]
fn consolidation_harness_rejects_an_empty_case_list() {
    let empty = serde_json::json!({
        "description": "a concept",
        "source": "core",
        "cases": [],
    });
    let err = validate("mutant", &empty).expect_err("an empty case list must be rejected");
    assert!(err.contains("empty case list"), "unexpected error: {err}");

    let missing_id = serde_json::json!({
        "description": "a concept",
        "source": "core",
        "cases": [{ "input": 1 }],
    });
    let err = validate("mutant", &missing_id).expect_err("a case without an id must be rejected");
    assert!(err.contains("needs a non-empty `id`"), "unexpected error: {err}");
}

#[test]
fn consolidation_files_on_disk_are_well_formed() {
    let dir = vector_path("harness").parent().expect("vector dir").to_path_buf();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{} must exist: {e}", dir.display()))
        .map(|entry| entry.expect("readable dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort();

    let files = entries.len();
    let mut total = 0;
    for path in entries {
        let concept = path.file_stem().expect("json stem").to_string_lossy().into_owned();
        total += validate(&concept, &load(&concept)).unwrap_or_else(|e| panic!("{e}"));
    }
    assert!(
        files >= 1,
        "test-vectors/consolidation/ holds at least the harness fixture"
    );
    assert!(total >= files, "every file carries at least one case");
}
