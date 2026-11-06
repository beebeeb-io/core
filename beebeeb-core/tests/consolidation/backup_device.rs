//! LD-0113 — device folders: naming, identity, the machine-derived id and the
//! manifest (spec §4.2 rules 2-4).
//!
//! Cases live in `test-vectors/consolidation/backup_device.json`, written by
//! `test-vectors/tools/make_backup_device_vectors.py` (ids via hashlib).

use beebeeb_core::backup::{
    DeviceFolderCandidate, DeviceFolderChoice, DeviceManifest, DeviceSelf, FolderManifest, FolderState, TakenName,
    device_folder_name, device_id_from_machine_id, find_device_folder, parse_manifest, serialize_manifest,
};
use beebeeb_types::backup::Platform;
use serde_json::Value;
use uuid::Uuid;

pub const CONCEPT: &str = "backup_device";

fn uuid(v: &Value) -> Uuid {
    Uuid::parse_str(v.as_str().expect("uuid string")).expect("uuid")
}

fn opt_str(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

fn platform(v: &Value) -> Platform {
    serde_json::from_value(v.clone()).expect("platform")
}

fn me(v: &Value) -> DeviceSelf {
    DeviceSelf {
        device_id: v["device_id"].as_str().expect("device_id").to_string(),
        name: v["name"].as_str().expect("name").to_string(),
        platform: platform(&v["platform"]),
    }
}

fn candidate(v: &Value) -> DeviceFolderCandidate {
    DeviceFolderCandidate {
        folder_id: uuid(&v["folder_id"]),
        name: v["name"].as_str().expect("name").to_string(),
        manifest: match &v["manifest"] {
            Value::Null => FolderManifest::Absent,
            Value::String(s) if s == "unreadable" => FolderManifest::Unreadable,
            // What a client does with the text it decrypted: a manifest that
            // does not parse is Unreadable (the uniffi binding does the same).
            m => match parse_manifest(&m.to_string()) {
                Ok(parsed) => FolderManifest::Parsed(parsed),
                Err(_) => FolderManifest::Unreadable,
            },
        },
    }
}

/// The input with its keys sorted, compact: what `serialize_manifest` must
/// reproduce byte-for-byte.
fn key_sorted(json: &str) -> String {
    serde_json::to_string(&serde_json::from_str::<Value>(json).expect("valid json")).expect("serialize")
}

#[test]
fn backup_device_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 57, "every named backup_device case is present");

    let (mut names, mut machine_ids, mut finds, mut manifests) = (0, 0, 0, 0);
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        match case["kind"].as_str().expect("case kind") {
            "name" => {
                names += 1;
                let taken: Vec<TakenName> = case["taken"]
                    .as_array()
                    .expect("taken")
                    .iter()
                    .map(|t| TakenName {
                        name: t["name"].as_str().expect("name").to_string(),
                        device_id: opt_str(&t["device_id"]),
                    })
                    .collect();
                let my_id = case["my_id"].as_str().expect("my_id");
                let got = device_folder_name(case["raw"].as_str().expect("raw"), my_id, &taken);
                assert_eq!(got, case["expected"].as_str().expect("expected"), "{id}");
            }
            "machine_id" => {
                machine_ids += 1;
                let got = device_id_from_machine_id(case["machine_id"].as_str().expect("machine_id"));
                assert_eq!(got, case["expected"].as_str().expect("expected"), "{id}");
                let parsed = Uuid::parse_str(&got).expect("a UUID string");
                assert_eq!(got, parsed.to_string(), "{id}: lowercase hyphenated");
                assert_eq!(parsed.get_version_num(), 8, "{id}: RFC 4122 version 8");
                assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122, "{id}: RFC 4122 variant");
            }
            "find" => {
                finds += 1;
                let candidates: Vec<DeviceFolderCandidate> = case["candidates"]
                    .as_array()
                    .expect("candidates")
                    .iter()
                    .map(candidate)
                    .collect();
                let got = find_device_folder(&me(&case["me"]), &candidates);
                let expect = &case["expect"];
                let want = if let Some(f) = expect.get("existing") {
                    DeviceFolderChoice::Existing(uuid(f))
                } else if let Some(f) = expect.get("adopt_legacy") {
                    DeviceFolderChoice::AdoptLegacy(uuid(f))
                } else {
                    DeviceFolderChoice::Create {
                        name: expect["create"].as_str().expect("create").to_string(),
                    }
                };
                assert_eq!(got, want, "{id}");
            }
            "manifest" => {
                manifests += 1;
                let json = case["json"].as_str().expect("json");
                let parsed = parse_manifest(json).unwrap_or_else(|e| panic!("{id}: {e}"));
                let expect = &case["expect"];
                assert_eq!(parsed.device_id, opt_str(&expect["device_id"]), "{id}: device_id");
                let want_platform = (!expect["platform"].is_null()).then(|| platform(&expect["platform"]));
                assert_eq!(parsed.platform, want_platform, "{id}: platform");
                assert_eq!(
                    parsed.device_name,
                    expect["device_name"].as_str().unwrap(),
                    "{id}: device_name"
                );
                assert_eq!(
                    parsed.folders.len() as u64,
                    expect["folders"].as_u64().unwrap(),
                    "{id}: folders"
                );
                // The input itself, unless the case names what is written back.
                let written = expect["written"].as_str().unwrap_or(json);
                assert_eq!(
                    serialize_manifest(&parsed),
                    key_sorted(written),
                    "{id}: byte-for-byte round trip"
                );
            }
            "manifest_error" => {
                manifests += 1;
                assert!(parse_manifest(case["json"].as_str().expect("json")).is_err(), "{id}");
            }
            other => panic!("{id}: unknown kind `{other}`"),
        }
    }
    println!(
        "backup_device: {} cases ({names} name, {machine_ids} machine id, {finds} find, {manifests} manifest)",
        cases.len()
    );
    assert_eq!(
        (names, machine_ids, finds, manifests),
        (28, 3, 14, 12),
        "case counts per kind"
    );
}

/// Review finding 4: a field this version knows wins over kept text of the
/// same name, so a renamed device is written with its new name, and a real id
/// replaces the legacy text it was parsed next to.
#[test]
fn manifest_known_field_wins_over_kept_text() {
    let id = Uuid::parse_str("00000001-0000-4000-8000-0000000000aa").expect("uuid");
    let mut other = serde_json::Map::new();
    other.insert("device_name".into(), Value::from("Old name"));
    other.insert("device_id".into(), Value::from("legacy-text"));
    other.insert("platform".into(), Value::from("amiga"));
    other.insert("version".into(), Value::from(7));
    other.insert("folders".into(), Value::from("not a list"));
    other.insert("note".into(), Value::from("kept"));
    let manifest = DeviceManifest {
        version: 1,
        device_id: Some(id.to_string()),
        device_name: "New name".into(),
        platform: None,
        folders: vec![FolderState {
            category: "pictures".into(),
            enabled: true,
            last_pass_at_ms: None,
            items: 3,
            other: serde_json::Map::from_iter([
                ("enabled".to_string(), Value::from("no")),
                ("source_hint".to_string(), Value::from("kept")),
            ]),
        }],
        other,
    };
    let written = serialize_manifest(&manifest);
    let back: Value = serde_json::from_str(&written).expect("json");
    assert_eq!(back["device_name"], "New name", "{written}");
    assert_eq!(back["device_id"], id.to_string(), "{written}");
    assert_eq!(back["version"], 1, "{written}");
    // The struct's folders win over the kept "folders" text, and a folder's
    // known field over its own kept text of that name (delta 3 #7).
    assert_eq!(back["folders"][0]["enabled"], true, "{written}");
    assert_eq!(back["folders"][0]["source_hint"], "kept", "{written}");
    assert_eq!(back["folders"].as_array().map(Vec::len), Some(1), "{written}");
    // No platform field: the text parse could not read is kept.
    assert_eq!(back["platform"], "amiga", "{written}");
    assert_eq!(back["note"], "kept", "{written}");
    let reparsed = parse_manifest(&written).expect("parses");
    assert_eq!(
        (reparsed.device_id.as_deref(), reparsed.device_name.as_str()),
        (Some(id.to_string().as_str()), "New name")
    );
}
