//! `test-vectors/archives_v1.json`: every committed fixture's listing and
//! every word, against an independent Python generator
//! (`test-vectors/tools/gen_archives_v1.py`). The wasm and Swift runners
//! read the same file.

use std::collections::BTreeMap;
use std::io::Cursor;

use beebeeb_core::archives::words::{count_label, size_label};
use beebeeb_core::archives::{
    ArchiveEntry, ArchiveKey, ArchiveListing, ArchivePlatform, ArchiveRefusal, ArchiveSession, EntryCipher,
    ReadSeekSource, SessionStep, SkipReason, archive_text,
};
use serde_json::Value;

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/archives_v1.json");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/archives");

fn vectors() -> Value {
    let text = std::fs::read_to_string(VECTORS).expect("read test-vectors/archives_v1.json");
    let doc: Value = serde_json::from_str(&text).expect("parse the vectors");
    assert_eq!(doc["version"], 1, "vectors version");
    doc
}

fn rows<'a>(doc: &'a Value, field: &str) -> &'a Vec<Value> {
    doc[field].as_array().unwrap_or_else(|| panic!("`{field}` is an array"))
}

fn text<'a>(row: &'a Value, field: &str) -> &'a str {
    row[field]
        .as_str()
        .unwrap_or_else(|| panic!("`{field}` is a string in {row}"))
}

fn list(bytes: Vec<u8>) -> Result<ArchiveListing, ArchiveRefusal> {
    let source = ReadSeekSource::new(Cursor::new(bytes)).expect("an in-memory source");
    let mut session = ArchiveSession::open(source, ArchivePlatform::Native);
    match session.step() {
        SessionStep::Listed => Ok(session.listing().expect("listed").clone()),
        SessionStep::Refused(refusal) => Err(refusal),
        other => panic!("a blocking source gave {other:?}"),
    }
}

fn refusal_string(refusal: ArchiveRefusal) -> String {
    match refusal {
        ArchiveRefusal::Foreign(format) => format!("foreign:{}", format.as_str()),
        other => other.as_str().to_string(),
    }
}

fn cipher_string(cipher: EntryCipher) -> String {
    match cipher {
        EntryCipher::None => "none".into(),
        EntryCipher::ZipCrypto => "zipcrypto".into(),
        EntryCipher::Aes { bits, ae } => format!("aes{bits}_ae{ae}"),
    }
}

fn skip_string(skip: &SkipReason) -> String {
    match skip {
        SkipReason::Method(name) => format!("method:{name}"),
        SkipReason::Unsupported(what) => format!("unsupported:{what}"),
        other => other.as_str().to_string(),
    }
}

/// An entry in the vectors' own shape.
fn entry_row(entry: &ArchiveEntry) -> Value {
    serde_json::json!({
        "display_path": entry.display_path,
        "path": entry.path.as_ref().map(|p| p.joined()),
        "kind": entry.kind.as_str(),
        "size": entry.size.to_string(),
        "cipher": cipher_string(entry.cipher),
        "skip": entry.skip.as_ref().map(skip_string),
    })
}

#[test]
fn every_fixture_lists_as_recorded() {
    let doc = vectors();
    let fixtures = rows(&doc, "fixtures");
    let mut on_disk: Vec<String> = std::fs::read_dir(FIXTURES)
        .expect("read test-vectors/archives")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect();
    on_disk.sort();
    let mut recorded: Vec<String> = fixtures.iter().map(|row| text(row, "file").to_string()).collect();
    recorded.sort();
    assert_eq!(
        on_disk, recorded,
        "every committed fixture has a row, and every row a file"
    );

    let mut entries = 0usize;
    for row in fixtures {
        let file = text(row, "file");
        let bytes = std::fs::read(format!("{FIXTURES}/{file}")).expect("read the fixture");
        match list(bytes) {
            Ok(listing) => {
                assert!(
                    row["refusal"].is_null(),
                    "{file}: listed, but recorded as refused: {}",
                    row["refusal"]
                );
                assert_eq!(listing.format.as_str(), text(row, "format"), "{file}: format");
                assert!(listing.complete, "{file}: complete");
                let got: Vec<Value> = listing.entries.iter().map(entry_row).collect();
                let want = rows(row, "entries");
                for (i, (got, want)) in got.iter().zip(want).enumerate() {
                    assert_eq!(got, want, "{file}: entry {i}");
                }
                assert_eq!(got.len(), want.len(), "{file}: entry count");
                entries += got.len();
            }
            Err(refusal) => {
                assert_eq!(refusal_string(refusal), text(row, "refusal"), "{file}: refusal");
                assert!(row["format"].is_null(), "{file}: a refused fixture has no format");
                assert!(
                    rows(row, "entries").is_empty(),
                    "{file}: a refused fixture has no entries"
                );
            }
        }
    }
    println!("{} fixtures, {entries} entries", fixtures.len());
}

#[test]
fn every_word_byte_exact() {
    let doc = vectors();
    let words = rows(&doc, "words");
    let mut keys = BTreeMap::new();
    for row in words {
        let name = text(row, "key");
        let key = ArchiveKey::parse(name).unwrap_or_else(|| panic!("unknown key `{name}`"));
        let args: Vec<(&str, &str)> = row["args"]
            .as_object()
            .expect("args is an object")
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str().expect("an argument is a string")))
            .collect();
        let got = archive_text(key, &args);
        assert_eq!(got.key, name, "{name}: key");
        assert_eq!(got.text, text(row, "text"), "{name} {args:?}");
        let mut got_args: Vec<(&str, &str)> = got.args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let mut want_args = args.clone();
        got_args.sort();
        want_args.sort();
        assert_eq!(got_args, want_args, "{name}: args");
        *keys.entry(name).or_insert(0usize) += 1;
    }
    assert_eq!(keys.len(), ArchiveKey::ALL.len(), "every key has a row");
    assert_eq!(keys.len(), 63, "spec §9 has 63 keys");

    let counts = rows(&doc, "counts");
    for row in counts {
        let value: u64 = text(row, "value").parse().expect("a decimal count");
        assert_eq!(count_label(value), text(row, "text"), "count {value}");
    }
    let sizes = rows(&doc, "sizes");
    for row in sizes {
        let bytes: u64 = text(row, "bytes").parse().expect("a decimal size");
        assert_eq!(size_label(bytes), text(row, "text"), "size {bytes}");
    }
    println!(
        "{} words over {} keys, {} counts, {} sizes",
        words.len(),
        keys.len(),
        counts.len(),
        sizes.len()
    );
}
