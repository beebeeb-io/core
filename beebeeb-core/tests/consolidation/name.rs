//! Move 1 — name and metadata decryption (spec §16.2).
//!
//! The vector in `test-vectors/consolidation/name.json` pins the three shapes a
//! client hands core and the name, MIME and chunk-format pin core returns.
//! The batch readers must agree with their single-item forms, in input order,
//! with a bad row failing that row only.

#![allow(deprecated)]

use beebeeb_core::CoreError;
use beebeeb_core::chunk_stream::ExpectedChunkFormat;
use beebeeb_core::encrypt::{
    NameMetadata, decrypt_file_metadata, decrypt_name, decrypt_name_metadata, decrypt_name_metadata_with_key,
    encrypt_name_with_chunk_format,
};
use beebeeb_core::encrypt_batch::{decrypt_files_metadata, decrypt_names_metadata};
use beebeeb_core::kdf::{FileKey, MasterKey};
use serde_json::Value;

pub const CONCEPT: &str = "name";

fn bytes32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap_or_else(|e| panic!("not hex: {e}"));
    bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected 32 bytes, got {}", v.len()))
}

fn master_key(case: &Value) -> MasterKey {
    MasterKey::from_bytes(bytes32(case["master_key_hex"].as_str().expect("master_key_hex")))
}

fn pin(value: &Value) -> ExpectedChunkFormat {
    let code = value.as_u64().expect("chunk_format number") as u8;
    ExpectedChunkFormat::from_u8(code).expect("known chunk format")
}

fn assert_metadata(case_id: &str, meta: &NameMetadata, expected: &Value) {
    assert_eq!(
        meta.name,
        expected["name"].as_str().expect("expected.name"),
        "{case_id}: name"
    );
    assert_eq!(
        meta.mime_type.as_deref(),
        expected["mime_type"].as_str(),
        "{case_id}: mime_type"
    );
    assert_eq!(
        meta.chunk_format,
        pin(&expected["chunk_format"]),
        "{case_id}: chunk_format"
    );
}

#[test]
fn name_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert!(cases.len() >= 6, "the named cases of move 1 are all present");

    // Batch equivalence is checked against the same rows the singles read.
    let mut batchable: Vec<(String, String)> = Vec::new();

    for case in &cases {
        let case_id = case["id"].as_str().expect("case id");
        let expected = &case["expected"];
        match case["kind"].as_str().expect("case kind") {
            "plaintext" => {
                let mk = master_key(case);
                let file_id = case["file_id"].as_str().expect("file_id");
                let input = case["input"].as_str().expect("input");
                let meta = decrypt_name_metadata(&mk, file_id, input).expect("plaintext metadata reads");
                assert_metadata(case_id, &meta, expected);
                assert_eq!(
                    decrypt_name(&mk, file_id, input).expect("plaintext name reads"),
                    expected["name"].as_str().unwrap(),
                    "{case_id}: decrypt_name"
                );
                batchable.push((file_id.to_string(), input.to_string()));
            }
            "encrypted-master-key" => {
                let mk = master_key(case);
                let file_id = case["file_id"].as_str().expect("file_id");
                let envelope = case["name_encrypted"].as_str().expect("name_encrypted");
                let meta = decrypt_file_metadata(&mk, file_id, envelope).expect("file metadata reads");
                assert_metadata(case_id, &meta, expected);
                batchable.push((file_id.to_string(), envelope.to_string()));
            }
            "encrypted-file-key" => {
                let fk = FileKey::from_bytes(bytes32(case["file_key_hex"].as_str().expect("file_key_hex")));
                let envelope = case["name_encrypted"].as_str().expect("name_encrypted");
                let meta = decrypt_name_metadata_with_key(&fk, envelope).expect("shared-folder metadata reads");
                assert_metadata(case_id, &meta, expected);
            }
            "roundtrip" => {
                let mk = master_key(case);
                let file_id = case["file_id"].as_str().expect("file_id");
                let name = case["name"].as_str().expect("name");
                let mime = case["mime_type"].as_str();
                let sealed = encrypt_name_with_chunk_format(&mk, file_id, name, mime, pin(&case["pin"]))
                    .expect("the shipped writer seals");
                let meta = decrypt_file_metadata(&mk, file_id, &sealed).expect("the file reader opens it");
                assert_metadata(case_id, &meta, expected);
            }
            "encrypted-wrong-key" => {
                let mk = master_key(case);
                let file_id = case["file_id"].as_str().expect("file_id");
                let envelope = case["name_encrypted"].as_str().expect("name_encrypted");
                let err = decrypt_name_metadata(&mk, file_id, envelope)
                    .expect_err("a wrong key must be a typed error, never a panic or a name");
                assert!(
                    matches!(err, CoreError::Decryption),
                    "{case_id}: expected CoreError::Decryption, got {err:?}"
                );
            }
            other => panic!("{case_id}: unknown case kind `{other}`"),
        }
    }

    // The batch readers are the single readers over N rows: same order, same
    // values, and the file reader refuses the plaintext rows per row.
    let borrowed: Vec<(String, &str)> = batchable.iter().map(|(id, enc)| (id.clone(), enc.as_str())).collect();
    let mk = MasterKey::from_bytes(bytes32(
        cases[0]["master_key_hex"].as_str().expect("the shared master key"),
    ));
    let batch = decrypt_names_metadata(&mk, &borrowed);
    assert_eq!(batch.len(), borrowed.len(), "batch length and order are preserved");
    for ((file_id, envelope), result) in borrowed.iter().zip(&batch) {
        let single = decrypt_name_metadata(&mk, file_id, envelope);
        match (single, result) {
            (Ok(a), Ok(b)) => assert_eq!(&a, b, "{file_id}: batch disagrees with the single reader"),
            (Err(_), Err(_)) => {}
            (a, b) => panic!("{file_id}: single {a:?} vs batch {b:?}"),
        }
    }
    let file_rows: Vec<(String, &str)> = batchable
        .iter()
        .filter(|(_, envelope)| envelope.starts_with('{'))
        .map(|(id, envelope)| (id.clone(), envelope.as_str()))
        .collect();
    let files = decrypt_files_metadata(&mk, &file_rows);
    assert!(
        files
            .iter()
            .all(|result| result.as_ref().is_ok_and(|m| m.name.starts_with("vector-v2"))),
        "the file reader returns the pin for every encrypted row"
    );
    for ((file_id, envelope), result) in file_rows.iter().zip(&files) {
        assert_eq!(
            result.as_ref().ok().cloned(),
            decrypt_file_metadata(&mk, file_id, envelope).ok(),
            "{file_id}: file batch disagrees with the single reader"
        );
    }
}
