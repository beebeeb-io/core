#![allow(deprecated)]

use std::io::Cursor;

use beebeeb_core::CoreError;
use beebeeb_core::chunk_stream::{
    ChunkDecryptor, ChunkEncryptor, ChunkFormat, ExpectedChunkFormat, MAX_CHUNK_SIZE, VersionCommitment,
    VersionCounterStatus, WRITE_FORMAT, check_version_counter,
};
use beebeeb_core::encrypt::{
    METADATA_SEAL_WRITE, MetadataSeal, decrypt_file_metadata, decrypt_name, decrypt_name_with_key,
    decrypt_note_for_metadata, decrypt_thumbnail_for_metadata, encrypt_chunk_raw, encrypt_metadata,
    encrypt_name_with_version,
};
use beebeeb_core::kdf::{MasterKey, derive_file_key};

const FILE_ID: &str = "a11cf00d-0000-4000-8000-000000002020";

fn master() -> MasterKey {
    MasterKey::from_bytes([0x42; 32])
}

fn version(master: &MasterKey, plaintext: &[u8], previous: Option<VersionCommitment>) -> (Vec<u8>, VersionCommitment) {
    let mut enc = ChunkEncryptor::for_push_with_chunk_size(master, FILE_ID, plaintext.len() as u64, 64).unwrap();
    let frame = enc.push_chunk(plaintext).unwrap().data;
    let commitment = enc.version_commitment(previous).unwrap();
    enc.finish().unwrap();
    (frame, commitment)
}

#[test]
fn production_write_switches_content_and_metadata_together() {
    assert_eq!(WRITE_FORMAT, ChunkFormat::V2);
    assert_eq!(METADATA_SEAL_WRITE, MetadataSeal::Subkey);
}

#[test]
fn metadata_roundtrips_the_version_commitment() {
    let master = master();
    let (_, commitment) = version(&master, b"current", None);
    let sealed = encrypt_name_with_version(
        &master,
        FILE_ID,
        "current.txt",
        Some("text/plain"),
        ExpectedChunkFormat::V2,
        commitment,
    )
    .unwrap();

    let metadata = decrypt_file_metadata(&master, FILE_ID, &sealed).unwrap();
    assert_eq!(metadata.version, Some(commitment));
    assert!(metadata.is_version_protected());
}

#[test]
fn current_and_historical_reads_use_their_own_metadata() {
    let master = master();
    let (old_frame, old_commitment) = version(&master, b"old", None);
    let old_name = encrypt_name_with_version(
        &master,
        FILE_ID,
        "history.txt",
        None,
        ExpectedChunkFormat::V2,
        old_commitment,
    )
    .unwrap();
    let old_metadata = decrypt_file_metadata(&master, FILE_ID, &old_name).unwrap();

    let (current_frame, current_commitment) = version(&master, b"current", Some(old_commitment));
    let current_name = encrypt_name_with_version(
        &master,
        FILE_ID,
        "history.txt",
        None,
        ExpectedChunkFormat::V2,
        current_commitment,
    )
    .unwrap();
    let current_metadata = decrypt_file_metadata(&master, FILE_ID, &current_name).unwrap();

    let mut current = ChunkDecryptor::for_current_version(&master, FILE_ID, &current_metadata);
    assert!(matches!(current.push_frame(&old_frame), Err(CoreError::Decryption)));

    let mut current = ChunkDecryptor::for_current_version(&master, FILE_ID, &current_metadata);
    assert_eq!(current.push_frame(&current_frame).unwrap().data, b"current");
    current.finish().unwrap();

    let mut historical = ChunkDecryptor::for_historical_version(&master, FILE_ID, &old_metadata);
    assert_eq!(historical.push_frame(&old_frame).unwrap().data, b"old");
    historical.finish().unwrap();
}

#[test]
fn legacy_metadata_is_readable_and_reported_unprotected() {
    let master = master();
    let file_key = derive_file_key(&master, FILE_ID.as_bytes());
    let plaintext = serde_json::json!({"name":"legacy.txt","mime_type":null}).to_string();
    let envelope = serde_json::to_string(&encrypt_metadata(&file_key, &plaintext).unwrap()).unwrap();

    let metadata = decrypt_file_metadata(&master, FILE_ID, &envelope).unwrap();
    assert_eq!(metadata.version, None);
    assert!(!metadata.is_version_protected());
}

#[test]
fn raw_key_fallback_cannot_open_a_recorded_v2_pin() {
    let master = master();
    let file_key = derive_file_key(&master, FILE_ID.as_bytes());
    let plaintext = serde_json::json!({
        "name":"downgrade.txt",
        "mime_type":null,
        "chunk_format":2
    })
    .to_string();
    let envelope = serde_json::to_string(&encrypt_metadata(&file_key, &plaintext).unwrap()).unwrap();

    assert!(matches!(
        decrypt_file_metadata(&master, FILE_ID, &envelope),
        Err(CoreError::Decryption)
    ));
    assert!(matches!(
        decrypt_name(&master, FILE_ID, &envelope),
        Err(CoreError::Decryption)
    ));
    assert_eq!(decrypt_name_with_key(&file_key, &envelope), None);
}

#[test]
fn protected_notes_and_thumbnails_do_not_fall_back_to_the_raw_key() {
    let master = master();
    let file_key = derive_file_key(&master, FILE_ID.as_bytes());
    let (_, commitment) = version(&master, b"current", None);
    let sealed = encrypt_name_with_version(
        &master,
        FILE_ID,
        "current.txt",
        None,
        ExpectedChunkFormat::V2,
        commitment,
    )
    .unwrap();
    let metadata = decrypt_file_metadata(&master, FILE_ID, &sealed).unwrap();

    let raw_thumbnail = encrypt_chunk_raw(&file_key, b"thumbnail").unwrap();
    assert!(matches!(
        decrypt_thumbnail_for_metadata(&file_key, &raw_thumbnail, &metadata),
        Err(CoreError::Decryption)
    ));

    let raw_note = serde_json::to_string(&encrypt_metadata(&file_key, "note").unwrap()).unwrap();
    assert!(matches!(
        decrypt_note_for_metadata(&file_key, &raw_note, &metadata),
        Err(CoreError::Decryption)
    ));
}

#[test]
fn counter_check_is_pure_and_flags_rollback() {
    assert_eq!(check_version_counter(4, None), VersionCounterStatus::FirstSeen);
    assert_eq!(check_version_counter(4, Some(4)), VersionCounterStatus::Current);
    assert_eq!(check_version_counter(5, Some(4)), VersionCounterStatus::Advanced);
    assert_eq!(check_version_counter(3, Some(4)), VersionCounterStatus::Rollback);
}

#[test]
fn pull_decryptor_applies_the_chunk_size_cap_before_allocating() {
    let master = master();
    let err = ChunkDecryptor::from_reader(
        &master,
        FILE_ID,
        ExpectedChunkFormat::V2,
        MAX_CHUNK_SIZE + 1,
        Cursor::new(Vec::<u8>::new()),
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}
