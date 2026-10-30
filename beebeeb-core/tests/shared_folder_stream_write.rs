#![allow(deprecated)] // pre-L13 writers are the parity baseline

use std::io::Cursor;

use beebeeb_core::CoreError;
use beebeeb_core::chunk_stream::{
    CHUNK_OVERHEAD, ChunkDecryptor, ChunkEncryptor, ChunkFormat, EncryptedChunk, ExpectedChunkFormat, MAX_CHUNK_SIZE,
    WRITE_FORMAT,
};
use beebeeb_core::encrypt::{decrypt_file_metadata_with_key, encrypt_chunk_raw, encrypt_name_for};
use beebeeb_core::kdf::{FileKey, MasterKey, derive_file_key};

const ID: &str = "11111111-1111-4111-8111-111111111111";
const SIZE: u64 = 32;

fn key() -> FileKey {
    FileKey::from_bytes(std::array::from_fn(|i| 0xa0 + i as u8))
}

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn push_all(enc: &mut ChunkEncryptor, plaintext: &[u8]) -> Vec<EncryptedChunk> {
    if plaintext.is_empty() {
        vec![enc.push_chunk(&[]).unwrap()]
    } else {
        plaintext
            .chunks(SIZE as usize)
            .map(|part| enc.push_chunk(part).unwrap())
            .collect()
    }
}

fn open(key: FileKey, id: &str, frames: &[EncryptedChunk], pin: ExpectedChunkFormat) -> Result<Vec<u8>, CoreError> {
    let mut dec = ChunkDecryptor::for_push_with_file_key(key, id, pin);
    let mut out = Vec::new();
    for frame in frames {
        out.extend_from_slice(&dec.push_frame(&frame.data)?.data);
    }
    dec.finish()?;
    Ok(out)
}

#[test]
fn push_random_key_roundtrip() {
    let master = MasterKey::from_bytes([7; 32]);
    assert_ne!(key().as_bytes(), derive_file_key(&master, ID.as_bytes()).as_bytes());
    for len in [0, 1, 31, 32, 33, 129] {
        let plaintext = plaintext(len);
        let mut enc = ChunkEncryptor::for_push_with_file_key(key(), ID, len as u64, SIZE).unwrap();
        assert_eq!(enc.format(), WRITE_FORMAT);
        let frames = push_all(&mut enc, &plaintext);
        let pin = ExpectedChunkFormat::recorded_for(enc.format());
        let summary = enc.finish().unwrap();
        assert_eq!(summary.total_plaintext, len as u64);
        assert_eq!(
            summary.total_ciphertext,
            len as u64 + CHUNK_OVERHEAD * frames.len() as u64
        );
        let opened = open(key(), ID, &frames, pin).unwrap();
        assert_eq!(opened, plaintext);
        let wrong_key_result = open(derive_file_key(&master, ID.as_bytes()), ID, &frames, pin);
        assert!(wrong_key_result.is_err());
    }
}

#[test]
fn reader_random_key_roundtrip() {
    for len in [0, 1, 32, 33, 129] {
        let plaintext = plaintext(len);
        let mut enc =
            ChunkEncryptor::from_reader_with_file_key(key(), ID, len as u64, SIZE, Cursor::new(plaintext.clone()))
                .unwrap();
        let mut frames = Vec::new();
        while let Some(frame) = enc.next_chunk().unwrap() {
            assert_eq!(frame.index as usize, frames.len());
            frames.push(frame);
        }
        let pin = ExpectedChunkFormat::recorded_for(enc.format());
        let summary = enc.finish().unwrap();
        assert_eq!(summary.chunk_count as usize, frames.len());
        let opened = open(key(), ID, &frames, pin).unwrap();
        assert_eq!(opened, plaintext);
        let wrong_key_result = open(FileKey::from_bytes([0x33; 32]), ID, &frames, pin);
        assert!(wrong_key_result.is_err());
    }
}

#[test]
fn v2_replacement_pin_and_file_id() {
    // Model an existing file's authenticated v2 metadata, never a server pin.
    let metadata = encrypt_name_for(&key(), "guest.txt", None, ExpectedChunkFormat::V2).unwrap();
    let pin = decrypt_file_metadata_with_key(&key(), &metadata).unwrap().chunk_format;
    let plaintext = plaintext(97);
    let mut enc = ChunkEncryptor::for_push_with_file_key(key(), ID, 97, SIZE)
        .unwrap()
        .with_recorded_pin(pin)
        .unwrap();
    assert_eq!(enc.format(), ChunkFormat::V2);
    let frames = push_all(&mut enc, &plaintext);
    enc.finish().unwrap();
    let opened = open(key(), ID, &frames, pin).unwrap();
    assert_eq!(opened, plaintext);
    assert!(open(key(), "22222222-2222-4222-8222-222222222222", &frames, pin).is_err());
    let wrong_key_result = open(FileKey::from_bytes([0x33; 32]), ID, &frames, pin);
    assert!(wrong_key_result.is_err());
    let mut replacement =
        ChunkEncryptor::from_reader_with_file_key(key(), ID, 97, SIZE, Cursor::new(plaintext.clone()))
            .unwrap()
            .with_recorded_pin(pin)
            .unwrap();
    let mut other = Vec::new();
    while let Some(frame) = replacement.next_chunk().unwrap() {
        other.push(frame);
    }
    replacement.finish().unwrap();
    assert_eq!(open(key(), ID, &other, pin).unwrap(), plaintext);
    assert_ne!(&frames[0].data[..12], &other[0].data[..12]);
    let mut mixed = frames.clone();
    mixed[1] = other[1].clone();
    assert!(open(key(), ID, &mixed, pin).is_err());
    let legacy_frame = EncryptedChunk {
        index: 0,
        data: encrypt_chunk_raw(&key(), b"legacy").unwrap(),
    };
    assert!(open(key(), ID, &[legacy_frame], pin).is_err());
    let mut started = ChunkEncryptor::for_push_with_file_key(key(), ID, 1, SIZE).unwrap();
    started.push_chunk(b"x").unwrap();
    assert!(started.with_recorded_pin(pin).is_err());
}

#[test]
fn truncation_never_finishes() {
    let enc = ChunkEncryptor::for_push_with_file_key(key(), ID, 65, SIZE).unwrap();
    let truncated_finish = enc.finish();
    assert!(truncated_finish.is_err());
    let mut short = ChunkEncryptor::for_push_with_file_key(key(), ID, 33, SIZE).unwrap();
    short.push_chunk(&[1; 32]).unwrap();
    short.push_chunk(&[]).unwrap();
    assert!(short.finish().is_err());
    let mut short_reader =
        ChunkEncryptor::from_reader_with_file_key(key(), ID, 65, SIZE, Cursor::new(vec![1; 64])).unwrap();
    while short_reader.next_chunk().unwrap().is_some() {}
    assert!(short_reader.finish().is_err());
    let mut enc = ChunkEncryptor::for_push_with_file_key(key(), ID, 65, SIZE)
        .unwrap()
        .with_recorded_pin(ExpectedChunkFormat::V2)
        .unwrap();
    let frames = push_all(&mut enc, &plaintext(65));
    enc.finish().unwrap();
    let mut dec = ChunkDecryptor::for_push_with_file_key(key(), ID, ExpectedChunkFormat::V2);
    for frame in &frames[..frames.len() - 1] {
        dec.push_frame(&frame.data).unwrap();
    }
    let truncated_finish = dec.finish();
    assert!(truncated_finish.is_err());
}

#[test]
fn bounds_and_legacy_constructor() {
    for (file_size, chunk_size) in [(0, 0), (1, MAX_CHUNK_SIZE + 1), (1, u64::MAX), (u64::MAX, 1)] {
        assert!(ChunkEncryptor::for_push_with_file_key(key(), ID, file_size, chunk_size).is_err());
        assert!(
            ChunkEncryptor::from_reader_with_file_key(key(), ID, file_size, chunk_size, Cursor::new(Vec::<u8>::new()),)
                .is_err()
        );
    }
    assert!(ChunkEncryptor::for_push_with_file_key(key(), ID, 0, MAX_CHUNK_SIZE).is_ok());
    let master = MasterKey::from_bytes([7; 32]);
    let plaintext = plaintext(65);
    let mut legacy = ChunkEncryptor::for_push_with_chunk_size(&master, ID, 65, SIZE).unwrap();
    let pin = ExpectedChunkFormat::recorded_for(legacy.format());
    let frames = push_all(&mut legacy, &plaintext);
    legacy.finish().unwrap();
    assert_eq!(
        open(derive_file_key(&master, ID.as_bytes()), ID, &frames, pin).unwrap(),
        plaintext
    );
    let mut explicit =
        ChunkEncryptor::for_push_with_file_key(derive_file_key(&master, ID.as_bytes()), ID, 65, SIZE).unwrap();
    let frames = push_all(&mut explicit, &plaintext);
    explicit.finish().unwrap();
    let mut dec = ChunkDecryptor::for_push(&master, ID, pin);
    let mut opened = Vec::new();
    for frame in &frames {
        opened.extend_from_slice(&dec.push_frame(&frame.data).unwrap().data);
    }
    dec.finish().unwrap();
    assert_eq!(opened, plaintext);
}
