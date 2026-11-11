//! 2326 delta2 P2-2: a request row's content is read through a READER, not a
//! one-shot sequential handle.
//!
//! The reader owns the row's content key `C` (zeroized on drop), bound to the
//! row's file id and recorded chunk-format pin. It has no key getter, hands out
//! a fresh sequential decryptor per call, and opens one frame by index.

use beebeeb_core::CoreError;
use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor, ChunkFormat, ExpectedChunkFormat, VersionCommitment};
use beebeeb_core::encrypt::NameMetadata;
use beebeeb_core::kdf::FileKey;
use beebeeb_core::request_content::RequestContentReader;

const ID: &str = "66666666-6666-4666-8666-666666666666";
const KEY: [u8; 32] = [0x22; 32];
const OTHER_ID: &str = "77777777-7777-4777-8777-777777777777";

/// One v1 frame under `KEY`: `nonce || ciphertext || tag`, no AAD.
fn v1_frame(plaintext: &[u8]) -> Vec<u8> {
    let blob = beebeeb_core::encrypt::encrypt_chunk(&FileKey::from_bytes(KEY), plaintext).unwrap();
    let mut frame = blob.nonce.clone();
    frame.extend_from_slice(&blob.ciphertext);
    frame
}

/// One v2 upload of `plaintext` under `KEY`, bound to `item_id`.
fn v2_frames_for(item_id: &str, plaintext: &[u8], chunk_size: u64) -> (Vec<Vec<u8>>, [u8; 12]) {
    let mut enc =
        ChunkEncryptor::for_push_with_file_key(FileKey::from_bytes(KEY), item_id, plaintext.len() as u64, chunk_size)
            .unwrap()
            .with_recorded_pin(ExpectedChunkFormat::V2)
            .unwrap();
    let frames: Vec<Vec<u8>> = plaintext
        .chunks(chunk_size as usize)
        .map(|c| enc.push_chunk(c).unwrap().data)
        .collect();
    enc.finish().unwrap();
    let version: [u8; 12] = frames[0][..12].try_into().unwrap();
    (frames, version)
}

/// One v2 upload of `plaintext` under `KEY`, bound to `ID`.
fn v2_frames(plaintext: &[u8], chunk_size: u64) -> (Vec<Vec<u8>>, [u8; 12]) {
    v2_frames_for(ID, plaintext, chunk_size)
}

/// The reader for a row whose authenticated metadata records v2 and commits to
/// the upload `version` (frame 0's nonce, first version).
fn committed_reader(version: &[u8; 12]) -> RequestContentReader {
    let record = NameMetadata {
        name: "upload.bin".into(),
        mime_type: None,
        chunk_format: ExpectedChunkFormat::V2,
        version: Some(VersionCommitment::new(*version, 1).unwrap()),
    };
    RequestContentReader::for_metadata(FileKey::from_bytes(KEY), ID, &record)
}

#[test]
fn a_v2_pinned_reader_refuses_a_v1_frame_that_an_unrecorded_reader_opens() {
    let plaintext = b"the request upload";
    let frame = v1_frame(plaintext);

    // The row's name authenticated v2, so its reader refuses a v1 frame under C.
    let pinned = RequestContentReader::new(FileKey::from_bytes(KEY), ID, ExpectedChunkFormat::V2);
    let err = pinned
        .open_frame(&[], 0, true, ChunkFormat::V1Legacy, &frame)
        .expect_err("a reader pinned to v2 must refuse a v1 frame under the same C");
    assert!(
        matches!(err, CoreError::InvalidInput(_)),
        "the pin must refuse with InvalidInput, got {err:?}"
    );

    // The SAME frame opens on an Unrecorded reader under the same key C: the
    // pin refused it, not the key.
    let unrecorded = RequestContentReader::new(FileKey::from_bytes(KEY), ID, ExpectedChunkFormat::Unrecorded);
    assert_eq!(
        unrecorded
            .open_frame(&[], 0, true, ChunkFormat::V1Legacy, &frame)
            .unwrap(),
        plaintext
    );
}

#[test]
fn a_range_read_opens_frame_k_without_frames_0_to_k_minus_1() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    let (frames, version) = v2_frames(&plaintext, 32);
    let reader = committed_reader(&version);

    // Only frame 2 is presented; frames 0 and 1 were never opened.
    let got = reader
        .open_frame(&version, 2, true, ChunkFormat::V2, &frames[2])
        .unwrap();
    assert_eq!(got, &plaintext[64..96]);
}

#[test]
fn a_second_decryptor_opens_after_the_first_failed_mid_stream() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    let (frames, version) = v2_frames(&plaintext, 32);
    let reader = committed_reader(&version);

    let mut first = reader.decryptor();
    first.push_frame(&frames[0]).unwrap();
    assert!(first.push_frame(&frames[2]).is_err(), "frame 2 must fail at index 1");

    // A fresh decryptor starts again at index 0; the failed cursor is not reused.
    let mut second = reader.decryptor();
    let mut out = Vec::new();
    for frame in &frames {
        out.extend_from_slice(&second.push_frame(frame).unwrap().data);
    }
    second.finish().unwrap();
    assert_eq!(out, plaintext);
}

#[test]
fn the_readers_byte_output_is_plaintext_not_a_key() {
    // The reader's whole API is file_id(), pin(), decryptor() and open_frame().
    // None of them returns the key: the only byte-returning call is open_frame,
    // whose output is plaintext. A 32-byte plaintext is used here so the result
    // has exactly key length and can be fed to a decryptor as a candidate key.
    let plaintext = [0x5au8; 32];
    let (frames, version) = v2_frames(&plaintext, 64);
    let reader = committed_reader(&version);

    let out = reader
        .open_frame(&version, 0, true, ChunkFormat::V2, &frames[0])
        .unwrap();
    assert_eq!(out, plaintext);

    let candidate: [u8; 32] = out.as_slice().try_into().unwrap();
    let mut wrong = ChunkDecryptor::for_version_with_file_key(
        FileKey::from_bytes(candidate),
        ID,
        ExpectedChunkFormat::V2,
        Some(VersionCommitment::new(version, 1).unwrap()),
    );
    assert!(
        wrong.push_frame(&frames[0]).is_err(),
        "the reader's output must not be a key that opens the row's frame"
    );
}

#[test]
fn the_readers_debug_output_omits_the_key() {
    let reader = RequestContentReader::new(FileKey::from_bytes(KEY), ID, ExpectedChunkFormat::V2);
    let shown = format!("{reader:?}");
    assert!(shown.contains("RequestContentReader"), "{shown}");
    assert!(shown.contains(ID), "{shown}");
    assert!(!shown.contains("file_key"), "Debug names the key field: {shown}");
    assert!(
        !shown.contains(&"22".repeat(32)),
        "Debug printed the key as hex: {shown}"
    );
    assert!(
        !shown.contains(&format!("{KEY:?}")),
        "Debug printed the key's bytes: {shown}"
    );
}

#[test]
fn open_frame_refuses_a_middle_frame_claimed_as_last() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    let (frames, version) = v2_frames(&plaintext, 32);
    let reader = committed_reader(&version);

    // frames[1] is a middle frame; its AAD binds `is_last = false`.
    assert!(
        reader
            .open_frame(&version, 1, true, ChunkFormat::V2, &frames[1])
            .is_err(),
        "frames[1] is not the last frame; claiming it is must not open it"
    );
    // The real position opens it: the refusal above is about `is_last`, not the
    // frame.
    assert_eq!(
        reader
            .open_frame(&version, 1, false, ChunkFormat::V2, &frames[1])
            .unwrap(),
        &plaintext[32..64]
    );
}

#[test]
fn open_frame_refuses_a_frame_at_the_wrong_index() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    let (frames, version) = v2_frames(&plaintext, 32);
    let reader = committed_reader(&version);

    // frames[2] is bound to index 2; presenting it as index 1 must fail.
    assert!(
        reader
            .open_frame(&version, 1, true, ChunkFormat::V2, &frames[2])
            .is_err(),
        "frames[2] must not open at index 1"
    );
}

#[test]
fn open_frame_refuses_a_wrong_version_id() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    let (frames, version) = v2_frames(&plaintext, 32);
    let reader = committed_reader(&version);

    let mut wrong = version;
    wrong[0] ^= 0x01;
    assert!(
        reader.open_frame(&wrong, 2, true, ChunkFormat::V2, &frames[2]).is_err(),
        "frames[2] must not open under another upload's version id"
    );
}

#[test]
fn open_frame_refuses_a_frame_bound_to_another_id() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    // The same key C, but the upload was bound to a DIFFERENT file id.
    let (frames, version) = v2_frames_for(OTHER_ID, &plaintext, 32);
    let reader = committed_reader(&version);

    assert!(
        reader
            .open_frame(&version, 0, true, ChunkFormat::V2, &frames[0])
            .is_err(),
        "a frame bound to another id must not open under this reader"
    );
}

/// Guus's ruling of 2026-11-07, "refuse v2 without commitment": a reader whose
/// record carries no version commitment opens no v2 frame, through its
/// sequential decryptor or its random-access path. Mutant: `open_frame`'s and
/// core's no-commitment refusals removed: both reads return plaintext.
#[test]
fn a_reader_without_a_commitment_opens_no_v2_frame() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    let (frames, version) = v2_frames(&plaintext, 32);
    for pin in [ExpectedChunkFormat::V2, ExpectedChunkFormat::Unrecorded] {
        let reader = RequestContentReader::new(FileKey::from_bytes(KEY), ID, pin);
        let err = reader
            .open_frame(&version, 2, true, ChunkFormat::V2, &frames[2])
            .expect_err("a v2 frame without a commitment");
        assert!(matches!(err, CoreError::InvalidInput(_)), "{pin:?}: {err:?}");
        let err = reader
            .decryptor()
            .push_frame(&frames[0])
            .expect_err("a v2 frame 0 without a commitment");
        assert!(matches!(err, CoreError::InvalidInput(_)), "{pin:?}: {err:?}");
    }
    // The committed reader opens the same frames.
    assert_eq!(
        committed_reader(&version)
            .open_frame(&version, 2, true, ChunkFormat::V2, &frames[2])
            .unwrap(),
        &plaintext[64..96]
    );
}
