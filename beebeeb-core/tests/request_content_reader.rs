//! 2326 delta2 P2-2: a request row's content is read through a READER, not a
//! one-shot sequential handle.
//!
//! The reader owns the row's content key `C` (zeroized on drop), bound to the
//! row's file id and recorded chunk-format pin. It has no key getter, hands out
//! a fresh sequential decryptor per call, and opens one frame by index.

use beebeeb_core::CoreError;
use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor, ChunkFormat, ExpectedChunkFormat};
use beebeeb_core::kdf::FileKey;
use beebeeb_core::request_content::RequestContentReader;

const ID: &str = "66666666-6666-4666-8666-666666666666";
const KEY: [u8; 32] = [0x22; 32];

/// One v1 frame under `KEY`: `nonce || ciphertext || tag`, no AAD.
fn v1_frame(plaintext: &[u8]) -> Vec<u8> {
    let blob = beebeeb_core::encrypt::encrypt_chunk(&FileKey::from_bytes(KEY), plaintext).unwrap();
    let mut frame = blob.nonce.clone();
    frame.extend_from_slice(&blob.ciphertext);
    frame
}

/// One v2 upload of `plaintext` under `KEY`, bound to `ID`.
fn v2_frames(plaintext: &[u8], chunk_size: u64) -> (Vec<Vec<u8>>, [u8; 12]) {
    let mut enc =
        ChunkEncryptor::for_push_with_file_key(FileKey::from_bytes(KEY), ID, plaintext.len() as u64, chunk_size)
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
    let reader = RequestContentReader::new(FileKey::from_bytes(KEY), ID, ExpectedChunkFormat::V2);

    // Only frame 2 is presented; frames 0 and 1 were never opened.
    let got = reader
        .open_frame(&version, 2, true, ChunkFormat::V2, &frames[2])
        .unwrap();
    assert_eq!(got, &plaintext[64..96]);
}

#[test]
fn a_second_decryptor_opens_after_the_first_failed_mid_stream() {
    let plaintext: Vec<u8> = (0..96u8).collect();
    let (frames, _) = v2_frames(&plaintext, 32);
    let reader = RequestContentReader::new(FileKey::from_bytes(KEY), ID, ExpectedChunkFormat::V2);

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
fn the_reader_exposes_no_key_bytes() {
    // The reader's whole API is file_id(), pin(), decryptor() and open_frame().
    // None of them returns the key: the only byte-returning call is open_frame,
    // whose output is plaintext. A 32-byte plaintext is used here so the result
    // has exactly key length and can be fed to a decryptor as a candidate key.
    let plaintext = [0x5au8; 32];
    let (frames, version) = v2_frames(&plaintext, 64);
    let reader = RequestContentReader::new(FileKey::from_bytes(KEY), ID, ExpectedChunkFormat::V2);

    let out = reader
        .open_frame(&version, 0, true, ChunkFormat::V2, &frames[0])
        .unwrap();
    assert_eq!(out, plaintext);

    let candidate: [u8; 32] = out.as_slice().try_into().unwrap();
    let mut wrong = ChunkDecryptor::for_push_with_file_key(FileKey::from_bytes(candidate), ID, ExpectedChunkFormat::V2);
    assert!(
        wrong.push_frame(&frames[0]).is_err(),
        "the reader's output must not be a key that opens the row's frame"
    );
}
