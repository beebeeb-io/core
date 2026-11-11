//! Move 10 — the download side (spec §16.2).
//!
//! Cases live in `test-vectors/consolidation/download.json`; this runner
//! executes them against `beebeeb_core::download`, the promoted loop that
//! `beebeeb-upload` now delegates to.

use beebeeb_core::chunk_stream::{ChunkEncryptor, ExpectedChunkFormat, VersionCommitment};
use beebeeb_core::download::{
    DownloadFailure, checked_frame_size, chunk_offset, compute_chunk_boundaries, decrypt_chunks_to, decrypt_frames_to,
};
use beebeeb_core::kdf::FileKey;
use serde_json::Value;

pub const CONCEPT: &str = "download";

const FILE_ID: &str = "3f1c0e7a-0000-4000-8000-000000000001";
const KEY: [u8; 32] = [9u8; 32];
const OTHER_KEY: [u8; 32] = [10u8; 32];

fn plaintext_of(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn frames_for(plaintext: &[u8], chunk_size: u64, seed: [u8; 32]) -> (Vec<Vec<u8>>, VersionCommitment) {
    let mut enc =
        ChunkEncryptor::for_push_with_file_key(FileKey::from_bytes(seed), FILE_ID, plaintext.len() as u64, chunk_size)
            .expect("encryptor");
    let frames = plaintext
        .chunks(chunk_size as usize)
        .map(|chunk| enc.push_chunk(chunk).expect("push_chunk").data)
        .collect();
    let version = enc.version_commitment(None).expect("commitment");
    enc.finish().expect("finish");
    (frames, version)
}

fn u64_of(case: &Value, key: &str) -> u64 {
    case[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

#[test]
fn download_cases_match_core() {
    let cases = super::cases(CONCEPT);
    assert_eq!(cases.len(), 17, "every named download case is present");

    let mut seen = std::collections::BTreeMap::new();
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        let kind = case["kind"].as_str().expect("case kind");
        *seen.entry(kind.to_string()).or_insert(0usize) += 1;

        match kind {
            "boundaries" => {
                let count = u64_of(case, "chunk_count") as u32;
                let got = compute_chunk_boundaries(u64_of(case, "total_len") as usize, count)
                    .unwrap_or_else(|e| panic!("{id}: {e}"));
                let want: Vec<(usize, usize)> = case["expected"]
                    .as_array()
                    .expect("expected pairs")
                    .iter()
                    .map(|pair| {
                        let pair = pair.as_array().expect("pair");
                        (
                            pair[0].as_u64().expect("start") as usize,
                            pair[1].as_u64().expect("end") as usize,
                        )
                    })
                    .collect();
                assert_eq!(got, want, "{id}");
            }
            "boundary-error" => {
                let count = u64_of(case, "chunk_count") as u32;
                let err = compute_chunk_boundaries(u64_of(case, "total_len") as usize, count)
                    .expect_err("this payload must be rejected");
                let want = case["expect"].as_str().expect("expect");
                assert!(err.to_string().contains(want), "{id}: `{err}` must contain `{want}`");
            }
            "offset" => {
                let total = u64_of(case, "total_len") as usize;
                let count = u64_of(case, "chunk_count") as u32;
                for (index, want) in case["offsets"].as_array().expect("offsets").iter().enumerate() {
                    let got = chunk_offset(total, count, index as u32).unwrap_or_else(|e| panic!("{id}: {e}"));
                    assert_eq!(got, want.as_u64().expect("offset") as usize, "{id}: offset {index}");
                }
                let beyond = u64_of(case, "out_of_range") as u32;
                assert!(
                    chunk_offset(total, count, beyond).is_err(),
                    "{id}: offset {beyond} must be out of range"
                );
            }
            "frame-size" => {
                let chunk_size = case["chunk_size"].as_u64();
                let got = checked_frame_size(
                    u64_of(case, "total_len"),
                    u64_of(case, "chunk_count") as u32,
                    chunk_size,
                )
                .unwrap_or_else(|e| panic!("{id}: {e}"));
                assert_eq!(got as u64, u64_of(case, "expected"), "{id}");
            }
            "roundtrip" | "roundtrip-chunks" | "roundtrip-error" => {
                let size = u64_of(case, "plaintext_size") as usize;
                let chunk_size = u64_of(case, "chunk_size");
                let plaintext = plaintext_of(size);
                let (mut frames, version) = frames_for(&plaintext, chunk_size, KEY);
                let count = case["chunk_count"]
                    .as_u64()
                    .map(|n| n as u32)
                    .unwrap_or(frames.len() as u32);

                if let Some(index) = case["tamper_frame"].as_u64() {
                    let index = index as usize;
                    frames[index][0] ^= 0x01;
                }
                if let Some(drop) = case["drop_frames"].as_u64() {
                    let keep = frames.len() - drop as usize;
                    frames.truncate(keep);
                }
                let key = if case["wrong_key"].as_bool().unwrap_or(false) {
                    FileKey::from_bytes(OTHER_KEY)
                } else {
                    FileKey::from_bytes(KEY)
                };

                let mut out = Vec::new();
                let result = if kind == "roundtrip-chunks" {
                    // The whole-payload splitter derives the boundaries from the
                    // declared count, so it is only exact when every frame is
                    // the same size (uniform v2 frames).
                    let payload: Vec<u8> = frames.iter().flatten().copied().collect();
                    decrypt_chunks_to(
                        &key,
                        FILE_ID,
                        ExpectedChunkFormat::Unrecorded,
                        Some(version),
                        count,
                        &payload,
                        &mut out,
                        |_, _| {},
                    )
                } else {
                    // Frames arrived whole (header-sized v2 reads), including a
                    // short last chunk.
                    let refs: Vec<&[u8]> = frames.iter().map(|frame| frame.as_slice()).collect();
                    decrypt_frames_to(
                        &key,
                        FILE_ID,
                        ExpectedChunkFormat::Unrecorded,
                        Some(version),
                        count,
                        &refs,
                        &mut out,
                        |_, _| {},
                    )
                };

                if kind != "roundtrip-error" {
                    let summary = result.unwrap_or_else(|e| panic!("{id}: {e}"));
                    assert_eq!(out, plaintext, "{id}: plaintext");
                    assert_eq!(summary.plaintext_size, size as u64, "{id}: size");
                    assert_eq!(summary.chunks_decrypted, count, "{id}: chunks");
                } else {
                    let err = result.expect_err("this stream must be rejected");
                    match case["expect"].as_str().expect("expect") {
                        "chunk_decryption" => match err {
                            DownloadFailure::ChunkDecryption { chunk, .. } => {
                                assert_eq!(chunk, u64_of(case, "chunk") as u32, "{id}: failing chunk")
                            }
                            other => panic!("{id}: expected ChunkDecryption, got {other:?}"),
                        },
                        "invalid_response" => assert!(
                            matches!(err, DownloadFailure::InvalidResponse(_)),
                            "{id}: expected InvalidResponse, got {err:?}"
                        ),
                        other => panic!("{id}: unknown expected failure `{other}`"),
                    }
                }
            }
            other => panic!("{id}: unknown case kind `{other}`"),
        }
    }

    let want = [
        ("boundaries", 3),
        ("boundary-error", 3),
        ("offset", 1),
        ("frame-size", 3),
        ("roundtrip", 2),
        ("roundtrip-chunks", 1),
        ("roundtrip-error", 4),
    ];
    for (kind, count) in want {
        assert_eq!(seen.get(kind), Some(&count), "`{kind}` case count");
    }
    for required in [
        "download_resume_offset",
        "download_tampered_frame",
        "download_aborted_stream",
    ] {
        assert!(cases.iter().any(|case| case["id"] == required), "missing `{required}`");
    }
}
