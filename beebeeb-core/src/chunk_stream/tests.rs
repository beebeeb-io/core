#![allow(deprecated)]
use super::*;
use crate::encrypt::decrypt_chunk_raw;
use crate::kdf::derive_master_key;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const MIB: usize = 1024 * 1024;

fn mk() -> MasterKey {
    derive_master_key("test-password", b"test-salt-16bytes").unwrap()
}

/// Deterministic, non-trivial test data.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Encrypt every chunk of `data` via the pull path and return the frames.
fn encrypt_all(
    master: &MasterKey,
    file_id: &str,
    data: &[u8],
    profile: ChunkProfile,
) -> (Vec<EncryptedChunk>, ChunkEncryptorSummary) {
    let mut enc =
        ChunkEncryptor::from_reader(master, file_id, data.len() as u64, profile, Cursor::new(data.to_vec())).unwrap();
    let mut frames = Vec::new();
    while let Some(c) = enc.next_chunk().unwrap() {
        frames.push(c);
    }
    let summary = enc.finish().unwrap();
    (frames, summary)
}

/// Decrypt a sequence of frames via the push decryptor and concatenate.
fn decrypt_frames(master: &MasterKey, file_id: &str, frames: &[EncryptedChunk]) -> Vec<u8> {
    let mut dec = ChunkDecryptor::for_push(master, file_id, exp());
    let mut out = Vec::new();
    for f in frames {
        out.extend_from_slice(&dec.push_frame(&f.data).unwrap().data);
    }
    out
}

/// What the metadata records for a file written by the default encryptor.
fn exp() -> ExpectedChunkFormat {
    ExpectedChunkFormat::recorded_for(WRITE_FORMAT)
}

fn assert_send<T: Send>() {}

#[test]
fn types_are_send() {
    // Compile-time guard: both primitives must be movable into a blocking
    // thread (the CLI's spawn_blocking).
    assert_send::<ChunkEncryptor>();
    assert_send::<ChunkDecryptor>();
}

#[test]
fn roundtrip_single_chunk_equality_not_byte_equality() {
    let m = mk();
    let data = pattern(4096);
    let (frames, summary) = encrypt_all(&m, "f1", &data, ChunkProfile::Desktop);
    assert_eq!(frames.len(), 1);
    assert_eq!(summary.chunk_count, 1);

    // Ciphertext frame must not equal the plaintext.
    assert_ne!(frames[0].data, data);
    // ...but it must decrypt back to it.
    let recovered = decrypt_frames(&m, "f1", &frames);
    assert_eq!(recovered, data);

    // Re-encrypting the same bytes yields different ciphertext (random nonce)
    // but the same plaintext on decrypt.
    let (frames2, _) = encrypt_all(&m, "f1", &data, ChunkProfile::Desktop);
    assert_ne!(frames2[0].data, frames[0].data);
    assert_eq!(decrypt_frames(&m, "f1", &frames2), data);
}

#[test]
fn empty_file_one_chunk_total_28_decrypts_empty() {
    let m = mk();
    let (frames, summary) = encrypt_all(&m, "empty", &[], ChunkProfile::Desktop);
    assert_eq!(frames.len(), 1, "empty file still produces one chunk");
    assert_eq!(frames[0].data.len(), NONCE_LEN + TAG_LEN); // 28
    assert_eq!(summary.chunk_count, 1);
    assert_eq!(summary.total_plaintext, 0);
    assert_eq!(summary.total_ciphertext, 28);

    let recovered = decrypt_frames(&m, "empty", &frames);
    assert!(recovered.is_empty());
}

#[test]
fn expected_total_ciphertext_for_empty_is_28() {
    let m = mk();
    let enc = ChunkEncryptor::from_reader(&m, "e", 0, ChunkProfile::Desktop, Cursor::new(Vec::new())).unwrap();
    assert_eq!(enc.expected_total_ciphertext(), 28);
}

#[test]
fn sub_chunk_roundtrip() {
    let m = mk();
    let data = pattern(100); // far below the 4 MiB minimum chunk
    let (frames, summary) = encrypt_all(&m, "small", &data, ChunkProfile::Desktop);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].data.len(), 100 + 28);
    assert_eq!(summary.total_plaintext, 100);
    assert_eq!(decrypt_frames(&m, "small", &frames), data);
}

#[test]
fn multi_chunk_roundtrip() {
    let m = mk();
    // 9 MiB with Desktop (<=64 MiB -> 4 MiB chunk) => 3 chunks: 4 + 4 + 1.
    let data = pattern(9 * MIB);
    let (frames, summary) = encrypt_all(&m, "multi", &data, ChunkProfile::Desktop);
    assert_eq!(frames.len(), 3);
    assert_eq!(summary.chunk_count, 3);
    assert_eq!(frames[0].data.len(), 4 * MIB + 28);
    assert_eq!(frames[1].data.len(), 4 * MIB + 28);
    assert_eq!(frames[2].data.len(), MIB + 28);
    assert_eq!(summary.total_plaintext, 9 * MIB as u64);
    assert_eq!(decrypt_frames(&m, "multi", &frames), data);
}

#[test]
fn exact_multiple_has_no_trailing_empty_chunk() {
    let m = mk();
    // 8 MiB == exactly two 4 MiB chunks; must NOT emit a third empty chunk.
    let data = pattern(8 * MIB);
    let (frames, summary) = encrypt_all(&m, "exact", &data, ChunkProfile::Desktop);
    assert_eq!(frames.len(), 2);
    assert_eq!(summary.chunk_count, 2);
    assert_eq!(frames[1].data.len(), 4 * MIB + 28);
    assert_eq!(decrypt_frames(&m, "exact", &frames), data);
}

#[test]
fn wrong_key_decrypt_errors_no_panic() {
    let m = mk();
    let data = pattern(2048);
    let (frames, _) = encrypt_all(&m, "secret", &data, ChunkProfile::Desktop);

    // Wrong master key.
    let wrong = derive_master_key("different-password", b"different-salt-16").unwrap();
    let mut dec = ChunkDecryptor::for_push(&wrong, "secret", exp());
    assert!(matches!(dec.push_frame(&frames[0].data), Err(CoreError::Decryption)));

    // Right master key, wrong file_id.
    let mut dec2 = ChunkDecryptor::for_push(&m, "other-file", exp());
    assert!(matches!(dec2.push_frame(&frames[0].data), Err(CoreError::Decryption)));
}

#[test]
fn push_form_equals_pull_form() {
    let m = mk();
    let data = pattern(9 * MIB);

    // Pull
    let (pull_frames, _) = encrypt_all(&m, "pp", &data, ChunkProfile::Desktop);

    // Push, caller slicing by the plan's chunk size.
    let mut push = ChunkEncryptor::for_push(&m, "pp", data.len() as u64, ChunkProfile::Desktop).unwrap();
    let chunk_size = push.chunk_plan().chunk_size_bytes as usize;
    let mut push_frames = Vec::new();
    for slice in data.chunks(chunk_size) {
        push_frames.push(push.push_chunk(slice).unwrap());
    }
    let push_summary = push.finish().unwrap();

    // Same count and same per-chunk sizes (deterministic: pt + 28).
    assert_eq!(pull_frames.len(), push_frames.len());
    for (a, b) in pull_frames.iter().zip(&push_frames) {
        assert_eq!(a.index, b.index);
        assert_eq!(a.data.len(), b.data.len());
    }
    // Both decrypt to the original plaintext.
    assert_eq!(decrypt_frames(&m, "pp", &pull_frames), data);
    assert_eq!(decrypt_frames(&m, "pp", &push_frames), data);
    assert_eq!(push_summary.chunk_count, 3);
    assert_eq!(push_summary.total_plaintext, 9 * MIB as u64);
}

#[test]
fn finish_ok_on_complete() {
    let m = mk();
    let data = pattern(5 * MIB);
    let mut enc = ChunkEncryptor::from_reader(
        &m,
        "ok",
        data.len() as u64,
        ChunkProfile::Desktop,
        Cursor::new(data.clone()),
    )
    .unwrap();
    while enc.next_chunk().unwrap().is_some() {}
    let summary = enc.finish().unwrap();
    assert_eq!(summary.total_plaintext, 5 * MIB as u64);
    assert_eq!(
        summary.total_ciphertext,
        5 * MIB as u64 + 28 * summary.chunk_count as u64
    );
}

#[test]
fn finish_err_on_short_read_shrink() {
    let m = mk();
    // Declare 9 MiB (3 chunks) but the reader only has 4 MiB of data: the
    // file shrank between stat and read. finish() must reject it.
    let declared = 9 * MIB as u64;
    let actual = pattern(4 * MIB);
    let mut enc =
        ChunkEncryptor::from_reader(&m, "shrink", declared, ChunkProfile::Desktop, Cursor::new(actual)).unwrap();
    // Pull all planned chunks (later ones come back empty).
    let mut emitted = 0;
    while enc.next_chunk().unwrap().is_some() {
        emitted += 1;
    }
    assert_eq!(emitted, 3);
    let err = enc.finish().unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn finish_err_when_caller_stops_early() {
    let m = mk();
    let data = pattern(9 * MIB);
    let mut enc =
        ChunkEncryptor::from_reader(&m, "early", data.len() as u64, ChunkProfile::Desktop, Cursor::new(data)).unwrap();
    // Only pull the first of three planned chunks.
    let _ = enc.next_chunk().unwrap().unwrap();
    let err = enc.finish().unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn grown_source_is_not_detected_documented_limitation() {
    // DOCUMENTED LIMITATION: when file_size is an exact multiple of the
    // chunk size, a source that grew after stat is NOT detected — the
    // plan-driven loop stops at the original chunk_count and the extra
    // bytes are silently ignored. finish() returns Ok.
    let m = mk();
    let declared = 8 * MIB as u64; // exactly two 4 MiB chunks
    let bigger = pattern(10 * MIB); // grew by 2 MiB after stat
    let mut enc =
        ChunkEncryptor::from_reader(&m, "grow", declared, ChunkProfile::Desktop, Cursor::new(bigger.clone())).unwrap();
    let mut frames = Vec::new();
    while let Some(c) = enc.next_chunk().unwrap() {
        frames.push(c);
    }
    // Only the two declared chunks were emitted; the growth was ignored.
    assert_eq!(frames.len(), 2);
    let summary = enc
        .finish()
        .expect("growth on an exact-multiple file is NOT caught by finish()");
    assert_eq!(summary.total_plaintext, 8 * MIB as u64);

    // The recovered plaintext is the first 8 MiB only — the appended 2 MiB
    // is lost. This is the residual edge documented on finish().
    let recovered = decrypt_frames(&m, "grow", &frames);
    assert_eq!(recovered, bigger[..8 * MIB]);
}

#[test]
fn u32_chunk_count_guard_rejects() {
    let m = mk();
    // u64::MAX / 1-byte chunks overflows u32 chunk_count.
    let err = ChunkEncryptor::for_push_with_chunk_size(&m, "huge", u64::MAX, 1).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));

    // Same overflow via the profile ladder (256 MiB chunks at u64::MAX size).
    let err2 = ChunkEncryptor::for_push(&m, "huge", u64::MAX, ChunkProfile::Desktop).unwrap_err();
    assert!(matches!(err2, CoreError::InvalidInput(_)));
}

#[test]
fn for_push_with_chunk_size_rejects_above_max() {
    // R3: a hostile/misconfigured server returning an oversized chunk size
    // must be rejected before it can drive a multi-GB allocation.
    let m = mk();
    let too_big = MAX_CHUNK_SIZE + 1;
    let err = ChunkEncryptor::for_push_with_chunk_size(&m, "oom", 10 * MIB as u64, too_big).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));

    // The exact cap is accepted (boundary is inclusive).
    let ok = ChunkEncryptor::for_push_with_chunk_size(&m, "edge", 10 * MIB as u64, MAX_CHUNK_SIZE);
    assert!(ok.is_ok());
}

#[test]
fn from_reader_with_chunk_size_rejects_above_max() {
    // R3: same cap on the pull-form override constructor.
    let m = mk();
    let too_big = MAX_CHUNK_SIZE + 1;
    let err =
        ChunkEncryptor::from_reader_with_chunk_size(&m, "oom2", 10 * MIB as u64, too_big, Cursor::new(Vec::new()))
            .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn for_push_with_chunk_size_honors_override() {
    let m = mk();
    let data = pattern(40);
    let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, "ovr", 40, 16).unwrap();
    let plan = enc.chunk_plan();
    assert_eq!(plan.chunk_size_bytes, 16);
    assert_eq!(plan.chunk_count, 3); // 16 + 16 + 8

    let mut frames = Vec::new();
    for slice in data.chunks(16) {
        frames.push(enc.push_chunk(slice).unwrap());
    }
    assert_eq!(frames[0].data.len(), 16 + 28);
    assert_eq!(frames[1].data.len(), 16 + 28);
    assert_eq!(frames[2].data.len(), 8 + 28);

    let summary = enc.finish().unwrap();
    assert_eq!(summary.chunk_count, 3);
    assert_eq!(summary.total_plaintext, 40);
    assert_eq!(summary.chunk_size_bytes, 16);

    assert_eq!(decrypt_frames(&m, "ovr", &frames), data);
}

#[test]
fn from_reader_with_chunk_size_honors_override() {
    let m = mk();
    let data = pattern(40);
    let mut enc = ChunkEncryptor::from_reader_with_chunk_size(&m, "rdrovr", 40, 16, Cursor::new(data.clone())).unwrap();
    assert_eq!(enc.chunk_plan().chunk_size_bytes, 16);
    assert_eq!(enc.chunk_plan().chunk_count, 3); // 16 + 16 + 8
    let mut frames = Vec::new();
    while let Some(c) = enc.next_chunk().unwrap() {
        frames.push(c);
    }
    assert_eq!(frames[0].data.len(), 16 + 28);
    assert_eq!(frames[2].data.len(), 8 + 28);
    assert_eq!(decrypt_frames(&m, "rdrovr", &frames), data);
}

#[test]
fn from_reader_with_chunk_size_rejects_zero() {
    let m = mk();
    let err = ChunkEncryptor::from_reader_with_chunk_size(&m, "z2", 40, 0, Cursor::new(Vec::new())).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn push_chunk_beyond_plan_errors() {
    let m = mk();
    let mut enc = ChunkEncryptor::for_push_with_chunk_size(&m, "cap", 16, 16).unwrap();
    assert_eq!(enc.chunk_plan().chunk_count, 1);
    let _ = enc.push_chunk(&pattern(16)).unwrap();
    let err = enc.push_chunk(&[0u8]).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn decryptor_pull_roundtrip() {
    let m = mk();
    let data = pattern(9 * MIB);
    let (frames, _) = encrypt_all(&m, "decpull", &data, ChunkProfile::Desktop);

    // Concatenate frames into a contiguous wire body, then stream-decrypt.
    let mut body = Vec::new();
    for f in &frames {
        body.extend_from_slice(&f.data);
    }
    let chunk_size = ChunkEncryptor::from_reader(
        &m,
        "decpull",
        data.len() as u64,
        ChunkProfile::Desktop,
        Cursor::new(Vec::new()),
    )
    .unwrap()
    .chunk_plan()
    .chunk_size_bytes;

    let mut dec = ChunkDecryptor::from_reader(&m, "decpull", exp(), chunk_size, Cursor::new(body)).unwrap();
    let mut out = Vec::new();
    let mut idx = 0u32;
    while let Some(c) = dec.next_chunk().unwrap() {
        assert_eq!(c.index, idx);
        idx += 1;
        out.extend_from_slice(&c.data);
    }
    assert_eq!(idx, 3);
    assert_eq!(out, data);
}

#[test]
fn decryptor_chunk_size_zero_errors() {
    let m = mk();
    let err = ChunkDecryptor::from_reader(&m, "z", exp(), 0, Cursor::new(Vec::new())).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn decryptor_rejects_truncated_frame() {
    let m = mk();
    let mut dec = ChunkDecryptor::for_push(&m, "trunc", exp());
    // Fewer than nonce(12) + tag(16) bytes — cannot be a valid frame.
    let err = dec.push_frame(&[0u8; 20]).unwrap_err();
    assert!(matches!(err, CoreError::Decryption));
}

/// A reader that synthesizes up to `remaining` bytes WITHOUT ever allocating
/// them, recording the largest single read it is asked to perform.
struct CountingReader {
    remaining: u64,
    max_read: Arc<AtomicUsize>,
    total_served: Arc<AtomicU64>,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.max_read.fetch_max(buf.len(), Ordering::SeqCst);
        if self.remaining == 0 {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.remaining) as usize;
        for b in &mut buf[..n] {
            *b = 0xAB;
        }
        self.remaining -= n as u64;
        self.total_served.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }
}

#[test]
fn memory_ceiling_8gib_no_full_allocation() {
    let m = mk();
    let max_read = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicU64::new(0));
    let eight_gib: u64 = 8 * 1024 * 1024 * 1024;

    let reader = CountingReader {
        remaining: eight_gib,
        max_read: max_read.clone(),
        total_served: total.clone(),
    };
    // Explicit 16 MiB chunk so this memory-mechanics test is independent of
    // the chunk-size ladder (the ladder is covered by beebeeb-types' vector
    // test). The point here is that the read buffer is sized to the chunk,
    // not to the 8 GiB file.
    let mut enc = ChunkEncryptor::from_reader_with_chunk_size(&m, "huge", eight_gib, 16 * MIB as u64, reader).unwrap();

    let plan = enc.chunk_plan();
    assert_eq!(plan.chunk_size_bytes, 16 * MIB as u64);
    assert_eq!(plan.chunk_count, eight_gib / (16 * MIB as u64)); // 512
    assert_eq!(enc.expected_total_ciphertext(), eight_gib + 28 * plan.chunk_count);

    // The read buffer is sized to the chunk, NOT the 8 GiB file.
    let cap_before = enc.buf.capacity();
    assert_eq!(cap_before, 16 * MIB);

    // Pull a handful of chunks — enough to prove the buffer is reused and
    // never grows, and that no read ever exceeds the chunk size.
    for _ in 0..8 {
        let c = enc.next_chunk().unwrap().unwrap();
        assert_eq!(c.data.len(), 16 * MIB + 28);
        assert_eq!(enc.buf.capacity(), cap_before, "read buffer capacity must not grow");
        assert!(
            max_read.load(Ordering::SeqCst) <= 16 * MIB,
            "no single read may exceed the chunk size"
        );
    }

    // We consumed only 8 * 16 MiB = 128 MiB of the 8 GiB stream.
    assert_eq!(total.load(Ordering::SeqCst), 8 * (16 * MIB as u64));
}

#[test]
fn default_v2_output_does_not_open_via_legacy_decrypt_chunk_raw() {
    // Production output must not open with the legacy no-AAD primitive.
    // The frame layout and sizes are unchanged; the shared decryptor reads
    // both formats.
    let m = mk();
    let data = pattern(9 * MIB);
    let (frames, _) = encrypt_all(&m, "legacy", &data, ChunkProfile::Desktop);
    let file_key = derive_file_key(&m, b"legacy");
    for f in &frames {
        assert_eq!(
            decrypt_chunk_raw(&file_key, &f.data).is_ok(),
            WRITE_FORMAT == ChunkFormat::V1Legacy
        );
        assert_eq!(f.data.len(), frames_len_for(&data, f.index));
    }
    assert_eq!(decrypt_frames(&m, "legacy", &frames), data);
}

#[test]
fn v2_output_does_not_open_via_legacy_decrypt_chunk_raw() {
    // A v2 frame never opens with the legacy no-AAD open (it is sealed
    // under the chunk subkey, with AAD), so the binding cannot be stripped.
    let m = mk();
    let data = pattern(9 * MIB);
    let mut enc = ChunkEncryptor::from_reader(
        &m,
        "legacy-v2",
        data.len() as u64,
        ChunkProfile::Desktop,
        Cursor::new(data.clone()),
    )
    .unwrap()
    .with_format(ChunkFormat::V2)
    .unwrap();
    let file_key = derive_file_key(&m, b"legacy-v2");
    let mut dec = ChunkDecryptor::for_push(&m, "legacy-v2", ExpectedChunkFormat::V2);
    let mut out = Vec::new();
    while let Some(f) = enc.next_chunk().unwrap() {
        assert!(decrypt_chunk_raw(&file_key, &f.data).is_err());
        assert_eq!(f.data.len(), frames_len_for(&data, f.index));
        out.extend_from_slice(&dec.push_frame(&f.data).unwrap().data);
    }
    enc.finish().unwrap();
    dec.finish().unwrap();
    assert_eq!(out, data);
}

/// Frame length is plaintext + 28 in both formats (layout unchanged).
fn frames_len_for(data: &[u8], index: u32) -> usize {
    let start = index as usize * 4 * MIB;
    (data.len() - start).min(4 * MIB) + NONCE_LEN + TAG_LEN
}

#[test]
fn production_write_format_is_v2() {
    assert_eq!(WRITE_FORMAT, ChunkFormat::V2);
    let m = mk();
    let enc = ChunkEncryptor::for_push(&m, "fmt", 10, ChunkProfile::Web).unwrap();
    assert_eq!(enc.format(), ChunkFormat::V2);
    assert_eq!(ExpectedChunkFormat::recorded_for(enc.format()), ExpectedChunkFormat::V2);
}
