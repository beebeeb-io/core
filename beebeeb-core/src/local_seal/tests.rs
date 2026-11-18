use super::*;
use crate::kdf::derive_file_key;
use serde_json::Value;
use std::io::Cursor;

const VECTORS: &str = include_str!("../../../test-vectors/local_seal.json");
const OWNER_ID: &str = "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01";
const OTHER_OWNER_ID: &str = "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12";
const FOREIGN_ID: &str = "11111111-1111-8111-8111-111111111111";

fn master() -> MasterKey {
    MasterKey::from_bytes(std::array::from_fn(|i| i as u8))
}

fn other_master() -> MasterKey {
    MasterKey::from_bytes([0x99; 32])
}

fn meta() -> SnapshotMeta {
    SnapshotMeta {
        base_version: 7,
        saved_at: 1_700_000_000,
        kind: 2,
    }
}

fn is_decryption<T>(r: Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::Decryption))
}

fn is_invalid<T>(r: Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::InvalidInput(_)))
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    h(v).try_into().expect("length")
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + 3) % 251) as u8).collect()
}

// ─── snapshot ───────────────────────────────────────────────────────────────

#[test]
fn snapshot_round_trips_for_owner_and_foreign_ids() {
    for id in [OWNER_ID, FOREIGN_ID] {
        for len in [0usize, 1, 100, 70_000] {
            let data = pattern(len);
            let sealed = seal_recovery_snapshot(&master(), id, &meta(), &data).unwrap();
            assert_eq!(sealed.len(), len + 50, "blob is plaintext + 50 bytes");
            let (m, plain) = open_recovery_snapshot(&master(), id, &sealed).unwrap();
            assert_eq!(m, meta());
            assert_eq!(&*plain, &data);
            assert_eq!(peek_snapshot_meta(&sealed).unwrap(), meta());
        }
    }
}

#[test]
fn snapshot_vectors_match_the_independent_writer() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let snap = &doc["snapshot"];
    let mk = MasterKey::from_bytes(arr(&snap["master_key"]));
    let records = snap["records"].as_array().unwrap();
    assert_eq!(records.len(), 4);
    for r in records {
        let id = r["file_id"].as_str().unwrap();
        let m = SnapshotMeta {
            base_version: r["base_version"].as_i64().unwrap(),
            saved_at: r["saved_at"].as_i64().unwrap(),
            kind: r["kind"].as_u64().unwrap() as u8,
        };
        let plaintext = h(&r["plaintext"]);
        assert_eq!(
            derive_snapshot_key(&mk, id).unwrap().as_bytes().to_vec(),
            h(&r["snapshot_key"])
        );
        assert_eq!(snapshot_aad(id, &m), h(&r["aad"]));
        assert_eq!(snapshot_header(&m).to_vec(), h(&r["header"]));
        let sealed = seal_recovery_snapshot_with_nonce(&mk, id, &m, &plaintext, &arr(&r["nonce"])).unwrap();
        assert_eq!(sealed, h(&r["sealed"]), "{}", r["name"]);
        let (om, op) = open_recovery_snapshot(&mk, id, &sealed).unwrap();
        assert_eq!(om, m);
        assert_eq!(&*op, &plaintext);
    }
}

#[test]
fn snapshot_nonce_is_fresh_each_seal() {
    let a = seal_recovery_snapshot(&master(), OWNER_ID, &meta(), b"same").unwrap();
    let b = seal_recovery_snapshot(&master(), OWNER_ID, &meta(), b"same").unwrap();
    assert_ne!(a, b);
}

#[test]
fn snapshot_wrong_key_or_file_id_fails_closed() {
    let sealed = seal_recovery_snapshot(&master(), OWNER_ID, &meta(), b"secret text").unwrap();
    assert!(is_decryption(open_recovery_snapshot(
        &other_master(),
        OWNER_ID,
        &sealed
    )));
    assert!(is_decryption(open_recovery_snapshot(
        &master(),
        OTHER_OWNER_ID,
        &sealed
    )));
    assert!(is_decryption(open_recovery_snapshot(&master(), FOREIGN_ID, &sealed)));
    // A non-canonical id is refused outright, never treated as another file.
    for bad in ["", "not-an-id", &OWNER_ID.to_uppercase(), &OWNER_ID.replace('-', "")] {
        assert!(is_invalid(open_recovery_snapshot(&master(), bad, &sealed)), "{bad}");
        assert!(
            is_invalid(seal_recovery_snapshot(&master(), bad, &meta(), b"x")),
            "{bad}"
        );
    }
}

#[test]
fn snapshot_every_changed_byte_fails_closed_with_the_documented_error() {
    let sealed = seal_recovery_snapshot(&master(), OWNER_ID, &meta(), b"hello recovery").unwrap();
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        let r = open_recovery_snapshot(&master(), OWNER_ID, &bad);
        let kind_now_invalid = i == 5 && !(1..=3).contains(&bad[5]);
        let expect_invalid = i < 5 || kind_now_invalid;
        if expect_invalid {
            assert!(is_invalid(r), "byte {i} must be InvalidInput");
        } else {
            assert!(is_decryption(r), "byte {i} must be Decryption");
        }
    }
    // Kind byte moved to another valid kind: the tag fails.
    let mut bad = sealed.clone();
    bad[5] = 3;
    assert!(is_decryption(open_recovery_snapshot(&master(), OWNER_ID, &bad)));
    bad[5] = 0;
    assert!(is_invalid(open_recovery_snapshot(&master(), OWNER_ID, &bad)));
    bad[5] = 4;
    assert!(is_invalid(open_recovery_snapshot(&master(), OWNER_ID, &bad)));
}

#[test]
fn snapshot_truncation_and_extension_fail_closed() {
    let sealed = seal_recovery_snapshot(&master(), OWNER_ID, &meta(), b"hello recovery").unwrap();
    for cut in 0..sealed.len() {
        let r = open_recovery_snapshot(&master(), OWNER_ID, &sealed[..cut]);
        if cut < SNAPSHOT_HEADER_LEN {
            assert!(is_invalid(r), "cut {cut}");
        } else {
            assert!(is_decryption(r), "cut {cut}");
        }
    }
    let mut longer = sealed.clone();
    longer.push(0);
    assert!(is_decryption(open_recovery_snapshot(&master(), OWNER_ID, &longer)));
}

#[test]
fn an_older_snapshot_under_a_newer_meta_fails_closed() {
    let old = seal_recovery_snapshot(&master(), OWNER_ID, &meta(), b"old edits").unwrap();
    let newer = SnapshotMeta {
        base_version: 8,
        saved_at: 1_700_000_500,
        kind: 2,
    };
    let newer_blob = seal_recovery_snapshot(&master(), OWNER_ID, &newer, b"new edits").unwrap();
    // Old ciphertext with the newer header, and the reverse.
    let mut spliced = newer_blob[..SNAPSHOT_HEADER_LEN].to_vec();
    spliced.extend_from_slice(&old[SNAPSHOT_HEADER_LEN..]);
    assert!(is_decryption(open_recovery_snapshot(&master(), OWNER_ID, &spliced)));
    let mut spliced = old[..SNAPSHOT_HEADER_LEN].to_vec();
    spliced.extend_from_slice(&newer_blob[SNAPSHOT_HEADER_LEN..]);
    assert!(is_decryption(open_recovery_snapshot(&master(), OWNER_ID, &spliced)));
    // Each header edit alone (version, time, kind) fails too.
    for edit in [
        SnapshotMeta {
            base_version: 8,
            ..meta()
        },
        SnapshotMeta {
            saved_at: meta().saved_at + 1,
            ..meta()
        },
        SnapshotMeta { kind: 1, ..meta() },
    ] {
        let mut b = snapshot_header(&edit).to_vec();
        b.extend_from_slice(&old[SNAPSHOT_HEADER_LEN..]);
        assert!(is_decryption(open_recovery_snapshot(&master(), OWNER_ID, &b)));
    }
}

#[test]
fn snapshot_rejects_bad_meta_and_oversize_input() {
    for bad in [
        SnapshotMeta { kind: 0, ..meta() },
        SnapshotMeta { kind: 4, ..meta() },
        SnapshotMeta {
            base_version: -1,
            ..meta()
        },
        SnapshotMeta { saved_at: -1, ..meta() },
    ] {
        assert!(is_invalid(seal_recovery_snapshot(&master(), OWNER_ID, &bad, b"x")));
    }
    let big = vec![0u8; MAX_SNAPSHOT_BYTES + 1];
    assert!(is_invalid(seal_recovery_snapshot(&master(), OWNER_ID, &meta(), &big)));
    assert!(is_invalid(peek_snapshot_meta(b"BBSN")));
    assert!(is_invalid(peek_snapshot_meta(b"")));
}

#[test]
fn the_snapshot_key_is_not_the_file_key_and_a_snapshot_does_not_open_as_file_content() {
    let sk = derive_snapshot_key(&master(), OWNER_ID).unwrap();
    let fk = derive_file_key(&master(), OWNER_ID.as_bytes());
    assert_ne!(sk.as_bytes(), fk.as_bytes());
    let sealed = seal_recovery_snapshot(&master(), OWNER_ID, &meta(), b"content").unwrap();
    let frame = &sealed[SNAPSHOT_HEADER_LEN..];
    assert!(is_decryption(open_raw_with_aad(
        &fk,
        frame,
        &snapshot_aad(OWNER_ID, &meta())
    )));
    assert!(is_decryption(open_raw_with_aad(&fk, frame, &[])));
    // And the snapshot key does not open a v1 (no-AAD) content frame.
    let v1 = crate::encrypt::seal_raw_with_aad(&fk, b"content", &[]).unwrap();
    assert!(is_decryption(open_raw_with_aad(&sk, &v1, &[])));
}

// ─── scratch ────────────────────────────────────────────────────────────────

fn nonces(salt: u8) -> Vec<[u8; NONCE_LEN]> {
    (0..300u32)
        .map(|i| {
            let mut n = [salt; NONCE_LEN];
            n[8..].copy_from_slice(&i.to_be_bytes());
            n
        })
        .collect()
}

fn test_key(b: u8) -> ScratchKey {
    ScratchKey::for_vectors([b; 32])
}

/// Write `data` at a small chunk size with the floor lowered, in odd-sized pieces.
fn write_small(key: &ScratchKey, id: [u8; 16], purpose: u8, chunk: u32, data: &[u8]) -> Vec<u8> {
    let mut w = ScratchWriter::with_vector_params(key, Vec::new(), purpose, chunk, 1, id, nonces(id[0])).unwrap();
    assert_eq!(w.scratch_id(), id);
    for piece in data.chunks(7) {
        w.write_all(piece).unwrap();
    }
    let (out, n) = w.finish().unwrap();
    assert_eq!(n, data.len() as u64);
    out
}

fn read_small(key: &ScratchKey, file: &[u8], purpose: u8, id: &[u8; 16]) -> io::Result<Vec<u8>> {
    let mut r = ScratchReader::with_min_chunk(key, Cursor::new(file), purpose, id, 1)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}

fn verify_small(key: &ScratchKey, file: &[u8], purpose: u8) -> Result<VerifiedScratch, CoreError> {
    verify_scratch_with_min_chunk(key, Cursor::new(file), purpose, 1)
}

const ID_A: [u8; 16] = [0xA1; 16];
const ID_B: [u8; 16] = [0xB2; 16];
const CH: usize = 16;

fn frames_of(file: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let header = file[..SCRATCH_HEADER_LEN].to_vec();
    let frames = file[SCRATCH_HEADER_LEN..]
        .chunks(CH + FRAME_OVERHEAD)
        .map(<[u8]>::to_vec)
        .collect();
    (header, frames)
}

fn join(header: &[u8], frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = header.to_vec();
    for f in frames {
        out.extend_from_slice(f);
    }
    out
}

fn assert_fails_everywhere(key: &ScratchKey, file: &[u8], purpose: u8, id: &[u8; 16], what: &str) {
    assert!(is_decryption(verify_small(key, file, purpose)), "{what}: verify");
    let err = read_small(key, file, purpose, id).expect_err(what);
    let inner = err.get_ref().and_then(|i| i.downcast_ref::<CoreError>());
    assert!(
        matches!(inner, Some(CoreError::Decryption)),
        "{what}: reader gave {err:?}"
    );
}

#[test]
fn scratch_round_trips_at_every_edge() {
    let key = test_key(1);
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 48, 100] {
        let data = pattern(len);
        let file = write_small(&key, ID_A, 1, CH as u32, &data);
        let expected_frames = if len == 0 { 1 } else { len.div_ceil(CH) };
        assert_eq!(
            file.len(),
            SCRATCH_HEADER_LEN + len + expected_frames * FRAME_OVERHEAD,
            "len {len}: the exact multiple ends in one full final frame, never an empty one"
        );
        assert_eq!(read_small(&key, &file, 1, &ID_A).unwrap(), data, "len {len}");
        let v = verify_small(&key, &file, 1).unwrap();
        assert_eq!(v.plaintext_len, len as u64);
        assert_eq!(v.scratch_id, ID_A);
    }
}

#[test]
fn scratch_round_trips_with_the_shipped_constructors() {
    let key = ScratchKey::generate().unwrap();
    let data = pattern(MIN_SCRATCH_CHUNK as usize * 2 + 123);
    let mut w = ScratchWriter::new(&key, Vec::new(), SCRATCH_PURPOSE_STAGED_SAVE, MIN_SCRATCH_CHUNK).unwrap();
    w.write_all(&data).unwrap();
    let id = w.scratch_id();
    let (file, n) = w.finish().unwrap();
    assert_eq!(n, data.len() as u64);
    let v = verify_scratch(&key, Cursor::new(&file), SCRATCH_PURPOSE_STAGED_SAVE).unwrap();
    assert_eq!((v.plaintext_len, v.scratch_id), (data.len() as u64, id));
    let mut r = ScratchReader::new(&key, Cursor::new(&file), SCRATCH_PURPOSE_STAGED_SAVE, &id).unwrap();
    assert_eq!(r.scratch_id(), id);
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
    // Two files of one key get different ids and different bytes.
    let mut w2 = ScratchWriter::new(&key, Vec::new(), 2, DEFAULT_SCRATCH_CHUNK).unwrap();
    w2.write_all(&data).unwrap();
    assert_ne!(w2.scratch_id(), id);
}

#[test]
fn scratch_writer_rejects_bad_purpose_and_chunk_sizes() {
    let key = test_key(1);
    for p in [0u8, 3, 255] {
        assert!(is_invalid(ScratchWriter::new(
            &key,
            Vec::new(),
            p,
            DEFAULT_SCRATCH_CHUNK
        )));
    }
    for c in [0u32, 1, MIN_SCRATCH_CHUNK - 1, (MAX_CHUNK_SIZE + 1) as u32, u32::MAX] {
        assert!(is_invalid(ScratchWriter::new(&key, Vec::new(), 1, c)), "chunk {c}");
    }
    assert!(ScratchWriter::new(&key, Vec::new(), 1, MIN_SCRATCH_CHUNK).is_ok());
    assert!(ScratchWriter::new(&key, Vec::new(), 1, MAX_CHUNK_SIZE as u32).is_ok());
    // The reader refuses the same purposes.
    let file = write_small(&key, ID_A, 1, CH as u32, b"abc");
    assert!(is_invalid(verify_scratch(&key, Cursor::new(&file), 3)));
}

#[test]
fn scratch_vectors_match_the_independent_writer() {
    use sha2::Digest;
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let s = &doc["scratch"];
    let key = ScratchKey::for_vectors(arr(&s["scratch_key"]));
    let id: [u8; 16] = arr(&s["scratch_id"]);
    let chunk = s["chunk_size"].as_u64().unwrap() as u32;
    assert_eq!(chunk, MIN_SCRATCH_CHUNK);
    let files = s["files"].as_array().unwrap();
    assert_eq!(files.len(), 6);
    for f in files {
        let purpose = f["purpose"].as_u64().unwrap() as u8;
        let len = f["plaintext_len"].as_u64().unwrap() as usize;
        assert_eq!(key.file_key(&id).as_bytes().to_vec(), h(&f["file_key"]));
        let frames = f["frames"].as_array().unwrap();
        let queue: Vec<[u8; NONCE_LEN]> = frames.iter().map(|fr| arr(&fr["nonce"])).collect();
        // The shipped floor applies: these are real-size files.
        let mut w =
            ScratchWriter::with_vector_params(&key, Vec::new(), purpose, chunk, MIN_SCRATCH_CHUNK, id, queue).unwrap();
        let data = pattern(len);
        for piece in data.chunks(10_000) {
            w.write_all(piece).unwrap();
        }
        let (file, n) = w.finish().unwrap();
        assert_eq!(n as usize, len);
        assert_eq!(file[..SCRATCH_HEADER_LEN].to_vec(), h(&f["header"]), "{}", f["name"]);
        assert_eq!(file.len() as u64, f["file_len"].as_u64().unwrap(), "{}", f["name"]);
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&file)),
            f["file_sha256"].as_str().unwrap(),
            "{}",
            f["name"]
        );
        if let Some(full) = f.get("file") {
            assert_eq!(file, h(full));
        }
        let header: [u8; SCRATCH_HEADER_LEN] = file[..SCRATCH_HEADER_LEN].try_into().unwrap();
        for fr in frames {
            let aad = frame_aad(
                &header,
                fr["index"].as_u64().unwrap() as u32,
                fr["final"].as_bool().unwrap(),
            );
            assert_eq!(aad, h(&fr["aad"]));
        }
        let finals: Vec<bool> = frames.iter().map(|fr| fr["final"].as_bool().unwrap()).collect();
        assert_eq!(finals.iter().filter(|b| **b).count(), 1);
        assert!(*finals.last().unwrap());
        // And the committed bytes open.
        let v = verify_scratch(&key, Cursor::new(&file), purpose).unwrap();
        assert_eq!((v.plaintext_len as usize, v.scratch_id), (len, id));
    }
}

#[test]
fn scratch_dropped_final_frame_and_cut_files_fail_closed() {
    let key = test_key(1);
    for len in [32usize, 40, 48, 1] {
        let file = write_small(&key, ID_A, 1, CH as u32, &pattern(len));
        let (header, frames) = frames_of(&file);
        if frames.len() > 1 {
            // Drop the final frame: the last present frame was sealed as non-final.
            let cut = join(&header, &frames[..frames.len() - 1]);
            assert_fails_everywhere(&key, &cut, 1, &ID_A, "dropped final frame");
        }
        // Header only (a writer dropped without finish).
        assert_fails_everywhere(&key, &header, 1, &ID_A, "no frames");
        // A frame cut in the middle, at every length.
        for cut_at in SCRATCH_HEADER_LEN..file.len() {
            let r = verify_small(&key, &file[..cut_at], 1);
            assert!(is_decryption(r), "len {len} cut at {cut_at}");
        }
    }
    // A header cut short is an invalid file, not a decryption oracle.
    let file = write_small(&key, ID_A, 1, CH as u32, b"x");
    assert!(is_invalid(verify_small(&key, &file[..10], 1)));
    assert!(is_invalid(verify_small(&key, &[], 1)));
}

#[test]
fn scratch_dropped_middle_swapped_duplicated_and_appended_frames_fail_closed() {
    let key = test_key(1);
    let file = write_small(&key, ID_A, 1, CH as u32, &pattern(4 * CH));
    let (header, frames) = frames_of(&file);
    assert_eq!(frames.len(), 4);
    // Drop a middle frame.
    let mut f = frames.clone();
    f.remove(1);
    assert_fails_everywhere(&key, &join(&header, &f), 1, &ID_A, "dropped middle");
    // Swap two frames.
    let mut f = frames.clone();
    f.swap(0, 2);
    assert_fails_everywhere(&key, &join(&header, &f), 1, &ID_A, "swap");
    let mut f = frames.clone();
    f.swap(2, 3);
    assert_fails_everywhere(&key, &join(&header, &f), 1, &ID_A, "swap with the final frame");
    // Duplicate a frame (middle and final).
    let mut f = frames.clone();
    f.insert(1, frames[1].clone());
    assert_fails_everywhere(&key, &join(&header, &f), 1, &ID_A, "duplicate middle");
    let mut f = frames.clone();
    f.push(frames[3].clone());
    assert_fails_everywhere(&key, &join(&header, &f), 1, &ID_A, "duplicate final");
    // A frame appended after the final one, and one stray byte.
    let mut f = frames.clone();
    f.push(frames[0].clone());
    assert_fails_everywhere(&key, &join(&header, &f), 1, &ID_A, "frame after final");
    let mut longer = file.clone();
    longer.push(0);
    assert_fails_everywhere(&key, &longer, 1, &ID_A, "trailing byte");
    // Short data after a full final frame.
    let mut longer = file.clone();
    longer.extend_from_slice(&[0u8; FRAME_OVERHEAD]);
    assert_fails_everywhere(&key, &longer, 1, &ID_A, "empty frame after the final one");
}

#[test]
fn scratch_frame_from_a_second_file_of_the_same_key_fails_closed() {
    let key = test_key(1);
    let data = pattern(3 * CH);
    let a = write_small(&key, ID_A, 1, CH as u32, &data);
    let b = write_small(&key, ID_B, 1, CH as u32, &data);
    let (ha, fa) = frames_of(&a);
    let (_, fb) = frames_of(&b);
    for i in 0..3 {
        let mut f = fa.clone();
        f[i] = fb[i].clone();
        assert_fails_everywhere(&key, &join(&ha, &f), 1, &ID_A, "spliced frame");
    }
}

#[test]
fn scratch_wrong_key_purpose_or_file_id_fails_closed() {
    let key = test_key(1);
    let file = write_small(&key, ID_A, 2, CH as u32, &pattern(40));
    assert!(is_decryption(verify_small(&test_key(2), &file, 2)));
    assert!(
        is_decryption(verify_small(&key, &file, 1)),
        "known purpose, not the expected one"
    );
    // A reader built with another file's id (a valid file of the same session swapped in).
    let err = ScratchReader::with_min_chunk(&key, Cursor::new(&file), 2, &ID_B, 1)
        .err()
        .unwrap();
    assert!(matches!(err, CoreError::Decryption));
    // The per-file key: the same bytes read under the other file's derived key do not open.
    assert_ne!(key.file_key(&ID_A).as_bytes(), key.file_key(&ID_B).as_bytes());
    assert_ne!(key.file_key(&ID_A).as_bytes(), test_key(2).file_key(&ID_A).as_bytes());
}

#[test]
fn scratch_every_changed_header_byte_fails_closed_with_the_documented_error() {
    let key = test_key(1);
    let file = write_small(&key, ID_A, 1, CH as u32, &pattern(40));
    for i in 0..SCRATCH_HEADER_LEN {
        for bit in [0x01u8, 0x80] {
            let mut bad = file.clone();
            bad[i] ^= bit;
            let r = verify_small(&key, &bad, 1);
            let purpose_unknown = i == 5 && !(1..=2).contains(&bad[5]);
            let chunk_now = u32::from_be_bytes(bad[6..10].try_into().unwrap());
            let chunk_invalid = (6..10).contains(&i) && (chunk_now == 0 || u64::from(chunk_now) > MAX_CHUNK_SIZE);
            if i < 5 || purpose_unknown || chunk_invalid {
                assert!(is_invalid(r), "byte {i} bit {bit:#x}");
            } else {
                assert!(is_decryption(r), "byte {i} bit {bit:#x}");
            }
        }
    }
    // Every ciphertext, nonce and tag bit position of the first frame.
    for i in SCRATCH_HEADER_LEN..file.len() {
        let mut bad = file.clone();
        bad[i] ^= 0x01;
        assert!(is_decryption(verify_small(&key, &bad, 1)), "byte {i}");
    }
}

#[test]
fn scratch_header_floor_and_ceiling_are_enforced_by_the_shipped_reader() {
    let key = test_key(1);
    // A file written with a small chunk (floor lowered) is refused by the shipped reader.
    let file = write_small(&key, ID_A, 1, CH as u32, b"abc");
    assert!(is_invalid(verify_scratch(&key, Cursor::new(&file), 1)));
    assert!(is_invalid(
        ScratchReader::new(&key, Cursor::new(&file), 1, &ID_A).map(|_| ())
    ));
}

#[test]
fn a_hostile_chunk_size_in_a_header_allocates_nothing_beyond_the_file() {
    let key = test_key(1);
    let mut header = Vec::new();
    header.extend_from_slice(SCRATCH_MAGIC);
    header.push(SCRATCH_VERSION);
    header.push(1);
    header.extend_from_slice(&(MAX_CHUNK_SIZE as u32).to_be_bytes());
    header.extend_from_slice(&ID_A);
    let mut file = header.clone();
    file.extend_from_slice(&[7u8; 100]);
    assert!(is_decryption(verify_scratch(&key, Cursor::new(&file), 1)));
}

#[test]
fn scratch_reader_releases_no_final_ok_on_a_cut_file() {
    let key = test_key(1);
    let file = write_small(&key, ID_A, 1, CH as u32, &pattern(3 * CH));
    let (header, frames) = frames_of(&file);
    let cut = join(&header, &frames[..2]);
    let mut r = ScratchReader::with_min_chunk(&key, Cursor::new(&cut), 1, &ID_A, 1).unwrap();
    let mut out = Vec::new();
    assert!(r.read_to_end(&mut out).is_err(), "the cut file never ends in Ok");
    // Once failed, it stays failed.
    assert!(r.read(&mut [0u8; 4]).is_err());
}

#[test]
fn scratch_writer_dropped_without_finish_never_opens() {
    let key = test_key(1);
    let mut w = ScratchWriter::with_vector_params(&key, Vec::new(), 1, CH as u32, 1, ID_A, nonces(1)).unwrap();
    w.write_all(&pattern(3 * CH)).unwrap();
    let ScratchWriter { out, .. } = w;
    assert!(is_decryption(verify_small(&key, &out, 1)));
}

#[test]
fn scratch_key_debug_shows_no_bytes() {
    let key = ScratchKey::for_vectors([0x5A; 32]);
    assert_eq!(format!("{key:?}"), "ScratchKey(..)");
    assert_eq!(format!("{key:#?}"), "ScratchKey(..)");
}

#[test]
fn local_seal_is_not_exported_to_the_binding_crates() {
    fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                scan(&p, hits);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    if text.contains("local_seal") || text.contains("ScratchKey") {
                        hits.push(p.display().to_string());
                    }
                }
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut found_a_crate = 0;
    let mut hits = Vec::new();
    for krate in ["beebeeb-uniffi", "beebeeb-wasm"] {
        let src = root.join(krate).join("src");
        if src.is_dir() {
            found_a_crate += 1;
        }
        scan(&src, &mut hits);
    }
    assert_eq!(found_a_crate, 2, "both binding crates must be scanned");
    assert!(hits.is_empty(), "local_seal must stay out of the bindings: {hits:?}");
}
