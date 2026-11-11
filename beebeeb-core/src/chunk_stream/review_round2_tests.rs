#![allow(deprecated)]
use super::*;
use crate::kdf::derive_master_key;

fn mk() -> MasterKey {
    derive_master_key("round2-password", b"round2-salt-16by").unwrap()
}

const CS: u64 = 16;

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(seed))
        .collect()
}

/// One upload (= one version) of `data` under `file_id`, v2 frames.
fn v2_upload(m: &MasterKey, file_id: &str, data: &[u8]) -> Vec<Vec<u8>> {
    let mut enc = ChunkEncryptor::for_push_with_chunk_size(m, file_id, data.len() as u64, CS)
        .unwrap()
        .with_format(ChunkFormat::V2)
        .unwrap();
    let frames: Vec<Vec<u8>> = data
        .chunks(CS as usize)
        .map(|c| enc.push_chunk(c).unwrap().data)
        .collect();
    enc.finish().unwrap();
    frames
}

/// The metadata a v2 upload writes: `name_encrypted` recording v2.
fn v2_name_encrypted(m: &MasterKey, file_id: &str) -> String {
    crate::encrypt::encrypt_name_with_chunk_format(
        m,
        file_id,
        "report.pdf",
        Some("application/pdf"),
        ExpectedChunkFormat::V2,
    )
    .unwrap()
}

/// A client reading a file: the pin comes from the decrypted metadata (the
/// FILE reader, which refuses plaintext names — round 3), then frames are
/// opened in order and the stream must finish.
fn read_file(m: &MasterKey, file_id: &str, name_encrypted: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
    let meta = crate::encrypt::decrypt_file_metadata(m, file_id, name_encrypted)?;
    let mut dec = match meta.version {
        Some(_) => ChunkDecryptor::for_current_version(m, file_id, &meta),
        None => super::self_committed_decryptor(m, file_id, meta.chunk_format, frames.first().map(Vec::as_slice)),
    };
    let mut out = Vec::new();
    for f in frames {
        out.extend_from_slice(&dec.push_frame(f)?.data);
    }
    dec.finish()?;
    Ok(out)
}

/// The reader for a file uploaded as v2 (metadata records v2).
fn read_v2(m: &MasterKey, file_id: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, CoreError> {
    read_file(m, file_id, &v2_name_encrypted(m, file_id), frames)
}

/// A `name_encrypted` JSON envelope (no AAD, same per-file key) as a wire
/// frame `nonce || ct || tag`.
fn blob_frame(name_encrypted: &str) -> Vec<u8> {
    let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(name_encrypted).unwrap();
    [blob.nonce, blob.ciphertext].concat()
}

#[test]
fn p1_1_name_blob_served_as_frame0_of_a_v2_file_is_rejected() {
    let m = mk();
    let id = "fresh-v2-file";
    let real = v2_upload(&m, id, &pattern(64, 1));
    let name_encrypted = v2_name_encrypted(&m, id);
    assert_eq!(read_file(&m, id, &name_encrypted, &real).unwrap(), pattern(64, 1));
    // The server serves the file's OWN name blob as its single frame.
    let forged = vec![blob_frame(&name_encrypted)];
    let got = read_file(&m, id, &name_encrypted, &forged);
    assert!(
        got.is_err(),
        "a v2 file must not be downgradable to v1 by serving its own name blob as frame 0 (got {} plaintext bytes)",
        got.map(|p| p.len()).unwrap_or(0)
    );
}

#[test]
fn p1_1_thumbnail_blob_served_as_frame0_of_a_v2_file_is_rejected() {
    let m = mk();
    let id = "fresh-v2-photo";
    let _real = v2_upload(&m, id, &pattern(64, 2));
    // Thumbnails are a no-AAD seal under the raw per-file key (web thumbnail.ts).
    let fk = derive_file_key(&m, id.as_bytes());
    let thumb = crate::encrypt::encrypt_chunk_raw(&fk, b"\xff\xd8\xff\xe0 fake jpeg thumbnail").unwrap();
    assert!(
        read_v2(&m, id, &[thumb]).is_err(),
        "a same-key thumbnail blob must not be accepted as a complete v1 file"
    );
}

#[test]
fn residual_unrecorded_metadata_still_detects_documented() {
    // The residual risk, pinned so a change to it is visible: a file whose
    // metadata records NO format (pre-1908 metadata, or rewritten by a
    // pre-1908 client) is read with detection, and detection cannot tell a
    // genuine one-frame v1 file from another no-AAD blob under the same
    // key. This is why every v2 upload records `chunk_format: 2` and why
    // renames must carry it forward (see encrypt_name_with_chunk_format).
    // Round 3 narrows it to LEGACY-sealed blobs (names/thumbnails sealed
    // under the raw file key: every one written before the metadata seal
    // switch); subkey-sealed ones never open as content
    // (`review_round3_tests::p1b_*`). Decision on the rest: workspace task
    // 1912.
    let m = mk();
    let id = "legacy-metadata-file";
    let legacy_name = crate::encrypt::encrypt_name_sealed(
        &m,
        id,
        "old.txt",
        None,
        ExpectedChunkFormat::Unrecorded,
        crate::encrypt::MetadataSeal::Legacy,
    )
    .unwrap();
    let meta = crate::encrypt::decrypt_name_metadata(&m, id, &legacy_name).unwrap();
    assert_eq!(meta.chunk_format, ExpectedChunkFormat::Unrecorded);
    let forged = vec![blob_frame(&legacy_name)];
    let got = read_file(&m, id, &legacy_name, &forged).unwrap();
    assert!(
        got.starts_with(b"{"),
        "detection accepts a same-key blob as v1 — the documented residual"
    );
}

#[test]
fn p1_2_middle_splice_from_another_version_is_rejected() {
    // Version A and version B of ONE file id (a replace keeps the id, so
    // both versions share the per-file key). Same sizes, every frame valid.
    let m = mk();
    let id = "versioned-doc";
    let a = v2_upload(&m, id, &pattern(96, 3)); // 6 chunks
    let b = v2_upload(&m, id, &pattern(96, 4)); // 6 chunks
    let mut spliced = b.clone();
    spliced[1] = a[1].clone();
    assert!(
        read_v2(&m, id, &spliced).is_err(),
        "version A's chunk 1 spliced into version B must be rejected"
    );
}

#[test]
fn p1_2_truncation_with_another_versions_last_frame_is_rejected() {
    // Version A has 4 chunks (A3 sealed as last); version B has 6. Serving
    // B0 B1 B2 + A3 looks like a complete 4-chunk file.
    let m = mk();
    let id = "versioned-doc-2";
    let a = v2_upload(&m, id, &pattern(64, 5)); // 4 chunks
    let b = v2_upload(&m, id, &pattern(96, 6)); // 6 chunks
    let forged = vec![b[0].clone(), b[1].clone(), b[2].clone(), a[3].clone()];
    assert!(
        read_v2(&m, id, &forged).is_err(),
        "B truncated with A's last-sealed frame must be rejected"
    );
}

#[test]
fn p1_2_tail_from_another_version_is_rejected() {
    let m = mk();
    let id = "versioned-doc-3";
    let a = v2_upload(&m, id, &pattern(64, 7));
    let b = v2_upload(&m, id, &pattern(64, 8));
    let forged = vec![b[0].clone(), b[1].clone(), a[2].clone(), a[3].clone()];
    assert!(
        read_v2(&m, id, &forged).is_err(),
        "B's head with A's tail must be rejected"
    );
}
