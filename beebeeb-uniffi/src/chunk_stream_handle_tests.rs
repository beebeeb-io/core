use super::*;

fn mk_handle() -> Arc<MasterKeyHandle> {
    // Any 32 bytes is a valid master key for a roundtrip test.
    MasterKeyHandle::from_keychain_bytes(vec![7u8; 32]).unwrap()
}

/// What the metadata records for a file written by the default encryptor.
fn default_expected() -> u8 {
    ExpectedChunkFormat::recorded_for(beebeeb_core::chunk_stream::WRITE_FORMAT).as_u8()
}

/// A metadata record with this format pin and no version commitment.
fn pin(chunk_format: u8) -> NameMetadataDto {
    NameMetadataDto {
        name: "file".into(),
        mime_type: None,
        chunk_format,
        version_id: None,
        version_counter: None,
    }
}

#[test]
fn push_roundtrip_via_handles() {
    let mk = mk_handle();
    let file_id = "ffi-push-roundtrip".to_string();
    let data = b"hello via the uniffi chunk-stream handle".to_vec();

    let enc = ChunkEncryptorHandle::for_push(&mk, file_id.clone(), data.len() as u64, "mobile".into()).unwrap();
    assert_eq!(enc.chunk_plan().unwrap().chunk_count, 1);
    assert_eq!(enc.chunk_format().unwrap(), 2, "production output is v2");
    let frame = enc.push_chunk(data.clone()).unwrap();
    assert_eq!(frame.index, 0);
    assert_ne!(frame.data, data); // ciphertext != plaintext
    let summary = enc.finish().unwrap();
    assert_eq!(summary.chunk_count, 1);
    assert_eq!(summary.total_plaintext, data.len() as u64);

    let dec = ChunkDecryptorHandle::for_push(&mk, file_id, pin(default_expected())).unwrap();
    let out = dec.push_frame(frame.data).unwrap();
    assert_eq!(out.index, 0);
    assert_eq!(out.data, data);
    assert_eq!(dec.chunk_format().unwrap(), Some(2));
    let s = dec.finish().unwrap();
    assert_eq!((s.chunk_count, s.format), (1, 2));
}

/// Task 1908: two equal-size v2 chunks (as a client writes them after the
/// gated v2 switch). Core-written via the dev-only `test-support` feature.
#[allow(deprecated)]
fn two_v2_frames(mk: &MasterKeyHandle, file_id: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
    // 5 MiB on the "mobile" ladder (4 MiB chunks) => 2 chunks.
    let data: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 253) as u8).collect();
    let frames = mk
        .with_key(|m| {
            let mut enc = ChunkEncryptor::for_push(m, file_id, data.len() as u64, beebeeb_types::ChunkProfile::Mobile)
                .unwrap()
                .with_format(ChunkFormat::V2)
                .unwrap();
            let cs = enc.chunk_plan().chunk_size_bytes as usize;
            let frames: Vec<Vec<u8>> = data.chunks(cs).map(|c| enc.push_chunk(c).unwrap().data).collect();
            enc.finish().unwrap();
            frames
        })
        .unwrap();
    assert_eq!(frames.len(), 2);
    (data, frames)
}

#[test]
fn handle_rejects_reorder_and_truncation() {
    let mk = mk_handle();
    let (_, frames) = two_v2_frames(&mk, "ffi-v2");

    for expected in [0u8, 2] {
        // Out of order: chunk 1 pushed first.
        let dec = ChunkDecryptorHandle::for_push(&mk, "ffi-v2".into(), pin(expected)).unwrap();
        assert!(dec.push_frame(frames[1].clone()).is_err());

        // Truncated: only chunk 0, then finish.
        let dec = ChunkDecryptorHandle::for_push(&mk, "ffi-v2".into(), pin(expected)).unwrap();
        dec.push_frame(frames[0].clone()).unwrap();
        assert!(
            dec.finish().is_err(),
            "finish must reject a v2 stream without its last chunk"
        );
    }
    // Unknown expected-format codes are refused, not treated as "detect".
    for bad in [1u8, 3] {
        assert!(ChunkDecryptorHandle::for_push(&mk, "ffi-v2".into(), pin(bad)).is_err());
    }
}

#[test]
fn handle_v2_pin_refuses_name_blob_as_frame0() {
    // Review round 2 P1-1 through the FFI: metadata records v2, the server
    // serves the file's own name blob as its only frame.
    let mk = mk_handle();
    let id = "ffi-downgrade";
    let ne = mk
        .encrypt_name_with_chunk_format(id.into(), "a.pdf".into(), Some("application/pdf".into()), 2)
        .unwrap();
    let meta = mk.decrypt_name_metadata(id.into(), ne.clone()).unwrap();
    assert_eq!((meta.name.as_str(), meta.chunk_format), ("a.pdf", 2));
    let blob = parse_name_blob(&ne);
    let forged = [blob.nonce, blob.ciphertext].concat();
    let dec = ChunkDecryptorHandle::for_push(&mk, id.into(), pin(meta.chunk_format)).unwrap();
    assert!(dec.push_frame(forged).is_err());
    // A name written without a format reads back as 0 (unrecorded).
    let legacy = mk.encrypt_name(id.into(), "a.pdf".into(), None).unwrap();
    assert_eq!(mk.decrypt_name_metadata(id.into(), legacy).unwrap().chunk_format, 0);
    assert!(
        mk.encrypt_name_with_chunk_format(id.into(), "a".into(), None, 1)
            .is_err()
    );
}

#[test]
fn handle_file_metadata_refuses_plaintext_folder_reader_keeps_it() {
    // Round 3 P1-B through the FFI: files refuse a plaintext name.
    let mk = mk_handle();
    let id = "ffi-plaintext";
    assert!(mk.decrypt_file_metadata(id.into(), "innocent.txt".into()).is_err());
    assert_eq!(
        mk.decrypt_name_metadata(id.into(), "Photos".into()).unwrap().name,
        "Photos"
    );
    let fk = mk.derive_file_key(id.as_bytes().to_vec()).unwrap();
    assert!(fk.decrypt_file_metadata("innocent.txt".into()).is_err());
    // A real envelope reads through both file readers.
    let ne = mk.encrypt_name(id.into(), "a.pdf".into(), None).unwrap();
    assert_eq!(mk.decrypt_file_metadata(id.into(), ne.clone()).unwrap().name, "a.pdf");
    assert_eq!(fk.decrypt_file_metadata(ne).unwrap().chunk_format, 0);
}

#[test]
fn handle_thumbnail_roundtrip_and_resume_policy() {
    let mk = mk_handle();
    let fk = mk.derive_file_key(b"ffi-thumb".to_vec()).unwrap();
    let sealed = fk.encrypt_thumbnail(b"webp bytes".to_vec()).unwrap();
    assert_eq!(fk.decrypt_thumbnail(sealed).unwrap(), b"webp bytes");

    // Production v2 uploads always restart rather than append to an old
    // upload session; unknown codes are errors.
    let enc = ChunkEncryptorHandle::for_push(&mk, "ffi-resume".into(), 10, "mobile".into()).unwrap();
    for stored in [None, Some(1), Some(2)] {
        assert_eq!(
            enc.resume_policy(stored).unwrap(),
            SessionResumeAction::RestartWithFreshSession,
            "stored {stored:?}"
        );
    }
    assert!(enc.resume_policy(Some(3)).is_err());
}

#[test]
fn handle_replace_of_a_v2_pinned_file_uses_the_recorded_pin() {
    // Task 1908 round 4, I-1 through the FFI: pin from the file's metadata
    // -> apply_recorded_pin -> the new version reads back under that pin.
    let mk = mk_handle();
    let id = "ffi-replace-v2";
    let name = mk
        .encrypt_name_with_chunk_format(id.into(), "a.pdf".into(), None, 2)
        .unwrap();
    let recorded = mk.decrypt_file_metadata(id.into(), name).unwrap();
    assert_eq!(recorded.chunk_format, 2);
    let data = b"replaced content of a v2-pinned file".to_vec();
    let enc = ChunkEncryptorHandle::for_push(&mk, id.into(), data.len() as u64, "mobile".into()).unwrap();
    enc.apply_recorded_pin(recorded.chunk_format).unwrap();
    assert_eq!(enc.chunk_format().unwrap(), 2, "a v2-pinned file must be written as v2");
    let frame = enc.push_chunk(data.clone()).unwrap();
    enc.finish().unwrap();
    let dec = ChunkDecryptorHandle::for_push(&mk, id.into(), recorded).unwrap();
    assert_eq!(dec.push_frame(frame.data).unwrap().data, data);
    dec.finish().unwrap();

    // Unrecorded keeps the write format; unknown codes are errors.
    let enc0 = ChunkEncryptorHandle::for_push(&mk, "ffi-replace-v1".into(), 4, "mobile".into()).unwrap();
    enc0.apply_recorded_pin(0).unwrap();
    assert_eq!(enc0.chunk_format().unwrap(), default_write_format());
    for bad in [1u8, 3] {
        let e = ChunkEncryptorHandle::for_push(&mk, "ffi-bad-pin".into(), 4, "mobile".into()).unwrap();
        assert!(e.apply_recorded_pin(bad).is_err(), "pin code {bad}");
    }
}

#[test]
fn handle_thumbnail_for_a_v2_pin_is_not_raw_key_sealed() {
    let mk = mk_handle();
    let fk = mk.derive_file_key(b"ffi-thumb-pin".to_vec()).unwrap();
    let sealed = fk.encrypt_thumbnail_for(b"webp".to_vec(), 2).unwrap();
    assert_eq!(fk.decrypt_thumbnail(sealed.clone()).unwrap(), b"webp");
    assert!(
        fk.decrypt_chunk(sealed[..12].to_vec(), sealed[12..].to_vec()).is_err(),
        "a v2-pinned thumbnail must not open under the raw file key"
    );
    assert!(fk.encrypt_thumbnail_for(b"webp".to_vec(), 7).is_err());
}

#[test]
fn handle_note_for_a_v2_pin_is_subkey_sealed_and_not_a_name() {
    // Task 1908 round 5 through the FFI: a note written for a v2-pinned
    // file never sits under the raw file key and never opens as the
    // file's metadata (the downgrade a raw-key note allowed).
    let mk = mk_handle();
    let id = "ffi-note-v2";
    let name = mk
        .encrypt_name_with_chunk_format(id.into(), "a.pdf".into(), None, 2)
        .unwrap();
    let pin = mk.decrypt_file_metadata(id.into(), name).unwrap().chunk_format;
    assert_eq!(pin, 2);
    let fk = mk.derive_file_key(id.as_bytes().to_vec()).unwrap();
    let note = fk.encrypt_note_for("ffi note".into(), pin).unwrap();
    assert_eq!(fk.decrypt_note(note.clone()).unwrap(), "ffi note");
    let blob = parse_name_blob(&note);
    assert!(
        fk.decrypt_chunk(blob.nonce.clone(), blob.ciphertext.clone()).is_err(),
        "a v2-pinned note must not open under the raw file key"
    );
    assert!(
        fk.decrypt_file_metadata(note.clone()).is_err(),
        "a v2 note must not open as the file's metadata"
    );
    assert!(mk.decrypt_file_metadata(id.into(), note).is_err());

    // Unrecorded follows the write switch; unknown codes are errors.
    let n0 = fk.encrypt_note_for("n0".into(), 0).unwrap();
    assert_eq!(fk.decrypt_note(n0).unwrap(), "n0");
    assert_eq!(fk.decrypt_note(fk.encrypt_note("n".into()).unwrap()).unwrap(), "n");
    for bad in [1u8, 7] {
        assert!(fk.encrypt_note_for("x".into(), bad).is_err(), "pin code {bad}");
    }
    assert!(fk.decrypt_note("a plaintext note".into()).is_err());
}

#[test]
fn handle_name_for_keeps_the_pin_under_a_file_key_handle_1958() {
    // Task 1958 through the FFI: the rename writer of a FileKeyHandle keeps
    // a v2 pin, seals under the name subkey, and for a derived key reads back
    // through the master-key reader too.
    let mk = mk_handle();
    let id = "ffi-name-for";
    let fk = mk.derive_file_key(id.as_bytes().to_vec()).unwrap();
    let renamed = fk
        .encrypt_name_for("renamed.pdf".into(), Some("application/pdf".into()), 2)
        .unwrap();
    let meta = fk.decrypt_file_metadata(renamed.clone()).unwrap();
    assert_eq!((meta.name.as_str(), meta.chunk_format), ("renamed.pdf", 2));
    assert_eq!(
        mk.decrypt_file_metadata(id.into(), renamed.clone())
            .unwrap()
            .chunk_format,
        2
    );
    let blob = parse_name_blob(&renamed);
    assert!(
        fk.decrypt_chunk(blob.nonce.clone(), blob.ciphertext.clone()).is_err(),
        "a v2-pinned name must not open under the raw file key"
    );
    let r0 = fk.encrypt_name_for("r0.txt".into(), None, 0).unwrap();
    assert_eq!(fk.decrypt_file_metadata(r0).unwrap().chunk_format, 0);
    for bad in [1u8, 7] {
        assert!(fk.encrypt_name_for("x".into(), None, bad).is_err(), "pin code {bad}");
    }
}

/// The key of the published given-key name vectors (task 1958): 32 bytes
/// NOT derived from any master key.
const GIVEN_FILE_KEY: [u8; 32] = [
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
];

#[test]
fn a_non_derived_key_reaches_the_name_writer_and_reader_1958_r4() {
    // Task 1958 round 4 (Codex P1): a key the app holds as bytes (a
    // file-request upload's content key, a shared file's key) becomes a
    // FileKeyHandle, and its name round-trips with the pin: what Swift and
    // Kotlin could not do while `derive_file_key` was the only way in.
    let fk = FileKeyHandle::from_key_bytes(GIVEN_FILE_KEY.to_vec()).unwrap();
    for pin in [0u8, 2] {
        let sealed = fk
            .encrypt_name_for("request-upload.pdf".into(), Some("application/pdf".into()), pin)
            .unwrap();
        let meta = fk.decrypt_file_metadata(sealed.clone()).unwrap();
        assert_eq!(meta.name, "request-upload.pdf", "pin {pin}");
        assert_eq!(meta.mime_type.as_deref(), Some("application/pdf"), "pin {pin}");
        assert_eq!(meta.chunk_format, pin, "pin {pin}");
        // The same key as core's, byte for byte: core's with-key reader opens it.
        let core_meta =
            encrypt::decrypt_file_metadata_with_key(&kdf::FileKey::from_bytes(GIVEN_FILE_KEY), &sealed).unwrap();
        assert_eq!(core_meta.chunk_format.as_u8(), pin, "pin {pin}");
    }
    // The rest of the handle is reachable for such a key too (notes).
    let note = fk.encrypt_note_for("a note".into(), 2).unwrap();
    assert_eq!(fk.decrypt_note(note).unwrap(), "a note");
}

#[test]
fn file_key_handle_from_key_bytes_refuses_other_lengths_1958_r4() {
    for len in [0usize, 16, 31, 33, 64] {
        match FileKeyHandle::from_key_bytes(vec![0x42; len]) {
            Err(CryptoError::InvalidInput { .. }) => {}
            Err(other) => panic!("{len} bytes: wrong error {other:?}"),
            Ok(_) => panic!("{len} bytes must be refused"),
        }
    }
}

/// The default write format's code (2).
fn default_write_format() -> u8 {
    beebeeb_core::chunk_stream::WRITE_FORMAT.as_u8()
}

/// Parse a native `name_encrypted` envelope (numeric-array JSON).
fn parse_name_blob(json: &str) -> beebeeb_types::EncryptedBlob {
    let (nonce, ciphertext) = beebeeb_core::metadata_wire::parse_encrypted_metadata(json).unwrap();
    beebeeb_types::EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce,
        ciphertext,
    }
}

#[test]
fn handle_with_file_key_and_random_access_frame_open() {
    let mk = mk_handle();
    let (data, frames) = two_v2_frames(&mk, "ffi-fk");
    let fk = mk.derive_file_key(b"ffi-fk".to_vec()).unwrap();
    let fk_bytes = mk
        .with_key(|m| kdf::derive_file_key(m, b"ffi-fk").as_bytes().to_vec())
        .unwrap();

    // File-key decryptors (share recipient path): raw bytes and handle.
    for dec in [
        ChunkDecryptorHandle::for_push_with_file_key(fk_bytes.clone(), "ffi-fk".into(), pin(2)).unwrap(),
        ChunkDecryptorHandle::for_push_with_file_key_handle(&fk, "ffi-fk".into(), pin(2)).unwrap(),
    ] {
        let mut out = Vec::new();
        for f in &frames {
            out.extend(dec.push_frame(f.clone()).unwrap().data);
        }
        assert_eq!(dec.version_id().unwrap().unwrap(), frames[0][..12].to_vec());
        dec.finish().unwrap();
        assert_eq!(out, data);
    }

    // Wrong file id with the right key fails.
    let dec = ChunkDecryptorHandle::for_push_with_file_key_handle(&fk, "other".into(), pin(2)).unwrap();
    assert!(dec.push_frame(frames[0].clone()).is_err());

    // Random access: right position + version opens; wrong position, last
    // flag, version or format fails.
    let vid = frames[0][..12].to_vec();
    assert_eq!(
        fk.decrypt_chunk_frame("ffi-fk".into(), vid.clone(), 1, true, 2, frames[1].clone())
            .unwrap(),
        data[4 * 1024 * 1024..]
    );
    let (_, other_upload) = two_v2_frames(&mk, "ffi-fk");
    for (v, i, last, fmt, frame) in [
        (vid.clone(), 0, false, 2, frames[1].clone()),
        (vid.clone(), 1, false, 2, frames[1].clone()),
        (vid.clone(), 1, true, 1, frames[1].clone()),
        (vid.clone(), 1, true, 9, frames[1].clone()),
        (vid.clone(), 1, true, 2, other_upload[1].clone()),
        (other_upload[0][..12].to_vec(), 1, true, 2, frames[1].clone()),
        (vid[..11].to_vec(), 1, true, 2, frames[1].clone()),
    ] {
        assert!(fk.decrypt_chunk_frame("ffi-fk".into(), v, i, last, fmt, frame).is_err());
    }
}

#[test]
fn contiguous_to_file_binds_file_id_and_rejects_swap() {
    let mk = mk_handle();
    let (data, frames) = two_v2_frames(&mk, "ffi-contig");
    let fk_bytes = mk
        .with_key(|m| kdf::derive_file_key(m, b"ffi-contig").as_bytes().to_vec())
        .unwrap();
    let dir = std::env::temp_dir().join(format!("bb_uniffi_contig_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out.bin").to_string_lossy().into_owned();
    let cs = 4 * 1024 * 1024u64;

    let n = decrypt_contiguous_to_file(
        fk_bytes.clone(),
        "ffi-contig".into(),
        2,
        frames.concat(),
        cs,
        out.clone(),
    )
    .unwrap();
    assert_eq!(n, data.len() as u64);
    std::fs::remove_file(&out).unwrap();

    // Truncated to chunk 0: rejected, nothing written.
    assert!(
        decrypt_contiguous_to_file(
            fk_bytes.clone(),
            "ffi-contig".into(),
            2,
            frames[0].clone(),
            cs,
            out.clone()
        )
        .is_err()
    );
    assert!(!std::path::Path::new(&out).exists());

    // Pre-sliced variant: wrong file id rejected; right id opens.
    let pairs = || -> Vec<EncryptedChunkData> {
        frames
            .iter()
            .map(|f| EncryptedChunkData {
                nonce: f[..12].to_vec(),
                ciphertext: f[12..].to_vec(),
            })
            .collect()
    };
    assert!(decrypt_chunks_to_file(fk_bytes.clone(), "not-the-id".into(), 2, pairs(), out.clone()).is_err());
    assert_eq!(
        decrypt_chunks_to_file(fk_bytes, "ffi-contig".into(), 2, pairs(), out.clone()).unwrap(),
        data.len() as u64
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finished_handle_rejects_reuse() {
    let mk = mk_handle();
    let enc = ChunkEncryptorHandle::for_push(&mk, "x".into(), 4, "mobile".into()).unwrap();
    let _ = enc.push_chunk(vec![1, 2, 3, 4]).unwrap();
    enc.finish().unwrap();
    assert!(enc.push_chunk(vec![0]).is_err());
    assert!(enc.finish().is_err());
    assert!(enc.next_chunk().is_err());
}

#[test]
fn wrong_key_decrypt_errors() {
    let mk = mk_handle();
    let enc = ChunkEncryptorHandle::for_push(&mk, "secret".into(), 5, "mobile".into()).unwrap();
    let frame = enc.push_chunk(b"hello".to_vec()).unwrap();
    let wrong = MasterKeyHandle::from_keychain_bytes(vec![9u8; 32]).unwrap();
    let dec = ChunkDecryptorHandle::for_push(&wrong, "secret".into(), pin(default_expected())).unwrap();
    assert!(dec.push_frame(frame.data).is_err());
}

#[test]
fn pull_file_roundtrip_via_handles() {
    use std::io::Write;
    let mk = mk_handle();
    let dir = std::env::temp_dir().join("beebeeb_uniffi_chunk_stream_pull");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.bin");
    // 9 MiB → mobile profile 4 MiB chunks → 3 chunks (4 + 4 + 1).
    let content: Vec<u8> = (0..9 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(&input, &content).unwrap();

    let enc = ChunkEncryptorHandle::from_file(
        &mk,
        "pullfile".into(),
        input.to_string_lossy().into_owned(),
        "mobile".into(),
    )
    .unwrap();
    let chunk_size = enc.chunk_plan().unwrap().chunk_size_bytes;
    assert_eq!(chunk_size, 4 * 1024 * 1024);

    let enc_path = dir.join("in.enc");
    let mut out_file = std::fs::File::create(&enc_path).unwrap();
    let mut frames = 0u32;
    while let Some(c) = enc.next_chunk().unwrap() {
        out_file.write_all(&c.data).unwrap();
        frames += 1;
    }
    out_file.flush().unwrap();
    drop(out_file);
    assert_eq!(frames, 3);
    let summary = enc.finish().unwrap();
    assert_eq!(summary.total_plaintext, content.len() as u64);

    let dec = ChunkDecryptorHandle::from_file(
        &mk,
        "pullfile".into(),
        pin(default_expected()),
        chunk_size,
        enc_path.to_string_lossy().into_owned(),
    )
    .unwrap();
    let mut recovered = Vec::new();
    while let Some(c) = dec.next_chunk().unwrap() {
        recovered.extend_from_slice(&c.data);
    }
    assert_eq!(recovered, content);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Crypto review, P2-4: every decryptor constructor takes the record
/// `decrypt_file_metadata` returned and enforces its version commitment, so an
/// older complete upload of the same file is refused, through the master key
/// and through a key handle alike.
#[test]
fn decryptors_from_metadata_refuse_another_upload_of_the_same_file() {
    let mk = mk_handle();
    let id = "ffi-replay";
    let data = b"forty bytes of content for the replay ok".to_vec();
    let upload = || {
        let enc = ChunkEncryptorHandle::for_push(&mk, id.into(), data.len() as u64, "mobile".into()).unwrap();
        let frame = enc.push_chunk(data.clone()).unwrap().data;
        let version = enc.version_commitment(None).unwrap();
        enc.finish().unwrap();
        (frame, version)
    };
    let (older, _) = upload();
    let (current, version) = upload();
    let sealed = mk
        .encrypt_name_with_version(
            id.into(),
            "a.txt".into(),
            None,
            2,
            version.version_id,
            version.version_counter,
        )
        .unwrap();
    let file_key = FileKeyHandle::new(kdf::derive_file_key(
        &kdf::MasterKey::from_bytes([7u8; 32]),
        id.as_bytes(),
    ));
    let owner_record = || mk.decrypt_file_metadata(id.into(), sealed.clone()).unwrap();
    let key_record = || file_key.decrypt_file_metadata(sealed.clone()).unwrap();
    assert_eq!(owner_record().version_counter, Some(1));

    let decryptors = || {
        let record = key_record();
        [
            ChunkDecryptorHandle::for_push(&mk, id.into(), owner_record()).unwrap(),
            ChunkDecryptorHandle::for_push_with_file_key_handle(&file_key, id.into(), key_record()).unwrap(),
            ChunkDecryptorHandle::for_version_with_file_key_handle(
                &file_key,
                id.into(),
                record.chunk_format,
                record.version_id,
                record.version_counter,
            )
            .unwrap(),
        ]
    };
    for dec in decryptors() {
        assert_eq!(dec.push_frame(current.clone()).unwrap().data, data);
    }
    for dec in decryptors() {
        assert!(
            dec.push_frame(older.clone()).is_err(),
            "an older upload opened under the record"
        );
    }
    assert!(
        ChunkDecryptorHandle::for_version_with_file_key_handle(&file_key, id.into(), 2, key_record().version_id, None)
            .is_err(),
        "half a commitment is refused"
    );
}
