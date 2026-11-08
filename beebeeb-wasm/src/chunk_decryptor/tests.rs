//! Native seams of the decryptor constructors (P2-4). `JsError` cannot be
//! built off wasm, so these drive `metadata_pin` and `with_pin` directly; the
//! JS surface is covered by `js-tests/decryptor_metadata.test.cjs`.

use super::*;
use beebeeb_core::chunk_stream::{ChunkEncryptor, ChunkFormat};

fn metadata(chunk_format: u8, version_id: Option<&str>, version_counter: Option<f64>) -> DecryptorMetadataJs {
    DecryptorMetadataJs {
        chunk_format,
        version_id: version_id.map(str::to_owned),
        version_counter,
    }
}

#[test]
fn metadata_pin_takes_the_commitment_and_refuses_half_of_one() {
    let (expected, version) = metadata_pin(&metadata(0, None, None)).unwrap();
    assert_eq!(expected, ExpectedChunkFormat::Unrecorded);
    assert!(version.is_none(), "legacy metadata opens v1 content only");

    let (expected, version) = metadata_pin(&metadata(2, Some("00112233445566778899aAbB"), Some(3.0))).unwrap();
    assert_eq!(expected, ExpectedChunkFormat::V2);
    let version = version.unwrap();
    assert_eq!(
        version.version_id,
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]
    );
    assert_eq!(version.counter, 3);

    for refused in [
        metadata(2, Some("00112233445566778899aabb"), None),
        metadata(2, None, Some(3.0)),
        metadata(2, Some("00112233445566778899aab"), Some(3.0)),
        metadata(2, Some("00112233445566778899aabg"), Some(3.0)),
        metadata(2, Some("00112233445566778899aabb"), Some(0.0)),
        metadata(2, Some("00112233445566778899aabb"), Some(1.5)),
        metadata(2, Some("00112233445566778899aabb"), Some(f64::NAN)),
        metadata(7, None, None),
        // The ruling of 2026-11-07: a v2 record without a commitment.
        metadata(2, None, None),
    ] {
        assert!(metadata_pin(&refused).is_err());
    }
}

// The fixed-chunk-size seam, as the other binding tests use it.
#[allow(deprecated)]
fn upload(mk: &kdf::MasterKey, file_id: &str, data: &[u8]) -> (Vec<Vec<u8>>, VersionCommitment) {
    let mut enc = ChunkEncryptor::for_push_with_chunk_size(mk, file_id, data.len() as u64, 16)
        .unwrap()
        .with_format(ChunkFormat::V2)
        .unwrap();
    let frames: Vec<Vec<u8>> = data.chunks(16).map(|c| enc.push_chunk(c).unwrap().data).collect();
    let commitment = enc.version_commitment(None).unwrap();
    enc.finish().unwrap();
    (frames, commitment)
}

#[test]
fn a_decryptor_from_metadata_refuses_another_upload_of_the_same_file() {
    let mk = kdf::MasterKey::from_bytes([5u8; 32]);
    let file_id = "wasm-replay";
    let data: Vec<u8> = (0..40u8).collect();
    let (older, _) = upload(&mk, file_id, &data);
    let (current, commitment) = upload(&mk, file_id, &data);
    let hex_id: String = commitment.version_id.iter().map(|b| format!("{b:02x}")).collect();
    let record = metadata(2, Some(&hex_id), Some(commitment.counter as f64));

    let open = |frames: &[Vec<u8>]| {
        let (expected, version) = metadata_pin(&record).unwrap();
        let mut dec = WasmChunkDecryptor::with_pin(
            kdf::derive_file_key(&mk, file_id.as_bytes()),
            file_id,
            expected,
            version,
        );
        let mut out = Vec::new();
        for frame in frames {
            out.extend(dec.inner.push_frame(frame)?.data);
        }
        dec.inner.finish().map(|_| out)
    };
    assert_eq!(open(&current).unwrap(), data);
    assert!(
        open(&older).is_err(),
        "the server served an older upload in place of the recorded one"
    );
}

/// Moved from `lib.rs` (size baseline). Since Guus's ruling of 2026-11-07 a
/// v2 record without a commitment opens nothing, here and through the
/// random-access open `decrypt_chunk_frame` calls. Mutant: `metadata_pin`'s
/// and core's no-commitment refusals removed: the three refusals pass.
#[test]
#[allow(deprecated)]
fn wasm_decryptor_roundtrip_and_v2_format() {
    // Task 1908: the web decryptor (both constructors, pinned v2 as the
    // metadata records it) reads v2 back in order; the web encryptor also
    // writes v2. Error paths throw JsError,
    // which cannot be constructed off-wasm (see NOTE below), so only the
    // success seams are exercised here; the rejection cases live in core.
    let mk = kdf::derive_master_key("test-password", b"test-salt-16bytes").unwrap();
    let mk_bytes = mk.to_bytes();
    let file_id = "wasm-dec-1";
    let data: Vec<u8> = (0..40usize).map(|i| (i % 251) as u8).collect();
    let enc = crate::WasmChunkEncryptor::with_chunk_size(mk_bytes.as_ref(), file_id.to_string(), data.len() as u64, 16)
        .unwrap();
    assert_eq!(enc.format(), 2, "web uploads use v2");

    // Explicit v2 frames exercise the fixed-size test seam.
    let mut enc = ChunkEncryptor::for_push_with_chunk_size(&mk, file_id, data.len() as u64, 16)
        .unwrap()
        .with_format(ChunkFormat::V2)
        .unwrap();
    let frames: Vec<Vec<u8>> = data.chunks(16).map(|c| enc.push_chunk(c).unwrap().data).collect();
    enc.finish().unwrap();

    // The name metadata a v2 upload writes records 2.
    let ne = crate::encrypt_name_with_chunk_format(mk_bytes.as_ref(), file_id, "a.txt", None, 2).unwrap();
    let meta = beebeeb_core::encrypt::decrypt_name_metadata(&mk, file_id, &ne).unwrap();
    assert_eq!(meta.chunk_format, ExpectedChunkFormat::V2);
    let pin = meta.chunk_format.as_u8();

    // The ruling of 2026-11-07: a `chunk_format: 2` record without a
    // commitment is refused before any frame.
    let bare = DecryptorMetadataJs {
        chunk_format: pin,
        version_id: None,
        version_counter: None,
    };
    assert!(metadata_pin(&bare).is_err());
    let hex: String = frames[0][..12].iter().map(|b| format!("{b:02x}")).collect();
    let record = DecryptorMetadataJs {
        chunk_format: pin,
        version_id: Some(hex),
        version_counter: Some(1.0),
    };
    let (expected, version) = metadata_pin(&record).unwrap();
    let file_key = kdf::derive_file_key(&mk, file_id.as_bytes());
    let mut dec = WasmChunkDecryptor::with_pin(file_key, file_id, expected, version);
    assert_eq!(dec.format(), 0);
    assert_eq!(dec.version_id(), None);
    let mut out = Vec::new();
    for f in &frames {
        out.extend(dec.push_frame(f).unwrap());
    }
    assert_eq!(out, data);
    assert_eq!(dec.format(), 2);
    assert_eq!(dec.chunks_decrypted(), 3);
    let vid = dec.version_id().unwrap();
    assert_eq!(vid, frames[0][..12].to_vec());
    let summary = dec.inner.finish().unwrap();
    assert_eq!(summary.chunk_count, 3);

    // Without the commitment the same frames open nothing.
    let fk = kdf::derive_file_key(&mk, file_id.as_bytes());
    let mut dec = WasmChunkDecryptor::with_pin(kdf::FileKey::from_bytes(*fk.as_bytes()), file_id, expected, None);
    assert!(dec.inner.push_frame(&frames[0]).is_err());

    // Random-access open at the right position and version: what
    // `decrypt_chunk_frame` calls once it has parsed the JS record.
    let committed = beebeeb_core::encrypt::NameMetadata {
        name: String::new(),
        mime_type: None,
        chunk_format: expected,
        version,
    };
    let last = beebeeb_core::chunk_stream::open_recorded_chunk(&fk, file_id, &committed, 2, true, &frames[2]).unwrap();
    assert_eq!(last, data[32..]);
    let bare = beebeeb_core::encrypt::NameMetadata {
        version: None,
        ..committed
    };
    assert!(beebeeb_core::chunk_stream::open_recorded_chunk(&fk, file_id, &bare, 2, true, &frames[2]).is_err());
}
