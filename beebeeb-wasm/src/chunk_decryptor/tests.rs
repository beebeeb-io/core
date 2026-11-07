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
    assert!(version.is_none(), "legacy metadata stays readable, unprotected");

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
