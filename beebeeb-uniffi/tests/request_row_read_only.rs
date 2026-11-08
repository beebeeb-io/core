//! Task 2275 §15 / 2326 delta D-P2: request-row results are read-only.
//!
//! A request row whose name is sealed under the content key `C` must not hand
//! a caller anything that can seal a name: the anonymous uploader holds `C`.
//! Renames go through `seal_request_rename`, which derives the §15 string key
//! from the item id, never `C`.

use beebeeb_core::chunk_stream::{ChunkEncryptor, ExpectedChunkFormat};
use beebeeb_core::kdf::{FileKey, MasterKey};
use beebeeb_uniffi::{
    FileKeyHandle, MasterKeyHandle, derive_master_key, derive_x25519_public, seal_to_request, wrap_request_private,
};

const SALT: &[u8] = b"test-salt-16bytes";
const O_ID: &str = "66666666-6666-4666-8666-666666666666";

#[test]
fn request_row_results_never_hand_back_a_sealing_key() {
    let mk = derive_master_key("owner".into(), SALT.to_vec()).unwrap();
    let owner = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
    let r_priv = [0x11u8; 32];
    let r_pub = derive_x25519_public(r_priv.to_vec()).unwrap();
    let content_key = vec![0x22u8; 32];
    let wrap = wrap_request_private(mk.key.clone(), Vec::new(), r_priv.to_vec()).unwrap();
    let sealed = seal_to_request(r_pub, Vec::new(), content_key.clone()).unwrap();
    let content_handle = FileKeyHandle::from_key_bytes(content_key).unwrap();
    let name = content_handle.encrypt_name_for("upload.bin".into(), None, 0).unwrap();

    let detailed = owner
        .resolve_request_row_detailed(
            O_ID.to_string(),
            Vec::new(),
            wrap.wrapped.clone(),
            wrap.nonce.clone(),
            sealed.e_pub.clone(),
            sealed.wrapped_key.clone(),
            name.clone(),
        )
        .unwrap();
    assert_eq!(detailed.seal, "unbound");
    assert_eq!(detailed.name_origin, "request_content");
    assert_eq!(detailed.name, "upload.bin");
    assert_eq!(detailed.rename_target.as_ref().unwrap().pin, 0);
    // The content reader is pinned to the row's recorded format and has no key.
    assert_eq!(detailed.content.chunk_format(), 0);

    // The legacy view is read-only too: it still opens the row and carries a
    // content handle, never a key that could seal a name.
    let legacy = owner
        .resolve_request_row(
            O_ID.to_string(),
            Vec::new(),
            wrap.wrapped,
            wrap.nonce,
            sealed.e_pub,
            sealed.wrapped_key,
            name,
        )
        .unwrap();
    assert_eq!(legacy.name, "upload.bin");
    assert_eq!(legacy.name_origin, "request_content");
    assert_eq!(legacy.chunk_format, 0);

    // The reader actually reads: a v1 upload under C opens through a fresh
    // decryptor (the old assertion only checked a format that is None for any
    // decryptor and never used `legacy.content`). The row's record carries no
    // version commitment, so only v1 content opens (Guus's ruling of
    // 2026-11-07); its v2 content is refused below.
    let plaintext: Vec<u8> = (0..96u8).collect();
    let frames: Vec<Vec<u8>> = plaintext
        .chunks(32)
        .map(|c| beebeeb_core::encrypt::encrypt_chunk_raw(&FileKey::from_bytes([0x22u8; 32]), c).unwrap())
        .collect();
    let mut enc =
        ChunkEncryptor::for_push_with_file_key(FileKey::from_bytes([0x22u8; 32]), O_ID, plaintext.len() as u64, 32)
            .unwrap();
    let v2_frames: Vec<Vec<u8>> = plaintext.chunks(32).map(|c| enc.push_chunk(c).unwrap().data).collect();
    enc.finish().unwrap();
    for reader in [&detailed.content, &legacy.content] {
        assert!(reader.decryptor().unwrap().push_frame(v2_frames[0].clone()).is_err());
        let dec = reader.decryptor().unwrap();
        let mut out = Vec::new();
        for frame in &frames {
            out.extend_from_slice(&dec.push_frame(frame.clone()).unwrap().data);
        }
        dec.finish().unwrap();
        assert_eq!(out, plaintext);
    }

    // The same v1 frame opens through open_frame on this unrecorded reader.
    let v1 = beebeeb_core::encrypt::encrypt_chunk(&FileKey::from_bytes([0x22u8; 32]), b"the request upload").unwrap();
    let mut v1_frame = v1.nonce.clone();
    v1_frame.extend_from_slice(&v1.ciphertext);
    assert_eq!(
        detailed.content.open_frame(Vec::new(), 0, true, 1, v1_frame).unwrap(),
        b"the request upload"
    );

    // D-P2: renaming goes through the core sealer. The sealed name opens under
    // the string-derived key and NOT under C, which the uploader holds.
    let renamed = owner
        .seal_request_rename(O_ID.to_string(), 0, "renamed.bin".into(), None)
        .unwrap();
    let derived = owner.derive_file_key(O_ID.as_bytes().to_vec()).unwrap();
    assert_eq!(
        derived.decrypt_file_metadata(renamed.clone()).unwrap().name,
        "renamed.bin"
    );
    assert!(
        content_handle.decrypt_file_metadata(renamed).is_err(),
        "a rename sealed under C would hand the owner's name to the uploader"
    );
}

#[test]
fn a_bound_request_row_reads_v2_content_through_both_readers() {
    let mk = derive_master_key("owner".into(), SALT.to_vec()).unwrap();
    let owner = MasterKeyHandle::from_keychain_bytes(mk.key.clone()).unwrap();
    let r_priv = [0x11u8; 32];
    let r_pub = derive_x25519_public(r_priv.to_vec()).unwrap();
    let content_key = [0x22u8; 32];
    let wrap = wrap_request_private(mk.key.clone(), Vec::new(), r_priv.to_vec()).unwrap();
    // Bound: the content key is sealed to the row's O id.
    let sealed = seal_to_request(r_pub, O_ID.as_bytes().to_vec(), content_key.to_vec()).unwrap();
    // v2 frames under C, bound to the O id.
    let plaintext: Vec<u8> = (0..96u8).collect();
    let mut enc =
        ChunkEncryptor::for_push_with_file_key(FileKey::from_bytes(content_key), O_ID, plaintext.len() as u64, 32)
            .unwrap()
            .with_recorded_pin(ExpectedChunkFormat::V2)
            .unwrap();
    let frames: Vec<Vec<u8>> = plaintext.chunks(32).map(|c| enc.push_chunk(c).unwrap().data).collect();
    let version = enc.version_commitment(None).unwrap();
    enc.finish().unwrap();
    // The name is under the string-derived key, records v2 and commits to
    // that upload (without the commitment no reader would open it).
    let derived_key = beebeeb_core::kdf::derive_file_key(
        &MasterKey::from_bytes(mk.key.clone().try_into().unwrap()),
        O_ID.as_bytes(),
    );
    let name = beebeeb_core::encrypt::encrypt_name_for_version(
        &derived_key,
        "upload.bin",
        None,
        ExpectedChunkFormat::V2,
        version,
    )
    .unwrap();

    let detailed = owner
        .resolve_request_row_detailed(
            O_ID.to_string(),
            Vec::new(),
            wrap.wrapped.clone(),
            wrap.nonce.clone(),
            sealed.e_pub.clone(),
            sealed.wrapped_key.clone(),
            name.clone(),
        )
        .unwrap();
    assert_eq!(detailed.seal, "bound");
    assert_eq!(detailed.chunk_format, 2);
    assert_eq!(detailed.content.chunk_format(), 2);
    assert_eq!(detailed.content.file_id(), O_ID);

    let legacy = owner
        .resolve_request_row(
            O_ID.to_string(),
            Vec::new(),
            wrap.wrapped,
            wrap.nonce,
            sealed.e_pub,
            sealed.wrapped_key,
            name,
        )
        .unwrap();
    assert_eq!(legacy.chunk_format, 2);

    // A reader built from the name key (a mutant) or with a wrong file id
    // cannot open the frames.
    for reader in [&detailed.content, &legacy.content] {
        let dec = reader.decryptor().unwrap();
        let mut out = Vec::new();
        for frame in &frames {
            out.extend_from_slice(&dec.push_frame(frame.clone()).unwrap().data);
        }
        dec.finish().unwrap();
        assert_eq!(out, plaintext);
    }

    // open_frame is the guard's other entry point: a v1 frame under the same C
    // is refused by these V2-pinned readers (the core test shows an Unrecorded
    // reader opens the same frame, so the pin refuses it, not the key).
    let v1 = beebeeb_core::encrypt::encrypt_chunk(&FileKey::from_bytes(content_key), b"bound upload").unwrap();
    let mut v1_frame = v1.nonce.clone();
    v1_frame.extend_from_slice(&v1.ciphertext);
    let err = detailed
        .content
        .open_frame(Vec::new(), 0, true, 1, v1_frame)
        .expect_err("a reader pinned to v2 must refuse format 1");
    assert!(err.to_string().contains("records chunk format 2"), "{err}");
}
