use beebeeb_core::chunk_stream::ExpectedChunkFormat;
use beebeeb_core::encrypt::{decrypt_file_metadata_with_key, encrypt_chunk_raw, encrypt_name_for};
use beebeeb_core::kdf::{FileKey, MasterKey, derive_file_key};
use beebeeb_core::owned_keys::{
    FolderWrap, KeyOrigin, resolve_owned_key, unwrap_child_key, unwrap_folder_custody, unwrap_owner_file_key,
    wrap_child_key, wrap_folder_custody, wrap_owner_file_key,
};

const FILE_ID: &str = "11111111-1111-8111-8111-111111111111";
const FOLDER_ID: &str = "22222222-2222-4222-8222-222222222222";
const OWNER_CHILD: &str = "000102030405060708090a0b8445b9d6a50527a6b0efec13ddca8e0ca7212f00d7e7502cf6e74373483ee447d1630e980ca0f3eb11e393badeec5269";
const FOLDER_CHILD: &str = "000102030405060708090a0b53e1dd8ab183dc0c6eddf3c784fb530e4436147ac012610979e5790104c1ca8d5c25fd93131629cf38285dae21a72b4f";
const FOLDER_CHILD_FOLDER: &str = "000102030405060708090a0b53e1dd8ab183dc0c6eddf3c784fb530e4436147ac012610979e5790104c1ca8d5aceac9fd4508b6ee48d87b6de2521fd";
const OWNER_ROOT: &str = "000102030405060708090a0be76dd2b5f6581ea20f0e3ef1730df58cb833f1c91ca6fbe931adc3cf50c1117b5e683d28ba2e1e04614014c4fbcd8572";

fn master() -> MasterKey {
    MasterKey::from_bytes(std::array::from_fn(|i| i as u8))
}

fn folder() -> FileKey {
    FileKey::from_bytes(std::array::from_fn(|i| 0x80 + i as u8))
}

fn child() -> FileKey {
    FileKey::from_bytes(std::array::from_fn(|i| 0xa0 + i as u8))
}

#[test]
fn owner_kat() {
    let master = master();
    let expected_child_key = *child().as_bytes();
    let unwrapped = unwrap_owner_file_key(&master, FILE_ID, &hex::decode(OWNER_CHILD).unwrap()).unwrap();
    assert_eq!(unwrapped.as_bytes(), &expected_child_key);
    let root = unwrap_folder_custody(&master, FOLDER_ID, &hex::decode(OWNER_ROOT).unwrap()).unwrap();
    assert_eq!(root.as_bytes(), folder().as_bytes());
    let custody = wrap_folder_custody(&master, FOLDER_ID, &root).unwrap();
    let second_custody = wrap_folder_custody(&master, FOLDER_ID, &root).unwrap();
    assert_ne!(&custody[..12], &second_custody[..12]);
    assert_eq!(
        unwrap_folder_custody(&master, FOLDER_ID, &custody).unwrap().as_bytes(),
        root.as_bytes()
    );

    let first = wrap_owner_file_key(&master, FILE_ID, &child()).unwrap();
    let second = wrap_owner_file_key(&master, FILE_ID, &child()).unwrap();
    assert_eq!(first.len(), 60);
    assert_ne!(&first[..12], &second[..12]);
    assert_eq!(
        unwrap_owner_file_key(&master, FILE_ID, &first).unwrap().as_bytes(),
        &expected_child_key
    );
    // Canonical textual UUID bytes, not the binary 16-byte UUID: an L8 record
    // is bound to the id TEXT, and a non-canonical id is refused outright
    // (task 2275 L12) before any AES-GCM work.
    assert!(
        beebeeb_core::kdf::wrap_owner_file_key(&master, uuid::Uuid::parse_str(FILE_ID).unwrap().as_bytes(), &child())
            .is_err()
    );
}

#[test]
fn folder_kat() {
    let folder = folder();
    let expected_child_key = *child().as_bytes();
    let unwrapped = unwrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &hex::decode(FOLDER_CHILD).unwrap()).unwrap();
    assert_eq!(unwrapped.as_bytes(), &expected_child_key);
    let first = wrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &child()).unwrap();
    let second = wrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &child()).unwrap();
    assert_eq!(first.len(), 60);
    assert_ne!(&first[..12], &second[..12]);
    assert_eq!(
        unwrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &first)
            .unwrap()
            .as_bytes(),
        &expected_child_key
    );
    assert!(unwrap_child_key(&child(), FOLDER_ID, FILE_ID, 1, &first).is_err());
    let folder_frame = hex::decode(FOLDER_CHILD_FOLDER).unwrap();
    assert_eq!(
        unwrap_child_key(&folder, FOLDER_ID, FILE_ID, 2, &folder_frame)
            .unwrap()
            .as_bytes(),
        &expected_child_key
    );
    assert!(unwrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &folder_frame).is_err());
}

#[test]
fn resolution_order() {
    let master = master();
    let folder = folder();
    let owner_wrap = hex::decode(OWNER_CHILD).unwrap();
    let different_child = FileKey::from_bytes([0x33; 32]);
    let folder_wrap = wrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &different_child).unwrap();
    let owner_name = encrypt_name_for(&child(), "owned.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
    let folder_name = encrypt_name_for(&different_child, "shared.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
    let resolve = |owner: Option<&[u8]>, frame: &[u8], name: &str| {
        resolve_owned_key(
            &master,
            FILE_ID,
            owner,
            Some(FolderWrap {
                folder_key: &folder,
                shared_folder_id: FOLDER_ID,
                kind: 1,
                wrapped_key: frame,
            }),
            name,
            None,
        )
        .unwrap()
    };
    let winner = resolve(Some(owner_wrap.as_slice()), folder_wrap.as_slice(), &owner_name);
    assert_eq!(winner.origin, KeyOrigin::OwnerWrap);
    assert_eq!(winner.key.as_bytes(), child().as_bytes());
    let invalid = [0; 60];
    for owner in [None, Some(invalid.as_slice())] {
        let recovered = resolve(owner, folder_wrap.as_slice(), &folder_name);
        assert_eq!(recovered.origin, KeyOrigin::FolderWrap);
        assert_eq!(recovered.key.as_bytes(), different_child.as_bytes());
    }
    let moved_out = resolve_owned_key(&master, FILE_ID, Some(&owner_wrap), None, &owner_name, None).unwrap();
    assert_eq!(moved_out.origin, KeyOrigin::OwnerWrap);
    assert_eq!(moved_out.key.as_bytes(), child().as_bytes());
    // The owner envelope's key must authenticate the name too: the shared
    // folder key's name does not open under the L8 key.
    assert!(resolve_owned_key(&master, FILE_ID, Some(&owner_wrap), None, &folder_name, None).is_err());
}

#[test]
fn foreign_never_derived() {
    let master = master();
    let folder = folder();
    let derived = derive_file_key(&master, FILE_ID.as_bytes());
    let derived_name = encrypt_name_for(&derived, "derived.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
    let invalid = [0; 60];
    for owner in [None, Some(invalid.as_slice())] {
        assert!(resolve_owned_key(&master, FILE_ID, owner, None, &derived_name, None).is_err());
        assert!(
            resolve_owned_key(
                &master,
                FILE_ID,
                owner,
                Some(FolderWrap {
                    folder_key: &folder,
                    shared_folder_id: FOLDER_ID,
                    kind: 1,
                    wrapped_key: &invalid,
                }),
                &derived_name,
                None,
            )
            .is_err()
        );
    }
    // Envelope presence with a name that does not authenticate blocks the row.
    for owner in [invalid.as_slice(), &[]] {
        assert!(resolve_owned_key(&master, FILE_ID, Some(owner), None, &derived_name, None).is_err());
    }
}

#[test]
fn invalid_frames() {
    let master = master();
    let folder = folder();
    for length in [0, 12, 28, 59, 61] {
        assert!(unwrap_owner_file_key(&master, FILE_ID, &vec![0; length]).is_err());
        assert!(unwrap_folder_custody(&master, FOLDER_ID, &vec![0; length]).is_err());
        assert!(unwrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &vec![0; length]).is_err());
    }
    // Authenticated frames with plaintext of the wrong size must also fail.
    for length in [0, 31, 33, 64] {
        let bytes = vec![0x55; length];
        let owner = encrypt_chunk_raw(&derive_file_key(&master, FILE_ID.as_bytes()), &bytes).unwrap();
        let child = encrypt_chunk_raw(&folder, &bytes).unwrap();
        assert!(unwrap_owner_file_key(&master, FILE_ID, &owner).is_err());
        assert!(unwrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &child).is_err());
    }
    for offset in [0, 12, 59] {
        let mut owner = hex::decode(OWNER_CHILD).unwrap();
        let mut child = hex::decode(FOLDER_CHILD).unwrap();
        owner[offset] ^= 1;
        child[offset] ^= 1;
        assert!(unwrap_owner_file_key(&master, FILE_ID, &owner).is_err());
        assert!(unwrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &child).is_err());
    }
}

#[test]
fn wrong_owner_or_id() {
    let frame = hex::decode(OWNER_CHILD).unwrap();
    assert!(unwrap_owner_file_key(&MasterKey::from_bytes([0xff; 32]), FILE_ID, &frame).is_err());
    assert!(unwrap_owner_file_key(&master(), FOLDER_ID, &frame).is_err());
}

#[test]
fn legacy_derived_unchanged() {
    const OWNER_FILE: &str = "66666666-6666-4666-8666-666666666666";
    let master = master();
    let resolved = resolve_owned_key(&master, OWNER_FILE, None, None, "legacy.bin", None).unwrap();
    assert_eq!(resolved.origin, KeyOrigin::Derived);
    assert_eq!(
        resolved.key.as_bytes(),
        derive_file_key(&master, OWNER_FILE.as_bytes()).as_bytes()
    );
    assert_eq!(
        resolved.name,
        beebeeb_core::owned_keys::ResolvedName::Plaintext("legacy.bin".into())
    );
    assert!(resolved.write_target.is_some());
    // An unrelated unusable folder inventory does not change ordinary owner files.
    let folder = folder();
    let resolved = resolve_owned_key(
        &master,
        OWNER_FILE,
        None,
        Some(FolderWrap {
            folder_key: &folder,
            shared_folder_id: FOLDER_ID,
            kind: 1,
            wrapped_key: &[],
        }),
        "legacy.bin",
        None,
    )
    .unwrap();
    assert_eq!(resolved.origin, KeyOrigin::Derived);
}

#[test]
fn folder_name_key_adoption() {
    const NESTED_ID: &str = "55555555-5555-8555-8555-555555555555"; // foreign (F)
    let master = master();
    let folder = folder();
    let random_key = child();
    assert_ne!(
        random_key.as_bytes(),
        derive_file_key(&master, NESTED_ID.as_bytes()).as_bytes()
    );
    let name = encrypt_name_for(
        &random_key,
        "Guest holiday folder",
        None,
        ExpectedChunkFormat::Unrecorded,
    )
    .unwrap();
    let frame = wrap_child_key(&folder, FOLDER_ID, NESTED_ID, 2, &random_key).unwrap();
    let resolved = resolve_owned_key(
        &master,
        NESTED_ID,
        None,
        Some(FolderWrap {
            folder_key: &folder,
            shared_folder_id: FOLDER_ID,
            kind: 2,
            wrapped_key: &frame,
        }),
        &name,
        None,
    )
    .unwrap();
    let metadata = decrypt_file_metadata_with_key(&resolved.key, &name).unwrap();
    assert_eq!(metadata.name, "Guest holiday folder");
    let adoption = wrap_owner_file_key(&master, NESTED_ID, &resolved.key).unwrap();
    let after_move = resolve_owned_key(&master, NESTED_ID, Some(&adoption), None, &name, None).unwrap();
    assert_eq!(after_move.origin, KeyOrigin::OwnerWrap);
    assert_eq!(after_move.key.as_bytes(), random_key.as_bytes());
    assert_eq!(
        decrypt_file_metadata_with_key(&after_move.key, &name).unwrap().name,
        metadata.name
    );
}

// Adapted from the independent rv-core45 review proof. The four regression
// cases stay separate from the original eight happy-path/selection cases.
mod review_l6_l7 {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    use beebeeb_core::chunk_stream::{ChunkDecryptor, ChunkEncryptor};
    use beebeeb_core::encrypt::encrypt_name;
    use beebeeb_types::EncryptedBlob;
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    const B: &str = "33333333-3333-8333-8333-333333333333";
    const OTHER_ROOT: &str = "44444444-4444-4444-8444-444444444444";

    #[test]
    fn custody_accepts_the_l6_hkdf_and_aad_contract() {
        let master = master();
        let mut context = b"beebeeb-folder-custody-v1".to_vec();
        context.extend_from_slice(FOLDER_ID.as_bytes());
        let raw_master = Zeroizing::new(master.to_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, raw_master.as_ref())
            .expand(&context, key.as_mut())
            .unwrap();
        let nonce = [0x37; 12];
        let folder = folder();
        // Independent AES-GCM/HKDF reference, not the adapter under test.
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: folder.as_bytes(),
                    aad: &context,
                },
            )
            .unwrap();
        let mut frame = nonce.to_vec();
        frame.extend_from_slice(&encrypted);
        let candidate = unwrap_folder_custody(&master, FOLDER_ID, &frame).unwrap();
        assert_eq!(candidate.as_bytes(), folder.as_bytes());
        let shipped = wrap_folder_custody(&master, FOLDER_ID, &folder).unwrap();
        assert_eq!(shipped.len(), 60);
        assert_eq!(
            unwrap_folder_custody(&master, FOLDER_ID, &shipped).unwrap().as_bytes(),
            folder.as_bytes()
        );
        assert!(unwrap_folder_custody(&master, OTHER_ROOT, &shipped).is_err());
        assert!(unwrap_folder_custody(&MasterKey::from_bytes([0xff; 32]), FOLDER_ID, &shipped).is_err());
    }

    #[test]
    fn custody_rejects_name_and_content_confusion() {
        let master = master();
        // A four-character legacy name has exactly 32 authenticated JSON bytes.
        let name = encrypt_name(&master, FOLDER_ID, "test", None).unwrap();
        let blob: EncryptedBlob = serde_json::from_str(&name).unwrap();
        let mut frame = blob.nonce;
        frame.extend_from_slice(&blob.ciphertext);
        assert_eq!(frame.len(), 60);
        assert!(unwrap_folder_custody(&master, FOLDER_ID, &frame).is_err());
        let custody = wrap_folder_custody(&master, FOLDER_ID, &folder()).unwrap();
        let mut content = ChunkDecryptor::for_push_with_file_key(
            derive_file_key(&master, FOLDER_ID.as_bytes()),
            FOLDER_ID,
            ExpectedChunkFormat::Unrecorded,
        );
        assert!(content.push_frame(&custody).is_err());
        // Never upgrade an old unbound custody frame by silently reading it.
        let old = encrypt_chunk_raw(&derive_file_key(&master, FOLDER_ID.as_bytes()), folder().as_bytes()).unwrap();
        assert!(unwrap_folder_custody(&master, FOLDER_ID, &old).is_err());
    }

    #[test]
    fn folder_child_swap_cannot_authenticate_as_another_item() {
        let master = master();
        let folder = folder();
        let child_a = child();
        let child_b = FileKey::from_bytes([0xb1; 32]);
        let name_a = encrypt_name_for(&child_a, "invoice.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
        let name_b = encrypt_name_for(&child_b, "invoice.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
        let wrap_a = wrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &child_a).unwrap();
        let wrap_b = wrap_child_key(&folder, FOLDER_ID, B, 1, &child_b).unwrap();
        let legit = resolve_owned_key(
            &master,
            B,
            None,
            Some(FolderWrap {
                folder_key: &folder,
                shared_folder_id: FOLDER_ID,
                kind: 1,
                wrapped_key: &wrap_b,
            }),
            &name_b,
            None,
        )
        .unwrap();
        assert_eq!(legit.key.as_bytes(), child_b.as_bytes());
        let data_a = b"different logical item";
        let mut enc = ChunkEncryptor::for_push_with_file_key(child_a, FILE_ID, data_a.len() as u64, 32).unwrap();
        let content_a = enc.push_chunk(data_a).unwrap();
        enc.finish().unwrap();
        // A server replays A's wrap, authenticated name and v1 bytes on B's row.
        let attack = (|| -> Result<Vec<u8>, beebeeb_core::CoreError> {
            let resolved = resolve_owned_key(
                &master,
                B,
                None,
                Some(FolderWrap {
                    folder_key: &folder,
                    shared_folder_id: FOLDER_ID,
                    kind: 1,
                    wrapped_key: &wrap_a,
                }),
                &name_a,
                None,
            )?;
            let metadata = decrypt_file_metadata_with_key(&resolved.key, &name_a)?;
            let mut dec = ChunkDecryptor::for_push_with_file_key(resolved.key, B, metadata.chunk_format);
            let plaintext = dec.push_frame(&content_a.data)?.data;
            dec.finish()?;
            Ok(plaintext)
        })();
        assert!(attack.is_err());
    }

    #[test]
    fn folder_child_rejects_other_root_kind_and_unbound_frame() {
        let master = master();
        let folder = folder();
        let frame = wrap_child_key(&folder, FOLDER_ID, FILE_ID, 1, &child()).unwrap();
        let name = encrypt_name_for(&child(), "x.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
        let resolve = |root, kind, frame| {
            resolve_owned_key(
                &master,
                FILE_ID,
                None,
                Some(FolderWrap {
                    folder_key: &folder,
                    shared_folder_id: root,
                    kind,
                    wrapped_key: frame,
                }),
                &name,
                None,
            )
        };
        assert_eq!(
            resolve(FOLDER_ID, 1, &frame).unwrap().key.as_bytes(),
            child().as_bytes()
        );
        assert!(resolve(OTHER_ROOT, 1, &frame).is_err());
        assert!(resolve(FOLDER_ID, 2, &frame).is_err());
        assert!(resolve(FOLDER_ID, 0, &frame).is_err());
        assert!(resolve("invalid-root", 1, &frame).is_err());
        let unbound = encrypt_chunk_raw(&folder, child().as_bytes()).unwrap();
        assert!(resolve(FOLDER_ID, 1, &unbound).is_err());
    }
}

// L8 regressions: the old opener accepted content, names and legacy owner wraps.
#[test]
fn l8_owner_rejects_own_v1_content_frame() {
    let master = master();
    let content_key = derive_file_key(&master, FILE_ID.as_bytes());
    let known_content = [0x55; 32];
    let frame = encrypt_chunk_raw(&content_key, &known_content).unwrap();
    assert_eq!(frame.len(), 60);
    assert_eq!(
        beebeeb_core::encrypt::decrypt_chunk_raw(&content_key, &frame).unwrap(),
        known_content
    );
    assert!(
        unwrap_owner_file_key(&master, FILE_ID, &frame).is_err(),
        "v1 content accepted as owner wrap"
    );
}

#[test]
fn l8_owner_rejects_own_legacy_name_envelope() {
    let master = master();
    let name = beebeeb_core::encrypt::encrypt_name(&master, FILE_ID, "test", None).unwrap();
    let blob: beebeeb_types::EncryptedBlob = serde_json::from_str(&name).unwrap();
    let plaintext = beebeeb_core::encrypt::decrypt_chunk(&derive_file_key(&master, FILE_ID.as_bytes()), &blob).unwrap();
    assert_eq!(plaintext, br#"{"mime_type":null,"name":"test"}"#);
    let frame = [blob.nonce, blob.ciphertext].concat();
    assert_eq!(frame.len(), 60, "fixture must pass the old length gate");
    assert!(
        unwrap_owner_file_key(&master, FILE_ID, &frame).is_err(),
        "legacy name accepted as owner wrap"
    );
}

#[test]
fn l8_resolver_never_reads_legacy_owner_format() {
    let master = master();
    let old = encrypt_chunk_raw(&derive_file_key(&master, FILE_ID.as_bytes()), child().as_bytes()).unwrap();
    let name = encrypt_name_for(&child(), "x.txt", None, ExpectedChunkFormat::Unrecorded).unwrap();
    assert!(
        resolve_owned_key(&master, FILE_ID, Some(&old), None, &name, None).is_err(),
        "resolver accepted legacy owner wrap"
    );
}

#[test]
fn l8_owner_wrap_binds_item_and_purpose() {
    let master = master();
    let wrap = wrap_owner_file_key(&master, FILE_ID, &child()).unwrap();
    assert_eq!(
        unwrap_owner_file_key(&master, FILE_ID, &wrap).unwrap().as_bytes(),
        child().as_bytes()
    );
    assert!(unwrap_owner_file_key(&master, FOLDER_ID, &wrap).is_err());
    assert!(unwrap_folder_custody(&master, FILE_ID, &wrap).is_err());
    let custody = wrap_folder_custody(&master, FILE_ID, &child()).unwrap();
    assert!(unwrap_owner_file_key(&master, FILE_ID, &custody).is_err());
}
