//! Task 2275 L12/L13/L14: item id classes, the resolver's write shapes,
//! request rows and the child-wrap equality check.
#![allow(deprecated)]

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use beebeeb_core::chunk_stream::ExpectedChunkFormat;
use beebeeb_core::encrypt::{
    decrypt_file_metadata_with_key, encrypt_chunk_raw, encrypt_name_for, encrypt_name_with_chunk_format,
};
use beebeeb_core::file_request::{seal_to_request, wrap_request_private};
use beebeeb_core::item_id::{ItemClass, NewItemId, is_foreign_item_id, item_class};
use beebeeb_core::kdf::{FileKey, MasterKey, derive_file_key};
use beebeeb_core::opaque::derive_x25519_public;
use beebeeb_core::owned_keys::{
    FirstChunk, FolderWrap, ItemKind, KeyOrigin, RequestSeal, ResolvedName, child_wrap_matches, resolve_owned_key,
    resolve_request_row, unwrap_child_key, wrap_child_key, wrap_owner_file_key,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// A foreign (F) id.
const F_ID: &str = "11111111-1111-8111-8111-111111111111";
/// A second foreign (F) id.
const F_ID_2: &str = "33333333-3333-8333-8333-333333333333";
/// An owner (O) id (version 4).
const O_ID: &str = "66666666-6666-4666-8666-666666666666";
/// Another owner (O) id (version 4).
const O_ID_2: &str = "abcdefab-cdef-4abc-8def-abcdefabcdef";
/// A shared root id (only its 16 bytes matter for L7).
const ROOT: &str = "77777777-7777-4777-8777-777777777777";

fn master() -> MasterKey {
    MasterKey::from_bytes(std::array::from_fn(|i| i as u8))
}

fn folder() -> FileKey {
    FileKey::from_bytes(std::array::from_fn(|i| 0x80 + i as u8))
}

fn other() -> FileKey {
    FileKey::from_bytes([0x44; 32])
}

fn name_for(key: &FileKey, name: &str) -> String {
    encrypt_name_for(key, name, None, ExpectedChunkFormat::Unrecorded).unwrap()
}

fn chunk_of(key: &FileKey, data: &[u8]) -> Vec<u8> {
    encrypt_chunk_raw(key, data).unwrap()
}

fn split_chunk(frame: &[u8], index: u32) -> FirstChunk<'_> {
    FirstChunk {
        nonce: &frame[..12],
        ciphertext: &frame[12..],
        index,
    }
}

/// An L8 envelope for `item_id` built independently of core's writer.
fn l8_frame(master: &MasterKey, item_id: &str, key: &FileKey) -> Vec<u8> {
    let mut context = b"beebeeb-owner-file-key-v1".to_vec();
    context.extend_from_slice(item_id.as_bytes());
    let raw_master = Zeroizing::new(master.to_bytes());
    let mut derived = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, raw_master.as_ref())
        .expand(&context, derived.as_mut())
        .unwrap();
    let nonce = [0x5a; 12];
    let cipher = Aes256Gcm::new_from_slice(derived.as_ref()).unwrap();
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: key.as_bytes(),
                aad: &context,
            },
        )
        .unwrap();
    [nonce.to_vec(), sealed].concat()
}

// ── A1: an owner row never adopts a wrap ─────────────────────────────

#[test]
fn a1_owner_row_never_uses_a_child_wrap() {
    let master = master();
    let key = other();
    let name = name_for(&key, "wrapped.txt");
    let wrap = wrap_child_key(&folder(), ROOT, O_ID, 1, &key).unwrap();
    let result = resolve_owned_key(
        &master,
        O_ID,
        ItemKind::File,
        None,
        Some(FolderWrap {
            shared_folder_id: ROOT,
            kind: 1,
            folder_key: &folder(),
            wrapped_key: &wrap,
        }),
        &name,
        None,
    );
    assert!(result.is_err(), "owner row adopted the shared-folder key");
}

// ── A3: an owner row ignores an L8 envelope ──────────────────────────

#[test]
fn a3_owner_row_ignores_an_l8_envelope() {
    let master = master();
    let envelope = l8_frame(&master, O_ID, &other());
    let derived = derive_file_key(&master, O_ID.as_bytes());
    let name = name_for(&derived, "mine.txt");
    let resolved = resolve_owned_key(&master, O_ID, ItemKind::File, Some(&envelope), None, &name, None).unwrap();
    assert_eq!(resolved.origin, KeyOrigin::Derived);
    assert_eq!(resolved.key.as_bytes(), derived.as_bytes());
    assert_ne!(resolved.key.as_bytes(), other().as_bytes());
}

#[test]
fn a3_l8_refuses_owner_ids_for_wrap_and_unwrap() {
    let master = master();
    assert!(wrap_owner_file_key(&master, O_ID, &other()).is_err());
    let envelope = l8_frame(&master, O_ID, &other());
    assert!(beebeeb_core::owned_keys::unwrap_owner_file_key(&master, O_ID, &envelope).is_err());
    // Foreign ids still work.
    assert!(wrap_owner_file_key(&master, F_ID, &other()).is_ok());
}

// ── A5/A6: foreign rows resolve only by envelope or wrap ─────────────

#[test]
fn a5_foreign_row_resolves_by_l8_then_by_child_wrap() {
    let master = master();
    let key = other();
    let name = name_for(&key, "adopted.txt");
    let envelope = wrap_owner_file_key(&master, F_ID, &key).unwrap();
    let by_envelope = resolve_owned_key(&master, F_ID, ItemKind::File, Some(&envelope), None, &name, None).unwrap();
    assert_eq!(by_envelope.origin, KeyOrigin::OwnerWrap);
    assert_eq!(by_envelope.key.as_bytes(), key.as_bytes());
    let target = by_envelope.write_target.as_ref().expect("adopted row is writable");
    assert_eq!(target.item_id(), F_ID);
    assert_eq!(target.key().as_bytes(), key.as_bytes());
    assert_eq!(target.pin(), ExpectedChunkFormat::Unrecorded);

    let key_2 = FileKey::from_bytes([0x55; 32]);
    let name_2 = name_for(&key_2, "in-folder.txt");
    let wrap = wrap_child_key(&folder(), ROOT, F_ID_2, 1, &key_2).unwrap();
    let by_wrap = resolve_owned_key(
        &master,
        F_ID_2,
        ItemKind::File,
        None,
        Some(FolderWrap {
            shared_folder_id: ROOT,
            kind: 1,
            folder_key: &folder(),
            wrapped_key: &wrap,
        }),
        &name_2,
        None,
    )
    .unwrap();
    assert_eq!(by_wrap.origin, KeyOrigin::FolderWrap);
    assert_eq!(by_wrap.key.as_bytes(), key_2.as_bytes());
    assert!(by_wrap.write_target.is_some());
}

#[test]
fn a5_foreign_row_needs_the_wrap_key_to_authenticate_the_name() {
    let master = master();
    let key = other();
    // The envelope opens, but the name was sealed under a different key.
    let envelope = wrap_owner_file_key(&master, F_ID, &key).unwrap();
    let name = name_for(&derive_file_key(&master, F_ID.as_bytes()), "theirs.txt");
    assert!(resolve_owned_key(&master, F_ID, ItemKind::File, Some(&envelope), None, &name, None).is_err());
}

#[test]
fn a6_foreign_row_never_derives_a_key() {
    let master = master();
    let derived = derive_file_key(&master, F_ID.as_bytes());
    let name = name_for(&derived, "looks-owner.txt");
    assert!(resolve_owned_key(&master, F_ID, ItemKind::File, None, None, &name, None).is_err());
    let invalid = [0u8; 60];
    assert!(resolve_owned_key(&master, F_ID, ItemKind::File, Some(&invalid), None, &name, None).is_err());
}

// ── A23 / A25 ────────────────────────────────────────────────────────

#[test]
fn a23_non_canonical_ids_are_refused() {
    let lettered = "aaaaaaaa-bbbb-8ccc-9ddd-eeeeeeeeeeee";
    let upper = lettered.to_uppercase();
    let braced = format!("{{{lettered}}}");
    for bad in [upper.as_str(), braced.as_str()] {
        assert!(matches!(
            is_foreign_item_id(bad),
            Err(beebeeb_core::CoreError::InvalidInput(_))
        ));
        assert!(matches!(item_class(bad), Err(beebeeb_core::CoreError::InvalidInput(_))));
        assert!(resolve_owned_key(&master(), bad, ItemKind::File, None, None, "x.txt", None).is_err());
    }
}

#[test]
fn a25_uppercase_sealed_owner_row_is_derived_upper_repair_and_read_only() {
    let master = master();
    let upper_key = derive_file_key(&master, O_ID_2.to_uppercase().as_bytes());
    let name = name_for(&upper_key, "iphone-file.txt");
    let resolved = resolve_owned_key(&master, O_ID_2, ItemKind::File, None, None, &name, None).unwrap();
    assert_eq!(resolved.origin, KeyOrigin::DerivedUpperRepair);
    assert_eq!(resolved.key.as_bytes(), upper_key.as_bytes());
    assert!(
        resolved.write_target.is_none(),
        "an upper-repair row must stay read-only"
    );
}

// ── Owner conventions ────────────────────────────────────────────────

#[test]
fn owner_conventions_string_then_binary() {
    let master = master();
    let string_key = derive_file_key(&master, O_ID.as_bytes());
    let name = name_for(&string_key, "string.txt");
    let resolved = resolve_owned_key(&master, O_ID, ItemKind::File, None, None, &name, None).unwrap();
    assert_eq!(resolved.origin, KeyOrigin::Derived);
    assert_eq!(
        resolved.write_target.as_ref().unwrap().pin(),
        ExpectedChunkFormat::Unrecorded
    );

    let binary_key = derive_file_key(&master, uuid::Uuid::parse_str(O_ID).unwrap().as_bytes());
    let name = name_for(&binary_key, "binary.txt");
    let resolved = resolve_owned_key(&master, O_ID, ItemKind::File, None, None, &name, None).unwrap();
    assert_eq!(resolved.origin, KeyOrigin::DerivedBinary);
    assert_eq!(resolved.key.as_bytes(), binary_key.as_bytes());
    assert!(resolved.write_target.is_some());
}

// ── Plaintext names ──────────────────────────────────────────────────

#[test]
fn plaintext_folder_uses_the_string_convention() {
    let master = master();
    let resolved = resolve_owned_key(&master, O_ID, ItemKind::Folder, None, None, "Legacy folder", None).unwrap();
    assert_eq!(resolved.origin, KeyOrigin::Derived);
    assert_eq!(
        resolved.key.as_bytes(),
        derive_file_key(&master, O_ID.as_bytes()).as_bytes()
    );
    assert_eq!(resolved.name, ResolvedName::Plaintext("Legacy folder".into()));
}

#[test]
fn plaintext_file_is_picked_by_chunk_zero() {
    let master = master();
    let binary_key = derive_file_key(&master, uuid::Uuid::parse_str(O_ID).unwrap().as_bytes());
    let frame = chunk_of(&binary_key, b"content");
    let resolved = resolve_owned_key(
        &master,
        O_ID,
        ItemKind::File,
        None,
        None,
        "legacy.bin",
        Some(split_chunk(&frame, 0)),
    )
    .unwrap();
    assert_eq!(resolved.origin, KeyOrigin::DerivedBinary);
    assert_eq!(resolved.key.as_bytes(), binary_key.as_bytes());

    // A later chunk, or a chunk under an unknown key, cannot identify the row.
    assert!(
        resolve_owned_key(
            &master,
            O_ID,
            ItemKind::File,
            None,
            None,
            "legacy.bin",
            Some(split_chunk(&frame, 1))
        )
        .is_err()
    );
    let stranger = chunk_of(&other(), b"content");
    assert!(
        resolve_owned_key(
            &master,
            O_ID,
            ItemKind::File,
            None,
            None,
            "legacy.bin",
            Some(split_chunk(&stranger, 0))
        )
        .is_err()
    );
}

#[test]
fn split_row_reports_the_content_key_and_stays_read_only() {
    let master = master();
    // A row id with hex letters, so the uppercase convention is a distinct derive.
    let name_key = derive_file_key(&master, O_ID_2.as_bytes());
    let name = name_for(&name_key, "split.txt");
    // The stored version was sealed under the uppercase (upper-repair) convention.
    let content_key = derive_file_key(&master, O_ID_2.to_uppercase().as_bytes());
    let frame = chunk_of(&content_key, b"content");
    let resolved = resolve_owned_key(
        &master,
        O_ID_2,
        ItemKind::File,
        None,
        None,
        &name,
        Some(split_chunk(&frame, 0)),
    )
    .unwrap();
    assert_eq!(resolved.origin, KeyOrigin::Derived);
    assert_eq!(resolved.key.as_bytes(), name_key.as_bytes());
    let split = resolved
        .content_key
        .as_ref()
        .expect("an SF-0002 split row must expose the content key separately");
    assert_eq!(split.as_bytes(), content_key.as_bytes());
    assert!(
        resolved.write_target.is_none(),
        "an upper-repair content key must make the whole row read-only"
    );

    // When the name and the version agree there is no split key and the row stays writable.
    let same = chunk_of(&name_key, b"content");
    let resolved = resolve_owned_key(
        &master,
        O_ID_2,
        ItemKind::File,
        None,
        None,
        &name,
        Some(split_chunk(&same, 0)),
    )
    .unwrap();
    assert!(resolved.content_key.is_none());
    assert!(resolved.write_target.is_some());
}

// ── NewItemId / write shapes ─────────────────────────────────────────

#[test]
fn new_item_ids_are_core_minted_and_class_correct() {
    let master = master();
    let owner = NewItemId::owner(&master).unwrap();
    let foreign = NewItemId::foreign(&master).unwrap();
    assert_eq!(item_class(owner.as_str()).unwrap(), ItemClass::Owner);
    assert_eq!(item_class(foreign.as_str()).unwrap(), ItemClass::Foreign);
    assert!(is_foreign_item_id(foreign.as_str()).unwrap());
    assert_eq!(owner.as_str().len(), 36);
}

#[test]
fn new_item_and_target_sealers_use_the_derived_key() {
    let master = master();
    let id = NewItemId::owner(&master).unwrap();
    let sealed = beebeeb_core::encrypt::encrypt_name_for_new_item(
        &master,
        &id,
        "new.txt",
        Some("text/plain"),
        ExpectedChunkFormat::Unrecorded,
    )
    .unwrap();
    let meta = decrypt_file_metadata_with_key(&derive_file_key(&master, id.as_str().as_bytes()), &sealed).unwrap();
    assert_eq!(meta.name, "new.txt");
    assert_eq!(meta.mime_type.as_deref(), Some("text/plain"));

    // A foreign new id cannot be sealed before adoption.
    let foreign = NewItemId::foreign(&master).unwrap();
    assert!(
        beebeeb_core::encrypt::encrypt_name_for_new_item(
            &master,
            &foreign,
            "new.txt",
            None,
            ExpectedChunkFormat::Unrecorded,
        )
        .is_err()
    );

    // A replacement name goes through the resolved row's target, same key.
    let name = name_for(&derive_file_key(&master, O_ID.as_bytes()), "old.txt");
    let resolved = resolve_owned_key(&master, O_ID, ItemKind::File, None, None, &name, None).unwrap();
    let target = resolved.write_target.as_ref().unwrap();
    let replaced = beebeeb_core::encrypt::encrypt_name_for_target(target, "renamed.txt", None).unwrap();
    assert_eq!(
        decrypt_file_metadata_with_key(target.key(), &replaced).unwrap().name,
        "renamed.txt"
    );
}

// ── Request rows (2236) ──────────────────────────────────────────────

struct RequestFixture {
    master: MasterKey,
    item_id: String,
    request_id: Vec<u8>,
    wrapped_private: Vec<u8>,
    wrap_nonce: Vec<u8>,
    e_pub: [u8; 32],
    wrapped_content_key: Vec<u8>,
    content_key: [u8; 32],
}

fn request_fixture() -> RequestFixture {
    request_fixture_for(O_ID)
}

fn request_fixture_for(item_id: &str) -> RequestFixture {
    let master = master();
    let request_id = vec![0x01; 16];
    let request_private = [0x11u8; 32];
    let request_public = derive_x25519_public(&request_private);
    let content_key = [0x22u8; 32];
    let (wrapped_private, wrap_nonce) = wrap_request_private(&master, &request_id, &request_private).unwrap();
    let sealed = seal_to_request(&request_public, item_id.as_bytes(), &content_key).unwrap();
    RequestFixture {
        master,
        item_id: item_id.to_string(),
        request_id,
        wrapped_private,
        wrap_nonce,
        e_pub: sealed.e_pub,
        wrapped_content_key: sealed.wrapped_key,
        content_key,
    }
}

/// What `web/src/pages/upload-request.tsx` and `bb request send` write: the
/// request-private wrap and the per-upload seal both use the EMPTY id (the
/// 2236 convention), and the name is sealed under the content key `C`.
fn shipped_request_fixture() -> RequestFixture {
    shipped_request_fixture_for(O_ID)
}

fn shipped_request_fixture_for(item_id: &str) -> RequestFixture {
    let master = master();
    let request_private = [0x11u8; 32];
    let request_public = derive_x25519_public(&request_private);
    let content_key = [0x22u8; 32];
    let (wrapped_private, wrap_nonce) = wrap_request_private(&master, b"", &request_private).unwrap();
    let sealed = seal_to_request(&request_public, b"", &content_key).unwrap();
    RequestFixture {
        master,
        item_id: item_id.to_string(),
        request_id: Vec::new(),
        wrapped_private,
        wrap_nonce,
        e_pub: sealed.e_pub,
        wrapped_content_key: sealed.wrapped_key,
        content_key,
    }
}

impl RequestFixture {
    fn resolve(&self, name: &str) -> Result<beebeeb_core::owned_keys::RequestRowKeys, beebeeb_core::CoreError> {
        resolve_request_row(
            &self.master,
            &self.item_id,
            &self.request_id,
            &self.wrapped_private,
            &self.wrap_nonce,
            &self.e_pub,
            &self.wrapped_content_key,
            name,
        )
    }
}

#[test]
fn shipped_unbound_request_row_opens_and_is_marked_unbound() {
    let fixture = shipped_request_fixture();
    let content = FileKey::from_bytes(fixture.content_key);
    let name = name_for(&content, "upload.bin");
    let row = fixture
        .resolve(&name)
        .expect("a row sealed exactly as the web/CLI uploader writes it must open");
    assert_eq!(row.content_key.as_bytes(), &fixture.content_key);
    assert_eq!(row.name_origin, KeyOrigin::RequestContent);
    assert_eq!(row.seal, RequestSeal::Unbound);
}

#[test]
fn shipped_request_wrap_requires_the_empty_context() {
    // Every shipped request wraps its private key under the EMPTY context (the
    // server mints the request id after the wrap). Passing the real id must
    // refuse with a clear error, never retry the empty context silently.
    let fixture = shipped_request_fixture();
    let content = FileKey::from_bytes(fixture.content_key);
    let name = name_for(&content, "upload.bin");
    let real_request_id = [0x01u8; 16];
    let err = resolve_request_row(
        &fixture.master,
        &fixture.item_id,
        &real_request_id,
        &fixture.wrapped_private,
        &fixture.wrap_nonce,
        &fixture.e_pub,
        &fixture.wrapped_content_key,
        &name,
    )
    .err()
    .expect("a shipped row must not unwrap under a real request id");
    assert!(
        err.to_string().contains("request_wrap_context"),
        "the refusal must name the context to pass: {err}"
    );

    // The empty context (what every shipped request uses) opens.
    let row = fixture.resolve(&name).unwrap();
    assert_eq!(row.seal, RequestSeal::Unbound);
}

#[test]
fn bound_request_row_is_marked_bound() {
    let fixture = request_fixture();
    let derived = derive_file_key(&fixture.master, fixture.item_id.as_bytes());
    let name = name_for(&derived, "upload.bin");
    let row = fixture.resolve(&name).unwrap();
    assert_eq!(row.content_key.as_bytes(), &fixture.content_key);
    assert_eq!(row.name_origin, KeyOrigin::Derived);
    assert_eq!(row.seal, RequestSeal::Bound);
}

#[test]
fn request_row_class_and_name_checks_precede_any_open() {
    let fixture = shipped_request_fixture();
    let content = FileKey::from_bytes(fixture.content_key);
    let name = name_for(&content, "upload.bin");

    // The envelope would open unbound, so only the class check can refuse it.
    let err = resolve_request_row(
        &fixture.master,
        F_ID,
        &fixture.request_id,
        &fixture.wrapped_private,
        &fixture.wrap_nonce,
        &fixture.e_pub,
        &fixture.wrapped_content_key,
        &name,
    )
    .err()
    .expect("a foreign id must be refused before any open");
    assert!(
        err.to_string().contains("request row class check"),
        "a foreign id must be refused by class before any open: {err}"
    );

    // The crypto cannot even unwrap here. If the class check ran after the
    // opens, this row would report a decryption failure instead.
    let err = resolve_request_row(
        &fixture.master,
        F_ID,
        &fixture.request_id,
        &[0u8; 32],
        &[0u8; 12],
        &fixture.e_pub,
        &fixture.wrapped_content_key,
        &name,
    )
    .err()
    .expect("a foreign id must be refused before the unwrap");
    assert!(
        err.to_string().contains("request row class check"),
        "with crypto that cannot unwrap, the class check must still win: {err}"
    );

    // A plaintext name authenticates nothing and must be refused before any open.
    let err = fixture
        .resolve("upload.bin")
        .err()
        .expect("a plaintext name must be refused");
    assert!(
        err.to_string().contains("request row name check"),
        "a plaintext name must be refused before any open: {err}"
    );
}

#[test]
fn request_row_carries_a_rename_target_unless_upper_repair() {
    // A string-convention name keeps its recorded pin and its derived name key.
    let fixture = request_fixture();
    let name = encrypt_name_with_chunk_format(
        &fixture.master,
        &fixture.item_id,
        "upload.bin",
        None,
        ExpectedChunkFormat::V2,
    )
    .unwrap();
    let row = fixture.resolve(&name).unwrap();
    let target = row
        .rename_target
        .expect("a string-convention row must have a rename target");
    assert_eq!(target.origin(), KeyOrigin::Derived);
    assert_eq!(target.pin(), ExpectedChunkFormat::V2);
    assert_eq!(target.key().as_bytes(), row.name_key.as_bytes());
    assert_eq!(
        target.key().as_bytes(),
        derive_file_key(&fixture.master, fixture.item_id.as_bytes()).as_bytes()
    );

    // An upper-repair name is READ-ONLY: no rename target.
    let fixture = request_fixture_for(O_ID_2);
    let upper = O_ID_2.to_ascii_uppercase();
    let name = encrypt_name_with_chunk_format(
        &fixture.master,
        &upper,
        "upload.bin",
        None,
        ExpectedChunkFormat::Unrecorded,
    )
    .unwrap();
    let row = fixture.resolve(&name).unwrap();
    assert_eq!(row.name_origin, KeyOrigin::DerivedUpperRepair);
    assert!(row.rename_target.is_none(), "an upper-repair name is read-only");
}

#[test]
fn request_row_rename_target_is_never_the_content_key() {
    // A row whose name is under C (the shipped uploader's name): the uploader
    // holds C, so a rename sealed under C would hand the owner's new name to
    // the uploader. §15: the target is ALWAYS the string-convention key.
    let fixture = shipped_request_fixture();
    let content = FileKey::from_bytes(fixture.content_key);
    let name = encrypt_name_for(&content, "upload.bin", None, ExpectedChunkFormat::V2).unwrap();
    let row = fixture.resolve(&name).unwrap();
    assert_eq!(row.name_origin, KeyOrigin::RequestContent);
    let target = row
        .rename_target
        .expect("the row is writable, so it must carry a rename target");
    let derived = derive_file_key(&fixture.master, fixture.item_id.as_bytes());
    assert_eq!(target.origin(), KeyOrigin::Derived);
    assert_eq!(target.pin(), ExpectedChunkFormat::V2);
    assert_eq!(target.key().as_bytes(), derived.as_bytes());
    assert_ne!(
        target.key().as_bytes(),
        &fixture.content_key,
        "the rename target must never be the content key C"
    );
}

#[test]
fn unbound_request_row_refuses_a_binary_convention_name() {
    let fixture = shipped_request_fixture();
    let binary = uuid::Uuid::parse_str(O_ID).unwrap();
    let binary_key = derive_file_key(&fixture.master, binary.as_bytes());
    let name = name_for(&binary_key, "upload.bin");
    let err = fixture
        .resolve(&name)
        .err()
        .expect("the unbound row must refuse a binary name");
    assert!(
        err.to_string().contains("string convention"),
        "an unbound row's name resolves only under the string convention: {err}"
    );
}

#[test]
fn unbound_request_row_name_under_the_string_key_is_derived() {
    // A shipped row (empty contexts) that an old client renamed: the new name
    // is sealed under the string-convention key, so an unbound row must open
    // it as Derived, not fall through to C (A9c).
    let fixture = shipped_request_fixture();
    let derived = derive_file_key(&fixture.master, fixture.item_id.as_bytes());
    let name = encrypt_name_for(&derived, "renamed.bin", None, ExpectedChunkFormat::V2).unwrap();
    let row = fixture
        .resolve(&name)
        .expect("an unbound row's string-convention name must open");
    assert_eq!(row.seal, RequestSeal::Unbound);
    assert_eq!(row.name_origin, KeyOrigin::Derived);
    assert_eq!(row.name_key.as_bytes(), derived.as_bytes());
}

#[test]
fn unbound_request_row_refuses_an_upper_repair_name() {
    let fixture = shipped_request_fixture_for(O_ID_2);
    let upper = fixture.item_id.to_ascii_uppercase();
    let upper_key = derive_file_key(&fixture.master, upper.as_bytes());
    let name = name_for(&upper_key, "upload.bin");
    let err = fixture
        .resolve(&name)
        .err()
        .expect("the unbound row must refuse an upper-repair name");
    assert!(
        err.to_string().contains("string convention"),
        "an unbound row's name resolves only under the string convention: {err}"
    );
}

#[test]
fn request_row_content_is_under_c() {
    let fixture = request_fixture();
    let derived = derive_file_key(&fixture.master, O_ID.as_bytes());
    let name = name_for(&derived, "upload.bin");
    let row = fixture.resolve(&name).unwrap();
    assert_eq!(row.content_key.as_bytes(), &fixture.content_key);
    assert_eq!(row.name_origin, KeyOrigin::Derived);
    assert_eq!(row.name_key.as_bytes(), derived.as_bytes());
}

#[test]
fn request_row_name_can_be_under_c() {
    let fixture = request_fixture();
    let content = FileKey::from_bytes(fixture.content_key);
    let name = name_for(&content, "upload.bin");
    let row = fixture.resolve(&name).unwrap();
    assert_eq!(row.name_origin, KeyOrigin::RequestContent);
    assert_eq!(row.name_key.as_bytes(), &fixture.content_key);
}

#[test]
fn request_row_name_under_neither_is_an_error() {
    let fixture = request_fixture();
    let name = name_for(&other(), "upload.bin");
    assert!(fixture.resolve(&name).is_err());
}

#[test]
fn request_row_refuses_a_foreign_item_id() {
    let fixture = request_fixture();
    let derived = derive_file_key(&fixture.master, F_ID.as_bytes());
    let name = name_for(&derived, "upload.bin");
    let result = resolve_request_row(
        &fixture.master,
        F_ID,
        &fixture.request_id,
        &fixture.wrapped_private,
        &fixture.wrap_nonce,
        &fixture.e_pub,
        &fixture.wrapped_content_key,
        &name,
    );
    let err = match result {
        Ok(_) => panic!("a request row resolved for a foreign item id; foreign rows go through L8 or L7"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("owner item id"),
        "the refusal must be the class rule, not a side effect: {err}"
    );
}

// ── L14 child wrap equality ──────────────────────────────────────────

#[test]
fn child_wrap_matches_only_the_honest_wrap() {
    let folder = folder();
    let key = other();
    let wrap = wrap_child_key(&folder, ROOT, F_ID, 1, &key).unwrap();
    assert!(child_wrap_matches(&folder, ROOT, F_ID, 1, &wrap, &key));
    assert!(!child_wrap_matches(&folder, ROOT, F_ID_2, 1, &wrap, &key));
    assert!(!child_wrap_matches(&folder, ROOT, F_ID, 2, &wrap, &key));
    assert!(!child_wrap_matches(&folder, O_ID, F_ID, 1, &wrap, &key));
    assert!(!child_wrap_matches(
        &folder,
        ROOT,
        F_ID,
        1,
        &wrap,
        &FileKey::from_bytes([0x99; 32])
    ));
    assert!(!child_wrap_matches(&folder, ROOT, F_ID, 1, &wrap[..59], &key));
    let decayed = unwrap_child_key(&folder, ROOT, F_ID, 1, &wrap).unwrap();
    assert_eq!(decayed.as_bytes(), key.as_bytes());
}
