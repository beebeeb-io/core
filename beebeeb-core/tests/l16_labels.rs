//! L16 (task 2237/task 2275): link labels under the owner's purpose wrap,
//! guest actor names under a folder-key subkey bound to the root, and the one
//! legacy child opener that refuses a name-shaped 32-byte plaintext.
//!
//! Every test here runs against the public API only. The fixed-nonce opener
//! cases (an over-bound label, invalid UTF-8 under a valid tag) live in
//! `kdf`'s unit tests, where the vector seams exist.

use beebeeb_core::chunk_stream::ExpectedChunkFormat;
use beebeeb_core::encrypt::{decrypt_chunk, decrypt_name_with_key, encrypt_chunk, encrypt_name_for};
use beebeeb_core::kdf::{
    FileKey, MasterKey, open_folder_actor_name, open_legacy_child_key, seal_folder_actor_name, unwrap_folder_child,
    unwrap_folder_custody, unwrap_link_label, unwrap_link_owner_key, unwrap_owner_file_key, wrap_folder_child,
    wrap_link_label, wrap_link_owner_key, wrap_owner_file_key,
    unwrap_link_owner_token,
};
use beebeeb_core::CoreError;
use beebeeb_types::EncryptedBlob;

const SHARE_A: [u8; 16] = [0x11; 16];
const SHARE_B: [u8; 16] = [0x22; 16];
const ROOT_A: [u8; 16] = [0x31; 16];
const ROOT_B: [u8; 16] = [0x42; 16];
const ITEM: [u8; 16] = [0x53; 16];

fn master() -> MasterKey {
    MasterKey::from_bytes([0x40; 32])
}

fn folder_key() -> FileKey {
    FileKey::from_bytes([0x80; 32])
}

fn frame(blob: &EncryptedBlob) -> Vec<u8> {
    [blob.nonce.as_slice(), blob.ciphertext.as_slice()].concat()
}

fn json(blob: &EncryptedBlob) -> String {
    serde_json::to_string(blob).unwrap()
}

#[test]
fn label_round_trips_and_is_nfc() {
    let blob = wrap_link_label(&master(), &SHARE_A, "Cafe\u{301} photos").unwrap();
    assert_eq!(unwrap_link_label(&master(), &SHARE_A, &blob).unwrap(), "Café photos");
}

#[test]
fn label_is_bound_to_the_share_and_the_purpose() {
    let blob = wrap_link_label(&master(), &SHARE_A, "Trip").unwrap();

    // Bindings: another share id and another master key are both refused.
    assert!(matches!(
        unwrap_link_label(&master(), &SHARE_B, &blob),
        Err(CoreError::Decryption)
    ));
    assert!(matches!(
        unwrap_link_label(&MasterKey::from_bytes([0x41; 32]), &SHARE_A, &blob),
        Err(CoreError::Decryption)
    ));

    // Confusion matrix: a label frame is not an L6 owner wrap, custody, L8
    // envelope, L7 child wrap or an actor name.
    assert!(unwrap_link_owner_key(&master(), &SHARE_A, &blob).is_err());
    assert!(unwrap_link_owner_token(&master(), &SHARE_A, &blob).is_err());
    assert!(unwrap_folder_custody(&master(), &SHARE_A, &blob).is_err());
    assert!(unwrap_owner_file_key(&master(), &ITEM, &blob).is_err());
    assert!(
        unwrap_folder_child(&folder_key(), &ROOT_A, &ITEM, 1, &blob).is_err(),
        "a label frame opens as an L7 child wrap"
    );
    assert!(
        open_folder_actor_name(&folder_key(), &ROOT_A, &json(&blob)).is_err(),
        "a label frame opens as an actor name"
    );

    // Neither label nor actor name opens through the legacy child opener.
    assert!(open_legacy_child_key(&folder_key(), &frame(&blob)).is_none());
}

#[test]
fn actor_name_round_trips_and_is_bound_to_the_root_and_key() {
    let sealed = seal_folder_actor_name(&folder_key(), &ROOT_A, "Mama").unwrap();
    assert_eq!(open_folder_actor_name(&folder_key(), &ROOT_A, &sealed).unwrap(), "Mama");

    // Root A vs root B under the same key bytes.
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_B, &sealed),
        Err(CoreError::Decryption)
    ));
    // Another folder key.
    assert!(matches!(
        open_folder_actor_name(&FileKey::from_bytes([0x81; 32]), &ROOT_A, &sealed),
        Err(CoreError::Decryption)
    ));

    // Confusion matrix: the actor-name blob is not a label, not a name under
    // the raw folder key, not an L7 child wrap, not custody, and never opens
    // through the legacy child opener.
    let as_blob: EncryptedBlob = serde_json::from_str(&sealed).unwrap();
    assert!(unwrap_link_label(&master(), &SHARE_A, &as_blob).is_err());
    assert!(unwrap_link_owner_key(&master(), &SHARE_A, &as_blob).is_err());
    assert_eq!(decrypt_name_with_key(&folder_key(), &sealed), None);
    assert!(unwrap_folder_child(&folder_key(), &ROOT_A, &ITEM, 2, &as_blob).is_err());
    assert!(unwrap_folder_custody(&master(), &ROOT_A, &as_blob).is_err());
    assert!(open_legacy_child_key(&folder_key(), &frame(&as_blob)).is_none());
}

#[test]
fn actor_name_opener_strips_control_and_bidi_characters() {
    let sealed = seal_folder_actor_name(&folder_key(), &ROOT_A, "Ali\u{202E}ce\u{2066}\u{7}").unwrap();
    assert_eq!(open_folder_actor_name(&folder_key(), &ROOT_A, &sealed).unwrap(), "Alice");
}

#[test]
fn openers_refuse_wrong_shapes_and_bounds() {
    // A plaintext value that is not an envelope (no `{`).
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_A, "Mama"),
        Err(CoreError::Decryption)
    ));
    // The web `{nonce, ciphertext}` shape is not the writer's container.
    let short: EncryptedBlob = serde_json::from_str(
        &seal_folder_actor_name(&folder_key(), &ROOT_A, "Mama").unwrap(),
    )
    .unwrap();
    let web_shape = serde_json::json!({ "nonce": short.nonce, "ciphertext": short.ciphertext }).to_string();
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_A, &web_shape),
        Err(CoreError::Decryption)
    ));

    // Bounds: an empty and an over-bound label; an empty and an over-bound name.
    assert!(matches!(
        wrap_link_label(&master(), &SHARE_A, ""),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        wrap_link_label(&master(), &SHARE_A, &"x".repeat(41)),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        seal_folder_actor_name(&folder_key(), &ROOT_A, ""),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        seal_folder_actor_name(&folder_key(), &ROOT_A, &"x".repeat(65)),
        Err(CoreError::InvalidInput(_))
    ));

    // Ids: every new binding requires exactly 16 bytes.
    assert!(matches!(
        wrap_link_label(&master(), &[0u8; 15], "Trip"),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        unwrap_link_label(&master(), &[0u8; 15], &wrap_link_label(&master(), &SHARE_A, "Trip").unwrap()),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        seal_folder_actor_name(&folder_key(), &[0u8; 15], "Mama"),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        open_folder_actor_name(
            &folder_key(),
            &[0u8; 15],
            &seal_folder_actor_name(&folder_key(), &ROOT_A, "Mama").unwrap()
        ),
        Err(CoreError::InvalidInput(_))
    ));
}

#[test]
fn legacy_child_opener_round_trips_a_real_key_and_refuses_frames_off_shape() {
    let child = FileKey::from_bytes([0xF8; 32]);
    let blob = encrypt_chunk(&folder_key(), child.as_bytes()).unwrap();
    let frame = frame(&blob);

    assert_eq!(open_legacy_child_key(&folder_key(), &frame).unwrap().as_bytes(), child.as_bytes());
    // Wrong folder key, wrong frame length.
    assert!(open_legacy_child_key(&FileKey::from_bytes([0x81; 32]), &frame).is_none());
    assert!(open_legacy_child_key(&folder_key(), &frame[..59]).is_none());
    assert!(open_legacy_child_key(&folder_key(), &[0u8; 60]).is_none());
}

/// L16d, the red case: a 4-character label is a 32-byte plaintext, and today's
/// generic opener hands it back as if it were a child key. The legacy child
/// opener refuses it (L9 rule 1).
#[test]
fn l16d_name_shaped_plaintext_opens_generically_and_is_refused_as_a_child_key() {
    let name_shape: &[u8] = br#"{"name":"Mama","mime_type":null}"#;
    assert_eq!(name_shape.len(), 32, "the spec's 4-character label is 32 bytes");

    let blob = encrypt_chunk(&folder_key(), name_shape).unwrap();
    // The red: the generic opener returns the name, not a key.
    assert_eq!(decrypt_chunk(&folder_key(), &blob).unwrap(), name_shape);
    // The refusal that closes it.
    assert!(open_legacy_child_key(&folder_key(), &frame(&blob)).is_none());
}

#[test]
fn l7_and_l8_writers_still_produce_their_own_shapes() {
    // Guard: the new functions did not change the existing L6/L7/L8 bytes.
    let l7 = wrap_folder_child(&folder_key(), &ROOT_A, &ITEM, 1, &FileKey::from_bytes([0x0a; 32])).unwrap();
    assert_eq!(
        unwrap_folder_child(&folder_key(), &ROOT_A, &ITEM, 1, &l7).unwrap().as_bytes(),
        &[0x0a; 32]
    );
    let l8 = wrap_owner_file_key(&master(), &ITEM, &FileKey::from_bytes([0x0b; 32])).unwrap();
    assert_eq!(
        unwrap_owner_file_key(&master(), &ITEM, &l8).unwrap().as_bytes(),
        &[0x0b; 32]
    );
    let l6 = wrap_link_owner_key(&master(), &SHARE_A, &FileKey::from_bytes([0x0c; 32])).unwrap();
    assert_eq!(
        unwrap_link_owner_key(&master(), &SHARE_A, &l6).unwrap().as_bytes(),
        &[0x0c; 32]
    );
    let name = encrypt_name_for(&folder_key(), "report.pdf", None, ExpectedChunkFormat::Unrecorded).unwrap();
    assert_eq!(decrypt_name_with_key(&folder_key(), &name).as_deref(), Some("report.pdf"));
}
