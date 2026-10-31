//! L16 (task 2237/task 2275): link labels under the owner's purpose wrap,
//! guest actor names under a folder-key subkey bound to the root, and the one
//! legacy child opener that refuses a name-shaped 32-byte plaintext.
//!
//! Every test here runs against the public API only. The fixed-nonce opener
//! cases (an over-bound label, invalid UTF-8 under a valid tag) live in
//! `kdf`'s unit tests, where the vector seams exist.

use beebeeb_core::CoreError;
use beebeeb_core::chunk_stream::ExpectedChunkFormat;
use beebeeb_core::encrypt::{decrypt_chunk, decrypt_name_with_key, encrypt_chunk, encrypt_name_for};
use beebeeb_core::kdf::{
    FILE_KEY_INFO, FOLDER_ACTOR_NAME_INFO, FOLDER_CHILD_LABEL, FOLDER_CUSTODY_LABEL, FOLDER_LINK_KEY_INFO,
    FOLDER_LINK_PASSPHRASE_SALT_LABEL, FileKey, INVITE_OWNER_COPY_LABEL, LEGACY_CHILD_FRAME_LEN, LINK_LABEL_LABEL,
    LINK_OWNER_KEY_LABEL, LINK_OWNER_TOKEN_LABEL, MasterKey, OWNER_FILE_KEY_LABEL, SEARCH_INDEX_SHARD_INFO,
    SHARED_FOLDER_INDEX_KEY_INFO, open_folder_actor_name, open_legacy_child_key, seal_folder_actor_name,
    unwrap_folder_child, unwrap_folder_custody, unwrap_link_label, unwrap_link_owner_key, unwrap_link_owner_token,
    unwrap_owner_file_key, wrap_folder_child, wrap_link_label, wrap_link_owner_key, wrap_owner_file_key,
};
use beebeeb_types::EncryptedBlob;

const SHARE_A: [u8; 16] = [0x11; 16];
const SHARE_B: [u8; 16] = [0x22; 16];
const ROOT_A: [u8; 16] = [0x31; 16];
const ROOT_B: [u8; 16] = [0x42; 16];
const ITEM: [u8; 16] = [0x53; 16];
/// L8 owner-file-key envelopes are foreign (`F`) item ids only (task 2275 L12).
const FOREIGN_ITEM_ID: &str = "11111111-1111-8111-8111-111111111111";

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
}

/// S5(a): every HKDF info/AAD label in `kdf` is distinct and no label is a
/// prefix of another, so two derivations can never share a key by accident
/// (and `label || id` can never be forged from a shorter label plus a longer id).
#[test]
fn every_kdf_label_is_distinct_and_not_a_prefix_of_another() {
    let labels: [(&str, &[u8]); 13] = [
        ("FILE_KEY_INFO", FILE_KEY_INFO),
        ("SEARCH_INDEX_SHARD_INFO", SEARCH_INDEX_SHARD_INFO),
        ("SHARED_FOLDER_INDEX_KEY_INFO", SHARED_FOLDER_INDEX_KEY_INFO),
        ("FOLDER_LINK_KEY_INFO", FOLDER_LINK_KEY_INFO),
        ("FOLDER_LINK_PASSPHRASE_SALT_LABEL", FOLDER_LINK_PASSPHRASE_SALT_LABEL),
        ("FOLDER_CHILD_LABEL", FOLDER_CHILD_LABEL),
        ("OWNER_FILE_KEY_LABEL", OWNER_FILE_KEY_LABEL),
        ("FOLDER_CUSTODY_LABEL", FOLDER_CUSTODY_LABEL),
        ("LINK_OWNER_KEY_LABEL", LINK_OWNER_KEY_LABEL),
        ("LINK_OWNER_TOKEN_LABEL", LINK_OWNER_TOKEN_LABEL),
        ("INVITE_OWNER_COPY_LABEL", INVITE_OWNER_COPY_LABEL),
        ("LINK_LABEL_LABEL", LINK_LABEL_LABEL),
        ("FOLDER_ACTOR_NAME_INFO", FOLDER_ACTOR_NAME_INFO),
    ];
    for (i, (a_name, a)) in labels.iter().enumerate() {
        for (b_name, b) in labels.iter().skip(i + 1) {
            assert_ne!(a, b, "{a_name} and {b_name} are the same HKDF label");
            assert!(
                !a.starts_with(b) && !b.starts_with(a),
                "{a_name} and {b_name}: one label is a prefix of the other"
            );
        }
    }
}

/// S5(b): cross-open rows that feed a REAL output of one writer to another
/// opener, with the SAME 16-byte id where the formats allow it, and require the
/// failure to be the AEAD (`CoreError::Decryption`) rather than a length or id
/// check. The label text is 32 bytes so its ciphertext is 48 bytes — the L7
/// child wrap's length — and the row cannot fail on the length check instead.
#[test]
fn cross_open_rows_fail_the_aead_not_a_length_or_id_check() {
    let label_text = "0123456789abcdef0123456789abcdef";
    assert_eq!(label_text.len(), 32);
    let label = wrap_link_label(&master(), &SHARE_A, label_text).unwrap();
    assert_eq!(label.ciphertext.len(), 48);

    // A label frame into the other purpose openers, same id bytes as its share.
    assert!(matches!(
        unwrap_link_owner_key(&master(), &SHARE_A, &label),
        Err(CoreError::Decryption)
    ));
    assert!(matches!(
        unwrap_link_owner_token(&master(), &SHARE_A, &label),
        Err(CoreError::Decryption)
    ));
    assert!(matches!(
        unwrap_folder_custody(&master(), &SHARE_A, &label),
        Err(CoreError::Decryption)
    ));
    assert!(
        matches!(
            unwrap_folder_child(&folder_key(), &SHARE_A, &ITEM, 1, &label),
            Err(CoreError::Decryption)
        ),
        "a 48-byte label ciphertext must fail the L7 AEAD, not its length check"
    );
    assert!(
        matches!(
            open_folder_actor_name(&folder_key(), &SHARE_A, &json(&label)),
            Err(CoreError::Decryption)
        ),
        "a label envelope with the same 16 id bytes must fail the actor-name AEAD"
    );
    // L8's context can only carry a 36-byte F item id, so the same id bytes are
    // not expressible; given a valid id the refusal is still the AEAD.
    assert!(matches!(
        unwrap_owner_file_key(&master(), FOREIGN_ITEM_ID.as_bytes(), &label),
        Err(CoreError::Decryption)
    ));

    // The reverse direction: a real actor-name envelope, a real L7 child wrap
    // and a real L8 owner wrap into the label opener, same id bytes where the
    // format allows it.
    // 32 bytes of name: the same 48-byte ciphertext as the label, so the row
    // below reaches the AEAD of every opener that has a length check.
    let sealed = seal_folder_actor_name(&folder_key(), &ROOT_A, &"n".repeat(32)).unwrap();
    let named: EncryptedBlob = serde_json::from_str(&sealed).unwrap();
    assert_eq!(named.ciphertext.len(), 48);
    assert!(matches!(
        unwrap_link_label(&master(), &ROOT_A, &named),
        Err(CoreError::Decryption)
    ));

    let child = wrap_folder_child(&folder_key(), &SHARE_A, &ITEM, 1, &FileKey::from_bytes([0x0a; 32])).unwrap();
    assert!(matches!(
        unwrap_link_label(&master(), &SHARE_A, &child),
        Err(CoreError::Decryption)
    ));

    let owner = wrap_owner_file_key(&master(), FOREIGN_ITEM_ID.as_bytes(), &FileKey::from_bytes([0x0b; 32])).unwrap();
    assert!(matches!(
        unwrap_link_label(&master(), &SHARE_A, &owner),
        Err(CoreError::Decryption)
    ));

    // A 60-byte output of each writer (a 32-byte plaintext) reaches the legacy
    // child opener's AEAD and is refused there too, not by its length check.
    assert_eq!(frame(&label).len(), LEGACY_CHILD_FRAME_LEN);
    assert!(open_legacy_child_key(&folder_key(), &frame(&label)).is_none());
    assert_eq!(frame(&named).len(), LEGACY_CHILD_FRAME_LEN);
    assert!(open_legacy_child_key(&folder_key(), &frame(&named)).is_none());
}

/// S3: exactly one envelope shape. The opener re-serializes what it parsed the
/// way `seal_folder_actor_name` writes it and requires byte equality.
#[test]
fn the_actor_name_opener_refuses_every_other_envelope_shape() {
    let sealed = seal_folder_actor_name(&folder_key(), &ROOT_A, "Mama").unwrap();
    assert_eq!(open_folder_actor_name(&folder_key(), &ROOT_A, &sealed).unwrap(), "Mama");

    // An extra field.
    let mut value: serde_json::Value = serde_json::from_str(&sealed).unwrap();
    value["extra"] = serde_json::json!("field");
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_A, &value.to_string()),
        Err(CoreError::Decryption)
    ));

    // Reordered keys.
    let blob: EncryptedBlob = serde_json::from_str(&sealed).unwrap();
    let reordered = serde_json::json!({
        "ciphertext": blob.ciphertext,
        "nonce": blob.nonce,
        "cipher_suite": blob.cipher_suite,
    })
    .to_string();
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_A, &reordered),
        Err(CoreError::Decryption)
    ));

    // Added whitespace, inside the object and at the ends.
    let padded = sealed.replacen('{', "{ ", 1).replacen('}', " }", 1);
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_A, &padded),
        Err(CoreError::Decryption)
    ));
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_A, &format!("\n{sealed}\n")),
        Err(CoreError::Decryption)
    ));
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
    // through the legacy child opener. The name is 32 bytes, so the L7 row
    // reaches the AEAD instead of failing its 48-byte length check.
    let thirty_two = "n".repeat(32);
    let matrix_sealed = seal_folder_actor_name(&folder_key(), &ROOT_A, &thirty_two).unwrap();
    let as_blob: EncryptedBlob = serde_json::from_str(&matrix_sealed).unwrap();
    assert_eq!(as_blob.ciphertext.len(), 48);
    assert!(matches!(
        unwrap_link_label(&master(), &ROOT_A, &as_blob),
        Err(CoreError::Decryption)
    ));
    assert!(matches!(
        unwrap_link_owner_key(&master(), &ROOT_A, &as_blob),
        Err(CoreError::Decryption)
    ));
    assert_eq!(decrypt_name_with_key(&folder_key(), &matrix_sealed), None);
    assert!(matches!(
        unwrap_folder_child(&folder_key(), &ROOT_A, &ITEM, 2, &as_blob),
        Err(CoreError::Decryption)
    ));
    assert!(matches!(
        unwrap_folder_custody(&master(), &ROOT_A, &as_blob),
        Err(CoreError::Decryption)
    ));
    assert!(open_legacy_child_key(&folder_key(), &frame(&as_blob)).is_none());
}

#[test]
fn actor_name_opener_strips_control_and_bidi_characters() {
    let sealed = seal_folder_actor_name(&folder_key(), &ROOT_A, "Ali\u{202E}ce\u{2066}\u{7}").unwrap();
    assert_eq!(
        open_folder_actor_name(&folder_key(), &ROOT_A, &sealed).unwrap(),
        "Alice"
    );
}

#[test]
fn openers_refuse_wrong_shapes_and_bounds() {
    // A plaintext value that is not an envelope (no `{`).
    assert!(matches!(
        open_folder_actor_name(&folder_key(), &ROOT_A, "Mama"),
        Err(CoreError::Decryption)
    ));
    // The web `{nonce, ciphertext}` shape is not the writer's container.
    let short: EncryptedBlob =
        serde_json::from_str(&seal_folder_actor_name(&folder_key(), &ROOT_A, "Mama").unwrap()).unwrap();
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
        unwrap_link_label(
            &master(),
            &[0u8; 15],
            &wrap_link_label(&master(), &SHARE_A, "Trip").unwrap()
        ),
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

    assert_eq!(
        open_legacy_child_key(&folder_key(), &frame).unwrap().as_bytes(),
        child.as_bytes()
    );
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
        unwrap_folder_child(&folder_key(), &ROOT_A, &ITEM, 1, &l7)
            .unwrap()
            .as_bytes(),
        &[0x0a; 32]
    );
    let l8 = wrap_owner_file_key(&master(), FOREIGN_ITEM_ID.as_bytes(), &FileKey::from_bytes([0x0b; 32])).unwrap();
    assert_eq!(
        unwrap_owner_file_key(&master(), FOREIGN_ITEM_ID.as_bytes(), &l8)
            .unwrap()
            .as_bytes(),
        &[0x0b; 32]
    );
    let l6 = wrap_link_owner_key(&master(), &SHARE_A, &FileKey::from_bytes([0x0c; 32])).unwrap();
    assert_eq!(
        unwrap_link_owner_key(&master(), &SHARE_A, &l6).unwrap().as_bytes(),
        &[0x0c; 32]
    );
    let name = encrypt_name_for(&folder_key(), "report.pdf", None, ExpectedChunkFormat::Unrecorded).unwrap();
    assert_eq!(
        decrypt_name_with_key(&folder_key(), &name).as_deref(),
        Some("report.pdf")
    );
}
