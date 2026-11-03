//! Task 2275 §15 / 2326 delta D-P2: request-row results are read-only.
//!
//! A request row whose name is sealed under the content key `C` must not hand
//! a caller anything that can seal a name: the anonymous uploader holds `C`.
//! Renames go through `seal_request_rename`, which derives the §15 string key
//! from the item id, never `C`.

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
    // The content handle is read-only and has no key getter.
    assert_eq!(detailed.content.chunk_format().unwrap(), None);

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
