#![allow(deprecated)]
//! Task 1922: the WASM handle's own path (no JS engine needed for these).
use super::*;

fn handle() -> ClientMetaKey {
    ClientMetaKey::try_new(vec![0x40u8; 32]).unwrap()
}

const RECORD: &str = "19220000-0000-4000-8000-000000000001";

#[test]
fn the_handle_seals_and_opens_every_field() {
    let h = handle();
    for (field, device) in [
        (1u32, None),
        (2, Some("19220000-0000-4000-8000-0000000000aa".to_string())),
        (3, Some("19220000-0000-4000-8000-0000000000AA".to_string())),
        (4, Some("19220000-0000-4000-8000-0000000000aa".to_string())),
    ] {
        let sealed = h.seal_seam(RECORD, device.as_deref(), field, "some value").unwrap();
        assert!(sealed.starts_with("bbcm1."));
        let opened = h.open_seam(RECORD, device.as_deref(), field, &sealed).unwrap();
        assert_eq!(opened, "some value");
    }
}

#[test]
fn the_handle_rejects_a_bad_master_key_and_a_bad_field() {
    assert!(ClientMetaKey::try_new(vec![0u8; 31]).is_err());
    let h = handle();
    assert!(h.seal_seam("not-a-uuid", None, 1, "x").is_err());
    assert!(h.seal_seam(RECORD, None, 5, "x").is_err());
    // A u32 from JS: 257 used to wrap to 1 before the u8::try_from check.
    assert!(h.seal_seam(RECORD, None, 257, "x").is_err());
    assert!(h.seal_seam(RECORD, None, 256, "x").is_err());
    assert!(h.open_seam(RECORD, None, 257, "bbcm1.x").is_err());
    assert!(h.seal_seam(RECORD, None, 1, "x").unwrap().starts_with("bbcm1."));
}

#[test]
fn open_row_isolates_bad_rows() {
    let h = handle();
    let good = h.seal_seam(RECORD, None, 1, "host").unwrap();
    assert_eq!(
        h.open_row(ClientMetaItemJs {
            record_key: RECORD.into(),
            device_key: None,
            field: 1,
            envelope: Some(good),
        })
        .unwrap(),
        "host"
    );
    assert!(
        h.open_row(ClientMetaItemJs {
            record_key: RECORD.into(),
            device_key: None,
            field: 2,
            envelope: Some("bbcm1.nope".into()),
        })
        .is_err()
    );
}

#[test]
fn a_null_envelope_row_fails_alone() {
    let h = handle();
    let good = h.seal_seam(RECORD, None, 1, "host").unwrap();
    let rows = h.open_many_rows(vec![
        ClientMetaItemJs {
            record_key: RECORD.into(),
            device_key: None,
            field: 1,
            envelope: Some(good),
        },
        // A null envelope is a per-row failure, not a batch failure.
        ClientMetaItemJs {
            record_key: RECORD.into(),
            device_key: None,
            field: 1,
            envelope: None,
        },
        // Likewise a bad field, a bad UUID and a bad envelope.
        ClientMetaItemJs {
            record_key: RECORD.into(),
            device_key: None,
            field: 257,
            envelope: Some("bbcm1.x".into()),
        },
        ClientMetaItemJs {
            record_key: "not-a-uuid".into(),
            device_key: None,
            field: 1,
            envelope: Some("bbcm1.x".into()),
        },
        ClientMetaItemJs {
            record_key: RECORD.into(),
            device_key: None,
            field: 1,
            envelope: Some("bbcm1.nope".into()),
        },
    ]);
    assert_eq!(rows.len(), 5);
    assert!(rows[0].ok);
    assert_eq!(rows[0].value.as_deref(), Some("host"));
    for row in &rows[1..] {
        assert!(!row.ok, "a bad row never becomes ok");
        assert!(row.value.is_none());
    }
}

/// wasm-bindgen does not camel-case method names; the documented JS names are
/// explicit attributes. `cargo test` has no JS engine, so the source is checked
/// (the same style as `no_doc_comment_contains_a_block_comment_token`).
#[test]
fn the_client_meta_methods_use_the_documented_js_names() {
    let src = include_str!("lib.rs");
    for (attribute, method) in [
        ("#[wasm_bindgen(js_name = openMany)]", "pub fn open_many("),
        ("#[wasm_bindgen(js_name = fitForSeal)]", "pub fn fit_for_seal("),
    ] {
        let at = src
            .find(method)
            .unwrap_or_else(|| panic!("{method} is missing from the WASM surface"));
        let before = &src[..at];
        let window = &before[before.len().saturating_sub(200)..];
        assert!(
            window.contains(attribute),
            "{method} must carry {attribute}; a missing js_name exposes the Rust name to JS"
        );
    }
}
