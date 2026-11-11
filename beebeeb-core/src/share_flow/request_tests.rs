//! File requests: the pinned `file_request_seal_open` vector and the create / rebuild contract of
//! web `pages/file-request.tsx`.
use serde_json::{Value, json};

use super::*;
use crate::auth_flow::Method;
use crate::file_request::{derive_request_wrap_key, open_request_upload, seal_to_request};

const APP: &str = "https://app.beebeeb.test";

fn vector(name: &str) -> Value {
    let all: Value = serde_json::from_str(include_str!("../../../test-vectors/vectors.json")).expect("vectors");
    all["vectors"]
        .as_array()
        .or_else(|| all.as_array())
        .expect("vector list")
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector {name} missing"))
        .clone()
}

fn hexv(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().expect(key)).expect("hex")
}

fn key32(v: &Value, key: &str) -> [u8; 32] {
    hexv(v, key).try_into().expect("32 bytes")
}

#[test]
fn vector_file_request_seal_open() {
    let v = vector("file_request_seal_open");
    let m = MasterKey::from_bytes(key32(&v, "master_key_hex"));
    let request_id = hexv(&v, "request_id_hex");
    assert_eq!(
        derive_request_wrap_key(&m, &request_id).to_vec(),
        hexv(&v, "expected_wrap_key_hex")
    );
    let r_priv = unwrap_request_private(
        &m,
        &request_id,
        &hexv(&v, "wrapped_private_hex"),
        &hexv(&v, "wrap_nonce_hex"),
    )
    .unwrap();
    assert_eq!(*r_priv, key32(&v, "r_priv_hex"));
    assert_eq!(derive_x25519_public(&r_priv), key32(&v, "r_pub_hex"));
    let e_pub = key32(&v, "e_pub_hex");
    let opened = open_request_upload(&r_priv, &e_pub, &hexv(&v, "file_id_hex"), &hexv(&v, "wrapped_key_hex")).unwrap();
    assert_eq!(opened.to_vec(), hexv(&v, "content_key_hex"));
}

#[test]
fn a_request_link_carries_r_pub_and_rebuilds_from_the_stored_wrap() {
    let m = MasterKey::from_bytes([5; 32]);
    let options = RequestOptions {
        title: "  Tax papers ".into(),
        description: Some("   ".into()),
        target_folder_id: Some("2237c000-0000-4000-8000-000000000001".into()),
        max_files: Some(10),
        max_total_bytes: None,
        expires_in_secs: Some(86_400),
    };
    let (mut flow, req) = CreateRequest::start(APP, &options, &m).unwrap();
    assert_eq!((req.method, req.path.as_str()), (Method::Post, FILE_REQUESTS_PATH));
    let body = req.body.clone().unwrap();
    assert_eq!(body["title"], "Tax papers");
    assert!(body.get("description").is_none() && body.get("max_total_bytes").is_none());
    assert_eq!(
        (body["max_files"].clone(), body["expires_in_secs"].clone()),
        (json!(10), json!(86_400))
    );
    let (wrapped, nonce) = (
        body["wrapped_private_key"].as_str().unwrap().to_owned(),
        body["wrap_nonce"].as_str().unwrap().to_owned(),
    );
    let created = flow
        .on_response(HttpResponse::new(201, json!({ "id": "abc123", "token": "tok_EN-9" })))
        .unwrap();
    assert_eq!(created.display, format!("{APP}/r/tok_EN-9"));
    // The uploader seals to the fragment's key; the owner opens with the stored wrap.
    let fragment = created.link.split('#').nth(1).unwrap();
    let r_pub: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(fragment)
        .unwrap()
        .try_into()
        .unwrap();
    let sealed = seal_to_request(&r_pub, b"file-1", &[0x42; 32]).unwrap();
    let r_priv = unwrap_request_private(&m, &[], &b64_decode(&wrapped).unwrap(), &b64_decode(&nonce).unwrap()).unwrap();
    let opened = open_request_upload(&r_priv, &sealed.e_pub, b"file-1", &sealed.wrapped_key).unwrap();
    assert_eq!(*opened, [0x42; 32]);
    let rebuilt = rebuild_request_link(APP, &m, Some("tok_EN-9"), Some(&wrapped), Some(&nonce)).unwrap();
    assert_eq!(rebuilt.as_str(), created.link.as_str());
    assert!(
        rebuild_request_link(
            APP,
            &MasterKey::from_bytes([6; 32]),
            Some("tok_EN-9"),
            Some(&wrapped),
            Some(&nonce)
        )
        .is_none()
    );
    assert!(rebuild_request_link(APP, &m, None, Some(&wrapped), Some(&nonce)).is_none());
    assert_eq!(
        flow.on_response(HttpResponse::new(201, json!({}))).unwrap_err(),
        ShareFlowError::WrongState
    );
}

#[test]
fn a_request_needs_a_title_and_a_clean_token() {
    let m = MasterKey::from_bytes([5; 32]);
    let empty = RequestOptions {
        title: "  ".into(),
        ..Default::default()
    };
    assert_eq!(
        CreateRequest::start(APP, &empty, &m).unwrap_err(),
        ShareFlowError::InvalidInput("title")
    );
    let ok = RequestOptions {
        title: "x".into(),
        ..Default::default()
    };
    let (mut flow, _) = CreateRequest::start(APP, &ok, &m).unwrap();
    let err = flow
        .on_response(HttpResponse::new(201, json!({ "id": "abc", "token": "../x" })))
        .unwrap_err();
    assert_eq!(err, ShareFlowError::Protocol("bad token"));
    let close = close_request("abc123").unwrap();
    assert_eq!(
        (close.method, close.path.as_str(), close.body.is_none()),
        (Method::Post, "/api/v1/file-requests/abc123/close", true)
    );
}
