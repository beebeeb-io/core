//! Bundles: the create contract of web's bundle branch (`prepareBundleShareItems`,
//! `wrapBundleToken`, the one 409 retry), opened with the pinned `share_key_wrap` primitive
//! (`unwrap_key_from_share`, web's `unwrapBundleItemKey`).
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::super::link::{LinkOptions, LinkStep, rebuild_bundle_link};
use super::super::{b64_decode, unwrap_key_from_share};
use super::*;
use crate::auth_flow::HttpResponse;

const APP: &str = "https://app.beebeeb.test";
const IDS: [&str; 3] = [
    "2238a000-0000-4000-8000-000000000001",
    "2238a000-0000-4000-8000-000000000002",
    "2238a000-0000-4000-8000-000000000003",
];

#[test]
fn every_item_opens_under_the_links_k_c_and_the_owner_can_rebuild_it() {
    let m = MasterKey::from_bytes([4; 32]);
    let keys: Vec<FileKey> = (0..3u8).map(|i| FileKey::from_bytes([0x90 + i; 32])).collect();
    let items: Vec<BundleItem<'_>> = IDS
        .iter()
        .zip(&keys)
        .enumerate()
        .map(|(i, (id, k))| BundleItem {
            file_id: id,
            position: i as u32,
            file_key: k,
        })
        .collect();
    let options = LinkOptions {
        expires_in_hours: None,
        max_opens: Some(10),
        passphrase: Some(Zeroizing::new("  open sesame ".into())),
    };
    let (mut flow, req) = CreateLink::bundle(APP, &items, &m, &options).unwrap();
    let body = req.body.clone().unwrap();
    assert_eq!(body["share_type"], "bundle");
    assert!(body.get("expires_in_hours").is_none(), "never = the field left out");
    assert_eq!(
        (body["max_opens"].clone(), body["passphrase"].clone()),
        (json!(10), json!("open sesame"))
    );
    let first_token = body["token"].as_str().unwrap().to_owned();
    // The server's token collision is retried once with a fresh token.
    let collision = json!({ "error": "share token already exists — regenerate and retry" });
    let LinkStep::Send(retry) = flow.on_response(HttpResponse::new(409, collision)).unwrap() else {
        panic!()
    };
    let body: Value = retry.body.unwrap();
    assert_ne!(body["token"].as_str().unwrap(), first_token);
    let LinkStep::Created(created) = flow
        .on_response(HttpResponse::new(201, json!({ "id": "5a1e" })))
        .unwrap()
    else {
        panic!()
    };
    let fragment = created.link.split("#key=").nth(1).unwrap();
    let k_c: [u8; 32] = crate::share_link::key_bytes(fragment).unwrap().try_into().unwrap();
    let wire = body["items"].as_array().unwrap();
    assert_eq!(wire.len(), 3);
    for (i, item) in wire.iter().enumerate() {
        assert_eq!(
            (item["file_id"].as_str().unwrap(), item["position"].as_u64().unwrap()),
            (IDS[i], i as u64)
        );
        let opened =
            unwrap_key_from_share(&k_c, &b64_decode(item["wrapped_file_key"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(opened.as_slice(), keys[i].as_bytes());
    }
    let rebuilt = rebuild_bundle_link(
        APP,
        &m,
        body["owner_wrapped_key"].as_str(),
        body["owner_wrapped_token"].as_str(),
    )
    .unwrap();
    assert_eq!(rebuilt.as_str(), created.link.as_str());
}

/// The bundle route's collision sent as the code (LD-0155), in `error` or `code`: one fresh token.
#[test]
fn a_bundle_token_collision_sent_as_token_taken_gets_one_fresh_token() {
    let m = MasterKey::from_bytes([4; 32]);
    let key = FileKey::from_bytes([0x90; 32]);
    let items = [BundleItem {
        file_id: IDS[0],
        position: 0,
        file_key: &key,
    }];
    for collision in [
        json!({ "error": "token_taken", "message": "That link token is already in use — generate a new one." }),
        json!({ "code": "token_taken", "error": "That link token is already in use — generate a new one." }),
    ] {
        let (mut flow, first) = CreateLink::bundle(APP, &items, &m, &LinkOptions::default()).unwrap();
        let LinkStep::Send(retry) = flow.on_response(HttpResponse::new(409, collision.clone())).unwrap() else {
            panic!("expected a retry for {collision}")
        };
        assert_ne!(first.body.unwrap()["token"], retry.body.unwrap()["token"]);
        assert!(matches!(
            flow.on_response(HttpResponse::new(201, json!({ "id": "5a1e" })))
                .unwrap(),
            LinkStep::Created(_)
        ));
    }
}

#[test]
fn a_bundle_holds_one_to_256_files() {
    let m = MasterKey::from_bytes([4; 32]);
    let key = FileKey::from_bytes([1; 32]);
    let none: Vec<BundleItem<'_>> = Vec::new();
    assert_eq!(
        CreateLink::bundle(APP, &none, &m, &LinkOptions::default()).unwrap_err(),
        ShareFlowError::InvalidInput("no items")
    );
    let many: Vec<BundleItem<'_>> = (0..=BUNDLE_MAX_ITEMS as u32)
        .map(|i| BundleItem {
            file_id: IDS[0],
            position: i,
            file_key: &key,
        })
        .collect();
    assert_eq!(
        CreateLink::bundle(APP, &many, &m, &LinkOptions::default()).unwrap_err(),
        ShareFlowError::InvalidInput("too many items")
    );
    let bad = [BundleItem {
        file_id: "../x",
        position: 0,
        file_key: &key,
    }];
    assert_eq!(
        CreateLink::bundle(APP, &bad, &m, &LinkOptions::default()).unwrap_err(),
        ShareFlowError::InvalidInput("item id")
    );
}
