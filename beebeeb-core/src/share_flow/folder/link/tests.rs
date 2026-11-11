//! Folder links: the pinned link vectors (`combine_folder_link_key`, `folder_link_passphrase`,
//! `folder_link_passphrase_nfd`, `link_owner_key_v1`, `link_owner_token_v1`) and the create
//! contract of web `createFolderLinkWithKeys` (`test/folder-link-create.test.ts` behaviour).
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::super::super::{b64_decode, split, unwrap_key_from_share};
use super::super::{CustodyMemory, FolderShare, FolderStep};
use super::*;
use crate::auth_flow::Method;
use crate::kdf;

const FOLDER: &str = "2237c000-0000-4000-8000-000000000001";
const APP: &str = "https://app.beebeeb.test";

fn vector(name: &str) -> Value {
    let all: Value = serde_json::from_str(include_str!("../../../../../test-vectors/vectors.json")).expect("vectors");
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

fn master() -> MasterKey {
    MasterKey::from_bytes([3; 32])
}

fn resp(status: u16, body: Value) -> HttpResponse {
    HttpResponse::new(status, body)
}

fn body_of(step: FolderStep) -> (String, Value) {
    match step {
        FolderStep::Send(s) => (s.request.path, s.request.body.unwrap_or(Value::Null)),
        other => panic!("expected a request, got {other:?}"),
    }
}

// ── Pinned vectors ───────────────────────────────────────────────────────────

#[test]
fn vector_combine_folder_link_key() {
    let v = vector("combine_folder_link_key");
    let k_c = key32(&v, "k_c_hex");
    let stretch = key32(&v, "passphrase_stretch_hex");
    assert_eq!(
        kdf::combine_folder_link_key(&k_c, None).to_vec(),
        hexv(&v, "expected_without_passphrase_hex")
    );
    assert_eq!(
        kdf::combine_folder_link_key(&k_c, Some(&stretch)).to_vec(),
        hexv(&v, "expected_with_passphrase_hex")
    );
}

#[test]
fn vector_folder_link_passphrase_nfd_is_normalized_to_the_nfc_key() {
    let nfc = vector("folder_link_passphrase");
    let nfd = vector("folder_link_passphrase_nfd");
    let raw = nfd["passphrase"].as_str().unwrap();
    assert_ne!(
        raw,
        nfc["passphrase"].as_str().unwrap(),
        "the vector is spelled differently"
    );
    let normalized = normalize_passphrase(raw).unwrap();
    assert_eq!(
        normalized.as_str(),
        nfc["passphrase"].as_str().unwrap(),
        "the body carries the NFC form"
    );
    let stretch = kdf::derive_folder_link_passphrase_stretch(&normalized, nfd["token"].as_str().unwrap()).unwrap();
    assert_eq!(stretch.to_vec(), hexv(&nfd, "stretch_hex"));
    let link_key = kdf::combine_folder_link_key(&key32(&nfd, "k_c_hex"), Some(&stretch));
    assert_eq!(link_key.to_vec(), hexv(&nfd, "link_key_hex"));
    assert_eq!(
        normalize_passphrase("   ").unwrap_err(),
        ShareFlowError::InvalidInput("passphrase empty")
    );
}

#[test]
fn vector_link_owner_copies_open_under_their_share_id() {
    for name in ["link_owner_key_v1", "link_owner_token_v1"] {
        let v = vector(name);
        let m = MasterKey::from_bytes(key32(&v, "master_key_hex"));
        let rec = v["record_id"].as_str().unwrap();
        let blob = split(&hexv(&v, "wrapped_hex")).unwrap();
        let plain = if name == "link_owner_key_v1" {
            kdf::unwrap_link_owner_key(&m, rec.as_bytes(), &blob)
                .unwrap()
                .as_bytes()
                .to_vec()
        } else {
            kdf::unwrap_link_owner_token(&m, rec.as_bytes(), &blob)
                .unwrap()
                .to_vec()
        };
        assert_eq!(plain, hexv(&v, "plaintext_hex"), "{name}");
        assert!(kdf::unwrap_link_owner_key(&m, b"share-other", &blob).is_err());
    }
}

// ── The create contract ──────────────────────────────────────────────────────

fn input(passphrase: Option<&str>) -> FolderLinkInput<'static> {
    FolderLinkInput {
        folder_id: FOLDER,
        app_url: APP,
        access_level: "add",
        label: Some("Team drop"),
        expires_in_hours: Some(48),
        cap_bytes: None,
        max_opens: Some(5),
        passphrase: passphrase.map(|p| Zeroizing::new(p.to_owned())),
        custody: CustodyMemory::default(),
    }
}

/// Custody exists; the folder is empty. Returns the first create body.
fn to_create(flow: &mut FolderShare, first: FolderStep, folder_key: &FileKey, m: &MasterKey) -> (String, Value) {
    let (p, _) = body_of(first);
    assert_eq!(p, format!("/api/v1/shared-folders/{FOLDER}"));
    let custody = b64(&frame(
        kdf::wrap_folder_custody(m, FOLDER.as_bytes(), folder_key).unwrap(),
    ));
    flow.on_response(resp(200, json!({ "owner_wrapped_folder_key": custody })))
        .unwrap();
    let step = flow.on_response(resp(200, json!({ "files": [] }))).unwrap();
    body_of(step)
}

#[test]
fn a_plain_link_wraps_the_folder_key_under_k_c_and_seals_owner_copies_under_the_share_id() {
    let m = master();
    let folder_key = FileKey::from_bytes([0x81; 32]);
    let (mut flow, first) = FolderShare::link(input(None), &m).unwrap();
    let (path, body) = to_create(&mut flow, first, &folder_key, &m);
    assert_eq!(path, "/api/v1/shares/folder-links");
    assert_eq!(body["format"], "l7");
    assert_eq!(body["access_level"], "add");
    assert_eq!(
        (body["expires_in_hours"].clone(), body["max_opens"].clone()),
        (json!(48), json!(5))
    );
    assert!(body.get("cap_bytes").is_none() && body.get("passphrase").is_none());
    assert_eq!(body["folder_keys"].as_array().unwrap().len(), 1, "the root's name key");
    let id = body["id"].as_str().unwrap().to_owned();
    assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(), 4);
    let token = body["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 43, "32 random bytes, base64url without padding");
    let label = split(&b64_decode(body["label_encrypted"].as_str().unwrap()).unwrap()).unwrap();
    let share = uuid::Uuid::parse_str(&id).unwrap();
    assert_eq!(
        kdf::unwrap_link_label(&m, share.as_bytes(), &label).unwrap(),
        "Team drop"
    );

    let created = flow
        .on_response(resp(200, json!({ "id": id, "access_level": "add", "key_version": 1 })))
        .unwrap();
    let FolderStep::LinkCreated(c) = created else {
        panic!("{created:?}")
    };
    assert_eq!(c.share_id, id);
    assert_eq!(c.display, format!("{APP}/f/{token}"));
    assert!(!c.passphrase_protected);
    let fragment = c.link.split("#key=").nth(1).expect("the link keeps #key=");
    let k_c: [u8; 32] = crate::share_link::key_bytes(fragment).unwrap().try_into().unwrap();
    let unwrap_key = kdf::combine_folder_link_key(&k_c, None);
    let opened = unwrap_key_from_share(
        &unwrap_key,
        &b64_decode(body["wrapped_folder_key"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(opened.as_slice(), folder_key.as_bytes());
    let owner_key = split(&b64_decode(body["owner_wrapped_key"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        kdf::unwrap_link_owner_key(&m, id.as_bytes(), &owner_key)
            .unwrap()
            .as_bytes(),
        &k_c
    );
    let owner_token = split(&b64_decode(body["owner_wrapped_token"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        kdf::unwrap_link_owner_token(&m, id.as_bytes(), &owner_token)
            .unwrap()
            .as_slice(),
        token.as_bytes()
    );
    // The owner rebuilds the same link from the stored copies; another share id or master does not.
    let (ok_b64, ot_b64) = (body["owner_wrapped_key"].as_str(), body["owner_wrapped_token"].as_str());
    let rebuilt =
        rebuild_folder_link(APP, &m, &id, ok_b64, ot_b64, body["wrapped_folder_key"].as_str(), false).unwrap();
    assert_eq!(rebuilt.as_str(), c.link.as_str());
    let other = "2237c000-0000-4000-8000-0000000000ee";
    assert!(rebuild_folder_link(APP, &m, other, ok_b64, ot_b64, None, false).is_none());
    let wrong = b64(&wrap_key_for_share(&[9; 32], &[1; 32]).unwrap());
    assert!(
        rebuild_folder_link(APP, &m, &id, ok_b64, ot_b64, Some(&wrong), false).is_none(),
        "a stored folder key that does not open under K_c is never handed out"
    );
}

#[test]
fn a_taken_id_is_resealed_under_a_fresh_id_at_most_three_times() {
    let m = master();
    let folder_key = FileKey::from_bytes([0x82; 32]);
    let (mut flow, first) = FolderShare::link(input(None), &m).unwrap();
    let (_, first_body) = to_create(&mut flow, first, &folder_key, &m);
    let (_, second) = body_of(flow.on_response(resp(409, json!({ "code": "id_taken" }))).unwrap());
    assert_ne!(second["id"], first_body["id"]);
    assert_eq!(
        second["token"], first_body["token"],
        "only the id and what is bound to it change"
    );
    assert_eq!(second["wrapped_folder_key"], first_body["wrapped_folder_key"]);
    assert_ne!(second["owner_wrapped_key"], first_body["owner_wrapped_key"]);
    let (_, third) = body_of(flow.on_response(resp(409, json!({ "code": "id_taken" }))).unwrap());
    let err = flow.on_response(resp(409, json!({ "code": "id_taken" }))).unwrap_err();
    assert_eq!(err, ShareFlowError::Server { status: 409 });
    let _ = third;
    // A server that stores another id is refused.
    let (mut flow, first) = FolderShare::link(input(None), &m).unwrap();
    to_create(&mut flow, first, &folder_key, &m);
    let other = json!({ "id": "2237c000-0000-4000-8000-0000000000ff", "key_version": 1 });
    assert_eq!(
        flow.on_response(resp(200, other)).unwrap_err(),
        ShareFlowError::Protocol("stored under another id")
    );
}

#[test]
fn a_passphrase_link_needs_both_the_fragment_and_the_passphrase() {
    let m = master();
    let folder_key = FileKey::from_bytes([0x83; 32]);
    let (mut flow, first) = FolderShare::link(input(Some("folder cafe\u{301} 2237")), &m).unwrap();
    let (_, body) = to_create(&mut flow, first, &folder_key, &m);
    assert_eq!(body["passphrase"], "folder caf\u{e9} 2237", "sent in NFC");
    let id = body["id"].as_str().unwrap().to_owned();
    let FolderStep::LinkCreated(c) = flow
        .on_response(resp(201, json!({ "id": id, "key_version": 1 })))
        .unwrap()
    else {
        panic!()
    };
    assert!(c.passphrase_protected);
    let fragment = c.link.split("#key=").nth(1).unwrap();
    let k_c: [u8; 32] = crate::share_link::key_bytes(fragment).unwrap().try_into().unwrap();
    let wrapped = b64_decode(body["wrapped_folder_key"].as_str().unwrap()).unwrap();
    assert!(unwrap_key_from_share(&kdf::combine_folder_link_key(&k_c, None), &wrapped).is_err());
    let stretch =
        kdf::derive_folder_link_passphrase_stretch("folder caf\u{e9} 2237", body["token"].as_str().unwrap()).unwrap();
    let opened = unwrap_key_from_share(&kdf::combine_folder_link_key(&k_c, Some(&stretch)), &wrapped).unwrap();
    assert_eq!(opened.as_slice(), folder_key.as_bytes());
}

#[test]
fn link_input_is_checked_before_any_request() {
    let m = master();
    let mut bad = input(None);
    bad.access_level = "owner";
    assert_eq!(
        FolderShare::link(bad, &m).unwrap_err(),
        ShareFlowError::InvalidInput("access level")
    );
    assert_eq!(
        FolderShare::link(input(Some(" \t ")), &m).unwrap_err(),
        ShareFlowError::InvalidInput("passphrase empty")
    );
    // An upgrade-needing folder is refused at the create too (contract §2).
    let (mut flow, first) = FolderShare::link(input(None), &m).unwrap();
    to_create(&mut flow, first, &FileKey::from_bytes([0x84; 32]), &m);
    assert_eq!(
        flow.on_response(resp(409, json!({ "code": "upgrade_required" })))
            .unwrap_err(),
        ShareFlowError::FolderNeedsUpgrade
    );
    let _ = Method::Post;
}

#[test]
fn link_limits_past_the_bounds_are_refused_before_any_request() {
    let m = master();
    let mut longest = input(None);
    longest.expires_in_hours = Some(MAX_EXPIRES_IN_HOURS);
    longest.max_opens = Some(MAX_OPENS);
    assert!(FolderShare::link(longest, &m).is_ok());
    let mut too_long = input(None);
    too_long.expires_in_hours = Some(MAX_EXPIRES_IN_HOURS + 1);
    assert_eq!(
        FolderShare::link(too_long, &m).unwrap_err(),
        ShareFlowError::InvalidInput("expires in hours")
    );
    let mut too_many = input(None);
    too_many.max_opens = Some(MAX_OPENS + 1);
    assert_eq!(
        FolderShare::link(too_many, &m).unwrap_err(),
        ShareFlowError::InvalidInput("max opens")
    );
}
