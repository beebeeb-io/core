//! Web's share KATs (`repos/web/test/share-wrap-kat.test.ts`, the pinned `share_key_wrap` and
//! `x25519_share_key_exchange` vectors in `test-vectors/vectors.json`) and the flow contracts.
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::link::{CreateLink, LinkOptions, LinkStep, open_link_file_key, rebuild_link};
use super::member::{InviteOutcome, InviteStep, MemberInvite, PeerKeyExpectation, ShareTarget, approve_request};
use super::*;
use crate::auth_flow::Method;
use crate::opaque::derive_x25519_public;

const APP: &str = "https://app.beebeeb.test";
const FILE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const INVITE_ID: &str = "7a1d1c2e-0000-4000-8000-000000000001";

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

fn hex32(v: &Value, key: &str) -> [u8; 32] {
    hex::decode(v[key].as_str().expect(key))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn master(byte: u8) -> MasterKey {
    MasterKey::from_bytes([byte; 32])
}

fn ok(body: Value) -> HttpResponse {
    HttpResponse::new(200, body)
}

// ── share-wrap-kat.test.ts ────────────────────────────────────────────────────

#[test]
fn kat1_unwrap_decrypts_the_pinned_vector() {
    let v = vector("share_key_wrap");
    let wrapped = hex::decode(format!(
        "{}{}",
        v["nonce_hex"].as_str().unwrap(),
        v["ciphertext_hex"].as_str().unwrap()
    ))
    .unwrap();
    assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
    let out = unwrap_key_from_share(&hex32(&v, "wrap_key_hex"), &wrapped).expect("unwrap");
    assert_eq!(out.as_slice(), &hex32(&v, "key_to_wrap_hex"));
}

#[test]
fn kat1b_a_flipped_ciphertext_bit_fails_authentication() {
    let v = vector("share_key_wrap");
    let mut wrapped = hex::decode(format!(
        "{}{}",
        v["nonce_hex"].as_str().unwrap(),
        v["ciphertext_hex"].as_str().unwrap()
    ))
    .unwrap();
    wrapped[15] ^= 0x01;
    assert_eq!(
        unwrap_key_from_share(&hex32(&v, "wrap_key_hex"), &wrapped).unwrap_err(),
        ShareFlowError::Crypto
    );
}

#[test]
fn kat2a_core_chunk_frame_opens_with_unwrap() {
    let v = vector("share_key_wrap");
    let wrap = FileKey::from_bytes(hex32(&v, "wrap_key_hex"));
    let blob = encrypt_chunk(&wrap, &hex32(&v, "key_to_wrap_hex")).unwrap();
    let wrapped = [blob.nonce, blob.ciphertext].concat();
    assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
    let out = unwrap_key_from_share(&hex32(&v, "wrap_key_hex"), &wrapped).unwrap();
    assert_eq!(out.as_slice(), &hex32(&v, "key_to_wrap_hex"));
}

#[test]
fn kat2b_wrap_output_opens_with_core_decrypt_chunk() {
    let v = vector("share_key_wrap");
    let wrapped = wrap_key_for_share(&hex32(&v, "wrap_key_hex"), &hex32(&v, "key_to_wrap_hex")).unwrap();
    assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
    let blob = EncryptedBlob {
        cipher_suite: CipherSuite::V1Aes256Gcm,
        nonce: wrapped[..12].to_vec(),
        ciphertext: wrapped[12..].to_vec(),
    };
    let out = decrypt_chunk(&FileKey::from_bytes(hex32(&v, "wrap_key_hex")), &blob).unwrap();
    assert_eq!(out, hex32(&v, "key_to_wrap_hex"));
}

#[test]
fn kat2c_wrap_unwrap_roundtrip() {
    let v = vector("share_key_wrap");
    let wrapped = wrap_key_for_share(&hex32(&v, "wrap_key_hex"), &hex32(&v, "key_to_wrap_hex")).unwrap();
    let out = unwrap_key_from_share(&hex32(&v, "wrap_key_hex"), &wrapped).unwrap();
    assert_eq!(out.as_slice(), &hex32(&v, "key_to_wrap_hex"));
}

#[test]
fn kat_x25519_member_share_key_matches_the_pinned_vector() {
    let v = vector("x25519_share_key_exchange");
    let file_id = String::from_utf8(hex::decode(v["file_id_hex"].as_str().unwrap()).unwrap()).unwrap();
    let alice = MasterKey::from_bytes(hex32(&v, "alice_master_key_hex"));
    let bob = MasterKey::from_bytes(hex32(&v, "bob_master_key_hex"));
    let expected = hex32(&v, "expected_share_key_hex");
    let a = member_share_key(&alice, &hex32(&v, "bob_x25519_public_hex"), &file_id).unwrap();
    let b = member_share_key(&bob, &hex32(&v, "alice_x25519_public_hex"), &file_id).unwrap();
    assert_eq!(a.as_bytes(), &expected);
    assert_eq!(b.as_bytes(), &expected);
}

#[test]
fn member_seal_opens_for_the_recipient_only() {
    let (alice, bob, eve) = (master(1), master(2), master(3));
    let pub_of = |m: &MasterKey| derive_x25519_public(&derive_x25519_private(m));
    let file_key = FileKey::from_bytes([7; 32]);
    let sealed = seal_file_key_for_member(&alice, &pub_of(&bob), FILE_ID, &file_key).unwrap();
    assert_eq!(sealed.len(), WRAPPED_KEY_LEN);
    let opened = open_member_file_key(&bob, &pub_of(&alice), FILE_ID, &sealed).unwrap();
    assert_eq!(opened.as_bytes(), file_key.as_bytes());
    assert!(open_member_file_key(&eve, &pub_of(&alice), FILE_ID, &sealed).is_err());
    assert!(
        open_member_file_key(&bob, &pub_of(&alice), INVITE_ID, &sealed).is_err(),
        "bound to the file id"
    );
}

// ── member invites ────────────────────────────────────────────────────────────

fn file_target() -> ShareTarget {
    ShareTarget {
        item_id: FILE_ID.into(),
        is_folder: false,
    }
}

#[test]
fn a_folder_is_never_shared_through_the_file_path() {
    let target = ShareTarget {
        item_id: FILE_ID.into(),
        is_folder: true,
    };
    let err = MemberInvite::start(
        &target,
        "bob@beebeeb.test",
        &master(1),
        &FileKey::from_bytes([7; 32]),
        PeerKeyExpectation::NotCompared,
    )
    .unwrap_err();
    assert_eq!(err, ShareFlowError::InvalidInput("is_folder: use FolderInvite"));
}

#[test]
fn invite_to_a_claimed_recipient_seals_and_approves() {
    let (alice, bob) = (master(1), master(2));
    let bob_pub = derive_x25519_public(&derive_x25519_private(&bob));
    let file_key = FileKey::from_bytes([7; 32]);
    let (mut flow, first) = MemberInvite::start(
        &file_target(),
        " bob@beebeeb.test ",
        &alice,
        &file_key,
        PeerKeyExpectation::NotCompared,
    )
    .unwrap();
    assert_eq!(first.path, "/api/v1/shares/invites");
    assert_eq!(
        first.body.as_ref().unwrap(),
        &json!({"file_id": FILE_ID, "recipient_email": "bob@beebeeb.test"})
    );
    let step = flow
        .on_response(ok(
            json!({"invite_id": INVITE_ID, "status": "claimed", "recipient_public_key": b64(&bob_pub)}),
        ))
        .unwrap();
    let InviteStep::Send(approve) = step else {
        panic!("expected the approval")
    };
    assert_eq!(approve.path, format!("/api/v1/shares/invites/{INVITE_ID}/approve"));
    let blob = b64_decode(approve.body.as_ref().unwrap()["encrypted_file_key"].as_str().unwrap()).unwrap();
    let alice_pub = derive_x25519_public(&derive_x25519_private(&alice));
    assert_eq!(
        open_member_file_key(&bob, &alice_pub, FILE_ID, &blob)
            .unwrap()
            .as_bytes(),
        &[7; 32]
    );
    let InviteStep::Done(outcome) = flow.on_response(ok(json!({}))).unwrap() else {
        panic!("expected done")
    };
    assert_eq!(
        outcome,
        InviteOutcome::Shared {
            invite_id: INVITE_ID.into(),
            recipient_public_key: bob_pub,
        }
    );
    assert!(matches!(
        flow.on_response(ok(json!({}))),
        Err(ShareFlowError::WrongState)
    ));
}

#[test]
fn invite_without_a_recipient_key_is_sent_not_shared() {
    let (mut flow, _) = MemberInvite::start(
        &file_target(),
        "new@beebeeb.test",
        &master(1),
        &FileKey::from_bytes([7; 32]),
        PeerKeyExpectation::NotCompared,
    )
    .unwrap();
    let InviteStep::Done(outcome) = flow
        .on_response(ok(json!({"invite_id": INVITE_ID, "status": "invited"})))
        .unwrap()
    else {
        panic!("expected done")
    };
    assert_eq!(
        outcome,
        InviteOutcome::Invited {
            invite_id: INVITE_ID.into(),
            status: "invited".into()
        }
    );
}

#[test]
fn a_failed_approval_leaves_the_invite_awaiting_approval() {
    let bob_pub = derive_x25519_public(&derive_x25519_private(&master(2)));
    let (mut flow, _) = MemberInvite::start(
        &file_target(),
        "bob@beebeeb.test",
        &master(1),
        &FileKey::from_bytes([7; 32]),
        PeerKeyExpectation::NotCompared,
    )
    .unwrap();
    flow.on_response(ok(
        json!({"invite_id": INVITE_ID, "status": "claimed", "recipient_public_key": b64(&bob_pub)}),
    ))
    .unwrap();
    let InviteStep::Done(outcome) = flow.on_response(HttpResponse::new(500, json!({}))).unwrap() else {
        panic!("expected done")
    };
    assert_eq!(
        outcome,
        InviteOutcome::AwaitingApproval {
            invite_id: INVITE_ID.into(),
            recipient_public_key: Some(bob_pub),
        }
    );
}

#[test]
fn bad_input_and_server_ids_are_refused() {
    let key = FileKey::from_bytes([7; 32]);
    assert!(
        MemberInvite::start(
            &file_target(),
            "not-an-email",
            &master(1),
            &key,
            PeerKeyExpectation::NotCompared
        )
        .is_err()
    );
    let bad = ShareTarget {
        item_id: "../x".into(),
        is_folder: false,
    };
    assert!(
        MemberInvite::start(
            &bad,
            "bob@beebeeb.test",
            &master(1),
            &key,
            PeerKeyExpectation::NotCompared
        )
        .is_err()
    );
    let (mut flow, _) = MemberInvite::start(
        &file_target(),
        "bob@beebeeb.test",
        &master(1),
        &key,
        PeerKeyExpectation::NotCompared,
    )
    .unwrap();
    let err = flow
        .on_response(ok(json!({"invite_id": "a/../b", "status": "invited"})))
        .unwrap_err();
    assert_eq!(err, ShareFlowError::Protocol("bad id"));
    assert!(
        approve_request(
            "a/b",
            FILE_ID,
            &b64(&[9; 32]),
            &master(1),
            &key,
            PeerKeyExpectation::NotCompared
        )
        .is_err()
    );
    assert!(revoke_link_request("x?y").is_err());
    let revoke = revoke_link_request(INVITE_ID).unwrap();
    assert_eq!(
        (revoke.method, revoke.path.as_str()),
        (Method::Delete, "/api/v1/shares/7a1d1c2e-0000-4000-8000-000000000001")
    );
}

#[test]
fn typed_refusals_keep_their_code() {
    let (mut flow, _) = MemberInvite::start(
        &file_target(),
        "bob@beebeeb.test",
        &master(1),
        &FileKey::from_bytes([7; 32]),
        PeerKeyExpectation::NotCompared,
    )
    .unwrap();
    let err = flow
        .on_response(HttpResponse::new(409, json!({"code": "plan_required"})))
        .unwrap_err();
    assert_eq!(err.code(), "plan_required");
}

// ── B05e: the seal checks the key a "compared" mark was made against ──────────

fn fp(key: &[u8; 32]) -> [u8; 32] {
    super::safety::key_fingerprint(key).unwrap()
}

/// The server answers with a key that is not the one the user compared: the flow stops before
/// sealing (no approval request is built) and reports the key it was given.
#[test]
fn a_server_key_that_differs_from_the_compared_mark_is_refused_and_nothing_is_sealed() {
    let bob_pub = derive_x25519_public(&derive_x25519_private(&master(2)));
    let other_pub = derive_x25519_public(&derive_x25519_private(&master(3)));
    let (mut flow, _) = MemberInvite::start(
        &file_target(),
        "bob@beebeeb.test",
        &master(1),
        &FileKey::from_bytes([7; 32]),
        PeerKeyExpectation::Compared(fp(&bob_pub)),
    )
    .unwrap();
    let step = flow
        .on_response(ok(
            json!({"invite_id": INVITE_ID, "status": "claimed", "recipient_public_key": b64(&other_pub)}),
        ))
        .unwrap();
    let InviteStep::Done(outcome) = step else {
        panic!("a seal request was built: {step:?}")
    };
    assert_eq!(
        outcome,
        InviteOutcome::PeerKeyChanged {
            invite_id: INVITE_ID.into(),
            recipient_public_key: other_pub,
        }
    );
    assert_eq!(outcome.refusal_code(), Some("peer_key_changed"));
    assert!(matches!(
        flow.on_response(ok(json!({}))),
        Err(ShareFlowError::WrongState)
    ));
}

#[test]
fn the_compared_key_seals_and_reports_the_key_it_sealed_to() {
    let bob_pub = derive_x25519_public(&derive_x25519_private(&master(2)));
    let (mut flow, _) = MemberInvite::start(
        &file_target(),
        "bob@beebeeb.test",
        &master(1),
        &FileKey::from_bytes([7; 32]),
        PeerKeyExpectation::Compared(fp(&bob_pub)),
    )
    .unwrap();
    let step = flow
        .on_response(ok(
            json!({"invite_id": INVITE_ID, "status": "claimed", "recipient_public_key": b64(&bob_pub)}),
        ))
        .unwrap();
    assert!(matches!(step, InviteStep::Send(_)));
    let InviteStep::Done(outcome) = flow.on_response(ok(json!({}))).unwrap() else {
        panic!("expected done")
    };
    assert_eq!(
        outcome,
        InviteOutcome::Shared {
            invite_id: INVITE_ID.into(),
            recipient_public_key: bob_pub,
        }
    );
    assert_eq!(outcome.refusal_code(), None);
}

#[test]
fn share_anyway_seals_to_the_bytes_the_refusal_carried_never_a_refetched_key() {
    let key = FileKey::from_bytes([7; 32]);
    let bob_pub = derive_x25519_public(&derive_x25519_private(&master(2)));
    let other_pub = derive_x25519_public(&derive_x25519_private(&master(3)));
    let mark = PeerKeyExpectation::Compared(fp(&bob_pub));
    // The server now serves another key: refused, and the refusal carries those bytes.
    let (mut flow, _) = MemberInvite::start(&file_target(), "bob@beebeeb.test", &master(1), &key, mark).unwrap();
    let step = flow
        .on_response(ok(
            json!({"invite_id": INVITE_ID, "status": "claimed", "recipient_public_key": b64(&other_pub)}),
        ))
        .unwrap();
    let InviteStep::Done(InviteOutcome::PeerKeyChanged {
        recipient_public_key: carried,
        ..
    }) = step
    else {
        panic!("expected peer_key_changed")
    };
    assert_eq!(carried, other_pub);
    let err = approve_request(INVITE_ID, FILE_ID, &b64(&other_pub), &master(1), &key, mark).unwrap_err();
    assert_eq!(err, ShareFlowError::PeerKeyChanged);
    assert_eq!(err.code(), "peer_key_changed");
    // The user accepts: seal to the CARRIED bytes with Compared(fingerprint of those bytes).
    let accepted = PeerKeyExpectation::Compared(fp(&carried));
    let sealed = approve_request(INVITE_ID, FILE_ID, &b64(&carried), &master(1), &key, accepted).unwrap();
    assert_eq!(sealed.recipient_public_key, other_pub);
    assert_eq!(
        sealed.request.path,
        format!("/api/v1/shares/invites/{INVITE_ID}/approve")
    );
}

#[test]
fn share_anyway_refuses_again_when_the_server_swaps_the_key_a_second_time() {
    let key = FileKey::from_bytes([7; 32]);
    let carried = derive_x25519_public(&derive_x25519_private(&master(3)));
    let swapped = derive_x25519_public(&derive_x25519_private(&master(4)));
    let accepted = PeerKeyExpectation::Compared(fp(&carried));
    // A host that hands the re-fetched key to the accept call gets a refusal, not a seal.
    let err = approve_request(INVITE_ID, FILE_ID, &b64(&swapped), &master(1), &key, accepted).unwrap_err();
    assert_eq!(err, ShareFlowError::PeerKeyChanged);
    // ... and the refusal carries the new bytes, so the user is asked again.
    assert_ne!(swapped, carried);
}

#[test]
fn the_seal_refuses_a_key_the_safety_number_refuses() {
    let key = FileKey::from_bytes([7; 32]);
    let mut high_bit = derive_x25519_public(&derive_x25519_private(&master(2)));
    high_bit[31] |= 0x80;
    let small_order = [0u8; 32];
    for bad in [high_bit, small_order] {
        for exp in [PeerKeyExpectation::NotCompared, PeerKeyExpectation::Compared([1; 32])] {
            let err = approve_request(INVITE_ID, FILE_ID, &b64(&bad), &master(1), &key, exp).unwrap_err();
            assert!(matches!(err, ShareFlowError::InvalidInput(_)), "{err:?}");
        }
    }
}

#[test]
fn the_safety_number_uses_the_own_key_derived_from_the_master_key() {
    let alice = master(1);
    let alice_pub = derive_x25519_public(&derive_x25519_private(&alice));
    let bob_pub = derive_x25519_public(&derive_x25519_private(&master(2)));
    let (a, b) = (
        "0b3c7a52-5d0e-4f1a-9d2e-1c6f3a8b9e01",
        "7f9e2d14-3a6b-4c8d-8e1f-2b4a6c8d0e12",
    );
    let n = super::safety::safety_number(&alice, a, b, &bob_pub).unwrap();
    assert_eq!(
        n,
        super::safety::safety_number_for_keys(a, &alice_pub, b, &bob_pub).unwrap()
    );
    assert_eq!(n.peer_fingerprint, fp(&bob_pub));
}

// ── links ─────────────────────────────────────────────────────────────────────

fn created(flow: &mut CreateLink) -> super::link::CreatedLink {
    match flow
        .on_response(ok(json!({"id": INVITE_ID, "token": "ignored"})))
        .unwrap()
    {
        LinkStep::Created(c) => c,
        LinkStep::Send(_) => panic!("expected created"),
    }
}

#[test]
fn a_link_opens_for_the_recipient_and_rebuilds_for_the_owner() {
    let owner = master(1);
    let file_key = FileKey::from_bytes([7; 32]);
    let opts = LinkOptions {
        expires_in_hours: Some(168),
        max_opens: None,
        passphrase: None,
    };
    let (mut flow, req) = CreateLink::start(APP, FILE_ID, &owner, &file_key, &opts).unwrap();
    let body = req.body.clone().unwrap();
    assert_eq!(req.path, "/api/v1/shares");
    assert_eq!(body["file_id"], FILE_ID);
    assert_eq!(body["expires_in_hours"], 168);
    assert!(body["max_opens"].is_null() && body.get("passphrase").is_none());
    for field in ["wrapped_file_key", "owner_wrapped_key"] {
        assert_eq!(
            b64_decode(body[field].as_str().unwrap()).unwrap().len(),
            WRAPPED_KEY_LEN,
            "{field}"
        );
    }
    let token = body["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 27);
    let link = created(&mut flow);
    assert_eq!(link.share_id, INVITE_ID);
    assert_eq!(display_form(&link.link), format!("{APP}/s/{token}"));
    let parsed = crate::share_link::parse(&link.link).unwrap();
    let opened = open_link_file_key(&parsed.key, body["wrapped_file_key"].as_str().unwrap()).unwrap();
    assert_eq!(opened.as_bytes(), &[7; 32]);
    let rebuilt = rebuild_link(
        APP,
        &owner,
        body["owner_wrapped_key"].as_str(),
        body["owner_wrapped_token"].as_str(),
        body["wrapped_file_key"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(*rebuilt, *link.link);
    // A stored wrapped_file_key that does not open under this share's K_c: no link is handed out.
    let foreign = b64(&super::wrap_key_for_share(&[9u8; 32], &[7u8; 32]).unwrap());
    assert!(
        rebuild_link(
            APP,
            &owner,
            body["owner_wrapped_key"].as_str(),
            body["owner_wrapped_token"].as_str(),
            &foreign,
        )
        .is_none(),
        "the content key must open under the rebuilt K_c"
    );
    assert!(
        rebuild_link(
            APP,
            &master(2),
            body["owner_wrapped_key"].as_str(),
            body["owner_wrapped_token"].as_str(),
            body["wrapped_file_key"].as_str().unwrap(),
        )
        .is_none()
    );
    assert!(rebuild_link(APP, &owner, None, body["owner_wrapped_token"].as_str(), "x").is_none());
    // The key is required: an empty one is a refusal, never a skipped check.
    assert!(
        rebuild_link(
            APP,
            &owner,
            body["owner_wrapped_key"].as_str(),
            body["owner_wrapped_token"].as_str(),
            "",
        )
        .is_none()
    );
    assert!(!format!("{link:?}{flow:?}").contains(&token));
}

#[test]
fn a_token_collision_retries_once_with_a_fresh_token() {
    let (mut flow, first) = CreateLink::start(
        APP,
        FILE_ID,
        &master(1),
        &FileKey::from_bytes([7; 32]),
        &LinkOptions::default(),
    )
    .unwrap();
    let LinkStep::Send(second) = flow
        .on_response(HttpResponse::new(
            409,
            json!({"error": "share token already exists — regenerate and retry"}),
        ))
        .unwrap()
    else {
        panic!("expected a retry")
    };
    let (a, b) = (first.body.unwrap(), second.body.unwrap());
    assert_ne!(a["token"], b["token"]);
    assert_eq!(a["wrapped_file_key"], b["wrapped_file_key"], "same K_c, same blobs");
    let err = flow.on_response(HttpResponse::new(409, json!({}))).unwrap_err();
    assert_eq!(err, ShareFlowError::Server { status: 409 });
}

#[test]
fn a_typed_409_is_a_refusal_not_a_retry() {
    let (mut flow, _) = CreateLink::start(
        APP,
        FILE_ID,
        &master(1),
        &FileKey::from_bytes([7; 32]),
        &LinkOptions::default(),
    )
    .unwrap();
    let err = flow
        .on_response(HttpResponse::new(409, json!({"code": "trial_sharing_unavailable"})))
        .unwrap_err();
    assert_eq!(err, ShareFlowError::Refused("trial_sharing_unavailable"));
}

#[test]
fn the_passphrase_is_trimmed_and_needs_four_characters() {
    let key = FileKey::from_bytes([7; 32]);
    let with = |p: &str| LinkOptions {
        passphrase: Some(Zeroizing::new(p.to_owned())),
        ..LinkOptions::default()
    };
    assert!(CreateLink::start(APP, FILE_ID, &master(1), &key, &with(" abc ")).is_err());
    let (_, req) = CreateLink::start(APP, FILE_ID, &master(1), &key, &with("  abcd ")).unwrap();
    assert_eq!(req.body.unwrap()["passphrase"], "abcd");
    let (_, req) = CreateLink::start(APP, FILE_ID, &master(1), &key, &with("   ")).unwrap();
    assert!(req.body.unwrap().get("passphrase").is_none());
    assert!(CreateLink::start("ftp://x", FILE_ID, &master(1), &key, &LinkOptions::default()).is_err());
}
