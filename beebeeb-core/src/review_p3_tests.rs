//! Delta review fixes (v0.2.8 review, P3 items): one test per item that the old code can compile.

use serde_json::{Value, json};

use crate::kdf::{FileKey, MasterKey};
use crate::passkey::ceremony::{self, ExpectedRp, RequestOptions};
use crate::share_flow::member::{MemberInvite, ShareTarget, approve_request};
use crate::share_flow::{b64, open_member_file_key, seal_file_key_for_member};

const FILE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn master(b: u8) -> MasterKey {
    MasterKey::from_bytes([b; 32])
}

#[test]
fn terms_url_with_a_backslash_anywhere_is_refused() {
    let own = |u: &str| crate::signup_flow::own_https_url(Some(&json!(u)));
    assert_eq!(own("https://beebeeb.io\\@evil.example/x"), None);
    assert_eq!(own("https://beebeeb.io/terms\\x"), None);
    assert_eq!(
        own("https://beebeeb.io/terms").as_deref(),
        Some("https://beebeeb.io/terms")
    );
}

#[test]
fn file_person_share_entry_points_refuse_an_upper_case_id() {
    let upper = FILE_ID.to_uppercase();
    let (alice, bob) = (master(1), master(2));
    let key = FileKey::from_bytes([7; 32]);
    let public = crate::opaque::derive_x25519_public(&crate::opaque::derive_x25519_private(&bob));
    let target = ShareTarget {
        item_id: upper.clone(),
        is_folder: false,
    };
    assert!(MemberInvite::start(&target, "bob@beebeeb.test", &alice, &key).is_err());
    assert!(
        approve_request(
            "0a0a0a0a-0000-4000-8000-000000000001",
            &upper,
            &b64(&public),
            &alice,
            &key
        )
        .is_err()
    );
    let sealed = seal_file_key_for_member(&alice, &public, FILE_ID, &key).unwrap();
    let alice_pub = crate::opaque::derive_x25519_public(&crate::opaque::derive_x25519_private(&alice));
    assert!(open_member_file_key(&bob, &alice_pub, &upper, &sealed).is_err());
    assert!(seal_file_key_for_member(&alice, &public, &upper, &key).is_err());
    assert!(open_member_file_key(&bob, &alice_pub, FILE_ID, &sealed).is_ok());
}

#[test]
fn folder_link_rebuild_refuses_an_upper_case_share_id() {
    use crate::share_flow::folder::rebuild_folder_link;
    // Owner copies sealed under the upper-case spelling: only a canonical-id check can refuse them.
    let m = master(1);
    let id = "2237c000-0000-4000-8000-0000000000ee";
    let upper = id.to_uppercase();
    let seal = |sid: &str| {
        let k = crate::kdf::wrap_link_owner_key(&m, sid.as_bytes(), &FileKey::from_bytes([3; 32])).unwrap();
        let t = crate::kdf::wrap_link_owner_token(&m, sid.as_bytes(), b"tok").unwrap();
        (b64(&crate::share_flow::frame(k)), b64(&crate::share_flow::frame(t)))
    };
    let app = "https://app.beebeeb.io";
    let (k, t) = seal(id);
    assert!(rebuild_folder_link(app, &m, id, Some(&k), Some(&t), None, false).is_some());
    let (k, t) = seal(&upper);
    assert!(rebuild_folder_link(app, &m, &upper, Some(&k), Some(&t), None, false).is_none());
}

fn forced(uv: &str) -> (String, String, String) {
    let reg = json!({
        "publicKey": {
            "rp": { "name": "Beebeeb", "id": "beebeeb.io" },
            "user": { "id": ceremony::b64url(b"user-handle-16by"), "name": "a", "displayName": "a" },
            "challenge": ceremony::b64url(&[5u8; 32]),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "authenticatorSelection": { "residentKey": "required", "userVerification": uv },
        },
        "reg_id": "4f1c2a8e-6b1d-4b5e-9a35-2b7f7d1f0c11"
    });
    let rp = ExpectedRp::new("beebeeb.io");
    let creation = ceremony::parse_registration_start(&reg, &rp).unwrap().options;
    let probe = RequestOptions::local_prf_probe(&creation, &[1u8; 16]);
    let login = json!({
        "publicKey": {
            "challenge": ceremony::b64url(&[6u8; 32]), "rpId": "beebeeb.io",
            "allowCredentials": [{ "type": "public-key", "id": ceremony::b64url(&[1u8; 16]) }],
            "userVerification": uv
        },
        "auth_state": "c3RhdGU", "user_id": "9d0e1a1f-0000-4000-8000-000000000001"
    });
    let assertion = ceremony::parse_assertion_start(&login, &rp).unwrap().options;
    (
        creation.user_verification,
        probe.user_verification,
        assertion.user_verification,
    )
}

#[test]
fn a_server_option_of_discouraged_or_preferred_comes_out_required_everywhere() {
    for uv in ["discouraged", "preferred", "required", ""] {
        let (c, p, a) = forced(uv);
        assert_eq!(
            (c.as_str(), p.as_str(), a.as_str()),
            ("required", "required", "required"),
            "server sent {uv:?}"
        );
    }
    let _: Option<Value> = None;
}
