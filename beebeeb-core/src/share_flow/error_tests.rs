//! How the share flows read the server's refusals, in the server's own body shapes
//! (`beebeeb-api` `error/response.rs`), and the link limits.
use serde_json::json;

use super::link::{CreateLink, LinkOptions, LinkStep, MAX_EXPIRES_IN_HOURS, MAX_OPENS};
use super::*;
use crate::kdf::{FileKey, MasterKey};

const APP: &str = "https://app.beebeeb.test";
const FILE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn start(options: &LinkOptions) -> Result<(CreateLink, HttpRequest), ShareFlowError> {
    CreateLink::start(
        APP,
        FILE_ID,
        &MasterKey::from_bytes([1; 32]),
        &FileKey::from_bytes([7; 32]),
        options,
    )
}

// ── 403: a refusal with the server's code, never the session ──────────────────

#[test]
fn a_coded_403_keeps_the_servers_code() {
    let bodies = [
        (
            "sharing_paused",
            json!({
                "error": "sharing_paused",
                "message": "Sharing is paused on this account while we review it. Your files are unaffected.",
            }),
        ),
        (
            "email_unverified",
            json!({
                "error": "email_unverified",
                "message": "Verify your email address to upload, share, or receive files. Check your inbox or request a new link.",
            }),
        ),
        (
            "billing_read_only",
            json!({
                "error": "billing_read_only",
                "message": "Your account is read-only due to an unpaid invoice. Update your payment method to restore access.",
            }),
        ),
        (
            "billing_suspended",
            json!({
                "error": "billing_suspended",
                "message": "Your account is suspended due to an unpaid invoice. Update your payment method or export your data.",
            }),
        ),
        ("account_suspended", json!({ "error": "account_suspended" })),
        ("forbidden", json!({ "error": "forbidden" })),
        (
            "confirmation_required",
            json!({ "error": "confirmation_required", "message": "This action requires password confirmation" }),
        ),
        // A coded route's shape (`code` first, the text in `error`), as `ServerError::parse_coded_body` reads it.
        (
            "sharing_paused",
            json!({ "code": "sharing_paused", "error": "Sharing is paused on this account while we review it." }),
        ),
    ];
    for (code, body) in bodies {
        let err = ShareFlowError::from_status(&HttpResponse::new(403, body));
        assert_eq!(err, ShareFlowError::Forbidden { code: code.to_owned() }, "{code}");
        assert_eq!(err.host_code(), code);
        assert_eq!(err.code(), "forbidden");
    }
}

#[test]
fn the_frozen_403_carries_no_code_and_its_text_is_never_kept() {
    // `ApiError::AccountFrozen`: the generic `{"error": <message>}` body.
    let err = ShareFlowError::from_status(&HttpResponse::new(
        403,
        json!({ "error": "Your account is frozen. Unfreeze it in Settings → Privacy to resume." }),
    ));
    assert_eq!(
        err,
        ShareFlowError::Forbidden {
            code: "forbidden".to_owned()
        }
    );
    assert!(!err.to_string().contains("frozen"), "{err}");
}

#[test]
fn a_frozen_account_with_its_code_keeps_it() {
    // `ApiError::AccountFrozen` once it sends `{"error": "account_frozen", "message": ...}` (LD-0155).
    let body = json!({
        "error": "account_frozen",
        "message": "Your account is frozen. Unfreeze it in Settings → Privacy to resume.",
    });
    let err = ShareFlowError::from_status(&HttpResponse::new(403, body.clone()));
    assert_eq!(
        err,
        ShareFlowError::Forbidden {
            code: "account_frozen".to_owned()
        }
    );
    let (mut flow, _) = start(&LinkOptions::default()).unwrap();
    assert_eq!(
        flow.on_response(HttpResponse::new(403, body)).unwrap_err().host_code(),
        "account_frozen"
    );
}

#[test]
fn a_401_is_the_session_and_a_typed_refusal_wins_over_the_status() {
    let unauthorized = ShareFlowError::from_status(&HttpResponse::new(401, json!({ "error": "unauthorized" })));
    assert_eq!(unauthorized, ShareFlowError::Unauthorized);
    let refused = ShareFlowError::from_status(&HttpResponse::new(
        403,
        json!({ "error": "trial_cancelled_read_only", "message": "..." }),
    ));
    assert_eq!(refused, ShareFlowError::Refused("trial_cancelled_read_only"));
}

#[test]
fn a_link_refused_with_403_reaches_the_caller_with_its_code() {
    let (mut flow, _) = start(&LinkOptions::default()).unwrap();
    let err = flow
        .on_response(HttpResponse::new(
            403,
            json!({ "error": "sharing_paused", "message": "Sharing is paused on this account while we review it. Your files are unaffected." }),
        ))
        .unwrap_err();
    assert_eq!(err.host_code(), "sharing_paused");
}

// ── 409: only a token collision gets a fresh token ────────────────────────────

#[test]
fn a_refused_409_in_the_servers_shape_is_sent_once() {
    // `ApiError::ConflictCode`: `{"error": <code>, "message": <text>}` (signup_plan `plan_required`).
    let (mut flow, _) = start(&LinkOptions::default()).unwrap();
    let err = flow
        .on_response(HttpResponse::new(
            409,
            json!({ "error": "plan_required", "message": "Sharing needs a plan. The storage you already have stays as it is." }),
        ))
        .unwrap_err();
    assert_eq!(err, ShareFlowError::Refused("plan_required"));
    assert_eq!(
        flow.on_response(HttpResponse::new(200, json!({}))).unwrap_err(),
        ShareFlowError::WrongState
    );
}

#[test]
fn an_other_409_is_not_a_token_collision() {
    // `ApiError::Conflict("upload is still in progress")`.
    let (mut flow, _) = start(&LinkOptions::default()).unwrap();
    let err = flow
        .on_response(HttpResponse::new(
            409,
            json!({ "error": "upload is still in progress" }),
        ))
        .unwrap_err();
    assert_eq!(err, ShareFlowError::Server { status: 409 });
}

#[test]
fn the_servers_token_collision_gets_one_fresh_token() {
    for body in [
        // An older `POST /shares`: `ApiError::Conflict` on the token's unique violation.
        json!({ "error": "share token already exists — regenerate and retry" }),
        // `POST /shares` that sends the code (LD-0155): `ApiError::ConflictCode`, the sentence in `message`.
        json!({ "error": "token_taken", "message": "share token already exists — regenerate and retry" }),
        // A coded route's shape: the code in `code`, the text in `error`.
        json!({ "code": "token_taken", "error": "share token already exists — regenerate and retry" }),
    ] {
        let (mut flow, first) = start(&LinkOptions::default()).unwrap();
        let LinkStep::Send(second) = flow.on_response(HttpResponse::new(409, body.clone())).unwrap() else {
            panic!("expected a retry for {body}")
        };
        assert_ne!(first.body.unwrap()["token"], second.body.unwrap()["token"]);
        assert_eq!(
            flow.on_response(HttpResponse::new(409, body)).unwrap_err(),
            ShareFlowError::Server { status: 409 },
            "one retry only"
        );
    }
}

// ── Link limits ───────────────────────────────────────────────────────────────

#[test]
fn link_limits_are_bounded() {
    let with = |expires_in_hours, max_opens| LinkOptions {
        expires_in_hours,
        max_opens,
        passphrase: None,
    };
    assert!(start(&with(Some(MAX_EXPIRES_IN_HOURS), Some(MAX_OPENS))).is_ok());
    assert_eq!(
        start(&with(Some(MAX_EXPIRES_IN_HOURS + 1), None)).unwrap_err(),
        ShareFlowError::InvalidInput("expires in hours")
    );
    assert_eq!(
        start(&with(Some(u32::MAX), None)).unwrap_err(),
        ShareFlowError::InvalidInput("expires in hours")
    );
    assert_eq!(
        start(&with(None, Some(MAX_OPENS + 1))).unwrap_err(),
        ShareFlowError::InvalidInput("max opens")
    );
    assert_eq!(MAX_OPENS, i32::MAX as u32);
    let key = FileKey::from_bytes([7; 32]);
    let items = [super::bundle::BundleItem {
        file_id: FILE_ID,
        position: 0,
        file_key: &key,
    }];
    assert_eq!(
        CreateLink::bundle(
            APP,
            &items,
            &MasterKey::from_bytes([1; 32]),
            &with(None, Some(u32::MAX))
        )
        .unwrap_err(),
        ShareFlowError::InvalidInput("max opens")
    );
}
