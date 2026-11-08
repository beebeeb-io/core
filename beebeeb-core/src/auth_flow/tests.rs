//! The flows against a mock server that runs core's own OPAQUE server half and the requester's
//! decrypt, so a round trip proves the wire end to end without a network.
use std::sync::OnceLock;

use base64::Engine;
use serde_json::{Value, json};

use super::device::{Approval, ApproveStep, DENY_PATH, DeviceFacts, DeviceRequest, DeviceRequestEvent};
use super::sign_in::{SignIn, SignInStep, can_submit};
use super::step_up::{StepUp, StepUpPurpose, StepUpStep};
use super::*;
use crate::opaque_protocol as op;

const EMAIL: &str = "anna@northwind.studio";
const PASSWORD: &[u8] = b"correct horse battery staple";

struct Account {
    setup: Vec<u8>,
    file: Vec<u8>,
}

/// One registration for the whole suite (each OPAQUE leg pays Argon2id).
fn account() -> &'static Account {
    static ACCOUNT: OnceLock<Account> = OnceLock::new();
    ACCOUNT.get_or_init(|| {
        let setup = op::create_server_setup();
        let start = op::client_registration_start(PASSWORD).unwrap();
        let resp = op::server_registration_start(&setup, &start.message, EMAIL.as_bytes()).unwrap();
        let upload = op::client_registration_finish(&start.state, PASSWORD, &resp).unwrap();
        let file = op::server_registration_finish(&upload).unwrap();
        Account { setup, file }
    })
}

fn enc(b: &[u8]) -> String {
    b64().encode(b)
}

/// The server's half of an OPAQUE start leg (login or confirm).
fn opaque_start(req: &HttpRequest) -> HttpResponse {
    let a = account();
    let msg = b64_decode(req.body.as_ref().unwrap()["client_message"].as_str().unwrap()).unwrap();
    let r = op::server_login_start(&a.setup, &a.file, &msg, EMAIL.as_bytes()).unwrap();
    HttpResponse::new(
        200,
        json!({ "server_message": enc(&r.message), "server_state": enc(&r.state), "ksf_version": 1 }),
    )
}

/// The server's half of an OPAQUE finish leg: `Ok` when the password proved itself.
fn opaque_finish(req: &HttpRequest) -> Result<(), ()> {
    let body = req.body.as_ref().unwrap();
    let state = b64_decode(body["server_state"].as_str().unwrap()).unwrap();
    let msg = b64_decode(body["client_message"].as_str().unwrap()).unwrap();
    op::server_login_finish(&state, &msg).map(|_| ()).map_err(|_| ())
}

fn drive_sign_in(password: &[u8], finish: impl Fn(&HttpRequest) -> HttpResponse) -> Result<SignInStep, AuthFlowError> {
    let (mut flow, req) = SignIn::start(EMAIL, password)?;
    assert_eq!(req.path, sign_in::LOGIN_START_PATH);
    assert_eq!(req.auth, RequestAuth::None);
    match flow.on_response(opaque_start(&req))? {
        SignInStep::Send(req2) => {
            assert_eq!(req2.path, sign_in::LOGIN_FINISH_PATH);
            flow.on_response(finish(&req2))
        }
        _ => panic!("expected the finish leg"),
    }
}

#[test]
fn password_sign_in_returns_the_session_token() {
    let step = drive_sign_in(PASSWORD, |req| {
        assert!(opaque_finish(req).is_ok());
        HttpResponse::new(200, json!({ "session_token": "sess-1" }))
    })
    .unwrap();
    match step {
        SignInStep::SignedIn { session_token } => assert_eq!(session_token.as_str(), "sess-1"),
        _ => panic!("expected SignedIn"),
    }
}

#[test]
fn a_wrong_password_is_invalid_credentials_and_never_reaches_finish() {
    let err = drive_sign_in(b"wrong password!!", |_| panic!("finish must not be sent"))
        .err()
        .unwrap();
    assert_eq!(err, AuthFlowError::InvalidCredentials);
}

#[test]
fn unknown_email_401_rate_limit_and_deleted_map_to_codes() {
    let (mut f, _) = SignIn::start(EMAIL, PASSWORD).unwrap();
    assert_eq!(
        f.on_response(HttpResponse::new(404, Value::Null)).err(),
        Some(AuthFlowError::InvalidCredentials)
    );
    let (mut f, _) = SignIn::start(EMAIL, PASSWORD).unwrap();
    let mut r = HttpResponse::new(429, Value::Null);
    r.retry_after_secs = Some(30);
    assert_eq!(
        f.on_response(r).err(),
        Some(AuthFlowError::RateLimited { retry_after_secs: 30 })
    );
    let (mut f, _) = SignIn::start(EMAIL, PASSWORD).unwrap();
    let deleted = HttpResponse::new(403, json!({ "code": "account_deleted", "message": "server words" }));
    assert_eq!(f.on_response(deleted).err(), Some(AuthFlowError::AccountDeleted));
}

#[test]
fn two_factor_holds_the_partial_token_and_verifies_six_or_eight_digits() {
    let step = drive_sign_in(PASSWORD, |_| {
        HttpResponse::new(200, json!({ "requires_2fa": true, "partial_token": "partial-1" }))
    })
    .unwrap();
    let SignInStep::SecondFactor(pending) = step else {
        panic!("expected the second factor")
    };
    let req = pending.verify("123 456").unwrap();
    assert_eq!(req.path, sign_in::TWO_FACTOR_VERIFY_PATH);
    assert_eq!(req.body.as_ref().unwrap()["code"], "123456");
    assert_eq!(req.body.as_ref().unwrap()["partial_token"], "partial-1");
    assert!(pending.verify("1234-5678").is_ok(), "a backup code");
    assert!(pending.verify("12345").is_err());
    assert!(pending.verify("12a456").is_err());
    assert_eq!(
        pending.on_verify_response(HttpResponse::new(401, Value::Null)).err(),
        Some(AuthFlowError::WrongCode)
    );
    let token = pending
        .on_verify_response(HttpResponse::new(200, json!({ "session_token": "sess-2" })))
        .unwrap();
    assert_eq!(token.as_str(), "sess-2");
}

#[test]
fn submit_needs_an_address_and_a_password() {
    assert!(can_submit("anna@northwind.studio", 1));
    assert!(!can_submit("anna@northwind.studio", 0));
    assert!(!can_submit("anna", 5));
    assert!(!can_submit("anna@localhost", 5));
    assert!(SignIn::start("not-an-email", PASSWORD).is_err());
}

fn drive_step_up(purpose: StepUpPurpose) -> (Value, HttpRequest) {
    let (mut flow, req) = StepUp::start(PASSWORD, purpose).unwrap();
    assert_eq!(
        (req.path.as_str(), req.auth),
        (step_up::CONFIRM_START_PATH, RequestAuth::Session)
    );
    let StepUpStep::Send(fin) = flow.on_response(opaque_start(&req)).unwrap() else {
        panic!("finish leg")
    };
    assert!(opaque_finish(&fin).is_ok());
    let body = fin.body.clone().unwrap();
    let StepUpStep::Confirmed(token) = flow
        .on_response(HttpResponse::new(200, json!({ "confirmation_token": "ct-1" })))
        .unwrap()
    else {
        panic!("confirmed")
    };
    assert_eq!(format!("{token:?}"), "ConfirmToken(<redacted>)");
    let consumer = token.attach(HttpRequest::post("/api/v1/x", json!({}), RequestAuth::Session));
    (body, consumer)
}

#[test]
fn step_up_binds_the_device_approval_purpose_and_code() {
    let (body, consumer) = drive_step_up(StepUpPurpose::DeviceApproval {
        code: "k7qm 4wtd".into(),
    });
    assert_eq!(body["purpose"], "cli_device_approval");
    assert_eq!(body["cli_code"], "K7QM-4WTD");
    assert_eq!(consumer.confirm_token.as_deref().map(String::as_str), Some("ct-1"));
    let (generic, _) = drive_step_up(StepUpPurpose::Generic);
    assert!(generic.get("purpose").is_none());
}

#[test]
fn step_up_never_falls_back_to_a_plaintext_password() {
    let (mut flow, _) = StepUp::start(PASSWORD, StepUpPurpose::Generic).unwrap();
    let err = flow
        .on_response(HttpResponse::new(409, json!({ "opaque_unavailable": true })))
        .err();
    assert_eq!(err, Some(AuthFlowError::OpaqueUnavailable));
}

#[test]
fn device_request_and_approval_hand_over_the_keys_end_to_end() {
    // Requester opens the socket.
    let mut request = DeviceRequest::new();
    let facts = DeviceFacts {
        device_name: Some("Anna-Laptop".into()),
        client: "desktop".into(),
        client_version: "2.0.0".into(),
        os: "windows".into(),
    };
    let init: Value = serde_json::from_str(&request.init_frame(&facts)).unwrap();
    assert_eq!(init["device_name"], "Anna-Laptop");
    let requester_pub = init["ecdh_public_key_b64"].as_str().unwrap().to_owned();
    let waiting =
        json!({ "user_code": "K7QM-4WTD", "verification_uri": "https://app.beebeeb.test/cli-auth", "expires_in": 300 });
    match request.on_frame(&waiting.to_string()).unwrap() {
        DeviceRequestEvent::Waiting {
            user_code,
            verification_uri,
            expires_in,
        } => {
            assert_eq!((user_code.as_str(), expires_in), ("K7QM-4WTD", 300));
            assert!(!verification_uri.contains("K7QM"), "the link carries no code");
        }
        _ => panic!("waiting"),
    }

    // Approver looks it up, steps up, claims and relays.
    let (lookup, req) = Approval::lookup("k7qm-4wtd").unwrap();
    assert_eq!(req.path, "/api/v1/auth/cli-pubkey?code=K7QM-4WTD");
    let facts_json = json!({
        "requested_at": "2026-11-08T10:00:00Z", "expires_at": "2026-11-08T10:05:00Z",
        "ip": "203.0.113.7", "country": "DE", "device_name": "Anna-Laptop", "client": "desktop", "os": "windows"
    });
    let pending = lookup
        .on_response(HttpResponse::new(
            200,
            json!({ "ecdh_public_key_b64": requester_pub, "request": facts_json }),
        ))
        .unwrap();
    assert_eq!(pending.facts().country.as_deref(), Some("DE"));
    assert_eq!(
        pending.facts().seconds_left(
            chrono::DateTime::parse_from_rfc3339("2026-11-08T10:01:00Z")
                .unwrap()
                .timestamp()
        ),
        Some(240)
    );
    assert!(!pending.code_matches("K7QM-4WTE"));
    assert!(pending.code_matches("k7qm4wtd"));
    let master = [7u8; 32];
    let (mut run, req) = pending.approve("K7QM4WTD", PASSWORD, &master).unwrap();
    let ApproveStep::Send(fin) = run.on_response(opaque_start(&req)).unwrap() else {
        panic!()
    };
    assert_eq!(fin.body.as_ref().unwrap()["cli_code"], "K7QM-4WTD");
    let ApproveStep::Send(claim) = run
        .on_response(HttpResponse::new(200, json!({ "confirmation_token": "ct" })))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(claim.path, device::CLAIM_PATH);
    assert_eq!(claim.confirm_token.as_deref().map(String::as_str), Some("ct"));
    let ApproveStep::Send(relay) = run
        .on_response(HttpResponse::new(201, json!({ "session_token": "new-device-session" })))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(relay.path, device::RELAY_PATH);
    let rb = relay.body.clone().unwrap();
    assert!(
        !rb.to_string().contains("new-device-session"),
        "the relay carries ciphertext only"
    );
    assert!(matches!(
        run.on_response(HttpResponse::new(200, Value::Null)).unwrap(),
        ApproveStep::Approved
    ));

    // The server relays the ciphertext to the requester's socket.
    let frame = json!({
        "nonce_b64": rb["nonce_b64"], "encrypted_payload_b64": rb["encrypted_payload_b64"],
        "browser_ecdh_public_b64": rb["browser_ecdh_public_b64"],
    });
    match request.on_frame(&frame.to_string()).unwrap() {
        DeviceRequestEvent::Approved(creds) => {
            assert_eq!(creds.session_token, "new-device-session");
            assert_eq!(creds.master_key, master);
        }
        _ => panic!("approved"),
    }
}

#[test]
fn a_claimed_code_is_already_handled_and_an_unknown_code_is_not_found() {
    let (lookup, _) = Approval::lookup("K7QM-4WTD").unwrap();
    assert_eq!(
        lookup.on_response(HttpResponse::new(404, Value::Null)).err(),
        Some(AuthFlowError::RequestNotFound)
    );
    assert!(Approval::lookup("nope").is_err());

    let key = crate::cli_auth::CliEphemeralKey::generate();
    let (lookup, _) = Approval::lookup("K7QM-4WTD").unwrap();
    let pending = lookup
        .on_response(HttpResponse::new(
            200,
            json!({ "ecdh_public_key_b64": enc(key.public_key_bytes()), "request": null }),
        ))
        .unwrap();
    let (mut run, req) = pending.approve("K7QM-4WTD", PASSWORD, &[1u8; 32]).unwrap();
    let ApproveStep::Send(_) = run.on_response(opaque_start(&req)).unwrap() else {
        panic!()
    };
    let ApproveStep::Send(_) = run
        .on_response(HttpResponse::new(200, json!({ "confirmation_token": "ct" })))
        .unwrap()
    else {
        panic!()
    };
    let claimed = HttpResponse::new(409, json!({ "code": "cli_code_claimed" }));
    assert_eq!(run.on_response(claimed).err(), Some(AuthFlowError::AlreadyHandled));
}

#[test]
fn requester_maps_timeout_denied_and_garbled_keys() {
    let waiting = json!({ "user_code": "K7QM-4WTD", "verification_uri": "u", "expires_in": 300 }).to_string();
    let mut r = DeviceRequest::new();
    r.on_frame(&waiting).unwrap();
    assert_eq!(r.on_frame(r#"{"error":"timeout"}"#).err(), Some(AuthFlowError::Expired));
    let mut r = DeviceRequest::new();
    r.on_frame(&waiting).unwrap();
    assert_eq!(r.on_frame(r#"{"error":"denied"}"#).err(), Some(AuthFlowError::Denied));
    let mut r = DeviceRequest::new();
    r.on_frame(&waiting).unwrap();
    let other = crate::cli_auth::CliEphemeralKey::generate();
    let bad = json!({ "nonce_b64": enc(&[0u8; 12]), "encrypted_payload_b64": enc(&[1u8; 40]),
        "browser_ecdh_public_b64": enc(other.public_key_bytes()) });
    assert_eq!(
        r.on_frame(&bad.to_string()).err(),
        Some(AuthFlowError::KeysDidNotArrive)
    );
}

#[test]
fn no_debug_print_carries_a_secret() {
    let (flow, req) = StepUp::start(PASSWORD, StepUpPurpose::Generic).unwrap();
    drop(flow);
    let printed = format!("{req:?}");
    assert!(!printed.contains("client_message"), "{printed}");
    let mut with_token = HttpRequest::post("/p", json!({ "partial_token": "secret-partial" }), RequestAuth::None);
    with_token.confirm_token = Some(zeroize::Zeroizing::new("secret-ct".into()));
    let printed = format!("{with_token:?}");
    assert!(
        !printed.contains("secret-partial") && !printed.contains("secret-ct"),
        "{printed}"
    );
}

#[test]
fn device_codes_normalize_like_the_server() {
    assert_eq!(normalize_device_code(" k7qm-4wtd ").as_deref(), Some("K7QM-4WTD"));
    assert_eq!(normalize_device_code("K7QM4WTD").as_deref(), Some("K7QM-4WTD"));
    assert!(normalize_device_code("K7QM-4WT").is_none());
    assert!(normalize_device_code("K7QM-4WT!").is_none());
}

#[test]
fn deny_posts_the_code_and_maps_not_found() {
    let (denial, req) = Approval::deny(" k7qm-4wtd ").unwrap();
    assert_eq!((req.method, req.path.as_str()), (Method::Post, DENY_PATH));
    assert_eq!(req.auth, RequestAuth::Session);
    assert!(req.confirm_token.is_none());
    assert_eq!(req.body.as_ref().unwrap()["user_code"], "K7QM-4WTD");
    assert!(
        denial
            .on_response(HttpResponse::new(200, json!({ "denied": true })))
            .is_ok()
    );
    let (denial, _) = Approval::deny("K7QM-4WTD").unwrap();
    assert_eq!(
        denial.on_response(HttpResponse::new(404, json!({}))).err(),
        Some(AuthFlowError::RequestNotFound)
    );
    let (denial, _) = Approval::deny("K7QM-4WTD").unwrap();
    assert!(denial.on_response(HttpResponse::new(200, json!({}))).is_err());
    assert_eq!(
        Approval::deny("nope").err().map(|e| e.code()),
        Some("request_not_found")
    );
}

#[test]
fn the_approval_payload_is_serialized_into_one_presized_buffer() {
    let token = "tok-\"quoted\"-\u{1}-value";
    let master = [7u8; 32];
    let buf = device::approval_plaintext(token, &master);
    let initial_cap = 64 + 6 * token.len() + b64().encode(master).len();
    // The buffer was never reallocated, so no freed copy of the payload exists.
    assert_eq!(buf.capacity(), initial_cap, "the payload buffer reallocated");
    let v: Value = serde_json::from_slice(&buf).unwrap();
    assert!(v["session_token"].as_str() == Some(token), "token round-trips");
    assert!(v["master_key_b64"].as_str() == Some(b64().encode(master).as_str()));
    assert_eq!(v.as_object().unwrap().len(), 2);
}

#[test]
fn a_cli_code_never_silently_replaces_another_purpose() {
    use super::step_up::StepUpPurpose as P;
    let s = |v: &str| Some(v.to_owned());
    assert_eq!(P::from_parts(None, None), Ok(P::Generic));
    assert_eq!(P::from_parts(s(""), None), Ok(P::Generic));
    assert_eq!(
        P::from_parts(s("password_step_up"), None),
        Ok(P::Named("password_step_up".into()))
    );
    assert_eq!(
        P::from_parts(None, s("K7QM-4WTD")),
        Ok(P::DeviceApproval {
            code: "K7QM-4WTD".into()
        })
    );
    assert_eq!(
        P::from_parts(s("cli_device_approval"), s("K7QM-4WTD")),
        Ok(P::DeviceApproval {
            code: "K7QM-4WTD".into()
        })
    );
    assert_eq!(
        P::from_parts(s("password_step_up"), s("K7QM-4WTD")).unwrap_err().code(),
        "invalid_input"
    );
    assert_eq!(
        P::from_parts(s("cli_device_approval"), None).unwrap_err().code(),
        "invalid_input"
    );
}
