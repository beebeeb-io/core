//! PhraseRecovery against a mock server built on core's own OPAQUE server half.
use base64::Engine;
use serde_json::json;

use super::*;
use crate::opaque_protocol;

fn ok(body: serde_json::Value) -> HttpResponse {
    HttpResponse::new(200, body)
}

fn phrase() -> (String, [u8; 32]) {
    let (p, mk) = recovery::generate_recovery_phrase().unwrap();
    (p, *opaque::compute_recovery_check(&mk))
}

#[test]
fn only_the_check_leaves_the_device() {
    let (p, check) = phrase();
    let (_, req) = PhraseRecovery::start(SignupPolicy::default(), "Anna@example.eu", &p.to_uppercase()).unwrap();
    assert_eq!(req.path, RECOVER_START_PATH);
    let body = req.body.unwrap();
    assert_eq!(body["email"], "anna@example.eu");
    assert_eq!(b64().decode(body["recovery_check"].as_str().unwrap()).unwrap(), check);
    let first = p.split_whitespace().next().unwrap();
    assert!(!body.to_string().contains(first));
}

#[test]
fn a_bad_phrase_is_refused_before_sending() {
    let words = "abandon ".repeat(12);
    assert_eq!(
        PhraseRecovery::start(SignupPolicy::default(), "anna@example.eu", &words).unwrap_err(),
        SignupError::InvalidPhrase
    );
    assert_eq!(
        PhraseRecovery::start(SignupPolicy::default(), "anna@example.eu", "abandon ability").unwrap_err(),
        SignupError::InvalidPhrase
    );
    assert_eq!(unknown_word_positions(&["abandon", "abel", "", "Zoo"]), vec![1]);
}

#[test]
fn a_refused_phrase_is_one_answer() {
    let (p, _) = phrase();
    for status in [400, 401, 404] {
        let (mut f, _) = PhraseRecovery::start(SignupPolicy::default(), "anna@example.eu", &p).unwrap();
        assert_eq!(
            f.on_start_response(&HttpResponse::new(status, json!({}))).unwrap_err(),
            SignupError::PhraseNotAccepted
        );
    }
    let (mut f, _) = PhraseRecovery::start(SignupPolicy::default(), "anna@example.eu", &p).unwrap();
    assert!(matches!(
        f.on_start_response(&HttpResponse::new(429, json!({}))).unwrap_err(),
        SignupError::RateLimited { .. }
    ));
    assert_eq!(
        f.set_password("long enough pass", "long enough pass").unwrap_err(),
        SignupError::WrongState
    );
}

fn recover(final_resp: HttpResponse) -> Result<Recovered, SignupError> {
    let setup = opaque_protocol::create_server_setup();
    let (p, check) = phrase();
    let (mut f, _) = PhraseRecovery::start(SignupPolicy::default(), "anna@example.eu", &p).unwrap();
    f.on_start_response(&ok(json!({ "recovery_token": "rt" }))).unwrap();
    assert_eq!(
        f.set_password("short", "short").unwrap_err(),
        SignupError::PasswordTooShort { missing: 7 }
    );
    let req = f.set_password("a brand new password", "a brand new password").unwrap();
    assert_eq!(req.path, RECOVER_REGISTER_PATH);
    let body = req.body.unwrap();
    assert_eq!(body["recovery_token"], "rt");
    let msg = b64().decode(body["client_message"].as_str().unwrap()).unwrap();
    let sm = opaque_protocol::server_registration_start(&setup, &msg, b"anna@example.eu").unwrap();
    let req = f
        .on_register_response(&ok(json!({ "server_message": b64().encode(sm) })))
        .unwrap();
    assert_eq!(req.path, RECOVER_FINALIZE_PATH);
    let body = req.body.unwrap();
    opaque_protocol::server_registration_finish(&b64().decode(body["opaque_registration"].as_str().unwrap()).unwrap())
        .unwrap();
    assert_eq!(b64().decode(body["recovery_check"].as_str().unwrap()).unwrap(), check);
    f.on_finalize_response(&final_resp)
}

#[test]
fn full_recovery_signs_in_with_the_same_master_key() {
    match recover(ok(json!({ "session_token": "s9" }))).unwrap() {
        Recovered::SignedIn { session_token, .. } => assert_eq!(session_token.as_str(), "s9"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn two_factor_or_an_older_server_asks_for_a_sign_in() {
    assert!(matches!(
        recover(ok(json!({ "requires_2fa": true, "partial_token": "p" }))).unwrap(),
        Recovered::SignInRequired
    ));
    let r = HttpResponse::new(409, json!({ "error": "password_set_sign_in_required" }));
    assert!(matches!(recover(r).unwrap(), Recovered::SignInRequired));
    assert_eq!(
        recover(HttpResponse::new(410, json!({}))).unwrap_err(),
        SignupError::RecoveryExpired
    );
}
