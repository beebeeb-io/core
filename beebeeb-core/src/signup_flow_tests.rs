//! SignupFlow against a mock server built on core's own OPAQUE server half.
use base64::Engine;
use serde_json::json;

use super::*;
use crate::opaque_protocol;

fn ok(body: serde_json::Value) -> HttpResponse {
    HttpResponse::new(200, body)
}

fn policy(breach: bool) -> SignupPolicy {
    let mut doc = json!({ "policy": {
        "password": { "min_length": 12 },
        "recovery_phrase": { "verify_word_count": 3 },
        "email_code": { "length": 8, "ttl_seconds": 900, "resend_after_seconds": 60 },
        "terms": { "version": "2026-10", "url": "https://beebeeb.io/terms", "privacy_url": "https://evil.example/p" }
    }});
    if breach {
        doc["policy"]["password"]["breach_check"] =
            json!({ "endpoint": "/api/v1/breach/range/{prefix}", "fail_open": false });
    }
    SignupPolicy::from_response(&ok(doc)).unwrap()
}

/// Drive the flow to a verified email and an accepted password.
fn to_password(breach: bool) -> SignupFlow {
    let mut f = SignupFlow::new(policy(breach));
    let req = f.send_code(" Anna@Example.EU ").unwrap();
    assert_eq!(req.path, EMAIL_START_PATH);
    assert_eq!(req.body.as_ref().unwrap()["email"], "anna@example.eu");
    f.on_code_sent(&HttpResponse::new(202, json!({}))).unwrap();
    let req = f.verify_code("1234 5678").unwrap();
    assert_eq!(req.body.as_ref().unwrap()["code"], "12345678");
    f.on_code_verified(&ok(json!({ "signup_ticket": "tkt" }))).unwrap();
    let pw = "correct horse battery staple";
    if breach {
        let req = f.breach_request(pw).unwrap();
        assert!(req.path.starts_with("/api/v1/breach/range/"));
        assert_eq!(
            f.on_breach_response(Some(200), "0000000000000000000000000000000000A:1\n"),
            Some(BreachVerdict::Clean)
        );
    }
    f.set_password(pw, pw).unwrap();
    f
}

fn confirm(f: &mut SignupFlow) {
    let words = f.phrase_words().unwrap();
    assert_eq!(words.len(), 12);
    f.acknowledge_phrase().unwrap();
    let pos = f.challenge_positions().unwrap();
    assert_eq!(pos.len(), 3);
    let answers: Vec<String> = pos
        .iter()
        .map(|p| format!(" {} ", words[*p as usize - 1].to_uppercase()))
        .collect();
    f.confirm_phrase(&answers).unwrap();
}

#[test]
fn policy_reads_the_servers_numbers_and_keeps_the_floor() {
    let p = SignupPolicy::from_response(&ok(
        json!({ "policy": { "password": { "min_length": 4 }, "email_code": { "length": 6 } } }),
    ))
    .unwrap();
    assert_eq!(p.min_length, 12);
    assert_eq!(p.code_length, 6);
    assert_eq!(p.resend_after_secs, 60);
    let q = policy(true);
    assert_eq!(q.breach_endpoint.as_deref(), Some("/api/v1/breach/range/{prefix}"));
    assert_eq!(q.terms_url.as_deref(), Some("https://beebeeb.io/terms"));
    assert_eq!(q.privacy_url, None, "a foreign link is dropped");
    let bad = SignupPolicy::from_response(&ok(
        json!({ "password": { "breach_check": { "endpoint": "https://x.example/{prefix}" } } }),
    ))
    .unwrap();
    assert_eq!(bad.breach_endpoint, None);
}

#[test]
fn bad_email_and_code_are_refused_before_sending() {
    let mut f = SignupFlow::new(policy(false));
    assert_eq!(f.send_code("anna").unwrap_err(), SignupError::InvalidEmail);
    assert_eq!(f.verify_code("12345678").unwrap_err(), SignupError::WrongState);
    f.send_code("anna@example.eu").unwrap();
    assert_eq!(f.verify_code("1234").unwrap_err(), SignupError::WrongCode);
    assert_eq!(f.verify_code("1234567a").unwrap_err(), SignupError::WrongCode);
}

#[test]
fn wrong_code_and_rate_limit_map_to_codes() {
    let mut f = SignupFlow::new(policy(false));
    f.send_code("anna@example.eu").unwrap();
    let mut r = HttpResponse::new(429, json!({}));
    r.retry_after_secs = Some(42);
    assert_eq!(
        f.on_code_sent(&r).unwrap_err(),
        SignupError::RateLimited { retry_after_secs: 42 }
    );
    assert_eq!(
        f.on_code_verified(&HttpResponse::new(400, json!({ "message": "invalid or expired code" })))
            .unwrap_err(),
        SignupError::WrongCode
    );
    assert!(!f.email_verified());
}

#[test]
fn password_rules_come_from_the_ceremony() {
    let mut f = SignupFlow::new(policy(true));
    f.send_code("anna@example.eu").unwrap();
    f.on_code_verified(&ok(json!({ "signup_ticket": "t" }))).unwrap();
    assert_eq!(
        f.set_password("short pw", "short pw").unwrap_err(),
        SignupError::PasswordTooShort { missing: 4 }
    );
    assert_eq!(
        f.set_password("long enough pass", "long enough pasS").unwrap_err(),
        SignupError::PasswordMismatch
    );
    assert_eq!(
        f.set_password("long enough pass", "long enough pass").unwrap_err(),
        SignupError::BreachCheckMissing
    );
    // An outage with fail_open false keeps the person here.
    f.breach_request("long enough pass").unwrap();
    assert_eq!(f.on_breach_response(None, ""), Some(BreachVerdict::CheckFailedBlocked));
    assert_eq!(
        f.set_password("long enough pass", "long enough pass").unwrap_err(),
        SignupError::BreachCheckBlocked
    );
    // A check made for another password does not count.
    f.breach_request("another long one").unwrap();
    let _ = f.on_breach_response(Some(200), "");
    assert_eq!(
        f.set_password("long enough pass", "long enough pass").unwrap_err(),
        SignupError::BreachCheckMissing
    );
    assert_eq!(f.evaluate("abc").missing_characters, 9);
}

#[test]
fn wrong_words_do_not_pass() {
    let mut f = to_password(false);
    f.phrase_words().unwrap();
    f.acknowledge_phrase().unwrap();
    assert_eq!(
        f.confirm_phrase(&["zoo", "zoo", "zoo"]).unwrap_err(),
        SignupError::PhraseWordMismatch
    );
    // The same words come back after Show the words again.
    let a: Vec<String> = f.phrase_words().unwrap().iter().map(|w| w.to_string()).collect();
    let b: Vec<String> = f.phrase_words().unwrap().iter().map(|w| w.to_string()).collect();
    assert_eq!(a, b);
}

#[test]
fn registration_needs_the_phrase_confirmed() {
    let mut f = to_password(false);
    assert!(f.register_start().is_err());
}

#[test]
fn full_signup_against_a_mock_server() {
    let setup = opaque_protocol::create_server_setup();
    let mut f = to_password(true);
    confirm(&mut f);
    let req = f.register_start().unwrap();
    assert_eq!(req.path, REGISTER_START_PATH);
    let body = req.body.unwrap();
    assert_eq!(body["signup_ticket"], "tkt");
    let msg = b64().decode(body["client_message"].as_str().unwrap()).unwrap();
    let server_message = opaque_protocol::server_registration_start(&setup, &msg, b"anna@example.eu").unwrap();
    let req = f
        .on_register_start(&ok(json!({ "server_message": b64().encode(server_message) })))
        .unwrap();
    assert_eq!(req.path, REGISTER_FINISH_PATH);
    let body = req.body.unwrap();
    let upload = b64().decode(body["client_message"].as_str().unwrap()).unwrap();
    opaque_protocol::server_registration_finish(&upload).unwrap();
    assert_eq!(
        b64().decode(body["x25519_public_key"].as_str().unwrap()).unwrap().len(),
        32
    );
    assert_eq!(
        b64().decode(body["recovery_check"].as_str().unwrap()).unwrap().len(),
        32
    );
    let created = f
        .on_register_finish(&ok(json!({ "user_id": "u1", "session_token": "s1" })))
        .unwrap();
    assert_eq!(created.session_token.as_str(), "s1");
    assert_eq!(created.user_id, "u1");
    assert!(!format!("{created:?}").contains("s1"));
    let terms = f.terms_request().unwrap();
    assert_eq!(terms.body.unwrap()["version"], "2026-10");
    assert_eq!(terms.auth, RequestAuth::Session);
}

#[test]
fn an_expired_ticket_goes_back_to_verify_and_keeps_the_phrase() {
    let mut f = to_password(false);
    confirm(&mut f);
    f.register_start().unwrap();
    let refused = HttpResponse::new(403, json!({ "error": "signup_ticket_invalid" }));
    assert_eq!(f.on_register_start(&refused).unwrap_err(), SignupError::TicketExpired);
    assert!(!f.email_verified());
    assert_eq!(f.register_start().unwrap_err(), SignupError::TicketExpired);
    f.send_code("anna@example.eu").unwrap();
    f.on_code_verified(&ok(json!({ "signup_ticket": "t2" }))).unwrap();
    let req = f.register_start().unwrap();
    assert_eq!(req.body.unwrap()["signup_ticket"], "t2");
}

#[test]
fn a_server_failure_lets_the_person_try_again() {
    let mut f = to_password(false);
    confirm(&mut f);
    f.register_start().unwrap();
    assert_eq!(
        f.on_register_start(&HttpResponse::new(500, json!({}))).unwrap_err(),
        SignupError::RegistrationFailed
    );
    assert!(f.register_start().is_ok());
}

#[test]
fn debug_prints_hold_no_secret() {
    let mut f = to_password(false);
    let words = f.phrase_words().unwrap();
    let dbg = format!("{f:?}");
    assert!(!dbg.contains("tkt"));
    assert!(!dbg.contains(words[0].as_str()));
    assert!(!dbg.contains("correct horse"));
}
