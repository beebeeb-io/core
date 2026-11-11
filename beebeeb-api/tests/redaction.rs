//! Crypto review, P2-5: wire records that carry a secret print
//! `[REDACTED]` for it in `Debug` (core CLAUDE.md, "Secrets ... never appear in
//! errors or debug output").

use beebeeb_api::{proposed, routes};

fn assert_hidden(debug: String, secrets: &[&str]) {
    for secret in secrets {
        assert!(!debug.contains(secret), "{secret} leaked: {debug}");
    }
    assert!(debug.contains("[REDACTED]"), "{debug}");
}

fn from_json<T: serde::de::DeserializeOwned>(json: serde_json::Value) -> T {
    serde_json::from_value(json).unwrap()
}

#[test]
fn authenticator_setup_hides_the_secret_its_uri_and_the_backup_codes() {
    let setup: routes::account::TotpSetup = from_json(serde_json::json!({
        "secret": "JBSWY3DPEHPK3PXP",
        "qr_uri": "otpauth://totp/Beebeeb?secret=JBSWY3DPEHPK3PXP",
        "backup_codes": ["backup-code-one", "backup-code-two"],
    }));
    assert_eq!(setup.secret.as_str(), "JBSWY3DPEHPK3PXP");
    assert_hidden(
        format!("{setup:?}"),
        &["JBSWY3DPEHPK3PXP", "backup-code-one", "backup-code-two"],
    );
}

#[test]
fn share_link_requests_and_records_hide_passphrases_and_tokens() {
    use beebeeb_core::share_flow::link::{CreateLink, LinkOptions};
    let options = LinkOptions {
        passphrase: Some("pass-phrase-secret".to_owned().into()),
        ..LinkOptions::default()
    };
    let (_, request) = CreateLink::start(
        "https://app.beebeeb.test",
        "550e8400-e29b-41d4-a716-446655440000",
        &beebeeb_core::kdf::MasterKey::from_bytes([1; 32]),
        &beebeeb_core::kdf::FileKey::from_bytes([7; 32]),
        &options,
    )
    .unwrap();
    let token = request.body.as_ref().unwrap()["token"].as_str().unwrap().to_owned();
    let builder = beebeeb_api::RequestBuilder::new(beebeeb_api::ClientIdentity::new("desktop", "1"))
        .with_auth("session-token-secret", "user");
    let sent = beebeeb_api::FlowRequest::new(request).build(builder).unwrap();
    let body: serde_json::Value = serde_json::from_slice(sent.body()).unwrap();
    assert_eq!(body["passphrase"], "pass-phrase-secret", "the wire form is unchanged");
    assert_hidden(
        format!("{sent:?}"),
        &["pass-phrase-secret", &token, "session-token-secret"],
    );

    let manifest: routes::shares::ChunkManifest = from_json(serde_json::json!({
        "chunk_count": 1, "size_bytes": 1, "chunks": [],
        "download_token": "download-token-secret", "download_token_expires_at": "2099",
    }));
    assert_hidden(format!("{manifest:?}"), &["download-token-secret"]);
}

#[test]
fn other_new_records_hide_their_tokens_tickets_and_codes() {
    let stream: routes::sync::StreamToken = from_json(serde_json::json!({"token": "stream-token-secret"}));
    assert_hidden(format!("{stream:?}"), &["stream-token-secret"]);
    let request: routes::file_requests::FileRequest =
        from_json(serde_json::json!({"id": "r", "token": "request-token-secret", "closed": false}));
    assert_hidden(format!("{request:?}"), &["request-token-secret"]);
    let created: routes::file_requests::Created =
        from_json(serde_json::json!({"id": "r", "token": "created-token-secret"}));
    assert_hidden(format!("{created:?}"), &["created-token-secret"]);
    let ticket: routes::onboarding::SignupTicket =
        from_json(serde_json::json!({"signup_ticket": "signup-ticket-secret"}));
    assert_hidden(format!("{ticket:?}"), &["signup-ticket-secret"]);
    let export: routes::account::DataExport =
        from_json(serde_json::json!({"id": "e", "status": "ready", "download_url": "https://x/?sig=export-secret"}));
    assert_hidden(format!("{export:?}"), &["export-secret"]);

    let verify = routes::onboarding::EmailVerify {
        email: "a@example.test".into(),
        code: zeroize::Zeroizing::new("email-code-secret".into()),
    };
    assert_hidden(format!("{verify:?}"), &["email-code-secret"]);
    let start = routes::onboarding::EmailStart {
        email: "a@example.test".into(),
        pilot_key: Some("pilot-key-secret".into()),
    };
    assert_hidden(format!("{start:?}"), &["pilot-key-secret"]);
    let answer = proposed::KeyProofAnswer {
        response: "tag".into(),
        email_code_ticket: Some("email-ticket-secret".into()),
    };
    assert_hidden(format!("{answer:?}"), &["email-ticket-secret"]);
}
