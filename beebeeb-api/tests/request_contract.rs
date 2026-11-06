use beebeeb_api::{
    Answer, ApiError, ClientIdentity, RequestBuilder,
    routes::{devices, files, uploads},
};

fn builder() -> RequestBuilder {
    RequestBuilder::new(ClientIdentity::new("mobile-ios", "1.2.3"))
        .with_auth("secret-session-token", "32e1e894-5249-4ca1-995b-0f031d52b26f")
}

#[test]
fn builder_adds_auth_expected_user_and_client_headers() {
    let request = files::get("file-id").build(&builder(), &()).unwrap();
    assert_eq!(request.header("X-Beebeeb-Client"), Some("mobile-ios"));
    assert_eq!(request.header("X-Beebeeb-Client-Version"), Some("1.2.3"));
    assert_eq!(request.header("Authorization"), Some("Bearer secret-session-token"));
    assert_eq!(
        request.header("X-Beebeeb-Expected-User"),
        Some("32e1e894-5249-4ca1-995b-0f031d52b26f")
    );
}

#[test]
fn installed_device_report_uses_hardware_identity_and_reported_name() {
    let request = devices::register()
        .build(
            &builder(),
            &devices::Register {
                client_key: None,
                hostname_encrypted: None,
                hostname: None,
                platform: "ios".into(),
                bb_version: Some("1.2.3".into()),
                push_token: None,
                hardware_id: Some("a0b8c4a2-65f3-4c08-8d72-a393139b90ed".into()),
                reported_name: Some("mobile-ios".into()),
            },
        )
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    assert_eq!(body["hardware_id"], "a0b8c4a2-65f3-4c08-8d72-a393139b90ed");
    assert_eq!(body["reported_name"], "mobile-ios");
    assert_eq!(body["platform"], "ios");
    assert_eq!(body["bb_version"], "1.2.3");
    assert!(body.get("hostname").is_none());
    assert!(body.get("push_token").is_none());
}

#[test]
fn capabilities_are_sent_on_every_authenticated_request_including_chunks() {
    let builder = builder().with_capabilities(["file-write-v2", "version-metadata-v1"]);
    let ordinary = files::get("f").build(&builder, &()).unwrap();
    assert_eq!(
        ordinary.header("X-Beebeeb-Capabilities"),
        Some("file-write-v2, version-metadata-v1")
    );

    let init = uploads::init()
        .build(
            &builder,
            &uploads::InitRequest {
                file_id: None,
                file_name: "sealed".into(),
                file_size_bytes: 12,
                parent_id: None,
                profile: beebeeb_types::ChunkProfile::Mobile,
                preferred_region: None,
                chunk_size_bytes: Some(12),
                chunk_count: Some(1),
                is_media: false,
                base_version_number: None,
                created_at: None,
                conflict_created: false,
                version_metadata_encrypted: None,
            },
        )
        .unwrap();
    assert_eq!(
        init.header("X-Beebeeb-Capabilities"),
        Some("file-write-v2, version-metadata-v1")
    );

    let chunk = uploads::chunk("session", 0).build(&builder, b"ciphertext").unwrap();
    assert_eq!(
        chunk.header("X-Beebeeb-Capabilities"),
        Some("file-write-v2, version-metadata-v1")
    );
}

#[test]
fn request_debug_redacts_headers_body_and_sensitive_paths() {
    let request = beebeeb_api::routes::shares::public_get("public-secret-token")
        .build(&builder(), &())
        .unwrap();
    let debug = format!("{request:?}");
    assert!(!debug.contains("secret-session-token"));
    assert!(!debug.contains("public-secret-token"));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn answer_rejects_oversize_and_hostile_json() {
    let endpoint = files::get("f");
    let too_large = Answer::new(200, vec![], vec![b'x'; endpoint.max_response_bytes() + 1]);
    assert!(matches!(
        endpoint.parse(too_large),
        Err(ApiError::ResponseTooLarge { .. })
    ));

    let malformed = Answer::new(200, vec![], b"{not-json".to_vec());
    assert!(matches!(endpoint.parse(malformed), Err(ApiError::InvalidJson)));
}

#[test]
fn signup_web_only_keeps_the_typed_redirect_url() {
    let error = beebeeb_api::routes::onboarding::email_start()
        .parse(beebeeb_api::Answer::new(
            403,
            vec![],
            br#"{"error":"signup_web_only","message":"Create your account on the web at beebeeb.io.","signup_url":"https://app.beebeeb.io/signup"}"#.to_vec(),
        ))
        .unwrap_err();
    match error {
        beebeeb_api::ApiError::SignupWebOnly { signup_url } => {
            assert_eq!(signup_url, "https://app.beebeeb.io/signup")
        }
        other => panic!("expected typed signup refusal, got {other:?}"),
    }
}

#[test]
fn non_success_uses_core_server_error_parser() {
    let answer = Answer::new(
        409,
        vec![],
        br#"{"error":"account_mismatch","message":"wrong account"}"#.to_vec(),
    );
    let error = files::get("f").parse(answer).unwrap_err();
    match error {
        ApiError::Server(error) => {
            assert_eq!(error.code.as_deref(), Some("account_mismatch"));
            assert_eq!(error.message, "wrong account");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
