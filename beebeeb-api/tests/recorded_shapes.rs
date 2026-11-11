use beebeeb_api::{
    Answer, FlowRequest, proposed,
    routes::{account, auth, files, folder_links, invites, onboarding, photo_backup, settings, shares, sync, uploads},
};
use beebeeb_core::share_flow::{folder, link, member};

fn answer(json: &str) -> Answer {
    Answer::new(200, vec![], json.as_bytes().to_vec())
}

#[test]
fn parses_recorded_live_onboarding_shape() {
    let body = r#"{"schema":1,"generated_at":"2026-11-04T09:44:10Z","ttl_seconds":300,"client":{"status":"ok"},"stage":"pre_account","signup":{"allowed":true,"mode":"native","reason":null,"web_url":"http://127.0.0.1:3031/signup"},"policy":{"password":{"min_length":12,"breach_check":{"endpoint":"/api/v1/auth/pwned-range/{prefix}","fail_open":true}},"recovery_phrase":{"word_count":12,"verify_word_count":3},"terms":{"version":"2026-09-29","url":"https://beebeeb.io/terms","privacy_url":"https://beebeeb.io/privacy"},"email_code":{"length":8,"ttl_seconds":900,"resend_after_seconds":60,"ticket_ttl_seconds":1800},"pilot_key":{"required":false}},"steps":[{"id":"enter_email","status":"todo","required":true,"ui":"action"},{"id":"verify_email_code","status":"todo","required":true,"ui":"action","params":{"length":8,"ttl_seconds":900}},{"id":"accept_terms","status":"todo","required":true,"ui":"action","params":{"version":"2026-09-29"}},{"id":"set_password","status":"todo","required":true,"ui":"action"},{"id":"save_recovery_phrase","status":"todo","required":true,"ui":"action"},{"id":"create_account","status":"todo","required":true,"ui":"action"}],"blocking":true,"copy":{"locale":"en","region_line":"Stored in the EU."},"fallback":{"kind":"use_web","url":"http://127.0.0.1:3031/signup"}}"#;
    let parsed = onboarding::document(false).parse(answer(body)).unwrap();
    assert_eq!(parsed.schema, 1);
    assert_eq!(parsed.stage, onboarding::OnboardingStage::PreAccount);
    assert_eq!(parsed.policy.as_ref().unwrap().password.min_length, 12);
    assert_eq!(parsed.policy.as_ref().unwrap().email_code.length, 8);
    assert_eq!(parsed.policy.as_ref().unwrap().recovery_phrase.word_count, 12);
    assert_eq!(parsed.policy.as_ref().unwrap().recovery_phrase.verify_word_count, 3);
    assert_eq!(parsed.policy.as_ref().unwrap().terms.version, "2026-09-29");
    assert_eq!(parsed.steps[1].id, "verify_email_code");
}

#[test]
fn parses_recorded_signup_email_start_shape() {
    let parsed = onboarding::email_start()
        .parse(Answer::new(
            202,
            vec![],
            br#"{"message":"If that address can sign up, we've sent you a code."}"#.to_vec(),
        ))
        .unwrap();
    assert!(parsed.message.contains("sent you a code"));
}

#[test]
fn session_creating_answers_never_invent_a_proven_key_state() {
    let registration = onboarding::register_finish()
        .parse(answer(r#"{"user_id":"account","session_token":"secret"}"#))
        .unwrap();
    assert_eq!(registration.key_state, None);

    let registration = onboarding::register_finish()
        .parse(answer(
            r#"{"user_id":"account","session_token":"secret","key_state":"locked"}"#,
        ))
        .unwrap();
    assert_eq!(registration.key_state.as_deref(), Some("locked"));

    let login = auth::opaque_finish()
        .parse(answer(
            r#"{"session_token":"secret","user_id":"account","key_state":"locked"}"#,
        ))
        .unwrap();
    assert_eq!(login.session_token.as_deref(), Some("secret"));
    assert_eq!(login.partial_token, None);
    assert_eq!(login.requires_2fa, None);
    assert_eq!(login.key_state.as_deref(), Some("locked"));

    let login_factor = auth::opaque_finish()
        .parse(answer(r#"{"requires_2fa":true,"partial_token":"partial-secret"}"#))
        .unwrap();
    assert_eq!(login_factor.session_token, None);
    assert_eq!(login_factor.partial_token.as_deref(), Some("partial-secret"));
    assert_eq!(login_factor.requires_2fa, Some(true));

    let two_factor = auth::complete_two_factor()
        .parse(answer(
            r#"{"user_id":"account","session_token":"secret","key_state":"locked"}"#,
        ))
        .unwrap();
    assert_eq!(two_factor.key_state.as_deref(), Some("locked"));

    let changed = proposed::change_password_finish()
        .parse(answer(
            r#"{"user_id":"account","session_token":"secret","key_state":"proven"}"#,
        ))
        .unwrap();
    assert_eq!(changed.key_state.as_deref(), Some("proven"));
}

#[test]
fn parses_recorded_device_report_shape() {
    let reported = beebeeb_api::routes::devices::register()
        .parse(answer(
            r#"{"id":"53d33e04-3cf1-4cd2-9e37-a266be4d0b0c","client_key":null,"hostname_encrypted":null,"hostname":"","platform":"macos","bb_version":"0.1.1","last_seen":"2026-11-04T12:00:00Z","created_at":"2026-11-04T12:00:00Z","hardware_id":"a0b8c4a2-65f3-4c08-8d72-a393139b90ed","reported_name":"desktop","reported_by_device":true,"holds_key":true}"#,
        ))
        .unwrap();
    assert_eq!(reported.reported_name.as_deref(), Some("desktop"));
    assert_eq!(
        reported.hardware_id.as_deref(),
        Some("a0b8c4a2-65f3-4c08-8d72-a393139b90ed")
    );
    assert_eq!(reported.holds_key, Some(true));
}

#[test]
fn parses_recorded_ok_action_shapes() {
    let bodies = [
        proposed::approve_device_link("link")
            .parse(answer(r#"{"ok":true}"#))
            .unwrap()
            .ok,
        proposed::deny_device_link("link")
            .parse(answer(r#"{"ok":true}"#))
            .unwrap()
            .ok,
        proposed::ack_device_link("link")
            .parse(answer(r#"{"ok":true}"#))
            .unwrap()
            .ok,
        proposed::send_device_link_pake("link")
            .parse(answer(r#"{"ok":true}"#))
            .unwrap()
            .ok,
        proposed::cancel_recovery("recovery")
            .parse(answer(r#"{"ok":true}"#))
            .unwrap()
            .ok,
        proposed::cancel_recovery_with_token("recovery")
            .parse(answer(r#"{"ok":true}"#))
            .unwrap()
            .ok,
        proposed::store_passkey_copy()
            .parse(Answer::new(201, vec![], br#"{"ok":true}"#.to_vec()))
            .unwrap()
            .ok,
    ];
    assert!(bodies.into_iter().all(std::convert::identity));
}

#[test]
fn parses_recorded_invite_action_shapes() {
    let denied = invites::deny("invite")
        .parse(answer(r#"{"message":"invite denied","status":"denied"}"#))
        .unwrap();
    assert_eq!(denied.status, "denied");
    let withdrawn = invites::withdraw("invite")
        .parse(answer(r#"{"message":"claim withdrawn","status":"invited"}"#))
        .unwrap();
    assert_eq!(withdrawn.status, "invited");
}

#[test]
fn parses_recorded_preference_shapes() {
    let loaded = settings::preference("client_meta.contact.example")
        .parse(answer(r#"{"value":{"display_name":"Example"}}"#))
        .unwrap();
    assert_eq!(loaded.value["display_name"], "Example");

    let saved = settings::set_preference("client_meta.contact.example")
        .parse(answer(r#"{"message":"preference saved"}"#))
        .unwrap();
    assert_eq!(saved.message, "preference saved");
}

#[test]
fn parses_recorded_auth_action_shapes() {
    let logged_out = auth::logout().parse(answer(r#"{"message":"logged out"}"#)).unwrap();
    assert_eq!(logged_out.message, "logged out");

    let enabled = account::enable_totp()
        .parse(answer(r#"{"message":"2FA enabled"}"#))
        .unwrap();
    assert_eq!(enabled.message, "2FA enabled");
    let disabled = account::disable_totp()
        .parse(answer(r#"{"message":"2FA disabled"}"#))
        .unwrap();
    assert_eq!(disabled.message, "2FA disabled");
}

#[test]
fn parses_recorded_file_action_shapes() {
    let trashed = files::trash("file")
        .parse(answer(r#"{"message":"moved to trash","trashed_count":3}"#))
        .unwrap();
    assert_eq!(trashed.trashed_count, 3);
    let deleted = files::permanent_delete("file")
        .parse(answer(r#"{"message":"permanently deleted"}"#))
        .unwrap();
    assert_eq!(deleted.message, "permanently deleted");
    let usage = files::usage()
        .parse(answer(
            r#"{"used_bytes":42,"plan_limit_bytes":-1,"plan_name":"unlimited"}"#,
        ))
        .unwrap();
    assert_eq!(usage.plan_limit_bytes, -1);
}

#[test]
fn parses_recorded_folder_link_revoke_shape() {
    let revoked = folder_links::revoke("link")
        .parse(answer(r#"{"message":"link revoked"}"#))
        .unwrap();
    assert_eq!(revoked.message, "link revoked");
}

#[test]
fn parses_recorded_upload_abandon_shape() {
    let abandoned = uploads::abandon("file")
        .parse(answer(
            r#"{"id":"018f","status":"reverted","previous_version_number":2,"deleted":false}"#,
        ))
        .unwrap();
    assert_eq!(abandoned.previous_version_number, Some(2));
    assert!(!abandoned.deleted);
}

#[test]
fn parses_recorded_account_session_shapes() {
    let sessions = proposed::list_account_sessions()
        .parse(answer(
            r#"{"sessions":[{"id":"018f","is_current":true,"created_at":"2026-11-03T09:44:10Z","expires_at":"2026-12-03T09:44:10Z"}]}"#,
        ))
        .unwrap();
    assert!(sessions.sessions[0].is_current);
    assert_eq!(sessions.sessions[0].expires_at, "2026-12-03T09:44:10Z");

    let revoked = proposed::revoke_account_session("018f")
        .parse(answer(r#"{"message":"session revoked"}"#))
        .unwrap();
    assert_eq!(revoked.message, "session revoked");
}

#[test]
fn parses_recorded_file_listing_shape() {
    let body = r#"{
      "files":[{"id":"018f","parent_id":null,"name_encrypted":"sealed","is_folder":false,"is_trashed":false,"size_bytes":42,"version_number":3}],
      "next_cursor":"cursor"
    }"#;
    let parsed = files::list(None, false).parse(answer(body)).unwrap();
    assert_eq!(parsed.files[0].id, "018f");
    assert_eq!(parsed.next_cursor.as_deref(), Some("cursor"));
    assert_eq!(parsed.files[0].extra["version_number"], 3);
}

#[test]
fn parses_recorded_upload_init_shape() {
    let body = r#"{
      "file_id":"file","tenant_id":"tenant","object_version_id":"version",
      "upload_session_id":"session","chunk_size_bytes":4194304,"chunk_count":2,
      "storage_format_version":2,"storage_pool_id":"pool","region":"eu",
      "storage_location":{"region":"eu","country":"Netherlands","country_code":"NL"},
      "lease_expires_at":"2026-11-03T12:00:00Z","lease_seconds":3600,"heartbeat_interval_secs":1200
    }"#;
    let parsed = uploads::init()
        .parse(Answer::new(201, vec![], body.as_bytes().to_vec()))
        .unwrap();
    assert_eq!(parsed.upload_session_id, "session");
    assert_eq!(parsed.chunk_count, 2);
}

#[test]
fn parses_recorded_photo_backup_shapes() {
    let stats = photo_backup::stats()
        .parse(answer(
            r#"{"total_backed_up":4210,"last_backup_at":"2026-11-03T12:00:00Z","total_size_bytes":999}"#,
        ))
        .unwrap();
    assert_eq!(stats.total_backed_up, 4210);
    assert_eq!(stats.total_size_bytes, 999);

    let identifiers = photo_backup::identifiers("device")
        .parse(answer(r#"{"identifiers":{"file-a":"asset-a"}}"#))
        .unwrap();
    assert_eq!(identifiers.identifiers["file-a"], "asset-a");
}

/// Review r5, P1-1: the server keys every photo-backup association by
/// `X-Beebeeb-Device-Id` and puts a request without it in the account's
/// shared `''` map. Every keyed route carries it; `stats` is account-wide.
#[test]
fn photo_backup_routes_carry_the_device_id() {
    use beebeeb_api::{ClientIdentity, RequestBuilder};
    let builder = RequestBuilder::new(ClientIdentity::new("mobile-ios", "1")).with_auth("token", "user");
    let check = photo_backup::Check {
        identifiers: vec!["photo".into()],
    };
    let mark = photo_backup::Mark {
        local_identifier: "photo".into(),
        file_id: "file".into(),
    };
    let keyed = [
        photo_backup::check("phone-a").build(&builder, &check).unwrap(),
        photo_backup::mark("phone-a").build(&builder, &mark).unwrap(),
        photo_backup::identifiers("phone-a").build(&builder, &()).unwrap(),
        photo_backup::ids("phone-a", Some("next"), 100)
            .build(&builder, &())
            .unwrap(),
        photo_backup::clear_association("phone-a", "file")
            .build(&builder, &())
            .unwrap(),
    ];
    for request in &keyed {
        assert_eq!(
            request.header(photo_backup::DEVICE_ID_HEADER),
            Some("phone-a"),
            "{}",
            request.path()
        );
    }
    let stats = photo_backup::stats().build(&builder, &()).unwrap();
    assert_eq!(stats.header(photo_backup::DEVICE_ID_HEADER), None);
}

#[test]
fn parses_recorded_sync_submit_shape() {
    let parsed = sync::submit()
        .parse(answer(
            r#"{"applied":[{"client_op_id":"op","seq_id":8,"user_seq":3}],"rejected":[]}"#,
        ))
        .unwrap();
    assert_eq!(parsed.applied[0].seq_id, 8);
    assert!(parsed.rejected.is_empty());
}

#[test]
fn raw_upload_body_stays_raw() {
    use beebeeb_api::{ClientIdentity, RequestBuilder};
    let builder = RequestBuilder::new(ClientIdentity::new("mobile-ios", "1")).with_auth("token", "user");
    let request = uploads::chunk("session", 2).build(&builder, &[0, 1, 255]).unwrap();
    assert_eq!(request.body(), &[0, 1, 255]);
    assert_eq!(request.header("Content-Type"), Some("application/octet-stream"));
}

#[test]
fn public_share_chunk_routes_carry_the_required_headers() {
    use beebeeb_api::{ClientIdentity, RequestBuilder};
    let builder = RequestBuilder::new(ClientIdentity::new("mobile-ios", "1"));
    let manifest = shares::chunk_manifest("secret-token", Some("open sesame"))
        .build(&builder, &())
        .unwrap();
    assert_eq!(manifest.header("X-Share-Passphrase"), Some("open sesame"));
    let chunk = shares::chunk("secret-token", 3, "download-ticket", Some("open sesame"))
        .build(&builder, &())
        .unwrap();
    assert_eq!(chunk.header("X-Share-Download-Token"), Some("download-ticket"));
    assert_eq!(chunk.header("X-Share-Passphrase"), Some("open sesame"));
}

#[test]
fn version_history_uses_the_version_settings_route() {
    use beebeeb_api::{ClientIdentity, Method, RequestBuilder};
    let builder = RequestBuilder::new(ClientIdentity::new("mobile-ios", "1")).with_auth("token", "user");
    let request = settings::set_version_setting()
        .build(
            &builder,
            &settings::SetVersionSetting {
                scope: "account".into(),
                target_id: None,
                enabled: true,
                max_versions: None,
                retention_days: Some(30),
            },
        )
        .unwrap();
    assert_eq!(request.method(), Method::Put);
    assert_eq!(request.path(), "/api/v1/version-settings");
}

// ── The share bodies the server reads ─────────────────────────────────────────
//
// The server's field names, from its request types: `CreateInviteRequest`
// (`routes/invites/create.rs`), `ApproveRequest` (`routes/invites/approval.rs`),
// `CreateShareRequest` (`routes/shares/create.rs`) and `CreateFolderLinkRequest`
// (`routes/folder_links.rs`). The server ignores a field it does not declare, so a misspelt name is
// a value that silently never arrives.

const INVITE_CREATE_FIELDS: [&str; 9] = [
    "file_id",
    "recipient_email",
    "permission",
    "capability",
    "is_folder_share",
    "encrypted_folder_key",
    "encrypted_owner_folder_key",
    "folder_keys",
    "format",
];
const LINK_CREATE_FIELDS: [&str; 10] = [
    "file_id",
    "share_type",
    "items",
    "expires_in_hours",
    "max_opens",
    "passphrase",
    "wrapped_file_key",
    "owner_wrapped_key",
    "token",
    "owner_wrapped_token",
];
const FOLDER_LINK_CREATE_FIELDS: [&str; 14] = [
    "format",
    "id",
    "folder_id",
    "access_level",
    "label_encrypted",
    "expires_in_hours",
    "max_opens",
    "passphrase",
    "cap_bytes",
    "wrapped_folder_key",
    "owner_wrapped_key",
    "owner_wrapped_token",
    "token",
    "folder_keys",
];

const INVITE_APPROVE_FIELDS: [&str; 1] = ["encrypted_file_key"];

const SHARE_FILE: &str = "550e8400-e29b-41d4-a716-446655440000";
const SHARE_FOLDER: &str = "2237c000-0000-4000-8000-000000000001";

fn share_builder() -> beebeeb_api::RequestBuilder {
    beebeeb_api::RequestBuilder::new(beebeeb_api::ClientIdentity::new("desktop", "1"))
        .with_auth("session-token", "32e1e894-5249-4ca1-995b-0f031d52b26f")
}

/// The JSON body of a built request.
fn sent_body(request: &beebeeb_api::Request) -> serde_json::Value {
    serde_json::from_slice(request.body()).expect("a share body is JSON")
}

/// Every key of `body` is a field the server's request type declares, and every field in `required`
/// carries a value. One assertion reports every difference.
fn assert_server_reads(route: &str, body: &serde_json::Value, declared: &[&str], required: &[&str]) {
    let object = body.as_object().expect("a share body is a JSON object");
    let unread: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !declared.contains(key))
        .collect();
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|field| object.get(*field).is_none_or(serde_json::Value::is_null))
        .collect();
    assert!(
        unread.is_empty() && missing.is_empty(),
        "{route}: the server does not read {unread:?}; the body has no value for {missing:?}"
    );
}

fn share_master() -> beebeeb_core::kdf::MasterKey {
    beebeeb_core::kdf::MasterKey::from_bytes([1; 32])
}

fn share_file_key() -> beebeeb_core::kdf::FileKey {
    beebeeb_core::kdf::FileKey::from_bytes([7; 32])
}

/// A request of core's share flow as `beebeeb-api` builds it for the transport.
fn sent(request: beebeeb_core::auth_flow::HttpRequest) -> beebeeb_api::Request {
    FlowRequest::new(request).build(share_builder()).unwrap()
}

fn flow_answer(status: u16, body: serde_json::Value) -> beebeeb_core::auth_flow::HttpResponse {
    beebeeb_core::auth_flow::HttpResponse::new(status, body)
}

/// The invite-create body as `beebeeb-api` builds it for the transport.
fn invite_create_request() -> beebeeb_api::Request {
    let target = member::ShareTarget {
        item_id: SHARE_FILE.into(),
        is_folder: false,
    };
    let (_, request) = member::MemberInvite::start(
        &target,
        "bob@example.test",
        &share_master(),
        &share_file_key(),
        member::PeerKeyExpectation::NotCompared,
    )
    .unwrap();
    sent(request)
}

/// The link-create body as `beebeeb-api` builds it for the transport.
fn link_create_request() -> beebeeb_api::Request {
    let (_, request) = link::CreateLink::start(
        "https://app.beebeeb.test",
        SHARE_FILE,
        &share_master(),
        &share_file_key(),
        &link::LinkOptions::default(),
    )
    .unwrap();
    sent(request)
}

/// The folder-link-create body as `beebeeb-api` builds it for the transport: the flow's first
/// requests answered for a folder with no custody record, no invite and no children.
fn folder_link_create_request() -> beebeeb_api::Request {
    let input = folder::FolderLinkInput {
        folder_id: SHARE_FOLDER,
        app_url: "https://app.beebeeb.test",
        access_level: "view",
        label: None,
        expires_in_hours: None,
        cap_bytes: None,
        max_opens: None,
        passphrase: None,
        custody: beebeeb_core::share_flow::folder_keys::CustodyMemory::default(),
    };
    let (mut flow, _custody_read) = folder::FolderShare::link(input, &share_master()).unwrap();
    let last = [
        flow_answer(404, serde_json::json!({"error": "not_found"})),
        flow_answer(200, serde_json::json!({"invites": []})),
        flow_answer(200, serde_json::json!({"key_version": 1})),
        flow_answer(200, serde_json::json!({"files": []})),
    ]
    .into_iter()
    .map(|answer| flow.on_response(answer).unwrap())
    .last();
    let Some(folder::FolderStep::Send(create)) = last else {
        panic!("the flow did not reach the create: {last:?}")
    };
    sent(create.request)
}

/// RFC 7748's example public key (Alice), in the standard base64 the server lists keys in.
const RECIPIENT_PUBLIC_KEY_B64: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

/// The approval body as `beebeeb-api` builds it for the transport.
fn invite_approve_request() -> beebeeb_api::Request {
    let approval = member::approve_request(
        "7a1d1c2e-0000-4000-8000-000000000001",
        SHARE_FILE,
        RECIPIENT_PUBLIC_KEY_B64,
        &share_master(),
        &share_file_key(),
        member::PeerKeyExpectation::NotCompared,
    )
    .unwrap();
    sent(approval.request)
}

#[test]
fn invite_create_body_uses_the_server_field_names() {
    let request = invite_create_request();
    assert_eq!(request.path(), "/api/v1/shares/invites");
    assert_server_reads(
        "invite create",
        &sent_body(&request),
        &INVITE_CREATE_FIELDS,
        &["file_id", "recipient_email"],
    );
}

#[test]
fn link_create_body_carries_the_owner_copies_the_server_stores() {
    let request = link_create_request();
    assert_eq!(request.path(), "/api/v1/shares");
    // The token and both owner copies travel together (the server refuses a partial set): with them
    // the owner can copy the link again later.
    assert_server_reads(
        "link create",
        &sent_body(&request),
        &LINK_CREATE_FIELDS,
        &[
            "file_id",
            "wrapped_file_key",
            "token",
            "owner_wrapped_key",
            "owner_wrapped_token",
        ],
    );
}

#[test]
fn folder_link_create_body_carries_the_subtree_wraps_and_their_format() {
    let request = folder_link_create_request();
    assert_eq!(request.path(), "/api/v1/shares/folder-links");
    // `folder_keys` are the wraps the public listing hands a guest; `format` says how they are sealed.
    assert_server_reads(
        "folder link create",
        &sent_body(&request),
        &FOLDER_LINK_CREATE_FIELDS,
        &[
            "id",
            "folder_id",
            "wrapped_folder_key",
            "token",
            "owner_wrapped_key",
            "owner_wrapped_token",
            "folder_keys",
            "format",
        ],
    );
}

#[test]
fn invite_approval_body_uses_the_server_field_names() {
    let request = invite_approve_request();
    assert_eq!(
        request.path(),
        "/api/v1/shares/invites/7a1d1c2e-0000-4000-8000-000000000001/approve"
    );
    assert_server_reads(
        "invite approval",
        &sent_body(&request),
        &INVITE_APPROVE_FIELDS,
        &["encrypted_file_key"],
    );
}

/// The owner's listing and the public answer carry no token (the server keeps only its hash); the
/// owner's link comes back from the owner copies and the stored `wrapped_file_key`.
#[test]
fn parses_recorded_share_listing_and_public_share_shapes() {
    let listed = shares::mine()
        .parse(answer(
            r#"{"shares":[{"id":"8d2f0000-0000-4000-8000-000000000001","file_id":"550e8400-e29b-41d4-a716-446655440000","share_type":"file","item_count":0,"expires_at":null,"max_opens":null,"open_count":0,"download_count":0,"last_opened_at":null,"has_passphrase":false,"revoked":false,"created_at":"2026-11-11T12:00:00+00:00","owner_wrapped_key":"b3duZXIta2V5","owner_wrapped_token":"b3duZXItdG9rZW4=","file":{"name_encrypted":"sealed","size_bytes":42}}]}"#,
        ))
        .unwrap();
    let share = &listed.shares[0];
    assert_eq!(share.id, "8d2f0000-0000-4000-8000-000000000001");
    assert_eq!(share.file_id.as_deref(), Some(SHARE_FILE));
    assert_eq!(share.extra["owner_wrapped_key"], "b3duZXIta2V5");
    assert_eq!(share.extra["owner_wrapped_token"], "b3duZXItdG9rZW4=");

    let public = shares::public_get("public-token")
        .parse(answer(
            r#"{"id":"8d2f0000-0000-4000-8000-000000000001","share_type":"file","name_encrypted":"sealed","size_bytes":42,"expires_at":null,"max_opens":null,"open_count":1,"download_count":0,"created_at":"2026-11-11T12:00:00+00:00","double_encrypted":true,"wrapped_file_key":"d3JhcHBlZA=="}"#,
        ))
        .unwrap();
    assert_eq!(public.id, "8d2f0000-0000-4000-8000-000000000001");
    assert_eq!(public.extra["wrapped_file_key"], "d3JhcHBlZA==");
}
