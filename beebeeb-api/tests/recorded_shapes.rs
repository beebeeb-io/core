use beebeeb_api::{
    Answer, proposed,
    routes::{account, auth, files, folder_links, invites, onboarding, photo_backup, settings, shares, sync, uploads},
};

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

    let login = auth::login()
        .parse(answer(
            r#"{"session_token":"secret","user_id":"account","salt":"0123456789abcdef","key_state":"locked"}"#,
        ))
        .unwrap();
    assert_eq!(login.session_token.as_deref(), Some("secret"));
    assert_eq!(login.partial_token, None);
    assert_eq!(login.requires_2fa, None);
    assert_eq!(login.key_state.as_deref(), Some("locked"));

    let login_factor = auth::login()
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
    let approved = invites::approve("invite")
        .parse(answer(
            r#"{"message":"invite approved","status":"approved","permission":"view"}"#,
        ))
        .unwrap();
    assert_eq!(approved.permission, "view");
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
