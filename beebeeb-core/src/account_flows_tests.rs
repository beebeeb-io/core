//! Account flows against a mock server that runs the real server half of OPAQUE.

use super::*;
use crate::opaque_protocol as op;

const EMAIL: &[u8] = b"anna@example.eu";

fn register(setup: &[u8], password: &[u8], username: &[u8]) -> Vec<u8> {
    let start = op::client_registration_start(password).unwrap();
    let resp = op::server_registration_start(setup, &start.message, username).unwrap();
    let upload = op::client_registration_finish(&start.state, password, &resp).unwrap();
    op::server_registration_finish(&upload).unwrap()
}

/// A small in-memory server: OPAQUE step-up, re-registration, and the account routes.
struct MockServer {
    setup: Vec<u8>,
    username: Vec<u8>,
    password_file: Vec<u8>,
    login_state: Option<Vec<u8>>,
    reg_username: Option<Vec<u8>>,
    issued_tokens: Vec<String>,
    used_tokens: Vec<String>,
    log: Vec<String>,
    totp_enabled: bool,
    opaque_unavailable: bool,
    email_taken: bool,
}

impl MockServer {
    fn new(password: &[u8]) -> Self {
        let setup = op::create_server_setup();
        let password_file = register(&setup, password, EMAIL);
        Self {
            setup,
            username: EMAIL.to_vec(),
            password_file,
            login_state: None,
            reg_username: None,
            issued_tokens: vec![],
            used_tokens: vec![],
            log: vec![],
            totp_enabled: false,
            opaque_unavailable: false,
            email_taken: false,
        }
    }

    fn take_token(&mut self, req: &ApiRequest) -> bool {
        let Some(t) = req.confirm_token() else { return false };
        if self.used_tokens.iter().any(|u| u == t) || !self.issued_tokens.iter().any(|i| i == t) {
            return false;
        }
        self.used_tokens.push(t.to_string());
        true
    }

    fn b(req: &ApiRequest, f: &str) -> Vec<u8> {
        B64.decode(req.body.as_ref().unwrap()[f].as_str().unwrap()).unwrap()
    }
}

impl AccountTransport for MockServer {
    fn send(&mut self, req: &ApiRequest) -> Result<ApiResponse, AccountFlowError> {
        self.log.push(format!(
            "{} {}{}",
            req.method.as_str(),
            req.path,
            if req.confirm_token().is_some() { " +token" } else { "" }
        ));
        let r = match req.path.as_str() {
            PATH_CONFIRM_START => {
                if self.opaque_unavailable {
                    return Ok(ApiResponse::new(409, json!({ "opaque_unavailable": true })));
                }
                let msg = Self::b(req, "client_message");
                let s = op::server_login_start(&self.setup, &self.password_file, &msg, &self.username).unwrap();
                self.login_state = Some(s.state);
                ApiResponse::new(
                    200,
                    json!({ "server_message": B64.encode(&s.message), "server_state": "st", "ksf_version": 1 }),
                )
            }
            PATH_CONFIRM_FINISH => {
                let fin = Self::b(req, "client_message");
                match op::server_login_finish(&self.login_state.take().unwrap(), &fin) {
                    Ok(_) => {
                        let t = format!("tok{}", self.issued_tokens.len());
                        self.issued_tokens.push(t.clone());
                        ApiResponse::new(200, json!({ "confirmation_token": t, "expires_at": "x" }))
                    }
                    Err(_) => ApiResponse::new(401, json!({ "error": "invalid" })),
                }
            }
            PATH_CHANGE_PASSWORD_START | PATH_EMAIL_START => {
                if !self.take_token(req) {
                    return Ok(ApiResponse::new(403, json!({ "code": "confirmation_required" })));
                }
                let body = req.body.as_ref().unwrap();
                let (field, user) = if req.path == PATH_EMAIL_START {
                    if self.email_taken {
                        return Ok(ApiResponse::new(
                            409,
                            json!({ "error": "This email is already in use." }),
                        ));
                    }
                    (
                        "opaque_client_message",
                        body["new_email"].as_str().unwrap().as_bytes().to_vec(),
                    )
                } else {
                    ("client_message", self.username.clone())
                };
                let msg = Self::b(req, field);
                let resp = op::server_registration_start(&self.setup, &msg, &user).unwrap();
                self.reg_username = Some(user);
                ApiResponse::new(
                    200,
                    json!({ "server_message": B64.encode(&resp), "email_change_token": "ect" }),
                )
            }
            PATH_CHANGE_PASSWORD_FINISH => {
                if !self.take_token(req) {
                    return Ok(ApiResponse::new(403, json!({})));
                }
                let body = req.body.as_ref().unwrap();
                assert!(body["recovery_check"].is_string() && body["x25519_public_key"].is_string());
                self.password_file = op::server_registration_finish(&Self::b(req, "client_message")).unwrap();
                ApiResponse::new(
                    200,
                    json!({ "message": "ok", "salt": "", "session_token": "new-session" }),
                )
            }
            PATH_EMAIL_FINISH => {
                assert_eq!(req.body.as_ref().unwrap()["email_change_token"], "ect");
                assert!(req.confirm_token().is_none());
                self.password_file = op::server_registration_finish(&Self::b(req, "opaque_registration")).unwrap();
                self.username = self.reg_username.take().unwrap();
                ApiResponse::new(
                    200,
                    json!({ "email": String::from_utf8(self.username.clone()).unwrap() }),
                )
            }
            PATH_TOTP_SETUP => {
                if self.totp_enabled && !self.take_token(req) {
                    let code = req.body.as_ref().and_then(|b| b["code"].as_str());
                    if code != Some("123456") {
                        return Ok(ApiResponse::new(403, json!({ "code": "confirmation_required" })));
                    }
                }
                let codes: Vec<String> = (0..8).map(|i| format!("{:08}", 11111111 * (i % 9 + 1))).collect();
                ApiResponse::new(
                    200,
                    json!({ "secret": "JBSWY3DPEHPK3PXP", "qr_uri": "otpauth://totp/x", "backup_codes": codes }),
                )
            }
            PATH_TOTP_ENABLE | PATH_TOTP_DISABLE => {
                let code = req.body.as_ref().unwrap()["code"].as_str().unwrap();
                if code != "123456" {
                    return Ok(ApiResponse::new(400, json!({ "error": "Invalid code" })));
                }
                self.totp_enabled = req.path == PATH_TOTP_ENABLE;
                ApiResponse::new(200, json!({ "message": "ok" }))
            }
            PATH_DELETE_ACCOUNT => {
                if !self.take_token(req) {
                    return Ok(ApiResponse::new(403, json!({})));
                }
                assert_eq!(req.body.as_ref().unwrap()["confirmation"], "DELETE");
                ApiResponse::new(200, json!({ "message": "ok", "shred_after": "2026-11-11T19:42:00Z" }))
            }
            PATH_REVOKE_OTHERS => ApiResponse::new(200, json!({ "revoked": 3 })),
            PATH_PROFILE | PATH_TRACKING | PATH_VERIFY_EMAIL => ApiResponse::new(200, json!({})),
            p if p.starts_with(PATH_SESSIONS) => ApiResponse::new(204, Value::Null),
            other => panic!("unexpected path {other}"),
        };
        Ok(r)
    }
}

fn binding() -> AccountBinding {
    AccountBinding::from_master_key(&MasterKey::from_bytes([7u8; 32]))
}

const OLD: &str = "correct horse battery";
const NEW: &str = "a much better passphrase";

#[test]
fn change_password_two_step_ups_then_new_password_logs_in() {
    let mut server = MockServer::new(OLD.as_bytes());
    let flow = AccountFlow::change_password(OLD, NEW, binding()).unwrap();
    let outcome = run(flow, &mut server).unwrap();
    let AccountOutcome::PasswordChanged { session_token } = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(session_token.as_str(), "new-session");
    assert_eq!(
        server.log,
        [
            "POST /api/v1/auth/confirm-opaque-start",
            "POST /api/v1/auth/confirm-opaque-finish",
            "POST /api/v1/auth/change-password-start +token",
            "POST /api/v1/auth/confirm-opaque-start",
            "POST /api/v1/auth/confirm-opaque-finish",
            "POST /api/v1/auth/change-password-finish +token",
        ]
    );
    assert_eq!(server.used_tokens, ["tok0", "tok1"], "one single-use token per leg");
    // The new password now passes a step-up; the old one does not.
    assert!(run(AccountFlow::delete_account(NEW).unwrap(), &mut server).is_ok());
    assert_eq!(
        run(AccountFlow::delete_account(OLD).unwrap(), &mut server).unwrap_err(),
        AccountFlowError::WrongPassword
    );
}

#[test]
fn change_password_wrong_current_changes_nothing() {
    let mut server = MockServer::new(OLD.as_bytes());
    let err = run(
        AccountFlow::change_password("not the password", NEW, binding()).unwrap(),
        &mut server,
    )
    .unwrap_err();
    assert_eq!(err, AccountFlowError::WrongPassword);
    assert_eq!(err.code(), "wrong_password");
    assert!(
        !server.log.iter().any(|l| l.contains("change-password")),
        "{:?}",
        server.log
    );
}

#[test]
fn change_password_policy_is_checked_before_any_request() {
    assert_eq!(
        AccountFlow::change_password(OLD, "short", binding()).err(),
        Some(AccountFlowError::WeakPassword)
    );
    assert_eq!(
        AccountFlow::change_password(OLD, OLD, binding()).err(),
        Some(AccountFlowError::SamePassword)
    );
}

#[test]
fn opaque_unavailable_never_falls_back_to_plaintext() {
    let mut server = MockServer::new(OLD.as_bytes());
    server.opaque_unavailable = true;
    let err = run(AccountFlow::delete_account(OLD).unwrap(), &mut server).unwrap_err();
    assert_eq!(err, AccountFlowError::OpaqueUnavailable);
    assert_eq!(server.log, ["POST /api/v1/auth/confirm-opaque-start"]);
}

#[test]
fn change_email_reregisters_under_the_new_address() {
    let mut server = MockServer::new(OLD.as_bytes());
    let out = run(
        AccountFlow::change_email(" New@Example.eu ", OLD, binding()).unwrap(),
        &mut server,
    )
    .unwrap();
    let AccountOutcome::EmailChanged { email } = out else {
        panic!()
    };
    assert_eq!(email, "new@example.eu");
    // The same password now proves itself under the new username.
    assert!(run(AccountFlow::delete_account(OLD).unwrap(), &mut server).is_ok());
    assert!(run(AccountFlow::verify_email("1234 5678").unwrap(), &mut server).is_ok());
    assert_eq!(
        AccountFlow::verify_email("1234").err(),
        Some(AccountFlowError::InvalidCode)
    );
}

#[test]
fn change_email_in_use_and_invalid() {
    let mut server = MockServer::new(OLD.as_bytes());
    server.email_taken = true;
    let err = run(
        AccountFlow::change_email("x@example.eu", OLD, binding()).unwrap(),
        &mut server,
    )
    .unwrap_err();
    assert_eq!(err, AccountFlowError::EmailInUse);
    assert_eq!(
        AccountFlow::change_email("nope", OLD, binding()).err(),
        Some(AccountFlowError::InvalidEmail)
    );
}

#[test]
fn totp_setup_confirm_releases_backup_codes_only_after_the_code() {
    let mut server = MockServer::new(OLD.as_bytes());
    let AccountOutcome::TotpEnrollment(enrollment) =
        run(AccountFlow::totp_setup(None, None).unwrap(), &mut server).unwrap()
    else {
        panic!()
    };
    assert_eq!(enrollment.secret.as_str(), "JBSWY3DPEHPK3PXP");
    // A wrong code keeps TOTP off and gives no codes.
    let err = run(AccountFlow::totp_confirm(enrollment, "000000").unwrap(), &mut server).unwrap_err();
    assert_eq!(err, AccountFlowError::InvalidCode);
    assert!(!server.totp_enabled);

    let AccountOutcome::TotpEnrollment(enrollment) =
        run(AccountFlow::totp_setup(None, None).unwrap(), &mut server).unwrap()
    else {
        panic!()
    };
    let AccountOutcome::BackupCodes(codes) =
        run(AccountFlow::totp_confirm(enrollment, "123456").unwrap(), &mut server).unwrap()
    else {
        panic!()
    };
    assert_eq!(codes.len(), 8);
    assert!(codes.iter().all(|c| c.len() == 8));
    assert!(server.totp_enabled);
}

#[test]
fn totp_setup_when_on_needs_a_step_up_or_the_current_code() {
    let mut server = MockServer::new(OLD.as_bytes());
    server.totp_enabled = true;
    assert_eq!(
        run(AccountFlow::totp_setup(None, None).unwrap(), &mut server).unwrap_err(),
        AccountFlowError::Server(403)
    );
    assert!(run(AccountFlow::totp_setup(Some(OLD), None).unwrap(), &mut server).is_ok());
    assert!(server.log.contains(&"POST /api/v1/auth/2fa/setup +token".to_string()));
    assert!(run(AccountFlow::totp_setup(None, Some("123 456")).unwrap(), &mut server).is_ok());
    assert_eq!(
        run(AccountFlow::totp_setup(None, Some("654321")).unwrap(), &mut server).unwrap_err(),
        AccountFlowError::InvalidCode
    );
}

#[test]
fn totp_disable_with_code() {
    let mut server = MockServer::new(OLD.as_bytes());
    server.totp_enabled = true;
    assert_eq!(
        run(AccountFlow::totp_disable("111111").unwrap(), &mut server).unwrap_err(),
        AccountFlowError::InvalidCode
    );
    assert!(server.totp_enabled);
    assert!(run(AccountFlow::totp_disable("123456").unwrap(), &mut server).is_ok());
    assert!(!server.totp_enabled);
    assert_eq!(
        AccountFlow::totp_disable("12ab56").err(),
        Some(AccountFlowError::InvalidCode)
    );
}

#[test]
fn delete_account_step_up_inside_and_schedule() {
    let mut server = MockServer::new(OLD.as_bytes());
    let out = run(AccountFlow::delete_account(OLD).unwrap(), &mut server).unwrap();
    let AccountOutcome::DeletionScheduled { shred_after } = out else {
        panic!()
    };
    assert_eq!(shred_after, "2026-11-11T19:42:00Z");
    assert_eq!(server.log.last().unwrap(), "DELETE /api/v1/auth/account +token");
}

#[test]
fn sessions_name_and_activity() {
    let mut server = MockServer::new(OLD.as_bytes());
    let AccountOutcome::Revoked { count } = run(AccountFlow::revoke_other_sessions(), &mut server).unwrap() else {
        panic!()
    };
    assert_eq!(count, 3);
    assert!(run(AccountFlow::revoke_session("4f2a-11").unwrap(), &mut server).is_ok());
    assert_eq!(
        AccountFlow::revoke_session("../x").err(),
        Some(AccountFlowError::Protocol)
    );
    assert!(run(AccountFlow::set_display_name("  Anna  ").unwrap(), &mut server).is_ok());
    assert_eq!(
        AccountFlow::set_display_name("   ").err(),
        Some(AccountFlowError::NameEmpty)
    );
    assert_eq!(
        AccountFlow::set_display_name(&"a".repeat(65)).err(),
        Some(AccountFlowError::NameTooLong)
    );
    assert!(run(AccountFlow::set_activity_logging(false), &mut server).is_ok());
}

#[test]
fn resume_out_of_order_is_refused() {
    let mut flow = AccountFlow::revoke_other_sessions();
    assert_eq!(
        flow.resume(ApiResponse::new(200, json!({}))).unwrap_err(),
        AccountFlowError::OutOfOrder
    );
    let mut flow = AccountFlow::revoke_other_sessions();
    flow.start().unwrap();
    assert!(flow.start().is_err());
}

#[test]
fn debug_output_never_prints_secrets() {
    let req = ApiRequest::new(Method::Post, "/p", Some(json!({ "client_message": "SECRETMSG" })))
        .gated(Zeroizing::new("TOKEN123".into()));
    let s = format!("{req:?}");
    assert!(!s.contains("SECRETMSG") && !s.contains("TOKEN123"), "{s}");
    let out = AccountOutcome::PasswordChanged {
        session_token: Zeroizing::new("SESSIONTOK".into()),
    };
    assert!(!format!("{out:?}").contains("SESSIONTOK"));
}

#[test]
fn host_session_totp_round_trip_keeps_codes_until_confirmed() {
    let mut server = MockServer::new(OLD.as_bytes());
    let mut host = HostSession::new();
    let mut step = host.begin(AccountFlow::totp_setup(None, None).unwrap()).unwrap();
    while !step.done {
        let req = ApiRequest::new(
            match step.method.as_str() {
                "POST" => Method::Post,
                "PUT" => Method::Put,
                "DELETE" => Method::Delete,
                _ => Method::Get,
            },
            step.path.clone(),
            serde_json::from_str(&step.body_json).ok(),
        );
        let resp = server.send(&req).unwrap();
        step = host.resume(resp.status, &resp.body.to_string()).unwrap();
    }
    let o = step.outcome.unwrap();
    assert_eq!(o.kind, "totp_enrollment");
    assert!(
        o.backup_codes.is_empty(),
        "codes are not released before the code is confirmed"
    );
    let step = host.totp_confirm("123456").unwrap();
    let req = ApiRequest::new(
        Method::Post,
        step.path.clone(),
        serde_json::from_str(&step.body_json).ok(),
    );
    let resp = server.send(&req).unwrap();
    let done = host.resume(resp.status, &resp.body.to_string()).unwrap();
    assert_eq!(done.outcome.unwrap().backup_codes.len(), 8);
    assert!(host.totp_confirm("123456").is_err(), "the enrollment is used once");
}

#[test]
fn verify_password_only_steps_up() {
    let mut server = MockServer::new(OLD.as_bytes());
    assert!(matches!(
        run(AccountFlow::verify_password(OLD).unwrap(), &mut server).unwrap(),
        AccountOutcome::Done
    ));
    assert_eq!(
        run(AccountFlow::verify_password("nope nope").unwrap(), &mut server).unwrap_err(),
        AccountFlowError::WrongPassword
    );
    assert!(
        server.log.iter().all(|l| l.contains("confirm-opaque")),
        "{:?}",
        server.log
    );
}
