//! How refusals decode: the account-delete routes' coded shape, a `Retry-After` delay
//! sent as a header only, and the step-up routes whose 401 is not a session verdict.
//! The bodies are the server's, as its account-delete and error renderers write them.

use beebeeb_api::{
    Answer, ApiError, Header, proposed,
    routes::{account, auth, downloads},
};
use beebeeb_core::api_error::ServerError;

fn refusal(error: ApiError) -> ServerError {
    match error {
        ApiError::Server(server) => server,
        other => panic!("expected the server's refusal, got {other:?}"),
    }
}

fn delete_request_refusal(status: u16, headers: Vec<Header>, body: &str) -> ServerError {
    refusal(
        account::request_deletion()
            .parse(Answer::new(status, headers, body.as_bytes().to_vec()))
            .expect_err("a refusal"),
    )
}

#[test]
fn delete_request_refusals_keep_the_code_the_server_puts_in_code() {
    let cases = [
        (
            403,
            r#"{"code":"second_factor_required","error":"Enter the code from your authenticator app, or a backup code."}"#,
            "second_factor_required",
            "Enter the code from your authenticator app, or a backup code.",
        ),
        (
            409,
            r#"{"code":"delete_already_scheduled","error":"This account is already scheduled for deletion. Cancel that first."}"#,
            "delete_already_scheduled",
            "This account is already scheduled for deletion. Cancel that first.",
        ),
        (
            409,
            r#"{"code":"delete_subscription_active","error":"You still have an active subscription. Cancel it first, then ask again. No link was sent."}"#,
            "delete_subscription_active",
            "You still have an active subscription. Cancel it first, then ask again. No link was sent.",
        ),
        (
            429,
            r#"{"code":"delete_request_rate_limited","error":"A link was sent less than a minute ago. Check your email, or try again in a minute."}"#,
            "delete_request_rate_limited",
            "A link was sent less than a minute ago. Check your email, or try again in a minute.",
        ),
        (
            502,
            r#"{"code":"delete_email_failed","error":"The confirmation email could not be sent. Nothing was scheduled. Try again later."}"#,
            "delete_email_failed",
            "The confirmation email could not be sent. Nothing was scheduled. Try again later.",
        ),
        // The refusals of the route's shared guards keep the two-field shape.
        (
            403,
            r#"{"error":"confirmation_required","message":"This action requires password confirmation"}"#,
            "confirmation_required",
            "This action requires password confirmation",
        ),
        (
            400,
            r#"{"error":"invalid_totp_code","message":"That code didn't match. Check your authenticator app and try again."}"#,
            "invalid_totp_code",
            "That code didn't match. Check your authenticator app and try again.",
        ),
    ];
    for (status, body, code, text) in cases {
        let error = delete_request_refusal(status, vec![], body);
        assert_eq!(error.status, status, "{code}");
        assert!(error.is_code(code), "{code}: decoded as {:?}", error.code);
        assert_eq!(error.message, text, "{code}");
    }
}

#[test]
fn a_retry_after_header_reaches_the_refusal_when_the_body_names_no_delay() {
    let rate_limited = delete_request_refusal(
        429,
        vec![Header::new("retry-after", "60")],
        r#"{"code":"delete_request_rate_limited","error":"A link was sent less than a minute ago. Check your email, or try again in a minute."}"#,
    );
    assert_eq!(rate_limited.retry_after(), Some(60));

    let statement_timeout = refusal(
        auth::me()
            .parse(Answer::new(
                503,
                vec![Header::new("Retry-After", "5")],
                br#"{"error":"statement_timeout","message":"This took too long, so the server stopped it. Try again in a moment."}"#.to_vec(),
            ))
            .expect_err("a refusal"),
    );
    assert_eq!(
        statement_timeout.retry_after(),
        Some(5),
        "the header name is case-insensitive"
    );

    let raw = refusal(
        downloads::file("file-1")
            .parse(Answer::new(
                429,
                vec![Header::new("retry-after", "12")],
                br#"{"error":"rate_limited"}"#.to_vec(),
            ))
            .expect_err("a refusal"),
    );
    assert_eq!(raw.retry_after(), Some(12), "raw routes read the header too");

    let body_wins = refusal(
        auth::me()
            .parse(Answer::new(
                429,
                vec![Header::new("retry-after", "60")],
                br#"{"error":"server_busy","retry_after":17}"#.to_vec(),
            ))
            .expect_err("a refusal"),
    );
    assert_eq!(body_wins.retry_after(), Some(17), "the body's own delay wins");
}

#[test]
fn only_the_password_step_up_routes_say_their_401_is_not_a_session_verdict() {
    assert!(proposed::confirm_opaque_start().is_step_up());
    assert!(proposed::confirm_opaque_finish().is_step_up());
    assert!(!auth::me().is_step_up());
    assert!(!account::request_deletion().is_step_up());
    assert!(!proposed::change_password_start().is_step_up());
    assert!(!proposed::change_email_start().is_step_up());
}
