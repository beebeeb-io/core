use super::*;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use beebeeb_api::{Answer, Header};
use beebeeb_core::opaque_protocol::{
    client_registration_finish, client_registration_start, server_login_finish, server_login_start,
    server_registration_finish,
};
use tokio::sync::broadcast;

const ACCOUNT: &[u8] = b"person@example.test";
const PASSWORD: &str = "correct horse battery staple 42";
const CONFIRM_TOKEN: &str = "confirm-token-1";
const STEP_UP_START: &str = "/api/v1/auth/confirm-opaque-start";
const STEP_UP_FINISH: &str = "/api/v1/auth/confirm-opaque-finish";
const DELETE_REQUEST: &str = "/api/v1/auth/account/delete-request";
const ACCOUNT_ME: &str = "/api/v1/auth/me";

/// Where the server answers the password step-up with its 401.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StepUpRefusal {
    /// At the start: password checks are locked after failed guesses, or the
    /// session is gone (the server answers both alike).
    Start,
    /// At the finish: the proof is refused.
    Finish,
}

/// A server that holds one account's OPAQUE password file. It answers the
/// step-up, the account (`GET /auth/me`), and the delete request only when
/// that carries the token the step-up minted; every other path is a 404. It
/// keeps every request it saw.
struct StepUpServer {
    server_setup: Vec<u8>,
    password_file: Vec<u8>,
    login_state: Mutex<Option<Vec<u8>>>,
    step_up_refusal: Option<StepUpRefusal>,
    session_gone: bool,
    delete_refusal: Option<Answer>,
    requests: Mutex<Vec<beebeeb_api::Request>>,
}

impl StepUpServer {
    fn with_account_password(password: &str) -> Self {
        let server_setup = create_server_setup();
        let started = client_registration_start(password.as_bytes()).unwrap();
        let answer = server_registration_start(&server_setup, &started.message, ACCOUNT).unwrap();
        let upload = client_registration_finish(&started.state, password.as_bytes(), &answer).unwrap();
        Self {
            server_setup,
            password_file: server_registration_finish(&upload).unwrap(),
            login_state: Mutex::new(None),
            step_up_refusal: None,
            session_gone: false,
            delete_refusal: None,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Refuse a delete request that carries a valid token with `refusal`, as
    /// the server does for an account that may not be deleted now.
    fn refusing_the_delete_request(mut self, refusal: Answer) -> Self {
        self.delete_refusal = Some(refusal);
        self
    }

    fn refusing_the_step_up_at(mut self, at: StepUpRefusal) -> Self {
        self.step_up_refusal = Some(at);
        self
    }

    /// The session no longer exists: `GET /auth/me` answers 401.
    fn with_the_session_gone(mut self) -> Self {
        self.session_gone = true;
        self
    }

    fn requests(&self) -> Vec<beebeeb_api::Request> {
        self.requests.lock().unwrap().clone()
    }

    fn paths(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| request.path().to_owned())
            .collect()
    }

    fn json(status: u16, body: serde_json::Value) -> Answer {
        Answer::new(status, Vec::new(), serde_json::to_vec(&body).unwrap())
    }

    fn unauthorized() -> Answer {
        Self::json(401, serde_json::json!({ "error": "unauthorized" }))
    }
}

/// A delete-request refusal as the server writes it: the stable code in
/// `code`, the text in `error`.
fn coded_refusal(status: u16, code: &str, text: &str, headers: Vec<Header>) -> Answer {
    Answer::new(
        status,
        headers,
        serde_json::to_vec(&serde_json::json!({ "code": code, "error": text })).unwrap(),
    )
}

fn drained(events: &mut broadcast::Receiver<EngineEvent>) -> Vec<EngineEvent> {
    std::iter::from_fn(|| events.try_recv().ok()).collect()
}

fn session_expiries(events: &[EngineEvent]) -> usize {
    events
        .iter()
        .filter(|event| **event == EngineEvent::SessionExpired)
        .count()
}

impl Transport for StepUpServer {
    fn send<'a>(&'a self, request: beebeeb_api::Request, _max_response_bytes: usize) -> TransportFuture<'a> {
        Box::pin(async move {
            self.requests
                .lock()
                .map_err(|_| TransportError::Network)?
                .push(request.clone());
            let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap_or(serde_json::Value::Null);
            let client_message = || {
                body["client_message"]
                    .as_str()
                    .and_then(|text| STANDARD.decode(text).ok())
                    .ok_or(TransportError::Network)
            };
            Ok(match request.path() {
                STEP_UP_START if self.step_up_refusal == Some(StepUpRefusal::Start) => Self::unauthorized(),
                STEP_UP_FINISH if self.step_up_refusal == Some(StepUpRefusal::Finish) => Self::unauthorized(),
                ACCOUNT_ME if self.session_gone => Self::unauthorized(),
                ACCOUNT_ME => Self::json(
                    200,
                    serde_json::json!({ "id": "account-id", "email": "person@example.test" }),
                ),
                STEP_UP_START => {
                    let started =
                        server_login_start(&self.server_setup, &self.password_file, &client_message()?, ACCOUNT)
                            .map_err(|_| TransportError::Network)?;
                    *self.login_state.lock().map_err(|_| TransportError::Network)? = Some(started.state);
                    Self::json(
                        200,
                        serde_json::json!({
                            "server_message": STANDARD.encode(started.message),
                            "server_state": "server-state-1",
                            "ksf_version": 1,
                        }),
                    )
                }
                STEP_UP_FINISH => {
                    let state = self
                        .login_state
                        .lock()
                        .map_err(|_| TransportError::Network)?
                        .take()
                        .ok_or(TransportError::Network)?;
                    match server_login_finish(&state, &client_message()?) {
                        Ok(_) => Self::json(
                            200,
                            serde_json::json!({
                                "confirmation_token": CONFIRM_TOKEN,
                                "expires_at": "2026-11-11T12:05:00Z",
                            }),
                        ),
                        Err(_) => Self::json(401, serde_json::json!({ "error": "invalid credentials" })),
                    }
                }
                DELETE_REQUEST if request.header("X-Confirm-Token") == Some(CONFIRM_TOKEN) => {
                    match &self.delete_refusal {
                        Some(refusal) => refusal.clone(),
                        None => Self::json(
                            200,
                            serde_json::json!({
                                "email_link_sent": true,
                                "link_expires_at": "2026-11-11T13:00:00Z",
                                "scheduled": false,
                            }),
                        ),
                    }
                }
                _ => Self::json(404, serde_json::json!({ "error": "not found" })),
            })
        })
    }
}

fn signed_in_client(server: &Arc<StepUpServer>) -> Client {
    let client = Client::new(ClientConfig::for_tests(), server.clone()).unwrap();
    client.set_authentication("session-token", "account-id").unwrap();
    client
}

/// The secret's own bytes and the encodings a request could carry it in.
fn forms_of(secret: &str) -> Vec<Vec<u8>> {
    let hex: String = secret.bytes().map(|byte| format!("{byte:02x}")).collect();
    let percent: String = secret
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => char::from(byte).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect();
    [
        secret.to_owned(),
        STANDARD.encode(secret),
        STANDARD_NO_PAD.encode(secret),
        URL_SAFE.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
        hex.to_uppercase(),
        hex,
        percent,
        secret.replace(' ', "+"),
    ]
    .into_iter()
    .map(String::into_bytes)
    .collect()
}

/// Where in `request` the secret appears, in any of its forms: the body, the
/// path, a header name or a header value.
fn carries(request: &beebeeb_api::Request, secret: &str) -> bool {
    let mut fields: Vec<&[u8]> = vec![request.body(), request.path().as_bytes()];
    for header in request.headers() {
        fields.push(header.name.as_bytes());
        fields.push(header.value.as_bytes());
    }
    forms_of(secret).iter().any(|form| {
        fields
            .iter()
            .any(|field| field.windows(form.len()).any(|window| window == form.as_slice()))
    })
}

fn body_keys(request: &beebeeb_api::Request) -> Vec<String> {
    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    let mut keys: Vec<String> = body.as_object().expect("a JSON object").keys().cloned().collect();
    keys.sort();
    keys
}

#[tokio::test]
async fn account_deletion_never_puts_the_password_on_the_wire() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD));
    let client = signed_in_client(&server);

    let _ = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), Some("123456".to_owned()))
        .await;

    let requests = server.requests();
    assert_eq!(requests.len(), 3, "the step-up's two requests and the delete request");
    for request in &requests {
        assert!(
            !carries(request, PASSWORD),
            "the password is in the request to {}",
            request.path()
        );
    }
}

#[tokio::test]
async fn the_step_up_bodies_hold_only_the_opaque_messages() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD));
    let client = signed_in_client(&server);

    client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await
        .unwrap();

    let requests = server.requests();
    assert_eq!(requests[0].path(), STEP_UP_START);
    assert_eq!(body_keys(&requests[0]), ["client_message"]);
    assert_eq!(requests[1].path(), STEP_UP_FINISH);
    assert_eq!(body_keys(&requests[1]), ["client_message", "server_state"]);
}

#[tokio::test]
async fn account_deletion_asks_for_the_link_with_the_step_up_token() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD));
    let client = signed_in_client(&server);

    client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), Some("123456".to_owned()))
        .await
        .expect("the server accepts a delete request that carries the step-up token");

    let requests = server.requests();
    let paths: Vec<&str> = requests.iter().map(|request| request.path()).collect();
    assert_eq!(paths, [STEP_UP_START, STEP_UP_FINISH, DELETE_REQUEST]);
    let delete = &requests[2];
    assert_eq!(delete.method(), beebeeb_api::Method::Post);
    assert_eq!(delete.header("X-Confirm-Token"), Some(CONFIRM_TOKEN));
    let mut header_names: Vec<&str> = delete.headers().iter().map(|header| header.name.as_str()).collect();
    header_names.sort_unstable();
    assert_eq!(
        header_names,
        [
            "Authorization",
            "Content-Type",
            "X-Beebeeb-Client",
            "X-Beebeeb-Client-Version",
            "X-Beebeeb-Expected-User",
            "X-Confirm-Token",
        ]
    );
    let body: serde_json::Value = serde_json::from_slice(delete.body()).unwrap();
    assert_eq!(body, serde_json::json!({ "code": "123456" }));
}

#[tokio::test]
async fn account_deletion_without_an_authenticator_code_sends_an_empty_body() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD));
    let client = signed_in_client(&server);

    client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await
        .expect("an account without an authenticator needs no code");

    let requests = server.requests();
    let delete = requests.last().expect("the delete request");
    assert_eq!(delete.path(), DELETE_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(delete.body()).unwrap();
    assert_eq!(body, serde_json::json!({}));
}

#[tokio::test]
async fn a_wrong_password_never_reaches_the_delete_request() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD));
    let client = signed_in_client(&server);

    let refused = client
        .request_account_deletion(Zeroizing::new("not the password".to_owned()), None)
        .await;

    assert!(refused.is_err(), "a wrong password must not delete anything");
    let requests = server.requests();
    let paths: Vec<&str> = requests.iter().map(|request| request.path()).collect();
    assert_eq!(paths, [STEP_UP_START], "only the step-up may be tried");
}

fn server_refusal(result: Result<(), AuthError>) -> beebeeb_core::api_error::ServerError {
    match result {
        Err(AuthError::Client(ClientError::Api(beebeeb_api::ApiError::Server(error)))) => error,
        other => panic!("expected the server's refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_refused_delete_request_reports_the_servers_refusal() {
    let server = Arc::new(
        StepUpServer::with_account_password(PASSWORD).refusing_the_delete_request(coded_refusal(
            409,
            "delete_subscription_active",
            "You still have an active subscription. Cancel it first, then ask again. No link was sent.",
            vec![],
        )),
    );
    let client = signed_in_client(&server);

    let refused = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await;

    let error = server_refusal(refused);
    assert_eq!(error.status, 409);
    assert_eq!(error.code.as_deref(), Some("delete_subscription_active"));
    assert_eq!(
        error.message,
        "You still have an active subscription. Cancel it first, then ask again. No link was sent."
    );
}

#[tokio::test]
async fn a_rate_limited_delete_request_carries_the_delay_from_its_header() {
    let server = Arc::new(
        StepUpServer::with_account_password(PASSWORD).refusing_the_delete_request(coded_refusal(
            429,
            "delete_request_rate_limited",
            "A link was sent less than a minute ago. Check your email, or try again in a minute.",
            vec![Header::new("retry-after", "60")],
        )),
    );
    let client = signed_in_client(&server);

    let refused = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await;

    let error = server_refusal(refused);
    assert!(error.is_code("delete_request_rate_limited"));
    assert_eq!(error.retry_after(), Some(60));
}

#[tokio::test]
async fn a_wrong_password_is_not_confirmed_and_the_session_stays() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD));
    let client = signed_in_client(&server);
    let mut events = client.events().subscribe();

    let refused = client
        .request_account_deletion(Zeroizing::new("not the password".to_owned()), None)
        .await;

    assert!(matches!(refused, Err(AuthError::PasswordNotConfirmed)), "{refused:?}");
    assert_eq!(server.paths(), [STEP_UP_START]);
    assert_eq!(session_expiries(&drained(&mut events)), 0);
}

#[tokio::test]
async fn a_refused_proof_ends_the_deletion_without_ending_the_session() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD).refusing_the_step_up_at(StepUpRefusal::Finish));
    let client = signed_in_client(&server);
    let mut events = client.events().subscribe();

    let refused = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await;

    assert!(matches!(refused, Err(AuthError::PasswordNotConfirmed)), "{refused:?}");
    assert_eq!(server.paths(), [STEP_UP_START, STEP_UP_FINISH]);
    assert_eq!(session_expiries(&drained(&mut events)), 0);
}

#[tokio::test]
async fn a_refused_proof_ends_the_password_change_without_ending_the_session() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD).refusing_the_step_up_at(StepUpRefusal::Finish));
    let client = signed_in_client(&server);
    let store = crate::MemorySecretStore::default();
    let mut events = client.events().subscribe();

    let refused = client
        .change_password(
            Zeroizing::new(PASSWORD.to_owned()),
            Zeroizing::new("a different long passphrase 7".to_owned()),
            &store,
        )
        .await;

    assert!(matches!(refused, Err(AuthError::PasswordNotConfirmed)), "{refused:?}");
    assert_eq!(server.paths(), [STEP_UP_START, STEP_UP_FINISH]);
    assert_eq!(session_expiries(&drained(&mut events)), 0);
}

#[tokio::test]
async fn a_refused_proof_ends_the_email_change_without_ending_the_session() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD).refusing_the_step_up_at(StepUpRefusal::Finish));
    let client = signed_in_client(&server);
    let store = crate::MemorySecretStore::default();
    session("account-id", "session-token", 1)
        .save(&store, "test-app")
        .unwrap();
    let mut events = client.events().subscribe();

    let refused = client
        .change_email("new@example.test", Zeroizing::new(PASSWORD.to_owned()), &store)
        .await;

    assert!(matches!(refused, Err(AuthError::PasswordNotConfirmed)), "{refused:?}");
    assert_eq!(server.paths(), [STEP_UP_START, STEP_UP_FINISH]);
    assert_eq!(session_expiries(&drained(&mut events)), 0);
}

#[tokio::test]
async fn a_refused_start_on_a_live_session_is_a_refused_step_up() {
    let server = Arc::new(StepUpServer::with_account_password(PASSWORD).refusing_the_step_up_at(StepUpRefusal::Start));
    let client = signed_in_client(&server);
    let mut events = client.events().subscribe();

    let refused = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await;

    assert!(matches!(refused, Err(AuthError::PasswordNotConfirmed)), "{refused:?}");
    assert_eq!(server.paths(), [STEP_UP_START, ACCOUNT_ME], "the account is asked once");
    assert_eq!(session_expiries(&drained(&mut events)), 0);
}

#[tokio::test]
async fn a_refused_start_on_a_gone_session_reports_the_session_expired_once() {
    let server = Arc::new(
        StepUpServer::with_account_password(PASSWORD)
            .refusing_the_step_up_at(StepUpRefusal::Start)
            .with_the_session_gone(),
    );
    let client = signed_in_client(&server);
    let mut events = client.events().subscribe();

    let refused = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await;

    assert_eq!(server_refusal(refused).status, 401);
    assert_eq!(server.paths(), [STEP_UP_START, ACCOUNT_ME]);
    assert_eq!(session_expiries(&drained(&mut events)), 1);
}

#[tokio::test]
async fn a_401_on_the_delete_request_still_reports_the_session_expired() {
    let server = Arc::new(
        StepUpServer::with_account_password(PASSWORD).refusing_the_delete_request(StepUpServer::unauthorized()),
    );
    let client = signed_in_client(&server);
    let mut events = client.events().subscribe();

    let refused = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await;

    assert_eq!(server_refusal(refused).status, 401);
    assert_eq!(server.paths(), [STEP_UP_START, STEP_UP_FINISH, DELETE_REQUEST]);
    assert_eq!(session_expiries(&drained(&mut events)), 1);
}
