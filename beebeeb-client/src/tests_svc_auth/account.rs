use super::*;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use beebeeb_core::opaque_protocol::{
    client_registration_finish, client_registration_start, server_login_finish, server_login_start,
    server_registration_finish,
};

const ACCOUNT: &[u8] = b"person@example.test";
const PASSWORD: &str = "correct horse battery staple 42";
const CONFIRM_TOKEN: &str = "confirm-token-1";
const STEP_UP_START: &str = "/api/v1/auth/confirm-opaque-start";
const STEP_UP_FINISH: &str = "/api/v1/auth/confirm-opaque-finish";
const DELETE_REQUEST: &str = "/api/v1/auth/account/delete-request";

/// A server that holds one account's OPAQUE password file. It answers the
/// step-up, and the delete request only when that carries the token the
/// step-up minted; every other path is a 404. It keeps every request it saw.
struct StepUpServer {
    server_setup: Vec<u8>,
    password_file: Vec<u8>,
    login_state: Mutex<Option<Vec<u8>>>,
    delete_refusal: Option<(u16, &'static str)>,
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
            delete_refusal: None,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Refuse a delete request that carries a valid token, as the server does
    /// for an account that may not be deleted yet.
    fn refusing_the_delete_request(mut self, status: u16, code: &'static str) -> Self {
        self.delete_refusal = Some((status, code));
        self
    }

    fn requests(&self) -> Vec<beebeeb_api::Request> {
        self.requests.lock().unwrap().clone()
    }

    fn json(status: u16, body: serde_json::Value) -> beebeeb_api::Answer {
        beebeeb_api::Answer::new(status, Vec::new(), serde_json::to_vec(&body).unwrap())
    }
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
                    match self.delete_refusal {
                        Some((status, code)) => Self::json(status, serde_json::json!({ "error": code })),
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

#[tokio::test]
async fn a_refused_delete_request_reports_the_servers_refusal() {
    let server =
        Arc::new(StepUpServer::with_account_password(PASSWORD).refusing_the_delete_request(409, "subscription_active"));
    let client = signed_in_client(&server);

    let refused = client
        .request_account_deletion(Zeroizing::new(PASSWORD.to_owned()), None)
        .await;

    match refused {
        Err(AuthError::Client(ClientError::Api(beebeeb_api::ApiError::Server(error)))) => {
            assert_eq!(error.status, 409);
            assert!(error.is_code("subscription_active"), "{error:?}");
        }
        other => panic!("expected the server's refusal, got {other:?}"),
    }
}
