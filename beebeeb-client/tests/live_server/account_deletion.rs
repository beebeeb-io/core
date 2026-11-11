//! Account deletion against the server: a request mails one confirmation link and schedules
//! nothing, a wrong password never gets past the step-up, and an account with an authenticator
//! needs its code.

use super::*;
use beebeeb_client::{ReqwestTransport, Transport, TransportFuture, auth::AuthError};
use std::time::Instant;

const DELETION_LINK_SUBJECT: &str = "Confirm that you want to delete your Beebeeb account";
const STEP_UP_START: &str = "/api/v1/auth/confirm-opaque-start";
const STEP_UP_FINISH: &str = "/api/v1/auth/confirm-opaque-finish";
const DELETE_REQUEST: &str = "/api/v1/auth/account/delete-request";
/// How long a scenario waits for the deletion mail, and how long it watches for one that must not
/// come. The server sends the mail before it answers, so a mail the request caused is already there.
const DELETION_MAIL_WAIT: Duration = Duration::from_secs(10);

/// What the recording transport keeps of an answer. Never a value: the step-up's answer carries
/// the confirmation token.
#[derive(Clone)]
struct AnswerShape {
    path: String,
    status: u16,
    keys: Vec<String>,
}

/// The reqwest transport, keeping the shape of every answer it hands back.
struct RecordingTransport {
    inner: ReqwestTransport,
    answers: Mutex<Vec<AnswerShape>>,
}

impl RecordingTransport {
    fn answers(&self) -> Vec<AnswerShape> {
        self.answers.lock().unwrap().clone()
    }

    fn paths(&self) -> Vec<String> {
        self.answers().into_iter().map(|answer| answer.path).collect()
    }
}

impl Transport for RecordingTransport {
    fn send<'a>(&'a self, request: beebeeb_api::Request, max_response_bytes: usize) -> TransportFuture<'a> {
        Box::pin(async move {
            let path = request.path().to_owned();
            let answer = self.inner.send(request, max_response_bytes).await?;
            let mut keys: Vec<String> = serde_json::from_slice::<Value>(&answer.body)
                .ok()
                .and_then(|body| body.as_object().map(|object| object.keys().cloned().collect()))
                .unwrap_or_default();
            keys.sort();
            self.answers.lock().unwrap().push(AnswerShape {
                path,
                status: answer.status,
                keys,
            });
            Ok(answer)
        })
    }
}

/// The account's own session, under the declaration it was provisioned with, on a client whose
/// transport records every answer: only the transport differs from `account.client`.
fn recording_client(account: &LiveAccount) -> TestResult<(Client, Arc<RecordingTransport>)> {
    let transport = Arc::new(RecordingTransport {
        inner: ReqwestTransport::new(&account.api_url)?,
        answers: Mutex::default(),
    });
    let client = Client::new(
        ClientConfig::new("web", env!("CARGO_PKG_VERSION"), &account.app_id),
        transport.clone(),
    )?;
    client.set_session(&account.session)?;
    Ok((client, transport))
}

async fn deletion_mail_checkpoint(account: &LiveAccount) -> TestResult<MailCheckpoint> {
    let (_, mailpit_url) = live_urls()?;
    mail_checkpoint(&mailpit_url, &account.email, DELETION_LINK_SUBJECT).await
}

/// How many deletion mails reached the account after `checkpoint`: as soon as there is one, else 0
/// once `DELETION_MAIL_WAIT` has passed. Only the listing is read; the link is never fetched.
async fn deletion_mails_since(account: &LiveAccount, checkpoint: &MailCheckpoint) -> TestResult<usize> {
    let (_, mailpit_url) = live_urls()?;
    let deadline = Instant::now() + DELETION_MAIL_WAIT;
    loop {
        let listing = mail_listing(&mailpit_url).await?;
        let count = new_mail_messages(&listing, &account.email, DELETION_LINK_SUBJECT, checkpoint).len();
        if count > 0 || Instant::now() >= deadline {
            return Ok(count);
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// Where the server says the account's delete stands: `none`, `requested` or `scheduled`.
async fn deletion_state(account: &LiveAccount) -> TestResult<String> {
    let response = reqwest::Client::new()
        .get(format!("{}/api/v1/auth/account/deletion", account.api_url))
        .bearer_auth(stored_session_token(account)?)
        .send()
        .await?
        .error_for_status()?;
    let body: Value = serde_json::from_slice(&response.bytes().await?)?;
    Ok(body["state"]
        .as_str()
        .ok_or("the deletion state answer has no state")?
        .to_owned())
}

/// The account still works: its own client still lists the device it signed up on.
async fn assert_account_works(account: &LiveAccount) -> TestResult {
    let devices = account.client.list_devices().await?.devices;
    assert!(
        !devices.is_empty(),
        "the account lost its device after a deletion request"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn a_request_mails_one_link_and_schedules_nothing() -> TestResult {
    let account = provision_account().await?;
    let (client, transport) = recording_client(&account)?;
    let checkpoint = deletion_mail_checkpoint(&account).await?;
    client
        .request_account_deletion(Zeroizing::new(account.password.clone()), None)
        .await
        .map_err(|error| format!("the deletion request failed: {error}"))?;
    let answers = transport.answers();
    let paths: Vec<&str> = answers.iter().map(|answer| answer.path.as_str()).collect();
    assert_eq!(paths, [STEP_UP_START, STEP_UP_FINISH, DELETE_REQUEST]);
    assert_eq!(answers[2].status, 200, "the delete request was not accepted");
    assert_eq!(answers[2].keys, ["email_link_sent", "link_expires_at", "scheduled"]);
    assert_eq!(
        deletion_mails_since(&account, &checkpoint).await?,
        1,
        "the request did not mail exactly one confirmation link"
    );
    assert_eq!(
        deletion_state(&account).await?,
        "requested",
        "the request did not leave only a pending link"
    );
    assert_account_works(&account).await
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn a_wrong_password_sends_no_delete_request_and_no_mail() -> TestResult {
    let account = provision_account().await?;
    let (client, transport) = recording_client(&account)?;
    let checkpoint = deletion_mail_checkpoint(&account).await?;
    let refused = client
        .request_account_deletion(Zeroizing::new(format!("{}-wrong", account.password)), None)
        .await;
    assert!(
        matches!(refused, Err(AuthError::Crypto)),
        "the step-up did not refuse a wrong password: {refused:?}"
    );
    assert_eq!(
        transport.paths(),
        [STEP_UP_START],
        "a wrong password went past the step-up's first message"
    );
    assert_eq!(
        deletion_mails_since(&account, &checkpoint).await?,
        0,
        "a refused deletion request mailed a link"
    );
    assert_eq!(
        deletion_state(&account).await?,
        "none",
        "a refused deletion request left a pending link"
    );
    assert_account_works(&account).await
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn a_two_factor_account_needs_its_authenticator_code() -> TestResult {
    let account = provision_account().await?;
    let enrollment = account.client.setup_authenticator().await?;
    account
        .client
        .enable_authenticator(totp_now(enrollment.secret())?)
        .await?;
    let (client, transport) = recording_client(&account)?;
    let checkpoint = deletion_mail_checkpoint(&account).await?;
    let without_code = client
        .request_account_deletion(Zeroizing::new(account.password.clone()), None)
        .await;
    assert!(
        without_code.is_err(),
        "a two-factor account had a link sent without its code"
    );
    client
        .request_account_deletion(
            Zeroizing::new(account.password.clone()),
            Some(totp_now(enrollment.secret())?),
        )
        .await
        .map_err(|error| format!("the authenticator code did not complete the deletion request: {error}"))?;
    let delete_statuses: Vec<u16> = transport
        .answers()
        .iter()
        .filter(|answer| answer.path == DELETE_REQUEST)
        .map(|answer| answer.status)
        .collect();
    assert_eq!(
        delete_statuses,
        [403, 200],
        "the server did not refuse the request without the code, then accept it with the code"
    );
    assert_eq!(
        deletion_mails_since(&account, &checkpoint).await?,
        1,
        "the two requests did not mail exactly one confirmation link"
    );
    assert_eq!(deletion_state(&account).await?, "requested");
    Ok(())
}
