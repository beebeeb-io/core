//! Opt-in contract tests for a real Beebeeb server and Mailpit.
//!
//! Every scenario is ignored because normal test runs are hermetic. Set
//! `BB_LIVE_API_URL` and `BB_LIVE_MAILPIT_URL`, then run this test target with
//! `--ignored --test-threads=1`. The server must enable sign-up, recovery,
//! device links, public-share chunks, services, SSE, and short-lived sessions.
//! It must also run with `BB_REFUSE_V1_WRITES=1` and `BB_VERSION_METADATA=1`.

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use beebeeb_client::{
    Client, ClientConfig, MemorySecretStore, SecretStore, Session,
    auth::{NewDeviceUnlock, PasswordAccepted, RecoveryChanges, RecoveryKitOutput, SignInChallenge, SignupService},
    devices::DeviceLinkPoll,
    downloads::{DownloadFile, DownloadResult, DownloadService},
    uploads::{NetworkKind, TransferFinished, UploadRequest, UploadService},
};
use beebeeb_core::{
    encrypt::decrypt_file_metadata,
    kdf::MasterKey,
    kdf::derive_file_key,
    onboarding::{BreachPolicy, CeremonyConfig, PasswordPolicy},
    sync::SyncEngine,
    system_folders::Service,
};
use beebeeb_store::{Store, TransferState};
use beebeeb_types::{ChunkProfile, limits::MemoryBudget};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use tokio::time::sleep;
use uuid::Uuid;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const SIGNUP_CODE_SUBJECT: &str = "Verify your email for Beebeeb";
const LOGIN_CODE_SUBJECT: &str = "Your Beebeeb sign-in code";
const RECOVERY_REPLACEMENT_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

struct LiveAccount {
    api_url: String,
    email: String,
    password: String,
    recovery_words: Vec<String>,
    client: Arc<Client>,
    store: MemorySecretStore,
    session: Session,
    master_key: MasterKey,
    email_code_length: usize,
    app_id: String,
}

fn live_urls() -> TestResult<(String, String)> {
    let api = env::var("BB_LIVE_API_URL")?;
    let mailpit = env::var("BB_LIVE_MAILPIT_URL")?;
    Ok((
        api.trim_end_matches('/').to_owned(),
        mailpit.trim_end_matches('/').to_owned(),
    ))
}

fn live_client_named(api_url: &str, client_name: &str) -> TestResult<(Client, String)> {
    let app_id = format!("live-contract-{}", Uuid::new_v4());
    let client = Client::with_reqwest(
        ClientConfig::new(client_name, env!("CARGO_PKG_VERSION"), &app_id),
        api_url,
    )?;
    Ok((client, app_id))
}

fn live_client(api_url: &str) -> TestResult<(Client, String)> {
    live_client_named(api_url, "desktop")
}

async fn provision_account() -> TestResult<LiveAccount> {
    let (api_url, mailpit_url) = live_urls()?;
    // Account creation is intentionally web-only on the server. These tests
    // use the exact web client declaration only for provisioning; every
    // subsequent new-device flow uses the native desktop declaration.
    let (client, app_id) = live_client_named(&api_url, "web")?;
    let client = Arc::new(client);
    let email = format!("contract-{}@example.test", Uuid::new_v4());
    let password = format!("Contract-live-{}-A9!", Uuid::new_v4());
    let onboarding = client
        .fetch_onboarding()
        .await
        .map_err(|error| format!("account provisioning could not fetch onboarding: {error}"))?;
    let policy = onboarding
        .policy
        .as_ref()
        .ok_or("pre-account onboarding omitted policy")?;
    let email_code_length = usize::try_from(policy.email_code.length)
        .map_err(|_| "onboarding email-code length does not fit this platform")?;
    let email_required = onboarding.steps.iter().any(|step| step.id == "verify_email_code");
    let mut signup = SignupService::new(
        &email,
        CeremonyConfig {
            password_policy: PasswordPolicy::from_server(policy.password.min_length),
            email_verification_required: email_required,
            verify_word_count: policy.recovery_phrase.verify_word_count,
            breach: BreachPolicy::NotRequired,
        },
    )?;

    if email_required {
        let checkpoint = mail_checkpoint(&mailpit_url, &email, SIGNUP_CODE_SUBJECT).await?;
        client
            .start_signup_email(&signup)
            .await
            .map_err(|error| format!("account provisioning could not request the signup email: {error}"))?;
        let code = wait_for_mail_code(
            &mailpit_url,
            &email,
            SIGNUP_CODE_SUBJECT,
            email_code_length,
            &checkpoint,
        )
        .await?;
        client
            .verify_signup_email(&mut signup, code)
            .await
            .map_err(|error| format!("account provisioning could not verify the signup email: {error}"))?;
    }
    signup.set_password(&password, &password, None)?;
    let kit = signup.begin_recovery_kit()?;
    let recovery_words: Vec<String> = kit.words().map(str::to_owned).collect();
    if recovery_words.len() != policy.recovery_phrase.word_count as usize {
        return Err(format!(
            "recovery kit returned {} words; onboarding requires {}",
            recovery_words.len(),
            policy.recovery_phrase.word_count
        )
        .into());
    }
    signup.mark_recovery_output_saved(RecoveryKitOutput::Pdf);
    signup.mark_recovery_output_saved(RecoveryKitOutput::Text);
    signup.acknowledge_recovery_kit()?;
    let answers: Vec<String> = signup
        .challenge_positions()?
        .into_iter()
        .map(|position| recovery_words[position as usize - 1].clone())
        .collect();
    signup.confirm_phrase(&answers)?;

    let store = MemorySecretStore::default();
    let created = client
        .create_account(&mut signup, policy.terms.version.clone(), &store)
        .await
        .map_err(|error| format!("account provisioning could not finish registration: {error}"))?;
    let key_bytes = created.master_key.to_bytes();
    let installed = client
        .install_new_device(created.into_ready(), &api_url, &store)
        .await
        .map_err(|error| format!("account provisioning could not prove and install the signup session: {error}"))?;
    let session =
        Session::load_for_user(&store, installed.owner(), &app_id)?.ok_or("new account session was not stored")?;

    Ok(LiveAccount {
        api_url,
        email,
        password,
        recovery_words,
        client,
        store,
        session,
        master_key: MasterKey::from_bytes(*key_bytes),
        email_code_length,
        app_id,
    })
}

/// The stored raw token, so a scenario can ask the server directly whether it
/// still works after the client has forgotten it.
fn stored_session_token(account: &LiveAccount) -> TestResult<String> {
    let name = format!("session.token.{}", account.app_id);
    let token = account.store.get(&name)?.ok_or("session token was not stored")?;
    Ok(String::from_utf8(token.to_vec())?)
}

async fn account_status_for_token(account: &LiveAccount, token: &str) -> TestResult<u16> {
    let response = reqwest::Client::new()
        .get(format!("{}/api/v1/auth/me", account.api_url))
        .bearer_auth(token)
        .send()
        .await?;
    Ok(response.status().as_u16())
}

async fn password_challenge_on_new_device(
    account: &LiveAccount,
    client: &Client,
    store: &MemorySecretStore,
) -> TestResult<SignInChallenge> {
    client
        .sign_in_on_device(&account.email, Zeroizing::new(account.password.clone()), None, store)
        .await
        .map_err(|error| format!("new-device password sign-in failed: {error}").into())
}

async fn password_on_new_device(
    account: &LiveAccount,
    client: &Client,
    store: &MemorySecretStore,
) -> TestResult<PasswordAccepted> {
    let challenge = password_challenge_on_new_device(account, client, store).await?;
    match challenge {
        SignInChallenge::PasswordAccepted(accepted) => Ok(accepted),
        SignInChallenge::TwoFactor(_) => Err("new-device sign-in unexpectedly required 2FA".into()),
        SignInChallenge::RecoveryPasswordProven(_) => Err("new-device sign-in returned a recovery proof".into()),
    }
}

async fn authorize_unlock_email(account: &LiveAccount, client: &Client, unlock: &mut NewDeviceUnlock) -> TestResult {
    let (_, mailpit_url) = live_urls()?;
    let checkpoint = mail_checkpoint(&mailpit_url, &account.email, LOGIN_CODE_SUBJECT).await?;
    let challenge = client
        .request_email_code(account.email.clone())
        .await
        .map_err(|error| format!("new-device email-code request failed: {error}"))?;
    let code = wait_for_mail_code(
        &mailpit_url,
        &account.email,
        LOGIN_CODE_SUBJECT,
        account.email_code_length,
        &checkpoint,
    )
    .await?;
    client
        .submit_unlock_email_code(unlock, challenge.challenge, code)
        .await
        .map(|_| ())
        .map_err(|error| format!("new-device email-code verification failed: {error}").into())
}

fn decode_base32(input: &str) -> TestResult<Vec<u8>> {
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut output = Vec::new();
    for byte in input
        .bytes()
        .filter(|byte| *byte != b'=' && !byte.is_ascii_whitespace())
    {
        let value = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err("authenticator secret was not RFC 4648 base32".into()),
        };
        bits = (bits << 5) | u32::from(value);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1u32 << bit_count).saturating_sub(1);
        }
    }
    Ok(output)
}

fn totp_now(secret: &str) -> TestResult<String> {
    let key = decode_base32(secret)?;
    let counter = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).map_err(|_| "invalid authenticator key")?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

#[test]
fn recovery_replacement_secret_meets_the_server_totp_minimum() -> TestResult {
    assert!(
        decode_base32(RECOVERY_REPLACEMENT_SECRET)?.len() >= 16,
        "recovery replacement TOTP secret is below the server's 128-bit minimum"
    );
    Ok(())
}

#[derive(Default)]
struct MailCheckpoint {
    latest_created: Option<String>,
    ids: BTreeSet<String>,
}

async fn mail_listing(mailpit_url: &str) -> TestResult<Value> {
    let http = reqwest::Client::new();
    let response = http
        .get(format!("{mailpit_url}/api/v1/messages?limit=100"))
        .send()
        .await?
        .error_for_status()?;
    Ok(serde_json::from_slice(&response.bytes().await?)?)
}

async fn mail_checkpoint(mailpit_url: &str, recipient: &str, subject: &str) -> TestResult<MailCheckpoint> {
    let listing = mail_listing(mailpit_url).await?;
    let mut checkpoint = MailCheckpoint::default();
    for message in matching_mail_messages(&listing, recipient, subject) {
        checkpoint.ids.insert(message.id);
        if checkpoint
            .latest_created
            .as_ref()
            .is_none_or(|latest| message.created > *latest)
        {
            checkpoint.latest_created = Some(message.created);
        }
    }
    Ok(checkpoint)
}

async fn wait_for_mail_code(
    mailpit_url: &str,
    recipient: &str,
    subject: &str,
    expected_length: usize,
    checkpoint: &MailCheckpoint,
) -> TestResult<String> {
    let http = reqwest::Client::new();
    for _ in 0..60 {
        let listing = mail_listing(mailpit_url).await?;
        for id in new_mail_messages(&listing, recipient, subject, checkpoint) {
            let response = http
                .get(format!("{mailpit_url}/api/v1/message/{id}"))
                .send()
                .await?
                .error_for_status()?;
            let message: Value = serde_json::from_slice(&response.bytes().await?)?;
            let mut body = String::new();
            collect_mail_body(&message, &mut body);
            if let Some(code) = first_numeric_code(&body, expected_length) {
                return Ok(code);
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
    Err(format!("Mailpit did not receive a new '{subject}' code for {recipient}").into())
}

struct MailMessage {
    id: String,
    created: String,
}

fn matching_mail_messages(listing: &Value, recipient: &str, subject: &str) -> Vec<MailMessage> {
    let Some(messages) = listing.get("messages").and_then(Value::as_array) else {
        return Vec::new();
    };
    messages
        .iter()
        .filter(|message| message.to_string().contains(recipient))
        .filter(|message| value_string(message, &["Subject", "subject"]) == Some(subject))
        .filter_map(|message| {
            Some(MailMessage {
                id: value_string(message, &["ID", "Id", "id"])?.to_owned(),
                created: value_string(message, &["Created", "created"])?.to_owned(),
            })
        })
        .collect()
}

fn value_string<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn new_mail_messages(listing: &Value, recipient: &str, subject: &str, checkpoint: &MailCheckpoint) -> Vec<String> {
    let mut messages = matching_mail_messages(listing, recipient, subject)
        .into_iter()
        .filter(|message| {
            !checkpoint.ids.contains(&message.id)
                && checkpoint
                    .latest_created
                    .as_ref()
                    .is_none_or(|created| message.created >= *created)
        })
        .collect::<Vec<_>>();
    messages.sort_by(|left, right| right.created.cmp(&left.created));
    messages.into_iter().map(|message| message.id).collect()
}

fn collect_mail_body(value: &Value, body: &mut String) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.to_ascii_lowercase().as_str(), "text" | "html" | "subject") {
                    if let Some(value) = value.as_str() {
                        body.push_str(value);
                        body.push('\n');
                    }
                } else {
                    collect_mail_body(value, body);
                }
            }
        }
        Value::Array(values) => values.iter().for_each(|value| collect_mail_body(value, body)),
        _ => {}
    }
}

fn first_numeric_code(text: &str, expected_length: usize) -> Option<String> {
    text.split(|character: char| !character.is_ascii_digit())
        .find(|run| run.len() == expected_length)
        .map(str::to_owned)
}

#[test]
fn mail_selection_requires_the_expected_subject_and_a_new_created_message() {
    let listing: Value = serde_json::from_str(
        r#"{"messages":[
          {"ID":"signup-old","Created":"2026-11-04T09:00:00Z","Subject":"Verify your email for Beebeeb","To":[{"Address":"person@example.test"}]},
          {"ID":"login-new","Created":"2026-11-04T09:01:00Z","Subject":"Your Beebeeb sign-in code","To":[{"Address":"person@example.test"}]}
        ]}"#,
    )
    .unwrap();
    let checkpoint = MailCheckpoint {
        latest_created: Some("2026-11-04T09:00:00Z".into()),
        ids: ["signup-old".to_owned()].into_iter().collect(),
    };

    let messages = new_mail_messages(
        &listing,
        "person@example.test",
        "Your Beebeeb sign-in code",
        &checkpoint,
    );

    assert_eq!(messages, vec!["login-new"]);
}

async fn perform_transfer(
    service: &UploadService,
    api_url: &str,
    upload_id: i64,
    request: beebeeb_client::uploads::TransferRequest,
    now_ms: i64,
) -> TestResult {
    let url = if request.url.starts_with("http://") || request.url.starts_with("https://") {
        request.url.clone()
    } else {
        format!("{api_url}{}", request.url)
    };
    let body = tokio::fs::read(&request.body_path)
        .await
        .map_err(|error| format!("upload could not read staged ciphertext: {error}"))?;
    let mut outgoing = reqwest::Client::new().put(url).body(body);
    for (name, value) in &request.headers {
        outgoing = outgoing.header(name, value);
    }
    let response = outgoing
        .send()
        .await
        .map_err(|error| format!("upload chunk request failed: {error}"))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let response_body = response.bytes().await?;
    let finished = service
        .transfer_finished(
            upload_id,
            &request.ticket,
            status,
            content_type.as_deref(),
            retry_after.as_deref(),
            &response_body,
            now_ms,
        )
        .await
        .map_err(|error| format!("upload rejected a chunk result: {error}"))?;
    if let TransferFinished::Failed { reason, .. } = finished {
        return Err(format!("upload chunk reached terminal failure at HTTP status {status}: {reason:?}").into());
    }
    Ok(())
}

async fn drive_upload(
    account: &LiveAccount,
    root: &tempfile::TempDir,
    plaintext: &[u8],
    disk_limit: u64,
    recreate_after_first_batch: bool,
) -> TestResult<String> {
    let source = root.path().join("source.bin");
    tokio::fs::write(&source, plaintext).await?;
    let mut request = UploadRequest::new(
        &source,
        "live-upload.bin",
        Some("application/octet-stream".into()),
        None,
    );
    request.disk_limit = disk_limit;
    drive_upload_request(account, root, request, recreate_after_first_batch).await
}

async fn drive_replacement_upload(
    account: &LiveAccount,
    root: &tempfile::TempDir,
    file_id: &str,
    plaintext: &[u8],
) -> TestResult<String> {
    let source = root.path().join("replacement.bin");
    tokio::fs::write(&source, plaintext).await?;
    let entry = account.client.get_file(file_id).await?;
    let versions = account.client.file_versions(file_id).await?;
    let current = versions
        .versions
        .iter()
        .find(|version| version.version_number == versions.current_version)
        .ok_or("version listing omitted the replacement base")?;
    let current_metadata = current
        .version_metadata_encrypted
        .clone()
        .or(entry.name_encrypted)
        .ok_or("replacement base omitted encrypted metadata")?;
    let request = UploadRequest::replacement(
        &source,
        "live-upload.bin",
        Some("application/octet-stream".into()),
        file_id,
        versions.current_version,
        current_metadata,
    );
    drive_upload_request(account, root, request, false).await
}

async fn drive_upload_request(
    account: &LiveAccount,
    root: &tempfile::TempDir,
    request: UploadRequest,
    recreate_after_first_batch: bool,
) -> TestResult<String> {
    let store = Arc::new(Mutex::new(Store::open_in_memory()?));
    let staging = root.path().join("staging");
    let mut service = UploadService::new(account.client.clone(), store.clone(), &staging)?;
    let upload_id = service.enqueue(request, 1)?;
    let file_id = service
        .list()?
        .into_iter()
        .find(|entry| entry.id == upload_id)
        .ok_or("queued upload disappeared before transfer")?
        .file_id;
    let mut recreated = false;
    for tick in 2..200i64 {
        if service
            .list()?
            .into_iter()
            .find(|entry| entry.id == upload_id)
            .is_some_and(|entry| entry.state == TransferState::Succeeded)
        {
            return Ok(file_id);
        }
        let Some((claimed_id, requests)) = service.next_transfers(4, NetworkKind::WiFi, tick).await? else {
            continue;
        };
        if claimed_id != upload_id {
            return Err("upload service claimed the wrong durable transfer".into());
        }
        for request in requests {
            perform_transfer(&service, &account.api_url, upload_id, request, tick).await?;
        }
        if recreate_after_first_batch && !recreated {
            drop(service);
            service = UploadService::new(account.client.clone(), store.clone(), &staging)?;
            recreated = true;
        }
    }
    Err("upload did not reach succeeded state within 198 transfer passes".into())
}

async fn download_uploaded_file(account: &LiveAccount, root: &tempfile::TempDir, file_id: &str) -> TestResult<Vec<u8>> {
    let entry = account.client.get_file(file_id).await?;
    let versions = account.client.file_versions(file_id).await?;
    let version = versions
        .versions
        .iter()
        .find(|version| version.version_number == versions.current_version)
        .ok_or("version listing omitted its current version")?;
    let plan = beebeeb_types::plan_chunks(entry.size_bytes, ChunkProfile::Mobile);
    let description = DownloadFile {
        file_id: file_id.to_owned(),
        name_encrypted: version
            .version_metadata_encrypted
            .clone()
            .or(entry.name_encrypted)
            .ok_or("uploaded file response omitted encrypted metadata")?,
        size_bytes: entry.size_bytes,
        chunk_size_bytes: plan.chunk_size_bytes,
        chunk_count: version.chunk_count,
        object_version_id: version.id.clone(),
    };
    let downloads = DownloadService::new(
        account.client.clone(),
        Arc::new(Mutex::new(Store::open_in_memory()?)),
        root.path().join("cache"),
        64 * 1024 * 1024,
        MemoryBudget::NATIVE,
    )?;
    let path = match downloads.open(&description, 1).await? {
        DownloadResult::Ready(path) => path,
        DownloadResult::HandOff { .. } => return Err("small live download unexpectedly required handoff".into()),
        DownloadResult::Saved => return Err("cache download returned the save-to result variant".into()),
    };
    Ok(tokio::fs::read(path).await?)
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn signup_with_recovery_key() -> TestResult {
    let account = provision_account().await?;
    assert!(account.recovery_words.len() >= 12);
    assert!(!account.session.owner().is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn password_signin_returns_a_typed_state() -> TestResult {
    let account = provision_account().await?;
    let (other, _) = live_client(&account.api_url)?;
    let error = other
        .sign_in(&account.email, Zeroizing::new(account.password.clone()), None)
        .await
        .expect_err("sign-in without a hardware identity unexpectedly created a session");
    assert!(matches!(
        error,
        beebeeb_client::auth::AuthError::HardwareIdentityRequired
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn two_factor_completion_installs_after_email_gated_key_proof() -> TestResult {
    let account = provision_account().await?;
    let enrollment = account
        .client
        .setup_authenticator()
        .await
        .map_err(|error| format!("2FA setup failed: {error}"))?;
    account
        .client
        .enable_authenticator(totp_now(enrollment.secret())?)
        .await
        .map_err(|error| format!("2FA enable failed: {error}"))?;

    let (other, app_id) = live_client(&account.api_url)?;
    let store = MemorySecretStore::default();
    let challenge = password_challenge_on_new_device(&account, &other, &store).await?;
    let SignInChallenge::TwoFactor(challenge) = challenge else {
        return Err("2FA-enabled account did not return a two-factor challenge".into());
    };
    let accepted = other
        .submit_two_factor(challenge, totp_now(enrollment.secret())?)
        .await
        .map_err(|error| format!("correct TOTP did not complete sign-in: {error}"))?;
    let mut unlock = NewDeviceUnlock::recovery(accepted)
        .map_err(|error| format!("2FA completion did not return a locked session: {error}"))?;
    authorize_unlock_email(&account, &other, &mut unlock).await?;
    unlock.provide_recovery_key(MasterKey::from_bytes(*account.master_key.to_bytes()))?;
    let installed = other
        .install_new_device(unlock.into_ready()?, &account.api_url, &store)
        .await
        .map_err(|error| format!("2FA session failed email-ticket key proof: {error}"))?;
    assert!(
        Session::load_for_user(&store, installed.owner(), &app_id)?.is_some(),
        "2FA and key proof did not persist the new-device session"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn new_device_installs_after_locked_session_email_gated_key_proof() -> TestResult {
    let account = provision_account().await?;
    let (other, app_id) = live_client(&account.api_url)?;
    let store = MemorySecretStore::default();
    let accepted = password_on_new_device(&account, &other, &store).await?;
    let mut unlock = NewDeviceUnlock::recovery(accepted)?;
    authorize_unlock_email(&account, &other, &mut unlock).await?;
    unlock.provide_recovery_key(MasterKey::from_bytes(*account.master_key.to_bytes()))?;
    let installed = other
        .install_new_device(unlock.into_ready()?, &account.api_url, &store)
        .await
        .map_err(|error| format!("email-authorized new device failed key proof: {error}"))?;
    assert!(
        Session::load_for_user(&store, installed.owner(), &app_id)?.is_some(),
        "email-authorized device did not persist its session"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn device_link_start_requires_an_authenticated_starter() -> TestResult {
    let account = provision_account().await?;
    let (new_device, _) = live_client(&account.api_url)?;
    assert!(new_device.start_device_link("live second device".into()).await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn locked_key_proof_refuses_the_wrong_recovery_key() -> TestResult {
    let account = provision_account().await?;
    account
        .client
        .prove_session_key(&account.master_key)
        .await
        .map_err(|error| format!("known account key failed its server binding proof: {error}"))?;

    let (other, _) = live_client(&account.api_url)?;
    let store = MemorySecretStore::default();
    let accepted = password_on_new_device(&account, &other, &store).await?;
    let mut unlock = NewDeviceUnlock::recovery(accepted)?;
    authorize_unlock_email(&account, &other, &mut unlock).await?;
    unlock.provide_recovery_key(MasterKey::from_bytes([0x7d; 32]))?;
    let result = other
        .install_new_device(unlock.into_ready()?, &account.api_url, &store)
        .await;
    assert!(
        result.is_err(),
        "server accepted a key proof made with the wrong account key"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn qr_device_approval_transfers_the_account_key_between_two_clients() -> TestResult {
    let account = provision_account().await?;
    let (new_device, _) = live_client(&account.api_url)?;
    let store = MemorySecretStore::default();
    let accepted = password_on_new_device(&account, &new_device, &store).await?;
    let mut pending = new_device
        .start_device_link_for_sign_in(&accepted, "live QR device".into())
        .await
        .map_err(|error| format!("locked new device could not start QR link: {error}"))?;
    let id = pending.id().to_owned();
    // The approver gets the QR only from scanned text.
    let qr = beebeeb_client::devices::DeviceLinkQr::parse(&pending.qr_payload()?)?;
    let code = pending.typed_code()?.to_owned();
    account
        .client
        .approve_device_link(&id, &qr, &code)
        .await
        .map_err(|error| format!("existing client could not approve QR link: {error}"))?;
    let DeviceLinkPoll::Approved(approved) = new_device.poll_device_link(&mut pending).await? else {
        return Err("QR link did not become approved after approval response".into());
    };
    let beebeeb_client::devices::ApprovedDeviceLink {
        material,
        acknowledgement,
    } = approved;
    let mut unlock = NewDeviceUnlock::approval(accepted)?;
    unlock.provide_approval(material)?;
    new_device
        .acknowledge_device_link(acknowledgement)
        .await
        .map_err(|error| format!("QR-approved device could not acknowledge the link before key proof: {error}"))?;
    new_device
        .install_new_device(unlock.into_ready()?, &account.api_url, &store)
        .await
        .map_err(|error| format!("QR-approved account key failed installation: {error}"))?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn typed_device_approval_uses_the_client_session_id_between_two_clients() -> TestResult {
    let account = provision_account().await?;
    let (new_device, _) = live_client(&account.api_url)?;
    let store = MemorySecretStore::default();
    let accepted = password_on_new_device(&account, &new_device, &store).await?;
    let pending = new_device
        .start_device_link_for_sign_in(&accepted, "live typed device".into())
        .await?;
    let id = pending.id().to_owned();
    let typed_code = pending.typed_code()?.to_owned();
    // Relay order: the approver speaks first, the new device answers with its
    // confirmation, and the approver checks it before sealing.
    let (approver, approver_message) = account
        .client
        .begin_typed_device_approval(&id, &typed_code)
        .await
        .map_err(|error| format!("approver could not start typed PAKE from server session_id: {error}"))?;
    if approver.device_name() != "live typed device" {
        return Err("the relay did not return the canonical device name".into());
    }
    account
        .client
        .send_device_link_pake(&id, beebeeb_api::proposed::DeviceLinkRole::Approver, &approver_message)
        .await?;
    let relayed_approver = new_device
        .get_device_link_pake(&id, beebeeb_api::proposed::DeviceLinkRole::NewDevice)
        .await?
        .ok_or("server did not relay the approver PAKE message")?;
    let (mut receiver, new_message) = pending.answer_typed_path(&relayed_approver)?;
    new_device
        .send_device_link_pake(&id, beebeeb_api::proposed::DeviceLinkRole::NewDevice, &new_message)
        .await?;
    let relayed_new = account
        .client
        .get_device_link_pake(&id, beebeeb_api::proposed::DeviceLinkRole::Approver)
        .await?
        .ok_or("server did not relay the new-device PAKE message")?;
    account.client.approve_typed_device_link(approver, &relayed_new).await?;
    let DeviceLinkPoll::Approved(approved) = new_device.poll_typed_device_link(&mut receiver).await? else {
        return Err("typed link did not become approved after PAKE completion".into());
    };
    let beebeeb_client::devices::ApprovedDeviceLink {
        material,
        acknowledgement,
    } = approved;
    let mut unlock = NewDeviceUnlock::approval(accepted)?;
    unlock.provide_approval(material)?;
    new_device
        .acknowledge_device_link(acknowledgement)
        .await
        .map_err(|error| format!("typed-approved device could not acknowledge the link before key proof: {error}"))?;
    new_device
        .install_new_device(unlock.into_ready()?, &account.api_url, &store)
        .await
        .map_err(|error| format!("typed-approved account key failed installation: {error}"))?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn recovery_without_password_enters_the_waiting_state() -> TestResult {
    let account = provision_account().await?;
    let attempt = account
        .client
        .start_recovery(&account.email, &account.master_key, None)
        .await?;
    assert!(attempt.waits());
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn recovery_key_plus_password_has_no_wait_and_registers_a_new_password() -> TestResult {
    let account = provision_account().await?;
    let replacement = format!("Replacement-{}-Z7!", Uuid::new_v4());
    let attempt = account
        .client
        .start_recovery_with_password(
            &account.email,
            Zeroizing::new(account.password.clone()),
            &account.master_key,
            None,
        )
        .await
        .map_err(|error| format!("password proof could not start recovery: {error}"))?;
    assert!(!attempt.waits(), "valid password proof still received the 72-hour wait");
    let recovered = account
        .client
        .complete_recovery(
            &attempt,
            &account.email,
            RecoveryChanges {
                new_password: Some(Zeroizing::new(replacement)),
                ..RecoveryChanges::default()
            },
        )
        .await
        .map_err(|error| format!("password-only recovery completion failed: {error}"))?;
    account
        .client
        .install_recovered_session(
            &recovered,
            MasterKey::from_bytes(*account.master_key.to_bytes()),
            &account.api_url,
            &MemorySecretStore::default(),
        )
        .map_err(|error| format!("completed recovery session was not installable: {error}"))?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn recovery_replaces_a_lost_authenticator() -> TestResult {
    let account = provision_account().await?;
    let original = account.client.setup_authenticator().await?;
    account
        .client
        .enable_authenticator(totp_now(original.secret())?)
        .await?;
    let replacement_secret = RECOVERY_REPLACEMENT_SECRET;
    let attempt = account
        .client
        .start_recovery_with_password(
            &account.email,
            Zeroizing::new(account.password.clone()),
            &account.master_key,
            None,
        )
        .await?;
    account
        .client
        .complete_recovery(
            &attempt,
            &account.email,
            RecoveryChanges {
                new_authenticator: Some(Zeroizing::new(replacement_secret.into())),
                authenticator_code: Some(totp_now(replacement_secret)?),
                ..RecoveryChanges::default()
            },
        )
        .await
        .map_err(|error| format!("recovery could not replace the lost authenticator: {error}"))?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn recovery_replaces_a_lost_email_address() -> TestResult {
    let account = provision_account().await?;
    let (_, mailpit_url) = live_urls()?;
    let replacement_email = format!("replacement-{}@example.test", Uuid::new_v4());
    let attempt = account
        .client
        .start_recovery_with_password(
            &account.email,
            Zeroizing::new(account.password.clone()),
            &account.master_key,
            None,
        )
        .await?;
    let checkpoint = mail_checkpoint(&mailpit_url, &replacement_email, SIGNUP_CODE_SUBJECT).await?;
    let staged = account
        .client
        .complete_recovery(
            &attempt,
            &account.email,
            RecoveryChanges {
                new_email: Some(replacement_email.clone()),
                ..RecoveryChanges::default()
            },
        )
        .await;
    assert!(
        matches!(
            staged,
            Err(beebeeb_client::auth::AuthError::RecoveryEmailVerificationRequired)
        ),
        "email replacement did not stop at the mailbox-verification stage"
    );
    let code = wait_for_mail_code(
        &mailpit_url,
        &replacement_email,
        SIGNUP_CODE_SUBJECT,
        account.email_code_length,
        &checkpoint,
    )
    .await?;
    account
        .client
        .complete_recovery(
            &attempt,
            &account.email,
            RecoveryChanges {
                new_password: Some(Zeroizing::new(account.password.clone())),
                new_email: Some(replacement_email),
                email_verification_code: Some(code),
                ..RecoveryChanges::default()
            },
        )
        .await
        .map_err(|error| format!("verified replacement mailbox did not complete recovery: {error}"))?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn missing_file_version_probe_is_side_effect_free() -> TestResult {
    let account = provision_account().await?;
    let versions = account
        .client
        .file_versions("00000000-0000-0000-0000-000000000000")
        .await;
    assert!(versions.is_err(), "the missing-file probe must not create state");
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn rename_move_trash_and_restore() -> TestResult {
    let account = provision_account().await?;
    let parent = account
        .client
        .create_folder(&account.session, "live parent", None)
        .await?;
    let child = account
        .client
        .create_folder(&account.session, "live child", Some(parent.id.clone()))
        .await?;
    let renamed = account
        .client
        .rename_entry(&account.session, child.wire(), "live renamed")
        .await?;
    let moved = account
        .client
        .move_entry(&account.session, renamed.wire(), None)
        .await?;
    account.client.trash_entry(moved.wire()).await?;
    account.client.restore_entry(moved.wire()).await?;
    let restored = account.client.get_file_record(&account.session, &moved.id).await?;
    assert!(!restored.is_trashed, "restored entry remained marked as trashed");
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn upload_download_and_version_check_round_trip_plaintext() -> TestResult {
    let account = provision_account().await?;
    let root = tempfile::tempdir()?;
    let plaintext = b"live upload/download/version contract";
    let file_id = drive_upload(&account, &root, plaintext, 32 * 1024 * 1024, false).await?;
    let record = account.client.get_file_record(&account.session, &file_id).await?;
    account
        .client
        .rename_entry(&account.session, record.wire(), "live-renamed-upload.bin")
        .await?;
    assert_eq!(
        account.client.get_file_record(&account.session, &file_id).await?.name,
        "live-renamed-upload.bin"
    );
    let downloaded = download_uploaded_file(&account, &root, &file_id).await?;
    assert_eq!(
        downloaded, plaintext,
        "downloaded plaintext did not match uploaded bytes"
    );
    let versions = account.client.file_versions(&file_id).await?;
    assert_eq!(versions.file_id, file_id, "version route answered for a different file");
    assert_eq!(
        versions.versions.len(),
        1,
        "new upload did not have exactly one version"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn replace_restore_and_download_preserves_plaintext_and_counter() -> TestResult {
    let account = provision_account().await?;
    let root = tempfile::tempdir()?;
    let first = b"first protected version";
    let second = b"second protected version";
    let file_id = drive_upload(&account, &root, first, 32 * 1024 * 1024, false).await?;
    let before = account.client.file_versions(&file_id).await?;
    let first_version = before
        .versions
        .iter()
        .find(|version| version.version_number == before.current_version)
        .ok_or("initial version listing omitted current version")?
        .id
        .clone();

    let replaced = drive_replacement_upload(&account, &root, &file_id, second).await?;
    assert_eq!(replaced, file_id);
    assert_eq!(download_uploaded_file(&account, &root, &file_id).await?, second);

    let counter_store = Mutex::new(Store::open_in_memory()?);
    let restored = account
        .client
        .restore_version(&account.session, &counter_store, &file_id, &first_version)
        .await?;
    let counter = restored.counter.ok_or("protected restore omitted its counter")?;
    assert_eq!(
        counter_store.lock().unwrap().highest_file_version(&file_id)?,
        Some(counter)
    );
    let current = account.client.get_file(&file_id).await?;
    let metadata = decrypt_file_metadata(
        &account.master_key,
        &file_id,
        current
            .name_encrypted
            .as_deref()
            .ok_or("restored file omitted current metadata")?,
    )?;
    assert_eq!(metadata.version.map(|version| version.counter), Some(counter));
    assert_eq!(download_uploaded_file(&account, &root, &file_id).await?, first);
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn resumed_upload_reopens_durable_state_and_finishes() -> TestResult {
    let account = provision_account().await?;
    let root = tempfile::tempdir()?;
    let plaintext = vec![0x5au8; 10 * 1024 * 1024];
    let file_id = drive_upload(&account, &root, &plaintext, 6 * 1024 * 1024, true).await?;
    let downloaded = download_uploaded_file(&account, &root, &file_id).await?;
    assert_eq!(
        downloaded, plaintext,
        "resumed upload did not preserve every plaintext byte"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn complete_snapshot_then_sse_event_and_catch_up() -> TestResult {
    let account = provision_account().await?;
    let mut engine = SyncEngine::new(format!("live-sync-{}", Uuid::new_v4()));
    account
        .client
        .refresh_sync_snapshot(&account.session, &mut engine)
        .await
        .map_err(|error| format!("complete snapshot failed: {error}"))?;
    let before = engine.position();
    let stream =
        account
            .client
            .foreground_sync_with_timeout(&account.session, &mut engine, 100, Duration::from_secs(15));
    let mutation = async {
        sleep(Duration::from_millis(500)).await;
        account
            .client
            .create_folder(&account.session, "live SSE folder", None)
            .await
    };
    let (stream_result, mutation_result) = tokio::join!(stream, mutation);
    mutation_result.map_err(|error| format!("SSE trigger mutation failed: {error}"))?;
    stream_result.map_err(|error| format!("SSE foreground batch/catch-up failed: {error}"))?;
    account.client.catch_up_sync(&account.session, &mut engine, 100).await?;
    assert!(
        engine.position().seq_id > before.seq_id,
        "snapshot cursor did not advance after the SSE-triggered mutation"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn new_account_has_no_share_links() -> TestResult {
    let account = provision_account().await?;
    assert!(account.client.my_share_links().await?.shares.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn share_create_public_download_and_revoke() -> TestResult {
    let account = provision_account().await?;
    let root = tempfile::tempdir()?;
    let file_id = drive_upload(&account, &root, b"public-share-live", 32 * 1024 * 1024, false).await?;
    let wrapped = STANDARD.encode([0x51u8; 60]);
    let share = account
        .client
        .create_share_link(&file_id, &wrapped, Some(1), None)
        .await
        .map_err(|error| format!("share creation failed: {error}"))?;
    let entry = account.client.get_file(&file_id).await?;
    let versions = account.client.file_versions(&file_id).await?;
    let version = versions
        .versions
        .iter()
        .find(|version| version.version_number == versions.current_version)
        .ok_or("share source omitted its current version")?;
    let name_encrypted = entry
        .name_encrypted
        .as_deref()
        .ok_or("share source omitted encrypted metadata")?;
    let metadata = beebeeb_core::encrypt::decrypt_file_metadata(&account.master_key, &file_id, name_encrypted)?;
    let file_key = derive_file_key(&account.master_key, file_id.as_bytes());
    let plan = beebeeb_types::plan_chunks(entry.size_bytes, ChunkProfile::Mobile);
    let (anonymous, _) = live_client(&account.api_url)?;
    let anonymous = Arc::new(anonymous);
    let downloads = DownloadService::new(
        anonymous,
        Arc::new(Mutex::new(Store::open_in_memory()?)),
        root.path().join("anonymous-cache"),
        64 * 1024 * 1024,
        MemoryBudget::NATIVE,
    )?;
    let public_root = root.path().join("public");
    std::fs::create_dir(&public_root)?;
    let public_directory = beebeeb_core::path_safety::TrustedDirectory::open(&public_root)?;
    let result = downloads
        .share_view_download(
            &share.token,
            None,
            &file_id,
            &file_key,
            &metadata,
            version.chunk_count,
            entry.size_bytes,
            plan.chunk_size_bytes,
            &public_directory,
            "shared.bin",
        )
        .await
        .map_err(|error| format!("public share download failed before revoke: {error}"))?;
    assert_eq!(result, DownloadResult::Saved);
    assert_eq!(std::fs::read(public_root.join("shared.bin"))?, b"public-share-live");
    account
        .client
        .revoke_share_link(&share.id)
        .await
        .map_err(|error| format!("share revoke failed: {error}"))?;
    assert!(
        downloads
            .share_view_download(
                &share.token,
                None,
                &file_id,
                &file_key,
                &metadata,
                version.chunk_count,
                entry.size_bytes,
                plan.chunk_size_bytes,
                &public_directory,
                "revoked.bin",
            )
            .await
            .is_err(),
        "revoked share remained publicly downloadable"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn system_service_enable_marks_its_folder_and_refuses_normal_mutation() -> TestResult {
    let account = provision_account().await?;
    let item = beebeeb_core::item_id::NewItemId::owner(&account.master_key)?;
    let sealed_name = beebeeb_core::encrypt::encrypt_name_for_new_item(
        &account.master_key,
        &item,
        "Mail backup",
        None,
        beebeeb_core::chunk_stream::ExpectedChunkFormat::Unrecorded,
    )?;
    let enabled = account
        .client
        .enable_system_service(Service::MailBackup, item.as_str().to_owned(), sealed_name, None)
        .await
        .map_err(|error| format!("mail-backup service enable failed: {error}"))?;
    assert!(enabled.enabled, "service enable response did not report enabled");
    let folder = account
        .client
        .get_file_record(&account.session, &enabled.folder_id)
        .await?;
    assert_eq!(
        folder.managed_by.as_deref(),
        Some(Service::MailBackup.as_str()),
        "enabled service folder was not marked as managed"
    );
    let refused = account
        .client
        .rename_entry(&account.session, folder.wire(), "must be refused")
        .await;
    assert!(refused.is_err(), "ordinary rename mutated a service-managed folder");
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn signout_one_app() -> TestResult {
    let account = provision_account().await?;
    let token = stored_session_token(&account)?;
    assert_eq!(account_status_for_token(&account, &token).await?, 200);
    account.client.sign_out_this_app(&account.store).await?;
    assert_eq!(
        account_status_for_token(&account, &token).await?,
        401,
        "app sign-out left its session usable on the server"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn whole_device_signout_removes_server_device_and_local_session() -> TestResult {
    let account = provision_account().await?;
    let token = stored_session_token(&account)?;
    assert_eq!(account_status_for_token(&account, &token).await?, 200);
    let devices = account.client.list_devices().await?;
    let device = devices
        .devices
        .first()
        .ok_or("new account had no device row to sign out")?;
    let generation = account
        .client
        .sign_out_whole_device(&device.id, true, &account.store)
        .await
        .map_err(|error| format!("whole-device sign-out failed: {error}"))?;
    assert!(
        generation > account.session.generation(),
        "device sign-out did not advance local generation"
    );
    assert_eq!(
        account_status_for_token(&account, &token).await?,
        401,
        "device sign-out left its session usable on the server"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires BB_LIVE_API_URL and BB_LIVE_MAILPIT_URL"]
async fn removing_another_device_ends_only_that_devices_session() -> TestResult {
    let account = provision_account().await?;
    let own_token = stored_session_token(&account)?;
    let before: Vec<String> = account
        .client
        .list_devices()
        .await?
        .devices
        .into_iter()
        .map(|device| device.id)
        .collect();

    let (other, other_app) = live_client(&account.api_url)?;
    let store = MemorySecretStore::default();
    let accepted = password_on_new_device(&account, &other, &store).await?;
    let mut unlock = NewDeviceUnlock::recovery(accepted)?;
    authorize_unlock_email(&account, &other, &mut unlock).await?;
    unlock.provide_recovery_key(MasterKey::from_bytes(*account.master_key.to_bytes()))?;
    other
        .install_new_device(unlock.into_ready()?, &account.api_url, &store)
        .await?;
    let other_token = store
        .get(&format!("session.token.{other_app}"))?
        .ok_or("second device session token was not stored")?;
    let other_token = String::from_utf8(other_token.to_vec())?;
    assert_eq!(account_status_for_token(&account, &other_token).await?, 200);

    let devices = account.client.list_devices().await?.devices;
    assert_eq!(devices.len(), 2, "two devices on one platform shared one entry");
    let second = devices
        .iter()
        .find(|device| !before.contains(&device.id))
        .ok_or("second device was not listed as its own entry")?;
    account.client.remove_device(&second.id).await?;

    assert_eq!(
        account_status_for_token(&account, &other_token).await?,
        401,
        "removed device kept its session"
    );
    assert_eq!(
        account_status_for_token(&account, &own_token).await?,
        200,
        "removing another device ended the remover's session"
    );
    assert_eq!(account.client.list_devices().await?.devices.len(), 1);
    Ok(())
}

#[test]
#[ignore = "documented manual DB step; sqlx is not cached in this workspace"]
fn session_expiry_live_step_is_intentionally_manual() {
    // The live process must expire only the just-created session:
    // UPDATE sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1;
    // Then GET /api/v1/auth/me must fail and emit EngineEvent::SessionExpired.
    // The hermetic session-expiry unit test covers the client behavior. This
    // marker performs no network or DB mutation because this workspace has no
    // cached sqlx package.
}
