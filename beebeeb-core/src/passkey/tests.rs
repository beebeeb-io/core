//! Passkey vault + flow tests: web's vectors, core's vectors (which web's TS must open), and every flow against a
//! mock server with a mock authenticator.

use std::collections::HashMap;
use std::future::{Future, Ready, ready};
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use serde_json::{Value, json};

use super::ceremony::{self, CreationOptions, NativeAssertion, NativeAttestation, PasskeyError, RequestOptions};
use super::flow::{
    self, ApiRequest, ApiResponse, Assertion, Method, PasskeyAuthenticator, PasskeyHttp, Registration, VaultOutcome,
};
use super::*;

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn mk(bytes: &[u8]) -> MasterKey {
    MasterKey::from_bytes(bytes.try_into().unwrap())
}

fn sha(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

// ── the primitive ───────────────────────────────────────────────────────────

const WEB_VECTORS: &str = include_str!("../../../test-vectors/passkey_vault.json");
const CORE_VECTORS: &str = include_str!("../../../test-vectors/passkey_vault_core.json");

#[test]
fn passkey_salts_match_web_and_the_webauthn_prf_hash() {
    let v: Value = serde_json::from_str(WEB_VECTORS).unwrap();
    assert_eq!(hex(&prf_eval_input()), v["prf_eval_input"].as_str().unwrap());
    assert_eq!(hex(&hmac_secret_salt()), v["hmac_secret_salt"].as_str().unwrap());
}

#[test]
fn passkey_web_vectors_open_and_rewrap_byte_for_byte() {
    let v: Value = serde_json::from_str(WEB_VECTORS).unwrap();
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let mut checked = 0;
    for row in rows {
        let prf = PrfOutput::from_slice(&unhex(row["prf_output"].as_str().unwrap())).unwrap();
        let master = unhex(row["master_key"].as_str().unwrap());
        let blob = unhex(row["blob"].as_str().unwrap());
        assert_eq!(
            hex(derive_wrap_key(&prf).unwrap().as_slice()),
            row["wrap_key"].as_str().unwrap()
        );
        let opened = unwrap_vault_key(&prf, &blob).unwrap();
        assert_eq!(opened.as_bytes().as_slice(), master.as_slice());
        let nonce: [u8; 12] = blob[..12].try_into().unwrap();
        assert_eq!(wrap_vault_key_with_nonce(&prf, &mk(&master), nonce).unwrap(), blob);
        checked += 1;
    }
    assert_eq!(checked, 6);
}

/// Core's own vectors, for web's TS to open (`scripts/passkey-vectors/web-opens-core.ts`). Regenerate with
/// `BB_WRITE_PASSKEY_VECTORS=1 cargo test -p beebeeb-core passkey_core_vectors`; otherwise the file must equal what
/// core generates now.
fn core_vectors() -> Value {
    let mut rows = Vec::new();
    for i in 0..4 {
        let prf_bytes = sha(&format!("core-passkey-vector/prf/{i}"));
        let master = sha(&format!("core-passkey-vector/master/{i}"));
        let nonce: [u8; 12] = sha(&format!("core-passkey-vector/nonce/{i}"))[..12].try_into().unwrap();
        let prf = PrfOutput::from_slice(&prf_bytes).unwrap();
        let blob = wrap_vault_key_with_nonce(&prf, &mk(&master), nonce).unwrap();
        rows.push(json!({ "prf_output": hex(&prf_bytes), "master_key": hex(&master), "blob": hex(&blob) }));
    }
    // Two rows web must refuse: a flipped tag byte, and the right blob under another PRF output.
    let prf_bytes = sha("core-passkey-vector/prf/0");
    let prf = PrfOutput::from_slice(&prf_bytes).unwrap();
    let master = sha("core-passkey-vector/master/0");
    let mut blob = wrap_vault_key_with_nonce(&prf, &mk(&master), [7u8; 12]).unwrap();
    let good = blob.clone();
    *blob.last_mut().unwrap() ^= 0x01;
    rows.push(
        json!({ "prf_output": hex(&prf_bytes), "master_key": hex(&master), "blob": hex(&blob), "expect": "refuse" }),
    );
    rows.push(json!({ "prf_output": hex(&sha("core-passkey-vector/other")), "master_key": hex(&master), "blob": hex(&good), "expect": "refuse" }));
    json!({ "source": "beebeeb-core passkey::tests::core_vectors", "rows": rows })
}

#[test]
fn passkey_core_vectors_are_generated_and_core_reads_them() {
    let generated = core_vectors();
    if std::env::var_os("BB_WRITE_PASSKEY_VECTORS").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/passkey_vault_core.json");
        std::fs::write(path, serde_json::to_string_pretty(&generated).unwrap() + "\n").unwrap();
        return;
    }
    let on_disk: Value = serde_json::from_str(CORE_VECTORS).unwrap();
    assert_eq!(
        on_disk, generated,
        "test-vectors/passkey_vault_core.json is hand-edited or stale"
    );
    let (mut opened, mut refused) = (0, 0);
    for row in on_disk["rows"].as_array().unwrap() {
        let prf = PrfOutput::from_slice(&unhex(row["prf_output"].as_str().unwrap())).unwrap();
        let result = unwrap_vault_key(&prf, &unhex(row["blob"].as_str().unwrap()));
        if row.get("expect").is_some() {
            assert!(matches!(result, Err(CoreError::Decryption)));
            refused += 1;
        } else {
            assert_eq!(hex(result.unwrap().as_bytes()), row["master_key"].as_str().unwrap());
            opened += 1;
        }
    }
    assert_eq!((opened, refused), (4, 2));
}

#[test]
fn passkey_unwrap_refuses_wrong_lengths_tamper_and_the_wrong_prf() {
    let prf = PrfOutput::from_slice(&[1u8; 32]).unwrap();
    let blob = wrap_vault_key(&prf, &mk(&[9u8; 32])).unwrap();
    assert_eq!(blob.len(), VAULT_BLOB_LEN);
    assert!(matches!(
        unwrap_vault_key(&prf, &blob[..59]),
        Err(CoreError::InvalidInput(_))
    ));
    let mut longer = blob.clone();
    longer.push(0);
    assert!(matches!(
        unwrap_vault_key(&prf, &longer),
        Err(CoreError::InvalidInput(_))
    ));
    for i in [0, 12, 43, 59] {
        let mut t = blob.clone();
        t[i] ^= 0x80;
        assert!(
            matches!(unwrap_vault_key(&prf, &t), Err(CoreError::Decryption)),
            "byte {i}"
        );
    }
    let other = PrfOutput::from_slice(&[2u8; 32]).unwrap();
    assert!(matches!(unwrap_vault_key(&other, &blob), Err(CoreError::Decryption)));
    assert!(PrfOutput::from_slice(&[0u8; 31]).is_err());
    assert_eq!(format!("{prf:?}"), "PrfOutput(..)");
    // Two wraps of one key never share a nonce.
    assert_ne!(blob[..12], wrap_vault_key(&prf, &mk(&[9u8; 32])).unwrap()[..12]);
}

// ── the wire ────────────────────────────────────────────────────────────────

fn register_start_answer() -> Value {
    json!({
        "publicKey": {
            "rp": { "name": "Beebeeb", "id": "beebeeb.io" },
            "user": { "id": ceremony::b64url(b"user-handle-16by"), "name": "ada@example.eu", "displayName": "ada@example.eu" },
            "challenge": ceremony::b64url(&[5u8; 32]),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -257 }],
            "timeout": 300000,
            "excludeCredentials": [{ "type": "public-key", "id": ceremony::b64url(&[1u8; 16]) }],
            "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
            "attestation": "none",
            "extensions": { "credProps": true }
        },
        "reg_id": "4f1c2a8e-6b1d-4b5e-9a35-2b7f7d1f0c11"
    })
}

fn login_start_answer() -> Value {
    json!({
        "publicKey": {
            "challenge": ceremony::b64url(&[6u8; 32]),
            "timeout": 300000,
            "rpId": "beebeeb.io",
            "allowCredentials": [{ "type": "public-key", "id": ceremony::b64url(&[1u8; 16]) }],
            "userVerification": "required"
        },
        "auth_state": "c3RhdGU",
        "user_id": "9d0e1a1f-0000-4000-8000-000000000001"
    })
}

#[test]
fn passkey_registration_options_decode_the_server_answer() {
    let start = ceremony::parse_registration_start(&register_start_answer()).unwrap();
    let o = &start.options;
    assert_eq!(start.reg_id, "4f1c2a8e-6b1d-4b5e-9a35-2b7f7d1f0c11");
    assert_eq!(
        (o.rp_id.as_str(), o.origin.as_str()),
        ("beebeeb.io", "https://beebeeb.io")
    );
    assert_eq!(o.user_id, b"user-handle-16by");
    assert_eq!(o.challenge, vec![5u8; 32]);
    assert_eq!(o.algorithms, vec![-7, -257]);
    assert_eq!(o.exclude_credentials, vec![vec![1u8; 16]]);
    assert_eq!(
        (o.resident_key.as_str(), o.user_verification.as_str()),
        ("required", "required")
    );
    assert_eq!(o.prf.hmac_secret_salt, hmac_secret_salt().to_vec());
    let cd: Value = serde_json::from_slice(&o.client_data_json()).unwrap();
    assert_eq!(
        cd,
        json!({ "type": "webauthn.create", "challenge": ceremony::b64url(&[5u8; 32]), "origin": "https://beebeeb.io", "crossOrigin": false })
    );
    // The double-wrapped shape web also accepts.
    let mut double = register_start_answer();
    double["publicKey"] = json!({ "publicKey": register_start_answer()["publicKey"] });
    assert_eq!(ceremony::parse_registration_start(&double).unwrap(), start);
    assert_eq!(
        ceremony::parse_registration_start(&json!({ "reg_id": "x" })),
        Err(PasskeyError::Malformed("publicKey"))
    );
}

#[test]
fn passkey_finish_bodies_match_the_web_wire() {
    let start = ceremony::parse_registration_start(&register_start_answer()).unwrap();
    let att = NativeAttestation {
        credential_id: vec![0xfb; 3],
        attestation_object: vec![1, 2],
        client_data_json: b"{}".to_vec(),
    };
    let body = ceremony::registration_finish_body(&start, &att, Some("Work laptop"));
    assert_eq!(
        body,
        json!({
            "credential": { "id": "-_v7", "rawId": "-_v7", "type": "public-key",
                "response": { "attestationObject": "AQI", "clientDataJSON": "e30" }, "extensions": {} },
            "reg_id": "4f1c2a8e-6b1d-4b5e-9a35-2b7f7d1f0c11",
            "name": "Work laptop"
        })
    );
    assert_eq!(
        ceremony::escrow_body(&[0xfb; 3], &[0xfb; 3]),
        json!({ "credential_id": "-_v7", "encrypted_vault_key": "+/v7" })
    );
    assert_eq!(ceremony::escrow_path(&[0xfb; 3]), "/api/v1/auth/vault-key-escrow/-_v7");

    let start = ceremony::parse_assertion_start(&login_start_answer()).unwrap();
    assert_eq!(start.options.allow_credentials, vec![vec![1u8; 16]]);
    let a = NativeAssertion {
        credential_id: vec![1u8; 16],
        authenticator_data: vec![3],
        client_data_json: b"{}".to_vec(),
        signature: vec![4],
        user_handle: None,
    };
    let body = ceremony::assertion_finish_body(&start, &a);
    assert_eq!(body["credential"]["response"]["userHandle"], Value::Null);
    assert_eq!(body["auth_state"], "c3RhdGU");
    assert_eq!(body["user_id"], "9d0e1a1f-0000-4000-8000-000000000001");
    let cd: Value = serde_json::from_slice(&start.options.client_data_json()).unwrap();
    assert_eq!(cd["type"], "webauthn.get");
}

#[test]
fn passkey_list_remove_and_errors_keep_to_codes() {
    let list = ceremony::parse_passkey_list(&json!({ "passkeys": [
        { "id": "a", "name": "Phone", "created_at": "2026-11-01T10:00:00Z" },
        { "id": "b", "name": "Key", "created_at": "2026-11-02T10:00:00Z", "last_used_at": "2026-11-03T10:00:00Z", "prf": true }
    ]}))
    .unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!((list[0].prf, list[0].last_used_at.as_deref()), (None, None));
    assert_eq!(
        (list[1].prf, list[1].last_used_at.as_deref()),
        (Some(true), Some("2026-11-03T10:00:00Z"))
    );
    assert_eq!(
        ceremony::remove_path("../../account"),
        Err(PasskeyError::Malformed("passkey id"))
    );
    assert!(ceremony::remove_path("4f1c2a8e-6b1d-4b5e-9a35-2b7f7d1f0c11").is_ok());
    assert_eq!(
        ceremony::server_error(403, &json!({ "error": "confirmation_required" })),
        PasskeyError::ConfirmationRequired
    );
    let e = ceremony::server_error(
        400,
        &json!({ "error": "Bad thing at https://api.beebeeb.test", "message": "secret detail" }),
    );
    assert_eq!(
        e,
        PasskeyError::Server {
            status: 400,
            code: None
        }
    );
    assert_eq!(e.code(), "passkey_server_error");
}

// ── the flows, against a mock server ────────────────────────────────────────

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the mocks are always ready"),
    }
}

const SESSION: &str = "session-from-login";
const NEW_SESSION: &str = "session-minted-by-passkey";

/// One recorded call: method, path, bearer, confirm token, body.
type Call = (Method, String, Option<String>, Option<String>, Option<Value>);

#[derive(Default)]
struct Server {
    /// (method, path, bearer, confirm token, body) of every call, in order.
    calls: Mutex<Vec<Call>>,
    escrow: Mutex<HashMap<String, String>>,
    fail_escrow_store: bool,
}

impl PasskeyHttp for Server {
    fn send(&self, r: ApiRequest) -> impl Future<Output = Result<ApiResponse, PasskeyError>> + Send {
        let bearer = r.bearer.as_ref().map(|t| t.to_string());
        let confirm = r.confirm_token.as_ref().map(|t| t.to_string());
        self.calls.lock().unwrap().push((
            r.method,
            r.path.clone(),
            bearer.clone(),
            confirm.clone(),
            r.body.clone(),
        ));
        let ok = |body: Value| Ok(ApiResponse { status: 200, body });
        let res = match (r.method, r.path.as_str()) {
            (Method::Post, "/api/v1/auth/passkey/register-start") if confirm.as_deref() == Some("fresh-proof") => {
                ok(register_start_answer())
            }
            (Method::Post, "/api/v1/auth/passkey/register-start") => Ok(ApiResponse {
                status: 403,
                body: json!({ "error": "confirmation_required" }),
            }),
            (Method::Post, "/api/v1/auth/passkey/register-finish") => {
                ok(json!({ "id": "7a7a7a7a-0000-4000-8000-000000000007", "name": "x", "created_at": "now" }))
            }
            (Method::Post, "/api/v1/auth/vault-key-escrow") if self.fail_escrow_store => Ok(ApiResponse {
                status: 409,
                body: json!({ "error": "conflict" }),
            }),
            (Method::Post, "/api/v1/auth/vault-key-escrow") => {
                let b = r.body.unwrap();
                self.escrow.lock().unwrap().insert(
                    b["credential_id"].as_str().unwrap().to_string(),
                    b["encrypted_vault_key"].as_str().unwrap().to_string(),
                );
                Ok(ApiResponse {
                    status: 201,
                    body: json!({ "ok": true }),
                })
            }
            (Method::Post, "/api/v1/auth/passkey/login-start") => ok(login_start_answer()),
            (Method::Post, "/api/v1/auth/passkey/login-finish") => ok(
                json!({ "user_id": "9d0e1a1f-0000-4000-8000-000000000002", "session_token": NEW_SESSION, "salt": "00" }),
            ),
            (Method::Get, path) if path.starts_with("/api/v1/auth/vault-key-escrow/") => {
                let id = path.rsplit('/').next().unwrap();
                match self.escrow.lock().unwrap().get(id) {
                    Some(blob) => ok(json!({ "credential_id": id, "encrypted_vault_key": blob })),
                    None => Ok(ApiResponse {
                        status: 404,
                        body: json!({ "error": "not_found" }),
                    }),
                }
            }
            (Method::Get, "/api/v1/auth/passkeys") => {
                ok(json!({ "passkeys": [{ "id": "a", "name": "Phone", "created_at": "t" }] }))
            }
            (Method::Delete, _) => ok(json!({ "message": "passkey removed" })),
            _ => Ok(ApiResponse {
                status: 404,
                body: Value::Null,
            }),
        };
        let r: Ready<_> = ready(res);
        r
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Prf {
    AtCreate,
    OnlyOnGet,
    None,
}

struct Authenticator {
    prf: Prf,
    prf_bytes: [u8; 32],
    gets: Mutex<Vec<RequestOptions>>,
    creates: Mutex<usize>,
}

impl Authenticator {
    fn new(prf: Prf) -> Self {
        Self {
            prf,
            prf_bytes: [0x42; 32],
            gets: Mutex::new(Vec::new()),
            creates: Mutex::new(0),
        }
    }
    fn prf_output(&self) -> Option<PrfOutput> {
        Some(PrfOutput::from_slice(&self.prf_bytes).unwrap())
    }
}

impl PasskeyAuthenticator for Authenticator {
    fn make_credential(&self, o: &CreationOptions) -> impl Future<Output = Result<Registration, PasskeyError>> + Send {
        *self.creates.lock().unwrap() += 1;
        assert_eq!(o.prf.hmac_secret_salt, hmac_secret_salt().to_vec());
        ready(Ok(Registration {
            attestation: NativeAttestation {
                credential_id: vec![1u8; 16],
                attestation_object: vec![0xa0],
                client_data_json: o.client_data_json(),
            },
            prf_output: if self.prf == Prf::AtCreate {
                self.prf_output()
            } else {
                None
            },
            prf_enabled: Some(self.prf != Prf::None),
        }))
    }
    fn get_assertion(&self, o: &RequestOptions) -> impl Future<Output = Result<Assertion, PasskeyError>> + Send {
        self.gets.lock().unwrap().push(o.clone());
        ready(Ok(Assertion {
            assertion: NativeAssertion {
                credential_id: vec![1u8; 16],
                authenticator_data: vec![0],
                client_data_json: o.client_data_json(),
                signature: vec![0],
                user_handle: None,
            },
            prf_output: if self.prf == Prf::None { None } else { self.prf_output() },
        }))
    }
}

#[test]
fn passkey_add_with_prf_at_create_escrows_a_blob_the_sign_in_opens() {
    let server = Server::default();
    let authn = Authenticator::new(Prf::AtCreate);
    let vault_key = mk(&[0x11; 32]);
    let added = block_on(flow::add_passkey(
        &server,
        &authn,
        SESSION,
        "fresh-proof",
        Some("Laptop"),
        Some(&vault_key),
    ))
    .unwrap();
    assert_eq!(
        added,
        flow::Added {
            id: "7a7a7a7a-0000-4000-8000-000000000007".into(),
            prf: true,
            escrowed: true
        }
    );
    assert_eq!(authn.gets.lock().unwrap().len(), 0, "no probe when create gave PRF");
    {
        let calls = server.calls.lock().unwrap();
        let paths: Vec<_> = calls.iter().map(|c| c.1.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/api/v1/auth/passkey/register-start",
                "/api/v1/auth/passkey/register-finish",
                "/api/v1/auth/vault-key-escrow"
            ]
        );
        assert_eq!(calls[0].3.as_deref(), Some("fresh-proof"));
        assert!(calls.iter().all(|c| c.2.as_deref() == Some(SESSION)));
        assert_eq!(calls[1].4.as_ref().unwrap()["name"], "Laptop");
        // The escrow body carries ciphertext only: never the vault key, the PRF output or the wrap key.
        let escrow = serde_json::to_string(&calls[2].4).unwrap();
        for secret in [hex(&[0x11; 32]), hex(&[0x42; 32])] {
            assert!(!escrow.contains(&secret));
        }
    }
    let signed = block_on(flow::sign_in(&server, &authn, "ada@example.eu")).unwrap();
    assert_eq!(signed.user_id, "9d0e1a1f-0000-4000-8000-000000000002");
    assert_eq!(signed.session_token.as_str(), NEW_SESSION);
    let key = signed.vault.into_master_key().expect("unlocked");
    assert_eq!(key.as_bytes(), &[0x11; 32]);
    let calls = server.calls.lock().unwrap();
    let last = calls.last().unwrap();
    assert_eq!(
        (last.0, last.2.as_deref()),
        (Method::Get, Some(NEW_SESSION)),
        "the escrow is read with the NEW session"
    );
}

#[test]
fn passkey_add_probes_for_prf_when_create_gives_none() {
    let server = Server::default();
    let authn = Authenticator::new(Prf::OnlyOnGet);
    let added = block_on(flow::add_passkey(
        &server,
        &authn,
        SESSION,
        "fresh-proof",
        None,
        Some(&mk(&[3; 32])),
    ))
    .unwrap();
    assert!(added.prf && added.escrowed);
    let gets = authn.gets.lock().unwrap();
    assert_eq!(gets.len(), 1);
    assert_eq!(
        gets[0].allow_credentials,
        vec![vec![1u8; 16]],
        "the probe names only the new credential"
    );
    assert_ne!(
        gets[0].challenge,
        vec![5u8; 32],
        "the probe never reuses the server's challenge"
    );
    assert_eq!(
        server.calls.lock().unwrap().len(),
        3,
        "the probe never reaches the server"
    );
}

#[test]
fn passkey_without_prf_is_added_but_never_escrowed_and_signs_in_locked() {
    let server = Server::default();
    let authn = Authenticator::new(Prf::None);
    let added = block_on(flow::add_passkey(
        &server,
        &authn,
        SESSION,
        "fresh-proof",
        None,
        Some(&mk(&[3; 32])),
    ))
    .unwrap();
    assert_eq!((added.prf, added.escrowed), (false, false));
    assert_eq!(
        authn.gets.lock().unwrap().len(),
        0,
        "the platform said no PRF: no probe"
    );
    assert_eq!(server.calls.lock().unwrap().len(), 2, "no escrow call");
    let signed = block_on(flow::sign_in(&server, &authn, "ada@example.eu")).unwrap();
    assert!(matches!(signed.vault, VaultOutcome::NoPrf));
}

#[test]
fn passkey_sign_in_reports_no_escrow_and_a_blob_that_does_not_open() {
    let server = Server::default();
    let authn = Authenticator::new(Prf::AtCreate);
    let signed = block_on(flow::sign_in(&server, &authn, "ada@example.eu")).unwrap();
    assert!(matches!(signed.vault, VaultOutcome::NoEscrow));
    // An escrow made under another PRF output.
    let other = PrfOutput::from_slice(&[0x01; 32]).unwrap();
    let blob = wrap_vault_key(&other, &mk(&[9; 32])).unwrap();
    let body = ceremony::escrow_body(&[1u8; 16], &blob);
    server.escrow.lock().unwrap().insert(
        body["credential_id"].as_str().unwrap().into(),
        body["encrypted_vault_key"].as_str().unwrap().into(),
    );
    let signed = block_on(flow::sign_in(&server, &authn, "ada@example.eu")).unwrap();
    assert!(matches!(signed.vault, VaultOutcome::UnwrapFailed));
    assert!(
        !format!("{signed:?}").contains(NEW_SESSION),
        "Debug never prints the session"
    );
}

#[test]
fn passkey_add_needs_a_fresh_proof_and_survives_a_failed_escrow() {
    let server = Server::default();
    let authn = Authenticator::new(Prf::AtCreate);
    let err = block_on(flow::add_passkey(&server, &authn, SESSION, "stale", None, None)).unwrap_err();
    assert_eq!(err, PasskeyError::ConfirmationRequired);
    assert_eq!(
        *authn.creates.lock().unwrap(),
        0,
        "no platform prompt before the server agreed"
    );
    let server = Server {
        fail_escrow_store: true,
        ..Server::default()
    };
    let added = block_on(flow::add_passkey(
        &server,
        &authn,
        SESSION,
        "fresh-proof",
        None,
        Some(&mk(&[3; 32])),
    ))
    .unwrap();
    assert_eq!((added.prf, added.escrowed), (true, false));
    // No vault key in memory: added with PRF, nothing escrowed, no escrow call.
    let server = Server::default();
    let added = block_on(flow::add_passkey(&server, &authn, SESSION, "fresh-proof", None, None)).unwrap();
    assert_eq!((added.prf, added.escrowed), (true, false));
    assert_eq!(server.calls.lock().unwrap().len(), 2);
}

#[test]
fn passkey_list_and_remove_go_to_the_right_routes() {
    let server = Server::default();
    let list = block_on(flow::list_passkeys(&server, SESSION)).unwrap();
    assert_eq!(list.len(), 1);
    block_on(flow::remove_passkey(
        &server,
        SESSION,
        Some("proof"),
        "4f1c2a8e-6b1d-4b5e-9a35-2b7f7d1f0c11",
    ))
    .unwrap();
    let calls = server.calls.lock().unwrap();
    assert_eq!(calls[1].0, Method::Delete);
    assert_eq!(calls[1].1, "/api/v1/auth/passkeys/4f1c2a8e-6b1d-4b5e-9a35-2b7f7d1f0c11");
    assert_eq!(calls[1].3.as_deref(), Some("proof"));
    drop(calls);
    let err = block_on(flow::remove_passkey(&server, SESSION, None, "not-a-uuid")).unwrap_err();
    assert_eq!(err.code(), "passkey_malformed");
    assert_eq!(
        server.calls.lock().unwrap().len(),
        2,
        "a bad id never reaches the server"
    );
}
