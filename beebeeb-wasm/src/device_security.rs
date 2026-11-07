use beebeeb_api::{Endpoint, Method};
use beebeeb_core::CoreError;
use beebeeb_core::device_link::{
    AccountKeyMaterial, ConfirmedTypedApproval, DeviceLinkQr, NewDeviceLink, PakeSealedAccountKeyMaterial,
    SealedAccountKeyMaterial, TypedCodeApprover, TypedCodeReceiver, seal_for_new_device,
};
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::key_proof::{KeyProofBinding, KeyProofChallenge, answer_challenge};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Stable error text when the approver's confirmation check fails: the typed
/// code did not match, or the device's reported name was changed on the way.
/// Show it as a failed attempt and deny the link.
pub const CONFIRMATION_FAILED: &str = "confirmation_failed";
/// Stable error text for a relayed message that is not a typed-code message.
pub const MALFORMED_ANSWER: &str = "malformed_answer";

#[derive(Serialize)]
struct DeviceLinkPublicJs {
    session_id: Vec<u8>,
    public_key: Vec<u8>,
    device_name: String,
    qr_payload: String,
}

#[derive(Serialize)]
struct SealedDeviceLinkJs {
    session_id: Vec<u8>,
    recipient_public: Vec<u8>,
    approver_public: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize)]
struct TypedSealJs {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn typed_error(error: CoreError) -> JsError {
    match error {
        CoreError::Decryption => JsError::new(CONFIRMATION_FAILED),
        _ => JsError::new(MALFORMED_ANSWER),
    }
}

/// The new device's side of a link. Send `publicFields().session_id`,
/// `public_key` and `device_name` (the canonical form) to `start_device_link`;
/// render `qr_payload` as the QR and show `typedCode()` next to it.
#[wasm_bindgen]
pub struct WasmNewDeviceLink {
    inner: Option<NewDeviceLink>,
}

#[wasm_bindgen]
impl WasmNewDeviceLink {
    #[wasm_bindgen(constructor)]
    pub fn new(session_id: &[u8], device_name: &str) -> Result<WasmNewDeviceLink, JsError> {
        let session_id = fixed(session_id, "session id")?;
        let link = NewDeviceLink::generate(session_id, device_name)
            .map_err(|_| JsError::new("device link could not be created"))?;
        Ok(Self { inner: Some(link) })
    }

    #[wasm_bindgen(js_name = publicFields)]
    pub fn public_fields(&self) -> Result<JsValue, JsError> {
        let link = self.link()?;
        serde_wasm_bindgen::to_value(&DeviceLinkPublicJs {
            session_id: link.qr().session_id().to_vec(),
            public_key: link.public_key().to_vec(),
            device_name: link.device_name().to_owned(),
            qr_payload: link.qr_payload(),
        })
        .map_err(|_| JsError::new("device link fields could not be encoded"))
    }

    #[wasm_bindgen(js_name = typedCode)]
    pub fn typed_code(&self) -> Result<String, JsError> {
        self.link().map(|link| link.typed_code().to_owned())
    }

    /// QR path: open the approval relayed for this link. The link supplies its
    /// own session id and public key; the attempt consumes it.
    pub fn open(
        &mut self,
        approver_public: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<WasmAccountKeyMaterial, JsError> {
        let link = self.take()?;
        let sealed = SealedAccountKeyMaterial::from_parts(
            *link.qr().session_id(),
            *link.public_key(),
            fixed(approver_public, "approver public key")?,
            fixed(nonce, "nonce")?,
            ciphertext.to_vec(),
        )
        .map_err(|_| JsError::new("invalid sealed device-link material"))?;
        let material = link
            .open(sealed)
            .map_err(|_| JsError::new("device-link material did not authenticate"))?;
        Ok(WasmAccountKeyMaterial {
            master_key: material.into_master_key(),
        })
    }

    /// Typed-code path: answer the approver's message (relayed under role
    /// `approver`). Relay the receiver's `message` under role `new_device`,
    /// then open the approval with it. The attempt consumes this link.
    #[wasm_bindgen(js_name = answerTypedCode)]
    pub fn answer_typed_code(&mut self, approver_message: &[u8]) -> Result<WasmTypedReceiver, JsError> {
        let (receiver, message) = self.take()?.answer_typed_code(approver_message).map_err(typed_error)?;
        Ok(WasmTypedReceiver {
            inner: Some(receiver),
            message,
        })
    }
}

impl WasmNewDeviceLink {
    fn link(&self) -> Result<&NewDeviceLink, JsError> {
        self.inner
            .as_ref()
            .ok_or_else(|| JsError::new("device link has already been consumed"))
    }

    fn take(&mut self) -> Result<NewDeviceLink, JsError> {
        self.inner
            .take()
            .ok_or_else(|| JsError::new("device link has already been consumed"))
    }
}

/// The new device after it answered a typed-code attempt.
#[wasm_bindgen]
pub struct WasmTypedReceiver {
    inner: Option<TypedCodeReceiver>,
    message: Vec<u8>,
}

#[wasm_bindgen]
impl WasmTypedReceiver {
    /// The message to relay under role `new_device`.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    /// Open the relayed typed-code approval (`nonce`, `ciphertext` from the
    /// link result). The approver's tag is checked first; one attempt.
    pub fn open(&mut self, nonce: &[u8], ciphertext: &[u8]) -> Result<WasmAccountKeyMaterial, JsError> {
        let receiver = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("typed-code receiver has already been used"))?;
        let sealed = PakeSealedAccountKeyMaterial::from_parts(fixed(nonce, "nonce")?, ciphertext.to_vec())
            .map_err(|_| JsError::new(MALFORMED_ANSWER))?;
        let material = receiver
            .open(sealed)
            .map_err(|_| JsError::new("device-link material did not authenticate"))?;
        Ok(WasmAccountKeyMaterial {
            master_key: material.into_master_key(),
        })
    }
}

enum ApprovalState {
    Started(TypedCodeApprover),
    Confirmed(ConfirmedTypedApproval),
    Spent,
}

/// The approver's side of a typed-code attempt, for a browser without a camera.
/// Construct it with the code the person typed and the link detail's
/// `session_id` and `device_name`; relay `message` under role `approver`; pass
/// the new device's answer to `confirm`, and only then `seal`. Show
/// `deviceName` while the person types: `confirm` proves the new device
/// reported it.
#[wasm_bindgen]
pub struct WasmTypedApproval {
    state: ApprovalState,
    device_name: String,
    message: Vec<u8>,
}

#[wasm_bindgen]
impl WasmTypedApproval {
    #[wasm_bindgen(constructor)]
    pub fn new(typed_code: &str, session_id: &[u8], device_name: &str) -> Result<WasmTypedApproval, JsError> {
        let session_id = fixed(session_id, "session id")?;
        let (approver, message) = TypedCodeApprover::start(typed_code, &session_id, device_name)
            .map_err(|_| JsError::new(MALFORMED_ANSWER))?;
        Ok(Self {
            device_name: approver.device_name().to_owned(),
            state: ApprovalState::Started(approver),
            message,
        })
    }

    /// The message to relay under role `approver`.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    #[wasm_bindgen(getter, js_name = deviceName)]
    pub fn device_name(&self) -> String {
        self.device_name.clone()
    }

    /// Check the new device's answer (relayed under role `new_device`). Throws
    /// `confirmation_failed` for a wrong code or a changed device name, and
    /// `malformed_answer` for anything that is not an answer; the attempt is
    /// spent either way, so deny the link and start again.
    pub fn confirm(&mut self, new_device_message: &[u8]) -> Result<(), JsError> {
        match std::mem::replace(&mut self.state, ApprovalState::Spent) {
            ApprovalState::Started(approver) => {
                self.state = ApprovalState::Confirmed(approver.confirm(new_device_message).map_err(typed_error)?);
                Ok(())
            }
            _ => Err(JsError::new("typed-code approval has already been used")),
        }
    }

    /// Seal the account key for the confirmed new device: `{ nonce, ciphertext }`
    /// for `approve_device_link` (with no `approver_public`). Throws before
    /// `confirm` succeeded.
    pub fn seal(&mut self, master_key: &[u8]) -> Result<JsValue, JsError> {
        let master_key = master(master_key)?;
        match std::mem::replace(&mut self.state, ApprovalState::Spent) {
            ApprovalState::Confirmed(confirmed) => {
                let sealed = confirmed
                    .seal(AccountKeyMaterial::from_master_key(master_key))
                    .map_err(|_| JsError::new("device link could not be sealed"))?;
                serde_wasm_bindgen::to_value(&TypedSealJs {
                    nonce: sealed.nonce().to_vec(),
                    ciphertext: sealed.ciphertext().to_vec(),
                })
                .map_err(|_| JsError::new("sealed device link could not be encoded"))
            }
            _ => Err(JsError::new("typed-code approval is not confirmed")),
        }
    }
}

/// Account key material stays opaque after device approval. It can answer a
/// proof but has no byte getter.
#[wasm_bindgen]
pub struct WasmAccountKeyMaterial {
    master_key: MasterKey,
}

#[wasm_bindgen]
impl WasmAccountKeyMaterial {
    #[wasm_bindgen(js_name = answerSessionKeyProof)]
    pub fn answer_session_key_proof(
        &self,
        nonce: &[u8],
        server_public: &[u8],
        session_id: &[u8],
        account_id: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        answer(
            &self.master_key,
            KeyProofBinding::Session { session_id, account_id },
            nonce,
            server_public,
        )
    }

    #[wasm_bindgen(js_name = answerRecoveryKeyProof)]
    pub fn answer_recovery_key_proof(
        &self,
        nonce: &[u8],
        server_public: &[u8],
        canonical_email: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        answer(
            &self.master_key,
            KeyProofBinding::Recovery { canonical_email },
            nonce,
            server_public,
        )
    }
}

#[wasm_bindgen(js_name = sealDeviceLink)]
/// QR path, approver side. `scanned_qr` is the raw text the camera read from
/// the new device's screen; core parses it, so no fingerprint bytes come from
/// JavaScript. Never build that text from server data: the typed code gives no
/// protection against a substituted key on this path. Without a camera, use
/// `WasmTypedApproval`.
pub fn seal_device_link(
    master_key: &[u8],
    scanned_qr: &str,
    relayed_public: &[u8],
    typed_code: &str,
) -> Result<JsValue, JsError> {
    let master_key = master(master_key)?;
    let qr = DeviceLinkQr::parse(scanned_qr).map_err(|_| JsError::new("not a Beebeeb device-link QR"))?;
    let relayed_public = fixed(relayed_public, "relayed public key")?;
    let sealed = seal_for_new_device(
        &qr,
        &relayed_public,
        typed_code,
        AccountKeyMaterial::from_master_key(master_key),
    )
    .map_err(|_| JsError::new("device link could not be sealed"))?;
    serde_wasm_bindgen::to_value(&SealedDeviceLinkJs {
        session_id: sealed.session_id().to_vec(),
        recipient_public: sealed.recipient_public().to_vec(),
        approver_public: sealed.approver_public().to_vec(),
        nonce: sealed.nonce().to_vec(),
        ciphertext: sealed.ciphertext().to_vec(),
    })
    .map_err(|_| JsError::new("sealed device link could not be encoded"))
}

#[wasm_bindgen(js_name = answerSessionKeyProof)]
pub fn answer_session_key_proof(
    master_key: &[u8],
    nonce: &[u8],
    server_public: &[u8],
    session_id: &[u8],
    account_id: &[u8],
) -> Result<Vec<u8>, JsError> {
    let master_key = master(master_key)?;
    answer(
        &master_key,
        KeyProofBinding::Session { session_id, account_id },
        nonce,
        server_public,
    )
}

#[derive(Serialize)]
struct ApiDescriptorJs {
    method: &'static str,
    path: String,
    max_response_bytes: usize,
}

#[wasm_bindgen(js_name = apiDescriptor)]
pub fn api_descriptor(name: &str, id: Option<String>) -> Result<JsValue, JsError> {
    macro_rules! descriptor {
        ($endpoint:expr) => {{
            let endpoint = $endpoint;
            descriptor_value(&endpoint)
        }};
    }
    match name {
        "opaque_start" => descriptor!(beebeeb_api::routes::auth::opaque_start()),
        "opaque_finish" => descriptor!(beebeeb_api::routes::auth::opaque_finish()),
        "two_factor" => descriptor!(beebeeb_api::routes::auth::complete_two_factor()),
        "request_email_code" => descriptor!(beebeeb_api::proposed::request_email_code()),
        "submit_email_code" => descriptor!(beebeeb_api::proposed::submit_email_code()),
        "start_device_link" => descriptor!(beebeeb_api::proposed::start_device_link()),
        "device_link_result" => descriptor!(beebeeb_api::proposed::device_link_result(required_id(id.as_deref())?)),
        "send_device_link_pake" => {
            descriptor!(beebeeb_api::proposed::send_device_link_pake(required_id(
                id.as_deref()
            )?))
        }
        "get_device_link_pake" => {
            descriptor!(beebeeb_api::proposed::get_device_link_pake(required_id(id.as_deref())?))
        }
        "get_device_link_pake_for_approver" => {
            descriptor!(beebeeb_api::proposed::get_device_link_pake_for_role(
                required_id(id.as_deref())?,
                beebeeb_api::proposed::DeviceLinkRole::Approver,
            ))
        }
        "pending_device_links" => descriptor!(beebeeb_api::proposed::pending_device_links()),
        "get_device_link" => descriptor!(beebeeb_api::proposed::get_device_link(required_id(id.as_deref())?)),
        "approve_device_link" => {
            descriptor!(beebeeb_api::proposed::approve_device_link(required_id(id.as_deref())?))
        }
        "deny_device_link" => descriptor!(beebeeb_api::proposed::deny_device_link(required_id(id.as_deref())?)),
        "start_key_proof" => descriptor!(beebeeb_api::proposed::start_key_proof()),
        "finish_key_proof" => descriptor!(beebeeb_api::proposed::finish_key_proof()),
        _ => Err(JsError::new("unknown API descriptor")),
    }
}

fn descriptor_value<Req, Res>(endpoint: &Endpoint<Req, Res>) -> Result<JsValue, JsError> {
    let method = match endpoint.method() {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
    };
    serde_wasm_bindgen::to_value(&ApiDescriptorJs {
        method,
        path: endpoint.path().to_owned(),
        max_response_bytes: endpoint.max_response_bytes(),
    })
    .map_err(|_| JsError::new("API descriptor could not be encoded"))
}

fn answer(
    master_key: &MasterKey,
    binding: KeyProofBinding<'_>,
    nonce: &[u8],
    server_public: &[u8],
) -> Result<Vec<u8>, JsError> {
    let challenge = KeyProofChallenge::from_parts(fixed(nonce, "nonce")?, fixed(server_public, "server public key")?);
    answer_challenge(master_key, binding, &challenge)
        .map(|response| response.as_bytes().to_vec())
        .map_err(|_| JsError::new("key proof could not be answered"))
}

fn master(bytes: &[u8]) -> Result<MasterKey, JsError> {
    let bytes = Zeroizing::new(fixed(bytes, "master key")?);
    Ok(MasterKey::from_bytes(*bytes))
}

fn fixed<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{name} must be {N} bytes")))
}

fn required_id(id: Option<&str>) -> Result<&str, JsError> {
    id.filter(|value| !value.is_empty())
        .ok_or_else(|| JsError::new("descriptor requires an id"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn account_material_has_no_raw_key_getter() {
        let source = include_str!("device_security.rs");
        let at = source.find("impl WasmAccountKeyMaterial").unwrap();
        let end = source.find("#[wasm_bindgen(js_name = sealDeviceLink)]").unwrap();
        let body = &source[at..end];
        assert!(!body.contains("master_key(&self)"));
        assert!(!body.contains("to_bytes()"));
    }

    #[test]
    fn descriptors_are_purpose_specific() {
        let source = include_str!("device_security.rs");
        let forbidden = ["pub fn ", "execute"].concat();
        assert!(!source.contains(&forbidden));
        for name in ["opaque_start", "start_device_link", "start_key_proof"] {
            assert!(source.contains(name));
        }
    }
}
