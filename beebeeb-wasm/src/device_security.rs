use beebeeb_api::{Endpoint, Method};
use beebeeb_core::device_link::{
    AccountKeyMaterial, DeviceLinkQr, NewDeviceLink, SealedAccountKeyMaterial, seal_for_new_device,
};
use beebeeb_core::kdf::MasterKey;
use beebeeb_core::key_proof::{KeyProofBinding, KeyProofChallenge, answer_challenge};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct DeviceLinkPublicJs {
    session_id: Vec<u8>,
    public_key: Vec<u8>,
    fingerprint: Vec<u8>,
}

#[derive(Serialize)]
struct SealedDeviceLinkJs {
    session_id: Vec<u8>,
    recipient_public: Vec<u8>,
    approver_public: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
pub struct WasmNewDeviceLink {
    inner: Option<NewDeviceLink>,
}

#[wasm_bindgen]
impl WasmNewDeviceLink {
    #[wasm_bindgen(constructor)]
    pub fn new(session_id: &[u8]) -> Result<WasmNewDeviceLink, JsError> {
        let session_id = fixed(session_id, "session id")?;
        let link = NewDeviceLink::generate(session_id).map_err(|_| JsError::new("device link could not be created"))?;
        Ok(Self { inner: Some(link) })
    }

    #[wasm_bindgen(js_name = publicFields)]
    pub fn public_fields(&self) -> Result<JsValue, JsError> {
        let link = self
            .inner
            .as_ref()
            .ok_or_else(|| JsError::new("device link has already been consumed"))?;
        let qr = link.qr();
        serde_wasm_bindgen::to_value(&DeviceLinkPublicJs {
            session_id: qr.session_id().to_vec(),
            public_key: link.public_key().to_vec(),
            fingerprint: qr.fingerprint().to_vec(),
        })
        .map_err(|_| JsError::new("device link fields could not be encoded"))
    }

    #[wasm_bindgen(js_name = typedCode)]
    pub fn typed_code(&self) -> Result<String, JsError> {
        self.inner
            .as_ref()
            .map(|link| link.typed_code().to_owned())
            .ok_or_else(|| JsError::new("device link has already been consumed"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &mut self,
        typed_code: &str,
        session_id: &[u8],
        recipient_public: &[u8],
        approver_public: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<WasmAccountKeyMaterial, JsError> {
        let sealed = SealedAccountKeyMaterial::from_parts(
            fixed(session_id, "session id")?,
            fixed(recipient_public, "recipient public key")?,
            fixed(approver_public, "approver public key")?,
            fixed(nonce, "nonce")?,
            ciphertext.to_vec(),
        )
        .map_err(|_| JsError::new("invalid sealed device-link material"))?;
        let link = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("device link has already been consumed"))?;
        let material = link
            .open(typed_code, sealed)
            .map_err(|_| JsError::new("device-link material did not authenticate"))?;
        Ok(WasmAccountKeyMaterial {
            master_key: material.into_master_key(),
        })
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
pub fn seal_device_link(
    master_key: &[u8],
    session_id: &[u8],
    fingerprint: &[u8],
    relayed_public: &[u8],
    typed_code: &str,
) -> Result<JsValue, JsError> {
    let master_key = master(master_key)?;
    let qr = DeviceLinkQr::from_parts(fixed(session_id, "session id")?, fixed(fingerprint, "fingerprint")?);
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
