//! WASM surface for core's account flows (desktop v2 B14). Thin: every rule lives in
//! `beebeeb_core::account_flows`. JS performs each HTTP step with `fetch` and feeds the
//! reply back; `confirm_token` goes straight into the `X-Confirm-Token` header.
//! Errors are thrown as the stable code string (`wrong_password`, `invalid_code`, ...).

use beebeeb_core::account_flows::{self as af, AccountBinding, AccountFlow, HostSession};
use wasm_bindgen::prelude::*;

fn err(e: af::AccountFlowError) -> JsValue {
    JsValue::from_str(e.code())
}

#[wasm_bindgen(js_name = AccountFlow)]
pub struct AccountFlowJs {
    inner: HostSession,
}

impl AccountFlowJs {
    fn begin(&mut self, flow: Result<AccountFlow, af::AccountFlowError>) -> Result<JsValue, JsValue> {
        let step = self.inner.begin(flow.map_err(err)?).map_err(err)?;
        serde_wasm_bindgen::to_value(&step).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

fn binding(recovery_check_b64: String, x25519_public_b64: String) -> AccountBinding {
    AccountBinding {
        recovery_check_b64,
        x25519_public_b64,
    }
}

#[wasm_bindgen(js_class = AccountFlow)]
impl AccountFlowJs {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: HostSession::new(),
        }
    }

    #[wasm_bindgen(js_name = changePassword)]
    pub fn change_password(
        &mut self,
        current: String,
        new_password: String,
        recovery_check_b64: String,
        x25519_public_b64: String,
    ) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::change_password(
            &current,
            &new_password,
            binding(recovery_check_b64, x25519_public_b64),
        ))
    }

    #[wasm_bindgen(js_name = changeEmail)]
    pub fn change_email(
        &mut self,
        new_email: String,
        password: String,
        recovery_check_b64: String,
        x25519_public_b64: String,
    ) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::change_email(
            &new_email,
            &password,
            binding(recovery_check_b64, x25519_public_b64),
        ))
    }

    #[wasm_bindgen(js_name = verifyEmail)]
    pub fn verify_email(&mut self, code: String) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::verify_email(&code))
    }

    #[wasm_bindgen(js_name = totpSetup)]
    pub fn totp_setup(&mut self, password: Option<String>, current_code: Option<String>) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::totp_setup(password.as_deref(), current_code.as_deref()))
    }

    #[wasm_bindgen(js_name = totpConfirm)]
    pub fn totp_confirm(&mut self, code: String) -> Result<JsValue, JsValue> {
        let step = self.inner.totp_confirm(&code).map_err(err)?;
        serde_wasm_bindgen::to_value(&step).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = totpDisable)]
    pub fn totp_disable(&mut self, code: String) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::totp_disable(&code))
    }

    #[wasm_bindgen(js_name = revokeSession)]
    pub fn revoke_session(&mut self, session_id: String) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::revoke_session(&session_id))
    }

    #[wasm_bindgen(js_name = revokeOtherSessions)]
    pub fn revoke_other_sessions(&mut self) -> Result<JsValue, JsValue> {
        self.begin(Ok(AccountFlow::revoke_other_sessions()))
    }

    #[wasm_bindgen(js_name = setDisplayName)]
    pub fn set_display_name(&mut self, name: String) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::set_display_name(&name))
    }

    #[wasm_bindgen(js_name = setActivityLogging)]
    pub fn set_activity_logging(&mut self, on: bool) -> Result<JsValue, JsValue> {
        self.begin(Ok(AccountFlow::set_activity_logging(on)))
    }

    #[wasm_bindgen(js_name = verifyPassword)]
    pub fn verify_password(&mut self, password: String) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::verify_password(&password))
    }

    #[wasm_bindgen(js_name = deleteAccount)]
    pub fn delete_account(&mut self, password: String) -> Result<JsValue, JsValue> {
        self.begin(AccountFlow::delete_account(&password))
    }

    pub fn resume(&mut self, status: u16, body_text: String) -> Result<JsValue, JsValue> {
        let step = self.inner.resume(status, &body_text).map_err(err)?;
        serde_wasm_bindgen::to_value(&step).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn abandon(&mut self) {
        self.inner.abandon();
    }
}

impl Default for AccountFlowJs {
    fn default() -> Self {
        Self::new()
    }
}
