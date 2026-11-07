use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AuthChallengeKind {
    TwoFactor,
    PasswordAccepted,
    RecoveryPasswordProven,
}

impl From<SignInStateKind> for AuthChallengeKind {
    fn from(value: SignInStateKind) -> Self {
        match value {
            SignInStateKind::TwoFactor => Self::TwoFactor,
            SignInStateKind::PasswordAccepted => Self::PasswordAccepted,
            SignInStateKind::RecoveryPasswordProven => Self::RecoveryPasswordProven,
        }
    }
}

#[derive(uniffi::Object)]
pub struct AuthChallengeHandle {
    pub(crate) state: Mutex<Option<SignInChallenge>>,
    kind: AuthChallengeKind,
    canonical_email: String,
}

#[uniffi::export]
impl AuthChallengeHandle {
    pub fn kind(&self) -> AuthChallengeKind {
        self.kind
    }

    pub fn canonical_email(&self) -> String {
        self.canonical_email.clone()
    }
}

#[derive(uniffi::Object)]
pub struct PasswordAcceptedHandle {
    pub(crate) state: Mutex<Option<beebeeb_client::auth::PasswordAccepted>>,
    owner: String,
    canonical_email: String,
}

#[derive(uniffi::Object)]
pub struct EmailCodeChallengeHandle {
    state: Mutex<Option<beebeeb_api::proposed::EmailCodeChallenge>>,
    expires_at: String,
    message: String,
}

#[uniffi::export]
impl EmailCodeChallengeHandle {
    pub fn expires_at(&self) -> String {
        self.expires_at.clone()
    }

    pub fn message(&self) -> String {
        self.message.clone()
    }
}

#[derive(uniffi::Object)]
pub struct EmailCodeTicketHandle {
    state: Mutex<Option<beebeeb_api::proposed::EmailCodeTicket>>,
    expires_in: u64,
}

#[uniffi::export]
impl EmailCodeTicketHandle {
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

#[uniffi::export]
impl PasswordAcceptedHandle {
    pub fn owner(&self) -> String {
        self.owner.clone()
    }

    pub fn canonical_email(&self) -> String {
        self.canonical_email.clone()
    }
}

pub(crate) fn password_accepted_handle(
    accepted: beebeeb_client::auth::PasswordAccepted,
) -> Arc<PasswordAcceptedHandle> {
    let owner = accepted.owner().to_owned();
    let canonical_email = accepted.canonical_email().to_owned();
    Arc::new(PasswordAcceptedHandle {
        state: Mutex::new(Some(accepted)),
        owner,
        canonical_email,
    })
}

fn auth_challenge_handle(challenge: SignInChallenge) -> Arc<AuthChallengeHandle> {
    let kind = challenge.kind().into();
    let canonical_email = challenge.canonical_email().to_owned();
    Arc::new(AuthChallengeHandle {
        state: Mutex::new(Some(challenge)),
        kind,
        canonical_email,
    })
}

#[derive(uniffi::Object)]
pub struct AuthServiceHandle {
    pub(crate) root: Arc<NativeClientHandle>,
}

#[uniffi::export]
impl AuthServiceHandle {
    pub fn sign_in(&self, email: String, password: String) -> Result<Arc<AuthChallengeHandle>, ServiceError> {
        let challenge = self
            .root
            .runtime
            .block_on(self.root.client.sign_in(&email, Zeroizing::new(password), None))
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        Ok(auth_challenge_handle(challenge))
    }

    pub fn sign_in_on_device(&self, email: String, password: String) -> Result<Arc<AuthChallengeHandle>, ServiceError> {
        let challenge = self
            .root
            .runtime
            .block_on(self.root.client.sign_in_on_device(
                &email,
                Zeroizing::new(password),
                None,
                self.root.secret_store.as_ref(),
            ))
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        Ok(auth_challenge_handle(challenge))
    }

    pub fn submit_two_factor(
        &self,
        challenge: &AuthChallengeHandle,
        code: String,
    ) -> Result<Arc<PasswordAcceptedHandle>, ServiceError> {
        let state = challenge
            .state
            .lock()
            .map_err(|_| ServiceError::unavailable())?
            .take()
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let SignInChallenge::TwoFactor(state) = state else {
            return Err(ServiceError::new(ServiceErrorKind::InvalidInput));
        };
        let accepted = self
            .root
            .runtime
            .block_on(self.root.client.submit_two_factor(state, code))
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        Ok(password_accepted_handle(accepted))
    }

    pub fn accept_password(
        &self,
        challenge: &AuthChallengeHandle,
    ) -> Result<Arc<PasswordAcceptedHandle>, ServiceError> {
        let state = challenge
            .state
            .lock()
            .map_err(|_| ServiceError::unavailable())?
            .take()
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let SignInChallenge::PasswordAccepted(accepted) = state else {
            return Err(ServiceError::new(ServiceErrorKind::InvalidInput));
        };
        Ok(password_accepted_handle(accepted))
    }

    pub fn unlock_known_device(&self, accepted: &PasswordAcceptedHandle) -> Result<u64, ServiceError> {
        self.refuse_account_mismatch(accepted)?;
        let accepted = take_password_accepted(accepted)?;
        let owner = accepted.owner().to_owned();
        let installed = self
            .root
            .runtime
            .block_on(
                self.root
                    .client
                    .unlock_known_device(accepted, self.root.secret_store.as_ref()),
            )
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        self.root.load_installed_session(&owner)?;
        Ok(installed.generation())
    }

    pub fn install_new_device_with_passkey(
        &self,
        accepted: &PasswordAcceptedHandle,
        master_key: &MasterKeyHandle,
        email_ticket: &EmailCodeTicketHandle,
    ) -> Result<u64, ServiceError> {
        self.install_new_device(accepted, master_key, email_ticket, true, None)
    }

    pub fn install_new_device_with_recovery_key(
        &self,
        accepted: &PasswordAcceptedHandle,
        master_key: &MasterKeyHandle,
        email_ticket: &EmailCodeTicketHandle,
    ) -> Result<u64, ServiceError> {
        self.install_new_device(accepted, master_key, email_ticket, false, None)
    }

    pub fn install_new_device_with_passkey_replacing_account(
        &self,
        accepted: &PasswordAcceptedHandle,
        master_key: &MasterKeyHandle,
        email_ticket: &EmailCodeTicketHandle,
        replacement: &AccountReplacementHandle,
    ) -> Result<u64, ServiceError> {
        self.install_new_device(accepted, master_key, email_ticket, true, Some(replacement))
    }

    pub fn install_new_device_with_recovery_key_replacing_account(
        &self,
        accepted: &PasswordAcceptedHandle,
        master_key: &MasterKeyHandle,
        email_ticket: &EmailCodeTicketHandle,
        replacement: &AccountReplacementHandle,
    ) -> Result<u64, ServiceError> {
        self.install_new_device(accepted, master_key, email_ticket, false, Some(replacement))
    }

    pub fn request_email_code(&self, email: String) -> Result<Arc<EmailCodeChallengeHandle>, ServiceError> {
        let challenge = self
            .root
            .runtime
            .block_on(self.root.client.request_email_code(email))
            .map_err(map_client_error)?;
        Ok(Arc::new(EmailCodeChallengeHandle {
            expires_at: challenge.expires_at.clone(),
            message: challenge.message.clone(),
            state: Mutex::new(Some(challenge)),
        }))
    }

    pub fn submit_email_code(
        &self,
        challenge: &EmailCodeChallengeHandle,
        code: String,
    ) -> Result<Arc<EmailCodeTicketHandle>, ServiceError> {
        let challenge = challenge
            .state
            .lock()
            .map_err(|_| ServiceError::unavailable())?
            .take()
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let ticket = self
            .root
            .runtime
            .block_on(self.root.client.submit_email_code(challenge.challenge, code))
            .map_err(map_client_error)?;
        Ok(Arc::new(EmailCodeTicketHandle {
            expires_in: ticket.expires_in,
            state: Mutex::new(Some(ticket)),
        }))
    }

    pub fn create_passkey_copy(&self, prompt: Box<dyn PasskeyPrompt>) -> Result<String, ServiceError> {
        let adapter = PasskeyPromptAdapter {
            callback: prompt,
            account_id: self.root.client.account_id().map_err(map_client_error)?,
        };
        self.root
            .runtime
            .block_on(self.root.client.create_passkey_copy(&adapter))
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))
    }

    pub fn open_with_passkey(
        &self,
        accepted: &PasswordAcceptedHandle,
        prompt: Box<dyn PasskeyPrompt>,
    ) -> Result<Arc<MasterKeyHandle>, ServiceError> {
        let state = accepted.state.lock().map_err(|_| ServiceError::unavailable())?;
        let accepted = state
            .as_ref()
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        let adapter = PasskeyPromptAdapter {
            callback: prompt,
            account_id: accepted.owner().to_owned(),
        };
        let key = self
            .root
            .runtime
            .block_on(self.root.client.open_with_passkey(accepted, &adapter))
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        Ok(MasterKeyHandle::new(key))
    }
}

impl AuthServiceHandle {
    pub(crate) fn refuse_account_mismatch(&self, accepted: &PasswordAcceptedHandle) -> Result<(), ServiceError> {
        let stored = Session::stored_owner(self.root.secret_store.as_ref())
            .map_err(|_| ServiceError::new(ServiceErrorKind::Storage))?;
        if stored.as_deref().is_some_and(|owner| owner != accepted.owner) {
            Err(ServiceError::new(ServiceErrorKind::AnotherAccountOnDevice))
        } else {
            Ok(())
        }
    }

    fn install_new_device(
        &self,
        accepted: &PasswordAcceptedHandle,
        master_key: &MasterKeyHandle,
        email_ticket: &EmailCodeTicketHandle,
        passkey: bool,
        replacement: Option<&AccountReplacementHandle>,
    ) -> Result<u64, ServiceError> {
        if replacement.is_none() {
            self.refuse_account_mismatch(accepted)?;
        }
        let accepted = take_password_accepted(accepted)?;
        let owner = accepted.owner().to_owned();
        let mut unlock = if passkey {
            beebeeb_client::auth::NewDeviceUnlock::passkey(accepted)
        } else {
            beebeeb_client::auth::NewDeviceUnlock::recovery(accepted)
        }
        .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        let ticket = email_ticket
            .state
            .lock()
            .map_err(|_| ServiceError::unavailable())?
            .take()
            .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))?;
        unlock
            .provide_email_code_ticket(ticket)
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        let key = copy_master_key(master_key)?;
        let key_bytes = Zeroizing::new(*key.to_bytes());
        let key = MasterKey::from_bytes(*key_bytes);
        if passkey {
            unlock.provide_passkey(key)
        } else {
            unlock.provide_recovery_key(key)
        }
        .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        let ready = unlock
            .into_ready()
            .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        let installed = if let Some(replacement) = replacement {
            let replacement = replacement.take(&self.root)?;
            self.root
                .runtime
                .block_on(self.root.client.install_new_device_replacing_account(
                    ready,
                    &self.root.api_base,
                    self.root.secret_store.as_ref(),
                    replacement,
                ))
        } else {
            self.root.runtime.block_on(self.root.client.install_new_device(
                ready,
                &self.root.api_base,
                self.root.secret_store.as_ref(),
            ))
        }
        .map_err(|_| ServiceError::new(ServiceErrorKind::Authentication))?;
        self.root.load_installed_session(&owner)?;
        Ok(installed.generation())
    }
}

pub(crate) fn take_password_accepted(
    handle: &PasswordAcceptedHandle,
) -> Result<beebeeb_client::auth::PasswordAccepted, ServiceError> {
    handle
        .state
        .lock()
        .map_err(|_| ServiceError::unavailable())?
        .take()
        .ok_or_else(|| ServiceError::new(ServiceErrorKind::InvalidInput))
}

#[uniffi::export(callback_interface)]
pub trait SecretStoreCallback: Send + Sync {
    /// Authorize Rust to access a named native secret. Secret bytes never enter
    /// the callback; storage is performed by the Rust Keychain backend.
    fn authorize_access(&self, name: String) -> bool;
}

/// What the platform passkey prompt returned. `prf_output` is key material: a
/// [`SecretBytes`](crate::SecretBytes) (plain `Data` / `ByteArray` to Swift and
/// Kotlin), wiped on drop and redacted in `Debug`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyPromptResult {
    pub credential_id: String,
    pub prf_output: crate::SecretBytes,
    pub user_verified: bool,
}

#[uniffi::export(callback_interface)]
pub trait PasskeyPrompt: Send + Sync {
    fn create(&self, account_id: String) -> Option<PasskeyPromptResult>;
    fn authenticate(&self, account_id: String) -> Option<PasskeyPromptResult>;
}

struct PasskeyPromptAdapter {
    callback: Box<dyn PasskeyPrompt>,
    account_id: String,
}

impl beebeeb_client::auth::PasskeyPrompt for PasskeyPromptAdapter {
    fn create<'a>(&'a self) -> beebeeb_client::auth::PasskeyPromptFuture<'a> {
        Box::pin(async move {
            let output = self
                .callback
                .create(self.account_id.clone())
                .filter(|output| output.user_verified)
                .ok_or(beebeeb_client::auth::PasskeyPromptError)?;
            Ok(beebeeb_client::auth::PasskeyPromptOutput {
                credential_id: output.credential_id,
                prf_output: output.prf_output.into_zeroizing(),
            })
        })
    }

    fn authenticate<'a>(&'a self) -> beebeeb_client::auth::PasskeyPromptFuture<'a> {
        Box::pin(async move {
            let output = self
                .callback
                .authenticate(self.account_id.clone())
                .filter(|output| output.user_verified)
                .ok_or(beebeeb_client::auth::PasskeyPromptError)?;
            Ok(beebeeb_client::auth::PasskeyPromptOutput {
                credential_id: output.credential_id,
                prf_output: output.prf_output.into_zeroizing(),
            })
        })
    }
}
