use super::*;

impl Client {
    pub async fn setup_authenticator(&self) -> Result<AuthenticatorEnrollment, AuthError> {
        let answer = self
            .execute(
                &beebeeb_api::routes::account::setup_totp(),
                &beebeeb_api::routes::account::TotpSetupRequest::default(),
            )
            .await?;
        Ok(AuthenticatorEnrollment {
            secret: answer.secret,
            qr_uri: answer.qr_uri,
        })
    }

    pub async fn enable_authenticator(&self, code: String) -> Result<(), AuthError> {
        self.execute(
            &beebeeb_api::routes::account::enable_totp(),
            &beebeeb_api::routes::account::TotpCode { code },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn remove_authenticator(&self, code: String) -> Result<(), AuthError> {
        self.execute(
            &beebeeb_api::routes::account::disable_totp(),
            &beebeeb_api::routes::account::TotpCode { code },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn request_account_deletion(
        &self,
        password: Zeroizing<String>,
        authenticator_code: Option<String>,
    ) -> Result<(), AuthError> {
        let confirmation = self.confirm_action(&password).await?;
        // The step-up is the password's only use: wipe it before the next request.
        drop(password);
        self.execute_confirmed(
            &beebeeb_api::routes::account::request_deletion(),
            &beebeeb_api::routes::account::DeletionRequest {
                code: authenticator_code.map(Zeroizing::new),
            },
            &confirmation.token,
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }
}

pub struct AuthenticatorEnrollment {
    secret: Zeroizing<String>,
    qr_uri: Option<Zeroizing<String>>,
}

struct ConfirmationToken {
    token: Zeroizing<String>,
}

impl std::fmt::Debug for ConfirmationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfirmationToken([REDACTED])")
    }
}

impl Client {
    async fn confirm_action(&self, password: &Zeroizing<String>) -> Result<ConfirmationToken, AuthError> {
        let started = client_login_start(password.as_bytes()).map_err(|_| AuthError::Crypto)?;
        let state = Zeroizing::new(started.state);
        let answer = self
            .execute(
                &proposed::confirm_opaque_start(),
                &proposed::ConfirmOpaqueStart {
                    client_message: STANDARD.encode(started.message),
                },
            )
            .await?;
        if answer.ksf_version == 0 {
            return Err(AuthError::LegacyUpgradeNotAuthorized);
        }
        let server_message = STANDARD
            .decode(answer.server_message)
            .map_err(|_| AuthError::MalformedAnswer)?;
        let finish = client_login_finish(
            &state,
            password.as_bytes(),
            &server_message,
            u32::from(answer.ksf_version),
        )
        .map_err(|_| AuthError::Crypto)?;
        let confirmed = self
            .execute(
                &proposed::confirm_opaque_finish(),
                &proposed::ConfirmOpaqueFinish {
                    client_message: STANDARD.encode(finish.message),
                    server_state: answer.server_state,
                },
            )
            .await?;
        if confirmed.confirmation_token.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        Ok(ConfirmationToken {
            token: Zeroizing::new(confirmed.confirmation_token),
        })
    }

    pub async fn change_password(
        &self,
        current_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
        store: &dyn SecretStore,
    ) -> Result<InstalledSession, AuthError> {
        if new_password.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let first_confirmation = self.confirm_action(&current_password).await?;
        let registration = client_registration_start(new_password.as_bytes()).map_err(|_| AuthError::Crypto)?;
        let registration_state = Zeroizing::new(registration.state);
        let start = self
            .execute_confirmed(
                &proposed::change_password_start(),
                &proposed::ChangePasswordStart {
                    client_message: STANDARD.encode(registration.message),
                },
                &first_confirmation.token,
            )
            .await?;
        let server_message = STANDARD
            .decode(start.server_message)
            .map_err(|_| AuthError::MalformedAnswer)?;
        let upload = client_registration_finish(&registration_state, new_password.as_bytes(), &server_message)
            .map_err(|_| AuthError::Crypto)?;
        let second_confirmation = self.confirm_action(&current_password).await?;
        let changed = self
            .execute_confirmed(
                &proposed::change_password_finish(),
                &proposed::ChangePasswordFinish {
                    client_message: STANDARD.encode(upload),
                },
                &second_confirmation.token,
            )
            .await?;
        if changed.user_id.is_empty() || changed.session_token.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let key_state = SessionKeyState::parse(changed.key_state.as_deref())?;
        if Session::stored_owner(store)?.as_deref() != Some(changed.user_id.as_str()) {
            return Err(AuthError::AnotherAccountOnDevice);
        }
        let stored =
            Session::load_for_user(store, &changed.user_id, self.app_id())?.ok_or(AuthError::AccountOwnership)?;
        self.set_authentication(changed.session_token.clone(), changed.user_id.clone())?;
        let _ = key_state;
        if let Err(error) = self.prove_session_key(stored.master_key()).await {
            let _ = self.clear_authentication();
            return Err(error);
        }
        let generation = self.generation().checked_add(1).ok_or(AuthError::MalformedAnswer)?;
        let refreshed = stored.refresh(changed.session_token, generation)?;
        refreshed.save(store, self.app_id())?;
        self.set_session(&refreshed)?;
        Ok(InstalledSession {
            owner: changed.user_id,
            generation,
        })
    }

    pub async fn change_email(
        &self,
        new_email: &str,
        password: Zeroizing<String>,
        store: &dyn SecretStore,
    ) -> Result<String, AuthError> {
        let new_email = canonical_email(new_email);
        if new_email.is_empty() || password.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let owner = self.authenticated_owner()?;
        let stored = Session::load_for_user(store, &owner, self.app_id())?.ok_or(AuthError::AccountOwnership)?;
        let confirmation = self.confirm_action(&password).await?;
        let registration = client_registration_start(password.as_bytes()).map_err(|_| AuthError::Crypto)?;
        let state = Zeroizing::new(registration.state);
        let start = self
            .execute_confirmed(
                &proposed::change_email_start(),
                &proposed::ChangeEmailStart {
                    new_email: new_email.clone(),
                    opaque_client_message: STANDARD.encode(registration.message),
                },
                &confirmation.token,
            )
            .await?;
        let server_message = STANDARD
            .decode(start.server_message)
            .map_err(|_| AuthError::MalformedAnswer)?;
        let upload =
            client_registration_finish(&state, password.as_bytes(), &server_message).map_err(|_| AuthError::Crypto)?;
        let private = beebeeb_core::opaque::derive_x25519_private(stored.master_key());
        let public = beebeeb_core::opaque::derive_x25519_public(&private);
        let recovery_check = beebeeb_core::opaque::compute_recovery_check(stored.master_key());
        let changed = self
            .execute(
                &proposed::change_email_finish(),
                &proposed::ChangeEmailFinish {
                    email_change_token: start.email_change_token,
                    opaque_registration: STANDARD.encode(upload),
                    recovery_check: STANDARD.encode(*recovery_check),
                    x25519_public_key: STANDARD.encode(public),
                },
            )
            .await?;
        if canonical_email(&changed.email) != new_email {
            return Err(AuthError::MalformedAnswer);
        }
        Ok(new_email)
    }
}

impl AuthenticatorEnrollment {
    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn qr_uri(&self) -> Option<&str> {
        self.qr_uri.as_deref().map(String::as_str)
    }
}

impl std::fmt::Debug for AuthenticatorEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatorEnrollment")
            .field("secret", &"[REDACTED]")
            .field("qr_uri", &self.qr_uri.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}
