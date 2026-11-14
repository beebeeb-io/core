use super::*;

impl Client {
    pub async fn setup_authenticator(&self) -> Result<AuthenticatorEnrollment, AuthError> {
        self.person_call(crate::LockedAction::ManageFactors)?;
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
        self.person_call(crate::LockedAction::ManageFactors)?;
        self.execute(
            &beebeeb_api::routes::account::enable_totp(),
            &beebeeb_api::routes::account::TotpCode {
                code: Zeroizing::new(code),
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn remove_authenticator(&self, code: String) -> Result<(), AuthError> {
        self.person_call(crate::LockedAction::ManageFactors)?;
        self.execute(
            &beebeeb_api::routes::account::disable_totp(),
            &beebeeb_api::routes::account::TotpCode {
                code: Zeroizing::new(code),
            },
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
        self.person_call(crate::LockedAction::DeleteAccount)?;
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

pub(super) fn is_unauthorized(error: &ClientError) -> bool {
    matches!(error, ClientError::Api(beebeeb_api::ApiError::Server(server)) if server.status == 401)
}

impl Client {
    /// The password step-up. Its routes answer 401 to a refused step-up as well as to a
    /// dead session, so the client reports no expired session for them
    /// (`Endpoint::is_step_up`); a refusal is `AuthError::PasswordNotConfirmed`.
    async fn confirm_action(&self, password: &Zeroizing<String>) -> Result<ConfirmationToken, AuthError> {
        let started = client_login_start(password.as_bytes()).map_err(|_| AuthError::Crypto)?;
        let state = Zeroizing::new(started.state);
        let start_reply = self
            .execute(
                &proposed::confirm_opaque_start(),
                &proposed::ConfirmOpaqueStart {
                    client_message: STANDARD.encode(started.message),
                },
            )
            .await;
        let answer = match start_reply {
            Err(error) if is_unauthorized(&error) => return Err(self.refused_step_up().await),
            start_reply => start_reply?,
        };
        if answer.ksf_version == 0 {
            return Err(AuthError::LegacyUpgradeNotAuthorized);
        }
        let server_message = STANDARD
            .decode(answer.server_message)
            .map_err(|_| AuthError::MalformedAnswer)?;
        // OPAQUE's finish fails alike for a wrong password and a record made for another one.
        let finish = client_login_finish(
            &state,
            password.as_bytes(),
            &server_message,
            u32::from(answer.ksf_version),
        )
        .map_err(|_| AuthError::PasswordNotConfirmed)?;
        let finish_reply = self
            .execute(
                &proposed::confirm_opaque_finish(),
                &proposed::ConfirmOpaqueFinish {
                    client_message: STANDARD.encode(finish.message),
                    server_state: answer.server_state,
                },
            )
            .await;
        let confirmed = match finish_reply {
            // The session can end between start and finish: a 401 here is asked about as well.
            Err(error) if is_unauthorized(&error) => return Err(self.refused_step_up().await),
            finish_reply => finish_reply?,
        };
        if confirmed.confirmation_token.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        Ok(ConfirmationToken {
            token: Zeroizing::new(confirmed.confirmation_token),
        })
    }

    /// What a 401 from the step-up means. The server answers it alike for a dead session and
    /// for a refused step-up (password checks locked after failed guesses at the start, a
    /// refused proof at the finish), so ask for the account: an answer means the session
    /// lives and the step-up was refused; a failure is that request's own, a dead session
    /// reported as expired the usual way.
    async fn refused_step_up(&self) -> AuthError {
        match self.execute(&auth::me(), &()).await {
            Ok(_) => AuthError::PasswordNotConfirmed,
            Err(error) => error.into(),
        }
    }

    pub async fn change_password(
        &self,
        current_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
        store: &dyn SecretStore,
    ) -> Result<InstalledSession, AuthError> {
        self.person_call(crate::LockedAction::ChangeSettings)?;
        // The change is for the session it starts with: this is its account generation.
        let entered_at = self.generation();
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
        let stored = Session::load_for_user_proven(store, &changed.user_id, self.app_id())?
            .ok_or(AuthError::AccountOwnership)?;
        // The change replaces the session, and the app is in the same lock state afterwards.
        // The state is read here, not before the requests above: a screen lock that landed
        // while they were on their way stays locked. From here to the install the app is
        // closed, and a closed app cannot be screen-locked or opened by anything weaker.
        // It is read in the step that sets the new credentials, so no lock lands in between.
        // Everything below belongs to those credentials, at this account generation.
        // They are set only while the session the change started with is still the one in
        // the process: a vault lock or a sign-out that landed since the call began, also
        // between the last answer and this step, wins. No key is loaded again for it.
        let sign_outs = self.sign_outs();
        let set = self.set_authentication_reading_lock(
            changed.session_token.clone(),
            changed.user_id.clone(),
            Some(entered_at),
        );
        let (changed_at, lock_before) = match set {
            Ok(set) => set,
            Err(error) => {
                // The server has changed the password: the old password's record goes.
                lock::replace_screen_check(store, None);
                return Err(error.into());
            }
        };
        let _ = key_state;
        if let Err(error) = self.prove_session_key(stored.master_key()).await {
            if !matches!(error, AuthError::Client(ClientError::StaleAccount)) {
                let _ = self.clear_authentication();
            }
            return Err(error);
        }
        let generation = changed_at.checked_add(1).ok_or(AuthError::MalformedAnswer)?;
        let refreshed = stored.refresh(changed.session_token, generation)?;
        // The old password's check record must not outlive the change, whatever becomes of
        // the install: the server has already changed the password. With the password path
        // on, the new password gets a record of its own. The key stretch (about a second)
        // runs here, before anything of the new session is written.
        let record = self
            .lock_password_path()
            .then(|| {
                beebeeb_core::screen_lock::enroll(
                    &new_password,
                    &changed.user_id,
                    changed.password_counter.unwrap_or(0),
                )
                .ok()
            })
            .flatten();
        lock::replace_screen_check(store, record);
        // Nothing of the new session is saved for a session that is no longer the one in the
        // process: a vault lock, a sign-out or an ended session that landed meanwhile wins.
        if self.generation() != changed_at {
            self.forget_refused_save(store, sign_outs);
            return Err(ClientError::StaleAccount.into());
        }
        refreshed.save(store, self.app_id())?;
        // The install and the lock state move in one step, and only for the session this
        // call proved: a lock that landed after the last answer is not undone, the key is
        // not installed again and the lock is not opened.
        let installed = self.install_session_at(&refreshed, changed_at, |flow| {
            if beebeeb_api::flows::key_may_be_loaded(lock_before.state()) {
                // A screen lock asked for while the app was held closed is not lost either:
                // `install_session_at` applies it in this same step.
                *flow = lock_before;
            }
        });
        if let Err(error) = installed {
            self.forget_refused_save(store, sign_outs);
            return Err(error.into());
        }
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
        self.person_call(crate::LockedAction::ChangeSettings)?;
        let new_email = canonical_email(new_email);
        if new_email.is_empty() || password.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let owner = self.authenticated_owner()?;
        let stored = Session::load_for_user_proven(store, &owner, self.app_id())?.ok_or(AuthError::AccountOwnership)?;
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
