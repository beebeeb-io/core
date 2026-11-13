use super::*;

impl Client {
    pub async fn sign_in(
        &self,
        email: &str,
        password: Zeroizing<String>,
        legacy: Option<LegacyUpgradeAuthorization>,
    ) -> Result<SignInChallenge, AuthError> {
        self.sign_in_with_options(email, &password, legacy.as_ref(), SignInOptions::default())
            .await
    }

    pub async fn sign_in_on_device(
        &self,
        email: &str,
        password: Zeroizing<String>,
        legacy: Option<LegacyUpgradeAuthorization>,
        store: &dyn SecretStore,
    ) -> Result<SignInChallenge, AuthError> {
        let hardware = HardwareIdentity::load_or_create(store)?;
        let mut challenge = self
            .sign_in_with_options(
                email,
                &password,
                legacy.as_ref(),
                SignInOptions {
                    hardware_id: Some(hardware.id().to_owned()),
                    hardware_identity_secret: hardware.secret().map(str::to_owned),
                    request_password_proof: false,
                },
            )
            .await?;
        // The server has just accepted this exact password: stretch it for the screen-lock
        // check record while it is still in hand. It is sealed and saved with the installed
        // session, never before. A stretch that cannot run means no record, not a failed sign-in.
        if self.lock_password_path() {
            let pending = beebeeb_core::screen_lock::stretch(&password).ok();
            match &mut challenge {
                SignInChallenge::TwoFactor(state) => state.screen_check = pending,
                SignInChallenge::PasswordAccepted(state) => state.screen_check = pending,
                SignInChallenge::RecoveryPasswordProven(_) => {}
            }
        }
        Ok(challenge)
    }

    /// Proves the current password for recovery without creating a login
    /// session. The returned proof is opaque, redacted, and consumed when
    /// recovery is started.
    pub async fn prove_recovery_password(
        &self,
        email: &str,
        password: Zeroizing<String>,
        legacy: Option<LegacyUpgradeAuthorization>,
    ) -> Result<RecoveryPasswordProof, AuthError> {
        match self
            .sign_in_with_options(
                email,
                &password,
                legacy.as_ref(),
                SignInOptions {
                    request_password_proof: true,
                    ..SignInOptions::default()
                },
            )
            .await?
        {
            SignInChallenge::RecoveryPasswordProven(proof) => Ok(proof),
            _ => Err(AuthError::MalformedAnswer),
        }
    }

    /// Starts the no-wait recovery path by combining the recovery key with a
    /// one-use password proof obtained immediately beforehand.
    pub async fn start_recovery_with_password(
        &self,
        email: &str,
        password: Zeroizing<String>,
        master_key: &MasterKey,
        legacy: Option<LegacyUpgradeAuthorization>,
    ) -> Result<RecoveryAttempt, AuthError> {
        let proof = self.prove_recovery_password(email, password, legacy).await?;
        self.start_recovery(email, master_key, Some(proof)).await
    }

    async fn sign_in_with_options(
        &self,
        email: &str,
        password: &Zeroizing<String>,
        legacy: Option<&LegacyUpgradeAuthorization>,
        options: SignInOptions,
    ) -> Result<SignInChallenge, AuthError> {
        let email = canonical_email(email);
        if email.is_empty() || password.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        let start = client_login_start(password.as_bytes()).map_err(|_| AuthError::Crypto)?;
        let state = Zeroizing::new(start.state);
        let answer = self
            .execute(
                &auth::opaque_start(),
                &auth::OpaqueStartRequest {
                    email: email.clone(),
                    client_message: STANDARD.encode(start.message),
                },
            )
            .await?;
        let server_message = STANDARD
            .decode(answer.server_message)
            .map_err(|_| AuthError::InvalidAnswer {
                step: "OPAQUE login start",
                field: "server_message",
            })?;
        let mut finish = if answer.ksf_version == 0 {
            let authorization = legacy.ok_or(AuthError::LegacyUpgradeNotAuthorized)?;
            if authorization.canonical_email != email {
                return Err(AuthError::LegacyUpgradeNotAuthorized);
            }
            client_login_finish_legacy_upgrade(&state, password.as_bytes(), &server_message)
                .map_err(|_| AuthError::Crypto)?
        } else {
            client_login_finish(
                &state,
                password.as_bytes(),
                &server_message,
                u32::from(answer.ksf_version),
            )
            .map_err(|_| AuthError::Crypto)?
        };
        let response = self
            .execute(
                &auth::opaque_finish(),
                &auth::OpaqueFinishRequest {
                    email: email.clone(),
                    client_message: STANDARD.encode(&finish.message),
                    server_state: answer.server_state,
                    hardware_id: options.hardware_id.clone(),
                    hardware_identity_secret: options.hardware_identity_secret,
                    request_password_proof: options.request_password_proof,
                },
            )
            .await?;
        finish.message.clear();
        sign_in_state(
            email,
            response,
            answer.ksf_version == 0,
            options.hardware_id,
            options.request_password_proof,
        )
    }

    pub async fn submit_two_factor(
        &self,
        challenge: TwoFactorChallenge,
        code: String,
    ) -> Result<PasswordAccepted, AuthError> {
        let response = self
            .execute(
                &auth::complete_two_factor(),
                &auth::TwoFactorRequest {
                    partial_token: challenge.partial_token,
                    code: Zeroizing::new(code),
                },
            )
            .await?;
        if response.session_token.is_empty() || response.user_id.is_empty() {
            return Err(AuthError::MalformedAnswer);
        }
        Ok(PasswordAccepted {
            session_token: Zeroizing::new(response.session_token),
            canonical_email: challenge.canonical_email,
            owner: response.user_id,
            key_state: SessionKeyState::parse(response.key_state.as_deref())?,
            legacy_upgrade_required: challenge.legacy_upgrade_required,
            factor_satisfied: true,
            email_code_satisfied: false,
            authenticator_required: true,
            hardware_id: challenge.hardware_id,
            hardware_identity_secret: None,
            screen_check: challenge.screen_check,
        })
    }

    pub async fn request_email_code(&self, email: String) -> Result<proposed::EmailCodeChallenge, ClientError> {
        self.execute(
            &proposed::request_email_code(),
            &proposed::EmailCodeRequest {
                email: canonical_email(&email),
            },
        )
        .await
    }

    pub async fn submit_email_code(
        &self,
        challenge: String,
        code: String,
    ) -> Result<proposed::EmailCodeTicket, ClientError> {
        self.execute(
            &proposed::submit_email_code(),
            &proposed::EmailCodeSubmit {
                challenge,
                code: Zeroizing::new(code),
            },
        )
        .await
    }
}
